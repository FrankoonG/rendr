package wire

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

// TestJoinAckMux (M3, WP16 W3): a view's JOIN_ACK on a MUX trunk carries
// its refusal code in the RxNext field (the low 32 bits; the high 32 bits
// stay zero). The fixed vectors below are the payload byte for byte; a code round-trips through
// PutJoinAckMux and ParseJoinAckMux; an OK JOIN_ACK is unchanged; a
// non-zero high half is ErrReserved; and a dedicated carrier's JOIN_ACK
// keeps M2's rule — a refusal with a non-zero RxNext field, a code
// included, is ErrReserved for ParseJoinAck.
func TestJoinAckMux(t *testing.T) {
	vecs := []struct {
		name string
		a    JoinAck
		code uint32
	}{
		{"capacity_mux_full", JoinAck{Status: StatusCapacity}, CodeMuxFull},
		{"capacity_carriers", JoinAck{Status: StatusCapacity}, CodeCarriers},
		{"unknown_session", JoinAck{Status: StatusUnknownSession}, 0},
		{"ok", JoinAck{Status: StatusOK, RxNext: 1 << 20}, CodeMuxFull},
	}
	// The payload bytes, written out: status ‖ u64 big-endian.
	payloads := map[string]string{
		"capacity_mux_full": "020000000000000006",
		"capacity_carriers": "020000000000000004",
		"unknown_session":   "010000000000000000",
		"ok":                "000000000000100000",
	}
	for _, v := range vecs {
		var b [JoinAckLen]byte
		if n := PutJoinAckMux(b[:], &v.a, v.code); n != JoinAckLen {
			t.Fatalf("%s: PutJoinAckMux wrote %d bytes", v.name, n)
		}
		if got := hex.EncodeToString(b[:]); got != payloads[v.name] {
			t.Fatalf("%s: payload %s, want %s", v.name, got, payloads[v.name])
		}
		a, code, err := ParseJoinAckMux(b[:])
		wantCode := v.code
		if v.a.Status == StatusOK {
			wantCode = 0
		}
		if err != nil || a != v.a || code != wantCode {
			t.Fatalf("%s: ParseJoinAckMux %+v code %d %v, want %+v code %d", v.name, a, code, err, v.a, wantCode)
		}
		// The frame round-trips through the codec.
		fr := AppendFrame(nil, Header{Type: TypeJoinAck, Fseq: 5, Handle: 2}, b[:])
		f, n, err := DecodeFrame(fr)
		if err != nil || n != len(fr) || !bytes.Equal(f.Payload, b[:]) {
			t.Fatalf("%s: frame decode %v (%d of %d)", v.name, err, n, len(fr))
		}
		// A dedicated carrier's parser: OK unchanged, a coded refusal reserved.
		ja, err := ParseJoinAck(b[:])
		switch {
		case v.a.Status == StatusOK && (err != nil || ja != v.a):
			t.Fatalf("%s: ParseJoinAck %+v %v", v.name, ja, err)
		case v.a.Status != StatusOK && v.code != 0 && !errors.Is(err, ErrReserved):
			t.Fatalf("%s: ParseJoinAck of a coded refusal: %v, want ErrReserved", v.name, err)
		case v.a.Status != StatusOK && v.code == 0 && err != nil:
			t.Fatalf("%s: ParseJoinAck of an uncoded refusal: %v", v.name, err)
		}
	}
	// The high half of a refusal's field is reserved.
	bad, _ := hex.DecodeString("020000000100000006")
	if _, _, err := ParseJoinAckMux(bad); !errors.Is(err, ErrReserved) {
		t.Fatalf("a code beyond 32 bits: %v, want ErrReserved", err)
	}
	// M2's rules stay: length and status.
	if _, _, err := ParseJoinAckMux(make([]byte, JoinAckLen-1)); !errors.Is(err, ErrShort) {
		t.Fatalf("short: %v", err)
	}
	if _, _, err := ParseJoinAckMux(make([]byte, JoinAckLen+1)); !errors.Is(err, ErrTrailing) {
		t.Fatalf("trailing: %v", err)
	}
	if _, _, err := ParseJoinAckMux(append([]byte{byte(StatusGoingAway) + 1}, make([]byte, 8)...)); !errors.Is(err, ErrValue) {
		t.Fatalf("status beyond GOING_AWAY: %v", err)
	}
	// PutJoinAck (handle 1, dedicated carriers) never writes a code.
	var b [JoinAckLen]byte
	PutJoinAck(b[:], &JoinAck{Status: StatusCapacity, RxNext: uint64(CodeMuxFull)})
	if hex.EncodeToString(b[:]) != "020000000000000000" {
		t.Fatalf("PutJoinAck refusal %x, want its RxNext zero", b)
	}
	if _, err := ParseJoinAck(bad); !errors.Is(err, ErrReserved) {
		t.Fatalf("dedicated JOIN_ACK with a non-zero reserved field: %v, want ErrReserved", err)
	}
}

// TestJoinAckEndCode_L47 (M4, WP13 B-1; L47): OptEndCode is optional
// PREFACE bit 1, echoed like OptMux, and the golden PREFACE and
// PREFACE_ACK with it differ from M1's only in that bit and the CRC. Under
// it a JOIN_ACK(UNKNOWN_SESSION) on handle 1 carries the ended session's
// RST code in PutJoinAckMux's layout (golden
// join_ack_unknown_session_endcode, 0x5000 in the low half of the RxNext
// field); without it the canonical JOIN_ACK is unchanged (golden
// join_ack_unknown_session), and ParseJoinAck — a dialer that did not
// negotiate the bit — rejects the coded form as ErrReserved.
func TestJoinAckEndCode_L47(t *testing.T) {
	if OptEndCode != 2 || KnownOptional&OptEndCode == 0 || EchoOpt(OptEndCode) != OptEndCode || EchoOpt(OptMux) != OptMux {
		t.Fatalf("OptEndCode %#x, KnownOptional %#x", OptEndCode, KnownOptional)
	}
	for _, pair := range [][2]string{{"preface", "preface_optendcode"}, {"preface_ack_ok", "preface_ack_optendcode"}} {
		plain, ec := goldenByName(t, pair[0]).b, goldenByName(t, pair[1]).b
		if !bytes.Equal(plain[:12], ec[:12]) || !bytes.Equal(plain[16:36], ec[16:36]) || ec[12] != 0 || ec[13] != 0 || ec[14] != 0 || ec[15] != byte(OptEndCode) {
			t.Errorf("%s:\n% x\nwant %s with only opt bit 1 (and the CRC) changed:\n% x", pair[1], ec, pair[0], plain)
		}
	}
	coded := goldenByName(t, "join_ack_unknown_session_endcode").b
	plain := goldenByName(t, "join_ack_unknown_session").b
	pc, pp := coded[HeaderLen:HeaderLen+JoinAckLen], plain[HeaderLen:HeaderLen+JoinAckLen]
	if want := []byte{byte(StatusUnknownSession), 0, 0, 0, 0, 0, 0, 0x50, 0}; !bytes.Equal(pc, want) {
		t.Errorf("coded JOIN_ACK payload % x, want % x", pc, want)
	}
	if !bytes.Equal(coded[:HeaderLen], plain[:HeaderLen]) {
		t.Errorf("the coded JOIN_ACK's header differs from the canonical one's")
	}
	if a, code, err := ParseJoinAckMux(pc); err != nil || a.Status != StatusUnknownSession || a.RxNext != 0 || code != 0x5000 {
		t.Errorf("ParseJoinAckMux(coded) = %+v, %d, %v", a, code, err)
	}
	if _, err := ParseJoinAck(pc); !errors.Is(err, ErrReserved) {
		t.Errorf("ParseJoinAck(coded) = %v, want ErrReserved (a dialer without OptEndCode)", err)
	}
	var b [JoinAckLen]byte
	if PutJoinAckMux(b[:], &JoinAck{Status: StatusUnknownSession}, 0); !bytes.Equal(b[:], pp) {
		t.Errorf("code 0 encodes % x, want the canonical % x", b, pp)
	}
	if a, code, err := ParseJoinAckMux(pp); err != nil || code != 0 || a.Status != StatusUnknownSession {
		t.Errorf("ParseJoinAckMux(canonical) = %+v, %d, %v", a, code, err)
	}
}
