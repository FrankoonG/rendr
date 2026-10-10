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
