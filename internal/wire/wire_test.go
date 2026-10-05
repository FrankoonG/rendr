package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"math"
	"testing"
)

// acceptors lists the top-level decoders that accept b as one whole, valid
// encoding: "preface", "preface_ack", or "frame/<TYPE>" (DecodeFrame
// consuming every byte, then the payload parser of the frame's type).
func acceptors(b []byte) []string {
	var out []string
	if _, err := ParsePreface(b); err == nil {
		out = append(out, "preface")
	}
	if _, err := ParsePrefaceAck(b); err == nil {
		out = append(out, "preface_ack")
	}
	if f, n, err := DecodeFrame(b); err == nil && n == len(b) {
		if _, err := decodeTyped(f.Type, f.Payload); err == nil {
			out = append(out, "frame/"+f.Type.String())
		}
	}
	return out
}

func wantAcceptor(v vector) string {
	if v.kind == "frame" {
		return "frame/" + v.hdr.Type.String()
	}
	return v.kind
}

// reseal recomputes the CRC32C of a 40-byte preface after its fields were edited.
func reseal(b []byte) []byte {
	binary.BigEndian.PutUint32(b[36:40], crc32.Checksum(b[:36], crc32.MakeTable(crc32.Castagnoli)))
	return b
}

// TestDecoderSeedsExactlyOne_L44_L43: every valid encoding is accepted by
// exactly one decoder (L44: the messages are mutually exclusive), no
// truncated-by-1 or extended-by-1 variant is accepted, and no single-bit
// corruption of any vector is accepted by any decoder (L43: the CRC32C
// covers the header and the payload; a spliced header fails it).
func TestDecoderSeedsExactlyOne_L44_L43(t *testing.T) {
	vs := goldenVectors()
	flips := 0
	for _, v := range vs {
		if got := acceptors(v.b); len(got) != 1 || got[0] != wantAcceptor(v) {
			t.Errorf("%s: accepted by %v, want exactly [%s]", v.name, got, wantAcceptor(v))
		}
		if got := acceptors(v.b[:len(v.b)-1]); len(got) != 0 {
			t.Errorf("%s truncated by 1: accepted by %v", v.name, got)
		}
		if got := acceptors(append(bytes.Clone(v.b), 0)); len(got) != 0 {
			t.Errorf("%s extended by 1: accepted by %v", v.name, got)
		}
		// Single-bit corruption: every bit of short vectors, a deterministic
		// spread (header, trailer and a stride through the payload) of long ones.
		c := bytes.Clone(v.b)
		bits := len(c) * 8
		step := 1
		if bits > 8*600 {
			step = bits/2048 + 1
		}
		for i := 0; i < bits; i++ {
			if step > 1 && i >= 8*HeaderLen && i < bits-8*TrailerLen && i%step != 0 {
				continue
			}
			c[i/8] ^= 1 << (i % 8)
			if got := acceptors(c); len(got) != 0 {
				t.Errorf("%s with bit %d flipped: accepted by %v", v.name, i, got)
			}
			c[i/8] ^= 1 << (i % 8)
			flips++
		}
	}
	// Stimulus proof: the corruption sweep actually ran over every vector.
	if flips < 20000 {
		t.Fatalf("only %d single-bit corruptions were checked", flips)
	}

	// Splices: a frame re-stamped with another carrier's fseq, or a header of
	// one frame in front of another's payload, fails the CRC.
	var ack, ackFin []byte
	for _, v := range vs {
		switch v.name {
		case "ack_none":
			ack = v.b
		case "ack_fin_delivered":
			ackFin = v.b
		}
	}
	restamped := bytes.Clone(ack)
	binary.BigEndian.PutUint32(restamped[5:9], 0x77)
	if _, _, err := DecodeFrame(restamped); !errors.Is(err, ErrCRC) {
		t.Errorf("re-stamped fseq: %v, want ErrCRC", err)
	}
	spliced := append(bytes.Clone(ackFin[:HeaderLen]), ack[HeaderLen:]...)
	if _, _, err := DecodeFrame(spliced); !errors.Is(err, ErrCRC) {
		t.Errorf("header of one ACK on another's payload: %v, want ErrCRC", err)
	}
	// Two frames back to back decode one at a time.
	both := append(bytes.Clone(ack), ackFin...)
	if _, n, err := DecodeFrame(both); err != nil || n != len(ack) {
		t.Errorf("concatenated frames: n=%d err=%v, want n=%d", n, err, len(ack))
	}
	if got := acceptors(both); len(got) != 0 {
		t.Errorf("two concatenated frames accepted as one encoding by %v", got)
	}

	// A PREFACE or PREFACE_ACK fed to the frame decoder fails check (1)
	// before its type byte 'R' is looked at: bytes 2–4 ('D', '2', major)
	// read as Len ≥ 0x443200 > MaxFramePayload whatever the major, so the
	// canonical header order of §5.2 makes it ErrLength, not ErrType.
	pre, pack := validPrefaces()
	prefaces := 0
	for _, p := range [][]byte{pre, pack} {
		for major := range 256 {
			b := bytes.Clone(p)
			b[4] = byte(major)
			reseal(b)
			if _, err := ParseHeader(b); !errors.Is(err, ErrLength) {
				t.Errorf("preface % x as a header: %v, want ErrLength", b[:HeaderLen], err)
			}
			if f, n, err := DecodeFrame(b); !errors.Is(err, ErrLength) || n != 0 || f.Payload != nil {
				t.Errorf("preface % x as a frame: n=%d %v, want ErrLength", b[:HeaderLen], n, err)
			}
			prefaces++
		}
	}
	if prefaces != 512 {
		t.Fatalf("%d prefaces fed to the frame decoder, want 512", prefaces)
	}
}

func validPrefaces() (pre, ack []byte) {
	pre = make([]byte, PrefaceLen)
	PutPreface(pre, &Preface{Kind: KindStream, Instance: gDialer, CarrierID: gCarrier})
	ack = make([]byte, PrefaceLen)
	PutPrefaceAck(ack, &PrefaceAck{Status: PrefaceOK, Instance: gPassive, CarrierID: gCarrier})
	return pre, ack
}

// stepSeed is one PREFACE or PREFACE_ACK that fails at exactly one step of
// the canonical order (design §5.1).
type stepSeed struct {
	name string
	role Role
	b    []byte
	want error
}

// prefaceStepSeeds returns, for both directions, one seed per step of the
// canonical order: valid up to the step, damaged at the step and in every
// later field, so the error proves which check runs first.
func prefaceStepSeeds() []stepSeed {
	pre, ack := validPrefaces()
	var out []stepSeed
	for _, d := range []struct {
		name      string
		role      Role
		valid     []byte
		wrongRole byte
		badByte6  byte
	}{
		{"preface", RoleDialer, pre, byte(RolePassive), 9},
		{"preface_ack", RolePassive, ack, byte(RoleDialer), 5},
	} {
		damage := []func(b []byte){
			func(b []byte) { b[3] = '1' },               // magic
			func(b []byte) {},                           // crc (handled below)
			func(b []byte) { b[4] = 3; b[5] = 0x99 },    // major (and the minor)
			func(b []byte) { b[7] = d.wrongRole },       // role
			func(b []byte) { b[6] = d.badByte6 },        // kind / status
			func(b []byte) { clear(b[16:32]) },          // zero instance
			func(b []byte) { clear(b[32:36]) },          // zero carrier ID
			func(b []byte) { b[8] |= 0x80; b[11] |= 1 }, // required bits
		}
		want := []error{ErrMagic, ErrCRC, ErrMajor, ErrMalformed, ErrMalformed, ErrMalformed, ErrMalformed, ErrFeature}
		names := []string{"magic", "crc", "major", "role", "kind_or_status", "zero_instance", "zero_carrier", "required_bits"}
		for i := range damage {
			b := bytes.Clone(d.valid)
			for _, f := range damage[i:] {
				f(b)
			}
			reseal(b)
			if i < 2 {
				b[39] ^= 0x01 // the CRC is wrong for the magic and CRC steps
			}
			out = append(out, stepSeed{d.name + "/" + names[i], d.role, b, want[i]})
		}
		bad := bytes.Clone(d.valid)
		bad[0] = 'X' // length is checked before the magic
		out = append(out,
			stepSeed{d.name + "/length_short", d.role, bad[:PrefaceLen-1], ErrShort},
			stepSeed{d.name + "/length_trailing", d.role, append(bytes.Clone(bad), 0), ErrTrailing},
			stepSeed{d.name + "/empty", d.role, nil, ErrShort},
		)
	}
	return out
}

// TestPrefaceCheckOrder_L44 asserts the exact error of each step of the
// canonical order (design §5.1) for PREFACE and PREFACE_ACK. Every seed is
// valid up to its step and also damaged in every later field, so the error
// proves which check runs first.
func TestPrefaceCheckOrder_L44(t *testing.T) {
	pre, ack := validPrefaces()
	for _, s := range prefaceStepSeeds() {
		var err error
		if s.role == RoleDialer {
			_, err = ParsePreface(s.b)
		} else {
			_, err = ParsePrefaceAck(s.b)
		}
		if !errors.Is(err, s.want) {
			t.Errorf("%s: %v, want %v", s.name, err, s.want)
		}
	}
	type dir struct {
		name     string
		valid    []byte
		parse    func([]byte) error
		badByte6 []byte // invalid kinds / statuses
	}
	dirs := []dir{
		{"preface", pre, func(b []byte) error { _, err := ParsePreface(b); return err }, []byte{0, 3, 9, 0xff}},
		{"preface_ack", ack, func(b []byte) error { _, err := ParsePrefaceAck(b); return err }, []byte{5, 9, 0xff}},
	}
	for _, d := range dirs {
		// Length precedes everything, even a wrong magic.
		bad := bytes.Clone(d.valid)
		bad[0] = 'X'
		if err := d.parse(bad[:PrefaceLen-1]); !errors.Is(err, ErrShort) {
			t.Errorf("%s 39 bytes: %v, want ErrShort", d.name, err)
		}
		if err := d.parse(append(bad, 0)); !errors.Is(err, ErrTrailing) {
			t.Errorf("%s 41 bytes: %v, want ErrTrailing", d.name, err)
		}
		if err := d.parse(nil); !errors.Is(err, ErrShort) {
			t.Errorf("%s empty: %v, want ErrShort", d.name, err)
		}
		// Another major with bytes 5–35 changed and a valid CRC is ErrMajor
		// whatever those bytes hold (P19: only length, magic, major and CRC
		// are stable across majors).
		for _, major := range []byte{0, 1, 3, 255} {
			for seed := range uint32(8) {
				b := bytes.Clone(d.valid)
				b[4] = major
				copy(b[5:36], pattern(31, seed))
				if err := d.parse(reseal(b)); !errors.Is(err, ErrMajor) {
					t.Errorf("%s major %d seed %d: %v, want ErrMajor", d.name, major, seed, err)
				}
			}
		}
		// Every invalid kind / status is ErrMalformed.
		for _, v := range d.badByte6 {
			b := bytes.Clone(d.valid)
			b[6] = v
			if err := d.parse(reseal(b)); !errors.Is(err, ErrMalformed) {
				t.Errorf("%s byte 6 = %d: %v, want ErrMalformed", d.name, v, err)
			}
		}
		// Unknown optional bits are ignored.
		b := bytes.Clone(d.valid)
		binary.BigEndian.PutUint32(b[12:16], 0xffffffff)
		if err := d.parse(reseal(b)); err != nil {
			t.Errorf("%s with unknown optional bits: %v, want nil", d.name, err)
		}
	}

	// ErrFeature comes with the decoded value so the FEATURE answer can echo it.
	b := bytes.Clone(pre)
	binary.BigEndian.PutUint32(b[8:12], 1)
	p, err := ParsePreface(reseal(b))
	if !errors.Is(err, ErrFeature) || p.Req != 1 || p.CarrierID != gCarrier || p.Instance != gDialer || p.Kind != KindStream {
		t.Errorf("required bit: %+v, %v; want the decoded preface with ErrFeature", p, err)
	}
	b = bytes.Clone(ack)
	binary.BigEndian.PutUint32(b[8:12], 2)
	a, err := ParsePrefaceAck(reseal(b))
	if !errors.Is(err, ErrFeature) || a.Req != 2 || a.CarrierID != gCarrier || a.Instance != gPassive {
		t.Errorf("ack required bit: %+v, %v; want the decoded ack with ErrFeature", a, err)
	}
	// The two directions never accept each other (role byte).
	if _, err := ParsePrefaceAck(pre); !errors.Is(err, ErrMalformed) {
		t.Errorf("PREFACE fed to ParsePrefaceAck: %v, want ErrMalformed", err)
	}
	if _, err := ParsePreface(ack); !errors.Is(err, ErrMalformed) {
		t.Errorf("PREFACE_ACK fed to ParsePreface: %v, want ErrMalformed", err)
	}
	// A datagram PREFACE is well-formed at the wire level (M2 kind).
	b = bytes.Clone(pre)
	b[6] = byte(KindDatagram)
	if p, err := ParsePreface(reseal(b)); err != nil || p.Kind != KindDatagram {
		t.Errorf("datagram preface: %+v, %v", p, err)
	}
}

// legacyV1Hello returns the first bytes a v1 dialer (protocol 1.22) writes on
// a TCP path: u16 length prefix | 8-byte v1 header (VER 3, CTRL, control code
// HELLO = 0x01, seq 0) | HELLO payload (negotiation, flow ID, instance, caps,
// initial target, receive capacity, manifest length, manifest).
func legacyV1Hello(code byte) []byte {
	var p []byte
	p = binary.BigEndian.AppendUint16(p, 1)    // protocol major
	p = binary.BigEndian.AppendUint16(p, 22)   // protocol minor
	p = binary.BigEndian.AppendUint32(p, 0)    // mobility supported, required
	p = binary.BigEndian.AppendUint64(p, 0x7f) // supported features
	p = binary.BigEndian.AppendUint64(p, 0x07) // required features
	p = append(p, pattern(16, 1)...)           // session epoch
	p = binary.BigEndian.AppendUint64(p, 1)    // graph revision
	p = append(p, pattern(32, 2)...)           // graph digest
	p = append(p, pattern(16, 1)...)           // flow ID
	p = append(p, gDialer[:]...)               // instance ID
	p = binary.BigEndian.AppendUint32(p, 0)    // caps
	p = append(p, pattern(16, 3)...)           // initial target
	p = binary.BigEndian.AppendUint32(p, 1200) // receive frame capacity
	manifest := pattern(64, 4)
	p = binary.BigEndian.AppendUint32(p, uint32(len(manifest)))
	p = append(p, manifest...)
	frame := append([]byte{0xe0, code, 0, 0, 0, 0, 0, 0}, p...)
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(frame))), frame...)
}

// legacyMsessHello returns an msess (M1a) HELLO: "HMS" | version 1 | kind |
// sid[16] | sub u32 | rxNext u64 | mode u8 | grace u16 | tlen u16 | target.
func legacyMsessHello(kind byte, target string) []byte {
	b := append([]byte("HMS"), 1, kind)
	b = append(b, gSID[:]...)
	b = binary.BigEndian.AppendUint32(b, 1)
	b = binary.BigEndian.AppendUint64(b, 0)
	b = append(b, 1)
	b = binary.BigEndian.AppendUint16(b, 15)
	b = binary.BigEndian.AppendUint16(b, uint16(len(target)))
	return append(b, target...)
}

// legacyMsessHelloAck returns an msess HELLO_ACK: "HMS" | 1 | status |
// rxNext u64 | mlen u16 | msg.
func legacyMsessHelloAck(status byte, msg string) []byte {
	b := append([]byte("HMS"), 1, status)
	b = binary.BigEndian.AppendUint64(b, 0)
	b = binary.BigEndian.AppendUint16(b, uint16(len(msg)))
	return append(b, msg...)
}

func legacyHandshakes() []struct {
	name string
	b    []byte
} {
	return []struct {
		name string
		b    []byte
	}{
		{"v1_hello", legacyV1Hello(0x01)},
		{"v1_hello_ack", legacyV1Hello(0x09)},
		{"msess_open", legacyMsessHello(1, "127.0.0.1:7")},
		{"msess_join", legacyMsessHello(2, "")},
		{"msess_probe", legacyMsessHello(3, "")},
		{"msess_open_packet", legacyMsessHello(4, "127.0.0.1:53")},
		{"msess_hello_ack", legacyMsessHelloAck(0, "")},
		{"msess_hello_ack_msg", legacyMsessHelloAck(1, "unknown session")},
	}
}

// TestLegacyHandshakesRejected_L44: v1 and msess handshakes are rejected
// cleanly as "not rendr" (ErrMagic once 40 bytes are present; ErrShort for a
// shorter message, on which the passive simply waits for its deadline), by
// both preface decoders, and no decoder accepts any of their bytes.
func TestLegacyHandshakesRejected_L44(t *testing.T) {
	for _, c := range legacyHandshakes() {
		// The passive reads exactly PrefaceLen bytes before deciding; a
		// dialer reads exactly PrefaceLen bytes of the answer.
		head := c.b[:min(len(c.b), PrefaceLen)]
		want := ErrMagic
		if len(c.b) < PrefaceLen {
			want = ErrShort
		}
		if _, err := ParsePreface(head); !errors.Is(err, want) {
			t.Errorf("%s: ParsePreface(first %d bytes) = %v, want %v", c.name, len(head), err, want)
		}
		if _, err := ParsePrefaceAck(head); !errors.Is(err, want) {
			t.Errorf("%s: ParsePrefaceAck(first %d bytes) = %v, want %v", c.name, len(head), err, want)
		}
		if _, err := ParsePreface(c.b); err == nil {
			t.Errorf("%s: whole message accepted by ParsePreface", c.name)
		}
		// As a frame the bytes fail the header checks in their canonical
		// order: these carry a length beyond MaxFramePayload in bytes 2–4.
		if _, _, err := DecodeFrame(c.b); err == nil || !errors.Is(err, refHeaderErr(c.b)) {
			t.Errorf("%s: DecodeFrame = %v, want %v", c.name, err, refHeaderErr(c.b))
		}
		if got := acceptors(c.b); len(got) != 0 {
			t.Errorf("%s: accepted by %v", c.name, got)
		}
		if got := acceptors(head); len(got) != 0 {
			t.Errorf("%s (first %d bytes): accepted by %v", c.name, len(head), got)
		}
	}
}

// TestNonCanonicalAnswersRejected_L44 (C32): the fields of OPEN_ACK and
// JOIN_ACK that have no meaning for a status are reserved zero. The
// encoders write them whatever the caller's struct holds; the parsers reject
// any other value with ErrReserved.
func TestNonCanonicalAnswersRejected_L44(t *testing.T) {
	buf := make([]byte, 512)
	// Encoders canonicalize.
	n := PutOpenAck(buf, &OpenAck{Status: StatusOK, Window: 77, Code: 5, Msg: []byte("ignored")})
	if a, err := ParseOpenAck(buf[:n]); err != nil || a.Window != 77 || a.Code != 0 || a.Msg != nil || n != OpenAckFixedLen {
		t.Errorf("OK OPEN_ACK from a non-canonical struct: n=%d %+v %v", n, a, err)
	}
	for st := StatusUnknownSession; st <= StatusGoingAway; st++ {
		n := PutOpenAck(buf, &OpenAck{Status: st, Window: 77, Code: 9, Msg: []byte("m")})
		if a, err := ParseOpenAck(buf[:n]); err != nil || a.Window != 0 || a.Code != 9 || string(a.Msg) != "m" {
			t.Errorf("status %d OPEN_ACK from a non-canonical struct: %+v %v", st, a, err)
		}
		n = PutJoinAck(buf, &JoinAck{Status: st, RxNext: 99})
		if a, err := ParseJoinAck(buf[:n]); err != nil || a.RxNext != 0 {
			t.Errorf("status %d JOIN_ACK from a non-canonical struct: %+v %v", st, a, err)
		}
	}
	// Parsers reject every non-canonical zero field.
	openAck := func(status byte, window, code uint32, msg string) []byte {
		b := []byte{status}
		b = binary.BigEndian.AppendUint32(b, window)
		b = binary.BigEndian.AppendUint32(b, code)
		return append(append(b, byte(len(msg))), msg...)
	}
	for _, p := range nonCanonicalAnswers() {
		var err error
		if p.t == TypeOpenAck {
			_, err = ParseOpenAck(p.p)
		} else {
			_, err = ParseJoinAck(p.p)
		}
		if !errors.Is(err, ErrReserved) {
			t.Errorf("%s: %v, want ErrReserved", p.name, err)
		}
	}
	// The canonical forms of the same answers are accepted.
	if _, err := ParseOpenAck(openAck(0, 1<<20, 0, "")); err != nil {
		t.Errorf("canonical OK: %v", err)
	}
	if _, err := ParseOpenAck(openAck(3, 0, 42, "no")); err != nil {
		t.Errorf("canonical REJECTED: %v", err)
	}
}

type rawPayload struct {
	name string
	t    Type
	p    []byte
}

// nonCanonicalAnswers lists every non-canonical zero field of OPEN_ACK and
// JOIN_ACK (also used as fuzz seeds).
func nonCanonicalAnswers() []rawPayload {
	openAck := func(status byte, window, code uint32, msg string) []byte {
		b := []byte{status}
		b = binary.BigEndian.AppendUint32(b, window)
		b = binary.BigEndian.AppendUint32(b, code)
		return append(append(b, byte(len(msg))), msg...)
	}
	joinAck := func(status byte, rx uint64) []byte {
		return binary.BigEndian.AppendUint64([]byte{status}, rx)
	}
	out := []rawPayload{
		{"open_ack_ok_code", TypeOpenAck, openAck(0, 1<<20, 1, "")},
		{"open_ack_ok_msg", TypeOpenAck, openAck(0, 1<<20, 0, "x")},
		{"open_ack_ok_code_msg", TypeOpenAck, openAck(0, 0, 7, "why")},
	}
	for st := byte(1); st <= byte(StatusGoingAway); st++ {
		out = append(out,
			rawPayload{"open_ack_" + ackStatusNames[st] + "_window", TypeOpenAck, openAck(st, 1, 0, "")},
			rawPayload{"join_ack_" + ackStatusNames[st] + "_rxnext", TypeJoinAck, joinAck(st, 1)},
		)
	}
	return out
}

// TestPayloadErrors_L44: every parser rejects short input, trailing bytes,
// out-of-range values and non-zero reserved fields with the documented error.
func TestPayloadErrors_L44(t *testing.T) {
	sid := gSID[:]
	open := func(kind, mode byte, flags, pmtu, mlen uint16, meta string) []byte {
		b := append([]byte(nil), sid...)
		b = append(b, kind, mode)
		b = binary.BigEndian.AppendUint16(b, flags)
		b = binary.BigEndian.AppendUint32(b, 1000)
		b = binary.BigEndian.AppendUint32(b, 1<<20)
		b = binary.BigEndian.AppendUint16(b, pmtu)
		b = binary.BigEndian.AppendUint16(b, mlen)
		return append(b, meta...)
	}
	zeroSID := func(b []byte) []byte { clear(b[:16]); return b }
	sched := func(n byte, ids ...uint32) []byte {
		b := binary.BigEndian.AppendUint32(nil, 1)
		b = append(b, make([]byte, 24)...) // the migration counts
		b = append(b, n)
		for _, id := range ids {
			b = binary.BigEndian.AppendUint32(b, id)
		}
		return b
	}
	ping := func(pad []byte) []byte { return append(make([]byte, PingFixedLen), pad...) }
	type tc struct {
		name string
		err  error
		got  error
	}
	e := func(_ any, err error) error { return err }
	cases := []tc{
		{"open short", ErrShort, e(ParseOpen(open(1, 1, 0, 0, 0, "")[:31], 100))},
		{"open meta short", ErrShort, e(ParseOpen(open(1, 1, 0, 0, 3, "ab"), 100))},
		{"open meta trailing", ErrTrailing, e(ParseOpen(open(1, 1, 0, 0, 1, "ab"), 100))},
		// mlen beyond the limit is reported before the metadata is looked
		// at: the payload here holds none of it.
		{"open mlen > maxMeta before reading", ErrLength, e(ParseOpen(open(1, 1, 0, 0, 101, ""), 100))},
		{"open mlen > MaxMetadata clamp", nil, e(ParseOpen(open(1, 1, 0, 0, 3, "abc"), 1<<20))},
		{"open negative maxMeta", ErrLength, e(ParseOpen(open(1, 1, 0, 0, 1, "a"), -5))},
		{"open zero sid", ErrReserved, e(ParseOpen(zeroSID(open(1, 1, 0, 0, 0, "")), 100))},
		{"open kind 0", ErrValue, e(ParseOpen(open(0, 1, 0, 0, 0, ""), 100))},
		{"open kind 3", ErrValue, e(ParseOpen(open(3, 1, 0, 0, 0, ""), 100))},
		{"open mode 0", ErrValue, e(ParseOpen(open(1, 0, 0, 0, 0, ""), 100))},
		{"open mode 4", ErrValue, e(ParseOpen(open(1, 4, 0, 0, 0, ""), 100))},
		{"open mode 3 decodes", nil, e(ParseOpen(open(1, 3, 0, 0, 0, ""), 100))},
		{"open early flag", ErrReserved, e(ParseOpen(open(1, 1, OpenFlagEarly, 0, 0, ""), 100))},
		{"open undefined flag", ErrReserved, e(ParseOpen(open(1, 1, 0x8000, 0, 0, ""), 100))},
		{"open stream pmtu", ErrReserved, e(ParseOpen(open(1, 1, 0, 1200, 0, ""), 100))},
		{"open datagram pmtu", nil, e(ParseOpen(open(2, 1, 0, 1200, 0, ""), 100))},
		{"open_ack short", ErrShort, e(ParseOpenAck(make([]byte, 9)))},
		{"open_ack msg short", ErrShort, e(ParseOpenAck(append(make([]byte, 9), 1)))},
		{"open_ack msg trailing", ErrTrailing, e(ParseOpenAck(append(make([]byte, 10), 'x')))},
		{"open_ack status 6", ErrValue, e(ParseOpenAck(append([]byte{6}, make([]byte, 9)...)))},
		{"open_ack status 255", ErrValue, e(ParseOpenAck(append([]byte{255}, make([]byte, 9)...)))},
		{"join short", ErrShort, e(ParseJoin(make([]byte, JoinLen-1)))},
		{"join trailing", ErrTrailing, e(ParseJoin(append(append(append([]byte(nil), sid...), 1), make([]byte, 9)...)))},
		{"join zero sid", ErrReserved, e(ParseJoin(append(make([]byte, 16), append([]byte{1}, make([]byte, 8)...)...)))},
		{"join mode 0", ErrValue, e(ParseJoin(append(append([]byte(nil), sid...), append([]byte{0}, make([]byte, 8)...)...)))},
		{"join mode 4", ErrValue, e(ParseJoin(append(append([]byte(nil), sid...), append([]byte{4}, make([]byte, 8)...)...)))},
		{"join_ack short", ErrShort, e(ParseJoinAck(make([]byte, 8)))},
		{"join_ack trailing", ErrTrailing, e(ParseJoinAck(make([]byte, 10)))},
		{"join_ack status 6", ErrValue, e(ParseJoinAck(append([]byte{6}, make([]byte, 8)...)))},
		{"data empty", ErrLength, e(ParseDataOffset(nil))},
		{"data offset only", ErrLength, e(ParseDataOffset(make([]byte, 8)))},
		{"data overflow", ErrValue, e(ParseDataOffset(append(binary.BigEndian.AppendUint64(nil, 1<<64-2), 1, 2)))},
		{"data end at 2^64", ErrValue, e(ParseDataOffset(append(binary.BigEndian.AppendUint64(nil, 1<<64-1), 1)))},
		{"data end at 2^64-1", nil, e(ParseDataOffset(append(binary.BigEndian.AppendUint64(nil, 1<<64-2), 1)))},
		{"ack short", ErrShort, e(ParseAck(make([]byte, 15)))},
		{"ack trailing", ErrTrailing, e(ParseAck(make([]byte, 17)))},
		{"fin short", ErrShort, e(ParseFin(make([]byte, 7)))},
		{"fin trailing", ErrTrailing, e(ParseFin(make([]byte, 9)))},
		{"rst short", ErrShort, e(ParseRst(make([]byte, 4)))},
		{"rst msg short", ErrShort, e(ParseRst([]byte{0, 0, 0, 1, 2, 'x'}))},
		{"rst msg trailing", ErrTrailing, e(ParseRst([]byte{0, 0, 0, 1, 0, 'x'}))},
		{"rst unknown code", nil, e(ParseRst([]byte{0, 0, 0xff, 0xff, 0}))},
		{"sched short", ErrShort, e(ParseSched(make([]byte, 4)))},
		{"sched counts short", ErrShort, e(ParseSched(make([]byte, SchedFixedLen-1)))},
		{"sched n 0", ErrValue, e(ParseSched(sched(0)))},
		{"sched n 17", ErrValue, e(ParseSched(sched(17, make([]uint32, 17)...)))},
		{"sched ids short", ErrShort, e(ParseSched(sched(2, 1)))},
		{"sched ids trailing", ErrTrailing, e(ParseSched(sched(1, 1, 2)))},
		{"sched zero id", ErrValue, e(ParseSched(sched(2, 1, 0)))},
		{"sched duplicate id", ErrValue, e(ParseSched(sched(3, 1, 2, 1)))},
		{"ping short", ErrShort, e(ParsePing(make([]byte, 19)))},
		{"ping pad non-zero", ErrReserved, e(ParsePing(ping([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 1})))},
		{"ping pad too long", ErrLength, e(ParsePing(make([]byte, PingFixedLen+MaxPingPad+1)))},
		{"ping pad max", nil, e(ParsePing(make([]byte, PingFixedLen+MaxPingPad)))},
		{"close empty", ErrShort, e(ParseClose(nil))},
		{"close trailing", ErrTrailing, e(ParseClose([]byte{1, 0}))},
		{"close reason 0", ErrValue, e(ParseClose([]byte{0}))},
		{"close reason 3", ErrValue, e(ParseClose([]byte{3}))},
		{"goaway empty", ErrShort, e(ParseGoAway(nil))},
		{"goaway trailing", ErrTrailing, e(ParseGoAway([]byte{1, 1}))},
		{"goaway reason 0", ErrValue, e(ParseGoAway([]byte{0}))},
		{"goaway reason 2", ErrValue, e(ParseGoAway([]byte{2}))},
	}
	for _, c := range cases {
		if !errors.Is(c.got, c.err) || (c.err == nil && c.got != nil) {
			t.Errorf("%s: %v, want %v", c.name, c.got, c.err)
		}
	}
}

// TestDataEndAndCheckPad_L42_L44: the DATA end rule and the PING pad rule
// exist once, in package wire (design §0.7 W2; L42: one helper validates),
// for the reader that holds a big DATA payload in its own buffer or streams
// a large pad. DataEnd rejects an empty or oversize data length (ErrLength,
// checked first) and an end beyond 2^64 − 1 (ErrValue); CheckPad accepts
// only zero bytes, wherever a non-zero one sits (in the 8-byte word loop or
// the tail). ParseDataOffset and ParsePing give the same verdicts on
// contiguous payloads, a pad checked chunk by chunk gives the verdict of
// the whole pad, and neither helper allocates (non-race lane).
func TestDataEndAndCheckPad_L42_L44(t *testing.T) {
	const maxData = MaxFramePayload - DataPrefixLen
	payload := make([]byte, MaxFramePayload+1) // DATA payloads: offset prefix, then zero data
	for _, c := range []struct {
		name string
		off  uint64
		n    int
		end  uint64
		err  error
	}{
		{"one byte at 0", 0, 1, 1, nil},
		{"max data at 0", 0, maxData, maxData, nil},
		{"offset 2^62", 1 << 62, 64 << 10, 1<<62 + 64<<10, nil},
		{"empty", 5, 0, 0, ErrLength},
		{"negative", 5, -1, 0, ErrLength},
		{"one beyond max", 0, maxData + 1, 0, ErrLength},
		{"length checked before the end", math.MaxUint64, 0, 0, ErrLength},
		{"end at 2^64-1", math.MaxUint64 - 1, 1, math.MaxUint64, nil},
		{"end at 2^64", math.MaxUint64, 1, 0, ErrValue},
		{"max data ending at 2^64-1", math.MaxUint64 - maxData, maxData, math.MaxUint64, nil},
		{"max data ending at 2^64", math.MaxUint64 - maxData + 1, maxData, 0, ErrValue},
	} {
		end, err := DataEnd(c.off, c.n)
		if end != c.end || !sameErr(err, c.err) {
			t.Errorf("DataEnd %s (off %d, n %d) = %d, %v; want %d, %v", c.name, c.off, c.n, end, err, c.end, c.err)
		}
		if c.n < 0 {
			continue
		}
		p := payload[:DataPrefixLen+c.n]
		PutDataOffset(p, c.off)
		wantOff := c.off
		if c.err != nil {
			wantOff = 0
		}
		if off, err := ParseDataOffset(p); off != wantOff || !sameErr(err, c.err) {
			t.Errorf("ParseDataOffset %s = %d, %v; want %d, %v", c.name, off, err, wantOff, c.err)
		}
	}
	if off, err := ParseDataOffset(payload[:DataPrefixLen-1]); off != 0 || !errors.Is(err, ErrLength) {
		t.Errorf("ParseDataOffset of a partial offset = %d, %v; want ErrLength", off, err)
	}

	pad := make([]byte, MaxPingPad)
	ping := make([]byte, PingFixedLen+MaxPingPad)
	for _, n := range []int{0, 1, 7, 8, 9, 16, 17, 1000, MaxPingPad} {
		at := []int{-1} // -1: all zero; else the index of the one non-zero byte
		for i := range n {
			if n <= 17 || i == 0 || i == 7 || i == 8 || i == n/2 || i == n-8 || i == n-1 {
				at = append(at, i)
			}
		}
		for _, i := range at {
			b := pad[:n]
			clear(b)
			var want error
			if i >= 0 {
				b[i], want = 1<<(i%8), ErrReserved
			}
			if err := CheckPad(b); !sameErr(err, want) {
				t.Errorf("CheckPad of %d bytes, non-zero at %d: %v, want %v", n, i, err, want)
			}
			copy(ping[PingFixedLen:], b)
			if pg, err := ParsePing(ping[:PingFixedLen+n]); !sameErr(err, want) || (err == nil && pg.Pad != n) {
				t.Errorf("ParsePing with a %d-byte pad, non-zero at %d: pad %d, %v; want %v", n, i, pg.Pad, err, want)
			}
			for _, chunk := range []int{1, 5, 8, 4096} {
				var got error
				for rest := b; len(rest) > 0 && got == nil; rest = rest[min(chunk, len(rest)):] {
					got = CheckPad(rest[:min(chunk, len(rest))])
				}
				if !sameErr(got, want) {
					t.Errorf("CheckPad in %d-byte chunks of %d bytes, non-zero at %d: %v, want %v", chunk, n, i, got, want)
				}
			}
		}
	}

	zero, dirty := make([]byte, MaxPingPad), make([]byte, MaxPingPad)
	dirty[len(dirty)-1] = 0x80
	if a := testing.AllocsPerRun(100, func() {
		sinkU64, sinkErr = DataEnd(1<<40, maxData)
		_, sinkErr = DataEnd(math.MaxUint64, 1)
		_, sinkErr = DataEnd(0, 0)
		sinkErr = CheckPad(zero)
		sinkErr = CheckPad(dirty)
	}); a != 0 && !raceEnabled {
		t.Errorf("DataEnd and CheckPad: %v allocs", a)
	}
}

// TestParseHeaderRules_L44 sweeps every type byte, flag bit, handle class and
// length bound of design §5.2 checks (1)–(5), including their order.
func TestParseHeaderRules_L44(t *testing.T) {
	hdr := func(typ, flags byte, length, handle uint32) []byte {
		b := make([]byte, HeaderLen)
		b[0], b[1] = typ, flags
		b[2], b[3], b[4] = byte(length>>16), byte(length>>8), byte(length)
		binary.BigEndian.PutUint32(b[5:9], 0xfffffff0)
		binary.BigEndian.PutUint32(b[9:13], handle)
		return b
	}
	accepted := 0
	for i := range 256 {
		ty := Type(i)
		lo, hi, ok := PayloadBounds(ty)
		handle := uint32(SessionHandle)
		if ty.CarrierLevel() {
			handle = 0
		}
		_, err := ParseHeader(hdr(byte(i), 0, uint32(lo), handle))
		switch {
		case ty.Known() || ty.Extension():
			if !ok || err != nil {
				t.Errorf("type %v: ok=%v err=%v, want accepted", ty, ok, err)
			}
			accepted++
		default:
			if ok || !errors.Is(err, ErrType) {
				t.Errorf("type %v: ok=%v err=%v, want ErrType", ty, ok, err)
			}
		}
		if !ok {
			continue
		}
		// Length bounds.
		if lo > 0 && !ty.Extension() {
			if _, err := ParseHeader(hdr(byte(i), 0, uint32(lo-1), handle)); !errors.Is(err, ErrLength) {
				t.Errorf("type %v len %d: %v, want ErrLength", ty, lo-1, err)
			}
		}
		if _, err := ParseHeader(hdr(byte(i), 0, uint32(hi), handle)); err != nil {
			t.Errorf("type %v len %d (max): %v", ty, hi, err)
		}
		if hi < MaxFramePayload {
			if _, err := ParseHeader(hdr(byte(i), 0, uint32(hi+1), handle)); !errors.Is(err, ErrLength) {
				t.Errorf("type %v len %d: %v, want ErrLength", ty, hi+1, err)
			}
		}
		// Flags: every undefined bit of a core type is rejected; extension
		// flags are opaque.
		for bit := range 8 {
			f := byte(1) << bit
			_, err := ParseHeader(hdr(byte(i), f, uint32(lo), handle))
			if ty.Extension() || AllowedFlags(ty)&f != 0 {
				if err != nil {
					t.Errorf("type %v flag %#x: %v, want accepted", ty, f, err)
				}
			} else if !errors.Is(err, ErrFlags) {
				t.Errorf("type %v flag %#x: %v, want ErrFlags", ty, f, err)
			}
		}
		// Handles (design §0.7 W1): carrier-level frames need 0, session
		// frames exactly SessionHandle (M1: one session per carrier), so 0,
		// 2 and 0xffffffff are ErrHandle on a session frame; extension
		// handles are opaque.
		for _, hd := range []uint32{0, 1, 2, 0xffffffff} {
			_, err := ParseHeader(hdr(byte(i), 0, uint32(lo), hd))
			wantOK := ty.Extension() || (ty.CarrierLevel() && hd == 0) || (!ty.CarrierLevel() && hd == SessionHandle)
			if wantOK != (err == nil) || (!wantOK && !errors.Is(err, ErrHandle)) {
				t.Errorf("type %v handle %d: %v (want accepted: %v)", ty, hd, err, wantOK)
			}
		}
	}
	if accepted != 13+128 {
		t.Fatalf("%d type bytes accepted, want 13 core + 128 extension", accepted)
	}
	// M2 types are unknown core types in M1.
	for _, ty := range []byte{0x20, 0x21, 0x34, 0x35, 0x00, 0x7f, 'R'} {
		if _, err := ParseHeader(hdr(ty, 0, 9, 1)); !errors.Is(err, ErrType) {
			t.Errorf("type %#x: %v, want ErrType", ty, err)
		}
	}
	// (1) precedes (2)..(5): an oversize length is ErrLength even for an
	// unknown type, bad flags or a bad handle, and for extensions.
	for _, b := range [][]byte{
		hdr(0x7f, 0xff, MaxFramePayload+1, 0),
		hdr(byte(TypeAck), 0xff, MaxFramePayload+1, 0),
		hdr(0x80, 0, MaxFramePayload+1, 0),
		hdr(byte(TypeData), 0, 0xffffff, 1),
	} {
		if _, err := ParseHeader(b); !errors.Is(err, ErrLength) {
			t.Errorf("oversize header % x: %v, want ErrLength", b, err)
		}
	}
	// (2) precedes (3), (3) precedes (4), (4) precedes (5).
	if _, err := ParseHeader(hdr(0x20, 0xff, 1, 0)); !errors.Is(err, ErrType) {
		t.Errorf("unknown type with bad flags: %v, want ErrType", err)
	}
	if _, err := ParseHeader(hdr(byte(TypeFin), 0x01, 3, 0)); !errors.Is(err, ErrFlags) {
		t.Errorf("FIN with a flag, handle 0 and a bad length: %v, want ErrFlags", err)
	}
	if _, err := ParseHeader(hdr(byte(TypePing), 0, 3, 1)); !errors.Is(err, ErrHandle) {
		t.Errorf("PING with handle 1 and a bad length: %v, want ErrHandle", err)
	}
	if _, err := ParseHeader(hdr(byte(TypeAck), 0, 3, 2)); !errors.Is(err, ErrHandle) {
		t.Errorf("ACK with handle 2 and a bad length: %v, want ErrHandle", err)
	}
	if _, err := ParseHeader(make([]byte, HeaderLen-1)); !errors.Is(err, ErrShort) {
		t.Errorf("12-byte header: %v, want ErrShort", err)
	}
	// Bytes after the header are ignored.
	if h, err := ParseHeader(append(hdr(byte(TypeAck), 3, AckLen, SessionHandle), 1, 2, 3)); err != nil || h.Flags != 3 || h.Handle != SessionHandle || h.Len != AckLen || h.Fseq != 0xfffffff0 {
		t.Errorf("header with trailing bytes: %+v %v", h, err)
	}
	// An extension header decodes its handle as given.
	if h, err := ParseHeader(hdr(0x9a, 0x5a, 7, 0x01020304)); err != nil || h.Type != 0x9a || h.Flags != 0x5a || h.Handle != 0x01020304 || h.Len != 7 {
		t.Errorf("extension header: %+v %v", h, err)
	}
}

// TestDecodeFrameIncremental_L42: every proper prefix of a valid frame is
// ErrShort (no partial frame is ever returned), a header error is reported
// as soon as the 13 header bytes exist (nothing waits for or sizes anything
// by an invalid length), and the payload cannot be grown over the trailer.
func TestDecodeFrameIncremental_L42(t *testing.T) {
	for _, v := range goldenVectors() {
		if v.kind != "frame" || len(v.b) > 4096 {
			continue
		}
		for i := range len(v.b) {
			if f, n, err := DecodeFrame(v.b[:i]); !errors.Is(err, ErrShort) || n != 0 || f.Payload != nil {
				t.Fatalf("%s prefix %d: n=%d err=%v", v.name, i, n, err)
			}
		}
		f, n, err := DecodeFrame(v.b)
		if err != nil || n != len(v.b) || cap(f.Payload) != len(f.Payload) {
			t.Fatalf("%s: n=%d err=%v cap=%d len=%d", v.name, n, err, cap(f.Payload), len(f.Payload))
		}
	}
	oversize := make([]byte, HeaderLen)
	oversize[0], oversize[2], oversize[4] = byte(TypeData), 0x10, 0x01 // len = MaxFramePayload + 1
	binary.BigEndian.PutUint32(oversize[9:13], 1)
	if _, n, err := DecodeFrame(oversize); !errors.Is(err, ErrLength) || n != 0 {
		t.Fatalf("header claiming MaxFramePayload+1: n=%d err=%v, want ErrLength at once", n, err)
	}
}

// TestPutPanics: programming errors in encoders panic instead of emitting a
// frame the peer would reject.
func TestPutPanics(t *testing.T) {
	big := make([]byte, 2*MaxFramePayload)
	for name, f := range map[string]func(){
		"PutHeader len":       func() { PutHeader(big, &Header{Type: TypeData, Len: MaxFramePayload + 1}) },
		"PutHeader short":     func() { PutHeader(big[:HeaderLen-1], &Header{}) },
		"PutPreface short":    func() { PutPreface(big[:PrefaceLen-1], &Preface{}) },
		"PutPrefaceAck short": func() { PutPrefaceAck(big[:PrefaceLen-1], &PrefaceAck{}) },
		"PutOpen meta":        func() { PutOpen(big, &Open{Metadata: big[:MaxMetadata+1]}) },
		"PutOpen short":       func() { PutOpen(big[:OpenFixedLen+2], &Open{Metadata: big[:3]}) },
		"PutOpenAck msg":      func() { PutOpenAck(big, &OpenAck{Status: StatusRejected, Msg: big[:MaxMsg+1]}) },
		"PutRst msg":          func() { PutRst(big, &Rst{Msg: big[:MaxMsg+1]}) },
		"PutSched n0":         func() { PutSched(big, &Sched{N: 0}) },
		"PutSched n17":        func() { PutSched(big, &Sched{N: MaxSchedIDs + 1}) },
		"PutPing pad":         func() { PutPing(big, &Ping{Pad: MaxPingPad + 1}) },
		"PutPing negative":    func() { PutPing(big, &Ping{Pad: -1}) },
		"PutAck short":        func() { PutAck(big[:AckLen-1], &Ack{}) },
		"AppendFrame":         func() { AppendFrame(nil, Header{Type: TypeData}, big[:MaxFramePayload+1]) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: no panic", name)
				}
			}()
			f()
		}()
	}
}

// Sinks keep the compiler from discarding decoded values in allocation tests.
var (
	sinkPreface    Preface
	sinkPrefaceAck PrefaceAck
	sinkHeader     Header
	sinkFrame      Frame
	sinkOpen       Open
	sinkOpenAck    OpenAck
	sinkJoin       Join
	sinkJoinAck    JoinAck
	sinkU64        uint64
	sinkAck        Ack
	sinkRst        Rst
	sinkSched      Sched
	sinkPing       Ping
	sinkClose      CloseReason
	sinkGoAway     GoAwayReason
	sinkErr        error
	sinkN          int
)

// decodeConcrete runs the decoder of v without boxing results in interfaces.
func decodeConcrete(b []byte) {
	if len(b) == PrefaceLen && b[0] == 'R' {
		sinkPreface, sinkErr = ParsePreface(b)
		sinkPrefaceAck, sinkErr = ParsePrefaceAck(b)
		return
	}
	sinkHeader, sinkErr = ParseHeader(b)
	sinkFrame, sinkN, sinkErr = DecodeFrame(b)
	p := sinkFrame.Payload
	switch sinkFrame.Type {
	case TypeOpen:
		sinkOpen, sinkErr = ParseOpen(p, MaxMetadata)
	case TypeOpenAck:
		sinkOpenAck, sinkErr = ParseOpenAck(p)
	case TypeJoin:
		sinkJoin, sinkErr = ParseJoin(p)
	case TypeJoinAck:
		sinkJoinAck, sinkErr = ParseJoinAck(p)
	case TypeData:
		sinkU64, sinkErr = ParseDataOffset(p)
	case TypeAck:
		sinkAck, sinkErr = ParseAck(p)
	case TypeFin:
		sinkU64, sinkErr = ParseFin(p)
	case TypeRst:
		sinkRst, sinkErr = ParseRst(p)
	case TypeSched:
		sinkSched, sinkErr = ParseSched(p)
	case TypePing, TypePong:
		sinkPing, sinkErr = ParsePing(p)
	case TypeClose:
		sinkClose, sinkErr = ParseClose(p)
	case TypeGoAway:
		sinkGoAway, sinkErr = ParseGoAway(p)
	}
}

// TestCodecZeroAllocs_L41_L44: every decoder and every encoder (into caller
// memory) allocates nothing, for every golden vector and every error path.
func TestCodecZeroAllocs_L41_L44(t *testing.T) {
	vs := goldenVectors()
	for _, v := range vs {
		b := v.b
		if a := testing.AllocsPerRun(20, func() { decodeConcrete(b) }); a != 0 {
			t.Errorf("decoding %s: %v allocs", v.name, a)
		}
		bad := bytes.Clone(v.b)
		bad[len(bad)-1] ^= 0xff
		if a := testing.AllocsPerRun(20, func() { decodeConcrete(bad) }); a != 0 {
			t.Errorf("rejecting corrupted %s: %v allocs", v.name, a)
		}
	}
	dst := make([]byte, 2*MaxFramePayload)
	meta := pattern(MaxMetadata, 1)
	msg := pattern(MaxMsg, 2)
	pre := Preface{Kind: KindStream, Instance: gDialer, CarrierID: 1}
	ack := PrefaceAck{Status: PrefaceCapacity, Instance: gPassive, CarrierID: 1}
	h := Header{Type: TypeData, Len: 1 << 16, Fseq: 9, Handle: 1}
	o := Open{SID: gSID, Kind: KindStream, Mode: 1, Metadata: meta}
	oa := OpenAck{Status: StatusRejected, Code: 1, Msg: msg}
	j := Join{SID: gSID, Mode: 2, RxNext: 5}
	ja := JoinAck{Status: StatusOK, RxNext: 5}
	ak := Ack{Delivered: 1, Window: 2, EpochEcho: 3}
	r := Rst{Code: RstLinger, Msg: msg}
	s := Sched{Epoch: 1, N: MaxSchedIDs}
	for i := range s.IDs {
		s.IDs[i] = uint32(i + 1)
	}
	pg := Ping{ID: 1, Pad: 1000}
	payload := pattern(1<<16, 3)
	encoders := map[string]func(){
		"PutPreface":    func() { PutPreface(dst, &pre) },
		"PutPrefaceAck": func() { PutPrefaceAck(dst, &ack) },
		"PutHeader":     func() { PutHeader(dst, &h) },
		"PutOpen":       func() { sinkN = PutOpen(dst, &o) },
		"PutOpenAck":    func() { sinkN = PutOpenAck(dst, &oa) },
		"PutJoin":       func() { sinkN = PutJoin(dst, &j) },
		"PutJoinAck":    func() { sinkN = PutJoinAck(dst, &ja) },
		"PutDataOffset": func() { PutDataOffset(dst, 1<<40) },
		"PutAck":        func() { sinkN = PutAck(dst, &ak) },
		"PutFin":        func() { sinkN = PutFin(dst, 77) },
		"PutRst":        func() { sinkN = PutRst(dst, &r) },
		"PutSched":      func() { sinkN = PutSched(dst, &s) },
		"PutPing":       func() { sinkN = PutPing(dst, &pg) },
		"PutReason":     func() { sinkN = PutReason(dst, 1) },
		"CRC chain":     func() { PutTrailer(dst, CRCUpdate(CRC(dst[:HeaderLen]), payload)) },
		"AppendFrame into capacity": func() {
			sinkN = len(AppendFrame(dst[:0], h, payload))
		},
	}
	for name, f := range encoders {
		if a := testing.AllocsPerRun(20, f); a != 0 {
			t.Errorf("%s: %v allocs", name, a)
		}
	}
}

// TestWireLayout_L44 builds one encoding of every structure byte by byte
// from the tables of design §5.1–§5.3 (independently of the encoders) and
// compares it with the encoders' output, so the golden vectors cannot pin a
// layout that differs from the specification.
func TestWireLayout_L44(t *testing.T) {
	be16 := func(v uint16) []byte { return binary.BigEndian.AppendUint16(nil, v) }
	be32 := func(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }
	be64 := func(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	castagnoli := crc32.MakeTable(crc32.Castagnoli)
	withCRC := func(b []byte) []byte { return append(b, be32(crc32.Checksum(b, castagnoli))...) }

	buf := make([]byte, 1<<17)
	check := func(name string, got, want []byte) {
		t.Helper()
		if !bytes.Equal(got, want) {
			t.Errorf("%s:\n got % x\nwant % x", name, got, want)
		}
	}

	// PREFACE: "RND2" | major | minor | kind | role=1 | req | opt | instance | carrierID | crc
	PutPreface(buf, &Preface{Minor: 3, Kind: KindStream, Req: 0, Opt: 0x10, Instance: gDialer, CarrierID: 0x0a0b0c0d})
	check("PREFACE", buf[:PrefaceLen], withCRC(cat([]byte("RND2"), []byte{2, 3, 1, 1}, be32(0), be32(0x10), gDialer[:], be32(0x0a0b0c0d))))
	// PREFACE_ACK: status in byte 6, role=2.
	PutPrefaceAck(buf, &PrefaceAck{Status: PrefaceFeature, Opt: 1, Instance: gPassive, CarrierID: 0x0a0b0c0d})
	check("PREFACE_ACK", buf[:PrefaceLen], withCRC(cat([]byte("RND2"), []byte{2, 0, 2, 2}, be32(0), be32(1), gPassive[:], be32(0x0a0b0c0d))))

	// Frame: type | flags | len u24 | fseq u32 | handle u32 | payload | crc32c(header ‖ payload)
	got := AppendFrame(nil, Header{Type: TypeAck, Flags: 3, Fseq: 0x01020304, Handle: 1}, be64(0x1122334455667788)[:8])
	check("frame", got, withCRC(cat([]byte{0x11, 3, 0, 0, 8}, be32(0x01020304), be32(1), be64(0x1122334455667788))))

	// OPEN: sid[16] · kind · mode · flags u16 · retain_ms u32 · window u32 · pmtu u16 · mlen u16 · metadata
	n := PutOpen(buf, &Open{SID: gSID, Kind: KindStream, Mode: 2, RetainMs: 34000, Window: 0x00800000, Metadata: []byte("meta")})
	check("OPEN", buf[:n], cat(gSID[:], []byte{1, 2}, be16(0), be32(34000), be32(0x00800000), be16(0), be16(4), []byte("meta")))
	// OPEN_ACK: status · window u32 · code u32 · mlen u8 · msg
	n = PutOpenAck(buf, &OpenAck{Status: StatusRejected, Code: 0xabcdef01, Msg: []byte("no")})
	check("OPEN_ACK", buf[:n], cat([]byte{3}, be32(0), be32(0xabcdef01), []byte{2}, []byte("no")))
	// JOIN: sid[16] · mode · rxNext u64
	n = PutJoin(buf, &Join{SID: gSID, Mode: 1, RxNext: 0x0102030405060708})
	check("JOIN", buf[:n], cat(gSID[:], []byte{1}, be64(0x0102030405060708)))
	// JOIN_ACK: status · rxNext u64
	n = PutJoinAck(buf, &JoinAck{Status: StatusOK, RxNext: 42})
	check("JOIN_ACK", buf[:n], cat([]byte{0}, be64(42)))
	// DATA prefix: offset u64
	PutDataOffset(buf, 0x0102030405060708)
	check("DATA offset", buf[:DataPrefixLen], be64(0x0102030405060708))
	// ACK: delivered u64 · window u32 · epochEcho u32
	n = PutAck(buf, &Ack{Delivered: 9, Window: 10, EpochEcho: 11})
	check("ACK", buf[:n], cat(be64(9), be32(10), be32(11)))
	// FIN: offset u64
	n = PutFin(buf, 1<<40)
	check("FIN", buf[:n], be64(1<<40))
	// RST: code u32 · mlen u8 · msg
	n = PutRst(buf, &Rst{Code: RstIdle, Msg: []byte("idle")})
	check("RST", buf[:n], cat(be32(5), []byte{4}, []byte("idle")))
	// SCHED: epoch u32 · death u64 · quality u64 · explicit u64 · n u8 · carrierID[n] u32
	n = PutSched(buf, &Sched{Epoch: 0x01020304, Death: 5, Quality: 1 << 40, Explicit: 0x0a0b0c0d0e0f1011, N: 2, IDs: [MaxSchedIDs]uint32{7, 0x09080706}})
	check("SCHED", buf[:n], cat(be32(0x01020304), be64(5), be64(1<<40), be64(0x0a0b0c0d0e0f1011), []byte{2}, be32(7), be32(0x09080706)))
	// PING / PONG: id u32 · ts u64 · nonce u64 · pad (zero bytes); the
	// destination's garbage is overwritten with zeros.
	for i := range 40 {
		buf[i] = 0xee
	}
	n = PutPing(buf, &Ping{ID: 5, TS: 6, Nonce: 7, Pad: 3})
	check("PING", buf[:n], cat(be32(5), be64(6), be64(7), []byte{0, 0, 0}))
	// CLOSE / GOAWAY: reason u8
	n = PutReason(buf, uint8(CloseCapacity))
	check("CLOSE", buf[:n], []byte{2})
}

// TestPrefaceFseq_L43 (design §0.13 A6): the first fseq of a carrier
// direction is the CRC32C field of the PREFACE or PREFACE_ACK that opened
// it, so carriers that differ in instance or carrier ID start elsewhere.
func TestPrefaceFseq_L43(t *testing.T) {
	seen := map[uint32]bool{}
	for i, inst := range [][16]byte{gDialer, gPassive} {
		for id := uint32(1); id <= 3; id++ {
			b := make([]byte, PrefaceLen)
			if i == 0 {
				PutPreface(b, &Preface{Kind: KindStream, Instance: inst, CarrierID: id})
			} else {
				PutPrefaceAck(b, &PrefaceAck{Status: PrefaceOK, Instance: inst, CarrierID: id})
			}
			got := PrefaceFseq(b)
			if want := CRC(b[:36]); got != want || got != binary.BigEndian.Uint32(b[36:40]) {
				t.Fatalf("PrefaceFseq %#x, want the CRC field %#x", got, want)
			}
			seen[got] = true
		}
	}
	if len(seen) != 6 {
		t.Fatalf("%d distinct first fseqs for 6 prefaces", len(seen))
	}
}

func TestSeqLessWraps(t *testing.T) {
	for _, c := range []struct {
		a, b uint32
		less bool
	}{
		{0, 1, true}, {1, 0, false}, {5, 5, false},
		{0xffffffff, 0, true}, {0, 0xffffffff, false},
		{0xfffffff0, 0x10, true}, {0x10, 0xfffffff0, false},
		{0, 0x7fffffff, true}, {0x7fffffff, 0, false},
	} {
		if got := SeqLess(c.a, c.b); got != c.less {
			t.Errorf("SeqLess(%#x, %#x) = %v", c.a, c.b, got)
		}
	}
}

func TestTypeStrings(t *testing.T) {
	want := map[Type]string{
		TypeOpen: "OPEN", TypeOpenAck: "OPEN_ACK", TypeJoin: "JOIN", TypeJoinAck: "JOIN_ACK",
		TypeData: "DATA", TypeAck: "ACK", TypeFin: "FIN", TypeRst: "RST", TypeSched: "SCHED",
		TypePing: "PING", TypePong: "PONG", TypeClose: "CLOSE", TypeGoAway: "GOAWAY",
		0x20: "0x20", 0x80: "0x80", 0xff: "0xff", 0x00: "0x00",
	}
	for ty, s := range want {
		if got := ty.String(); got != s {
			t.Errorf("Type(%#x).String() = %q, want %q", uint8(ty), got, s)
		}
	}
}
