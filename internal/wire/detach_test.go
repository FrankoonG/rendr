package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"testing"
)

// M3 wire tests (M3 design §A3, §A11.1 WP1): the DETACH codec and its
// fuzz target. The handle rule, OptMux, mode 3, REL{DETACH} and the M3
// golden vectors are in m3_test.go.

// sinkDetach keeps decoded DETACH values alive in allocation tests.
var sinkDetach Detach

// refDetachErr is an independent statement of ParseDetach (§A3.4):
// exactly 5 bytes, handle ≠ 0, reason 1 or 2.
func refDetachErr(p []byte) error {
	switch {
	case len(p) < 5:
		return ErrShort
	case len(p) > 5:
		return ErrTrailing
	case binary.BigEndian.Uint32(p[0:4]) == 0, p[4] != 1 && p[4] != 2:
		return ErrValue
	}
	return nil
}

// TestDetachCodec_L44: DETACH is a carrier-level core type (handle 0,
// flags 0, payload exactly handle u32 · reason u8); the payload decodes
// only with a non-zero handle and a reason of 1 or 2; every other length
// is ErrShort or ErrTrailing (a trailing byte is rejected); errors return
// the zero value; the layout is byte-exact and the encoder writes invalid
// fields as given (M3 design §A3.4, M3-D6).
func TestDetachCodec_L44(t *testing.T) {
	// The type: known, carrier-level, never an extension, flags 0, length 5.
	if !TypeDetach.Known() || !TypeDetach.CarrierLevel() || TypeDetach.Extension() || TypeDetach != 0x36 {
		t.Fatalf("DETACH %#x: known %v, carrier level %v", uint8(TypeDetach), TypeDetach.Known(), TypeDetach.CarrierLevel())
	}
	if AllowedFlags(TypeDetach) != 0 || TypeDetach.String() != "DETACH" {
		t.Errorf("DETACH flags %#x, name %q", AllowedFlags(TypeDetach), TypeDetach.String())
	}
	if lo, hi, ok := PayloadBounds(TypeDetach); !ok || lo != DetachLen || hi != DetachLen || DetachLen != 5 {
		t.Errorf("DETACH bounds %d..%d (%v)", lo, hi, ok)
	}

	// Round trip and layout, byte by byte (independently of the encoder).
	accepted := 0
	for _, h := range []uint32{1, 2, 7, 0x80000000, 0xffffffff} {
		for _, r := range []DetachReason{DetachEnded, DetachRetired} {
			want := []byte{byte(h >> 24), byte(h >> 16), byte(h >> 8), byte(h), byte(r)}
			buf := bytes.Repeat([]byte{0xee}, DetachLen+3)
			if n := PutDetach(buf, &Detach{Handle: h, Reason: r}); n != DetachLen || !bytes.Equal(buf[:n], want) || !bytes.Equal(buf[n:], []byte{0xee, 0xee, 0xee}) {
				t.Errorf("PutDetach(%d, %d) = %d % x, want % x", h, r, n, buf, want)
			}
			orig := bytes.Clone(want)
			d, err := ParseDetach(want)
			if err != nil || d != (Detach{Handle: h, Reason: r}) || !bytes.Equal(want, orig) {
				t.Errorf("ParseDetach(% x) = %+v, %v", want, d, err)
			}
			accepted++
		}
	}
	if accepted != 10 {
		t.Fatalf("%d round trips", accepted)
	}

	// Every length but 5, handle 0 and every reason byte but 1 and 2.
	type tc struct {
		name string
		p    []byte
		err  error
	}
	cases := []tc{
		{"empty", nil, ErrShort},
		{"short by one", []byte{0, 0, 0, 2}, ErrShort},
		{"trailing byte", []byte{0, 0, 0, 2, 1, 0}, ErrTrailing},
		{"trailing valid DETACH", []byte{0, 0, 0, 2, 1, 0, 0, 0, 3, 1}, ErrTrailing},
		{"handle 0, ended", []byte{0, 0, 0, 0, 1}, ErrValue},
		{"handle 0, retired", []byte{0, 0, 0, 0, 2}, ErrValue},
		{"handle 0, reason 0", []byte{0, 0, 0, 0, 0}, ErrValue},
	}
	for r := range 256 {
		if r != 1 && r != 2 {
			cases = append(cases, tc{"reason", []byte{0, 0, 0, 2, byte(r)}, ErrValue})
		}
	}
	for n := range 16 {
		if n != DetachLen {
			p := bytes.Repeat([]byte{1}, n)
			want := ErrShort
			if n > DetachLen {
				want = ErrTrailing
			}
			cases = append(cases, tc{"length", p, want})
		}
	}
	for _, c := range cases {
		d, err := ParseDetach(c.p)
		if !errors.Is(err, c.err) || d != (Detach{}) || !sameErr(refDetachErr(c.p), c.err) {
			t.Errorf("%s % x: %+v, %v, want %v", c.name, c.p, d, err, c.err)
		}
	}
	if len(cases) != 7+254+15 {
		t.Fatalf("%d rejection cases", len(cases))
	}

	// The encoder writes invalid fields as given (tests build bad frames).
	var b [DetachLen]byte
	PutDetach(b[:], &Detach{Handle: 0, Reason: 9})
	if !bytes.Equal(b[:], []byte{0, 0, 0, 0, 9}) {
		t.Errorf("PutDetach of an invalid value: % x", b)
	}
	// A short destination is a programming error.
	func() {
		defer func() {
			if recover() == nil {
				t.Error("PutDetach into 4 bytes: no panic")
			}
		}()
		PutDetach(b[:DetachLen-1], &Detach{Handle: 1, Reason: DetachEnded})
	}()

	// The whole frame, byte by byte: type 0x36 | flags 0 | len 5 | fseq |
	// handle 0 | handle u32 · reason u8 | crc32c.
	frame := AppendFrame(nil, Header{Type: TypeDetach, Fseq: 0x01020304}, []byte{0, 0, 0, 9, 2})
	body := []byte{0x36, 0, 0, 0, 5, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 9, 2}
	want := binary.BigEndian.AppendUint32(bytes.Clone(body), crc32.Checksum(body, crc32.MakeTable(crc32.Castagnoli)))
	if !bytes.Equal(frame, want) || len(frame) != 22 {
		t.Errorf("DETACH frame\n got % x\nwant % x", frame, want)
	}
	f, n, err := DecodeFrame(frame)
	if err != nil || n != len(frame) || f.Type != TypeDetach || f.Handle != 0 || f.Len != DetachLen {
		t.Fatalf("DecodeFrame(DETACH) = %+v, %d, %v", f.Header, n, err)
	}
	if d, err := ParseDetach(f.Payload); err != nil || d != (Detach{Handle: 9, Reason: DetachRetired}) {
		t.Errorf("DETACH payload: %+v, %v", d, err)
	}

	// Header rules of the frame: handle 0 only, no flag, length exactly 5.
	for _, c := range []struct {
		flags  byte
		length uint32
		handle uint32
		err    error
	}{
		{0, 5, 0, nil},
		{0, 5, 1, ErrHandle},
		{0, 5, 2, ErrHandle},
		{0, 5, 0xffffffff, ErrHandle},
		{0x01, 5, 0, ErrFlags},
		{0x80, 5, 0, ErrFlags},
		{0, 4, 0, ErrLength},
		{0, 6, 0, ErrLength},
		{0, 0, 0, ErrLength},
	} {
		if _, err := ParseHeader(hdrBytes(0x36, c.flags, c.length, 1, c.handle)); !sameErr(err, c.err) {
			t.Errorf("DETACH header flags %#x len %d handle %d: %v, want %v", c.flags, c.length, c.handle, err, c.err)
		}
	}

	// Decoding allocates nothing, on success and on every error path.
	for _, p := range [][]byte{{0, 0, 0, 2, 1}, {0, 0, 0, 0, 1}, {0, 0, 0, 2, 3}, {1}, {0, 0, 0, 2, 1, 0}} {
		if a := testing.AllocsPerRun(20, func() { sinkDetach, sinkErr = ParseDetach(p) }); a != 0 {
			t.Errorf("ParseDetach(% x): %v allocs", p, a)
		}
	}
}

// FuzzDetach_L44: the DETACH codec has M2's codec properties on any input
// (M3 design §A9.4): no panic, the input unchanged, the result equal to an
// independent reference, an accepted payload re-encodes to exactly its
// bytes (decode(encode(x)) == x), errors return the zero value, nothing
// allocates; a whole DETACH frame among the inputs is accepted by exactly
// one decoder. Seeds: the shared seeds (every golden vector, M3's
// included, truncated and extended by one byte), the DETACH payloads of
// the golden vectors, and every reason byte at handles 0, 1 and 2^32−1.
func FuzzDetach_L44(f *testing.F) {
	for _, s := range payloadSeeds(TypeDetach) {
		f.Add(s)
	}
	for _, h := range []uint32{0, 1, 0xffffffff} {
		for r := range 256 {
			f.Add(append(binary.BigEndian.AppendUint32(nil, h), byte(r)))
		}
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		forPayload(b, TypeDetach, func(p []byte) { checkDetachInput(t, p) })
		if fr, n, err := DecodeFrame(b); err == nil && n == len(b) && fr.Type == TypeDetach {
			if _, perr := ParseDetach(fr.Payload); perr == nil {
				if acc := acceptors(b); len(acc) != 1 || acc[0] != "frame/DETACH" {
					t.Fatalf("DETACH frame accepted by %v, want exactly [frame/DETACH]", acc)
				}
			}
		}
	})
}

func checkDetachInput(t *testing.T, p []byte) {
	t.Helper()
	orig := bytes.Clone(p)
	d, err := ParseDetach(p)
	if want := refDetachErr(p); !sameErr(err, want) {
		t.Fatalf("DETACH % x: %v, want %v", p, err, want)
	}
	if err != nil {
		if d != (Detach{}) {
			t.Fatalf("error %v with %+v", err, d)
		}
	} else {
		var re [DetachLen]byte
		if n := PutDetach(re[:], &d); n != DetachLen || !bytes.Equal(re[:], p) {
			t.Fatalf("DETACH %+v re-encodes as % x, want % x", d, re, p)
		}
		if d.Handle == 0 || (d.Reason != DetachEnded && d.Reason != DetachRetired) {
			t.Fatalf("accepted %+v", d)
		}
	}
	if !bytes.Equal(p, orig) {
		t.Fatal("ParseDetach modified its input")
	}
	checkAllocs(t, "ParseDetach", func() { sinkDetach, sinkErr = ParseDetach(p) })
}
