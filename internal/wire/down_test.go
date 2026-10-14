package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"testing"
)

// M5 wire tests (PA-86; F-7): the DOWN codec, its REL wrapping, its golden
// vectors and its fuzz target.

// downVal is a decoded DOWN payload: the dead trunk's CarrierID.
type downVal uint32

// sinkDownID keeps decoded DOWN values alive in allocation tests.
var sinkDownID uint32

// goldenVectorsM5 builds the vectors M5 adds (PA-86), after every M1–M4
// vector, which stays byte-identical: DOWN bare on a stream trunk and
// REL-wrapped on a datagram trunk, both naming gCarrierJoin (the trunk that
// died) as the trunk gCarrier would report it.
func goldenVectorsM5() []vector {
	return []vector{
		frameVec("down", TypeDown, 0, 19, 0, downVal(gCarrierJoin)),
		relVec("rel_down", 16, RelHead{Cseq: 9, Type: TypeDown}, downVal(gCarrierJoin)),
	}
}

// refDownErr is an independent statement of ParseDown (PA-86): exactly 4
// bytes, the CarrierID not 0.
func refDownErr(p []byte) error {
	switch {
	case len(p) < 4:
		return ErrShort
	case len(p) > 4:
		return ErrTrailing
	case binary.BigEndian.Uint32(p) == 0:
		return ErrValue
	}
	return nil
}

// TestDownCodec_L44: DOWN is a carrier-level core type 0x37 (handle 0,
// flags 0, payload exactly carrierID u32); the payload decodes only with a
// CarrierID other than 0; every other length is ErrShort or ErrTrailing (a
// trailing byte is rejected); errors return 0; the layout is byte-exact,
// the encoder writes an invalid value as given, and decoding allocates
// nothing (PA-86).
func TestDownCodec_L44(t *testing.T) {
	// The type: known, carrier-level, wrappable, never an extension, flags
	// 0, length 4, named DOWN.
	if !TypeDown.Known() || !TypeDown.CarrierLevel() || !Wrappable(TypeDown) || TypeDown.Extension() || TypeDown != 0x37 {
		t.Fatalf("DOWN %#x: known %v, carrier level %v, wrappable %v", uint8(TypeDown), TypeDown.Known(), TypeDown.CarrierLevel(), Wrappable(TypeDown))
	}
	if AllowedFlags(TypeDown) != 0 || TypeDown.String() != "DOWN" {
		t.Errorf("DOWN flags %#x, name %q", AllowedFlags(TypeDown), TypeDown.String())
	}
	if lo, hi, ok := PayloadBounds(TypeDown); !ok || lo != DownLen || hi != DownLen || DownLen != 4 {
		t.Errorf("DOWN bounds %d..%d (%v)", lo, hi, ok)
	}

	// Round trip and layout, byte by byte (independently of the encoder).
	for _, id := range []uint32{1, 2, 0x01020305, 0x7fffffff, 0x80000000, 0xffffffff} {
		want := []byte{byte(id >> 24), byte(id >> 16), byte(id >> 8), byte(id)}
		buf := bytes.Repeat([]byte{0xee}, DownLen+3)
		if n := PutDown(buf, id); n != DownLen || !bytes.Equal(buf[:n], want) || !bytes.Equal(buf[n:], []byte{0xee, 0xee, 0xee}) {
			t.Errorf("PutDown(%#x) = %d % x, want % x", id, n, buf, want)
		}
		orig := bytes.Clone(want)
		got, err := ParseDown(want)
		if err != nil || got != id || !bytes.Equal(want, orig) {
			t.Errorf("ParseDown(% x) = %#x, %v", want, got, err)
		}
	}

	// Every length but 4 and the CarrierID 0.
	type tc struct {
		name string
		p    []byte
		err  error
	}
	cases := []tc{
		{"empty", nil, ErrShort},
		{"short by one", []byte{0, 0, 0}, ErrShort},
		{"trailing byte", []byte{0, 0, 0, 2, 0}, ErrTrailing},
		{"trailing valid DOWN", []byte{0, 0, 0, 2, 0, 0, 0, 3}, ErrTrailing},
		{"CarrierID 0", []byte{0, 0, 0, 0}, ErrValue},
	}
	for n := range 16 {
		if n != DownLen {
			want := ErrShort
			if n > DownLen {
				want = ErrTrailing
			}
			cases = append(cases, tc{"length", bytes.Repeat([]byte{1}, n), want})
		}
	}
	for _, c := range cases {
		id, err := ParseDown(c.p)
		if !errors.Is(err, c.err) || id != 0 || !sameErr(refDownErr(c.p), c.err) {
			t.Errorf("%s % x: %#x, %v, want %v", c.name, c.p, id, err, c.err)
		}
	}
	if len(cases) != 5+15 {
		t.Fatalf("%d rejection cases", len(cases))
	}

	// The encoder writes an invalid value as given (tests build bad frames).
	var b [DownLen]byte
	PutDown(b[:], 0)
	if !bytes.Equal(b[:], []byte{0, 0, 0, 0}) {
		t.Errorf("PutDown(0): % x", b)
	}
	// A short destination is a programming error.
	func() {
		defer func() {
			if recover() == nil {
				t.Error("PutDown into 3 bytes: no panic")
			}
		}()
		PutDown(b[:DownLen-1], 1)
	}()

	// The whole frame, byte by byte: type 0x37 | flags 0 | len 4 | fseq |
	// handle 0 | carrierID u32 | crc32c.
	frame := AppendFrame(nil, Header{Type: TypeDown, Fseq: 0x01020304}, []byte{0, 0, 0, 9})
	body := []byte{0x37, 0, 0, 0, 4, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 9}
	want := binary.BigEndian.AppendUint32(bytes.Clone(body), crc32.Checksum(body, crc32.MakeTable(crc32.Castagnoli)))
	if !bytes.Equal(frame, want) || len(frame) != 21 {
		t.Errorf("DOWN frame\n got % x\nwant % x", frame, want)
	}
	f, n, err := DecodeFrame(frame)
	if err != nil || n != len(frame) || f.Type != TypeDown || f.Handle != 0 || f.Len != DownLen {
		t.Fatalf("DecodeFrame(DOWN) = %+v, %d, %v", f.Header, n, err)
	}
	if id, err := ParseDown(f.Payload); err != nil || id != 9 {
		t.Errorf("DOWN payload: %#x, %v", id, err)
	}

	// Header rules of the frame: handle 0 only, no flag, length exactly 4.
	for _, c := range []struct {
		flags  byte
		length uint32
		handle uint32
		err    error
	}{
		{0, 4, 0, nil},
		{0, 4, 1, ErrHandle},
		{0, 4, 2, ErrHandle},
		{0, 4, 0xffffffff, ErrHandle},
		{0x01, 4, 0, ErrFlags},
		{0x80, 4, 0, ErrFlags},
		{0, 3, 0, ErrLength},
		{0, 5, 0, ErrLength},
		{0, 0, 0, ErrLength},
	} {
		if _, err := ParseHeader(hdrBytes(0x37, c.flags, c.length, 1, c.handle)); !sameErr(err, c.err) {
			t.Errorf("DOWN header flags %#x len %d handle %d: %v, want %v", c.flags, c.length, c.handle, err, c.err)
		}
	}

	// The golden vectors: the bare frame on a stream trunk (21 bytes) and
	// the REL on a datagram trunk (31 bytes, inner handle 0, within
	// ControlFloor), both naming gCarrierJoin.
	d, rd := goldenByName(t, "down"), goldenByName(t, "rel_down")
	if f, _, err := DecodeFrame(d.b); err != nil || f.Type != TypeDown || len(d.b) != 21 {
		t.Errorf("down: %+v, %d bytes, %v", f.Header, len(d.b), err)
	} else if id, err := ParseDown(f.Payload); err != nil || id != gCarrierJoin {
		t.Errorf("down names %#x, %v", id, err)
	}
	if r, ok := rd.val.(relVal); !ok || r.Head.Type != TypeDown || r.Head.Handle != 0 || r.Inner != downVal(gCarrierJoin) || len(rd.b) != 31 || len(rd.b) > ControlFloor {
		t.Errorf("rel_down: %+v, %d bytes", rd.val, len(rd.b))
	}

	// Decoding allocates nothing, on success and on every error path.
	for _, p := range [][]byte{{0, 0, 0, 2}, {0, 0, 0, 0}, {1}, {0, 0, 0, 2, 0}} {
		if a := testing.AllocsPerRun(20, func() { sinkDownID, sinkErr = ParseDown(p) }); a != 0 {
			t.Errorf("ParseDown(% x): %v allocs", p, a)
		}
	}
}

// TestWrappableDown: DOWN is REL-wrapped on datagram trunks (PA-86):
// Wrappable, its inner handle 0 (any other is ErrHandle), its inner payload
// exactly 4 bytes (ErrLength otherwise), no inner flag (ErrFlags); the
// payload rules (CarrierID 0 is ErrValue) apply after unwrapping;
// RelMaxPayload is unchanged.
func TestWrappableDown(t *testing.T) {
	inner := []byte{0, 0, 0, 3}
	rh, in, err := ParseRel(relPayload(RelHead{Cseq: 0xffffffff, Type: TypeDown}, inner))
	if err != nil || rh != (RelHead{Cseq: 0xffffffff, Type: TypeDown}) || !bytes.Equal(in, inner) {
		t.Fatalf("REL{DOWN}: %+v % x %v", rh, in, err)
	}
	if id, err := ParseDown(in); err != nil || id != 3 {
		t.Errorf("REL{DOWN} inner: %#x, %v", id, err)
	}
	for _, c := range []struct {
		name  string
		h     RelHead
		inner []byte
		err   error
	}{
		{"inner handle 1", RelHead{Cseq: 1, Type: TypeDown, Handle: 1}, inner, ErrHandle},
		{"inner handle max", RelHead{Cseq: 1, Type: TypeDown, Handle: 0xffffffff}, inner, ErrHandle},
		{"inner flag", RelHead{Cseq: 1, Type: TypeDown, Flags: 1}, inner, ErrFlags},
		{"inner 3 bytes", RelHead{Cseq: 1, Type: TypeDown}, inner[:3], ErrLength},
		{"inner 5 bytes", RelHead{Cseq: 1, Type: TypeDown}, append(bytes.Clone(inner), 0), ErrLength},
		{"inner empty", RelHead{Cseq: 1, Type: TypeDown}, nil, ErrLength},
	} {
		rh, in, err := ParseRel(relPayload(c.h, c.inner))
		if !errors.Is(err, c.err) || rh != (RelHead{}) || in != nil {
			t.Errorf("REL{DOWN} %s: %+v, %v, want %v", c.name, rh, err, c.err)
		}
	}
	if _, in, err := ParseRel(relPayload(RelHead{Cseq: 1, Type: TypeDown}, []byte{0, 0, 0, 0})); err != nil {
		t.Fatal(err)
	} else if _, err := ParseDown(in); !errors.Is(err, ErrValue) {
		t.Errorf("REL{DOWN 0}: %v, want ErrValue", err)
	}
	if FrameOverhead+RelHeadLen+DownLen != 31 || RelMaxPayload != 275 {
		t.Errorf("REL{DOWN} %d bytes, RelMaxPayload %d", FrameOverhead+RelHeadLen+DownLen, RelMaxPayload)
	}
}

// FuzzDown_L44: the DOWN codec has the codec properties on any input (M2
// design §A3.10): no panic, the input unchanged, the result equal to an
// independent reference, an accepted payload re-encodes to exactly its
// bytes (decode(encode(x)) == x), errors return 0, nothing allocates; a
// whole DOWN frame among the inputs is accepted by exactly one decoder.
// Seeds: the shared seeds (every golden vector, M5's included, truncated
// and extended by one byte), the DOWN payloads of the golden vectors, and
// the CarrierIDs 0, 1 and 2^32−1 with and without a trailing byte.
func FuzzDown_L44(f *testing.F) {
	for _, s := range payloadSeeds(TypeDown) {
		f.Add(s)
	}
	for _, id := range []uint32{0, 1, 0xffffffff} {
		f.Add(binary.BigEndian.AppendUint32(nil, id))
		f.Add(append(binary.BigEndian.AppendUint32(nil, id), 0))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		forPayload(b, TypeDown, func(p []byte) { checkDownInput(t, p) })
		if fr, n, err := DecodeFrame(b); err == nil && n == len(b) && fr.Type == TypeDown {
			if _, perr := ParseDown(fr.Payload); perr == nil {
				if acc := acceptors(b); len(acc) != 1 || acc[0] != "frame/DOWN" {
					t.Fatalf("DOWN frame accepted by %v, want exactly [frame/DOWN]", acc)
				}
			}
		}
	})
}

func checkDownInput(t *testing.T, p []byte) {
	t.Helper()
	orig := bytes.Clone(p)
	id, err := ParseDown(p)
	if want := refDownErr(p); !sameErr(err, want) {
		t.Fatalf("DOWN % x: %v, want %v", p, err, want)
	}
	if err != nil {
		if id != 0 {
			t.Fatalf("error %v with %#x", err, id)
		}
	} else {
		var re [DownLen]byte
		if n := PutDown(re[:], id); n != DownLen || !bytes.Equal(re[:], p) {
			t.Fatalf("DOWN %#x re-encodes as % x, want % x", id, re, p)
		}
		if id == 0 {
			t.Fatal("accepted CarrierID 0")
		}
	}
	if !bytes.Equal(p, orig) {
		t.Fatal("ParseDown modified its input")
	}
	checkAllocs(t, "ParseDown", func() { sinkDownID, sinkErr = ParseDown(p) })
}
