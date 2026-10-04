package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"hash/crc32"
	"math/rand/v2"
	"sync/atomic"
	"testing"
)

// The fuzz targets of design §5.5. Plain `go test` replays the seeds (every
// golden vector, each truncated and extended by one byte, the v1 and msess
// handshakes, one PREFACE and one PREFACE_ACK failing at each step of the
// canonical order, extension frames with non-zero flags and handles 0 and 1,
// and every non-canonical OPEN_ACK/JOIN_ACK zero field). Properties checked
// on every input: no panic, the input is unchanged, the result equals an
// independent reference of the specification, an accepted input re-encodes
// to exactly the same bytes (decode(encode(x)) == x), and an accepted
// whole encoding is accepted by exactly one decoder. Allocation-freedom
// (AllocsPerRun == 0) is checked on every seed and, while the fuzzing engine
// runs, on a sample of the generated inputs (AllocsPerRun stops the world,
// which would slow fuzzing down if it ran on every input).

// fuzzing reports whether the fuzzing engine runs (rather than the seeds
// being replayed as ordinary subtests).
func fuzzing() bool {
	f := flag.Lookup("test.fuzz")
	return f != nil && f.Value.String() != ""
}

const (
	// allocSampleEvery: while fuzzing, one checkAllocs call in this many is
	// measured (each fuzz worker process counts its own calls).
	allocSampleEvery = 4096
	// fuzzAllocRuns is the AllocsPerRun count of a sampled check.
	// AllocsPerRun reports mallocs / runs rounded down: a deterministic
	// decoder that allocates does so on every call and reports ≥ 1, while a
	// few stray allocations of the fuzzing engine during the measurement (a
	// timer goroutine) round down to 0.
	fuzzAllocRuns = 64
)

// allocChecks counts the checkAllocs calls made while fuzzing.
var allocChecks atomic.Uint64

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// refPrefaceErr is an independent statement of the canonical check order
// (design §5.1) for a PREFACE (role dialer) or PREFACE_ACK (role passive).
func refPrefaceErr(b []byte, role Role) error {
	switch {
	case len(b) < 40:
		return ErrShort
	case len(b) > 40:
		return ErrTrailing
	case string(b[:4]) != "RND2":
		return ErrMagic
	case crc32.Checksum(b[:36], castagnoli) != binary.BigEndian.Uint32(b[36:40]):
		return ErrCRC
	case b[4] != 2:
		return ErrMajor
	case b[7] != byte(role):
		return ErrMalformed
	case role == RoleDialer && b[6] != 1 && b[6] != 2:
		return ErrMalformed
	case role == RolePassive && b[6] > 4:
		return ErrMalformed
	case bytes.Equal(b[16:32], make([]byte, 16)) || binary.BigEndian.Uint32(b[32:36]) == 0:
		return ErrMalformed
	case binary.BigEndian.Uint32(b[8:12]) != 0:
		return ErrFeature
	}
	return nil
}

// headerRule is the §5.2/§5.3 row of one core type.
type headerRule struct {
	flags   byte
	carrier bool // handle must be 0; otherwise it must be 1 (the M1 session handle, design §0.7 W1)
	lo, hi  int  // payload length bounds
}

// refRules is an independent copy of the design tables.
var refRules = map[byte]headerRule{
	0x01: {0, false, 32, 32 + 65535},
	0x02: {0, false, 10, 10 + 255},
	0x03: {0, false, 25, 25},
	0x04: {0, false, 9, 9},
	0x10: {0, false, 9, 1 << 20},
	0x11: {0x03, false, 16, 16},
	0x12: {0, false, 8, 8},
	0x13: {0, false, 5, 5 + 255},
	0x14: {0x03, false, 9, 5 + 4*16},
	0x30: {0x01, true, 20, 64 << 10},
	0x31: {0, true, 20, 64 << 10},
	0x32: {0, true, 1, 1},
	0x33: {0, true, 1, 1},
}

// refHeaderErr is an independent statement of header checks (1)–(5).
func refHeaderErr(b []byte) error {
	if len(b) < 13 {
		return ErrShort
	}
	n := int(b[2])<<16 | int(b[3])<<8 | int(b[4])
	if n > 1<<20 {
		return ErrLength
	}
	if b[0] >= 0x80 {
		return nil
	}
	r, ok := refRules[b[0]]
	handle := binary.BigEndian.Uint32(b[9:13])
	switch {
	case !ok:
		return ErrType
	case b[1]&^r.flags != 0:
		return ErrFlags
	case r.carrier && handle != 0, !r.carrier && handle != 1:
		return ErrHandle
	case n < r.lo || n > r.hi:
		return ErrLength
	}
	return nil
}

func sameErr(got, want error) bool {
	if want == nil {
		return got == nil
	}
	return errors.Is(got, want)
}

// checkAllocs asserts that f allocates nothing: on every replayed seed, and
// on every allocSampleEvery-th call while fuzzing.
func checkAllocs(t *testing.T, name string, f func()) {
	t.Helper()
	runs := 2
	if fuzzing() {
		if allocChecks.Add(1)%allocSampleEvery != 0 {
			return
		}
		runs = fuzzAllocRuns
	}
	if a := testing.AllocsPerRun(runs, f); a != 0 {
		t.Fatalf("%s allocated %v times", name, a)
	}
}

// fuzzSeeds is the seed corpus shared by every target (each target accepts
// any byte string).
func fuzzSeeds() [][]byte {
	var out [][]byte
	for _, v := range goldenVectors() {
		out = append(out, v.b, v.b[:len(v.b)-1], append(bytes.Clone(v.b), 0))
	}
	for _, c := range legacyHandshakes() {
		out = append(out, c.b, c.b[:min(len(c.b), PrefaceLen)])
	}
	for _, s := range prefaceStepSeeds() {
		out = append(out, s.b)
	}
	// Extension frames with non-zero flags and handles 0 and 1 (all four
	// combinations are also golden vectors).
	for _, h := range []Header{
		{Type: 0x80, Flags: 0xff, Handle: 0}, {Type: 0x80, Flags: 0x01, Handle: 1},
		{Type: 0xc3, Flags: 0x80, Handle: 0xffffffff}, {Type: 0xff, Flags: 0xff, Handle: 1},
	} {
		out = append(out, AppendFrame(nil, h, []byte("opaque")))
	}
	// Every non-canonical OPEN_ACK / JOIN_ACK zero field, as a frame.
	for _, p := range nonCanonicalAnswers() {
		out = append(out, AppendFrame(nil, Header{Type: p.t, Fseq: 1, Handle: SessionHandle}, p.p))
	}
	// Header errors at each of the checks (1)–(5) and an oversize length
	// (no allocation may follow from it, L42).
	for _, h := range [][]byte{
		{0x10, 0, 0x10, 0x00, 0x01, 0, 0, 0, 1, 0, 0, 0, 1},                // DATA len = max+1
		{0x20, 0, 0, 0, 9, 0, 0, 0, 1, 0, 0, 0, 1},                         // M2 type
		{0x11, 0x04, 0, 0, 16, 0, 0, 0, 1, 0, 0, 0, 1},                     // ACK undefined flag
		{0x30, 0, 0, 0, 20, 0, 0, 0, 1, 0, 0, 0, 1},                        // PING handle 1
		{0x11, 0, 0, 0, 16, 0, 0, 0, 1, 0, 0, 0, 2},                        // ACK handle 2 (not the session handle)
		{0x12, 0, 0, 0, 7, 0, 0, 0, 1, 0, 0, 0, 1},                         // FIN short
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // short header
	} {
		out = append(out, h)
	}
	return out
}

func FuzzPreface_L44(f *testing.F) {
	for _, s := range fuzzSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		checkPrefaceInput(t, b, RoleDialer)
		if len(b) == PrefaceLen && string(b[:4]) == "RND2" {
			checkPrefaceInput(t, reseal(bytes.Clone(b)), RoleDialer) // explore past the CRC
		}
	})
}

func FuzzPrefaceAck_L44(f *testing.F) {
	for _, s := range fuzzSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		checkPrefaceInput(t, b, RolePassive)
		if len(b) == PrefaceLen && string(b[:4]) == "RND2" {
			checkPrefaceInput(t, reseal(bytes.Clone(b)), RolePassive)
		}
	})
}

func checkPrefaceInput(t *testing.T, b []byte, role Role) {
	t.Helper()
	orig := bytes.Clone(b)
	var (
		err error
		out [PrefaceLen]byte
		ok  bool
	)
	if role == RoleDialer {
		var p Preface
		p, err = ParsePreface(b)
		if err == nil || errors.Is(err, ErrFeature) {
			PutPreface(out[:], &p)
			ok = true
		} else if p != (Preface{}) {
			t.Fatalf("error %v returned a non-zero preface %+v", err, p)
		}
		checkAllocs(t, "ParsePreface", func() { sinkPreface, sinkErr = ParsePreface(b) })
	} else {
		var a PrefaceAck
		a, err = ParsePrefaceAck(b)
		if err == nil || errors.Is(err, ErrFeature) {
			PutPrefaceAck(out[:], &a)
			ok = true
		} else if a != (PrefaceAck{}) {
			t.Fatalf("error %v returned a non-zero ack %+v", err, a)
		}
		checkAllocs(t, "ParsePrefaceAck", func() { sinkPrefaceAck, sinkErr = ParsePrefaceAck(b) })
	}
	if want := refPrefaceErr(b, role); !sameErr(err, want) {
		t.Fatalf("role %d: error %v, the canonical order says %v (input % x)", role, err, want, b)
	}
	if ok && !bytes.Equal(out[:], b) {
		t.Fatalf("decoded value re-encodes differently:\n in % x\nout % x", b, out)
	}
	if err == nil {
		want := "preface"
		if role == RolePassive {
			want = "preface_ack"
		}
		if acc := acceptors(b); len(acc) != 1 || acc[0] != want {
			t.Fatalf("accepted by %v, want exactly [%s]", acc, want)
		}
	}
	if !bytes.Equal(b, orig) {
		t.Fatal("the decoder modified its input")
	}
}

func FuzzHeader_L44(f *testing.F) {
	for _, s := range fuzzSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		orig := bytes.Clone(b)
		h, err := ParseHeader(b)
		if want := refHeaderErr(b); !sameErr(err, want) {
			t.Fatalf("error %v, the design tables say %v (header % x)", err, want, b[:min(len(b), HeaderLen)])
		}
		if err == nil {
			var out [HeaderLen]byte
			PutHeader(out[:], &h)
			if !bytes.Equal(out[:], b[:HeaderLen]) {
				t.Fatalf("header re-encodes differently: % x vs % x", out, b[:HeaderLen])
			}
			if lo, hi, ok := PayloadBounds(h.Type); !ok || int(h.Len) < lo || int(h.Len) > hi {
				t.Fatalf("accepted %+v outside PayloadBounds", h)
			}
		} else if h != (Header{}) {
			t.Fatalf("error %v returned a non-zero header %+v", err, h)
		}
		if !bytes.Equal(b, orig) {
			t.Fatal("ParseHeader modified its input")
		}
		checkAllocs(t, "ParseHeader", func() { sinkHeader, sinkErr = ParseHeader(b) })
	})
}

func FuzzFrame_L44(f *testing.F) {
	for _, s := range fuzzSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		checkFrameInput(t, b)
		// Explore past the CRC barrier: the same bytes with a recomputed
		// trailer reach the payload parsers.
		if h, err := ParseHeader(b); err == nil {
			if end := HeaderLen + int(h.Len); len(b) >= end+TrailerLen {
				c := bytes.Clone(b)
				PutTrailer(c[end:], CRC(c[:end]))
				checkFrameInput(t, c)
			}
		}
	})
}

// checkFrameInput decodes one frame at the front of b and dispatches its
// payload by type to the type's parser.
func checkFrameInput(t *testing.T, b []byte) {
	t.Helper()
	orig := bytes.Clone(b)
	fr, n, err := DecodeFrame(b)
	h, herr := ParseHeader(b)
	if err != nil {
		if n != 0 || fr.Payload != nil || fr.Header != (Header{}) {
			t.Fatalf("error %v with n=%d frame %+v", err, n, fr.Header)
		}
		switch {
		case herr != nil:
			if !errors.Is(err, herr) {
				t.Fatalf("DecodeFrame %v, ParseHeader %v", err, herr)
			}
		case len(b) < FrameOverhead+int(h.Len):
			if !errors.Is(err, ErrShort) {
				t.Fatalf("incomplete frame: %v, want ErrShort", err)
			}
		default:
			end := HeaderLen + int(h.Len)
			if !errors.Is(err, ErrCRC) || crc32.Checksum(b[:end], castagnoli) == binary.BigEndian.Uint32(b[end:]) {
				t.Fatalf("complete frame: %v (CRC matches: %v)", err, crc32.Checksum(b[:end], castagnoli) == binary.BigEndian.Uint32(b[end:]))
			}
		}
	} else {
		if herr != nil || h != fr.Header {
			t.Fatalf("DecodeFrame header %+v, ParseHeader %+v %v", fr.Header, h, herr)
		}
		if n != FrameOverhead+int(fr.Len) || n > len(b) || !bytes.Equal(fr.Payload, b[HeaderLen:HeaderLen+int(fr.Len)]) || cap(fr.Payload) != len(fr.Payload) {
			t.Fatalf("frame %+v: n=%d of %d, payload len %d cap %d", fr.Header, n, len(b), len(fr.Payload), cap(fr.Payload))
		}
		if re := AppendFrame(nil, fr.Header, fr.Payload); !bytes.Equal(re, b[:n]) {
			t.Fatalf("frame re-encodes differently")
		}
		v, perr := decodeTyped(fr.Type, fr.Payload)
		switch {
		case perr == nil:
			if enc := encodeTyped(fr.Type, v); !bytes.Equal(enc, fr.Payload) {
				t.Fatalf("%v payload accepted but not canonical:\n in % x\nout % x", fr.Type, fr.Payload, enc)
			}
			if n == len(b) {
				if acc := acceptors(b); len(acc) != 1 || acc[0] != "frame/"+fr.Type.String() {
					t.Fatalf("accepted by %v, want exactly [frame/%v]", acc, fr.Type)
				}
			}
		case fr.Type.Extension():
			t.Fatalf("extension payload rejected: %v", perr)
		}
	}
	if !bytes.Equal(b, orig) {
		t.Fatal("the decoder modified its input")
	}
	checkAllocs(t, "decode", func() { decodeConcrete(b) })
}

func FuzzStream_L42_L43(f *testing.F) {
	var all []byte
	for _, v := range goldenVectors() {
		if v.kind == "frame" {
			all = append(all, v.b...)
		}
	}
	corrupt := bytes.Clone(all)
	corrupt[len(corrupt)/2] ^= 0x10
	oversize := append(bytes.Clone(all[:len(all)/3]), 0x10, 0, 0x10, 0x00, 0x01, 0, 0, 0, 1, 0, 0, 0, 1)
	pre, _ := validPrefaces()
	for seed := range uint64(3) {
		f.Add(all, seed)
		f.Add(all[:len(all)-1], seed)
		f.Add(corrupt, seed)
		f.Add(oversize, seed)
	}
	f.Add(append(bytes.Clone(pre), all[:200]...), uint64(7))
	f.Add([]byte{}, uint64(0))
	f.Fuzz(func(t *testing.T, stream []byte, seed uint64) {
		orig := bytes.Clone(stream)
		want, wantAt, wantErr := decodeOneShot(stream)
		got, gotAt, gotErr := decodeChunked(stream, seed)
		if !errors.Is(gotErr, wantErr) || gotAt != wantAt || len(got) != len(want) {
			t.Fatalf("chunked: %d frames, stop at %d with %v; one-shot: %d frames, stop at %d with %v",
				len(got), gotAt, gotErr, len(want), wantAt, wantErr)
		}
		for i := range want {
			if got[i].Header != want[i].Header || !bytes.Equal(got[i].Payload, want[i].Payload) {
				t.Fatalf("frame %d differs: %+v vs %+v", i, got[i].Header, want[i].Header)
			}
			if len(want[i].Payload) != int(want[i].Len) {
				t.Fatalf("frame %d is partial: %d of %d payload bytes", i, len(want[i].Payload), want[i].Len)
			}
		}
		// Decoding stops only at an error; a stream consumed to its end
		// stops with ErrShort (waiting for the next header).
		if wantErr == nil || (wantAt == len(stream) && !errors.Is(wantErr, ErrShort)) {
			t.Fatalf("stream ended with %v at %d of %d", wantErr, wantAt, len(stream))
		}
		if !bytes.Equal(stream, orig) {
			t.Fatal("the decoder modified its input")
		}
		checkAllocs(t, "stream decode", func() { decodeAll(stream) })
	})
}

// decodeAll decodes frames from the front of b until the first error and
// keeps nothing (the allocation check of the stream target).
func decodeAll(b []byte) {
	for at := 0; ; {
		f, n, err := DecodeFrame(b[at:])
		if err != nil {
			sinkErr = err
			return
		}
		sinkFrame = f
		at += n
	}
}

// decodeOneShot decodes frames from the front of b until the first error;
// it returns the frames, the offset where decoding stopped, and the error
// (ErrShort at the end of the stream or in a trailing partial frame).
func decodeOneShot(b []byte) (frames []Frame, at int, err error) {
	for {
		f, n, err := DecodeFrame(b[at:])
		if err != nil {
			return frames, at, err
		}
		frames = append(frames, f)
		at += n
	}
}

// decodeChunked feeds b to a reader in pseudo-random chunk sizes (1 byte to
// 64 KiB) and decodes every complete frame as soon as it is buffered, the
// way the carrier reader does. Frames are copied out of the reader's buffer.
func decodeChunked(b []byte, seed uint64) (frames []Frame, at int, err error) {
	rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	var buf []byte // everything fed so far; frames are decoded from buf[at:]
	fed := 0
	for {
		for {
			f, n, err := DecodeFrame(buf[at:])
			if errors.Is(err, ErrShort) {
				break
			}
			if err != nil {
				return frames, at, err
			}
			f.Payload = bytes.Clone(f.Payload)
			frames = append(frames, f)
			at += n
		}
		if fed == len(b) {
			return frames, at, ErrShort
		}
		k := 1 + rng.IntN(1<<uint(rng.IntN(17)))
		k = min(k, len(b)-fed)
		buf = append(buf, b[fed:fed+k]...)
		fed += k
	}
}
