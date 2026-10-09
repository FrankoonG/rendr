package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"hash/crc32"
	"math"
	"math/rand/v2"
	"sync/atomic"
	"testing"
)

// The fuzz targets of design §5.5 and of M2 design §A3.10 (DGRAM, PACK,
// REL with its nesting, RACK, the flow header, whole datagrams and both
// windows). Plain `go test` replays the seeds (every golden vector, each
// truncated and extended by one byte, the v1 and msess handshakes, one
// PREFACE and one PREFACE_ACK failing at each step of the canonical order,
// extension frames with non-zero flags and handles 0 and 1, every
// non-canonical OPEN_ACK/JOIN_ACK zero field, and the M2 targets' own
// seeds). Properties checked on every input: no panic, the input is
// unchanged, the result equals an independent reference of the
// specification, an accepted input re-encodes to exactly the same bytes
// (decode(encode(x)) == x), and an accepted whole encoding is accepted by
// exactly one decoder. Allocation-freedom (AllocsPerRun == 0) is checked on
// every seed and, while the fuzzing engine runs, on a sample of the
// generated inputs (AllocsPerRun stops the world, which would slow fuzzing
// down if it ran on every input).

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
	0x14: {0x03, false, 29 + 4, 29 + 4*16}, // epoch, three u64 migration counts, n (§0.13 A3)
	0x30: {0x01, true, 20, 64 << 10},
	0x31: {0, true, 20, 64 << 10},
	0x32: {0, true, 1, 1},
	0x33: {0, true, 1, 1},
	// M2 (design §A3.1; known since M2, §A8.7).
	0x20: {0, false, 8, 1 << 20}, // DGRAM: seq u64 · bytes (empty legal)
	0x21: {0x03, false, 20, 20},  // PACK: FIN_DELIVERED, DONE
	0x34: {0, true, 10, 1 << 20}, // REL: cseq · itype · iflags · ihandle · ipayload
	0x35: {0, true, 8, 8},        // RACK: cumAck · sack
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
		{0x22, 0, 0, 0, 9, 0, 0, 0, 1, 0, 0, 0, 1},                         // unassigned core type
		{0x52, 0, 0, 0, 9, 0, 0, 0, 1, 0, 0, 0, 1},                         // 0x52 ('R') is never assigned
		{0x20, 0, 0, 0, 9, 0, 0, 0, 1, 0, 0, 0, 1},                         // DGRAM (an unknown type in M1, §A8.7)
		{0x34, 0, 0, 0, 9, 0, 0, 0, 1, 0, 0, 0, 0},                         // REL shorter than its head
		{0x35, 0, 0, 0, 8, 0, 0, 0, 1, 0, 0, 0, 1},                         // RACK with handle 1
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

// M2 fuzz targets (M2 design §A3.10).

// refWrappable is an independent copy of the REL set: plan:356's nine
// control frames and PACK (M2-D39).
var refWrappable = map[byte]bool{
	0x01: true, 0x02: true, 0x03: true, 0x04: true, 0x12: true,
	0x13: true, 0x14: true, 0x32: true, 0x33: true, 0x21: true,
}

// refRelErr is an independent statement of ParseRel's check order (§A3.3):
// length, wrappable inner type, inner flags, inner handle, inner length.
func refRelErr(p []byte) error {
	if len(p) < 10 {
		return ErrShort
	}
	r, ok := refRules[p[4]]
	handle := binary.BigEndian.Uint32(p[6:10])
	n := len(p) - 10
	switch {
	case !ok || !refWrappable[p[4]]:
		return ErrType
	case p[5]&^r.flags != 0:
		return ErrFlags
	case r.carrier && handle != 0, !r.carrier && handle != 1:
		return ErrHandle
	case n < r.lo || n > r.hi:
		return ErrLength
	}
	return nil
}

// refDgramErr, refPackErr, refRackErr and refFlowErr state §A3.2–§A3.4
// independently of the codecs.
func refDgramErr(p []byte) error {
	if len(p) < 8 {
		return ErrShort
	}
	return nil
}

func refPackErr(p []byte) error {
	switch {
	case len(p) < 20:
		return ErrShort
	case len(p) > 20:
		return ErrTrailing
	case binary.BigEndian.Uint64(p[8:16]) == 0 && binary.BigEndian.Uint64(p[0:8]) != 0:
		return ErrReserved
	}
	return nil
}

func refRackErr(p []byte) error {
	switch {
	case len(p) < 8:
		return ErrShort
	case len(p) > 8:
		return ErrTrailing
	case binary.BigEndian.Uint32(p[4:8]) >= 1<<7:
		return ErrReserved
	}
	return nil
}

func refFlowErr(d []byte) error {
	if len(d) < 9 || d[0] != 2 || binary.BigEndian.Uint64(d[1:9]) == 0 {
		return ErrFlowHeader
	}
	return nil
}

// payloadSeeds returns the shared seeds plus the payloads of the golden
// frames of type t, each also truncated and extended by one byte.
func payloadSeeds(t Type) [][]byte {
	out := fuzzSeeds()
	for _, v := range goldenVectors() {
		if v.kind != "frame" && v.kind != "reject" {
			continue
		}
		f, _, err := DecodeFrame(v.b)
		if err != nil || f.Type != t {
			continue
		}
		p := f.Payload
		out = append(out, bytes.Clone(p), bytes.Clone(p[:len(p)-1]), append(bytes.Clone(p), 0))
	}
	return out
}

// forPayload runs check on b and, when b starts with a header of type t and
// holds its payload, on that payload too (CRC or not), so the shared frame
// seeds reach the payload parser.
func forPayload(b []byte, t Type, check func([]byte)) {
	check(b)
	if h, err := ParseHeader(b); err == nil && h.Type == t && len(b) >= HeaderLen+int(h.Len) {
		check(b[HeaderLen : HeaderLen+int(h.Len)])
	}
}

func FuzzDgram_L44(f *testing.F) {
	for _, s := range payloadSeeds(TypeDgram) {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		forPayload(b, TypeDgram, func(p []byte) { checkDgramInput(t, p) })
	})
}

func checkDgramInput(t *testing.T, p []byte) {
	t.Helper()
	orig := bytes.Clone(p)
	seq, data, err := ParseDgram(p)
	if want := refDgramErr(p); !sameErr(err, want) {
		t.Fatalf("DGRAM % x: %v, want %v", p, err, want)
	}
	if err != nil {
		if seq != 0 || data != nil {
			t.Fatalf("error %v with seq %#x and %d data bytes", err, seq, len(data))
		}
	} else {
		if seq != binary.BigEndian.Uint64(p) || len(data) != len(p)-DgramPrefixLen || cap(data) != len(data) ||
			(len(data) > 0 && &data[0] != &p[DgramPrefixLen]) {
			t.Fatalf("DGRAM of %d bytes: seq %#x, %d data bytes (cap %d)", len(p), seq, len(data), cap(data))
		}
		re := make([]byte, DgramPrefixLen+len(data))
		PutDgramSeq(re, seq)
		copy(re[DgramPrefixLen:], data)
		if !bytes.Equal(re, p) {
			t.Fatalf("DGRAM re-encodes differently")
		}
	}
	if !bytes.Equal(p, orig) {
		t.Fatal("ParseDgram modified its input")
	}
	checkAllocs(t, "ParseDgram", func() { sinkU64, sinkBytes, sinkErr = ParseDgram(p) })
}

func FuzzPack_L44(f *testing.F) {
	for _, s := range payloadSeeds(TypePack) {
		f.Add(s)
	}
	f.Add(bcat(bu64(5), bu64(0), bu32(1))) // highestSeq without received
	f.Fuzz(func(t *testing.T, b []byte) {
		forPayload(b, TypePack, func(p []byte) { checkPackInput(t, p) })
	})
}

func checkPackInput(t *testing.T, p []byte) {
	t.Helper()
	orig := bytes.Clone(p)
	pk, err := ParsePack(p)
	if want := refPackErr(p); !sameErr(err, want) {
		t.Fatalf("PACK % x: %v, want %v", p, err, want)
	}
	if err != nil {
		if pk != (Pack{}) {
			t.Fatalf("error %v with %+v", err, pk)
		}
	} else {
		var re [PackLen]byte
		PutPack(re[:], &pk)
		if !bytes.Equal(re[:], p) {
			t.Fatalf("PACK %+v re-encodes differently: % x vs % x", pk, re, p)
		}
	}
	if !bytes.Equal(p, orig) {
		t.Fatal("ParsePack modified its input")
	}
	checkAllocs(t, "ParsePack", func() { sinkPack, sinkErr = ParsePack(p) })
}

func FuzzRack_L44(f *testing.F) {
	for _, s := range payloadSeeds(TypeRack) {
		f.Add(s)
	}
	for bit := range 32 {
		f.Add(bcat(bu32(9), bu32(1<<bit))) // every sack bit, reserved ones included
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		forPayload(b, TypeRack, func(p []byte) { checkRackInput(t, p) })
	})
}

func checkRackInput(t *testing.T, p []byte) {
	t.Helper()
	orig := bytes.Clone(p)
	r, err := ParseRack(p)
	if want := refRackErr(p); !sameErr(err, want) {
		t.Fatalf("RACK % x: %v, want %v", p, err, want)
	}
	if err != nil {
		if r != (Rack{}) {
			t.Fatalf("error %v with %+v", err, r)
		}
	} else {
		var re [RackLen]byte
		PutRack(re[:], &r)
		if !bytes.Equal(re[:], p) {
			t.Fatalf("RACK %+v re-encodes differently", r)
		}
	}
	if !bytes.Equal(p, orig) {
		t.Fatal("ParseRack modified its input")
	}
	checkAllocs(t, "ParseRack", func() { sinkRack, sinkErr = ParseRack(p) })
}

// relNestingSeeds are REL payloads with every inner type byte (flags 0,
// the handle its class requires; a valid payload for wrappable types, 20
// zero bytes otherwise), every flag bit of the wrappable types and of REL,
// RACK and DGRAM, and REL inside REL — as a REL payload and as a whole
// REL frame (plan:363 "REL 嵌套").
func relNestingSeeds() [][]byte {
	var out [][]byte
	for i := range 256 {
		ty := Type(i)
		inner := validInner(ty)
		if inner == nil {
			inner = make([]byte, 20)
		}
		out = append(out, relPayload(RelHead{Cseq: uint32(i), Type: ty, Handle: relHandle(ty)}, inner))
		if Wrappable(ty) || ty == TypeRel || ty == TypeRack || ty == TypeDgram {
			for bit := range 8 {
				out = append(out, relPayload(RelHead{Cseq: 1, Type: ty, Flags: 1 << bit, Handle: relHandle(ty)}, inner))
			}
		}
	}
	nested := relPayload(RelHead{Cseq: 1, Type: TypeFin, Handle: SessionHandle}, validInner(TypeFin))
	return append(out,
		relPayload(RelHead{Cseq: 2, Type: TypeRel}, nested),
		relPayload(RelHead{Cseq: 2, Type: TypeRel, Handle: SessionHandle}, AppendFrame(nil, Header{Type: TypeRel, Fseq: 1}, nested)),
	)
}

func FuzzRel_L44(f *testing.F) {
	for _, s := range payloadSeeds(TypeRel) {
		f.Add(s)
	}
	for _, s := range relNestingSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		forPayload(b, TypeRel, func(p []byte) { checkRelInput(t, p) })
	})
}

// checkRelInput: ParseRel follows the reference order; an accepted head
// re-encodes exactly, its type is wrappable (never REL), its inner payload
// aliases the input and, when the inner parser accepts it, is canonical.
func checkRelInput(t *testing.T, p []byte) {
	t.Helper()
	orig := bytes.Clone(p)
	h, inner, err := ParseRel(p)
	if want := refRelErr(p); !sameErr(err, want) {
		t.Fatalf("REL % x: %v, want %v", p[:min(len(p), 16)], err, want)
	}
	if err != nil {
		if h != (RelHead{}) || inner != nil {
			t.Fatalf("error %v with %+v and %d inner bytes", err, h, len(inner))
		}
	} else {
		if len(inner) != len(p)-RelHeadLen || cap(inner) != len(inner) || (len(inner) > 0 && &inner[0] != &p[RelHeadLen]) {
			t.Fatalf("REL inner: %d bytes (cap %d) of %d", len(inner), cap(inner), len(p))
		}
		var hb [RelHeadLen]byte
		PutRelHead(hb[:], &h)
		if !bytes.Equal(hb[:], p[:RelHeadLen]) || !Wrappable(h.Type) || h.Type == TypeRel {
			t.Fatalf("REL head %+v re-encodes as % x", h, hb)
		}
		if v, ierr := decodeTyped(h.Type, inner); ierr == nil {
			if enc := encodeTyped(h.Type, v); !bytes.Equal(enc, inner) {
				t.Fatalf("REL{%v} inner payload accepted but not canonical", h.Type)
			}
		}
	}
	if !bytes.Equal(p, orig) {
		t.Fatal("ParseRel modified its input")
	}
	checkAllocs(t, "ParseRel", func() { sinkErr = parseTyped(TypeRel, p) })
}

func FuzzFlowHeader_L44(f *testing.F) {
	for _, s := range fuzzSeeds() {
		f.Add(s)
	}
	for v := range 4 {
		f.Add(bcat([]byte{byte(v)}, bu64(gFlow))) // versions around 2
	}
	f.Add([]byte{FlowVersion, 0, 0, 0, 0, 0, 0, 0, 1})
	f.Fuzz(func(t *testing.T, d []byte) {
		orig := bytes.Clone(d)
		flow, rest, err := ParseFlowHeader(d)
		if want := refFlowErr(d); !sameErr(err, want) {
			t.Fatalf("flow header % x: %v, want %v", d[:min(len(d), FlowHeaderLen)], err, want)
		}
		if err != nil {
			if flow != 0 || rest != nil {
				t.Fatalf("error %v with flow %#x", err, flow)
			}
		} else {
			if flow != binary.BigEndian.Uint64(d[1:FlowHeaderLen]) || len(rest) != len(d)-FlowHeaderLen || cap(rest) != len(rest) ||
				(len(rest) > 0 && &rest[0] != &d[FlowHeaderLen]) {
				t.Fatalf("flow %#x, %d rest bytes (cap %d) of %d", flow, len(rest), cap(rest), len(d))
			}
			var re [FlowHeaderLen]byte
			PutFlowHeader(re[:], flow)
			if !bytes.Equal(re[:], d[:FlowHeaderLen]) {
				t.Fatalf("flow header re-encodes differently")
			}
		}
		if !bytes.Equal(d, orig) {
			t.Fatal("ParseFlowHeader modified its input")
		}
		checkAllocs(t, "ParseFlowHeader", func() { sinkU64, sinkBytes, sinkErr = ParseFlowHeader(d) })
	})
}

// poisonFrame is a valid frame placed after a datagram's end, inside its
// slice's capacity, to prove that the walk never reads past the datagram.
var poisonFrame = AppendFrame(nil, Header{Type: TypeRack, Fseq: 1}, make([]byte, RackLen))

// datagramSeeds are the shared seeds plus packed datagrams (control frames
// in front of a DGRAM, handshake datagrams back to back) and damaged
// handshake datagrams (PREFACE CRC, frame CRC, a PREFACE behind frames).
func datagramSeeds() [][]byte {
	out := fuzzSeeds()
	g := map[string][]byte{}
	for _, v := range goldenVectors() {
		g[v.name] = v.b
	}
	out = append(out,
		bcat(g["rack_sack"], g["rel_pack_flagged"], g["ping_pad0"], g["dgram_1000"]),
		bcat(g["h2_ok"], g["h3_open_ack"], g["ping_pad0"]),
		bcat(g["h3_open_ack"], g["h4_rack"], g["dgram_empty"]),
		bcat(g["h2_ok"], g["preface"]),
		bcat(g["refusal_version"], g["rack_zero"]),
	)
	for _, at := range []int{20, PrefaceLen + 3, len(g["h1_open"]) - 1} {
		bad := bytes.Clone(g["h1_open"])
		bad[at] ^= 1
		out = append(out, bad)
	}
	return out
}

func FuzzDatagram_L44_L43(f *testing.F) {
	for _, s := range datagramSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		checkDatagramInput(t, b)
		if _, rest, err := ParseFlowHeader(b); err == nil {
			checkDatagramInput(t, rest)
		}
	})
}

// checkDatagramInput walks b as the rendr bytes of one datagram: the walk
// consumes it exactly or stops at exactly one error (the elements before
// it form a valid datagram, the element at the stop fails on its own with
// that error), agrees with the value model, never reads past the datagram
// (bytes after its end inside the slice's capacity change nothing), leaves
// the input unchanged and allocates nothing.
func checkDatagramInput(t *testing.T, b []byte) {
	t.Helper()
	orig := bytes.Clone(b)
	elems, at, err := walkDatagram(b)
	switch {
	case err == nil && at != len(b):
		t.Fatalf("accepted %d of %d bytes", at, len(b))
	case err != nil && at >= len(b):
		t.Fatalf("error %v at %d of %d bytes", err, at, len(b))
	}
	if err != nil {
		if pe, pat, perr := walkDatagram(b[:at]); perr != nil || pe != elems || pat != at {
			t.Fatalf("the %d bytes before the error are not %d valid elements: %d, %v", at, elems, pe, perr)
		}
		var ferr error
		if at == 0 && IsPreface(b) {
			ferr = parsePrefaceEither(b[:PrefaceLen])
		} else {
			f, _, derr := DecodeFrame(b[at:])
			if ferr = derr; derr == nil {
				ferr = parseTyped(f.Type, f.Payload)
			}
		}
		if !errors.Is(ferr, err) {
			t.Fatalf("the element at %d fails with %v alone, %v in the walk", at, ferr, err)
		}
	}
	if vals, merr := decodeDatagram(b); !sameErr(merr, err) || len(vals) != elems {
		t.Fatalf("model: %d elements, %v; walk: %d elements, %v", len(vals), merr, elems, err)
	}
	for _, poison := range [][]byte{make([]byte, 2*len(poisonFrame)), bcat(poisonFrame, poisonFrame)} {
		buf := make([]byte, len(b)+len(poison))
		copy(buf, b)
		copy(buf[len(b):], poison)
		if e2, at2, err2 := walkDatagram(buf[:len(b)]); e2 != elems || at2 != at || !sameErr(err2, err) {
			t.Fatalf("bytes after the datagram changed the walk: %d/%d/%v vs %d/%d/%v", e2, at2, err2, elems, at, err)
		}
	}
	if !bytes.Equal(b, orig) {
		t.Fatal("the datagram walk modified its input")
	}
	checkAllocs(t, "datagram walk", func() { sinkN, sinkAt, sinkErr = walkDatagram(b) })
}

// maxWindowOps bounds the ops of one window fuzz input.
const maxWindowOps = 4096

func FuzzFseqWindow_L43(f *testing.F) {
	f.Add(uint32(1), []byte{2, 0, 0, 2, 0, 0, 0, 0xff, 0xf0, 0, 0xff, 0xff})
	f.Add(uint32(0xfffffff0), bytes.Repeat([]byte{2, 0, 0}, 40)) // across the wrap (L14)
	f.Add(uint32(0x7fffffff), []byte{1, 0x7f, 0xff, 1, 0x80, 0, 0, 0x80, 0, 3, 0x12, 0x34})
	f.Add(uint32(0), []byte{0, 0x80, 0, 0, 0x80, 0, 0, 0xc0, 0, 0, 0x7f, 0xff})
	f.Add(uint32(5), []byte{})
	f.Fuzz(func(t *testing.T, first uint32, ops []byte) {
		var w FseqWindow
		w.Init(first)
		m := newFseqModel(first)
		last := first
		for i := 0; i+3 <= len(ops) && i < 3*maxWindowOps; i += 3 {
			f := nextFseq(m.top, [3]byte(ops[i:i+3]))
			if got, want := w.Accept(f), m.accept(f); got != want {
				t.Fatalf("first %#x, op %d: Accept(%#x) = %d, the model says %d", first, i/3, f, got, want)
			}
			last = f
		}
		checkAllocs(t, "FseqWindow.Accept", func() { sinkVerdict = w.Accept(last); sinkVerdict = w.Accept(last + 1) })
	})
}

func FuzzSeqWindow_L39(f *testing.F) {
	missing0 := bytes.Repeat([]byte{2, 0, 0}, 1500) // 1, 2, 3, … with seq 0 never sent
	f.Add(uint8(0), uint64(1), missing0)
	f.Add(uint8(1), uint64(1<<62-3000), missing0) // near the session's limit (L14)
	f.Add(uint8(2), uint64(1000), []byte{0, 0x80, 0, 0, 0xff, 0xff, 1, 0x80, 0, 0, 0x40, 0, 3, 1, 2})
	f.Add(uint8(0), uint64(math.MaxUint64-5), []byte{2, 0, 0, 2, 0, 0, 0, 0xc0, 0})
	f.Fuzz(func(t *testing.T, size uint8, first uint64, ops []byte) {
		words := 16 << (size % 3) // 1024, 2048 or 4096 bits
		var w SeqWindow
		w.Init(make([]uint64, words))
		width := uint64(words) * 64
		m := newSeqModel(width)
		s := first
		for i := 0; i < 3*maxWindowOps; i += 3 {
			if got, want := w.Accept(s), m.accept(s); got != want {
				t.Fatalf("width %d, op %d: Accept(%#x) = %d, the model says %d", width, i/3, s, got, want)
			}
			if i+3 > len(ops) {
				break
			}
			s = nextSeq(m.top, width, [3]byte(ops[i:i+3]))
		}
		checkAllocs(t, "SeqWindow.Accept", func() { sinkVerdict = w.Accept(s); sinkVerdict = w.Accept(s + 1) })
	})
}
