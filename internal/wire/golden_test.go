package wire

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

// update rewrites testdata/golden.txt from the encoders. Use it only for a
// deliberate wire change (design §5.5): before v2.0.0 the change is recorded
// in the milestone report, after v2.0.0 it needs a version bump.
var update = flag.Bool("update", false, "rewrite testdata/golden.txt from the encoders (deliberate wire changes only)")

const goldenPath = "testdata/golden.txt"

const goldenHeader = `# rendr wire format v2 golden vectors (design §5.5): one "name hex" per line.
# Regenerate only with: go test ./internal/wire -run TestGolden -update
# Any change before v2.0.0 is deliberate and recorded in the milestone report;
# after v2.0.0 it needs a version bump.
`

// Fixed field values of the golden vectors.
var (
	gDialer  = [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	gPassive = [16]byte{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30}
	gSID     = [16]byte{0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf}
)

const gCarrier = 0x01020304

// Decoded payload values that have no struct of their own in package wire.
type (
	dataVal struct {
		Off  uint64
		Body []byte
	}
	finVal uint64
	extVal []byte
)

// pattern returns n deterministic pseudo-random bytes (an LCG keyed by seed).
func pattern(n int, seed uint32) []byte {
	b := make([]byte, n)
	x := seed*2654435761 + 1
	for i := range b {
		x = x*1103515245 + 12345
		b[i] = byte(x >> 16)
	}
	return b
}

// vector is one golden encoding and the canonical value it encodes.
type vector struct {
	name string
	b    []byte
	kind string // "preface", "preface_ack" or "frame"
	hdr  Header // frames: the expected header (Len included)
	val  any    // Preface, PrefaceAck, or the decoded payload value
}

func prefaceVec(name string, p Preface) vector {
	b := make([]byte, PrefaceLen)
	PutPreface(b, &p)
	return vector{name: name, b: b, kind: "preface", val: p}
}

func prefaceAckVec(name string, a PrefaceAck) vector {
	b := make([]byte, PrefaceLen)
	PutPrefaceAck(b, &a)
	return vector{name: name, b: b, kind: "preface_ack", val: a}
}

func frameVec(name string, t Type, flags uint8, fseq, handle uint32, val any) vector {
	payload := encodeTyped(t, val)
	h := Header{Type: t, Flags: flags, Len: uint32(len(payload)), Fseq: fseq, Handle: handle}
	return vector{name: name, b: AppendFrame(nil, h, payload), kind: "frame", hdr: h, val: val}
}

var ackStatusNames = []string{"ok", "unknown_session", "capacity", "rejected", "bad_request", "going_away"}

// goldenVectors builds every golden vector of design §5.5 from canonical values.
func goldenVectors() []vector {
	var vs []vector
	add := func(v vector) { vs = append(vs, v) }

	add(prefaceVec("preface", Preface{Kind: KindStream, Instance: gDialer, CarrierID: gCarrier}))
	add(prefaceVec("preface_datagram_optional_bits", Preface{Minor: 7, Kind: KindDatagram, Opt: 0x80000001, Instance: gDialer, CarrierID: 0xffffffff}))
	for st, name := range []string{"ok", "version", "feature", "going_away", "capacity"} {
		add(prefaceAckVec("preface_ack_"+name, PrefaceAck{Status: PrefaceStatus(st), Instance: gPassive, CarrierID: gCarrier}))
	}

	for i, m := range []int{0, 4096, 65535} {
		o := Open{SID: gSID, Kind: KindStream, Mode: uint8(1 + i), RetainMs: 34000, Window: 8 << 20}
		if m > 0 {
			o.Metadata = pattern(m, uint32(m))
		}
		add(frameVec(fmt.Sprintf("open_mlen%d", m), TypeOpen, 0, FirstFseq, SessionHandle, o))
	}

	add(frameVec("open_ack_ok", TypeOpenAck, 0, FirstFseq, SessionHandle, OpenAck{Status: StatusOK, Window: 8 << 20}))
	codes := map[AckStatus]uint32{StatusCapacity: CodeMaxSessions, StatusRejected: 0x00010001, StatusBadRequest: CodeBadMode}
	for st := StatusUnknownSession; st <= StatusGoingAway; st++ {
		for _, m := range []int{0, MaxMsg} {
			a := OpenAck{Status: st, Code: codes[st]}
			if m > 0 {
				a.Msg = pattern(m, uint32(st))
			}
			add(frameVec(fmt.Sprintf("open_ack_%s_msg%d", ackStatusNames[st], m), TypeOpenAck, 0, FirstFseq, SessionHandle, a))
		}
	}

	add(frameVec("join_selector", TypeJoin, 0, FirstFseq, SessionHandle, Join{SID: gSID, Mode: 1, RxNext: 0x0000000100000000}))
	add(frameVec("join_bond", TypeJoin, 0, FirstFseq, SessionHandle, Join{SID: gSID, Mode: 2}))
	for st := StatusOK; st <= StatusGoingAway; st++ {
		a := JoinAck{Status: st}
		if st == StatusOK {
			a.RxNext = 123456789
		}
		add(frameVec("join_ack_"+ackStatusNames[st], TypeJoinAck, 0, FirstFseq, SessionHandle, a))
	}

	add(frameVec("data_1", TypeData, 0, 2, SessionHandle, dataVal{Off: 0, Body: []byte{0x5a}}))
	add(frameVec("data_64k", TypeData, 0, 0xffffffff, SessionHandle, dataVal{Off: 1<<62 - 64<<10, Body: pattern(64<<10, 64)}))

	for _, fl := range []struct {
		name  string
		flags uint8
	}{{"none", 0}, {"fin_delivered", FlagAckFinDelivered}, {"done", FlagAckDone}, {"fin_delivered_done", FlagAckFinDelivered | FlagAckDone}} {
		add(frameVec("ack_"+fl.name, TypeAck, fl.flags, 3, SessionHandle, Ack{Delivered: 1 << 20, Window: 8 << 20, EpochEcho: 3}))
	}

	add(frameVec("fin", TypeFin, 0, 4, SessionHandle, finVal(1<<20+17)))

	for code := RstClosed; code <= RstWithdrawn; code++ {
		for _, m := range []int{0, MaxMsg} {
			r := Rst{Code: code}
			if m > 0 {
				r.Msg = pattern(m, code)
			}
			add(frameVec(fmt.Sprintf("rst_code%d_msg%d", code, m), TypeRst, 0, 5, SessionHandle, r))
		}
	}

	for cause, cname := range []string{"initial", "death", "quality", "explicit"} {
		one := Sched{Epoch: 7, N: 1}
		one.IDs[0] = gCarrier
		add(frameVec("sched_n1_"+cname, TypeSched, uint8(cause), 6, SessionHandle, one))
		all := Sched{Epoch: 0xffffffff, Death: 0x0102030405060708, Quality: 3, Explicit: 0xffffffffffffffff, N: MaxSchedIDs}
		for i := range all.IDs {
			all.IDs[i] = uint32(i + 1)
		}
		add(frameVec("sched_n16_"+cname, TypeSched, uint8(cause), 6, SessionHandle, all))
	}

	for _, busy := range []bool{false, true} {
		for _, pad := range []int{0, 1000} {
			var flags uint8
			name := "ping"
			if busy {
				flags, name = FlagPingBusy, "ping_busy"
			}
			add(frameVec(fmt.Sprintf("%s_pad%d", name, pad), TypePing, flags, FirstFseq, 0, Ping{ID: 1, TS: 0x0102030405060708, Nonce: 0xdeadbeefcafef00d, Pad: pad}))
		}
	}
	for _, pad := range []int{0, 1000} {
		add(frameVec(fmt.Sprintf("pong_pad%d", pad), TypePong, 0, 8, 0, Ping{ID: 1, TS: 0x0102030405060708, Nonce: 0xdeadbeefcafef00d, Pad: pad}))
	}

	add(frameVec("close_retire", TypeClose, 0, 9, 0, CloseRetire))
	add(frameVec("close_capacity", TypeClose, 0, 9, 0, CloseCapacity))
	add(frameVec("goaway_shutdown", TypeGoAway, 0, 10, 0, GoAwayShutdown))

	add(frameVec("ext_80_flags00_handle0", Type(0x80), 0x00, 11, 0, extVal("extension")))
	add(frameVec("ext_81_flagsff_handle1", Type(0x81), 0xff, 11, 1, extVal(pattern(300, 0x81))))
	add(frameVec("ext_fe_flagsff_handle0_empty", Type(0xfe), 0xff, 11, 0, extVal(nil)))
	add(frameVec("ext_ff_flags00_handle1", Type(0xff), 0x00, 11, 1, extVal("x")))
	return vs
}

// decodeTyped decodes payload p of a frame of type t with its type's parser.
// Extension payloads are opaque and always accepted.
func decodeTyped(t Type, p []byte) (any, error) {
	switch t {
	case TypeOpen:
		return ParseOpen(p, MaxMetadata)
	case TypeOpenAck:
		return ParseOpenAck(p)
	case TypeJoin:
		return ParseJoin(p)
	case TypeJoinAck:
		return ParseJoinAck(p)
	case TypeData:
		off, err := ParseDataOffset(p)
		if err != nil {
			return nil, err
		}
		return dataVal{Off: off, Body: p[DataPrefixLen:]}, nil
	case TypeAck:
		return ParseAck(p)
	case TypeFin:
		off, err := ParseFin(p)
		return finVal(off), err
	case TypeRst:
		return ParseRst(p)
	case TypeSched:
		return ParseSched(p)
	case TypePing, TypePong:
		return ParsePing(p)
	case TypeClose:
		return ParseClose(p)
	case TypeGoAway:
		return ParseGoAway(p)
	}
	if t.Extension() {
		if len(p) == 0 {
			return extVal(nil), nil
		}
		return extVal(p), nil
	}
	return nil, ErrType
}

// encodeTyped encodes a decoded payload value with its type's encoder.
func encodeTyped(t Type, v any) []byte {
	size := OpenFixedLen + MaxMetadata // the largest non-DATA core payload
	switch v := v.(type) {
	case dataVal:
		size = DataPrefixLen + len(v.Body)
	case extVal:
		size = len(v)
	}
	b := make([]byte, size)
	var n int
	switch v := v.(type) {
	case Open:
		n = PutOpen(b, &v)
	case OpenAck:
		n = PutOpenAck(b, &v)
	case Join:
		n = PutJoin(b, &v)
	case JoinAck:
		n = PutJoinAck(b, &v)
	case dataVal:
		PutDataOffset(b, v.Off)
		n = DataPrefixLen + copy(b[DataPrefixLen:], v.Body)
	case Ack:
		n = PutAck(b, &v)
	case finVal:
		n = PutFin(b, uint64(v))
	case Rst:
		n = PutRst(b, &v)
	case Sched:
		n = PutSched(b, &v)
	case Ping:
		n = PutPing(b, &v)
	case CloseReason:
		n = PutReason(b, uint8(v))
	case GoAwayReason:
		n = PutReason(b, uint8(v))
	case extVal:
		n = copy(b, v)
	default:
		panic(fmt.Sprintf("encodeTyped: %T for %v", v, t))
	}
	return b[:n:n]
}

// checkVector decodes v.b with the one decoder that must accept it and
// compares the result with the canonical source value.
func checkVector(v vector) error {
	var got any
	switch v.kind {
	case "preface":
		p, err := ParsePreface(v.b)
		if err != nil {
			return err
		}
		got = p
	case "preface_ack":
		a, err := ParsePrefaceAck(v.b)
		if err != nil {
			return err
		}
		got = a
	case "frame":
		f, n, err := DecodeFrame(v.b)
		if err != nil {
			return err
		}
		if n != len(v.b) {
			return fmt.Errorf("consumed %d of %d bytes", n, len(v.b))
		}
		if f.Header != v.hdr {
			return fmt.Errorf("header %+v, want %+v", f.Header, v.hdr)
		}
		if got, err = decodeTyped(f.Type, f.Payload); err != nil {
			return err
		}
	}
	if !reflect.DeepEqual(got, v.val) {
		return fmt.Errorf("decoded %+v, want %+v", got, v.val)
	}
	return nil
}

func readGolden(t *testing.T) (names []string, enc map[string][]byte) {
	t.Helper()
	fh, err := os.Open(goldenPath)
	if err != nil {
		t.Fatalf("golden vectors missing (generate them with -update): %v", err)
	}
	defer fh.Close()
	enc = map[string][]byte{}
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		name, h, ok := strings.Cut(text, " ")
		if !ok {
			t.Fatalf("%s:%d: want \"name hex\"", goldenPath, line)
		}
		b, err := hex.DecodeString(h)
		if err != nil {
			t.Fatalf("%s:%d: %v", goldenPath, line, err)
		}
		if _, dup := enc[name]; dup {
			t.Fatalf("%s:%d: duplicate vector %q", goldenPath, line, name)
		}
		names = append(names, name)
		enc[name] = b
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return names, enc
}

func writeGolden(t *testing.T, vs []vector) {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteString(goldenHeader)
	for _, v := range vs {
		fmt.Fprintf(&buf, "%s %s\n", v.name, hex.EncodeToString(v.b))
	}
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(goldenPath, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("rewrote %s (%d vectors)", goldenPath, len(vs))
}

// TestGolden_L44 pins wire format v2: the committed vectors must equal what
// the encoders produce from canonical values, in the same order, and each
// must decode back to exactly that value (decode(encode(x)) == x).
func TestGolden_L44(t *testing.T) {
	vs := goldenVectors()
	if *update {
		writeGolden(t, vs)
	}
	names, enc := readGolden(t)
	if len(names) != len(vs) {
		t.Errorf("golden file has %d vectors, the encoders %d", len(names), len(vs))
	}
	for i, v := range vs {
		if i < len(names) && names[i] != v.name {
			t.Errorf("vector %d is %q in the file, %q from the encoders", i, names[i], v.name)
		}
		b, ok := enc[v.name]
		if !ok {
			t.Errorf("%s: missing from %s", v.name, goldenPath)
			continue
		}
		if !bytes.Equal(b, v.b) {
			t.Errorf("%s: committed encoding differs from the encoder (first difference at byte %d)", v.name, firstDiff(b, v.b))
		}
		if err := checkVector(v); err != nil {
			t.Errorf("%s: %v", v.name, err)
		}
	}
	// Every status, flag combination and size class the design lists is present.
	for _, want := range []string{
		"preface", "preface_ack_ok", "preface_ack_version", "preface_ack_feature", "preface_ack_going_away", "preface_ack_capacity",
		"open_mlen0", "open_mlen4096", "open_mlen65535", "open_ack_ok", "open_ack_going_away_msg255",
		"join_ack_ok", "join_ack_going_away", "data_1", "data_64k", "ack_fin_delivered_done", "fin",
		"rst_code6_msg255", "sched_n16_explicit", "ping_busy_pad1000", "pong_pad0", "close_capacity", "goaway_shutdown",
		"ext_81_flagsff_handle1", "ext_fe_flagsff_handle0_empty",
	} {
		if _, ok := enc[want]; !ok {
			t.Errorf("golden file lacks %q", want)
		}
	}
}

func firstDiff(a, b []byte) int {
	for i := range min(len(a), len(b)) {
		if a[i] != b[i] {
			return i
		}
	}
	return min(len(a), len(b))
}
