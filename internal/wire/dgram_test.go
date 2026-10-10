package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"math"
	"testing"
)

// M2 test helpers: decoded values of the four new types, the datagram
// model, and the handshake values of the golden vectors (M2 design §A3).

// Fixed values of the M2 golden vectors.
const (
	gCarrierJoin  uint32 = 0x01020305         // the JOIN carrier of the handshake vectors
	gCarrierProbe uint32 = 0x01020306         // the probe carrier
	gFlow         uint64 = 0x8877665544332211 // the raw-UDP flow ID
	gNonce        uint64 = 0xdeadbeefcafef00d // PING nonce (salt ^ id)
	gTS           uint64 = 0x0102030405060708 // PING timestamp

	gBudget     = 1152                    // the QUIC DATAGRAM frame budget (plan:331)
	gMaxPayload = gBudget - DgramOverhead // 1127
	gMaxMeta    = gBudget - 99            // the metadata an OPEN on that budget carries (§A3.9)
)

// Decoded payload values of the M2 types without a struct of their own.
type (
	dgramVal struct {
		Seq  uint64
		Body []byte // nil when empty
	}
	// relVal is a decoded REL payload: its head and the inner payload
	// decoded by the inner type's parser.
	relVal struct {
		Head  RelHead
		Inner any
	}
	flowVal uint64
	// udpVal is a decoded raw-UDP datagram: the flow ID and the elements
	// of its rendr bytes.
	udpVal struct {
		Flow  uint64
		Elems []dgElem
	}
)

// dgElem is one element of a datagram's rendr bytes: the PREFACE or
// PREFACE_ACK (Kind "preface" / "preface_ack", Val the decoded preface) or
// a frame (Kind "frame", Hdr its header, Val its decoded payload).
type dgElem struct {
	Kind string
	Hdr  Header
	Val  any
}

// gPacketOpen is the OPEN of the golden packet session: QUIC-like budget
// 1152 offered, MaxPayload 1127.
func gPacketOpen() Open {
	return Open{SID: gSID, Kind: KindDatagram, Mode: 1, RetainMs: 34000, Window: gBudget, PMTU: gMaxPayload}
}

// gProbePing is the PING of the golden probe handshake (H1p) and, echoed,
// its PONG (H2p).
func gProbePing() Ping { return Ping{ID: 1, TS: gTS, Nonce: gNonce ^ 1} }

func dgPrefaceVec(id uint32) vector {
	return prefaceVec("", Preface{Kind: KindDatagram, Instance: gDialer, CarrierID: id})
}

func dgAckVec(st PrefaceStatus, id uint32) vector {
	return prefaceAckVec("", PrefaceAck{Status: st, Instance: gPassive, CarrierID: id})
}

// relVec is a REL frame (carrier level, handle 0, flags 0) wrapping inner.
func relVec(name string, fseq uint32, h RelHead, inner any) vector {
	return frameVec(name, TypeRel, 0, fseq, 0, relVal{Head: h, Inner: inner})
}

// rejectFrameVec is a frame with a valid header and CRC whose payload its
// type's parser rejects with err.
func rejectFrameVec(name string, t Type, fseq, handle uint32, val any, err error) vector {
	v := frameVec(name, t, 0, fseq, handle, val)
	v.kind, v.as, v.err = "reject", "frame", err
	return v
}

func flowHeaderVec(name string, flow uint64) vector {
	b := make([]byte, FlowHeaderLen)
	PutFlowHeader(b, flow)
	return vector{name: name, b: b, kind: "flow_header", val: flowVal(flow)}
}

// elemsOf returns the datagram elements a preface, frame or datagram
// vector consists of.
func elemsOf(v vector) []dgElem {
	switch v.kind {
	case "datagram":
		return v.val.([]dgElem)
	case "frame":
		return []dgElem{{Kind: "frame", Hdr: v.hdr, Val: v.val}}
	}
	return []dgElem{{Kind: v.kind, Val: v.val}} // preface, preface_ack
}

// datagramVec concatenates preface and frame vectors into one datagram.
func datagramVec(name string, parts ...vector) vector {
	var b []byte
	var elems []dgElem
	for _, p := range parts {
		b = append(b, p.b...)
		elems = append(elems, elemsOf(p)...)
	}
	return vector{name: name, b: b, kind: "datagram", val: elems}
}

// udpVec prefixes inner's rendr bytes with a raw-UDP flow header.
func udpVec(name string, flow uint64, inner vector) vector {
	b := make([]byte, FlowHeaderLen, FlowHeaderLen+len(inner.b))
	PutFlowHeader(b, flow)
	return vector{name: name, b: append(b, inner.b...), kind: "udp", val: udpVal{Flow: flow, Elems: elemsOf(inner)}}
}

// decodeDatagram decodes the rendr bytes of one datagram as a carrier
// reader walks them (M2 design §A3.4): an optional PREFACE or PREFACE_ACK
// (by its role byte), then whole frames filling the rest exactly, each
// payload decoded by its type's parser (a REL's inner payload too). It
// stops at the first error and returns the elements before it.
func decodeDatagram(b []byte) ([]dgElem, error) {
	var out []dgElem
	if IsPreface(b) {
		head := b[:PrefaceLen]
		var e dgElem
		var err error
		if Role(head[7]) == RolePassive {
			var a PrefaceAck
			a, err = ParsePrefaceAck(head)
			e = dgElem{Kind: "preface_ack", Val: a}
		} else {
			var p Preface
			p, err = ParsePreface(head)
			e = dgElem{Kind: "preface", Val: p}
		}
		if err != nil {
			return nil, err
		}
		out = append(out, e)
		b = b[PrefaceLen:]
	}
	for len(b) > 0 {
		f, n, err := DecodeFrame(b)
		if err != nil {
			return out, err
		}
		v, err := decodeTyped(f.Type, f.Payload)
		if err != nil {
			return out, err
		}
		out = append(out, dgElem{Kind: "frame", Hdr: f.Header, Val: v})
		b = b[n:]
	}
	return out, nil
}

// walkDatagram is decodeDatagram without keeping anything (the allocation
// gate of the datagram walk): it returns the number of elements accepted,
// the offset where it stopped (len(b) when err is nil) and the error.
func walkDatagram(b []byte) (elems, at int, err error) {
	if IsPreface(b) {
		if err := parsePrefaceEither(b[:PrefaceLen]); err != nil {
			return 0, 0, err
		}
		elems, at = 1, PrefaceLen
	}
	for at < len(b) {
		f, n, err := DecodeFrame(b[at:])
		if err == nil {
			err = parseTyped(f.Type, f.Payload)
		}
		if err != nil {
			return elems, at, err
		}
		elems++
		at += n
	}
	return elems, at, nil
}

// parsePrefaceEither parses the 40 bytes of a datagram's leading PREFACE
// or PREFACE_ACK, chosen by its role byte.
func parsePrefaceEither(b []byte) error {
	if Role(b[7]) == RolePassive {
		sinkPrefaceAck, sinkErr = ParsePrefaceAck(b)
	} else {
		sinkPreface, sinkErr = ParsePreface(b)
	}
	return sinkErr
}

// parseTyped runs the payload parser of type t on p and returns its error,
// keeping the decoded value in a sink: the allocation-free counterpart of
// decodeTyped (a REL's inner payload is parsed too). Unknown core types are
// ErrType; extension payloads are opaque.
func parseTyped(t Type, p []byte) error {
	var err error
	switch t {
	case TypeOpen:
		sinkOpen, err = ParseOpen(p, MaxMetadata)
	case TypeOpenAck:
		sinkOpenAck, err = ParseOpenAck(p)
	case TypeJoin:
		sinkJoin, err = ParseJoin(p)
	case TypeJoinAck:
		sinkJoinAck, err = ParseJoinAck(p)
	case TypeData:
		sinkU64, err = ParseDataOffset(p)
	case TypeAck:
		sinkAck, err = ParseAck(p)
	case TypeFin:
		sinkU64, err = ParseFin(p)
	case TypeRst:
		sinkRst, err = ParseRst(p)
	case TypeSched:
		sinkSched, err = ParseSched(p)
	case TypePing, TypePong:
		sinkPing, err = ParsePing(p)
	case TypeClose:
		sinkClose, err = ParseClose(p)
	case TypeGoAway:
		sinkGoAway, err = ParseGoAway(p)
	case TypeDgram:
		sinkU64, sinkBytes, err = ParseDgram(p)
	case TypePack:
		sinkPack, err = ParsePack(p)
	case TypeRack:
		sinkRack, err = ParseRack(p)
	case TypeDetach:
		sinkDetach, err = ParseDetach(p)
	case TypeRel:
		var inner []byte
		if sinkRelHead, inner, err = ParseRel(p); err == nil {
			err = parseTyped(sinkRelHead.Type, inner)
		}
	default:
		if !t.Extension() {
			err = ErrType
		}
	}
	sinkErr = err
	return err
}

// relPayload encodes a REL payload: h, then inner as given.
func relPayload(h RelHead, inner []byte) []byte {
	b := make([]byte, RelHeadLen+len(inner))
	PutRelHead(b, &h)
	copy(b[RelHeadLen:], inner)
	return b
}

// validInner returns a canonical payload of every Wrappable type (nil for
// the others).
func validInner(t Type) []byte {
	switch t {
	case TypeOpen:
		return encodeTyped(t, gPacketOpen())
	case TypeOpenAck:
		return encodeTyped(t, OpenAck{Status: StatusOK, Window: PacketWindow(gMaxPayload, gBudget)})
	case TypeJoin:
		return encodeTyped(t, Join{SID: gSID, Mode: 2, RxNext: gBudget})
	case TypeJoinAck:
		return encodeTyped(t, JoinAck{Status: StatusOK, RxNext: gBudget})
	case TypeFin:
		return encodeTyped(t, finVal(77))
	case TypeRst:
		return encodeTyped(t, Rst{Code: RstIdle, Msg: []byte("idle")})
	case TypeSched:
		s := Sched{Epoch: 2, N: 1}
		s.IDs[0] = 9
		return encodeTyped(t, s)
	case TypeClose:
		return encodeTyped(t, CloseRetire)
	case TypeGoAway:
		return encodeTyped(t, GoAwayShutdown)
	case TypePack:
		return encodeTyped(t, Pack{HighestSeq: 3, Received: 2, EpochEcho: 1})
	case TypeDetach:
		return encodeTyped(t, Detach{Handle: 5, Reason: DetachEnded})
	}
	return nil
}

// relHandle is the inner handle ParseRel requires for type t.
func relHandle(t Type) uint32 {
	if t.CarrierLevel() {
		return 0
	}
	return SessionHandle
}

func bu16(v uint16) []byte        { return binary.BigEndian.AppendUint16(nil, v) }
func bu32(v uint32) []byte        { return binary.BigEndian.AppendUint32(nil, v) }
func bu64(v uint64) []byte        { return binary.BigEndian.AppendUint64(nil, v) }
func bcat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

// goldenByName returns the golden vector called name.
func goldenByName(t *testing.T, name string) vector {
	t.Helper()
	for _, v := range goldenVectors() {
		if v.name == name {
			return v
		}
	}
	t.Fatalf("no golden vector %q", name)
	return vector{}
}

// hdrBytes is a 13-byte frame header with the given fields.
func hdrBytes(typ, flags byte, length, fseq, handle uint32) []byte {
	b := make([]byte, HeaderLen)
	b[0], b[1] = typ, flags
	b[2], b[3], b[4] = byte(length>>16), byte(length>>8), byte(length)
	binary.BigEndian.PutUint32(b[5:9], fseq)
	binary.BigEndian.PutUint32(b[9:13], handle)
	return b
}

// TestDgramPackCodec_L44: DGRAM is seq u64 ‖ bytes (an empty datagram is
// legal, the bytes alias the input, every seq decodes: the session checks
// its limits) and PACK is exactly highestSeq u64 · received u64 · epochEcho
// u32 with the canonical rule received = 0 ⇒ highestSeq = 0; both are
// session frames with their header rules (M2 design §A3.1, §A3.2).
func TestDgramPackCodec_L44(t *testing.T) {
	for _, seq := range []uint64{0, 1, 1 << 32, 1<<62 - 1, 1 << 62, math.MaxUint64} {
		for _, body := range [][]byte{nil, {0x5a}, pattern(37, 1), pattern(MaxPacketPayload, 2)} {
			p := make([]byte, DgramPrefixLen+len(body))
			PutDgramSeq(p, seq)
			copy(p[DgramPrefixLen:], body)
			if !bytes.Equal(p[:DgramPrefixLen], bu64(seq)) {
				t.Fatalf("DGRAM prefix of seq %#x: % x", seq, p[:DgramPrefixLen])
			}
			got, data, err := ParseDgram(p)
			if err != nil || got != seq || !bytes.Equal(data, body) || len(data) != len(body) || cap(data) != len(data) {
				t.Fatalf("DGRAM seq %#x, %d bytes: seq %#x, %d bytes (cap %d), %v", seq, len(body), got, len(data), cap(data), err)
			}
			if len(body) > 0 && &data[0] != &p[DgramPrefixLen] {
				t.Fatalf("DGRAM data does not alias the payload")
			}
			if data == nil {
				t.Fatalf("an empty DGRAM decodes to nil data")
			}
		}
	}
	for n := range DgramPrefixLen {
		if seq, data, err := ParseDgram(make([]byte, n)); !errors.Is(err, ErrShort) || seq != 0 || data != nil {
			t.Errorf("DGRAM of %d bytes: %d, %v, %v; want ErrShort", n, seq, data, err)
		}
	}
	if seq, data, err := ParseDgram(nil); !errors.Is(err, ErrShort) || seq != 0 || data != nil {
		t.Errorf("nil DGRAM: %d, %v, %v", seq, data, err)
	}

	for _, c := range []struct {
		name string
		p    Pack
	}{
		{"zero", Pack{}},
		{"first", Pack{HighestSeq: 1, Received: 1}},
		{"seq limit", Pack{HighestSeq: 1<<62 - 1, Received: 1<<62 - 1, EpochEcho: 0xffffffff}},
		{"max", Pack{HighestSeq: math.MaxUint64, Received: math.MaxUint64, EpochEcho: 7}},
		// received ≤ highestSeq + 1 is the session's check, not the codec's.
		{"received beyond highest", Pack{HighestSeq: 5, Received: 100, EpochEcho: 1}},
	} {
		b := make([]byte, PackLen+3)
		if n := PutPack(b, &c.p); n != PackLen {
			t.Fatalf("%s: PutPack returned %d", c.name, n)
		}
		if want := bcat(bu64(c.p.HighestSeq), bu64(c.p.Received), bu32(c.p.EpochEcho)); !bytes.Equal(b[:PackLen], want) {
			t.Fatalf("%s: % x, want % x", c.name, b[:PackLen], want)
		}
		if got, err := ParsePack(b[:PackLen]); err != nil || got != c.p {
			t.Errorf("%s: %+v, %v", c.name, got, err)
		}
	}
	for n := range PackLen {
		if _, err := ParsePack(make([]byte, n)); !errors.Is(err, ErrShort) {
			t.Errorf("PACK of %d bytes: %v, want ErrShort", n, err)
		}
	}
	if _, err := ParsePack(make([]byte, PackLen+1)); !errors.Is(err, ErrTrailing) {
		t.Errorf("PACK of %d bytes: %v, want ErrTrailing", PackLen+1, err)
	}
	for _, hi := range []uint64{1, 1 << 40, math.MaxUint64} {
		if p, err := ParsePack(bcat(bu64(hi), bu64(0), bu32(3))); !errors.Is(err, ErrReserved) || p != (Pack{}) {
			t.Errorf("PACK highestSeq %#x with received 0: %+v %v, want ErrReserved", hi, p, err)
		}
	}
	// The encoder writes the canonical form itself (C32's rule for PACK).
	b := make([]byte, PackLen)
	PutPack(b, &Pack{HighestSeq: 99, Received: 0, EpochEcho: 4})
	if p, err := ParsePack(b); err != nil || p != (Pack{EpochEcho: 4}) {
		t.Errorf("PACK from a non-canonical struct: %+v %v", p, err)
	}

	// Header rules: session frames (handle SessionHandle); DGRAM 8 … MaxFramePayload with no
	// flags, PACK exactly 20 with FIN_DELIVERED and DONE.
	if AllowedFlags(TypeDgram) != 0 || AllowedFlags(TypePack) != FlagPackFinDelivered|FlagPackDone || FlagPackFinDelivered != FlagAckFinDelivered || FlagPackDone != FlagAckDone {
		t.Errorf("flags: DGRAM %#x, PACK %#x", AllowedFlags(TypeDgram), AllowedFlags(TypePack))
	}
	for _, c := range []struct {
		name string
		h    []byte
		err  error
	}{
		{"DGRAM empty", hdrBytes(0x20, 0, 8, 1, 1), nil},
		{"DGRAM max", hdrBytes(0x20, 0, MaxFramePayload, 1, 1), nil},
		{"DGRAM 7", hdrBytes(0x20, 0, 7, 1, 1), ErrLength},
		{"DGRAM flag", hdrBytes(0x20, 1, 8, 1, 1), ErrFlags},
		{"DGRAM handle 0", hdrBytes(0x20, 0, 8, 1, 0), ErrHandle},
		{"DGRAM handle 2", hdrBytes(0x20, 0, 8, 1, 2), nil}, // any non-zero session handle since M3 (M3-D4)
		{"PACK", hdrBytes(0x21, 3, 20, 1, 1), nil},
		{"PACK 19", hdrBytes(0x21, 0, 19, 1, 1), ErrLength},
		{"PACK 21", hdrBytes(0x21, 0, 21, 1, 1), ErrLength},
		{"PACK flag 2", hdrBytes(0x21, 4, 20, 1, 1), ErrFlags},
		{"PACK handle 0", hdrBytes(0x21, 0, 20, 1, 0), ErrHandle},
	} {
		if _, err := ParseHeader(c.h); !sameErr(err, c.err) {
			t.Errorf("%s: %v, want %v", c.name, err, c.err)
		}
	}
}

// TestRelRackCodec_L44: REL is cseq u32 · itype u8 · iflags u8 · ihandle
// u32 · ipayload with its check order (length, wrappable type, flags,
// handle, inner length), every wrappable type round-trips and its inner
// payload aliases the input; RACK is exactly cumAck u32 · sack u32 with
// only the RelWindow − 1 sack bits defined (M2 design §A3.3).
func TestRelRackCodec_L44(t *testing.T) {
	wrapped := 0
	for i := range 256 {
		ty := Type(i)
		if !Wrappable(ty) {
			continue
		}
		flagSets := []uint8{0}
		if f := AllowedFlags(ty); f != 0 {
			flagSets = append(flagSets, f)
		}
		for _, fl := range flagSets {
			for _, cseq := range []uint32{FirstCseq, 0, 0xffffffff, 0x80000000} {
				h := RelHead{Cseq: cseq, Type: ty, Flags: fl, Handle: relHandle(ty)}
				inner := validInner(ty)
				p := relPayload(h, inner)
				if want := bcat(bu32(cseq), []byte{byte(ty), fl}, bu32(h.Handle), inner); !bytes.Equal(p, want) {
					t.Fatalf("REL{%v} layout % x, want % x", ty, p, want)
				}
				got, in, err := ParseRel(p)
				if err != nil || got != h || !bytes.Equal(in, inner) || cap(in) != len(in) || &in[0] != &p[RelHeadLen] {
					t.Fatalf("REL{%v} flags %#x cseq %#x: %+v %v (inner equal %v)", ty, fl, cseq, got, err, bytes.Equal(in, inner))
				}
				if _, err := decodeTyped(got.Type, in); err != nil {
					t.Fatalf("REL{%v}: inner payload rejected by its parser: %v", ty, err)
				}
				wrapped++
			}
		}
	}
	if wrapped != (11+2)*4 { // eleven types (DETACH since M3), two of them (SCHED, PACK) with flags
		t.Fatalf("%d REL round trips, want %d", wrapped, (11+2)*4)
	}

	// Check order: each seed is valid up to its step and damaged at the
	// step and in every later field, so the error proves which check runs
	// first.
	fin := bu64(5)
	for _, c := range []struct {
		name string
		p    []byte
		err  error
	}{
		{"short", bcat(bu32(1), []byte{0x7f, 0xff}, bu32(9))[:RelHeadLen-1], ErrShort},
		{"empty", nil, ErrShort},
		{"type", bcat(bu32(1), []byte{byte(TypeData), 0xff}, bu32(9)), ErrType},
		{"flags", bcat(bu32(1), []byte{byte(TypeFin), 1}, bu32(9), fin[:3]), ErrFlags},
		{"handle", bcat(bu32(1), []byte{byte(TypeFin), 0}, bu32(0), fin[:3]), ErrHandle},
		{"handle 2", bcat(bu32(1), []byte{byte(TypeFin), 0}, bu32(2), fin), nil}, // any non-zero session handle since M3 (M3-D4)
		{"handle 2, short", bcat(bu32(1), []byte{byte(TypeFin), 0}, bu32(2), fin[:7]), ErrLength},
		{"DETACH handle 1", bcat(bu32(1), []byte{byte(TypeDetach), 0}, bu32(1), validInner(TypeDetach)), ErrHandle},
		{"DETACH", bcat(bu32(1), []byte{byte(TypeDetach), 0}, bu32(0), validInner(TypeDetach)), nil},
		{"length", bcat(bu32(1), []byte{byte(TypeFin), 0}, bu32(1), fin[:7]), ErrLength},
		{"length trailing", bcat(bu32(1), []byte{byte(TypeFin), 0}, bu32(1), fin, []byte{0}), ErrLength},
		{"CLOSE handle 1", bcat(bu32(1), []byte{byte(TypeClose), 0}, bu32(1), []byte{1}), ErrHandle},
		{"CLOSE flags", bcat(bu32(1), []byte{byte(TypeClose), 2}, bu32(0), []byte{1}), ErrFlags},
		{"CLOSE", bcat(bu32(1), []byte{byte(TypeClose), 0}, bu32(0), []byte{1}), nil},
		{"SCHED cause", bcat(bu32(1), []byte{byte(TypeSched), 3}, bu32(1), validInner(TypeSched)), nil},
		{"SCHED flag 2", bcat(bu32(1), []byte{byte(TypeSched), 4}, bu32(1), validInner(TypeSched)), ErrFlags},
		{"PACK flags", bcat(bu32(1), []byte{byte(TypePack), 3}, bu32(1), validInner(TypePack)), nil},
		{"PACK flag 2", bcat(bu32(1), []byte{byte(TypePack), 4}, bu32(1), validInner(TypePack)), ErrFlags},
		{"OPEN beyond its metadata bound", bcat(bu32(1), []byte{byte(TypeOpen), 0}, bu32(1), make([]byte, OpenFixedLen+MaxMetadata+1)), ErrLength},
		{"OPEN at its metadata bound", bcat(bu32(1), []byte{byte(TypeOpen), 0}, bu32(1), make([]byte, OpenFixedLen+MaxMetadata)), nil},
	} {
		h, in, err := ParseRel(c.p)
		if !sameErr(err, c.err) {
			t.Errorf("%s: %v, want %v", c.name, err, c.err)
		}
		if err != nil && (h != (RelHead{}) || in != nil) {
			t.Errorf("%s: error %v with %+v, inner %d bytes", c.name, err, h, len(in))
		}
	}
	// Inner length bounds are the inner type's PayloadBounds; the inner
	// payload's own rules are its parser's (applied at dispatch).
	for i := range 256 {
		ty := Type(i)
		if !Wrappable(ty) {
			continue
		}
		lo, hi, _ := PayloadBounds(ty)
		for _, n := range []int{lo - 1, lo, hi, hi + 1} {
			if n < 0 {
				continue
			}
			_, _, err := ParseRel(relPayload(RelHead{Cseq: 1, Type: ty, Handle: relHandle(ty)}, make([]byte, n)))
			var want error
			if n < lo || n > hi {
				want = ErrLength
			}
			if !sameErr(err, want) {
				t.Errorf("REL{%v} inner %d bytes (bounds %d…%d): %v, want %v", ty, n, lo, hi, err, want)
			}
		}
	}
	zeroOpen := relPayload(RelHead{Cseq: 1, Type: TypeOpen, Handle: SessionHandle}, make([]byte, OpenFixedLen))
	if _, in, err := ParseRel(zeroOpen); err != nil || parseTyped(TypeOpen, in) == nil {
		t.Errorf("REL{OPEN} with a zero SID: ParseRel %v, the inner parser must reject it", err)
	}
	// REL header rules: carrier level, no flags, 10 … MaxFramePayload.
	for _, c := range []struct {
		name string
		h    []byte
		err  error
	}{
		{"REL", hdrBytes(0x34, 0, RelHeadLen, 1, 0), nil},
		{"REL max", hdrBytes(0x34, 0, MaxFramePayload, 1, 0), nil},
		{"REL 9", hdrBytes(0x34, 0, RelHeadLen-1, 1, 0), ErrLength},
		{"REL flag", hdrBytes(0x34, 1, RelHeadLen, 1, 0), ErrFlags},
		{"REL handle 1", hdrBytes(0x34, 0, RelHeadLen, 1, 1), ErrHandle},
		{"RACK", hdrBytes(0x35, 0, RackLen, 1, 0), nil},
		{"RACK 7", hdrBytes(0x35, 0, RackLen-1, 1, 0), ErrLength},
		{"RACK 9", hdrBytes(0x35, 0, RackLen+1, 1, 0), ErrLength},
		{"RACK flag", hdrBytes(0x35, 0x80, RackLen, 1, 0), ErrFlags},
		{"RACK handle 1", hdrBytes(0x35, 0, RackLen, 1, 1), ErrHandle},
	} {
		if _, err := ParseHeader(c.h); !sameErr(err, c.err) {
			t.Errorf("%s: %v, want %v", c.name, err, c.err)
		}
	}

	// RACK: every defined sack combination and the cumAck wrap (L14).
	b := make([]byte, RackLen)
	for _, cum := range []uint32{0, FirstCseq, 0x7fffffff, 0xfffffffe, 0xffffffff} {
		for sack := uint32(0); sack <= rackSackMask; sack++ {
			r := Rack{CumAck: cum, Sack: sack}
			if n := PutRack(b, &r); n != RackLen || !bytes.Equal(b, bcat(bu32(cum), bu32(sack))) {
				t.Fatalf("RACK %+v: % x", r, b)
			}
			if got, err := ParseRack(b); err != nil || got != r {
				t.Fatalf("RACK %+v: %+v %v", r, got, err)
			}
		}
	}
	if rackSackMask != 0x7f || RelWindow-1 != 7 {
		t.Fatalf("sack mask %#x for RelWindow %d", rackSackMask, RelWindow)
	}
	for bit := RelWindow - 1; bit < 32; bit++ {
		r := Rack{CumAck: 3, Sack: 1 << bit}
		PutRack(b, &r) // written as given
		if got, err := ParseRack(b); !errors.Is(err, ErrReserved) || got != (Rack{}) {
			t.Errorf("RACK sack bit %d: %+v %v, want ErrReserved", bit, got, err)
		}
	}
	for n := range RackLen {
		if _, err := ParseRack(make([]byte, n)); !errors.Is(err, ErrShort) {
			t.Errorf("RACK of %d bytes: %v, want ErrShort", n, err)
		}
	}
	if _, err := ParseRack(make([]byte, RackLen+1)); !errors.Is(err, ErrTrailing) {
		t.Errorf("RACK of 9 bytes: %v, want ErrTrailing", err)
	}
}

// TestRelNestingImpossible_L44: a REL carries exactly the ten wrappable
// types — plan:356's nine control frames and PACK — and every other type
// byte is ErrType whatever its flags, handle and length: REL inside REL,
// RACK, DGRAM, DATA, ACK, PING, PONG, extensions and unassigned types can
// never be wrapped (plan:363 "REL 嵌套"; M2-D7).
func TestRelNestingImpossible_L44(t *testing.T) {
	want := map[Type]bool{
		TypeOpen: true, TypeOpenAck: true, TypeJoin: true, TypeJoinAck: true, TypeFin: true,
		TypeRst: true, TypeSched: true, TypeClose: true, TypeGoAway: true, TypePack: true,
		TypeDetach: true, // M3-D6
	}
	lengths := []int{0, 1, 8, 20, RelMaxPayload, 1 << 16}
	bufs := make([][]byte, len(lengths))
	for i, n := range lengths {
		bufs[i] = make([]byte, RelHeadLen+n)
	}
	checked := 0
	for i := range 256 {
		ty := Type(i)
		if Wrappable(ty) != want[ty] {
			t.Errorf("Wrappable(%v) = %v", ty, Wrappable(ty))
		}
		if want[ty] {
			if !ty.Known() || ty.Extension() || (ty.CarrierLevel() && ty != TypeClose && ty != TypeGoAway && ty != TypeDetach) {
				t.Errorf("wrappable %v: known %v, carrier level %v", ty, ty.Known(), ty.CarrierLevel())
			}
			if _, _, err := ParseRel(relPayload(RelHead{Cseq: 1, Type: ty, Handle: relHandle(ty)}, validInner(ty))); err != nil {
				t.Errorf("REL{%v}: %v", ty, err)
			}
			continue
		}
		for _, flags := range []uint8{0, 1, 0xff} {
			for _, handle := range []uint32{0, 1, 0xffffffff} {
				for _, p := range bufs {
					PutRelHead(p, &RelHead{Cseq: 1, Type: ty, Flags: flags, Handle: handle})
					h, in, err := ParseRel(p)
					if !errors.Is(err, ErrType) || h != (RelHead{}) || in != nil {
						t.Fatalf("REL{%v} flags %#x handle %d, %d bytes: %v, want ErrType", ty, flags, handle, len(p), err)
					}
					checked++
				}
			}
		}
	}
	if checked != (256-11)*3*3*6 {
		t.Fatalf("%d non-wrappable REL payloads checked", checked)
	}
	// A valid REL payload wrapped again, and a whole valid REL frame as the
	// inner payload, are ErrType: nesting is impossible by construction.
	inner := relPayload(RelHead{Cseq: 1, Type: TypeFin, Handle: SessionHandle}, validInner(TypeFin))
	if _, _, err := ParseRel(inner); err != nil {
		t.Fatalf("inner REL: %v", err)
	}
	frame := AppendFrame(nil, Header{Type: TypeRel, Fseq: 3}, inner)
	for _, in := range [][]byte{inner, frame} {
		for _, handle := range []uint32{0, SessionHandle} {
			if _, _, err := ParseRel(relPayload(RelHead{Cseq: 2, Type: TypeRel, Handle: handle}, in)); !errors.Is(err, ErrType) {
				t.Errorf("REL in REL (%d inner bytes, handle %d): %v, want ErrType", len(in), handle, err)
			}
		}
	}
	for _, ty := range []Type{TypeRel, TypeRack, TypeDgram, TypeData, TypeAck, TypePing, TypePong, TypeReservedR, 0x80, 0xff, 0x00} {
		if Wrappable(ty) {
			t.Errorf("%v is wrappable", ty)
		}
	}
}

// TestFlowHeader_L44_L58: the raw-UDP flow header is ver u8 (= 2) · flow
// u64 (≠ 0), frozen; anything shorter, another version or flow 0 is
// ErrFlowHeader (dropped and counted, never answered: L58); the rendr bytes
// behind it alias the datagram and may be empty (M2 design §A3.4).
func TestFlowHeader_L44_L58(t *testing.T) {
	for _, flow := range []uint64{1, gFlow, 1 << 63, math.MaxUint64} {
		b := make([]byte, FlowHeaderLen+3)
		PutFlowHeader(b, flow)
		copy(b[FlowHeaderLen:], "xyz")
		if !bytes.Equal(b[:FlowHeaderLen], bcat([]byte{2}, bu64(flow))) {
			t.Fatalf("flow header of %#x: % x", flow, b[:FlowHeaderLen])
		}
		got, rest, err := ParseFlowHeader(b)
		if err != nil || got != flow || string(rest) != "xyz" || &rest[0] != &b[FlowHeaderLen] || cap(rest) != len(rest) {
			t.Fatalf("flow %#x: %#x, %q (cap %d), %v", flow, got, rest, cap(rest), err)
		}
		if got, rest, err := ParseFlowHeader(b[:FlowHeaderLen]); err != nil || got != flow || len(rest) != 0 {
			t.Fatalf("a bare flow header: %#x, %d rest bytes, %v", got, len(rest), err)
		}
		for n := range FlowHeaderLen {
			if got, rest, err := ParseFlowHeader(b[:n]); !errors.Is(err, ErrFlowHeader) || got != 0 || rest != nil {
				t.Errorf("flow header of %d bytes: %#x %v %v", n, got, rest, err)
			}
		}
		for v := range 256 {
			if v == FlowVersion {
				continue
			}
			c := bytes.Clone(b)
			c[0] = byte(v)
			if got, rest, err := ParseFlowHeader(c); !errors.Is(err, ErrFlowHeader) || got != 0 || rest != nil {
				t.Fatalf("flow header version %d: %#x %v %v", v, got, rest, err)
			}
		}
	}
	zero := bcat([]byte{FlowVersion}, bu64(0), []byte("RND2"))
	if got, rest, err := ParseFlowHeader(zero); !errors.Is(err, ErrFlowHeader) || got != 0 || rest != nil {
		t.Errorf("flow 0: %#x %v %v", got, rest, err)
	}
	if FlowHeaderLen != 9 || FlowVersion != 2 {
		t.Fatalf("the flow header is frozen at 9 bytes, version 2")
	}
	for name, f := range map[string]func(){
		"flow 0": func() { PutFlowHeader(make([]byte, FlowHeaderLen), 0) },
		"short":  func() { PutFlowHeader(make([]byte, FlowHeaderLen-1), 1) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("PutFlowHeader %s: no panic", name)
				}
			}()
			f()
		}()
	}
	// A raw-UDP H1 is accepted only as a flow-headed datagram; its flow
	// header is not a frame and its rendr bytes are the H1.
	udp := goldenByName(t, "udp_h1_open")
	if got := acceptors(udp.b); len(got) != 1 || got[0] != "udp" {
		t.Errorf("udp_h1_open accepted by %v", got)
	}
	if _, rest, err := ParseFlowHeader(udp.b); err != nil || !bytes.Equal(rest, goldenByName(t, "h1_open").b) {
		t.Errorf("udp_h1_open rendr bytes differ from h1_open: %v", err)
	}
	b := goldenByName(t, "flow_header").b
	if a := testing.AllocsPerRun(100, func() {
		sinkU64, sinkBytes, sinkErr = ParseFlowHeader(b)
		sinkU64, sinkBytes, sinkErr = ParseFlowHeader(zero)
		PutFlowHeader(b, gFlow)
	}); a != 0 {
		t.Errorf("flow header codec: %v allocs", a)
	}
}

// TestPrefaceTypeReserved_L44: 0x52 ('R', the first PREFACE magic byte) is
// never a frame type, so a datagram's rendr bytes that start with "RND2"
// are a PREFACE or PREFACE_ACK candidate and never a frame (IsPreface), and
// no frame is ever taken for a preface (M2 design §A3.1, §A3.4).
func TestPrefaceTypeReserved_L44(t *testing.T) {
	if TypeReservedR != 0x52 || byte(TypeReservedR) != Magic[0] {
		t.Fatalf("TypeReservedR = %#x", byte(TypeReservedR))
	}
	if TypeReservedR.Known() || TypeReservedR.Extension() || TypeReservedR.CarrierLevel() || Wrappable(TypeReservedR) {
		t.Errorf("0x52 is assigned: known %v", TypeReservedR.Known())
	}
	if _, _, ok := PayloadBounds(TypeReservedR); ok {
		t.Errorf("0x52 has payload bounds")
	}
	for _, flags := range []byte{0, 1} {
		for _, handle := range []uint32{0, 1} {
			if _, err := ParseHeader(hdrBytes(0x52, flags, 20, 1, handle)); !errors.Is(err, ErrType) {
				t.Errorf("type 0x52 flags %d handle %d: %v, want ErrType", flags, handle, err)
			}
		}
	}
	known := 0
	for i := range 256 {
		if ty := Type(i); ty.Known() {
			known++
			if byte(ty) == Magic[0] {
				t.Errorf("%v starts with the magic byte", ty)
			}
		}
	}
	if known != 18 {
		t.Fatalf("%d known core types, want 13 (M1) + 4 (M2) + 1 (M3)", known)
	}
	pre, ack := validPrefaces()
	for _, c := range []struct {
		name string
		b    []byte
		want bool
	}{
		{"PREFACE", pre, true},
		{"PREFACE_ACK", ack, true},
		{"PREFACE with frames behind it", goldenByName(t, "h1_open").b, true},
		{"magic and 36 zero bytes (a candidate; the parsers decide)", bcat([]byte("RND2"), make([]byte, 36)), true},
		{"39 bytes", pre[:PrefaceLen-1], false},
		{"other magic", bcat([]byte("RND1"), pre[4:]), false},
		{"lower case", bcat([]byte("rND2"), pre[4:]), false},
		{"empty", nil, false},
		{"REL before PREFACE", goldenByName(t, "rel_open_packet").b, false},
		{"H3", goldenByName(t, "h3_open_ack").b, false},
	} {
		if got := IsPreface(c.b); got != c.want {
			t.Errorf("IsPreface(%s) = %v", c.name, got)
		}
	}
	frames := 0
	for _, v := range goldenVectors() {
		if v.kind == "frame" || (v.kind == "reject" && v.as == "frame") {
			frames++
			if IsPreface(v.b) || IsPreface(append(bytes.Clone(v.b), pre...)) {
				t.Errorf("%s is taken for a preface", v.name)
			}
		}
	}
	if frames < 80 {
		t.Fatalf("only %d golden frames checked", frames)
	}
	if a := testing.AllocsPerRun(100, func() { sinkBool = IsPreface(pre) || IsPreface(pre[:7]) }); a != 0 {
		t.Errorf("IsPreface: %v allocs", a)
	}
}

// TestOpenPacketFields_L44: for a packet session (OPEN kind 2) the codec
// requires pmtu in 512 … 65,507 and window 0 (a stream carrier) or in
// MinFrameBudget … MaxDatagram (ErrValue); the checks come after every M1
// check; stream OPENs, OPEN_ACK, JOIN and JOIN_ACK keep their M1 rules and
// layouts (M2 design §A3.5, PA-2).
func TestOpenPacketFields_L44(t *testing.T) {
	open := func(kind byte, window uint32, pmtu uint16) []byte {
		b := make([]byte, OpenFixedLen)
		PutOpen(b, &Open{SID: gSID, Kind: CarrierKind(kind), Mode: 1, RetainMs: 34000, Window: window, PMTU: pmtu})
		return b
	}
	for _, c := range []struct {
		name   string
		kind   byte
		window uint32
		pmtu   uint16
		err    error
	}{
		{"packet, minimum", 2, MinFrameBudget, MinPacketPayload, nil},
		{"packet, maximum", 2, MaxDatagram, MaxPacketPayload, nil},
		{"packet, QUIC budget", 2, gBudget, gMaxPayload, nil},
		{"packet on a stream carrier", 2, 0, MaxPacketPayload, nil},
		{"packet pmtu 0", 2, gBudget, 0, ErrValue},
		{"packet pmtu 511", 2, gBudget, 511, ErrValue},
		{"packet pmtu 65508", 2, gBudget, 65508, ErrValue},
		{"packet pmtu 65535", 2, 0, 65535, ErrValue},
		{"packet window 1", 2, 1, gMaxPayload, ErrValue},
		{"packet window 536", 2, MinFrameBudget - 1, gMaxPayload, ErrValue},
		{"packet window 65508", 2, MaxDatagram + 1, gMaxPayload, ErrValue},
		{"packet window 8 MiB (a stream window)", 2, 8 << 20, gMaxPayload, ErrValue},
		{"packet window max", 2, math.MaxUint32, gMaxPayload, ErrValue},
		{"stream, any window", 1, 8 << 20, 0, nil},
		{"stream, window 0", 1, 0, 0, nil},
		{"stream, window max", 1, math.MaxUint32, 0, nil},
		{"stream with a pmtu", 1, 8 << 20, gMaxPayload, ErrReserved},
	} {
		o, err := ParseOpen(open(c.kind, c.window, c.pmtu), 0)
		if !sameErr(err, c.err) {
			t.Errorf("%s: %v, want %v", c.name, err, c.err)
			continue
		}
		if err == nil && (o.Window != c.window || o.PMTU != c.pmtu || o.Kind != CarrierKind(c.kind)) {
			t.Errorf("%s: decoded %+v", c.name, o)
		}
	}
	accepted := 0
	for pmtu := range 1 << 16 {
		_, err := ParseOpen(open(2, gBudget, uint16(pmtu)), 0)
		if ok := pmtu >= MinPacketPayload && pmtu <= MaxPacketPayload; ok != (err == nil) || (!ok && !errors.Is(err, ErrValue)) {
			t.Fatalf("packet pmtu %d: %v", pmtu, err)
		}
		if err == nil {
			accepted++
		}
	}
	if accepted != MaxPacketPayload-MinPacketPayload+1 {
		t.Fatalf("%d pmtu values accepted", accepted)
	}
	for _, w := range []uint32{0, 1, 2, 536, 537, 538, 1152, 65506, 65507, 65508, 1 << 16, 1 << 20, math.MaxUint32} {
		_, err := ParseOpen(open(2, w, gMaxPayload), 0)
		if ok := w == 0 || (w >= MinFrameBudget && w <= MaxDatagram); ok != (err == nil) || (!ok && !errors.Is(err, ErrValue)) {
			t.Errorf("packet window %d: %v", w, err)
		}
	}
	// The packet checks run after every M1 check (the passive's reason
	// code follows the first failing field).
	bad := func(edit func(b []byte)) []byte {
		b := open(2, 1, 1) // pmtu and window both out of range
		edit(b)
		return b
	}
	for _, c := range []struct {
		name string
		b    []byte
		max  int
		err  error
	}{
		{"pmtu before window", bad(func([]byte) {}), 0, ErrValue},
		{"mlen over the limit first", bad(func(b []byte) { b[31] = 1 }), 0, ErrLength},
		{"zero SID first", bad(func(b []byte) { clear(b[:16]) }), 0, ErrReserved},
		{"mode first", bad(func(b []byte) { b[17] = 0 }), 0, ErrValue},
		{"flags first", bad(func(b []byte) { b[19] = 1 }), 0, ErrReserved},
	} {
		if _, err := ParseOpen(c.b, c.max); !errors.Is(err, c.err) {
			t.Errorf("%s: %v, want %v", c.name, err, c.err)
		}
	}
	// The packet fields sit in the M1 layout: window at bytes 24–27, pmtu
	// at 28–29.
	b := open(2, gBudget, gMaxPayload)
	if !bytes.Equal(b, bcat(gSID[:], []byte{2, 1}, bu16(0), bu32(34000), bu32(gBudget), bu16(gMaxPayload), bu16(0))) {
		t.Errorf("packet OPEN layout % x", b)
	}
	// OPEN_ACK, JOIN and JOIN_ACK cannot know the session kind: their
	// codecs accept every window and rxNext as in M1.
	buf := make([]byte, 64)
	for _, w := range []uint32{0, PacketWindow(gMaxPayload, gBudget), PacketWindow(MaxPacketPayload, 0), math.MaxUint32} {
		n := PutOpenAck(buf, &OpenAck{Status: StatusOK, Window: w})
		if a, err := ParseOpenAck(buf[:n]); err != nil || a.Window != w {
			t.Errorf("OPEN_ACK window %#x: %+v %v", w, a, err)
		}
	}
	for _, rx := range []uint64{0, gBudget, MaxDatagram, math.MaxUint64} {
		n := PutJoin(buf, &Join{SID: gSID, Mode: 1, RxNext: rx})
		if j, err := ParseJoin(buf[:n]); err != nil || j.RxNext != rx {
			t.Errorf("JOIN rxNext %d: %+v %v", rx, j, err)
		}
		n = PutJoinAck(buf, &JoinAck{Status: StatusOK, RxNext: rx})
		if a, err := ParseJoinAck(buf[:n]); err != nil || a.RxNext != rx {
			t.Errorf("JOIN_ACK rxNext %d: %+v %v", rx, a, err)
		}
	}
}

// TestPacketWindowSplit: OPEN_ACK(OK).window of a packet session is pmtu_acc
// << 16 | cmtu_acc and splits back exactly; the OPEN_ACK codec carries it
// unchanged (M2-D11).
func TestPacketWindowSplit(t *testing.T) {
	if w := PacketWindow(1127, 1152); w != 0x04670480 {
		t.Fatalf("PacketWindow(1127, 1152) = %#x", w)
	}
	for _, p := range []uint16{0, 1, MinPacketPayload, gMaxPayload, MaxPacketPayload, math.MaxUint16} {
		for _, c := range []uint16{0, 1, MinFrameBudget, gBudget, MaxDatagram, math.MaxUint16} {
			w := PacketWindow(p, c)
			if w != uint32(p)<<16|uint32(c) {
				t.Fatalf("PacketWindow(%d, %d) = %#x", p, c, w)
			}
			if gp, gc := SplitPacketWindow(w); gp != p || gc != c {
				t.Fatalf("SplitPacketWindow(%#x) = %d, %d; want %d, %d", w, gp, gc, p, c)
			}
		}
	}
	for _, w := range []uint32{0, 1, 0xffff, 0x10000, 0x04670480, 0x80000000, math.MaxUint32} {
		if got := PacketWindow(SplitPacketWindow(w)); got != w {
			t.Fatalf("PacketWindow(SplitPacketWindow(%#x)) = %#x", w, got)
		}
	}
	b := make([]byte, OpenAckFixedLen)
	PutOpenAck(b, &OpenAck{Status: StatusOK, Window: PacketWindow(gMaxPayload, gBudget)})
	a, err := ParseOpenAck(b)
	if p, c := SplitPacketWindow(a.Window); err != nil || p != gMaxPayload || c != gBudget {
		t.Fatalf("OPEN_ACK(OK) packet window: %d, %d, %v", p, c, err)
	}
	if p, c := SplitPacketWindow(PacketWindow(MaxPacketPayload, 0)); p != MaxPacketPayload || c != 0 {
		t.Fatalf("a stream carrier's cmtu_acc 0: %d, %d", p, c)
	}
}

// TestControlFrameSizes_L37: every row of the size table of M2 design
// §A3.9, and its consequences: the largest control frame after the
// handshake fits ControlFloor, every datagram carrier carries MaxPayload ≥
// 512, MaxPayload on one carrier is budget − 25 and the metadata an OPEN
// carries is budget − 99 (L37; plan:331, plan:358).
func TestControlFrameSizes_L37(t *testing.T) {
	size := func(ty Type, v any) int { return FrameOverhead + len(encodeTyped(ty, v)) }
	rel := func(ty Type, flags uint8, v any) int {
		return size(TypeRel, relVal{Head: RelHead{Cseq: 1, Type: ty, Flags: flags, Handle: relHandle(ty)}, Inner: v})
	}
	withMeta := func(m int) Open {
		o := gPacketOpen()
		if m > 0 {
			o.Metadata = make([]byte, m)
		}
		return o
	}
	msg := func(k int) []byte {
		if k == 0 {
			return nil
		}
		return make([]byte, k)
	}
	sched := func(n int) Sched {
		s := Sched{Epoch: 1, N: n}
		for i := range n {
			s.IDs[i] = uint32(i + 1)
		}
		return s
	}
	h1 := len(goldenByName(t, "h1_open").b)
	type row struct {
		name      string
		got, want int
	}
	rows := []row{
		{"DGRAM, 0 bytes", size(TypeDgram, dgramVal{Seq: 1}), 25},
		{"DGRAM, 1000 bytes", size(TypeDgram, dgramVal{Seq: 1, Body: make([]byte, 1000)}), 25 + 1000},
		{"PACK", size(TypePack, Pack{}), 37},
		{"REL{PACK}", rel(TypePack, 3, Pack{HighestSeq: 1, Received: 1}), 47},
		{"RACK", size(TypeRack, Rack{}), 25},
		{"PING", size(TypePing, Ping{ID: 1}), 37},
		{"PONG", size(TypePong, Ping{ID: 1}), 37},
		{"PING, pad 100", size(TypePing, Ping{ID: 1, Pad: 100}), 37 + 100},
		{"REL{OPEN}, no metadata", rel(TypeOpen, 0, withMeta(0)), 59},
		{"REL{OPEN}, 1053 bytes of metadata", rel(TypeOpen, 0, withMeta(gMaxMeta)), 59 + gMaxMeta},
		{"REL{OPEN_ACK} OK", rel(TypeOpenAck, 0, OpenAck{Status: StatusOK, Window: 1}), 37},
		{"REL{OPEN_ACK}, a 255-byte message", rel(TypeOpenAck, 0, OpenAck{Status: StatusRejected, Msg: msg(MaxMsg)}), 292},
		{"REL{JOIN}", rel(TypeJoin, 0, Join{SID: gSID, Mode: 1}), 52},
		{"REL{JOIN_ACK}", rel(TypeJoinAck, 0, JoinAck{}), 36},
		{"REL{FIN}", rel(TypeFin, 0, finVal(1)), 35},
		{"REL{RST}, no message", rel(TypeRst, 0, Rst{Code: 1}), 32},
		{"REL{RST}, a 255-byte message", rel(TypeRst, 0, Rst{Code: 1, Msg: msg(MaxMsg)}), 32 + 255},
		{"REL{CLOSE}", rel(TypeClose, 0, CloseRetire), 28},
		{"REL{GOAWAY}", rel(TypeGoAway, 0, GoAwayShutdown), 28},
		// M3 (design §A3.6).
		{"DETACH (stream)", size(TypeDetach, Detach{Handle: 2, Reason: DetachEnded}), 22},
		{"REL{DETACH} (datagram)", rel(TypeDetach, 0, Detach{Handle: 2, Reason: DetachRetired}), 32},
		{"OPEN on a live stream trunk, no metadata", size(TypeOpen, Open{SID: gSID, Kind: KindStream, Mode: ModeRace}), 49},
		{"OPEN on a live stream trunk, 100 bytes of metadata", size(TypeOpen, Open{SID: gSID, Kind: KindStream, Mode: 1, Metadata: make([]byte, 100)}), 49 + 100},
		{"REL{OPEN} on a live datagram trunk, no metadata", rel(TypeOpen, 0, withMeta(0)), 59},
		{"H1: PREFACE ‖ REL{OPEN}", h1, 99},
		{"H1: PREFACE ‖ REL{JOIN}", len(goldenByName(t, "h1_join").b), 92},
		{"H1p: PREFACE ‖ PING", len(goldenByName(t, "h1_probe").b), 77},
		{"H2: PREFACE_ACK ‖ RACK", len(goldenByName(t, "h2_ok").b), 65},
		{"H2p: PREFACE_ACK ‖ PONG", len(goldenByName(t, "h2_probe").b), 77},
		{"PREFACE-level refusal", len(goldenByName(t, "refusal_version").b), 40},
		{"raw-UDP flow carriers: + 9", len(goldenByName(t, "udp_h1_open").b), h1 + 9},
	}
	for n := 1; n <= MaxSchedIDs; n++ {
		rows = append(rows, row{"REL{SCHED} n", rel(TypeSched, 0, sched(n)), 56 + 4*n})
	}
	for _, budget := range []int{MinFrameBudget, gBudget, 1223, MaxDatagram} {
		rows = append(rows,
			row{"MTU probe PING at the budget", size(TypePing, Ping{ID: 9, Pad: budget - 37}), budget},
			row{"DGRAM of budget − 25 bytes", size(TypeDgram, dgramVal{Seq: 1, Body: make([]byte, budget-DgramOverhead)}), budget},
			row{"H1 with budget − 99 bytes of metadata", PrefaceLen + rel(TypeOpen, 0, withMeta(budget-99)), budget},
		)
	}
	for _, r := range rows {
		if r.got != r.want {
			t.Errorf("%s: %d bytes, want %d", r.name, r.got, r.want)
		}
	}
	if rows[len(rows)-1].got == 0 || len(rows) < 40 {
		t.Fatalf("size table incomplete: %d rows", len(rows))
	}

	// The largest REL payload after the handshake (every wrappable type
	// but OPEN, the dialer's first datagram only) is RelMaxPayload, and its
	// frame fits ControlFloor.
	largest := 0
	for i := range 256 {
		if ty := Type(i); Wrappable(ty) && ty != TypeOpen {
			_, hi, _ := PayloadBounds(ty)
			largest = max(largest, RelHeadLen+hi)
		}
	}
	if largest != RelMaxPayload || RelMaxPayload != 275 || FrameOverhead+RelMaxPayload != 292 || FrameOverhead+RelMaxPayload > ControlFloor {
		t.Errorf("largest post-handshake REL payload %d, RelMaxPayload %d, frame %d, ControlFloor %d", largest, RelMaxPayload, FrameOverhead+RelMaxPayload, ControlFloor)
	}
	if ControlFloor >= MinFrameBudget || MinFrameBudget-DgramOverhead != MinPacketPayload || MinFrameBudget != 537 || DgramOverhead != 25 {
		t.Errorf("ControlFloor %d, MinFrameBudget %d, DgramOverhead %d", ControlFloor, MinFrameBudget, DgramOverhead)
	}
	for _, c := range []struct {
		name                      string
		budget, payload, metadata int
	}{
		{"QUIC", gBudget, 1127, 1053},
		{"carrier/udp default (MaxDatagram 1232)", 1232 - FlowHeaderLen, 1198, 1124},
		{"MinFrameBudget", MinFrameBudget, MinPacketPayload, MinFrameBudget - 99},
		{"MaxDatagram", MaxDatagram, MaxDatagram - 25, MaxDatagram - 99},
	} {
		if c.budget-DgramOverhead != c.payload || c.budget-(PrefaceLen+FrameOverhead+RelHeadLen+OpenFixedLen) != c.metadata {
			t.Errorf("%s budget %d: MaxPayload %d, metadata %d", c.name, c.budget, c.budget-DgramOverhead, c.budget-99)
		}
	}
	if MaxPacketPayload != MaxDatagram || MaxDatagram != 65507 || MinPacketPayload != 512 {
		t.Errorf("packet payload bounds %d … %d, MaxDatagram %d", MinPacketPayload, MaxPacketPayload, MaxDatagram)
	}
}

// TestHandshakeDatagrams_L44: the datagram handshakes H1 (PREFACE ‖
// REL{FirstCseq, OPEN | JOIN}), H1p (PREFACE ‖ PING), H2 (PREFACE_ACK ‖
// RACK{FirstCseq}), H2p (PREFACE_ACK ‖ PONG), H3 (REL{FirstCseq, OPEN_ACK}),
// H4 (RACK{FirstCseq}) and the PREFACE-level refusals, built byte by byte
// from M2 design §A3.4 and §A5.10 independently of the encoders, equal the
// golden vectors; each direction's first frame carries its PREFACE's or
// PREFACE_ACK's CRC field as fseq and later frames follow it; a resent H1 is
// byte-identical and its frame is a window duplicate (plan:320–324; L44).
func TestHandshakeDatagrams_L44(t *testing.T) {
	castagnoli := crc32.MakeTable(crc32.Castagnoli)
	crc := func(b []byte) []byte { return bu32(crc32.Checksum(b, castagnoli)) }
	preface := func(b6, role byte, inst [16]byte, id uint32) []byte {
		h := bcat([]byte("RND2"), []byte{2, 0, b6, role}, bu32(0), bu32(0), inst[:], bu32(id))
		return append(h, crc(h)...)
	}
	frame := func(typ, flags byte, fseq, handle uint32, payload []byte) []byte {
		n := len(payload)
		h := bcat([]byte{typ, flags, byte(n >> 16), byte(n >> 8), byte(n)}, bu32(fseq), bu32(handle), payload)
		return append(h, crc(h)...)
	}
	first := func(pf []byte) uint32 { return binary.BigEndian.Uint32(pf[36:40]) } // design §0.13 A6
	rel := func(cseq uint32, itype, iflags byte, ihandle uint32, inner []byte) []byte {
		return bcat(bu32(cseq), []byte{itype, iflags}, bu32(ihandle), inner)
	}

	pre := preface(2, 1, gDialer, gCarrier) // kind datagram, role dialer
	openP := bcat(gSID[:], []byte{2, 1}, bu16(0), bu32(34000), bu32(1152), bu16(1127), bu16(0))
	h1 := bcat(pre, frame(0x34, 0, first(pre), 0, rel(1, 0x01, 0, 1, openP)))
	preJ := preface(2, 1, gDialer, gCarrierJoin)
	h1j := bcat(preJ, frame(0x34, 0, first(preJ), 0, rel(1, 0x03, 0, 1, bcat(gSID[:], []byte{1}, bu64(1152)))))
	preP := preface(2, 1, gDialer, gCarrierProbe)
	ping := bcat(bu32(1), bu64(gTS), bu64(gNonce^1))
	h1p := bcat(preP, frame(0x30, 0, first(preP), 0, ping))
	ack := preface(0, 2, gPassive, gCarrier) // status OK, role passive
	h2 := bcat(ack, frame(0x35, 0, first(ack), 0, bcat(bu32(1), bu32(0))))
	ackP := preface(0, 2, gPassive, gCarrierProbe)
	h2p := bcat(ackP, frame(0x31, 0, first(ackP), 0, ping))
	h3 := frame(0x34, 0, first(ack)+1, 0, rel(1, 0x02, 0, 1, bcat([]byte{0}, bu32(1127<<16|1152), bu32(0), []byte{0})))
	h4 := frame(0x35, 0, first(pre)+1, 0, bcat(bu32(1), bu32(0)))
	refusal := preface(1, 2, gPassive, gCarrier) // VERSION
	udp := bcat([]byte{2}, bu64(gFlow), h1)

	for _, c := range []struct {
		name string
		want []byte
		size int
	}{
		{"h1_open", h1, 99},
		{"h1_resend", h1, 99},
		{"h1_join", h1j, 92},
		{"h1_probe", h1p, 77},
		{"h2_ok", h2, 65},
		{"h2_probe", h2p, 77},
		{"h3_open_ack", h3, 37},
		{"h4_rack", h4, 25},
		{"refusal_version", refusal, 40},
		{"udp_h1_open", udp, 108},
	} {
		got := goldenByName(t, c.name).b
		if !bytes.Equal(got, c.want) || len(got) != c.size {
			t.Errorf("%s (%d bytes, want %d):\n got % x\nwant % x", c.name, len(got), c.size, got, c.want)
		}
		rendr := c.want
		if c.name == "udp_h1_open" {
			rendr = rendr[FlowHeaderLen:]
		}
		if _, at, err := walkDatagram(rendr); err != nil {
			t.Errorf("%s does not walk: stop at %d: %v", c.name, at, err)
		}
	}
	// Every PREFACE-level refusal is the PREFACE_ACK alone.
	for st := PrefaceVersion; st <= PrefaceCapacity; st++ {
		b := make([]byte, PrefaceLen)
		PutPrefaceAck(b, &PrefaceAck{Status: st, Instance: gPassive, CarrierID: gCarrier})
		if want := preface(byte(st), 2, gPassive, gCarrier); !bytes.Equal(b, want) || !IsPreface(b) {
			t.Errorf("refusal %d: % x, want % x", st, b, want)
		}
		if elems, at, err := walkDatagram(b); err != nil || elems != 1 || at != PrefaceLen {
			t.Errorf("refusal %d walks as %d elements, %v", st, elems, err)
		}
	}

	// Decoded: the REL cseqs, the RACKs that cover them, the PONG echo,
	// the packet fields, and the fseq chain of each direction.
	elems := func(b []byte) []dgElem {
		t.Helper()
		e, err := decodeDatagram(b)
		if err != nil {
			t.Fatalf("decode % x: %v", b, err)
		}
		return e
	}
	e1, e2, e1p, e2p := elems(h1), elems(h2), elems(h1p), elems(h2p)
	open := e1[1].Val.(relVal)
	if pf := e1[0].Val.(Preface); pf.Kind != KindDatagram || len(e1) != 2 || e1[1].Hdr.Fseq != PrefaceFseq(h1) ||
		open.Head != (RelHead{Cseq: FirstCseq, Type: TypeOpen, Handle: SessionHandle}) {
		t.Errorf("H1: %+v", e1)
	}
	if o := open.Inner.(Open); o.Kind != KindDatagram || o.Window != gBudget || o.PMTU != gMaxPayload {
		t.Errorf("H1 OPEN: %+v", o)
	}
	if r := e2[1].Val.(Rack); r.CumAck != open.Head.Cseq || r.Sack != 0 || e2[1].Hdr.Fseq != PrefaceFseq(h2) || e2[0].Val.(PrefaceAck).Status != PrefaceOK {
		t.Errorf("H2: %+v", e2)
	}
	if e1p[1].Val != e2p[1].Val || e1p[1].Val.(Ping).Pad != 0 || e1p[1].Hdr.Type != TypePing || e2p[1].Hdr.Type != TypePong ||
		e1p[1].Hdr.Fseq != PrefaceFseq(h1p) || e2p[1].Hdr.Fseq != PrefaceFseq(h2p) {
		t.Errorf("H1p/H2p: %+v / %+v", e1p, e2p)
	}
	r3 := elems(h3)[0]
	oa := r3.Val.(relVal)
	if pm, cm := SplitPacketWindow(oa.Inner.(OpenAck).Window); r3.Hdr.Fseq != PrefaceFseq(h2)+1 || oa.Head.Cseq != FirstCseq || pm != gMaxPayload || cm != gBudget {
		t.Errorf("H3: fseq %#x, %+v", r3.Hdr.Fseq, oa)
	}
	r4 := elems(h4)[0]
	if r4.Hdr.Fseq != PrefaceFseq(h1)+1 || r4.Val.(Rack).CumAck != oa.Head.Cseq {
		t.Errorf("H4: %+v", r4)
	}
	if PrefaceFseq(h1) == PrefaceFseq(h1j) || PrefaceFseq(h1) == PrefaceFseq(h2) {
		t.Errorf("first fseqs do not differ between carriers and directions")
	}
	// IsPreface tells the handshake datagrams from every other one; the REL
	// of an H1 that arrives without its PREFACE is a frame only (the
	// passive drops it and keeps no state, plan:324).
	for name, b := range map[string][]byte{"H1": h1, "H1p": h1p, "H2": h2, "H2p": h2p} {
		if !IsPreface(b) {
			t.Errorf("%s: not a preface candidate", name)
		}
	}
	for name, b := range map[string][]byte{"H3": h3, "H4": h4, "H1 without its PREFACE": h1[PrefaceLen:]} {
		if IsPreface(b) {
			t.Errorf("%s: taken for a preface", name)
		}
	}
	// A resent H1 is byte-identical (PA-21): the passive's window drops its
	// frame as a duplicate after the first copy.
	var w FseqWindow
	w.Init(PrefaceFseq(h1))
	resend := goldenByName(t, "h1_resend").b
	for i, b := range [][]byte{h1, resend} {
		f, _, err := DecodeFrame(b[PrefaceLen:])
		want := WindowNew
		if i > 0 {
			want = WindowDuplicate
		}
		if v := w.Accept(f.Fseq); err != nil || v != want {
			t.Errorf("H1 copy %d: %v, %v", i, v, err)
		}
	}
	// The largest H1 fits the QUIC budget exactly.
	meta := gPacketOpen()
	meta.Metadata = make([]byte, gMaxMeta)
	if n := PrefaceLen + FrameOverhead + len(encodeTyped(TypeRel, relVal{Head: open.Head, Inner: meta})); n != gBudget {
		t.Errorf("H1 with %d bytes of metadata: %d bytes, want %d", gMaxMeta, n, gBudget)
	}
}
