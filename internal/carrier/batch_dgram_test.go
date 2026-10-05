package carrier

import (
	"bytes"
	"encoding/binary"
	"math/rand/v2"
	"net"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// dgBatch returns a fresh round of a datagram batch with frame budget
// budget and REL room room.
func dgBatch(budget, room int) *Batch {
	b := NewBatch(0)
	b.Reset(time.Unix(1700000000, 0))
	b.SetDatagram(budget, room)
	return b
}

// stampRels stamps consecutive cseqs from first on every new REL of the
// round, as the writer's relSeal does, and returns their REL payloads
// (copies, as the send slots hold them).
func stampRels(b *Batch, first uint32) [][]byte {
	var out [][]byte
	for k := range b.relCount() {
		out = append(out, bytes.Clone(b.relPayload(k, first+uint32(k))))
	}
	return out
}

// frameSize returns the bytes frame i occupies on the wire.
func frameSize(b *Batch, i int) int {
	return wire.FrameOverhead + int(b.frames[i].hdr.Len)
}

// datagram is one packed datagram of a sealed batch.
type datagram struct {
	i, end, n int
	bytes     []byte
}

// packDatagrams packs a sealed batch into datagrams for budget, as the
// datagram writer does (nextDatagram, appendDatagram into a reused scratch
// after headroom bytes), and returns them with the rendr bytes copied.
func packDatagrams(b *Batch, budget, headroom int) []datagram {
	var out []datagram
	scratch := make([]byte, 0, headroom+wire.MaxDatagram)
	for i := 0; i < b.Len(); {
		end, n := b.nextDatagram(i, budget)
		d := b.appendDatagram(scratch[:headroom], i, end)
		out = append(out, datagram{i: i, end: end, n: n, bytes: bytes.Clone(d[headroom:])})
		i = end
	}
	return out
}

// decodeAll decodes every frame of rendr bytes p, which must hold complete
// frames only (a datagram, or the coalesced stream form).
func decodeAll(t *testing.T, p []byte) []wire.Frame {
	t.Helper()
	var out []wire.Frame
	for len(p) > 0 {
		f, n, err := wire.DecodeFrame(p)
		if err != nil {
			t.Fatalf("frame %d: %v", len(out), err)
		}
		out = append(out, f)
		p = p[n:]
	}
	return out
}

// TestBatchDgram_L41 (M2 design §A5.8, M2-D7, M2-D12, M2-D16, M2-D26,
// M2-D39; Revision 1, R1-20): the datagram mode of a Batch. A datagram
// batch reserves the reliable control frames as REL frames within the
// round's REL room — a reliable Add* without room refuses and changes
// nothing, every other frame still fits — the writer stamps their cseqs
// (relPayload) before seal, a retransmission is a new outer frame around
// the byte-identical REL payload and takes no room; a DGRAM is seq ‖
// referenced body with one chunk reference per (batch, chunk), counted as
// DATA only on a stream batch; and the sealed frames pack into datagrams
// whole and in insertion order, at most one DGRAM per datagram as its last
// frame, a padded PING or PONG alone, control frames riding in front of the
// next DGRAM when they fit, an oversize frame alone. A stream batch keeps
// every M1 behaviour and carries DGRAM and PACK as ordinary frames.
func TestBatchDgram_L41(t *testing.T) {
	t.Run("mode", func(t *testing.T) {
		b := NewBatch(0)
		b.Reset(time.Unix(1, 0))
		if b.Datagram() || b.RelRoom() != 0 || b.DgramRoom() != wire.MaxPacketPayload {
			t.Fatalf("stream round: datagram %v, REL room %d, DGRAM room %d", b.Datagram(), b.RelRoom(), b.DgramRoom())
		}
		b.SetDatagram(1152, wire.RelWindow)
		if !b.Datagram() || b.RelRoom() != wire.RelWindow || b.DgramRoom() != 1152-wire.DgramOverhead {
			t.Fatalf("datagram round: datagram %v, REL room %d, DGRAM room %d", b.Datagram(), b.RelRoom(), b.DgramRoom())
		}
		b.SetDatagram(wire.MinFrameBudget, 3) // still empty: the round's values may be set again
		if b.RelRoom() != 3 || b.DgramRoom() != wire.MinPacketPayload {
			t.Fatalf("after a second SetDatagram: REL room %d, DGRAM room %d", b.RelRoom(), b.DgramRoom())
		}
		b.SetDatagram(10, 0) // a budget below the DGRAM overhead carries no datagram
		if b.DgramRoom() != 0 {
			t.Fatalf("budget 10: DGRAM room %d", b.DgramRoom())
		}
		b.addPing(false, &wire.Ping{ID: 1})
		mustPanic(t, "SetDatagram on a batch with frames", func() { b.SetDatagram(1152, 8) })
		b.Reset(time.Unix(2, 0))
		if b.Datagram() || b.RelRoom() != 0 || b.relCount() != 0 || b.relRefused() {
			t.Fatal("Reset did not end datagram mode")
		}
		mustPanic(t, "negative budget", func() { NewBatch(0).SetDatagram(-1, 8) })
		mustPanic(t, "budget above MaxDatagram", func() { NewBatch(0).SetDatagram(wire.MaxDatagram+1, 8) })
		mustPanic(t, "negative REL room", func() { NewBatch(0).SetDatagram(1152, -1) })
		mustPanic(t, "REL room above RelWindow", func() { NewBatch(0).SetDatagram(1152, wire.RelWindow+1) })
	})

	t.Run("rel marking", func(t *testing.T) {
		sched := wire.Sched{Epoch: 7, N: 2, IDs: [wire.MaxSchedIDs]uint32{11, 12}}
		pack := wire.Pack{HighestSeq: 99, Received: 90, EpochEcho: 7}
		msg := bytes.Repeat([]byte{'r'}, wire.MaxMsg)
		type rel struct {
			t      wire.Type
			flags  uint8
			handle uint32
			size   int // bytes on the wire (M2 design §A3.9)
		}
		wants := []rel{
			{wire.TypeOpenAck, 0, h1, 292},                                         // REL{OPEN_ACK} with a 255-byte message
			{wire.TypeJoinAck, 0, h1, 36},                                          // REL{JOIN_ACK}
			{wire.TypeFin, 0, h1, 35},                                              // REL{FIN}
			{wire.TypeRst, 0, h1, 32 + 6},                                          // REL{RST} with a 6-byte message
			{wire.TypeSched, uint8(wire.SchedDeath), h1, 56 + 4*2},                 // REL{SCHED} with 2 IDs
			{wire.TypePack, 0, h1, 47},                                             // a reliable PACK
			{wire.TypePack, wire.FlagPackFinDelivered | wire.FlagPackDone, h1, 47}, // a flagged PACK is always reliable
			{wire.TypeClose, 0, 0, 28},                                             // REL{CLOSE}
		}
		b := dgBatch(1232, wire.RelWindow)
		adds := []bool{
			b.AddOpenAck(h1, &wire.OpenAck{Status: wire.StatusCapacity, Code: wire.CodeCarriers, Msg: msg}),
			b.AddJoinAck(h1, &wire.JoinAck{Status: wire.StatusOK, RxNext: 1152}),
			b.AddFin(h1, 4242),
			b.AddRst(h1, &wire.Rst{Code: wire.RstLinger, Msg: []byte("linger")}),
			b.AddSched(h1, wire.SchedDeath, &sched),
			b.AddPack(h1, 0, &pack, true),
			b.AddPack(h1, wire.FlagPackFinDelivered|wire.FlagPackDone, &pack, false),
			b.addClose(wire.CloseRetire),
		}
		for i, ok := range adds {
			if !ok {
				t.Fatalf("reliable frame %d refused with REL room left", i)
			}
		}
		if b.RelRoom() != 0 || b.relCount() != wire.RelWindow || b.relRefused() {
			t.Fatalf("after %d reliable frames: REL room %d, relCount %d, refused %v", wire.RelWindow, b.RelRoom(), b.relCount(), b.relRefused())
		}
		// The REL window is used: every reliable Add* refuses and changes
		// nothing; every other frame still fits.
		n, used, ctl := b.Len(), b.used, b.ctl
		refused := []bool{
			b.addGoAway(wire.GoAwayShutdown),
			b.AddFin(h1, 1),
			b.AddSched(h1, wire.SchedQuality, &sched),
			b.AddPack(h1, 0, &pack, true),
			b.AddPack(h1, wire.FlagPackDone, &pack, false),
			b.AddOpenAck(h1, &wire.OpenAck{Status: wire.StatusOK}),
			b.AddJoinAck(h1, &wire.JoinAck{Status: wire.StatusOK}),
			b.AddRst(h1, &wire.Rst{Code: 1}),
		}
		for i, ok := range refused {
			if ok {
				t.Fatalf("reliable frame %d added without REL room", i)
			}
		}
		if b.Len() != n || b.used != used || b.ctl != ctl || b.relCount() != wire.RelWindow || !b.relRefused() {
			t.Fatalf("refused reliable frames changed the batch: len %d/%d arena %d/%d ctl %d/%d refused %v", b.Len(), n, b.used, used, b.ctl, ctl, b.relRefused())
		}
		if !b.AddPack(h1, 0, &pack, false) || !b.addRack(&wire.Rack{CumAck: 3}) || !b.addPing(false, &wire.Ping{ID: 2}) ||
			!b.addPong(&wire.Ping{ID: 3}) || !b.AddDgram(h1, 5, []byte("dgram"), nil) {
			t.Fatal("an unreliable frame was refused once the REL room was used")
		}
		if f := b.Frame(n); f.Rel || f.Header.Type != wire.TypePack || b.frames[n].hdr.Type != wire.TypePack {
			t.Fatalf("an unreliable unflagged PACK was wrapped: %+v", f.Header)
		}

		// Each REL: outer header REL (handle 0, length 10 + inner), the
		// inner frame in Frame's view, the M1 parsers accept the inner
		// payload, the sizes of §A3.9.
		for i, w := range wants {
			f, out := b.Frame(i), b.frames[i].hdr
			if out.Type != wire.TypeRel || out.Flags != 0 || out.Handle != 0 || int(out.Len) != wire.RelHeadLen+int(f.Header.Len) {
				t.Errorf("frame %d outer header %+v", i, out)
			}
			if !f.Rel || f.Header.Type != w.t || f.Header.Flags != w.flags || f.Header.Handle != w.handle || len(f.Payload) != int(f.Header.Len) {
				t.Errorf("frame %d inner %+v rel %v, want %v flags %#x handle %d", i, f.Header, f.Rel, w.t, w.flags, w.handle)
			}
			if got := frameSize(b, i); got != w.size {
				t.Errorf("frame %d (%v) is %d bytes on the wire, want %d", i, w.t, got, w.size)
			}
		}
		if a, err := wire.ParseOpenAck(b.Frame(0).Payload); err != nil || a.Status != wire.StatusCapacity || !bytes.Equal(a.Msg, msg) {
			t.Errorf("REL{OPEN_ACK}: %+v %v", a, err)
		}
		if a, err := wire.ParseJoinAck(b.Frame(1).Payload); err != nil || a.RxNext != 1152 {
			t.Errorf("REL{JOIN_ACK}: %+v %v", a, err)
		}
		if off, err := wire.ParseFin(b.Frame(2).Payload); err != nil || off != 4242 {
			t.Errorf("REL{FIN}: %d %v", off, err)
		}
		if r, err := wire.ParseRst(b.Frame(3).Payload); err != nil || string(r.Msg) != "linger" {
			t.Errorf("REL{RST}: %+v %v", r, err)
		}
		if s, err := wire.ParseSched(b.Frame(4).Payload); err != nil || s != sched {
			t.Errorf("REL{SCHED}: %+v %v", s, err)
		}
		if r, err := wire.ParseClose(b.Frame(7).Payload); err != nil || r != wire.CloseRetire {
			t.Errorf("REL{CLOSE}: %v %v", r, err)
		}

		// The cseqs, in insertion order, and the REL payload layout:
		// cseq u32 · itype u8 · iflags u8 · ihandle u32 · ipayload.
		pays := stampRels(b, 0xfffffffe) // wraps (L14)
		for k, p := range pays {
			f := b.Frame(int(b.relIdx[k]))
			cs := binary.BigEndian.Uint32(p[0:4])
			if cs != 0xfffffffe+uint32(k) || wire.Type(p[4]) != f.Header.Type || p[5] != f.Header.Flags ||
				binary.BigEndian.Uint32(p[6:10]) != f.Header.Handle || !bytes.Equal(p[wire.RelHeadLen:], f.Payload) || len(p) > wire.RelMaxPayload {
				t.Errorf("REL %d payload %x (cseq %#x)", k, p[:wire.RelHeadLen], cs)
			}
			h, inner, err := wire.ParseRel(p)
			if err != nil || h.Cseq != cs || h.Type != f.Header.Type || !bytes.Equal(inner, f.Payload) {
				t.Errorf("REL %d: ParseRel %+v %v", k, h, err)
			}
		}
		if k, err := wire.ParsePack(b.Frame(5).Payload); err != nil || k != pack {
			t.Errorf("REL{PACK}: %+v %v", k, err)
		}
		mustPanic(t, "relPayload(-1)", func() { b.relPayload(-1, 1) })
		mustPanic(t, "relPayload(relCount)", func() { b.relPayload(b.relCount(), 1) })

		// The same calls on a stream batch: ordinary frames (M1), nothing
		// wrapped, no REL room needed.
		s := NewBatch(0)
		s.Reset(time.Unix(3, 0))
		ok := s.AddOpenAck(h1, &wire.OpenAck{Status: wire.StatusOK, Window: 1 << 20}) && s.AddJoinAck(h1, &wire.JoinAck{Status: wire.StatusOK}) &&
			s.AddFin(h1, 4242) && s.AddRst(h1, &wire.Rst{Code: 1}) && s.AddSched(h1, wire.SchedDeath, &sched) &&
			s.AddPack(h1, 0, &pack, true) && s.AddPack(h1, wire.FlagPackDone, &pack, false) && s.addClose(wire.CloseRetire) && s.addGoAway(wire.GoAwayShutdown)
		if !ok || s.Len() != 9 || s.relCount() != 0 || s.RelRoom() != 0 || s.relRefused() {
			t.Fatalf("stream batch: ok %v len %d relCount %d", ok, s.Len(), s.relCount())
		}
		types := []wire.Type{wire.TypeOpenAck, wire.TypeJoinAck, wire.TypeFin, wire.TypeRst, wire.TypeSched, wire.TypePack, wire.TypePack, wire.TypeClose, wire.TypeGoAway}
		for i, ty := range types {
			if f := s.Frame(i); f.Rel || f.Header.Type != ty || s.frames[i].hdr.Type != ty {
				t.Errorf("stream frame %d: %v (rel %v), want a bare %v", i, f.Header.Type, f.Rel, ty)
			}
		}
		if f := s.Frame(6); f.Header.Flags != wire.FlagPackDone || f.Header.Handle != h1 || f.Header.Len != wire.PackLen {
			t.Errorf("stream PACK header %+v", f.Header)
		}
		s.seal(1) // nothing to stamp on a stream batch
		mustPanic(t, "ACK on a datagram batch", func() { dgBatch(1152, 8).AddAck(h1, 0, &wire.Ack{}) })
		mustPanic(t, "DATA on a datagram batch", func() { dgBatch(1152, 8).AddData(h1, 0, []byte{1}, nil, false) })
		mustPanic(t, "RACK on a stream batch", func() { s.addRack(&wire.Rack{}) })
		mustPanic(t, "REL retransmission on a stream batch", func() { s.addRelRetx(make([]byte, wire.RelHeadLen)) })
		mustPanic(t, "undefined PACK flags", func() { s.AddPack(h1, 0x04, &pack, false) })
	})

	t.Run("rel room", func(t *testing.T) {
		// A carrier with all eight RELs outstanding: no reliable frame, and
		// the refusal is recorded for the writer's blocked flag (W5).
		b := dgBatch(1152, 0)
		if b.AddFin(h1, 1) || b.addClose(wire.CloseRetire) || b.AddPack(h1, wire.FlagPackDone, &wire.Pack{}, false) || b.Len() != 0 || !b.relRefused() {
			t.Fatalf("REL room 0: len %d, refused %v", b.Len(), b.relRefused())
		}
		if !b.AddPack(h1, 0, &wire.Pack{}, false) || b.Len() != 1 {
			t.Fatal("REL room 0 refused an unreliable PACK")
		}
		// Room 3: exactly three reliable frames, whatever their type.
		b = dgBatch(1152, 3)
		got := 0
		for i := range 6 {
			if b.AddFin(h1, uint64(i)) {
				got++
			}
			if b.relRefused() != (got == 3 && i >= 3) {
				t.Fatalf("after %d attempts: refused %v", i+1, b.relRefused())
			}
		}
		if got != 3 || b.Len() != 3 || b.relCount() != 3 || b.RelRoom() != 0 {
			t.Fatalf("room 3: %d placed, len %d, relCount %d, room %d", got, b.Len(), b.relCount(), b.RelRoom())
		}
		// A full batch refuses a reliable frame without reporting the REL
		// window: the frame waits for the next round, not for a RACK.
		b = dgBatch(1152, wire.RelWindow)
		for range MaxBatchFrames {
			b.addPing(false, &wire.Ping{})
		}
		if b.AddFin(h1, 1) || b.relRefused() || b.RelRoom() != wire.RelWindow {
			t.Fatalf("full batch: refused %v, room %d", b.relRefused(), b.RelRoom())
		}
	})

	t.Run("seal and retransmission", func(t *testing.T) {
		// Round 1: two new RELs, stamped and sealed; the wire frames are
		// REL frames whose payloads are exactly the stamped REL payloads.
		b := dgBatch(1152, wire.RelWindow)
		sched := wire.Sched{Epoch: 2, N: 1, IDs: [wire.MaxSchedIDs]uint32{9}}
		if !b.AddFin(h1, 77) || !b.AddSched(h1, wire.SchedQuality, &sched) {
			t.Fatal("building round 1")
		}
		mustPanic(t, "seal before relPayload", func() { b.seal(1) })
		b.relPayload(0, 41)
		mustPanic(t, "seal with one REL unstamped", func() { b.seal(1) })
		b.relPayload(1, 42)
		pays := [][]byte{bytes.Clone(b.relPayload(0, 41)), bytes.Clone(b.relPayload(1, 42))} // re-stamping is idempotent
		if next := b.seal(100); next != 102 {
			t.Fatalf("seal returned %d", next)
		}
		raw1 := b.appendTo(nil)
		first := decodeAll(t, raw1)
		for i, f := range first {
			if f.Type != wire.TypeRel || f.Fseq != 100+uint32(i) || f.Handle != 0 || !bytes.Equal(f.Payload, pays[i]) {
				t.Fatalf("round 1 frame %d: %+v", i, f.Header)
			}
			if bf := b.Frame(i); !bf.Rel || bf.Header.Fseq != f.Fseq {
				t.Fatalf("round 1 view %d: %+v", i, bf.Header)
			}
		}
		if h, inner, err := wire.ParseRel(first[0].Payload); err != nil || h.Cseq != 41 || h.Type != wire.TypeFin {
			t.Fatalf("REL{FIN}: %+v %v", h, err)
		} else if off, err := wire.ParseFin(inner); err != nil || off != 77 {
			t.Fatalf("REL{FIN} inner: %d %v", off, err)
		}

		// Round 2: the oldest is retransmitted — a new outer frame (new
		// fseq, new CRC) around the byte-identical REL payload (PA-21) —
		// taking no REL room and not counted as new, next to a new REL.
		b.Reset(time.Unix(1700000001, 0))
		b.SetDatagram(1152, wire.RelWindow-2)
		if !b.addRelRetx(pays[0]) || !b.AddRst(h1, &wire.Rst{Code: wire.RstLinger}) {
			t.Fatal("building round 2")
		}
		if b.relCount() != 1 || b.RelRoom() != wire.RelWindow-3 {
			t.Fatalf("round 2: relCount %d, room %d", b.relCount(), b.RelRoom())
		}
		if f := b.Frame(0); !f.Rel || f.Header.Type != wire.TypeFin || f.Header.Handle != h1 {
			t.Fatalf("retransmission view %+v", f.Header)
		}
		stampRels(b, 43)
		b.seal(500)
		raw2 := b.appendTo(nil)
		second := decodeAll(t, raw2)
		if second[0].Type != wire.TypeRel || second[0].Fseq != 500 || !bytes.Equal(second[0].Payload, first[0].Payload) {
			t.Fatalf("retransmission: %+v, payload equal %v", second[0].Header, bytes.Equal(second[0].Payload, first[0].Payload))
		}
		// Byte for byte: the same REL payload inside a new header (fseq)
		// and a new trailer (CRC), so the receiver's fseq window accepts it.
		end := wire.HeaderLen + len(pays[0])
		if !bytes.Equal(raw2[wire.HeaderLen:end], raw1[wire.HeaderLen:end]) || bytes.Equal(raw2[:wire.HeaderLen], raw1[:wire.HeaderLen]) ||
			bytes.Equal(raw2[end:end+wire.TrailerLen], raw1[end:end+wire.TrailerLen]) {
			t.Fatalf("retransmitted frame %x, original %x", raw2[:end+wire.TrailerLen], raw1[:end+wire.TrailerLen])
		}
		if h, _, err := wire.ParseRel(second[1].Payload); err != nil || h.Cseq != 43 || h.Type != wire.TypeRst {
			t.Fatalf("round 2 new REL: %+v %v", h, err)
		}
		// The retransmitted copy changes nothing in the slot it came from.
		if binary.BigEndian.Uint32(pays[0]) != 41 {
			t.Fatal("the REL payload changed")
		}
		mustPanic(t, "REL payload too short", func() { dgBatch(1152, 8).addRelRetx(make([]byte, wire.RelHeadLen-1)) })
		mustPanic(t, "REL payload too long", func() { dgBatch(1152, 8).addRelRetx(make([]byte, wire.RelMaxPayload+1)) })
		full := dgBatch(1152, 8)
		for range MaxBatchFrames {
			full.addPing(false, &wire.Ping{})
		}
		if full.addRelRetx(pays[0]) || full.addRack(&wire.Rack{}) {
			t.Fatal("a REL retransmission or RACK was added to a full batch")
		}
	})

	t.Run("dgram", func(t *testing.T) {
		p, bud := NewBufPool(), NewBudget(1<<30)
		ca, cb := filledChunk(p, bud, 7), filledChunk(p, bud, 8)
		defer ca.Release()
		defer cb.Release()
		b := dgBatch(1152, wire.RelWindow)
		room := 1152 - wire.DgramOverhead
		// One reference per (batch, chunk): three datagrams of chunk A,
		// one of B, A again, an empty datagram and one without a chunk.
		adds := []struct {
			seq  uint64
			body []byte
			ref  *Buf
		}{
			{1, ca.B[0:1000], ca}, {2, ca.B[1000:1100], ca}, {3, ca.B[1100 : 1100+room], ca},
			{4, cb.B[0:10], cb}, {5, ca.B[5000:5001], ca}, {6, ca.B[6000:6000], ca}, {7, []byte("x"), nil},
		}
		for _, a := range adds {
			if !b.AddDgram(h1, a.seq, a.body, a.ref) {
				t.Fatalf("DGRAM %d refused", a.seq)
			}
		}
		if ca.refs.Load() != 2 || cb.refs.Load() != 2 {
			t.Fatalf("chunk references: A %d, B %d; want 2 each (the test's and the batch's)", ca.refs.Load(), cb.refs.Load())
		}
		total := 0
		for i, a := range adds {
			f := b.Frame(i)
			total += len(a.body)
			if f.Header.Type != wire.TypeDgram || f.Header.Handle != h1 || int(f.Header.Len) != wire.DgramPrefixLen+len(a.body) ||
				f.Seq != a.seq || f.Chunk != a.ref || f.Rel || len(f.Body) != len(a.body) {
				t.Errorf("DGRAM %d view: %+v seq %d chunk %p", i, f.Header, f.Seq, f.Chunk)
			}
			if len(a.body) > 0 && &f.Body[0] != &a.body[0] {
				t.Errorf("DGRAM %d body copied instead of referenced", i)
			}
		}
		// Nothing is DATA on a datagram batch (no submitted bytes, M2-D26);
		// the DGRAM bytes are counted apart.
		if b.dataBytes() != 0 || b.Room() != defaultBatchBudget || b.dgramBytes() != total {
			t.Fatalf("datagram batch: data %d room %d dgram bytes %d (want 0, %d, %d)", b.dataBytes(), b.Room(), b.dgramBytes(), defaultBatchBudget, total)
		}
		// DgramRoom is the carrier's budget, never the batch's fill: a
		// full batch keeps reporting it and AddDgram refuses instead.
		if b.AddDgram(h1, 8, ca.B[:room+1], ca) || b.Len() != len(adds) {
			t.Fatal("a datagram above DgramRoom was added")
		}
		for b.Len() < MaxBatchFrames {
			b.addPing(false, &wire.Ping{})
		}
		if b.DgramRoom() != room || b.AddDgram(h1, 8, ca.B[:1], ca) || b.AddDgram(h1, 8, nil, nil) {
			t.Fatalf("full batch: DGRAM room %d, a DGRAM was added", b.DgramRoom())
		}
		if n, ok := b.datagramDgram(3); !ok || n != room {
			t.Fatalf("datagramDgram(3) = %d %v", n, ok)
		}
		if _, ok := b.datagramDgram(len(adds) + 1); ok {
			t.Fatal("datagramDgram reported a DGRAM for a PING")
		}
		b.ReleaseRefs()
		if ca.refs.Load() != 1 || cb.refs.Load() != 1 {
			t.Fatalf("after ReleaseRefs: A %d, B %d", ca.refs.Load(), cb.refs.Load())
		}
		if f := b.Frame(0); f.Body != nil || f.Chunk != nil {
			t.Fatal("Frame still exposes a released DGRAM body")
		}
		if n, ok := b.datagramDgram(1); !ok || n != 1000 {
			t.Fatalf("datagramDgram after ReleaseRefs = %d %v", n, ok)
		}
		b.ReleaseRefs() // idempotent
		b.Reset(time.Time{})
		if ca.refs.Load() != 1 || cb.refs.Load() != 1 || bud.Used() != 2*int64(classSize(2)) {
			t.Fatalf("after Reset: A %d, B %d, charged %d", ca.refs.Load(), cb.refs.Load(), bud.Used())
		}
		// Reset releases what ReleaseRefs did not; a chunk the session
		// released while the write was in flight stays alive until then.
		d := p.Get(ChunkSize, bud)
		b.SetDatagram(1152, 8)
		b.AddDgram(h1, 1, d.B[:10], d)
		b.AddDgram(h1, 2, d.B[10:20], d)
		d.Release()
		if d.refs.Load() != 1 {
			t.Fatalf("in-flight chunk refs %d", d.refs.Load())
		}
		b.Reset(time.Time{})
		if d.refs.Load() != 0 || bud.Used() != 2*int64(classSize(2)) {
			t.Fatalf("Reset left the in-flight chunk referenced: refs %d", d.refs.Load())
		}

		// A stream batch: DGRAM bytes are DATA (Room, dataBytes; M2-D26)
		// and DgramRoom is min(Room, MaxPacketPayload).
		s := NewBatch(3000)
		s.Reset(time.Time{})
		if s.DgramRoom() != 3000 || !s.AddDgram(h1, 1, ca.B[:2000], ca) || s.Room() != 1000 || s.dataBytes() != 2000 || s.dgramBytes() != 2000 {
			t.Fatalf("stream batch: room %d data %d", s.Room(), s.dataBytes())
		}
		if s.DgramRoom() != 1000 || s.AddDgram(h1, 2, ca.B[:1001], ca) || !s.AddDgram(h1, 2, ca.B[:1000], ca) || s.Room() != 0 || ca.refs.Load() != 2 {
			t.Fatalf("stream batch at its budget: room %d, chunk refs %d", s.Room(), ca.refs.Load())
		}
		if !s.AddDgram(h1, 3, nil, nil) || s.Frame(2).Header.Len != wire.DgramPrefixLen {
			t.Fatal("an empty datagram was refused by a stream batch whose DATA budget is used")
		}
		big := NewBatch(1 << 20)
		big.Reset(time.Time{})
		if big.DgramRoom() != wire.MaxPacketPayload {
			t.Fatalf("1 MiB stream batch: DGRAM room %d", big.DgramRoom())
		}
		s.Reset(time.Time{})
		mustPanic(t, "DGRAM with handle 0", func() { dgBatch(1152, 8).AddDgram(0, 1, nil, nil) })
		mustPanic(t, "DGRAM beyond MaxPacketPayload", func() {
			NewBatch(1<<20).AddDgram(h1, 1, make([]byte, wire.MaxPacketPayload+1), nil)
		})
	})

	t.Run("packing", func(t *testing.T) {
		const budget = 1152
		p, bud := NewBufPool(), NewBudget(1<<30)
		c := filledChunk(p, bud, 9)
		defer c.Release()
		b := dgBatch(budget, wire.RelWindow)
		sched := wire.Sched{Epoch: 4, N: 1, IDs: [wire.MaxSchedIDs]uint32{5}}
		room := b.DgramRoom()
		ok := b.addRack(&wire.Rack{CumAck: 9}) && // 0: RACK 25
			b.addPong(&wire.Ping{ID: 3}) && // 1: PONG 37
			b.addPing(false, &wire.Ping{ID: 4}) && // 2: PING 37
			b.AddFin(h1, 600) && // 3: REL{FIN} 35
			b.AddSched(h1, wire.SchedQuality, &sched) && // 4: REL{SCHED} 60
			b.AddPack(h1, 0, &wire.Pack{HighestSeq: 3, Received: 3}, false) && // 5: PACK 37
			b.AddDgram(h1, 100, c.B[0:500], c) && // 6: DGRAM 525
			b.AddDgram(h1, 101, c.B[500:500+room], c) && // 7: DGRAM 1152, the whole budget
			b.AddDgram(h1, 102, nil, nil) && // 8: an empty DGRAM 25
			b.AddDgram(h1, 103, c.B[3000:3100], c) && // 9: DGRAM 125
			b.addPing(false, &wire.Ping{ID: 5, Pad: budget - wire.FrameOverhead - wire.PingFixedLen}) && // 10: MTU probe 1152
			b.addRack(&wire.Rack{CumAck: 10}) && // 11: RACK 25
			b.AddPack(h1, 0, &wire.Pack{HighestSeq: 5, Received: 5}, false) && // 12: PACK 37
			b.AddDgram(h1, 104, c.B[2000:2000+room], c) && // 13: DGRAM 1152
			b.addPong(&wire.Ping{ID: 6, Pad: 100}) && // 14: padded PONG 137
			b.addPing(false, &wire.Ping{ID: 7}) && // 15: PING 37
			b.addPong(&wire.Ping{ID: 8, Pad: 50}) && // 16: padded PONG 87
			b.addRack(&wire.Rack{CumAck: 11}) && // 17: RACK 25
			b.addClose(wire.CloseRetire) // 18: REL{CLOSE} 28
		if !ok || b.Len() != 19 {
			t.Fatalf("building the batch: ok %v len %d", ok, b.Len())
		}
		stampRels(b, 1)
		b.seal(1000)
		want := []struct{ i, end, n int }{
			{0, 7, 25 + 37 + 37 + 35 + 60 + 37 + 525}, // control frames ride in front of the DGRAM
			{7, 8, budget},    // a DGRAM ends its datagram; this one fills the budget exactly
			{8, 9, 25},        // an empty DGRAM is a datagram of its own: the next DGRAM would fit, but
			{9, 10, 125},      // two DGRAMs never share a datagram (a lost datagram stays one lost datagram)
			{10, 11, budget},  // the MTU probe travels alone
			{11, 13, 25 + 37}, // RACK and PACK do not fit in front of a full-budget DGRAM
			{13, 14, budget},
			{14, 15, 137}, // a padded PONG alone
			{15, 16, 37},  // a PING before a padded PONG stays apart from it
			{16, 17, 87},
			{17, 19, 25 + 28}, // the batch's tail: no DGRAM
		}
		const headroom = wire.FlowHeaderLen // a raw-UDP flow carrier builds after its flow header
		got := packDatagrams(b, budget, headroom)
		if len(got) != len(want) {
			t.Fatalf("%d datagrams, want %d", len(got), len(want))
		}
		var joined []byte
		for k, d := range got {
			if d.i != want[k].i || d.end != want[k].end || d.n != want[k].n || len(d.bytes) != d.n {
				t.Errorf("datagram %d: frames [%d, %d) %d bytes (%d written), want [%d, %d) %d", k, d.i, d.end, d.n, len(d.bytes), want[k].i, want[k].end, want[k].n)
			}
			fs := decodeAll(t, d.bytes)
			if len(fs) != d.end-d.i {
				t.Fatalf("datagram %d decodes into %d frames, want %d", k, len(fs), d.end-d.i)
			}
			for j, f := range fs {
				if f.Fseq != 1000+uint32(d.i+j) || (f.Type == wire.TypeDgram) != (j == len(fs)-1 && b.frames[d.end-1].hdr.Type == wire.TypeDgram) {
					t.Errorf("datagram %d frame %d: %v fseq %d", k, j, f.Type, f.Fseq)
				}
			}
			joined = append(joined, d.bytes...)
		}
		if !bytes.Equal(joined, b.appendTo(nil)) {
			t.Fatal("the datagrams are not the batch's frames in insertion order")
		}
		// appendDatagram keeps the headroom in front, appends exactly n
		// bytes into the reused scratch and copies the DGRAM body there:
		// the datagram stays intact when the chunk changes afterwards (the
		// chunk may be recycled once the batch releases it).
		flow := bytes.Repeat([]byte{0xab}, headroom)
		scratch := append(make([]byte, 0, headroom+budget), flow...)
		out := b.appendDatagram(scratch, 0, 7)
		if len(out) != headroom+want[0].n || !bytes.Equal(out[:headroom], flow) || &out[0] != &scratch[0] {
			t.Fatalf("appendDatagram: %d bytes, headroom kept %v, scratch reused %v", len(out), bytes.Equal(out[:headroom], flow), &out[0] == &scratch[0])
		}
		c.B[0] ^= 0xff
		if fs := decodeAll(t, out[headroom:]); fs[6].Type != wire.TypeDgram {
			t.Fatal("datagram 0 does not end with its DGRAM")
		} else if seq, body, err := wire.ParseDgram(fs[6].Payload); err != nil || seq != 100 || len(body) != 500 || body[0] != 9 {
			t.Fatalf("DGRAM 100 after the chunk changed: seq %d, %d bytes, err %v", seq, len(body), err)
		}
		c.B[0] ^= 0xff
		// After a budget shrink a frame above the budget forms a datagram
		// of its own (the transport refuses it); i < end always.
		if end, n := b.nextDatagram(7, 600); end != 8 || n != budget {
			t.Fatalf("oversize DGRAM after a shrink: [7, %d) %d bytes", end, n)
		}
		if end, n := b.nextDatagram(0, 600); end != 6 || n != 25+37+37+35+60+37 {
			t.Fatalf("budget 600: [0, %d) %d bytes", end, n)
		}
		if end, n := b.nextDatagram(0, 20); end != 1 || n != 25 {
			t.Fatalf("budget 20: [0, %d) %d bytes", end, n)
		}
		if end, n := b.nextDatagram(18, budget); end != 19 || n != 28 {
			t.Fatalf("last frame: [18, %d) %d bytes", end, n)
		}
		mustPanic(t, "nextDatagram(-1)", func() { b.nextDatagram(-1, budget) })
		mustPanic(t, "nextDatagram(Len)", func() { b.nextDatagram(b.Len(), budget) })
		mustPanic(t, "appendDatagram empty range", func() { b.appendDatagram(nil, 3, 3) })
		mustPanic(t, "appendDatagram beyond Len", func() { b.appendDatagram(nil, 0, b.Len()+1) })
		b.ReleaseRefs()
	})

	t.Run("packing model", func(t *testing.T) {
		// Random datagram batches against the packing rules of M2-D12,
		// checked on every datagram: whole frames in insertion order that
		// partition the batch; at most one DGRAM, as the last frame; a
		// padded PING or PONG alone; within the budget unless a single
		// frame; and greedy — the next datagram's first frame could not
		// have joined the previous datagram.
		p, bud := NewBufPool(), NewBudget(1<<30)
		c := filledChunk(p, bud, 10)
		defer c.Release()
		rng := rand.New(rand.NewPCG(41, 12))
		var stored [][]byte
		// Stimulus: every rule must have decided some datagram boundary.
		var seen struct{ ride, alone, oversize, budgetSplit, dgramSplit, retx, refused int }
		for trial := range 400 {
			budget := wire.ControlFloor + rng.IntN(2000)
			b := dgBatch(budget, rng.IntN(wire.RelWindow+1))
			for b.Len() < MaxBatchFrames && rng.IntN(70) != 0 {
				switch rng.IntN(12) {
				case 0:
					b.addRack(&wire.Rack{CumAck: rng.Uint32(), Sack: rng.Uint32N(1 << (wire.RelWindow - 1))})
				case 1:
					b.addPing(rng.IntN(2) == 0, &wire.Ping{ID: rng.Uint32()})
				case 2:
					b.addPong(&wire.Ping{ID: rng.Uint32()})
				case 3:
					b.addPing(false, &wire.Ping{ID: rng.Uint32(), Pad: max(1, budget-wire.FrameOverhead-wire.PingFixedLen)})
				case 4:
					b.addPong(&wire.Ping{ID: rng.Uint32(), Pad: 1 + rng.IntN(400)})
				case 5:
					b.AddFin(h1, rng.Uint64())
				case 6:
					s := wire.Sched{Epoch: rng.Uint32(), N: 1 + rng.IntN(wire.MaxSchedIDs)}
					b.AddSched(h1, wire.SchedDeath, &s)
				case 7:
					b.AddPack(h1, 0, &wire.Pack{}, false)
				case 8:
					b.AddPack(h1, uint8(rng.IntN(4)), &wire.Pack{HighestSeq: 1, Received: 1}, true)
				case 9, 10:
					n := rng.IntN(b.DgramRoom() + 1)
					off := rng.IntN(ChunkSize - n + 1)
					b.AddDgram(h1, rng.Uint64(), c.B[off:off+n], c)
				case 11:
					if len(stored) > 0 && b.addRelRetx(stored[rng.IntN(len(stored))]) {
						seen.retx++
					} else {
						b.addClose(wire.CloseRetire)
					}
				}
			}
			if b.relRefused() {
				seen.refused++
			}
			if b.Len() == 0 {
				continue
			}
			if rels := stampRels(b, rng.Uint32()); len(rels) > 0 {
				stored = rels
			}
			b.seal(rng.Uint32())
			pack := budget
			if rng.IntN(4) == 0 {
				pack = wire.ControlFloor + rng.IntN(budget-wire.ControlFloor+1) // a shrink after Fill
			}
			ds := packDatagrams(b, pack, rng.IntN(2)*wire.FlowHeaderLen)
			var joined []byte
			next := 0
			for k, d := range ds {
				if d.i != next || d.end <= d.i {
					t.Fatalf("trial %d datagram %d: frames [%d, %d) after %d", trial, k, d.i, d.end, next)
				}
				next = d.end
				sum := 0
				for j := d.i; j < d.end; j++ {
					sum += frameSize(b, j)
					if b.frames[j].hdr.Type == wire.TypeDgram && j != d.end-1 {
						t.Fatalf("trial %d datagram %d: a DGRAM at %d is not its last frame (end %d)", trial, k, j, d.end)
					}
					if b.frames[j].alone() && d.end-d.i != 1 {
						t.Fatalf("trial %d datagram %d: padded %v shares a datagram [%d, %d)", trial, k, b.frames[j].hdr.Type, d.i, d.end)
					}
				}
				if sum != d.n || len(d.bytes) != d.n || (d.end-d.i > 1 && d.n > pack) {
					t.Fatalf("trial %d datagram %d: %d bytes (sum %d, written %d), budget %d, %d frames", trial, k, d.n, sum, len(d.bytes), pack, d.end-d.i)
				}
				if k > 0 {
					prev, first := &b.frames[d.i-1], &b.frames[d.i]
					fits := ds[k-1].n+frameSize(b, d.i) <= pack
					switch {
					case prev.hdr.Type != wire.TypeDgram && !prev.alone() && !first.alone():
						if fits {
							t.Fatalf("trial %d datagram %d: frame %d (%d bytes) fits the previous datagram of %d bytes (budget %d)", trial, k, d.i, frameSize(b, d.i), ds[k-1].n, pack)
						}
						seen.budgetSplit++
					case prev.hdr.Type == wire.TypeDgram && fits && !first.alone():
						seen.dgramSplit++ // it would have fitted: the DGRAM ended the datagram
					}
				}
				switch last := &b.frames[d.end-1]; {
				case last.hdr.Type == wire.TypeDgram && d.end-d.i > 1:
					seen.ride++
				case last.alone():
					seen.alone++
				}
				if d.end-d.i == 1 && d.n > pack {
					seen.oversize++
				}
				if fs := decodeAll(t, d.bytes); len(fs) != d.end-d.i {
					t.Fatalf("trial %d datagram %d: %d frames decoded, want %d", trial, k, len(fs), d.end-d.i)
				}
				joined = append(joined, d.bytes...)
			}
			if next != b.Len() || !bytes.Equal(joined, b.appendTo(nil)) {
				t.Fatalf("trial %d: the datagrams cover %d of %d frames or reorder them", trial, next, b.Len())
			}
			b.ReleaseRefs()
		}
		if c.refs.Load() != 1 {
			t.Fatalf("chunk refs %d after the trials", c.refs.Load())
		}
		t.Logf("stimulus: %+v", seen)
		if seen.ride < 50 || seen.alone < 50 || seen.oversize < 10 || seen.budgetSplit < 50 || seen.dgramSplit < 50 || seen.retx < 50 || seen.refused < 10 {
			t.Fatalf("the trials did not exercise every packing rule: %+v", seen)
		}
	})

	t.Run("stream batch", func(t *testing.T) {
		// A packet session on a stream carrier: DGRAM and PACK are
		// ordinary frames of the M1 write shapes — the vectored form
		// references the DGRAM bodies, the coalesced form copies them, both
		// byte-identical — and the stream decodes into exactly them.
		p, bud := NewBufPool(), NewBudget(1<<30)
		c := filledChunk(p, bud, 11)
		defer c.Release()
		b := NewBatch(0)
		b.Reset(time.Unix(7, 0))
		pk := wire.Pack{HighestSeq: 41, Received: 40, EpochEcho: 2}
		ok := b.addPing(false, &wire.Ping{ID: 1}) &&
			b.AddPack(h1, wire.FlagPackFinDelivered, &pk, true) &&
			b.AddDgram(h1, 1<<62-1, c.B[:BigData], c) &&
			b.AddDgram(h1, 7, nil, nil) &&
			b.AddDgram(h1, 8, c.B[BigData:BigData+3], c) &&
			b.AddFin(h1, 9)
		if !ok || b.Len() != 6 || b.dataBytes() != BigData+3 || c.refs.Load() != 2 {
			t.Fatalf("building: ok %v len %d data %d chunk refs %d", ok, b.Len(), b.dataBytes(), c.refs.Load())
		}
		b.seal(5)
		stream := b.appendTo(make([]byte, 0, b.wireLen()))
		bufs := b.appendBuffers(make(net.Buffers, 0, 2*MaxBatchFrames+1))
		if !bytes.Equal(bytes.Join(bufs, nil), stream) || len(stream) != b.wireLen() {
			t.Fatal("vectored and coalesced forms differ")
		}
		if len(bufs) != 5 || &bufs[1][0] != &c.B[0] || &bufs[3][0] != &c.B[BigData] {
			t.Fatalf("%d iovecs; the DGRAM bodies are not referenced", len(bufs))
		}
		fs := decodeAll(t, stream)
		types := []wire.Type{wire.TypePing, wire.TypePack, wire.TypeDgram, wire.TypeDgram, wire.TypeDgram, wire.TypeFin}
		for i, f := range fs {
			if f.Type != types[i] || f.Fseq != 5+uint32(i) {
				t.Fatalf("frame %d: %v fseq %d", i, f.Type, f.Fseq)
			}
		}
		if k, err := wire.ParsePack(fs[1].Payload); err != nil || k != pk || fs[1].Flags != wire.FlagPackFinDelivered {
			t.Fatalf("PACK %+v %v flags %#x", k, err, fs[1].Flags)
		}
		for i, w := range []struct {
			seq  uint64
			body []byte
		}{{1<<62 - 1, c.B[:BigData]}, {7, nil}, {8, c.B[BigData : BigData+3]}} {
			if seq, body, err := wire.ParseDgram(fs[2+i].Payload); err != nil || seq != w.seq || !bytes.Equal(body, w.body) {
				t.Fatalf("DGRAM %d: seq %d, %d bytes, %v", i, seq, len(body), err)
			}
		}
		b.ReleaseRefs()
		if c.refs.Load() != 1 {
			t.Fatalf("chunk refs %d after ReleaseRefs", c.refs.Load())
		}
	})
}

// TestBatchDgramZeroAllocs_L41 (M2 design §A8.5, L41): a whole datagram
// writer round — Reset, SetDatagram, carrier control (RACK, PONG, a REL
// retransmission, PING), Fill's reliable PACK, REL{FIN}, REL{SCHED}, 40
// DGRAMs of one chunk and a bare PACK, REL{CLOSE}, relPayload for each new
// REL, seal, packing every datagram into the reused scratch after the
// raw-UDP flow header, ReleaseRefs — allocates nothing, and the control
// frames ride in front of the first DGRAM. The chunk stays referenced by
// the test, so no pool traffic is involved and the count is exact under
// -race too.
func TestBatchDgramZeroAllocs_L41(t *testing.T) {
	p, bud := NewBufPool(), NewBudget(1<<30)
	c := filledChunk(p, bud, 12)
	defer c.Release()
	const budget = 1232 - wire.FlowHeaderLen // carrier/udp's default MaxDatagram 1232: MTU 1223
	b := NewBatch(0)
	scratch := make([]byte, 0, wire.FlowHeaderLen+budget) // the writer's scratch: budget + Headroom
	retx := make([]byte, wire.RelHeadLen+wire.FinLen)     // a stored REL payload (its send slot)
	wire.PutRelHead(retx, &wire.RelHead{Cseq: 1, Type: wire.TypeFin, Handle: h1})
	wire.PutFin(retx[wire.RelHeadLen:], 9)
	ping := wire.Ping{ID: 1, TS: 2, Nonce: 3}
	sched := wire.Sched{Epoch: 1, N: 2, IDs: [wire.MaxSchedIDs]uint32{1, 2}}
	pack := wire.Pack{HighestSeq: 10, Received: 10, EpochEcho: 1}
	rack := wire.Rack{CumAck: 1}
	now := time.Unix(9, 0)
	fseq, cseq := uint32(1), uint32(2)
	var datagrams, first int
	round := func() {
		b.Reset(now)
		b.SetDatagram(budget, wire.RelWindow-1)
		b.addRack(&rack)
		b.addPong(&ping)
		b.addRelRetx(retx)
		b.addPing(false, &ping)
		b.AddPack(h1, 0, &pack, true)
		b.AddFin(h1, 50)
		b.AddSched(h1, wire.SchedQuality, &sched)
		for i := range 40 {
			b.AddDgram(h1, uint64(i), c.B[i*900:(i+1)*900], c)
		}
		b.AddPack(h1, 0, &pack, false)
		b.addClose(wire.CloseRetire)
		for k := range b.relCount() {
			b.relPayload(k, cseq)
			cseq++
		}
		fseq = b.seal(fseq)
		for i := 0; i < b.Len(); datagrams++ {
			end, _ := b.nextDatagram(i, budget)
			if i == 0 {
				first = end
			}
			sinkBytes = b.appendDatagram(scratch[:wire.FlowHeaderLen], i, end)
			i = end
		}
		b.ReleaseRefs()
	}
	round()
	if b.Len() != 49 || b.relCount() != 4 || first != 8 || datagrams != 41 || c.refs.Load() != 1 {
		t.Fatalf("round: %d frames, %d new RELs, first datagram [0, %d), %d datagrams, chunk refs %d; want 49, 4, [0, 8), 41, 1",
			b.Len(), b.relCount(), first, datagrams, c.refs.Load())
	}
	if a := testing.AllocsPerRun(100, round); a != 0 {
		t.Fatalf("%v allocations per datagram batch round", a)
	}
	// 102 rounds: ours, AllocsPerRun's warm-up and its 100 measured runs.
	if fseq != 1+102*49 || cseq != 2+102*4 || datagrams != 102*41 || c.refs.Load() != 1 {
		t.Fatalf("after 102 rounds: fseq %d, cseq %d, %d datagrams, chunk refs %d", fseq, cseq, datagrams, c.refs.Load())
	}
}
