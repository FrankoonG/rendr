package carrier

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

const h1 = wire.SessionHandle

// filledChunk returns a 64 KiB-class chunk whose bytes follow a pattern.
func filledChunk(p *BufPool, bud *Budget, seed byte) *Buf {
	c := p.Get(ChunkSize, bud)
	for i := range c.B {
		c.B[i] = byte(i*13) + seed
	}
	return c
}

// TestBatchAppendInspect: every Add* appends one frame with the right
// header and an encoding the wire parsers accept, in insertion order, and
// Frame exposes it for Fill-level tests.
func TestBatchAppendInspect(t *testing.T) {
	p, bud := NewBufPool(), NewBudget(1<<30)
	chunk := filledChunk(p, bud, 1)
	defer chunk.Release()
	b := NewBatch(256 << 10)
	now := time.Unix(1700000000, 5)
	b.Reset(now)
	if !b.Now().Equal(now) || b.Len() != 0 || b.Room() != 256<<10 || b.Full() || !b.WakeTime().IsZero() || b.CapBlocked() {
		t.Fatalf("fresh round: now %v len %d room %d full %v", b.Now(), b.Len(), b.Room(), b.Full())
	}
	sched := wire.Sched{Epoch: 9, N: 2, IDs: [wire.MaxSchedIDs]uint32{3, 4}}
	ack := wire.Ack{Delivered: 1 << 33, Window: 8 << 20, EpochEcho: 9}
	adds := []bool{
		b.AddOpenAck(h1, &wire.OpenAck{Status: wire.StatusOK, Window: 8 << 20}),
		b.AddJoinAck(h1, &wire.JoinAck{Status: wire.StatusOK, RxNext: 77}),
		b.AddRst(h1, &wire.Rst{Code: wire.RstLinger, Msg: []byte("linger")}),
		b.AddSched(h1, wire.SchedQuality, &sched),
		b.AddAck(h1, wire.FlagAckFinDelivered|wire.FlagAckDone, &ack),
		b.AddData(h1, 4096, chunk.B[4096:8192], chunk, false),
		b.AddData(h1, 0, chunk.B[:100], chunk, true),
		b.AddFin(h1, 8192),
	}
	for i, ok := range adds {
		if !ok {
			t.Fatalf("add %d refused", i)
		}
	}
	if b.Len() != 8 || b.Room() != 256<<10-4096-100 || b.dataBytes() != 4196 || b.retxBytes() != 100 {
		t.Fatalf("len %d room %d data %d retx %d", b.Len(), b.Room(), b.dataBytes(), b.retxBytes())
	}
	type want struct {
		t     wire.Type
		flags uint8
		len   int
	}
	wants := []want{
		{wire.TypeOpenAck, 0, wire.OpenAckFixedLen},
		{wire.TypeJoinAck, 0, wire.JoinAckLen},
		{wire.TypeRst, 0, wire.RstFixedLen + 6},
		{wire.TypeSched, uint8(wire.SchedQuality), wire.SchedFixedLen + 8},
		{wire.TypeAck, wire.FlagAckFinDelivered | wire.FlagAckDone, wire.AckLen},
		{wire.TypeData, 0, wire.DataPrefixLen + 4096},
		{wire.TypeData, 0, wire.DataPrefixLen + 100},
		{wire.TypeFin, 0, wire.FinLen},
	}
	for i, w := range wants {
		f := b.Frame(i)
		if f.Header.Type != w.t || f.Header.Flags != w.flags || int(f.Header.Len) != w.len || f.Header.Handle != h1 || f.Header.Fseq != 0 {
			t.Errorf("frame %d header %+v, want %v flags %#x len %d", i, f.Header, w.t, w.flags, w.len)
		}
		if w.t != wire.TypeData && len(f.Payload) != w.len {
			t.Errorf("frame %d payload %d bytes, want %d", i, len(f.Payload), w.len)
		}
	}
	if a, err := wire.ParseOpenAck(b.Frame(0).Payload); err != nil || a.Status != wire.StatusOK || a.Window != 8<<20 {
		t.Errorf("OPEN_ACK %+v %v", a, err)
	}
	if a, err := wire.ParseJoinAck(b.Frame(1).Payload); err != nil || a.RxNext != 77 {
		t.Errorf("JOIN_ACK %+v %v", a, err)
	}
	if r, err := wire.ParseRst(b.Frame(2).Payload); err != nil || r.Code != wire.RstLinger || string(r.Msg) != "linger" {
		t.Errorf("RST %+v %v", r, err)
	}
	if s, err := wire.ParseSched(b.Frame(3).Payload); err != nil || s != sched {
		t.Errorf("SCHED %+v %v", s, err)
	}
	if a, err := wire.ParseAck(b.Frame(4).Payload); err != nil || a != ack {
		t.Errorf("ACK %+v %v", a, err)
	}
	if off, err := wire.ParseFin(b.Frame(7).Payload); err != nil || off != 8192 {
		t.Errorf("FIN %d %v", off, err)
	}
	d := b.Frame(5)
	if d.Off != 4096 || d.Chunk != chunk || d.Retx || len(d.Body) != 4096 || &d.Body[0] != &chunk.B[4096] {
		t.Errorf("DATA frame: off %d retx %v body aliases the chunk: %v", d.Off, d.Retx, len(d.Body) > 0 && &d.Body[0] == &chunk.B[4096])
	}
	if d := b.Frame(6); d.Off != 0 || !d.Retx || &d.Body[0] != &chunk.B[0] {
		t.Errorf("retransmitted DATA frame: %+v", d.Header)
	}
	mustPanic(t, "Frame(-1)", func() { b.Frame(-1) })
	mustPanic(t, "Frame(Len)", func() { b.Frame(b.Len()) })
	b.Reset(now)
	if b.Len() != 0 || b.Room() != 256<<10 || chunk.refs.Load() != 1 {
		t.Fatalf("after Reset: len %d room %d chunk refs %d", b.Len(), b.Room(), chunk.refs.Load())
	}
}

// TestBatchCanonicalAnswers (C32): the batch encodes OPEN_ACK and JOIN_ACK
// through the canonicalizing encoders, whatever the caller's struct holds.
func TestBatchCanonicalAnswers(t *testing.T) {
	b := NewBatch(0)
	b.Reset(time.Time{})
	b.AddOpenAck(h1, &wire.OpenAck{Status: wire.StatusOK, Window: 5, Code: 3, Msg: []byte("x")})
	b.AddOpenAck(h1, &wire.OpenAck{Status: wire.StatusCapacity, Window: 5, Code: wire.CodeCarriers, Msg: []byte("full")})
	b.AddJoinAck(h1, &wire.JoinAck{Status: wire.StatusUnknownSession, RxNext: 5})
	if f := b.Frame(0); f.Header.Len != wire.OpenAckFixedLen {
		t.Fatalf("OK OPEN_ACK len %d", f.Header.Len)
	} else if a, err := wire.ParseOpenAck(f.Payload); err != nil || a.Code != 0 || a.Msg != nil || a.Window != 5 {
		t.Fatalf("OK OPEN_ACK %+v %v", a, err)
	}
	if a, err := wire.ParseOpenAck(b.Frame(1).Payload); err != nil || a.Window != 0 || a.Code != wire.CodeCarriers || string(a.Msg) != "full" {
		t.Fatalf("CAPACITY OPEN_ACK %+v %v", a, err)
	}
	if a, err := wire.ParseJoinAck(b.Frame(2).Payload); err != nil || a.RxNext != 0 {
		t.Fatalf("UNKNOWN_SESSION JOIN_ACK %+v %v", a, err)
	}
}

// TestBatchDataBudget: Room counts DATA bodies only, a segment is never cut
// to fit (it fits or waits for the next batch), and the default budget
// holds exactly four full 64 KiB segments (design §5.6).
func TestBatchDataBudget(t *testing.T) {
	p, bud := NewBufPool(), NewBudget(1<<30)
	c := filledChunk(p, bud, 2)
	defer c.Release()
	b := NewBatch(0)
	b.Reset(time.Time{})
	if b.Room() != defaultBatchBudget {
		t.Fatalf("NewBatch(0) room %d", b.Room())
	}
	for i := range 4 {
		if !b.AddData(h1, uint64(i)*ChunkSize, c.B[:ChunkSize], c, false) {
			t.Fatalf("segment %d refused", i)
		}
	}
	refs := c.refs.Load()
	if b.AddData(h1, 4*ChunkSize, c.B[:ChunkSize], c, false) || b.AddData(h1, 4*ChunkSize, c.B[:1], c, false) {
		t.Fatal("a DATA body beyond Room was added")
	}
	if b.Len() != 4 || b.Room() != 0 || c.refs.Load() != refs {
		t.Fatalf("a refused AddData changed the batch: len %d room %d refs %d", b.Len(), b.Room(), c.refs.Load())
	}
	// Control frames do not count against Room.
	if !b.AddFin(h1, 4*ChunkSize) || b.Room() != 0 {
		t.Fatal("FIN refused in a batch whose DATA budget is used")
	}
	small := NewBatch(100)
	small.Reset(time.Time{})
	if small.AddData(h1, 0, c.B[:101], c, false) || !small.AddData(h1, 0, c.B[:100], c, false) || small.Room() != 0 {
		t.Fatalf("budget 100: room %d", small.Room())
	}
	small.Reset(time.Time{})
	b.Reset(time.Time{})
	mustPanic(t, "empty DATA", func() { b.AddData(h1, 0, nil, nil, false) })
	mustPanic(t, "handle 0", func() { b.AddData(0, 0, c.B[:1], nil, false) })
	mustPanic(t, "oversize DATA", func() {
		NewBatch(4<<20).AddData(h1, 0, make([]byte, wire.MaxFramePayload), nil, false)
	})
	if c.refs.Load() != 1 {
		t.Fatalf("chunk refs %d after the batches were reset", c.refs.Load())
	}
}

// TestBatchFrameAndArenaLimits: at most MaxBatchFrames frames and
// ControlArena control-payload bytes per batch; Full reports when no frame
// of any kind fits.
func TestBatchFrameAndArenaLimits(t *testing.T) {
	b := NewBatch(1 << 20)
	b.Reset(time.Time{})
	ack := wire.Ack{Delivered: 1}
	for i := range MaxBatchFrames {
		if b.Full() || !b.AddAck(h1, 0, &ack) {
			t.Fatalf("ACK %d refused", i)
		}
	}
	if !b.Full() || b.AddAck(h1, 0, &ack) || b.AddData(h1, 0, []byte{1}, nil, false) || b.addPing(false, &wire.Ping{}) || b.addClose(wire.CloseRetire) {
		t.Fatal("a frame beyond MaxBatchFrames was added")
	}
	if b.Len() != MaxBatchFrames {
		t.Fatalf("len %d", b.Len())
	}

	// Control arena: 31 RSTs with 255-byte messages and one with 127 bytes
	// fill the 8 KiB exactly; then no control frame fits, DATA still does.
	b.Reset(time.Time{})
	msg := bytes.Repeat([]byte{'m'}, wire.MaxMsg)
	for i := range 31 {
		if !b.AddRst(h1, &wire.Rst{Code: 1, Msg: msg}) {
			t.Fatalf("RST %d refused", i)
		}
	}
	if !b.AddRst(h1, &wire.Rst{Code: 1, Msg: msg[:ControlArena-31*(wire.RstFixedLen+wire.MaxMsg)-wire.RstFixedLen]}) {
		t.Fatal("the RST that fills the arena exactly was refused")
	}
	if b.ctl != ControlArena {
		t.Fatalf("control arena %d, want %d", b.ctl, ControlArena)
	}
	if b.AddFin(h1, 1) || b.addGoAway(wire.GoAwayShutdown) || b.addPong(&wire.Ping{}) {
		t.Fatal("a control frame beyond ControlArena was added")
	}
	if b.Full() {
		t.Fatal("Full with DATA room left")
	}
	big := make([]byte, wire.MaxFramePayload-wire.DataPrefixLen) // the largest DATA body
	if !b.AddData(h1, 0, big, nil, false) || b.Full() || !b.AddData(h1, 1, big[:wire.DataPrefixLen], nil, false) || !b.Full() {
		t.Fatalf("after the DATA budget was used: room %d full %v", b.Room(), b.Full())
	}
	if b.wireLen() != b.used+b.bodies || b.used > arenaSize {
		t.Fatalf("arena %d of %d", b.used, arenaSize)
	}

	mustPanic(t, "ACK flags", func() { b.AddAck(h1, 0x04, &ack) })
	mustPanic(t, "SCHED cause", func() { b.AddSched(h1, 4, &wire.Sched{N: 1}) })
	mustPanic(t, "SCHED n", func() { b.AddSched(h1, 0, &wire.Sched{N: 0}) })
	mustPanic(t, "RST msg", func() { b.AddRst(h1, &wire.Rst{Msg: make([]byte, wire.MaxMsg+1)}) })
	mustPanic(t, "OPEN_ACK msg", func() {
		b.AddOpenAck(h1, &wire.OpenAck{Status: wire.StatusRejected, Msg: make([]byte, wire.MaxMsg+1)})
	})
	mustPanic(t, "session frame with handle 0", func() { NewBatch(0).AddFin(0, 1) })
}

// TestBatchRefsHoldChunk_L17_L43: a DATA frame holds its own reference on
// the chunk, so a chunk the session releases mid-write (an ACK freed it) is
// neither recycled nor uncharged until the writer's ReleaseRefs; a refused
// AddData takes no reference; ReleaseRefs is idempotent and Reset releases.
func TestBatchRefsHoldChunk_L17_L43(t *testing.T) {
	p, bud := NewBufPool(), NewBudget(1<<30)
	c := filledChunk(p, bud, 3)
	keep := bytes.Clone(c.B)
	b := NewBatch(ChunkSize)
	b.Reset(time.Time{})
	if !b.AddData(h1, 0, c.B[:10], c, false) || !b.AddData(h1, 10, c.B[10:20], c, true) || c.refs.Load() != 3 {
		t.Fatalf("refs %d after two DATA frames", c.refs.Load())
	}
	if b.AddData(h1, 20, c.B[:ChunkSize], c, false) || c.refs.Load() != 3 {
		t.Fatalf("a refused AddData took a reference: %d", c.refs.Load())
	}
	// The session drops its reference while the write is in flight.
	c.Release()
	if c.refs.Load() != 2 || bud.Used() != int64(classSize(2)) {
		t.Fatalf("chunk freed under the writer: refs %d used %d", c.refs.Load(), bud.Used())
	}
	// A new chunk of the same class cannot be this one.
	other := p.Get(ChunkSize, bud)
	if other == c {
		t.Fatal("a chunk still referenced by a batch was handed out again")
	}
	clear(other.B)
	if !bytes.Equal(c.B, keep) {
		t.Fatal("the in-flight chunk was overwritten")
	}
	other.Release()
	b.ReleaseRefs()
	if c.refs.Load() != 0 || bud.Used() != 0 {
		t.Fatalf("after ReleaseRefs: refs %d used %d", c.refs.Load(), bud.Used())
	}
	if f := b.Frame(0); f.Chunk != nil || f.Body != nil {
		t.Fatal("Frame still exposes a released chunk")
	}
	b.ReleaseRefs() // idempotent
	b.Reset(time.Time{})
	if bud.Used() != 0 {
		t.Fatalf("budget %d after a second ReleaseRefs and Reset", bud.Used())
	}

	// Reset releases what ReleaseRefs did not.
	d := p.Get(ChunkSize, bud)
	b.AddData(h1, 0, d.B[:1], d, false)
	d.Release()
	b.Reset(time.Time{})
	if bud.Used() != 0 {
		t.Fatalf("Reset left %d bytes charged", bud.Used())
	}
}

// TestBatchWakeAndCapBlocked: the earliest WakeAt of a round wins, a zero
// time is ignored, and Reset clears both requests.
func TestBatchWakeAndCapBlocked(t *testing.T) {
	b := NewBatch(0)
	t0 := time.Unix(100, 0)
	b.Reset(t0)
	b.WakeAt(t0.Add(30 * time.Millisecond))
	b.WakeAt(t0.Add(10 * time.Millisecond))
	b.WakeAt(t0.Add(20 * time.Millisecond))
	b.WakeAt(time.Time{})
	if !b.WakeTime().Equal(t0.Add(10 * time.Millisecond)) {
		t.Fatalf("WakeTime %v", b.WakeTime())
	}
	b.MarkCapBlocked()
	if !b.CapBlocked() {
		t.Fatal("CapBlocked not recorded")
	}
	b.Reset(t0.Add(time.Second))
	if !b.WakeTime().IsZero() || b.CapBlocked() || !b.Now().Equal(t0.Add(time.Second)) {
		t.Fatalf("after Reset: wake %v capBlocked %v now %v", b.WakeTime(), b.CapBlocked(), b.Now())
	}
}

// TestBatchSealRoundTrip_L41_L43: a sealed batch — carrier control, session
// control, DATA and FIN — goes on the wire as consecutive complete frames
// with consecutive (wrapping) fseq and valid CRC32C trailers; the vectored
// form and the coalesced form are byte-identical; the stream re-parses into
// exactly the appended frames; and a body changed after sealing fails the
// receiver's CRC instead of being accepted (L43).
func TestBatchSealRoundTrip_L41_L43(t *testing.T) {
	p, bud := NewBufPool(), NewBudget(1<<30)
	c1, c2 := filledChunk(p, bud, 4), filledChunk(p, bud, 5)
	defer c1.Release()
	defer c2.Release()
	b := NewBatch(0)
	b.Reset(time.Unix(5, 0))
	sched := wire.Sched{Epoch: 3, N: 1, IDs: [wire.MaxSchedIDs]uint32{42}}
	ok := b.addPong(&wire.Ping{ID: 7, TS: 1, Nonce: 2, Pad: 1000}) &&
		b.addPing(true, &wire.Ping{ID: 8, TS: 3, Nonce: 4}) &&
		b.addGoAway(wire.GoAwayShutdown) &&
		b.AddSched(h1, wire.SchedDeath, &sched) &&
		b.AddAck(h1, wire.FlagAckFinDelivered, &wire.Ack{Delivered: 10, Window: 20, EpochEcho: 3}) &&
		b.AddData(h1, 0, c1.B[:ChunkSize], c1, false) &&
		b.AddData(h1, ChunkSize, c2.B[:5000], c2, true) &&
		b.AddFin(h1, ChunkSize+5000) &&
		b.addClose(wire.CloseRetire)
	if !ok || b.Len() != 9 {
		t.Fatalf("building the batch: ok %v len %d", ok, b.Len())
	}
	const first uint32 = 0xfffffffe
	if next, want := b.seal(first), first+uint32(b.Len()); next != want || next != 7 {
		t.Fatalf("seal returned fseq %#x, want %#x (wrapped)", next, want)
	}
	stream := b.appendTo(make([]byte, 0, b.wireLen()))
	if len(stream) != b.wireLen() || cap(stream) != b.wireLen() {
		t.Fatalf("coalesced %d bytes (cap %d), wireLen %d", len(stream), cap(stream), b.wireLen())
	}
	bufs := b.appendBuffers(make(net.Buffers, 0, 2*MaxBatchFrames+1))
	if len(bufs) != 2*3+1 { // three bodies: the PONG pad and two DATA bodies
		t.Fatalf("%d iovecs, want 7", len(bufs))
	}
	if &bufs[3][0] != &c1.B[0] || &bufs[5][0] != &c2.B[0] {
		t.Fatal("the vectored form copies DATA bodies instead of referencing the chunks")
	}
	if !bytes.Equal(bytes.Join(bufs, nil), stream) {
		t.Fatal("vectored and coalesced forms differ")
	}
	rest := stream
	for i := 0; len(rest) > 0; i++ {
		fr, n, err := wire.DecodeFrame(rest)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		bf := b.Frame(i)
		if fr.Header != bf.Header || fr.Fseq != first+uint32(i) {
			t.Fatalf("frame %d header %+v, appended %+v", i, fr.Header, bf.Header)
		}
		var want []byte
		switch fr.Type {
		case wire.TypeData:
			want = make([]byte, wire.DataPrefixLen)
			wire.PutDataOffset(want, bf.Off)
			want = append(want, bf.Body...)
		default:
			want = append(append([]byte(nil), bf.Payload...), bf.Body...)
		}
		if !bytes.Equal(fr.Payload, want) {
			t.Fatalf("frame %d (%v) payload differs", i, fr.Type)
		}
		rest = rest[n:]
		if i == b.Len()-1 && len(rest) != 0 {
			t.Fatalf("%d bytes after the last frame", len(rest))
		}
	}
	if pong, err := wire.ParsePing(append(append([]byte(nil), b.Frame(0).Payload...), b.Frame(0).Body...)); err != nil || pong.Pad != 1000 || pong.ID != 7 {
		t.Fatalf("PONG %+v %v", pong, err)
	}
	if b.Frame(1).Header.Flags != wire.FlagPingBusy || b.Frame(0).Header.Flags != 0 {
		t.Fatal("PING BUSY / PONG flags")
	}

	// L43: an embedder or a chunk reuse that changes body bytes after the
	// CRC was computed is detected by the receiver.
	c2.B[100] ^= 0x01
	altered := b.appendTo(nil)
	at := 0
	for i := range 6 { // skip to the second DATA frame (index 6)
		_, n, err := wire.DecodeFrame(altered[at:])
		if err != nil {
			t.Fatalf("frame %d before the altered one: %v", i, err)
		}
		at += n
	}
	if _, _, err := wire.DecodeFrame(altered[at:]); !errors.Is(err, wire.ErrCRC) {
		t.Fatalf("altered DATA body: %v, want ErrCRC", err)
	}
	c2.B[100] ^= 0x01
	b.ReleaseRefs()
}

var (
	sinkBufs  net.Buffers
	sinkBytes []byte
)

// TestBatchRoundZeroAllocs_L41: a whole writer round — Reset, carrier and
// session control, four 64 KiB DATA frames, FIN, seal, both write shapes,
// ReleaseRefs — allocates nothing. The chunk stays referenced by the test,
// so no pool traffic is involved and the count is exact under -race too.
func TestBatchRoundZeroAllocs_L41(t *testing.T) {
	p, bud := NewBufPool(), NewBudget(1<<30)
	c := filledChunk(p, bud, 6)
	defer c.Release()
	b := NewBatch(0)
	bufs := make(net.Buffers, 0, 2*MaxBatchFrames+1)
	scratch := make([]byte, 0, 512<<10)
	ping := wire.Ping{ID: 1, TS: 2, Nonce: 3}
	sched := wire.Sched{Epoch: 1, N: 2, IDs: [wire.MaxSchedIDs]uint32{1, 2}}
	ack := wire.Ack{Delivered: 1, Window: 2}
	now := time.Unix(9, 0)
	fseq := uint32(1)
	round := func() {
		b.Reset(now)
		b.addPong(&ping)
		b.addPing(false, &ping)
		b.AddSched(h1, wire.SchedQuality, &sched)
		b.AddAck(h1, 0, &ack)
		for i := range 4 {
			b.AddData(h1, uint64(i)*ChunkSize, c.B[:ChunkSize], c, i%2 == 0)
		}
		b.AddFin(h1, 4*ChunkSize)
		b.WakeAt(now.Add(time.Millisecond))
		fseq = b.seal(fseq)
		sinkBufs = b.appendBuffers(bufs[:0])
		sinkBytes = b.appendTo(scratch[:0])
		b.ReleaseRefs()
	}
	round()
	if a := testing.AllocsPerRun(100, round); a != 0 {
		t.Fatalf("%v allocations per batch round", a)
	}
	if b.Len() != 9 || b.dataBytes() != 4*ChunkSize || c.refs.Load() != 1 {
		t.Fatalf("round: len %d data %d chunk refs %d", b.Len(), b.dataBytes(), c.refs.Load())
	}
	// 102 rounds: ours, AllocsPerRun's warm-up and its 100 measured runs.
	if want := 1 + 102*9; fseq != uint32(want) {
		t.Fatalf("fseq %d after 102 rounds of 9 frames, want %d", fseq, want)
	}
}
