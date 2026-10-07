package session

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Packet data-plane test harness (M2 design §A11.3 WP6a: "session harness
// with fake ports and datagram batches"). Sessions are built as Dial or
// NewPending would (initStreamLocked, then initPacketLocked), lanes ride
// fake ports that report a carrier kind, a DgramMax and a REL room, and
// the actor's few steps the data plane depends on (attach, death, routing,
// end, Close, termination) are done by hand under s.mu, calling the WP6a
// functions exactly where WP6b's actor code calls them. Fill, Datagram,
// Control and WriteBlocked are driven directly with real carrier Batches
// in datagram or stream mode, Bufs and wire codecs; no carrier goroutine
// runs unless a test emulates writers itself. Every package-level helper
// starts with "dp" (the stream's use "st", the actor's "ac").

// dpPort is a lane's carrier as the packet plane sees it: port plus the
// pktPort introspection.
type dpPort struct {
	id    uint32
	dgram bool
	wake  chan struct{} // cap 1
	b     *carrier.Batch

	mu        sync.Mutex
	wakes     int
	calls     int // Wake, Capacity, Inflight, WriteBlocked, RelRoom calls (L54)
	srtt      time.Duration
	inflight  int64
	capacity  int64
	blocked   bool
	closeSent bool
	budget    int // frame budget (datagram ports)
	relRoom   int // REL room of the carrier (Conn.RelRoom) and of its batches
}

func dpNewPort(id uint32, dgram bool) *dpPort {
	return &dpPort{id: id, dgram: dgram, wake: make(chan struct{}, 1), b: carrier.NewBatch(0),
		capacity: 1 << 40, budget: 1400, relRoom: wire.RelWindow}
}

func (f *dpPort) ID() uint32 { return f.id }

func (f *dpPort) Wake() {
	f.mu.Lock()
	f.wakes++
	f.calls++
	f.mu.Unlock()
	select {
	case f.wake <- struct{}{}:
	default:
	}
}

func (f *dpPort) RequestPing() {}

func (f *dpPort) Inflight() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.inflight
}

func (f *dpPort) Capacity() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.capacity
}

func (f *dpPort) SRTT() time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.srtt
}

func (f *dpPort) WriteBlocked() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.blocked
}

func (f *dpPort) CloseSent() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closeSent
}

func (f *dpPort) Kill(carrier.Cause, string) bool { return true }

func (f *dpPort) Kind() wire.CarrierKind {
	if f.dgram {
		return wire.KindDatagram
	}
	return wire.KindStream
}

func (f *dpPort) DgramMax() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.dgram {
		return wire.MaxPacketPayload
	}
	return f.budget - wire.DgramOverhead
}

func (f *dpPort) RelRoom() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if !f.dgram {
		return 0
	}
	return f.relRoom
}

func (f *dpPort) set(fn func(f *dpPort)) {
	f.mu.Lock()
	fn(f)
	f.mu.Unlock()
}

func (f *dpPort) wakeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.wakes
}

func (f *dpPort) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

var (
	_ port    = (*dpPort)(nil)
	_ pktPort = (*dpPort)(nil)
)

// dpOpt configures a test packet session; zero fields take the defaults
// of dpSession.
type dpOpt struct {
	role       Role
	mode       Mode
	queue      int
	maxAge     time.Duration
	packetPing time.Duration
	packEvery  int
	finWaitMax time.Duration
	dedupBits  int
	firstSeq   uint64
	limit      uint64
	maxPayload int
	idle       time.Duration
	linger     time.Duration
	pool       *carrier.BufPool
	budget     *carrier.Budget
	hooks      *testhooks.Hooks
}

// dpSession returns an open packet session initialized as Dial or
// NewPending would, with its MaxPayload fixed as the OPEN exchange would
// (default 1375: a 1400-byte frame budget).
func dpSession(o dpOpt) *Session {
	if o.role == 0 {
		o.role = RoleDialer
	}
	if o.mode == 0 {
		o.mode = ModeSelector
	}
	if o.pool == nil {
		o.pool = carrier.NewBufPool()
	}
	if o.budget == nil {
		o.budget = carrier.NewBudget(1 << 30)
	}
	if o.maxPayload == 0 {
		o.maxPayload = 1400 - wire.DgramOverhead
	}
	if o.limit == 0 {
		o.limit = 1 << 62
	}
	if o.linger == 0 {
		o.linger = 2 * time.Second
	}
	env := &Env{
		Carrier: &carrier.Env{
			Bufs:   o.pool,
			DBufs:  carrier.NewDatagramBufPool(),
			Budget: o.budget,
			Timing: carrier.Timing{PingBusy: 50 * time.Millisecond, BatchBudget: 256 << 10},
		},
		Hooks: o.hooks,
	}
	s := &Session{env: env, p: Params{
		Role: o.role, Mode: o.mode, Window: 1 << 20,
		OffsetLimit: o.limit, FirstEpoch: 1, Linger: o.linger, IdleTimeout: o.idle,
		Kind: wire.KindDatagram,
		Packet: PacketParams{
			MaxPayload: o.maxPayload, Queue: o.queue, MaxAge: o.maxAge, PacketPing: o.packetPing,
			PackEvery: o.packEvery, FinWaitMax: o.finWaitMax, DedupBits: o.dedupBits, FirstSeq: o.firstSeq,
		},
	}}
	s.mb.init()
	s.mu.Lock()
	s.initStreamLocked()
	s.initPacketLocked()
	s.pk.maxPayload = o.maxPayload // the dialer's OPEN_ACK fixed it (passive: already set)
	s.ctl.state = StateOpen
	s.mu.Unlock()
	return s
}

// dpAddLane adds a lane as the actor does on an attach (confirmed; the
// selector's active data lane or a bond member when data), registered with
// laneAddedLocked, then the packet routing summary (routingChangedLocked's
// packet branch).
func dpAddLane(s *Session, id uint32, data, dgram bool) (*lane, *dpPort) {
	fp := dpNewPort(id, dgram)
	l := &lane{s: s, port: fp, id: id, factory: -1, since: time.Now()}
	s.mu.Lock()
	defer s.mu.Unlock()
	l.state = LaneMember
	l.firstSent = s.p.Role == RolePassive
	l.schedSent = s.ctl.epoch
	l.echoRel = s.ctl.epoch
	if data {
		l.data = true
		if s.p.Mode != ModeBond {
			l.state = LaneActive
			s.ctl.active = l
		}
	}
	s.lanes = append(s.lanes, l)
	s.laneAddedLocked(l)
	s.pktRecomputeLocked()
	return l, fp
}

// dpRoute changes l's data eligibility as an actor routing change does.
func dpRoute(s *Session, l *lane, data bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l.data = data
	if s.p.Mode != ModeBond {
		if data {
			l.state = LaneActive
			s.ctl.active = l
		} else if s.ctl.active == l {
			s.ctl.active = nil
			l.state = LaneMember
		}
	}
	s.pktRecomputeLocked()
	s.pktWakeLocked(time.Now())
}

// dpKill is the actor's death step for l with WP6b's packet additions.
func dpKill(s *Session, l *lane) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l.state = LaneDead
	l.data = false
	if s.ctl.active == l {
		s.ctl.active = nil
	}
	s.laneGoneLocked(l)
	s.pktRecomputeLocked()
	s.pktWakeLocked(time.Now())
}

// dpClose is Session.Close with WP6b's packet branch.
func dpClose(s *Session) {
	s.mu.Lock()
	s.pktCloseLocked(time.Now())
	if c := s.closing; c != nil {
		s.closing = nil
		close(c)
	}
	s.mu.Unlock()
	s.ringActor()
}

// dpEnd is the actor's end with WP6b's packet branch of endLocked.
func dpEnd(s *Session, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.st.ended {
		s.endLocked(err)
		s.pktEndLocked()
	}
}

// dpTerm runs the actor's termination rules at now (terminationLocked,
// unchanged for packet sessions) on a session whose lanes are fakes: the
// lanes are hidden from the end procedure (no carrier to retire), the ring
// release of WP6b's endLocked branch follows. It returns the end error
// (nil: not ended) and the RST the end procedure placed.
func dpTerm(s *Session, now time.Time) (error, *wire.Rst) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.ended {
		return s.st.endErr, s.ctl.rst
	}
	a := &actor{s: s}
	lanes := s.lanes
	s.lanes = nil
	a.terminationLocked(now)
	s.lanes = lanes
	if !a.ending {
		return nil, nil
	}
	s.pktEndLocked()
	return a.endErr, s.ctl.rst
}

// dpLocked runs fn under s.mu.
func dpLocked[T any](s *Session, fn func(st *stream, pk *packet) T) T {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fn(&s.st, s.pk)
}

// dpCtr returns s's packet counters.
func dpCtr(s *Session) PacketCounters {
	return dpLocked(s, func(_ *stream, pk *packet) PacketCounters { return pk.ctr })
}

// dpFill runs one Fill of l (its port's batch, datagram mode on a datagram
// port) at now; the batch keeps its references until the caller releases
// them (ReleaseRefs) or the next dpFill of that port resets it.
func dpFill(l *lane, now time.Time) *carrier.Batch {
	fp := l.port.(*dpPort)
	b := fp.b
	b.Reset(now)
	if fp.dgram {
		fp.mu.Lock()
		budget, rel := fp.budget, fp.relRoom
		fp.mu.Unlock()
		b.SetDatagram(budget, rel)
	}
	(*plane)(l).Fill(nil, b)
	return b
}

// dpIdle runs l's Fill until it appends nothing (a writer that went
// idle), releasing each batch; the frames are discarded.
func dpIdle(l *lane) {
	for range 64 {
		b := dpFill(l, time.Now())
		n := b.Len()
		b.ReleaseRefs()
		if n == 0 {
			return
		}
	}
	panic("dpIdle: the lane never went idle")
}

// dpFrame is a recorded frame of a batch.
type dpFrame struct {
	typ   wire.Type
	flags uint8
	rel   bool
	seq   uint64 // DGRAM
	body  []byte // DGRAM (copy)
	fin   uint64 // FIN
	pack  wire.Pack
}

func (f dpFrame) String() string {
	switch f.typ {
	case wire.TypeDgram:
		return fmt.Sprintf("DGRAM(%d,+%d)", f.seq, len(f.body))
	case wire.TypeFin:
		return fmt.Sprintf("FIN(%d rel=%v)", f.fin, f.rel)
	case wire.TypePack:
		return fmt.Sprintf("PACK(hi=%d rcv=%d echo=%d f=%d rel=%v)", f.pack.HighestSeq, f.pack.Received, f.pack.EpochEcho, f.flags, f.rel)
	}
	return f.typ.String()
}

// dpFrames returns the frames of b (bodies copied).
func dpFrames(b *carrier.Batch) []dpFrame {
	out := make([]dpFrame, 0, b.Len())
	for i := range b.Len() {
		bf := b.Frame(i)
		f := dpFrame{typ: bf.Header.Type, flags: bf.Header.Flags, rel: bf.Rel}
		switch f.typ {
		case wire.TypeDgram:
			f.seq, f.body = bf.Seq, append([]byte(nil), bf.Body...)
		case wire.TypeFin:
			f.fin, _ = wire.ParseFin(bf.Payload)
		case wire.TypePack:
			f.pack, _ = wire.ParsePack(bf.Payload)
		}
		out = append(out, f)
	}
	return out
}

// dpDrop decides whether frame i of a batch on lane index lane is lost.
type dpDrop func(lane int, f carrier.BatchFrame) bool

// dpDeliver hands the frames of b to the endpoint of lane to, as a
// datagram carrier's reader would after the REL layer: a DGRAM of at least
// BigData in a reader-owned Buf (reference moved), a smaller one borrowed;
// every control frame (inner frame of a REL) to Control. It returns the
// first violation and stops there.
func dpDeliver(b *carrier.Batch, to *lane, idx int, drop dpDrop) error {
	for i := range b.Len() {
		f := b.Frame(i)
		if drop != nil && drop(idx, f) {
			continue
		}
		if err := dpDeliverFrame(to, f); err != nil {
			return err
		}
	}
	return nil
}

func dpDeliverFrame(to *lane, f carrier.BatchFrame) error {
	if f.Header.Type == wire.TypeDgram {
		return dpDatagram(to, f.Seq, f.Body)
	}
	return (*plane)(to).Control(nil, f.Header, f.Payload)
}

// dpDatagram delivers one DGRAM to lane to as a reader does.
func dpDatagram(to *lane, seq uint64, body []byte) error {
	if len(body) < carrier.BigData {
		return (*plane)(to).Datagram(nil, seq, body, nil)
	}
	env := to.s.env.Carrier
	buf := env.DBufs.Get(len(body), env.Budget)
	n := copy(buf.B, body)
	return (*plane)(to).Datagram(nil, seq, buf.B[:n], buf)
}

// dpSendFin delivers FIN(final) to l.
func dpSendFin(l *lane, final uint64) error {
	var p [wire.FinLen]byte
	wire.PutFin(p[:], final)
	return (*plane)(l).Control(nil, wire.Header{Type: wire.TypeFin, Len: wire.FinLen, Handle: wire.SessionHandle}, p[:])
}

// dpSendPack delivers PACK{pa} with flags to l.
func dpSendPack(l *lane, flags uint8, pa wire.Pack) error {
	var p [wire.PackLen]byte
	wire.PutPack(p[:], &pa)
	return (*plane)(l).Control(nil, wire.Header{Type: wire.TypePack, Flags: flags, Len: wire.PackLen, Handle: wire.SessionHandle}, p[:])
}

// dpSide is one session of a pair with its lanes (lane i of one side is
// the peer of lane i of the other).
type dpSide struct {
	s  *Session
	ls []*lane
	ps []*dpPort
}

// dpPair is a dialer (a) and a passive (b) joined lane by lane.
type dpPair struct {
	a, b dpSide
}

// dpNewPair builds a pair with one lane per entry of dgram (true: a
// datagram carrier); in selector mode lane 0 is the active data lane, in
// bond mode every lane is a data member.
func dpNewPair(oa, ob dpOpt, dgram ...bool) *dpPair {
	oa.role, ob.role = RoleDialer, RolePassive
	if ob.mode == 0 {
		ob.mode = oa.mode
	}
	p := &dpPair{a: dpSide{s: dpSession(oa)}, b: dpSide{s: dpSession(ob)}}
	for i, dg := range dgram {
		for _, sd := range []*dpSide{&p.a, &p.b} {
			data := i == 0 || sd.s.p.Mode == ModeBond
			l, fp := dpAddLane(sd.s, uint32(i+1), data, dg)
			sd.ls, sd.ps = append(sd.ls, l), append(sd.ps, fp)
		}
	}
	return p
}

// dpPump runs every live lane of from until its Fill appends nothing (the
// writer's self-continuation, bounded) and delivers each batch to the
// matching lane of to, unless that lane is dead. It returns the frames
// moved and the first violation.
func dpPump(from, to *dpSide, drop dpDrop) (int, error) {
	moved := 0
	for i, l := range from.ls {
		if l.state == LaneDead {
			continue
		}
		for range 64 {
			b := dpFill(l, time.Now())
			n := b.Len()
			var err error
			if to.ls[i].state != LaneDead {
				err = dpDeliver(b, to.ls[i], i, drop)
			}
			b.ReleaseRefs()
			if err != nil {
				return moved, err
			}
			moved += n
			if n == 0 {
				break
			}
		}
	}
	return moved, nil
}

// dpSettle pumps both directions until a round moves nothing.
func dpSettle(t testing.TB, p *dpPair, drop dpDrop) {
	t.Helper()
	for range 100 {
		na, err := dpPump(&p.a, &p.b, drop)
		if err != nil {
			t.Fatalf("a → b: %v", err)
		}
		nb, err := dpPump(&p.b, &p.a, drop)
		if err != nil {
			t.Fatalf("b → a: %v", err)
		}
		if na == 0 && nb == 0 {
			return
		}
	}
	t.Fatal("the pair did not settle")
}

// dpPayload returns an n-byte datagram whose first 8 bytes (if room) are id
// and whose rest depends on id.
func dpPayload(id uint64, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(id*31 + uint64(i)*7)
	}
	if n >= 8 {
		binary.BigEndian.PutUint64(b, id)
	}
	return b
}

// dpID returns the id dpPayload put in d.
func dpID(d []byte) uint64 { return binary.BigEndian.Uint64(d) }

// dpWrite queues dpPayload(id, n) on s and fails the test unless WriteTo
// accepted it.
func dpWrite(t testing.TB, s *Session, id uint64, n int) {
	t.Helper()
	if k, err := s.WriteTo(dpPayload(id, n)); k != n || err != nil {
		t.Fatalf("WriteTo(%d bytes) = %d, %v", n, k, err)
	}
}

// dpReadAll reads every datagram queued on s without waiting: it stops at
// the first datagram it would wait for (rx empty) and returns the
// datagrams and the error that ended it (nil when it stopped because the
// queue was empty and nothing else was due).
func dpReadAll(t testing.TB, s *Session) ([][]byte, error) {
	t.Helper()
	var out [][]byte
	buf := make([]byte, 1<<16)
	for {
		ready := dpLocked(s, func(st *stream, pk *packet) bool {
			return pk.rx.n > 0 || st.closed || st.ended || (st.peerFinDelivered && pk.rx.n == 0)
		})
		if !ready {
			return out, nil
		}
		n, err := s.ReadFrom(buf)
		if err != nil {
			return out, err
		}
		out = append(out, append([]byte(nil), buf[:n]...))
	}
}

// dpReadEOF reads every datagram up to io.EOF (which must be decided).
func dpReadEOF(t testing.TB, s *Session) [][]byte {
	t.Helper()
	out, err := dpReadAll(t, s)
	if err != io.EOF {
		t.Fatalf("after %d datagrams: %v, want io.EOF", len(out), err)
	}
	return out
}
