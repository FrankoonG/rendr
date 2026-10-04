package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Actor test harness (design §16.2 WP7): two sessions joined by real
// carrier.Conns over rendrtest.Link inside synctest bubbles (buffered
// links: two rendr ends cannot handshake over a raw net.Pipe until WP3b,
// design §0.8 V1), with a small in-test admission shim standing in for the
// root's — ReadHello, then NewPending and Start (inserted under the table
// lock), AttachOpen, Join and tombstones — and fake factories over the
// links. The health layer is inert (DialSpec.Health == nil) unless a test
// passes its own healthSource. Every package-level helper of the actor
// tests starts with "ac" (the stream's use "st", the mailbox's "mb").

// acTiming is the carrier timing of the actor tests: fast death detection
// and short dials, like the scenario fixture.
func acTiming() carrier.Timing {
	return carrier.Timing{
		PingBusy: 50 * time.Millisecond, PingIdle: time.Second,
		DeadMin: time.Second, DeadMax: 2 * time.Second, WriteStall: time.Second,
		DialTimeout: 2 * time.Second, HandshakeTimeout: 2 * time.Second,
		ProbeInterval: 200 * time.Millisecond, SessionlessIdle: 3 * time.Second,
		AbandonWait: time.Second, Window: 1 << 20, CapFloor: 128 << 10,
		BatchBudget: 256 << 10, Segment: 64 << 10,
	}
}

// acParams is the session template of the actor tests.
func acParams(mode Mode) Params {
	return Params{
		Role: RoleDialer, Mode: mode, Window: 1 << 20,
		Grace: 5 * time.Second, Retain: 10 * time.Second, BackoffMax: time.Second,
		JoinStagger: 200 * time.Millisecond, RetireGrace: 500 * time.Millisecond,
		Linger: 2 * time.Second, AcceptTimeout: 10 * time.Second,
		Selector: sched.SelectorParams{
			Band: 0.25, Floor: 5 * time.Millisecond, Dwell: time.Second,
			Cooldown: 2 * time.Second, Fresh: 2 * time.Second,
		},
		MaxCarriers: 6, AckEvery: 64 << 10, AckDelay: 20 * time.Millisecond,
		RescueMin: 300 * time.Millisecond, WindowReadvertise: 200 * time.Millisecond,
		OffsetLimit: 1 << 62, FirstEpoch: 1, TombstoneTTL: 30 * time.Second,
	}
}

// acRegistry records Registry calls.
type acRegistry struct {
	mu        sync.Mutex
	opened    []*Session
	ended     map[*Session]Verdict
	lingering map[*Session]bool
	orphaned  map[*Session]int // Orphaned(on) calls
	onOpened  func(s *Session) // optional: runs on the actor goroutine (a test may hold it)
	onEnded   func(s *Session, v Verdict)
}

func (r *acRegistry) Opened(s *Session) {
	r.mu.Lock()
	r.opened = append(r.opened, s)
	f := r.onOpened
	r.mu.Unlock()
	if f != nil {
		f(s)
	}
}

func (r *acRegistry) Lingering(s *Session, on bool) {
	r.mu.Lock()
	if r.lingering == nil {
		r.lingering = make(map[*Session]bool)
	}
	r.lingering[s] = on
	r.mu.Unlock()
}

func (r *acRegistry) Orphaned(s *Session, on bool) {
	r.mu.Lock()
	if r.orphaned == nil {
		r.orphaned = make(map[*Session]int)
	}
	if on {
		r.orphaned[s]++
	}
	r.mu.Unlock()
}

func (r *acRegistry) Ended(s *Session, v Verdict) {
	r.mu.Lock()
	if r.ended == nil {
		r.ended = make(map[*Session]Verdict)
	}
	if _, dup := r.ended[s]; dup {
		r.mu.Unlock()
		panic("Registry.Ended called twice for one session")
	}
	r.ended[s] = v
	f := r.onEnded
	r.mu.Unlock()
	if f != nil {
		f(s, v)
	}
}

// endedVerdict returns the verdict s ended with and whether it ended.
func (r *acRegistry) endedVerdict(s *Session) (Verdict, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.ended[s]
	return v, ok
}

// acEvents records events. hold, when set, runs on the emitting actor's
// goroutine for every event before it is recorded (a test may block there
// to hold that actor between two steps).
type acEvents struct {
	mu   sync.Mutex
	evs  []Event
	hold atomic.Pointer[func(Event)]
}

func (e *acEvents) Emit(ev Event) {
	if h := e.hold.Load(); h != nil {
		(*h)(ev)
	}
	e.mu.Lock()
	e.evs = append(e.evs, ev)
	e.mu.Unlock()
}

// of returns the events of kind k for session sid.
func (e *acEvents) of(sid [16]byte, k EventKind) []Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []Event
	for _, ev := range e.evs {
		if ev.Session == sid && ev.Kind == k {
			out = append(out, ev)
		}
	}
	return out
}

// acSide is one "Runtime" of a test: its carrier and session environments.
type acSide struct {
	cenv *carrier.Env
	env  *Env
	reg  *acRegistry
	ev   *acEvents
	p    Params
}

func acNewSide(inst byte, hooks *testhooks.Hooks) *acSide {
	reg, ev := &acRegistry{}, &acEvents{}
	cenv := &carrier.Env{
		Local: [16]byte{inst, 0x5A, 0xC7}, Timing: acTiming(),
		IDs: carrier.NewIDAllocator(1), Abandon: carrier.NewAbandonPool(256),
		Bufs: carrier.NewBufPool(), Budget: carrier.NewBudget(1 << 30), Hooks: hooks,
	}
	env := &Env{Carrier: cenv, Events: ev, Registry: reg, Rand: func() float64 { return 0.5 }, Hooks: hooks}
	return &acSide{cenv: cenv, env: env, reg: reg, ev: ev, p: acParams(ModeSelector)}
}

// acPassive is the in-test admission shim (design §6.1–§6.5): one
// handshake goroutine per carrier runs ReadHello; an OPEN for an unknown
// session creates it with NewPending, inserts it under the table lock and
// Starts it (the insert-or-get winner); a duplicate OPEN goes to
// AttachOpen; a JOIN to Join; a tombstone answers its verdict.
type acPassive struct {
	*acSide
	t       testing.TB
	maxMeta int
	gate    carrier.Gate
	// answer, when set, may replace the admission of a new OPEN by a
	// scripted OPEN_ACK (typed Dial answers); ok false admits normally.
	answer func(o *wire.Open) (oa wire.OpenAck, ok bool)
	// joinAnswer, when set, may answer a JOIN with a scripted JOIN_ACK
	// (the carrier is closed after it); ok false routes the JOIN normally.
	joinAnswer func(j *wire.Join) (ja wire.JoinAck, ok bool)
	mu         sync.Mutex
	tab        map[[16]byte]*acEntry
	pending    chan *Session // admitted sessions in admission order (the listener queue)
	wg         sync.WaitGroup
	// Admission outcomes (stimulus proofs): JOIN answers by status, and
	// duplicate OPENs refused by AttachOpen by status and code.
	joins      map[wire.AckStatus]int
	openRefuse map[[2]uint32]int
	// closing holds the carriers the shim answered and closed itself (the
	// root's handshake goroutines own those); teardown joins them.
	closing []*carrier.Conn
}

// closed records a carrier the shim answered and closed.
func (p *acPassive) closed(c *carrier.Conn) {
	p.mu.Lock()
	p.closing = append(p.closing, c)
	p.mu.Unlock()
}

// joinClosing waits for every carrier the shim closed (bounded: each one's
// close is itself bounded by its write deadline, drain and AbandonWait).
func (p *acPassive) joinClosing(t testing.TB) {
	p.mu.Lock()
	cs := append([]*carrier.Conn(nil), p.closing...)
	p.mu.Unlock()
	for _, c := range cs {
		select {
		case <-c.Done():
		case <-time.After(10 * time.Second):
			t.Errorf("a carrier the admission shim closed is not done")
		}
	}
}

// counts returns copies of the admission counters.
func (p *acPassive) counts() (joins map[wire.AckStatus]int, openRefuse map[[2]uint32]int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	joins, openRefuse = make(map[wire.AckStatus]int), make(map[[2]uint32]int)
	for k, v := range p.joins {
		joins[k] = v
	}
	for k, v := range p.openRefuse {
		openRefuse[k] = v
	}
	return joins, openRefuse
}

type acEntry struct {
	s    *Session
	tomb bool
	v    Verdict
}

func acNewPassive(t testing.TB, inst byte, hooks *testhooks.Hooks) *acPassive {
	p := &acPassive{acSide: acNewSide(inst, hooks), t: t, maxMeta: 4096, tab: make(map[[16]byte]*acEntry), pending: make(chan *Session, 64),
		joins: make(map[wire.AckStatus]int), openRefuse: make(map[[2]uint32]int)}
	p.reg.onEnded = p.tombstone
	return p
}

// tombstone replaces a live entry by its verdict (Registry.Ended).
func (p *acPassive) tombstone(s *Session, v Verdict) {
	p.mu.Lock()
	if e := p.tab[s.ID()]; e != nil && e.s == s {
		e.s, e.tomb, e.v = nil, true, v
	}
	p.mu.Unlock()
}

// session returns the live session sid, or nil.
func (p *acPassive) session(sid [16]byte) *Session {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e := p.tab[sid]; e != nil {
		return e.s
	}
	return nil
}

// accept is a rendrtest LinkConfig.Accept.
func (p *acPassive) accept(nc net.Conn) error {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		h, err := carrier.ReadHello(p.cenv, nc, time.Now().Add(2*time.Second), p.maxMeta, p.gate)
		if err != nil {
			return
		}
		switch h.First.Type {
		case wire.TypeOpen:
			p.admitOpen(h)
		case wire.TypeJoin:
			p.admitJoin(h)
		default:
			h.Conn.Kill(carrier.CauseLocalClose, "no sessionless carriers in actor tests")
			p.closed(h.Conn)
		}
	}()
	return nil
}

func (p *acPassive) admitOpen(h *carrier.Hello) {
	o, err := wire.ParseOpen(h.Payload, p.maxMeta)
	if err != nil {
		p.answerOpen(h.Conn, wire.OpenAck{Status: wire.StatusBadRequest, Code: wire.CodeBadValue})
		return
	}
	if p.answer != nil {
		if oa, ok := p.answer(&o); ok {
			p.answerOpen(h.Conn, oa)
			return
		}
	}
	p.mu.Lock()
	e := p.tab[o.SID]
	if e == nil {
		pp := p.p
		pp.Role, pp.Mode = RolePassive, Mode(o.Mode)
		pp.Grace = min(max(time.Duration(o.RetainMs)*time.Millisecond, time.Second), 400*time.Second)
		s := NewPending(p.env, PassiveSpec{SID: o.SID, Params: pp, DialerInstance: h.Preface.Instance, PeerWindow: o.Window, Metadata: o.Metadata}, h.Conn)
		p.tab[o.SID] = &acEntry{s: s}
		p.mu.Unlock()
		s.Start()
		p.pending <- s
		return
	}
	s, tomb, v := e.s, e.tomb, e.v
	p.mu.Unlock()
	if tomb {
		p.answerOpen(h.Conn, v.OpenAck())
		return
	}
	if taken, v := s.AttachOpen(h.Conn); !taken {
		p.mu.Lock()
		p.openRefuse[[2]uint32{uint32(v.Status), v.Code}]++
		p.mu.Unlock()
		p.answerOpen(h.Conn, v.OpenAck())
	}
}

func (p *acPassive) admitJoin(h *carrier.Hello) {
	j, err := wire.ParseJoin(h.Payload)
	if err != nil {
		p.answerJoin(h.Conn, wire.StatusBadRequest)
		return
	}
	if p.joinAnswer != nil {
		if ja, ok := p.joinAnswer(&j); ok {
			var b [wire.JoinAckLen]byte
			h.Conn.WriteAndClose(wire.TypeJoinAck, 0, wire.SessionHandle, b[:wire.PutJoinAck(b[:], &ja)], time.Time{})
			p.closed(h.Conn)
			return
		}
	}
	s := p.session(j.SID)
	if s == nil {
		p.mu.Lock()
		p.joins[wire.StatusUnknownSession]++
		p.mu.Unlock()
		p.answerJoin(h.Conn, wire.StatusUnknownSession)
		return
	}
	taken, st := s.Join(h.Conn, &j)
	p.mu.Lock()
	p.joins[st]++
	p.mu.Unlock()
	if !taken {
		p.answerJoin(h.Conn, st)
	}
}

// answerOpen writes oa on the unstarted carrier c and closes it.
func (p *acPassive) answerOpen(c *carrier.Conn, oa wire.OpenAck) {
	b := make([]byte, wire.OpenAckFixedLen+len(oa.Msg))
	c.WriteAndClose(wire.TypeOpenAck, 0, wire.SessionHandle, b[:wire.PutOpenAck(b, &oa)], time.Time{})
	p.closed(c)
}

// answerJoin writes JOIN_ACK(st) on the unstarted carrier c and closes it.
func (p *acPassive) answerJoin(c *carrier.Conn, st wire.AckStatus) {
	var b [wire.JoinAckLen]byte
	c.WriteAndClose(wire.TypeJoinAck, 0, wire.SessionHandle, b[:wire.PutJoinAck(b[:], &wire.JoinAck{Status: st})], time.Time{})
	p.closed(c)
}

// acWorld is one test's two Runtimes, links and sessions; teardown shuts
// every session down, waits for Done, closes the links, joins the
// handshakes and checks that both Budgets returned to zero.
type acWorld struct {
	t     testing.TB
	a     *acSide
	b     *acPassive
	links []*rendrtest.Link
	sess  []*Session
	sid   byte
	quit  chan struct{} // stops the watchdog
}

// acWatchdog bounds a test in virtual time: a bubble whose carriers keep
// timers running never reports a deadlock, so a test stuck in an unbounded
// wait would otherwise spin until the binary's real-time timeout.
const acWatchdog = 10 * time.Minute

// acNewWorld makes a dialer Runtime with hooks (nil: none) and a passive
// one without: both ends would call DeathObserved with the same CarrierIDs.
func acNewWorld(t testing.TB, hooks *testhooks.Hooks) *acWorld {
	w := &acWorld{t: t, a: acNewSide(1, hooks), b: acNewPassive(t, 2, nil), quit: make(chan struct{})}
	go func() {
		select {
		case <-w.quit:
		case <-time.After(acWatchdog):
			panic(fmt.Sprintf("%s: stuck for %v of virtual time", t.Name(), acWatchdog))
		}
	}()
	return w
}

// acLinkDelay is the one-way delay every actor-test link starts with. On a
// link without delay a PONG can arrive before its PING's write commit
// (with GOMAXPROCS=1 every PONG does); the carrier estimator then gives no
// sample and does not advance its PONG watermark, so a carrier that sends
// DATA stays capped at its capacity floor for good (a carrier-layer defect
// reported to WP3). A virtual one-way delay makes every PONG arrive after
// the commit: the commit happens at the write's virtual instant, the PONG
// two delays later.
const acLinkDelay = time.Millisecond

// link makes a link to the passive.
func (w *acWorld) link(name string) *rendrtest.Link {
	l := w.linkTo(name, w.b)
	return l
}

// linkTo makes a link to passive p (another instance of the peer).
func (w *acWorld) linkTo(name string, p *acPassive) *rendrtest.Link {
	l := rendrtest.NewLink(rendrtest.LinkConfig{Name: name, Accept: p.accept})
	l.SetDelay(acLinkDelay, 0)
	w.links = append(w.links, l)
	return l
}

// slowLink makes a link with a 1 ms one-way delay and a 32 MiB/s
// bottleneck per direction, so transfers take virtual time and a fault can
// hit them midway (a bubble runs CPU-bound work to completion before
// synctest.Wait returns).
func (w *acWorld) slowLink(name string) *rendrtest.Link {
	l := w.link(name)
	l.SetDelay(time.Millisecond, 0)
	l.SetRate(32 << 20)
	return l
}

// factories returns one factory per link, in order.
func acFactories(links ...*rendrtest.Link) []carrier.Factory {
	fs := make([]carrier.Factory, len(links))
	for i, l := range links {
		fs[i] = carrier.Factory{Index: i, Name: l.Name(), Dial: l.Dial}
	}
	return fs
}

// spec returns a DialSpec over links with a fresh session ID.
func (w *acWorld) spec(mode Mode, links ...*rendrtest.Link) DialSpec {
	w.sid++
	p := w.a.p
	p.Mode = mode
	return DialSpec{SID: [16]byte{0xD1, w.sid}, Params: p, Factories: acFactories(links...)}
}

// dial runs Dial with spec and health source h (nil: inert).
func (w *acWorld) dial(ctx context.Context, spec DialSpec, h healthSource) (*Session, error) {
	s, err := dial(ctx, w.a.env, spec, h)
	if s != nil {
		w.sess = append(w.sess, s)
	}
	return s, err
}

// confirmNext takes the next admitted pending session and confirms it.
func (w *acWorld) confirmNext() *Session {
	w.t.Helper()
	s := <-w.b.pending
	w.sess = append(w.sess, s)
	if err := s.Confirm(); err != nil {
		w.t.Fatalf("Confirm: %v", err)
	}
	return s
}

// open dials over links and confirms the passive side.
func (w *acWorld) open(mode Mode, h healthSource, links ...*rendrtest.Link) (dialer, passive *Session) {
	w.t.Helper()
	spec := w.spec(mode, links...)
	type res struct {
		s   *Session
		err error
	}
	ch := make(chan res, 1)
	go func() {
		s, err := w.dial(context.Background(), spec, h)
		ch <- res{s, err}
	}()
	passive = w.confirmNext()
	r := <-ch
	if r.err != nil {
		w.t.Fatalf("Dial: %v", r.err)
	}
	return r.s, passive
}

// teardown shuts every session down and joins everything: each session's
// Done (it covers its lanes, its attempts and every carrier it closed
// itself), the links, the shim's handshakes and the carriers the shim
// closed. Every buffer is charged only while a started carrier's reader or
// writer holds it, so both Budgets are back at zero once that is all done.
func (w *acWorld) teardown() {
	defer close(w.quit)
	for _, s := range w.sess {
		s.Shutdown()
	}
	for len(w.b.pending) > 0 {
		s := <-w.b.pending
		w.sess = append(w.sess, s)
		s.Shutdown()
	}
	for _, s := range w.sess {
		acDone(w.t, s, 10*time.Second)
	}
	for _, l := range w.links {
		l.Close()
	}
	w.b.wg.Wait()
	w.b.joinClosing(w.t)
	synctest.Wait()
	if u := w.a.cenv.Budget.Used(); u != 0 {
		w.t.Errorf("dialer Budget: %d bytes still charged", u)
	}
	if u := w.b.cenv.Budget.Used(); u != 0 {
		w.t.Errorf("passive Budget: %d bytes still charged", u)
	}
}

// acSnap returns the published snapshot of s and the routed active lane id
// read in one critical section (L27).
func acRouted(s *Session) (reported, routed uint32, dataLanes int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.lanes {
		if l.data {
			dataLanes++
		}
	}
	if a := s.ctl.active; a != nil {
		routed = a.id
	}
	for _, ls := range s.snap.Load().lanes {
		if ls.state == LaneActive {
			reported = ls.id
		}
	}
	return reported, routed, dataLanes
}

// acActive returns the CarrierID Status reports as active (0: none).
func acActive(s *Session) uint32 {
	for _, c := range s.Status().Carriers {
		if c.State == LaneActive {
			return c.ID
		}
	}
	return 0
}

// acWaitFor advances virtual time in steps until cond holds or within
// passed (then it fails the test with what).
func acWaitFor(t testing.TB, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		synctest.Wait()
		if cond() {
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("not within %v: %s", within, what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// acTransfer writes n bytes of PRNG(seed) on from (then CloseWrite when
// closeWrite) while to reads them through a Verifier; it returns the
// writer's and the verifier's errors once both finished.
func acTransfer(from, to *Session, n int64, seed uint64, closeWrite bool) (wErr, rErr error) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		wErr = acWritePRNG(from, n, seed)
		if wErr == nil && closeWrite {
			wErr = from.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		v := rendrtest.NewVerifier(seed, n)
		if closeWrite {
			rErr = v.ReadAll(to)
			return
		}
		buf := make([]byte, 64<<10)
		var got int64
		for got < n {
			k, err := to.Read(buf[:min(int64(len(buf)), n-got)])
			v.Write(buf[:k])
			got += int64(k)
			if err != nil {
				rErr = fmt.Errorf("read after %d of %d bytes: %w", got, n, err)
				return
			}
		}
		rErr = v.Done(io.EOF)
	}()
	wg.Wait()
	return wErr, rErr
}

// acWritePRNG writes n bytes of PRNG(seed) to s in 48 KiB pieces.
func acWritePRNG(s *Session, n int64, seed uint64) error {
	g := rendrtest.PRNG(seed)
	buf := make([]byte, 48<<10)
	for n > 0 {
		k := min(int64(len(buf)), n)
		g.Read(buf[:k])
		if _, err := s.Write(buf[:k]); err != nil {
			return err
		}
		n -= k
	}
	return nil
}

// acIsCtx reports a context error.
func acIsCtx(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// acHealth is a fake health layer (healthSource): the test publishes
// per-factory RTT evidence; MarkFailed and Succeeded maintain failed marks
// as the real layer does; every publication rings the subscribers.
type acHealth struct {
	mu      sync.Mutex
	snap    atomic.Pointer[carrier.Snapshot]
	subs    map[int]carrier.Doorbell
	nextSub int
	rtt     []time.Duration // 0: no sample (Unknown)
	failed  []bool
	marks   int
	fresh   time.Duration
}

func acNewHealth(n int, fresh time.Duration) *acHealth {
	h := &acHealth{subs: make(map[int]carrier.Doorbell), rtt: make([]time.Duration, n), failed: make([]bool, n), fresh: fresh}
	h.publish(time.Now())
	return h
}

// set publishes fresh evidence: rtt[i] > 0 is a probe sample of factory i
// at now (a successful probe PONG also clears the factory's failed mark,
// as the real layer does).
func (h *acHealth) set(rtt ...time.Duration) {
	h.mu.Lock()
	copy(h.rtt, rtt)
	h.probedLocked()
	h.mu.Unlock()
	h.publish(time.Now())
}

// bump republishes the current evidence with fresh timestamps (new probe
// samples: a new version, one more ring for every subscriber).
func (h *acHealth) bump() {
	h.mu.Lock()
	h.probedLocked()
	h.mu.Unlock()
	h.publish(time.Now())
}

// probedLocked clears the failed marks of the factories with a sample.
func (h *acHealth) probedLocked() {
	for i, r := range h.rtt {
		if r > 0 {
			h.failed[i] = false
		}
	}
}

func (h *acHealth) publish(now time.Time) {
	h.mu.Lock()
	old := h.snap.Load()
	sn := &carrier.Snapshot{Probing: true, Fresh: h.fresh, Sum: make([]sched.Summary, len(h.rtt)), Failed: append([]bool(nil), h.failed...), Info: make([]carrier.FactoryInfo, len(h.rtt))}
	if old != nil {
		sn.Version = old.Version + 1
	}
	for i, r := range h.rtt {
		if r > 0 {
			sn.Sum[i] = sched.Summary{Seen: true, Mean: r, N: 32, At: now}
		}
	}
	h.snap.Store(sn)
	subs := make([]carrier.Doorbell, 0, len(h.subs))
	for _, b := range h.subs {
		subs = append(subs, b)
	}
	h.mu.Unlock()
	for _, b := range subs {
		b.Ring()
	}
}

func (h *acHealth) Snapshot() *carrier.Snapshot { return h.snap.Load() }

func (h *acHealth) Subscribe(b carrier.Doorbell) func() {
	h.mu.Lock()
	id := h.nextSub
	h.nextSub++
	h.subs[id] = b
	h.mu.Unlock()
	return func() {
		h.mu.Lock()
		delete(h.subs, id)
		h.mu.Unlock()
	}
}

func (h *acHealth) MarkFailed(i int, reason string) {
	h.mu.Lock()
	h.failed[i] = true
	h.marks++
	h.mu.Unlock()
	h.publish(time.Now())
}

func (h *acHealth) Succeeded(i int) {
	h.mu.Lock()
	changed := h.failed[i]
	h.failed[i] = false
	h.mu.Unlock()
	if changed {
		h.publish(time.Now())
	}
}

func (h *acHealth) Gauges() []*carrier.Gauge { return nil }

func (h *acHealth) Hold() func() { return func() {} }

// acFreshen republishes h's evidence every 250 ms, as probes keep it fresh,
// until the returned stop is called (it joins the goroutine).
func acFreshen(h *acHealth) (stop func()) {
	quit, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(250 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-quit:
				return
			case <-t.C:
				h.bump()
			}
		}
	}()
	return func() {
		close(quit)
		<-done
	}
}

// acDone waits for s.Done within a virtual-time bound (a bubble with live
// carrier timers never reports a deadlock, so every wait is bounded).
func acDone(t testing.TB, s *Session, within time.Duration) {
	t.Helper()
	select {
	case <-s.Done():
	case <-time.After(within):
		t.Fatalf("%v session not done within %v: %+v", s.Role(), within, s.Status())
	}
}
