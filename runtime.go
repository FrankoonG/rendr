package rendr

import (
	"context"
	"crypto/rand"
	"math"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/udpflow"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Runtime is one rendr instance: it owns its InstanceID, admission tables
// (handshake slots, session table and tombstones, sessionless carriers),
// the memory accounts, the buffer pool, the abandoned-call pool, the event
// queue, its Listeners and Peers. All methods are safe for concurrent use.
type Runtime struct {
	id      InstanceID
	eff     effective            // immutable after construction
	ov      *testhooks.Overrides // a copy, for normalizeListen; nil in production
	cenv    carrier.Env          // immutable after construction
	abandon *carrier.AbandonPool // goroutines stuck in embedder code (L52)
	budget  *carrier.Budget      // MaxBufferedBytes: the data buffers
	stages  *carrier.Budget      // the reader stages, outside MaxBufferedBytes (design §0.14 B2)
	ev      *eventQueue          // nil without Config.OnEvent
	table   *sessionTable[*session.Session]
	hs      *hsTable
	slt     *slTable
	gateFn  carrier.Gate    // rt.gate, bound once
	ctx     context.Context // cancelled by Close: in-flight Dials withdraw
	cancel  context.CancelCauseFunc
	backlog [numKinds]atomic.Int64 // pending sessions across Listeners per kind (Status.AcceptBacklog)
	closing atomic.Bool            // set under mu by Close; read lock-free on admission paths

	hsg  *group        // handshake goroutines (accept loops and Handle start them) and their conn closers
	slg  *group        // sessionless carriers' watchers
	dial *group        // Peer.Dial calls inside session.Dial
	cut  chan struct{} // closed by Close at its close bound: refusals still in flight end (awaitRefusal)

	mu        sync.Mutex // a leaf (design §3.2)
	closed    chan struct{}
	adjust    []string // Status.ConfigAdjustments: Config first, then "Listen[i]."
	nconfig   int      // the Config's records at the front of adjust (never trimmed)
	nlisten   int      // Listen calls so far (the i of "Listen[i].")
	listeners map[*Listener]struct{}
	peers     map[*Peer]struct{}
	sl        map[*carrier.Conn]struct{}   // live sessionless carriers
	sources   map[*udpflow.Source]struct{} // FromPacketConn sources whose Done is not closed (Status.Datagram.Sources)
	draining  []<-chan struct{}            // Done of ended sessions that may still run (joined by Close)
	pruneAt   int

	fmu    sync.Mutex                    // guards pflows; taken before a udpflow.Flow's lock (holdFlow), never while one is held
	pflows map[*session.Session]*flowSet // passive packet sessions: the raw-UDP flows of their OPEN carriers (listener_pkt.go)
}

// Join bounds of Runtime.Close (design §3.1, §6.8).
const (
	closeSlack      = 250 * time.Millisecond // beyond the sessions' and probe runs' own bound
	minPruneAt      = 64                     // draining list prune threshold floor
	maxFactories    = wire.MaxSchedIDs       // carriers per Peer (MaxCarriersPerSession ≤ 16)
	maxListenAdjust = 64                     // Listen records kept in ConfigAdjustments, the latest (W4-L2-2)
)

// NewRuntime normalizes cfg (see Config) and draws the InstanceID from
// crypto/rand. It fails only if crypto/rand fails; out-of-range values are
// clamped, never rejected. It starts no goroutine unless cfg.OnEvent is set
// (the event worker).
func NewRuntime(cfg Config) (*Runtime, error) {
	return newRuntime(cfg, nil)
}

// newRuntime builds a Runtime from cfg with ov applied after normalization
// (testhooks; nil in production).
func newRuntime(cfg Config, ov *testhooks.Overrides) (*Runtime, error) {
	id, err := newInstanceID(rand.Reader)
	if err != nil {
		return nil, err
	}
	var ovc *testhooks.Overrides
	if ov != nil {
		c := *ov // frozen: a later change of the caller's value has no effect
		ovc = &c
	}
	eff, adj := normalize(cfg, ovc)
	rt := &Runtime{
		id:        id,
		eff:       eff,
		ov:        ovc,
		abandon:   carrier.NewAbandonPool(eff.abandonLimit),
		budget:    carrier.NewBudget(eff.cfg.MaxBufferedBytes),
		stages:    carrier.NewBudget(math.MaxInt64), // forced charges only: never refuses
		table:     newSessionTable[*session.Session](eff.cfg.MaxSessions),
		hs:        newHSTable(eff.cfg.Handshake.MaxConcurrent),
		slt:       newSLTable(eff.cfg.Sessionless.PerInstance, eff.cfg.Sessionless.Total),
		hsg:       newGroup(),
		slg:       newGroup(),
		dial:      newGroup(),
		cut:       make(chan struct{}),
		closed:    make(chan struct{}),
		adjust:    adj,
		nconfig:   len(adj),
		listeners: make(map[*Listener]struct{}),
		peers:     make(map[*Peer]struct{}),
		sl:        make(map[*carrier.Conn]struct{}),
		sources:   make(map[*udpflow.Source]struct{}),
		pflows:    make(map[*session.Session]*flowSet),
		pruneAt:   minPruneAt,
	}
	rt.cenv = carrier.Env{
		Local:   id,
		Timing:  eff.timing,
		Presets: eff.presets,
		IDs:     carrier.NewIDAllocator(eff.firstCarrierID),
		Abandon: rt.abandon,
		Bufs:    carrier.NewBufPool(),
		Budget:  rt.budget,
		Stages:  rt.stages,
		Hooks:   eff.hooks,
		DBufs:   carrier.NewDatagramBufPool(),
		Dgram:   &carrier.DgramStats{},
	}
	rt.gateFn = rt.gate
	rt.ctx, rt.cancel = context.WithCancelCause(context.Background())
	rt.ev = newEventQueue(eff.cfg.OnEvent, eff.eventQueue, eff.hooks)
	return rt, nil
}

// InstanceID returns this Runtime's InstanceID.
func (rt *Runtime) InstanceID() InstanceID { return rt.id }

// NewPeer validates and deep-copies cfg: 1–16 carriers of both kinds, every
// Name non-empty and unique, every Dial non-nil, every DatagramCarrier's MTU
// within 537–65,507. A Peer with two or more carriers runs the health layer
// (probe carriers, of both kinds) while it is in use.
func (rt *Runtime) NewPeer(cfg PeerConfig) (*Peer, error) {
	p, err := newPeer(rt, cfg)
	if err != nil {
		return nil, err
	}
	rt.mu.Lock()
	if rt.closing.Load() {
		rt.mu.Unlock()
		p.shutdown()
		return nil, net.ErrClosed
	}
	rt.peers[p] = struct{}{}
	rt.mu.Unlock()
	return p, nil
}

// Listen creates a Listener over cfg.Sources (one accept goroutine per
// FromListener source, one demultiplexing goroutine per FromPacketConn
// source). cfg is normalized like Config; adjustments are appended to
// Status.ConfigAdjustments with the prefix "Listen[i]." (only the latest
// 64 Listen records are kept, see Status). When Listen fails the sources
// stay owned by the caller.
func (rt *Runtime) Listen(cfg ListenConfig) (*Listener, error) {
	srcs, psrcs, err := listenSources(cfg.Sources)
	if err != nil {
		return nil, err
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.closing.Load() {
		return nil, net.ErrClosed
	}
	ncfg, adj := normalizeListen(rt.nlisten, cfg, rt.ov)
	rt.nlisten++
	rt.adjust = append(rt.adjust, adj...)
	if over := len(rt.adjust) - rt.nconfig - maxListenAdjust; over > 0 {
		rt.adjust = slices.Delete(rt.adjust, rt.nconfig, rt.nconfig+over) // the oldest Listen records
	}
	ln := newListener(rt, ncfg, srcs)
	ln.psrcs = rt.newSourcesLocked(psrcs)
	rt.listeners[ln] = struct{}{}
	ln.start()
	return ln, nil
}

// Status returns the Runtime counters. Counters are read individually;
// consistency across them is not claimed.
func (rt *Runtime) Status() Status {
	now := time.Now()
	rt.mu.Lock()
	adj := slices.Clone(rt.adjust)
	rt.pruneDrainingLocked()
	srcs := rt.liveSourcesLocked()
	rt.mu.Unlock()
	dropped, panics := rt.ev.counters()
	return Status{
		Instance:           rt.id,
		Sessions:           rt.table.counts(now),
		Handshakes:         rt.hs.len(),
		HandshakeEvictions: rt.hs.evicted(),
		AcceptBacklog:      [2]int{int(rt.backlog[kindIdxStream].Load()), int(rt.backlog[kindIdxPacket].Load())},
		Sessionless:        rt.slt.len(),
		BufferedBytes:      rt.budget.Used() + rt.stages.Used(),
		Abandoned:          rt.abandon.Len(),
		EventsDropped:      dropped,
		CallbackPanics:     panics,
		ConfigAdjustments:  adj,
		Datagram:           rt.datagramStatus(srcs),
	}
}

// Close shuts the Runtime down (idempotent, bounded): new handshakes are
// answered PREFACE_ACK(GOING_AWAY); every Listener closes; every pending
// session is answered GOING_AWAY; every open session that has not ended —
// one whose application called Close and that is still finishing in the
// background included — sends RST(AbortGoingAway) and GOAWAY and ends
// locally with net.ErrClosed; every Peer stops probing;
// sessionless carriers get GOAWAY; an admission refusal still being written
// gets the close bound, min(1 s, DeadMax), and is then cut, and every
// FromPacketConn socket is closed (its flows end); then every
// goroutine is joined within about 2 s, plus AbandonWait (1 s, the bound on
// waiting for a goroutine stuck in embedder code) for a stuck
// Config.OnEvent callback, and stragglers stuck in embedder code are counted
// in Status.Abandoned. Later calls on the Runtime and its objects return
// net.ErrClosed.
//
// Sessions reset by Close end with net.ErrClosed, their peers' with
// *AbortError (AbortGoingAway), or with io.EOF where both FINs had already
// been delivered and only the final confirmation was outstanding. For a
// clean end, let every session finish first: Read until io.EOF,
// Conn.Close, wait until Conn.Done is closed (bounded by your own context;
// Conn.Status().Err is io.EOF after a clean finish), and only then Close.
//
// A concurrent or later Close waits for the first one to finish, except
// when it is called from Config.OnEvent (it then returns at once: the first
// Close never waits for the callback that called it).
func (rt *Runtime) Close() error {
	rt.mu.Lock()
	if rt.closing.Load() {
		done := rt.closed
		rt.mu.Unlock()
		if !rt.onEventWorker() {
			<-done
		}
		return nil
	}
	rt.closing.Store(true) // step 1: the gate answers GOING_AWAY, Dial fails, no Listen or NewPeer
	lns := mapKeys(rt.listeners)
	peers := mapKeys(rt.peers)
	sl := mapKeys(rt.sl)
	srcs := mapKeys(rt.sources)
	rt.mu.Unlock()
	rt.cancel(net.ErrClosed) // in-flight Dials withdraw (session.Dial returns within 100 ms)

	// Steps 2–5 only post work: nothing before the joins waits for a session
	// or an embedder call, so a large table or backlog cannot eat into the
	// join bounds, which count from the end of step 5.
	//
	// Step 2: every Listener stops (its sources are closed once). Its
	// pending sessions are answered GOING_AWAY by their Shutdown in step 3.
	for _, ln := range lns {
		ln.shut()
	}
	// Step 3: every session; pending ones answer GOING_AWAY.
	for _, s := range rt.table.live() {
		s.Shutdown()
	}
	// Step 4: every Peer stops probing (Health.Close is bounded).
	health := newGroup()
	for _, p := range peers {
		health.add()
		go func() {
			defer health.done(nil)
			p.shutdown()
		}()
	}
	// Step 5: sessionless carriers; unfinished handshakes are closed (the
	// drain is final: no handshake starts afterwards). Their closers are
	// members of the handshake group, so a stuck embedder Close is counted
	// before Close returns (L52).
	for _, c := range sl {
		c.GoAway()
	}
	for _, nc := range rt.hs.drain() {
		rt.hsg.add()
		rt.closeWatched(nc)
	}

	t1 := time.Now()
	wait := rt.eff.timing.AbandonWait
	kill := min(time.Second, rt.eff.cfg.DeadMax)
	killAt := t1.Add(kill) // the close bound of a CLOSE frame (§4.7) and of a refusal
	joinBy := t1.Add(wait) // accept loops, in-flight Dials
	// The own bound of a session after Shutdown and of a Peer's probe run
	// after Health.Close (design §4.7, §0.9 X2): lanes whose CLOSE is
	// unwritten are killed at the Kill bound and their stuck parts
	// abandoned AbandonWait later; dial attempts still running are
	// abandoned 2·AbandonWait after their cancellation.
	bound := t1.Add(max(kill+wait, 2*wait) + closeSlack)

	// Step 7 (W14: before the event queue). After the handshakes, accept
	// loops and in-flight Dials no session can appear any more; one that
	// a racing handshake or Dial created after the snapshot of step 3 saw
	// closing and shut it down itself (admitOpen, Peer.Dial), so the second
	// snapshot (live or ended) is only joined. A failed Dial's session
	// withdrawing in the background is in it too: its Dial stays a member
	// of rt.dial until the session's Registry.Ended (dialReg), and Ended
	// records the session for this snapshot before it leaves the table.
	for _, ln := range lns {
		ln.loops.wait(joinBy, rt.abandon)
	}
	rt.dial.wait(joinBy, nil)
	// At the close bound: sessionless carriers whose CLOSE is still
	// unwritten are killed, and refusals still being written or drained are
	// cut (their conns closed, awaitRefusal); AbandonWait later every
	// handshake goroutine still running is stuck in embedder code.
	rt.hsg.wait(killAt, nil)
	if !rt.slg.wait(killAt, nil) {
		for _, c := range sl {
			if !c.CloseSent() {
				c.Kill(carrier.CauseLocalClose, "Runtime.Close: CLOSE not written within the close bound")
			}
		}
	}
	close(rt.cut)
	// FromPacketConn sources close their sockets only after the sessions
	// (M2-D58, M2 design §A4.6): the open packet sessions' RST(GoingAway)
	// and their carriers' GOAWAYs are REL-wrapped and travel over these
	// sockets, so every session — the ones that ended meanwhile included —
	// gets until its end or the close bound. Then every flow's reads fail,
	// and each source's Done is joined below.
	if len(srcs) > 0 {
		early := doneOf(rt.table.live())
		rt.mu.Lock()
		early = append(early, rt.draining...)
		rt.mu.Unlock()
		waitDone(early, killAt)
		for _, src := range srcs {
			src.Abort()
		}
	}
	rt.hsg.wait(killAt.Add(wait), rt.abandon)
	join := doneOf(rt.table.live())
	rt.mu.Lock()
	join = append(join, rt.draining...)
	rt.mu.Unlock()

	for _, src := range srcs {
		join = append(join, src.Done())
	}
	waitDone(join, bound)
	rt.slg.wait(bound, nil)
	health.wait(bound, nil)

	// Step 6: the event queue delivers what is queued (SessionEnd events of
	// the sessions ended above included) and its worker is joined.
	rt.ev.join(wait, rt.abandon)

	rt.mu.Lock()
	rt.draining = nil
	close(rt.closed) // under mu: noteEnded records nothing afterwards
	rt.mu.Unlock()
	return nil
}

// onEventWorker reports whether the caller runs on the event worker (it
// was called from Config.OnEvent).
func (rt *Runtime) onEventWorker() bool {
	return rt.ev != nil && goid() == rt.ev.worker.Load()
}

// doneOf returns the Done channels of ss.
func doneOf(ss []*session.Session) []<-chan struct{} {
	out := make([]<-chan struct{}, len(ss))
	for i, s := range ss {
		out[i] = s.Done()
	}
	return out
}

// waitDone waits until every channel in done (sessions' Done) closed or
// deadline. A session that misses its own bound is not abandoned: rendr's
// own goroutines always end (design §6.8); Close only stops waiting.
func waitDone(done []<-chan struct{}, deadline time.Time) {
	if len(done) == 0 {
		return
	}
	t := time.NewTimer(time.Until(deadline))
	defer t.Stop()
	for _, ch := range done {
		select {
		case <-ch:
		case <-t.C:
			return
		}
	}
}

// gate decides the PREFACE_ACK status of a valid PREFACE (design §5.1):
// GOING_AWAY while the Runtime closes, CAPACITY while the abandoned-call
// pool is full (no new carrier is created then, D20), else OK.
func (rt *Runtime) gate(*wire.Preface) wire.PrefaceStatus {
	switch {
	case rt.closing.Load():
		return wire.PrefaceGoingAway
	case rt.abandon.Full():
		return wire.PrefaceCapacity
	}
	return wire.PrefaceOK
}

// noteEnded records an ended session's Done until it closes, so that Close
// joins the session even when it no longer has a table entry (a passive
// tombstone keeps no session; a dialer entry is removed; a failed Dial
// never had one). The Registries call it before they remove the table
// entry, so a session is always in the table or in this list (or both) for
// Close's snapshot. Only the Done channel is kept, never the session
// itself, so an ended session's memory is not held here. Closed channels
// are pruned when the list doubled and whenever Status is read.
func (rt *Runtime) noteEnded(s *session.Session) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if isClosed(rt.closed) {
		return
	}
	rt.draining = append(rt.draining, s.Done())
	if len(rt.draining) >= rt.pruneAt {
		rt.pruneDrainingLocked()
	}
}

// pruneDrainingLocked drops the Done channels that closed and sets the
// next count-based prune at twice what is kept (at least minPruneAt).
func (rt *Runtime) pruneDrainingLocked() {
	kept := rt.draining[:0]
	for _, ch := range rt.draining {
		if !isClosed(ch) {
			kept = append(kept, ch)
		}
	}
	clear(rt.draining[len(kept):])
	rt.draining = kept
	rt.pruneAt = max(minPruneAt, 2*len(kept))
}

// isClosed reports whether ch is closed (non-blocking).
func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// mapKeys returns the keys of m (unordered).
func mapKeys[K comparable, V any](m map[K]V) []K {
	out := make([]K, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// group joins a dynamic set of goroutines with a bound (design §3.1, L52):
// wait returns when every member exited, or at the deadline; members still
// running then — stuck in embedder code — are counted once in the
// abandoned-call pool and leave it when they finally exit. No member may be
// added after a wait with a pool gave up (every group stops admitting
// members before it is joined: a closed Listener starts no handshake, a
// drained handshake table admits none, a closing Runtime starts no Dial and
// no sessionless carrier); a member may add another while it still runs.
type group struct {
	mu   sync.Mutex
	n    int           // members running
	owed int           // members counted as abandoned that are still running
	idle chan struct{} // closed while n == 0
}

func newGroup() *group {
	g := &group{idle: make(chan struct{})}
	close(g.idle)
	return g
}

// add counts one more member; call it before starting the goroutine.
func (g *group) add() {
	g.mu.Lock()
	if g.n == 0 {
		g.idle = make(chan struct{})
	}
	g.n++
	g.mu.Unlock()
}

// done is called by a member when it exits; a member that was counted as
// abandoned leaves pool. The count is exact: done and wait's adoption run
// under the same lock, so every Adopt precedes its Leave.
func (g *group) done(pool *carrier.AbandonPool) {
	g.mu.Lock()
	g.n--
	leave := g.owed > 0
	if leave {
		g.owed--
	}
	if g.n == 0 {
		close(g.idle)
	}
	g.mu.Unlock()
	if leave && pool != nil {
		pool.Leave()
	}
}

// wait waits until no member runs or deadline; then every member not yet
// counted is adopted by pool (nil: none, the members are rendr's own and
// always end). It reports whether every member exited.
func (g *group) wait(deadline time.Time, pool *carrier.AbandonPool) bool {
	g.mu.Lock()
	idle := g.idle
	g.mu.Unlock()
	if !isClosed(idle) {
		t := time.NewTimer(time.Until(deadline))
		select {
		case <-idle:
		case <-t.C:
		}
		t.Stop()
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.n == 0 {
		return true
	}
	if pool != nil {
		for range g.n - g.owed {
			pool.Adopt() // an atomic add: safe under this leaf lock
		}
		g.owed = g.n
	}
	return false
}

// running returns the members running (tests).
func (g *group) running() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.n
}

// goWatched runs f — an embedder call such as a conn's Close — on a new
// goroutine that already holds a membership of g (the caller added it),
// and counts that goroutine in pool when f is still running d later, also
// when nobody joins g then (D20: a full pool makes new carriers fail fast).
// The watch that counts it also ends its membership of g, so a later wait
// neither waits for it nor counts it again; it leaves pool when f returns.
// A wait that counted it first is settled by the watch's done (g's owed
// count makes that done leave pool once), so the goroutine is always
// counted exactly once.
func (g *group) goWatched(pool *carrier.AbandonPool, d time.Duration, f func()) {
	var state atomic.Int32 // 0 running, 1 returned in time, 2 counted by the watch
	t := time.AfterFunc(d, func() {
		if state.CompareAndSwap(0, 2) {
			pool.Adopt()
			g.done(pool)
		}
	})
	go func() {
		defer func() { // also on runtime.Goexit inside f (L51)
			if state.CompareAndSwap(0, 1) {
				t.Stop()
				g.done(pool)
				return
			}
			pool.Leave()
		}()
		f()
	}()
}
