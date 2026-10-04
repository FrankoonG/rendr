package rendr

import (
	"context"
	"crypto/rand"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Runtime is one rendr instance: it owns its InstanceID, admission tables
// (handshake slots, session table and tombstones, sessionless carriers),
// the memory budget, the buffer pool, the abandoned-call pool, the event
// queue, its Listeners and Peers. All methods are safe for concurrent use.
type Runtime struct {
	id      InstanceID
	eff     effective            // immutable after construction
	ov      *testhooks.Overrides // a copy, for normalizeListen; nil in production
	cenv    carrier.Env          // immutable after construction
	abandon *carrier.AbandonPool // goroutines stuck in embedder code (L52)
	budget  *carrier.Budget      // MaxBufferedBytes accounting
	ev      *eventQueue          // nil without Config.OnEvent
	table   *sessionTable[*session.Session]
	hs      *hsTable
	slt     *slTable
	gateFn  carrier.Gate    // rt.gate, bound once
	ctx     context.Context // cancelled by Close: in-flight Dials withdraw
	cancel  context.CancelCauseFunc
	backlog atomic.Int64 // pending sessions across Listeners (Status.AcceptBacklog[0])
	closing atomic.Bool  // set under mu by Close; read lock-free on admission paths

	hsg  *group // handshake goroutines (accept loops and Handle start them)
	slg  *group // sessionless carriers' watchers
	dial *group // Peer.Dial calls inside session.Dial

	mu        sync.Mutex // a leaf (design §3.2)
	closed    chan struct{}
	adjust    []string // Status.ConfigAdjustments: Config first, then "Listen[i]."
	nlisten   int      // Listen calls so far (the i of "Listen[i].")
	listeners map[*Listener]struct{}
	peers     map[*Peer]struct{}
	sl        map[*carrier.Conn]struct{} // live sessionless carriers
	draining  []*session.Session         // ended sessions whose Done may still be open (joined by Close)
	pruneAt   int
}

// Join bounds of Runtime.Close (design §3.1, §6.8).
const (
	closeSlack   = 250 * time.Millisecond // beyond the sessions' own bound (Kill bound + AbandonWait)
	minPruneAt   = 64                     // draining list prune threshold floor
	maxFactories = wire.MaxSchedIDs       // carriers per Peer (MaxCarriersPerSession ≤ 16)
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
		table:     newSessionTable[*session.Session](eff.cfg.MaxSessions),
		hs:        newHSTable(eff.cfg.Handshake.MaxConcurrent),
		slt:       newSLTable(eff.cfg.Sessionless.PerInstance, eff.cfg.Sessionless.Total),
		hsg:       newGroup(),
		slg:       newGroup(),
		dial:      newGroup(),
		closed:    make(chan struct{}),
		adjust:    adj,
		listeners: make(map[*Listener]struct{}),
		peers:     make(map[*Peer]struct{}),
		sl:        make(map[*carrier.Conn]struct{}),
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
		Hooks:   eff.hooks,
	}
	rt.gateFn = rt.gate
	rt.ctx, rt.cancel = context.WithCancelCause(context.Background())
	rt.ev = newEventQueue(eff.cfg.OnEvent, eff.eventQueue, eff.hooks)
	return rt, nil
}

// InstanceID returns this Runtime's InstanceID.
func (rt *Runtime) InstanceID() InstanceID { return rt.id }

// NewPeer validates and deep-copies cfg: 1–16 carriers, every Name non-empty
// and unique, every Dial non-nil. A Peer with two or more carriers runs the
// health layer (probe carriers) while it is in use.
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
// pull source). cfg is normalized like Config; adjustments are appended to
// Status.ConfigAdjustments with the prefix "Listen[i].". When Listen fails
// the sources stay owned by the caller.
func (rt *Runtime) Listen(cfg ListenConfig) (*Listener, error) {
	srcs, err := listenSources(cfg.Sources)
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
	ln := newListener(rt, ncfg, srcs)
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
	rt.mu.Unlock()
	dropped, panics := rt.ev.counters()
	return Status{
		Instance:           rt.id,
		Sessions:           rt.table.counts(now),
		Handshakes:         rt.hs.len(),
		HandshakeEvictions: rt.hs.evicted(),
		AcceptBacklog:      [2]int{int(rt.backlog.Load()), 0},
		Sessionless:        rt.slt.len(),
		BufferedBytes:      rt.budget.Used(),
		Abandoned:          rt.abandon.Len(),
		EventsDropped:      dropped,
		CallbackPanics:     panics,
		ConfigAdjustments:  adj,
	}
}

// Close shuts the Runtime down (idempotent, bounded): new handshakes are
// answered PREFACE_ACK(GOING_AWAY); every Listener closes (pending sessions
// answered GOING_AWAY); every session sends RST(AbortGoingAway) and GOAWAY
// and ends locally with net.ErrClosed; every Peer stops probing; sessionless
// carriers get GOAWAY; then every goroutine is joined within about 2 s,
// stragglers stuck in embedder code are counted in Status.Abandoned. Later
// calls on the Runtime and its objects return net.ErrClosed.
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
	rt.mu.Unlock()
	rt.cancel(net.ErrClosed) // in-flight Dials withdraw (session.Dial returns within 100 ms)

	t0 := time.Now()
	wait := rt.eff.timing.AbandonWait
	killAt := t0.Add(min(time.Second, rt.eff.cfg.DeadMax))
	bound := killAt.Add(wait + closeSlack) // the sessions' own close bound (§4.7) plus slack
	joinBy := t0.Add(wait)                 // handshakes, accept loops, in-flight Dials

	// Step 2: every Listener (sources closed once, pending → GOING_AWAY).
	var refuse []*session.Session
	for _, ln := range lns {
		refuse = append(refuse, ln.shut()...)
	}
	for _, s := range refuse {
		s.RefusePending(wire.StatusGoingAway, 0)
	}
	// Step 3: every session.
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
	// Step 5: sessionless carriers; unfinished handshakes are closed.
	for _, c := range sl {
		c.GoAway()
	}
	for _, nc := range rt.hs.drain() {
		carrier.CloseConn(&rt.cenv, nc)
	}

	// Step 7 (W14: before the event queue). After the handshakes, accept
	// loops and in-flight Dials no session can appear any more; one that
	// a racing handshake or Dial created after the snapshot of step 3 saw
	// closing and shut it down itself (admitOpen, Peer.Dial), so the second
	// snapshot (live or ended) is only joined.
	for _, ln := range lns {
		ln.loops.wait(joinBy, rt.abandon)
	}
	rt.hsg.wait(joinBy, rt.abandon)
	rt.dial.wait(joinBy, nil)
	join := rt.table.live()
	rt.mu.Lock()
	join = append(join, rt.draining...)
	rt.mu.Unlock()

	if !rt.slg.wait(killAt, nil) {
		for _, c := range sl {
			if !c.CloseSent() {
				c.Kill(carrier.CauseLocalClose, "Runtime.Close: CLOSE not written within the close bound")
			}
		}
	}
	waitSessions(join, bound)
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

// waitSessions waits until every session's Done closed or deadline. A
// session that misses its own bound is not abandoned: rendr's own goroutines
// always end (design §6.8); Close only stops waiting.
func waitSessions(ss []*session.Session, deadline time.Time) {
	if len(ss) == 0 {
		return
	}
	t := time.NewTimer(time.Until(deadline))
	defer t.Stop()
	for _, s := range ss {
		select {
		case <-s.Done():
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

// noteEnded records an ended session until its Done closes, so that Close
// joins it even when it no longer has a table entry (a passive tombstone
// keeps no session; a dialer entry is removed; a failed Dial never had
// one). Sessions whose Done closed are pruned when the list doubled.
func (rt *Runtime) noteEnded(s *session.Session) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if isClosed(rt.closed) {
		return
	}
	rt.draining = append(rt.draining, s)
	if len(rt.draining) < rt.pruneAt {
		return
	}
	kept := rt.draining[:0]
	for _, x := range rt.draining {
		select {
		case <-x.Done():
		default:
			kept = append(kept, x)
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
// added after a wait that gave up (every group stops admitting members
// before it is joined: a closed Listener starts no handshake, a closing
// Runtime no Dial and no sessionless carrier).
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
