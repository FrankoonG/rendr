package carrier

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Probe runs of the Peer health layer (design §7.8, plan §3.9). A run is
// one stretch of probing: Use or Hold starts it, the idle stop or Close
// ends it. Its goroutine owns one probe slot per factory — a redial
// cadence, at most one attempt and at most one probe carrier — and ends
// with a bounded wind-down that joins everything it started.

var (
	// errProbeStopped is the cancellation cause of probe attempts when their
	// run ends (idle stop or Close).
	errProbeStopped = errors.New("rendr: probing stopped")
	// errProbeGoexit: an embedder call ran runtime.Goexit on a probe
	// attempt's goroutine (L51); the attempt counts as failed.
	errProbeGoexit = errors.New("rendr: probe attempt ended by runtime.Goexit")
)

// healthRun is one run. Fields marked (mu) are guarded by Health.mu; acts
// belongs to the run goroutine.
type healthRun struct {
	h       *Health
	started time.Time
	ctx     context.Context // cancelled with errProbeStopped by the wind-down
	cancel  context.CancelCauseFunc
	bell    probeBell     // rung by the run's probe carriers, attempts and Hold releases
	stop    chan struct{} // closed by Close
	done    chan struct{} // closed when the goroutine exited (after its wind-down)
	first   chan struct{} // closed when every factory has first evidence, or when the run ends

	stopped     bool            // (mu) stop is closed
	firstDue    bool            // (mu) every factory has first evidence: the next publication closes first
	firstClosed bool            // (mu) first is closed
	ended       bool            // (mu) the wind-down began: late attempt results are discarded
	slots       []probeSlot     // (mu) one per factory
	live        []*Conn         // (mu) every Conn the run started or discarded and has not seen Done
	atts        []*probeAttempt // (mu) every attempt the run started whose goroutine was not seen to exit
	acts        []probeAction   // the run goroutine's queue of work done outside mu
}

// probeSlot is one factory's probe state within a run.
type probeSlot struct {
	// cad is the redial cadence, cap BackoffMax (plan §3.6). Its failure
	// count n (Fails) is not reset when a probe dial completes the PREFACE
	// exchange but only when the probe carrier it established held its
	// path for Probe.BackoffMax (endedLocked).
	cad     sched.Cadence
	conn    *Conn         // the started probe carrier; nil: none
	retired bool          // Retire was called on conn (the peer sent GOAWAY)
	att     *probeAttempt // the attempt in flight; nil: none
}

// probeAttempt is one probe dial (Establish with a PING first frame).
type probeAttempt struct {
	id    uint64    // its cadence attempt id
	start time.Time // when the cadence started it
	done  chan struct{}
	state atomic.Int32 // attRunning → attDone, or → attAbandoned by a wind-down that stopped waiting

	finished bool         // (mu) the result below is set
	est      *Established // (mu)
	err      error        // (mu)
}

// Attempt accounting states (the joiner's side of the abandoned-call rule).
const (
	attRunning int32 = iota
	attDone
	attAbandoned
)

// probeAction is work the run goroutine does after releasing Health.mu:
// Health.mu is a leaf, so conn methods that lock and goroutine starts
// never run under it.
type probeAction struct {
	op     uint8
	slot   int
	att    *probeAttempt
	conn   *Conn
	detail string
}

const (
	opAttempt uint8 = iota + 1 // start the attempt's goroutine
	opStart                    // start an established probe carrier
	opRetire                   // retire a probe carrier (peer GOAWAY)
	opKill                     // discard an unstarted carrier (a refused probe)
)

// probeBell is a cap-1 coalescing doorbell (carrier.Doorbell).
type probeBell chan struct{}

// Ring never blocks; a token left while the run is busy makes it run one
// more step.
func (b probeBell) Ring() {
	select {
	case b <- struct{}{}:
	default:
	}
}

// startRunLocked starts a run at now: fresh cadences (every first attempt
// is immediate), WaitFirst counting from now, the goroutine.
func (h *Health) startRunLocked(now time.Time) {
	ctx, cancel := context.WithCancelCause(context.Background())
	r := &healthRun{
		h:       h,
		started: now,
		ctx:     ctx,
		cancel:  cancel,
		bell:    make(probeBell, 1),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
		first:   make(chan struct{}),
		slots:   make([]probeSlot, len(h.fac)),
	}
	for i := range h.fac {
		h.fac[i].first = false
	}
	h.run = r
	h.runs = append(h.runs, r)
	h.publishLocked() // Probing
	go r.loop()
}

// stopLocked asks the run to end (Close).
func (r *healthRun) stopLocked() {
	if !r.stopped {
		r.stopped = true
		close(r.stop)
	}
}

func (r *healthRun) closeFirstLocked() {
	if !r.firstClosed {
		r.firstClosed = true
		close(r.first)
	}
}

// loop is the run goroutine: a step under Health.mu, the queued actions
// outside it, then a wait for the bell, the stop or the next timed event.
func (r *healthRun) loop() {
	h := r.h
	t := time.NewTimer(time.Hour)
	t.Stop()
	for {
		now := time.Now()
		h.mu.Lock()
		wake, end := r.stepLocked(now)
		h.mu.Unlock()
		if end != nil {
			r.windDown(end)
			return
		}
		r.perform()
		if !wake.IsZero() {
			t.Reset(wake.Sub(now))
		}
		select {
		case <-r.bell:
		case <-r.stop:
		case <-t.C:
		}
		t.Stop()
	}
}

// stepLocked reconciles the run at now: probe carriers that ended or got a
// GOAWAY, finished attempts, attempts due by their cadence, the idle stop.
// It queues conn work in r.acts and returns the next timed wake, or the
// end set once the run must stop (Close, or no Use, Hold or release for
// IdleStop while no session holds the Peer).
func (r *healthRun) stepLocked(now time.Time) (wake time.Time, end *runEnd) {
	h := r.h
	if h.closed || r.stopped {
		return time.Time{}, r.endLocked()
	}
	if h.holds == 0 {
		idle := h.lastUse.Add(h.p.IdleStop)
		if !now.Before(idle) {
			return time.Time{}, r.endLocked()
		}
		wake = idle
	}
	r.pruneLocked()
	changed := false
	for i := range r.slots {
		s := &r.slots[i]
		if c := s.conn; c != nil {
			if dead, cause, _, _ := c.Death(); dead {
				r.endedLocked(i, s, cause, now)
				changed = true
			} else if c.PeerGoAway() && !s.retired {
				// A probe carrier that received GOAWAY retires; its
				// replacement follows the cadence (a restarted passive has
				// a new instance, design §6.8).
				s.retired = true
				r.acts = append(r.acts, probeAction{op: opRetire, conn: c})
			}
		}
		if a := s.att; a != nil && a.finished {
			s.att = nil
			r.resultLocked(i, s, a, now)
			changed = true
		}
		if s.conn == nil && s.att == nil {
			if ok, at := s.cad.Ready(now); !ok {
				wake = earliest(wake, at)
			} else {
				a := &probeAttempt{id: s.cad.Start(now), start: now, done: make(chan struct{})}
				s.att = a
				r.atts = append(r.atts, a)
				h.fac[i].attempts++
				r.acts = append(r.acts, probeAction{op: opAttempt, slot: i, att: a})
				changed = true
			}
		}
	}
	if changed {
		h.publishLocked()
	}
	return wake, nil
}

// earliest returns the earlier of two times, ignoring zero values.
func earliest(a, b time.Time) time.Time {
	if a.IsZero() || (!b.IsZero() && b.Before(a)) {
		return b
	}
	return a
}

// endedLocked handles the end of slot i's probe carrier. A death (any
// cause but retired) marks the factory failed with its cause; a planned
// end (the peer's CLOSE, or our retirement after its GOAWAY) does not.
//
// The replacement (plan §3.6 applied to probe slots, design §7.7): a probe
// carrier that held its path — it lived at least Probe.BackoffMax from the
// start of the attempt that established it — is replaced at once and the
// slot's failure count n restarts at 0. A shorter-lived one counts as one
// more failure of the slot: the replacement starts at max(now, that start
// + Backoff(n)) and n grows. So a path that accepts probe carriers and
// then drops them is redialled like one that refuses them (the spacing
// grows to Probe.BackoffMax) instead of at dial speed, while the first
// replacement of a carrier that lived longer than Backoff(n) still starts
// at once. Plan §3.6 resets n at a completed PREFACE exchange (since §0.14
// B6 only at a session slot's first refusal or inside its recovery window);
// for probe slots that would loop on such a path, so a probe establishment
// leaves n alone (resultLocked).
func (r *healthRun) endedLocked(i int, s *probeSlot, cause Cause, now time.Time) {
	h := r.h
	f := &h.fac[i]
	if f.conn == s.conn {
		f.conn = nil
	}
	s.conn, s.retired = nil, false
	if cause.Death() {
		h.markLocked(i, cause.String(), now)
	}
	if !now.Before(s.cad.LastStart.Add(h.p.BackoffMax)) {
		s.cad.Fails = 0
		s.cad.Kick()
		return
	}
	next := s.cad.LastStart.Add(sched.Backoff(s.cad.Fails, h.p.BackoffMax, h.p.Rand()))
	if next.Before(now) {
		next = now
	}
	s.cad.NextAt, s.cad.Immediate = next, false
	s.cad.Fails++
}

// resultLocked applies a finished attempt of slot i (design §7.8): a PONG
// echoing the establishment PING is success (the establishment PONG itself
// is no sample, D26); a CLOSE answer (capacity: the passive's sessionless
// pool is full, plan §3.5), a GOAWAY answer, a refused PREFACE or any
// error is a probe failure: failed mark with its reason and a growing
// backoff, so a refusing passive is not redialled in a tight loop. A
// success clears a failed mark set before its attempt started, but keeps
// the slot's failure count until the carrier held its path for
// Probe.BackoffMax (endedLocked).
func (r *healthRun) resultLocked(i int, s *probeSlot, a *probeAttempt, now time.Time) {
	h := r.h
	f := &h.fac[i]
	u := h.p.Rand()
	if a.err != nil {
		s.cad.Finish(now, a.id, sched.OutcomeFailed, h.p.BackoffMax, u)
		h.markLocked(i, probeFailReason(a.err), now)
		return
	}
	c := a.est.Conn
	r.live = append(r.live, c)
	if a.est.Resp.Type != wire.TypePong {
		s.cad.Finish(now, a.id, sched.OutcomeFailed, h.p.BackoffMax, u)
		reason := probeRefusalReason(a.est)
		h.markLocked(i, reason, now)
		r.acts = append(r.acts, probeAction{op: opKill, conn: c, detail: "probe refused: " + reason})
		return
	}
	fails := s.cad.Fails
	s.cad.Finish(now, a.id, sched.OutcomeAttached, h.p.BackoffMax, u)
	s.cad.Fails = fails
	s.conn, s.retired = c, false
	f.conn = c
	f.agg.Reset()                               // a new incarnation starts Unknown (L23)
	f.pHead, f.pN, f.early = 0, 0, probeEarly{} // its PING ids restart: no record of another incarnation may match
	if f.failed && !a.start.Before(f.markAt) {
		h.clearLocked(i) // a successful probe dial after the mark (plan §3.9)
	}
	r.acts = append(r.acts, probeAction{op: opStart, conn: c})
}

// probeFailReason names a failed probe attempt for FactoryStatus.FailReason.
func probeFailReason(err error) string {
	var ee *EstablishError
	if !errors.As(err, &ee) {
		return CauseTransportError.String()
	}
	switch ee.Status {
	case wire.PrefaceCapacity:
		return "capacity"
	case wire.PrefaceGoingAway:
		return "going_away"
	case wire.PrefaceVersion:
		return "version"
	case wire.PrefaceFeature:
		return "feature"
	}
	return ee.Cause.String()
}

// probeRefusalReason names an established probe answered by CLOSE or GOAWAY.
func probeRefusalReason(est *Established) string {
	if est.Resp.Type == wire.TypeClose {
		if reason, err := wire.ParseClose(est.Payload); err == nil && reason == wire.CloseCapacity {
			return "capacity"
		}
		return "closed"
	}
	return "going_away"
}

// pruneLocked forgets conns whose Done closed and attempts whose goroutine
// exited (they need no join), so both lists stay bounded by the slots
// however often a probe reconnects (invariant 4).
func (r *healthRun) pruneLocked() {
	live := r.live[:0]
	for _, c := range r.live {
		select {
		case <-c.Done():
		default:
			live = append(live, c)
		}
	}
	clear(r.live[len(live):])
	r.live = live
	atts := r.atts[:0]
	for _, a := range r.atts {
		select {
		case <-a.done:
		default:
			atts = append(atts, a)
		}
	}
	clear(r.atts[len(atts):])
	r.atts = atts
}

// perform runs the queued actions outside Health.mu.
func (r *healthRun) perform() {
	for _, a := range r.acts {
		switch a.op {
		case opAttempt:
			go r.attempt(a.slot, a.att)
		case opStart:
			a.conn.Start(nil, r.bell, StartOptions{Probe: true, Observer: r.h.obs})
		case opRetire:
			a.conn.Retire(wire.CloseRetire)
		case opKill:
			a.conn.Kill(CauseLocalClose, a.detail)
		}
	}
	clear(r.acts)
	r.acts = r.acts[:0]
}

// attempt is the goroutine of one probe dial: Establish with a PING first
// frame (Establish allocates nothing it does not own: the CarrierID is
// released by it on failure and by the Conn's Done otherwise; it calls
// Hooks.DialStart itself, V8), then the result is posted to the run. A
// result that arrives after the run's wind-down began is discarded here:
// an established carrier is killed and joined before the attempt reports
// itself done, so the wind-down's join of the attempt covers it.
func (r *healthRun) attempt(i int, a *probeAttempt) {
	h := r.h
	posted := false
	defer func() {
		if !posted {
			// runtime.Goexit inside an embedder call during Establish (L51):
			// Establish closed its conn; the slot still needs a result.
			h.mu.Lock()
			if !r.ended {
				a.err, a.finished = errProbeGoexit, true
			}
			h.mu.Unlock()
			r.bell.Ring()
		}
		if !a.state.CompareAndSwap(attRunning, attDone) && h.env.Abandon != nil {
			h.env.Abandon.Leave() // the wind-down counted it as abandoned
		}
		close(a.done)
	}()
	id := h.env.IDs.Next()
	est, err := Establish(r.ctx, h.env, h.facs[i], id, wire.TypePing, nil, nil)
	h.mu.Lock()
	keep := !r.ended
	if keep {
		a.est, a.err, a.finished = est, err, true
	}
	h.mu.Unlock()
	posted = true
	if keep {
		r.bell.Ring()
		return
	}
	if est != nil {
		est.Conn.Kill(CauseLocalClose, "probing stopped")
		<-est.Conn.Done()
	}
}

// runEnd is what a run's wind-down must stop and join.
type runEnd struct {
	conns []*Conn         // every carrier the run started or discarded and has not seen Done
	kill  []*Conn         // unstarted carriers of finished attempts the run never applied
	atts  []*probeAttempt // attempts still in flight: joined within 2·AbandonWait, else abandoned
	tails []*probeAttempt // attempts that posted their result and are exiting: joined without a bound
}

// endLocked ends the run (Health.mu held): it detaches the run (later
// attempt results are discarded, the observer ignores its carriers),
// releases WaitFirst, publishes Probing = false unless another run is
// current, and returns what the wind-down must stop and join: every carrier
// and every attempt goroutine the run started that was not seen to end.
// An attempt that already posted its result runs only rendr code after
// that (a ring, a CAS, close(done)), so it is joined without a bound; one
// still in flight can no longer post and is joined within 2·AbandonWait.
func (r *healthRun) endLocked() *runEnd {
	h := r.h
	r.ended = true
	if h.run == r {
		h.run = nil
	}
	e := &runEnd{conns: r.live}
	r.live = nil
	for _, a := range r.atts {
		if a.finished {
			e.tails = append(e.tails, a)
		} else {
			e.atts = append(e.atts, a)
		}
	}
	r.atts = nil
	for i := range r.slots {
		s := &r.slots[i]
		if f := &h.fac[i]; s.conn != nil && f.conn == s.conn {
			f.conn = nil
		}
		if a := s.att; a != nil && a.finished && a.est != nil {
			e.kill = append(e.kill, a.est.Conn) // posted but never applied: never started
			e.conns = append(e.conns, a.est.Conn)
		}
		*s = probeSlot{}
	}
	r.closeFirstLocked()
	h.publishLocked()
	return e
}

// windDown stops and joins everything the run started (design §3.1, §6.8
// steps 4 and 7): attempts are cancelled; started probe carriers retire
// with CLOSE and are killed when their CLOSE is still unwritten after
// min(1 s, DeadMax); unstarted ones are killed; every carrier's Done is
// awaited (each is bounded by the carrier itself: a part stuck in embedder
// code is abandoned after AbandonWait). A cancelled attempt returns
// within AbandonWait unless its own goroutine is stuck in an embedder call:
// GuardedDial and Establish leave a stuck helper goroutine of theirs (the
// factory call, a hello writer) behind and count it in Env.Abandon
// themselves. So the wind-down counts an attempt only when it is still
// running 2·AbandonWait after its cancellation, until it returns, and no
// stuck call is ever counted twice. Every other attempt goroutine has
// exited when the wind-down ends. Then the run leaves Health.runs and its
// done closes.
func (r *healthRun) windDown(e *runEnd) {
	h := r.h
	tm := h.env.Timing.withDefaults()
	r.cancel(errProbeStopped)
	abandon := time.NewTimer(2 * tm.AbandonWait)
	defer abandon.Stop()
	kill := time.NewTimer(min(time.Second, tm.DeadMax))
	defer kill.Stop()
	for _, c := range e.kill {
		c.Kill(CauseLocalClose, "probing stopped")
	}
	for _, c := range e.conns {
		c.Retire(wire.CloseRetire) // a no-op on a dead carrier
	}
	killed := false
	for _, c := range e.conns {
		if !killed {
			select {
			case <-c.Done():
				continue
			case <-kill.C:
				killed = true
				for _, k := range e.conns {
					if !k.CloseSent() {
						k.Kill(CauseLocalClose, "probe CLOSE not written in time")
					}
				}
			}
		}
		<-c.Done()
	}
	gaveUp := false
	for _, a := range e.atts {
		if !gaveUp {
			select {
			case <-a.done:
				continue
			case <-abandon.C:
				gaveUp = true
			}
		}
		// Adopt before the CAS: the attempt's Leave (its own CAS failed)
		// then always follows this Adopt, so the pool never reads negative.
		if h.env.Abandon != nil {
			h.env.Abandon.Adopt()
			if !a.state.CompareAndSwap(attRunning, attAbandoned) {
				h.env.Abandon.Leave() // it finished meanwhile
			}
		}
	}
	for _, a := range e.tails {
		<-a.done
	}
	h.mu.Lock()
	if k := slices.Index(h.runs, r); k >= 0 {
		h.runs = slices.Delete(h.runs, k, k+1)
	}
	h.mu.Unlock()
	close(r.done)
}
