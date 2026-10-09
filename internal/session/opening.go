package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// The dialer side (design §6.6, §6.7, §7.1, §7.7): one slot per factory
// with its own redial cadence and at most one attempt at a time (L20,
// L22), the opening race of Dial, the attempt goroutines and the handling
// of their results. Every attempt runs carrier.Establish on its own
// goroutine and posts exactly one dialResult; results carry the slot's
// attempt id, so a result the slot no longer waits for is closed instead
// of attached (L21).

// healthSource is the session's view of the Peer health layer:
// *carrier.Health in production, a fake in the actor's tests. A nil
// healthSource is inert: no evidence (configuration order), no failed
// marks reported, no waiting.
type healthSource interface {
	Snapshot() *carrier.Snapshot
	Subscribe(b carrier.Doorbell) (cancel func())
	// MarkFailedAt dates a failed mark by the failure rather than by the
	// call (W4-MARKAT): markFailed calls it after the actor's step, so a
	// probe round trip of the factory between the failure and that call
	// still clears or prevents the mark.
	MarkFailedAt(i int, reason string, at time.Time)
	Succeeded(i int)
	Gauges() []*carrier.Gauge
	Hold() (release func())
}

var _ healthSource = (*carrier.Health)(nil)

// Dial outcome states (one CAS decides between success and withdrawal).
const (
	dialWaiting int32 = iota
	dialSucceeded
	dialFailed
	dialWithdrawn
)

// Attempt states (abandonment accounting at the session's end).
const (
	attemptRunning int32 = iota
	attemptFinished
	attemptAbandoned
)

var (
	errGoneAway      = errors.New("rendr: the peer instance went away")
	errNotBound      = errors.New("rendr: carrier reached another peer instance")
	errLateInstance  = errors.New("rendr: OPEN_ACK(OK) from an instance other than the bound one")
	errDialWithdrawn = errors.New("rendr: dial withdrawn")
	errAttemptExited = errors.New("rendr: dial attempt ended by runtime.Goexit in an embedder call")
)

// markPending is the failedVer of a local failed mark whose health-layer
// call has not run yet.
const markPending = ^uint64(0)

// rstWithdrawn is the RST(AbortWithdrawn) payload answering a late or
// foreign OPEN_ACK(OK) (C9, C25).
var rstWithdrawn = func() []byte {
	var p [wire.RstFixedLen]byte
	return p[:wire.PutRst(p[:], &wire.Rst{Code: wire.RstWithdrawn})]
}()

// dialer is the dialer part of the actor state.
type dialer struct {
	spec   DialSpec
	h      healthSource
	gauges []*carrier.Gauge // per factory (multi-factory Peers only)
	slots  []slot
	open   []byte // the OPEN payload, built once at Dial and sent by every attempt

	opened    bool      // the first OPEN_ACK(OK) bound the session
	openBy    time.Time // Dial start + Grace: ErrNoPath without an OPEN_ACK(OK)
	state     atomic.Int32
	result    chan error // capacity 1: the opening outcome for Dial
	last      atomic.Pointer[error]
	running   int       // attempts in flight
	abandonBy time.Time // end phase: attempts still running then are abandoned

	race   sched.Race // opening race and selector failover race (§6.6, §7.3)
	raceOn bool

	sel      sched.Selector
	selVer   uint64
	selWake  time.Time
	selAct   int // the active factory the last evaluation saw
	switchTo int // factory of a planned switch whose JOIN runs (-1: none)

	// failed holds the local failed marks: the only marks of an inert
	// health layer, and otherwise a mirror of a MarkFailed call until the
	// health layer's snapshots carry it. failedVer is the snapshot version
	// current right after that call (markPending before it ran): any
	// snapshot at least that new shows the mark or its later clearing by a
	// probe PONG, so the local mark yields to it (§7.8).
	failed    []bool
	failedVer []uint64
	selFailed []bool // the merged marks handed to the selector
	cands     []sched.Candidate
	rank      []int

	unsub   func()
	release func()
}

// slot is one factory of the session's snapshot.
type slot struct {
	f      carrier.Factory
	cad    sched.Cadence
	gen    uint32   // incarnations attached so far
	att    *attempt // the attempt in flight, if any
	member bool     // bond: this factory keeps a member
}

// attempt is one dial attempt in flight.
type attempt struct {
	slot   int
	id     uint64 // the slot's cadence attempt id
	cid    uint32 // the CarrierID (owned by Establish, V8)
	kind   wire.Type
	cancel context.CancelCauseFunc
	state  atomic.Int32
}

func newDialer(spec DialSpec, h healthSource) *dialer {
	d := &dialer{spec: spec, h: h, result: make(chan error, 1), switchTo: -1, selAct: -1}
	d.slots = make([]slot, len(spec.Factories))
	for i, f := range spec.Factories {
		f.Index = i
		d.slots[i].f = f
	}
	d.failed = make([]bool, len(spec.Factories))
	d.failedVer = make([]uint64, len(spec.Factories))
	d.selFailed = make([]bool, len(spec.Factories))
	d.sel = sched.NewSelector(spec.Params.Selector)
	if spec.Params.Kind == wire.KindDatagram {
		// Class-up (M2-D48): the selector compares kind classes with the
		// index-to-class mapping rankLocked uses.
		cl := make([]uint8, len(spec.Factories))
		for i := range spec.Factories {
			cl[i] = kindClass(spec.Params.Kind, &spec.Factories[i])
		}
		d.sel.SetClasses(cl)
	}
	return d
}

// lastErr returns the last carrier error of the opening phase.
func (d *dialer) lastErr() error {
	if p := d.last.Load(); p != nil {
		return *p
	}
	return nil
}

func (d *dialer) setLast(err error) { d.last.Store(&err) }

// wrapLast wraps the last carrier error into a Dial error (§9): err (a
// sentinel such as ErrNoPath, or ctx.Err()) and last both stay reachable by
// errors.Is and errors.As — errors.As still finds the
// *carrier.EstablishError —, except that the result never matches io.EOF
// or io.ErrUnexpectedEOF (design §0.14 B13, invariant 1): a carrier whose
// far end closed during the handshake failed as a carrier, and a Dial
// error must not read as the end of a stream.
func wrapLast(err, last error) error {
	if last == nil {
		return err
	}
	return fmt.Errorf("%w (last carrier error: %w)", err, &lastCarrierError{last})
}

// lastCarrierError is the last carrier error inside a Dial error
// (wrapLast). It has the wrapped error's text and forwards errors.As and
// errors.Is to it, but answers errors.Is false for io.EOF and
// io.ErrUnexpectedEOF; it has no Unwrap method, so errors.Is cannot reach
// them past it.
type lastCarrierError struct{ err error }

func (e *lastCarrierError) Error() string { return e.err.Error() }

// Is matches target in the wrapped error's tree unless target is io.EOF or
// io.ErrUnexpectedEOF.
func (e *lastCarrierError) Is(target error) bool {
	return target != io.EOF && target != io.ErrUnexpectedEOF && errors.Is(e.err, target)
}

// As finds the first error in the wrapped error's tree that matches target.
func (e *lastCarrierError) As(target any) bool { return errors.As(e.err, target) }

// gauge returns factory i's self-load gauge (nil without a health layer).
func (d *dialer) gauge(i int) *carrier.Gauge {
	if i < len(d.gauges) {
		return d.gauges[i]
	}
	return nil
}

// laneGauge returns the self-load gauge a carrier of kind k of factory i
// starts with: a datagram carrier gets none (nothing is submitted on it,
// M2-D26; a packet selector on datagram carriers has no self-load gauge,
// R1-33); a stream carrier keeps M1's — also a packet session's, where
// DGRAM bytes are DATA.
func (a *actor) laneGauge(k wire.CarrierKind, i int) *carrier.Gauge {
	if k == wire.KindDatagram {
		return nil
	}
	return a.d.gauge(i)
}

// openPayload encodes the OPEN every attempt of this session sends. A
// packet session's OPEN has kind 2, its MaxPayload offer in pmtu and a
// window of 0, which Establish replaces by each datagram attempt's cmtu
// offer (M2-D11, §A3.5; a stream carrier keeps 0).
func openPayload(s *Session, window uint32) []byte {
	retain := s.p.Retain
	if retain <= 0 {
		retain = orDefault(s.p.Grace, defGrace)
	}
	ms := min(retain.Milliseconds(), 1<<32-1)
	o := wire.Open{SID: s.id, Kind: wire.KindStream, Mode: uint8(s.p.Mode), RetainMs: uint32(ms), Window: window, Metadata: s.meta}
	if s.pk != nil {
		o.Kind, o.Window, o.PMTU = wire.KindDatagram, 0, uint16(s.pktOffer())
	}
	p := make([]byte, wire.OpenFixedLen+len(s.meta))
	return p[:wire.PutOpen(p, &o)]
}

// markFailed sets factory i's failed mark for a failure at at (a carrier's
// death time, or the step's now): a health-layer call after the lock is
// released, dated by at (MarkFailedAt), mirrored by a local mark so that a
// race ranked in the same step already ranks the factory last (§7.3). The
// local mark yields to the health layer once a snapshot published after
// that call is seen (failedLocked), whatever its mark says by then: the
// health layer clears a mark at the next successful probe PONG (§7.8), or
// does not set it when a probe round trip already followed the failure,
// which a snapshot the actor never read could not tell it.
func (a *actor) markFailed(i int, reason string, at time.Time) {
	d := a.d
	d.failed[i] = true
	if h := d.h; h != nil {
		d.failedVer[i] = markPending
		a.later = append(a.later, func() {
			h.MarkFailedAt(i, reason, at)
			v := uint64(0)
			if sn := h.Snapshot(); sn != nil {
				v = sn.Version
			}
			if d.failed[i] && d.failedVer[i] == markPending { // runs on the actor goroutine
				d.failedVer[i] = v
			}
		})
	}
}

// succeeded clears factory i's failed mark: a PREFACE exchange completed
// on it (plan §3.6).
func (a *actor) succeeded(i int) {
	d := a.d
	d.failed[i] = false
	if h := d.h; h != nil {
		a.later = append(a.later, func() { h.Succeeded(i) })
	}
}

// failedLocked reports factory i's failed mark at snapshot snap (nil:
// none): the health layer's mark once snap is at least as new as the
// version recorded after the local mark's MarkFailed call (the local mark
// is dropped then), else the local mark too.
func (a *actor) failedLocked(snap *carrier.Snapshot, i int) bool {
	d := a.d
	if snap == nil {
		return d.failed[i]
	}
	if d.failed[i] && d.failedVer[i] != markPending && snap.Version >= d.failedVer[i] {
		d.failed[i] = false // the health layer's snapshots carry the mark (or its clearing) now
	}
	return d.failed[i] || (i < len(snap.Failed) && snap.Failed[i])
}

// noteGoAway records an instance that answered GOING_AWAY or sent GOAWAY
// (the Peer never OPENs to it again, D21). The note is an answer: it
// reaches the Peer before Dial's result, so a Dial retried at once cannot
// OPEN to that instance again.
func (a *actor) noteGoAway(inst [16]byte) {
	if f := a.d.spec.NoteGoAway; f != nil && inst != ([16]byte{}) {
		a.answer(func() { f(inst) })
	}
}

// rankLocked ranks the factories at now (§7.8): the health snapshot
// classified at now (configuration order when the health layer is inert)
// with the failed marks — the snapshot's, and the local ones it does not
// show yet (failedLocked). Only the factories the session may dial are
// ranked (DialSpec.Eligible, M2-D46; integration 1 D6): the others never
// get a race, bond or redial slot. A packet session's datagram factories
// rank before its stream factories (Candidate.Class, M2-D47).
func (a *actor) rankLocked(now time.Time) []int {
	d := a.d
	var snap *carrier.Snapshot
	if d.h != nil {
		snap = d.h.Snapshot()
	}
	d.cands = d.cands[:0]
	for i := range d.slots {
		if !d.spec.eligible(i) {
			continue
		}
		c := sched.Candidate{Index: i, Failed: a.failedLocked(snap, i), Class: kindClass(a.s.p.Kind, &d.slots[i].f)}
		if snap != nil && i < len(snap.Sum) {
			c.Ev = snap.Evidence(i, now)
		}
		d.cands = append(d.cands, c)
	}
	d.rank = sched.Rank(d.cands, d.rank)
	return d.rank
}

// startRaceLocked starts a staggered race over the current ranking (the
// opening phase, or a selector that lost its active lane without a
// fallback). The dead factory ranks last (failed) but stays a candidate.
//
// The opening race of a packet session skips the datagram factories whose
// frame budget cannot carry the OPEN (M2-D52); they still JOIN.
func (a *actor) startRaceLocked(now time.Time) {
	d := a.d
	order := a.rankLocked(now)
	if !d.opened && a.s.pk != nil {
		k := 0
		for _, i := range order {
			if openFits(&d.slots[i].f, len(a.s.meta)) {
				order[k] = i
				k++
			}
		}
		order = order[:k]
	}
	d.race = sched.NewRace(order, orDefault(a.s.p.JoinStagger, defJoinStagger), now)
	d.raceOn = true
}

// openOverhead is what an OPEN costs in a datagram besides its metadata:
// PREFACE, frame header and trailer, REL header and the OPEN's fixed part
// (M2-D52: a datagram factory can carry an OPEN iff 99 + metadata ≤ MTU).
const openOverhead = wire.PrefaceLen + wire.FrameOverhead + wire.RelHeadLen + wire.OpenFixedLen

// openFits reports whether factory f can carry a packet session's OPEN with
// meta bytes of metadata: every stream factory; a datagram factory whose
// frame budget holds it (M2-D52).
func openFits(f *carrier.Factory, meta int) bool {
	return f.Kind != wire.KindDatagram || openOverhead+meta <= f.MTU
}

// raceLocked starts the race's attempts: the first ready candidate at
// once, the next whenever no attempt attached within JoinStagger, while
// fewer than MaxCarriers attempts are outstanding (P20).
func (a *actor) raceLocked(now time.Time) {
	d := a.d
	kind := wire.TypeJoin
	if !d.opened {
		kind = wire.TypeOpen
	}
	ready := func(i int) (bool, time.Time) { return d.slots[i].cad.Ready(now) }
	for d.running < a.maxCarriers() {
		i, start, wake := d.race.Next(now, d.running, ready)
		if !start {
			a.want(wake)
			return
		}
		a.startAttemptLocked(now, i, kind)
	}
}

// dialActLocked runs the dialer's policy for a step: the opening phase, or
// the selector's failover race and quality policy, or bond membership —
// except while the session waits only for the peer's DONE (doneWaitLocked).
func (a *actor) dialActLocked(now time.Time) {
	d := a.d
	switch {
	case !d.opened:
		a.openingLocked(now)
	case a.doneWaitLocked():
	case a.s.p.Mode.members(): // bond and race (M3-D29)
		a.bondSlotsLocked(now)
	default:
		a.selectorLocked(now)
	}
}

// doneWaitLocked reports that no new attempt may start (design §0.13 A2,
// amending X3): our DONE was sent, the peer's is outstanding, and a lane is
// still alive or an ended lane's reader is still pending
// (awaitReaderLocked). Everything of ours was acknowledged, so a carrier
// can only bring the peer's DONE, which any live lane brings as well — and
// our own DONE goes out again on a survivor with every re-ACK. A peer that
// ended cleanly retires its carriers right after its DONE, so the CLOSE on
// one lane can precede the DONE on another: redialling the retired member
// would only race the clean end. Once no lane is alive and no reader is
// pending, the no-path episode starts and the slots redial as before (a
// JOIN answered UNKNOWN_SESSION after our DONE is a clean end, D4).
func (a *actor) doneWaitLocked() bool {
	st := &a.s.st
	return st.doneSent && !st.peerDone && (a.hasAliveLocked() || a.readersPendingLocked())
}

// openingLocked runs Dial's opening phase (§6.6) until the first
// OPEN_ACK(OK), a terminal answer, the grace, or the withdrawal.
func (a *actor) openingLocked(now time.Time) {
	d := a.d
	if d.state.Load() == dialWithdrawn {
		a.terminateLocked(now, errDialWithdrawn, nil, false)
		return
	}
	if !now.Before(d.openBy) {
		a.failOpeningLocked(now, wrapLast(ErrNoPath, d.lastErr()))
		return
	}
	a.want(d.openBy)
	if !d.raceOn {
		a.startRaceLocked(now)
	}
	a.raceLocked(now)
}

// failOpeningLocked ends the opening phase with a terminal error for Dial
// (unless Dial was already withdrawn) and withdraws every other attempt
// (C25).
func (a *actor) failOpeningLocked(now time.Time, err error) {
	d := a.d
	if d.state.CompareAndSwap(dialWaiting, dialFailed) {
		ch := d.result
		a.answer(func() { ch <- err })
	}
	a.terminateLocked(now, err, nil, false)
}

// onWithdrawLocked: Dial's ctx ended first (its CAS to withdrawn won).
func (a *actor) onWithdrawLocked(now time.Time) {
	if a.d != nil && !a.d.opened {
		a.terminateLocked(now, errDialWithdrawn, nil, false)
	}
}

// startAttemptLocked starts one attempt on factory i: an OPEN (opening
// phase) or a JOIN carrying rxNext = rRead (§6.7).
func (a *actor) startAttemptLocked(now time.Time, i int, kind wire.Type) {
	s := a.s
	d := a.d
	sl := &d.slots[i]
	payload := d.open
	if kind == wire.TypeJoin {
		rx := s.st.rRead
		if s.pk != nil {
			rx = 0 // the cmtu offer: Establish writes a datagram attempt's (M2-D11)
		}
		var j [wire.JoinLen]byte
		n := wire.PutJoin(j[:], &wire.Join{SID: s.id, Mode: uint8(s.p.Mode), RxNext: rx})
		payload = j[:n]
	}
	base := context.Background()
	if f := d.spec.AttemptContext; f != nil {
		base = f(base)
	}
	ctx, cancel := context.WithCancelCause(base)
	at := &attempt{slot: i, id: sl.cad.Start(now), cid: s.env.Carrier.IDs.Next(), kind: kind, cancel: cancel}
	sl.att = at
	d.running++
	a.dirty = true // Status shows the attempt as a joining carrier (L22)
	go a.runAttempt(ctx, at, sl.f, payload)
}

// runAttempt is a dial-attempt goroutine: Establish, Hooks.DialResult,
// then exactly one post of the result. A result the actor can no longer
// take (it exited) is closed here; an attempt the actor abandoned at its
// end leaves the abandoned-call pool when it finally returns.
//
// An embedder conn call inside Establish may run runtime.Goexit on this
// goroutine (L51); Establish then releases the CarrierID and closes the
// conn itself, and this goroutine's deferred cleanup reports the attempt
// as failed, so the slot's cadence, the attempt count and the abandoned
// pool stay exact and the slot redials.
func (a *actor) runAttempt(ctx context.Context, at *attempt, f carrier.Factory, payload []byte) {
	s := a.s
	posted := false
	defer func() {
		if !posted {
			a.postResult(at, nil, errAttemptExited)
		}
		if !at.state.CompareAndSwap(attemptRunning, attemptFinished) {
			if p := s.env.Carrier.Abandon; p != nil {
				p.Leave()
			}
		}
	}()
	check := a.openCheck
	if at.kind == wire.TypeJoin {
		check = a.joinCheck
	}
	var est *carrier.Established
	var err error
	if p := a.d.spec.Pool; p != nil {
		// Through the Peer's pool (M3-D16): a live trunk's new view, a
		// coalesced wait or a dial of its own. A JOIN uses only trunks of
		// the bound instance (M3-D17; s.peer is final once a JOIN starts).
		var inst [16]byte
		if at.kind == wire.TypeJoin {
			inst = s.peer
		}
		est, err = p.Attempt(ctx, f.Index, at.cid, at.kind, payload, check, inst, s.poolKey())
	} else {
		est, err = carrier.Establish(ctx, s.env.Carrier, f, at.cid, at.kind, payload, check)
	}
	posted = true
	a.postResult(at, est, err)
}

// postResult runs Hooks.DialResult and posts the attempt's one result; a
// result the actor can no longer take (it exited) is closed here.
func (a *actor) postResult(at *attempt, est *carrier.Established, err error) {
	s := a.s
	if h := s.env.Hooks; h != nil && h.DialResult != nil {
		h.DialResult(at.cid)
	}
	if !s.mb.post(&dialResult{slot: at.slot, attempt: at.id, est: est, err: err}) {
		discardEst(est, at.kind)
	}
}

// openCheck rejects, per PREFACE_ACK, instances in the Peer's gone-away
// set and, once the session is bound, every instance other than the bound
// one (C9): Establish then answers an OPEN it wrote with RST(withdrawn).
func (a *actor) openCheck(ack *wire.PrefaceAck) error {
	if f := a.d.spec.GoneAway; f != nil && f(ack.Instance) {
		return errGoneAway
	}
	if a.s.bound.Load() && ack.Instance != a.s.peer {
		return errNotBound
	}
	return nil
}

// joinCheck accepts only the bound instance (§6.7).
func (a *actor) joinCheck(ack *wire.PrefaceAck) error {
	if ack.Instance != a.s.peer {
		return errNotBound
	}
	return nil
}

// discardEst closes the carrier of a result nobody attaches: a late
// OPEN_ACK(OK) of a session that never opened gets RST(AbortWithdrawn), so
// the passive does not keep a session for it (C25); any other is killed.
func discardEst(est *carrier.Established, kind wire.Type) {
	if est == nil {
		return
	}
	if kind == wire.TypeOpen && est.Resp.Type == wire.TypeOpenAck {
		if oa, err := wire.ParseOpenAck(est.Payload); err == nil && oa.Status == wire.StatusOK {
			withdrawConn(est.Conn)
			return
		}
	}
	est.Conn.Kill(carrier.CauseLocalClose, "dial result not attached")
}

// withdrawConn answers an OPEN_ACK(OK) nobody keeps with RST(AbortWithdrawn)
// on the unstarted carrier and closes it (V8). On a view of a started MUX
// trunk (a fast-path result) the RST is the view's last frame and DETACH
// follows; the trunk and its other views are untouched (R1-2, R1-5 rule
// 1). A fresh trunk's view 1 keeps M2's path: its waiters retry (M3-D19).
func withdrawConn(c *carrier.Conn) {
	c.WriteAndClose(wire.TypeRst, 0, c.Handle(), rstWithdrawn, time.Time{})
}

// discardEst is discardEst for a result the running actor drops: the
// carrier joins the exit join (§6.8).
func (a *actor) discardEst(est *carrier.Established, kind wire.Type) {
	if est != nil {
		discardEst(est, kind)
		a.dropConn(est.Conn)
	}
}

// killEst kills the carrier of a result the actor does not attach (a
// refusal, a mismatch, a violation) and hands it to the exit join. On a
// view of a started MUX trunk a refusal or a mismatch ends the view only
// (Kill: DETACH(ended), R1-2); a protocol violation kills the trunk and so
// every view on it (KillTrunk, M3-D15). On a dedicated or unstarted
// carrier the two are M2's Kill.
func (a *actor) killEst(est *carrier.Established, cause carrier.Cause, detail string) {
	if cause == carrier.CauseProtocolViolation {
		est.Conn.KillTrunk(cause, detail)
	} else {
		est.Conn.Kill(cause, detail)
	}
	a.dropConn(est.Conn)
}

// viewDetached reports a result whose view of a MUX trunk the peer
// detached before the attach (R1-9, attached-pending × the peer's DETACH).
// A dedicated carrier keeps M2's reading: a peer CLOSE that arrives before
// the attach is handled by the attached lane as any peer CLOSE.
func viewDetached(c *carrier.Conn) bool { return c.Mux() && c.PeerClosed() }

// poolKey identifies the session to the Peer's pool (M3-D17, R1-6: at most
// one unreaped view of a session per trunk): the session's address, which
// stays unique while any of its views lives (each view's endpoint
// references the session).
func (s *Session) poolKey() uintptr { return uintptr(unsafe.Pointer(s)) }

// viewBudget is the budget side of a lane's carrier for the packet checks
// of a response (pktOpenAckLocked, pktJoinAckLocked): the carrier itself,
// except that a view opened on a started MUX trunk (handle above 1) keeps
// the trunk's negotiated budget — SetBudget is never called after Start
// (M2-D50, M3-D24) — so its answer is only validated against it.
type viewBudget struct{ *carrier.Conn }

// SetBudget fixes an unstarted carrier's budget; a no-op on a view of a
// started trunk.
func (v viewBudget) SetBudget(cmtu int) {
	if v.Handle() == wire.SessionHandle {
		v.Conn.SetBudget(cmtu)
	}
}

// cancelAttemptsLocked withdraws every attempt in flight (C25): their
// contexts end with carrier.ErrWithdrawn (Establish sends RST(withdrawn)
// where an OPEN was written) and the end phase abandons the ones still
// running 2·AbandonWait later. A cancelled attempt returns within
// AbandonWait unless its own goroutine is stuck in an embedder call:
// GuardedDial and Establish leave a stuck helper goroutine of theirs (the
// factory call, the hello writer) behind and count it in the abandoned
// pool themselves — GuardedDial dialGrace (≤ AbandonWait) after the
// cancellation, before the attempt returns; Establish's hello writer
// AbandonWait after it. Abandoning the attempt at that last instant would
// count one stuck call twice, so the actor waits twice as long (as the
// health layer's wind-down does).
func (a *actor) cancelAttemptsLocked(now time.Time) {
	d := a.d
	d.raceOn = false
	d.abandonBy = now.Add(2 * a.abandonWait())
	for i := range d.slots {
		if at := d.slots[i].att; at != nil {
			at.cancel(carrier.ErrWithdrawn)
		}
	}
	if d.running > 0 {
		a.want(d.abandonBy)
	}
}

// abandonAttemptsLocked counts the attempts still running at abandonBy in
// the abandoned-call pool (they are stuck in embedder code; L52) and stops
// waiting for them.
func (a *actor) abandonAttemptsLocked() {
	d := a.d
	for i := range d.slots {
		sl := &d.slots[i]
		at := sl.att
		if at == nil {
			continue
		}
		if at.state.CompareAndSwap(attemptRunning, attemptAbandoned) {
			if p := a.s.env.Carrier.Abandon; p != nil {
				p.Adopt()
			}
			sl.att = nil
			d.running--
			a.dirty = true
		}
	}
}

// onDialResultLocked handles one attempt's result.
func (a *actor) onDialResultLocked(now time.Time, r *dialResult) {
	d := a.d
	if d == nil || r.slot < 0 || r.slot >= len(d.slots) {
		a.discardEst(r.est, wire.TypeJoin)
		return
	}
	// A result nobody attaches is withdrawn with an RST only while the
	// session never opened (an opened session is never reset that way).
	kind := wire.TypeJoin
	if !d.opened {
		kind = wire.TypeOpen
	}
	sl := &d.slots[r.slot]
	at := sl.att
	if at == nil || at.id != r.attempt {
		a.discardEst(r.est, kind) // abandoned: no longer waited for (L21)
		return
	}
	sl.att = nil
	d.running--
	at.cancel(context.Canceled)
	a.dirty = true
	if a.ending {
		a.discardEst(r.est, kind)
		return
	}
	if r.err != nil {
		a.attemptFailedLocked(now, r.slot, at, r.err)
		return
	}
	a.attemptAnsweredLocked(now, r.slot, at, r.est)
}

// finish records an attempt's cadence outcome. A refusal while the session
// has no live carrier — the opening phase or a no-path episode, both bounded
// by the grace — keeps the first backoff step whatever the slot's count:
// the passive may be refusing only until it drops a carrier the dialer has
// already lost (design D27), and the failover race dials a slot without a
// Kick, so the slot's recovery window does not cover it. Refusals beside a
// live carrier back off to the cap (§0.14 B6).
func (a *actor) finish(now time.Time, i int, at *attempt, o sched.Outcome) {
	limit := orDefault(a.s.p.BackoffMax, defBackoffMax)
	if o == sched.OutcomeRefused && !a.hasAliveLocked() {
		limit = sched.BackoffBase
	}
	a.d.slots[i].cad.Finish(now, at.id, o, limit, a.rand())
}

// attemptFailedLocked handles an attempt whose Establish failed (§6.6,
// §6.7): version and capacity answers are terminal for Dial; a refused
// instance and any answer after the PREFACE exchange count as Refused
// (failed mark cleared; the backoff resets at the slot's first refusal and
// inside its recovery window, and keeps its first step while no carrier
// lives: sched.Cadence, finish); everything else is Failed (failed mark,
// backoff). An open session ends when the bound instance answers
// GOING_AWAY (*AbortError) or a JOIN reached a restarted peer
// (ErrSessionLost) — cleanly (io.EOF) once our DONE was sent (doneOr).
func (a *actor) attemptFailedLocked(now time.Time, i int, at *attempt, err error) {
	s := a.s
	d := a.d
	d.setLast(err)
	var e *carrier.EstablishError
	errors.As(err, &e)
	outcome := sched.OutcomeFailed
	if e != nil && e.PrefaceOK {
		outcome = sched.OutcomeRefused
	}
	var terminal, end error
	switch {
	case e == nil:
	case e.Status == wire.PrefaceVersion || e.Status == wire.PrefaceFeature:
		terminal = fmt.Errorf("%w: %w", ErrVersion, err)
	case e.Status == wire.PrefaceGoingAway:
		a.noteGoAway(e.Instance)
		terminal = fmt.Errorf("%w: %w", ErrCapacity, err)
		if d.opened && e.Instance == s.peer {
			end = a.doneOr(&AbortError{Code: AbortGoingAway, Msg: "peer going away", Remote: true})
		}
	case e.Status == wire.PrefaceCapacity:
		terminal = fmt.Errorf("%w: %w", ErrCapacity, err)
		outcome = sched.OutcomeRefused
	case e.Cause == carrier.CauseInstanceMismatch:
		outcome = sched.OutcomeRefused
		if at.kind == wire.TypeJoin && !a.hasAliveLocked() {
			// Peer restart (plan §3.4): a redialled carrier reached another
			// instance while the session has no live carrier.
			end = a.doneOr(fmt.Errorf("%w: %w", ErrSessionLost, err))
		}
	}
	a.finish(now, i, at, outcome)
	if outcome == sched.OutcomeFailed {
		reason := "dial"
		if e != nil {
			reason = e.Cause.String()
		}
		a.markFailed(i, reason, now)
	} else if e != nil && e.PrefaceOK {
		a.succeeded(i)
	}
	a.switchFailedLocked(now, i)
	switch {
	case !d.opened && terminal != nil:
		a.failOpeningLocked(now, terminal)
	case end != nil:
		a.terminateLocked(now, end, nil, false)
	}
}

// switchFailedLocked: a planned switch's JOIN did not attach; nothing
// changed and every dwell restarts (W10).
func (a *actor) switchFailedLocked(now time.Time, i int) {
	if d := a.d; i == d.switchTo {
		d.switchTo = -1
		d.sel.Switched(now, false)
	}
}

// attemptAnsweredLocked handles an attempt whose handshake completed with
// a response frame. A GOAWAY answer from the bound instance ends an open
// session like a GOAWAY on a lane (peerGoAwayLocked): *AbortError, or
// io.EOF once our DONE was sent (doneOr).
func (a *actor) attemptAnsweredLocked(now time.Time, i int, at *attempt, est *carrier.Established) {
	s := a.s
	d := a.d
	switch est.Resp.Type {
	case wire.TypeOpenAck:
		oa, _ := wire.ParseOpenAck(est.Payload) // validated by Establish
		if oa.Status == wire.StatusOK {
			a.openOKLocked(now, i, at, est, oa.Window)
		} else {
			a.openRefusedLocked(now, i, at, est, &oa)
		}
	case wire.TypeJoinAck:
		ja, _ := wire.ParseJoinAck(est.Payload)
		if ja.Status == wire.StatusOK {
			a.joinOKLocked(now, i, at, est, ja.RxNext)
		} else {
			a.joinRefusedLocked(now, i, at, est, ja.Status)
		}
	case wire.TypeGoAway:
		a.killEst(est, carrier.CauseGoAway, "GOAWAY answered the first frame")
		a.noteGoAway(est.Ack.Instance)
		a.finish(now, i, at, sched.OutcomeRefused)
		a.switchFailedLocked(now, i)
		switch {
		case !d.opened:
			a.failOpeningLocked(now, fmt.Errorf("%w: GOAWAY", ErrCapacity))
		case est.Ack.Instance == s.peer:
			a.terminateLocked(now, a.doneOr(&AbortError{Code: AbortGoingAway, Msg: "peer going away", Remote: true}), nil, false)
		}
	default: // CLOSE: the carrier was refused
		a.killEst(est, carrier.CauseRetired, "CLOSE answered the first frame")
		a.finish(now, i, at, sched.OutcomeRefused)
		a.switchFailedLocked(now, i)
	}
}

// openOKLocked handles OPEN_ACK(OK): the first one binds the session to
// its instance and opens it; a later one is kept only from the bound
// instance (C9), as a bond member or a retired selector race loser. A
// packet session checks each carrier's packet values first (§A3.5, R1-5):
// the first OPEN_ACK fixes MaxPayload, every carrier gets its own budget.
func (a *actor) openOKLocked(now time.Time, i int, at *attempt, est *carrier.Established, window uint32) {
	s := a.s
	d := a.d
	if dead, _, _, _ := est.Conn.Death(); dead || viewDetached(est.Conn) {
		// Ended before the attach — also a view whose peer detached it
		// while it was attached-pending (R1-9): a carrier refusal, no
		// cadence failure, no lane.
		a.dropConn(est.Conn)
		a.finish(now, i, at, sched.OutcomeRefused)
		return
	}
	inst := est.Ack.Instance
	if s.pk != nil && (!d.opened || inst == s.peer) {
		if err := s.pktOpenAckLocked(viewBudget{est.Conn}, window, !d.opened); err != nil {
			a.pktBadAnswerLocked(now, i, at, est, err)
			return
		}
	}
	if !d.opened {
		if !d.state.CompareAndSwap(dialWaiting, dialSucceeded) {
			// Dial's ctx ended first: withdraw (C25).
			withdrawConn(est.Conn)
			a.dropConn(est.Conn)
			a.finish(now, i, at, sched.OutcomeRefused)
			a.terminateLocked(now, errDialWithdrawn, nil, false)
			return
		}
		d.opened, a.opened = true, true
		a.openedAt = now
		d.raceOn = false
		s.peer = inst
		s.bound.Store(true)
		s.peerWindowLocked(window)
		s.ctl.state = StateOpen
		ch := d.result
		a.answer(func() { ch <- nil })
		if s.p.Mode.members() {
			a.chooseMembersLocked(now, i)
		}
		a.attachLocked(now, i, at, est)
		return
	}
	if inst != s.peer {
		// A restarted peer opened a session of its own: withdraw it; it is
		// never a member (one byte stream is never split, plan §3.4).
		withdrawConn(est.Conn)
		a.dropConn(est.Conn)
		d.setLast(errLateInstance)
		a.finish(now, i, at, sched.OutcomeRefused)
		return
	}
	a.attachLocked(now, i, at, est)
}

// openRefusedLocked handles a non-OK OPEN_ACK: terminal for Dial except
// CAPACITY CodeCarriers, which refuses one carrier of a pending session the
// opening race filled (P20, C16): that attempt backs off and the race
// continues. After the session opened, a refusal only ends the attempt.
func (a *actor) openRefusedLocked(now time.Time, i int, at *attempt, est *carrier.Established, oa *wire.OpenAck) {
	d := a.d
	a.killEst(est, carrier.CauseLocalClose, "OPEN refused")
	a.finish(now, i, at, sched.OutcomeRefused)
	a.succeeded(i)
	if d.opened {
		return
	}
	var terminal error
	switch oa.Status {
	case wire.StatusCapacity:
		if oa.Code == wire.CodeCarriers {
			d.setLast(fmt.Errorf("%w: OPEN_ACK CAPACITY (carrier limit)", ErrCapacity))
			return
		}
		terminal = fmt.Errorf("%w: OPEN_ACK CAPACITY (code %d)", ErrCapacity, oa.Code)
	case wire.StatusRejected:
		terminal = &RejectError{Code: oa.Code, Msg: string(oa.Msg)}
	case wire.StatusBadRequest:
		if oa.Code == wire.CodeMetadataSize {
			terminal = ErrMetadataTooLarge
		} else {
			terminal = fmt.Errorf("%w: OPEN_ACK BAD_REQUEST (code %d)", ErrProtocol, oa.Code)
		}
	case wire.StatusUnknownSession:
		terminal = fmt.Errorf("%w: OPEN_ACK UNKNOWN_SESSION", ErrSessionLost)
	case wire.StatusGoingAway:
		a.noteGoAway(est.Ack.Instance)
		terminal = fmt.Errorf("%w: OPEN_ACK GOING_AWAY", ErrCapacity)
	default:
		terminal = fmt.Errorf("%w: OPEN_ACK status %d", ErrProtocol, oa.Status)
	}
	a.failOpeningLocked(now, terminal)
}

// joinOKLocked handles JOIN_ACK(OK): its rxNext trims our retransmissions
// (beyond what was sent kills that carrier); then the lane attaches.
func (a *actor) joinOKLocked(now time.Time, i int, at *attempt, est *carrier.Established, rxNext uint64) {
	s := a.s
	if viewDetached(est.Conn) {
		// The peer detached the view while it was attached-pending (R1-9):
		// a carrier refusal, no cadence failure, no lane; our DETACH(ended)
		// answered it already.
		a.dropConn(est.Conn)
		a.finish(now, i, at, sched.OutcomeRefused)
		a.switchFailedLocked(now, i)
		return
	}
	if dead, _, _, _ := est.Conn.Death(); dead || est.Ack.Instance != s.peer {
		a.killEst(est, carrier.CauseInstanceMismatch, "JOIN answered by another instance")
		a.finish(now, i, at, sched.OutcomeRefused)
		a.switchFailedLocked(now, i)
		return
	}
	if s.pk != nil {
		if err := s.pktJoinAckLocked(viewBudget{est.Conn}, rxNext); err != nil {
			a.pktBadAnswerLocked(now, i, at, est, err)
			a.switchFailedLocked(now, i)
			return
		}
	} else if err := s.applyRxNextLocked(rxNext); err != nil {
		a.killEst(est, carrier.CauseProtocolViolation, "JOIN_ACK rxNext beyond sent")
		a.finish(now, i, at, sched.OutcomeFailed)
		a.switchFailedLocked(now, i)
		return
	}
	a.attachLocked(now, i, at, est)
}

// pktBadAnswerLocked fails an attempt whose OPEN_ACK(OK) or JOIN_ACK(OK)
// carried invalid packet values (§A3.5): a protocol violation of that
// carrier, which is killed; the attempt counts as failed (failed mark,
// backoff) and the race or redial continues.
func (a *actor) pktBadAnswerLocked(now time.Time, i int, at *attempt, est *carrier.Established, err error) {
	a.killEst(est, carrier.CauseProtocolViolation, err.Error())
	a.d.setLast(err)
	a.finish(now, i, at, sched.OutcomeFailed)
	a.markFailed(i, carrier.CauseProtocolViolation.String(), now)
}

// joinRefusedLocked handles a non-OK JOIN_ACK from the bound instance
// (§6.7): UNKNOWN_SESSION ends the session (ErrSessionLost, L19),
// BAD_REQUEST with ErrProtocol, GOING_AWAY like a GOAWAY; CAPACITY backs
// off. UNKNOWN_SESSION and GOING_AWAY end cleanly (io.EOF) once our DONE
// was sent (D4, doneOr); BAD_REQUEST proves no peer gone and keeps its
// error.
func (a *actor) joinRefusedLocked(now time.Time, i int, at *attempt, est *carrier.Established, st wire.AckStatus) {
	a.killEst(est, carrier.CauseLocalClose, "JOIN refused")
	a.finish(now, i, at, sched.OutcomeRefused)
	a.succeeded(i)
	a.switchFailedLocked(now, i)
	switch st {
	case wire.StatusUnknownSession:
		a.terminateLocked(now, a.doneOr(fmt.Errorf("%w: JOIN_ACK UNKNOWN_SESSION", ErrSessionLost)), nil, false)
	case wire.StatusBadRequest:
		a.terminateLocked(now, fmt.Errorf("%w: JOIN_ACK BAD_REQUEST", ErrProtocol), nil, false)
	case wire.StatusGoingAway:
		a.noteGoAway(est.Ack.Instance)
		a.terminateLocked(now, a.doneOr(&AbortError{Code: AbortGoingAway, Msg: "peer going away", Remote: true}), nil, false)
	}
}

// attachLocked attaches an established carrier of factory i as a new lane
// and gives it its role: a bond or race member (data-eligible at attach,
// with a growth SCHED); the selector's active lane when there is none (the
// race winner, counted with the routing loss's cause); the planned
// switch's target; otherwise a race loser, retired with CLOSE and no
// penalty (D23). In bond and race a factory that is no member slot — an
// opening-race attempt that completed after the session opened on another
// factory — is such a loser too: it never becomes a second member of its
// fate group, nor a member beyond MaxCarriers (M3-D37, PA-31).
func (a *actor) attachLocked(now time.Time, i int, at *attempt, est *carrier.Established) {
	s := a.s
	d := a.d
	ctl := &s.ctl
	sl := &d.slots[i]
	if sl.gen > 0 {
		ctl.rejoins++ // a new incarnation of this slot (§6.7)
	}
	sl.gen++
	l := a.newLaneLocked(now, est.Conn, i, sl.gen, LaneMember)
	// A view opened on a started MUX trunk owes its go frame (M3-D8): the
	// passive holds the view after its OK response until it arrives.
	l.goOwed = est.Conn.Handle() != wire.SessionHandle
	a.finish(now, i, at, sched.OutcomeAttached)
	switch {
	case s.p.Mode.members() && sl.member:
		l.data = true
		a.publishSchedLocked(now, wire.SchedInitial) // the grown member set (the first SCHED too)
		a.owedDeathLocked(now, l.id)
	case s.p.Mode.members():
		a.retireLaneLocked(l)
	case ctl.active == nil:
		a.activateLocked(l)
		cause := wire.SchedInitial
		if a.lossSet {
			cause = a.lossCause
		}
		a.publishSchedLocked(now, cause)
		if a.lossSet {
			a.lossSet = false
			a.countLocked(now, a.lossCause, a.lossFrom, l.id, a.lossEv)
		}
		d.raceOn = false
		d.sel.Switched(now, false)
	case i == d.switchTo:
		a.qualitySwitchLocked(now, l)
	default:
		a.retireLaneLocked(l)
	}
	s.raceAttachLocked(l)
	s.routingChangedLocked()
	a.episodeEndLocked(now)
	est.Conn.Start(s.endpoint(l), &s.mb, carrier.StartOptions{Gauge: a.laneGauge(est.Conn.Kind(), i)})
	a.succeeded(i)
	a.event(now, EventCarrierUp, l.id, 0, 0, carrier.CauseNone, nil)
}
