package session

import (
	"bytes"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// PassiveSpec describes an admitted OPEN.
type PassiveSpec struct {
	SID            [16]byte
	Params         Params   // passive: Grace = clamp(OPEN.retain_ms, 1 s, 400 s)
	DialerInstance [16]byte // from the OPEN carrier's PREFACE; the bound instance
	PeerWindow     uint32   // OPEN.window: the dialer's initial receive window
	Metadata       []byte   // copied
}

// NewPending creates an unstarted passive session in StatePending with
// first (the unstarted OPEN carrier) as its first lane. It starts nothing,
// so the admission creates it outside every admission lock and then does
// the shard's insert-or-get (design §6.2): the winner of that insert calls
// Start; a loser is discarded unstarted (it owns no goroutine and no Budget
// charge) and its carrier goes to the winner's AttachOpen. A pending
// session survives the death of its carriers; it ends only by Confirm (→
// open), Reject, AcceptTimeout (CAPACITY, CodeAcceptTimeout),
// RefusePending, Shutdown, or an RST from the dialer (withdrawn:
// ErrSessionLost for a later Confirm).
//
// Further contracts of this implementation: Params.Role is set to
// RolePassive and a zero Params.Mode to ModeSelector; AcceptTimeout counts
// from this call (the admission). The session calls Env.Registry: Opened
// at Confirm, Lingering on Close, Orphaned around no-path episodes of an
// open session, and Ended at its end with the verdict its tombstone
// repeats.
func NewPending(env *Env, spec PassiveSpec, first *carrier.Conn) *Session {
	p := spec.Params
	p.Role = RolePassive
	if p.Mode == 0 {
		p.Mode = ModeSelector
	}
	s := &Session{env: env, p: p, id: spec.SID, meta: bytes.Clone(spec.Metadata), peer: spec.DialerInstance}
	s.done = make(chan struct{})
	s.mb.init()
	now := time.Now()
	s.mu.Lock()
	s.initStreamLocked()
	s.peerWindowLocked(spec.PeerWindow)
	s.ctl.state = StatePending
	s.ctl.epoch = p.FirstEpoch - 1 // the first SCHED (FirstEpoch) is newer (V15)
	s.ctl.rescuedBase = ^uint64(0)
	l := &lane{s: s, c: first, port: first, id: first.ID(), factory: -1, gen: 1, since: now}
	l.state = LaneJoining
	l.schedSent = s.ctl.epoch
	s.lanes = append(s.lanes, l)
	s.laneAddedLocked(l)
	s.initialSnapLocked()
	s.mu.Unlock()
	return s
}

// Start launches the actor of a session made by NewPending and starts its
// first carrier: the reader runs (it notices the dialer closing the carrier
// or sending RST(AbortWithdrawn)); the writer is held (StartOptions.Hold)
// until the verdict. Called exactly once, by the admission that inserted
// the session. Commands posted before Start (AttachOpen, Join, Confirm,
// Reject, RefusePending, Shutdown) wait in the mailbox and are handled in
// order once the actor runs.
func (s *Session) Start() {
	if !s.mb.start() {
		return // a second Start: the actor already runs
	}
	a := newActor(s)
	s.mu.Lock()
	first := s.lanes[0] // the actor is not running yet: NewPending's lane
	s.mu.Unlock()
	a.gen = first.gen
	a.acceptBy = first.since.Add(orDefault(s.p.AcceptTimeout, defAcceptTimeout))
	first.c.Start(first, &s.mb, carrier.StartOptions{Hold: true})
	go a.run()
}

// carriersLocked counts the lanes that are not dead plus the adopts posted
// but not yet handled: the carrier limit of Join and AttachOpen (D27, C31).
func (s *Session) carriersLocked() int {
	n := s.ctl.adopting
	for _, l := range s.lanes {
		if l.state != LaneDead {
			n++
		}
	}
	return n
}

// maxCarriers is Params.MaxCarriers with its default.
func (s *Session) maxCarriers() int {
	if s.p.MaxCarriers > 0 {
		return s.p.MaxCarriers
	}
	return defMaxCarriers
}

// finalVerdict is the verdict of an ended session (its last snapshot).
func (s *Session) finalVerdict() Verdict {
	if sn := s.snap.Load(); sn != nil {
		return sn.verdict
	}
	return Verdict{Status: wire.StatusUnknownSession}
}

// AttachOpen handles a duplicate OPEN for this session (L47): a pending
// session parks c as one more OPEN carrier (answered at the verdict); an
// open session adopts c like a JOIN and writes OPEN_ACK(OK, window) as its
// first frame. The carrier limit counts adopts posted but not yet handled
// (as Join). When it does not take c (session ended, or at MaxCarriers),
// taken is false and v is the verdict the caller writes as OPEN_ACK before
// closing c.
func (s *Session) AttachOpen(c *carrier.Conn) (taken bool, v Verdict) {
	s.mu.Lock()
	switch {
	case s.ctl.state == StateEnded:
		s.mu.Unlock()
		return false, s.finalVerdict()
	case s.carriersLocked() >= s.maxCarriers():
		s.mu.Unlock()
		return false, Verdict{Status: wire.StatusCapacity, Code: wire.CodeCarriers}
	}
	s.ctl.adopting++
	s.mu.Unlock()
	if !s.mb.post(&adopt{conn: c, kind: adoptOpen}) {
		return false, s.finalVerdict() // the actor exited meanwhile
	}
	return true, Verdict{}
}

// Confirm opens a pending session: OPEN_ACK(OK, window) becomes the first
// frame of every OPEN carrier and their writers are released. It returns
// ErrSessionLost if the dialer withdrew, ErrCapacity if AcceptTimeout already
// answered, net.ErrClosed if the Listener or Runtime closed, and an error
// for a second call.
func (s *Session) Confirm() error {
	c := &confirm{reply: make(chan error, 1)}
	if !s.mb.post(c) {
		return verdictErr(s.finalVerdict())
	}
	return <-c.reply
}

// Reject ends a pending session with OPEN_ACK(REJECTED, code, msg[:255]) on
// every OPEN carrier; the tombstone repeats this verdict to duplicate OPENs.
// Errors as for Confirm.
func (s *Session) Reject(code uint32, msg string) error {
	r := &reject{code: code, msg: msg, reply: make(chan error, 1)}
	if !s.mb.post(r) {
		return verdictErr(s.finalVerdict())
	}
	return <-r.reply
}

// RefusePending ends a pending session with OPEN_ACK(status, code) — used
// for GOING_AWAY when its Listener closes. It returns false if the session is
// not pending.
//
// It waits for the actor's answer, so it must not be called with a lock
// held that the session's own goroutines may need.
func (s *Session) RefusePending(status wire.AckStatus, code uint32) bool {
	r := &refuse{status: status, code: code, reply: make(chan bool, 1)}
	if !s.mb.post(r) {
		return false
	}
	return <-r.reply
}

// Join handles a JOIN for a live table entry (the admission only checked
// the key: a missing entry or a tombstone is answered UNKNOWN_SESSION by the
// caller). Under the session lock — the session's own state is
// authoritative, and it turns open before OPEN_ACK can be queued — it
// validates the state (pending: BAD_REQUEST, P9; ended: UNKNOWN_SESSION),
// the mode (BAD_REQUEST) and the carrier limit (CAPACITY: MaxCarriers lanes
// that are not dead plus adopts posted but not yet handled, D27); applies
// j.RxNext as a delivered offset (it trims retransmissions and never changes
// the window; RxNext beyond what was sent is BAD_REQUEST); and posts an
// adopt of c, which the actor gives JOIN_ACK(OK, rxNext = rRead) as its
// first frame. When taken is false the caller writes JOIN_ACK(status) and
// closes c.
func (s *Session) Join(c *carrier.Conn, j *wire.Join) (taken bool, status wire.AckStatus) {
	s.mu.Lock()
	switch {
	case s.ctl.state == StatePending:
		status = wire.StatusBadRequest
	case s.ctl.state == StateEnded:
		status = wire.StatusUnknownSession
	case Mode(j.Mode) != s.p.Mode:
		status = wire.StatusBadRequest
	case s.carriersLocked() >= s.maxCarriers():
		status = wire.StatusCapacity
	case s.applyRxNextLocked(j.RxNext) != nil:
		status = wire.StatusBadRequest
	default:
		s.ctl.adopting++
		s.mu.Unlock()
		if !s.mb.post(&adopt{conn: c, kind: adoptJoin, join: *j}) {
			return false, wire.StatusUnknownSession // the actor exited meanwhile
		}
		return true, wire.StatusOK
	}
	s.mu.Unlock()
	return false, status
}
