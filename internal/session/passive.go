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
	PeerWindow     uint32   // OPEN.window: the dialer's initial receive window (stream sessions; a packet session's OPEN.window is the carrier budget offer, M2-D11)
	Metadata       []byte   // copied
	// MaxPayload is a packet session's accepted MaxPayload (pmtu_acc,
	// M2-D49), carried by Confirm's OPEN_ACK; 0 for stream sessions.
	// NewPending fixes the session's MaxPayload from it, so
	// PendingPacket.MaxPayload reads the accepted value before Confirm (M2
	// design Revision 1, R1-32).
	MaxPayload int
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
	if p.Kind == wire.KindDatagram && spec.MaxPayload > 0 {
		// The accepted MaxPayload is the session's from here (R1-32):
		// initPacketLocked fixes it, PendingPacket reads it before Confirm.
		p.Packet.MaxPayload = spec.MaxPayload
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
	a.unconfirmed = append(a.unconfirmed, first)
	a.acceptBy = first.since.Add(orDefault(s.p.AcceptTimeout, defAcceptTimeout))
	first.c.Start(s.endpoint(first), &s.mb, carrier.StartOptions{Hold: true})
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

// knownCarrierLocked reports whether id is the CarrierID of a carrier the
// session attached: a lane's, or one of the last eight dead lanes' of the
// published snapshot (the CarrierStatus history, R1-11).
func (s *Session) knownCarrierLocked(id uint32) bool {
	for _, l := range s.lanes {
		if l.id == id {
			return true
		}
	}
	if sn := s.snap.Load(); sn != nil {
		for i := range sn.lanes {
			if ls := &sn.lanes[i]; ls.state == LaneDead && ls.id == id {
				return true
			}
		}
	}
	return false
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
// closing c. A carrier whose CarrierID the session already attached — a
// live lane's or one of its last eight dead lanes' — is refused with
// BAD_REQUEST (CodeBadValue): a correct dialer never reuses one, so only a
// replayed or duplicated first datagram meets it (M2-D84; Revision 1,
// R1-11). For a packet session the admission has validated c's packet OPEN
// fields and set its budget (R1-5); its OPEN_ACK window is c's own.
func (s *Session) AttachOpen(c *carrier.Conn) (taken bool, v Verdict) {
	s.mu.Lock()
	switch {
	case s.ctl.state == StateEnded:
		s.mu.Unlock()
		return false, s.finalVerdict()
	case s.knownCarrierLocked(c.ID()):
		s.mu.Unlock()
		return false, Verdict{Status: wire.StatusBadRequest, Code: wire.CodeBadValue}
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
// ErrSessionLost if the dialer withdrew (also when its RST or GOAWAY
// arrived before the actor executed this Confirm), ErrCapacity if
// AcceptTimeout already answered, net.ErrClosed if the Listener or Runtime
// closed, and an error for a second call.
//
// Confirm, Reject and RefusePending wait for the actor's answer, which it
// sends after releasing the session lock and before any Env.Registry call
// of that step (Opened, Ended, Lingering, Orphaned): a caller may hold a
// lock the Registry methods take — the actor waits for it only after
// answering — but none that the session lock may wait for (design §3.2:
// the admission locks are never held together with a session lock).
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
// when its Listener closes: CAPACITY(CodeBacklog) while the Runtime runs
// (a closed Listener is not the instance going away, D21), GOING_AWAY when
// Runtime.Close runs concurrently. It returns false if the session is not
// pending.
//
// It waits for the actor's answer (sent before the verdict's Registry
// calls, as for Confirm), so it must not be called with a lock held that
// the session's own goroutines may need.
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
//
// A carrier whose CarrierID the session already attached (a live lane's or
// one of its last eight dead lanes') is refused with BAD_REQUEST (M2-D84,
// R1-11). Carrier kinds (§A3.5): a stream session's JOIN on a datagram
// carrier is BAD_REQUEST; a packet session's JOIN carries the carrier's
// cmtu offer in RxNext — 0 on a stream carrier, 537 … 65,507 on a datagram
// carrier, else BAD_REQUEST — and nothing is acknowledged by it; the
// accepted budget cmtu_acc = min(offer, the transport's limit) is set on c
// (Conn.SetBudget, outside the session lock and before the adopt is
// posted) and returned in JOIN_ACK(OK).RxNext (M2-D50).
func (s *Session) Join(c *carrier.Conn, j *wire.Join) (taken bool, status wire.AckStatus) {
	cmtu, kindOK := pktJoinBudget(s.pk != nil, c.Kind(), j.RxNext, transportLimit(c))
	s.mu.Lock()
	switch {
	case s.ctl.state == StatePending:
		status = wire.StatusBadRequest
	case s.ctl.state == StateEnded:
		status = wire.StatusUnknownSession
	case Mode(j.Mode) != s.p.Mode, !kindOK, s.knownCarrierLocked(c.ID()):
		status = wire.StatusBadRequest
	case s.carriersLocked() >= s.maxCarriers():
		status = wire.StatusCapacity
	case s.applyRxNextLocked(j.RxNext) != nil:
		status = wire.StatusBadRequest
	default:
		s.ctl.adopting++
		s.mu.Unlock()
		if s.pk != nil {
			c.SetBudget(cmtu) // the carrier is unstarted until the actor adopts it
		}
		if !s.mb.post(&adopt{conn: c, kind: adoptJoin, join: *j}) {
			return false, wire.StatusUnknownSession // the actor exited meanwhile
		}
		return true, wire.StatusOK
	}
	s.mu.Unlock()
	return false, status
}
