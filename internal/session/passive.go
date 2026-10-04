package session

import (
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
func NewPending(env *Env, spec PassiveSpec, first *carrier.Conn) *Session {
	panic("unimplemented: M1b")
}

// Start launches the actor of a session made by NewPending and starts its
// first carrier: the reader runs (it notices the dialer closing the carrier
// or sending RST(AbortWithdrawn)); the writer is held (StartOptions.Hold)
// until the verdict. Called exactly once, by the admission that inserted
// the session. Commands posted before Start (AttachOpen, Join, Confirm,
// Reject, RefusePending, Shutdown) wait in the mailbox and are handled in
// order once the actor runs.
func (s *Session) Start() {
	panic("unimplemented: M1b")
}

// AttachOpen handles a duplicate OPEN for this session (L47): a pending
// session parks c as one more OPEN carrier (answered at the verdict); an
// open session adopts c like a JOIN and writes OPEN_ACK(OK, window) as its
// first frame. The carrier limit counts adopts posted but not yet handled
// (as Join). When it does not take c (session ended, or at MaxCarriers),
// taken is false and v is the verdict the caller writes as OPEN_ACK before
// closing c.
func (s *Session) AttachOpen(c *carrier.Conn) (taken bool, v Verdict) {
	panic("unimplemented: M1b")
}

// Confirm opens a pending session: OPEN_ACK(OK, window) becomes the first
// frame of every OPEN carrier and their writers are released. It returns
// ErrSessionLost if the dialer withdrew, ErrCapacity if AcceptTimeout already
// answered, net.ErrClosed if the Listener or Runtime closed, and an error
// for a second call.
func (s *Session) Confirm() error {
	panic("unimplemented: M1b")
}

// Reject ends a pending session with OPEN_ACK(REJECTED, code, msg[:255]) on
// every OPEN carrier; the tombstone repeats this verdict to duplicate OPENs.
// Errors as for Confirm.
func (s *Session) Reject(code uint32, msg string) error {
	panic("unimplemented: M1b")
}

// RefusePending ends a pending session with OPEN_ACK(status, code) — used
// for GOING_AWAY when its Listener closes. It returns false if the session is
// not pending.
func (s *Session) RefusePending(status wire.AckStatus, code uint32) bool {
	panic("unimplemented: M1b")
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
	panic("unimplemented: M1b")
}
