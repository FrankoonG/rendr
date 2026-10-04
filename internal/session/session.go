package session

import (
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
)

// Session is one stream session: its stream state, its lanes and its actor.
// All exported methods are safe for concurrent use.
type Session struct {
	_ struct{} // unexported state is defined by the implementation (design §3, §4, §7)
}

// ID returns the session ID.
func (s *Session) ID() [16]byte {
	panic("unimplemented: M1b")
}

// PeerInstance returns the bound peer InstanceID (dialer: from the PREFACE_ACK
// of the carrier that carried the first OPEN_ACK(OK); passive: the dialer's).
func (s *Session) PeerInstance() [16]byte {
	panic("unimplemented: M1b")
}

// Metadata returns the session's OPEN metadata (owned by the session; do not
// modify).
func (s *Session) Metadata() []byte {
	panic("unimplemented: M1b")
}

// Mode returns the mode fixed at OPEN.
func (s *Session) Mode() Mode {
	panic("unimplemented: M1b")
}

// Role returns the side.
func (s *Session) Role() Role {
	panic("unimplemented: M1b")
}

// State returns the current lifecycle state.
func (s *Session) State() State {
	panic("unimplemented: M1b")
}

// Status returns a snapshot: the control part as last published by the
// actor (published under the session lock together with every routing
// change, so the reported active carrier always equals the routed one,
// L27), plus the data counters and per-carrier estimator figures read at
// call time.
func (s *Session) Status() Status {
	panic("unimplemented: M1b")
}

// Done is closed after the session ended and every goroutine it owns (actor,
// dial attempts, carriers) exited or was abandoned after its bound.
func (s *Session) Done() <-chan struct{} {
	panic("unimplemented: M1b")
}

// Shutdown is Runtime.Close for this session: a pending session answers
// OPEN_ACK(GOING_AWAY); an open session sends RST(AbortGoingAway) and GOAWAY
// on its live carriers and ends locally with net.ErrClosed. Carriers whose
// CLOSE is not written within min(1 s, DeadMax) are killed, so Done closes
// within about 2 s unless a goroutine is stuck in embedder code (it is
// then counted as abandoned; design §4.7). It returns at once; Done reports
// completion.
func (s *Session) Shutdown() {
	panic("unimplemented: M1b")
}

// Status is the session snapshot (field-for-field rendr.SessionStatus).
type Status struct {
	ID                                           [16]byte
	Mode                                         Mode
	Role                                         Role
	PeerInstance                                 [16]byte
	State                                        State
	Err                                          error // the end error once State == StateEnded
	SchedEpoch, SchedEchoed                      uint32
	MigDeath, MigQuality, MigExplicit            uint64
	Rejoins, NoPathEpisodes                      uint64
	InNoPath                                     bool
	TxBytes, AckedBytes, RxBytes, DeliveredBytes uint64
	RetransmittedBytes                           uint64
	Window, PeerWindow                           int64 // advertised receive window; peer right edge − acked
	Carriers                                     []CarrierStatus
}

// CarrierStatus is one lane in a Status (live lanes in attach order, then the
// last 8 dead ones).
type CarrierStatus struct {
	ID          uint32
	Name        string // factory name; "" on the passive side
	Gen         uint32 // incarnation number of the factory slot (dialer); attach order (passive)
	State       LaneState
	Stats       carrier.Stats
	DeathCause  carrier.Cause
	DeathDetail string
	DeathAt     time.Time
}
