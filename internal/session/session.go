package session

import (
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// ID returns the session ID.
func (s *Session) ID() [16]byte {
	return s.id
}

// PeerInstance returns the bound peer InstanceID (dialer: from the PREFACE_ACK
// of the carrier that carried the first OPEN_ACK(OK); passive: the dialer's).
func (s *Session) PeerInstance() [16]byte {
	return s.peer
}

// Metadata returns the session's OPEN metadata (owned by the session; do not
// modify).
func (s *Session) Metadata() []byte {
	return s.meta
}

// Mode returns the mode fixed at OPEN.
func (s *Session) Mode() Mode {
	return s.p.Mode
}

// Role returns the side.
func (s *Session) Role() Role {
	return s.p.Role
}

// State returns the current lifecycle state.
func (s *Session) State() State {
	if sn := s.snap.Load(); sn != nil {
		return sn.state
	}
	return StatePending
}

// Status returns a snapshot: the control part as last published by the
// actor (published under the session lock together with every routing
// change, so the reported active carrier always equals the routed one,
// L27), plus the data counters and per-carrier estimator figures read at
// call time; a dead carrier's figures are final once it was joined (the
// step that prunes it records its last Stats, §0.14 B7).
func (s *Session) Status() Status {
	return s.status()
}

// Done is closed after the session ended and every goroutine it owns (actor,
// dial attempts, carriers) exited or was abandoned after its bound.
func (s *Session) Done() <-chan struct{} {
	return s.done
}

// Shutdown is Runtime.Close for this session: a pending session answers
// OPEN_ACK(GOING_AWAY); an open session sends RST(AbortGoingAway) and GOAWAY
// on its live carriers and ends locally with net.ErrClosed. Carriers whose
// CLOSE is not written within min(1 s, DeadMax) are killed, so Done closes
// within about 2 s unless a goroutine is stuck in embedder code (it is
// then counted as abandoned; design §4.7). It returns at once; Done reports
// completion.
func (s *Session) Shutdown() {
	s.mb.post(&shutdown{}) // refused only once the actor exited: nothing left to shut down
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

	// M2. Kind is the session kind (wire.KindStream or wire.KindDatagram);
	// MaxPayload and Packet are set for packet sessions only.
	Kind       wire.CarrierKind
	MaxPayload int
	Packet     *PacketCounters

	// M3. DupBytes counts the stream receiver's discarded duplicates (every
	// mode); Race the sender's extra copies (race sessions only).
	DupBytes uint64
	Race     RaceCounters
}

// RaceCounters are a race sender's extra copies (field-for-field
// rendr.RaceCounters; M3-D35).
type RaceCounters struct {
	CopyBytes uint64 // stream: payload bytes placed below another lane's cursor
	Copies    uint64 // packet: extra placements of datagrams another lane already placed, less the carriers' refusals (raceRefused)
}

// PacketCounters count the datagrams of one packet session on this side
// (field-for-field rendr.PacketCounters; M2-D61). In a Status snapshot a
// datagram a carrier refused as too large counts in DropTooLarge and not in
// Sent, so Sent + DropQueue + DropAge + DropTooLarge + DropNoPath + still
// queued = accepted by WriteTo (M2 design §A7.2, Revision 1, R1-31).
type PacketCounters struct {
	Sent          uint64 // placed on a carrier (seq assigned) and not refused by it
	Received      uint64 // accepted from carriers (new seqs)
	Duplicates    uint64 // received again inside the dedup window, also after the peer's FIN was delivered (M3-D35); in a race session the members' copies while they arrive inside the window (KL-15)
	DropQueue     uint64 // send side: evicted by a full queue, refused by MaxBufferedBytes, or still queued at the end
	DropAge       uint64 // send side: older than Packet.MaxAge before placement while a data lane existed
	DropTooLarge  uint64 // send side: no live data lane could carry it, a carrier refused it as too large, or a budget shrink left it on a member too small for it while every member that can carry it was write-blocked or at its capacity (M2-D45, L37)
	DropNoPath    uint64 // send side: aged out or discarded while the session had no data lane
	DropRecvQueue uint64 // receive side: evicted by a full receive queue (the application did not read)
	DropLate      uint64 // receive side: older than the dedup window, or new and arrived after the peer's FIN was delivered (R1-12); in a race session also a member's copy of a received datagram that arrives beyond the window (KL-15): no loss, delivered once
	PeerReceived  uint64 // the peer's Received, from its PACKs (merged by max)
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
