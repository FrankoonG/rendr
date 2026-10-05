package rendr

import "time"

// Status is a Runtime snapshot.
type Status struct {
	Instance           InstanceID
	Sessions           SessionCounts
	Handshakes         int    // occupied handshake slots
	HandshakeEvictions uint64 // unfinished handshakes evicted because the slots were full
	AcceptBacklog      [2]int // pending sessions across Listeners: [0] stream, [1] packet (0: no packet sessions yet)
	Sessionless        int    // probe carriers held by this (passive) Runtime

	// BufferedBytes is the use of the MaxBufferedBytes budget (send,
	// receive and write buffers) plus the carrier reader stages (about
	// 16 KiB per live carrier). It is 0 after Runtime.Close, except for
	// buffers still held by calls stuck in embedder code (Abandoned).
	BufferedBytes int64

	Abandoned         int      // goroutines still stuck in embedder calls past their bound (see Runtime.Close)
	EventsDropped     uint64   // events dropped because the queue was full
	CallbackPanics    uint64   // OnEvent calls that panicked (recovered) or called runtime.Goexit
	ConfigAdjustments []string // "Field: old → new (reason)"; Config first, then "Listen[i].Field: ..."

	Datagram DatagramStatus // FromPacketConn sources and datagram carriers (M2)
}

// DatagramStatus summarises the raw-UDP sources (FromPacketConn) and the
// datagram carriers of a Runtime.
type DatagramStatus struct {
	Sources    int    // live FromPacketConn sources
	Flows      int    // live raw-UDP flows, admitting ones included (bounded, see FromPacketConn)
	Admitting  int    // flows before a positive verdict was written for them (≤ 32 per source IP address)
	Dropped    uint64 // datagrams and frames dropped: malformed, unknown flow, foreign source, duplicate or out-of-window frames, quota, truncated
	Truncated  uint64 // of Dropped: truncated or oversize datagrams
	InboxDrops uint64 // datagrams a full flow inbox dropped
	ReadErrors uint64 // transient read errors (ICMP class), backed off and ignored
	Rebinds    uint64 // raw-UDP flows whose reply address moved after a nonce check
}

// SessionCounts counts sessions of both roles. Open, Pending, Lingering and
// Orphaned are mutually disjoint: a session counts in the first of
// Pending, Lingering, Orphaned that applies, else in Open, so their sum is
// the number of live sessions. A dialer session that is still dialling
// holds a MaxSessions unit but counts in no category until its Dial
// succeeds.
type SessionCounts struct {
	Open       int // open sessions not in another category
	Pending    int // passive sessions waiting for Confirm/Reject
	Lingering  int // sessions whose application called Close and that have not ended
	Orphaned   int // passive sessions inside a no-path episode
	Tombstones int // ended passive sessions remembered for PassiveRetain + Linger, so that a late OPEN cannot start them again
}

// SessionStatus is a session snapshot.
type SessionStatus struct {
	ID           SessionID
	Kind         Kind
	Mode         Mode
	Role         Role
	PeerInstance InstanceID
	State        State
	Err          error // the end error once State == StateEnded (io.EOF after a clean finish), else nil

	SchedEpoch  uint32 // dialer: last epoch published; passive: last epoch applied
	SchedEchoed uint32 // dialer: highest epoch echoed by the passive; passive: equals SchedEpoch

	Migrations     MigrationCounts // never counts the initial attach
	Rejoins        uint64          // dialer only: carriers attached on a factory slot that already had one; not migrations
	NoPathEpisodes uint64
	InNoPath       bool

	TxBytes            uint64 // accepted from the application
	AckedBytes         uint64 // acknowledged as delivered to the peer application
	RxBytes            uint64 // received in order
	DeliveredBytes     uint64 // read by the application (or discarded after Close)
	RetransmittedBytes uint64

	Window     int64 // currently advertised receive window
	PeerWindow int64 // peer's right edge minus AckedBytes

	Carriers []CarrierStatus // live carriers in attach order, then the last 8 dead ones

	// Packet sessions (Kind KindPacket): MaxPayload is fixed at OPEN;
	// TxBytes, RxBytes and DeliveredBytes count datagram payload bytes
	// accepted by WriteTo, accepted from carriers and returned by ReadFrom;
	// AckedBytes, RetransmittedBytes, Window and PeerWindow are 0.
	MaxPayload int
	Packet     *PacketCounters // nil for stream sessions
}

// PacketCounters count the datagrams of one packet session on this side.
// Sent and the send-side drops add up to what WriteTo accepted (a datagram
// still queued is in none of them; nothing is queued after the end): a
// datagram a carrier refused as too large counts in DropTooLarge, not in
// Sent. A datagram that was sent and not received was lost with a carrier,
// dropped by the network, or counted in the peer's receive-side drops.
type PacketCounters struct {
	Sent          uint64 // handed to a carrier and not refused by it
	Received      uint64 // accepted from carriers (distinct)
	Duplicates    uint64 // received again inside the dedup window
	DropQueue     uint64 // send side: evicted by a full queue, refused by MaxBufferedBytes, or still queued at the end
	DropAge       uint64 // send side: not handed to a carrier within Packet.MaxAge while one existed
	DropTooLarge  uint64 // send side: no live carrier could carry it, or a carrier refused it as too large
	DropNoPath    uint64 // send side: aged out or discarded while the session had no carrier
	DropRecvQueue uint64 // receive side: evicted from a full receive queue (the application did not read)
	DropLate      uint64 // receive side: older than the dedup window, or arrived after ReadFrom already returned io.EOF
	PeerReceived  uint64 // the peer's Received, as last reported by its accounting frames
}

// MigrationCounts counts migrations by cause. Selector: a change
// of the active carrier instance at publication; bond: a member that dies
// with unacknowledged data of this side that is moved to other members. Both
// ends count the same selector migrations: the dialer decides them, and the
// passive takes the dialer's cumulative counts from every scheduling update
// it applies, so they agree once the passive has followed the latest one.
type MigrationCounts struct {
	Death, Quality, Explicit uint64
}

// CarrierStatus is one carrier of a session. A dead carrier's figures are
// final once its goroutines have finished (or were abandoned) and it was
// released.
type CarrierStatus struct {
	ID       CarrierID
	Name     string // factory name ("" on the passive side)
	Kind     Kind
	Gen      uint32 // incarnation number of the factory slot (dialer) or attach order (passive)
	State    CarrierState
	SRTT     time.Duration
	MinRTT   time.Duration
	Rate     float64 // bytes/s proven by PONG watermarks
	Inflight int     // bytes written and not yet proven received
	Cap      int     // in-flight capacity cap

	TxBytes   uint64
	RxBytes   uint64
	RetxBytes uint64
	Frames    uint64

	DeathCause  Cause
	DeathDetail string

	// Datagram carriers (zero on stream carriers).
	MTU         int    // current frame budget: bytes of rendr frames per datagram
	Dropped     uint64 // datagrams and frames this carrier dropped (truncated, malformed, duplicate, out of window, foreign)
	Retransmits uint64 // reliable control retransmissions (first datagram included)
	Rebinds     uint64 // reply-address moves (passive raw-UDP flows)
}
