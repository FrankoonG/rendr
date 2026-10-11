package rendr

import "time"

// Status is a Runtime snapshot.
type Status struct {
	Instance           InstanceID    // this Runtime's InstanceID
	Sessions           SessionCounts // live sessions by category, and tombstones
	Handshakes         int           // occupied handshake slots
	HandshakeEvictions uint64        // unfinished handshakes evicted because the slots were full
	AcceptBacklog      [2]int        // pending sessions across Listeners: [0] stream (Accept), [1] packet (AcceptPacket)
	Sessionless        int           // probe carriers held by this (passive) Runtime

	// BufferedBytes is the use of the MaxBufferedBytes budget (send,
	// receive and write buffers, and the datagrams queued for raw-UDP
	// flows) plus the carrier reader stages (about 16 KiB per live stream
	// carrier, the datagram classes of a datagram carrier, and a raw-UDP
	// flow's control reserve while it holds datagrams). The read buffer a
	// FromPacketConn source keeps for its socket (one datagram buffer per
	// source, at most 64 KiB) holds no data while it waits and is not
	// counted; a datagram read into it counts once it is queued for a
	// flow. So it is 0 with no session and no carrier, also while
	// Listeners with FromPacketConn sources are open (plan:774), and
	// after Runtime.Close, except for buffers still held by calls stuck in
	// embedder code (Abandoned).
	BufferedBytes int64

	Abandoned      int    // goroutines still stuck in embedder calls past their bound (see Runtime.Close)
	EventsDropped  uint64 // events dropped because the queue was full
	CallbackPanics uint64 // OnEvent calls that panicked (recovered) or called runtime.Goexit

	// ConfigAdjustments lists the clamped fields as "Field: old → new
	// (reason)": every record of the Config first, then the records of
	// the Listen calls ("Listen[i].Field: ..."), of which only the latest
	// 64 are kept, oldest first, so Listen churn cannot grow the list.
	ConfigAdjustments []string

	Datagram DatagramStatus // FromPacketConn sources and datagram carriers (M2)

	Mux    MuxStatus // shared carriers (M3)
	Actors int       // session actor goroutines running now; an idle session's actor is parked and holds none
}

// MuxStatus counts the carriers a Runtime shares between sessions (rendr
// mux: the carriers of factories without Props.CheapSubflow).
type MuxStatus struct {
	Carriers  int    // live carriers that negotiated mux (both roles)
	Views     int    // sessions attached to them (a session counts once per such carrier)
	FastPaths uint64 // dialer: OPENs and JOINs placed on a live carrier instead of dialling
	Coalesced uint64 // dialer: attempts that waited for another session's dial of the same factory (for a session of the same kind)
	MuxFull   uint64 // CAPACITY answers because a carrier held its maximum of sessions (both roles)
}

// DatagramStatus summarises the raw-UDP sources (FromPacketConn) and the
// datagram carriers of a Runtime.
type DatagramStatus struct {
	Sources    int    // live FromPacketConn sources
	Flows      int    // live raw-UDP flows, admitting ones included (bounded, see FromPacketConn)
	Admitting  int    // flows counted against their source IP address's quotas (≤ 32 OPEN and ≤ 32 JOIN or probe flows per address): from the first datagram until a positive verdict was written for them, their dialer answered an OPEN's address check, or their removal; a source that answers the check is bounded by AcceptBacklog, MaxSessions and Flows instead (see FromPacketConn)
	Dropped    uint64 // datagrams and frames dropped: malformed, unknown flow, foreign source, duplicate or out-of-window frames, quota, truncated
	Truncated  uint64 // of Dropped: truncated or oversize datagrams
	InboxDrops uint64 // datagrams a full flow inbox dropped
	ReadErrors uint64 // transient read errors (ICMP class), backed off and ignored
	Rebinds    uint64 // raw-UDP flows whose reply address moved after a nonce check

	// I/O on rendr's own UDP sockets (carrier/udp dialer sockets and the
	// carrier/udp Listen sockets adopted by FromPacketConn). SendCalls and
	// RecvCalls count the system calls on rendr-owned sockets that moved
	// at least one datagram: sendmmsg/recvmmsg on Linux amd64/arm64,
	// single-datagram calls otherwise and for H2 repeats, challenges,
	// plain-mode writes and the plain redo after a fallback; a partial
	// sendmmsg is one call. A call that ended in EAGAIN, EINTR or an error
	// before its first datagram is not counted. SentDatagrams and
	// RecvDatagrams count the datagrams those calls moved, so
	// SentDatagrams/SendCalls > 1 shows that sends were batched. Each
	// counter is updated at its call's return and read on its own, so a
	// snapshot taken while calls run may be off by the calls in progress.
	// QUIC and embedder sockets are not counted.
	SendCalls, SentDatagrams uint64
	RecvCalls, RecvDatagrams uint64

	// BatchFallbacks counts sockets that stopped batching because the
	// kernel or a sandbox refused sendmmsg/recvmmsg (each socket at most
	// once). ChargeRefused counts receive slots the memory budget refused;
	// the reader then kept its depth.
	BatchFallbacks uint64
	ChargeRefused  uint64
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
	ID           SessionID  // the session ID, the same on both ends
	Kind         Kind       // KindStream or KindPacket
	Mode         Mode       // fixed at OPEN
	Role         Role       // RoleDialer or RolePassive
	PeerInstance InstanceID // the bound peer Runtime (zero while an EarlyReturn dialer waits for the answer)
	State        State      // lifecycle state
	Err          error      // the end error once State == StateEnded (io.EOF after a clean finish), else nil

	SchedEpoch  uint32 // dialer: last epoch published; passive: last epoch applied
	SchedEchoed uint32 // dialer: highest epoch echoed by the passive; passive: equals SchedEpoch

	Migrations     MigrationCounts // never counts the initial attach
	Rejoins        uint64          // dialer only: carriers attached on a factory slot that already had one; not migrations
	NoPathEpisodes uint64          // times the session lost its last carrier (EventNoPathStart)
	InNoPath       bool            // the session has no carrier now

	TxBytes            uint64 // accepted from the application
	AckedBytes         uint64 // acknowledged as delivered to the peer application
	RxBytes            uint64 // received in order
	DeliveredBytes     uint64 // read by the application (or discarded after Close)
	RetransmittedBytes uint64 // DATA payload bytes sent again from the retransmit queue (requeued after a carrier death, a bond rescue or an early-data verdict)

	Window     int64 // currently advertised receive window
	PeerWindow int64 // peer's right edge minus AckedBytes

	Carriers []CarrierStatus // live carriers in attach order, then the last 8 dead ones

	// Packet sessions (Kind KindPacket): MaxPayload is fixed at OPEN;
	// TxBytes, RxBytes and DeliveredBytes count datagram payload bytes
	// accepted by WriteTo, accepted from carriers and returned by ReadFrom;
	// AckedBytes, RetransmittedBytes, Window and PeerWindow are 0.
	MaxPayload int
	Packet     *PacketCounters // nil for stream sessions

	DupBytes uint64       // stream receiver: bytes that arrived again (race copies, rescue duplicates) and were discarded
	Race     RaceCounters // zero unless ModeRace

	// EarlyBytes is the early data of an EarlyReturn opening (M4-D18),
	// fixed at the peer's answer. Dialer: the bytes that travelled with the
	// OPEN on the carrier that won the opening (DialOptions.EarlyReturn; 0
	// when it won on a carrier shared with other sessions, or without
	// EarlyReturn). Passive: the bytes received before Confirm.
	EarlyBytes uint64
}

// RaceCounters count a race sender's extra copies: the session's TxBytes
// and PacketCounters.Sent count each byte or datagram once, the carriers'
// TxBytes count every copy.
type RaceCounters struct {
	CopyBytes uint64 // stream sender: payload bytes placed by a lane below another lane's cursor (extra copies)
	Copies    uint64 // packet sender: extra placements of datagrams another lane already placed, less the carriers' refusals
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
	Duplicates    uint64 // received again inside the dedup window (the 16,384 datagrams behind the newest received), also after ReadFrom returned io.EOF; in a race session the members' copies of a datagram while they arrive inside the window (copies beyond it count in DropLate)
	DropQueue     uint64 // send side: evicted by a full queue, refused by MaxBufferedBytes, or still queued at the end
	DropAge       uint64 // send side: not handed to a carrier within Packet.MaxAge while one existed
	DropTooLarge  uint64 // send side: no live carrier could carry it, a carrier refused it as too large, or a budget shrink left it on a member too small for it while every member that can carry it was write-blocked or at its capacity
	DropNoPath    uint64 // send side: aged out or discarded while the session had no carrier
	DropRecvQueue uint64 // receive side: evicted from a full receive queue (the application did not read)
	DropLate      uint64 // receive side: older than the dedup window, or new and arrived after ReadFrom already returned io.EOF; in a race session also a member's copy of a datagram already received that arrives 16,384 datagrams or more behind the newest (members more than about 330 ms apart at 50,000 datagrams/s): no loss, the datagram was delivered once
	PeerReceived  uint64 // the peer's Received, as last reported by its accounting frames
}

// MigrationCounts counts migrations by cause. Selector: a change
// of the active carrier instance at publication; bond: a member that dies
// with unacknowledged data of this side that is moved to other members. Both
// ends count the same selector migrations: the dialer decides them, and the
// passive takes the dialer's cumulative counts from every scheduling update
// it applies, so they agree once the passive has followed the latest one.
type MigrationCounts struct {
	Death, Quality, Explicit uint64 // by cause: a carrier death, a selector quality switch, a carrier retired by the peer (CLOSE, GOAWAY)
}

// CarrierStatus is one carrier of a session. A dead carrier's figures are
// final once its goroutines have finished (or were abandoned) and it was
// released. A session that returns to a shared carrier it used before
// lists that carrier's ID once per use; Handle tells the rows apart.
//
// On a carrier shared between sessions (rendr mux, Shared > 1) TxBytes,
// RxBytes, RetxBytes and Frames count this session's traffic only; the
// estimator (SRTT, MinRTT, Rate, Inflight, Cap) and the datagram fields
// (MTU, Dropped, Retransmits, Rebinds) are the carrier's, the same for
// every session on it — a datagram the carrier drops belongs to no
// session — and a dead row keeps the values it had when the session left
// the carrier.
type CarrierStatus struct {
	ID       CarrierID     // allocated by the dialer; the same on both ends
	Name     string        // factory name ("" on the passive side)
	Kind     Kind          // KindStream or KindDatagram
	Gen      uint32        // incarnation number of the factory slot (dialer) or attach order (passive)
	State    CarrierState  // the carrier's role in the session
	SRTT     time.Duration // smoothed PING round trip (0 before the first PONG)
	MinRTT   time.Duration // smallest PING round trip seen
	Rate     float64       // bytes/s proven by PONG watermarks
	Inflight int           // bytes written and not yet proven received
	Cap      int           // in-flight capacity cap

	TxBytes   uint64 // DATA and DGRAM payload bytes sent on this carrier
	RxBytes   uint64 // DATA and DGRAM payload bytes received on this carrier
	RetxBytes uint64 // of TxBytes: retransmitted DATA payload bytes
	Frames    uint64 // frames written

	DeathCause  Cause  // why the carrier ended (CauseNone while it lives)
	DeathDetail string // diagnostic text for DeathCause, such as the transport error

	// Datagram carriers (zero on stream carriers).
	MTU         int    // current frame budget: bytes of rendr frames per datagram
	Dropped     uint64 // datagrams and frames this carrier dropped (truncated, malformed, duplicate, out of window, foreign)
	Retransmits uint64 // reliable control retransmissions (first datagram included)
	Rebinds     uint64 // reply-address moves (passive raw-UDP flows)

	Handle    uint32 // this session's handle on the carrier (1 on an unshared carrier)
	Shared    int    // sessions on the carrier at the snapshot (1 = unshared; 0 once dead)
	FateGroup string // dialer: the factory's Props.FateGroup ("" on the passive side)
}
