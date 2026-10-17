package rendr

import (
	"math"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

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
	// flow's control reserve and its queue's entry blocks, about 5 KiB per
	// 64 datagrams beyond its first 8, while it holds datagrams). The read
	// buffer a FromPacketConn source keeps for its socket (one datagram
	// buffer per source, at most 64 KiB) holds no data while it waits and
	// is not counted; a datagram read into it counts once it is queued for a
	// flow. A udp.Listen socket that reads several datagrams per call
	// (Linux amd64 and arm64, udp.Options.MaxBatch other than 1: the
	// default 0 selects 32) also holds, from its first read on and while
	// datagrams arrive, up to D − 1 more read buffers of its MaxDatagram
	// class and D message headers of about 184 bytes each,
	// D = min(MaxBatch, 32), all counted (about 70 KiB at the defaults);
	// once its read has waited one to two seconds without a datagram it
	// returns them, and it reads one datagram per call until the next one
	// arrives (a datagram carrier's reader does the same with its own
	// extra buffers). So it is 0 with no session and no carrier,
	// also while Listeners with FromPacketConn sources are open — within
	// two seconds of their last datagram, or of their start if none
	// arrived (plan:774) — and after Runtime.Close, except for buffers
	// still held by calls stuck in embedder code (Abandoned).
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
	Dropped    uint64 // datagrams and frames dropped: malformed, unknown flow, foreign source, duplicate or out-of-window frames, quota, truncated, a received DGRAM MaxBufferedBytes refused, or a send lost to a transient error
	Truncated  uint64 // of Dropped: truncated or oversize datagrams
	InboxDrops uint64 // datagrams a raw-UDP flow dropped because its inbox was full or MaxBufferedBytes refused them
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
	// the reader then kept, or fell back to, the depth it could charge (a
	// dialer carrier keeps its depth; a listening socket reads with the
	// slots it has).
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
	Copies    uint64 // packet sender: extra placements of datagrams another lane already placed, less the carriers' refusals and the copies a dying carrier handed back unwritten (so, like PacketCounters.Sent, it can decrease between two snapshots)
}

// PacketCounters count the datagrams of one packet session on this side.
// Sent and the send-side drops add up to what WriteTo accepted (a datagram
// still queued is in none of them, nor is one a dying carrier handed back
// unwritten while it waits to be placed again; nothing is queued after the
// end): a datagram a carrier refused as too large counts in DropTooLarge,
// not in Sent. A datagram that was sent and not received was lost in
// flight (dropped by the network, or with a carrier that died), dropped by
// a carrier of either side or by the peer's raw-UDP flow (counted in
// Status.Datagram and, for a carrier, in its CarrierStatus.Dropped, or in
// a QUIC carrier's Counters; not here), or counted in the peer's DropLate.
// Sent − PeerReceived counts them as far as the peer has reported; during
// traffic it also holds the datagrams still in flight.
type PacketCounters struct {
	Sent          uint64 // handed to a carrier, not refused by it and not handed back unwritten by a carrier that died; a refused datagram leaves Sent for DropTooLarge, and a handed-back one leaves it until it is placed again or counted in a drop counter, so Sent can decrease between two snapshots
	Received      uint64 // accepted from carriers (distinct)
	Duplicates    uint64 // received again inside the dedup window (the 16,384 datagrams behind the newest received), also after ReadFrom returned io.EOF; in a race session the members' copies of a datagram while they arrive inside the window (copies beyond it count in DropLate)
	DropQueue     uint64 // send side: evicted by a full queue, refused by MaxBufferedBytes, still queued or waiting to be placed again at the end or at the peer's FIN, or handed back unwritten by a dying carrier after either or while too many waited
	DropAge       uint64 // send side: not handed to a carrier, or not placed again after a dying carrier handed it back unwritten, within Packet.MaxAge of its WriteTo while one existed
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
// every session on it — a datagram the carrier drops is not counted per
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
	Dropped     uint64 // datagrams and frames this carrier dropped (truncated, malformed, duplicate, out of window, foreign, a received DGRAM MaxBufferedBytes refused, a send lost to a transient error)
	Retransmits uint64 // reliable control retransmissions (first datagram included)
	Rebinds     uint64 // reply-address moves (passive raw-UDP flows)

	Handle    uint32 // this session's handle on the carrier (1 on an unshared carrier)
	Shared    int    // sessions on the carrier at the snapshot (1 = unshared; 0 once dead)
	FateGroup string // dialer: the factory's Props.FateGroup ("" on the passive side)
}

// The internal packages mirror the public enums numerically (design §2.4,
// §2.5), so conversions are plain type conversions. These declarations fail
// to compile if a value ever diverges: an array length must be a
// non-negative constant, and [0]struct{} only accepts a zero difference.
var (
	_ [0]struct{} = [int(ModeSelector) - int(session.ModeSelector)]struct{}{}
	_ [0]struct{} = [int(ModeBond) - int(session.ModeBond)]struct{}{}
	_ [0]struct{} = [int(ModeRace) - int(session.ModeRace)]struct{}{}
	_ [0]struct{} = [int(RoleDialer) - int(session.RoleDialer)]struct{}{}
	_ [0]struct{} = [int(RolePassive) - int(session.RolePassive)]struct{}{}
	_ [0]struct{} = [int(StatePending) - int(session.StatePending)]struct{}{}
	_ [0]struct{} = [int(StateOpen) - int(session.StateOpen)]struct{}{}
	_ [0]struct{} = [int(StateClosing) - int(session.StateClosing)]struct{}{}
	_ [0]struct{} = [int(StateEnded) - int(session.StateEnded)]struct{}{}
	_ [0]struct{} = [int(CarrierJoining) - int(session.LaneJoining)]struct{}{}
	_ [0]struct{} = [int(CarrierActive) - int(session.LaneActive)]struct{}{}
	_ [0]struct{} = [int(CarrierMember) - int(session.LaneMember)]struct{}{}
	_ [0]struct{} = [int(CarrierRetiring) - int(session.LaneRetiring)]struct{}{}
	_ [0]struct{} = [int(CarrierDead) - int(session.LaneDead)]struct{}{}
	_ [0]struct{} = [int(EventCarrierUp) - int(session.EventCarrierUp)]struct{}{}
	_ [0]struct{} = [int(EventCarrierDown) - int(session.EventCarrierDown)]struct{}{}
	_ [0]struct{} = [int(EventMigration) - int(session.EventMigration)]struct{}{}
	_ [0]struct{} = [int(EventNoPathStart) - int(session.EventNoPathStart)]struct{}{}
	_ [0]struct{} = [int(EventNoPathEnd) - int(session.EventNoPathEnd)]struct{}{}
	_ [0]struct{} = [int(EventSessionEnd) - int(session.EventSessionEnd)]struct{}{}
	_ [0]struct{} = [int(CauseNone) - int(carrier.CauseNone)]struct{}{}
	_ [0]struct{} = [int(CausePingTimeout) - int(carrier.CausePingTimeout)]struct{}{}
	_ [0]struct{} = [int(CauseWriteStall) - int(carrier.CauseWriteStall)]struct{}{}
	_ [0]struct{} = [int(CauseTransportError) - int(carrier.CauseTransportError)]struct{}{}
	_ [0]struct{} = [int(CauseProtocolViolation) - int(carrier.CauseProtocolViolation)]struct{}{}
	_ [0]struct{} = [int(CauseInstanceMismatch) - int(carrier.CauseInstanceMismatch)]struct{}{}
	_ [0]struct{} = [int(CauseGoAway) - int(carrier.CauseGoAway)]struct{}{}
	_ [0]struct{} = [int(CauseLocalClose) - int(carrier.CauseLocalClose)]struct{}{}
	_ [0]struct{} = [int(CauseRetired) - int(carrier.CauseRetired)]struct{}{}
	_ [0]struct{} = [int(CauseQuality) - int(carrier.CauseQuality)]struct{}{}
	_ [0]struct{} = [int(CausePeerDown) - int(carrier.CausePeerDown)]struct{}{}
	_ [0]struct{} = [int(EvidenceUnknown) - int(sched.EvUnknown)]struct{}{}
	_ [0]struct{} = [int(EvidenceFresh) - int(sched.EvFresh)]struct{}{}
	_ [0]struct{} = [int(EvidenceHeld) - int(sched.EvHeld)]struct{}{}
	_ [0]struct{} = [int(EvidenceStale) - int(sched.EvStale)]struct{}{}
)

// eventFrom converts a session event; Seq is assigned by the event queue.
func eventFrom(ev session.Event) Event {
	return Event{
		Time:    ev.Time,
		Kind:    EventKind(ev.Kind),
		Session: SessionID(ev.Session),
		Carrier: CarrierID(ev.Carrier),
		From:    CarrierID(ev.From),
		To:      CarrierID(ev.To),
		Cause:   Cause(ev.Cause),
		Err:     ev.Err,
	}
}

// sessionStatusFrom converts a session snapshot (M2-D61): a packet
// session reports KindPacket, its MaxPayload and its PacketCounters; M3
// adds the receiver's DupBytes and the race sender's copies (M3-D35).
// CarrierStatus.FateGroup is the Peer's to fill (peerProps.status).
func sessionStatusFrom(st session.Status) SessionStatus {
	out := SessionStatus{
		ID:           SessionID(st.ID),
		Kind:         kindFrom(st.Kind),
		Mode:         Mode(st.Mode),
		Role:         Role(st.Role),
		PeerInstance: InstanceID(st.PeerInstance),
		State:        State(st.State),
		Err:          st.Err,
		SchedEpoch:   st.SchedEpoch,
		SchedEchoed:  st.SchedEchoed,
		Migrations: MigrationCounts{
			Death:    st.MigDeath,
			Quality:  st.MigQuality,
			Explicit: st.MigExplicit,
		},
		Rejoins:            st.Rejoins,
		NoPathEpisodes:     st.NoPathEpisodes,
		InNoPath:           st.InNoPath,
		TxBytes:            st.TxBytes,
		AckedBytes:         st.AckedBytes,
		RxBytes:            st.RxBytes,
		DeliveredBytes:     st.DeliveredBytes,
		RetransmittedBytes: st.RetransmittedBytes,
		Window:             st.Window,
		PeerWindow:         st.PeerWindow,
		MaxPayload:         st.MaxPayload,
		DupBytes:           st.DupBytes,
		Race:               RaceCounters{CopyBytes: st.Race.CopyBytes, Copies: st.Race.Copies},
		EarlyBytes:         st.EarlyBytes,
	}
	if pc := st.Packet; pc != nil {
		out.Packet = &PacketCounters{
			Sent:          pc.Sent,
			Received:      pc.Received,
			Duplicates:    pc.Duplicates,
			DropQueue:     pc.DropQueue,
			DropAge:       pc.DropAge,
			DropTooLarge:  pc.DropTooLarge,
			DropNoPath:    pc.DropNoPath,
			DropRecvQueue: pc.DropRecvQueue,
			DropLate:      pc.DropLate,
			PeerReceived:  pc.PeerReceived,
		}
	}
	if len(st.Carriers) > 0 {
		out.Carriers = make([]CarrierStatus, len(st.Carriers))
		for i := range st.Carriers {
			out.Carriers[i] = carrierStatusFrom(&st.Carriers[i])
		}
	}
	return out
}

// carrierStatusFrom converts one lane of a session snapshot: its kind is
// the carrier's (Stats.Kind); a datagram carrier's counters are copied
// (M2-D61); the session's handle on the carrier and the carrier's view
// count (M3-D49).
func carrierStatusFrom(cs *session.CarrierStatus) CarrierStatus {
	return CarrierStatus{
		ID:          CarrierID(cs.ID),
		Name:        cs.Name,
		Kind:        kindFrom(cs.Stats.Kind),
		Gen:         cs.Gen,
		State:       CarrierState(cs.State),
		SRTT:        cs.Stats.SRTT,
		MinRTT:      cs.Stats.MinRTT,
		Rate:        cs.Stats.Rate,
		Inflight:    clampInt(cs.Stats.Inflight),
		Cap:         clampInt(cs.Stats.Cap),
		TxBytes:     cs.Stats.TxBytes,
		RxBytes:     cs.Stats.RxBytes,
		RetxBytes:   cs.Stats.RetxBytes,
		Frames:      cs.Stats.Frames,
		DeathCause:  Cause(cs.DeathCause),
		DeathDetail: cs.DeathDetail,
		MTU:         cs.Stats.MTU,
		Dropped:     cs.Stats.Dropped,
		Retransmits: cs.Stats.Retransmits,
		Rebinds:     cs.Stats.Rebinds,
		Handle:      cs.Stats.Handle,
		Shared:      cs.Stats.Shared,
	}
}

// kindFrom converts a session kind; zero (every M1 session) is a stream
// session.
func kindFrom(k wire.CarrierKind) Kind {
	if k == wire.KindDatagram {
		return KindPacket
	}
	return KindStream
}

// peerStatusFrom converts a health snapshot classified at now (Peer.Status,
// design §10.1). names are the Peer's factory names in configuration order.
// A nil snapshot (single-factory Peer, nothing published yet) reports every
// factory Unknown without probing.
func peerStatusFrom(snap *carrier.Snapshot, names []string, now time.Time) PeerStatus {
	out := PeerStatus{Factories: make([]FactoryStatus, len(names))}
	if snap == nil {
		for i, n := range names {
			out.Factories[i] = FactoryStatus{Name: n}
		}
		return out
	}
	out.Probing = snap.Probing
	for i, n := range names {
		var (
			ev     sched.Evidence
			failed bool
			info   carrier.FactoryInfo
		)
		if i < len(snap.Sum) {
			ev = snap.Evidence(i, now)
		}
		if i < len(snap.Failed) {
			failed = snap.Failed[i]
		}
		if i < len(snap.Info) {
			info = snap.Info[i]
		}
		out.Factories[i] = factoryStatusFrom(n, ev, failed, info)
	}
	return out
}

// factoryStatusFrom builds one FactoryStatus from classified evidence. RTT
// is the aggregated value of Fresh and Held evidence (0 for a Held path
// without a value, and for Unknown and Stale).
func factoryStatusFrom(name string, ev sched.Evidence, failed bool, info carrier.FactoryInfo) FactoryStatus {
	fs := FactoryStatus{
		Name:          name,
		Evidence:      Evidence(ev.State),
		Samples:       info.Samples,
		LoadedSamples: info.LoadedSamples,
		Failed:        failed,
		FailReason:    info.FailReason,
		ProbeCarrier:  CarrierID(info.ProbeCarrier),
		Attempts:      info.Attempts,
	}
	if ev.State == sched.EvFresh || ev.State == sched.EvHeld {
		fs.RTT = ev.RTT
	}
	return fs
}

// clampInt converts an int64 counter to int, saturating on 32-bit platforms.
func clampInt(v int64) int {
	if v > math.MaxInt {
		return math.MaxInt
	}
	if v < math.MinInt {
		return math.MinInt
	}
	return int(v)
}
