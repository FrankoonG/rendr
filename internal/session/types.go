package session

import (
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Mode is the scheduling mode fixed at OPEN (numerically equal to rendr.Mode).
type Mode uint8

// Modes.
const (
	ModeSelector Mode = 1
	ModeBond     Mode = 2
	ModeRace     Mode = 3 // every member carries every byte or datagram (M3-D28)
)

// Role is the session side (numerically equal to rendr.Role).
type Role uint8

// Roles.
const (
	RoleDialer  Role = 1
	RolePassive Role = 2
)

// State is the session lifecycle (numerically equal to rendr.State).
type State uint8

// States.
const (
	StatePending State = 1 // passive: OPEN admitted, waiting for Confirm/Reject/AcceptTimeout
	StateOpen    State = 2 // data flows (possibly inside a no-path episode)
	StateClosing State = 3 // the application called Close; linger delivers the rest
	StateEnded   State = 4 // terminal; Status().Err is the end error (io.EOF after a clean finish)
)

// LaneState is a carrier's role in a session (numerically equal to
// rendr.CarrierState).
type LaneState uint8

// Lane states.
const (
	LaneJoining  LaneState = 1 // handshake not exchanged / first response not yet written: carries no DATA (L22)
	LaneActive   LaneState = 2 // selector: the data carrier
	LaneMember   LaneState = 3 // bond: a data member; selector: a live non-active carrier
	LaneRetiring LaneState = 4 // planned retirement: no new DATA; CLOSE once acknowledged or after RetireGrace
	LaneDead     LaneState = 5 // ended; DeathCause says why (the last 8 are kept for Status)
)

// EventKind is numerically equal to rendr.EventKind.
type EventKind uint8

// Event kinds.
const (
	EventCarrierUp   EventKind = 1
	EventCarrierDown EventKind = 2
	EventMigration   EventKind = 3
	EventNoPathStart EventKind = 4
	EventNoPathEnd   EventKind = 5
	EventSessionEnd  EventKind = 6
)

// Event is converted 1:1 into rendr.Event (which adds Seq).
type Event struct {
	Kind              EventKind
	Session           [16]byte
	Carrier, From, To uint32
	Cause             carrier.Cause
	Err               error
	Time              time.Time // publication time (L09)
}

// EventSink receives events. Emit never blocks (it enqueues or counts a
// drop) and is never called with a session lock held.
type EventSink interface{ Emit(ev Event) }

// Verdict is what a passive session's tombstone answers to a later OPEN with
// the same (dialer InstanceID, sid) (L47; design decision D11).
type Verdict struct {
	Opened bool           // the session reached StateOpen: tombstone answers UNKNOWN_SESSION
	Status wire.AckStatus // never-opened sessions: REJECTED, CAPACITY or GOING_AWAY; a withdrawn one: UNKNOWN_SESSION
	Code   uint32
	Msg    string
}

// OpenAck returns the OPEN_ACK that repeats this verdict.
func (v Verdict) OpenAck() wire.OpenAck {
	if v.Opened {
		return wire.OpenAck{Status: wire.StatusUnknownSession}
	}
	return wire.OpenAck{Status: v.Status, Code: v.Code, Msg: []byte(v.Msg)}
}

// Registry is implemented by the root admission tables. Sessions call it
// without holding their lock.
type Registry interface {
	// Opened: a passive session left StatePending (counts move from Pending to Open).
	Opened(s *Session)
	// Lingering: the application closed the session (on) / the session ended (off).
	Lingering(s *Session, on bool)
	// Orphaned: a passive session entered (on) or left (off) a no-path episode.
	Orphaned(s *Session, on bool)
	// Ended: the session ended; the passive table entry becomes a tombstone
	// answering v for Params.TombstoneTTL; the session's MaxSessions unit is
	// released.
	Ended(s *Session, v Verdict)
}

// Params is the frozen per-session configuration (L20), built by package
// rendr from the normalized Runtime config, DialOptions and testhooks.
type Params struct {
	Role              Role
	Mode              Mode
	Window            int64                // local receive window W; also bounds the unacknowledged send buffer
	Grace             time.Duration        // dialer: NoPathGrace; passive: PassiveRetain from OPEN (clamped 1 s..400 s)
	Retain            time.Duration        // dialer: PassiveRetain announced in OPEN (Grace + PingIdle + DeadMax + slack)
	BackoffMax        time.Duration        // session redial cap: min(RejoinBackoffMax, Grace/2)
	JoinStagger       time.Duration        // failover and opening race stagger
	RetireGrace       time.Duration        // planned switch: old carrier's retirement bound
	Linger            time.Duration        // Close: background delivery bound, then RST
	IdleTimeout       time.Duration        // 0 = off
	AcceptTimeout     time.Duration        // passive pending sessions (Listener's AcceptTimeout)
	Selector          sched.SelectorParams // dialer selector quality policy
	MaxCarriers       int                  // MaxCarriersPerSession
	AckEvery          int                  // ACK after this many delivered bytes (64 KiB)
	AckDelay          time.Duration        // ... or this long after the first unacknowledged delivery (20 ms)
	RescueMin         time.Duration        // bond rescue threshold floor (300 ms)
	WindowReadvertise time.Duration        // re-advertise cadence while the advertised window is < 64 KiB (200 ms)
	FirstOffset       uint64               // first stream offset (testhooks preset; 0)
	OffsetLimit       uint64               // stream offset limit (2^62, L14)
	FirstEpoch        uint32               // first SCHED epoch (1)
	TombstoneTTL      time.Duration        // passive: Grace + Linger

	// Kind is the session kind: wire.KindStream (zero means stream: every
	// M1 session) or wire.KindDatagram for a packet session (M2-D1).
	Kind wire.CarrierKind
	// Packet is the frozen packet configuration (packet sessions only).
	Packet PacketParams

	// ActorLinger: the actor parks after this long without a step that did
	// work (M3-D42; 0 = 1 s; testhooks.ActorLinger).
	ActorLinger time.Duration
	// Actors is the Runtime's gauge of running actor goroutines
	// (rendr.Status.Actors, M3-D44); nil: not counted.
	Actors *atomic.Int64
}

// PacketParams is the frozen configuration of a packet session (M2-D1),
// from Config.Packet, Config.PacketPing and testhooks.
type PacketParams struct {
	// MaxPayload: dialer — the offer computed from the factory snapshot
	// (M2-D49); passive — the accepted value. The session's fixed value is
	// set when the OPEN exchange completes (Session.MaxPayload).
	MaxPayload int
	Queue      int           // Packet.Queue: bytes per direction (and Queue/64 datagrams)
	MaxAge     time.Duration // Packet.MaxAge: a datagram not placed within this is dropped
	PacketPing time.Duration // PACK delay after the first unreported datagram (Config.PacketPing)
	PackEvery  int           // PACK after this many datagrams (256)
	FinWaitMax time.Duration // upper clamp of the EOF straggler wait (1 s)
	DedupBits  int           // receive dedup window (wire.DefaultSeqWindowBits)
	FirstSeq   uint64        // first seq in each direction (testhooks preset; 0); the limit is OffsetLimit (L14)
}

// Env holds the Runtime-wide services a session uses.
type Env struct {
	Carrier  *carrier.Env
	Events   EventSink
	Registry Registry
	Rand     func() float64   // U[0,1) jitter source
	Hooks    *testhooks.Hooks // nil in production
}
