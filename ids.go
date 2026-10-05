package rendr

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// InstanceID identifies one Runtime incarnation: 128 random bits from
// crypto/rand drawn by NewRuntime, never persisted, never all zero. It is
// not an identity or a credential.
type InstanceID [16]byte

// String returns 32 lowercase hex digits.
func (id InstanceID) String() string { return hex.EncodeToString(id[:]) }

// IsZero reports the all-zero (invalid) ID.
func (id InstanceID) IsZero() bool { return id == InstanceID{} }

// SessionID identifies a session: chosen by the dialer from crypto/rand and
// reused by every OPEN and JOIN of that session.
type SessionID [16]byte

// String returns 32 lowercase hex digits.
func (id SessionID) String() string { return hex.EncodeToString(id[:]) }

// newInstanceID draws a Runtime's InstanceID from r (crypto/rand.Reader in
// production; plan §3.4): never all zero. The error is r's failure.
func newInstanceID(r io.Reader) (InstanceID, error) {
	id, err := randomID(r)
	return InstanceID(id), err
}

// newSessionID draws a dialer session ID from r (crypto/rand.Reader in
// production; L47): never all zero, which the OPEN decoder rejects.
func newSessionID(r io.Reader) (SessionID, error) {
	id, err := randomID(r)
	return SessionID(id), err
}

// errZeroIDs reports a random source that keeps producing the invalid
// all-zero ID (a broken or exhausted source, never crypto/rand).
var errZeroIDs = errors.New("rendr: random source produced only all-zero IDs")

// randomID reads 128 random bits from r, redrawing an all-zero value (at
// most 4 draws; crypto/rand yields zero with probability 2^-128).
func randomID(r io.Reader) ([16]byte, error) {
	var id [16]byte
	for range 4 {
		if _, err := io.ReadFull(r, id[:]); err != nil {
			return [16]byte{}, fmt.Errorf("rendr: drawing a random ID: %w", err)
		}
		if id != ([16]byte{}) {
			return id, nil
		}
	}
	return [16]byte{}, errZeroIDs
}

// CarrierID identifies a carrier incarnation: allocated by the dialer
// Runtime, never 0, never reused while in use in that Runtime.
type CarrierID uint32

// Mode is the scheduling mode of a session, fixed at OPEN.
type Mode uint8

// Modes. The zero Mode in DialOptions selects ModeSelector. Race (3)
// follows in milestone M3.
const (
	// ModeSelector: one active carrier at a time; quality switching by the
	// probe evidence; racing failover on death.
	ModeSelector Mode = 1
	// ModeBond: every member carrier carries data (capacity pull, rescue);
	// a dead member is redialled immediately. The dialer keeps one member
	// per factory of the Peer, up to the dialer's MaxCarriersPerSession. A
	// passive whose MaxCarriersPerSession is below that member count refuses
	// the surplus members, which are then redialled for the session's whole
	// life at intervals that grow to RejoinBackoffMax, so a Peer used for
	// bond sessions should not have more factories than the passive's
	// MaxCarriersPerSession.
	ModeBond Mode = 2
)

// String returns "selector", "bond" or "mode(N)".
func (m Mode) String() string {
	switch m {
	case ModeSelector:
		return "selector"
	case ModeBond:
		return "bond"
	}
	return "mode(" + itoa(uint64(m)) + ")"
}

// Kind is the session or carrier kind. Packet sessions and datagram
// carriers (value 2) follow in milestone M2.
type Kind uint8

// Kinds.
const KindStream Kind = 1

// String returns "stream" or "kind(N)".
func (k Kind) String() string {
	if k == KindStream {
		return "stream"
	}
	return "kind(" + itoa(uint64(k)) + ")"
}

// Role is the side of a session.
type Role uint8

// Roles.
const (
	RoleDialer  Role = 1 // dials carriers and decides scheduling for both directions
	RolePassive Role = 2 // accepts carriers and follows the dialer's scheduling updates (SCHED)
)

// String returns "dialer", "passive" or "role(N)".
func (r Role) String() string {
	switch r {
	case RoleDialer:
		return "dialer"
	case RolePassive:
		return "passive"
	}
	return "role(" + itoa(uint64(r)) + ")"
}

// State is a session's lifecycle state in Status.
type State uint8

// States.
const (
	StatePending State = 1 // passive: OPEN admitted, waiting for Confirm/Reject/AcceptTimeout
	StateOpen    State = 2 // data flows; may be inside a no-path episode (SessionStatus.InNoPath)
	StateClosing State = 3 // the application called Close; the session lingers to finish or reset
	StateEnded   State = 4 // terminal; SessionStatus.Err is the end error (io.EOF after a clean finish)
)

// String returns "pending", "open", "closing", "ended" or "state(N)".
func (s State) String() string {
	switch s {
	case StatePending:
		return "pending"
	case StateOpen:
		return "open"
	case StateClosing:
		return "closing"
	case StateEnded:
		return "ended"
	}
	return "state(" + itoa(uint64(s)) + ")"
}

// CarrierState is a carrier's role in a session.
type CarrierState uint8

// Carrier states.
const (
	CarrierJoining  CarrierState = 1 // OPEN_ACK/JOIN_ACK not exchanged yet: carries no DATA
	CarrierActive   CarrierState = 2 // selector: the data carrier
	CarrierMember   CarrierState = 3 // bond: a data member; selector: a live non-active carrier
	CarrierRetiring CarrierState = 4 // planned retirement: no new DATA; CLOSE when acknowledged or after RetireGrace
	CarrierDead     CarrierState = 5 // ended; DeathCause/DeathDetail say why (the last 8 are kept)
)

// String returns "joining", "active", "member", "retiring", "dead" or "carrier(N)".
func (s CarrierState) String() string {
	switch s {
	case CarrierJoining:
		return "joining"
	case CarrierActive:
		return "active"
	case CarrierMember:
		return "member"
	case CarrierRetiring:
		return "retiring"
	case CarrierDead:
		return "dead"
	}
	return "carrier(" + itoa(uint64(s)) + ")"
}

// Cause is why a carrier ended (CarrierStatus.DeathCause, EventCarrierDown)
// and, in EventMigration, why a session's data moved (see Event).
type Cause uint8

// Causes.
const (
	CauseNone              Cause = 0 // no cause; in EventMigration: a selector passive's death migration (see Event)
	CausePingTimeout       Cause = 1 // the oldest committed PING stayed unanswered beyond the death deadline
	CauseWriteStall        Cause = 2 // one batch write exceeded the stall window
	CauseTransportError    Cause = 3 // EOF, RST, read/write error, (0, nil), invalid counts, panic in the conn
	CauseProtocolViolation Cause = 4 // decode, CRC, fseq, ACK beyond sent, window overrun, conflicting FIN
	CauseInstanceMismatch  Cause = 5 // the carrier reached another rendr instance than the session's
	CauseGoAway            Cause = 6 // the peer sent GOAWAY
	CauseLocalClose        Cause = 7 // closed by this side
	CauseRetired           Cause = 8 // ended by a CLOSE (planned or the peer's); not a death; explicit in EventMigration
	CauseQuality           Cause = 9 // only in EventMigration: a selector quality switch
)

// String returns "ping_timeout", "write_stall", "transport_error",
// "protocol_violation", "instance_mismatch", "goaway", "local_close",
// "retired", "quality", or "none" for CauseNone and unknown values.
func (c Cause) String() string {
	switch c {
	case CausePingTimeout:
		return "ping_timeout"
	case CauseWriteStall:
		return "write_stall"
	case CauseTransportError:
		return "transport_error"
	case CauseProtocolViolation:
		return "protocol_violation"
	case CauseInstanceMismatch:
		return "instance_mismatch"
	case CauseGoAway:
		return "goaway"
	case CauseLocalClose:
		return "local_close"
	case CauseRetired:
		return "retired"
	case CauseQuality:
		return "quality"
	}
	return "none"
}

// EventKind identifies an Event.
type EventKind uint8

// Event kinds.
const (
	EventCarrierUp   EventKind = 1 // a carrier was confirmed (OPEN_ACK/JOIN_ACK exchanged)
	EventCarrierDown EventKind = 2 // a carrier ended (Cause)
	EventMigration   EventKind = 3 // a migration counted in SessionStatus.Migrations: From → To with Cause (see Event)
	EventNoPathStart EventKind = 4 // the session lost its last carrier
	EventNoPathEnd   EventKind = 5 // a carrier attached during a no-path episode
	EventSessionEnd  EventKind = 6 // the session ended (Err)
)

// String returns the event kind name ("carrier_up", ...).
func (k EventKind) String() string {
	switch k {
	case EventCarrierUp:
		return "carrier_up"
	case EventCarrierDown:
		return "carrier_down"
	case EventMigration:
		return "migration"
	case EventNoPathStart:
		return "no_path_start"
	case EventNoPathEnd:
		return "no_path_end"
	case EventSessionEnd:
		return "session_end"
	}
	return "event(" + itoa(uint64(k)) + ")"
}

// Evidence is a factory's probe evidence class in PeerStatus (see
// ProbePolicy and SelectorPolicy).
type Evidence uint8

// Evidence classes.
const (
	EvidenceUnknown Evidence = 0 // no probe sample since the probe carrier connected
	EvidenceFresh   Evidence = 1 // an unloaded sample within Probe.Fresh
	EvidenceHeld    Evidence = 2 // only samples loaded by this Peer's own traffic within Probe.Fresh
	EvidenceStale   Evidence = 3 // no sample within Probe.Fresh
)

// String returns "unknown", "fresh", "held" or "stale".
func (e Evidence) String() string {
	switch e {
	case EvidenceFresh:
		return "fresh"
	case EvidenceHeld:
		return "held"
	case EvidenceStale:
		return "stale"
	}
	return "unknown"
}

// Addr is the logical address of one end of a session. It never changes
// across migrations and never reveals carrier addresses.
type Addr struct {
	Instance InstanceID // the Runtime at this end
	Session  SessionID
}

// Network returns "rendr".
func (a Addr) Network() string { return "rendr" }

// String returns "<instance hex>/<session hex>".
func (a Addr) String() string { return a.Instance.String() + "/" + a.Session.String() }

func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
