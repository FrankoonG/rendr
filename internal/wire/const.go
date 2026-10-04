package wire

// Sizes and limits of wire format v2 (plan §5).
const (
	// Major is the wire major version; a PREFACE with another major is
	// answered PREFACE_ACK(VERSION).
	Major = 2
	// Minor is the wire minor version this build sends. Receivers ignore it.
	Minor = 0

	// PrefaceLen is the fixed size of PREFACE and PREFACE_ACK.
	PrefaceLen = 40
	// HeaderLen is the frame header size: type, flags, len (u24), fseq, handle.
	HeaderLen = 13
	// TrailerLen is the CRC32C trailer size.
	TrailerLen = 4
	// FrameOverhead is the per-frame overhead (header + trailer).
	FrameOverhead = HeaderLen + TrailerLen
	// MaxFramePayload is the hard payload limit, checked before any read or
	// allocation sized by a frame length.
	MaxFramePayload = 1 << 20

	// DataPrefixLen is the DATA payload prefix (the u64 stream offset).
	DataPrefixLen = 8
	// DataHeadLen is what a writer encodes in front of DATA bytes:
	// the header plus the offset.
	DataHeadLen = HeaderLen + DataPrefixLen

	// OpenFixedLen is the OPEN payload without metadata.
	OpenFixedLen = 32
	// OpenAckFixedLen is the OPEN_ACK payload without its message.
	OpenAckFixedLen = 10
	// JoinLen is the exact JOIN payload size.
	JoinLen = 25
	// JoinAckLen is the exact JOIN_ACK payload size.
	JoinAckLen = 9
	// AckLen is the exact ACK payload size.
	AckLen = 16
	// FinLen is the exact FIN payload size.
	FinLen = 8
	// RstFixedLen is the RST payload without its message.
	RstFixedLen = 5
	// SchedFixedLen is the SCHED payload without carrier IDs: epoch u32,
	// the three migration counts u64 and n u8.
	SchedFixedLen = 29
	// PingFixedLen is the PING/PONG payload without padding.
	PingFixedLen = 20
	// ReasonLen is the exact CLOSE and GOAWAY payload size.
	ReasonLen = 1

	// MaxSchedIDs bounds the carrier IDs of one SCHED (= max MaxCarriersPerSession).
	MaxSchedIDs = 16
	// MaxMsg bounds OPEN_ACK and RST messages (u8 length).
	MaxMsg = 255
	// MaxMetadata is the largest OPEN metadata the format can carry (u16 length).
	MaxMetadata = 65535
	// MaxPingPad bounds PING/PONG zero padding so that a padded PING payload
	// fits in 64 KiB.
	MaxPingPad = 64<<10 - PingFixedLen

	// FirstFseq is the conventional first fseq of test vectors and scripted
	// peers. A carrier direction starts at PrefaceFseq of the PREFACE or
	// PREFACE_ACK that opened it (design §0.13 A6) unless a test preset
	// fixes it.
	FirstFseq uint32 = 1
	// SessionHandle is the handle every session frame uses in M1 (one
	// session per carrier, chosen by the dialer, echoed by the passive).
	// ParseHeader rejects a session frame with any other handle (ErrHandle).
	SessionHandle uint32 = 1
	// KnownRequired is the set of required PREFACE feature bits this build
	// implements (none). Any other required bit is answered FEATURE.
	KnownRequired uint32 = 0
)

// Magic starts every PREFACE and PREFACE_ACK.
var Magic = [4]byte{'R', 'N', 'D', '2'}

// CarrierKind is byte 6 of a PREFACE.
type CarrierKind uint8

// Carrier kinds. M1 accepts only KindStream.
const (
	KindStream   CarrierKind = 1
	KindDatagram CarrierKind = 2
)

// Role is byte 7 of a PREFACE (dialer) or PREFACE_ACK (passive).
type Role uint8

// Roles.
const (
	RoleDialer  Role = 1
	RolePassive Role = 2
)

// PrefaceStatus is byte 6 of a PREFACE_ACK.
type PrefaceStatus uint8

// PREFACE_ACK statuses.
const (
	PrefaceOK        PrefaceStatus = 0
	PrefaceVersion   PrefaceStatus = 1
	PrefaceFeature   PrefaceStatus = 2
	PrefaceGoingAway PrefaceStatus = 3
	PrefaceCapacity  PrefaceStatus = 4
)

// Type is the frame type byte. 0x01–0x7F are core types (unknown ones kill
// the carrier); 0x80–0xFF are ignorable extensions: only their length is
// checked before the payload is read, their flags and handle are opaque,
// and every carrier (session, probe or sessionless) skips them after the
// CRC check (plan §5).
type Type uint8

// Frame types used by M1 stream sessions. 0x20 DGRAM, 0x21 PACK, 0x34 REL
// and 0x35 RACK are reserved for M2; decoding them in M1 yields ErrType.
const (
	TypeOpen    Type = 0x01
	TypeOpenAck Type = 0x02
	TypeJoin    Type = 0x03
	TypeJoinAck Type = 0x04
	TypeData    Type = 0x10
	TypeAck     Type = 0x11
	TypeFin     Type = 0x12
	TypeRst     Type = 0x13
	TypeSched   Type = 0x14
	TypePing    Type = 0x30
	TypePong    Type = 0x31
	TypeClose   Type = 0x32
	TypeGoAway  Type = 0x33
)

// Extension reports whether t is in the ignorable extension range (≥ 0x80).
func (t Type) Extension() bool { return t >= 0x80 }

// CarrierLevel reports whether t is a carrier-level core type (PING, PONG,
// CLOSE, GOAWAY), whose handle must be 0. Every other core type is a
// session frame whose handle must be SessionHandle: an M1 carrier carries
// exactly one session (M3's mux relaxes this to any non-zero handle,
// dispatched by handle). ParseHeader enforces both rules (ErrHandle). The
// handle of an extension type is opaque and never checked.
func (t Type) CarrierLevel() bool {
	return t == TypePing || t == TypePong || t == TypeClose || t == TypeGoAway
}

// Known reports whether t is one of the 13 core types M1 implements.
func (t Type) Known() bool {
	switch t {
	case TypeOpen, TypeOpenAck, TypeJoin, TypeJoinAck, TypeData, TypeAck, TypeFin,
		TypeRst, TypeSched, TypePing, TypePong, TypeClose, TypeGoAway:
		return true
	}
	return false
}

// String returns the frame type name ("OPEN", "ACK", ...) or "0xNN".
func (t Type) String() string {
	switch t {
	case TypeOpen:
		return "OPEN"
	case TypeOpenAck:
		return "OPEN_ACK"
	case TypeJoin:
		return "JOIN"
	case TypeJoinAck:
		return "JOIN_ACK"
	case TypeData:
		return "DATA"
	case TypeAck:
		return "ACK"
	case TypeFin:
		return "FIN"
	case TypeRst:
		return "RST"
	case TypeSched:
		return "SCHED"
	case TypePing:
		return "PING"
	case TypePong:
		return "PONG"
	case TypeClose:
		return "CLOSE"
	case TypeGoAway:
		return "GOAWAY"
	}
	const hex = "0123456789abcdef"
	return string([]byte{'0', 'x', hex[t>>4], hex[t&0x0f]})
}

// Header flag bits. Undefined bits must be 0 (ErrFlags). Bits are per type.
const (
	// FlagAckFinDelivered (ACK): the sender of the ACK has delivered the
	// receiver's FIN to its application (rRead reached the FIN offset).
	FlagAckFinDelivered uint8 = 1 << 0
	// FlagAckDone (ACK): design §4.7 DONE — the sender's FIN is acknowledged
	// and the receiver's FIN is delivered; this is the sender's last session
	// frame. A session ends after it has sent DONE and received DONE.
	FlagAckDone uint8 = 1 << 1
	// FlagPingBusy (PING): the sender's writer on this carrier was
	// send-backlogged during the last PING interval (self-load guard, §8).
	// PONG flags are always 0.
	FlagPingBusy uint8 = 1 << 0
	// SchedCauseMask (SCHED): the low two flag bits carry the SchedCause of
	// the change so both ends count migrations identically.
	SchedCauseMask uint8 = 0x03
)

// SchedCause is carried in the SCHED header flags (SchedCauseMask).
type SchedCause uint8

// SCHED causes.
const (
	SchedInitial  SchedCause = 0 // first SCHED of a session, or membership growth
	SchedDeath    SchedCause = 1 // the previous active (selector) or a member (bond) died
	SchedQuality  SchedCause = 2 // selector quality switch
	SchedExplicit SchedCause = 3 // planned retirement requested by the peer (CLOSE, GOAWAY)
)

// AllowedFlags returns the flag bits defined for core type t (0 for core
// types without flags). Extension flags are opaque: every bit is allowed.
func AllowedFlags(t Type) uint8 {
	if t.Extension() {
		return 0xFF
	}
	switch t {
	case TypeAck:
		return FlagAckFinDelivered | FlagAckDone
	case TypePing:
		return FlagPingBusy
	case TypeSched:
		return SchedCauseMask
	}
	return 0
}

// AckStatus is the status byte of OPEN_ACK and JOIN_ACK.
type AckStatus uint8

// OPEN_ACK / JOIN_ACK statuses.
const (
	StatusOK             AckStatus = 0
	StatusUnknownSession AckStatus = 1
	StatusCapacity       AckStatus = 2
	StatusRejected       AckStatus = 3
	StatusBadRequest     AckStatus = 4
	StatusGoingAway      AckStatus = 5
)

// Reason codes carried in OPEN_ACK.code for non-application statuses
// (design decision D10). REJECTED carries the application's own code.
const (
	CodeBadMode       uint32 = 1 // BAD_REQUEST: unknown mode, or JOIN mode differs from the session
	CodeBadKind       uint32 = 2 // BAD_REQUEST: kind is not stream (M1)
	CodeMetadataSize  uint32 = 3 // BAD_REQUEST: mlen exceeds the passive's MaxMetadata → ErrMetadataTooLarge
	CodeBadValue      uint32 = 4 // BAD_REQUEST: reserved flags, pmtu or another field out of range
	CodeMaxSessions   uint32 = 1 // CAPACITY: the passive Runtime is at MaxSessions
	CodeBacklog       uint32 = 2 // CAPACITY: the Listener's AcceptBacklog is full
	CodeAcceptTimeout uint32 = 3 // CAPACITY: the application did not Confirm within AcceptTimeout
	CodeCarriers      uint32 = 4 // CAPACITY: the session already holds MaxCarriersPerSession carriers
	CodeAbandoned     uint32 = 5 // CAPACITY: the passive's abandoned-call pool is full
)

// RST codes below 256 are reserved for rendr; rendr.AbortCode values equal
// them.
const (
	RstClosed    uint32 = 1 // the peer application closed while this side still sent to it (TCP close() semantics)
	RstLinger    uint32 = 2 // the sender's Linger expired before its data and FIN were delivered
	RstGoingAway uint32 = 3 // the sender's Runtime is closing
	RstExhausted uint32 = 4 // a stream offset reached the offset limit (2^62, L14)
	RstIdle      uint32 = 5 // the sender's IdleTimeout expired
	RstWithdrawn uint32 = 6 // the dialer abandoned Dial after its OPEN may have been admitted (L49)
)

// OpenFlagEarly is OPEN flag bit 0 (early data). It is reserved until M4 and
// must be 0 (ErrReserved).
const OpenFlagEarly uint16 = 1 << 0

// CloseReason is the CLOSE payload.
type CloseReason uint8

// CLOSE reasons.
const (
	CloseRetire   CloseReason = 1 // planned retirement: no new frames follow; drain, then close
	CloseCapacity CloseReason = 2 // passive sessionless pool full (plan §3.5)
)

// GoAwayReason is the GOAWAY payload.
type GoAwayReason uint8

// GOAWAY reasons.
const GoAwayShutdown GoAwayReason = 1 // the sending instance is closing
