package wire

import "errors"

// Decoding errors. Every one of them is a protocol violation when it occurs
// on an established carrier (the carrier is killed; the session survives).
var (
	// ErrShort: the input is shorter than the structure requires.
	ErrShort = errors.New("rendr/wire: short input")
	// ErrTrailing: bytes remain after a complete fixed-size structure.
	ErrTrailing = errors.New("rendr/wire: trailing bytes")
	// ErrMagic: a PREFACE that does not start with "RND2" (v1, msess or not
	// rendr at all). The passive closes without answering.
	ErrMagic = errors.New("rendr/wire: not a rendr preface")
	// ErrMajor: a PREFACE or PREFACE_ACK with valid magic and CRC but an
	// unsupported major version; the passive answers PREFACE_ACK(VERSION),
	// the dialer reports ErrVersion.
	ErrMajor = errors.New("rendr/wire: unsupported major version")
	// ErrFeature: a well-formed PREFACE (or PREFACE_ACK) requiring an unknown
	// feature bit; the passive answers PREFACE_ACK(FEATURE), the dialer
	// reports ErrVersion.
	ErrFeature = errors.New("rendr/wire: unknown required feature")
	// ErrMalformed: a structural error (role, kind, zero instance, zero
	// carrier ID, bad enumeration in a preface).
	ErrMalformed = errors.New("rendr/wire: malformed")
	// ErrCRC: CRC32C mismatch.
	ErrCRC = errors.New("rendr/wire: crc mismatch")
	// ErrType: an unknown core frame type (0x01–0x7F), including M2 types.
	ErrType = errors.New("rendr/wire: unknown core frame type")
	// ErrFlags: an undefined flag bit is set.
	ErrFlags = errors.New("rendr/wire: undefined flag bits")
	// ErrHandle: a session frame whose handle is not SessionHandle, or a
	// carrier-level frame whose handle is not 0.
	ErrHandle = errors.New("rendr/wire: bad handle")
	// ErrLength: a length outside the type's bounds or beyond MaxFramePayload.
	ErrLength = errors.New("rendr/wire: bad length")
	// ErrReserved: a reserved field or bit is not zero.
	ErrReserved = errors.New("rendr/wire: reserved field not zero")
	// ErrValue: an enumerated or numeric field is out of range.
	ErrValue = errors.New("rendr/wire: value out of range")
)
