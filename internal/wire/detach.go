package wire

import "encoding/binary"

// DETACH (M3 design §A3.4, M3-D6): the carrier-level frame that ends one
// handle of a MUX trunk without touching the trunk or the other handles.
//
//	DETACH = type 0x36 | flags 0 | len 5 | fseq | handle 0 | payload: handle u32 (≠ 0) · reason u8 | crc32c
//
// It is legal only on a MUX trunk (a dedicated carrier treats it as a
// violation), REL-wrapped on datagram trunks and ordered by the byte stream
// on stream trunks. A side places at most one DETACH per handle and nothing
// for that handle after it. The reason is informational: DETACH ends the
// view and never changes session state (M3 design Revision 1, R1-5). A
// refusal response (OPEN_ACK or JOIN_ACK not OK) ends its handle without a
// DETACH (M3-D7).
//
// The codec knows DETACH like every other core type (Known, CarrierLevel,
// Wrappable, PayloadBounds, String); whether a carrier accepts it is the
// carrier's legality rule (§A3.3), not a header property.

// TypeDetach ends one handle of a MUX trunk (carrier-level: its frame
// handle is 0; the ended handle is in the payload).
const TypeDetach Type = 0x36

// DetachLen is the exact DETACH payload size: handle u32 · reason u8.
const DetachLen = 5

// DetachReason is the DETACH reason byte.
type DetachReason uint8

// DETACH reasons. Any other value is ErrValue.
const (
	// DetachEnded: the session ended or abandoned the view.
	DetachEnded DetachReason = 1
	// DetachRetired: a planned lane retirement (selector quality switch,
	// the echo rule of a planned packet switch).
	DetachRetired DetachReason = 2
)

// Detach is the DETACH payload.
type Detach struct {
	Handle uint32       // the handle that ends; never 0
	Reason DetachReason // DetachEnded or DetachRetired
}

// PutDetach writes d into dst and returns DetachLen. The fields are written
// as given (no validation, so tests can build invalid frames). It panics if
// dst is too small.
func PutDetach(dst []byte, d *Detach) int {
	_ = dst[DetachLen-1]
	binary.BigEndian.PutUint32(dst[0:4], d.Handle)
	dst[4] = uint8(d.Reason)
	return DetachLen
}

// ParseDetach decodes a DETACH payload: exactly DetachLen bytes (ErrShort
// or ErrTrailing otherwise, as every fixed-size payload), a handle other
// than 0 and a reason of 1 or 2 (else ErrValue). An error returns the zero
// Detach.
func ParseDetach(p []byte) (Detach, error) {
	if err := exactTail(len(p), DetachLen); err != nil {
		return Detach{}, err
	}
	d := Detach{Handle: binary.BigEndian.Uint32(p[0:4]), Reason: DetachReason(p[4])}
	if d.Handle == 0 || d.Reason < DetachEnded || d.Reason > DetachRetired {
		return Detach{}, ErrValue
	}
	return d, nil
}
