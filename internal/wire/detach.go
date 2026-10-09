package wire

// DETACH (M3 design §A3.4, M3-D6): the carrier-level frame that ends one
// handle of a MUX trunk without touching the trunk or the other handles.
//
//	DETACH = type 0x36 | flags 0 | len 5 | fseq | handle 0 | payload: handle u32 (≠ 0) · reason u8 | crc32c
//
// It is legal only on a MUX trunk (a dedicated carrier treats it as a
// violation), REL-wrapped on datagram trunks and ordered by the byte stream
// on stream trunks. A side places at most one DETACH per handle and nothing
// for that handle after it. The reason is informational: DETACH ends the
// view and never changes session state (M3 design Revision 1, R1-5).
//
// Until the M3 wire work package implements the codec and flips Known,
// CarrierLevel and Wrappable, a received 0x36 stays an unknown core type
// (ErrType), so an M3 build keeps M2's wire behaviour.

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
	panic("unimplemented: M3")
}

// ParseDetach decodes a DETACH payload: exactly DetachLen bytes (ErrShort
// or ErrTrailing otherwise, as every fixed-size payload), a handle other
// than 0 and a reason of 1 or 2 (else ErrValue).
func ParseDetach(p []byte) (Detach, error) {
	panic("unimplemented: M3")
}
