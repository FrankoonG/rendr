package wire

import "encoding/binary"

// DOWN (M5 design, PA-86; F-7): the carrier-level frame that reports the
// death of another MUX trunk between the same two Runtimes.
//
//	DOWN = type 0x37 | flags 0 | len 4 | fseq | handle 0 | payload: carrierID u32 (≠ 0) | crc32c
//
// Meaning: the carrier with this dialer-assigned CarrierID, between the
// same two Runtimes as the trunk the DOWN arrives on, is dead at the
// sender's end. The pair is the receiving trunk's: the passive matches the
// dialer instance of the trunk's PREFACE, the dialer the passive instance of
// its PREFACE_ACK; CarrierIDs are the dialer's namespace, so a DOWN names
// only a trunk of the same direction as the trunk it travels on.
//
// It is legal only on an established MUX trunk, as DETACH is: REL-wrapped
// on datagram trunks, ordered by the byte stream on stream trunks. On a
// dedicated or probe carrier it is a protocol violation, and so is a DOWN
// that names the trunk it arrives on. The receiver kills its end of the
// live MUX trunk the ID names with the cause peer_down, as a local
// transport death; an unknown, dead, retiring or other-pair ID is ignored
// (a DOWN races the receiver's own detection). A side sends DOWN for its
// own trunk's death with any cause but retired, goaway and peer_down (the
// peer knows those), on every other live MUX trunk of the pair, ahead of
// the death's session frames.
//
// The codec knows DOWN like every other core type (Known, CarrierLevel,
// Wrappable, PayloadBounds, String, AllowedFlags 0); whether a carrier
// accepts it is the carrier's legality rule, not a header property.

// TypeDown reports the death of another MUX trunk of the pair
// (carrier-level: its frame handle is 0; the dead trunk's CarrierID is in
// the payload).
const TypeDown Type = 0x37

// DownLen is the exact DOWN payload size: carrierID u32.
const DownLen = 4

// PutDown writes the DOWN payload naming carrierID into dst and returns
// DownLen. The value is written as given (no validation, so tests can build
// invalid frames). It panics if dst is too small.
func PutDown(dst []byte, carrierID uint32) int {
	_ = dst[DownLen-1]
	binary.BigEndian.PutUint32(dst[0:DownLen], carrierID)
	return DownLen
}

// ParseDown decodes a DOWN payload: exactly DownLen bytes (ErrShort or
// ErrTrailing otherwise, as every fixed-size payload) and a CarrierID other
// than 0 (ErrValue: 0 is never a CarrierID). An error returns 0.
func ParseDown(p []byte) (carrierID uint32, err error) {
	if err := exactTail(len(p), DownLen); err != nil {
		return 0, err
	}
	id := binary.BigEndian.Uint32(p[0:DownLen])
	if id == 0 {
		return 0, ErrValue
	}
	return id, nil
}
