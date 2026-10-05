package carrier

import (
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// The passive datagram handshake (M2-D19…M2-D22; M2 design §A5.10).

// dgHandshake holds what a started datagram carrier keeps of its handshake:
// the PREFACE it accepted (passive: duplicate detection) or the PREFACE_ACK
// it read (dialer), the stored H2 datagram and the "repeat H2" flag set by
// the reader for the writer (dgestablish.go, dghello.go). WP3b owns its
// layout; the reader and writer (WP3a) use only repeatH2, dupH1 and h2 (M2
// design §A11.5; Revision 1, R1-20).
type dgHandshake struct {
	// repeatH2 (under Conn.mu) is set by the passive reader for a duplicate
	// H1 and cleared by the writer, which writes the stored H2 datagram
	// first and alone in its next round (M2-D19).
	repeatH2 bool
}

// dupH1 reports whether rendr bytes (a datagram after its flow header)
// start with the PREFACE this passive carrier accepted: a duplicate H1,
// answered with the stored H2. Always false on a dialer.
func (h *dgHandshake) dupH1(rendr []byte) bool {
	panic("unimplemented: M2")
}

// h2 returns the stored H2 rendr bytes (PREFACE_ACK ‖ RACK{FirstCseq}, or
// ‖ PONG for a probe) that the writer repeats verbatim; nil on a dialer.
func (h *dgHandshake) h2() []byte {
	panic("unimplemented: M2")
}

// dgWriteAndClose is Conn.WriteAndClose on an unstarted datagram Conn (M2
// design §A5.10 "Verdicts", M2-D21): the passive's first REL,
// REL{FirstCseq, t(flags, handle, payload)}, at the next tx fseq, written
// by the closer and then retransmitted on the RTO schedule (a new outer
// frame around the same REL payload) until a RACK covering it arrives or
// min(deadline, now + 2 s); a duplicate H1 meanwhile gets the stored H2
// and the verdict again; then the PacketIO closes through ncClose. The
// death record becomes CauseLocalClose; bounded and abandoned like
// closeWriteOne (V2 last resort). WP3b implements it.
func (c *Conn) dgWriteAndClose(t wire.Type, flags uint8, handle uint32, payload []byte, deadline time.Time) {
	panic("unimplemented: M2")
}

// ReadHelloDatagram is ReadHello for a datagram carrier (M2-D19; M2 design
// §A5.10): it reads datagrams from io under deadline until one is a complete
// valid H1 — a PREFACE of kind datagram followed by exactly one first frame,
// REL{FirstCseq, OPEN or JOIN} or a bare PING with zero pad, at the
// PREFACE's first fseq — and drops and counts every other datagram without
// creating state (plan:324). ErrMajor and ErrFeature are answered
// PREFACE_ACK(VERSION or FEATURE), the gate's refusal PREFACE_ACK(CAPACITY
// or GOING_AWAY), statelessly and for each duplicate H1 for at most 2 s
// (M2-D21); then io is closed and an error returned. On success it writes
// H2 = PREFACE_ACK(OK) ‖ RACK{FirstCseq} (a probe: PREFACE_ACK(OK) ‖ PONG),
// keeps it for duplicates and returns the unstarted Conn with the Hello
// fields of ReadHello (MetaTooLarge for an OPEN whose metadata exceeds
// maxMeta). Every failure closes io exactly once.
func ReadHelloDatagram(env *Env, io PacketIO, deadline time.Time, maxMeta int, gate Gate) (*Hello, error) {
	panic("unimplemented: M2")
}
