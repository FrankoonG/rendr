package carrier

import "time"

// The passive datagram handshake (M2-D19…M2-D22; M2 design §A5.10).

// dgHandshake holds what a started datagram carrier keeps of its handshake:
// the PREFACE it accepted (passive: duplicate detection) or the PREFACE_ACK
// it read (dialer), the stored H2 datagram and the "repeat H2" flag set by
// the reader for the writer (dgestablish.go, dghello.go).
type dgHandshake struct{}

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
