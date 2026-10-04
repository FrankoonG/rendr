package rendr

import (
	"context"
	"net"
	"time"
)

// Source is where a Listener gets carriers from. The set is closed: M1 has
// FromListener; M2 adds FromPacketConn.
type Source interface{ isSource() }

type listenerSource struct{ l net.Listener }

func (listenerSource) isSource() {}

// FromListener is a pull source: one accept goroutine per source hands every
// accepted conn to the handshake. Ownership of l moves to the Listener, which
// closes it exactly once on Close. Temporary accept errors (EMFILE) back off
// 5 ms → 100 ms; one failing source never stops another (L50).
func FromListener(l net.Listener) Source { return listenerSource{l: l} }

// ListenConfig configures a Listener.
type ListenConfig struct {
	Sources       []Source      // may be empty: a push-only listener fed by Handle
	AcceptBacklog int           // 128; 1–65536: pending stream sessions of this Listener
	AcceptTimeout time.Duration // 10 s; 0.1 s–60 s: then OPEN_ACK(CAPACITY, accept timeout)
}

// Listener admits carriers and hands new stream sessions to the application
// for Confirm or Reject. Carriers of sessions that already exist (JOIN,
// duplicate OPEN) are routed by the Runtime, so a carrier may arrive on any
// source or Listener of the Runtime (L50).
type Listener struct {
	_ struct{} // unexported state is defined by the implementation
}

// Handle pushes one embedder-accepted carrier into the handshake and
// returns at once (the handshake runs on its own goroutine bounded by
// Handshake.Timeout). It returns net.ErrClosed after Close; c is then closed.
func (ln *Listener) Handle(c net.Conn) error {
	panic("unimplemented: M1b")
}

// Accept returns the next pending stream session, in admission order,
// skipping sessions that were withdrawn or timed out. It returns exactly one
// of (*PendingConn, nil) or (nil, err): ctx.Err() when ctx ends (the queue is
// untouched), net.ErrClosed after Close.
func (ln *Listener) Accept(ctx context.Context) (*PendingConn, error) {
	panic("unimplemented: M1b")
}

// Close stops the sources (closing every FromListener listener exactly
// once, bounded), answers every pending session OPEN_ACK(GOING_AWAY), and
// makes Accept and Handle return net.ErrClosed. Confirmed sessions are not
// affected. Idempotent.
func (ln *Listener) Close() error {
	panic("unimplemented: M1b")
}

// PendingConn is an admitted OPEN waiting for the application's decision.
// It holds a backlog slot until Confirm, Reject or AcceptTimeout.
type PendingConn struct {
	_ struct{} // unexported state is defined by the implementation
}

// ID returns the session ID.
func (p *PendingConn) ID() SessionID {
	panic("unimplemented: M1b")
}

// Mode returns the mode requested by the dialer.
func (p *PendingConn) Mode() Mode {
	panic("unimplemented: M1b")
}

// Metadata returns the dialer's OPEN metadata (owned by the PendingConn; do
// not modify).
func (p *PendingConn) Metadata() []byte {
	panic("unimplemented: M1b")
}

// PeerInstance returns the dialer's InstanceID.
func (p *PendingConn) PeerInstance() InstanceID {
	panic("unimplemented: M1b")
}

// Confirm accepts the session: OPEN_ACK(OK) goes out on every carrier that
// carried this OPEN, and the returned *Conn is the passive end. Errors:
// ErrSessionLost if the dialer withdrew, ErrCapacity if AcceptTimeout already
// answered, net.ErrClosed after Listener.Close or Runtime.Close, an error for
// a second decision.
func (p *PendingConn) Confirm() (*Conn, error) {
	panic("unimplemented: M1b")
}

// Reject refuses the session with OPEN_ACK(REJECTED, code, msg); msg is
// truncated to 255 bytes. The dialer's Dial returns *RejectError{code, msg};
// a retried OPEN gets the same answer. Errors as for Confirm.
func (p *PendingConn) Reject(code uint32, msg string) error {
	panic("unimplemented: M1b")
}
