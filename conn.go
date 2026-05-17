package rendr

import "net"

// Conn is a stream-oriented rendr connection. It is a net.Conn that
// survives underlying path changes.
//
// Hard contract (CLAUDE.md, hard rule #1): no Read/Write/Close on this
// interface returns an error caused by a migration. A migration in
// flight may pause individual Read/Write calls but never surfaces a
// reset / SO_ERROR / read-zero / write-error. If the migration budget
// (90s) elapses without a usable path, Read/Write will then return a
// real error and the Conn is dead.
type Conn interface {
	net.Conn

	// Paths returns a snapshot of the currently-attached path set.
	Paths() []PathInfo

	// SetMode atomically switches the operational mode.
	// Some transitions are illegal at runtime: race → bond is rejected
	// (race has no per-path sequencing; bond requires it). bond → prime
	// and prime ↔ race are allowed. SetMode returns nil on success or
	// an error describing the rejection cause.
	SetMode(Mode) error

	// FlowID returns the 16-byte flow identifier assigned at handshake.
	// It is invariant for the Conn's lifetime (see docs/architecture.md
	// "不变量").
	FlowID() [16]byte
}

// PacketConn is the datagram analogue of Conn.
type PacketConn interface {
	net.PacketConn

	Paths() []PathInfo
	SetMode(Mode) error
	FlowID() [16]byte
}
