package transport

import (
	"context"
	"net"
)

// PathSessionKind states which rendr application contract a framed listener
// can safely carry. It describes framing semantics, not the network carrier.
type PathSessionKind uint8

const (
	// PathSessionAny accepts both stream and packet rendr sessions.
	PathSessionAny PathSessionKind = iota
	// PathSessionStream accepts only net.Conn-style rendr sessions.
	PathSessionStream
	// PathSessionPacket accepts only net.PacketConn-style rendr sessions.
	PathSessionPacket
)

// PathListener accepts paths that already implement rendr transport framing,
// quality reporting, and death notification. AcceptPath must honor ctx and
// return a non-nil PathConn on success. Close must promptly unblock any
// concurrent AcceptPath call without invalidating paths already returned. A
// Runtime invokes AcceptPath serially per listener, may retry after a context
// deadline, and owns each successfully returned path. SessionKind must return
// a valid, immutable factual contract.
type PathListener interface {
	AcceptPath(context.Context) (PathConn, error)
	SessionKind() PathSessionKind
	Close() error
	Addr() net.Addr
}
