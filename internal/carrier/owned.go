package carrier

import (
	"net"
	"syscall"
	"time"
)

// OwnedTCP is the ownership token of a TCP socket that rendr itself created
// (plan §7, L57): only package carrier/tcp constructs it. The batch writer
// uses zero-copy vectored writes (net.Buffers → writev) and the teardown
// uses CloseWrite only on an *OwnedTCP; every other net.Conn gets exactly one
// coalesced Write per batch and is never type-asserted for extra methods, so
// an embedder's wrapper can never be bypassed.
type OwnedTCP struct {
	c *net.TCPConn
}

// NewOwnedTCP wraps c, which the caller created and configured (keepalive
// disabled on both ends, TCP_NODELAY on). Ownership of c moves to the result.
func NewOwnedTCP(c *net.TCPConn) *OwnedTCP { return &OwnedTCP{c: c} }

// Read implements net.Conn.
func (o *OwnedTCP) Read(p []byte) (int, error) { return o.c.Read(p) }

// Write implements net.Conn.
func (o *OwnedTCP) Write(p []byte) (int, error) { return o.c.Write(p) }

// Close implements net.Conn.
func (o *OwnedTCP) Close() error { return o.c.Close() }

// CloseWrite half-closes the socket (teardown order of L05).
func (o *OwnedTCP) CloseWrite() error { return o.c.CloseWrite() }

// LocalAddr implements net.Conn.
func (o *OwnedTCP) LocalAddr() net.Addr { return o.c.LocalAddr() }

// RemoteAddr implements net.Conn.
func (o *OwnedTCP) RemoteAddr() net.Addr { return o.c.RemoteAddr() }

// SetDeadline implements net.Conn.
func (o *OwnedTCP) SetDeadline(t time.Time) error { return o.c.SetDeadline(t) }

// SetReadDeadline implements net.Conn.
func (o *OwnedTCP) SetReadDeadline(t time.Time) error { return o.c.SetReadDeadline(t) }

// SetWriteDeadline implements net.Conn.
func (o *OwnedTCP) SetWriteDeadline(t time.Time) error { return o.c.SetWriteDeadline(t) }

// SyscallConn exposes the raw socket for socket-option tests (L26).
func (o *OwnedTCP) SyscallConn() (syscall.RawConn, error) { return o.c.SyscallConn() }

// WriteBuffers writes bufs with one vectored write (writev on Unix, WSASend
// on Windows) and consumes them like net.Buffers.WriteTo.
func (o *OwnedTCP) WriteBuffers(bufs *net.Buffers) (int64, error) { return bufs.WriteTo(o.c) }
