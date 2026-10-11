//go:build linux && (amd64 || arm64)

package udpsocket

import (
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// accelerated: sendmmsg and recvmmsg exist on this target (M5-D8).
const accelerated = true

// mmsghdr is the kernel's struct mmsghdr: a msghdr and the byte count the
// call reports for that message (64 bytes on amd64 and arm64).
type mmsghdr struct {
	hdr unix.Msghdr
	len uint32
	_   [4]byte
}

// batchSys holds a Batch's kernel arrays — one header, one iovec and one
// socket address per message, allocated once in NewBatch — and the
// RawConn callbacks bound once as method values, with their per-call
// arguments and results as fields (R1-13: no closure per call).
type batchSys struct {
	hdrs  []mmsghdr
	iovs  []unix.Iovec
	names []unix.RawSockaddrInet6
}

func (s *batchSys) init(b *Batch) {
	s.hdrs = make([]mmsghdr, b.max)
	s.iovs = make([]unix.Iovec, b.max)
	s.names = make([]unix.RawSockaddrInet6, b.max)
}

// connSys is a socket's batch state: the time (Unix nanoseconds) of the
// last fd −1 probe that found the calls permitted, cached for 1 s (R1-3).
type connSys struct {
	permittedAt atomic.Int64
}

// sendmmsg sends the n prepared messages of b from index k on fd.
func sendmmsg(fd uintptr, b *Batch, k, n int) (int, error) { panic("WP1") }

// recvmmsg receives up to n messages into b's prepared slots on fd.
func recvmmsg(fd uintptr, b *Batch, n int) (int, error) { panic("WP1") }

// probe runs sendmmsg and recvmmsg on fd −1: nil (EBADF) = permitted;
// ENOSYS or EPERM = absent or denied.
func probe() error { panic("WP1") }

// writeBatch sends ms through sendmmsg on the netpoller (§A4.2, R1-3).
func (c *Conn) writeBatch(b *Batch, ms []Msg) (int, error) { panic("WP1") }

// readBatch receives into ms through recvmmsg on the netpoller (§A4.2).
func (c *Conn) readBatch(b *Batch, ms []Msg) (int, error) { panic("WP1") }
