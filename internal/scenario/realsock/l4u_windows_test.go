//go:build windows

package realsock

import (
	"net"
	"syscall"
	"unsafe"
)

// l4uConnResetOn switches Winsock's SIO_UDP_CONNRESET back on for c (the
// L4 UDP rows' stimulus only, M6 design §A16.3). The net package switches
// it off on every UDP socket it makes (net/fd_windows.go), so that an ICMP
// port unreachable never fails a later read; switched on, a datagram that
// drew one fails the socket's next read with WSAECONNRESET.
func l4uConnResetOn(c *net.UDPConn) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var ierr error
	if err := rc.Control(func(fd uintptr) {
		on, ret := uint32(1), uint32(0)
		ierr = syscall.WSAIoctl(syscall.Handle(fd), syscall.SIO_UDP_CONNRESET, (*byte)(unsafe.Pointer(&on)), uint32(unsafe.Sizeof(on)), nil, 0, &ret, nil, 0)
	}); err != nil {
		return err
	}
	return ierr
}
