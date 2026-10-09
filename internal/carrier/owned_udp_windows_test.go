package carrier

import (
	"errors"
	"net"
	"syscall"
	"testing"
	"unsafe"
)

// wp5ErrnoCases returns this OS's rows of the error table of rendr's own UDP
// sockets (M2 design §A6.4; Winsock numbers from winerror.h): the noise
// errnos, the abort, the too-large errno and some permanent ones. No errno
// is noise on a write only here.
func wp5ErrnoCases() wp5Errnos {
	return wp5Errnos{
		noise: []error{
			syscall.Errno(10061), // WSAECONNREFUSED
			syscall.Errno(10054), // WSAECONNRESET
			syscall.Errno(10052), // WSAENETRESET
			syscall.Errno(10065), // WSAEHOSTUNREACH
			syscall.Errno(10051), // WSAENETUNREACH
			syscall.Errno(10064), // WSAEHOSTDOWN
			syscall.Errno(10055), // WSAENOBUFS
		},
		abort:   syscall.Errno(10053), // WSAECONNABORTED
		msgSize: syscall.Errno(10040), // WSAEMSGSIZE
		others: []error{
			syscall.Errno(10038), // WSAENOTSOCK
			syscall.Errno(10022), // WSAEINVAL
			syscall.Errno(10013), // WSAEACCES
			syscall.Errno(10049), // WSAEADDRNOTAVAIL
		},
	}
}

// wp5CheckOSTruncation pins how Windows reports a datagram longer than the
// read buffer (plan:638): the buffer is filled and the read fails with
// WSAEMSGSIZE.
func wp5CheckOSTruncation(t *testing.T, n, bufLen, flags int, err error) {
	t.Helper()
	if !errors.Is(err, syscall.Errno(10040)) || n != bufLen {
		t.Fatalf("truncated read: n %d of %d, flags %#x, %v; want the buffer filled and WSAEMSGSIZE", n, bufLen, flags, err)
	}
}

// wp5ReportICMP turns SIO_UDP_CONNRESET back on for u (Go turns it off on
// every UDP socket it creates): a datagram to a closed port then fails the
// socket's next read with WSAECONNRESET, which it returns.
func wp5ReportICMP(t *testing.T, u *net.UDPConn) error {
	t.Helper()
	rc, err := u.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var serr error
	if err := rc.Control(func(fd uintptr) {
		flag, ret := uint32(1), uint32(0)
		serr = syscall.WSAIoctl(syscall.Handle(fd), syscall.SIO_UDP_CONNRESET, (*byte)(unsafe.Pointer(&flag)),
			uint32(unsafe.Sizeof(flag)), nil, 0, &ret, nil, 0)
	}); err != nil || serr != nil {
		t.Fatalf("SIO_UDP_CONNRESET: %v, %v", err, serr)
	}
	return syscall.Errno(10054) // WSAECONNRESET
}
