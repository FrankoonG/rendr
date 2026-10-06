package carrier

import (
	"errors"
	"syscall"
	"testing"
)

// wp5ErrnoCases returns this OS's rows of the error table of rendr's own UDP
// sockets (M2 design §A6.4; Winsock numbers from winerror.h): the noise
// errnos, the abort, the too-large errno and some permanent ones.
func wp5ErrnoCases() (noise []error, abort, msgSize error, others []error) {
	noise = []error{
		syscall.Errno(10061), // WSAECONNREFUSED
		syscall.Errno(10054), // WSAECONNRESET
		syscall.Errno(10052), // WSAENETRESET
		syscall.Errno(10065), // WSAEHOSTUNREACH
		syscall.Errno(10051), // WSAENETUNREACH
		syscall.Errno(10064), // WSAEHOSTDOWN
		syscall.Errno(10055), // WSAENOBUFS
	}
	others = []error{
		syscall.Errno(10038), // WSAENOTSOCK
		syscall.Errno(10022), // WSAEINVAL
		syscall.Errno(10013), // WSAEACCES
		syscall.Errno(10049), // WSAEADDRNOTAVAIL
	}
	return noise, syscall.Errno(10053), syscall.Errno(10040), others // WSAECONNABORTED, WSAEMSGSIZE
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
