//go:build unix

package carrier

import (
	"syscall"
	"testing"
)

// wp5ErrnoCases returns this OS's rows of the error table of rendr's own UDP
// sockets (M2 design §A6.4): the noise errnos, the abort, the too-large
// errno and some permanent ones.
func wp5ErrnoCases() (noise []error, abort, msgSize error, others []error) {
	noise = []error{syscall.ECONNREFUSED, syscall.ECONNRESET, syscall.ENETRESET, syscall.EHOSTUNREACH,
		syscall.ENETUNREACH, syscall.EHOSTDOWN, syscall.ENOBUFS}
	others = []error{syscall.EBADF, syscall.EINVAL, syscall.EPERM, syscall.ENOTSOCK}
	return noise, syscall.ECONNABORTED, syscall.EMSGSIZE, others
}

// wp5CheckOSTruncation pins how Unix reports a datagram longer than the read
// buffer: silently (L58) — n is the buffer length, MSG_TRUNC is set and no
// error is returned.
func wp5CheckOSTruncation(t *testing.T, n, bufLen, flags int, err error) {
	t.Helper()
	if err != nil || n != bufLen || flags&syscall.MSG_TRUNC == 0 {
		t.Fatalf("truncated read: n %d of %d, flags %#x, %v; want the buffer filled, MSG_TRUNC, no error", n, bufLen, flags, err)
	}
}
