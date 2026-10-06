//go:build unix

package carrier

import (
	"net"
	"syscall"
	"testing"
)

// wp5ErrnoCases returns this OS's rows of the error table of rendr's own UDP
// sockets (M2 design §A6.4): the noise errnos, EPERM (a local packet filter's
// refusal: noise on a write, death on a read), the abort, the too-large
// errno and some permanent ones.
func wp5ErrnoCases() wp5Errnos {
	return wp5Errnos{
		noise: []error{syscall.ECONNREFUSED, syscall.ECONNRESET, syscall.ENETRESET, syscall.EHOSTUNREACH,
			syscall.ENETUNREACH, syscall.EHOSTDOWN, syscall.ENOBUFS},
		sendNoise: []error{syscall.EPERM},
		abort:     syscall.ECONNABORTED,
		msgSize:   syscall.EMSGSIZE,
		others:    []error{syscall.EBADF, syscall.EINVAL, syscall.EACCES, syscall.ENOTSOCK},
	}
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

// wp5ReportICMP returns nil: an unconnected socket on Unix reports no
// ICMP-derived errors. Linux does with IP_RECVERR, but Go's poller then
// fails a read blocked at that moment with "not pollable" (an EPOLLERR-only
// event) instead of the errno, depending on whether the poller saw the
// event first — so the real ICMP row runs on Windows, and the injected
// errno rows cover this OS.
func wp5ReportICMP(*testing.T, *net.UDPConn) error { return nil }
