//go:build unix

package carrier

import (
	"errors"
	"syscall"
)

// udpMsgTrunc is the recvmsg flag of a datagram longer than the buffer
// (L58: Linux truncates silently and reports only this flag; the max+1
// buffer catches the same datagrams).
const udpMsgTrunc = syscall.MSG_TRUNC

// udpErrnoClass is the errno table of rendr's own UDP sockets on Unix (M2
// design §A6.4). The sockets are unconnected, so ICMP-derived errors are
// rare (a pending ECONNREFUSED, an unreachable route on send); they and
// ENOBUFS lose a datagram, never the carrier.
func udpErrnoClass(err error) udpClass {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return udpOther
	}
	switch errno {
	case syscall.EMSGSIZE:
		return udpMsgSize
	case syscall.ECONNREFUSED, syscall.ECONNRESET, syscall.ENETRESET,
		syscall.EHOSTUNREACH, syscall.ENETUNREACH, syscall.EHOSTDOWN, syscall.ENOBUFS:
		return udpNoise
	case syscall.ECONNABORTED:
		return udpAbort
	}
	return udpOther
}
