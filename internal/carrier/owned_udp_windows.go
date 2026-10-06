package carrier

import (
	"errors"
	"syscall"
)

// udpMsgTrunc is MSG_TRUNC in a WSAMSG's flags. Windows also fails such a
// read with WSAEMSGSIZE (n = len(b), no source address), which readResult
// maps to a truncation drop, never a socket error (plan:638).
const udpMsgTrunc = 0x0100

// Winsock errors of rendr's own UDP sockets (winerror.h). WSAEMSGSIZE is not
// syscall.EMSGSIZE on Windows (M2 design §A6.4).
const (
	wsaEMSGSIZE     syscall.Errno = 10040
	wsaENETUNREACH  syscall.Errno = 10051
	wsaENETRESET    syscall.Errno = 10052
	wsaECONNABORTED syscall.Errno = 10053
	wsaECONNRESET   syscall.Errno = 10054
	wsaENOBUFS      syscall.Errno = 10055
	wsaECONNREFUSED syscall.Errno = 10061
	wsaEHOSTDOWN    syscall.Errno = 10064
	wsaEHOSTUNREACH syscall.Errno = 10065
)

// udpErrnoClass is the errno table of rendr's own UDP sockets on Windows
// (M2 design §A6.4). Go disables SIO_UDP_CONNRESET and SIO_UDP_NETRESET on
// its UDP sockets, so the reset errors are not expected here; they are noise
// if they come.
func udpErrnoClass(err error) udpClass {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return udpOther
	}
	switch errno {
	case wsaEMSGSIZE:
		return udpMsgSize
	case wsaECONNREFUSED, wsaECONNRESET, wsaENETRESET,
		wsaEHOSTUNREACH, wsaENETUNREACH, wsaEHOSTDOWN, wsaENOBUFS:
		return udpNoise
	case wsaECONNABORTED:
		return udpAbort
	}
	return udpOther
}
