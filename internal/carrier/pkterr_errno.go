//go:build !plan9 && !wasip1

package carrier

import (
	"errors"
	"syscall"
)

// The Windows errnos ClassifyPacketErr matches on every OS (winerror.h;
// M2 design Revision 1, R1-28).
const (
	pktWSAEMSGSIZE     syscall.Errno = 10040
	pktWSAENETUNREACH  syscall.Errno = 10051
	pktWSAENETRESET    syscall.Errno = 10052
	pktWSAECONNABORTED syscall.Errno = 10053
	pktWSAECONNRESET   syscall.Errno = 10054
	pktWSAENOBUFS      syscall.Errno = 10055
	pktWSAECONNREFUSED syscall.Errno = 10061
	pktWSAEHOSTDOWN    syscall.Errno = 10064
	pktWSAEHOSTUNREACH syscall.Errno = 10065
)

// packetErrnoClass is ClassifyPacketErr's errno table: the build
// platform's POSIX errnos and the Windows ones; ok false when err carries
// no errno of the table.
func packetErrnoClass(err error, write bool) (PacketErrClass, bool) {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return 0, false
	}
	switch errno {
	case syscall.EMSGSIZE, pktWSAEMSGSIZE:
		return PacketErrSize, true
	case syscall.ECONNREFUSED, syscall.ECONNRESET, syscall.ENETRESET,
		syscall.EHOSTUNREACH, syscall.ENETUNREACH, syscall.EHOSTDOWN, syscall.ENOBUFS,
		pktWSAECONNREFUSED, pktWSAECONNRESET, pktWSAENETRESET,
		pktWSAEHOSTUNREACH, pktWSAENETUNREACH, pktWSAEHOSTDOWN, pktWSAENOBUFS:
		return PacketErrNoise, true
	case syscall.ECONNABORTED, pktWSAECONNABORTED:
		return PacketErrAbort, true
	case syscall.EPERM:
		if write {
			return PacketErrNoise, true // a local packet filter dropped the datagram
		}
		return PacketErrDeath, true
	}
	return 0, false
}
