//go:build !plan9 && !wasip1

package carrier

import (
	"fmt"
	"syscall"
)

// pktErrnoRows are the errno rows of TestClassifyPacketErr_L58: the build
// platform's POSIX errnos and the Windows numbers, matched on every OS.
func pktErrnoRows() []pktErrRow {
	var rows []pktErrRow
	both := func(name string, e syscall.Errno, read, write PacketErrClass) {
		rows = append(rows,
			pktErrRow{name + " on a read", pktOpErr("read", e), false, read},
			pktErrRow{name + " on a write", pktOpErr("write", e), true, write})
	}
	for _, e := range []syscall.Errno{syscall.ECONNREFUSED, syscall.ECONNRESET, syscall.ENETRESET,
		syscall.EHOSTUNREACH, syscall.ENETUNREACH, syscall.EHOSTDOWN, syscall.ENOBUFS} {
		both(fmt.Sprintf("errno %d (%v)", uint(e), e), e, PacketErrNoise, PacketErrNoise)
	}
	for _, n := range []syscall.Errno{10051, 10052, 10054, 10055, 10061, 10064, 10065} {
		both(fmt.Sprintf("Windows errno %d", uint(n)), n, PacketErrNoise, PacketErrNoise)
	}
	both("EMSGSIZE", syscall.EMSGSIZE, PacketErrSize, PacketErrSize)
	both("WSAEMSGSIZE", 10040, PacketErrSize, PacketErrSize)
	both("ECONNABORTED", syscall.ECONNABORTED, PacketErrAbort, PacketErrAbort)
	both("WSAECONNABORTED", 10053, PacketErrAbort, PacketErrAbort)
	both("EPERM (a local packet filter)", syscall.EPERM, PacketErrDeath, PacketErrNoise)
	both("EBADF", syscall.EBADF, PacketErrDeath, PacketErrDeath)
	return rows
}
