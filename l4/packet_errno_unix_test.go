//go:build unix

package l4

import "syscall"

// pfLinuxNoise holds the noise errnos only Linux has (packet_errno_linux_test.go).
var pfLinuxNoise []pfErrno

// pfSymNoise are this OS's noise errnos of an l4 socket (M6-D15, R1-2):
// the ICMP-derived errors a connected UDP socket reports on its next call,
// and the send-path errors. ETIMEDOUT is an errno, so a network event,
// not a deadline.
func pfSymNoise() []pfErrno {
	return append([]pfErrno{
		{"ECONNREFUSED", syscall.ECONNREFUSED},
		{"EHOSTUNREACH", syscall.EHOSTUNREACH},
		{"ENETUNREACH", syscall.ENETUNREACH},
		{"EHOSTDOWN", syscall.EHOSTDOWN},
		{"EACCES", syscall.EACCES},
		{"EPROTO", syscall.EPROTO},
		{"ENOPROTOOPT", syscall.ENOPROTOOPT},
		{"ENETDOWN", syscall.ENETDOWN},
		{"ENOBUFS", syscall.ENOBUFS},
		{"EPERM", syscall.EPERM},
		{"ECONNRESET", syscall.ECONNRESET},
		{"ETIMEDOUT", syscall.ETIMEDOUT},
	}, pfLinuxNoise...)
}

// pfSymFatal is this OS's fatal set (M6-D15): a closed, invalid,
// wrong-kind or unconnected socket.
func pfSymFatal() []pfErrno {
	return []pfErrno{
		{"EBADF", syscall.EBADF},
		{"ENOTSOCK", syscall.ENOTSOCK},
		{"EINVAL", syscall.EINVAL},
		{"EFAULT", syscall.EFAULT},
		{"ENOTCONN", syscall.ENOTCONN},
		{"EDESTADDRREQ", syscall.EDESTADDRREQ},
		{"EISCONN", syscall.EISCONN},
		{"EOPNOTSUPP", syscall.EOPNOTSUPP},
		{"ESHUTDOWN", syscall.ESHUTDOWN},
	}
}

// pfSymSize is this OS's "message too long" errno.
func pfSymSize() []pfErrno { return []pfErrno{{"EMSGSIZE", syscall.EMSGSIZE}} }
