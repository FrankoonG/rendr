//go:build unix

package l4

import "syscall"

// symCode maps this OS's errno symbols to their codes (M4 design §A8.1).
func symCode(e syscall.Errno) (RejectCode, bool) {
	switch e {
	case syscall.ECONNREFUSED:
		return CodeRefused, true
	case syscall.ENETUNREACH, syscall.ENETDOWN:
		return CodeNetUnreachable, true
	case syscall.EHOSTUNREACH, syscall.EHOSTDOWN:
		return CodeHostUnreachable, true
	case syscall.ETIMEDOUT:
		return CodeTimeout, true
	case syscall.EADDRNOTAVAIL, syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.ENOMEM:
		return CodeCapacity, true
	case syscall.EACCES, syscall.EPERM:
		return CodeNotAllowed, true
	}
	return 0, false
}

// symLocal maps this OS's errno symbols of the l4 sockets' size class and
// fatal set (M6-D15, R1-2): EMSGSIZE is WSAEMSGSIZE's twin (a read here
// truncates a longer datagram silently, so a read reports EMSGSIZE only
// for an ICMP fragmentation-needed or packet-too-big of an earlier send on
// a connected socket, which ForwardPacket counts as noise: its buffer is
// not filled); a closed, invalid, wrong-kind or unconnected socket (EBADF,
// ENOTSOCK, EINVAL, EFAULT, ENOTCONN, EDESTADDRREQ, EISCONN, EOPNOTSUPP,
// and ESHUTDOWN, the twin of WSAESHUTDOWN) is a defect, never a network
// event. Every other errno is noise (the caller's default): Linux reports
// each ICMP error of a connected UDP socket on its next call
// (ECONNREFUSED, EHOSTUNREACH, ENETUNREACH, EACCES, EPROTO, ENOPROTOOPT,
// ENONET, EHOSTDOWN), and a send may fail ENOBUFS, ENETDOWN or EPERM.
func symLocal(e syscall.Errno) (localClass, bool) {
	switch e {
	case syscall.EMSGSIZE:
		return classSize, true
	case syscall.EBADF, syscall.ENOTSOCK, syscall.EINVAL, syscall.EFAULT, syscall.ENOTCONN,
		syscall.EDESTADDRREQ, syscall.EISCONN, syscall.EOPNOTSUPP, syscall.ESHUTDOWN:
		return classFatal, true
	}
	return 0, false
}
