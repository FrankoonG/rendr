//go:build unix

package tcp_test

import "syscall"

const (
	solSocket   = syscall.SOL_SOCKET
	soKeepAlive = syscall.SO_KEEPALIVE
	ipprotoTCP  = syscall.IPPROTO_TCP
	tcpNoDelay  = syscall.TCP_NODELAY
)

func getsockopt(fd uintptr, level, opt int) (int, error) {
	return syscall.GetsockoptInt(int(fd), level, opt)
}
