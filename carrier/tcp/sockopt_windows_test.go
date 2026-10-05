package tcp_test

import (
	"syscall"
	"unsafe"
)

const (
	solSocket   = syscall.SOL_SOCKET
	soKeepAlive = syscall.SO_KEEPALIVE
	ipprotoTCP  = syscall.IPPROTO_TCP
	tcpNoDelay  = syscall.TCP_NODELAY
)

func getsockopt(fd uintptr, level, opt int) (int, error) {
	var v int32
	n := int32(unsafe.Sizeof(v))
	err := syscall.Getsockopt(syscall.Handle(fd), int32(level), int32(opt), (*byte)(unsafe.Pointer(&v)), &n)
	return int(v), err
}
