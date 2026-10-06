package udp

import (
	"syscall"
	"testing"
	"unsafe"
)

// wp5DF returns the don't-fragment option rendr sets on this OS for an IPv4
// or IPv6 socket and the value it must read (IP_DONTFRAGMENT,
// IPV6_DONTFRAG).
func wp5DF(v6 bool) (level, opt, want int, ok bool) {
	if v6 {
		return syscall.IPPROTO_IPV6, ipv6DontFrag, 1, true
	}
	return syscall.IPPROTO_IP, ipDontFragment, 1, true
}

// wp5Getsockopt reads an integer socket option.
func wp5Getsockopt(fd uintptr, level, opt int) (int, error) {
	var v int32
	n := int32(unsafe.Sizeof(v))
	err := syscall.Getsockopt(syscall.Handle(fd), int32(level), int32(opt), (*byte)(unsafe.Pointer(&v)), &n)
	return int(v), err
}

const (
	wp5SolSocket = syscall.SOL_SOCKET
	wp5SoRcvbuf  = syscall.SO_RCVBUF
	wp5SoSndbuf  = syscall.SO_SNDBUF
)

// wp5BufferWant returns what SO_RCVBUF or SO_SNDBUF must read on a socket
// rendr asked for n bytes: Windows grants the size asked for.
func wp5BufferWant(_ *testing.T, n int, _ bool) int { return n }
