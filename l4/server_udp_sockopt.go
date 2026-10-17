//go:build unix || windows

package l4

import "syscall"

// clearBroadcast turns SO_BROADCAST off on the socket fd, which Go's net
// package turns on for every IPv4 datagram socket it makes (M6-D34; see
// udpTargetControl).
func clearBroadcast(fd uintptr) error {
	return setsockoptInt(syscall.SetsockoptInt, fd, syscall.SOL_SOCKET, syscall.SO_BROADCAST, 0)
}

// setsockoptInt calls set, which is syscall.SetsockoptInt, on fd. Its
// descriptor type is int on Unix and syscall.Handle on Windows; this one
// definition covers both.
func setsockoptInt[H ~int | ~uintptr](set func(H, int, int, int) error, fd uintptr, level, opt, v int) error {
	return set(H(fd), level, opt, v)
}
