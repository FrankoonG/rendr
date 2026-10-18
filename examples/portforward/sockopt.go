//go:build unix || windows

package main

import "syscall"

// clearBroadcast turns SO_BROADCAST off on the socket fd, which Go's net
// package turns on for every IPv4 datagram socket; the OS then refuses a
// directed broadcast: Linux at the connect (EACCES), Windows and the BSDs
// at the send, both answered CodeNotAllowed by l4 (M6-D34, §A6.3).
func clearBroadcast(fd uintptr) error { return setOff(syscall.SetsockoptInt, fd) }

// setOff calls set, syscall.SetsockoptInt, whose descriptor is an int on
// Unix and a syscall.Handle on Windows: this one definition covers both.
func setOff[H ~int | ~uintptr](set func(H, int, int, int) error, fd uintptr) error {
	return set(H(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 0)
}
