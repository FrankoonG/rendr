//go:build unix || windows

package main

import (
	"errors"
	"log"
	"net"
	"runtime"
	"syscall"
)

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

// getInt calls get, syscall.GetsockoptInt (an int descriptor on Unix, a
// syscall.Handle on Windows), on fd.
func getInt[H ~int | ~uintptr](get func(H, int, int) (int, error), fd uintptr, opt int) (int, error) {
	return get(H(fd), syscall.SOL_SOCKET, opt)
}

// grantedBuffers is checkBuffers' probe (a variable only so that tests can
// stand in for the OS): the SO_RCVBUF and SO_SNDBUF a fresh loopback UDP
// socket reports after asking for n bytes of each.
var grantedBuffers = func(n int) (rcv, snd int, err error) {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return 0, 0, err
	}
	defer c.Close()
	c.SetReadBuffer(n)
	c.SetWriteBuffer(n)
	rc, err := c.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var rerr, serr error
	if err := rc.Control(func(fd uintptr) {
		rcv, rerr = getInt(syscall.GetsockoptInt, fd, syscall.SO_RCVBUF)
		snd, serr = getInt(syscall.GetsockoptInt, fd, syscall.SO_SNDBUF)
	}); err != nil {
		return 0, 0, err
	}
	return rcv, snd, errors.Join(rerr, serr)
}

// checkBuffers logs one warning when the OS grants the subcommand's UDP
// sockets of kind less than the n bytes of receive or send buffer it asks
// for (§A4.4 item 6): a burst beyond them is lost. Linux caps a request at
// net.core.rmem_max and wmem_max (212,992 bytes by default) and reports
// twice what it grants; darwin keeps its default for a request above
// kern.ipc.maxsockbuf; Windows grants it.
func checkBuffers(logger *log.Logger, sub, kind string, n int) {
	rcv, snd, err := grantedBuffers(n)
	if err != nil {
		return
	}
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		rcv, snd = rcv/2, snd/2
	}
	if rcv < n || snd < n {
		logger.Printf("%s: warning: UDP %s sockets get %d bytes of receive and %d of send buffer, not the %d asked for; bursts beyond them are lost (on Linux raise net.core.rmem_max and net.core.wmem_max)", sub, kind, rcv, snd, n)
	}
}
