package udp

import (
	"net"
	"syscall"
	"testing"
)

// wp5DF returns the don't-fragment option rendr sets on this OS for an IPv4
// or IPv6 socket and the value it must read (M2-D66: probe semantics).
func wp5DF(v6 bool) (level, opt, want int, ok bool) {
	if v6 {
		return syscall.IPPROTO_IPV6, syscall.IPV6_MTU_DISCOVER, syscall.IPV6_PMTUDISC_PROBE, true
	}
	return syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_PROBE, true
}

// wp5Getsockopt reads an integer socket option.
func wp5Getsockopt(fd uintptr, level, opt int) (int, error) {
	return syscall.GetsockoptInt(int(fd), level, opt)
}

const (
	wp5SolSocket = syscall.SOL_SOCKET
	wp5SoRcvbuf  = syscall.SO_RCVBUF
	wp5SoSndbuf  = syscall.SO_SNDBUF
)

// wp5BufferWant returns what SO_RCVBUF (read) or SO_SNDBUF must read on a
// socket rendr asked for n bytes. Linux reports twice the size it grants;
// with the FORCE options' privilege (CAP_NET_ADMIN) it grants n, else the
// plain option caps n at rmem_max (wmem_max). A control socket asked the
// same way shows which applies to this process.
func wp5BufferWant(t *testing.T, n int, read bool) int {
	t.Helper()
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	force, opt := syscall.SO_SNDBUFFORCE, syscall.SO_SNDBUF
	if read {
		force, opt = syscall.SO_RCVBUFFORCE, syscall.SO_RCVBUF
	}
	rc, err := u.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var ferr, gerr error
	if err := rc.Control(func(fd uintptr) { ferr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, force, n) }); err != nil {
		t.Fatal(err)
	}
	if ferr == nil {
		return 2 * n
	}
	if read {
		err = u.SetReadBuffer(n)
	} else {
		err = u.SetWriteBuffer(n)
	}
	if err != nil {
		t.Fatal(err)
	}
	var v int
	if err := rc.Control(func(fd uintptr) { v, gerr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, opt) }); err != nil || gerr != nil {
		t.Fatalf("getsockopt: %v, %v", err, gerr)
	}
	return v
}
