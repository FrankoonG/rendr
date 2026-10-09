package udp

import (
	"net"
	"syscall"
)

// setDontFragment sets IP_PMTUDISC_PROBE: the kernel sets DF on every
// datagram and never fragments, but sends up to the interface MTU whatever
// path MTU an ICMP message reported (rendr's MTU probe, not the kernel's
// cache, judges the path; M2-D66). An IPv6 socket gets
// IPV6_PMTUDISC_PROBE and, best effort, the IPv4 option for the IPv4
// datagrams a dual-stack socket carries.
func setDontFragment(u *net.UDPConn, v6 bool) error {
	rc, err := u.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	err = rc.Control(func(fd uintptr) {
		if v6 {
			serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_MTU_DISCOVER, syscall.IPV6_PMTUDISC_PROBE)
			_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_PROBE)
			return
		}
		serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_PROBE)
	})
	if err != nil {
		return err
	}
	return serr
}

// setBuffers sizes the socket buffers, best effort: SO_RCVBUFFORCE and
// SO_SNDBUFFORCE pass rmem_max and wmem_max when the process may
// (CAP_NET_ADMIN), else the plain options, which the kernel caps at them.
func setBuffers(u *net.UDPConn, read, write int) {
	var rerr, werr error = syscall.EPERM, syscall.EPERM
	if rc, err := u.SyscallConn(); err == nil {
		_ = rc.Control(func(fd uintptr) {
			rerr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUFFORCE, read)
			werr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUFFORCE, write)
		})
	}
	if rerr != nil {
		_ = u.SetReadBuffer(read)
	}
	if werr != nil {
		_ = u.SetWriteBuffer(write)
	}
}
