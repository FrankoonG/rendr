package udp

import (
	"net"
	"syscall"
)

// IP_DONTFRAGMENT and IPV6_DONTFRAG (ws2ipdef.h).
const (
	ipDontFragment = 14
	ipv6DontFrag   = 14
)

// setDontFragment sets IP_DONTFRAGMENT (IPV6_DONTFRAG on an IPv6 socket,
// and best effort the IPv4 option for the IPv4 datagrams of a dual-stack
// socket): a datagram larger than the interface MTU fails with WSAEMSGSIZE
// instead of being fragmented (M2-D66).
func setDontFragment(u *net.UDPConn, v6 bool) error {
	rc, err := u.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	err = rc.Control(func(fd uintptr) {
		h := syscall.Handle(fd)
		if v6 {
			serr = syscall.SetsockoptInt(h, syscall.IPPROTO_IPV6, ipv6DontFrag, 1)
			_ = syscall.SetsockoptInt(h, syscall.IPPROTO_IP, ipDontFragment, 1)
			return
		}
		serr = syscall.SetsockoptInt(h, syscall.IPPROTO_IP, ipDontFragment, 1)
	})
	if err != nil {
		return err
	}
	return serr
}

// setBuffers sizes the socket buffers, best effort (Windows grants the
// requested sizes).
func setBuffers(u *net.UDPConn, read, write int) {
	_ = u.SetReadBuffer(read)
	_ = u.SetWriteBuffer(write)
}
