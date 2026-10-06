//go:build !linux && !windows

package udp

import "net"

// setDontFragment: nothing on this platform (compile-only; M2 design
// §A6.1). The MTU probe still turns a persistent misfit into a death.
func setDontFragment(*net.UDPConn, bool) error { return nil }

// setBuffers sizes the socket buffers, best effort.
func setBuffers(u *net.UDPConn, read, write int) {
	_ = u.SetReadBuffer(read)
	_ = u.SetWriteBuffer(write)
}
