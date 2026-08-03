//go:build linux

package smoke

import (
	"fmt"
	"net"
	"syscall"
)

// G3UDPBufferPreflight verifies that Linux will not clamp the QUIC adapter's
// socket-buffer request below the published 100k-pps fixture requirement.
func G3UDPBufferPreflight() error {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return fmt.Errorf("measure G3 UDP buffer capacity: listen: %w", err)
	}
	defer conn.Close()
	if err := conn.SetReadBuffer(int(g3RequiredUDPBufferBytes)); err != nil {
		return fmt.Errorf("measure G3 UDP buffer capacity: set SO_RCVBUF: %w", err)
	}
	if err := conn.SetWriteBuffer(int(g3RequiredUDPBufferBytes)); err != nil {
		return fmt.Errorf("measure G3 UDP buffer capacity: set SO_SNDBUF: %w", err)
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("measure G3 UDP buffer capacity: syscall conn: %w", err)
	}
	var receiveBytes, sendBytes int
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		receiveBytes, socketErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
		if socketErr != nil {
			return
		}
		sendBytes, socketErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF)
	}); err != nil {
		return fmt.Errorf("measure G3 UDP buffer capacity: inspect socket: %w", err)
	}
	if socketErr != nil {
		return fmt.Errorf("measure G3 UDP buffer capacity: getsockopt: %w", socketErr)
	}
	return validateG3EffectiveUDPBuffers(int64(receiveBytes), int64(sendBytes))
}
