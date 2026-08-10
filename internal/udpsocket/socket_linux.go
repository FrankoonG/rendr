//go:build linux

package udpsocket

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"time"
	"unsafe"

	quic "github.com/quic-go/quic-go"
	"golang.org/x/sys/unix"
)

const udpSegmentDataSize = 2

type packetConnView struct{ socket *Socket }

var _ quic.OOBCapablePacketConn = (*packetConnView)(nil)
var _ net.Conn = (*packetConnView)(nil)

func platformGSOAllowed() bool { return true }

func newPacketConnView(socket *Socket) net.PacketConn { return &packetConnView{socket: socket} }

func (c *packetConnView) ReadFrom(payload []byte) (int, net.Addr, error) {
	return c.socket.conn.ReadFrom(payload)
}

// x/net's IPv4 packet wrapper requires the concrete PacketConn to also
// implement net.Conn, even though quic-go's public OOB contract doesn't say
// so. These methods preserve the underlying UDPConn semantics; QUIC still
// uses ReadMsgUDP and WriteMsgUDP for packet I/O.
func (c *packetConnView) Read(payload []byte) (int, error) {
	return c.socket.Read(payload)
}

func (c *packetConnView) Write(payload []byte) (int, error) {
	return c.socket.Write(payload)
}

func (c *packetConnView) WriteTo(payload []byte, address net.Addr) (int, error) {
	udpAddress, ok := address.(*net.UDPAddr)
	if !ok {
		name := "<nil>"
		if address != nil {
			name = address.String()
		}
		return 0, &net.AddrError{Err: "destination is not UDP", Addr: name}
	}
	n, _, err := c.WriteMsgUDP(payload, nil, udpAddress)
	return n, err
}

func (c *packetConnView) Close() error                       { return c.socket.Close() }
func (c *packetConnView) LocalAddr() net.Addr                { return c.socket.LocalAddr() }
func (c *packetConnView) RemoteAddr() net.Addr               { return c.socket.RemoteAddr() }
func (c *packetConnView) SetDeadline(t time.Time) error      { return c.socket.SetDeadline(t) }
func (c *packetConnView) SetReadDeadline(t time.Time) error  { return c.socket.SetReadDeadline(t) }
func (c *packetConnView) SetWriteDeadline(t time.Time) error { return c.socket.SetWriteDeadline(t) }
func (c *packetConnView) SetReadBuffer(bytes int) error      { return c.socket.SetReadBuffer(bytes) }
func (c *packetConnView) SetWriteBuffer(bytes int) error     { return c.socket.SetWriteBuffer(bytes) }

func (c *packetConnView) SyscallConn() (syscall.RawConn, error) {
	return c.socket.conn.SyscallConn()
}

func (c *packetConnView) ReadMsgUDP(payload, oob []byte) (int, int, int, *net.UDPAddr, error) {
	return c.socket.conn.ReadMsgUDP(payload, oob)
}

func (c *packetConnView) WriteMsgUDP(payload, oob []byte, address *net.UDPAddr) (int, int, error) {
	segmentSize, stripped, found, err := stripUDPSegment(oob)
	if err != nil {
		return 0, 0, err
	}
	if !found {
		n, oobN, writeErr := c.socket.writeMsg(payload, oob, address)
		if writeErr != nil {
			if n != 0 || oobN != 0 {
				return n, oobN, ambiguousWriteError("ordinary datagram", n, len(payload), writeErr)
			}
			if errors.Is(writeErr, unix.EIO) {
				return 0, 0, ordinaryWriteError(writeErr)
			}
			return 0, 0, writeErr
		}
		if n == len(payload) && oobN == len(oob) {
			c.socket.ordinaryDatagrams.Add(1)
			return n, oobN, nil
		}
		if n != 0 || oobN != 0 {
			return n, oobN, ambiguousWriteError("ordinary datagram", n, len(payload), nil)
		}
		return 0, 0, io.ErrShortWrite
	}
	datagrams, err := splitSuperPacket(payload, segmentSize)
	if err != nil {
		return 0, 0, err
	}
	c.socket.send.Lock()
	defer c.socket.send.Unlock()
	if len(datagrams) == 1 {
		n, oobN, writeErr := c.socket.writeMsg(payload, stripped, address)
		if writeErr != nil {
			if n != 0 || oobN != 0 {
				return n, oobN, ambiguousWriteError("ordinary datagram", n, len(payload), writeErr)
			}
			if errors.Is(writeErr, unix.EIO) {
				return 0, 0, ordinaryWriteError(writeErr)
			}
			return 0, 0, writeErr
		}
		if n != len(payload) || oobN != len(stripped) {
			return n, oobN, ambiguousWriteError("ordinary datagram", n, len(payload), nil)
		}
		c.socket.ordinaryDatagrams.Add(1)
		return n, len(oob), nil
	}
	if c.socket.currentTreatment() == treatmentOrdinary {
		completed, writeErr := writeOrdinaryDatagrams(c.socket.writeMsg, datagrams, stripped, address, func() {
			c.socket.ordinaryDatagrams.Add(1)
		})
		if writeErr != nil {
			return completed * segmentSize, 0, writeErr
		}
		return len(payload), len(oob), nil
	}

	c.socket.gsoAttempts.Add(1)
	n, oobN, writeErr := c.socket.writeMsg(payload, oob, address)
	if writeErr == nil {
		if n == len(payload) && oobN == len(oob) {
			c.socket.gsoSegments.Add(uint64(len(datagrams)))
			c.socket.gsoSuperPackets.Add(1)
			return n, oobN, nil
		}
		return n, oobN, ambiguousWriteError("GSO super-packet", n, len(payload), nil)
	}
	if n == 0 && oobN == 0 && isGlobalGSOContradiction(writeErr) {
		c.socket.transitionToFallback(causeRuntimeUnsupported, true)
		return c.replayOrdinary(datagrams, stripped, address, segmentSize, len(payload), len(oob))
	}
	if n == 0 && oobN == 0 && isPathGSOContradiction(writeErr) {
		c.socket.transitionToFallback(causePathUnsupported, false)
		return c.replayOrdinary(datagrams, stripped, address, segmentSize, len(payload), len(oob))
	}
	if n != 0 || oobN != 0 {
		return n, oobN, ambiguousWriteError("GSO super-packet", n, len(payload), writeErr)
	}
	return 0, 0, writeErr
}

func (c *packetConnView) replayOrdinary(
	datagrams [][]byte,
	oob []byte,
	address *net.UDPAddr,
	segmentSize, payloadBytes, originalOOBBytes int,
) (int, int, error) {
	completed, err := writeOrdinaryDatagrams(c.socket.writeMsg, datagrams, oob, address, func() {
		c.socket.ordinaryDatagrams.Add(1)
	})
	if err != nil {
		return completed * segmentSize, 0, err
	}
	return payloadBytes, originalOOBBytes, nil
}

func (s *Socket) writeBatchPlatform(datagrams [][]byte, payload []byte, segmentSize int, address *net.UDPAddr) (int, error) {
	s.send.Lock()
	defer s.send.Unlock()
	if s.currentTreatment() == treatmentOrdinary {
		return writeOrdinaryDatagrams(s.writeMsg, datagrams, nil, address, func() {
			s.ordinaryDatagrams.Add(1)
		})
	}
	oob := udpSegmentControl(segmentSize)
	s.gsoAttempts.Add(1)
	n, oobN, err := s.writeMsg(payload, oob, address)
	if err == nil {
		if n == len(payload) && oobN == len(oob) {
			s.gsoSegments.Add(uint64(len(datagrams)))
			s.gsoSuperPackets.Add(1)
			return len(datagrams), nil
		}
		return 0, ambiguousWriteError("GSO super-packet", n, len(payload), nil)
	}
	if n != 0 || oobN != 0 {
		return 0, ambiguousWriteError("GSO super-packet", n, len(payload), err)
	}
	if !isGlobalGSOContradiction(err) && !isPathGSOContradiction(err) {
		return 0, err
	}
	if isGlobalGSOContradiction(err) {
		s.transitionToFallback(causeRuntimeUnsupported, true)
	} else {
		s.transitionToFallback(causePathUnsupported, false)
	}
	return writeOrdinaryDatagrams(s.writeMsg, datagrams, nil, address, func() {
		s.ordinaryDatagrams.Add(1)
	})
}

func stripUDPSegment(oob []byte) (segmentSize int, stripped []byte, found bool, err error) {
	remaining := oob
	for len(remaining) != 0 {
		header, body, rest, parseErr := unix.ParseOneSocketControlMessage(remaining)
		if parseErr != nil {
			return 0, nil, false, parseErr
		}
		consumed := len(remaining) - len(rest)
		if header.Level == unix.IPPROTO_UDP && header.Type == unix.UDP_SEGMENT {
			if found || len(body) != udpSegmentDataSize {
				return 0, nil, false, unix.EINVAL
			}
			segmentSize = int(binary.NativeEndian.Uint16(body))
			if segmentSize == 0 {
				return 0, nil, false, unix.EINVAL
			}
			found = true
		} else {
			stripped = append(stripped, remaining[:consumed]...)
		}
		remaining = rest
	}
	return segmentSize, stripped, found, nil
}

func splitSuperPacket(payload []byte, segmentSize int) ([][]byte, error) {
	if segmentSize <= 0 || len(payload) == 0 || len(payload) > MaxGSOSuperPacket {
		return nil, unix.EINVAL
	}
	count := (len(payload) + segmentSize - 1) / segmentSize
	if count > MaxGSOSegments {
		return nil, unix.EINVAL
	}
	datagrams := make([][]byte, 0, count)
	for offset := 0; offset < len(payload); offset += segmentSize {
		end := offset + segmentSize
		if end > len(payload) {
			end = len(payload)
		}
		datagrams = append(datagrams, payload[offset:end])
	}
	return datagrams, nil
}

func udpSegmentControl(segmentSize int) []byte {
	oob := make([]byte, unix.CmsgSpace(udpSegmentDataSize))
	header := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	header.Level = unix.IPPROTO_UDP
	header.Type = unix.UDP_SEGMENT
	header.SetLen(unix.CmsgLen(udpSegmentDataSize))
	binary.NativeEndian.PutUint16(oob[unix.CmsgSpace(0):], uint16(segmentSize))
	return oob
}

func isGlobalGSOContradiction(err error) bool {
	return errors.Is(err, unix.ENOPROTOOPT) || errors.Is(err, unix.EOPNOTSUPP)
}

func isPathGSOContradiction(err error) bool {
	// A definite zero-byte permission failure can be specific to the optional
	// UDP_SEGMENT treatment while the same datagrams remain sendable normally.
	// Treat it like EIO only after the active probe had selected GSO. Ordinary
	// sends keep their original errors and are never replayed here.
	return errors.Is(err, unix.EIO) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES)
}

func ordinaryWriteError(err error) error {
	// quic-go treats every *os.SyscallError(EIO) as a failed GSO send. When
	// gsoSize is zero, its segment replay loop cannot advance. Hide the errno
	// after a definite zero-byte ordinary failure so the connection fails
	// closed instead of retrying or spinning.
	return fmt.Errorf("udpsocket: ordinary datagram write failed (%v)", err)
}
