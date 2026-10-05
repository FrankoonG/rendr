package carrier

import (
	"net"
	"net/netip"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// OwnedUDP is a datagram carrier on a rendr-owned, unconnected UDP socket:
// one per carrier/udp dialer carrier, constructed only by package
// carrier/udp (an ownership token, never an interface assertion on embedder
// values: L57). It is the net.PacketConn a rendr.DatagramCarrier.Dial of
// carrier/udp returns, and the core recognises its exact type and then uses
// it as a PacketIO: ReadMsgUDPAddrPort reads (truncation by MSG_TRUNC on
// Linux, WSAEMSGSIZE on Windows, n == len everywhere), an exact source
// filter (one AddrPort compare), the flow header written and checked by the
// token itself (Headroom wire.FlowHeaderLen), WriteToUDPAddrPort writes —
// no allocation per datagram (M2-D4, M2-D66).
//
// Its net.PacketConn methods exist for the factory signature, tests and
// diagnostics: ReadFrom strips and WriteTo adds the flow header. Close
// closes the socket exactly once.
type OwnedUDP struct {
	u     *net.UDPConn
	peer  netip.AddrPort
	flow  uint64
	limit int // MaxDatagram: the largest UDP payload, flow header included
}

// NewOwnedUDP returns the token for u, a socket carrier/udp opened toward
// peer for one carrier, with that carrier's flow ID (≠ 0, crypto/rand) and
// MaxDatagram (546–65,507). Ownership of u moves to the token.
func NewOwnedUDP(u *net.UDPConn, peer netip.AddrPort, flow uint64, maxDatagram int) *OwnedUDP {
	return &OwnedUDP{u: u, peer: peer, flow: flow, limit: maxDatagram}
}

// Flow returns the carrier's flow ID.
func (o *OwnedUDP) Flow() uint64 { return o.flow }

// ReadFrom reads one datagram of the flow and returns its rendr bytes.
func (o *OwnedUDP) ReadFrom(p []byte) (int, net.Addr, error) { panic("unimplemented: M2") }

// WriteTo sends p, prefixed with the flow header, to addr.
func (o *OwnedUDP) WriteTo(p []byte, addr net.Addr) (int, error) { panic("unimplemented: M2") }

// Close closes the socket.
func (o *OwnedUDP) Close() error { return o.u.Close() }

// LocalAddr returns the socket's local address.
func (o *OwnedUDP) LocalAddr() net.Addr { return o.u.LocalAddr() }

// SetDeadline sets the socket's deadlines.
func (o *OwnedUDP) SetDeadline(t time.Time) error { return o.u.SetDeadline(t) }

// SetReadDeadline sets the socket's read deadline.
func (o *OwnedUDP) SetReadDeadline(t time.Time) error { return o.u.SetReadDeadline(t) }

// SetWriteDeadline sets the socket's write deadline.
func (o *OwnedUDP) SetWriteDeadline(t time.Time) error { return o.u.SetWriteDeadline(t) }

// ReadSize implements PacketIO: MaxDatagram + 1.
func (o *OwnedUDP) ReadSize() int { return o.limit + 1 }

// ReadDatagram implements PacketIO.
func (o *OwnedUDP) ReadDatagram(buf []byte) ([]byte, PeerKey, ReadEvent, error) {
	panic("unimplemented: M2")
}

// Release implements PacketIO (no-op).
func (o *OwnedUDP) Release() {}

// Headroom implements PacketIO: the flow header.
func (o *OwnedUDP) Headroom() int { return wire.FlowHeaderLen }

// WriteDatagram implements PacketIO.
func (o *OwnedUDP) WriteDatagram(b []byte) error { panic("unimplemented: M2") }

// WriteDatagramTo implements PacketIO: a dialer socket never rebinds.
func (o *OwnedUDP) WriteDatagramTo(b []byte, dst PeerKey) error { return ErrNoRebind }

// SetPeer implements PacketIO: a dialer socket never rebinds.
func (o *OwnedUDP) SetPeer(dst PeerKey) error { return ErrNoRebind }

// Limit implements PacketIO: MaxDatagram − 9.
func (o *OwnedUDP) Limit() int { return o.limit - wire.FlowHeaderLen }

var (
	_ net.PacketConn = (*OwnedUDP)(nil)
	_ PacketIO       = (*OwnedUDP)(nil)
)

// OwnedUDPSocket is a rendr-owned listening UDP socket (carrier/udp Listen)
// for rendr.FromPacketConn: package udpflow reads and writes it with
// AddrPort calls and truncation detection, without an allocation per
// datagram (M2-D66). Any other net.PacketConn given to FromPacketConn is
// used through its interface methods only (L57). Constructed only by
// carrier/udp.
type OwnedUDPSocket struct {
	u     *net.UDPConn
	limit int // MaxDatagram
}

// NewOwnedUDPSocket returns the token for u with its MaxDatagram.
// Ownership of u moves to the token.
func NewOwnedUDPSocket(u *net.UDPConn, maxDatagram int) *OwnedUDPSocket {
	return &OwnedUDPSocket{u: u, limit: maxDatagram}
}

// MaxDatagram returns the largest UDP payload the socket reads and writes.
func (s *OwnedUDPSocket) MaxDatagram() int { return s.limit }

// ReadAddrPort reads one datagram into p (len(p) ≥ MaxDatagram + 1) and
// returns its length and source; ev is ReadTruncated, ReadEmpty or
// ReadNoise for a datagram or error that is not handed over (M2 design
// §A6.4); err is a permanent socket error.
func (s *OwnedUDPSocket) ReadAddrPort(p []byte) (n int, src netip.AddrPort, ev ReadEvent, err error) {
	panic("unimplemented: M2")
}

// WriteAddrPort sends p as one datagram to dst. EMSGSIZE and WSAEMSGSIZE are
// a *wire.DatagramTooLargeError with Max 0; ICMP-class errors ErrNoise.
func (s *OwnedUDPSocket) WriteAddrPort(p []byte, dst netip.AddrPort) error {
	panic("unimplemented: M2")
}

// ReadFrom implements net.PacketConn (tests and diagnostics).
func (s *OwnedUDPSocket) ReadFrom(p []byte) (int, net.Addr, error) { return s.u.ReadFrom(p) }

// WriteTo implements net.PacketConn (tests and diagnostics).
func (s *OwnedUDPSocket) WriteTo(p []byte, addr net.Addr) (int, error) { return s.u.WriteTo(p, addr) }

// Close closes the socket.
func (s *OwnedUDPSocket) Close() error { return s.u.Close() }

// LocalAddr returns the socket's local address.
func (s *OwnedUDPSocket) LocalAddr() net.Addr { return s.u.LocalAddr() }

// SetDeadline sets the socket's deadlines.
func (s *OwnedUDPSocket) SetDeadline(t time.Time) error { return s.u.SetDeadline(t) }

// SetReadDeadline sets the socket's read deadline.
func (s *OwnedUDPSocket) SetReadDeadline(t time.Time) error { return s.u.SetReadDeadline(t) }

// SetWriteDeadline sets the socket's write deadline.
func (s *OwnedUDPSocket) SetWriteDeadline(t time.Time) error { return s.u.SetWriteDeadline(t) }

var _ net.PacketConn = (*OwnedUDPSocket)(nil)
