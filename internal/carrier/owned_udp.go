package carrier

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
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
	recv  int // the receive limit in rendr bytes: limit − 9 until SetLimit lowers it (R1-6)

	// hdr is the carrier's flow header, built once: every datagram the
	// token writes starts with it, and a datagram it reads belongs to the
	// flow iff it starts with it (M2 design §A3.4: ver u8 = 2 · flow u64,
	// big-endian, frozen; the token writes and checks it itself).
	hdr [wire.FlowHeaderLen]byte
}

// NewOwnedUDP returns the token for u, a socket carrier/udp opened toward
// peer for one carrier, with that carrier's flow ID (≠ 0, crypto/rand) and
// MaxDatagram (546–65,507; carrier/udp has already clamped it to the MTU of
// the interface the route to peer uses, M2 design Revision 1, R1-16).
// Ownership of u moves to the token. It panics for flow 0 or a MaxDatagram
// out of range (programming errors of carrier/udp).
func NewOwnedUDP(u *net.UDPConn, peer netip.AddrPort, flow uint64, maxDatagram int) *OwnedUDP {
	if flow == 0 {
		panic("rendr/carrier: OwnedUDP with flow ID 0")
	}
	checkMaxDatagram(maxDatagram)
	o := &OwnedUDP{u: u, peer: unmapAddrPort(peer), flow: flow, limit: maxDatagram, recv: maxDatagram - wire.FlowHeaderLen}
	o.hdr[0] = wire.FlowVersion
	binary.BigEndian.PutUint64(o.hdr[1:], flow)
	return o
}

// Flow returns the carrier's flow ID.
func (o *OwnedUDP) Flow() uint64 { return o.flow }

// ReadFrom reads one datagram of the flow and returns its rendr bytes.
// Datagrams that ReadDatagram would not hand over — empty, truncated, from
// another source, without this flow's header — are skipped; a transient
// (noise) error is returned as ErrNoise, any other error as is. p shorter
// than the rendr bytes receives their prefix. The address is always the
// peer's. For tests and diagnostics: it allocates a read buffer per call.
func (o *OwnedUDP) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, o.ReadSize())
	for {
		data, _, ev, err := o.ReadDatagram(buf)
		switch {
		case err != nil:
			return 0, nil, err
		case ev == ReadNoise:
			return 0, nil, ErrNoise
		case ev != ReadOK:
			continue
		}
		return copy(p, data), net.UDPAddrFromAddrPort(o.peer), nil
	}
}

// WriteTo sends p, prefixed with the flow header, to addr (a *net.UDPAddr).
// Errors follow WriteDatagram's classification; on success it returns
// len(p). For tests and diagnostics: it allocates the datagram per call.
func (o *OwnedUDP) WriteTo(p []byte, addr net.Addr) (int, error) {
	ua, ok := addr.(*net.UDPAddr)
	if !ok || ua == nil {
		return 0, &net.OpError{Op: "write", Net: "udp", Source: o.u.LocalAddr(), Addr: addr, Err: syscall.EINVAL}
	}
	b := make([]byte, wire.FlowHeaderLen+len(p))
	copy(b, o.hdr[:])
	copy(b[wire.FlowHeaderLen:], p)
	n, err := o.u.WriteToUDPAddrPort(b, unmapAddrPort(ua.AddrPort()))
	if err := udpWriteResult(n, len(b), err, false); err != nil {
		return 0, err
	}
	return len(p), nil
}

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

// SyscallConn exposes the raw socket for socket-option tests (don't-fragment
// and buffer sizes), as OwnedTCP's does.
func (o *OwnedUDP) SyscallConn() (syscall.RawConn, error) { return o.u.SyscallConn() }

// ReadSize implements PacketIO: the receive limit + the flow header + 1
// (MaxDatagram + 1 until SetLimit).
func (o *OwnedUDP) ReadSize() int { return o.recv + wire.FlowHeaderLen + 1 }

// SetLimit implements PacketIO: the receive limit in rendr bytes, at most
// Limit() (called before Start only).
func (o *OwnedUDP) SetLimit(n int) { o.recv = min(n, o.Limit()) }

// ReadDatagram implements PacketIO: one ReadMsgUDPAddrPort into exactly the
// first ReadSize() bytes of buf, classified by readResult (M2 design §A6.1,
// §A6.4).
func (o *OwnedUDP) ReadDatagram(buf []byte) ([]byte, PeerKey, ReadEvent, error) {
	b := buf[:o.ReadSize()]
	n, _, flags, src, err := o.u.ReadMsgUDPAddrPort(b, nil)
	return o.readResult(b, n, flags, src, err)
}

// readResult maps one read of the dialer socket into b to the PacketIO
// contract, in the order of M2 design §A6.1: a datagram longer than the
// receive limit (Windows WSAEMSGSIZE, MSG_TRUNC, or n filling b, which is
// one byte longer than the largest datagram accepted) is ReadTruncated; an
// empty one ReadEmpty; one from any source but the peer ReadForeign (L59);
// one without this flow's header ReadBadEnvelope (L58); the header alone
// ReadEmpty; else the rendr bytes after the header, aliasing b. Noise
// errors are ReadNoise with a nil error; every other error is returned and
// ends the carrier — ECONNABORTED included: an administrative abort
// unhashes the auto-bound port, so the socket can never receive again
// (§A6.4). An expired read deadline is returned for the caller to judge.
func (o *OwnedUDP) readResult(b []byte, n, flags int, src netip.AddrPort, err error) ([]byte, PeerKey, ReadEvent, error) {
	if err != nil {
		switch udpErrClass(err) {
		case udpMsgSize:
			return nil, PeerKey{}, ReadTruncated, nil
		case udpNoise:
			return nil, PeerKey{}, ReadNoise, nil
		}
		return nil, PeerKey{}, ReadOK, err
	}
	if n < 0 || n > len(b) {
		return nil, PeerKey{}, ReadOK, errUDPReadCount
	}
	if flags&udpMsgTrunc != 0 || n == len(b) {
		return nil, PeerKey{}, ReadTruncated, nil
	}
	key := PeerKey{AP: unmapAddrPort(src)}
	switch {
	case n == 0:
		return nil, key, ReadEmpty, nil
	case key.AP != o.peer:
		return nil, key, ReadForeign, nil
	case n < wire.FlowHeaderLen || [wire.FlowHeaderLen]byte(b[:wire.FlowHeaderLen]) != o.hdr:
		return nil, key, ReadBadEnvelope, nil
	case n == wire.FlowHeaderLen:
		return nil, key, ReadEmpty, nil // the flow's header and no rendr bytes: nothing to hand over
	}
	return b[wire.FlowHeaderLen:n], key, ReadOK, nil
}

// Release implements PacketIO (no-op).
func (o *OwnedUDP) Release() {}

// Headroom implements PacketIO: the flow header.
func (o *OwnedUDP) Headroom() int { return wire.FlowHeaderLen }

// WriteDatagram implements PacketIO: it writes the flow header into
// b[:Headroom()] and sends b to the peer with one WriteToUDPAddrPort.
// EMSGSIZE and WSAEMSGSIZE are a *wire.DatagramTooLargeError with Max 0
// (after carrier/udp's interface-MTU clamp only a route change produces
// them; the MTU probe then decides, R1-16); noise errors ErrNoise; a count
// other than len(b) an error (L42: the carrier dies, never retried on it);
// every other error, ECONNABORTED included, is returned (death).
func (o *OwnedUDP) WriteDatagram(b []byte) error {
	*(*[wire.FlowHeaderLen]byte)(b) = o.hdr
	n, err := o.u.WriteToUDPAddrPort(b, o.peer)
	return udpWriteResult(n, len(b), err, false)
}

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
// Ownership of u moves to the token. It panics for a MaxDatagram out of
// range (546–65,507; a programming error of carrier/udp).
func NewOwnedUDPSocket(u *net.UDPConn, maxDatagram int) *OwnedUDPSocket {
	checkMaxDatagram(maxDatagram)
	return &OwnedUDPSocket{u: u, limit: maxDatagram}
}

// MaxDatagram returns the largest UDP payload the socket reads and writes.
func (s *OwnedUDPSocket) MaxDatagram() int { return s.limit }

// ReadAddrPort reads one datagram into p (len(p) ≥ MaxDatagram + 1) and
// returns its length and source; ev is ReadTruncated, ReadEmpty or
// ReadNoise for a datagram or error that is not handed over (M2 design
// §A6.4); err is a permanent socket error.
func (s *OwnedUDPSocket) ReadAddrPort(p []byte) (n int, src netip.AddrPort, ev ReadEvent, err error) {
	b := p[:s.limit+1]
	n, _, flags, src, err := s.u.ReadMsgUDPAddrPort(b, nil)
	return s.readResult(b, n, flags, src, err)
}

// readResult maps one read of the listening socket into b as OwnedUDP's
// does, without the source and flow checks (package udpflow demultiplexes
// by flow ID and source). The source is unmapped (an IPv4 client of a
// dual-stack socket appears as IPv4), so it compares equal to the AddrPort
// of a *net.UDPAddr source and writes back to the same client. ECONNABORTED
// is ReadNoise here: the socket is bound explicitly and keeps receiving
// after an administrative abort, which must not end every flow (§A6.1).
func (s *OwnedUDPSocket) readResult(b []byte, n, flags int, src netip.AddrPort, err error) (int, netip.AddrPort, ReadEvent, error) {
	if err != nil {
		switch udpErrClass(err) {
		case udpMsgSize:
			return 0, netip.AddrPort{}, ReadTruncated, nil
		case udpNoise, udpAbort:
			return 0, netip.AddrPort{}, ReadNoise, nil
		}
		return 0, netip.AddrPort{}, ReadOK, err
	}
	if n < 0 || n > len(b) {
		return 0, netip.AddrPort{}, ReadOK, errUDPReadCount
	}
	if flags&udpMsgTrunc != 0 || n == len(b) {
		return 0, netip.AddrPort{}, ReadTruncated, nil
	}
	src = unmapAddrPort(src)
	if n == 0 {
		return 0, src, ReadEmpty, nil
	}
	return n, src, ReadOK, nil
}

// WriteAddrPort sends p as one datagram to dst. EMSGSIZE and WSAEMSGSIZE are
// a *wire.DatagramTooLargeError with Max 0 (with the interface-MTU clamp of
// R1-16 only a route change produces them; the MTU probe then decides);
// ICMP-class errors ErrNoise.
func (s *OwnedUDPSocket) WriteAddrPort(p []byte, dst netip.AddrPort) error {
	n, err := s.u.WriteToUDPAddrPort(p, dst)
	return udpWriteResult(n, len(p), err, true)
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

// SyscallConn exposes the raw socket for socket-option tests (don't-fragment
// and buffer sizes), as OwnedTCP's does.
func (s *OwnedUDPSocket) SyscallConn() (syscall.RawConn, error) { return s.u.SyscallConn() }

var _ net.PacketConn = (*OwnedUDPSocket)(nil)

// udpClass classifies an error of rendr's own UDP sockets (M2 design
// §A6.4; the errno sets are per OS: owned_udp_unix.go,
// owned_udp_windows.go, owned_udp_other.go).
type udpClass uint8

const (
	udpOther   udpClass = iota // returned to the caller: a permanent error (death), a closed socket, or the caller's deadline
	udpNoise                   // ICMP class, ENOBUFS, Temporary(): the datagram or read is lost, the carrier lives
	udpMsgSize                 // EMSGSIZE, WSAEMSGSIZE: a write refused as too large; on Windows also a truncated read
	udpAbort                   // ECONNABORTED, WSAECONNABORTED: death on a dialer socket, noise on a listening one
)

// udpErrClass classifies err. The caller's deadline comes first (an
// expired deadline is Temporary() too, and must reach the caller as a
// timeout: handshakes, closers and the write-stall watchdog rely on it),
// then the platform's errno table, then Temporary().
func udpErrClass(err error) udpClass {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return udpOther
	}
	if c := udpErrnoClass(err); c != udpOther {
		return c
	}
	var t interface{ Temporary() bool }
	if errors.As(err, &t) && t.Temporary() {
		return udpNoise
	}
	return udpOther
}

// udpWriteResult maps one write of a datagram of want bytes to the PacketIO
// contract: too large → errUDPTooLarge, noise → ErrNoise, an abort → ErrNoise
// on a listening socket (the shared socket stays bound and in use), a count
// other than want → errUDPWriteCount (L42), anything else as is.
func udpWriteResult(n, want int, err error, listening bool) error {
	if err != nil {
		switch udpErrClass(err) {
		case udpMsgSize:
			return errUDPTooLarge
		case udpNoise:
			return ErrNoise
		case udpAbort:
			if listening {
				return ErrNoise
			}
		}
		return err
	}
	if n != want {
		return errUDPWriteCount
	}
	return nil
}

var (
	// errUDPTooLarge is the refusal of rendr's own sockets: the size the
	// path carries now is unknown (Max 0), so it lowers no budget and the
	// MTU probe decides (M2-D25, R1-16). One shared value, never modified:
	// a refusal allocates nothing.
	errUDPTooLarge error = &wire.DatagramTooLargeError{}
	// errUDPWriteCount: a datagram write that reported another count than
	// the datagram's length (L42, PA-19).
	errUDPWriteCount = errors.New("rendr/carrier: UDP datagram write returned an invalid count")
	// errUDPReadCount: a datagram read that reported a count outside the
	// buffer (L42).
	errUDPReadCount = errors.New("rendr/carrier: UDP datagram read returned an invalid count")
)

// checkMaxDatagram panics unless n is a valid MaxDatagram: room for the
// flow header and the smallest frame budget, and at most a UDP payload.
func checkMaxDatagram(n int) {
	if n < wire.MinFrameBudget+wire.FlowHeaderLen || n > wire.MaxDatagram {
		panic("rendr/carrier: UDP MaxDatagram out of range")
	}
}

// unmapAddrPort returns ap with an IPv4-mapped IPv6 address unmapped.
func unmapAddrPort(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}
