package carrier

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// packetIO is the PacketIO NewPacketIO returns for an embedder
// net.PacketConn (M2-D4; M2 design §A6.4): exactly one peer, the embedder's
// interface methods only, each through a guarded call (a panic is an error;
// runtime.Goexit unwinds to the calling goroutine's own guard), every count
// checked, every error classified by ClassifyPacketErr. No other method of
// pc or of an address is called — a source address's String() only, under
// a panic guard, when the peer is neither the same value nor a
// *net.UDPAddr (L38, L57).
type packetIO struct {
	env   *Env
	pc    net.PacketConn
	peer  net.Addr // the embedder's original peer value: every WriteTo passes it
	key   PeerKey  // the peer, normalised once
	udp   bool     // the peer is a *net.UDPAddr: key.AP is its address
	limit int      // Limit: the factory MTU (dialer) or wire.MaxDatagram (HandlePacket)
	recv  int      // the receive limit: limit until SetLimit (before Start only; read by the reader after Start)

	closed atomic.Bool
}

// Errors of NewPacketIO.
var (
	errPacketIONil   = errors.New("rendr/carrier: NewPacketIO: nil conn or peer")
	errPacketIOLimit = errors.New("rendr/carrier: NewPacketIO: limit outside the frame budget range")
)

func newPacketIO(env *Env, pc net.PacketConn, peer net.Addr, limit int) (*packetIO, error) {
	if pc == nil || nilAddr(peer) {
		return nil, errPacketIONil
	}
	if limit < wire.MinFrameBudget || limit > wire.MaxDatagram {
		return nil, fmt.Errorf("%w: %d", errPacketIOLimit, limit)
	}
	p := &packetIO{env: env, pc: pc, peer: peer, limit: limit, recv: limit}
	if ua, ok := peer.(*net.UDPAddr); ok {
		p.key, p.udp = PeerKey{AP: udpAddrPort(ua)}, true
		return p, nil
	}
	s, err := addrString(peer)
	if err != nil {
		return nil, fmt.Errorf("rendr/carrier: NewPacketIO: peer: %w", err)
	}
	p.key = PeerKey{Str: s}
	return p, nil
}

// udpAddrPort returns a *net.UDPAddr's address and port, an IPv4-mapped
// address unmapped (as rendr's own sockets report their sources).
func udpAddrPort(ua *net.UDPAddr) netip.AddrPort {
	return unmapAddrPort(ua.AddrPort())
}

// addrString returns a.String() under a panic guard.
func addrString(a net.Addr) (s string, err error) {
	defer func() {
		if r := recover(); r != nil {
			s, err = "", &panicError{"Addr.String", r}
		}
	}()
	return a.String(), nil
}

// sameAddr reports a == b as interface values (pointer identity for pointer
// types); a dynamic type that cannot be compared is not the same.
func sameAddr(a, b net.Addr) (same bool) {
	defer func() {
		if recover() != nil {
			same = false
		}
	}()
	return a == b
}

// isPeer reports whether src is the peer: the same value (the QUIC facade
// and most embedder conns return the peer they were given), a
// *net.UDPAddr compared as an address and port, or else the guarded
// String() of src compared with the peer's (a panicking String is not the
// peer).
func (p *packetIO) isPeer(src net.Addr) bool {
	if src == nil {
		return false
	}
	if sameAddr(src, p.peer) {
		return true
	}
	if ua, ok := src.(*net.UDPAddr); ok {
		return ua != nil && p.udp && udpAddrPort(ua) == p.key.AP
	}
	if p.udp {
		return false
	}
	s, err := addrString(src)
	return err == nil && s == p.key.Str
}

// ReadSize implements PacketIO: the receive limit + 1 (no headroom).
func (p *packetIO) ReadSize() int { return p.recv + 1 }

// SetLimit implements PacketIO: the receive limit, within
// [wire.MinFrameBudget, Limit()].
func (p *packetIO) SetLimit(n int) { p.recv = min(max(n, wire.MinFrameBudget), p.limit) }

// ReadDatagram implements PacketIO: one ReadFrom into exactly the first
// ReadSize() bytes of buf. A count outside the buffer is an error (L42); an
// error is classified (noise → ReadNoise, a size error → ReadTruncated, the
// caller's deadline, an abort and every other error returned: an abort ends
// a carrier's own conn); a datagram filling the buffer is ReadTruncated
// (plan:634), an empty one ReadEmpty (PA-18), one from another source
// ReadForeign (L59).
func (p *packetIO) ReadDatagram(buf []byte) ([]byte, PeerKey, ReadEvent, error) {
	b := buf[:p.ReadSize()]
	n, src, err := callReadFrom(p.pc, b)
	if n < 0 || n > len(b) {
		return nil, PeerKey{}, ReadOK, &countError{"ReadFrom", n, len(b)}
	}
	if err != nil {
		switch ClassifyPacketErr(err, false) {
		case PacketErrNoise:
			return nil, PeerKey{}, ReadNoise, nil
		case PacketErrSize:
			return nil, PeerKey{}, ReadTruncated, nil
		}
		return nil, PeerKey{}, ReadOK, err // death (an abort included) or the caller's deadline
	}
	switch {
	case n == len(b):
		return nil, PeerKey{}, ReadTruncated, nil
	case n == 0:
		return nil, PeerKey{}, ReadEmpty, nil
	case !p.isPeer(src):
		return nil, PeerKey{}, ReadForeign, nil
	}
	return b[:n], p.key, ReadOK, nil
}

// Release implements PacketIO (no-op).
func (p *packetIO) Release() {}

// Headroom implements PacketIO: embedder conns carry rendr bytes only.
func (p *packetIO) Headroom() int { return 0 }

// WriteDatagram implements PacketIO: one WriteTo of b to the original peer
// value. A count outside [0, len(b)] or other than len(b) is an error that
// is neither noise nor a size refusal (L42: the carrier dies, never
// retried); a size error is a *wire.DatagramTooLargeError (the embedder's
// own, with its Max, or Max 0 for EMSGSIZE); noise — EPERM included
// (integration 1, D11) — is ErrNoise; the caller's deadline, an abort and
// every other error are returned (write stall or death).
func (p *packetIO) WriteDatagram(b []byte) error {
	n, err := callWriteTo(p.pc, b, p.peer)
	if n < 0 || n > len(b) {
		return &countError{"WriteTo", n, len(b)}
	}
	if err != nil {
		switch ClassifyPacketErr(err, true) {
		case PacketErrNoise:
			return ErrNoise
		case PacketErrSize:
			if errors.Is(err, wire.ErrDatagramTooLarge) {
				return err // keeps its Max (M2-D25)
			}
			return errUDPTooLarge // EMSGSIZE: the size the path carries is unknown (Max 0)
		}
		return err
	}
	if n != len(b) {
		return &countError{"WriteTo", n, len(b)}
	}
	return nil
}

// WriteDatagramTo implements PacketIO: an embedder conn never rebinds.
func (p *packetIO) WriteDatagramTo(b []byte, dst PeerKey) error { return ErrNoRebind }

// SetPeer implements PacketIO: an embedder conn never rebinds.
func (p *packetIO) SetPeer(dst PeerKey) error { return ErrNoRebind }

// SetDeadline implements PacketIO (guarded).
func (p *packetIO) SetDeadline(t time.Time) error { return callSetDeadline(p.pc, t) }

// SetReadDeadline implements PacketIO (guarded).
func (p *packetIO) SetReadDeadline(t time.Time) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = &panicError{"SetReadDeadline", r}
		}
	}()
	return p.pc.SetReadDeadline(t)
}

// SetWriteDeadline implements PacketIO (guarded).
func (p *packetIO) SetWriteDeadline(t time.Time) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = &panicError{"SetWriteDeadline", r}
		}
	}()
	return p.pc.SetWriteDeadline(t)
}

// Close implements PacketIO: the embedder's Close, exactly once.
func (p *packetIO) Close() error {
	if !p.closed.CompareAndSwap(false, true) {
		return nil
	}
	return callClose(p.pc)
}

// Limit implements PacketIO.
func (p *packetIO) Limit() int { return p.limit }

var _ PacketIO = (*packetIO)(nil)

// callReadFrom and callWriteTo are the guarded embedder calls of a packet
// conn (L51): a panic becomes a *panicError; counts are checked by the
// caller.
func callReadFrom(pc net.PacketConn, b []byte) (n int, src net.Addr, err error) {
	defer func() {
		if r := recover(); r != nil {
			n, src, err = 0, nil, &panicError{"ReadFrom", r}
		}
	}()
	return pc.ReadFrom(b)
}

func callWriteTo(pc net.PacketConn, b []byte, dst net.Addr) (n int, err error) {
	defer func() {
		if r := recover(); r != nil {
			n, err = 0, &panicError{"WriteTo", r}
		}
	}()
	return pc.WriteTo(b, dst)
}
