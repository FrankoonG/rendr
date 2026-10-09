package rendr

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/session"
)

// PacketConn is one end of a packet session (plan §7; M2). It implements
// net.PacketConn: each WriteTo is one datagram, delivered at most once,
// possibly reordered, or lost — only datagrams in flight on a carrier that
// dies, or dropped by the session's bounded queues (see PacketCounters);
// nothing is retransmitted. Each ReadFrom returns one datagram. Carrier
// changes are invisible: the addresses are logical (Addr) and never change.
// All methods are safe for concurrent use.
type PacketConn struct {
	s      *session.Session
	local  Addr
	remote Addr
	raddr  net.Addr // remote boxed once: ReadFrom returns it without allocating
}

var _ net.PacketConn = (*PacketConn)(nil)

// newPacketConn wraps the packet session s of rt; the peer instance is
// bound before the session is handed to the application, so both
// addresses are fixed here. The remote address is boxed once, so ReadFrom
// returns it without allocating.
func newPacketConn(rt *Runtime, s *session.Session) *PacketConn {
	sid := SessionID(s.ID())
	c := &PacketConn{
		s:      s,
		local:  Addr{Instance: rt.id, Session: sid},
		remote: Addr{Instance: InstanceID(s.PeerInstance()), Session: sid},
	}
	c.raddr = c.remote
	return c
}

// ReadFrom returns the next datagram and the session's remote address. A
// datagram longer than p returns (len(p), addr, io.ErrShortBuffer) and its
// rest is discarded (unlike net.UDPConn, which truncates silently). io.EOF
// comes only after the peer closed, once every datagram it sent that
// arrived was returned (or did not arrive within a short bound after its
// close); then calls return net.ErrClosed after Close, the session's end
// error after a failure, or os.ErrDeadlineExceeded after the read deadline.
func (c *PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.s.ReadFrom(p)
	if err != nil && !errors.Is(err, io.ErrShortBuffer) {
		return n, nil, err
	}
	return n, c.raddr, err
}

// WriteTo queues p as one datagram and returns (len(p), nil) at once: it
// never blocks (a full queue drops its oldest datagram). addr must be nil
// or the session's remote address (an Addr or a non-nil *Addr), else
// ErrPacketDestinationMismatch, without calling any method of addr. len(p)
// above MaxPayload returns (0, ErrPacketTooLarge). After Close or after the
// peer closed: net.ErrClosed; after a failure the end error; past the write
// deadline (0, os.ErrDeadlineExceeded) with nothing queued.
func (c *PacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if !c.isRemote(addr) {
		return 0, ErrPacketDestinationMismatch
	}
	return c.s.WriteTo(p)
}

// isRemote reports whether addr names this session's peer: nil, the remote
// Addr, or a non-nil *Addr holding it. Nothing of addr but its dynamic type
// is used — no method of a foreign address is ever called (L38), and a
// typed nil *Addr is a mismatch.
func (c *PacketConn) isRemote(addr net.Addr) bool {
	switch a := addr.(type) {
	case nil:
		return true
	case Addr:
		return a == c.remote
	case *Addr:
		return a != nil && *a == c.remote
	}
	return false
}

// Close returns at once: later calls return net.ErrClosed and received
// datagrams are discarded; datagrams already queued are still sent while
// younger than Packet.MaxAge, then the session's end is signalled to the
// peer. The session ends once both sides confirmed the end (Done), or after
// Linger with a reset. There is no half-close: the peer's ReadFrom returns
// io.EOF after the datagrams it holds, and its WriteTo net.ErrClosed.
func (c *PacketConn) Close() error { return c.s.Close() }

// LocalAddr returns this end's logical address.
func (c *PacketConn) LocalAddr() net.Addr { return c.local }

// RemoteAddr returns the peer's logical address, the address ReadFrom
// returns. It never changes.
func (c *PacketConn) RemoteAddr() net.Addr { return c.remote }

// SetDeadline sets the read and write deadlines (net.PacketConn semantics).
func (c *PacketConn) SetDeadline(t time.Time) error {
	if err := c.s.SetReadDeadline(t); err != nil {
		return err
	}
	return c.s.SetWriteDeadline(t)
}

// SetReadDeadline sets the deadline of ReadFrom calls.
func (c *PacketConn) SetReadDeadline(t time.Time) error { return c.s.SetReadDeadline(t) }

// SetWriteDeadline sets the deadline of WriteTo calls (WriteTo never waits:
// only a deadline already passed matters).
func (c *PacketConn) SetWriteDeadline(t time.Time) error { return c.s.SetWriteDeadline(t) }

// ID returns the session ID.
func (c *PacketConn) ID() SessionID { return c.local.Session }

// PeerInstance returns the peer Runtime's InstanceID bound at OPEN.
func (c *PacketConn) PeerInstance() InstanceID { return c.remote.Instance }

// Metadata returns the OPEN metadata.
func (c *PacketConn) Metadata() []byte { return c.s.Metadata() }

// MaxPayload returns the largest datagram WriteTo accepts and the peer may
// send, fixed when the session opened.
func (c *PacketConn) MaxPayload() int { return c.s.MaxPayload() }

// Status returns a snapshot of the session.
func (c *PacketConn) Status() SessionStatus { return sessionStatusFrom(c.s.Status()) }

// Done is closed when the session has ended and every carrier goroutine was
// joined (or abandoned and counted).
func (c *PacketConn) Done() <-chan struct{} { return c.s.Done() }

// DialPacket opens a packet session (see PacketConn). It is Dial for
// datagrams: the same race, ranking, waiting and errors, with datagram
// factories ranked before stream factories. The session's MaxPayload is
// fixed by the OPEN exchange: the smallest datagram budget of the Peer's
// datagram factories (bond with a stream factory: Packet.MaxPayload, the
// stream members carrying what the datagram members cannot), bounded by
// both sides' Packet.MaxPayload. Metadata that no factory able to carry an
// OPEN can carry is refused at once with ErrMetadataTooLarge (a datagram
// factory carries at most its MTU − 99 bytes of metadata). A carrier/udp
// carrier clamped at its Dial to a smaller route MTU carries less than its
// factory MTU: an OPEN that does not fit it fails that attempt, and when
// every datagram factory returned such a carrier, a Dial that would end
// with ErrNoPath (after NoPathGrace) ends with ErrMetadataTooLarge.
func (p *Peer) DialPacket(ctx context.Context, o DialOptions) (*PacketConn, error) {
	s, err := p.dial(ctx, o, true)
	if err != nil {
		return nil, err
	}
	return newPacketConn(p.rt, s), nil
}

// AcceptPacket returns the next pending packet session; Accept returns only
// stream sessions. Same ctx, backlog and Close rules as Accept: the packet
// backlog is separate (ListenConfig.AcceptBacklog per session kind).
func (ln *Listener) AcceptPacket(ctx context.Context) (*PendingPacket, error) {
	it, err := ln.next(ctx, kindIdxPacket)
	if err != nil {
		return nil, err
	}
	return &PendingPacket{s: it.s, ln: ln, it: it}, nil
}

// PendingPacket is a packet session waiting for Confirm or Reject; the
// rules of PendingConn apply (AcceptTimeout answers CAPACITY).
type PendingPacket struct {
	s  *session.Session
	ln *Listener
	it *pendItem // its backlog slot: marked when the Listener closed
}

// ID returns the session ID.
func (p *PendingPacket) ID() SessionID { return SessionID(p.s.ID()) }

// Mode returns the session's mode.
func (p *PendingPacket) Mode() Mode { return Mode(p.s.Mode()) }

// Metadata returns the OPEN metadata.
func (p *PendingPacket) Metadata() []byte { return p.s.Metadata() }

// PeerInstance returns the dialer's InstanceID.
func (p *PendingPacket) PeerInstance() InstanceID { return InstanceID(p.s.PeerInstance()) }

// MaxPayload returns the session's MaxPayload: the value Confirm's
// OPEN_ACK carries, fixed when the OPEN was admitted (M2 design Revision 1,
// R1-32).
func (p *PendingPacket) MaxPayload() int { return p.s.MaxPayload() }

// Confirm accepts the session (OPEN_ACK OK) and returns its PacketConn.
func (p *PendingPacket) Confirm() (*PacketConn, error) {
	if err := p.s.Confirm(); err != nil {
		return nil, decisionErr(p.it, err)
	}
	return newPacketConn(p.ln.rt, p.s), nil
}

// Reject refuses the session (OPEN_ACK REJECTED); the dialer's DialPacket
// returns *RejectError{code, msg}.
func (p *PendingPacket) Reject(code uint32, msg string) error {
	return decisionErr(p.it, p.s.Reject(code, msg))
}
