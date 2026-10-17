package rendr

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/session"
)

// Conn is one end of a stream session. It implements net.Conn; its
// addresses are logical (Addr) and stable across migrations. All methods
// are safe for concurrent use; concurrent Writes are serialized and never
// interleave, as are concurrent Reads.
type Conn struct {
	s     *session.Session
	local Addr
	props *peerProps // dialer: the Peer's Props (CarrierStatus.FateGroup); nil on the passive
}

var _ net.Conn = (*Conn)(nil)

// newConn wraps the session s of rt. The local address is fixed here; the
// remote one is the session's bound peer instance (remote).
func newConn(rt *Runtime, s *session.Session) *Conn {
	return &Conn{s: s, local: Addr{Instance: rt.id, Session: SessionID(s.ID())}}
}

// remote is Addr{peer instance, session}. The session binds its peer
// instance once (passive: the OPEN's PREFACE; dialer: the first
// OPEN_ACK(OK), before Dial returns unless EarlyReturn) and never rebinds
// it (L38, M4-D15), so the address is read from the session: the zero
// InstanceID until an EarlyReturn session's peer answered, then fixed.
func (c *Conn) remote() Addr {
	a := Addr{Session: c.local.Session}
	if c.s.PeerBound() {
		a.Instance = InstanceID(c.s.PeerInstance())
	}
	return a
}

// Read reads delivered bytes. io.EOF is returned only when the peer's FIN
// reached the contiguous delivery point; carrier failures never surface.
// After a session failure Read returns its error (ErrNoPath, ErrSessionLost,
// *AbortError, ErrIdleTimeout); after local Close, net.ErrClosed; after the
// read deadline, os.ErrDeadlineExceeded (the session is unaffected).
func (c *Conn) Read(p []byte) (int, error) { return c.s.Read(p) }

// Write copies p into the session's send buffer and returns. n is what the
// session accepted; on a deadline the accepted bytes are still delivered,
// after a session failure they are not guaranteed. It returns net.ErrClosed
// after Close or CloseWrite.
func (c *Conn) Write(p []byte) (int, error) { return c.s.Write(p) }

// Close returns at once. Buffered and further incoming data is discarded;
// blocked calls return net.ErrClosed; the session delivers what was written
// and finishes in the background within Linger, or resets the peer
// (AbortClosed if the peer keeps sending, AbortLinger at expiry); Done is
// closed once it has ended. Runtime.Close resets a closed session that has
// not finished yet (it ends with net.ErrClosed, the peer's with
// *AbortError, or with io.EOF if both FINs had already been delivered). The
// clean end: Read until io.EOF (the peer's FIN arrived, so Close discards
// nothing), Close (this side's FIN, unless CloseWrite sent it), wait for
// Done bounded by your own context (Status().Err is io.EOF after a clean
// finish), and only then Runtime.Close.
func (c *Conn) Close() error { return c.s.Close() }

// CloseWrite sends one FIN after everything written so far (idempotent);
// later Writes return net.ErrClosed; reading continues until the peer's FIN.
func (c *Conn) CloseWrite() error { return c.s.CloseWrite() }

// LocalAddr returns Addr{this Runtime, session}.
func (c *Conn) LocalAddr() net.Addr { return c.local }

// RemoteAddr returns Addr{peer instance, session}. With
// DialOptions.EarlyReturn its Instance is zero until the peer accepted the
// session; it never changes afterwards.
func (c *Conn) RemoteAddr() net.Addr { return c.remote() }

// SetDeadline sets the read and the write deadline, as SetReadDeadline and
// SetWriteDeadline do (net.Conn semantics).
func (c *Conn) SetDeadline(t time.Time) error {
	rerr := c.s.SetReadDeadline(t)
	if werr := c.s.SetWriteDeadline(t); rerr == nil {
		rerr = werr
	}
	return rerr
}

// SetReadDeadline sets the read deadline: blocked Reads re-evaluate at once;
// zero clears it; a past time fails Reads immediately with
// os.ErrDeadlineExceeded.
func (c *Conn) SetReadDeadline(t time.Time) error { return c.s.SetReadDeadline(t) }

// SetWriteDeadline sets the write deadline; a Write that times out after
// partial acceptance returns (k, os.ErrDeadlineExceeded) and the k bytes are
// delivered.
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.s.SetWriteDeadline(t) }

// ID returns the session ID.
func (c *Conn) ID() SessionID { return c.local.Session }

// PeerInstance returns the peer InstanceID the session is bound to: with
// DialOptions.EarlyReturn the zero InstanceID until the peer accepted the
// session, then fixed for the session's life.
func (c *Conn) PeerInstance() InstanceID { return c.remote().Instance }

// Metadata returns the session's OPEN metadata (do not modify).
func (c *Conn) Metadata() []byte { return c.s.Metadata() }

// Status returns a snapshot of the session (the diagnostic surface and the
// test oracle). The control part is published by the session's scheduler
// together with every routing change, so the reported active carrier always
// equals the routed one.
func (c *Conn) Status() SessionStatus { return c.props.status(c.s.Status()) }

// Done returns a channel that is closed once the session has fully ended:
// Status().State is StateEnded with its final Err (io.EOF after a clean
// finish; else the end error, such as ErrNoPath, *AbortError, or
// net.ErrClosed when this side reset the session), Status().Carriers lists
// only dead carriers (no dial attempt is left), and every goroutine the
// session owns has finished its work (its scheduler exits right after
// closing Done) or, if stuck in embedder code, was abandoned after its
// bound and counted in the Runtime's Status.Abandoned. It is the same
// channel on every call, closed exactly once, for dialer and passive Conns
// alike, and never before that end. Status may report StateEnded slightly
// earlier: Done also waits for the session's carriers and dial attempts to
// finish (within about 2 s).
//
// Done only observes the end. A session ends by itself once both FINs were
// delivered and acknowledged, after Close within Linger, on a failure
// (ErrNoPath, ErrSessionLost, *AbortError, ErrIdleTimeout), or when
// Runtime.Close resets it. For a clean end, wait for Done before
// Runtime.Close (see Close).
func (c *Conn) Done() <-chan struct{} { return c.s.Done() }

// Abort resets the session now: an RST with code goes to the peer, whose
// pending and later Reads and Writes return *AbortError{Code: code, Msg:
// msg (at most 255 bytes), Remote: true}; data not yet delivered in either
// direction is discarded; this side's calls return net.ErrClosed; Done
// closes once the session's carriers are released. code must be at least
// 256 (smaller codes are rendr's); otherwise Abort returns an error and does
// nothing. It is idempotent; after the session ended it does nothing; after
// Close it replaces the linger with the reset; on a session dialled with
// EarlyReturn that has no answer yet it withdraws the OPEN. Abort, Close,
// CloseWrite and a peer's RST racing resolve to one end.
func (c *Conn) Abort(code AbortCode, msg string) error {
	if code < 256 {
		return fmt.Errorf("rendr: Abort code %d is reserved (codes below 256 are rendr's)", uint32(code))
	}
	return c.s.Abort(uint32(code), msg)
}

// SetIdleTimeout overrides Config.IdleTimeout for this session from now on,
// with the same meaning and clamp: 0 or a negative value turns idle expiry
// off; other values are clamped to 10 s–24 h. The idle clock is not
// restarted. Both roles. It returns net.ErrClosed once the session has
// ended.
func (c *Conn) SetIdleTimeout(d time.Duration) error {
	return c.s.SetIdleTimeout(d)
}

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
	raddr  net.Addr   // remote boxed once: ReadFrom returns it without allocating
	props  *peerProps // dialer: the Peer's Props (CarrierStatus.FateGroup); nil on the passive
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
func (c *PacketConn) Status() SessionStatus { return c.props.status(c.s.Status()) }

// Done is closed when the session has ended and every carrier goroutine was
// joined (or abandoned and counted).
func (c *PacketConn) Done() <-chan struct{} { return c.s.Done() }

// SetIdleTimeout overrides Config.IdleTimeout for this packet session from
// now on, with Conn.SetIdleTimeout's meaning and clamp: 0 or a negative
// value turns idle expiry off; other values are clamped to 10 s–24 h. The
// idle clock (moved by every accepted WriteTo, every datagram accepted from
// a carrier and every datagram ReadFrom returns) is not restarted. Both
// roles. It returns net.ErrClosed once the session has ended.
func (c *PacketConn) SetIdleTimeout(d time.Duration) error { return c.s.SetIdleTimeout(d) }

// DialPacket opens a packet session (see PacketConn). It is Dial for
// datagrams: the same race, ranking, waiting and errors, with datagram
// factories ranked before stream factories. The session's MaxPayload is
// fixed by the OPEN exchange: the smallest datagram budget of the Peer's
// datagram factories (bond or race with a stream factory:
// Packet.MaxPayload, the stream members carrying what the datagram members
// cannot), bounded by
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
	c := newPacketConn(p.rt, s)
	c.props = &p.props // CarrierStatus.FateGroup
	return c, nil
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

// Context returns a context that is done once this pending packet session
// can no longer be confirmed: at Confirm, Reject, AcceptTimeout, the
// dialer's withdrawal, Listener.Close or Runtime.Close. Its Deadline is the
// AcceptTimeout instant; Err is context.DeadlineExceeded when AcceptTimeout
// ended it, else context.Canceled. No goroutine waits on it, also under
// context.AfterFunc (it has an AfterFunc method), as PendingConn.Context.
func (p *PendingPacket) Context() context.Context { return pendingPacketCtx{pendingCtx{s: p.s}} }
