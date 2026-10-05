package rendr

import (
	"net"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/session"
)

// Conn is one end of a stream session. It implements net.Conn; its
// addresses are logical (Addr) and stable across migrations. All methods
// are safe for concurrent use; concurrent Writes are serialized and never
// interleave, as are concurrent Reads.
type Conn struct {
	s      *session.Session
	local  Addr
	remote Addr
}

var _ net.Conn = (*Conn)(nil)

// newConn wraps the session s of rt. The peer instance is bound before a
// session is handed to the application (dialer: the first OPEN_ACK(OK);
// passive: the OPEN's PREFACE), so both addresses are fixed here.
func newConn(rt *Runtime, s *session.Session) *Conn {
	sid := SessionID(s.ID())
	return &Conn{
		s:      s,
		local:  Addr{Instance: rt.id, Session: sid},
		remote: Addr{Instance: InstanceID(s.PeerInstance()), Session: sid},
	}
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

// RemoteAddr returns Addr{peer instance, session}.
func (c *Conn) RemoteAddr() net.Addr { return c.remote }

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

// PeerInstance returns the peer InstanceID the session is bound to.
func (c *Conn) PeerInstance() InstanceID { return c.remote.Instance }

// Metadata returns the session's OPEN metadata (do not modify).
func (c *Conn) Metadata() []byte { return c.s.Metadata() }

// Status returns a snapshot of the session (the diagnostic surface and the
// test oracle). The control part is published by the session's scheduler
// together with every routing change, so the reported active carrier always
// equals the routed one.
func (c *Conn) Status() SessionStatus { return sessionStatusFrom(c.s.Status()) }

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
