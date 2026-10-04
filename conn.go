package rendr

import (
	"net"
	"time"
)

// Conn is one end of a stream session. It implements net.Conn; its
// addresses are logical (Addr) and stable across migrations. All methods
// are safe for concurrent use; concurrent Writes are serialized and never
// interleave, as are concurrent Reads.
type Conn struct {
	_ struct{} // unexported state is defined by the implementation
}

var _ net.Conn = (*Conn)(nil)

// Read reads delivered bytes. io.EOF is returned only when the peer's FIN
// reached the contiguous delivery point; carrier failures never surface.
// After a session failure Read returns its error (ErrNoPath, ErrSessionLost,
// *AbortError, ErrIdleTimeout); after local Close, net.ErrClosed; after the
// read deadline, os.ErrDeadlineExceeded (the session is unaffected).
func (c *Conn) Read(p []byte) (int, error) {
	panic("unimplemented: M1b")
}

// Write copies p into the session's send buffer and returns. n is what the
// session accepted; on a deadline the accepted bytes are still delivered,
// after a session failure they are not guaranteed. It returns net.ErrClosed
// after Close or CloseWrite.
func (c *Conn) Write(p []byte) (int, error) {
	panic("unimplemented: M1b")
}

// Close returns at once. Buffered and further incoming data is discarded;
// blocked calls return net.ErrClosed; the session delivers what was written
// and finishes in the background within Linger, or resets the peer
// (AbortClosed if the peer keeps sending, AbortLinger at expiry).
func (c *Conn) Close() error {
	panic("unimplemented: M1b")
}

// CloseWrite sends one FIN after everything written so far (idempotent);
// later Writes return net.ErrClosed; reading continues until the peer's FIN.
func (c *Conn) CloseWrite() error {
	panic("unimplemented: M1b")
}

// LocalAddr returns Addr{this Runtime, session}.
func (c *Conn) LocalAddr() net.Addr {
	panic("unimplemented: M1b")
}

// RemoteAddr returns Addr{peer instance, session}.
func (c *Conn) RemoteAddr() net.Addr {
	panic("unimplemented: M1b")
}

// SetDeadline sets both deadlines (net.Conn semantics; L06).
func (c *Conn) SetDeadline(t time.Time) error {
	panic("unimplemented: M1b")
}

// SetReadDeadline sets the read deadline: blocked Reads re-evaluate at once;
// zero clears it; a past time fails Reads immediately with
// os.ErrDeadlineExceeded.
func (c *Conn) SetReadDeadline(t time.Time) error {
	panic("unimplemented: M1b")
}

// SetWriteDeadline sets the write deadline; a Write that times out after
// partial acceptance returns (k, os.ErrDeadlineExceeded) and the k bytes are
// delivered.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	panic("unimplemented: M1b")
}

// ID returns the session ID.
func (c *Conn) ID() SessionID {
	panic("unimplemented: M1b")
}

// PeerInstance returns the peer InstanceID the session is bound to.
func (c *Conn) PeerInstance() InstanceID {
	panic("unimplemented: M1b")
}

// Metadata returns the session's OPEN metadata (do not modify).
func (c *Conn) Metadata() []byte {
	panic("unimplemented: M1b")
}

// Status returns a snapshot of the session (the diagnostic surface and the
// test oracle). The control part is published by the session's scheduler
// together with every routing change, so the reported active carrier always
// equals the routed one.
func (c *Conn) Status() SessionStatus {
	panic("unimplemented: M1b")
}
