package session

import "time"

// Read implements the application read side (L01, L02, L07). It returns
// io.EOF only when the peer's FIN is at the contiguous delivery point; a
// carrier error never surfaces. Precedence when nothing is readable: local
// Close → net.ErrClosed; EOF condition → io.EOF; session end → its error;
// read deadline → os.ErrDeadlineExceeded. The copy into p happens outside
// the session lock; the commit afterwards decides "Read won" (data
// returned) or "Close won" ((0, net.ErrClosed), data discarded).
func (s *Session) Read(p []byte) (int, error) {
	panic("unimplemented: M1b")
}

// Write copies p into the send buffer and returns (L10, L17): reserve under
// the lock, copy outside it, commit under it, in rounds of at most 256 KiB.
// Precedence before each round: local Close or CloseWrite → net.ErrClosed;
// session end → its error; write deadline → os.ErrDeadlineExceeded. A
// partial acceptance returns (k, err); after a deadline the k bytes are
// delivered (L06), after a session failure they are not guaranteed.
func (s *Session) Write(p []byte) (int, error) {
	panic("unimplemented: M1b")
}

// CloseWrite half-closes (L04): idempotent; the FIN offset is fixed at the
// reserved end at the time of the first call, so a Write that already holds
// a reservation completes below it and every later Write returns
// net.ErrClosed. Reading continues until the peer's FIN.
func (s *Session) CloseWrite() error {
	panic("unimplemented: M1b")
}

// Close returns at once (L03): CloseWrite semantics, buffered and future
// received data is discarded, every blocked call is woken with
// net.ErrClosed, and the session lingers in the background (≤ Linger) to
// deliver what was written and exchange FIN/DONE, then ends — or sends RST
// (AbortClosed if the peer keeps sending to a closed application, AbortLinger
// at expiry). Idempotent.
func (s *Session) Close() error {
	panic("unimplemented: M1b")
}

// SetReadDeadline implements net.Conn deadline semantics for reads (L06): a
// per-direction generation timer; every call wakes blocked readers to
// re-evaluate; the zero time clears; a past time fails pending and future
// reads at once. Deadlines never affect control frames, retransmissions or
// ACKs.
func (s *Session) SetReadDeadline(t time.Time) error {
	panic("unimplemented: M1b")
}

// SetWriteDeadline is SetReadDeadline for writes.
func (s *Session) SetWriteDeadline(t time.Time) error {
	panic("unimplemented: M1b")
}
