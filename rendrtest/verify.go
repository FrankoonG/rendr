package rendrtest

import "io"

// PRNG returns the deterministic xorshift stream of the M1a fixture for
// seed; it never fails and never ends.
func PRNG(seed uint64) io.Reader {
	panic("unimplemented: M1b")
}

// Digest returns the SHA-256 of exactly n bytes read from r, or an error if
// fewer arrived.
func Digest(r io.Reader, n int64) ([32]byte, error) {
	panic("unimplemented: M1b")
}

// Verifier checks a received stream against PRNG(seed) of exactly want
// bytes (L64): it accepts io.EOF only after exactly want matching bytes;
// every other outcome — a mismatch, a short or long stream, io.ErrClosedPipe,
// net.ErrClosed or any other error — is a failure that carries the error's
// text. It never tolerates an error type to stay green.
type Verifier struct {
	_ struct{} // unexported state is defined by the implementation
}

// NewVerifier returns a verifier for want bytes of PRNG(seed).
func NewVerifier(seed uint64, want int64) *Verifier {
	panic("unimplemented: M1b")
}

// Write consumes received bytes; it fails at the first mismatching byte
// (the error names its offset) or past want bytes.
func (v *Verifier) Write(p []byte) (int, error) {
	panic("unimplemented: M1b")
}

// Done judges the end of the stream: nil only if readErr is io.EOF and
// exactly want bytes matched.
func (v *Verifier) Done(readErr error) error {
	panic("unimplemented: M1b")
}

// ReadAll reads r to its end through the verifier and returns Done's verdict.
func (v *Verifier) ReadAll(r io.Reader) error {
	panic("unimplemented: M1b")
}
