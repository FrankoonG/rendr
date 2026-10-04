package rendrtest

import (
	"crypto/sha256"
	"fmt"
	"io"
)

// prng is the xorshift64 byte stream of the M1a fixture.
type prng struct{ x uint64 }

// PRNG returns the deterministic xorshift stream of the M1a fixture for
// seed; it never fails and never ends.
func PRNG(seed uint64) io.Reader { return &prng{x: seed*2654435761 + 1} }

func (p *prng) Read(b []byte) (int, error) {
	x := p.x
	for i := range b {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		b[i] = byte(x)
	}
	p.x = x
	return len(b), nil
}

// Digest returns the SHA-256 of exactly n bytes read from r, or an error if
// fewer arrived.
func Digest(r io.Reader, n int64) ([32]byte, error) {
	h := sha256.New()
	k, err := io.CopyN(h, r, n)
	if k != n {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return [32]byte{}, fmt.Errorf("rendrtest: Digest: %d of %d bytes: %w", k, n, err)
	}
	var d [32]byte
	h.Sum(d[:0])
	return d, nil
}

// Verifier checks a received stream against PRNG(seed) of exactly want
// bytes (L64): it accepts io.EOF only after exactly want matching bytes;
// every other outcome — a mismatch, a short or long stream, io.ErrClosedPipe,
// net.ErrClosed or any other error — is a failure that carries the error's
// text. It never tolerates an error type to stay green.
type Verifier struct {
	gen  io.Reader
	want int64
	got  int64 // bytes matched so far
	err  error // first failure (sticky)
	exp  []byte
}

// NewVerifier returns a verifier for want bytes of PRNG(seed).
func NewVerifier(seed uint64, want int64) *Verifier {
	return &Verifier{gen: PRNG(seed), want: want}
}

// Write consumes received bytes; it fails at the first mismatching byte
// (the error names its offset) or past want bytes.
func (v *Verifier) Write(p []byte) (int, error) {
	if v.err != nil {
		return 0, v.err
	}
	fit := int(min(int64(len(p)), v.want-v.got))
	for done := 0; done < fit; {
		n := min(fit-done, 64<<10)
		if cap(v.exp) < n {
			v.exp = make([]byte, 64<<10)
		}
		exp := v.exp[:n]
		v.gen.Read(exp)
		for i, b := range p[done : done+n] {
			if b != exp[i] {
				v.got += int64(i)
				v.err = fmt.Errorf("rendrtest: byte mismatch at offset %d of %d: got %#02x, want %#02x", v.got, v.want, b, exp[i])
				return done + i, v.err
			}
		}
		done += n
		v.got += int64(n)
	}
	if fit < len(p) {
		v.err = fmt.Errorf("rendrtest: received more than the expected %d bytes", v.want)
		return fit, v.err
	}
	return len(p), nil
}

// Done judges the end of the stream: nil only if readErr is io.EOF and
// exactly want bytes matched.
func (v *Verifier) Done(readErr error) error {
	switch {
	case v.err != nil && readErr != nil && readErr != io.EOF:
		return fmt.Errorf("%w (the stream then failed: %v)", v.err, readErr)
	case v.err != nil:
		return v.err
	case readErr == nil:
		return fmt.Errorf("rendrtest: stream judged before its end after %d of %d bytes", v.got, v.want)
	case readErr != io.EOF:
		return fmt.Errorf("rendrtest: stream failed after %d of %d bytes: %w", v.got, v.want, readErr)
	case v.got != v.want:
		return fmt.Errorf("rendrtest: EOF after %d of %d bytes", v.got, v.want)
	}
	return nil
}

// ReadAll reads r to its end through the verifier and returns Done's verdict.
func (v *Verifier) ReadAll(r io.Reader) error {
	buf := make([]byte, 64<<10)
	for idle := 0; ; {
		n, err := r.Read(buf)
		if n < 0 || n > len(buf) {
			return v.Done(fmt.Errorf("invalid read count %d of %d", n, len(buf)))
		}
		if n > 0 {
			idle = 0
			if _, werr := v.Write(buf[:n]); werr != nil {
				return v.Done(err)
			}
		} else if err == nil {
			if idle++; idle >= 100 {
				return v.Done(io.ErrNoProgress)
			}
		}
		if err != nil {
			return v.Done(err)
		}
	}
}
