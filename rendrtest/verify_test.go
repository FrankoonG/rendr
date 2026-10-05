package rendrtest

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// step is one scripted Read result.
type step struct {
	b   []byte
	err error
}

// scripted is a reader that returns its steps in order (each step's bytes,
// possibly over several Reads, then its error).
type scripted struct{ steps []step }

func (s *scripted) Read(p []byte) (int, error) {
	if len(s.steps) == 0 {
		return 0, io.EOF
	}
	st := &s.steps[0]
	n := copy(p, st.b)
	st.b = st.b[n:]
	if len(st.b) > 0 {
		return n, nil
	}
	err := st.err
	s.steps = s.steps[1:]
	return n, err
}

func prngBytes(seed uint64, n int) []byte {
	b := make([]byte, n)
	PRNG(seed).Read(b)
	return b
}

// TestVerifierRejectsErrClosedPipe_L64: the verifier accepts io.EOF only
// after exactly the expected bytes; io.ErrClosedPipe — the error a G2
// harness once tolerated as EOF — and every other ending fails with the
// error's text, as do the far-end behaviours built on it.
func TestVerifierRejectsErrClosedPipe_L64(t *testing.T) {
	const want = 100 << 10
	data := prngBytes(9, want)
	bad := bytes.Clone(data)
	bad[77777] ^= 1
	cases := []struct {
		name  string
		steps []step
		ok    bool
		text  string // required in the error
	}{
		{"exact then EOF", []step{{data, nil}, {nil, io.EOF}}, true, ""},
		{"exact with EOF in the last read", []step{{data, io.EOF}}, true, ""},
		{"exact then ErrClosedPipe", []step{{data, io.ErrClosedPipe}}, false, io.ErrClosedPipe.Error()},
		{"half then ErrClosedPipe", []step{{data[:want/2], io.ErrClosedPipe}}, false, io.ErrClosedPipe.Error()},
		{"exact then net.ErrClosed", []step{{data, net.ErrClosed}}, false, net.ErrClosed.Error()},
		{"exact then ErrUnexpectedEOF", []step{{data, io.ErrUnexpectedEOF}}, false, io.ErrUnexpectedEOF.Error()},
		{"exact then wrapped EOF", []step{{data, fmt.Errorf("relay: %w", io.EOF)}}, false, "relay: EOF"},
		{"short then EOF", []step{{data[:want-1], io.EOF}}, false, fmt.Sprintf("EOF after %d of %d bytes", want-1, want)},
		{"long then EOF", []step{{append(bytes.Clone(data), 0), io.EOF}}, false, "more than the expected"},
		{"mismatch", []step{{bad, io.EOF}}, false, "mismatch at offset 77777"},
		{"no progress", []step{{nil, nil}}, false, io.ErrNoProgress.Error()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := &scripted{steps: c.steps}
			if c.name == "no progress" {
				r = &scripted{steps: make([]step, 1000)}
			}
			err := NewVerifier(9, want).ReadAll(r)
			switch {
			case c.ok && err != nil:
				t.Fatalf("a correct stream failed: %v", err)
			case !c.ok && err == nil:
				t.Fatal("accepted")
			case !c.ok && !strings.Contains(err.Error(), c.text):
				t.Fatalf("error %q does not carry %q", err, c.text)
			}
		})
	}
	// The error is matchable, not only printed.
	err := NewVerifier(9, want).ReadAll(&scripted{steps: []step{{data, io.ErrClosedPipe}}})
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("%v does not match io.ErrClosedPipe", err)
	}
	// Done without the end of the stream is no verdict of success.
	v := NewVerifier(9, 3)
	v.Write(prngBytes(9, 3))
	if v.Done(nil) == nil {
		t.Fatal("Done(nil) accepted a stream that did not end")
	}
	// A far-end behaviour fails the same way on an ErrClosedPipe.
	c := &scriptConn{r: &scripted{steps: []step{{data, io.ErrClosedPipe}}}}
	if err := HalfCloseCheck(want, 9, 10)(c); err == nil || !strings.Contains(err.Error(), io.ErrClosedPipe.Error()) {
		t.Fatalf("HalfCloseCheck on ErrClosedPipe: %v", err)
	}
}

// scriptConn is a net.Conn whose reads are scripted and whose writes vanish.
type scriptConn struct {
	r      io.Reader
	closed bool
}

func (c *scriptConn) Read(p []byte) (int, error)       { return c.r.Read(p) }
func (c *scriptConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *scriptConn) CloseWrite() error                { return nil }
func (c *scriptConn) Close() error                     { c.closed = true; return nil }
func (c *scriptConn) LocalAddr() net.Addr              { return nil }
func (c *scriptConn) RemoteAddr() net.Addr             { return nil }
func (c *scriptConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptConn) SetWriteDeadline(time.Time) error { return nil }

// m1aPRNG is the M1a fixture's generator, verbatim (internal/msess
// helpers_test.go prngReader): the moved suite compares digests of both.
type m1aPRNG struct{ x uint64 }

func (p *m1aPRNG) Read(b []byte) (int, error) {
	for i := range b {
		p.x ^= p.x << 13
		p.x ^= p.x >> 7
		p.x ^= p.x << 17
		b[i] = byte(p.x)
	}
	return len(b), nil
}

// TestPRNGIsTheM1aStream: PRNG(seed) is byte-identical to the M1a
// generator, in any read size; Digest hashes exactly n bytes and reports a
// short stream.
func TestPRNGIsTheM1aStream(t *testing.T) {
	for _, seed := range []uint64{0, 1, 7, 1 << 40} {
		ref := make([]byte, 1<<20)
		(&m1aPRNG{x: seed*2654435761 + 1}).Read(ref)
		got := make([]byte, 0, len(ref))
		r := PRNG(seed)
		for n := 1; len(got) < len(ref); n = n*3 + 1 {
			b := make([]byte, min(n, len(ref)-len(got)))
			r.Read(b)
			got = append(got, b...)
		}
		if !bytes.Equal(got, ref) {
			t.Fatalf("seed %d: PRNG differs from the M1a stream", seed)
		}
		d, err := Digest(PRNG(seed), int64(len(ref)))
		if err != nil || d != sha256.Sum256(ref) {
			t.Fatalf("seed %d: Digest = %x, %v", seed, d, err)
		}
	}
	if _, err := Digest(bytes.NewReader(make([]byte, 10)), 11); err == nil || !strings.Contains(err.Error(), "10 of 11") {
		t.Fatalf("Digest of a short stream: %v", err)
	}
}
