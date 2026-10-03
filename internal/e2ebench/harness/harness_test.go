package harness

import (
	"net"
	"testing"
)

func pipePair() (net.Conn, net.Conn, func(), error) {
	c, s := net.Pipe()
	return c, s, func() {}, nil
}

func TestRunOverPipe(t *testing.T) {
	l, err := Run("pipe", pipePair, 3<<20+123, 3, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if l.Bench != "e2e-1" || l.GOMAXPROCS != 8 || len(l.RunsMbps) != 3 || l.MedianMbps <= 0 {
		t.Fatalf("line %+v", l)
	}
}

// corrupt flips one byte in transit, which must be reported as a CRC mismatch.
type corrupt struct{ net.Conn }

func (c corrupt) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		p[0] ^= 0xff
	}
	return n, err
}

func TestRunDetectsCorruption(t *testing.T) {
	pair := func() (net.Conn, net.Conn, func(), error) {
		c, s := net.Pipe()
		return c, corrupt{s}, func() {}, nil
	}
	if _, err := Run("bad", pair, 1<<20, 1, 0); err == nil {
		t.Fatal("corruption not detected")
	}
}

func TestMedian(t *testing.T) {
	if median([]float64{5, 1, 3}) != 3 || median([]float64{4, 1, 3, 2}) != 2.5 {
		t.Fatal("median")
	}
}

// mutating corrupts the caller's buffer in place before sending it: sender
// and receiver CRCs agree, only the independent expected CRC catches it.
type mutating struct{ net.Conn }

func (m mutating) Write(p []byte) (int, error) {
	if len(p) > 0 {
		p[0] ^= 0xff
	}
	return m.Conn.Write(p)
}

func TestRunDetectsMutatingWrite(t *testing.T) {
	pair := func() (net.Conn, net.Conn, func(), error) {
		c, s := net.Pipe()
		return mutating{c}, s, func() {}, nil
	}
	if _, err := Run("bad", pair, 1<<20, 1, 0); err == nil {
		t.Fatal("mutated sender buffer not detected")
	}
}

// failingWriter errors on the first write; the receiver must not hang.
type failingWriter struct{ net.Conn }

func (f failingWriter) Write([]byte) (int, error) { return 0, net.ErrClosed }

func TestRunSenderFailureDoesNotHang(t *testing.T) {
	pair := func() (net.Conn, net.Conn, func(), error) {
		c, s := net.Pipe()
		return failingWriter{c}, s, func() {}, nil
	}
	if _, err := Run("bad", pair, 1<<20, 1, 0); err == nil {
		t.Fatal("sender failure not reported")
	}
}
