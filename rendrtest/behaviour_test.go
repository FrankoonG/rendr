package rendrtest

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// halfConn is one end of an in-memory full-duplex stream with half-close
// (two io.Pipes), standing in for a rendr Conn.
type halfConn struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func halfPipe() (*halfConn, *halfConn) {
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()
	return &halfConn{r: r1, w: w2}, &halfConn{r: r2, w: w1}
}

func (c *halfConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *halfConn) Write(p []byte) (int, error) { return c.w.Write(p) }
func (c *halfConn) CloseWrite() error           { return c.w.Close() }
func (c *halfConn) Close() error {
	c.w.Close()
	return c.r.CloseWithError(net.ErrClosed)
}
func (c *halfConn) LocalAddr() net.Addr              { return nil }
func (c *halfConn) RemoteAddr() net.Addr             { return nil }
func (c *halfConn) SetDeadline(time.Time) error      { return nil }
func (c *halfConn) SetReadDeadline(time.Time) error  { return nil }
func (c *halfConn) SetWriteDeadline(time.Time) error { return nil }

// runBehaviour starts b on the far end and returns the near end and the
// behaviour's verdict channel.
func runBehaviour(b Behaviour) (*halfConn, <-chan error) {
	near, far := halfPipe()
	verdict := make(chan error, 1)
	go func() { verdict <- b(far) }()
	return near, verdict
}

// TestBehaviours: each far-end behaviour does what it promises and reports
// nil only then.
func TestBehaviours(t *testing.T) {
	t.Run("echo", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			c, verdict := runBehaviour(Echo())
			data := prngBytes(1, 300<<10)
			go func() {
				c.Write(data)
				c.CloseWrite()
			}()
			got, err := io.ReadAll(c)
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("echoed %d of %d bytes, %v", len(got), len(data), err)
			}
			if err := <-verdict; err != nil {
				t.Fatalf("Echo: %v", err)
			}
		})
	})
	t.Run("echo-needs-closewrite", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			near, far := net.Pipe()
			verdict := make(chan error, 1)
			go func() { verdict <- Echo()(far) }()
			near.Close()
			if err := <-verdict; err == nil || !strings.Contains(err.Error(), "CloseWrite") {
				t.Fatalf("Echo on a conn without CloseWrite: %v", err)
			}
		})
	})
	t.Run("gen", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			c, verdict := runBehaviour(Gen(200<<10, 7))
			go c.Write([]byte("discarded by Gen"))
			if err := NewVerifier(7, 200<<10).ReadAll(c); err != nil {
				t.Fatalf("Gen stream: %v", err)
			}
			if err := <-verdict; err != nil {
				t.Fatalf("Gen: %v", err)
			}
			c.Close()
		})
	})
	t.Run("sink", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var n atomic.Int64
			c, verdict := runBehaviour(Sink(&n))
			c.Write(make([]byte, 12345))
			c.CloseWrite()
			if err := <-verdict; err != nil || n.Load() != 12345 {
				t.Fatalf("Sink: %v, counted %d", err, n.Load())
			}
			c.Close()
		})
	})
	t.Run("stall", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			release := make(chan struct{})
			c, verdict := runBehaviour(Stall(release))
			c.Write([]byte("hello"))
			c.CloseWrite()
			time.Sleep(time.Hour)
			select {
			case err := <-verdict:
				t.Fatalf("Stall returned %v before release", err)
			default:
			}
			close(release)
			if err := <-verdict; err != nil {
				t.Fatalf("Stall: %v", err)
			}
			if _, err := c.Read(make([]byte, 1)); err != io.EOF {
				t.Fatalf("after Stall: %v, want EOF without an answer", err)
			}
		})
	})
	t.Run("half-close-check", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			c, verdict := runBehaviour(HalfCloseCheck(64<<10, 3, 32<<10))
			go func() {
				c.Write(prngBytes(3, 64<<10))
				c.CloseWrite()
			}()
			if err := NewVerifier(4, 32<<10).ReadAll(c); err != nil {
				t.Fatalf("reply: %v", err)
			}
			if err := <-verdict; err != nil {
				t.Fatalf("HalfCloseCheck: %v", err)
			}
		})
	})
	t.Run("half-close-check-short", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			c, verdict := runBehaviour(HalfCloseCheck(64<<10, 3, 32<<10))
			c.Write(prngBytes(3, 64<<10-1))
			c.CloseWrite()
			err := <-verdict
			if err == nil || !strings.Contains(err.Error(), "EOF after 65535 of 65536 bytes") {
				t.Fatalf("HalfCloseCheck on a short stream: %v", err)
			}
			if _, err := io.ReadAll(c); err != nil && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("after a failed check: %v", err)
			}
		})
	})
}
