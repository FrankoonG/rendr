package msess_test

// In-memory connections for the far-end (target) side of the fixture:
// memPipe is a buffered, bidirectional byte stream with TCP-like half-close
// (CloseWrite delivers EOF after the buffered bytes) and net.Conn deadlines;
// msgPipe is a datagram pipe that preserves message boundaries and drops
// when full, like a connected UDP socket.

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

type memAddr string

func (a memAddr) Network() string { return "mem" }
func (a memAddr) String() string  { return string(a) }

var errBrokenPipe = errors.New("mem: broken pipe")

// half is one direction of a memPipe.
type half struct {
	mu      sync.Mutex
	cond    *sync.Cond
	buf     []byte
	limit   int
	eof     bool // the writer half-closed or closed: EOF once drained
	gone    bool // the reader closed: writes fail
	rdl     time.Time
	wdl     time.Time
	rTimer  *time.Timer
	wTimer  *time.Timer
	rClosed bool // the reading end was closed locally
	wClosed bool // the writing end was closed locally
}

func newHalf(limit int) *half {
	h := &half{limit: limit}
	h.cond = sync.NewCond(&h.mu)
	return h
}

func (h *half) wake() {
	h.mu.Lock()
	h.cond.Broadcast()
	h.mu.Unlock()
}

type memConn struct {
	rx, tx        *half
	local, remote memAddr
	once          sync.Once
	onClose       func()
}

// memPipe returns the two ends of an in-memory stream connection; each
// direction buffers up to limit bytes.
func memPipe(limit int, a, b string) (*memConn, *memConn) {
	ab, ba := newHalf(limit), newHalf(limit)
	return &memConn{rx: ba, tx: ab, local: memAddr(a), remote: memAddr(b)},
		&memConn{rx: ab, tx: ba, local: memAddr(b), remote: memAddr(a)}
}

func (c *memConn) Read(p []byte) (int, error) {
	h := c.rx
	h.mu.Lock()
	defer h.mu.Unlock()
	for {
		switch {
		case h.rClosed:
			return 0, net.ErrClosed
		case len(h.buf) > 0:
			n := copy(p, h.buf)
			h.buf = h.buf[n:]
			if len(h.buf) == 0 {
				h.buf = nil
			}
			h.cond.Broadcast()
			return n, nil
		case h.eof:
			return 0, io.EOF
		case !h.rdl.IsZero() && !time.Now().Before(h.rdl):
			return 0, os.ErrDeadlineExceeded
		}
		h.cond.Wait()
	}
}

func (c *memConn) Write(p []byte) (int, error) {
	h := c.tx
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for len(p) > 0 {
		switch {
		case h.wClosed:
			return n, net.ErrClosed
		case h.eof:
			return n, errBrokenPipe // written after CloseWrite
		case h.gone:
			return n, errBrokenPipe
		case !h.wdl.IsZero() && !time.Now().Before(h.wdl):
			return n, os.ErrDeadlineExceeded
		}
		if room := h.limit - len(h.buf); room > 0 {
			k := min(room, len(p))
			h.buf = append(h.buf, p[:k]...)
			p, n = p[k:], n+k
			h.cond.Broadcast()
			continue
		}
		h.cond.Wait()
	}
	return n, nil
}

// CloseWrite ends this end's sending direction: the peer reads EOF after
// the bytes already written.
func (c *memConn) CloseWrite() error {
	h := c.tx
	h.mu.Lock()
	h.eof = true
	h.cond.Broadcast()
	h.mu.Unlock()
	return nil
}

func (c *memConn) Close() error {
	c.once.Do(func() {
		c.tx.mu.Lock()
		c.tx.eof, c.tx.wClosed = true, true
		c.tx.cond.Broadcast()
		c.tx.mu.Unlock()
		c.rx.mu.Lock()
		c.rx.gone, c.rx.rClosed, c.rx.buf = true, true, nil
		c.rx.cond.Broadcast()
		c.rx.mu.Unlock()
		if c.onClose != nil {
			c.onClose()
		}
	})
	return nil
}

func (c *memConn) LocalAddr() net.Addr  { return c.local }
func (c *memConn) RemoteAddr() net.Addr { return c.remote }

func (c *memConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *memConn) SetReadDeadline(t time.Time) error {
	h := c.rx
	h.mu.Lock()
	defer h.mu.Unlock()
	h.rdl = t
	h.rTimer = armWake(h.rTimer, t, h)
	h.cond.Broadcast()
	return nil
}

func (c *memConn) SetWriteDeadline(t time.Time) error {
	h := c.tx
	h.mu.Lock()
	defer h.mu.Unlock()
	h.wdl = t
	h.wTimer = armWake(h.wTimer, t, h)
	h.cond.Broadcast()
	return nil
}

func armWake(tm *time.Timer, t time.Time, h *half) *time.Timer {
	if tm != nil {
		tm.Stop()
	}
	if t.IsZero() {
		return nil
	}
	return time.AfterFunc(time.Until(t), h.wake)
}

// msgPipe returns the two ends of an in-memory datagram connection. Each
// direction queues up to depth datagrams; further ones are dropped.
func msgPipe(depth int, a, b string) (*msgConn, *msgConn) {
	ab, ba := make(chan []byte, depth), make(chan []byte, depth)
	return &msgConn{rx: ba, tx: ab, done: make(chan struct{}), local: memAddr(a), remote: memAddr(b)},
		&msgConn{rx: ab, tx: ba, done: make(chan struct{}), local: memAddr(b), remote: memAddr(a)}
}

type msgConn struct {
	rx, tx        chan []byte
	done          chan struct{}
	once          sync.Once
	local, remote memAddr
}

func (c *msgConn) Read(p []byte) (int, error) {
	select {
	case <-c.done:
		return 0, net.ErrClosed
	case d := <-c.rx:
		return copy(p, d), nil
	}
}

func (c *msgConn) Write(p []byte) (int, error) {
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}
	select {
	case c.tx <- append([]byte(nil), p...):
	default: // full: dropped, like UDP
	}
	return len(p), nil
}

func (c *msgConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return nil
}

func (c *msgConn) LocalAddr() net.Addr  { return c.local }
func (c *msgConn) RemoteAddr() net.Addr { return c.remote }

// Deadlines are not used on packet targets by the code under test.
func (c *msgConn) SetDeadline(time.Time) error      { return nil }
func (c *msgConn) SetReadDeadline(time.Time) error  { return nil }
func (c *msgConn) SetWriteDeadline(time.Time) error { return nil }
