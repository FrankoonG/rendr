package rendrtest

import (
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// linkConn is the conn a link hands to the dialer (side 0) or to Accept
// (side 1): a net.Pipe end plus the scripted misbehaviours of its side. It
// deliberately offers only the net.Conn methods (no CloseWrite): rendr must
// treat it like any embedder conn.
type linkConn struct {
	net.Conn
	l    *Link
	side int
	kind *atomic.Int32
	gone <-chan struct{} // the carrier was shut

	mu        sync.Mutex
	wdl       time.Time        // write deadline, for Soft blocks
	dlCh      chan struct{}    // closed and renewed when wdl changes
	never     <-chan time.Time // a deadline that never expires
	closedCh  chan struct{}
	closeOnce sync.Once
}

func newConn(l *Link, c net.Conn, side int, kind *atomic.Int32, gone <-chan struct{}) *linkConn {
	return &linkConn{Conn: c, l: l, side: side, kind: kind, gone: gone,
		dlCh: make(chan struct{}), never: make(chan time.Time), closedCh: make(chan struct{})}
}

// Read implements net.Conn; an armed OverRead reports len(p)+1.
func (c *linkConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && c.l.armedR[c.side].Load() && c.l.takeOverRead(c.side) {
		c.l.count(c.kind.Load(), cOverReads, 1)
		return len(p) + 1, err
	}
	return n, err
}

// Write implements net.Conn with the side's block mode, panics and scripts.
func (c *linkConn) Write(p []byte) (int, error) {
	l := c.l
	if !l.armedW[c.side].Load() {
		return c.Conn.Write(p)
	}
	if err := c.waitBlock(); err != nil {
		return 0, err
	}
	panicNow, r, scripted := l.takeWrite(c.side)
	switch {
	case panicNow:
		l.count(c.kind.Load(), cPanics, 1)
		panic("rendrtest: scripted Write panic")
	case scripted:
		l.count(c.kind.Load(), cScripted, 1)
		return c.scripted(p, r)
	}
	return c.Conn.Write(p)
}

// scripted performs one scripted Write.
func (c *linkConn) scripted(p []byte, r WriteResult) (int, error) {
	if r.ZeroWrite {
		return 0, nil
	}
	n := r.N
	if r.Relative {
		n += len(p)
	}
	if k := min(max(n, 0), len(p)); r.Transmit && k > 0 {
		if m, err := c.Conn.Write(p[:k]); err != nil {
			return m, err
		}
	}
	return n, r.Err
}

// waitBlock waits while the side's writes are blocked. Soft blocks end with
// the write deadline, Close or the carrier's end; Hard blocks only when
// lifted (BlockWrites, Release, Link.Close).
func (c *linkConn) waitBlock() error {
	l := c.l
	counted := false
	for {
		l.mu.Lock()
		m, ch, closed := l.sides[c.side].block, l.blockCh, l.closed
		l.mu.Unlock()
		if closed { // Close lifted the block before it shut the carriers
			return io.ErrClosedPipe
		}
		if m == BlockOff {
			return nil
		}
		if !counted {
			counted = true
			l.count(c.kind.Load(), cBlocked, 1)
		}
		if m == BlockHard {
			<-ch
			continue
		}
		c.mu.Lock()
		dl, dlCh := c.wdl, c.dlCh
		c.mu.Unlock()
		expired := c.never
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return c.timeout()
			}
			expired = time.After(d)
		}
		select {
		case <-ch:
		case <-dlCh:
		case <-c.closedCh:
			return io.ErrClosedPipe
		case <-c.gone:
			return io.ErrClosedPipe
		case <-expired:
			return c.timeout()
		}
	}
}

// timeout is the error net.Pipe returns for an expired write deadline.
func (c *linkConn) timeout() error {
	return &net.OpError{Op: "write", Net: "pipe", Source: c.LocalAddr(), Addr: c.RemoteAddr(), Err: os.ErrDeadlineExceeded}
}

// Close implements net.Conn.
func (c *linkConn) Close() error {
	c.closeOnce.Do(func() { close(c.closedCh) })
	return c.Conn.Close()
}

// SetDeadline implements net.Conn.
func (c *linkConn) SetDeadline(t time.Time) error {
	c.noteWriteDeadline(t)
	return c.Conn.SetDeadline(t)
}

// SetWriteDeadline implements net.Conn.
func (c *linkConn) SetWriteDeadline(t time.Time) error {
	c.noteWriteDeadline(t)
	return c.Conn.SetWriteDeadline(t)
}

func (c *linkConn) noteWriteDeadline(t time.Time) {
	c.mu.Lock()
	c.wdl = t
	close(c.dlCh)
	c.dlCh = make(chan struct{})
	c.mu.Unlock()
}

// takeWrite consumes the side's next write misbehaviour: a panic first,
// then a script.
func (l *Link) takeWrite(i int) (panicNow bool, r WriteResult, scripted bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := &l.sides[i]
	switch {
	case s.panics > 0:
		s.panics--
		panicNow = true
	case len(s.scripts) > 0:
		r, scripted = s.scripts[0], true
		s.scripts = s.scripts[1:]
	}
	l.rearm(i)
	return panicNow, r, scripted
}

// takeOverRead consumes one pending over-read of side i.
func (l *Link) takeOverRead(i int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.sides[i].over == 0 {
		return false
	}
	l.sides[i].over--
	l.rearm(i)
	return true
}
