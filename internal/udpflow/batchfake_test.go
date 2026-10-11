package udpflow

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/udpsocket"
)

// fakeSock is the seam of rendr's own socket for the batched Source (M5
// WP3): a sockIO whose reads return up to len(ms) queued datagrams per
// call — as recvmmsg on Linux returns what is queued, never waiting for
// more — and whose writes are recorded per call. It is also the Source's
// net.PacketConn (Close ends a waiting read). Every wait is on channels,
// so it is durable inside a synctest bubble, and it runs on every OS.
type fakeSock struct {
	max  int
	mode atomic.Uint32 // udpsocket.Mode

	mu       sync.Mutex
	q        []fakeMsg
	rErrs    []error // returned by the next reads, before any datagram
	kick     chan struct{}
	closedCh chan struct{}
	closed   bool
	offered  []int // len(ms) of every ReadBatch call, recorded at its start
	got      []int // datagrams every successful ReadBatch returned
	out      []fakeMsg
	wsizes   []int // len(ms) of every WriteBatch call
	wbatched []bool
	wErrs    []fakeWErr // results of the next WriteBatch calls
}

type fakeMsg struct {
	b    []byte
	addr netip.AddrPort
}

// fakeWErr makes a WriteBatch call send n of its messages and return err.
type fakeWErr struct {
	n   int
	err error
}

func newFakeSock(max int) *fakeSock {
	c := &fakeSock{max: max, kick: make(chan struct{}, 1), closedCh: make(chan struct{})}
	c.mode.Store(uint32(udpsocket.ModeBatch))
	return c
}

// queue adds datagrams from from (one read returns up to its depth).
func (c *fakeSock) queue(from netip.AddrPort, ds ...[]byte) {
	c.mu.Lock()
	for _, d := range ds {
		c.q = append(c.q, fakeMsg{b: append([]byte(nil), d...), addr: from})
	}
	c.mu.Unlock()
	c.wake()
}

// failRead makes the next read return err.
func (c *fakeSock) failRead(err error) {
	c.mu.Lock()
	c.rErrs = append(c.rErrs, err)
	c.mu.Unlock()
	c.wake()
}

func (c *fakeSock) wake() {
	select {
	case c.kick <- struct{}{}:
	default:
	}
}

// reads returns copies of the per-call records.
func (c *fakeSock) reads() (offered, got []int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]int(nil), c.offered...), append([]int(nil), c.got...)
}

func (c *fakeSock) ReadBatch(b *udpsocket.Batch, ms []udpsocket.Msg) (int, error) {
	c.mu.Lock()
	c.offered = append(c.offered, len(ms))
	if len(ms) > 1 && (b == nil || b.Cap() < len(ms)) {
		c.mu.Unlock()
		panic("fakeSock: a batched read without a Batch of its depth")
	}
	c.mu.Unlock()
	for {
		c.mu.Lock()
		switch {
		case c.closed:
			c.mu.Unlock()
			return 0, net.ErrClosed
		case len(c.rErrs) > 0:
			err := c.rErrs[0]
			c.rErrs = c.rErrs[1:]
			c.mu.Unlock()
			return 0, err
		case len(c.q) > 0:
			n := min(len(ms), len(c.q))
			for i := range n {
				d, m := c.q[i], &ms[i]
				m.N = copy(m.Buf, d.b)
				m.Trunc = m.N == len(m.Buf) // udpsocket's rule: the slot is one byte longer than the limit
				m.Addr = d.addr
			}
			clear(c.q[:n])
			c.q = c.q[n:]
			c.got = append(c.got, n)
			c.mu.Unlock()
			return n, nil
		}
		c.mu.Unlock()
		select {
		case <-c.kick:
		case <-c.closedCh:
		}
	}
}

func (c *fakeSock) WriteBatch(b *udpsocket.Batch, ms []udpsocket.Msg) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wsizes = append(c.wsizes, len(ms))
	c.wbatched = append(c.wbatched, b != nil)
	n, err := len(ms), error(nil)
	if len(c.wErrs) > 0 {
		n, err = min(c.wErrs[0].n, len(ms)), c.wErrs[0].err
		c.wErrs = c.wErrs[1:]
	}
	for _, m := range ms[:n] {
		c.out = append(c.out, fakeMsg{b: append([]byte(nil), m.Buf...), addr: m.Addr})
	}
	return n, err
}

func (c *fakeSock) Mode() udpsocket.Mode { return udpsocket.Mode(c.mode.Load()) }
func (c *fakeSock) MaxBatch() int        { return c.max }

func (c *fakeSock) ReadFrom([]byte) (int, net.Addr, error) {
	panic("fakeSock: the Source reads rendr's own socket through sockIO only")
}

func (c *fakeSock) WriteTo([]byte, net.Addr) (int, error) {
	panic("fakeSock: the Source writes rendr's own socket through sockIO only")
}

func (c *fakeSock) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.closedCh)
	}
	return nil
}

func (c *fakeSock) written() []fakeMsg {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]fakeMsg(nil), c.out...)
}

func (c *fakeSock) LocalAddr() net.Addr              { return udpAddr(1, 4000) }
func (c *fakeSock) SetDeadline(time.Time) error      { return nil }
func (c *fakeSock) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeSock) SetWriteDeadline(time.Time) error { return nil }

// newSeamSource returns a Source that reads and writes io as rendr's own
// socket of maxDatagram (pc closes it).
func newSeamSource(env *carrier.Env, pc net.PacketConn, io sockIO, maxDatagram int, lim Limits) *Source {
	s := NewSource(env, pc, lim)
	s.maxDgram = maxDatagram
	s.setIO(io)
	return s
}

// fharness runs one Source over a fakeSock; admitted flows are recorded.
type fharness struct {
	t   *testing.T
	env *carrier.Env
	c   *fakeSock
	s   *Source
	mu  sync.Mutex
	fs  []*Flow
}

func newFHarness(t *testing.T, env *carrier.Env, lim Limits, c *fakeSock, maxDatagram int) *fharness {
	h := &fharness{t: t, env: env, c: c}
	h.s = newSeamSource(env, c, c, maxDatagram, lim)
	go h.s.Run(func(f *Flow) {
		h.mu.Lock()
		h.fs = append(h.fs, f)
		h.mu.Unlock()
	})
	return h
}

func (h *fharness) flows() []*Flow {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]*Flow(nil), h.fs...)
}

// shutdown aborts the source, closes every flow and waits for Done.
func (h *fharness) shutdown() {
	h.s.Abort()
	for _, f := range h.flows() {
		f.Release()
		f.Close()
	}
	<-h.s.Done()
}

// buffered is Status.BufferedBytes of the env: both accounts.
func buffered(env *carrier.Env) int64 { return env.Budget.Used() + env.Stages.Used() }
