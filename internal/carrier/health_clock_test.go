package carrier

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestProbeSubTickRTTIsASample_L28 (wave-2 integration): a probe round trip
// shorter than the clock's resolution measures 0 — on Windows' monotonic
// clock (steps of about 0.3–0.5 ms) nearly every loopback or LAN probe
// does, and so does a zero-delay link in a bubble. sched.Aggregator rejects
// a zero RTT as untimed, so such a path never got evidence and every
// cold-start Dial of a multi-factory Peer waited the whole DialWait. The
// sample counts as 1 ns: the path becomes Fresh, and WaitFirst is released
// by it like by any other sample.
func TestProbeSubTickRTTIsASample_L28(t *testing.T) {
	t.Run("Observer", func(t *testing.T) {
		env := hEnv()
		h := NewHealth(env, []Factory{{Name: "a"}, {Name: "b"}}, prParams())
		defer h.Close()
		a, b := net.Pipe()
		t.Cleanup(func() { a.Close(); b.Close() })
		cur := newConn(env, a, env.IDs.Next(), hPassiveInst, 0, "a", true)
		h.mu.Lock()
		h.fac[0].conn = cur
		h.mu.Unlock()
		at := time.Now()
		h.obs.PingCommitted(cur, 1, at)
		h.obs.Pong(cur, 1, 0, at)
		s := h.Snapshot()
		if s.Info[0].Samples != 1 || s.Sum[0].N != 1 || !s.Sum[0].At.Equal(at) {
			t.Fatalf("a zero-RTT PONG gave no sample: info %+v, summary %+v", s.Info[0], s.Sum[0])
		}
		if ev := s.Evidence(0, at); ev.State != sched.EvFresh || ev.RTT != time.Nanosecond {
			t.Fatalf("evidence %+v, want Fresh 1ns", ev)
		}
		// A zero-RTT PONG that overtook its commit callback waits for it
		// and then counts the same way.
		at2 := at.Add(time.Second)
		h.obs.Pong(cur, 2, 0, at2)
		if s := h.Snapshot(); s.Info[0].Samples != 1 {
			t.Fatalf("a PONG ahead of its commit callback became a sample before it: %+v", s.Info[0])
		}
		h.obs.PingCommitted(cur, 2, at2)
		if s := h.Snapshot(); s.Info[0].Samples != 2 || s.Sum[0].N != 2 || s.Sum[0].Mean != time.Nanosecond {
			t.Fatalf("early zero-RTT PONG: info %+v, summary %+v", s.Info[0], s.Sum[0])
		}
	})
	t.Run("ZeroDelayLinks", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			// Each probe carrier writes through a prSockConn: like a socket,
			// its Write returns once the bytes are buffered, and they leave
			// only after the writer finished the write's commit. A Link's
			// own conn is a net.Pipe whose Write returns only once the far
			// end read the bytes; at GOMAXPROCS=1 its pump goroutines then
			// run the whole zero-delay round trip before the writer resumes,
			// so every PONG raced its PING's write commit and was no sample
			// (V6) — a property of the synchronous test conn, not of the
			// sub-tick round trip this test is about.
			sem := make(chan struct{}, 1)
			var socks []*prSockConn
			var smu sync.Mutex
			r := newPrRigDial(t, 2, nil, func(i int, l *rendrtest.Link) func(context.Context) (net.Conn, error) {
				return func(ctx context.Context) (net.Conn, error) {
					nc, err := l.Dial(ctx)
					if err != nil {
						return nil, err
					}
					sc := newPrSockConn(nc, sem)
					smu.Lock()
					socks = append(socks, sc)
					smu.Unlock()
					return sc, nil
				}
			})
			for _, l := range r.links {
				l.SetDelay(0, 0) // every round trip takes no virtual time: RTT 0
			}
			r.h.Use()
			r.h.WaitFirst(context.Background())
			// The probe carrier's cadence PINGs at 0, 2 and 4 s (the
			// establishment PONG is no sample, D26): every PONG measures 0,
			// and none races its commit, so each is a sample.
			settle := func() {
				// The test's own synctest.Wait takes sem like a pump's: two
				// concurrent Waits panic. It repeats while a socket model
				// still holds bytes (its pump waited for sem behind us), so
				// the snapshot sees every write that was due by now.
				for {
					sem <- struct{}{}
					synctest.Wait()
					<-sem
					smu.Lock()
					busy := false
					for _, sc := range socks {
						busy = busy || sc.pending()
					}
					smu.Unlock()
					if !busy {
						return
					}
				}
			}
			time.Sleep(time.Until(r.start.Add(4500 * time.Millisecond)))
			settle()
			s := r.h.Snapshot()
			for i := range s.Sum {
				if s.Info[i].Attempts != 1 || s.Info[i].Samples != 3 || s.Failed[i] {
					t.Fatalf("factory %d: zero-delay round trips gave %d samples (want 3, one per cadence PING): info %+v, failed %v", i, s.Info[i].Samples, s.Info[i], s.Failed[i])
				}
				if ev := s.Evidence(i, time.Now()); ev.State != sched.EvFresh || ev.RTT != time.Nanosecond {
					t.Fatalf("factory %d: evidence %+v, want Fresh 1ns", i, ev)
				}
			}
			smu.Lock()
			defer smu.Unlock()
			if len(socks) != 2 {
				t.Fatalf("%d probe conns dialled, want 2", len(socks))
			}
			for k, sc := range socks {
				// The PREFACE with its establishment PING, then three cadence
				// PINGs, each its own write, all crossed the socket model.
				if n := sc.writes.Load(); n < 4 {
					t.Fatalf("probe conn %d: %d writes forwarded, want at least 4", k, n)
				}
			}
		})
	})
}

// prSockConn models a socket's send buffer over a synchronous test conn:
// Write appends to the buffer and returns at once; a pump forwards the
// buffer once every other goroutine of the bubble is durably blocked
// (synctest.Wait), so bytes leave only after the writing goroutine
// finished what follows its Write — no virtual time passes. sem
// serializes the synctest.Wait calls of every pump and of the test
// goroutine (concurrent ones panic): no goroutine of the bubble may call
// synctest.Wait without holding it. It is a channel, so a goroutine
// waiting for it is durably blocked.
type prSockConn struct {
	net.Conn
	sem    chan struct{}
	kick   chan struct{} // cap 1
	done   chan struct{} // closed by Close
	once   sync.Once
	writes atomic.Int64 // buffers forwarded

	mu  sync.Mutex
	buf []byte
	err error // the forwarding write's error, or net.ErrClosed
}

func newPrSockConn(nc net.Conn, sem chan struct{}) *prSockConn {
	c := &prSockConn{Conn: nc, sem: sem, kick: make(chan struct{}, 1), done: make(chan struct{})}
	go c.pump()
	return c
}

func (c *prSockConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if c.err != nil {
		err := c.err
		c.mu.Unlock()
		return 0, err
	}
	c.buf = append(c.buf, p...)
	c.mu.Unlock()
	select {
	case c.kick <- struct{}{}:
	default:
	}
	return len(p), nil
}

// pending reports whether the model holds bytes its pump has not
// forwarded yet.
func (c *prSockConn) pending() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.buf) != 0 && c.err == nil
}

func (c *prSockConn) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		if c.err == nil {
			c.err = net.ErrClosed
		}
		c.mu.Unlock()
		close(c.done)
	})
	return c.Conn.Close()
}

func (c *prSockConn) pump() {
	for {
		select {
		case <-c.kick:
		case <-c.done:
			return
		}
		select {
		case c.sem <- struct{}{}:
		case <-c.done:
			return
		}
		synctest.Wait()
		<-c.sem
		c.mu.Lock()
		b := c.buf
		c.buf = nil
		c.mu.Unlock()
		if len(b) == 0 {
			continue
		}
		if _, err := c.Conn.Write(b); err != nil {
			c.mu.Lock()
			if c.err == nil {
				c.err = err
			}
			c.mu.Unlock()
			return
		}
		c.writes.Add(1)
	}
}
