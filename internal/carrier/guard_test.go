package carrier

import (
	"context"
	"errors"
	"io"
	"math"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestCarrierIDWrapSkipsInUse_L14: CarrierIDs are never 0 and never an ID
// still in use: from a preset near 2^32 the counter wraps past 0, and when
// it comes around to IDs that are still in use it skips them. Concurrent
// allocations are distinct.
func TestCarrierIDWrapSkipsInUse_L14(t *testing.T) {
	a := NewIDAllocator(math.MaxUint32 - 1)
	got := []uint32{a.Next(), a.Next(), a.Next()}
	if got[0] != math.MaxUint32-1 || got[1] != math.MaxUint32 || got[2] != 1 {
		t.Fatalf("IDs across the wrap: %v", got)
	}
	a.Release(math.MaxUint32) // free again; max−1 and 1 stay in use
	a.mu.Lock()
	a.next = math.MaxUint32 - 1 // the counter came around (2^32 allocations later)
	a.mu.Unlock()
	if id := a.Next(); id != math.MaxUint32 {
		t.Fatalf("got %d: an in-use ID (max−1) was not skipped", id)
	}
	if id := a.Next(); id != 2 {
		t.Fatalf("got %d: 0 and the in-use ID 1 must be skipped", id)
	}
	if n := a.inUse(); n != 4 {
		t.Fatalf("%d IDs in use, want 4", n)
	}
	for _, id := range []uint32{math.MaxUint32 - 1, math.MaxUint32, 1, 2} {
		a.Release(id)
	}
	if n := a.inUse(); n != 0 {
		t.Fatalf("%d IDs in use after release", n)
	}
	if id := NewIDAllocator(0).Next(); id != 1 {
		t.Fatalf("default first ID %d", id)
	}

	var mu sync.Mutex
	seen := map[uint32]bool{}
	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				id := a.Next()
				mu.Lock()
				if id == 0 || seen[id] {
					t.Errorf("duplicate or zero ID %d", id)
				}
				seen[id] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
}

// TestCarrierPanicsContained_L51: a panic or runtime.Goexit inside any
// embedder conn method — the reader's stage and big-DATA reads, the
// writer's batch write, and the close paths (the closer's SetDeadline, the
// verdict write of WriteAndClose) — and a Read returning len+1, is
// contained: the carrier dies with transport_error (or keeps its earlier
// cause), the process survives, the carrier joins, its conn is closed
// exactly once, every buffer (the reader stage, a big-DATA payload being
// read, the coalescing scratch) returns to the Budget and nothing is
// abandoned.
func TestCarrierPanicsContained_L51(t *testing.T) {
	boom := func() { panic("boom") }
	kill := func(c *Conn, _ *wirePeer) { c.Kill(CauseLocalClose, "test kill") }
	cases := []struct {
		name      string
		hook      func(h *hookConn)
		unstarted bool                       // the carrier is never started (the admission's WriteAndClose path)
		run       func(c *Conn, p *wirePeer) // the stimulus (nil: the started carrier's first PING only)
		cause     Cause
		detail    string
	}{
		{"Write panics", func(h *hookConn) {
			h.onWrite = func(net.Conn, []byte) (int, error) { boom(); return 0, nil }
		}, false, nil, CauseTransportError, "Write panicked"},
		{"Read panics", func(h *hookConn) {
			h.onRead = func(net.Conn, []byte) (int, error) { boom(); return 0, nil }
		}, false, nil, CauseTransportError, "Read panicked"},
		{"Read returns len+1", func(h *hookConn) {
			h.onRead = func(_ net.Conn, p []byte) (int, error) { return len(p) + 1, nil }
		}, false, nil, CauseTransportError, "invalid count"},
		{"Write calls Goexit", func(h *hookConn) {
			h.onWrite = func(net.Conn, []byte) (int, error) { runtime.Goexit(); return 0, nil }
		}, false, nil, CauseTransportError, "Goexit"},
		{"Read calls Goexit", func(h *hookConn) {
			h.onRead = func(net.Conn, []byte) (int, error) { runtime.Goexit(); return 0, nil }
		}, false, nil, CauseTransportError, "Goexit"},
		{"Read calls Goexit inside a big DATA payload", func(h *hookConn) {
			h.onRead = func(nc net.Conn, p []byte) (int, error) {
				if len(p) > classSize(0) { // the Read into the payload's own Buf (stage reads are smaller)
					runtime.Goexit()
				}
				return nc.Read(p)
			}
		}, false, func(_ *Conn, p *wirePeer) {
			go p.sendFrames(hFrame{t: wire.TypeData, handle: wire.SessionHandle, payload: dataPayload(0, 100<<10)})
		}, CauseTransportError, "Goexit"},
		{"SetWriteDeadline panics", func(h *hookConn) {
			h.onSetWriteDeadline = func(net.Conn, time.Time) error { boom(); return nil }
		}, false, nil, CauseTransportError, "SetWriteDeadline panicked"},
		{"SetDeadline and Close panic", func(h *hookConn) {
			h.onSetDeadline = func(net.Conn, time.Time) error { boom(); return nil }
			h.onClose = func(nc net.Conn) error { nc.Close(); boom(); return nil }
		}, false, kill, CauseLocalClose, "test kill"},
		{"SetDeadline calls Goexit while closing", func(h *hookConn) {
			h.onSetDeadline = func(net.Conn, time.Time) error { runtime.Goexit(); return nil }
		}, false, kill, CauseLocalClose, "test kill"},
		{"Write calls Goexit in WriteAndClose", func(h *hookConn) {
			h.onWrite = func(net.Conn, []byte) (int, error) { runtime.Goexit(); return 0, nil }
		}, true, func(c *Conn, _ *wirePeer) {
			c.WriteAndClose(wire.TypeClose, 0, 0, []byte{byte(wire.CloseCapacity)}, time.Now().Add(time.Second))
		}, CauseLocalClose, "closed after"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env := hEnv()
				var hc *hookConn
				c, p := hPair(t, env, func(nc net.Conn) net.Conn {
					hc = &hookConn{Conn: nc}
					tc.hook(hc)
					return hc
				})
				if !tc.unstarted {
					c.Start(&hEP{}, &hBell{}, StartOptions{})
					synctest.Wait()
				}
				if tc.run != nil {
					tc.run(c, p)
				}
				hWait(t, c)
				p.close()
				dead, cause, detail, _ := c.Death()
				if !dead || cause != tc.cause || !strings.Contains(detail, tc.detail) {
					t.Fatalf("death %v %v %q, want %v containing %q", dead, cause, detail, tc.cause, tc.detail)
				}
				if n := hc.closes.Load(); n != 1 {
					t.Fatalf("conn closed %d times", n)
				}
				if env.Budget.Used() != 0 || env.Abandon.Len() != 0 {
					t.Fatalf("budget %d, abandoned %d", env.Budget.Used(), env.Abandon.Len())
				}
			})
		})
	}
}

// TestAbandonPoolBounds_L52: a carrier whose Read ignores deadlines and
// Close still joins (Done) AbandonWait after it was killed, with the stuck
// reader counted in the abandoned-call pool; while the pool is full, new
// carriers fail fast (GuardedDial and Establish with ErrAbandonFull, the
// factory not even called); when the stuck calls return, the pool empties
// and dialing works again. A factory that ignores its context is abandoned
// the same way and its late conn is closed exactly once.
func TestAbandonPoolBounds_L52(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		env.Abandon = NewAbandonPool(2)
		release := make(chan struct{})
		var stuck []*Conn
		for range 2 {
			c, p := hPair(t, env, func(nc net.Conn) net.Conn {
				return &hookConn{Conn: nc, onRead: func(net.Conn, []byte) (int, error) {
					<-release // ignores deadlines and Close
					return 0, io.EOF
				}}
			})
			c.Start(&hEP{}, &hBell{}, StartOptions{})
			stuck = append(stuck, c)
			_ = p
		}
		synctest.Wait()
		start := time.Now()
		for _, c := range stuck {
			c.Kill(CauseLocalClose, "shutdown")
		}
		for _, c := range stuck {
			hWait(t, c)
		}
		if d := time.Since(start); d != env.Timing.AbandonWait {
			t.Fatalf("joined after %v, want AbandonWait %v", d, env.Timing.AbandonWait)
		}
		if n := env.Abandon.Len(); n != 2 || !env.Abandon.Full() {
			t.Fatalf("abandoned %d (full %v), want the two stuck readers", n, env.Abandon.Full())
		}

		var calls, starts atomic.Int32
		env.Hooks = &testhooks.Hooks{DialStart: func(int) { starts.Add(1) }}
		factory := func(context.Context) (net.Conn, error) {
			calls.Add(1)
			a, b := net.Pipe()
			b.Close()
			return a, nil
		}
		if _, err := GuardedDial(context.Background(), env, factory); !errors.Is(err, ErrAbandonFull) {
			t.Fatalf("GuardedDial with a full pool: %v", err)
		}
		_, err := Establish(context.Background(), env, Factory{Name: "f", Dial: factory}, env.IDs.Next(), wire.TypePing, nil, nil)
		var ee *EstablishError
		if !errors.As(err, &ee) || ee.Stage != "dial" || !errors.Is(err, ErrAbandonFull) || calls.Load() != 0 || starts.Load() != 0 {
			t.Fatalf("Establish with a full pool: %v (factory calls %d, DialStart %d)", err, calls.Load(), starts.Load())
		}

		close(release)
		synctest.Wait()
		if n := env.Abandon.Len(); n != 0 {
			t.Fatalf("%d still abandoned after the stuck calls returned", n)
		}
		nc, err := GuardedDial(context.Background(), env, factory)
		if err != nil || calls.Load() != 1 {
			t.Fatalf("GuardedDial after the pool emptied: %v", err)
		}
		nc.Close()

		// A factory that ignores its context.
		late := make(chan struct{})
		var lateConn *hookConn
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(100*time.Millisecond, cancel)
		start = time.Now()
		_, err = GuardedDial(ctx, env, func(context.Context) (net.Conn, error) {
			<-late
			a, b := net.Pipe()
			b.Close()
			lateConn = &hookConn{Conn: a}
			return lateConn, nil
		})
		if !errors.Is(err, context.Canceled) || time.Since(start) != 100*time.Millisecond {
			t.Fatalf("ignoring factory: %v after %v", err, time.Since(start))
		}
		time.Sleep(env.Timing.AbandonWait)
		synctest.Wait()
		if n := env.Abandon.Len(); n != 1 {
			t.Fatalf("abandoned %d, want the stuck factory call", n)
		}
		close(late)
		synctest.Wait()
		if env.Abandon.Len() != 0 || lateConn == nil || lateConn.closes.Load() != 1 {
			t.Fatalf("after the late return: abandoned %d, late conn closes %v", env.Abandon.Len(), lateConn)
		}
	})
}

// TestGuardedDialMisbehaviour_L51: every way a factory can misbehave ends
// in a typed result, bounded in time, with any conn it produced closed
// exactly once.
func TestGuardedDialMisbehaviour_L51(t *testing.T) {
	errDial := errors.New("dial refused")
	cases := []struct {
		name    string
		f       func(ctx context.Context, mk func() net.Conn) (net.Conn, error)
		ctx     time.Duration // cancel after this (0: never)
		want    error
		took    time.Duration
		closed  int32
		timeout bool
	}{
		{"nil nil", func(context.Context, func() net.Conn) (net.Conn, error) { return nil, nil }, 0, ErrNilConn, 0, 0, false},
		{"panic", func(context.Context, func() net.Conn) (net.Conn, error) { panic("factory") }, 0, ErrFactoryPanic, 0, 0, false},
		{"Goexit", func(context.Context, func() net.Conn) (net.Conn, error) { runtime.Goexit(); return nil, nil }, 0, ErrFactoryPanic, 0, 0, false},
		{"conn and error", func(_ context.Context, mk func() net.Conn) (net.Conn, error) { return mk(), errDial }, 0, errDial, 0, 1, false},
		{"ignores ctx until DialTimeout", func(_ context.Context, mk func() net.Conn) (net.Conn, error) {
			time.Sleep(time.Hour)
			return mk(), nil
		}, 0, nil, 10 * time.Second, 1, true},
		{"late success after cancel", func(_ context.Context, mk func() net.Conn) (net.Conn, error) {
			time.Sleep(3 * time.Second)
			return mk(), nil
		}, 500 * time.Millisecond, context.Canceled, 500 * time.Millisecond, 1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env := hEnv()
				var made []*hookConn
				var mu sync.Mutex
				mk := func() net.Conn {
					a, b := net.Pipe()
					b.Close()
					h := &hookConn{Conn: a}
					mu.Lock()
					made = append(made, h)
					mu.Unlock()
					return h
				}
				ctx := context.Background()
				if tc.ctx > 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(ctx)
					time.AfterFunc(tc.ctx, cancel)
				}
				start := time.Now()
				nc, err := GuardedDial(ctx, env, func(ctx context.Context) (net.Conn, error) { return tc.f(ctx, mk) })
				took := time.Since(start)
				if nc != nil {
					t.Fatalf("got a conn: %v", nc)
				}
				var ne net.Error
				switch {
				case tc.timeout && !(errors.As(err, &ne) && ne.Timeout()):
					t.Fatalf("err %v, want a timeout", err)
				case !tc.timeout && !errors.Is(err, tc.want):
					t.Fatalf("err %v, want %v", err, tc.want)
				}
				if took != tc.took {
					t.Fatalf("returned after %v, want %v", took, tc.took)
				}
				time.Sleep(2 * time.Hour) // every late call returns
				synctest.Wait()
				mu.Lock()
				defer mu.Unlock()
				if int32(len(made)) != tc.closed {
					t.Fatalf("%d conns made, want %d", len(made), tc.closed)
				}
				for _, h := range made {
					if h.closes.Load() != 1 {
						t.Fatalf("a factory conn was closed %d times", h.closes.Load())
					}
				}
				if env.Abandon.Len() != 0 {
					t.Fatalf("abandoned %d after every call returned", env.Abandon.Len())
				}
			})
		})
	}
}

// TestAbandonedWriteKeepsItsBuffers_L52 (§4.1 abandoned-call rule): a
// carrier killed while its writer is stuck in an embedder Write that
// ignores deadlines and Close joins AbandonWait later with the writer
// counted as abandoned, and the send chunk the stuck write may still read
// stays referenced (never recycled under it) until that Write returns; so
// does the coalescing scratch the Write was handed, whose class capacity
// stays charged to the Budget (it is visible in BufferedBytes) until then.
// Then the references go, the Budget returns to zero and the pool empties.
func TestAbandonedWriteKeepsItsBuffers_L52(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		release := make(chan struct{})
		var calls atomic.Int32
		c, p := hPair(t, env, func(nc net.Conn) net.Conn {
			return &hookConn{Conn: nc, onWrite: func(nc net.Conn, b []byte) (int, error) {
				if calls.Add(1) == 2 {
					<-release // ignores deadlines and Close
					return 0, net.ErrClosed
				}
				return nc.Write(b)
			}}
		})
		src := newSource(env, 16<<10, false)
		c.Start(src, &hBell{}, StartOptions{})
		synctest.Wait() // the first PING written
		src.offer(32 << 10)
		c.Wake()
		synctest.Wait() // the second write (two DATA frames on the chunk) is stuck
		if refs := src.chunk.refs.Load(); refs != 3 {
			t.Fatalf("chunk refs %d during the write, want the source's and two DATA frames'", refs)
		}
		stage := int64(classSize(0))
		scratch := int64(classSize(classFor(2 * (16<<10 + wire.DataHeadLen + wire.TrailerLen))))
		if got := env.Budget.Used(); got != stage+scratch {
			t.Fatalf("budget %d during the write, want the reader stage %d + the batch scratch %d", got, stage, scratch)
		}
		c.Kill(CauseLocalClose, "shutdown")
		hWait(t, c)
		if env.Abandon.Len() != 1 || src.chunk.refs.Load() != 3 || env.Budget.Used() != scratch {
			t.Fatalf("after Done: abandoned %d, chunk refs %d, budget %d (want the scratch %d)", env.Abandon.Len(), src.chunk.refs.Load(), env.Budget.Used(), scratch)
		}
		close(release)
		synctest.Wait()
		if env.Abandon.Len() != 0 || src.chunk.refs.Load() != 1 || env.Budget.Used() != 0 {
			t.Fatalf("after the stuck Write returned: abandoned %d, chunk refs %d, budget %d", env.Abandon.Len(), src.chunk.refs.Load(), env.Budget.Used())
		}
		p.close()
		src.chunk.Release()
	})
}

// TestHandshakeGoexitContained_L51: a conn call that runs runtime.Goexit on
// the handshake's own goroutine — Establish waiting for the PREFACE_ACK,
// ReadHello reading the PREFACE — still closes the conn exactly once, and
// Establish still releases its carrier ID; nothing is abandoned.
func TestHandshakeGoexitContained_L51(t *testing.T) {
	goexitRead := func(net.Conn, []byte) (int, error) { runtime.Goexit(); return 0, nil }
	for _, side := range []string{"Establish", "ReadHello"} {
		t.Run(side, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env := hEnv()
				a, b := net.Pipe()
				hc := &hookConn{Conn: a, onRead: goexitRead}
				go io.Copy(io.Discard, b) // the other end takes whatever is written; EOF once hc is closed
				done := make(chan struct{})
				returned := false
				go func() {
					defer close(done)
					if side == "Establish" {
						f := Factory{Name: "g", Dial: func(context.Context) (net.Conn, error) { return hc, nil }}
						_, _ = Establish(context.Background(), env, f, env.IDs.Next(), wire.TypeOpen, openPayload(0), nil)
					} else {
						_, _ = ReadHello(env, hc, time.Now().Add(time.Second), 4096, nil)
					}
					returned = true
				}()
				<-done
				synctest.Wait() // the guarded close ran
				b.Close()
				if returned {
					t.Fatal("the stimulus did not happen: the handshake returned")
				}
				if hc.reads.Load() != 1 || hc.closes.Load() != 1 {
					t.Fatalf("reads %d (want the Goexit one), conn closed %d times", hc.reads.Load(), hc.closes.Load())
				}
				if env.IDs.inUse() != 0 || env.Abandon.Len() != 0 {
					t.Fatalf("IDs in use %d, abandoned %d", env.IDs.inUse(), env.Abandon.Len())
				}
			})
		})
	}
}

// TestDoneSettlesAccountsFirst_L52: what a joiner reads after Done is final
// when Done closes — the reader stuck in an embedder Read is already
// counted in the abandoned-call pool (Status.Abandoned, the Full fail-fast
// gate) and the CarrierID is already released. Holding the ID allocator's
// lock (white-box, real time: a mutex is no durable block for synctest)
// parks the carrier exactly at its release: by then the stuck reader must
// be counted and Done must still be open.
func TestDoneSettlesAccountsFirst_L52(t *testing.T) {
	env := hEnv()
	env.Timing.AbandonWait = 20 * time.Millisecond
	a, b := net.Pipe()
	go io.Copy(io.Discard, b) // ends when the carrier closes its end
	release := make(chan struct{})
	hc := &hookConn{Conn: a, onRead: func(net.Conn, []byte) (int, error) {
		<-release // ignores deadlines and Close
		return 0, io.EOF
	}}
	id := env.IDs.Next()
	c := newConn(env, hc, id, hPeerInst, 0, "f0", true) // a dialer carrier: Done releases its ID
	c.Start(&hEP{}, &hBell{}, StartOptions{})
	var once sync.Once
	unstick := func() { once.Do(func() { close(release) }) }
	env.IDs.mu.Lock()
	locked := true
	defer func() { // a failed assertion still unparks the carrier and its reader
		if locked {
			env.IDs.mu.Unlock()
		}
		unstick()
	}()
	c.Kill(CauseLocalClose, "shutdown")
	for start := time.Now(); env.Abandon.Len() != 1; time.Sleep(time.Millisecond) {
		if time.Since(start) > 5*time.Second {
			t.Fatalf("the stuck reader was not counted before the ID release (abandoned %d)", env.Abandon.Len())
		}
	}
	select {
	case <-c.Done():
		t.Fatal("Done closed before the CarrierID was released")
	case <-time.After(20 * time.Millisecond):
	}
	env.IDs.mu.Unlock()
	locked = false
	select {
	case <-c.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Done did not close after the ID allocator was released")
	}
	if env.IDs.inUse() != 0 || env.Abandon.Len() != 1 {
		t.Fatalf("after Done: IDs in use %d, abandoned %d", env.IDs.inUse(), env.Abandon.Len())
	}
	unstick()
	for start := time.Now(); env.Abandon.Len() != 0; time.Sleep(time.Millisecond) {
		if time.Since(start) > 5*time.Second {
			t.Fatal("the reader did not leave the pool after its Read returned")
		}
	}
}
