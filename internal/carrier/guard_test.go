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
// embedder conn method, and a Read returning len+1, is contained: the
// carrier dies with transport_error (or keeps its earlier cause), the
// process survives, the carrier joins, its conn is closed exactly once,
// its reader stage returns to the Budget and nothing is abandoned.
func TestCarrierPanicsContained_L51(t *testing.T) {
	boom := func() { panic("boom") }
	cases := []struct {
		name   string
		hook   func(h *hookConn)
		kill   bool // the test kills the carrier (the misbehaviour is in the close path)
		cause  Cause
		detail string
	}{
		{"Write panics", func(h *hookConn) {
			h.onWrite = func(net.Conn, []byte) (int, error) { boom(); return 0, nil }
		}, false, CauseTransportError, "Write panicked"},
		{"Read panics", func(h *hookConn) {
			h.onRead = func(net.Conn, []byte) (int, error) { boom(); return 0, nil }
		}, false, CauseTransportError, "Read panicked"},
		{"Read returns len+1", func(h *hookConn) {
			h.onRead = func(_ net.Conn, p []byte) (int, error) { return len(p) + 1, nil }
		}, false, CauseTransportError, "invalid count"},
		{"Write calls Goexit", func(h *hookConn) {
			h.onWrite = func(net.Conn, []byte) (int, error) { runtime.Goexit(); return 0, nil }
		}, false, CauseTransportError, "Goexit"},
		{"Read calls Goexit", func(h *hookConn) {
			h.onRead = func(net.Conn, []byte) (int, error) { runtime.Goexit(); return 0, nil }
		}, false, CauseTransportError, "Goexit"},
		{"SetWriteDeadline panics", func(h *hookConn) {
			h.onSetWriteDeadline = func(net.Conn, time.Time) error { boom(); return nil }
		}, false, CauseTransportError, "SetWriteDeadline panicked"},
		{"SetDeadline and Close panic", func(h *hookConn) {
			h.onSetDeadline = func(net.Conn, time.Time) error { boom(); return nil }
			h.onClose = func(nc net.Conn) error { nc.Close(); boom(); return nil }
		}, true, CauseLocalClose, "test kill"},
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
				c.Start(&hEP{}, &hBell{}, StartOptions{})
				synctest.Wait()
				if tc.kill {
					c.Kill(CauseLocalClose, "test kill")
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

		var calls atomic.Int32
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
		if !errors.As(err, &ee) || ee.Stage != "dial" || !errors.Is(err, ErrAbandonFull) || calls.Load() != 0 {
			t.Fatalf("Establish with a full pool: %v (factory calls %d)", err, calls.Load())
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
