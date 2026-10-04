package carrier

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// GuardedDial's stuck factory call (design §0.10 Y8): when its attempt gives
// up — the context ended or DialTimeout passed — while the factory call
// still runs, the call is counted in the abandoned-call pool at once and
// leaves it when the factory returns; it is never counted twice. Names in
// this file use the ga prefix.

// gaFactory is a factory that ignores its context: it blocks until
// release is closed and then returns a fresh conn (a late success), which
// it records.
type gaFactory struct {
	release chan struct{}
	once    sync.Once
	mu      sync.Mutex
	calls   int
	conns   []*hookConn
}

func newGaFactory() *gaFactory { return &gaFactory{release: make(chan struct{})} }

// free lets every call return (idempotent; also a test cleanup, so a failed
// test leaves its bubble empty).
func (f *gaFactory) free() { f.once.Do(func() { close(f.release) }) }

func (f *gaFactory) dial(context.Context) (net.Conn, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	<-f.release
	a, b := net.Pipe()
	b.Close()
	h := &hookConn{Conn: a}
	f.mu.Lock()
	f.conns = append(f.conns, h)
	f.mu.Unlock()
	return h, nil
}

// closedOnce reports whether every late conn was closed exactly once, and
// how many there were.
func (f *gaFactory) closedOnce() (n int, once bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, h := range f.conns {
		if h.closes.Load() != 1 {
			return len(f.conns), false
		}
	}
	return len(f.conns), true
}

// TestGuardedDialAdoptsStuckCallAtOnce_L52 (design §0.10 Y8, §0.9 X2): a
// guarded factory call that ignores its context is counted in the
// abandoned-call pool in the instant its caller gives up — the context
// cancelled, DialTimeout reached, or an Establish attempt withdrawn — so a
// joiner that saw the attempt end already sees it; it stays counted exactly
// once (also past AbandonWait and the 2·AbandonWait at which a wind-down
// abandons attempts that are still running: the attempt itself returned)
// until the factory returns, and its late conn is then closed exactly once.
// A call that returns in time is never counted.
func TestGuardedDialAdoptsStuckCallAtOnce_L52(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(t *testing.T, env *Env, f *gaFactory) (err error, took time.Duration)
		took time.Duration
		want func(err error) bool
	}{
		{"context cancelled", func(t *testing.T, env *Env, f *gaFactory) (error, time.Duration) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			time.AfterFunc(100*time.Millisecond, cancel)
			start := time.Now()
			nc, err := GuardedDial(ctx, env, f.dial)
			if nc != nil {
				t.Fatalf("a conn after the caller gave up: %v", nc)
			}
			return err, time.Since(start)
		}, 100 * time.Millisecond, func(err error) bool { return errors.Is(err, context.Canceled) }},
		{"DialTimeout", func(t *testing.T, env *Env, f *gaFactory) (error, time.Duration) {
			start := time.Now()
			nc, err := GuardedDial(context.Background(), env, f.dial)
			if nc != nil {
				t.Fatalf("a conn after the caller gave up: %v", nc)
			}
			return err, time.Since(start)
		}, 300 * time.Millisecond, func(err error) bool { return isTimeout(err) }},
		{"Establish withdrawn", func(t *testing.T, env *Env, f *gaFactory) (error, time.Duration) {
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			time.AfterFunc(100*time.Millisecond, func() { cancel(ErrWithdrawn) })
			start := time.Now()
			_, err := Establish(ctx, env, Factory{Name: "stuck", Dial: f.dial}, env.IDs.Next(), wire.TypeOpen, openPayload(0), nil)
			var ee *EstablishError
			if !errors.As(err, &ee) || ee.Stage != "dial" || ee.Cause != CauseLocalClose || env.IDs.inUse() != 0 {
				t.Fatalf("Establish: %v (IDs in use %d)", err, env.IDs.inUse())
			}
			return err, time.Since(start)
		}, 100 * time.Millisecond, func(err error) bool { return errors.Is(err, ErrWithdrawn) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env := hEnv()
				env.Timing.DialTimeout = 300 * time.Millisecond
				f := newGaFactory()
				t.Cleanup(f.free)
				err, took := tc.run(t, env, f)
				gaveUp := time.Now()
				// Counted before the caller learned the outcome: no wait.
				if n := env.Abandon.Len(); n != 1 || !tc.want(err) || took != tc.took {
					t.Fatalf("after %v: %v, abandoned %d; want the stuck call counted at once after %v", took, err, n, tc.took)
				}
				for _, at := range []time.Duration{env.Timing.AbandonWait, 2*env.Timing.AbandonWait + time.Second} {
					time.Sleep(time.Until(gaveUp.Add(at)))
					synctest.Wait()
					if n := env.Abandon.Len(); n != 1 {
						t.Fatalf("abandoned %d at %v after the give-up, want the one stuck call", n, at)
					}
				}
				f.mu.Lock()
				calls := f.calls
				f.mu.Unlock()
				if calls != 1 {
					t.Fatalf("stimulus: %d factory calls, want 1", calls)
				}
				f.free() // the factory returns a conn nobody wants
				synctest.Wait()
				if n, once := f.closedOnce(); env.Abandon.Len() != 0 || n != 1 || !once {
					t.Fatalf("after the late return: abandoned %d, late conns %d closed once %v", env.Abandon.Len(), n, once)
				}
			})
		})
	}
	t.Run("in time", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			env := hEnv()
			env.Timing.DialTimeout = 300 * time.Millisecond
			for _, d := range []time.Duration{0, 299 * time.Millisecond} {
				nc, err := GuardedDial(context.Background(), env, func(context.Context) (net.Conn, error) {
					time.Sleep(d)
					a, b := net.Pipe()
					b.Close()
					return a, nil
				})
				if err != nil || nc == nil || env.Abandon.Len() != 0 {
					t.Fatalf("a call returning after %v: %v, %v, abandoned %d", d, nc, err, env.Abandon.Len())
				}
				nc.Close()
			}
			// A call that honours its context returns with it: counted at
			// most for that instant, never left behind.
			ctx, cancel := context.WithCancel(context.Background())
			time.AfterFunc(100*time.Millisecond, cancel)
			nc, err := GuardedDial(ctx, env, func(ctx context.Context) (net.Conn, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			})
			synctest.Wait()
			if nc != nil || !errors.Is(err, context.Canceled) || env.Abandon.Len() != 0 {
				t.Fatalf("a call that honours its context: %v, %v, abandoned %d", nc, err, env.Abandon.Len())
			}
		})
	})
}

// TestHealthCloseSeesStuckProbeDial_L52 (design §0.10 Y8): a probe factory
// that ignores its context is still inside its call when Health.Close
// cancels the attempt; Close returns at once (the attempt returned) and the
// stuck call is already counted in the abandoned-call pool when it does —
// a Runtime's Status.Abandoned reflects it at Close — and still exactly
// once 2·AbandonWait later, after the wind-down's own bound for attempts
// that are still running. It leaves the pool when the factory returns.
func TestHealthCloseSeesStuckProbeDial_L52(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newPrRig(t, 2, nil)
		r.links[1].SetDial(rendrtest.DialHangForever)
		r.h.Use()
		r.until(time.Second)
		if st := r.links[1].Stats(); st.Dials != 1 || st.DialFailures != 0 || r.h.Snapshot().Info[1].ProbeCarrier != 0 {
			t.Fatalf("stimulus: path 1 %+v, info %+v", st, r.h.Snapshot().Info[1])
		}
		if n := r.env.Abandon.Len(); n != 0 {
			t.Fatalf("abandoned %d while the attempt still waits for the call", n)
		}
		t0 := time.Now()
		r.h.Close()
		if d := time.Since(t0); d > 40*time.Millisecond {
			t.Fatalf("Close took %v (one 20 ms CLOSE exchange on path 0)", d)
		}
		if n := r.env.Abandon.Len(); n != 1 {
			t.Fatalf("abandoned %d when Close returned, want the stuck factory call", n)
		}
		time.Sleep(2*r.env.Timing.AbandonWait + time.Second)
		synctest.Wait()
		if n := r.env.Abandon.Len(); n != 1 {
			t.Fatalf("abandoned %d after 2·AbandonWait, want the one stuck call (never twice)", n)
		}
		r.links[1].Release()
		synctest.Wait()
		if n := r.env.Abandon.Len(); n != 0 {
			t.Fatalf("abandoned %d after the factory returned", n)
		}
	})
}
