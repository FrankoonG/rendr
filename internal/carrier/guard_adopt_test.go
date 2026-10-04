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

// GuardedDial's factory call after its caller gave up (design §0.10 Y8,
// §3.1, §6.8 step 7, L52): the call is still joined for dialGrace. A factory
// that honours its context returns within it and is never counted; a call
// still running then is stuck in embedder code: it is counted in the
// abandoned-call pool before GuardedDial returns, leaves it when the factory
// returns, and is never counted twice. Names in this file use the ga
// prefix.

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
	return f.conn(), nil
}

// conn makes and records a conn whose other end is already closed.
func (f *gaFactory) conn() *hookConn {
	a, b := net.Pipe()
	b.Close()
	h := &hookConn{Conn: a}
	f.mu.Lock()
	f.conns = append(f.conns, h)
	f.mu.Unlock()
	return h
}

func (f *gaFactory) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// closedOnce reports whether every conn the factory made was closed exactly
// once, and how many there were.
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

// gaGiveUp is one way a guarded factory call is given up (DialTimeout is
// 300 ms): dial runs the call on f, gives up at at, and reports whether a
// conn (or a carrier) came back and the error.
type gaGiveUp struct {
	name string
	at   time.Duration
	want func(err error) bool
	dial func(env *Env, f func(context.Context) (net.Conn, error)) (got bool, err error)
}

// gaEstablish runs f through Establish (an OPEN attempt), which owns the
// factory call's context: its attempt deadline is DialTimeout.
func gaEstablish(ctx context.Context, env *Env, f func(context.Context) (net.Conn, error)) (bool, error) {
	est, err := Establish(ctx, env, Factory{Name: "ga", Dial: f}, env.IDs.Next(), wire.TypeOpen, openPayload(0), nil)
	if est != nil {
		est.Conn.Kill(CauseLocalClose, "test end")
	}
	return est != nil, err
}

var gaGiveUps = []gaGiveUp{
	{"context cancelled", 100 * time.Millisecond,
		func(err error) bool { return errors.Is(err, context.Canceled) },
		func(env *Env, f func(context.Context) (net.Conn, error)) (bool, error) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			time.AfterFunc(100*time.Millisecond, cancel)
			nc, err := GuardedDial(ctx, env, f)
			return nc != nil, err
		}},
	{"DialTimeout of an attempt", 300 * time.Millisecond,
		func(err error) bool {
			var ee *EstablishError
			return errors.As(err, &ee) && ee.Stage == "dial" && ee.Cause == CauseTransportError && isTimeout(err)
		},
		func(env *Env, f func(context.Context) (net.Conn, error)) (bool, error) {
			return gaEstablish(context.Background(), env, f)
		}},
	{"attempt withdrawn", 100 * time.Millisecond,
		func(err error) bool {
			var ee *EstablishError
			return errors.As(err, &ee) && ee.Stage == "dial" && ee.Cause == CauseLocalClose && errors.Is(err, ErrWithdrawn)
		},
		func(env *Env, f func(context.Context) (net.Conn, error)) (bool, error) {
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			time.AfterFunc(100*time.Millisecond, func() { cancel(ErrWithdrawn) })
			return gaEstablish(ctx, env, f)
		}},
}

// TestGuardedDialCountsStuckCallBeforeReturning_L52 (design §0.10 Y8, §0.9
// X2): a guarded factory call that ignores its context is counted in the
// abandoned-call pool before its caller learns that the call was given up —
// the context cancelled, an attempt's DialTimeout reached, an attempt
// withdrawn — dialGrace after the give-up, so a joiner that saw the attempt
// end already sees it; it stays counted exactly once (also past
// AbandonWait and the 2·AbandonWait at which a wind-down abandons attempts
// that are still running: the attempt itself returned) until the factory
// returns, and its late conn is then closed exactly once.
func TestGuardedDialCountsStuckCallBeforeReturning_L52(t *testing.T) {
	for _, g := range gaGiveUps {
		t.Run(g.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env := hEnv()
				env.Timing.DialTimeout = 300 * time.Millisecond
				f := newGaFactory()
				t.Cleanup(f.free)
				start := time.Now()
				got, err := g.dial(env, f.dial)
				took := time.Since(start)
				// Counted before the caller learned the outcome: no settling.
				if n := env.Abandon.Len(); n != 1 || got || !g.want(err) || took != g.at+dialGrace {
					t.Fatalf("after %v: conn %v, %v, abandoned %d; want the give-up error after %v and the stuck call counted", took, got, err, n, g.at+dialGrace)
				}
				gaveUp := start.Add(g.at)
				for _, at := range []time.Duration{env.Timing.AbandonWait, 2*env.Timing.AbandonWait + time.Second} {
					time.Sleep(time.Until(gaveUp.Add(at)))
					synctest.Wait()
					if n := env.Abandon.Len(); n != 1 {
						t.Fatalf("abandoned %d at %v after the give-up, want the one stuck call", n, at)
					}
				}
				if calls := f.callCount(); calls != 1 {
					t.Fatalf("stimulus: %d factory calls, want 1", calls)
				}
				f.free() // the factory returns a conn nobody wants
				synctest.Wait()
				if n, once := f.closedOnce(); env.Abandon.Len() != 0 || n != 1 || !once || env.IDs.inUse() != 0 {
					t.Fatalf("after the late return: abandoned %d, late conns %d closed once %v, IDs in use %d", env.Abandon.Len(), n, once, env.IDs.inUse())
				}
			})
		})
	}
}

// TestGuardedDialNeverCountsHonouringCall_L52 (design §3.1, §6.8 step 7,
// L52): a factory that honours its context — returning when it ends, 1 ms
// later, or with a conn 10 ms later — is joined within dialGrace whichever
// way its call is given up: the caller gets the give-up error as soon as
// the factory returned, the call is never counted in the abandoned-call
// pool (read at the caller's return without settling, as a leak check right
// after Runtime.Close would), and a conn it returns is closed exactly once.
// A call that returns in time is never counted either.
func TestGuardedDialNeverCountsHonouringCall_L52(t *testing.T) {
	for _, g := range gaGiveUps {
		for _, h := range []struct {
			name  string
			after time.Duration // the factory returns this long after its context ended
			conn  bool          // with a conn: a success that came too late
		}{
			{"at once", 0, false},
			{"1ms later", time.Millisecond, false},
			{"a conn 10ms later", 10 * time.Millisecond, true},
		} {
			t.Run(g.name+"/"+h.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					env := hEnv()
					env.Timing.DialTimeout = 300 * time.Millisecond
					f := newGaFactory()
					var ended time.Time // when the factory saw its context end
					start := time.Now()
					got, err := g.dial(env, func(ctx context.Context) (net.Conn, error) {
						f.mu.Lock()
						f.calls++
						f.mu.Unlock()
						<-ctx.Done()
						f.mu.Lock()
						ended = time.Now()
						f.mu.Unlock()
						time.Sleep(h.after)
						if h.conn {
							return f.conn(), nil
						}
						return nil, ctx.Err()
					})
					took := time.Since(start)
					counted := env.Abandon.Len() // at the caller's return, unsettled
					time.Sleep(time.Second)      // every call returned, also after a failure
					synctest.Wait()
					if counted != 0 || got || !g.want(err) || took != g.at+h.after {
						t.Fatalf("after %v: conn %v, %v, abandoned %d; want the give-up error after %v, nothing counted", took, got, err, counted, g.at+h.after)
					}
					conns, once := f.closedOnce()
					f.mu.Lock()
					calls, endedAfter := f.calls, ended.Sub(start)
					f.mu.Unlock()
					if calls != 1 || endedAfter != g.at {
						t.Fatalf("stimulus: %d factory calls, context ended after %v (want %v)", calls, endedAfter, g.at)
					}
					if env.Abandon.Len() != 0 || !once || (conns == 1) != h.conn || env.IDs.inUse() != 0 {
						t.Fatalf("abandoned %d, conns %d closed once %v, IDs in use %d", env.Abandon.Len(), conns, once, env.IDs.inUse())
					}
				})
			})
		}
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
		})
	})
}

// TestHealthCloseSeesStuckProbeDial_L52 (design §0.10 Y8): a probe factory
// that ignores its context is still inside its call when Health.Close
// cancels the attempt; the attempt gives the call up dialGrace later, so
// Close returns then (path 0's CLOSE exchange takes 20 ms) and the stuck
// call is already counted in the abandoned-call pool when it does — a
// Runtime's Status.Abandoned reflects it at Close — and still exactly once
// 2·AbandonWait later, after the wind-down's own bound for attempts that are
// still running. It leaves the pool when the factory returns.
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
		if d := time.Since(t0); d != dialGrace {
			t.Fatalf("Close took %v, want the stuck call's grace %v", d, dialGrace)
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
