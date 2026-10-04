package rendr

import (
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// fakeListener is a scripted net.Listener source (L50). Accept returns a
// scripted result if one is queued, else a conn pushed into conns, else it
// blocks until Close — or, with hang, until release regardless of Close.
type fakeListener struct {
	conns   chan net.Conn
	script  chan acceptResult // returned before blocking
	hang    bool
	release chan struct{}
	closed  chan struct{}
	once    sync.Once
	accepts atomic.Int32
	closes  atomic.Int32
	mu      sync.Mutex
	calls   []time.Time // when Accept was called
	panics  bool
	repeat  *acceptResult // returned on every call (never blocks)
}

type acceptResult struct {
	c   net.Conn
	err error
}

func newFakeListener() *fakeListener {
	return &fakeListener{
		conns:   make(chan net.Conn, 16),
		script:  make(chan acceptResult, 16),
		release: make(chan struct{}),
		closed:  make(chan struct{}),
	}
}

func (l *fakeListener) Accept() (net.Conn, error) {
	l.accepts.Add(1)
	l.mu.Lock()
	l.calls = append(l.calls, time.Now())
	l.mu.Unlock()
	if l.panics {
		panic("fakeListener: Accept panics")
	}
	if l.repeat != nil {
		return l.repeat.c, l.repeat.err
	}
	select {
	case r := <-l.script:
		return r.c, r.err
	default:
	}
	if l.hang {
		<-l.release
		return nil, errors.New("fakeListener: released")
	}
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *fakeListener) Close() error {
	l.closes.Add(1)
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *fakeListener) Addr() net.Addr { return fakeAddr{} }

func (l *fakeListener) callTimes() []time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]time.Time(nil), l.calls...)
}

type fakeAddr struct{}

func (fakeAddr) Network() string { return "fake" }
func (fakeAddr) String() string  { return "fake" }

// emfile is the accept error of an exhausted fd table (a temporary error).
func emfile() error {
	return &net.OpError{Op: "accept", Net: "tcp", Err: os.NewSyscallError("accept", syscall.EMFILE)}
}

// pushProbe delivers a scripted probe carrier through src and runs it up
// to its first PONG.
func pushProbe(t testing.TB, rt *Runtime, src *fakeListener, inst [16]byte, id uint32) *wpDialer {
	t.Helper()
	a, b := net.Pipe()
	src.conns <- a
	d := &wpDialer{t: t, nc: b, inst: inst, id: id, txFseq: wire.FirstFseq, rxFseq: wire.FirstFseq}
	d.hello(rt)
	d.send(wire.TypePing, 0, wpPing(wire.Ping{ID: id, Nonce: uint64(id)}))
	d.expect(wire.TypePong)
	return d
}

// TestListenerClosedRefusesWork_L50: after Close, Handle returns
// net.ErrClosed and closes the conn exactly once, Accept returns
// net.ErrClosed, Close stays idempotent, and the Runtime forgets the
// Listener; Handle(nil) is an error that touches nothing.
func TestListenerClosedRefusesWork_L50(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, nil)
		ln := wpListen(t, rt, ListenConfig{})
		if err := ln.Handle(nil); err == nil || errors.Is(err, net.ErrClosed) {
			t.Fatalf("Handle(nil) = %v", err)
		}
		for range 2 {
			if err := ln.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
		}
		a, b := net.Pipe()
		c := &countConn{Conn: a}
		if err := ln.Handle(c); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Handle after Close: %v", err)
		}
		var buf [1]byte
		if n, err := b.Read(buf[:]); n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("pushed conn after Close: read (%d, %v)", n, err)
		}
		synctest.Wait()
		if n := c.closes.Load(); n != 1 {
			t.Fatalf("pushed conn closed %d times", n)
		}
		if pc, err := ln.Accept(context.Background()); pc != nil || !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept after Close: %v, %v", pc, err)
		}
		rt.mu.Lock()
		_, known := rt.listeners[ln]
		rt.mu.Unlock()
		if known {
			t.Fatal("the Runtime still holds a closed Listener")
		}
		rt.Close()
		wpNoState(t, rt)
	})
}

// TestAcceptContextAndClose_L50: Accept honours its ctx (an ended ctx
// returns ctx.Err() at once, a deadline returns at the deadline) and
// returns net.ErrClosed as soon as its Listener or the Runtime closes;
// it always returns exactly one of a PendingConn and an error.
func TestAcceptContextAndClose_L50(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, nil)
		ln := wpListen(t, rt, ListenConfig{})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if pc, err := ln.Accept(ctx); pc != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("Accept(cancelled) = %v, %v", pc, err)
		}
		start := time.Now()
		ctx, cancel = context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		if pc, err := ln.Accept(ctx); pc != nil || !errors.Is(err, context.DeadlineExceeded) || time.Since(start) != 300*time.Millisecond {
			t.Fatalf("Accept(deadline) = %v, %v after %v", pc, err, time.Since(start))
		}

		accept := func(ln *Listener) <-chan error {
			ch := make(chan error, 1)
			go func() {
				pc, err := ln.Accept(context.Background())
				if pc != nil {
					err = errors.New("a PendingConn without a session")
				}
				ch <- err
			}()
			return ch
		}
		blocked := accept(ln)
		synctest.Wait()
		start = time.Now()
		ln.Close()
		if err := <-blocked; !errors.Is(err, net.ErrClosed) || time.Since(start) != 0 {
			t.Fatalf("blocked Accept at Listener.Close: %v after %v", err, time.Since(start))
		}
		ln2 := wpListen(t, rt, ListenConfig{})
		blocked = accept(ln2)
		synctest.Wait()
		rt.Close()
		if err := <-blocked; !errors.Is(err, net.ErrClosed) {
			t.Fatalf("blocked Accept at Runtime.Close: %v", err)
		}
	})
}

// TestAcceptCloseRace_L50: Accept racing Close (100 runs, four Accepts
// each, Close before, while and after they block): every Accept returns
// exactly one of (PendingConn, nil) or (nil, error) — here net.ErrClosed —
// and nothing leaks (the bubble ends with no goroutine left).
func TestAcceptCloseRace_L50(t *testing.T) {
	for i := range 100 {
		synctest.Test(t, func(t *testing.T) {
			rt := wpTestRuntime(t, Config{}, nil)
			ln := wpListen(t, rt, ListenConfig{})
			results := make(chan error, 4)
			for range 4 {
				go func() {
					pc, err := ln.Accept(context.Background())
					if (pc == nil) == (err == nil) {
						err = errors.New("Accept returned both or neither")
					}
					results <- err
				}()
			}
			if i%3 == 1 {
				synctest.Wait() // the Accepts block first
			}
			var wg sync.WaitGroup
			wg.Go(func() { ln.Close() })
			if i%3 == 2 {
				wg.Go(func() { rt.Close() })
			}
			for range 4 {
				if err := <-results; !errors.Is(err, net.ErrClosed) {
					t.Fatalf("run %d: Accept: %v", i, err)
				}
			}
			wg.Wait()
			rt.Close()
		})
	}
}

// TestBlockedSourceAbandoned_L50: a source whose Accept ignores Close
// cannot hold Listener.Close: after the bound (AbandonWait) Close returns
// and the stuck accept goroutine is counted in Status.Abandoned until its
// Accept finally returns. The source is still closed exactly once, and a
// healthy source of the same Listener keeps admitting carriers meanwhile.
func TestBlockedSourceAbandoned_L50(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, nil)
		blocked, good := newFakeListener(), newFakeListener()
		blocked.hang = true
		ln := wpListen(t, rt, ListenConfig{Sources: []Source{FromListener(blocked), FromListener(good)}})
		d := pushProbe(t, rt, good, wpInst(0x71), 1)
		synctest.Wait()
		if blocked.accepts.Load() != 1 {
			t.Fatalf("blocked source: %d Accept calls", blocked.accepts.Load())
		}
		start := time.Now()
		ln.Close()
		if el := time.Since(start); el != rt.eff.timing.AbandonWait {
			t.Fatalf("Listener.Close took %v, want the bound %v", el, rt.eff.timing.AbandonWait)
		}
		if st := rt.Status(); st.Abandoned != 1 {
			t.Fatalf("abandoned %d, want the stuck accept loop", st.Abandoned)
		}
		if blocked.closes.Load() != 1 || good.closes.Load() != 1 {
			t.Fatalf("sources closed %d and %d times", blocked.closes.Load(), good.closes.Load())
		}
		close(blocked.release)
		synctest.Wait()
		if st := rt.Status(); st.Abandoned != 0 {
			t.Fatalf("abandoned %d after the stuck Accept returned", st.Abandoned)
		}
		d.close()
		rt.Close()
		wpNoState(t, rt)
	})
}

// TestAcceptTemporaryErrors_L50: temporary accept errors (EMFILE) back off
// 5 ms, 10 ms, ... up to 100 ms between attempts and never stop the
// source; then (1000 runs under -race) Listener.Close and Runtime.Close
// racing an accept loop that spins on EMFILE never panic, close the source
// exactly once and join the loop.
func TestAcceptTemporaryErrors_L50(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, nil)
		src := newFakeListener()
		for range 8 {
			src.script <- acceptResult{err: emfile()}
		}
		ln := wpListen(t, rt, ListenConfig{Sources: []Source{FromListener(src)}})
		time.Sleep(time.Second)
		synctest.Wait()
		calls := src.callTimes()
		want := []time.Duration{5, 10, 20, 40, 80, 100, 100, 100}
		if len(calls) != len(want)+1 {
			t.Fatalf("%d Accept calls, want %d", len(calls), len(want)+1)
		}
		for i, w := range want {
			if gap := calls[i+1].Sub(calls[i]); gap != w*time.Millisecond {
				t.Fatalf("gap %d: %v, want %v", i, gap, w*time.Millisecond)
			}
		}
		d := pushProbe(t, rt, src, wpInst(0x72), 1) // the source still works
		d.close()
		ln.Close()
		rt.Close()
		wpNoState(t, rt)
	})

	synctest.Test(t, func(t *testing.T) {
		r := rand.New(rand.NewPCG(50, 50))
		for i := range 1000 {
			rt := wpTestRuntime(t, Config{}, nil)
			src := newFakeListener()
			src.repeat = &acceptResult{err: emfile()}
			ln := wpListen(t, rt, ListenConfig{Sources: []Source{FromListener(src)}})
			time.Sleep(time.Duration(r.IntN(300)) * time.Millisecond)
			var wg sync.WaitGroup
			wg.Go(func() { ln.Close() })
			wg.Go(func() { rt.Close() })
			wg.Wait()
			if n := ln.loops.running(); n != 0 {
				t.Fatalf("run %d: %d accept goroutines left", i, n)
			}
			if n := src.closes.Load(); n != 1 {
				t.Fatalf("run %d: source closed %d times", i, n)
			}
			if st := rt.Status(); st.Abandoned != 0 {
				t.Fatalf("run %d: abandoned %d", i, st.Abandoned)
			}
		}
	})
}

// TestListenerSourceFailureIsolated_L50: one failing source never stops
// another (L50) and a misbehaving source cannot crash the process or leak
// conns (L51): a permanent error and a panic in Accept stop only that
// source (no retry), a conn returned together with an error is closed
// exactly once, (nil, nil) backs off like a temporary error instead of
// spinning, and a healthy source keeps admitting carriers.
func TestListenerSourceFailureIsolated_L50(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, nil)
		failing, panicking, withConn, nilNil, good := newFakeListener(), newFakeListener(), newFakeListener(), newFakeListener(), newFakeListener()
		failing.script <- acceptResult{err: errors.New("fakeListener: permanent failure")}
		panicking.panics = true
		a, _ := net.Pipe()
		leaked := &countConn{Conn: a}
		withConn.script <- acceptResult{c: leaked, err: emfile()}
		nilNil.repeat = &acceptResult{}
		ln := wpListen(t, rt, ListenConfig{Sources: []Source{
			FromListener(failing), FromListener(panicking), FromListener(withConn), FromListener(nilNil), FromListener(good),
		}})
		time.Sleep(time.Second)
		synctest.Wait()
		if failing.accepts.Load() != 1 || panicking.accepts.Load() != 1 {
			t.Fatalf("a failed source was retried: %d and %d Accept calls", failing.accepts.Load(), panicking.accepts.Load())
		}
		if n := leaked.closes.Load(); n != 1 {
			t.Fatalf("a conn returned with an error was closed %d times", n)
		}
		if n := nilNil.accepts.Load(); n < 5 || n > 20 {
			t.Fatalf("(nil, nil) source: %d Accept calls in 1 s, want a backoff", n)
		}
		d := pushProbe(t, rt, good, wpInst(0x73), 1)
		d.close()
		ln.Close()
		rt.Close()
		wpNoState(t, rt)
	})
}
