package l4

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// M4 WP5 review rows: the default dialer (a Server without a Dial hook and
// the package-level Serve), a session decided before the dial, a target
// that connects after Serve's ctx ended, and hook conns whose Close panics.

// setDialTCP replaces the default dialer for one test.
func setDialTCP(t testing.TB, dial func(ctx context.Context, addr string) (net.Conn, error)) {
	t.Helper()
	old := dialTCP
	dialTCP = dial
	t.Cleanup(func() { dialTCP = old })
}

// dialRecord is what one default-dialer call saw.
type dialRecord struct {
	mu       sync.Mutex
	calls    int
	at       time.Time // the call's start
	deadline time.Time // its ctx's deadline (zero: none)
	done     time.Time // when its ctx ended (zero: not yet)
}

// hang is a default dialer that records its call and waits for ctx, as a
// target that never answers.
func (d *dialRecord) hang(ctx context.Context, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.calls++
	d.at = time.Now()
	d.deadline, _ = ctx.Deadline()
	d.mu.Unlock()
	<-ctx.Done()
	d.mu.Lock()
	d.done = time.Now()
	d.mu.Unlock()
	return nil, &net.OpError{Op: "dial", Net: "tcp", Err: ctx.Err()}
}

func (d *dialRecord) snapshot() (calls int, at, deadline, done time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls, d.at, d.deadline, d.done
}

// TestServerDefaultDialerBudget (M4-D29 for the default dialer): without a
// Dial hook the target dial's ctx carries the dial budget — DialTimeout, or
// the pending deadline − 250 ms when that comes first — and ends there; the
// dialer is answered CodeTimeout before the AcceptTimeout.
func TestServerDefaultDialerBudget(t *testing.T) {
	rows := []struct {
		name          string
		acceptTimeout time.Duration
		dialTimeout   time.Duration
		lo, hi        time.Duration // the budget from the call's start
	}{
		{"DialTimeout", 0, time.Second, time.Second, time.Second},
		{"pending deadline", 2 * time.Second, 30 * time.Second, 1700 * time.Millisecond, 1750 * time.Millisecond},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var rec dialRecord
				setDialTCP(t, rec.hang)
				w := newSrvWorld(t, srvOpts{acceptTimeout: row.acceptTimeout})
				s := &Server{DialTimeout: row.dialTimeout}
				sv := serve(w, s)
				start := time.Now()
				r := recv(t, dialAsync(context.Background(), w, kitTarget), time.Minute)
				wantReject(t, r.err, CodeTimeout)
				calls, at, deadline, done := rec.snapshot()
				if calls != 1 || deadline.IsZero() {
					t.Fatalf("%d default dials; ctx deadline %v (want the budget)", calls, deadline)
				}
				if b := deadline.Sub(at); b < row.lo || b > row.hi {
					t.Fatalf("the dial ctx's budget %v, want %v–%v", b, row.lo, row.hi)
				}
				if !done.Equal(deadline) {
					t.Fatalf("the dial ctx ended %v after its deadline", done.Sub(deadline))
				}
				if row.acceptTimeout > 0 && r.at.Sub(start) >= row.acceptTimeout {
					t.Fatalf("refused after %v, not before the AcceptTimeout", r.at.Sub(start))
				}
				// The Server counts a refusal after sending it (Server.reject), so the
				// dialer can see the refusal before Status counts it.
				waitFor(t, time.Minute, "the Server counts the refusal", func() bool { return s.Status().ByCode[CodeTimeout] != 0 })
				if st := s.Status(); st.ByCode[CodeTimeout] != 1 || st.Dialing != 0 || st.Hooks != 0 {
					t.Fatalf("status %+v", st)
				}
				sv.stop(t)
				w.shutdown()
			})
		})
	}
}

// TestServerDefaultDialerWithdraw_L49 (M4-D22, P2 and P6 for the default
// dialer): the dialer's withdrawal, or Listener.Close, during a default
// target dial ends that dial's ctx within 100 ms; the handler sends no
// Reject (Lost == 1).
func TestServerDefaultDialerWithdraw_L49(t *testing.T) {
	for _, row := range []string{"withdrawal", "Listener.Close"} {
		t.Run(row, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var rec dialRecord
				setDialTCP(t, rec.hang)
				w := newSrvWorld(t, srvOpts{})
				s := &Server{}
				sv := serve(w, s)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				ch := dialAsync(ctx, w, kitTarget)
				waitFor(t, time.Minute, "the default dial runs", func() bool { c, _, _, _ := rec.snapshot(); return c == 1 })
				time.Sleep(100 * time.Millisecond)
				ended := time.Now()
				if row == "withdrawal" {
					cancel()
				} else {
					w.ln.Close()
				}
				r := recv(t, ch, time.Minute)
				if row == "withdrawal" && !errors.Is(r.err, context.Canceled) || row != "withdrawal" && !errors.Is(r.err, rendr.ErrCapacity) {
					t.Fatalf("Dial: %v", r.err)
				}
				waitFor(t, time.Minute, "the default dial ends", func() bool { _, _, _, d := rec.snapshot(); return !d.IsZero() })
				if _, _, _, d := rec.snapshot(); d.Sub(ended) > 100*time.Millisecond {
					t.Fatalf("the default dial's ctx ended %v after the %s", d.Sub(ended), row)
				}
				waitFor(t, time.Minute, "the handler ends", func() bool { return s.Status().Dialing == 0 })
				if st := s.Status(); st.Lost != 1 || st.Rejected != 0 || st.Confirmed+st.Unconfirmed != 0 {
					t.Fatalf("status %+v", st)
				}
				sv.stop(t)
				w.shutdown()
			})
		})
	}
}

// TestServeDefaultEcho: the package-level Serve (a zero Server) dials the
// OPEN's target with the default dialer, forwards an intact echo, and
// returns context.Canceled after its ctx is cancelled.
func TestServeDefaultEcho(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		target := rendrtest.NewTarget(rendrtest.TargetEcho(), 0)
		var addrs []string
		var mu sync.Mutex
		setDialTCP(t, func(ctx context.Context, addr string) (net.Conn, error) {
			mu.Lock()
			addrs = append(addrs, addr)
			mu.Unlock()
			return target.Dial(ctx, addr)
		})
		w := newSrvWorld(t, srvOpts{})
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- Serve(ctx, w.ln) }()
		c, err := Dial(context.Background(), w.peer, kitTarget, rendr.DialOptions{})
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		echoRoundTrip(t, c, 128<<10, 3)
		c.Close()
		waitFor(t, time.Minute, "the target is released", func() bool { return target.Counts().Open == 0 })
		mu.Lock()
		if len(addrs) != 1 || addrs[0] != kitTarget {
			t.Fatalf("default dials %q, want one to %q", addrs, kitTarget)
		}
		mu.Unlock()
		if tc := target.Counts(); tc.Accepted != 1 || tc.BytesIn != 128<<10 || tc.RSTIn != 0 {
			t.Fatalf("target %+v", tc)
		}
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Serve: %v", err)
			}
		case <-time.After(time.Minute):
			t.Fatal("Serve did not return")
		}
		w.shutdown()
	})
}

// TestServerHandleDecidedBeforeDial_L49 (R1-6 rule 2 before the dial): a
// pending session withdrawn between Accept and Handle is not dialled for
// (no hook call, no default dial) and gets no Reject (Lost == 1).
func TestServerHandleDecidedBeforeDial_L49(t *testing.T) {
	for _, custom := range []bool{true, false} {
		name := "default dialer"
		if custom {
			name = "hook"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var rec dialRecord
				setDialTCP(t, rec.hang)
				w := newSrvWorld(t, srvOpts{})
				s := &Server{}
				var hookCalls atomic.Int64
				if custom {
					s.Dial = func(ctx context.Context, r Request) (net.Conn, error) {
						hookCalls.Add(1)
						return rec.hang(ctx, r.Addr)
					}
				}
				ctx, cancel := context.WithCancel(context.Background())
				ch := dialAsync(ctx, w, kitTarget)
				p, err := w.ln.Accept(context.Background())
				if err != nil {
					t.Fatalf("Accept: %v", err)
				}
				cancel()
				if r := recv(t, ch, time.Minute); !errors.Is(r.err, context.Canceled) {
					t.Fatalf("Dial: %v", r.err)
				}
				select {
				case <-p.Context().Done():
				case <-time.After(time.Minute):
					t.Fatal("the withdrawal did not end the pending context")
				}
				s.Handle(context.Background(), p)
				if c, _, _, _ := rec.snapshot(); c != 0 || hookCalls.Load() != 0 {
					t.Fatalf("%d dials (%d hook calls) for a withdrawn session", c, hookCalls.Load())
				}
				if st := s.Status(); st.Lost != 1 || st.Rejected != 0 || st.Hooks != 0 || st.Dialing != 0 {
					t.Fatalf("status %+v", st)
				}
				w.shutdown()
			})
		})
	}
}

// TestServerCtxCancelThenConnect (R1-6, M4-D34): a hook that ignores ctx
// and returns a connected target 100 ms after Serve's ctx was cancelled
// (inside its budget): the session is rejected CodeDialFailed and never
// confirmed, and the target is reset and closed once.
func TestServerCtxCancelThenConnect(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newSrvWorld(t, srvOpts{})
		target := rendrtest.NewTarget(rendrtest.TargetEcho(), 0)
		var spies []*spyConn
		var mu sync.Mutex
		dialTarget := spyHook(target, &spies, &mu)
		var called atomic.Bool
		s := &Server{Dial: func(ctx context.Context, r Request) (net.Conn, error) {
			called.Store(true)
			<-ctx.Done()
			time.Sleep(100 * time.Millisecond)
			return dialTarget(context.Background(), r)
		}}
		sv := serve(w, s)
		ch := dialAsync(context.Background(), w, kitTarget)
		waitFor(t, time.Minute, "the hook is called", called.Load)
		cancelled := time.Now()
		sv.cancel()
		r := recv(t, ch, time.Minute)
		wantReject(t, r.err, CodeDialFailed)
		if el := r.at.Sub(cancelled); el < 100*time.Millisecond || el > 150*time.Millisecond {
			t.Fatalf("refused %v after the cancel, want when the target connected (100 ms)", el)
		}
		if err := sv.wait(t, time.Minute); !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve: %v", err)
		}
		waitFor(t, time.Minute, "the target is released", func() bool { return target.Counts().Open == 0 })
		if st := s.Status(); st.Confirmed != 0 || st.Unconfirmed != 0 || st.ByCode[CodeDialFailed] != 1 || st.Live != 0 {
			t.Fatalf("status %+v", st)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(spies) != 1 {
			t.Fatalf("%d target conns", len(spies))
		}
		_, linger0, closes, _ := spies[0].snapshot()
		if tc := target.Counts(); closes != 1 || linger0 == 0 || tc.RSTIn != 1 || tc.FINIn != 0 {
			t.Fatalf("target conn: %d closes, %d SetLinger(0); target %+v", closes, linger0, tc)
		}
		w.shutdown()
	})
}

// badCloseConn is a hook conn whose Close panics, or calls runtime.Goexit.
type badCloseConn struct {
	net.Conn
	goexit bool
	closes atomic.Int32
}

func (c *badCloseConn) Close() error {
	c.closes.Add(1)
	c.Conn.Close()
	if c.goexit {
		runtime.Goexit()
	}
	panic("rendr test: Close panics")
}

// TestServerHookConnClosePanics_L51 (M4-D30): a conn the Server drops on
// the hook's behalf — returned with an error, or late after the call was
// abandoned — whose Close panics or calls runtime.Goexit does not bring
// the process down: the call is answered as usual, the Close is counted in
// Panics, the conn is closed once, and the hook count returns to 0.
func TestServerHookConnClosePanics_L51(t *testing.T) {
	rows := []struct {
		name   string
		late   bool
		goexit bool
		code   RejectCode
	}{
		{"conn and err, panic", false, false, CodeRefused},
		{"conn and err, goexit", false, true, CodeRefused},
		{"late conn, panic", true, false, CodeTimeout},
		{"late conn, goexit", true, true, CodeTimeout},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newSrvWorld(t, srvOpts{})
				refuse, _ := rendrtest.ScriptedDial(rendrtest.OutcomeRefuse())
				var bad *badCloseConn
				var mu sync.Mutex
				s := &Server{DialTimeout: time.Second, Dial: func(ctx context.Context, r Request) (net.Conn, error) {
					c, _ := rendrtest.TargetPipe(0)
					mu.Lock()
					bad = &badCloseConn{Conn: c, goexit: row.goexit}
					b := bad
					mu.Unlock()
					if row.late {
						time.Sleep(20 * time.Second) // ignores ctx
						return b, nil
					}
					_, err := refuse(ctx, r.Addr)
					return b, err
				}}
				sv := serve(w, s)
				r := recv(t, dialAsync(context.Background(), w, kitTarget), time.Minute)
				wantReject(t, r.err, row.code)
				waitFor(t, time.Minute, "the hook call ends", func() bool { return s.Status().Hooks == 0 })
				st := s.Status()
				mu.Lock()
				closes := bad.closes.Load()
				mu.Unlock()
				if st.Panics != 1 || st.Abandoned != 0 || closes != 1 {
					t.Fatalf("status %+v; Close called %d times", st, closes)
				}
				sv.stop(t)
				w.shutdown()
			})
		})
	}
}
