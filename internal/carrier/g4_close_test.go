package carrier

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// A close whose Close does not wait for its SetDeadline (design §0.14 B3,
// §0.8 V2; L51, L52). Every close of an embedder conn calls
// SetDeadline(now) and Close, but a conn whose deadline setters wait for a
// pending call — a websocket adapter that honours gorilla's one-reader and
// one-writer rule — and whose Close ends that call would hold a close that
// calls Close only after SetDeadline returned for as long as the call is
// pending: on a silent path, until the peer closes. Names in this file use
// the g4 prefix.

// g4LockedConn wraps a net.Conn the way such an adapter does: Read holds
// the read lock and Write the write lock for the whole call, and the
// deadline setters are read or write methods — SetReadDeadline takes the
// read lock, SetWriteDeadline the write lock, SetDeadline both — so a
// setter waits while a Read or Write is in progress. A deadline set before
// a call applies to it (it goes to the wrapped conn), and Close, which may
// be called at any time, closes the wrapped conn and so ends a Read or
// Write in progress. The locks are 1-slot channels: a waiting setter is
// durably blocked in a synctest bubble.
type g4LockedConn struct {
	net.Conn
	rd, wr  chan struct{}
	inCall  atomic.Int32 // Reads and Writes in progress
	onClose func()       // runs after the wrapped conn was closed (nil: none)

	closes      atomic.Int32
	closedAt    atomic.Int64 // UnixNano of the first Close; 0: never closed
	callAtClose atomic.Bool  // a Read or Write was in progress at the first Close (the stimulus)
	closed      chan struct{}
	once        sync.Once
}

func newG4LockedConn(nc net.Conn) *g4LockedConn {
	return &g4LockedConn{Conn: nc, rd: make(chan struct{}, 1), wr: make(chan struct{}, 1), closed: make(chan struct{})}
}

func (c *g4LockedConn) Read(p []byte) (int, error) {
	c.rd <- struct{}{}
	defer func() { <-c.rd }()
	c.inCall.Add(1)
	defer c.inCall.Add(-1)
	return c.Conn.Read(p)
}

func (c *g4LockedConn) Write(p []byte) (int, error) {
	c.wr <- struct{}{}
	defer func() { <-c.wr }()
	c.inCall.Add(1)
	defer c.inCall.Add(-1)
	return c.Conn.Write(p)
}

func (c *g4LockedConn) SetReadDeadline(t time.Time) error {
	c.rd <- struct{}{}
	defer func() { <-c.rd }()
	return c.Conn.SetReadDeadline(t)
}

func (c *g4LockedConn) SetWriteDeadline(t time.Time) error {
	c.wr <- struct{}{}
	defer func() { <-c.wr }()
	return c.Conn.SetWriteDeadline(t)
}

func (c *g4LockedConn) SetDeadline(t time.Time) error {
	err := c.SetReadDeadline(t)
	if werr := c.SetWriteDeadline(t); err == nil {
		err = werr
	}
	return err
}

func (c *g4LockedConn) Close() error {
	if c.closes.Add(1) == 1 {
		c.closedAt.Store(time.Now().UnixNano())
		c.callAtClose.Store(c.inCall.Load() > 0)
	}
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closed) })
	if c.onClose != nil {
		c.onClose()
	}
	return err
}

// closedAfter returns how long after start the conn was first closed, or −1.
func (c *g4LockedConn) closedAfter(start time.Time) time.Duration {
	n := c.closedAt.Load()
	if n == 0 {
		return -1
	}
	return time.Unix(0, n).Sub(start)
}

// waitClosed waits up to a (virtual) minute for the first Close.
func (c *g4LockedConn) waitClosed(t testing.TB) {
	t.Helper()
	select {
	case <-c.closed:
	case <-time.After(time.Minute):
		t.Fatal("the conn was never closed")
	}
}

// g4SilentPassive reads the dialer's PREFACE and OPEN and then neither
// answers, reads nor closes: the dialer's PREFACE_ACK Read stays pending.
func g4SilentPassive(nc net.Conn) {
	var in [wire.PrefaceLen + wire.FrameOverhead + wire.OpenFixedLen]byte
	_, _ = io.ReadFull(nc, in[:])
}

// TestG4CarrierEndClosesLockedConn_L52 (design §0.14 B3): a carrier whose
// conn's deadline setters wait for the reader's Read — the reader of a
// started carrier reads with no deadline — ends on a path that stays
// silent. Its closer calls SetDeadline(now) and Close, and the Close does
// not wait for the SetDeadline: the conn is closed exactly once when the
// carrier ends, the Read and then the SetDeadline return, and Done closes
// with nothing abandoned and the Budget back at zero. This holds for a
// death (Kill, ping_timeout, write_stall with a Write that ignores its
// deadline in progress too), for the end of a planned retirement whose
// peer never answers its CLOSE, and when the embedder's Close panics. A
// carrier that never started has no call in progress and is closed at
// once too. Before B3 the closer called Close only after SetDeadline
// returned, the last resort of its abandonment saw the close as done, and
// the conn was never closed: reader and closer stayed in the
// abandoned-call pool until the peer closed.
func TestG4CarrierEndClosesLockedConn_L52(t *testing.T) {
	kill := func(c *Conn) { c.Kill(CauseLocalClose, "test kill") }
	for _, tc := range []struct {
		name    string
		writes  bool // the conn's Writes block, ignoring their deadline (the peer never reads)
		start   bool // the carrier is started: its reader waits in Read
		onClose func()
		end     func(c *Conn) // nil: the carrier ends by itself
		cause   Cause
		calls   int32 // Reads and Writes in progress before the end (the stimulus)
	}{
		{"Kill while the reader waits", false, true, nil, kill, CauseLocalClose, 1},
		{"ping_timeout on a silent path", false, true, nil, nil, CausePingTimeout, 1},
		{"write_stall with the Read and the Write in progress", true, true, nil, nil, CauseWriteStall, 2},
		{"retirement whose peer never answers its CLOSE", false, true, nil,
			func(c *Conn) { c.Retire(wire.CloseRetire) }, CauseRetired, 1},
		{"the embedder's Close panics", false, true, func() { panic("boom") }, kill, CauseLocalClose, 1},
		{"never started: no call in progress", false, false, nil, kill, CauseLocalClose, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env := hEnv()
				a, b := net.Pipe()
				t.Cleanup(func() { b.Close() }) // a failed test still ends its bubble
				var lc *g4LockedConn
				if tc.writes {
					lc = newG4LockedConn(newLRConn(a, false)) // Writes ignore their deadline, honour Close
				} else {
					lc = newG4LockedConn(a)
					p := startPeer(b, env.Presets.firstFseq()) // reads everything, never answers
					t.Cleanup(p.close)
				}
				lc.onClose = tc.onClose
				c := hConn(env, lc)
				hCleanup(t, c, nil)
				if tc.start {
					c.Start(&hEP{}, &hBell{}, StartOptions{})
				}
				synctest.Wait()
				if n := lc.inCall.Load(); n != tc.calls {
					t.Fatalf("stimulus: %d calls in progress, want %d", n, tc.calls)
				}
				if tc.end != nil {
					tc.end(c)
				}
				hWait(t, c)
				synctest.Wait()
				dead, cause, _, at := c.Death()
				if !dead || cause != tc.cause {
					t.Fatalf("death %v %v, want %v", dead, cause, tc.cause)
				}
				if n, after := lc.closes.Load(), lc.closedAfter(at); n != 1 || after != 0 {
					t.Fatalf("conn closed %d times, first %v after the carrier ended; want once, at once", n, after)
				}
				if got := lc.callAtClose.Load(); got != tc.start {
					t.Fatalf("a call was in progress when the conn was closed: %v, want %v (the Close must not wait for the Read)", got, tc.start)
				}
				if env.Abandon.Len() != 0 || env.Budget.Used() != 0 {
					t.Fatalf("abandoned %d, budget %d", env.Abandon.Len(), env.Budget.Used())
				}
			})
		})
	}
}

// TestG4CloseConnLockedConn_L52 (design §0.14 B3): CloseConn calls
// SetDeadline(now) and Close on guarded goroutines, and the Close does not
// wait for the SetDeadline. A conn whose deadline setters wait for a Read
// in progress is closed at once: the Read returns, and so does an attempt
// whose context ends while its PREFACE_ACK Read waits on a passive that
// stays silent (its abort closes the conn through CloseConn): Establish
// returns at the cancellation with the conn closed exactly once, the
// carrier ID released and nothing abandoned. Before B3 the SetDeadline
// held the Close until the Read returned by itself: never for the first,
// at the attempt's deadline for the second.
func TestG4CloseConnLockedConn_L52(t *testing.T) {
	t.Run("a Read in progress", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			env := hEnv()
			a, b := net.Pipe()
			t.Cleanup(func() { b.Close() })
			lc := newG4LockedConn(a)
			readErr := make(chan error, 1)
			go func() {
				_, err := lc.Read(make([]byte, 1))
				readErr <- err
			}()
			synctest.Wait()
			if n := lc.inCall.Load(); n != 1 {
				t.Fatalf("stimulus: %d calls in progress, want the Read", n)
			}
			start := time.Now()
			CloseConn(env, lc)
			var err error
			select {
			case err = <-readErr:
			case <-time.After(time.Minute):
				t.Fatal("the Read in progress never returned: the conn was not closed")
			}
			synctest.Wait()
			if err == nil || time.Since(start) != 0 {
				t.Fatalf("the Read returned %v after %v, want an error at once", err, time.Since(start))
			}
			if n, after := lc.closes.Load(), lc.closedAfter(start); n != 1 || after != 0 || !lc.callAtClose.Load() || env.Abandon.Len() != 0 {
				t.Fatalf("conn closed %d times, first after %v (Read in progress then: %v); abandoned %d", n, after, lc.callAtClose.Load(), env.Abandon.Len())
			}
		})
	})
	t.Run("an attempt cancelled in its PREFACE_ACK Read", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			env := hEnv()
			a, b := net.Pipe()
			t.Cleanup(func() { b.Close() })
			lc := newG4LockedConn(a)
			go g4SilentPassive(b)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f := Factory{Name: "g4", Dial: func(context.Context) (net.Conn, error) { return lc, nil }}
			type result struct {
				est *Established
				err error
				at  time.Time
			}
			res := make(chan result, 1)
			go func() {
				est, err := Establish(ctx, env, f, env.IDs.Next(), wire.TypeOpen, openPayload(0), nil)
				res <- result{est, err, time.Now()}
			}()
			synctest.Wait() // the passive read the hello; Establish waits in its PREFACE_ACK Read
			if n := lc.inCall.Load(); n != 1 {
				t.Fatalf("stimulus: %d calls in progress, want the PREFACE_ACK Read", n)
			}
			start := time.Now()
			cancel()
			var r result
			select {
			case r = <-res:
			case <-time.After(time.Minute):
				t.Fatal("Establish did not return")
			}
			synctest.Wait()
			var ee *EstablishError
			if r.est != nil || !errors.As(r.err, &ee) || ee.Cause != CauseLocalClose || !errors.Is(r.err, context.Canceled) {
				t.Fatalf("Establish = %v, %v", r.est, r.err)
			}
			if d := r.at.Sub(start); d != 0 {
				t.Fatalf("Establish returned %v after the cancellation, want at once", d)
			}
			if n, after := lc.closes.Load(), lc.closedAfter(start); n != 1 || after != 0 || !lc.callAtClose.Load() {
				t.Fatalf("conn closed %d times, first %v after the cancellation (Read in progress then: %v); want once, at once", n, after, lc.callAtClose.Load())
			}
			if env.Abandon.Len() != 0 || env.IDs.inUse() != 0 {
				t.Fatalf("abandoned %d, IDs in use %d", env.Abandon.Len(), env.IDs.inUse())
			}
		})
	})
}

// TestG4StuckSetDeadlineCounted_L52 (design §0.14 B3, L52): an embedder
// SetDeadline that never returns — it ignores Close — does not delay the
// Close beside it, and it is still counted exactly. The conn is closed
// once, at once; the goroutine stuck in SetDeadline is counted in the
// abandoned-call pool AbandonWait after the close began: a carrier's Done
// waits for its deadline part until then (a joiner woken by Done sees the
// count), and CloseConn's guarded goroutine is counted by its own watch.
// When the SetDeadline returns the pool empties. Before B3 the Close waited
// behind the SetDeadline and never ran.
func TestG4StuckSetDeadlineCounted_L52(t *testing.T) {
	for _, tc := range []struct {
		name  string
		close func(env *Env, nc net.Conn) (done <-chan struct{})
	}{
		{"a carrier's Kill", func(env *Env, nc net.Conn) <-chan struct{} {
			c := hConn(env, nc)
			c.Kill(CauseLocalClose, "test kill")
			return c.Done()
		}},
		{"CloseConn", func(env *Env, nc net.Conn) <-chan struct{} {
			CloseConn(env, nc)
			return nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env := hEnv()
				a, b := net.Pipe()
				t.Cleanup(func() { b.Close() })
				release := make(chan struct{})
				var once sync.Once
				free := func() { once.Do(func() { close(release) }) }
				t.Cleanup(free) // a failed test still ends its bubble
				var sets atomic.Int32
				hc := &hookConn{Conn: a, onSetDeadline: func(net.Conn, time.Time) error {
					sets.Add(1)
					<-release // ignores Close
					return nil
				}}
				start := time.Now()
				done := tc.close(env, hc)
				synctest.Wait()
				if n := sets.Load(); n != 1 {
					t.Fatalf("stimulus: SetDeadline called %d times, want once (stuck)", n)
				}
				if n := hc.closes.Load(); n != 1 || time.Since(start) != 0 {
					t.Fatalf("closed %d times after %v, want once, at once", n, time.Since(start))
				}
				if done != nil {
					select {
					case <-done:
						t.Fatal("Done closed while the deadline part was stuck in SetDeadline and not yet counted")
					default:
					}
				}
				time.Sleep(env.Timing.AbandonWait)
				synctest.Wait()
				if done != nil {
					select {
					case <-done:
					default:
						t.Fatal("Done still open AbandonWait after the close")
					}
				}
				if n := env.Abandon.Len(); n != 1 {
					t.Fatalf("abandoned %d AbandonWait after the close, want the stuck SetDeadline", n)
				}
				free()
				synctest.Wait()
				if n, k := hc.closes.Load(), env.Abandon.Len(); n != 1 || k != 0 {
					t.Fatalf("after the SetDeadline returned: closed %d times, abandoned %d", n, k)
				}
			})
		})
	}
}

// TestG4LastResortClosesLockedConn_L52 (design §0.14 B3, §0.8 V2): a
// verdict write — the frame or the drain of WriteAndClose, the inline
// verdict, the RST(withdrawn) after an instance refusal — on a conn whose
// call ignores its deadline while it holds the lock its deadline setters
// wait for, to a peer that neither reads nor closes: the last resort calls
// Close directly, not after a SetDeadline of its own, so the conn is
// closed exactly once at the last resort, the stuck call returns and
// nothing stays abandoned. Before B3 the last resort's SetDeadline waited
// for the stuck call, and the conn was never closed.
func TestG4LastResortClosesLockedConn_L52(t *testing.T) {
	const abandonWait = time.Second // hTiming
	errOther := errors.New("not the bound instance")
	for _, tc := range []struct {
		name  string
		deaf  bool // the drain's Read ignores its deadline (else the verdict's Write does)
		after time.Duration
		run   func(t *testing.T, env *Env, nc net.Conn, peer net.Conn)
	}{
		{"WriteAndClose frame, the peer never reads", false, abandonWait + time.Second + drainMax,
			func(t *testing.T, env *Env, nc net.Conn, _ net.Conn) {
				c := hConn(env, nc)
				c.WriteAndClose(wire.TypeClose, 0, 0, []byte{byte(wire.CloseCapacity)}, time.Now().Add(time.Second))
				hWait(t, c)
			}},
		{"WriteAndClose drain, the peer reads the verdict and stays", true, abandonWait + time.Second + drainMax,
			func(t *testing.T, env *Env, nc net.Conn, peer net.Conn) {
				go func() {
					var fr [wire.FrameOverhead + 1]byte
					_, _ = io.ReadFull(peer, fr[:]) // then silent: the drain never sees EOF
				}()
				c := hConn(env, nc)
				c.WriteAndClose(wire.TypeClose, 0, 0, []byte{byte(wire.CloseCapacity)}, time.Now().Add(time.Second))
				hWait(t, c)
			}},
		{"inline verdict, the peer never reads", false, abandonWait + time.Second + drainMax,
			func(t *testing.T, env *Env, nc net.Conn, _ net.Conn) {
				done := make(chan struct{})
				go func() {
					defer close(done)
					writeAndCloseInline(env, &closeOnce{nc: nc}, hPrefaceAck(wire.PrefaceVersion, 9), time.Now().Add(time.Second))
				}()
				select {
				case <-done:
				case <-time.After(time.Minute):
					t.Fatal("the inline verdict never returned")
				}
			}},
		{"RST(withdrawn) after an instance refusal, the peer stops reading", false, abandonWait + 3*drainMax,
			func(t *testing.T, env *Env, nc net.Conn, peer net.Conn) {
				id := env.IDs.Next()
				go lrSilentPassive(peer, id)
				f := Factory{Name: "g4", Dial: func(context.Context) (net.Conn, error) { return nc, nil }}
				_, err := Establish(context.Background(), env, f, id, wire.TypeOpen, openPayload(0), func(*wire.PrefaceAck) error { return errOther })
				var ee *EstablishError
				if !errors.As(err, &ee) || ee.Cause != CauseInstanceMismatch {
					t.Fatalf("Establish: %v", err)
				}
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env := hEnv()
				a, b := net.Pipe()
				t.Cleanup(func() { b.Close() }) // unblocks a goroutine the last resort missed
				lc := newG4LockedConn(newLRConn(a, tc.deaf))
				start := time.Now()
				tc.run(t, env, lc, b)
				lc.waitClosed(t)
				synctest.Wait()
				if !lc.callAtClose.Load() {
					t.Fatal("stimulus: no stuck call in progress when the conn was closed")
				}
				if n, at := lc.closes.Load(), lc.closedAfter(start); n != 1 || at != tc.after {
					t.Fatalf("conn closed %d times, first after %v; want once, by the last resort after %v", n, at, tc.after)
				}
				if env.Abandon.Len() != 0 || env.IDs.inUse() != 0 {
					t.Fatalf("abandoned %d (the stuck goroutine must return once closed), IDs in use %d", env.Abandon.Len(), env.IDs.inUse())
				}
			})
		})
	}
}

// TestG4WithdrawnAttemptLockedConn_L49_L52 (design §0.14 B3, L49, L52): an
// OPEN attempt withdrawn — its context cancelled with cause ErrWithdrawn —
// while its PREFACE_ACK Read waits on a conn whose deadline setters wait
// for that Read, towards a passive that stays silent. The withdrawal's
// goroutine starts SetDeadline(now) on a goroutine of its own, which waits
// behind the Read, and waits at most drainMax for the handshake to leave
// the conn before the best-effort RST. The handshake cannot leave, so the
// RST is dropped and the conn is closed: exactly once, drainMax after the
// withdrawal, while the Read is in progress, and Establish returns then
// with the withdrawal. Nothing is counted in the abandoned-call pool at any
// time, also with an AbandonWait shorter than drainMax: the SetDeadline
// that waits for that close is not stuck in embedder code, and returns
// with the Read. Before the fix the SetDeadline ran on the withdrawal's own
// goroutine and held it until its last resort (AbandonWait + 3·drainMax);
// a SetDeadline counted AbandonWait after it started would be counted
// before the close that ends it.
func TestG4WithdrawnAttemptLockedConn_L49_L52(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const wait = 500 * time.Millisecond // shorter than drainMax
		env := hEnv()
		env.Timing.AbandonWait = wait
		a, b := net.Pipe()
		t.Cleanup(func() { b.Close() }) // a failed test still ends its bubble
		lc := newG4LockedConn(a)
		go g4SilentPassive(b)
		ctx, cancel := context.WithCancelCause(context.Background())
		defer cancel(nil)
		f := Factory{Name: "g4", Dial: func(context.Context) (net.Conn, error) { return lc, nil }}
		type result struct {
			est *Established
			err error
			at  time.Time
		}
		res := make(chan result, 1)
		go func() {
			est, err := Establish(ctx, env, f, env.IDs.Next(), wire.TypeOpen, openPayload(0), nil)
			res <- result{est, err, time.Now()}
		}()
		synctest.Wait() // the passive read the hello; Establish waits in its PREFACE_ACK Read
		if n := lc.inCall.Load(); n != 1 {
			t.Fatalf("stimulus: %d calls in progress, want the PREFACE_ACK Read", n)
		}
		start := time.Now()
		cancel(ErrWithdrawn)
		time.Sleep((wait + drainMax) / 2) // past AbandonWait, before drainMax
		synctest.Wait()
		if n, k := lc.closes.Load(), env.Abandon.Len(); n != 0 || k != 0 {
			t.Fatalf("%v after the withdrawal: conn closed %d times, abandoned %d; want the handshake still awaited and nothing counted", time.Since(start), n, k)
		}
		var r result
		select {
		case r = <-res:
		case <-time.After(time.Minute):
			t.Fatal("Establish did not return")
		}
		synctest.Wait()
		var ee *EstablishError
		if r.est != nil || !errors.As(r.err, &ee) || ee.Cause != CauseLocalClose || !errors.Is(r.err, ErrWithdrawn) {
			t.Fatalf("Establish = %v, %v; want the withdrawal", r.est, r.err)
		}
		if d := r.at.Sub(start); d != drainMax {
			t.Fatalf("Establish returned %v after the withdrawal, want %v (the handshake awaited, then the close)", d, drainMax)
		}
		if n, after := lc.closes.Load(), lc.closedAfter(start); n != 1 || after != drainMax || !lc.callAtClose.Load() {
			t.Fatalf("conn closed %d times, first %v after the withdrawal (Read in progress then: %v); want once, after %v, while the Read waited", n, after, lc.callAtClose.Load(), drainMax)
		}
		if env.Abandon.Len() != 0 || env.IDs.inUse() != 0 {
			t.Fatalf("abandoned %d, IDs in use %d", env.Abandon.Len(), env.IDs.inUse())
		}
		time.Sleep(wait + 3*drainMax) // past every watch the withdrawal armed
		synctest.Wait()
		if n, k := lc.closes.Load(), env.Abandon.Len(); n != 1 || k != 0 {
			t.Fatalf("later: conn closed %d times, abandoned %d", n, k)
		}
	})
}

// TestG4WithdrawRstFollowsUnblockingDeadline_L49 (design §0.14 B3, L49):
// the withdrawal's SetDeadline(now), which unblocks the handshake, runs on
// a goroutine of its own, so the RST(withdrawn) after it must wait until it
// returned: a SetDeadline that applies its write half only after the RST's
// write deadline was set would expire the RST's Write. The conn's
// SetDeadline sets the read deadline (the handshake's response Read
// returns, the handshake leaves the conn), then waits until released before
// it sets the write deadline; the passive reads nothing more after the
// hello until after the release.
// The RST's write is set up only after the SetDeadline returned, so the
// passive reads exactly one RST(withdrawn) after the OPEN, and the conn is
// closed exactly once, after the drain; Establish returns at the
// withdrawal and nothing is abandoned.
func TestG4WithdrawRstFollowsUnblockingDeadline_L49(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		a, b := net.Pipe()
		t.Cleanup(func() { b.Close() }) // a failed test still ends its bubble
		gate := make(chan struct{})
		var gateOnce sync.Once
		release := func() { gateOnce.Do(func() { close(gate) }) }
		t.Cleanup(release)
		var sets atomic.Int32
		hc := &hookConn{Conn: a, onSetDeadline: func(nc net.Conn, d time.Time) error {
			if sets.Add(1) == 1 {
				return nc.SetDeadline(d) // the attempt's deadline
			}
			err := nc.SetReadDeadline(d)
			<-gate // the write half comes late
			if werr := nc.SetWriteDeadline(d); err == nil {
				err = werr
			}
			return err
		}}
		id := env.IDs.Next()
		readNow := make(chan struct{})
		var after []byte
		passive := make(chan error, 1)
		go func() {
			var in [wire.PrefaceLen + wire.FrameOverhead + wire.OpenFixedLen]byte
			if _, err := io.ReadFull(b, in[:]); err != nil {
				passive <- err
				return
			}
			if _, err := b.Write(hPrefaceAck(wire.PrefaceOK, id)); err != nil {
				passive <- err
				return
			}
			<-readNow
			var err error
			after, err = io.ReadAll(b)
			passive <- err
		}()
		ctx, cancel := context.WithCancelCause(context.Background())
		defer cancel(nil)
		f := Factory{Name: "g4", Dial: func(context.Context) (net.Conn, error) { return hc, nil }}
		res := make(chan error, 1)
		go func() {
			_, err := Establish(ctx, env, f, id, wire.TypeOpen, openPayload(0), nil)
			res <- err
		}()
		synctest.Wait() // PREFACE_ACK(OK) read; Establish waits in its response Read
		start := time.Now()
		cancel(ErrWithdrawn)
		if err := <-res; !errors.Is(err, ErrWithdrawn) || time.Since(start) != 0 {
			t.Fatalf("Establish = %v after %v, want the withdrawal at once", err, time.Since(start))
		}
		synctest.Wait()
		if n := sets.Load(); n != 2 {
			t.Fatalf("stimulus: %d SetDeadline calls, want the attempt's and the withdrawal's, its write half held", n)
		}
		release()
		synctest.Wait()
		close(readNow)
		if err := <-passive; err != nil {
			t.Fatalf("passive: %v", err)
		}
		fr, n, err := wire.DecodeFrame(after)
		if err != nil || n != len(after) || fr.Type != wire.TypeRst {
			t.Fatalf("after the OPEN the passive read %d bytes (%+v, %v), want one RST", len(after), fr.Header, err)
		}
		if r, err := wire.ParseRst(fr.Payload); err != nil || r.Code != wire.RstWithdrawn {
			t.Fatalf("RST %+v %v", r, err)
		}
		synctest.Wait()
		if hc.closes.Load() != 1 || env.Abandon.Len() != 0 || env.IDs.inUse() != 0 {
			t.Fatalf("conn closed %d times, abandoned %d, IDs in use %d", hc.closes.Load(), env.Abandon.Len(), env.IDs.inUse())
		}
	})
}
