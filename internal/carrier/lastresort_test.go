package carrier

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// lrConn is one end of a net.Pipe that ignores write deadlines (unless
// writeDeadlines) — and, when deaf, read deadlines too — but honours Close:
// a Write or Read in progress returns as soon as the conn is closed (design
// §0.8 V2). It counts Writes and Closes, records when it was first closed
// and closes closed then (a gate for the tests).
type lrConn struct {
	net.Conn
	deaf           bool
	writeDeadlines bool // honour write deadlines like a plain net.Pipe end
	writes         atomic.Int32
	closes         atomic.Int32
	closedAt       atomic.Int64 // UnixNano of the first Close; 0: never closed
	closed         chan struct{}
	once           sync.Once
}

func newLRConn(nc net.Conn, deaf bool) *lrConn {
	return &lrConn{Conn: nc, deaf: deaf, closed: make(chan struct{})}
}

func (l *lrConn) Write(p []byte) (int, error) {
	l.writes.Add(1)
	return l.Conn.Write(p)
}

func (l *lrConn) Close() error {
	if l.closes.Add(1) == 1 {
		l.closedAt.Store(time.Now().UnixNano())
	}
	err := l.Conn.Close()
	l.once.Do(func() { close(l.closed) })
	return err
}

func (l *lrConn) SetDeadline(t time.Time) error {
	_ = l.SetWriteDeadline(t)
	return l.SetReadDeadline(t)
}

func (l *lrConn) SetWriteDeadline(t time.Time) error {
	if !l.writeDeadlines {
		return nil
	}
	return l.Conn.SetWriteDeadline(t)
}

func (l *lrConn) SetReadDeadline(t time.Time) error {
	if l.deaf {
		return nil
	}
	return l.Conn.SetReadDeadline(t)
}

// closedAfter returns how long after start the conn was first closed, or −1.
func (l *lrConn) closedAfter(start time.Time) time.Duration {
	n := l.closedAt.Load()
	if n == 0 {
		return -1
	}
	return time.Unix(0, n).Sub(start)
}

// waitClosed waits for the first Close (inside a bubble the wait is
// virtual: time advances to the timer that closes the conn).
func (l *lrConn) waitClosed(t testing.TB) {
	t.Helper()
	select {
	case <-l.closed:
	case <-time.After(time.Minute):
		t.Fatal("the conn was never closed")
	}
}

// lrSilentPassive is a passive end that reads the dialer's PREFACE and
// OPEN, answers PREFACE_ACK(OK) for carrier id and then neither reads nor
// closes: a verdict the dialer writes after it is never taken.
func lrSilentPassive(nc net.Conn, id uint32) {
	var in [wire.PrefaceLen + wire.FrameOverhead + wire.OpenFixedLen]byte
	if _, err := io.ReadFull(nc, in[:]); err != nil {
		return
	}
	_, _ = nc.Write(hPrefaceAck(wire.PrefaceOK, id))
}

// TestVerdictWriteLastResortClose_L52 (design §0.8 V2): a verdict write on
// a conn that ignores its write deadline (or the drain's read deadline)
// but honours Close, to a peer that neither reads nor closes — the frame
// or the drain of WriteAndClose, the RST(withdrawn) after an instance
// refusal or after a withdrawal, and the inline verdict meant for
// ReadHello's PREFACE_ACK refusals — ends when the abandonment timer adopts
// the stuck goroutine: the conn is then closed exactly once, at that moment
// (the last resort), the goroutine returns and leaves the abandoned-call
// pool. Establish returns before its RST (written on a goroutine of its
// own); the inline verdict holds its caller until the last resort, as a
// refusal holds its handshake slot. Without the last resort the conn stays
// open and the goroutine stuck.
func TestVerdictWriteLastResortClose_L52(t *testing.T) {
	const abandonWait = time.Second // hTiming
	errOther := errors.New("not the bound instance")
	refusal := func() []byte { return hPrefaceAck(wire.PrefaceVersion, 9) }
	for _, tc := range []struct {
		name   string
		deaf   bool
		writes int32 // Writes the conn saw (the stimulus)
		after  time.Duration
		run    func(t *testing.T, env *Env, nc *lrConn, peer net.Conn)
	}{
		{"WriteAndClose frame, the peer never reads", false, 1, abandonWait + time.Second + drainMax,
			func(t *testing.T, env *Env, nc *lrConn, _ net.Conn) {
				c := hConn(env, nc)
				start := time.Now()
				c.WriteAndClose(wire.TypeClose, 0, 0, []byte{byte(wire.CloseCapacity)}, start.Add(time.Second))
				hWait(t, c)
				if d := time.Since(start); d != abandonWait+time.Second+drainMax {
					t.Fatalf("Done after %v, want the abandonment of the closer", d)
				}
				if cause := hCause(c); cause != CauseLocalClose {
					t.Fatalf("cause %v", cause)
				}
			}},
		{"WriteAndClose drain, the peer reads the verdict and stays", true, 1, abandonWait + time.Second + drainMax,
			func(t *testing.T, env *Env, nc *lrConn, peer net.Conn) {
				got := make(chan wire.Type, 1)
				go func() {
					var fr [wire.FrameOverhead + 1]byte
					if _, err := io.ReadFull(peer, fr[:]); err != nil {
						got <- 0
						return
					}
					got <- wire.Type(fr[0]) // then silent: the drain never sees EOF
				}()
				c := hConn(env, nc)
				c.WriteAndClose(wire.TypeClose, 0, 0, []byte{byte(wire.CloseCapacity)}, time.Now().Add(time.Second))
				if typ := <-got; typ != wire.TypeClose {
					t.Fatalf("the peer read %v, want the CLOSE verdict", typ)
				}
				hWait(t, c)
			}},
		{"RST(withdrawn) after an instance refusal, the peer stops reading", false, 2, abandonWait + 3*drainMax,
			func(t *testing.T, env *Env, nc *lrConn, peer net.Conn) {
				id := env.IDs.Next()
				go lrSilentPassive(peer, id)
				f := Factory{Name: "lr", Dial: func(context.Context) (net.Conn, error) { return nc, nil }}
				start := time.Now()
				_, err := Establish(context.Background(), env, f, id, wire.TypeOpen, openPayload(0), func(*wire.PrefaceAck) error { return errOther })
				var ee *EstablishError
				if !errors.As(err, &ee) || ee.Cause != CauseInstanceMismatch || time.Since(start) != 0 {
					t.Fatalf("after %v: %v", time.Since(start), err)
				}
			}},
		{"RST(withdrawn) after a withdrawal, the peer stops reading", false, 2, 100*time.Millisecond + abandonWait + 3*drainMax,
			func(t *testing.T, env *Env, nc *lrConn, peer net.Conn) {
				id := env.IDs.Next()
				go lrSilentPassive(peer, id)
				ctx, cancel := context.WithCancelCause(context.Background())
				defer cancel(nil)
				time.AfterFunc(100*time.Millisecond, func() { cancel(ErrWithdrawn) })
				f := Factory{Name: "lr", Dial: func(context.Context) (net.Conn, error) { return nc, nil }}
				start := time.Now()
				_, err := Establish(ctx, env, f, id, wire.TypeOpen, openPayload(0), nil)
				if !errors.Is(err, ErrWithdrawn) || time.Since(start) != 100*time.Millisecond {
					t.Fatalf("after %v: %v, want the withdrawal at once", time.Since(start), err)
				}
			}},
		{"inline verdict (a PREFACE_ACK refusal), the peer never reads", false, 1, abandonWait + time.Second + drainMax,
			func(t *testing.T, env *Env, nc *lrConn, _ net.Conn) {
				start := time.Now()
				writeAndCloseInline(env, &closeOnce{nc: nc}, refusal(), start.Add(time.Second))
				if d := time.Since(start); d != abandonWait+time.Second+drainMax {
					t.Fatalf("returned after %v, want the last resort", d)
				}
			}},
		{"inline verdict drain, the peer reads the refusal and stays", true, 1, abandonWait + time.Second + drainMax,
			func(t *testing.T, env *Env, nc *lrConn, peer net.Conn) {
				got := make(chan []byte, 1)
				go func() {
					var ab [wire.PrefaceLen]byte
					_, _ = io.ReadFull(peer, ab[:])
					got <- ab[:] // then silent: the drain never sees EOF
				}()
				start := time.Now()
				writeAndCloseInline(env, &closeOnce{nc: nc}, refusal(), start.Add(time.Second))
				if ack, err := wire.ParsePrefaceAck(<-got); err != nil || ack.Status != wire.PrefaceVersion {
					t.Fatalf("the peer read %+v %v, want the refusal", ack, err)
				}
				if d := time.Since(start); d != abandonWait+time.Second+drainMax {
					t.Fatalf("returned after %v, want the last resort", d)
				}
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env := hEnv()
				a, b := net.Pipe()
				defer b.Close() // unblocks a goroutine the last resort missed, so the bubble can end
				nc := newLRConn(a, tc.deaf)
				start := time.Now()
				tc.run(t, env, nc, b)
				nc.waitClosed(t)
				synctest.Wait()
				if nc.writes.Load() != tc.writes {
					t.Fatalf("stimulus: %d conn Writes, want %d", nc.writes.Load(), tc.writes)
				}
				if n, at := nc.closes.Load(), nc.closedAfter(start); n != 1 || at != tc.after {
					t.Fatalf("conn closed %d times, first after %v; want once, by the last resort after %v", n, at, tc.after)
				}
				if env.Abandon.Len() != 0 || env.IDs.inUse() != 0 {
					t.Fatalf("abandoned %d (the stuck goroutine must return once closed), IDs in use %d", env.Abandon.Len(), env.IDs.inUse())
				}
			})
		})
	}
}

// TestInlineVerdictGoexitClosesOnce_L51: a runtime.Goexit inside the
// embedder's Write of an inline verdict skips its final close; the
// caller's Goexit guard closes through the same closeOnce, so the conn is
// closed exactly once — also when the last resort already closed it under
// a Write that ignored its deadline and then ran Goexit — and nothing stays
// counted in the abandoned-call pool.
func TestInlineVerdictGoexitClosesOnce_L51(t *testing.T) {
	for _, tc := range []struct {
		name  string
		block bool // the Write blocks until the conn is closed, then runs Goexit
		at    time.Duration
	}{{"at once", false, 0}, {"after the last resort", true, time.Second + time.Second + drainMax}} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env := hEnv()
				a, b := net.Pipe()
				defer b.Close()
				closed := make(chan struct{})
				var once sync.Once
				var closes atomic.Int32
				hc := &hookConn{Conn: a,
					onWrite: func(net.Conn, []byte) (int, error) {
						if tc.block {
							<-closed // ignores its deadline, honours Close
						}
						runtime.Goexit()
						return 0, nil
					},
					onSetWriteDeadline: func(net.Conn, time.Time) error { return nil },
					onClose: func(nc net.Conn) error {
						closes.Add(1)
						once.Do(func() { close(closed) })
						return nc.Close()
					}}
				k := &closeOnce{nc: hc}
				start := time.Now()
				done := make(chan struct{})
				returned := false
				go func() {
					defer close(done)
					defer k.async(env) // the caller's Goexit guard (ReadHello's)
					writeAndCloseInline(env, k, hPrefaceAck(wire.PrefaceCapacity, 9), start.Add(time.Second))
					returned = true
				}()
				<-done
				synctest.Wait()
				if returned || hc.writes.Load() != 1 {
					t.Fatalf("stimulus: returned %v, writes %d; want one Write that ran Goexit", returned, hc.writes.Load())
				}
				if d := time.Since(start); d != tc.at {
					t.Fatalf("the Goexit came after %v, want %v", d, tc.at)
				}
				if closes.Load() != 1 || env.Abandon.Len() != 0 {
					t.Fatalf("conn closed %d times, abandoned %d", closes.Load(), env.Abandon.Len())
				}
			})
		})
	}
}

// TestLastResortNeverClosesTwice_L52: when the goroutine that the
// abandonment adopts is stuck inside the embedder's Close itself, the last
// resort does not call Close again: the conn is closed exactly once, the
// closer stays counted in the abandoned-call pool until that Close
// returns, and then leaves it.
func TestLastResortNeverClosesTwice_L52(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		a, b := net.Pipe()
		defer b.Close()
		release := make(chan struct{})
		hc := &hookConn{Conn: a, onClose: func(nc net.Conn) error {
			<-release
			return nc.Close()
		}}
		c := hConn(env, hc)
		start := time.Now()
		c.Kill(CauseLocalClose, "discarded")
		hWait(t, c)
		if d := time.Since(start); d != env.Timing.AbandonWait {
			t.Fatalf("Done after %v, want AbandonWait", d)
		}
		synctest.Wait()
		if hc.closes.Load() != 1 || env.Abandon.Len() != 1 {
			t.Fatalf("closes %d, abandoned %d: want the one hanging Close, counted", hc.closes.Load(), env.Abandon.Len())
		}
		close(release)
		synctest.Wait()
		if hc.closes.Load() != 1 || env.Abandon.Len() != 0 {
			t.Fatalf("after the Close returned: closes %d, abandoned %d", hc.closes.Load(), env.Abandon.Len())
		}
	})
}
