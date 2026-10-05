package rendr

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

	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// trackedConns wraps every conn a factory returns and counts their Close
// calls (L49, L51: every carrier is closed exactly once). block, when set,
// makes each Close block until release is closed.
type trackedConns struct {
	mu      sync.Mutex
	conns   []*trackedConn
	block   bool
	release chan struct{}
}

type trackedConn struct {
	net.Conn
	tc     *trackedConns
	closes atomic.Int32
}

func (c *trackedConn) Close() error {
	c.closes.Add(1)
	err := c.Conn.Close()
	if c.tc.block {
		<-c.tc.release
	}
	return err
}

func newTrackedConns(block bool) *trackedConns {
	return &trackedConns{block: block, release: make(chan struct{})}
}

// wrap is a factory over dial whose conns are tracked.
func (tc *trackedConns) wrap(name string, dial func(context.Context) (net.Conn, error)) StreamCarrier {
	return StreamCarrier{Name: name, Dial: func(ctx context.Context) (net.Conn, error) {
		c, err := dial(ctx)
		if c == nil {
			return nil, err
		}
		w := &trackedConn{Conn: c, tc: tc}
		tc.mu.Lock()
		tc.conns = append(tc.conns, w)
		tc.mu.Unlock()
		return w, err
	}}
}

// closes returns the Close count of every tracked conn.
func (tc *trackedConns) closes() []int32 {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	out := make([]int32, len(tc.conns))
	for i, c := range tc.conns {
		out[i] = c.closes.Load()
	}
	return out
}

// requireClosedOnce requires at least one tracked conn and exactly one
// Close of each.
func (tc *trackedConns) requireClosedOnce(t testing.TB) {
	t.Helper()
	cs := tc.closes()
	if len(cs) == 0 {
		t.Fatal("no carrier was dialled")
	}
	for i, n := range cs {
		if n != 1 {
			t.Fatalf("carrier %d closed %d times, want 1", i, n)
		}
	}
}

// TestDialCancelSilentPeer_L49: a Dial whose peer never answers returns
// within 200 ms of its context ending (L49: the contract is 100 ms) with
// the context's error — cancellation and deadline alike — while the
// carrier it opened is closed exactly once in the background, and nothing
// is left in the Runtime. Two silent peers: a blackholed link (the bytes
// vanish) and a peer that reads the PREFACE and OPEN but never answers.
func TestDialCancelSilentPeer_L49(t *testing.T) {
	for _, silent := range []string{"blackhole", "reads only"} {
		t.Run(silent, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				rt := wpTestRuntime(t, Config{}, nil)
				var dial func(context.Context) (net.Conn, error)
				var link *rendrtest.Link
				var wg sync.WaitGroup
				if silent == "blackhole" {
					link = rendrtest.NewLink(rendrtest.LinkConfig{Name: "void"})
					link.SetBlackhole(true)
					dial = link.Dial
				} else {
					dial = func(context.Context) (net.Conn, error) {
						a, b := net.Pipe()
						wg.Go(func() {
							io.Copy(io.Discard, b)
							b.Close()
						})
						return a, nil
					}
				}
				tc := newTrackedConns(false)
				p, err := rt.NewPeer(PeerConfig{Carriers: []Carrier{tc.wrap("silent", dial)}})
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				res := e2eDialAsync(ctx, p, DialOptions{})
				time.Sleep(time.Second)
				cancel()
				t0 := time.Now()
				r := <-res
				if r.c != nil || !errors.Is(r.err, context.Canceled) || time.Since(t0) > 200*time.Millisecond {
					t.Fatalf("cancelled Dial = %v, %v after %v", r.c, r.err, time.Since(t0))
				}
				ctx, cancel = context.WithTimeout(context.Background(), 300*time.Millisecond)
				defer cancel()
				r = <-e2eDialAsync(ctx, p, DialOptions{})
				if r.c != nil || !errors.Is(r.err, context.DeadlineExceeded) || r.at > 500*time.Millisecond {
					t.Fatalf("Dial past its deadline = %v, %v after %v", r.c, r.err, r.at)
				}
				// The withdrawal writes RST(withdrawn) after the OPEN, then
				// closes in the L05 order: a drain of what the silent peer
				// sent, bounded by 1 s, then Close.
				time.Sleep(1500 * time.Millisecond)
				synctest.Wait()
				tc.requireClosedOnce(t)
				if units := rt.table.inUse(); units != 0 {
					t.Fatalf("%d MaxSessions units after the cancelled Dials", units)
				}
				rt.Close()
				if link != nil {
					link.Close()
				}
				wg.Wait()
				wpNoState(t, rt)
			})
		})
	}
}

// TestDialCancelAfterAccept_L49: cancelling a Dial whose OPEN the passive
// already admitted (L49). Before the passive application decides, Dial
// returns the context error within 200 ms, the dialer withdraws its OPEN
// (RST(withdrawn)) and the passive learns it within 1 s: Confirm returns
// ErrSessionLost and the session leaves a tombstone, no pending slot.
// Cancelling after Dial returned has no effect on the session. When the
// cancellation races the passive's Confirm, exactly one CAS decides: the
// Dial either returns the session, which then works, or the context error,
// and then the passive end learns the withdrawal within 1 s.
func TestDialCancelAfterAccept_L49(t *testing.T) {
	t.Run("before Confirm", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
			ctx, cancel := context.WithCancel(context.Background())
			res := e2eDialAsync(ctx, e.peer(), DialOptions{})
			pc, err := e.ln.Accept(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			cancel()
			t0 := time.Now()
			if r := <-res; r.c != nil || !errors.Is(r.err, context.Canceled) || time.Since(t0) > 200*time.Millisecond {
				t.Fatalf("Dial = %v, %v after %v", r.c, r.err, time.Since(t0))
			}
			select {
			case <-pc.s.Done(): // the withdrawal reached the passive and ended its session
			case <-time.After(time.Second):
				t.Fatal("the passive did not learn the withdrawal within 1 s")
			}
			if _, err := pc.Confirm(); !errors.Is(err, ErrSessionLost) || time.Since(t0) > time.Second {
				t.Fatalf("Confirm after the withdrawal: %v after %v", err, time.Since(t0))
			}
			synctest.Wait()
			if st := e.p.Status(); st.Sessions != (SessionCounts{Tombstones: 1}) || st.AcceptBacklog[0] != 0 {
				t.Fatalf("passive after the withdrawal: %+v", st)
			}
			e.close()
		})
	})
	t.Run("after Dial returned", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
			ctx, cancel := context.WithCancel(context.Background())
			res := e2eDialAsync(ctx, e.peer(), DialOptions{})
			sc := e2eConfirm(t, e.ln)
			r := <-res
			if r.err != nil {
				t.Fatal(r.err)
			}
			cancel()
			synctest.Wait()
			e2eExchange(t, r.c, sc, 256<<10, 3)
			e2eFinish(t, r.c, sc)
			e.close()
		})
	})
	t.Run("racing Confirm", func(t *testing.T) {
		won, lost := 0, 0
		for i := range 20 {
			synctest.Test(t, func(t *testing.T) {
				e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
				ctx, cancel := context.WithCancel(context.Background())
				res := e2eDialAsync(ctx, e.peer(), DialOptions{})
				pc, err := e.ln.Accept(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				confirmed := make(chan *Conn, 1)
				go func() {
					c, _ := pc.Confirm()
					confirmed <- c
				}()
				if i%2 == 0 {
					synctest.Wait() // let the Confirm reach the actor first in half of the runs
				}
				cancel()
				r := <-res
				sc := <-confirmed
				t0 := time.Now()
				switch {
				case r.err == nil:
					won++
					if sc == nil {
						t.Fatal("Dial succeeded but Confirm failed")
					}
					e2eExchange(t, r.c, sc, 64<<10, uint64(i))
					e2eFinish(t, r.c, sc)
				case !errors.Is(r.err, context.Canceled):
					t.Fatalf("Dial: %v", r.err)
				default:
					lost++
					if sc != nil {
						var ae *AbortError
						if _, err := sc.Read(make([]byte, 1)); !errors.As(err, &ae) || ae.Code != AbortWithdrawn || time.Since(t0) > time.Second {
							t.Fatalf("the passive end of a withdrawn session: %v after %v", err, time.Since(t0))
						}
					}
				}
				synctest.Wait()
				e.close()
			})
		}
		t.Logf("the Dial won %d and the cancellation %d of 20 races", won, lost)
	})
}

// TestDialCancelBlockedClose_L49: a carrier whose Close blocks cannot hold
// a cancelled Dial (L49): Dial returns within 200 ms, the carrier's Close is
// called exactly once on a goroutine of its own, which is counted in
// Status.Abandoned while it is stuck (L52); Runtime.Close stays bounded,
// and when the embedder's Close returns nothing is left.
func TestDialCancelBlockedClose_L49(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := wpTestRuntime(t, Config{}, &testhooks.Overrides{AbandonWait: 500 * time.Millisecond})
		link := rendrtest.NewLink(rendrtest.LinkConfig{Name: "void"})
		link.SetBlackhole(true)
		tc := newTrackedConns(true)
		p, err := rt.NewPeer(PeerConfig{Carriers: []Carrier{tc.wrap("stuck-close", link.Dial)}})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		res := e2eDialAsync(ctx, p, DialOptions{})
		time.Sleep(500 * time.Millisecond)
		cancel()
		t0 := time.Now()
		if r := <-res; r.c != nil || !errors.Is(r.err, context.Canceled) || time.Since(t0) > 200*time.Millisecond {
			t.Fatalf("Dial = %v, %v after %v", r.c, r.err, time.Since(t0))
		}
		// The withdrawal's closer (RST(withdrawn), a drain ≤ 1 s, Close) is
		// counted when it is still running AbandonWait + 3 × 1 s after it
		// started (its write, unblock and drain bounds).
		time.Sleep(4 * time.Second)
		synctest.Wait()
		if cs := tc.closes(); len(cs) != 1 || cs[0] != 1 {
			t.Fatalf("Close calls %v, want exactly one on the one carrier", cs)
		}
		if n := rt.Status().Abandoned; n != 1 {
			t.Fatalf("abandoned %d, want the stuck Close", n)
		}
		t0 = time.Now()
		rt.Close()
		if el := time.Since(t0); el > 2500*time.Millisecond {
			t.Fatalf("Runtime.Close took %v", el)
		}
		close(tc.release)
		synctest.Wait()
		if st := rt.Status(); st.Abandoned != 0 {
			t.Fatalf("abandoned %d after the Close returned", st.Abandoned)
		}
		tc.requireClosedOnce(t)
		link.Close()
		wpNoState(t, rt)
	})
}

// TestTerminalOutcomeWithdrawsParkedOpens_L49: every terminal outcome of
// the opening phase withdraws the OPENs that may be parked on the passive
// (design §6.6 C25), so a pending session there is never confirmed as an
// orphan: the passive learns the withdrawal, Confirm returns
// ErrSessionLost and the session leaves only a tombstone. Two terminal
// outcomes: ErrNoPath at NoPathGrace while the OPEN waits for the
// application, and ErrVersion from another factory while the first
// factory's OPEN is parked.
func TestTerminalOutcomeWithdrawsParkedOpens_L49(t *testing.T) {
	t.Run("ErrNoPath at grace", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ov := &testhooks.Overrides{NoPathGrace: 2 * time.Second}
			e := e2eNew(t, Config{}, Config{}, ov, ListenConfig{}, "a")
			res := e2eDialAsync(context.Background(), e.peer(), DialOptions{})
			pc, err := e.ln.Accept(context.Background()) // the application takes it but does not decide
			if err != nil {
				t.Fatal(err)
			}
			r := <-res
			if r.c != nil || !errors.Is(r.err, ErrNoPath) || r.at < 2*time.Second || r.at > 2200*time.Millisecond {
				t.Fatalf("Dial = %v, %v after %v; want ErrNoPath at the 2 s grace", r.c, r.err, r.at)
			}
			synctest.Wait()
			if _, err := pc.Confirm(); !errors.Is(err, ErrSessionLost) {
				t.Fatalf("Confirm of the parked OPEN: %v", err)
			}
			if st := e.p.Status(); st.Sessions != (SessionCounts{Tombstones: 1}) || st.AcceptBacklog[0] != 0 {
				t.Fatalf("passive %+v", st)
			}
			e.close()
		})
	})
	t.Run("ErrVersion from another factory", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ov := &testhooks.Overrides{JoinStagger: 200 * time.Millisecond}
			e := e2eNew(t, Config{}, Config{}, ov, ListenConfig{}, "a")
			e.links[0].SetDelay(time.Millisecond, 0)
			old := &scriptedPassive{t: t, answer: func(p wire.Preface, _ wire.Frame) []byte {
				return prefaceAck(p, wire.PrefaceVersion, wpInst(0x01), nil)
			}}
			peer, err := e.d.NewPeer(PeerConfig{Carriers: []Carrier{e2eCarrier(e.links[0]), old.carrier("old")}})
			if err != nil {
				t.Fatal(err)
			}
			res := e2eDialAsync(context.Background(), peer, DialOptions{})
			pc, err := e.ln.Accept(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			r := <-res
			if r.c != nil || !errors.Is(r.err, ErrVersion) {
				t.Fatalf("Dial = %v, %v; want ErrVersion", r.c, r.err)
			}
			time.Sleep(10 * time.Millisecond) // the RST(withdrawn) crosses the 1 ms link
			synctest.Wait()
			if _, err := pc.Confirm(); !errors.Is(err, ErrSessionLost) {
				t.Fatalf("Confirm of the parked OPEN: %v", err)
			}
			if st := e.p.Status(); st.Sessions.Tombstones != 1 || st.Sessions.Pending != 0 || st.AcceptBacklog[0] != 0 {
				t.Fatalf("passive %+v", st)
			}
			e.close()
			old.wg.Wait()
		})
	})
}
