package l4

import (
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// M4 WP5: the pending-phase race table P1–P10 (M4 design §A6.6, M4-D31).

// TestServerConfirmAfterTargetConnect (P1, M4-D31): the session is
// confirmed only after the target connected, so the dialer's Dial returns
// after the target accepted; Forward then owns the target: an echo
// exchange is intact, and when the client ends the target is closed with
// FINs both ways and no reset.
func TestServerConfirmAfterTargetConnect(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newSrvWorld(t, srvOpts{})
		target := rendrtest.NewTarget(rendrtest.TargetEcho(), 0)
		var dialled, early atomic.Bool
		s := &Server{Dial: func(ctx context.Context, r Request) (net.Conn, error) {
			time.Sleep(time.Second) // a target that takes a second to accept
			c, err := target.Dial(ctx, r.Addr)
			if dialled.Load() {
				early.Store(true)
			}
			return c, err
		}}
		sv := serve(w, s)
		start := time.Now()
		c, err := Dial(context.Background(), w.peer, kitTarget, rendr.DialOptions{})
		dialled.Store(true)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		if el := time.Since(start); el < time.Second || early.Load() {
			t.Fatalf("Dial returned after %v, before the target connected (early %v)", el, early.Load())
		}
		echoRoundTrip(t, c, 256<<10, 1)
		c.Close()
		waitFor(t, time.Minute, "the forward ends", func() bool { return s.Status().Live == 0 && target.Counts().Open == 0 })
		tc := target.Counts()
		if tc.Accepted != 1 || tc.FINIn != 1 || tc.FINOut != 1 || tc.RSTIn != 0 || tc.RSTOut != 0 || tc.BytesIn != 256<<10 {
			t.Fatalf("target %+v", tc)
		}
		if st := s.Status(); st.Confirmed != 1 || st.Rejected != 0 || st.Unconfirmed != 0 || st.Lost != 0 || st.Dialing != 0 || st.Hooks != 0 {
			t.Fatalf("status %+v", st)
		}
		if err := sv.stop(t); !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve: %v", err)
		}
		w.shutdown()
	})
}

// TestServerWithdrawCancelsDial_L49 (P2): the dialer cancels its Dial
// after admission while the target dial hangs. The dialer's Dial returns
// ctx.Err() at once; the withdrawal ends the pending context, which ends
// the target dial within 100 ms; no Reject is sent (Lost == 1, R1-25) and
// no target conn is left.
func TestServerWithdrawCancelsDial_L49(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newSrvWorld(t, srvOpts{})
		dial, counts := rendrtest.ScriptedDial(rendrtest.OutcomeHang())
		hl := newHookLog(hookOf(dial))
		s := &Server{Dial: hl.dial}
		sv := serve(w, s)
		ctx, cancel := context.WithCancel(context.Background())
		ch := dialAsync(ctx, w, kitTarget)
		waitFor(t, time.Minute, "the hook is called", func() bool { return counts.Calls() == 1 })
		time.Sleep(100 * time.Millisecond) // the dial is under way
		cancelled := time.Now()
		cancel()
		r := recv(t, ch, time.Minute)
		if !errors.Is(r.err, context.Canceled) || r.c != nil || r.at.Sub(cancelled) > time.Millisecond {
			t.Fatalf("Dial after cancel: %v after %v", r.err, r.at.Sub(cancelled))
		}
		waitFor(t, time.Minute, "the dial ends", func() bool { return s.Status().Dialing == 0 })
		_, _, _, returns := hl.snapshot()
		if len(returns) != 1 || returns[0].Sub(cancelled) > 100*time.Millisecond {
			t.Fatalf("the target dial returned %v after the withdrawal (want ≤ 100 ms)", returns[0].Sub(cancelled))
		}
		if st := s.Status(); st.Lost != 1 || st.Rejected != 0 || st.Confirmed != 0 || st.Unconfirmed != 0 || st.Hooks != 0 {
			t.Fatalf("status %+v", st)
		}
		if n := counts.Unclosed(); n != 0 {
			t.Fatalf("%d target conns left open", n)
		}
		if err := sv.stop(t); !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve: %v", err)
		}
		w.shutdown()
	})
}

// TestServerWithdrawRacesConfirm_L49 (P3, M4-D31, R1-25): the target dial
// succeeds at the instant the dialer withdraws, in both orders. When the
// withdrawal is first, Confirm fails and the target is reset and closed
// exactly once (Unconfirmed == 1); when Confirm is first, the confirmed
// session is reset by the dialer's withdrawal and Forward resets the
// target. Either way the target ends with an RST and nothing stays open.
func TestServerWithdrawRacesConfirm_L49(t *testing.T) {
	type outcome int
	const (
		unconfirmed outcome = 1 << iota
		confirmed
	)
	rows := []struct {
		name string
		// hook is the dial: cancel withdraws the dialer's Dial.
		hook func(ctx context.Context, cancel context.CancelFunc)
		want outcome
	}{
		{"withdrawal first", func(ctx context.Context, cancel context.CancelFunc) {
			cancel()
			<-ctx.Done() // the pending phase ended; the target accepts now
		}, unconfirmed},
		{"same instant", func(ctx context.Context, cancel context.CancelFunc) {
			cancel()
			time.Sleep(kitOneWay) // the withdrawal's RST arrives now
		}, unconfirmed | confirmed},
		{"confirm first", func(ctx context.Context, cancel context.CancelFunc) {
			time.AfterFunc(time.Millisecond, cancel) // before the OPEN_ACK reaches the dialer
		}, confirmed},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newSrvWorld(t, srvOpts{})
				target := rendrtest.NewTarget(rendrtest.TargetEcho(), 0)
				var spies []*spyConn
				var mu sync.Mutex
				dialTarget := spyHook(target, &spies, &mu)
				ctx, cancel := context.WithCancel(context.Background())
				s := &Server{Dial: func(hctx context.Context, r Request) (net.Conn, error) {
					row.hook(hctx, cancel)
					return dialTarget(context.Background(), r)
				}}
				sv := serve(w, s)
				r := recv(t, dialAsync(ctx, w, kitTarget), time.Minute)
				if !errors.Is(r.err, context.Canceled) {
					t.Fatalf("Dial: %v, want the withdrawal", r.err)
				}
				waitFor(t, time.Minute, "the target is released", func() bool {
					st := s.Status()
					return st.Dialing == 0 && st.Live == 0 && st.Confirmed+st.Unconfirmed == 1 && target.Counts().Open == 0
				})
				st := s.Status()
				got := unconfirmed
				if st.Confirmed == 1 {
					got = confirmed
				}
				if got&row.want == 0 {
					t.Fatalf("status %+v: outcome %v, want %v", st, got, row.want)
				}
				if got == unconfirmed && (st.Unconfirmed != 1 || st.Lost != 0 || st.Rejected != 0) {
					t.Fatalf("status %+v", st)
				}
				t.Logf("outcome: confirmed %d, unconfirmed %d", st.Confirmed, st.Unconfirmed)
				mu.Lock()
				defer mu.Unlock()
				if len(spies) != 1 {
					t.Fatalf("%d target conns", len(spies))
				}
				_, linger0, closes, _ := spies[0].snapshot()
				tc := target.Counts()
				if closes != 1 || linger0 == 0 || tc.Accepted != 1 || tc.RSTIn != 1 || tc.Open != 0 {
					t.Fatalf("target conn: %d closes, %d SetLinger(0); target %+v", closes, linger0, tc)
				}
				sv.stop(t)
				w.shutdown()
			})
		})
	}
}

// TestServerDialBoundedByPendingDeadline (P4, M4-D29): a DialTimeout
// beyond the Listener's AcceptTimeout is clamped to the pending deadline
// minus 250 ms, so the dialer gets CodeTimeout before the core's CAPACITY;
// a budget already spent at Accept is answered CodeTimeout without a dial.
func TestServerDialBoundedByPendingDeadline(t *testing.T) {
	t.Run("clamped", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := newSrvWorld(t, srvOpts{acceptTimeout: 2 * time.Second})
			dial, _ := rendrtest.ScriptedDial(rendrtest.OutcomeHang())
			hl := newHookLog(hookOf(dial))
			s := &Server{Dial: hl.dial, DialTimeout: 30 * time.Second}
			sv := serve(w, s)
			start := time.Now()
			r := recv(t, dialAsync(context.Background(), w, kitTarget), time.Minute)
			wantReject(t, r.err, CodeTimeout)
			if el := r.at.Sub(start); el >= 2*time.Second {
				t.Fatalf("refused after %v, not before the AcceptTimeout", el)
			}
			_, _, _, returns := hl.snapshot()
			hl.mu.Lock()
			took := returns[0].Sub(hl.starts[0])
			hl.mu.Unlock()
			if took < 1700*time.Millisecond || took > 1750*time.Millisecond {
				t.Fatalf("the target dial ran %v, want the pending deadline − 250 ms (≈ 1.75 s)", took)
			}
			sv.stop(t)
			w.shutdown()
		})
	})
	t.Run("spent", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := newSrvWorld(t, srvOpts{acceptTimeout: 200 * time.Millisecond})
			dial, counts := rendrtest.ScriptedDial(rendrtest.OutcomeHang())
			s := &Server{Dial: hookOf(dial)}
			sv := serve(w, s)
			r := recv(t, dialAsync(context.Background(), w, kitTarget), time.Minute)
			wantReject(t, r.err, CodeTimeout)
			if n := counts.Calls(); n != 0 {
				t.Fatalf("%d hook calls with the budget spent", n)
			}
			// The Server counts a refusal after sending it (Server.reject), so the
			// dialer can see the refusal before Status counts it.
			waitFor(t, time.Minute, "the Server counts the refusal", func() bool { return s.Status().ByCode[CodeTimeout] != 0 })
			if st := s.Status(); st.Hooks != 0 || st.ByCode[CodeTimeout] != 1 {
				t.Fatalf("status %+v", st)
			}
			sv.stop(t)
			w.shutdown()
		})
	})
}

// TestServerLateDialAfterAcceptTimeout_L51 (P5, M4-D30): a hook that
// ignores ctx and returns a conn long after its budget. The handler
// answers CodeTimeout at the budget + 1 s, or, when the AcceptTimeout came
// first, finds the session refused (Lost, no Reject); Confirm is never
// called; the late conn is closed exactly once and Abandoned returns to 0.
func TestServerLateDialAfterAcceptTimeout_L51(t *testing.T) {
	rows := []struct {
		name          string
		acceptTimeout time.Duration
		dialTimeout   time.Duration
		answeredAt    time.Duration // when the handler gives up (budget + 1 s)
		refused       bool          // the AcceptTimeout answers before the handler
	}{
		{"answered CodeTimeout", 0, time.Second, 2 * time.Second, false},
		{"AcceptTimeout first", time.Second, 30 * time.Second, 1750 * time.Millisecond, true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newSrvWorld(t, srvOpts{acceptTimeout: row.acceptTimeout})
				dial, counts := rendrtest.ScriptedDial(rendrtest.OutcomeLate(5 * time.Second))
				s := &Server{Dial: hookOf(dial), DialTimeout: row.dialTimeout}
				sv := serve(w, s)
				start := time.Now()
				r := recv(t, dialAsync(context.Background(), w, kitTarget), time.Minute)
				if row.refused {
					if !errors.Is(r.err, rendr.ErrCapacity) {
						t.Fatalf("Dial: %v, want ErrCapacity (AcceptTimeout)", r.err)
					}
				} else {
					wantReject(t, r.err, CodeTimeout)
					if el := r.at.Sub(start); el < row.answeredAt || el > row.answeredAt+50*time.Millisecond {
						t.Fatalf("refused after %v, want the budget + 1 s (%v)", el, row.answeredAt)
					}
				}
				waitFor(t, time.Minute, "the handler gives up", func() bool { return s.Status().Dialing == 0 })
				if el := time.Since(start); el < row.answeredAt || el > row.answeredAt+50*time.Millisecond {
					t.Fatalf("the handler gave up after %v, want %v", el, row.answeredAt)
				}
				if st := s.Status(); st.Abandoned != 1 || st.Hooks != 1 || st.Confirmed+st.Unconfirmed != 0 {
					t.Fatalf("status while abandoned %+v", st)
				}
				waitFor(t, time.Minute, "the late call returns", func() bool { return s.Status().Hooks == 0 })
				st := s.Status()
				if st.Abandoned != 0 || st.Confirmed+st.Unconfirmed != 0 || counts.Unclosed() != 0 || counts.Calls() != 1 {
					t.Fatalf("status %+v; %d late conns open", st, counts.Unclosed())
				}
				if row.refused && (st.Lost != 1 || st.Rejected != 0) || !row.refused && (st.Lost != 0 || st.ByCode[CodeTimeout] != 1) {
					t.Fatalf("status %+v", st)
				}
				sv.stop(t)
				w.shutdown()
			})
		})
	}
}

// TestServerListenerCloseDuringDial_L50 (P6): Listener.Close during the
// target dial refuses the pending session (the dialer gets ErrCapacity),
// which ends the dial at once through the pending context; the handler
// sends nothing (Lost) and Serve returns net.ErrClosed.
func TestServerListenerCloseDuringDial_L50(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newSrvWorld(t, srvOpts{})
		dial, counts := rendrtest.ScriptedDial(rendrtest.OutcomeHang())
		hl := newHookLog(hookOf(dial))
		s := &Server{Dial: hl.dial}
		sv := serve(w, s)
		ch := dialAsync(context.Background(), w, kitTarget)
		waitFor(t, time.Minute, "the hook is called", func() bool { return counts.Calls() == 1 })
		closed := time.Now()
		w.ln.Close()
		r := recv(t, ch, time.Minute)
		if !errors.Is(r.err, rendr.ErrCapacity) {
			t.Fatalf("Dial: %v, want ErrCapacity", r.err)
		}
		if err := sv.wait(t, time.Minute); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Serve: %v, want net.ErrClosed", err)
		}
		_, _, _, returns := hl.snapshot()
		if len(returns) != 1 || returns[0].Sub(closed) > 100*time.Millisecond {
			t.Fatalf("the target dial returned %v after Listener.Close", returns[0].Sub(closed))
		}
		if st := s.Status(); st.Lost != 1 || st.Rejected != 0 || st.Dialing != 0 || st.Hooks != 0 {
			t.Fatalf("status %+v", st)
		}
		w.shutdown()
	})
}

// TestServerRuntimeCloseDuringDial (P7): Runtime.Close during the target
// dial answers the dialer GOING_AWAY (ErrCapacity), ends the dial, and
// every Server goroutine ends (the bubble checks that none is left).
func TestServerRuntimeCloseDuringDial(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newSrvWorld(t, srvOpts{})
		dial, counts := rendrtest.ScriptedDial(rendrtest.OutcomeHang())
		hl := newHookLog(hookOf(dial))
		s := &Server{Dial: hl.dial}
		sv := serve(w, s)
		ch := dialAsync(context.Background(), w, kitTarget)
		waitFor(t, time.Minute, "the hook is called", func() bool { return counts.Calls() == 1 })
		closed := time.Now()
		w.p.Close()
		r := recv(t, ch, time.Minute)
		if !errors.Is(r.err, rendr.ErrCapacity) {
			t.Fatalf("Dial: %v, want ErrCapacity (GOING_AWAY)", r.err)
		}
		if err := sv.wait(t, time.Minute); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Serve: %v, want net.ErrClosed", err)
		}
		_, _, running, returns := hl.snapshot()
		if running != 0 || len(returns) != 1 || returns[0].Sub(closed) > 100*time.Millisecond {
			t.Fatalf("the target dial: %d running, returned %v after Runtime.Close", running, returns)
		}
		if st := s.Status(); st.Lost+st.Rejected != 1 || st.Dialing != 0 || st.Hooks != 0 || st.Live != 0 {
			t.Fatalf("status %+v", st)
		}
		w.shutdown()
	})
}

// TestServerCtxCancelDuringDial (P8, M4-D34, R1-6): Serve's ctx cancelled
// during the target dial cancels the dial at once and rejects the session
// CodeDialFailed — also when the hook then reports a failure classify
// would map elsewhere (a resolver timeout) — and Serve returns
// context.Canceled after its handlers.
func TestServerCtxCancelDuringDial(t *testing.T) {
	rows := []struct {
		name string
		hook func(ctx context.Context, r Request) (net.Conn, error)
	}{
		{"hang", func(ctx context.Context, r Request) (net.Conn, error) {
			<-ctx.Done()
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: ctx.Err()}
		}},
		{"resolver timeout", func(ctx context.Context, r Request) (net.Conn, error) {
			<-ctx.Done()
			return nil, &net.DNSError{Err: "i/o timeout", Name: "target.test", IsTimeout: true}
		}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newSrvWorld(t, srvOpts{})
				hl := newHookLog(row.hook)
				s := &Server{Dial: hl.dial}
				sv := serve(w, s)
				ch := dialAsync(context.Background(), w, kitTarget)
				waitFor(t, time.Minute, "the hook is called", func() bool { c, _, _, _ := hl.snapshot(); return c == 1 })
				time.Sleep(100 * time.Millisecond)
				cancelled := time.Now()
				sv.cancel()
				r := recv(t, ch, time.Minute)
				wantReject(t, r.err, CodeDialFailed)
				if el := r.at.Sub(cancelled); el > 100*time.Millisecond {
					t.Fatalf("refused %v after the cancel", el)
				}
				if err := sv.wait(t, time.Minute); !errors.Is(err, context.Canceled) {
					t.Fatalf("Serve: %v", err)
				}
				if st := s.Status(); st.Rejected != 1 || st.ByCode[CodeDialFailed] != 1 || st.Lost != 0 || st.Dialing != 0 || st.Hooks != 0 {
					t.Fatalf("status %+v", st)
				}
				w.shutdown()
			})
		})
	}
}

// TestServerRuntimeCloseReleasesTargets_L52 (P9): Runtime.Close with 100
// live forwards ends every session and resets every target within 1 s;
// Serve returns and no goroutine is left (the bubble checks).
func TestServerRuntimeCloseReleasesTargets_L52(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const n = 100
		w := newSrvWorld(t, srvOpts{worldOpts: worldOpts{n: n}})
		target := rendrtest.NewTarget(rendrtest.TargetEcho(), 0)
		s := &Server{Dial: hookOf(target.Dial)}
		sv := serve(w, s)
		conns := make([]*rendr.Conn, n)
		var wg sync.WaitGroup
		for i := range conns {
			wg.Go(func() {
				c, err := Dial(context.Background(), w.peer, kitTarget, rendr.DialOptions{})
				if err != nil {
					t.Errorf("Dial %d: %v", i, err)
					return
				}
				conns[i] = c
				if _, err := pingErr(c, 1024); err != nil {
					t.Errorf("ping %d: %v", i, err)
				}
			})
		}
		wg.Wait()
		if t.Failed() {
			t.FailNow()
		}
		if st, tc := s.Status(), target.Counts(); st.Live != n || tc.Open != n {
			t.Fatalf("stimulus: %d live forwards, %d targets open", st.Live, tc.Open)
		}
		closed := time.Now()
		w.p.Close()
		waitFor(t, time.Second, "every target is released", func() bool { return target.Counts().Open == 0 })
		if err := sv.wait(t, time.Second); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Serve: %v", err)
		}
		t.Logf("targets released %v after Runtime.Close", time.Since(closed))
		tc := target.Counts()
		if tc.RSTIn != n || tc.FINIn != 0 {
			t.Fatalf("targets: %d reset, %d FINs (want %d resets)", tc.RSTIn, tc.FINIn, n)
		}
		for i, c := range conns {
			waitDone(t, c, time.Minute)
			if err := c.Status().Err; err == nil || errors.Is(err, io.EOF) {
				t.Fatalf("dialer session %d ended %v, want an error", i, err)
			}
		}
		if st := s.Status(); st.Live != 0 || st.Confirmed != n {
			t.Fatalf("status %+v", st)
		}
		w.shutdown()
	})
}

// p10Rate is the links' rate in P10: the OPEN storm and its answers share
// the bottleneck with the echo session, so a ping sent during the storm
// queues behind its frames, while the storm's bytes still clear well
// within one baseline round trip (2 × kitOneWay) when nothing stalls.
const p10Rate = 32 << 20

// pingSample is one ping of P10's loaded phase.
type pingSample struct {
	at  time.Time // when the ping was written
	rtt time.Duration
}

// TestServerDialConcurrencyBounded_L48 (P10, M4-D28): 1,000 OPENs at once
// with a hanging hook and AcceptBacklog 128: at most 128 hook calls run at
// once, the rest are answered CAPACITY at once, and an established L4
// echo through the same Server and the same rate-limited link keeps its
// round trip within twice its baseline while the storm lasts: P99 over
// every ping from the storm's start to its last answer, and every ping
// written before the last CAPACITY answer. The pings run back to back
// behind the storm's queued OPENs, and at least one of the burst's pings
// must show queueing behind the storm's frames (the stimulus proof). The bubble has
// no CPU contention: this row proves protocol-level head-of-line isolation
// (a full backlog or the Server's dials never hold the shared carrier).
func TestServerDialConcurrencyBounded_L48(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const n, backlog = 1000, 128
		w := newSrvWorld(t, srvOpts{worldOpts: worldOpts{n: n, rate: p10Rate}, backlog: backlog})
		echo := rendrtest.NewTarget(rendrtest.TargetEcho(), 0)
		hang, _ := rendrtest.ScriptedDial(rendrtest.OutcomeHang())
		hl := newHookLog(func(ctx context.Context, r Request) (net.Conn, error) {
			if r.Addr == "echo.test:7" {
				return echo.Dial(ctx, r.Addr)
			}
			return hang(ctx, r.Addr)
		})
		s := &Server{Dial: hl.dial}
		sv := serve(w, s)
		c, err := Dial(context.Background(), w.peer, "echo.test:7", rendr.DialOptions{})
		if err != nil {
			t.Fatalf("Dial echo: %v", err)
		}
		const pings = 200
		rtts := make([]time.Duration, pings)
		for i := range rtts {
			rtts[i] = ping(t, c, 512)
			time.Sleep(10 * time.Millisecond)
		}
		base := p99(rtts)

		// The storm's OPENs are queued at the bottleneck first (every Dial
		// is blocked waiting for its answer), then the pinger runs back to
		// back behind them until the storm's last answer.
		start := time.Now()
		results := make(chan dialRes, n)
		for range n {
			go func() {
				c, err := Dial(context.Background(), w.peer, kitTarget, rendr.DialOptions{})
				results <- dialRes{c, err, time.Now()}
			}()
		}
		synctest.Wait()
		stopPing := make(chan struct{})
		pinged := make(chan []pingSample, 1)
		go func() {
			var ss []pingSample
			defer func() { pinged <- ss }()
			for {
				select {
				case <-stopPing:
					return
				default:
				}
				at := time.Now()
				d, err := pingErr(c, 512)
				if err != nil {
					t.Errorf("ping under the storm: %v", err)
					return
				}
				ss = append(ss, pingSample{at, d})
			}
		}()
		capacity, timeouts := 0, 0
		var lastCapacity time.Time
		for range n {
			r := <-results
			switch {
			case errors.Is(r.err, rendr.ErrCapacity):
				capacity++
				if r.at.After(lastCapacity) {
					lastCapacity = r.at
				}
			case r.err != nil:
				if code, ok := CodeOf(r.err); ok && code == CodeTimeout {
					timeouts++
					continue
				}
				t.Fatalf("Dial: %v", r.err)
			default:
				t.Fatalf("a Dial to a hanging target succeeded")
			}
		}
		end := time.Now()
		close(stopPing)
		samples := <-pinged
		var loaded, burst []time.Duration
		for _, p := range samples {
			if p.at.Before(end) {
				loaded = append(loaded, p.rtt)
			}
			if p.at.Before(lastCapacity) {
				burst = append(burst, p.rtt)
			}
		}
		calls, peak, _, _ := hl.snapshot()
		st := w.links[0].Stats()
		t.Logf("%d CAPACITY (last %v), %d CodeTimeout (last %v); %d hook calls, peak %d; link bytes %d; P99 %v → %v over %d pings; burst %d pings, max %v",
			capacity, lastCapacity.Sub(start), timeouts, end.Sub(start), calls, peak, st.Throttled, base, p99(loaded), len(loaded), len(burst), slices.Max(append([]time.Duration{0}, burst...)))
		if peak > backlog { // the echo session's call ended before the storm
			t.Fatalf("%d hook calls at once, want ≤ %d", peak, backlog)
		}
		if timeouts == 0 || capacity == 0 || capacity+timeouts != n {
			t.Fatalf("stimulus: %d CAPACITY, %d CodeTimeout of %d", capacity, timeouts, n)
		}
		if el := lastCapacity.Sub(start); el > time.Second {
			t.Fatalf("a CAPACITY answer took %v, want at once", el)
		}
		if len(burst) < 3 || len(loaded) < 100 {
			t.Fatalf("stimulus: %d pings during the CAPACITY burst (want ≥ 3), %d under the storm (want ≥ 100)", len(burst), len(loaded))
		}
		if slices.Max(burst) <= base {
			t.Fatalf("stimulus: no burst ping queued behind the storm (max %v, baseline %v)", slices.Max(burst), base)
		}
		if l := p99(loaded); l > 2*base {
			t.Fatalf("echo P99 %v under the OPEN storm, baseline %v", l, base)
		}
		if m := slices.Max(burst); m > 2*base {
			t.Fatalf("an echo ping took %v during the CAPACITY burst, baseline P99 %v", m, base)
		}
		echoRoundTrip(t, c, 64<<10, 9)
		c.Close()
		sv.stop(t)
		w.shutdown()
	})
}

// p99 returns the 99th percentile of rtts (it sorts them).
func p99(rtts []time.Duration) time.Duration {
	if len(rtts) == 0 {
		return 0
	}
	slices.Sort(rtts)
	return rtts[max(len(rtts)*99/100-1, 0)]
}
