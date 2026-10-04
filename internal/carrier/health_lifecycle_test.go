package carrier

import (
	"context"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// prGoroutines counts the goroutines other than the caller whose stack
// contains frame (after synctest.Wait, exiting goroutines are gone).
func prGoroutines(frame string) int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	count := 0
	for i, st := range strings.Split(string(buf), "\n\n") {
		if i > 0 && strings.Contains(st, frame) { // the caller's own stack comes first
			count++
		}
	}
	return count
}

// TestHealthWaitFirstColdStartOnly (D30, plan §3.9): at a cold start
// WaitFirst returns once every factory has a sample or a failure, never
// later than DialWait after probing started, earlier when ctx ends or the
// Health closes; in steady state (DialWait passed since the start) it
// returns at once even while a factory has no evidence at all.
func TestHealthWaitFirstColdStartOnly(t *testing.T) {
	cases := []struct {
		name     string
		setup    func(r *prRig)
		want     time.Duration
		complete bool // every factory has evidence (a sample or a mark) when WaitFirst returns
	}{
		// Establishment takes one 20 ms RTT and the first PING another.
		{"BothSampled", nil, 40 * time.Millisecond, true},
		{"FailureCounts", func(r *prRig) { r.links[1].SetRefuse(true) }, 40 * time.Millisecond, true},
		{"HangingDialBoundedByDialWait", func(r *prRig) { r.links[1].SetDial(rendrtest.DialHang) }, 800 * time.Millisecond, false},
		{"SlowPathBoundedByDialWait", func(r *prRig) { r.links[1].SetDelay(500*time.Millisecond, 0) }, 800 * time.Millisecond, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := newPrRig(t, 2, nil)
				if tc.setup != nil {
					tc.setup(r)
				}
				r.h.Use()
				r.h.WaitFirst(context.Background())
				if got := r.since(); got != tc.want {
					t.Fatalf("cold start waited %v, want %v", got, tc.want)
				}
				// The Dial that WaitFirst releases ranks with the evidence
				// that released it: it is already in the snapshot.
				s := r.h.Snapshot()
				for i := range s.Sum {
					known := s.Evidence(i, time.Now()).State != sched.EvUnknown || s.Failed[i]
					if tc.complete && !known {
						t.Fatalf("WaitFirst returned before factory %d's evidence was published: %+v", i, s.Info[i])
					}
				}
				r.until(5 * time.Second)
				r.links[1].SetDial(rendrtest.DialHang) // factory 1 may stay without evidence for good
				r.h.Use()
				t0 := time.Now()
				r.h.WaitFirst(context.Background())
				if d := time.Since(t0); d != 0 {
					t.Fatalf("steady-state WaitFirst waited %v", d)
				}
			})
		})
	}
	t.Run("ContextEnds", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := newPrRig(t, 2, nil)
			r.links[1].SetDial(rendrtest.DialHang)
			r.h.Use()
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			r.h.WaitFirst(ctx)
			if got := r.since(); got != 300*time.Millisecond {
				t.Fatalf("WaitFirst returned after %v, want the context's 300ms", got)
			}
		})
	})
	t.Run("CloseReleases", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := newPrRig(t, 2, nil)
			r.links[1].SetDial(rendrtest.DialHang)
			r.h.Use()
			go func() {
				time.Sleep(200 * time.Millisecond)
				r.h.Close()
			}()
			r.h.WaitFirst(context.Background())
			if got := r.since(); got != 200*time.Millisecond {
				t.Fatalf("WaitFirst returned after %v, want Close at 200ms", got)
			}
			r.h.WaitFirst(context.Background()) // closed: at once
			if got := r.since(); got != 200*time.Millisecond {
				t.Fatalf("WaitFirst after Close waited until %v", got)
			}
		})
	})
}

// TestHealthIdleStopAndRestart_L52 (design §3.1, §7.8): probing stops IdleStop
// after the last Use while no session holds the Peer — its probe carriers
// retire with CLOSE on both ends and its goroutine exits, and nothing is
// dialled while idle; the next Use restarts it as a cold start (WaitFirst
// waits for first samples again); every later Use moves the idle stop; a
// Hold starts probing when it is stopped and keeps it running past
// IdleStop, which then counts from the release.
func TestHealthIdleStopAndRestart_L52(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newPrRig(t, 2, nil)
		dials := func() int64 { return r.links[0].Stats().Dials + r.links[1].Stats().Dials }
		probing := func(at time.Duration, want bool) {
			t.Helper()
			r.until(at)
			if got := r.h.Snapshot().Probing; got != want {
				t.Fatalf("at %v: probing %v, want %v", at, got, want)
			}
		}
		r.h.Use()
		r.until(5*time.Minute - time.Second)
		p0, p1 := r.probe(0), r.probe(1)
		if s := r.h.Snapshot(); !s.Probing || p0 == nil || p1 == nil || s.Info[0].Samples < 140 {
			t.Fatalf("before IdleStop: probing %v, info %+v", s.Probing, s.Info[0])
		}
		r.until(5*time.Minute + 100*time.Millisecond)
		s := r.h.Snapshot()
		if s.Probing || s.Info[0].ProbeCarrier != 0 || s.Info[1].ProbeCarrier != 0 {
			t.Fatalf("after IdleStop: probing %v, info %+v %+v", s.Probing, s.Info[0], s.Info[1])
		}
		for i, c := range []*Conn{p0, p1} {
			pas := r.pas.on(i)
			if hCause(c) != CauseRetired || len(pas) != 1 || hCause(pas[0]) != CauseRetired {
				t.Fatalf("path %d: probe ended %v, passive %v", i, hCause(c), hCause(pas[0]))
			}
		}
		if n := prGoroutines("(*healthRun)"); n != 0 {
			t.Fatalf("%d health goroutines after the idle stop", n)
		}
		r.until(6 * time.Minute)
		if d := dials(); d != 2 {
			t.Fatalf("%d dials, want 2: nothing is dialled while idle", d)
		}

		// The next Use is a cold start again.
		r.h.Use()
		t0 := time.Now()
		r.h.WaitFirst(context.Background())
		if d := time.Since(t0); d != 40*time.Millisecond {
			t.Fatalf("WaitFirst after the restart waited %v, want 40ms", d)
		}
		if s = r.h.Snapshot(); !s.Probing || s.Info[0].Attempts != 2 || s.Sum[0].N != 1 {
			t.Fatalf("after the restart: probing %v, info %+v, summary %+v", s.Probing, s.Info[0], s.Sum[0])
		}

		// Later Uses move the idle stop: probing runs until IdleStop after
		// the last one (12 min), without a new run or dial.
		probing(9*time.Minute, true)
		r.h.Use()
		probing(12*time.Minute, true)
		r.h.Use()
		probing(17*time.Minute-time.Second, true)
		if d := dials(); d != 4 {
			t.Fatalf("%d dials, want 4: a Use during a run starts nothing", d)
		}
		probing(17*time.Minute+100*time.Millisecond, false)

		// A Hold starts probing when it is stopped and keeps it running
		// past IdleStop; IdleStop then counts from the release.
		r.until(18 * time.Minute)
		release := r.h.Hold()
		r.until(18*time.Minute + 100*time.Millisecond)
		if s = r.h.Snapshot(); !s.Probing || s.Info[0].Attempts != 3 || s.Info[0].ProbeCarrier == 0 || s.Info[1].ProbeCarrier == 0 {
			t.Fatalf("Hold did not start probing: probing %v, info %+v %+v", s.Probing, s.Info[0], s.Info[1])
		}
		probing(30*time.Minute, true)
		release()
		release() // idempotent
		probing(35*time.Minute-time.Second, true)
		probing(35*time.Minute+100*time.Millisecond, false)
		r.h.mu.Lock()
		holds, runs := r.h.holds, len(r.h.runs)
		r.h.mu.Unlock()
		if holds != 0 || runs != 0 || dials() != 6 {
			t.Fatalf("holds %d, runs %d, dials %d after the last stop", holds, runs, dials())
		}
	})
}

// TestPeerCloseJoinsProbes (M1a carried issue, design §11.5, §3.1, §6.8):
// Close stops probing and joins every goroutine it started before it
// returns — promptly when the paths cooperate (one CLOSE exchange), and
// within the bounds when they do not: a factory that ignores its context
// and a probe carrier whose writes ignore deadlines and Close are
// abandoned (counted in Env.Abandon until they return), the latter after
// the kill bound for an unwritten CLOSE. A probe dial whose result arrives
// while the run winds down never leaves its carrier behind.
func TestPeerCloseJoinsProbes(t *testing.T) {
	t.Run("Cooperative_L52", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := newPrRig(t, 3, nil)
			r.h.Use()
			r.until(5 * time.Second)
			probes := []*Conn{r.probe(0), r.probe(1), r.probe(2)}
			dials := r.links[0].Stats().Dials + r.links[1].Stats().Dials + r.links[2].Stats().Dials
			t0 := time.Now()
			r.h.Close()
			if d := time.Since(t0); d > 40*time.Millisecond {
				t.Fatalf("Close took %v with cooperative paths (one 20 ms CLOSE exchange)", d)
			}
			for i, c := range probes {
				select {
				case <-c.Done():
				default:
					t.Fatalf("probe %d not joined when Close returned", i)
				}
				if hCause(c) != CauseRetired {
					t.Fatalf("probe %d ended %v, want retired (CLOSE)", i, hCause(c))
				}
			}
			synctest.Wait()
			if n := prGoroutines("internal/carrier.(*"); n != 0 {
				t.Fatalf("%d carrier or health goroutines outlive Close", n)
			}
			for i := range probes {
				if pas := r.pas.on(i); hCause(pas[0]) != CauseRetired {
					t.Fatalf("passive carrier %d ended %v, want retired", i, hCause(pas[0]))
				}
			}
			s := r.h.Snapshot()
			if s.Probing || s.Info[0].ProbeCarrier != 0 || r.env.Abandon.Len() != 0 {
				t.Fatalf("after Close: probing %v, info %+v, abandoned %d", s.Probing, s.Info[0], r.env.Abandon.Len())
			}
			// A closed Health starts nothing; Close is idempotent.
			r.h.Use()
			r.h.Hold()()
			r.h.WaitFirst(context.Background())
			t1 := time.Now()
			r.h.Close()
			if d := time.Since(t1); d != 0 {
				t.Fatalf("second Close took %v", d)
			}
			r.until(10 * time.Second)
			if r.h.Snapshot().Probing {
				t.Fatal("probing restarted after Close")
			}
			if d := r.links[0].Stats().Dials + r.links[1].Stats().Dials + r.links[2].Stats().Dials; d != dials {
				t.Fatalf("dials %d → %d after Close", dials, d)
			}
		})
	})
	t.Run("StuckPaths_L20_L52", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := newPrRig(t, 3, nil)
			// Path 1's factory hangs and ignores its context; path 2's probe
			// carrier gets every write hard-blocked after its establishment.
			r.links[1].SetDial(rendrtest.DialHangForever)
			r.h.Use()
			r.until(time.Second)
			ok, stuck := r.probe(0), r.probe(2)
			r.links[2].BlockWrites(rendrtest.Up, rendrtest.BlockHard)
			r.until(2500 * time.Millisecond) // path 2's PING write of 2.02 s is stuck
			if !stuck.WriteBlocked() || r.links[2].Stats().Probe.WritesBlocked != 1 || r.links[1].Stats().Dials != 1 || r.links[1].Stats().DialFailures != 0 {
				t.Fatalf("stimulus: blocked %v, path 2 %+v, path 1 %+v", stuck.WriteBlocked(), r.links[2].Stats().Probe, r.links[1].Stats())
			}
			t0 := time.Now()
			r.h.Close()
			// Bound: path 2's CLOSE stays unwritten, so it is killed after
			// min(1 s, DeadMax); its stuck writer is abandoned AbandonWait
			// later. The cancelled attempt of path 1 returns at once.
			if d := time.Since(t0); d != 2*time.Second {
				t.Fatalf("Close took %v, want the kill bound plus AbandonWait (2s)", d)
			}
			if hCause(ok) != CauseRetired || hCause(stuck) != CauseLocalClose {
				t.Fatalf("probe causes: %v, %v", hCause(ok), hCause(stuck))
			}
			if n := r.env.Abandon.Len(); n != 2 {
				t.Fatalf("abandoned %d, want 2 (path 1's factory call, path 2's writer)", n)
			}
			synctest.Wait()
			if n := prGoroutines("(*healthRun)"); n != 0 {
				t.Fatalf("%d health goroutines outlive Close", n)
			}
			r.links[1].Release()
			r.links[2].Release()
			synctest.Wait()
			if n := r.env.Abandon.Len(); n != 0 {
				t.Fatalf("abandoned %d after the embedder calls returned", n)
			}
		})
	})
	t.Run("SilentPeer_L52", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := newPrRig(t, 2, nil)
			r.h.Use()
			r.until(5 * time.Second)
			silent := r.probe(1)
			r.links[1].SetStall(true) // our CLOSE is written but never answered
			t0 := time.Now()
			r.h.Close()
			// The retirement ends at the drain bound after our CLOSE:
			// min(2·srtt + 100 ms, 1 s) = 140 ms with a 20 ms RTT.
			if d := time.Since(t0); d != 140*time.Millisecond {
				t.Fatalf("Close took %v, want the 140ms drain bound", d)
			}
			if hCause(silent) != CauseRetired || !silent.CloseSent() || r.links[1].Stats().Probe.Held == 0 {
				t.Fatalf("silent peer: probe ended %v, CLOSE sent %v, link %+v", hCause(silent), silent.CloseSent(), r.links[1].Stats().Probe)
			}
			r.links[1].SetStall(false)
		})
	})
	t.Run("StuckAttempt_L52", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := newPrRig(t, 2, nil)
			// Path 1's attempt blocks in its hello write, which ignores
			// deadlines and Close: after the cancellation that Write stays
			// inside embedder code.
			r.links[1].BlockWrites(rendrtest.Up, rendrtest.BlockHard)
			r.h.Use()
			r.until(time.Second)
			r.h.mu.Lock()
			a := r.h.run.slots[1].att
			r.h.mu.Unlock()
			if st := r.links[1].Stats().All; st.WritesBlocked != 1 || a == nil || r.h.Snapshot().Info[1].ProbeCarrier != 0 {
				t.Fatalf("stimulus: %+v", st)
			}
			t0 := time.Now()
			r.h.Close()
			d := time.Since(t0)
			// Exactly the one goroutine inside the Write is counted, never
			// twice. Either Establish writes the hello on a helper goroutine
			// (design §0.8 V1): it abandons that writer AbandonWait after the
			// cancellation and returns, and Close joins the attempt. Or the
			// attempt's own goroutine is the writer: the wind-down abandons
			// the attempt at its bound, 2·AbandonWait.
			if n := r.env.Abandon.Len(); n != 1 {
				t.Fatalf("abandoned %d, want the one stuck Write", n)
			}
			switch st := a.state.Load(); {
			case st == attDone && d == time.Second:
			case st == attAbandoned && d == 2*time.Second:
			default:
				t.Fatalf("Close took %v with the attempt in state %d: want 1s with the attempt joined, or 2s with it abandoned", d, st)
			}
			r.links[1].Release()
			synctest.Wait()
			if n := r.env.Abandon.Len(); n != 0 {
				t.Fatalf("abandoned %d after the write returned", n)
			}
			if n := prGoroutines("(*healthRun)"); n != 0 {
				t.Fatalf("%d health goroutines left after the stuck attempt returned", n)
			}
		})
	})
	t.Run("ConcurrentClose_L52", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := newPrRig(t, 2, nil)
			r.h.Use()
			r.until(time.Second)
			r.links[1].BlockWrites(rendrtest.Up, rendrtest.BlockHard)
			r.until(2500 * time.Millisecond)
			var wg sync.WaitGroup
			ends := make([]time.Duration, 3)
			for k := range ends {
				wg.Add(1)
				go func() {
					defer wg.Done()
					r.h.Close()
					ends[k] = r.since()
				}()
			}
			wg.Wait()
			for k, e := range ends {
				if e != 4500*time.Millisecond {
					t.Fatalf("Close %d returned at %v, want 4.5s (every caller waits for the joins)", k, e)
				}
			}
			r.links[1].Release()
		})
	})
	// Late attempt results: path 1's first attempt completes its handshake
	// at 20 ms and is held inside Establish (prGate) until the test lets it
	// return its carrier.
	gated := func(t *testing.T) (*prRig, *prGate, *probeAttempt) {
		t.Helper()
		gate := newPrGate()
		r := newPrRigDial(t, 2, nil, func(i int, l *rendrtest.Link) func(context.Context) (net.Conn, error) {
			if i == 1 {
				return gate.dial(l)
			}
			return l.Dial
		})
		r.h.Use()
		r.until(time.Second)
		r.h.mu.Lock()
		a := r.h.run.slots[1].att
		r.h.mu.Unlock()
		if !gate.held() || a == nil || r.probe(1) != nil || r.probe(0) == nil || len(r.pas.on(1)) != 1 {
			t.Fatalf("stimulus: held %v, attempt %v, probes %v %v", gate.held(), a, r.probe(0), r.probe(1))
		}
		return r, gate, a
	}
	// settled checks that nothing the run started outlives Close: the
	// attempt's goroutine, the late carrier (its CarrierID is released when
	// its Done closes) and its passive end (EOF once the dialer closed it).
	settled := func(t *testing.T, r *prRig, a *probeAttempt) {
		t.Helper()
		select {
		case <-a.done:
		default:
			t.Fatal("the attempt's goroutine outlives Close")
		}
		if n, ab := r.env.IDs.inUse(), r.env.Abandon.Len(); n != 0 || ab != 0 {
			t.Fatalf("after Close: %d CarrierIDs in use, %d abandoned", n, ab)
		}
		r.until(r.since() + 100*time.Millisecond)
		if c := hCause(r.pas.on(1)[0]); c != CauseTransportError {
			t.Fatalf("the late carrier's passive end ended %v, want transport_error (the dialer closed it)", c)
		}
		if s := r.h.Snapshot(); s.Probing || s.Info[1].ProbeCarrier != 0 {
			t.Fatalf("after Close: probing %v, info %+v", s.Probing, s.Info[1])
		}
		if n := prGoroutines("internal/carrier.(*"); n != 0 {
			t.Fatalf("%d carrier or health goroutines outlive Close", n)
		}
	}
	t.Run("LateResultDiscarded_L52", func(t *testing.T) {
		// The result arrives after the wind-down began: the attempt itself
		// discards the carrier (kill and join) before it ends, and Close
		// waits for that instead of abandoning the attempt.
		synctest.Test(t, func(t *testing.T) {
			r, gate, a := gated(t)
			ret := make(chan time.Duration)
			go func() {
				r.h.Close()
				ret <- r.since()
			}()
			r.until(1100 * time.Millisecond)
			select {
			case at := <-ret:
				t.Fatalf("Close returned at %v while the attempt was still held", at)
			default:
			}
			gate.open()
			if at := <-ret; at != 1100*time.Millisecond {
				t.Fatalf("Close returned at %v, want 1.1s (when the held attempt ended)", at)
			}
			r.h.mu.Lock()
			finished, est := a.finished, a.est
			r.h.mu.Unlock()
			if finished || est != nil {
				t.Fatalf("a result that arrived during the wind-down was posted: finished %v, est %v", finished, est)
			}
			settled(t, r, a)
		})
	})
	t.Run("PostedResultNotApplied_L52", func(t *testing.T) {
		// The result is posted, but the run ends in the very step that
		// would apply it: the wind-down kills the never-started carrier
		// and joins it and the attempt.
		synctest.Test(t, func(t *testing.T) {
			r, gate, a := gated(t)
			// Close's flag without its stop signal: the run goroutine
			// sleeps until the attempt posts its result and rings it, so
			// the step that ends the run finds that result unapplied.
			r.h.mu.Lock()
			r.h.closed = true
			close(r.h.closedCh)
			r.h.mu.Unlock()
			gate.open()
			t0 := time.Now()
			r.h.Close()
			if d := time.Since(t0); d != 20*time.Millisecond {
				t.Fatalf("Close took %v, want path 0's CLOSE exchange (20ms)", d)
			}
			r.h.mu.Lock()
			est := a.est
			r.h.mu.Unlock()
			if est == nil {
				t.Fatal("stimulus: the held attempt did not post its result")
			}
			c := est.Conn
			select {
			case <-c.Done():
			default:
				t.Fatal("the unapplied carrier was not joined")
			}
			if _, cause, detail, _ := c.Death(); cause != CauseLocalClose || detail != "probing stopped" {
				t.Fatalf("the unapplied carrier ended %v (%s), want local_close (probing stopped)", cause, detail)
			}
			if st := c.Stats(); st.Frames != 0 {
				t.Fatalf("the unapplied carrier was started: %d frames written", st.Frames)
			}
			settled(t, r, a)
		})
	})
}

// TestProbePeerCloseReconnects_L22_L23 (V6, V16, design §6.8): a probe
// carrier that the passive retires with CLOSE answers it, ends as retired
// (no failed mark) and is replaced at once; the new incarnation is Unknown
// until its own first PING is answered. A probe carrier that receives
// GOAWAY — here without the CLOSE that normally follows it — is retired by
// the health layer itself (our CLOSE goes out at once, no death, no mark)
// and replaced the same way.
func TestProbePeerCloseReconnects_L22_L23(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newPrRig(t, 2, nil)
		r.h.Use()
		r.until(3 * time.Second)
		old := r.probe(0)
		pas := r.pas.on(0)
		if old == nil || len(pas) != 1 {
			t.Fatalf("setup: probe %v, passive carriers %d", old, len(pas))
		}
		pas[0].Retire(wire.CloseRetire) // the passive retires its sessionless carrier
		// Its CLOSE arrives at 3.01 s and is answered; the slot redials at
		// once; the new carrier is established at 3.03 s.
		r.until(3020 * time.Millisecond)
		if hCause(old) != CauseRetired || hCause(pas[0]) != CauseRetired {
			t.Fatalf("CLOSE exchange: probe %v, passive %v", hCause(old), hCause(pas[0]))
		}
		r.until(3040 * time.Millisecond)
		s := r.h.Snapshot()
		nc := r.probe(0)
		if nc == nil || nc == old || s.Info[0].ProbeCarrier != nc.ID() || s.Failed[0] || s.Info[0].Attempts != 2 {
			t.Fatalf("reconnect: probe %v (old %v), failed %v, info %+v", nc, old, s.Failed[0], s.Info[0])
		}
		if ev := s.Evidence(0, time.Now()); ev.State != sched.EvUnknown {
			t.Fatalf("new incarnation evidence %v, want Unknown", ev)
		}
		r.until(3050 * time.Millisecond)
		if s = r.h.Snapshot(); s.Sum[0].N != 1 || !s.Sum[0].At.Equal(r.start.Add(3050*time.Millisecond)) || s.Failed[0] {
			t.Fatalf("first sample of the new incarnation: summary %+v, failed %v", s.Sum[0], s.Failed[0])
		}

		// GOAWAY alone.
		r.until(6 * time.Second)
		old = r.probe(0)
		pas = r.pas.on(0)
		r.links[0].DropNextFrame(rendrtest.Down, rendrtest.FrameClose)
		pas[1].GoAway() // GOAWAY, then CLOSE, which the link drops
		r.until(6300 * time.Millisecond)
		s = r.h.Snapshot()
		nc = r.probe(0)
		if hCause(old) != CauseRetired || !old.CloseSent() || s.Failed[0] {
			t.Fatalf("GOAWAY: probe ended %v (CLOSE sent %v), failed %v", hCause(old), old.CloseSent(), s.Failed[0])
		}
		if nc == nil || nc == old || s.Info[0].Attempts != 3 {
			t.Fatalf("GOAWAY: no replacement (probe %v, info %+v)", nc, s.Info[0])
		}
		if st := r.links[0].Stats().Probe; st.FramesDropped != 1 {
			t.Fatalf("stimulus: %d frames dropped, want the passive's CLOSE", st.FramesDropped)
		}
	})
}

// TestHealthInertSingleFactory (design §7.8): a single-factory Health is
// inert — no gauges, no goroutine, no probe dial, WaitFirst at once — yet
// its snapshot carries the factory (Unknown) and its failed mark, and
// Subscribe rings on every publication until cancelled. A Health without
// factories is inert too.
func TestHealthInertSingleFactory(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		l := rendrtest.NewLink(rendrtest.LinkConfig{Name: "only", Accept: newPrPassive().accept(0)})
		defer l.Close()
		h := NewHealth(env, []Factory{{Name: "only", Dial: l.Dial}}, prParams())
		if h.Gauges() != nil {
			t.Fatal("an inert Health has gauges")
		}
		s := h.Snapshot()
		if s.Version != 1 || s.Probing || len(s.Sum) != 1 || s.Evidence(0, time.Now()).State != sched.EvUnknown || s.Failed[0] {
			t.Fatalf("initial snapshot %+v", s)
		}
		bell := &hBell{}
		cancel := h.Subscribe(bell)
		h.Use()
		release := h.Hold()
		t0 := time.Now()
		h.WaitFirst(context.Background())
		if time.Since(t0) != 0 {
			t.Fatal("inert WaitFirst waited")
		}
		time.Sleep(time.Minute)
		if st := l.Stats(); st.Dials != 0 || h.Snapshot().Probing {
			t.Fatalf("inert Health dialled %d times", st.Dials)
		}
		h.MarkFailed(0, "ping_timeout")
		if s = h.Snapshot(); !s.Failed[0] || s.Info[0].FailReason != "ping_timeout" || bell.n.Load() != 1 {
			t.Fatalf("MarkFailed: %+v, rings %d", s.Info[0], bell.n.Load())
		}
		h.Succeeded(0)
		h.Succeeded(0) // nothing to clear: no publication
		h.MarkFailed(3, "out of range")
		if s = h.Snapshot(); s.Failed[0] || s.Version != 3 || bell.n.Load() != 2 {
			t.Fatalf("Succeeded: failed %v, version %d, rings %d", s.Failed[0], s.Version, bell.n.Load())
		}
		cancel()
		h.MarkFailed(0, "write_stall")
		if bell.n.Load() != 2 {
			t.Fatal("rung after cancel")
		}
		release()
		release()
		h.Close()
		h.Close()

		none := NewHealth(env, nil, prParams())
		none.Use()
		none.WaitFirst(context.Background())
		if len(none.Snapshot().Sum) != 0 || none.Gauges() != nil {
			t.Fatal("a Health without factories")
		}
		none.Close()
	})
}
