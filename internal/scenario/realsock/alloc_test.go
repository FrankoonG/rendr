package realsock

import (
	"io"
	"runtime"
	"runtime/debug"
	"sync/atomic"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/carrier/tcp"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The steady-state allocation gate of rendr mux (M3 design §A11.4, R1-26:
// WP15's of the five M3 zero-allocation gates; L41, L54) and the parked
// actor's wake-up benchmark. The other four gates are unit tests of their
// owners' packages: TestMuxWriterZeroAllocs and TestTrunkDispatchZeroAllocs
// (internal/carrier, WP8), TestRaceFillZeroAllocs_L41_L54
// (internal/session, WP3) and TestActorParkZeroAllocs (internal/session,
// WP5).

// TestMuxSteadyStateZeroAllocs_L41_L54 (§A11.4; M1's Y4 for rendr mux):
// the steady state of four stream sessions on one MUX trunk costs no
// allocation end to end. Two Runtimes over carrier/tcp on loopback
// (default Props; rendr-owned TCP conns: vectored writes), driven only
// through the public API. A round writes 16 KiB on each of the four
// dialer conns — four views ready at once, so the trunk writer runs its
// control pass and DRR rounds (M3-D10) — and then reads the 16 KiB of
// each on the passive: the application copies, the trunk writer, the
// passive trunk's dispatch to the views (M3-D4), the frame decode and the
// ACK, PING and PONG traffic; the window must hold at least one DRR Fill
// call per round (testhooks AfterViewFill, the stimulus). Over a window of at least 4,000 DATA and
// control frames written by the dialer's views and at least 50 PING
// intervals (PingBusy 10 ms), the raw number of heap allocations of every
// goroutine (runtime.MemStats.Mallocs, GC off, one P) is at most 40: an
// allocation per frame, per round, per PING or per PONG alone exceeds it.
// Asserted in the non-race lane; the race lane runs the same window
// without the assertion and logs the figure (R-F1).
func TestMuxSteadyStateZeroAllocs_L41_L54(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	const (
		n         = 4
		size      = 16 << 10
		warm      = 256
		maxAllocs = 40
		minFrames = 100 * maxAllocs
	)
	cfg := rendr.Config{PingBusy: 10 * time.Millisecond}
	var drrFills atomic.Int64 // the trunk writers' DRR Fill calls (stimulus)
	ov := &testhooks.Overrides{Hooks: &testhooks.Hooks{AfterViewFill: func(uint32, uint32) { drrFills.Add(1) }}}
	l := msTCPListen(t)
	m := newMsPair(t, cfg, ov, rendr.ListenConfig{Sources: []rendr.Source{rendr.FromListener(l)}},
		[]rendr.Carrier{tcp.Carrier("direct", "tcp", l.Addr().String(), tcp.Options{})})
	dcs, pcs := make([]*rendr.Conn, n), make([]*rendr.Conn, n)
	for i := range n {
		dcs[i], pcs[i] = m.open(rendr.ModeSelector)
	}
	if dm, pm := m.d.Status().Mux, m.p.Status().Mux; dm.Carriers != 1 || dm.Views != n || pm.Carriers != 1 || pm.Views != n {
		t.Fatalf("Mux: dialer %+v, passive %+v; want %d views on one trunk", dm, pm, n)
	}
	wbuf := make([]byte, size)
	if _, err := io.ReadFull(rendrtest.PRNG(41), wbuf); err != nil {
		t.Fatal(err)
	}
	rbuf := make([]byte, size)
	round := func() {
		for i := range n {
			if k, err := dcs[i].Write(wbuf); k != size || err != nil {
				t.Fatalf("session %d: Write = %d, %v", i, k, err)
			}
		}
		for i := range n {
			if k, err := io.ReadFull(pcs[i], rbuf); k != size || err != nil {
				t.Fatalf("session %d: Read = %d, %v", i, k, err)
			}
		}
	}
	frames := func() (sum uint64) {
		for i := range n {
			sum += dcs[i].Status().Carriers[0].Frames
		}
		return sum
	}
	// Warm-up: pools, rings, windows, the poller's timers, ACK and PING
	// state; it also measures the frames per round, which sizes the window
	// (Status is not read inside it).
	f0 := frames()
	for range warm {
		round()
	}
	perRound := float64(frames()-f0) / warm
	if perRound < n {
		t.Fatalf("load: %.1f frames per round of %d writes during the warm-up", perRound, n)
	}
	minRounds, minWindow := int(float64(minFrames)/perRound*1.25)+1, 50*cfg.PingBusy
	trunk := dcs[0].Status().Carriers[0].ID
	f1, d1 := frames(), drrFills.Load()
	mallocs, rounds, el := msCountMallocs(minRounds, minWindow, round)
	wrote, drr := frames()-f1, drrFills.Load()-d1
	if string(rbuf) != string(wbuf) {
		t.Fatal("the last round delivered other bytes")
	}
	for i := range n {
		st := dcs[i].Status()
		if len(st.Carriers) != 1 || st.Carriers[0].ID != trunk || st.Carriers[0].Shared != n || st.TxBytes != uint64(warm+msRefill+rounds)*size {
			t.Fatalf("load: session %d after %d rounds: %+v", i, rounds, st)
		}
	}
	if wrote < minFrames || el < minWindow {
		t.Fatalf("load: %d frames in %d rounds over %v, want ≥ %d frames and ≥ %v", wrote, rounds, el, minFrames, minWindow)
	}
	// Stimulus: the window ran the trunk writers' DRR rounds (several views
	// ready at once), not one view at a time.
	if drr < int64(rounds) {
		t.Fatalf("stimulus: %d DRR Fill calls in %d rounds, want at least one per round", drr, rounds)
	}
	t.Logf("%d allocations in %d rounds of %d × %d KiB (%v; the dialer's views wrote %d frames; %d DRR Fill calls)", mallocs, rounds, n, size>>10, el, wrote, drr)
	if msRace {
		t.Logf("race lane: not asserted")
	} else if mallocs > maxAllocs {
		t.Fatalf("%d allocations in %d steady-state rounds (%d frames) over %v, want at most %d", mallocs, rounds, wrote, el, maxAllocs)
	}
	for i := range n {
		msEnd(t, dcs[i], pcs[i])
	}
	m.muxZero()
	m.close()
}

// msRefill is how many times msCountMallocs runs f before its window.
const msRefill = 16

// msCountMallocs runs f at least n times and for at least window, with the
// garbage collector off and one P (as testing.AllocsPerRun), and returns
// the raw number of heap allocations of every goroutine during the window,
// the runs and the window's duration. A GC runs first, so that no pool is
// moved to its victim cache during the window, and msRefill runs refill
// what it took from the pools.
func msCountMallocs(n int, window time.Duration, f func()) (mallocs uint64, runs int, el time.Duration) {
	runtime.GC()
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	for range msRefill {
		f()
	}
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	start := time.Now()
	for runs < n || time.Since(start) < window {
		f()
		runs++
	}
	el = time.Since(start)
	runtime.ReadMemStats(&m1)
	return m1.Mallocs - m0.Mallocs, runs, el
}

// BenchmarkActorKick (§A11.4, M3-D42; perf lane, recorded, never gating):
// the wake-up of a parked session actor through the public API. One bond
// stream session over carrier/tcp (ActorLinger 5 ms, a testhooks
// override) is let park on both ends. Each operation writes one byte on
// the dialer: the Write that makes data outstanding rings a bond actor
// (its rescue clock, W7), a kick of the parked actor; the clock stops once
// the actor runs (the session registry's parked gauge drops), so ns/op is
// the time from the Write to the running actor. The byte is read on the
// passive outside the clock, and the next operation waits until both
// actors parked again.
func BenchmarkActorKick(b *testing.B) {
	l := msTCPListen(b)
	ov := &testhooks.Overrides{ActorLinger: 5 * time.Millisecond}
	m := newMsPair(b, rendr.Config{}, ov, rendr.ListenConfig{Sources: []rendr.Source{rendr.FromListener(l)}},
		[]rendr.Carrier{tcp.Carrier("direct", "tcp", l.Addr().String(), tcp.Options{})})
	dc, pc := m.open(rendr.ModeBond)
	parked0 := testhooks.ParkedSessions.Load()
	bothParked := func() bool { return testhooks.ParkedSessions.Load()-parked0 == 2 }
	one, got := []byte{1}, make([]byte, 1)
	b.ReportAllocs()
	b.ResetTimer()
	b.StopTimer()
	for range b.N {
		msUntil(b, 5*time.Second, "both actors parked", bothParked)
		b.StartTimer()
		if _, err := dc.Write(one); err != nil {
			b.Fatal(err)
		}
		for deadline := time.Now().Add(5 * time.Second); bothParked(); runtime.Gosched() {
			if time.Now().After(deadline) {
				b.Fatal("the Write did not kick the parked bond actor within 5 s")
			}
		}
		b.StopTimer()
		if _, err := io.ReadFull(pc, got); err != nil {
			b.Fatal(err)
		}
	}
	msEnd(b, dc, pc)
	m.muxZero()
	m.close()
}
