package carrier

import (
	"runtime"
	"runtime/debug"
	"slices"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// The M6 rows of the dialer reader's header reuse (delegate decision after
// wave C, "allocation gates near their bound": on Linux workers I1 found
// the only rendr allocations in the l4 gates' windows in dgReader.grow —
// getHdr building headers, udpsocket.NewBatch and batchSys.init).

// reuseBatch is a fakeBatch that records every header the reader lends it,
// in a slice made large enough beforehand (no allocation while it runs),
// and refuses the next refuse lends (a transport still returning earlier
// extras).
type reuseBatch struct {
	*fakeBatch
	lent   []*ioHdr // under fakeBatch.mu
	refuse atomic.Int32
}

func (a *reuseBatch) lend(h *ioHdr) bool {
	if a.refuse.Load() > 0 {
		a.refuse.Add(-1)
		return false
	}
	if !a.fakeBatch.lend(h) {
		return false
	}
	a.mu.Lock()
	a.lent = append(a.lent, h)
	a.mu.Unlock()
	return true
}

// lentSince returns the headers lent from index i on.
func (a *reuseBatch) lentSince(i int) []*ioHdr {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.lent[i:])
}

// lentLen returns how many headers were lent.
func (a *reuseBatch) lentLen() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.lent)
}

// reuseRig starts a dialer carrier read through a reuseBatch of MaxBatch
// 32, with room to record n datagrams and their calls without allocating.
// The raw peer answers no PING: the carrier's death bound is out of reach
// for the tests' idle periods.
func reuseRig(t *testing.T, n int) (*dgSide, *rawPeer, *reuseBatch) {
	s, p := rawPairWith(t, 1200, true, func(e *Env) {
		e.Timing.PingBusy, e.Timing.PingIdle = time.Hour, time.Hour
		e.Timing.DeadMin, e.Timing.DeadMax = time.Hour, 2*time.Hour
	})
	rb := &reuseBatch{fakeBatch: newFakeBatch(s.io, DefaultMaxBatch)}
	rb.lent = make([]*ioHdr, 0, n/8+16)
	rb.rcalls = make([]int, 0, n/4+16)
	rb.wcalls = make([]int, 0, n/4+16)
	rb.parkAt = make([]time.Time, 0, n/4+16)
	s.ep.dgs = make([]dgRec, 0, n)
	prev := dgBatchOf
	dgBatchOf = func(io PacketIO) BatchIO {
		if f, ok := io.(*fakeIO); ok && f == rb.fakeIO {
			return rb
		}
		return prev(io)
	}
	t.Cleanup(func() { dgBatchOf = prev })
	s.start(StartOptions{})
	synctest.Wait()
	return s, p, rb
}

// drainHdrPools takes every header the calling goroutine's P can reach out
// of the header pools and drops it: the state two collections leave them
// in, and the one a header returned on another P's private slot leaves
// them in for this P (sync.Pool never hands those out elsewhere).
func drainHdrPools() {
	for c := range hdrPools {
		for hdrPools[c].Get() != nil {
		}
	}
}

// collectTwice empties every pool of the process, on every P: a pooled
// item survives one collection (the victim cache), not two.
func collectTwice() {
	runtime.GC()
	runtime.GC()
}

// TestDgramReadAdaptiveDepthReuse_L16_L54 (M6 delegate decision after wave
// C; R1-5, M5-D61; L16, L54): a datagram carrier whose read depth grows
// and shrinks 100 times allocates nothing after warm-up. Each cycle a
// queued burst of 64 grows a dialer reader's depth 1 → 32 (read calls
// 1, 2, 4, 8, 16, 32, 1): it takes a header of each of the five classes
// 2 … 32 and returns four; three sparse parked datagrams halve it to 4
// (Env.Budget drops to 3 slots, the header of 32 kept); then the idle
// release returns the header and every slot (Env.Budget and Env.Stages at
// their baselines). Before every regrowth the header pools hold nothing
// the reader's P reaches:
//   - drained: they are emptied by hand (drainHdrPools); the 100 cycles,
//     run at one P with the collector off as countMallocs and
//     testing.AllocsPerRun count, allocate nothing at all;
//   - collected: two collections empty them, at the test's GOMAXPROCS;
//     every header the reader takes in the 100 cycles is one it took during
//     warm-up — none is built — while its slots come back from the
//     Runtime's DBufs, which the collections empty too (a pool of their
//     own, outside this row).
//
// In both, every cycle reads in exactly those ten calls and lends five
// headers, Env.Stages holds one header of 32 (32 × hdrPerMsg) at depth 32
// and 4, and every one of the 6,834 datagrams is delivered in order.
// Mutants: a reader's return goes to the pool, not the reserve (putRead;
// grow's return of the header it outgrew; collect's of an idle release's);
// a reader's take skips the reserve; a reserved header handed out
// uncharged; a return that keeps its charge.
func TestDgramReadAdaptiveDepthReuse_L16_L54(t *testing.T) {
	t.Run("drained", func(t *testing.T) {
		defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
		depthReuse(t, false)
	})
	t.Run("collected", func(t *testing.T) { depthReuse(t, true) })
}

// depthReuse is one variant of TestDgramReadAdaptiveDepthReuse_L16_L54:
// the header pools emptied by two collections (collect) or by hand.
func depthReuse(t *testing.T, collect bool) {
	const (
		warm, cycles = 2, 100
		burst        = 64
		sparse       = 3
		per          = burst + sparse
	)
	setIdleRelease(t, 100*time.Millisecond)
	synctest.Test(t, func(t *testing.T) {
		s, p, rb := reuseRig(t, per*(warm+cycles))
		bud, stg := s.env.Budget, s.env.Stages
		base, sbase := bud.Used(), stg.Used()
		bursts := make([][][]byte, warm+cycles)
		singles := make([][][]byte, warm+cycles)
		for i := range bursts {
			bursts[i] = p.burst(per*i, burst, 100)
			singles[i] = p.burst(per*i+burst, sparse, 100)
		}
		// The first miss of a cycle's accounts is recorded in bad (no
		// allocation) and fails the test after the window.
		var bad struct {
			cycle               int
			what                string
			budget, stages      int64
			wantBud, wantStages int64
		}
		check := func(i int, what string, wantBud, wantStages int64) {
			if bad.what == "" && (bud.Used()-base != wantBud || stg.Used()-sbase != wantStages) {
				bad.cycle, bad.what = i, what
				bad.budget, bad.stages = bud.Used()-base, stg.Used()-sbase
				bad.wantBud, bad.wantStages = wantBud, wantStages
			}
		}
		cycle := func(i int) {
			if collect {
				collectTwice()
			} else {
				drainHdrPools()
			}
			injectBurst(s.io, p.io.addr, bursts[i])
			synctest.Wait()
			check(i, "at depth 32", 31*slotSize(), 32*hdrPerMsg)
			for j := range sparse {
				injectBurst(s.io, p.io.addr, singles[i][j:j+1])
				synctest.Wait()
			}
			check(i, "halved to 4", 3*slotSize(), 32*hdrPerMsg)
			time.Sleep(2*batchIdleRelease + time.Millisecond)
			synctest.Wait()
			check(i, "after the idle release", 0, 0)
		}

		var ms0, ms1 runtime.MemStats
		if !collect {
			runtime.GC() // the bursts' garbage, before the collector stops
			defer debug.SetGCPercent(debug.SetGCPercent(-1))
		}
		for i := range warm {
			cycle(i)
		}
		warmHdrs := rb.lentSince(0)
		mark, wmark := rb.lentLen(), len(rb.readCalls())
		runtime.ReadMemStats(&ms0)
		for i := range cycles {
			cycle(warm + i)
		}
		runtime.ReadMemStats(&ms1)
		mallocs, gcs := ms1.Mallocs-ms0.Mallocs, ms1.NumGC-ms0.NumGC
		lent := rb.lentSince(mark)
		t.Logf("%d cycles of depth 1 → 32 → 4 → 1 (%d headers lent): %d allocations, %d collections", cycles, len(lent), mallocs, gcs)

		if bad.what != "" {
			t.Fatalf("cycle %d %s: Budget %d, Stages %d above the baseline; want %d (slots) and %d (one header of 32)",
				bad.cycle, bad.what, bad.budget, bad.stages, bad.wantBud, bad.wantStages)
		}
		calls := rb.readCalls()[wmark:]
		want := slices.Repeat([]int{1, 2, 4, 8, 16, 32, 1, 1, 1, 1}, cycles)
		if !slices.Equal(calls, want) {
			t.Fatalf("read calls of the window %v…, want [1 2 4 8 16 32 1 1 1 1] × %d (stimulus)", calls[:min(len(calls), 30)], cycles)
		}
		if len(lent) != 5*cycles {
			t.Fatalf("%d headers lent in %d cycles, want 5 per cycle (stimulus)", len(lent), cycles)
		}
		for i, h := range lent {
			if !slices.Contains(warmHdrs, h) {
				t.Fatalf("cycle %d took a header (class %d) it never took during warm-up: built anew, not reused", i/5, h.class)
			}
		}
		if got := seqsOf(s.ep); !slices.Equal(got, upTo(per*(warm+cycles))) {
			t.Fatalf("delivered %d datagrams (first %v), want 0 … %d in order", len(got), got[:min(len(got), 10)], per*(warm+cycles)-1)
		}
		if dead, cause, detail, _ := s.c.Death(); dead {
			t.Fatalf("carrier died: %v %q", cause, detail)
		}
		switch {
		case collect && gcs < 2*cycles:
			t.Fatalf("%d collections in %d cycles, want at least 2 per cycle (stimulus)", gcs, cycles)
		case !collect && gcs != 0:
			t.Fatalf("%d collections in the window with the collector off", gcs)
		case !collect && carrierRace:
			t.Log("race lane: allocations not asserted")
		case !collect && mallocs != 0:
			t.Fatalf("%d allocations in %d cycles of regrowth, want none", mallocs, cycles)
		}
	})
}

// TestDgramReadHeaderReturnsReused_L16_L54 (M6 delegate decision after
// wave C; R1-5, M5-D15; L16, L54): every other way a dialer reader returns
// a header puts it where the next growth finds it, with two collections
// emptying every pool in between (so nothing found there is reused):
//   - exit: a carrier killed at depth 32 (its reader's endDepth); a second
//     carrier's growth 1 → 32 lends exactly the five headers the first
//     one lent;
//   - fallback: the socket stops batching at depth 32 — the extras go back
//     (nothing held, Env.Budget and Env.Stages at their baselines) — and
//     batches again: the regrowth lends the same five headers;
//   - refused slot: after an idle release, a growth 2 → 4 that Env.Budget
//     refuses (ChargeRefused +2, the depth stays 2) returns the header of
//     4 it took; once the Budget has room, the growth lends that header —
//     the one lent during warm-up;
//   - refused lend: after an idle release, a growth 1 → 2 whose lend the
//     transport refuses (nothing held, both accounts at their baselines)
//     returns the header of 2 it took; the next growth lends that header.
//
// Every datagram is delivered in order. Mutants: shrink's return at depth
// 1 (exit, fallback), the refused slot's and the refused lend's return
// each to the pool instead of the reserve.
func TestDgramReadHeaderReturnsReused_L16_L54(t *testing.T) {
	setIdleRelease(t, 100*time.Millisecond)
	// warmUp grows the rig's depth 1 → 32 with datagrams 0 … 63 and returns
	// the five headers lent.
	warmUp := func(t *testing.T, s *dgSide, p *rawPeer, rb *reuseBatch) []*ioHdr {
		t.Helper()
		mark := rb.lentLen()
		injectBurst(s.io, p.io.addr, p.burst(0, 64, 100))
		synctest.Wait()
		if calls := rb.readCalls(); !slices.Equal(calls, []int{1, 2, 4, 8, 16, 32, 1}) {
			t.Fatalf("warm-up calls %v, want [1 2 4 8 16 32 1] (stimulus)", calls)
		}
		hs := rb.lentSince(mark)
		if len(hs) != 5 {
			t.Fatalf("%d headers lent growing 1 → 32, want 5 (stimulus)", len(hs))
		}
		return hs
	}
	// reused fails unless every header in got was in from.
	reused := func(t *testing.T, got, from []*ioHdr) {
		t.Helper()
		for _, h := range got {
			if !slices.Contains(from, h) {
				t.Fatalf("a header of class %d was built anew after its return, not reused", h.class)
			}
		}
	}
	idle := func(t *testing.T, s *dgSide, rb *reuseBatch, base, sbase int64) {
		t.Helper()
		time.Sleep(2*batchIdleRelease + time.Millisecond)
		synctest.Wait()
		if rb.holding() || s.env.Budget.Used() != base || s.env.Stages.Used() != sbase {
			t.Fatal("extras held after the idle release (stimulus)")
		}
	}
	t.Run("exit", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, p, rb := reuseRig(t, 64)
			first := warmUp(t, s, p, rb)
			s.c.Kill(CauseLocalClose, "test: exit at depth 32")
			<-s.c.Done()
			if s.env.Budget.Used() != 0 || s.env.Stages.Used() != 0 {
				t.Fatalf("after the exit: Budget %d, Stages %d; want nothing charged", s.env.Budget.Used(), s.env.Stages.Used())
			}
			collectTwice()
			s2, p2, rb2 := reuseRig(t, 64)
			second := warmUp(t, s2, p2, rb2)
			if !slices.Equal(second, first) {
				reused(t, second, first)
				t.Fatal("the second carrier lent other headers than the first one returned")
			}
			if got := seqsOf(s2.ep); !slices.Equal(got, upTo(64)) {
				t.Fatalf("delivered %v", got)
			}
		})
	})
	t.Run("fallback", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, p, rb := reuseRig(t, 192)
			base, sbase := s.env.Budget.Used(), s.env.Stages.Used()
			first := warmUp(t, s, p, rb)
			rb.setMax(1)
			injectBurst(s.io, p.io.addr, p.burst(64, 1, 100))
			synctest.Wait()
			if rb.holding() || s.env.Budget.Used() != base || s.env.Stages.Used() != sbase {
				t.Fatal("extras held after the fallback (stimulus)")
			}
			rb.setMax(DefaultMaxBatch)
			collectTwice()
			mark := rb.lentLen()
			injectBurst(s.io, p.io.addr, p.burst(65, 64, 100))
			synctest.Wait()
			if calls := rb.readCalls()[7:]; !slices.Equal(calls, []int{1, 1, 2, 4, 8, 16, 32, 1}) {
				t.Fatalf("calls %v after the fallback, want [1] then [1 2 4 8 16 32 1] (stimulus)", calls)
			}
			reused(t, rb.lentSince(mark), first)
			if got := seqsOf(s.ep); !slices.Equal(got, upTo(129)) {
				t.Fatalf("delivered %v", got)
			}
		})
	})
	t.Run("refused slot", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, p, rb := reuseRig(t, 192)
			bud := s.env.Budget
			base, sbase := bud.Used(), s.env.Stages.Used()
			first := warmUp(t, s, p, rb)
			idle(t, s, rb, base, sbase)
			injectBurst(s.io, p.io.addr, p.burst(64, 1, 100)) // depth 1 → 2
			synctest.Wait()
			charge := bud.Max() - bud.Used()
			bud.Acquire(charge)
			refused := s.env.Dgram.ChargeRefused.Load()
			mark := rb.lentLen()
			injectBurst(s.io, p.io.addr, p.burst(65, 2, 100)) // a full call at depth 2: growth to 4 refused
			synctest.Wait()
			if r := s.env.Dgram.ChargeRefused.Load() - refused; r != 2 || rb.lentLen() != mark {
				t.Fatalf("ChargeRefused +%d, %d headers lent; want +2 and none: the growth to 4 refused (stimulus)", r, rb.lentLen()-mark)
			}
			bud.Release(charge)
			collectTwice()
			injectBurst(s.io, p.io.addr, p.burst(67, 2, 100)) // the growth to 4 again
			synctest.Wait()
			got := rb.lentSince(mark)
			if len(got) != 1 || got[0].cap() != 4 {
				t.Fatalf("%d headers lent once the Budget had room, want the one of 4 (stimulus)", len(got))
			}
			reused(t, got, first)
			if calls := rb.readCalls()[7:]; !slices.Equal(calls, []int{1, 2, 2}) {
				t.Fatalf("calls %v, want [1 2 2]", calls)
			}
			if got := seqsOf(s.ep); !slices.Equal(got, upTo(69)) {
				t.Fatalf("delivered %v", got)
			}
		})
	})
	t.Run("refused lend", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, p, rb := reuseRig(t, 192)
			base, sbase := s.env.Budget.Used(), s.env.Stages.Used()
			first := warmUp(t, s, p, rb)
			idle(t, s, rb, base, sbase)
			rb.refuse.Store(1)
			mark := rb.lentLen()
			injectBurst(s.io, p.io.addr, p.burst(64, 1, 100)) // depth 1 → 2: the lend refused
			synctest.Wait()
			if rb.refuse.Load() != 0 || rb.lentLen() != mark || rb.holding() || s.env.Budget.Used() != base || s.env.Stages.Used() != sbase {
				t.Fatal("after the refused lend: want it consumed, nothing lent or held, both accounts at their baselines (stimulus)")
			}
			collectTwice()
			injectBurst(s.io, p.io.addr, p.burst(65, 1, 100)) // depth 1 → 2 again
			synctest.Wait()
			got := rb.lentSince(mark)
			if len(got) != 1 || got[0].cap() != 2 {
				t.Fatalf("%d headers lent at the next growth, want the one of 2 (stimulus)", len(got))
			}
			reused(t, got, first)
			if got := seqsOf(s.ep); !slices.Equal(got, upTo(66)) {
				t.Fatalf("delivered %v", got)
			}
		})
	})
}
