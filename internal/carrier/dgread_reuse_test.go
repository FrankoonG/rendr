package carrier

import (
	"runtime"
	"runtime/debug"
	"slices"
	"sync"
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
// extras). While holdRel is set, an idle release that took the extras
// blocks after it completed (the transport idle) until relGate closes:
// before idleFire records its generation (relGen) and wakes the read, the
// window in which a growth's lend finds the transport idle with the stale
// header not yet matched by collect; relHeld counts the releases waiting
// there.
type reuseBatch struct {
	*fakeBatch
	lent    []*ioHdr // under fakeBatch.mu
	refuse  atomic.Int32
	holdRel atomic.Bool
	relGate chan struct{}
	relHeld atomic.Int32
}

func (a *reuseBatch) tryRelease(seq uint64) bool {
	ok := a.fakeBatch.tryRelease(seq)
	if ok && a.holdRel.Load() {
		a.relHeld.Add(1)
		<-a.relGate
		a.relHeld.Add(-1)
	}
	return ok
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
	rb := &reuseBatch{fakeBatch: newFakeBatch(s.io, DefaultMaxBatch), relGate: make(chan struct{})}
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
//     testing.AllocsPerRun count, allocate nothing (AllocsPerRun's
//     criterion: less than one object per cycle; a header is six or more);
//   - collected: two collections empty them, at the test's GOMAXPROCS;
//     every header the reader takes in the 100 cycles is one it took during
//     warm-up — none is built — while its slots come back from the
//     Runtime's DBufs, which the collections empty too (a pool of their
//     own, outside this row).
//
// In both, every cycle reads in exactly those ten calls and lends five
// headers, Env.Stages holds one header of 32 (32 × hdrPerMsg) at depth 32
// and 4, and every one of the 6,834 datagrams is delivered in order. Both
// variants model the loss of the pooled headers (by hand, by collections):
// without a loss — one P, the collector off, the pools warm — the pools
// alone hand a warm reader its headers back, so the row proves the
// reserve, not the l4 gates' counts on Linux (I2's lanes measure those).
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
		case !collect && mallocs/cycles != 0:
			// testing.AllocsPerRun's criterion: an allocation per cycle (a
			// header is six objects or more) fails; fewer than one per cycle
			// in all, which a goroutine outside the bubble may make while
			// synctest.Wait blocks, does not (the raw count is logged above).
			t.Fatalf("%d allocations in %d cycles of regrowth (%d per cycle), want none", mallocs, cycles, mallocs/cycles)
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
//   - stale at lend: an idle release takes the header of 32 and completes
//     (the transport idle, the slots and the charge back), but is held
//     before idleFire records its generation (reuseBatch.holdRel); a
//     datagram read meanwhile makes the reader's growth 1 → 2 lend while
//     the header of 32 is still stale (collect cannot match it yet), so
//     grow returns it; once the release goes on, the regrowth 2 → 32 lends
//     that same header of 32, and every header it lends is one lent before;
//   - four at once: four dialer readers (hdrSpares' derivation: two
//     readers in step × two headers of a class each) hold a header of 32
//     at once and return them at their idle releases; every header their
//     regrowths lend is one lent before (a reserve of fewer than four
//     entries per class builds the rest anew).
//
// Every datagram is delivered in order. Mutants: shrink's return at depth
// 1 (exit, fallback), the refused slot's, the refused lend's and grow's
// stale return each to the pool instead of the reserve; a reserve of fewer
// than four entries per class (four at once).
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
	t.Run("stale at lend", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, p, rb := reuseRig(t, 192)
			base, sbase := s.env.Budget.Used(), s.env.Stages.Used()
			first := warmUp(t, s, p, rb)
			h32 := first[len(first)-1]
			if h32.cap() != 32 || !rb.holding() {
				t.Fatal("no header of 32 held after the warm-up (stimulus)")
			}
			// The release goes on before the cleanup's Kill on every path:
			// the reader's exit waits for a firing in flight (relMu).
			open := sync.OnceFunc(func() {
				rb.holdRel.Store(false)
				close(rb.relGate)
			})
			defer open()
			rb.holdRel.Store(true)
			time.Sleep(2*batchIdleRelease + time.Millisecond)
			synctest.Wait()
			if rb.relHeld.Load() != 1 || rb.state.Load() != fbIdle || s.env.Budget.Used() != base || s.env.Stages.Used() != sbase {
				t.Fatal("no completed idle release held before idleFire records it: not held, the transport not idle, or the extras still charged (stimulus)")
			}
			mark := rb.lentLen()
			injectBurst(s.io, p.io.addr, p.burst(64, 1, 100)) // read into slot 0; growth 1 → 2 while the header of 32 is stale
			synctest.Wait()
			got := rb.lentSince(mark)
			// Still held: relGen not recorded, so collect could not match the
			// stale header before the growth's lend; grow returned it.
			if len(got) != 1 || got[0].cap() != 2 || rb.relHeld.Load() != 1 {
				t.Fatalf("%d headers lent during the held release (held %d), want the one of 2 with the release still held: the growth's lend found the transport idle (stimulus)", len(got), rb.relHeld.Load())
			}
			reused(t, got, first)
			open()
			synctest.Wait()
			collectTwice()
			mark = rb.lentLen()
			injectBurst(s.io, p.io.addr, p.burst(65, 64, 100)) // depth 2 → 32
			synctest.Wait()
			if calls := rb.readCalls()[7:]; !slices.Equal(calls, []int{1, 2, 4, 8, 16, 32, 2}) {
				t.Fatalf("calls %v after the warm-up, want [1] then [2 4 8 16 32 2] (stimulus)", calls)
			}
			got = rb.lentSince(mark)
			if len(got) != 4 || got[3].cap() != 32 {
				t.Fatalf("%d headers lent growing 2 → 32, want four, the last of 32 (stimulus)", len(got))
			}
			reused(t, got, first)
			if got[3] != h32 {
				t.Fatal("the regrowth to 32 lent another header than the stale one grow returned")
			}
			if got := seqsOf(s.ep); !slices.Equal(got, upTo(129)) {
				t.Fatalf("delivered %v", got)
			}
		})
	})
	t.Run("four at once", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			const readers = 4 // hdrSpares' derivation (env.go); not hdrSpares itself, which the row pins
			type rig struct {
				s           *dgSide
				p           *rawPeer
				rb          *reuseBatch
				base, sbase int64
			}
			rigs := make([]rig, readers)
			for i := range rigs {
				s, p, rb := reuseRig(t, 192)
				rigs[i] = rig{s, p, rb, s.env.Budget.Used(), s.env.Stages.Used()}
			}
			var warm []*ioHdr
			for _, r := range rigs {
				warm = append(warm, warmUp(t, r.s, r.p, r.rb)...)
			}
			for i, r := range rigs {
				if !r.rb.holding() || r.s.env.Stages.Used()-r.sbase != 32*hdrPerMsg {
					t.Fatalf("reader %d: Stages %d above its baseline, want one header of 32 held (stimulus: four held at once)", i, r.s.env.Stages.Used()-r.sbase)
				}
			}
			time.Sleep(2*batchIdleRelease + time.Millisecond)
			synctest.Wait()
			for i, r := range rigs {
				if r.rb.holding() || r.s.env.Budget.Used() != r.base || r.s.env.Stages.Used() != r.sbase {
					t.Fatalf("reader %d: extras held after the idle release (stimulus)", i)
				}
			}
			collectTwice()
			for i, r := range rigs {
				mark := r.rb.lentLen()
				injectBurst(r.s.io, r.p.io.addr, r.p.burst(64, 64, 100))
				synctest.Wait()
				if calls := r.rb.readCalls()[7:]; !slices.Equal(calls, []int{1, 2, 4, 8, 16, 32, 1}) {
					t.Fatalf("reader %d: calls %v after the idle release, want [1 2 4 8 16 32 1] (stimulus)", i, calls)
				}
				got := r.rb.lentSince(mark)
				if len(got) != 5 {
					t.Fatalf("reader %d: %d headers lent regrowing 1 → 32, want 5 (stimulus)", i, len(got))
				}
				reused(t, got, warm)
				if got := seqsOf(r.s.ep); !slices.Equal(got, upTo(128)) {
					t.Fatalf("reader %d delivered %v", i, got)
				}
			}
		})
	})
}
