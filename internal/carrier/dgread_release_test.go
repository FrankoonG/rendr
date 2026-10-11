package carrier

import (
	"slices"
	"testing"
	"testing/synctest"
	"time"
)

// TestDgramReadFallbackBlockedReleases_L16 (R1-5 rules 3 and 5, M5-D15):
// a reader holding the extras of depth 32 whose socket stops batching
// while no datagram follows — its parked read ends with a noise event, so
// no depth rule runs after it — gives the extras back before its next
// read, which reads slot 0 alone and would hold them while it blocks (the
// fakeBatch's plainHold): within 2 × batchIdleRelease, and before any
// datagram arrives, Env.Budget and Env.Stages are at their baselines and
// nothing is held; the next datagrams are read one per call. Mutant: no
// fallback check before the read (the extras stay held until a datagram
// arrives or the carrier dies).
func TestDgramReadFallbackBlockedReleases_L16(t *testing.T) {
	setIdleRelease(t, 100*time.Millisecond)
	synctest.Test(t, func(t *testing.T) {
		s, p, fb, base, sbase := depthRig(t)
		bud, stg := s.env.Budget, s.env.Stages
		injectBurst(s.io, p.io.addr, p.burst(0, 64, 100))
		synctest.Wait()
		if !fb.holding() || bud.Used() == base || stg.Used() == sbase {
			t.Fatal("no extras held after the burst (stimulus)")
		}
		fb.plainHold.Store(true)
		fb.setMax(1)
		s.io.injectEvent(ReadNoise, nil) // wakes the parked read: no datagram, no depth rule
		synctest.Wait()
		time.Sleep(2*batchIdleRelease + time.Millisecond)
		synctest.Wait()
		if fb.holding() || bud.Used() != base || stg.Used() != sbase {
			t.Fatalf("blocked after the fallback, no datagram: holding %v, Budget %+d, Stages %+d; want nothing held", fb.holding(), bud.Used()-base, stg.Used()-sbase)
		}
		mark := len(fb.readCalls())
		injectBurst(s.io, p.io.addr, p.burst(64, 3, 100))
		synctest.Wait()
		if calls := fb.readCalls()[mark:]; !slices.Equal(calls, []int{1, 1, 1}) {
			t.Fatalf("calls %v after the fallback, want three of one", calls)
		}
		if got := seqsOf(s.ep); !slices.Equal(got, upTo(67)) {
			t.Fatalf("delivered %v", got)
		}
		if dead, cause, detail, _ := s.c.Death(); dead {
			t.Fatalf("carrier died: %v %q", cause, detail)
		}
	})
}

// TestDgramIdleReleaseGenOfReleasedHeader (R1-5, M5-D61): the idle
// release records the generation of the header it actually released, not
// the reader's latest lend — a lend that raced the release would otherwise
// leave the released header unmatched by collect (never pooled until the
// next lend or the reader's exit). The reader side is driven directly: the
// reader lent generation 6 last, the header released is generation 5, and
// collect pools it. Mutant: relGen from the latest lend (the generation
// loaded before tryRelease).
func TestDgramIdleReleaseGenOfReleasedHeader(t *testing.T) {
	f, _ := newFakeIOPair(t, 1200)
	fb := newFakeBatch(f, 32)
	stages := NewBudget(1 << 20)
	rd := &dgReader{dio: fb}
	fb.onRelease(rd.releaseHdr)
	rd.idleT = time.AfterFunc(time.Hour, func() {})
	rd.idleT.Stop()
	defer rd.idleT.Stop()
	h := getHdr(2, stages)
	h.k, h.gen = 2, 5
	fb.relHdr = h
	fb.state.Store(fbParked)
	fb.nparks.Store(4)
	rd.lastSeq.Store(4) // parked for a whole period
	rd.armed.Store(true)
	rd.gen = 6
	rd.idleFire()
	if fb.holding() || stages.Used() != 0 {
		t.Fatalf("holding %v, Stages %d; want the header released", fb.holding(), stages.Used())
	}
	if g := rd.relGen.Load(); g != 5 {
		t.Fatalf("relGen %d after releasing the header of generation 5, want 5", g)
	}
	rd.stale = h
	rd.collect()
	if rd.stale != nil {
		t.Fatal("collect left the released header unpooled")
	}
}
