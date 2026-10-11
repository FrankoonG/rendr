package carrier

import (
	"runtime"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// M5 WP2 rows of the dialer reader's adaptive depth (M5 design §A4.4;
// Revision 1 R1-4, R1-5, R1-7): a fakeBatch emulates the dialer socket's
// udpsocket.Reader — one datagram through the fixed header at depth 1, up
// to k queued datagrams with lent extras, parks counted while extras are
// held, an idle release only from a park — over the harness's link.

// injectBurst queues ds from src in f's inbox in one critical section and
// wakes its reader once: the whole burst is queued before the reader
// wakes.
func injectBurst(f *fakeIO, src PeerKey, ds [][]byte) {
	f.mu.Lock()
	for _, d := range ds {
		if f.closed || f.n == len(f.ring) {
			f.lost.Add(1)
			continue
		}
		s := &f.ring[(f.head+f.n)%len(f.ring)]
		s.b = append(s.b[:0], d...)
		s.src, s.ev, s.err = src, ReadOK, nil
		f.n++
	}
	f.mu.Unlock()
	select {
	case f.wake <- struct{}{}:
	default:
	}
}

// burst returns n datagrams of one DGRAM of size bytes each, for the seqs
// from seq on, numbered from the peer's next fseq.
func (p *rawPeer) burst(seq, n, size int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = p.datagram(dgramFrame(uint64(seq+i), size))
	}
	return out
}

// setIdleRelease sets batchIdleRelease for the test; call it before the
// carriers are built, so that it is restored after they ended.
func setIdleRelease(t testing.TB, d time.Duration) {
	prev := batchIdleRelease
	batchIdleRelease = d
	t.Cleanup(func() { batchIdleRelease = prev })
}

// slotSize is the class capacity of a reader slot of a 1200-byte budget
// over the harness's link (ReadSize 1201: the 2 KiB class).
func slotSize() int64 { return int64(dgramLayout.size(dgramLayout.class(1201))) }

// TestDgramReadAdaptiveDepth_L16 (R1-4, R3-23): with Env.Budget filled by
// a test charge, a burst of 20 queued datagrams is read at depth 1 — each
// full call's growth to 2 is refused, ChargeRefused counts exactly those
// 20 refused slots — and nothing is charged; once the charge is released
// a burst of 40 is read at depths 1, 2, 4, 8, 16, 32 (the slots charged
// to Env.Budget, the header to Env.Stages); an idle release returns
// everything (BufferedBytes at its baseline) and the next burst starts at
// depth 1 again, growing to 4; with the Budget full once more, a full
// call at depth 4 is refused its growth to 8: ChargeRefused +4 (the slots
// 4 … 7; a count per attempt would say +1), the depth stays 4. Mutants:
// extra read slots taken without TryGet (no refusal); a refusal counted
// once per attempt.
func TestDgramReadAdaptiveDepth_L16(t *testing.T) {
	setIdleRelease(t, 100*time.Millisecond)
	synctest.Test(t, func(t *testing.T) {
		s, p := rawPair(t, 1200, true)
		fb := newFakeBatch(s.io, 32)
		useBatch(t, fb)
		s.start(StartOptions{})
		synctest.Wait()
		bud, stg := s.env.Budget, s.env.Stages
		base, sbase := bud.Used(), stg.Used()

		charge := bud.Max() - bud.Used()
		bud.Acquire(charge)
		mark := len(fb.readCalls())
		injectBurst(s.io, p.io.addr, p.burst(0, 20, 100))
		synctest.Wait()
		if calls := fb.readCalls()[mark:]; !slices.Equal(calls, slices.Repeat([]int{1}, 20)) {
			t.Fatalf("calls %v with the budget full, want 20 of one datagram", calls)
		}
		if r := s.env.Dgram.ChargeRefused.Load(); r != 20 {
			t.Fatalf("ChargeRefused %d, want 20", r)
		}
		if bud.Used() != base+charge || stg.Used() != sbase {
			t.Fatalf("charged %d / %d with the budget full, want nothing", bud.Used()-base-charge, stg.Used()-sbase)
		}

		bud.Release(charge)
		mark = len(fb.readCalls())
		injectBurst(s.io, p.io.addr, p.burst(20, 40, 100))
		synctest.Wait()
		if calls := fb.readCalls()[mark:]; !slices.Equal(calls, []int{1, 2, 4, 8, 16, 9}) {
			t.Fatalf("calls %v, want [1 2 4 8 16 9]", calls)
		}
		if got, want := bud.Used()-base, 31*slotSize(); got != want {
			t.Fatalf("slots charged %d, want 31 × %d", got, slotSize())
		}
		if got := stg.Used() - sbase; got != 32*hdrPerMsg {
			t.Fatalf("header charged %d, want %d", got, 32*hdrPerMsg)
		}
		if r := s.env.Dgram.ChargeRefused.Load(); r != 20 {
			t.Fatalf("ChargeRefused %d after the release, want 20", r)
		}

		time.Sleep(2*batchIdleRelease + time.Millisecond)
		synctest.Wait()
		if bud.Used() != base || stg.Used() != sbase || fb.holding() {
			t.Fatalf("after the idle release: charged %d / %d, holding %v; want the baseline", bud.Used()-base, stg.Used()-sbase, fb.holding())
		}
		mark = len(fb.readCalls())
		injectBurst(s.io, p.io.addr, p.burst(60, 3, 100))
		synctest.Wait()
		if calls := fb.readCalls()[mark:]; !slices.Equal(calls, []int{1, 2}) {
			t.Fatalf("calls %v after the release, want [1 2]: depth 1 again", calls)
		}
		if got := seqsOf(s.ep); !slices.Equal(got, upTo(63)) {
			t.Fatalf("delivered %v", got)
		}

		// Depth 4 now (the call of 2 grew it); the Budget full again.
		full := bud.Max()
		bud.Acquire(full)
		mark = len(fb.readCalls())
		injectBurst(s.io, p.io.addr, p.burst(63, 8, 100))
		synctest.Wait()
		if calls := fb.readCalls()[mark:]; !slices.Equal(calls, []int{4, 4}) {
			t.Fatalf("calls %v with the Budget full at depth 4, want [4 4]: each growth to 8 refused", calls)
		}
		if r := s.env.Dgram.ChargeRefused.Load(); r != 28 {
			t.Fatalf("ChargeRefused %d, want 28 (20 + 2 refused growths of 4 slots)", r)
		}
		bud.Release(full)
		if got := seqsOf(s.ep); !slices.Equal(got, upTo(71)) {
			t.Fatalf("delivered %v", got)
		}
		if dead, cause, detail, _ := s.c.Death(); dead {
			t.Fatalf("carrier died: %v %q", cause, detail)
		}
	})
}

// TestDgramReadKeepsDepthAcrossShortParks (R1-5): bursts of 25 datagrams
// every 250 µs. After warm-up every burst is read in at most two counted
// calls (here one), no slot or header is taken or returned per burst, the
// reader keeps its extras across the parks between bursts, and they go
// back only after an idle batchIdleRelease. Mutant: the depth reset at
// every park.
func TestDgramReadKeepsDepthAcrossShortParks(t *testing.T) {
	setIdleRelease(t, 200*time.Millisecond)
	synctest.Test(t, func(t *testing.T) {
		s, p := rawPair(t, 1200, true)
		fb := newFakeBatch(s.io, 32)
		useBatch(t, fb)
		s.start(StartOptions{})
		synctest.Wait()
		bud := s.env.Budget
		base := bud.Used()
		var lends int
		var used int64
		for i := range 40 {
			mark := len(fb.readCalls())
			injectBurst(s.io, p.io.addr, p.burst(25*i, 25, 100))
			synctest.Wait()
			calls := fb.readCalls()[mark:]
			if i < 3 {
				lends, used = fb.lendCount(), bud.Used()
			} else {
				if len(calls) > 2 || slices.Contains(calls, 0) {
					t.Fatalf("burst %d read in calls %v, want at most 2", i, calls)
				}
				if fb.lendCount() != lends || bud.Used() != used {
					t.Fatalf("burst %d: lends %d → %d, slots charged %d → %d; want none taken or returned per burst", i, lends, fb.lendCount(), used-base, bud.Used()-base)
				}
			}
			if !fb.holding() {
				t.Fatalf("burst %d: the reader parked without its extras", i)
			}
			time.Sleep(250 * time.Microsecond)
		}
		if got := len(seqsOf(s.ep)); got != 1000 {
			t.Fatalf("%d datagrams delivered, want 1000", got)
		}
		time.Sleep(batchIdleRelease / 2)
		synctest.Wait()
		if !fb.holding() || bud.Used() == base {
			t.Fatal("extras released within half an idle period")
		}
		time.Sleep(2 * batchIdleRelease)
		synctest.Wait()
		if fb.holding() || bud.Used() != base {
			t.Fatalf("after two idle periods: holding %v, slots charged %d", fb.holding(), bud.Used()-base)
		}
	})
}

// warmGoroutines runs n goroutines at once to their end: the runtime keeps
// their records for reuse (a later goroutine allocates none).
func warmGoroutines(n int) {
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
		}()
	}
	close(start)
	wg.Wait()
}

// heapBytes returns the live heap after two collections (sync.Pool items
// survive one).
func heapBytes() int64 {
	var ms runtime.MemStats
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&ms)
	return int64(ms.HeapAlloc)
}

// TestBatchMemoryBounded_L16 (invariant 4; R1-5): 1,000 dialer carriers
// read a burst of 64 datagrams each. While busy, BufferedBytes holds at
// most the slot formula — per carrier (MaxBatch − 1) slots and one header
// — and the extras were really taken; within 2 × batchIdleRelease of the
// last datagram BufferedBytes is back at its baseline; the live heap per
// idle carrier exceeds that of 1,000 carriers with MaxBatch 1 by at most
// 256 bytes; and after Close nothing is charged.
func TestBatchMemoryBounded_L16(t *testing.T) {
	setIdleRelease(t, 100*time.Millisecond)
	const n = 1000
	run := func(t *testing.T, max int) (busy, heap int64) {
		synctest.Test(t, func(t *testing.T) {
			env := dgEnv()
			type side struct {
				io, peer *fakeIO
				c        *Conn
				p        *rawPeer
			}
			sides := make([]side, n)
			byIO := make(map[*fakeIO]*fakeBatch, n)
			for i := range sides {
				ia, ib := lightFakeIOPair(1200)
				fb := newFakeBatch(ia, max)
				fb.norec = true
				byIO[ia] = fb
				sides[i] = side{io: ia, peer: ib, c: dgConn(env, ia, 1200, true), p: &rawPeer{io: ib, fseq: env.Presets.firstFseq()}}
			}
			prev := dgBatchOf
			dgBatchOf = func(io PacketIO) BatchIO {
				if f, ok := io.(*fakeIO); ok {
					if fb := byIO[f]; fb != nil {
						return fb
					}
				}
				return prev(io)
			}
			defer func() { dgBatchOf = prev }()
			for _, s := range sides {
				s.c.Start(&dEP{}, &hBell{}, StartOptions{})
			}
			synctest.Wait()
			base := env.Budget.Used() + env.Stages.Used()
			// The idle releases of a thousand readers fire at one instant of
			// the bubble's clock, each on a goroutine of its own: the
			// runtime's goroutine records they need are allocated here, in
			// both runs, so the heap compares what the carriers hold.
			warmGoroutines(2 * n)
			heap0 := heapBytes()
			for _, s := range sides {
				injectBurst(s.io, s.peer.addr, s.p.burst(0, 64, 100))
			}
			synctest.Wait()
			busy = env.Budget.Used() + env.Stages.Used() - base
			if limit := int64(n) * (int64(max-1)*slotSize() + int64(2<<hdrClass(max))*hdrPerMsg); max > 1 && (busy <= 0 || busy > limit) {
				t.Fatalf("MaxBatch %d busy: %d bytes charged, want 0 < charged ≤ %d", max, busy, limit)
			}
			time.Sleep(2*batchIdleRelease + time.Millisecond)
			synctest.Wait()
			if b := env.Budget.Used() + env.Stages.Used(); b != base {
				t.Fatalf("MaxBatch %d idle: %d bytes above the baseline", max, b-base)
			}
			heap = heapBytes() - heap0
			for _, s := range sides {
				if dead, cause, detail, _ := s.c.Death(); dead {
					t.Fatalf("a carrier died: %v %q", cause, detail)
				}
				s.c.Kill(CauseLocalClose, "test end")
			}
			for _, s := range sides {
				<-s.c.Done()
			}
			if env.Budget.Used() != 0 || env.Stages.Used() != 0 {
				t.Fatalf("after Close: %d / %d bytes charged", env.Budget.Used(), env.Stages.Used())
			}
		})
		return busy, heap
	}
	_, ctl := run(t, 1)
	busy, heap := run(t, 32)
	t.Logf("busy charge %d B per carrier; idle heap %d B per carrier vs %d B with MaxBatch 1", busy/n, heap/n, ctl/n)
	if per := (heap - ctl) / n; per > 256 {
		t.Fatalf("idle heap per carrier exceeds the MaxBatch 1 control by %d bytes, want ≤ 256", per)
	}
}

// lightFakeIOPair is newFakeIOPair without the preallocated inbox buffers
// (a slot's buffer grows at its first datagram): a thousand links fit.
func lightFakeIOPair(limit int) (a, b *fakeIO) {
	a = &fakeIO{wake: make(chan struct{}, 1), done: make(chan struct{}), addr: fakeAddr(1), limit: limit, recv: limit}
	b = &fakeIO{wake: make(chan struct{}, 1), done: make(chan struct{}), addr: fakeAddr(2), limit: limit, recv: limit}
	a.other, b.other = b, a
	a.cur, b.cur = b.addr, a.addr
	return a, b
}

// TestDgramReaderDrainsQueuedFake_L54 (R1-7, the host's version of
// TestDgramReaderDrainsQueued_L54): 64 datagrams queued before the reader
// starts are drained in 7 calls (depths 1 … 32, then the one left); that
// tail call found its datagram queued — the end of a burst, not sparse
// traffic — so the depth stays, and the next burst of 20 is one call.
// Mutant: any call returning fewer than k/4 halves the depth.
func TestDgramReaderDrainsQueuedFake_L54(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p := rawPair(t, 1200, true)
		fb := newFakeBatch(s.io, 32)
		useBatch(t, fb)
		injectBurst(s.io, p.io.addr, p.burst(0, 64, 100))
		s.start(StartOptions{})
		synctest.Wait()
		if calls := fb.readCalls(); !slices.Equal(calls, []int{1, 2, 4, 8, 16, 32, 1}) {
			t.Fatalf("calls %v, want [1 2 4 8 16 32 1]", calls)
		}
		injectBurst(s.io, p.io.addr, p.burst(64, 20, 100))
		synctest.Wait()
		if calls := fb.readCalls()[7:]; !slices.Equal(calls, []int{20}) {
			t.Fatalf("second burst in calls %v, want [20]", calls)
		}
		if got := seqsOf(s.ep); !slices.Equal(got, upTo(84)) {
			t.Fatalf("delivered %v", got)
		}
	})
}
