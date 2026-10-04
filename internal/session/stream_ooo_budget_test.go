package session

import (
	"bytes"
	"math/rand/v2"
	"slices"
	"testing"
	"time"
)

// TestOOOSmallFramesBudgetBounded_L15 (V3, D13): tiny DATA frames (1–24
// bytes) arrive out of order, strictly descending or in a random order,
// while the head byte of the stream is withheld. Every frame that cannot
// extend a run needs a 16 KiB run of its own, so the out-of-order data soon
// reaches the receive cap: the Budget charge stays within 2·W plus one run,
// the excess is dropped and counted in oooDropped (exactly: every delivered
// byte is either held or counted), and nothing is a violation. Then the
// head arrives and the contiguous prefix reads back byte-exact. The
// sender's retransmission fills every hole, either as the tiny frames
// again in ascending order or as 64 KiB frames kept by reference (a rescue,
// or a replay after a carrier death). The charge stays bounded throughout:
// in-order data takes its room from the out-of-order data, which is shed
// highest first and counted, and runs promoted to the in-order queue are
// merged into its tail run, so tiny frames end up densely packed. The whole
// stream reads back byte-exact and every buffer returns to the Budget.
func TestOOOSmallFramesBudgetBounded_L15(t *testing.T) {
	const (
		w       = 256 << 10    // W: the receive cap is 2·W
		total   = w / 2        // the stream; every frame lies inside the window
		maxTiny = 24           // tiny frames carry 1–24 bytes
		bound   = 2*w + runCap // 2·W plus one run (one lane)
	)
	cases := []struct {
		name    string
		reverse bool // strictly descending offsets, else a seeded random order
		chunks  bool // the retransmission uses 64 KiB frames, else the tiny frames ascending
	}{
		{"reverse/tiny-retransmission", true, false},
		{"reverse/chunk-retransmission", true, true},
		{"random/tiny-retransmission", false, false},
		{"random/chunk-retransmission", false, true},
	}
	for ci, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rng := rand.New(rand.NewPCG(uint64(ci), 15))
			s := stSession(stOpt{role: RolePassive, window: w})
			budget := s.env.Carrier.Budget
			l, _ := stAddLane(s, 1, false)
			want := stPattern(0, total)
			type frame struct{ off, n int }
			var frs []frame // [1, total) in tiny frames; the head [0, 1) is withheld
			for off := 1; off < total; {
				n := min(1+rng.IntN(maxTiny), total-off)
				frs = append(frs, frame{off, n})
				off += n
			}
			order := slices.Clone(frs)
			if tc.reverse {
				slices.Reverse(order)
			} else {
				rng.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
			}

			var maxUsed int64
			deliver := func(what string, off, n int) {
				t.Helper()
				if err := stDeliverData(l, uint64(off), want[off:off+n]); err != nil {
					t.Fatalf("%s frame [%d,+%d): %v", what, off, n, err)
				}
				used := budget.Used()
				maxUsed = max(maxUsed, used)
				if used > bound {
					t.Fatalf("%s frame [%d,+%d) took the Budget charge to %d, want ≤ 2·W + one run = %d", what, off, n, used, bound)
				}
				if counted := stLocked(s, func(st *stream) int64 { return st.oooCap }); used > counted {
					t.Fatalf("%s frame [%d,+%d): Budget charge %d above the counted receive charge %d", what, off, n, used, counted)
				}
			}
			checkCharge := func(when string, exact bool) {
				t.Helper()
				counted, recomputed := stRecvCharge(s)
				if counted != recomputed {
					t.Fatalf("%s: counted receive charge %d, the segments hold %d", when, counted, recomputed)
				}
				if used := budget.Used(); exact && used != counted {
					t.Fatalf("%s: Budget charge %d, receive charge %d (runs only: they must agree)", when, used, counted)
				}
			}

			// 1. Out of order, the head withheld: the cap is reached and
			// holds; every byte is held or counted as dropped.
			for _, f := range order {
				deliver("out-of-order", f.off, f.n)
			}
			checkCharge("after the out-of-order frames", true)
			held, _, _ := stOOO(s)
			st1 := stLocked(s, func(st *stream) [2]uint64 { return [2]uint64{st.rTail, st.oooDropped} })
			if st1[0] != 0 {
				t.Fatalf("rTail %d with the head withheld", st1[0])
			}
			if st1[1] == 0 {
				t.Fatal("stimulus missing: the receive cap was never hit (nothing dropped)")
			}
			if held+st1[1] != total-1 {
				t.Fatalf("held %d + dropped %d bytes, want every delivered byte (%d) held or counted", held, st1[1], total-1)
			}
			if maxUsed <= 2*w-runCap {
				t.Fatalf("load missing: the out-of-order charge peaked at %d, below the cap %d less one run", maxUsed, 2*w)
			}
			t.Logf("%d tiny frames: %d bytes held out of order for a charge of %d, %d dropped", len(frs), held, maxUsed, st1[1])

			// 2. The head arrives: the contiguous prefix is readable and exact.
			deliver("head", 0, 1)
			from := int(stLocked(s, func(st *stream) uint64 { return st.rTail }))
			if got := stReadN(t, s, from); !bytes.Equal(got, want[:from]) {
				t.Fatalf("the prefix [0,%d) read back corrupted", from)
			}

			// 3. The sender retransmits everything not yet acknowledged
			// (from rRead on): in-order data takes room from the
			// out-of-order data, and promoted runs merge.
			promoted := false
			retransmit := func(off, n int) {
				t.Helper()
				_, low, ok := stOOO(s)
				deliver("retransmitted", off, n)
				if r := stLocked(s, func(st *stream) uint64 { return st.rTail }); ok && r > low {
					promoted = true // an out-of-order segment moved to inq
				}
			}
			if tc.chunks {
				for off := from; off < total; {
					e := min(total, (off/chunkSize+1)*chunkSize)
					retransmit(off, e-off)
					off = e
				}
			} else {
				for _, f := range frs {
					if f.off+f.n > from {
						retransmit(f.off, f.n)
					}
				}
			}
			checkCharge("after the retransmission", !tc.chunks)
			st3 := stLocked(s, func(st *stream) [3]uint64 {
				return [3]uint64{st.rTail, uint64(len(st.ooq.s)), st.oooDropped}
			})
			if st3[0] != total || st3[1] != 0 {
				t.Fatalf("after the retransmission rTail %d with %d out-of-order segments, want %d and none", st3[0], st3[1], total)
			}
			if !promoted {
				t.Fatal("stimulus missing: no out-of-order segment was promoted")
			}
			if tc.reverse && st3[2] == st1[1] {
				t.Fatal("stimulus missing: in-order data never took room from out-of-order data (nothing shed)")
			}
			if !tc.chunks {
				// Only runs: promoted ones were merged, so every run but the
				// tail is at least half full (unmerged tiny runs are not).
				runs := stLocked(s, func(st *stream) []int {
					var r []int
					for i := range st.inq.n {
						sg := st.inq.at(i)
						if !sg.run {
							t.Errorf("in-order segment at %d kept by reference with tiny frames only", sg.off)
						}
						r = append(r, len(sg.b))
					}
					return r
				})
				if len(runs) == 0 {
					t.Fatal("no in-order segment holds the retransmitted bytes")
				}
				for i, n := range runs[:len(runs)-1] {
					if n < runSize/2 {
						t.Fatalf("in-order run %d of %d holds %d bytes: promoted runs were not merged (%v)", i, len(runs), n, runs)
					}
				}
			}

			// The whole stream reads back exact; every buffer returns.
			if got := stReadN(t, s, total-from); !bytes.Equal(got, want[from:]) {
				t.Fatal("the retransmitted stream read back corrupted")
			}
			fin := stLocked(s, func(st *stream) [3]uint64 { return [3]uint64{st.rxBytes, st.delivered, uint64(st.oooCap)} })
			if fin != [3]uint64{total, total, 0} {
				t.Fatalf("rxBytes/delivered/charge = %v, want %d, %d, 0", fin, total, total)
			}
			if u := budget.Used(); u != 0 {
				t.Fatalf("Budget.Used = %d with every byte read", u)
			}
			stEnd(s, errClosed)
			if u := budget.Used(); u != 0 {
				t.Fatalf("Budget.Used = %d after the end", u)
			}
		})
	}
}

// TestStreamPromotionMergeCopyLimit (V3, P17): twenty 1000-byte frames
// arrive in descending order, each in a run of its own; a 600-byte head
// frame then makes the whole chain contiguous in one Data call. Promoted
// runs are merged into the in-order tail run only while they fit its room
// and the call's copy limit allows: fewer than 16 KiB under the lock, the
// head's own 600 bytes (copied in any case: it has no Buf) included. The
// others move as they are; the merged runs return to the Budget at once and
// the stream reads back exact.
func TestStreamPromotionMergeCopyLimit(t *testing.T) {
	const head, n, k = 600, 1000, 20
	s := stSession(stOpt{role: RolePassive})
	budget := s.env.Carrier.Budget
	l, _ := stAddLane(s, 1, false)
	want := stPattern(0, head+n*k)
	for i := k - 1; i >= 0; i-- {
		off := head + i*n
		if err := l.Data(nil, uint64(off), want[off:off+n], nil); err != nil {
			t.Fatal(err)
		}
	}
	if u, runs := budget.Used(), stLocked(s, func(st *stream) int { return len(st.ooq.s) }); runs != k || u != k*runCap {
		t.Fatalf("stimulus: %d out-of-order runs charging %d, want %d runs of one frame each", runs, u, k)
	}
	if err := l.Data(nil, 0, want[:head], nil); err != nil {
		t.Fatal(err)
	}
	// The head and 15 merged runs fill 15 600 bytes of the new tail run
	// (600 + 15 000 bytes copied in this call). The 16th run no longer fits
	// the room left (784 bytes) and moves as it is; the next four would fit
	// its room but not the copy limit left (783 bytes): a 17th merge would
	// have copied 16 600 bytes under the lock.
	got := stLocked(s, func(st *stream) []int {
		var r []int
		for i := range st.inq.n {
			r = append(r, len(st.inq.at(i).b))
		}
		return r
	})
	if exp := []int{head + 15*n, n, n, n, n, n}; !slices.Equal(got, exp) {
		t.Fatalf("in-order segments %v, want %v", got, exp)
	}
	if counted, recomputed := stRecvCharge(s); counted != 6*runCap || recomputed != counted || budget.Used() != counted {
		t.Fatalf("charge counted %d, recomputed %d, Budget %d; want 6 runs (%d)", counted, recomputed, budget.Used(), 6*runCap)
	}
	if b := stReadN(t, s, head+n*k); !bytes.Equal(b, want) {
		t.Fatal("the promoted chain read back corrupted")
	}
	stEnd(s, errClosed)
	if u := budget.Used(); u != 0 {
		t.Fatalf("Budget.Used = %d after the end", u)
	}
}

// TestStreamRecvCapProperty (V3): random mixes of tiny, small and large DATA
// frames of one consistent stream (out of order, duplicated, overlapping,
// re-cut) inside a window that slides as the application reads and ACKs
// are placed, interleaved with partial reads and, for odd seeds, a Close
// that switches to discard mode, keep the receive accounting exact and the
// cap in force after every call: st.oooCap equals the class capacity of the
// segments held, never understates the Budget charge, and stays within 2·W
// whenever out-of-order data is held; inq covers [rRead, rTail)
// contiguously; ooq is ascending, disjoint and strictly beyond rTail (no
// contiguous segment is left behind); oooDropped only grows. Across the
// seeds the cap binds, out-of-order data is dropped and shed, and segments
// are promoted (stimulus). A final retransmission completes the stream,
// which reads back exact.
func TestStreamRecvCapProperty(t *testing.T) {
	const (
		w     = 256 << 10
		total = 4 * w
	)
	var capHits, drops, sheds, promotions, closedDone int
	for seed := range uint64(24) {
		rng := rand.New(rand.NewPCG(seed, 61))
		s := stSession(stOpt{role: RolePassive, window: w})
		budget := s.env.Carrier.Budget
		l, _ := stAddLane(s, 1, false)
		want := stPattern(0, total)
		closeAt := -1
		if seed%2 == 1 {
			closeAt = 200 + rng.IntN(2000)
		}
		var got []byte
		var dropped uint64
		buf := make([]byte, 64<<10)
		check := func(when string) {
			t.Helper()
			s.mu.Lock()
			defer s.mu.Unlock()
			st := &s.st
			fail := func(format string, a ...any) {
				t.Helper()
				t.Fatalf("seed %d %s: "+format, append([]any{seed, when}, a...)...)
			}
			var charge int64
			if st.inq.n == 0 {
				if st.rRead != st.rTail {
					fail("inq empty with rRead %d < rTail %d", st.rRead, st.rTail)
				}
			} else if h := st.inq.at(0); h.off > st.rRead || h.end() <= st.rRead {
				fail("the first in-order segment [%d,%d) does not hold rRead %d", h.off, h.end(), st.rRead)
			}
			for i := range st.inq.n {
				sg := st.inq.at(i)
				if len(sg.b) == 0 || (i > 0 && sg.off != st.inq.at(i-1).end()) {
					fail("in-order segment %d [%d,+%d) not contiguous", i, sg.off, len(sg.b))
				}
				charge += segCap(sg)
			}
			if st.inq.n > 0 && st.inq.back().end() != st.rTail {
				fail("inq ends at %d, rTail %d", st.inq.back().end(), st.rTail)
			}
			lo := st.rTail + 1
			for i := range st.ooq.s {
				sg := &st.ooq.s[i]
				if len(sg.b) == 0 || sg.off < lo {
					fail("out-of-order segment %d [%d,+%d) overlaps or is contiguous with rTail %d", i, sg.off, len(sg.b), st.rTail)
				}
				lo = sg.end()
				charge += segCap(sg)
			}
			if charge != st.oooCap {
				fail("counted receive charge %d, the segments hold %d", st.oooCap, charge)
			}
			if u := budget.Used(); u > st.oooCap {
				fail("Budget charge %d above the counted receive charge %d", u, st.oooCap)
			}
			if len(st.ooq.s) > 0 && st.oooCap > 2*w {
				fail("receive charge %d above 2·W with out-of-order data held", st.oooCap)
			}
			if st.oooDropped < dropped {
				fail("oooDropped went back from %d to %d", dropped, st.oooDropped)
			}
			dropped = st.oooDropped
		}
		view := func() [5]uint64 {
			return stLocked(s, func(st *stream) [5]uint64 {
				return [5]uint64{st.rRead, st.rTail, st.rightEdge, st.oooDropped, uint64(len(st.ooq.s))}
			})
		}
		deliver := func(off, n int) {
			t.Helper()
			before := view()
			if err := stDeliverData(l, uint64(off), want[off:off+n]); err != nil {
				t.Fatalf("seed %d frame [%d,+%d): %v", seed, off, n, err)
			}
			check("after a frame")
			after := view()
			if after[4] > 0 && stLocked(s, func(st *stream) int64 { return st.oooCap }) > 2*w-runCap {
				capHits++ // the cap binds: no further run fits
			}
			if after[3] > before[3] {
				drops++
				if after[1] > before[1] {
					sheds++ // in-order data took room from out-of-order data
				}
			}
			if after[1] > before[1] && after[1] > uint64(off+n) {
				promotions++
			}
		}
		// advance places an ACK, as the duty lane's writer would: the
		// right edge follows rRead (the window slides).
		advance := func() {
			s.mu.Lock()
			s.bumpNowLocked()
			s.mu.Unlock()
			_, b := stFill(l, time.Now())
			b.ReleaseRefs()
		}
		read := func(limit int) {
			t.Helper()
			v := view()
			avail := int(v[1] - v[0])
			if avail == 0 {
				return
			}
			k, err := s.Read(buf[:min(avail, limit, len(buf))])
			if err != nil {
				t.Fatalf("seed %d: Read: %v", seed, err)
			}
			got = append(got, buf[:k]...)
			check("after a Read")
		}
		closed := false
		for step := range 3000 {
			if step == closeAt {
				s.Close()
				closed = true
				check("after Close")
			}
			v := view()
			switch r := rng.IntN(16); {
			case r < 13: // a frame in the window (a little below rRead too), or at the in-order end
				lo := max(int(v[0])-4<<10, 0)
				off := lo + rng.IntN(int(v[2])-lo)
				if r >= 11 {
					off = int(v[1])
				}
				if off >= int(min(v[2], total)) {
					continue
				}
				var n int
				switch c := rng.IntN(10); {
				case c < 5:
					n = 1 + rng.IntN(64)
				case c < 8:
					n = 1 + rng.IntN(16<<10-1)
				default:
					n = 16<<10 + rng.IntN(48<<10+1)
				}
				deliver(off, min(n, int(min(v[2], total))-off))
			case r < 15: // a partial read of what is readable
				if !closed {
					read(1 + rng.IntN(32<<10))
				}
			default:
				advance()
			}
		}
		// The sender retransmits what is missing, window by window.
		for v := view(); v[1] < total; v = view() {
			for off := int(v[1]); off < int(min(v[2], total)); off = int(view()[1]) {
				deliver(off, min(int(min(v[2], total)), (off/chunkSize+1)*chunkSize)-off)
			}
			for !closed && view()[1] > view()[0] {
				read(len(buf))
			}
			advance()
			if n := view(); n[1] == v[1] && n[2] == v[2] {
				t.Fatalf("seed %d: no progress at rTail %d, right edge %d", seed, n[1], n[2])
			}
		}
		if closed {
			if d := stLocked(s, func(st *stream) uint64 { return st.delivered }); d != total {
				t.Fatalf("seed %d: %d bytes delivered in discard mode, want %d", seed, d, total)
			}
			closedDone++
		} else if len(got) != total {
			t.Fatalf("seed %d: read %d bytes, want %d", seed, len(got), total)
		}
		if !bytes.Equal(got, want[:len(got)]) {
			t.Fatalf("seed %d: the stream read back corrupted", seed)
		}
		stEnd(s, errClosed)
		if u := budget.Used(); u != 0 {
			t.Fatalf("seed %d: Budget.Used = %d after the end", seed, u)
		}
	}
	t.Logf("cap binding %d times, %d dropping calls (%d sheds), %d promotions", capHits, drops, sheds, promotions)
	if capHits == 0 || drops == 0 || sheds == 0 || promotions == 0 || closedDone == 0 {
		t.Fatalf("stimulus missing: cap binding %d, drops %d, sheds %d, promotions %d, discard-mode runs %d",
			capHits, drops, sheds, promotions, closedDone)
	}
}

// stRecvCharge returns the counted receive charge (st.oooCap) and the
// charge recomputed from the segments: the class capacity of every segment
// in inq and ooq.
func stRecvCharge(s *Session) (counted, recomputed int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := &s.st
	for i := range st.inq.n {
		recomputed += segCap(st.inq.at(i))
	}
	for i := range st.ooq.s {
		recomputed += segCap(&st.ooq.s[i])
	}
	return st.oooCap, recomputed
}

// stOOO returns the payload bytes held out of order and the lowest
// out-of-order offset (ok is false when ooq is empty).
func stOOO(s *Session) (held, low uint64, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.st.ooq.s {
		held += uint64(len(s.st.ooq.s[i].b))
	}
	if len(s.st.ooq.s) > 0 {
		low, ok = s.st.ooq.s[0].off, true
	}
	return held, low, ok
}
