package session

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Receive memory tests (design §4.4, D13, §0.8 V3): the receive charge cap,
// exact accounting, dense placement of small frames in any arrival order,
// the copy limit, and the recovery of dropped bytes through a sender's
// retransmission.

// stWatchCopies installs the receive copy hook for s until the test ends:
// every placement by one of s's Data calls must copy fewer than 16 KiB under
// the session lock (§3.2, P17). It returns a function reporting the largest
// copy of one call so far and the copy of the latest call. Tests that use it
// do not run in parallel.
func stWatchCopies(t testing.TB, s *Session) func() (most, last int) {
	var most, last atomic.Int64
	recvCopyHook.Store(&recvHook{s: s, fn: func(n int) {
		if n >= runSize {
			t.Errorf("one Data call copied %d bytes under the session lock, want fewer than %d", n, runSize)
		}
		last.Store(int64(n))
		for m := most.Load(); int64(n) > m && !most.CompareAndSwap(m, int64(n)); m = most.Load() {
		}
	}})
	t.Cleanup(func() { recvCopyHook.Store(nil) })
	return func() (int, int) { return int(most.Load()), int(last.Load()) }
}

// stRecvInvariants checks the receive structure of s and returns the first
// violation: st.oooCap is the class capacity of the segments held — and,
// if exact, the whole Budget charge — and no two segments share a buffer;
// every segment's bytes end at its buffer's end of capacity (it may grow
// into that room), a run starts at its buffer's first byte and holds at most
// 16 KiB; inq covers [rRead, rTail) contiguously (while a Read copies, Close
// may have consumed segments its commit releases); ooq is ascending,
// disjoint and beyond rTail with nothing contiguous left at rTail; and the
// receive charge is within 2·W while out-of-order data is held.
func stRecvInvariants(s *Session, exact bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := &s.st
	bufs := make(map[*carrier.Buf]bool)
	var charge int64
	check := func(where string, sg *seg) error {
		switch {
		case sg.buf == nil || len(sg.b) == 0:
			return fmt.Errorf("%s segment at %d is empty", where, sg.off)
		case bufs[sg.buf]:
			return fmt.Errorf("%s segment at %d shares its buffer with another segment", where, sg.off)
		case &sg.b[:cap(sg.b)][cap(sg.b)-1] != &sg.buf.B[:cap(sg.buf.B)][cap(sg.buf.B)-1]:
			return fmt.Errorf("%s segment at %d does not reach its buffer's end of capacity", where, sg.off)
		case sg.run && (cap(sg.b) != cap(sg.buf.B) || len(sg.b) > runSize):
			return fmt.Errorf("%s run at %d holds %d bytes from buffer offset %d", where, sg.off, len(sg.b), cap(sg.buf.B)-cap(sg.b))
		}
		bufs[sg.buf] = true
		charge += segCap(sg)
		return nil
	}
	if st.inq.n == 0 {
		if st.rRead != st.rTail {
			return fmt.Errorf("inq empty with rRead %d < rTail %d", st.rRead, st.rTail)
		}
	} else if h := st.inq.at(0); h.off > st.rRead || (h.end() <= st.rRead && !st.rcopying) {
		return fmt.Errorf("the first in-order segment [%d,%d) does not hold rRead %d", h.off, h.end(), st.rRead)
	}
	for i := range st.inq.n {
		sg := st.inq.at(i)
		if i > 0 && sg.off != st.inq.at(i-1).end() {
			return fmt.Errorf("in-order segment %d at %d not contiguous", i, sg.off)
		}
		if err := check("in-order", sg); err != nil {
			return err
		}
	}
	if st.inq.n > 0 && st.inq.back().end() != st.rTail {
		return fmt.Errorf("inq ends at %d, rTail %d", st.inq.back().end(), st.rTail)
	}
	lo := st.rTail + 1
	for i := range st.ooq.s {
		sg := &st.ooq.s[i]
		if sg.off < lo {
			return fmt.Errorf("out-of-order segment %d at %d overlaps, or is contiguous with rTail %d", i, sg.off, st.rTail)
		}
		if err := check("out-of-order", sg); err != nil {
			return err
		}
		lo = sg.end()
	}
	if charge != st.oooCap {
		return fmt.Errorf("counted receive charge %d, the segments hold %d", st.oooCap, charge)
	}
	if u := s.env.Carrier.Budget.Used(); exact && u != charge {
		return fmt.Errorf("Budget charge %d, receive charge %d", u, charge)
	}
	if len(st.ooq.s) > 0 && st.oooCap > s.recvLimit() {
		return fmt.Errorf("receive charge %d above 2·W = %d with out-of-order data held", st.oooCap, s.recvLimit())
	}
	return nil
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

// stSegs returns the payload length of every in-order segment and every
// out-of-order one.
func stSegs(s *Session) (in, out []int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.st.inq.n {
		in = append(in, len(s.st.inq.at(i).b))
	}
	for i := range s.st.ooq.s {
		out = append(out, len(s.st.ooq.s[i].b))
	}
	return in, out
}

// TestOOOSmallFramesBudgetBounded_L15 (V3, D13): a stream of tiny DATA
// frames (1–24 bytes) travels over two lanes, alternating; the fast lane's
// frames arrive out of order — strictly descending or in a seeded random
// order — while the slow lane's and the head byte of the stream are still
// in flight. Each fast-lane frame is isolated and needs a run of its own,
// so the out-of-order data reaches the receive cap: the Budget charge stays
// within 2·W (exactly the counted charge), the excess is dropped and counted
// in oooDropped (every byte held or counted), and nothing is a violation.
// Then the head arrives and the contiguous prefix reads back byte-exact; the
// slow lane's frames follow in ascending order, extending the held runs next
// to them or, beyond a dropped frame, meeting the cap themselves. The
// sender's retransmission of everything not yet acknowledged — the tiny
// frames again in ascending order, or 64 KiB frames kept by reference —
// fills every hole the drops left, promoting what was held: promoted runs
// merge into the in-order tail. The charge stays within 2·W + one run
// throughout, every Data call copies fewer than 16 KiB, in-order runs end up
// densely packed, the whole stream reads back byte-exact and every buffer
// returns to the Budget.
func TestOOOSmallFramesBudgetBounded_L15(t *testing.T) {
	const (
		w       = 256 << 10    // W: the receive cap is 2·W
		total   = w / 2        // the stream; every frame lies inside the window
		maxTiny = 24           // tiny frames carry 1–24 bytes
		bound   = 2*w + runCap // 2·W plus one run (one lane)
	)
	cases := []struct {
		name    string
		reverse bool // the fast lane's frames strictly descending, else in a seeded random order
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
			copies := stWatchCopies(t, s)
			l, _ := stAddLane(s, 1, false)
			want := stPattern(0, total)
			type frame struct{ off, n int }
			var fast, slow []frame // [1, total) in tiny frames, alternating lanes; [0, 1) is withheld
			for off, k := 1, 0; off < total; k++ {
				f := frame{off, min(1+rng.IntN(maxTiny), total-off)}
				if k%2 == 0 {
					fast = append(fast, f)
				} else {
					slow = append(slow, f)
				}
				off += f.n
			}
			order := slices.Clone(fast)
			if tc.reverse {
				slices.Reverse(order)
			} else {
				rng.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
			}

			var maxUsed int64
			promoted := false
			deliver := func(what string, off, n int) {
				t.Helper()
				_, low, ok := stOOO(s)
				if err := stDeliverData(l, uint64(off), want[off:off+n]); err != nil {
					t.Fatalf("%s frame [%d,+%d): %v", what, off, n, err)
				}
				if r := stLocked(s, func(st *stream) uint64 { return st.rTail }); ok && r > low {
					promoted = true // an out-of-order segment moved to inq
				}
				used := budget.Used()
				maxUsed = max(maxUsed, used)
				if used > bound {
					t.Fatalf("%s frame [%d,+%d) took the Budget charge to %d, want ≤ 2·W + one run = %d", what, off, n, used, bound)
				}
				if err := stRecvInvariants(s, true); err != nil {
					t.Fatalf("%s frame [%d,+%d): %v", what, off, n, err)
				}
			}

			// 1. The fast lane, the head withheld: the cap is reached and
			// holds; every byte is held or counted as dropped.
			fastBytes := 0
			for _, f := range order {
				deliver("fast-lane", f.off, f.n)
				fastBytes += f.n
			}
			held, _, _ := stOOO(s)
			st1 := stLocked(s, func(st *stream) [2]uint64 { return [2]uint64{st.rTail, st.oooDropped} })
			if st1[0] != 0 {
				t.Fatalf("rTail %d with the head withheld", st1[0])
			}
			if st1[1] == 0 {
				t.Fatal("stimulus missing: the receive cap was never hit (nothing dropped)")
			}
			if held+st1[1] != uint64(fastBytes) {
				t.Fatalf("held %d + dropped %d bytes, want every fast-lane byte (%d) held or counted", held, st1[1], fastBytes)
			}
			if maxUsed <= 2*w-runCap {
				t.Fatalf("load missing: the out-of-order charge peaked at %d, below the cap %d less one run", maxUsed, 2*w)
			}
			t.Logf("%d fast-lane frames: %d bytes held out of order for a charge of %d, %d dropped", len(fast), held, maxUsed, st1[1])

			// 2. The head arrives: the contiguous prefix is readable and exact.
			deliver("head", 0, 1)
			from := int(stLocked(s, func(st *stream) uint64 { return st.rTail }))
			if got := stReadN(t, s, from); !bytes.Equal(got, want[:from]) {
				t.Fatalf("the prefix [0,%d) read back corrupted", from)
			}

			// 3. The slow lane's frames arrive in order: they extend the
			// held runs next to them, closing gaps; where a fast-lane frame
			// was dropped they are out of order and meet the cap themselves.
			for _, f := range slow {
				deliver("slow-lane", f.off, f.n)
			}
			gap := stLocked(s, func(st *stream) uint64 { return st.rTail })
			if gap >= total {
				t.Fatal("stimulus missing: the drops left no hole for the retransmission")
			}

			// 4. The sender retransmits everything not yet acknowledged (from
			// rRead on): the holes fill and the stream completes.
			if tc.chunks {
				for off := from; off < total; {
					e := min(total, (off/chunkSize+1)*chunkSize)
					deliver("retransmitted", off, e-off)
					off = e
				}
			} else {
				all := slices.Concat(fast, slow)
				slices.SortFunc(all, func(a, b frame) int { return a.off - b.off })
				for _, f := range all {
					if f.off+f.n > from {
						deliver("retransmitted", f.off, f.n)
					}
				}
			}
			st4 := stLocked(s, func(st *stream) [2]uint64 { return [2]uint64{st.rTail, uint64(len(st.ooq.s))} })
			if st4[0] != total || st4[1] != 0 {
				t.Fatalf("after the retransmission rTail %d with %d out-of-order segments, want %d and none", st4[0], st4[1], total)
			}
			if !promoted {
				t.Fatal("stimulus missing: no out-of-order segment was promoted")
			}
			if !tc.chunks {
				// Only runs, densely packed: promoted runs merged into the
				// tail, so the runs average more than half full.
				in, _ := stSegs(s)
				if bytesIn := total - from; len(in) > 2*bytesIn/runSize+2 {
					t.Fatalf("%d in-order runs for %d bytes: promoted runs were not merged (%v)", len(in), bytesIn, in)
				}
			}
			if most, _ := copies(); most == 0 {
				t.Fatal("stimulus missing: nothing was copied")
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

	// Contiguous tiny frames in strictly descending order, the head
	// withheld: each frame's run takes the run after it as the gap between
	// them closes, so the out-of-order data stays dense — about one run per
	// 16 KiB, nothing dropped — where a run per frame used to fill the cap.
	t.Run("contiguous-reverse", func(t *testing.T) {
		rng := rand.New(rand.NewPCG(9, 15))
		s := stSession(stOpt{role: RolePassive, window: w})
		budget := s.env.Carrier.Budget
		stWatchCopies(t, s)
		l, _ := stAddLane(s, 1, false)
		want := stPattern(0, total)
		var offs []int
		for off := 1; off < total; off += 1 + rng.IntN(maxTiny) {
			offs = append(offs, off)
		}
		for i := len(offs) - 1; i >= 0; i-- {
			end := total
			if i+1 < len(offs) {
				end = offs[i+1]
			}
			if err := l.Data(nil, uint64(offs[i]), want[offs[i]:end], nil); err != nil {
				t.Fatalf("frame [%d,%d): %v", offs[i], end, err)
			}
			if err := stRecvInvariants(s, true); err != nil {
				t.Fatalf("frame [%d,%d): %v", offs[i], end, err)
			}
		}
		d := stLocked(s, func(st *stream) uint64 { return st.oooDropped })
		if u := budget.Used(); d != 0 || u > (total/runSize+2)*runCap {
			t.Fatalf("%d tiny frames held for a charge of %d with %d bytes dropped, want about one run per 16 KiB and none dropped", len(offs), u, d)
		}
		if err := l.Data(nil, 0, want[:1], nil); err != nil {
			t.Fatal(err)
		}
		if got := stReadN(t, s, total); !bytes.Equal(got, want) {
			t.Fatal("the stream read back corrupted")
		}
		stEnd(s, errClosed)
		if u := budget.Used(); u != 0 {
			t.Fatalf("Budget.Used = %d after the end", u)
		}
	})
}

// stClass returns the capacity of the buffer a reader takes for a DATA
// payload of n bytes (design §4.9: Get(n + LookAhead)).
func stClass(n int) int64 {
	b := carrier.NewBufPool().Get(n+carrier.LookAhead, nil)
	defer b.Release()
	return int64(cap(b.B))
}

// TestStreamRefFrameChargedOnce (V3): a frame kept by reference is one
// segment and is charged once, however many held segments it overlaps.
// 105 three-byte segments are held out of order in [64 KiB, 128 KiB), a run
// each; two in-order 64 KiB frames then arrive. Each becomes one in-order
// segment, and the second replaces every held run it covers (they hold the
// same bytes), so the counted receive charge is exactly the Budget charge —
// two frame buffers — instead of one buffer capacity per piece of a frame.
// An out-of-order 64 KiB frame that follows is therefore admitted, nothing
// dropped: the real charge is far below 2·W. Nothing is copied under the
// lock; the stream reads back exact and every buffer returns.
func TestStreamRefFrameChargedOnce(t *testing.T) {
	const w = 1 << 20
	s := stSession(stOpt{role: RolePassive, window: w})
	budget := s.env.Carrier.Budget
	copies := stWatchCopies(t, s)
	l, _ := stAddLane(s, 1, false)
	want := stPattern(0, 320<<10)
	deliver := func(off, n int) {
		t.Helper()
		if err := stDeliverData(l, uint64(off), want[off:off+n]); err != nil {
			t.Fatalf("frame [%d,+%d): %v", off, n, err)
		}
		if err := stRecvInvariants(s, true); err != nil {
			t.Fatalf("frame [%d,+%d): %v", off, n, err)
		}
	}
	const step = (64 << 10) / 105
	for k := range 105 {
		deliver(64<<10+1+k*step, 3)
	}
	if _, out := stSegs(s); len(out) != 105 || budget.Used() != 105*runCap {
		t.Fatalf("stimulus: %d out-of-order segments charging %d, want 105 runs", len(out), budget.Used())
	}
	for _, off := range []int{0, 64 << 10} {
		deliver(off, 64<<10)
		if _, last := copies(); last != 0 {
			t.Fatalf("the frame at %d copied %d bytes: a frame kept by reference copies nothing", off, last)
		}
	}
	frame := stClass(64 << 10)
	in, out := stSegs(s)
	if !slices.Equal(in, []int{64 << 10, 64 << 10}) || len(out) != 0 {
		t.Fatalf("segments in order %v, out of order %v; want two whole frames and nothing held out of order", in, out)
	}
	if u := budget.Used(); u != 2*frame {
		t.Fatalf("Budget charge %d, want the two frame buffers (%d)", u, 2*frame)
	}
	deliver(256<<10, 64<<10)
	if d := stLocked(s, func(st *stream) uint64 { return st.oooDropped }); d != 0 {
		t.Fatalf("the out-of-order 64 KiB frame lost %d bytes with the real charge at %d of 2·W = %d", d, budget.Used(), 2*w)
	}
	if _, last := copies(); last != 0 {
		t.Fatalf("the out-of-order frame copied %d bytes: a frame kept by reference copies nothing", last)
	}
	deliver(128<<10, 64<<10)
	deliver(192<<10, 64<<10)
	if got := stReadN(t, s, 320<<10); !bytes.Equal(got, want) {
		t.Fatal("the stream read back corrupted")
	}
	stEnd(s, errClosed)
	if u := budget.Used(); u != 0 {
		t.Fatalf("Budget.Used = %d after the end", u)
	}
}

// TestStreamRefOrCopyAtLimit (V3, P17, V11): a frame that arrives in a Buf
// is copied — its buffer released at once — only when its new bytes are
// below the copy limit and copying holds no more memory than keeping it
// would; otherwise it is kept whole by reference, one segment that replaces
// the held segments it covers. Each case checks the bytes copied by the
// call, the segments held and the exact Budget charge, then reads the
// stream back.
func TestStreamRefOrCopyAtLimit(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(deliver func(off, n int))
		frame  [2]int // the frame [off, off+n) delivered last
		copied int    // bytes copied by its Data call
		in     []int  // in-order segments afterwards
		charge int64  // the Budget charge afterwards
	}{{
		// 16 383 new bytes ahead of a held 16 385-byte frame: copied.
		name:   "new-below-limit",
		setup:  func(d func(off, n int)) { d(16383, 16385) },
		frame:  [2]int{0, 32 << 10},
		copied: 16383,
		in:     []int{16383, 16385},
		charge: runCap + stClass(16385),
	}, {
		// 16 384 new bytes: kept by reference over the held frame.
		name:   "new-at-limit",
		setup:  func(d func(off, n int)) { d(16384, 16384) },
		frame:  [2]int{0, 32 << 10},
		copied: 0,
		in:     []int{32 << 10},
		charge: stClass(32 << 10),
	}, {
		// 100 new bytes ahead of four dense held runs that charge more than
		// the frame's buffer: the frame replaces them.
		name: "replaces-dense-runs",
		setup: func(d func(off, n int)) {
			for off := 100; off < 64<<10; off += 16000 {
				d(off, min(16000, 64<<10-off))
			}
		},
		frame:  [2]int{0, 64 << 10},
		copied: 0,
		in:     []int{64 << 10},
		charge: stClass(64 << 10),
	}, {
		// The frame overlaps 44 KiB already in order; five sparse held runs
		// lie in the 20 KiB it would keep: copying its new bytes and merging
		// the runs holds less than a 64 KiB buffer for 20 KiB would.
		name: "merges-sparse-runs",
		setup: func(d func(off, n int)) {
			d(0, 44<<10)
			for k := range 5 {
				d(44<<10+100+k*4000, 3000)
			}
		},
		frame:  [2]int{0, 64 << 10},
		copied: 5480 + 3*3000,
		in:     []int{44<<10 + 100 + 3*4000, 4000, 3000 + 1380},
		charge: stClass(44<<10) + 2*runCap,
	}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := stSession(stOpt{role: RolePassive})
			budget := s.env.Carrier.Budget
			l, _ := stAddLane(s, 1, false)
			want := stPattern(0, 64<<10)
			var last int
			recvCopyHook.Store(&recvHook{s: s, fn: func(n int) { last = n }})
			t.Cleanup(func() { recvCopyHook.Store(nil) })
			deliver := func(off, n int) {
				t.Helper()
				if err := stDeliverData(l, uint64(off), want[off:off+n]); err != nil {
					t.Fatalf("frame [%d,+%d): %v", off, n, err)
				}
				if err := stRecvInvariants(s, true); err != nil {
					t.Fatalf("frame [%d,+%d): %v", off, n, err)
				}
			}
			tc.setup(deliver)
			deliver(tc.frame[0], tc.frame[1])
			if last != tc.copied {
				t.Errorf("the frame's Data call copied %d bytes, want %d", last, tc.copied)
			}
			if in, out := stSegs(s); !slices.Equal(in, tc.in) || len(out) != 0 {
				t.Errorf("segments in order %v, out of order %v; want %v and none", in, out, tc.in)
			}
			if u := budget.Used(); u != tc.charge {
				t.Errorf("Budget charge %d, want %d", u, tc.charge)
			}
			if got := stReadN(t, s, tc.frame[0]+tc.frame[1]); !bytes.Equal(got, want[:len(got)]) {
				t.Fatal("the stream read back corrupted")
			}
			stEnd(s, errClosed)
			if u := budget.Used(); u != 0 {
				t.Fatalf("Budget.Used = %d after the end", u)
			}
		})
	}
}

// TestStreamOOOMergesOnArrival (V3, P17): out-of-order runs merge as gaps
// close, so small frames end up densely packed in any arrival order.
// Twenty 1000-byte frames arrive in descending order: each frame's new run
// takes the run that follows it — copied, the follower's buffer released —
// while it fits and the call's copy limit allows, so the chain is two runs,
// not twenty. A 600-byte head makes it contiguous: the first run merges into
// the in-order tail, the second moves as it is. Then 3000 contiguous tiny
// frames arrive in a random order and end up in runs that average more than
// half full. Every Data call copies fewer than 16 KiB; the stream reads
// back exact and every buffer returns.
func TestStreamOOOMergesOnArrival(t *testing.T) {
	const head, n, k = 600, 1000, 20
	// 8 MiB: the shuffled phase peaks near 750 islands, a run each, well
	// within the 1020 runs of the cap, so nothing is dropped.
	s := stSession(stOpt{role: RolePassive, window: 8 << 20})
	budget := s.env.Carrier.Budget
	copies := stWatchCopies(t, s)
	l, _ := stAddLane(s, 1, false)
	want := stPattern(0, 256<<10)
	deliver := func(off, n int) {
		t.Helper()
		if err := l.Data(nil, uint64(off), want[off:off+n], nil); err != nil {
			t.Fatalf("frame [%d,+%d): %v", off, n, err)
		}
		if err := stRecvInvariants(s, true); err != nil {
			t.Fatalf("frame [%d,+%d): %v", off, n, err)
		}
	}
	for i := k - 1; i >= 0; i-- {
		deliver(head+i*n, n)
	}
	// Frame 4's run took frames 5–19 (15 000 bytes, 16 000 copied by that
	// call); frame 3's could not take that 16 000-byte run, and frames 0–2
	// then merged into frame 3's.
	if in, out := stSegs(s); len(in) != 0 || !slices.Equal(out, []int{4 * n, 16 * n}) || budget.Used() != 2*runCap {
		t.Fatalf("after the descending chain: in order %v, out of order %v charging %d; want two runs (4000, 16000)", in, out, budget.Used())
	}
	if most, _ := copies(); most != 16*n {
		t.Fatalf("the largest copy of one call is %d bytes, want %d (a frame and the 15 it merged)", most, 16*n)
	}
	deliver(0, head)
	if in, out := stSegs(s); !slices.Equal(in, []int{head + 4*n, 16 * n}) || len(out) != 0 {
		t.Fatalf("after the head: in order %v, out of order %v; want [4600 16000] and none", in, out)
	}

	// Random order: islands merge as the gaps between them close.
	rng := rand.New(rand.NewPCG(7, 7))
	from := head + k*n
	type frame struct{ off, n int }
	var frs []frame
	for off := from; len(frs) < 3000; {
		f := frame{off, 1 + rng.IntN(24)}
		frs = append(frs, f)
		off += f.n
	}
	to := frs[len(frs)-1].off + frs[len(frs)-1].n
	rng.Shuffle(len(frs), func(i, j int) { frs[i], frs[j] = frs[j], frs[i] })
	for _, f := range frs {
		deliver(f.off, f.n)
	}
	in, out := stSegs(s)
	if d := stLocked(s, func(st *stream) uint64 { return st.oooDropped }); d != 0 || len(out) != 0 || stLocked(s, func(st *stream) uint64 { return st.rTail }) != uint64(to) {
		t.Fatalf("the shuffled frames left %d out-of-order segments, %d bytes dropped", len(out), d)
	}
	if rest := in[2:]; len(rest) > 2*(to-from)/runSize+2 {
		t.Fatalf("%d runs for %d shuffled bytes: islands did not merge (%v)", len(rest), to-from, rest)
	}
	if got := stReadN(t, s, to); !bytes.Equal(got, want[:to]) {
		t.Fatal("the stream read back corrupted")
	}
	stEnd(s, errClosed)
	if u := budget.Used(); u != 0 {
		t.Fatalf("Budget.Used = %d after the end", u)
	}
}

// TestStreamRefRoomAbsorbsSmallFrames (V3): a frame kept by reference
// offers the slack of its size class behind its payload to the bytes that
// follow it. In-order frames of 16 KiB + 40 bytes (a 32 KiB-class buffer)
// alternate with small frames; each small frame goes into the room of the
// frame before it instead of a run of its own that the next frame would
// seal. The charge stays at one buffer per large frame, below 2× the bytes,
// where a run per small frame would make it about 3× for 1-byte frames. The
// stream reads back exact.
func TestStreamRefRoomAbsorbsSmallFrames(t *testing.T) {
	const big, cycles = 16<<10 + 40, 30
	for _, small := range []int{1, 600, 16000} {
		t.Run(fmt.Sprint(small), func(t *testing.T) {
			s := stSession(stOpt{role: RolePassive})
			budget := s.env.Carrier.Budget
			stWatchCopies(t, s)
			l, _ := stAddLane(s, 1, false)
			total := cycles * (big + small)
			want := stPattern(0, total)
			for off := 0; off < total; {
				for _, n := range []int{big, small} {
					if err := stDeliverData(l, uint64(off), want[off:off+n]); err != nil {
						t.Fatalf("frame [%d,+%d): %v", off, n, err)
					}
					off += n
				}
				if err := stRecvInvariants(s, true); err != nil {
					t.Fatal(err)
				}
			}
			in, _ := stSegs(s)
			if want := slices.Repeat([]int{big + small}, cycles); !slices.Equal(in, want) {
				t.Fatalf("in-order segments %v, want %d of %d bytes: the small frames did not go into the room", in, cycles, big+small)
			}
			if u := budget.Used(); u != cycles*stClass(big) || u >= 2*int64(total) {
				t.Fatalf("Budget charge %d for %d bytes, want %d (one buffer per large frame, below 2×)", u, total, cycles*stClass(big))
			}
			if got := stReadN(t, s, total); !bytes.Equal(got, want) {
				t.Fatal("the stream read back corrupted")
			}
			stEnd(s, errClosed)
			if u := budget.Used(); u != 0 {
				t.Fatalf("Budget.Used = %d after the end", u)
			}
		})
	}
}

// TestStreamPromoteRefillBounded (V3): without a reader, cycles of
// out-of-order chains promoted by a gap fill, followed by in-order data up
// to the window, keep the receive charge within 2·W + one run at every
// step. Each cycle withholds the byte at rTail, sends a chain of 1000-byte
// frames in descending order, then the byte: the chain's runs merged as it
// arrived, so promotion leaves dense runs in order instead of a run per
// frame. The in-order refill that follows — 64 KiB frames, 1000-byte frames,
// or 16 KiB + 40-byte frames alternating with 600-byte ones — adds about its
// own bytes. Every Data call copies fewer than 16 KiB; the stream reads back
// exact and every buffer returns.
func TestStreamPromoteRefillBounded(t *testing.T) {
	const w = 1 << 20
	refills := []struct {
		name  string
		sizes []int // frame sizes, in turn
	}{
		{"chunks", []int{64 << 10}},
		{"small", []int{1000}},
		{"alternating", []int{16<<10 + 40, 600}},
	}
	for _, chain := range []int{10, 20, 40} {
		for _, rf := range refills {
			t.Run(fmt.Sprintf("chain%d/%s", chain, rf.name), func(t *testing.T) {
				s := stSession(stOpt{role: RolePassive, window: w})
				budget := s.env.Carrier.Budget
				stWatchCopies(t, s)
				l, _ := stAddLane(s, 1, false)
				want := stPattern(0, w)
				var maxUsed int64
				deliver := func(off, n int) {
					t.Helper()
					if err := stDeliverData(l, uint64(off), want[off:off+n]); err != nil {
						t.Fatalf("frame [%d,+%d): %v", off, n, err)
					}
					used := budget.Used()
					maxUsed = max(maxUsed, used)
					if used > 2*w+runCap {
						t.Fatalf("frame [%d,+%d) took the Budget charge to %d (%.2f·W), want ≤ 2·W + one run", off, n, used, float64(used)/w)
					}
					if err := stRecvInvariants(s, true); err != nil {
						t.Fatalf("frame [%d,+%d): %v", off, n, err)
					}
				}
				rTail := func() int { return int(stLocked(s, func(st *stream) uint64 { return st.rTail })) }
				cycles := 0
				for ; cycles < 37; cycles++ {
					base := rTail()
					if base+1+chain*1000 > w/2 {
						break // half the window stays for the refill
					}
					for k := chain - 1; k >= 0; k-- {
						deliver(base+1+k*1000, 1000)
					}
					deliver(base, 1)
					if r := rTail(); r != base+1+chain*1000 {
						t.Fatalf("cycle %d: rTail %d after the gap fill, want %d (the whole chain promoted)", cycles, r, base+1+chain*1000)
					}
				}
				if cycles < 10 {
					t.Fatalf("stimulus missing: %d cycles", cycles)
				}
				after := budget.Used()
				for i, off := 0, rTail(); off < w; i++ {
					n := min(rf.sizes[i%len(rf.sizes)], w-off)
					deliver(off, n)
					off += n
				}
				t.Logf("%d cycles: charge %.2f·W after them, peak %.2f·W", cycles, float64(after)/w, float64(maxUsed)/w)
				if got := stReadN(t, s, w); !bytes.Equal(got, want) {
					t.Fatal("the stream read back corrupted")
				}
				stEnd(s, errClosed)
				if u := budget.Used(); u != 0 {
					t.Fatalf("Budget.Used = %d after the end", u)
				}
			})
		}
	}
}

// TestStreamShedHighestFirst (V3): when in-order data pushes the receive
// charge above 2·W, out-of-order segments are shed from the highest offset
// down, so the bytes kept are the ones the application needs first; the
// shed bytes are counted in oooDropped and the cap holds again. The
// retransmission completes the stream, which reads back exact.
func TestStreamShedHighestFirst(t *testing.T) {
	const w = 256 << 10
	s := stSession(stOpt{role: RolePassive, window: w})
	budget := s.env.Carrier.Budget
	l, _ := stAddLane(s, 1, false)
	want := stPattern(0, w)
	deliver := func(off, n int) {
		t.Helper()
		if err := stDeliverData(l, uint64(off), want[off:off+n]); err != nil {
			t.Fatalf("frame [%d,+%d): %v", off, n, err)
		}
		if err := stRecvInvariants(s, true); err != nil {
			t.Fatalf("frame [%d,+%d): %v", off, n, err)
		}
	}
	dropped := func() int { return int(stLocked(s, func(st *stream) uint64 { return st.oooDropped })) }
	ooqOffs := func() []int {
		return stLocked(s, func(st *stream) []int {
			var o []int
			for i := range st.ooq.s {
				o = append(o, int(st.ooq.s[i].off))
			}
			return o
		})
	}
	// Isolated 100-byte frames out of order, a run each, until the cap
	// drops one.
	var offs []int
	for k := 0; ; k++ {
		off := 128<<10 + k*1024
		d := dropped()
		deliver(off, 100)
		if dropped() > d {
			break
		}
		offs = append(offs, off)
	}
	if len(offs) != int(2*w/runCap) || dropped() != 100 {
		t.Fatalf("stimulus: %d runs held, %d bytes dropped; want %d runs and one frame dropped", len(offs), dropped(), 2*w/runCap)
	}
	deliver(0, 64<<10) // in order: one more buffer takes the charge above 2·W
	kept := ooqOffs()
	if len(kept) == len(offs) {
		t.Fatal("stimulus missing: nothing was shed")
	}
	if !slices.Equal(kept, offs[:len(kept)]) {
		t.Fatalf("kept out-of-order segments %v, want the lowest %d of %v", kept, len(kept), offs)
	}
	if d := dropped() - 100; d != 100*(len(offs)-len(kept)) {
		t.Fatalf("%d bytes counted as shed, want %d", d, 100*(len(offs)-len(kept)))
	}
	if u := budget.Used(); u > 2*w {
		t.Fatalf("Budget charge %d above 2·W after shedding", u)
	}
	// The sender retransmits from rTail: the stream completes.
	end := offs[len(offs)-1] + 1024
	for off := 64 << 10; off < end; off += 64 << 10 {
		deliver(off, min(64<<10, end-off))
	}
	if got := stReadN(t, s, end); !bytes.Equal(got, want[:end]) {
		t.Fatal("the stream read back corrupted")
	}
	stEnd(s, errClosed)
	if u := budget.Used(); u != 0 {
		t.Fatalf("Budget.Used = %d after the end", u)
	}
}

// TestStreamDiscardShedsDuringReadCopy (V3, §4.7, L07): after Close,
// in-order data is consumed on arrival, but while a Read copy is in flight
// the consumed buffers are released only at that Read's commit. In-order
// data arriving in that window still raises the receive charge, so
// out-of-order data is shed exactly as in the normal path and the cap holds
// while the Read copies. The Read then loses the race ((0, net.ErrClosed))
// and its commit releases the consumed buffers.
func TestStreamDiscardShedsDuringReadCopy(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const w = 256 << 10
		var once sync.Once
		entered, release := make(chan struct{}), make(chan struct{})
		hooks := &testhooks.Hooks{ReadDequeued: func() {
			once.Do(func() {
				close(entered)
				<-release
			})
		}}
		s := stSession(stOpt{role: RolePassive, window: w, hooks: hooks})
		budget := s.env.Carrier.Budget
		l, _ := stAddLane(s, 1, false)
		want := stPattern(0, w)
		deliver := func(off, n int) {
			t.Helper()
			if err := stDeliverData(l, uint64(off), want[off:off+n]); err != nil {
				t.Fatalf("frame [%d,+%d): %v", off, n, err)
			}
			if err := stRecvInvariants(s, true); err != nil {
				t.Fatalf("frame [%d,+%d): %v", off, n, err)
			}
		}
		dropped := func() uint64 { return stLocked(s, func(st *stream) uint64 { return st.oooDropped }) }
		deliver(0, 1000)
		for k := 0; dropped() == 0; k++ {
			deliver(128<<10+k*1024, 100) // isolated: a run each, until the cap drops one
		}
		done := make(chan stIO, 1)
		go func() {
			n, err := s.Read(make([]byte, 1000))
			done <- stIO{n, err}
		}()
		<-entered // the Read copies [0, 1000) outside the lock
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		before := dropped()
		deliver(1000, 64<<10) // consumed on arrival; its buffer waits for the commit
		st := stLocked(s, func(st *stream) [3]uint64 {
			return [3]uint64{st.delivered, uint64(len(st.ooq.s)), uint64(st.inq.n)}
		})
		if st[0] != 1000+64<<10 || st[2] == 0 {
			t.Fatalf("delivered %d with %d in-order segments, want %d consumed and their release deferred", st[0], st[2], 1000+64<<10)
		}
		if dropped() == before || st[1] == 0 {
			t.Fatalf("stimulus: %d bytes shed, %d out-of-order segments left; want some shed and some kept", dropped()-before, st[1])
		}
		close(release)
		if r := <-done; r.n != 0 || !errors.Is(r.err, net.ErrClosed) {
			t.Fatalf("Read = (%d, %v), want (0, net.ErrClosed): Close won", r.n, r.err)
		}
		if err := stRecvInvariants(s, true); err != nil {
			t.Fatalf("after the Read's commit: %v", err)
		}
		if n := stLocked(s, func(st *stream) int { return st.inq.n }); n != 0 {
			t.Fatalf("%d consumed in-order segments still held after the commit", n)
		}
		stEnd(s, errClosed)
		if u := budget.Used(); u != 0 {
			t.Fatalf("Budget.Used = %d after the end", u)
		}
	})
}

// TestStreamOOODropsRecoveredByRescue (V3, D13, §4.11): out-of-order bytes
// dropped at the receive cap are not lost: the sender still holds them and
// retransmits them. A bond pair sends 600-byte frames over two lanes, one
// frame per lane in turn; lane 2's frames are held in flight, so lane 1's
// arrive isolated, a run each, until the cap drops the rest. When lane 2's
// frames arrive, the receiver delivers up to the first dropped frame and
// stalls there: nothing resends a dropped frame by itself. Each stall is
// resolved as the actor's rescue resolves it: the lane holding the stuck
// head is found and the other lane sends the duplicate. The receiver reads
// the whole stream byte-exact, every byte is acknowledged and every buffer
// returns. (Recovery needs a lane other than the holder; while the holder is
// the only data lane, nothing resends its dropped bytes.)
func TestStreamOOODropsRecoveredByRescue(t *testing.T) {
	const (
		w     = 256 << 10
		seg   = 600
		total = 160 << 10
	)
	p := stNewPair(stOpt{mode: ModeBond, window: w, segment: seg}, stOpt{window: w}, 2)
	stWatchCopies(t, p.b)
	for _, fp := range p.ap {
		fp.set(func(f *stPort) { f.capacity = seg }) // one frame per Fill
	}
	data := stPattern(0, total)
	if n, err := p.a.Write(data); n != total || err != nil {
		t.Fatalf("Write = (%d, %v)", n, err)
	}
	type wframe struct {
		h    wire.Header
		off  uint64
		body []byte
	}
	var inFlight []wframe // lane 2's frames, delayed
	now := time.Now()
	for {
		n1, _ := p.step(0, true, now) // lane 1: delivered at once
		b := p.batch
		b.Reset(now)
		p.al[1].Fill(nil, b)
		n2 := b.Len()
		for i := range n2 {
			f := b.Frame(i)
			body := f.Payload
			if f.Header.Type == wire.TypeData {
				body = f.Body
			}
			inFlight = append(inFlight, wframe{f.Header, f.Off, bytes.Clone(body)})
		}
		b.ReleaseRefs()
		if n1 == 0 && n2 == 0 {
			break
		}
	}
	recv := func() [3]uint64 {
		return stLocked(p.b, func(st *stream) [3]uint64 { return [3]uint64{st.rRead, st.rTail, st.oooDropped} })
	}
	if v := recv(); v[2] == 0 || stLocked(p.a, func(st *stream) uint64 { return st.sNext }) != total {
		t.Fatalf("stimulus: %d bytes dropped by the receiver, want some, with every byte sent", v[2])
	}
	for _, f := range inFlight {
		var err error
		if f.h.Type == wire.TypeData {
			err = stDeliverData(p.bl[1], f.off, f.body)
		} else {
			err = p.bl[1].Control(nil, f.h, f.body)
		}
		if err != nil {
			t.Fatalf("lane 2 frame %v at %d: %v", f.h.Type, f.off, err)
		}
	}
	var got []byte
	readAll := func() {
		v := recv()
		if n := int(v[1] - v[0]); n > 0 {
			got = append(got, stReadN(t, p.b, n)...)
		}
		p.pump(true) // ACKs back, and anything the sender may send
	}
	rescues := 0
	for readAll(); len(got) < total; readAll() {
		// Stalled at a dropped frame: nothing moves by itself.
		stuck := recv()[1]
		if p.pump(true); recv()[1] != stuck {
			t.Fatalf("progress at %d without a rescue", stuck)
		}
		p.a.mu.Lock()
		holder, sp, ok := p.a.rescueHolderLocked()
		if ok {
			p.a.st.rescue = rescueSlot{set: true, sp: sp, holder: holder}
			p.a.routingChangedLocked()
		}
		p.a.mu.Unlock()
		if !ok || sp.off != stuck {
			t.Fatalf("stalled at %d: rescue span %v (ok %v), want one starting there", stuck, sp, ok)
		}
		rescues++
		other := 0
		if holder == p.al[0] {
			other = 1
		}
		fs, b := stFill(holder, now) // the holder keeps its original
		b.ReleaseRefs()
		if stCount(fs, wire.TypeData) != 0 {
			t.Fatalf("the holder sent %v while a rescue was pending", fs)
		}
		fs, b = stFill(p.al[other], now)
		if len(fs) == 0 || fs[0].typ != wire.TypeData || fs[0].off != sp.off || !fs[0].retx {
			t.Fatalf("the other lane sent %v, want the duplicate of [%d,+%d) first", fs, sp.off, sp.n)
		}
		if err := stDeliver(b, p.bl[other]); err != nil {
			t.Fatal(err)
		}
		b.ReleaseRefs()
		if recv()[1] <= stuck {
			t.Fatalf("the rescue of [%d,+%d) did not advance the receiver", sp.off, sp.n)
		}
	}
	if !bytes.Equal(got, data) {
		t.Fatal("the stream read back corrupted")
	}
	if b := stLocked(p.a, func(st *stream) uint64 { return st.sBase }); b != total {
		t.Fatalf("sender sBase %d, want %d: not every byte acknowledged", b, total)
	}
	if errs := p.errors(); len(errs) != 0 {
		t.Fatalf("violations: %v", errs)
	}
	t.Logf("%d bytes dropped by the receiver, recovered by %d rescues", recv()[2], rescues)
	if rescues == 0 {
		t.Fatal("stimulus missing: no rescue was needed")
	}
	p.close(t)
}

// TestStreamRecvCapProperty (V3): random mixes of tiny, small and large DATA
// frames of one consistent stream — out of order, duplicated, overlapping,
// re-cut, and isolated tiny frames that each need a run — inside a window
// that slides as the application reads and ACKs are placed, interleaved
// with partial reads and, for odd seeds, a Close that switches to discard
// mode, keep the receive structure exact after every call
// (stRecvInvariants: the counted charge is the Budget charge, one segment
// per buffer, inq and ooq well formed, the cap in force while out-of-order
// data is held), every call copies fewer than 16 KiB and oooDropped only
// grows. Across the seeds the cap binds, out-of-order data is dropped and
// shed, and segments are promoted (stimulus). A final retransmission
// completes the stream, which reads back exact.
func TestStreamRecvCapProperty(t *testing.T) {
	const (
		w     = 256 << 10
		total = 4 * w
	)
	var capHits, drops, sheds, promotions, closedDone int
	var worst float64 // the in-order charge per window with nothing out of order
	for seed := range uint64(24) {
		rng := rand.New(rand.NewPCG(seed, 61))
		s := stSession(stOpt{role: RolePassive, window: w})
		budget := s.env.Carrier.Budget
		stWatchCopies(t, s)
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
			if err := stRecvInvariants(s, true); err != nil {
				t.Fatalf("seed %d %s: %v", seed, when, err)
			}
			d := stLocked(s, func(st *stream) uint64 { return st.oooDropped })
			inOnly := stLocked(s, func(st *stream) bool { return len(st.ooq.s) == 0 })
			if d < dropped {
				t.Fatalf("seed %d %s: oooDropped went back from %d to %d", seed, when, dropped, d)
			}
			dropped = d
			if inOnly {
				worst = max(worst, float64(budget.Used())/w)
			}
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
			hi := int(min(v[2], total))
			switch r := rng.IntN(16); {
			case r < 3: // an isolated tiny frame beyond the in-order end: a run of its own
				span := (hi - int(v[1])) / 64
				if span < 2 {
					continue
				}
				off := int(v[1]) + 64*(1+rng.IntN(span-1)) + 7
				deliver(off, min(1+rng.IntN(8), hi-off))
			case r < 13: // a frame in the window (a little below rRead too), or at the in-order end
				lo := max(int(v[0])-4<<10, 0)
				off := lo + rng.IntN(int(v[2])-lo)
				if r >= 11 {
					off = int(v[1])
				}
				if off >= hi {
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
				deliver(off, min(n, hi-off))
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
	t.Logf("cap binding %d times, %d dropping calls (%d sheds), %d promotions; in-order charge peaked at %.2f·W", capHits, drops, sheds, promotions, worst)
	if capHits == 0 || drops == 0 || sheds == 0 || promotions == 0 || closedDone == 0 {
		t.Fatalf("stimulus missing: cap binding %d, drops %d, sheds %d, promotions %d, discard-mode runs %d",
			capHits, drops, sheds, promotions, closedDone)
	}
}
