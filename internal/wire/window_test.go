package wire

import (
	"math"
	"math/rand/v2"
	"runtime"
	"testing"
)

// fseqModel is a map model of FseqWindow's specification (M2 design
// §A3.7): after Init(first) the FseqWindowBits fseqs before first count as
// seen; an fseq newer than the newest (serial arithmetic) is new and
// becomes the newest; one FseqWindowBits or more behind the newest is late;
// a seen one is a duplicate; any other is new once.
type fseqModel struct {
	top  uint32
	seen map[uint32]bool
}

func newFseqModel(first uint32) *fseqModel {
	m := &fseqModel{top: first - 1, seen: map[uint32]bool{}}
	for i := range uint32(FseqWindowBits) {
		m.seen[first-1-i] = true
	}
	return m
}

func (m *fseqModel) accept(f uint32) WindowVerdict {
	if f != m.top && int32(f-m.top) > 0 {
		// Forget what leaves the window: the d numbers from top − 1023 on,
		// or everything after a jump of the width or more (so a number seen
		// one lap of 2^32 ago is never taken for seen).
		if d := f - m.top; d >= FseqWindowBits {
			clear(m.seen)
		} else {
			for v := m.top - (FseqWindowBits - 1); v != f-(FseqWindowBits-1); v++ {
				delete(m.seen, v)
			}
		}
		m.top = f
		m.seen[f] = true
		return WindowNew
	}
	if m.top-f >= FseqWindowBits {
		return WindowLate
	}
	if m.seen[f] {
		return WindowDuplicate
	}
	m.seen[f] = true
	return WindowNew
}

// seqModel is a map model of SeqWindow's specification (§A3.7): the first
// accepted seq is new and the newest; a seq after the newest is new and
// becomes the newest; one at least the width behind the newest is late; a
// seen one a duplicate; any other new once.
type seqModel struct {
	width   uint64
	started bool
	top     uint64
	seen    map[uint64]bool
}

func newSeqModel(width uint64) *seqModel { return &seqModel{width: width, seen: map[uint64]bool{}} }

func (m *seqModel) accept(s uint64) WindowVerdict {
	switch {
	case !m.started || s > m.top:
		if d := s - m.top; !m.started || d >= m.width {
			clear(m.seen)
		} else {
			for i := range d { // forget top − width + 1 … s − width
				if m.top+1+i >= m.width {
					delete(m.seen, m.top+1+i-m.width)
				}
			}
		}
		m.started, m.top = true, s
		m.seen[s] = true
		return WindowNew
	case m.top-s >= m.width:
		return WindowLate
	case m.seen[s]:
		return WindowDuplicate
	}
	m.seen[s] = true
	return WindowNew
}

// nearMove maps v (an int16) to a move relative to the newest of a window
// of the given width: negative values go back by up to 1.1·width, most of
// them a little (quadratic: reordered and duplicate arrivals, the rest
// late), non-negative ones forward by a small step (0 … width/64: loss),
// so the window keeps its history.
func nearMove(v, width int64) int64 {
	if v >= 0 {
		return v * width / (64 << 15)
	}
	return -(v * v * width * 11 / (10 << 30))
}

// nextFseq derives the next fseq a fuzz input offers from three op bytes
// and the model's newest: near it (nearMove), a jump either way up to
// ±2^27, the next in order, or an arbitrary value.
func nextFseq(top uint32, op [3]byte) uint32 {
	v := int32(int16(uint16(op[1])<<8 | uint16(op[2])))
	switch op[0] % 4 {
	case 0:
		return top + uint32(nearMove(int64(v), FseqWindowBits))
	case 1:
		return top + uint32(v<<12)
	case 2:
		return top + 1
	}
	return uint32(v) * 65537
}

// nextSeq is nextFseq for u64 seqs (jumps up to ±2^31).
func nextSeq(top, width uint64, op [3]byte) uint64 {
	v := int64(int16(uint16(op[1])<<8 | uint16(op[2])))
	switch op[0] % 4 {
	case 0:
		return top + uint64(nearMove(v, int64(width)))
	case 1:
		return top + uint64(v<<16)
	case 2:
		return top + 1
	}
	return uint64(v) * 0x9e3779b97f4a7c15
}

// randDelta draws the next number of the model tests relative to the
// newest of a window of width w: 45 % the next in order, 10 % a small gap
// of loss (+2 … +16), 20 % a recent one (0 … 31 behind: mostly
// duplicates), 12 % a reordered one (32 … w − 1 behind), 10 % a late one
// (w … 4w behind), 2 % a forward jump (w … w + 2^27) and 1 % an arbitrary
// value (arbitrary true: the caller draws it).
func randDelta(rng *rand.Rand, w int64) (d int64, arbitrary bool) {
	switch r := rng.IntN(100); {
	case r < 45:
		return 1, false
	case r < 55:
		return 2 + rng.Int64N(15), false
	case r < 75:
		return -rng.Int64N(32), false
	case r < 87:
		return -(32 + rng.Int64N(w-32)), false
	case r < 97:
		return -(w + rng.Int64N(3*w)), false
	case r < 99:
		return w + rng.Int64N(1<<27), false
	}
	return 0, true
}

// TestFseqWindow_L43_L14: the datagram fseq window (M2-D13, plan:333) —
// Init makes everything before the first fseq "seen"; a reordered fseq
// inside the 1024-frame window is accepted once (not strict +1), a repeated
// one is a duplicate, one 1024 or more behind the newest is late; jumps of
// 1024 or more clear the window; u32 serial arithmetic across 2^32 (L14:
// a preset near the limit wraps and keeps accepting); verdicts equal the map
// model under random reordering, duplication, loss and jumps; no
// allocation.
func TestFseqWindow_L43_L14(t *testing.T) {
	var w FseqWindow
	expect := func(f uint32, want WindowVerdict) {
		t.Helper()
		if got := w.Accept(f); got != want {
			t.Fatalf("Accept(%#x) = %d, want %d", f, got, want)
		}
	}
	// Init: the 1024 fseqs before first are seen, older ones late.
	first := uint32(100)
	w.Init(first)
	expect(first-1, WindowDuplicate)
	expect(first-1-1023, WindowDuplicate) // wraps below 0: serial arithmetic
	expect(first-1-1024, WindowLate)
	expect(first, WindowNew)
	expect(first, WindowDuplicate)
	// Loss and reordering: a gap is skipped, the late arrival is new once.
	expect(102, WindowNew)
	expect(101, WindowNew)
	expect(101, WindowDuplicate)
	expect(110, WindowNew)
	for f := uint32(103); f < 110; f++ {
		expect(f, WindowNew)
	}
	// The window edge: 1023 behind the newest is inside, 1024 late.
	top := uint32(110)
	expect(top-1023, WindowDuplicate) // before first: seen since Init
	expect(top-1024, WindowLate)
	// A jump of exactly 1023 keeps one old bit; 1024 or more clears all.
	expect(top+1023, WindowNew)
	expect(top, WindowDuplicate)
	expect(top+1, WindowNew) // passed over by the jump: new
	expect(top-1, WindowLate)
	top += 1023
	for _, jump := range []uint32{1024, 1025, 4096, 1 << 20, 1<<31 - 1} {
		top += jump
		expect(top, WindowNew)
		expect(top-1, WindowNew)    // inside the new window, never seen
		expect(top-1023, WindowNew) // the far edge, cleared by the jump
		expect(top-1023, WindowDuplicate)
		expect(top-1024, WindowLate)
	}
	// 2^31 ahead is not newer in serial arithmetic: late, never a jump.
	expect(top+1<<31, WindowLate)
	expect(top, WindowDuplicate)

	// L14: an fseq preset at the u32 limit keeps working across the wrap.
	w.Init(0xfffffffe)
	for i := range uint32(10) {
		expect(0xfffffffe+i, WindowNew)
	}
	expect(0xffffffff, WindowDuplicate)
	expect(0xfffffffd, WindowDuplicate) // before first
	w.Init(0xfffffffe)
	for _, f := range []uint32{0xffffffff, 2, 0, 1, 0xfffffffe, 3} { // reordered across the wrap
		expect(f, WindowNew)
	}
	expect(0, WindowDuplicate)

	// Against the map model: random reordering, duplication, loss and
	// jumps, from several starts (also across the wrap).
	rng := rand.New(rand.NewPCG(43, 14))
	for _, first := range []uint32{1, 0xfffffc00, 0x7fffffff, 0xfffffffe} {
		w.Init(first)
		m := newFseqModel(first)
		counts := [3]int{}
		for range 20000 {
			d, arbitrary := randDelta(rng, FseqWindowBits)
			f := m.top + uint32(d)
			if arbitrary {
				f = rng.Uint32()
			}
			got, want := w.Accept(f), m.accept(f)
			if got != want {
				t.Fatalf("first %#x: Accept(%#x) = %d, model %d", first, f, got, want)
			}
			counts[got]++
		}
		// Stimulus proof: every verdict occurred many times.
		for v, n := range counts {
			if n < 1000 {
				t.Fatalf("first %#x: verdict %d occurred %d times", first, v, n)
			}
		}
		t.Logf("first %#x: new %d, duplicate %d, late %d", first, counts[WindowNew], counts[WindowDuplicate], counts[WindowLate])
	}

	f := uint32(5)
	if a := testing.AllocsPerRun(1000, func() {
		f += 3
		sinkVerdict = w.Accept(f)
		sinkVerdict = w.Accept(f - 1)
		sinkVerdict = w.Accept(f - 1)
		sinkVerdict = w.Accept(f - 5000)
	}); a != 0 && !raceEnabled {
		t.Errorf("FseqWindow.Accept: %v allocs", a)
	}
	if grew := allocatedDuring(func() {
		for range 200000 {
			f += 2
			sinkVerdict = w.Accept(f)
			sinkVerdict = w.Accept(f - 1)
		}
	}); grew && !raceEnabled {
		t.Errorf("FseqWindow allocated while accepting 400,000 fseqs")
	}
}

// allocatedDuring reports whether run allocated: more than a few mallocs or
// a few KiB in raw MemStats counts (background runtime noise aside), which
// catches amortized growth that AllocsPerRun's rounded average hides.
func allocatedDuring(run func()) bool {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	run()
	runtime.ReadMemStats(&after)
	return after.Mallocs-before.Mallocs > 16 || after.TotalAlloc-before.TotalAlloc > 16<<10
}

// TestSeqWindow_L39: a packet session's dedup window (M2-D36) — with seq 0
// missing forever the window follows the newest seq, its state stays the
// fixed storage and Accept never allocates; a duplicate inside the window
// is reported, a seq the width or more behind the newest is late; the first
// accepted seq may be any (a reordered start loses nothing); seqs near 2^62
// and every storage size behave as the map model; Init clears its storage
// and rejects sizes that are not a power of two ≥ 16 words.
func TestSeqWindow_L39(t *testing.T) {
	storage := make([]uint64, DefaultSeqWindowBits/64)
	var w SeqWindow
	w.Init(storage)
	expect := func(s uint64, want WindowVerdict) {
		t.Helper()
		if got := w.Accept(s); got != want {
			t.Fatalf("Accept(%d) = %d, want %d", s, got, want)
		}
	}
	// seq 0 is missing forever: nothing is pinned.
	const n = 100000
	for s := uint64(1); s <= n; s++ {
		expect(s, WindowNew)
	}
	expect(0, WindowLate)
	expect(n, WindowDuplicate)
	expect(n-DefaultSeqWindowBits+1, WindowDuplicate)
	expect(n-DefaultSeqWindowBits, WindowLate)
	if len(w.bits) != len(storage) || &w.bits[0] != &storage[0] || cap(w.bits) != cap(storage) {
		t.Fatalf("the window's state is not the caller's storage")
	}
	s := uint64(n)
	if a := testing.AllocsPerRun(1000, func() {
		s++
		sinkVerdict = w.Accept(s)
		sinkVerdict = w.Accept(s)
		sinkVerdict = w.Accept(0)
		sinkVerdict = w.Accept(s + DefaultSeqWindowBits) // a jump: clears everything
	}); a != 0 && !raceEnabled {
		t.Errorf("SeqWindow.Accept: %v allocs", a)
	}
	// The state stays the fixed storage over a long run with seq 0 still
	// missing: raw allocation counts, not AllocsPerRun's rounded average,
	// so amortized growth (a map per seq) cannot hide.
	if grew := allocatedDuring(func() {
		for range 200000 {
			s++
			sinkVerdict = w.Accept(s)
			sinkVerdict = w.Accept(s - 7)
		}
	}); grew && !raceEnabled {
		t.Errorf("SeqWindow allocated while accepting 200,000 seqs")
	}

	// The first accepted seq may be any: earlier seqs inside the window are
	// new once. Init clears the storage of an earlier use.
	w.Init(storage)
	expect(500, WindowNew)
	expect(10, WindowNew)
	expect(10, WindowDuplicate)
	expect(499, WindowNew)
	expect(500, WindowDuplicate)
	w.Init(storage)
	expect(10, WindowNew)
	w.Init(storage)
	for i, word := range storage {
		if word != 0 {
			t.Fatalf("Init left word %d = %#x", i, word)
		}
	}
	expect(10, WindowNew)

	// Against the map model: every storage size, from a small start and
	// near 2^62 (the session ends there, L14), so the ring index wraps many
	// times; the session's seqs never wrap u64 (fuzzing covers arbitrary
	// values).
	rng := rand.New(rand.NewPCG(39, 62))
	for _, words := range []int{16, 32, 256, 1024} {
		width := uint64(words) * 64
		for _, start := range []uint64{4*width + 1, 1<<62 - 1<<34} {
			w.Init(make([]uint64, words))
			m := newSeqModel(width)
			if w.Accept(start) != WindowNew || m.accept(start) != WindowNew {
				t.Fatalf("the first seq is not new")
			}
			counts := [3]int{}
			top := start
			for range 20000 {
				d, arbitrary := randDelta(rng, int64(width))
				if arbitrary {
					d = 1
				}
				s := top + uint64(d)
				got, want := w.Accept(s), m.accept(s)
				if got != want {
					t.Fatalf("width %d start %#x: Accept(%#x) = %d, model %d", width, start, s, got, want)
				}
				counts[got]++
				top = m.top
			}
			for v, c := range counts {
				if c < 1000 {
					t.Fatalf("width %d start %#x: verdict %d occurred %d times", width, start, v, c)
				}
			}
			if m.top < start || m.top >= 1<<62 && start < 1<<61 {
				t.Fatalf("width %d: the newest %#x left the session's range from %#x", width, m.top, start)
			}
		}
	}

	// u64 seqs do not wrap: the largest seq is newer than everything.
	w.Init(storage)
	expect(math.MaxUint64-1, WindowNew)
	expect(math.MaxUint64, WindowNew)
	expect(0, WindowLate)
	expect(math.MaxUint64-1, WindowDuplicate)

	for _, words := range []int{0, 1, 8, 15, 17, 24, 100, 1000} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Init with %d words: no panic", words)
				}
			}()
			w.Init(make([]uint64, words))
		}()
	}
}
