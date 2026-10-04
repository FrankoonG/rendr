package carrier

import (
	"runtime"
	"sync"
	"testing"
)

// poolDrops reports whether sync.Pool drops items, which it does on purpose
// under the race detector. Allocation counts of pool-backed paths are then
// not asserted: allocation gates belong to the non-race lane (design §11.1);
// the code paths still run and their accounting is still checked.
func poolDrops() bool {
	var p sync.Pool
	p.New = func() any { return new([64]byte) }
	x := p.Get()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range 1000 {
		p.Put(x)
		x = p.Get()
	}
	runtime.ReadMemStats(&after)
	return after.Mallocs-before.Mallocs > 100
}

func mustPanic(t *testing.T, name string, f func()) {
	t.Helper()
	defer func() {
		t.Helper()
		if recover() == nil {
			t.Errorf("%s: no panic", name)
		}
	}()
	f()
}

// TestBufClasses: Get returns the smallest of the seven classes 2^k + 64
// (k = 14..20) that holds n bytes, for every class edge.
func TestBufClasses(t *testing.T) {
	p := NewBufPool()
	sizes := []int{0, 1, BigData, ChunkSize, MaxClass, MaxClass + ClassSlack}
	for k := minClassShift; k <= maxClassShift; k++ {
		for d := -2; d <= 2; d++ {
			sizes = append(sizes, 1<<k+ClassSlack+d, 1<<k+d)
		}
	}
	for _, n := range sizes {
		if n < 0 || n > MaxClass+ClassSlack {
			continue
		}
		c := classFor(n)
		b := p.Get(n, nil)
		if len(b.B) != classSize(c) || len(b.B) < n || cap(b.B) != len(b.B) {
			t.Errorf("Get(%d): len %d cap %d, class %d of %d bytes", n, len(b.B), cap(b.B), c, classSize(c))
		}
		if c > 0 && classSize(c-1) >= n {
			t.Errorf("Get(%d): class %d is not the smallest (class %d holds %d)", n, c, c-1, classSize(c-1))
		}
		if want := 1<<(minClassShift+c) + ClassSlack; len(b.B) != want {
			t.Errorf("Get(%d): len %d, want 2^%d+64", n, len(b.B), minClassShift+c)
		}
		b.Release()
	}
	if got := classSize(numClasses - 1); got != MaxClass+ClassSlack {
		t.Fatalf("largest class %d, want MaxClass+ClassSlack", got)
	}
	mustPanic(t, "Get(-1)", func() { p.Get(-1, nil) })
	mustPanic(t, "Get(max+1)", func() { p.Get(MaxClass+ClassSlack+1, nil) })
	mustPanic(t, "TryGet(max+1)", func() { p.TryGet(MaxClass+ClassSlack+1, NewBudget(1<<30)) })
}

// TestBufClassBoundaryLookAhead_L42 (C15) sweeps every big-DATA payload size
// n = 2^k+30 … 2^k+64 for k = 14, 15, 16 at the Buf level: the reader reads
// payload, trailer and the next frame's header and offset into
// Get(n+LookAhead).B[:n+LookAhead], which always fits, while the pre-C15
// bound n+4+LookAhead overflowed the class at the top of each class.
func TestBufClassBoundaryLookAhead_L42(t *testing.T) {
	p := NewBufPool()
	bud := NewBudget(1 << 30)
	next := []byte{0x10, 0, 0, 9, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 7} // header + offset of the next frame
	for k := 14; k <= 16; k++ {
		overflowed := 0
		for n := 1<<k + 30; n <= 1<<k+64; n++ {
			b := p.Get(n+LookAhead, bud)
			if len(b.B) < n+LookAhead {
				t.Fatalf("n=%d: Get(n+LookAhead) holds %d bytes", n, len(b.B))
			}
			if n+4+LookAhead > len(b.B) {
				overflowed++
			}
			// One read in steady state: payload ‖ trailer ‖ look-ahead.
			win := b.B[:n+LookAhead]
			for i := range n {
				win[i] = byte(i * 7)
			}
			copy(win[n:], []byte{0xde, 0xad, 0xbe, 0xef})
			copy(win[n+4:], next)
			if win[n] != 0xde || win[n+3] != 0xef || string(win[n+4:]) != string(next) || win[n-1] != byte((n-1)*7) {
				t.Fatalf("n=%d: window contents corrupted", n)
			}
			b.Release()
		}
		// Stimulus proof: the sweep reached the sizes where the old bound
		// would have sliced beyond the class (n+25 in (2^k+60, 2^k+64]).
		if overflowed != 4 {
			t.Fatalf("k=%d: %d sizes where n+4+LookAhead exceeds the class, want 4", k, overflowed)
		}
	}
	if bud.Used() != 0 {
		t.Fatalf("budget %d after every buffer was released", bud.Used())
	}
}

// TestBudgetAccounting: TryAcquire never exceeds max, Acquire is a forced
// charge, Release returns exactly what was charged; concurrent users never
// observe usage above max through TryAcquire.
func TestBudgetAccounting(t *testing.T) {
	b := NewBudget(1000)
	if b.Max() != 1000 || b.Used() != 0 {
		t.Fatalf("new budget: max %d used %d", b.Max(), b.Used())
	}
	steps := []struct {
		try  int64
		ok   bool
		used int64
	}{{600, true, 600}, {500, false, 600}, {400, true, 1000}, {1, false, 1000}}
	for _, s := range steps {
		if ok := b.TryAcquire(s.try); ok != s.ok || b.Used() != s.used {
			t.Fatalf("TryAcquire(%d) = %v, used %d; want %v, %d", s.try, ok, b.Used(), s.ok, s.used)
		}
	}
	b.Acquire(50) // forced: a promised receive buffer
	if b.Used() != 1050 || b.TryAcquire(1) {
		t.Fatalf("after a forced charge: used %d", b.Used())
	}
	b.Release(1050)
	if b.Used() != 0 {
		t.Fatalf("used %d after releasing everything", b.Used())
	}

	const workers, rounds, unit, max = 8, 5000, 7, 100
	cb := NewBudget(max)
	var wg sync.WaitGroup
	var bad, granted sync.Map
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n := 0
			for range rounds {
				if cb.TryAcquire(unit) {
					n++
					if u := cb.Used(); u > max {
						bad.Store(w, u)
					}
					cb.Release(unit)
				}
			}
			granted.Store(w, n)
		}()
	}
	wg.Wait()
	bad.Range(func(k, v any) bool { t.Errorf("worker %v saw usage %v > %d", k, v, max); return true })
	total := 0
	granted.Range(func(_, v any) bool { total += v.(int); return true })
	if total == 0 || cb.Used() != 0 {
		t.Fatalf("concurrent use: %d grants, final usage %d", total, cb.Used())
	}
}

// TestBufRefcountAndBudget: a Buf charges its class capacity once, survives
// every Release but the last, and uncharges exactly once.
func TestBufRefcountAndBudget(t *testing.T) {
	p := NewBufPool()
	bud := NewBudget(1 << 30)
	b := p.Get(ChunkSize, bud)
	if b.refs.Load() != 1 || bud.Used() != int64(classSize(2)) || len(b.B) != ChunkSize+ClassSlack {
		t.Fatalf("Get(ChunkSize): refs %d used %d len %d", b.refs.Load(), bud.Used(), len(b.B))
	}
	b.Ref()
	b.Ref()
	b.Release()
	b.Release()
	if b.refs.Load() != 1 || bud.Used() != int64(classSize(2)) {
		t.Fatalf("after 2 refs and 2 releases: refs %d used %d", b.refs.Load(), bud.Used())
	}
	b.Release()
	if b.refs.Load() != 0 || bud.Used() != 0 {
		t.Fatalf("after the last release: refs %d used %d", b.refs.Load(), bud.Used())
	}
	var nilBuf *Buf
	nilBuf.Release() // no-op

	// TryGet: refused without charging; Get: forced beyond max.
	small := NewBudget(int64(classSize(2)))
	a := p.TryGet(ChunkSize, small)
	if a == nil || small.Used() != small.Max() {
		t.Fatalf("TryGet within budget: %v used %d", a, small.Used())
	}
	if c := p.TryGet(1, small); c != nil || small.Used() != small.Max() {
		t.Fatalf("TryGet beyond budget: %v used %d", c, small.Used())
	}
	forced := p.Get(BigData, small)
	if small.Used() != small.Max()+int64(classSize(0)) {
		t.Fatalf("forced Get: used %d", small.Used())
	}
	forced.Release()
	a.Release()
	if c := p.TryGet(ChunkSize, small); c == nil {
		t.Fatal("TryGet after the budget freed up returned nil")
	} else {
		c.Release()
	}
	// A nil budget charges nothing.
	u := p.Get(MaxClass, nil)
	if len(u.B) != MaxClass+ClassSlack || u.budget != nil {
		t.Fatalf("Get with a nil budget: len %d budget %v", len(u.B), u.budget)
	}
	u.Release()
	if small.Used() != 0 || bud.Used() != 0 {
		t.Fatalf("budgets after release: %d, %d", small.Used(), bud.Used())
	}
}

// TestBufSharedAcrossGoroutines: references handed to several goroutines
// (the batch writer, the session, a reader) are released concurrently; the
// last one returns the buffer exactly once (run under -race).
func TestBufSharedAcrossGoroutines(t *testing.T) {
	p := NewBufPool()
	bud := NewBudget(1 << 30)
	for range 200 {
		b := p.Get(ChunkSize, bud)
		const holders = 8
		for range holders - 1 {
			b.Ref()
		}
		var wg sync.WaitGroup
		for range holders {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = b.B[0]
				b.Release()
			}()
		}
		wg.Wait()
		if bud.Used() != 0 {
			t.Fatalf("budget %d after every holder released", bud.Used())
		}
	}
}

// TestBufDoubleRelease: a double Release is a bug. The rendrdebug build
// (go test -tags rendrdebug) panics on it, on a Ref of a released buffer and
// on a Budget released below zero, and poisons released buffers; a normal
// build ignores a double Release without uncharging or pooling twice.
func TestBufDoubleRelease(t *testing.T) {
	p := NewBufPool()
	bud := NewBudget(1 << 30)
	b := p.Get(BigData, bud)
	b.B[0] = 1
	b.Release()
	if !bufDebug {
		b.Release() // ignored
		if bud.Used() != 0 {
			t.Fatalf("a double release uncharged twice: used %d", bud.Used())
		}
		return
	}
	if b.B[0] != 0xdb || b.B[len(b.B)-1] != 0xdb {
		t.Errorf("released buffer not poisoned: %#x %#x", b.B[0], b.B[len(b.B)-1])
	}
	mustPanic(t, "double Release", func() { b.Release() })
	c := p.Get(BigData, nil)
	c.Release()
	mustPanic(t, "Ref after release", func() { c.Ref() })
	mustPanic(t, "Budget below zero", func() { NewBudget(10).Release(1) })
}

// TestBufPoolZeroAllocs_L41: in steady state Get, TryGet, Ref and Release
// allocate nothing (warm per-class pools).
func TestBufPoolZeroAllocs_L41(t *testing.T) {
	p := NewBufPool()
	bud := NewBudget(1 << 30)
	cycle := func() {
		b := p.Get(ChunkSize, bud)
		b.Ref()
		b.Release()
		b.Release()
		c := p.TryGet(BigData+LookAhead, bud)
		c.Release()
	}
	cycle()
	allocs := testing.AllocsPerRun(1000, cycle)
	if bud.Used() != 0 {
		t.Fatalf("budget %d after the cycles", bud.Used())
	}
	if poolDrops() {
		t.Logf("sync.Pool drops items (race detector): %v allocs per cycle not asserted", allocs)
		return
	}
	if allocs != 0 {
		t.Fatalf("%v allocations per Get/Ref/Release cycle", allocs)
	}
}
