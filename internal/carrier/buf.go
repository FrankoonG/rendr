package carrier

import (
	"math/bits"
	"sync"
	"sync/atomic"
)

// Buffer sizes.
const (
	// ChunkSize is the send-buffer chunk span: chunk k of a session covers
	// stream offsets [k·ChunkSize, (k+1)·ChunkSize). Chunks never move.
	ChunkSize = 64 << 10
	// BigData is the DATA payload size from which a reader reads the payload
	// straight into its own Buf and hands it to the session by reference;
	// smaller payloads are copied by the session into run buffers.
	BigData = 16 << 10
	// LookAhead is what a reader may read past a large payload in the same
	// Read call, the trailer included: trailer (4) + next header (13) + next
	// DATA offset (8). A big DATA payload of n bytes is read into
	// Get(n + LookAhead) and never past B[n+LookAhead] (design §4.9).
	LookAhead = 25
	// ClassSlack is the extra capacity of every size class (room for LookAhead).
	ClassSlack = 64
	// MaxClass is the largest size-class payload (MaxFramePayload).
	MaxClass = 1 << 20
)

// Size classes: class c holds 2^(minClassShift+c) + ClassSlack bytes
// (16 KiB + 64 … 1 MiB + 64, design §4.1).
const (
	minClassShift = 14
	maxClassShift = 20
	numClasses    = maxClassShift - minClassShift + 1
)

// classSize returns the capacity of class c.
func classSize(c int) int { return 1<<(minClassShift+c) + ClassSlack }

// classFor returns the smallest class whose capacity is at least n. It
// panics if n is negative or larger than MaxClass + ClassSlack.
func classFor(n int) int {
	if n < 0 || n > MaxClass+ClassSlack {
		panic("rendr/carrier: buffer size out of range")
	}
	if n <= 1<<minClassShift+ClassSlack {
		return 0
	}
	return bits.Len(uint(n-ClassSlack-1)) - minClassShift
}

// Budget is the Runtime-wide MaxBufferedBytes account (plan §3.7). Usage is
// one atomic counter; there is no lock and no waiter list (app writers that
// find the budget exhausted re-check on a timer, design §4.2).
type Budget struct {
	used atomic.Int64
	max  int64
}

// NewBudget returns a budget of max bytes.
func NewBudget(max int64) *Budget {
	return &Budget{max: max}
}

// TryAcquire charges n bytes unless that would exceed max (send chunks).
func (b *Budget) TryAcquire(n int64) bool {
	for {
		u := b.used.Load()
		if u+n > b.max {
			return false
		}
		if b.used.CompareAndSwap(u, u+n) {
			return true
		}
	}
}

// Acquire charges n bytes unconditionally (receive buffers inside an
// already advertised window; they were promised).
func (b *Budget) Acquire(n int64) {
	b.used.Add(n)
}

// Release returns n bytes.
func (b *Budget) Release(n int64) {
	if b.used.Add(-n) < 0 && bufDebug {
		b.used.Add(n) // the panic is the only effect
		panic("rendr/carrier: Budget released below zero")
	}
}

// Used returns the bytes currently charged.
func (b *Budget) Used() int64 {
	return b.used.Load()
}

// Max returns the budget size.
func (b *Budget) Max() int64 {
	return b.max
}

// Buf is a pooled, reference-counted byte buffer of one size class
// (2^k + ClassSlack bytes, 16 KiB ≤ 2^k ≤ 1 MiB). It is the only storage for
// send chunks and for received DATA payloads. A Buf starts with one
// reference; it returns to its pool and uncharges its Budget when the last
// reference is released. A Buf that was handed to an embedder call that may
// still be running is never released (it is dropped to the GC).
type Buf struct {
	// B is the whole buffer (len == class capacity). Owners slice it.
	B []byte

	full   []byte       // the class buffer; B is reset to it by every Get
	refs   atomic.Int32 // references; 0 while pooled
	class  uint8
	pool   *BufPool
	budget *Budget // charged with the class capacity; nil: uncharged
}

// Ref adds a reference. It must only be called by a holder of a reference.
func (b *Buf) Ref() {
	if b.refs.Add(1) <= 1 && bufDebug {
		b.refs.Add(-1) // the panic is the only effect
		panic("rendr/carrier: Buf.Ref on a released buffer")
	}
}

// Release drops a reference; the last one returns b to its pool and
// uncharges its Budget. Releasing more often than referencing panics in
// tests (debug build tag) and is a bug. Release on a nil Buf does nothing.
func (b *Buf) Release() {
	if b == nil {
		return
	}
	n := b.refs.Add(-1)
	if n > 0 {
		return
	}
	if n < 0 {
		// A double release. Production builds ignore it rather than pool
		// the buffer twice; the rendrdebug build makes it fatal.
		if bufDebug {
			b.refs.Add(1) // the panic is the only effect
			panic("rendr/carrier: Buf released more often than referenced")
		}
		return
	}
	if bud := b.budget; bud != nil {
		b.budget = nil
		bud.Release(int64(len(b.full)))
	}
	if bufDebug {
		poison(b.full)
	}
	b.pool.pools[b.class].Put(b)
}

// poison overwrites a released buffer (rendrdebug builds) so that a use
// after release shows up as corrupted data and CRC failures in tests.
func poison(b []byte) {
	for i := range b {
		b[i] = 0xdb
	}
}

// BufPool is the Runtime-wide set of size-class pools (one sync.Pool per
// class). It is safe for concurrent use and allocation-free in steady state.
type BufPool struct {
	pools [numClasses]sync.Pool
}

// NewBufPool returns an empty pool.
func NewBufPool() *BufPool {
	p := &BufPool{}
	for c := range p.pools {
		size, class := classSize(c), uint8(c)
		p.pools[c].New = func() any {
			full := make([]byte, size)
			return &Buf{B: full, full: full, class: class, pool: p}
		}
	}
	return p
}

// Get returns a Buf of the smallest class with len(B) ≥ n (n ≤ MaxClass +
// ClassSlack), charging its capacity to budget unconditionally (nil budget:
// uncharged). It panics if n is too large (programming error).
func (p *BufPool) Get(n int, budget *Budget) *Buf {
	c := classFor(n)
	if budget != nil {
		budget.Acquire(int64(classSize(c)))
	}
	return p.take(c, budget)
}

// TryGet is Get with budget.TryAcquire: it returns nil when the budget
// refuses the class capacity.
func (p *BufPool) TryGet(n int, budget *Budget) *Buf {
	c := classFor(n)
	if budget != nil && !budget.TryAcquire(int64(classSize(c))) {
		return nil
	}
	return p.take(c, budget)
}

// take hands out one Buf of class c already charged to budget.
func (p *BufPool) take(c int, budget *Budget) *Buf {
	b := p.pools[c].Get().(*Buf)
	if bufDebug && b.refs.Load() != 0 {
		panic("rendr/carrier: pooled Buf is still referenced")
	}
	b.B = b.full
	b.budget = budget
	b.refs.Store(1)
	return b
}
