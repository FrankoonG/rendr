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
	// MaxClass is the largest size-class payload of the stream pool
	// (MaxFramePayload).
	MaxClass = 1 << 20
)

// Size classes of the stream pool (NewBufPool): class c holds
// 2^(minClassShift+c) + ClassSlack bytes (16 KiB + 64 … 1 MiB + 64, design
// §4.1).
const (
	minClassShift = 14
	maxClassShift = 20
	numClasses    = maxClassShift - minClassShift + 1
)

// Size classes of the datagram pool (NewDatagramBufPool, M2-D28): class c
// holds 2^(minDgramShift+c) + ClassSlack bytes (2 KiB + 64 … 64 KiB + 64).
// The largest datagram buffer — wire.MaxDatagram plus a raw-UDP flow header
// plus the truncation byte — fits the largest class.
const (
	minDgramShift = 11
	maxDgramShift = 16
	numDgramClass = maxDgramShift - minDgramShift + 1
)

// classLayout is the size-class layout of one BufPool (M2 design Revision
// 1, R1-20): class c < n holds 2^(shift+c) + ClassSlack bytes. Making it a
// property of the pool lets the datagram pool use small classes while the
// stream pool keeps its classes, charges and allocation gates unchanged.
type classLayout struct {
	shift int // log2 of the smallest class payload
	n     int // number of classes (≤ numClasses, the length of BufPool.pools)
}

// The layouts of a Runtime's two pools: Env.Bufs and Env.DBufs.
var (
	streamLayout = classLayout{shift: minClassShift, n: numClasses}
	dgramLayout  = classLayout{shift: minDgramShift, n: numDgramClass}
)

// size returns the capacity of class c.
func (l classLayout) size(c int) int { return 1<<(l.shift+c) + ClassSlack }

// limit returns the largest size a Get of this layout accepts: the capacity
// of its largest class.
func (l classLayout) limit() int { return l.size(l.n - 1) }

// class returns the smallest class whose capacity is at least n. It panics
// if n is negative or larger than limit() (programming errors).
func (l classLayout) class(n int) int {
	if n < 0 || n > l.limit() {
		panic("rendr/carrier: buffer size out of range")
	}
	if n <= 1<<l.shift+ClassSlack {
		return 0
	}
	return bits.Len(uint(n-ClassSlack-1)) - l.shift
}

// classSize returns the capacity of stream-pool class c.
func classSize(c int) int { return streamLayout.size(c) }

// classFor returns the smallest stream-pool class whose capacity is at
// least n. It panics if n is negative or larger than MaxClass + ClassSlack.
func classFor(n int) int { return streamLayout.class(n) }

// Budget is a byte account; a Buf releases its charge to the Budget it was
// charged to. A Runtime has two (design §0.14 B2). Env.Budget is the
// MaxBufferedBytes account of the data buffers (plan §3.7): send chunks,
// packet-queue storage, received datagrams of 16 KiB or more and udpflow
// inbox buffers (TryAcquire or TryGet, which may refuse), receive buffers
// inside an advertised window and stream write scratches (Acquire, forced);
// its usage drives the window advertisement. Env.Stages is the fixed
// account of the buffers carriers and flows hold for a handshake or for
// their whole life: a stream carrier's reader stage (16 KiB + ClassSlack
// per started carrier), a datagram carrier's handshake and reader buffers
// and its writer scratch (datagram-pool classes, M2-D28, M2-D60), and a
// udpflow flow's control-reserve buffers (M2 design §A6.2). Only forced
// charges use it, so its max is never consulted. Status.BufferedBytes is
// the sum of both. A udpflow source's own read buffer (one per source) is
// in neither while it waits for the socket: it holds no data (R-C3-2).
// Usage is one atomic counter; there is no lock and no waiter list (app
// writers that find the budget exhausted re-check on a timer, design §4.2).
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

// Buf is a pooled, reference-counted byte buffer of one size class of its
// pool (2^k + ClassSlack bytes: 16 KiB ≤ 2^k ≤ 1 MiB in the stream pool,
// 2 KiB ≤ 2^k ≤ 64 KiB in the datagram pool). It is the only storage for
// send chunks, received DATA payloads and datagram buffers. A Buf starts
// with one reference; it returns to the pool it came from and uncharges its
// Budget when the last reference is released. A Buf that was handed to an
// embedder call that may still be running is never released (it is dropped
// to the GC).
type Buf struct {
	// B is the whole buffer (len == class capacity). Owners slice it.
	B []byte

	full   []byte       // the class buffer; B is reset to it by every Get
	refs   atomic.Int32 // references; 0 while pooled
	class  uint8
	pool   *BufPool
	budget *Budget // charged with the class capacity; nil: uncharged
}

// TryCharge charges b, taken uncharged (Get with a nil budget), to budget
// with TryAcquire and reports whether b is now charged to it; a nil budget
// charges nothing and succeeds. Only b's sole holder calls it, before b is
// shared: a udpflow source's read buffer is charged when the datagram read
// into it moves to a flow's inbox (R-C3-2).
func (b *Buf) TryCharge(budget *Budget) bool {
	if budget == nil {
		return true
	}
	if b.budget != nil || !budget.TryAcquire(int64(len(b.full))) {
		return false
	}
	b.budget = budget
	return true
}

// Uncharge returns b's charge: TryCharge undone by b's sole holder.
func (b *Buf) Uncharge() {
	if bud := b.budget; bud != nil {
		b.budget = nil
		bud.Release(int64(len(b.full)))
	}
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

// BufPool is a Runtime-wide set of size-class pools (one sync.Pool per
// class) with its own class layout: the stream pool (NewBufPool, Env.Bufs)
// or the datagram pool (NewDatagramBufPool, Env.DBufs). A Buf always
// returns to the pool it came from. It is safe for concurrent use and
// allocation-free in steady state.
type BufPool struct {
	layout classLayout
	pools  [numClasses]sync.Pool // the first layout.n are used
}

// NewBufPool returns an empty stream pool: the size classes 16 KiB … 1 MiB
// (each + ClassSlack) of send chunks, received DATA payloads, write
// scratches and reader stages.
func NewBufPool() *BufPool {
	return newBufPool(streamLayout)
}

// newBufPool returns an empty pool of layout l.
func newBufPool(l classLayout) *BufPool {
	p := &BufPool{layout: l}
	for c := range l.n {
		size, class := l.size(c), uint8(c)
		p.pools[c].New = func() any {
			full := make([]byte, size)
			return &Buf{B: full, full: full, class: class, pool: p}
		}
	}
	return p
}

// Get returns a Buf of the smallest class of this pool with len(B) ≥ n,
// charging its capacity to budget unconditionally (nil budget: uncharged).
// n must not exceed the pool's largest class (MaxClass + ClassSlack in the
// stream pool, 64 KiB + ClassSlack in the datagram pool); a larger n panics
// (programming error).
func (p *BufPool) Get(n int, budget *Budget) *Buf {
	c := p.layout.class(n)
	if budget != nil {
		budget.Acquire(int64(p.layout.size(c)))
	}
	return p.take(c, budget)
}

// TryGet is Get with budget.TryAcquire: it returns nil when the budget
// refuses the class capacity.
func (p *BufPool) TryGet(n int, budget *Budget) *Buf {
	c := p.layout.class(n)
	if budget != nil && !budget.TryAcquire(int64(p.layout.size(c))) {
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
