package carrier

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

// Budget is the Runtime-wide MaxBufferedBytes account (plan §3.7). Usage is
// one atomic counter; there is no lock and no waiter list (app writers that
// find the budget exhausted re-check on a timer, design §4.2).
type Budget struct {
	_ struct{} // unexported state is defined by the implementation
}

// NewBudget returns a budget of max bytes.
func NewBudget(max int64) *Budget {
	panic("unimplemented: M1b")
}

// TryAcquire charges n bytes unless that would exceed max (send chunks).
func (b *Budget) TryAcquire(n int64) bool {
	panic("unimplemented: M1b")
}

// Acquire charges n bytes unconditionally (receive buffers inside an
// already advertised window; they were promised).
func (b *Budget) Acquire(n int64) {
	panic("unimplemented: M1b")
}

// Release returns n bytes.
func (b *Budget) Release(n int64) {
	panic("unimplemented: M1b")
}

// Used returns the bytes currently charged.
func (b *Budget) Used() int64 {
	panic("unimplemented: M1b")
}

// Max returns the budget size.
func (b *Budget) Max() int64 {
	panic("unimplemented: M1b")
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
	// unexported state (atomic refcount, class, charged budget) is defined by the implementation.
}

// Ref adds a reference. It must only be called by a holder of a reference.
func (b *Buf) Ref() {
	panic("unimplemented: M1b")
}

// Release drops a reference; the last one returns b to its pool and
// uncharges its Budget. Releasing more often than referencing panics in
// tests (debug build tag) and is a bug.
func (b *Buf) Release() {
	panic("unimplemented: M1b")
}

// BufPool is the Runtime-wide set of size-class pools (one sync.Pool per
// class). It is safe for concurrent use and allocation-free in steady state.
type BufPool struct {
	_ struct{} // unexported state is defined by the implementation
}

// NewBufPool returns an empty pool.
func NewBufPool() *BufPool {
	panic("unimplemented: M1b")
}

// Get returns a Buf of the smallest class with len(B) ≥ n (n ≤ MaxClass +
// ClassSlack), charging its capacity to budget unconditionally (nil budget:
// uncharged). It panics if n is too large (programming error).
func (p *BufPool) Get(n int, budget *Budget) *Buf {
	panic("unimplemented: M1b")
}

// TryGet is Get with budget.TryAcquire: it returns nil when the budget
// refuses the class capacity.
func (p *BufPool) TryGet(n int, budget *Budget) *Buf {
	panic("unimplemented: M1b")
}
