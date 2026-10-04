package carrier

import (
	"time"

	"github.com/FrankoonG/rendr/v2/internal/testhooks"
)

// Env is the set of Runtime-wide services every carrier of a Runtime uses.
// It is built once by package rendr and never changes afterwards.
type Env struct {
	Local   [16]byte         // this Runtime's InstanceID
	Timing  Timing           // effective timing (normalized config + testhooks)
	Presets Presets          // counter presets (L14); zero values in production
	IDs     *IDAllocator     // dialer-side CarrierIDs
	Abandon *AbandonPool     // goroutines stuck in embedder calls past their bound (L52)
	Bufs    *BufPool         // receive buffers and send chunks
	Budget  *Budget          // MaxBufferedBytes accounting
	Hooks   *testhooks.Hooks // nil in production
}

// Timing is the effective per-carrier timing and sizing of a Runtime.
type Timing struct {
	PingBusy, PingIdle time.Duration // PING cadence (plan §3.6)
	DeadMin, DeadMax   time.Duration // death deadline clamp
	WriteStall         time.Duration // stall window floor
	DialTimeout        time.Duration // bounds one factory call and one whole attempt
	HandshakeTimeout   time.Duration // passive: PREFACE + first frame + verdict write
	ProbeInterval      time.Duration // PING cadence of dialer probe carriers
	SessionlessIdle    time.Duration // passive probe carriers close after this long without a PING
	AbandonWait        time.Duration // bound on joining a goroutine stuck in embedder code (1 s)
	Window             int64         // capacity ceiling (= Config.Window)
	CapFloor           int64         // capacity floor (128 KiB)
	BatchBudget        int           // DATA payload bytes per batch (256 KiB)
	Segment            int           // largest DATA payload a sender puts in one frame (64 KiB)
}

// Presets are counter start values (L14); zero means the production default.
type Presets struct {
	FirstFseq   uint32 // first fseq in each direction (0 = wire.FirstFseq)
	FirstPingID uint32 // first PING id (0 = 1)
}

// IDAllocator hands out dialer CarrierIDs: never 0 and never an ID still in
// use in this Runtime (after the counter wraps, in-use IDs are skipped).
type IDAllocator struct {
	_ struct{} // unexported state is defined by the implementation
}

// NewIDAllocator returns an allocator whose first ID is first (0 = 1).
func NewIDAllocator(first uint32) *IDAllocator {
	panic("unimplemented: M1b")
}

// Next returns a fresh CarrierID and marks it in use.
func (a *IDAllocator) Next() uint32 {
	panic("unimplemented: M1b")
}

// Release marks id free; it is called when the carrier's Done closes.
func (a *IDAllocator) Release(id uint32) {
	panic("unimplemented: M1b")
}

// AbandonPool counts goroutines that are still inside embedder code
// (factory calls, conn Read/Write/Close, OnEvent) after their joiner stopped
// waiting for them (plan §3.7, L52). It is exposed as Status.Abandoned.
type AbandonPool struct {
	_ struct{} // unexported state is defined by the implementation
}

// NewAbandonPool returns a pool that reports Full at limit (256 in production).
func NewAbandonPool(limit int) *AbandonPool {
	panic("unimplemented: M1b")
}

// Adopt counts one more abandoned goroutine. It never blocks.
func (p *AbandonPool) Adopt() {
	panic("unimplemented: M1b")
}

// Leave is called by an abandoned goroutine when its embedder call finally
// returned.
func (p *AbandonPool) Leave() {
	panic("unimplemented: M1b")
}

// Len returns the number of goroutines currently abandoned.
func (p *AbandonPool) Len() int {
	panic("unimplemented: M1b")
}

// Full reports Len() ≥ limit. While full, new carriers fail fast: Peer.Dial
// returns ErrCapacity, dial attempts fail with ErrAbandonFull, and the
// passive answers PREFACE_ACK(CAPACITY).
func (p *AbandonPool) Full() bool {
	panic("unimplemented: M1b")
}
