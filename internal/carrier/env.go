package carrier

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Env is the set of Runtime-wide services every carrier of a Runtime uses.
// It is built once by package rendr and never changes afterwards.
type Env struct {
	Local   [16]byte         // this Runtime's InstanceID
	Timing  Timing           // effective timing (normalized config + testhooks)
	Presets Presets          // counter presets (L14); zero values in production
	IDs     *IDAllocator     // dialer-side CarrierIDs
	Abandon *AbandonPool     // goroutines stuck in embedder calls past their bound (L52)
	Bufs    *BufPool         // receive buffers, send chunks, write scratches and reader stages
	Budget  *Budget          // MaxBufferedBytes: the data buffers (send chunks, receive buffers, write scratches)
	Stages  *Budget          // the reader stages, outside MaxBufferedBytes (stageBudget; nil: Budget)
	Hooks   *testhooks.Hooks // nil in production

	// DBufs is the datagram buffer pool (classes 2 KiB … 64 KiB, M2-D28):
	// datagram reader buffers and writer scratches (charged to Stages),
	// udpflow inbox buffers (charged to Budget). The stream pool Bufs keeps
	// its M1 classes. NewRuntime sets it (NewDatagramBufPool, WP3c);
	// component tests that need it set their own; nil in M1 tests.
	DBufs *BufPool
	// Dgram are the Runtime-wide datagram counters behind
	// rendr.Status.Datagram; nil in component tests.
	Dgram *DgramStats
}

// stageBudget returns the account a carrier's reader stage is charged to
// for the reader's whole life (design §0.14 B2, revising D29): Stages, a
// fixed account of one 16 KiB-class buffer per started carrier that
// neither Budget.TryAcquire (send chunks) nor the window advertisement
// (Budget.Used) sees, so idle carriers cannot exhaust MaxBufferedBytes and
// freeze the sessions' data. Status.BufferedBytes reports both accounts.
// An Env without a stage account charges its stages to Budget.
func (e *Env) stageBudget() *Budget {
	if e.Stages != nil {
		return e.Stages
	}
	return e.Budget
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

	// M2: datagram carriers (M2-D16, M2-D23, M2-D24). Zero selects the
	// default (withDefaults). The REL and H1 timeout is
	// sched.RTOWithin(srtt, rttvar, sampled, RelRTOInit, RelRTOMin,
	// RelRTOMax), its n-th retransmission's sched.RTOBackoffWithin(rto, n,
	// RelRTOMax).
	PacketPing    time.Duration // PING cadence of a packet-active datagram carrier (1 s)
	PacketActive  time.Duration // a DGRAM written or read within this keeps a carrier packet-active (PingIdle, 10 s)
	RelRTOInit    time.Duration // REL and H1 timeout before the first RTT sample (300 ms)
	RelRTOMin     time.Duration // REL timeout clamp, lower (200 ms)
	RelRTOMax     time.Duration // REL timeout clamp, upper (2 s)
	MTUProbeEvery int           // every n-th PacketPing-cadence PING is an MTU probe (10)
	MTUProbeFails int           // consecutive unanswered probes that kill the carrier (3)
}

// Defaults for zero Timing fields (plan §4). package rendr always fills
// Timing completely; the defaults only keep a partially filled Timing (a
// component test) from spinning or dividing by zero.
const (
	defPingBusy        = 50 * time.Millisecond
	defPingIdle        = 10 * time.Second
	defDeadMin         = 3 * time.Second
	defDeadMax         = 4 * time.Second
	defWriteStall      = 2 * time.Second
	defDialTimeout     = 10 * time.Second
	defHandshake       = 10 * time.Second
	defProbeInterval   = 2 * time.Second
	defSessionlessIdle = 30 * time.Second
	defAbandonWait     = time.Second
	defWindow          = 8 << 20
	defCapFloor        = 128 << 10

	// M2 (datagram carriers; M2 design §A7.4). PacketActive defaults to
	// PingIdle.
	defPacketPing    = time.Second
	defRelRTOInit    = 300 * time.Millisecond
	defRelRTOMin     = 200 * time.Millisecond
	defRelRTOMax     = 2 * time.Second
	defMTUProbeEvery = 10
	defMTUProbeFails = 3
)

// withDefaults returns t with every zero (or negative) field replaced by
// its default and DeadMax raised to DeadMin.
func (t Timing) withDefaults() Timing {
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&t.PingBusy, defPingBusy)
	def(&t.PingIdle, defPingIdle)
	def(&t.DeadMin, defDeadMin)
	def(&t.DeadMax, defDeadMax)
	def(&t.WriteStall, defWriteStall)
	def(&t.DialTimeout, defDialTimeout)
	def(&t.HandshakeTimeout, defHandshake)
	def(&t.ProbeInterval, defProbeInterval)
	def(&t.SessionlessIdle, defSessionlessIdle)
	def(&t.AbandonWait, defAbandonWait)
	if t.DeadMax < t.DeadMin {
		t.DeadMax = t.DeadMin
	}
	if t.Window <= 0 {
		t.Window = defWindow
	}
	if t.CapFloor <= 0 {
		t.CapFloor = defCapFloor
	}
	if t.BatchBudget <= 0 {
		t.BatchBudget = defaultBatchBudget
	}
	if t.Segment <= 0 {
		t.Segment = ChunkSize
	}
	def(&t.PacketPing, defPacketPing)
	def(&t.PacketActive, t.PingIdle)
	def(&t.RelRTOInit, defRelRTOInit)
	def(&t.RelRTOMin, defRelRTOMin)
	def(&t.RelRTOMax, defRelRTOMax)
	if t.RelRTOMax < t.RelRTOMin {
		t.RelRTOMax = t.RelRTOMin
	}
	if t.MTUProbeEvery <= 0 {
		t.MTUProbeEvery = defMTUProbeEvery
	}
	if t.MTUProbeFails <= 0 {
		t.MTUProbeFails = defMTUProbeFails
	}
	return t
}

// Presets are counter start values (L14); zero means the production default.
type Presets struct {
	FirstFseq   uint32 // first fseq in each direction (0: derived from the direction's PREFACE or PREFACE_ACK, §0.13 A6)
	FirstPingID uint32 // first PING id (0 = 1)
	FirstCseq   uint32 // first REL cseq in each direction of a datagram carrier (0 = wire.FirstCseq; L14)
}

// firstFseq returns the fseq a Conn starts with before its handshake sets
// the derived one (fseqFrom): FirstFseq when preset, else wire.FirstFseq.
// Only a Conn that skips the handshake (package tests) keeps it.
func (p Presets) firstFseq() uint32 {
	if p.FirstFseq == 0 {
		return wire.FirstFseq
	}
	return p.FirstFseq
}

// fseqFrom returns the fseq of the first frame in the direction that hello
// — a PREFACE or PREFACE_ACK, as written on the wire — opened: FirstFseq
// when preset (L14 wrap tests, scripted peers), else hello's CRC field
// (wire.PrefaceFseq), so every carrier direction numbers its frames from
// its own start and a frame spliced from another carrier fails the fseq
// check (design §0.13 A6; L43).
func (p Presets) fseqFrom(hello []byte) uint32 {
	if p.FirstFseq != 0 {
		return p.FirstFseq
	}
	return wire.PrefaceFseq(hello)
}

// firstCseq returns the first REL cseq of each direction of a datagram
// carrier: FirstCseq when preset (both Runtimes of a test preset the same
// value, as FirstFseq), else wire.FirstCseq. The handshakes derive the REL
// start values of M2 design Revision 1, R1-3, from it.
func (p Presets) firstCseq() uint32 {
	if p.FirstCseq == 0 {
		return wire.FirstCseq
	}
	return p.FirstCseq
}

// firstPingID returns the id of a carrier's first PING.
func (p Presets) firstPingID() uint32 {
	if p.FirstPingID == 0 {
		return 1
	}
	return p.FirstPingID
}

// IDAllocator hands out dialer CarrierIDs: never 0 and never an ID still in
// use in this Runtime (after the counter wraps, in-use IDs are skipped).
type IDAllocator struct {
	mu   sync.Mutex
	next uint32
	used map[uint32]struct{}
}

// NewIDAllocator returns an allocator whose first ID is first (0 = 1).
func NewIDAllocator(first uint32) *IDAllocator {
	if first == 0 {
		first = 1
	}
	return &IDAllocator{next: first, used: make(map[uint32]struct{})}
}

// Next returns a fresh CarrierID and marks it in use. The counter wraps
// (L14): 0 is never returned and an ID that is still in use is skipped. The
// in-use set is bounded by the live carriers, so the scan is short.
func (a *IDAllocator) Next() uint32 {
	a.mu.Lock()
	defer a.mu.Unlock()
	for {
		id := a.next
		a.next++
		if id == 0 {
			continue
		}
		if _, busy := a.used[id]; busy {
			continue
		}
		a.used[id] = struct{}{}
		return id
	}
}

// Release marks id free; it is called when the carrier's Done closes.
func (a *IDAllocator) Release(id uint32) {
	a.mu.Lock()
	delete(a.used, id)
	a.mu.Unlock()
}

// inUse returns the number of IDs currently marked in use (tests).
func (a *IDAllocator) inUse() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.used)
}

// AbandonPool counts goroutines that are still inside embedder code
// (factory calls, conn Read/Write/Close, OnEvent) after their joiner stopped
// waiting for them (plan §3.7, L52). It is exposed as Status.Abandoned.
type AbandonPool struct {
	n     atomic.Int64
	limit int64
}

// NewAbandonPool returns a pool that reports Full at limit (256 in production).
func NewAbandonPool(limit int) *AbandonPool {
	return &AbandonPool{limit: int64(limit)}
}

// Adopt counts one more abandoned goroutine. It never blocks.
func (p *AbandonPool) Adopt() {
	p.n.Add(1)
}

// Leave is called by an abandoned goroutine when its embedder call finally
// returned.
func (p *AbandonPool) Leave() {
	p.n.Add(-1)
}

// Len returns the number of goroutines currently abandoned.
func (p *AbandonPool) Len() int {
	return int(p.n.Load())
}

// Full reports Len() ≥ limit. While full, new carriers fail fast: Peer.Dial
// returns ErrCapacity, dial attempts fail with ErrAbandonFull, and the
// passive answers PREFACE_ACK(CAPACITY).
func (p *AbandonPool) Full() bool {
	return p.n.Load() >= p.limit
}
