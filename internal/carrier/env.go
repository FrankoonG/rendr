package carrier

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/udpsocket"
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
	// MuxFull counts the CAPACITY CodeMuxFull answers this Runtime's
	// passive MUX trunks queued (rendr.Status.Mux.MuxFull, passive role;
	// the dialer's are PoolStats.MuxFull); nil in component tests.
	MuxFull *atomic.Uint64
	// PoolLive (dialer) is called, without a pool lock held, when a pool
	// whose Close ran publishes a fresh trunk (a session that survived
	// Peer.Close dialled): the owner tracks the pool again if it dropped
	// it (rendr.Status.Mux, Runtime.Close's join). nil: no call.
	PoolLive func(*Pool)

	// Admit (passive) receives an OPEN or JOIN for a new handle on a started
	// MUX trunk (M3-D21, §A5.6): v is the new view (pending or joining,
	// endpoint shim), h and p the frame. It runs on the trunk's reader with
	// no carrier lock held, must not block, and answers through v (a
	// response as the view's first frame) or Conn.Refuse. nil: no passive
	// mux (an OPEN or JOIN on a live trunk is then refused).
	Admit func(v *Conn, h wire.Header, p []byte)

	// Trunks is the Runtime's index of its established MUX trunks by pair
	// (PA-86, down.go): the hook through which a dying trunk queues DOWN on
	// the other trunks of its pair and a received DOWN finds the trunk it
	// names. NewRuntime sets it; nil (component tests): no DOWN is sent, and
	// one received names no trunk.
	Trunks *TrunkSet
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

	// M3: rendr mux (M3-D10, M3-D12, M3-D50). Internal constants with
	// testhooks overrides; zero selects the default.
	MuxMaxViews         int // views per stream MUX trunk, refusal answers queued included (256)
	MuxMaxViewsDatagram int // views per datagram MUX trunk, refusal answers queued included (64)
	MuxQuantum          int // DRR quantum: DATA/DGRAM payload bytes per view per writer round (64 KiB)
	MuxRefusalRing      int // queued refusal answers per trunk (the trunk kind's MuxMaxViews, R1-4)
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
	if t.MuxMaxViews <= 0 {
		t.MuxMaxViews = defMuxMaxViews
	}
	if t.MuxMaxViewsDatagram <= 0 {
		t.MuxMaxViewsDatagram = defMuxMaxViewsDatagram
	}
	if t.MuxQuantum <= 0 {
		t.MuxQuantum = defMuxQuantum
	}
	// MuxRefusalRing stays 0 unless set: the refusal ring then holds the
	// trunk kind's MuxMaxViews answers (R1-4; refuse).
	return t
}

// Presets are counter start values (L14); zero means the production default.
type Presets struct {
	FirstFseq   uint32 // first fseq in each direction (0: derived from the direction's PREFACE or PREFACE_ACK, §0.13 A6)
	FirstPingID uint32 // first PING id (0 = 1)
	FirstCseq   uint32 // first REL cseq in each direction of a datagram carrier (0 = wire.FirstCseq; L14)
	FirstHandle uint32 // first handle a dialer allocates on a MUX trunk (0 = wire.SessionHandle; L14)
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

// ioHdr is a pooled batch header (M5 design Revision 1, R1-5 rule 1): the
// udpsocket.Batch of one capacity class (2, 4, … 64 messages) with the
// message array of one batched call and, for a reader, its slots. A
// rendr-owned socket's WriteDatagrams holds one for a call of two or more
// datagrams; a dialer carrier's reader holds one while it reads at depth
// two or more (kept across short parks, returned at its idle release,
// dgread.go). Nobody holds one while idle, and none is allocated per call:
// the headers live in one pool per class — the readers' also in a bounded
// reserve beside it (getReadHdr) — shared by the Runtimes of the process
// as sync.Pool shares DBufs' classes; each Runtime is charged for the
// headers it holds, to Env.Stages (forced: visible in BufferedBytes), so
// the per-Runtime accounts of plan:221 stay separate.
type ioHdr struct {
	b      *udpsocket.Batch
	ms     []udpsocket.Msg // len = the class capacity; cleared when pooled
	slots  []*Buf          // a reader's slots 1 … k−1 (DBufs, charged to Env.Budget); slot 0 is the reader's own buffer
	k      int             // a reader's depth (2 … capacity)
	gen    uint64          // a reader's lend generation (dgread.go)
	class  uint8
	stages *Budget // the account charged while held; nil: uncharged
}

// The header classes and their charge. hdrPerMsg estimates one message's
// share of a header: a kernel header, an iovec and a socket address
// (≈ 108 bytes on the batching targets), a udpsocket.Msg (72) and a slot
// pointer.
const (
	hdrClasses = 6 // capacities 2 << c: 2 … 64 = udpsocket.MaxMsgs
	hdrPerMsg  = 192
)

var hdrPools [hdrClasses]sync.Pool

// hdrClass returns the smallest class whose capacity holds n messages
// (2 ≤ n ≤ 64).
func hdrClass(n int) int {
	c := 0
	for 2<<c < n {
		c++
	}
	return c
}

// The readers' reserve (M6 delegate decision after wave C on the
// allocation gates; L16, L54). A dialer reader takes a header at every
// regrowth — its first growth after an idle release or a socket fallback,
// and each growth past the class it holds — and returns one at each class
// change, idle release, fallback and exit. Through the pools alone such a
// take builds a new header whenever the pool has none the taker's P can
// reach: after two collections, or with the returned header in another
// P's private slot (the reader's goroutine moves between Ps, its idle
// release runs on the timer's; the gates' switch to one P strands every
// other P's). So a reader's return fills the reserve first and a reader's
// take empties it first, the pools holding the rest: up to hdrSpares
// headers per class that every P reaches and no collection drops. One
// atomic pointer per entry — a take swaps a header out, a return swaps one
// into an empty entry: no lock, and no ABA, since no exchange expects a
// header — bounds it at hdrSpares × six classes (at most ≈ 100 KiB with
// Linux's kernel arrays, ≈ 50 KiB at the default MaxBatch's five).
// Reserved headers are uncharged, as pooled ones: they belong to no
// Runtime. Writers use the pools only (getHdr, put): they take and return
// one per call, where a process-wide entry would be a contended cache line
// on the hot path. Rows: TestDgramReadAdaptiveDepthReuse_L16_L54,
// TestDgramReadHeaderReturnsReused_L16_L54; the bound,
// TestBatchMemoryBounded_L16.
const hdrSpares = 4

var hdrReserve [hdrClasses][hdrSpares]atomic.Pointer[ioHdr]

// getHdr returns a header for n messages (2 ≤ n ≤ udpsocket.MaxMsgs) of the
// smallest class that holds them, charged to stages (nil: uncharged).
func getHdr(n int, stages *Budget) *ioHdr {
	c := hdrClassFor(n)
	h, _ := hdrPools[c].Get().(*ioHdr)
	if h == nil {
		cp := 2 << c
		h = &ioHdr{b: udpsocket.NewBatch(cp), ms: make([]udpsocket.Msg, cp), slots: make([]*Buf, cp), class: uint8(c)}
	}
	h.chargeTo(stages)
	return h
}

// getReadHdr is getHdr for a dialer reader: a reserved header when its
// class has one, else getHdr's.
func getReadHdr(n int, stages *Budget) *ioHdr {
	res := &hdrReserve[hdrClassFor(n)]
	for i := range res {
		if res[i].Load() == nil {
			continue
		}
		if h := res[i].Swap(nil); h != nil {
			h.chargeTo(stages)
			return h
		}
	}
	return getHdr(n, stages)
}

// hdrClassFor is hdrClass with the range check of a header's size: n
// outside 2 … udpsocket.MaxMsgs panics (a programming error).
func hdrClassFor(n int) int {
	if n < 2 || n > udpsocket.MaxMsgs {
		panic("rendr/carrier: batch header size out of range")
	}
	return hdrClass(n)
}

// chargeTo charges the header to stages (nil: uncharged).
func (h *ioHdr) chargeTo(stages *Budget) {
	if stages != nil {
		stages.Acquire(h.charge())
		h.stages = stages
	}
}

// cap returns the header's capacity in messages.
func (h *ioHdr) cap() int { return len(h.ms) }

// charge returns the bytes a held header is charged.
func (h *ioHdr) charge() int64 { return int64(len(h.ms) * hdrPerMsg) }

// uncharge returns the header's charge (idempotent).
func (h *ioHdr) uncharge() {
	if s := h.stages; s != nil {
		h.stages = nil
		s.Release(h.charge())
	}
}

// put returns h to its pool: uncharged, with no reference to a call's
// buffers. Its slots must have been released (nil).
func (h *ioHdr) put() {
	h.reset()
	hdrPools[h.class].Put(h)
}

// putRead is put for a dialer reader's header: into an empty entry of the
// reserve, else to the pool.
func (h *ioHdr) putRead() {
	h.reset()
	res := &hdrReserve[h.class]
	for i := range res {
		if res[i].CompareAndSwap(nil, h) {
			return
		}
	}
	hdrPools[h.class].Put(h)
}

// reset makes h a pooled header: uncharged, no reference to a call's
// buffers, no depth.
func (h *ioHdr) reset() {
	h.uncharge()
	clear(h.ms)
	h.k, h.gen = 0, 0
}
