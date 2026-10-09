package rendrtest

import (
	"context"
	"errors"
	"hash/fnv"
	"math/rand/v2"
	"net"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Dir is a link direction.
type Dir uint8

// Directions.
const (
	Up   Dir = 1 // dialer → passive
	Down Dir = 2 // passive → dialer
)

// FrameType names a rendr frame type for frame-targeted controls.
type FrameType uint8

// Frame types (values equal the wire format's type bytes).
const (
	FrameOpen    FrameType = 0x01
	FrameOpenAck FrameType = 0x02
	FrameJoin    FrameType = 0x03
	FrameJoinAck FrameType = 0x04
	FrameData    FrameType = 0x10
	FrameAck     FrameType = 0x11
	FrameFin     FrameType = 0x12
	FrameRst     FrameType = 0x13
	FrameSched   FrameType = 0x14
	FramePing    FrameType = 0x30
	FramePong    FrameType = 0x31
	FrameClose   FrameType = 0x32
	FrameGoAway  FrameType = 0x33
)

// CorruptMode selects how CorruptNextFrame damages a frame.
type CorruptMode uint8

// Corruption modes.
const (
	CorruptHeader  CorruptMode = 1 // flip a bit of the header's fseq: the receiver sees an fseq violation
	CorruptPayload CorruptMode = 2 // flip a payload bit: the receiver sees a CRC violation
	CorruptTrailer CorruptMode = 3 // flip a CRC bit
	// ForgeAckBeyondSent rewrites an ACK's delivered offset far beyond
	// anything sent, keeping fseq and recomputing the CRC: the receiver must
	// kill exactly this carrier for "ACK beyond sent".
	ForgeAckBeyondSent CorruptMode = 4
)

// DialBehavior makes the link's factory misbehave (fail, hang, return
// (nil, nil), panic, ...), to test that rendr contains an untrusted factory.
type DialBehavior uint8

// Dial behaviours.
const (
	DialNormal      DialBehavior = 0
	DialError       DialBehavior = 1 // return an error at once
	DialHang        DialBehavior = 2 // block until ctx ends (or Release / Close)
	DialHangForever DialBehavior = 3 // ignore ctx; return an error only after Release or Close
	DialNilNil      DialBehavior = 4 // return (nil, nil)
	DialPanic       DialBehavior = 5 // panic
	DialGoexit      DialBehavior = 6 // runtime.Goexit
	DialLateSuccess DialBehavior = 7 // ignore ctx; succeed after Release (the late conn must be closed once)
)

// BlockMode controls writes on one side of a link's carriers.
type BlockMode uint8

// Block modes.
const (
	BlockOff  BlockMode = 0 // writes proceed
	BlockSoft BlockMode = 1 // writes block but honour deadlines and Close
	BlockHard BlockMode = 2 // writes block and ignore deadlines and Close until Release (an abandoned call)
)

// BlackholeMode selects whether a blackhole also swallows carrier closes.
type BlackholeMode uint8

// Blackhole modes.
const (
	// BlackholeBytes (the default) swallows bytes only: an end that closes
	// its conn while the link is blackholed still ends the far end's conn
	// at once (it reads EOF, its writes fail), as if the close took
	// another path.
	BlackholeBytes BlackholeMode = 0
	// BlackholeCloses also swallows closes, as an nft DROP of a TCP path
	// does (no FIN, RST or ICMP passes): a carrier one end closes while the
	// link is blackholed stays open at the far end — its writes keep
	// vanishing, its reads see nothing — so the far end must reach its own
	// verdict. The close is deferred, not dropped: when the blackhole is
	// lifted (or the mode is set back to BlackholeBytes) it crosses at
	// once, as the closing stack's retransmitted FIN, or its RST to the
	// far end's next segment, does once the path passes packets again.
	// Kill and Close still end such a carrier at once. Each carrier whose
	// close was held back counts once as ClosesHeld.
	BlackholeCloses BlackholeMode = 1
)

// WriteResult scripts the result of one conn Write, including results a
// correct conn never returns (a count above len(p), (0, nil)), to test how
// rendr handles them.
type WriteResult struct {
	N         int   // bytes reported written (relative to len(p) when Relative)
	Relative  bool  // N is added to len(p) (e.g. −3 for "len−3", +1 for "len+1")
	Err       error // error returned with N
	Transmit  bool  // the reported bytes are actually forwarded (otherwise nothing is)
	ZeroWrite bool  // report (0, nil) regardless of N
}

// LinkConfig configures a Link.
type LinkConfig struct {
	// Name is the link's name; tests usually give the StreamCarrier that
	// dials through the link the same name. It also seeds the link's jitter,
	// so equal names give equal jitter sequences.
	Name string
	// Accept receives the passive end of every new carrier, typically
	// (*rendr.Listener).Handle. It must return; when it fails (or is nil) the
	// passive end is closed.
	Accept func(net.Conn) error
	// Buffer is how many bytes per direction a Write may hand to the link
	// before it blocks (default 2 MiB, at least 1 KiB). Bytes accepted but not
	// yet delivered are lost when the carrier is killed, as on a broken
	// connection.
	Buffer int
}

const (
	defaultBuffer = 2 << 20
	minBuffer     = 1 << 10
	readSize      = 64 << 10 // largest chunk a pump reads at once
	forgeBeyond   = 1 << 40  // ForgeAckBeyondSent adds this to the delivered offset
)

var (
	errRefused  = errors.New("rendrtest: link refused the dial")
	errScripted = errors.New("rendrtest: scripted dial error")
	errReleased = errors.New("rendrtest: hanging dial released")
)

// Link is an in-memory path: every Dial creates one carrier whose two
// directions pass through pumps that apply delay/jitter (order preserving),
// a rate limit, blackhole, stall, frame-aware corruption, drops and
// injection. Controls apply to current and future carriers; the one-shot
// frame controls apply to every current carrier; the one-shot conn controls
// (ScriptWrites, PanicWrites, OverRead) are consumed by the next matching
// call on any conn of that side, current or future. One-shot controls do
// not choose a carrier class: on a link that also carries a probe carrier
// they may hit the probe, so a stimulus proof checks Stats().Session (or the
// test gives the link a single carrier).
//
// The rate limit is one bottleneck per direction shared by all carriers of
// the link, paced when bytes are transmitted: bytes of every carrier queue
// behind each other in arrival order, so a probe carrier's PING waits
// behind a session carrier's bulk exactly as at a real bottleneck (what
// tests of rendr's self-load guard need). Bytes lost to Kill or the blackhole
// leave the queue without taking bottleneck time, a stall stops the
// bottleneck (its backlog then drains at the rate) and SetRate applies to
// every byte still queued. The one-way delay is added after the bottleneck.
//
// Create a Link inside the synctest bubble that uses it; Close it before
// the bubble ends.
type Link struct {
	name   string
	accept func(net.Conn) error
	buffer int

	// mu guards the carrier sets, the dial behaviour and the conn
	// misbehaviours. Order: mu → flow.mu → smu.
	mu       sync.Mutex
	closed   bool
	refuse   bool
	dialBeh  DialBehavior
	release  chan struct{} // closed by Release (then renewed) and by Close (for good)
	sides    [2]side       // conn misbehaviours: [0] the dialer's conns, [1] the passive's
	blockCh  chan struct{} // closed and renewed on every block-mode change
	carriers []*carrier    // live carriers
	history  []*carrier    // every carrier, in creation order
	dead     []*deadOpen   // dials made while blackholed
	txOn     bool          // the bottleneck goroutines run (from the first carrier until Close)
	stop     chan struct{} // closed by Close: the bottlenecks exit
	wg       sync.WaitGroup
	armedW   [2]atomic.Bool // a write misbehaviour may apply to side i
	armedR   [2]atomic.Bool // an over-read is pending on side i

	// smu guards timing and loss settings and the bottleneck queues; it is a
	// leaf lock.
	smu       sync.Mutex
	delay     time.Duration
	jitter    time.Duration
	rate      float64 // bytes/s per direction, 0 = unlimited
	blackhole bool
	bhMode    BlackholeMode
	stalled   bool
	ctl       chan struct{}    // closed and renewed on every rate, stall, blackhole or blackhole-mode change
	bq        [2][]*chunk      // the bottleneck queue of each direction, in arrival order
	txWork    [2]chan struct{} // cap 1: a chunk was queued at bottleneck i
	rng       [2]*rand.Rand    // jitter per direction; seeded from the name (deterministic)

	ctr       [3]counters // all, session, probe
	throttled atomic.Int64
	dials     atomic.Int64
	dialFails atomic.Int64

	// afterCheck, tests only (nil otherwise), runs in an ordinary dial
	// between its SetRefuse check and the carrier's creation.
	afterCheck func()
}

// side holds the conn misbehaviours of one side.
type side struct {
	block   BlockMode
	scripts []WriteResult
	panics  int
	over    int
}

// NewLink returns a link; nothing runs until the first Dial.
func NewLink(cfg LinkConfig) *Link {
	b := cfg.Buffer
	if b <= 0 {
		b = defaultBuffer
	}
	h := fnv.New64a()
	h.Write([]byte(cfg.Name))
	s := h.Sum64()
	return &Link{
		name:    cfg.Name,
		accept:  cfg.Accept,
		buffer:  max(b, minBuffer),
		release: make(chan struct{}),
		blockCh: make(chan struct{}),
		stop:    make(chan struct{}),
		ctl:     make(chan struct{}),
		txWork:  [2]chan struct{}{make(chan struct{}, 1), make(chan struct{}, 1)},
		rng: [2]*rand.Rand{
			rand.New(rand.NewPCG(s, s^0x9e3779b97f4a7c15)),
			rand.New(rand.NewPCG(s^1, s^0x7f4a7c159e3779b9)),
		},
	}
}

// Name returns the link name.
func (l *Link) Name() string { return l.name }

// Dial is a rendr StreamCarrier.Dial: it creates one carrier through the
// link (honouring SetRefuse, SetBlackhole and SetDial) and passes the far
// end to Accept on a link-owned goroutine.
func (l *Link) Dial(ctx context.Context) (net.Conn, error) {
	return l.dial(ctx, nil)
}

// DialEarly is a rendr StreamCarrier.DialEarly: first travels ahead of the
// stream (the far end reads it first) and is classified like any first bytes.
func (l *Link) DialEarly(ctx context.Context, first []byte) (net.Conn, error) {
	return l.dial(ctx, slices.Clone(first))
}

func (l *Link) dial(ctx context.Context, first []byte) (net.Conn, error) {
	l.dials.Add(1)
	l.mu.Lock()
	beh, refuse, closed, rel := l.dialBeh, l.refuse, l.closed, l.release
	l.mu.Unlock()
	fail := func(err error) (net.Conn, error) {
		l.dialFails.Add(1)
		return nil, err
	}
	switch {
	case closed:
		return fail(net.ErrClosed)
	case refuse:
		return fail(errRefused)
	}
	switch beh {
	case DialError:
		return fail(errScripted)
	case DialHang:
		select {
		case <-ctx.Done():
			return fail(ctx.Err())
		case <-rel:
			return fail(errReleased)
		}
	case DialHangForever:
		<-rel
		return fail(errReleased)
	case DialNilNil:
		l.dialFails.Add(1)
		return nil, nil
	case DialPanic:
		l.dialFails.Add(1)
		panic("rendrtest: scripted factory panic")
	case DialGoexit:
		l.dialFails.Add(1)
		runtime.Goexit()
	case DialLateSuccess:
		<-rel
	default:
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		if h := l.afterCheck; h != nil {
			h()
		}
		return l.open(first, true)
	}
	return l.open(first, false)
}

// SetDelay sets the one-way delay and uniform jitter of both directions,
// added to bytes as they leave the bottleneck (bytes already past it keep
// their delivery time).
func (l *Link) SetDelay(oneWay, jitter time.Duration) {
	l.smu.Lock()
	l.delay, l.jitter = max(oneWay, 0), max(jitter, 0)
	l.smu.Unlock()
}

// SetRate caps each direction's shared bottleneck at bytesPerSec (0 =
// unlimited). The change applies at once, also to bytes already queued.
func (l *Link) SetRate(bytesPerSec float64) {
	l.smu.Lock()
	l.rate = max(bytesPerSec, 0)
	l.bumpCtl()
	l.smu.Unlock()
}

// SetBlackhole makes bytes vanish without closing anything (counted as
// Dropped): new bytes, bytes still queued at the bottleneck (they take no
// bottleneck time) and bytes in flight when they would arrive. New dials
// "open" but never answer. Whether a carrier's close crosses a blackhole
// is SetBlackholeMode's choice (by default it does).
func (l *Link) SetBlackhole(on bool) {
	l.smu.Lock()
	l.blackhole = on
	l.bumpCtl()
	l.smu.Unlock()
}

// SetBlackholeMode sets what SetBlackhole swallows (BlackholeBytes by
// default). Closes held back by BlackholeCloses cross as soon as the mode
// is set back to BlackholeBytes.
func (l *Link) SetBlackholeMode(m BlackholeMode) {
	if m > BlackholeCloses {
		panic("rendrtest: unknown BlackholeMode")
	}
	l.smu.Lock()
	l.bhMode = m
	l.bumpCtl()
	l.smu.Unlock()
}

// endCarrier ends the carrier after one of its ends closed (or a write
// into an end failed). While the link swallows closes (blackholed in
// BlackholeCloses mode) the close is held back — the far end stays open —
// until that ends or the carrier is shut otherwise (Kill, Close).
func (f *flow) endCarrier() {
	c, l := f.c, f.c.l
	for {
		l.smu.Lock()
		hold, ctl := l.blackhole && l.bhMode == BlackholeCloses, l.ctl
		l.smu.Unlock()
		if !hold {
			c.shut()
			return
		}
		if c.closeHeld.CompareAndSwap(false, true) {
			l.count(c.kind.Load(), cClosesHeld, 1)
		}
		select {
		case <-ctl:
		case <-c.done:
			return
		}
	}
}

// SetStall holds bytes (not lost) until un-stalled (counted as Held, once
// per chunk): the bottleneck transmits nothing and nothing in flight
// arrives. After the stall the backlog drains at the rate.
func (l *Link) SetStall(on bool) {
	l.smu.Lock()
	if l.stalled != on {
		l.stalled = on
		l.bumpCtl()
	}
	l.smu.Unlock()
}

// bumpCtl wakes everything waiting on a rate, stall, blackhole or
// blackhole-mode change.
// l.smu held.
func (l *Link) bumpCtl() {
	close(l.ctl)
	l.ctl = make(chan struct{})
}

// SetRefuse makes new dials fail.
func (l *Link) SetRefuse(on bool) {
	l.mu.Lock()
	l.refuse = on
	l.mu.Unlock()
}

// SetDial sets the factory behaviour for new dials.
func (l *Link) SetDial(b DialBehavior) {
	l.mu.Lock()
	l.dialBeh = b
	l.mu.Unlock()
}

// Kill closes both ends of every current carrier and returns how many it
// killed (counted as Killed). Bytes buffered in the link are lost (counted
// as BufferLost) and give back their share of the bottleneck at once; Kill
// returns after the carriers' pumps exited, so the counters are final.
// Dials made while blackholed are closed too.
func (l *Link) Kill() int {
	l.mu.Lock()
	cs := slices.Clone(l.carriers)
	dead := l.dead
	l.dead = nil
	l.mu.Unlock()
	var killed []*carrier
	for _, c := range cs {
		if c.shut() {
			killed = append(killed, c)
			l.count(c.kind.Load(), cKilled, 1)
		}
	}
	for _, d := range dead {
		d.shut()
	}
	for _, c := range killed {
		c.pumps.Wait()
		c.countLost()
	}
	return len(killed)
}

// CorruptNext flips one byte in the next chunk forwarded in direction d of
// every current carrier, wherever that byte falls: unlike CorruptNextFrame
// it ignores frame boundaries.
func (l *Link) CorruptNext(d Dir) {
	l.mu.Lock()
	for _, c := range l.carriers {
		c.corrupt[d.index()].Store(true)
	}
	l.mu.Unlock()
}

// CorruptNextFrame damages the next frame of type t forwarded in direction
// d on every current carrier (frame-wide CRC and ACK-beyond-sent tests).
// ForgeAckBeyondSent applies only to ACK frames.
func (l *Link) CorruptNextFrame(d Dir, t FrameType, m CorruptMode) {
	if m == ForgeAckBeyondSent && t != FrameAck {
		panic("rendrtest: ForgeAckBeyondSent applies only to ACK frames")
	}
	if m < CorruptHeader || m > ForgeAckBeyondSent {
		panic("rendrtest: unknown CorruptMode")
	}
	l.eachFlow(d, func(f *flow) { f.tr.corrupts = append(f.tr.corrupts, corruptOp{t, m}) })
}

// DropNextFrame removes the next frame of type t in direction d on every
// current carrier: the receiver sees an fseq gap.
func (l *Link) DropNextFrame(d Dir, t FrameType) {
	l.eachFlow(d, func(f *flow) { f.tr.drops = append(f.tr.drops, t) })
}

// InjectAfterNextFrame inserts one frame of type t with the given flags,
// handle and payload after the next frame of type after in direction d on
// every current carrier (probe carriers included), with the correct fseq
// and CRC; later frames of that direction are re-stamped so that only the
// injected frame's semantics can trigger a reaction (stale PONG,
// conflicting FIN, ACK beyond sent, ...). Counted as FramesInjected.
func (l *Link) InjectAfterNextFrame(d Dir, after, t FrameType, flags uint8, handle uint32, payload []byte) {
	if len(payload) > wire.MaxFramePayload {
		panic("rendrtest: injected payload beyond MaxFramePayload")
	}
	inj := &injection{after: after, t: t, flags: flags, handle: handle, payload: slices.Clone(payload)}
	l.eachFlow(d, func(f *flow) { f.tr.injects = append(f.tr.injects, inj) })
}

// CaptureNextFrame copies the raw bytes (header through trailer) of the next
// frame of type t forwarded in direction d on any current carrier into the
// returned channel (buffered, one frame) and forwards the frame unchanged
// (counted as FramesCaptured). Tests use it to learn values they cannot
// compute, such as an old carrier incarnation's PING nonce for a stale-PONG
// injection, or to obtain another session's frame for a splice. The first
// carrier to forward such a frame wins, a probe carrier included: check
// Stats().Session.FramesCaptured or use a link with one carrier. The
// channel receives the frame before FramesCaptured counts it (and before
// the frame is forwarded), so a test that received the frame must wait
// until the count shows it before asserting on it. Without a current
// carrier the channel never receives.
func (l *Link) CaptureNextFrame(d Dir, t FrameType) <-chan []byte {
	cp := &capture{t: t, ch: make(chan []byte, 1)}
	l.eachFlow(d, func(f *flow) { f.tr.captures = append(f.tr.captures, cp) })
	return cp.ch
}

// InjectRaw inserts raw at the next frame boundary in direction d on every
// current carrier (probe carriers included), byte for byte: neither fseq
// nor CRC is re-stamped, so spliced bytes of another carrier or session hit
// the receiver's fseq and CRC checks exactly as a misbehaving relay's
// would. Counted as FramesInjected. A carrier that is between frames gets
// raw at once.
func (l *Link) InjectRaw(d Dir, raw []byte) {
	raw = slices.Clone(raw)
	l.eachFlow(d, func(f *flow) {
		if f.tr.atBoundary() {
			k := f.c.kind.Load()
			f.enqueue(slices.Clone(raw), k)
			l.count(k, cFramesInjected, 1)
			return
		}
		f.tr.raws = append(f.tr.raws, raw) // copied into the stream when emitted
	})
}

// eachFlow runs fn on direction d of every current carrier under the
// flow's lock.
func (l *Link) eachFlow(d Dir, fn func(f *flow)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.carriers {
		f := c.flows[d.index()]
		f.mu.Lock()
		fn(f)
		f.mu.Unlock()
	}
}

// ScriptWrites makes the next Writes of side d's conns (Up: the dialer's,
// Down: the passive's) return the scripted results, counted as
// WritesScripted. Each result is consumed by the next Write on any conn of
// that side, a probe carrier's included.
func (l *Link) ScriptWrites(d Dir, r ...WriteResult) {
	l.mu.Lock()
	s := &l.sides[d.index()]
	s.scripts = append(s.scripts, r...)
	l.rearm(d.index())
	l.mu.Unlock()
}

// BlockWrites blocks Writes of side d's conns per m (BlockOff lifts it);
// every Write that blocks is counted once as WritesBlocked.
func (l *Link) BlockWrites(d Dir, m BlockMode) {
	l.mu.Lock()
	if !l.closed {
		l.sides[d.index()].block = m
		l.bumpBlock()
		l.rearm(d.index())
	}
	l.mu.Unlock()
}

// PanicWrites makes the next Write on any conn of side d panic, counted as
// WritePanics.
func (l *Link) PanicWrites(d Dir) {
	l.mu.Lock()
	l.sides[d.index()].panics++
	l.rearm(d.index())
	l.mu.Unlock()
}

// OverRead makes the next Read on any conn of side d that returns data
// report the invalid count len(p)+1, counted as OverReads.
func (l *Link) OverRead(d Dir) {
	l.mu.Lock()
	l.sides[d.index()].over++
	l.rearm(d.index())
	l.mu.Unlock()
}

// Release unblocks every Hard-blocked write and hanging dial, so that a
// synctest bubble can end without leaked goroutines: blocked writes of both
// sides proceed (both block modes are reset to BlockOff), DialHangForever
// calls fail and DialLateSuccess calls succeed. The dial behaviour itself
// stays as set.
func (l *Link) Release() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.closed {
		l.releaseAll()
		l.release = make(chan struct{})
	}
}

// releaseAll releases hanging dials and turns every write block off. l.mu
// held.
func (l *Link) releaseAll() {
	close(l.release)
	for i := range l.sides {
		l.sides[i].block = BlockOff
		l.rearm(i)
	}
	l.bumpBlock()
}

// bumpBlock wakes every write blocked by a block mode. l.mu held.
func (l *Link) bumpBlock() {
	close(l.blockCh)
	l.blockCh = make(chan struct{})
}

// rearm refreshes the fast-path flags of side i. l.mu held.
func (l *Link) rearm(i int) {
	s := &l.sides[i]
	l.armedW[i].Store(s.block != BlockOff || len(s.scripts) > 0 || s.panics > 0)
	l.armedR[i].Store(s.over > 0)
}

// Stats returns the link counters.
func (l *Link) Stats() Stats {
	return Stats{
		All:          l.ctr[0].snap(),
		Session:      l.ctr[1].snap(),
		Probe:        l.ctr[2].snap(),
		Throttled:    l.throttled.Load(),
		Dials:        l.dials.Load(),
		DialFailures: l.dialFails.Load(),
	}
}

// Carriers lists every carrier the link created, in creation order.
func (l *Link) Carriers() []CarrierInfo {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]CarrierInfo, len(l.history))
	for i, c := range l.history {
		out[i] = CarrierInfo{
			Seq:       c.seq,
			First:     FrameType(c.first.Load()),
			Session:   c.kind.Load() == kindSession,
			Up:        c.up.Load(),
			Down:      c.down.Load(),
			Held:      c.held.Load(),
			Closed:    c.closed.Load(),
			CloseHeld: c.closeHeld.Load(),
		}
	}
	return out
}

// NextSeq is the Seq the next carrier of the link will get.
func (l *Link) NextSeq() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.history)
}

// Close refuses new carriers, closes every current one, releases every
// blocked write and hanging dial, and joins every goroutine the link
// started (pumps and Accept calls). Idempotent.
func (l *Link) Close() {
	l.mu.Lock()
	if !l.closed {
		l.closed = true
		l.releaseAll()
		close(l.stop)
	}
	cs := slices.Clone(l.carriers)
	dead := l.dead
	l.dead = nil
	l.mu.Unlock()
	for _, c := range cs {
		c.shut()
	}
	for _, d := range dead {
		d.shut()
	}
	l.wg.Wait()
}

// Counts are fault and traffic counters of a set of carriers. Every
// control has one, so a stimulus proof can show that a fault touched the
// carrier class it is about.
type Counts struct {
	Killed          int64         // carriers closed by Kill
	Bytes           int64         // bytes the far ends have read, both directions (a chunk counts once read in full)
	Dropped         int64         // bytes discarded by the blackhole
	Held            int64         // chunks held back by a stall
	Corrupted       int64         // chunks corrupted by CorruptNext
	FramesCorrupted int64         // frames damaged by CorruptNextFrame
	FramesDropped   int64         // frames removed by DropNextFrame
	FramesInjected  int64         // frames inserted by InjectAfterNextFrame or InjectRaw
	BufferLost      int64         // bytes accepted by a Write and lost when the carrier was killed
	MaxDelay        time.Duration // largest delay applied
	WritesScripted  int64         // Writes that returned a ScriptWrites result
	WritesBlocked   int64         // Writes blocked by BlockWrites
	WritePanics     int64         // Writes that panicked (PanicWrites)
	OverReads       int64         // Reads that reported len(p)+1 (OverRead)
	FramesCaptured  int64         // frames copied by CaptureNextFrame (counted after the copy reached its channel)
	ClosesHeld      int64         // carriers whose close a BlackholeCloses blackhole held back (once per carrier)
}

// Stats are a link's counters: over all carriers, session carriers only,
// and probe carriers only.
type Stats struct {
	All, Session, Probe Counts
	Throttled           int64 // bytes that passed the rate limiter
	Dials               int64 // factory calls
	DialFailures        int64 // factory calls that failed (refused, scripted, ...)
}

// CarrierInfo is a snapshot of one carrier for per-carrier assertions.
type CarrierInfo struct {
	Seq       int       // creation order on its link
	First     FrameType // first frame type after the PREFACE (0 until it crossed)
	Session   bool      // First is OPEN or JOIN
	Up, Down  int64     // bytes the far end has read in each direction (as Counts.Bytes)
	Held      int64     // chunks held by a stall
	Closed    bool
	CloseHeld bool // a BlackholeCloses blackhole held its close back (as Counts.ClosesHeld)
}

// index maps a direction to its array index (Up 0, Down 1).
func (d Dir) index() int {
	if d == Down {
		return 1
	}
	return 0
}

// Carrier classes (by the first frame after the PREFACE).
const (
	kindUnknown int32 = iota
	kindSession
	kindProbe
	kindOther
)

// ctr indexes counters.
type ctr int

const (
	cKilled ctr = iota
	cBytes
	cDropped
	cHeld
	cCorrupted
	cFramesCorrupted
	cFramesDropped
	cFramesInjected
	cBufferLost
	cMaxDelay
	cScripted
	cBlocked
	cPanics
	cOverReads
	cCaptured
	cClosesHeld
	nCtr
)

type counters [nCtr]atomic.Int64

func (c *counters) bump(k ctr, n int64) {
	if k != cMaxDelay {
		c[k].Add(n)
		return
	}
	for {
		old := c[k].Load()
		if n <= old || c[k].CompareAndSwap(old, n) {
			return
		}
	}
}

func (c *counters) snap() Counts {
	return Counts{
		Killed:          c[cKilled].Load(),
		Bytes:           c[cBytes].Load(),
		Dropped:         c[cDropped].Load(),
		Held:            c[cHeld].Load(),
		Corrupted:       c[cCorrupted].Load(),
		FramesCorrupted: c[cFramesCorrupted].Load(),
		FramesDropped:   c[cFramesDropped].Load(),
		FramesInjected:  c[cFramesInjected].Load(),
		BufferLost:      c[cBufferLost].Load(),
		MaxDelay:        time.Duration(c[cMaxDelay].Load()),
		WritesScripted:  c[cScripted].Load(),
		WritesBlocked:   c[cBlocked].Load(),
		WritePanics:     c[cPanics].Load(),
		OverReads:       c[cOverReads].Load(),
		FramesCaptured:  c[cCaptured].Load(),
		ClosesHeld:      c[cClosesHeld].Load(),
	}
}

// count adds n to counter k of all carriers and of the carrier's class.
func (l *Link) count(kind int32, k ctr, n int64) {
	if n == 0 {
		return
	}
	l.ctr[0].bump(k, n)
	switch kind {
	case kindSession:
		l.ctr[1].bump(k, n)
	case kindProbe:
		l.ctr[2].bump(k, n)
	}
}
