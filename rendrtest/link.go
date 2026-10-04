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
	// kill exactly this carrier for "ACK beyond sent" (L13).
	ForgeAckBeyondSent CorruptMode = 4
)

// DialBehavior makes the link's factory misbehave (L51).
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

// WriteResult scripts the result of one conn Write (L42).
type WriteResult struct {
	N         int   // bytes reported written (relative to len(p) when Relative)
	Relative  bool  // N is added to len(p) (e.g. −3 for "len−3", +1 for "len+1")
	Err       error // error returned with N
	Transmit  bool  // the reported bytes are actually forwarded (otherwise nothing is)
	ZeroWrite bool  // report (0, nil) regardless of N
}

// LinkConfig configures a Link.
type LinkConfig struct {
	// Name is the link's name (the factory name in the fixture).
	Name string
	// Accept receives the passive end of every new carrier, typically
	// (*rendr.Listener).Handle. It must return; when it fails (or is nil) the
	// passive end is closed.
	Accept func(net.Conn) error
	// Buffer is how many bytes per direction a Write may hand to the link
	// before it blocks (default 2 MiB, at least 1 KiB). Bytes accepted but not
	// yet delivered are lost when the carrier is killed: the buffer-loss model
	// of L10/L61.
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
// a token-bucket rate, blackhole, stall, frame-aware corruption, drops and
// injection. Controls apply to current and future carriers; the one-shot
// frame controls apply to every current carrier; the one-shot conn controls
// (ScriptWrites, PanicWrites, OverRead) are consumed by the next matching
// call on any conn of that side, current or future.
//
// The rate limiter is one bottleneck per direction shared by all carriers of
// the link: bytes of every carrier queue behind each other in arrival order,
// so a probe carrier's PING waits behind a session carrier's bulk exactly as
// at a real bottleneck (the self-load guard tests, design §8.5).
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
	wg       sync.WaitGroup
	armedW   [2]atomic.Bool // a write misbehaviour may apply to side i
	armedR   [2]atomic.Bool // an over-read is pending on side i

	// smu guards timing and loss settings; it is a leaf lock.
	smu       sync.Mutex
	delay     time.Duration
	jitter    time.Duration
	rate      float64      // bytes/s per direction, 0 = unlimited
	freeAt    [2]time.Time // the shared bottleneck of each direction is busy until then
	blackhole bool
	stalled   bool
	stallCh   chan struct{} // closed and renewed on every stall change
	rng       *rand.Rand    // jitter; seeded from the name (deterministic)

	ctr       [3]counters // all, session, probe
	throttled atomic.Int64
	dials     atomic.Int64
	dialFails atomic.Int64
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
		stallCh: make(chan struct{}),
		rng:     rand.New(rand.NewPCG(s, s^0x9e3779b97f4a7c15)),
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
	}
	return l.open(first)
}

// SetDelay sets the one-way delay and uniform jitter of both directions.
func (l *Link) SetDelay(oneWay, jitter time.Duration) {
	l.smu.Lock()
	l.delay, l.jitter = max(oneWay, 0), max(jitter, 0)
	l.smu.Unlock()
}

// SetRate caps each direction at bytesPerSec (0 = unlimited).
func (l *Link) SetRate(bytesPerSec float64) {
	l.smu.Lock()
	l.rate = max(bytesPerSec, 0)
	l.smu.Unlock()
}

// SetBlackhole makes bytes vanish without closing anything; new dials
// "open" but never answer (counted as Dropped).
func (l *Link) SetBlackhole(on bool) {
	l.smu.Lock()
	l.blackhole = on
	l.smu.Unlock()
}

// SetStall holds bytes (not lost) until un-stalled (counted as Held).
func (l *Link) SetStall(on bool) {
	l.smu.Lock()
	if l.stalled != on {
		l.stalled = on
		close(l.stallCh)
		l.stallCh = make(chan struct{})
	}
	l.smu.Unlock()
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
// as BufferLost); Kill returns after the carriers' pumps exited, so the
// counters are final. Dials made while blackholed are closed too.
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
// every current carrier (M1a behaviour).
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
// current carrier: the receiver sees an fseq gap (L43).
func (l *Link) DropNextFrame(d Dir, t FrameType) {
	l.eachFlow(d, func(f *flow) { f.tr.drops = append(f.tr.drops, t) })
}

// InjectAfterNextFrame inserts one frame of type t with the given flags,
// handle and payload after the next frame of type after in direction d, with
// the correct fseq and CRC; later frames of that direction are re-stamped so
// that only the injected frame's semantics can trigger a reaction (stale
// PONG, conflicting FIN, ACK beyond sent, ...).
func (l *Link) InjectAfterNextFrame(d Dir, after, t FrameType, flags uint8, handle uint32, payload []byte) {
	if len(payload) > wire.MaxFramePayload {
		panic("rendrtest: injected payload beyond MaxFramePayload")
	}
	inj := &injection{after: after, t: t, flags: flags, handle: handle, payload: slices.Clone(payload)}
	l.eachFlow(d, func(f *flow) { f.tr.injects = append(f.tr.injects, inj) })
}

// CaptureNextFrame copies the raw bytes (header through trailer) of the next
// frame of type t forwarded in direction d on any current carrier into the
// returned channel (buffered, one frame) and forwards the frame unchanged.
// Tests use it to learn values they cannot compute, such as an old
// incarnation's PING nonce for a stale-PONG injection (L21), or to obtain
// another session's frame for a splice (L43). Without a current carrier the
// channel never receives.
func (l *Link) CaptureNextFrame(d Dir, t FrameType) <-chan []byte {
	cp := &capture{t: t, ch: make(chan []byte, 1)}
	l.eachFlow(d, func(f *flow) { f.tr.captures = append(f.tr.captures, cp) })
	return cp.ch
}

// InjectRaw inserts raw at the next frame boundary in direction d on every
// current carrier, byte for byte: neither fseq nor CRC is re-stamped, so
// spliced bytes of another carrier or session hit the receiver's fseq and
// CRC checks exactly as a misbehaving relay's would (L43). Counted as
// FramesInjected. A carrier that is between frames gets raw at once.
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

// ScriptWrites makes the next Writes of side d's conn (Up: the dialer's
// conn, Down: the passive's) return the scripted results (L42).
func (l *Link) ScriptWrites(d Dir, r ...WriteResult) {
	l.mu.Lock()
	s := &l.sides[d.index()]
	s.scripts = append(s.scripts, r...)
	l.rearm(d.index())
	l.mu.Unlock()
}

// BlockWrites blocks Writes of side d's conns per m (BlockOff lifts it).
func (l *Link) BlockWrites(d Dir, m BlockMode) {
	l.mu.Lock()
	if !l.closed {
		l.sides[d.index()].block = m
		l.bumpBlock()
		l.rearm(d.index())
	}
	l.mu.Unlock()
}

// PanicWrites makes the next Write of side d's conns panic (L51).
func (l *Link) PanicWrites(d Dir) {
	l.mu.Lock()
	l.sides[d.index()].panics++
	l.rearm(d.index())
	l.mu.Unlock()
}

// OverRead makes the next Read of side d's conns that returns data report
// len(p)+1 (L42).
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
			Seq:     c.seq,
			First:   FrameType(c.first.Load()),
			Session: c.kind.Load() == kindSession,
			Up:      c.up.Load(),
			Down:    c.down.Load(),
			Held:    c.held.Load(),
			Closed:  c.closed.Load(),
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

// Counts are fault and traffic counters of a set of carriers.
type Counts struct {
	Killed          int64         // carriers closed by Kill
	Bytes           int64         // bytes forwarded (both directions)
	Dropped         int64         // bytes discarded by the blackhole
	Held            int64         // chunks held back by a stall
	Corrupted       int64         // chunks corrupted by CorruptNext
	FramesCorrupted int64         // frames damaged by CorruptNextFrame
	FramesDropped   int64         // frames removed by DropNextFrame
	FramesInjected  int64         // frames inserted by InjectAfterNextFrame or InjectRaw
	BufferLost      int64         // bytes accepted by a Write and lost when the carrier was killed
	MaxDelay        time.Duration // largest delay applied
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
	Seq      int       // creation order on its link
	First    FrameType // first frame type after the PREFACE (0 until it crossed)
	Session  bool      // First is OPEN or JOIN
	Up, Down int64     // bytes delivered in each direction
	Held     int64     // chunks held by a stall
	Closed   bool
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
	// Counted but not (yet) part of Counts: conn misbehaviours and captures.
	cScripted
	cBlocked
	cPanics
	cOverReads
	cCaptured
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
