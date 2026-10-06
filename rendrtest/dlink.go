package rendrtest

import (
	"context"
	"net"
	"runtime"
	"slices"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// M2 frame types for frame-targeted controls (values equal the wire
// format's type bytes). A datagram control matching FrameRel matches every
// REL; matching a wrapped type (FrameFin, FrameSched, FrameOpenAck, …) also
// looks inside REL frames.
const (
	FrameDgram FrameType = 0x20
	FramePack  FrameType = 0x21
	FrameRel   FrameType = 0x34
	FrameRack  FrameType = 0x35
)

// DialNilAddr makes a datagram factory return (pc, nil, nil): rendr must
// close pc once and count a failed dial (L51).
const DialNilAddr DialBehavior = 8

// MTUMode selects what a datagram link does with a datagram above its MTU.
type MTUMode uint8

// MTU modes.
const (
	MTUDrop   MTUMode = 1 // the datagram is silently lost (a path MTU black hole)
	MTURefuse MTUMode = 2 // WriteTo returns a *wire.DatagramTooLargeError{Max: MTU} (an embedder conn that knows its limit)
)

// DatagramLinkConfig configures a DatagramLink.
type DatagramLinkConfig struct {
	// Name is the link's name (and its jitter and loss seed).
	Name string
	// Accept receives the passive end of every new carrier, typically
	// (*rendr.Listener).HandlePacket. It must return; on an error (or when
	// nil) the passive end is closed.
	Accept func(pc net.PacketConn, peer net.Addr) error
	// MTU is the largest datagram carried (default and maximum 65,507); a
	// larger WriteTo is refused (MTURefuse) until SetMTU chooses otherwise.
	MTU int
	// Queue is how many datagrams per direction may wait in the link
	// (default 1024); more are tail-dropped and counted as lost. The bound
	// is shared by every carrier of the link and holds a datagram from its
	// WriteTo until a reader takes it: held by a stall, waiting at the rate
	// bottleneck, on its way (delay) or arrived and unread. A direction
	// thus carries at most Queue datagrams per one-way delay (the default:
	// about 10,000 per second at 100 ms), and the datagrams waiting at a
	// conn that nobody reads take room from every carrier until that conn
	// is closed: give high-rate or long-delay scenarios a larger Queue.
	Queue int
}

// DatagramLink is an in-memory datagram path (M2 design §A8.1; plan:637):
// every Dial creates one carrier, a pair of net.PacketConns built from
// channels and timers with distinct fake *net.UDPAddr addresses, whose
// passive end is pushed into Accept. Each direction applies delay and
// jitter (reordering allowed: datagrams are independent), a rate limit
// shared by the link's carriers, random or targeted loss, duplication,
// reordering, an MTU, blackhole and stall; conn misbehaviour (scripted
// write counts, read faults, truncation, foreign sources) and factory
// misbehaviour (DialBehavior, DialNilAddr) test rendr's distrust of
// embedder conns. Every control is counted (Stats), split into all, session
// and probe carriers (classified by the first datagram: PREFACE ‖ REL{OPEN
// or JOIN} = session, PREFACE ‖ PING = probe) for stimulus proofs (L63).
//
// Controls apply to every carrier of the link, current and future. The
// one-shot controls are consumed by the next matching datagram or call on
// any carrier, whichever carrier that is: on a link that also carries a
// probe carrier a stimulus proof checks Stats().Session (or the test keeps
// one carrier). Direction controls (SetDelay … ForeignNext) take the
// direction a datagram travels (Up: dialer → passive); conn controls
// (ScriptWrites, ReadFaults, TruncateNext) take the side whose conns make
// the call (Up: the dialer's conns, Down: the passive's).
//
// Counters without a field of their own: Stall shows in arrival times,
// Kill in Lost (the datagrams it lost) and in the conns' errors, CaptureNext
// in its channel.
//
// Queue (DatagramLinkConfig) bounds each direction over all carriers, from
// WriteTo to the reader, transit included: datagrams per second × one-way
// delay must stay well below it, or the link tail-drops on its own.
//
// Accounting, per class: Sent + Duplicated + Injected = Delivered +
// Truncated + Lost + the datagrams still in the link. Sent counts the
// datagrams WriteTo accepted (an MTUDrop loss included, an MTURefuse
// refusal not: that is Oversize only); Lost every one the link dropped
// (loss, DropNext, blackhole, a full queue, Kill, Close, a closed receiver,
// a WriteTo to an address no conn has, MTUDrop).
//
// Create a DatagramLink inside the synctest bubble that uses it; Close it
// before the bubble ends. Datagrams carry no flow header: a DatagramLink
// serves Listener.HandlePacket. DatagramHub serves FromPacketConn.
type DatagramLink struct {
	cfg DatagramLinkConfig
	n   *dnet

	// guarded by n.mu
	refuse  bool
	dialBeh DialBehavior
	release chan struct{} // closed by Release (then renewed) and by Close (for good)
	live    []*dcarrier   // carriers with at least one end not closed or killed
	created int
	queued  [2]int // datagrams in the link per direction
}

// dcarrier is one carrier of a DatagramLink: the dialer's end ep[0]
// (receives Down) and the passive's end ep[1] (receives Up).
type dcarrier struct {
	l     *DatagramLink
	seq   int
	ep    [2]*endpoint
	kind  int32 // n.mu; classified by the dialer's first datagram
	typed bool
}

// NewDatagramLink returns a link; nothing runs until the first Dial.
func NewDatagramLink(cfg DatagramLinkConfig) *DatagramLink {
	return &DatagramLink{cfg: cfg, n: newDnet(cfg.Name, cfg.Queue, cfg.MTU, 3), release: make(chan struct{})}
}

// Name returns the link's name.
func (l *DatagramLink) Name() string { return l.cfg.Name }

// Dial is a rendr.DatagramCarrier.Dial (tests build rendr.DatagramCarrier{
// Name, Dial: l.Dial, MTU} themselves: rendrtest never imports rendr). It
// creates one carrier (honouring Refuse and SetDialBehavior), passes the
// passive end and the dialer's address to Accept on a link-owned goroutine,
// and returns the dialer's end and the passive's address.
func (l *DatagramLink) Dial(ctx context.Context) (net.PacketConn, net.Addr, error) {
	n := l.n
	n.dials.Add(1)
	n.mu.Lock()
	beh, refuse, closed, rel := l.dialBeh, l.refuse, n.closed, l.release
	n.mu.Unlock()
	fail := func(err error) (net.PacketConn, net.Addr, error) {
		n.dialFails.Add(1)
		return nil, nil, err
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
		n.dialFails.Add(1)
		return nil, nil, nil
	case DialPanic:
		n.dialFails.Add(1)
		panic("rendrtest: scripted factory panic")
	case DialGoexit:
		n.dialFails.Add(1)
		runtime.Goexit()
	case DialLateSuccess:
		<-rel
	case DialNilAddr:
		pc, _, err := l.open()
		if err != nil {
			return nil, nil, err
		}
		n.dialFails.Add(1)
		return pc, nil, nil
	default:
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
	}
	return l.open()
}

// open creates a carrier and starts its Accept call.
func (l *DatagramLink) open() (net.PacketConn, net.Addr, error) {
	n := l.n
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		n.dialFails.Add(1)
		return nil, nil, net.ErrClosed
	}
	k := l.created
	l.created++
	c := &dcarrier{l: l, seq: k, kind: kindUnknown}
	c.ep[0] = n.newEndpoint(fakeAddr(1, k), Down.index(), 0, &c.kind, c)
	c.ep[1] = n.newEndpoint(fakeAddr(2, k), Up.index(), 1, &c.kind, c)
	l.live = append(l.live, c)
	n.carriers.Add(1)
	n.wg.Add(1)
	accept := l.cfg.Accept
	n.mu.Unlock()
	go func() {
		defer n.wg.Done()
		if accept == nil || accept(c.ep[1], c.ep[0].laddr) != nil {
			c.ep[1].Close()
		}
	}()
	return c.ep[0], c.ep[1].laddr, nil
}

func (c *dcarrier) first(e *endpoint, p []byte) {
	if !c.typed && e == c.ep[0] {
		c.typed, c.kind = true, classifyDatagram(p)
	}
}

// out routes a datagram to the carrier's other end; any other address is
// a datagram to nowhere.
func (c *dcarrier) out(e *endpoint, p []byte, addr net.Addr) (droute, bool) {
	i := e.side // the dialer's end sends Up (0), the passive's Down (1)
	peer := c.ep[1-i]
	return droute{dst: peer, src: e.laddr, dir: i, cls: c.kind, q: &c.l.queued[i]}, sameAddr(addr, peer.laddr)
}

func (c *dcarrier) arrive(_ *endpoint, dg *dgram) ([]byte, bool) { return dg.b, true }

func (c *dcarrier) gone(e *endpoint) {
	if o := c.ep[1-e.side]; o.closed || o.killed {
		if i := slices.Index(c.l.live, c); i >= 0 {
			c.l.live = slices.Delete(c.l.live, i, i+1)
		}
	}
}

// SetDelay sets the one-way delay and jitter of direction d (per datagram;
// reordering follows from the jitter). Datagrams already on the wire keep
// their arrival time.
func (l *DatagramLink) SetDelay(d Dir, delay, jitter time.Duration) {
	l.n.mu.Lock()
	p := &l.n.dirs[d.index()]
	p.delay, p.jitter = max(delay, 0), max(jitter, 0)
	l.n.mu.Unlock()
}

// SetRate limits direction d to bytesPerSec (0: unlimited), one bottleneck
// shared by the link's carriers: datagrams of every carrier are
// transmitted one after the other in the order they were written, each
// taking len/bytesPerSec, before their delay. The rate applies to
// datagrams written after the call. Datagrams lost to a blackhole or Kill
// give their bottleneck time back; a datagram that reaches a closed conn
// has taken its share.
func (l *DatagramLink) SetRate(d Dir, bytesPerSec float64) {
	l.n.mu.Lock()
	l.n.dirs[d.index()].rate = max(bytesPerSec, 0)
	l.n.mu.Unlock()
}

// SetLoss drops each datagram of direction d with probability p (seeded).
func (l *DatagramLink) SetLoss(d Dir, p float64) {
	l.n.mu.Lock()
	l.n.dirs[d.index()].loss = p
	l.n.mu.Unlock()
}

// SetDuplicate delivers each datagram of direction d twice with probability
// p; the copy takes no bottleneck time and draws its own delay.
func (l *DatagramLink) SetDuplicate(d Dir, p float64) {
	l.n.mu.Lock()
	l.n.dirs[d.index()].dup = p
	l.n.mu.Unlock()
}

// SetReorder delays each datagram of direction d by extra with probability p.
func (l *DatagramLink) SetReorder(d Dir, p float64, extra time.Duration) {
	l.n.mu.Lock()
	path := &l.n.dirs[d.index()]
	path.reorder, path.extra = p, max(extra, 0)
	l.n.mu.Unlock()
}

// SetMTU sets the largest datagram both directions carry (n ≤ 0 or above
// 65,507: 65,507) and what happens to a larger one. It panics for an
// unknown mode.
func (l *DatagramLink) SetMTU(n int, mode MTUMode) {
	if mode != MTUDrop && mode != MTURefuse {
		panic("rendrtest: unknown MTUMode")
	}
	if n <= 0 || n > wire.MaxDatagram {
		n = wire.MaxDatagram
	}
	l.n.mu.Lock()
	l.n.mtu, l.n.mtuMode = n, mode
	l.n.mu.Unlock()
}

// Blackhole drops (on) or passes (off) every datagram of direction d. At
// the start of a blackhole the datagrams of d still in flight or held by a
// stall are lost too (their bottleneck time given back); the ones that
// already arrived stay readable.
func (l *DatagramLink) Blackhole(d Dir, on bool) {
	l.n.mu.Lock()
	l.n.setBlackhole(d.index(), on)
	l.n.mu.Unlock()
}

// Stall holds (on) or releases (off) direction d: datagrams queue up to
// Queue, WriteTo keeps returning. Nothing that had not arrived when the
// stall began arrives while it lasts; at the release every datagram whose
// arrival time passed arrives at once and the ones written meanwhile are
// transmitted from then on (at the rate).
func (l *DatagramLink) Stall(d Dir, on bool) {
	l.n.mu.Lock()
	l.n.setStall(d.index(), on)
	l.n.mu.Unlock()
}

// Kill fails every current carrier of the link: both conns return
// net.ErrClosed from then on (their first Close still succeeds), and the
// datagrams in flight between them are lost (their bottleneck time given
// back). Later Dials create new carriers.
func (l *DatagramLink) Kill() {
	l.n.mu.Lock()
	l.kill(true)
	l.n.mu.Unlock()
}

// kill fails every live carrier: nothing of the link is in flight any
// more, so both bottlenecks are free at once. n.mu held.
func (l *DatagramLink) kill(counted bool) {
	for _, c := range slices.Clone(l.live) {
		killed := false
		for _, e := range c.ep {
			killed = e.shut(true) || killed
		}
		if killed && counted {
			l.n.count(c.kind, dcKilled, 1)
		}
	}
	l.live = nil
	now := time.Now()
	for i := range l.n.dirs {
		l.n.dirs[i].idle(now)
	}
}

// Refuse makes later Dials fail (on) or succeed (off).
func (l *DatagramLink) Refuse(on bool) {
	l.n.mu.Lock()
	l.refuse = on
	l.n.mu.Unlock()
}

// SetDialBehavior makes later Dials misbehave (DialBehavior, DialNilAddr).
func (l *DatagramLink) SetDialBehavior(b DialBehavior) {
	l.n.mu.Lock()
	l.dialBeh = b
	l.n.mu.Unlock()
}

// Release ends a hanging Dial (DialHang, DialHangForever, DialLateSuccess).
func (l *DatagramLink) Release() {
	l.n.mu.Lock()
	if !l.n.closed {
		close(l.release)
		l.release = make(chan struct{})
	}
	l.n.mu.Unlock()
}

// DropNext drops the next n datagrams of direction d that carry a frame of
// type t (inside REL as well), on any carrier.
func (l *DatagramLink) DropNext(d Dir, t FrameType, n int) {
	if n <= 0 {
		return
	}
	l.n.mu.Lock()
	p := &l.n.dirs[d.index()]
	p.drops = append(p.drops, dropOp{t: t, n: n})
	l.n.mu.Unlock()
}

// CorruptNext flips one bit — the lowest bit of the middle byte — of the
// next non-empty datagram a reader of direction d takes.
func (l *DatagramLink) CorruptNext(d Dir) {
	l.n.mu.Lock()
	l.n.dirs[d.index()].corrupt++
	l.n.mu.Unlock()
}

// InjectRaw delivers b as one datagram in direction d on the newest
// carrier: it arrives at once from the carrier's other end, untouched by
// the path's controls (counted as Injected). Without a carrier, or when
// the newest carrier's receiving end is closed, nothing happens.
func (l *DatagramLink) InjectRaw(d Dir, b []byte) {
	n := l.n
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(l.live) == 0 {
		return
	}
	c, i := l.live[len(l.live)-1], d.index()
	dst, src := c.ep[1-i], c.ep[i]
	if dst.closed || dst.killed {
		return
	}
	n.count(c.kind, dcInjected, 1)
	q := &l.queued[i]
	if *q >= n.queue {
		n.count(c.kind, dcLost, 1)
		return
	}
	dg := n.newDgram(len(b))
	copy(dg.b, b)
	dg.src, dg.cls, dg.q, dg.dir = src.laddr, c.kind, q, i
	*q++
	dst.inject(time.Now(), dg)
}

// CaptureNext returns a copy of the next datagram of direction d that
// carries a frame of type t (inside REL as well), on any carrier, as the
// sender wrote it: the copy is taken before the path's controls, so the
// datagram may still be lost (a DropNext of the same type drops the
// datagram the capture copied). Two captures armed for one type receive
// two consecutive matching datagrams. The channel is buffered (one).
func (l *DatagramLink) CaptureNext(d Dir, t FrameType) <-chan []byte {
	c := &dcapture{t: t, ch: make(chan []byte, 1)}
	l.n.mu.Lock()
	p := &l.n.dirs[d.index()]
	p.captures = append(p.captures, c)
	l.n.mu.Unlock()
	return c.ch
}

// ScriptWrites makes the next WriteTo calls of side d's conns (Up = the
// dialer's) return the given results, as Link.ScriptWrites (L42): each is
// consumed by the next WriteTo on any conn of that side. N (relative to
// len(p) when Relative) and Err are returned; with Transmit the first N
// bytes are sent as a datagram; ZeroWrite returns (0, nil) and sends
// nothing.
func (l *DatagramLink) ScriptWrites(d Dir, rs ...WriteResult) {
	l.n.mu.Lock()
	s := &l.n.sides[d.index()]
	s.scripts = append(s.scripts, rs...)
	l.n.mu.Unlock()
}

// ReadFaults makes the next ReadFrom calls of side d's conns return the
// given errors before any datagram (ICMP-class or permanent, L58), one per
// call; a waiting ReadFrom returns its fault at once.
func (l *DatagramLink) ReadFaults(d Dir, errs ...error) {
	n := l.n
	n.mu.Lock()
	i := d.index()
	n.sides[i].faults = append(n.sides[i].faults, errs...)
	for _, e := range n.eps {
		if e.side == i {
			signal(e.wake)
		}
	}
	n.mu.Unlock()
}

// TruncateNext makes the next ReadFrom of side d report a truncated
// datagram: Linux style (n == len(p), nil) or Windows style (n == len(p)
// with a *net.OpError wrapping syscall.Errno(10040), WSAEMSGSIZE, on every
// OS: rendr classifies embedder errors by one platform-independent table,
// M2 design Revision 1, R1-28). It applies to the next datagram that
// arrives, which is lost to the reader: p holds its first bytes (the rest
// of p is zeroed), and the Windows style reports no source address.
func (l *DatagramLink) TruncateNext(d Dir, windows bool) {
	l.n.mu.Lock()
	s := &l.n.sides[d.index()]
	s.truncs = append(s.truncs, windows)
	l.n.mu.Unlock()
}

// ForeignNext delivers the next datagram of direction d from another
// address (L59): a fresh one that no conn of the link has.
func (l *DatagramLink) ForeignNext(d Dir) {
	l.n.mu.Lock()
	l.n.dirs[d.index()].foreign++
	l.n.mu.Unlock()
}

// Stats returns the link's counters.
func (l *DatagramLink) Stats() DatagramStats { return l.n.stats() }

// Close kills every carrier and joins every goroutine the link started; it
// releases hanging Dials, and later Dials fail. Idempotent.
func (l *DatagramLink) Close() error {
	n := l.n
	n.mu.Lock()
	if !n.closed {
		n.closed = true
		close(l.release)
		l.kill(false)
	}
	n.mu.Unlock()
	n.wg.Wait()
	return nil
}

// DatagramCounts count one class of carriers of a datagram link or hub.
type DatagramCounts struct {
	Sent, Delivered, Lost, Duplicated, Reordered uint64
	Oversize, Injected, Corrupted, Truncated     uint64
	Foreign, ScriptedWrites, ReadFaults          uint64
}

// DatagramStats are a datagram link's or hub's counters.
type DatagramStats struct {
	All, Session, Probe DatagramCounts
	Dials, DialFailures uint64
	Carriers            int // carriers created
	Rebinds, Spoofed    uint64
}
