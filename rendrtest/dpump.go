package rendrtest

import (
	"bytes"
	"errors"
	"hash/fnv"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// The machinery DatagramLink and DatagramHub share (M2 design §A8.1): fake
// UDP sockets ("endpoints") that receive into a heap of datagrams in
// flight, ordered by arrival time, and a FIFO of arrived ones; the path of
// each direction (one bottleneck shared by every carrier, delay and jitter,
// seeded loss, duplication and reordering, blackhole, stall); the one-shot
// controls; the counters; and the frame classification of datagrams.
//
// Nothing here runs a goroutine: a datagram's arrival time is computed when
// it is written, and a reader waits for the earliest arrival on a timer of
// its own. Every wait selects on channels and timers created by whoever
// built the network, so inside a synctest bubble every wait is durable.

// kindNone marks datagrams of no carrier (Spoof and Flood): they are
// counted in no class.
const kindNone int32 = -1

// Defaults of both fakes.
const (
	defaultDgramQueue = 1024
	recycleMax        = 256     // recycled datagrams kept
	recycleCap        = 4 << 10 // largest buffer recycled
	compactReady      = 1024    // ready FIFO head that triggers a compaction
)

// errWSAEMSGSIZE is Windows' WSAEMSGSIZE, which rendr classifies by number
// on every OS (M2 design Revision 1, R1-28).
const errWSAEMSGSIZE = syscall.Errno(10040)

// errMissingAddress is what net.UDPConn.WriteTo returns for a nil
// *net.UDPAddr.
var errMissingAddress = errors.New("missing address")

// dnet is one fake network: a DatagramLink or a DatagramHub. mu guards the
// network, its endpoints and every datagram in it; the counters are atomic
// so that Stats never waits.
type dnet struct {
	mu      sync.Mutex
	closed  bool
	queue   int // bound of every datagram queue (per link direction; per hub client and direction)
	mtu     int
	mtuMode MTUMode
	dirs    [2]dpath    // [Up.index()] dialer → passive, [Down.index()] passive → dialer
	sides   [2]dside    // conn misbehaviours of the dialer's side [0] and the passive's [1]
	eps     []*endpoint // open endpoints
	seq     uint64      // arrival order among equal arrival times
	free    []*dgram    // recycled datagrams
	fpool   byte        // address pool of foreign addresses
	nextFor int         // foreign addresses handed out

	ctr       [3]dcounters // all, session, probe
	dials     atomic.Uint64
	dialFails atomic.Uint64
	carriers  atomic.Int64
	rebinds   atomic.Uint64
	spoofed   atomic.Uint64
	wg        sync.WaitGroup // goroutines the network started (Accept calls, floods)
}

// dpath is one direction of a network. Every datagram written into it
// passes, in this order: the capture tap (CaptureNext sees what the sender
// wrote), the blackhole, DropNext, seeded loss, the queue bound (tail
// drop) and duplication; then — unless the direction is stalled, which
// holds it — its transmission at the shared bottleneck (rate), one delay
// with jitter and, with probability reorder, an extra delay. CorruptNext,
// ForeignNext and the read-side controls act when a reader takes it.
type dpath struct {
	delay, jitter time.Duration
	rate          float64   // bytes per second; 0: unlimited
	busy          time.Time // the bottleneck transmits until then
	loss, dup     float64
	reorder       float64
	extra         time.Duration
	blackhole     bool
	stalled       bool
	stallAt       time.Time
	held          []*dgram // accepted while stalled, transmitted at the release
	rng           *rand.Rand
	drops         []dropOp
	captures      []*dcapture
	corrupt       int // pending CorruptNext
	foreign       int // pending ForeignNext
}

// dside holds the conn misbehaviours of one side, each consumed by the next
// matching call on any conn of that side.
type dside struct {
	scripts []WriteResult
	faults  []error
	truncs  []bool // pending TruncateNext; true: Windows style
}

type dropOp struct {
	t FrameType
	n int
}

type dcapture struct {
	t  FrameType
	ch chan []byte
}

// dgram is one datagram in a network.
type dgram struct {
	b    []byte
	due  time.Time // arrival time at dst
	seq  uint64
	src  *net.UDPAddr // the source dst's reader sees
	dst  *endpoint
	cls  int32 // class of its carrier (counters)
	q    *int  // the queue it counts against
	dir  int
	ext  netip.AddrPort // DatagramHub, passive → client: the address it was sent to
	dupe bool           // a duplicate: it takes no bottleneck time
}

func (a *dgram) before(b *dgram) bool {
	return a.due.Before(b.due) || a.due.Equal(b.due) && a.seq < b.seq
}

// droute is where a datagram a conn writes goes.
type droute struct {
	dst *endpoint
	src *net.UDPAddr // the source the receiver sees
	dir int
	cls int32
	q   *int
	pre []byte         // bytes the network puts in front (the hub client's flow header)
	ext netip.AddrPort // the destination address (DatagramHub replies)
	rec *hclient       // a hub client whose datagrams Replay may repeat
}

// epOwner is what an endpoint belongs to: a carrier of a DatagramLink, a
// client of a DatagramHub, or the hub's socket. Every method runs with the
// network's lock held.
type epOwner interface {
	// first sees every datagram the endpoint is asked to write, before any
	// control: a carrier is classified by its dialer's first datagram.
	first(e *endpoint, p []byte)
	// out resolves a datagram written to addr; ok is false when nothing
	// listens there (the datagram is lost, counted in r.cls).
	out(e *endpoint, p []byte, addr net.Addr) (r droute, ok bool)
	// arrive returns the bytes of a datagram the endpoint's reader takes;
	// ok is false when it is lost on the last hop.
	arrive(e *endpoint, dg *dgram) (b []byte, ok bool)
	// gone tells the owner that the endpoint was closed or killed.
	gone(e *endpoint)
}

// endpoint is one fake UDP socket: a net.PacketConn whose methods take the
// network's lock. It offers only the net.PacketConn methods: rendr must use
// it as any embedder conn (L57).
type endpoint struct {
	n      *dnet
	laddr  *net.UDPAddr
	rx     int    // the direction it receives
	side   int    // 0 the dialer's side, 1 the passive's
	kind   *int32 // the class its own calls count in
	owner  epOwner
	in     []*dgram // in flight: a min-heap by (due, seq)
	ready  []*dgram // arrived, in arrival order: ready[rhead:]
	rhead  int
	closed bool          // Close was called
	killed bool          // Kill or the network's Close failed it
	wake   chan struct{} // cap 1: something for a waiting reader
	done   chan struct{} // closed when the endpoint is closed or killed
	rdl    time.Time
	wdl    time.Time
	dlCh   chan struct{} // closed and renewed when the read deadline changes
	tm     *time.Timer   // a stopped timer for the next ReadFrom that waits
}

var _ net.PacketConn = (*endpoint)(nil)

// newDnet returns a network whose randomness is seeded by name: equal names
// give equal loss, duplication, reordering and jitter sequences.
func newDnet(name string, queue, mtu int, fpool byte) *dnet {
	h := fnv.New64a()
	h.Write([]byte(name))
	s := h.Sum64()
	if queue <= 0 {
		queue = defaultDgramQueue
	}
	if mtu <= 0 || mtu > wire.MaxDatagram {
		mtu = wire.MaxDatagram
	}
	n := &dnet{queue: queue, mtu: mtu, mtuMode: MTURefuse, fpool: fpool}
	n.dirs[0].rng = rand.New(rand.NewPCG(s, s^0x9e3779b97f4a7c15))
	n.dirs[1].rng = rand.New(rand.NewPCG(s^1, s^0x7f4a7c159e3779b9))
	return n
}

// newEndpoint creates an open endpoint. n.mu held.
func (n *dnet) newEndpoint(laddr *net.UDPAddr, rx, side int, kind *int32, o epOwner) *endpoint {
	e := &endpoint{n: n, laddr: laddr, rx: rx, side: side, kind: kind, owner: o,
		wake: make(chan struct{}, 1), done: make(chan struct{}), dlCh: make(chan struct{})}
	n.eps = append(n.eps, e)
	return e
}

// fakeAddr is address k of pool p: 127.p.x.y and a port, distinct for every
// k of a pool (loopback addresses that nothing real ever answers).
func fakeAddr(p byte, k int) *net.UDPAddr {
	q, r := k/60000, k%60000
	ip := netip.AddrFrom4([4]byte{127, p, byte(q >> 8), byte(q)})
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, uint16(2000+r)))
}

// foreignAddr hands out a fresh address of the network's foreign pool.
// n.mu held.
func (n *dnet) foreignAddr() *net.UDPAddr {
	n.nextFor++
	return fakeAddr(n.fpool, n.nextFor)
}

// apOf returns a *net.UDPAddr's address and port (IPv4-mapped unmapped).
func apOf(a net.Addr) (netip.AddrPort, bool) {
	u, ok := a.(*net.UDPAddr)
	if !ok || u == nil {
		return netip.AddrPort{}, false
	}
	ap := u.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}

// sameAddr reports whether a names b: the same pointer or an equal
// *net.UDPAddr.
func sameAddr(a net.Addr, b *net.UDPAddr) bool {
	if u, ok := a.(*net.UDPAddr); ok && u == b {
		return true
	}
	x, ok := apOf(a)
	y, _ := apOf(b)
	return ok && x == y
}

// dctr indexes the datagram counters. The first twelve are DatagramCounts'
// fields; the rest have no exported field.
type dctr int

const (
	dcSent dctr = iota
	dcDelivered
	dcLost
	dcDuplicated
	dcReordered
	dcOversize
	dcInjected
	dcCorrupted
	dcTruncated
	dcForeign
	dcScripted
	dcReadFaults
	dcHeld     // datagrams a stall held
	dcKilled   // carriers Kill failed
	dcCaptured // datagrams CaptureNext copied
	nDctr
)

type dcounters [nDctr]atomic.Uint64

func (c *dcounters) snap() DatagramCounts {
	return DatagramCounts{
		Sent:           c[dcSent].Load(),
		Delivered:      c[dcDelivered].Load(),
		Lost:           c[dcLost].Load(),
		Duplicated:     c[dcDuplicated].Load(),
		Reordered:      c[dcReordered].Load(),
		Oversize:       c[dcOversize].Load(),
		Injected:       c[dcInjected].Load(),
		Corrupted:      c[dcCorrupted].Load(),
		Truncated:      c[dcTruncated].Load(),
		Foreign:        c[dcForeign].Load(),
		ScriptedWrites: c[dcScripted].Load(),
		ReadFaults:     c[dcReadFaults].Load(),
	}
}

// count adds v to counter k of all carriers and of class cls.
func (n *dnet) count(cls int32, k dctr, v uint64) {
	if v == 0 || cls == kindNone {
		return
	}
	n.ctr[0][k].Add(v)
	switch cls {
	case kindSession:
		n.ctr[1][k].Add(v)
	case kindProbe:
		n.ctr[2][k].Add(v)
	}
}

func (n *dnet) stats() DatagramStats {
	return DatagramStats{
		All:          n.ctr[0].snap(),
		Session:      n.ctr[1].snap(),
		Probe:        n.ctr[2].snap(),
		Dials:        n.dials.Load(),
		DialFailures: n.dialFails.Load(),
		Carriers:     int(n.carriers.Load()),
		Rebinds:      n.rebinds.Load(),
		Spoofed:      n.spoofed.Load(),
	}
}

// newDgram returns a datagram with a buffer of size bytes. n.mu held.
func (n *dnet) newDgram(size int) *dgram {
	if k := len(n.free); k > 0 {
		dg := n.free[k-1]
		n.free[k-1] = nil
		n.free = n.free[:k-1]
		if cap(dg.b) >= size {
			dg.b = dg.b[:size]
		} else {
			dg.b = make([]byte, size)
		}
		return dg
	}
	return &dgram{b: make([]byte, size)}
}

// recycle keeps dg's buffer for a later datagram. n.mu held.
func (n *dnet) recycle(dg *dgram) {
	b := dg.b[:0]
	*dg = dgram{}
	if cap(b) <= recycleCap && len(n.free) < recycleMax {
		dg.b = b
		n.free = append(n.free, dg)
	}
}

// lose drops a datagram that was in the network: counted lost. n.mu held.
func (n *dnet) lose(dg *dgram) {
	n.count(dg.cls, dcLost, 1)
	*dg.q--
	n.recycle(dg)
}

// transmit takes p, accepted by a WriteTo at now, into the path of r.dir
// toward r.dst (see dpath for the order). n.mu held.
func (n *dnet) transmit(now time.Time, r droute, p []byte) {
	path := &n.dirs[r.dir]
	cls := r.cls
	n.count(cls, dcSent, 1)
	if r.rec != nil {
		r.rec.record(r.pre, p)
	}
	if len(path.captures) > 0 {
		n.tap(path, cls, p)
	}
	if path.blackhole || path.takeDrop(p) || path.loss > 0 && path.rng.Float64() < path.loss {
		n.count(cls, dcLost, 1)
		return
	}
	dup := path.dup > 0 && path.rng.Float64() < path.dup
	for i := range 2 {
		if i == 1 && !dup {
			return
		}
		if *r.q >= n.queue { // tail drop; a duplicate that does not fit is not made
			if i == 0 {
				n.count(cls, dcLost, 1)
			}
			return
		}
		dg := n.newDgram(len(r.pre) + len(p))
		copy(dg.b[copy(dg.b, r.pre):], p)
		dg.src, dg.dst, dg.cls, dg.q, dg.dir, dg.ext, dg.dupe = r.src, r.dst, cls, r.q, r.dir, r.ext, i == 1
		*r.q++
		if i == 1 {
			n.count(cls, dcDuplicated, 1)
		}
		if path.stalled {
			path.held = append(path.held, dg)
			n.count(cls, dcHeld, 1)
			continue
		}
		n.launch(path, dg, now)
	}
}

// launch puts dg on the wire of its path at now: after its transmission at
// the shared bottleneck (a duplicate takes none), one delay with jitter
// later, plus the reorder delay when drawn. n.mu held.
func (n *dnet) launch(p *dpath, dg *dgram, now time.Time) {
	dst := dg.dst
	if dst.closed || dst.killed {
		n.lose(dg) // UDP to a closed port
		return
	}
	end := now
	if p.rate > 0 {
		end = maxTime(p.busy, now)
		if !dg.dupe {
			end = end.Add(time.Duration(float64(len(dg.b)) / p.rate * float64(time.Second)))
			p.busy = end
		}
	}
	d := p.delay
	if p.jitter > 0 {
		d = max(d+time.Duration(p.rng.Int64N(int64(2*p.jitter)+1))-p.jitter, 0)
	}
	if p.reorder > 0 && p.rng.Float64() < p.reorder {
		d += p.extra
		n.count(dg.cls, dcReordered, 1)
	}
	n.seq++
	dg.due, dg.seq = end.Add(d), n.seq
	dst.pushIn(dg)
	signal(dst.wake)
}

// tap gives a copy of b to the earliest armed capture whose type b
// carries. n.mu held.
func (n *dnet) tap(p *dpath, cls int32, b []byte) {
	for i, c := range p.captures {
		if carries(b, c.t) {
			p.captures = slices.Delete(p.captures, i, i+1)
			c.ch <- bytes.Clone(b) // buffered, and every capture fires once
			n.count(cls, dcCaptured, 1)
			return
		}
	}
}

// takeDrop consumes one armed DropNext whose type b carries.
func (p *dpath) takeDrop(b []byte) bool {
	for i := range p.drops {
		if carries(b, p.drops[i].t) {
			if p.drops[i].n--; p.drops[i].n <= 0 {
				p.drops = slices.Delete(p.drops, i, i+1)
			}
			return true
		}
	}
	return false
}

// setBlackhole drops (on) every datagram of direction i from now on,
// including those still in flight or held by a stall (the ones that
// already arrived stay readable); the lost ones give their bottleneck time
// back. n.mu held.
func (n *dnet) setBlackhole(i int, on bool) {
	p := &n.dirs[i]
	p.blackhole = on
	if !on {
		return
	}
	now := time.Now()
	for _, e := range n.eps {
		if e.rx == i {
			e.promote(now)
			for _, dg := range e.in {
				n.lose(dg)
			}
			e.in = nil
		}
	}
	for _, dg := range p.held {
		n.lose(dg)
	}
	p.held = nil
	p.idle(now)
}

// idle gives the bottleneck time of the datagrams still queued at it back,
// once none of them can arrive any more: the bottleneck is free from now
// on. A datagram already past the bottleneck keeps its arrival time.
func (p *dpath) idle(now time.Time) {
	if p.busy.After(now) {
		p.busy = now
	}
}

// setStall holds (on) or releases (off) direction i. While it is held,
// nothing that had not arrived when the stall began arrives, and new
// datagrams wait untransmitted (up to the queue bound). At the release the
// datagrams whose arrival time passed meanwhile arrive at once and the
// waiting ones are transmitted from then on, at the rate. n.mu held.
func (n *dnet) setStall(i int, on bool) {
	p := &n.dirs[i]
	now := time.Now()
	if on {
		if !p.stalled {
			p.stalled, p.stallAt = true, now
		}
		return
	}
	if !p.stalled {
		return
	}
	for _, e := range n.eps {
		if e.rx == i {
			for _, dg := range e.in {
				if dg.due.After(p.stallAt) && !dg.due.After(now) {
					n.count(dg.cls, dcHeld, 1)
				}
			}
		}
	}
	p.stalled = false
	held := p.held
	p.held = nil
	for _, dg := range held {
		n.launch(p, dg, now)
	}
	for _, e := range n.eps {
		if e.rx == i {
			signal(e.wake)
		}
	}
}

// purgeHeld drops the stalled datagrams addressed to e. n.mu held.
func (n *dnet) purgeHeld(e *endpoint) {
	for i := range n.dirs {
		p := &n.dirs[i]
		p.held = slices.DeleteFunc(p.held, func(dg *dgram) bool {
			if dg.dst != e {
				return false
			}
			n.lose(dg)
			return true
		})
	}
}

// pushIn adds dg to the in-flight heap.
func (e *endpoint) pushIn(dg *dgram) {
	h := append(e.in, dg)
	for i := len(h) - 1; i > 0; {
		p := (i - 1) / 2
		if !h[i].before(h[p]) {
			break
		}
		h[i], h[p] = h[p], h[i]
		i = p
	}
	e.in = h
}

// popIn removes the earliest datagram in flight.
func (e *endpoint) popIn() *dgram {
	h := e.in
	top, last := h[0], len(h)-1
	h[0], h[last] = h[last], nil
	h = h[:last]
	for i := 0; ; {
		m := 2*i + 1
		if m >= len(h) {
			break
		}
		if r := m + 1; r < len(h) && h[r].before(h[m]) {
			m = r
		}
		if !h[m].before(h[i]) {
			break
		}
		h[i], h[m] = h[m], h[i]
		i = m
	}
	e.in = h
	return top
}

func (e *endpoint) popReady() *dgram {
	dg := e.ready[e.rhead]
	e.ready[e.rhead] = nil
	e.rhead++
	switch {
	case e.rhead == len(e.ready):
		e.ready, e.rhead = e.ready[:0], 0
	case e.rhead >= compactReady && 2*e.rhead >= len(e.ready):
		k := copy(e.ready, e.ready[e.rhead:])
		clear(e.ready[k:])
		e.ready, e.rhead = e.ready[:k], 0
	}
	return dg
}

// promote moves every datagram that arrived by now from in flight to the
// ready FIFO, in arrival order: its arrival time passed, and its direction
// is not stalled since before it arrived. n.mu held.
func (e *endpoint) promote(now time.Time) {
	p := &e.n.dirs[e.rx]
	for len(e.in) > 0 {
		top := e.in[0]
		if top.due.After(now) || p.stalled && top.due.After(p.stallAt) {
			return
		}
		e.ready = append(e.ready, e.popIn())
	}
}

// nextArrival is the arrival time of the next datagram in flight; zero
// when none can arrive before a control changes. n.mu held.
func (e *endpoint) nextArrival() time.Time {
	if len(e.in) == 0 {
		return time.Time{}
	}
	top, p := e.in[0], &e.n.dirs[e.rx]
	if p.stalled && top.due.After(p.stallAt) {
		return time.Time{}
	}
	return top.due
}

// inject makes dg arrive now, behind everything that arrived before.
// n.mu held.
func (e *endpoint) inject(now time.Time, dg *dgram) {
	e.promote(now)
	e.n.seq++
	dg.due, dg.seq, dg.dst = now, e.n.seq, e
	e.ready = append(e.ready, dg)
	signal(e.wake)
}

// shut closes (kill false) or kills the endpoint; the first of the two
// drops what it holds, wakes every call and tells the owner. It reports
// whether this call ended the endpoint. n.mu held.
func (e *endpoint) shut(kill bool) bool {
	first := !e.closed && !e.killed
	if kill {
		e.killed = true
	} else {
		e.closed = true
	}
	if !first {
		return false
	}
	n := e.n
	for _, dg := range e.in {
		n.lose(dg)
	}
	for _, dg := range e.ready[e.rhead:] {
		n.lose(dg)
	}
	e.in, e.ready, e.rhead = nil, nil, 0
	n.purgeHeld(e)
	close(e.done)
	if i := slices.Index(n.eps, e); i >= 0 {
		n.eps = slices.Delete(n.eps, i, i+1)
	}
	e.owner.gone(e)
	return true
}

func (e *endpoint) opErr(op string, err error) error {
	return &net.OpError{Op: op, Net: "udp", Source: e.laddr, Err: err}
}

// usable returns the error of an operation on an ended endpoint.
func (e *endpoint) usable(op string) error {
	if e.closed || e.killed {
		return e.opErr(op, net.ErrClosed)
	}
	return nil
}

// ReadFrom implements net.PacketConn: the next arrived datagram, its source
// and — when p is too short — Linux-style truncation (n == len(p), nil).
// Read faults come first, then the read deadline; it waits for the next
// arrival, a read-deadline change, Close or Kill.
func (e *endpoint) ReadFrom(p []byte) (int, net.Addr, error) {
	n := e.n
	var tm *time.Timer // the endpoint's spare timer while this call has it
	defer func() {
		if tm != nil {
			tm.Stop()
			n.mu.Lock()
			e.tm = tm
			n.mu.Unlock()
		}
	}()
	n.mu.Lock()
	for {
		if err := e.usable("read"); err != nil {
			n.mu.Unlock()
			return 0, nil, err
		}
		if s := &n.sides[e.side]; len(s.faults) > 0 {
			err := s.faults[0]
			s.faults = s.faults[1:]
			n.count(*e.kind, dcReadFaults, 1)
			e.passOn()
			n.mu.Unlock()
			return 0, nil, err
		}
		now := time.Now()
		if !e.rdl.IsZero() && !now.Before(e.rdl) {
			n.mu.Unlock()
			return 0, nil, e.opErr("read", os.ErrDeadlineExceeded)
		}
		e.promote(now)
		for len(e.ready) > e.rhead {
			dg := e.popReady()
			*dg.q--
			b, ok := e.owner.arrive(e, dg)
			if !ok {
				n.count(dg.cls, dcLost, 1)
				n.recycle(dg)
				continue
			}
			k, addr, err := e.handOver(p, dg, b)
			n.recycle(dg)
			e.passOn()
			n.mu.Unlock()
			return k, addr, err
		}
		until, rdl := e.nextArrival(), e.rdl
		if !rdl.IsZero() && (until.IsZero() || rdl.Before(until)) {
			until = rdl
		}
		wake, dl, done := e.wake, e.dlCh, e.done
		if !until.IsZero() && tm == nil {
			tm, e.tm = e.tm, nil
		}
		n.mu.Unlock()
		var tc <-chan time.Time
		if !until.IsZero() {
			if d := until.Sub(now); tm == nil {
				tm = time.NewTimer(d)
			} else {
				tm.Reset(d)
			}
			tc = tm.C
		}
		select {
		case <-wake:
		case <-dl:
		case <-done:
		case <-tc:
		}
		n.mu.Lock()
	}
}

// passOn hands the wake on to another reader of e blocked in ReadFrom when
// the call that returns leaves something for one: a datagram that arrived
// or is still in flight (a reader blocked since before it was sent, or
// since its direction was stalled, has no timer for it), or a read fault of
// e's side. Deadline changes and the end of e wake every reader
// themselves. n.mu held.
func (e *endpoint) passOn() {
	if len(e.ready) > e.rhead || len(e.in) > 0 || len(e.n.sides[e.side].faults) > 0 {
		signal(e.wake)
	}
}

// handOver gives the reader the datagram bytes b of dg with the read-side
// controls applied: ForeignNext and CorruptNext of its direction, then
// TruncateNext of the reader's side, else Linux-style truncation when p is
// too short. n.mu held.
func (e *endpoint) handOver(p []byte, dg *dgram, b []byte) (int, net.Addr, error) {
	n := e.n
	path, side := &n.dirs[e.rx], &n.sides[e.side]
	addr := net.Addr(dg.src)
	if path.foreign > 0 {
		path.foreign--
		addr = n.foreignAddr()
		n.count(dg.cls, dcForeign, 1)
	}
	if path.corrupt > 0 && len(b) > 0 {
		path.corrupt--
		b[len(b)/2] ^= 0x01
		n.count(dg.cls, dcCorrupted, 1)
	}
	if len(side.truncs) > 0 {
		windows := side.truncs[0]
		side.truncs = side.truncs[1:]
		clear(p[copy(p, b):])
		n.count(dg.cls, dcTruncated, 1)
		if windows {
			return len(p), nil, e.opErr("read", os.NewSyscallError("wsarecvfrom", errWSAEMSGSIZE))
		}
		return len(p), addr, nil
	}
	k := copy(p, b)
	if len(b) > len(p) {
		n.count(dg.cls, dcTruncated, 1)
	} else {
		n.count(dg.cls, dcDelivered, 1)
	}
	return k, addr, nil
}

// WriteTo implements net.PacketConn. It never blocks: the datagram is
// copied into the network (or refused, or lost) at once. A write deadline
// that has passed fails it, and so does an address that is not a
// non-nil *net.UDPAddr, as on a real socket; a datagram to an address that
// no conn has is lost (UDP to nowhere).
func (e *endpoint) WriteTo(p []byte, addr net.Addr) (int, error) {
	n := e.n
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := e.usable("write"); err != nil {
		return 0, err
	}
	now := time.Now()
	if !e.wdl.IsZero() && !now.Before(e.wdl) {
		return 0, e.opErr("write", os.ErrDeadlineExceeded)
	}
	e.owner.first(e, p)
	if s := &n.sides[e.side]; len(s.scripts) > 0 {
		r := s.scripts[0]
		s.scripts = s.scripts[1:]
		n.count(*e.kind, dcScripted, 1)
		return e.scripted(now, p, addr, r)
	}
	return e.send(now, p, addr)
}

// send writes p to addr: as net.UDPConn, an address that is not a
// *net.UDPAddr, or a nil one, fails the call; then the MTU (refused or
// lost) and the route. n.mu held.
func (e *endpoint) send(now time.Time, p []byte, addr net.Addr) (int, error) {
	n := e.n
	switch u, isUDP := addr.(*net.UDPAddr); {
	case !isUDP:
		return 0, &net.OpError{Op: "write", Net: "udp", Source: e.laddr, Addr: addr, Err: syscall.EINVAL}
	case u == nil:
		return 0, e.opErr("write", errMissingAddress)
	}
	r, ok := e.owner.out(e, p, addr)
	if len(r.pre)+len(p) > n.mtu {
		n.count(r.cls, dcOversize, 1)
		if n.mtuMode == MTURefuse {
			return 0, &wire.DatagramTooLargeError{Max: n.mtu - len(r.pre)}
		}
		n.count(r.cls, dcSent, 1)
		n.count(r.cls, dcLost, 1)
		return len(p), nil
	}
	if !ok {
		n.count(r.cls, dcSent, 1)
		n.count(r.cls, dcLost, 1)
		return len(p), nil
	}
	n.transmit(now, r, p)
	return len(p), nil
}

// scripted performs one scripted WriteTo: the reported count and error,
// and with Transmit the first count bytes of p sent as a datagram.
func (e *endpoint) scripted(now time.Time, p []byte, addr net.Addr, r WriteResult) (int, error) {
	if r.ZeroWrite {
		return 0, nil
	}
	k := r.N
	if r.Relative {
		k += len(p)
	}
	if m := min(max(k, 0), len(p)); r.Transmit && m > 0 {
		e.send(now, p[:m], addr)
	}
	return k, r.Err
}

// Close implements net.PacketConn: the datagrams it holds are lost, every
// call returns. A second Close fails, as on a real socket; the first Close
// of a killed endpoint succeeds.
func (e *endpoint) Close() error {
	n := e.n
	n.mu.Lock()
	defer n.mu.Unlock()
	if e.closed {
		return e.opErr("close", net.ErrClosed)
	}
	e.shut(false)
	return nil
}

// LocalAddr implements net.PacketConn.
func (e *endpoint) LocalAddr() net.Addr { return e.laddr }

// SetDeadline implements net.PacketConn.
func (e *endpoint) SetDeadline(t time.Time) error { return e.setDeadline(t, true, true) }

// SetReadDeadline implements net.PacketConn; a waiting ReadFrom honours a
// new deadline at once.
func (e *endpoint) SetReadDeadline(t time.Time) error { return e.setDeadline(t, true, false) }

// SetWriteDeadline implements net.PacketConn.
func (e *endpoint) SetWriteDeadline(t time.Time) error { return e.setDeadline(t, false, true) }

func (e *endpoint) setDeadline(t time.Time, read, write bool) error {
	n := e.n
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := e.usable("set"); err != nil {
		return err
	}
	if read {
		e.rdl = t
		close(e.dlCh)
		e.dlCh = make(chan struct{})
	}
	if write {
		e.wdl = t
	}
	return nil
}

// frameAt returns the type, payload and size of the whole frame at the
// front of b; ok is false when b holds none (too short, or the frame runs
// past b). Nothing is validated: the fake must see damaged traffic too.
func frameAt(b []byte) (t FrameType, payload []byte, size int, ok bool) {
	if len(b) < wire.HeaderLen {
		return 0, nil, 0, false
	}
	end := wire.HeaderLen + (int(b[2])<<16 | int(b[3])<<8 | int(b[4]))
	if end+wire.TrailerLen > len(b) {
		return 0, nil, 0, false
	}
	return FrameType(b[0]), b[wire.HeaderLen:end], end + wire.TrailerLen, true
}

// relInner returns the type a REL payload wraps (wire.ParseRel); false for
// a malformed REL.
func relInner(payload []byte) (FrameType, bool) {
	h, _, err := wire.ParseRel(payload)
	if err != nil {
		return 0, false
	}
	return FrameType(h.Type), true
}

// carries reports whether the rendr bytes b of a datagram — after a
// PREFACE or PREFACE_ACK when they start with one — hold a frame of type t,
// or a REL wrapping one; FrameRel matches every REL. The walk stops at the
// first frame that runs past b.
func carries(b []byte, t FrameType) bool {
	if wire.IsPreface(b) {
		b = b[wire.PrefaceLen:]
	}
	for {
		ft, payload, size, ok := frameAt(b)
		if !ok {
			return false
		}
		if ft == t {
			return true
		}
		if ft == FrameRel {
			if it, ok := relInner(payload); ok && it == t {
				return true
			}
		}
		b = b[size:]
	}
}

// classifyDatagram classifies a carrier by the rendr bytes of its dialer's
// first datagram: a PREFACE followed by OPEN or JOIN (inside a REL, as
// rendr sends them on datagram carriers) is a session carrier, a PREFACE
// followed by PING a probe carrier, anything else other.
func classifyDatagram(b []byte) int32 {
	if !wire.IsPreface(b) {
		return kindOther
	}
	t, payload, _, ok := frameAt(b[wire.PrefaceLen:])
	if !ok {
		return kindOther
	}
	if t == FrameRel {
		if t, ok = relInner(payload); !ok {
			return kindOther
		}
	}
	return classify(t)
}
