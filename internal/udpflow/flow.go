package udpflow

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

var (
	// errSourceClosed: the flow's shared socket is closed or its source
	// stopped (Abort, a permanent read error): the carrier ends.
	errSourceClosed = fmt.Errorf("rendr/udpflow: the shared socket is closed: %w", net.ErrClosed)
	// errNotCandidate: WriteDatagramTo or SetPeer named another address
	// than the flow's latest rebind candidate (M2-D27). It wraps
	// carrier.ErrNoRebind: a datagram from a newer source replaced the
	// candidate while a challenge to the older one was in flight, so the
	// challenge is lost — never the carrier.
	errNotCandidate = fmt.Errorf("%w: not the flow's latest rebind candidate", carrier.ErrNoRebind)
	// errWriteCount: a foreign conn's WriteTo reported another count than
	// the datagram's length (L42, PA-19).
	errWriteCount = errors.New("rendr/udpflow: datagram write returned an invalid count")
	// errTooLarge: a foreign conn refused a datagram as too large without
	// telling the size it can send, or rendr's own socket refused it (Max
	// 0: the MTU probe decides, M2-D25). One shared value, never modified.
	errTooLarge error = &wire.DatagramTooLargeError{}
	// errNoResults: ReadDatagrams without room for a result.
	errNoResults = errors.New("rendr/udpflow: ReadDatagrams without a result slot")
)

// testWake, if set by a test, sees every wake signal of a flow (wakeLocked,
// whether or not its reader waits): the one-wake-per-touched-flow rows
// count them (M5-D14). Unset in production.
var testWake atomic.Pointer[func(f *Flow)]

// isTooLarge reports whether err matches wire.ErrDatagramTooLarge.
func isTooLarge(err error) bool { return errors.Is(err, wire.ErrDatagramTooLarge) }

// Flow is one raw-UDP carrier's view of the shared socket. *Flow implements
// carrier.PacketIO and can rebind: a datagram of the flow from another
// source is returned as carrier.ReadCandidate (M2-D27), and SetPeer moves
// the reply address once the carrier verified the candidate.
type Flow struct {
	id  uint64
	src *Source
	hdr [wire.FlowHeaderLen]byte // the flow header of every datagram written
	ip  netip.Addr               // the H1's source IP address (its admitting quota)
	cls uint8                    // the H1's admission class

	admitting bool // Source.mu: counted in its IP's admitting flows

	mu         sync.Mutex
	ring       []entry // the inbox: n entries from head, grown up to Limits.Inbox
	head, n    int
	cur        entry   // the datagram the last ReadDatagram returned, until the next call or Release
	held       []entry // the datagrams the last ReadDatagrams returned, until the next call or Release
	heldBytes  int64   // held's capacity, charged to Env.Budget (R3-28); 0 once Close returned it
	reserveOut int     // control-reserve buffers in the inbox, cur or held
	limit      int     // the receive limit in rendr bytes (SetLimit, R1-6)
	peer       netip.AddrPort
	peerAddr   *net.UDPAddr // the peer as a foreign conn's address value (nil on rendr's own socket)
	cand       netip.AddrPort
	candAddr   *net.UDPAddr
	hasCand    bool // cand is the latest rebind candidate returned
	closed     bool
	waiting    bool          // the reader waits on wakeCh
	wakeCh     chan struct{} // cap 1
	rdl        time.Time     // read deadline
	rdlExpired bool
	rdlTimer   *time.Timer
	wdl        time.Time // write deadline: recorded only (the writer's watchdog bounds a stuck write)
}

// entry is one inbox datagram: its rendr bytes in buf.
type entry struct {
	buf     *carrier.Buf
	data    []byte
	src     netip.AddrPort
	addr    *net.UDPAddr
	reserve bool // buf is a control-reserve buffer (Stages)
}

// pushResult is the outcome of an inbox push.
type pushResult uint8

const (
	pushOK     pushResult = iota
	pushFull              // the inbox (or the control reserve) is full: InboxDrops
	pushClosed            // the flow was closed meanwhile: Dropped
)

// newFlow returns a flow created by the H1 from src.
func newFlow(s *Source, id uint64, ip netip.Addr, cls uint8, src netip.AddrPort, addr *net.UDPAddr) *Flow {
	f := &Flow{id: id, src: s, ip: ip, cls: cls, ring: make([]entry, min(minRing, s.lim.Inbox)),
		limit: s.maxDgram - wire.FlowHeaderLen, peer: src, peerAddr: addr, wakeCh: make(chan struct{}, 1)}
	wire.PutFlowHeader(f.hdr[:], id)
	return f
}

// ID returns the flow ID.
func (f *Flow) ID() uint64 { return f.id }

// Admitted tells the source that a positive verdict was written for the
// flow (OPEN_ACK or JOIN_ACK OK, or a probe carrier started): it leaves the
// per-source admitting count.
func (f *Flow) Admitted() { f.unadmit() }

// SourceProven tells the source that the flow's peer answered the address
// check of its OPEN's H2 (carrier.SourceChecker): it receives the passive's
// datagrams, so the flow leaves the per-source admitting count while its
// session waits for the application (bounded by the Listener's
// AcceptBacklog instead).
func (f *Flow) SourceProven() { f.unadmit() }

var _ carrier.SourceChecker = (*Flow)(nil)

// Removed reports whether the flow was closed (Close: it left its
// source's table and holds no inbox), so that a record of flows can drop
// it (package rendr's pending flow record, W4-L2-1).
func (f *Flow) Removed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// unadmit takes the flow out of its source IP's admitting count (once).
func (f *Flow) unadmit() {
	s := f.src
	s.mu.Lock()
	if f.admitting {
		f.admitting = false
		s.unadmitLocked(f)
	}
	s.mu.Unlock()
}

// push queues data (aliasing buf) from src; the inbox takes buf only on
// pushOK. It never blocks (the demux never waits for a reader) and never
// wakes the reader: the demux wakes every flow it pushed to once after the
// datagrams of one read (M5-D14).
func (f *Flow) push(buf *carrier.Buf, data []byte, src netip.AddrPort, addr *net.UDPAddr, reserve bool) pushResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return pushClosed
	}
	if !f.roomLocked() {
		return pushFull
	}
	f.enqueueLocked(entry{buf: buf, data: data, src: src, addr: addr, reserve: reserve})
	return pushOK
}

// pushReserve queues a copy of rb in a control-reserve buffer (charged to
// Stages) while fewer than reserveBufs are in use (M2-D59; L16).
func (f *Flow) pushReserve(rb []byte, src netip.AddrPort, addr *net.UDPAddr) pushResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return pushClosed
	}
	if f.reserveOut >= reserveBufs || !f.roomLocked() {
		return pushFull
	}
	s := f.src
	buf := s.dbufs.Get(len(rb), s.stages)
	f.reserveOut++
	f.enqueueLocked(entry{buf: buf, data: buf.B[:copy(buf.B, rb)], src: src, addr: addr, reserve: true})
	return pushOK
}

// roomLocked reports whether the inbox can take one more datagram, growing
// the ring (doubling, up to Limits.Inbox) when it is full but below the
// bound.
func (f *Flow) roomLocked() bool {
	if f.n < len(f.ring) {
		return true
	}
	limit := f.src.lim.Inbox
	if len(f.ring) >= limit {
		return false
	}
	ring := make([]entry, min(2*len(f.ring), limit))
	for i := range f.n {
		ring[i] = f.ring[(f.head+i)%len(f.ring)]
	}
	f.ring, f.head = ring, 0
	return true
}

// enqueueLocked appends e (room checked); the caller wakes the reader.
func (f *Flow) enqueueLocked(e entry) {
	f.ring[(f.head+f.n)%len(f.ring)] = e
	f.n++
}

// wake wakes a waiting reader (datagrams were queued, or the source died).
func (f *Flow) wake() {
	f.mu.Lock()
	f.wakeLocked()
	f.mu.Unlock()
}

// wakeLocked signals the reader if it waits (cap-1 channel, coalescing).
func (f *Flow) wakeLocked() {
	if fn := testWake.Load(); fn != nil {
		(*fn)(f)
	}
	if !f.waiting {
		return
	}
	f.waiting = false
	select {
	case f.wakeCh <- struct{}{}:
	default:
	}
}

// releaseHeldLocked returns the buffers of the datagrams the reader holds:
// the last ReadDatagram's and the last ReadDatagrams'. A closed flow also
// drops the held slice itself (its charge went back at Close).
func (f *Flow) releaseHeldLocked() {
	f.releaseLocked(&f.cur)
	for i := range f.held {
		f.releaseLocked(&f.held[i])
	}
	f.held = f.held[:0]
	if f.closed {
		f.held = nil
	}
}

// releaseLocked returns e's buffer (and its reserve slot).
func (f *Flow) releaseLocked(e *entry) {
	if e.buf == nil {
		return
	}
	if e.reserve {
		f.reserveOut--
	}
	e.buf.Release()
	*e = entry{}
}

// ReadSize implements carrier.PacketIO: 0 (inbox buffers are handed out).
func (f *Flow) ReadSize() int { return 0 }

// SetLimit implements carrier.PacketIO: inbox datagrams with more rendr
// bytes than n are returned as carrier.ReadTruncated (R1-6).
func (f *Flow) SetLimit(n int) {
	f.mu.Lock()
	f.limit = min(n, f.Limit())
	f.mu.Unlock()
}

// ReadDatagram implements carrier.PacketIO: the next inbox datagram. It
// returns the rendr bytes (the flow header removed) aliasing an inbox
// buffer, valid until the next call or Release, ignoring buf. A datagram
// from another source than the current peer is ReadCandidate and becomes
// the flow's latest rebind candidate; one longer than the receive limit
// is ReadTruncated (its buffer already returned). It blocks until a
// datagram, the read deadline (os.ErrDeadlineExceeded), Close
// (net.ErrClosed) or the source's end (an error matching net.ErrClosed).
func (f *Flow) ReadDatagram(buf []byte) ([]byte, carrier.PeerKey, carrier.ReadEvent, error) {
	f.mu.Lock()
	if err := f.waitLocked(); err != nil {
		f.mu.Unlock()
		return nil, carrier.PeerKey{}, carrier.ReadOK, err
	}
	e, key, ev := f.popLocked()
	if ev != carrier.ReadTruncated {
		f.cur = e
	}
	f.mu.Unlock()
	return e.data, key, ev, nil
}

// waitLocked returns the buffers the reader holds and waits until the inbox
// holds a datagram (nil) or the read fails: Close (net.ErrClosed), the
// source's end, or the read deadline (os.ErrDeadlineExceeded). f.mu is
// held on entry and on return.
func (f *Flow) waitLocked() error {
	f.releaseHeldLocked()
	for {
		switch {
		case f.closed:
			return net.ErrClosed
		case f.src.killed.Load():
			return errSourceClosed
		case f.rdlExpired:
			return os.ErrDeadlineExceeded
		case f.n > 0:
			return nil
		}
		f.waiting = true
		f.mu.Unlock()
		<-f.wakeCh
		f.mu.Lock()
	}
}

// popLocked takes the inbox head (f.n > 0): a datagram longer than the
// receive limit is ReadTruncated (its buffer returned, e zero); one from
// another source than the peer is ReadCandidate and becomes the latest
// rebind candidate. The caller holds e's buffer.
func (f *Flow) popLocked() (e entry, key carrier.PeerKey, ev carrier.ReadEvent) {
	e = f.ring[f.head]
	f.ring[f.head] = entry{}
	f.head = (f.head + 1) % len(f.ring)
	f.n--
	key = carrier.PeerKey{AP: e.src}
	if len(e.data) > f.limit {
		f.releaseLocked(&e)
		return e, key, carrier.ReadTruncated
	}
	ev = carrier.ReadOK
	if e.src != f.peer {
		f.cand, f.candAddr, f.hasCand = e.src, e.addr, true
		ev = carrier.ReadCandidate
	}
	return e, key, ev
}

// Release implements carrier.PacketIO: returns the inbox buffers of the
// last ReadDatagram or ReadDatagrams.
func (f *Flow) Release() {
	f.mu.Lock()
	f.releaseHeldLocked()
	f.mu.Unlock()
}

// Headroom implements carrier.PacketIO: the flow header.
func (f *Flow) Headroom() int { return wire.FlowHeaderLen }

// WriteDatagram implements carrier.PacketIO: to the flow's current peer.
// It writes the flow header into b[:Headroom()] and sends b through the
// shared socket (rendr's own: WriteAddrPort; a foreign conn: WriteTo with
// the peer's address value). Errors follow the datagram I/O contract (M2
// design §A6.4): a too-large refusal matches wire.ErrDatagramTooLarge,
// noise (an abort of the shared socket included) is carrier.ErrNoise, an
// invalid count and every other error end the carrier; after Close or the
// source's end the error matches net.ErrClosed.
func (f *Flow) WriteDatagram(b []byte) error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return net.ErrClosed
	}
	dst, addr := f.peer, f.peerAddr
	f.mu.Unlock()
	*(*[wire.FlowHeaderLen]byte)(b) = f.hdr
	return f.src.write(b, dst, addr)
}

// WriteDatagramTo implements carrier.PacketIO: a rebind challenge to the
// latest candidate only. b has WriteDatagram's layout (the flow header is
// written into b[:Headroom()]).
func (f *Flow) WriteDatagramTo(b []byte, dst carrier.PeerKey) error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return net.ErrClosed
	}
	if !f.hasCand || dst != (carrier.PeerKey{AP: f.cand}) {
		f.mu.Unlock()
		return errNotCandidate
	}
	to, addr := f.cand, f.candAddr
	f.mu.Unlock()
	*(*[wire.FlowHeaderLen]byte)(b) = f.hdr
	return f.src.write(b, to, addr)
}

// SetPeer implements carrier.PacketIO: the latest candidate only. The
// carrier's reader calls it when a rebind commits (Flow.mu guards the
// peer).
func (f *Flow) SetPeer(dst carrier.PeerKey) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return net.ErrClosed
	}
	if !f.hasCand || dst != (carrier.PeerKey{AP: f.cand}) {
		return errNotCandidate
	}
	f.peer, f.peerAddr = f.cand, f.candAddr
	f.cand, f.candAddr, f.hasCand = netip.AddrPort{}, nil, false
	return nil
}

// SetDeadline implements carrier.PacketIO.
func (f *Flow) SetDeadline(t time.Time) error {
	if err := f.SetReadDeadline(t); err != nil {
		return err
	}
	return f.SetWriteDeadline(t)
}

// SetReadDeadline implements carrier.PacketIO (wakes a waiting read).
func (f *Flow) SetReadDeadline(t time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return net.ErrClosed
	}
	f.rdl, f.rdlExpired = t, false
	if t.IsZero() {
		if f.rdlTimer != nil {
			f.rdlTimer.Stop()
		}
		return nil
	}
	d := time.Until(t)
	if d <= 0 {
		f.rdlExpired = true
		f.wakeLocked()
		return nil
	}
	if f.rdlTimer == nil {
		f.rdlTimer = time.AfterFunc(d, f.deadlineFired)
	} else {
		f.rdlTimer.Reset(d)
	}
	return nil
}

// deadlineFired expires the read deadline if it is still the one set
// (a timer of an older deadline may fire late).
func (f *Flow) deadlineFired() {
	f.mu.Lock()
	if !f.rdl.IsZero() && !time.Now().Before(f.rdl) {
		f.rdlExpired = true
		f.wakeLocked()
	}
	f.mu.Unlock()
}

// SetWriteDeadline implements carrier.PacketIO (recorded; a shared socket
// has no per-flow write deadline, the writer's watchdog bounds a stuck
// write).
func (f *Flow) SetWriteDeadline(t time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return net.ErrClosed
	}
	f.wdl = t
	return nil
}

// Close implements carrier.PacketIO: removes the flow (pointer compare),
// releases its inbox (the queued buffers and the ring) and the charge of
// its held-entry slice (R3-28) and wakes its reader; the socket stays
// open. The buffers of the datagrams the reader holds are returned by its
// next ReadDatagram, ReadDatagrams or Release, never under it: Close may
// run on another goroutine while the reader still uses them (PacketIO's
// reader half belongs to the reader), so the reader must call Release (or
// a read, which then fails) when it exits, or the buffers stay charged to
// Env.Budget. Close is idempotent.
func (f *Flow) Close() error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil
	}
	f.closed = true
	for f.n > 0 {
		f.releaseLocked(&f.ring[f.head])
		f.head = (f.head + 1) % len(f.ring)
		f.n--
	}
	f.ring, f.head = nil, 0 // a stale *Flow pins no inbox (every ring access checks closed first)
	if f.heldBytes > 0 {
		// The slice itself may still carry the reader's datagrams: the
		// reader's next read or Release returns them and drops it.
		f.src.env.Budget.Release(f.heldBytes)
		f.heldBytes = 0
	}
	if f.rdlTimer != nil {
		f.rdlTimer.Stop()
	}
	f.wakeLocked()
	f.mu.Unlock()
	f.src.remove(f)
	return nil
}

// Limit implements carrier.PacketIO: the socket's MaxDatagram − 9
// (wire.MaxDatagram − 9 for a foreign conn).
func (f *Flow) Limit() int { return f.src.maxDgram - wire.FlowHeaderLen }

var _ carrier.PacketIO = (*Flow)(nil)
