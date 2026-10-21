package carrier

import (
	"errors"
	"os"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/udpsocket"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// The reader of a datagram carrier (M2-D13, M2-D14, M2-D30; M2 design
// §A5.7 and Revision 1, R1-1, R1-4, R1-27; the batched reads of M5 design
// §A4.4).

// Reader back-off (M2-D15): a transient read error waits noiseMin, doubling
// to noiseMax, until a datagram is handed over. The spin guard (M2-D86,
// R1-27 as amended by WP12): every spinIdle consecutive reads that handed
// nothing over (empty, truncated, foreign, bad envelope) pause spinPause —
// fixed, not doubling, as udpflow's emptyRun/emptyPause (L58). A conn that
// answers (0, nil) forever is read at most spinIdle times per spinPause
// instead of spinning a core, while a burst of real empty or foreign
// datagrams is still read at tens of thousands per second: a doubling
// back-off read the rest of a 400-datagram burst at 100 ms each and
// starved the carrier into a ping_timeout (WP12
// TestUDPZeroLengthIsNotDeath_L42).
const (
	noiseMin  = 5 * time.Millisecond
	noiseMax  = 100 * time.Millisecond
	spinIdle  = 64
	spinPause = time.Millisecond
)

// dbufs returns the pool of datagram reader buffers and writer scratches:
// Env.DBufs, or the stream pool in component tests that set none.
func (c *Conn) dbufs() *BufPool {
	if c.env.DBufs != nil {
		return c.env.DBufs
	}
	return c.env.Bufs
}

// dgReader is the datagram reader goroutine's own state.
type dgReader struct {
	buf     *Buf // the read buffer, io.ReadSize() bytes (nil: the transport hands out its own); slot 0 of a batched read
	backoff time.Duration
	idle    int         // consecutive reads that handed nothing over
	timer   *time.Timer // the back-off timer, created at the first back-off

	// A transport with a BatchIO but no depth (a flow, M5 design §A4.5):
	// the results of one ReadDatagrams call. While they are handled
	// (batch), a pause is deferred (pend, the longest asked for) until the
	// call's buffers went back (M2: a buffer goes back before any pause).
	rs    []ReadResult
	batch bool
	pend  time.Duration

	// The adaptive depth of a dialer socket (depthIO; M5 design §A4.4,
	// Revision 1 R1-4, R1-5). Depth 1 reads into buf through the socket's
	// fixed one-message header; depth k ≥ 2 holds hdr, a pooled header
	// whose slots 1 … k−1 are charged to Env.Budget (lent to the
	// transport: the four-state word of R1-5 says who owns it). hdr, stale
	// and gen belong to the reader goroutine; the atomics are shared with
	// the idle-release timer.
	dio       depthIO
	hdr       *ioHdr // the lent extras; nil at depth 1
	stale     *ioHdr // extras an idle release took: pooled once that release completed
	gen       uint64 // lend generations (each lent header gets the next)
	size      int    // the slots' length: ReadSize()
	pool      *BufPool
	budget    *Budget        // the slots' account (Env.Budget: refusable, R1-4)
	stages    *Budget        // the headers' account (Env.Stages: forced)
	refused   *atomic.Uint64 // DgramStats.ChargeRefused (nil in component tests)
	idleT     *time.Timer    // the idle release (batchIdleRelease), armed while extras are held
	armed     atomic.Bool    // idleT is armed
	lastSeq   atomic.Uint64  // the reader's parks at idleT's previous firing
	relGen    atomic.Uint64  // the generation the latest idle release returned (after it completed)
	relHdrGen atomic.Uint64  // the generation of the header releaseHdr returned (the timer's goroutine; published as relGen)
	woke      atomic.Bool    // the idle release set the read deadline to wake the reader
	// relMu (one slot, made by startDepth) orders a firing of idleT
	// against the reader's exit (endDepth), as the passive Source's reader
	// does (internal/udpflow): a firing holds it for its whole run, and
	// endDepth takes it, sets ended and stops idleT before the extras go
	// back, so the reader's partDone — and the carrier's Done — follows a
	// release in flight (every charge is back) and no firing re-arms the
	// timer after the exit. A channel rather than a sync.Mutex, so that a
	// reader waiting for a release in flight is durably blocked in a
	// synctest bubble (TestDgramReaderExitWaitsForIdleRelease). ended
	// (under relMu): the reader exited; a firing releases and re-arms
	// nothing.
	relMu chan struct{}
	ended bool
}

// depthIO is a dialer socket's side of the adaptive receive depth (M5
// design §A4.4; R1-4, R1-5): *OwnedUDP over its udpsocket.Reader, and the
// in-memory transports of the tests. The reader lends it a pooled header
// (lend) and reads at that header's depth; while the read is parked an
// idle release (tryRelease, on the timer's goroutine) may take the header
// back, after which the read returns one datagram in slot 0.
type depthIO interface {
	PacketIO
	// depthMax is the most datagrams one read may move now: MaxBatch while
	// the socket batches, else 1 (the depth then falls back to 1).
	depthMax() int
	// readDepth waits like ReadDatagram and reads n ≥ 1 datagrams in
	// arrival order: into slot0 alone, or — while the reader holds the
	// lent h — up to h.k into slot0 and h.slots[1:h.k]. A transient error
	// (noise, a Windows truncation) is n = 0 with its event; any other
	// error is returned. As BatchIO.ReadDatagrams, a call ends at its
	// first ReadCandidate (OwnedUDP cannot rebind and never returns one).
	readDepth(slot0 *Buf, h *ioHdr) (n int, ev ReadEvent, err error)
	// result is the i-th datagram of the latest readDepth, classified as
	// ReadDatagram classifies one (Data aliases its slot).
	result(i int) (data []byte, src PeerKey, ev ReadEvent)
	// lend makes h the reader's extras (replacing held ones); false, with
	// nothing changed, while an idle release still returns earlier ones.
	lend(h *ioHdr) bool
	// held reports whether the reader holds the extras; false after a read
	// that held them means an idle release took them.
	held() bool
	// reclaim takes held extras back (depth 1, exit, fallback).
	reclaim() bool
	// parks, holding and tryRelease are the idle release's side (R1-5):
	// the reader's parks while holding extras; whether it holds them
	// (held or parked); parked → releasing by CAS when it has not parked
	// since seq, then the release function, then idle.
	parks() uint64
	holding() bool
	tryRelease(seq uint64) bool
	// onRelease sets the release function (before the first lend).
	onRelease(f func(*ioHdr))
}

// batchIdleRelease is how long a dialer reader may stay parked with its
// extras before the idle release returns them (R1-5, M5-D61): the shared
// udpsocket.IdleRelease, the passive Source's period too. Tests lower it.
var batchIdleRelease = udpsocket.IdleRelease

// flowReadDepth bounds the results one ReadDatagrams call of a flow
// returns (a flow drains its inbox: no system call, one lock per call;
// the Source wakes a flow once per receive batch, M5-D14).
const flowReadDepth = 8

// dgReadLoop is the reader goroutine of a datagram carrier: it walks the
// response datagram's tail (dialer, R1-1), then reads — one datagram per
// ReadDatagram call, or through the transport's BatchIO several per call
// (M5 design §A4.4) — and walks each datagram's frames (header and
// bounds, CRC, the fseq window, the M2-D30 rule, dispatch) in arrival
// order. Loss, corruption and noise never end it (PA-1); a read error, a
// violation or the end of a retirement does.
func (c *Conn) dgReadLoop() {
	dg := c.dg
	rd := &dgReader{}
	normal := false
	defer func() {
		if !normal { // runtime.Goexit inside an embedder ReadFrom (L51)
			c.killCarrier(CauseTransportError, "conn ReadFrom called runtime.Goexit")
		}
		// The embedder call returned or unwound: only this goroutine pools
		// its buffer (§4.1), and it returns a flow buffer it may still hold
		// (PacketIO.Release; Close never does, integration 2).
		dg.io.Release()
		rd.endDepth()
		clear(rd.rs)
		if rd.buf != nil {
			rd.buf.Release()
			rd.buf = nil
		}
		if rd.timer != nil {
			rd.timer.Stop()
		}
		c.partDone(partReader)
	}()
	if o, ok := dg.io.(*OwnedUDP); ok {
		o.bind(c.env) // the batched I/O and its counters (M5 design §A4.4)
	}
	if n := dg.io.ReadSize(); n > 0 {
		// After SetBudget: recvLimit + Headroom + 1 (R1-6), a 2 KiB class for
		// QUIC and default raw UDP, charged to the stage account.
		rd.buf = c.dbufs().Get(n, c.env.stageBudget())
	}
	if tail := dg.tail; tail != nil {
		// The rest of the response datagram: frames the passive packed
		// behind its first response (R1-1), walked as that datagram's rest.
		dg.tail = nil
		if !c.dgFrames(tail, PeerKey{}, ReadOK, time.Now()) {
			normal = true
			return
		}
	}
	bio := dgBatchOf(dg.io)
	if d, ok := bio.(depthIO); ok && rd.buf != nil {
		rd.startDepth(c, d)
		for c.dgReadDepth(rd) {
		}
	} else if bio != nil {
		k := min(max(bio.MaxBatch(), 1), flowReadDepth)
		if rd.buf != nil {
			k = 1 // no slots beyond the reader's own buffer
		}
		rd.rs = make([]ReadResult, k)
		rd.rs[0].buf = rd.buf
		for c.dgReadBatch(rd, bio) {
		}
	} else {
		for c.dgReadOne(rd) {
		}
	}
	normal = true
}

// dgReadOne reads and handles one datagram; it reports whether the reader
// continues.
func (c *Conn) dgReadOne(rd *dgReader) bool {
	dg := c.dg
	var b []byte
	if rd.buf != nil {
		b = rd.buf.B
	}
	data, src, ev, err := dg.io.ReadDatagram(b)
	if err != nil {
		c.readFailed(err) // death (transport_error), or the end of a retirement (M1 V6)
		return false
	}
	handed := ev == ReadOK || ev == ReadCandidate
	if !handed && ev != ReadNoise {
		dg.io.Release() // a dropped datagram's buffer goes back before any pause
	}
	ok := c.dgHandle(rd, data, src, ev)
	if handed {
		dg.io.Release()
	}
	return ok
}

// dgHandle handles one datagram or read event of the reader (§A5.7): noise
// backs off; an empty, truncated, foreign or badly enveloped datagram is
// dropped and counted, under the spin guard; a datagram handed over is
// walked (dgFrames). It reports whether the reader continues.
func (c *Conn) dgHandle(rd *dgReader, data []byte, src PeerKey, ev ReadEvent) bool {
	switch ev {
	case ReadNoise:
		c.dgReadError()
		return c.dgBackoff(rd)
	case ReadEmpty, ReadTruncated, ReadForeign, ReadBadEnvelope:
		if ev == ReadTruncated {
			c.dgTruncated()
		} else {
			c.dgDropped(1)
		}
		rd.idle++
		if rd.idle >= spinIdle {
			rd.idle = 0
			return c.dgPause(rd, spinPause) // the spin guard (R1-27)
		}
		return true
	}
	rd.backoff, rd.idle = 0, 0
	c.dg.ctr.datagramsRx.Add(1)
	return c.dgFrames(data, src, ev, time.Now())
}

// dgReadBatch reads one ReadDatagrams call of a transport with a BatchIO
// and no depth (a flow: its inbox, M5-D14) and handles its results in
// arrival order; then the transport gets the call's buffers back
// (Release). It reports whether the reader continues.
//
// A pause one of them asks for (noise back-off, the spin guard) is taken
// after Release, the longest of them once: the transport's buffers never
// wait out a pause, as in M2's per-datagram path; the results after the
// one that asked are handled before it instead of after it (they were read
// already). The transport ends a call at its first ReadCandidate (BatchIO),
// so a rebind that result commits applies to every later datagram.
func (c *Conn) dgReadBatch(rd *dgReader, bio BatchIO) bool {
	n, err := bio.ReadDatagrams(rd.rs)
	if err != nil {
		c.readFailed(err)
		return false
	}
	ok := true
	rd.batch = true
	for i := 0; i < n && ok; i++ {
		r := &rd.rs[i]
		ok = c.dgHandle(rd, r.Data, r.Src, r.Ev)
	}
	rd.batch = false
	for i := range n {
		rd.rs[i].Data, rd.rs[i].Src = nil, PeerKey{}
	}
	c.dg.io.Release()
	if d := rd.pend; d > 0 {
		rd.pend = 0
		ok = ok && c.dgPause(rd, d)
	}
	return ok
}

// startDepth prepares the adaptive depth over d: the accounts, the release
// function and the idle-release timer (one per dialer reader, created
// whatever MaxBatch is, so a reader that never batches holds the same).
func (rd *dgReader) startDepth(c *Conn, d depthIO) {
	rd.dio, rd.size = d, d.ReadSize()
	rd.pool, rd.budget, rd.stages = c.dbufs(), c.env.Budget, c.env.stageBudget()
	if s := c.env.Dgram; s != nil {
		rd.refused = &s.ChargeRefused
	}
	d.onRelease(rd.releaseHdr)
	rd.relMu = make(chan struct{}, 1)
	rd.idleT = time.AfterFunc(time.Hour, rd.idleFire)
	rd.idleT.Stop()
}

// dgReadDepth reads one readDepth call of a dialer socket, handles its
// datagrams in arrival order and then adapts the depth (§A4.4): k doubles
// (≤ depthMax) when a call returns k datagrams; it halves when a call that
// waited for the socket (parked) returns fewer than k/4 — a call that
// found datagrams queued and drained them is the tail of a burst, not
// sparse traffic, so the depth stays for the next burst (R1-5, R1-7); it
// is 1 whenever the socket does not batch, and after an idle release. It
// reports whether the reader continues.
func (c *Conn) dgReadDepth(rd *dgReader) bool {
	d := rd.dio
	if rd.hdr != nil && d.depthMax() < 2 {
		// The socket stopped batching since the last call (M5-D15) — or that
		// call moved no datagram, so no depth rule ran after it: the extras go
		// back before a read that cannot use them, which may block with them
		// held until a datagram arrives (R1-5 rule 5).
		rd.shrink(1)
	}
	p0 := d.parks()
	n, ev, err := d.readDepth(rd.buf, rd.hdr)
	if rd.hdr != nil && !d.held() {
		// An idle release took the extras while the read was parked: their
		// slots and charge are gone; the header itself returns to its pool
		// once that release completed (collect).
		rd.stale, rd.hdr = rd.hdr, nil
	}
	if err != nil {
		rd.collect()
		if errors.Is(err, os.ErrDeadlineExceeded) && rd.woke.Swap(false) {
			// The idle release's wake, not a caller's deadline: the read
			// goes on. Every closer's SetDeadline(now) follows the close of
			// dying (setDeath, then startCloser), so dying is checked after
			// the deadline was cleared: a closer's deadline this clear may
			// have erased belongs to a carrier whose reader exits here.
			_ = d.SetReadDeadline(time.Time{})
			select {
			case <-c.dying:
				return false
			default:
			}
			return true
		}
		c.readFailed(err)
		return false
	}
	if n == 0 {
		rd.collect()
		return c.dgHandle(rd, nil, PeerKey{}, ev)
	}
	for i := range n {
		data, src, ev := d.result(i)
		if !c.dgHandle(rd, data, src, ev) {
			return false
		}
	}
	// After the results: one read through a stale header's message array
	// (a release that won while the read was parked) is handled by now.
	rd.collect()
	c.dgAdapt(rd, n, d.parks() != p0)
	return true
}

// dgAdapt applies the depth rule of dgReadDepth after a call that moved n
// datagrams (parked: it waited for the socket).
func (c *Conn) dgAdapt(rd *dgReader, n int, parked bool) {
	k, hi := 1, rd.dio.depthMax()
	if rd.hdr != nil {
		k = rd.hdr.k
	}
	switch {
	case k > hi:
		rd.shrink(max(hi, 1)) // the socket stopped batching (M5-D15)
	case n >= k && k < hi:
		rd.grow(min(2*k, hi))
	case parked && 4*n < k:
		rd.shrink(k / 2)
	}
}

// grow raises the depth to nk: the slots k … nk−1 taken with TryGet on
// Env.Budget — a refusal keeps the depth k, returns the slots the growth
// got and counts the nk − k slots it would have added in ChargeRefused
// (R1-4; refused receive slots on both readers, M5 design R3-23) — and,
// when the held header is too small (or none is held), a header of nk's
// class lent to the transport: a reserved one (getReadHdr), so a regrowth
// reuses the headers earlier growths returned, whatever the collector or
// the scheduler did to the pools (TestDgramReadAdaptiveDepthReuse_L16_L54).
// A lend refused while an idle release still returns earlier extras keeps
// depth 1. Every header the reader returns goes back through putRead.
func (rd *dgReader) grow(nk int) {
	h, k := rd.hdr, 1
	if h != nil {
		k = h.k
	}
	nh := h
	if h == nil || h.cap() < nk {
		nh = getReadHdr(nk, rd.stages)
	}
	for i := k; i < nk; i++ {
		s := rd.pool.TryGet(rd.size, rd.budget)
		if s == nil {
			if rd.refused != nil {
				rd.refused.Add(uint64(nk - k))
			}
			releaseSlots(nh, k, i)
			if nh != h {
				nh.putRead()
			}
			return
		}
		nh.slots[i] = s
	}
	if nh == h {
		h.k = nk
		return
	}
	if h != nil {
		copy(nh.slots[1:k], h.slots[1:k])
	}
	rd.gen++
	nh.k, nh.gen = nk, rd.gen
	if !rd.dio.lend(nh) {
		releaseSlots(nh, k, nk)
		clear(nh.slots[1:k])
		nh.putRead()
		return
	}
	if h != nil {
		clear(h.slots[1:k]) // moved to nh
		h.putRead()
	}
	if rd.stale != nil {
		// The lend found the Reader idle: the release that took the stale
		// header completed.
		rd.stale.putRead()
		rd.stale = nil
	}
	rd.hdr = nh
	rd.arm()
}

// shrink lowers the depth to nk (≥ 1): the slots nk … k−1 are released; at
// depth 1 the header goes back as well.
func (rd *dgReader) shrink(nk int) {
	h := rd.hdr
	if h == nil {
		return
	}
	if nk > 1 {
		releaseSlots(h, nk, h.k)
		h.k = nk
		return
	}
	rd.dio.reclaim()
	releaseSlots(h, 1, h.k)
	h.putRead()
	rd.hdr = nil
}

// releaseSlots releases h's slots [from, to).
func releaseSlots(h *ioHdr, from, to int) {
	for i := from; i < to; i++ {
		h.slots[i].Release()
		h.slots[i] = nil
	}
}

// collect pools the stale header once the idle release that took it
// completed.
func (rd *dgReader) collect() {
	if s := rd.stale; s != nil && rd.relGen.Load() == s.gen {
		s.putRead()
		rd.stale = nil
	}
}

// endDepth ends the idle release and returns the reader's extras when it
// exits: a firing in progress completes first — a release in flight
// returns its slots and its header's charge before the reader's partDone
// — and none releases or re-arms after it (relMu, ended: the Stop under
// relMu cancels a re-arm by the firing that held it); held extras are
// taken back from the transport, and a stale header, whose release has
// completed by then, goes back to its pool.
func (rd *dgReader) endDepth() {
	if rd.dio == nil {
		return
	}
	rd.relMu <- struct{}{}
	rd.ended = true
	rd.idleT.Stop()
	<-rd.relMu
	if rd.hdr != nil {
		rd.shrink(1)
	}
	rd.collect()
	rd.stale = nil
}

// arm arms the idle release once the reader holds extras.
func (rd *dgReader) arm() {
	if rd.armed.CompareAndSwap(false, true) {
		rd.lastSeq.Store(rd.dio.parks())
		rd.idleT.Reset(batchIdleRelease)
	}
}

// idleFire is the idle release (R1-5 rule 3; on the timer's goroutine). A
// reader that has stayed parked since the previous firing — a whole
// period — has its extras released (parked → releasing by CAS, then
// releaseHdr, then idle), and its read is woken by a read deadline of
// now, so the header returns to its pool at once (its message array stays
// referenced by the parked read until it returns). A busy reader costs one
// O(1) firing per period; the timer touches no traffic (a resource
// release, not a liveness trigger: invariant 7). relMu orders a firing
// before the reader's exit (endDepth).
func (rd *dgReader) idleFire() {
	rd.relMu <- struct{}{}
	defer func() { <-rd.relMu }()
	if rd.ended {
		return
	}
	d := rd.dio
	if d.holding() {
		seq := d.parks()
		if seq != rd.lastSeq.Load() {
			rd.lastSeq.Store(seq) // it parked again during the period
			rd.idleT.Reset(batchIdleRelease)
			return
		}
		rd.relHdrGen.Store(0)
		if !d.tryRelease(seq) {
			rd.idleT.Reset(batchIdleRelease) // held and reading: busy
			return
		}
		// The generation of the header actually released (releaseHdr), not
		// the latest lend: a lend that raced the release would leave the
		// released header unmatched by collect.
		rd.relGen.Store(rd.relHdrGen.Load())
		rd.woke.Store(true)
		_ = d.SetReadDeadline(time.Now())
	}
	rd.armed.Store(false)
	if d.holding() && rd.armed.CompareAndSwap(false, true) {
		rd.lastSeq.Store(d.parks())
		rd.idleT.Reset(batchIdleRelease)
	}
}

// releaseHdr is the release function of the idle release (on the timer's
// goroutine, while the transport is releasing): h's slots and charge go
// back; the reader pools the header itself (collect).
func (rd *dgReader) releaseHdr(h *ioHdr) {
	releaseSlots(h, 1, h.k)
	h.uncharge()
	rd.relHdrGen.Store(h.gen)
}

// dgBackoff sleeps the reader's back-off (5 ms doubling to 100 ms); it
// reports whether the reader continues. A dead carrier's reader exits
// here: a transport that keeps answering after Close (empties, noise)
// never makes it spin.
func (c *Conn) dgBackoff(rd *dgReader) bool {
	rd.backoff = min(max(2*rd.backoff, noiseMin), noiseMax)
	return c.dgPause(rd, rd.backoff)
}

// dgPause sleeps d on the reader's timer — or, while dgReadBatch handles a
// call's results, defers it until the call's buffers went back; it reports
// whether the reader continues (false: the carrier is dying).
func (c *Conn) dgPause(rd *dgReader, d time.Duration) bool {
	select {
	case <-c.dying:
		return false
	default:
	}
	if rd.batch {
		rd.pend = max(rd.pend, d) // after the call's buffers went back (dgReadBatch)
		return true
	}
	if rd.timer == nil {
		rd.timer = time.NewTimer(d)
	} else {
		rd.timer.Reset(d)
	}
	select {
	case <-rd.timer.C:
		return true
	case <-c.dying:
		rd.timer.Stop()
		return false
	}
}

// dgFrames handles the rendr bytes of one datagram received at now from
// src (§A5.7, §A3.8): a datagram starting with a PREFACE is a duplicate H1
// on the passive (the stored H2 is repeated; while the passive's first REL
// is unacknowledged — held, or released with H3 on its way — a copy from a
// new source also starts a challenge, R1-14 as amended by wave 4) and
// dropped otherwise;
// a frame that fails to decode drops the rest of the datagram (PA-1); a
// window duplicate or late frame is dropped; a frame a window or more ahead
// moves the window only when its datagram proves it (dgJumpProof), and is
// dropped otherwise (dgJumpClaim; m3 FSEQJUMP); after the peer's CLOSE
// every later frame but a RACK or a REL is dropped (M2-D30). A
// ReadCandidate datagram of which a frame was newly accepted starts a
// rebind challenge (M2-D27), or retargets the one in flight unless it
// carried a challenge answer that committed nothing; one whose frames were
// only ahead may start one but never retargets (a jump with a NAT move
// proves itself with the challenge's answer). It reports whether the
// reader continues.
func (c *Conn) dgFrames(data []byte, src PeerKey, ev ReadEvent, now time.Time) bool {
	dg := c.dg
	if wire.IsPreface(data) {
		if !c.dialer && dg.hs.dupH1(data) {
			c.mu.Lock()
			dg.hs.repeatH2 = true
			// Until our first REL (H3 or a verdict) is acknowledged, the
			// dialer sends nothing but H1 copies: held, and after the hold
			// was released while H3 is still on its way (W4-REL-3).
			early := dg.rel.una == c.env.Presets.firstCseq()
			c.mu.Unlock()
			c.wakeWriter()
			if ev == ReadCandidate && (early || dg.held.Load()) {
				c.rebindCandidate(src, now, true) // a rebound handshake (R1-14)
			}
		} else {
			c.dgDropped(1)
		}
		return true
	}
	advanced, committed, answered, claimed := false, false, false, false
	proof := 0 // whether the datagram proves a jump: 0 not checked yet, 1 yes, -1 no
	for len(data) > 0 {
		f, n, err := wire.DecodeFrame(data)
		if err != nil || (!c.mux && !dedicatedOK(f.Type, f.Handle)) {
			c.dgDropped(1) // the rest of this datagram (PA-1; a dedicated carrier: §A3.2)
			break
		}
		data = data[n:]
		switch dg.rwin.Accept(f.Fseq) {
		case wire.WindowNew:
		case wire.WindowAhead:
			if proof == 0 {
				proof = -1
				if c.dgJumpProof(&f, data, src, now) {
					proof = 1
				}
			}
			if proof < 0 {
				c.dgDropped(1)
				c.dgJumpClaim(&f, now)
				claimed = true
				continue
			}
			dg.rwin.Jump(f.Fseq)
			dg.jumpAt = time.Time{} // the claim is proven (dgJumpPingLocked)
		default:
			c.dgDropped(1)
			continue
		}
		if !advanced {
			advanced = true
			c.lastRx.Store(c.dgSince(now))
		}
		if dg.peerClosed && wire.SeqLess(dg.peerCloseFseq, f.Fseq) && f.Type != wire.TypeRack && f.Type != wire.TypeRel {
			c.dgDropped(1) // nothing new follows the peer's CLOSE (M2-D30)
			continue
		}
		ok, ans := c.dgDispatch(&f, src, ev == ReadCandidate, now)
		if !ok {
			return false
		}
		committed = committed || ans == chalCommitted
		answered = answered || ans == chalRefused
	}
	if ev == ReadCandidate && (advanced || claimed) && !committed {
		c.rebindCandidate(src, now, advanced && !answered)
	}
	return true
}

// dgJumpProof reports whether the datagram from src whose frame f is a
// window or more ahead proves that it comes from this direction's sender:
// f or a frame after it (rest) is a PONG only that sender sends — the
// answer to a PING of this incarnation that is still outstanding (id ≠ 0,
// nonce salt ^ id, its record in the ring; L23) or to the rebind challenge
// in flight (id 0, its nonce, from its candidate; M2-D27). A PONG to an
// answered PING proves nothing: the fseq window compares in serial
// arithmetic, so a datagram of this direction replayed 2^31 to
// 2^32 − wire.FseqWindowBits frames later reads a window or more ahead,
// and its old PONG would move the window behind every genuine frame (m3
// W2). The sender jumps that far after an outage cost a window of frames,
// and the PONG to the PING the outage left outstanding (retried at the
// RTO: dgPingDueLocked) or to one that dgJumpClaim asked for (at once,
// then at the round trip's pace: dgJumpPingLocked) arrives within a round
// trip after the outage, or after the path stops losing those PINGs. A
// datagram of another carrier direction or session, whose fseqs start
// elsewhere (§0.13 A6), lands ahead about half the time, but its PONGs
// answer another salt or another challenge: it never moves the window (m3
// FSEQJUMP; §A9.1, R1-35).
func (c *Conn) dgJumpProof(f *wire.Frame, rest []byte, src PeerKey, now time.Time) bool {
	if c.dgProves(f.Type, f.Payload, src, now) {
		return true
	}
	for len(rest) > 0 {
		g, n, err := wire.DecodeFrame(rest)
		if err != nil || (!c.mux && !dedicatedOK(g.Type, g.Handle)) {
			return false
		}
		rest = rest[n:]
		if c.dgProves(g.Type, g.Payload, src, now) {
			return true
		}
	}
	return false
}

// dgProves reports whether a frame of type t with payload p from src is a
// PONG of the kinds dgJumpProof names.
func (c *Conn) dgProves(t wire.Type, p []byte, src PeerKey, now time.Time) bool {
	if t != wire.TypePong {
		return false
	}
	pg, err := wire.ParsePing(p)
	switch {
	case err != nil:
		return false
	case pg.ID != 0:
		return c.pingOutstanding(pg.ID, pg.Nonce) // its record holds nonce salt ^ id
	}
	c.mu.Lock()
	ch := &c.dg.chal
	ok := ch.active && !c.chalExpiredLocked(now) && pg.Nonce == ch.nonce && src == ch.cand
	c.mu.Unlock()
	return ok
}

// dgJumpClaim handles a frame a window or more ahead whose datagram proved
// nothing (dgJumpProof; the caller drops and counts it). An outage costs
// frames both ways, so the peer may have jumped as well and wait for the
// same proof: a PING the frame carries is answered — a challenge PING in a
// free challenge-PONG slot, any other in a free PONG slot, so a frame of
// another carrier never displaces a genuine answer, and a PONG of ours
// that answers another carrier's PING matches nothing at the peer — and a
// PING of ours whose PONG proves the jump is asked for when the claim
// says so (dgJumpPingLocked). Nothing else of the frame is applied.
func (c *Conn) dgJumpClaim(f *wire.Frame, now time.Time) {
	var p wire.Ping
	ping := false
	if f.Type == wire.TypePing {
		var err error
		p, err = wire.ParsePing(f.Payload)
		ping = err == nil
	}
	dg, st := c.dg, &c.st
	wake := false
	c.mu.Lock()
	switch {
	case !ping:
	case p.ID == 0:
		if ch := &dg.chal; !ch.pongDue {
			ch.pong, ch.pongDue = p, true
			ch.pong.Pad = 0
			wake = true
		}
	case !st.pongDue:
		st.pong, st.pongDue = p, true
		wake = true
	}
	if c.dgJumpPingLocked(now) {
		st.pingReq = true
		wake = true
	}
	c.mu.Unlock()
	if wake {
		c.wakeWriter()
	}
}

// dgJumpPingLocked reports whether the unproven forward jump of a frame
// read at now asks for a PING of the carrier, whose PONG proves it (m5
// PA-85, amending m3 FSEQJUMP's "at most one per RTO"); the reader calls
// it with Conn.mu held. A claim begins with the first such frame since the
// window last took a jump, or since a ping timeout D (the death deadline)
// without one, and asks at once; a later frame of the claim asks again
// once dgJumpEveryLocked has passed since the last request — the smoothed
// RTT unless the claim is foreign or the PING ring runs short, so a lost
// PING or PONG costs a round trip, not an RTO.
func (c *Conn) dgJumpPingLocked(now time.Time) bool {
	dg, st := c.dg, &c.st
	d := sched.DeathDeadline(st.srtt, st.inflight(), st.rate, c.tm.DeadMin, c.tm.DeadMax)
	prev := dg.jumpLast
	dg.jumpLast = now
	if dg.jumpAt.IsZero() || now.Sub(prev) >= d {
		dg.jumpAt = now // a new claim: ask at once
	} else if now.Sub(dg.jumpPing) < c.dgJumpEveryLocked(d, now) {
		return false
	}
	dg.jumpPing = now
	return true
}

// dgJumpEveryLocked is the spacing at now of a jump claim's PING requests
// (dgJumpPingLocked) for a ping timeout d. It is the smoothed RTT, at
// least minRateSample (never more often than a PING may judge an
// interval), and longer in two cases:
//
//   - The claim is foreign: it began d ago or more, and the carrier still
//     accepted a frame within the last RTO and round trip (the answers to
//     PINGs an RTO apart arrive that often). A genuine jump is proven
//     within a ping timeout or its carrier dies, and a carrier that still
//     accepts frames has its own direction in the window, so the claimed
//     frames are another carrier direction's or session's: they ask at M3's
//     pace, once per RTO, and never draw a PING per round trip for longer
//     than d. A carrier that has accepted nothing for that long — its own
//     direction jumped too, perhaps after a foreign claim began, or its
//     PINGs go unanswered — asks at the round trip's pace again, until the
//     proof, an answer in the window, or its death a ping timeout after its
//     oldest unanswered PING.
//   - pingCadenceMax PINGs are outstanding (a long loss of the PINGs or
//     their PONGs): at least the time left to the carrier's death deadline
//     (its oldest unanswered PING's) over the records still free, so the
//     rest of the ring is spread evenly over that time. A ring that
//     requests filled while the reverse path lost them would leave no PING
//     to prove the jump once the path is back (a full ring encodes none),
//     and the carrier would die of ping_timeout with its path working.
func (c *Conn) dgJumpEveryLocked(d time.Duration, now time.Time) time.Duration {
	st := &c.st
	every := max(st.srtt, minRateSample)
	if now.Sub(c.dg.jumpAt) >= d {
		rto := c.relRTOLocked()
		if last := c.lastRx.Load(); last != 0 && c.dgSince(now)-last < int64(rto+st.srtt) {
			every = max(every, rto)
		}
	}
	if free := pingRingSize - st.n; st.n >= pingCadenceMax && free > 0 {
		_, at, _ := c.deathDueLocked(now)
		if at.IsZero() {
			at = now.Add(d)
		}
		every = max(every, at.Sub(now)/time.Duration(free))
	}
	return every
}

// chalAnswer is what one frame did to the rebind challenge (dgDispatch).
type chalAnswer uint8

const (
	chalNone      chalAnswer = iota // no challenge answer
	chalCommitted                   // a PONG with id 0 that committed the rebind
	chalRefused                     // a PONG with id 0 that committed nothing (dropped and counted)
)

// dgDispatch handles one accepted frame (the legality of §A3.6): PING and
// PONG bare (id 0: the rebind challenge and its answer, M2-D27; a PONG
// with id 0 from the current peer — cand false — may answer a passive OPEN
// flow's address check instead, SourceChecker); REL and
// RACK by the REL sublayer; DGRAM to the packet endpoint; a bare PACK to the
// endpoint; extensions skipped; every other bare frame — DATA, ACK and a
// reliable type outside REL — is a violation. ans reports what the frame
// did to the rebind challenge.
func (c *Conn) dgDispatch(f *wire.Frame, src PeerKey, cand bool, now time.Time) (ok bool, ans chalAnswer) {
	switch f.Type {
	case wire.TypePing:
		p, err := wire.ParsePing(f.Payload)
		if err != nil {
			c.violation("PING: %v", err)
			return false, chalNone
		}
		if p.ID == 0 {
			c.onChallengePing(&p)
			return true, chalNone
		}
		c.onPing(f.Flags&wire.FlagPingBusy != 0, &p, now)
		return true, chalNone
	case wire.TypePong:
		p, err := wire.ParsePing(f.Payload)
		if err != nil {
			c.violation("PONG: %v", err)
			return false, chalNone
		}
		if p.ID == 0 {
			if !cand && c.sourceChecked(&p) {
				return true, chalNone
			}
			if c.onChallengePong(&p, src, now) {
				return true, chalCommitted
			}
			return true, chalRefused
		}
		c.pong(&p, now)
		return true, chalNone
	case wire.TypeRel:
		return c.relOnRel(f, now), chalNone
	case wire.TypeRack:
		return c.relOnRack(f.Payload, now), chalNone
	case wire.TypeDgram:
		return c.dgOnDgram(f.Handle, f.Payload, now), chalNone
	case wire.TypePack:
		var v *Conn
		if c.mux {
			act, mv, _ := c.classify(f.Type, f.Handle)
			if act != actDispatch {
				if act == actIllegal {
					c.dgDropped(1) // §A3.3 on a datagram trunk: dropped and counted (PA-1)
				}
				return true, chalNone
			}
			v = mv
		} else {
			v = c.route(f.Handle) // a one-view trunk: a compare with view 1's handle
		}
		if v == nil {
			c.violation("PACK for handle %d: no such view", f.Handle)
			return false, chalNone
		}
		if v.ep == nil {
			c.violation("PACK on a carrier without a session")
			return false, chalNone
		}
		if !v.enter() {
			return true, chalNone // the view's Done closed after our DETACH: not delivered
		}
		err := v.ep.Control(v, f.Header, f.Payload)
		v.exit()
		if err != nil {
			c.violation("PACK: %v", err)
			return false, chalNone
		}
		return true, chalNone
	}
	if f.Type.Extension() {
		return true, chalNone // CRC-checked and skipped (§5.2); never inside REL
	}
	c.violation("bare %v on a datagram carrier", f.Type)
	return false, chalNone
}

// dgOnDgram hands one DGRAM for handle h to the packet endpoint of its view
// (route; §A5.3): below BigData
// the payload is valid during the call (the session copies it); BigData or
// more is copied first into a Buf of its own (TryGet against the Budget,
// outside every lock; refused: the datagram is dropped and counted) whose
// ownership moves to the endpoint. A DGRAM that makes an idle carrier
// packet-active wakes the writer (PacketPing cadence, M2-D23).
func (c *Conn) dgOnDgram(h uint32, p []byte, now time.Time) bool {
	seq, data, err := wire.ParseDgram(p)
	if err != nil {
		c.violation("DGRAM: %v", err)
		return false
	}
	var v *Conn
	if c.mux {
		act, mv, _ := c.classify(wire.TypeDgram, h)
		if act != actDispatch {
			if act == actIllegal {
				c.dgDropped(1) // §A3.3 on a datagram trunk: dropped and counted (PA-1)
			}
			return true
		}
		v = mv
	} else {
		v = c.route(h)
	}
	if v == nil {
		c.violation("DGRAM for handle %d: no such view", h)
		return false
	}
	if v.pep == nil {
		if v.ep == nil {
			c.violation("DGRAM on a carrier without a session")
		} else {
			c.violation("DGRAM on a stream session")
		}
		return false
	}
	active := c.packetActive(now)
	c.dg.lastDgram.Store(c.dgSince(now))
	if !active {
		c.wakeWriter()
	}
	c.rxBytes.Add(uint64(len(data)))
	if !v.enter() {
		return true // the view's Done closed after our DETACH: not delivered (M3-D13)
	}
	defer v.exit()
	v.countRx(len(data))
	var buf *Buf
	if len(data) >= BigData {
		buf = c.env.Bufs.TryGet(len(data), c.env.Budget)
		if buf == nil {
			c.dgDropped(1) // MaxBufferedBytes refused it
			return true
		}
		n := copy(buf.B, data)
		data = buf.B[:n]
	}
	if err := v.pep.Datagram(v, seq, data, buf); err != nil {
		c.violation("DGRAM: %v", err)
		return false
	}
	return true
}
