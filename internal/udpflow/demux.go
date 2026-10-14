package udpflow

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/udpsocket"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// reader is the state of a Source's Run goroutine (M2 design §A6.2).
type reader struct {
	s     *Source
	admit Admit

	// slot are the read slots of rendr's own socket (class MaxDatagram +
	// 1), one per datagram of a read (M5-D13, R1-4). Slot 0 is uncharged
	// while it waits for the socket: an idle source holds no buffered bytes
	// for it (R-C3-2), and a datagram read into it is charged to the Budget
	// when it moves to its flow's inbox (Buf.TryCharge; refused: it is
	// copied out as from the spare — into a Budget-charged buffer of its
	// size, else the flow's control reserve, else dropped). Slots 1 … D−1
	// (D = min(MaxBatch, 32), R1-6) are taken with TryGet on the Budget:
	// charged while they wait, they move to an inbox with that charge
	// (nothing is charged twice); a refused one stays empty, the read uses
	// the slots it has and ChargeRefused counts it. A dropped datagram
	// leaves its slot for the next read (nothing allocated for junk).
	slot [srcMaxDepth]*carrier.Buf
	// ms are the messages of one read, at[i] the slot of ms[i].
	ms [srcMaxDepth]udpsocket.Msg
	at [srcMaxDepth]uint8

	// The extras of a read at depth D ≥ 2 — slots 1 … D−1 and bt, a Batch
	// of D messages taken from the Source's pool (s.rpool, so a regrow
	// allocates nothing) and charged to Stages while held (btBytes, D ×
	// batchMsgBytes; R1-5 rules 1 and 4) — and their idle release
	// (plan:774; M5 design R1-5 rule 3, which srcidle applies to the
	// passive Source). The reads of rendr's own socket go through rd, the
	// dialer reader's udpsocket.Reader, whose four-state word says who owns
	// the extras: the reader goroutine while they are held (held mirrors
	// rd.Held() after each read; the reader touches slots 1 … D−1 and bt
	// only while held is true), nobody while its read is parked (in the
	// netpoller, or in a plain read), and the idle-release timer (idleT,
	// the period s.idleRel) once it took them by CAS from a read that
	// stayed parked for a whole period; it returns them on its own
	// goroutine (releaseIdle). The parked read then waits at depth 1 — it
	// moves the next datagram into slot 0 — and the read after it is at D
	// again; shed keeps depth 1 across reads that end in an error until a
	// datagram arrives. An idle Source thus holds what it held at M4: slot
	// 0, uncharged.
	rd      srcReader // nil: tokenIO (depth 1)
	bt      *udpsocket.Batch
	btBytes int64
	held    bool
	shed    bool
	idleT   *time.Timer   // armed while the extras are held (rd.Holding)
	armed   atomic.Bool   // idleT is armed
	lastSeq atomic.Uint64 // rd.Parks() at idleT's previous firing
	// relMu (one slot) orders a firing of idleT against the reader's exit
	// (endIdle): a channel rather than a sync.Mutex, so that a reader
	// waiting for a release in flight is durably blocked in a synctest
	// bubble (TestSourceDoneWaitsForIdleRelease). ended (under relMu): the
	// reader exited, a firing releases and re-arms nothing.
	relMu chan struct{}
	ended bool
	// rb is the buffer the datagram being routed lies in (route's direct
	// case): a slot taken out of r.slot while it is routed, nil once an
	// inbox took it; rbCharged reports that it is charged to the Budget
	// (slots 1 … D−1).
	rb        *carrier.Buf
	rbCharged bool
	// spare is a foreign conn's read buffer (its ReadFrom reads into it; a
	// routed datagram is copied out), uncharged as slot 0.
	spare *carrier.Buf
	// touched are the flows the current read pushed datagrams to: each is
	// woken once after the read's datagrams were routed (M5-D14).
	touched [srcMaxDepth]*Flow
	nt      int

	backoff time.Duration // the next noise backoff (0: backoffMin)
	timer   *time.Timer   // the backoff timer, reused
	empties int           // consecutive empty reads
}

// exit ends Run: the source stops (no admission, every flow's reads fail),
// the socket closes once, and Done follows when every flow ended. It also
// runs when the conn's ReadFrom called runtime.Goexit.
func (r *reader) exit() {
	s := r.s
	if r.timer != nil {
		r.timer.Stop()
	}
	r.endIdle()
	r.rb.Release()
	r.spare.Release()
	r.rb, r.spare = nil, nil
	r.slot[0].Release()
	r.slot[0] = nil
	clear(r.ms[:])
	r.wakeTouched()
	s.mu.Lock()
	if s.abCharge > 0 { // the abandoned read returned (runStuck's charge)
		s.stages.Release(s.abCharge)
		s.abCharge = 0
	}
	s.killLocked()
	s.closeSocketLocked()
	if s.runWatch != nil {
		s.runWatch.finish() // a late return of an abandoned ReadFrom leaves the pool
	}
	s.run = runExited
	s.checkDoneLocked()
	s.mu.Unlock()
}

// loopOwned reads rendr's own listening socket (s.bio): up to D datagrams
// per call into the read slots, each classified as one read of the socket
// would be and routed in arrival order, then every flow that received
// datagrams is woken once (M5 design §A4.4, §A4.5); no allocation per
// datagram. An idle Source returns its extras (idleFire).
func (r *reader) loopOwned() {
	r.startDepth()
	for !r.s.halted.Load() && r.readOwned() {
	}
}

// startDepth prepares the reads of rendr's own socket: rd over the
// Source's socket and the idle-release timer, stopped (one per Source).
func (r *reader) startDepth() {
	if r.rd = newSrcReader(r.s.bio, r.releaseIdle); r.rd != nil {
		r.relMu = make(chan struct{}, 1)
		r.idleT = time.AfterFunc(time.Hour, r.idleFire)
		r.idleT.Stop()
	}
}

// readOwned is one read of loopOwned; false ends the loop.
func (r *reader) readOwned() bool {
	s := r.s
	k := r.fill(r.depth())
	var n int
	var err error
	if r.rd != nil {
		n, err = r.rd.ReadBatch(r.ms[:k])
		if r.held && !r.rd.Held() {
			// The idle release took the extras while the read was parked
			// (idleFire): their slots and charges went back on the timer's
			// goroutine, and the read moved at most one datagram, into
			// slot 0.
			r.held, r.shed = false, true
		}
	} else {
		n, err = s.bio.ReadBatch(nil, r.ms[:k])
	}
	if err != nil {
		clear(r.ms[:k])
		switch carrier.ClassifyPacketErr(err, false) {
		case carrier.PacketErrSize:
			s.countTruncated() // Windows WSAEMSGSIZE: a truncated datagram
			return true
		case carrier.PacketErrNoise, carrier.PacketErrAbort:
			r.noise() // the socket is bound explicitly: an abort is noise (M2 §A6.1)
			return true
		}
		return false // closed by Stop or Abort, or a permanent error: this source stops (L50)
	}
	if n < 1 || n > k {
		clear(r.ms[:k])
		return false // an invalid count (L42)
	}
	r.shed = false // traffic: the next read regrows to D
	for i := range n {
		m := &r.ms[i]
		switch {
		case m.Trunc:
			s.countTruncated()
		case m.N == 0:
			s.drop() // a real empty datagram: the kernel cannot spin on empties, no backoff (L58)
		default:
			r.backoff, r.empties = 0, 0
			j := r.at[i]
			r.rb, r.rbCharged, r.slot[j] = r.slot[j], j != 0, nil
			src := netip.AddrPortFrom(m.Addr.Addr().Unmap(), m.Addr.Port())
			s.route(r, m.Buf[:m.N], src, nil, true)
			r.slot[j], r.rb, r.rbCharged = r.rb, nil, false // nil: an inbox took it
		}
	}
	clear(r.ms[:k])
	r.wakeTouched()
	return true
}

// depth returns the depth of the next read: the Source's (readDepth), or
// 1 while the extras are shed — after an idle release, until a datagram
// arrives (srcidle).
func (r *reader) depth() int {
	if r.shed {
		return 1
	}
	return r.s.readDepth()
}

// fill prepares the next read at depth d: it refills the empty slots —
// slot 0 uncharged, slots 1 … d−1 by TryGet on the Budget (a refusal
// leaves the slot empty and counts ChargeRefused, R1-4) — and returns the
// number of messages, one per slot it has (≥ 1). Reading at d ≥ 2 takes
// the extras first (hold); at depth 1 — a socket that fell back, a reader
// whose extras the idle release took, a Hold refused — it reads into
// slot 0 alone and gives back extras it holds.
func (r *reader) fill(d int) int {
	s := r.s
	if r.slot[0] == nil {
		r.slot[0] = s.dbufs.Get(s.maxDgram+1, nil) // charged at hand-over
		s.rbuf.Store(int64(len(r.slot[0].B)))
	}
	if d >= 2 && !r.held {
		r.hold()
	}
	if d < 2 || !r.held {
		r.dropExtras()
		r.ms[0], r.at[0] = udpsocket.Msg{Buf: r.slot[0].B[:s.maxDgram+1]}, 0
		return 1
	}
	k, refused := 0, 0
	for j := range d {
		if r.slot[j] == nil {
			if r.slot[j] = s.dbufs.TryGet(s.maxDgram+1, s.env.Budget); r.slot[j] == nil {
				refused++
				continue
			}
		}
		r.ms[k], r.at[k] = udpsocket.Msg{Buf: r.slot[j].B[:s.maxDgram+1]}, uint8(j)
		k++
	}
	if refused > 0 {
		if dg := s.env.Dgram; dg != nil {
			dg.ChargeRefused.Add(uint64(refused))
		}
	}
	return k
}

// hold takes the extras for a read at depth D: a Batch of D messages from
// the Source's pool (rpool: the depth's class, R1-5 rules 1 and 4),
// charged to Stages before rd holds it, and arms the idle release; the
// slots 1 … D−1 follow in fill. rd refuses the Batch while an idle
// release still returns the previous extras: the Batch goes back with its
// charge and the read stays at depth 1.
func (r *reader) hold() {
	if r.rd == nil {
		return // tokenIO: one datagram per call
	}
	s := r.s
	b := s.rpool.Get().(*udpsocket.Batch)
	n := int64(b.Cap()) * batchMsgBytes
	s.stages.Acquire(n)
	if _, ok := r.rd.Hold(b); !ok {
		s.stages.Release(n)
		s.rpool.Put(b)
		return
	}
	r.bt, r.btBytes, r.held = b, n, true
	r.arm()
}

// dropExtras takes held extras back from rd and returns them (depth 1, or
// the reader's exit). The reader goroutine calls it between reads: no slot
// holds a datagram then (a routed one moved to its inbox, any other was
// dropped).
func (r *reader) dropExtras() {
	if !r.held {
		return
	}
	r.rd.Drop()
	r.held = false
	r.releaseExtras()
}

// releaseExtras returns the extras: the slots 1 … D−1, each with its
// Budget charge, and the Batch, with its Stages charge, to the Source's
// pool. Their owner runs it: the reader goroutine after Drop, or the idle
// release while rd is releasing them (releaseIdle).
func (r *reader) releaseExtras() {
	for i := 1; i < len(r.slot); i++ {
		r.slot[i].Release()
		r.slot[i] = nil
	}
	r.s.stages.Release(r.btBytes)
	r.s.rpool.Put(r.bt)
	r.bt, r.btBytes = nil, 0
}

// releaseIdle is rd's release function: rd.TryRelease runs it on the
// timer's goroutine while rd is releasing the extras of a parked read,
// which never touches them again (udpsocket.Reader).
func (r *reader) releaseIdle(*udpsocket.Batch) { r.releaseExtras() }

// arm arms the idle release once the reader holds the extras.
func (r *reader) arm() {
	if r.idleT != nil && r.armed.CompareAndSwap(false, true) {
		r.lastSeq.Store(r.rd.Parks())
		r.idleT.Reset(r.s.idleRel)
	}
}

// idleFire is the idle release (on the timer's goroutine), R1-5 rule 3 as
// the dialer's reader runs it (internal/carrier's dgReader.idleFire): a
// reader that has stayed parked since the previous firing — a whole
// period, rd.Parks() unchanged — has its extras taken by rd.TryRelease
// (parked → releasing by CAS, then releaseIdle, then idle). Unlike the
// dialer's, it sets no read deadline: the dialer wakes its read to pool a
// header whose message array that read still references, while the
// Source's messages are its own and its Batch went back at once, so the
// parked read simply moves the next datagram into slot 0. A reader that
// holds its extras while it routes a read's datagrams is never released:
// the CAS needs a parked read. A busy reader costs one O(1) firing per
// period; the timer touches no traffic (a resource release, not a
// liveness trigger: invariant 7). relMu orders a firing before the
// reader's exit (endIdle).
func (r *reader) idleFire() {
	r.relMu <- struct{}{}
	defer func() { <-r.relMu }()
	if r.ended {
		return
	}
	rd := r.rd
	if rd.Holding() {
		seq := rd.Parks()
		if seq != r.lastSeq.Load() {
			r.lastSeq.Store(seq) // it parked again during the period
			r.idleT.Reset(r.s.idleRel)
			return
		}
		if !rd.TryRelease(seq) {
			r.idleT.Reset(r.s.idleRel) // held and reading: busy
			return
		}
	}
	r.armed.Store(false)
	if rd.Holding() && r.armed.CompareAndSwap(false, true) {
		// The reader took new extras while this firing released the old.
		r.lastSeq.Store(rd.Parks())
		r.idleT.Reset(r.s.idleRel)
	}
}

// endIdle ends the idle release when the reader exits: a firing in
// progress completes first — its charges are back before Done — and none
// releases or re-arms after it; extras the reader holds go back.
func (r *reader) endIdle() {
	if r.idleT != nil {
		r.idleT.Stop()
		r.relMu <- struct{}{}
		r.ended = true
		<-r.relMu
	}
	r.dropExtras()
}

// touch records that f received a datagram of the current read; f is woken
// once by wakeTouched (M5-D14). A full set — more flows than a read moves,
// which only a direct caller of route can produce — wakes f at once.
func (r *reader) touch(f *Flow) {
	for _, g := range r.touched[:r.nt] {
		if g == f {
			return
		}
	}
	if r.nt == len(r.touched) {
		f.wake()
		return
	}
	r.touched[r.nt] = f
	r.nt++
}

// wakeTouched wakes every flow of the current read once: its reader drains
// the whole inbox per wake (M2), so one wake per flow per read loses
// nothing (M5 design §A4.5).
func (r *reader) wakeTouched() {
	for i, f := range r.touched[:r.nt] {
		f.wake()
		r.touched[i] = nil
	}
	r.nt = 0
}

// loopForeign reads an embedder conn through ReadFrom only (L57): into the
// spare, the source address required to be a *net.UDPAddr; errors are
// classified by carrier.ClassifyPacketErr, an abort being noise on a
// shared listening socket (integration 1, D16).
func (r *reader) loopForeign() {
	s := r.s
	r.spare = s.dbufs.Get(wire.MaxDatagram+1, nil) // uncharged: routed datagrams are copied out
	s.rbuf.Store(int64(len(r.spare.B)))
	for !s.halted.Load() {
		b := r.spare.B[:wire.MaxDatagram+1]
		n, addr, err := callReadFrom(s.pc, b)
		if err != nil {
			if s.halted.Load() {
				return
			}
			switch carrier.ClassifyPacketErr(err, false) {
			case carrier.PacketErrSize:
				s.countTruncated() // Windows WSAEMSGSIZE: a truncated datagram
				continue
			case carrier.PacketErrNoise, carrier.PacketErrAbort, carrier.PacketErrDeadline:
				r.noise()
				continue
			}
			return // a permanent error: this source stops (L50)
		}
		switch {
		case n < 0 || n > len(b):
			return // an invalid count (L42): the conn is broken
		case n == len(b):
			s.countTruncated()
			continue
		case n == 0:
			r.emptyForeign()
			continue
		}
		r.backoff, r.empties = 0, 0
		ua, ok := addr.(*net.UDPAddr)
		if !ok || ua == nil {
			s.drop() // only UDP sources can be flows (L57)
			continue
		}
		ap := ua.AddrPort()
		if !ap.Addr().IsValid() {
			s.drop()
			continue
		}
		s.route(r, b[:n], netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), ua, false)
		r.wakeTouched()
	}
}

// noise counts a transient read error and backs off 5 → 100 ms (L58).
func (r *reader) noise() {
	s := r.s
	s.readErrors.Add(1)
	if d := s.env.Dgram; d != nil {
		d.ReadErrors.Add(1)
	}
	d := r.backoff
	if d <= 0 {
		d = backoffMin
	}
	r.backoff = min(2*d, backoffMax)
	r.pause(d)
}

// emptyForeign drops an empty read of a foreign conn; every emptyRun
// consecutive empty reads pause emptyPause. A conn that returns (0, addr,
// nil) forever thus reads at most emptyRun times per emptyPause instead of
// spinning a core (PA-18, R1-27), while a real flood of empty datagrams
// keeps tens of thousands of reads per second — a doubling backoff would
// starve every flow on the socket (L58).
func (r *reader) emptyForeign() {
	r.s.drop()
	r.empties++
	if r.empties >= emptyRun {
		r.empties = 0
		r.pause(emptyPause)
	}
}

// pause waits d (or until the socket closes) on the reused timer.
func (r *reader) pause(d time.Duration) {
	if r.timer == nil {
		r.timer = time.NewTimer(d)
	} else {
		r.timer.Reset(d)
	}
	select {
	case <-r.timer.C:
	case <-r.s.quit:
	}
}

// route delivers one datagram d (flow header included) from src: addr is
// the foreign conn's source value (nil for rendr's own socket), direct
// reports that d lies in r.rb, which then moves to the flow's inbox. A
// known flow that received d is recorded for the read's wake (r.touch). It
// allocates nothing unless it creates a flow.
func (s *Source) route(r *reader, d []byte, src netip.AddrPort, addr *net.UDPAddr, direct bool) {
	id, rb, err := wire.ParseFlowHeader(d)
	if err != nil || len(rb) == 0 {
		s.drop() // no flow header, or nothing behind it
		return
	}
	s.mu.Lock()
	f := s.flows[id]
	s.mu.Unlock()
	if f != nil {
		s.deliver(r, f, rb, src, addr, direct)
		return
	}
	s.admitH1(r, id, rb, src, addr, direct)
}

// deliver queues the rendr bytes rb of a known flow f: the read buffer
// itself (direct) with its Budget charge — taken now for slot 0, carried
// by the other slots — else a copy in a Budget-charged buffer, else — the
// Budget refuses — a copy in one of f's control-reserve buffers, only for
// a datagram without a DGRAM frame (M2-D59; L16). f is woken after the
// read (r.touch, M5-D14).
func (s *Source) deliver(r *reader, f *Flow, rb []byte, src netip.AddrPort, addr *net.UDPAddr, direct bool) {
	var res pushResult
	switch {
	case direct && (r.rbCharged || r.rb.TryCharge(s.env.Budget)):
		if res = f.push(r.rb, rb, src, addr, false); res == pushOK {
			r.rb = nil // moved to the inbox
		} else if !r.rbCharged {
			r.rb.Uncharge() // it stays the read buffer
		}
	default: // a foreign conn's spare, or the Budget refused rb's class
		if buf := s.dbufs.TryGet(len(rb), s.env.Budget); buf != nil {
			data := buf.B[:copy(buf.B, rb)]
			if res = f.push(buf, data, src, addr, false); res != pushOK {
				buf.Release()
			}
		} else if reservable(rb) {
			res = f.pushReserve(rb, src, addr)
		} else {
			res = pushFull // a DGRAM under memory pressure: dropped, control goes on
		}
	}
	switch res {
	case pushOK:
		r.touch(f)
	case pushFull:
		s.inboxDrops.Add(1)
		if d := s.env.Dgram; d != nil {
			d.InboxDrops.Add(1)
		}
	case pushClosed:
		s.drop()
	}
}

// admitH1 handles a datagram of an unknown flow (M2 design §A6.2): only a
// complete valid H1 creates a flow — when admission is open, the ID not
// tombstoned (R1-11), the flow table below MaxFlows and the source IP's
// admitting flows of the H1's class below that class's quota (R1-21) —
// and everything else is dropped without state; a PREFACE of another
// major or with unknown required features is answered VERSION or FEATURE,
// a valid H1 while stopped CAPACITY, statelessly.
func (s *Source) admitH1(r *reader, id uint64, rb []byte, src netip.AddrPort, addr *net.UDPAddr, direct bool) {
	cls, refuse, cid, ok := s.checkH1(rb)
	if refuse != wire.PrefaceOK {
		s.answer(id, refuse, cid, src, addr)
		s.drop()
		return
	}
	if !ok {
		s.drop()
		return
	}
	now := time.Now() // valid H1s only: junk reads no clock
	ip := src.Addr()
	s.mu.Lock()
	switch {
	case s.stopped:
		answer := !s.closing
		s.mu.Unlock()
		if answer {
			s.answer(id, wire.PrefaceCapacity, cid, src, addr)
		}
		s.drop()
		return
	case s.tombLocked(id, now):
		s.mu.Unlock()
		s.drop() // a late copy or replay of a removed flow's H1 (R1-11)
		return
	case len(s.flows) >= s.lim.MaxFlows || s.perIP[ip][cls] >= s.lim.quota(cls):
		s.mu.Unlock()
		s.quotaDrops.Add(1)
		s.drop() // silent: no amplification (L58)
		return
	}
	f := newFlow(s, id, ip, cls, src, addr)
	s.flows[id] = f
	c := s.perIP[ip]
	c[cls]++
	s.perIP[ip] = c
	s.admitting++
	f.admitting = true
	s.mu.Unlock()

	// The H1 into the new inbox: a fresh flow's inbox is empty and its
	// reserve free, and an H1 carries no DGRAM, so it always fits. Nobody
	// reads the flow before admit hands it over: no wake.
	if direct && (r.rbCharged || r.rb.TryCharge(s.env.Budget)) {
		f.push(r.rb, rb, src, addr, false)
		r.rb = nil
	} else if buf := s.dbufs.TryGet(len(rb), s.env.Budget); buf != nil {
		f.push(buf, buf.B[:copy(buf.B, rb)], src, addr, false)
	} else {
		f.pushReserve(rb, src, addr)
	}
	if r.admit == nil {
		f.Close()
		return
	}
	r.admit(f)
}

// checkH1 validates the rendr bytes of an unknown flow's datagram as a
// complete H1 (M2 design §A5.10): a PREFACE of kind datagram and exactly
// one frame filling the rest at the PREFACE's first fseq whose header and
// CRC verify — REL{FirstCseq, OPEN | JOIN} or a PING with pad 0. ok
// reports a valid H1 of class cls; refuse is VERSION or FEATURE for a
// PREFACE the passive answers (cid: the carrier ID to echo).
func (s *Source) checkH1(rb []byte) (cls uint8, refuse wire.PrefaceStatus, cid uint32, ok bool) {
	if !wire.IsPreface(rb) {
		return 0, wire.PrefaceOK, 0, false
	}
	pre := rb[:wire.PrefaceLen]
	p, err := wire.ParsePreface(pre)
	switch err {
	case nil:
	case wire.ErrMajor:
		// Another major: the carrier ID's place is the only echo we can give.
		return 0, wire.PrefaceVersion, binary.BigEndian.Uint32(pre[32:36]), false
	case wire.ErrFeature:
		return 0, wire.PrefaceFeature, p.CarrierID, false
	default:
		return 0, wire.PrefaceOK, 0, false
	}
	if p.Kind != wire.KindDatagram {
		return 0, wire.PrefaceOK, 0, false
	}
	rest := rb[wire.PrefaceLen:]
	fr, n, err := wire.DecodeFrame(rest)
	if err != nil || n != len(rest) {
		return 0, wire.PrefaceOK, 0, false
	}
	first := s.firstFseq
	if first == 0 {
		first = wire.PrefaceFseq(pre)
	}
	if fr.Fseq != first {
		return 0, wire.PrefaceOK, 0, false
	}
	switch fr.Type {
	case wire.TypeRel:
		h, _, err := wire.ParseRel(fr.Payload)
		if err != nil || h.Cseq != s.firstCseq {
			return 0, wire.PrefaceOK, 0, false
		}
		switch h.Type {
		case wire.TypeOpen:
			return classOpen, wire.PrefaceOK, p.CarrierID, true
		case wire.TypeJoin:
			return classJoin, wire.PrefaceOK, p.CarrierID, true
		}
	case wire.TypePing:
		if len(fr.Payload) == wire.PingFixedLen {
			return classJoin, wire.PrefaceOK, p.CarrierID, true
		}
	}
	return 0, wire.PrefaceOK, 0, false
}

// answer writes the stateless PREFACE_ACK(st) to src under the request's
// flow header (M2-D21): 49 bytes for a request of at least 49, no state.
// Errors are ignored (the dialer resends its H1).
func (s *Source) answer(id uint64, st wire.PrefaceStatus, cid uint32, src netip.AddrPort, addr *net.UDPAddr) {
	b := s.ans[:]
	wire.PutFlowHeader(b, id)
	ack := wire.PrefaceAck{Minor: wire.Minor, Status: st, Instance: s.env.Local, CarrierID: cid}
	wire.PutPrefaceAck(b[wire.FlowHeaderLen:], &ack)
	if s.bio != nil {
		_ = s.write(b, src, nil) // counted with the socket's other calls
		return
	}
	_, _ = callWriteTo(s.pc, b, addr)
}

// reservable reports whether rb (rendr bytes) are whole frames — after an
// optional PREFACE — none of which is a DGRAM: a header walk without CRCs,
// deciding whether a datagram may use a flow's control reserve (L16).
func reservable(rb []byte) bool {
	if wire.IsPreface(rb) {
		rb = rb[wire.PrefaceLen:]
	}
	for len(rb) > 0 {
		if len(rb) < wire.HeaderLen || wire.Type(rb[0]) == wire.TypeDgram {
			return false
		}
		end := wire.FrameOverhead + (int(rb[2])<<16 | int(rb[3])<<8 | int(rb[4]))
		if end > len(rb) {
			return false
		}
		rb = rb[end:]
	}
	return true
}

// drop counts a datagram dropped before reaching a flow.
func (s *Source) drop() {
	s.dropped.Add(1)
	if d := s.env.Dgram; d != nil {
		d.Dropped.Add(1)
	}
}

// countTruncated counts a truncated or oversize datagram (of Dropped).
func (s *Source) countTruncated() {
	s.truncated.Add(1)
	if d := s.env.Dgram; d != nil {
		d.Truncated.Add(1)
	}
	s.drop()
}

// write sends one datagram of a flow to dst: through rendr's own socket
// (one counted call; its classes: too large, noise — an abort included on
// a listening socket — or death, ownedWriteErr) or a foreign conn's
// WriteTo with addr (writeForeign).
func (s *Source) write(b []byte, dst netip.AddrPort, addr *net.UDPAddr) error {
	ds := [1][]byte{b}
	_, err := s.writeBatch(ds[:], dst, addr)
	return err
}

// writeForeign sends one datagram through a foreign conn by WriteTo with
// addr, classified by carrier.ClassifyPacketErr (an abort is noise on the
// shared socket; integration 1, D16).
func (s *Source) writeForeign(b []byte, addr *net.UDPAddr) error {
	n, err := callWriteTo(s.pc, b, addr)
	if err != nil {
		switch carrier.ClassifyPacketErr(err, true) {
		case carrier.PacketErrNoise, carrier.PacketErrAbort:
			return carrier.ErrNoise
		case carrier.PacketErrSize:
			if isTooLarge(err) {
				return err // keeps its Max for errors.As
			}
			return errTooLarge
		}
		return err
	}
	if n != len(b) {
		return errWriteCount // L42: never retried on this carrier
	}
	return nil
}

// Guarded calls of a foreign conn (L57): a panic becomes an error (the
// source stops on a read, the carrier dies on a write); runtime.Goexit is
// handled by the callers' deferred cleanup.

func callReadFrom(pc net.PacketConn, p []byte) (n int, addr net.Addr, err error) {
	defer func() {
		if v := recover(); v != nil {
			n, addr, err = 0, nil, &panicError{op: "ReadFrom", v: v}
		}
	}()
	return pc.ReadFrom(p)
}

func callWriteTo(pc net.PacketConn, p []byte, addr *net.UDPAddr) (n int, err error) {
	defer func() {
		if v := recover(); v != nil {
			n, err = 0, &panicError{op: "WriteTo", v: v}
		}
	}()
	return pc.WriteTo(p, addr)
}

// panicError reports a panic inside a foreign conn's method.
type panicError struct {
	op string
	v  any
}

func (e *panicError) Error() string {
	return fmt.Sprintf("rendr/udpflow: conn %s panicked: %v", e.op, e.v)
}
