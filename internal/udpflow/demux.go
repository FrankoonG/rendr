package udpflow

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// reader is the state of a Source's Run goroutine (M2 design §A6.2).
type reader struct {
	s     *Source
	admit Admit

	// rb is the next read's buffer while the Budget grants one (rendr's own
	// socket: class MaxDatagram + 1, TryGet against Env.Budget): a datagram
	// read into it is handed to its flow's inbox without a copy, and a
	// dropped one leaves it for the next read (nothing allocated for junk).
	rb *carrier.Buf
	// spare is the Stages-charged read buffer used while the Budget refuses
	// (rendr's own socket) and for every read of a foreign conn (its
	// ReadFrom reads into it; a routed datagram is copied out).
	spare *carrier.Buf

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
	r.rb.Release()
	r.spare.Release()
	r.rb, r.spare = nil, nil
	s.mu.Lock()
	s.killLocked()
	s.closeSocketLocked()
	if s.runWatch != nil {
		s.runWatch.finish() // a late return of an abandoned ReadFrom leaves the pool
	}
	s.run = runExited
	s.checkDoneLocked()
	s.mu.Unlock()
}

// loopOwned reads rendr's own listening socket: ReadAddrPort into a
// Budget-charged buffer (else the spare), no allocation per datagram, its
// own error and truncation classes (WP5).
func (r *reader) loopOwned() {
	s := r.s
	r.spare = s.dbufs.Get(s.maxDgram+1, s.stages)
	for !s.halted.Load() {
		if r.rb == nil {
			r.rb = s.dbufs.TryGet(s.maxDgram+1, s.env.Budget)
		}
		b, direct := r.spare.B, false
		if r.rb != nil {
			b, direct = r.rb.B, true
		}
		n, src, ev, err := s.own.ReadAddrPort(b)
		switch {
		case err != nil:
			return // closed by Stop or Abort, or a permanent error: this source stops (L50)
		case ev == carrier.ReadTruncated:
			s.countTruncated()
			continue
		case ev == carrier.ReadNoise:
			r.noise()
			continue
		case ev == carrier.ReadEmpty:
			s.drop() // a real empty datagram: the kernel cannot spin on empties, no backoff (L58)
			continue
		}
		r.backoff, r.empties = 0, 0
		s.route(r, b[:n], src, nil, direct)
	}
}

// loopForeign reads an embedder conn through ReadFrom only (L57): into the
// spare, the source address required to be a *net.UDPAddr; errors are
// classified by carrier.ClassifyPacketErr, an abort being noise on a
// shared listening socket (integration 1, D16).
func (r *reader) loopForeign() {
	s := r.s
	r.spare = s.dbufs.Get(wire.MaxDatagram+1, s.stages)
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
// reports that d lies in r.rb, which then moves to the flow's inbox. It
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
// itself (direct), else a copy in a Budget-charged buffer, else — the
// Budget refuses — a copy in one of f's control-reserve buffers, only for
// a datagram without a DGRAM frame (M2-D59; L16).
func (s *Source) deliver(r *reader, f *Flow, rb []byte, src netip.AddrPort, addr *net.UDPAddr, direct bool) {
	var res pushResult
	switch {
	case direct:
		if res = f.push(r.rb, rb, src, addr, false); res == pushOK {
			r.rb = nil // moved to the inbox
		}
	default:
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
	// reserve free, and an H1 carries no DGRAM, so it always fits.
	if direct {
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
	if s.own != nil {
		_ = s.own.WriteAddrPort(b, src)
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

// write sends one datagram of a flow to dst: rendr's own socket by
// WriteAddrPort (its classes: too large, noise — an abort included on a
// listening socket — or death), a foreign conn by WriteTo with addr,
// classified by carrier.ClassifyPacketErr (an abort is noise on the shared
// socket; integration 1, D16).
func (s *Source) write(b []byte, dst netip.AddrPort, addr *net.UDPAddr) error {
	if s.halted.Load() {
		return errSourceClosed
	}
	if s.own != nil {
		return s.own.WriteAddrPort(b, dst)
	}
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
