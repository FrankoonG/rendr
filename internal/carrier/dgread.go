package carrier

import (
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// The reader of a datagram carrier (M2-D13, M2-D14, M2-D30; M2 design
// §A5.7 and Revision 1, R1-1, R1-4, R1-27).

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
	buf     *Buf // the read buffer, io.ReadSize() bytes (nil: the transport hands out its own)
	backoff time.Duration
	idle    int         // consecutive reads that handed nothing over
	timer   *time.Timer // the back-off timer, created at the first back-off
}

// dgReadLoop is the reader goroutine of a datagram carrier: it walks the
// response datagram's tail (dialer, R1-1), then reads one datagram per
// ReadDatagram call and walks its frames (header and bounds, CRC, the fseq
// window, the M2-D30 rule, dispatch). Loss, corruption and noise never end
// it (PA-1); a read error, a violation or the end of a retirement does.
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
		if rd.buf != nil {
			rd.buf.Release()
			rd.buf = nil
		}
		if rd.timer != nil {
			rd.timer.Stop()
		}
		c.partDone(partReader)
	}()
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
	for c.dgReadOne(rd) {
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
		dg.io.Release()
		rd.idle++
		if rd.idle >= spinIdle {
			rd.idle = 0
			return c.dgPause(rd, spinPause) // the spin guard (R1-27)
		}
		return true
	}
	rd.backoff, rd.idle = 0, 0
	dg.ctr.datagramsRx.Add(1)
	ok := c.dgFrames(data, src, ev, time.Now())
	dg.io.Release()
	return ok
}

// dgBackoff sleeps the reader's back-off (5 ms doubling to 100 ms); it
// reports whether the reader continues. A dead carrier's reader exits
// here: a transport that keeps answering after Close (empties, noise)
// never makes it spin.
func (c *Conn) dgBackoff(rd *dgReader) bool {
	rd.backoff = min(max(2*rd.backoff, noiseMin), noiseMax)
	return c.dgPause(rd, rd.backoff)
}

// dgPause sleeps d on the reader's timer; it reports whether the reader
// continues (false: the carrier is dying).
func (c *Conn) dgPause(rd *dgReader, d time.Duration) bool {
	select {
	case <-c.dying:
		return false
	default:
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
// arithmetic, so a datagram of this direction replayed 2^31 to 2^32−1024
// frames later reads a window or more ahead, and its old PONG would move
// the window behind every genuine frame (m3 W2). The sender jumps that far after an outage cost a window of
// frames, and the PONG to the PING the outage left outstanding, retried at
// the RTO, or asked for by dgJumpClaim, arrives within a round trip of its
// end. A datagram of another carrier direction or session, whose fseqs
// start elsewhere (§0.13 A6), lands ahead about half the time, but its
// PONGs answer another salt or another challenge: it never moves the
// window (m3 FSEQJUMP; §A9.1, R1-35).
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
// PING of ours is asked for, at most one per RTO, whose PONG proves the
// jump. Nothing else of the frame is applied.
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
	if dg.jumpPing.IsZero() || now.Sub(dg.jumpPing) >= c.relRTOLocked() {
		dg.jumpPing = now
		st.pingReq = true
		wake = true
	}
	c.mu.Unlock()
	if wake {
		c.wakeWriter()
	}
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
