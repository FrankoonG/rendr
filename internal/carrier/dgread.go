package carrier

import (
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// The reader of a datagram carrier (M2-D13, M2-D14, M2-D30; M2 design
// §A5.7 and Revision 1, R1-1, R1-4, R1-27).

// Reader back-off (M2-D15, M2-D86): a transient read error, and every read
// after spinIdle consecutive reads that handed nothing over (on a transport
// other than rendr's own UDP socket), waits noiseMin, doubling to noiseMax,
// until a datagram is handed over.
const (
	noiseMin = 5 * time.Millisecond
	noiseMax = 100 * time.Millisecond
	spinIdle = 64
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
	guard   bool        // the spin guard applies (not on rendr's own socket)
	timer   *time.Timer // the back-off timer, created at the first back-off
}

// dgReadLoop is the reader goroutine of a datagram carrier: it walks the
// response datagram's tail (dialer, R1-1), then reads one datagram per
// ReadDatagram call and walks its frames (header and bounds, CRC, the fseq
// window, the M2-D30 rule, dispatch). Loss, corruption and noise never end
// it (PA-1); a read error, a violation or the end of a retirement does.
func (c *Conn) dgReadLoop() {
	dg := c.dg
	// rendr's own socket cannot spin: each of its reads consumes a datagram
	// that someone sent, so a burst of empty, foreign or malformed ones is
	// read at once instead of 100 ms each behind the back-off, which would
	// starve the carrier into a ping_timeout (as udpflow reads its own
	// socket, L58; WP12 TestUDPZeroLengthIsNotDeath_L42).
	_, own := dg.io.(*OwnedUDP)
	rd := &dgReader{guard: !own}
	normal := false
	defer func() {
		if !normal { // runtime.Goexit inside an embedder ReadFrom (L51)
			c.Kill(CauseTransportError, "conn ReadFrom called runtime.Goexit")
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
		if rd.guard && rd.idle >= spinIdle {
			return c.dgBackoff(rd) // the spin guard (R1-27)
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
	select {
	case <-c.dying:
		return false
	default:
	}
	rd.backoff = min(max(2*rd.backoff, noiseMin), noiseMax)
	if rd.timer == nil {
		rd.timer = time.NewTimer(rd.backoff)
	} else {
		rd.timer.Reset(rd.backoff)
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
// on the passive (the stored H2 is repeated; on a held passive flow a copy
// from a new source also starts a challenge, R1-14) and dropped otherwise;
// a frame that fails to decode drops the rest of the datagram (PA-1); a
// window duplicate or late frame is dropped; after the peer's CLOSE every
// later frame but a RACK or a REL is dropped (M2-D30). A ReadCandidate
// datagram of which a frame was newly accepted starts a rebind challenge
// (M2-D27). It reports whether the reader continues.
func (c *Conn) dgFrames(data []byte, src PeerKey, ev ReadEvent, now time.Time) bool {
	dg := c.dg
	if wire.IsPreface(data) {
		if !c.dialer && dg.hs.dupH1(data) {
			c.mu.Lock()
			dg.hs.repeatH2 = true
			c.mu.Unlock()
			c.Wake()
			if ev == ReadCandidate && dg.held.Load() {
				c.rebindCandidate(src, now) // a rebound handshake (R1-14)
			}
		} else {
			c.dgDropped(1)
		}
		return true
	}
	advanced, committed := false, false
	for len(data) > 0 {
		f, n, err := wire.DecodeFrame(data)
		if err != nil {
			c.dgDropped(1) // the rest of this datagram (PA-1)
			break
		}
		data = data[n:]
		if dg.rwin.Accept(f.Fseq) != wire.WindowNew {
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
		ok, comm := c.dgDispatch(&f, src, now)
		if !ok {
			return false
		}
		committed = committed || comm
	}
	if ev == ReadCandidate && advanced && !committed {
		c.rebindCandidate(src, now)
	}
	return true
}

// dgDispatch handles one accepted frame (the legality of §A3.6): PING and
// PONG bare (id 0: the rebind challenge and its answer, M2-D27); REL and
// RACK by the REL sublayer; DGRAM to the packet endpoint; a bare PACK to the
// endpoint; extensions skipped; every other bare frame — DATA, ACK and a
// reliable type outside REL — is a violation. committed reports a rebind
// commit.
func (c *Conn) dgDispatch(f *wire.Frame, src PeerKey, now time.Time) (ok, committed bool) {
	switch f.Type {
	case wire.TypePing:
		p, err := wire.ParsePing(f.Payload)
		if err != nil {
			c.violation("PING: %v", err)
			return false, false
		}
		if p.ID == 0 {
			c.onChallengePing(&p)
			return true, false
		}
		c.onPing(f.Flags&wire.FlagPingBusy != 0, &p, now)
		return true, false
	case wire.TypePong:
		p, err := wire.ParsePing(f.Payload)
		if err != nil {
			c.violation("PONG: %v", err)
			return false, false
		}
		if p.ID == 0 {
			return true, c.onChallengePong(&p, src, now)
		}
		c.pong(&p, now)
		return true, false
	case wire.TypeRel:
		return c.relOnRel(f, now), false
	case wire.TypeRack:
		return c.relOnRack(f.Payload, now), false
	case wire.TypeDgram:
		return c.dgOnDgram(f.Payload, now), false
	case wire.TypePack:
		if c.ep == nil {
			c.violation("PACK on a carrier without a session")
			return false, false
		}
		if err := c.ep.Control(c, f.Header, f.Payload); err != nil {
			c.violation("PACK: %v", err)
			return false, false
		}
		return true, false
	}
	if f.Type.Extension() {
		return true, false // CRC-checked and skipped (§5.2); never inside REL
	}
	c.violation("bare %v on a datagram carrier", f.Type)
	return false, false
}

// dgOnDgram hands one DGRAM to the packet endpoint (§A5.3): below BigData
// the payload is valid during the call (the session copies it); BigData or
// more is copied first into a Buf of its own (TryGet against the Budget,
// outside every lock; refused: the datagram is dropped and counted) whose
// ownership moves to the endpoint. A DGRAM that makes an idle carrier
// packet-active wakes the writer (PacketPing cadence, M2-D23).
func (c *Conn) dgOnDgram(p []byte, now time.Time) bool {
	seq, data, err := wire.ParseDgram(p)
	if err != nil {
		c.violation("DGRAM: %v", err)
		return false
	}
	if c.pep == nil {
		if c.ep == nil {
			c.violation("DGRAM on a carrier without a session")
		} else {
			c.violation("DGRAM on a stream session")
		}
		return false
	}
	active := c.packetActive(now)
	c.dg.lastDgram.Store(c.dgSince(now))
	if !active {
		c.Wake()
	}
	c.rxBytes.Add(uint64(len(data)))
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
	if err := c.pep.Datagram(c, seq, data, buf); err != nil {
		c.violation("DGRAM: %v", err)
		return false
	}
	return true
}
