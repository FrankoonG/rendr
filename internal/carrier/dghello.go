package carrier

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// The passive datagram handshake (M2-D19…M2-D22; M2 design §A5.10).

// dgHandshake holds what a started datagram carrier keeps of its handshake:
// the PREFACE it accepted (passive: duplicate detection) or the PREFACE_ACK
// it read (dialer), the stored H2 datagram and the "repeat H2" flag set by
// the reader for the writer (dgestablish.go, dghello.go). WP3b owns its
// layout; the reader and writer (WP3a) use only repeatH2, dupH1 and h2 (M2
// design §A11.5; Revision 1, R1-20).
type dgHandshake struct {
	// repeatH2 (under Conn.mu) is set by the passive reader for a duplicate
	// H1 and cleared by the writer, which writes the stored H2 datagram
	// first and alone in its next round (M2-D19).
	repeatH2 bool

	pre []byte // (I) passive: the 40 PREFACE bytes of the accepted H1
	h2b []byte // (I) passive: the stored H2 rendr bytes, repeated verbatim
	ack []byte // (I) dialer: the 40 PREFACE_ACK bytes the handshake read
}

// dupH1 reports whether rendr bytes (a datagram after its flow header)
// start with the PREFACE this passive carrier accepted: a duplicate H1,
// answered with the stored H2. Always false on a dialer.
func (h *dgHandshake) dupH1(rendr []byte) bool {
	return h.pre != nil && len(rendr) >= wire.PrefaceLen && bytes.Equal(rendr[:wire.PrefaceLen], h.pre)
}

// h2 returns the stored H2 rendr bytes (PREFACE_ACK ‖ RACK{FirstCseq}, or
// ‖ PONG for a probe) that the writer repeats verbatim; nil on a dialer.
func (h *dgHandshake) h2() []byte {
	return h.h2b
}

// verdictMax bounds the repetition of a datagram verdict and of a
// PREFACE-level refusal (M2-D21).
const verdictMax = 2 * time.Second

// dgWriteAndClose is Conn.WriteAndClose on an unstarted datagram Conn (M2
// design §A5.10 "Verdicts", M2-D21): the passive's first REL,
// REL{FirstCseq, t(flags, handle, payload)}, at the next tx fseq, written
// by the closer and then retransmitted on the RTO schedule (a new outer
// frame around the same REL payload) until a RACK covering it arrives or
// min(deadline, now + 2 s); a duplicate H1 meanwhile gets the stored H2
// and the verdict again; then the PacketIO closes through ncClose. The
// death record becomes CauseLocalClose; bounded and abandoned like
// closeWriteOne (V2 last resort). WP3b implements it.
//
// The closer is the Conn's partCloser: its abandonment AbandonWait after
// the verdict's bound closes the PacketIO as the last resort (abandonParts,
// R1-7), which ends a read that ignores its deadline on a transport that
// honours Close.
func (c *Conn) dgWriteAndClose(t wire.Type, flags uint8, handle uint32, payload []byte, deadline time.Time) {
	if !c.setDeath(CauseLocalClose, "closed after a "+t.String()) {
		return
	}
	end := time.Now().Add(verdictMax)
	if deadline.Before(end) {
		end = deadline
	}
	c.mu.Lock()
	cs := c.dg.rel.next
	c.dg.rel.next++
	c.mu.Unlock()
	rp := make([]byte, wire.RelHeadLen+len(payload))
	wire.PutRelHead(rp, &wire.RelHead{Cseq: cs, Type: t, Flags: flags, Handle: handle})
	copy(rp[wire.RelHeadLen:], payload)

	wait := c.tm.AbandonWait
	if d := time.Until(end); d > 0 {
		wait += d
	}
	c.jmu.Lock()
	c.join.running |= partCloser
	c.join.closing = true
	c.join.timer = time.AfterFunc(wait, c.abandonParts)
	c.jmu.Unlock()
	go c.dgVerdict(rp, cs, end)
}

// dgVerdict is the closer of a datagram verdict (dgWriteAndClose): it
// writes the verdict REL, answers a duplicate H1 with the stored H2 and the
// verdict again, resends the verdict at RelRTOInit doubling to RelRTOMax
// until a RACK covering cs arrives or end, then closes the PacketIO
// (closeConn, also on runtime.Goexit inside an embedder call, L51).
func (c *Conn) dgVerdict(rp []byte, cs uint32, end time.Time) {
	defer c.partDone(partCloser)
	defer c.closeConn()
	dg := c.dg
	io := dg.io
	rb, b := hsReadBuf(c.env, io)
	defer rb.Release() // after the last read returned
	hr := io.Headroom()
	scratch := make([]byte, hr, hr+wire.FrameOverhead+len(rp))
	_ = io.SetWriteDeadline(end)
	send := func() bool {
		d := wire.AppendFrame(scratch[:hr], wire.Header{Type: wire.TypeRel, Fseq: c.wr.fseq}, rp)
		c.wr.fseq++
		return c.dgHandshakeWritten(io.WriteDatagram(d)) == nil
	}
	if !send() {
		return
	}
	var p hsPause
	k := 0
	next := time.Now().Add(sched.RTOBackoffWithin(c.tm.RelRTOInit, 0, c.tm.RelRTOMax))
	for {
		now := time.Now()
		if !now.Before(end) {
			return
		}
		if !now.Before(next) {
			k++
			dg.ctr.retransmits.Add(1)
			if !send() {
				return
			}
			next = now.Add(sched.RTOBackoffWithin(c.tm.RelRTOInit, k, c.tm.RelRTOMax))
		}
		rdl := next
		if end.Before(rdl) {
			rdl = end
		}
		_ = io.SetReadDeadline(rdl)
		data, _, ev, err := io.ReadDatagram(b)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			return // closed, or a transport error: the verdict is best effort
		}
		if ev != ReadOK {
			io.Release()
			if !p.dropped(ev, end, nil) {
				return
			}
			continue
		}
		p.reset()
		if wire.IsPreface(data) {
			dup := dg.hs.dupH1(data)
			io.Release()
			if dup {
				// A duplicate H1: the stored H2, then the verdict again.
				dg.ctr.retransmits.Add(1)
				d := append(scratch[:hr], dg.hs.h2b...)
				if c.dgHandshakeWritten(io.WriteDatagram(d)) != nil || !send() {
					return
				}
			}
			continue
		}
		acked := verdictRacked(data, &dg.rwin, cs)
		io.Release()
		if acked {
			return
		}
	}
}

// verdictRacked walks the frames of rendr bytes d through the window w
// and reports whether a RACK in them covers cseq cs.
func verdictRacked(d []byte, w *wire.FseqWindow, cs uint32) bool {
	for len(d) > 0 {
		f, n, err := wire.DecodeFrame(d)
		if err != nil {
			return false
		}
		d = d[n:]
		if w.Accept(f.Fseq) != wire.WindowNew || f.Type != wire.TypeRack {
			continue
		}
		if rk, err := wire.ParseRack(f.Payload); err == nil && !wire.SeqLess(rk.CumAck, cs) {
			return true
		}
	}
	return false
}

// dgHandshakeWritten classifies a handshake or verdict datagram's write:
// written, refused as too large or lost to noise — the datagram is lost,
// a later copy may pass — or any other error (returned: the handshake
// ends).
func (c *Conn) dgHandshakeWritten(err error) error {
	switch {
	case err == nil:
		c.dg.ctr.datagrams.Add(1)
		return nil
	case errors.Is(err, wire.ErrDatagramTooLarge), errors.Is(err, ErrNoise):
		c.dgDropped(1)
		return nil
	}
	return err
}

// ReadHelloDatagram is ReadHello for a datagram carrier (M2-D19; M2 design
// §A5.10): it reads datagrams from io under deadline until one is a complete
// valid H1 — a PREFACE of kind datagram followed by exactly one first frame,
// REL{FirstCseq, OPEN or JOIN} or a bare PING with zero pad, at the
// PREFACE's first fseq — and drops and counts every other datagram without
// creating state (plan:324). ErrMajor and ErrFeature are answered
// PREFACE_ACK(VERSION or FEATURE), the gate's refusal PREFACE_ACK(CAPACITY
// or GOING_AWAY), statelessly and for each duplicate H1 for at most 2 s
// (M2-D21); then io is closed and an error returned. On success it writes
// H2 = PREFACE_ACK(OK) ‖ RACK{FirstCseq} (a probe: PREFACE_ACK(OK) ‖ PONG),
// keeps it for duplicates and returns the unstarted Conn with the Hello
// fields of ReadHello (MetaTooLarge for an OPEN whose metadata exceeds
// maxMeta). Every failure closes io exactly once.
//
// Further contracts of this implementation: the OPEN or JOIN payload is
// handed over as received (a copy; its fields are judged by the admission,
// which answers BAD_REQUEST as for stream carriers); Hello.First is the
// inner frame's header (type, flags, length and handle of the wrapped OPEN
// or JOIN, the outer frame's fseq) or the PING's; the Conn's REL start
// values are R1-3's (send FirstCseq; receive FirstCseq, or FirstCseq − 1
// after a probe's PING), its frame budget and receive limit
// wire.MinFrameBudget until the admission's SetBudget (a probe keeps it),
// and io's receive limit max(len(H1), wire.MinFrameBudget) until then;
// its first PONG was H2p's, so a sessionless carrier has none due; the
// handshake's read buffer is io.ReadSize() bytes of the datagram pool,
// charged to the stage account and released before it returns; when a
// call of io runs runtime.Goexit on the caller's goroutine, io is still
// closed exactly once (L51; the caller's own deferred cleanup releases its
// handshake slot).
func ReadHelloDatagram(env *Env, io PacketIO, deadline time.Time, maxMeta int, gate Gate) (*Hello, error) {
	k := &closeOnce{nc: io} // every close of io goes through k: exactly once (L52)
	returned := false
	var rb *Buf
	defer func() {
		rb.Release()
		if !returned { // runtime.Goexit inside an embedder call (L51)
			k.async(env)
		}
	}()
	var b []byte
	rb, b = hsReadBuf(env, io)
	h, err := readHelloDatagram(env, k, io, b, deadline, maxMeta, gate)
	returned = true
	return h, err
}

// helloH1 is a parsed complete valid H1.
type helloH1 struct {
	pf      wire.Preface
	first   wire.Header // the inner OPEN or JOIN (outer fseq), or the PING
	payload []byte      // aliases the datagram
	ping    wire.Ping
	meta    bool // an OPEN whose metadata exceeds maxMeta
}

// parseH1 validates rendr bytes d as a complete H1 (M2 design §A5.10):
// a PREFACE (whose error alone decides a refusal: ErrMajor and ErrFeature
// come back with ok false and that error) of kind datagram, then exactly
// one frame filling the rest at the PREFACE's first fseq: REL{first cseq,
// OPEN or JOIN} (the wrapper checked by ParseRel) or a PING with zero pad.
func parseH1(env *Env, d []byte, maxMeta int) (h helloH1, ok bool, perr error) {
	if !wire.IsPreface(d) {
		return h, false, nil
	}
	pf, err := wire.ParsePreface(d[:wire.PrefaceLen])
	h.pf = pf // ErrFeature comes with the decoded value (the FEATURE answer echoes its carrier ID)
	if err != nil {
		return h, false, err
	}
	if pf.Kind != wire.KindDatagram {
		return h, false, nil
	}
	rest := d[wire.PrefaceLen:]
	f, n, err := wire.DecodeFrame(rest)
	if err != nil || n != len(rest) || f.Fseq != env.Presets.fseqFrom(d[:wire.PrefaceLen]) {
		return h, false, nil
	}
	switch f.Type {
	case wire.TypeRel:
		rh, inner, err := wire.ParseRel(f.Payload)
		if err != nil || rh.Cseq != env.Presets.firstCseq() || (rh.Type != wire.TypeOpen && rh.Type != wire.TypeJoin) {
			return h, false, nil
		}
		h.first = wire.Header{Type: rh.Type, Flags: rh.Flags, Len: uint32(len(inner)), Fseq: f.Fseq, Handle: rh.Handle}
		if rh.Type == wire.TypeOpen && len(inner)-wire.OpenFixedLen > min(max(maxMeta, 0), wire.MaxMetadata) {
			h.meta = true // answered without handing the metadata over
			return h, true, nil
		}
		h.payload = inner
	case wire.TypePing:
		p, err := wire.ParsePing(f.Payload)
		if err != nil || p.Pad != 0 {
			return h, false, nil
		}
		h.first, h.ping = f.Header, p
	default:
		return h, false, nil
	}
	return h, true, nil
}

// readHelloDatagram is ReadHelloDatagram without the Goexit guard: every
// return path closes k's transport unless a Hello owns it.
func readHelloDatagram(env *Env, k *closeOnce, io PacketIO, b []byte, deadline time.Time, maxMeta int, gate Gate) (*Hello, error) {
	fail := func(err error) (*Hello, error) {
		k.async(env)
		return nil, err
	}
	if err := io.SetDeadline(deadline); err != nil {
		var pe *panicError
		if errors.As(err, &pe) {
			return fail(err)
		}
	}
	var p hsPause
	for {
		data, _, ev, err := io.ReadDatagram(b)
		if err != nil {
			return fail(fmt.Errorf("rendr: datagram handshake: reading H1: %w", err))
		}
		if ev != ReadOK {
			io.Release()
			dgEnvDropped(env)
			if !p.dropped(ev, deadline, nil) {
				return fail(fmt.Errorf("rendr: datagram handshake: %w", os.ErrDeadlineExceeded))
			}
			continue
		}
		p.reset()
		h, ok, perr := parseH1(env, data, maxMeta)
		switch {
		case errors.Is(perr, wire.ErrMajor):
			// Another major: the carrier ID's place is the only echo we can give.
			id := binary.BigEndian.Uint32(data[32:36])
			return dgRefuse(env, k, io, b, deadline, wire.PrefaceVersion, id, data[:wire.PrefaceLen], perr)
		case errors.Is(perr, wire.ErrFeature):
			return dgRefuse(env, k, io, b, deadline, wire.PrefaceFeature, h.pf.CarrierID, data[:wire.PrefaceLen], perr)
		case !ok:
			io.Release()
			dgEnvDropped(env) // no PREFACE_ACK for garbage, no state (plan:324)
			continue
		}
		status := wire.PrefaceOK
		if gate != nil {
			status = gate(&h.pf)
		}
		if status != wire.PrefaceOK {
			return dgRefuse(env, k, io, b, deadline, status, h.pf.CarrierID, data[:wire.PrefaceLen],
				fmt.Errorf("PREFACE_ACK %s", prefaceStatusName(status)))
		}
		hello, err := acceptH1(env, io, data, &h)
		io.Release()
		if err != nil {
			return fail(err)
		}
		if err := io.SetDeadline(time.Time{}); err != nil {
			var pe *panicError
			if errors.As(err, &pe) {
				return fail(err)
			}
		}
		return hello, nil
	}
}

// acceptH1 answers the complete valid H1 d with H2 and builds the unstarted
// passive Conn (R1-3's start values, the window past the H1 frame, the
// stored PREFACE and H2).
func acceptH1(env *Env, io PacketIO, d []byte, h *helloH1) (*Hello, error) {
	probe := h.first.Type == wire.TypePing
	var ab [wire.PrefaceLen]byte
	wire.PutPrefaceAck(ab[:], &wire.PrefaceAck{Minor: wire.Minor, Status: wire.PrefaceOK, Instance: env.Local, CarrierID: h.pf.CarrierID})
	afirst := env.Presets.fseqFrom(ab[:])
	h2 := append(make([]byte, 0, wire.PrefaceLen+wire.FrameOverhead+wire.PingFixedLen), ab[:]...)
	fcs := env.Presets.firstCseq()
	if probe {
		var pp [wire.PingFixedLen]byte
		wire.PutPing(pp[:], &h.ping) // the PONG echoes the PING (pad 0)
		h2 = wire.AppendFrame(h2, wire.Header{Type: wire.TypePong, Fseq: afirst}, pp[:])
	} else {
		var rk [wire.RackLen]byte
		wire.PutRack(rk[:], &wire.Rack{CumAck: fcs})
		h2 = wire.AppendFrame(h2, wire.Header{Type: wire.TypeRack, Fseq: afirst}, rk[:])
	}
	c := newDatagramConn(env, io, h.pf.CarrierID, h.pf.Instance, -1, "", false)
	dg := c.dg
	dg.hs.pre = bytes.Clone(d[:wire.PrefaceLen])
	dg.hs.h2b = h2
	dg.rwin.Init(h.first.Fseq)
	dg.rwin.Accept(h.first.Fseq)
	dg.rel.initSend(fcs) // our first REL is H3 (or a verdict)
	if probe {
		dg.rel.initRecv(fcs - 1) // H1p carried no REL (R1-3)
		c.SetBudget(wire.MinFrameBudget)
	} else {
		dg.rel.initRecv(fcs) // H1's REL was dispatched as the Hello
		dg.recvLimit = wire.MinFrameBudget
		dg.budget.Store(wire.MinFrameBudget) // until the admission's SetBudget
		// The transport reads no more than a duplicate H1 until then: a
		// verdict closer's buffer (dgVerdict) stays a small class even on a
		// 64 KiB transport, and still recognises the duplicate.
		io.SetLimit(max(len(d), wire.MinFrameBudget))
	}
	c.wr.fseq = afirst + 1
	c.rd.fseq = h.first.Fseq + 1

	hr := io.Headroom()
	w := append(make([]byte, hr, hr+len(h2)), h2...)
	if err := c.dgHandshakeWritten(io.WriteDatagram(w)); err != nil {
		return nil, fmt.Errorf("rendr: datagram handshake: writing H2: %w", err)
	}
	hello := &Hello{Conn: c, Preface: h.pf, First: h.first, Ping: h.ping, MetaTooLarge: h.meta}
	if h.payload != nil {
		hello.Payload = bytes.Clone(h.payload)
	}
	return hello, nil
}

// dgRefuse writes the PREFACE-level refusal PREFACE_ACK(status) alone and
// writes it again, unchanged, for every later datagram that starts with the
// refused PREFACE bytes pre, until min(deadline, now + 2 s) (M2-D21); then
// io closes (through k) and errHelloRefused wrapping cause is returned. It
// keeps no state but the 40 bytes, on the handshake goroutine and in its
// slot (L48); a read that ignores its deadline is ended by the slot's
// eviction, which closes io.
func dgRefuse(env *Env, k *closeOnce, io PacketIO, b []byte, deadline time.Time, status wire.PrefaceStatus, id uint32, pre []byte, cause error) (*Hello, error) {
	var refused [wire.PrefaceLen]byte
	copy(refused[:], pre)
	io.Release()
	hr := io.Headroom()
	w := make([]byte, hr+wire.PrefaceLen)
	wire.PutPrefaceAck(w[hr:], &wire.PrefaceAck{Minor: wire.Minor, Status: status, Instance: env.Local, CarrierID: id})
	ans := bytes.Clone(w[hr:])
	end := time.Now().Add(verdictMax)
	if deadline.Before(end) {
		end = deadline
	}
	write := func() bool {
		copy(w[hr:], ans) // WriteDatagram may have filled the headroom
		err := io.WriteDatagram(w)
		return err == nil || errors.Is(err, ErrNoise) || errors.Is(err, wire.ErrDatagramTooLarge)
	}
	if write() {
		_ = io.SetReadDeadline(end)
		var p hsPause
		for {
			data, _, ev, err := io.ReadDatagram(b)
			if err != nil {
				break
			}
			if ev != ReadOK {
				io.Release()
				if !p.dropped(ev, end, nil) {
					break
				}
				continue
			}
			p.reset()
			dup := len(data) >= wire.PrefaceLen && bytes.Equal(data[:wire.PrefaceLen], refused[:])
			io.Release()
			if dup && !write() {
				break
			}
		}
	}
	k.async(env)
	return nil, fmt.Errorf("%w: %w", errHelloRefused, cause)
}

// dgEnvDropped counts one datagram a handshake dropped in the Runtime-wide
// counters.
func dgEnvDropped(env *Env) {
	if s := env.Dgram; s != nil {
		s.Dropped.Add(1)
	}
}

// hsReadBuf returns a handshake's read buffer for io: io.ReadSize() bytes
// of the datagram pool charged to the stage account (nil for a transport
// that hands out its own buffers); a component Env without pools gets a
// plain slice.
func hsReadBuf(env *Env, io PacketIO) (*Buf, []byte) {
	n := io.ReadSize()
	if n <= 0 {
		return nil, nil
	}
	pool := env.DBufs
	if pool == nil {
		pool = env.Bufs
	}
	if pool == nil {
		return nil, make([]byte, n)
	}
	rb := pool.Get(n, env.stageBudget())
	return rb, rb.B
}

// hsPause is the back-off of a handshake's reads (M2-D15, R1-27): a
// transient error, and every read after spinIdle consecutive reads that
// handed nothing over, waits 5 ms doubling to 100 ms.
type hsPause struct {
	idle    int
	backoff time.Duration
}

func (p *hsPause) reset() { p.idle, p.backoff = 0, 0 }

// dropped records a read of event ev that handed nothing over and sleeps
// the back-off when one is due, at most until end (zero: unbounded) and
// until abort closes; it reports false when end passed or abort closed.
func (p *hsPause) dropped(ev ReadEvent, end time.Time, abort <-chan struct{}) bool {
	p.idle++
	if ev != ReadNoise && p.idle < spinIdle {
		return true
	}
	p.backoff = min(max(2*p.backoff, noiseMin), noiseMax)
	d := p.backoff
	if !end.IsZero() {
		left := time.Until(end)
		if left <= 0 {
			return false
		}
		d = min(d, left)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-abort:
		return false
	}
}
