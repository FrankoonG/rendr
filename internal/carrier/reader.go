package carrier

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// reader is the reader goroutine's own state (design §4.9).
type reader struct {
	fseq  uint32 // next expected rx fseq (strict +1, wrapping: L14, L43)
	stage *Buf   // one 16 KiB-class Buf, charged to the stage account for the reader's life (Env.stageBudget, B2)
	// big is the Buf a big DATA payload is being read into (nil otherwise):
	// if an embedder Read calls runtime.Goexit while filling it, the
	// reader's exit releases it with the stage (abandoned-call rule, §4.1).
	big  *Buf
	r, w int // stage.B[r:w] holds bytes read but not yet consumed
	// pending is an error that a Read returned together with bytes (L01):
	// the bytes are processed first, the error ends the reader when more
	// bytes are needed.
	pending error
}

// releaseBig releases the big-DATA buffer of a frame that is not handed over.
func (rd *reader) releaseBig() {
	if rd.big != nil {
		rd.big.Release()
		rd.big = nil
	}
}

// errAfterClose: the peer sent a frame after its CLOSE (no frame follows
// a CLOSE).
var errAfterClose = errors.New("frame after the peer's CLOSE")

// readLoop is the carrier's reader goroutine: it reads whole frames into
// reader-owned memory, verifies fseq and CRC32C, and dispatches them; it
// never blocks on a write (L08). It ends at the first transport error,
// protocol violation or death, and at the end of a planned retirement.
func (c *Conn) readLoop() {
	rd := &c.rd
	normal := false
	defer func() {
		if !normal { // runtime.Goexit inside an embedder Read (L51)
			c.killCarrier(CauseTransportError, "conn Read called runtime.Goexit")
		}
		// The embedder call returned or unwound: only this goroutine pools
		// its buffers (§4.1), so both accounts return to zero (R7).
		rd.releaseBig()
		if rd.stage != nil {
			rd.stage.Release()
			rd.stage = nil
		}
		c.partDone(partReader)
	}()
	if rd.stage == nil {
		rd.stage = c.env.Bufs.Get(BigData, c.env.stageBudget())
	}
	for c.readFrame(rd) {
	}
	normal = true
}

// fill makes at least need bytes (need ≤ len(stage)) available in the
// stage, reading from the conn with count checks (L42): a count outside
// [0, len] or (0, nil) is a transport error; bytes that come with an error
// are kept and the error is reported only when more bytes are needed (L01).
func (c *Conn) fill(rd *reader, need int) error {
	sb := rd.stage.B
	if rd.r == rd.w {
		rd.r, rd.w = 0, 0
	}
	for rd.w-rd.r < need {
		if rd.pending != nil {
			return rd.pending
		}
		if len(sb)-rd.r < need {
			rd.w = copy(sb, sb[rd.r:rd.w])
			rd.r = 0
		}
		n, err := callRead(c.nc, sb[rd.w:])
		if n < 0 || n > len(sb)-rd.w {
			return &countError{"Read", n, len(sb) - rd.w}
		}
		rd.w += n
		if err != nil {
			if n == 0 {
				return err
			}
			rd.pending = err
			continue
		}
		if n == 0 {
			return errZeroRead
		}
	}
	return nil
}

// readFailed ends the reader on a read error: after either side's CLOSE it
// completes the planned retirement; otherwise the carrier died
// (transport_error). A carrier that is already dead is left alone.
func (c *Conn) readFailed(err error) {
	if c.death.Load() != nil {
		return
	}
	if c.closeSent.Load() || c.peerClosed.Load() {
		c.finishRetire("retired: read ended after CLOSE")
		return
	}
	c.killCarrier(CauseTransportError, "read: "+err.Error())
}

// violation kills the carrier with protocol_violation (L43, invariant 6:
// only this carrier dies).
func (c *Conn) violation(format string, a ...any) {
	c.killCarrier(CauseProtocolViolation, fmt.Sprintf(format, a...))
}

// readFrame reads, verifies and dispatches one frame. It reports whether the
// reader continues.
func (c *Conn) readFrame(rd *reader) bool {
	if err := c.fill(rd, wire.HeaderLen); err != nil {
		c.readFailed(err)
		return false
	}
	h, err := wire.ParseHeader(rd.stage.B[rd.r:rd.w]) // length, type, flags, handle, bounds (§5.2)
	if err != nil {
		c.violation("header: %v", err)
		return false
	}
	if h.Fseq != rd.fseq {
		c.violation("fseq %d, want %d", h.Fseq, rd.fseq)
		return false
	}
	if c.peerClosed.Load() {
		c.violation("%v: %v", h.Type, errAfterClose)
		return false
	}
	if h.Type == wire.TypeRel || h.Type == wire.TypeRack {
		// Datagram-carrier control (M2 §A3.6): a violation on every stream
		// carrier, before the session check (probe and sessionless carriers
		// have no endpoint) and the size check (never skipped as large).
		c.violation("%v on a stream carrier", h.Type)
		return false
	}
	// v is the view a session frame is for (route: on a one-view trunk a
	// compare with view 1's handle); nil for carrier-level and extension
	// frames.
	var v *Conn
	if !h.Type.Extension() && !h.Type.CarrierLevel() {
		if c.mux {
			// A MUX trunk: the frame's handle and the view's state decide
			// (§A3.3, §A5.4; mux.go).
			act, mv, why := c.classify(h.Type, h.Handle)
			switch act {
			case actIllegal:
				c.violation("%v for handle %d: %s", h.Type, h.Handle, why)
				return false
			case actDispatch:
				v = mv
			default:
				return c.readMux(rd, h, act, mv)
			}
		} else {
			v = c.route(h.Handle)
		}
		switch {
		case v == nil:
			c.violation("%v for handle %d: no such view", h.Type, h.Handle)
			return false
		case v.ep == nil:
			c.violation("%v on a carrier without a session", h.Type)
			return false
		case h.Type == wire.TypeOpen || h.Type == wire.TypeOpenAck || h.Type == wire.TypeJoin || h.Type == wire.TypeJoinAck:
			c.violation("%v after establishment", h.Type)
			return false
		case h.Type == wire.TypeData && int(h.Len)-wire.DataPrefixLen >= BigData:
			return c.readBigData(rd, h, v)
		case h.Type == wire.TypeDgram && v.pep != nil && int(h.Len)-wire.DgramPrefixLen >= BigData:
			// A packet session's DGRAM of 16 KiB or more is read by reference
			// like big DATA (M2 §A5.3; integration 1, D1: this replaces the
			// readStreamed guard for packet sessions only).
			return c.readBigData(rd, h, v)
		}
	}
	total := wire.HeaderLen + int(h.Len) + wire.TrailerLen
	if total > len(rd.stage.B) {
		return c.readStreamed(rd, h)
	}
	if err := c.fill(rd, total); err != nil {
		c.readFailed(err)
		return false
	}
	f := rd.stage.B[rd.r : rd.r+total]
	body := f[:wire.HeaderLen+int(h.Len)]
	if wire.CRC(body) != wire.Trailer(f[len(body):]) {
		c.violation("%v: crc mismatch", h.Type)
		return false
	}
	rd.r += total
	rd.fseq++
	now := c.frameArrived()
	return c.dispatch(v, h, body[wire.HeaderLen:], now)
}

// frameArrived records the arrival of a verified frame and returns now.
func (c *Conn) frameArrived() time.Time {
	now := time.Now()
	c.lastRx.Store(max(int64(now.Sub(c.base)), 1))
	return now
}

// dataArrived accounts n DATA payload bytes that arrived at now (also in
// the self-load volume of a dialer session carrier's Gauge, §8.2); the
// first DATA after a PING wakes the writer, whose PING cadence becomes
// PingBusy (P12).
func (c *Conn) dataArrived(n int, now time.Time) {
	c.rxBytes.Add(uint64(n))
	if g := c.opts.Gauge; g != nil {
		g.AddRx(n, now)
	}
	if !c.rxData.Load() && c.rxData.CompareAndSwap(false, true) {
		c.wakeWriter()
	}
}

// dispatch handles one verified frame whose payload p lives in the stage
// (valid until the next read). v is the view of a session frame (readFrame
// routed it and checked its endpoint); nil for carrier-level and extension
// frames. The DATA and DGRAM accounting (dataArrived) stays trunk-wide
// (M3-D11).
func (c *Conn) dispatch(v *Conn, h wire.Header, p []byte, now time.Time) bool {
	switch h.Type {
	case wire.TypePing:
		ping, err := wire.ParsePing(p)
		if err != nil {
			c.violation("PING: %v", err)
			return false
		}
		c.onPing(h.Flags&wire.FlagPingBusy != 0, &ping, now)
	case wire.TypePong:
		pong, err := wire.ParsePing(p)
		if err != nil {
			c.violation("PONG: %v", err)
			return false
		}
		c.pong(&pong, now)
	case wire.TypeClose:
		if _, err := wire.ParseClose(p); err != nil {
			c.violation("CLOSE: %v", err)
			return false
		}
		c.peerClosed.Store(true)
		c.ringViews()
		if c.closeSent.Load() {
			c.finishRetire("retired: CLOSE exchange complete")
			return false
		}
		if c.view1.ep == nil {
			// A probe or sessionless carrier has no session to drain: it
			// answers the peer's CLOSE with its own at once (its owner may
			// still call Retire; it is idempotent).
			c.Retire(wire.CloseRetire)
		}
	case wire.TypeGoAway:
		if _, err := wire.ParseGoAway(p); err != nil {
			c.violation("GOAWAY: %v", err)
			return false
		}
		c.peerGoAway.Store(true)
		c.ringViews()
	case wire.TypeDetach:
		// A MUX trunk's end of one handle (M3-D6; detach.go); a
		// violation on a dedicated carrier.
		if why, _ := c.onDetach(p); why != "" {
			c.violation("%s", why)
			return false
		}
	case wire.TypeData:
		off, err := wire.ParseDataOffset(p)
		if err != nil {
			c.violation("DATA: %v", err)
			return false
		}
		data := p[wire.DataPrefixLen:]
		c.dataArrived(len(data), now)
		if !v.enter() {
			return true // the view's Done closed after our DETACH: dropped (M3-D13)
		}
		v.countRx(len(data))
		err = v.ep.Data(v, off, data, nil)
		v.exit()
		if err != nil {
			c.violation("DATA: %v", err)
			return false
		}
	case wire.TypeDgram:
		// A packet session's datagram on a stream carrier: its bytes count
		// as DATA there (busy cadence, byte clock, M2-D26).
		if v.pep == nil {
			c.violation("DGRAM on a stream session")
			return false
		}
		seq, data, err := wire.ParseDgram(p)
		if err != nil {
			c.violation("DGRAM: %v", err)
			return false
		}
		c.dataArrived(len(data), now)
		if !v.enter() {
			return true
		}
		v.countRx(len(data))
		err = v.pep.Datagram(v, seq, data, nil)
		v.exit()
		if err != nil {
			c.violation("DGRAM: %v", err)
			return false
		}
	default:
		if h.Type.Extension() {
			return true // CRC-checked and skipped on every carrier (§5.2)
		}
		if !v.enter() {
			return true
		}
		err := v.ep.Control(v, h, p)
		v.exit()
		if err != nil {
			c.violation("%v: %v", h.Type, err)
			return false
		}
	}
	return true
}

// readMux reads, verifies and handles a session frame of a MUX trunk that
// is not dispatched to a view's endpoint (§A3.3): an admitted OPEN or JOIN
// for a new handle (admit), a dialer view's response (onResponse), or a
// legal frame that is not delivered. A frame beyond the stage (an OPEN
// with large metadata, a big DATA of a view whose Done closed) is read
// into a Buf of its own.
func (c *Conn) readMux(rd *reader, h wire.Header, act muxAct, v *Conn) bool {
	total := wire.HeaderLen + int(h.Len) + wire.TrailerLen
	var body []byte
	var buf *Buf
	if total <= len(rd.stage.B) {
		if err := c.fill(rd, total); err != nil {
			c.readFailed(err)
			return false
		}
		f := rd.stage.B[rd.r : rd.r+total]
		body = f[:wire.HeaderLen+int(h.Len)]
		if wire.CRC(body) != wire.Trailer(f[len(body):]) {
			c.violation("%v: crc mismatch", h.Type)
			return false
		}
		rd.r += total
	} else {
		buf = c.env.Bufs.Get(total, c.env.Budget)
		rd.big = buf
		got := copy(buf.B[:total], rd.stage.B[rd.r:rd.w])
		rd.r += got
		for got < total {
			if rd.pending != nil {
				rd.releaseBig()
				c.readFailed(rd.pending)
				return false
			}
			rd.r, rd.w = 0, 0
			m, err := callRead(c.nc, buf.B[got:total])
			if m < 0 || m > total-got {
				rd.releaseBig()
				c.readFailed(&countError{"Read", m, total - got})
				return false
			}
			got += m
			if err != nil {
				if got < total {
					rd.releaseBig()
					c.readFailed(err)
					return false
				}
				rd.pending = err
			} else if m == 0 {
				rd.releaseBig()
				c.readFailed(errZeroRead)
				return false
			}
		}
		body = buf.B[:wire.HeaderLen+int(h.Len)]
		if wire.CRC(body) != wire.Trailer(buf.B[len(body):total]) {
			rd.releaseBig()
			c.violation("%v: crc mismatch", h.Type)
			return false
		}
	}
	rd.fseq++
	now := c.frameArrived()
	p := body[wire.HeaderLen:]
	ok := true
	switch act {
	case actAdmit:
		c.admit(h.Handle, h, p)
		ok = c.death.Load() == nil
	case actResponse:
		if err := c.onResponse(v, h, p); err != nil {
			c.violation("%v: %v", h.Type, err)
			ok = false
		}
	}
	if h.Type == wire.TypeData || h.Type == wire.TypeDgram {
		if n := int(h.Len) - wire.DataPrefixLen; n > 0 {
			c.dataArrived(n, now)
		}
	}
	if buf != nil {
		rd.releaseBig()
	}
	return ok
}

// pong applies a PONG outside Conn.mu's callers: the estimator update under
// the lock, then the capacity wake (C5) and the probe observer.
func (c *Conn) pong(p *wire.Ping, now time.Time) {
	c.mu.Lock()
	matched, rtt, wake := c.onPongLocked(p, now)
	if c.dg != nil {
		c.dgPongProbeLocked(p)
	}
	c.mu.Unlock()
	if wake {
		c.wakeWriter()
	}
	if matched {
		if o := c.opts.Observer; o != nil {
			o.Pong(c, p.ID, rtt, now)
		}
	}
}

// readBigData reads a DATA frame whose payload is at least BigData bytes
// straight into its own pooled Buf and hands it to the endpoint by
// reference (design §4.9) — v's endpoint, the view readFrame routed the
// frame to; a packet session's DGRAM of that size the same
// way (DATA and DGRAM share the 8-byte prefix; only the endpoint call
// differs, M2 §A5.3). The read bound is n + LookAhead (the trailer
// included, C15), which Get(n + LookAhead) always covers; at most 21 bytes
// of the next frame read along are moved back to the stage. A partial frame
// is never handed over (L42).
func (c *Conn) readBigData(rd *reader, h wire.Header, v *Conn) bool {
	n := int(h.Len) - wire.DataPrefixLen
	if err := c.fill(rd, wire.DataHeadLen); err != nil {
		c.readFailed(err)
		return false
	}
	sb := rd.stage.B
	head := sb[rd.r : rd.r+wire.DataHeadLen]
	off := binary.BigEndian.Uint64(head[wire.HeaderLen:])
	dgram := h.Type == wire.TypeDgram
	if !dgram {
		if _, err := wire.DataEnd(off, n); err != nil {
			c.violation("DATA: %v", err)
			return false
		}
	}
	crc := wire.CRC(head) // before the stage is reused for the look-ahead
	rd.r += wire.DataHeadLen
	buf := c.env.Bufs.Get(n+LookAhead, c.env.Budget)
	rd.big = buf
	want := n + wire.TrailerLen
	got := copy(buf.B[:want], sb[rd.r:rd.w])
	rd.r += got
	for got < want {
		if rd.pending != nil {
			rd.releaseBig()
			c.readFailed(rd.pending)
			return false
		}
		rd.r, rd.w = 0, 0 // the stage is empty
		m, err := callRead(c.nc, buf.B[got:n+LookAhead])
		if m < 0 || m > n+LookAhead-got {
			rd.releaseBig()
			c.readFailed(&countError{"Read", m, n + LookAhead - got})
			return false
		}
		got += m
		if err != nil {
			if got < want {
				rd.releaseBig()
				c.readFailed(err)
				return false
			}
			rd.pending = err
		} else if m == 0 {
			rd.releaseBig()
			c.readFailed(errZeroRead)
			return false
		}
	}
	if got > want {
		rd.w = copy(sb, buf.B[want:got]) // the next frame's head (≤ 21 bytes)
		rd.r = 0
	}
	crc = wire.CRCUpdate(crc, buf.B[:n])
	if crc != wire.Trailer(buf.B[n:want]) {
		rd.releaseBig()
		c.violation("%v: crc mismatch", h.Type)
		return false
	}
	rd.fseq++
	c.dataArrived(n, c.frameArrived())
	rd.big = nil // buf's reference moves to the endpoint
	if !v.enter() {
		buf.Release() // the view's Done closed after our DETACH: dropped (M3-D13)
		return true
	}
	v.countRx(n)
	var err error
	if dgram {
		err = v.pep.Datagram(v, off, buf.B[:n], buf)
	} else {
		err = v.ep.Data(v, off, buf.B[:n], buf)
	}
	v.exit()
	if err != nil {
		c.violation("%v: %v", h.Type, err)
		return false
	}
	return true
}

// readStreamed reads a frame larger than the stage that is not big DATA (an
// extension, or a PING or PONG with a large pad) through the stage with a
// running CRC: an extension is discarded; of a PING or PONG only the fixed
// part is kept and every pad byte must be zero (wire.CheckPad).
func (c *Conn) readStreamed(rd *reader, h wire.Header) bool {
	if !h.Type.Extension() && h.Type != wire.TypePing && h.Type != wire.TypePong {
		// A core frame larger than the stage that is not big DATA (M2: a
		// DGRAM of 16 KiB or more until the packet path reads it by
		// reference) is never skipped as if it were an extension.
		c.violation("%v of %d bytes on a stream carrier", h.Type, h.Len)
		return false
	}
	sb := rd.stage.B
	crc := wire.CRC(sb[rd.r : rd.r+wire.HeaderLen])
	rd.r += wire.HeaderLen
	isPing := h.Type == wire.TypePing || h.Type == wire.TypePong
	var fixed [wire.PingFixedLen]byte
	have := 0
	for remain := int(h.Len); remain > 0; {
		if rd.r == rd.w {
			if err := c.fill(rd, 1); err != nil {
				c.readFailed(err)
				return false
			}
		}
		k := min(remain, rd.w-rd.r)
		chunk := sb[rd.r : rd.r+k]
		crc = wire.CRCUpdate(crc, chunk)
		if isPing {
			if have < len(fixed) {
				m := copy(fixed[have:], chunk)
				have += m
				chunk = chunk[m:]
			}
			if err := wire.CheckPad(chunk); err != nil {
				c.violation("%v pad: %v", h.Type, err)
				return false
			}
		}
		rd.r += k
		remain -= k
	}
	if err := c.fill(rd, wire.TrailerLen); err != nil {
		c.readFailed(err)
		return false
	}
	if crc != wire.Trailer(sb[rd.r:rd.r+wire.TrailerLen]) {
		c.violation("%v: crc mismatch", h.Type)
		return false
	}
	rd.r += wire.TrailerLen
	rd.fseq++
	now := c.frameArrived()
	if !isPing {
		return true // an extension: skipped (§5.2)
	}
	p, err := wire.ParsePing(fixed[:])
	if err != nil {
		c.violation("%v: %v", h.Type, err)
		return false
	}
	p.Pad = int(h.Len) - wire.PingFixedLen
	if h.Type == wire.TypePing {
		c.onPing(h.Flags&wire.FlagPingBusy != 0, &p, now)
	} else {
		c.pong(&p, now)
	}
	return true
}
