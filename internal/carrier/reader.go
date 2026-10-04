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
	stage *Buf   // one 16 KiB-class Buf, force-charged to the Budget for the reader's life (D29)
	r, w  int    // stage.B[r:w] holds bytes read but not yet consumed
	// pending is an error that a Read returned together with bytes (L01):
	// the bytes are processed first, the error ends the reader when more
	// bytes are needed.
	pending error
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
			c.Kill(CauseTransportError, "conn Read called runtime.Goexit")
		}
		if rd.stage != nil {
			rd.stage.Release() // the embedder call returned: only this goroutine pools its buffers (§4.1)
			rd.stage = nil
		}
		c.partDone(partReader)
	}()
	if rd.stage == nil {
		rd.stage = c.env.Bufs.Get(BigData, c.env.Budget)
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
	c.Kill(CauseTransportError, "read: "+err.Error())
}

// violation kills the carrier with protocol_violation (L43, invariant 6:
// only this carrier dies).
func (c *Conn) violation(format string, a ...any) {
	c.Kill(CauseProtocolViolation, fmt.Sprintf(format, a...))
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
	if !h.Type.Extension() && !h.Type.CarrierLevel() {
		switch {
		case c.ep == nil:
			c.violation("%v on a carrier without a session", h.Type)
			return false
		case h.Type == wire.TypeOpen || h.Type == wire.TypeOpenAck || h.Type == wire.TypeJoin || h.Type == wire.TypeJoinAck:
			c.violation("%v after establishment", h.Type)
			return false
		case h.Type == wire.TypeData && int(h.Len)-wire.DataPrefixLen >= BigData:
			return c.readBigData(rd, h)
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
	return c.dispatch(h, body[wire.HeaderLen:], now)
}

// frameArrived records the arrival of a verified frame and returns now.
func (c *Conn) frameArrived() time.Time {
	now := time.Now()
	c.lastRx.Store(max(int64(now.Sub(c.base)), 1))
	return now
}

// dataArrived accounts n DATA payload bytes; the first DATA after a PING
// wakes the writer, whose PING cadence becomes PingBusy (P12).
func (c *Conn) dataArrived(n int) {
	c.rxBytes.Add(uint64(n))
	if !c.rxData.Load() && c.rxData.CompareAndSwap(false, true) {
		c.Wake()
	}
}

// dispatch handles one verified frame whose payload p lives in the stage
// (valid until the next read).
func (c *Conn) dispatch(h wire.Header, p []byte, now time.Time) bool {
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
		c.ring()
		if c.closeSent.Load() {
			c.finishRetire("retired: CLOSE exchange complete")
			return false
		}
		if c.ep == nil {
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
		c.ring()
	case wire.TypeData:
		off, err := wire.ParseDataOffset(p)
		if err != nil {
			c.violation("DATA: %v", err)
			return false
		}
		data := p[wire.DataPrefixLen:]
		c.dataArrived(len(data))
		if err := c.ep.Data(c, off, data, nil); err != nil {
			c.violation("DATA: %v", err)
			return false
		}
	default:
		if h.Type.Extension() {
			return true // CRC-checked and skipped on every carrier (§5.2)
		}
		if err := c.ep.Control(c, h, p); err != nil {
			c.violation("%v: %v", h.Type, err)
			return false
		}
	}
	return true
}

// pong applies a PONG outside Conn.mu's callers: the estimator update under
// the lock, then the capacity wake (C5) and the probe observer.
func (c *Conn) pong(p *wire.Ping, now time.Time) {
	c.mu.Lock()
	matched, rtt, wake := c.onPongLocked(p, now)
	c.mu.Unlock()
	if wake {
		c.Wake()
	}
	if matched {
		if o := c.opts.Observer; o != nil {
			o.Pong(c, p.ID, rtt, now)
		}
	}
}

// readBigData reads a DATA frame whose payload is at least BigData bytes
// straight into its own pooled Buf and hands it to the endpoint by
// reference (design §4.9). The read bound is n + LookAhead (the trailer
// included, C15), which Get(n + LookAhead) always covers; at most 21 bytes
// of the next frame read along are moved back to the stage. A partial frame
// is never handed over (L42).
func (c *Conn) readBigData(rd *reader, h wire.Header) bool {
	n := int(h.Len) - wire.DataPrefixLen
	if err := c.fill(rd, wire.DataHeadLen); err != nil {
		c.readFailed(err)
		return false
	}
	sb := rd.stage.B
	head := sb[rd.r : rd.r+wire.DataHeadLen]
	off := binary.BigEndian.Uint64(head[wire.HeaderLen:])
	if _, err := wire.DataEnd(off, n); err != nil {
		c.violation("DATA: %v", err)
		return false
	}
	crc := wire.CRC(head) // before the stage is reused for the look-ahead
	rd.r += wire.DataHeadLen
	buf := c.env.Bufs.Get(n+LookAhead, c.env.Budget)
	want := n + wire.TrailerLen
	got := copy(buf.B[:want], sb[rd.r:rd.w])
	rd.r += got
	for got < want {
		if rd.pending != nil {
			buf.Release()
			c.readFailed(rd.pending)
			return false
		}
		rd.r, rd.w = 0, 0 // the stage is empty
		m, err := callRead(c.nc, buf.B[got:n+LookAhead])
		if m < 0 || m > n+LookAhead-got {
			buf.Release()
			c.readFailed(&countError{"Read", m, n + LookAhead - got})
			return false
		}
		got += m
		if err != nil {
			if got < want {
				buf.Release()
				c.readFailed(err)
				return false
			}
			rd.pending = err
		} else if m == 0 {
			buf.Release()
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
		buf.Release()
		c.violation("DATA: crc mismatch")
		return false
	}
	rd.fseq++
	c.frameArrived()
	c.dataArrived(n)
	if err := c.ep.Data(c, off, buf.B[:n], buf); err != nil { // buf's reference moved to the endpoint
		c.violation("DATA: %v", err)
		return false
	}
	return true
}

// readStreamed reads a frame larger than the stage that is not big DATA (an
// extension, or a PING or PONG with a large pad) through the stage with a
// running CRC: an extension is discarded; of a PING or PONG only the fixed
// part is kept and every pad byte must be zero (wire.CheckPad).
func (c *Conn) readStreamed(rd *reader, h wire.Header) bool {
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
