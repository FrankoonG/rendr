package carrier

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// The dialer's datagram handshake (M2-D19, M2-D20; M2 design §A5.10 and
// Revision 1, R1-1, R1-3, R1-14): Establish's branch for a datagram
// factory.

// Errors of the datagram handshake.
var (
	errNoDialPacket = errors.New("rendr/carrier: datagram factory without DialPacket")
	errH1TooLarge   = errors.New("rendr/carrier: the first datagram exceeds the carrier's frame budget")
)

// dgDial is one datagram dial attempt (establishDatagram).
type dgDial struct {
	ctx    context.Context
	env    *Env
	tm     Timing
	f      Factory
	id     uint32
	t      wire.Type
	pingID uint32
	salt   uint64
	fcs    uint32 // the first REL cseq of each direction

	pc       net.PacketConn // the factory's conn until io owns it
	io       PacketIO
	k        *closeOnce // closes io once on every failure path
	deadline time.Time
	tx       uint32 // the next tx fseq
	retx     uint64 // H1 copies after the first
	wrote    bool   // a copy of H1 was written: a withdrawal sends the RST

	// The guard of the attempt (hsGuard's rules for a datagram transport):
	// abort unblocks the handshake's read when the attempt's context ends;
	// a read that ignores its deadline is ended by closing io drainMax
	// later.
	mu       sync.Mutex
	finished bool // the guarded phase ended: a later abort does nothing
	aborted  bool
	left     chan struct{} // closed by finish
	abortCh  chan struct{} // closed by abort
	set      <-chan struct{}
	last     *time.Timer
}

// dialInfoFor returns the DialInfo of an attempt for carrier id of factory
// f with first frame t (M2-D55; R1-32: a Kind of 0 is a stream factory).
func dialInfoFor(f Factory, id uint32, t wire.Type, payload []byte) DialInfo {
	d := DialInfo{Carrier: id, Kind: f.Kind, Probe: t == wire.TypePing}
	if d.Kind == 0 {
		d.Kind = wire.KindStream
	}
	if (t == wire.TypeOpen || t == wire.TypeJoin) && len(payload) >= len(d.Session) {
		copy(d.Session[:], payload)
	}
	return d
}

// establishDatagram is Establish for a datagram factory (M2 design §A5.10):
// the guarded factory call with the DialInfo attached; the transport (the
// *OwnedUDP token by its exact type, else NewPacketIO with the factory MTU,
// whose failure closes the conn once); the cmtu offer min(f.MTU, Limit)
// (a probe: wire.MinFrameBudget), written into OPEN.window or JOIN.rxNext
// of a copy of payload; H1 = PREFACE ‖ REL{FirstCseq, OPEN | JOIN} (a
// probe: PREFACE ‖ PING) written once and resent verbatim at RelRTOInit
// doubling to RelRTOMax until a PREFACE_ACK, a RACK covering it or the
// response, at most Handshake.Timeout after the first copy; the
// PREFACE_ACK checked in M1's canonical order (a malformed one is a lost
// datagram); then, until the response, frames through the receive window:
// a RACK, PING (id 0: the rebind challenge, answered at once through this
// socket, R1-14), a PONG of another id, PACK, DGRAM and a REL with another
// cseq are dropped and counted (M2-D20); the response REL{FirstCseq,
// OPEN_ACK | JOIN_ACK | CLOSE | GOAWAY} (or the probe's PONG) returns the
// unstarted Conn — R1-3's REL start values, the window, the PREFACE_ACK,
// the rest of the response's datagram as its tail (R1-1) — after H4, the
// RACK of a REL response (best effort). A bare control frame, DATA, ACK, a
// malformed REL or RACK and a malformed response are protocol violations.
// A withdrawal after a written OPEN, and a failed check, send one
// best-effort REL{FirstCseq + 1, RST(withdrawn)} datagram before the close.
func establishDatagram(ctx context.Context, env *Env, f Factory, id uint32, t wire.Type, payload []byte, check func(*wire.PrefaceAck) error) (*Established, error) {
	switch t {
	case wire.TypeOpen, wire.TypeJoin:
	case wire.TypePing:
		if len(payload) != 0 {
			panic("rendr/carrier: Establish: a PING first frame takes no payload")
		}
	default:
		panic("rendr/carrier: Establish: first frame must be OPEN, JOIN or PING")
	}
	var sb [8]byte
	_, _ = rand.Read(sb[:])
	d := &dgDial{
		ctx: ctx, env: env, tm: env.Timing.withDefaults(), f: f, id: id, t: t,
		pingID: env.Presets.firstPingID(), salt: binary.LittleEndian.Uint64(sb[:]), fcs: env.Presets.firstCseq(),
		left: make(chan struct{}), abortCh: make(chan struct{}),
	}
	returned := false
	var rb *Buf
	defer func() {
		rb.Release()
		if returned {
			return
		}
		// runtime.Goexit inside an embedder call (L51): io is closed exactly
		// once and the id released.
		d.finish()
		d.closeIO()
		if env.IDs != nil {
			env.IDs.Release(id)
		}
	}()
	est, err := d.run(payload, check, &rb)
	returned = true
	return est, err
}

// fail ends the attempt without a transport to close.
func (d *dgDial) fail(e *EstablishError) (*Established, error) {
	if d.env.IDs != nil {
		d.env.IDs.Release(d.id)
	}
	return nil, e
}

// failed ends the attempt after the transport exists (M1's mapping): an
// abort that ran first turns the outcome into the context's (a
// withdrawal: after a written OPEN, the RST datagram first) or the
// attempt deadline's; rst asks for the RST (a failed check); then io is
// closed once.
func (d *dgDial) failed(stage string, cause Cause, prefaceOK bool, inst [16]byte, err error, rst bool) (*Established, error) {
	// The attempt ended by its context or its deadline — whichever of the
	// abort and an expired read deadline the handshake saw first.
	if d.finish() || !time.Now().Before(d.deadline) {
		if d.ctx.Err() != nil {
			cause, err = CauseLocalClose, fmt.Errorf("%w (%v)", context.Cause(d.ctx), err)
			rst = errors.Is(context.Cause(d.ctx), ErrWithdrawn)
		} else {
			cause, err = CauseTransportError, fmt.Errorf("%w (%v)", errDialTimeout, err)
			rst = false
		}
	}
	if rst && d.t == wire.TypeOpen && d.wrote {
		d.withdraw()
	}
	d.closeIO()
	e := &EstablishError{Stage: stage, Cause: cause, PrefaceOK: prefaceOK, Err: err}
	if prefaceOK {
		e.Instance = inst
	}
	return d.fail(e)
}

// abort runs when the attempt's context ends (cancel, withdrawal or the
// attempt deadline) before finish: SetDeadline(now) unblocks the
// handshake's read on a transport that honours it, and io is closed
// drainMax later if the handshake is still inside a call then.
func (d *dgDial) abort() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.finished || d.aborted {
		return
	}
	d.aborted = true
	close(d.abortCh)
	d.set = d.k.goDeadline(d.env, d.tm.AbandonWait+drainMax)
	d.last = time.AfterFunc(drainMax, func() {
		select {
		case <-d.left:
		default:
			d.k.last(d.env)
		}
	})
}

// finish ends the guarded phase and reports whether abort ran first.
func (d *dgDial) finish() (aborted bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.finished {
		d.finished = true
		close(d.left)
	}
	return d.aborted
}

func (d *dgDial) isAborted() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.aborted
}

// closeIO closes io once; a factory conn that no io owns yet (a Goexit
// inside NewPacketIO's guarded String) is closed instead.
func (d *dgDial) closeIO() {
	switch {
	case d.io != nil:
		d.k.async(d.env)
	case d.pc != nil:
		closePacketConn(d.env, d.pc)
	}
}

// withdraw writes the best-effort REL{FirstCseq + 1, RST(withdrawn)}
// datagram at the next tx fseq (L49), bounded by drainMax; after an abort
// only once its SetDeadline(now) returned and while io is not closing.
func (d *dgDial) withdraw() {
	if d.set != nil {
		t := time.NewTimer(drainMax)
		defer t.Stop()
		select {
		case <-d.set:
		case <-t.C:
			return
		}
	}
	if d.k.closing.Load() {
		return
	}
	_ = d.io.SetWriteDeadline(time.Now().Add(drainMax))
	var rp [wire.RelHeadLen + wire.RstFixedLen]byte
	wire.PutRelHead(rp[:], &wire.RelHead{Cseq: d.fcs + 1, Type: wire.TypeRst, Handle: wire.SessionHandle})
	wire.PutRst(rp[wire.RelHeadLen:], &wire.Rst{Code: wire.RstWithdrawn})
	_ = d.io.WriteDatagram(d.frame(wire.Header{Type: wire.TypeRel}, rp[:]))
}

// frame returns one frame of type h.Type at the next tx fseq, after the
// transport's headroom: a datagram of its own.
func (d *dgDial) frame(h wire.Header, payload []byte) []byte {
	hr := d.io.Headroom()
	h.Fseq = d.tx
	d.tx++
	return wire.AppendFrame(make([]byte, hr, hr+wire.FrameOverhead+len(payload)), h, payload)
}

// write writes a handshake datagram: written, refused as too large or lost
// to noise is no failure (a later copy may pass); any other error is.
func (d *dgDial) write(b []byte) error {
	err := d.io.WriteDatagram(b)
	switch {
	case err == nil:
		d.wrote = true
		return nil
	case errors.Is(err, wire.ErrDatagramTooLarge), errors.Is(err, ErrNoise):
		dgEnvDropped(d.env)
		return nil
	}
	return err
}

// run is establishDatagram's body; every return path closes io unless the
// Established owns it, and releases id on failure.
func (d *dgDial) run(payload []byte, check func(*wire.PrefaceAck) error, rb **Buf) (*Established, error) {
	env, tm, f := d.env, d.tm, d.f
	if f.DialPacket == nil {
		return d.fail(&EstablishError{Stage: "dial", Cause: CauseTransportError, Err: errNoDialPacket})
	}
	d.deadline = time.Now().Add(tm.DialTimeout)
	if dl, ok := d.ctx.Deadline(); ok && dl.Before(d.deadline) {
		d.deadline = dl
	}
	actx, cancel := context.WithDeadline(d.ctx, d.deadline)
	defer cancel()
	dctx := withDialInfo(actx, dialInfoFor(f, d.id, d.t, payload))
	pc, peer, err := GuardedDialPacket(dctx, env, func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		if h := env.Hooks; h != nil && h.DialStart != nil {
			h.DialStart(f.Index)
		}
		return f.DialPacket(ctx)
	})
	if err != nil {
		cause := CauseTransportError
		if d.ctx.Err() != nil {
			cause = CauseLocalClose
		}
		return d.fail(&EstablishError{Stage: "dial", Cause: cause, Err: err})
	}
	if o, ok := pc.(*OwnedUDP); ok { // the exact token type (L57)
		d.io = o
	} else {
		d.pc = pc
		pio, err := newPacketIO(env, pc, peer, f.MTU)
		if err != nil {
			d.pc = nil
			closePacketConn(env, pc) // NewPacketIO did not take it (L57)
			return d.fail(&EstablishError{Stage: "dial", Cause: CauseTransportError, Err: err})
		}
		d.io = pio
	}
	d.k = &closeOnce{nc: d.io}
	io := d.io

	// The cmtu offer (M2-D50): min(factory MTU, transport Limit); a probe
	// carrier's budget is MinFrameBudget (M2-D71).
	offer := io.Limit()
	if f.MTU > 0 {
		offer = min(offer, f.MTU)
	}
	if d.t == wire.TypePing {
		offer = wire.MinFrameBudget
	}
	io.SetLimit(offer) // the handshake reads with offer + Headroom + 1 (R1-6)

	h1, first := d.buildH1(payload, offer)
	if n := len(h1) - io.Headroom(); n > offer {
		d.closeIO()
		return d.fail(&EstablishError{Stage: "dial", Cause: CauseTransportError,
			Err: fmt.Errorf("%w: %d bytes, budget %d", errH1TooLarge, n, offer)})
	}
	d.tx = first + 1

	stop := context.AfterFunc(actx, d.abort)
	defer stop()
	_ = io.SetWriteDeadline(d.deadline)
	var b []byte
	*rb, b = hsReadBuf(env, io)

	now := time.Now()
	if err := d.write(h1); err != nil {
		return d.failed("preface", CauseTransportError, false, [16]byte{}, err, false)
	}
	k := 0
	next := now.Add(sched.RTOBackoffWithin(tm.RelRTOInit, 0, tm.RelRTOMax))
	resendUntil := now.Add(tm.HandshakeTimeout)

	var (
		ack      wire.PrefaceAck
		ackBytes []byte // the PREFACE_ACK(OK) read; nil before
		rwin     wire.FseqWindow
		p        hsPause
	)
	for {
		if d.isAborted() {
			return d.failed(stageOf(ackBytes), CauseTransportError, ackBytes != nil, ack.Instance, errAttemptEnded, false)
		}
		now := time.Now()
		if !next.IsZero() && !now.Before(next) {
			if now.Before(resendUntil) {
				k++
				if err := d.write(h1); err != nil { // the same bytes: a verbatim copy (PA-21)
					return d.failed(stageOf(ackBytes), CauseTransportError, ackBytes != nil, ack.Instance, err, false)
				}
				d.retx++
				next = now.Add(sched.RTOBackoffWithin(tm.RelRTOInit, k, tm.RelRTOMax))
			} else {
				next = time.Time{} // copies stop Handshake.Timeout after the first
			}
		}
		rdl := d.deadline
		if !next.IsZero() && next.Before(rdl) {
			rdl = next
		}
		_ = io.SetReadDeadline(rdl)
		data, _, ev, err := io.ReadDatagram(b)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) && !d.isAborted() && time.Now().Before(d.deadline) {
				continue // a copy of H1 is due
			}
			return d.failed(stageOf(ackBytes), CauseTransportError, ackBytes != nil, ack.Instance, err, false)
		}
		if ev != ReadOK {
			io.Release()
			dgEnvDropped(env)
			p.dropped(ev, d.deadline, d.abortCh) // the loop's checks end the attempt
			continue
		}
		p.reset()
		if wire.IsPreface(data) {
			switch {
			case ackBytes == nil:
				a, done, est, ferr := d.prefaceAck(data[:wire.PrefaceLen], check)
				if done {
					io.Release()
					return est, ferr
				}
				if a == nil {
					io.Release()
					dgEnvDropped(env) // a damaged PREFACE_ACK is a lost datagram (PA-1)
					continue
				}
				ack = *a
				ackBytes = bytes.Clone(data[:wire.PrefaceLen])
				rwin.Init(env.Presets.fseqFrom(ackBytes))
			case !bytes.Equal(data[:wire.PrefaceLen], ackBytes):
				io.Release()
				dgEnvDropped(env)
				continue
			}
			data = data[wire.PrefaceLen:] // a duplicate H2's frames are window duplicates
		} else if ackBytes == nil {
			io.Release()
			dgEnvDropped(env) // before the PREFACE_ACK nothing is processed
			continue
		}
		r, verr := d.frames(data, &rwin)
		if verr != nil {
			io.Release()
			return d.failed("response", CauseProtocolViolation, true, ack.Instance, verr, false)
		}
		if r.acked {
			next = time.Time{} // a RACK covering H1's REL: no more copies
		}
		if !r.ok {
			io.Release()
			continue
		}
		est, err := d.established(&ack, ackBytes, &rwin, &r, offer)
		io.Release()
		return est, err
	}
}

// stageOf names the handshake stage: "preface" before the PREFACE_ACK,
// "response" after it.
func stageOf(ack []byte) string {
	if ack == nil {
		return "preface"
	}
	return "response"
}

// buildH1 returns H1 after the transport's headroom — PREFACE(kind
// datagram) ‖ REL{FirstCseq, OPEN | JOIN} with the cmtu offer in a copy of
// payload, or PREFACE ‖ PING{id, nonce = salt ^ id} — and its frame's fseq.
func (d *dgDial) buildH1(payload []byte, offer int) ([]byte, uint32) {
	hr := d.io.Headroom()
	h1 := make([]byte, hr+wire.PrefaceLen, hr+wire.PrefaceLen+wire.FrameOverhead+wire.RelHeadLen+max(len(payload), wire.PingFixedLen))
	wire.PutPreface(h1[hr:], &wire.Preface{Minor: wire.Minor, Kind: wire.KindDatagram, Instance: d.env.Local, CarrierID: d.id})
	first := d.env.Presets.fseqFrom(h1[hr:])
	if d.t == wire.TypePing {
		var pp [wire.PingFixedLen]byte
		wire.PutPing(pp[:], &wire.Ping{ID: d.pingID, Nonce: d.salt ^ uint64(d.pingID)})
		return wire.AppendFrame(h1, wire.Header{Type: wire.TypePing, Fseq: first}, pp[:]), first
	}
	rp := make([]byte, wire.RelHeadLen+len(payload))
	wire.PutRelHead(rp, &wire.RelHead{Cseq: d.fcs, Type: d.t, Handle: wire.SessionHandle})
	inner := rp[wire.RelHeadLen:]
	copy(inner, payload)
	// The cmtu offer travels in OPEN.window or JOIN.rxNext (M2-D11, §A3.5).
	switch {
	case d.t == wire.TypeOpen && len(inner) >= 28:
		binary.BigEndian.PutUint32(inner[24:28], uint32(offer))
	case d.t == wire.TypeJoin && len(inner) >= 25:
		binary.BigEndian.PutUint64(inner[17:25], uint64(offer))
	}
	return wire.AppendFrame(h1, wire.Header{Type: wire.TypeRel, Fseq: first}, rp), first
}

// prefaceAck handles the first PREFACE_ACK (M1's canonical order, design
// §5.1): a malformed one returns nil and not done — a lost datagram; a
// well-formed non-OK answer, a wrong carrier ID echo and a failed check end
// the attempt (done); an OK one returns the PrefaceAck.
func (d *dgDial) prefaceAck(ab []byte, check func(*wire.PrefaceAck) error) (*wire.PrefaceAck, bool, *Established, error) {
	ack, perr := wire.ParsePrefaceAck(ab)
	switch {
	case perr == nil, errors.Is(perr, wire.ErrFeature):
		if ack.CarrierID != d.id {
			est, err := d.failed("preface", CauseProtocolViolation, false, [16]byte{}, fmt.Errorf("PREFACE_ACK echoes carrier %d, want %d", ack.CarrierID, d.id), false)
			return nil, true, est, err
		}
	case errors.Is(perr, wire.ErrMajor):
		// Another major answers in its own format; magic, major and CRC are
		// stable across majors: a deterministic version gap.
	default:
		return nil, false, nil, nil
	}
	var status wire.PrefaceStatus
	switch {
	case errors.Is(perr, wire.ErrMajor):
		status = wire.PrefaceVersion
	case errors.Is(perr, wire.ErrFeature):
		status = wire.PrefaceFeature
	default:
		status = ack.Status
	}
	if status != wire.PrefaceOK {
		e := &EstablishError{Stage: "preface", Cause: CauseTransportError, Status: status, Err: fmt.Errorf("PREFACE_ACK %s", prefaceStatusName(status))}
		if perr != nil {
			e.Err = perr
		}
		if !errors.Is(perr, wire.ErrMajor) {
			e.Instance = ack.Instance // a v2 answer: e.g. the instance a GOING_AWAY names
		}
		if d.finish() && d.ctx.Err() != nil {
			e.Cause, e.Err = CauseLocalClose, context.Cause(d.ctx)
		}
		d.closeIO()
		est, err := d.fail(e)
		return nil, true, est, err
	}
	if check != nil {
		if err := check(&ack); err != nil {
			est, ferr := d.failed("preface", CauseInstanceMismatch, true, ack.Instance, err, true)
			return nil, true, est, ferr
		}
	}
	return &ack, false, nil, nil
}

// dgResp is the outcome of one datagram's frames before the response.
type dgResp struct {
	acked   bool        // a RACK covered H1's REL
	ok      bool        // the response arrived
	rel     bool        // it was a REL (H4 follows)
	hdr     wire.Header // the response (a REL's inner frame, with the outer fseq)
	payload []byte      // aliases the datagram
	tail    []byte      // the rest of the response's datagram (R1-1)
}

// frames walks the frames of rendr bytes data before the response (M2-D20):
// header, bounds and CRC (a damaged frame drops the rest, PA-1), the
// receive window, then by type. It returns at the response with the rest of
// the datagram as the tail, or a protocol violation.
func (d *dgDial) frames(data []byte, rwin *wire.FseqWindow) (r dgResp, err error) {
	for len(data) > 0 {
		f, n, derr := wire.DecodeFrame(data)
		if derr != nil {
			dgEnvDropped(d.env) // the rest of this datagram (PA-1)
			return r, nil
		}
		data = data[n:]
		if rwin.Accept(f.Fseq) != wire.WindowNew {
			dgEnvDropped(d.env)
			continue
		}
		switch f.Type {
		case wire.TypeRack:
			rk, perr := wire.ParseRack(f.Payload)
			if perr != nil {
				return r, fmt.Errorf("RACK: %w", perr)
			}
			if err := d.checkRack(rk); err != nil {
				return r, err
			}
			if d.t != wire.TypePing && !wire.SeqLess(rk.CumAck, d.fcs) {
				r.acked = true
			}
		case wire.TypeRel:
			h, inner, perr := wire.ParseRel(f.Payload)
			if perr != nil {
				return r, fmt.Errorf("REL: %w", perr)
			}
			if h.Cseq != d.fcs {
				dgEnvDropped(d.env) // a REL with another cseq (M2-D20)
				continue
			}
			rh := wire.Header{Type: h.Type, Flags: h.Flags, Len: uint32(len(inner)), Fseq: f.Fseq, Handle: h.Handle}
			if !responseAllowed(d.t, rh) {
				return r, fmt.Errorf("%v as the response to %v", h.Type, d.t)
			}
			if err := validateResponse(rh, inner, d.pingID, d.salt); err != nil {
				return r, err
			}
			r.ok, r.rel, r.hdr, r.payload, r.tail = true, true, rh, inner, data
			return r, nil
		case wire.TypePong:
			pg, perr := wire.ParsePing(f.Payload)
			if perr != nil {
				return r, fmt.Errorf("PONG: %w", perr)
			}
			if d.t != wire.TypePing || pg.ID != d.pingID {
				dgEnvDropped(d.env) // a PONG of another id (M2-D20)
				continue
			}
			if !responseAllowed(d.t, f.Header) {
				return r, fmt.Errorf("PONG with a %d-byte pad as the response", pg.Pad)
			}
			if err := validateResponse(f.Header, f.Payload, d.pingID, d.salt); err != nil {
				return r, err
			}
			r.ok, r.hdr, r.payload, r.tail = true, f.Header, f.Payload, data
			return r, nil
		case wire.TypePing:
			pg, perr := wire.ParsePing(f.Payload)
			if perr != nil {
				return r, fmt.Errorf("PING: %w", perr)
			}
			if pg.ID == 0 {
				// A rebind challenge: its PONG at once, through this socket
				// and NAT mapping (R1-14).
				pg.Pad = 0
				var pp [wire.PingFixedLen]byte
				wire.PutPing(pp[:], &pg)
				if err := d.write(d.frame(wire.Header{Type: wire.TypePong}, pp[:])); err != nil {
					return r, err
				}
				continue
			}
			dgEnvDropped(d.env) // the passive's PING before H3 (M2-D20)
		case wire.TypePack, wire.TypeDgram:
			dgEnvDropped(d.env) // session frames before H3 (M2-D20)
		default:
			if f.Type.Extension() {
				continue // CRC-checked and skipped
			}
			return r, fmt.Errorf("bare %v before the response", f.Type)
		}
	}
	return r, nil
}

// checkRack validates a RACK against what H1 sent: nothing beyond
// FirstCseq (a probe: nothing at all) may be acknowledged or sacked.
func (d *dgDial) checkRack(rk wire.Rack) error {
	next := d.fcs + 1 // the next cseq this side would send
	if d.t == wire.TypePing {
		next = d.fcs
	}
	if wire.SeqLess(next-1, rk.CumAck) {
		return fmt.Errorf("RACK: cumAck %d beyond the last cseq sent %d", rk.CumAck, next-1)
	}
	for i := range uint32(wire.RelWindow - 1) {
		if rk.Sack&(1<<i) != 0 && !wire.SeqLess(rk.CumAck+2+i, next) {
			return fmt.Errorf("RACK: sack bit %d names cseq %d, never sent", i, rk.CumAck+2+i)
		}
	}
	return nil
}

// established builds the unstarted dialer Conn of the response r (M2
// design §A5.10; R1-1, R1-3): H4 first for a REL response (best effort),
// then budget and receive limit offer, the window, the REL start values,
// the PREFACE_ACK, the tail, the tx fseq after H4 and the PING ids.
func (d *dgDial) established(ack *wire.PrefaceAck, ackBytes []byte, rwin *wire.FseqWindow, r *dgResp, offer int) (*Established, error) {
	if d.finish() { // the attempt ended after the response arrived: no carrier
		return d.failed("response", CauseLocalClose, true, ack.Instance, errAttemptEnded, false)
	}
	if r.rel {
		var rk [wire.RackLen]byte
		wire.PutRack(rk[:], &wire.Rack{CumAck: d.fcs})
		_ = d.write(d.frame(wire.Header{Type: wire.TypeRack}, rk[:])) // H4, best effort
	}
	_ = d.io.SetDeadline(time.Time{})
	c := newDatagramConn(d.env, d.io, d.id, ack.Instance, d.f.Index, d.f.Name, true)
	c.salt = d.salt
	c.SetBudget(offer)
	dg := c.dg
	dg.rwin = *rwin
	dg.hs.ack = ackBytes
	if len(r.tail) > 0 {
		dg.tail = bytes.Clone(r.tail) // frames the passive packed behind its response (R1-1)
	}
	// R1-3's start values: H1's REL{F} (OPEN, JOIN) was answered; a probe
	// sent none. The passive's response REL{F} was dispatched here; a
	// probe's PONG response carried none.
	switch {
	case d.t != wire.TypePing:
		dg.rel.initSend(d.fcs + 1)
		dg.rel.initRecv(d.fcs)
	case r.rel:
		dg.rel.initSend(d.fcs)
		dg.rel.initRecv(d.fcs)
	default:
		dg.rel.initSend(d.fcs)
		dg.rel.initRecv(d.fcs - 1)
	}
	dg.ctr.retransmits.Add(d.retx)
	c.wr.fseq = d.tx
	c.rd.fseq = r.hdr.Fseq + 1
	if d.t == wire.TypePing {
		c.st.nextPingID = d.pingID + 1
		if c.st.nextPingID == 0 {
			c.st.nextPingID = 1 // id 0 is the rebind challenge (L14)
		}
	}
	return &Established{Conn: c, Ack: *ack, Resp: r.hdr, Payload: bytes.Clone(r.payload)}, nil
}
