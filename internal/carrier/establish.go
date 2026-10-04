package carrier

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Factory is one carrier factory of a Peer's snapshot (L20: frozen at Dial).
type Factory struct {
	Index     int                                                       // configuration order
	Name      string                                                    // unique within the Peer
	Dial      func(ctx context.Context) (net.Conn, error)               // required
	DialEarly func(ctx context.Context, first []byte) (net.Conn, error) // optional
}

// Established is a dialer carrier whose handshake completed: PREFACE_ACK(OK)
// and the passive's first frame were read and verified.
type Established struct {
	Conn    *Conn           // unstarted; owns the net.Conn and any bytes read past the response frame
	Ack     wire.PrefaceAck // Status == PrefaceOK
	Resp    wire.Header     // the passive's first frame: OPEN_ACK, JOIN_ACK, PONG, CLOSE or GOAWAY
	Payload []byte          // a copy of the response payload (≤ 300 bytes)
}

// EstablishError describes a failed attempt. It wraps the underlying error.
type EstablishError struct {
	Stage     string             // "dial", "preface", "response"
	Cause     Cause              // CauseTransportError, CauseProtocolViolation, CauseInstanceMismatch or CauseLocalClose (ctx)
	Status    wire.PrefaceStatus // the PREFACE_ACK status when a well-formed non-OK one was read
	PrefaceOK bool               // the PREFACE exchange completed (cadence outcome Refused, not Failed)
	Instance  [16]byte           // the passive InstanceID when PrefaceOK
	Err       error
}

// Error implements error.
func (e *EstablishError) Error() string {
	s := "rendr: carrier " + e.Stage
	if e.Status != wire.PrefaceOK {
		s += ": PREFACE_ACK " + prefaceStatusName(e.Status)
	}
	s += " (" + e.Cause.String() + ")"
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}

// Unwrap returns the underlying error.
func (e *EstablishError) Unwrap() error { return e.Err }

func prefaceStatusName(s wire.PrefaceStatus) string {
	switch s {
	case wire.PrefaceOK:
		return "OK"
	case wire.PrefaceVersion:
		return "VERSION"
	case wire.PrefaceFeature:
		return "FEATURE"
	case wire.PrefaceGoingAway:
		return "GOING_AWAY"
	case wire.PrefaceCapacity:
		return "CAPACITY"
	}
	return fmt.Sprintf("status %d", uint8(s))
}

// Establish runs one dial attempt for carrier id on factory f, bounded as a
// whole by Timing.DialTimeout and by ctx: the guarded factory call (DialEarly
// with PREFACE ‖ first frame when f.DialEarly is set, else Dial followed by
// one Write of PREFACE ‖ first frame); then PREFACE_ACK and exactly one
// response frame under the same deadline; then deadlines are cleared.
//
// Establish builds the first frame itself, so counter presets (L14) apply to
// it like to every later frame: type t is TypeOpen or TypeJoin (session
// carriers; payload encoded by wire.PutOpen/PutJoin; handle SessionHandle)
// or TypePing (probe carriers; payload must be nil: Establish encodes the
// PING with the Conn's first PING id and nonce = salt ^ id; handle 0). Its
// fseq is the Runtime's first fseq (Env.Presets.FirstFseq, 0 = wire.FirstFseq)
// and the Conn's tx fseq and PING id counters continue after it. A PING's
// response must be a PONG echoing its id and nonce (else a protocol
// violation); that establishment PONG is not an RTT sample (design D26).
//
// check, if non-nil, is called on every PREFACE_ACK(OK) before the response
// is awaited; it may read state that changes while attempts run (the
// session's bound instance and the Peer's gone-away set, design §6.6). Its
// error ends the attempt with PrefaceOK set and Cause CauseInstanceMismatch;
// for an OPEN, Establish then writes a best-effort RST(wire.RstWithdrawn)
// before closing, so that an admitted OPEN on the wrong instance does not
// linger as a pending session.
//
// A malformed PREFACE_ACK is a carrier error, never a version error. A
// well-formed non-OK answer is returned as an *EstablishError with Status
// set: VERSION, FEATURE, GOING_AWAY or CAPACITY as written; a PREFACE_ACK
// with valid magic and CRC from another major (wire.ErrMajor) is reported as
// PrefaceVersion and one with unknown required bits (wire.ErrFeature) as
// PrefaceFeature (design §5.1). When ctx is cancelled with cause ErrWithdrawn
// after the first frame was written, Establish writes a best-effort
// RST(wire.RstWithdrawn) (bounded, guarded) before closing (L49).
//
// Further contracts of this implementation: Hooks.DialStart(f.Index) runs
// right before the factory call, on the guarded goroutine (a hook that
// blocks acts like a hanging factory; a fast-failed attempt calls neither);
// Establish owns id — the returned Conn
// releases it to env.IDs when its Done closes, and a failed attempt
// releases it before returning; every conn it obtained is closed exactly
// once unless it is returned inside the Established; an accepted response
// is OPEN_ACK (for OPEN), JOIN_ACK (for JOIN) or PONG (for PING), or CLOSE
// or GOAWAY for any of them, and every one is fully validated (CRC, fseq,
// canonical payload) before it is returned; a well-formed non-OK
// PREFACE_ACK of this major also reports the passive's Instance (the
// instance a GOING_AWAY names, design §6.6), with PrefaceOK false.
func Establish(ctx context.Context, env *Env, f Factory, id uint32, t wire.Type, payload []byte, check func(*wire.PrefaceAck) error) (*Established, error) {
	first := env.Presets.firstFseq()
	pingID := env.Presets.firstPingID()
	var sb [8]byte
	_, _ = rand.Read(sb[:])
	salt := binary.LittleEndian.Uint64(sb[:])

	hello := make([]byte, wire.PrefaceLen, wire.PrefaceLen+wire.FrameOverhead+max(len(payload), wire.PingFixedLen))
	wire.PutPreface(hello, &wire.Preface{Minor: wire.Minor, Kind: wire.KindStream, Instance: env.Local, CarrierID: id})
	switch t {
	case wire.TypeOpen, wire.TypeJoin:
		hello = wire.AppendFrame(hello, wire.Header{Type: t, Fseq: first, Handle: wire.SessionHandle}, payload)
	case wire.TypePing:
		if len(payload) != 0 {
			panic("rendr/carrier: Establish: a PING first frame takes no payload")
		}
		var pp [wire.PingFixedLen]byte
		wire.PutPing(pp[:], &wire.Ping{ID: pingID, Nonce: salt ^ uint64(pingID)})
		hello = wire.AppendFrame(hello, wire.Header{Type: wire.TypePing, Fseq: first}, pp[:])
	default:
		panic("rendr/carrier: Establish: first frame must be OPEN, JOIN or PING")
	}

	fail := func(e *EstablishError) (*Established, error) {
		if env.IDs != nil {
			env.IDs.Release(id)
		}
		return nil, e
	}
	tm := env.Timing.withDefaults()
	deadline := time.Now().Add(tm.DialTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	actx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	dialStart := func() {
		if h := env.Hooks; h != nil && h.DialStart != nil {
			h.DialStart(f.Index)
		}
	}
	var nc net.Conn
	var err error
	if f.DialEarly != nil {
		nc, err = GuardedDialEarly(actx, env, func(ctx context.Context, first []byte) (net.Conn, error) {
			dialStart()
			return f.DialEarly(ctx, first)
		}, hello)
	} else {
		nc, err = GuardedDial(actx, env, func(ctx context.Context) (net.Conn, error) {
			dialStart()
			return f.Dial(ctx)
		})
	}
	if err != nil {
		if ctx.Err() != nil {
			return fail(&EstablishError{Stage: "dial", Cause: CauseLocalClose, Err: err})
		}
		return fail(&EstablishError{Stage: "dial", Cause: CauseTransportError, Err: err})
	}

	g := &hsGuard{env: env, nc: nc, ctx: ctx, firstWritten: f.DialEarly != nil}
	if t == wire.TypeOpen {
		g.rst = withdrawFrame(first + 1)
	}
	stop := context.AfterFunc(actx, g.abort)
	defer stop()
	// failed closes the conn once (with RST(withdrawn) when asked) and maps
	// an I/O error caused by the abort to the context's outcome.
	failed := func(stage string, cause Cause, prefaceOK bool, inst [16]byte, err error, rst bool) (*Established, error) {
		if g.finish() { // aborted: ctx ended or the attempt deadline passed
			if ctx.Err() != nil {
				cause, err = CauseLocalClose, fmt.Errorf("%w (%v)", context.Cause(ctx), err)
			} else {
				cause, err = CauseTransportError, fmt.Errorf("%w (%v)", errDialTimeout, err)
			}
		} else if rst {
			g.closeWith(g.rst)
		}
		g.closeWith(nil)
		e := &EstablishError{Stage: stage, Cause: cause, PrefaceOK: prefaceOK, Err: err}
		if prefaceOK {
			e.Instance = inst
		}
		return fail(e)
	}

	_ = callSetDeadline(nc, deadline)
	if f.DialEarly == nil {
		if err := writeFull(nc, hello); err != nil {
			return failed("preface", CauseTransportError, false, [16]byte{}, err, false)
		}
		g.mu.Lock()
		g.firstWritten = true
		g.mu.Unlock()
	}

	// PREFACE_ACK, checked in the canonical order (design §5.1).
	var ab [wire.PrefaceLen]byte
	if err := readFull(nc, ab[:]); err != nil {
		return failed("preface", CauseTransportError, false, [16]byte{}, err, false)
	}
	ack, perr := wire.ParsePrefaceAck(ab[:])
	switch {
	case perr == nil, errors.Is(perr, wire.ErrFeature):
		if ack.CarrierID != id {
			return failed("preface", CauseProtocolViolation, false, [16]byte{}, fmt.Errorf("PREFACE_ACK echoes carrier %d, want %d", ack.CarrierID, id), false)
		}
	case errors.Is(perr, wire.ErrMajor):
		// Another major answers in its own format; magic, major and CRC
		// are stable across majors, so this is a deterministic version gap.
	default:
		return failed("preface", CauseProtocolViolation, false, [16]byte{}, fmt.Errorf("PREFACE_ACK: %w", perr), false)
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
		if g.finish() && ctx.Err() != nil {
			e.Cause, e.Err = CauseLocalClose, context.Cause(ctx)
		}
		g.closeWith(nil)
		return fail(e)
	}
	if check != nil {
		if err := check(&ack); err != nil {
			return failed("preface", CauseInstanceMismatch, true, ack.Instance, err, true)
		}
	}

	// The passive's first frame.
	var hb [wire.HeaderLen]byte
	if err := readFull(nc, hb[:]); err != nil {
		return failed("response", CauseTransportError, true, ack.Instance, err, false)
	}
	h, herr := wire.ParseHeader(hb[:])
	if herr != nil {
		return failed("response", CauseProtocolViolation, true, ack.Instance, fmt.Errorf("response header: %w", herr), false)
	}
	if h.Fseq != first {
		return failed("response", CauseProtocolViolation, true, ack.Instance, fmt.Errorf("response fseq %d, want %d", h.Fseq, first), false)
	}
	if !responseAllowed(t, h) {
		return failed("response", CauseProtocolViolation, true, ack.Instance, fmt.Errorf("%v as the response to %v", h.Type, t), false)
	}
	rb := make([]byte, int(h.Len)+wire.TrailerLen) // ≤ 265 + 4: responseAllowed bounds it
	if err := readFull(nc, rb); err != nil {
		return failed("response", CauseTransportError, true, ack.Instance, err, false)
	}
	p := rb[:h.Len]
	if wire.CRCUpdate(wire.CRC(hb[:]), p) != wire.Trailer(rb[h.Len:]) {
		return failed("response", CauseProtocolViolation, true, ack.Instance, fmt.Errorf("%v: %w", h.Type, wire.ErrCRC), false)
	}
	if err := validateResponse(h, p, pingID, salt); err != nil {
		return failed("response", CauseProtocolViolation, true, ack.Instance, err, false)
	}
	if g.finish() { // ctx ended or the attempt deadline passed after the last byte: no carrier
		return failed("response", CauseLocalClose, true, ack.Instance, errors.New("attempt ended"), false)
	}
	_ = callSetDeadline(nc, time.Time{})

	c := newConn(env, nc, id, ack.Instance, f.Index, f.Name, true)
	c.salt = salt
	c.wr.fseq, c.rd.fseq = first+1, first+1
	if t == wire.TypePing {
		c.st.nextPingID = pingID + 1
	}
	return &Established{Conn: c, Ack: ack, Resp: h, Payload: p}, nil
}

// responseAllowed reports whether h may answer a first frame of type t,
// and bounds its length: OPEN_ACK answers OPEN, JOIN_ACK answers JOIN, a
// PONG without pad answers PING; CLOSE and GOAWAY may answer any.
func responseAllowed(t wire.Type, h wire.Header) bool {
	switch h.Type {
	case wire.TypeClose, wire.TypeGoAway:
		return true
	case wire.TypeOpenAck:
		return t == wire.TypeOpen
	case wire.TypeJoinAck:
		return t == wire.TypeJoin
	case wire.TypePong:
		return t == wire.TypePing && h.Len == wire.PingFixedLen
	}
	return false
}

// validateResponse applies the canonical payload rules (C32) and checks
// that a PONG echoes the establishment PING's id and nonce.
func validateResponse(h wire.Header, p []byte, pingID uint32, salt uint64) error {
	var err error
	switch h.Type {
	case wire.TypeOpenAck:
		_, err = wire.ParseOpenAck(p)
	case wire.TypeJoinAck:
		_, err = wire.ParseJoinAck(p)
	case wire.TypeClose:
		_, err = wire.ParseClose(p)
	case wire.TypeGoAway:
		_, err = wire.ParseGoAway(p)
	case wire.TypePong:
		var pong wire.Ping
		pong, err = wire.ParsePing(p)
		if err == nil && (pong.ID != pingID || pong.Nonce != salt^uint64(pingID)) {
			err = errors.New("PONG does not echo the establishment PING")
		}
	}
	if err != nil {
		return fmt.Errorf("%v: %w", h.Type, err)
	}
	return nil
}

// withdrawFrame encodes RST(withdrawn) with the dialer's second fseq.
func withdrawFrame(fseq uint32) []byte {
	var p [wire.RstFixedLen]byte
	wire.PutRst(p[:], &wire.Rst{Code: wire.RstWithdrawn})
	return wire.AppendFrame(nil, wire.Header{Type: wire.TypeRst, Fseq: fseq, Handle: wire.SessionHandle}, p[:])
}

// hsGuard bounds a dialer handshake (Establish) by its context: when the
// attempt's context ends first, abort closes the conn (after a best-effort
// RST(withdrawn) when the session withdrew an OPEN that was written, L49),
// which unblocks the handshake I/O. The conn is closed at most once.
type hsGuard struct {
	env          *Env
	nc           net.Conn
	ctx          context.Context // the caller's context (its cause tells a withdrawal)
	rst          []byte          // RST(withdrawn) for an OPEN; nil otherwise
	closed       atomic.Bool
	mu           sync.Mutex
	finished     bool
	aborted      bool
	firstWritten bool
}

func (g *hsGuard) abort() {
	g.mu.Lock()
	if g.finished {
		g.mu.Unlock()
		return
	}
	g.aborted = true
	rst := g.rst != nil && g.firstWritten && errors.Is(context.Cause(g.ctx), ErrWithdrawn)
	g.mu.Unlock()
	if rst {
		g.closeWith(g.rst)
		return
	}
	g.closeWith(nil)
}

// finish ends the guarded phase and reports whether abort ran first.
func (g *hsGuard) finish() (aborted bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.finished = true
	return g.aborted
}

// closeWith closes the conn once: with frame non-nil it first writes it
// (bounded by drainMax), all on a guarded goroutine.
func (g *hsGuard) closeWith(frame []byte) {
	if !g.closed.CompareAndSwap(false, true) {
		return
	}
	if frame == nil {
		CloseConn(g.env, g.nc)
		return
	}
	writeThenClose(g.env, g.nc, frame)
}

// writeThenClose writes frame (bounded by drainMax) and closes nc on a
// guarded goroutine counted in the abandoned-call pool when it hangs.
func writeThenClose(env *Env, nc net.Conn, frame []byte) {
	w := startWatch(env.Abandon, env.Timing.withDefaults().AbandonWait+drainMax)
	go func() {
		defer w.finish()
		_ = callSetWriteDeadline(nc, time.Now().Add(drainMax))
		_ = writeFull(nc, frame)
		closeNow(nc)
	}()
}
