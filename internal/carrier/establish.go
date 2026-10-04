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
	Instance  [16]byte           // the passive InstanceID when PrefaceOK; also set (PrefaceOK false) from a well-formed non-OK PREFACE_ACK of this major, e.g. the instance a GOING_AWAY names (§6.6)
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
// The Write of PREFACE ‖ first frame runs on a guarded helper goroutine
// while Establish reads PREFACE_ACK (design §0.8 V1): on a synchronous conn
// (net.Pipe, some in-memory embedder transports) a Write returns only as
// the other end reads, and the passive writes PREFACE_ACK between reading
// the PREFACE and the first frame (P18), so one goroutine writing first and
// reading afterwards would hold both ends until the deadline. The wire
// order does not change: after a PREFACE_ACK(OK) the helper is joined
// before check runs and before anything else is read or written (the
// response, an RST), and every return path joins it too. A failed hello
// Write — an error, an invalid count, a panic or runtime.Goexit in the
// embedder's Write — closes the conn and ends the attempt at once as a
// transport error of stage "preface" with PrefaceOK false, also when the
// PREFACE_ACK read was still waiting. Once the conn is being closed (a
// failure, a non-OK answer, an abort), the join waits at most
// Timing.AbandonWait for a Write that ignores its deadline and Close; such
// a writer is then counted in env.Abandon until its Write returns (L52), and
// nothing more is written on that conn.
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
// PrefaceFeature (design §5.1). When ctx is cancelled with cause ErrWithdrawn,
// Establish returns at once (a hello Write still in progress is cut by the
// deadline) and, if the first frame was written completely, writes a
// best-effort RST(wire.RstWithdrawn) (bounded, guarded) before closing
// (L49). Both RSTs are followed by the L05 close order on a guarded
// goroutine (CloseWrite on an OwnedTCP, a drain of what the passive already
// sent bounded by 1 s, Close), so an answer racing the withdrawal cannot
// turn the close into a TCP reset that discards the RST; on a conn that
// ignores the RST's write deadline the goroutine is adopted by the
// abandoned-call pool AbandonWait after its bounds and its conn is closed
// as a last resort (design §0.8 V2).
//
// Further contracts of this implementation: Hooks.DialStart(f.Index) runs
// right before the factory call, on the guarded goroutine (a hook that
// blocks acts like a hanging factory; a fast-failed attempt calls neither);
// Establish owns id — the returned Conn
// releases it to env.IDs when its Done closes, and a failed attempt
// releases it before returning; every conn it obtained is closed exactly
// once unless it is returned inside the Established, also when a conn call
// runs runtime.Goexit on the caller's goroutine (L51: the id is released
// then too, and the caller's own deferred cleanup must report the attempt);
// an accepted response
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

	// returned is set on every return path; a conn call that runs
	// runtime.Goexit on this goroutine skips them all, and the deferred
	// cleanup then closes the conn exactly once, joins the hello writer and
	// releases id (L51).
	var g *hsGuard
	returned := false
	defer func() {
		if returned {
			return
		}
		if g != nil {
			g.finish()
			g.closeWith(nil, false)
			g.leave()
		}
		if env.IDs != nil {
			env.IDs.Release(id)
		}
	}()
	fail := func(e *EstablishError) (*Established, error) {
		returned = true
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

	g = newHsGuard(ctx, env, nc, f.DialEarly != nil)
	if t == wire.TypeOpen {
		g.rst = withdrawFrame(first + 1)
	}
	stop := context.AfterFunc(actx, g.abort)
	defer stop()
	// failed closes the conn once (with RST(withdrawn) when asked and the
	// first frame was written: the hello writer was joined then), joins the
	// hello writer, and maps an I/O error caused by the abort to the
	// context's outcome.
	failed := func(stage string, cause Cause, prefaceOK bool, inst [16]byte, err error, rst bool) (*Established, error) {
		if g.finish() { // aborted: ctx ended or the attempt deadline passed
			if ctx.Err() != nil {
				cause, err = CauseLocalClose, fmt.Errorf("%w (%v)", context.Cause(ctx), err)
			} else {
				cause, err = CauseTransportError, fmt.Errorf("%w (%v)", errDialTimeout, err)
			}
		} else if rst {
			g.closeWith(g.rst, false)
		}
		g.closeWith(nil, false)
		g.leave()
		e := &EstablishError{Stage: stage, Cause: cause, PrefaceOK: prefaceOK, Err: err}
		if prefaceOK {
			e.Instance = inst
		}
		return fail(e)
	}

	_ = callSetDeadline(nc, deadline)
	if g.isAborted() {
		// The abort ran before this deadline was set and may have been
		// overridden by it; every later abort unblocks the conn after it.
		return failed("preface", CauseTransportError, false, [16]byte{}, errors.New("attempt ended"), false)
	}
	if f.DialEarly == nil {
		g.startHello(hello) // written while PREFACE_ACK is read (design §0.8 V1)
	}

	// PREFACE_ACK, checked in the canonical order (design §5.1).
	var ab [wire.PrefaceLen]byte
	if err := readFull(nc, ab[:]); err != nil {
		if werr := g.helloFailed(); werr != nil {
			err = werr // the hello Write failed first; its close ended this read
		}
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
		// Closed first, so a hello Write the passive will not read ends
		// now: the typed answer never waits for the deadline (L44).
		g.closeWith(nil, false)
		g.leave()
		return fail(e)
	}
	// PREFACE_ACK(OK): the passive reads the first frame next (P18). Join
	// the hello writer before check, and before anything follows the first
	// frame on the wire (an RST) or is read after it (the response).
	if err := g.join(); err != nil {
		return failed("preface", CauseTransportError, false, [16]byte{}, err, false)
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
	returned = true
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

// Errors of the hello writer (design §0.8 V1).
var (
	// errHelloGoexit: the embedder's Write called runtime.Goexit on the
	// hello writer (L51).
	errHelloGoexit = errors.New("rendr: conn Write called runtime.Goexit")
	// errHelloAbandoned: the hello Write ignored its deadline and the close
	// for AbandonWait; the writer was counted in the abandoned-call pool.
	errHelloAbandoned = errors.New("rendr: hello Write abandoned in the embedder")
)

// hsGuard bounds a dialer handshake (Establish) by its context: when the
// attempt's context ends first, abort closes the conn (after a best-effort
// RST(withdrawn) when the session withdrew an OPEN that was written, L49),
// which unblocks the handshake I/O. The conn is closed at most once.
//
// It also owns the hello writer, the guarded helper goroutine that writes
// PREFACE ‖ first frame while the handshake reads PREFACE_ACK (design §0.8
// V1). The handshake joins the writer (join, leave) before anything follows
// the first frame and before it returns; left tells a concurrent
// RST(withdrawn) that neither of them touches the conn any more.
type hsGuard struct {
	env     *Env
	nc      net.Conn
	ctx     context.Context // the caller's context (its cause tells a withdrawal)
	rst     []byte          // RST(withdrawn) for an OPEN; nil otherwise
	left    chan struct{}   // closed by leave: neither the handshake nor its hello writer touches the conn
	closing chan struct{}   // closed when the close of the conn began (closeWith): bounds the join
	wdone   chan struct{}   // closed when the hello writer returned or unwound; nil without one (DialEarly)
	closed  atomic.Bool

	mu           sync.Mutex
	finished     bool  // the guarded phase ended: a later abort does nothing
	aborted      bool  // abort ran before finish
	firstWritten bool  // PREFACE ‖ first frame were written completely (DialEarly: by the factory)
	wfinished    bool  // the hello writer returned; werr is final
	werr         error // the hello Write's error
	wabandoned   bool  // the hello writer was counted in the abandoned-call pool
	leftClosed   bool
}

func newHsGuard(ctx context.Context, env *Env, nc net.Conn, firstWritten bool) *hsGuard {
	return &hsGuard{env: env, nc: nc, ctx: ctx, firstWritten: firstWritten, left: make(chan struct{}), closing: make(chan struct{})}
}

func (g *hsGuard) abort() {
	g.mu.Lock()
	if g.finished {
		g.mu.Unlock()
		return
	}
	g.aborted = true
	withdraw := g.rst != nil && errors.Is(context.Cause(g.ctx), ErrWithdrawn)
	g.mu.Unlock()
	if withdraw {
		// Whether the RST may follow is decided once the handshake left
		// the conn: only after a first frame that was written completely.
		g.closeWith(g.rst, true)
		return
	}
	g.closeWith(nil, false)
}

// finish ends the guarded phase and reports whether abort ran first.
func (g *hsGuard) finish() (aborted bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.finished = true
	return g.aborted
}

// isAborted reports whether abort ran.
func (g *hsGuard) isAborted() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.aborted
}

// wroteFirst reports whether PREFACE ‖ first frame were written completely.
func (g *hsGuard) wroteFirst() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.firstWritten
}

// startHello writes hello on the hello writer, a guarded helper goroutine
// (design §0.8 V1): a panic in the embedder's Write is an error (callWrite),
// runtime.Goexit is detected by the deferred result, invalid counts are
// errors (writeFull, L42), and a failed Write closes the conn at once so
// that the handshake's PREFACE_ACK read ends with it instead of waiting
// for the deadline. The writer is joined by join; it is counted in the
// abandoned-call pool only when join gave up on it.
func (g *hsGuard) startHello(hello []byte) {
	g.wdone = make(chan struct{})
	go func() {
		err := errHelloGoexit // kept when the Write unwinds with runtime.Goexit
		defer func() {
			g.mu.Lock()
			g.wfinished, g.werr = true, err
			if err == nil {
				g.firstWritten = true
			}
			abandoned := g.wabandoned
			g.mu.Unlock()
			close(g.wdone)
			if abandoned && g.env.Abandon != nil {
				g.env.Abandon.Leave()
			}
			if err != nil {
				g.closeWith(nil, false)
			}
		}()
		err = writeFull(g.nc, hello)
	}()
}

// helloFailed returns the hello Write's error once the writer returned
// with one, else nil.
func (g *hsGuard) helloFailed() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.wfinished {
		return nil
	}
	return g.werr
}

// join waits for the hello writer and returns its result (nil: the first
// frame was written). While the conn is open it waits as long as the Write
// runs: the passive reads the first frame right after its PREFACE_ACK, and
// the attempt's deadline bounds the wait (abort closes the conn). Once the
// close of the conn began it waits at most AbandonWait more; a writer still
// inside the embedder's Write then (a conn that ignores its deadline and
// Close) is counted in the abandoned-call pool until its Write returns
// (L52), and join reports errHelloAbandoned. Only the handshake's own
// goroutine calls it.
func (g *hsGuard) join() error {
	if g.wdone == nil {
		return nil // DialEarly: the factory sent PREFACE ‖ first frame
	}
	select {
	case <-g.wdone:
		return g.helloFailed()
	case <-g.closing:
	}
	g.mu.Lock()
	gaveUp := g.wabandoned
	g.mu.Unlock()
	if !gaveUp {
		t := time.NewTimer(g.env.Timing.withDefaults().AbandonWait)
		select {
		case <-g.wdone:
			t.Stop()
			return g.helloFailed()
		case <-t.C:
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.wfinished {
		return g.werr
	}
	if !g.wabandoned {
		// Adopt under the lock the writer reads wabandoned under: its
		// Leave always follows this Adopt.
		g.wabandoned = true
		if g.env.Abandon != nil {
			g.env.Abandon.Adopt()
		}
	}
	return errHelloAbandoned
}

// leave joins the hello writer and closes left: the handshake no longer
// touches the conn. Its caller has begun the close of the conn
// (closeWith), which bounds the join.
func (g *hsGuard) leave() {
	_ = g.join()
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.leftClosed {
		g.leftClosed = true
		close(g.left)
	}
}

// closeWith begins the close of the conn, once: with frame nil at once
// (SetDeadline(now), Close; CloseConn); otherwise after writing frame in
// the L05 order (writeThenClose), but only when PREFACE ‖ first frame were
// written completely — nothing may follow a partial first frame. concurrent
// says that the handshake may still be inside a conn call (abort): the
// frame then waits until the handshake and its hello writer left the conn
// (left), and the first-frame condition is decided only then.
func (g *hsGuard) closeWith(frame []byte, concurrent bool) {
	if !g.closed.CompareAndSwap(false, true) {
		return
	}
	close(g.closing)
	switch {
	case frame != nil && concurrent:
		writeThenClose(g.env, g.nc, frame, g.left, g.wroteFirst)
	case frame != nil && g.wroteFirst():
		writeThenClose(g.env, g.nc, frame, nil, nil)
	default:
		CloseConn(g.env, g.nc)
	}
}

// writeThenClose writes frame and closes nc in the L05 order — the frame
// (bounded by drainMax), CloseWrite on an OwnedTCP, a drain bounded by
// drainMax, then SetDeadline(now) and Close — on a guarded goroutine
// counted in the abandoned-call pool when it hangs. The drain reads what
// the passive already sent (an OPEN_ACK racing a withdrawal), so the close
// never answers unread bytes with a TCP reset that could discard the frame
// before the passive read it (Windows drops buffered data on a reset).
// When left is non-nil the handshake may still be inside a conn call: the
// goroutine first unblocks it (SetDeadline(now): the handshake's read and
// a hello Write in progress return at once) and waits until it left the
// conn, at most drainMax, so that neither the drain nor the frame competes
// with it; ok, if non-nil, is then asked whether the frame may be written
// at all (the first frame was written completely), else the conn is only
// closed. When the goroutine is adopted by the abandoned-call pool — a conn
// that ignores the write or the drain's read deadline and a peer that does
// not read or close — its conn is closed exactly once as a last resort
// (design §0.8 V2), which unblocks it on a conn that honours Close.
func writeThenClose(env *Env, nc net.Conn, frame []byte, left <-chan struct{}, ok func() bool) {
	k := &closeOnce{nc: nc}
	w := armWatch(env.Abandon, env.Timing.withDefaults().AbandonWait+3*drainMax, func() { k.lastResort(env) })
	go func() {
		defer w.finish()
		defer k.now() // exactly once, also on runtime.Goexit in a conn call (L51)
		if left != nil {
			_ = callSetDeadline(nc, time.Now())
			t := time.NewTimer(drainMax)
			select {
			case <-left:
			case <-t.C:
			}
			t.Stop()
		}
		if ok != nil && !ok() {
			return
		}
		_ = callSetWriteDeadline(nc, time.Now().Add(drainMax))
		if writeFull(nc, frame) != nil {
			return
		}
		if o, isOwned := nc.(*OwnedTCP); isOwned {
			_ = callCloseWrite(o)
		}
		drain(nc, time.Now().Add(drainMax))
	}()
}
