package carrier

import (
	"context"
	"net"
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
	panic("unimplemented: M1b")
}

// Unwrap returns the underlying error.
func (e *EstablishError) Unwrap() error { return e.Err }

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
func Establish(ctx context.Context, env *Env, f Factory, id uint32, t wire.Type, payload []byte, check func(*wire.PrefaceAck) error) (*Established, error) {
	panic("unimplemented: M1b")
}

// Hello is a passive carrier whose PREFACE was accepted (PREFACE_ACK(OK)
// already written) and whose first frame was read and verified.
type Hello struct {
	Conn    *Conn        // unstarted; owns the net.Conn
	Preface wire.Preface // the dialer's PREFACE (instance, carrier ID)
	First   wire.Header  // OPEN, JOIN or PING
	Payload []byte       // a copy of the OPEN or JOIN payload (bounded by 32 + maxMeta)
	Ping    wire.Ping    // the parsed PING when First.Type == TypePing
	// MetaTooLarge: an OPEN whose metadata exceeds maxMeta; its payload was
	// not read. The admission answers OPEN_ACK(BAD_REQUEST, CodeMetadataSize).
	MetaTooLarge bool
}

// Gate decides the PREFACE_ACK status for a valid PREFACE: PrefaceOK,
// PrefaceGoingAway (Runtime closing) or PrefaceCapacity (abandoned pool full).
type Gate func(p *wire.Preface) wire.PrefaceStatus

// ReadHello runs the passive handshake on nc under deadline (accept time +
// Handshake.Timeout; L48): read the 40-byte PREFACE and validate it with
// wire.ParsePreface, whose error alone decides the answer (canonical check
// order, design §5.1): ErrMajor answers VERSION and ErrFeature FEATURE, then
// closes; every other error closes nc silently. Then ask gate; write
// PREFACE_ACK; on OK read exactly one frame, which must be OPEN, JOIN or PING
// with the Runtime's first fseq (Env.Presets.FirstFseq, 0 = wire.FirstFseq),
// checking the header before reading or allocating anything sized by it.
// A PING first frame (probe carrier) is also recorded as the Conn's pending
// PONG, so a sessionless carrier answers it as its first frame once
// started. Every failure closes nc (via CloseConn) and returns an error; no
// session state exists at that point.
func ReadHello(env *Env, nc net.Conn, deadline time.Time, maxMeta int, gate Gate) (*Hello, error) {
	panic("unimplemented: M1b")
}

// WriteAndClose writes one frame (the next tx fseq) on an unstarted Conn —
// an admission verdict such as OPEN_ACK(CAPACITY), JOIN_ACK(UNKNOWN_SESSION)
// or CLOSE(capacity) — bounded by deadline, then closes it in the L05 order
// (CloseWrite on OwnedTCP only, bounded drain, Close). It returns at once;
// the work runs on a guarded goroutine.
func (c *Conn) WriteAndClose(t wire.Type, flags uint8, handle uint32, payload []byte, deadline time.Time) {
	panic("unimplemented: M1b")
}
