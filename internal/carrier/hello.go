package carrier

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

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

// Errors of ReadHello (the conn is already closed when they are returned).
var (
	// errHelloRefused: the PREFACE was answered with a non-OK PREFACE_ACK.
	errHelloRefused = errors.New("rendr: handshake refused")
	// errHelloFirst: the first frame is not OPEN, JOIN or PING, or its
	// fseq is not the first fseq.
	errHelloFirst = errors.New("rendr: handshake: bad first frame")
)

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
// started. Every failure closes nc exactly once, on a guarded goroutine
// (CloseConn), and returns an error; no session state exists at that
// point.
//
// Further contracts of this implementation: a PREFACE whose kind is not
// stream (a datagram carrier needs a packet conn, M2) is closed silently
// like a malformed one; a non-OK PREFACE_ACK (VERSION, FEATURE or the
// gate's answer) is written and followed by the L05 close order (CloseWrite
// on an OwnedTCP, a drain bounded by min(deadline, 1 s), Close) on the
// calling handshake goroutine, in its slot, so that the dialer reads the
// answer instead of a reset; on a conn that ignores its deadlines, towards
// a dialer that neither reads nor closes, the conn is closed AbandonWait
// after both bounds as the last resort (design §0.8 V2), which returns the
// refusal on a conn that honours Close; ReadHello never counts the calling
// goroutine in the abandoned-call pool — the caller's owner joins it and
// counts it once if it stays stuck (root's handshake group), as for a
// handshake stuck in a Read (L52); PREFACE_ACK(OK) is written right after
// the PREFACE is validated (P18); a PING first frame's pad is streamed
// (never allocated by its length) and must be zero; when a conn call runs
// runtime.Goexit on the caller's goroutine, nc is still closed exactly
// once (L51; the caller's own deferred cleanup must release its handshake
// slot).
func ReadHello(env *Env, nc net.Conn, deadline time.Time, maxMeta int, gate Gate) (*Hello, error) {
	k := &closeOnce{nc: nc} // every close of nc goes through k: exactly once (L52)
	returned := false
	defer func() {
		if !returned { // runtime.Goexit inside an embedder conn call (L51)
			k.async(env)
		}
	}()
	h, err := readHello(env, k, deadline, maxMeta, gate)
	returned = true
	return h, err
}

// readHello is ReadHello without the Goexit guard: every return path closes
// k's conn unless a Hello owns it.
func readHello(env *Env, k *closeOnce, deadline time.Time, maxMeta int, gate Gate) (*Hello, error) {
	nc := k.nc
	fail := func(err error) (*Hello, error) {
		k.async(env)
		return nil, err
	}
	if err := callSetDeadline(nc, deadline); err != nil {
		var pe *panicError
		if errors.As(err, &pe) {
			return fail(err)
		}
	}
	var pb [wire.PrefaceLen]byte
	if err := readFull(nc, pb[:]); err != nil {
		return fail(fmt.Errorf("rendr: handshake: reading PREFACE: %w", err))
	}
	p, perr := wire.ParsePreface(pb[:])
	switch {
	case perr == nil:
	case errors.Is(perr, wire.ErrMajor):
		// Another major: the carrier ID's place is the only echo we can give.
		refuse(env, k, deadline, wire.PrefaceVersion, binary.BigEndian.Uint32(pb[32:36]))
		return nil, fmt.Errorf("%w: %w", errHelloRefused, perr)
	case errors.Is(perr, wire.ErrFeature):
		refuse(env, k, deadline, wire.PrefaceFeature, p.CarrierID)
		return nil, fmt.Errorf("%w: %w", errHelloRefused, perr)
	default:
		return fail(fmt.Errorf("rendr: handshake: PREFACE: %w", perr))
	}
	if p.Kind != wire.KindStream {
		return fail(fmt.Errorf("rendr: handshake: PREFACE kind %d on a stream conn: %w", p.Kind, wire.ErrMalformed))
	}
	status := wire.PrefaceOK
	if gate != nil {
		status = gate(&p)
	}
	if status != wire.PrefaceOK {
		refuse(env, k, deadline, status, p.CarrierID)
		return nil, fmt.Errorf("%w: PREFACE_ACK %s", errHelloRefused, prefaceStatusName(status))
	}
	var ab [wire.PrefaceLen]byte
	wire.PutPrefaceAck(ab[:], &wire.PrefaceAck{Minor: wire.Minor, Status: wire.PrefaceOK, Instance: env.Local, CarrierID: p.CarrierID})
	if err := writeFull(nc, ab[:]); err != nil {
		return fail(fmt.Errorf("rendr: handshake: writing PREFACE_ACK: %w", err))
	}

	first := env.Presets.firstFseq()
	var hb [wire.HeaderLen]byte
	if err := readFull(nc, hb[:]); err != nil {
		return fail(fmt.Errorf("rendr: handshake: reading the first frame: %w", err))
	}
	h, herr := wire.ParseHeader(hb[:])
	if herr != nil {
		return fail(fmt.Errorf("%w: %w", errHelloFirst, herr))
	}
	if h.Fseq != first {
		return fail(fmt.Errorf("%w: fseq %d, want %d", errHelloFirst, h.Fseq, first))
	}
	hello := &Hello{Preface: p, First: h}
	switch h.Type {
	case wire.TypeOpen:
		if int(h.Len)-wire.OpenFixedLen > min(max(maxMeta, 0), wire.MaxMetadata) {
			hello.MetaTooLarge = true // answered without reading the metadata
			break
		}
		payload, err := readPayload(nc, hb[:], int(h.Len))
		if err != nil {
			return fail(err)
		}
		hello.Payload = payload
	case wire.TypeJoin:
		payload, err := readPayload(nc, hb[:], int(h.Len))
		if err != nil {
			return fail(err)
		}
		hello.Payload = payload
	case wire.TypePing:
		ping, err := readHelloPing(nc, hb[:], int(h.Len))
		if err != nil {
			return fail(err)
		}
		hello.Ping = ping
	default:
		return fail(fmt.Errorf("%w: %v", errHelloFirst, h.Type))
	}
	if err := callSetDeadline(nc, time.Time{}); err != nil {
		var pe *panicError
		if errors.As(err, &pe) {
			return fail(err)
		}
	}
	c := newConn(env, nc, p.CarrierID, p.Instance, -1, "", false)
	c.rd.fseq = first + 1
	if h.Type == wire.TypePing {
		c.st.pong, c.st.pongDue = hello.Ping, true
	}
	hello.Conn = c
	return hello, nil
}

// readPayload reads an n-byte payload and its trailer (n is bounded by
// ParseHeader and the caller) and verifies the CRC over header ‖ payload.
// The returned payload is a copy owned by the caller.
func readPayload(nc net.Conn, hdr []byte, n int) ([]byte, error) {
	b := make([]byte, n+wire.TrailerLen)
	if err := readFull(nc, b); err != nil {
		return nil, fmt.Errorf("rendr: handshake: reading the first frame: %w", err)
	}
	if wire.CRCUpdate(wire.CRC(hdr), b[:n]) != wire.Trailer(b[n:]) {
		return nil, fmt.Errorf("%w: %w", errHelloFirst, wire.ErrCRC)
	}
	return b[:n:n], nil
}

// readHelloPing reads a PING payload of n bytes with its trailer, streaming
// the pad through a small buffer (CheckPad, running CRC).
func readHelloPing(nc net.Conn, hdr []byte, n int) (wire.Ping, error) {
	var fixed [wire.PingFixedLen]byte
	if err := readFull(nc, fixed[:]); err != nil {
		return wire.Ping{}, fmt.Errorf("rendr: handshake: reading the first frame: %w", err)
	}
	crc := wire.CRCUpdate(wire.CRC(hdr), fixed[:])
	var chunk [512]byte
	for pad := n - wire.PingFixedLen; pad > 0; {
		k := min(pad, len(chunk))
		if err := readFull(nc, chunk[:k]); err != nil {
			return wire.Ping{}, fmt.Errorf("rendr: handshake: reading the first frame: %w", err)
		}
		if err := wire.CheckPad(chunk[:k]); err != nil {
			return wire.Ping{}, fmt.Errorf("%w: PING pad: %w", errHelloFirst, err)
		}
		crc = wire.CRCUpdate(crc, chunk[:k])
		pad -= k
	}
	var tr [wire.TrailerLen]byte
	if err := readFull(nc, tr[:]); err != nil {
		return wire.Ping{}, fmt.Errorf("rendr: handshake: reading the first frame: %w", err)
	}
	if crc != wire.Trailer(tr[:]) {
		return wire.Ping{}, fmt.Errorf("%w: %w", errHelloFirst, wire.ErrCRC)
	}
	ping, err := wire.ParsePing(fixed[:])
	if err != nil {
		return wire.Ping{}, fmt.Errorf("%w: %w", errHelloFirst, err)
	}
	ping.Pad = n - wire.PingFixedLen
	return ping, nil
}

// refuse writes a non-OK PREFACE_ACK and closes k's conn in the L05 order
// on the handshake goroutine, in its slot (writeAndCloseInline: the write
// bounded by the handshake deadline, the drain by min(deadline, 1 s), the
// last resort on a conn that ignores its deadlines, design §0.8 V2; the
// goroutine is counted by its owner, never here).
func refuse(env *Env, k *closeOnce, deadline time.Time, status wire.PrefaceStatus, carrierID uint32) {
	var ab [wire.PrefaceLen]byte
	wire.PutPrefaceAck(ab[:], &wire.PrefaceAck{Minor: wire.Minor, Status: status, Instance: env.Local, CarrierID: carrierID})
	writeAndCloseInline(env, k, ab[:], deadline)
}
