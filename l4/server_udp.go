package l4

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/v2"
)

// The UDP side of the Server (M6 design §A6; M6-D16 … M6-D20).

// defaultUDPBuffer is the socket buffer size the default UDP dialer
// requests when Server.UDPBuffer is 0 or less (M6-D20, R1-14).
const defaultUDPBuffer = 1 << 20

// dialUDP is the target dial of a UDP flow on a Server without a Dial
// hook: a socket connected to addr, names resolved here (M6-D17). It is a
// variable only so that tests can observe the default dialer's calls and
// the conn it returns (their buffer requests); nothing else sets it.
var dialUDP = func(ctx context.Context, addr string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "udp", addr)
}

// errNotDatagram is LastErr of a UDP flow whose Dial hook returned a conn
// that is not a connected datagram conn (M6-D17, R1-11).
var errNotDatagram = errors.New("l4: Dial hook returned no connected datagram conn for a UDP flow")

// errBadDatagramConn is LastErr of a UDP flow whose Dial hook's conn
// panicked or called runtime.Goexit (v is nil then) in the datagram check
// (R1-11). It wraps nothing: CodeDialFailed.
type errBadDatagramConn struct{ v any }

func (e errBadDatagramConn) Error() string {
	return fmt.Sprint("l4: Dial hook's conn failed its datagram check: ", e.v)
}

// HandleUDP serves one pending packet session and returns when its flow
// ended: it requires UDP (else CodeBadCommand); the metadata must name a
// CmdUDP target (ParseUDPMetadata: CmdConnect on a packet session is
// CodeBadCommand); the target socket is dialled while the session is
// pending; a first datagram that rode the OPEN is written to it once (a
// policy-class error of that write is rejected CodeNotAllowed); the session
// is confirmed after that (a dial failure is rejected with the classified
// code); then the flow is forwarded as by ForwardPacket with UDPIdle, the
// first datagram counted toward its class, until the flow ends. Use it for
// Listeners shared with other packet sessions (Match tells them apart).
// Cancelling ctx stops the dial (CodeDialFailed) or ends the flow. After
// the flow ended (its MaxFlows unit released) HandleUDP waits for its
// session's end (PacketConn.Done, at most the Runtime's Linger), unless
// ctx is done, so that UDPServerStatus.SessionDrops holds the session's
// final drop counts (R1-38).
func (s *Server) HandleUDP(ctx context.Context, p *rendr.PendingPacket) {
	pc := s.serveFlow(ctx, p)
	if pc == nil {
		return
	}
	select {
	case <-pc.Done():
	case <-ctx.Done():
	}
	s.flow.sessionDrops.Add(packetDrops(pc.Status().Packet))
}

// serveFlow is HandleUDP up to the flow's end: it returns the flow's
// session once the forward ended, or nil when no session was confirmed.
func (s *Server) serveFlow(ctx context.Context, p *rendr.PendingPacket) *rendr.PacketConn {
	k := &s.udp
	if !s.UDP {
		s.reject(p, k, CodeBadCommand) // M6-D16: UDP is opt-in
		return nil
	}
	if !acquire(&k.units, int64(s.maxFlows())) {
		s.reject(p, k, CodeCapacity) // M6-D19: at once, no dial
		return nil
	}
	defer k.units.Add(-1)
	// The kind check is the parser (M6-D1, R1-8): CmdConnect, and every
	// command but CmdUDP, is CodeBadCommand here.
	r, err := ParseUDPMetadata(p.Metadata())
	if err != nil {
		s.reject(p, k, metadataCode(err))
		return nil
	}
	t := s.connect(ctx, p, k, r)
	if t == nil {
		return nil
	}
	var seed flowSeed
	if len(r.First) > 0 {
		if p.Context().Err() != nil {
			// Decided once the socket was dialled (withdrawn, timed out, its
			// Listener or Runtime closed; §A6.5): nothing can be confirmed,
			// so nothing is written.
			resetConn(t)
			k.unconfirmed.Add(1)
			return nil
		}
		at := time.Now()
		written, refuse := s.writeFirst(ctx, p.Context(), t, r.First)
		if refuse != 0 {
			resetConn(t)
			switch { // as connect: Serve's ctx first, then the pending context
			case ctx.Err() != nil:
				s.reject(p, k, CodeDialFailed)
			case p.Context().Err() != nil:
				k.unconfirmed.Add(1) // decided during the write: no Reject, as a failed Confirm
			default:
				s.reject(p, k, refuse)
			}
			return nil
		}
		if written {
			// R1-10: the forward's class tracker counts this datagram.
			seed = flowSeed{at: at, dir: towardLocal}
		}
	}
	pc, err := p.Confirm()
	if err != nil {
		// Decided while the target socket was dialled or the first
		// datagram written (withdrawn, timed out, its Listener or Runtime
		// closed; §A5.4): the target may have received the first datagram,
		// whose replies are lost — UDP semantics.
		resetConn(t)
		k.unconfirmed.Add(1)
		return nil
	}
	k.confirmed.Add(1)
	s.flow.maxPayload.Store(int64(pc.MaxPayload()))
	k.live.Add(1)
	res := forwardPacket(ctx, pc, t, s.UDPIdle, seed, &s.flow.tally)
	cause := endCauseOf(res.SessionErr)
	if res.LocalErr != nil {
		cause = endLocal
	}
	s.flow.ended.add(cause)
	k.live.Add(-1)
	return pc
}

// writeFirst writes the first datagram that rode the OPEN to the target
// socket t, once, before Confirm (M6-D18, R1-17), and reports whether it
// was written (counted in FirstSent) or the code the flow is refused
// with: CodeNotAllowed for an errno M4's table maps to it (EACCES, EPERM,
// WSAEACCES: a directed broadcast on Windows, a netfilter drop on
// output), CodeDialFailed for an error of the fatal class (M6-D15: an
// error that is not an errno, the fatal errno set, an invalid count). Any
// other error is noise: counted in TargetNoise, and the flow goes on
// (neither written nor refused). A Write that blocks (an embedder's own
// datagram conn) is ended by the pending phase's end (pctx) or Serve's
// ctx, which set t's write deadline (L52: nothing holds a handler).
func (s *Server) writeFirst(ctx, pctx context.Context, t net.Conn, b []byte) (written bool, refuse RejectCode) {
	halt := func() { t.SetWriteDeadline(time.Now()) }
	stopP, stopC := context.AfterFunc(pctx, halt), context.AfterFunc(ctx, halt)
	n, err := t.Write(b)
	stopP()
	stopC()
	if err == nil && n != len(b) {
		err = errBadDatagramCount // L42
	}
	if err == nil {
		s.flow.firstSent.Add(1)
		return true, 0
	}
	s.lastErr.Store(&err)
	if c, ok := errnoCode(err); ok && c == CodeNotAllowed {
		return false, CodeNotAllowed
	}
	if errClass(err) == classFatal {
		return false, CodeDialFailed
	}
	s.flow.firstNoise.Add(1)
	return false, 0
}

// requestBuffers asks for n bytes of receive and send buffer on the
// default dialer's conn c (R1-14: bursts from the target wait there).
// Best effort: the kernel caps the values (rmem_max, wmem_max), and an
// error leaves the system default.
func requestBuffers(c net.Conn, n int) {
	if b, ok := c.(interface {
		SetReadBuffer(int) error
		SetWriteBuffer(int) error
	}); ok {
		b.SetReadBuffer(n)
		b.SetWriteBuffer(n)
	}
}

func (s *Server) maxFlows() int {
	if s.MaxFlows <= 0 {
		return DefaultMaxFlows
	}
	return s.MaxFlows
}

func (s *Server) udpBuffer() int {
	if s.UDPBuffer <= 0 {
		return defaultUDPBuffer
	}
	return s.UDPBuffer
}

// packetDrops sums a packet session's drop counters (R1-38): its send
// side's DropQueue, DropAge, DropTooLarge and DropNoPath, its receive
// side's DropRecvQueue and DropLate. nil (a stream session's) is 0.
func packetDrops(pk *rendr.PacketCounters) uint64 {
	if pk == nil {
		return 0
	}
	return pk.DropQueue + pk.DropAge + pk.DropTooLarge + pk.DropNoPath + pk.DropRecvQueue + pk.DropLate
}

// flowCounts are a Server's counters of its UDP flows' datagrams and ends
// (UDPServerStatus beside kindStats).
type flowCounts struct {
	// tally is every forward's live counts: toLocal → ToTarget,
	// toSession → FromTarget, tooLarge → TooLarge, noise → TargetNoise.
	tally                 packetTally
	firstSent, firstNoise atomic.Uint64 // first datagrams written; noise errors of those writes
	sessionDrops          atomic.Uint64
	maxPayload            atomic.Int64
	ended                 endCounts
}

// udpStatus is Status's UDP part.
func (s *Server) udpStatus() UDPServerStatus {
	k, f := &s.udp, &s.flow
	first := f.firstSent.Load()
	return UDPServerStatus{
		Dialing:      int(k.dialing.Load()),
		Live:         int(k.live.Load()),
		Confirmed:    k.confirmed.Load(),
		Rejected:     k.rejected.Load(),
		Unconfirmed:  k.unconfirmed.Load(),
		Lost:         k.lost.Load(),
		ByCode:       k.codes(),
		ToTarget:     f.tally.toLocal.Load() + first,
		FromTarget:   f.tally.toSession.Load(),
		FirstSent:    first,
		TooLarge:     f.tally.tooLarge.Load(),
		TargetNoise:  f.tally.noise.Load() + f.firstNoise.Load(),
		SessionDrops: f.sessionDrops.Load(),
		MaxPayload:   int(f.maxPayload.Load()),
		Ended:        f.ended.snapshot(),
	}
}

// UDPServerStatus counts a Server's UDP flows.
type UDPServerStatus struct {
	Dialing, Live                          int    // flows being dialled for; flows being forwarded
	Confirmed, Rejected, Unconfirmed, Lost uint64 // as the TCP counters, for flows
	ByCode                                 map[RejectCode]uint64
	ToTarget, FromTarget                   uint64 // datagrams written to the targets (FirstSent included) and read from them
	FirstSent                              uint64 // first datagrams written from the OPEN
	TooLarge                               uint64 // target datagrams above their flow's MaxPayload, dropped
	TargetNoise                            uint64 // egress errors of the noise classes, counted and ignored
	SessionDrops                           uint64 // datagrams the flows' sessions dropped (their PacketCounters' drop fields), summed at each flow's end
	MaxPayload                             int    // the MaxPayload of the latest flow confirmed (0 before any)
	Ended                                  FlowEnds
}

// FlowEnds counts ended flows by cause.
type FlowEnds struct {
	Idle        uint64 // this end's idle limit (ErrIdleTimeout)
	PeerIdle    uint64 // the other end's (*rendr.AbortError{AbortIdle})
	PeerClosed  uint64 // the other end closed the flow (io.EOF): its stop, eviction or local failure
	NoPath      uint64
	SessionLost uint64
	GoingAway   uint64
	Stopped     uint64 // this side's ctx or Serve ended
	Evicted     uint64 // ingress only: ended to make room in a full table
	Local       uint64 // a fatal local socket error
	Other       uint64
}

// endCause is a flow's end cause: the field of FlowEnds it counts in.
type endCause uint8

const (
	endIdle endCause = iota
	endPeerIdle
	endPeerClosed
	endNoPath
	endSessionLost
	endGoingAway
	endStopped
	endEvicted
	endLocal
	endOther
	numEndCauses
)

// endCauseOf maps the end error of a flow's packet session (PacketResult's
// SessionErr, or ReadFrom's error at the ingress) to its cause (M6 design
// §A5.3): ErrIdleTimeout is this end's idle limit; *AbortError AbortIdle
// from the peer the other end's, AbortGoingAway a Runtime closing; io.EOF
// the peer's close; ErrNoPath, ErrSessionLost; a ctx error this side's
// stop; anything else (net.ErrClosed after a local failure, which the
// caller counts as endLocal) is endOther.
func endCauseOf(err error) endCause {
	switch {
	case errors.Is(err, rendr.ErrIdleTimeout):
		return endIdle
	case errors.Is(err, io.EOF):
		return endPeerClosed
	case errors.Is(err, rendr.ErrNoPath):
		return endNoPath
	case errors.Is(err, rendr.ErrSessionLost):
		return endSessionLost
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return endStopped
	}
	if ae, ok := errors.AsType[*rendr.AbortError](err); ok {
		switch {
		case ae.Code == rendr.AbortIdle && ae.Remote:
			return endPeerIdle
		case ae.Code == rendr.AbortGoingAway:
			return endGoingAway
		}
	}
	return endOther
}

// endCounts counts flow ends by cause (FlowEnds' live form; shared by the
// Server and the PortForward ingress).
type endCounts [numEndCauses]atomic.Uint64

func (c *endCounts) add(k endCause) { c[k].Add(1) }

func (c *endCounts) snapshot() FlowEnds {
	return FlowEnds{
		Idle:        c[endIdle].Load(),
		PeerIdle:    c[endPeerIdle].Load(),
		PeerClosed:  c[endPeerClosed].Load(),
		NoPath:      c[endNoPath].Load(),
		SessionLost: c[endSessionLost].Load(),
		GoingAway:   c[endGoingAway].Load(),
		Stopped:     c[endStopped].Load(),
		Evicted:     c[endEvicted].Load(),
		Local:       c[endLocal].Load(),
		Other:       c[endOther].Load(),
	}
}

// pending is what the target dial and the refusal need of a pending
// session of either kind (m6-design W1.3): *rendr.PendingConn and
// *rendr.PendingPacket.
type pending interface {
	Context() context.Context
	Reject(code uint32, msg string) error
}

var (
	_ pending = (*rendr.PendingConn)(nil)
	_ pending = (*rendr.PendingPacket)(nil)
)

// isDatagramConn reports whether c, a Dial hook's conn for a UDP flow, is
// a connected datagram conn (M6-D17, R1-11): RemoteAddr is non-nil and c
// implements net.PacketConn or its LocalAddr is non-nil with Network "udp",
// "udp4" or "udp6". The hook call's goroutine runs it (runHook), whose
// recovery turns a panic or runtime.Goexit in these methods into
// CodeDialFailed and Panics.
func isDatagramConn(c net.Conn) bool {
	if c.RemoteAddr() == nil {
		return false // unconnected (a ListenUDP socket), or no address at all
	}
	if _, ok := c.(net.PacketConn); ok {
		return true
	}
	la := c.LocalAddr()
	if la == nil {
		return false
	}
	switch la.Network() {
	case "udp", "udp4", "udp6":
		return true
	}
	return false
}
