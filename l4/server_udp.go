package l4

import (
	"context"
	"net"

	"github.com/FrankoonG/rendr/v2"
)

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
// Cancelling ctx stops the dial (CodeDialFailed) or ends the flow.
//
// Skeleton (M6 wave 0): not implemented yet; every session is rejected
// CodeDialFailed.
func (s *Server) HandleUDP(ctx context.Context, p *rendr.PendingPacket) {
	p.Reject(uint32(CodeDialFailed), CodeDialFailed.String())
}

// UDPServerStatus counts a Server's UDP flows.
type UDPServerStatus struct {
	Dialing, Live                          int    // flows being dialled for; flows being forwarded
	Confirmed, Rejected, Unconfirmed, Lost uint64 // as the TCP counters, for flows
	ByCode                                 map[RejectCode]uint64
	ToTarget, FromTarget                   uint64 // datagrams
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
// "udp4" or "udp6". The caller runs it under recover (a panic: CodeDialFailed
// and Panics).
//
// Skeleton (M6 wave 0): no conn is accepted.
func isDatagramConn(c net.Conn) bool { return false }
