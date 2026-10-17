package l4

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/FrankoonG/rendr/v2"
)

// PacketResult reports how a ForwardPacket ended.
type PacketResult struct {
	ToSession, ToLocal uint64 // datagrams moved in each direction
	TooLarge           uint64 // local datagrams above pc.MaxPayload(), dropped
	LocalNoise         uint64 // local read and write errors of the noise classes, counted and ignored
	Stream             bool   // the flow became a stream
	// SessionErr is the session's end: io.EOF (the peer closed),
	// rendr.ErrIdleTimeout, *rendr.AbortError, rendr.ErrNoPath,
	// rendr.ErrSessionLost, net.ErrClosed (closed on this side after a
	// local failure), or ctx.Err().
	SessionErr error
	LocalErr   error // the local error that ended the forward, else nil
}

// ForwardPacket moves datagrams between the packet session pc and local, a
// connected datagram conn (each Read returns one datagram from local's far
// end, each Write sends one: a connected *net.UDPConn), until the session
// ends, a fatal local error occurs or ctx is done, and then closes both.
// Boundaries are kept; zero-length datagrams are forwarded. A local
// datagram longer than pc.MaxPayload() is dropped and counted (TooLarge),
// never split (an io.ErrShortBuffer from local counts as TooLarge too).
// Local system-call errors — a port or host unreachable, an
// administratively prohibited destination, a message too long, no buffer
// space: every syscall.Errno except a small fatal set (a closed or invalid
// descriptor, an unconnected socket) — are counted and ignored; a run of
// them backs off up to 100 ms; they never end the flow. Other errors end it.
// ForwardPacket applies idle's classes to pc with SetIdleTimeout (Short at
// once, Stream once the flow is a stream). It sets no deadlines during the
// transfer, owns pc and local from the call on, and starts one goroutine
// that ends before it returns. Carrier changes are invisible to local.
//
// Skeleton (M6 wave 0): not implemented yet; it closes both and returns
// the error as LocalErr.
func ForwardPacket(ctx context.Context, pc *rendr.PacketConn, local net.Conn, idle FlowIdle) PacketResult {
	pc.Close()
	local.Close()
	return PacketResult{SessionErr: net.ErrClosed, LocalErr: errors.New("l4: not implemented")}
}

// flowDir is the direction in which a datagram moved through a forward.
type flowDir uint8

const (
	towardSession flowDir = iota + 1 // from local (the client at the ingress, the target at the passive) to the session
	towardLocal                      // from the session to local
)

// flowClass is one end's class tracker of a UDP flow, shared by
// ForwardPacket, the passive's seeded forward and the PortForward ingress
// (M6-D9, R1-7, R1-10, R1-23; m6-design W1.3). It applies activeRule():
// seed records a datagram that moved before the tracker's owner started
// (HandleUDP's first datagram, written to the target before Confirm:
// towardLocal), out one that moved toward the session at now, in one that
// moved toward local at now. Each reports whether the flow became a stream
// with that datagram — true at most once in the tracker's life — and the
// caller then calls pc.SetIdleTimeout(Stream) once. At most two time
// comparisons per datagram until the promotion, none after; no allocation.
//
// Skeleton (M6 wave 0): the methods never promote.
type flowClass struct{}

func (c *flowClass) seed(at time.Time, d flowDir) bool { return false }
func (c *flowClass) out(now time.Time) bool            { return false }
func (c *flowClass) in(now time.Time) bool             { return false }
