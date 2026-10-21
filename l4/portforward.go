package l4

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/v2"
)

// UDPSocket is the socket PortForward.ServeUDP reads and writes: an
// unconnected UDP socket bound to the ingress address. *net.UDPConn
// implements it. ServeUDP refuses a socket that also has a RemoteAddr
// method returning non-nil (a connected socket).
type UDPSocket interface {
	// ReadFromUDPAddrPort reads one datagram and the address it came from.
	ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error)
	// WriteToUDPAddrPort sends one datagram to addr.
	WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error)
	// LocalAddr is the address the socket is bound to.
	LocalAddr() net.Addr
	// SetReadDeadline ends a blocked read at ServeUDP's stop.
	SetReadDeadline(t time.Time) error
	// Close closes the socket; ServeUDP calls it exactly once, at its stop.
	Close() error
}

// ErrNonLoopback: ServeTCP or ServeUDP was given a socket bound to a
// non-loopback or unspecified address without AllowNonLoopback.
var ErrNonLoopback = errors.New("l4: a non-loopback ingress requires PortForward.AllowNonLoopback")

// Errors of the ingress checks before the first read or accept.
var (
	errNoPeer          = errors.New("l4: PortForward.Peer is nil")
	errConnectedSocket = errors.New("l4: ServeUDP needs an unconnected socket (it reports a RemoteAddr)")
)

// PortForward forwards local ports to targets reached through one Peer:
// every TCP connection that ServeTCP accepts becomes one stream session
// (Dial, then Forward); every UDP flow on a ServeUDP socket — the datagrams
// of one client source address — becomes one packet session (DialUDP, then
// forwarding), like a NAT mapping. Peer is required; the other fields have
// defaults. A PortForward must not be copied after first use. It does no
// authentication: whoever reaches an ingress socket reaches its target.
type PortForward struct {
	Peer    *rendr.Peer       // the Peer every connection and flow is dialled through (required)
	Options rendr.DialOptions // every session's Mode, Metadata (Request.App) and NoPathGrace; EarlyReturn applies to TCP only
	// AllowNonLoopback permits sockets bound to non-loopback or unspecified
	// addresses (a LAN-facing ingress). Without it Serve refuses them.
	AllowNonLoopback bool
	MaxConns         int           // TCP connections at once over every ServeTCP (0: DefaultMaxConns); one beyond is reset at once
	MaxFlows         int           // UDP flows at once over every ServeUDP, opening and held entries included (0 or less: DefaultMaxFlows)
	Idle             FlowIdle      // the UDP flows' classes (zero: the defaults)
	IdleTimeout      time.Duration // TCP sessions (0: DefaultIdleTimeout; negative: none), as l4.Dial and Server

	tcp tcpForwardCounters // ServeTCP's
	udp udpForwardCounters // ServeUDP's

	// flows holds the MaxFlows units: one per table entry (opening, open or
	// held) over every ServeUDP. A unit moves with its entry's place in the
	// table: an eviction or an expiry-race replacement hands the place to
	// the newcomer without a release (M6-D13, M6-D29).
	flows atomic.Int64
	// opening counts the entries in the opening stage over every ServeUDP
	// (at most ingressOpeningMax, M6-D27).
	opening atomic.Int64

	mu     sync.Mutex
	serves map[*udpServe]struct{} // the running ServeUDP calls (Flows)
}

// tcpForwardCounters are ServeTCP's counters (TCPForwardStatus).
type tcpForwardCounters struct {
	conns                                  atomic.Int64 // MaxConns units: connections being forwarded
	accepted, refused, failed, acceptNoise atomic.Uint64
	byCode                                 [CodeDialFailed - CodeBadRequest + 1]atomic.Uint64
	lastErr                                atomic.Pointer[error]
}

// dialFailed counts a failed Dial: Failed, its code when it is an l4
// refusal, LastErr.
func (c *tcpForwardCounters) dialFailed(err error) {
	c.failed.Add(1)
	if code, ok := CodeOf(err); ok {
		c.byCode[code-CodeBadRequest].Add(1)
	}
	c.lastErr.Store(&err)
}

// udpForwardCounters are ServeUDP's counters (UDPForwardStatus). The
// gauges change under a table lock at each entry's state change; every
// counter is an atomic, so Status reads them without a lock.
type udpForwardCounters struct {
	open, held                                        atomic.Int64 // gauges: open flows, held clients (Opening is PortForward.opening)
	opened, failed, evicted, replaced                 atomic.Uint64
	byCode                                            [CodeDialFailed - CodeBadRequest + 1]atomic.Uint64
	ends                                              flowEndCounts
	toSession, toClient, firstInOpen, tooLarge        atomic.Uint64
	tooLargeMax, maxPayload                           atomic.Int64
	dropFull, dropOpening, dropOpenQueue, dropOpenAge atomic.Uint64
	dropHeld, readNoise, writeNoise, sessionDrops     atomic.Uint64
	sessionUnreported                                 atomic.Uint64
	lastErr                                           atomic.Pointer[error]
}

// openFailed counts a failed DialUDP: Failed, its code when it is an l4
// refusal, LastErr.
func (c *udpForwardCounters) openFailed(err error) {
	c.failed.Add(1)
	if code, ok := CodeOf(err); ok {
		c.byCode[code-CodeBadRequest].Add(1)
	}
	c.lastErr.Store(&err)
}

// noteTooLarge counts a client datagram of n bytes above its flow's
// MaxPayload (TooLarge, TooLargeMax).
func (c *udpForwardCounters) noteTooLarge(n int) {
	c.tooLarge.Add(1)
	for {
		m := c.tooLargeMax.Load()
		if int64(n) <= m || c.tooLargeMax.CompareAndSwap(m, int64(n)) {
			return
		}
	}
}

// flowEndCounts are the atomic twins of FlowEnds.
type flowEndCounts struct {
	idle, peerIdle, peerClosed, noPath, sessionLost, goingAway, stopped, evicted, local, other atomic.Uint64
}

func (c *flowEndCounts) snapshot() FlowEnds {
	return FlowEnds{
		Idle: c.idle.Load(), PeerIdle: c.peerIdle.Load(), PeerClosed: c.peerClosed.Load(), NoPath: c.noPath.Load(),
		SessionLost: c.sessionLost.Load(), GoingAway: c.goingAway.Load(), Stopped: c.stopped.Load(),
		Evicted: c.evicted.Load(), Local: c.local.Load(), Other: c.other.Load(),
	}
}

// byCodeMap is the ByCode map of a status: the codes counted so far.
func byCodeMap(a *[CodeDialFailed - CodeBadRequest + 1]atomic.Uint64) map[RejectCode]uint64 {
	m := make(map[RejectCode]uint64)
	for i := range a {
		if n := a[i].Load(); n > 0 {
			m[CodeBadRequest+RejectCode(i)] = n
		}
	}
	return m
}

func loadErr(p *atomic.Pointer[error]) error {
	if e := p.Load(); e != nil {
		return *e
	}
	return nil
}

// Status returns a snapshot of the PortForward's counters.
func (f *PortForward) Status() PortForwardStatus {
	t, u := &f.tcp, &f.udp
	return PortForwardStatus{
		TCP: TCPForwardStatus{
			Live:        int(t.conns.Load()),
			Accepted:    t.accepted.Load(),
			Refused:     t.refused.Load(),
			Failed:      t.failed.Load(),
			ByCode:      byCodeMap(&t.byCode),
			AcceptNoise: t.acceptNoise.Load(),
			LastErr:     loadErr(&t.lastErr),
		},
		UDP: UDPForwardStatus{
			Flows:         int(u.open.Load()),
			Opening:       int(f.opening.Load()),
			Held:          int(u.held.Load()),
			Opened:        u.opened.Load(),
			Failed:        u.failed.Load(),
			Evicted:       u.evicted.Load(),
			Replaced:      u.replaced.Load(),
			ByCode:        byCodeMap(&u.byCode),
			Ended:         u.ends.snapshot(),
			ToSession:     u.toSession.Load(),
			ToClient:      u.toClient.Load(),
			FirstInOpen:   u.firstInOpen.Load(),
			TooLarge:      u.tooLarge.Load(),
			TooLargeMax:   int(u.tooLargeMax.Load()),
			MaxPayload:    int(u.maxPayload.Load()),
			DropFull:      u.dropFull.Load(),
			DropOpening:   u.dropOpening.Load(),
			DropOpenQueue: u.dropOpenQueue.Load(),
			DropOpenAge:   u.dropOpenAge.Load(),
			DropHeld:      u.dropHeld.Load(),
			ReadNoise:     u.readNoise.Load(),
			WriteNoise:    u.writeNoise.Load(),
			SessionDrops:  u.sessionDrops.Load(),
			LastErr:       loadErr(&u.lastErr),

			SessionUnreported: u.sessionUnreported.Load(),
		},
	}
}

// maxConns is MaxConns with its default.
func (f *PortForward) maxConns() int {
	if f.MaxConns <= 0 {
		return DefaultMaxConns
	}
	return f.MaxConns
}

// maxFlows is MaxFlows with its default (no upper clamp).
func (f *PortForward) maxFlows() int {
	if f.MaxFlows <= 0 {
		return DefaultMaxFlows
	}
	return f.MaxFlows
}

// checkIngress is the bind check of both Serve calls (M6-D22, plan:58,
// M4-D44): an address that is not a loopback address — an unspecified
// one included — is ErrNonLoopback unless AllowNonLoopback; a Unix-domain
// address counts as loopback.
func (f *PortForward) checkIngress(a net.Addr) error {
	if f.AllowNonLoopback || isLoopbackAddr(a) {
		return nil
	}
	return ErrNonLoopback
}

// isLoopbackAddr reports whether a is a loopback address (an IPv4-mapped
// one included) or a Unix-domain address. A nil address, an unspecified
// one and anything else are not.
func isLoopbackAddr(a net.Addr) bool {
	var ip net.IP
	switch v := a.(type) {
	case nil:
		return false
	case *net.UnixAddr:
		return v != nil
	case *net.UDPAddr:
		if v == nil {
			return false
		}
		ip = v.IP
	case *net.TCPAddr:
		if v == nil {
			return false
		}
		ip = v.IP
	case *net.IPAddr:
		if v == nil {
			return false
		}
		ip = v.IP
	default:
		ap, err := netip.ParseAddrPort(a.String())
		return err == nil && ap.Addr().Unmap().IsLoopback()
	}
	addr, ok := netip.AddrFromSlice(ip)
	return ok && addr.Unmap().IsLoopback()
}

// isNilAddr reports whether a is no address: nil, or a nil *net.UDPAddr
// (an unconnected socket's RemoteAddr).
func isNilAddr(a net.Addr) bool {
	switch v := a.(type) {
	case nil:
		return true
	case *net.UDPAddr:
		return v == nil
	}
	return false
}

// FlowState is a UDP flow's state in a PortForward's table.
type FlowState uint8

// UDP flow states.
const (
	FlowOpening FlowState = iota + 1 // DialUDP running
	FlowOpen                         // forwarding
	FlowHeld                         // its open failed; the client's datagrams are dropped until the hold ends
)

// FlowInfo describes one UDP flow.
type FlowInfo struct {
	Client  netip.AddrPort      // the source address the flow maps, as the socket reported it
	Target  string              // its ServeUDP's target
	State   FlowState           // opening, open or held
	Stream  bool                // the flow became a stream at this end
	Since   time.Time           // its first datagram
	Last    time.Time           // its last datagram in either direction
	Session rendr.SessionStatus // zero unless State is FlowOpen
}

// PortForwardStatus counts what a PortForward does, TCP and UDP apart.
type PortForwardStatus struct {
	TCP TCPForwardStatus // ServeTCP's connections
	UDP UDPForwardStatus // ServeUDP's flows
}

// TCPForwardStatus counts a PortForward's TCP connections.
type TCPForwardStatus struct {
	Live                      int                   // connections being dialled or forwarded (MaxConns units)
	Accepted, Refused, Failed uint64                // Refused: beyond MaxConns; Failed: Dial errors (typed ones in ByCode)
	ByCode                    map[RejectCode]uint64 // Failed by code (the l4 Server's refusals)
	AcceptNoise               uint64                // temporary Accept errors, backed off
	LastErr                   error                 // the latest Dial error
}

// UDPForwardStatus counts a PortForward's UDP flows.
type UDPForwardStatus struct {
	Flows, Opening, Held       int                   // open flows; flows being opened; held clients
	Opened, Failed             uint64                // sessions opened; opens that failed (typed refusals in ByCode)
	Evicted, Replaced          uint64                // flows ended to make room; flows reopened at an expiry race
	ByCode                     map[RejectCode]uint64 // Failed by code (the l4 Server's refusals)
	Ended                      FlowEnds              // ended flows by cause
	ToSession, ToClient        uint64                // datagrams
	FirstInOpen                uint64                // first datagrams that rode the OPEN
	TooLarge                   uint64                // client datagrams above their flow's MaxPayload, dropped
	TooLargeMax                int                   // the largest of them (the ingress reads whole datagrams)
	MaxPayload                 int                   // the MaxPayload of the latest flow opened (0 before any)
	DropFull, DropOpening      uint64                // a new client while the table had no victim; the opening stage full
	DropOpenQueue, DropOpenAge uint64                // an opening flow's queue overflowed; queued longer than 1 s
	DropHeld                   uint64                // datagrams of held clients
	ReadNoise                  uint64                // socket read errors of the noise classes, counted and backed off
	WriteNoise                 uint64                // replies the socket's write refused (any error: the reply is lost), counted and ignored
	SessionDrops               uint64                // datagrams the flows' sessions dropped (their PacketCounters' drop fields), summed at each flow's end
	LastErr                    error                 // the latest DialUDP error

	// SessionUnreported counts the datagrams the flows' sessions handed to
	// a carrier and the peer never reported received (PacketCounters.Sent
	// − PeerReceived), summed at each flow end the peer or the path
	// decided (Ended.PeerIdle, NoPath, SessionLost, GoingAway): lost in
	// flight or with the peer's session. An upper bound: a datagram the
	// peer received in its last report delay before the end counts too
	// (see the package doc, "UDP flows").
	SessionUnreported uint64
}
