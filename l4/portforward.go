package l4

import (
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/FrankoonG/rendr/v2"
)

// UDPSocket is the socket PortForward.ServeUDP reads and writes: an
// unconnected UDP socket bound to the ingress address. *net.UDPConn
// implements it. ServeUDP refuses a socket that also has a RemoteAddr
// method returning non-nil (a connected socket).
type UDPSocket interface {
	ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error)
	WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error)
	LocalAddr() net.Addr
	SetReadDeadline(t time.Time) error
	Close() error
}

// ErrNonLoopback: ServeTCP or ServeUDP was given a socket bound to a
// non-loopback or unspecified address without AllowNonLoopback.
var ErrNonLoopback = errors.New("l4: a non-loopback ingress requires PortForward.AllowNonLoopback")

// PortForward forwards local ports to targets reached through one Peer:
// every TCP connection that ServeTCP accepts becomes one stream session
// (Dial, then Forward); every UDP flow on a ServeUDP socket — the datagrams
// of one client source address — becomes one packet session (DialUDP, then
// forwarding), like a NAT mapping. Peer is required; the other fields have
// defaults. A PortForward must not be copied after first use. It does no
// authentication: whoever reaches an ingress socket reaches its target.
type PortForward struct {
	Peer    *rendr.Peer
	Options rendr.DialOptions // every session's Mode, Metadata (Request.App) and NoPathGrace; EarlyReturn applies to TCP only
	// AllowNonLoopback permits sockets bound to non-loopback or unspecified
	// addresses (a LAN-facing ingress). Without it Serve refuses them.
	AllowNonLoopback bool
	MaxConns         int           // TCP connections at once over every ServeTCP (0: DefaultMaxConns); one beyond is reset at once
	MaxFlows         int           // UDP flows at once over every ServeUDP, opening and held entries included (0 or less: DefaultMaxFlows)
	Idle             FlowIdle      // the UDP flows' classes (zero: the defaults)
	IdleTimeout      time.Duration // TCP sessions (0: DefaultIdleTimeout; negative: none), as l4.Dial and Server
}

// Status returns a snapshot of the PortForward's counters.
//
// Skeleton (M6 wave 0): every counter is zero.
func (f *PortForward) Status() PortForwardStatus { return PortForwardStatus{} }

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
	TCP TCPForwardStatus
	UDP UDPForwardStatus
}

// TCPForwardStatus counts a PortForward's TCP connections.
type TCPForwardStatus struct {
	Live                      int    // connections being forwarded
	Accepted, Refused, Failed uint64 // Refused: beyond MaxConns; Failed: Dial errors (typed ones in ByCode)
	ByCode                    map[RejectCode]uint64
	AcceptNoise               uint64 // temporary Accept errors, backed off
	LastErr                   error  // the latest Dial error
}

// UDPForwardStatus counts a PortForward's UDP flows.
type UDPForwardStatus struct {
	Flows, Opening, Held       int    // open flows; flows being opened; held clients
	Opened, Failed             uint64 // sessions opened; opens that failed (typed refusals in ByCode)
	Evicted, Replaced          uint64 // flows ended to make room; flows reopened at an expiry race
	ByCode                     map[RejectCode]uint64
	Ended                      FlowEnds
	ToSession, ToClient        uint64 // datagrams
	FirstInOpen                uint64 // first datagrams that rode the OPEN
	TooLarge                   uint64 // client datagrams above their flow's MaxPayload, dropped
	TooLargeMax                int    // the largest of them (the ingress reads whole datagrams)
	MaxPayload                 int    // the MaxPayload of the latest flow opened (0 before any)
	DropFull, DropOpening      uint64 // a new client while the table had no victim; the opening stage full
	DropOpenQueue, DropOpenAge uint64 // an opening flow's queue overflowed; queued longer than 1 s
	DropHeld                   uint64 // datagrams of held clients
	ReadNoise, WriteNoise      uint64 // socket errors of the noise classes, counted and ignored
	SessionDrops               uint64 // datagrams the flows' sessions dropped (their PacketCounters' drop fields), summed at each flow's end
	LastErr                    error  // the latest DialUDP error
}
