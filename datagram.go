package rendr

import (
	"context"
	"net"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
)

// DatagramCarrier is a factory of datagram carriers to the Peer's rendr
// instance: a net.PacketConn plus the peer address rendr writes to (an L7
// datagram tunnel, a QUIC DATAGRAM connection from the quic module, a raw
// UDP socket from carrier/udp). rendr treats both as untrusted, as
// StreamCarrier: calls are bounded by DialTimeout even when ctx is ignored,
// panics and Goexit are contained, (nil, _, nil) and (pc, nil, nil) are
// errors (pc is closed once), a conn returned late is closed exactly once,
// and conns are used only through the net.PacketConn interface, except the
// sockets package carrier/udp creates.
//
// rendr reads with pc.ReadFrom (datagrams from any source other than peer
// are dropped and counted) and writes every datagram with
// pc.WriteTo(b, peer), so pc must not be a connected UDP socket. One WriteTo
// is one datagram: the conn delivers it whole or not at all and never
// splits or merges datagrams (embedding contract, plan:59). A WriteTo
// refused because the datagram is too large must return an error matching
// ErrDatagramTooLarge (DatagramTooLargeError): the carrier then lowers its
// budget instead of dying. ReadFrom returning (0, addr, nil) is an empty
// datagram, not an error. The conn's own keepalives and idle timeouts must
// exceed PassiveRetain (embedding contract, L26).
//
// Datagram carriers built here serve a passive that uses
// Listener.HandlePacket; carrier/udp's carriers serve a passive that uses
// FromPacketConn (they prefix each datagram with rendr's raw-UDP flow
// header).
type DatagramCarrier struct {
	// Name identifies the factory in Status, PeerStatus and ranking ties;
	// unique and non-empty within a Peer.
	Name string
	// Dial opens one carrier. Required.
	Dial func(ctx context.Context) (net.PacketConn, net.Addr, error)
	// MTU is the largest datagram rendr passes to one WriteTo, in bytes —
	// the carrier's frame budget offer: required, 537–65,507 (NewPeer
	// rejects other values). A packet session carries application datagrams
	// of up to MTU − 25 bytes on it. The quic module sets 1152; carrier/udp
	// sets its MaxDatagram − 9 (its sockets add the 9-byte flow header
	// themselves).
	MTU int
}

func (DatagramCarrier) isCarrier() {}

// packetSource is a FromPacketConn source.
type packetSource struct{ pc net.PacketConn }

func (packetSource) isSource() {}

// FromPacketConn is a pull source of raw-UDP datagram carriers: one
// goroutine reads pc and demultiplexes the datagrams by rendr's 64-bit flow
// ID (the 9-byte flow header carrier/udp's dialers put in front of every
// datagram). A datagram of an unknown flow creates a flow only when it is a
// complete valid first datagram of a carrier; anything else is dropped and
// counted, and nothing is allocated for it. Flows are bounded: at most 32
// admitting flows per source IP address and MaxSessions ×
// MaxCarriersPerSession + Sessionless.Total + Handshake.MaxConcurrent
// flows in all (at most 65,536); every flow's inbox holds at most 512
// datagrams (see Status.Datagram).
//
// Ownership of pc moves to the Listener: Listener.Close stops admitting new
// flows (a new carrier is refused with CAPACITY) and closes pc once its
// last flow ended, so accepted sessions keep their carriers; Runtime.Close
// closes it at once. A pc from carrier/udp's Listen gets allocation-free
// reads and writes and truncation detection; any other net.PacketConn is
// used through its methods only (its ReadFrom may allocate an address per
// datagram).
func FromPacketConn(pc net.PacketConn) Source { return packetSource{pc: pc} }

// HandlePacket pushes one embedder-accepted datagram carrier — a
// net.PacketConn whose datagrams come only from peer, such as a QUIC
// connection's DATAGRAM facade or a per-peer tunnel — into the handshake and
// returns at once. rendr reads with ReadFrom (datagrams from any other
// source are dropped) and writes with WriteTo(b, peer); the conn contract of
// DatagramCarrier applies. On success the Listener owns pc and closes it
// when the carrier ends. On an error — a nil pc or peer, a peer address
// whose String panics, the Listener closed — pc stays the caller's and is
// not closed (unlike Handle, which closes its conn after Close; L57).
func (ln *Listener) HandlePacket(pc net.PacketConn, peer net.Addr) error {
	panic("unimplemented: M2")
}

// DialInfo describes the carrier a factory call is for.
type DialInfo struct {
	Carrier CarrierID // the CarrierID this attempt uses (it appears in Status on both ends)
	Kind    Kind      // the factory's kind
	Probe   bool      // a probe carrier of the Peer health layer (no session)
	Session SessionID // the session the carrier is for; zero for probes
}

// CarrierDialInfo returns the DialInfo of the factory call whose context
// this is (StreamCarrier.Dial and DialEarly, DatagramCarrier.Dial) and true,
// or false for any other context. It lets an embedder label its tunnel
// requests and logs with rendr's carrier and session IDs.
func CarrierDialInfo(ctx context.Context) (DialInfo, bool) {
	d, ok := carrier.DialInfoFrom(ctx)
	if !ok {
		return DialInfo{}, false
	}
	return DialInfo{Carrier: CarrierID(d.Carrier), Kind: Kind(d.Kind), Probe: d.Probe, Session: SessionID(d.Session)}, true
}
