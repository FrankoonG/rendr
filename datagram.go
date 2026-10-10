package rendr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
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
	// themselves), clamped in advance to the interface MTU for an IP
	// literal.
	//
	// MTU should be what every carrier of the factory carries: DialPacket's
	// metadata check (an OPEN takes MTU − 99 bytes of metadata at most), the
	// MaxPayload offer and the opening race read it before any carrier
	// exists. A carrier whose transport carries less (a carrier/udp socket
	// clamped at Dial to its interface MTU) offers its own lower budget.
	// When the session's MaxPayload offer came from the datagram factories'
	// budgets (a selector session, or a bond session without a
	// StreamCarrier) that carrier's OPEN lowers it to the carrier's budget
	// − 25, so the session's MaxPayload still fits the carrier that opened
	// it; a bond session with a StreamCarrier keeps Packet.MaxPayload for
	// its stream carriers. Metadata that fits MTU but not such a carrier's
	// budget ends DialPacket with ErrMetadataTooLarge once NoPathGrace
	// passed (on a Peer without a StreamCarrier), instead of at once.
	MTU int
	// Props describe the factory to the scheduler: fate group, cheap
	// subflows, head-of-line coupling. The zero value shares the factory's
	// carriers between the Peer's packet sessions in a fate group of its
	// own.
	Props Props
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
// admitting flows per source IP address for OPENs and 32 for JOINs and
// probes, and MaxSessions × MaxCarriersPerSession + Sessionless.Total +
// Handshake.MaxConcurrent flows in all (at most 65,536); every flow's
// inbox holds at most 512 datagrams (see Status.Datagram). A flow is
// admitting from its first datagram until a positive verdict was written
// for it or, for an OPEN, until its dialer answered the address check of
// the passive's first answer, which proves that the source receives the
// passive's datagrams: a pending session whose dialer answered it waits
// for Accept in the Listener's AcceptBacklog, not in its address's quota,
// so the dialers behind one NAT address never starve each other, while a
// source that never reads the answers (a blind or spoofed flood) keeps at
// most 32 OPEN flows, pending sessions included. The per-address quota
// therefore protects the backlog only against blind floods: a source that
// answers the check is bounded like a stream Listener's clients — by
// AcceptBacklog per session kind, MaxSessions and the flow bound above —
// so one such address can hold the whole packet backlog, and further
// OPENs, from any address, are then answered CAPACITY. A datagram beyond a
// quota is dropped silently.
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
	switch {
	case pc == nil:
		return errNilPacketConn
	case peer == nil:
		return errNilPeer
	}
	// The receive limit is unknown (any offer is accepted, M2-D60); the
	// negotiated budget lowers it before the carrier starts (R1-6). A peer
	// whose String panics fails here, and pc stays the caller's (L57).
	io, err := carrier.NewPacketIO(&ln.rt.cenv, pc, peer, wire.MaxDatagram)
	if err != nil {
		return fmt.Errorf("rendr: HandlePacket: %w", err)
	}
	if !ln.beginHandshake() {
		return net.ErrClosed // unlike Handle, pc stays the caller's (M2-D57)
	}
	ln.rt.startHandshakeDatagram(ln, io, time.Now())
	return nil
}

// Errors of HandlePacket (pc stays the caller's).
var (
	errNilPacketConn = errors.New("rendr: HandlePacket: nil net.PacketConn")
	errNilPeer       = errors.New("rendr: HandlePacket: nil peer address")
)

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
	k := Kind(d.Kind)
	if k == 0 {
		k = KindStream // a factory without an explicit kind is a stream factory
	}
	return DialInfo{Carrier: CarrierID(d.Carrier), Kind: k, Probe: d.Probe, Session: SessionID(d.Session)}, true
}
