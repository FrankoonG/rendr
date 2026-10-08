// Package udp is rendr's built-in plaintext raw-UDP datagram carrier: a
// listening socket for rendr.FromPacketConn and a factory that opens one
// fresh, unconnected UDP socket per carrier (M2-D66; plan:634). Every
// datagram of a carrier starts with rendr's 9-byte flow header — version 2
// and the carrier's 64-bit flow ID, drawn from crypto/rand for every dial —
// so that one listening socket serves many carriers; the rest is rendr's
// own bytes (a carrier's first datagram carries its PREFACE right after the
// header). Sockets set don't-fragment with probe semantics (Linux
// IP_PMTUDISC_PROBE, Windows IP_DONTFRAGMENT): a datagram that does not fit
// the path is lost, never fragmented, and rendr's MTU probe turns a
// persistent misfit into a carrier death. Like carrier/tcp, the carrier is
// neither encrypted nor authenticated and refuses non-loopback addresses
// unless AllowNonLoopback is set; the flow ID is not authentication (L59).
//
// rendr recognises the sockets this package creates and reads and writes
// them without allocating per datagram, with exact truncation detection.
// Every other net.PacketConn, one that wraps a socket of this package
// included, is used only through its methods.
//
// # Threat model
//
// The flow ID keeps blind off-path injection out: a sender must guess 64
// random bits to reach a carrier at all. It is the only barrier, and it is
// no secret from anyone who sees the traffic: the frame CRC is public and
// any frame number ahead of the receive window is accepted, so a holder of a
// flow ID can kill its carrier with one forged datagram that breaks the
// protocol, or retire it with a forged CLOSE. Replies move to a new client
// address only after that address answered a random nonce (NAT rebinding,
// L59), so a replayed or blindly spoofed datagram never redirects them —
// but an on-path attacker that receives at the address it forges can answer,
// as with QUIC path validation. A captured first datagram replayed after
// the listener forgot the removed flow's ID (it remembers the ID for the
// longer of the handshake and dial timeouts plus two seconds) opens a
// pending session again. Damaged datagrams are dropped and counted, never a
// death: that keeps corrupting paths from churning carriers but is no
// protection against forgery. The defence is the embedder's authentication:
// use this carrier on loopback (the default), on a trusted network, or
// inside an authenticated channel (plan:361).
//
// # Sizes
//
// A listening socket's MaxDatagram should be at least every dialer's, else
// the handshake lowers a larger dialer budget to the listener's; either way
// nothing is truncated in steady state. A longer datagram that still
// arrives is dropped and counted, never delivered in part (L58).
package udp

import (
	"context"
	"errors"
	"net"

	"github.com/FrankoonG/rendr/v2"
)

// ErrNonLoopback is returned by Listen and by the factory's Dial for a
// non-loopback address without Options.AllowNonLoopback.
var ErrNonLoopback = errors.New("rendr/carrier/udp: non-loopback address requires AllowNonLoopback")

// DefaultMaxDatagram is the UDP payload size used when Options.MaxDatagram
// is 0: the IPv6 minimum MTU (1280) minus the IPv6 and UDP headers, which
// every path must carry. A packet session over it carries application
// datagrams of up to 1,198 bytes.
const DefaultMaxDatagram = 1232

// Options configure the built-in UDP carrier.
type Options struct {
	// AllowNonLoopback permits non-loopback addresses (see the package
	// documentation). Without it Listen binds only loopback IPs; with it a
	// wildcard listen is allowed but suits single-homed hosts only (replies
	// leave from the routing-chosen source address).
	AllowNonLoopback bool
	// MaxDatagram is the largest UDP payload rendr sends or accepts on the
	// socket, the 9-byte flow header included: 0 selects
	// DefaultMaxDatagram; else 546–65,507. The factory's
	// DatagramCarrier.MTU is MaxDatagram − 9, clamped in advance as Dial
	// clamps it when the address is an IP literal (see Carrier). A
	// listening socket should allow at least every dialer's value: the
	// carriers then agree on the dialer's (a larger dialer value is lowered
	// to the listener's at the handshake). A value above what the local interface carries is lowered
	// to it — by Dial to the MTU of the interface the route to the peer
	// uses (the loopback interface's for a loopback peer), by Listen on a
	// specific address to that address's interface MTU, minus the IP and
	// UDP headers — so the socket never refuses its own datagrams as too
	// large (M2 design Revision 1, R1-16); a wildcard Listen cannot know its
	// route and keeps the value.
	MaxDatagram int
	// ReadBuffer and WriteBuffer size the socket buffers, best effort: 0
	// selects 4 MiB and 1 MiB (on Linux raised past rmem_max/wmem_max with
	// the FORCE options when the process may).
	ReadBuffer, WriteBuffer int
}

// Listen opens a rendr-owned UDP socket on network ("udp", "udp4", "udp6")
// and address for rendr.FromPacketConn. Without AllowNonLoopback the
// address must be a loopback IP or a host name whose every address is
// loopback, checked before and after binding (ErrNonLoopback); an empty
// host (wildcard) requires AllowNonLoopback.
func Listen(network, address string, o Options) (net.PacketConn, error) {
	return listen(context.Background(), network, address, o)
}

// Carrier returns a DatagramCarrier named name whose every Dial resolves
// network/address (loopback only without AllowNonLoopback, as Listen),
// opens a fresh unconnected socket bound to the loopback address of the
// peer's family for a loopback peer (else the unspecified address) and an
// ephemeral port, draws a new flow ID and returns the socket — closed on
// every failure before Dial returns (L57) — and the peer as a
// *net.UDPAddr. An IPv6 link-local peer names its interface in the zone,
// by name or by index.
//
// MTU is MaxDatagram − 9 (0, which NewPeer rejects, for an invalid
// MaxDatagram), lowered to what the carriers will carry (W4 L3-1): for an
// IP literal that Dial accepts, Carrier applies Dial's interface clamp
// once, best effort (a route lookup, which sends nothing, and the
// interface table), so that DialPacket's metadata check, the MaxPayload
// offer and the opening race see the clamped budget. For a host name, or
// when the clamp at Dial is lower than the one Carrier saw (a route that
// changed), each carrier's own budget offer is the clamped one, and the
// OPEN's MaxPayload offer follows it (rendr.DatagramCarrier.MTU).
func Carrier(name, network, address string, o Options) rendr.DatagramCarrier {
	mtu := 0
	if m, err := o.maxDatagram(); err == nil {
		mtu = literalClamp(network, address, o.AllowNonLoopback, m) - flowHeaderLen
	}
	return rendr.DatagramCarrier{
		Name: name,
		MTU:  mtu,
		Dial: func(ctx context.Context) (net.PacketConn, net.Addr, error) { return dial(ctx, network, address, o) },
	}
}
