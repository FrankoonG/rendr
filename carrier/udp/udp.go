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
// no secret from anyone who sees the traffic. The frame CRC is public, and
// a frame inside the receive window is accepted on its CRC alone. A frame a
// window or more ahead moves the window only when its datagram also proves
// the jump — a PONG answering a PING of this carrier that is still
// outstanding, or the answer to the receiver's rebind challenge — and is
// dropped and counted otherwise. So a holder of a flow ID can still kill its
// carrier with one forged in-window frame that breaks the protocol, or
// retire it with a forged CLOSE. Replies move to a new client
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
//
// A packet session over this carrier carries application datagrams of up
// to MaxDatagram − 34 bytes (the flow header and rendr's datagram
// framing): 1,198 with the default, below what many UDP applications send
// — game-streaming video at its LAN packet size (about 1,400 bytes),
// WireGuard at its default MTU (1,452), the largest DNS answers with EDNS
// (1,232), every QUIC Initial (at least 1,200). A larger datagram is
// dropped and counted, never fragmented (package l4 counts it where it was
// read). To carry such applications, set MaxDatagram on both ends — every
// dialer's Carrier and the passive's Listen socket — to the smallest MTU
// on the path minus 28 (IPv4) or 48 (IPv6): 1,472 on a 1500-byte IPv4
// path carries datagrams of up to 1,438 bytes, 1,452 on IPv6 up to 1,418;
// size the application below that where it can be sized (a WireGuard MTU
// of at most MaxDatagram − 66). Dial lowers the value to the first hop's
// interface MTU by itself, but cannot see a smaller MTU further along the
// path, and too high is worse than too low: a datagram that fits the first
// hop but not a later one is lost (don't-fragment), and the carrier dies
// when its fourth MTU probe finds the three before it unanswered (about
// 40 s after it attached, at the default PacketPing) and is redialled
// with the same budget, again about every 40 s, because a packet
// session's MaxPayload is fixed at its OPEN and a failed probe does not
// lower it. Set the value from the real path MTU, and size ReadBuffer
// for the larger buffer class (see Options).
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
	// carriers then agree on the dialer's (a larger dialer value is
	// lowered to the listener's at the handshake). A value above what the
	// local interface carries is lowered to it — by Dial to the MTU of the
	// interface the route to the peer uses (the loopback interface's for a
	// loopback peer), by Listen on a specific address to that address's
	// interface MTU, minus the IP and UDP headers — so the socket never
	// refuses its own datagrams as too large (M2 design Revision 1, R1-16);
	// a wildcard Listen cannot know its route and keeps the value.
	MaxDatagram int
	// ReadBuffer and WriteBuffer size the socket buffers, best effort: 0
	// selects 4 MiB and 1 MiB (on Linux raised past rmem_max/wmem_max with
	// the FORCE options when the process may).
	//
	// A Listen socket's ReadBuffer also sizes what each carrier it serves
	// may queue in rendr: the datagrams that arrived for the carrier and
	// were not delivered yet. Each is held in a rendr buffer of the size
	// class of the socket's MaxDatagram whatever its length (2,112 bytes
	// at the default MaxDatagram, 16,448 at 9,000, 65,600 at 65,507; a
	// smaller one only while the memory budget refuses that class), and a
	// carrier queues a datagram while it holds fewer than 512 or its
	// buffers come to less than ReadBuffer bytes: it holds the larger of
	// 512 and ReadBuffer divided by the class, rounded up. The queue thus
	// follows the socket buffer the embedder sized, and a carrier whose
	// reader falls behind loses nothing while its queue holds less. The
	// default 4 MiB holds 1,986 datagrams at the default MaxDatagram (about
	// 20 ms at 100,000 a second) but only 512 at a MaxDatagram of 9,000 or
	// 65,507: with a large MaxDatagram, size ReadBuffer by its class. Queued
	// datagrams count in rendr.Status.BufferedBytes and stay within
	// Config.MaxBufferedBytes; one that finds its carrier's queue full, or
	// the budget used up, is dropped and counted in
	// rendr.Status.Datagram.InboxDrops. Any other net.PacketConn given to
	// rendr.FromPacketConn queues at most 512 datagrams per carrier.
	ReadBuffer, WriteBuffer int
	// MaxBatch is the most datagrams one send or receive system call moves
	// on Linux amd64/arm64 (sendmmsg, recvmmsg): 0 or a negative value
	// selects 32, 1 moves one datagram per call, values above 64 become 64;
	// a listening socket reads at most 32 per call. Batching never delays
	// a datagram: a writer sends what it has when it wakes. Other
	// platforms always move one datagram per call. rendr.Status.Datagram
	// counts the calls and the datagrams they moved (SendCalls,
	// SentDatagrams, RecvCalls, RecvDatagrams).
	MaxBatch int
}

// Listen opens a rendr-owned UDP socket on network ("udp", "udp4", "udp6")
// and address for rendr.FromPacketConn. Without AllowNonLoopback the
// address must be a loopback IP or a host name whose every address is
// loopback, checked before and after binding (ErrNonLoopback); an empty
// host (wildcard) requires AllowNonLoopback.
//
// A wildcard socket is single-homed: replies leave from the source address
// the routing table chooses, not necessarily the address a datagram
// arrived at (rendr does not use IP_PKTINFO). Bind a specific address on a
// multi-homed host.
//
// Each carrier the socket serves queues the datagrams its reader has not
// taken yet: at least 512, and as many as fit Options.ReadBuffer in
// buffers of the MaxDatagram size class. The per-carrier queue follows the
// read buffer, so size it for the longest pause of a carrier's reader as
// well as for the socket (see Options.ReadBuffer). The queued datagrams,
// and the queue's entries beyond its first 8, count in
// rendr.Status.BufferedBytes while they are held.
//
// Where the socket reads several datagrams per call (Linux amd64 and
// arm64, Options.MaxBatch other than 1: the default 0 selects 32), its
// source holds up to min(MaxBatch, 32) − 1 read buffers beyond its first,
// and a message header per read buffer, from its first read on and while
// datagrams arrive, counted in rendr.Status.BufferedBytes. Once its read
// has waited one to two seconds without a datagram it returns them and
// reads one datagram per call until the next arrives; the first read
// buffer holds no data while it waits and is not counted, so a listening
// socket adds nothing to BufferedBytes from two seconds after its last
// datagram, or after it began to read if none arrived, with or without
// sessions.
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
// changed), each carrier's own budget offer is the clamped one, and an
// OPEN whose MaxPayload offer came from the datagram factories' budgets
// follows it (rendr.DatagramCarrier.MTU).
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
