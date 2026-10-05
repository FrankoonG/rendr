package carrier

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"time"
)

// PacketIO is the transport of one datagram carrier (M2-D4): exactly one
// peer, one datagram per call. Three implementations exist: *OwnedUDP (a
// carrier/udp dialer socket, recognised by its exact type: L57), the
// adapter NewPacketIO returns for an embedder net.PacketConn (DatagramCarrier
// factories, Listener.HandlePacket, the quic module's DATAGRAM facade), and
// *udpflow.Flow (a flow of a shared FromPacketConn socket).
//
// The reader half (ReadSize, ReadDatagram, Release, SetReadDeadline) is
// called only by the carrier's reader goroutine and, before Start, by the
// handshake; the writer half (Headroom, WriteDatagram, WriteDatagramTo,
// SetPeer, SetWriteDeadline) only by the writer goroutine and, before Start
// or for a refusal, by the handshake and the closer; SetDeadline, Close and
// Limit by any goroutine. The I/O contract is M2 design §A6.4.
type PacketIO interface {
	// ReadSize is the buffer length ReadDatagram needs: the receive limit
	// + 1 (truncation detection, plan:634) + Headroom. Flows return 0: they
	// hand out their inbox buffers instead (see Release).
	ReadSize() int
	// ReadDatagram reads the next datagram into buf (flows ignore buf and
	// return an inbox buffer) and returns its rendr bytes — the flow header
	// already removed — aliasing that buffer, valid until the next call or
	// Release. ev reports a datagram that was not handed over (empty,
	// truncated, foreign source, bad flow header) or a transient error
	// (ReadNoise: back off 5–100 ms, keep reading); ReadCandidate is a valid
	// datagram from a new source on a transport that can rebind. A non-nil
	// err ends the carrier (transport_error), e.g. after Close.
	ReadDatagram(buf []byte) (data []byte, src PeerKey, ev ReadEvent, err error)
	// Release returns the buffer of the last ReadDatagram to its owner
	// (flows); a no-op otherwise.
	Release()
	// Headroom is the number of bytes WriteDatagram fills in front of the
	// rendr bytes itself (wire.FlowHeaderLen for raw-UDP flow carriers, else
	// 0): the writer builds every datagram in one scratch after this many
	// bytes, so a datagram is copied once.
	Headroom() int
	// WriteDatagram sends b[Headroom():] as one datagram to the current
	// peer, filling b[:Headroom()] itself. nil: sent whole. An error
	// matching wire.ErrDatagramTooLarge refuses this datagram only (the
	// carrier lives, M2-D25); ErrNoise loses this datagram only; any other
	// error, and an invalid count, ends the carrier (L42: never retried on
	// it).
	WriteDatagram(b []byte) error
	// WriteDatagramTo sends b to dst instead of the current peer (a rebind
	// challenge, M2-D27); ErrNoRebind on transports that cannot rebind.
	WriteDatagramTo(b []byte, dst PeerKey) error
	// SetPeer makes dst the current peer (a committed rebind); ErrNoRebind
	// on transports that cannot rebind.
	SetPeer(dst PeerKey) error
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	// Close unblocks every call and releases the transport exactly once
	// (a flow leaves its source's table; the shared socket stays open).
	Close() error
	// Limit is the largest rendr datagram (after the flow header) the
	// transport can receive: a flow's socket MaxDatagram − 9; an *OwnedUDP's
	// MaxDatagram − 9; wire.MaxDatagram for embedder conns (unknown).
	Limit() int
}

// ReadEvent classifies a datagram ReadDatagram did not hand over as an
// ordinary datagram of the current peer (M2-D15).
type ReadEvent uint8

// Read events.
const (
	ReadOK          ReadEvent = iota // a datagram from the current peer
	ReadCandidate                    // a datagram from a new source on a rebindable transport (a rebind candidate, M2-D27)
	ReadEmpty                        // zero bytes: dropped, never a death (unlike a stream carrier's (0, nil), PA-18)
	ReadTruncated                    // longer than the receive limit, MSG_TRUNC or WSAEMSGSIZE: dropped (L58)
	ReadForeign                      // from another source on a transport that cannot rebind: dropped (L59)
	ReadBadEnvelope                  // a raw-UDP datagram without a valid flow header for this flow: dropped
	ReadNoise                        // an ICMP-class or temporary read error: back off, keep reading (L58, plan:638)
)

// PeerKey identifies a datagram source (M2-D15): an AddrPort for rendr's
// own sockets and *net.UDPAddr sources; for any other net.Addr type its
// String() taken once under a panic guard (L38, L57). It is comparable.
type PeerKey struct {
	AP  netip.AddrPort
	Str string
}

var (
	// ErrNoRebind: the transport cannot change its peer.
	ErrNoRebind = errors.New("rendr/carrier: the transport cannot rebind")
	// ErrNoise: a transient datagram error (ICMP class, ENOBUFS); the
	// datagram is lost, the carrier lives.
	ErrNoise = errors.New("rendr/carrier: transient datagram error")
)

// DgramStats are the Runtime-wide datagram counters (rendr.Status.Datagram):
// every datagram carrier and every udpflow source adds to them.
type DgramStats struct {
	Dropped    atomic.Uint64 // datagrams and frames dropped by sources and datagram carriers
	Truncated  atomic.Uint64 // of Dropped: truncated or oversize datagrams
	InboxDrops atomic.Uint64 // datagrams a full or refused flow inbox dropped
	ReadErrors atomic.Uint64 // transient read errors (noise) of sources and datagram carriers
	Rebinds    atomic.Uint64 // committed rebinds of raw-UDP flows
}

// NewPacketIO adapts an embedder net.PacketConn whose datagrams come from
// peer (M2-D4, L57): interface methods only, each through the guarded call
// wrappers (panic and Goexit contained, counts checked); peer is normalised
// once into a PeerKey (pointer identity first, then *net.UDPAddr → AddrPort,
// else a guarded String()); datagrams from other sources are ReadForeign;
// WriteDatagram always passes the original peer value to WriteTo. limit is
// the receive limit (the negotiated cmtu; wire.MaxDatagram while unknown).
// Errors: a nil pc or peer, a peer whose String panics. Ownership of pc
// moves to the result only on success (L57).
func NewPacketIO(env *Env, pc net.PacketConn, peer net.Addr, limit int) (PacketIO, error) {
	panic("unimplemented: M2")
}

// GuardedDialPacket calls a datagram factory under the GuardedDial rules
// (DialTimeout + dialGrace even when ctx is ignored, panic and Goexit
// contained, an abandoned call counted, ErrAbandonFull fail-fast; a late
// result closed exactly once). (nil, _, nil) and (pc, nil, nil) are
// ErrNilConn, with pc closed once.
func GuardedDialPacket(ctx context.Context, env *Env, f func(context.Context) (net.PacketConn, net.Addr, error)) (net.PacketConn, net.Addr, error) {
	panic("unimplemented: M2")
}
