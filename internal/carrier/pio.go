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
// SetWriteDeadline) only by the writer goroutine and, before Start or for a
// refusal, by the handshake and the closer; SetPeer by the writer or the
// reader (a rebind commits in the reader, M2-D27; implementations guard the
// peer with their own lock); SetLimit only before Start (Conn.SetBudget);
// SetDeadline, Close and Limit by any goroutine. The I/O contract is M2
// design §A6.4.
type PacketIO interface {
	// ReadSize is the buffer length ReadDatagram needs: the current
	// receive limit (Limit() until SetLimit lowered it) + 1 (truncation
	// detection, plan:634) + Headroom. Callers pass a buffer of at least
	// ReadSize() bytes; the transport reads into its first ReadSize() bytes,
	// so the caller and the transport judge truncation against the same
	// length (M2 design Revision 1, R1-6). Flows return 0: they hand out
	// their inbox buffers instead (see Release) and apply the receive limit
	// themselves.
	ReadSize() int
	// SetLimit lowers the receive limit to n rendr bytes
	// (wire.MinFrameBudget ≤ n ≤ Limit()): a longer datagram is then
	// ReadTruncated, and ReadSize follows. Conn.SetBudget calls it once with
	// the negotiated cmtu before Start (R1-6); Limit keeps reporting the
	// transport's capacity.
	SetLimit(n int)
	// ReadDatagram reads the next datagram into buf (flows ignore buf and
	// return an inbox buffer) and returns its rendr bytes — the flow header
	// already removed — aliasing that buffer, valid until the next call or
	// Release. ev reports a datagram that was not handed over (empty,
	// truncated, foreign source, bad flow header) or a transient error
	// (ReadNoise: back off 5–100 ms, keep reading); ReadCandidate is a valid
	// datagram from a new source on a transport that can rebind. A non-nil
	// err ends the carrier (transport_error), e.g. after Close, except the
	// expiry of a read deadline its caller set (handshake, closer), which
	// the caller recognises by errors.Is(err, os.ErrDeadlineExceeded) as
	// the net.PacketConn contract defines it — never by Timeout(), which a
	// dead conn may report too (quic-go's idle timeout; integration 1).
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
	// SetPeer makes dst the current peer (a committed rebind, called by the
	// reader or the writer); ErrNoRebind on transports that cannot rebind.
	SetPeer(dst PeerKey) error
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	// Close unblocks every call and releases the transport exactly once
	// (a flow leaves its source's table; the shared socket stays open).
	Close() error
	// Limit is the largest rendr datagram (after the flow header) the
	// transport can receive — its capacity, used for the cmtu offer and
	// cmtu_acc: a flow's socket MaxDatagram − 9; an *OwnedUDP's MaxDatagram
	// − 9 (carrier/udp clamps MaxDatagram to the route's interface MTU at
	// Dial, R1-16); the limit given to NewPacketIO for embedder conns
	// (wire.MaxDatagram when unknown).
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
	// ErrNoise: a transient datagram error (ICMP class, ENOBUFS, a local
	// packet filter's refusal of a send); the datagram is lost, the carrier
	// lives.
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
// the transport's Limit and its initial receive limit: the factory MTU on
// a dialer, wire.MaxDatagram for Listener.HandlePacket (unknown); the
// negotiated cmtu lowers the receive limit later (SetLimit, R1-6), so a
// started carrier reads with cmtu + 1 bytes. Transport errors are
// classified by one table on every OS (M2 design §A6.4, Revision 1, R1-28):
// the Windows errnos (WSAEMSGSIZE 10040, WSAENETRESET 10052,
// WSAECONNABORTED 10053, WSAECONNRESET 10054) and the POSIX ones match
// everywhere, so an embedder conn — or the in-memory fake — behaves the same
// on every host. As on rendr's own sockets (integration 1), EPERM on a
// write is noise (a local packet filter dropped the datagram; a refusal
// that persists ends the carrier by ping_timeout) and death on a read, and
// an error matching ErrNoise or reporting Temporary() is noise on reads
// and writes; the caller's own deadline is recognised by
// errors.Is(err, os.ErrDeadlineExceeded), never by Timeout(), which a dead
// conn may report too. NewPacketIO fails for a nil pc or peer and for a
// peer whose String panics. Ownership of pc moves to the result only on
// success (L57).
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
