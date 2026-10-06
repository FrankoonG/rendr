package carrier

import (
	"errors"
	"os"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// PacketErrClass is the class of an error that an embedder net.PacketConn
// returned, in the datagram I/O contract (M2 design §A6.4).
type PacketErrClass uint8

// Packet error classes.
const (
	// PacketErrDeath: any other error, net.ErrClosed and QUIC close errors
	// included: the carrier ends (transport_error), or the udpflow source
	// stops.
	PacketErrDeath PacketErrClass = iota
	// PacketErrNoise: an ICMP-class error, ENOBUFS, an error matching
	// ErrNoise or reporting Temporary(), and on a write EPERM (a local
	// packet filter's drop): the datagram or the read is lost, the carrier
	// lives (a read backs off 5 → 100 ms).
	PacketErrNoise
	// PacketErrSize: EMSGSIZE or WSAEMSGSIZE, or on a write an error
	// matching wire.ErrDatagramTooLarge: a write refused as too large (its
	// Max, if any, by errors.As), a read truncated.
	PacketErrSize
	// PacketErrAbort: ECONNABORTED or WSAECONNABORTED (udp_diag
	// SOCK_DESTROY): death for a carrier's own conn, noise for a shared
	// listening socket (a udpflow source).
	PacketErrAbort
	// PacketErrDeadline: the caller's own deadline expired
	// (errors.Is(err, os.ErrDeadlineExceeded), never Timeout()).
	PacketErrDeadline
)

// ClassifyPacketErr classifies err, returned by an embedder conn's ReadFrom
// (write false) or WriteTo (write true), by the one table of every OS (M2
// design §A6.4, Revision 1, R1-28; EPERM on a write since integration 1):
// the POSIX errnos of the build platform and the Windows errnos WSAEMSGSIZE
// (10040), WSAENETUNREACH (10051), WSAENETRESET (10052), WSAECONNABORTED
// (10053), WSAECONNRESET (10054), WSAENOBUFS (10055), WSAECONNREFUSED
// (10061), WSAEHOSTDOWN (10064) and WSAEHOSTUNREACH (10065) match on every
// OS, so an embedder conn — or the in-memory fake — is classified the same
// on every host. A deadline comes first (an expired deadline may also
// report Temporary()), then the errno table, then ErrNoise and
// Temporary(). err is not nil. NewPacketIO and udpflow's foreign conns use
// it; rendr's own sockets keep their per-OS tables (owned_udp_*.go).
func ClassifyPacketErr(err error, write bool) PacketErrClass {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return PacketErrDeadline
	}
	if c, ok := packetErrnoClass(err, write); ok {
		return c
	}
	if write && errors.Is(err, wire.ErrDatagramTooLarge) {
		return PacketErrSize
	}
	if errors.Is(err, ErrNoise) {
		return PacketErrNoise
	}
	var t interface{ Temporary() bool }
	if errors.As(err, &t) && t.Temporary() {
		return PacketErrNoise
	}
	return PacketErrDeath
}
