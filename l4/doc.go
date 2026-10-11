// Package l4 carries TCP connections over rendr stream sessions. A dialer
// opens one session per connection with Dial, naming the target in the
// OPEN's metadata; a passive Runtime runs a Server on a Listener, which dials
// each target while its session is pending, confirms on success or rejects
// with one of the RejectCode values, and forwards bytes both ways. Forward
// is the forwarder on both ends: half-closes cross in both directions; a
// reset or failure on either side becomes a reset on the other, never a
// clean end of stream; a session that ends releases its socket at once,
// also when the socket's peer ignores FIN or never reads. Sessions are
// idle-limited to DefaultIdleTimeout unless changed. The package does no
// authentication: a Server dials whatever a dialer asks for unless its Dial
// hook refuses (ErrDenied) — the default dials any address the host can
// reach, its loopback and private networks included; policy that must hold
// for every path to an address checks the resolved address
// (net.Dialer.Control), not Request.Addr. After local's FIN, Forward
// reads nothing more from local, so a later close of local is not
// observable (TCP sends nothing for it): such a session ends when the far
// side ends it, at its idle limit, or when ctx ends.
//
// # Metadata
//
// The OPEN's metadata is the L4 header, version 1, followed by the
// application's own metadata (Request.App, DialOptions.Metadata on Dial):
//
//	"L4" | version 1 | command 1 (CONNECT) | atyp | address | port (u16, big-endian) | app
//
// with SOCKS5's address types: 1 IPv4 (4 bytes), 4 IPv6 (16 bytes), 3 a
// domain (a length byte, then the name). Every target has exactly one
// encoding and ParseMetadata accepts nothing else: an IPv4-mapped IPv6
// address travels as IPv4; unspecified, multicast and limited-broadcast
// addresses, IPv6 zones and port 0 are refused; a domain is labels of 1–63
// bytes from [A-Za-z0-9_-] joined by single dots, at most 253 bytes plus an
// optional trailing dot (kept as given), whose last label is neither all
// digits nor 0x-hex (names resolvers would read as an IPv4 address, such as
// "127.1"). The dialer resolves nothing: a name is resolved by the passive,
// with its DNS view. The header is at most 262 bytes, and the whole
// metadata stays within Handshake.MaxMetadata (4 KiB by default, checked
// before any network I/O). The destination travels only in the OPEN, never
// in a JOIN, a migration or a retry. Match tells L4 sessions apart on a
// Listener shared with other sessions; Server.Handle serves those.
//
// # Ends of a forwarded connection
//
//	At either end                         Forward does                      The far end sees
//	local read → io.EOF (FIN)              Conn.CloseWrite                   FIN after every byte
//	local read or write → other error      Conn.Abort(AbortReset); reset     RST
//	session read → io.EOF                  CloseWrite on local (if offered)  FIN after every byte
//	session error (abort, idle, no path)   reset local                       RST
//	ctx done                               Conn.Abort(AbortShutdown); reset  RST at both far ends
//	carrier death, migration               nothing                           nothing
//
// A reset is SetLinger(0) and Close where the local conn offers it, else a
// plain Close. A reset decided on the dialer while no carrier is alive
// (its local conn resets during an outage) has no path to travel, even if
// one returns at once: it reaches the passive as rendr.ErrNoPath once the
// passive's PassiveRetain runs out (the dialer's NoPathGrace + PingIdle +
// DeadMax + 5 s, 34 s with the defaults, counted from the passive's loss of
// its last carrier), and the target is reset then: late, but never a clean
// end. The opposite direction keeps its code: a reset decided on the
// passive while no carrier is alive (its target resets during an outage)
// reaches the dialer as a *rendr.AbortError with that code once a stream
// carrier returns while the ended session's tombstone lasts, because the
// tombstone answers the dialer's rejoin with the code.
//
// A dial that fails reaches the dialer as a *rendr.RejectError whose
// CodeOf is the class of the failure (refused, unreachable, timeout, name
// not found, …); its message is the code's fixed text, never the raw
// error, which stays on the passive (ServerStatus.LastErr). The message is
// empty when the refusal is repeated for an OPEN retried on a shared
// carrier (after a carrier death took the first answer down): such a
// repeat carries the code only. The code is what to act on.
//
// # Bounds and memory
//
// Target dials in flight are bounded by the Listener's AcceptBacklog, each
// by Server.DialTimeout and the pending session's AcceptTimeout; a Server
// dials for and forwards at most Server.MaxConns connections and runs at
// most 192 custom Dial hook calls at once, abandoned ones included. A
// forwarded connection costs three goroutines and 64 KiB of pooled
// buffers on top of its session's windows: at the default MaxConns of
// 10,000 that is ≈ 880 MiB, so deployments size MaxConns to their memory.
// A silent connection ends at its idle limit (DefaultIdleTimeout, on both
// ends).
package l4
