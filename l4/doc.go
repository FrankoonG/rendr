// Package l4 forwards TCP connections and UDP flows through rendr
// sessions. A TCP connection is one stream session; a UDP flow — the
// datagrams between one client source address and one target, like a NAT
// mapping — is one packet session. A dialer opens one session per
// connection with Dial, or per flow with DialUDP, naming the target in the
// OPEN's metadata; a passive Runtime runs a Server on a Listener, which
// dials each target while its session is pending, confirms on success or
// rejects with one of the RejectCode values, and forwards both ways (UDP
// flows only when Server.UDP is set). Forward and ForwardPacket are the
// forwarders on both ends. PortForward is a local ingress: it accepts TCP
// connections and reads UDP datagrams on local sockets and forwards each
// connection or flow to a target through one Peer.
//
// Forward, for TCP: half-closes cross in both directions; a reset or failure
// on either side becomes a reset on the other, never a clean end of stream;
// a session that ends releases its socket at once, also when the socket's
// peer ignores FIN or never reads. Sessions are idle-limited to
// DefaultIdleTimeout unless changed. After local's FIN, Forward reads
// nothing more from local, so a later close of local is not observable (TCP
// sends nothing for it): such a session ends when the far side ends it, at
// its idle limit, or when ctx ends.
//
// The package does no authentication: a Server dials whatever a dialer
// asks for unless its Dial hook refuses (ErrDenied) — the default dials
// any address the host can reach, its loopback and private networks
// included; policy that must hold for every path to an address checks the
// resolved address (net.Dialer.Control), not Request.Addr. A PortForward
// forwards whatever reaches its ports.
//
// # Metadata
//
// The OPEN's metadata is the L4 header, version 1, followed by a tail that
// depends on the command:
//
//	"L4" | version 1 | command | atyp | address | port (u16, big-endian) | tail
//	command 1    (CmdConnect, a TCP connection):  tail = app
//	command 0x11 (CmdUDP, a UDP flow):            tail = flen (u16) | first datagram (flen bytes) | app
//
// where app is the application's own metadata (Request.App,
// DialOptions.Metadata on Dial and DialUDP), with SOCKS5's address types:
// 1 IPv4 (4 bytes), 4 IPv6 (16 bytes), 3 a domain (a length byte, then the
// name). Every target has exactly one encoding and the parsers accept
// nothing else: an IPv4-mapped IPv6 address travels as IPv4; unspecified,
// multicast and limited-broadcast addresses, IPv6 zones and port 0 are
// refused; a domain is labels of 1–63 bytes from [A-Za-z0-9_-] joined by
// single dots, at most 253 bytes plus an optional trailing dot (kept as
// given), whose last label is neither all digits nor 0x-hex (names
// resolvers would read as an IPv4 address, such as "127.1"). A flen of 0
// is the only encoding of "no first datagram". ParseMetadata decodes
// CONNECT metadata only and ParseUDPMetadata UDP metadata only; each
// answers the other command, and every unknown one, CodeBadCommand, so the
// parser is the kind check (Handle uses ParseMetadata, HandleUDP
// ParseUDPMetadata). AppendMetadata encodes both. The dialer resolves
// nothing: a name is resolved by the passive, with its DNS view. The header
// is at most 262 bytes (264 with flen); a UDP flow's metadata is at most
// 65,535 bytes, and the first datagram rides in it only when the whole
// metadata stays within 438 bytes (see "UDP flows"). The whole metadata
// stays within Handshake.MaxMetadata (4 KiB by default, checked before any
// network I/O). The destination travels only in the OPEN, never in a JOIN,
// a migration or a retry. Match tells L4 sessions apart on a Listener
// shared with other sessions; Server.Handle and Server.HandleUDP serve
// those.
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
// # UDP flows
//
// A flow's datagrams keep their boundaries and are delivered at most once,
// possibly reordered, never retransmitted and never split. On the passive
// the Server connects one UDP socket per flow to the target (a name is
// resolved there), so the target sees one source address — the passive
// host's, with a port of the flow's own — for the flow's whole life,
// across every carrier death, migration, quality switch and carrier NAT
// rebinding, and only the target's datagrams reach the flow. In RFC 4787's
// terms mapping and filtering are address-and-port-dependent (a
// "symmetric" NAT): client-server protocols work; peer-to-peer hole
// punching does not, nor does a target that answers from another address
// or port. There is no hairpinning and no ICMP relay in either direction,
// and DSCP and ECN marks are not carried. Multicast and broadcast are not
// forwarded: the metadata rules refuse such targets, and the default UDP
// dialer refuses a name that resolves to one and turns SO_BROADCAST off,
// so the OS refuses a subnet-directed broadcast (Linux at the connect;
// Windows at the first send, so a flow whose OPEN carries no first datagram
// opens and counts its sends as TargetNoise); a Dial hook must do the same
// itself (see Security). Discovery that relies on them, such as a
// game-streaming client's automatic search for hosts, does not cross a
// forward: add hosts by address. A client whose own NAT gives it a new
// source port gets a new flow, and the old one idles out.
//
// DialUDP opens one flow's session; ForwardPacket forwards it to a
// connected datagram conn (both ends use it: Server.HandleUDP on the
// passive, an embedder's own ingress on the dialer); PortForward.ServeUDP
// does both for every client of a local socket. A flow ends only by
// idleness or with its session, never by a datagram. Each end judges its
// idle class on its own; the end whose limit runs out first ends the flow
// (rendr.ErrIdleTimeout there, a *rendr.AbortError with AbortIdle at the
// other end):
//
//	Class   Entered at an end                                          Idle limit
//	short   the session opened (the passive counts the first           FlowIdle.Short (30 s)
//	        datagram it wrote)
//	stream  within one activity period — a run of datagrams with no    FlowIdle.Stream (180 s),
//	        gap of 2 s or more — datagrams moved both ways, and the    set once, never undone
//	        period has lasted 2 s
//
// So a query and its answer (DNS) stay short and end 30 s after the answer,
// also when a client reuses its source port after a pause of 2 s or more (a
// new period); an unanswered sender stays short; a stream — game video with
// the client's pings, a VPN tunnel that carries traffic — becomes one within
// about 2 s; a flow that only exchanges keepalives (a quiet WireGuard
// tunnel's, every 25 s) stays short and lives while they come within Short,
// and in a full table it can make room for a new client (see Port
// forwarding): give such a tunnel a PortForward of its own. A negative
// FlowIdle field turns that class's idle end off; a negative Short turns
// off both. DialUDP alone sets DefaultFlowIdle on its session;
// ForwardPacket and PortForward apply the classes.
//
//	The flow ends by                        Seen at the other end         FlowEnds (this end; the other)
//	this end's idle limit (ErrIdleTimeout)  AbortIdle                     Idle; PeerIdle
//	this end's stop                         io.EOF                        Stopped; PeerClosed
//	an eviction at the ingress              io.EOF                        Evicted; PeerClosed
//	a fatal error of the passive's socket   io.EOF                        Local; PeerClosed
//	this end's Runtime.Close                AbortGoingAway                Stopped; GoingAway
//	no carrier for NoPathGrace              ErrNoPath (at PassiveRetain)  NoPath; NoPath
//	a restart of the passive                ErrSessionLost at the dialer  —; SessionLost
//
// On a datagram carrier that a Peer's sessions share, at a round trip of
// 100 ms or more, a burst of flows ending together can outlast the close
// bound, and a few of them end ErrSessionLost at the dialer instead of
// idle; the client's next datagram opens a new flow.
//
// After any end the ingress removes the flow, and the client's next
// datagram opens a new one — a new session, a new socket on the passive, a
// new source port at the target — as a NAT does when a mapping expires; a
// datagram that meets the end of its flow at the ingress opens the new flow
// itself (UDPForwardStatus.Replaced). The passive closes the flow's socket
// once, at the end. An ingress that stops while no carrier lives reaches
// the passive only at its PassiveRetain (34 s by default), which closes
// the flow's socket then.
//
// A datagram the ingress takes from a client, or the passive from a target,
// is delivered or counted: by the status counters (the drops and TooLarge of
// UDPForwardStatus and UDPServerStatus, the far end's write noise, and
// SessionDrops, the drops of the flows' sessions), or, after its session
// handed it to a carrier, as a loss in flight (which a carrier's or the
// network's counters show) or with the peer's session. At a flow end the
// peer or the path decided (PeerIdle, PeerClosed, NoPath, SessionLost,
// GoingAway) SessionUnreported adds the datagrams the session handed to a
// carrier that the peer had not reported received by then: those lost in
// flight or with the peer's session (one that crossed the peer's idle end
// or its close, or reached a restarted passive). It is an upper bound: a
// datagram the peer received after the last of its reports that arrived
// counts too — normally one within the peer's report delay before the end
// (its PacketPing, 1 s by default), more after a lost report (a lossy
// return path) — so lost ≤ SessionUnreported ≤ lost + those; after the
// peer's idle end it is exact unless a report was lost. An end this side
// decided adds nothing: what its session sent before reaches the peer
// ahead of the end. After a stop the session still sends or drops what it
// queued, so the ingress reads its drops at the session's end, at most
// 2.1 s after the close: the largest Packet.MaxAge, within which a session
// without a carrier drops what it held (a stop while no carrier lives
// takes that long). An evicted flow's drops are read at once: it was idle
// for at least 1 s, so its session holds none of its datagrams unless
// Packet.MaxAge exceeds 1 s. Either way, what a session whose carriers
// cannot take datagrams drops after that read is in no counter. A first
// datagram that rode an OPEN that failed counts DropHeld, though a passive
// may have written it to the target before its Confirm failed
// (UDPServerStatus.FirstSent and Unconfirmed count it there).
//
// The first datagram. DialUDP puts a flow's first datagram into the OPEN
// when the whole metadata stays within 438 bytes (a DNS query, a WireGuard
// handshake initiation, a STUN request; never a QUIC Initial): the Server
// writes it to the target before it confirms the session, so the target
// receives it one round trip earlier; a larger one follows the open. It is
// sent at most once. One that rides is sent with the OPEN whenever the OPEN
// is sent (after a carrier dial or retransmissions), so it can reach the
// target as late as the open completes (up to 12 s at a PortForward),
// outside Packet.MaxAge. A Peer with several factories that was unused for a
// while waits up to Probe.DialWait for its probes, and a factory whose
// datagram carriers are full (64 flows each) dials another, before the OPEN
// leaves. On a datagram carrier that a Peer's sessions already share, the
// passive sends a new flow's replies only once the dialer's first frame for
// the flow has arrived, about one round trip after its OPEN_ACK. There the
// first datagram still reaches the target one round trip earlier, but the
// first reply reaches the client earlier only by the time the target takes
// to answer, at most one round trip: an instant answer gains nothing, a
// resolver that takes a round trip or more gains the whole round trip. On a
// carrier dialled for the flow, or a CheapSubflow factory's, the first
// reply comes one round trip earlier too. Replies written meanwhile wait in
// the passive session's queue, within its Packet.Queue and Packet.MaxAge.
//
// Sizes. A flow's largest datagram is its session's MaxPayload, fixed at the
// OPEN: the smallest datagram budget among the Peer's datagram factories, 25
// bytes below their MTU, and never more than either side's
// Packet.MaxPayload. With carrier/udp's default MaxDatagram (1,232 bytes)
// that is 1,198; over QUIC DATAGRAM it is 1,127 and cannot be raised. Two
// shapes carry datagrams of up to Packet.MaxPayload (65,507 bytes by
// default) instead: a Peer with stream carriers only, with TCP's
// head-of-line latency, and a bond or race session on a Peer that also has
// stream factories, where the datagrams wider than the datagram carriers'
// budget ride the stream carriers, with that latency, and are not counted
// TooLarge (one that no live carrier can carry is dropped by the session,
// PacketCounters.DropTooLarge); a selector session on such a Peer keeps the
// datagram budget. Such a bond or race session opens on a datagram carrier,
// and its stream carrier joins about one round trip later: a wider datagram
// the dialer writes in between, a flow's first datagram included, is dropped
// (DropTooLarge), and the client must send it again; the flow lives on and
// carries the next one. A datagram above MaxPayload is never fragmented or
// split: it is dropped and counted where it was read — at the ingress
// (UDPForwardStatus.TooLarge, and TooLargeMax: the ingress reads whole
// datagrams), at the passive (UDPServerStatus.TooLarge), under ForwardPacket
// (PacketResult.TooLarge). The application sees loss, as on a path whose MTU
// is too small, and no ICMP. Common datagrams exceed the default:
// game-streaming video at its LAN packet size (about 1,400 bytes), WireGuard
// at its default MTU (1,452), the largest DNS answers with EDNS (1,232) and
// every QUIC Initial (at least 1,200: HTTP/3 through a default forward
// cannot handshake). To carry them, set udp.Options.MaxDatagram to the
// smallest MTU on the path minus 28 (IPv4) or 48 (IPv6) on the dialer's
// carriers and on the passive's listening socket: 1,472 on a 1500-byte path
// carries 1,438 bytes (a WireGuard MTU of up to 1,406). Too high is worse
// than too low (see package carrier/udp).
//
// Peers and modes. Put UDP forwards on a Peer with datagram carriers only,
// and TCP forwards on another: on a Peer that also has stream carriers,
// bond and race sessions also send datagrams on them (every one wider than
// the datagram carriers' budget among them, see Sizes), with TCP's
// head-of-line latency, and a selector session falls back to them when
// every datagram carrier is dead. For latency-sensitive streams (game
// streaming, voice): race when every path has spare capacity for the
// stream (a carrier's death loses nothing); selector otherwise (a killed
// carrier costs a gap below about 200 ms, a path that dies silently a few
// seconds of loss); bond only for a stream that one path cannot carry, over
// paths of similar round-trip time. Size every buffer a burst crosses: a
// burst from the target waits in the passive's flow socket, then in the
// sessions' Packet.Queue, the carrier sockets' udp.Options.ReadBuffer and
// the client application's own socket; a burst from the client waits in
// the ingress socket. The default UDP dialer requests Server.UDPBuffer for
// the flow socket; Server.UDPBuffer does not apply to a Dial hook, which
// sizes the socket it returns itself (SetReadBuffer and SetWriteBuffer).
//
// DNS-like forwards. Stub resolvers send each query from a fresh ephemeral
// port, so a busy DNS forward with the default classes keeps one table
// entry per query for 30 s after its answer. Give such a forward a
// PortForward of its own with Idle{Short: 10 * time.Second, Stream: 10 *
// time.Second} and a MaxFlows of at least 1.5 × queries a second × 10 s: a
// steady N new flows a second that each live L hold min(N × L, MaxFlows)
// entries.
//
// System-call errors of the l4 sockets — the ingress socket, the
// passive's flow sockets, ForwardPacket's local conn — are counted and
// never end a flow: every syscall.Errno (an ICMP port, host or network
// unreachable or administratively prohibited, a parameter problem, a
// message too long, no buffer space, a netfilter drop) except a small
// fatal set (a closed, invalid or unconnected socket); a run of read
// errors backs off up to 100 ms. Linux reports a connected socket's ICMP
// errors on its next call; Go's sockets on Windows report none. An error
// that is not an Errno (an embedder conn's own) ends the flow.
//
// Security. Server.UDP is off by default. Once on, the default dialer
// reaches every address the passive host can, its loopback services (a
// local DNS stub, NTP, SNMP) and private networks included: an open UDP
// relay at the session's rate. Give the Server a Dial hook that checks
// r.Cmd and the resolved address (net.Dialer.Control also runs before a
// UDP connect) and turns SO_BROADCAST off in that Control, as the default
// dialer does: Go turns it on for every IPv4 UDP socket. Such a hook also
// sizes its socket's buffers (see Peers and modes). A hook written for TCP
// alone must check r.Cmd; a stream conn returned for a UDP flow is
// refused CodeDialFailed. A PortForward does no authentication: whoever
// reaches an ingress port reaches its target and costs a flow, a session
// and a socket on the passive. On a LAN-facing ingress (AllowNonLoopback) a
// host that can spoof LAN source addresses can also make it reflect the
// target's replies, with whatever amplification the target's protocol
// has, toward the spoofed addresses: put a firewall in front of it, and
// filter sources by wrapping the UDPSocket.
//
// Compatibility. A Server without UDP, or a v2.0.0 passive, never serves a
// flow: its OPEN waits in the packet backlog until the Listener's
// AcceptTimeout (10 s by default) and DialUDP returns rendr.ErrCapacity
// (an embedder's own AcceptPacket loop that decodes with ParseMetadata
// refuses it CodeBadCommand at once). Upgrade the passive first.
//
// # Port forwarding
//
// PortForward forwards local ports to targets through one Peer: ServeTCP
// accepts connections from a net.Listener and forwards each as Dial and
// Forward do; ServeUDP reads a UDPSocket (an unconnected *net.UDPConn) and
// forwards each client source address as one flow, its replies going back to
// exactly that address. Both refuse a socket bound to a non-loopback or
// unspecified address (ErrNonLoopback) unless AllowNonLoopback is set (a
// Unix-domain listener counts as loopback), and ServeUDP refuses a connected
// socket. A Serve call owns its listener or socket from the call on and
// closes it exactly once (ServeTCP when it stops accepting, ServeUDP at its
// stop), and returns only after every connection or flow it started has
// ended. One PortForward may serve several listeners and sockets at once;
// MaxConns, MaxFlows and Status cover them together. A TCP connection that
// cannot be forwarded (beyond MaxConns, a failed Dial) is reset, never
// closed cleanly. Status counts TCP and UDP apart; Flows lists the UDP flows
// (state, class, times, each open flow's SessionStatus) for diagnostics. A
// wildcard socket is single-homed: replies leave from the source address the
// routing table chooses, so bind a specific address on a multi-homed host; a
// dual-stack wildcard socket keys an IPv4 client by its IPv4-mapped address.
//
// A new client's first datagram opens its flow (DialUDP, at most 12 s); its
// later datagrams wait for the open (at most 8 datagrams and 16 KiB, each
// charged at its buffer class, at most 1 s old at the flush) and are sent in
// order; one longer than the flow's MaxPayload counts TooLarge at the flush
// however long it waited. A client whose open failed, or whose flow the far
// end closed within 5 s of its open, is held: its datagrams are dropped
// (DropHeld) for 5 s, so a refusing passive sees at most one OPEN per client
// every 5 s while the table has room. At most 256 flows are being opened at
// once per PortForward (beyond: DropOpening). When MaxFlows entries exist
// (opening and held ones included), a new client takes the place of a held
// client, or of an open flow that never became a stream and has been idle
// for at least 1 s (the least recently active among up to 8 entries sampled
// from its socket's table); a stream and an opening flow are never taken.
// Without such an entry the new client's datagram is dropped (DropFull).
// Because MaxFlows covers every socket of a PortForward, a flood of new
// sources on one port can refuse new flows on another: use one PortForward
// per traffic kind and trust class (a DNS forward apart from a streaming
// forward).
//
// # Bounds and memory
//
// Target dials in flight are bounded by the Listener's AcceptBacklog, each
// by Server.DialTimeout and the pending session's AcceptTimeout; a Server
// dials for and forwards at most Server.MaxConns connections and
// Server.MaxFlows UDP flows (apart), and runs at most 192 custom Dial hook
// calls for each kind at once, abandoned ones included. One Server may Serve
// several Listeners at once; its bounds and Status cover them together. A
// forwarded connection costs three goroutines and 64 KiB of pooled buffers
// on top of its session's windows: at the default MaxConns of 10,000 that is
// ≈ 880 MiB, so deployments size MaxConns to their memory. A silent
// connection ends at its idle limit (DefaultIdleTimeout, on both ends). A
// forwarded UDP flow costs, on the passive, three goroutines, one connected
// socket (a file descriptor and an ephemeral port; Linux has about 28,000
// per source address), 2 × MaxPayload + 1 bytes of buffers and its session,
// besides the kernel buffers in use (the default dialer requests
// Server.UDPBuffer, 1 MiB by default, which the kernel charges as datagrams
// queue), so the default MaxFlows of 4,096 needs as many file descriptors;
// at the ingress, one goroutine, one MaxPayload buffer and its session:
// about 20 KiB of heap and a goroutine stack per flow at a datagram
// carrier's MaxPayload. These buffers are outside the sessions'
// MaxBufferedBytes and grow with MaxPayload: where flows carry
// Packet.MaxPayload (65,507 bytes; see Sizes) a flow costs about 84 KiB at
// the ingress and 128 KiB of buffers at the passive, about 340 MiB and
// 512 MiB at the default MaxFlows. Put UDP forwards on a Peer with datagram
// carriers only, or lower Packet.MaxPayload or MaxFlows.
package l4
