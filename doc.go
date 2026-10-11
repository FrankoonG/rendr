// Package rendr keeps one application connection alive across many
// underlying carriers between two rendr instances.
//
// A dialer Runtime opens sessions to a passive Runtime through a Peer; each
// session is a net.Conn (*Conn) whose bytes travel over any number of
// carriers — rendr-to-rendr connections supplied by the embedder (L7
// tunnels) or the built-in plaintext TCP carrier (package carrier/tcp). When
// a carrier dies, degrades or is replaced, the application sees no
// interruption, error or lost byte: rendr keeps byte offsets, acknowledges
// only what was delivered to the peer application, retransmits from the
// acknowledged front and moves the session to another carrier (selector
// mode), keeps every carrier busy (bond mode) or sends every byte on every
// carrier and keeps the first copy (race mode).
//
// Semantics:
//   - Read returns io.EOF only when the peer's FIN reached the contiguous
//     delivery point. Carrier failures never surface; when no carrier is
//     left for NoPathGrace the session fails with ErrNoPath.
//   - Write copies into the session's send buffer and returns; n is what the
//     session accepted. After a deadline the accepted bytes are delivered;
//     after a session failure they are not guaranteed.
//   - Close returns at once; the session lingers in the background (at most
//     Linger) to deliver what was written, then finishes or resets.
//     Conn.Done is closed once it has fully ended. For a clean end, read
//     until io.EOF, Close, wait on Done, and only then close the Runtime:
//     Runtime.Close resets every session that has not ended.
//   - Deadlines follow net.Conn and never end the session.
//
// Packet sessions (Peer.DialPacket, Listener.AcceptPacket) carry datagrams
// instead of a byte stream: a *PacketConn is a net.PacketConn whose
// WriteTo sends one datagram of at most MaxPayload bytes (fixed at OPEN;
// larger ones fail with ErrPacketTooLarge) and whose ReadFrom returns one.
// Datagrams are delivered at most once, possibly reordered, never
// retransmitted; they are lost only in flight on a carrier that dies or
// when a bounded queue drops them (counted). Their carriers are datagram
// carriers — the built-in raw UDP carrier (package carrier/udp, with a
// listening socket served through FromPacketConn), the QUIC carriers of
// the nested module github.com/FrankoonG/rendr/quic/v2, or an embedder's
// net.PacketConn (DatagramCarrier, Listener.HandlePacket) — and stream
// carriers too. ReadFrom returns io.EOF only after the peer closed its end
// and the datagrams this side holds were read; a carrier change is as
// invisible as for a stream session. On Linux amd64 and arm64 the sockets
// package carrier/udp creates move up to its Options.MaxBatch datagrams
// per system call (sendmmsg, recvmmsg), with a one-way fallback to one
// call per datagram where the kernel refuses them; Status.Datagram counts
// the calls and the datagrams they moved.
//
// Race sessions (ModeRace) take their member carriers as bond sessions do
// and send every byte or datagram on each of them; the receiver keeps the
// first copy. Each byte or datagram arrives over whichever member delivers
// it first, but throughput is the fastest member's, never the sum, and the
// wire bytes and the sender's CPU grow with the member count. A session's counters count
// each byte or datagram once; SessionStatus.Race, DupBytes and the
// carriers' own counters show the copies.
//
// Carrier properties: each factory's Props tell the scheduler what its
// carriers share. Factories with one FateGroup fail together (a shared first
// hop, relay or transport connection): bond and race keep at most one
// member per group, and selector failover tries other groups first.
// HoLCoupled marks a group whose carriers share one in-order pipe, so a
// stalled carrier's acknowledgement duty never moves onto a sibling.
// NewPeer refuses a FateGroup longer than 64 bytes, HoLCoupled without a
// FateGroup, and factories of one group that disagree on HoLCoupled.
//
// Shared carriers (rendr mux): unless a factory sets Props.CheapSubflow,
// the sessions of one Peer share the live carriers of that factory, each
// carrier sessions of one kind: on a stream factory the packet sessions
// share carriers apart from the stream sessions' (so a datagram never
// waits behind a stream session's backlog). A new session or a failover
// uses a live carrier of its kind instead of dialling one, and a carrier
// closes when its last session ends; there is no idle retention.
// Sessions on one carrier share its head-of-line blocking and its fate: its
// death migrates each of them, as it would a session of its own. On a
// carrier that was already live, the passive's first bytes for a session
// leave about one round trip later than on a fresh carrier (the passive
// waits for the dialer's first frame for that session). CheapSubflow
// factories give every session its own carriers.
//
// Early return (DialOptions.EarlyReturn) gives Dial the semantics of TCP
// Fast Open: Dial returns before any network I/O, the session opens with
// its first Write, Read or CloseWrite, and up to Handshake.EarlyDataMax
// (64 KiB) of the first bytes written travel with the OPEN when the
// session dials a carrier of its own, so a protocol whose client speaks
// first saves one round trip. The opening's outcome — a refusal, no path —
// is then the error of the next Read and Write instead of Dial's. The
// passive application reads early bytes only after it confirmed the
// session; a refused session discards them. On a carrier shared with other
// sessions no early data is sent, which costs the same round trip.
//
// Package l4 carries TCP connections over stream sessions: l4.Dial names
// the target in the OPEN's metadata, an l4.Server dials it while the
// session is pending and confirms only once the target connected (else it
// rejects with a typed code), and l4.Forward moves the bytes with half-close
// and resets mapped in both directions.
//
// Idle sessions hold no goroutine: a session's scheduler parks after about
// a second without work and restarts at its next event or deadline
// (Status.Actors counts the running ones).
//
// Security model: rendr provides no confidentiality and no authentication.
// A rendr listener must only be reachable through an authenticated,
// encrypted channel that the embedder controls (see examples/mtls). An
// InstanceID is not an identity. The built-in raw TCP and raw UDP carriers
// (carrier/tcp, carrier/udp) are plaintext and loopback-only unless
// explicitly allowed (AllowNonLoopback); the UDP flow ID is no
// authentication. The QUIC carriers encrypt, but authenticate only what
// their tls.Config verifies.
//
// Embedding contract: every carrier of a Peer must reach the same rendr
// instance; relays may only forward rendr bytes opaquely or fail explicitly;
// carrier keepalive and idle timers must exceed PassiveRetain, the time the
// passive side keeps a session without carriers: the dialer's NoPathGrace +
// PingIdle + DeadMax + 5 s (34 s with the defaults). Frame sequence numbers
// (fseq), CRC32C and InstanceID checks kill a misbehaving carrier but do
// not replace the contract: a relay or peer that re-frames the traffic and
// recomputes CRC and fseq can inject plausible bytes into any session on
// its carrier, and a race copy that differs from the first copy is
// detected only while the first copy is still buffered.
package rendr
