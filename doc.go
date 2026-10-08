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
// mode) or keeps every carrier busy (bond mode).
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
// the nested module github.com/FrankoonG/rendr/v2/quic, or an embedder's
// net.PacketConn (DatagramCarrier, Listener.HandlePacket) — and stream
// carriers too. ReadFrom returns io.EOF only after the peer closed its end
// and the datagrams this side holds were read; a carrier change is as
// invisible as for a stream session.
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
// not replace the contract.
package rendr
