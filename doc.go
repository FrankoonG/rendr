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
// Security model: rendr provides no confidentiality and no authentication.
// A rendr listener must only be reachable through an authenticated,
// encrypted channel that the embedder controls (see examples/mtls). An
// InstanceID is not an identity. The built-in raw TCP carrier is plaintext
// and loopback-only unless explicitly allowed.
//
// Embedding contract: every carrier of a Peer must reach the same rendr
// instance; relays may only forward rendr bytes opaquely or fail explicitly;
// carrier keepalive and idle timers must exceed PassiveRetain, the time the
// passive side keeps a session without carriers: the dialer's NoPathGrace +
// PingIdle + DeadMax + 5 s (34 s with the defaults). Frame sequence numbers
// (fseq), CRC32C and InstanceID checks kill a misbehaving carrier but do
// not replace the contract.
package rendr
