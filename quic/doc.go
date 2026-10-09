// Package quic provides rendr carriers over QUIC (RFC 9000) with upstream
// quic-go: a stream carrier (one QUIC connection carrying one client
// bidirectional stream) and a datagram carrier (one QUIC connection carrying
// DATAGRAM frames, RFC 9221), and a listener that hands both kinds to a
// rendr.Listener (M2-D67; plan:635).
//
// Every carrier is its own QUIC connection, so two carriers never share a
// fate: the fate group plan:635 describes is empty in M2 (PA-12). A dialer
// carrier has its own UDP socket, released when the carrier closes; the
// carriers a Listener accepted share its socket, which closes after the
// last of them (Listener.Done).
//
// Security: QUIC always encrypts, but encryption is not authentication. A
// tls.Config is required and only what it verifies is authenticated; the
// ALPN is fixed to "rendr/2" and verified after the handshake.
//
// Liveness belongs to rendr (L26): keepalives are off, and the QUIC idle
// timeout is at least MinIdleTimeout (default DefaultIdleTimeout) unless
// Options.IdleTimeout sets another value explicitly — a value below rendr's
// PassiveRetain lets QUIC end carriers that rendr still considers alive and
// is meant for tests only.
//
// Datagram budget: a DATAGRAM carrier's frame budget is the static
// DatagramBudget (1152 bytes), valid at QUIC's minimum packet size; it is
// checked at attach (an oversize probe) and only ever lowered when quic-go
// refuses a datagram as too large (plan:635). A packet session over it
// carries application datagrams of up to 1127 bytes (plan:331). One pump
// goroutine per connection drains received DATAGRAMs into a bounded queue
// (L46); one sender goroutine drains a bounded egress queue into quic-go,
// so rendr's carrier writer never blocks on QUIC's congestion control and
// a congested path drops datagrams instead of stalling the carrier.
//
// The package uses only rendr's public API: its conns are ordinary embedder
// conns for rendr's core.
package quic
