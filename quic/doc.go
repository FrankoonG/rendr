// Package quic provides rendr carriers over QUIC (RFC 9000) with upstream
// quic-go: a stream carrier (one QUIC connection carrying one client
// bidirectional stream), a datagram carrier (one QUIC connection carrying
// DATAGRAM frames, RFC 9221), and a listener that hands both kinds to a
// rendr.Listener. It is a separate module (github.com/FrankoonG/rendr/quic/v2)
// so that rendr's root module depends only on the standard library and
// golang.org/x/sys.
//
// Every carrier is its own QUIC connection, so two carriers never share a
// connection's fate; the factories leave Props at their zero value, and the
// sessions of one Peer share the factory's live carriers (rendr mux). A
// dialer carrier has its own UDP socket, released when the carrier closes;
// the carriers a Listener accepted share its socket, which closes after the
// last of them (Listener.Done).
//
// Security: QUIC always encrypts, but encryption is not authentication. A
// tls.Config is required and only what it verifies is authenticated; the
// ALPN is fixed to "rendr/2-q1" and verified after the handshake; a peer
// of an earlier encapsulation ("rendr/2") fails the handshake.
//
// Liveness belongs to rendr: keepalives are off, and the QUIC idle
// timeout is at least MinIdleTimeout (default DefaultIdleTimeout) unless
// Options.IdleTimeout sets another value explicitly — a value below rendr's
// PassiveRetain lets QUIC end carriers that rendr still considers alive and
// is meant for tests only.
//
// Datagram budget: a DATAGRAM carrier's frame budget is the static
// DatagramBudget (1152 bytes), valid at QUIC's minimum packet size after
// the carrier's 4-byte sequence number; it is checked at attach (an
// oversize probe) and only ever lowered when quic-go refuses a datagram as
// too large. A packet session over it carries application datagrams of up
// to 1127 bytes. One pump goroutine per connection drains received
// DATAGRAMs into a bounded queue; one sender goroutine drains a bounded
// egress queue into quic-go, so rendr's carrier writer never blocks on
// QUIC's congestion control and a congested path drops datagrams instead
// of stalling the carrier.
//
// Wire: every DATAGRAM payload is a 4-byte big-endian sequence number,
// counting per direction the datagrams handed to quic-go from 0, followed
// by one rendr datagram; the ALPN versions this format. A DATAGRAM shorter
// than the sequence number ends the connection.
//
// Limitations of DATAGRAM carriers (quic-go v0.63): quic-go's congestion
// control is Reno with a packet threshold of 3 and no undo of spurious loss
// detection, and it offers no option to change either. On a path that
// reorders by 3 packets or more the congestion window shrinks below the
// path's rate, and a constant-rate flow loses datagrams to the egress
// queue's 250-ms age limit (counted in Counters.EgressDrops). quic-go also
// drops received DATAGRAM frames beyond 128 per connection without a
// signal (a fixed limit rendr cannot prevent from overflowing when the
// receiving process stalls): when the carrier's pump does not run while
// more than 128 DATAGRAMs arrive (12.8 ms at 10,000 datagrams a second; a
// 45-datagram loss at that rate takes about 17 ms) the excess is lost. The
// pump never waits while datagrams are queued, nor on rendr's consumer.
// The carrier counts them in Counters.IngressDrops from the gaps in its
// per-DATAGRAM sequence numbers, when the next datagram arrives. When
// DATAGRAMs arrive in order that count is exact, except that a datagram
// lost in the network during such an overflow counts too. On a path that
// reorders it is no bound: it can be too high (a datagram reordered during
// an overflow counts and is still delivered) or too low (a late datagram
// the full queue dropped after a later one was queued is missed, and once
// the queue has drained, a late datagram numbered above every one received
// hides the overflow's drops numbered above it). quic-go's 256-packet
// queue of unprocessed packets, which drops when its own connection
// goroutine stalls, is not visible to the carrier: such a drop looks like
// a loss in the network. On reordering paths use the raw UDP carrier
// (carrier/udp) or the QUIC stream carrier.
//
// The package uses only rendr's public API: its conns are ordinary embedder
// conns for rendr's core.
package quic
