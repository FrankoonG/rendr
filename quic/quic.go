package quic

import (
	"crypto/tls"
	"net"
	"time"

	"github.com/FrankoonG/rendr/v2"
	qgo "github.com/quic-go/quic-go"
)

// ALPN is the only application protocol a rendr QUIC carrier negotiates.
const ALPN = "rendr/2"

// DatagramBudget is the frame budget of a QUIC DATAGRAM carrier — the bytes
// rendr passes to one SendDatagram — and its DatagramCarrier.MTU: the
// largest payload quic-go admits and packs at the 1200-byte minimum QUIC
// packet size even with a 20-byte connection ID, a 4-byte packet number,
// the 16-byte tag and the DATAGRAM frame header.
const DatagramBudget = 1152

// Idle timeouts (L26).
const (
	// MinIdleTimeout is the smallest QUIC idle timeout a carrier uses when
	// Options.IdleTimeout is 0: longer than any rendr PassiveRetain (at most
	// 400 s), so QUIC never ends a carrier rendr still considers alive.
	MinIdleTimeout = 450 * time.Second
	// DefaultIdleTimeout is the idle timeout when neither Options.IdleTimeout
	// nor Options.Config sets one.
	DefaultIdleTimeout = 10 * time.Minute
)

// Options configure QUIC carriers and listeners.
type Options struct {
	// TLS is required: a client configuration for the carriers, a server
	// configuration with a certificate for Listen. It is cloned; NextProtos
	// must be empty or exactly [ALPN] (else the constructor fails).
	TLS *tls.Config
	// Config optionally tunes quic-go. Always overridden: KeepAlivePeriod 0,
	// Allow0RTT false, InitialPacketSize 1200 when unset, EnableDatagrams
	// and the stream limits per role and kind; MaxIdleTimeout is raised to
	// at least MinIdleTimeout (0 selects DefaultIdleTimeout) unless
	// IdleTimeout is set.
	Config *qgo.Config
	// IdleTimeout, when non-zero, is the QUIC idle timeout, honoured as
	// given. Below rendr's PassiveRetain it breaks the embedding contract
	// (L26): for tests that need QUIC's own timer to fire (L01).
	IdleTimeout time.Duration
	// LocalAddr optionally fixes a dialer carrier's local "ip:port".
	LocalAddr string
	// StatelessResetKey lets a restarted listener reset its old connections
	// at once; useful only if it is the same across restarts.
	StatelessResetKey *qgo.StatelessResetKey
	// Listener limits (defaults 10 s, 256, 4096): how long an accepted
	// connection may take to open its stream or send its first DATAGRAM,
	// how many connections may be in handshake or in that wait (the oldest
	// is evicted beyond), and how many may be alive in total (refused
	// beyond).
	HandshakeTimeout time.Duration
	MaxPending       int
	MaxConns         int
	// DatagramQueueBytes bounds the per-connection DATAGRAM ingress queue
	// (default 2.25 MiB, at most 2048 datagrams); overflow is dropped and
	// counted (L46).
	DatagramQueueBytes int
}

// StreamCarrier returns a stream carrier factory named name that dials
// address over QUIC: one connection with one client bidirectional stream
// per carrier. It fails for a missing or invalid TLS configuration.
func StreamCarrier(name, address string, o Options) (rendr.StreamCarrier, error) {
	panic("unimplemented: M2")
}

// DatagramCarrier returns a datagram carrier factory named name that dials
// address over QUIC: one connection per carrier, DATAGRAM frames only, MTU
// DatagramBudget. Dial refuses a connection whose peer does not support
// DATAGRAM or whose current limit is below DatagramBudget. It fails for a
// missing or invalid TLS configuration.
func DatagramCarrier(name, address string, o Options) (rendr.DatagramCarrier, error) {
	panic("unimplemented: M2")
}

// Listen opens a QUIC listener on network ("udp", "udp4", "udp6") and
// address. Serve hands its carriers to a rendr.Listener.
func Listen(network, address string, o Options) (*Listener, error) {
	panic("unimplemented: M2")
}

// Listener accepts QUIC connections and classifies each by its first event:
// a client stream makes it a stream carrier (rendr.Listener.Handle), a
// DATAGRAM a datagram carrier (rendr.Listener.HandlePacket); both, or
// neither within HandshakeTimeout, closes it. Admission is bounded before
// any handshake state exists (ConnContext, L48).
type Listener struct {
	opts Options
}

// Serve hands every carrier to rl until Close; it returns net.ErrClosed
// after Close. Closing rl and l are independent: carriers already handed to
// rl keep running when l closes.
func (l *Listener) Serve(rl *rendr.Listener) error { panic("unimplemented: M2") }

// Addr returns the listening address.
func (l *Listener) Addr() net.Addr { panic("unimplemented: M2") }

// Close stops accepting; carriers already handed to rendr keep running.
func (l *Listener) Close() error { panic("unimplemented: M2") }

// Done is closed when the listener's transport and UDP socket are closed
// (after Close, once no carrier uses them).
func (l *Listener) Done() <-chan struct{} { panic("unimplemented: M2") }

// Stats returns the listener's counters.
func (l *Listener) Stats() ListenerStats { panic("unimplemented: M2") }

// ListenerStats are a Listener's counters.
type ListenerStats struct {
	Refused          uint64 // connections refused by the admission bounds
	Evicted          uint64 // pending connections evicted (oldest first)
	ClassifyTimeouts uint64 // connections that neither opened a stream nor sent a DATAGRAM in time
	BadKind          uint64 // connections that did both
	BudgetRefused    uint64 // datagram connections whose DATAGRAM limit was below DatagramBudget
	Streams          uint64 // stream carriers handed to rendr
	Datagrams        uint64 // datagram carriers handed to rendr
	DatagramDrops    uint64 // DATAGRAMs the ingress queues dropped (L46)
}
