package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"sync/atomic"
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
	// must be empty or exactly [ALPN] (else the constructor fails). A
	// carrier verifies the server's certificate against ServerName when it
	// is set, else against the host of its address: a host name (also sent
	// as SNI) or an IP literal.
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
	// LocalAddr optionally fixes a dialer carrier's local "ip:port". Every
	// carrier binds a socket of its own to it, so a non-zero port allows
	// only one live carrier of the factory at a time: use port 0 unless
	// that is intended.
	LocalAddr string
	// StatelessResetKey lets a restarted listener reset its old connections
	// at once; useful only if it is the same across restarts.
	StatelessResetKey *qgo.StatelessResetKey
	// Listener limits (defaults 10 s, 256, 4096): how long an accepted
	// connection may take to open its stream or send its first DATAGRAM;
	// how many connections may be in handshake (new ones are refused
	// beyond) and, separately, in that wait (the oldest is evicted beyond);
	// and how many may be alive in total (refused beyond).
	HandshakeTimeout time.Duration
	MaxPending       int
	MaxConns         int
	// DatagramQueueBytes bounds the per-connection DATAGRAM ingress queue
	// (default 2.25 MiB, at most 2048 datagrams); overflow is dropped and
	// counted (L46).
	DatagramQueueBytes int
	// Counters, when non-nil, receives the datagram drops of every carrier
	// and listener built with these Options (one value may be shared): the
	// transport's own losses, for loss attribution.
	Counters *Counters
}

// Counters count the datagrams the quic module's adapters dropped (M2
// design §A6.3, Revision 1, R1-9). A drop here is a transport loss, like a
// kernel socket's: rendr counted the datagram as sent.
type Counters struct {
	// IngressDrops: received DATAGRAMs a full ingress queue dropped (L46).
	IngressDrops atomic.Uint64
	// EgressDrops: DATAGRAMs the egress queue dropped — the oldest when it
	// was full (256 datagrams or 512 KiB), or one older than 250 ms when its
	// turn came: QUIC's congestion control sends slower than rendr writes,
	// and a datagram carrier's WriteTo never blocks on it.
	EgressDrops atomic.Uint64
}

// StreamCarrier returns a stream carrier factory named name that dials
// address over QUIC: one connection with one client bidirectional stream
// per carrier. The conn's Close returns at once; its QUIC connection and
// its UDP socket are released after a linger of at most 500 ms (or at the
// peer's close) that lets the peer read the last bytes. It fails for a
// missing or invalid TLS configuration.
func StreamCarrier(name, address string, o Options) (rendr.StreamCarrier, error) {
	tc, err := clientTLS(o.TLS, address)
	if err != nil {
		return rendr.StreamCarrier{}, err
	}
	o = o.norm()
	return rendr.StreamCarrier{Name: name, Dial: func(ctx context.Context) (net.Conn, error) {
		return dialStream(ctx, address, tc, &o)
	}}, nil
}

// DatagramCarrier returns a datagram carrier factory named name that dials
// address over QUIC: one connection per carrier, DATAGRAM frames only, MTU
// DatagramBudget. Dial refuses a connection whose peer does not support
// DATAGRAM or whose current limit is below DatagramBudget. The conn's
// WriteTo never blocks on QUIC's congestion control: it queues the datagram
// in a bounded egress queue that one sender goroutine per connection
// drains into quic-go (drops counted in Options.Counters); an error of an
// earlier datagram (too large, connection closed) is returned by the next
// WriteTo. It fails for a missing or invalid TLS configuration.
func DatagramCarrier(name, address string, o Options) (rendr.DatagramCarrier, error) {
	tc, err := clientTLS(o.TLS, address)
	if err != nil {
		return rendr.DatagramCarrier{}, err
	}
	o = o.norm()
	return rendr.DatagramCarrier{Name: name, MTU: DatagramBudget, Dial: func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		return dialDatagram(ctx, address, tc, &o)
	}}, nil
}

// Listen opens a QUIC listener on network ("udp", "udp4", "udp6") and
// address. Serve hands its carriers to a rendr.Listener.
func Listen(network, address string, o Options) (*Listener, error) {
	return listen(network, address, o)
}

// Listener accepts QUIC connections and classifies each by its first event:
// a client stream makes it a stream carrier (rendr.Listener.Handle), a
// DATAGRAM a datagram carrier (rendr.Listener.HandlePacket); both, or
// neither within HandshakeTimeout, closes it. Admission is bounded before
// any handshake state exists (ConnContext, L48).
type Listener struct {
	opts Options
	udp  *net.UDPConn
	tr   *qgo.Transport
	ql   *qgo.Listener
	ctr  Counters // drops of the handed datagram carriers
	done chan struct{}
	fin  sync.Once

	mu      sync.Mutex
	closing bool
	shaking int       // ConnContext … Accept: QUIC handshakes in flight
	conns   int       // ConnContext … the connection's end
	waiting []*waiter // accepted, not yet classified, oldest first
	refs    int       // 1 until Close, plus every accepted connection not yet released
	stats   ListenerStats
}

// Serve hands every carrier to rl until Close; it returns net.ErrClosed
// after Close. Closing rl and l are independent: carriers already handed to
// rl keep running when l closes.
func (l *Listener) Serve(rl *rendr.Listener) error {
	if rl == nil {
		return errors.New("rendr/quic: Serve needs a rendr.Listener")
	}
	return l.serve(rl)
}

// Addr returns the listening address.
func (l *Listener) Addr() net.Addr { return l.udp.LocalAddr() }

// Close stops accepting; carriers already handed to rendr keep running.
func (l *Listener) Close() error {
	l.mu.Lock()
	if l.closing {
		l.mu.Unlock()
		return nil
	}
	l.closing = true
	ws := l.waiting
	l.waiting = nil
	l.mu.Unlock()
	for _, w := range ws {
		w.cancel(errListenerClosed)
	}
	err := l.ql.Close() // refuses the handshakes in flight; accepted connections stay
	l.unref()
	return err
}

// Done is closed when the listener's transport and UDP socket are closed
// (after Close, once no carrier uses them).
func (l *Listener) Done() <-chan struct{} { return l.done }

// Stats returns the listener's counters.
func (l *Listener) Stats() ListenerStats {
	l.mu.Lock()
	s := l.stats
	l.mu.Unlock()
	s.DatagramDrops, s.EgressDrops = l.ctr.IngressDrops.Load(), l.ctr.EgressDrops.Load()
	return s
}

// ListenerStats are a Listener's counters.
type ListenerStats struct {
	// Refused counts the connection attempts the admission bounds refused,
	// per Initial packet: a retransmitted or split ClientHello counts again.
	Refused          uint64
	Evicted          uint64 // pending connections evicted (oldest first)
	ClassifyTimeouts uint64 // connections that neither opened a stream nor sent a DATAGRAM in time
	BadKind          uint64 // connections that did both, or negotiated another ALPN
	BudgetRefused    uint64 // datagram connections whose DATAGRAM limit was below DatagramBudget
	Streams          uint64 // stream carriers handed to rendr
	Datagrams        uint64 // datagram carriers handed to rendr
	DatagramDrops    uint64 // DATAGRAMs the ingress queues dropped (L46)
	EgressDrops      uint64 // DATAGRAMs the egress queues of handed carriers dropped (R1-9)
}
