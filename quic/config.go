package quic

import (
	"cmp"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	qgo "github.com/quic-go/quic-go"
)

// Application error codes the adapters close connections with
// (diagnostics only: rendr never interprets them, L01).
const (
	codeClosed           qgo.ApplicationErrorCode = iota // closed by rendr
	codeHandshakeTimeout                                 // neither a stream nor a DATAGRAM in time
	codeRefused                                          // evicted by the admission bound
	codeBadKind                                          // both kinds, or another ALPN
	codeBudget                                           // DATAGRAM limit below DatagramBudget
	codeListenerClosed
)

const (
	ingressMax  = 2048 // datagrams in one ingress queue (L46)
	ingressInit = 16   // its first ring; a drained ring above 4·ingressInit is released
	egressMax   = 256  // datagrams in one egress queue (R1-9)
	egressBytes = 512 << 10
	egressAge   = 250 * time.Millisecond
	egressSpare = 8 // released egress buffers kept for reuse
)

var (
	errNoTLS           = errors.New("rendr/quic: Options.TLS is required")
	errNoCert          = errors.New("rendr/quic: Listen needs a server tls.Config with a certificate")
	errRefused         = errors.New("rendr/quic: listener admission bound reached")
	errEvicted         = errors.New("rendr/quic: evicted by a newer connection")
	errClassifyTimeout = errors.New("rendr/quic: neither a stream nor a DATAGRAM in time")
	errListenerClosed  = errors.New("rendr/quic: listener closed")
)

// norm fills in the listener and queue defaults (non-positive: default).
func (o Options) norm() Options {
	o.HandshakeTimeout = cmp.Or(max(o.HandshakeTimeout, 0), 10*time.Second)
	o.MaxPending = cmp.Or(max(o.MaxPending, 0), 256)
	o.MaxConns = cmp.Or(max(o.MaxConns, 0), 4096)
	o.DatagramQueueBytes = max(cmp.Or(max(o.DatagramQueueBytes, 0), 2048*DatagramBudget), DatagramBudget)
	return o
}

// quicConfig returns a clone of base with rendr's fields enforced (L26),
// also on the per-client configurations of GetConfigForClient. The
// server serves both kinds; a client enables DATAGRAM for datagram
// carriers only.
func quicConfig(base *qgo.Config, idle time.Duration, server, datagrams bool) *qgo.Config {
	c := &qgo.Config{}
	if base != nil {
		c = base.Clone()
	}
	c.KeepAlivePeriod = 0 // rendr's PING is the only liveness authority (invariant 7)
	c.Allow0RTT = false   // 0-RTT data is replayable
	switch {
	case idle > 0:
		c.MaxIdleTimeout = idle // as given: tests only below PassiveRetain (PA-22)
	case c.MaxIdleTimeout == 0:
		c.MaxIdleTimeout = DefaultIdleTimeout
	case c.MaxIdleTimeout < MinIdleTimeout:
		c.MaxIdleTimeout = MinIdleTimeout
	}
	c.InitialPacketSize = cmp.Or(c.InitialPacketSize, 1200) // the floor keeps DatagramBudget valid after an MTU reset
	// Receive windows (rendr's Window is the flow-control authority): the
	// defaults fill what is unset; an initial window never exceeds its max.
	c.MaxStreamReceiveWindow = cmp.Or(c.MaxStreamReceiveWindow, 16<<20)
	c.InitialStreamReceiveWindow = min(cmp.Or(c.InitialStreamReceiveWindow, 1<<20), c.MaxStreamReceiveWindow)
	c.MaxConnectionReceiveWindow = cmp.Or(c.MaxConnectionReceiveWindow, 24<<20)
	c.InitialConnectionReceiveWindow = min(cmp.Or(c.InitialConnectionReceiveWindow, 3<<19), c.MaxConnectionReceiveWindow)
	c.MaxIncomingUniStreams = -1
	c.EnableDatagrams = server || datagrams
	c.MaxIncomingStreams = -1 // the passive never opens a stream
	if server {
		c.MaxIncomingStreams = 1 // a stream carrier is one client bidirectional stream
		if f := c.GetConfigForClient; f != nil {
			c.GetConfigForClient = func(ci *qgo.ClientInfo) (*qgo.Config, error) {
				pc, err := f(ci)
				if err != nil {
					return nil, err
				}
				return quicConfig(pc, idle, true, true), nil
			}
		}
	}
	return c
}

// clientTLS is tlsConfig for a carrier dialing address: an unset
// ServerName becomes the address's host unless that is an IP literal, so
// the certificate is verified against the name dialed (quic-go would
// verify a resolved address against the IP, and crypto/tls sends no SNI
// for an IP).
func clientTLS(base *tls.Config, address string) (*tls.Config, error) {
	c, err := tlsConfig(base, false)
	if err != nil || c.ServerName != "" {
		return c, err
	}
	if host, _, err := net.SplitHostPort(address); err == nil {
		if _, err := netip.ParseAddr(host); err != nil {
			c.ServerName = host
		}
	}
	return c, nil
}

// tlsConfig clones base with NextProtos [ALPN] (empty is completed, any
// other list is an error); a server configuration needs a certificate.
func tlsConfig(base *tls.Config, server bool) (*tls.Config, error) {
	if base == nil {
		return nil, errNoTLS
	}
	c := base.Clone()
	switch {
	case len(c.NextProtos) == 0:
		c.NextProtos = []string{ALPN}
	case len(c.NextProtos) != 1 || c.NextProtos[0] != ALPN:
		return nil, fmt.Errorf("rendr/quic: tls.Config.NextProtos must be empty or [%q], not %q", ALPN, c.NextProtos)
	}
	if server && len(c.Certificates) == 0 && c.GetCertificate == nil && c.GetConfigForClient == nil {
		return nil, errNoCert
	}
	return c, nil
}

// closedError wraps a dead connection's error that claims Timeout or
// Temporary — quic-go's idle and handshake timeouts, its stateless reset
// (Temporary) — so that no caller takes it for the expiry of a deadline it
// set or for transient noise: every QUIC error ends the carrier (L01;
// M2 design §A6.4). errors.As still finds the QUIC error.
type closedError struct{ error }

func (e closedError) Unwrap() error { return e.error }
func (closedError) Timeout() bool   { return false }
func (closedError) Temporary() bool { return false }

// connErr returns err for an adapter's caller: a deadline expiry as is,
// another timeout-like or temporary error as a closedError.
func connErr(err error) error {
	var ne net.Error
	if err == nil || errors.Is(err, os.ErrDeadlineExceeded) || !errors.As(err, &ne) || !(ne.Timeout() || ne.Temporary()) {
		return err
	}
	return closedError{err}
}
