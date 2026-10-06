package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/rendrtest"
	qgo "github.com/quic-go/quic-go"
)

// TestQUICConfigEnforced_L26: rendr's PING is the only liveness authority,
// so every quic-go configuration — the embedder's, a per-client one, the
// dialer's and the listener's — has no keepalive, no 0-RTT and an idle
// timeout of at least MinIdleTimeout unless Options.IdleTimeout sets one
// explicitly; the stream limits and DATAGRAM support follow role and kind.
func TestQUICConfigEnforced_L26(t *testing.T) {
	user := &qgo.Config{KeepAlivePeriod: 15 * time.Second, Allow0RTT: true, MaxIdleTimeout: 30 * time.Second,
		MaxIncomingStreams: 100, MaxIncomingUniStreams: 100, HandshakeIdleTimeout: 3 * time.Second}
	for _, tc := range []struct {
		name              string
		server, datagrams bool
		wantDG            bool
		wantStreams       int64
	}{
		{"listener", true, true, true, 1},
		{"stream dialer", false, false, false, -1},
		{"datagram dialer", false, true, true, -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := quicConfig(user, 0, tc.server, tc.datagrams)
			if c.KeepAlivePeriod != 0 || c.Allow0RTT || c.MaxIdleTimeout != MinIdleTimeout {
				t.Errorf("keepalive %v, 0-RTT %v, idle %v; want 0, false, %v", c.KeepAlivePeriod, c.Allow0RTT, c.MaxIdleTimeout, MinIdleTimeout)
			}
			if c.EnableDatagrams != tc.wantDG || c.MaxIncomingStreams != tc.wantStreams || c.MaxIncomingUniStreams != -1 {
				t.Errorf("datagrams %v, streams %d, uni %d; want %v, %d, -1", c.EnableDatagrams, c.MaxIncomingStreams, c.MaxIncomingUniStreams, tc.wantDG, tc.wantStreams)
			}
			if c.InitialPacketSize != 1200 || c.HandshakeIdleTimeout != 3*time.Second {
				t.Errorf("initial packet size %d, handshake idle %v; want 1200 and the embedder's 3 s", c.InitialPacketSize, c.HandshakeIdleTimeout)
			}
			if c.InitialStreamReceiveWindow != 1<<20 || c.MaxStreamReceiveWindow != 16<<20 ||
				c.InitialConnectionReceiveWindow != 3<<19 || c.MaxConnectionReceiveWindow != 24<<20 {
				t.Errorf("windows %d/%d, %d/%d", c.InitialStreamReceiveWindow, c.MaxStreamReceiveWindow,
					c.InitialConnectionReceiveWindow, c.MaxConnectionReceiveWindow)
			}
		})
	}
	if user.KeepAlivePeriod != 15*time.Second || user.MaxIdleTimeout != 30*time.Second || user.EnableDatagrams {
		t.Error("the embedder's quic.Config was modified")
	}
	for _, tc := range []struct {
		name     string
		cfg      *qgo.Config
		explicit time.Duration
		want     time.Duration
	}{
		{"no config", nil, 0, DefaultIdleTimeout},
		{"unset", &qgo.Config{}, 0, DefaultIdleTimeout},
		{"below the floor", &qgo.Config{MaxIdleTimeout: 400 * time.Second}, 0, MinIdleTimeout},
		{"above the floor", &qgo.Config{MaxIdleTimeout: time.Hour}, 0, time.Hour},
		{"explicit, honoured as given", &qgo.Config{MaxIdleTimeout: time.Hour}, time.Second, time.Second},
	} {
		if got := quicConfig(tc.cfg, tc.explicit, false, true).MaxIdleTimeout; got != tc.want {
			t.Errorf("%s: idle timeout %v, want %v", tc.name, got, tc.want)
		}
	}
	if got := quicConfig(&qgo.Config{InitialPacketSize: 1350}, 0, false, false).InitialPacketSize; got != 1350 {
		t.Errorf("an explicit InitialPacketSize became %d", got)
	}
	for _, tc := range []struct {
		name           string
		cfg            *qgo.Config
		is, ms, ic, mc uint64
	}{ // receive windows: an initial window never exceeds its max; explicit values are kept
		{"max below the default initial", &qgo.Config{MaxStreamReceiveWindow: 512 << 10, MaxConnectionReceiveWindow: 768 << 10},
			512 << 10, 512 << 10, 768 << 10, 768 << 10},
		{"explicit initial", &qgo.Config{InitialStreamReceiveWindow: 4 << 20, InitialConnectionReceiveWindow: 6 << 20},
			4 << 20, 16 << 20, 6 << 20, 24 << 20},
	} {
		c := quicConfig(tc.cfg, 0, false, false)
		if c.InitialStreamReceiveWindow != tc.is || c.MaxStreamReceiveWindow != tc.ms ||
			c.InitialConnectionReceiveWindow != tc.ic || c.MaxConnectionReceiveWindow != tc.mc {
			t.Errorf("%s: windows %d/%d, %d/%d; want %d/%d, %d/%d", tc.name, c.InitialStreamReceiveWindow, c.MaxStreamReceiveWindow,
				c.InitialConnectionReceiveWindow, c.MaxConnectionReceiveWindow, tc.is, tc.ms, tc.ic, tc.mc)
		}
	}
	perClient := quicConfig(&qgo.Config{GetConfigForClient: func(*qgo.ClientInfo) (*qgo.Config, error) {
		return &qgo.Config{KeepAlivePeriod: 5 * time.Second, Allow0RTT: true, MaxIdleTimeout: 10 * time.Second}, nil
	}}, 0, true, true)
	pc, err := perClient.GetConfigForClient(&qgo.ClientInfo{})
	if err != nil || pc.KeepAlivePeriod != 0 || pc.Allow0RTT || pc.MaxIdleTimeout != MinIdleTimeout || !pc.EnableDatagrams || pc.MaxIncomingStreams != 1 {
		t.Errorf("per-client configuration not enforced: %+v, %v", pc, err)
	}
	if o := (Options{}).norm(); o.HandshakeTimeout != 10*time.Second || o.MaxPending != 256 || o.MaxConns != 4096 ||
		o.DatagramQueueBytes != 2048*DatagramBudget {
		t.Errorf("defaults %v %d %d %d", o.HandshakeTimeout, o.MaxPending, o.MaxConns, o.DatagramQueueBytes)
	}
}

// TestQUICALPN_L44: the ALPN is fixed to rendr/2 — any other NextProtos is
// a constructor error, a client offering another protocol fails the QUIC
// handshake before the Listener sees it, and a handshake that negotiated
// another protocol anyway (a per-client tls.Config) is closed by the
// Listener as a bad kind, never handed to rendr.
func TestQUICALPN_L44(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	srvTLS, cliTLS := testTLS(t)
	if _, err := StreamCarrier("q", "127.0.0.1:1", Options{}); !errors.Is(err, errNoTLS) {
		t.Errorf("no TLS: %v", err)
	}
	if _, err := Listen("udp4", "127.0.0.1:0", Options{TLS: cliTLS}); !errors.Is(err, errNoCert) {
		t.Errorf("Listen without a certificate: %v", err)
	}
	for _, protos := range [][]string{{"h3"}, {ALPN, "h3"}, {"h3", ALPN}, {ALPN, ALPN}} {
		bad := func(base *tls.Config) Options { c := base.Clone(); c.NextProtos = protos; return Options{TLS: c} }
		_, e1 := StreamCarrier("q", "127.0.0.1:1", bad(cliTLS))
		_, e2 := DatagramCarrier("q", "127.0.0.1:1", bad(cliTLS))
		_, e3 := Listen("udp4", "127.0.0.1:0", bad(srvTLS))
		if e1 == nil || e2 == nil || e3 == nil {
			t.Errorf("NextProtos %q accepted: %v, %v, %v", protos, e1, e2, e3)
		}
	}
	for _, protos := range [][]string{nil, {ALPN}} {
		c := cliTLS.Clone()
		c.NextProtos = protos
		tc, err := tlsConfig(c, false)
		if err != nil || !slices.Equal(tc.NextProtos, []string{ALPN}) || !slices.Equal(c.NextProtos, protos) {
			t.Errorf("NextProtos %q: %q, %v (the caller's config must stay unchanged)", protos, tc.NextProtos, err)
		}
	}

	l, f := serveFake(t, Options{})
	raw := cliTLS.Clone()
	raw.NextProtos = []string{"h3"}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if qc, err := rawTransport(t).Dial(ctx, l.Addr(), raw, quicConfig(nil, 0, false, true)); err == nil {
		_ = qc.CloseWithError(0, "")
		t.Fatal("a client offering h3 completed the handshake")
	} else if te := (*qgo.TransportError)(nil); !errors.As(err, &te) || !te.ErrorCode.IsCryptoError() {
		t.Errorf("dial with ALPN h3: %v, want a TLS alert", err)
	}

	// A per-client tls.Config may negotiate another protocol; the passive
	// verifies it after the handshake.
	srv2 := srvTLS.Clone()
	srv2.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		c := srvTLS.Clone()
		c.NextProtos = []string{"h3"}
		return c, nil
	}
	l2, f2 := serveFake(t, Options{TLS: srv2})
	qc, err := rawTransport(t).Dial(ctx, l2.Addr(), raw, quicConfig(nil, 0, false, true))
	if err != nil {
		t.Fatal(err)
	}
	defer qc.CloseWithError(0, "")
	if p := qc.ConnectionState().TLS.NegotiatedProtocol; p != "h3" {
		t.Fatalf("negotiated %q", p)
	}
	if err := qc.SendDatagram([]byte("first")); err != nil {
		t.Fatal(err)
	}
	if code, remote := closeCode(t, qc); code != codeBadKind || !remote {
		t.Errorf("closed with code %d (remote %v), want codeBadKind from the listener", code, remote)
	}
	if s := l2.Stats(); s.BadKind != 1 || s.Datagrams+s.Streams != 0 || len(f2.packets)+len(f2.streams) != 0 {
		t.Errorf("stats %+v", s)
	}
	if s := l.Stats(); s.Datagrams+s.Streams+s.BadKind != 0 || len(f.packets)+len(f.streams) != 0 {
		t.Errorf("a failed handshake reached the listener: %+v", s)
	}
}

// TestQUICDialByHostName: a carrier dialed by host name verifies the
// server's certificate against that name (sent as SNI) unless
// tls.Config.ServerName is set, which is kept; an IP literal is verified
// against the IP.
func TestQUICDialByHostName(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	l, _ := serveFake(t, Options{TLS: nameOnlyTLS(t)}) // the certificate names only localhost
	port := strconv.Itoa(l.Addr().(*net.UDPAddr).Port)
	for _, tc := range []struct {
		name, host, serverName string
		ok                     bool
	}{
		{"by name", "localhost", "", true},
		{"explicit ServerName kept", "localhost", "other.invalid", false},
		{"IP literal with ServerName", "127.0.0.1", "localhost", true},
		{"IP literal", "127.0.0.1", "", false},
	} {
		o := clientOptions(t)
		o.TLS.ServerName = tc.serverName
		addr := net.JoinHostPort(tc.host, port)
		sc, err := StreamCarrier("q", addr, o)
		if err != nil {
			t.Fatal(err)
		}
		dc, err := DatagramCarrier("q", addr, o)
		if err != nil {
			t.Fatal(err)
		}
		c, serr := sc.Dial(dialCtx(t))
		if c != nil {
			_ = c.Close()
		}
		pc, _, derr := dc.Dial(dialCtx(t))
		if pc != nil {
			_ = pc.Close()
		}
		if (serr == nil) != tc.ok || (derr == nil) != tc.ok {
			t.Errorf("%s (%s, ServerName %q): stream %v, datagram %v; want success %v", tc.name, addr, tc.serverName, serr, derr, tc.ok)
		}
	}
}
