package quic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	qgo "github.com/quic-go/quic-go"
)

// The WP9 tests run on real loopback sockets, outside synctest bubbles
// (quic-go needs the network poller); every test registers
// rendrtest.AssertNoLeak first so that it checks after every cleanup.

var (
	pkiOnce        sync.Once
	pkiSrv, pkiCli *tls.Config
	pkiErr         error
	errNotHanded   = errors.New("fake rendr: closed")
)

const (
	handTimeout        = 5 * time.Second // a carrier reaches the fake rendr side
	testDialTimeout    = 5 * time.Second // as rendr's DialTimeout bounds a factory call
	testEventuallyTime = 5 * time.Second
)

// testTLS returns a server configuration whose certificate (signed by a
// test CA) names 127.0.0.1, ::1 and localhost, and a client configuration
// that verifies it.
func testTLS(t testing.TB) (srv, cli *tls.Config) {
	t.Helper()
	pkiOnce.Do(func() {
		issue := func(tmpl, parent *x509.Certificate, signer any) (tls.Certificate, error) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return tls.Certificate{}, err
			}
			if parent == nil {
				parent, signer = tmpl, key
			}
			der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
			if err != nil {
				return tls.Certificate{}, err
			}
			leaf, err := x509.ParseCertificate(der)
			return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, err
		}
		now := time.Now()
		ca, err := issue(&x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "rendr quic test CA"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign}, nil, nil)
		if err != nil {
			pkiErr = err
			return
		}
		leaf, err := issue(&x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "rendr quic test"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), DNSNames: []string{"localhost"},
			IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}, KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, ca.Leaf, ca.PrivateKey)
		if err != nil {
			pkiErr = err
			return
		}
		pool := x509.NewCertPool()
		pool.AddCert(ca.Leaf)
		pkiSrv = &tls.Config{Certificates: []tls.Certificate{leaf}}
		pkiCli = &tls.Config{RootCAs: pool}
	})
	if pkiErr != nil {
		t.Fatal(pkiErr)
	}
	return pkiSrv.Clone(), pkiCli.Clone()
}

// fakeRendr stands in for a *rendr.Listener: it collects what Serve hands
// over, or refuses everything once refuse is set.
type fakeRendr struct {
	streams chan net.Conn
	packets chan *dgramConn
	mu      sync.Mutex
	refuse  bool
}

func newFakeRendr() *fakeRendr {
	return &fakeRendr{streams: make(chan net.Conn, 64), packets: make(chan *dgramConn, 64)}
}

func (f *fakeRendr) refusing() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.refuse
}

func (f *fakeRendr) Handle(c net.Conn) error {
	if f.refusing() {
		_ = c.Close() // as rendr.Listener.Handle after Close
		return net.ErrClosed
	}
	f.streams <- c
	return nil
}

func (f *fakeRendr) HandlePacket(pc net.PacketConn, peer net.Addr) error {
	d := pc.(*dgramConn)
	if f.refusing() || peer != d.peer {
		return errNotHanded // pc stays the caller's (rendr's HandlePacket contract)
	}
	f.packets <- d
	return nil
}

func (f *fakeRendr) stream(t testing.TB) net.Conn {
	t.Helper()
	select {
	case c := <-f.streams:
		return c
	case <-time.After(handTimeout):
		t.Fatal("no stream carrier handed over")
		return nil
	}
}

func (f *fakeRendr) packet(t testing.TB) *dgramConn {
	t.Helper()
	select {
	case d := <-f.packets:
		return d
	case <-time.After(handTimeout):
		t.Fatal("no datagram carrier handed over")
		return nil
	}
}

// serveFake opens a Listener on loopback and serves it to a fakeRendr;
// the cleanup closes it, checks Serve's net.ErrClosed, closes whatever is
// left in the fake and waits for Done.
func serveFake(t testing.TB, o Options) (*Listener, *fakeRendr) {
	t.Helper()
	if o.TLS == nil {
		o.TLS, _ = testTLS(t)
	}
	l, err := Listen("udp4", "127.0.0.1:0", o)
	if err != nil {
		t.Fatal(err)
	}
	f := newFakeRendr()
	served := make(chan error, 1)
	go func() { served <- l.serve(f) }()
	t.Cleanup(func() {
		_ = l.Close()
		if err := <-served; !errors.Is(err, net.ErrClosed) {
			t.Errorf("Serve returned %v, want net.ErrClosed", err)
		}
		f.mu.Lock()
		f.refuse = true
		f.mu.Unlock()
		for done := false; !done; {
			select {
			case c := <-f.streams:
				_ = c.Close()
			case d := <-f.packets:
				_ = d.Close()
			default:
				done = true
			}
		}
		select {
		case <-l.Done():
		case <-time.After(testEventuallyTime):
			t.Errorf("Listener.Done not closed after every carrier was closed")
		}
	})
	return l, f
}

// rawClientTLS is the client configuration of a raw quic-go dialer.
func rawClientTLS(t testing.TB) *tls.Config {
	_, cli := testTLS(t)
	cli.NextProtos = []string{ALPN}
	return cli
}

// clientOptions returns dialer Options trusting the test CA.
func clientOptions(t testing.TB) Options {
	_, cli := testTLS(t)
	return Options{TLS: cli}
}

// dialCtx returns a context bounded like rendr's DialTimeout.
func dialCtx(t testing.TB) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), testDialTimeout)
	t.Cleanup(cancel)
	return ctx
}

// dgramPair dials a datagram carrier to a served Listener and returns both
// adapters after the classification datagram was read on the passive.
func dgramPair(t testing.TB, so, co Options) (cli, srv *dgramConn, l *Listener) {
	t.Helper()
	l, f := serveFake(t, so)
	if co.TLS == nil {
		co.TLS = clientOptions(t).TLS
	}
	dc, err := DatagramCarrier("q", l.Addr().String(), co)
	if err != nil {
		t.Fatal(err)
	}
	pc, peer, err := dc.Dial(dialCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	cli = pc.(*dgramConn)
	t.Cleanup(func() { _ = cli.Close() })
	if peer != cli.peer {
		t.Fatalf("Dial returned peer %v, not the conn's peer value", peer)
	}
	if _, err := cli.WriteTo([]byte("classify"), nil); err != nil {
		t.Fatal(err)
	}
	srv = f.packet(t)
	t.Cleanup(func() { _ = srv.Close() })
	buf := make([]byte, DatagramBudget+1)
	if n, from, err := srv.ReadFrom(buf); err != nil || string(buf[:n]) != "classify" || from != srv.peer {
		t.Fatalf("first datagram: %q from %v, %v", buf[:n], from, err)
	}
	return cli, srv, l
}

// streamPair dials a stream carrier to a served Listener and returns both
// ends once the passive got the stream (the dialer writes one byte).
func streamPair(t testing.TB, so, co Options) (cli, srv net.Conn, l *Listener) {
	t.Helper()
	l, f := serveFake(t, so)
	if co.TLS == nil {
		co.TLS = clientOptions(t).TLS
	}
	sc, err := StreamCarrier("q", l.Addr().String(), co)
	if err != nil {
		t.Fatal(err)
	}
	if cli, err = sc.Dial(dialCtx(t)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	if _, err := cli.Write([]byte{0x5a}); err != nil {
		t.Fatal(err)
	}
	srv = f.stream(t)
	t.Cleanup(func() { _ = srv.Close() })
	b := make([]byte, 1)
	if _, err := srv.Read(b); err != nil || b[0] != 0x5a {
		t.Fatalf("first byte %x, %v", b, err)
	}
	return cli, srv, l
}

// rawPair connects two quic-go conns over loopback with the given
// configurations (nil: rendr's enforced client and server configurations),
// each on its own Transport and socket.
func rawPair(t testing.TB, ccfg, scfg *qgo.Config) (cli, srv *qgo.Conn) {
	t.Helper()
	if ccfg == nil {
		ccfg = quicConfig(nil, 0, false, true)
	}
	if scfg == nil {
		scfg = quicConfig(nil, 0, true, true)
	}
	srvTLS, cliTLS := testTLS(t)
	srvTLS.NextProtos, cliTLS.NextProtos = []string{ALPN}, []string{ALPN}
	str, ctr := rawTransport(t), rawTransport(t)
	ln, err := str.Listen(srvTLS, scfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	ctx := dialCtx(t)
	if cli, err = ctr.Dial(ctx, str.Conn.LocalAddr(), cliTLS, ccfg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.CloseWithError(0, "") })
	if srv, err = ln.Accept(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.CloseWithError(0, "") })
	return cli, srv
}

// rawTransport is a quic-go Transport on its own loopback socket.
func rawTransport(t testing.TB) *qgo.Transport {
	t.Helper()
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	tr := &qgo.Transport{Conn: u}
	t.Cleanup(func() { _ = tr.Close(); _ = u.Close() })
	return tr
}

// eventually polls cond every 5 ms until it holds or the time is up.
func eventually(t testing.TB, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(testEventuallyTime)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("not after %v: %s", testEventuallyTime, what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// closeCode returns the application error code and the remote flag of
// the error that ended qc (it waits for the end).
func closeCode(t testing.TB, qc *qgo.Conn) (qgo.ApplicationErrorCode, bool) {
	t.Helper()
	select {
	case <-qc.Context().Done():
	case <-time.After(testEventuallyTime):
		t.Fatal("connection not closed")
	}
	var ae *qgo.ApplicationError
	if !errors.As(context.Cause(qc.Context()), &ae) {
		t.Fatalf("connection ended by %v, not an application error", context.Cause(qc.Context()))
	}
	return ae.ErrorCode, ae.Remote
}
