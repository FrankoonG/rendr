// Command mtls shows how an embedder wraps rendr carriers in mutually
// authenticated TLS 1.3 over carrier/tcp with the standard library:
// rendr neither encrypts nor authenticates, so the passive side
// verifies the client certificate before a carrier reaches rendr and the
// dialer's factory completes its handshake before rendr sees the conn. A
// rendr InstanceID is not an identity; trust comes from the certificates.
// It echoes one message through a session on the IPv4 loopback address and
// ends that session cleanly on both sides before either Runtime closes:
// each side reads until io.EOF, closes its Conn and waits for Conn.Done.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/carrier/tcp"
)

const (
	loopback = "127.0.0.1" // the only address the example uses
	greeting = "hello over mutually authenticated carriers"
)

// pki holds the TLS 1.3 configurations issued by a throwaway in-memory CA:
// server requires and verifies the client certificate; client trusts the CA
// and presents the client leaf.
type pki struct{ server, client *tls.Config }

// newPKI issues an ECDSA P-256 CA and loopback leaves valid for a day.
func newPKI() (*pki, error) {
	tmpl := func(serial int64, name string, usage x509.ExtKeyUsage) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
			IPAddresses: []net.IP{net.ParseIP(loopback)},
		}
	}
	caTmpl := tmpl(1, "rendr example CA", x509.ExtKeyUsageAny)
	caTmpl.IsCA, caTmpl.BasicConstraintsValid, caTmpl.KeyUsage = true, true, x509.KeyUsageCertSign
	ca, err := issue(caTmpl, nil)
	if err != nil {
		return nil, err
	}
	srv, err1 := issue(tmpl(2, "rendr example passive", x509.ExtKeyUsageServerAuth), &ca)
	cli, err2 := issue(tmpl(3, "rendr example dialer", x509.ExtKeyUsageClientAuth), &ca)
	if err := errors.Join(err1, err2); err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Leaf)
	return &pki{
		server: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{srv},
			ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert},
		client: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cli},
			RootCAs: pool, ServerName: loopback},
	}, nil
}

// issue creates a key and a certificate for tmpl signed by parent (or self).
func issue(tmpl *x509.Certificate, parent *tls.Certificate) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	signer, signKey := tmpl, any(key)
	if parent != nil {
		signer, signKey = parent.Leaf, parent.PrivateKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, err
}

// tlsCarrier is a factory of carrier/tcp connections wrapped in TLS; the
// handshake verifies the passive's certificate before rendr sees the conn.
func tlsCarrier(name, addr string, cfg *tls.Config) rendr.StreamCarrier {
	base := tcp.Carrier(name, "tcp", addr, tcp.Options{})
	return rendr.StreamCarrier{Name: name, Dial: func(ctx context.Context) (net.Conn, error) {
		c, err := base.Dial(ctx)
		if err != nil {
			return nil, err
		}
		tc := tls.Client(c, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			c.Close()
			return nil, err
		}
		return tc, nil
	}}
}

// serveTLS hands only conns from ln whose TLS handshake (verifying the client
// certificate) completed within timeout to handle, a rendr Listener's
// Handle. stop closes ln and joins every goroutine serveTLS started.
func serveTLS(ln net.Listener, cfg *tls.Config, timeout time.Duration, handle func(net.Conn) error) (stop func()) {
	var wg sync.WaitGroup
	wg.Go(func() {
		for c, err := ln.Accept(); err == nil; c, err = ln.Accept() {
			wg.Go(func() {
				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				defer cancel()
				tc := tls.Server(c, cfg)
				if err := tc.HandshakeContext(ctx); err != nil {
					c.Close()
				} else if handle(tc) != nil {
					tc.Close()
				}
			})
		}
	})
	return func() { ln.Close(); wg.Wait() }
}

// result is what run observed: the echo, and the final Status of the
// session at each end as finish reported it (ended with io.EOF when run
// succeeds).
type result struct {
	echo            []byte
	dialer, passive rendr.SessionStatus
}

// run starts both Runtimes, echoes msg through one session and reports the
// result. Each side ends its session (finish) before its Runtime closes.
func run(p *pki, msg []byte) (r result, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	passive, err := rendr.NewRuntime(rendr.Config{})
	if err != nil {
		return r, err
	}
	defer passive.Close()
	ln, err := passive.Listen(rendr.ListenConfig{}) // push-only: fed by serveTLS
	if err != nil {
		return r, err
	}
	raw, err := tcp.Listen("tcp", net.JoinHostPort(loopback, "0"), tcp.Options{})
	if err != nil {
		return r, err
	}
	defer serveTLS(raw, p.server, 10*time.Second, ln.Handle)()
	var app sync.WaitGroup // the passive application
	var appErr error
	app.Go(func() { r.passive, appErr = echoOne(ctx, ln) })
	r.echo, r.dialer, err = dialEcho(ctx, raw.Addr().String(), p.client, msg)
	if err != nil {
		cancel() // the passive application stops waiting
	}
	app.Wait()
	return r, errors.Join(err, appErr)
}

// dialEcho sends msg and a FIN over one selector session, reads the echo
// until the passive's FIN and ends the session (finish) before its Runtime
// closes. It returns the echo and the session's final Status (zero unless
// finish ran).
func dialEcho(ctx context.Context, addr string, cfg *tls.Config, msg []byte) (echo []byte, st rendr.SessionStatus, err error) {
	dialer, err := rendr.NewRuntime(rendr.Config{})
	if err != nil {
		return nil, st, err
	}
	defer dialer.Close() // runs last: it resets every session that has not ended
	peer, err := dialer.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{tlsCarrier("mtls", addr, cfg)}})
	if err != nil {
		return nil, st, err
	}
	conn, err := peer.Dial(ctx, rendr.DialOptions{Mode: rendr.ModeSelector})
	if err != nil {
		return nil, st, err
	}
	defer conn.Close()
	if _, err := conn.Write(msg); err != nil {
		return nil, st, err
	}
	if err := conn.CloseWrite(); err != nil { // our FIN ends the passive's echo loop
		return nil, st, err
	}
	if echo, err = io.ReadAll(conn); err == nil { // until the passive's FIN
		st, err = finish(ctx, conn)
	}
	return echo, st, err
}

// echoOne confirms one session, echoes it until the dialer's FIN and ends
// it (finish; its Close sends the passive's FIN after the echo). It returns
// the session's final Status (zero unless finish ran).
func echoOne(ctx context.Context, ln *rendr.Listener) (rendr.SessionStatus, error) {
	pc, err := ln.Accept(ctx)
	if err != nil {
		return rendr.SessionStatus{}, err
	}
	c, err := pc.Confirm()
	if err != nil {
		return rendr.SessionStatus{}, err
	}
	defer c.Close()
	if _, err := io.Copy(c, c); err != nil {
		return rendr.SessionStatus{}, err
	}
	return finish(ctx, c)
}

// finish closes c and waits, bounded by ctx, until its session has ended
// (Conn.Done). It returns the session's final Status and an error unless the
// end was clean (io.EOF).
//
// Call it once Read returned io.EOF: the peer's FIN has arrived, so Close
// discards nothing; it sends this side's FIN unless CloseWrite already did.
// The session then finishes in the background: it delivers what was
// written and, once both FINs are delivered, exchanges DONE with the peer;
// then Done is closed. Only after that may the Runtime close: Runtime.Close
// resets every session that has not ended — also a closed one that is still
// finishing — which then ends with net.ErrClosed and its peer with
// *rendr.AbortError instead of io.EOF (unless both FINs had already been
// delivered and only the final confirmation was outstanding). (A Close
// while the peer may still send discards what arrives and can reset the
// peer: AbortClosed, or AbortLinger after Config.Linger.)
func finish(ctx context.Context, c *rendr.Conn) (rendr.SessionStatus, error) {
	c.Close()
	select {
	case <-c.Done(): // ended: the Status read below is final
	case <-ctx.Done():
		return c.Status(), fmt.Errorf("session not ended: %w", ctx.Err())
	}
	st := c.Status()
	if st.Err != io.EOF {
		return st, fmt.Errorf("session ended with %w", st.Err)
	}
	return st, nil
}

func main() {
	p, err := newPKI()
	if err != nil {
		log.Fatal("mtls: ", err)
	}
	r, err := run(p, []byte(greeting))
	if err != nil {
		log.Fatal("mtls: ", err)
	}
	fmt.Printf("echoed %q; the session ended cleanly at both ends\n", r.echo)
}
