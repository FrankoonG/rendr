// Command mtls shows how an embedder wraps rendr carriers in mutually
// authenticated TLS 1.3 over carrier/tcp with the standard library (plan
// §1.4): rendr neither encrypts nor authenticates, so the passive side
// verifies the client certificate before a carrier reaches rendr and the
// dialer's factory completes its handshake before rendr sees the conn. A
// rendr InstanceID is not an identity; trust comes from the certificates.
// It echoes one message through a session on the IPv4 loopback address.
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
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/carrier/tcp"
)

// loopback is the only address the example uses.
const loopback = "127.0.0.1"

// pki holds the TLS configurations issued by a throwaway in-memory CA.
type pki struct {
	server *tls.Config // ClientAuth: RequireAndVerifyClientCert, MinVersion TLS 1.3
	client *tls.Config // RootCAs = the CA, Certificates = client leaf
}

// newPKI issues an ECDSA P-256 CA and loopback leaves valid for a day.
func newPKI() (*pki, error) {
	now := time.Now()
	tmpl := func(serial int64, name string, usage x509.ExtKeyUsage) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
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
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
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
	return func() {
		ln.Close()
		wg.Wait()
	}
}

// run starts both Runtimes, dials, echoes msg and returns what came back.
func run(p *pki, msg []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	passive, err := rendr.NewRuntime(rendr.Config{})
	if err != nil {
		return nil, err
	}
	defer passive.Close()
	ln, err := passive.Listen(rendr.ListenConfig{}) // push-only: fed by serveTLS
	if err != nil {
		return nil, err
	}
	raw, err := tcp.Listen("tcp", net.JoinHostPort(loopback, "0"), tcp.Options{})
	if err != nil {
		return nil, err
	}
	defer serveTLS(raw, p.server, 10*time.Second, ln.Handle)()
	echoed := make(chan error, 1)
	go func() { echoed <- echoOne(ctx, ln) }() // the passive application
	got, err := dialEcho(ctx, raw.Addr().String(), p.client, msg)
	cancel() // an echo still waiting in Accept gives up
	return got, errors.Join(err, <-echoed)
}

// dialEcho sends msg and a FIN over one selector session and reads the echo.
func dialEcho(ctx context.Context, addr string, cfg *tls.Config, msg []byte) ([]byte, error) {
	dialer, err := rendr.NewRuntime(rendr.Config{})
	if err != nil {
		return nil, err
	}
	defer dialer.Close()
	peer, err := dialer.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{tlsCarrier("mtls", addr, cfg)}})
	if err != nil {
		return nil, err
	}
	conn, err := peer.Dial(ctx, rendr.DialOptions{Mode: rendr.ModeSelector})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err := conn.Write(msg); err != nil {
		return nil, err
	}
	if err := conn.CloseWrite(); err != nil {
		return nil, err
	}
	return io.ReadAll(conn)
}

// echoOne confirms one session and echoes it until the dialer's FIN.
func echoOne(ctx context.Context, ln *rendr.Listener) error {
	pc, err := ln.Accept(ctx)
	if err != nil {
		return err
	}
	c, err := pc.Confirm()
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := io.Copy(c, c); err != nil {
		return err
	}
	return c.CloseWrite()
}

func main() {
	p, err := newPKI()
	if err == nil {
		var got []byte
		if got, err = run(p, []byte("hello over mutually authenticated carriers")); err == nil {
			fmt.Printf("echoed %q\n", got)
			return
		}
	}
	fmt.Fprintln(os.Stderr, "mtls:", err)
	os.Exit(1)
}
