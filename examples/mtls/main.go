// Command mtls shows how an embedder wraps rendr carriers in mutually
// authenticated TLS using only the standard library (plan §1.4, ≤ 200
// lines). rendr itself neither encrypts nor authenticates: here every
// carrier is a TLS 1.3 connection over carrier/tcp, the passive side requires
// and verifies a client certificate (tls.RequireAndVerifyClientCert) and
// hands a carrier to rendr only after its handshake succeeded, and the
// dialer's factory completes HandshakeContext before handing the conn to
// rendr. rendr sees only the *tls.Conn, so it uses the coalesced write path
// (one TLS record per batch). A rendr InstanceID is not an identity: trust
// comes from the certificates.
//
// The program builds a throwaway CA and two leaf certificates in memory,
// starts a passive and a dialer Runtime on the IPv4 loopback address, dials
// one selector session, echoes a message through it and exits 0. Its test
// also checks that a client without a certificate never reaches rendr.
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

// pki holds the in-memory CA and the two TLS configurations.
type pki struct {
	server *tls.Config // ClientAuth: RequireAndVerifyClientCert, MinVersion TLS 1.3
	client *tls.Config // RootCAs = the CA, Certificates = client leaf
}

// newPKI generates an ECDSA P-256 CA and server/client leaves valid for the
// IPv4 loopback address for one day.
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

// issue creates a key and a certificate for tmpl signed by parent
// (self-signed when parent is nil).
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

// tlsCarrier is a rendr carrier factory: a carrier/tcp connection wrapped in
// TLS whose handshake (verifying the passive's certificate) completes before
// rendr sees the conn.
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

// serveTLS accepts raw carriers from ln, completes each TLS handshake — which
// verifies the client certificate — within timeout, and hands only
// authenticated conns to handle (a rendr Listener's Handle). stop closes ln
// and waits for every goroutine serveTLS started.
func serveTLS(ln net.Listener, cfg *tls.Config, timeout time.Duration, handle func(net.Conn) error) (stop func()) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				defer cancel()
				tc := tls.Server(c, cfg)
				if err := tc.HandshakeContext(ctx); err != nil {
					c.Close()
					return
				}
				if handle(tc) != nil {
					tc.Close()
				}
			}()
		}
	}()
	return func() {
		ln.Close()
		wg.Wait()
	}
}

// run starts both Runtimes, dials, echoes msg and returns what came back.
func run(p *pki, msg []byte) (got []byte, err error) {
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

	var wg sync.WaitGroup
	var echoErr error
	wg.Add(1)
	go func() { // the passive application
		defer wg.Done()
		echoErr = echoOne(ctx, ln)
	}()
	defer func() {
		cancel() // an echo still waiting in Accept gives up
		wg.Wait()
		if err == nil {
			err = echoErr
		}
	}()

	dialer, err := rendr.NewRuntime(rendr.Config{})
	if err != nil {
		return nil, err
	}
	defer dialer.Close()
	peer, err := dialer.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{tlsCarrier("mtls", raw.Addr().String(), p.client)}})
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
	if err != nil {
		fmt.Fprintln(os.Stderr, "pki:", err)
		os.Exit(1)
	}
	got, err := run(p, []byte("hello over mutually authenticated carriers"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "run:", err)
		os.Exit(1)
	}
	fmt.Printf("echoed %q\n", got)
}
