package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/carrier/tcp"
)

// TestMutualTLSGatesCarriers checks the TLS layer of the example on real
// loopback sockets, ahead of rendr: a dialer with the client certificate
// reaches the handler (rendr's Listener.Handle in run) over a verified TLS
// 1.3 conn carrying bytes both ways; a dialer without a certificate, and a
// dialer that does not trust the passive's CA, never reach it.
func TestMutualTLSGatesCarriers(t *testing.T) {
	p, err := newPKI()
	if err != nil {
		t.Fatalf("newPKI: %v", err)
	}
	raw, err := tcp.Listen("tcp", net.JoinHostPort(loopback, "0"), tcp.Options{})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	handled := make(chan net.Conn, 4)
	stop := serveTLS(raw, p.server, 5*time.Second, func(c net.Conn) error {
		handled <- c
		return nil
	})
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addr := raw.Addr().String()

	c, err := tlsCarrier("mtls", addr, p.client).Dial(ctx)
	if err != nil {
		t.Fatalf("authenticated dial: %v", err)
	}
	defer c.Close()
	srv := <-handled
	defer srv.Close()
	st := srv.(*tls.Conn).ConnectionState()
	if st.Version != tls.VersionTLS13 || len(st.PeerCertificates) != 1 || st.PeerCertificates[0].Subject.CommonName != "rendr example dialer" {
		t.Fatalf("passive sees version %#x, peer certificates %d", st.Version, len(st.PeerCertificates))
	}
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(srv, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("Read = %q, %v", buf, err)
	}

	anon := p.client.Clone()
	anon.Certificates = nil
	if c, err := tlsCarrier("anon", addr, anon).Dial(ctx); err == nil {
		// TLS 1.3 clients finish before the server checks their certificate:
		// the rejection arrives as an alert on the first read.
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Fatal("a client without a certificate could read")
		}
		c.Close()
	}
	untrusting := p.client.Clone()
	untrusting.RootCAs = x509.NewCertPool()
	if c, err := tlsCarrier("untrusting", addr, untrusting).Dial(ctx); err == nil {
		c.Close()
		t.Fatal("a dialer that does not trust the CA completed its handshake")
	}
	stop()
	if n := len(handled); n != 0 {
		t.Fatalf("%d unauthenticated carriers reached the handler", n)
	}
}
