package quic

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// applyOptsToTLS clones base and applies any path-spec overrides
// (server_name, alpn, insecure, ca_pem). Returning a fresh clone
// every call keeps concurrent DialPath calls from racing on the
// shared base.
func applyOptsToTLS(base *tls.Config, opts map[string]string) (*tls.Config, error) {
	out := base.Clone()
	if v, ok := opts["server_name"]; ok && v != "" {
		out.ServerName = v
	}
	if v, ok := opts["alpn"]; ok && v != "" {
		parts := strings.Split(v, ",")
		out.NextProtos = parts
		// Force the rendr ALPN to appear in the list - even if the
		// embedder forgot it - because the server side advertises it.
		hasRendr := false
		for _, p := range parts {
			if strings.TrimSpace(p) == ALPN {
				hasRendr = true
				break
			}
		}
		if !hasRendr {
			out.NextProtos = append(out.NextProtos, ALPN)
		}
	}
	if v, ok := opts["insecure"]; ok && v == "true" {
		out.InsecureSkipVerify = true //nolint:gosec // opt-in
	}
	if v, ok := opts["ca_pem"]; ok && v != "" {
		pool := out.RootCAs
		if pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(v)) {
			return nil, fmt.Errorf("quic: ca_pem did not contain any parseable certificate")
		}
		out.RootCAs = pool
	}
	return out, nil
}

// ALPN is the protocol identifier rendr advertises in QUIC TLS.
// Embedders that want a custom ALPN must override via the Transport
// constructor; the value is wire-stable so any change requires
// bumping proto.Version per CLAUDE.md hard rule #7.
const ALPN = "rendr/0"

// devTLSConfig builds an insecure self-signed TLS config suitable for
// dev / test loopback. Production embedders must supply their own
// tls.Config (cert from a real CA, peer-name pinning, etc).
//
// Returns one config for the server (listening) and one for the
// client (dialing). They share a freshly-generated key.
func devTLSConfig() (server *tls.Config, client *tls.Config, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rendr-dev"},
		DNSNames:     []string{"rendr-dev", "localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, err
	}
	server = &tls.Config{
		Certificates: []tls.Certificate{pair},
		NextProtos:   []string{ALPN},
		MinVersion:   tls.VersionTLS13,
	}
	client = &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // dev-only convenience
		NextProtos:         []string{ALPN},
		MinVersion:         tls.VersionTLS13,
	}
	return server, client, nil
}
