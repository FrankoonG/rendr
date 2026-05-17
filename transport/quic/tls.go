package quic

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

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
