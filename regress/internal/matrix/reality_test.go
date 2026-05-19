package matrix

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	cryptotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/regress/internal/matrix/driver"
	"github.com/FrankoonG/rendr/regress/internal/xrayglue"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/vless"
	vlessinbound "github.com/xtls/xray-core/proxy/vless/inbound"
	vlessoutbound "github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	transtcp "github.com/xtls/xray-core/transport/internet/tcp"

	_ "github.com/xtls/xray-core/transport/internet/reality"
)

// TestT3VlessVisionRealityXItself — DEFERRED.
//
// REALITY is designed to look indistinguishable from a real HTTPS
// server even to an active probe. Its authentication path requires
// the configured Dest (fallback target) to respond to TLS probes
// the way a real-world site like google.com:443 would — specific
// cipher suite selection, ALPN behavior, and certificate validation
// path that a stock crypto/tls listener doesn't satisfy. uTLS-chrome
// on the client side compounds the mismatch.
//
// xray-core's own REALITY tests deliberately use a real internet
// host (commented "may fail in some region") because the upstream
// test infra has no local equivalent. Replicating that in-process
// requires either:
//   - running a uTLS-fingerprint-matching Go server (no off-the-
//     shelf library does this; xray-core itself bundles parts of
//     refraction-networking/utls but it's tightly integrated)
//   - or a small standalone fake-Chrome TLS server in our test
//     package
//
// Either is its own ~200-LOC piece, larger than the existing case
// shape. Skip for now and surface the gap in the report so it's
// visible. The other VLESS+Vision+TLS variants (plain TLS,
// TLS+MLKEM) already cover the bulk of the protocol+rendr-migration
// interaction; REALITY adds resistance-to-probing semantics that
// rendr is transparent to.
func TestT3VlessVisionRealityXItself(t *testing.T) {
	t.Skip("REALITY needs a real-internet-like TLS Dest (uTLS fingerprint+cipher match); see test source for the longer note")
	_ = mustGenerateX25519
	_ = startTLSFallback
	_ = startVlessRealityServer
	_ = startVlessRealityClient
	_ = xrayglue.XrayInstanceAsStreamFactory
	_ = rendr.PathSpec{}
	_ = driver.FileXferOpts{}
	_ = context.Background
	_ = time.Second
	_ = protocol.NewID
	_ = uuid.New
	_ = hex.DecodeString
}

func mustGenerateX25519(t *testing.T) (privBytes, pubBytes []byte) {
	t.Helper()
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv.Bytes(), priv.PublicKey().Bytes()
}

// startTLSFallback runs a minimal TLS listener that accepts + closes
// every incoming connection. It exists only so REALITY has a Dest
// to forward unauthenticated probe traffic to (test clients always
// authenticate, so this codepath isn't exercised, but REALITY's
// config validation requires a reachable Dest).
func startTLSFallback(t *testing.T) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	tlsCert := cryptotls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}
	ln, err := cryptotls.Listen("tcp", "127.0.0.1:0", &cryptotls.Config{
		Certificates: []cryptotls.Certificate{tlsCert},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// REALITY's probe-forwarding path needs the Dest to
			// actually complete a TLS handshake and stay alive long
			// enough for REALITY to inspect the ServerHello. Drive
			// the handshake by reading + discarding; close on EOF.
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
						return
					}
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

func startVlessRealityServer(t *testing.T, port int, userID, destAddr string, priv []byte, shortIds [][]byte) *core.Instance {
	t.Helper()
	cfg := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(xnet.Port(port))}},
					Listen:   xnet.NewIPOrDomain(xnet.LocalHostIP),
					StreamSettings: &internet.StreamConfig{
						ProtocolName: "tcp",
						SecurityType: serial.GetMessageType(&reality.Config{}),
						SecuritySettings: []*serial.TypedMessage{
							serial.ToTypedMessage(&reality.Config{
								Dest:        destAddr,
								ServerNames: []string{"localhost"},
								PrivateKey:  priv,
								ShortIds:    shortIds,
								Type:        "tcp",
							}),
						},
					},
				}),
				ProxySettings: serial.ToTypedMessage(&vlessinbound.Config{
					Users: []*protocol.User{
						{
							Account: serial.ToTypedMessage(&vless.Account{
								Id:   userID,
								Flow: vless.XRV,
							}),
						},
					},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
				}),
			},
		},
	}
	return mustStartInstance(t, cfg)
}

func startVlessRealityClient(t *testing.T, port int, userID string, pub, shortID []byte) *core.Instance {
	t.Helper()
	cfg := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&vlessoutbound.Config{
					Vnext: &protocol.ServerEndpoint{
						Address: xnet.NewIPOrDomain(xnet.LocalHostIP),
						Port:    uint32(port),
						User: &protocol.User{
							Account: serial.ToTypedMessage(&vless.Account{
								Id:   userID,
								Flow: vless.XRV,
							}),
						},
					},
				}),
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
					StreamSettings: &internet.StreamConfig{
						ProtocolName: "tcp",
						TransportSettings: []*internet.TransportConfig{
							{
								ProtocolName: "tcp",
								Settings:     serial.ToTypedMessage(&transtcp.Config{}),
							},
						},
						SecurityType: serial.GetMessageType(&reality.Config{}),
						SecuritySettings: []*serial.TypedMessage{
							serial.ToTypedMessage(&reality.Config{
								Fingerprint: "chrome",
								ServerName:  "localhost",
								PublicKey:   pub,
								ShortId:     shortID,
								SpiderX:     "/",
							}),
						},
					},
				}),
			},
		},
	}
	return mustStartInstance(t, cfg)
}
