package matrix

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/regress/internal/matrix/driver"
	"github.com/FrankoonG/rendr/regress/internal/xrayglue"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tls"

	_ "github.com/xtls/xray-core/proxy/trojan"
)

// TestT3TrojanxTrojan — PYS-D-2 reference (Trojan + TLS). Trojan
// REQUIRES TLS (its protocol identity is "looks like HTTPS"), so
// this is also the first TLS-using case in the matrix. Self-signed
// cert generated per run; client pins the SHA-256 to skip
// hostname verification (127.0.0.1 vs CN=localhost mismatch).
//
// Topology mirrors SS-2022/VMess: rendr -> trojan outbound (TLS
// to trojan server) -> trojan decodes -> freedom -> rendr-server.
// Two paths, each an independent TLS-wrapped Trojan session.
func TestT3TrojanxTrojan(t *testing.T) {
	trojanServerPort := pickFreePort(t)
	password := randomTrojanPassword(t)
	ct, ctHash := cert.MustGenerate(nil, cert.CommonName("localhost"))

	trojanServerInst := startTrojanServer(t, trojanServerPort, password, ct)
	defer trojanServerInst.Close()
	trojanClientInst := startTrojanClient(t, trojanServerPort, password, ctHash)
	defer trojanClientInst.Close()

	factory := xrayglue.XrayInstanceAsStreamFactory(trojanClientInst)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	r := driver.RunFileXfer(ctx, driver.FileXferOpts{
		CaseName: "T3.stream.trojan×trojan",
		Paths: []rendr.PathSpec{
			{Transport: "xray-trojan"},
			{Transport: "xray-trojan"},
		},
		Factories: []driver.NamedFactory{
			{Name: "xray-trojan", Stream: factory},
		},
	})
	if r.Failure != "" {
		t.Fatalf("case failed: %s", r.Failure)
	}
	if !r.SHA256Match {
		t.Fatal("sha256 mismatch")
	}
	if r.MigrationsDone == 0 {
		t.Fatal("zero migrations fired")
	}
	t.Logf("PASS: %s elapsed=%s bytes=%d migrations=%d/%d",
		r.Name, r.Elapsed, r.BytesReceived, r.MigrationsDone, r.MigrationsAsked)
}

func startTrojanServer(t *testing.T, trojanServerPort int, password string, srvCert *cert.Certificate) *core.Instance {
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
					PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(xnet.Port(trojanServerPort))}},
					Listen:   xnet.NewIPOrDomain(xnet.LocalHostIP),
					StreamSettings: &internet.StreamConfig{
						SecurityType: serial.GetMessageType(&tls.Config{}),
						SecuritySettings: []*serial.TypedMessage{
							serial.ToTypedMessage(&tls.Config{
								Certificate: []*tls.Certificate{tls.ParseCertificate(srvCert)},
							}),
						},
					},
				}),
				ProxySettings: serial.ToTypedMessage(&trojan.ServerConfig{
					Users: []*protocol.User{
						{
							Account: serial.ToTypedMessage(&trojan.Account{Password: password}),
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

func startTrojanClient(t *testing.T, trojanServerPort int, password string, srvCertHash [32]byte) *core.Instance {
	t.Helper()
	cfg := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&trojan.ClientConfig{
					Server: &protocol.ServerEndpoint{
						Address: xnet.NewIPOrDomain(xnet.LocalHostIP),
						Port:    uint32(trojanServerPort),
						User: &protocol.User{
							Account: serial.ToTypedMessage(&trojan.Account{Password: password}),
						},
					},
				}),
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
					StreamSettings: &internet.StreamConfig{
						SecurityType: serial.GetMessageType(&tls.Config{}),
						SecuritySettings: []*serial.TypedMessage{
							serial.ToTypedMessage(&tls.Config{
								PinnedPeerCertSha256: [][]byte{srvCertHash[:]},
							}),
						},
					},
				}),
			},
		},
	}
	return mustStartInstance(t, cfg)
}

// randomTrojanPassword: 24 random base64-url bytes. Trojan's auth
// token is an arbitrary string; this just needs to be unguessable
// per run.
func randomTrojanPassword(t *testing.T) string {
	t.Helper()
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
