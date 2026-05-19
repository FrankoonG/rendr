package matrix

import (
	"context"
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
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/vless"
	vlessinbound "github.com/xtls/xray-core/proxy/vless/inbound"
	vlessoutbound "github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/transport/internet"
	transtcp "github.com/xtls/xray-core/transport/internet/tcp"
	"github.com/xtls/xray-core/transport/internet/tls"
)

// TestT3VlessVisionTLSMLKEM_xItself — PYS-D-6: VLESS+Vision+TLS+
// MLKEM-768+X25519 hybrid key exchange. The TLS config's
// CurvePreferences elevates "x25519mlkem768" so the TLS handshake
// performs post-quantum key agreement in addition to the classical
// X25519. Both sides must offer the same curve.
//
// xray-core's tls/config.ParseCurveName maps "x25519mlkem768" to
// crypto/tls.X25519MLKEM768; Go's standard library 1.23+ ships
// MLKEM support. Per docs/regression-suite.md §7.7 S5.
func TestT3VlessVisionTLSMLKEM_xItself(t *testing.T) {
	port := pickFreePort(t)
	userID := protocol.NewID(uuid.New()).String()
	ct, ctHash := cert.MustGenerate(nil, cert.CommonName("localhost"))

	curves := []string{"x25519mlkem768", "x25519"}
	srv := startVlessVisionMLKEMServer(t, port, userID, ct, curves)
	defer srv.Close()
	cli := startVlessVisionMLKEMClient(t, port, userID, ctHash, curves)
	defer cli.Close()

	factory := xrayglue.XrayInstanceAsStreamFactory(cli)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	r := driver.RunFileXfer(ctx, driver.FileXferOpts{
		CaseName: "T3.stream.vless+vision+tls+mlkem × itself",
		Paths: []rendr.PathSpec{
			{Transport: "xray-vless-vision-tls-mlkem"},
			{Transport: "xray-vless-vision-tls-mlkem"},
		},
		Factories: []driver.NamedFactory{
			{Name: "xray-vless-vision-tls-mlkem", Stream: factory},
		},
	})
	if r.Failure != "" {
		t.Fatalf("case failed: %s", r.Failure)
	}
	if !r.SHA256Match || r.MigrationsDone == 0 {
		t.Fatalf("mlkem case: sha=%v migs=%d", r.SHA256Match, r.MigrationsDone)
	}
	t.Logf("PASS: %s elapsed=%s migrations=%d", r.Name, r.Elapsed, r.MigrationsDone)
}

func startVlessVisionMLKEMServer(t *testing.T, port int, userID string, srvCert *cert.Certificate, curves []string) *core.Instance {
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
						SecurityType: serial.GetMessageType(&tls.Config{}),
						SecuritySettings: []*serial.TypedMessage{
							serial.ToTypedMessage(&tls.Config{
								Certificate:      []*tls.Certificate{tls.ParseCertificate(srvCert)},
								CurvePreferences: curves,
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

func startVlessVisionMLKEMClient(t *testing.T, port int, userID string, srvCertHash [32]byte, curves []string) *core.Instance {
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
						SecurityType: serial.GetMessageType(&tls.Config{}),
						SecuritySettings: []*serial.TypedMessage{
							serial.ToTypedMessage(&tls.Config{
								PinnedPeerCertSha256: [][]byte{srvCertHash[:]},
								CurvePreferences:     curves,
							}),
						},
					},
				}),
			},
		},
	}
	return mustStartInstance(t, cfg)
}
