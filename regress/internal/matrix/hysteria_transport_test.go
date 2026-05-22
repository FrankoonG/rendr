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
	xhy "github.com/xtls/xray-core/transport/internet/hysteria"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

// TestT3VlessTCPxVlessHysteria2Transport is the xray-facing companion
// to the root TCP->UDP-backed stream regression. Path A uses the
// existing VLESS/TCP/TLS profile; path B uses xray's Hysteria2 stream
// transport, which carries VLESS bytes over UDP/QUIC. The driver
// performs explicit mid-file rendr migrations and requires a matching
// SHA-256.
func TestT3VlessTCPxVlessHysteria2Transport(t *testing.T) {
	tcpPort := pickFreePort(t)
	tcpUserID := protocol.NewID(uuid.New()).String()
	tcpCert, tcpCertHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	tcpSrv := startVlessVisionServer(t, tcpPort, tcpUserID, tcpCert)
	defer tcpSrv.Close()
	tcpCli := startVlessVisionClient(t, tcpPort, tcpUserID, tcpCertHash)
	defer tcpCli.Close()

	hyPort := pickFreePort(t)
	hyUserID := protocol.NewID(uuid.New()).String()
	hyAuth := "rendr-hy2-" + protocol.NewID(uuid.New()).String()
	hyCert, hyCertHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	hySrv := startVlessHysteria2TransportServer(t, hyPort, hyUserID, hyAuth, hyCert)
	defer hySrv.Close()
	hyCli := startVlessHysteria2TransportClient(t, hyPort, hyUserID, hyAuth, hyCertHash)
	defer hyCli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	r := driver.RunFileXfer(ctx, driver.FileXferOpts{
		CaseName: "T3.stream.vless+tcp x vless+hysteria2-transport",
		Paths: []rendr.PathSpec{
			{Transport: "xray-vless-tcp"},
			{Transport: "xray-vless-hysteria2"},
		},
		Factories: []driver.NamedFactory{
			{Name: "xray-vless-tcp", Stream: xrayglue.XrayInstanceAsStreamFactory(tcpCli)},
			{Name: "xray-vless-hysteria2", Stream: xrayglue.XrayInstanceAsStreamFactory(hyCli)},
		},
		MigrationFractions: []float64{0.3, 0.6},
	})
	if r.Failure != "" {
		t.Fatalf("case failed: %s", r.Failure)
	}
	if !r.SHA256Match || r.MigrationsDone == 0 {
		t.Fatalf("vless tcp x hysteria2 transport: sha=%v migs=%d", r.SHA256Match, r.MigrationsDone)
	}
	t.Logf("PASS: %s elapsed=%s bytes=%d migrations=%d/%d",
		r.Name, r.Elapsed, r.BytesReceived, r.MigrationsDone, r.MigrationsAsked)
}

func startVlessHysteria2TransportServer(t *testing.T, port int, userID, auth string, srvCert *cert.Certificate) *core.Instance {
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
						ProtocolName: "hysteria",
						TransportSettings: []*internet.TransportConfig{
							{
								ProtocolName: "hysteria",
								Settings: serial.ToTypedMessage(&xhy.Config{
									Version: 2,
									Auth:    auth,
								}),
							},
						},
						SecurityType: serial.GetMessageType(&xtls.Config{}),
						SecuritySettings: []*serial.TypedMessage{
							serial.ToTypedMessage(&xtls.Config{
								Certificate: []*xtls.Certificate{xtls.ParseCertificate(srvCert)},
								NextProtocol: []string{
									"h3",
								},
							}),
						},
					},
				}),
				ProxySettings: serial.ToTypedMessage(&vlessinbound.Config{
					Users: []*protocol.User{
						{
							Account: serial.ToTypedMessage(&vless.Account{Id: userID}),
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

func startVlessHysteria2TransportClient(t *testing.T, port int, userID, auth string, srvCertHash [32]byte) *core.Instance {
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
							Account: serial.ToTypedMessage(&vless.Account{Id: userID}),
						},
					},
				}),
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
					StreamSettings: &internet.StreamConfig{
						ProtocolName: "hysteria",
						TransportSettings: []*internet.TransportConfig{
							{
								ProtocolName: "hysteria",
								Settings: serial.ToTypedMessage(&xhy.Config{
									Version: 2,
									Auth:    auth,
								}),
							},
						},
						SecurityType: serial.GetMessageType(&xtls.Config{}),
						SecuritySettings: []*serial.TypedMessage{
							serial.ToTypedMessage(&xtls.Config{
								PinnedPeerCertSha256: [][]byte{srvCertHash[:]},
								NextProtocol: []string{
									"h3",
								},
							}),
						},
					},
				}),
			},
		},
	}
	return mustStartInstance(t, cfg)
}
