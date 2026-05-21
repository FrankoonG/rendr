package matrix

import (
	"context"
	stdnet "net"
	"testing"
	"time"

	"github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/regress/internal/matrix/driver"
	"github.com/FrankoonG/rendr/regress/internal/xrayglue"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	xreverse "github.com/xtls/xray-core/app/reverse"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/geodata"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/blackhole"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	ss2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/vless"
	vlessoutbound "github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/proxy/vmess"
	vmessinbound "github.com/xtls/xray-core/proxy/vmess/inbound"
	vmessoutbound "github.com/xtls/xray-core/proxy/vmess/outbound"
	"github.com/xtls/xray-core/transport/internet"
	transtcp "github.com/xtls/xray-core/transport/internet/tcp"
	"github.com/xtls/xray-core/transport/internet/tls"
)

// TestT3StreamNestedTwoLayer — PYS-N-1 (nested 2-layer chain).
//
// rendr-side note: rendr's PathFactory wraps the final net.Conn
// from xray, so nesting depth is transparent to rendr's migration
// engine. This case uses two real xray protocol layers:
//
//	rendr path factory
//	  -> SS-2022 client outbound
//	  -> SS-2022 middle inbound
//	  -> VLESS+Vision+TLS middle outbound
//	  -> VLESS+Vision+TLS server inbound
//	  -> freedom
//	  -> rendr server
//
// The target rendr-server address is carried through both protocol
// handshakes. Migration then moves the in-flight file transfer across
// two independent nested sessions.
func TestT3StreamNestedTwoLayer(t *testing.T) {
	vlessPort := pickFreePort(t)
	ssMiddlePort := pickFreePort(t)

	userID := protocol.NewID(uuid.New()).String()
	ct, ctHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	vlessServer := startVlessVisionServer(t, vlessPort, userID, ct)
	defer vlessServer.Close()

	const ssMethod = "2022-blake3-aes-128-gcm"
	ssKey := randomSSKey(t)
	middle := startSSInboundToVLESSOutbound(t, ssMiddlePort, ssMethod, ssKey, vlessPort, userID, ctHash)
	defer middle.Close()

	ssClient := startSSClient(t, ssMiddlePort, ssMethod, ssKey)
	defer ssClient.Close()

	factory := xrayglue.XrayInstanceAsStreamFactory(ssClient)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	r := driver.RunFileXfer(ctx, driver.FileXferOpts{
		CaseName: "T3.stream.nested.ss2022-to-vless+vision+tls × itself",
		Paths: []rendr.PathSpec{
			{Transport: "xray-nested-ss-vless"},
			{Transport: "xray-nested-ss-vless"},
		},
		Factories: []driver.NamedFactory{
			{Name: "xray-nested-ss-vless", Stream: factory},
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

// TestT3StreamReverseOutbound — PYS-V-1 (reverse). A portal xray
// instance exposes an external TCP entrypoint and a VMess reverse
// inbound. A bridge instance actively connects to that reverse
// inbound; portal-side traffic entering the external entrypoint is
// then carried back over the reverse tunnel and finally freedom-dials
// the rendr server. The rendr path factory sees only a net.Conn to
// the portal entrypoint, so the reverse direction is transparent to
// the engine.
func TestT3StreamReverseOutbound(t *testing.T) {
	rendrSrvPort := pickFreePort(t)
	rendrSrvAddr := "127.0.0.1:" + portStr(rendrSrvPort)

	externalPort := pickFreePort(t)
	reversePort := pickFreePort(t)
	userID := protocol.NewID(uuid.New()).String()

	portal := startReversePortal(t, externalPort, reversePort, rendrSrvAddr, userID)
	defer portal.Close()
	bridge := startReverseBridge(t, reversePort, userID)
	defer bridge.Close()
	time.Sleep(500 * time.Millisecond)

	externalAddr := "127.0.0.1:" + portStr(externalPort)
	factory := func(ctx context.Context, _ string) (stdnet.Conn, error) {
		var d stdnet.Dialer
		return d.DialContext(ctx, "tcp", externalAddr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	r := driver.RunFileXfer(ctx, driver.FileXferOpts{
		CaseName:   "T3.stream.reverse-vmess × itself",
		ListenAddr: rendrSrvAddr,
		Paths: []rendr.PathSpec{
			{Transport: "xray-reverse-vmess", Address: externalAddr},
			{Transport: "xray-reverse-vmess", Address: externalAddr},
		},
		Factories: []driver.NamedFactory{
			{Name: "xray-reverse-vmess", Stream: factory},
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

func startSSInboundToVLESSOutbound(t *testing.T, ssPort int, ssMethod, ssKey string, vlessPort int, userID string, srvCertHash [32]byte) *core.Instance {
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
					PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(xnet.Port(ssPort))}},
					Listen:   xnet.NewIPOrDomain(xnet.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&ss2022.ServerConfig{
					Method:  ssMethod,
					Key:     ssKey,
					Network: []xnet.Network{xnet.Network_TCP},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&vlessoutbound.Config{
					Vnext: &protocol.ServerEndpoint{
						Address: xnet.NewIPOrDomain(xnet.LocalHostIP),
						Port:    uint32(vlessPort),
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
							}),
						},
					},
				}),
			},
		},
	}
	return mustStartInstance(t, cfg)
}

func startReversePortal(t *testing.T, externalPort, reversePort int, rendrSrvAddr, userID string) *core.Instance {
	t.Helper()
	host, portInt := mustSplitHostPort(t, rendrSrvAddr)
	cfg := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&xreverse.Config{
				PortalConfig: []*xreverse.PortalConfig{
					{
						Tag:    "portal",
						Domain: "rendr-reverse.example",
					},
				},
			}),
			serial.ToTypedMessage(&router.Config{
				Rule: []*router.RoutingRule{
					{
						Domain: []*geodata.DomainRule{
							{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Full, Value: "rendr-reverse.example"}}},
						},
						TargetTag: &router.RoutingRule_Tag{Tag: "portal"},
					},
					{
						InboundTag: []string{"external"},
						TargetTag:  &router.RoutingRule_Tag{Tag: "portal"},
					},
				},
			}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				Tag: "external",
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(xnet.Port(externalPort))}},
					Listen:   xnet.NewIPOrDomain(xnet.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					RewriteAddress:  xnet.NewIPOrDomain(xnet.ParseAddress(host)),
					RewritePort:     uint32(portInt),
					AllowedNetworks: []xnet.Network{xnet.Network_TCP},
				}),
			},
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(xnet.Port(reversePort))}},
					Listen:   xnet.NewIPOrDomain(xnet.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&vmessinbound.Config{
					User: []*protocol.User{
						{
							Account: serial.ToTypedMessage(&vmess.Account{
								Id: userID,
							}),
						},
					},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&blackhole.Config{}),
			},
		},
	}
	return mustStartInstance(t, cfg)
}

func startReverseBridge(t *testing.T, reversePort int, userID string) *core.Instance {
	t.Helper()
	cfg := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&xreverse.Config{
				BridgeConfig: []*xreverse.BridgeConfig{
					{
						Tag:    "bridge",
						Domain: "rendr-reverse.example",
					},
				},
			}),
			serial.ToTypedMessage(&router.Config{
				Rule: []*router.RoutingRule{
					{
						Domain: []*geodata.DomainRule{
							{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Full, Value: "rendr-reverse.example"}}},
						},
						TargetTag: &router.RoutingRule_Tag{Tag: "reverse"},
					},
					{
						InboundTag: []string{"bridge"},
						TargetTag:  &router.RoutingRule_Tag{Tag: "freedom"},
					},
				},
			}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				Tag: "freedom",
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
				}),
			},
			{
				Tag: "reverse",
				ProxySettings: serial.ToTypedMessage(&vmessoutbound.Config{
					Receiver: &protocol.ServerEndpoint{
						Address: xnet.NewIPOrDomain(xnet.LocalHostIP),
						Port:    uint32(reversePort),
						User: &protocol.User{
							Account: serial.ToTypedMessage(&vmess.Account{
								Id: userID,
								SecuritySettings: &protocol.SecurityConfig{
									Type: protocol.SecurityType_AES128_GCM,
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
