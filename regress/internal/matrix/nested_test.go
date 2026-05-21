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
	ss2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/vless"
	vlessoutbound "github.com/xtls/xray-core/proxy/vless/outbound"
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

// TestT3StreamReverseOutbound — PYS-V-1 (reverse).
//
// DEFERRED.
//
// xray reverse proxy lets a server behind NAT initiate the
// connection to a "portal" running on the public network; clients
// reach the server via the portal's reverse-bridge inbound.
// Configuring this in-process needs both the bridge inbound + the
// portal outbound + matching reverse.Config on both sides. The
// session bridging logic is also stateful — datagrams need to flow
// in a specific direction for the tunnel to come up.
//
// Same disposition as nested: shape is achievable, no upstream
// programmatic scenario test to crib from. rendr's path migration
// is transparent to which direction the underlying conn was
// initiated — the relay topology case already proves migration
// works through a multi-hop path. Defer reverse until needed.
func TestT3StreamReverseOutbound(t *testing.T) {
	t.Skip("xray reverse outbound is configurable but needs reference encoding; tracked, not gating")
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
