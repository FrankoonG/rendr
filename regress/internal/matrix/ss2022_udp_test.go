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
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/freedom"
	ss2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
)

// TestT3PacketSS2022UDPxUDPFlow covers SS-2022 UDP as a low-rate
// packet-mode protocol path. The high-PPS packet contract remains on
// rendr udpflow and QUIC DATAGRAM; this case only proves that xray's
// SS-2022 UDP outbound/inbound chain can serve as a PacketPathFactory
// and migrate against a plain udpflow path without violating packet
// boundaries.
//
// Architecturally this should work the same way the SS-2022 stream
// case does: xray SS-2022 UDP outbound encrypts each datagram and
// forwards to the SS-2022 server, which decrypts and freedom-UDP-
// dials the embedded target (rendr-server addr). Earlier 2k pps
// attempts lost most datagrams in xray's UDP relay path, so this
// stays deliberately small and does not replace the high-rate G3
// gates.
func TestT3PacketSS2022UDPxUDPFlow(t *testing.T) {
	ssPort := pickFreePort(t)
	ssKey := randomSSKey(t)
	const method = "2022-blake3-aes-128-gcm"

	ssServer := startSSUDPServer(t, ssPort, method, ssKey)
	defer ssServer.Close()
	ssClient := startSSUDPClient(t, ssPort, method, ssKey)
	defer ssClient.Close()

	factory := xrayglue.XrayInstanceAsPacketFactory(ssClient)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	r := driver.RunUDPEcho(ctx, driver.UDPEchoOpts{
		CaseName:     "T3.packet.ss2022-udp × udpflow",
		AcceptListen: "udpflow",
		Paths: []rendr.PathSpec{
			{Transport: "xray-ss2022-udp"},
			{Transport: "udpflow"},
		},
		Factories: []driver.NamedFactory{
			{Name: "xray-ss2022-udp", Packet: factory},
		},
		PPS:          100,
		Duration:     3 * time.Second,
		PayloadLen:   512,
		Migrations:   3,
		LossPct:      5.0,
		P95CeilingMs: 100,
	})
	if r.Failure != "" {
		t.Fatalf("case failed: %s", r.Failure)
	}
	t.Logf("PASS: %s sent=%d recv=%d loss=%.2f%% p95=%.1fms migrations=%d",
		r.Name, r.Sent, r.Received, r.LossPct, r.P95ms, r.MigrationsDone)
}

// startSSUDPServer: SS-2022 inbound configured to handle UDP +
// freedom UDP outbound (relays decoded datagrams to whatever target
// the SS protocol header embedded).
func startSSUDPServer(t *testing.T, port int, method, keyB64 string) *core.Instance {
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
				}),
				ProxySettings: serial.ToTypedMessage(&ss2022.ServerConfig{
					Method:  method,
					Key:     keyB64,
					Network: []xnet.Network{xnet.Network_UDP},
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

func startSSUDPClient(t *testing.T, port int, method, keyB64 string) *core.Instance {
	t.Helper()
	cfg := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&ss2022.ClientConfig{
					Address: xnet.NewIPOrDomain(xnet.LocalHostIP),
					Port:    uint32(port),
					Method:  method,
					Key:     keyB64,
				}),
			},
		},
	}
	return mustStartInstance(t, cfg)
}
