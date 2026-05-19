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
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/freedom"
)

// TestT3PacketXrayFreedomUDPxUDPFlow — PYP-xray-direct half of the
// stream/D-7 split: one path uses rendr's built-in udpflow, the
// other routes datagrams through an xray freedom UDP outbound.
// xray's freedom outbound is a no-op proxy for the dispatch path
// (no encryption, just opaque UDP forwarding), so this case
// validates the PacketPathFactory plumbing (core.DialUDP +
// udpflow.WrapFromSpec wrap) without a protocol layer in the way.
//
// Once this proves the wiring is clean, SS-2022-UDP / VLESS-UDP
// follow with the same structure but a non-freedom outbound.
func TestT3PacketXrayFreedomUDPxUDPFlow(t *testing.T) {
	xrayInst := startFreedomInstanceForUDP(t)
	defer xrayInst.Close()
	xrayPacketFactory := xrayglue.XrayInstanceAsPacketFactory(xrayInst)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	r := driver.RunUDPEcho(ctx, driver.UDPEchoOpts{
		CaseName: "T3.packet.xray-freedom-udp × udpflow",
		AcceptListen: "udpflow",
		Paths: []rendr.PathSpec{
			{Transport: "xray-freedom-udp"},
			{Transport: "udpflow"},
		},
		Factories: []driver.NamedFactory{
			{Name: "xray-freedom-udp", Packet: xrayPacketFactory},
		},
		PPS:        2000,
		Duration:   3 * time.Second,
		PayloadLen: 1024,
		Migrations: 3,
		LossPct:    1.0,
	})
	if r.Failure != "" {
		t.Fatalf("case failed: %s", r.Failure)
	}
	t.Logf("PASS: %s sent=%d recv=%d loss=%.2f%% p95=%.1fms migrations=%d",
		r.Name, r.Sent, r.Received, r.LossPct, r.P95ms, r.MigrationsDone)
}

// startFreedomInstanceForUDP runs an xray Instance with a single
// freedom outbound suitable for UDP dispatch via core.DialUDP. The
// same shape as the TCP freedom instance from matrix_test.go but
// kept distinct so dispatcher routing for UDP traffic is explicit.
func startFreedomInstanceForUDP(t *testing.T) *core.Instance {
	t.Helper()
	cfg := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
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
