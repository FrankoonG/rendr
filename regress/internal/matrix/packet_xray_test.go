package matrix

import (
	"context"
	"testing"
	"time"

	"github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/regress/internal/matrix/driver"
	rendrxray "github.com/FrankoonG/rendr/xray"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	xrouter "github.com/xtls/xray-core/app/router"
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
	xrayPacketFactory := rendrxray.XrayInstanceAsPacketFactory(xrayInst)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	r := driver.RunUDPEcho(ctx, driver.UDPEchoOpts{
		CaseName:     "T3.packet.xray-freedom-udp × udpflow",
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

// TestT3PacketXrayBalancerUDPxUDPFlow covers M9 X6's packet side:
// an xray BalancingRule selects multiple UDP-capable outbounds, and
// rendr treats each selected outbound as one packet path. The outbounds
// are freedom here so the assertion focuses on BalancerObject adapter
// plumbing rather than protocol encryption.
func TestT3PacketXrayBalancerUDPxUDPFlow(t *testing.T) {
	xrayInst := startTaggedFreedomInstanceForUDP(t, "udp-path-a", "udp-path-b")
	defer xrayInst.Close()

	factories, err := rendrxray.XrayBalancerAsPacketFactories(xrayInst, &xrouter.BalancingRule{
		Tag:              "rendr-udp-paths",
		OutboundSelector: []string{"udp-path-"},
		Strategy:         "roundrobin",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(factories) != 2 {
		t.Fatalf("factory count=%d want 2", len(factories))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	paths := make([]rendr.PathSpec, len(factories))
	named := make([]driver.NamedFactory, len(factories))
	for i, f := range factories {
		paths[i] = rendr.PathSpec{Transport: f.Name}
		named[i] = driver.NamedFactory{Name: f.Name, Packet: f.Factory}
	}

	r := driver.RunUDPEcho(ctx, driver.UDPEchoOpts{
		CaseName:     "T3.packet.xray-balancer-udp x udpflow",
		AcceptListen: "udpflow",
		Paths:        paths,
		Factories:    named,
		PPS:          2000,
		Duration:     3 * time.Second,
		PayloadLen:   1024,
		Migrations:   3,
		LossPct:      1.0,
	})
	if r.Failure != "" {
		t.Fatalf("case failed: %s", r.Failure)
	}
	if r.MigrationsDone == 0 {
		t.Fatal("zero migrations fired")
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

func startTaggedFreedomInstanceForUDP(t *testing.T, tags ...string) *core.Instance {
	t.Helper()
	cfg := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
	}
	for _, tag := range tags {
		cfg.Outbound = append(cfg.Outbound, &core.OutboundHandlerConfig{
			Tag: tag,
			ProxySettings: serial.ToTypedMessage(&freedom.Config{
				FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
			}),
		})
	}
	return mustStartInstance(t, cfg)
}
