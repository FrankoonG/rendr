package xray

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/FrankoonG/rendr"
	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	xrouter "github.com/xtls/xray-core/app/router"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/freedom"
	"google.golang.org/protobuf/proto"

	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
)

func TestXrayInstanceAsStreamFactoryFreedomOutbound(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		c, err := echo.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()

	inst := startFreedomInstance(t)
	defer inst.Close()
	factory := XrayInstanceAsStreamFactory(inst)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := factory(ctx, echo.Addr().String())
	if err != nil {
		t.Fatalf("factory dial via freedom: %v", err)
	}
	defer conn.Close()

	want := []byte("hello via public rendr/xray glue")
	if _, err := conn.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("payload: got %q want %q", got, want)
	}
}

func TestParseTCPDestination(t *testing.T) {
	dest, err := parseTCPDestination("127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	if dest.Network != xnet.Network_TCP || dest.Port != 443 {
		t.Fatalf("destination=%v", dest)
	}
	if _, err := parseTCPDestination("bad"); err == nil {
		t.Fatal("expected bad addr error")
	}
}

func TestXrayBalancerAsStreamFactories(t *testing.T) {
	ln, err := ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := ln.AcceptContext(ctx)
		if err != nil {
			t.Errorf("AcceptContext: %v", err)
			return
		}
		accepted <- c
	}()

	inst := startTaggedFreedomInstance(t, "path-a", "path-b")
	defer inst.Close()
	factories, err := XrayBalancerAsStreamFactories(inst, &xrouter.BalancingRule{
		Tag:              "rendr-paths",
		OutboundSelector: []string{"path-"},
		Strategy:         "roundrobin",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(factories) != 2 {
		t.Fatalf("factory count=%d want 2", len(factories))
	}
	if factories[0].OutboundTag != "path-a" || factories[1].OutboundTag != "path-b" {
		t.Fatalf("unexpected outbound tags: %+v", factories)
	}

	d := &rendr.Dialer{
		Mode: rendr.ModePrime,
		Paths: []rendr.PathSpec{
			{Transport: factories[0].Name, Address: ln.Addr().String()},
			{Transport: factories[1].Name, Address: ln.Addr().String()},
		},
	}
	for _, f := range factories {
		if err := d.AddStreamPathFactory(f.Name, f.Factory); err != nil {
			t.Fatal(err)
		}
	}

	c, err := d.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	srv := <-accepted
	defer srv.Close()

	want := []byte("xray balancer outbound as rendr path")
	if _, err := c.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(srv, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("payload got %q want %q", got, want)
	}
}

func startFreedomInstance(t *testing.T) *core.Instance {
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
	cfgBytes, err := proto.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	inst, err := core.StartInstance("protobuf", cfgBytes)
	if err != nil {
		t.Fatal(err)
	}
	return inst
}

func startTaggedFreedomInstance(t *testing.T, tags ...string) *core.Instance {
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
	cfgBytes, err := proto.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	inst, err := core.StartInstance("protobuf", cfgBytes)
	if err != nil {
		t.Fatal(err)
	}
	return inst
}
