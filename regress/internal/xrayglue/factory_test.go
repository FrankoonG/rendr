package xrayglue

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/freedom"
	"google.golang.org/protobuf/proto"

	// Side-effect: register the inbound / outbound manager
	// implementations + dispatcher + freedom outbound with xray's
	// protobuf-driven registry. Without these the Config above
	// builds but core.StartInstance fails with "X is not registered".
	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/proxy/freedom"
)

// TestFactoryThroughFreedomOutbound is the minimal proof-of-life
// for the glue B helper. Builds an xray Config with a single freedom
// outbound (direct dial, no proxy hop), starts the Instance,
// constructs a StreamPathFactory atop it, then dials a local TCP
// echo server and round-trips a small payload.
//
// This validates the dispatch path:
//
//	rendr.StreamPathFactory(addr) -> core.Dial -> freedom outbound
//	-> bare TCP -> echo server -> bytes flow back through
//	the dispatcher-allocated net.Conn.
//
// Real VLESS/Trojan/etc tests need full xray-server peers in addition
// to the client-side outbound; this freedom case is the smoke that
// proves the helper plumbing itself is correct.
func TestFactoryThroughFreedomOutbound(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		c, err := echo.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()

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
	defer inst.Close()

	factory := XrayInstanceAsStreamFactory(inst)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := factory(ctx, echo.Addr().String())
	if err != nil {
		t.Fatalf("factory dial via freedom: %v", err)
	}
	defer conn.Close()

	want := []byte("hello via xray freedom outbound")
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
