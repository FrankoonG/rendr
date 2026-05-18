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
	"google.golang.org/protobuf/proto"

	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/proxy/freedom"
)

// TestT3FreedomXFreedom: zeroth T3 case. Both rendr paths back onto
// the same xray Instance with a single freedom outbound. No protocol
// hop is exercised — freedom dials directly — but the case proves
// the full plumbing end-to-end:
//
//   rendr.Dialer with two StreamPathFactory-backed paths ->
//     factory(addr) -> core.Dial -> freedom outbound -> bare TCP ->
//       rendr.ListenTCP accept -> rendr server-side conn -> http.Serve
//   rendr.Dial client side -> http.Client over rendr.Conn ->
//     GET 30 MiB; mid-stream Migrate at 30%/50%/70%; SHA-256 check.
//
// Once this passes, layering a real protocol (vless / trojan / ss)
// on top is purely a matter of swapping the xray Config.
func TestT3FreedomXFreedom(t *testing.T) {
	inst := startFreedomInstance(t)
	defer inst.Close()

	factory := xrayglue.XrayInstanceAsStreamFactory(inst)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	r := driver.RunFileXfer(ctx, driver.FileXferOpts{
		CaseName: "T3.stream.freedom×freedom",
		Paths: []rendr.PathSpec{
			{Transport: "xray-freedom"},
			{Transport: "xray-freedom"},
		},
		Factories: []driver.NamedFactory{
			{Name: "xray-freedom", Stream: factory},
		},
	})
	if r.Failure != "" {
		t.Fatalf("case failed: %s", r.Failure)
	}
	if !r.SHA256Match {
		t.Fatal("sha256 mismatch (impossible to reach here)")
	}
	if r.MigrationsDone == 0 {
		t.Fatal("zero migrations fired")
	}
	t.Logf("PASS: %s elapsed=%s bytes=%d migrations=%d/%d",
		r.Name, r.Elapsed, r.BytesReceived, r.MigrationsDone, r.MigrationsAsked)
}

// startFreedomInstance builds the minimal xray Config (one freedom
// outbound, default dispatcher/proxyman) and returns a running
// *core.Instance. Test ownership: caller defers Close.
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
