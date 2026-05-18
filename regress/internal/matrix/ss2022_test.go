package matrix

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
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
	"google.golang.org/protobuf/proto"

	_ "github.com/xtls/xray-core/proxy/shadowsocks_2022"
)

// TestT3SS2022xSS2022: stream.D-4 reference per
// docs/regression-suite.md §7.2.1. Both rendr paths use a
// Shadowsocks-2022-blake3-aes-128-gcm outbound; the matching SS
// inbound runs on the same host and forwards (via freedom) to the
// rendr-server addr. Each path is an independent SS session through
// the same SS-server peer, so migration moves an in-flight HTTP file
// transfer across two distinct AEAD sessions.
//
// Topology (single-process; all loopback):
//
//   rendr-client.Dialer
//     paths: 2 × {Transport: "ss-2022", Address: rendrSrvAddr}
//     factory: xrayInstance(ssClient) per path
//   ssClient: SS-2022 outbound -> ssServerPort
//   ssServer: SS-2022 inbound on ssServerPort -> freedom outbound
//   rendrSrv: rendr.ListenTCP serving 30 MiB via HTTP
//
//   factory(rendrSrvAddr) -> core.Dial(ssClient, rendrSrvAddr) ->
//     SS-encrypted dial to ssServerPort ->
//     ssServer decrypts, freedom-dials rendrSrvAddr ->
//     rendr accepts -> path attached.
func TestT3SS2022xSS2022(t *testing.T) {
	// Pick a free port for the SS inbound (loopback only).
	ssServerPort := pickFreePort(t)

	// 16-byte key, base64-encoded, for 2022-blake3-aes-128-gcm.
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	keyB64 := base64.StdEncoding.EncodeToString(key)
	const method = "2022-blake3-aes-128-gcm"

	ssServerInst := startSSServer(t, ssServerPort, method, keyB64)
	defer ssServerInst.Close()

	ssClientInst := startSSClient(t, ssServerPort, method, keyB64)
	defer ssClientInst.Close()

	factory := xrayglue.XrayInstanceAsStreamFactory(ssClientInst)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	r := driver.RunFileXfer(ctx, driver.FileXferOpts{
		CaseName: "T3.stream.ss2022×ss2022",
		Paths: []rendr.PathSpec{
			{Transport: "xray-ss2022"},
			{Transport: "xray-ss2022"},
		},
		Factories: []driver.NamedFactory{
			{Name: "xray-ss2022", Stream: factory},
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

// startSSServer runs an xray Instance with a Shadowsocks-2022
// inbound on ssServerPort + a freedom outbound. Decoded traffic is
// dialed to the inner target embedded in the SS handshake (which is
// the rendr-server addr, supplied by the client factory).
func startSSServer(t *testing.T, ssServerPort int, method, keyB64 string) *core.Instance {
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
					PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(xnet.Port(ssServerPort))}},
					Listen:   xnet.NewIPOrDomain(xnet.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&ss2022.ServerConfig{
					Method:  method,
					Key:     keyB64,
					Network: []xnet.Network{xnet.Network_TCP},
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

// startSSClient runs an xray Instance with a Shadowsocks-2022
// outbound pointing at the SS server. core.Dial on this instance
// will dispatch to that outbound and the SS handshake encodes the
// target the caller passed into core.Dial.
func startSSClient(t *testing.T, ssServerPort int, method, keyB64 string) *core.Instance {
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
					Port:    uint32(ssServerPort),
					Method:  method,
					Key:     keyB64,
				}),
			},
		},
	}
	return mustStartInstance(t, cfg)
}

func mustStartInstance(t *testing.T, cfg *core.Config) *core.Instance {
	t.Helper()
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

// pickFreePort opens an ephemeral listener, captures the assigned
// port, closes the listener, returns the port. The race-window
// before xray reopens that port is loopback-only and tiny; for
// in-process tests it's reliable enough.
func pickFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	if p == 0 {
		t.Fatal("pickFreePort got 0")
	}
	_ = fmt.Sprint // keep fmt import alive in case helpers grow
	return p
}
