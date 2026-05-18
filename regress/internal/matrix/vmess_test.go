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
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/vmess"
	vmessinbound "github.com/xtls/xray-core/proxy/vmess/inbound"
	vmessoutbound "github.com/xtls/xray-core/proxy/vmess/outbound"

	_ "github.com/xtls/xray-core/proxy/vmess/inbound"
	_ "github.com/xtls/xray-core/proxy/vmess/outbound"
)

// TestT3VMessxVMess — VMess (no TLS, AES-128-GCM AEAD) both paths.
// Mirrors TestT3SS2022xSS2022 but with VMess as the application
// protocol. Each rendr path is a distinct VMess session sharing the
// same UUID, terminated at the same vmess-server which freedom-dials
// the rendr-server addr.
func TestT3VMessxVMess(t *testing.T) {
	vmessServerPort := pickFreePort(t)
	userID := protocol.NewID(uuid.New()).String()

	vmessServerInst := startVMessServer(t, vmessServerPort, userID)
	defer vmessServerInst.Close()
	vmessClientInst := startVMessClient(t, vmessServerPort, userID)
	defer vmessClientInst.Close()

	factory := xrayglue.XrayInstanceAsStreamFactory(vmessClientInst)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	r := driver.RunFileXfer(ctx, driver.FileXferOpts{
		CaseName: "T3.stream.vmess×vmess",
		Paths: []rendr.PathSpec{
			{Transport: "xray-vmess"},
			{Transport: "xray-vmess"},
		},
		Factories: []driver.NamedFactory{
			{Name: "xray-vmess", Stream: factory},
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

// TestT3SS2022xVMess — cross-protocol case: path A uses
// Shadowsocks-2022 (one factory), path B uses VMess (another
// factory). Same rendr-server target, two distinct xray-server
// peers (one SS inbound, one VMess inbound). Proves rendr migrates
// across paths of heterogeneous xray-protocol stacks.
//
// This is the architecturally distinctive shape — the most natural
// fit for the user's mental model of "rendr.Dialer holds multiple
// xray outbounds, each potentially a different protocol, all
// terminating at the same rendr server".
func TestT3SS2022xVMess(t *testing.T) {
	rendrUnusedHack := pickFreePort(t)
	_ = rendrUnusedHack

	// SS-2022 server + client.
	ssPort := pickFreePort(t)
	ssKey := randomSSKey(t)
	const ssMethod = "2022-blake3-aes-128-gcm"
	ssServerInst := startSSServer(t, ssPort, ssMethod, ssKey)
	defer ssServerInst.Close()
	ssClientInst := startSSClient(t, ssPort, ssMethod, ssKey)
	defer ssClientInst.Close()

	// VMess server + client.
	vmessPort := pickFreePort(t)
	userID := protocol.NewID(uuid.New()).String()
	vmessServerInst := startVMessServer(t, vmessPort, userID)
	defer vmessServerInst.Close()
	vmessClientInst := startVMessClient(t, vmessPort, userID)
	defer vmessClientInst.Close()

	ssFactory := xrayglue.XrayInstanceAsStreamFactory(ssClientInst)
	vmessFactory := xrayglue.XrayInstanceAsStreamFactory(vmessClientInst)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	r := driver.RunFileXfer(ctx, driver.FileXferOpts{
		CaseName: "T3.stream.ss2022×vmess",
		Paths: []rendr.PathSpec{
			{Transport: "xray-ss2022"},
			{Transport: "xray-vmess"},
		},
		Factories: []driver.NamedFactory{
			{Name: "xray-ss2022", Stream: ssFactory},
			{Name: "xray-vmess", Stream: vmessFactory},
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

func startVMessServer(t *testing.T, vmessServerPort int, userID string) *core.Instance {
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
					PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(xnet.Port(vmessServerPort))}},
					Listen:   xnet.NewIPOrDomain(xnet.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&vmessinbound.Config{
					User: []*protocol.User{
						{
							Account: serial.ToTypedMessage(&vmess.Account{Id: userID}),
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

func startVMessClient(t *testing.T, vmessServerPort int, userID string) *core.Instance {
	t.Helper()
	cfg := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&vmessoutbound.Config{
					Receiver: &protocol.ServerEndpoint{
						Address: xnet.NewIPOrDomain(xnet.LocalHostIP),
						Port:    uint32(vmessServerPort),
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

