package matrix

import (
	"context"
	"net"
	"strconv"
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
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"

	_ "github.com/xtls/xray-core/proxy/dokodemo"
)

// TestT3StreamDirectXRelay — PYS-R-1 reference per
// docs/regression-suite.md §7.2.1. Path A dials the rendr server
// directly through xray's freedom outbound; Path B dials a
// transparent relay (xray dokodemo-door inbound + freedom outbound)
// that re-forwards every TCP byte to the same rendr server. Both
// paths terminate at the same rendr instance (C1 still satisfied
// because the relay is byte-for-byte transparent: the bytes the
// rendr server sees on Path B are identical to those on Path A,
// just one extra TCP hop's worth of latency).
//
// Migration moves the in-flight file transfer between direct and
// relayed paths, validating the engine across heterogeneous-RTT
// path sets.
func TestT3StreamDirectXRelay(t *testing.T) {
	clientInst := startFreedomInstance(t) // reused from matrix_test.go
	defer clientInst.Close()
	factory := xrayglue.XrayInstanceAsStreamFactory(clientInst)

	relayPort := pickFreePort(t)
	// rendr server's listen addr is :0 — we don't know it until
	// driver.RunFileXfer creates the listener. So we use PathSpec
	// with an empty Address (Path A direct, the driver fills it
	// in) and a placeholder Address for Path B that we'll override
	// to the relay addr below.
	//
	// Trick: spin up the relay AFTER the driver picks the rendr
	// server addr. But driver.RunFileXfer encapsulates listener
	// creation. Workaround: pre-allocate the rendr server addr by
	// calling pickFreePort first, then pass it via ListenAddr.
	rendrSrvPort := pickFreePort(t)
	rendrSrvAddr := "127.0.0.1:" + portStr(rendrSrvPort)

	relayInst := startTransparentRelay(t, relayPort, rendrSrvAddr)
	defer relayInst.Close()
	relayAddr := "127.0.0.1:" + portStr(relayPort)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	r := driver.RunFileXfer(ctx, driver.FileXferOpts{
		CaseName:   "T3.stream.direct × relay",
		ListenAddr: rendrSrvAddr,
		Paths: []rendr.PathSpec{
			{Transport: "xray-freedom", Address: rendrSrvAddr},
			{Transport: "xray-freedom", Address: relayAddr},
		},
		Factories: []driver.NamedFactory{
			{Name: "xray-freedom", Stream: factory},
		},
	})
	if r.Failure != "" {
		t.Fatalf("case failed: %s", r.Failure)
	}
	if !r.SHA256Match || r.MigrationsDone == 0 {
		t.Fatalf("relay case: sha=%v migs=%d", r.SHA256Match, r.MigrationsDone)
	}
	t.Logf("PASS: %s elapsed=%s migrations=%d", r.Name, r.Elapsed, r.MigrationsDone)
}

// startTransparentRelay runs an xray Instance with one dokodemo-door
// inbound on relayPort and a freedom outbound. dokodemo rewrites
// every incoming TCP connection's destination to downstreamAddr so
// the relay is byte-for-byte transparent — clients see a normal
// TCP socket to relayPort; the bytes arrive at downstreamAddr.
func startTransparentRelay(t *testing.T, relayPort int, downstreamAddr string) *core.Instance {
	t.Helper()
	host, portInt := mustSplitHostPort(t, downstreamAddr)
	cfg := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(xnet.Port(relayPort))}},
					Listen:   xnet.NewIPOrDomain(xnet.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					RewriteAddress:  xnet.NewIPOrDomain(xnet.ParseAddress(host)),
					RewritePort:     uint32(portInt),
					AllowedNetworks: []xnet.Network{xnet.Network_TCP},
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

// mustSplitHostPort splits "host:port" and parses the port. Used
// by startTransparentRelay to wire dokodemo's RewriteAddress.
func mustSplitHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("atoi %q: %v", portStr, err)
	}
	return host, p
}

// portStr renders an int port for the "host:port" string form.
func portStr(p int) string { return strconv.Itoa(p) }
