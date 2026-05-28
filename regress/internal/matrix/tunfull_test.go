package matrix

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/l3ingress"
	"github.com/FrankoonG/rendr/l3session"
	"github.com/FrankoonG/rendr/regress/internal/matrix/driver"
	"github.com/FrankoonG/rendr/regress/internal/xrayglue"
	rendrxray "github.com/FrankoonG/rendr/xray"

	xrouter "github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/uuid"
)

const tunT3FixtureSize = 8 << 20

func TestTUNT3FreedomStreamOverTUN(t *testing.T) {
	inst := startFreedomInstance(t)
	defer inst.Close()

	runTUNXrayStreamTransfer(t, "freedom", []rendr.PathSpec{
		{Transport: "xray-freedom"},
		{Transport: "xray-freedom"},
	}, []driver.NamedFactory{
		{Name: "xray-freedom", Stream: xrayglue.XrayInstanceAsStreamFactory(inst)},
	})
}

func TestTUNT3SS2022StreamOverTUN(t *testing.T) {
	ssPort := pickFreePort(t)
	ssKey := randomSSKey(t)
	const method = "2022-blake3-aes-128-gcm"

	ssServer := startSSServer(t, ssPort, method, ssKey)
	defer ssServer.Close()
	ssClient := startSSClient(t, ssPort, method, ssKey)
	defer ssClient.Close()

	runTUNXrayStreamTransfer(t, "ss2022", []rendr.PathSpec{
		{Transport: "xray-ss2022"},
		{Transport: "xray-ss2022"},
	}, []driver.NamedFactory{
		{Name: "xray-ss2022", Stream: xrayglue.XrayInstanceAsStreamFactory(ssClient)},
	})
}

func TestTUNT3VMessStreamOverTUN(t *testing.T) {
	vmessPort := pickFreePort(t)
	userID := protocol.NewID(uuid.New()).String()

	vmessServer := startVMessServer(t, vmessPort, userID)
	defer vmessServer.Close()
	vmessClient := startVMessClient(t, vmessPort, userID)
	defer vmessClient.Close()

	runTUNXrayStreamTransfer(t, "vmess", []rendr.PathSpec{
		{Transport: "xray-vmess"},
		{Transport: "xray-vmess"},
	}, []driver.NamedFactory{
		{Name: "xray-vmess", Stream: xrayglue.XrayInstanceAsStreamFactory(vmessClient)},
	})
}

func TestTUNT3TrojanTLSStreamOverTUN(t *testing.T) {
	trojanPort := pickFreePort(t)
	password := "tun-t3-trojan-pass"
	ct, ctHash := cert.MustGenerate(nil, cert.CommonName("localhost"))

	trojanServer := startTrojanServer(t, trojanPort, password, ct)
	defer trojanServer.Close()
	trojanClient := startTrojanClient(t, trojanPort, password, ctHash)
	defer trojanClient.Close()

	runTUNXrayStreamTransfer(t, "trojan-tls", []rendr.PathSpec{
		{Transport: "xray-trojan"},
		{Transport: "xray-trojan"},
	}, []driver.NamedFactory{
		{Name: "xray-trojan", Stream: xrayglue.XrayInstanceAsStreamFactory(trojanClient)},
	})
}

func TestTUNT3VLESSVisionTLSStreamOverTUN(t *testing.T) {
	vlessPort := pickFreePort(t)
	userID := protocol.NewID(uuid.New()).String()
	ct, ctHash := cert.MustGenerate(nil, cert.CommonName("localhost"))

	vlessServer := startVlessVisionServer(t, vlessPort, userID, ct)
	defer vlessServer.Close()
	vlessClient := startVlessVisionClient(t, vlessPort, userID, ctHash)
	defer vlessClient.Close()

	runTUNXrayStreamTransfer(t, "vless-vision-tls", []rendr.PathSpec{
		{Transport: "xray-vless-vision-tls"},
		{Transport: "xray-vless-vision-tls"},
	}, []driver.NamedFactory{
		{Name: "xray-vless-vision-tls", Stream: xrayglue.XrayInstanceAsStreamFactory(vlessClient)},
	})
}

func TestTUNT3VLESSVisionTLSMLKEMStreamOverTUN(t *testing.T) {
	vlessPort := pickFreePort(t)
	userID := protocol.NewID(uuid.New()).String()
	ct, ctHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	curves := []string{"X25519MLKEM768"}

	vlessServer := startVlessVisionMLKEMServer(t, vlessPort, userID, ct, curves)
	defer vlessServer.Close()
	vlessClient := startVlessVisionMLKEMClient(t, vlessPort, userID, ctHash, curves)
	defer vlessClient.Close()

	runTUNXrayStreamTransfer(t, "vless-vision-tls-mlkem", []rendr.PathSpec{
		{Transport: "xray-vless-vision-tls-mlkem"},
		{Transport: "xray-vless-vision-tls-mlkem"},
	}, []driver.NamedFactory{
		{Name: "xray-vless-vision-tls-mlkem", Stream: xrayglue.XrayInstanceAsStreamFactory(vlessClient)},
	})
}

func TestTUNT3VLESSVisionRealityStreamOverTUN(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("REALITY TUN matrix is validated on Linux VM; Windows loopback closes the local REALITY probe path")
	}
	realityPort := pickFreePort(t)
	userID := protocol.NewID(uuid.New()).String()
	priv, pub := mustGenerateX25519(t)
	shortID := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	destAddr := startTLSFallback(t)

	realityServer := startVlessRealityServer(t, realityPort, userID, destAddr, priv, [][]byte{shortID})
	defer realityServer.Close()
	realityClient := startVlessRealityClient(t, realityPort, userID, pub, shortID)
	defer realityClient.Close()

	runTUNXrayStreamTransfer(t, "vless-reality", []rendr.PathSpec{
		{Transport: "xray-vless-reality"},
		{Transport: "xray-vless-reality"},
	}, []driver.NamedFactory{
		{Name: "xray-vless-reality", Stream: xrayglue.XrayInstanceAsStreamFactory(realityClient)},
	})
}

func TestTUNT3VLESSHysteria2TransportStreamOverTUN(t *testing.T) {
	port := pickFreePort(t)
	userID := protocol.NewID(uuid.New()).String()
	auth := "tun-t3-hysteria-auth"
	ct, ctHash := cert.MustGenerate(nil, cert.CommonName("localhost"))

	hyServer := startVlessHysteria2TransportServer(t, port, userID, auth, ct)
	defer hyServer.Close()
	hyClient := startVlessHysteria2TransportClient(t, port, userID, auth, ctHash)
	defer hyClient.Close()

	runTUNXrayStreamTransfer(t, "vless-hysteria2", []rendr.PathSpec{
		{Transport: "xray-vless-hysteria2"},
		{Transport: "xray-vless-hysteria2"},
	}, []driver.NamedFactory{
		{Name: "xray-vless-hysteria2", Stream: xrayglue.XrayInstanceAsStreamFactory(hyClient)},
	})
}

func TestTUNT3MixedSS2022VMessStreamOverTUN(t *testing.T) {
	ssPort := pickFreePort(t)
	ssKey := randomSSKey(t)
	const ssMethod = "2022-blake3-aes-128-gcm"
	ssServer := startSSServer(t, ssPort, ssMethod, ssKey)
	defer ssServer.Close()
	ssClient := startSSClient(t, ssPort, ssMethod, ssKey)
	defer ssClient.Close()

	vmessPort := pickFreePort(t)
	userID := protocol.NewID(uuid.New()).String()
	vmessServer := startVMessServer(t, vmessPort, userID)
	defer vmessServer.Close()
	vmessClient := startVMessClient(t, vmessPort, userID)
	defer vmessClient.Close()

	runTUNXrayStreamTransfer(t, "mixed-ss2022-vmess", []rendr.PathSpec{
		{Transport: "xray-ss2022"},
		{Transport: "xray-vmess"},
	}, []driver.NamedFactory{
		{Name: "xray-ss2022", Stream: xrayglue.XrayInstanceAsStreamFactory(ssClient)},
		{Name: "xray-vmess", Stream: xrayglue.XrayInstanceAsStreamFactory(vmessClient)},
	})
}

func TestTUNT3ThreePathSSVMessVLESSStreamOverTUN(t *testing.T) {
	ssPort := pickFreePort(t)
	ssKey := randomSSKey(t)
	const ssMethod = "2022-blake3-aes-128-gcm"
	ssServer := startSSServer(t, ssPort, ssMethod, ssKey)
	defer ssServer.Close()
	ssClient := startSSClient(t, ssPort, ssMethod, ssKey)
	defer ssClient.Close()

	vmessPort := pickFreePort(t)
	vmessUID := protocol.NewID(uuid.New()).String()
	vmessServer := startVMessServer(t, vmessPort, vmessUID)
	defer vmessServer.Close()
	vmessClient := startVMessClient(t, vmessPort, vmessUID)
	defer vmessClient.Close()

	vlessPort := pickFreePort(t)
	vlessUID := protocol.NewID(uuid.New()).String()
	ct, ctHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
	vlessServer := startVlessVisionServer(t, vlessPort, vlessUID, ct)
	defer vlessServer.Close()
	vlessClient := startVlessVisionClient(t, vlessPort, vlessUID, ctHash)
	defer vlessClient.Close()

	runTUNXrayStreamTransfer(t, "three-path-ss-vmess-vless", []rendr.PathSpec{
		{Transport: "xray-ss2022"},
		{Transport: "xray-vmess"},
		{Transport: "xray-vless-vision-tls"},
	}, []driver.NamedFactory{
		{Name: "xray-ss2022", Stream: xrayglue.XrayInstanceAsStreamFactory(ssClient)},
		{Name: "xray-vmess", Stream: xrayglue.XrayInstanceAsStreamFactory(vmessClient)},
		{Name: "xray-vless-vision-tls", Stream: xrayglue.XrayInstanceAsStreamFactory(vlessClient)},
	})
}

func TestTUNT3DirectRelayStreamOverTUN(t *testing.T) {
	ln, err := rendr.ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	listenAddr := ln.Addr().String()
	clientInst := startFreedomInstance(t)
	defer clientInst.Close()
	relayPort := pickFreePort(t)
	relayAddr := "127.0.0.1:" + portStr(relayPort)
	relay := startTransparentRelay(t, relayPort, listenAddr)
	defer relay.Close()

	runTUNXrayStreamTransferOnListener(t, "direct-relay", ln, []rendr.PathSpec{
		{Transport: "xray-freedom", Address: listenAddr},
		{Transport: "xray-freedom", Address: relayAddr},
	}, []driver.NamedFactory{
		{Name: "xray-freedom", Stream: xrayglue.XrayInstanceAsStreamFactory(clientInst)},
	})
}

func TestTUNT3NestedTwoLayerStreamOverTUN(t *testing.T) {
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

	runTUNXrayStreamTransfer(t, "nested-ss-vless", []rendr.PathSpec{
		{Transport: "xray-nested-ss-vless"},
		{Transport: "xray-nested-ss-vless"},
	}, []driver.NamedFactory{
		{Name: "xray-nested-ss-vless", Stream: xrayglue.XrayInstanceAsStreamFactory(ssClient)},
	})
}

func TestTUNT3PacketXrayFreedomUDPxUDPFlowOverTUN(t *testing.T) {
	xrayInst := startFreedomInstanceForUDP(t)
	defer xrayInst.Close()

	runTUNXrayPacketEcho(t, "packet-freedom-udp", []rendr.PathSpec{
		{Transport: "xray-freedom-udp"},
		{Transport: "udpflow"},
	}, []driver.NamedFactory{
		{Name: "xray-freedom-udp", Packet: rendrxray.XrayInstanceAsPacketFactory(xrayInst)},
	})
}

func TestTUNT3PacketXrayBalancerUDPxUDPFlowOverTUN(t *testing.T) {
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
	paths := make([]rendr.PathSpec, len(factories))
	named := make([]driver.NamedFactory, len(factories))
	for i, f := range factories {
		paths[i] = rendr.PathSpec{Transport: f.Name}
		named[i] = driver.NamedFactory{Name: f.Name, Packet: f.Factory}
	}
	runTUNXrayPacketEcho(t, "packet-balancer-udp", paths, named)
}

func runTUNXrayStreamTransfer(t *testing.T, label string, paths []rendr.PathSpec, factories []driver.NamedFactory) {
	t.Helper()
	ln, err := rendr.ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	runTUNXrayStreamTransferOnListener(t, label, ln, paths, factories)
}

func runTUNXrayStreamTransferOnListener(t *testing.T, label string, ln rendr.Listener, paths []rendr.PathSpec, factories []driver.NamedFactory) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	listenAddr := ln.Addr().String()
	for i := range paths {
		if paths[i].Address == "" {
			paths[i].Address = listenAddr
		}
		if paths[i].Opts == nil {
			paths[i].Opts = map[string]string{}
		}
		paths[i].Opts["name"] = fmt.Sprintf("tun-t3-%s-%d", label, i+1)
	}

	children := make([]rendr.Target, 0, len(paths))
	for i, ps := range paths {
		children = append(children, rendr.Path(fmt.Sprintf("tun-t3-%s-target-%d", label, i+1), ps))
	}
	root := rendr.Selector("tun-t3-"+label, children)
	id := l3ingress.L3Identity{
		Proto:   l3ingress.ProtocolTCP,
		SrcIP:   netip.MustParseAddr("10.0.0.2"),
		SrcPort: uint16(47000 + len(label)),
		DstIP:   netip.MustParseAddr("198.51.100.30"),
		DstPort: 443,
	}
	manager := &l3session.Manager{
		Starter: l3session.Starter{Options: []l3session.DialerOption{
			func(_ l3ingress.SessionRequest, d *rendr.Dialer) error {
				for _, f := range factories {
					if f.Stream != nil {
						if err := d.AddStreamPathFactory(f.Name, f.Stream); err != nil {
							return err
						}
					}
				}
				return nil
			},
		}},
	}
	relay := &l3session.TCPRelay{Manager: manager, BufferSize: 64 << 10}
	app, endpoint := net.Pipe()
	defer app.Close()

	relayErr := make(chan error, 1)
	go func() {
		relayErr <- relay.Serve(ctx, l3ingress.PacketEvent{
			Meta: l3ingress.PacketMeta{Identity: id},
			Flow: l3ingress.FlowMeta{L3Identity: id, Direction: l3ingress.DirectionIngress},
			Decision: l3ingress.FlowDecision{
				Peer:   "peer-xray",
				Root:   root,
				Egress: "xray",
			},
			Decided: true,
		}, endpoint)
	}()

	server, err := acceptTUNXrayStream(ctx, ln)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	session, err := waitTUNXraySession(ctx, manager, id)
	if err != nil {
		t.Fatal(err)
	}
	admin, ok := session.Conn.(rendr.AdminConn)
	if !ok {
		t.Fatal("session conn is not rendr.AdminConn")
	}
	waitTUNXrayPaths(ctx, admin, len(paths))

	payload := make([]byte, tunT3FixtureSize)
	for i := range payload {
		payload[i] = byte((i*13 + len(label)) & 0xff)
	}
	want := sha256.Sum256(payload)
	recvErr := make(chan error, 1)
	gotHash := sha256.New()
	go func() {
		buf := make([]byte, 128*1024)
		var got int
		for got < len(payload) {
			n, err := server.Read(buf)
			if err != nil {
				recvErr <- err
				return
			}
			gotHash.Write(buf[:n])
			got += n
		}
		recvErr <- nil
	}()

	triggers := []int{len(payload) / 3, len(payload) * 2 / 3}
	nextMig := 0
	for off := 0; off < len(payload); {
		end := off + 128*1024
		if end > len(payload) {
			end = len(payload)
		}
		if err := writeTUNXrayAll(app, payload[off:end]); err != nil {
			t.Fatalf("write at %d: %v", off, err)
		}
		off = end
		for nextMig < len(triggers) && off >= triggers[nextMig] {
			if err := migrateTUNXray(admin); err != nil {
				t.Fatalf("migrate %d: %v", nextMig, err)
			}
			nextMig++
		}
	}
	if err := <-recvErr; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotHash.Sum(nil), want[:]) {
		t.Fatalf("sha256 mismatch for %s", label)
	}
	if admin.MigrationCount() == 0 {
		t.Fatalf("zero migrations for %s", label)
	}
	_ = app.Close()
	select {
	case err := <-relayErr:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("relay shutdown timeout")
	}
}

func acceptTUNXrayStream(ctx context.Context, ln rendr.Listener) (rendr.Conn, error) {
	actx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return ln.Accept(actx)
}

func waitTUNXraySession(ctx context.Context, manager *l3session.Manager, id l3ingress.L3Identity) (*l3session.Session, error) {
	deadline := time.After(15 * time.Second)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if sess, ok := manager.Session(id); ok && sess.Conn != nil {
			return sess, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline:
			return nil, fmt.Errorf("stream session timeout")
		case <-tick.C:
		}
	}
}

func waitTUNXrayPaths(ctx context.Context, admin rendr.AdminConn, want int) {
	deadline := time.After(5 * time.Second)
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for len(admin.Paths()) < want {
		select {
		case <-ctx.Done():
			return
		case <-deadline:
			return
		case <-tick.C:
		}
	}
}

func migrateTUNXray(admin rendr.AdminConn) error {
	cur := admin.ActivePath()
	for _, p := range admin.Paths() {
		if p.ID != cur {
			return admin.Migrate(p.ID)
		}
	}
	return fmt.Errorf("no alternate path from active=%d", cur)
}

func writeTUNXrayAll(c net.Conn, p []byte) error {
	for len(p) > 0 {
		n, err := c.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("short write")
		}
		p = p[n:]
	}
	return nil
}

func runTUNXrayPacketEcho(t *testing.T, label string, paths []rendr.PathSpec, factories []driver.NamedFactory) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	ln, err := rendr.ListenUDPFlowPacket("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	listenAddr := ln.Addr().String()
	for i := range paths {
		if paths[i].Address == "" {
			paths[i].Address = listenAddr
		}
		if paths[i].Opts == nil {
			paths[i].Opts = map[string]string{}
		}
		paths[i].Opts["name"] = fmt.Sprintf("tun-t3-%s-%d", label, i+1)
	}
	children := make([]rendr.Target, 0, len(paths))
	for i, ps := range paths {
		children = append(children, rendr.Path(fmt.Sprintf("tun-t3-%s-target-%d", label, i+1), ps))
	}
	root := rendr.Selector("tun-t3-"+label, children)
	id := l3ingress.L3Identity{
		Proto:   l3ingress.ProtocolUDP,
		SrcIP:   netip.MustParseAddr("10.0.0.2"),
		SrcPort: uint16(50000 + len(label)),
		DstIP:   netip.MustParseAddr("198.51.100.53"),
		DstPort: 53,
	}
	manager := &l3session.Manager{
		Starter: l3session.Starter{Options: []l3session.DialerOption{
			func(_ l3ingress.SessionRequest, d *rendr.Dialer) error {
				for _, f := range factories {
					if f.Packet != nil {
						if err := d.AddPacketPathFactory(f.Name, f.Packet); err != nil {
							return err
						}
					}
				}
				return nil
			},
		}},
	}
	dev := &tunT3CaptureDevice{writes: make(chan []byte, 4096)}
	relay := &l3session.UDPRelay{Device: dev, Manager: manager, BufferSize: 2048}
	defer relay.Close()

	accepted := make(chan rendr.PacketConn, 1)
	go func() {
		actx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		pc, err := ln.AcceptPacket(actx)
		if err == nil {
			accepted <- pc
		}
	}()

	firstPayload := makeTUNXrayUDPPayload(0)
	firstPacket, firstMeta, err := udpEventParts(id, firstPayload)
	if err != nil {
		t.Fatal(err)
	}
	if err := relay.HandlePacket(ctx, l3ingress.PacketEvent{
		Packet: firstPacket,
		Meta:   firstMeta,
		Flow:   l3ingress.FlowMeta{L3Identity: id, Direction: l3ingress.DirectionIngress},
		Decision: l3ingress.FlowDecision{
			Peer:   "peer-xray",
			Root:   root,
			Egress: "xray",
		},
		Decided: true,
	}); err != nil {
		t.Fatal(err)
	}

	var server rendr.PacketConn
	select {
	case server = <-accepted:
	case <-time.After(15 * time.Second):
		t.Fatal("packet accept timeout")
	}
	defer server.Close()
	echoErr := startTUNXrayPacketEcho(server)
	session, err := waitTUNXrayPacketSession(ctx, manager, id)
	if err != nil {
		t.Fatal(err)
	}
	admin, ok := session.PacketConn.(rendr.AdminPacketConn)
	if !ok {
		t.Fatal("session packet conn is not rendr.AdminPacketConn")
	}
	waitTUNXrayPacketPaths(ctx, admin, len(paths))

	const total = 300
	received := map[uint64]struct{}{}
	recvDone := make(chan struct{})
	go func() {
		defer close(recvDone)
		idle := time.NewTimer(5 * time.Second)
		defer idle.Stop()
		for {
			select {
			case packet := <-dev.writes:
				if !idle.Stop() {
					select {
					case <-idle.C:
					default:
					}
				}
				idle.Reset(500 * time.Millisecond)
				meta, err := l3ingress.ParsePacket(packet)
				if err != nil {
					continue
				}
				payload, err := l3ingress.UDPPayload(packet, meta)
				if err != nil || len(payload) < 8 {
					continue
				}
				seq := binary.BigEndian.Uint64(payload[:8])
				received[seq] = struct{}{}
			case <-idle.C:
				return
			}
		}
	}()

	startMigrations := admin.MigrationCount()
	for seq := 1; seq < total; seq++ {
		if seq == total/3 || seq == (total*2)/3 {
			if err := migrateTUNXrayPacket(admin); err != nil {
				t.Fatalf("packet migrate at seq %d: %v", seq, err)
			}
		}
		payload := makeTUNXrayUDPPayload(uint64(seq))
		packet, meta, err := udpEventParts(id, payload)
		if err != nil {
			t.Fatal(err)
		}
		if err := relay.HandlePacket(ctx, l3ingress.PacketEvent{
			Packet: packet,
			Meta:   meta,
			Flow:   l3ingress.FlowMeta{L3Identity: id, Direction: l3ingress.DirectionIngress},
			Decision: l3ingress.FlowDecision{
				Peer:   "peer-xray",
				Root:   root,
				Egress: "xray",
			},
			Decided: true,
		}); err != nil {
			t.Fatalf("packet send seq %d: %v", seq, err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	<-recvDone
	if got := len(received); got < total*95/100 {
		keys := make([]int, 0, len(received))
		for seq := range received {
			keys = append(keys, int(seq))
		}
		sort.Ints(keys)
		t.Fatalf("received %d/%d packets for %s; seqs=%v", got, total, label, keys)
	}
	if admin.MigrationCount() == startMigrations {
		t.Fatalf("zero packet migrations for %s", label)
	}
	relay.CloseFlow(id)
	select {
	case err := <-echoErr:
		if err != nil && err != io.EOF && !isNetClosed(err) {
			t.Fatal(err)
		}
	default:
	}
}

func makeTUNXrayUDPPayload(seq uint64) []byte {
	payload := make([]byte, 512)
	binary.BigEndian.PutUint64(payload[:8], seq)
	binary.BigEndian.PutUint64(payload[8:16], uint64(time.Now().UnixNano()))
	return payload
}

func udpEventParts(id l3ingress.L3Identity, payload []byte) ([]byte, l3ingress.PacketMeta, error) {
	packet, err := l3ingress.BuildUDPPacket(id, payload)
	if err != nil {
		return nil, l3ingress.PacketMeta{}, err
	}
	meta, err := l3ingress.ParsePacket(packet)
	if err != nil {
		return nil, l3ingress.PacketMeta{}, err
	}
	return packet, meta, nil
}

func waitTUNXrayPacketPaths(ctx context.Context, admin rendr.AdminPacketConn, want int) {
	deadline := time.After(5 * time.Second)
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for len(admin.Paths()) < want {
		select {
		case <-ctx.Done():
			return
		case <-deadline:
			return
		case <-tick.C:
		}
	}
}

func waitTUNXrayPacketSession(ctx context.Context, manager *l3session.Manager, id l3ingress.L3Identity) (*l3session.Session, error) {
	deadline := time.After(15 * time.Second)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if sess, ok := manager.Session(id); ok && sess.PacketConn != nil {
			return sess, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline:
			return nil, fmt.Errorf("packet session timeout")
		case <-tick.C:
		}
	}
}

func migrateTUNXrayPacket(admin rendr.AdminPacketConn) error {
	cur := admin.ActivePath()
	for _, p := range admin.Paths() {
		if p.ID != cur {
			return admin.Migrate(p.ID)
		}
	}
	return fmt.Errorf("no alternate packet path from active=%d", cur)
}

func startTUNXrayPacketEcho(pc rendr.PacketConn) <-chan error {
	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				errCh <- err
				return
			}
			if _, err := pc.WriteTo(buf[:n], addr); err != nil {
				errCh <- err
				return
			}
		}
	}()
	return errCh
}

type tunT3CaptureDevice struct {
	writes chan []byte
}

func (d *tunT3CaptureDevice) Read([]byte) (int, error) { return 0, io.EOF }
func (d *tunT3CaptureDevice) Write(p []byte) (int, error) {
	if d.writes != nil {
		d.writes <- p
	}
	return len(p), nil
}
func (d *tunT3CaptureDevice) Close() error { return nil }
func (d *tunT3CaptureDevice) Name() string { return "tun-t3-capture0" }
func (d *tunT3CaptureDevice) MTU() int     { return 1500 }

func isNetClosed(err error) bool {
	if err == nil {
		return false
	}
	return err == net.ErrClosed || strings.Contains(err.Error(), "closed network connection")
}
