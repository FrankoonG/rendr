package matrix

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/l3ingress"
	"github.com/FrankoonG/rendr/l3session"
	"github.com/FrankoonG/rendr/regress/internal/matrix/driver"
	"github.com/FrankoonG/rendr/regress/internal/xrayglue"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/uuid"
)

const tunT3FixtureSize = 8 << 20

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

func runTUNXrayStreamTransfer(t *testing.T, label string, paths []rendr.PathSpec, factories []driver.NamedFactory) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	ln, err := rendr.ListenTCP("127.0.0.1:0")
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
