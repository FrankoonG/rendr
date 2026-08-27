package l3stack

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/l3ingress"
	"github.com/FrankoonG/rendr/l3session"
	"github.com/FrankoonG/rendr/transport/udpflow"
)

type gatewayPacketTracker struct {
	mu    sync.Mutex
	conns map[string][]*gatewayTrackedPacketConn
}

type gatewayTrackedPacketConn struct {
	net.PacketConn
	name       string
	generation uint64
	closeOnce  sync.Once
	closeErr   error
	closed     atomic.Bool
}

func newGatewayPacketTracker() *gatewayPacketTracker {
	return &gatewayPacketTracker{conns: make(map[string][]*gatewayTrackedPacketConn)}
}

func (tracker *gatewayPacketTracker) factory(name string) rendr.PacketFactory {
	return rendr.PacketFactory{
		Carrier: rendr.CarrierUDP,
		Dial: func(_ context.Context, address string) (rendr.PacketEndpoint, error) {
			peer, err := net.ResolveUDPAddr("udp4", address)
			if err != nil {
				return rendr.PacketEndpoint{}, err
			}
			conn, err := net.ListenUDP("udp4", nil)
			if err != nil {
				return rendr.PacketEndpoint{}, err
			}
			tracker.mu.Lock()
			tracked := &gatewayTrackedPacketConn{
				PacketConn: conn,
				name:       name,
				generation: uint64(len(tracker.conns[name]) + 1),
			}
			tracker.conns[name] = append(tracker.conns[name], tracked)
			tracker.mu.Unlock()
			return rendr.PacketEndpoint{Conn: tracked, Peer: peer, MaxDatagramSize: udpflow.MaxDatagram}, nil
		},
	}
}

func (tracker *gatewayPacketTracker) waitFor(t *testing.T, names ...string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		tracker.mu.Lock()
		ready := true
		for _, name := range names {
			ready = ready && len(tracker.conns[name]) != 0
		}
		tracker.mu.Unlock()
		if ready {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("packet factories did not produce all paths: %v", names)
}

func (tracker *gatewayPacketTracker) closeOne(name string) bool {
	tracker.mu.Lock()
	conns := tracker.conns[name]
	tracker.mu.Unlock()
	return len(conns) != 0 && conns[0].Close() == nil
}

func (tracker *gatewayPacketTracker) connection(name string, generation uint64) *gatewayTrackedPacketConn {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	for _, conn := range tracker.conns[name] {
		if conn.generation == generation {
			return conn
		}
	}
	return nil
}

func (tracker *gatewayPacketTracker) counts() map[string]int {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	counts := make(map[string]int, len(tracker.conns))
	for name, conns := range tracker.conns {
		counts[name] = len(conns)
	}
	return counts
}

func (conn *gatewayTrackedPacketConn) Close() error {
	conn.closeOnce.Do(func() {
		conn.closeErr = conn.PacketConn.Close()
		conn.closed.Store(true)
	})
	return conn.closeErr
}

func TestGatewayUDPPhysicalCarrierDeathMigratesWithoutAdministrativeSelection(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("physical UDP carrier-death qualification requires the Linux release runtime")
	}
	serverRuntime, err := rendr.NewRuntime(rendr.DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	rawPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := serverRuntime.Listen(rendr.ListenConfig{
		AcceptL3Identity: true,
		Packets: []rendr.PacketSource{{
			Name: "udpflow", Carrier: rendr.CarrierUDP, Conn: rawPacketConn, MaxDatagramSize: 1400,
		}},
	})
	if err != nil {
		_ = rawPacketConn.Close()
		t.Fatal(err)
	}
	defer listener.Close()

	echo, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	echoDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 256)
		for index := 0; index < 2; index++ {
			n, peer, readErr := echo.ReadFrom(buffer)
			if readErr != nil {
				echoDone <- readErr
				return
			}
			if _, writeErr := echo.WriteTo(append([]byte("reply:"), buffer[:n]...), peer); writeErr != nil {
				echoDone <- writeErr
				return
			}
		}
		echoDone <- nil
	}()

	registry := l3ingress.NewEgressRegistry()
	if err := registry.Register("direct", &gatewayTestUDPEgress{
		remote:     echo.LocalAddr().(*net.UDPAddr).AddrPort(),
		identities: make(chan l3ingress.L3Identity, 1),
	}); err != nil {
		t.Fatal(err)
	}
	peerCtx, stopPeer := context.WithTimeout(context.Background(), 10*time.Second)
	defer stopPeer()
	peerDone := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.AcceptPacket(peerCtx)
		if acceptErr == nil {
			acceptErr = (&l3session.UDPPeerRelay{PacketConn: conn, Egresses: registry}).Run(peerCtx)
			_ = conn.Close()
		}
		peerDone <- acceptErr
	}()

	clientRuntime, err := rendr.NewRuntime(rendr.DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	tracker := newGatewayPacketTracker()
	for _, name := range []string{"kill-a", "kill-b"} {
		if err := clientRuntime.RegisterPacketFactory(name, tracker.factory(name)); err != nil {
			t.Fatal(err)
		}
	}
	root := rendr.Selector("root", []rendr.Target{
		rendr.Path("udp-a", rendr.PathSpec{Transport: "kill-a", Address: listener.Addr().String()}),
		rendr.Path("udp-b", rendr.PathSpec{Transport: "kill-b", Address: listener.Addr().String()}),
	})
	device := newGatewayTestDevice(1500)
	gateway, err := New(Config{
		Device:  device,
		Starter: &l3session.Starter{Runtime: clientRuntime},
		Router: func(context.Context, l3ingress.FlowMeta) (l3ingress.FlowDecision, error) {
			return l3ingress.FlowDecision{Peer: "peer-a", Root: root, Egress: "direct"}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	gatewayDone := make(chan error, 1)
	go func() { gatewayDone <- gateway.Run(ctx) }()
	defer func() {
		cancel()
		_ = gateway.Close()
		_ = device.Close()
	}()

	id := l3ingress.L3Identity{
		Proto: l3ingress.ProtocolUDP,
		SrcIP: netip.MustParseAddr("10.20.0.2"), SrcPort: 44000,
		DstIP: netip.MustParseAddr("198.51.100.80"), DstPort: 53,
	}
	first := []byte("before-physical-death")
	sendGatewayUDPPacket(t, device, id, first)
	readGatewayUDPReply(t, device, id, append([]byte("reply:"), first...))
	admin := waitGatewayPacketControl(t, gateway, id, 2)
	tracker.waitFor(t, "kill-a", "kill-b")
	pathsBefore := admin.Paths()
	activeBefore := admin.ActivePath()
	activeTransport := ""
	var survivorBefore rendr.PathInfo
	for _, path := range pathsBefore {
		if path.ID == activeBefore {
			activeTransport = path.Spec.Transport
			continue
		}
		survivorBefore = path
	}
	if activeTransport == "" || survivorBefore.ID == 0 || survivorBefore.Spec.Transport == activeTransport {
		t.Fatalf("invalid physical predecessor/survivor binding active=%d transport=%q paths=%+v",
			activeBefore, activeTransport, pathsBefore)
	}
	activeConn := tracker.connection(activeTransport, 1)
	survivorConn := tracker.connection(survivorBefore.Spec.Transport, 1)
	countsBefore := tracker.counts()
	if activeConn == nil || survivorConn == nil || countsBefore[activeTransport] != 1 ||
		countsBefore[survivorBefore.Spec.Transport] != 1 {
		t.Fatalf("factory generations before death active=%p survivor=%p counts=%v",
			activeConn, survivorConn, countsBefore)
	}
	if activeConn == survivorConn || activeConn.closed.Load() || survivorConn.closed.Load() {
		t.Fatalf("invalid socket state before death active_closed=%t survivor_closed=%t",
			activeConn.closed.Load(), survivorConn.closed.Load())
	}
	baselineMigrations := admin.MigrationCount()
	migrationEvents := make(chan rendr.MigrationEvent, 2)
	subscription := admin.OnMigrationEvent(func(event rendr.MigrationEvent) {
		migrationEvents <- event
	})
	defer subscription.Cancel()
	if subscription.AfterOrdinal() != baselineMigrations {
		t.Fatalf("migration subscription starts after %d want %d",
			subscription.AfterOrdinal(), baselineMigrations)
	}
	if !tracker.closeOne(activeTransport) {
		t.Fatalf("failed to physically close active transport %q", activeTransport)
	}
	if !activeConn.closed.Load() {
		t.Fatalf("factory generation %s/%d did not physically close", activeConn.name, activeConn.generation)
	}

	var migration rendr.MigrationEvent
	select {
	case migration = <-migrationEvents:
	case <-time.After(3 * time.Second):
		t.Fatalf("physical death emitted no migration event: active=%d before=%d count=%d",
			admin.ActivePath(), activeBefore, admin.MigrationCount())
	}
	if migration.OldPathID != activeBefore || migration.NewPathID != survivorBefore.ID ||
		migration.Cause != "death" || migration.Ordinal != baselineMigrations+1 {
		t.Fatalf("physical death event=%+v want path %d->%d ordinal %d",
			migration, activeBefore, survivorBefore.ID, baselineMigrations+1)
	}
	if migration.Evidence.Kind != rendr.MigrationEvidenceRoute ||
		migration.Evidence.TopologyEpoch == 0 ||
		migration.Evidence.Source.PathID != activeBefore ||
		migration.Evidence.Result.PathID != survivorBefore.ID ||
		migration.Evidence.Source.PathOwner == 0 ||
		migration.Evidence.Source.PathGeneration == 0 ||
		migration.Evidence.Source.RouteGeneration == 0 ||
		migration.Evidence.Source.HealthRevision == 0 ||
		migration.Evidence.Result.PathOwner == 0 ||
		migration.Evidence.Result.PathGeneration == 0 ||
		migration.Evidence.Result.RouteGeneration == 0 ||
		migration.Evidence.Result.HealthRevision == 0 ||
		migration.Evidence.Source.LocalTargetID == ([16]byte{}) ||
		migration.Evidence.Source.PeerTargetID == ([16]byte{}) ||
		migration.Evidence.Result.LocalTargetID == ([16]byte{}) ||
		migration.Evidence.Result.PeerTargetID == ([16]byte{}) {
		t.Fatalf("physical death event lacks exact route-generation binding: %+v", migration.Evidence)
	}
	// Generic PacketFactory carriers do not own a leaf-mobility endpoint.
	// Physical fallback must not manufacture selector or endpoint authority;
	// the selector aligns its desired child afterward without a second event.
	if migration.Evidence.HealthEpoch != 0 ||
		migration.Evidence.TransactionID != ([16]byte{}) ||
		migration.Evidence.RefreshEvidenceGeneration != 0 ||
		migration.Evidence.SourceEndpointGeneration != 0 ||
		migration.Evidence.ResultEndpointGeneration != 0 ||
		migration.Evidence.Source.EndpointGeneration != 0 ||
		migration.Evidence.Source.PeerMobilityEpoch != 0 ||
		migration.Evidence.Result.EndpointGeneration != 0 ||
		migration.Evidence.Result.PeerMobilityEpoch != 0 ||
		migration.Evidence.Selector != (rendr.MigrationSelectorBinding{}) ||
		migration.Evidence.Leaf != (rendr.MigrationLeafBinding{}) ||
		len(migration.Evidence.ProbeGenerations) != 0 {
		t.Fatalf("physical route fallback claimed unrelated selector or leaf authority: %+v", migration.Evidence)
	}
	if got := admin.MigrationCount(); got != baselineMigrations+1 {
		t.Fatalf("physical death migration count=%d want %d", got, baselineMigrations+1)
	}
	if admin.ActivePath() != survivorBefore.ID {
		t.Fatalf("active path after death=%d want existing survivor=%d", admin.ActivePath(), survivorBefore.ID)
	}
	countsAfter := tracker.counts()
	if countsAfter[activeTransport] != countsBefore[activeTransport] ||
		countsAfter[survivorBefore.Spec.Transport] != countsBefore[survivorBefore.Spec.Transport] ||
		tracker.connection(survivorBefore.Spec.Transport, 1) != survivorConn || survivorConn.closed.Load() {
		t.Fatalf("migration dialed a replacement or replaced survivor: before=%v after=%v survivor_same=%t closed=%t",
			countsBefore, countsAfter,
			tracker.connection(survivorBefore.Spec.Transport, 1) == survivorConn,
			survivorConn.closed.Load())
	}

	second := []byte("after-physical-death")
	sendGatewayUDPPacket(t, device, id, second)
	readGatewayUDPReply(t, device, id, append([]byte("reply:"), second...))
	if got := admin.MigrationCount(); got != baselineMigrations+1 {
		t.Fatalf("post-survivor traffic changed migration count=%d want %d", got, baselineMigrations+1)
	}
	select {
	case extra := <-migrationEvents:
		t.Fatalf("physical death emitted an extra migration event: %+v", extra)
	default:
	}

	select {
	case err := <-echoDone:
		if err != nil {
			t.Fatalf("UDP echo: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("UDP echo did not receive both requests")
	}
	cancel()
	stopPeer()
	select {
	case err := <-gatewayDone:
		if err != nil {
			t.Fatalf("gateway Run: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("gateway did not stop")
	}
	select {
	case err := <-peerDone:
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("UDP peer relay: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("UDP peer relay did not stop")
	}
}
