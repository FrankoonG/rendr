package l3stack

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/proto"
)

type terminalReadUDPConn struct {
	*net.UDPConn
	terminal error
	armed    atomic.Bool
	fired    chan struct{}
	fireOnce sync.Once
}

// Shadow the embedded message method so Listener exercises the generic
// PacketConn ReadFrom contract, including n>0 with a terminal error.
func (*terminalReadUDPConn) ReadMsgUDP() {}

func (conn *terminalReadUDPConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	n, source, err := conn.UDPConn.ReadFrom(payload)
	if err != nil || !conn.armed.Load() || !udpflowDatagramCarriesData(payload[:n]) {
		return n, source, err
	}
	if conn.armed.CompareAndSwap(true, false) {
		conn.fireOnce.Do(func() { close(conn.fired) })
		return n, source, conn.terminal
	}
	return n, source, err
}

func udpflowDatagramCarriesData(datagram []byte) bool {
	if len(datagram) < proto.UDPFlowHeaderSize+proto.HeaderSize {
		return false
	}
	flowHeader, err := proto.DecodeUDPFlow(datagram[:proto.UDPFlowHeaderSize])
	if err != nil || flowHeader.Version != proto.UDPFlowVersion {
		return false
	}
	frameHeader, err := proto.DecodeHeader(datagram[proto.UDPFlowHeaderSize:])
	return err == nil && frameHeader.Version == proto.Version && frameHeader.Type == proto.FrameData
}

type runtimePacketControl interface {
	rendr.PacketConn
	rendr.MigrationController
	rendr.ConnectionObserver
}

func waitRuntimePacketPaths(t *testing.T, conn rendr.PacketConn, want int) runtimePacketControl {
	t.Helper()
	control, ok := conn.(runtimePacketControl)
	if !ok {
		t.Fatalf("packet connection %T has no migration observation surface", conn)
	}
	deadline := time.Now().Add(3 * time.Second)
	for len(control.Paths()) < want && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := len(control.Paths()); got < want {
		t.Fatalf("packet paths=%d want at least %d: %+v", got, want, control.Paths())
	}
	return control
}

func pathIDByAddress(paths []rendr.PathInfo, address string) uint32 {
	for _, path := range paths {
		if path.Spec.Address == address {
			return path.ID
		}
	}
	return 0
}

func pathIDByLocalAddress(paths []rendr.PathInfo, address string) uint32 {
	for _, path := range paths {
		if path.LocalAddr == address {
			return path.ID
		}
	}
	return 0
}

func waitRuntimeActiveAddress(t *testing.T, control runtimePacketControl, address string) uint32 {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		pathID := pathIDByAddress(control.Paths(), address)
		if pathID != 0 && control.ActivePath() == pathID {
			return pathID
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("active path=%d did not select address %q: %+v", control.ActivePath(), address, control.Paths())
	return 0
}

func waitRuntimeActiveLocalAddress(t *testing.T, control runtimePacketControl, address string) uint32 {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		pathID := pathIDByLocalAddress(control.Paths(), address)
		if pathID != 0 && control.ActivePath() == pathID {
			return pathID
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("active path=%d did not select local address %q: %+v", control.ActivePath(), address, control.Paths())
	return 0
}

func readRuntimePacket(t *testing.T, conn net.PacketConn, want []byte) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 256)
	n, _, err := conn.ReadFrom(payload)
	if err != nil || !bytes.Equal(payload[:n], want) {
		t.Fatalf("ReadFrom=%d, %v, %q want %q", n, err, payload[:n], want)
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeTerminalUDPPayloadPrecedesPathDeathWithPausedReader(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	terminalErr := errors.New("terminal UDP carrier read")
	rawA, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	sourceA := &terminalReadUDPConn{UDPConn: rawA, terminal: terminalErr, fired: make(chan struct{})}
	rawB, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_ = sourceA.Close()
		t.Fatal(err)
	}

	serverRuntime, err := rendr.NewRuntime(rendr.DefaultRuntimeConfig())
	if err != nil {
		_ = sourceA.Close()
		_ = rawB.Close()
		t.Fatal(err)
	}
	listener, err := serverRuntime.Listen(rendr.ListenConfig{Packets: []rendr.PacketSource{
		{Name: "terminal-a", Carrier: rendr.CarrierUDP, Conn: sourceA, MaxDatagramSize: 1400},
		{Name: "survivor-b", Carrier: rendr.CarrierUDP, Conn: rawB, MaxDatagramSize: 1400},
	}})
	if err != nil {
		_ = sourceA.Close()
		_ = rawB.Close()
		t.Fatal(err)
	}
	defer listener.Close()

	acceptResult := make(chan struct {
		conn rendr.PacketConn
		err  error
	}, 1)
	go func() {
		conn, acceptErr := listener.AcceptPacket(ctx)
		acceptResult <- struct {
			conn rendr.PacketConn
			err  error
		}{conn: conn, err: acceptErr}
	}()
	clientRuntime, err := rendr.NewRuntime(rendr.DefaultRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	addressA := sourceA.LocalAddr().String()
	addressB := rawB.LocalAddr().String()
	root := rendr.Selector("root", []rendr.Target{
		rendr.Path("path-a", rendr.PathSpec{Transport: "udpflow", Address: addressA}),
		rendr.Path("path-b", rendr.PathSpec{Transport: "udpflow", Address: addressB}),
	})
	client, err := clientRuntime.DialPacket(ctx, rendr.SessionConfig{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	accepted := <-acceptResult
	if accepted.err != nil {
		t.Fatal(accepted.err)
	}
	server := accepted.conn
	defer server.Close()
	clientControl := waitRuntimePacketPaths(t, client, 2)
	serverControl := waitRuntimePacketPaths(t, server, 2)

	if err := clientControl.SelectTarget("root", "path-a"); err != nil {
		t.Fatal(err)
	}
	clientPathA := waitRuntimeActiveAddress(t, clientControl, addressA)
	serverPathA := waitRuntimeActiveLocalAddress(t, serverControl, addressA)
	serverPathB := pathIDByLocalAddress(serverControl.Paths(), addressB)
	if clientPathA == 0 || serverPathA == 0 || serverPathB == 0 || serverPathA == serverPathB {
		t.Fatalf("invalid A/B path binding client=%d server=%d/%d", clientPathA, serverPathA, serverPathB)
	}

	warmup := []byte("warmup-before-terminal")
	if n, err := client.WriteTo(warmup, nil); err != nil || n != len(warmup) {
		t.Fatalf("warmup WriteTo=%d, %v", n, err)
	}
	readRuntimePacket(t, server, warmup)

	baselineMigrations := serverControl.MigrationCount()
	events := make(chan rendr.MigrationEvent, 2)
	subscription := serverControl.OnMigrationEvent(func(event rendr.MigrationEvent) { events <- event })
	defer subscription.Cancel()
	sourceA.armed.Store(true)
	terminalPayload := []byte("payload-before-path-death")
	if n, err := client.WriteTo(terminalPayload, nil); err != nil || n != len(terminalPayload) {
		t.Fatalf("terminal WriteTo=%d, %v", n, err)
	}
	select {
	case <-sourceA.fired:
	case <-time.After(3 * time.Second):
		t.Fatal("terminal n>0+err read was not injected on path A")
	}

	var migration rendr.MigrationEvent
	select {
	case migration = <-events:
	case <-time.After(3 * time.Second):
		t.Fatalf("path death did not commit while application reader was paused: active=%d migrations=%d",
			serverControl.ActivePath(), serverControl.MigrationCount())
	}
	if migration.OldPathID != serverPathA || migration.NewPathID != serverPathB || migration.Cause != "death" {
		t.Fatalf("migration=%+v want exact A->B death", migration)
	}
	if migration.Ordinal != baselineMigrations+1 || serverControl.MigrationCount() != baselineMigrations+1 {
		t.Fatalf("migration ordinal/count=%d/%d want %d", migration.Ordinal,
			serverControl.MigrationCount(), baselineMigrations+1)
	}
	if migration.Evidence.Kind != rendr.MigrationEvidenceRoute ||
		migration.Evidence.TopologyEpoch == 0 ||
		migration.Evidence.Source.PathID != serverPathA ||
		migration.Evidence.Result.PathID != serverPathB ||
		migration.Evidence.Source.PathOwner == 0 ||
		migration.Evidence.Source.PathGeneration == 0 ||
		migration.Evidence.Source.RouteGeneration == 0 ||
		migration.Evidence.Source.EndpointGeneration == 0 ||
		migration.Evidence.Result.PathOwner == 0 ||
		migration.Evidence.Result.PathGeneration == 0 ||
		migration.Evidence.Result.RouteGeneration == 0 ||
		migration.Evidence.Result.EndpointGeneration == 0 {
		t.Fatalf("migration evidence is not generation-bound: %+v", migration.Evidence)
	}

	readRuntimePacket(t, server, terminalPayload)
	if err := server.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	duplicate := make([]byte, 256)
	if n, _, err := server.ReadFrom(duplicate); n != 0 || err == nil {
		t.Fatalf("terminal payload duplicated: ReadFrom=%d, %v, %q", n, err, duplicate[:n])
	}
	if err := server.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}

	postMigration := []byte("survivor-after-terminal")
	if n, err := client.WriteTo(postMigration, nil); err != nil || n != len(postMigration) {
		t.Fatalf("post-migration WriteTo=%d, %v", n, err)
	}
	readRuntimePacket(t, server, postMigration)
}
