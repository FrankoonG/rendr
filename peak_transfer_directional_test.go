package rendr

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type peakDirectionalPath struct {
	conn net.Conn
	mu   sync.Mutex
	die  func(transport.DeathCause, error)
}

func (p *peakDirectionalPath) Read(b []byte) (int, error)  { return p.conn.Read(b) }
func (p *peakDirectionalPath) Write(b []byte) (int, error) { return p.conn.Write(b) }
func (p *peakDirectionalPath) Close() error                { return p.conn.Close() }
func (*peakDirectionalPath) Quality() transport.PathQuality {
	return transport.PathQuality{}
}
func (p *peakDirectionalPath) OnDeath(fn func(transport.DeathCause, error)) {
	p.mu.Lock()
	p.die = fn
	p.mu.Unlock()
}
func (*peakDirectionalPath) LocalAddr() string  { return "peak-directional-local" }
func (*peakDirectionalPath) RemoteAddr() string { return "peak-directional-remote" }

type peakDirectionalFixture struct {
	client           *engine.Engine
	server           *engine.Engine
	controller       *peakTransferController
	localNormal      proto.TargetID
	localPeak        proto.TargetID
	peerSelector     proto.TargetID
	peerNormal       proto.TargetID
	peerPeak         proto.TargetID
	serverNormalPath uint32
	serverPeakPath   uint32
}

func newPeakDirectionalFixture(t *testing.T, localRoot, peerRoot Target) *peakDirectionalFixture {
	t.Helper()
	localPlan, err := compileTargetForDial(localRoot)
	if err != nil {
		t.Fatalf("compile local target: %v", err)
	}
	peerPlan, err := compileTargetForDial(peerRoot)
	if err != nil {
		t.Fatalf("compile peer target: %v", err)
	}
	localTargets := peakTargetsFromManifest(localPlan.graph.manifest)
	peerTargets := peakTargetsFromManifest(peerPlan.graph.manifest)
	flowID := [16]byte{0x70, 0x65, 0x61, 0x6b}
	client := engine.New(engine.SideClient, flowID, engine.Limits{}.Clamp())
	server := engine.New(engine.SideServer, flowID, engine.Limits{}.Clamp())
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	if err := client.ConfigureLocalGraph(1, localPlan.graph.manifest); err != nil {
		t.Fatalf("configure client local graph: %v", err)
	}
	if err := client.ConfigurePeerGraph(1, peerPlan.graph.manifest); err != nil {
		t.Fatalf("configure client peer graph: %v", err)
	}
	if err := server.ConfigureLocalGraph(1, peerPlan.graph.manifest); err != nil {
		t.Fatalf("configure server local graph: %v", err)
	}
	if err := server.ConfigurePeerGraph(1, localPlan.graph.manifest); err != nil {
		t.Fatalf("configure server peer graph: %v", err)
	}
	for _, e := range []*engine.Engine{client, server} {
		if err := e.ConfigureExecution(proto.ExecutionKindSelector); err != nil {
			t.Fatalf("configure execution: %v", err)
		}
	}

	attach := func(localID, peerID proto.TargetID, localName, peerName string) (uint32, uint32) {
		clientConn, serverConn := net.Pipe()
		clientID, err := client.AttachPathBound(&peakDirectionalPath{conn: clientConn}, transport.PathSpec{
			Transport: "memory", Opts: map[string]string{"name": localName},
		}, engine.PathBinding{LocalTXTargetID: localID, PeerTXTargetID: peerID})
		if err != nil {
			t.Fatalf("attach client path: %v", err)
		}
		serverID, err := server.AttachPathBound(&peakDirectionalPath{conn: serverConn}, transport.PathSpec{
			Transport: "memory", Opts: map[string]string{"name": peerName},
		}, engine.PathBinding{LocalTXTargetID: peerID, PeerTXTargetID: localID})
		if err != nil {
			t.Fatalf("attach server path: %v", err)
		}
		return clientID, serverID
	}
	localNormalNode, _ := localPlan.graph.manifest.Node(localTargets.normalTargetID)
	localPeakNode, _ := localPlan.graph.manifest.Node(localTargets.peakTargetID)
	peerNormalNode, _ := peerPlan.graph.manifest.Node(peerTargets.normalTargetID)
	peerPeakNode, _ := peerPlan.graph.manifest.Node(peerTargets.peakTargetID)
	clientNormalPath, serverNormalPath := attach(localTargets.normalTargetID, peerTargets.normalTargetID, localNormalNode.Name, peerNormalNode.Name)
	clientPeakPath, serverPeakPath := attach(localTargets.peakTargetID, peerTargets.peakTargetID, localPeakNode.Name, peerPeakNode.Name)
	if err := client.InitializePolicySelection(localTargets.selectorID, localTargets.normalTargetID, "test-initial"); err != nil {
		t.Fatalf("initialize client policy: %v", err)
	}
	if err := server.InitializePolicySelection(peerTargets.selectorID, peerTargets.normalTargetID, "test-initial"); err != nil {
		t.Fatalf("initialize server policy: %v", err)
	}
	controller := newPeakTransferController(client, func(Mode) {}, localPlan, []uint32{clientNormalPath, clientPeakPath})
	return &peakDirectionalFixture{
		client: client, server: server, controller: controller,
		localNormal: localTargets.normalTargetID, localPeak: localTargets.peakTargetID,
		peerSelector: peerTargets.selectorID, peerNormal: peerTargets.normalTargetID, peerPeak: peerTargets.peakTargetID,
		serverNormalPath: serverNormalPath, serverPeakPath: serverPeakPath,
	}
}

func TestPeakTransferRXUsesAsymmetricPeerGraphTargets(t *testing.T) {
	fixture := newPeakDirectionalFixture(t,
		Selector("client-root", []Target{
			Path("client-normal", PathSpec{}),
			Path("client-peak", PathSpec{}),
		}, PeakTransfer{Targets: []string{"client-peak"}}),
		Selector("server-root", []Target{
			Path("server-normal", PathSpec{}),
			Path("server-peak", PathSpec{}),
		}, PeakTransfer{Targets: []string{"server-peak"}}),
	)
	if fixture.controller.localTargets.selectorID == fixture.controller.peerTargets.selectorID ||
		fixture.controller.localTargets.peakTargetID == fixture.controller.peerTargets.peakTargetID {
		t.Fatal("test setup did not produce asymmetric directional target IDs")
	}
	if err := fixture.controller.applyPolicy(true, ModeSelector, peakTransferPeak, "test-promote"); err != nil {
		t.Fatalf("RX peak request: %v", err)
	}
	if got := fixture.server.ActivePath(); got != fixture.serverPeakPath {
		t.Fatalf("server active path after RX promote = %d, want peer peak path %d", got, fixture.serverPeakPath)
	}
	if got := fixture.client.ActivePath(); got == 0 || got == fixture.serverPeakPath {
		t.Fatalf("RX policy request changed or confused the client sender path: %d", got)
	}
	if err := fixture.controller.applyPolicy(true, ModeSelector, peakTransferNormal, "test-return"); err != nil {
		t.Fatalf("RX normal request: %v", err)
	}
	if got := fixture.server.ActivePath(); got != fixture.serverNormalPath {
		t.Fatalf("server active path after RX return = %d, want peer normal path %d", got, fixture.serverNormalPath)
	}
}

func TestPeakTransferRXRejectsLocalIDThatAliasesPeerSibling(t *testing.T) {
	fixture := newPeakDirectionalFixture(t,
		Selector("shared-root", []Target{
			Path("normal-a", PathSpec{}),
			Path("peak-b", PathSpec{}),
		}, PeakTransfer{Targets: []string{"peak-b"}}),
		Selector("shared-root", []Target{
			Path("peak-b", PathSpec{}),
			Path("normal-a", PathSpec{}),
		}, PeakTransfer{Targets: []string{"normal-a"}}),
	)
	if fixture.localPeak != fixture.peerNormal {
		t.Fatal("test setup did not alias the local peak ID to the peer normal sibling")
	}
	for _, test := range []struct {
		name       string
		selectorID proto.TargetID
		targetID   proto.TargetID
	}{
		{
			name:       "foreign selector",
			selectorID: proto.DeriveTargetID(proto.GraphNodeKindSelector, "foreign-selector"),
			targetID:   fixture.peerPeak,
		},
		{
			name:       "foreign target",
			selectorID: fixture.peerSelector,
			targetID:   proto.DeriveTargetID(proto.GraphNodeKindPath, "foreign-target"),
		},
		{
			name:       "valid peer sibling with wrong role",
			selectorID: fixture.controller.localTargets.selectorID,
			targetID:   fixture.localPeak,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err := fixture.controller.requestPeerSelection(ctx, peakTransferPeak,
				test.selectorID, test.targetID, "substituted")
			if err == nil {
				t.Fatal("accepted a substituted peer peak-transfer target")
			}
			if got := fixture.server.ActivePath(); got != fixture.serverNormalPath {
				t.Fatalf("rejected substitution changed server path to %d, want %d", got, fixture.serverNormalPath)
			}
		})
	}
	if err := fixture.controller.applyPolicy(true, ModeSelector, peakTransferPeak, "valid-peer-role"); err != nil {
		t.Fatalf("valid peer peak request: %v", err)
	}
	if got := fixture.server.ActivePath(); got != fixture.serverPeakPath {
		t.Fatalf("valid peer peak request selected path %d, want %d", got, fixture.serverPeakPath)
	}
}
