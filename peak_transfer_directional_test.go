package rendr

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type peakDirectionalPath struct {
	conn    net.Conn
	mu      sync.Mutex
	die     func(transport.DeathCause, error)
	quality transport.PathQuality
}

func (p *peakDirectionalPath) Read(b []byte) (int, error)  { return p.conn.Read(b) }
func (p *peakDirectionalPath) Write(b []byte) (int, error) { return p.conn.Write(b) }
func (p *peakDirectionalPath) Close() error                { return p.conn.Close() }
func (p *peakDirectionalPath) Quality() transport.PathQuality {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.quality
}
func (p *peakDirectionalPath) QualityContext(ctx context.Context) (transport.PathQuality, error) {
	select {
	case <-ctx.Done():
		return transport.PathQuality{}, ctx.Err()
	default:
		return p.Quality(), nil
	}
}
func (p *peakDirectionalPath) setQuality(quality transport.PathQuality) {
	p.mu.Lock()
	p.quality = quality
	p.mu.Unlock()
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
	localGraph       compiledTargetGraph
	localNormal      proto.TargetID
	localPeak        proto.TargetID
	peerSelector     proto.TargetID
	peerNormal       proto.TargetID
	peerPeak         proto.TargetID
	clientNormalPath uint32
	clientPeakPath   uint32
	serverNormalPath uint32
	serverPeakPath   uint32
	serverPathIDs    map[proto.TargetID]uint32
	clientPaths      map[proto.TargetID]*peakDirectionalPath // client-owned TX evidence, keyed by local target
	serverPaths      map[proto.TargetID]*peakDirectionalPath // server-owned TX evidence, keyed by peer target
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
	serverPathIDs := make(map[proto.TargetID]uint32)
	clientPaths := make(map[proto.TargetID]*peakDirectionalPath)
	serverPaths := make(map[proto.TargetID]*peakDirectionalPath)
	attach := func(localID, peerID proto.TargetID, localName, peerName string) (uint32, uint32) {
		clientConn, serverConn := net.Pipe()
		quality := transport.PathQuality{RTT: time.Millisecond, At: time.Now()}
		clientPath := &peakDirectionalPath{conn: clientConn, quality: quality}
		clientID, err := client.AttachPathBound(clientPath, transport.PathSpec{
			Transport: "memory", Opts: map[string]string{"name": localName},
		}, engine.PathBinding{LocalTXTargetID: localID, PeerTXTargetID: peerID})
		if err != nil {
			t.Fatalf("attach client path: %v", err)
		}
		serverPath := &peakDirectionalPath{conn: serverConn, quality: quality}
		serverID, err := server.AttachPathBound(serverPath, transport.PathSpec{
			Transport: "memory", Opts: map[string]string{"name": peerName},
		}, engine.PathBinding{LocalTXTargetID: peerID, PeerTXTargetID: localID})
		if err != nil {
			t.Fatalf("attach server path: %v", err)
		}
		clientPaths[localID] = clientPath
		serverPathIDs[peerID] = serverID
		serverPaths[peerID] = serverPath
		return clientID, serverID
	}
	localNormalNode, _ := localPlan.graph.manifest.Node(localTargets.normalTargetID)
	_, localPeak, ok := localTargets.selection(peakTransferPeak)
	if !ok {
		t.Fatal("local peak target is unavailable")
	}
	_, peerPeak, ok := peerTargets.selection(peakTransferPeak)
	if !ok {
		t.Fatal("peer peak target is unavailable")
	}
	peerNormalNode, _ := peerPlan.graph.manifest.Node(peerTargets.normalTargetID)
	pathIDs := make([]uint32, 0, 1+len(localTargets.peakTargetIDs))
	clientNormalPath, serverNormalPath := attach(localTargets.normalTargetID, peerTargets.normalTargetID, localNormalNode.Name, peerNormalNode.Name)
	pathIDs = append(pathIDs, clientNormalPath)
	clientPeakPath := uint32(0)
	serverPeakPath := uint32(0)
	for i, localPeakID := range localTargets.peakTargetIDs {
		peerIndex := i
		if peerIndex >= len(peerTargets.peakTargetIDs) {
			peerIndex = len(peerTargets.peakTargetIDs) - 1
		}
		peerPeakID := peerTargets.peakTargetIDs[peerIndex]
		localPeakNode, _ := localPlan.graph.manifest.Node(localPeakID)
		peerPeakNode, _ := peerPlan.graph.manifest.Node(peerPeakID)
		attachedClientPath, attachedServerPath := attach(localPeakID, peerPeakID, localPeakNode.Name, peerPeakNode.Name)
		pathIDs = append(pathIDs, attachedClientPath)
		if i == 0 {
			clientPeakPath = attachedClientPath
			serverPeakPath = attachedServerPath
		}
	}
	if err := client.InitializePolicySelection(localTargets.selectorID, localTargets.normalTargetID, "test-initial"); err != nil {
		t.Fatalf("initialize client policy: %v", err)
	}
	if err := server.InitializePolicySelection(peerTargets.selectorID, peerTargets.normalTargetID, "test-initial"); err != nil {
		t.Fatalf("initialize server policy: %v", err)
	}
	installPeakTransferPeerAdmission(server)
	controller := newPeakTransferController(client, localPlan, pathIDs)
	return &peakDirectionalFixture{
		client: client, server: server, controller: controller,
		localGraph:  localPlan.graph,
		localNormal: localTargets.normalTargetID, localPeak: localPeak,
		peerSelector: peerTargets.selectorID, peerNormal: peerTargets.normalTargetID, peerPeak: peerPeak,
		clientNormalPath: clientNormalPath, clientPeakPath: clientPeakPath,
		serverNormalPath: serverNormalPath, serverPeakPath: serverPeakPath,
		serverPathIDs: serverPathIDs, clientPaths: clientPaths, serverPaths: serverPaths,
	}
}

func TestPeakTransferReconcilesActualLocalTargetChanges(t *testing.T) {
	newFixture := func(t *testing.T) *peakDirectionalFixture {
		t.Helper()
		return newPeakDirectionalFixture(t,
			Selector("reconcile-client-root", []Target{
				Path("reconcile-client-normal", PathSpec{}),
				Path("reconcile-client-peak", PathSpec{}),
			}, PeakTransfer{Targets: []string{"reconcile-client-peak"}}),
			Selector("reconcile-server-root", []Target{
				Path("reconcile-server-normal", PathSpec{}),
				Path("reconcile-server-peak", PathSpec{}),
			}, PeakTransfer{Targets: []string{"reconcile-server-peak"}}),
		)
	}
	assertReconciled := func(t *testing.T, fixture *peakDirectionalFixture) {
		t.Helper()
		fixture.controller.observeDelivery(time.Now(), false)
		fixture.controller.mu.Lock()
		state := fixture.controller.tx
		fixture.controller.mu.Unlock()
		if state.onPeak || state.activePeakTarget != (proto.TargetID{}) || state.cursor.valid {
			t.Fatalf("controller retained stale peak phase after actual target changed: %+v", state)
		}
	}

	t.Run("public SelectTarget", func(t *testing.T) {
		fixture := newFixture(t)
		if err := fixture.client.SelectPeakTransferTarget(
			fixture.controller.localTargets.selectorID, fixture.localPeak, true, "test-promote",
		); err != nil {
			t.Fatal(err)
		}
		fixture.controller.tx = peakTransferDirection{
			onPeak: true, activePeakTarget: fixture.localPeak,
			cursor: peakDeliveryCursor{valid: true, targetID: fixture.localPeak},
		}
		conn := &engineBackedConn{e: fixture.client, graph: fixture.localGraph}
		if err := conn.SelectTarget("reconcile-client-root", "reconcile-client-normal"); err != nil {
			t.Fatalf("public SelectTarget: %v", err)
		}
		assertReconciled(t, fixture)
	})

	t.Run("active peak path death", func(t *testing.T) {
		fixture := newFixture(t)
		if err := fixture.client.SelectPeakTransferTarget(
			fixture.controller.localTargets.selectorID, fixture.localPeak, true, "test-promote",
		); err != nil {
			t.Fatal(err)
		}
		fixture.controller.tx = peakTransferDirection{
			onPeak: true, activePeakTarget: fixture.localPeak,
			cursor: peakDeliveryCursor{valid: true, targetID: fixture.localPeak},
		}
		if err := fixture.client.RemovePath(fixture.clientPeakPath); err != nil {
			t.Fatalf("remove active peak path: %v", err)
		}
		deadline := time.Now().Add(time.Second)
		for {
			_, effective, _, ok := fixture.client.SelectorSelection(fixture.controller.localTargets.selectorID)
			if ok && effective == fixture.localNormal {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("path death did not project normal target: active=%d", fixture.client.ActivePath())
			}
			time.Sleep(time.Millisecond)
		}
		assertReconciled(t, fixture)
	})
}

func TestPeakTransferRetryDeadlineStartsAfterPolicyCompletion(t *testing.T) {
	fixture := newPeakDirectionalFixture(t,
		Selector("retry-client-root", []Target{
			Path("retry-client-normal", PathSpec{}),
			Path("retry-client-peak", PathSpec{}),
		}, PeakTransfer{Targets: []string{"retry-client-peak"}, SaturationFor: time.Nanosecond}),
		Selector("retry-server-root", []Target{
			Path("retry-server-normal", PathSpec{}),
			Path("retry-server-peak", PathSpec{}),
		}, PeakTransfer{Targets: []string{"retry-server-peak"}}),
	)
	startedAt := time.Now()
	fixture.controller.tx.normalBytes = defaultPeakMinBytes
	fixture.controller.tx.normalPeakBps = 100
	fixture.controller.tx.saturatedSince = startedAt.Add(-time.Second)
	fixture.controller.policyApplyForTest = func(bool, peakTransferChoice, proto.TargetID, string) error {
		time.Sleep(2 * defaultPeakWindow)
		return engine.ErrPolicyRejected
	}
	fixture.controller.evaluate(startedAt, defaultPeakMinSampleBytes, 100, false)
	completedAt := time.Now()
	fixture.controller.policyApplyForTest = nil
	fixture.controller.mu.Lock()
	retryAfter := fixture.controller.tx.policyRetryAfter
	fixture.controller.mu.Unlock()
	if !retryAfter.After(completedAt) {
		t.Fatalf("retry deadline=%s was measured from policy start; completion=%s", retryAfter, completedAt)
	}
}

func TestPeakTransferPeerInitializationCannotOverrideNewRXPhase(t *testing.T) {
	fixture := newPeakDirectionalFixture(t,
		Selector("init-client-root", []Target{
			Path("init-client-normal", PathSpec{}),
			Path("init-client-peak", PathSpec{}),
		}, PeakTransfer{Targets: []string{"init-client-peak"}}),
		Selector("init-server-root", []Target{
			Path("init-server-normal", PathSpec{}),
			Path("init-server-peak", PathSpec{}),
		}, PeakTransfer{Targets: []string{"init-server-peak"}}),
	)
	initialization := peakPeerInitialization{
		selectorID:      fixture.peerSelector,
		phaseGeneration: fixture.controller.directionPhase(true),
		retryDelay:      defaultPeakWindow,
		active:          true,
	}
	fixture.controller.mu.Lock()
	fixture.controller.peerInitializationErr = errors.New("injected stale initialization retry")
	fixture.controller.mu.Unlock()
	selected, _, err := fixture.controller.beginPeakObservation(true, nil, "new-rx-demand")
	if err != nil {
		t.Fatalf("new RX peak phase: %v", err)
	}
	if selected != fixture.peerPeak || fixture.server.ActivePath() != fixture.serverPeakPath {
		t.Fatalf("new RX phase selected target/path=%x/%d want %x/%d",
			selected, fixture.server.ActivePath(), fixture.peerPeak, fixture.serverPeakPath)
	}
	fixture.controller.advancePeerInitialization(&initialization, time.Now())
	fixture.controller.mu.Lock()
	state := fixture.controller.rx
	initializationErr := fixture.controller.peerInitializationErr
	fixture.controller.mu.Unlock()
	if initialization.active || initializationErr != nil {
		t.Fatalf("stale initialization remained active/error=%t/%v", initialization.active, initializationErr)
	}
	if !state.onPeak || state.activePeakTarget != fixture.peerPeak ||
		fixture.server.ActivePath() != fixture.serverPeakPath {
		t.Fatalf("stale initialization overrode new RX phase: state=%+v active=%d", state, fixture.server.ActivePath())
	}
}

func TestPeakTransferDirectionWorkersDoNotBlockEachOther(t *testing.T) {
	fixture := newPeakDirectionalFixture(t,
		Selector("workers-client-root", []Target{
			Path("workers-client-normal", PathSpec{}),
			Path("workers-client-peak", PathSpec{}),
		}, PeakTransfer{Targets: []string{"workers-client-peak"}, SaturationFor: time.Nanosecond}),
		Selector("workers-server-root", []Target{
			Path("workers-server-normal", PathSpec{}),
			Path("workers-server-peak", PathSpec{}),
		}, PeakTransfer{Targets: []string{"workers-server-peak"}, SaturationFor: time.Nanosecond}),
	)
	old := time.Now().Add(-time.Second)
	fixture.controller.mu.Lock()
	fixture.controller.tx.normalBytes = defaultPeakMinBytes
	fixture.controller.tx.normalPeakBps = 1
	fixture.controller.tx.saturatedSince = old
	fixture.controller.rx.normalBytes = defaultPeakMinBytes
	fixture.controller.rx.normalPeakBps = 1
	fixture.controller.rx.saturatedSince = old
	fixture.controller.mu.Unlock()
	fixture.controller.directionObserveForTest = func(now time.Time, rx bool) {
		fixture.controller.evaluate(now, defaultPeakMinSampleBytes, 1, rx)
	}

	txEntered := make(chan struct{})
	rxEntered := make(chan struct{})
	releaseTX := make(chan struct{})
	var txOnce, rxOnce, releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseTX) }) })
	fixture.controller.policyApplyForTest = func(rx bool, choice peakTransferChoice, _ proto.TargetID, _ string) error {
		if choice != peakTransferPeak {
			return nil
		}
		if rx {
			rxOnce.Do(func() { close(rxEntered) })
			return nil
		}
		txOnce.Do(func() { close(txEntered) })
		<-releaseTX
		return nil
	}
	fixture.controller.workers.Add(2)
	go func() {
		defer fixture.controller.workers.Done()
		fixture.controller.directionLoop(false, proto.TargetID{})
	}()
	go func() {
		defer fixture.controller.workers.Done()
		fixture.controller.directionLoop(true, proto.TargetID{})
	}()
	select {
	case <-txEntered:
	case <-time.After(time.Second):
		t.Fatal("TX worker did not enter the blocked policy transaction")
	}
	select {
	case <-rxEntered:
	case <-time.After(time.Second):
		t.Fatal("RX worker was blocked behind the TX policy transaction")
	}
	releaseOnce.Do(func() { close(releaseTX) })
	fixture.controller.stopLoop()
	fixture.controller.policyApplyForTest = nil
	fixture.controller.directionObserveForTest = nil
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
		fixture.localPeak == fixture.peerPeak {
		t.Fatal("test setup did not produce asymmetric directional target IDs")
	}
	if err := fixture.controller.applyPolicy(true, peakTransferPeak, "test-promote"); err != nil {
		t.Fatalf("RX peak request: %v", err)
	}
	if got := fixture.server.ActivePath(); got != fixture.serverPeakPath {
		t.Fatalf("server active path after RX promote = %d, want peer peak path %d", got, fixture.serverPeakPath)
	}
	if got := fixture.client.ActivePath(); got == 0 || got == fixture.serverPeakPath {
		t.Fatalf("RX policy request changed or confused the client sender path: %d", got)
	}
	if err := fixture.controller.applyPolicy(true, peakTransferNormal, "test-return"); err != nil {
		t.Fatalf("RX normal request: %v", err)
	}
	if got := fixture.server.ActivePath(); got != fixture.serverNormalPath {
		t.Fatalf("server active path after RX return = %d, want peer normal path %d", got, fixture.serverNormalPath)
	}
}

func TestPeakTransferPeerAdmissionUsesOwnerJitterWithoutCrossRoleBorrowing(t *testing.T) {
	fixture := newPeakDirectionalFixture(t,
		Selector("client-quality-root", []Target{
			Path("client-quality-normal", PathSpec{}),
			Path("client-quality-peak", PathSpec{}),
		}, PeakTransfer{Targets: []string{"client-quality-peak"}}),
		Selector("server-quality-root", []Target{
			Path("server-quality-normal", PathSpec{}),
			Path("server-quality-peak", PathSpec{}),
		}, PeakTransfer{Targets: []string{"server-quality-peak"}}),
	)
	if fixture.localPeak == fixture.peerPeak ||
		fixture.clientPaths[fixture.localPeak] == fixture.serverPaths[fixture.peerPeak] {
		t.Fatal("test setup did not isolate endpoint roles and directional target IDs")
	}

	const jitterBoundary = 200 * time.Millisecond
	qualityAt := time.Now()
	atBoundary := transport.PathQuality{
		RTT: 10 * time.Millisecond, Jitter: jitterBoundary, At: qualityAt,
	}
	aboveBoundary := transport.PathQuality{
		RTT: 10 * time.Millisecond, Jitter: jitterBoundary + time.Nanosecond, At: qualityAt,
	}

	// This fixture never starts either selector, so no path probe can replace
	// the independently controlled PathConn timing evidence.
	fixture.clientPaths[fixture.localPeak].setQuality(atBoundary)
	fixture.serverPaths[fixture.peerPeak].setQuality(aboveBoundary)
	if !fixture.client.LocalPeakTransferTargetHealthy(fixture.controller.localTargets.selectorID, fixture.localPeak) {
		t.Fatal("client sender rejected jitter exactly at the admission boundary")
	}
	ranked, err := fixture.server.RankLocalSelectorClass(fixture.peerSelector, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(ranked) != 1 || ranked[0] != fixture.peerPeak {
		t.Fatalf("ordinary server selector ranking=%x want over-boundary peak %x before admission", ranked, fixture.peerPeak)
	}
	if fixture.server.LocalPeakTransferTargetHealthy(fixture.peerSelector, fixture.peerPeak) {
		t.Fatal("server sender admitted jitter above the admission boundary")
	}
	if err := fixture.controller.applyPolicy(true, peakTransferPeak, "owner-jitter-reject"); !errors.Is(err, engine.ErrPolicyRejected) {
		t.Fatalf("peer policy rejection=%v, want %v", err, engine.ErrPolicyRejected)
	}
	if got := fixture.server.ActivePath(); got != fixture.serverNormalPath {
		t.Fatalf("rejected peer request changed server sender path=%d want normal=%d", got, fixture.serverNormalPath)
	}
	if got := fixture.client.ActivePath(); got != fixture.clientNormalPath {
		t.Fatalf("rejected peer request changed client sender path=%d want normal=%d", got, fixture.clientNormalPath)
	}

	fixture.clientPaths[fixture.localPeak].setQuality(aboveBoundary)
	fixture.serverPaths[fixture.peerPeak].setQuality(atBoundary)
	if fixture.client.LocalPeakTransferTargetHealthy(fixture.controller.localTargets.selectorID, fixture.localPeak) {
		t.Fatal("client sender admitted jitter above the admission boundary")
	}
	if !fixture.server.LocalPeakTransferTargetHealthy(fixture.peerSelector, fixture.peerPeak) {
		t.Fatal("server sender rejected jitter exactly at the admission boundary")
	}
	if err := fixture.controller.applyPolicy(true, peakTransferPeak, "owner-jitter-boundary"); err != nil {
		t.Fatalf("peer policy boundary acceptance: %v", err)
	}
	if got := fixture.server.ActivePath(); got != fixture.serverPeakPath {
		t.Fatalf("accepted peer request selected server sender path=%d want peak=%d", got, fixture.serverPeakPath)
	}
	if got := fixture.client.ActivePath(); got != fixture.clientNormalPath {
		t.Fatalf("peer acceptance borrowed or changed client sender path=%d want normal=%d", got, fixture.clientNormalPath)
	}
}

func TestPeakTransferControllerOwnsBothSenderDirectionsIndependently(t *testing.T) {
	peak := PeakTransfer{
		SaturationFor: time.Nanosecond,
		ReturnFor:     time.Nanosecond,
	}
	localPeak := peak
	localPeak.Targets = []string{"client-peak"}
	peerPeak := peak
	peerPeak.Targets = []string{"server-peak"}
	fixture := newPeakDirectionalFixture(t,
		Selector("client-root", []Target{
			Path("client-normal", PathSpec{}),
			Path("client-peak", PathSpec{}),
		}, localPeak),
		Selector("server-root", []Target{
			Path("server-normal", PathSpec{}),
			Path("server-peak", PathSpec{}),
		}, peerPeak),
	)

	promote := func(rx bool, now time.Time) {
		state := &fixture.controller.tx
		if rx {
			state = &fixture.controller.rx
		}
		state.normalBytes = defaultPeakMinBytes
		state.normalPeakBps = 100
		state.saturatedSince = now.Add(-time.Millisecond)
		fixture.controller.evaluate(now, defaultPeakMinSampleBytes, 100, rx)
		if !state.onPeak {
			t.Fatalf("rx=%t did not promote its sender direction: %+v", rx, state)
		}
	}
	returnToNormal := func(rx bool, now time.Time) {
		state := &fixture.controller.tx
		if rx {
			state = &fixture.controller.rx
		}
		state.returnSince = now.Add(-time.Millisecond)
		fixture.controller.evaluate(now, 0, 0, rx)
		if state.onPeak {
			t.Fatalf("rx=%t did not return its sender direction: %+v", rx, state)
		}
	}

	now := time.Now()
	promote(false, now)
	if got := fixture.client.ActivePath(); got != fixture.clientPeakPath {
		t.Fatalf("write demand selected client path %d, want peak %d", got, fixture.clientPeakPath)
	}
	if got := fixture.server.ActivePath(); got != fixture.serverNormalPath {
		t.Fatalf("write demand changed peer sender path to %d, want normal %d", got, fixture.serverNormalPath)
	}

	promote(true, now.Add(time.Millisecond))
	if got := fixture.server.ActivePath(); got != fixture.serverPeakPath {
		t.Fatalf("read demand selected peer path %d, want peak %d", got, fixture.serverPeakPath)
	}
	if got := fixture.client.ActivePath(); got != fixture.clientPeakPath {
		t.Fatalf("read demand disturbed local sender path: got %d want %d", got, fixture.clientPeakPath)
	}

	returnToNormal(false, now.Add(2*time.Millisecond))
	if got := fixture.client.ActivePath(); got != fixture.clientNormalPath {
		t.Fatalf("write demand return selected client path %d, want normal %d", got, fixture.clientNormalPath)
	}
	if got := fixture.server.ActivePath(); got != fixture.serverPeakPath {
		t.Fatalf("write demand return disturbed peer sender path: got %d want %d", got, fixture.serverPeakPath)
	}

	returnToNormal(true, now.Add(3*time.Millisecond))
	if got := fixture.server.ActivePath(); got != fixture.serverNormalPath {
		t.Fatalf("read demand return selected peer path %d, want normal %d", got, fixture.serverNormalPath)
	}
}

func TestPeerClassSelectionReturnsSenderResolvedTarget(t *testing.T) {
	fixture := newPeakDirectionalFixture(t,
		Selector("client-class-root", []Target{
			Path("client-class-normal", PathSpec{}),
			Path("client-class-peak", PathSpec{}),
		}, PeakTransfer{Targets: []string{"client-class-peak"}}),
		Selector("server-class-root", []Target{
			Path("server-class-normal", PathSpec{}),
			Path("server-class-peak", PathSpec{}),
		}, PeakTransfer{Targets: []string{"server-class-peak"}}),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resolved, _, err := fixture.client.RequestPeerSelectionClass(ctx, fixture.peerSelector, true, "class-e2e")
	if err != nil {
		t.Fatal(err)
	}
	if resolved != fixture.peerPeak || fixture.server.ActivePath() != fixture.serverPeakPath {
		t.Fatalf("resolved/active=%x/%d want peer peak %x/%d", resolved, fixture.server.ActivePath(), fixture.peerPeak, fixture.serverPeakPath)
	}
	resolved, _, err = fixture.client.RequestPeerSelectionClass(ctx, fixture.peerSelector, false, "class-e2e-return")
	if err != nil {
		t.Fatal(err)
	}
	if resolved != fixture.peerNormal || fixture.server.ActivePath() != fixture.serverNormalPath {
		t.Fatalf("resolved/active=%x/%d want peer normal %x/%d", resolved, fixture.server.ActivePath(), fixture.peerNormal, fixture.serverNormalPath)
	}
}

func TestPeakTransferAutomaticRXUsesPeerOwnedPeakRanking(t *testing.T) {
	for _, test := range []struct {
		name       string
		invalidate func(*testing.T, *peakDirectionalFixture, proto.TargetID)
	}{
		{
			name: "stale first candidate",
			invalidate: func(t *testing.T, fixture *peakDirectionalFixture, targetID proto.TargetID) {
				t.Helper()
				fixture.serverPaths[targetID].setQuality(transport.PathQuality{
					RTT: time.Millisecond, At: time.Now().Add(-time.Hour),
				})
			},
		},
		{
			name: "unavailable first candidate",
			invalidate: func(t *testing.T, fixture *peakDirectionalFixture, targetID proto.TargetID) {
				t.Helper()
				if err := fixture.server.RemovePath(fixture.serverPathIDs[targetID]); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPeakDirectionalFixture(t,
				Selector("client-root", []Target{
					Path("client-normal", PathSpec{}),
					Path("client-peak-1", PathSpec{}),
					Path("client-peak-2", PathSpec{}),
				}, PeakTransfer{Targets: []string{"client-peak-1", "client-peak-2"}, SaturationFor: time.Nanosecond}),
				Selector("server-root", []Target{
					Path("server-normal", PathSpec{}),
					Path("server-peak-1", PathSpec{}),
					Path("server-peak-2", PathSpec{}),
				}, PeakTransfer{Targets: []string{"server-peak-1", "server-peak-2"}, SaturationFor: time.Nanosecond}),
			)
			peaks := fixture.controller.peerTargets.peakTargetIDs
			if len(peaks) != 2 {
				t.Fatalf("peer peak candidates=%x want two", peaks)
			}
			first, second := peaks[0], peaks[1]
			fixture.serverPaths[second].setQuality(transport.PathQuality{RTT: 2 * time.Millisecond, At: time.Now()})
			test.invalidate(t, fixture, first)

			ranked, err := fixture.server.RankLocalSelectorClass(fixture.peerSelector, true)
			if err != nil {
				t.Fatal(err)
			}
			if len(ranked) == 0 || ranked[0] != second {
				t.Fatalf("peer-owned peak ranking=%x want healthy second candidate %x", ranked, second)
			}

			now := time.Now()
			fixture.controller.rx.normalBytes = defaultPeakMinBytes
			fixture.controller.rx.normalPeakBps = 100
			fixture.controller.rx.saturatedSince = now.Add(-time.Second)
			fixture.controller.evaluate(now, defaultPeakMinSampleBytes, 100, true)
			if !fixture.controller.rx.onPeak || fixture.controller.rx.activePeakTarget != second {
				t.Fatalf("automatic RX state=%+v want peer-resolved target %x", fixture.controller.rx, second)
			}
			if got, want := fixture.server.ActivePath(), fixture.serverPathIDs[second]; got != want {
				t.Fatalf("peer sender active path=%d want healthy second candidate path=%d", got, want)
			}
		})
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
	if err := fixture.controller.applyPolicy(true, peakTransferPeak, "valid-peer-role"); err != nil {
		t.Fatalf("valid peer peak request: %v", err)
	}
	if got := fixture.server.ActivePath(); got != fixture.serverPeakPath {
		t.Fatalf("valid peer peak request selected path %d, want %d", got, fixture.serverPeakPath)
	}
}

func TestPeakTransferPolicyFailureDoesNotDivergeControllerState(t *testing.T) {
	fixture := newPeakDirectionalFixture(t,
		Selector("client-root", []Target{
			Path("client-normal", PathSpec{}), Path("client-peak", PathSpec{}),
		}, PeakTransfer{Targets: []string{"client-peak"}}),
		Selector("server-root", []Target{
			Path("server-normal", PathSpec{}), Path("server-peak", PathSpec{}),
		}, PeakTransfer{Targets: []string{"server-peak"}}),
	)
	now := time.Now()
	for _, test := range []struct {
		name        string
		operation   string
		applyErr    error
		wantOnPeak  bool
		wantUnknown bool
		wantRetry   bool
	}{
		{name: "promote rejected", operation: "promote", applyErr: engine.ErrPolicyRejected, wantRetry: true},
		{name: "promote outcome unknown", operation: "promote", applyErr: engine.ErrPolicyOutcomeUnknown, wantUnknown: true, wantRetry: true},
		{name: "return rejected", operation: "return", applyErr: engine.ErrPolicyRejected, wantOnPeak: true, wantRetry: true},
		{name: "return outcome unknown", operation: "return", applyErr: engine.ErrPolicyOutcomeUnknown, wantOnPeak: true, wantUnknown: true, wantRetry: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			controller := fixture.controller
			controller.tx = peakTransferDirection{}
			controller.policyApplyForTest = func(bool, peakTransferChoice, proto.TargetID, string) error {
				return test.applyErr
			}
			if test.operation == "promote" {
				controller.tx.normalBytes = defaultPeakMinBytes
				controller.tx.normalPeakBps = 100
				controller.tx.saturatedSince = now.Add(-time.Second)
				controller.evaluate(now, defaultPeakMinSampleBytes, 100, false)
			} else {
				controller.tx.onPeak = true
				controller.tx.activePeakTarget = fixture.localPeak
				controller.tx.normalPeakBps = 100
				controller.tx.peakStarted = now
				controller.tx.returnSince = now.Add(-time.Second)
				controller.evaluate(now, 0, 0, false)
			}
			if controller.tx.onPeak != test.wantOnPeak || controller.tx.policyOutcomeUncertain != test.wantUnknown {
				t.Fatalf("state on_peak/unknown=%t/%t want %t/%t", controller.tx.onPeak,
					controller.tx.policyOutcomeUncertain, test.wantOnPeak, test.wantUnknown)
			}
			if got := controller.tx.policyRetryAfter.After(now); got != test.wantRetry {
				t.Fatalf("retry scheduled=%t want %t (retry_after=%v)", got, test.wantRetry,
					controller.tx.policyRetryAfter)
			}
			if test.wantUnknown {
				retryAt := controller.tx.policyRetryAfter
				controller.policyApplyForTest = func(bool, peakTransferChoice, proto.TargetID, string) error {
					return nil
				}
				controller.evaluatePassiveWithPending(
					retryAt, 0, 0, 0, defaultPeakWindow, proto.TargetID{}, false, false,
				)
				if controller.tx.policyOutcomeUncertain {
					t.Fatal("outcome-unknown direction did not re-enter reconciliation after its retry deadline")
				}
			}
			if test.operation == "promote" && controller.tx.activePeakTarget != (proto.TargetID{}) {
				t.Fatalf("failed promotion published active target %x", controller.tx.activePeakTarget)
			}
			controller.policyApplyForTest = nil
		})
	}
	t.Run("authoritative normal clears uncertainty", func(t *testing.T) {
		controller := fixture.controller
		controller.tx = peakTransferDirection{
			onPeak:                   true,
			activePeakTarget:         fixture.localPeak,
			policyOutcomeUncertain:   true,
			policyRetryAfter:         now.Add(time.Hour),
			lastPolicyError:          engine.ErrPolicyOutcomeUnknown.Error(),
			actualTarget:             fixture.localPeak,
			actualSelectorGeneration: 1,
		}
		controller.reconcileActualTarget(
			false, controller.localTargets.selectorID,
			controller.localTargets.normalTargetID, 2,
		)
		if controller.tx.onPeak || controller.tx.policyOutcomeUncertain ||
			!controller.tx.policyRetryAfter.IsZero() || controller.tx.lastPolicyError != "" {
			t.Fatalf("authoritative normal did not clear uncertain state: %+v", controller.tx)
		}
	})
}

func TestPeakTransferRetryableReturnUsesObservationBackoff(t *testing.T) {
	fixture := newPeakDirectionalFixture(t,
		Selector("client-root", []Target{
			Path("client-normal", PathSpec{}), Path("client-peak", PathSpec{}),
		}, PeakTransfer{Targets: []string{"client-peak"}}),
		Selector("server-root", []Target{
			Path("server-normal", PathSpec{}), Path("server-peak", PathSpec{}),
		}, PeakTransfer{Targets: []string{"server-peak"}}),
	)
	controller := fixture.controller
	controller.policyApplyForTest = func(bool, peakTransferChoice, proto.TargetID, string) error {
		return engine.ErrSelectorDecisionUnavailable
	}
	t.Cleanup(func() { controller.policyApplyForTest = nil })

	for _, test := range []struct {
		name   string
		bytes  uint64
		demand uint64
		bps    float64
	}{
		{name: "failed capacity verification", bytes: defaultPeakMinSampleBytes, demand: defaultPeakMinSampleBytes, bps: 1},
		{name: "idle demand return"},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Now()
			controller.tx = peakTransferDirection{
				onPeak:           true,
				activePeakTarget: fixture.localPeak,
				normalPeakBps:    100,
				peakStarted:      now.Add(-time.Second),
				returnSince:      now.Add(-time.Second),
			}
			controller.evaluatePassive(
				now, test.bytes, test.demand, test.bps,
				defaultPeakWindow, fixture.localPeak, false,
			)
			after := time.Now()
			retryAfter := controller.tx.policyRetryAfter
			if !retryAfter.After(after) || retryAfter.After(after.Add(2*defaultPeakWindow)) {
				t.Fatalf("retry deadline=%v after=%v, want short observation backoff", retryAfter, after)
			}
			if controller.tx.lastPolicyError != engine.ErrSelectorDecisionUnavailable.Error() {
				t.Fatalf("last policy error=%q want selector decision unavailable", controller.tx.lastPolicyError)
			}
		})
	}
}

func TestPeakTransferSlowCandidateSuppressesOnlyThatCandidate(t *testing.T) {
	fixture := newPeakDirectionalFixture(t,
		Selector("client-root", []Target{
			Path("client-normal", PathSpec{}),
			Path("client-peak-1", PathSpec{}),
			Path("client-peak-2", PathSpec{}),
		}, PeakTransfer{Targets: []string{"client-peak-1", "client-peak-2"}}),
		Selector("server-root", []Target{
			Path("server-normal", PathSpec{}),
			Path("server-peak-1", PathSpec{}),
			Path("server-peak-2", PathSpec{}),
		}, PeakTransfer{Targets: []string{"server-peak-1", "server-peak-2"}}),
	)
	peaks := fixture.controller.localTargets.peakTargetIDs
	if len(peaks) != 2 {
		t.Fatalf("peak targets=%x want two", peaks)
	}
	now := time.Now()
	fixture.controller.tx = peakTransferDirection{
		onPeak: true, activePeakTarget: peaks[0], normalPeakBps: 100,
		peakStarted: now.Add(-defaultPeakWindow),
	}
	fixture.controller.policyApplyForTest = func(_ bool, choice peakTransferChoice, _ proto.TargetID, _ string) error {
		if choice != peakTransferNormal {
			t.Fatalf("slow candidate requested choice=%v want normal", choice)
		}
		return nil
	}
	fixture.controller.evaluatePassive(now, defaultPeakMinSampleBytes, defaultPeakMinSampleBytes,
		1, defaultPeakWindow, peaks[0], false)
	fixture.controller.policyApplyForTest = nil
	if fixture.controller.tx.onPeak || !fixture.controller.tx.peakTargetSuppressed(peaks[0], now) {
		t.Fatalf("slow first candidate was not returned/suppressed: %+v", fixture.controller.tx)
	}
	if fixture.controller.tx.peakTargetSuppressed(peaks[1], now) {
		t.Fatal("slow first candidate suppressed healthy sibling")
	}
	selected, ok := fixture.controller.selectHealthyPeakTarget(false)
	if !ok || selected != peaks[1] {
		t.Fatalf("next candidate=%x,%t want healthy sibling %x", selected, ok, peaks[1])
	}
}

func TestPeerPeakCommitGenerationRejectsOlderDeliveryCohort(t *testing.T) {
	selectorID := proto.DeriveTargetID(proto.GraphNodeKindSelector, "peer-generation-root")
	normalID := proto.DeriveTargetID(proto.GraphNodeKindPath, "peer-generation-normal")
	peakID := proto.DeriveTargetID(proto.GraphNodeKindPath, "peer-generation-peak")
	controller := &peakTransferController{
		peerTargets: peakTransferTargets{
			selectorID: selectorID, normalTargetID: normalID,
			normalTargetIDs: []proto.TargetID{normalID},
			peakTargetIDs:   []proto.TargetID{peakID},
		},
		rx: peakTransferDirection{
			onPeak: true, activePeakTarget: peakID,
			actualTarget: normalID, actualSelectorGeneration: 2,
		},
	}

	controller.mu.Lock()
	notePeerPolicyCommitLocked(&controller.rx, peakID, 3)
	controller.mu.Unlock()
	controller.reconcileActualTarget(true, selectorID, normalID, 2)
	controller.reconcileActualTarget(true, selectorID, normalID, 3)
	controller.evaluatePassive(
		time.Now(), defaultPeakMinSampleBytes, defaultPeakMinSampleBytes,
		1, defaultPeakWindow, normalID, true,
	)

	controller.mu.Lock()
	defer controller.mu.Unlock()
	if !controller.rx.onPeak || controller.rx.activePeakTarget != peakID ||
		controller.rx.actualTarget != peakID || controller.rx.actualSelectorGeneration != 3 {
		t.Fatalf("older normal cohort overrode committed peer peak generation: %+v", controller.rx)
	}
}

func TestPeakPolicyObserverRejectsStaleAndUnversionedCallbacks(t *testing.T) {
	selectorID := proto.DeriveTargetID(proto.GraphNodeKindSelector, "observer-generation-root")
	normalID := proto.DeriveTargetID(proto.GraphNodeKindPath, "observer-generation-normal")
	peakID := proto.DeriveTargetID(proto.GraphNodeKindPath, "observer-generation-peak")
	targets := peakTransferTargets{
		selectorID: selectorID, normalTargetID: normalID,
		normalTargetIDs: []proto.TargetID{normalID},
		peakTargetIDs:   []proto.TargetID{peakID},
	}
	controller := &peakTransferController{
		localTargets: targets,
		tx: peakTransferDirection{
			onPeak: true, activePeakTarget: peakID,
			actualTarget: peakID, actualSelectorGeneration: 3,
		},
	}
	controller.observeCommittedPeakPolicy(selectorID, normalID, 2, false, "peak-return")
	controller.observeCommittedPeakPolicy(selectorID, normalID, 0, false, "peak-return")
	if !controller.tx.onPeak || controller.tx.activePeakTarget != peakID ||
		controller.tx.actualTarget != peakID || controller.tx.actualSelectorGeneration != 3 {
		t.Fatalf("stale/unversioned observer overwrote generation 3: %+v", controller.tx)
	}
	controller.observeCommittedPeakPolicy(selectorID, normalID, 4, false, "peak-return")
	if controller.tx.onPeak || controller.tx.actualTarget != normalID ||
		controller.tx.actualSelectorGeneration != 4 {
		t.Fatalf("newer observer did not publish normal generation 4: %+v", controller.tx)
	}
}

func TestPeakObservationCannotOverwriteNewerCommittedCallback(t *testing.T) {
	selector := proto.DeriveTargetID(proto.GraphNodeKindSelector, "phase-guard-selector")
	normal := proto.DeriveTargetID(proto.GraphNodeKindPath, "phase-guard-normal")
	peakB := proto.DeriveTargetID(proto.GraphNodeKindPath, "phase-guard-peak-b")
	peakC := proto.DeriveTargetID(proto.GraphNodeKindPath, "phase-guard-peak-c")
	controller := &peakTransferController{
		localTargets: peakTransferTargets{
			selectorID: selector, normalTargetID: normal,
			normalTargetIDs: []proto.TargetID{normal},
			peakTargetIDs:   []proto.TargetID{peakB, peakC},
		},
	}
	controller.tx.actualTarget = normal
	controller.tx.actualSelectorGeneration = 1
	controller.policyApplyForTest = func(bool, peakTransferChoice, proto.TargetID, string) error {
		controller.observeCommittedPeakPolicy(selector, peakC, 3, true, "newer-factual-commit")
		return nil
	}

	selected, intentPhase, err := controller.beginPeakObservation(false, nil, "older-peak-intent")
	if err != nil {
		t.Fatal(err)
	}
	if selected != peakB {
		t.Fatalf("older policy selected=%x want=%x", selected, peakB)
	}
	controller.mu.Lock()
	state := controller.tx
	controller.mu.Unlock()
	if state.phaseGeneration == intentPhase || !state.onPeak || state.activePeakTarget != peakC ||
		state.actualTarget != peakC || state.actualSelectorGeneration != 3 {
		t.Fatalf("older promotion overwrote newer callback: intent_phase=%d state=%+v", intentPhase, state)
	}
}

func TestPeakOutcomeUnknownCannotOverwriteFactualCommit(t *testing.T) {
	selector := proto.DeriveTargetID(proto.GraphNodeKindSelector, "unknown-guard-selector")
	normal := proto.DeriveTargetID(proto.GraphNodeKindPath, "unknown-guard-normal")
	peak := proto.DeriveTargetID(proto.GraphNodeKindPath, "unknown-guard-peak")
	controller := &peakTransferController{
		opts: PeakTransfer{SaturationFor: time.Millisecond, SaturationRatio: 0.5},
		localTargets: peakTransferTargets{
			selectorID: selector, normalTargetID: normal,
			normalTargetIDs: []proto.TargetID{normal},
			peakTargetIDs:   []proto.TargetID{peak},
		},
	}
	now := time.Now()
	controller.tx.actualTarget = normal
	controller.tx.actualSelectorGeneration = 1
	controller.tx.normalPeakBps = 8 << 20
	controller.tx.normalBytes = defaultPeakMinBytes
	controller.tx.saturatedSince = now.Add(-time.Second)
	controller.policyApplyForTest = func(bool, peakTransferChoice, proto.TargetID, string) error {
		controller.observeCommittedPeakPolicy(selector, peak, 2, true, "committed-before-replay-error")
		return engine.ErrPolicyOutcomeUnknown
	}

	controller.evaluatePassiveWithPending(
		now, defaultPeakMinSampleBytes, defaultPeakMinSampleBytes,
		8<<20, defaultPeakWindow, normal, false, false,
	)
	controller.mu.Lock()
	state := controller.tx
	controller.mu.Unlock()
	if !state.onPeak || state.activePeakTarget != peak || state.actualTarget != peak ||
		state.actualSelectorGeneration != 2 || state.policyOutcomeUncertain || state.lastPolicyError != "" {
		t.Fatalf("post-commit error overwrote factual callback: %+v", state)
	}
}

func TestPeakReturnCannotResetNewerCommittedCallback(t *testing.T) {
	selector := proto.DeriveTargetID(proto.GraphNodeKindSelector, "return-guard-selector")
	normal := proto.DeriveTargetID(proto.GraphNodeKindPath, "return-guard-normal")
	peakB := proto.DeriveTargetID(proto.GraphNodeKindPath, "return-guard-peak-b")
	peakC := proto.DeriveTargetID(proto.GraphNodeKindPath, "return-guard-peak-c")
	controller := &peakTransferController{
		localTargets: peakTransferTargets{
			selectorID: selector, normalTargetID: normal,
			normalTargetIDs: []proto.TargetID{normal},
			peakTargetIDs:   []proto.TargetID{peakB, peakC},
		},
	}
	now := time.Now()
	controller.tx.onPeak = true
	controller.tx.activePeakTarget = peakB
	controller.tx.actualTarget = peakB
	controller.tx.actualSelectorGeneration = 2
	controller.tx.normalPeakBps = 8 << 20
	controller.tx.returnSince = now.Add(-time.Second)
	controller.policyApplyForTest = func(bool, peakTransferChoice, proto.TargetID, string) error {
		controller.observeCommittedPeakPolicy(selector, peakC, 3, true, "newer-factual-commit")
		return nil
	}

	controller.evaluatePassiveWithPending(
		now, 1, 0, 1, defaultPeakWindow, peakB, false, false,
	)
	controller.mu.Lock()
	state := controller.tx
	controller.mu.Unlock()
	if !state.onPeak || state.activePeakTarget != peakC || state.actualTarget != peakC ||
		state.actualSelectorGeneration != 3 {
		t.Fatalf("older return reset newer callback: %+v", state)
	}
}

func TestPeakRXZeroProgressCannotStartIdleReturn(t *testing.T) {
	selector := proto.DeriveTargetID(proto.GraphNodeKindSelector, "rx-zero-selector")
	normal := proto.DeriveTargetID(proto.GraphNodeKindPath, "rx-zero-normal")
	peak := proto.DeriveTargetID(proto.GraphNodeKindPath, "rx-zero-peak")
	controller := &peakTransferController{
		peerTargets: peakTransferTargets{
			selectorID: selector, normalTargetID: normal,
			normalTargetIDs: []proto.TargetID{normal},
			peakTargetIDs:   []proto.TargetID{peak},
		},
	}
	controller.rx.onPeak = true
	controller.rx.activePeakTarget = peak
	controller.rx.actualTarget = peak
	controller.rx.actualSelectorGeneration = 2
	controller.rx.normalPeakBps = 8 << 20
	var transitions int
	controller.policyApplyForTest = func(rx bool, choice peakTransferChoice, targetID proto.TargetID, cause string) error {
		if !rx || choice != peakTransferNormal || targetID != normal || cause != "peak-return" {
			t.Fatalf("unexpected policy transition rx=%t choice=%d target=%x cause=%q", rx, choice, targetID, cause)
		}
		transitions++
		return nil
	}

	now := time.Now()
	controller.evaluatePassiveWithPending(now, 0, 0, 0, defaultPeakWindow, peak, false, true)
	controller.evaluatePassiveWithPending(now.Add(2*time.Second), 0, 0, 0, defaultPeakWindow, peak, false, true)
	controller.mu.Lock()
	returnSince := controller.rx.returnSince
	onPeak := controller.rx.onPeak
	controller.mu.Unlock()
	if transitions != 0 || !onPeak || !returnSince.IsZero() {
		t.Fatalf("RX zero progress started idle return: transitions=%d on_peak=%t return_since=%s", transitions, onPeak, returnSince)
	}

	lowDemandAt := now.Add(3 * time.Second)
	controller.evaluatePassiveWithPending(lowDemandAt, 1, 0, 1, defaultPeakWindow, peak, false, true)
	controller.evaluatePassiveWithPending(lowDemandAt.Add(time.Second), 0, 0, 0, defaultPeakWindow, peak, false, true)
	controller.mu.Lock()
	onPeak = controller.rx.onPeak
	controller.mu.Unlock()
	if transitions != 1 || onPeak {
		t.Fatalf("delivered low demand did not permit RX return: transitions=%d on_peak=%t", transitions, onPeak)
	}
}
