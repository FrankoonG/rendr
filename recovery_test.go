package rendr

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/transport"
	"github.com/FrankoonG/rendr/transport/tcp"
)

func TestRuntimeAutomaticallyRedialsDeadGenericLeaf(t *testing.T) {
	listener, err := listenRuntimeTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := listener.Accept(ctx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	runtime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	var attempts atomic.Int32
	if err := runtime.RegisterStreamFactory("recover-stream", StreamFactory{
		Carrier: CarrierTCP,
		Dial: func(ctx context.Context, address string) (net.Conn, error) {
			attempt := attempts.Add(1)
			if attempt == 2 || attempt == 3 {
				return nil, &net.DNSError{Err: "injected recovery dial failure", IsTemporary: true}
			}
			var dialer net.Dialer
			return dialer.DialContext(ctx, "tcp", address)
		},
	}); err != nil {
		t.Fatal(err)
	}
	spec := PathSpec{Transport: "recover-stream", Address: listener.Addr().String(), Opts: map[string]string{"name": "b"}}
	clientConn, err := runtime.Dial(context.Background(), SessionConfig{Root: Selector("root", []Target{Path("b", spec)})})
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	var serverConn Conn
	select {
	case serverConn = <-accepted:
	case err := <-acceptErr:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("accept timed out")
	}
	defer serverConn.Close()

	client := clientConn.(*engineBackedConn)
	server := serverConn
	serverObserver := server.(ConnectionObserver)
	deadID := client.Paths()[0].ID
	deadServerID := server.Paths()[0].ID
	if err := client.e.ForceKillPathForTest(deadID); err != nil {
		t.Fatal(err)
	}
	replacement, serverReplacement := waitForStreamReplacement(t, client, server, deadID, deadServerID, 5*time.Second)
	if attempts.Load() < 4 {
		t.Fatalf("recovery did not retry injected dial failures: attempts=%d", attempts.Load())
	}
	assertBidirectionalStreamPayload(t, client, server, "first-replacement")
	assertPathCarriedData(t, client.Paths(), replacement)
	assertPathCarriedData(t, server.Paths(), serverReplacement)
	if err := client.e.ForceKillPathForTest(replacement); err != nil {
		t.Fatal(err)
	}
	second, secondServer := waitForStreamReplacement(t, client, server, replacement, serverReplacement, 5*time.Second)
	if attempts.Load() < 5 {
		t.Fatalf("immediate second death did not redial again: attempts=%d", attempts.Load())
	}
	assertBidirectionalStreamPayload(t, client, server, "second-replacement")
	assertPathCarriedData(t, client.Paths(), second)
	assertPathCarriedData(t, server.Paths(), secondServer)
	waitForMigrationCounts(t, client.MigrationCount, serverObserver.MigrationCount, 2)
}

func TestRecoveryGenerationReconcilesStartupAndInFlightDeath(t *testing.T) {
	e := engine.New(engine.SideClient, engine.NewClientFlowID(), engine.Limits{}.Clamp())
	defer e.Close()
	spec := PathSpec{Transport: "generation-test", Address: "peer", Opts: map[string]string{"name": "leaf"}}
	var attempts atomic.Int32
	var peersMu sync.Mutex
	var peers []net.Conn
	defer func() {
		peersMu.Lock()
		defer peersMu.Unlock()
		for _, peer := range peers {
			_ = peer.Close()
		}
	}()
	add := func(context.Context, PathSpec) (uint32, error) {
		attempt := attempts.Add(1)
		local, peer := net.Pipe()
		peersMu.Lock()
		peers = append(peers, peer)
		peersMu.Unlock()
		id, err := e.AttachPath(tcp.Wrap(local), spec)
		if err != nil {
			_ = local.Close()
			return 0, err
		}
		if attempt == 1 {
			if err := e.ForceKillPathForTest(id); err != nil {
				return 0, err
			}
		}
		return id, nil
	}
	supervisor := newPathRecoverySupervisor(e, nil, add, []PathSpec{spec}, nil, retryPolicy{})
	if supervisor == nil {
		t.Fatal("recovery supervisor was not created")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if attempts.Load() >= 2 && len(e.Paths()) == 1 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("generation reconciliation lost replacement death: attempts=%d paths=%v", attempts.Load(), e.Paths())
}

func TestCleanRemovalCancelsInFlightRecoveryWithoutResurrection(t *testing.T) {
	e := engine.New(engine.SideClient, engine.NewClientFlowID(), engine.Limits{}.Clamp())
	defer e.Close()
	attachPipe := func(spec PathSpec) (uint32, net.Conn) {
		t.Helper()
		local, peer := net.Pipe()
		id, err := e.AttachPath(tcp.Wrap(local), spec)
		if err != nil {
			_ = local.Close()
			_ = peer.Close()
			t.Fatal(err)
		}
		return id, peer
	}
	leaf := PathSpec{Transport: "cancel-test", Address: "peer", Opts: map[string]string{"name": "leaf"}}
	guard := PathSpec{Transport: "cancel-test", Address: "guard", Opts: map[string]string{"name": "guard"}}
	leafID, leafPeer := attachPipe(leaf)
	defer leafPeer.Close()
	_, guardPeer := attachPipe(guard)
	defer guardPeer.Close()

	started := make(chan struct{})
	canceled := make(chan struct{})
	var startedOnce sync.Once
	var canceledOnce sync.Once
	var attempts atomic.Int32
	add := func(ctx context.Context, _ PathSpec) (uint32, error) {
		attempts.Add(1)
		startedOnce.Do(func() { close(started) })
		<-ctx.Done()
		canceledOnce.Do(func() { close(canceled) })
		return 0, ctx.Err()
	}
	if supervisor := newPathRecoverySupervisor(e, nil, add, []PathSpec{leaf}, nil, retryPolicy{}); supervisor == nil {
		t.Fatal("recovery supervisor was not created")
	}
	if err := e.ForceKillPathForTest(leafID); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("recovery attempt did not start")
	}

	manualID, manualPeer := attachPipe(leaf)
	defer manualPeer.Close()
	if err := e.RemovePath(manualID); err != nil {
		t.Fatal(err)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("clean removal did not cancel in-flight recovery")
	}
	time.Sleep(3 * recoveryInitialBackoff)
	if got := attempts.Load(); got != 1 {
		t.Fatalf("cleanly removed leaf was redialed %d times", got)
	}
	for _, path := range e.Paths() {
		if pathSpecName(path.Spec) == "leaf" {
			t.Fatalf("cleanly removed leaf was resurrected: %v", e.Paths())
		}
	}
}

func TestCleanRemovalTombstoneIgnoresDelayedTransportDeath(t *testing.T) {
	e := engine.New(engine.SideClient, engine.NewClientFlowID(), engine.Limits{}.Clamp())
	defer e.Close()
	attach := func(spec PathSpec) (uint32, net.Conn) {
		local, peer := net.Pipe()
		id, err := e.AttachPath(tcp.Wrap(local), spec)
		if err != nil {
			_ = local.Close()
			_ = peer.Close()
			t.Fatal(err)
		}
		return id, peer
	}
	leaf := PathSpec{Transport: "tombstone-test", Address: "peer", Opts: map[string]string{"name": "leaf"}}
	guard := PathSpec{Transport: "tombstone-test", Address: "guard", Opts: map[string]string{"name": "guard"}}
	leafID, leafPeer := attach(leaf)
	defer leafPeer.Close()
	_, guardPeer := attach(guard)
	defer guardPeer.Close()

	var attempts atomic.Int32
	supervisor := newPathRecoverySupervisor(e, nil, func(context.Context, PathSpec) (uint32, error) {
		attempts.Add(1)
		return 0, errors.New("unexpected redial")
	}, []PathSpec{leaf}, nil, retryPolicy{})
	if supervisor == nil {
		t.Fatal("recovery supervisor was not created")
	}
	if err := e.RemovePath(leafID); err != nil {
		t.Fatal(err)
	}
	waitAbsent := func(spec PathSpec, label string) {
		t.Helper()
		deadline := time.Now().Add(time.Second)
		for recoveryLeafAttached(e.Paths(), spec) && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if recoveryLeafAttached(e.Paths(), spec) {
			t.Fatalf("%s clean event was not consumed: %v", label, e.Paths())
		}
	}
	waitAbsent(leaf, "leaf")
	supervisor.publishDeathForTest(engine.PathDeathEvent{ID: leafID, Spec: leaf.Clone(), Cause: transport.CauseTransportError, Err: errors.New("delayed old generation")})
	if active := supervisor.activeWorkersForTest(); active != 0 {
		t.Fatalf("delayed transport death started %d recovery worker(s)", active)
	}
	if got := attempts.Load(); got != 0 {
		t.Fatalf("delayed transport death resurrected clean leaf: attempts=%d", got)
	}
}

func TestRecoveryRemoveThenAddSameLeafIgnoresOldGenerationDeath(t *testing.T) {
	e := engine.New(engine.SideClient, engine.NewClientFlowID(), engine.Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	var peersMu sync.Mutex
	var peers []net.Conn
	attachPath := func(spec PathSpec) (uint32, error) {
		local, peer := net.Pipe()
		id, err := e.AttachPath(tcp.Wrap(local), spec)
		if err != nil {
			_ = local.Close()
			_ = peer.Close()
			return 0, err
		}
		peersMu.Lock()
		peers = append(peers, peer)
		peersMu.Unlock()
		return id, nil
	}
	attach := func(spec PathSpec) uint32 {
		t.Helper()
		id, err := attachPath(spec)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	t.Cleanup(func() {
		peersMu.Lock()
		defer peersMu.Unlock()
		for _, peer := range peers {
			_ = peer.Close()
		}
	})

	leaf := PathSpec{Transport: "generation-order-test", Address: "leaf", Opts: map[string]string{"name": "leaf"}}
	guard := PathSpec{Transport: "generation-order-test", Address: "guard", Opts: map[string]string{"name": "guard"}}
	oldID := attach(leaf)
	attach(guard)
	oldRef, ok := e.PathRef(oldID)
	if !ok {
		t.Fatal("old path reference unavailable")
	}
	recovered := make(chan uint32, 1)
	var attempts atomic.Int32
	supervisor := newPathRecoverySupervisor(e, nil, func(context.Context, PathSpec) (uint32, error) {
		attempts.Add(1)
		id, err := attachPath(leaf)
		if err == nil {
			recovered <- id
		}
		return id, err
	}, []PathSpec{leaf}, nil, retryPolicy{})
	if supervisor == nil {
		t.Fatal("recovery supervisor was not created")
	}
	if err := e.RemovePath(oldID); err != nil {
		t.Fatal(err)
	}
	newID := attach(leaf)
	supervisor.pathAdded(leaf, newID)
	supervisor.publishDeathForTest(engine.PathDeathEvent{
		ID: oldRef.ID, Owner: oldRef.Owner, Spec: leaf.Clone(),
		Cause: transport.CauseTransportError, Err: errors.New("delayed old generation death"),
	})
	supervisor.publishDeathForTest(engine.PathDeathEvent{
		ID: oldRef.ID, Owner: oldRef.Owner, Spec: leaf.Clone(),
		Cause: transport.CauseCleanClose, Administrative: true,
	})
	if active := supervisor.activeWorkersForTest(); active != 0 || attempts.Load() != 0 {
		t.Fatalf("old generation death started recovery: active=%d attempts=%d", active, attempts.Load())
	}
	if ref, ok := e.PathRef(newID); !ok || ref.ID != newID {
		t.Fatalf("old generation death removed manual replacement %d: paths=%v", newID, e.Paths())
	}

	if err := e.ForceKillPathForTest(newID); err != nil {
		t.Fatal(err)
	}
	select {
	case replacementID := <-recovered:
		if replacementID == newID {
			t.Fatalf("recovery reused dead path ID %d", newID)
		}
	case <-time.After(time.Second):
		t.Fatal("new generation death did not trigger recovery")
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("new generation recovery attempts=%d, want 1", got)
	}
}

func TestCanceledRecoveryDoesNotClaimConcurrentManualPath(t *testing.T) {
	e := engine.New(engine.SideClient, engine.NewClientFlowID(), engine.Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })

	attach := func(spec PathSpec) (uint32, net.Conn) {
		t.Helper()
		local, peer := net.Pipe()
		id, err := e.AttachPath(tcp.Wrap(local), spec)
		if err != nil {
			_ = local.Close()
			_ = peer.Close()
			t.Fatal(err)
		}
		return id, peer
	}

	guard := PathSpec{Transport: "canceled-owner-test", Address: "guard", Opts: map[string]string{"name": "guard"}}
	_, guardPeer := attach(guard)
	t.Cleanup(func() { _ = guardPeer.Close() })
	leaf := PathSpec{Transport: "canceled-owner-test", Address: "leaf", Opts: map[string]string{"name": "leaf"}}

	started := make(chan struct{})
	release := make(chan struct{})
	returned := make(chan struct{})
	var startOnce sync.Once
	var returnOnce sync.Once
	add := func(ctx context.Context, _ PathSpec) (uint32, error) {
		startOnce.Do(func() { close(started) })
		<-ctx.Done()
		<-release
		returnOnce.Do(func() { close(returned) })
		return 0, ctx.Err()
	}
	tracker := newPathStatusTracker([]PathSpec{leaf}, "")
	supervisor := newPathRecoverySupervisor(e, nil, add, []PathSpec{leaf}, tracker, retryPolicy{})
	if supervisor == nil {
		t.Fatal("recovery supervisor was not created")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("recovery attempt did not start")
	}

	manualID, manualPeer := attach(leaf)
	t.Cleanup(func() { _ = manualPeer.Close() })
	supervisor.pathAdded(leaf, manualID)
	close(release)
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("canceled recovery dial did not return")
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		active := supervisor.activeWorkersForTest()
		_, attached := e.PathRef(manualID)
		if active == 0 || !attached {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if ref, ok := e.PathRef(manualID); !ok || ref.ID != manualID {
		t.Fatalf("stale recovery completion retired concurrent manual path %d: paths=%v", manualID, e.Paths())
	}
	if active := supervisor.activeWorkersForTest(); active != 0 {
		t.Fatalf("canceled recovery completion did not drain: active=%d", active)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-supervisor.done:
	case <-time.After(time.Second):
		t.Fatal("recovery supervisor did not quiesce after engine close")
	}
}

func TestDelayedAddNotificationCannotUndoCleanRemoval(t *testing.T) {
	e := engine.New(engine.SideClient, engine.NewClientFlowID(), engine.Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	attach := func(spec PathSpec) (uint32, net.Conn) {
		t.Helper()
		local, peer := net.Pipe()
		id, err := e.AttachPath(tcp.Wrap(local), spec)
		if err != nil {
			_ = local.Close()
			_ = peer.Close()
			t.Fatal(err)
		}
		return id, peer
	}
	leaf := PathSpec{Transport: "delayed-add-test", Address: "leaf", Opts: map[string]string{"name": "leaf"}}
	guard := PathSpec{Transport: "delayed-add-test", Address: "guard", Opts: map[string]string{"name": "guard"}}
	leafID, leafPeer := attach(leaf)
	t.Cleanup(func() { _ = leafPeer.Close() })
	_, guardPeer := attach(guard)
	t.Cleanup(func() { _ = guardPeer.Close() })

	var attempts atomic.Int32
	supervisor := newPathRecoverySupervisor(e, nil, func(context.Context, PathSpec) (uint32, error) {
		attempts.Add(1)
		return 0, errors.New("unexpected recovery")
	}, []PathSpec{leaf}, nil, retryPolicy{})
	if supervisor == nil {
		t.Fatal("recovery supervisor was not created")
	}
	ref, ok := e.PathRef(leafID)
	if !ok {
		t.Fatal("leaf ref unavailable before delayed notification")
	}
	if err := e.RemovePath(leafID); err != nil {
		t.Fatal(err)
	}
	// Model AddPath's notification being delayed until after the exact
	// generation was administratively removed.
	supervisor.pathAddedRef(leaf, leafID, ref)
	if active := supervisor.activeWorkersForTest(); active != 0 || attempts.Load() != 0 {
		t.Fatalf("delayed add notification resurrected clean leaf: active=%d attempts=%d", active, attempts.Load())
	}
}

func TestRecoveryStopCancelsWorkerWithoutRestart(t *testing.T) {
	e := engine.New(engine.SideClient, engine.NewClientFlowID(), engine.Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	spec := PathSpec{Transport: "stop-test", Address: "leaf", Opts: map[string]string{"name": "leaf"}}
	started := make(chan struct{})
	var once sync.Once
	var attempts atomic.Int32
	supervisor := newPathRecoverySupervisor(e, nil, func(ctx context.Context, _ PathSpec) (uint32, error) {
		attempts.Add(1)
		once.Do(func() { close(started) })
		<-ctx.Done()
		return 0, ctx.Err()
	}, []PathSpec{spec}, nil, retryPolicy{})
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("recovery worker did not start")
	}
	supervisor.stop()
	select {
	case <-supervisor.done:
	case <-time.After(time.Second):
		t.Fatal("stopped recovery supervisor did not quiesce")
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("recovery restarted after stop: attempts=%d", got)
	}
}

func TestRecoveryStatusUpdatesAreActorValidated(t *testing.T) {
	e := engine.New(engine.SideClient, engine.NewClientFlowID(), engine.Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	spec := PathSpec{Transport: "status-test", Address: "leaf", Opts: map[string]string{"name": "leaf"}}
	tracker := newPathStatusTracker([]PathSpec{spec}, "")
	supervisor := newPathRecoverySupervisor(e, nil, func(context.Context, PathSpec) (uint32, error) {
		return 0, errors.New("injected dial failure")
	}, []PathSpec{spec}, tracker, retryPolicy{MinBackoff: time.Second, MaxBackoff: time.Second})
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		status := tracker.snapshot(nil)
		if len(status) == 1 && status[0].State == PathPending && strings.Contains(status[0].LastError, "injected dial failure") {
			supervisor.stop()
			return
		}
		time.Sleep(time.Millisecond)
	}
	supervisor.stop()
	t.Fatalf("recovery failure was not published through actor: %+v", tracker.snapshot(nil))
}

func TestRecoveryLeafPathRefChoosesNewestOwner(t *testing.T) {
	e := engine.New(engine.SideClient, engine.NewClientFlowID(), engine.Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	spec := PathSpec{Transport: "owner-test", Address: "leaf", Opts: map[string]string{"name": "leaf"}}
	attach := func() (uint32, net.Conn) {
		local, peer := net.Pipe()
		id, err := e.AttachPath(tcp.Wrap(local), spec)
		if err != nil {
			t.Fatal(err)
		}
		return id, peer
	}
	firstID, firstPeer := attach()
	t.Cleanup(func() { _ = firstPeer.Close() })
	secondID, secondPeer := attach()
	t.Cleanup(func() { _ = secondPeer.Close() })
	first, _ := e.PathRef(firstID)
	second, _ := e.PathRef(secondID)
	latest, ok := recoveryLeafPathRef(e, spec)
	if !ok || latest != second || latest.Owner <= first.Owner {
		t.Fatalf("latest leaf ref=%+v ok=%t, owners first=%+v second=%+v", latest, ok, first, second)
	}
}

func TestCleanRemovalRetiresLateSuccessfulRecoveryAttach(t *testing.T) {
	e := engine.New(engine.SideClient, engine.NewClientFlowID(), engine.Limits{}.Clamp())
	defer e.Close()
	guard := PathSpec{Transport: "late-attach-test", Address: "guard", Opts: map[string]string{"name": "guard"}}
	guardLocal, guardPeer := net.Pipe()
	defer guardPeer.Close()
	if _, err := e.AttachPath(tcp.Wrap(guardLocal), guard); err != nil {
		t.Fatal(err)
	}
	leaf := PathSpec{Transport: "late-attach-test", Address: "peer", Opts: map[string]string{"name": "leaf"}}
	started := make(chan struct{})
	release := make(chan struct{})
	attached := make(chan uint32, 1)
	var startOnce sync.Once
	var latePeer net.Conn
	var latePeerMu sync.Mutex
	defer func() {
		latePeerMu.Lock()
		defer latePeerMu.Unlock()
		if latePeer != nil {
			_ = latePeer.Close()
		}
	}()
	add := func(context.Context, PathSpec) (uint32, error) {
		startOnce.Do(func() { close(started) })
		<-release // Deliberately model a factory that commits after cancellation.
		local, peer := net.Pipe()
		latePeerMu.Lock()
		latePeer = peer
		latePeerMu.Unlock()
		id, err := e.AttachPath(tcp.Wrap(local), leaf)
		if err == nil {
			attached <- id
		}
		return id, err
	}
	tracker := newPathStatusTracker([]PathSpec{leaf}, "")
	supervisor := newPathRecoverySupervisor(e, nil, add, []PathSpec{leaf}, tracker, retryPolicy{})
	if supervisor == nil {
		t.Fatal("recovery supervisor was not created")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("recovery attempt did not start")
	}
	manualLocal, manualPeer := net.Pipe()
	defer manualPeer.Close()
	manualID, err := e.AttachPath(tcp.Wrap(manualLocal), leaf)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.RemovePath(manualID); err != nil {
		t.Fatal(err)
	}
	close(release)
	var lateID uint32
	select {
	case lateID = <-attached:
	case <-time.After(time.Second):
		t.Fatal("late recovery did not attach")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !recoveryLeafAttached(e.Paths(), leaf) && supervisor.activeWorkersForTest() == 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if recoveryLeafAttached(e.Paths(), leaf) || supervisor.activeWorkersForTest() != 0 {
		t.Fatalf("late successful recovery attach %d survived clean tombstone: %v", lateID, e.Paths())
	}
	if !recoveryLeafAttached(e.Paths(), guard) || e.IsClosed() {
		t.Fatalf("late cleanup damaged guard/session: paths=%v closed=%t", e.Paths(), e.IsClosed())
	}
	statuses := tracker.snapshot(e.Paths())
	if len(statuses) == 0 || statuses[0].State != PathUnavailable {
		t.Fatalf("stale recovery completion overwrote tombstone status: %+v", statuses)
	}
	latePeerMu.Lock()
	peer := latePeer
	latePeerMu.Unlock()
	if peer == nil {
		t.Fatal("late recovery peer was not recorded")
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("late recovery carrier remained open after exact retirement")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatalf("late recovery carrier was not closed: %v", err)
	}
}

func TestCleanRemovalRetiresLateRecoveryThatBecomesLastPath(t *testing.T) {
	e := engine.New(engine.SideClient, engine.NewClientFlowID(), engine.Limits{}.Clamp())
	defer e.Close()
	attach := func(spec PathSpec) (uint32, net.Conn) {
		t.Helper()
		local, peer := net.Pipe()
		id, err := e.AttachPath(tcp.Wrap(local), spec)
		if err != nil {
			_ = local.Close()
			_ = peer.Close()
			t.Fatal(err)
		}
		return id, peer
	}
	guard := PathSpec{Transport: "last-path-test", Address: "guard", Opts: map[string]string{"name": "guard"}}
	guardID, guardPeer := attach(guard)
	defer guardPeer.Close()
	leaf := PathSpec{Transport: "last-path-test", Address: "leaf", Opts: map[string]string{"name": "leaf"}}

	started := make(chan struct{})
	releaseAttach := make(chan struct{})
	allowReturn := make(chan struct{})
	attached := make(chan uint32, 1)
	var startOnce, releaseOnce, returnOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(releaseAttach) })
		returnOnce.Do(func() { close(allowReturn) })
	})
	var latePeer net.Conn
	var latePeerMu sync.Mutex
	defer func() {
		latePeerMu.Lock()
		defer latePeerMu.Unlock()
		if latePeer != nil {
			_ = latePeer.Close()
		}
	}()
	add := func(context.Context, PathSpec) (uint32, error) {
		startOnce.Do(func() { close(started) })
		<-releaseAttach
		local, peer := net.Pipe()
		latePeerMu.Lock()
		latePeer = peer
		latePeerMu.Unlock()
		id, err := e.AttachPath(tcp.Wrap(local), leaf)
		if err != nil {
			return 0, err
		}
		attached <- id
		<-allowReturn
		return id, nil
	}
	supervisor := newPathRecoverySupervisor(e, nil, add, []PathSpec{leaf}, nil, retryPolicy{})
	if supervisor == nil {
		t.Fatal("recovery supervisor was not created")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("recovery attempt did not start")
	}
	manualID, manualPeer := attach(leaf)
	defer manualPeer.Close()
	if err := e.RemovePath(manualID); err != nil {
		t.Fatal(err)
	}
	releaseOnce.Do(func() { close(releaseAttach) })
	var lateID uint32
	select {
	case lateID = <-attached:
	case <-time.After(time.Second):
		t.Fatal("late recovery did not attach")
	}
	if err := e.RemovePath(guardID); err != nil {
		t.Fatal(err)
	}
	paths := e.Paths()
	if e.IsClosed() || len(paths) != 1 || paths[0].ID != lateID {
		t.Fatalf("pre-completion last-path state closed=%t paths=%v, want late path %d", e.IsClosed(), paths, lateID)
	}
	returnOnce.Do(func() { close(allowReturn) })
	deadline := time.Now().Add(2 * time.Second)
	for (len(e.Paths()) != 0 || supervisor.activeWorkersForTest() != 0) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if paths := e.Paths(); len(paths) != 0 {
		t.Fatalf("paths after tombstoned sole replacement cleanup=%v", paths)
	}
	if active := supervisor.activeWorkersForTest(); active != 0 {
		t.Fatalf("recovery workers after stale last-path retirement=%d", active)
	}
	if state := e.State(); state != engine.BridgeMigrating {
		t.Fatalf("state after stale last-path retirement=%s, want %s", state, engine.BridgeMigrating)
	}
	if e.IsClosed() || errors.Is(e.CloseErr(), io.EOF) {
		t.Fatalf("stale last-path retirement manufactured EOF: closed=%t err=%v", e.IsClosed(), e.CloseErr())
	}
}

func TestCleanPathRemovalDoesNotTriggerAutomaticRedial(t *testing.T) {
	listener, err := listenRuntimeTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan Conn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, acceptErr := listener.Accept(ctx)
		if acceptErr == nil {
			accepted <- conn
		}
	}()
	runtime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	var attempts atomic.Int32
	if err := runtime.RegisterStreamFactory("clean-stream", StreamFactory{
		Carrier: CarrierTCP,
		Dial: func(ctx context.Context, address string) (net.Conn, error) {
			attempts.Add(1)
			var dialer net.Dialer
			return dialer.DialContext(ctx, "tcp", address)
		},
	}); err != nil {
		t.Fatal(err)
	}
	spec := func(name string) PathSpec {
		return PathSpec{Transport: "clean-stream", Address: listener.Addr().String(), Opts: map[string]string{"name": name}}
	}
	conn, err := runtime.Dial(context.Background(), SessionConfig{Root: Selector("root", []Target{
		Path("a", spec("a")), Path("b", spec("b")),
	})})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	server := <-accepted
	defer server.Close()
	if !waitForNPaths(t, conn, server, "clean-stream", listener.Addr().String(), 2, 5*time.Second) {
		t.Fatal("initial paths did not attach")
	}
	client := conn.(*engineBackedConn)
	var removeID uint32
	for _, path := range client.Paths() {
		if !path.Active {
			removeID = path.ID
			break
		}
	}
	if removeID == 0 {
		t.Fatal("no removable secondary path")
	}
	attemptsBeforeRemoval := attempts.Load()
	if err := client.RemovePath(removeID); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	if got := attempts.Load(); got != attemptsBeforeRemoval {
		t.Fatalf("clean removal triggered redial: attempts before=%d after=%d", attemptsBeforeRemoval, got)
	}
	if got := len(client.Paths()); got != 1 {
		t.Fatalf("cleanly removed path reappeared: %v", client.Paths())
	}
}

func TestRuntimeAutomaticallyRedialsDeadGenericPacketLeaf(t *testing.T) {
	listener, err := listenRuntimeUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan PacketConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := listener.AcceptPacket(ctx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	runtime, err := NewRuntime(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	var attempts atomic.Int32
	if err := runtime.RegisterPacketFactory("recover-packet", PacketFactory{
		Carrier: CarrierUDP,
		Dial: func(context.Context, string) (net.PacketConn, error) {
			attempt := attempts.Add(1)
			if attempt == 2 || attempt == 3 {
				return nil, &net.DNSError{Err: "injected packet recovery dial failure", IsTemporary: true}
			}
			return net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		},
	}); err != nil {
		t.Fatal(err)
	}
	spec := PathSpec{Transport: "recover-packet", Address: listener.Addr().String(), Opts: map[string]string{"name": "b"}}
	clientConn, err := runtime.DialPacket(context.Background(), SessionConfig{Root: Selector("root", []Target{Path("b", spec)})})
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	var serverConn PacketConn
	select {
	case serverConn = <-accepted:
	case err := <-acceptErr:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("packet accept timed out")
	}
	defer serverConn.Close()

	client := clientConn.(*enginePacketConn)
	server := serverConn
	serverObserver := server.(ConnectionObserver)
	deadID := client.Paths()[0].ID
	deadServerID := server.Paths()[0].ID
	if err := client.e.ForceKillPathForTest(deadID); err != nil {
		t.Fatal(err)
	}
	replacement, serverReplacement := waitForPacketReplacement(t, client, server, deadID, deadServerID, 5*time.Second)
	if attempts.Load() < 4 {
		t.Fatalf("packet recovery did not retry dial failures: attempts=%d", attempts.Load())
	}
	assertBidirectionalPacketPayload(t, client, server, "first-packet-replacement")
	assertPathCarriedData(t, client.Paths(), replacement)
	assertPathCarriedData(t, server.Paths(), serverReplacement)
	if err := client.e.ForceKillPathForTest(replacement); err != nil {
		t.Fatal(err)
	}
	second, secondServer := waitForPacketReplacement(t, client, server, replacement, serverReplacement, 5*time.Second)
	if attempts.Load() < 5 {
		t.Fatalf("packet immediate second death did not redial: attempts=%d", attempts.Load())
	}
	assertBidirectionalPacketPayload(t, client, server, "second-packet-replacement")
	assertPathCarriedData(t, client.Paths(), second)
	assertPathCarriedData(t, server.Paths(), secondServer)
	waitForMigrationCounts(t, client.MigrationCount, serverObserver.MigrationCount, 2)
	if status := client.Status(); status.Protocol != SessionProtocolFramedPacketV3 {
		t.Fatalf("packet protocol=%q", status.Protocol)
	}
}

func waitForStreamReplacement(t *testing.T, client *engineBackedConn, server Conn, oldClientID, oldServerID uint32, timeout time.Duration) (uint32, uint32) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		clientPaths := client.Paths()
		serverPaths := server.Paths()
		if len(clientPaths) == 1 && clientPaths[0].ID != oldClientID &&
			len(serverPaths) == 1 && serverPaths[0].ID != oldServerID {
			return clientPaths[0].ID, serverPaths[0].ID
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("stream replacement did not commit: old client/server=%d/%d client=%v server=%v", oldClientID, oldServerID, client.Paths(), server.Paths())
	return 0, 0
}

func waitForPacketReplacement(t *testing.T, client *enginePacketConn, server PacketConn, oldClientID, oldServerID uint32, timeout time.Duration) (uint32, uint32) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	observedErrors := make(map[string]struct{})
	for time.Now().Before(deadline) {
		clientPaths := client.Paths()
		serverPaths := server.Paths()
		if len(clientPaths) == 1 && clientPaths[0].ID != oldClientID &&
			len(serverPaths) == 1 && serverPaths[0].ID != oldServerID {
			return clientPaths[0].ID, serverPaths[0].ID
		}
		for _, path := range client.status.snapshot(clientPaths, client.carriers) {
			if path.LastError != "" {
				observedErrors[path.LastError] = struct{}{}
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("packet replacement did not commit: old client/server=%d/%d client=%v server=%v client_status=%+v server_status=%+v client_close=%v observed_errors=%v",
		oldClientID, oldServerID, client.Paths(), server.Paths(), client.Status(), server.Status(),
		client.e.CloseErr(), observedErrors)
	return 0, 0
}

func assertBidirectionalStreamPayload(t *testing.T, client, server net.Conn, label string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	_ = client.SetDeadline(deadline)
	_ = server.SetDeadline(deadline)
	defer client.SetDeadline(time.Time{})
	defer server.SetDeadline(time.Time{})
	clientPayload := []byte(label + "-client")
	if _, err := client.Write(clientPayload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(clientPayload))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(clientPayload) {
		t.Fatalf("client payload=%q want %q", got, clientPayload)
	}
	serverPayload := []byte(label + "-server")
	if _, err := server.Write(serverPayload); err != nil {
		t.Fatal(err)
	}
	got = make([]byte, len(serverPayload))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(serverPayload) {
		t.Fatalf("server payload=%q want %q", got, serverPayload)
	}
}

func assertBidirectionalPacketPayload(t *testing.T, client, server net.PacketConn, label string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	_ = client.SetDeadline(deadline)
	_ = server.SetDeadline(deadline)
	defer client.SetDeadline(time.Time{})
	defer server.SetDeadline(time.Time{})
	clientPayload := []byte(label + "-client")
	if _, err := client.WriteTo(clientPayload, nil); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(clientPayload))
	n, _, err := server.ReadFrom(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(got[:n]) != string(clientPayload) {
		t.Fatalf("client packet=%q want %q", got[:n], clientPayload)
	}
	serverPayload := []byte(label + "-server")
	if _, err := server.WriteTo(serverPayload, nil); err != nil {
		t.Fatal(err)
	}
	got = make([]byte, len(serverPayload))
	n, _, err = client.ReadFrom(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(got[:n]) != string(serverPayload) {
		t.Fatalf("server packet=%q want %q", got[:n], serverPayload)
	}
}

func assertPathCarriedData(t *testing.T, paths []PathInfo, id uint32) {
	t.Helper()
	for _, path := range paths {
		if path.ID == id {
			if path.DataWrites == 0 {
				t.Fatalf("replacement path %d carried no DATA: %v", id, paths)
			}
			return
		}
	}
	t.Fatalf("replacement path %d disappeared: %v", id, paths)
}

func waitForMigrationCounts(t *testing.T, client, server func() uint64, want uint64) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if client() == want && server() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("migration counts client/server=%d/%d, want %d/%d", client(), server(), want, want)
}
