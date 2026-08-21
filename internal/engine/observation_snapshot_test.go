package engine

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

func TestConnectionObservationRetriesAcrossTopologyEpochChange(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	targets := configureLeafSelectorRuntime(t, e, "a", "b")
	observationEntered := make(chan struct{})
	releaseObservation := make(chan struct{})
	var hookOnce atomic.Bool
	e.connectionObservationAfterTopology = func() {
		if hookOnce.CompareAndSwap(false, true) {
			close(observationEntered)
			<-releaseObservation
		}
	}
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseObservation) }) })
	attachFixturePath(t, e, newLifecycleHealthyPath(),
		transport.PathSpec{Transport: "memory", Address: "observation-a"},
		targets["a"],
	)

	payload := []byte("stable-before-topology-change")
	if n, err := e.SendData(payload); n != len(payload) || err != nil {
		t.Fatalf("SendData=(%d,%v), want (%d,nil)", n, err, len(payload))
	}
	if !closeLinearizationAckThrough(e, 1) {
		t.Fatal("could not acknowledge the pre-change DATA frame")
	}
	if before := e.TargetApplicationDelivery(targets["a"]); !before.Attributable {
		t.Fatalf("pre-change root delivery is not attributable: %+v", before)
	}

	done := make(chan ConnectionObservationSnapshot, 1)
	go func() { done <- e.ConnectionObservation() }()
	select {
	case <-observationEntered:
	case <-time.After(time.Second):
		t.Fatal("observation did not reach the post-topology barrier")
	}
	attachFixturePath(t, e, newLifecycleHealthyPath(),
		transport.PathSpec{Transport: "memory", Address: "observation-b"},
		targets["b"],
	)
	releaseOnce.Do(func() { close(releaseObservation) })

	select {
	case snapshot := <-done:
		if snapshot.Topology.Epoch != e.currentPathTopologyEpoch() || len(snapshot.Topology.Paths) != 2 {
			t.Fatalf("observation returned stale topology: %+v", snapshot.Topology)
		}
		if snapshot.RootDelivery.Attributable || snapshot.RootDelivery.PublishedBytes != 0 ||
			snapshot.RootDelivery.AckedBytes != 0 {
			t.Fatalf("observation mixed old root evidence with new topology: %+v", snapshot.RootDelivery)
		}
	case <-time.After(time.Second):
		t.Fatal("observation did not retry after topology changed")
	}
}

func TestConnectionObservationRetriesAcrossSelectorCommit(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	targets := configureLeafSelectorRuntime(t, e, "a", "b")
	aID := attachFixturePath(t, e, newLifecycleHealthyPath(),
		transport.PathSpec{Transport: "memory", Address: "selector-a"},
		targets["a"],
	)
	bID := attachFixturePath(t, e, newLifecycleHealthyPath(),
		transport.PathSpec{Transport: "memory", Address: "selector-b"},
		targets["b"],
	)
	if e.ActivePath() != aID {
		t.Fatalf("initial active path=%d, want a=%d", e.ActivePath(), aID)
	}

	observationEntered := make(chan struct{})
	releaseObservation := make(chan struct{})
	var hookOnce atomic.Bool
	e.connectionObservationAfterTopology = func() {
		if hookOnce.CompareAndSwap(false, true) {
			close(observationEntered)
			<-releaseObservation
		}
	}
	done := make(chan ConnectionObservationSnapshot, 1)
	go func() { done <- e.ConnectionObservation() }()
	select {
	case <-observationEntered:
	case <-time.After(time.Second):
		t.Fatal("observation did not reach the selector-commit barrier")
	}
	if err := e.SelectExplicitTarget(targets["root"], targets["b"], "observation-race"); err != nil {
		close(releaseObservation)
		t.Fatal(err)
	}
	close(releaseObservation)

	select {
	case snapshot := <-done:
		if snapshot.Topology.ActivePath != bID || snapshot.Topology.PolicyGeneration == 0 {
			t.Fatalf("observation returned pre-commit topology with post-commit evidence: %+v", snapshot.Topology)
		}
	case <-time.After(time.Second):
		t.Fatal("observation did not retry after selector commit")
	}
}

func TestConnectionObservationFallsBackCoherentlyUnderSustainedSelectorChurn(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	targets := configureLeafSelectorRuntime(t, e, "a", "b")
	aID := attachFixturePath(t, e, newLifecycleHealthyPath(),
		transport.PathSpec{Transport: "memory", Address: "churn-a"},
		targets["a"],
	)
	bID := attachFixturePath(t, e, newLifecycleHealthyPath(),
		transport.PathSpec{Transport: "memory", Address: "churn-b"},
		targets["b"],
	)
	if e.ActivePath() != aID {
		t.Fatalf("initial active path=%d want a=%d", e.ActivePath(), aID)
	}

	var attempts int
	var churnErr error
	var keepChurning atomic.Bool
	keepChurning.Store(true)
	e.connectionObservationAfterTopology = func() {
		if !keepChurning.Load() {
			return
		}
		attempts++
		target := targets["b"]
		if attempts%2 == 0 {
			target = targets["a"]
		}
		if err := e.SelectExplicitTarget(targets["root"], target, "observation-churn"); err != nil && churnErr == nil {
			churnErr = err
		}
	}

	done := make(chan ConnectionObservationSnapshot, 1)
	go func() { done <- e.ConnectionObservation() }()
	var snapshot ConnectionObservationSnapshot
	select {
	case snapshot = <-done:
	case <-time.After(time.Second):
		keepChurning.Store(false)
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("observation did not stop after churn was released")
		}
		t.Fatal("observation did not complete through its bounded coherent fallback")
	}
	if churnErr != nil {
		t.Fatalf("selector churn failed: %v", churnErr)
	}
	if attempts != connectionObservationOptimisticRetries {
		t.Fatalf("optimistic attempts=%d want %d before coherent fallback", attempts, connectionObservationOptimisticRetries)
	}
	if snapshot.Topology.PolicyGeneration != e.policyObservationGen.Load() ||
		snapshot.Topology.PolicyGeneration != uint64(connectionObservationOptimisticRetries) {
		t.Fatalf("policy generation snapshot/current=%d/%d want %d",
			snapshot.Topology.PolicyGeneration, e.policyObservationGen.Load(), connectionObservationOptimisticRetries)
	}
	if snapshot.Topology.ActivePath != bID || e.ActivePath() != bID {
		t.Fatalf("active path snapshot/current=%d/%d want b=%d", snapshot.Topology.ActivePath, e.ActivePath(), bID)
	}
	if len(snapshot.Topology.EffectivePaths) != 1 || snapshot.Topology.EffectivePaths[0] != bID {
		t.Fatalf("effective paths=%v want [%d]", snapshot.Topology.EffectivePaths, bID)
	}
	activeInfos := 0
	for _, info := range snapshot.Topology.Paths {
		if info.Active {
			activeInfos++
			if info.ID != snapshot.Topology.ActivePath {
				t.Fatalf("active PathInfo=%d disagrees with topology active=%d", info.ID, snapshot.Topology.ActivePath)
			}
		}
	}
	if len(snapshot.Topology.Paths) != 2 || activeInfos != 1 {
		t.Fatalf("path snapshot count/active=%d/%d want 2/1", len(snapshot.Topology.Paths), activeInfos)
	}
	if snapshot.Replay.PublishedNext != e.sendPublishedNext.Load() ||
		snapshot.Replay.AckNext != e.sendAckNext.Load() {
		t.Fatalf("replay frontier snapshot=%d/%d current=%d/%d",
			snapshot.Replay.PublishedNext, snapshot.Replay.AckNext,
			e.sendPublishedNext.Load(), e.sendAckNext.Load())
	}
}

func TestConnectionObservationFallbackDoesNotDeadlockPacketBackpressureClose(t *testing.T) {
	manifest, _ := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindPath, "observation-packet-root"),
	)
	e := New(SideServer, NewClientFlowID(), Limits{MigrationBudget: time.Second}.Clamp())
	e.SetPacketMode()
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}

	// Make one DATA delivery hold recvMu exactly where packet backpressure
	// waits for either application capacity or engine closure.
	e.recvPacketCh = make(chan []byte, 1)
	e.recvPacketCh <- []byte("occupied")
	payload := []byte("blocked-delivery")
	header := proto.Header{Version: proto.Version, Type: proto.FrameData, Seq: 0}
	receiverDone := make(chan struct{})
	go func() {
		e.onRecvBatch([]recvFrame{{
			topologyEpoch: e.currentPathTopologyEpoch(),
			hdr:           header,
			payload:       payload,
			digest:        recvFrameDigest(header, payload),
		}})
		close(receiverDone)
	}()

	receiverOwnsLock := false
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if e.recvMu.TryLock() {
			e.recvMu.Unlock()
			time.Sleep(time.Millisecond)
			continue
		}
		receiverOwnsLock = true
		break
	}
	if !receiverOwnsLock {
		t.Fatal("packet receiver did not block with recvMu held")
	}

	var attempts atomic.Int32
	e.connectionObservationAfterTopology = func() {
		e.pathsMu.Lock()
		e.advancePathTopologyEpochLocked()
		e.pathsMu.Unlock()
		attempts.Add(1)
	}
	fallbackEntered := make(chan struct{})
	releaseFallback := make(chan struct{})
	var fallbackOnce, releaseOnce sync.Once
	e.connectionObservationFallbackLocked = func() {
		fallbackOnce.Do(func() { close(fallbackEntered) })
		<-releaseFallback
	}
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(releaseFallback) })
		_ = e.Close()
	})

	observationDone := make(chan ConnectionObservationSnapshot, 1)
	go func() { observationDone <- e.ConnectionObservation() }()
	awaitSignal(t, fallbackEntered, "coherent observation fallback")
	if got := attempts.Load(); got != connectionObservationOptimisticRetries {
		t.Fatalf("optimistic attempts=%d want %d", got, connectionObservationOptimisticRetries)
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- e.Close() }()
	select {
	case err := <-closeDone:
		t.Fatalf("Close crossed fallback pathsMu barrier: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	releaseOnce.Do(func() { close(releaseFallback) })
	select {
	case <-observationDone:
	case <-time.After(time.Second):
		t.Fatal("ConnectionObservation remained blocked after concurrent Close")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close remained blocked behind ConnectionObservation")
	}
	awaitSignal(t, receiverDone, "backpressured packet receiver shutdown")
}
