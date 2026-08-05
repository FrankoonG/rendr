package engine

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

func TestPreparedPathIsInvisibleUntilBridgeAckCommit(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	e := New(SideServer, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}

	a, aPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = aPeer.Close() })
	aCapture := &captureDispatchPath{PathConn: a}
	if _, err := e.AttachPathBound(aCapture, transport.PathSpec{Transport: "memory"}, PathBinding{
		LocalTXTargetID: ids["a"], PeerTXTargetID: ids["a"],
	}); err != nil {
		t.Fatal(err)
	}
	b, bPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = bPeer.Close() })
	bCapture := &captureDispatchPath{PathConn: b}
	pendingID, err := e.PreparePathBound(bCapture, transport.PathSpec{Transport: "memory"}, PathBinding{
		LocalTXTargetID: ids["b"], PeerTXTargetID: ids["b"],
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(e.Paths()); got != 1 {
		t.Fatalf("prepared path leaked into Paths: %d", got)
	}
	if _, err := e.SendData([]byte("before-ack")); err != nil {
		t.Fatal(err)
	}
	if got := bCapture.dataSequences(); len(got) != 0 {
		t.Fatalf("prepared path carried DATA before BRIDGE_ACK: %v", got)
	}
	if err := e.CommitPathAttach(pendingID); err != nil {
		t.Fatal(err)
	}
	if err := e.SelectLocalTarget(ids["root"], ids["b"], "after-ack"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.SendData([]byte("after-ack")); err != nil {
		t.Fatal(err)
	}
	if got := bCapture.dataSequences(); len(got) != 1 || got[0] != 1 {
		t.Fatalf("committed path DATA=%v, want [1]", got)
	}
}

func TestSameLeafAdmissionIsSerializedAndRollsBackToPredecessor(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
	)
	e := New(SideServer, NewClientFlowID(), Limits{ZombieMaxMigrations: 10}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	binding := PathBinding{LocalTXTargetID: ids["a"], PeerTXTargetID: ids["a"]}

	oldBase, oldPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = oldPeer.Close() })
	old := &observedClosePath{PathConn: oldBase}
	oldID, err := e.AttachPathBound(old, transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": "a"}}, binding)
	if err != nil {
		t.Fatal(err)
	}

	winnerBase, winnerPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = winnerPeer.Close() })
	winner := &observedClosePath{PathConn: winnerBase}
	winnerID, err := e.PreparePathBound(winner, transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": "a"}}, binding)
	if err != nil {
		t.Fatal(err)
	}
	concurrentBase, concurrentPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = concurrentPeer.Close() })
	concurrent := &observedClosePath{PathConn: concurrentBase}
	if _, err := e.PreparePathBound(concurrent, transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": "a"}}, binding); !errors.Is(err, ErrPathAttachInProgress) {
		t.Fatalf("concurrent prepare error = %v, want %v", err, ErrPathAttachInProgress)
	}

	if paths := e.Paths(); len(paths) != 1 || paths[0].ID != oldID {
		t.Fatalf("pending replacement displaced old path before stage: %v", paths)
	}
	if err := e.StagePathAttach(winnerID); err != nil {
		t.Fatalf("stage winner: %v", err)
	}
	stagedBase, stagedPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = stagedPeer.Close() })
	stagedConcurrent := &observedClosePath{PathConn: stagedBase}
	if _, err := e.PreparePathBound(stagedConcurrent, transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": "a"}}, binding); !errors.Is(err, ErrPathAttachInProgress) {
		t.Fatalf("prepare while staged error = %v, want %v", err, ErrPathAttachInProgress)
	}
	if paths := e.Paths(); len(paths) != 1 || paths[0].ID != oldID {
		t.Fatalf("staged path became TX-visible: %v", paths)
	}
	if err := e.ActivateStagedPath(winnerID, true); err != nil {
		t.Fatalf("activate winner: %v", err)
	}
	if paths := e.Paths(); len(paths) != 1 || paths[0].ID != winnerID {
		t.Fatalf("activated path set = %v, want winner only", paths)
	}
	if got := e.ActivePath(); got != winnerID {
		t.Fatalf("active path = %d, want winner %d", got, winnerID)
	}
	if old.closed.Load() {
		t.Fatal("predecessor closed before admission confirmation")
	}
	if !concurrent.closed.Load() || !stagedConcurrent.closed.Load() {
		t.Fatalf("rejected candidates closed = %t/%t, want true/true", concurrent.closed.Load(), stagedConcurrent.closed.Load())
	}
	if err := e.ForceKillPathForTest(winnerID); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for e.ActivePath() != oldID && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := e.ActivePath(); got != oldID {
		t.Fatalf("active path after successor death = %d, want predecessor %d", got, oldID)
	}
	if old.closed.Load() {
		t.Fatal("rollback predecessor was closed")
	}
	if got := e.MigrationCount(); got != 2 {
		t.Fatalf("activate plus rollback migrations = %d, want 2", got)
	}
}

func TestPathSpecOptsAreOwnedAcrossEngineBoundaries(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	path, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = peer.Close() })
	spec := transport.PathSpec{Transport: "memory", Address: "snapshot", Opts: map[string]string{"token": "frozen"}}
	id, err := e.AttachPath(path, spec)
	if err != nil {
		t.Fatal(err)
	}
	spec.Opts["token"] = "caller-mutated"
	first := e.Paths()
	if got := first[0].Spec.Opts["token"]; got != "frozen" {
		t.Fatalf("stored PathSpec option = %q, want frozen", got)
	}
	first[0].Spec.Opts["token"] = "snapshot-mutated"
	if got := e.Paths()[0].Spec.Opts["token"]; got != "frozen" {
		t.Fatalf("second PathSpec snapshot option = %q, want frozen", got)
	}

	mutated := make(chan struct{})
	observed := make(chan string, 1)
	e.OnPathDeath(func(event PathDeathEvent) {
		event.Spec.Opts["token"] = "hook-mutated"
		close(mutated)
	})
	e.OnPathDeath(func(event PathDeathEvent) {
		<-mutated
		observed <- event.Spec.Opts["token"]
	})
	if err := e.ForceKillPathForTest(id); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-observed:
		if got != "frozen" {
			t.Fatalf("death hook PathSpec option = %q, want frozen", got)
		}
	case <-time.After(time.Second):
		t.Fatal("death hook snapshots were not delivered")
	}
}

func TestSessionPathReservationsAreBounded(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	ids := make([]uint32, 0, maxSessionPaths)
	peers := make([]transport.PathConn, 0, maxSessionPaths+1)
	for i := 0; i < maxSessionPaths; i++ {
		path, peer := newMemoryPathPair()
		peers = append(peers, peer)
		id, err := e.PreparePathBound(path, transport.PathSpec{Transport: "memory"}, PathBinding{})
		if err != nil {
			t.Fatalf("prepare path %d: %v", i, err)
		}
		ids = append(ids, id)
	}
	extra, extraPeer := newMemoryPathPair()
	peers = append(peers, extraPeer)
	if _, err := e.PreparePathBound(extra, transport.PathSpec{Transport: "memory"}, PathBinding{}); err == nil {
		t.Fatalf("accepted more than %d simultaneous path reservations", maxSessionPaths)
	}
	for _, id := range ids {
		e.AbortPathAttach(id, nil)
	}
	for _, peer := range peers {
		_ = peer.Close()
	}
}

func TestBridgeAttachReplayCacheIsBounded(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
	)
	flow := NewClientFlowID()
	e := New(SideServer, flow, Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	localInstance := proto.InstanceID{1}
	peerInstance := proto.InstanceID{2}
	e.SetLocalInstanceID(localInstance)
	e.SetPeerInstanceID(peerInstance)
	binding := e.peerGraphBinding()
	var newest [16]byte
	for i := 0; i < maxSeenAttachIDs+17; i++ {
		newest = [16]byte{byte(i), byte(i >> 8), 1}
		tag := proto.BridgeTagPayload{
			BridgeID: flow, AttachID: newest, InstanceID: peerInstance,
			ExpectedPeerInstanceID: localInstance, SessionEpoch: proto.SessionEpoch(flow),
			Direction: peerSenderDirection(e.side), GraphRevision: binding.revision,
			GraphDigest: binding.digest, TargetID: ids["a"],
		}
		if err := e.ValidateBridgeBinding(tag); err != nil {
			t.Fatalf("validate attach %d: %v", i, err)
		}
	}
	e.attachMu.Lock()
	cacheLen := len(e.seenAttach)
	orderLen := len(e.seenAttachFIFO)
	e.attachMu.Unlock()
	if cacheLen != maxSeenAttachIDs || orderLen != maxSeenAttachIDs {
		t.Fatalf("attach replay cache=(%d,%d), want (%d,%d)", cacheLen, orderLen, maxSeenAttachIDs, maxSeenAttachIDs)
	}
	binding = e.peerGraphBinding()
	duplicate := proto.BridgeTagPayload{
		BridgeID: flow, AttachID: newest, InstanceID: peerInstance,
		ExpectedPeerInstanceID: localInstance, SessionEpoch: proto.SessionEpoch(flow),
		Direction: peerSenderDirection(e.side), GraphRevision: binding.revision,
		GraphDigest: binding.digest, TargetID: ids["a"],
	}
	if err := e.ValidateBridgeBinding(duplicate); err != ErrDuplicateAttach {
		t.Fatalf("newest replay error=%v, want %v", err, ErrDuplicateAttach)
	}
}

type blockingClosePath struct {
	transport.PathConn
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (p *blockingClosePath) Close() error {
	p.once.Do(func() { close(p.started) })
	<-p.release
	return p.PathConn.Close()
}

type observedClosePath struct {
	transport.PathConn
	closed atomic.Bool
}

func (p *observedClosePath) Close() error {
	p.closed.Store(true)
	return p.PathConn.Close()
}

func TestEngineCloseCannotBePinnedByOnePathAdapter(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	blockedBase, blockedPeer := newMemoryPathPair()
	defer blockedPeer.Close()
	blocked := &blockingClosePath{PathConn: blockedBase, started: make(chan struct{}), release: make(chan struct{})}
	if _, err := e.AttachPath(blocked, transport.PathSpec{Transport: "memory"}); err != nil {
		t.Fatal(err)
	}
	healthyBase, healthyPeer := newMemoryPathPair()
	defer healthyPeer.Close()
	healthy := &observedClosePath{PathConn: healthyBase}
	if _, err := e.AttachPath(healthy, transport.PathSpec{Transport: "memory"}); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- e.Close() }()
	select {
	case <-e.Closed():
		t.Fatal("engine reported quiescence while an owned adapter Close was still blocked")
	case <-time.After(20 * time.Millisecond):
	}
	select {
	case <-blocked.started:
	case <-time.After(50 * time.Millisecond):
		t.Fatal("blocked adapter Close was not attempted")
	}
	deadline := time.Now().Add(100 * time.Millisecond)
	for !healthy.closed.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !healthy.closed.Load() {
		t.Fatal("blocked adapter prevented healthy path Close")
	}
	var firstCloseErr error
	select {
	case firstCloseErr = <-done:
		if firstCloseErr == nil {
			t.Fatal("bounded Close did not report adapter timeout")
		}
	case <-time.After(pathCloseTimeout + 100*time.Millisecond):
		t.Fatal("Engine.Close exceeded path adapter timeout")
	}
	select {
	case <-e.Closed():
		t.Fatal("timed-out Close reported quiescence before blocked adapter exited")
	default:
	}
	if secondCloseErr := e.Close(); secondCloseErr != firstCloseErr {
		t.Fatalf("repeated Close error=%v, want persisted %v", secondCloseErr, firstCloseErr)
	}
	close(blocked.release)
	select {
	case <-e.Closed():
	case <-time.After(time.Second):
		t.Fatal("asynchronous reaper did not publish quiescence after adapter exit")
	}
}
