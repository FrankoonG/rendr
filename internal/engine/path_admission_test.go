package engine

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

func TestPathAdmissionCannotPublishAfterGracefulCloseStarts(t *testing.T) {
	t.Run("prepare", func(t *testing.T) {
		e, binding := admissionTestEngine(t)
		e.sendClosing.Store(true)
		candidate, peer := newMemoryPathPair()
		t.Cleanup(func() { _ = peer.Close() })
		if _, err := e.PreparePathBound(candidate, transport.PathSpec{Transport: "memory"}, binding); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("prepare after close gate error=%v, want %v", err, net.ErrClosed)
		}
	})

	t.Run("activate", func(t *testing.T) {
		e, binding := admissionTestEngine(t)
		candidate, peer := newMemoryPathPair()
		t.Cleanup(func() { _ = peer.Close() })
		id, err := e.PreparePathBound(candidate, transport.PathSpec{Transport: "memory"}, binding)
		if err != nil {
			t.Fatal(err)
		}
		if err := e.StagePathAttach(id); err != nil {
			t.Fatal(err)
		}
		e.sendClosing.Store(true)
		if err := e.ActivateStagedPath(id, false); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("activate after close gate error=%v, want %v", err, net.ErrClosed)
		}
	})
}

func admissionTestEngine(t *testing.T) (*Engine, PathBinding) {
	t.Helper()
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
	)
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	return e, PathBinding{LocalTXTargetID: ids["a"], PeerTXTargetID: ids["a"]}
}

func TestPathAdmissionLogicalGenerationAndCompletion(t *testing.T) {
	e, binding := admissionTestEngine(t)
	oldBase, oldPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = oldPeer.Close() })
	old := &observedClosePath{PathConn: oldBase}
	if _, err := e.AttachPathBound(old, transport.PathSpec{Transport: "memory"}, binding); err != nil {
		t.Fatal(err)
	}

	replacement, replacementPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = replacementPeer.Close() })
	id, err := e.PreparePathBound(replacement, transport.PathSpec{Transport: "memory"}, binding)
	if err != nil {
		t.Fatal(err)
	}
	base, err := e.PathAdmissionBaseGeneration(id)
	if err != nil || base != 1 {
		t.Fatalf("replacement base=%d err=%v, want 1", base, err)
	}
	if err := e.ValidatePathAdmissionBase(id, 0); err == nil {
		t.Fatal("accepted stale admission base")
	}
	if err := e.ValidatePathAdmissionBase(id, 1); err != nil {
		t.Fatal(err)
	}
	if err := e.StagePathAttach(id); err != nil {
		t.Fatal(err)
	}
	if err := e.ActivateStagedPath(id, true); err != nil {
		t.Fatal(err)
	}

	blocked, blockedPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = blockedPeer.Close() })
	if _, err := e.PreparePathBound(blocked, transport.PathSpec{Transport: "memory"}, binding); !errors.Is(err, ErrPathAttachInProgress) {
		t.Fatalf("prepare before completion error=%v, want %v", err, ErrPathAttachInProgress)
	}
	e.CompletePathAdmission(id)
	e.pathsMu.RLock()
	successor := e.paths[id]
	predecessors := append([]uint32(nil), e.pathPredecessors[id]...)
	retained := len(e.retainedPaths)
	e.pathsMu.RUnlock()
	if successor == nil {
		t.Fatal("completed admission lost successor")
	}
	select {
	case <-successor.admissionDone:
	default:
		t.Fatal("completed admission returned before closing removal barrier")
	}
	if len(predecessors) != 0 || retained != 0 {
		t.Fatalf("completed admission returned with predecessor ownership: predecessors=%v retained=%d", predecessors, retained)
	}
	deadline := time.Now().Add(time.Second)
	for !old.closed.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !old.closed.Load() {
		t.Fatal("completed admission retained predecessor")
	}

	next, nextPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = nextPeer.Close() })
	nextID, err := e.PreparePathBound(next, transport.PathSpec{Transport: "memory"}, binding)
	if err != nil {
		t.Fatal(err)
	}
	if base, err := e.PathAdmissionBaseGeneration(nextID); err != nil || base != 2 {
		t.Fatalf("next base=%d err=%v, want 2", base, err)
	}
	e.AbortPathAttach(nextID, nil)
}

func TestRemovePathWaitsForAdmissionCompletion(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	a, aPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = aPeer.Close() })
	if _, err := e.AttachPathBound(a, transport.PathSpec{Transport: "memory"}, PathBinding{
		LocalTXTargetID: ids["a"], PeerTXTargetID: ids["a"],
	}); err != nil {
		t.Fatal(err)
	}
	b, bPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = bPeer.Close() })
	bID, err := e.PreparePathBound(b, transport.PathSpec{Transport: "memory"}, PathBinding{
		LocalTXTargetID: ids["b"], PeerTXTargetID: ids["b"],
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.StagePathAttach(bID); err != nil {
		t.Fatal(err)
	}
	if err := e.ActivateStagedPath(bID, true); err != nil {
		t.Fatal(err)
	}
	e.pathsMu.RLock()
	bSlot := e.paths[bID]
	e.pathsMu.RUnlock()

	removed := make(chan error, 1)
	go func() { removed <- e.RemovePath(bID) }()
	deadline := time.Now().Add(time.Second)
	for bSlot.removeWaiters.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if bSlot.removeWaiters.Load() == 0 {
		t.Fatal("RemovePath did not enter admission wait")
	}
	select {
	case err := <-removed:
		t.Fatalf("RemovePath crossed unfinished admission barrier: %v", err)
	default:
	}
	e.CompletePathAdmission(bID)
	select {
	case err := <-removed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("RemovePath did not resume after admission completion")
	}
}

func TestAdmissionRetentionTimeoutCompletesRemovalBarrier(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	e := New(SideClient, NewClientFlowID(), Limits{MigrationBudget: 20 * time.Millisecond}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	a, aPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = aPeer.Close() })
	if _, err := e.AttachPathBound(a, transport.PathSpec{Transport: "memory"}, PathBinding{LocalTXTargetID: ids["a"], PeerTXTargetID: ids["a"]}); err != nil {
		t.Fatal(err)
	}
	b, bPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = bPeer.Close() })
	bID, err := e.PreparePathBound(b, transport.PathSpec{Transport: "memory"}, PathBinding{LocalTXTargetID: ids["b"], PeerTXTargetID: ids["b"]})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.StagePathAttach(bID); err != nil {
		t.Fatal(err)
	}
	if err := e.ActivateStagedPath(bID, true); err != nil {
		t.Fatal(err)
	}
	e.pathsMu.RLock()
	done := e.paths[bID].admissionDone
	e.pathsMu.RUnlock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("retention timeout did not complete admission barrier")
	}
	if err := e.RemovePath(bID); err != nil {
		t.Fatalf("remove after retention timeout: %v", err)
	}
}

func TestStagedPathIsReceiveReadyAndTXInvisible(t *testing.T) {
	e, binding := admissionTestEngine(t)
	activeBase, activePeer := newMemoryPathPair()
	t.Cleanup(func() { _ = activePeer.Close() })
	active := &captureDispatchPath{PathConn: activeBase}
	if _, err := e.AttachPathBound(active, transport.PathSpec{Transport: "memory"}, binding); err != nil {
		t.Fatal(err)
	}

	stagedBase, stagedPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = stagedPeer.Close() })
	staged := &captureDispatchPath{PathConn: stagedBase}
	id, err := e.PreparePathBound(staged, transport.PathSpec{Transport: "memory"}, binding)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.StagePathAttach(id); err != nil {
		t.Fatal(err)
	}
	if _, err := e.SendData([]byte("old-tx")); err != nil {
		t.Fatal(err)
	}
	if got := staged.dataSequences(); len(got) != 0 {
		t.Fatalf("staged path carried TX DATA: %v", got)
	}

	payload := []byte("new-rx")
	frame := make([]byte, proto.HeaderSize+len(payload))
	if err := (proto.Header{Version: proto.Version, Type: proto.FrameData, Seq: 0}).Encode(frame[:proto.HeaderSize]); err != nil {
		t.Fatal(err)
	}
	copy(frame[proto.HeaderSize:], payload)
	if _, err := stagedPeer.Write(frame); err != nil {
		t.Fatal(err)
	}
	received := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 32)
		n, err := e.Recv(buf)
		if err == nil {
			received <- append([]byte(nil), buf[:n]...)
		}
	}()
	select {
	case got := <-received:
		if string(got) != string(payload) {
			t.Fatalf("staged RX=%q want=%q", got, payload)
		}
	case <-time.After(time.Second):
		t.Fatal("staged path did not admit RX DATA")
	}
	e.AbortPathAttach(id, nil)
}
