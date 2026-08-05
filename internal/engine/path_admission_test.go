package engine

import (
	"errors"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

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
