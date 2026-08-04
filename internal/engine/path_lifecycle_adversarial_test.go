package engine

import (
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
	case <-time.After(50 * time.Millisecond):
		t.Fatal("engine lifecycle remained open behind blocked adapter Close")
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
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("bounded Close did not report adapter timeout")
		}
	case <-time.After(pathCloseTimeout + 100*time.Millisecond):
		t.Fatal("Engine.Close exceeded path adapter timeout")
	}
	close(blocked.release)
}
