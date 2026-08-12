package engine

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

func TestPeerPathRetirementConvergesPacketReverseTraffic(t *testing.T) {
	manifest, targets := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	client, server, captures := newRecursiveEnginePair(t, manifest, "a", "b")
	client.SetPacketMode()
	server.SetPacketMode()

	clientB := pathIDByName(t, client, "b")
	serverB := pathIDByName(t, server, "b")
	if err := client.SelectLocalTarget(targets["root"], targets["b"], "test"); err != nil {
		t.Fatal(err)
	}
	if err := server.SelectLocalTarget(targets["root"], targets["b"], "test"); err != nil {
		t.Fatal(err)
	}
	if client.ActivePath() != clientB || server.ActivePath() != serverB {
		t.Fatalf("B was not selected: client=%d/%d server=%d/%d", client.ActivePath(), clientB, server.ActivePath(), serverB)
	}

	failed, ok := captures["b"].PathConn.(*memoryPathConn)
	if !ok {
		t.Fatalf("client B path type=%T", captures["b"].PathConn)
	}
	failed.Fail(errors.New("injected one-sided packet carrier death"))
	waitPathDetached(t, client, clientB)
	waitPathDetached(t, server, serverB)

	clientA := pathIDByName(t, client, "a")
	serverA := pathIDByName(t, server, "a")
	if client.ActivePath() != clientA || server.ActivePath() != serverA {
		t.Fatalf("retirement did not converge on A: client=%d/%d server=%d/%d", client.ActivePath(), clientA, server.ActivePath(), serverA)
	}
	want := []byte("reverse-after-one-sided-packet-death")
	if err := server.SendPacket(want); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err := client.RecvPacket()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("reverse packet=%q want=%q", got, want)
	}
}

func TestPeerPathRetirementIsIdempotentAndGenerationSafe(t *testing.T) {
	manifest, _ := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	client, server, _ := newRecursiveEnginePair(t, manifest, "a", "b")
	clientB := pathIDByName(t, client, "b")
	serverB := pathIDByName(t, server, "b")
	retirement := pathRetirementPayloadForTest(t, client, clientB, proto.PathRetirementReasonAdministrative)

	if err := client.RemovePath(clientB); err != nil {
		t.Fatal(err)
	}
	waitPathDetached(t, server, serverB)
	if err := server.applyPeerPathRetirement(retirement); err != nil {
		t.Fatalf("duplicate retirement=%v", err)
	}

	clientPath, serverPath := newMemoryPathPair()
	attachRecursivePath(t, client, server, "b", clientPath, serverPath)
	newClientB := pathIDByName(t, client, "b")
	newServerB := pathIDByName(t, server, "b")
	if newClientB == clientB || newServerB == serverB {
		t.Fatalf("replacement reused physical path id: client=%d server=%d", newClientB, newServerB)
	}
	if err := server.applyPeerPathRetirement(retirement); err != nil {
		t.Fatalf("stale retirement=%v", err)
	}
	if _, ok := server.PathRef(newServerB); !ok {
		t.Fatal("stale retirement removed the recovered generation")
	}

	future := retirement
	future.RouteGeneration += 2
	if err := server.applyPeerPathRetirement(future); err == nil {
		t.Fatal("accepted retirement from a future generation")
	}
	if _, ok := server.PathRef(newServerB); !ok {
		t.Fatal("future retirement mutated the current generation")
	}
}

func TestPeerPathRetirementRemovesExactRetainedPredecessor(t *testing.T) {
	manifest, _ := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	receiver, _ := newStandaloneRetirementEngine(t, manifest, "a", "b")
	oldID := pathIDByName(t, receiver, "a")

	replacement, replacementPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = replacementPeer.Close() })
	newID := activateRetainedReplacement(t, receiver, "a", replacement)

	receiver.pathsMu.RLock()
	old := receiver.retainedPaths[oldID]
	active := receiver.paths[newID]
	if old == nil || active == nil {
		receiver.pathsMu.RUnlock()
		t.Fatalf("retained/active generations are absent: old=%v active=%v", old != nil, active != nil)
	}
	oldGeneration := old.routeGeneration.Load()
	activeGeneration := active.routeGeneration.Load()
	retirement := pathRetirementPayloadForReceiverSlot(t, receiver, old, oldGeneration, proto.PathRetirementReasonTransport)
	receiver.pathsMu.RUnlock()
	if activeGeneration != oldGeneration+1 {
		t.Fatalf("route generations old=%d active=%d, want consecutive", oldGeneration, activeGeneration)
	}

	if err := receiver.applyPeerPathRetirement(retirement); err != nil {
		t.Fatal(err)
	}
	receiver.pathsMu.RLock()
	_, retained := receiver.retainedPaths[oldID]
	predecessors := append([]uint32(nil), receiver.pathPredecessors[newID]...)
	current := receiver.paths[newID]
	receiver.pathsMu.RUnlock()
	if retained || len(predecessors) != 0 {
		t.Fatalf("exact predecessor survived retirement: retained=%v predecessors=%v", retained, predecessors)
	}
	if current != active || current.routeGeneration.Load() != activeGeneration {
		t.Fatal("retiring generation n changed active generation n+1")
	}
	eventuallyEngine(t, time.Second, func() bool {
		select {
		case <-old.conn.(*memoryPathConn).closed:
			return true
		default:
			return false
		}
	})
}

func TestPeerPathRetirementPropagatesRetainedPredecessorDeath(t *testing.T) {
	manifest, _ := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{}.Clamp())
	server := New(SideServer, flow, Limits{}.Clamp())
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	configureRecursivePair(t, client, server, manifest)
	oldClientA, oldServerAPath := newMemoryPathPair()
	attachRecursivePath(t, client, server, "a", oldClientA, oldServerAPath)
	clientB, serverB := newMemoryPathPair()
	attachRecursivePath(t, client, server, "b", clientB, serverB)
	oldClientID := pathIDByName(t, client, "a")
	oldServerID := pathIDByName(t, server, "a")
	replacementClient, replacementServer := newMemoryPathPair()
	newClientID := activateRetainedReplacement(t, client, "a", replacementClient)
	newServerID := activateRetainedReplacement(t, server, "a", replacementServer)

	oldClientA.Fail(errors.New("injected retained predecessor death"))
	eventuallyEngine(t, time.Second, func() bool {
		client.pathsMu.RLock()
		_, retained := client.retainedPaths[oldClientID]
		client.pathsMu.RUnlock()
		return !retained
	})
	eventuallyEngine(t, time.Second, func() bool {
		server.pathsMu.RLock()
		_, retained := server.retainedPaths[oldServerID]
		predecessors := len(server.pathPredecessors[newServerID])
		active := server.paths[newServerID]
		server.pathsMu.RUnlock()
		return !retained && predecessors == 0 && active != nil
	})
	if _, ok := client.PathRef(newClientID); !ok {
		t.Fatal("retained predecessor death removed the active client successor")
	}
	if _, ok := server.PathRef(newServerID); !ok {
		t.Fatal("peer retained retirement removed the active server successor")
	}
}

func TestPeerPathRetirementUsesLogicalIdentityAcrossSkewedIDsAndOwners(t *testing.T) {
	manifest, _ := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{}.Clamp())
	server := New(SideServer, flow, Limits{}.Clamp())
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	configureRecursivePair(t, client, server, manifest)
	server.nextPathID = 100
	server.nextPathGen = 1000
	for _, name := range []string{"a", "b"} {
		clientPath, serverPath := newMemoryPathPair()
		attachRecursivePath(t, client, server, name, clientPath, serverPath)
	}

	clientB := pathIDByName(t, client, "b")
	serverB := pathIDByName(t, server, "b")
	clientRef, _ := client.PathRef(clientB)
	serverRef, _ := server.PathRef(serverB)
	if clientRef.ID == serverRef.ID || clientRef.Owner == serverRef.Owner {
		t.Fatalf("fixture did not skew physical identity: client=%+v server=%+v", clientRef, serverRef)
	}
	if err := client.RemovePath(clientB); err != nil {
		t.Fatal(err)
	}
	waitPathDetached(t, server, serverB)

	want := []byte("traffic-after-skewed-retirement")
	if _, err := client.SendData(want); err != nil {
		t.Fatal(err)
	}
	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	n, err := server.Recv(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:n], want) {
		t.Fatalf("payload=%q want=%q", got[:n], want)
	}
}

func TestPeerPathRetirementBilateralSimultaneousDeparture(t *testing.T) {
	manifest, _ := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	client, server, _ := newRecursiveEnginePair(t, manifest, "a", "b")
	clientB := pathIDByName(t, client, "b")
	serverB := pathIDByName(t, server, "b")

	clientDeparture := detachAdministrativePathForRetirementTest(t, client, clientB)
	serverDeparture := detachAdministrativePathForRetirementTest(t, server, serverB)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		client.finishPathDeparture(clientDeparture)
	}()
	go func() {
		defer wg.Done()
		server.finishPathDeparture(serverDeparture)
	}()
	wg.Wait()
	eventuallyEngine(t, time.Second, func() bool {
		client.pathRetirementMu.Lock()
		clientQueued := len(client.pathRetirementQueued)
		client.pathRetirementMu.Unlock()
		server.pathRetirementMu.Lock()
		serverQueued := len(server.pathRetirementQueued)
		server.pathRetirementMu.Unlock()
		return clientQueued == 0 && serverQueued == 0
	})
	if client.CloseErr() != nil || server.CloseErr() != nil {
		t.Fatalf("simultaneous retirement closed session: client=%v server=%v", client.CloseErr(), server.CloseErr())
	}

	want := []byte("bilateral-retirement-survivor")
	if _, err := client.SendData(want); err != nil {
		t.Fatal(err)
	}
	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	n, err := server.Recv(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:n], want) {
		t.Fatalf("payload=%q want=%q", got[:n], want)
	}
}

func TestPeerPathRetirementDroppedControlReplaysExactFrame(t *testing.T) {
	manifest, _ := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{}.Clamp())
	server := New(SideServer, flow, Limits{}.Clamp())
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	configureRecursivePair(t, client, server, manifest)
	clientA, serverA := newMemoryPathPair()
	dropper := &pathRetirementDropOnce{PathConn: clientA}
	attachRecursivePath(t, client, server, "a", dropper, serverA)
	clientB, serverBPath := newMemoryPathPair()
	attachRecursivePath(t, client, server, "b", clientB, serverBPath)
	clientBID := pathIDByName(t, client, "b")
	serverBID := pathIDByName(t, server, "b")

	if err := client.RemovePath(clientBID); err != nil {
		t.Fatal(err)
	}
	eventuallyEngine(t, time.Second, dropper.dropped.Load)
	want := []byte("data-after-dropped-path-retire")
	if _, err := client.SendData(want); err != nil {
		t.Fatal(err)
	}
	if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	n, err := server.Recv(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:n], want) {
		t.Fatalf("payload=%q want=%q", got[:n], want)
	}
	waitPathDetached(t, server, serverBID)
	if writes := dropper.retirementWrites.Load(); writes < 2 {
		t.Fatalf("PATH_RETIRE writes=%d, dropped frame was not replayed", writes)
	}
	if server.CloseErr() != nil {
		t.Fatalf("exact replay closed receiver: %v", server.CloseErr())
	}
}

func TestPeerPathRetirementMultipleExactMatchesFailClosed(t *testing.T) {
	manifest, _ := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	receiver, _ := newStandaloneRetirementEngine(t, manifest, "a", "b")
	id := pathIDByName(t, receiver, "b")
	retirement := pathRetirementPayloadForReceiverPath(t, receiver, id, proto.PathRetirementReasonTransport)

	receiver.pathsMu.Lock()
	original := receiver.paths[id]
	duplicateConn, duplicatePeer := newMemoryPathPair()
	duplicate := newSyntheticRetirementSlot(id+1000, duplicateConn, original, retirement.RouteGeneration)
	receiver.retainedPaths[duplicate.id] = duplicate
	receiver.pathsMu.Unlock()
	t.Cleanup(func() { _ = duplicatePeer.Close() })

	if err := receiver.enqueuePathRetirementWork(pathRetirementWork{kind: pathRetirementWorkApply, payload: retirement}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-receiver.Closed():
	case <-time.After(2 * time.Second):
		t.Fatal("ambiguous exact retirement did not fail closed")
	}
	if !errors.Is(receiver.CloseErr(), ErrPeerProtocol) {
		t.Fatalf("close error=%v want ErrPeerProtocol", receiver.CloseErr())
	}
}

func TestLatePathRetirementDuringLocalTeardownDoesNotReplaceCloseCause(t *testing.T) {
	manifest, _ := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	receiver, _ := newStandaloneRetirementEngine(t, manifest, "a", "b")
	id := pathIDByName(t, receiver, "b")
	retirement := pathRetirementPayloadForReceiverPath(t, receiver, id, proto.PathRetirementReasonTransport)
	wire, err := retirement.Encode()
	if err != nil {
		t.Fatal(err)
	}
	receiver.setCloseErr(ErrZombie)
	if err := receiver.Close(); err != nil {
		t.Fatal(err)
	}
	receiver.recvMu.Lock()
	accepted := receiver.enqueueSequencedPathRetirementLocked(wire)
	finalErr, terminal := receiver.recvFinalErr, receiver.recvTerminal
	receiver.recvMu.Unlock()
	if !accepted || finalErr != nil || terminal {
		t.Fatalf("late PATH_RETIRE accepted/final/terminal=%t/%v/%t", accepted, finalErr, terminal)
	}
	if !errors.Is(receiver.CloseErr(), ErrZombie) {
		t.Fatalf("close error=%v, want ErrZombie", receiver.CloseErr())
	}
}

func TestPeerPathRetirementQueueSaturationStopsACKFrontier(t *testing.T) {
	manifest, _ := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	receiver, _ := newStandaloneRetirementEngine(t, manifest, "a", "b")
	id := pathIDByName(t, receiver, "b")
	retirement := pathRetirementPayloadForReceiverPath(t, receiver, id, proto.PathRetirementReasonTransport)

	entered := make(chan struct{})
	release := make(chan struct{})
	var enteredOnce sync.Once
	receiver.OnPathDeathSerial(func(event PathDeathEvent) {
		if event.ID == id {
			enteredOnce.Do(func() { close(entered) })
			<-release
		}
	})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	if err := receiver.enqueuePathRetirementWork(pathRetirementWork{kind: pathRetirementWorkApply, payload: retirement}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("retirement worker did not reach deterministic blocker")
	}

	for i := 1; i < pathRetirementInboxSize; i++ {
		queued := retirement
		queued.RouteGeneration = retirement.RouteGeneration + uint64(i+100)
		if err := receiver.enqueuePathRetirementWork(pathRetirementWork{kind: pathRetirementWorkApply, payload: queued}); err != nil {
			t.Fatalf("fill retirement queue at %d: %v", i, err)
		}
	}
	saturated := retirement
	saturated.RouteGeneration += 10_000
	wire, err := saturated.Encode()
	if err != nil {
		t.Fatal(err)
	}
	hdr := proto.Header{
		Version: proto.Version,
		Type:    proto.FrameCtrl,
		Flags:   proto.FlagsForCtrl(proto.CtrlPathRetire),
		Seq:     receiver.expectedRecvSeq,
	}
	receiver.recvMu.Lock()
	before := receiver.expectedRecvSeq
	receiver.recvQueue[before] = recvItem{
		isCtrl:  true,
		flags:   hdr.Flags,
		payload: wire,
		digest:  recvFrameDigest(hdr, wire),
	}
	packets := make([][]byte, 0)
	receiver.drainContiguousLocked(&packets)
	after := receiver.expectedRecvSeq
	terminal := receiver.recvTerminal
	finalErr := receiver.recvFinalErr
	receiver.recvMu.Unlock()
	if after != before {
		t.Fatalf("cumulative receive frontier advanced from %d to %d over saturated PATH_RETIRE", before, after)
	}
	if !terminal || !errors.Is(finalErr, ErrPeerProtocol) || !errors.Is(finalErr, errPathRetirementInboxFull) {
		t.Fatalf("saturation state terminal=%v err=%v", terminal, finalErr)
	}

	close(release)
	receiver.requestClose()
	select {
	case <-receiver.Closed():
	case <-time.After(2 * time.Second):
		t.Fatal("saturated retirement worker did not quiesce")
	}
}

func TestPeerPathRetirementWorkerIsTrackedByClose(t *testing.T) {
	manifest, _ := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	receiver, _ := newStandaloneRetirementEngine(t, manifest, "a", "b")
	id := pathIDByName(t, receiver, "b")
	retirement := pathRetirementPayloadForReceiverPath(t, receiver, id, proto.PathRetirementReasonTransport)
	entered := make(chan struct{})
	release := make(chan struct{})
	var enteredOnce sync.Once
	receiver.OnPathDeathSerial(func(event PathDeathEvent) {
		if event.ID == id {
			enteredOnce.Do(func() { close(entered) })
			<-release
		}
	})
	if err := receiver.enqueuePathRetirementWork(pathRetirementWork{kind: pathRetirementWorkApply, payload: retirement}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("retirement worker did not reach deterministic blocker")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- receiver.Close() }()
	select {
	case err := <-closeDone:
		t.Fatalf("Close returned before retirement worker: %v", err)
	case <-receiver.Closed():
		t.Fatal("Closed signaled before retirement worker returned")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not wait for retirement worker completion")
	}
	select {
	case <-receiver.Closed():
	case <-time.After(time.Second):
		t.Fatal("Closed did not signal after tracked worker completion")
	}
}

func TestPeerPathRetirementDefersAcrossAdmissionOutcome(t *testing.T) {
	manifest, targets := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{}.Clamp())
	server := New(SideServer, flow, Limits{}.Clamp())
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	configureRecursivePair(t, client, server, manifest)
	clientA, serverA := newMemoryPathPair()
	attachRecursivePath(t, client, server, "a", clientA, serverA)
	clientBBase, serverB := newMemoryPathPair()
	retirementCapture := &pathRetirementCounter{PathConn: clientBBase}
	attachRecursivePath(t, client, server, "b", retirementCapture, serverB)
	if err := client.SelectLocalTarget(targets["root"], targets["b"], "test"); err != nil {
		t.Fatal(err)
	}
	if err := server.SelectLocalTarget(targets["root"], targets["b"], "test"); err != nil {
		t.Fatal(err)
	}
	oldClientA := pathIDByName(t, client, "a")
	oldServerA := pathIDByName(t, server, "a")
	replacementClient, replacementServer := newMemoryPathPair()
	newClientA := activateRetainedReplacement(t, client, "a", replacementClient)
	newServerA := activateRetainedReplacement(t, server, "a", replacementServer)

	replacementClient.Fail(errors.New("injected death during path admission"))
	waitPathDetached(t, client, newClientA)
	time.Sleep(4 * pathRetirementRetry)
	if writes := retirementCapture.retirementWrites.Load(); writes != 0 {
		t.Fatalf("published PATH_RETIRE before local admission outcome: writes=%d", writes)
	}
	if _, ok := server.PathRef(newServerA); !ok {
		t.Fatal("peer applied retirement before its admission outcome")
	}

	client.CompletePathAdmission(oldClientA)
	eventuallyEngine(t, time.Second, func() bool { return retirementCapture.retirementWrites.Load() > 0 })
	time.Sleep(4 * pathRetirementRetry)
	if _, ok := server.PathRef(newServerA); !ok {
		t.Fatal("peer applied retirement while its admission was still live")
	}
	server.CompletePathAdmission(newServerA)
	waitPathDetached(t, server, newServerA)
	if _, ok := server.PathRef(pathIDByName(t, server, "b")); !ok {
		t.Fatal("admission-deferred retirement removed the survivor")
	}
	server.pathsMu.RLock()
	_, oldRetained := server.retainedPaths[oldServerA]
	server.pathsMu.RUnlock()
	if oldRetained {
		t.Fatal("completed admission retained its predecessor")
	}
}

type pathRetirementCounter struct {
	transport.PathConn
	retirementWrites atomic.Uint64
}

func (p *pathRetirementCounter) Write(frame []byte) (int, error) {
	if isPathRetirementFrame(frame) {
		p.retirementWrites.Add(1)
	}
	return p.PathConn.Write(frame)
}

type pathRetirementDropOnce struct {
	transport.PathConn
	dropped          atomic.Bool
	retirementWrites atomic.Uint64
}

func (p *pathRetirementDropOnce) Write(frame []byte) (int, error) {
	if isPathRetirementFrame(frame) {
		p.retirementWrites.Add(1)
		if p.dropped.CompareAndSwap(false, true) {
			return len(frame), nil
		}
	}
	return p.PathConn.Write(frame)
}

func isPathRetirementFrame(frame []byte) bool {
	if len(frame) < proto.HeaderSize {
		return false
	}
	hdr, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	return err == nil && hdr.Type == proto.FrameCtrl && proto.CtrlCodeFromFlags(hdr.Flags) == proto.CtrlPathRetire
}

func newStandaloneRetirementEngine(t *testing.T, manifest proto.GraphManifest, names ...string) (*Engine, map[string]*memoryPathConn) {
	t.Helper()
	e := New(SideServer, NewClientFlowID(), Limits{}.Clamp())
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	peers := make(map[string]*memoryPathConn, len(names))
	for _, name := range names {
		path, peer := newMemoryPathPair()
		peers[name] = peer
		spec := transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": name}}
		if _, err := e.AttachPath(path, spec); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_ = e.Close()
		for _, peer := range peers {
			_ = peer.Close()
		}
	})
	return e, peers
}

func activateRetainedReplacement(t *testing.T, e *Engine, name string, path transport.PathConn) uint32 {
	t.Helper()
	spec := transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": name}}
	binding, err := e.InferPathBinding(spec)
	if err != nil {
		t.Fatal(err)
	}
	id, err := e.PreparePathBound(path, spec, binding)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.StagePathAttach(id); err != nil {
		t.Fatal(err)
	}
	if err := e.ActivateStagedPath(id, true); err != nil {
		t.Fatal(err)
	}
	return id
}

func detachAdministrativePathForRetirementTest(t *testing.T, e *Engine, id uint32) pathDeparture {
	t.Helper()
	e.sendMu.Lock()
	runtime := e.localExecutionRuntime()
	e.pathsMu.Lock()
	slot := e.paths[id]
	if slot == nil {
		e.pathsMu.Unlock()
		e.sendMu.Unlock()
		t.Fatalf("path %d is absent", id)
	}
	departure := e.detachPathLocked(slot, runtime, transport.CauseCleanClose, nil, true)
	e.pathsMu.Unlock()
	e.sendMu.Unlock()
	return departure
}

func newSyntheticRetirementSlot(id uint32, conn transport.PathConn, source *pathSlot, routeGeneration uint64) *pathSlot {
	slot := &pathSlot{
		id:              id,
		gen:             source.gen + 1000,
		owner:           source.owner + 1000,
		conn:            conn,
		spec:            source.spec.Clone(),
		localTXTargetID: source.localTXTargetID,
		peerTXTargetID:  source.peerTXTargetID,
		writePermit:     newPathWritePermit(),
		quit:            make(chan struct{}),
		doneR:           make(chan struct{}),
		doneW:           make(chan struct{}),
		doneP:           make(chan struct{}),
		admissionDone:   make(chan struct{}),
	}
	slot.routeGeneration.Store(routeGeneration)
	slot.completeAdmission()
	return slot
}

func pathIDByName(t *testing.T, e *Engine, name string) uint32 {
	t.Helper()
	for _, path := range e.Paths() {
		if path.Spec.Opts["name"] == name {
			return path.ID
		}
	}
	t.Fatalf("path %q is absent", name)
	return 0
}

func pathRetirementPayloadForReceiverPath(t *testing.T, receiver *Engine, pathID uint32, reason proto.PathRetirementReason) proto.PathRetirementPayload {
	t.Helper()
	receiver.pathsMu.RLock()
	slot := receiver.paths[pathID]
	if slot == nil {
		receiver.pathsMu.RUnlock()
		t.Fatalf("path %d is absent", pathID)
	}
	payload := pathRetirementPayloadForReceiverSlot(t, receiver, slot, slot.routeGeneration.Load(), reason)
	receiver.pathsMu.RUnlock()
	return payload
}

func pathRetirementPayloadForReceiverSlot(t *testing.T, receiver *Engine, slot *pathSlot, generation uint64, reason proto.PathRetirementReason) proto.PathRetirementPayload {
	t.Helper()
	local := receiver.localGraphBinding()
	peer := receiver.peerGraphBinding()
	payload := proto.PathRetirementPayload{
		SessionEpoch:          proto.SessionEpoch(receiver.FlowID()),
		Direction:             peerSenderDirection(receiver.side),
		Reason:                reason,
		SenderGraphRevision:   peer.revision,
		SenderGraphDigest:     peer.digest,
		SenderTargetID:        slot.peerTXTargetID,
		ReceiverGraphRevision: local.revision,
		ReceiverGraphDigest:   local.digest,
		ReceiverTargetID:      slot.localTXTargetID,
		RouteGeneration:       generation,
	}
	if err := payload.Validate(); err != nil {
		t.Fatal(err)
	}
	return payload
}

func pathRetirementPayloadForTest(t *testing.T, sender *Engine, pathID uint32, reason proto.PathRetirementReason) proto.PathRetirementPayload {
	t.Helper()
	sender.pathsMu.RLock()
	slot := sender.paths[pathID]
	if slot == nil {
		sender.pathsMu.RUnlock()
		t.Fatalf("path %d is absent", pathID)
	}
	notice := peerPathRetirementNotice{
		localTargetID: slot.localTXTargetID, peerTargetID: slot.peerTXTargetID,
		routeGeneration: slot.routeGeneration.Load(), reason: reason,
	}
	sender.pathsMu.RUnlock()
	local := sender.localGraphBinding()
	peer := sender.peerGraphBinding()
	payload := proto.PathRetirementPayload{
		SessionEpoch: proto.SessionEpoch(sender.FlowID()), Direction: senderDirection(sender.side), Reason: notice.reason,
		SenderGraphRevision: local.revision, SenderGraphDigest: local.digest, SenderTargetID: notice.localTargetID,
		ReceiverGraphRevision: peer.revision, ReceiverGraphDigest: peer.digest, ReceiverTargetID: notice.peerTargetID,
		RouteGeneration: notice.routeGeneration,
	}
	if err := payload.Validate(); err != nil {
		t.Fatal(err)
	}
	return payload
}
