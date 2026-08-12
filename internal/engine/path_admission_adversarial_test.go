package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

const admissionAdversarialFloodCopies = 32

type admissionFloodPath struct {
	transport.PathConn
	controls   map[proto.CtrlCode]bool
	duplicates int
	injected   atomic.Uint64
}

type synchronousDeathWritePath struct {
	transport.PathConn
	callbackMu sync.Mutex
	callback   func(transport.DeathCause, error)
	entered    chan struct{}
	release    chan struct{}
	writeOnce  sync.Once
	deathOnce  sync.Once
}

func (p *synchronousDeathWritePath) OnDeath(fn func(transport.DeathCause, error)) {
	p.callbackMu.Lock()
	p.callback = fn
	p.callbackMu.Unlock()
}

func (p *synchronousDeathWritePath) Write(_ []byte) (int, error) {
	p.writeOnce.Do(func() { close(p.entered) })
	<-p.release
	err := errors.New("synchronous transport death")
	p.fireDeath(err)
	return 0, err
}

func (p *synchronousDeathWritePath) fireDeath(err error) {
	p.callbackMu.Lock()
	callback := p.callback
	p.callbackMu.Unlock()
	p.deathOnce.Do(func() {
		if callback != nil {
			callback(transport.CauseTransportError, err)
		}
	})
}

type admissionBlockingWritePath struct {
	transport.PathConn
	entered   chan struct{}
	unblock   chan struct{}
	writeOnce sync.Once
	closeOnce sync.Once
}

type admissionBlockingSuccessfulWritePath struct {
	transport.PathConn
	entered   chan struct{}
	release   chan struct{}
	writeOnce sync.Once
}

func (p *admissionBlockingSuccessfulWritePath) Write(frame []byte) (int, error) {
	p.writeOnce.Do(func() { close(p.entered) })
	<-p.release
	return len(frame), nil
}

func (p *admissionBlockingWritePath) Write(_ []byte) (int, error) {
	p.writeOnce.Do(func() { close(p.entered) })
	<-p.unblock
	return 0, net.ErrClosed
}

func (p *admissionBlockingWritePath) Close() error {
	p.closeOnce.Do(func() { close(p.unblock) })
	return p.PathConn.Close()
}

func (p *admissionFloodPath) Write(frame []byte) (int, error) {
	n, err := p.PathConn.Write(frame)
	if err != nil || n != len(frame) || len(frame) < proto.HeaderSize {
		return n, err
	}
	header, decodeErr := proto.DecodeHeader(frame[:proto.HeaderSize])
	if decodeErr != nil || header.Type != proto.FrameCtrl || !p.controls[proto.CtrlCodeFromFlags(header.Flags)] {
		return n, err
	}
	for i := 0; i < p.duplicates; i++ {
		duplicateN, duplicateErr := p.PathConn.Write(frame)
		if duplicateErr != nil || duplicateN != len(frame) {
			break
		}
		p.injected.Add(1)
	}
	return n, err
}

type admissionSetSizes struct {
	active       int
	pending      int
	staged       int
	retained     int
	predecessors int
	byLeaf       int
	byPath       int
	completed    int
	generations  []uint64
	inboxLens    []int
}

func TestPathAdmissionDuplicateControlFloodIsBounded(t *testing.T) {
	clientBase, serverBase := newMemoryPathPair()
	clientPath := &admissionFloodPath{
		PathConn:   clientBase,
		duplicates: admissionAdversarialFloodCopies,
		controls: map[proto.CtrlCode]bool{
			proto.CtrlPathAdmissionCommit:  true,
			proto.CtrlPathAdmissionConfirm: true,
			proto.CtrlPathAdmissionAck:     true,
		},
	}
	serverPath := &admissionFloodPath{
		PathConn:   serverBase,
		duplicates: admissionAdversarialFloodCopies,
		controls: map[proto.CtrlCode]bool{
			proto.CtrlPathAdmissionAck: true,
		},
	}

	client, server := establishHelloAdmissionPair(t, clientPath, serverPath)
	waitAdmissionCondition(t, 2*time.Second, "admission reservations to drain", func() bool {
		clientState := snapshotAdmissionSets(client)
		serverState := snapshotAdmissionSets(server)
		return clientState.byLeaf == 0 && clientState.byPath == 0 &&
			serverState.byLeaf == 0 && serverState.byPath == 0
	})

	if got := clientPath.injected.Load(); got < 3*admissionAdversarialFloodCopies {
		t.Fatalf("client injected %d duplicate controls, want at least %d", got, 3*admissionAdversarialFloodCopies)
	}
	if got := serverPath.injected.Load(); got < 3*admissionAdversarialFloodCopies {
		t.Fatalf("server injected %d duplicate ACKs, want at least %d", got, 3*admissionAdversarialFloodCopies)
	}
	assertSingleAdmissionGeneration(t, "client", snapshotAdmissionSets(client))
	assertSingleAdmissionGeneration(t, "server", snapshotAdmissionSets(server))
}

func TestPathAdmissionMutatedDuplicateDoesNotDisplaceOverlap(t *testing.T) {
	e, binding := newAdmissionAdversarialEngine(t, SideClient)
	oldBase, oldPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = oldPeer.Close() })
	old := &observedClosePath{PathConn: oldBase}
	oldID, err := e.AttachPathBound(old, transport.PathSpec{Transport: "memory"}, binding)
	if err != nil {
		t.Fatal(err)
	}

	replacement, replacementPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = replacementPeer.Close() })
	replacementID, valid := prepareBoundAdmission(t, e, replacement, binding, 0x21)
	if err := e.StagePathAttach(replacementID); err != nil {
		t.Fatal(err)
	}
	if err := e.ActivateStagedPath(replacementID, true); err != nil {
		t.Fatal(err)
	}

	mutated := valid
	mutated.ResponderPlanDigest[1] ^= 0xff
	if mutated.AdmissionID != valid.AdmissionID {
		t.Fatal("test mutation changed AdmissionID")
	}
	if err := e.BindPathAdmission(replacementID, mutated); err == nil {
		t.Fatal("mutated duplicate admission binding was accepted")
	}
	if err := e.CompletePathAdmissionBinding(replacementID, mutated); err == nil {
		t.Fatal("mutated duplicate completed the valid admission")
	}

	assertAdmissionOverlap(t, e, replacementID, oldID)
	if old.closed.Load() {
		t.Fatal("mutated duplicate closed the valid predecessor")
	}
	if err := e.CompletePathAdmissionBinding(replacementID, valid); err != nil {
		t.Fatalf("valid completion after mutation: %v", err)
	}
	waitAdmissionCondition(t, time.Second, "valid predecessor release", old.closed.Load)
}

func TestPathAdmissionConcurrentSameLeafPrepareStageHasOneWinner(t *testing.T) {
	e, binding := newAdmissionAdversarialEngine(t, SideClient)
	const competitors = 64

	type candidate struct {
		path *memoryPathConn
		peer *memoryPathConn
		id   uint32
		err  error
	}
	candidates := make([]candidate, competitors)
	for i := range candidates {
		candidates[i].path, candidates[i].peer = newMemoryPathPair()
		t.Cleanup(func() { _ = candidates[i].peer.Close() })
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range candidates {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			id, err := e.PreparePathBound(candidates[index].path, transport.PathSpec{Transport: "memory"}, binding)
			if err == nil {
				err = e.StagePathAttach(id)
			}
			candidates[index].id = id
			candidates[index].err = err
		}(i)
	}
	close(start)
	wg.Wait()

	winners := 0
	var winnerID uint32
	for i := range candidates {
		switch {
		case candidates[i].err == nil:
			winners++
			winnerID = candidates[i].id
		case errors.Is(candidates[i].err, ErrPathAttachInProgress):
		default:
			t.Fatalf("candidate %d error=%v, want %v", i, candidates[i].err, ErrPathAttachInProgress)
		}
	}
	if winners != 1 {
		t.Fatalf("same-leaf admission winners=%d, want 1", winners)
	}
	state := snapshotAdmissionSets(e)
	if state.pending != 0 || state.staged != 1 || state.byLeaf != 1 || state.byPath != 1 {
		t.Fatalf("serialized admission state=%+v", state)
	}
	e.pathsMu.RLock()
	_, staged := e.stagedPaths[winnerID]
	e.pathsMu.RUnlock()
	if !staged {
		t.Fatalf("winner path %d is not the sole staged path", winnerID)
	}
	e.AbortPathAttach(winnerID, nil)
}

func TestPathAdmissionStaleCompletionCannotReleaseNewerPredecessor(t *testing.T) {
	e, binding := newAdmissionAdversarialEngine(t, SideClient)
	initial, initialPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = initialPeer.Close() })
	if _, err := e.AttachPathBound(initial, transport.PathSpec{Transport: "memory"}, binding); err != nil {
		t.Fatal(err)
	}

	firstBase, firstPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = firstPeer.Close() })
	first := &observedClosePath{PathConn: firstBase}
	firstID, firstBinding := prepareBoundAdmission(t, e, first, binding, 0x31)
	if err := e.StagePathAttach(firstID); err != nil {
		t.Fatal(err)
	}
	if err := e.ActivateStagedPath(firstID, true); err != nil {
		t.Fatal(err)
	}
	if err := e.CompletePathAdmissionBinding(firstID, firstBinding); err != nil {
		t.Fatal(err)
	}

	second, secondPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = secondPeer.Close() })
	secondID, secondBinding := prepareBoundAdmission(t, e, second, binding, 0x32)
	if err := e.StagePathAttach(secondID); err != nil {
		t.Fatal(err)
	}
	if err := e.ActivateStagedPath(secondID, true); err != nil {
		t.Fatal(err)
	}

	if err := e.CompletePathAdmissionBinding(secondID, firstBinding); err == nil {
		t.Fatal("stale completion binding released a newer admission")
	}
	assertAdmissionOverlap(t, e, secondID, firstID)
	if first.closed.Load() {
		t.Fatal("stale completion closed the newer predecessor")
	}
	if err := e.CompletePathAdmissionBinding(secondID, secondBinding); err != nil {
		t.Fatalf("current completion binding: %v", err)
	}
	waitAdmissionCondition(t, time.Second, "newer predecessor release", first.closed.Load)
}

func TestPathAdmissionCloseQuiescesEveryLifecycleSet(t *testing.T) {
	tests := []struct {
		name  string
		build func(*testing.T, *Engine, PathBinding) []*pathSlot
	}{
		{
			name: "pending",
			build: func(t *testing.T, e *Engine, binding PathBinding) []*pathSlot {
				path, peer := newMemoryPathPair()
				t.Cleanup(func() { _ = peer.Close() })
				id, err := e.PreparePathBound(path, transport.PathSpec{Transport: "memory"}, binding)
				if err != nil {
					t.Fatal(err)
				}
				return []*pathSlot{admissionPathSlot(t, e, id)}
			},
		},
		{
			name: "staged",
			build: func(t *testing.T, e *Engine, binding PathBinding) []*pathSlot {
				path, peer := newMemoryPathPair()
				t.Cleanup(func() { _ = peer.Close() })
				id, err := e.PreparePathBound(path, transport.PathSpec{Transport: "memory"}, binding)
				if err != nil {
					t.Fatal(err)
				}
				if err := e.StagePathAttach(id); err != nil {
					t.Fatal(err)
				}
				return []*pathSlot{admissionPathSlot(t, e, id)}
			},
		},
		{
			name: "active-overlap",
			build: func(t *testing.T, e *Engine, binding PathBinding) []*pathSlot {
				old, oldPeer := newMemoryPathPair()
				t.Cleanup(func() { _ = oldPeer.Close() })
				oldID, err := e.AttachPathBound(old, transport.PathSpec{Transport: "memory"}, binding)
				if err != nil {
					t.Fatal(err)
				}
				candidate, candidatePeer := newMemoryPathPair()
				t.Cleanup(func() { _ = candidatePeer.Close() })
				candidateID, _ := prepareBoundAdmission(t, e, candidate, binding, 0x41)
				if err := e.StagePathAttach(candidateID); err != nil {
					t.Fatal(err)
				}
				if err := e.ActivateStagedPath(candidateID, true); err != nil {
					t.Fatal(err)
				}
				return []*pathSlot{admissionPathSlot(t, e, oldID), admissionPathSlot(t, e, candidateID)}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e, binding := newAdmissionAdversarialEngine(t, SideClient)
			slots := test.build(t, e, binding)
			startedReaders := make(map[*pathSlot]bool, len(slots))
			startedWriters := make(map[*pathSlot]bool, len(slots))
			e.pathsMu.RLock()
			for _, slot := range slots {
				_, pending := e.pendingPaths[slot.id]
				startedReaders[slot] = !pending
				_, staged := e.stagedPaths[slot.id]
				startedWriters[slot] = !pending && !staged
			}
			e.pathsMu.RUnlock()

			if err := e.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			state := snapshotAdmissionSets(e)
			if state.active != 0 || state.pending != 0 || state.staged != 0 || state.retained != 0 ||
				state.predecessors != 0 || state.byLeaf != 0 || state.byPath != 0 || state.completed != 0 || len(state.generations) != 0 {
				t.Fatalf("Close left admission state: %+v", state)
			}
			for _, slot := range slots {
				if startedReaders[slot] {
					waitAdmissionChannel(t, slot.doneR, "path reader")
				}
				if startedWriters[slot] {
					waitAdmissionChannel(t, slot.doneW, "path writer")
				}
				select {
				case <-slot.conn.(*memoryPathConn).closed:
				case <-time.After(time.Second):
					t.Fatalf("path %d transport was not closed", slot.id)
				}
			}
		})
	}
}

func TestPathAdmissionRetainedActivationReplaysUnackedDataOnce(t *testing.T) {
	client, server, clientBinding, serverBinding := newAdmissionAdversarialEnginePair(t)
	oldClient, oldServer := newMemoryPathPair()
	oldClient.dropWrites.Store(true)
	if _, err := client.AttachPathBound(oldClient, transport.PathSpec{Transport: "memory"}, clientBinding); err != nil {
		t.Fatal(err)
	}
	if _, err := server.AttachPathBound(oldServer, transport.PathSpec{Transport: "memory"}, serverBinding); err != nil {
		t.Fatal(err)
	}

	newClientBase, newServer := newMemoryPathPair()
	newClient := &captureDispatchPath{PathConn: newClientBase}
	if _, err := server.AttachPathBound(newServer, transport.PathSpec{Transport: "memory"}, serverBinding); err != nil {
		t.Fatal(err)
	}
	newClientID, _ := prepareBoundAdmission(t, client, newClient, clientBinding, 0x51)
	if err := client.StagePathAttach(newClientID); err != nil {
		t.Fatal(err)
	}

	payload := []byte("unacked-immediately-before-retained-activation")
	if _, err := client.SendData(payload); err != nil {
		t.Fatalf("SendData on predecessor: %v", err)
	}
	if got := newClient.dataSequences(); len(got) != 0 {
		t.Fatalf("staged successor carried DATA before activation: %v", got)
	}
	if err := client.ActivateStagedPath(newClientID, true); err != nil {
		t.Fatal(err)
	}

	if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	n, err := server.Recv(got)
	if err != nil {
		t.Fatalf("Recv replay: %v", err)
	}
	if n != len(payload) || !bytes.Equal(got[:n], payload) {
		t.Fatalf("replayed payload=%q want=%q", got[:n], payload)
	}
	waitAdmissionCondition(t, time.Second, "exactly one successor replay", func() bool {
		return len(newClient.dataSequences()) >= 1
	})
	if sequences := newClient.dataSequences(); len(sequences) != 1 || sequences[0] != 0 {
		t.Fatalf("successor DATA sequences=%v, want [0]", sequences)
	}

	if err := server.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	extra := make([]byte, 1)
	if n, err := server.Recv(extra); n != 0 || !errors.Is(err, ErrReadDeadlineExceeded) {
		t.Fatalf("duplicate application delivery n=%d err=%v, want deadline", n, err)
	}
}

func TestPathAdmissionActivationDoesNotDeadlockSynchronousDeathCallback(t *testing.T) {
	e, binding := newAdmissionAdversarialEngine(t, SideClient)
	oldBase, oldPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = oldPeer.Close() })
	old := &synchronousDeathWritePath{
		PathConn: oldBase,
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
	}
	oldID, err := e.AttachPathBound(old, transport.PathSpec{Transport: "memory"}, binding)
	if err != nil {
		t.Fatal(err)
	}
	oldSlot := admissionPathSlot(t, e, oldID)

	sendDone := make(chan error, 1)
	go func() {
		_, err := e.SendData([]byte("write-held-during-activation"))
		sendDone <- err
	}()
	waitAdmissionChannel(t, old.entered, "predecessor write")

	replacement, replacementPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = replacementPeer.Close() })
	replacementID, _ := prepareBoundAdmission(t, e, replacement, binding, 0x61)
	if err := e.StagePathAttach(replacementID); err != nil {
		t.Fatal(err)
	}
	activated := make(chan error, 1)
	go func() { activated <- e.ActivateStagedPath(replacementID, true) }()
	waitAdmissionCondition(t, time.Second, "predecessor TX fence", func() bool {
		return !oldSlot.txEnabled.Load()
	})
	close(old.release)

	select {
	case err := <-activated:
		if err != nil {
			t.Fatalf("ActivateStagedPath: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("activation deadlocked with synchronous OnDeath callback")
	}
	select {
	case <-sendDone:
	case <-time.After(time.Second):
		t.Fatal("blocked predecessor send did not return")
	}
	state := snapshotAdmissionSets(e)
	if state.retained != 0 || state.predecessors != 0 {
		t.Fatalf("dead predecessor survived activation fence: %+v", state)
	}
}

func TestPathAdmissionActivationDoesNotResurrectPredecessorRetiredAfterDrain(t *testing.T) {
	e, binding := newAdmissionAdversarialEngine(t, SideClient)
	old, oldPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = oldPeer.Close() })
	oldID, err := e.AttachPathBound(old, transport.PathSpec{Transport: "memory"}, binding)
	if err != nil {
		t.Fatal(err)
	}
	oldRef, ok := e.PathRef(oldID)
	if !ok {
		t.Fatal("predecessor has no exact path reference")
	}

	replacement, replacementPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = replacementPeer.Close() })
	replacementID, _ := prepareBoundAdmission(t, e, replacement, binding, 0x74)
	if err := e.StagePathAttach(replacementID); err != nil {
		t.Fatal(err)
	}

	var retireErr error
	e.activationAfterPredecessorDrain = func() {
		retireErr = e.RetirePath(oldRef, errors.New("peer retired drained predecessor"))
	}
	if err := e.ActivateStagedPath(replacementID, true); err != nil {
		t.Fatalf("ActivateStagedPath: %v", err)
	}
	e.activationAfterPredecessorDrain = nil
	if retireErr != nil {
		t.Fatalf("RetirePath: %v", retireErr)
	}
	assertRetiredPredecessorWasNotResurrected(t, e, oldID, replacementID)
}

func TestPathAdmissionActivationAcceptsPredecessorRetiredWhileDrainWaits(t *testing.T) {
	e, binding := newAdmissionAdversarialEngine(t, SideClient)
	old, oldPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = oldPeer.Close() })
	oldID, err := e.AttachPathBound(old, transport.PathSpec{Transport: "memory"}, binding)
	if err != nil {
		t.Fatal(err)
	}
	oldRef, ok := e.PathRef(oldID)
	if !ok {
		t.Fatal("predecessor has no exact path reference")
	}
	oldSlot := admissionPathSlot(t, e, oldID)
	if err := oldSlot.acquireWrite(context.Background()); err != nil {
		t.Fatal(err)
	}

	replacement, replacementPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = replacementPeer.Close() })
	replacementID, _ := prepareBoundAdmission(t, e, replacement, binding, 0x77)
	if err := e.StagePathAttach(replacementID); err != nil {
		oldSlot.releaseWrite()
		t.Fatal(err)
	}

	activated := make(chan error, 1)
	go func() { activated <- e.ActivateStagedPath(replacementID, true) }()
	waitAdmissionCondition(t, time.Second, "predecessor drain fence", func() bool {
		return oldSlot.maintenance.Load() && !oldSlot.txEnabled.Load()
	})
	if err := e.RetirePath(oldRef, errors.New("peer retired predecessor during drain")); err != nil {
		oldSlot.releaseWrite()
		t.Fatal(err)
	}
	oldSlot.releaseWrite()
	if err := <-activated; err != nil {
		t.Fatalf("ActivateStagedPath: %v", err)
	}
	assertRetiredPredecessorWasNotResurrected(t, e, oldID, replacementID)
}

func TestPathAdmissionActivationRejectsRetiredUndrainedProbeWriter(t *testing.T) {
	e, binding := newAdmissionAdversarialEngine(t, SideClient)
	oldBase, oldPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = oldPeer.Close() })
	old := newBlockingProbePath(oldBase, 1)
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(old.release) }) })
	oldID, err := e.AttachPathBound(old, transport.PathSpec{Transport: "memory"}, binding)
	if err != nil {
		t.Fatal(err)
	}
	oldRef, ok := e.PathRef(oldID)
	if !ok {
		t.Fatal("predecessor has no exact path reference")
	}
	oldSlot := admissionPathSlot(t, e, oldID)
	e.issuePathProbe(oldSlot)
	select {
	case <-old.started:
	case <-time.After(time.Second):
		t.Fatal("probe did not enter predecessor Conn.Write")
	}

	replacement, replacementPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = replacementPeer.Close() })
	replacementID, _ := prepareBoundAdmission(t, e, replacement, binding, 0x78)
	if err := e.StagePathAttach(replacementID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	activated := make(chan error, 1)
	go func() { activated <- e.activateStagedPathContext(ctx, replacementID, true, true) }()
	waitAdmissionCondition(t, time.Second, "predecessor probe drain fence", func() bool {
		return oldSlot.maintenance.Load() && !oldSlot.txEnabled.Load()
	})
	if err := e.RetirePath(oldRef, errors.New("retired while probe write remained blocked")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-activated:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("activation error=%v want undrained deadline", err)
		}
	case <-time.After(time.Second):
		t.Fatal("activation did not honor its probe-drain deadline")
	}
	e.pathsMu.RLock()
	published := e.paths[replacementID] != nil
	e.pathsMu.RUnlock()
	if published {
		t.Fatal("successor was published while retired predecessor probe still owned Conn.Write")
	}
	releaseOnce.Do(func() { close(old.release) })
}

func assertRetiredPredecessorWasNotResurrected(t *testing.T, e *Engine, predecessorID, successorID uint32) {
	t.Helper()
	e.pathsMu.RLock()
	defer e.pathsMu.RUnlock()
	if e.paths[predecessorID] != nil || e.retainedPaths[predecessorID] != nil {
		t.Fatalf("retired predecessor %d was resurrected", predecessorID)
	}
	if successor := e.paths[successorID]; successor == nil || !successor.txEnabled.Load() {
		t.Fatalf("successor %d is not active and TX-enabled", successorID)
	}
	if predecessors := e.pathPredecessors[successorID]; len(predecessors) != 0 {
		t.Fatalf("successor %d retained retired predecessors %v", successorID, predecessors)
	}
	if e.activeID != successorID {
		t.Fatalf("active path=%d want successor=%d", e.activeID, successorID)
	}
}

func TestPathAdmissionGracefulCloseDuringFenceReleasesStagedReservation(t *testing.T) {
	e, binding := newAdmissionAdversarialEngine(t, SideClient)
	oldBase, oldPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = oldPeer.Close() })
	old := &admissionBlockingSuccessfulWritePath{
		PathConn: oldBase,
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
	}
	oldID, err := e.AttachPathBound(old, transport.PathSpec{Transport: "memory"}, binding)
	if err != nil {
		t.Fatal(err)
	}
	oldSlot := admissionPathSlot(t, e, oldID)

	sendDone := make(chan error, 1)
	go func() {
		_, err := e.SendData([]byte("write-held-until-graceful-close"))
		sendDone <- err
	}()
	waitAdmissionChannel(t, old.entered, "predecessor write")

	replacement, replacementPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = replacementPeer.Close() })
	replacementID, _ := prepareBoundAdmission(t, e, replacement, binding, 0x75)
	if err := e.StagePathAttach(replacementID); err != nil {
		t.Fatal(err)
	}
	activated := make(chan error, 1)
	go func() {
		activated <- e.activateStagedPathContext(context.Background(), replacementID, true, true)
	}()
	waitAdmissionCondition(t, time.Second, "predecessor TX fence", func() bool {
		return oldSlot.maintenance.Load() && !oldSlot.txEnabled.Load()
	})
	e.sendClosing.Store(true)
	close(old.release)

	if err := <-activated; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("activation after graceful-close gate error=%v, want %v", err, net.ErrClosed)
	}
	if err := <-sendDone; err != nil {
		t.Fatalf("predecessor send after fence release: %v", err)
	}
	assertPathAdmissionReleased(t, e, replacementID)
}

func TestPathAdmissionTransferredReservationExpiresOnOriginalToken(t *testing.T) {
	e, binding := newAdmissionAdversarialEngineWithLimits(t, SideClient, Limits{
		MigrationBudget:     100 * time.Millisecond,
		ZombieMaxMigrations: 10,
	})
	resource := leafmobility.MustNewResource(leafmobility.ScopeEndpoint)
	newClaim := func() *leafmobility.Claim {
		driver := &enginePlanDriver{
			operation: leafmobility.OperationTCPRepair,
			evidence:  leafmobility.EvidenceDigest{0x76},
		}
		return leafmobility.MustNewDrivenClaim(leafmobility.Facts{
			Kind:       leafmobility.KindRawTCP,
			Role:       leafmobility.RoleDialer,
			Session:    leafmobility.SessionStream,
			Generation: leafmobility.NextGeneration(),
		}, driver, resource)
	}

	oldBase, oldPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = oldPeer.Close() })
	oldID, err := e.AttachPathBound(&claimedMemoryPath{PathConn: oldBase, claim: newClaim()}, transport.PathSpec{Transport: "memory"}, binding)
	if err != nil {
		t.Fatal(err)
	}

	replacementBase, replacementPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = replacementPeer.Close() })
	replacementID, _ := prepareBoundAdmission(t, e,
		&claimedMemoryPath{PathConn: replacementBase, claim: newClaim()}, binding, 0x76)
	if err := e.StagePathAttach(replacementID); err != nil {
		t.Fatal(err)
	}
	if err := e.ActivateStagedPath(replacementID, true); err != nil {
		t.Fatal(err)
	}

	e.pathsMu.RLock()
	key := e.pathAdmissionByPath[replacementID]
	token := e.pathAdmissionByLeaf[key].token
	e.pathsMu.RUnlock()
	if token == nil {
		t.Fatal("activated admission has no immutable token")
	}

	failMemoryPath(t, e, replacementID, replacementBase, errors.New("successor failed before admission deadline"))
	if active := e.ActivePath(); active != oldID {
		t.Fatalf("active path after successor death=%d, want predecessor=%d", active, oldID)
	}
	e.pathsMu.RLock()
	transferredKey, transferred := e.pathAdmissionByPath[oldID]
	transferredReservation := e.pathAdmissionByLeaf[key]
	e.pathsMu.RUnlock()
	if !transferred || transferredKey != key || transferredReservation.pathID != oldID || transferredReservation.token != token {
		t.Fatalf("reservation did not transfer with immutable token: transferred=%t key=%+v reservation=%+v", transferred, transferredKey, transferredReservation)
	}

	probeClaim := newClaim()
	if reservation, err := leafmobility.ReserveAdmissions(probeClaim); !errors.Is(err, leafmobility.ErrResourceAdmissionActive) {
		reservation.Release()
		t.Fatalf("shared resource before timeout error=%v, want %v", err, leafmobility.ErrResourceAdmissionActive)
	}

	deadline := time.Now().Add(time.Second)
	var probeReservation *leafmobility.AdmissionReservation
	for probeReservation == nil && time.Now().Before(deadline) {
		reservation, err := leafmobility.ReserveAdmissions(probeClaim)
		if err == nil {
			probeReservation = reservation
			break
		}
		if !errors.Is(err, leafmobility.ErrResourceAdmissionActive) {
			t.Fatalf("shared resource after transfer returned unexpected error: %v", err)
		}
		time.Sleep(time.Millisecond)
	}
	if probeReservation == nil {
		t.Fatal("transferred admission did not release shared resource at its original deadline")
	}
	probeReservation.Release()
	assertPathAdmissionReleased(t, e, oldID)
}

func TestPathAdmissionCommittedSuccessorDeathDoesNotRestorePredecessor(t *testing.T) {
	e, binding := newAdmissionAdversarialEngine(t, SideServer)
	oldBase, oldPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = oldPeer.Close() })
	old := &observedClosePath{PathConn: oldBase}
	oldID, err := e.AttachPathBound(old, transport.PathSpec{Transport: "memory"}, binding)
	if err != nil {
		t.Fatal(err)
	}

	replacement, replacementPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = replacementPeer.Close() })
	replacementID, _ := prepareBoundAdmission(t, e, replacement, binding, 0x62)
	if err := e.StagePathAttach(replacementID); err != nil {
		t.Fatal(err)
	}
	if err := e.activateStagedPathContext(context.Background(), replacementID, true, false); err != nil {
		t.Fatal(err)
	}
	failMemoryPath(t, e, replacementID, replacement, errors.New("successor failed after peer activation"))

	waitAdmissionCondition(t, time.Second, "unsafe predecessor retirement", old.closed.Load)
	if active := e.ActivePath(); active == oldID {
		t.Fatalf("committed successor failure restored predecessor %d", oldID)
	}
}

func TestPathAdmissionFenceTimeoutProcessesPendingPredecessorDeath(t *testing.T) {
	e, binding := newAdmissionAdversarialEngine(t, SideClient)
	oldBase, oldPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = oldPeer.Close() })
	old := &synchronousDeathWritePath{
		PathConn: oldBase,
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
	}
	oldID, err := e.AttachPathBound(old, transport.PathSpec{Transport: "memory"}, binding)
	if err != nil {
		t.Fatal(err)
	}
	oldSlot := admissionPathSlot(t, e, oldID)
	sendDone := make(chan error, 1)
	go func() {
		_, err := e.SendData([]byte("held-until-fence-timeout"))
		sendDone <- err
	}()
	waitAdmissionChannel(t, old.entered, "blocked predecessor write")

	replacement, replacementPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = replacementPeer.Close() })
	replacementID, _ := prepareBoundAdmission(t, e, replacement, binding, 0x64)
	if err := e.StagePathAttach(replacementID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	activated := make(chan error, 1)
	go func() { activated <- e.activateStagedPathContext(ctx, replacementID, true, true) }()
	waitAdmissionCondition(t, time.Second, "predecessor maintenance fence", func() bool {
		return oldSlot.maintenance.Load() && !oldSlot.txEnabled.Load()
	})
	old.fireDeath(errors.New("death while activation waits for write permit"))
	if err := <-activated; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("activation error=%v, want deadline", err)
	}
	close(old.release)
	select {
	case <-sendDone:
	case <-time.After(time.Second):
		t.Fatal("blocked predecessor send did not return")
	}
	waitAdmissionCondition(t, time.Second, "pending predecessor death processing", func() bool {
		e.pathsMu.RLock()
		defer e.pathsMu.RUnlock()
		return e.paths[oldID] == nil
	})
}

func TestPathAdmissionControlWriteHonorsContextBudget(t *testing.T) {
	e, binding := newAdmissionAdversarialEngine(t, SideClient)
	base, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = peer.Close() })
	path := &admissionBlockingWritePath{
		PathConn: base,
		entered:  make(chan struct{}),
		unblock:  make(chan struct{}),
	}
	id, err := e.PreparePathBound(path, transport.PathSpec{Transport: "memory"}, binding)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.StagePathAttach(id); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	started := time.Now()
	err = e.WritePathAdmissionControlContext(ctx, id, proto.CtrlPathAdmissionAck, []byte("bounded"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked control write error=%v, want deadline", err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("blocked control write exceeded budget by %v", elapsed)
	}
	waitAdmissionChannel(t, path.entered, "bounded control write")
	waitAdmissionCondition(t, time.Second, "timed-out admission path removal", func() bool {
		return snapshotAdmissionSets(e).staged == 0
	})
}

func TestGracefulCloseClosesAdmissionGateBeforeByeCompletes(t *testing.T) {
	e, binding := newAdmissionAdversarialEngine(t, SideClient)
	base, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = peer.Close() })
	path := &admissionBlockingWritePath{
		PathConn: base,
		entered:  make(chan struct{}),
		unblock:  make(chan struct{}),
	}
	if _, err := e.AttachPathBound(path, transport.PathSpec{Transport: "memory"}, binding); err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- e.GracefulClose(proto.ByeNormal) }()
	waitAdmissionChannel(t, path.entered, "blocked graceful BYE")

	candidate, candidatePeer := newMemoryPathPair()
	t.Cleanup(func() { _ = candidatePeer.Close() })
	if _, err := e.PreparePathBound(candidate, transport.PathSpec{Transport: "memory"}, binding); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("prepare during graceful close error=%v, want %v", err, net.ErrClosed)
	}
	_ = path.Close()
	_ = e.Close()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("graceful close did not finish after releasing BYE write")
	}
}

func TestCompletedAdmissionReplayKeepsOriginalDeadline(t *testing.T) {
	e, binding := newAdmissionAdversarialEngineWithLimits(t, SideClient, Limits{
		MigrationBudget: 30 * time.Millisecond,
	})
	base, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = peer.Close() })
	path := &admissionBlockingWritePath{
		PathConn: base,
		entered:  make(chan struct{}),
		unblock:  make(chan struct{}),
	}
	id, err := e.AttachPathBound(path, transport.PathSpec{Transport: "memory"}, binding)
	if err != nil {
		t.Fatal(err)
	}
	local := e.localGraphBinding()
	commit := admissionCommit(
		proto.PathAdmissionKindBridge,
		proto.SessionEpoch(e.FlowID()),
		proto.PathAdmissionID{0x71},
		senderDirection(SideClient),
		local.revision,
		local.digest,
		binding.LocalTXTargetID,
		binding.PeerTXTargetID,
		0,
		[]byte("proposal"),
		[]byte("response"),
	)
	activated := proto.PathAdmissionAck{
		PathAdmissionBinding: commit.PathAdmissionBinding,
		Phase:                proto.PathAdmissionPhaseActivated,
		Code:                 proto.AckOK,
	}
	activatedWire, err := activated.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.rememberCompletedPathAdmission(id, commit.PathAdmissionBinding, proto.PathAdmissionPhaseFinal, activatedWire); err != nil {
		t.Fatal(err)
	}
	e.pathsMu.RLock()
	slot := e.paths[id]
	completed := e.completedPathAdmissions[commit.PathAdmissionBinding]
	if completed == nil {
		e.pathsMu.RUnlock()
		t.Fatal("completed admission replay was not registered at engine scope")
	}
	expires := completed.expires
	e.pathsMu.RUnlock()
	receipt := proto.PathAdmissionAck{
		PathAdmissionBinding: commit.PathAdmissionBinding,
		Phase:                proto.PathAdmissionPhaseFinal,
		Code:                 proto.AckOK,
	}
	receiptWire, err := receipt.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !e.routePathAdmissionControl(slot, proto.CtrlPathAdmissionAck, receiptWire) {
		t.Fatal("completed admission receipt was not consumed")
	}
	waitAdmissionChannel(t, path.entered, "completed admission replay write")
	waitAdmissionCondition(t, 500*time.Millisecond, "fixed-deadline replay retirement", func() bool {
		_, ok := e.PathRef(id)
		return !ok
	})
	if err := e.CloseErr(); errors.Is(err, ErrPathAdmissionOutcomeUnknown) {
		t.Fatalf("completed replay expiry closed session as outcome unknown: %v", err)
	}
	if time.Now().After(expires.Add(300 * time.Millisecond)) {
		t.Fatalf("terminal replay outlived original deadline %v", expires)
	}
}

func TestCompletedAdmissionReplayReplacementIsBenign(t *testing.T) {
	e, binding := newAdmissionAdversarialEngine(t, SideClient)
	base, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = peer.Close() })
	path := &admissionBlockingWritePath{
		PathConn: base,
		entered:  make(chan struct{}),
		unblock:  make(chan struct{}),
	}
	id, err := e.AttachPathBound(path, transport.PathSpec{Transport: "memory"}, binding)
	if err != nil {
		t.Fatal(err)
	}
	local := e.localGraphBinding()
	makeCommit := func(token byte, base uint64) proto.PathAdmissionCommit {
		return admissionCommit(
			proto.PathAdmissionKindBridge, proto.SessionEpoch(e.FlowID()), proto.PathAdmissionID{token},
			senderDirection(SideClient), local.revision, local.digest,
			binding.LocalTXTargetID, binding.PeerTXTargetID, base,
			[]byte{token, 1}, []byte{token, 2},
		)
	}
	oldCommit := makeCommit(0x72, 0)
	oldActivated := proto.PathAdmissionAck{
		PathAdmissionBinding: oldCommit.PathAdmissionBinding,
		Phase:                proto.PathAdmissionPhaseActivated,
		Code:                 proto.AckOK,
	}
	oldActivatedWire, err := oldActivated.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.rememberCompletedPathAdmission(id, oldCommit.PathAdmissionBinding, proto.PathAdmissionPhaseFinal, oldActivatedWire); err != nil {
		t.Fatal(err)
	}
	receipt := proto.PathAdmissionAck{
		PathAdmissionBinding: oldCommit.PathAdmissionBinding,
		Phase:                proto.PathAdmissionPhaseFinal,
		Code:                 proto.AckOK,
	}
	receiptWire, err := receipt.Encode()
	if err != nil {
		t.Fatal(err)
	}
	e.pathsMu.RLock()
	slot := e.paths[id]
	e.pathsMu.RUnlock()
	if !e.routePathAdmissionControl(slot, proto.CtrlPathAdmissionAck, receiptWire) {
		t.Fatal("old completed receipt was not consumed")
	}
	waitAdmissionChannel(t, path.entered, "old completed replay write")

	newCommit := makeCommit(0x73, 1)
	newActivated := proto.PathAdmissionAck{
		PathAdmissionBinding: newCommit.PathAdmissionBinding,
		Phase:                proto.PathAdmissionPhaseActivated,
		Code:                 proto.AckOK,
	}
	newActivatedWire, err := newActivated.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.rememberCompletedPathAdmission(id, newCommit.PathAdmissionBinding, proto.PathAdmissionPhaseFinal, newActivatedWire); err != nil {
		t.Fatal(err)
	}
	e.pathsMu.RLock()
	_, oldPresent := e.completedPathAdmissions[oldCommit.PathAdmissionBinding]
	_, newPresent := e.completedPathAdmissions[newCommit.PathAdmissionBinding]
	e.pathsMu.RUnlock()
	if oldPresent || !newPresent {
		t.Fatalf("completed replacement state old=%t new=%t", oldPresent, newPresent)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if err := e.CloseErr(); errors.Is(err, ErrPathAdmissionOutcomeUnknown) {
		t.Fatalf("stale completed replay closed session as outcome unknown: %v", err)
	}
}

func TestUnknownPathAdmissionLinearizesWithCleanClose(t *testing.T) {
	for i := 0; i < 500; i++ {
		e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
		start := make(chan struct{})
		var wg sync.WaitGroup
		var admissionWon atomic.Bool
		var closeErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			e.BeginGracefulClose()
			closeErr = e.Close()
		}()
		go func() {
			defer wg.Done()
			<-start
			admissionWon.Store(e.closeForUnknownPathAdmissionIfLive())
		}()
		close(start)
		wg.Wait()

		gotUnknown := errors.Is(e.CloseErr(), ErrPathAdmissionOutcomeUnknown)
		if admissionWon.Load() != gotUnknown {
			t.Fatalf("iteration %d: admissionWon=%t closeErr=%v directCloseErr=%v",
				i, admissionWon.Load(), e.CloseErr(), closeErr)
		}
		if closeErr != nil {
			t.Fatalf("iteration %d: physical Close returned %v", i, closeErr)
		}
	}
}

func TestPathAdmissionStaleTerminalSourceRequiresCurrentRouteRetry(t *testing.T) {
	e, pathBinding := newAdmissionAdversarialEngine(t, SideClient)
	old, oldPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = oldPeer.Close() })
	oldID, err := e.AttachPathBound(old, transport.PathSpec{Transport: "memory"}, pathBinding)
	if err != nil {
		t.Fatal(err)
	}
	replacement, replacementPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = replacementPeer.Close() })
	replacementID, binding := prepareBoundAdmission(t, e, replacement, pathBinding, 0x74)
	if err := e.StagePathAttach(replacementID); err != nil {
		t.Fatal(err)
	}
	if err := e.ActivateStagedPath(replacementID, true); err != nil {
		t.Fatal(err)
	}
	staleSource, ok := e.PathRef(replacementID)
	if !ok {
		t.Fatal("replacement route is not active")
	}
	failMemoryPath(t, e, replacementID, replacement, errors.New("death after terminal proof dequeue"))
	if active := e.ActivePath(); active != oldID {
		t.Fatalf("active path after successor death=%d, want predecessor=%d", active, oldID)
	}
	if err := e.promotePathAdmissionRoute(binding, staleSource); !errors.Is(err, errPathAdmissionRouteChanged) {
		t.Fatalf("stale terminal source error=%v, want %v", err, errPathAdmissionRouteChanged)
	}
	currentSource, ok := e.PathRef(oldID)
	if !ok {
		t.Fatal("current predecessor route is unavailable")
	}
	if err := e.promotePathAdmissionRoute(binding, currentSource); err != nil {
		t.Fatalf("current terminal source retry: %v", err)
	}
	if err := e.completePathAdmissionBindingRoute(binding, false); err != nil {
		t.Fatal(err)
	}
	if e.CloseErr() != nil {
		t.Fatalf("stale source retry closed session: %v", e.CloseErr())
	}
}

func TestPathAdmissionFencedDispatchCannotKillRetainedPredecessor(t *testing.T) {
	e, binding := newAdmissionAdversarialEngine(t, SideClient)
	old, oldPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = oldPeer.Close() })
	oldID, err := e.AttachPathBound(old, transport.PathSpec{Transport: "memory"}, binding)
	if err != nil {
		t.Fatal(err)
	}
	replacement, replacementPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = replacementPeer.Close() })
	replacementID, _ := prepareBoundAdmission(t, e, replacement, binding, 0x63)
	if err := e.StagePathAttach(replacementID); err != nil {
		t.Fatal(err)
	}
	if err := e.ActivateStagedPath(replacementID, true); err != nil {
		t.Fatal(err)
	}

	oldSlot := admissionPathSlot(t, e, oldID)
	result := make(chan pathDispatchResult, 1)
	e.executePathDispatch(oldSlot, pathDispatchJob{
		frame:  executionDataFrame(t, 0, []byte("stale-route")),
		result: result,
	})
	if got := <-result; !errors.Is(got.err, ErrPathTXFenced) {
		t.Fatalf("stale dispatch error=%v, want TX fence", got.err)
	}
	assertAdmissionOverlap(t, e, replacementID, oldID)
}

func TestMalformedAdmissionControlClosesAsPeerProtocol(t *testing.T) {
	e, binding := newAdmissionAdversarialEngine(t, SideClient)
	path, peer := newMemoryPathPair()
	if _, err := e.AttachPathBound(path, transport.PathSpec{Transport: "memory"}, binding); err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, proto.HeaderSize+1)
	if err := (proto.Header{
		Version: proto.Version,
		Type:    proto.FrameCtrl,
		Flags:   proto.FlagsForCtrl(proto.CtrlPathAdmissionAck),
	}).Encode(frame[:proto.HeaderSize]); err != nil {
		t.Fatal(err)
	}
	frame[proto.HeaderSize] = 0xff
	if _, err := peer.Write(frame); err != nil {
		t.Fatal(err)
	}
	select {
	case <-e.Closed():
	case <-time.After(time.Second):
		t.Fatal("malformed admission control did not close engine")
	}
	if err := e.CloseErr(); !errors.Is(err, ErrPeerProtocol) {
		t.Fatalf("CloseErr=%v, want peer protocol", err)
	}
}

func newAdmissionAdversarialEngine(t *testing.T, side Side) (*Engine, PathBinding) {
	return newAdmissionAdversarialEngineWithLimits(t, side, Limits{
		MigrationBudget:     time.Second,
		ZombieMaxMigrations: 10,
	})
}

func newAdmissionAdversarialEngineWithLimits(t *testing.T, side Side, limits Limits) (*Engine, PathBinding) {
	t.Helper()
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
	)
	e := New(side, NewClientFlowID(), limits.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	return e, PathBinding{LocalTXTargetID: ids["a"], PeerTXTargetID: ids["a"]}
}

func newAdmissionAdversarialEnginePair(t *testing.T) (*Engine, *Engine, PathBinding, PathBinding) {
	t.Helper()
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
	)
	limits := Limits{MigrationBudget: time.Second, ZombieMaxMigrations: 10}.Clamp()
	flowID := NewClientFlowID()
	client := New(SideClient, flowID, limits)
	server := New(SideServer, flowID, limits)
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	for name, engine := range map[string]*Engine{"client": client, "server": server} {
		if err := engine.ConfigureLocalGraph(1, manifest); err != nil {
			t.Fatalf("configure %s local graph: %v", name, err)
		}
		if err := engine.ConfigurePeerGraph(1, manifest); err != nil {
			t.Fatalf("configure %s peer graph: %v", name, err)
		}
	}
	binding := PathBinding{LocalTXTargetID: ids["a"], PeerTXTargetID: ids["a"]}
	return client, server, binding, binding
}

func prepareBoundAdmission(
	t *testing.T,
	e *Engine,
	path transport.PathConn,
	pathBinding PathBinding,
	token byte,
) (uint32, proto.PathAdmissionBinding) {
	t.Helper()
	id, err := e.PreparePathBound(path, transport.PathSpec{Transport: "memory"}, pathBinding)
	if err != nil {
		t.Fatal(err)
	}
	base, err := e.PathAdmissionBaseGeneration(id)
	if err != nil {
		t.Fatal(err)
	}
	binding := proto.PathAdmissionBinding{
		Kind:                   proto.PathAdmissionKindBridge,
		Direction:              proto.SenderDirectionClientToServer,
		SessionEpoch:           proto.SessionEpoch{token},
		AdmissionID:            proto.PathAdmissionID{token},
		InitiatorGraphRevision: 1,
		InitiatorGraphDigest:   proto.GraphDigest{token},
		InitiatorTargetID:      pathBinding.LocalTXTargetID,
		ResponderTargetID:      pathBinding.PeerTXTargetID,
		BaseLeafGeneration:     base,
		ProposalDigest:         proto.PathAdmissionProposalDigest{token},
		ResponderPlanDigest:    proto.PathAdmissionPlanDigest{token, token + 1},
	}
	if err := e.BindPathAdmission(id, binding); err != nil {
		t.Fatal(err)
	}
	return id, binding
}

func snapshotAdmissionSets(e *Engine) admissionSetSizes {
	e.pathsMu.RLock()
	defer e.pathsMu.RUnlock()
	state := admissionSetSizes{
		active:       len(e.paths),
		pending:      len(e.pendingPaths),
		staged:       len(e.stagedPaths),
		retained:     len(e.retainedPaths),
		predecessors: len(e.pathPredecessors),
		byLeaf:       len(e.pathAdmissionByLeaf),
		byPath:       len(e.pathAdmissionByPath),
		completed:    len(e.completedPathAdmissions),
		generations:  make([]uint64, 0, len(e.pathLeafGeneration)),
	}
	for _, generation := range e.pathLeafGeneration {
		state.generations = append(state.generations, generation)
	}
	for _, set := range []map[uint32]*pathSlot{e.paths, e.pendingPaths, e.stagedPaths, e.retainedPaths} {
		for _, slot := range set {
			state.inboxLens = append(state.inboxLens, len(slot.admissionInbox))
		}
	}
	return state
}

func assertSingleAdmissionGeneration(t *testing.T, side string, state admissionSetSizes) {
	t.Helper()
	if state.active != 1 || state.pending != 0 || state.staged != 0 || state.retained != 0 ||
		state.predecessors != 0 || state.byLeaf != 0 || state.byPath != 0 {
		t.Fatalf("%s flood left unbounded admission state: %+v", side, state)
	}
	if len(state.generations) != 1 || state.generations[0] != 1 {
		t.Fatalf("%s logical generations=%v, want exactly [1]", side, state.generations)
	}
	for _, inboxLen := range state.inboxLens {
		if inboxLen > pathAdmissionInboxSize {
			t.Fatalf("%s admission inbox len=%d exceeds bound %d", side, inboxLen, pathAdmissionInboxSize)
		}
	}
}

func assertAdmissionOverlap(t *testing.T, e *Engine, successorID, predecessorID uint32) {
	t.Helper()
	e.pathsMu.RLock()
	defer e.pathsMu.RUnlock()
	if e.activeID != successorID || e.paths[successorID] == nil {
		t.Fatalf("active path=%d successor=%d", e.activeID, successorID)
	}
	if e.retainedPaths[predecessorID] == nil {
		t.Fatalf("predecessor %d was not retained", predecessorID)
	}
	predecessors := e.pathPredecessors[successorID]
	if len(predecessors) != 1 || predecessors[0] != predecessorID {
		t.Fatalf("successor %d predecessors=%v want [%d]", successorID, predecessors, predecessorID)
	}
}

func admissionPathSlot(t *testing.T, e *Engine, id uint32) *pathSlot {
	t.Helper()
	e.pathsMu.RLock()
	defer e.pathsMu.RUnlock()
	for _, set := range []map[uint32]*pathSlot{e.paths, e.pendingPaths, e.stagedPaths, e.retainedPaths} {
		if slot := set[id]; slot != nil {
			return slot
		}
	}
	t.Fatalf("path %d not found in any lifecycle set", id)
	return nil
}

func waitAdmissionCondition(t *testing.T, timeout time.Duration, description string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", description)
		}
		time.Sleep(time.Millisecond)
	}
}

func waitAdmissionChannel(t *testing.T, done <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal(fmt.Sprintf("timed out waiting for %s to quiesce", description))
	}
}
