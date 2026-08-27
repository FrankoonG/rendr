package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

const (
	widePacketFrameLimit   = 1400
	narrowPacketFrameLimit = 1152
)

type fixedPacketFrameLimitPath struct {
	transport.PathConn
	limit int
}

func fixedPacketCapacityBinding(target proto.TargetID, limit int) PathBinding {
	return PathBinding{
		LocalTXTargetID:           target,
		PeerTXTargetID:            target,
		LocalReceiveFrameCapacity: uint32(limit),
		PeerReceiveFrameCapacity:  uint32(limit),
	}
}

func (path *fixedPacketFrameLimitPath) MaxFrameSize() int { return path.limit }

type fixedPacketFrameLimitBatchPath struct {
	*recordingFrameBatchPath
	limit int
}

func (path *fixedPacketFrameLimitBatchPath) MaxFrameSize() int { return path.limit }

type claimedPacketFrameLimitPath struct {
	*claimedMemoryPath
	limit         int
	capacityCalls atomic.Int32
	closeCalls    atomic.Int32
}

func (path *claimedPacketFrameLimitPath) MaxFrameSize() int {
	path.capacityCalls.Add(1)
	return path.limit
}

func (path *claimedPacketFrameLimitPath) Close() error {
	path.closeCalls.Add(1)
	path.claim.RetireUnbound()
	return path.claimedMemoryPath.Close()
}

type blockingClaimedPacketFrameLimitPath struct {
	*claimedPacketFrameLimitPath
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (path *blockingClaimedPacketFrameLimitPath) MaxFrameSize() int {
	path.capacityCalls.Add(1)
	path.once.Do(func() { close(path.entered) })
	<-path.release
	return path.limit
}

func newClaimedPacketFrameLimitPath(limit int) (*claimedPacketFrameLimitPath, *memoryPathConn, *leafmobility.Claim) {
	base, peer := newMemoryPathPair()
	claim := leafmobility.MustNewClaim(leafmobility.Facts{
		Kind:       leafmobility.KindQUIC,
		Role:       leafmobility.RoleDialer,
		Scope:      leafmobility.ScopeEndpoint,
		Session:    leafmobility.SessionPacket,
		Generation: leafmobility.NextGeneration(),
	})
	return &claimedPacketFrameLimitPath{
		claimedMemoryPath: &claimedMemoryPath{PathConn: base, claim: claim},
		limit:             limit,
	}, peer, claim
}

func newPacketBudgetEngine(t *testing.T, leafNames ...string) (*Engine, map[string]proto.TargetID) {
	t.Helper()
	engine := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	engine.SetPacketMode()
	t.Cleanup(func() { _ = engine.Close() })
	return engine, configureLeafSelectorRuntime(t, engine, leafNames...)
}

func largePacketForNarrowLimit(t *testing.T, engine *Engine) []byte {
	t.Helper()
	payloadBytes := narrowPacketFrameLimit - engine.applicationPayloadOverhead() + 1
	if payloadBytes <= 0 || engine.applicationWireFrameBytes(payloadBytes) > widePacketFrameLimit {
		t.Fatalf("invalid packet budget fixture: payload=%d overhead=%d", payloadBytes, engine.applicationPayloadOverhead())
	}
	return bytes.Repeat([]byte{0xa5}, payloadBytes)
}

func attachFixedPacketPath(
	t *testing.T,
	engine *Engine,
	path transport.PathConn,
	limit int,
	target proto.TargetID,
	address string,
) uint32 {
	t.Helper()
	id, err := engine.AttachPathBound(
		&fixedPacketFrameLimitPath{PathConn: path, limit: limit},
		transport.PathSpec{Transport: "memory", Address: address},
		fixedPacketCapacityBinding(target, limit),
	)
	if err != nil {
		t.Fatalf("attach %s: %v", address, err)
	}
	return id
}

func TestNarrowPacketPathCannotInvalidateUnacknowledgedReplay(t *testing.T) {
	engine, targets := newPacketBudgetEngine(t, "wide", "narrow", "recovery")
	wide, widePeer := newMemoryPathPair()
	wideID := attachFixedPacketPath(t, engine, wide, widePacketFrameLimit, targets["wide"], "wide")

	payload := largePacketForNarrowLimit(t, engine)
	if published, err := engine.SendPacketResult(payload); err != nil || !published {
		t.Fatalf("large packet publication=%t/%v", published, err)
	}
	if got := engine.packetFrameLimit.Load(); got != widePacketFrameLimit {
		t.Fatalf("session frame limit=%d want %d", got, widePacketFrameLimit)
	}

	narrow, narrowPeer := newMemoryPathPair()
	_, err := engine.AttachPathBound(
		&fixedPacketFrameLimitPath{PathConn: narrow, limit: narrowPacketFrameLimit},
		transport.PathSpec{Transport: "memory", Address: "narrow"},
		fixedPacketCapacityBinding(targets["narrow"], narrowPacketFrameLimit),
	)
	if !errors.Is(err, ErrPacketTooLarge) {
		t.Fatalf("narrow admission error=%v want ErrPacketTooLarge", err)
	}
	if got := engine.packetFrameLimit.Load(); got != widePacketFrameLimit {
		t.Fatalf("rejected admission changed frame limit=%d want %d", got, widePacketFrameLimit)
	}
	if stats := engine.ReplayStats(); stats.FramesInUse != 1 {
		t.Fatalf("rejected admission changed replay custody: %+v", stats)
	}

	recovery, recoveryPeer := newMemoryPathPair()
	attachFixedPacketPath(t, engine, recovery, widePacketFrameLimit, targets["recovery"], "recovery")
	wide.Fail(errors.New("injected wide path death"))
	waitPathDetached(t, engine, wideID)

	wantFrame := readPacketBudgetDATAFrame(t, widePeer, time.Second)
	gotFrame := readPacketBudgetDATAFrame(t, recoveryPeer, 2*time.Second)
	if !bytes.Equal(gotFrame, wantFrame) {
		t.Fatalf("replayed frame changed across migration\nold=%x\nnew=%x", wantFrame, gotFrame)
	}
	if gotPayload := gotFrame[len(gotFrame)-len(payload):]; !bytes.Equal(gotPayload, payload) {
		t.Fatal("replayed packet payload changed")
	}
	if stats := engine.ReplayStats(); stats.FramesInUse != 1 {
		t.Fatalf("unacknowledged replay lost custody after migration: %+v", stats)
	}

	header, decodeErr := proto.DecodeHeader(gotFrame[:proto.HeaderSize])
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	engine.sendHistMu.Lock()
	entry := engine.sendHistoryEntryLocked(header.Seq)
	if entry == nil {
		engine.sendHistMu.Unlock()
		t.Fatal("replayed packet has no ledger owner")
	}
	proof := entry.proof
	engine.sendHistMu.Unlock()
	if valid, application := engine.acknowledgeSendFrames(header.Seq+1, proof); !valid || !application {
		t.Fatalf("packet ACK valid/application=%t/%t", valid, application)
	}

	narrowAfterACK, _ := newMemoryPathPair()
	attachFixedPacketPath(
		t, engine, narrowAfterACK, narrowPacketFrameLimit, targets["narrow"], "narrow-after-ack",
	)
	if got := engine.packetFrameLimit.Load(); got != narrowPacketFrameLimit {
		t.Fatalf("ACK-drained admission frame limit=%d want %d", got, narrowPacketFrameLimit)
	}
	if published, sendErr := engine.SendPacketResult(payload); published || !errors.Is(sendErr, ErrPacketTooLarge) {
		t.Fatalf("oversize packet after narrow admission=%t/%v", published, sendErr)
	}

	_ = narrowPeer.Close()
}

func TestOwnedPacketClaimRejectedBeforeBindingAndRetired(t *testing.T) {
	engine, targets := newPacketBudgetEngine(t, "wide", "narrow")
	wide, _ := newMemoryPathPair()
	attachFixedPacketPath(t, engine, wide, widePacketFrameLimit, targets["wide"], "wide")
	if published, err := engine.SendPacketResult(largePacketForNarrowLimit(t, engine)); err != nil || !published {
		t.Fatalf("large packet publication=%t/%v", published, err)
	}

	narrow, peer, claim := newClaimedPacketFrameLimitPath(narrowPacketFrameLimit)
	t.Cleanup(func() { _ = peer.Close() })
	_, err := engine.AttachPathBound(narrow, transport.PathSpec{Transport: "quic-like"},
		fixedPacketCapacityBinding(targets["narrow"], narrowPacketFrameLimit))
	if !errors.Is(err, ErrPacketTooLarge) {
		t.Fatalf("owned narrow admission error=%v want ErrPacketTooLarge", err)
	}
	state := claim.State()
	if state.Bound || !state.Retired {
		t.Fatalf("replay-rejected claim state=%+v want unbound and retired", state)
	}
	if narrow.capacityCalls.Load() != 1 {
		t.Fatalf("capacity stimulus calls=%d want 1", narrow.capacityCalls.Load())
	}
	eventuallyEngine(t, time.Second, func() bool { return narrow.closeCalls.Load() == 1 })
	if stats := engine.ReplayStats(); stats.FramesInUse != 1 {
		t.Fatalf("replay rejection lost packet custody: %+v", stats)
	}
}

func TestPacketPathCapacityInvalidValuesFailClosed(t *testing.T) {
	for _, limit := range []int{0, -1, proto.HeaderSize - 1} {
		t.Run(fmt.Sprintf("limit-%d", limit), func(t *testing.T) {
			engine := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
			engine.SetPacketMode()
			t.Cleanup(func() { _ = engine.Close() })
			path, peer := newMemoryPathPair()
			t.Cleanup(func() { _ = peer.Close() })
			wrapped := &fixedPacketFrameLimitPath{PathConn: path, limit: limit}
			_, err := engine.AttachPath(wrapped, transport.PathSpec{Transport: "invalid-capacity"})
			if !errors.Is(err, ErrPacketPathCapacityUnavailable) {
				t.Fatalf("capacity %d admission error=%v want ErrPacketPathCapacityUnavailable", limit, err)
			}
			select {
			case <-path.closed:
			default:
				t.Fatal("invalid-capacity path was not closed")
			}
		})
	}
}

func TestBoundPacketClaimAdmissionFailuresRetireExactBinding(t *testing.T) {
	tests := []struct {
		name  string
		cause error
	}{
		{name: "peer-reject", cause: fmt.Errorf("%w: injected peer rejection", ErrPathAdmissionRejected)},
		{name: "local-abort", cause: errors.New("injected local abort")},
		{name: "deadline", cause: context.DeadlineExceeded},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			engine, targets := newPacketBudgetEngine(t, "candidate")
			path, peer, claim := newClaimedPacketFrameLimitPath(widePacketFrameLimit)
			t.Cleanup(func() { _ = peer.Close() })
			id, err := engine.PreparePathBound(path, transport.PathSpec{Transport: "quic-like"},
				fixedPacketCapacityBinding(targets["candidate"], widePacketFrameLimit))
			if err != nil {
				t.Fatal(err)
			}
			before := claim.State()
			if !before.Bound || before.Retired || before.Binding.PathID != id {
				t.Fatalf("prepared claim state=%+v", before)
			}
			engine.AbortPathAttach(id, test.cause)
			eventuallyEngine(t, time.Second, func() bool {
				return claim.Retired() && path.closeCalls.Load() == 1
			})
			after := claim.State()
			if !after.Bound || !after.Retired || after.Binding != before.Binding {
				t.Fatalf("retired exact binding before=%+v after=%+v", before, after)
			}
		})
	}
}

func TestBoundPacketClaimPostCommitPeerRejectionRetiresExactBinding(t *testing.T) {
	engine, targets := newPacketBudgetEngine(t, "candidate")
	path, peer, claim := newClaimedPacketFrameLimitPath(widePacketFrameLimit)
	t.Cleanup(func() { _ = peer.Close() })
	id, err := engine.PreparePathBound(path, transport.PathSpec{Transport: "quic-like"},
		fixedPacketCapacityBinding(targets["candidate"], widePacketFrameLimit))
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.StagePathAttach(id); err != nil {
		t.Fatal(err)
	}
	before := claim.State()
	if !before.Bound || before.Retired || before.Binding.PathID != id {
		t.Fatalf("staged claim state=%+v", before)
	}
	if !engine.closeForUnknownPathAdmissionIfLive() {
		t.Fatal("post-commit peer rejection stimulus did not close the live session")
	}
	if !errors.Is(engine.CloseErr(), ErrPathAdmissionOutcomeUnknown) {
		t.Fatalf("post-commit close error=%v want ErrPathAdmissionOutcomeUnknown", engine.CloseErr())
	}
	eventuallyEngine(t, time.Second, func() bool {
		return claim.Retired() && path.closeCalls.Load() == 1
	})
	after := claim.State()
	if !after.Bound || !after.Retired || after.Binding != before.Binding {
		t.Fatalf("post-commit exact binding before=%+v after=%+v", before, after)
	}
}

func TestPacketCapacityDeadlineAndEngineCloseRetireClaims(t *testing.T) {
	t.Run("capacity callback deadline", func(t *testing.T) {
		engine, targets := newPacketBudgetEngine(t, "candidate")
		base, peer, claim := newClaimedPacketFrameLimitPath(widePacketFrameLimit)
		t.Cleanup(func() { _ = peer.Close() })
		path := &blockingClaimedPacketFrameLimitPath{
			claimedPacketFrameLimitPath: base,
			entered:                     make(chan struct{}),
			release:                     make(chan struct{}),
		}
		result := make(chan error, 1)
		go func() {
			_, err := engine.AttachPathBound(path, transport.PathSpec{Transport: "quic-like"},
				fixedPacketCapacityBinding(targets["candidate"], widePacketFrameLimit))
			result <- err
		}()
		awaitSignal(t, path.entered, "packet capacity callback")
		var err error
		select {
		case err = <-result:
		case <-time.After(2 * externalPathValueCallbackTimeout):
			t.Fatal("capacity callback deadline did not bound admission")
		}
		var deadlineErr *pathDispatchCallbackDeadlineError
		if !errors.As(err, &deadlineErr) {
			t.Fatalf("capacity deadline error=%v", err)
		}
		if state := claim.State(); state.Bound || !state.Retired {
			t.Fatalf("deadline-rejected claim state=%+v", state)
		}
		if path.closeCalls.Load() != 0 {
			t.Fatal("carrier closed before its capacity callback returned")
		}
		close(path.release)
		eventuallyEngine(t, time.Second, func() bool { return path.closeCalls.Load() == 1 })
	})

	t.Run("engine close during capacity callback", func(t *testing.T) {
		engine, targets := newPacketBudgetEngine(t, "candidate")
		base, peer, claim := newClaimedPacketFrameLimitPath(widePacketFrameLimit)
		t.Cleanup(func() { _ = peer.Close() })
		path := &blockingClaimedPacketFrameLimitPath{
			claimedPacketFrameLimitPath: base,
			entered:                     make(chan struct{}),
			release:                     make(chan struct{}),
		}
		attachDone := make(chan error, 1)
		go func() {
			_, err := engine.AttachPathBound(path, transport.PathSpec{Transport: "quic-like"},
				fixedPacketCapacityBinding(targets["candidate"], widePacketFrameLimit))
			attachDone <- err
		}()
		awaitSignal(t, path.entered, "packet capacity callback")
		closeDone := make(chan error, 1)
		go func() { closeDone <- engine.Close() }()
		select {
		case err := <-closeDone:
			t.Fatalf("Engine.Close returned before callback release: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
		close(path.release)
		attachErr := <-attachDone
		if err := <-closeDone; err != nil {
			t.Fatal(err)
		}
		state := claim.State()
		if !state.Retired || path.closeCalls.Load() != 1 {
			t.Fatalf("close-raced claim=%+v closeCalls=%d attachErr=%v", state, path.closeCalls.Load(), attachErr)
		}
		if state.Bound && (state.Binding.PathID == 0 || state.Binding.Owner == 0) {
			t.Fatalf("close-raced claim retained an invalid exact binding: %+v attachErr=%v", state, attachErr)
		}
	})

	t.Run("bound abort races engine close", func(t *testing.T) {
		engine, targets := newPacketBudgetEngine(t, "candidate")
		path, peer, claim := newClaimedPacketFrameLimitPath(widePacketFrameLimit)
		t.Cleanup(func() { _ = peer.Close() })
		id, err := engine.PreparePathBound(path, transport.PathSpec{Transport: "quic-like"},
			fixedPacketCapacityBinding(targets["candidate"], widePacketFrameLimit))
		if err != nil {
			t.Fatal(err)
		}
		before := claim.State()
		if !before.Bound || before.Retired {
			t.Fatalf("prepared claim=%+v", before)
		}
		var wait sync.WaitGroup
		wait.Add(2)
		go func() { defer wait.Done(); engine.AbortPathAttach(id, context.DeadlineExceeded) }()
		go func() { defer wait.Done(); _ = engine.Close() }()
		wait.Wait()
		after := claim.State()
		if !after.Bound || !after.Retired || after.Binding != before.Binding || path.closeCalls.Load() != 1 {
			t.Fatalf("abort/close claim before=%+v after=%+v closeCalls=%d", before, after, path.closeCalls.Load())
		}
	})
}

func TestPacketBudgetAdmissionAndPublicationLinearize(t *testing.T) {
	t.Run("publication wins", func(t *testing.T) {
		engine, targets := newPacketBudgetEngine(t, "wide", "narrow")
		wide, _ := newMemoryPathPair()
		attachFixedPacketPath(t, engine, wide, widePacketFrameLimit, targets["wide"], "wide")
		payload := largePacketForNarrowLimit(t, engine)

		locked := make(chan struct{})
		release := make(chan struct{})
		var once sync.Once
		engine.packetPublicationAfterBudgetLock = func() {
			once.Do(func() { close(locked) })
			<-release
		}
		t.Cleanup(func() {
			select {
			case <-release:
			default:
				close(release)
			}
		})

		type sendResult struct {
			published bool
			err       error
		}
		sendDone := make(chan sendResult, 1)
		go func() {
			published, err := engine.SendPacketResult(payload)
			sendDone <- sendResult{published: published, err: err}
		}()
		awaitSignal(t, locked, "packet budget publication lock")

		narrow, _ := newMemoryPathPair()
		attachDone := make(chan error, 1)
		go func() {
			_, err := engine.AttachPathBound(
				&fixedPacketFrameLimitPath{PathConn: narrow, limit: narrowPacketFrameLimit},
				transport.PathSpec{Transport: "memory", Address: "narrow"},
				fixedPacketCapacityBinding(targets["narrow"], narrowPacketFrameLimit),
			)
			attachDone <- err
		}()
		close(release)
		if result := <-sendDone; result.err != nil || !result.published {
			t.Fatalf("publication result=%+v", result)
		}
		if err := <-attachDone; !errors.Is(err, ErrPacketTooLarge) {
			t.Fatalf("concurrent narrow admission=%v want ErrPacketTooLarge", err)
		}
	})

	t.Run("admission wins", func(t *testing.T) {
		engine, targets := newPacketBudgetEngine(t, "wide", "narrow")
		wide, _ := newMemoryPathPair()
		attachFixedPacketPath(t, engine, wide, widePacketFrameLimit, targets["wide"], "wide")
		payload := largePacketForNarrowLimit(t, engine)

		beforeLock := make(chan struct{})
		release := make(chan struct{})
		var once sync.Once
		engine.packetPublicationBeforeBudgetLock = func() {
			once.Do(func() { close(beforeLock) })
			<-release
		}
		sendDone := make(chan error, 1)
		go func() {
			published, err := engine.SendPacketResult(payload)
			if published {
				err = fmt.Errorf("packet was published despite narrow admission: %w", err)
			}
			sendDone <- err
		}()
		awaitSignal(t, beforeLock, "packet before budget lock")

		narrow, _ := newMemoryPathPair()
		attachFixedPacketPath(t, engine, narrow, narrowPacketFrameLimit, targets["narrow"], "narrow")
		close(release)
		if err := <-sendDone; !errors.Is(err, ErrPacketTooLarge) {
			t.Fatalf("packet after narrower admission=%v want ErrPacketTooLarge", err)
		}
		if stats := engine.ReplayStats(); stats.FramesInUse != 0 {
			t.Fatalf("rejected packet entered replay custody: %+v", stats)
		}
	})
}

func TestPacketBatchMigrationRejectsNarrowPathWithoutLoss(t *testing.T) {
	manifest, targets := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "old", "narrow", "recovery"),
		runtimeNode(proto.GraphNodeKindPath, "old"),
		runtimeNode(proto.GraphNodeKindPath, "narrow"),
		runtimeNode(proto.GraphNodeKindPath, "recovery"),
	)
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{}.Clamp())
	server := New(SideServer, flow, Limits{}.Clamp())
	client.SetPacketMode()
	server.SetPacketMode()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	configureRecursivePair(t, client, server, manifest)

	oldClientBase, oldServerBase := newMemoryPathPair()
	oldBatch := &fixedPacketFrameLimitBatchPath{
		recordingFrameBatchPath: newRecordingFrameBatchPath(oldClientBase),
		limit:                   widePacketFrameLimit,
	}
	oldServer := &fixedPacketFrameLimitPath{PathConn: oldServerBase, limit: widePacketFrameLimit}
	attachRecursivePath(t, client, server, "old", oldBatch, oldServer)
	oldClientID := pathIDByName(t, client, "old")
	oldServerID := pathIDByName(t, server, "old")

	client.pathsMu.RLock()
	oldSlot := client.paths[oldClientID]
	client.pathsMu.RUnlock()
	if oldSlot == nil {
		t.Fatal("old packet path is missing")
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	var enteredOnce sync.Once
	var releaseOnce sync.Once
	oldSlot.dispatchBeforeWritePermit = func() {
		enteredOnce.Do(func() { close(entered) })
		<-release
	}
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })

	const packetCount = 8
	payloads := make([][]byte, packetCount)
	results := make(chan error, packetCount)
	for index := range payloads {
		payloads[index] = largePacketForNarrowLimit(t, client)
		payloads[index][0] = byte(index)
		go func(payload []byte) {
			published, err := client.SendPacketAcceptedResult(payload)
			if err == nil && !published {
				err = errors.New("packet was not accepted")
			}
			results <- err
		}(payloads[index])
	}
	awaitSignal(t, entered, "old packet batch dispatch")
	for range packetCount {
		if err := <-results; err != nil {
			t.Fatalf("accepted packet: %v", err)
		}
	}
	eventuallyEngine(t, time.Second, func() bool {
		return client.ReplayStats().FramesInUse == packetCount
	})

	narrow, _ := newMemoryPathPair()
	_, err := client.AttachPathBound(
		&fixedPacketFrameLimitPath{PathConn: narrow, limit: narrowPacketFrameLimit},
		transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": "narrow"}},
		fixedPacketCapacityBinding(targets["narrow"], narrowPacketFrameLimit),
	)
	if !errors.Is(err, ErrPacketTooLarge) {
		t.Fatalf("narrow batch successor error=%v want ErrPacketTooLarge", err)
	}

	recoveryClient, recoveryServer := newMemoryPathPair()
	attachRecursivePath(
		t, client, server, "recovery",
		&fixedPacketFrameLimitPath{PathConn: recoveryClient, limit: widePacketFrameLimit},
		&fixedPacketFrameLimitPath{PathConn: recoveryServer, limit: widePacketFrameLimit},
	)
	oldClientBase.Fail(errors.New("injected old client path death"))
	oldServerBase.Fail(errors.New("injected old server path death"))
	waitPathDetached(t, client, oldClientID)
	waitPathDetached(t, server, oldServerID)
	releaseOnce.Do(func() { close(release) })

	if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	seen := make(map[byte][]byte, packetCount)
	for range packetCount {
		packet, recvErr := server.RecvPacket()
		if recvErr != nil {
			t.Fatalf("receive replayed packet: %v", recvErr)
		}
		if len(packet) == 0 {
			t.Fatal("received empty packet")
		}
		key := packet[0]
		if _, duplicate := seen[key]; duplicate {
			t.Fatalf("application received duplicate packet %d", key)
		}
		seen[key] = packet
	}
	for index, want := range payloads {
		if got, ok := seen[byte(index)]; !ok || !bytes.Equal(got, want) {
			t.Fatalf("packet %d missing or changed", index)
		}
	}
	eventuallyEngine(t, 3*time.Second, func() bool {
		return client.ReplayStats().FramesInUse == 0
	})
}

func TestPacketBatchCompletedPrefixPathDeathReplaysWithoutDuplicate(t *testing.T) {
	manifest, _ := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "old", "recovery"),
		runtimeNode(proto.GraphNodeKindPath, "old"),
		runtimeNode(proto.GraphNodeKindPath, "recovery"),
	)
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{}.Clamp())
	server := New(SideServer, flow, Limits{}.Clamp())
	client.SetPacketMode()
	server.SetPacketMode()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	configureRecursivePair(t, client, server, manifest)

	oldClientBase, oldServerBase := newMemoryPathPair()
	oldBatch := &fixedPacketFrameLimitBatchPath{
		recordingFrameBatchPath: newRecordingFrameBatchPath(oldClientBase),
		limit:                   widePacketFrameLimit,
	}
	attachRecursivePath(
		t, client, server, "old", oldBatch,
		&fixedPacketFrameLimitPath{PathConn: oldServerBase, limit: widePacketFrameLimit},
	)
	oldClientID := pathIDByName(t, client, "old")

	recoveryClient, recoveryServer := newMemoryPathPair()
	attachRecursivePath(
		t, client, server, "recovery",
		&fixedPacketFrameLimitPath{PathConn: recoveryClient, limit: widePacketFrameLimit},
		&fixedPacketFrameLimitPath{PathConn: recoveryServer, limit: widePacketFrameLimit},
	)

	client.pathsMu.RLock()
	oldSlot := client.paths[oldClientID]
	client.pathsMu.RUnlock()
	if oldSlot == nil {
		t.Fatal("old packet path is missing")
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	var enteredOnce sync.Once
	var releaseOnce sync.Once
	oldSlot.dispatchBeforeWritePermit = func() {
		enteredOnce.Do(func() { close(entered) })
		<-release
	}
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })

	const (
		packetCount = 8
		prefixCount = 3
	)
	batchObserved := make(chan int, 1)
	injected := errors.New("injected packet batch prefix death")
	oldBatch.batchHook = func(frames [][]byte) (int, error) {
		select {
		case batchObserved <- len(frames):
		default:
		}
		if len(frames) < prefixCount {
			return 0, fmt.Errorf("batch size %d is smaller than required prefix %d", len(frames), prefixCount)
		}
		completed, err := oldBatch.writeWholeFrames(frames[:prefixCount])
		if err != nil || completed != prefixCount {
			return completed, errors.Join(err, io.ErrShortWrite)
		}
		oldClientBase.Fail(injected)
		return prefixCount, injected
	}

	payloads := make([][]byte, packetCount)
	results := make(chan error, packetCount)
	for index := range payloads {
		payloads[index] = bytes.Repeat([]byte{byte(index + 1)}, 512)
		go func(payload []byte) {
			published, err := client.SendPacketAcceptedResult(payload)
			if err == nil && !published {
				err = errors.New("packet was not accepted")
			}
			results <- err
		}(payloads[index])
	}
	awaitSignal(t, entered, "packet batch prefix dispatch")
	for range packetCount {
		if err := <-results; err != nil {
			t.Fatalf("accepted packet: %v", err)
		}
	}
	eventuallyEngine(t, time.Second, func() bool {
		return client.ReplayStats().FramesInUse == packetCount
	})
	releaseOnce.Do(func() { close(release) })

	select {
	case size := <-batchObserved:
		if size != packetCount {
			t.Fatalf("physical batch size=%d want %d", size, packetCount)
		}
	case <-time.After(time.Second):
		t.Fatal("partial batch stimulus did not occur")
	}
	waitPathDetached(t, client, oldClientID)

	if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	seen := make(map[byte][]byte, packetCount)
	for range packetCount {
		packet, err := server.RecvPacket()
		if err != nil {
			t.Fatalf("receive packet after partial batch death: %v", err)
		}
		if len(packet) == 0 {
			t.Fatal("received empty packet")
		}
		key := packet[0]
		if _, duplicate := seen[key]; duplicate {
			t.Fatalf("application received duplicate packet %d", key)
		}
		seen[key] = packet
	}
	for index, want := range payloads {
		key := byte(index + 1)
		if got, ok := seen[key]; !ok || !bytes.Equal(got, want) {
			t.Fatalf("packet %d missing or changed", key)
		}
	}
	if err := server.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if packet, err := server.RecvPacket(); len(packet) != 0 || !errors.Is(err, ErrReadDeadlineExceeded) {
		t.Fatalf("post-replay duplicate read=(%d,%v) want timeout", len(packet), err)
	}
	eventuallyEngine(t, 3*time.Second, func() bool {
		return client.ReplayStats().FramesInUse == 0
	})
}

func readPacketBudgetDATAFrame(t *testing.T, path *memoryPathConn, timeout time.Duration) []byte {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		select {
		case frame := <-path.in:
			if len(frame) < proto.HeaderSize {
				continue
			}
			header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
			if err == nil && header.Type == proto.FrameData {
				return frame
			}
		case <-deadline.C:
			t.Fatal("timed out waiting for packet DATA frame")
			return nil
		case <-path.closed:
			t.Fatal("packet peer closed before DATA frame")
			return nil
		case <-path.failed:
			t.Fatal("packet peer failed before DATA frame")
			return nil
		}
	}
}

var _ transport.FrameBatchWriter = (*fixedPacketFrameLimitBatchPath)(nil)
var _ transport.PacketPathConn = (*fixedPacketFrameLimitPath)(nil)
var _ transport.PacketPathConn = (*claimedPacketFrameLimitPath)(nil)
