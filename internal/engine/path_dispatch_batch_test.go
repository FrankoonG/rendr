package engine

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type recordingFrameBatchPath struct {
	transport.PathConn

	mu             sync.Mutex
	batches        [][]uint64
	ordinaryTypes  []proto.FrameType
	ordinarySeqs   []uint64
	batchStarted   chan struct{}
	batchStartOnce sync.Once
	batchHook      func([][]byte) (int, error)
	closed         chan struct{}
	closeOnce      sync.Once
}

func newRecordingFrameBatchPath(path transport.PathConn) *recordingFrameBatchPath {
	return &recordingFrameBatchPath{
		PathConn:     path,
		batchStarted: make(chan struct{}),
		closed:       make(chan struct{}),
	}
}

func (p *recordingFrameBatchPath) Write(frame []byte) (int, error) {
	p.recordOrdinary(frame)
	return p.PathConn.Write(frame)
}

func (p *recordingFrameBatchPath) WriteFrameBatch(frames [][]byte) (int, error) {
	seqs := make([]uint64, 0, len(frames))
	for _, frame := range frames {
		if header, err := decodeBatchTestHeader(frame); err == nil {
			seqs = append(seqs, header.Seq)
		}
	}
	p.mu.Lock()
	p.batches = append(p.batches, seqs)
	p.mu.Unlock()
	p.batchStartOnce.Do(func() { close(p.batchStarted) })
	if p.batchHook != nil {
		return p.batchHook(frames)
	}
	return p.writeWholeFrames(frames)
}

func (p *recordingFrameBatchPath) writeWholeFrames(frames [][]byte) (int, error) {
	for i, frame := range frames {
		n, err := p.PathConn.Write(frame)
		if err != nil {
			return i, err
		}
		if n != len(frame) {
			return i, io.ErrShortWrite
		}
	}
	return len(frames), nil
}

func (p *recordingFrameBatchPath) recordOrdinary(frame []byte) {
	header, err := decodeBatchTestHeader(frame)
	if err != nil {
		return
	}
	p.mu.Lock()
	p.ordinaryTypes = append(p.ordinaryTypes, header.Type)
	p.ordinarySeqs = append(p.ordinarySeqs, header.Seq)
	p.mu.Unlock()
}

func (p *recordingFrameBatchPath) snapshot() ([][]uint64, []proto.FrameType, []uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	batches := make([][]uint64, len(p.batches))
	for i := range p.batches {
		batches[i] = append([]uint64(nil), p.batches[i]...)
	}
	return batches, append([]proto.FrameType(nil), p.ordinaryTypes...), append([]uint64(nil), p.ordinarySeqs...)
}

func (p *recordingFrameBatchPath) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return p.PathConn.Close()
}

func TestPathWriterBatchesOrderedSixteenPacketDataFrames(t *testing.T) {
	e, slot, path := newBatchDispatchHarness(t, true)
	waiters := make([]*applicationDispatchWaiter, maximumPathDispatchBatch)
	for i := range waiters {
		waiters[i] = queueBatchApplicationJob(t, slot, uint64(i), true)
	}
	startBatchDispatchHarness(t, e, slot)
	for i, waiter := range waiters {
		result := awaitBatchDispatchResult(t, waiter)
		if result.err != nil {
			t.Fatalf("frame %d: %v", i, result.err)
		}
	}

	batches, ordinary, _ := path.snapshot()
	if len(batches) != 1 || len(batches[0]) != maximumPathDispatchBatch {
		t.Fatalf("batches=%v want one %d-frame batch", batches, maximumPathDispatchBatch)
	}
	for i, seq := range batches[0] {
		if seq != uint64(i) {
			t.Fatalf("batch sequence[%d]=%d want %d", i, seq, i)
		}
	}
	if len(ordinary) != 0 {
		t.Fatalf("ordinary writes=%v want none", ordinary)
	}
	if got := slot.dataWrites.Load(); got != maximumPathDispatchBatch {
		t.Fatalf("data writes=%d", got)
	}
	if got := slot.dataDispatches.Load(); got != maximumPathDispatchBatch {
		t.Fatalf("data dispatches=%d", got)
	}
	if got := slot.firstDataDispatches.Load(); got != maximumPathDispatchBatch {
		t.Fatalf("first data dispatches=%d", got)
	}
	if got := slot.batchWriteCalls.Load(); got != 1 {
		t.Fatalf("batch write calls=%d want 1", got)
	}
	if got := slot.batchWriteFrames.Load(); got != maximumPathDispatchBatch {
		t.Fatalf("batch write frames=%d want %d", got, maximumPathDispatchBatch)
	}
	if got := slot.batchWriteMax.Load(); got != maximumPathDispatchBatch {
		t.Fatalf("batch write max=%d want %d", got, maximumPathDispatchBatch)
	}
}

func TestPacketBatchPreservesReplayOwnershipAndPerJobCompletion(t *testing.T) {
	manifest, _ := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "path"),
		runtimeNode(proto.GraphNodeKindPath, "path"),
	)
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{}.Clamp())
	server := New(SideServer, flow, Limits{}.Clamp())
	client.SetPacketMode()
	server.SetPacketMode()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	configureRecursivePair(t, client, server, manifest)
	clientBase, serverPath := newMemoryPathPair()
	clientBase.dropWrites.Store(true)
	batchPath := newRecordingFrameBatchPath(clientBase)
	attachRecursivePath(t, client, server, "path", batchPath, serverPath)

	client.pathsMu.RLock()
	slot := client.paths[client.activeID]
	client.pathsMu.RUnlock()
	if slot == nil {
		t.Fatal("active packet path is missing")
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	var enteredOnce sync.Once
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	slot.dispatchBeforeWritePermit = func() {
		enteredOnce.Do(func() { close(entered) })
		<-release
	}

	type sendResult struct {
		published bool
		err       error
	}
	results := make(chan sendResult, maximumPathDispatchBatch)
	go func() {
		published, err := client.SendPacketResult([]byte("first"))
		results <- sendResult{published: published, err: err}
	}()
	awaitSignal(t, entered, "first dispatch pre-write boundary")
	for i := 1; i < maximumPathDispatchBatch; i++ {
		go func(value byte) {
			published, err := client.SendPacketResult([]byte{value})
			results <- sendResult{published: published, err: err}
		}(byte(i))
	}
	eventuallyEngine(t, time.Second, func() bool {
		stats := client.ReplayStats()
		return stats.PublishedNext == maximumPathDispatchBatch &&
			stats.FramesInUse == maximumPathDispatchBatch &&
			len(slot.dispatchQ) == maximumPathDispatchBatch-1
	})
	releaseOnce.Do(func() { close(release) })
	for i := 0; i < maximumPathDispatchBatch; i++ {
		select {
		case result := <-results:
			if !result.published || result.err != nil {
				t.Fatalf("packet result[%d]=%+v", i, result)
			}
		case <-time.After(time.Second):
			t.Fatalf("packet result %d timed out", i)
		}
	}
	batches, _, _ := batchPath.snapshot()
	if len(batches) != 1 || len(batches[0]) != maximumPathDispatchBatch {
		t.Fatalf("batches=%v want one %d-frame batch", batches, maximumPathDispatchBatch)
	}
	for i, seq := range batches[0] {
		if seq != uint64(i) {
			t.Fatalf("batch sequence[%d]=%d want %d", i, seq, i)
		}
	}
	stats := client.ReplayStats()
	if stats.FramesInUse != maximumPathDispatchBatch || stats.PublishedNext != maximumPathDispatchBatch {
		t.Fatalf("replay stats=%+v", stats)
	}
}

func TestPathWriterBatchPartialBoundaryCompletesOnlyWholePrefix(t *testing.T) {
	injected := errors.New("injected batch boundary failure")
	e, slot, path := newBatchDispatchHarness(t, true)
	path.batchHook = func(frames [][]byte) (int, error) {
		completed := 5
		if _, err := path.writeWholeFrames(frames[:completed]); err != nil {
			return 0, err
		}
		return completed, injected
	}
	waiters := make([]*applicationDispatchWaiter, 8)
	for i := range waiters {
		waiters[i] = queueBatchApplicationJob(t, slot, uint64(i), true)
	}
	startBatchDispatchHarness(t, e, slot)
	for i, waiter := range waiters {
		result := awaitBatchDispatchResult(t, waiter)
		if i < 5 && result.err != nil {
			t.Fatalf("completed frame %d: %v", i, result.err)
		}
		if i >= 5 && !errors.Is(result.err, injected) {
			t.Fatalf("suffix frame %d error=%v", i, result.err)
		}
	}
	if got := slot.dataWrites.Load(); got != 5 {
		t.Fatalf("data writes=%d want 5", got)
	}
	if got := slot.firstDataDispatches.Load(); got != 5 {
		t.Fatalf("first data dispatches=%d want 5", got)
	}
	if completed, err := classifyFrameBatchResult(8, 5, nil); completed != 5 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("nil-error partial result=(%d,%v), want (5, short write)", completed, err)
	}
	if completed, err := classifyFrameBatchResult(8, 9, injected); completed != 0 || err == nil {
		t.Fatalf("invalid count result=(%d,%v), want fail-closed zero prefix", completed, err)
	}
}

func TestPathWriterFenceDuringBatchWaitsForIndivisiblePhysicalCall(t *testing.T) {
	e, slot, path := newBatchDispatchHarness(t, true)
	release := make(chan struct{})
	path.batchHook = func(frames [][]byte) (int, error) {
		select {
		case <-release:
			return path.writeWholeFrames(frames)
		case <-path.closed:
			return 0, net.ErrClosed
		}
	}
	waiters := make([]*applicationDispatchWaiter, 4)
	for i := range waiters {
		waiters[i] = queueBatchApplicationJob(t, slot, uint64(i), true)
	}
	startBatchDispatchHarness(t, e, slot)
	awaitSignal(t, path.batchStarted, "batch start")
	if !slot.tryFenceDispatch() {
		t.Fatal("failed to establish dispatch fence during batch")
	}
	idle := make(chan error, 1)
	go func() {
		ctx, cancel := contextWithTestTimeout()
		defer cancel()
		idle <- slot.waitWriteIdle(ctx)
	}()
	select {
	case err := <-idle:
		t.Fatalf("fence observed idle before batch returned: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	for _, waiter := range waiters {
		if result := awaitBatchDispatchResult(t, waiter); result.err != nil {
			t.Fatal(result.err)
		}
	}
	select {
	case err := <-idle:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("fence did not observe batch completion")
	}
}

func TestPathWriterCloseFailsBlockedBatchPerJob(t *testing.T) {
	e, slot, path := newBatchDispatchHarness(t, true)
	path.batchHook = func([][]byte) (int, error) {
		<-path.closed
		return 0, net.ErrClosed
	}
	waiters := make([]*applicationDispatchWaiter, 3)
	for i := range waiters {
		waiters[i] = queueBatchApplicationJob(t, slot, uint64(i), true)
	}
	startBatchDispatchHarness(t, e, slot)
	awaitSignal(t, path.batchStarted, "batch start")
	if err := path.Close(); err != nil {
		t.Fatal(err)
	}
	slot.closeQuit()
	for i, waiter := range waiters {
		if result := awaitBatchDispatchResult(t, waiter); !errors.Is(result.err, net.ErrClosed) {
			t.Fatalf("frame %d error=%v want closed", i, result.err)
		}
	}
}

func TestPathWriterBatchStopsAtMixedControlAndDataBoundary(t *testing.T) {
	e, slot, path := newBatchDispatchHarness(t, true)
	first := queueBatchApplicationJob(t, slot, 0, true)
	second := queueBatchApplicationJob(t, slot, 1, true)
	controlResult := queueBatchControlJob(t, slot, 2)
	third := queueBatchApplicationJob(t, slot, 3, true)
	startBatchDispatchHarness(t, e, slot)
	for _, waiter := range []*applicationDispatchWaiter{first, second} {
		if result := awaitBatchDispatchResult(t, waiter); result.err != nil {
			t.Fatal(result.err)
		}
	}
	select {
	case result := <-controlResult:
		if result.err != nil {
			t.Fatal(result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("control dispatch did not complete")
	}
	if result := awaitBatchDispatchResult(t, third); result.err != nil {
		t.Fatal(result.err)
	}

	batches, ordinary, ordinarySeqs := path.snapshot()
	if len(batches) != 2 || !equalBatchSequences(batches[0], []uint64{0, 1}) || !equalBatchSequences(batches[1], []uint64{3}) {
		t.Fatalf("batches=%v want [[0 1] [3]]", batches)
	}
	if len(ordinary) != 1 || ordinary[0] != proto.FrameCtrl || ordinarySeqs[0] != 2 {
		t.Fatalf("ordinary types=%v seqs=%v", ordinary, ordinarySeqs)
	}
}

func TestPathWriterBatchDoesNotWaitForAnotherFrame(t *testing.T) {
	e, slot, path := newBatchDispatchHarness(t, true)
	e.packetWritesInFlight.Store(1)
	e.pathDispatchBatchYield = func() { t.Fatal("single packet writer yielded to build a batch") }
	startBatchDispatchHarness(t, e, slot)
	waiter := queueBatchApplicationJob(t, slot, 0, true)
	awaitSignal(t, path.batchStarted, "single-frame batch without a following job")
	if result := awaitBatchDispatchResult(t, waiter); result.err != nil {
		t.Fatal(result.err)
	}
	batches, _, _ := path.snapshot()
	if len(batches) != 1 || !equalBatchSequences(batches[0], []uint64{0}) {
		t.Fatalf("batches=%v want [[0]]", batches)
	}
	if slot.batchWriteCalls.Load() != 1 || slot.batchWriteFrames.Load() != 1 || slot.batchWriteMax.Load() != 1 {
		t.Fatalf("single batch telemetry calls/frames/max=%d/%d/%d",
			slot.batchWriteCalls.Load(), slot.batchWriteFrames.Load(), slot.batchWriteMax.Load())
	}
}

func TestPathWriterYieldsOnlyForExistingConcurrentPacketWriter(t *testing.T) {
	e, slot, path := newBatchDispatchHarness(t, true)
	e.packetWritesInFlight.Store(2)
	var second *applicationDispatchWaiter
	var once sync.Once
	e.pathDispatchBatchYield = func() {
		once.Do(func() { second = queueBatchApplicationJob(t, slot, 1, true) })
	}
	startBatchDispatchHarness(t, e, slot)
	first := queueBatchApplicationJob(t, slot, 0, true)
	if result := awaitBatchDispatchResult(t, first); result.err != nil {
		t.Fatal(result.err)
	}
	if second == nil {
		t.Fatal("concurrent packet writer never received a batch scheduling opportunity")
	}
	if result := awaitBatchDispatchResult(t, second); result.err != nil {
		t.Fatal(result.err)
	}
	batches, _, _ := path.snapshot()
	if len(batches) != 1 || !equalBatchSequences(batches[0], []uint64{0, 1}) {
		t.Fatalf("batches=%v want [[0 1]]", batches)
	}
}

func TestPathWriterFallsBackForOrdinaryPathConn(t *testing.T) {
	e, slot, _ := newBatchDispatchHarness(t, false)
	startBatchDispatchHarness(t, e, slot)
	waiter := queueBatchApplicationJob(t, slot, 0, true)
	if result := awaitBatchDispatchResult(t, waiter); result.err != nil {
		t.Fatal(result.err)
	}
	ordinary, ok := slot.conn.(*memoryPathConn)
	if !ok {
		t.Fatalf("fallback conn type=%T", slot.conn)
	}
	if got := ordinary.writes.Load(); got != 1 {
		t.Fatalf("ordinary PathConn writes=%d want 1", got)
	}
	if got := slot.dataWrites.Load(); got != 1 {
		t.Fatalf("data writes=%d want 1", got)
	}
	if slot.batchWriteCalls.Load() != 0 || slot.batchWriteFrames.Load() != 0 || slot.batchWriteMax.Load() != 0 {
		t.Fatalf("ordinary path reported batch telemetry calls/frames/max=%d/%d/%d",
			slot.batchWriteCalls.Load(), slot.batchWriteFrames.Load(), slot.batchWriteMax.Load())
	}
}

func TestPathWriterBatchExtensionLeavesStreamAndReplayWritesOrdinary(t *testing.T) {
	t.Run("stream application", func(t *testing.T) {
		e, slot, path := newBatchDispatchHarness(t, true)
		e.recvMu.Lock()
		e.packetized = false
		e.recvMu.Unlock()
		startBatchDispatchHarness(t, e, slot)
		waiter := queueBatchApplicationJob(t, slot, 0, true)
		if result := awaitBatchDispatchResult(t, waiter); result.err != nil {
			t.Fatal(result.err)
		}
		batches, ordinary, seqs := path.snapshot()
		if len(batches) != 0 || len(ordinary) != 1 || ordinary[0] != proto.FrameData || seqs[0] != 0 {
			t.Fatalf("batches=%v ordinary=%v seqs=%v", batches, ordinary, seqs)
		}
		if slot.batchWriteCalls.Load() != 0 {
			t.Fatalf("stream dispatch reported %d batch writes", slot.batchWriteCalls.Load())
		}
	})

	t.Run("packet replay", func(t *testing.T) {
		e, slot, path := newBatchDispatchHarness(t, true)
		result := make(chan pathDispatchResult, 1)
		if !slot.submitDispatch(pathDispatchJob{
			frame:  executionDataFrame(t, 8, []byte("replay")),
			result: result, generation: slot.dispatchNextGen.Add(1),
		}) {
			t.Fatal("failed to queue replay dispatch")
		}
		startBatchDispatchHarness(t, e, slot)
		select {
		case got := <-result:
			if got.err != nil {
				t.Fatal(got.err)
			}
		case <-time.After(time.Second):
			t.Fatal("replay dispatch timed out")
		}
		batches, ordinary, seqs := path.snapshot()
		if len(batches) != 0 || len(ordinary) != 1 || ordinary[0] != proto.FrameData || seqs[0] != 8 {
			t.Fatalf("batches=%v ordinary=%v seqs=%v", batches, ordinary, seqs)
		}
		if got := slot.firstDataDispatches.Load(); got != 0 {
			t.Fatalf("replay first-publication count=%d", got)
		}
		if slot.batchWriteCalls.Load() != 0 {
			t.Fatalf("replay reported %d batch writes", slot.batchWriteCalls.Load())
		}
	})
}

func TestLateBatchSuccessAfterSelectorHandoffCountsFirstPublicationOnce(t *testing.T) {
	manifest, _ := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "path"),
		runtimeNode(proto.GraphNodeKindPath, "path"),
	)
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{}.Clamp())
	server := New(SideServer, flow, Limits{}.Clamp())
	client.SetPacketMode()
	server.SetPacketMode()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	configureRecursivePair(t, client, server, manifest)
	clientBase, serverPath := newMemoryPathPair()
	batchPath := newRecordingFrameBatchPath(clientBase)
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	batchPath.batchHook = func(frames [][]byte) (int, error) {
		select {
		case <-release:
			return batchPath.writeWholeFrames(frames)
		case <-batchPath.closed:
			return 0, net.ErrClosed
		}
	}
	attachRecursivePath(t, client, server, "path", batchPath, serverPath)

	done := make(chan error, 1)
	go func() { done <- client.SendPacket([]byte("handoff")) }()
	awaitSignal(t, batchPath.batchStarted, "batch start")
	generation := client.beginSelectorCutover()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("handoff surfaced to application: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("application did not hand published packet to cutover")
	}
	if !client.selectorCutoverDidHandoff(generation) {
		t.Fatal("selector cutover did not receive dispatch ownership")
	}
	client.finishSelectorCutover(generation)
	releaseOnce.Do(func() { close(release) })

	eventuallyEngine(t, time.Second, func() bool {
		paths := client.Paths()
		return len(paths) == 1 && paths[0].DataWrites == 1 &&
			paths[0].DataDispatches == 1 && paths[0].FirstDataDispatches == 1
	})
	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	packet, err := server.RecvPacket()
	if err != nil {
		t.Fatal(err)
	}
	if string(packet) != "handoff" {
		t.Fatalf("packet=%q", packet)
	}
}

func TestPacketBatchSelectorCutoverReplaysBeforeLateOldSuccess(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{}.Clamp())
	server := New(SideServer, flow, Limits{}.Clamp())
	client.SetPacketMode()
	server.SetPacketMode()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	configureRecursivePair(t, client, server, manifest)

	clientA, serverA := newMemoryPathPair()
	oldPath := newRecordingFrameBatchPath(clientA)
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	oldPath.batchHook = func(frames [][]byte) (int, error) {
		select {
		case <-release:
			return oldPath.writeWholeFrames(frames)
		case <-oldPath.closed:
			return 0, net.ErrClosed
		}
	}
	attachRecursivePath(t, client, server, "a", oldPath, serverA)
	clientB, serverB := newMemoryPathPair()
	newPath := &captureDispatchPath{PathConn: clientB}
	attachRecursivePath(t, client, server, "b", newPath, serverB)

	sendDone := make(chan error, 1)
	go func() { sendDone <- client.SendPacket([]byte("cutover")) }()
	awaitSignal(t, oldPath.batchStarted, "old-path batch start")
	client.sendMu.Lock()
	sendLocked := true
	defer func() {
		if sendLocked {
			client.sendMu.Unlock()
		}
	}()
	cutoverDone := make(chan error, 1)
	go func() {
		cutoverDone <- client.selectLocalTarget(ids["root"], ids["b"], "quality", policySelectionQuality)
	}()
	eventuallyEngine(t, time.Second, func() bool {
		pending, _ := client.selectorCutoverSnapshot()
		return pending
	})
	select {
	case err := <-sendDone:
		if err != nil {
			t.Fatalf("packet handoff surfaced error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("packet did not hand off to selector cutover")
	}
	client.sendMu.Unlock()
	sendLocked = false
	select {
	case err := <-cutoverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("selector cutover did not replay on the new path")
	}
	if got := newPath.dataSequences(); !equalBatchSequences(got, []uint64{0}) {
		t.Fatalf("new-path replay sequences=%v want [0]", got)
	}

	releaseOnce.Do(func() { close(release) })
	eventuallyEngine(t, time.Second, func() bool {
		var oldInfo, newInfo *transport.PathInfo
		paths := client.Paths()
		for i := range paths {
			switch paths[i].Spec.Opts["name"] {
			case "a":
				oldInfo = &paths[i]
			case "b":
				newInfo = &paths[i]
			}
		}
		return oldInfo != nil && newInfo != nil &&
			oldInfo.DataDispatches == 1 && oldInfo.FirstDataDispatches == 1 &&
			newInfo.DataDispatches == 1 && newInfo.FirstDataDispatches == 0
	})
	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	packet, err := server.RecvPacket()
	if err != nil {
		t.Fatal(err)
	}
	if string(packet) != "cutover" {
		t.Fatalf("packet=%q", packet)
	}
	eventuallyEngine(t, time.Second, func() bool { return server.RecvDups() >= 1 })
}

func TestPacketBatchWriteDeadlineDoesNotCancelLatePhysicalSuccess(t *testing.T) {
	manifest, _ := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "path"),
		runtimeNode(proto.GraphNodeKindPath, "path"),
	)
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{}.Clamp())
	server := New(SideServer, flow, Limits{}.Clamp())
	client.SetPacketMode()
	server.SetPacketMode()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	configureRecursivePair(t, client, server, manifest)
	clientBase, serverPath := newMemoryPathPair()
	batchPath := newRecordingFrameBatchPath(clientBase)
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	batchPath.batchHook = func(frames [][]byte) (int, error) {
		select {
		case <-release:
			return batchPath.writeWholeFrames(frames)
		case <-batchPath.closed:
			return 0, net.ErrClosed
		}
	}
	attachRecursivePath(t, client, server, "path", batchPath, serverPath)

	done := make(chan error, 1)
	go func() { done <- client.SendPacket([]byte("deadline")) }()
	awaitSignal(t, batchPath.batchStarted, "batch start")
	if err := client.SetWriteDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrWriteDeadlineExceeded) {
			t.Fatalf("write error=%v want deadline", err)
		}
	case <-time.After(time.Second):
		t.Fatal("packet write did not observe deadline")
	}
	releaseOnce.Do(func() { close(release) })
	eventuallyEngine(t, time.Second, func() bool {
		paths := client.Paths()
		return len(paths) == 1 && paths[0].FirstDataDispatches == 1
	})
}

func TestAcceptedPacketReturnsAfterBoundedCustodyBeforePhysicalCompletion(t *testing.T) {
	manifest, _ := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "path"),
		runtimeNode(proto.GraphNodeKindPath, "path"),
	)
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{}.Clamp())
	server := New(SideServer, flow, Limits{}.Clamp())
	client.SetPacketMode()
	server.SetPacketMode()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	configureRecursivePair(t, client, server, manifest)
	clientBase, serverPath := newMemoryPathPair()
	batchPath := newRecordingFrameBatchPath(clientBase)
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	batchPath.batchHook = func(frames [][]byte) (int, error) {
		<-release
		return batchPath.writeWholeFrames(frames)
	}
	attachRecursivePath(t, client, server, "path", batchPath, serverPath)

	done := make(chan error, 1)
	go func() {
		_, err := client.SendPacketAcceptedResult([]byte("accepted"))
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("accepted packet waited for physical completion")
	}
	awaitSignal(t, batchPath.batchStarted, "accepted packet physical dispatch")
	client.selectorCutoverMu.Lock()
	if client.acceptedPacketDispatches != 1 {
		t.Fatalf("accepted packet dispatches=%d want 1", client.acceptedPacketDispatches)
	}
	client.selectorCutoverMu.Unlock()

	releaseOnce.Do(func() { close(release) })
	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	packet, err := server.RecvPacket()
	if err != nil || string(packet) != "accepted" {
		t.Fatalf("received packet=%q err=%v", packet, err)
	}
	eventuallyEngine(t, time.Second, func() bool {
		client.selectorCutoverMu.Lock()
		defer client.selectorCutoverMu.Unlock()
		return client.acceptedPacketDispatches == 0
	})
}

func TestAcceptedPacketLinearizesBeforeGracefulClose(t *testing.T) {
	manifest, _ := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "path"),
		runtimeNode(proto.GraphNodeKindPath, "path"),
	)
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{}.Clamp())
	server := New(SideServer, flow, Limits{}.Clamp())
	client.SetPacketMode()
	server.SetPacketMode()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	configureRecursivePair(t, client, server, manifest)
	clientBase, serverPath := newMemoryPathPair()
	batchPath := newRecordingFrameBatchPath(clientBase)
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	batchPath.batchHook = func(frames [][]byte) (int, error) {
		<-release
		return batchPath.writeWholeFrames(frames)
	}
	attachRecursivePath(t, client, server, "path", batchPath, serverPath)

	if published, err := client.SendPacketAcceptedResult([]byte("accepted-before-close")); err != nil || !published {
		t.Fatalf("accepted packet published=%t err=%v", published, err)
	}
	awaitSignal(t, batchPath.batchStarted, "accepted packet physical dispatch")

	client.BeginGracefulClose()
	closeDone := make(chan error, 1)
	go func() { closeDone <- client.GracefulClose(proto.ByeNormal) }()
	select {
	case err := <-closeDone:
		t.Fatalf("GracefulClose crossed an accepted blocked DATA dispatch: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	releaseOnce.Do(func() { close(release) })
	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	packet, err := server.RecvPacket()
	if err != nil || string(packet) != "accepted-before-close" {
		t.Fatalf("received packet=%q err=%v", packet, err)
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("GracefulClose after accepted DATA delivery: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("GracefulClose did not finish after accepted DATA and BYE were acknowledged")
	}

	batches, ordinaryTypes, ordinarySeqs := batchPath.snapshot()
	if len(batches) != 1 || !equalBatchSequences(batches[0], []uint64{0}) {
		t.Fatalf("DATA batches=%v want [[0]]", batches)
	}
	if len(ordinaryTypes) != 1 || ordinaryTypes[0] != proto.FrameCtrl ||
		len(ordinarySeqs) != 1 || ordinarySeqs[0] != 1 {
		t.Fatalf("post-DATA ordinary types/seqs=%v/%v want [CTRL]/[1]", ordinaryTypes, ordinarySeqs)
	}
}

func TestAcceptedPacketWithExistingDeadlineWaitsForPhysicalResult(t *testing.T) {
	manifest, _ := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "path"),
		runtimeNode(proto.GraphNodeKindPath, "path"),
	)
	client := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	server := New(SideServer, client.FlowID(), Limits{}.Clamp())
	client.SetPacketMode()
	server.SetPacketMode()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	configureRecursivePair(t, client, server, manifest)
	clientBase, serverPath := newMemoryPathPair()
	batchPath := newRecordingFrameBatchPath(clientBase)
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	batchPath.batchHook = func(frames [][]byte) (int, error) {
		<-release
		return batchPath.writeWholeFrames(frames)
	}
	attachRecursivePath(t, client, server, "path", batchPath, serverPath)
	if err := client.SetWriteDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := client.SendPacketAcceptedResult([]byte("deadline"))
		done <- err
	}()
	awaitSignal(t, batchPath.batchStarted, "deadline-bearing physical dispatch")
	select {
	case err := <-done:
		if !errors.Is(err, ErrWriteDeadlineExceeded) {
			t.Fatalf("write error=%v want deadline", err)
		}
	case <-time.After(time.Second):
		t.Fatal("deadline-bearing accepted packet did not time out")
	}
	releaseOnce.Do(func() { close(release) })
}

func TestAcceptedPacketInFlightForcesSelectorCutoverReplay(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{}.Clamp())
	server := New(SideServer, flow, Limits{}.Clamp())
	client.SetPacketMode()
	server.SetPacketMode()
	client.tailReplayInitialDelay = time.Hour
	client.tailReplayMaxBackoff = time.Hour
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	configureRecursivePair(t, client, server, manifest)

	clientA, serverA := newMemoryPathPair()
	oldPath := newRecordingFrameBatchPath(clientA)
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	oldPath.batchHook = func(frames [][]byte) (int, error) {
		<-release
		return oldPath.writeWholeFrames(frames)
	}
	attachRecursivePath(t, client, server, "a", oldPath, serverA)
	clientB, serverB := newMemoryPathPair()
	newPath := &captureDispatchPath{PathConn: clientB}
	attachRecursivePath(t, client, server, "b", newPath, serverB)

	if _, err := client.SendPacketAcceptedResult([]byte("cutover-accepted")); err != nil {
		t.Fatal(err)
	}
	awaitSignal(t, oldPath.batchStarted, "accepted old-path batch")
	cutoverDone := make(chan error, 1)
	go func() {
		cutoverDone <- client.selectLocalTarget(ids["root"], ids["b"], "quality", policySelectionQuality)
	}()
	select {
	case err := <-cutoverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("selector cutover did not replay accepted packet")
	}
	if got := newPath.dataSequences(); !equalBatchSequences(got, []uint64{0}) {
		t.Fatalf("new-path replay sequences=%v want [0]", got)
	}

	releaseOnce.Do(func() { close(release) })
	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	packet, err := server.RecvPacket()
	if err != nil || string(packet) != "cutover-accepted" {
		t.Fatalf("received packet=%q err=%v", packet, err)
	}
	eventuallyEngine(t, time.Second, func() bool { return server.RecvDups() >= 1 })
}

func newBatchDispatchHarness(t *testing.T, batch bool) (*Engine, *pathSlot, *recordingFrameBatchPath) {
	t.Helper()
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	e.SetPacketMode()
	path, peer := newMemoryPathPair()
	recording := newRecordingFrameBatchPath(path)
	var conn transport.PathConn = recording
	if !batch {
		conn = path
	}
	slot := &pathSlot{
		id: 1, owner: 1, conn: conn,
		quit: make(chan struct{}), doneW: make(chan struct{}),
		dispatchQ:   make(chan pathDispatchJob, pathDispatchQueueSize),
		writePermit: newPathWritePermit(), admissionDone: make(chan struct{}),
	}
	slot.txEnabled.Store(true)
	t.Cleanup(func() {
		slot.closeQuit()
		_ = conn.Close()
		_ = peer.Close()
		if slot.writerStarted.Load() {
			select {
			case <-slot.doneW:
			case <-time.After(time.Second):
				t.Error("batch path writer did not stop")
			}
		}
		_ = e.Close()
	})
	return e, slot, recording
}

func startBatchDispatchHarness(t *testing.T, e *Engine, slot *pathSlot) {
	t.Helper()
	if !slot.writerStarted.CompareAndSwap(false, true) {
		t.Fatal("batch dispatch harness already started")
	}
	go e.pathWriterLoop(slot)
}

func queueBatchApplicationJob(t *testing.T, slot *pathSlot, seq uint64, firstPublication bool) *applicationDispatchWaiter {
	t.Helper()
	waiter := acquireApplicationDispatchWaiter()
	job := pathDispatchJob{
		frame:            executionDataFrame(t, seq, []byte{byte(seq)}),
		firstPublication: firstPublication,
		applicationWait:  waiter,
		generation:       slot.dispatchNextGen.Add(1),
	}
	if !slot.submitDispatch(job) {
		releaseApplicationDispatchWaiter(waiter)
		t.Fatal("failed to queue packet application dispatch")
	}
	return waiter
}

func queueBatchControlJob(t *testing.T, slot *pathSlot, seq uint64) <-chan pathDispatchResult {
	t.Helper()
	frame := make([]byte, proto.HeaderSize)
	if err := (proto.Header{Version: proto.Version, Type: proto.FrameCtrl, Seq: seq}).Encode(frame); err != nil {
		t.Fatal(err)
	}
	result := make(chan pathDispatchResult, 1)
	if !slot.submitDispatch(pathDispatchJob{frame: frame, result: result, generation: slot.dispatchNextGen.Add(1)}) {
		t.Fatal("failed to queue control dispatch")
	}
	return result
}

func awaitBatchDispatchResult(t *testing.T, waiter *applicationDispatchWaiter) pathDispatchResult {
	t.Helper()
	select {
	case result := <-waiter.done:
		releaseApplicationDispatchWaiter(waiter)
		return result
	case <-time.After(time.Second):
		t.Fatal("dispatch result timed out")
		return pathDispatchResult{}
	}
}

func awaitSignal(t *testing.T, signal <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatalf("%s timed out", name)
	}
}

func decodeBatchTestHeader(frame []byte) (proto.Header, error) {
	if len(frame) < proto.HeaderSize {
		return proto.Header{}, io.ErrUnexpectedEOF
	}
	return proto.DecodeHeader(frame[:proto.HeaderSize])
}

func equalBatchSequences(left, right []uint64) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func contextWithTestTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), time.Second)
}
