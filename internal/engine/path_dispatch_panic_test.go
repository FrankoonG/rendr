package engine

import (
	"context"
	"errors"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/dispatchtrust"
	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type panicOncePathWrite struct {
	transport.PathConn
	mu        sync.Mutex
	remaining int
	cause     error
}

func (path *panicOncePathWrite) MaxFrameSize() int { return testPacketFrameSize(path.PathConn) }

func (path *panicOncePathWrite) LeafMobilityClaim() *leafmobility.Claim {
	return testPathMobilityClaim(path.PathConn)
}

type panicProbeControlPath struct {
	transport.PathConn
	mu        sync.Mutex
	code      proto.CtrlCode
	remaining int
	cause     error
}

func (path *panicProbeControlPath) MaxFrameSize() int { return testPacketFrameSize(path.PathConn) }

func (path *panicProbeControlPath) Write(frame []byte) (int, error) {
	if len(frame) >= proto.HeaderSize {
		header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
		if err == nil && header.Type == proto.FrameCtrl && proto.CtrlCodeFromFlags(header.Flags) == path.code {
			path.mu.Lock()
			if path.remaining > 0 {
				path.remaining--
				cause := path.cause
				path.mu.Unlock()
				panic(cause)
			}
			path.mu.Unlock()
		}
	}
	return path.PathConn.Write(frame)
}

func (path *panicOncePathWrite) Write(frame []byte) (int, error) {
	if !isDispatchDATAFrame(frame) {
		return path.PathConn.Write(frame)
	}
	path.mu.Lock()
	if path.remaining > 0 {
		path.remaining--
		cause := path.cause
		path.mu.Unlock()
		panic(cause)
	}
	path.mu.Unlock()
	return path.PathConn.Write(frame)
}

type panicOnceFrameDispatchWriter struct {
	transport.PathConn
	mu        sync.Mutex
	remaining int
	cause     error
}

func (path *panicOnceFrameDispatchWriter) MaxFrameSize() int {
	return testPacketFrameSize(path.PathConn)
}

func (path *panicOnceFrameDispatchWriter) WriteFrameDispatch(
	frame []byte,
	_ FrameDispatchAuthorization,
) (int, error) {
	path.mu.Lock()
	if path.remaining > 0 {
		path.remaining--
		cause := path.cause
		path.mu.Unlock()
		panic(cause)
	}
	path.mu.Unlock()
	return path.PathConn.Write(frame)
}

type panicOnceFrameBatchWriter struct {
	*recordingFrameBatchPath
	mu        sync.Mutex
	remaining int
	cause     error
}

func (path *panicOnceFrameBatchWriter) LeafMobilityClaim() *leafmobility.Claim {
	return testPathMobilityClaim(path.recordingFrameBatchPath.PathConn)
}

func (path *panicOnceFrameBatchWriter) WriteFrameBatch(frames [][]byte) (int, error) {
	path.mu.Lock()
	if path.remaining > 0 {
		path.remaining--
		cause := path.cause
		path.mu.Unlock()
		panic(cause)
	}
	path.mu.Unlock()
	return path.recordingFrameBatchPath.WriteFrameBatch(frames)
}

type panicDispatchTracePath struct {
	transport.PathConn
	mu           sync.Mutex
	beginPanics  int
	finishPanics int
	beginCalls   int
	finishCalls  int
	panicCause   error
}

func (path *panicDispatchTracePath) MaxFrameSize() int {
	return testPacketFrameSize(path.PathConn)
}

type panicDispatchTraceSpan struct {
	path *panicDispatchTracePath
}

type internalSentinelMatchingPanic struct {
	target error
}

func (err *internalSentinelMatchingPanic) Error() string {
	return "external panic value matching " + err.target.Error()
}

func (err *internalSentinelMatchingPanic) Is(target error) bool {
	return target == err.target
}

type goexitDispatchGate struct {
	entered     chan struct{}
	release     chan struct{}
	enteredOnce sync.Once
	releaseOnce sync.Once
	mu          sync.Mutex
	calls       int
}

func newGoexitDispatchGate() *goexitDispatchGate {
	return &goexitDispatchGate{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (gate *goexitDispatchGate) trigger() {
	gate.mu.Lock()
	gate.calls++
	gate.mu.Unlock()
	gate.enteredOnce.Do(func() { close(gate.entered) })
	<-gate.release
	runtime.Goexit()
}

func (gate *goexitDispatchGate) releaseCallback() {
	gate.releaseOnce.Do(func() { close(gate.release) })
}

func (gate *goexitDispatchGate) callCount() int {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	return gate.calls
}

type goexitPathConn struct {
	transport.PathConn
	gate *goexitDispatchGate
}

func (path *goexitPathConn) MaxFrameSize() int { return testPacketFrameSize(path.PathConn) }

func (path *goexitPathConn) LeafMobilityClaim() *leafmobility.Claim {
	return testPathMobilityClaim(path.PathConn)
}

func (path *goexitPathConn) Write(frame []byte) (int, error) {
	if isDispatchDATAFrame(frame) {
		path.gate.trigger()
	}
	return path.PathConn.Write(frame)
}

type goexitFrameDispatchPath struct {
	transport.PathConn
	gate *goexitDispatchGate
}

func (path *goexitFrameDispatchPath) MaxFrameSize() int {
	return testPacketFrameSize(path.PathConn)
}

func (path *goexitFrameDispatchPath) LeafMobilityClaim() *leafmobility.Claim {
	return testPathMobilityClaim(path.PathConn)
}

func (path *goexitFrameDispatchPath) WriteFrameDispatch(
	[]byte,
	FrameDispatchAuthorization,
) (int, error) {
	path.gate.trigger()
	return 0, nil
}

type goexitOwnedFrameDispatchPath struct {
	transport.PathConn
	gate *goexitDispatchGate
}

func (path *goexitOwnedFrameDispatchPath) MaxFrameSize() int {
	return testPacketFrameSize(path.PathConn)
}

func (path *goexitOwnedFrameDispatchPath) LeafMobilityClaim() *leafmobility.Claim {
	return testPathMobilityClaim(path.PathConn)
}

func (path *goexitOwnedFrameDispatchPath) WriteFrameDispatch(
	frame []byte,
	_ FrameDispatchAuthorization,
) (int, error) {
	return path.PathConn.Write(frame)
}

func (path *goexitOwnedFrameDispatchPath) WriteOwnedFrameDispatch(
	dispatchtrust.Token,
	[]byte,
	FrameDispatchAuthorization,
) (int, error) {
	path.gate.trigger()
	return 0, nil
}

type goexitDispatchTracerPath struct {
	transport.PathConn
	gate  *goexitDispatchGate
	phase string
}

func (path *goexitDispatchTracerPath) MaxFrameSize() int {
	return testPacketFrameSize(path.PathConn)
}

func (path *goexitDispatchTracerPath) LeafMobilityClaim() *leafmobility.Claim {
	return testPathMobilityClaim(path.PathConn)
}

type goexitDispatchTracerSpan struct {
	path *goexitDispatchTracerPath
}

func (path *goexitDispatchTracerPath) BeginFrameDispatch(
	FrameDispatchAuthorization,
) FrameDispatchSpan {
	if path.phase == "begin" {
		path.gate.trigger()
	}
	return &goexitDispatchTracerSpan{path: path}
}

func (span *goexitDispatchTracerSpan) FinishFrameDispatch(FrameDispatchCompletion) {
	if span.path.phase == "finish" {
		span.path.gate.trigger()
	}
}

type goexitFrameBatchPath struct {
	*recordingFrameBatchPath
	gate *goexitDispatchGate
}

func (path *goexitFrameBatchPath) LeafMobilityClaim() *leafmobility.Claim {
	return testPathMobilityClaim(path.recordingFrameBatchPath.PathConn)
}

func (path *goexitFrameBatchPath) WriteFrameBatch([][]byte) (int, error) {
	path.gate.trigger()
	return 0, nil
}

func (path *panicDispatchTracePath) BeginFrameDispatch(
	FrameDispatchAuthorization,
) FrameDispatchSpan {
	path.mu.Lock()
	path.beginCalls++
	if path.beginPanics > 0 {
		path.beginPanics--
		cause := path.panicCause
		path.mu.Unlock()
		panic(cause)
	}
	path.mu.Unlock()
	return &panicDispatchTraceSpan{path: path}
}

func (span *panicDispatchTraceSpan) FinishFrameDispatch(FrameDispatchCompletion) {
	span.path.mu.Lock()
	span.path.finishCalls++
	if span.path.finishPanics > 0 {
		span.path.finishPanics--
		cause := span.path.panicCause
		span.path.mu.Unlock()
		panic(cause)
	}
	span.path.mu.Unlock()
}

func TestPathDispatchContainsExternalWriterPanicsAndReleasesOwnership(t *testing.T) {
	t.Run("PathConn.Write", func(t *testing.T) {
		e, slot, _ := newBatchDispatchHarness(t, false)
		cause := errors.New("panic from generic path writer")
		slot.conn = &panicOncePathWrite{PathConn: slot.conn, remaining: 1, cause: cause}

		waiter := queueAcceptedPacketDispatch(t, e, slot, 0)
		startBatchDispatchHarness(t, e, slot)
		assertDispatchCallbackPanic(t, awaitBatchDispatchResult(t, waiter).err, cause, "PathConn.Write")
		assertDispatchResourcesReleased(t, e, slot)

		next := queueBatchApplicationJob(t, e, slot, 1, true)
		if result := awaitBatchDispatchResult(t, next); result.err != nil {
			t.Fatalf("writer loop did not survive generic Write panic: %v", result.err)
		}
		assertDispatchResourcesReleased(t, e, slot)
	})

	t.Run("FrameDispatchWriter", func(t *testing.T) {
		e, slot, _ := newBatchDispatchHarness(t, false)
		cause := errors.New("panic from frame dispatch writer")
		slot.conn = &panicOnceFrameDispatchWriter{PathConn: slot.conn, remaining: 1, cause: cause}

		first := queueBatchApplicationJob(t, e, slot, 0, true)
		startBatchDispatchHarness(t, e, slot)
		assertDispatchCallbackPanic(
			t, awaitBatchDispatchResult(t, first).err, cause,
			"FrameDispatchWriter.WriteFrameDispatch",
		)
		assertDispatchResourcesReleased(t, e, slot)

		next := queueBatchApplicationJob(t, e, slot, 1, true)
		if result := awaitBatchDispatchResult(t, next); result.err != nil {
			t.Fatalf("writer loop did not survive FrameDispatchWriter panic: %v", result.err)
		}
		assertDispatchResourcesReleased(t, e, slot)
	})

	t.Run("FrameBatchWriter", func(t *testing.T) {
		e, slot, recording := newBatchDispatchHarness(t, true)
		cause := errors.New("panic from frame batch writer")
		slot.conn = &panicOnceFrameBatchWriter{
			recordingFrameBatchPath: recording,
			remaining:               1,
			cause:                   cause,
		}

		first := queueBatchApplicationJob(t, e, slot, 0, true)
		second := queueBatchApplicationJob(t, e, slot, 1, true)
		startBatchDispatchHarness(t, e, slot)
		for _, waiter := range []*applicationDispatchWaiter{first, second} {
			assertDispatchCallbackPanic(
				t, awaitBatchDispatchResult(t, waiter).err, cause,
				"FrameBatchWriter.WriteFrameBatch",
			)
		}
		assertDispatchResourcesReleased(t, e, slot)

		next := queueBatchApplicationJob(t, e, slot, 2, true)
		if result := awaitBatchDispatchResult(t, next); result.err != nil {
			t.Fatalf("writer loop did not survive FrameBatchWriter panic: %v", result.err)
		}
		assertDispatchResourcesReleased(t, e, slot)
	})
}

func TestPathDispatchPanicRetiresExactBoundMobilityClaim(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		wrap      func(transport.PathConn, error) transport.PathConn
	}{
		{
			name: "write", operation: "PathConn.Write",
			wrap: func(path transport.PathConn, cause error) transport.PathConn {
				return &panicOncePathWrite{PathConn: path, remaining: 1, cause: cause}
			},
		},
		{
			name: "batch", operation: "FrameBatchWriter.WriteFrameBatch",
			wrap: func(path transport.PathConn, cause error) transport.PathConn {
				return &panicOnceFrameBatchWriter{
					recordingFrameBatchPath: newRecordingFrameBatchPath(path),
					remaining:               1,
					cause:                   cause,
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cause := errors.New("panic from bound packet path " + test.name)
			e, slot, id, claim := newAttachedAbnormalDispatchHarness(t, test.name, func(path transport.PathConn) transport.PathConn {
				return test.wrap(path, cause)
			})
			assertBoundTestClaim(t, claim)
			death := observeDispatchPathDeath(t, e, id)
			waiter := queueAcceptedPacketDispatch(t, e, slot, 0)
			assertDispatchCallbackPanic(t, awaitBatchDispatchResult(t, waiter).err, cause, test.operation)
			var event PathDeathEvent
			select {
			case event = <-death:
			case <-time.After(time.Second):
				t.Fatal("callback panic did not retire attached path")
			}
			assertDispatchCallbackPanic(t, event.Err, cause, test.operation)
			awaitDispatchWriterExit(t, slot)
			assertRetiredTestClaim(t, claim)
		})
	}
}

func TestPathDispatchInternalSentinelPanicRetiresAttachedPath(t *testing.T) {
	tests := []struct {
		name   string
		panic  error
		target error
	}{
		{name: "exact TX fence", panic: ErrPathTXFenced, target: ErrPathTXFenced},
		{name: "matching TX fence", panic: &internalSentinelMatchingPanic{target: ErrPathTXFenced}, target: ErrPathTXFenced},
		{name: "exact dispatch admission", panic: errFrameDispatchAdmission, target: errFrameDispatchAdmission},
		{name: "matching dispatch admission", panic: &internalSentinelMatchingPanic{target: errFrameDispatchAdmission}, target: errFrameDispatchAdmission},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
			e.SetPacketMode()
			t.Cleanup(func() { _ = e.Close() })
			ids := configureLeafSelectorRuntime(t, e, "sentinel-panic")
			base, peer := newMemoryPathPair()
			t.Cleanup(func() { _ = base.Close(); _ = peer.Close() })
			path := &panicOncePathWrite{PathConn: base, remaining: 1, cause: test.panic}
			id := attachFixturePath(
				t, e, path,
				transport.PathSpec{Transport: "panic-sentinel", Address: test.name},
				ids["sentinel-panic"],
			)
			e.pathsMu.RLock()
			slot := e.paths[id]
			e.pathsMu.RUnlock()
			if slot == nil {
				t.Fatal("attached panic path is missing")
			}

			death := make(chan PathDeathEvent, 1)
			cancel := e.OnPathDeathSerial(func(event PathDeathEvent) {
				if event.ID == id {
					death <- event
				}
			})
			t.Cleanup(cancel)
			waiter := queueAcceptedPacketDispatch(t, e, slot, 0)
			result := awaitBatchDispatchResult(t, waiter)
			assertDispatchCallbackPanic(t, result.err, test.panic, "PathConn.Write")
			if errors.Is(result.err, test.target) {
				t.Fatalf("external panic error matched internal sentinel %v", test.target)
			}

			var event PathDeathEvent
			select {
			case event = <-death:
			case <-time.After(time.Second):
				t.Fatal("sentinel panic did not retire attached path")
			}
			assertDispatchCallbackPanic(t, event.Err, test.panic, "PathConn.Write")
			if errors.Is(event.Err, test.target) {
				t.Fatalf("path death error matched internal sentinel %v", test.target)
			}
			awaitDispatchWriterExit(t, slot)

			e.pathsMu.RLock()
			_, attached := e.paths[id]
			e.pathsMu.RUnlock()
			if attached {
				t.Fatal("sentinel panic path remained in production topology")
			}
			if slot.submitDispatch(pathDispatchJob{}) {
				t.Fatal("retired sentinel panic path accepted another dispatch")
			}
			path.mu.Lock()
			remaining := path.remaining
			path.mu.Unlock()
			if remaining != 0 {
				t.Fatalf("panic callback remaining=%d want 0", remaining)
			}
		})
	}
}

func TestPathDispatchGoexitFailsClosedAndDrainsSingleWriter(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		wrap      func(transport.PathConn, *goexitDispatchGate) transport.PathConn
	}{
		{
			name: "PathConn.Write", operation: "PathConn.Write",
			wrap: func(path transport.PathConn, gate *goexitDispatchGate) transport.PathConn {
				return &goexitPathConn{PathConn: path, gate: gate}
			},
		},
		{
			name: "FrameDispatchWriter", operation: "FrameDispatchWriter.WriteFrameDispatch",
			wrap: func(path transport.PathConn, gate *goexitDispatchGate) transport.PathConn {
				return &goexitFrameDispatchPath{PathConn: path, gate: gate}
			},
		},
		{
			name: "OwnedFrameWriter", operation: "OwnedFrameWriter.WriteOwnedFrameDispatch",
			wrap: func(path transport.PathConn, gate *goexitDispatchGate) transport.PathConn {
				return &goexitOwnedFrameDispatchPath{PathConn: path, gate: gate}
			},
		},
		{
			name: "tracer begin", operation: "FrameDispatchTracer.BeginFrameDispatch",
			wrap: func(path transport.PathConn, gate *goexitDispatchGate) transport.PathConn {
				return &goexitDispatchTracerPath{PathConn: path, gate: gate, phase: "begin"}
			},
		},
		{
			name: "tracer finish", operation: "FrameDispatchSpan.FinishFrameDispatch",
			wrap: func(path transport.PathConn, gate *goexitDispatchGate) transport.PathConn {
				return &goexitDispatchTracerPath{PathConn: path, gate: gate, phase: "finish"}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gate := newGoexitDispatchGate()
			t.Cleanup(gate.releaseCallback)
			e, slot, id, claim := newAttachedAbnormalDispatchHarness(t, test.name, func(path transport.PathConn) transport.PathConn {
				return test.wrap(path, gate)
			})
			assertBoundTestClaim(t, claim)
			death := observeDispatchPathDeath(t, e, id)

			first := queueAcceptedPacketDispatch(t, e, slot, 0)
			awaitSignal(t, gate.entered, "single callback entry")
			assertDispatchCallbackOwnsResources(t, e, slot)
			second := queueAcceptedPacketDispatch(t, e, slot, 1)
			lastGeneration := slot.dispatchNextGen.Load()
			gate.releaseCallback()

			for _, waiter := range []*applicationDispatchWaiter{first, second} {
				assertDispatchCallbackGoexit(t, awaitBatchDispatchResult(t, waiter).err, test.operation)
			}
			assertDispatchGoexitRetiredPath(t, e, slot, id, death, gate, test.operation, lastGeneration)
			assertRetiredTestClaim(t, claim)
		})
	}
}

func TestPathDispatchGoexitFailsClosedAndDrainsBatchWriter(t *testing.T) {
	gate := newGoexitDispatchGate()
	t.Cleanup(gate.releaseCallback)
	e, slot, id, claim := newAttachedAbnormalDispatchHarness(t, "batch", func(path transport.PathConn) transport.PathConn {
		return &goexitFrameBatchPath{recordingFrameBatchPath: newRecordingFrameBatchPath(path), gate: gate}
	})
	assertBoundTestClaim(t, claim)
	death := observeDispatchPathDeath(t, e, id)

	first := queueAcceptedPacketDispatch(t, e, slot, 0)
	awaitSignal(t, gate.entered, "batch callback entry")
	assertDispatchCallbackOwnsResources(t, e, slot)
	second := queueAcceptedPacketDispatch(t, e, slot, 1)
	third := queueAcceptedPacketDispatch(t, e, slot, 2)
	lastGeneration := slot.dispatchNextGen.Load()
	gate.releaseCallback()

	for _, waiter := range []*applicationDispatchWaiter{first, second, third} {
		assertDispatchCallbackGoexit(
			t, awaitBatchDispatchResult(t, waiter).err,
			"FrameBatchWriter.WriteFrameBatch",
		)
	}
	assertDispatchGoexitRetiredPath(
		t, e, slot, id, death, gate, "FrameBatchWriter.WriteFrameBatch", lastGeneration,
	)
	assertRetiredTestClaim(t, claim)

	e.sendHistMu.Lock()
	for sequence := uint64(0); sequence <= 2; sequence++ {
		entry := e.sendHistoryEntryLocked(sequence)
		if entry != nil && entry.batchAttribution != nil && entry.batchAttribution.pending != 0 {
			e.sendHistMu.Unlock()
			t.Fatalf("sequence %d retained %d batch attribution receipts", sequence, entry.batchAttribution.pending)
		}
	}
	e.sendHistMu.Unlock()
}

func TestProbeControlWritesContainPathConnPanicsAndRetirePath(t *testing.T) {
	tests := []struct {
		name  string
		code  proto.CtrlCode
		start func(*Engine, *pathSlot)
	}{
		{
			name: "request",
			code: proto.CtrlPathProbe,
			start: func(e *Engine, slot *pathSlot) {
				e.issuePathProbe(slot)
			},
		},
		{
			name: "reply",
			code: proto.CtrlPathProbeReply,
			start: func(e *Engine, slot *pathSlot) {
				e.handlePathProbeRequest(slot, proto.ProbePayload{ID: 41, TS: 43}.Encode())
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
			t.Cleanup(func() { _ = e.Close() })
			ids := configureLeafSelectorRuntime(t, e, "panic-probe")
			base, peer := newMemoryPathPair()
			t.Cleanup(func() { _ = base.Close(); _ = peer.Close() })
			cause := errors.New("panic from probe control writer")
			path := &panicProbeControlPath{
				PathConn: base, code: test.code, remaining: 1, cause: cause,
			}
			id := attachFixturePath(
				t, e, path,
				transport.PathSpec{Transport: "probe-panic", Address: test.name},
				ids["panic-probe"],
			)
			e.pathsMu.RLock()
			slot := e.paths[id]
			e.pathsMu.RUnlock()
			if slot == nil {
				t.Fatal("attached probe path is missing")
			}

			death := make(chan PathDeathEvent, 1)
			cancel := e.OnPathDeathSerial(func(event PathDeathEvent) {
				if event.ID == id {
					death <- event
				}
			})
			t.Cleanup(cancel)
			test.start(e, slot)

			var event PathDeathEvent
			select {
			case event = <-death:
			case <-time.After(time.Second):
				t.Fatal("probe writer panic did not retire its path")
			}
			if event.Cause != transport.CauseTransportError {
				t.Fatalf("death cause=%v want transport error", event.Cause)
			}
			assertDispatchCallbackPanic(t, event.Err, cause, "PathConn.Write")

			ctx, cancelWait := context.WithTimeout(context.Background(), time.Second)
			if err := slot.waitProbeWriters(ctx); err != nil {
				cancelWait()
				t.Fatalf("probe writer did not drain after panic: %v", err)
			}
			cancelWait()
			slot.probeControlMu.Lock()
			writerCount := slot.probeWriterCount
			replyRunning := slot.probeReplyRunning
			pendingReply := len(slot.probeReplyPending)
			slot.probeControlMu.Unlock()
			if writerCount != 0 || replyRunning || pendingReply != 0 {
				t.Fatalf(
					"probe cleanup writers/running/pending=%d/%t/%d want 0/false/0",
					writerCount, replyRunning, pendingReply,
				)
			}
			if permits := len(slot.writePermit); permits != 1 {
				t.Fatalf("physical write permits=%d want 1 after probe panic", permits)
			}
			e.probeMu.Lock()
			outstanding := 0
			for _, observation := range e.probeOutstanding {
				if observation.slot == slot {
					outstanding++
				}
			}
			e.probeMu.Unlock()
			if outstanding != 0 {
				t.Fatalf("probe panic retained %d outstanding observations", outstanding)
			}
		})
	}
}

func TestSuccessfulDispatchPublishesCompletionBeforeResult(t *testing.T) {
	e, slot, _ := newBatchDispatchHarness(t, false)
	entered := make(chan struct{})
	release := make(chan struct{})
	var enteredOnce sync.Once
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	slot.dispatchBeforeCompletePublication = func() {
		enteredOnce.Do(func() { close(entered) })
		<-release
	}

	waiter := queueBatchApplicationJob(t, e, slot, 0, true)
	identity := pathDispatchIdentity{
		generation:     slot.dispatchNextGen.Load(),
		pathGeneration: pathProbeGenerationForSlot(slot),
	}
	if identity.generation == 0 {
		t.Fatal("queued dispatch has no generation")
	}
	slot.markDispatchStalled(identity)
	startBatchDispatchHarness(t, e, slot)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("dispatch did not reach completion publication boundary")
	}
	select {
	case result := <-waiter.done:
		t.Fatalf("result became visible before completion publication: %+v", result)
	default:
	}
	if completed := slot.dispatchDoneGen.Load(); completed >= identity.generation {
		t.Fatalf("completion generation=%d published before held boundary %d", completed, identity.generation)
	}
	if stalled := slot.dispatchStalled.state.Load(); stalled == nil || stalled.identity != identity {
		t.Fatalf("stall state=%+v want held identity %+v", stalled, identity)
	}

	releaseOnce.Do(func() { close(release) })
	if result := awaitBatchDispatchResult(t, waiter); result.err != nil {
		t.Fatalf("successful dispatch returned error: %v", result.err)
	}
	if completed := slot.dispatchDoneGen.Load(); completed < identity.generation {
		t.Fatalf("visible result preceded completion generation: got %d want >=%d", completed, identity.generation)
	}
	if stalled := slot.dispatchStalled.state.Load(); stalled != nil && stalled.identity == identity {
		t.Fatalf("visible result retained stall state for %+v", identity)
	}
}

func TestPathDispatchContainsTracerPanicsWithoutFailingTransport(t *testing.T) {
	tests := []struct {
		name         string
		beginPanics  int
		finishPanics int
		wantBegin    int
		wantFinish   int
	}{
		{name: "begin", beginPanics: 1, wantBegin: 2, wantFinish: 1},
		{name: "finish", finishPanics: 1, wantBegin: 2, wantFinish: 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e, slot, _ := newBatchDispatchHarness(t, false)
			path := &panicDispatchTracePath{
				PathConn:     slot.conn,
				beginPanics:  test.beginPanics,
				finishPanics: test.finishPanics,
				panicCause:   errors.New("panic from dispatch tracer"),
			}
			slot.conn = path

			first := queueBatchApplicationJob(t, e, slot, 0, true)
			startBatchDispatchHarness(t, e, slot)
			if result := awaitBatchDispatchResult(t, first); result.err != nil {
				t.Fatalf("tracer panic failed physical dispatch: %v", result.err)
			}
			second := queueBatchApplicationJob(t, e, slot, 1, true)
			if result := awaitBatchDispatchResult(t, second); result.err != nil {
				t.Fatalf("writer loop did not survive tracer panic: %v", result.err)
			}
			assertDispatchResourcesReleased(t, e, slot)

			path.mu.Lock()
			beginCalls, finishCalls := path.beginCalls, path.finishCalls
			path.mu.Unlock()
			if beginCalls != test.wantBegin || finishCalls != test.wantFinish {
				t.Fatalf(
					"tracer calls begin/finish=%d/%d want %d/%d",
					beginCalls, finishCalls, test.wantBegin, test.wantFinish,
				)
			}
		})
	}
}

func queueAcceptedPacketDispatch(
	t *testing.T,
	e *Engine,
	slot *pathSlot,
	seq uint64,
) *applicationDispatchWaiter {
	t.Helper()
	frame := executionDataFrame(t, seq, []byte("accepted packet panic containment"))
	admission := ensureBatchTestFrameAdmission(t, e, frame, true)
	waiter := acquireApplicationDispatchWaiter()
	e.selectorCutoverMu.Lock()
	ticket := e.nextDispatchCustodyTicketLocked()
	e.admitAcceptedPacketDispatchLocked(ticket)
	e.selectorCutoverMu.Unlock()
	if !slot.submitDispatch(pathDispatchJob{
		frame: frame, firstPublication: true, admission: admission,
		applicationWait: waiter, acceptedPacket: true, custodyTicket: ticket,
	}) {
		e.completeAcceptedPacketDispatch(ticket)
		releaseApplicationDispatchWaiter(waiter)
		t.Fatal("failed to queue accepted packet dispatch")
	}
	return waiter
}

func assertDispatchCallbackPanic(t *testing.T, err, cause error, operation string) {
	t.Helper()
	var panicErr *pathDispatchCallbackPanicError
	if !errors.As(err, &panicErr) {
		t.Fatalf("dispatch error=%v, want typed callback panic", err)
	}
	if panicErr.operation != operation {
		t.Fatalf("panic operation=%q want %q", panicErr.operation, operation)
	}
	wantType := reflect.TypeOf(cause).String()
	if panicErr.recoveredType != wantType {
		t.Fatalf("recovered panic type=%q want %q", panicErr.recoveredType, wantType)
	}
	if errors.Is(err, cause) {
		t.Fatalf("dispatch error unexpectedly unwraps external panic value %v", cause)
	}
}

func assertDispatchCallbackGoexit(t *testing.T, err error, operation string) {
	t.Helper()
	var goexitErr *pathDispatchCallbackGoexitError
	if !errors.As(err, &goexitErr) {
		t.Fatalf("dispatch error=%v, want typed callback Goexit", err)
	}
	if goexitErr.operation != operation {
		t.Fatalf("Goexit operation=%q want %q", goexitErr.operation, operation)
	}
}

func newAttachedAbnormalDispatchHarness(
	t *testing.T,
	name string,
	wrap func(transport.PathConn) transport.PathConn,
) (*Engine, *pathSlot, uint32, *leafmobility.Claim) {
	t.Helper()
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	e.SetPacketMode()
	t.Cleanup(func() { _ = e.Close() })
	ids := configureLeafSelectorRuntime(t, e, "abnormal")
	base, peer, claim := newClaimedPacketFrameLimitPath(widePacketFrameLimit)
	t.Cleanup(func() { _ = peer.Close() })
	path := transport.PathConn(base)
	if wrap != nil {
		path = wrap(base)
	}
	id := attachFixturePath(
		t, e, path,
		transport.PathSpec{Transport: "abnormal-callback", Address: name},
		ids["abnormal"],
	)
	e.pathsMu.RLock()
	slot := e.paths[id]
	e.pathsMu.RUnlock()
	if slot == nil {
		t.Fatal("attached abnormal callback path is missing")
	}
	return e, slot, id, claim
}

func testPathMobilityClaim(path transport.PathConn) *leafmobility.Claim {
	provider, ok := path.(leafmobility.Provider)
	if !ok {
		return nil
	}
	return provider.LeafMobilityClaim()
}

func assertBoundTestClaim(t *testing.T, claim *leafmobility.Claim) {
	t.Helper()
	state := claim.State()
	if !state.Bound || state.Retired || state.Binding.PathID == 0 || state.Binding.Owner == 0 {
		t.Fatalf("mobility claim is not exactly bound: %+v", state)
	}
}

func assertRetiredTestClaim(t *testing.T, claim *leafmobility.Claim) {
	t.Helper()
	eventuallyEngine(t, time.Second, func() bool { return claim.State().Retired })
	state := claim.State()
	if !state.Bound || !state.Retired || state.Binding.PathID == 0 || state.Binding.Owner == 0 {
		t.Fatalf("exact bound mobility claim was not retired: %+v", state)
	}
}

func observeDispatchPathDeath(t *testing.T, e *Engine, id uint32) <-chan PathDeathEvent {
	t.Helper()
	death := make(chan PathDeathEvent, 1)
	cancel := e.OnPathDeathSerial(func(event PathDeathEvent) {
		if event.ID == id {
			death <- event
		}
	})
	t.Cleanup(cancel)
	return death
}

func assertDispatchCallbackOwnsResources(t *testing.T, e *Engine, slot *pathSlot) {
	t.Helper()
	if permits := len(slot.writePermit); permits != 0 {
		t.Fatalf("callback write permits=%d want 0 while blocked", permits)
	}
	e.sendHistMu.Lock()
	activeLeases := len(e.frameDispatchLeases)
	e.sendHistMu.Unlock()
	if activeLeases != 1 {
		t.Fatalf("active frame dispatch leases=%d want 1 while callback is blocked", activeLeases)
	}
}

func assertDispatchGoexitRetiredPath(
	t *testing.T,
	e *Engine,
	slot *pathSlot,
	id uint32,
	death <-chan PathDeathEvent,
	gate *goexitDispatchGate,
	operation string,
	lastGeneration uint64,
) {
	t.Helper()
	var event PathDeathEvent
	select {
	case event = <-death:
	case <-time.After(time.Second):
		t.Fatal("callback Goexit did not retire attached path")
	}
	assertDispatchCallbackGoexit(t, event.Err, operation)
	awaitDispatchWriterExit(t, slot)

	if permits := len(slot.writePermit); permits != 1 {
		t.Fatalf("physical write permits=%d want 1 after callback Goexit", permits)
	}
	if queued := len(slot.dispatchQ); queued != 0 {
		t.Fatalf("dispatch queue retained %d jobs after callback Goexit", queued)
	}
	e.sendHistMu.Lock()
	activeLeases := len(e.frameDispatchLeases)
	e.sendHistMu.Unlock()
	if activeLeases != 0 {
		t.Fatalf("active frame dispatch leases=%d want 0 after callback Goexit", activeLeases)
	}
	e.selectorCutoverMu.Lock()
	accepted := e.acceptedPacketDispatches
	unclaimed := e.dispatchTicketsUnclaimed
	e.selectorCutoverMu.Unlock()
	if accepted != 0 || unclaimed != 0 {
		t.Fatalf("accepted packet custody count/unclaimed=%d/%d want 0/0", accepted, unclaimed)
	}
	if completed := slot.dispatchDoneGen.Load(); completed < lastGeneration {
		t.Fatalf("completed dispatch generation=%d want >=%d", completed, lastGeneration)
	}
	e.pathsMu.RLock()
	_, attached := e.paths[id]
	e.pathsMu.RUnlock()
	if attached {
		t.Fatal("callback Goexit path remained in production topology")
	}
	if slot.submitDispatch(pathDispatchJob{}) {
		t.Fatal("callback Goexit path accepted another dispatch")
	}
	if calls := gate.callCount(); calls != 1 {
		t.Fatalf("external callback calls=%d want exactly 1", calls)
	}
}

func awaitDispatchWriterExit(t *testing.T, slot *pathSlot) {
	t.Helper()
	select {
	case <-slot.doneW:
	case <-time.After(time.Second):
		t.Fatal("path writer did not close doneW")
	}
}

func isDispatchDATAFrame(frame []byte) bool {
	if len(frame) < proto.HeaderSize {
		return false
	}
	header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	return err == nil && header.Type == proto.FrameData
}

func assertDispatchResourcesReleased(t *testing.T, e *Engine, slot *pathSlot) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := slot.acquireWrite(ctx); err != nil {
		t.Fatalf("physical write permit leaked: %v", err)
	}
	slot.releaseWrite()
	if queued := len(slot.dispatchQ); queued != 0 {
		t.Fatalf("dispatch queue retained %d completed jobs", queued)
	}
	e.sendHistMu.Lock()
	activeLeases := len(e.frameDispatchLeases)
	e.sendHistMu.Unlock()
	if activeLeases != 0 {
		t.Fatalf("active frame dispatch leases=%d want 0", activeLeases)
	}
	e.selectorCutoverMu.Lock()
	accepted := e.acceptedPacketDispatches
	unclaimed := e.dispatchTicketsUnclaimed
	e.selectorCutoverMu.Unlock()
	if accepted != 0 || unclaimed != 0 {
		t.Fatalf("accepted packet custody count/unclaimed=%d/%d want 0/0", accepted, unclaimed)
	}
}
