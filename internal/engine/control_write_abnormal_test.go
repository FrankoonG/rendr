package engine

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type abnormalControlWritePath struct {
	transport.PathConn
	code      proto.CtrlCode
	mode      string
	cause     error
	mu        sync.Mutex
	remaining int
	attempts  atomic.Uint64
}

func (path *abnormalControlWritePath) MaxFrameSize() int {
	return testPacketFrameSize(path.PathConn)
}

func (path *abnormalControlWritePath) Write(frame []byte) (int, error) {
	if controlFrameCode(frame) == path.code {
		path.attempts.Add(1)
		path.mu.Lock()
		trigger := path.remaining > 0
		if trigger {
			path.remaining--
		}
		path.mu.Unlock()
		if trigger {
			switch path.mode {
			case "panic":
				panic(path.cause)
			case "goexit":
				runtime.Goexit()
			case "error":
				return 0, path.cause
			}
		}
	}
	return path.PathConn.Write(frame)
}

func controlFrameCode(frame []byte) proto.CtrlCode {
	if len(frame) < proto.HeaderSize {
		return 0
	}
	header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	if err != nil || header.Type != proto.FrameCtrl {
		return 0
	}
	return proto.CtrlCodeFromFlags(header.Flags)
}

func testControlFrame(t testing.TB, code proto.CtrlCode) []byte {
	t.Helper()
	frame := make([]byte, proto.HeaderSize)
	if err := (proto.Header{
		Version: proto.Version,
		Type:    proto.FrameCtrl,
		Flags:   proto.FlagsForCtrl(code),
	}).Encode(frame); err != nil {
		t.Fatal(err)
	}
	return frame
}

func TestWriteCtrlContainsPathConnPanicAndGoexit(t *testing.T) {
	for _, mode := range []string{"panic", "goexit"} {
		t.Run(mode, func(t *testing.T) {
			local, peer := newMemoryPathPair()
			t.Cleanup(func() { _ = local.Close(); _ = peer.Close() })
			cause := errors.New("abnormal handshake write")
			path := &abnormalControlWritePath{
				PathConn: local, code: proto.CtrlBye, mode: mode, cause: cause, remaining: 1,
			}
			result := make(chan error, 1)
			go func() { result <- writeCtrl(path, proto.CtrlBye, 0, nil, 0) }()
			select {
			case err := <-result:
				if mode == "panic" {
					assertDispatchCallbackPanic(t, err, cause, "PathConn.Write")
				} else {
					assertDispatchCallbackGoexit(t, err, "PathConn.Write")
				}
			case <-time.After(time.Second):
				t.Fatal("abnormal handshake write did not publish a terminal result")
			}
			if attempts := path.attempts.Load(); attempts != 1 {
				t.Fatalf("physical handshake attempts=%d want 1", attempts)
			}
		})
	}
}

func TestPathAdmissionControlGoexitPublishesResultAndRetiresPath(t *testing.T) {
	e, slot, id, path := newAttachedAbnormalControlHarness(t, proto.CtrlPathAdmissionCommit, "goexit")
	death := observeDispatchPathDeath(t, e, id)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := e.WritePathAdmissionControlContext(ctx, id, proto.CtrlPathAdmissionCommit, nil)
	assertDispatchCallbackGoexit(t, err, "PathConn.Write")
	event := awaitControlPathDeath(t, death)
	assertDispatchCallbackGoexit(t, event.Err, "PathConn.Write")
	assertControlPathRetired(t, e, slot, id)
	if attempts := path.attempts.Load(); attempts != 1 {
		t.Fatalf("admission callback attempts=%d want 1", attempts)
	}
}

func TestProbeControlGoexitReleasesOwnershipAndRetiresPath(t *testing.T) {
	tests := []struct {
		name  string
		code  proto.CtrlCode
		start func(*Engine, *pathSlot)
	}{
		{
			name: "request", code: proto.CtrlPathProbe,
			start: func(e *Engine, slot *pathSlot) { e.issuePathProbe(slot) },
		},
		{
			name: "reply", code: proto.CtrlPathProbeReply,
			start: func(e *Engine, slot *pathSlot) {
				e.handlePathProbeRequest(slot, proto.ProbePayload{ID: 31, TS: 37}.Encode())
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e, slot, id, path := newAttachedAbnormalControlHarness(t, test.code, "goexit")
			death := observeDispatchPathDeath(t, e, id)
			test.start(e, slot)
			event := awaitControlPathDeath(t, death)
			assertDispatchCallbackGoexit(t, event.Err, "PathConn.Write")
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			if err := slot.waitProbeWriters(ctx); err != nil {
				cancel()
				t.Fatalf("probe writers did not drain: %v", err)
			}
			cancel()
			slot.probeControlMu.Lock()
			writers := slot.probeWriterCount
			running := slot.probeReplyRunning
			pending := len(slot.probeReplyPending)
			slot.probeControlMu.Unlock()
			if writers != 0 || running || pending != 0 {
				t.Fatalf("probe state writers/running/pending=%d/%t/%d want 0/false/0", writers, running, pending)
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
				t.Fatalf("probe Goexit retained %d observations", outstanding)
			}
			assertControlPathRetired(t, e, slot, id)
			if attempts := path.attempts.Load(); attempts != 1 {
				t.Fatalf("probe callback attempts=%d want 1", attempts)
			}
		})
	}
}

func TestPathAckWriterAbnormalExitPublishesFalseAndRetiresPath(t *testing.T) {
	for _, mode := range []string{"panic", "goexit"} {
		t.Run(mode, func(t *testing.T) {
			e, slot, id, path := newAttachedAbnormalControlHarness(t, proto.CtrlBye, mode)
			death := observeDispatchPathDeath(t, e, id)
			result := make(chan bool, 1)
			e.enqueuePathAck(slot, pathAckWrite{
				frame: testControlFrame(t, proto.CtrlBye), terminal: true, result: result,
			})
			select {
			case ok := <-result:
				if ok {
					t.Fatal("abnormal ACK callback reported success")
				}
			case <-time.After(time.Second):
				t.Fatal("abnormal ACK callback did not publish false")
			}
			event := awaitControlPathDeath(t, death)
			if mode == "panic" {
				assertDispatchCallbackPanic(t, event.Err, path.cause, "PathConn.Write")
			} else {
				assertDispatchCallbackGoexit(t, event.Err, "PathConn.Write")
			}
			waitPathAckWriter(t, slot)
			assertControlPathRetired(t, e, slot, id)
			if attempts := path.attempts.Load(); attempts != 1 {
				t.Fatalf("ACK callback attempts=%d want 1", attempts)
			}
		})
	}
}

func TestPathAckWriterOrdinaryErrorDoesNotInventPathDeath(t *testing.T) {
	e, slot, id, path := newAttachedAbnormalControlHarness(t, proto.CtrlBye, "error")
	death := observeDispatchPathDeath(t, e, id)
	result := make(chan bool, 1)
	e.enqueuePathAck(slot, pathAckWrite{
		frame: testControlFrame(t, proto.CtrlBye), terminal: true, result: result,
	})
	select {
	case ok := <-result:
		if ok {
			t.Fatal("failed ACK write reported success")
		}
	case <-time.After(time.Second):
		t.Fatal("failed ACK write did not publish false")
	}
	waitPathAckWriter(t, slot)
	select {
	case event := <-death:
		t.Fatalf("ordinary ACK error invented path death: %+v", event)
	case <-time.After(20 * time.Millisecond):
	}
	e.pathsMu.RLock()
	attached := e.paths[id] == slot
	e.pathsMu.RUnlock()
	if !attached {
		t.Fatal("ordinary ACK error retired a path without transport death evidence")
	}
	if permits := len(slot.writePermit); permits != 1 {
		t.Fatalf("ordinary ACK error left %d write permits, want 1", permits)
	}
	if attempts := path.attempts.Load(); attempts != 1 {
		t.Fatalf("ordinary ACK attempts=%d want 1", attempts)
	}
}

type goexitLeafControlPath struct {
	*leafMobilityControlRouteTestPath
	once atomic.Bool
}

func (path *goexitLeafControlPath) Write([]byte) (int, error) {
	if path.once.CompareAndSwap(false, true) {
		path.attempts.Add(1)
		runtime.Goexit()
	}
	return 0, errors.New("unexpected repeated leaf control write")
}

func TestLeafMobilityControlGoexitTerminatesWithAndWithoutFallback(t *testing.T) {
	for _, withFallback := range []bool{false, true} {
		name := "without fallback"
		if withFallback {
			name = "with fallback"
		}
		t.Run(name, func(t *testing.T) {
			e, _ := newLeafMobilityControlRouteTestEngine(SideClient)
			_, subjectRef := addLeafMobilityControlRouteTestPath(e, 1, 1, nil)
			base := &leafMobilityControlRouteTestPath{closed: make(chan struct{})}
			abnormal := &goexitLeafControlPath{leafMobilityControlRouteTestPath: base}
			abnormalSlot := controlRouteTestSlot(2, 102, controlRouteTestTarget(2), controlRouteTestTarget(34), 2, abnormal)
			e.paths[2] = abnormalSlot
			var fallback *leafMobilityControlRouteTestPath
			if withFallback {
				fallback, _ = addLeafMobilityControlRouteTestPath(e, 3, 3, nil)
			}

			result := make(chan error, 1)
			go func() {
				_, err := e.sendLeafMobilityFrameAt(subjectRef, proto.CtrlLeafMobilityPrepare, []byte{1}, nil)
				result <- err
			}()
			select {
			case err := <-result:
				if withFallback {
					if err != nil {
						t.Fatalf("healthy fallback did not complete control write: %v", err)
					}
				} else {
					var callbackErr *pathDispatchCallbackGoexitError
					if !errors.As(err, &callbackErr) {
						t.Fatalf("terminal leaf control error=%v, want callback Goexit", err)
					}
				}
			case <-time.After(time.Second):
				t.Fatal("leaf control Goexit stranded its transaction")
			}
			eventuallyEngine(t, time.Second, func() bool {
				e.pathsMu.RLock()
				defer e.pathsMu.RUnlock()
				return e.paths[2] == nil
			})
			if permits := len(abnormalSlot.writePermit); permits != 1 {
				t.Fatalf("leaf control Goexit left %d write permits, want 1", permits)
			}
			if attempts := base.attempts.Load(); attempts != 1 {
				t.Fatalf("leaf control callback attempts=%d want 1", attempts)
			}
			if withFallback && fallback.writes.Load() != 1 {
				t.Fatalf("fallback writes=%d want 1", fallback.writes.Load())
			}
		})
	}
}

func newAttachedAbnormalControlHarness(
	t *testing.T,
	code proto.CtrlCode,
	mode string,
) (*Engine, *pathSlot, uint32, *abnormalControlWritePath) {
	t.Helper()
	e := New(SideClient, NewClientFlowID(), Limits{ProbeInterval: time.Hour}.Clamp())
	e.SetPacketMode()
	t.Cleanup(func() { closeEngineWithin(t, e) })
	ids := configureLeafSelectorRuntime(t, e, "abnormal-control")
	base, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = base.Close(); _ = peer.Close() })
	path := &abnormalControlWritePath{
		PathConn: base, code: code, mode: mode,
		cause: errors.New("abnormal control write"), remaining: 1,
	}
	id := attachFixturePath(
		t, e, path,
		transport.PathSpec{Transport: "abnormal-control", Address: mode},
		ids["abnormal-control"],
	)
	e.pathsMu.RLock()
	slot := e.paths[id]
	e.pathsMu.RUnlock()
	if slot == nil {
		t.Fatal("attached abnormal control path is missing")
	}
	return e, slot, id, path
}

func awaitControlPathDeath(t testing.TB, death <-chan PathDeathEvent) PathDeathEvent {
	t.Helper()
	select {
	case event := <-death:
		return event
	case <-time.After(time.Second):
		t.Fatal("control callback did not retire its path")
		return PathDeathEvent{}
	}
}

func assertControlPathRetired(t testing.TB, e *Engine, slot *pathSlot, id uint32) {
	t.Helper()
	eventuallyEngine(t, time.Second, func() bool {
		e.pathsMu.RLock()
		defer e.pathsMu.RUnlock()
		return e.paths[id] == nil
	})
	if permits := len(slot.writePermit); permits != 1 {
		t.Fatalf("control callback left %d write permits, want 1", permits)
	}
}

func waitPathAckWriter(t testing.TB, slot *pathSlot) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		slot.ackWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ACK writer did not terminate")
	}
	slot.ackMu.Lock()
	running := slot.ackRunning
	pending := slot.ackPendingSet
	slot.ackMu.Unlock()
	if running || pending {
		t.Fatalf("ACK state running/pending=%t/%t want false/false", running, pending)
	}
}

func closeEngineWithin(t testing.TB, e *Engine) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		_ = e.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Engine.Close did not terminate after abnormal control callback")
	}
}
