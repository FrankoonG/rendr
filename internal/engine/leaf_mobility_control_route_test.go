package engine

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

func TestLeafMobilityControlRouteRejectsSingleSubjectPath(t *testing.T) {
	e, _ := newLeafMobilityControlRouteTestEngine(SideClient)
	subject, subjectRef := addLeafMobilityControlRouteTestPath(e, 1, 1, nil)

	frame, err := e.sendLeafMobilityFrameAt(subjectRef, proto.CtrlLeafMobilityPrepare, []byte{1}, nil)
	if frame != nil || !errors.Is(err, ErrLeafMobilityControlRouteUnavailable) {
		t.Fatalf("frame=%x err=%v, want typed control-route error", frame, err)
	}
	if subject.writes.Load() != 0 {
		t.Fatalf("subject writes=%d, want 0", subject.writes.Load())
	}
}

func TestLeafMobilityFramesUseOnlyIndependentControlRoute(t *testing.T) {
	e, _ := newLeafMobilityControlRouteTestEngine(SideClient)
	subject, subjectRef := addLeafMobilityControlRouteTestPath(e, 1, 1, nil)
	control, _ := addLeafMobilityControlRouteTestPath(e, 2, 2, nil)
	subjectSlot := e.paths[subjectRef.ID]

	prepareFrame, err := e.sendLeafMobilityFrameAt(subjectRef, proto.CtrlLeafMobilityPrepare, []byte{1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.sendLeafMobilityFrameOnSlot(subjectRef, subjectSlot, proto.CtrlLeafMobilityAck, []byte{2}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.sendLeafMobilityFrameAt(subjectRef, proto.CtrlLeafMobilityCommit, []byte{3}, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.replayLeafMobilityFrame(subjectRef, prepareFrame); err != nil {
		t.Fatal(err)
	}
	outgoing := &outgoingLeafMobilityTransaction{source: subjectRef, sourceSlot: subjectSlot}
	if err := e.replayLeafMobilityFrameForOutgoing(outgoing, prepareFrame); err != nil {
		t.Fatal(err)
	}

	if subject.writes.Load() != 0 {
		t.Fatalf("subject writes=%d, want 0", subject.writes.Load())
	}
	if control.writes.Load() != 5 {
		t.Fatalf("control writes=%d, want 5", control.writes.Load())
	}
}

func TestLeafMobilityExactFrameFallsThroughFailedControlRoute(t *testing.T) {
	e, _ := newLeafMobilityControlRouteTestEngine(SideClient)
	subject, subjectRef := addLeafMobilityControlRouteTestPath(e, 1, 1, nil)
	controlA := &leafMobilityControlRouteTestPath{writeErr: errors.New("control A write failed"), closed: make(chan struct{})}
	controlA, _ = addLeafMobilityControlRouteTestPath(e, 2, 2, controlA)
	controlB, _ := addLeafMobilityControlRouteTestPath(e, 3, 3, nil)

	frame, err := e.sendLeafMobilityFrameAt(subjectRef, proto.CtrlLeafMobilityPrepare, []byte{1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.replayLeafMobilityFrame(subjectRef, frame); err != nil {
		t.Fatal(err)
	}
	frames := controlB.Frames()
	if len(frames) != 2 || string(frames[0]) != string(frame) || string(frames[1]) != string(frame) {
		t.Fatalf("control B frames=%x, want two exact copies of %x", frames, frame)
	}
	if subject.writes.Load() != 0 || controlA.attempts.Load() != 2 || controlB.writes.Load() != 2 {
		t.Fatalf("writes subject=%d controlA-attempts=%d controlB=%d",
			subject.writes.Load(), controlA.attempts.Load(), controlB.writes.Load())
	}
}

func TestLeafMobilityBlockedControlRouteFallsThroughWithinDeadline(t *testing.T) {
	e, _ := newLeafMobilityControlRouteTestEngine(SideClient)
	_, subjectRef := addLeafMobilityControlRouteTestPath(e, 1, 1, nil)
	controlA := &leafMobilityControlRouteTestPath{block: make(chan struct{}), started: make(chan struct{}), closed: make(chan struct{})}
	controlA, _ = addLeafMobilityControlRouteTestPath(e, 2, 2, controlA)
	controlB, _ := addLeafMobilityControlRouteTestPath(e, 3, 3, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err, pending := e.sendLeafMobilityFrameWithContext(ctx, func(writeCtx context.Context) ([]byte, error) {
		return e.sendLeafMobilityFrameAtContext(writeCtx, subjectRef, proto.CtrlLeafMobilityPrepare, []byte{1}, nil)
	})
	if pending != nil || err != nil {
		t.Fatalf("pending=%v err=%v, want in-deadline fallback", pending, err)
	}
	select {
	case <-controlA.closed:
	case <-time.After(time.Second):
		t.Fatal("route attempt did not close the blocked control slot")
	}
	select {
	case <-controlB.closed:
		t.Fatal("route attempt closed the healthy fallback control slot")
	default:
	}
	if controlB.writes.Load() != 1 {
		t.Fatalf("fallback control writes=%d, want 1", controlB.writes.Load())
	}
}

func TestLeafMobilityDeadlineBeforeControlWriteRegistrationDoesNotLeak(t *testing.T) {
	e, _ := newLeafMobilityControlRouteTestEngine(SideClient)
	_, subjectRef := addLeafMobilityControlRouteTestPath(e, 1, 1, nil)
	control, _ := addLeafMobilityControlRouteTestPath(e, 2, 2, nil)
	releaseSend := make(chan struct{})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err, pending := e.sendLeafMobilityFrameWithContext(ctx, func(writeCtx context.Context) ([]byte, error) {
		<-releaseSend
		return e.sendLeafMobilityFrameAtContext(writeCtx, subjectRef, proto.CtrlLeafMobilityPrepare, []byte{1}, nil)
	})
	if pending == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("pending=%v err=%v", pending, err)
	}
	close(releaseSend)
	select {
	case outcome := <-pending:
		if !errors.Is(outcome.err, context.DeadlineExceeded) {
			t.Fatalf("late write outcome=%v, want deadline", outcome.err)
		}
	case <-time.After(time.Second):
		t.Fatal("write that started after cancellation did not finish")
	}
	select {
	case <-control.closed:
		t.Fatal("deadline closed a control path that never began a write")
	default:
	}
	if active := e.activeLeafMobilityControlWrites(subjectRef); len(active) != 0 {
		t.Fatalf("active control writes=%d, want 0", len(active))
	}
}

func TestLeafMobilityControlRouteExcludesDispatchStalledPath(t *testing.T) {
	e, _ := newLeafMobilityControlRouteTestEngine(SideClient)
	_, subjectRef := addLeafMobilityControlRouteTestPath(e, 1, 1, nil)
	stalled, stalledRef := addLeafMobilityControlRouteTestPath(e, 2, 2, nil)
	healthy, _ := addLeafMobilityControlRouteTestPath(e, 3, 3, nil)
	e.paths[stalledRef.ID].dispatchStalled.Store(true)

	if _, err := e.sendLeafMobilityFrameAt(subjectRef, proto.CtrlLeafMobilityPrepare, []byte{1}, nil); err != nil {
		t.Fatal(err)
	}
	if stalled.writes.Load() != 0 || healthy.writes.Load() != 1 {
		t.Fatalf("stalled/healthy writes=%d/%d want 0/1", stalled.writes.Load(), healthy.writes.Load())
	}
}

func TestLeafMobilityControlRouteRevalidatesSubjectAfterWritePermit(t *testing.T) {
	e, _ := newLeafMobilityControlRouteTestEngine(SideClient)
	_, subjectRef := addLeafMobilityControlRouteTestPath(e, 1, 1, nil)
	control, controlRef := addLeafMobilityControlRouteTestPath(e, 2, 2, nil)
	controlSlot := e.paths[controlRef.ID]
	<-controlSlot.writePermit

	result := make(chan error, 1)
	go func() {
		_, err := e.sendLeafMobilityFrameAt(subjectRef, proto.CtrlLeafMobilityPrepare, []byte{1}, nil)
		result <- err
	}()
	eventuallyLeafMobilityControlRouteTest(t, func() bool {
		active := e.activeLeafMobilityControlWrites(subjectRef)
		return len(active) == 1 && active[0] == controlSlot
	})
	e.pathsMu.Lock()
	delete(e.paths, subjectRef.ID)
	e.pathsMu.Unlock()
	controlSlot.releaseWrite()
	select {
	case err := <-result:
		if !errors.Is(err, ErrLeafMobilityControlRouteUnavailable) {
			t.Fatalf("retired subject write=%v, want typed route error", err)
		}
	case <-time.After(time.Second):
		t.Fatal("control write did not revalidate retired subject")
	}
	if control.writes.Load() != 0 {
		t.Fatalf("retired subject published %d control frame(s)", control.writes.Load())
	}
}

func TestLeafMobilityDeadlineDuringRouteSelectionPreventsPublication(t *testing.T) {
	e, _ := newLeafMobilityControlRouteTestEngine(SideClient)
	_, subjectRef := addLeafMobilityControlRouteTestPath(e, 1, 1, nil)
	control, controlRef := addLeafMobilityControlRouteTestPath(e, 2, 2, nil)
	controlSlot := e.paths[controlRef.ID]
	controlSlot.dispatchMu.Lock()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	type sendResult struct {
		frame []byte
		err   error
	}
	result := make(chan sendResult, 1)
	var published atomic.Bool
	go func() {
		frame, err := e.sendLeafMobilityFrameAtContext(
			ctx, subjectRef, proto.CtrlLeafMobilityCommit, []byte{1},
			func([]byte) error { published.Store(true); return nil },
		)
		result <- sendResult{frame: frame, err: err}
	}()
	<-ctx.Done()
	controlSlot.dispatchMu.Unlock()
	select {
	case outcome := <-result:
		if outcome.frame != nil || !errors.Is(outcome.err, context.DeadlineExceeded) {
			t.Fatalf("frame=%x err=%v, want unpublished deadline", outcome.frame, outcome.err)
		}
	case <-time.After(time.Second):
		t.Fatal("route selection did not observe its expired deadline")
	}
	if published.Load() || control.writes.Load() != 0 {
		t.Fatalf("expired route published=%t writes=%d", published.Load(), control.writes.Load())
	}
}

func TestLeafMobilityControlRouteRevalidatesFenceAfterWritePermit(t *testing.T) {
	e, _ := newLeafMobilityControlRouteTestEngine(SideClient)
	_, subjectRef := addLeafMobilityControlRouteTestPath(e, 1, 1, nil)
	controlA, controlARef := addLeafMobilityControlRouteTestPath(e, 2, 2, nil)
	controlB, _ := addLeafMobilityControlRouteTestPath(e, 3, 3, nil)
	controlASlot := e.paths[controlARef.ID]
	<-controlASlot.writePermit

	result := make(chan error, 1)
	go func() {
		_, err := e.sendLeafMobilityFrameAt(subjectRef, proto.CtrlLeafMobilityPrepare, []byte{1}, nil)
		result <- err
	}()
	eventuallyLeafMobilityControlRouteTest(t, func() bool {
		active := e.activeLeafMobilityControlWrites(subjectRef)
		return len(active) == 1 && active[0] == controlASlot
	})
	controlASlot.fenceDispatch()
	controlASlot.releaseWrite()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("control write did not move past fenced candidate")
	}
	if controlA.writes.Load() != 0 || controlB.writes.Load() != 1 {
		t.Fatalf("writes after fence: controlA=%d controlB=%d", controlA.writes.Load(), controlB.writes.Load())
	}
}

func TestLeafMobilityControlRouteExcludesSharedAffectedResource(t *testing.T) {
	e, _ := newLeafMobilityControlRouteTestEngine(SideClient)
	_, subjectRef := addLeafMobilityControlRouteTestPath(e, 1, 1, nil)
	shared, sharedRef := addLeafMobilityControlRouteTestPath(e, 2, 2, nil)
	independent, _ := addLeafMobilityControlRouteTestPath(e, 3, 3, nil)
	resourceID := leafmobility.ResourceID{1}
	e.paths[subjectRef.ID].mobilityClaim = newLeafMobilityControlRouteTestClaim(t, resourceID)
	e.paths[sharedRef.ID].mobilityClaim = newLeafMobilityControlRouteTestClaim(t, resourceID)

	if _, err := e.sendLeafMobilityFrameAt(subjectRef, proto.CtrlLeafMobilityPrepare, []byte{1}, nil); err != nil {
		t.Fatal(err)
	}
	if shared.writes.Load() != 0 || independent.writes.Load() != 1 {
		t.Fatalf("shared-resource writes=%d independent writes=%d", shared.writes.Load(), independent.writes.Load())
	}
}

func TestLeafMobilityControlRouteSurvivesSubjectRetirement(t *testing.T) {
	e, _ := newLeafMobilityControlRouteTestEngine(SideClient)
	subject, subjectRef := addLeafMobilityControlRouteTestPath(e, 1, 1, nil)
	control, _ := addLeafMobilityControlRouteTestPath(e, 2, 2, nil)
	subjectSlot := e.paths[subjectRef.ID]
	delete(e.paths, subjectRef.ID)
	e.retainedPaths[subjectRef.ID] = subjectSlot

	frame, err := e.sendLeafMobilityFrameAt(subjectRef, proto.CtrlLeafMobilityCommit, []byte{1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.replayLeafMobilityFrame(subjectRef, frame); err != nil {
		t.Fatal(err)
	}
	if subject.writes.Load() != 0 || control.writes.Load() != 2 {
		t.Fatalf("retained subject writes=%d active control writes=%d", subject.writes.Load(), control.writes.Load())
	}
}

func TestLeafMobilityRetiredSubjectWithoutControlRouteReturnsUnavailable(t *testing.T) {
	e, _ := newLeafMobilityControlRouteTestEngine(SideClient)
	_, subjectRef := addLeafMobilityControlRouteTestPath(e, 1, 1, nil)
	subjectSlot := e.paths[subjectRef.ID]
	delete(e.paths, subjectRef.ID)
	e.retainedPaths[subjectRef.ID] = subjectSlot

	frame, err := e.sendLeafMobilityFrameAt(subjectRef, proto.CtrlLeafMobilityCommit, []byte{1}, nil)
	if frame != nil || !errors.Is(err, ErrLeafMobilityControlRouteUnavailable) {
		t.Fatalf("frame=%x err=%v, want typed control-route error", frame, err)
	}
}

func TestRouteLeafMobilityOOBRejectsRetiredSubjectConflicts(t *testing.T) {
	e, flow := newLeafMobilityControlRouteTestEngine(SideServer)
	subjectClient, subjectServer := controlRouteTestTarget(1), controlRouteTestTarget(2)
	subject := controlRouteTestSlot(1, 11, subjectServer, subjectClient, 7, nil)
	samePairControl := controlRouteTestSlot(2, 12, subjectServer, subjectClient, 8, nil)
	sharedResourceControl := controlRouteTestSlot(
		3, 13, controlRouteTestTarget(3), controlRouteTestTarget(4), 9, nil,
	)
	e.retainedPaths[subject.id] = subject
	e.paths[samePairControl.id] = samePairControl
	e.paths[sharedResourceControl.id] = sharedResourceControl
	resourceID := leafmobility.ResourceID{1}
	subject.mobilityClaim = newLeafMobilityControlRouteTestClaim(t, resourceID)
	sharedResourceControl.mobilityClaim = newLeafMobilityControlRouteTestClaim(t, resourceID)

	binding := validControlRouteTestBinding(flow, subjectClient, subjectServer, subject.routeGeneration.Load())
	prepare := proto.LeafMobilityPeerPlanPrepare{
		LeafMobilityPeerPlanBinding: binding,
		ActorEndpointGeneration:     1,
		ActorPlanDigest:             proto.LeafMobilityPlanDigest{1},
	}
	payload, err := prepare.Encode()
	if err != nil {
		t.Fatal(err)
	}
	header := proto.Header{
		Version: proto.Version, Type: proto.FrameCtrl,
		Flags: proto.FlagsForCtrl(proto.CtrlLeafMobilityPrepare), Seq: 42,
	}
	if err := e.routeLeafMobilityOOB(samePairControl, header, payload); err != nil {
		t.Fatalf("retired subject conflict closed the session: %v", err)
	}
	if err := e.routeLeafMobilityOOB(sharedResourceControl, header, payload); err != nil {
		t.Fatalf("retired shared-resource conflict closed the session: %v", err)
	}
	if len(e.leafTx.inbox) != 0 {
		t.Fatal("retired-subject conflict mutated the mobility inbox")
	}
}

func TestRouteLeafMobilityOOBNormalizesControlFailoverToSubjectReplay(t *testing.T) {
	e, flow := newLeafMobilityControlRouteTestEngine(SideServer)
	subjectClient, subjectServer := controlRouteTestTarget(1), controlRouteTestTarget(2)
	controlAClient, controlAServer := controlRouteTestTarget(3), controlRouteTestTarget(4)
	controlBClient, controlBServer := controlRouteTestTarget(5), controlRouteTestTarget(6)
	subject := controlRouteTestSlot(1, 11, subjectServer, subjectClient, 7, nil)
	samePairControl := controlRouteTestSlot(2, 12, subjectServer, subjectClient, 8, nil)
	controlA := controlRouteTestSlot(3, 13, controlAServer, controlAClient, 9, nil)
	controlB := controlRouteTestSlot(4, 14, controlBServer, controlBClient, 10, nil)
	sharedResourceControl := controlRouteTestSlot(5, 15, controlRouteTestTarget(7), controlRouteTestTarget(8), 11, nil)
	e.paths[subject.id], e.paths[samePairControl.id] = subject, samePairControl
	e.paths[controlA.id], e.paths[controlB.id] = controlA, controlB
	e.paths[sharedResourceControl.id] = sharedResourceControl
	resourceID := leafmobility.ResourceID{9}
	subject.mobilityClaim = newLeafMobilityControlRouteTestClaim(t, resourceID)
	sharedResourceControl.mobilityClaim = newLeafMobilityControlRouteTestClaim(t, resourceID)

	binding := validControlRouteTestBinding(flow, subjectClient, subjectServer, subject.routeGeneration.Load())
	prepare := proto.LeafMobilityPeerPlanPrepare{
		LeafMobilityPeerPlanBinding: binding,
		ActorEndpointGeneration:     1,
		ActorPlanDigest:             proto.LeafMobilityPlanDigest{1},
	}
	payload, err := prepare.Encode()
	if err != nil {
		t.Fatal(err)
	}
	header := proto.Header{Version: proto.Version, Type: proto.FrameCtrl, Flags: proto.FlagsForCtrl(proto.CtrlLeafMobilityPrepare), Seq: 41}
	if err := e.routeLeafMobilityOOB(samePairControl, header, payload); err != nil {
		t.Fatalf("same-pair control replay closed the session: %v", err)
	}
	if len(e.leafTx.inbox) != 0 {
		t.Fatal("same-pair rejection mutated the mobility inbox")
	}
	if err := e.routeLeafMobilityOOB(sharedResourceControl, header, payload); err != nil {
		t.Fatalf("shared-resource control replay closed the session: %v", err)
	}
	if len(e.leafTx.inbox) != 0 {
		t.Fatal("shared-resource rejection mutated the mobility inbox")
	}
	if err := e.routeLeafMobilityOOB(controlA, header, payload); err != nil {
		t.Fatal(err)
	}
	first := <-e.leafTx.inbox
	e.releaseLeafMobilityMessageKey(leafMobilityKey(first))
	if first.source != pathRefForSlot(subject) || first.replayed {
		t.Fatalf("first source=%+v replayed=%t, want subject=%+v", first.source, first.replayed, pathRefForSlot(subject))
	}
	if err := e.routeLeafMobilityOOB(controlB, header, payload); err != nil {
		t.Fatalf("exact replay on control B reported route change: %v", err)
	}
	second := <-e.leafTx.inbox
	if second.source != pathRefForSlot(subject) || !second.replayed {
		t.Fatalf("replay source=%+v replayed=%t, want subject=%+v", second.source, second.replayed, pathRefForSlot(subject))
	}
}

type leafMobilityControlRouteTestPath struct {
	writeErr error
	block    chan struct{}
	started  chan struct{}
	start    sync.Once
	closed   chan struct{}
	close    sync.Once
	attempts atomic.Uint64
	writes   atomic.Uint64
	mu       sync.Mutex
	frames   [][]byte
}

func (p *leafMobilityControlRouteTestPath) Read([]byte) (int, error) {
	<-p.closed
	return 0, net.ErrClosed
}

func (p *leafMobilityControlRouteTestPath) Write(frame []byte) (int, error) {
	p.attempts.Add(1)
	if p.started != nil {
		p.start.Do(func() { close(p.started) })
	}
	if p.block != nil {
		select {
		case <-p.block:
		case <-p.closed:
			return 0, net.ErrClosed
		}
	}
	if p.writeErr != nil {
		return 0, p.writeErr
	}
	p.mu.Lock()
	p.frames = append(p.frames, append([]byte(nil), frame...))
	p.mu.Unlock()
	p.writes.Add(1)
	return len(frame), nil
}

func (p *leafMobilityControlRouteTestPath) Close() error {
	p.close.Do(func() { close(p.closed) })
	return nil
}

func (p *leafMobilityControlRouteTestPath) Quality() transport.PathQuality {
	return transport.PathQuality{}
}
func (p *leafMobilityControlRouteTestPath) OnDeath(func(transport.DeathCause, error)) {}
func (p *leafMobilityControlRouteTestPath) LocalAddr() string                         { return "control-test-local" }
func (p *leafMobilityControlRouteTestPath) RemoteAddr() string                        { return "control-test-remote" }

func (p *leafMobilityControlRouteTestPath) Frames() [][]byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	frames := make([][]byte, len(p.frames))
	for i := range p.frames {
		frames[i] = append([]byte(nil), p.frames[i]...)
	}
	return frames
}

func newLeafMobilityControlRouteTestEngine(side Side) (*Engine, [16]byte) {
	flow := NewClientFlowID()
	return &Engine{
		side: side, flowID: flow, paths: make(map[uint32]*pathSlot),
		retainedPaths: make(map[uint32]*pathSlot), stagedPaths: make(map[uint32]*pathSlot),
		leafTx: newLeafMobilityRuntime(), closed: make(chan struct{}),
	}, flow
}

func addLeafMobilityControlRouteTestPath(
	e *Engine,
	id uint32,
	target byte,
	path *leafMobilityControlRouteTestPath,
) (*leafMobilityControlRouteTestPath, PathRef) {
	if path == nil {
		path = &leafMobilityControlRouteTestPath{closed: make(chan struct{})}
	}
	slot := controlRouteTestSlot(id, uint64(id)+100, controlRouteTestTarget(target), controlRouteTestTarget(target+32), uint64(id), path)
	e.paths[id] = slot
	return path, pathRefForSlot(slot)
}

func controlRouteTestSlot(
	id uint32,
	owner uint64,
	local, peer proto.TargetID,
	generation uint64,
	conn transport.PathConn,
) *pathSlot {
	slot := &pathSlot{
		id: id, owner: owner, localTXTargetID: local, peerTXTargetID: peer,
		conn: conn, writePermit: make(chan struct{}, 1), quit: make(chan struct{}),
	}
	slot.writePermit <- struct{}{}
	slot.routeGeneration.Store(generation)
	slot.txEnabled.Store(true)
	return slot
}

func newLeafMobilityControlRouteTestClaim(t testing.TB, resourceID leafmobility.ResourceID) *leafmobility.Claim {
	t.Helper()
	claim, err := leafmobility.NewClaim(leafmobility.Facts{
		Kind: leafmobility.KindRawTCP, Role: leafmobility.RoleDialer, Scope: leafmobility.ScopeEndpoint,
		Session: leafmobility.SessionStream, Generation: 1, ResourceID: resourceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return claim
}

func eventuallyLeafMobilityControlRouteTest(t testing.TB, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition did not become true")
}

func controlRouteTestTarget(value byte) proto.TargetID { return proto.TargetID{value} }

func validControlRouteTestBinding(flow [16]byte, clientTarget, serverTarget proto.TargetID, generation uint64) proto.LeafMobilityPeerPlanBinding {
	return proto.LeafMobilityPeerPlanBinding{
		CoordinatorSide: proto.LeafMobilityActorClient, ActorSide: proto.LeafMobilityActorClient,
		Direction: proto.SenderDirectionClientToServer, SessionKind: proto.LeafMobilitySessionStream,
		Operation: proto.LeafMobilityOperationTCPRepair, Fallback: proto.LeafMobilityFallbackRedialAttach,
		LeaseMillis: 1000, SessionEpoch: proto.SessionEpoch(flow), TransactionID: [16]byte{1},
		ClientGraph:           proto.GraphBinding{Revision: 1, Digest: proto.GraphDigest{1}},
		ServerGraph:           proto.GraphBinding{Revision: 1, Digest: proto.GraphDigest{2}},
		SubjectClientTargetID: clientTarget, SubjectServerTargetID: serverTarget,
		BaseGeneration: 1, ResourceScope: proto.LeafMobilityResourceEndpoint,
		ResourceID: proto.LeafMobilityResourceID{1}, SubjectRouteGeneration: generation,
	}
}
