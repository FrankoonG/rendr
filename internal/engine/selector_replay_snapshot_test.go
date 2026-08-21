package engine

import (
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type authorizationCaptureDispatchPath struct {
	*captureDispatchPath
	mu                sync.Mutex
	authorizations    []FrameDispatchAuthorization
	completions       []FrameDispatchCompletion
	frames            [][]byte
	writesWithoutAuth int
}

type authorizationCaptureDispatchSpan struct {
	path *authorizationCaptureDispatchPath
}

type resultCaptureDispatchPath struct {
	transport.PathConn
	mu             sync.Mutex
	authorizations []FrameDispatchAuthorization
	completions    []FrameDispatchCompletion
	bytesWritten   int
	writeErr       error
}

type resultCaptureDispatchSpan struct {
	path *resultCaptureDispatchPath
}

func (path *resultCaptureDispatchPath) BeginFrameDispatch(
	authorization FrameDispatchAuthorization,
) FrameDispatchSpan {
	path.mu.Lock()
	path.authorizations = append(path.authorizations, authorization)
	path.mu.Unlock()
	return &resultCaptureDispatchSpan{path: path}
}

func (span *resultCaptureDispatchSpan) FinishFrameDispatch(completion FrameDispatchCompletion) {
	span.path.mu.Lock()
	span.path.completions = append(span.path.completions, completion)
	span.path.mu.Unlock()
}

func (path *resultCaptureDispatchPath) Write([]byte) (int, error) {
	return path.bytesWritten, path.writeErr
}

func (path *authorizationCaptureDispatchPath) BeginFrameDispatch(
	authorization FrameDispatchAuthorization,
) FrameDispatchSpan {
	path.mu.Lock()
	path.authorizations = append(path.authorizations, authorization)
	path.mu.Unlock()
	return &authorizationCaptureDispatchSpan{path: path}
}

func (span *authorizationCaptureDispatchSpan) FinishFrameDispatch(completion FrameDispatchCompletion) {
	span.path.mu.Lock()
	span.path.completions = append(span.path.completions, completion)
	span.path.mu.Unlock()
}

func (path *authorizationCaptureDispatchPath) Write(frame []byte) (int, error) {
	if len(frame) >= proto.HeaderSize {
		if header, err := proto.DecodeHeader(frame[:proto.HeaderSize]); err == nil && header.Type == proto.FrameData {
			path.mu.Lock()
			if len(path.authorizations) <= len(path.frames) {
				path.writesWithoutAuth++
			}
			path.frames = append(path.frames, append([]byte(nil), frame...))
			path.mu.Unlock()
		}
	}
	return path.captureDispatchPath.Write(frame)
}

func (path *authorizationCaptureDispatchPath) snapshotAuthorization() (
	[]FrameDispatchAuthorization,
	[]FrameDispatchCompletion,
	[][]byte,
	int,
) {
	path.mu.Lock()
	defer path.mu.Unlock()
	authorizations := append([]FrameDispatchAuthorization(nil), path.authorizations...)
	completions := append([]FrameDispatchCompletion(nil), path.completions...)
	frames := make([][]byte, len(path.frames))
	for i := range path.frames {
		frames[i] = append([]byte(nil), path.frames[i]...)
	}
	return authorizations, completions, frames, path.writesWithoutAuth
}

func TestSelectorCutoverReplaySuppressesACKRetiredDATAAtSnapshot(t *testing.T) {
	tests := []struct {
		name       string
		installACK func(*Engine, chan struct{}, chan struct{})
		ack        bool
		wantReplay []uint64
	}{
		{
			name: "ACK retired before replay snapshot",
			installACK: func(e *Engine, entered, release chan struct{}) {
				e.boundedReplayBeforeSnapshot = func() {
					close(entered)
					<-release
				}
			},
			ack: true,
		},
		{
			name: "ACK accepted after replay snapshot",
			installACK: func(e *Engine, entered, release chan struct{}) {
				e.boundedReplayAfterSnapshot = func() {
					close(entered)
					<-release
				}
			},
			ack: true,
		},
		{name: "unacknowledged snapshot", wantReplay: []uint64{0}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
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
			b, bPeer := newMemoryPathPair()
			t.Cleanup(func() { _ = aPeer.Close(); _ = bPeer.Close() })
			aCapture := &captureDispatchPath{PathConn: a}
			bCapture := &captureDispatchPath{PathConn: b}
			if _, err := e.AttachPath(aCapture, transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": "a"}}); err != nil {
				t.Fatal(err)
			}
			if _, err := e.AttachPath(bCapture, transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": "b"}}); err != nil {
				t.Fatal(err)
			}
			if _, err := e.SendData([]byte("snapshot-boundary")); err != nil {
				t.Fatal(err)
			}
			if got := aCapture.dataSequences(); !slices.Equal(got, []uint64{0}) {
				t.Fatalf("initial path DATA=%v want [0]", got)
			}

			entered := make(chan struct{})
			release := make(chan struct{})
			if test.installACK != nil {
				test.installACK(e, entered, release)
			}
			selectionDone := make(chan error, 1)
			go func() {
				selectionDone <- e.selectLocalTarget(ids["root"], ids["b"], "snapshot-boundary", policySelectionProbeFailure)
			}()
			if test.installACK != nil {
				select {
				case <-entered:
				case <-time.After(time.Second):
					close(release)
					t.Fatal("selector replay did not reach the ACK boundary")
				}
				if test.ack {
					e.notePeerAck(currentAck(e, 1))
				}
				close(release)
			}
			select {
			case err := <-selectionDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("selector replay did not finish")
			}
			if got := bCapture.dataSequences(); !slices.Equal(got, test.wantReplay) {
				t.Fatalf("replacement replay=%v want %v", got, test.wantReplay)
			}
		})
	}
}

func TestPathWriterSuppressesACKRetiredDATAAtFinalBoundary(t *testing.T) {
	for _, test := range []struct {
		name             string
		firstPublication bool
	}{
		{name: "replay"},
		{name: "late initial cohort", firstPublication: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			manifest, _ := runtimeGraph(t,
				runtimeNode(proto.GraphNodeKindSelector, "root", "path"),
				runtimeNode(proto.GraphNodeKindPath, "path"),
			)
			e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
			t.Cleanup(func() { _ = e.Close() })
			if err := e.ConfigureLocalGraph(1, manifest); err != nil {
				t.Fatal(err)
			}
			if err := e.ConfigurePeerGraph(1, manifest); err != nil {
				t.Fatal(err)
			}

			path, peer := newMemoryPathPair()
			t.Cleanup(func() { _ = peer.Close() })
			capture := &captureDispatchPath{PathConn: path}
			ref, err := e.AttachPath(capture, transport.PathSpec{
				Transport: "memory",
				Opts:      map[string]string{"name": "path"},
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := e.SendData([]byte("writer-boundary")); err != nil {
				t.Fatal(err)
			}
			e.cancelTailReplay()
			frames := e.sendHistoryRange(0, 1)
			if len(frames) != 1 {
				t.Fatalf("replay history frames=%d want 1", len(frames))
			}
			admission, err := e.admitFrameDispatch(frames[0], test.firstPublication)
			if err != nil {
				t.Fatalf("admit replay: %v", err)
			}

			e.pathsMu.RLock()
			slot := e.paths[ref]
			e.pathsMu.RUnlock()
			if slot == nil {
				t.Fatal("attached path disappeared")
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

			result := make(chan pathDispatchResult, 1)
			if !slot.submitDispatch(pathDispatchJob{
				frame:            frames[0],
				firstPublication: test.firstPublication,
				admission:        admission,
				result:           result,
				generation:       slot.dispatchNextGen.Add(1),
			}) {
				t.Fatal("failed to queue replay")
			}
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("replay did not reach the final path-writer boundary")
			}
			e.notePeerAck(currentAck(e, 1))
			releaseOnce.Do(func() { close(release) })
			select {
			case got := <-result:
				if got.err != nil {
					t.Fatalf("retired replay result: %v", got.err)
				}
			case <-time.After(time.Second):
				t.Fatal("retired replay did not complete")
			}
			if got := capture.dataSequences(); !slices.Equal(got, []uint64{0}) {
				t.Fatalf("physical DATA writes=%v want [0]", got)
			}
		})
	}
}

func TestPathWriterAuthorizationBindsLedgerOwnedDATA(t *testing.T) {
	manifest, _ := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "path"),
		runtimeNode(proto.GraphNodeKindPath, "path"),
	)
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	base, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = peer.Close() })
	capture := &authorizationCaptureDispatchPath{
		captureDispatchPath: &captureDispatchPath{PathConn: base},
	}
	pathID, err := e.AttachPath(capture, transport.PathSpec{
		Transport: "memory", Opts: map[string]string{"name": "path"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.SendData([]byte("ledger-authorization")); err != nil {
		t.Fatal(err)
	}
	e.cancelTailReplay()
	authorizations, completions, frames, writesWithoutAuth := capture.snapshotAuthorization()
	if len(authorizations) != 1 || len(completions) != 1 || len(frames) != 1 || writesWithoutAuth != 0 {
		t.Fatalf("authorizations/completions/frames/unbound=%d/%d/%d/%d",
			len(authorizations), len(completions), len(frames), writesWithoutAuth)
	}
	authorization := authorizations[0]
	if authorization.Sequence != 0 || authorization.PublishedNext != 1 || authorization.AckNext != 0 ||
		authorization.AdmissionLedgerGeneration == 0 || authorization.LedgerGeneration == 0 ||
		authorization.AdmissionLedgerGeneration > authorization.LedgerGeneration ||
		authorization.AdmissionID == 0 || authorization.AttemptID == 0 ||
		authorization.Kind != FrameDispatchKindInitialCohort || authorization.AuthorizedAt.IsZero() ||
		authorization.FrameBytes != len(frames[0]) ||
		authorization.FrameDigest != proto.DigestFrame(frames[0]) {
		t.Fatalf("authorization=%+v", authorization)
	}
	completion := completions[0]
	if completion.StartedAt.IsZero() || completion.CompletedAt.Before(completion.StartedAt) ||
		completion.FrameBytes != len(frames[0]) || completion.BytesWritten != len(frames[0]) ||
		!completion.BytesWrittenKnown || !completion.WriteAttempted || !completion.WholeFrameAccepted ||
		completion.BatchIndex != 0 || completion.BatchSize != 1 || completion.Err != nil {
		t.Fatalf("completion=%+v", completion)
	}

	e.pathsMu.RLock()
	slot := e.paths[pathID]
	e.pathsMu.RUnlock()
	if slot == nil {
		t.Fatal("attached path disappeared")
	}
	ledgerFrames := e.sendHistoryRange(0, 1)
	if len(ledgerFrames) != 1 {
		t.Fatalf("ledger frames=%d want 1", len(ledgerFrames))
	}
	replayAdmission, err := e.admitFrameDispatch(ledgerFrames[0], false)
	if err != nil {
		t.Fatal(err)
	}
	mutated := append([]byte(nil), ledgerFrames[0]...)
	mutated[len(mutated)-1] ^= 0xff
	foreign := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = foreign.Close() })
	unpublished := executionDataFrame(t, 1, []byte("not-published"))
	unpublishedAdmission := replayAdmission
	unpublishedAdmission.sequence = 1
	unpublishedAdmission.digest = proto.DigestFrame(unpublished)
	tests := []struct {
		name      string
		frame     []byte
		first     bool
		admission frameDispatchAdmission
	}{
		{name: "missing admission", frame: ledgerFrames[0]},
		{name: "digest mismatch", frame: mutated, admission: replayAdmission},
		{name: "dispatch kind mismatch", frame: ledgerFrames[0], first: true, admission: replayAdmission},
		{name: "wrong engine owner", frame: ledgerFrames[0], admission: func() frameDispatchAdmission {
			value := replayAdmission
			value.owner = foreign
			return value
		}()},
		{name: "sequence mismatch", frame: ledgerFrames[0], admission: func() frameDispatchAdmission {
			value := replayAdmission
			value.sequence++
			return value
		}()},
		{name: "zero admission ID", frame: ledgerFrames[0], admission: func() frameDispatchAdmission {
			value := replayAdmission
			value.id = 0
			return value
		}()},
		{name: "zero admission generation", frame: ledgerFrames[0], admission: func() frameDispatchAdmission {
			value := replayAdmission
			value.ledgerGeneration = 0
			return value
		}()},
		{name: "future admission generation", frame: ledgerFrames[0], admission: func() frameDispatchAdmission {
			value := replayAdmission
			value.ledgerGeneration++
			return value
		}()},
		{name: "invalid dispatch kind", frame: ledgerFrames[0], admission: func() frameDispatchAdmission {
			value := replayAdmission
			value.kind = FrameDispatchKind(255)
			return value
		}()},
		{name: "unpublished DATA", frame: unpublished, admission: unpublishedAdmission},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := make(chan pathDispatchResult, 1)
			if !slot.submitDispatch(pathDispatchJob{
				frame: test.frame, firstPublication: test.first, admission: test.admission,
				result: result, generation: slot.dispatchNextGen.Add(1),
			}) {
				t.Fatal("failed to queue invalid DATA")
			}
			select {
			case got := <-result:
				if !errors.Is(got.err, errFrameDispatchAdmission) {
					t.Fatalf("result=%v want admission failure", got.err)
				}
			case <-time.After(time.Second):
				t.Fatal("invalid DATA did not complete")
			}
		})
	}
	_, _, physicalFrames, writesWithoutAuth := capture.snapshotAuthorization()
	if len(physicalFrames) != 1 || writesWithoutAuth != 0 || !slot.txEnabled.Load() {
		t.Fatalf("physical frames/unbound/path-enabled=%d/%d/%t", len(physicalFrames), writesWithoutAuth, slot.txEnabled.Load())
	}
}

func TestPathWriterTraceBindsNormalizedWriteResults(t *testing.T) {
	physicalErr := errors.New("physical write diagnostic")
	for _, test := range []struct {
		name         string
		bytesWritten func(int) int
		writeErr     error
		wantErr      error
		wantErrText  string
		wantWhole    bool
	}{
		{name: "full bytes plus error", bytesWritten: func(frameBytes int) int { return frameBytes }, writeErr: physicalErr, wantErr: physicalErr, wantWhole: true},
		{name: "partial bytes plus error", bytesWritten: func(frameBytes int) int { return frameBytes / 2 }, writeErr: physicalErr, wantErr: physicalErr},
		{name: "partial bytes without error", bytesWritten: func(frameBytes int) int { return frameBytes / 2 }, wantErr: io.ErrShortWrite},
		{name: "zero bytes without error", bytesWritten: func(int) int { return 0 }, wantErr: io.ErrShortWrite},
		{name: "negative byte count", bytesWritten: func(int) int { return -1 }, wantErrText: "invalid write count -1"},
		{name: "oversized byte count", bytesWritten: func(frameBytes int) int { return frameBytes + 1 }, wantErrText: "invalid write count"},
	} {
		t.Run(test.name, func(t *testing.T) {
			manifest, _ := runtimeGraph(t,
				runtimeNode(proto.GraphNodeKindSelector, "root", "path"),
				runtimeNode(proto.GraphNodeKindPath, "path"),
			)
			e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
			t.Cleanup(func() { _ = e.Close() })
			if err := e.ConfigureLocalGraph(1, manifest); err != nil {
				t.Fatal(err)
			}
			if err := e.ConfigurePeerGraph(1, manifest); err != nil {
				t.Fatal(err)
			}
			base, peer := newMemoryPathPair()
			t.Cleanup(func() { _ = peer.Close() })
			path := &resultCaptureDispatchPath{PathConn: base, writeErr: test.writeErr}
			pathID, err := e.AttachPath(path, transport.PathSpec{
				Transport: "memory", Opts: map[string]string{"name": "path"},
			})
			if err != nil {
				t.Fatal(err)
			}
			payload := []byte("write-result")
			frame := make([]byte, proto.HeaderSize+len(payload))
			if err := (proto.Header{Version: proto.Version, Type: proto.FrameData, Seq: 0}).Encode(frame); err != nil {
				t.Fatal(err)
			}
			copy(frame[proto.HeaderSize:], payload)
			reservePublishedTestFrame(t, e, frame)
			path.bytesWritten = test.bytesWritten(len(frame))
			admission, err := e.admitFrameDispatch(frame, true)
			if err != nil {
				t.Fatal(err)
			}
			e.pathsMu.RLock()
			slot := e.paths[pathID]
			e.pathsMu.RUnlock()
			if slot == nil {
				t.Fatal("attached path disappeared")
			}
			result := make(chan pathDispatchResult, 1)
			if !slot.submitDispatch(pathDispatchJob{
				frame: frame, firstPublication: true, admission: admission,
				result: result, generation: slot.dispatchNextGen.Add(1),
			}) {
				t.Fatal("failed to queue traced DATA")
			}
			select {
			case got := <-result:
				if test.wantErr != nil && !errors.Is(got.err, test.wantErr) {
					t.Fatalf("dispatch result=%v want %v", got.err, test.wantErr)
				}
				if test.wantErrText != "" && (got.err == nil || !strings.Contains(got.err.Error(), test.wantErrText)) {
					t.Fatalf("dispatch result=%v want text %q", got.err, test.wantErrText)
				}
			case <-time.After(time.Second):
				t.Fatal("traced DATA did not complete")
			}
			path.mu.Lock()
			authorizations := append([]FrameDispatchAuthorization(nil), path.authorizations...)
			completions := append([]FrameDispatchCompletion(nil), path.completions...)
			path.mu.Unlock()
			if len(authorizations) != 1 || len(completions) != 1 {
				t.Fatalf("authorization/completion=%d/%d", len(authorizations), len(completions))
			}
			completion := completions[0]
			if completion.BytesWritten != path.bytesWritten || !completion.BytesWrittenKnown ||
				!completion.WriteAttempted || completion.WholeFrameAccepted != test.wantWhole ||
				(test.wantErr != nil && !errors.Is(completion.Err, test.wantErr)) ||
				(test.wantErrText != "" && (completion.Err == nil || !strings.Contains(completion.Err.Error(), test.wantErrText))) {
				t.Fatalf("completion=%+v", completion)
			}
		})
	}
}

func TestFrameDispatchAuthorizationSeparatesAdmissionAndWriteLedgerGenerations(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	first := executionDataFrame(t, 0, []byte("first"))
	reservePublishedTestFrame(t, e, first)
	admission, err := e.admitFrameDispatch(first, false)
	if err != nil {
		t.Fatal(err)
	}
	reservePublishedTestFrame(t, e, executionDataFrame(t, 1, []byte("second")))
	authorization, data, retired, err := e.authorizeFrameDispatch(first, admission)
	if err != nil || !data || retired {
		t.Fatalf("authorization data/retired/err=%t/%t/%v", data, retired, err)
	}
	if authorization.AdmissionLedgerGeneration != admission.ledgerGeneration ||
		authorization.LedgerGeneration <= authorization.AdmissionLedgerGeneration {
		t.Fatalf("admission/write generations=%d/%d, want a factual advance",
			authorization.AdmissionLedgerGeneration, authorization.LedgerGeneration)
	}
}

func TestRaceFanoutSharesAdmissionAndUsesUniqueAttempts(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindRace, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{}.Clamp())
	server := New(SideServer, flow, Limits{}.Clamp())
	client.tailReplayInitialDelay = time.Hour
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	configureRecursivePair(t, client, server, manifest)
	paths := make([]*authorizationCaptureDispatchPath, 0, 2)
	for _, name := range []string{"a", "b"} {
		clientPath, serverPath := newMemoryPathPair()
		capture := &authorizationCaptureDispatchPath{
			captureDispatchPath: &captureDispatchPath{PathConn: clientPath},
		}
		paths = append(paths, capture)
		attachRecursivePath(t, client, server, name, capture, serverPath)
	}
	client.pathsMu.RLock()
	var delayed *pathSlot
	for _, slot := range client.paths {
		if slot.localTXTargetID == ids["b"] {
			delayed = slot
			break
		}
	}
	client.pathsMu.RUnlock()
	if delayed == nil {
		t.Fatal("delayed race child is absent")
	}
	if err := delayed.acquireWrite(context.Background()); err != nil {
		t.Fatal(err)
	}
	var releaseDelayed sync.Once
	t.Cleanup(func() { releaseDelayed.Do(delayed.releaseWrite) })
	payload := []byte("one-admission-many-physical-attempts")
	if _, err := client.SendData(payload); err != nil {
		t.Fatal(err)
	}
	client.cancelTailReplay()
	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len(payload))
	if n, err := server.Recv(buffer); err != nil || n != len(payload) || !slices.Equal(buffer[:n], payload) {
		t.Fatalf("Recv=%q/%v, want %q", buffer[:n], err, payload)
	}
	eventuallyEngine(t, time.Second, func() bool { return client.sendAckNext.Load() >= 1 })
	releaseDelayed.Do(delayed.releaseWrite)
	var admissionID uint64
	attempts := make(map[uint64]struct{}, len(paths))
	for index, path := range paths {
		var authorizations []FrameDispatchAuthorization
		var completions []FrameDispatchCompletion
		var frames [][]byte
		var unbound int
		deadline := time.Now().Add(time.Second)
		for {
			authorizations, completions, frames, unbound = path.snapshotAuthorization()
			if len(authorizations) == 1 && len(completions) == 1 && len(frames) == 1 {
				break
			}
			if time.Now().After(deadline) {
				break
			}
			time.Sleep(time.Millisecond)
		}
		if len(authorizations) != 1 || len(completions) != 1 || len(frames) != 1 || unbound != 0 {
			t.Fatalf("path %d authorization/completion/frame/unbound=%d/%d/%d/%d",
				index, len(authorizations), len(completions), len(frames), unbound)
		}
		authorization := authorizations[0]
		if authorization.Kind != FrameDispatchKindInitialCohort {
			t.Fatalf("path %d kind=%v", index, authorization.Kind)
		}
		if admissionID == 0 {
			admissionID = authorization.AdmissionID
		} else if authorization.AdmissionID != admissionID {
			t.Fatalf("path %d admission=%d want shared %d", index, authorization.AdmissionID, admissionID)
		}
		if authorization.AttemptID == 0 {
			t.Fatalf("path %d has zero attempt identity", index)
		}
		if _, duplicate := attempts[authorization.AttemptID]; duplicate {
			t.Fatalf("path %d reused attempt identity %d", index, authorization.AttemptID)
		}
		attempts[authorization.AttemptID] = struct{}{}
	}
}
