package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type crossRouteDataPath struct {
	transport.PathConn
	dataWrites atomic.Uint32
}

func (p *crossRouteDataPath) Write(frame []byte) (int, error) {
	n, err := p.PathConn.Write(frame)
	if err == nil && n == len(frame) && len(frame) >= proto.HeaderSize {
		hdr, decodeErr := proto.DecodeHeader(frame[:proto.HeaderSize])
		if decodeErr == nil && hdr.Type == proto.FrameData {
			p.dataWrites.Add(1)
		}
	}
	return n, err
}

type crossRouteAdmissionPath struct {
	transport.PathConn
	dropActivated bool
	dropFinal     bool

	commitWrites   atomic.Uint32
	activatedDrops atomic.Uint32
	finalDrops     atomic.Uint32
	killed         atomic.Bool
	deathFired     atomic.Uint32

	activatedDropped chan struct{}
	activatedRelease chan struct{}
	finalDropped     chan struct{}
	activatedOnce    sync.Once
	finalOnce        sync.Once
	releaseOnce      sync.Once
	killOnce         sync.Once
	deathMu          sync.Mutex
	deathFn          func(transport.DeathCause, error)
}

func newCrossRouteAdmissionPath(inner transport.PathConn, dropActivated bool) *crossRouteAdmissionPath {
	return &crossRouteAdmissionPath{
		PathConn:         inner,
		dropActivated:    dropActivated,
		activatedDropped: make(chan struct{}),
		activatedRelease: make(chan struct{}),
		finalDropped:     make(chan struct{}),
	}
}

func (p *crossRouteAdmissionPath) Write(frame []byte) (int, error) {
	switch admissionFrameKey(frame) {
	case "commit":
		p.commitWrites.Add(1)
	case "final":
		if p.dropFinal && p.finalDrops.CompareAndSwap(0, 1) {
			p.finalOnce.Do(func() { close(p.finalDropped) })
			return len(frame), nil
		}
	case "activated":
		if p.dropActivated {
			p.activatedDrops.Add(1)
			p.activatedOnce.Do(func() { close(p.activatedDropped) })
			<-p.activatedRelease
			return len(frame), nil
		}
	}
	return p.PathConn.Write(frame)
}

func (p *crossRouteAdmissionPath) releaseActivated() {
	p.releaseOnce.Do(func() { close(p.activatedRelease) })
}

func (p *crossRouteAdmissionPath) OnDeath(fn func(transport.DeathCause, error)) {
	p.deathMu.Lock()
	p.deathFn = fn
	p.deathMu.Unlock()
}

func (p *crossRouteAdmissionPath) kill(err error) error {
	var missingCallback bool
	p.killOnce.Do(func() {
		p.killed.Store(true)
		_ = p.PathConn.Close()
		p.deathMu.Lock()
		fn := p.deathFn
		p.deathMu.Unlock()
		if fn == nil {
			missingCallback = true
			return
		}
		p.deathFired.Add(1)
		fn(transport.CauseTransportError, err)
	})
	if missingCallback {
		return errors.New("transport death injected before engine installed OnDeath callback")
	}
	return nil
}

func TestPathAdmissionFinalReceiptOnPredecessorRecordsActualRoute(t *testing.T) {
	clientABase, serverABase := newMemoryPathPair()
	clientA := &crossRouteDataPath{PathConn: clientABase}
	serverA := &crossRouteDataPath{PathConn: serverABase}
	client, server := establishHelloAdmissionPair(t, clientA, serverA)
	waitAdmissionCondition(t, time.Second, "initial path A admission cleanup", func() bool {
		clientState, serverState := snapshotAdmissionSets(client), snapshotAdmissionSets(server)
		return clientState.byPath == 0 && serverState.byPath == 0
	})
	oldClientPath, oldServerPath := client.ActivePath(), server.ActivePath()

	clientBBase, serverBBase := newMemoryPathPair()
	clientB := newCrossRouteAdmissionPath(clientBBase, false)
	clientB.dropFinal = true
	serverB := newCrossRouteAdmissionPath(serverBBase, false)
	serverDone := startServerBridgeAdmission(server, serverB)
	type admissionResult struct {
		admission ClientBridgeAdmission
		err       error
	}
	clientDone := make(chan admissionResult, 1)
	go func() {
		admission, err := PerformClientBridgeAdmissionContext(context.Background(), clientB, client, "a",
			transport.PathSpec{Transport: "memory"})
		clientDone <- admissionResult{admission: admission, err: err}
	}()

	waitAdmissionChannel(t, clientB.finalDropped, "client FINAL receipt drop on successor B")
	if clientB.finalDrops.Load() != 1 || client.ActivePath() == oldClientPath {
		t.Fatalf("client did not activate B before dropping FINAL: drops=%d active=%d old=%d", clientB.finalDrops.Load(), client.ActivePath(), oldClientPath)
	}
	if err := clientB.kill(errors.New("injected client B death before FINAL receipt delivery")); err != nil {
		t.Fatal(err)
	}

	var result admissionResult
	select {
	case result = <-clientDone:
	case <-time.After(2 * time.Second):
		t.Fatal("client admission did not converge through predecessor A")
	}
	if result.err != nil {
		t.Fatalf("client admission: %v", result.err)
	}
	if result.admission.PathID != oldClientPath {
		t.Fatalf("client admitted route=%d, want predecessor A=%d", result.admission.PathID, oldClientPath)
	}
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server admission: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server admission did not converge through predecessor A")
	}
	if !waitCrossRouteCondition(time.Second, func() bool {
		return crossRouteOnlyPath(client, oldClientPath) && crossRouteOnlyPath(server, oldServerPath)
	}) {
		t.Fatalf("peers did not converge on A: client=%v server=%v", client.Paths(), server.Paths())
	}

	server.pathsMu.RLock()
	completedCount := len(server.completedPathAdmissions)
	if completedCount != 1 {
		server.pathsMu.RUnlock()
		t.Fatalf("server completed admissions=%d, want 1", completedCount)
	}
	var completedRoute PathRef
	for _, completed := range server.completedPathAdmissions {
		completedRoute = completed.successor
	}
	oldServerSlot := server.paths[oldServerPath]
	wantRoute := PathRef{}
	if oldServerSlot != nil {
		wantRoute = PathRef{ID: oldServerSlot.id, Owner: oldServerSlot.owner}
	}
	server.pathsMu.RUnlock()
	if oldServerSlot == nil || completedRoute != wantRoute {
		t.Fatalf("server tombstone route=%+v, want predecessor A=%+v", completedRoute, wantRoute)
	}
	if err := crossRouteBidirectionalPayload(&Conn{E: client}, &Conn{E: server}, time.Second, "final-on-a"); err != nil {
		t.Fatal(err)
	}
	if client.CloseErr() != nil || server.CloseErr() != nil {
		t.Fatalf("application session closed: client=%v server=%v", client.CloseErr(), server.CloseErr())
	}
}

func TestPathAdmissionInitiatorStagedDeathConvergesThroughPredecessor(t *testing.T) {
	testPathAdmissionStagedDeathConverges(t, true)
}

func TestPathAdmissionResponderStagedDeathConvergesThroughPredecessor(t *testing.T) {
	testPathAdmissionStagedDeathConverges(t, false)
}

func testPathAdmissionStagedDeathConverges(t *testing.T, killInitiator bool) {
	clientABase, serverABase := newMemoryPathPair()
	client, server := establishHelloAdmissionPair(t, clientABase, serverABase)
	waitAdmissionCondition(t, time.Second, "initial path A admission cleanup", func() bool {
		return snapshotAdmissionSets(client).byPath == 0 && snapshotAdmissionSets(server).byPath == 0
	})
	oldClientPath, oldServerPath := client.ActivePath(), server.ActivePath()
	clientBBase, serverBBase := newMemoryPathPair()
	clientB := newCrossRouteAdmissionPath(clientBBase, false)
	serverB := newCrossRouteAdmissionPath(serverBBase, false)

	var gate *blockingAdmissionPath
	if killInitiator {
		gate = newBlockingAdmissionPath(serverB, "final")
	} else {
		gate = newBlockingAdmissionPath(clientB, "confirm")
	}
	t.Cleanup(gate.unblock)
	serverPath := transport.PathConn(serverB)
	clientPath := transport.PathConn(clientB)
	if killInitiator {
		serverPath = gate
	} else {
		clientPath = gate
	}
	serverDone := startServerBridgeAdmission(server, serverPath)
	type admissionResult struct {
		admission ClientBridgeAdmission
		err       error
	}
	clientDone := make(chan admissionResult, 1)
	go func() {
		admission, err := PerformClientBridgeAdmissionContext(context.Background(), clientPath, client, "a",
			transport.PathSpec{Transport: "memory"})
		clientDone <- admissionResult{admission: admission, err: err}
	}()
	waitAdmissionChannel(t, gate.entered, "staged-death phase gate")
	if client.ActivePath() != oldClientPath || server.ActivePath() != oldServerPath {
		t.Fatalf("B activated before staged death: client=%d/%d server=%d/%d", oldClientPath, client.ActivePath(), oldServerPath, server.ActivePath())
	}
	if killInitiator {
		if err := clientB.kill(errors.New("injected initiator staged B death")); err != nil {
			t.Fatal(err)
		}
	} else if err := serverB.kill(errors.New("injected responder staged B death")); err != nil {
		t.Fatal(err)
	}
	gate.unblock()

	var result admissionResult
	select {
	case result = <-clientDone:
	case <-time.After(2 * time.Second):
		t.Fatal("client admission did not finish after staged death")
	}
	if result.err != nil || result.admission.PathID != oldClientPath {
		t.Fatalf("client admission=%+v err=%v, want predecessor A=%d", result.admission, result.err, oldClientPath)
	}
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server admission: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server admission did not finish after staged death")
	}
	if !waitCrossRouteCondition(time.Second, func() bool {
		return crossRouteOnlyPath(client, oldClientPath) && crossRouteOnlyPath(server, oldServerPath)
	}) {
		t.Fatalf("peers did not remain on A: client=%v server=%v", client.Paths(), server.Paths())
	}
	server.pathsMu.RLock()
	completedCount := len(server.completedPathAdmissions)
	var completedRoute PathRef
	for _, completed := range server.completedPathAdmissions {
		completedRoute = completed.successor
	}
	wantServerSlot := server.paths[oldServerPath]
	wantRoute := PathRef{}
	if wantServerSlot != nil {
		wantRoute = PathRef{ID: wantServerSlot.id, Owner: wantServerSlot.owner}
	}
	server.pathsMu.RUnlock()
	if completedCount != 1 || wantServerSlot == nil || completedRoute != wantRoute {
		t.Fatalf("server completed route count=%d route=%+v want=%+v", completedCount, completedRoute, wantRoute)
	}
	if err := crossRouteBidirectionalPayload(&Conn{E: client}, &Conn{E: server}, time.Second, "staged-death-on-a"); err != nil {
		t.Fatal(err)
	}
	if client.CloseErr() != nil || server.CloseErr() != nil {
		t.Fatalf("application session closed: client=%v server=%v", client.CloseErr(), server.CloseErr())
	}
}

func TestPathAdmissionDroppedActivatedSuccessorDeathConvergesThroughPredecessor(t *testing.T) {
	for _, test := range []struct {
		name       string
		killServer bool
	}{
		{name: "both peers observe successor death", killServer: true},
		{name: "only initiator observes successor death", killServer: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			testPathAdmissionDroppedActivatedSuccessorDeath(t, test.killServer)
		})
	}
}

func testPathAdmissionDroppedActivatedSuccessorDeath(t *testing.T, killServer bool) {
	clientABase, serverABase := newMemoryPathPair()
	clientA := &crossRouteDataPath{PathConn: clientABase}
	serverA := &crossRouteDataPath{PathConn: serverABase}
	client, server := establishHelloAdmissionPair(t, clientA, serverA)
	waitAdmissionCondition(t, time.Second, "initial path A admission cleanup", func() bool {
		clientState, serverState := snapshotAdmissionSets(client), snapshotAdmissionSets(server)
		return clientState.byPath == 0 && clientState.retained == 0 && clientState.predecessors == 0 &&
			serverState.byPath == 0 && serverState.retained == 0 && serverState.predecessors == 0
	})

	clientConn, serverConn := &Conn{E: client}, &Conn{E: server}
	if err := crossRouteBidirectionalPayload(clientConn, serverConn, time.Second, "path-a-baseline"); err != nil {
		t.Fatalf("predecessor path A was not healthy before admission: %v", err)
	}
	oldClientPath, oldServerPath := client.ActivePath(), server.ActivePath()
	if oldClientPath == 0 || oldServerPath == 0 {
		t.Fatalf("path A was not active on both peers: client=%d server=%d", oldClientPath, oldServerPath)
	}

	clientBBase, serverBBase := newMemoryPathPair()
	clientB := newCrossRouteAdmissionPath(clientBBase, false)
	serverB := newCrossRouteAdmissionPath(serverBBase, true)
	t.Cleanup(serverB.releaseActivated)
	serverDone := startServerBridgeAdmission(server, serverB)
	type clientAdmissionResult struct {
		admission ClientBridgeAdmission
		err       error
	}
	clientDone := make(chan clientAdmissionResult, 1)
	admissionCtx, cancelAdmission := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancelAdmission()
	go func() {
		admission, err := PerformClientBridgeAdmissionContext(admissionCtx, clientB, client, "a",
			transport.PathSpec{Transport: "memory"})
		clientDone <- clientAdmissionResult{admission: admission, err: err}
	}()

	select {
	case <-serverB.activatedDropped:
	case <-time.After(time.Second):
		t.Fatal("responder did not emit the terminal ACTIVATED on successor B")
	}
	if clientB.commitWrites.Load() == 0 {
		t.Fatal("successor B never reached COMMIT")
	}
	if serverB.activatedDrops.Load() == 0 {
		t.Fatal("terminal ACTIVATED drop stimulus did not occur")
	}
	if client.ActivePath() == oldClientPath || server.ActivePath() == oldServerPath {
		t.Fatalf("successor B was not activated before death: client=%d/%d server=%d/%d",
			oldClientPath, client.ActivePath(), oldServerPath, server.ActivePath())
	}
	assertAdmissionOverlap(t, client, client.ActivePath(), oldClientPath)
	assertAdmissionOverlap(t, server, server.ActivePath(), oldServerPath)
	for side, path := range map[string]*memoryPathConn{"client": clientABase, "server": serverABase} {
		select {
		case <-path.closed:
			t.Fatalf("healthy predecessor A was closed on %s before successor B died", side)
		default:
		}
	}

	deathErr := errors.New("injected successor B transport death after dropped ACTIVATED")
	if err := clientB.kill(deathErr); err != nil {
		t.Fatal(err)
	}
	if killServer {
		if err := serverB.kill(deathErr); err != nil {
			t.Fatal(err)
		}
	}
	wantServerDeaths := uint32(0)
	if killServer {
		wantServerDeaths = 1
	}
	if !clientB.killed.Load() || serverB.killed.Load() != killServer ||
		clientB.deathFired.Load() != 1 || serverB.deathFired.Load() != wantServerDeaths {
		t.Fatalf("successor B death stimulus incomplete: client(killed=%t callbacks=%d) server(killed=%t callbacks=%d)",
			clientB.killed.Load(), clientB.deathFired.Load(), serverB.killed.Load(), serverB.deathFired.Load())
	}
	serverB.releaseActivated()

	var admissionResult clientAdmissionResult
	admissionFinished := false
	select {
	case admissionResult = <-clientDone:
		admissionFinished = true
	case <-time.After(2 * time.Second):
	}
	var serverAdmissionErr error
	serverAdmissionFinished := false
	select {
	case serverAdmissionErr = <-serverDone:
		serverAdmissionFinished = true
	case <-time.After(2 * time.Second):
	}

	converged := waitCrossRouteCondition(time.Second, func() bool {
		return crossRouteOnlyPath(client, oldClientPath) && crossRouteOnlyPath(server, oldServerPath)
	})
	clientAWrites, serverAWrites := clientA.dataWrites.Load(), serverA.dataWrites.Load()
	payloadErr := crossRouteBidirectionalPayload(clientConn, serverConn, time.Second, "path-a-after-b-death")

	var failures []string
	if !admissionFinished {
		failures = append(failures, "admission transaction did not terminate")
	}
	if !serverAdmissionFinished {
		failures = append(failures, "responder admission transaction did not terminate")
	}
	if admissionResult.err != nil {
		failures = append(failures, fmt.Sprintf("initiator admission returned error: %v", admissionResult.err))
	} else if admissionResult.admission.PathID != oldClientPath {
		failures = append(failures, fmt.Sprintf("initiator admission returned stale route %d, want converged path A %d", admissionResult.admission.PathID, oldClientPath))
	}
	if serverAdmissionErr != nil {
		failures = append(failures, fmt.Sprintf("responder admission returned error: %v", serverAdmissionErr))
	}
	if !converged {
		failures = append(failures, fmt.Sprintf("peers did not converge on predecessor A (client active=%d paths=%v; server active=%d paths=%v)",
			client.ActivePath(), client.Paths(), server.ActivePath(), server.Paths()))
	}
	if err := client.CloseErr(); err != nil {
		failures = append(failures, fmt.Sprintf("client application connection closed: %v", err))
	}
	if err := server.CloseErr(); err != nil {
		failures = append(failures, fmt.Sprintf("server application connection closed: %v", err))
	}
	if payloadErr != nil {
		failures = append(failures, fmt.Sprintf("bidirectional application payload did not continue: %v", payloadErr))
	}
	if clientA.dataWrites.Load() <= clientAWrites || serverA.dataWrites.Load() <= serverAWrites {
		failures = append(failures, fmt.Sprintf("post-death payload did not traverse A in both directions (client DATA %d->%d; server DATA %d->%d)",
			clientAWrites, clientA.dataWrites.Load(), serverAWrites, serverA.dataWrites.Load()))
	}
	if len(failures) != 0 {
		t.Fatalf("cross-route admission recovery failed (client admission err=%v; server admission err=%v): %s",
			admissionResult.err, serverAdmissionErr, strings.Join(failures, "; "))
	}
}

func crossRouteOnlyPath(e *Engine, want uint32) bool {
	paths := e.Paths()
	return e.ActivePath() == want && len(paths) == 1 && paths[0].ID == want
}

func waitCrossRouteCondition(timeout time.Duration, condition func() bool) bool {
	deadline := time.Now().Add(timeout)
	for !condition() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(time.Millisecond)
	}
	return true
}

type crossRouteIOResult struct {
	operation string
	want      []byte
	got       []byte
	n         int
	err       error
}

func crossRouteBidirectionalPayload(client, server *Conn, timeout time.Duration, label string) error {
	deadline := time.Now().Add(timeout)
	if err := client.SetReadDeadline(deadline); err != nil {
		return err
	}
	defer func() { _ = client.SetReadDeadline(time.Time{}) }()
	if err := server.SetReadDeadline(deadline); err != nil {
		return err
	}
	defer func() { _ = server.SetReadDeadline(time.Time{}) }()

	up := []byte(label + "-up")
	down := []byte(label + "-down")
	results := make(chan crossRouteIOResult, 4)
	write := func(operation string, conn *Conn, payload []byte) {
		n, err := conn.Write(payload)
		results <- crossRouteIOResult{operation: operation, want: payload, n: n, err: err}
	}
	read := func(operation string, conn *Conn, payload []byte) {
		got := make([]byte, len(payload))
		n, err := io.ReadFull(conn, got)
		results <- crossRouteIOResult{operation: operation, want: payload, got: got, n: n, err: err}
	}
	go read("server read", server, up)
	go read("client read", client, down)
	go write("client write", client, up)
	go write("server write", server, down)

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	completed := make([]crossRouteIOResult, 0, 4)
	for len(completed) < 4 {
		select {
		case result := <-results:
			completed = append(completed, result)
			if result.err != nil {
				return fmt.Errorf("%s returned application-visible error after %d bytes: %w", result.operation, result.n, result.err)
			}
			if result.n != len(result.want) {
				return fmt.Errorf("%s transferred %d bytes, want %d", result.operation, result.n, len(result.want))
			}
			if result.got != nil && !bytes.Equal(result.got, result.want) {
				return fmt.Errorf("%s payload=%q want=%q", result.operation, result.got, result.want)
			}
		case <-timer.C:
			return fmt.Errorf("timed out with %d/4 application operations complete", len(completed))
		}
	}
	return nil
}
