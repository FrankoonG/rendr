package engine

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type closeLinearizationPath struct {
	owner *Engine

	mu      sync.Mutex
	headers []proto.Header

	closed   chan struct{}
	closeOne sync.Once
	deathMu  sync.Mutex
	deathFn  func(transport.DeathCause, error)

	byeStarted chan struct{}
	byeOne     sync.Once
	byeGate    <-chan struct{}
	autoAckBye bool

	writeStarted chan struct{}
	writeOne     sync.Once
	writeGate    <-chan struct{}
}

// blockingOptionalClosePath models optional transport hooks that are less
// reliable than the mandatory PathConn.Close contract. Close itself never
// takes writeMu and therefore still promptly releases a conforming blocked
// Write.
type blockingOptionalClosePath struct {
	*closeLinearizationPath

	writeMu         sync.Mutex
	blockWrite      bool
	writeBlocked    chan struct{}
	writeBlockedOne sync.Once

	markStarted chan struct{}
	markOne     sync.Once
	markGate    <-chan struct{}

	closeWriteStarted chan struct{}
	closeWriteOne     sync.Once
	closeWriteGate    <-chan struct{}
}

func newCloseLinearizationPath() *closeLinearizationPath {
	return &closeLinearizationPath{closed: make(chan struct{})}
}

func newBlockingOptionalClosePath() *blockingOptionalClosePath {
	return &blockingOptionalClosePath{
		closeLinearizationPath: newCloseLinearizationPath(),
		writeBlocked:           make(chan struct{}),
		markStarted:            make(chan struct{}),
		closeWriteStarted:      make(chan struct{}),
	}
}

func (p *blockingOptionalClosePath) Write(frame []byte) (int, error) {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if p.blockWrite {
		p.writeBlockedOne.Do(func() { close(p.writeBlocked) })
		<-p.closed
		return 0, net.ErrClosed
	}
	return p.closeLinearizationPath.Write(frame)
}

func (p *blockingOptionalClosePath) MarkQuiesced() {
	p.markOne.Do(func() { close(p.markStarted) })
	if p.markGate != nil {
		<-p.markGate
	}
}

func (p *blockingOptionalClosePath) CloseWrite() error {
	p.closeWriteOne.Do(func() { close(p.closeWriteStarted) })
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if p.closeWriteGate != nil {
		<-p.closeWriteGate
	}
	return nil
}

func (p *closeLinearizationPath) Read([]byte) (int, error) {
	<-p.closed
	return 0, net.ErrClosed
}

func (p *closeLinearizationPath) Write(frame []byte) (int, error) {
	select {
	case <-p.closed:
		return 0, net.ErrClosed
	default:
	}

	if len(frame) < proto.HeaderSize {
		return 0, proto.ErrBadHeader
	}
	hdr, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	if err != nil {
		return 0, err
	}
	p.mu.Lock()
	p.headers = append(p.headers, hdr)
	p.mu.Unlock()

	isBye := hdr.Type == proto.FrameCtrl && proto.CtrlCodeFromFlags(hdr.Flags) == proto.CtrlBye
	if isBye && p.byeStarted != nil {
		p.byeOne.Do(func() { close(p.byeStarted) })
	}
	if p.writeStarted != nil {
		p.writeOne.Do(func() { close(p.writeStarted) })
	}

	// A deliberately hostile PathConn may fail to honor Close while its Write
	// is blocked. Graceful shutdown still needs its own bounded escape path.
	if p.writeGate != nil {
		<-p.writeGate
	}
	if isBye && p.byeGate != nil {
		select {
		case <-p.byeGate:
		case <-p.closed:
			return 0, net.ErrClosed
		}
	}

	select {
	case <-p.closed:
		return 0, net.ErrClosed
	default:
	}
	if isBye && p.autoAckBye && p.owner != nil {
		closeLinearizationAckThrough(p.owner, hdr.Seq+1)
	}
	return len(frame), nil
}

func (p *closeLinearizationPath) Close() error {
	p.closeOne.Do(func() { close(p.closed) })
	return nil
}

func (*closeLinearizationPath) Quality() transport.PathQuality { return transport.PathQuality{} }

func (p *closeLinearizationPath) OnDeath(fn func(transport.DeathCause, error)) {
	p.deathMu.Lock()
	p.deathFn = fn
	p.deathMu.Unlock()
}

func (*closeLinearizationPath) LocalAddr() string  { return "close-linearization-local" }
func (*closeLinearizationPath) RemoteAddr() string { return "close-linearization-remote" }

func (p *closeLinearizationPath) snapshotHeaders() []proto.Header {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]proto.Header(nil), p.headers...)
}

func closeLinearizationAckThrough(e *Engine, nextSeq uint64) bool {
	e.sendHistMu.Lock()
	proof := e.sendAckProof
	for _, entry := range e.sendHist.entries {
		if entry.seq+1 == nextSeq {
			proof = entry.proof
			break
		}
	}
	e.sendHistMu.Unlock()

	binding := e.localGraphBinding()
	return e.notePeerAck(proto.AckPayload{
		SessionEpoch:  proto.SessionEpoch(e.flowID),
		Direction:     senderDirection(e.side),
		GraphRevision: binding.revision,
		GraphDigest:   binding.digest,
		NextSeq:       nextSeq,
		Proof:         proof,
	})
}

func attachCloseLinearizationPath(t *testing.T, e *Engine, path *closeLinearizationPath, targetID proto.TargetID) {
	t.Helper()
	path.owner = e
	attachFixturePath(t, e, path, transport.PathSpec{Transport: "adversarial", Address: "close-linearization"}, targetID)
}

func attachBlockingOptionalClosePath(t *testing.T, e *Engine, path *blockingOptionalClosePath, targetID proto.TargetID) {
	t.Helper()
	path.owner = e
	attachFixturePath(t, e, path, transport.PathSpec{Transport: "adversarial", Address: "blocking-optional-close"}, targetID)
}

func waitCloseLinearizationSignal(t *testing.T, ch <-chan struct{}, timeout time.Duration, label string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for %s", label)
	}
}

func TestCloseWaitsForReservedSequencedPublicationBeforeReplayCleanup(t *testing.T) {
	e := New(SideClient, [16]byte{0xc9}, Limits{MigrationBudget: 250 * time.Millisecond})
	targets := configureLeafSelectorRuntime(t, e, "path")
	path := newCloseLinearizationPath()
	attachCloseLinearizationPath(t, e, path, targets["path"])

	// Hold the ledger lock so the publisher owns sendMu but cannot finish its
	// replay reservation. Close must first publish cancellation, then wait for
	// this sequencer owner before it clears the ledger.
	e.sendHistMu.Lock()
	sendDone := make(chan error, 1)
	go func() {
		_, err := e.sendFrameTracked(proto.FrameCtrl, proto.FlagsForCtrl(proto.CtrlHeartbeat), nil)
		sendDone <- err
	}()
	deadline := time.Now().Add(time.Second)
	for atomic.LoadUint64(&e.sendSeq) == 0 {
		if time.Now().After(deadline) {
			e.sendHistMu.Unlock()
			t.Fatal("publisher did not acquire sequencer")
		}
		time.Sleep(time.Millisecond)
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- e.Close() }()
	select {
	case <-e.closed:
	case <-time.After(time.Second):
		e.sendHistMu.Unlock()
		t.Fatal("Close did not publish cancellation while publisher was reserved")
	}
	e.sendHistMu.Unlock()

	select {
	case err := <-sendDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("reserved publication error=%v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("reserved publication did not leave sequencer after cancellation")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after reserved publication left sequencer")
	}
}

func TestGracefulCloseRejectsDataAfterFinalSequenceLinearizes(t *testing.T) {
	e := New(SideClient, [16]byte{0xc1}, Limits{MigrationBudget: 250 * time.Millisecond})
	t.Cleanup(func() { _ = e.Close() })
	targets := configureLeafSelectorRuntime(t, e, "path")

	byeGate := make(chan struct{})
	var releaseBye sync.Once
	t.Cleanup(func() { releaseBye.Do(func() { close(byeGate) }) })
	path := newCloseLinearizationPath()
	path.byeStarted = make(chan struct{})
	path.byeGate = byeGate
	attachCloseLinearizationPath(t, e, path, targets["path"])

	closeDone := make(chan error, 1)
	go func() { closeDone <- e.GracefulClose(proto.ByeNormal) }()
	waitCloseLinearizationSignal(t, path.byeStarted, time.Second, "final BYE write")

	lateWriteDone := make(chan error, 1)
	go func() {
		_, err := e.SendData([]byte("must-not-follow-bye"))
		lateWriteDone <- err
	}()
	releaseBye.Do(func() { close(byeGate) })

	var lateErr error
	select {
	case lateErr = <-lateWriteDone:
	case <-time.After(300 * time.Millisecond):
		// ACKing the final frontier lets a conforming close finish and forces
		// any admitted writer to resolve rather than hiding behind teardown.
		closeLinearizationAckThrough(e, e.sendPublishedNext.Load())
		select {
		case lateErr = <-lateWriteDone:
		case <-time.After(300 * time.Millisecond):
			t.Fatal("DATA admission remained blocked after graceful-close linearization")
		}
	}
	if lateErr == nil {
		t.Error("DATA submitted after graceful-close linearization was accepted")
	}

	frontier := e.sendPublishedNext.Load()
	if !closeLinearizationAckThrough(e, frontier) && !e.IsClosed() {
		t.Fatalf("could not ACK graceful-close frontier %d", frontier)
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("GracefulClose: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("GracefulClose did not finish after final frontier was ACKed")
	}

	var byeCount int
	var byeSeq uint64
	for _, hdr := range path.snapshotHeaders() {
		if hdr.Type == proto.FrameCtrl && proto.CtrlCodeFromFlags(hdr.Flags) == proto.CtrlBye {
			byeCount++
			byeSeq = hdr.Seq
		}
	}
	if byeCount != 1 {
		t.Fatalf("BYE frame count = %d, want 1", byeCount)
	}
	for _, hdr := range path.snapshotHeaders() {
		if hdr.Type == proto.FrameData && hdr.Seq > byeSeq {
			t.Fatalf("DATA received sequence %d after final BYE sequence %d", hdr.Seq, byeSeq)
		}
	}
}

func TestGracefulCloseLinearizesAfterInFlightApplicationSendData(t *testing.T) {
	e := New(SideClient, [16]byte{0xc8}, Limits{MigrationBudget: 500 * time.Millisecond})
	writeGate := make(chan struct{})
	var releaseWrite sync.Once
	release := func() { releaseWrite.Do(func() { close(writeGate) }) }
	t.Cleanup(func() {
		release()
		_ = e.Close()
	})
	targets := configureLeafSelectorRuntime(t, e, "path")

	path := newCloseLinearizationPath()
	path.writeStarted = make(chan struct{})
	path.writeGate = writeGate
	path.autoAckBye = true
	attachCloseLinearizationPath(t, e, path, targets["path"])

	type writeResult struct {
		n   int
		err error
	}
	payload := []byte("application-write-before-close")
	writeDone := make(chan writeResult, 1)
	go func() {
		n, err := e.SendData(payload)
		writeDone <- writeResult{n: n, err: err}
	}()
	waitCloseLinearizationSignal(t, path.writeStarted, time.Second, "application SendData path write")

	closeDone := make(chan error, 1)
	go func() { closeDone <- e.GracefulClose(proto.ByeNormal) }()
	deadline := time.Now().Add(time.Second)
	for !e.sendClosing.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !e.sendClosing.Load() {
		t.Fatal("graceful close did not publish its no-new-work boundary")
	}
	release()

	select {
	case result := <-writeDone:
		if result.err != nil || result.n != len(payload) {
			t.Fatalf("in-flight SendData=(%d,%v), want (%d,nil)", result.n, result.err, len(payload))
		}
	case <-time.After(time.Second):
		t.Fatal("in-flight application SendData did not resolve")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("GracefulClose after in-flight SendData: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("GracefulClose did not resolve after application SendData")
	}

	var (
		dataSeqs []uint64
		byeSeqs  []uint64
	)
	for _, hdr := range path.snapshotHeaders() {
		switch {
		case hdr.Type == proto.FrameData:
			dataSeqs = append(dataSeqs, hdr.Seq)
		case hdr.Type == proto.FrameCtrl && proto.CtrlCodeFromFlags(hdr.Flags) == proto.CtrlBye:
			byeSeqs = append(byeSeqs, hdr.Seq)
		}
	}
	if len(dataSeqs) == 0 {
		t.Fatal("application SendData never reached the path")
	}
	if len(byeSeqs) != 1 {
		t.Fatalf("BYE sequences=%v, want exactly one", byeSeqs)
	}
	for _, seq := range dataSeqs {
		if seq >= byeSeqs[0] {
			t.Fatalf("application DATA sequence %d did not linearize before BYE %d", seq, byeSeqs[0])
		}
	}
}

func TestConcurrentGracefulCloseSharesFinalFrameAndResult(t *testing.T) {
	e := New(SideClient, [16]byte{0xc2}, Limits{MigrationBudget: 250 * time.Millisecond})
	t.Cleanup(func() { _ = e.Close() })
	targets := configureLeafSelectorRuntime(t, e, "path")

	byeGate := make(chan struct{})
	var releaseBye sync.Once
	t.Cleanup(func() { releaseBye.Do(func() { close(byeGate) }) })
	path := newCloseLinearizationPath()
	path.byeStarted = make(chan struct{})
	path.byeGate = byeGate
	path.autoAckBye = true
	attachCloseLinearizationPath(t, e, path, targets["path"])

	const callers = 16
	start := make(chan struct{})
	ready := make(chan struct{}, callers)
	results := make(chan error, callers)
	for i := 0; i < callers; i++ {
		go func() {
			ready <- struct{}{}
			<-start
			results <- e.GracefulClose(proto.ByeNormal)
		}()
	}
	for i := 0; i < callers; i++ {
		<-ready
	}
	close(start)
	waitCloseLinearizationSignal(t, path.byeStarted, time.Second, "shared final BYE")
	// While the first caller is held inside the transport, every other caller
	// has time to join the same shutdown transaction.
	time.Sleep(25 * time.Millisecond)
	releaseBye.Do(func() { close(byeGate) })

	for i := 0; i < callers; i++ {
		select {
		case err := <-results:
			if err != nil {
				t.Errorf("GracefulClose caller %d result = %v, want shared nil result", i, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("GracefulClose caller %d did not receive the shared result", i)
		}
	}

	byeCount := 0
	for _, hdr := range path.snapshotHeaders() {
		if hdr.Type == proto.FrameCtrl && proto.CtrlCodeFromFlags(hdr.Flags) == proto.CtrlBye {
			byeCount++
		}
	}
	if byeCount != 1 {
		t.Fatalf("concurrent GracefulClose emitted %d BYE frames, want 1", byeCount)
	}
}

func TestGracefulCloseAcceptsConcurrentCleanPeerCompletion(t *testing.T) {
	for attempt := 0; attempt < 100; attempt++ {
		e := New(SideClient, [16]byte{0xc5, byte(attempt)}, Limits{MigrationBudget: 250 * time.Millisecond})
		targets := configureLeafSelectorRuntime(t, e, "path")
		path := newCloseLinearizationPath()
		path.byeStarted = make(chan struct{})
		attachCloseLinearizationPath(t, e, path, targets["path"])

		done := make(chan error, 1)
		go func() { done <- e.GracefulClose(proto.ByeNormal) }()
		waitCloseLinearizationSignal(t, path.byeStarted, time.Second, "concurrent clean BYE")
		if err := e.Close(); err != nil {
			t.Fatalf("attempt %d concurrent clean Close: %v", attempt, err)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("attempt %d GracefulClose=%v, want clean completion", attempt, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("attempt %d GracefulClose did not observe concurrent close", attempt)
		}
	}
}

func TestGracefulClosePreservesConcurrentTerminalReason(t *testing.T) {
	e := New(SideClient, [16]byte{0xc6}, Limits{MigrationBudget: 250 * time.Millisecond})
	targets := configureLeafSelectorRuntime(t, e, "path")
	path := newCloseLinearizationPath()
	path.byeStarted = make(chan struct{})
	attachCloseLinearizationPath(t, e, path, targets["path"])
	done := make(chan error, 1)
	go func() { done <- e.GracefulClose(proto.ByeNormal) }()
	waitCloseLinearizationSignal(t, path.byeStarted, time.Second, "terminal-error BYE")
	e.setCloseErr(ErrZombie)
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrZombie) {
			t.Fatalf("GracefulClose=%v, want ErrZombie", err)
		}
	case <-time.After(time.Second):
		t.Fatal("GracefulClose did not preserve concurrent terminal error")
	}
}

func TestGracefulCloseIsBoundedBehindPermanentlyBlockedWrite(t *testing.T) {
	e := New(SideClient, [16]byte{0xc3}, Limits{MigrationBudget: 50 * time.Millisecond})
	t.Cleanup(func() { _ = e.Close() })
	targets := configureLeafSelectorRuntime(t, e, "path")

	writeGate := make(chan struct{})
	var releaseWrite sync.Once
	t.Cleanup(func() { releaseWrite.Do(func() { close(writeGate) }) })
	path := newCloseLinearizationPath()
	path.writeStarted = make(chan struct{})
	path.writeGate = writeGate
	attachCloseLinearizationPath(t, e, path, targets["path"])

	writeDone := make(chan error, 1)
	go func() {
		_, err := e.SendData([]byte("blocked-forever"))
		writeDone <- err
	}()
	waitCloseLinearizationSignal(t, path.writeStarted, time.Second, "blocked path write")

	closeDone := make(chan error, 1)
	go func() { closeDone <- e.GracefulClose(proto.ByeNormal) }()
	select {
	case err := <-closeDone:
		if err == nil {
			t.Error("GracefulClose reported success without publishing its final frame")
		}
	case <-time.After(500 * time.Millisecond):
		_ = e.Close()
		releaseWrite.Do(func() { close(writeGate) })
		<-writeDone
		t.Fatal("permanently blocked PathConn.Write made GracefulClose hang")
	}

	select {
	case <-e.closed:
	default:
		t.Error("bounded graceful-close failure did not publish the close boundary")
	}
	releaseWrite.Do(func() { close(writeGate) })
	select {
	case err := <-writeDone:
		if err == nil {
			t.Error("blocked DATA write succeeded after the engine closed")
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("blocked DATA writer did not exit after test gate release")
	}
	select {
	case <-e.Closed():
	case <-time.After(time.Second):
		t.Fatal("engine did not fully quiesce after the hostile writer was released")
	}
}

func TestGracefulCloseBoundsBlockingOptionalTransportHooks(t *testing.T) {
	t.Run("MarkQuiesced", func(t *testing.T) {
		e := New(SideClient, [16]byte{0xc7, 1}, Limits{MigrationBudget: 50 * time.Millisecond})
		targets := configureLeafSelectorRuntime(t, e, "path")
		markGate := make(chan struct{})
		var releaseMark sync.Once
		release := func() { releaseMark.Do(func() { close(markGate) }) }
		t.Cleanup(func() {
			release()
			_ = e.Close()
		})

		path := newBlockingOptionalClosePath()
		path.autoAckBye = true
		path.markGate = markGate
		attachBlockingOptionalClosePath(t, e, path, targets["path"])

		done := make(chan error, 1)
		go func() { done <- e.GracefulClose(proto.ByeNormal) }()
		waitCloseLinearizationSignal(t, path.markStarted, time.Second, "blocking MarkQuiesced")
		select {
		case err := <-done:
			var deadlineErr *pathDispatchCallbackDeadlineError
			if !errors.As(err, &deadlineErr) || deadlineErr.operation != "PathConn.MarkQuiesced" {
				t.Fatalf("GracefulClose error=%v want MarkQuiesced deadline", err)
			}
		case <-time.After(time.Second):
			_ = e.Close()
			release()
			<-done
			t.Fatal("blocking MarkQuiesced made GracefulClose unbounded")
		}
		select {
		case <-e.Closed():
		case <-time.After(time.Second):
			t.Fatal("engine ownership did not quiesce after bounded close")
		}

		select {
		case <-e.quiesceDone:
		case <-time.After(time.Second):
			t.Fatal("MarkQuiesced timeout retained its quiesce worker")
		}
		// MarkQuiesced may return late on the terminally closed old adapter, but
		// its revoked worker must not trigger a second optional mutation.
		release()
		select {
		case <-path.closeWriteStarted:
			t.Fatal("late MarkQuiesced completion invoked CloseWrite on a retired path")
		default:
		}
	})

	t.Run("CloseWrite", func(t *testing.T) {
		e := New(SideClient, [16]byte{0xc7, 2}, Limits{MigrationBudget: 50 * time.Millisecond})
		targets := configureLeafSelectorRuntime(t, e, "path")
		closeWriteGate := make(chan struct{})
		var releaseCloseWrite sync.Once
		release := func() { releaseCloseWrite.Do(func() { close(closeWriteGate) }) }
		t.Cleanup(func() {
			release()
			_ = e.Close()
		})

		path := newBlockingOptionalClosePath()
		path.autoAckBye = true
		path.closeWriteGate = closeWriteGate
		attachBlockingOptionalClosePath(t, e, path, targets["path"])

		done := make(chan error, 1)
		go func() { done <- e.GracefulClose(proto.ByeNormal) }()
		waitCloseLinearizationSignal(t, path.closeWriteStarted, time.Second, "blocking CloseWrite")
		select {
		case err := <-done:
			var deadlineErr *pathDispatchCallbackDeadlineError
			if !errors.As(err, &deadlineErr) || deadlineErr.operation != "PathConn.CloseWrite" {
				t.Fatalf("GracefulClose error=%v want CloseWrite deadline", err)
			}
		case <-time.After(time.Second):
			_ = e.Close()
			release()
			<-done
			t.Fatal("blocking CloseWrite made GracefulClose unbounded")
		}
		select {
		case <-e.Closed():
		case <-time.After(time.Second):
			t.Fatal("engine ownership did not quiesce after bounded close")
		}
		select {
		case <-e.quiesceDone:
		case <-time.After(time.Second):
			t.Fatal("CloseWrite timeout retained its quiesce worker")
		}
		release()
	})

	t.Run("CloseWriteContendsWithWrite", func(t *testing.T) {
		e := New(SideClient, [16]byte{0xc7, 3}, Limits{MigrationBudget: 50 * time.Millisecond})
		markGate := make(chan struct{})
		var releaseMark sync.Once
		release := func() { releaseMark.Do(func() { close(markGate) }) }
		t.Cleanup(func() {
			release()
			_ = e.Close()
		})
		targets := configureLeafSelectorRuntime(t, e, "path")
		path := newBlockingOptionalClosePath()
		path.autoAckBye = true
		path.markGate = markGate
		attachBlockingOptionalClosePath(t, e, path, targets["path"])

		done := make(chan error, 1)
		go func() { done <- e.GracefulClose(proto.ByeNormal) }()
		waitCloseLinearizationSignal(t, path.markStarted, time.Second, "pre-contention MarkQuiesced")
		path.writeMu.Lock()
		path.blockWrite = true
		path.writeMu.Unlock()

		e.pathsMu.RLock()
		slot := e.paths[e.activeID]
		e.pathsMu.RUnlock()
		if slot == nil {
			t.Fatal("explicit selector leaf was not attached")
		}
		frame := make([]byte, proto.HeaderSize+1)
		if err := (proto.Header{
			Version: proto.Version, Type: proto.FrameCtrl,
			Flags: proto.FlagsForCtrl(proto.CtrlHeartbeat),
		}).Encode(frame[:proto.HeaderSize]); err != nil {
			t.Fatal(err)
		}
		frame[len(frame)-1] = 0xa5
		writeDone := make(chan pathDispatchResult, 1)
		generation := slot.dispatchNextGen.Add(1)
		if !slot.submitDispatch(pathDispatchJob{frame: frame, result: writeDone, generation: generation}) {
			t.Fatal("could not submit the lock-holding leaf write")
		}
		waitCloseLinearizationSignal(t, path.writeBlocked, time.Second, "transport Write lock holder")

		release()
		waitCloseLinearizationSignal(t, path.closeWriteStarted, time.Second, "contending CloseWrite")
		select {
		case err := <-done:
			var deadlineErr *pathDispatchCallbackDeadlineError
			if !errors.As(err, &deadlineErr) || deadlineErr.operation != "PathConn.CloseWrite" {
				t.Fatalf("GracefulClose error=%v want contended CloseWrite deadline", err)
			}
		case <-time.After(time.Second):
			_ = e.Close()
			<-done
			t.Fatal("CloseWrite contention prevented required PathConn.Close")
		}
		select {
		case result := <-writeDone:
			if result.err == nil {
				t.Fatal("blocked Write succeeded after required Close")
			}
		case <-time.After(time.Second):
			t.Fatal("required Close did not unblock transport Write")
		}
		select {
		case <-e.quiesceDone:
		case <-time.After(time.Second):
			t.Fatal("CloseWrite contender did not drain after required Close")
		}
		select {
		case <-e.Closed():
		case <-time.After(time.Second):
			t.Fatal("engine ownership did not drain after contended close")
		}
	})
}

func TestPathOwnedForQuiesceRequiresCurrentActiveSlot(t *testing.T) {
	e := New(SideClient, [16]byte{0xc7, 4}, Limits{MigrationBudget: 50 * time.Millisecond})
	t.Cleanup(func() { _ = e.Close() })
	targets := configureLeafSelectorRuntime(t, e, "first", "second")
	first := newCloseLinearizationPath()
	second := newCloseLinearizationPath()
	attachCloseLinearizationPath(t, e, first, targets["first"])
	attachCloseLinearizationPath(t, e, second, targets["second"])

	e.pathsMu.RLock()
	firstSlot := e.paths[1]
	secondSlot := e.paths[2]
	e.pathsMu.RUnlock()
	if firstSlot == nil || secondSlot == nil {
		t.Fatalf("attached slots first=%v second=%v", firstSlot, secondSlot)
	}
	e.pathsMu.Lock()
	e.activeID = secondSlot.id
	e.pathsMu.Unlock()
	if e.pathOwnedForQuiesce(firstSlot) {
		t.Fatal("retained but inactive path was eligible for optional quiesce hooks")
	}
	if !e.pathOwnedForQuiesce(secondSlot) {
		t.Fatal("current active path was not eligible for optional quiesce hooks")
	}
}

func TestGracefulCloseHasTerminalCreditBeyondReplayCapacity(t *testing.T) {
	e := New(SideClient, [16]byte{0xc4}, Limits{MigrationBudget: 250 * time.Millisecond})
	t.Cleanup(func() { _ = e.Close() })
	targets := configureLeafSelectorRuntime(t, e, "path")

	path := newCloseLinearizationPath()
	path.byeStarted = make(chan struct{})
	path.autoAckBye = true
	attachCloseLinearizationPath(t, e, path, targets["path"])

	for i := 0; i < sendHistoryWindow; i++ {
		if err := e.SendPacket([]byte{byte(i)}); err != nil {
			t.Fatalf("fill normal replay credit %d: %v", i, err)
		}
	}
	for i := 0; i < sendControlReserve; i++ {
		if err := e.sendFrame(proto.FrameCtrl, proto.FlagsForCtrl(proto.CtrlHeartbeat), nil); err != nil {
			t.Fatalf("fill control replay credit %d: %v", i, err)
		}
	}
	if got := len(e.sendSlots); got != sendHistoryWindow {
		t.Fatalf("normal replay credits in use = %d, want %d", got, sendHistoryWindow)
	}
	if got := len(e.sendControlSlots); got != sendControlReserve {
		t.Fatalf("control replay credits in use = %d, want %d", got, sendControlReserve)
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- e.GracefulClose(proto.ByeNormal) }()
	select {
	case <-path.byeStarted:
	case <-time.After(300 * time.Millisecond):
		_ = e.Close()
		<-closeDone
		t.Fatal("exhausted replay credits prevented the terminal BYE from being published")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("GracefulClose with exhausted replay credits: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("GracefulClose hung after terminal BYE was ACKed")
	}

	var byeHeaders []proto.Header
	for _, hdr := range path.snapshotHeaders() {
		if hdr.Type == proto.FrameCtrl && proto.CtrlCodeFromFlags(hdr.Flags) == proto.CtrlBye {
			byeHeaders = append(byeHeaders, hdr)
		}
	}
	if len(byeHeaders) != 1 {
		t.Fatalf("terminal BYE count = %d, want 1", len(byeHeaders))
	}
	wantSeq := uint64(sendHistoryWindow + sendControlReserve)
	if byeHeaders[0].Seq != wantSeq {
		t.Fatalf("terminal BYE sequence = %d, want %d after exhausted credits", byeHeaders[0].Seq, wantSeq)
	}
	if !e.IsClosed() {
		t.Error("GracefulClose returned without closing the engine")
	}
}
