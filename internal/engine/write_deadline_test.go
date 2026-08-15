package engine

import (
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

func TestWriteDeadlinePastRejectsBeforePublicationAndCanBeCleared(t *testing.T) {
	e := New(SideClient, [16]byte{0xe1}, Limits{})
	t.Cleanup(func() { _ = e.Close() })
	targets := configureLeafSelectorRuntime(t, e, "past")
	attachFixturePath(t, e, newReplayBudgetPath(), transport.PathSpec{Transport: "deadline", Address: "past"}, targets["past"])
	conn := &Conn{E: e}
	if err := conn.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Write([]byte("must-not-publish")); n != 0 || !isWriteTimeout(err) {
		t.Fatalf("past-deadline Write=(%d,%v), want (0, timeout)", n, err)
	}
	waitWriteDeadlineCondition(t, time.Second, func() bool { return len(e.appWritePermit) == 1 }, "past-deadline cleanup")
	if next := atomic.LoadUint64(&e.sendSeq); next != 0 {
		t.Fatalf("past-deadline Write allocated sequence %d", next)
	}
	if stats := e.ReplayStats(); stats.PublishedNext != 0 || stats.FramesInUse != 0 || stats.BytesInUse != 0 {
		t.Fatalf("past-deadline Write changed replay state: %+v", stats)
	}
	if err := conn.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Write([]byte("alive")); n != len("alive") || err != nil {
		t.Fatalf("Write after deadline clear=(%d,%v)", n, err)
	}
}

func TestWriteDeadlineWakesReplayFrameCreditWait(t *testing.T) {
	e := New(SideClient, [16]byte{0xe2}, Limits{})
	t.Cleanup(func() { _ = e.Close() })
	configureLeafSelectorRuntime(t, e, "unavailable")
	for index := 0; index < sendHistoryWindow; index++ {
		if err := e.acquireSendSlot(false, 1); err != nil {
			t.Fatalf("reserve frame %d: %v", index, err)
		}
	}
	if err := e.SetWriteDeadline(time.Now().Add(40 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	n, err := (&Conn{E: e}).Write([]byte("blocked-on-frame-credit"))
	if n != 0 || !isWriteTimeout(err) {
		t.Fatalf("frame-credit Write=(%d,%v), want (0, timeout)", n, err)
	}
	waitWriteDeadlineCondition(t, time.Second, func() bool {
		return e.ReplayStats().CreditWaiters == 0 && len(e.appWritePermit) == 1
	}, "frame-credit waiter cleanup")
	if next := atomic.LoadUint64(&e.sendSeq); next != 0 {
		t.Fatalf("frame-credit timeout allocated sequence %d", next)
	}
	for index := 0; index < sendHistoryWindow; index++ {
		e.releaseSendSlot(false, 1)
	}
}

func TestWriteDeadlineWakesReplayByteCreditWait(t *testing.T) {
	e := New(SideClient, [16]byte{0xe3}, Limits{})
	t.Cleanup(func() { _ = e.Close() })
	configureLeafSelectorRuntime(t, e, "unavailable")
	if err := e.acquireSendSlot(false, sendHistoryByteLimit); err != nil {
		t.Fatal(err)
	}
	if err := e.SetWriteDeadline(time.Now().Add(40 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	n, err := (&Conn{E: e}).Write([]byte("blocked-on-byte-credit"))
	if n != 0 || !isWriteTimeout(err) {
		t.Fatalf("byte-credit Write=(%d,%v), want (0, timeout)", n, err)
	}
	waitWriteDeadlineCondition(t, time.Second, func() bool {
		stats := e.ReplayStats()
		return stats.CreditWaiters == 0 && stats.FramesInUse == 1 &&
			stats.BytesInUse == sendHistoryByteLimit && len(e.appWritePermit) == 1
	}, "byte-credit waiter cleanup")
	if next := atomic.LoadUint64(&e.sendSeq); next != 0 {
		t.Fatalf("byte-credit timeout allocated sequence %d", next)
	}
	e.releaseSendSlot(false, sendHistoryByteLimit)
}

func TestWriteDeadlineCannotPublishLaterWhileWaitingForSequencer(t *testing.T) {
	e := New(SideClient, [16]byte{0xe4}, Limits{})
	t.Cleanup(func() { _ = e.Close() })
	ids := configureWriteDeadlineGraph(t, e, "sequencer")
	if _, err := e.AttachPathBound(newReplayBudgetPath(), transport.PathSpec{Transport: "deadline", Address: "sequencer"}, PathBinding{
		LocalTXTargetID: ids["sequencer"], PeerTXTargetID: ids["sequencer"],
	}); err != nil {
		t.Fatal(err)
	}
	e.sendMu.Lock()
	locked := true
	defer func() {
		if locked {
			e.sendMu.Unlock()
		}
	}()
	if err := e.SetWriteDeadline(time.Now().Add(40 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	n, err := (&Conn{E: e}).Write([]byte("sequencer-wait"))
	if n != 0 || !isWriteTimeout(err) {
		t.Fatalf("sequencer Write=(%d,%v), want (0, timeout)", n, err)
	}
	if next := atomic.LoadUint64(&e.sendSeq); next != 0 {
		t.Fatalf("timed-out sequencer waiter published sequence %d", next)
	}
	e.sendMu.Unlock()
	locked = false
	waitWriteDeadlineCondition(t, time.Second, func() bool {
		stats := e.ReplayStats()
		return stats.FramesInUse == 0 && stats.BytesInUse == 0 && len(e.appWritePermit) == 1
	}, "sequencer waiter cleanup")
	if next := atomic.LoadUint64(&e.sendSeq); next != 0 {
		t.Fatalf("canceled sequencer waiter published late sequence %d", next)
	}
	if err := e.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if n, err := (&Conn{E: e}).Write([]byte("after-sequencer")); n != len("after-sequencer") || err != nil {
		t.Fatalf("Write after sequencer release=(%d,%v)", n, err)
	}
}

func TestWriteDeadlineAfterPublicationReturnsAcceptedBytesWithoutClosing(t *testing.T) {
	e := New(SideClient, [16]byte{0xe5}, Limits{})
	writeGate := make(chan struct{})
	released := false
	t.Cleanup(func() {
		if !released {
			close(writeGate)
		}
		_ = e.Close()
	})
	ids := configureWriteDeadlineGraph(t, e, "physical-write")
	clientPath, _ := newSequencerTestPathPair()
	clientPath.writeStarted = make(chan struct{})
	clientPath.writeGate = writeGate
	if _, err := e.AttachPathBound(clientPath, transport.PathSpec{Transport: "deadline", Address: "physical-write"}, PathBinding{
		LocalTXTargetID: ids["physical-write"], PeerTXTargetID: ids["physical-write"],
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.SetWriteDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("accepted-before-physical-write-completes")
	n, err := (&Conn{E: e}).Write(payload)
	if n != len(payload) || !isWriteTimeout(err) {
		t.Fatalf("post-publication Write=(%d,%v), want (%d, timeout)", n, err, len(payload))
	}
	select {
	case <-clientPath.writeStarted:
	default:
		t.Fatal("test did not reach the physical path Write")
	}
	if e.isClosed() || e.CloseErr() != nil {
		t.Fatalf("application timeout closed session: closed=%t err=%v", e.isClosed(), e.CloseErr())
	}
	if next := atomic.LoadUint64(&e.sendSeq); next != 1 {
		t.Fatalf("published sequence frontier=%d, want 1", next)
	}
	if err := e.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	close(writeGate)
	released = true
	waitWriteDeadlineCondition(t, time.Second, func() bool { return len(e.appWritePermit) == 1 }, "physical writer completion")
	if n, err := (&Conn{E: e}).Write([]byte("still-alive")); n != len("still-alive") || err != nil {
		t.Fatalf("Write after timeout recovery=(%d,%v)", n, err)
	}
}

func TestWriteDeadlineReturnsOnlyFullyPublishedStreamChunks(t *testing.T) {
	e := New(SideClient, [16]byte{0xe6}, Limits{})
	writeGate := make(chan struct{})
	released := false
	t.Cleanup(func() {
		if !released {
			close(writeGate)
		}
		_ = e.Close()
	})
	ids := configureWriteDeadlineGraph(t, e, "partial-stream")
	clientPath, _ := newSequencerTestPathPair()
	clientPath.writeStarted = make(chan struct{})
	clientPath.writeGate = writeGate
	if _, err := e.AttachPathBound(clientPath, transport.PathSpec{Transport: "deadline", Address: "partial-stream"}, PathBinding{
		LocalTXTargetID: ids["partial-stream"], PeerTXTargetID: ids["partial-stream"],
	}); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, MaxPayload+17)
	done := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		n, err := (&Conn{E: e}).Write(payload)
		done <- struct {
			n   int
			err error
		}{n: n, err: err}
	}()
	select {
	case <-clientPath.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("first stream frame did not enter physical Write")
	}
	if err := e.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		if result.n != MaxPayload || !isWriteTimeout(result.err) {
			t.Fatalf("partial stream Write=(%d,%v), want (%d, timeout)", result.n, result.err, MaxPayload)
		}
	case <-time.After(time.Second):
		t.Fatal("stream Write did not wake at deadline")
	}
	if next := atomic.LoadUint64(&e.sendSeq); next != 1 {
		t.Fatalf("partial stream allocated %d sequences, want 1", next)
	}
	if err := e.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	close(writeGate)
	released = true
	waitWriteDeadlineCondition(t, time.Second, func() bool { return len(e.appWritePermit) == 1 }, "partial stream writer cleanup")
}

func TestWriteDeadlineExtensionAndClearWakePendingPermitWait(t *testing.T) {
	e := New(SideClient, [16]byte{0xe7}, Limits{})
	t.Cleanup(func() { _ = e.Close() })
	targets := configureLeafSelectorRuntime(t, e, "extend")
	attachFixturePath(t, e, newReplayBudgetPath(), transport.PathSpec{Transport: "deadline", Address: "extend"}, targets["extend"])
	<-e.appWritePermit
	permitHeld := true
	defer func() {
		if permitHeld {
			e.releaseApplicationWritePermit()
		}
	}()
	if err := e.SetWriteDeadline(time.Now().Add(40 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := (&Conn{E: e}).Write([]byte("deadline-extension"))
		done <- err
	}()
	time.Sleep(15 * time.Millisecond)
	if err := e.SetWriteDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("extended deadline used stale timer: %v", err)
	default:
	}
	if err := e.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(120 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("cleared deadline did not preserve pending Write: %v", err)
	default:
	}
	e.releaseApplicationWritePermit()
	permitHeld = false
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Write after permit release: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Write did not complete after deadline clear and permit release")
	}
}

func TestWriteDeadlineDoesNotApplyToControlOrReplay(t *testing.T) {
	e := New(SideClient, [16]byte{0xe8}, Limits{})
	t.Cleanup(func() { _ = e.Close() })
	targets := configureLeafSelectorRuntime(t, e, "control")
	attachFixturePath(t, e, newReplayBudgetPath(), transport.PathSpec{Transport: "deadline", Address: "control"}, targets["control"])
	if err := e.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := e.sendFrame(proto.FrameCtrl, proto.FlagsForCtrl(proto.CtrlPathProbe), nil); err != nil {
		t.Fatalf("control inherited application deadline: %v", err)
	}
	frame := make([]byte, proto.HeaderSize+1)
	if err := (proto.Header{Version: proto.Version, Type: proto.FrameData, Seq: 0}).Encode(frame[:proto.HeaderSize]); err != nil {
		t.Fatal(err)
	}
	frame[proto.HeaderSize] = 1
	if err := e.replaySequencedFrame(frame); err != nil {
		t.Fatalf("replay inherited application deadline: %v", err)
	}
}

func TestRecursiveWriteDeadlineAddedWhilePhysicalWriteIsBlocked(t *testing.T) {
	e := New(SideClient, [16]byte{0xec}, Limits{})
	writeGate := make(chan struct{})
	released := false
	t.Cleanup(func() {
		if !released {
			close(writeGate)
		}
		_ = e.Close()
	})
	ids := configureWriteDeadlineGraph(t, e, "blocked")
	path, peer := newSequencerTestPathPair()
	t.Cleanup(func() { _ = peer.Close() })
	path.writeStarted = make(chan struct{})
	path.writeGate = writeGate
	pathID, err := e.AttachPathBound(path, transport.PathSpec{Transport: "deadline", Address: "recursive-blocked"}, PathBinding{
		LocalTXTargetID: ids["blocked"], PeerTXTargetID: ids["blocked"],
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("recursive-deadline-added-after-write-start")
	done := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		n, writeErr := (&Conn{E: e}).Write(payload)
		done <- struct {
			n   int
			err error
		}{n: n, err: writeErr}
	}()
	select {
	case <-path.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("recursive physical Write did not start")
	}
	if err := e.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		if result.n != len(payload) || !isWriteTimeout(result.err) {
			t.Fatalf("recursive Write=(%d,%v), want (%d, timeout)", result.n, result.err, len(payload))
		}
	case <-time.After(time.Second):
		t.Fatal("recursive Write did not observe newly-installed deadline")
	}
	ref, ok := e.PathRef(pathID)
	if !ok {
		t.Fatal("recursive deadline path detached")
	}
	e.pathsMu.RLock()
	slot := e.paths[ref.ID]
	e.pathsMu.RUnlock()
	if slot == nil || !slot.dispatchStalled.Load() {
		t.Fatal("blocked recursive path was not temporarily excluded")
	}
	if err := e.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	close(writeGate)
	released = true
	waitWriteDeadlineCondition(t, time.Second, func() bool { return !slot.dispatchStalled.Load() }, "recursive path re-admission")
	select {
	case frame := <-peer.in:
		header, decodeErr := proto.DecodeHeader(frame[:proto.HeaderSize])
		if decodeErr != nil || header.Type != proto.FrameData || string(frame[proto.HeaderSize:]) != string(payload) {
			t.Fatalf("recursive delayed frame=%x header=%+v err=%v", frame, header, decodeErr)
		}
	case <-time.After(time.Second):
		t.Fatal("published recursive frame did not finish after path release")
	}
}

func TestRecursiveWriteDeadlineExtensionAndClearReplacePendingTimer(t *testing.T) {
	e := New(SideClient, [16]byte{0xed}, Limits{})
	writeGate := make(chan struct{})
	released := false
	t.Cleanup(func() {
		if !released {
			close(writeGate)
		}
		_ = e.Close()
	})
	ids := configureWriteDeadlineGraph(t, e, "extend")
	path, peer := newSequencerTestPathPair()
	t.Cleanup(func() { _ = peer.Close() })
	path.writeStarted = make(chan struct{})
	path.writeGate = writeGate
	if _, err := e.AttachPathBound(path, transport.PathSpec{Transport: "deadline", Address: "recursive-extend"}, PathBinding{
		LocalTXTargetID: ids["extend"], PeerTXTargetID: ids["extend"],
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.SetWriteDeadline(time.Now().Add(80 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, writeErr := (&Conn{E: e}).Write([]byte("recursive-extension"))
		done <- writeErr
	}()
	select {
	case <-path.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("recursive extension Write did not start")
	}
	if err := e.SetWriteDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("recursive Write used stale original deadline: %v", err)
	default:
	}
	if err := e.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(220 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("recursive Write timed out after deadline clear: %v", err)
	default:
	}
	close(writeGate)
	released = true
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("recursive Write after release: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("recursive Write did not finish after release")
	}
}

func TestRecursiveWriteDeadlineLeavesHealthySiblingForControl(t *testing.T) {
	e := New(SideClient, [16]byte{0xee}, Limits{})
	writeGate := make(chan struct{})
	released := false
	t.Cleanup(func() {
		if !released {
			close(writeGate)
		}
		_ = e.Close()
	})
	ids := configureWriteDeadlineGraph(t, e, "blocked", "healthy")
	blocked, blockedPeer := newSequencerTestPathPair()
	healthy, healthyPeer := newSequencerTestPathPair()
	t.Cleanup(func() {
		_ = blockedPeer.Close()
		_ = healthyPeer.Close()
	})
	blocked.writeStarted = make(chan struct{})
	blocked.writeGate = writeGate
	paths := map[string]*sequencerTestPath{"blocked": blocked, "healthy": healthy}
	for _, name := range []string{"blocked", "healthy"} {
		path := paths[name]
		if _, err := e.AttachPathBound(path, transport.PathSpec{Transport: "deadline", Address: name}, PathBinding{
			LocalTXTargetID: ids[name], PeerTXTargetID: ids[name],
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.SetWriteDeadline(time.Now().Add(40 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("data-on-blocked-selector-child")
	if n, err := (&Conn{E: e}).Write(payload); n != len(payload) || !isWriteTimeout(err) {
		t.Fatalf("blocked selector Write=(%d,%v)", n, err)
	}
	if err := e.sendFrame(proto.FrameCtrl, proto.FlagsForCtrl(proto.CtrlPathProbe), nil); err != nil {
		t.Fatalf("control could not use healthy sibling: %v", err)
	}
	select {
	case frame := <-healthyPeer.in:
		header, decodeErr := proto.DecodeHeader(frame[:proto.HeaderSize])
		if decodeErr != nil || header.Type != proto.FrameCtrl {
			t.Fatalf("healthy sibling frame=%x header=%+v err=%v", frame, header, decodeErr)
		}
	case <-time.After(time.Second):
		t.Fatal("control frame did not reach healthy sibling")
	}
	close(writeGate)
	released = true
}

func TestMigrationBudgetBeatsLaterWriteDeadlineWithoutWorkerSelfWait(t *testing.T) {
	e := New(SideClient, [16]byte{0xe9}, Limits{MigrationBudget: 30 * time.Millisecond})
	targets := configureLeafSelectorRuntime(t, e, "unavailable")
	path, peer := newSequencerTestPathPair()
	t.Cleanup(func() { _ = peer.Close() })
	attachFixturePath(t, e, path,
		transport.PathSpec{Transport: "deadline", Address: "unavailable"},
		targets["unavailable"],
	)
	pathDeath := errors.New("injected last-path death before Write")
	path.Fail(pathDeath)
	path.notifyFailure(pathDeath)
	waitWriteDeadlineCondition(t, time.Second, func() bool {
		return e.ActivePath() == 0 && e.State() == BridgeMigrating
	}, "last-path death")
	if err := e.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("published-before-migration-budget")
	n, err := (&Conn{E: e}).Write(payload)
	if n != len(payload) || !errors.Is(err, ErrMigrationBudgetExceeded) {
		t.Fatalf("migration-budget Write=(%d,%v), want (%d,%v)", n, err, len(payload), ErrMigrationBudgetExceeded)
	}
	select {
	case <-e.Closed():
	case <-time.After(time.Second):
		t.Fatal("migration-budget close did not quiesce")
	}
	if closeErr := e.Close(); closeErr != nil {
		t.Fatalf("application writer caused teardown self-wait: %v", closeErr)
	}
}

func TestConcurrentWriteDeadlineMutationLeavesDeterministicFinalDeadline(t *testing.T) {
	e := New(SideClient, [16]byte{0xea}, Limits{})
	t.Cleanup(func() { _ = e.Close() })
	targets := configureLeafSelectorRuntime(t, e, "mutation")
	attachFixturePath(t, e, newReplayBudgetPath(), transport.PathSpec{Transport: "deadline", Address: "mutation"}, targets["mutation"])
	start := make(chan struct{})
	done := make(chan struct{}, 32)
	for worker := 0; worker < cap(done); worker++ {
		go func(worker int) {
			<-start
			for iteration := 0; iteration < 100; iteration++ {
				switch (worker + iteration) % 3 {
				case 0:
					_ = e.SetWriteDeadline(time.Time{})
				case 1:
					_ = e.SetWriteDeadline(time.Now().Add(time.Second))
				default:
					_ = e.SetWriteDeadline(time.Now().Add(-time.Second))
				}
			}
			done <- struct{}{}
		}(worker)
	}
	close(start)
	for worker := 0; worker < cap(done); worker++ {
		<-done
	}
	if err := e.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := (&Conn{E: e}).Write([]byte("final-past")); n != 0 || !isWriteTimeout(err) {
		t.Fatalf("final past deadline Write=(%d,%v)", n, err)
	}
	if err := e.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if n, err := (&Conn{E: e}).Write([]byte("final-clear")); n != len("final-clear") || err != nil {
		t.Fatalf("final clear deadline Write=(%d,%v)", n, err)
	}
}

func TestWriteDeadlineAndCloseRaceCannotDoubleReleaseReplayCredit(t *testing.T) {
	for iteration := 0; iteration < 100; iteration++ {
		e := New(SideClient, [16]byte{0xef}, Limits{})
		configureLeafSelectorRuntime(t, e, "unavailable")
		if err := e.acquireSendSlot(false, sendHistoryByteLimit); err != nil {
			t.Fatal(err)
		}
		if err := e.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		writeDone := make(chan error, 1)
		go func() {
			_, err := (&Conn{E: e}).Write([]byte("close-deadline-credit-race"))
			writeDone <- err
		}()
		waitWriteDeadlineCondition(t, time.Second, func() bool { return e.ReplayStats().CreditWaiters == 1 }, "credit race waiter")
		start := make(chan struct{})
		closeDone := make(chan error, 1)
		deadlineDone := make(chan struct{}, 1)
		go func() {
			<-start
			closeDone <- e.Close()
		}()
		go func() {
			<-start
			_ = e.SetWriteDeadline(time.Now().Add(-time.Second))
			deadlineDone <- struct{}{}
		}()
		close(start)
		select {
		case err := <-writeDone:
			if err == nil {
				t.Fatalf("iteration %d blocked Write succeeded during Close", iteration)
			}
		case <-time.After(time.Second):
			t.Fatalf("iteration %d blocked Write did not exit", iteration)
		}
		<-deadlineDone
		if err := <-closeDone; err != nil {
			t.Fatalf("iteration %d Close: %v", iteration, err)
		}
	}
}

func TestRecursiveWriteDeadlinePreservesDataBeforeFINAcrossSibling(t *testing.T) {
	flow := [16]byte{0xf0}
	client := New(SideClient, flow, Limits{})
	server := New(SideServer, flow, Limits{})
	writeGate := make(chan struct{})
	released := false
	t.Cleanup(func() {
		if !released {
			close(writeGate)
		}
		_ = client.Close()
		_ = server.Close()
	})
	clientIDs := configureWriteDeadlineGraph(t, client, "blocked", "healthy")
	serverIDs := configureWriteDeadlineGraph(t, server, "blocked", "healthy")
	blockedClient, blockedServer := newSequencerTestPathPair()
	healthyClient, healthyServer := newSequencerTestPathPair()
	blockedClient.writeStarted = make(chan struct{})
	blockedClient.writeGate = writeGate
	clientPaths := map[string]transport.PathConn{
		"blocked": blockedClient,
		"healthy": &writeDeadlineControlOnlyPath{PathConn: healthyClient},
	}
	serverPaths := map[string]transport.PathConn{"blocked": blockedServer, "healthy": healthyServer}
	for _, name := range []string{"blocked", "healthy"} {
		clientBinding := PathBinding{LocalTXTargetID: clientIDs[name], PeerTXTargetID: clientIDs[name]}
		serverBinding := PathBinding{LocalTXTargetID: serverIDs[name], PeerTXTargetID: serverIDs[name]}
		spec := transport.PathSpec{Transport: "deadline", Address: name}
		if _, err := client.AttachPathBound(clientPaths[name], spec, clientBinding); err != nil {
			t.Fatal(err)
		}
		if _, err := server.AttachPathBound(serverPaths[name], spec, serverBinding); err != nil {
			t.Fatal(err)
		}
	}
	if err := client.SetWriteDeadline(time.Now().Add(40 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("data-must-precede-fin")
	if n, err := (&Conn{E: client}).Write(payload); n != len(payload) || !isWriteTimeout(err) {
		t.Fatalf("DATA Write=(%d,%v)", n, err)
	}
	if err := client.SendStreamFin(); err != nil {
		t.Fatalf("FIN through healthy sibling: %v", err)
	}
	if err := server.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, err := server.Recv(make([]byte, len(payload))); n != 0 || !errors.Is(err, ErrReadDeadlineExceeded) {
		t.Fatalf("FIN overtook missing DATA: Recv=(%d,%v)", n, err)
	}
	if err := server.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := client.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	close(writeGate)
	released = true
	got := make([]byte, len(payload))
	if n, err := server.Recv(got); n != len(payload) || err != nil || string(got) != string(payload) {
		t.Fatalf("DATA after path release=(%q,%d,%v)", got, n, err)
	}
	if n, err := server.Recv(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("Recv after ordered FIN=(%d,%v)", n, err)
	}
}

type writeDeadlineControlOnlyPath struct {
	transport.PathConn
}

func (p *writeDeadlineControlOnlyPath) Write(frame []byte) (int, error) {
	if len(frame) >= proto.HeaderSize {
		header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
		if err == nil && header.Type == proto.FrameData {
			return len(frame), nil
		}
	}
	return p.PathConn.Write(frame)
}

func isWriteTimeout(err error) bool {
	if !errors.Is(err, ErrWriteDeadlineExceeded) || !errors.Is(err, os.ErrDeadlineExceeded) {
		return false
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func waitWriteDeadlineCondition(t testing.TB, timeout time.Duration, condition func() bool, name string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", name)
}

func configureWriteDeadlineGraph(t testing.TB, e *Engine, names ...string) map[string]proto.TargetID {
	t.Helper()
	ids := make(map[string]proto.TargetID, len(names))
	nodes := make([]proto.GraphNode, 0, len(names)+1)
	children := make([]proto.TargetID, 0, len(names))
	for _, name := range names {
		id := proto.DeriveTargetID(proto.GraphNodeKindPath, name)
		ids[name] = id
		children = append(children, id)
		nodes = append(nodes, proto.GraphNode{ID: id, Kind: proto.GraphNodeKindPath, Name: name})
	}
	rootID := children[0]
	if len(children) > 1 {
		rootID = proto.DeriveTargetID(proto.GraphNodeKindSelector, "write-deadline-root")
		nodes = append(nodes, proto.GraphNode{
			ID: rootID, Kind: proto.GraphNodeKindSelector, Name: "write-deadline-root", Children: children,
		})
	}
	manifest := proto.GraphManifest{RootID: rootID, Nodes: nodes}
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	return ids
}

func BenchmarkApplicationDataWriterOverhead(b *testing.B) {
	for _, benchmark := range []struct {
		name        string
		application bool
		selector    bool
	}{
		{name: "path-root-deadline-aware", application: true},
		{name: "path-root-sequencer-direct", application: false},
		{name: "selector-root-deadline-aware", application: true, selector: true},
		{name: "selector-root-sequencer-direct", application: false, selector: true},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			client := New(SideClient, [16]byte{0xeb}, Limits{})
			server := New(SideServer, [16]byte{0xeb}, Limits{})
			pathTarget := proto.DeriveTargetID(proto.GraphNodeKindPath, "write-deadline-benchmark")
			rootTarget := pathTarget
			nodes := []proto.GraphNode{{
				ID: pathTarget, Kind: proto.GraphNodeKindPath, Name: "write-deadline-benchmark",
			}}
			if benchmark.selector {
				rootTarget = proto.DeriveTargetID(proto.GraphNodeKindSelector, "write-deadline-benchmark-root")
				nodes = append([]proto.GraphNode{{
					ID: rootTarget, Kind: proto.GraphNodeKindSelector, Name: "write-deadline-benchmark-root",
					Children: []proto.TargetID{pathTarget},
				}}, nodes...)
			}
			manifest := proto.GraphManifest{RootID: rootTarget, Nodes: nodes}
			for _, endpoint := range []*Engine{client, server} {
				if err := endpoint.ConfigureLocalGraph(1, manifest); err != nil {
					b.Fatal(err)
				}
				if err := endpoint.ConfigurePeerGraph(1, manifest); err != nil {
					b.Fatal(err)
				}
			}
			client.SetPacketMode()
			server.SetPacketMode()
			b.Cleanup(func() {
				_ = client.Close()
				_ = server.Close()
			})
			clientPath, serverPath := newSequencerTestPathPair()
			spec := transport.PathSpec{Transport: "memory", Address: "write-deadline-benchmark"}
			binding := PathBinding{LocalTXTargetID: pathTarget, PeerTXTargetID: pathTarget}
			if _, err := client.AttachPathBound(clientPath, spec, binding); err != nil {
				b.Fatal(err)
			}
			if _, err := server.AttachPathBound(serverPath, spec, binding); err != nil {
				b.Fatal(err)
			}
			payload := make([]byte, 1024)
			drainDone := make(chan error, 1)
			go func() {
				for iteration := 0; iteration < b.N; iteration++ {
					if _, err := server.RecvPacket(); err != nil {
						drainDone <- err
						return
					}
				}
				drainDone <- nil
			}()
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				var err error
				if benchmark.application {
					err = client.SendPacket(payload)
				} else {
					err = client.sendFrame(proto.FrameData, 0, payload)
				}
				if err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			if err := <-drainDone; err != nil {
				b.Fatal(err)
			}
		})
	}
}
