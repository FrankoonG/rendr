package engine

import (
	"net"
	"sync"
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

func newCloseLinearizationPath() *closeLinearizationPath {
	return &closeLinearizationPath{closed: make(chan struct{})}
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

func attachCloseLinearizationPath(t *testing.T, e *Engine, path *closeLinearizationPath) {
	t.Helper()
	path.owner = e
	if _, err := e.AttachPath(path, transport.PathSpec{Transport: "adversarial", Address: "close-linearization"}); err != nil {
		t.Fatalf("AttachPath: %v", err)
	}
}

func waitCloseLinearizationSignal(t *testing.T, ch <-chan struct{}, timeout time.Duration, label string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for %s", label)
	}
}

func TestGracefulCloseRejectsDataAfterFinalSequenceLinearizes(t *testing.T) {
	e := New(SideClient, [16]byte{0xc1}, Limits{MigrationBudget: 250 * time.Millisecond})
	t.Cleanup(func() { _ = e.Close() })

	byeGate := make(chan struct{})
	var releaseBye sync.Once
	t.Cleanup(func() { releaseBye.Do(func() { close(byeGate) }) })
	path := newCloseLinearizationPath()
	path.byeStarted = make(chan struct{})
	path.byeGate = byeGate
	attachCloseLinearizationPath(t, e, path)

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

func TestConcurrentGracefulCloseSharesFinalFrameAndResult(t *testing.T) {
	e := New(SideClient, [16]byte{0xc2}, Limits{MigrationBudget: 250 * time.Millisecond})
	t.Cleanup(func() { _ = e.Close() })

	byeGate := make(chan struct{})
	var releaseBye sync.Once
	t.Cleanup(func() { releaseBye.Do(func() { close(byeGate) }) })
	path := newCloseLinearizationPath()
	path.byeStarted = make(chan struct{})
	path.byeGate = byeGate
	path.autoAckBye = true
	attachCloseLinearizationPath(t, e, path)

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

func TestGracefulCloseIsBoundedBehindPermanentlyBlockedWrite(t *testing.T) {
	e := New(SideClient, [16]byte{0xc3}, Limits{MigrationBudget: 50 * time.Millisecond})
	t.Cleanup(func() { _ = e.Close() })

	writeGate := make(chan struct{})
	var releaseWrite sync.Once
	t.Cleanup(func() { releaseWrite.Do(func() { close(writeGate) }) })
	path := newCloseLinearizationPath()
	path.writeStarted = make(chan struct{})
	path.writeGate = writeGate
	attachCloseLinearizationPath(t, e, path)

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
	case <-e.Closed():
	default:
		t.Error("bounded graceful-close failure left the engine open")
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
}

func TestGracefulCloseHasTerminalCreditBeyondReplayCapacity(t *testing.T) {
	e := New(SideClient, [16]byte{0xc4}, Limits{MigrationBudget: 250 * time.Millisecond})
	t.Cleanup(func() { _ = e.Close() })

	path := newCloseLinearizationPath()
	path.byeStarted = make(chan struct{})
	path.autoAckBye = true
	attachCloseLinearizationPath(t, e, path)

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
