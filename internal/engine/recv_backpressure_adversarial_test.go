package engine

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type recvAdversarialMemoryPath struct {
	peer *recvAdversarialMemoryPath
	in   chan []byte

	closed    chan struct{}
	closeOnce sync.Once
	deathMu   sync.Mutex
	deathFn   func(transport.DeathCause, error)
}

func (p *recvAdversarialMemoryPath) MaxFrameSize() int {
	return 1<<16 - 1
}

func newRecvAdversarialMemoryPathPair() (*recvAdversarialMemoryPath, *recvAdversarialMemoryPath) {
	a := &recvAdversarialMemoryPath{
		in:     make(chan []byte, sendHistoryWindow*4),
		closed: make(chan struct{}),
	}
	b := &recvAdversarialMemoryPath{
		in:     make(chan []byte, sendHistoryWindow*4),
		closed: make(chan struct{}),
	}
	a.peer = b
	b.peer = a
	return a, b
}

func (p *recvAdversarialMemoryPath) Read(buf []byte) (int, error) {
	select {
	case frame := <-p.in:
		return copy(buf, frame), nil
	case <-p.closed:
		return 0, net.ErrClosed
	}
}

func (p *recvAdversarialMemoryPath) Write(frame []byte) (int, error) {
	cp := append([]byte(nil), frame...)
	select {
	case p.peer.in <- cp:
		return len(frame), nil
	case <-p.closed:
		return 0, net.ErrClosed
	case <-p.peer.closed:
		return 0, net.ErrClosed
	}
}

func (p *recvAdversarialMemoryPath) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return nil
}

func (p *recvAdversarialMemoryPath) Quality() transport.PathQuality {
	return transport.PathQuality{}
}

func (p *recvAdversarialMemoryPath) OnDeath(fn func(transport.DeathCause, error)) {
	p.deathMu.Lock()
	p.deathFn = fn
	p.deathMu.Unlock()
}

func (p *recvAdversarialMemoryPath) LocalAddr() string  { return "recv-adversarial-local" }
func (p *recvAdversarialMemoryPath) RemoteAddr() string { return "recv-adversarial-remote" }

func attachRecvAdversarialPair(t *testing.T, client, server *Engine) {
	t.Helper()
	const leafName = "backpressure"
	ids := configureSymmetricLeafGroupRuntime(t, client, server, proto.GraphNodeKindSelector, leafName)
	clientPath, serverPath := newRecvAdversarialMemoryPathPair()
	attachFixturePath(t, client, clientPath, transport.PathSpec{Transport: "test", Address: "server"}, ids[leafName])
	attachFixturePath(t, server, serverPath, transport.PathSpec{Transport: "test", Address: "client"}, ids[leafName])
}

func TestRecvBackpressureBoundsUnconsumedStreamAndAckFrontier(t *testing.T) {
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{})
	server := New(SideServer, flow, Limits{})
	attachRecvAdversarialPair(t, client, server)

	// One replay window is the maximum credit this test permits ahead of
	// application consumption. ACKing more lets the sender recycle its bounded
	// ledger while recvDeliver grows without limit on a stalled application.
	const totalFrames = sendHistoryWindow*2 + 1
	writeDone := make(chan error, 1)
	go func() {
		for i := 0; i < totalFrames; i++ {
			if _, err := client.SendData([]byte{byte(i)}); err != nil {
				writeDone <- err
				return
			}
		}
		writeDone <- nil
	}()

	deadline := time.Now().Add(750 * time.Millisecond)
	var failure string
	writerExited := false
	for failure == "" && time.Now().Before(deadline) {
		if acked := client.sendAckNext.Load(); acked > sendHistoryWindow {
			failure = "peer ACK advanced beyond bounded unread credit"
			break
		}
		select {
		case err := <-writeDone:
			writerExited = true
			if err != nil {
				failure = "writer failed before receiver applied backpressure: " + err.Error()
			} else {
				failure = "writer completed although the application consumed no bytes"
			}
		default:
			time.Sleep(time.Millisecond)
		}
	}

	server.recvMu.Lock()
	unreadBytes := len(server.recvDeliver)
	server.recvMu.Unlock()
	if failure == "" && unreadBytes > sendHistoryWindow {
		failure = "receiver retained more than one bounded window of unread payload"
	}

	_ = client.Close()
	_ = server.Close()
	if !writerExited {
		select {
		case <-writeDone:
		case <-time.After(time.Second):
			t.Fatal("blocked writer did not exit after engine close")
		}
	}
	if failure != "" {
		t.Fatal(failure)
	}
}

func TestRecvBackpressurePacketAckWaitsForDeliveryCapacity(t *testing.T) {
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{})
	server := New(SideServer, flow, Limits{})
	client.SetPacketMode()
	server.SetPacketMode()
	attachRecvAdversarialPair(t, client, server)

	// Model an application that stopped consuming datagrams. A packet is not
	// ACK-owned until it has entered this bounded delivery queue.
	for i := 0; i < cap(server.recvPacketCh); i++ {
		server.recvPacketCh <- []byte{0xee}
	}
	if err := client.SendPacket([]byte("blocked-packet")); err != nil {
		t.Fatalf("send packet: %v", err)
	}

	deadline := time.Now().Add(100 * time.Millisecond)
	ackAdvanced := false
	for time.Now().Before(deadline) {
		if client.sendAckNext.Load() != 0 {
			ackAdvanced = true
			break
		}
		time.Sleep(time.Millisecond)
	}

	_ = client.Close()
	_ = server.Close()
	if ackAdvanced {
		t.Fatal("packet was ACKed before the full delivery queue admitted it")
	}
}

func TestRecvBackpressureResumesWithoutLossAfterSlowReader(t *testing.T) {
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{})
	server := New(SideServer, flow, Limits{})
	attachRecvAdversarialPair(t, client, server)
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	const totalFrames = sendHistoryWindow*3 + 17
	want := make([]byte, totalFrames)
	for index := range want {
		want[index] = byte(index*31 + 7)
	}
	writeDone := make(chan error, 1)
	go func() {
		for _, value := range want {
			if _, err := client.SendData([]byte{value}); err != nil {
				writeDone <- err
				return
			}
		}
		writeDone <- nil
	}()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) && client.ReplayStats().CreditWaiters == 0 {
		time.Sleep(time.Millisecond)
	}
	if stats := client.ReplayStats(); stats.CreditWaiters == 0 {
		server.recvMu.Lock()
		peerExpected := server.expectedRecvSeq
		peerUnread := len(server.recvDeliver)
		server.recvMu.Unlock()
		t.Fatalf("slow-reader replay-credit backpressure was not reached: sender=%+v peer_expected=%d peer_unread=%d",
			stats, peerExpected, peerUnread)
	}
	select {
	case err := <-writeDone:
		t.Fatalf("writer completed before the slow reader resumed: %v", err)
	default:
	}

	got := make([]byte, 0, len(want))
	buffer := make([]byte, 97)
	for len(got) < len(want) {
		n, err := server.Recv(buffer)
		if err != nil {
			t.Fatalf("receive after releasing backpressure: %v", err)
		}
		got = append(got, buffer[:n]...)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("slow-reader recovery payload mismatch: got=%d want=%d", len(got), len(want))
	}
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("writer failed after the reader resumed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("writer did not resume after the reader drained bounded delivery credit")
	}
	waitWriteDeadlineCondition(t, 2*time.Second, func() bool {
		stats := client.ReplayStats()
		return stats.FramesInUse == 0 && stats.BytesInUse == 0 && stats.CreditWaiters == 0
	}, "slow-reader replay-ledger drain")
	stats := client.ReplayStats()
	if stats.FramesHighWater > stats.FrameLimit || stats.BytesHighWater > stats.ByteLimit {
		t.Fatalf("slow-reader replay high water exceeded limits: %+v", stats)
	}
}

type recvAdversarialTerminalPath struct {
	closed    chan struct{}
	closeOnce sync.Once
	deathMu   sync.Mutex
	deathFn   func(transport.DeathCause, error)

	preAckStarted chan struct{}
	preAckRelease chan struct{}
	preAckOnce    sync.Once

	terminalAckDone  chan struct{}
	terminalAckOnce  sync.Once
	terminalAckStart chan struct{}
	terminalStartOne sync.Once
	terminalAckGate  <-chan struct{}
	blockTerminalAck bool
	byeWrites        atomic.Uint64
	byeSeen          atomic.Bool

	closeStarted chan struct{}
	closeRelease chan struct{}
	closeStart   sync.Once
	eventSeq     atomic.Uint64
	terminalOrd  atomic.Uint64
	closeOrd     atomic.Uint64
}

func newRecvAdversarialTerminalPath() *recvAdversarialTerminalPath {
	return &recvAdversarialTerminalPath{
		closed:           make(chan struct{}),
		preAckStarted:    make(chan struct{}),
		preAckRelease:    make(chan struct{}),
		terminalAckDone:  make(chan struct{}),
		terminalAckStart: make(chan struct{}),
		closeStarted:     make(chan struct{}),
		closeRelease:     make(chan struct{}),
	}
}

func (p *recvAdversarialTerminalPath) Read([]byte) (int, error) {
	<-p.closed
	return 0, net.ErrClosed
}

func (p *recvAdversarialTerminalPath) Write(frame []byte) (int, error) {
	if len(frame) >= proto.HeaderSize {
		if header, err := proto.DecodeHeader(frame[:proto.HeaderSize]); err == nil &&
			header.Type == proto.FrameCtrl && proto.CtrlCodeFromFlags(header.Flags) == proto.CtrlBye {
			p.byeWrites.Add(1)
		}
	}
	ack, ok := recvAdversarialDecodeAck(frame)
	if !ok {
		return len(frame), nil
	}
	if ack.NextSeq == 0 && ack.Gap {
		p.preAckOnce.Do(func() { close(p.preAckStarted) })
		select {
		case <-p.preAckRelease:
			return len(frame), nil
		case <-p.closed:
			return 0, net.ErrClosed
		}
	}
	if ack.NextSeq == 1 {
		p.terminalStartOne.Do(func() { close(p.terminalAckStart) })
		if p.terminalAckGate != nil {
			select {
			case <-p.terminalAckGate:
			case <-p.closed:
				return 0, net.ErrClosed
			}
		}
		if p.blockTerminalAck {
			<-p.closed
			return 0, net.ErrClosed
		}
		p.terminalOrd.Store(p.eventSeq.Add(1))
		p.terminalAckOnce.Do(func() { close(p.terminalAckDone) })
	}
	return len(frame), nil
}

func (p *recvAdversarialTerminalPath) Close() error {
	p.closeStart.Do(func() {
		p.closeOrd.Store(p.eventSeq.Add(1))
		close(p.closeStarted)
		<-p.closeRelease
		p.closeOnce.Do(func() { close(p.closed) })
	})
	return nil
}

func (p *recvAdversarialTerminalPath) Quality() transport.PathQuality {
	return transport.PathQuality{}
}

func (p *recvAdversarialTerminalPath) OnDeath(fn func(transport.DeathCause, error)) {
	p.deathMu.Lock()
	p.deathFn = fn
	p.deathMu.Unlock()
}

func (p *recvAdversarialTerminalPath) MarkByeSeen() { p.byeSeen.Store(true) }

func (p *recvAdversarialTerminalPath) LocalAddr() string  { return "terminal-local" }
func (p *recvAdversarialTerminalPath) RemoteAddr() string { return "terminal-remote" }

func recvAdversarialDecodeAck(frame []byte) (proto.AckPayload, bool) {
	if len(frame) < proto.HeaderSize {
		return proto.AckPayload{}, false
	}
	hdr, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	if err != nil || hdr.Type != proto.FrameCtrl || proto.CtrlCodeFromFlags(hdr.Flags) != proto.CtrlPathProbeReply {
		return proto.AckPayload{}, false
	}
	return proto.DecodeAck(frame[proto.HeaderSize:])
}

func recvAdversarialTerminalBatch(slot *pathSlot) []recvFrame {
	return []recvFrame{{
		slot: slot,
		hdr: proto.Header{
			Version: proto.Version,
			Type:    proto.FrameCtrl,
			Flags:   proto.FlagsForCtrl(proto.CtrlBye),
			Seq:     0,
		},
		payload: proto.ByePayload{Reason: proto.ByeNormal}.Encode(),
	}}
}

func attachRecvAdversarialTerminalPath(t *testing.T, e *Engine, path *recvAdversarialTerminalPath) *pathSlot {
	t.Helper()
	id, err := e.AttachPath(path, transport.PathSpec{Transport: "test", Address: "terminal"})
	if err != nil {
		t.Fatalf("attach terminal path: %v", err)
	}
	e.pathsMu.RLock()
	slot := e.paths[id]
	e.pathsMu.RUnlock()
	if slot == nil {
		t.Fatal("attached terminal path has no slot")
	}
	return slot
}

func TestRecvTerminalAckCompletesBeforeTransportClose(t *testing.T) {
	e := New(SideServer, [16]byte{0xb1}, Limits{})
	path := newRecvAdversarialTerminalPath()
	slot := attachRecvAdversarialTerminalPath(t, e, path)

	// Keep the ordinary ACK writer occupied. A terminal ACK must not be a
	// best-effort enqueue followed immediately by transport close.
	e.sendAck(0, true, e.recvProof)
	select {
	case <-path.preAckStarted:
	case <-time.After(time.Second):
		close(path.preAckRelease)
		close(path.closeRelease)
		_ = e.Close()
		t.Fatal("ordinary ACK writer did not enter the controlled write")
	}

	done := make(chan struct{})
	go func() {
		e.onRecvBatch(recvAdversarialTerminalBatch(slot))
		close(done)
	}()

	select {
	case <-path.closeStarted:
		// Current broken ordering arrives here while the terminal ACK is still
		// queued behind the controlled ordinary ACK.
	case <-path.terminalAckDone:
	case <-time.After(30 * time.Millisecond):
	}
	close(path.preAckRelease)

	select {
	case <-path.terminalAckDone:
	case <-path.closeStarted:
	case <-time.After(300 * time.Millisecond):
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		close(path.closeRelease)
		_ = e.Close()
		t.Fatal("terminal receive did not finish after releasing the ACK writer")
	}
	select {
	case <-path.closeStarted:
		t.Fatal("normal peer BYE closed the transport before local application Close")
	default:
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- e.GracefulClose(proto.ByeNormal) }()
	select {
	case <-path.closeStarted:
	case <-time.After(time.Second):
		t.Fatal("local Close after peer BYE did not release the transport")
	}
	close(path.closeRelease)
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("local Close after peer BYE: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("local Close after peer BYE did not finish")
	}

	terminalOrder := path.terminalOrd.Load()
	closeOrder := path.closeOrd.Load()
	if terminalOrder == 0 {
		t.Fatal("terminal ACK was lost when transport close overtook the ACK writer")
	}
	if closeOrder == 0 || terminalOrder >= closeOrder {
		t.Fatalf("terminal ACK order=%d, transport close order=%d; ACK must complete first", terminalOrder, closeOrder)
	}
}

func TestRecvTerminalAckBlockedWriteHasBoundedClose(t *testing.T) {
	e := New(SideServer, [16]byte{0xb2}, Limits{})
	path := newRecvAdversarialTerminalPath()
	path.blockTerminalAck = true
	slot := attachRecvAdversarialTerminalPath(t, e, path)

	done := make(chan struct{})
	go func() {
		e.onRecvBatch(recvAdversarialTerminalBatch(slot))
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		close(path.closeRelease)
		_ = e.Close()
		t.Fatal("terminal ACK handling exceeded its bounded write deadline")
	}
	select {
	case <-path.closeStarted:
		t.Fatal("bounded terminal ACK timeout closed the peer half before local Close")
	default:
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- e.GracefulClose(proto.ByeNormal) }()
	select {
	case <-path.closeStarted:
	case <-time.After(time.Second):
		close(path.closeRelease)
		_ = e.Close()
		t.Fatal("local Close did not unblock the timed-out terminal ACK write")
	}
	close(path.closeRelease)
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("local Close after timed-out terminal ACK: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("local Close remained blocked after transport release")
	}
}

func TestPeerNormalByeDoesNotExposeEOForSendReciprocalByeBeforeAckAttempt(t *testing.T) {
	e := New(SideServer, [16]byte{0xb3}, Limits{})
	path := newRecvAdversarialTerminalPath()
	ackGate := make(chan struct{})
	path.terminalAckGate = ackGate
	slot := attachRecvAdversarialTerminalPath(t, e, path)

	receiveDone := make(chan struct{})
	go func() {
		e.onRecvBatch(recvAdversarialTerminalBatch(slot))
		close(receiveDone)
	}()
	select {
	case <-path.terminalAckStart:
	case <-time.After(time.Second):
		close(ackGate)
		close(path.closeRelease)
		_ = e.Close()
		t.Fatal("terminal ACK attempt did not start")
	}

	readDone := make(chan error, 1)
	go func() {
		_, err := e.Recv(make([]byte, 1))
		readDone <- err
	}()
	select {
	case err := <-readDone:
		close(ackGate)
		close(path.closeRelease)
		_ = e.Close()
		t.Fatalf("Read exposed terminal state before ACK handoff: %v", err)
	case <-time.After(30 * time.Millisecond):
	}

	close(ackGate)
	select {
	case <-receiveDone:
	case <-time.After(time.Second):
		close(path.closeRelease)
		_ = e.Close()
		t.Fatal("terminal receive did not finish after ACK handoff")
	}
	select {
	case err := <-readDone:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("Read after ACK handoff = %v, want EOF", err)
		}
	case <-time.After(time.Second):
		close(path.closeRelease)
		_ = e.Close()
		t.Fatal("Read did not expose EOF after ACK handoff")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- e.GracefulClose(proto.ByeNormal) }()
	select {
	case <-path.closeStarted:
	case <-time.After(time.Second):
		close(path.closeRelease)
		_ = e.Close()
		t.Fatal("local Close after peer BYE did not start transport teardown")
	}
	close(path.closeRelease)
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("local Close after peer BYE: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("local Close after peer BYE did not finish")
	}
	if got := path.byeWrites.Load(); got != 0 {
		t.Fatalf("local Close emitted %d reciprocal BYE frames", got)
	}
}

func TestPeerNormalByeMarksEverySiblingPathCleanBeforeTerminalAck(t *testing.T) {
	e := New(SideServer, [16]byte{0xb5}, Limits{})
	first := newRecvAdversarialTerminalPath()
	firstSlot := attachRecvAdversarialTerminalPath(t, e, first)
	second := newRecvAdversarialTerminalPath()
	if _, err := e.AttachPath(second, transport.PathSpec{Transport: "test", Address: "terminal-sibling"}); err != nil {
		close(first.closeRelease)
		close(second.closeRelease)
		_ = e.Close()
		t.Fatalf("attach sibling terminal path: %v", err)
	}

	e.onRecvBatch(recvAdversarialTerminalBatch(firstSlot))
	if !first.byeSeen.Load() || !second.byeSeen.Load() {
		close(first.closeRelease)
		close(second.closeRelease)
		_ = e.Close()
		t.Fatalf("session BYE markers source/sibling=%t/%t", first.byeSeen.Load(), second.byeSeen.Load())
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- e.GracefulClose(proto.ByeNormal) }()
	for _, path := range []*recvAdversarialTerminalPath{first, second} {
		select {
		case <-path.closeStarted:
		case <-time.After(time.Second):
			close(first.closeRelease)
			close(second.closeRelease)
			_ = e.Close()
			t.Fatal("peer-normal Close did not start every sibling teardown")
		}
	}
	close(first.closeRelease)
	close(second.closeRelease)
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("peer-normal sibling Close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("peer-normal sibling Close did not finish")
	}
}
