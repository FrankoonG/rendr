package engine

import (
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
	clientPath, serverPath := newRecvAdversarialMemoryPathPair()
	if _, err := client.AttachPath(clientPath, transport.PathSpec{Transport: "test", Address: "server"}); err != nil {
		t.Fatalf("attach client path: %v", err)
	}
	if _, err := server.AttachPath(serverPath, transport.PathSpec{Transport: "test", Address: "client"}); err != nil {
		t.Fatalf("attach server path: %v", err)
	}
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
	blockTerminalAck bool

	closeStarted chan struct{}
	closeRelease chan struct{}
	closeStart   sync.Once
	eventSeq     atomic.Uint64
	terminalOrd  atomic.Uint64
	closeOrd     atomic.Uint64
}

func newRecvAdversarialTerminalPath() *recvAdversarialTerminalPath {
	return &recvAdversarialTerminalPath{
		closed:          make(chan struct{}),
		preAckStarted:   make(chan struct{}),
		preAckRelease:   make(chan struct{}),
		terminalAckDone: make(chan struct{}),
		closeStarted:    make(chan struct{}),
		closeRelease:    make(chan struct{}),
	}
}

func (p *recvAdversarialTerminalPath) Read([]byte) (int, error) {
	<-p.closed
	return 0, net.ErrClosed
}

func (p *recvAdversarialTerminalPath) Write(frame []byte) (int, error) {
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
	close(path.closeRelease)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("terminal receive did not finish after releasing ACK and close")
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
	case <-path.closeStarted:
		close(path.closeRelease)
	case <-time.After(500 * time.Millisecond):
		close(path.closeRelease)
		_ = e.Close()
		t.Fatal("terminal ACK handling blocked transport close beyond its bounded deadline")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("terminal receive remained blocked after transport close unblocked the ACK write")
	}
}
