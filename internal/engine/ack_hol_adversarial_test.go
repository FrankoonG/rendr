package engine

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type ackHOLAdversarialPath struct {
	writeGate    <-chan struct{}
	writeStarted chan struct{}
	writes       chan []byte

	closed       chan struct{}
	closeOnce    sync.Once
	writeOnce    sync.Once
	deathMu      sync.Mutex
	deathHandler func(transport.DeathCause, error)
}

func newAckHOLAdversarialPath(writeGate <-chan struct{}) *ackHOLAdversarialPath {
	return &ackHOLAdversarialPath{
		writeGate:    writeGate,
		writeStarted: make(chan struct{}),
		writes:       make(chan []byte, 8),
		closed:       make(chan struct{}),
	}
}

func (p *ackHOLAdversarialPath) Read([]byte) (int, error) {
	<-p.closed
	return 0, net.ErrClosed
}

func (p *ackHOLAdversarialPath) Write(frame []byte) (int, error) {
	p.writeOnce.Do(func() { close(p.writeStarted) })
	if p.writeGate != nil {
		// Deliberately ignore Close here. A hostile PathConn may leave an
		// in-flight write stuck forever; ACK progress on another path must not
		// depend on this implementation honoring cancellation.
		<-p.writeGate
	}
	copyFrame := append([]byte(nil), frame...)
	select {
	case p.writes <- copyFrame:
		return len(frame), nil
	case <-p.closed:
		return 0, net.ErrClosed
	}
}

func (p *ackHOLAdversarialPath) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return nil
}

func (*ackHOLAdversarialPath) Quality() transport.PathQuality {
	return transport.PathQuality{}
}

func (p *ackHOLAdversarialPath) OnDeath(fn func(transport.DeathCause, error)) {
	p.deathMu.Lock()
	p.deathHandler = fn
	p.deathMu.Unlock()
}

func (*ackHOLAdversarialPath) LocalAddr() string  { return "ack-hol-local" }
func (*ackHOLAdversarialPath) RemoteAddr() string { return "ack-hol-remote" }

func TestAckBlockedPathDoesNotHeadOfLineBlockHealthyPath(t *testing.T) {
	e := New(SideServer, NewClientFlowID(), Limits{})
	blockWrites := make(chan struct{})
	var releaseOnce sync.Once
	releaseBlockedWrite := func() { releaseOnce.Do(func() { close(blockWrites) }) }
	t.Cleanup(func() {
		releaseBlockedWrite()
		_ = e.Close()
	})

	blocked := newAckHOLAdversarialPath(blockWrites)
	if _, err := e.AttachPath(blocked, transport.PathSpec{Transport: "test", Address: "blocked"}); err != nil {
		t.Fatalf("attach blocked ACK path: %v", err)
	}

	// Start an ACK while the blocked path is the only attached destination.
	// This removes map iteration order from the test: the first write must be
	// the hostile one and must remain in flight when the healthy path appears.
	e.sendAck(1, true, e.recvProof)
	select {
	case <-blocked.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("ACK writer never reached the blocked path")
	}

	healthy := newAckHOLAdversarialPath(nil)
	if _, err := e.AttachPath(healthy, transport.PathSpec{Transport: "test", Address: "healthy"}); err != nil {
		t.Fatalf("attach healthy ACK path: %v", err)
	}
	e.sendAck(2, true, e.recvProof)

	select {
	case frame := <-healthy.writes:
		if len(frame) < proto.HeaderSize {
			t.Fatalf("healthy path received short ACK frame: %d bytes", len(frame))
		}
		hdr, err := proto.DecodeHeader(frame[:proto.HeaderSize])
		if err != nil {
			t.Fatalf("decode ACK header: %v", err)
		}
		if hdr.Type != proto.FrameCtrl || proto.CtrlCodeFromFlags(hdr.Flags) != proto.CtrlPathProbeReply {
			t.Fatalf("healthy path received control code %s, want cumulative ACK", proto.CtrlCodeFromFlags(hdr.Flags))
		}
		ack, ok := proto.DecodeAck(frame[proto.HeaderSize:])
		if !ok {
			t.Fatal("healthy path received malformed cumulative ACK")
		}
		if ack.NextSeq < 2 {
			t.Fatalf("healthy path ACK frontier = %d, want at least 2", ack.NextSeq)
		}
	case <-time.After(300 * time.Millisecond):
		releaseBlockedWrite()
		t.Fatal("blocked PathConn.Write prevented ACK progress on the healthy path")
	}
}

func TestPacketMissingFloorBoundsProofStateByReplayCredit(t *testing.T) {
	e := New(SideServer, NewClientFlowID(), Limits{})
	defer e.Close()
	e.SetPacketMode()

	// Keep SEQ 0 permanently absent while delivering later packets. The peer
	// cannot legitimately have more DATA in flight than its replay credits, so
	// receiver-owned per-frame proof state must use that credit as its bound,
	// not the much larger packet duplicate bitmap capacity.
	e.recvMu.Lock()
	for seq := uint64(1); seq <= uint64(sendHistoryWindow*4); seq++ {
		if e.isClosed() {
			break // fail-closed is an acceptable bounded response to this peer.
		}
		deliver := make([][]byte, 0, 1)
		e.onFrameRecvLocked(nil, proto.Header{
			Version: proto.Version,
			Type:    proto.FrameData,
			Seq:     seq,
		}, []byte{byte(seq)}, &deliver)
	}
	proofs := len(e.recvFrameProofs)
	marks := e.recvPacketMarks
	reorder := len(e.recvQueue)
	highWater := e.recvQueueHWM
	droppedThrough := e.recvDroppedThrough
	hasGap := e.recvHasGapLocked()
	e.recvMu.Unlock()

	if droppedThrough < uint64(packetRecvWindowBits) {
		t.Errorf("beyond-window stimulus was not dropped: dropped-through=%d window=%d", droppedThrough, packetRecvWindowBits)
	}
	if !hasGap {
		t.Error("dropping beyond-window packets did not leave a cumulative-ACK GAP")
	}
	if proofs > sendHistoryWindow {
		t.Errorf("packet proof entries = %d, want <= replay credit %d", proofs, sendHistoryWindow)
	}
	if marks > sendHistoryWindow {
		t.Errorf("packet out-of-order marks = %d, want <= replay credit %d", marks, sendHistoryWindow)
	}
	if dynamic := marks + reorder; dynamic > sendHistoryWindow {
		t.Errorf("packet dynamic receive state = %d (marks=%d reorder=%d), want <= replay credit %d", dynamic, marks, reorder, sendHistoryWindow)
	}
	if highWater > sendHistoryWindow {
		t.Errorf("packet receive high-water = %d, want <= replay credit %d", highWater, sendHistoryWindow)
	}
}
