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

	"github.com/FrankoonG/rendr/transport"
)

type sequencerTestPath struct {
	peer *sequencerTestPath
	in   chan []byte

	closed    chan struct{}
	closeOnce sync.Once

	deathMu sync.Mutex
	deathFn func(transport.DeathCause, error)

	writes        atomic.Uint64
	dropWrites    atomic.Bool
	dieFirstWrite atomic.Bool
	died          atomic.Bool
	writeStarted  chan struct{}
	writeGate     <-chan struct{}
	startOnce     sync.Once
}

func newSequencerTestPathPair() (*sequencerTestPath, *sequencerTestPath) {
	a := &sequencerTestPath{in: make(chan []byte, 1024), closed: make(chan struct{})}
	b := &sequencerTestPath{in: make(chan []byte, 1024), closed: make(chan struct{})}
	a.peer = b
	b.peer = a
	return a, b
}

func (p *sequencerTestPath) Read(buf []byte) (int, error) {
	select {
	case frame := <-p.in:
		return copy(buf, frame), nil
	case <-p.closed:
		return 0, net.ErrClosed
	}
}

func (p *sequencerTestPath) Write(frame []byte) (int, error) {
	select {
	case <-p.closed:
		return 0, net.ErrClosed
	default:
	}
	p.writes.Add(1)
	if p.writeStarted != nil {
		p.startOnce.Do(func() { close(p.writeStarted) })
	}
	if p.writeGate != nil {
		select {
		case <-p.writeGate:
		case <-p.closed:
			return 0, net.ErrClosed
		}
	}
	if p.dieFirstWrite.Load() && p.died.CompareAndSwap(false, true) {
		p.deathMu.Lock()
		fn := p.deathFn
		p.deathMu.Unlock()
		if fn != nil {
			fn(transport.CauseTransportError, errors.New("injected path death during write"))
		}
		return len(frame), nil
	}
	if p.dropWrites.Load() {
		return len(frame), nil
	}
	cp := append([]byte(nil), frame...)
	select {
	case p.peer.in <- cp:
		return len(frame), nil
	case <-p.peer.closed:
		return 0, net.ErrClosed
	case <-p.closed:
		return 0, net.ErrClosed
	}
}

func (p *sequencerTestPath) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return nil
}

func (*sequencerTestPath) Quality() transport.PathQuality { return transport.PathQuality{} }

func (p *sequencerTestPath) OnDeath(fn func(transport.DeathCause, error)) {
	p.deathMu.Lock()
	p.deathFn = fn
	p.deathMu.Unlock()
}

func (*sequencerTestPath) LocalAddr() string  { return "sequencer-local" }
func (*sequencerTestPath) RemoteAddr() string { return "sequencer-remote" }

func attachSequencerPair(t *testing.T, client, server *Engine, c, s *sequencerTestPath, name string) (uint32, uint32) {
	t.Helper()
	id, err := client.AttachPath(c, transport.PathSpec{Transport: "memory", Address: name})
	if err != nil {
		t.Fatalf("attach client %s: %v", name, err)
	}
	serverID, err := server.AttachPath(s, transport.PathSpec{Transport: "memory", Address: name})
	if err != nil {
		t.Fatalf("attach server %s: %v", name, err)
	}
	return id, serverID
}

func TestTXSequenceOwnedBeforePathWrite(t *testing.T) {
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{}.Clamp())
	server := New(SideServer, flow, Limits{}.Clamp())
	defer client.Close()
	defer server.Close()

	c1, s1 := newSequencerTestPathPair()
	c2, s2 := newSequencerTestPathPair()
	c1.dieFirstWrite.Store(true)
	attachSequencerPair(t, client, server, c1, s1, "fails-inside-write")
	attachSequencerPair(t, client, server, c2, s2, "survivor")

	want := []byte("journal-before-publish:later-frame")
	if _, err := client.SendData(want[:len("journal-before-publish:")]); err != nil {
		t.Fatalf("first SendData: %v", err)
	}
	if _, err := client.SendData(want[len("journal-before-publish:"):]); err != nil {
		t.Fatalf("second SendData: %v", err)
	}

	if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(&Conn{E: server}, got); err != nil {
		t.Fatalf("read after in-write death: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("payload = %q, want %q", got, want)
	}
}

func TestTXFinalFrameLinearizesAfterConcurrentWrite(t *testing.T) {
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{}.Clamp())
	server := New(SideServer, flow, Limits{}.Clamp())
	defer client.Close()
	defer server.Close()

	c, s := newSequencerTestPathPair()
	started := make(chan struct{})
	gate := make(chan struct{})
	c.writeStarted = started
	c.writeGate = gate
	attachSequencerPair(t, client, server, c, s, "blocked-writer")

	writeDone := make(chan error, 1)
	go func() {
		_, err := client.SendData([]byte("payload"))
		writeDone <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("data write did not reach path")
	}

	finalDone := make(chan error, 1)
	go func() { finalDone <- client.SendBye(0) }()
	select {
	case err := <-finalDone:
		t.Fatalf("final frame overtook in-flight write: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(gate)

	if err := <-writeDone; err != nil {
		t.Fatalf("data write: %v", err)
	}
	if err := <-finalDone; err != nil {
		t.Fatalf("final frame: %v", err)
	}
	if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("payload"))
	if _, err := io.ReadFull(&Conn{E: server}, got); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if string(got) != "payload" {
		t.Fatalf("payload = %q", got)
	}
	if _, err := (&Conn{E: server}).Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("read after final frame = %v, want EOF", err)
	}
}

func TestTXReplayLedgerDoesNotOverwriteUnackedHead(t *testing.T) {
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{}.Clamp())
	server := New(SideServer, flow, Limits{}.Clamp())
	defer client.Close()
	defer server.Close()

	c1, s1 := newSequencerTestPathPair()
	c2, s2 := newSequencerTestPathPair()
	c1.dropWrites.Store(true)
	s2.dropWrites.Store(true)
	deadID, serverDeadID := attachSequencerPair(t, client, server, c1, s1, "blackhole")
	attachSequencerPair(t, client, server, c2, s2, "survivor")

	const frames = 300
	want := bytes.Repeat([]byte{'x'}, frames)
	sendDone := make(chan error, 1)
	go func() {
		for i := range want {
			if _, err := client.SendData(want[i : i+1]); err != nil {
				sendDone <- err
				return
			}
		}
		sendDone <- nil
	}()

	deadline := time.Now().Add(2 * time.Second)
	for c1.writes.Load() < sendHistoryWindow && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if c1.writes.Load() < sendHistoryWindow {
		t.Fatalf("blackhole writes = %d, want at least %d", c1.writes.Load(), sendHistoryWindow)
	}
	if err := client.ForceKillPathForTest(deadID); err != nil {
		t.Fatalf("kill blackhole: %v", err)
	}
	if err := server.ForceKillPathForTest(serverDeadID); err != nil {
		t.Fatalf("kill peer blackhole: %v", err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for {
		server.recvMu.Lock()
		expected := server.expectedRecvSeq
		server.recvMu.Unlock()
		if expected >= sendHistoryWindow {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("peer advanced to %d, want at least %d before restoring ACK path", expected, sendHistoryWindow)
		}
		time.Sleep(time.Millisecond)
	}
	// Every immediate cumulative ACK was swallowed. The periodic ACK loop must
	// eventually repeat the current floor and release sender backpressure.
	s2.dropWrites.Store(false)

	select {
	case err := <-sendDone:
		if err != nil {
			t.Fatalf("send after failover: %v", err)
		}
	case <-time.After(4 * time.Second):
		client.sendHistMu.Lock()
		historyLen := len(client.sendHist.entries)
		client.sendHistMu.Unlock()
		server.recvMu.Lock()
		expected := server.expectedRecvSeq
		queued := len(server.recvQueue)
		server.recvMu.Unlock()
		t.Fatalf("sender remained blocked: survivor data writes=%d ack writes=%d ackNext=%d published=%d history=%d peer expected=%d queued=%d",
			c2.writes.Load(), s2.writes.Load(), client.sendAckNext.Load(), client.sendPublishedNext.Load(), historyLen, expected, queued)
	}

	if err := server.SetReadDeadline(time.Now().Add(4 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(&Conn{E: server}, got); err != nil {
		t.Fatalf("read replayed ledger: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("payload length/content mismatch: got %d bytes", len(got))
	}
}

func TestPacketGapCannotStrandFinalControlFrame(t *testing.T) {
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{}.Clamp())
	server := New(SideServer, flow, Limits{}.Clamp())
	client.SetPacketMode()
	server.SetPacketMode()
	defer client.Close()
	defer server.Close()

	c1, s1 := newSequencerTestPathPair()
	c2, s2 := newSequencerTestPathPair()
	c1.dropWrites.Store(true)
	deadID, serverDeadID := attachSequencerPair(t, client, server, c1, s1, "packet-blackhole")
	attachSequencerPair(t, client, server, c2, s2, "packet-survivor")

	want := []byte("packet-before-final")
	if err := client.SendPacket(want); err != nil {
		t.Fatalf("SendPacket: %v", err)
	}
	if err := client.ForceKillPathForTest(deadID); err != nil {
		t.Fatalf("kill packet blackhole: %v", err)
	}
	if err := server.ForceKillPathForTest(serverDeadID); err != nil {
		t.Fatalf("kill peer packet blackhole: %v", err)
	}
	if err := client.SendBye(0); err != nil {
		t.Fatalf("SendBye: %v", err)
	}

	if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err := server.RecvPacket()
	if err != nil {
		t.Fatalf("RecvPacket: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("packet = %q, want %q", got, want)
	}
	if _, err := server.RecvPacket(); !errors.Is(err, io.EOF) {
		t.Fatalf("RecvPacket after final frame = %v, want EOF", err)
	}
}
