package engine

import (
	"bytes"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/transport"
)

type memoryPathConn struct {
	peer       *memoryPathConn
	in         chan []byte
	closed     chan struct{}
	closeOnce  sync.Once
	deathMu    sync.Mutex
	deathFn    func(transport.DeathCause, error)
	dropWrites atomic.Bool
	quality    transport.PathQuality
	writes     atomic.Uint64
	reads      atomic.Uint64
}

func newMemoryPathPair() (*memoryPathConn, *memoryPathConn) {
	a := &memoryPathConn{
		in:     make(chan []byte, 64),
		closed: make(chan struct{}),
	}
	b := &memoryPathConn{
		in:     make(chan []byte, 64),
		closed: make(chan struct{}),
	}
	a.peer = b
	b.peer = a
	return a, b
}

func (p *memoryPathConn) Read(buf []byte) (int, error) {
	select {
	case frame := <-p.in:
		n := copy(buf, frame)
		p.reads.Add(1)
		return n, nil
	case <-p.closed:
		return 0, net.ErrClosed
	}
}

func (p *memoryPathConn) Write(frame []byte) (int, error) {
	select {
	case <-p.closed:
		return 0, net.ErrClosed
	default:
	}
	if p.dropWrites.Load() {
		p.writes.Add(1)
		return len(frame), nil
	}
	cp := append([]byte(nil), frame...)
	select {
	case p.peer.in <- cp:
		p.writes.Add(1)
		return len(frame), nil
	case <-p.peer.closed:
		return 0, net.ErrClosed
	case <-p.closed:
		return 0, net.ErrClosed
	}
}

func (p *memoryPathConn) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return nil
}

func (p *memoryPathConn) Quality() transport.PathQuality { return p.quality }

func (p *memoryPathConn) OnDeath(fn func(transport.DeathCause, error)) {
	p.deathMu.Lock()
	p.deathFn = fn
	p.deathMu.Unlock()
}

func (p *memoryPathConn) LocalAddr() string  { return "memory-local" }
func (p *memoryPathConn) RemoteAddr() string { return "memory-remote" }
func (p *memoryPathConn) Writes() uint64     { return p.writes.Load() }
func (p *memoryPathConn) Reads() uint64      { return p.reads.Load() }

func TestBondRedistributesDeadPathHistory(t *testing.T) {
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{}.Clamp())
	server := New(SideServer, flow, Limits{}.Clamp())
	defer client.Close()
	defer server.Close()

	client.SetMode(dispatchBond)
	client.SetBondPinSizeForTest(1)

	c1, s1 := newMemoryPathPair()
	c2, s2 := newMemoryPathPair()
	c1.dropWrites.Store(true)

	deadID, err := client.AttachPath(c1, transport.PathSpec{Transport: "memory", Address: "path-1"})
	if err != nil {
		t.Fatalf("attach client path 1: %v", err)
	}
	if _, err := server.AttachPath(s1, transport.PathSpec{Transport: "memory", Address: "path-1"}); err != nil {
		t.Fatalf("attach server path 1: %v", err)
	}
	if _, err := client.AttachPath(c2, transport.PathSpec{Transport: "memory", Address: "path-2"}); err != nil {
		t.Fatalf("attach client path 2: %v", err)
	}
	if _, err := server.AttachPath(s2, transport.PathSpec{Transport: "memory", Address: "path-2"}); err != nil {
		t.Fatalf("attach server path 2: %v", err)
	}

	client.pathsMu.Lock()
	client.bondCursor = ^uint64(0)
	client.bondPinLeft = 0
	client.pathsMu.Unlock()

	payload := []byte("lost-on-dead-bond-path")
	if _, err := client.SendData(payload); err != nil {
		t.Fatalf("SendData: %v", err)
	}
	if c1.Writes() != 1 || c2.Writes() != 0 {
		t.Fatalf("test did not route first frame to dropped path: c1=%d c2=%d", c1.Writes(), c2.Writes())
	}

	if err := client.ForceKillPathForTest(deadID); err != nil {
		t.Fatalf("ForceKillPathForTest: %v", err)
	}

	if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(&Conn{E: server}, got); err != nil {
		t.Fatalf("server did not receive redistributed frame: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("redistributed payload = %q, want %q", got, payload)
	}
}

func TestBondRedistributionSkipsAckedHistory(t *testing.T) {
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{}.Clamp())
	server := New(SideServer, flow, Limits{}.Clamp())
	defer client.Close()
	defer server.Close()

	client.SetMode(dispatchBond)
	client.SetBondPinSizeForTest(1)

	c1, s1 := newMemoryPathPair()
	c2, s2 := newMemoryPathPair()

	deadID, err := client.AttachPath(c1, transport.PathSpec{Transport: "memory", Address: "path-1"})
	if err != nil {
		t.Fatalf("attach client path 1: %v", err)
	}
	if _, err := server.AttachPath(s1, transport.PathSpec{Transport: "memory", Address: "path-1"}); err != nil {
		t.Fatalf("attach server path 1: %v", err)
	}
	if _, err := client.AttachPath(c2, transport.PathSpec{Transport: "memory", Address: "path-2"}); err != nil {
		t.Fatalf("attach client path 2: %v", err)
	}
	if _, err := server.AttachPath(s2, transport.PathSpec{Transport: "memory", Address: "path-2"}); err != nil {
		t.Fatalf("attach server path 2: %v", err)
	}

	client.pathsMu.Lock()
	client.bondCursor = ^uint64(0)
	client.bondPinLeft = 0
	client.pathsMu.Unlock()

	payload := []byte("acked-bond-frame")
	if _, err := client.SendData(payload); err != nil {
		t.Fatalf("SendData: %v", err)
	}
	if c1.Writes() != 1 || c2.Writes() != 0 {
		t.Fatalf("test did not route first frame to path 1: c1=%d c2=%d", c1.Writes(), c2.Writes())
	}

	if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(&Conn{E: server}, got); err != nil {
		t.Fatalf("server did not receive original frame: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("original payload = %q, want %q", got, payload)
	}

	deadline := time.Now().Add(2 * time.Second)
	for client.sendAckNext.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := client.sendAckNext.Load(); got < 1 {
		t.Fatalf("client did not receive cumulative ACK; sendAckNext=%d", got)
	}

	if err := client.ForceKillPathForTest(deadID); err != nil {
		t.Fatalf("ForceKillPathForTest: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if got := c2.Writes(); got != 0 {
		t.Fatalf("acked frame was redistributed to survivor: c2 writes=%d, want 0", got)
	}
}
