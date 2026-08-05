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

type memoryPathConn struct {
	peer       *memoryPathConn
	in         chan []byte
	closed     chan struct{}
	closeOnce  sync.Once
	failed     chan struct{}
	failOnce   sync.Once
	failMu     sync.Mutex
	failErr    error
	deathMu    sync.Mutex
	deathFn    func(transport.DeathCause, error)
	deathOnce  sync.Once
	dropWrites atomic.Bool
	quality    transport.PathQuality
	writes     atomic.Uint64
	reads      atomic.Uint64
}

func newMemoryPathPair() (*memoryPathConn, *memoryPathConn) {
	a := &memoryPathConn{
		in:     make(chan []byte, 64),
		closed: make(chan struct{}),
		failed: make(chan struct{}),
	}
	b := &memoryPathConn{
		in:     make(chan []byte, 64),
		closed: make(chan struct{}),
		failed: make(chan struct{}),
	}
	a.peer = b
	b.peer = a
	return a, b
}

func (p *memoryPathConn) Read(buf []byte) (int, error) {
	if err := p.failure(); err != nil {
		p.notifyFailure(err)
		return 0, err
	}
	select {
	case frame := <-p.in:
		n := copy(buf, frame)
		p.reads.Add(1)
		return n, nil
	case <-p.failed:
		err := p.failure()
		p.notifyFailure(err)
		return 0, err
	case <-p.closed:
		return 0, net.ErrClosed
	}
}

func (p *memoryPathConn) Write(frame []byte) (int, error) {
	if err := p.failure(); err != nil {
		p.notifyFailure(err)
		return 0, err
	}
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
	case <-p.failed:
		err := p.failure()
		p.notifyFailure(err)
		return 0, err
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

func (p *memoryPathConn) Fail(err error) {
	if err == nil {
		err = errors.New("injected memory path failure")
	}
	p.failOnce.Do(func() {
		p.failMu.Lock()
		p.failErr = err
		p.failMu.Unlock()
		close(p.failed)
	})
}

func (p *memoryPathConn) failure() error {
	select {
	case <-p.failed:
		p.failMu.Lock()
		err := p.failErr
		p.failMu.Unlock()
		if err == nil {
			return errors.New("memory path failed")
		}
		return err
	default:
		return nil
	}
}

func (p *memoryPathConn) notifyFailure(err error) {
	p.deathMu.Lock()
	fn := p.deathFn
	p.deathMu.Unlock()
	if fn != nil {
		p.deathOnce.Do(func() { fn(transport.CauseTransportError, err) })
	}
}

func failMemoryPath(t *testing.T, e *Engine, id uint32, path *memoryPathConn, err error) {
	t.Helper()
	path.Fail(err)
	waitPathDetached(t, e, id)
}

func waitPathDetached(t *testing.T, e *Engine, id uint32) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, ok := e.PathRef(id); !ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("path %d remained attached after fixture I/O failure", id)
		}
		time.Sleep(time.Millisecond)
	}
}

func (p *memoryPathConn) LocalAddr() string  { return "memory-local" }
func (p *memoryPathConn) RemoteAddr() string { return "memory-remote" }
func (p *memoryPathConn) Writes() uint64     { return p.writes.Load() }
func (p *memoryPathConn) Reads() uint64      { return p.reads.Load() }

func TestBondRedistributesDeadPathHistory(t *testing.T) {
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{BondPinSize: 1}.Clamp())
	server := New(SideServer, flow, Limits{}.Clamp())
	defer client.Close()
	defer server.Close()

	if err := client.ConfigureExecution(proto.ExecutionKindBond); err != nil {
		t.Fatal(err)
	}
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

	failMemoryPath(t, client, deadID, c1, errors.New("path-1 transport failed"))

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
	client := New(SideClient, flow, Limits{BondPinSize: 1}.Clamp())
	server := New(SideServer, flow, Limits{}.Clamp())
	defer client.Close()
	defer server.Close()

	if err := client.ConfigureExecution(proto.ExecutionKindBond); err != nil {
		t.Fatal(err)
	}
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

	failMemoryPath(t, client, deadID, c1, errors.New("path-1 transport failed"))
	time.Sleep(100 * time.Millisecond)
	if got := c2.Writes(); got != 0 {
		t.Fatalf("acked frame was redistributed to survivor: c2 writes=%d, want 0", got)
	}
}

func TestSelectorRedistributesUnackedFrameOnPathDeath(t *testing.T) {
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{}.Clamp())
	server := New(SideServer, flow, Limits{}.Clamp())
	defer client.Close()
	defer server.Close()

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

	payload := []byte("lost-on-dead-selector-path")
	if _, err := client.SendData(payload); err != nil {
		t.Fatalf("SendData: %v", err)
	}
	if c1.Writes() != 1 || c2.Writes() != 0 {
		t.Fatalf("test did not route first frame to dropped active path: c1=%d c2=%d", c1.Writes(), c2.Writes())
	}

	failMemoryPath(t, client, deadID, c1, errors.New("path-1 transport failed"))

	if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(&Conn{E: server}, got); err != nil {
		t.Fatalf("server did not receive redistributed selector frame: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("redistributed payload = %q, want %q", got, payload)
	}
}

func TestRemovePathReplaysUnackedFrame(t *testing.T) {
	for _, test := range []struct {
		name string
		kind proto.ExecutionKind
	}{
		{name: "selector", kind: proto.ExecutionKindSelector},
		{name: "bond", kind: proto.ExecutionKindBond},
	} {
		t.Run(test.name, func(t *testing.T) {
			kind := test.kind
			flow := NewClientFlowID()
			limits := Limits{}.Clamp()
			if kind == proto.ExecutionKindBond {
				limits = Limits{BondPinSize: 1}.Clamp()
			}
			client := New(SideClient, flow, limits)
			server := New(SideServer, flow, Limits{}.Clamp())
			defer client.Close()
			defer server.Close()
			if err := client.ConfigureExecution(kind); err != nil {
				t.Fatal(err)
			}
			c1, s1 := newMemoryPathPair()
			c2, s2 := newMemoryPathPair()
			c1.dropWrites.Store(true)
			removedID, err := client.AttachPath(c1, transport.PathSpec{Transport: "memory", Address: "path-1"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := server.AttachPath(s1, transport.PathSpec{Transport: "memory", Address: "path-1"}); err != nil {
				t.Fatal(err)
			}
			if _, err := client.AttachPath(c2, transport.PathSpec{Transport: "memory", Address: "path-2"}); err != nil {
				t.Fatal(err)
			}
			if _, err := server.AttachPath(s2, transport.PathSpec{Transport: "memory", Address: "path-2"}); err != nil {
				t.Fatal(err)
			}
			if kind == proto.ExecutionKindBond {
				client.pathsMu.Lock()
				client.bondCursor = ^uint64(0)
				client.bondPinLeft = 0
				client.pathsMu.Unlock()
			}

			payload := []byte("unacked-before-clean-remove")
			if _, err := client.SendData(payload); err != nil {
				t.Fatal(err)
			}
			if c1.Writes() != 1 || c2.Writes() != 0 {
				t.Fatalf("initial route writes: removed=%d survivor=%d", c1.Writes(), c2.Writes())
			}
			if err := client.RemovePath(removedID); err != nil {
				t.Fatal(err)
			}
			if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(&Conn{E: server}, got); err != nil {
				t.Fatalf("replayed read: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("replayed payload=%q want=%q", got, payload)
			}
			deadline := time.Now().Add(time.Second)
			for client.sendAckNext.Load() < 1 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if got := client.sendAckNext.Load(); got < 1 {
				t.Fatalf("replayed frame was not acknowledged: sendAckNext=%d", got)
			}
			if got := c2.Writes(); got != 1 {
				t.Fatalf("surviving path writes=%d, want one replay", got)
			}
			if got := server.RecvDups(); got != 0 {
				t.Fatalf("server duplicate frames=%d, want 0", got)
			}
		})
	}
}

func TestExplicitMigrateReplaysUnackedFrames(t *testing.T) {
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{}.Clamp())
	server := New(SideServer, flow, Limits{}.Clamp())
	defer client.Close()
	defer server.Close()

	c1, s1 := newMemoryPathPair()
	c2, s2 := newMemoryPathPair()
	c1.dropWrites.Store(true)

	if _, err := client.AttachPath(c1, transport.PathSpec{Transport: "memory", Address: "path-1"}); err != nil {
		t.Fatalf("attach client path 1: %v", err)
	}
	if _, err := server.AttachPath(s1, transport.PathSpec{Transport: "memory", Address: "path-1"}); err != nil {
		t.Fatalf("attach server path 1: %v", err)
	}
	targetID, err := client.AttachPath(c2, transport.PathSpec{Transport: "memory", Address: "path-2"})
	if err != nil {
		t.Fatalf("attach client path 2: %v", err)
	}
	if _, err := server.AttachPath(s2, transport.PathSpec{Transport: "memory", Address: "path-2"}); err != nil {
		t.Fatalf("attach server path 2: %v", err)
	}

	payload := []byte("lost-before-explicit-migrate")
	if _, err := client.SendData(payload); err != nil {
		t.Fatalf("SendData: %v", err)
	}
	if err := client.Migrate(targetID); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(&Conn{E: server}, got); err != nil {
		t.Fatalf("server did not receive replayed migrate frame: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("replayed payload = %q, want %q", got, payload)
	}
}
