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
	dataWrites atomic.Uint64
	reads      atomic.Uint64
	framesMu   sync.Mutex
	frames     []proto.Header
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

func TestSendHistoryFrameOwnershipContracts(t *testing.T) {
	frame := make([]byte, proto.HeaderSize+3)
	if err := (proto.Header{Version: proto.Version, Type: proto.FrameData, Seq: 1}).Encode(frame); err != nil {
		t.Fatal(err)
	}
	copy(frame[proto.HeaderSize:], "one")

	borrowed := &Engine{}
	if err := borrowed.reserveSendFrame(frame); err != nil {
		t.Fatal(err)
	}
	if &borrowed.sendHist.entries[0].frame[0] == &frame[0] {
		t.Fatal("borrowed reserve retained the caller's frame")
	}

	ownedFrame := append([]byte(nil), frame...)
	owned := &Engine{}
	if err := owned.reserveOwnedSendFrame(ownedFrame); err != nil {
		t.Fatal(err)
	}
	if &owned.sendHist.entries[0].frame[0] != &ownedFrame[0] {
		t.Fatal("owned reserve copied the transferred frame")
	}
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
	if len(frame) >= proto.HeaderSize {
		if header, err := proto.DecodeHeader(frame[:proto.HeaderSize]); err == nil {
			p.framesMu.Lock()
			p.frames = append(p.frames, header)
			p.framesMu.Unlock()
			if header.Type == proto.FrameData {
				p.dataWrites.Add(1)
			}
		}
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
func (p *memoryPathConn) DataWrites() uint64 { return p.dataWrites.Load() }

func (p *memoryPathConn) FrameHeaders() []proto.Header {
	p.framesMu.Lock()
	defer p.framesMu.Unlock()
	return append([]proto.Header(nil), p.frames...)
}
func (p *memoryPathConn) Reads() uint64 { return p.reads.Load() }

type accelerationMemoryPath struct {
	*memoryPathConn
	status transport.DatagramAccelerationStatus
}

func (p *accelerationMemoryPath) DatagramAccelerationStatus() transport.DatagramAccelerationStatus {
	return p.status
}

func TestPathInfosProjectsDatagramAccelerationEvidence(t *testing.T) {
	local, _ := newMemoryPathPair()
	want := transport.DatagramAccelerationStatus{
		Mode: transport.DatagramAccelerationGSO, Cause: "probe_confirmed", ProbeGeneration: 9,
		BatchCalls: 7, BatchDatagrams: 42, GSOAttempts: 11, GSOSuperPackets: 10, GSOSegments: 80,
	}
	info := pathInfos(
		[]*pathSlot{{id: 3, conn: &accelerationMemoryPath{memoryPathConn: local, status: want}}},
		3, DefaultLimits().ProbeInterval,
	)
	if len(info) != 1 || info[0].DatagramAcceleration != want {
		t.Fatalf("acceleration projection=%+v want %+v", info, want)
	}
}

func TestBondRedistributesDeadPathHistory(t *testing.T) {
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{BondPinSize: 1}.Clamp())
	server := New(SideServer, flow, Limits{}.Clamp())
	defer client.Close()
	defer server.Close()
	targets := configureSymmetricLeafGroupRuntime(t, client, server, proto.GraphNodeKindBond, "path-1", "path-2")
	c1, s1 := newMemoryPathPair()
	c2, s2 := newMemoryPathPair()
	c1.dropWrites.Store(true)

	deadID := attachFixturePath(t, client, c1, transport.PathSpec{Transport: "memory", Address: "path-1"}, targets["path-1"])
	attachFixturePath(t, server, s1, transport.PathSpec{Transport: "memory", Address: "path-1"}, targets["path-1"])
	attachFixturePath(t, client, c2, transport.PathSpec{Transport: "memory", Address: "path-2"}, targets["path-2"])
	attachFixturePath(t, server, s2, transport.PathSpec{Transport: "memory", Address: "path-2"}, targets["path-2"])

	payload := []byte("lost-on-dead-bond-path")
	if _, err := client.SendData(payload); err != nil {
		t.Fatalf("SendData: %v", err)
	}
	if c1.DataWrites() != 1 || c2.DataWrites() != 0 {
		t.Fatalf("test did not route first DATA frame to dropped path: c1=%d c2=%d", c1.DataWrites(), c2.DataWrites())
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
	targets := configureSymmetricLeafGroupRuntime(t, client, server, proto.GraphNodeKindBond, "path-1", "path-2")
	c1, s1 := newMemoryPathPair()
	c2, s2 := newMemoryPathPair()

	deadID := attachFixturePath(t, client, c1, transport.PathSpec{Transport: "memory", Address: "path-1"}, targets["path-1"])
	attachFixturePath(t, server, s1, transport.PathSpec{Transport: "memory", Address: "path-1"}, targets["path-1"])
	attachFixturePath(t, client, c2, transport.PathSpec{Transport: "memory", Address: "path-2"}, targets["path-2"])
	attachFixturePath(t, server, s2, transport.PathSpec{Transport: "memory", Address: "path-2"}, targets["path-2"])

	payload := []byte("acked-bond-frame")
	if _, err := client.SendData(payload); err != nil {
		t.Fatalf("SendData: %v", err)
	}
	if c1.DataWrites() != 1 || c2.DataWrites() != 0 {
		t.Fatalf("test did not route first DATA frame to path 1: c1=%d c2=%d", c1.DataWrites(), c2.DataWrites())
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
	if got := c2.DataWrites(); got != 0 {
		t.Fatalf("acked DATA frame was redistributed to survivor: c2 writes=%d, want 0", got)
	}
}

func TestSelectorRedistributesUnackedFrameOnPathDeath(t *testing.T) {
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{}.Clamp())
	server := New(SideServer, flow, Limits{}.Clamp())
	defer client.Close()
	defer server.Close()
	targets := configureSymmetricLeafGroupRuntime(t, client, server, proto.GraphNodeKindSelector, "path-1", "path-2")

	c1, s1 := newMemoryPathPair()
	c2, s2 := newMemoryPathPair()
	c1.dropWrites.Store(true)

	deadID := attachFixturePath(t, client, c1, transport.PathSpec{Transport: "memory", Address: "path-1"}, targets["path-1"])
	attachFixturePath(t, server, s1, transport.PathSpec{Transport: "memory", Address: "path-1"}, targets["path-1"])
	attachFixturePath(t, client, c2, transport.PathSpec{Transport: "memory", Address: "path-2"}, targets["path-2"])
	attachFixturePath(t, server, s2, transport.PathSpec{Transport: "memory", Address: "path-2"}, targets["path-2"])

	payload := []byte("lost-on-dead-selector-path")
	if _, err := client.SendData(payload); err != nil {
		t.Fatalf("SendData: %v", err)
	}
	if c1.DataWrites() != 1 || c2.DataWrites() != 0 {
		t.Fatalf("test did not route first DATA frame to dropped active path: c1=%d c2=%d", c1.DataWrites(), c2.DataWrites())
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
			targets := configureSymmetricLeafGroupRuntime(t, client, server, graphKindForExecutionFixture(t, kind), "path-1", "path-2")
			c1, s1 := newMemoryPathPair()
			c2, s2 := newMemoryPathPair()
			c1.dropWrites.Store(true)
			removedID := attachFixturePath(t, client, c1, transport.PathSpec{Transport: "memory", Address: "path-1"}, targets["path-1"])
			attachFixturePath(t, server, s1, transport.PathSpec{Transport: "memory", Address: "path-1"}, targets["path-1"])
			attachFixturePath(t, client, c2, transport.PathSpec{Transport: "memory", Address: "path-2"}, targets["path-2"])
			attachFixturePath(t, server, s2, transport.PathSpec{Transport: "memory", Address: "path-2"}, targets["path-2"])

			payload := []byte("unacked-before-clean-remove")
			if _, err := client.SendData(payload); err != nil {
				t.Fatal(err)
			}
			if c1.DataWrites() != 1 || c2.DataWrites() != 0 {
				t.Fatalf("initial DATA route writes: removed=%d survivor=%d", c1.DataWrites(), c2.DataWrites())
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
			if got := c2.DataWrites(); got != 1 {
				t.Fatalf("surviving path DATA writes=%d, want one replay", got)
			}
			deadline = time.Now().Add(time.Second)
			dataIndex, retireIndex := -1, -1
			for time.Now().Before(deadline) {
				for index, header := range c2.FrameHeaders() {
					if header.Type == proto.FrameData && dataIndex < 0 {
						dataIndex = index
					}
					if header.Type == proto.FrameCtrl &&
						proto.CtrlCodeFromFlags(header.Flags) == proto.CtrlPathRetire && retireIndex < 0 {
						retireIndex = index
					}
				}
				if dataIndex >= 0 && retireIndex >= 0 {
					break
				}
				time.Sleep(time.Millisecond)
			}
			if dataIndex < 0 || retireIndex < 0 {
				t.Fatalf("missing replay/retirement publication: data=%d retire=%d headers=%+v", dataIndex, retireIndex, c2.FrameHeaders())
			}
			if dataIndex >= retireIndex {
				t.Fatalf("PATH_RETIRE overtook frozen DATA replay: data index=%d retire index=%d headers=%+v", dataIndex, retireIndex, c2.FrameHeaders())
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
	clientTargets := configureLeafSelectorRuntime(t, client, "path-1", "path-2")
	serverTargets := configureLeafSelectorRuntime(t, server, "path-1", "path-2")

	c1, s1 := newMemoryPathPair()
	c2, s2 := newMemoryPathPair()
	c1.dropWrites.Store(true)

	if _, err := client.AttachPathBound(c1, transport.PathSpec{Transport: "memory", Address: "path-1"}, PathBinding{
		LocalTXTargetID: clientTargets["path-1"], PeerTXTargetID: clientTargets["path-1"],
	}); err != nil {
		t.Fatalf("attach client path 1: %v", err)
	}
	if _, err := server.AttachPathBound(s1, transport.PathSpec{Transport: "memory", Address: "path-1"}, PathBinding{
		LocalTXTargetID: serverTargets["path-1"], PeerTXTargetID: serverTargets["path-1"],
	}); err != nil {
		t.Fatalf("attach server path 1: %v", err)
	}
	_, err := client.AttachPathBound(c2, transport.PathSpec{Transport: "memory", Address: "path-2"}, PathBinding{
		LocalTXTargetID: clientTargets["path-2"], PeerTXTargetID: clientTargets["path-2"],
	})
	if err != nil {
		t.Fatalf("attach client path 2: %v", err)
	}
	if _, err := server.AttachPathBound(s2, transport.PathSpec{Transport: "memory", Address: "path-2"}, PathBinding{
		LocalTXTargetID: serverTargets["path-2"], PeerTXTargetID: serverTargets["path-2"],
	}); err != nil {
		t.Fatalf("attach server path 2: %v", err)
	}

	payload := []byte("lost-before-explicit-migrate")
	if _, err := client.SendData(payload); err != nil {
		t.Fatalf("SendData: %v", err)
	}
	if err := client.SelectExplicitTarget(clientTargets["root"], clientTargets["path-2"], "explicit"); err != nil {
		t.Fatalf("SelectExplicitTarget: %v", err)
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
