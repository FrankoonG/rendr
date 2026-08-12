package engine

import (
	"bytes"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type tailReplayInterceptPath struct {
	transport.PathConn
	match         func([]byte) bool
	dropRemaining atomic.Int64
	dropAll       atomic.Bool
	attempts      atomic.Uint64
	active        atomic.Int32
	maxActive     atomic.Int32
	framesMu      sync.Mutex
	frames        [][]byte
}

func newTailReplayInterceptPath(path transport.PathConn, match func([]byte) bool, drop int64) *tailReplayInterceptPath {
	p := &tailReplayInterceptPath{PathConn: path, match: match}
	p.dropRemaining.Store(drop)
	return p
}

func (p *tailReplayInterceptPath) Write(frame []byte) (int, error) {
	if p.match == nil || !p.match(frame) {
		return p.PathConn.Write(frame)
	}
	active := p.active.Add(1)
	defer p.active.Add(-1)
	for {
		maximum := p.maxActive.Load()
		if active <= maximum || p.maxActive.CompareAndSwap(maximum, active) {
			break
		}
	}
	p.attempts.Add(1)
	p.framesMu.Lock()
	p.frames = append(p.frames, append([]byte(nil), frame...))
	p.framesMu.Unlock()
	if p.dropAll.Load() || p.consumeDrop() {
		return len(frame), nil
	}
	return p.PathConn.Write(frame)
}

func (p *tailReplayInterceptPath) consumeDrop() bool {
	for {
		remaining := p.dropRemaining.Load()
		if remaining <= 0 {
			return false
		}
		if p.dropRemaining.CompareAndSwap(remaining, remaining-1) {
			return true
		}
	}
}

func (p *tailReplayInterceptPath) frameSnapshot() [][]byte {
	p.framesMu.Lock()
	defer p.framesMu.Unlock()
	out := make([][]byte, len(p.frames))
	for i := range p.frames {
		out[i] = append([]byte(nil), p.frames[i]...)
	}
	return out
}

func isTailReplayData(frame []byte) bool {
	if len(frame) < proto.HeaderSize {
		return false
	}
	hdr, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	return err == nil && hdr.Type == proto.FrameData
}

func isTailReplayControl(code proto.CtrlCode) func([]byte) bool {
	return func(frame []byte) bool {
		if len(frame) < proto.HeaderSize {
			return false
		}
		hdr, err := proto.DecodeHeader(frame[:proto.HeaderSize])
		return err == nil && hdr.Type == proto.FrameCtrl && proto.CtrlCodeFromFlags(hdr.Flags) == code
	}
}

func configureFastTailReplay(e *Engine) {
	e.tailReplayInitialDelay = 5 * time.Millisecond
	e.tailReplayMaxBackoff = 20 * time.Millisecond
}

func TestTailReplayDefaultPacingIncludesObservedRTTAndJitter(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	path, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = peer.Close() })
	path.quality = transport.PathQuality{RTT: 400 * time.Millisecond, Jitter: 50 * time.Millisecond, At: time.Now()}
	pathID, err := e.AttachPath(path, transport.PathSpec{Transport: "memory", Address: "high-rtt"})
	if err != nil {
		t.Fatal(err)
	}
	e.pathsMu.RLock()
	slot := e.paths[pathID]
	e.pathsMu.RUnlock()
	storeQuality := func(quality transport.PathQuality) {
		slot.probeEvidence.Store(&pathProbeEvidence{
			generation: pathProbeGenerationForSlot(slot), firstIssued: quality.At, lastIssued: quality.At,
			lastSuccess: quality.At, quality: quality, issued: 1, succeeded: 1,
		})
	}
	storeQuality(path.quality)
	initial, maximum := e.tailReplayTiming()
	if initial != 900*time.Millisecond || maximum != defaultTailReplayMaxBackoff {
		t.Fatalf("tail replay timing=%s/%s want 900ms/%s", initial, maximum, defaultTailReplayMaxBackoff)
	}

	path.quality = transport.PathQuality{RTT: 3 * time.Second, Jitter: time.Second, At: time.Now()}
	storeQuality(path.quality)
	initial, maximum = e.tailReplayTiming()
	if initial != maximumTailReplayInitialDelay || maximum != maximumTailReplayInitialDelay {
		t.Fatalf("clamped tail replay timing=%s/%s want %s", initial, maximum, maximumTailReplayInitialDelay)
	}
}

func TestTailReplayArmingRespectsStreamAndPacketContracts(t *testing.T) {
	frame := func(frameType proto.FrameType) []byte {
		encoded := make([]byte, proto.HeaderSize)
		if err := (proto.Header{Version: proto.Version, Type: frameType, Seq: 0}).Encode(encoded); err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	armed := func(e *Engine) bool {
		e.replayMu.Lock()
		defer e.replayMu.Unlock()
		return e.tailReplay.armed
	}

	stream := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = stream.Close() })
	stream.armTailReplayForFrame(frame(proto.FrameData), 1)
	if armed(stream) {
		t.Fatal("reliable stream DATA armed speculative tail replay")
	}
	stream.armTailReplayForFrame(frame(proto.FrameCtrl), 1)
	if !armed(stream) {
		t.Fatal("stream control did not retain tail convergence")
	}

	packet := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	packet.SetPacketMode()
	t.Cleanup(func() { _ = packet.Close() })
	packet.armTailReplayForFrame(frame(proto.FrameData), 1)
	if !armed(packet) {
		t.Fatal("packet DATA lost tail repair")
	}
}

func attachTailReplayPair(t *testing.T, client, server *Engine, clientPath, serverPath transport.PathConn, name string) {
	t.Helper()
	if _, err := client.AttachPath(clientPath, transport.PathSpec{Transport: "memory", Address: name}); err != nil {
		t.Fatalf("attach client %s: %v", name, err)
	}
	if _, err := server.AttachPath(serverPath, transport.PathSpec{Transport: "memory", Address: name}); err != nil {
		t.Fatalf("attach server %s: %v", name, err)
	}
}

func requireExactTailReplay(t *testing.T, path *tailReplayInterceptPath) {
	t.Helper()
	frames := path.frameSnapshot()
	if len(frames) < 2 {
		t.Fatalf("matching frame attempts=%d want initial publication plus replay", len(frames))
	}
	for i := 1; i < len(frames); i++ {
		if !bytes.Equal(frames[0], frames[i]) {
			t.Fatalf("replay %d changed immutable frame bytes\nfirst=%x\nreplay=%x", i, frames[0], frames[i])
		}
	}
}

func TestTailReplayDeliversLoneSilentlyLostData(t *testing.T) {
	flow := NewClientFlowID()
	limits := Limits{MigrationBudget: time.Second}.Clamp()
	client := New(SideClient, flow, limits)
	server := New(SideServer, flow, limits)
	client.SetPacketMode()
	server.SetPacketMode()
	configureFastTailReplay(client)
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	clientBase, serverPath := newSequencerTestPathPair()
	dropper := newTailReplayInterceptPath(clientBase, isTailReplayData, 1)
	attachTailReplayPair(t, client, server, dropper, serverPath, "tail-data-loss")

	want := []byte("lone-final-data")
	if err := client.SendPacket(want); err != nil {
		t.Fatalf("SendPacket: %v", err)
	}
	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err := server.RecvPacket()
	if err != nil {
		t.Fatalf("RecvPacket after silent tail loss: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("payload=%q want=%q", got, want)
	}
	eventuallyEngine(t, time.Second, func() bool { return client.sendAckNext.Load() == 1 })
	requireExactTailReplay(t, dropper)
	if client.MigrationCount() != 0 || client.CloseErr() != nil {
		t.Fatalf("tail recovery fabricated migration/error: migrations=%d error=%v", client.MigrationCount(), client.CloseErr())
	}
}

func TestTailReplayDeliversLoneSilentlyLostBye(t *testing.T) {
	flow := NewClientFlowID()
	limits := Limits{MigrationBudget: time.Second}.Clamp()
	client := New(SideClient, flow, limits)
	server := New(SideServer, flow, limits)
	configureFastTailReplay(client)
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	clientBase, serverPath := newSequencerTestPathPair()
	dropper := newTailReplayInterceptPath(clientBase, isTailReplayControl(proto.CtrlBye), 1)
	attachTailReplayPair(t, client, server, dropper, serverPath, "tail-bye-loss")

	closeDone := make(chan error, 1)
	go func() { closeDone <- client.GracefulClose(proto.ByeNormal) }()
	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, err := server.Recv(buf)
		readDone <- err
	}()
	select {
	case err := <-readDone:
		if err != io.EOF {
			t.Fatalf("server Recv after replayed BYE=%v want EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("silently lost lone BYE did not converge to peer EOF")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("GracefulClose after BYE replay: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("GracefulClose did not receive cumulative terminal ACK")
	}
	requireExactTailReplay(t, dropper)
}

func TestTailReplayAckAdvancementCancelsRetries(t *testing.T) {
	flow := NewClientFlowID()
	limits := Limits{MigrationBudget: time.Second}.Clamp()
	client := New(SideClient, flow, limits)
	server := New(SideServer, flow, limits)
	client.SetPacketMode()
	server.SetPacketMode()
	configureFastTailReplay(client)
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	clientBase, serverPath := newSequencerTestPathPair()
	serverPath.dropFirstAck.Store(true)
	counter := newTailReplayInterceptPath(clientBase, isTailReplayData, 0)
	attachTailReplayPair(t, client, server, counter, serverPath, "tail-ack-cancel")

	if err := client.SendPacket([]byte("ack-cancellation")); err != nil {
		t.Fatal(err)
	}
	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := server.RecvPacket(); err != nil {
		t.Fatal(err)
	}
	eventuallyEngine(t, time.Second, func() bool { return counter.attempts.Load() >= 2 })

	server.recvMu.Lock()
	nextSeq, proof := server.expectedRecvSeq, server.recvProof
	server.recvMu.Unlock()
	server.sendAck(nextSeq, false, proof)
	eventuallyEngine(t, time.Second, func() bool { return client.sendAckNext.Load() == nextSeq })

	time.Sleep(2 * client.tailReplayMaxBackoff)
	settled := counter.attempts.Load()
	time.Sleep(4 * client.tailReplayMaxBackoff)
	if got := counter.attempts.Load(); got != settled {
		t.Fatalf("ACKed tail kept replaying: attempts %d -> %d", settled, got)
	}
	client.replayMu.Lock()
	armed := client.tailReplay.armed
	client.replayMu.Unlock()
	if armed {
		t.Fatal("ACKed tail retained an armed retry lease")
	}
	if stats := client.ReplayStats(); stats.FramesInUse != 0 || stats.AckNext != nextSeq {
		t.Fatalf("ACK cancellation retained replay credit: %+v", stats)
	}
}

func TestTailReplayLeaseIsBoundedAndSingleFlight(t *testing.T) {
	flow := NewClientFlowID()
	limits := Limits{MigrationBudget: 60 * time.Millisecond}.Clamp()
	client := New(SideClient, flow, limits)
	server := New(SideServer, flow, limits)
	client.SetPacketMode()
	server.SetPacketMode()
	configureFastTailReplay(client)
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	clientBase, serverPath := newSequencerTestPathPair()
	dropper := newTailReplayInterceptPath(clientBase, isTailReplayData, 0)
	dropper.dropAll.Store(true)
	attachTailReplayPair(t, client, server, dropper, serverPath, "tail-bounded")
	payload := []byte("bounded-tail")
	if err := client.SendPacket(payload); err != nil {
		t.Fatal(err)
	}
	eventuallyEngine(t, time.Second, func() bool { return dropper.attempts.Load() >= 2 })
	time.Sleep(2 * limits.MigrationBudget)
	settled := dropper.attempts.Load()
	time.Sleep(2 * client.tailReplayMaxBackoff)
	if got := dropper.attempts.Load(); got != settled {
		t.Fatalf("expired tail lease kept retrying: attempts %d -> %d", settled, got)
	}
	if settled > 16 {
		t.Fatalf("bounded lease issued %d attempts in %v", settled, limits.MigrationBudget)
	}
	if maximum := dropper.maxActive.Load(); maximum != 1 {
		t.Fatalf("tail replay sender cardinality=%d want exactly one", maximum)
	}
	if stats := client.ReplayStats(); stats.FramesInUse != 1 ||
		stats.BytesInUse != uint64(proto.HeaderSize+len(payload)) || stats.FramesHighWater != 1 {
		t.Fatalf("tail retries consumed additional replay credit: %+v", stats)
	}
	client.replayMu.Lock()
	armed := client.tailReplay.armed
	client.replayMu.Unlock()
	if armed {
		t.Fatal("expired tail retry lease remained armed")
	}
	if client.MigrationCount() != 0 || client.CloseErr() != nil || client.IsClosed() {
		t.Fatalf("silent retry expiry changed session state: migrations=%d error=%v closed=%t", client.MigrationCount(), client.CloseErr(), client.IsClosed())
	}
}

func TestTailReplayCloseCancelsLeaseAndIdleHasNoChurn(t *testing.T) {
	flow := NewClientFlowID()
	limits := Limits{MigrationBudget: time.Second}.Clamp()
	client := New(SideClient, flow, limits)
	server := New(SideServer, flow, limits)
	client.SetPacketMode()
	server.SetPacketMode()
	configureFastTailReplay(client)
	t.Cleanup(func() { _ = server.Close() })

	clientBase, serverPath := newSequencerTestPathPair()
	dropper := newTailReplayInterceptPath(clientBase, isTailReplayData, 0)
	dropper.dropAll.Store(true)
	attachTailReplayPair(t, client, server, dropper, serverPath, "tail-close")
	time.Sleep(4 * client.tailReplayInitialDelay)
	if got := dropper.attempts.Load(); got != 0 {
		t.Fatalf("idle engine emitted %d DATA attempts", got)
	}
	if err := client.SendPacket([]byte("close-tail")); err != nil {
		t.Fatal(err)
	}
	eventuallyEngine(t, time.Second, func() bool { return dropper.attempts.Load() >= 2 })
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-client.Closed():
	case <-time.After(time.Second):
		t.Fatal("Close did not quiesce tail replay worker")
	}
	settled := dropper.attempts.Load()
	time.Sleep(4 * client.tailReplayMaxBackoff)
	if got := dropper.attempts.Load(); got != settled {
		t.Fatalf("closed engine kept tail replaying: attempts %d -> %d", settled, got)
	}
	client.replayMu.Lock()
	armed := client.tailReplay.armed
	client.replayMu.Unlock()
	if armed {
		t.Fatal("Close retained tail replay lease")
	}
}

func TestTailReplayConvergesLoneSilentlyLostPathRetire(t *testing.T) {
	manifest, _ := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{MigrationBudget: time.Second}.Clamp())
	server := New(SideServer, flow, Limits{MigrationBudget: time.Second}.Clamp())
	configureFastTailReplay(client)
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	configureRecursivePair(t, client, server, manifest)

	clientA, serverA := newMemoryPathPair()
	dropper := newTailReplayInterceptPath(clientA, isTailReplayControl(proto.CtrlPathRetire), 1)
	attachRecursivePath(t, client, server, "a", dropper, serverA)
	clientB, serverBPath := newMemoryPathPair()
	attachRecursivePath(t, client, server, "b", clientB, serverBPath)
	clientBID := pathIDByName(t, client, "b")
	serverBID := pathIDByName(t, server, "b")

	if err := client.RemovePath(clientBID); err != nil {
		t.Fatal(err)
	}
	// No later DATA or control frame is published. The tail lease is the only
	// event capable of exposing the silently lost PATH_RETIRE to the peer.
	waitPathDetached(t, server, serverBID)
	requireExactTailReplay(t, dropper)
	if client.CloseErr() != nil || server.CloseErr() != nil {
		t.Fatalf("PATH_RETIRE tail recovery closed session: client=%v server=%v", client.CloseErr(), server.CloseErr())
	}
}
