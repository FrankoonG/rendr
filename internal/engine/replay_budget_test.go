package engine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type replayBudgetPath struct {
	closed chan struct{}
	once   sync.Once
}

func newReplayBudgetPath() *replayBudgetPath {
	return &replayBudgetPath{closed: make(chan struct{})}
}

func (p *replayBudgetPath) Read([]byte) (int, error) {
	<-p.closed
	return 0, net.ErrClosed
}

func (p *replayBudgetPath) Write(payload []byte) (int, error) {
	select {
	case <-p.closed:
		return 0, net.ErrClosed
	default:
		return len(payload), nil
	}
}

func (p *replayBudgetPath) Close() error {
	p.once.Do(func() { close(p.closed) })
	return nil
}

func (p *replayBudgetPath) Quality() transport.PathQuality            { return transport.PathQuality{} }
func (p *replayBudgetPath) OnDeath(func(transport.DeathCause, error)) {}
func (p *replayBudgetPath) LocalAddr() string                         { return "replay-budget-local" }
func (p *replayBudgetPath) RemoteAddr() string                        { return "replay-budget-remote" }

func TestReplayBudgetPublishesBeyondLegacyFrameCliff(t *testing.T) {
	const legacyFrameLimit = 256
	if sendHistoryWindow <= legacyFrameLimit {
		t.Fatalf("replay frame budget=%d did not move beyond legacy cliff %d", sendHistoryWindow, legacyFrameLimit)
	}
	e := New(SideClient, [16]byte{0xb1}, Limits{})
	defer e.Close()
	ids := configureLeafSelectorRuntime(t, e, "path")
	attachFixturePath(t, e, newReplayBudgetPath(), transport.PathSpec{Transport: "budget", Address: "path"}, ids["path"])
	for sequence := 0; sequence <= legacyFrameLimit; sequence++ {
		if err := e.SendPacket([]byte{byte(sequence)}); err != nil {
			t.Fatalf("publish frame %d: %v", sequence, err)
		}
	}
	e.sendHistMu.Lock()
	entries := len(e.sendHist.entries)
	bytes := e.sendHist.reservedBytes
	e.sendHistMu.Unlock()
	if entries != legacyFrameLimit+1 || bytes != entries*(proto.HeaderSize+1) {
		t.Fatalf("replay ledger entries/bytes=%d/%d want %d/%d", entries, bytes,
			legacyFrameLimit+1, (legacyFrameLimit+1)*(proto.HeaderSize+1))
	}
}

const (
	legacyReplayFrameLimit = 256
	highBDPReplayFrames    = 4 * legacyReplayFrameLimit
	highBDPPayloadSize     = 1024
)

func TestReplayBudgetRecoversHighBDPFlightAfterPathDeath(t *testing.T) {
	flow := NewClientFlowID()
	limits := Limits{MigrationBudget: 3 * time.Second}.Clamp()
	client := New(SideClient, flow, limits)
	server := New(SideServer, flow, limits)
	ids := configureSymmetricLeafGroupRuntime(t, client, server, proto.GraphNodeKindSelector, "high-bdp", "survivor")
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	delayedClient, delayedServer := newSequencerTestPathPair()
	survivorClient, survivorServer := newSequencerTestPathPair()
	// Successful writes are held in the simulated path BDP and never reach the
	// peer. Killing the path discards that entire unacknowledged flight.
	delayedClient.dropWrites.Store(true)
	deadClientID := attachFixturePath(t, client, delayedClient,
		transport.PathSpec{Transport: "memory", Address: "high-bdp"}, ids["high-bdp"])
	deadServerID := attachFixturePath(t, server, delayedServer,
		transport.PathSpec{Transport: "memory", Address: "high-bdp"}, ids["high-bdp"])
	attachFixturePath(t, client, survivorClient,
		transport.PathSpec{Transport: "memory", Address: "survivor"}, ids["survivor"])
	attachFixturePath(t, server, survivorServer,
		transport.PathSpec{Transport: "memory", Address: "survivor"}, ids["survivor"])

	want := make([]byte, highBDPReplayFrames*highBDPPayloadSize)
	for frameIndex := 0; frameIndex < highBDPReplayFrames; frameIndex++ {
		frame := want[frameIndex*highBDPPayloadSize : (frameIndex+1)*highBDPPayloadSize]
		binary.BigEndian.PutUint32(frame, uint32(frameIndex))
		for offset := 4; offset < len(frame); offset++ {
			frame[offset] = byte(frameIndex*31 + offset)
		}
	}

	sendDone := make(chan error, 1)
	go func() {
		for frameIndex := 0; frameIndex < highBDPReplayFrames; frameIndex++ {
			frame := want[frameIndex*highBDPPayloadSize : (frameIndex+1)*highBDPPayloadSize]
			if _, err := client.SendData(frame); err != nil {
				sendDone <- err
				return
			}
		}
		sendDone <- nil
	}()

	select {
	case err := <-sendDone:
		if err != nil {
			t.Fatalf("publish high-BDP flight: %v", err)
		}
	case <-time.After(2 * time.Second):
		delayedClient.Fail(errors.New("release blocked high-BDP writer"))
		delayedServer.Fail(errors.New("release blocked high-BDP peer"))
		t.Fatalf("sender stalled at %d writes before exceeding the legacy %d-frame replay cliff",
			delayedClient.writes.Load(), legacyReplayFrameLimit)
	}

	client.sendHistMu.Lock()
	applicationFrames := 0
	for _, entry := range client.sendHist.entries {
		if entry.application {
			applicationFrames++
		}
	}
	replayBytes := client.sendHist.reservedBytes
	client.sendHistMu.Unlock()
	if applicationFrames != highBDPReplayFrames || applicationFrames <= legacyReplayFrameLimit {
		t.Fatalf("unacknowledged application frames=%d, want %d and >%d",
			applicationFrames, highBDPReplayFrames, legacyReplayFrameLimit)
	}
	wantReplayBytes := highBDPReplayFrames * (proto.HeaderSize + highBDPPayloadSize)
	if replayBytes != wantReplayBytes {
		t.Fatalf("immutable replay bytes=%d, want %d", replayBytes, wantReplayBytes)
	}
	if ackNext := client.sendAckNext.Load(); ackNext != 0 {
		t.Fatalf("cumulative ACK advanced to %d before path death, want 0", ackNext)
	}

	pathDeath := errors.New("injected high-BDP path death")
	delayedClient.Fail(pathDeath)
	delayedServer.Fail(pathDeath)
	waitPathDetached(t, client, deadClientID)
	waitPathDetached(t, server, deadServerID)

	deadline := time.Now().Add(3 * time.Second)
	var expected uint64
	var queued int
	for {
		server.recvMu.Lock()
		expected = server.expectedRecvSeq
		queued = len(server.recvQueue)
		server.recvMu.Unlock()
		if expected+uint64(queued) >= highBDPReplayFrames {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("survivor did not recover replay floor: expected=%d queued=%d survivor writes=%d",
				expected, queued, survivorClient.writes.Load())
		}
		time.Sleep(time.Millisecond)
	}
	if expected == 0 {
		t.Fatal("replay omitted sequence zero and left the receive floor stranded")
	}
	if queued >= recvReorderWindowLimit {
		t.Fatalf("replay queue reached fatal reorder limit: queued=%d limit=%d", queued, recvReorderWindowLimit)
	}
	if survivorClient.writes.Load() < highBDPReplayFrames {
		t.Fatalf("survivor carried %d writes, want at least %d replayed frames",
			survivorClient.writes.Load(), highBDPReplayFrames)
	}

	if err := server.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(&Conn{E: server}, got); err != nil {
		t.Fatalf("read replayed high-BDP flight: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("replayed high-BDP flight was missing, duplicated, or reordered")
	}

	deadline = time.Now().Add(3 * time.Second)
	for client.sendAckNext.Load() < highBDPReplayFrames && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if ackNext := client.sendAckNext.Load(); ackNext < highBDPReplayFrames {
		t.Fatalf("survivor ACK frontier=%d, want at least %d", ackNext, highBDPReplayFrames)
	}
	if err := server.CloseErr(); err != nil {
		t.Fatalf("receiver closed during bounded replay: %v", err)
	}
}

func TestReplayBudgetStaysBelowFatalReceiveWindow(t *testing.T) {
	maxSequencedFlight := sendHistoryWindow + sendControlReserve + 1
	if maxSequencedFlight >= recvReorderWindowLimit {
		t.Fatalf("maximum replay flight=%d can reach fatal receive window=%d",
			maxSequencedFlight, recvReorderWindowLimit)
	}
	if sendHistoryWindow > packetRecvWindowBits {
		t.Fatalf("packet replay flight=%d exceeds receive bitmap=%d", sendHistoryWindow, packetRecvWindowBits)
	}
}

func TestReplayByteCreditBlocksAndWakesWithinHardBound(t *testing.T) {
	e := New(SideClient, [16]byte{0xb2}, Limits{})
	defer e.Close()
	if err := e.acquireSendSlot(false, sendHistoryByteLimit); err != nil {
		t.Fatal(err)
	}
	assertReplayStats(t, e.ReplayStats(), 1, sendHistoryByteLimit, 1, sendHistoryByteLimit)
	done := make(chan error, 1)
	go func() { done <- e.acquireSendSlot(false, 1) }()
	assertReplayCreditBlocked(t, done)
	waitReplayWaiter(t, e, 1)
	stats := e.ReplayStats()
	if stats.FramesInUse != 2 || stats.BytesInUse != sendHistoryByteLimit || stats.BackpressureEvents != 1 {
		t.Fatalf("blocked byte-credit stats=%+v", stats)
	}
	e.releaseSendSlot(false, sendHistoryByteLimit)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("byte-credit waiter did not wake after release")
	}
	stats = e.ReplayStats()
	if stats.FramesInUse != 1 || stats.BytesInUse != 1 || stats.FramesHighWater != 2 ||
		stats.BytesHighWater != sendHistoryByteLimit || stats.CreditWaiters != 0 {
		t.Fatalf("released byte-credit stats=%+v", stats)
	}
	e.releaseSendSlot(false, 1)
	assertReplayStats(t, e.ReplayStats(), 0, 0, 2, sendHistoryByteLimit)
}

func TestReplayFrameCreditBlocksAndWakesWithinHardBound(t *testing.T) {
	e := New(SideClient, [16]byte{0xb3}, Limits{})
	defer e.Close()
	for index := 0; index < sendHistoryWindow; index++ {
		if err := e.acquireSendSlot(false, 1); err != nil {
			t.Fatalf("acquire frame credit %d: %v", index, err)
		}
	}
	assertReplayStats(t, e.ReplayStats(), sendHistoryWindow, sendHistoryWindow, sendHistoryWindow, sendHistoryWindow)
	done := make(chan error, 1)
	go func() { done <- e.acquireSendSlot(false, 1) }()
	assertReplayCreditBlocked(t, done)
	waitReplayWaiter(t, e, 1)
	stats := e.ReplayStats()
	if stats.FramesInUse != sendHistoryWindow || stats.FramesHighWater != sendHistoryWindow ||
		stats.CreditWaiters != 1 || stats.BackpressureEvents != 1 {
		t.Fatalf("blocked frame-credit stats=%+v", stats)
	}
	e.releaseSendSlot(false, 1)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("frame-credit waiter did not wake after release")
	}
	for index := 0; index < sendHistoryWindow; index++ {
		e.releaseSendSlot(false, 1)
	}
	assertReplayStats(t, e.ReplayStats(), 0, 0, sendHistoryWindow, sendHistoryWindow)
}

func TestRollbackReservedFrameReturnsFrameAndByteCredits(t *testing.T) {
	e := New(SideClient, [16]byte{0xb4}, Limits{})
	defer e.Close()
	frame := make([]byte, proto.HeaderSize+1)
	if err := (proto.Header{Version: proto.Version, Type: proto.FrameData, Seq: 0}).Encode(frame[:proto.HeaderSize]); err != nil {
		t.Fatal(err)
	}
	if err := e.acquireSendSlot(false, len(frame)); err != nil {
		t.Fatal(err)
	}
	if err := e.reserveSendFrame(frame); err != nil {
		t.Fatal(err)
	}
	if !e.rollbackReservedSendFrame(0) {
		t.Fatal("reserved frame did not roll back")
	}
	e.sendHistMu.Lock()
	entries, bytes := len(e.sendHist.entries), e.sendHist.reservedBytes
	e.sendHistMu.Unlock()
	if entries != 0 || bytes != 0 || len(e.sendSlots) != 0 {
		t.Fatalf("rollback retained ledger/byte/frame credits=%d/%d/%d", entries, bytes, len(e.sendSlots))
	}
}

func assertReplayCreditBlocked(t testing.TB, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("credit acquisition completed before release: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
}

func waitReplayWaiter(t testing.TB, e *Engine, want uint64) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if e.ReplayStats().CreditWaiters == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("credit waiters=%d want %d", e.ReplayStats().CreditWaiters, want)
}

func assertReplayStats(t testing.TB, stats ReplayStats, frames, bytes, frameHWM, byteHWM int) {
	t.Helper()
	if stats.FrameLimit != sendHistoryWindow || stats.ByteLimit != sendHistoryByteLimit ||
		stats.FramesInUse != uint64(frames) || stats.BytesInUse != uint64(bytes) ||
		stats.FramesHighWater != uint64(frameHWM) || stats.BytesHighWater != uint64(byteHWM) ||
		stats.FramesInUse > stats.FrameLimit || stats.BytesInUse > stats.ByteLimit || stats.Generation == 0 && frames != 0 {
		t.Fatalf("replay stats=%+v want frames/bytes/hwm=%d/%d/%d/%d", stats, frames, bytes, frameHWM, byteHWM)
	}
}
