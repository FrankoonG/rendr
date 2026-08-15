package engine

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type terminalReplayClosePath struct {
	owner *Engine

	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error

	byeStarted   chan struct{}
	byeOnce      sync.Once
	writeRelease <-chan struct{}

	closeStarted chan struct{}
	closeStart   sync.Once
	closeRelease <-chan struct{}

	deathMu sync.Mutex
	deathFn func(transport.DeathCause, error)
}

func newTerminalReplayClosePath() *terminalReplayClosePath {
	return &terminalReplayClosePath{
		closed:       make(chan struct{}),
		byeStarted:   make(chan struct{}),
		closeStarted: make(chan struct{}),
	}
}

func (p *terminalReplayClosePath) Read([]byte) (int, error) {
	<-p.closed
	return 0, net.ErrClosed
}

func (p *terminalReplayClosePath) Write(frame []byte) (int, error) {
	if len(frame) < proto.HeaderSize {
		return 0, proto.ErrBadHeader
	}
	header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	if err != nil {
		return 0, err
	}
	if header.Type == proto.FrameCtrl && proto.CtrlCodeFromFlags(header.Flags) == proto.CtrlBye {
		p.byeOnce.Do(func() { close(p.byeStarted) })
		if p.writeRelease != nil {
			<-p.writeRelease
		}
		if p.owner != nil {
			closeLinearizationAckThrough(p.owner, header.Seq+1)
		}
	}
	select {
	case <-p.closed:
		return 0, net.ErrClosed
	default:
		return len(frame), nil
	}
}

func (p *terminalReplayClosePath) Close() error {
	p.closeStart.Do(func() { close(p.closeStarted) })
	if p.closeRelease != nil {
		<-p.closeRelease
	}
	p.closeOnce.Do(func() { close(p.closed) })
	return p.closeErr
}

func (*terminalReplayClosePath) Quality() transport.PathQuality { return transport.PathQuality{} }

func (p *terminalReplayClosePath) OnDeath(fn func(transport.DeathCause, error)) {
	p.deathMu.Lock()
	p.deathFn = fn
	p.deathMu.Unlock()
}

func (*terminalReplayClosePath) LocalAddr() string  { return "terminal-replay-local" }
func (*terminalReplayClosePath) RemoteAddr() string { return "terminal-replay-remote" }

func attachTerminalReplayClosePath(t *testing.T, e *Engine, path *terminalReplayClosePath, targetID proto.TargetID) {
	t.Helper()
	path.owner = e
	attachFixturePath(t, e, path, transport.PathSpec{Transport: "test", Address: "terminal-replay"}, targetID)
}

func TestConcurrentGracefulAndCloseWaitForTeardownAndShareCarrierError(t *testing.T) {
	carrierErr := errors.New("injected carrier close failure")
	writeRelease := make(chan struct{})
	closeRelease := make(chan struct{})
	e := New(SideClient, [16]byte{0xd1}, Limits{MigrationBudget: time.Second}.Clamp())
	targets := configureLeafSelectorRuntime(t, e, "path")
	path := newTerminalReplayClosePath()
	path.closeErr = carrierErr
	path.writeRelease = writeRelease
	path.closeRelease = closeRelease
	attachTerminalReplayClosePath(t, e, path, targets["path"])

	gracefulDone := make(chan error, 1)
	go func() { gracefulDone <- e.GracefulClose(proto.ByeNormal) }()
	waitCloseLinearizationSignal(t, path.byeStarted, time.Second, "concurrent terminal BYE")

	closeDone := make(chan error, 1)
	go func() { closeDone <- e.Close() }()
	waitCloseLinearizationSignal(t, path.closeStarted, time.Second, "carrier Close")
	select {
	case err := <-gracefulDone:
		close(writeRelease)
		close(closeRelease)
		t.Fatalf("GracefulClose returned before carrier teardown completed: %v", err)
	case <-time.After(25 * time.Millisecond):
	}

	close(writeRelease)
	close(closeRelease)
	for name, result := range map[string]<-chan error{
		"Close":         closeDone,
		"GracefulClose": gracefulDone,
	} {
		select {
		case err := <-result:
			if !errors.Is(err, carrierErr) {
				t.Fatalf("%s error=%v, want carrier error", name, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s did not finish after carrier teardown", name)
		}
	}
	select {
	case <-e.Closed():
	default:
		t.Fatal("successful teardown result became visible before Closed")
	}
}

func TestConcurrentGracefulClosePreservesTeardownTimeout(t *testing.T) {
	writeRelease := make(chan struct{})
	closeRelease := make(chan struct{})
	e := New(SideClient, [16]byte{0xd2}, Limits{MigrationBudget: time.Second}.Clamp())
	targets := configureLeafSelectorRuntime(t, e, "path")
	path := newTerminalReplayClosePath()
	path.writeRelease = writeRelease
	path.closeRelease = closeRelease
	attachTerminalReplayClosePath(t, e, path, targets["path"])

	gracefulDone := make(chan error, 1)
	go func() { gracefulDone <- e.GracefulClose(proto.ByeNormal) }()
	waitCloseLinearizationSignal(t, path.byeStarted, time.Second, "timeout terminal BYE")
	closeDone := make(chan error, 1)
	go func() { closeDone <- e.Close() }()
	waitCloseLinearizationSignal(t, path.closeStarted, time.Second, "blocked carrier Close")
	close(writeRelease)

	for name, result := range map[string]<-chan error{
		"Close":         closeDone,
		"GracefulClose": gracefulDone,
	} {
		select {
		case err := <-result:
			if err == nil || !strings.Contains(err.Error(), "shutdown did not quiesce") {
				close(closeRelease)
				t.Fatalf("%s error=%v, want teardown timeout", name, err)
			}
		case <-time.After(pathCloseTimeout + time.Second):
			close(closeRelease)
			t.Fatalf("%s did not return its bounded teardown timeout", name)
		}
	}
	close(closeRelease)
	select {
	case <-e.Closed():
	case <-time.After(time.Second):
		t.Fatal("timed-out teardown did not eventually quiesce")
	}
}

func TestPeerEOFFollowedByImmediateAppCloseRetriesDroppedTerminalACK(t *testing.T) {
	flow := [16]byte{0xd3}
	limits := Limits{MigrationBudget: time.Second}.Clamp()
	client := New(SideClient, flow, limits)
	server := New(SideServer, flow, limits)
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	targets := configureSymmetricLeafGroupRuntime(t, client, server, proto.GraphNodeKindSelector, "path")

	clientPath, serverPath := newSequencerTestPathPair()
	serverPath.dropFirstAck.Store(true)
	attachFixturePath(t, client, clientPath, transport.PathSpec{Transport: "memory", Address: "peer-eof-immediate-close"}, targets["path"])
	attachFixturePath(t, server, serverPath, transport.PathSpec{Transport: "memory", Address: "peer-eof-immediate-close"}, targets["path"])

	clientClose := make(chan error, 1)
	go func() { clientClose <- client.GracefulClose(proto.ByeNormal) }()
	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Recv(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("server Recv=%v, want peer EOF", err)
	}
	if _, err := server.SendData([]byte("must-not-follow-bye")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("server write after peer BYE=%v, want closed write direction", err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("immediate app Close after peer EOF: %v", err)
	}
	select {
	case err := <-clientClose:
		if err != nil {
			t.Fatalf("peer close did not recover dropped terminal ACK: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("peer close stranded after first terminal ACK was dropped")
	}
	if !serverPath.droppedAck.Load() {
		t.Fatal("test did not drop the first terminal ACK")
	}
	if got := serverPath.ackWrites.Load(); got < 2 {
		t.Fatalf("terminal ACK attempts=%d, want initial plus close-preserved retry", got)
	}
}

func setTerminalReplayZombieLeftForTrip(e *Engine) {
	e.zombieMu.Lock()
	e.zombieLeft = 1
	e.zombieLastMig = time.Time{}
	e.zombieMu.Unlock()
}

func TestZombieTicketCommitSerializesCompetingTerminalCause(t *testing.T) {
	e := New(SideClient, [16]byte{0xd4}, Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	setTerminalReplayZombieLeftForTrip(e)
	ticket := e.accountMigration()
	commitEntered := make(chan struct{})
	commitRelease := make(chan struct{})
	e.zombieAtCommit = func() {
		close(commitEntered)
		<-commitRelease
	}

	tripDone := make(chan bool, 1)
	go func() { tripDone <- e.tripZombie(ticket) }()
	waitCloseLinearizationSignal(t, commitEntered, time.Second, "zombie terminal commit")
	competingDone := make(chan struct{})
	go func() {
		e.setCloseErr(ErrPeerProtocol)
		close(competingDone)
	}()
	select {
	case <-competingDone:
		close(commitRelease)
		t.Fatal("competing terminal cause published inside zombie commit")
	case <-time.After(25 * time.Millisecond):
	}
	close(commitRelease)
	if committed := <-tripDone; !committed {
		t.Fatal("current zombie ticket did not commit")
	}
	select {
	case <-competingDone:
	case <-time.After(time.Second):
		t.Fatal("competing terminal publisher remained blocked")
	}
	if err := e.CloseErr(); !errors.Is(err, ErrZombie) || errors.Is(err, ErrPeerProtocol) {
		t.Fatalf("terminal cause=%v, want committed ErrZombie", err)
	}
}

func TestReplayStatsCannotMixOccupancyAndACKGenerations(t *testing.T) {
	e := New(SideClient, [16]byte{0xd5}, Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	targets := configureLeafSelectorRuntime(t, e, "path")
	path := newCloseLinearizationPath()
	attachCloseLinearizationPath(t, e, path, targets["path"])
	if err := e.SendPacket([]byte("snapshot")); err != nil {
		t.Fatal(err)
	}

	snapshotCaptured := make(chan struct{})
	releaseSnapshot := make(chan struct{})
	e.replayStatsAfterCreditSnapshot = func() {
		close(snapshotCaptured)
		<-releaseSnapshot
	}
	statsDone := make(chan ReplayStats, 1)
	go func() { statsDone <- e.ReplayStats() }()
	waitCloseLinearizationSignal(t, snapshotCaptured, time.Second, "replay stats credit snapshot")
	if !closeLinearizationAckThrough(e, 1) {
		close(releaseSnapshot)
		t.Fatal("could not advance ACK generation during snapshot")
	}
	close(releaseSnapshot)
	stats := <-statsDone
	if stats.PublishedNext < stats.AckNext {
		t.Fatalf("replay stats regressed frontier: %+v", stats)
	}
	if got, want := stats.FramesInUse, stats.PublishedNext-stats.AckNext; got != want {
		t.Fatalf("mixed replay generations: stats=%+v frames=%d want=%d", stats, got, want)
	}
}

func TestCloseReleasesReplayPayloadCreditsAndWakesWaiters(t *testing.T) {
	e := New(SideClient, [16]byte{0xd6}, Limits{}.Clamp())
	targets := configureLeafSelectorRuntime(t, e, "path")
	path := newReplayBudgetPath()
	attachFixturePath(t, e, path, transport.PathSpec{Transport: "test", Address: "close-replay"}, targets["path"])
	payload := bytes.Repeat([]byte{0x6d}, 1024)
	if _, err := e.SendData(payload); err != nil {
		t.Fatal(err)
	}
	used := int(e.ReplayStats().BytesInUse)
	if err := e.acquireSendSlot(false, sendHistoryByteLimit-used); err != nil {
		t.Fatal(err)
	}
	waiter := make(chan error, 1)
	go func() { waiter <- e.acquireSendSlot(false, 1) }()
	waitReplayWaiter(t, e, 1)

	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-waiter:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("credit waiter error=%v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not wake replay-credit waiter")
	}
	stats := e.ReplayStats()
	if stats.FramesInUse != 0 || stats.BytesInUse != 0 || stats.CreditWaiters != 0 {
		t.Fatalf("Close retained replay credits: %+v", stats)
	}
	e.sendHistMu.Lock()
	entries := e.sendHist.entries
	e.sendHistMu.Unlock()
	if entries != nil || len(e.sendSlots) != 0 || len(e.sendControlSlots) != 0 {
		t.Fatalf("Close retained replay payload/slots: entries=%d frame-slots=%d control-slots=%d",
			len(entries), len(e.sendSlots), len(e.sendControlSlots))
	}

	// Exercise the token handoff itself, not only a byte-credit waiter. Close
	// and release share sendHistMu, so neither side may drain a channel token
	// after the other has committed to a blocking receive.
	for iteration := range 500 {
		candidate := New(SideClient, [16]byte{0xd6, byte(iteration)}, Limits{}.Clamp())
		control := iteration%2 != 0
		if err := candidate.acquireSendSlot(control, 1); err != nil {
			t.Fatalf("iteration %d acquire: %v", iteration, err)
		}
		start := make(chan struct{})
		released := make(chan struct{})
		closed := make(chan error, 1)
		go func() {
			<-start
			candidate.releaseSendSlot(control, 1)
			close(released)
		}()
		go func() {
			<-start
			closed <- candidate.Close()
		}()
		close(start)
		select {
		case <-released:
		case <-time.After(time.Second):
			t.Fatalf("iteration %d replay token release blocked across Close", iteration)
		}
		select {
		case err := <-closed:
			if err != nil {
				t.Fatalf("iteration %d Close: %v", iteration, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("iteration %d Close blocked across replay token release", iteration)
		}
	}
}

type retiredCloseErrorPath struct {
	transport.PathConn
	err  error
	done chan struct{}
	once sync.Once
}

func (p *retiredCloseErrorPath) Close() error {
	err := p.PathConn.Close()
	p.once.Do(func() { close(p.done) })
	return errors.Join(p.err, err)
}

type terminalReplayRecordingPath struct {
	*sequencerTestPath

	mu      sync.Mutex
	headers []proto.Header
}

func (p *terminalReplayRecordingPath) Write(frame []byte) (int, error) {
	if len(frame) >= proto.HeaderSize {
		if header, err := proto.DecodeHeader(frame[:proto.HeaderSize]); err == nil {
			p.mu.Lock()
			p.headers = append(p.headers, header)
			p.mu.Unlock()
		}
	}
	return p.sequencerTestPath.Write(frame)
}

func (p *terminalReplayRecordingPath) streamFINSequences() []uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	var sequences []uint64
	for _, header := range p.headers {
		if header.Type == proto.FrameCtrl && proto.CtrlCodeFromFlags(header.Flags) == proto.CtrlStreamFin {
			sequences = append(sequences, header.Seq)
		}
	}
	return sequences
}

func TestRetiredPathCloseErrorIsReportedBySessionClose(t *testing.T) {
	retiredErr := errors.New("injected retired path close failure")
	e := New(SideClient, [16]byte{0xd7}, Limits{}.Clamp())
	retiredBase, retiredPeer := newMemoryPathPair()
	defer retiredPeer.Close()
	retired := &retiredCloseErrorPath{PathConn: retiredBase, err: retiredErr, done: make(chan struct{})}
	retiredID, err := e.AttachPath(retired, transport.PathSpec{Transport: "test", Address: "retired-error"})
	if err != nil {
		t.Fatal(err)
	}
	survivor, survivorPeer := newMemoryPathPair()
	defer survivorPeer.Close()
	if _, err := e.AttachPath(survivor, transport.PathSpec{Transport: "test", Address: "survivor"}); err != nil {
		t.Fatal(err)
	}
	if err := e.RemovePath(retiredID); err != nil {
		t.Fatal(err)
	}
	waitCloseLinearizationSignal(t, retired.done, time.Second, "retired carrier Close")
	if err := e.Close(); !errors.Is(err, retiredErr) {
		t.Fatalf("session Close error=%v, want retired carrier error", err)
	}
}

func TestStreamFINReplaysAcrossCarrierFailureExactlyOnce(t *testing.T) {
	flow := [16]byte{0xd8}
	limits := Limits{MigrationBudget: 2 * time.Second}.Clamp()
	client := New(SideClient, flow, limits)
	server := New(SideServer, flow, limits)
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	targets := configureSymmetricLeafGroupRuntime(t, client, server, proto.GraphNodeKindSelector, "fin-failure", "fin-survivor")

	failedClientBase, failedServer := newSequencerTestPathPair()
	survivorClientBase, survivorServer := newSequencerTestPathPair()
	failedClient := &terminalReplayRecordingPath{sequencerTestPath: failedClientBase}
	survivorClient := &terminalReplayRecordingPath{sequencerTestPath: survivorClientBase}
	failedClient.dieFirstWrite.Store(true)
	failedClientID := attachFixturePath(t, client, failedClient, transport.PathSpec{Transport: "memory", Address: "fin-failure"}, targets["fin-failure"])
	failedServerID := attachFixturePath(t, server, failedServer, transport.PathSpec{Transport: "memory", Address: "fin-failure"}, targets["fin-failure"])
	attachFixturePath(t, client, survivorClient, transport.PathSpec{Transport: "memory", Address: "fin-survivor"}, targets["fin-survivor"])
	attachFixturePath(t, server, survivorServer, transport.PathSpec{Transport: "memory", Address: "fin-survivor"}, targets["fin-survivor"])

	if err := client.SendStreamFin(); err != nil {
		t.Fatalf("SendStreamFin across path death: %v", err)
	}
	waitPathDetached(t, client, failedClientID)
	failedServer.Fail(errors.New("retire failed FIN peer path"))
	waitPathDetached(t, server, failedServerID)
	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Recv(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("replayed FIN Recv=%v, want EOF", err)
	}
	failedFINs := failedClient.streamFINSequences()
	survivorFINs := survivorClient.streamFINSequences()
	if len(failedFINs) == 0 || len(survivorFINs) == 0 {
		t.Fatalf("FIN attempts failed/survivor=%v/%v, want both carriers exercised", failedFINs, survivorFINs)
	}
	finSequence := failedFINs[0]
	for _, attempts := range [][]uint64{failedFINs, survivorFINs} {
		for _, sequence := range attempts {
			if sequence != finSequence {
				t.Fatalf("FIN attempts failed/survivor=%v/%v, want one unique sequence", failedFINs, survivorFINs)
			}
		}
	}
	if err := client.SendStreamFin(); err != nil {
		t.Fatalf("idempotent SendStreamFin: %v", err)
	}
	if failedClient.writes.Load() == 0 || survivorClient.writes.Load() == 0 {
		t.Fatalf("FIN dispatches failed/survivor=%d/%d, want both carriers exercised",
			failedClient.writes.Load(), survivorClient.writes.Load())
	}

	response := []byte("reverse-after-replayed-fin")
	if _, err := server.SendData(response); err != nil {
		t.Fatalf("reverse write after replayed FIN: %v", err)
	}
	if err := server.SendStreamFin(); err != nil {
		t.Fatalf("reverse FIN: %v", err)
	}
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(&Conn{E: client})
	if err != nil {
		t.Fatalf("reverse read after replayed FIN: %v", err)
	}
	if !bytes.Equal(got, response) {
		t.Fatalf("reverse payload=%q want=%q", got, response)
	}
}

func TestStreamFINIdempotenceHasOneLogicalPublication(t *testing.T) {
	e := New(SideClient, [16]byte{0xd9}, Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	targets := configureLeafSelectorRuntime(t, e, "fin")
	path := newLifecycleHealthyPath()
	attachFixturePath(t, e, path, transport.PathSpec{Transport: "memory", Address: "fin"}, targets["fin"])

	if err := e.SendStreamFin(); err != nil {
		t.Fatal(err)
	}
	e.sendHistMu.Lock()
	publications := streamFINLedgerSequences(e.sendHist.entries)
	e.sendHistMu.Unlock()
	if len(publications) != 1 {
		t.Fatalf("logical FIN publications=%v want exactly one", publications)
	}
	sequenceAfterFirst := e.sendPublishedNext.Load()
	if err := e.SendStreamFin(); err != nil {
		t.Fatalf("idempotent FIN: %v", err)
	}
	e.sendHistMu.Lock()
	after := streamFINLedgerSequences(e.sendHist.entries)
	e.sendHistMu.Unlock()
	if len(after) != 1 || after[0] != publications[0] {
		t.Fatalf("idempotent FIN changed ledger: before=%v after=%v", publications, after)
	}
	if published := e.sendPublishedNext.Load(); published != sequenceAfterFirst {
		t.Fatalf("idempotent FIN advanced publication frontier %d -> %d", sequenceAfterFirst, published)
	}
}

func streamFINLedgerSequences(entries []sendHistoryEntry) []uint64 {
	var sequences []uint64
	for _, entry := range entries {
		if len(entry.frame) < proto.HeaderSize {
			continue
		}
		header, err := proto.DecodeHeader(entry.frame[:proto.HeaderSize])
		if err == nil && header.Type == proto.FrameCtrl && proto.CtrlCodeFromFlags(header.Flags) == proto.CtrlStreamFin {
			sequences = append(sequences, header.Seq)
		}
	}
	return sequences
}
