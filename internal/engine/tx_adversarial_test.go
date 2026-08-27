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

type txAdversarialReadStep struct {
	frame       []byte
	err         error
	signalDeath bool
}

type txAdversarialPath struct {
	reads  chan txAdversarialReadStep
	closed chan struct{}

	closeOnce sync.Once
	deathMu   sync.Mutex
	deathFn   func(transport.DeathCause, error)
	byeSeen   atomic.Bool

	writeMu sync.Mutex
	writes  [][]byte
	writeFn func([]byte) (int, error)
}

type txAdversarialGatedReadPath struct {
	transport.PathConn
	gate <-chan struct{}
}

func (p *txAdversarialGatedReadPath) Read(buf []byte) (int, error) {
	<-p.gate
	return p.PathConn.Read(buf)
}

func newTxAdversarialPath() *txAdversarialPath {
	return &txAdversarialPath{
		reads:  make(chan txAdversarialReadStep, 4),
		closed: make(chan struct{}),
	}
}

func (p *txAdversarialPath) Read(buf []byte) (int, error) {
	select {
	case step := <-p.reads:
		if step.signalDeath {
			cause := transport.CauseTransportError
			if p.byeSeen.Load() {
				cause = transport.CauseCleanClose
			}
			p.deathMu.Lock()
			fn := p.deathFn
			p.deathMu.Unlock()
			if fn != nil {
				fn(cause, step.err)
			}
		}
		n := copy(buf, step.frame)
		return n, step.err
	case <-p.closed:
		return 0, net.ErrClosed
	}
}

func (p *txAdversarialPath) Write(frame []byte) (int, error) {
	select {
	case <-p.closed:
		return 0, net.ErrClosed
	default:
	}

	cp := append([]byte(nil), frame...)
	p.writeMu.Lock()
	p.writes = append(p.writes, cp)
	fn := p.writeFn
	p.writeMu.Unlock()
	if fn != nil {
		return fn(cp)
	}
	return len(frame), nil
}

func (p *txAdversarialPath) setWriteFn(fn func([]byte) (int, error)) {
	p.writeMu.Lock()
	p.writeFn = fn
	p.writeMu.Unlock()
}

func (p *txAdversarialPath) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return nil
}

func (p *txAdversarialPath) Quality() transport.PathQuality { return transport.PathQuality{} }

func (p *txAdversarialPath) OnDeath(fn func(transport.DeathCause, error)) {
	p.deathMu.Lock()
	p.deathFn = fn
	p.deathMu.Unlock()
}

func (p *txAdversarialPath) LocalAddr() string  { return "tx-adversarial-local" }
func (p *txAdversarialPath) RemoteAddr() string { return "tx-adversarial-remote" }
func (p *txAdversarialPath) MarkByeSeen()       { p.byeSeen.Store(true) }

func (p *txAdversarialPath) frameCount(frameType proto.FrameType, code proto.CtrlCode) int {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()

	count := 0
	for _, frame := range p.writes {
		if len(frame) < proto.HeaderSize {
			continue
		}
		hdr, err := proto.DecodeHeader(frame[:proto.HeaderSize])
		if err != nil || hdr.Type != frameType {
			continue
		}
		if frameType != proto.FrameCtrl || proto.CtrlCodeFromFlags(hdr.Flags) == code {
			count++
		}
	}
	return count
}

func txAdversarialFrame(t *testing.T, frameType proto.FrameType, code proto.CtrlCode, seq uint64, payload []byte) []byte {
	t.Helper()
	flags := uint16(0)
	if frameType == proto.FrameCtrl {
		flags = proto.FlagsForCtrl(code)
	}
	frame := make([]byte, proto.HeaderSize+len(payload))
	if err := (proto.Header{Version: proto.Version, Type: frameType, Flags: flags, Seq: seq}).Encode(frame[:proto.HeaderSize]); err != nil {
		t.Fatalf("encode adversarial frame: %v", err)
	}
	copy(frame[proto.HeaderSize:], payload)
	return frame
}

func txAdversarialFillDataLedger(t *testing.T, e *Engine) {
	t.Helper()
	for i := 0; i < sendHistoryWindow; i++ {
		if err := e.SendPacket([]byte{byte(i)}); err != nil {
			t.Fatalf("fill replay ledger at frame %d: %v", i, err)
		}
	}
}

func txAdversarialRecvError(t *testing.T, e *Engine, timeout time.Duration) error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := e.Recv(make([]byte, 1))
		done <- err
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		_ = e.Close()
		<-done
		t.Fatalf("Recv did not terminate within %v", timeout)
		return nil
	}
}

// This is a deadlock oracle, not a migration-latency qualification. Replaying
// the full bounded window is O(window) and race instrumentation can amplify it
// under package-wide contention.
const txAdversarialDeadlockTimeout = 15 * time.Second

func TestTxAdversarialFullLedgerDoesNotBlockExplicitMigrate(t *testing.T) {
	e := New(SideClient, [16]byte{0xa1}, Limits{})
	defer e.Close()
	targets := configureLeafSelectorRuntime(t, e, "first", "second")

	first := newTxAdversarialPath()
	second := newTxAdversarialPath()
	if _, err := e.AttachPathBound(first, transport.PathSpec{Transport: "adversarial", Address: "first"}, PathBinding{
		LocalTXTargetID: targets["first"], PeerTXTargetID: targets["first"],
	}); err != nil {
		t.Fatalf("attach first path: %v", err)
	}
	secondID, err := e.AttachPathBound(second, transport.PathSpec{Transport: "adversarial", Address: "second"}, PathBinding{
		LocalTXTargetID: targets["second"], PeerTXTargetID: targets["second"],
	})
	if err != nil {
		t.Fatalf("attach second path: %v", err)
	}
	txAdversarialFillDataLedger(t, e)
	stats := e.ReplayStats()
	if stats.FramesInUse != stats.FrameLimit || stats.FrameLimit != sendHistoryWindow || stats.CreditWaiters != 0 {
		t.Fatalf("full replay ledger precondition is not proven: %+v", stats)
	}

	replayStarted := make(chan struct{})
	releaseReplay := make(chan struct{})
	var replayOnce sync.Once
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseReplay) }) }
	t.Cleanup(release)
	second.setWriteFn(func(frame []byte) (int, error) {
		if len(frame) >= proto.HeaderSize {
			hdr, err := proto.DecodeHeader(frame[:proto.HeaderSize])
			if err == nil && hdr.Type == proto.FrameData {
				replayOnce.Do(func() {
					close(replayStarted)
					<-releaseReplay
				})
			}
		}
		return len(frame), nil
	})

	done := make(chan error, 1)
	go func() { done <- e.SelectExplicitTarget(targets["root"], targets["second"], "explicit") }()
	select {
	case <-replayStarted:
	case err := <-done:
		if err != nil {
			t.Fatalf("Migrate with full replay ledger: %v", err)
		}
		t.Fatal("explicit Migrate returned before replaying the full ledger")
	case <-time.After(txAdversarialDeadlockTimeout):
		release()
		_ = e.Close()
		<-done
		t.Fatal("explicit Migrate did not reach successor replay with full credits occupied")
	}

	if got := e.ActivePath(); got != secondID {
		t.Fatalf("active path during replay = %d, want committed second path %d", got, secondID)
	}
	stats = e.ReplayStats()
	if stats.FramesInUse != stats.FrameLimit || stats.CreditWaiters != 0 {
		t.Fatalf("migration acquired new replay credit before successor write: %+v", stats)
	}
	if !e.policyOwnerMu.TryLock() {
		t.Fatal("successor replay retained the policy owner lock")
	}
	e.policyOwnerMu.Unlock()
	e.sendMu.initialize()
	if permits := len(e.sendMu.permit); permits != 0 {
		t.Fatalf("successor replay exposed %d sequencer permits, want none", permits)
	}
	release()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Migrate with full replay ledger: %v", err)
		}
	case <-time.After(txAdversarialDeadlockTimeout):
		_ = e.Close()
		<-done
		t.Fatal("explicit Migrate did not finish bounded full-ledger replay")
	}

	if got := e.ActivePath(); got != secondID {
		t.Fatalf("active path = %d, want healthy second path %d", got, secondID)
	}
	if got := second.frameCount(proto.FrameData, 0); got != sendHistoryWindow {
		t.Fatalf("replayed DATA frames on second path = %d, want %d", got, sendHistoryWindow)
	}
}

func TestTxAdversarialFinalCloseBoundedWithFullLedger(t *testing.T) {
	e := New(SideClient, [16]byte{0xa2}, Limits{})
	targets := configureLeafSelectorRuntime(t, e, "close")
	path := newTxAdversarialPath()
	attachFixturePath(t, e, path, transport.PathSpec{Transport: "adversarial", Address: "close"}, targets["close"])
	txAdversarialFillDataLedger(t, e)

	type closeResult struct {
		byeErr   error
		closeErr error
	}
	done := make(chan closeResult, 1)
	go func() {
		done <- closeResult{byeErr: e.SendBye(proto.ByeNormal), closeErr: e.Close()}
	}()

	select {
	case result := <-done:
		if result.byeErr != nil {
			t.Fatalf("send final BYE with full replay ledger: %v", result.byeErr)
		}
		if result.closeErr != nil {
			t.Fatalf("final Close: %v", result.closeErr)
		}
	case <-time.After(txAdversarialDeadlockTimeout):
		_ = e.Close()
		<-done
		t.Fatal("final close blocked behind a full data replay ledger")
	}

	if got := path.frameCount(proto.FrameCtrl, proto.CtrlBye); got != 1 {
		t.Fatalf("BYE writes = %d, want 1", got)
	}
}

func TestTxAdversarialByeAboveGapThenPathEOFCannotBeClean(t *testing.T) {
	e := New(SideServer, [16]byte{0xa3}, Limits{MigrationBudget: 25 * time.Millisecond})
	defer e.Close()
	path := newTxAdversarialPath()
	readGate := make(chan struct{})
	path.reads <- txAdversarialReadStep{
		frame: txAdversarialFrame(t, proto.FrameCtrl, proto.CtrlBye, 1, proto.ByePayload{Reason: proto.ByeNormal}.Encode()),
	}
	path.reads <- txAdversarialReadStep{err: io.EOF, signalDeath: true}
	if _, err := e.AttachPath(&txAdversarialGatedReadPath{PathConn: path, gate: readGate}, transport.PathSpec{Transport: "adversarial", Address: "bye-gap"}); err != nil {
		t.Fatalf("attach path: %v", err)
	}
	close(readGate)

	err := txAdversarialRecvError(t, e, time.Second)
	if errors.Is(err, io.EOF) {
		t.Fatalf("BYE above missing SEQ followed by path EOF became clean EOF")
	}
	if !errors.Is(err, ErrMigrationBudgetExceeded) {
		t.Fatalf("gap followed by path EOF = %v, want %v", err, ErrMigrationBudgetExceeded)
	}
}

func TestTxAdversarialNonNormalOrMalformedByeIsNotClean(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		want    error
	}{
		{
			name:    "non-normal migration budget reason",
			payload: proto.ByePayload{Reason: proto.ByeMigBudget}.Encode(),
			want:    ErrMigrationBudgetExceeded,
		},
		{
			name:    "malformed empty payload",
			payload: nil,
			want:    ErrPeerProtocol,
		},
	}

	for i, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			e := New(SideServer, [16]byte{0xa4, byte(i)}, Limits{})
			defer e.Close()
			path := newTxAdversarialPath()
			readGate := make(chan struct{})
			path.reads <- txAdversarialReadStep{
				frame: txAdversarialFrame(t, proto.FrameCtrl, proto.CtrlBye, 0, test.payload),
			}
			_, err := e.AttachPath(&txAdversarialGatedReadPath{PathConn: path, gate: readGate}, transport.PathSpec{Transport: "adversarial", Address: test.name})
			close(readGate)
			if err != nil {
				t.Fatalf("attach path: %v", err)
			}

			err = txAdversarialRecvError(t, e, time.Second)
			if errors.Is(err, io.EOF) {
				t.Fatalf("BYE payload %x became clean EOF", test.payload)
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("BYE payload %x = %v, want %v", test.payload, err, test.want)
			}
		})
	}
}

func TestTxAdversarialOneShotReplayWriteFailureRetriesWithoutTraffic(t *testing.T) {
	e := New(SideClient, [16]byte{0xa5}, Limits{})
	defer e.Close()
	targets := configureLeafSelectorRuntime(t, e, "replay-primary", "replay-successor")
	primary := newTxAdversarialPath()
	successor := newTxAdversarialPath()

	var dataAttempts atomic.Int32
	replaySucceeded := make(chan struct{})
	var replaySucceededOnce sync.Once
	countAttempt := func(frame []byte) (int32, bool) {
		if len(frame) < proto.HeaderSize {
			return 0, false
		}
		hdr, err := proto.DecodeHeader(frame[:proto.HeaderSize])
		if err != nil || hdr.Type != proto.FrameData || hdr.Seq != 0 {
			return 0, false
		}
		return dataAttempts.Add(1), true
	}
	primary.setWriteFn(func(frame []byte) (int, error) {
		attempt, counted := countAttempt(frame)
		if counted && attempt == 2 {
			return 0, errors.New("injected one-shot replay write failure")
		}
		return len(frame), nil
	})
	successor.setWriteFn(func(frame []byte) (int, error) {
		attempt, counted := countAttempt(frame)
		if counted && attempt == 3 {
			replaySucceededOnce.Do(func() { close(replaySucceeded) })
		}
		return len(frame), nil
	})

	attachFixturePath(t, e, primary, transport.PathSpec{Transport: "adversarial", Address: "replay-primary"}, targets["replay-primary"])
	attachFixturePath(t, e, successor, transport.PathSpec{Transport: "adversarial", Address: "replay-successor"}, targets["replay-successor"])
	if _, err := e.SendData([]byte("unacknowledged")); err != nil {
		t.Fatalf("initial SendData: %v", err)
	}
	if got := dataAttempts.Load(); got != 1 {
		t.Fatalf("initial DATA attempts = %d, want 1", got)
	}

	e.requestReplay(0)
	select {
	case <-replaySucceeded:
	case <-time.After(2 * time.Second):
		t.Fatalf("one-shot replay failure was not retried; DATA attempts = %d", dataAttempts.Load())
	}
}

func TestSelectorCommitSurvivesOneShotCutoverReplayFailure(t *testing.T) {
	e := New(SideClient, [16]byte{0xa5, 0x51}, Limits{MigrationBudget: 2 * time.Second, ProbeInterval: time.Hour}.Clamp())
	defer e.Close()
	targets := configureLeafSelectorRuntime(t, e, "cutover-primary", "cutover-successor")
	primary := newCloseReleasedWritePath()
	successor := newTxAdversarialPath()

	firstFenced := make(chan struct{})
	replayBlocked := make(chan struct{})
	releaseReplay := make(chan struct{})
	var replayAttempts atomic.Uint64
	successor.setWriteFn(func(frame []byte) (int, error) {
		if len(frame) < proto.HeaderSize {
			return len(frame), nil
		}
		hdr, err := proto.DecodeHeader(frame[:proto.HeaderSize])
		if err != nil || hdr.Type != proto.FrameData || hdr.Seq != 0 {
			return len(frame), nil
		}
		switch replayAttempts.Add(1) {
		case 1:
			close(firstFenced)
			return 0, ErrPathTXFenced
		case 2:
			close(replayBlocked)
			select {
			case <-releaseReplay:
				return len(frame), nil
			case <-successor.closed:
				return 0, net.ErrClosed
			}
		default:
			return len(frame), nil
		}
	})

	attachFixturePath(t, e, primary, transport.PathSpec{Transport: "adversarial", Address: "cutover-primary"}, targets["cutover-primary"])
	successorID := attachFixturePath(t, e, successor, transport.PathSpec{Transport: "adversarial", Address: "cutover-successor"}, targets["cutover-successor"])
	writeDone := make(chan error, 1)
	go func() {
		_, err := e.SendData([]byte("cutover-replay-owned"))
		writeDone <- err
	}()
	select {
	case <-primary.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("primary DATA write did not start")
	}

	selectDone := make(chan error, 1)
	go func() {
		selectDone <- e.SelectExplicitTarget(targets["root"], targets["cutover-successor"], "cutover-replay-failure")
	}()
	select {
	case <-firstFenced:
	case <-time.After(time.Second):
		t.Fatal("cutover replay did not encounter the injected TX fence")
	}
	select {
	case <-replayBlocked:
	case <-time.After(time.Second):
		t.Fatal("cutover replay did not retry after the TX fence")
	}
	if !e.policyOwnerMu.TryLock() {
		t.Fatal("committed replay retained policy owner lock")
	}
	e.policyOwnerMu.Unlock()
	if e.policyCutoverMu.TryLock() {
		e.policyCutoverMu.Unlock()
		t.Fatal("committed replay released cutover serialization before replay completed")
	}
	close(releaseReplay)
	select {
	case err := <-selectDone:
		if err != nil {
			t.Fatalf("selector cutover after transient replay fence: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("selector cutover did not finish after replay was released")
	}
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("application observed selector cutover: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("application frame did not hand off to selector cutover")
	}
	e.policyStateMu.Lock()
	generation, selected := e.policyGeneration, e.policySelections[targets["root"]]
	e.policyStateMu.Unlock()
	if generation != 1 || selected != targets["cutover-successor"] || e.ActivePath() != successorID {
		t.Fatalf("committed state generation/target/active=%d/%x/%d", generation, selected, e.ActivePath())
	}
	if got := replayAttempts.Load(); got < 2 {
		t.Fatalf("cutover replay attempts=%d want at least 2", got)
	}
	e.zombieMu.Lock()
	zombieLeft := e.zombieLeft
	e.zombieMu.Unlock()
	if zombieLeft != e.limits.ZombieMaxMigrations {
		t.Fatalf("transient TX fence consumed zombie budget: got=%d want=%d", zombieLeft, e.limits.ZombieMaxMigrations)
	}
}

func TestGapReplayFollowsCurrentCumulativeGapState(t *testing.T) {
	e := New(SideClient, [16]byte{0xa6}, Limits{})
	defer e.Close()
	e.gapReplayBackoff = time.Second
	targets := configureLeafSelectorRuntime(t, e, "gap-frontier")
	path := newTxAdversarialPath()

	var mu sync.Mutex
	attempts := make(map[uint64]int)
	changed := make(chan struct{}, 32)
	thirdSeq0 := make(chan struct{}, 1)
	path.setWriteFn(func(frame []byte) (int, error) {
		if len(frame) >= proto.HeaderSize {
			hdr, err := proto.DecodeHeader(frame[:proto.HeaderSize])
			if err == nil && hdr.Type == proto.FrameData {
				mu.Lock()
				attempts[hdr.Seq]++
				attempt := attempts[hdr.Seq]
				mu.Unlock()
				if hdr.Seq == 0 && attempt == 3 {
					select {
					case thirdSeq0 <- struct{}{}:
					default:
					}
				}
				select {
				case changed <- struct{}{}:
				default:
				}
			}
		}
		return len(frame), nil
	})
	attachFixturePath(t, e, path, transport.PathSpec{Transport: "adversarial", Address: "gap-frontier"}, targets["gap-frontier"])
	for i := 0; i < 4; i++ {
		if _, err := e.SendData([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	initialGap := currentAck(e, 0)
	initialGap.Gap = true
	if !e.notePeerAck(initialGap) {
		t.Fatal("failed to install initial cumulative gap")
	}
	e.requestGapReplay(initialGap.NextSeq)
	waitAttempts := func(seq uint64, want int) {
		t.Helper()
		deadline := time.NewTimer(time.Second)
		defer deadline.Stop()
		for {
			mu.Lock()
			got := attempts[seq]
			mu.Unlock()
			if got >= want {
				return
			}
			select {
			case <-changed:
			case <-deadline.C:
				t.Fatalf("SEQ %d attempts=%d want>=%d", seq, got, want)
			}
		}
	}
	waitAttempts(0, 2)
	select {
	case <-thirdSeq0:
		t.Fatal("stale ACK wake bypassed configured replay backoff")
	case <-time.After(20 * time.Millisecond):
	}
	mu.Lock()
	seq1BeforeACK := attempts[1]
	mu.Unlock()
	if seq1BeforeACK != 1 {
		t.Fatalf("replayed suffix before ACK frontier advanced: SEQ 1 attempts=%d", seq1BeforeACK)
	}
	cleared := currentAck(e, 1)
	if !e.notePeerAck(cleared) {
		t.Fatal("failed to install cumulative ACK for SEQ 0")
	}
	time.Sleep(25 * time.Millisecond)
	mu.Lock()
	seq1AfterClear := attempts[1]
	mu.Unlock()
	if seq1AfterClear != 1 {
		t.Fatalf("continued gap replay after Gap=false: SEQ 1 attempts=%d", seq1AfterClear)
	}

	continued := currentAck(e, 1)
	continued.Gap = true
	if !e.notePeerAck(continued) {
		t.Fatal("failed to install continuing cumulative gap")
	}
	e.requestGapReplay(1)
	waitAttempts(1, 2)
	if !e.notePeerAck(currentAck(e, 4)) {
		t.Fatal("failed to advance cumulative ACK to target")
	}
	time.Sleep(25 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if attempts[2] != 1 || attempts[3] != 1 {
		t.Fatalf("replayed acknowledged suffix: attempts=%v", attempts)
	}
}

func TestReplayACKStateIsMonotonicAcrossPathReaders(t *testing.T) {
	e := &Engine{}
	if !e.publishReplayAck(5, false) {
		t.Fatal("initial ACK state was not published")
	}
	if !e.publishReplayAck(5, true) {
		t.Fatal("same-frontier gap did not supersede no-gap state")
	}
	if e.publishReplayAck(5, false) {
		t.Fatal("stale same-frontier no-gap ACK cleared an observed gap")
	}
	if e.publishReplayAck(4, true) {
		t.Fatal("lower cumulative ACK frontier overwrote newer state")
	}
	next, gap, seen, version := e.replayAckState()
	if !seen || next != 5 || !gap || version != 2 {
		t.Fatalf("ACK state=(next=%d gap=%t seen=%t version=%d), want (5,true,true,2)", next, gap, seen, version)
	}
	if !e.publishReplayAck(6, false) {
		t.Fatal("advanced cumulative frontier did not clear gap state")
	}
	next, gap, seen, version = e.replayAckState()
	if !seen || next != 6 || gap || version != 3 {
		t.Fatalf("advanced ACK state=(next=%d gap=%t seen=%t version=%d), want (6,false,true,3)", next, gap, seen, version)
	}
}

func TestReplayACKStateConcurrentPathReaders(t *testing.T) {
	const (
		rounds  = 100
		workers = 64
		maxSeq  = uint64(31)
	)
	for round := 0; round < rounds; round++ {
		e := &Engine{}
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(workers)
		for worker := 0; worker < workers; worker++ {
			worker := worker
			go func() {
				defer wg.Done()
				<-start
				nextSeq := uint64(worker % int(maxSeq+1))
				gap := worker == workers-1 || worker%3 == 0
				e.publishReplayAck(nextSeq, gap)
			}()
		}
		close(start)
		wg.Wait()
		next, gap, seen, _ := e.replayAckState()
		if !seen || next != maxSeq || !gap {
			t.Fatalf("round %d concurrent ACK state=(next=%d gap=%t seen=%t), want (%d,true,true)", round, next, gap, seen, maxSeq)
		}
	}
}

func TestFullReplayPreemptsActiveGapRepair(t *testing.T) {
	e := New(SideClient, [16]byte{0xa7}, Limits{})
	defer e.Close()
	targets := configureLeafSelectorRuntime(t, e, "full-preempts-gap")
	path := newTxAdversarialPath()

	var mu sync.Mutex
	attempts := make(map[uint64]int)
	changed := make(chan struct{}, 64)
	path.setWriteFn(func(frame []byte) (int, error) {
		if len(frame) >= proto.HeaderSize {
			hdr, err := proto.DecodeHeader(frame[:proto.HeaderSize])
			if err == nil && hdr.Type == proto.FrameData {
				mu.Lock()
				attempts[hdr.Seq]++
				mu.Unlock()
				select {
				case changed <- struct{}{}:
				default:
				}
			}
		}
		return len(frame), nil
	})
	attachFixturePath(t, e, path, transport.PathSpec{Transport: "adversarial", Address: "full-preempts-gap"}, targets["full-preempts-gap"])
	for i := 0; i < 4; i++ {
		if _, err := e.SendData([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	e.requestGapReplay(0)

	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for {
		mu.Lock()
		gapActive := attempts[0] >= 2
		mu.Unlock()
		if gapActive {
			break
		}
		select {
		case <-changed:
		case <-deadline.C:
			t.Fatal("gap replay did not become active")
		}
	}

	e.requestReplay(0)
	for {
		mu.Lock()
		fullFinished := attempts[1] >= 2 && attempts[2] >= 2 && attempts[3] >= 2
		mu.Unlock()
		if fullFinished {
			break
		}
		select {
		case <-changed:
		case <-deadline.C:
			mu.Lock()
			defer mu.Unlock()
			t.Fatalf("full replay starved behind active gap repair: attempts=%v", attempts)
		}
	}
}

func TestReplayRequestsCoalesceWithoutDroppingLatestTarget(t *testing.T) {
	e := &Engine{replayWake: make(chan struct{}, 1)}
	e.queueReplay(replayRequest{nextSeq: 7, target: 10, kind: replayRequestGap})
	e.queueReplay(replayRequest{nextSeq: 5, target: 20, kind: replayRequestGap})
	request, ok := e.takeReplayRequest()
	if !ok || request.kind != replayRequestGap || request.nextSeq != 5 || request.target != 20 {
		t.Fatalf("merged gap request=%+v ok=%t", request, ok)
	}

	e.queueReplay(replayRequest{nextSeq: 9, target: 30, kind: replayRequestGap})
	e.queueReplay(replayRequest{nextSeq: 4, kind: replayRequestFull})
	e.queueReplay(replayRequest{nextSeq: 2, target: 40, kind: replayRequestGap})
	e.queueReplay(replayRequest{nextSeq: 3, kind: replayRequestFull})
	request, ok = e.takeReplayRequest()
	if !ok || request.kind != replayRequestFull || request.nextSeq != 2 {
		t.Fatalf("full replay did not dominate gaps: request=%+v ok=%t", request, ok)
	}

	e.queueReplay(replayRequest{nextSeq: 8, target: 12, kind: replayRequestGap})
	e.queueReplay(replayRequest{nextSeq: 6, target: 10, kind: replayRequestBounded})
	e.queueReplay(replayRequest{nextSeq: 7, target: 15, kind: replayRequestGap})
	request, ok = e.takeReplayRequest()
	if !ok || request.kind != replayRequestBounded || request.nextSeq != 6 || request.target != 15 {
		t.Fatalf("bounded replay did not preserve the exact union: request=%+v ok=%t", request, ok)
	}
	if _, ok := e.takeReplayRequest(); ok {
		t.Fatal("coalesced queue retained a duplicate request")
	}
}

func TestTxAdversarialSolePathRecoveryDeliversLastUnackedTail(t *testing.T) {
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{}.Clamp())
	server := New(SideServer, flow, Limits{}.Clamp())
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	targets := configureSymmetricLeafGroupRuntime(t, client, server, proto.GraphNodeKindSelector, "old", "replacement")

	oldClient, oldServer := newMemoryPathPair()
	oldClient.dropWrites.Store(true)
	oldClientID := attachFixturePath(t, client, oldClient, transport.PathSpec{Transport: "memory", Address: "old"}, targets["old"])
	oldServerID := attachFixturePath(t, server, oldServer, transport.PathSpec{Transport: "memory", Address: "old"}, targets["old"])

	tail := []byte("last-unacknowledged-tail")
	if _, err := client.SendData(tail); err != nil {
		t.Fatalf("publish tail: %v", err)
	}
	failMemoryPath(t, client, oldClientID, oldClient, errors.New("old client carrier failed"))
	failMemoryPath(t, server, oldServerID, oldServer, errors.New("old server carrier failed"))

	newClient, newServer := newMemoryPathPair()
	readGate := make(chan struct{})
	var releaseGate sync.Once
	releaseRead := func() { releaseGate.Do(func() { close(readGate) }) }
	defer releaseRead()
	attachFixturePath(t, server, &txAdversarialGatedReadPath{PathConn: newServer, gate: readGate}, transport.PathSpec{Transport: "memory", Address: "replacement"}, targets["replacement"])
	attachFixturePath(t, client, newClient, transport.PathSpec{Transport: "memory", Address: "replacement"}, targets["replacement"])
	if got := client.MigrationCount(); got != 1 {
		t.Fatalf("client recovery migrations = %d, want 1", got)
	}
	if got := server.MigrationCount(); got != 1 {
		t.Fatalf("server recovery migrations = %d, want 1", got)
	}
	client.zombieMu.Lock()
	clientZombieLeft := client.zombieLeft
	client.zombieMu.Unlock()
	server.zombieMu.Lock()
	serverZombieLeft := server.zombieLeft
	server.zombieMu.Unlock()
	wantZombieLeft := client.limits.ZombieMaxMigrations - 1
	if clientZombieLeft != wantZombieLeft || serverZombieLeft != wantZombieLeft {
		t.Fatalf("zombie accounting client/server = %d/%d, want %d/%d", clientZombieLeft, serverZombieLeft, wantZombieLeft, wantZombieLeft)
	}
	releaseRead()

	got := make([]byte, len(tail))
	recvDone := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(&Conn{E: server}, got)
		recvDone <- err
	}()
	select {
	case err := <-recvDone:
		if err != nil {
			t.Fatalf("receive replayed tail: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("last unacknowledged tail was not replayed after sole-path recovery")
	}
	if !bytes.Equal(got, tail) {
		t.Fatalf("replayed tail = %q, want %q", got, tail)
	}
}
