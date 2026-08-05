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

func TestTxAdversarialFullLedgerDoesNotBlockExplicitMigrate(t *testing.T) {
	e := New(SideClient, [16]byte{0xa1}, Limits{})
	defer e.Close()

	first := newTxAdversarialPath()
	second := newTxAdversarialPath()
	if _, err := e.AttachPath(first, transport.PathSpec{Transport: "adversarial", Address: "first"}); err != nil {
		t.Fatalf("attach first path: %v", err)
	}
	secondID, err := e.AttachPath(second, transport.PathSpec{Transport: "adversarial", Address: "second"})
	if err != nil {
		t.Fatalf("attach second path: %v", err)
	}
	txAdversarialFillDataLedger(t, e)

	done := make(chan error, 1)
	go func() { done <- e.Migrate(secondID) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Migrate with full replay ledger: %v", err)
		}
	case <-time.After(750 * time.Millisecond):
		_ = e.Close()
		<-done
		t.Fatal("explicit Migrate blocked behind a full data replay ledger")
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
	path := newTxAdversarialPath()
	if _, err := e.AttachPath(path, transport.PathSpec{Transport: "adversarial", Address: "close"}); err != nil {
		t.Fatalf("attach path: %v", err)
	}
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
	case <-time.After(750 * time.Millisecond):
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
	path.reads <- txAdversarialReadStep{
		frame: txAdversarialFrame(t, proto.FrameCtrl, proto.CtrlBye, 1, proto.ByePayload{Reason: proto.ByeNormal}.Encode()),
	}
	path.reads <- txAdversarialReadStep{err: io.EOF, signalDeath: true}
	if _, err := e.AttachPath(path, transport.PathSpec{Transport: "adversarial", Address: "bye-gap"}); err != nil {
		t.Fatalf("attach path: %v", err)
	}

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
	path := newTxAdversarialPath()

	var dataAttempts atomic.Int32
	replaySucceeded := make(chan struct{})
	var replaySucceededOnce sync.Once
	path.writeFn = func(frame []byte) (int, error) {
		if len(frame) < proto.HeaderSize {
			return len(frame), nil
		}
		hdr, err := proto.DecodeHeader(frame[:proto.HeaderSize])
		if err != nil || hdr.Type != proto.FrameData || hdr.Seq != 0 {
			return len(frame), nil
		}
		switch dataAttempts.Add(1) {
		case 2:
			return 0, errors.New("injected one-shot replay write failure")
		case 3:
			replaySucceededOnce.Do(func() { close(replaySucceeded) })
		}
		return len(frame), nil
	}

	if _, err := e.AttachPath(path, transport.PathSpec{Transport: "adversarial", Address: "replay-retry"}); err != nil {
		t.Fatalf("attach path: %v", err)
	}
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

func TestTxAdversarialSolePathRecoveryDeliversLastUnackedTail(t *testing.T) {
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{}.Clamp())
	server := New(SideServer, flow, Limits{}.Clamp())
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	oldClient, oldServer := newMemoryPathPair()
	oldClient.dropWrites.Store(true)
	oldClientID, err := client.AttachPath(oldClient, transport.PathSpec{Transport: "memory", Address: "old"})
	if err != nil {
		t.Fatal(err)
	}
	oldServerID, err := server.AttachPath(oldServer, transport.PathSpec{Transport: "memory", Address: "old"})
	if err != nil {
		t.Fatal(err)
	}

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
	if _, err := server.AttachPath(&txAdversarialGatedReadPath{PathConn: newServer, gate: readGate}, transport.PathSpec{Transport: "memory", Address: "replacement"}); err != nil {
		t.Fatalf("attach server replacement: %v", err)
	}
	if _, err := client.AttachPath(newClient, transport.PathSpec{Transport: "memory", Address: "replacement"}); err != nil {
		t.Fatalf("attach client replacement: %v", err)
	}
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
