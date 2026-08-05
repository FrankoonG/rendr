package engine

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

const policyTxUnitRevision = 17

type policyTxUnitAckObservation struct {
	ack        proto.PolicyAck
	pathName   string
	activePath uint32
	mode       uint32
	generation uint64
	selection  proto.TargetID
	pending    bool
	completed  int
}

type policyTxUnitAckRecorder struct {
	mu           sync.Mutex
	engine       *Engine
	selectorID   proto.TargetID
	observations []policyTxUnitAckObservation
	decodeErr    error
}

func (r *policyTxUnitAckRecorder) record(pathName string, frame []byte) {
	if len(frame) < proto.HeaderSize {
		r.setDecodeErr(fmt.Errorf("short frame: %d", len(frame)))
		return
	}
	header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	if err != nil {
		r.setDecodeErr(err)
		return
	}
	if header.Type != proto.FrameCtrl || proto.CtrlCodeFromFlags(header.Flags) != proto.CtrlPolicyAck {
		return
	}
	ack, err := proto.DecodePolicyAck(frame[proto.HeaderSize:])
	if err != nil {
		r.setDecodeErr(err)
		return
	}

	observation := policyTxUnitAckObservation{
		ack:        ack,
		pathName:   pathName,
		activePath: r.engine.ActivePath(),
		mode:       r.engine.Mode(),
	}
	r.engine.policyStateMu.Lock()
	observation.generation = r.engine.policyGeneration
	observation.selection = r.engine.policySelections[r.selectorID]
	observation.pending = r.engine.policyIncoming != nil
	observation.completed = len(r.engine.policyCompleted)
	r.engine.policyStateMu.Unlock()

	r.mu.Lock()
	r.observations = append(r.observations, observation)
	r.mu.Unlock()
}

func (r *policyTxUnitAckRecorder) setDecodeErr(err error) {
	r.mu.Lock()
	if r.decodeErr == nil {
		r.decodeErr = err
	}
	r.mu.Unlock()
}

func (r *policyTxUnitAckRecorder) snapshot() ([]policyTxUnitAckObservation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]policyTxUnitAckObservation(nil), r.observations...), r.decodeErr
}

type policyTxUnitPath struct {
	name      string
	recorder  *policyTxUnitAckRecorder
	closed    chan struct{}
	closeOnce sync.Once
	failed    chan struct{}
	failOnce  sync.Once
	failMu    sync.Mutex
	failErr   error
	deathMu   sync.Mutex
	deathFn   func(transport.DeathCause, error)
	deathOnce sync.Once
}

func newPolicyTxUnitPath(name string, recorder *policyTxUnitAckRecorder) *policyTxUnitPath {
	return &policyTxUnitPath{name: name, recorder: recorder, closed: make(chan struct{}), failed: make(chan struct{})}
}

func (p *policyTxUnitPath) Read([]byte) (int, error) {
	select {
	case <-p.failed:
		err := p.failure()
		p.notifyFailure(err)
		return 0, err
	case <-p.closed:
		return 0, net.ErrClosed
	}
}

func (p *policyTxUnitPath) Write(frame []byte) (int, error) {
	select {
	case <-p.failed:
		err := p.failure()
		p.notifyFailure(err)
		return 0, err
	case <-p.closed:
		return 0, net.ErrClosed
	default:
	}
	p.recorder.record(p.name, frame)
	return len(frame), nil
}

func (p *policyTxUnitPath) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return nil
}

func (p *policyTxUnitPath) Quality() transport.PathQuality { return transport.PathQuality{} }
func (p *policyTxUnitPath) OnDeath(fn func(transport.DeathCause, error)) {
	p.deathMu.Lock()
	p.deathFn = fn
	p.deathMu.Unlock()
}
func (p *policyTxUnitPath) LocalAddr() string  { return "policy-tx-local" }
func (p *policyTxUnitPath) RemoteAddr() string { return "policy-tx-remote" }

func (p *policyTxUnitPath) Fail(err error) {
	if err == nil {
		err = errors.New("injected policy path failure")
	}
	p.failOnce.Do(func() {
		p.failMu.Lock()
		p.failErr = err
		p.failMu.Unlock()
		close(p.failed)
	})
}

func (p *policyTxUnitPath) failure() error {
	p.failMu.Lock()
	defer p.failMu.Unlock()
	if p.failErr == nil {
		return errors.New("policy path failed")
	}
	return p.failErr
}

func (p *policyTxUnitPath) notifyFailure(err error) {
	p.deathMu.Lock()
	fn := p.deathFn
	p.deathMu.Unlock()
	if fn != nil {
		p.deathOnce.Do(func() { fn(transport.CauseTransportError, err) })
	}
}

type policyTxUnitFixture struct {
	engine     *Engine
	recorder   *policyTxUnitAckRecorder
	selectorID proto.TargetID
	targetA    proto.TargetID
	targetB    proto.TargetID
	pathA      uint32
	pathB      uint32
	nameA      string
	nameB      string
}

func newPolicyTxUnitFixture(t *testing.T) *policyTxUnitFixture {
	t.Helper()
	const (
		rootName = "policy-tx-unit-root"
		nameA    = "policy-tx-unit-a"
		nameB    = "policy-tx-unit-b"
	)
	pathA := policyTxUnitNode(proto.GraphNodeKindPath, nameA)
	pathB := policyTxUnitNode(proto.GraphNodeKindPath, nameB)
	selector := policyTxUnitNode(proto.GraphNodeKindSelector, rootName, pathA.ID, pathB.ID)
	manifest := proto.GraphManifest{
		RootID: selector.ID,
		Nodes:  []proto.GraphNode{selector, pathA, pathB},
	}
	engine, recorder, paths, _ := newPolicyTxUnitEngine(t, manifest, selector.ID, nameA, nameB)
	return &policyTxUnitFixture{
		engine:     engine,
		recorder:   recorder,
		selectorID: selector.ID,
		targetA:    pathA.ID,
		targetB:    pathB.ID,
		pathA:      paths[nameA],
		pathB:      paths[nameB],
		nameA:      nameA,
		nameB:      nameB,
	}
}

func newPolicyTxUnitEngine(t *testing.T, manifest proto.GraphManifest, selectorID proto.TargetID, leafNames ...string) (*Engine, *policyTxUnitAckRecorder, map[string]uint32, map[string]*policyTxUnitPath) {
	t.Helper()
	engine := New(SideServer, [16]byte{0xa7, 0x31}, Limits{}.Clamp())
	t.Cleanup(func() { _ = engine.Close() })
	if err := engine.ConfigureLocalGraph(policyTxUnitRevision, manifest); err != nil {
		t.Fatalf("ConfigureLocalGraph: %v", err)
	}
	if err := engine.ConfigurePeerGraph(policyTxUnitRevision, manifest); err != nil {
		t.Fatalf("ConfigurePeerGraph: %v", err)
	}
	if err := engine.ConfigureExecution(proto.ExecutionKindSelector); err != nil {
		t.Fatalf("ConfigureExecution: %v", err)
	}
	recorder := &policyTxUnitAckRecorder{engine: engine, selectorID: selectorID}
	paths := make(map[string]uint32, len(leafNames))
	pathHandles := make(map[string]*policyTxUnitPath, len(leafNames))
	for _, name := range leafNames {
		path := newPolicyTxUnitPath(name, recorder)
		id, err := engine.AttachPath(path, transport.PathSpec{
			Transport: "policy-tx-unit",
			Address:   name,
			Opts:      map[string]string{"name": name},
		})
		if err != nil {
			t.Fatalf("AttachPath(%q): %v", name, err)
		}
		paths[name] = id
		pathHandles[name] = path
	}
	return engine, recorder, paths, pathHandles
}

func policyTxUnitNode(kind proto.GraphNodeKind, name string, children ...proto.TargetID) proto.GraphNode {
	return proto.GraphNode{
		ID:       proto.DeriveTargetID(kind, name),
		Kind:     kind,
		Name:     name,
		Children: append([]proto.TargetID(nil), children...),
	}
}

func policyTxUnitPrepare(engine *Engine, txByte byte, base uint64, selectorID, targetID proto.TargetID) proto.PolicyPrepare {
	binding := engine.localGraphBinding()
	return proto.PolicyPrepare{
		PolicyTransactionBinding: proto.PolicyTransactionBinding{
			SessionEpoch:  proto.SessionEpoch(engine.flowID),
			Direction:     senderDirection(engine.side),
			GraphBinding:  proto.GraphBinding{Revision: binding.revision, Digest: binding.digest},
			TransactionID: [16]byte{txByte},
		},
		BaseGeneration: base,
		Action:         proto.PolicyActionSelectChild,
		SelectorID:     selectorID,
		TargetID:       targetID,
		Cause:          "policy-tx-unit",
	}
}

func policyTxUnitCommit(t *testing.T, prepare proto.PolicyPrepare, generation uint64, reservation proto.PolicyReservationID) proto.PolicyCommit {
	t.Helper()
	digest, err := prepare.ProposalDigest()
	if err != nil {
		t.Fatalf("ProposalDigest: %v", err)
	}
	return proto.PolicyCommit{
		PolicyTransactionBinding: prepare.PolicyTransactionBinding,
		Generation:               generation,
		ProposalDigest:           digest,
		ReservationID:            reservation,
	}
}

func policyTxUnitRequireAck(t *testing.T, recorder *policyTxUnitAckRecorder, call func() error) policyTxUnitAckObservation {
	t.Helper()
	before, err := recorder.snapshot()
	if err != nil {
		t.Fatalf("decode prior policy ACK: %v", err)
	}
	if err := call(); err != nil {
		t.Fatalf("policy handler: %v", err)
	}
	after, err := recorder.snapshot()
	if err != nil {
		t.Fatalf("decode policy ACK: %v", err)
	}
	if len(after) != len(before)+1 {
		t.Fatalf("policy ACK count=%d, want %d", len(after), len(before)+1)
	}
	return after[len(before)]
}

func policyTxUnitRequireViolation(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("accepted a policy protocol violation")
	}
	var violation *policyProtocolViolation
	if !errors.As(err, &violation) {
		t.Fatalf("error %T is not a policy protocol violation: %v", err, err)
	}
}

func policyTxUnitState(engine *Engine, selectorID proto.TargetID) (generation uint64, selection proto.TargetID, pending bool, completed int) {
	engine.policyStateMu.Lock()
	defer engine.policyStateMu.Unlock()
	return engine.policyGeneration, engine.policySelections[selectorID], engine.policyIncoming != nil, len(engine.policyCompleted)
}

func TestPolicyTransactionCommitAppliesStateBeforeFinalAck(t *testing.T) {
	fixture := newPolicyTxUnitFixture(t)
	prepare := policyTxUnitPrepare(fixture.engine, 1, 0, fixture.selectorID, fixture.targetB)
	prepareAck := policyTxUnitRequireAck(t, fixture.recorder, func() error {
		return fixture.engine.handlePolicyPrepare(prepare)
	})
	if prepareAck.ack.Phase != proto.PolicyAckPhasePrepare || prepareAck.ack.Code != proto.PolicyAckCodeAccept || prepareAck.ack.Generation != 1 {
		t.Fatalf("prepare ACK=%+v", prepareAck.ack)
	}
	if prepareAck.activePath != fixture.pathA || prepareAck.generation != 0 || prepareAck.selection != (proto.TargetID{}) || !prepareAck.pending {
		t.Fatalf("PREPARE changed owner state: %+v", prepareAck)
	}

	commit := policyTxUnitCommit(t, prepare, prepareAck.ack.Generation, prepareAck.ack.ReservationID)
	finalAck := policyTxUnitRequireAck(t, fixture.recorder, func() error {
		return fixture.engine.handlePolicyCommit(commit)
	})
	if finalAck.ack.Phase != proto.PolicyAckPhaseFinal || finalAck.ack.Code != proto.PolicyAckCodeAccept {
		t.Fatalf("final ACK=%+v", finalAck.ack)
	}
	if finalAck.ack.Generation != 1 || finalAck.ack.CurrentGeneration != 1 || finalAck.ack.CurrentTargetID != fixture.targetB {
		t.Fatalf("final ACK does not prove committed state: %+v", finalAck.ack)
	}
	if finalAck.pathName != fixture.nameB || finalAck.activePath != fixture.pathB {
		t.Fatalf("final ACK was published before dispatch changed: path=%q active=%d want %q/%d", finalAck.pathName, finalAck.activePath, fixture.nameB, fixture.pathB)
	}
	if finalAck.generation != 1 || finalAck.selection != fixture.targetB || finalAck.pending || finalAck.completed != 1 {
		t.Fatalf("final ACK was published before transaction state committed: %+v", finalAck)
	}
}

func TestPolicyTransactionDuplicatePrepareAndCommitAreIdempotent(t *testing.T) {
	fixture := newPolicyTxUnitFixture(t)
	prepare := policyTxUnitPrepare(fixture.engine, 2, 0, fixture.selectorID, fixture.targetB)
	firstPrepare := policyTxUnitRequireAck(t, fixture.recorder, func() error {
		return fixture.engine.handlePolicyPrepare(prepare)
	})
	duplicatePrepare := policyTxUnitRequireAck(t, fixture.recorder, func() error {
		return fixture.engine.handlePolicyPrepare(prepare)
	})
	if duplicatePrepare.ack != firstPrepare.ack {
		t.Fatalf("duplicate PREPARE ACK=%+v want %+v", duplicatePrepare.ack, firstPrepare.ack)
	}

	commit := policyTxUnitCommit(t, prepare, firstPrepare.ack.Generation, firstPrepare.ack.ReservationID)
	firstFinal := policyTxUnitRequireAck(t, fixture.recorder, func() error {
		return fixture.engine.handlePolicyCommit(commit)
	})
	duplicateFinal := policyTxUnitRequireAck(t, fixture.recorder, func() error {
		return fixture.engine.handlePolicyCommit(commit)
	})
	if duplicateFinal.ack != firstFinal.ack {
		t.Fatalf("duplicate COMMIT ACK=%+v want %+v", duplicateFinal.ack, firstFinal.ack)
	}
	generation, selection, pending, completed := policyTxUnitState(fixture.engine, fixture.selectorID)
	if generation != 1 || selection != fixture.targetB || pending || completed != 1 {
		t.Fatalf("idempotent replay changed state: generation=%d selection=%x pending=%v completed=%d", generation, selection, pending, completed)
	}
	if got := fixture.engine.MigrationCount(); got != 1 {
		t.Fatalf("duplicate COMMIT applied dispatch %d times, want 1", got)
	}
}

func TestPolicyTransactionRejectsTxIDReuseWithDifferentContent(t *testing.T) {
	t.Run("pending prepare", func(t *testing.T) {
		fixture := newPolicyTxUnitFixture(t)
		prepare := policyTxUnitPrepare(fixture.engine, 3, 0, fixture.selectorID, fixture.targetB)
		policyTxUnitRequireAck(t, fixture.recorder, func() error {
			return fixture.engine.handlePolicyPrepare(prepare)
		})
		changed := prepare
		changed.Cause = "different-content"
		before, _ := fixture.recorder.snapshot()
		policyTxUnitRequireViolation(t, fixture.engine.handlePolicyPrepare(changed))
		after, _ := fixture.recorder.snapshot()
		if len(after) != len(before) {
			t.Fatal("protocol violation emitted an ACK")
		}
		fixture.engine.policyStateMu.Lock()
		pending := fixture.engine.policyIncoming
		fixture.engine.policyStateMu.Unlock()
		if pending == nil || pending.prepare != prepare {
			t.Fatal("conflicting PREPARE replaced the pending transaction")
		}
	})

	t.Run("completed prepare and commit", func(t *testing.T) {
		fixture := newPolicyTxUnitFixture(t)
		prepare := policyTxUnitPrepare(fixture.engine, 4, 0, fixture.selectorID, fixture.targetB)
		prepareAck := policyTxUnitRequireAck(t, fixture.recorder, func() error {
			return fixture.engine.handlePolicyPrepare(prepare)
		})
		commit := policyTxUnitCommit(t, prepare, prepareAck.ack.Generation, prepareAck.ack.ReservationID)
		policyTxUnitRequireAck(t, fixture.recorder, func() error {
			return fixture.engine.handlePolicyCommit(commit)
		})

		changedPrepare := prepare
		changedPrepare.TargetID = fixture.targetA
		policyTxUnitRequireViolation(t, fixture.engine.handlePolicyPrepare(changedPrepare))
		changedCommit := commit
		changedCommit.Generation++
		policyTxUnitRequireViolation(t, fixture.engine.handlePolicyCommit(changedCommit))

		generation, selection, pending, completed := policyTxUnitState(fixture.engine, fixture.selectorID)
		if generation != 1 || selection != fixture.targetB || pending || completed != 1 {
			t.Fatalf("conflicting replay changed completed state: generation=%d selection=%x pending=%v completed=%d", generation, selection, pending, completed)
		}
	})
}

func TestPolicyTransactionRejectsStaleGeneration(t *testing.T) {
	fixture := newPolicyTxUnitFixture(t)
	fixture.engine.policyStateMu.Lock()
	fixture.engine.policyGeneration = 5
	fixture.engine.policySelections[fixture.selectorID] = fixture.targetA
	fixture.engine.policyStateMu.Unlock()

	prepare := policyTxUnitPrepare(fixture.engine, 5, 4, fixture.selectorID, fixture.targetB)
	observation := policyTxUnitRequireAck(t, fixture.recorder, func() error {
		return fixture.engine.handlePolicyPrepare(prepare)
	})
	if observation.ack.Phase != proto.PolicyAckPhasePrepare || observation.ack.Code != proto.PolicyAckCodeStale {
		t.Fatalf("stale PREPARE ACK=%+v", observation.ack)
	}
	if observation.ack.Generation != 0 || observation.ack.CurrentGeneration != 5 || observation.ack.CurrentTargetID != fixture.targetA {
		t.Fatalf("stale ACK does not report owner state: %+v", observation.ack)
	}
	generation, selection, pending, _ := policyTxUnitState(fixture.engine, fixture.selectorID)
	if generation != 5 || selection != fixture.targetA || pending {
		t.Fatalf("stale PREPARE mutated state: generation=%d selection=%x pending=%v", generation, selection, pending)
	}
}

func TestPolicyTransactionCrossedTransactionsAreBusy(t *testing.T) {
	t.Run("competing incoming transaction", func(t *testing.T) {
		fixture := newPolicyTxUnitFixture(t)
		first := policyTxUnitPrepare(fixture.engine, 6, 0, fixture.selectorID, fixture.targetB)
		firstAck := policyTxUnitRequireAck(t, fixture.recorder, func() error {
			return fixture.engine.handlePolicyPrepare(first)
		})
		crossed := policyTxUnitPrepare(fixture.engine, 7, 0, fixture.selectorID, fixture.targetA)
		busyPrepare := policyTxUnitRequireAck(t, fixture.recorder, func() error {
			return fixture.engine.handlePolicyPrepare(crossed)
		})
		if busyPrepare.ack.Phase != proto.PolicyAckPhasePrepare || busyPrepare.ack.Code != proto.PolicyAckCodeBusy {
			t.Fatalf("crossed PREPARE ACK=%+v", busyPrepare.ack)
		}
		busyCommit := policyTxUnitRequireAck(t, fixture.recorder, func() error {
			return fixture.engine.handlePolicyCommit(policyTxUnitCommit(t, crossed, firstAck.ack.Generation, firstAck.ack.ReservationID))
		})
		if busyCommit.ack.Phase != proto.PolicyAckPhaseFinal || busyCommit.ack.Code != proto.PolicyAckCodeBusy {
			t.Fatalf("crossed COMMIT ACK=%+v", busyCommit.ack)
		}
		final := policyTxUnitRequireAck(t, fixture.recorder, func() error {
			return fixture.engine.handlePolicyCommit(policyTxUnitCommit(t, first, firstAck.ack.Generation, firstAck.ack.ReservationID))
		})
		if final.ack.Code != proto.PolicyAckCodeAccept || final.ack.CurrentTargetID != fixture.targetB {
			t.Fatalf("original transaction did not retain ownership: %+v", final.ack)
		}
	})

	t.Run("opposite directions remain independent", func(t *testing.T) {
		fixture := newPolicyTxUnitFixture(t)
		outgoing := policyTxUnitPrepare(fixture.engine, 8, 0, fixture.selectorID, fixture.targetA)
		fixture.engine.policyStateMu.Lock()
		fixture.engine.policyOutgoing = &outgoingPolicyTransaction{prepare: outgoing}
		fixture.engine.policyStateMu.Unlock()

		incoming := policyTxUnitPrepare(fixture.engine, 9, 0, fixture.selectorID, fixture.targetB)
		ack := policyTxUnitRequireAck(t, fixture.recorder, func() error {
			return fixture.engine.handlePolicyPrepare(incoming)
		})
		if ack.ack.Code != proto.PolicyAckCodeAccept {
			t.Fatalf("outgoing transaction incorrectly made incoming owner busy: %+v", ack.ack)
		}
	})
}

func TestPolicyTransactionExpiryAndSupersededCommit(t *testing.T) {
	t.Run("expired prepare", func(t *testing.T) {
		fixture := newPolicyTxUnitFixture(t)
		prepare := policyTxUnitPrepare(fixture.engine, 10, 0, fixture.selectorID, fixture.targetB)
		prepareAck := policyTxUnitRequireAck(t, fixture.recorder, func() error {
			return fixture.engine.handlePolicyPrepare(prepare)
		})
		fixture.engine.policyStateMu.Lock()
		fixture.engine.policyIncoming.expires = time.Unix(0, 0)
		fixture.engine.policyStateMu.Unlock()

		commit := policyTxUnitCommit(t, prepare, prepareAck.ack.Generation, prepareAck.ack.ReservationID)
		expired := policyTxUnitRequireAck(t, fixture.recorder, func() error {
			return fixture.engine.handlePolicyCommit(commit)
		})
		if expired.ack.Phase != proto.PolicyAckPhaseFinal || expired.ack.Code != proto.PolicyAckCodeSuperseded {
			t.Fatalf("expired COMMIT ACK=%+v", expired.ack)
		}
		generation, selection, pending, completed := policyTxUnitState(fixture.engine, fixture.selectorID)
		if generation != 0 || selection != (proto.TargetID{}) || pending || completed != 1 || fixture.engine.ActivePath() != fixture.pathA {
			t.Fatalf("expired COMMIT state: generation=%d selection=%x pending=%v completed=%d active=%d", generation, selection, pending, completed, fixture.engine.ActivePath())
		}
	})

	t.Run("missing prepare", func(t *testing.T) {
		fixture := newPolicyTxUnitFixture(t)
		prepare := policyTxUnitPrepare(fixture.engine, 11, 0, fixture.selectorID, fixture.targetB)
		observation := policyTxUnitRequireAck(t, fixture.recorder, func() error {
			return fixture.engine.handlePolicyCommit(policyTxUnitCommit(t, prepare, 1, proto.PolicyReservationID{1}))
		})
		if observation.ack.Phase != proto.PolicyAckPhaseFinal || observation.ack.Code != proto.PolicyAckCodeSuperseded {
			t.Fatalf("unprepared COMMIT ACK=%+v", observation.ack)
		}
	})
}

func TestPolicyTransactionCompletedCacheIsBounded(t *testing.T) {
	engine := &Engine{policyCompleted: make(map[[16]byte]completedPolicyTransaction)}
	const extra = 3
	inserted := make([][16]byte, policyCompletedLimit+extra)
	engine.policyStateMu.Lock()
	for i := range inserted {
		inserted[i][0] = byte(i + 1)
		engine.rememberPolicyCompletedLocked(completedPolicyTransaction{
			prepare: proto.PolicyPrepare{PolicyTransactionBinding: proto.PolicyTransactionBinding{TransactionID: inserted[i]}},
			finalAck: proto.PolicyAck{
				Generation: uint64(i + 1),
			},
		})
	}
	engine.policyStateMu.Unlock()

	engine.policyStateMu.Lock()
	defer engine.policyStateMu.Unlock()
	if len(engine.policyCompleted) != policyCompletedLimit || len(engine.policyCompletedOrder) != policyCompletedLimit {
		t.Fatalf("completed cache map/order=%d/%d want %d/%d", len(engine.policyCompleted), len(engine.policyCompletedOrder), policyCompletedLimit, policyCompletedLimit)
	}
	for _, evicted := range inserted[:extra] {
		if _, ok := engine.policyCompleted[evicted]; ok {
			t.Fatalf("old completed transaction %x was not evicted", evicted)
		}
	}
	for i, want := range inserted[extra:] {
		if got := engine.policyCompletedOrder[i]; got != want {
			t.Fatalf("completed cache order[%d]=%x want %x", i, got, want)
		}
		if _, ok := engine.policyCompleted[want]; !ok {
			t.Fatalf("recent completed transaction %x was evicted", want)
		}
	}
}

func TestPolicyTransactionRejectsForeignGraphBinding(t *testing.T) {
	fixture := newPolicyTxUnitFixture(t)
	tests := []struct {
		name   string
		commit bool
		mutate func(*proto.PolicyTransactionBinding)
	}{
		{name: "session epoch", mutate: func(binding *proto.PolicyTransactionBinding) { binding.SessionEpoch[0] ^= 0xff }},
		{name: "sender direction", mutate: func(binding *proto.PolicyTransactionBinding) {
			binding.Direction = peerSenderDirection(fixture.engine.side)
		}},
		{name: "graph revision", mutate: func(binding *proto.PolicyTransactionBinding) { binding.GraphBinding.Revision++ }},
		{name: "graph digest", mutate: func(binding *proto.PolicyTransactionBinding) { binding.GraphBinding.Digest[0] ^= 0xff }},
		{name: "commit graph digest", commit: true, mutate: func(binding *proto.PolicyTransactionBinding) { binding.GraphBinding.Digest[1] ^= 0xff }},
	}
	for i, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepare := policyTxUnitPrepare(fixture.engine, byte(20+i), 0, fixture.selectorID, fixture.targetB)
			test.mutate(&prepare.PolicyTransactionBinding)
			var err error
			if test.commit {
				err = fixture.engine.handlePolicyCommit(policyTxUnitCommit(t, prepare, 1, proto.PolicyReservationID{1}))
			} else {
				err = fixture.engine.handlePolicyPrepare(prepare)
			}
			policyTxUnitRequireViolation(t, err)
		})
	}
	observations, err := fixture.recorder.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != 0 {
		t.Fatalf("foreign binding emitted %d ACKs", len(observations))
	}
	if generation, selection, pending, completed := policyTxUnitState(fixture.engine, fixture.selectorID); generation != 0 || selection != (proto.TargetID{}) || pending || completed != 0 {
		t.Fatalf("foreign binding changed state: generation=%d selection=%x pending=%v completed=%d", generation, selection, pending, completed)
	}
}

func TestPolicyTransactionRejectsNonImmediateSelectorChild(t *testing.T) {
	const (
		rootName = "policy-tx-nested-root"
		bondName = "policy-tx-nested-bond"
		nameA    = "policy-tx-nested-a"
		nameB    = "policy-tx-nested-b"
	)
	pathA := policyTxUnitNode(proto.GraphNodeKindPath, nameA)
	pathB := policyTxUnitNode(proto.GraphNodeKindPath, nameB)
	bond := policyTxUnitNode(proto.GraphNodeKindBond, bondName, pathB.ID)
	selector := policyTxUnitNode(proto.GraphNodeKindSelector, rootName, pathA.ID, bond.ID)
	manifest := proto.GraphManifest{
		RootID: selector.ID,
		Nodes:  []proto.GraphNode{selector, bond, pathA, pathB},
	}
	engine, recorder, paths, _ := newPolicyTxUnitEngine(t, manifest, selector.ID, nameA, nameB)

	descendant := policyTxUnitPrepare(engine, 30, 0, selector.ID, pathB.ID)
	rejected := policyTxUnitRequireAck(t, recorder, func() error {
		return engine.handlePolicyPrepare(descendant)
	})
	if rejected.ack.Phase != proto.PolicyAckPhasePrepare || rejected.ack.Code != proto.PolicyAckCodeReject {
		t.Fatalf("descendant target ACK=%+v", rejected.ack)
	}
	if _, _, pending, _ := policyTxUnitState(engine, selector.ID); pending {
		t.Fatal("non-immediate descendant reserved a transaction")
	}

	immediate := policyTxUnitPrepare(engine, 31, 0, selector.ID, bond.ID)
	prepareAck := policyTxUnitRequireAck(t, recorder, func() error {
		return engine.handlePolicyPrepare(immediate)
	})
	finalAck := policyTxUnitRequireAck(t, recorder, func() error {
		return engine.handlePolicyCommit(policyTxUnitCommit(t, immediate, prepareAck.ack.Generation, prepareAck.ack.ReservationID))
	})
	if finalAck.ack.Code != proto.PolicyAckCodeAccept || finalAck.ack.CurrentTargetID != bond.ID {
		t.Fatalf("immediate group target was not committed: %+v", finalAck.ack)
	}
	if finalAck.mode != dispatchBond || finalAck.activePath != paths[nameB] || finalAck.pathName != nameB {
		t.Fatalf("bond child was not applied before final ACK: mode=%d active=%d path=%q", finalAck.mode, finalAck.activePath, finalAck.pathName)
	}
}

func TestPolicyTransactionLocalDecisionSupersedesPreparedCommit(t *testing.T) {
	fixture := newPolicyTxUnitFixture(t)
	prepare := policyTxUnitPrepare(fixture.engine, 40, 0, fixture.selectorID, fixture.targetB)
	prepareAck := policyTxUnitRequireAck(t, fixture.recorder, func() error {
		return fixture.engine.handlePolicyPrepare(prepare)
	})
	if err := fixture.engine.SelectLocalTarget(fixture.selectorID, fixture.targetA, "local-wins"); err != nil {
		t.Fatalf("SelectLocalTarget: %v", err)
	}
	final := policyTxUnitRequireAck(t, fixture.recorder, func() error {
		return fixture.engine.handlePolicyCommit(policyTxUnitCommit(t, prepare, prepareAck.ack.Generation, prepareAck.ack.ReservationID))
	})
	if final.ack.Code != proto.PolicyAckCodeStale {
		t.Fatalf("stale remote COMMIT ACK=%+v", final.ack)
	}
	generation, selection, pending, _ := policyTxUnitState(fixture.engine, fixture.selectorID)
	if generation != 1 || selection != fixture.targetA || pending || fixture.engine.ActivePath() != fixture.pathA {
		t.Fatalf("remote COMMIT overwrote local decision: generation=%d selection=%x pending=%v active=%d", generation, selection, pending, fixture.engine.ActivePath())
	}
}

func TestPolicyTransactionProposalDigestPreventsExpiryABA(t *testing.T) {
	fixture := newPolicyTxUnitFixture(t)
	oldPrepare := policyTxUnitPrepare(fixture.engine, 41, 0, fixture.selectorID, fixture.targetB)
	oldAck := policyTxUnitRequireAck(t, fixture.recorder, func() error {
		return fixture.engine.handlePolicyPrepare(oldPrepare)
	})
	fixture.engine.policyStateMu.Lock()
	fixture.engine.policyIncoming.expires = time.Unix(0, 0)
	fixture.engine.expirePolicyIncomingLocked(fixture.engine.policyIncoming)
	fixture.engine.policyStateMu.Unlock()

	changed := oldPrepare
	changed.TargetID = fixture.targetA
	policyTxUnitRequireViolation(t, fixture.engine.handlePolicyPrepare(changed))

	oldCommit := policyTxUnitCommit(t, oldPrepare, oldAck.ack.Generation, oldAck.ack.ReservationID)
	final := policyTxUnitRequireAck(t, fixture.recorder, func() error {
		return fixture.engine.handlePolicyCommit(oldCommit)
	})
	if final.ack.Code != proto.PolicyAckCodeSuperseded {
		t.Fatalf("expired COMMIT ACK=%+v", final.ack)
	}
	if generation, selection, pending, _ := policyTxUnitState(fixture.engine, fixture.selectorID); generation != 0 || selection != (proto.TargetID{}) || pending {
		t.Fatalf("expired proposal mutated state: generation=%d selection=%x pending=%v", generation, selection, pending)
	}
}

func TestPolicyReservationPreventsExactCacheEvictionABA(t *testing.T) {
	fixture := newPolicyTxUnitFixture(t)
	oldPrepare := policyTxUnitPrepare(fixture.engine, 42, 0, fixture.selectorID, fixture.targetB)
	oldAck := policyTxUnitRequireAck(t, fixture.recorder, func() error {
		return fixture.engine.handlePolicyPrepare(oldPrepare)
	})
	fixture.engine.policyStateMu.Lock()
	fixture.engine.expirePolicyIncomingLocked(fixture.engine.policyIncoming)
	fixture.engine.policyStateMu.Unlock()

	for i := 0; i < policyCompletedLimit; i++ {
		stale := policyTxUnitPrepare(fixture.engine, byte(60+i), 99, fixture.selectorID, fixture.targetA)
		digest, err := stale.ProposalDigest()
		if err != nil {
			t.Fatal(err)
		}
		fixture.engine.policyStateMu.Lock()
		ack := fixture.engine.policyRejectLocked(stale.PolicyTransactionBinding, digest, proto.PolicyReservationID{}, proto.PolicyAckPhasePrepare, proto.PolicyAckCodeStale, 0, fixture.selectorID, "base generation is stale")
		fixture.engine.rememberPolicyCompletedLocked(completedPolicyTransaction{prepare: stale, digest: digest, prepareAck: ack})
		fixture.engine.policyStateMu.Unlock()
	}

	newPrepare := oldPrepare
	newAck := policyTxUnitRequireAck(t, fixture.recorder, func() error {
		return fixture.engine.handlePolicyPrepare(newPrepare)
	})
	if newAck.ack.ReservationID == oldAck.ack.ReservationID {
		t.Fatal("reaccepted proposal reused the expired owner reservation")
	}
	policyTxUnitRequireViolation(t, fixture.engine.handlePolicyCommit(policyTxUnitCommit(t, oldPrepare, oldAck.ack.Generation, oldAck.ack.ReservationID)))
	if generation, selection, pending, _ := policyTxUnitState(fixture.engine, fixture.selectorID); generation != 0 || selection != (proto.TargetID{}) || !pending {
		t.Fatalf("delayed old COMMIT changed new pending state: generation=%d selection=%x pending=%v", generation, selection, pending)
	}
	final := policyTxUnitRequireAck(t, fixture.recorder, func() error {
		return fixture.engine.handlePolicyCommit(policyTxUnitCommit(t, newPrepare, newAck.ack.Generation, newAck.ack.ReservationID))
	})
	if final.ack.Code != proto.PolicyAckCodeAccept || final.ack.CurrentTargetID != fixture.targetB {
		t.Fatalf("new proposal failed after ABA rejection: %+v", final.ack)
	}
}

func TestPolicyAckPhaseMailboxesCannotDisplaceFinalAck(t *testing.T) {
	fixture := newPolicyTxUnitFixture(t)
	peer := fixture.engine.peerGraphBinding()
	prepare := proto.PolicyPrepare{
		PolicyTransactionBinding: proto.PolicyTransactionBinding{
			SessionEpoch:  proto.SessionEpoch(fixture.engine.flowID),
			Direction:     peerSenderDirection(fixture.engine.side),
			GraphBinding:  proto.GraphBinding{Revision: peer.revision, Digest: peer.digest},
			TransactionID: [16]byte{90},
		},
		Action:     proto.PolicyActionSelectChild,
		SelectorID: fixture.selectorID,
		TargetID:   fixture.targetB,
	}
	digest, err := prepare.ProposalDigest()
	if err != nil {
		t.Fatal(err)
	}
	tx := &outgoingPolicyTransaction{
		prepare:     prepare,
		digest:      digest,
		prepareAcks: make(chan proto.PolicyAck, 1),
		finalAcks:   make(chan proto.PolicyAck, 1),
	}
	fixture.engine.policyStateMu.Lock()
	fixture.engine.policyOutgoing = tx
	fixture.engine.policyStateMu.Unlock()
	base := proto.PolicyAck{
		PolicyTransactionBinding: prepare.PolicyTransactionBinding,
		Code:                     proto.PolicyAckCodeAccept,
		Generation:               1,
		ProposalDigest:           digest,
		ReservationID:            proto.PolicyReservationID{1},
	}
	prepareAck := base
	prepareAck.Phase = proto.PolicyAckPhasePrepare
	finalAck := base
	finalAck.Phase = proto.PolicyAckPhaseFinal
	finalAck.CurrentGeneration = 1
	finalAck.CurrentTargetID = fixture.targetB
	for i := 0; i < 32; i++ {
		if err := fixture.engine.handlePolicyAck(prepareAck); err != nil {
			t.Fatal(err)
		}
	}
	if err := fixture.engine.handlePolicyAck(finalAck); err != nil {
		t.Fatal(err)
	}
	if len(tx.prepareAcks) != 1 || len(tx.finalAcks) != 1 {
		t.Fatalf("phase mailbox depths=%d/%d want=1/1", len(tx.prepareAcks), len(tx.finalAcks))
	}
}

func TestPolicyInboxCoalescesExactDuplicatePhase(t *testing.T) {
	e := &Engine{
		policyInbox:  make(chan policyMessage, 64),
		policyQueued: make(map[policyMessageKey]struct{}),
	}
	key := policyMessageKey{
		kind:          policyMessagePrepare,
		transactionID: [16]byte{91},
		digest:        proto.PolicyProposalDigest{1},
	}
	message := policyMessage{kind: policyMessagePrepare, key: key}
	for i := 0; i < 1024; i++ {
		if !e.enqueuePolicyMessageLocked(message) {
			t.Fatalf("duplicate %d was treated as inbox overflow", i)
		}
	}
	if got := len(e.policyInbox); got != 1 {
		t.Fatalf("coalesced inbox depth=%d want=1", got)
	}
	e.policyQueueMu.Lock()
	queued := len(e.policyQueued)
	e.policyQueueMu.Unlock()
	if queued != 1 || e.recvTerminal {
		t.Fatalf("coalesced state queued=%d terminal=%v", queued, e.recvTerminal)
	}
}

func TestPolicySelectedScopeDeathFallsBackWithoutSpin(t *testing.T) {
	pathA := policyTxUnitNode(proto.GraphNodeKindPath, "scope-fallback-a")
	pathB := policyTxUnitNode(proto.GraphNodeKindPath, "scope-selected-b")
	pathC := policyTxUnitNode(proto.GraphNodeKindPath, "scope-selected-c")
	bond := policyTxUnitNode(proto.GraphNodeKindBond, "scope-selected-bond", pathB.ID, pathC.ID)
	root := policyTxUnitNode(proto.GraphNodeKindSelector, "scope-root", pathA.ID, bond.ID)
	manifest := proto.GraphManifest{RootID: root.ID, Nodes: []proto.GraphNode{root, bond, pathA, pathB, pathC}}
	engine, _, paths, pathHandles := newPolicyTxUnitEngine(t, manifest, root.ID, pathA.Name, pathB.Name, pathC.Name)
	if err := engine.InitializePolicySelection(root.ID, pathA.ID, "initial"); err != nil {
		t.Fatal(err)
	}
	if err := engine.SelectLocalTarget(root.ID, bond.ID, "select-bond"); err != nil {
		t.Fatal(err)
	}
	if engine.Mode() != dispatchBond || engine.ActivePath() != paths[pathB.Name] {
		t.Fatalf("bond selection mode/active=%d/%d", engine.Mode(), engine.ActivePath())
	}
	pathHandles[pathB.Name].Fail(errors.New("selected bond path B failed"))
	waitPathDetached(t, engine, paths[pathB.Name])
	engine.markPayload()
	pathHandles[pathC.Name].Fail(errors.New("selected bond path C failed"))
	waitPathDetached(t, engine, paths[pathC.Name])
	if engine.ActivePath() != paths[pathA.Name] {
		t.Fatalf("fallback active=%d want=%d", engine.ActivePath(), paths[pathA.Name])
	}
	engine.pathsMu.RLock()
	scopeLen := len(engine.dispatchScope)
	scopeHasFallback := engine.dispatchScope[paths[pathA.Name]]
	engine.pathsMu.RUnlock()
	if scopeLen != 1 || !scopeHasFallback {
		t.Fatalf("recursive death fallback scope len=%d has-A=%v", scopeLen, scopeHasFallback)
	}
	done := make(chan error, 1)
	go func() {
		_, err := engine.SendData([]byte("fallback"))
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("bond dispatch spun after selected scope death")
	}
}

var _ transport.PathConn = (*policyTxUnitPath)(nil)
