package engine

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

const policyTxUnitRevision = 17

func TestPolicyCommitChallengeEntropyFailsClosed(t *testing.T) {
	want := bytes.Repeat([]byte{0xa5}, len(proto.PolicyCommitChallenge{}))
	challenge, err := readPolicyCommitChallenge(bytes.NewReader(want))
	if err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	if !bytes.Equal(challenge[:], want) {
		t.Fatalf("challenge=%x want=%x", challenge, want)
	}
	for _, test := range []struct {
		name   string
		reader *bytes.Reader
	}{
		{name: "all-zero", reader: bytes.NewReader(make([]byte, len(proto.PolicyCommitChallenge{})))},
		{name: "short", reader: bytes.NewReader(make([]byte, len(proto.PolicyCommitChallenge{})-1))},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := readPolicyCommitChallenge(test.reader); err == nil {
				t.Fatal("accepted invalid challenge entropy")
			}
		})
	}
	if _, err := readPolicyCommitChallenge(nil); err == nil {
		t.Fatal("accepted nil challenge entropy source")
	}
}

type policyTxUnitAckObservation struct {
	ack        proto.PolicyAck
	pathName   string
	activePath uint32
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
	name        string
	recorder    *policyTxUnitAckRecorder
	dataWrites  atomic.Uint64
	writeMu     sync.Mutex
	beforeWrite func([]byte)
	qualityMu   sync.RWMutex
	quality     transport.PathQuality
	qualityHook func()
	closed      chan struct{}
	closeOnce   sync.Once
	failed      chan struct{}
	failOnce    sync.Once
	failMu      sync.Mutex
	failErr     error
	deathMu     sync.Mutex
	deathFn     func(transport.DeathCause, error)
	deathOnce   sync.Once
	deathDone   chan struct{}
}

func newPolicyTxUnitPath(name string, recorder *policyTxUnitAckRecorder) *policyTxUnitPath {
	return &policyTxUnitPath{
		name: name, recorder: recorder,
		closed: make(chan struct{}), failed: make(chan struct{}), deathDone: make(chan struct{}),
	}
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
	p.writeMu.Lock()
	beforeWrite := p.beforeWrite
	p.writeMu.Unlock()
	if beforeWrite != nil {
		beforeWrite(frame)
	}
	if len(frame) >= proto.HeaderSize {
		if header, err := proto.DecodeHeader(frame[:proto.HeaderSize]); err == nil && header.Type == proto.FrameData {
			p.dataWrites.Add(1)
		}
	}
	p.recorder.record(p.name, frame)
	return len(frame), nil
}

func (p *policyTxUnitPath) SetBeforeWrite(fn func([]byte)) {
	p.writeMu.Lock()
	p.beforeWrite = fn
	p.writeMu.Unlock()
}

func (p *policyTxUnitPath) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return nil
}

func (p *policyTxUnitPath) Quality() transport.PathQuality {
	p.qualityMu.RLock()
	quality := p.quality
	hook := p.qualityHook
	p.qualityMu.RUnlock()
	if hook != nil {
		hook()
	}
	return quality
}

func (p *policyTxUnitPath) SetQuality(quality transport.PathQuality) {
	p.qualityMu.Lock()
	p.quality = quality
	p.qualityMu.Unlock()
}

func (p *policyTxUnitPath) SetQualityHook(hook func()) {
	p.qualityMu.Lock()
	p.qualityHook = hook
	p.qualityMu.Unlock()
}
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
		p.deathOnce.Do(func() {
			fn(transport.CauseTransportError, err)
			close(p.deathDone)
		})
	}
}

func waitPolicyTxUnitPathDeath(t *testing.T, path *policyTxUnitPath) {
	t.Helper()
	select {
	case <-path.deathDone:
	case <-time.After(time.Second):
		t.Fatal("policy path death callback did not complete")
	}
}

func policyTxZombieLeft(engine *Engine) int {
	engine.zombieMu.Lock()
	defer engine.zombieMu.Unlock()
	return engine.zombieLeft
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
	recorder := &policyTxUnitAckRecorder{engine: engine, selectorID: selectorID}
	paths := make(map[string]uint32, len(leafNames))
	pathHandles := make(map[string]*policyTxUnitPath, len(leafNames))
	for _, name := range leafNames {
		path := newPolicyTxUnitPath(name, recorder)
		node, ok := manifest.NodeByName(name)
		if !ok || node.Kind != proto.GraphNodeKindPath {
			t.Fatalf("manifest path %q is missing", name)
		}
		id, err := engine.AttachPathBound(path, transport.PathSpec{
			Transport: "policy-tx-unit",
			Address:   name,
			Opts:      map[string]string{"name": name},
		}, PathBinding{LocalTXTargetID: node.ID, PeerTXTargetID: node.ID})
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

func policyTxUnitClassPrepare(engine *Engine, txByte byte, base uint64, selectorID proto.TargetID, peak bool) proto.PolicyPrepare {
	prepare := policyTxUnitPrepare(engine, txByte, base, selectorID, proto.TargetID{})
	prepare.Action = proto.PolicyActionSelectBestNormal
	if peak {
		prepare.Action = proto.PolicyActionSelectBestPeak
	}
	return prepare
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
		CommitChallenge:          proto.PolicyCommitChallenge{0xa5, prepare.TransactionID[0]},
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
	if prepareAck.activePath != fixture.pathA || prepareAck.generation != 0 || prepareAck.selection != fixture.targetA ||
		prepareAck.ack.CurrentTargetID != fixture.targetA || !prepareAck.pending {
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
	if finalAck.ack.CommitChallenge != commit.CommitChallenge {
		t.Fatalf("final ACK challenge=%x want COMMIT challenge=%x", finalAck.ack.CommitChallenge, commit.CommitChallenge)
	}
	if finalAck.pathName != fixture.nameB || finalAck.activePath != fixture.pathB {
		t.Fatalf("final ACK was published before dispatch changed: path=%q active=%d want %q/%d", finalAck.pathName, finalAck.activePath, fixture.nameB, fixture.pathB)
	}
	if finalAck.generation != 1 || finalAck.selection != fixture.targetB || finalAck.pending || finalAck.completed != 1 {
		t.Fatalf("final ACK was published before transaction state committed: %+v", finalAck)
	}
}

func TestIncomingExactChildCommitOwnsBlockedDataBeforeFinalAck(t *testing.T) {
	const (
		rootName = "incoming-exact-cutover-root"
		nameA    = "incoming-exact-cutover-a"
		nameB    = "incoming-exact-cutover-b"
	)
	pathA := policyTxUnitNode(proto.GraphNodeKindPath, nameA)
	pathB := policyTxUnitNode(proto.GraphNodeKindPath, nameB)
	selector := policyTxUnitNode(proto.GraphNodeKindSelector, rootName, pathA.ID, pathB.ID)
	manifest := proto.GraphManifest{RootID: selector.ID, Nodes: []proto.GraphNode{selector, pathA, pathB}}
	e, recorder, paths, handles := newPolicyTxUnitEngine(t, manifest, selector.ID, nameA, nameB)
	prepare := policyTxUnitPrepare(e, 0x47, 0, selector.ID, pathB.ID)
	prepared := policyTxUnitRequireAck(t, recorder, func() error { return e.handlePolicyPrepare(prepare) })

	aStarted := make(chan struct{})
	bReplayStarted := make(chan struct{})
	releaseA := make(chan struct{})
	releaseB := make(chan struct{})
	var aStartOnce, bStartOnce, releaseAOnce, releaseBOnce sync.Once
	t.Cleanup(func() {
		releaseBOnce.Do(func() { close(releaseB) })
		releaseAOnce.Do(func() { close(releaseA) })
	})
	handles[nameA].SetBeforeWrite(func(frame []byte) {
		if len(frame) < proto.HeaderSize {
			return
		}
		header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
		if err != nil || header.Type != proto.FrameData {
			return
		}
		aStartOnce.Do(func() { close(aStarted) })
		<-releaseA
	})
	handles[nameB].SetBeforeWrite(func(frame []byte) {
		if len(frame) < proto.HeaderSize {
			return
		}
		header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
		if err != nil || header.Type != proto.FrameData {
			return
		}
		bStartOnce.Do(func() { close(bReplayStarted) })
		<-releaseB
	})

	writeDone := make(chan error, 1)
	go func() {
		_, err := e.SendData([]byte("incoming exact child owns this DATA"))
		writeDone <- err
	}()
	select {
	case <-aStarted:
	case <-time.After(time.Second):
		t.Fatal("DATA did not block on the former selected child")
	}

	commit := policyTxUnitCommit(t, prepare, prepared.ack.Generation, prepared.ack.ReservationID)
	commitDone := make(chan error, 1)
	go func() { commitDone <- e.handlePolicyCommit(commit) }()
	select {
	case <-bReplayStarted:
	case <-time.After(time.Second):
		t.Fatal("incoming exact-child commit did not replay blocked DATA on child B")
	}
	select {
	case writeErr := <-writeDone:
		if writeErr != nil {
			t.Fatalf("application write observed incoming cutover: %v", writeErr)
		}
	case <-time.After(time.Second):
		t.Fatal("application write did not transfer custody to incoming cutover")
	}
	observations, err := recorder.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, observation := range observations {
		if observation.ack.Phase == proto.PolicyAckPhaseFinal && observation.ack.Code == proto.PolicyAckCodeAccept {
			t.Fatal("successful FINAL overtook blocked DATA replay")
		}
	}

	releaseBOnce.Do(func() { close(releaseB) })
	select {
	case commitErr := <-commitDone:
		if commitErr != nil {
			t.Fatal(commitErr)
		}
	case <-time.After(time.Second):
		t.Fatal("incoming exact-child commit did not finish after replay")
	}
	observations, err = recorder.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	var final *policyTxUnitAckObservation
	for i := range observations {
		if observations[i].ack.Phase == proto.PolicyAckPhaseFinal {
			final = &observations[i]
		}
	}
	if final == nil || final.ack.Code != proto.PolicyAckCodeAccept || final.ack.CurrentTargetID != pathB.ID {
		t.Fatalf("final ACK=%+v want accepted child B", final)
	}
	if final.activePath != paths[nameB] || e.ActivePath() != paths[nameB] || handles[nameB].dataWrites.Load() == 0 {
		t.Fatalf("final route/active/B writes=%d/%d/%d want %d/%d/>0",
			final.activePath, e.ActivePath(), handles[nameB].dataWrites.Load(), paths[nameB], paths[nameB])
	}
	releaseAOnce.Do(func() { close(releaseA) })
}

func TestIncomingInactiveExactChildCommitRejectsTopologyEpochDrift(t *testing.T) {
	const (
		rootName  = "incoming-nested-epoch-root"
		innerName = "incoming-nested-epoch-inner"
		nameA     = "incoming-nested-epoch-a"
		nameB     = "incoming-nested-epoch-b"
		nameC     = "incoming-nested-epoch-c"
	)
	pathA := policyTxUnitNode(proto.GraphNodeKindPath, nameA)
	pathB := policyTxUnitNode(proto.GraphNodeKindPath, nameB)
	pathC := policyTxUnitNode(proto.GraphNodeKindPath, nameC)
	inner := policyTxUnitNode(proto.GraphNodeKindSelector, innerName, pathB.ID, pathC.ID)
	root := policyTxUnitNode(proto.GraphNodeKindSelector, rootName, pathA.ID, inner.ID)
	manifest := proto.GraphManifest{
		RootID: root.ID,
		Nodes:  []proto.GraphNode{root, inner, pathA, pathB, pathC},
	}
	e, recorder, paths, handles := newPolicyTxUnitEngine(t, manifest, root.ID, nameA, nameB, nameC)
	if active := e.ActivePath(); active != paths[nameA] {
		t.Fatalf("initial active=%d want A=%d", active, paths[nameA])
	}

	prepare := policyTxUnitPrepare(e, 0x48, 0, inner.ID, pathC.ID)
	prepared := policyTxUnitRequireAck(t, recorder, func() error { return e.handlePolicyPrepare(prepare) })

	admissionEntered := make(chan struct{})
	releaseAdmission := make(chan struct{})
	bDataStarted := make(chan struct{})
	releaseB := make(chan struct{})
	var admissionOnce, releaseAdmissionOnce, bDataOnce, releaseBOnce sync.Once
	t.Cleanup(func() {
		e.SetPeerPolicyAdmission(nil)
		releaseAdmissionOnce.Do(func() { close(releaseAdmission) })
		releaseBOnce.Do(func() { close(releaseB) })
	})
	e.SetPeerPolicyAdmission(func(selectorID, targetID proto.TargetID, cause string) error {
		admissionOnce.Do(func() { close(admissionEntered) })
		<-releaseAdmission
		return nil
	})
	handles[nameB].SetBeforeWrite(func(frame []byte) {
		if len(frame) < proto.HeaderSize {
			return
		}
		header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
		if err != nil || header.Type != proto.FrameData {
			return
		}
		bDataOnce.Do(func() { close(bDataStarted) })
		<-releaseB
	})

	commit := policyTxUnitCommit(t, prepare, prepared.ack.Generation, prepared.ack.ReservationID)
	commitDone := make(chan error, 1)
	go func() { commitDone <- e.handlePolicyCommit(commit) }()
	awaitSignal(t, admissionEntered, "incoming exact-child commit admission")

	handles[nameA].Fail(errors.New("injected root A death during admission"))
	waitPolicyTxUnitPathDeath(t, handles[nameA])
	eventuallyEngine(t, time.Second, func() bool { return e.ActivePath() == paths[nameB] })

	writeDone := make(chan error, 1)
	go func() {
		_, err := e.SendData([]byte("must remain owned by fallback B"))
		writeDone <- err
	}()
	awaitSignal(t, bDataStarted, "fallback B DATA dispatch")

	releaseAdmissionOnce.Do(func() { close(releaseAdmission) })
	select {
	case err := <-commitDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("stale incoming exact-child commit did not terminate")
	}
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("fallback B DATA custody returned an application error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("fallback B DATA did not transfer to replay-ledger custody")
	}
	if got := handles[nameB].dataWrites.Load(); got != 0 {
		t.Fatalf("fallback B completed %d physical DATA writes before release", got)
	}

	observations, err := recorder.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	var final *policyTxUnitAckObservation
	for i := range observations {
		if observations[i].ack.Phase == proto.PolicyAckPhaseFinal {
			final = &observations[i]
		}
	}
	if final == nil || final.ack.Code != proto.PolicyAckCodeReject {
		t.Fatalf("topology-stale FINAL=%+v want explicit rejection", final)
	}
	if final.ack.Code == proto.PolicyAckCodeAccept || final.ack.CurrentTargetID == pathC.ID {
		t.Fatalf("topology-stale commit published C: %+v", final.ack)
	}
	if got := handles[nameC].dataWrites.Load(); got != 0 {
		t.Fatalf("stale target C received %d DATA writes", got)
	}
	runtime := e.localExecutionRuntime()
	runtime.mu.Lock()
	innerDesired := runtime.selectors[inner.ID].desired
	runtime.mu.Unlock()
	if innerDesired != pathB.ID {
		t.Fatalf("inactive selector committed across topology drift: desired=%x want B=%x", innerDesired, pathB.ID)
	}

	releaseBOnce.Do(func() { close(releaseB) })
	eventuallyEngine(t, time.Second, func() bool { return handles[nameB].dataWrites.Load() > 0 })
}

func TestPolicyClassSelectionFreezesOwnerChoiceAndRejectsStaleCommit(t *testing.T) {
	const (
		nameA = "policy-class-a"
		nameB = "policy-class-b"
		nameP = "policy-class-peak"
	)
	pathA := policyTxUnitNode(proto.GraphNodeKindPath, nameA)
	pathB := policyTxUnitNode(proto.GraphNodeKindPath, nameB)
	pathP := policyTxUnitNode(proto.GraphNodeKindPath, nameP)
	selector := policyTxUnitNode(proto.GraphNodeKindSelector, "policy-class-root", pathA.ID, pathB.ID, pathP.ID)
	selector.PeakCandidates = []proto.TargetID{pathP.ID}
	manifest := proto.GraphManifest{RootID: selector.ID, Nodes: []proto.GraphNode{selector, pathA, pathB, pathP}}
	e, recorder, paths, handles := newPolicyTxUnitEngine(t, manifest, selector.ID, nameA, nameB, nameP)
	now := time.Now()
	handles[nameA].SetQuality(transport.PathQuality{RTT: 50 * time.Millisecond, At: now})
	handles[nameB].SetQuality(transport.PathQuality{RTT: 10 * time.Millisecond, At: now})
	handles[nameP].SetQuality(transport.PathQuality{RTT: time.Millisecond, At: now})

	prepare := policyTxUnitClassPrepare(e, 0x41, 0, selector.ID, false)
	first := policyTxUnitRequireAck(t, recorder, func() error { return e.handlePolicyPrepare(prepare) })
	if first.ack.Code != proto.PolicyAckCodeAccept || first.ack.ResolvedTargetID != pathB.ID ||
		first.ack.CurrentTargetID != pathA.ID || first.activePath != paths[nameA] {
		t.Fatalf("class PREPARE=%+v active=%d want frozen B with active A", first.ack, first.activePath)
	}

	// A retransmitted PREPARE must replay the original reservation even after
	// the quality order changes; silently resolving again would make COMMIT
	// ambiguous under the same proposal digest.
	handles[nameA].SetQuality(transport.PathQuality{RTT: time.Millisecond, At: now})
	handles[nameB].SetQuality(transport.PathQuality{RTT: 100 * time.Millisecond, At: now})
	replayed := policyTxUnitRequireAck(t, recorder, func() error { return e.handlePolicyPrepare(prepare) })
	if replayed.ack.ResolvedTargetID != pathB.ID || replayed.ack.ReservationID != first.ack.ReservationID ||
		replayed.ack.Generation != first.ack.Generation {
		t.Fatalf("duplicate PREPARE changed frozen result: first=%+v replay=%+v", first.ack, replayed.ack)
	}

	// The frozen target must still satisfy its class evidence at COMMIT. A stale
	// target is rejected rather than replaced behind the requester's back.
	handles[nameB].SetQuality(transport.PathQuality{RTT: 100 * time.Millisecond, At: now.Add(-time.Hour)})
	commit := policyTxUnitCommit(t, prepare, first.ack.Generation, first.ack.ReservationID)
	final := policyTxUnitRequireAck(t, recorder, func() error { return e.handlePolicyCommit(commit) })
	if final.ack.Code != proto.PolicyAckCodeReject || final.ack.ResolvedTargetID != (proto.TargetID{}) {
		t.Fatalf("stale class COMMIT=%+v want reject without resolved target", final.ack)
	}
	generation, selected, pending, _ := policyTxUnitState(e, selector.ID)
	if generation != 0 || selected != pathA.ID || pending || e.ActivePath() != paths[nameA] {
		t.Fatalf("rejected class COMMIT changed owner: generation=%d selected=%x pending=%t active=%d", generation, selected, pending, e.ActivePath())
	}
}

func TestPolicyClassSelectionCommitsExactPeakAndMarksHold(t *testing.T) {
	const (
		nameN = "policy-class-normal"
		nameP = "policy-class-peak"
	)
	normal := policyTxUnitNode(proto.GraphNodeKindPath, nameN)
	peak := policyTxUnitNode(proto.GraphNodeKindPath, nameP)
	selector := policyTxUnitNode(proto.GraphNodeKindSelector, "policy-class-peak-root", normal.ID, peak.ID)
	selector.PeakCandidates = []proto.TargetID{peak.ID}
	manifest := proto.GraphManifest{RootID: selector.ID, Nodes: []proto.GraphNode{selector, normal, peak}}
	e, recorder, paths, handles := newPolicyTxUnitEngine(t, manifest, selector.ID, nameN, nameP)
	now := time.Now()
	handles[nameN].SetQuality(transport.PathQuality{RTT: time.Millisecond, At: now})
	handles[nameP].SetQuality(transport.PathQuality{RTT: 20 * time.Millisecond, At: now})

	prepare := policyTxUnitClassPrepare(e, 0x42, 0, selector.ID, true)
	prepared := policyTxUnitRequireAck(t, recorder, func() error { return e.handlePolicyPrepare(prepare) })
	if prepared.ack.Code != proto.PolicyAckCodeAccept || prepared.ack.ResolvedTargetID != peak.ID {
		t.Fatalf("peak PREPARE=%+v", prepared.ack)
	}
	commit := policyTxUnitCommit(t, prepare, prepared.ack.Generation, prepared.ack.ReservationID)
	final := policyTxUnitRequireAck(t, recorder, func() error { return e.handlePolicyCommit(commit) })
	if final.ack.Code != proto.PolicyAckCodeAccept || final.ack.ResolvedTargetID != peak.ID ||
		final.ack.CurrentTargetID != peak.ID || e.ActivePath() != paths[nameP] {
		t.Fatalf("peak FINAL=%+v active=%d want peak=%d", final.ack, e.ActivePath(), paths[nameP])
	}
	runtime := e.localExecutionRuntime()
	runtime.mu.Lock()
	held := runtime.selectors[selector.ID] != nil && runtime.selectors[selector.ID].peakHeld
	runtime.mu.Unlock()
	if !held {
		t.Fatal("peer-owned peak commit did not establish selector peak hold")
	}
}

func TestPolicyPeakClassAdmissionFiltersBeforeOwnerRanking(t *testing.T) {
	const (
		normalName     = "policy-admission-normal"
		suppressedName = "policy-admission-suppressed"
		stableSlowName = "policy-admission-stable-slow"
		stableFastName = "policy-admission-stable-fast"
	)
	normal := policyTxUnitNode(proto.GraphNodeKindPath, normalName)
	suppressed := policyTxUnitNode(proto.GraphNodeKindPath, suppressedName)
	stableSlow := policyTxUnitNode(proto.GraphNodeKindPath, stableSlowName)
	stableFast := policyTxUnitNode(proto.GraphNodeKindPath, stableFastName)
	selector := policyTxUnitNode(
		proto.GraphNodeKindSelector, "policy-admission-root",
		normal.ID, suppressed.ID, stableSlow.ID, stableFast.ID,
	)
	selector.PeakCandidates = []proto.TargetID{suppressed.ID, stableSlow.ID, stableFast.ID}
	manifest := proto.GraphManifest{
		RootID: selector.ID, Nodes: []proto.GraphNode{selector, normal, suppressed, stableSlow, stableFast},
	}
	e, recorder, _, handles := newPolicyTxUnitEngine(
		t, manifest, selector.ID, normalName, suppressedName, stableSlowName, stableFastName,
	)
	now := time.Now()
	handles[normalName].SetQuality(transport.PathQuality{RTT: time.Millisecond, At: now})
	handles[suppressedName].SetQuality(transport.PathQuality{RTT: time.Millisecond, At: now})
	handles[stableSlowName].SetQuality(transport.PathQuality{RTT: 10 * time.Millisecond, LossPP: 10, At: now})
	handles[stableFastName].SetQuality(transport.PathQuality{RTT: 11 * time.Millisecond, At: now})
	e.SetPeerPolicyAdmission(func(_ proto.TargetID, targetID proto.TargetID, _ string) error {
		if targetID == suppressed.ID {
			return errors.New("candidate is capacity-suppressed")
		}
		return nil
	})

	prepare := policyTxUnitClassPrepare(e, 0x44, 0, selector.ID, true)
	prepared := policyTxUnitRequireAck(t, recorder, func() error { return e.handlePolicyPrepare(prepare) })
	if prepared.ack.Code != proto.PolicyAckCodeAccept || prepared.ack.ResolvedTargetID != stableFast.ID {
		t.Fatalf("peak PREPARE=%+v want stable candidate after pre-ranking suppression", prepared.ack)
	}
	e.policyStateMu.Lock()
	pending := e.policyIncoming
	e.policyStateMu.Unlock()
	if pending == nil || pending.decisionTopologyEpoch != e.currentPathTopologyEpoch() {
		t.Fatalf("class decision epoch=%v current=%d", pending, e.currentPathTopologyEpoch())
	}
}

func TestPolicyPeakClassCommitRejectsPreparedTopologyEpochDrift(t *testing.T) {
	const (
		normalName = "policy-class-epoch-normal"
		peakName   = "policy-class-epoch-peak"
	)
	normal := policyTxUnitNode(proto.GraphNodeKindPath, normalName)
	peak := policyTxUnitNode(proto.GraphNodeKindPath, peakName)
	selector := policyTxUnitNode(proto.GraphNodeKindSelector, "policy-class-epoch-root", normal.ID, peak.ID)
	selector.PeakCandidates = []proto.TargetID{peak.ID}
	manifest := proto.GraphManifest{RootID: selector.ID, Nodes: []proto.GraphNode{selector, normal, peak}}
	e, recorder, paths, handles := newPolicyTxUnitEngine(t, manifest, selector.ID, normalName, peakName)
	now := time.Now()
	handles[normalName].SetQuality(transport.PathQuality{RTT: time.Millisecond, At: now})
	handles[peakName].SetQuality(transport.PathQuality{RTT: 10 * time.Millisecond, At: now})

	prepare := policyTxUnitClassPrepare(e, 0x45, 0, selector.ID, true)
	prepared := policyTxUnitRequireAck(t, recorder, func() error { return e.handlePolicyPrepare(prepare) })
	if prepared.ack.Code != proto.PolicyAckCodeAccept || prepared.ack.ResolvedTargetID != peak.ID {
		t.Fatalf("peak PREPARE=%+v", prepared.ack)
	}
	e.pathsMu.Lock()
	peakSlot := e.paths[paths[peakName]]
	peakSlot.probeEndpointGen.Store(peakSlot.probeEndpointGen.Load() + 1)
	e.advancePathTopologyEpochLocked()
	e.pathsMu.Unlock()

	commit := policyTxUnitCommit(t, prepare, prepared.ack.Generation, prepared.ack.ReservationID)
	final := policyTxUnitRequireAck(t, recorder, func() error { return e.handlePolicyCommit(commit) })
	if final.ack.Code != proto.PolicyAckCodeReject || final.ack.ResolvedTargetID != (proto.TargetID{}) {
		t.Fatalf("topology-stale FINAL=%+v want rejection", final.ack)
	}
	generation, selected, pending, _ := policyTxUnitState(e, selector.ID)
	if generation != 0 || selected != normal.ID || pending || e.ActivePath() != paths[normalName] {
		t.Fatalf(
			"stale class commit changed owner generation=%d selected=%x pending=%t active=%d",
			generation, selected, pending, e.ActivePath(),
		)
	}
}

func TestCommittedPolicyCannotExpireDuringCutoverReplay(t *testing.T) {
	const (
		nameN = "policy-expiry-normal"
		nameP = "policy-expiry-peak"
	)
	normal := policyTxUnitNode(proto.GraphNodeKindPath, nameN)
	peak := policyTxUnitNode(proto.GraphNodeKindPath, nameP)
	selector := policyTxUnitNode(proto.GraphNodeKindSelector, "policy-expiry-root", normal.ID, peak.ID)
	selector.PeakCandidates = []proto.TargetID{peak.ID}
	manifest := proto.GraphManifest{RootID: selector.ID, Nodes: []proto.GraphNode{selector, normal, peak}}
	e, recorder, paths, handles := newPolicyTxUnitEngine(t, manifest, selector.ID, nameN, nameP)
	now := time.Now()
	handles[nameN].SetQuality(transport.PathQuality{RTT: time.Millisecond, At: now})
	handles[nameP].SetQuality(transport.PathQuality{RTT: 10 * time.Millisecond, At: now})

	primaryWriteEntered := make(chan struct{})
	releasePrimaryWrite := make(chan struct{})
	defer func() {
		select {
		case <-releasePrimaryWrite:
		default:
			close(releasePrimaryWrite)
		}
	}()
	var primaryWriteOnce sync.Once
	handles[nameN].SetBeforeWrite(func(frame []byte) {
		if len(frame) < proto.HeaderSize {
			return
		}
		header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
		if err != nil || header.Type != proto.FrameData {
			return
		}
		primaryWriteOnce.Do(func() { close(primaryWriteEntered) })
		<-releasePrimaryWrite
	})
	prepare := policyTxUnitClassPrepare(e, 0x43, 0, selector.ID, true)
	prepared := policyTxUnitRequireAck(t, recorder, func() error { return e.handlePolicyPrepare(prepare) })
	if prepared.ack.Code != proto.PolicyAckCodeAccept || prepared.ack.ResolvedTargetID != peak.ID {
		t.Fatalf("peak PREPARE=%+v", prepared.ack)
	}
	sendDone := make(chan error, 1)
	go func() {
		_, err := e.SendData([]byte("unacknowledged-before-policy-cutover"))
		sendDone <- err
	}()
	select {
	case <-primaryWriteEntered:
	case <-time.After(time.Second):
		t.Fatal("initial DATA did not block on the normal target")
	}

	replayEntered := make(chan struct{})
	releaseReplay := make(chan struct{})
	defer func() {
		select {
		case <-releaseReplay:
		default:
			close(releaseReplay)
		}
	}()
	var replayOnce sync.Once
	e.boundedReplayBeforeSnapshot = func() {
		replayOnce.Do(func() { close(replayEntered) })
		<-releaseReplay
	}
	commit := policyTxUnitCommit(t, prepare, prepared.ack.Generation, prepared.ack.ReservationID)
	commitDone := make(chan error, 1)
	go func() { commitDone <- e.handlePolicyCommit(commit) }()
	select {
	case <-replayEntered:
	case <-time.After(time.Second):
		t.Fatal("committed policy did not enter cutover replay")
	}

	e.expirePreparedPolicy(time.Now().Add(policyTransactionTTL))
	e.policyStateMu.Lock()
	pending := e.policyIncoming
	generation := e.policyGeneration
	selected := e.policySelections[selector.ID]
	completed := len(e.policyCompleted)
	e.policyStateMu.Unlock()
	if pending == nil || !pending.committed || generation != 1 || selected != peak.ID || completed != 0 {
		t.Fatalf("expiry changed committed replay state: pending=%+v generation=%d selected=%x completed=%d", pending, generation, selected, completed)
	}
	close(releaseReplay)
	select {
	case err := <-commitDone:
		if err != nil {
			t.Fatalf("handlePolicyCommit: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("policy commit did not finish after replay release")
	}
	close(releasePrimaryWrite)
	select {
	case err := <-sendDone:
		if err != nil {
			t.Fatalf("handed-off application write: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("handed-off application write did not return")
	}

	generation, selected, pendingExists, completed := policyTxUnitState(e, selector.ID)
	if generation != 1 || selected != peak.ID || pendingExists || completed != 1 || e.ActivePath() != paths[nameP] {
		t.Fatalf("final committed state generation=%d selected=%x pending=%t completed=%d active=%d", generation, selected, pendingExists, completed, e.ActivePath())
	}
}

func TestPeakPolicyObserverSeesCommittedTargetWhenCutoverReplayFails(t *testing.T) {
	const (
		nameNormal = "policy-observer-normal"
		namePeak   = "policy-observer-peak"
		cause      = "peak-transfer"
	)
	normal := policyTxUnitNode(proto.GraphNodeKindPath, nameNormal)
	peak := policyTxUnitNode(proto.GraphNodeKindPath, namePeak)
	selector := policyTxUnitNode(proto.GraphNodeKindSelector, "policy-observer-root", normal.ID, peak.ID)
	selector.PeakCandidates = []proto.TargetID{peak.ID}
	manifest := proto.GraphManifest{RootID: selector.ID, Nodes: []proto.GraphNode{selector, normal, peak}}
	e, _, paths, handles := newPolicyTxUnitEngine(t, manifest, selector.ID, nameNormal, namePeak)

	primaryWriteEntered := make(chan struct{})
	releasePrimaryWrite := make(chan struct{})
	var primaryWriteOnce, releasePrimaryOnce sync.Once
	t.Cleanup(func() { releasePrimaryOnce.Do(func() { close(releasePrimaryWrite) }) })
	handles[nameNormal].SetBeforeWrite(func(frame []byte) {
		if len(frame) < proto.HeaderSize {
			return
		}
		header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
		if err != nil || header.Type != proto.FrameData {
			return
		}
		primaryWriteOnce.Do(func() { close(primaryWriteEntered) })
		<-releasePrimaryWrite
	})

	sendDone := make(chan error, 1)
	go func() {
		_, err := e.SendData([]byte("unacknowledged-before-peak-cutover"))
		sendDone <- err
	}()
	select {
	case <-primaryWriteEntered:
	case <-time.After(time.Second):
		t.Fatal("initial DATA did not block on the normal target")
	}

	type peakObservation struct {
		selectorID proto.TargetID
		targetID   proto.TargetID
		peak       bool
		cause      string
	}
	observed := make(chan peakObservation, 2)
	e.SetPeakPolicyObserver(func(selectorID, targetID proto.TargetID, peak bool, cause string) {
		observed <- peakObservation{selectorID: selectorID, targetID: targetID, peak: peak, cause: cause}
	})

	replayInjected := make(chan struct{})
	var (
		replayOnce       sync.Once
		savedRuntime     *executionRuntime
		runtimeWithdrawn bool
	)
	restoreRuntime := func() {
		e.graphMu.Lock()
		if runtimeWithdrawn {
			e.localExec = savedRuntime
			runtimeWithdrawn = false
		}
		e.graphMu.Unlock()
	}
	defer restoreRuntime()
	e.boundedReplayBeforeSnapshot = func() {
		replayOnce.Do(func() {
			e.graphMu.Lock()
			savedRuntime = e.localExec
			e.localExec = nil
			runtimeWithdrawn = true
			e.graphMu.Unlock()
			close(replayInjected)
		})
	}

	err := e.SelectPeakTransferTarget(selector.ID, peak.ID, true, cause)
	restoreRuntime()
	releasePrimaryOnce.Do(func() { close(releasePrimaryWrite) })
	if !errors.Is(err, ErrPolicyOutcomeUnknown) {
		t.Fatalf("SelectPeakTransferTarget error=%v want %v", err, ErrPolicyOutcomeUnknown)
	}
	select {
	case <-replayInjected:
	default:
		t.Fatal("peak policy did not reach the injected post-commit replay failure")
	}
	select {
	case err := <-sendDone:
		if err != nil {
			t.Fatalf("handed-off application write: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("handed-off application write did not return")
	}

	generation, selected, pending, _ := policyTxUnitState(e, selector.ID)
	if generation != 1 || selected != peak.ID || pending || e.ActivePath() != paths[namePeak] {
		t.Fatalf("committed state generation=%d selected=%x pending=%t active=%d want generation=1 target=%x active=%d",
			generation, selected, pending, e.ActivePath(), peak.ID, paths[namePeak])
	}
	desired, effective, ok := savedRuntime.selectedChild(selector.ID)
	if !ok || desired != peak.ID || effective != peak.ID {
		t.Fatalf("committed runtime desired=%x effective=%x ok=%t want peak=%x", desired, effective, ok, peak.ID)
	}
	select {
	case got := <-observed:
		if got.selectorID != selector.ID || got.targetID != peak.ID || !got.peak || got.cause != cause {
			t.Fatalf("peak observation=%+v want selector=%x target=%x peak=true cause=%q", got, selector.ID, peak.ID, cause)
		}
	default:
		t.Fatal("committed peak policy was not observed after replay failure")
	}
	select {
	case got := <-observed:
		t.Fatalf("committed peak policy was observed more than once: %+v", got)
	default:
	}

	if err := e.selectLocalTarget(
		selector.ID, normal.ID, "probe-starved-data", policySelectionProbeStarvedData,
	); err != nil {
		t.Fatalf("factual peak departure: %v", err)
	}
	select {
	case got := <-observed:
		if got.selectorID != selector.ID || got.targetID != normal.ID || got.peak || got.cause != "probe-starved-data" {
			t.Fatalf("factual departure observation=%+v want selector=%x target=%x peak=false", got, selector.ID, normal.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("factual peak departure was not observed")
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
		if generation != 0 || selection != fixture.targetA || pending || completed != 1 || fixture.engine.ActivePath() != fixture.pathA {
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

func TestPolicyCommitCannotCrossReservationExpiryWhileWaitingForOwner(t *testing.T) {
	fixture := newPolicyTxUnitFixture(t)
	prepare := policyTxUnitPrepare(fixture.engine, 12, 0, fixture.selectorID, fixture.targetB)
	prepareAck := policyTxUnitRequireAck(t, fixture.recorder, func() error {
		return fixture.engine.handlePolicyPrepare(prepare)
	})
	commit := policyTxUnitCommit(t, prepare, prepareAck.ack.Generation, prepareAck.ack.ReservationID)

	fixture.engine.policyStateMu.Lock()
	fixture.engine.policyIncoming.expires = time.Now().Add(40 * time.Millisecond)
	expires := fixture.engine.policyIncoming.expires
	fixture.engine.policyStateMu.Unlock()
	reachedOwner := make(chan struct{})
	var reachedOnce sync.Once
	fixture.engine.policyCommitBeforeOwnerLock = func() {
		reachedOnce.Do(func() { close(reachedOwner) })
	}
	fixture.engine.policyOwnerMu.Lock()
	result := make(chan error, 1)
	go func() { result <- fixture.engine.handlePolicyCommit(commit) }()
	select {
	case <-reachedOwner:
	case <-time.After(time.Second):
		fixture.engine.policyOwnerMu.Unlock()
		t.Fatal("COMMIT did not pass its initial expiry check")
	}
	if wait := time.Until(expires) + time.Millisecond; wait > 0 {
		time.Sleep(wait)
	}
	fixture.engine.policyOwnerMu.Unlock()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("expired COMMIT remained blocked")
	}

	observations, err := fixture.recorder.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) < 2 {
		t.Fatalf("policy ACK observations=%d, want prepare and final", len(observations))
	}
	final := observations[len(observations)-1]
	if final.ack.Phase != proto.PolicyAckPhaseFinal || final.ack.Code != proto.PolicyAckCodeSuperseded {
		t.Fatalf("post-lock expiry ACK=%+v", final.ack)
	}
	generation, selection, pending, completed := policyTxUnitState(fixture.engine, fixture.selectorID)
	if generation != 0 || selection != fixture.targetA || pending || completed != 1 || fixture.engine.ActivePath() != fixture.pathA {
		t.Fatalf("expired COMMIT state: generation=%d selection=%x pending=%v completed=%d active=%d",
			generation, selection, pending, completed, fixture.engine.ActivePath())
	}
}

func TestSchedulerBookkeepingCannotOverwriteNewerExplicitSelection(t *testing.T) {
	fixture := newPolicyTxUnitFixture(t)
	runtime := fixture.engine.localExecutionRuntime()
	reachedCommit := make(chan struct{})
	releaseCommit := make(chan struct{})
	var hookOnce, releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseCommit) }) })
	fixture.engine.selectorDecisionAfterCommit = func() {
		hookOnce.Do(func() { close(reachedCommit) })
		<-releaseCommit
	}
	decisionDone := make(chan bool, 1)
	now := time.Now()
	go func() {
		decisionDone <- (&selector{}).applyRecursiveDecisions(fixture.engine, runtime, []selectorDecision{{
			selectorID: fixture.selectorID,
			targetID:   fixture.targetB,
			cause:      "quality",
			origin:     policySelectionQuality,
		}}, now)
	}()
	select {
	case <-reachedCommit:
	case <-time.After(time.Second):
		t.Fatal("scheduler decision did not reach committed bookkeeping")
	}
	explicitDone := make(chan error, 1)
	go func() {
		explicitDone <- fixture.engine.SelectExplicitTarget(fixture.selectorID, fixture.targetA, "explicit-newer")
	}()
	select {
	case err := <-explicitDone:
		t.Fatalf("explicit selection crossed scheduler bookkeeping: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(releaseCommit) })
	select {
	case <-decisionDone:
	case <-time.After(time.Second):
		t.Fatal("scheduler decision did not finish")
	}
	select {
	case err := <-explicitDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("newer explicit selection did not finish")
	}
	desired, effective, ok := runtime.selectedChild(fixture.selectorID)
	generation, selection, pending, _ := policyTxUnitState(fixture.engine, fixture.selectorID)
	if !ok || desired != fixture.targetA || effective != fixture.targetA || generation != 2 ||
		selection != fixture.targetA || pending || fixture.engine.ActivePath() != fixture.pathA {
		t.Fatalf("newer selection diverged: desired=%x effective=%x ok=%t generation=%d selection=%x pending=%t active=%d",
			desired, effective, ok, generation, selection, pending, fixture.engine.ActivePath())
	}
}

func TestSchedulerDecisionCannotCommitAcrossTopologyEpoch(t *testing.T) {
	fixture := newPolicyTxUnitFixture(t)
	runtime := fixture.engine.localExecutionRuntime()
	decisionEpoch := fixture.engine.currentPathTopologyEpoch()
	fixture.engine.pathsMu.Lock()
	fixture.engine.advancePathTopologyEpochLocked()
	fixture.engine.pathsMu.Unlock()

	beforeMigrations := fixture.engine.MigrationCount()
	applied := (&selector{}).applyRecursiveDecisions(
		fixture.engine,
		runtime,
		[]selectorDecision{{
			selectorID: fixture.selectorID, targetID: fixture.targetB,
			cause: "quality", origin: policySelectionQuality,
			topologyEpoch: decisionEpoch,
		}},
		time.Now(),
	)
	if applied {
		t.Fatal("stale quality decision was reported as a path-death commit")
	}
	desired, effective, _, ok := runtime.selectorSelection(fixture.selectorID)
	generation, selection, pending, completed := policyTxUnitState(fixture.engine, fixture.selectorID)
	cutoverPending, _ := fixture.engine.selectorCutoverSnapshot()
	if !ok || desired != fixture.targetA || effective != fixture.targetA ||
		generation != 0 || selection != fixture.targetA || pending || completed != 0 ||
		fixture.engine.ActivePath() != fixture.pathA || fixture.engine.MigrationCount() != beforeMigrations ||
		cutoverPending {
		t.Fatalf(
			"stale decision changed state desired/effective=%x/%x ok=%t generation=%d selection=%x pending/completed=%t/%d active=%d migrations=%d cutover=%t",
			desired, effective, ok, generation, selection, pending, completed,
			fixture.engine.ActivePath(), fixture.engine.MigrationCount(), cutoverPending,
		)
	}
}

func TestPeakTransferDecisionCannotCommitAcrossEndpointGeneration(t *testing.T) {
	const (
		normalName = "peak-epoch-normal"
		peakName   = "peak-epoch-candidate"
	)
	normal := policyTxUnitNode(proto.GraphNodeKindPath, normalName)
	peak := policyTxUnitNode(proto.GraphNodeKindPath, peakName)
	selector := policyTxUnitNode(proto.GraphNodeKindSelector, "peak-epoch-root", normal.ID, peak.ID)
	selector.PeakCandidates = []proto.TargetID{peak.ID}
	manifest := proto.GraphManifest{RootID: selector.ID, Nodes: []proto.GraphNode{selector, normal, peak}}
	e, _, paths, handles := newPolicyTxUnitEngine(t, manifest, selector.ID, normalName, peakName)
	now := time.Now()
	handles[normalName].SetQuality(transport.PathQuality{RTT: time.Millisecond, At: now})
	handles[peakName].SetQuality(transport.PathQuality{RTT: 10 * time.Millisecond, At: now})

	e.peakTransferDecisionBeforeCommit = func() {
		e.pathsMu.Lock()
		slot := e.paths[paths[peakName]]
		slot.probeEndpointGen.Store(slot.probeEndpointGen.Load() + 1)
		e.advancePathTopologyEpochLocked()
		e.pathsMu.Unlock()
	}
	beforeMigrations := e.MigrationCount()
	selected, err := e.SelectBestLocalPeakTransferTarget(selector.ID, nil, "peak-transfer")
	if !errors.Is(err, errStaleSelectorEvidence) || selected != (proto.TargetID{}) {
		t.Fatalf("selection=(%x,%v) want zero/%v", selected, err, errStaleSelectorEvidence)
	}
	desired, effective, _, ok := e.localExecutionRuntime().selectorSelection(selector.ID)
	generation, policyTarget, pending, completed := policyTxUnitState(e, selector.ID)
	if !ok || desired != normal.ID || effective != normal.ID || generation != 0 ||
		policyTarget != normal.ID || pending || completed != 0 || e.ActivePath() != paths[normalName] ||
		e.MigrationCount() != beforeMigrations {
		t.Fatalf(
			"stale peak decision changed state desired/effective=%x/%x ok=%t generation=%d target=%x pending/completed=%t/%d active=%d migrations=%d",
			desired, effective, ok, generation, policyTarget, pending, completed,
			e.ActivePath(), e.MigrationCount(),
		)
	}
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
	if generation, selection, pending, completed := policyTxUnitState(fixture.engine, fixture.selectorID); generation != 0 || selection != fixture.targetA || pending || completed != 0 {
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
	if finalAck.activePath != paths[nameB] || finalAck.pathName != nameB {
		t.Fatalf("bond child was not applied before final ACK: active=%d path=%q", finalAck.activePath, finalAck.pathName)
	}
	desired, effective, ok := engine.localExecutionRuntime().selectedChild(selector.ID)
	if !ok || desired != bond.ID || effective != bond.ID {
		t.Fatalf("committed selector state desired=%x effective=%x ok=%t", desired, effective, ok)
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
	if generation, selection, pending, _ := policyTxUnitState(fixture.engine, fixture.selectorID); generation != 0 || selection != fixture.targetA || pending {
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
		ack := fixture.engine.policyRejectLocked(stale.PolicyTransactionBinding, digest, proto.PolicyReservationID{}, proto.PolicyCommitChallenge{}, proto.PolicyAckPhasePrepare, proto.PolicyAckCodeStale, 0, fixture.selectorID, "base generation is stale")
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
	if generation, selection, pending, _ := policyTxUnitState(fixture.engine, fixture.selectorID); generation != 0 || selection != fixture.targetA || !pending {
		t.Fatalf("delayed old COMMIT changed new pending state: generation=%d selection=%x pending=%v", generation, selection, pending)
	}
	final := policyTxUnitRequireAck(t, fixture.recorder, func() error {
		return fixture.engine.handlePolicyCommit(policyTxUnitCommit(t, newPrepare, newAck.ack.Generation, newAck.ack.ReservationID))
	})
	if final.ack.Code != proto.PolicyAckCodeAccept || final.ack.CurrentTargetID != fixture.targetB {
		t.Fatalf("new proposal failed after ABA rejection: %+v", final.ack)
	}
}

func TestPolicyFinalAckRequiresCommitReceipt(t *testing.T) {
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
		ResolvedTargetID:         fixture.targetB,
		ProposalDigest:           digest,
		ReservationID:            proto.PolicyReservationID{1},
	}
	prepareAck := base
	prepareAck.Phase = proto.PolicyAckPhasePrepare
	finalAck := base
	finalAck.Phase = proto.PolicyAckPhaseFinal
	finalAck.CurrentGeneration = 1
	finalAck.CurrentTargetID = fixture.targetB
	finalAck.CommitChallenge = proto.PolicyCommitChallenge{0x44}
	for i := 0; i < 32; i++ {
		if err := fixture.engine.handlePolicyAck(prepareAck); err != nil {
			t.Fatal(err)
		}
	}
	if err := fixture.engine.handlePolicyAck(finalAck); err != nil {
		t.Fatal(err)
	}
	if len(tx.prepareAcks) != 1 || len(tx.finalAcks) != 0 {
		t.Fatalf("early FINAL mailbox depths=%d/%d want=1/0", len(tx.prepareAcks), len(tx.finalAcks))
	}
	fixture.engine.policyStateMu.Lock()
	tx.commitChallenge = finalAck.CommitChallenge
	tx.commitDispatched = true
	fixture.engine.policyStateMu.Unlock()
	changed := finalAck
	changed.CommitChallenge[1] = 1
	policyTxUnitRequireViolation(t, fixture.engine.handlePolicyAck(changed))
	if len(tx.finalAcks) != 0 {
		t.Fatal("mismatched FINAL entered the commit mailbox")
	}
	if err := fixture.engine.handlePolicyAck(finalAck); err != nil {
		t.Fatal(err)
	}
	if len(tx.prepareAcks) != 1 || len(tx.finalAcks) != 1 {
		t.Fatalf("bound phase mailbox depths=%d/%d want=1/1", len(tx.prepareAcks), len(tx.finalAcks))
	}
}

func TestPolicyInboxCoalescesExactDuplicatePhase(t *testing.T) {
	e := &Engine{
		policyInbox:  make(chan policyMessage, 64),
		policyQueued: make(map[policyMessageKey]struct{}),
	}
	key := policyMessageKey{
		kind: policyMessagePrepare, seq: 91,
		frameDigest: proto.FrameDigest{1},
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

func TestPolicyInboxDoesNotCoalesceDifferentFrameReceipt(t *testing.T) {
	e := &Engine{
		policyInbox:  make(chan policyMessage, 2),
		policyQueued: make(map[policyMessageKey]struct{}),
	}
	first := policyMessage{
		kind: policyMessageCommit,
		key:  policyMessageKey{kind: policyMessageCommit, seq: 7, frameDigest: proto.FrameDigest{1}},
	}
	second := first
	second.key.frameDigest[0] = 2
	if !e.enqueuePolicyMessageLocked(first) || !e.enqueuePolicyMessageLocked(second) {
		t.Fatal("distinct policy frame receipt was rejected")
	}
	if got := len(e.policyInbox); got != 2 {
		t.Fatalf("distinct policy receipts coalesced to depth=%d", got)
	}
}

func TestCompletedPolicyCommitRejectsChangedReservation(t *testing.T) {
	fixture := newPolicyTxUnitFixture(t)
	prepare := policyTxUnitPrepare(fixture.engine, 0x92, 0, fixture.selectorID, fixture.targetB)
	prepared := policyTxUnitRequireAck(t, fixture.recorder, func() error {
		return fixture.engine.handlePolicyPrepare(prepare)
	})
	commit := policyTxUnitCommit(t, prepare, prepared.ack.Generation, prepared.ack.ReservationID)
	policyTxUnitRequireAck(t, fixture.recorder, func() error {
		return fixture.engine.handlePolicyCommit(commit)
	})
	commit.ReservationID[0] ^= 0xff
	policyTxUnitRequireViolation(t, fixture.engine.handlePolicyCommit(commit))
}

func TestCompletedPolicyCommitRejectsChangedChallenge(t *testing.T) {
	fixture := newPolicyTxUnitFixture(t)
	prepare := policyTxUnitPrepare(fixture.engine, 0x93, 0, fixture.selectorID, fixture.targetB)
	prepared := policyTxUnitRequireAck(t, fixture.recorder, func() error {
		return fixture.engine.handlePolicyPrepare(prepare)
	})
	commit := policyTxUnitCommit(t, prepare, prepared.ack.Generation, prepared.ack.ReservationID)
	policyTxUnitRequireAck(t, fixture.recorder, func() error {
		return fixture.engine.handlePolicyCommit(commit)
	})
	commit.CommitChallenge[31] ^= 1
	policyTxUnitRequireViolation(t, fixture.engine.handlePolicyCommit(commit))
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
	if engine.ActivePath() != paths[pathB.Name] {
		t.Fatalf("bond selection active=%d want=%d", engine.ActivePath(), paths[pathB.Name])
	}
	type zombieObservation struct {
		active        uint32
		beforePayload int
		afterPayload  int
	}
	payloadObserved := make(chan zombieObservation, 1)
	cancelDeathHook := engine.OnPathDeathSerial(func(event PathDeathEvent) {
		if event.ID != paths[pathB.Name] {
			return
		}
		observation := zombieObservation{
			active:        engine.ActivePath(),
			beforePayload: policyTxZombieLeft(engine),
		}
		// Model application payload arriving as soon as the committed fallback
		// topology becomes observable. This is the former late-accounting gap.
		engine.markPayload()
		observation.afterPayload = policyTxZombieLeft(engine)
		payloadObserved <- observation
	})
	defer cancelDeathHook()

	pathHandles[pathB.Name].Fail(errors.New("selected bond path B failed"))
	waitPolicyTxUnitPathDeath(t, pathHandles[pathB.Name])
	observation := <-payloadObserved
	if observation.active != paths[pathC.Name] {
		t.Fatalf("first fallback active at payload=%d want=%d", observation.active, paths[pathC.Name])
	}
	if want := engine.limits.ZombieMaxMigrations - 1; observation.beforePayload != want {
		t.Fatalf("first migration accounting at publication=%d want=%d", observation.beforePayload, want)
	}
	if observation.afterPayload != engine.limits.ZombieMaxMigrations {
		t.Fatalf("payload credit=%d want=%d", observation.afterPayload, engine.limits.ZombieMaxMigrations)
	}
	if got := policyTxZombieLeft(engine); got != engine.limits.ZombieMaxMigrations {
		t.Fatalf("payload credit overwritten after first migration: got=%d want=%d", got, engine.limits.ZombieMaxMigrations)
	}

	pathHandles[pathC.Name].Fail(errors.New("selected bond path C failed"))
	waitPolicyTxUnitPathDeath(t, pathHandles[pathC.Name])
	if engine.ActivePath() != paths[pathA.Name] {
		t.Fatalf("fallback active=%d want=%d", engine.ActivePath(), paths[pathA.Name])
	}
	if got, want := policyTxZombieLeft(engine), engine.limits.ZombieMaxMigrations-1; got != want {
		t.Fatalf("second fallback zombie credit=%d want=%d", got, want)
	}
	if err := engine.CloseErr(); err != nil {
		t.Fatalf("second fallback closed after credited payload: %v", err)
	}
	engine.pathsMu.RLock()
	projected := engine.localExecutionRuntime().effectiveLeafTargets(engine.attachedLeafTargetsLocked())
	engine.pathsMu.RUnlock()
	if len(projected) != 1 || !projected[pathA.ID] {
		t.Fatalf("recursive death fallback leaves=%v want only A", projected)
	}
	writesBefore := pathHandles[pathA.Name].dataWrites.Load()
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
	deadline := time.Now().Add(time.Second)
	for pathHandles[pathA.Name].dataWrites.Load() <= writesBefore && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if writes := pathHandles[pathA.Name].dataWrites.Load(); writes <= writesBefore {
		t.Fatalf("fallback DATA did not reach A after cutover handoff: writes %d -> %d", writesBefore, writes)
	}
}

func TestPolicySelectedScopeTwoDeathsWithoutPayloadTripsZombie(t *testing.T) {
	pathA := policyTxUnitNode(proto.GraphNodeKindPath, "zombie-fallback-a")
	pathB := policyTxUnitNode(proto.GraphNodeKindPath, "zombie-selected-b")
	pathC := policyTxUnitNode(proto.GraphNodeKindPath, "zombie-selected-c")
	bond := policyTxUnitNode(proto.GraphNodeKindBond, "zombie-selected-bond", pathB.ID, pathC.ID)
	root := policyTxUnitNode(proto.GraphNodeKindSelector, "zombie-root", pathA.ID, bond.ID)
	manifest := proto.GraphManifest{RootID: root.ID, Nodes: []proto.GraphNode{root, bond, pathA, pathB, pathC}}
	engine, _, paths, pathHandles := newPolicyTxUnitEngine(t, manifest, root.ID, pathA.Name, pathB.Name, pathC.Name)
	if err := engine.InitializePolicySelection(root.ID, pathA.ID, "initial"); err != nil {
		t.Fatal(err)
	}
	if err := engine.SelectLocalTarget(root.ID, bond.ID, "select-bond"); err != nil {
		t.Fatal(err)
	}

	type zombieObservation struct {
		active uint32
		left   int
	}
	secondMigration := make(chan zombieObservation, 1)
	cancelDeathHook := engine.OnPathDeathSerial(func(event PathDeathEvent) {
		if event.ID == paths[pathC.Name] {
			secondMigration <- zombieObservation{active: engine.ActivePath(), left: policyTxZombieLeft(engine)}
		}
	})
	defer cancelDeathHook()

	pathHandles[pathB.Name].Fail(errors.New("first no-payload path failure"))
	waitPolicyTxUnitPathDeath(t, pathHandles[pathB.Name])
	if got := engine.ActivePath(); got != paths[pathC.Name] {
		t.Fatalf("first no-payload fallback active=%d want=%d", got, paths[pathC.Name])
	}
	if got, want := policyTxZombieLeft(engine), engine.limits.ZombieMaxMigrations-1; got != want {
		t.Fatalf("first no-payload migration accounting=%d want=%d", got, want)
	}

	pathHandles[pathC.Name].Fail(errors.New("second no-payload path failure"))
	waitPolicyTxUnitPathDeath(t, pathHandles[pathC.Name])
	observation := <-secondMigration
	if observation.active != paths[pathA.Name] {
		t.Fatalf("second no-payload fallback active at commit=%d want=%d", observation.active, paths[pathA.Name])
	}
	if observation.left != 0 {
		t.Fatalf("second no-payload migration accounting=%d want=0", observation.left)
	}
	select {
	case <-engine.closed:
	case <-time.After(time.Second):
		t.Fatal("two no-payload migrations did not close the zombie engine")
	}
	if err := engine.CloseErr(); !errors.Is(err, ErrZombie) {
		t.Fatalf("two no-payload migrations close error=%v want=%v", err, ErrZombie)
	}
}

var _ transport.PathConn = (*policyTxUnitPath)(nil)
