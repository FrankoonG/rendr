package engine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type leafMobilityEngineFixture struct {
	client, server       *Engine
	clientRef, serverRef PathRef
	clientWire           *memoryPathConn
	serverWire           *memoryPathConn
	clientClaim          *leafmobility.Claim
	serverClaim          *leafmobility.Claim
	clientDriver         *enginePlanDriver
	serverDriver         *enginePlanDriver
	clientResource       leafmobility.Resource
	serverResource       leafmobility.Resource
	binding              PathBinding
	ids                  map[string]proto.TargetID
}

type blockPreparedAckPath struct {
	transport.PathConn
	reached chan struct{}
	release chan struct{}
	once    sync.Once
}

func (p *blockPreparedAckPath) Write(frame []byte) (int, error) {
	n, err := p.PathConn.Write(frame)
	if err == nil && leafMobilityAckPhase(frame) == proto.LeafMobilityPeerPlanAckPhasePrepared {
		p.once.Do(func() { close(p.reached) })
		<-p.release
	}
	return n, err
}

type rerouteFinalAckPath struct {
	base   *memoryPathConn
	target **memoryPathConn
}

type dropLeafAckOncePath struct {
	transport.PathConn
	phase   proto.LeafMobilityPeerPlanAckPhase
	dropped atomic.Bool
	mu      sync.Mutex
	seqs    []uint64
}

type failLeafAckPath struct {
	transport.PathConn
	phase proto.LeafMobilityPeerPlanAckPhase
	err   error
}

type dropLeafAckPath struct {
	transport.PathConn
	phase proto.LeafMobilityPeerPlanAckPhase
}

type delayLeafCommitPath struct {
	base     *memoryPathConn
	captured chan []byte
	dropped  atomic.Bool
}

type blockLeafWritePath struct {
	transport.PathConn
	reached chan struct{}
	release chan struct{}
	once    sync.Once
}

type blockLeafResolutionPath struct {
	transport.PathConn
	reached chan struct{}
	release chan struct{}
	once    sync.Once
	writes  atomic.Uint32
}

type forwardThenBlockLeafResolutionPath struct {
	transport.PathConn
	reached chan struct{}
	release chan struct{}
	once    sync.Once
}

type dropLeafPreparePath struct {
	transport.PathConn
	dropped chan struct{}
	once    sync.Once
}

type forwardThenBlockLeafPreparePath struct {
	transport.PathConn
	reached chan struct{}
	release chan struct{}
	once    sync.Once
}

type closeUnblocksLeafWritePath struct {
	transport.PathConn
	reached   chan struct{}
	release   chan struct{}
	writeOnce sync.Once
	closeOnce sync.Once
}

type captureLeafPreparePath struct {
	transport.PathConn
	mu    sync.Mutex
	frame []byte
}

type captureLeafAckPath struct {
	transport.PathConn
	mu     sync.Mutex
	frames [][]byte
}

type captureLeafOOBPath struct {
	transport.PathConn
	mu     sync.Mutex
	frames [][]byte
}

func (p *captureLeafOOBPath) Write(frame []byte) (int, error) {
	if len(frame) >= proto.HeaderSize {
		header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
		if err == nil && header.Type == proto.FrameCtrl {
			switch proto.CtrlCodeFromFlags(header.Flags) {
			case proto.CtrlLeafMobilityPrepare, proto.CtrlLeafMobilityAck, proto.CtrlLeafMobilityCommit:
				p.mu.Lock()
				p.frames = append(p.frames, append([]byte(nil), frame...))
				p.mu.Unlock()
			}
		}
	}
	return p.PathConn.Write(frame)
}

func (p *dropLeafAckPath) Write(frame []byte) (int, error) {
	if leafMobilityAckPhase(frame) == p.phase {
		return len(frame), nil
	}
	return p.PathConn.Write(frame)
}

func (p *captureLeafOOBPath) captured() [][]byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	frames := make([][]byte, len(p.frames))
	for index := range p.frames {
		frames[index] = append([]byte(nil), p.frames[index]...)
	}
	return frames
}

func (p *captureLeafAckPath) Write(frame []byte) (int, error) {
	if leafMobilityAckPhase(frame) != proto.LeafMobilityPeerPlanAckPhaseInvalid {
		p.mu.Lock()
		p.frames = append(p.frames, append([]byte(nil), frame...))
		p.mu.Unlock()
		return len(frame), nil
	}
	return p.PathConn.Write(frame)
}

func (p *captureLeafAckPath) captured() [][]byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	frames := make([][]byte, len(p.frames))
	for index := range p.frames {
		frames[index] = append([]byte(nil), p.frames[index]...)
	}
	return frames
}

func (p *captureLeafPreparePath) Write(frame []byte) (int, error) {
	if len(frame) >= proto.HeaderSize {
		header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
		if err == nil && header.Type == proto.FrameCtrl && proto.CtrlCodeFromFlags(header.Flags) == proto.CtrlLeafMobilityPrepare {
			p.mu.Lock()
			p.frame = append([]byte(nil), frame...)
			p.mu.Unlock()
		}
	}
	return p.PathConn.Write(frame)
}

func (p *captureLeafPreparePath) captured() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]byte(nil), p.frame...)
}

func (p *blockLeafWritePath) Write(frame []byte) (int, error) {
	p.once.Do(func() { close(p.reached) })
	<-p.release
	return p.PathConn.Write(frame)
}

func (p *blockLeafResolutionPath) Write(frame []byte) (int, error) {
	if leafMobilityCommitStage(frame) == proto.LeafMobilityPeerPlanCommitStageRolledBack {
		p.writes.Add(1)
		p.once.Do(func() { close(p.reached) })
		<-p.release
	}
	return p.PathConn.Write(frame)
}

func (p *forwardThenBlockLeafResolutionPath) Write(frame []byte) (int, error) {
	if leafMobilityCommitStage(frame) != proto.LeafMobilityPeerPlanCommitStageRolledBack {
		return p.PathConn.Write(frame)
	}
	n, err := p.PathConn.Write(frame)
	p.once.Do(func() { close(p.reached) })
	<-p.release
	return n, err
}

func (p *dropLeafPreparePath) Write(frame []byte) (int, error) {
	if len(frame) >= proto.HeaderSize {
		header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
		if err == nil && header.Type == proto.FrameCtrl && proto.CtrlCodeFromFlags(header.Flags) == proto.CtrlLeafMobilityPrepare {
			p.once.Do(func() { close(p.dropped) })
			return len(frame), nil
		}
	}
	return p.PathConn.Write(frame)
}

func (p *forwardThenBlockLeafPreparePath) Write(frame []byte) (int, error) {
	if len(frame) < proto.HeaderSize {
		return p.PathConn.Write(frame)
	}
	header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	if err != nil || header.Type != proto.FrameCtrl || proto.CtrlCodeFromFlags(header.Flags) != proto.CtrlLeafMobilityPrepare {
		return p.PathConn.Write(frame)
	}
	n, writeErr := p.PathConn.Write(frame)
	p.once.Do(func() { close(p.reached) })
	<-p.release
	return n, writeErr
}

func (p *closeUnblocksLeafWritePath) Write(frame []byte) (int, error) {
	p.writeOnce.Do(func() { close(p.reached) })
	<-p.release
	return 0, net.ErrClosed
}

func (p *closeUnblocksLeafWritePath) Close() error {
	p.closeOnce.Do(func() { close(p.release) })
	return p.PathConn.Close()
}

func (p *dropLeafAckOncePath) Write(frame []byte) (int, error) {
	if leafMobilityAckPhase(frame) == p.phase {
		if header, err := proto.DecodeHeader(frame[:proto.HeaderSize]); err == nil {
			p.mu.Lock()
			p.seqs = append(p.seqs, header.Seq)
			p.mu.Unlock()
		}
		if p.dropped.CompareAndSwap(false, true) {
			return len(frame), nil
		}
	}
	return p.PathConn.Write(frame)
}

func (p *failLeafAckPath) Write(frame []byte) (int, error) {
	if leafMobilityAckPhase(frame) == p.phase {
		return 0, p.err
	}
	return p.PathConn.Write(frame)
}

func (p *dropLeafAckOncePath) recordedSeqs() []uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]uint64(nil), p.seqs...)
}

func (p *delayLeafCommitPath) Read(buf []byte) (int, error)                 { return p.base.Read(buf) }
func (p *delayLeafCommitPath) Close() error                                 { return p.base.Close() }
func (p *delayLeafCommitPath) Quality() transport.PathQuality               { return p.base.Quality() }
func (p *delayLeafCommitPath) OnDeath(fn func(transport.DeathCause, error)) { p.base.OnDeath(fn) }
func (p *delayLeafCommitPath) LocalAddr() string                            { return p.base.LocalAddr() }
func (p *delayLeafCommitPath) RemoteAddr() string                           { return p.base.RemoteAddr() }

func (p *delayLeafCommitPath) Write(frame []byte) (int, error) {
	if leafMobilityCommitStage(frame) == proto.LeafMobilityPeerPlanCommitStageCommit && p.dropped.CompareAndSwap(false, true) {
		p.captured <- append([]byte(nil), frame...)
		return len(frame), nil
	}
	return p.base.Write(frame)
}

func (p *rerouteFinalAckPath) Read(buf []byte) (int, error)                 { return p.base.Read(buf) }
func (p *rerouteFinalAckPath) Close() error                                 { return p.base.Close() }
func (p *rerouteFinalAckPath) Quality() transport.PathQuality               { return p.base.Quality() }
func (p *rerouteFinalAckPath) OnDeath(fn func(transport.DeathCause, error)) { p.base.OnDeath(fn) }
func (p *rerouteFinalAckPath) LocalAddr() string                            { return p.base.LocalAddr() }
func (p *rerouteFinalAckPath) RemoteAddr() string                           { return p.base.RemoteAddr() }

func (p *rerouteFinalAckPath) Write(frame []byte) (int, error) {
	if leafMobilityAckPhase(frame) == proto.LeafMobilityPeerPlanAckPhaseFinal && p.target != nil && *p.target != nil {
		copyOfFrame := append([]byte(nil), frame...)
		select {
		case (*p.target).in <- copyOfFrame:
			return len(frame), nil
		case <-(*p.target).closed:
			return 0, io.ErrClosedPipe
		}
	}
	return p.base.Write(frame)
}

func leafMobilityAckPhase(frame []byte) proto.LeafMobilityPeerPlanAckPhase {
	if len(frame) < proto.HeaderSize {
		return proto.LeafMobilityPeerPlanAckPhaseInvalid
	}
	header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	if err != nil || header.Type != proto.FrameCtrl || proto.CtrlCodeFromFlags(header.Flags) != proto.CtrlLeafMobilityAck {
		return proto.LeafMobilityPeerPlanAckPhaseInvalid
	}
	ack, err := proto.DecodeLeafMobilityPeerPlanAck(frame[proto.HeaderSize:])
	if err != nil {
		return proto.LeafMobilityPeerPlanAckPhaseInvalid
	}
	return ack.Phase
}

func leafMobilityCommitStage(frame []byte) proto.LeafMobilityPeerPlanCommitStage {
	if len(frame) < proto.HeaderSize {
		return proto.LeafMobilityPeerPlanCommitStageInvalid
	}
	header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	if err != nil || header.Type != proto.FrameCtrl || proto.CtrlCodeFromFlags(header.Flags) != proto.CtrlLeafMobilityCommit {
		return proto.LeafMobilityPeerPlanCommitStageInvalid
	}
	commit, err := proto.DecodeLeafMobilityPeerPlanCommit(frame[proto.HeaderSize:])
	if err != nil {
		return proto.LeafMobilityPeerPlanCommitStageInvalid
	}
	return commit.Stage
}

func TestEngineLeafMobilityAuthorityRequiresRealPeerTransaction(t *testing.T) {
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xa1)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
	if err != nil {
		t.Fatal(err)
	}
	if authority.State() != leafmobility.ResourceTransactionFinalAccepted || fixture.clientClaim.ExecutionGeneration() != 1 {
		t.Fatalf("authority=%d generation=%d", authority.State(), fixture.clientClaim.ExecutionGeneration())
	}
	permit, err := authority.Consume()
	if err != nil {
		t.Fatal(err)
	}
	if err := permit.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.client.SendData([]byte("after-authority")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, err := fixture.server.Recv(buf)
	if err != nil || string(buf[:n]) != "after-authority" {
		t.Fatalf("post-transaction data=%q err=%v", buf[:n], err)
	}
}

func TestEngineLeafMobilityConsumeRejectsChangedRouteGeneration(t *testing.T) {
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xa2)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
	if err != nil {
		t.Fatal(err)
	}
	fixture.client.pathsMu.Lock()
	slot := fixture.client.paths[fixture.clientRef.ID]
	slot.routeGeneration.Store(slot.routeGeneration.Load() + 1)
	fixture.client.pathsMu.Unlock()
	if _, err := authority.Consume(); !errors.Is(err, ErrStalePathRef) {
		t.Fatalf("Consume after route generation change=%v want=%v", err, ErrStalePathRef)
	}
	if authority.State() != leafmobility.ResourceTransactionOutcomeUnknown {
		t.Fatalf("authority state=%d want outcome-unknown", authority.State())
	}
}

func TestEngineLeafMobilityFinalRejectConsumesGeneration(t *testing.T) {
	blocker := &blockPreparedAckPath{reached: make(chan struct{}), release: make(chan struct{})}
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, func(path *memoryPathConn) transport.PathConn {
		blocker.PathConn = path
		return blocker
	})
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xa2)
	result := make(chan error, 1)
	go func() {
		_, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
		result <- err
	}()
	select {
	case <-blocker.reached:
	case <-time.After(time.Second):
		t.Fatal("peer never published PREPARED")
	}
	fixture.server.pathsMu.Lock()
	fixture.server.paths[fixture.serverRef.ID].mobilityClaim = nil
	fixture.server.pathsMu.Unlock()
	close(blocker.release)
	select {
	case err := <-result:
		if !errors.Is(err, ErrLeafMobilityRejected) {
			t.Fatalf("error=%v want=%v", err, ErrLeafMobilityRejected)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("transaction did not finish after final rejection")
	}
	if fixture.clientClaim.ExecutionGeneration() != 1 {
		t.Fatalf("rejected final generation=%d want=1", fixture.clientClaim.ExecutionGeneration())
	}
	fixture.server.pathsMu.Lock()
	fixture.server.paths[fixture.serverRef.ID].mobilityClaim = fixture.serverClaim
	fixture.server.pathsMu.Unlock()
	next := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xa3)
	if next.BaseGeneration != 1 {
		t.Fatalf("next base generation=%d want=1", next.BaseGeneration)
	}
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, next)
	if err != nil {
		t.Fatalf("transaction after final rejection: %v", err)
	}
	if fixture.clientClaim.ExecutionGeneration() != 2 {
		t.Fatalf("generation after retry=%d want=2", fixture.clientClaim.ExecutionGeneration())
	}
	if err := authority.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestEngineLeafMobilityPrepareRejectDoesNotDesynchronizeGeneration(t *testing.T) {
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
	first := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xa4)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, first)
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}

	fixture.server.pathsMu.Lock()
	fixture.server.paths[fixture.serverRef.ID].mobilityClaim = nil
	fixture.server.pathsMu.Unlock()
	rejected := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xa5)
	if rejected.BaseGeneration != 1 {
		t.Fatalf("rejected proposal base=%d want=1", rejected.BaseGeneration)
	}
	if authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, rejected); authority != nil ||
		!errors.Is(err, ErrLeafMobilityRejected) {
		t.Fatalf("rejected authority=%v error=%v", authority, err)
	}
	if generation := fixture.clientClaim.ExecutionGeneration(); generation != 2 {
		t.Fatalf("actor generation after rejected published proposal=%d want=2", generation)
	}
	peerKey := fixture.server.peerLeafLedgerKey(proto.LeafMobilityActorClient, proto.LeafMobilityResourceID(rejected.ResourceID))
	if generation, ok := fixture.server.leafTx.peerLedger.current(peerKey); !ok || generation != 1 {
		t.Fatalf("peer generation after pre-ledger rejection=(%d,%t) want=(1,true)", generation, ok)
	}

	fixture.server.pathsMu.Lock()
	fixture.server.paths[fixture.serverRef.ID].mobilityClaim = fixture.serverClaim
	fixture.server.pathsMu.Unlock()
	next := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xa6)
	if next.BaseGeneration != 2 {
		t.Fatalf("next proposal base=%d want=2", next.BaseGeneration)
	}
	authority, err = fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, next)
	if err != nil {
		t.Fatalf("transaction after rejected PREPARE: %v", err)
	}
	if err := authority.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if generation, ok := fixture.server.leafTx.peerLedger.current(peerKey); !ok || generation != 3 {
		t.Fatalf("peer generation after catch-up=(%d,%t) want=(3,true)", generation, ok)
	}
}

func TestEngineLeafMobilityRejectsFinalOnDifferentRoute(t *testing.T) {
	var rerouteTarget *memoryPathConn
	var rerouter *rerouteFinalAckPath
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, func(path *memoryPathConn) transport.PathConn {
		rerouter = &rerouteFinalAckPath{base: path, target: &rerouteTarget}
		return rerouter
	})
	clientB, serverB := newMemoryPathPair()
	rerouteTarget = clientB
	clientBID, err := fixture.client.AttachPathBound(clientB, transport.PathSpec{Transport: "memory"}, PathBinding{
		LocalTXTargetID: fixture.ids["b"], PeerTXTargetID: fixture.ids["b"],
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.server.AttachPathBound(serverB, transport.PathSpec{Transport: "memory"}, PathBinding{
		LocalTXTargetID: fixture.ids["b"], PeerTXTargetID: fixture.ids["b"],
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok := fixture.client.PathRef(clientBID); !ok {
		t.Fatal("missing reroute path")
	}
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xa4)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if authority, err := fixture.client.NegotiateLeafMobilityAuthority(ctx, fixture.clientRef, plan); authority != nil || !errors.Is(err, ErrLeafMobilityOutcomeUnknown) {
		t.Fatalf("cross-route authority=%v error=%v", authority, err)
	}
	if fixture.client.IsClosed() {
		t.Fatal("stale cross-route FINAL closed the healthy session")
	}
	if !fixture.clientResource.Snapshot().Poisoned {
		t.Fatal("cross-route FINAL released an uncertain mobility resource")
	}
	if _, err := fixture.client.SendData([]byte("cross-route-survivor")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, err := fixture.server.Recv(buf)
	if err != nil || string(buf[:n]) != "cross-route-survivor" {
		t.Fatalf("payload=%q err=%v", buf[:n], err)
	}
}

func TestEngineLeafMobilityRetriesDroppedAgreementPhase(t *testing.T) {
	for _, test := range []struct {
		name  string
		phase proto.LeafMobilityPeerPlanAckPhase
	}{
		{name: "prepared", phase: proto.LeafMobilityPeerPlanAckPhasePrepared},
		{name: "final", phase: proto.LeafMobilityPeerPlanAckPhaseFinal},
		{name: "released", phase: proto.LeafMobilityPeerPlanAckPhaseReleased},
	} {
		t.Run(test.name, func(t *testing.T) {
			dropper := &dropLeafAckOncePath{phase: test.phase}
			fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, func(path *memoryPathConn) transport.PathConn {
				dropper.PathConn = path
				return dropper
			})
			plan := engineLeafPlan(t, fixture.client, fixture.clientRef, byte(0xb0+test.phase))
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			authority, err := fixture.client.NegotiateLeafMobilityAuthority(ctx, fixture.clientRef, plan)
			if err != nil {
				t.Fatal(err)
			}
			if err := authority.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			if !dropper.dropped.Load() {
				t.Fatal("target ACK phase was not dropped")
			}
			seqs := dropper.recordedSeqs()
			if len(seqs) < 2 {
				t.Fatalf("ACK phase %d writes=%d want retry", test.phase, len(seqs))
			}
			if seqs[0] == 0 {
				t.Fatalf("ACK phase %d used reserved zero OOB message sequence", test.phase)
			}
			for _, seq := range seqs[1:] {
				if seq != seqs[0] {
					t.Fatalf("ACK phase %d retried with SEQs %v", test.phase, seqs)
				}
			}
		})
	}
}

func TestEngineLeafMobilityLateCommitAfterPreparedExpiryClosesGeneration(t *testing.T) {
	delayer := &delayLeafCommitPath{captured: make(chan []byte, 1)}
	fixture := newLeafMobilityEngineFixtureWithWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn { delayer.base = path; return delayer }, nil,
	)
	fixture.client.limits.MigrationBudget = 50 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xbc)
	result := make(chan error, 1)
	go func() {
		_, err := fixture.client.NegotiateLeafMobilityAuthority(ctx, fixture.clientRef, plan)
		result <- err
	}()
	var commitFrame []byte
	select {
	case commitFrame = <-delayer.captured:
	case <-time.After(time.Second):
		t.Fatal("actor did not publish COMMIT")
	}
	if err := <-result; !errors.Is(err, ErrLeafMobilityOutcomeUnknown) {
		t.Fatalf("actor result=%v want outcome unknown", err)
	}
	eventuallyEngine(t, time.Second, func() bool {
		fixture.server.leafTx.mu.Lock()
		defer fixture.server.leafTx.mu.Unlock()
		incoming := fixture.server.leafTx.incoming[[16]byte(plan.TransactionID)]
		return incoming != nil && incoming.state == incomingLeafMobilitySuperseded && incoming.hold == nil
	})
	select {
	case delayer.base.peer.in <- commitFrame:
	case <-time.After(time.Second):
		t.Fatal("could not deliver delayed COMMIT")
	}
	eventuallyEngine(t, time.Second, func() bool {
		fixture.server.leafTx.mu.Lock()
		defer fixture.server.leafTx.mu.Unlock()
		completed, ok := fixture.server.leafTx.completed[[16]byte(plan.TransactionID)]
		generation, seen := fixture.server.leafTx.peerLedger.current(
			fixture.server.peerLeafLedgerKey(proto.LeafMobilityActorClient, proto.LeafMobilityResourceID(plan.ResourceID)),
		)
		return ok && completed.final.Code == proto.LeafMobilityPeerPlanAckCodeSuperseded && seen && generation == 1
	})
	eventuallyEngine(t, time.Second, func() bool {
		snapshot := fixture.clientResource.Snapshot()
		return fixture.clientClaim.ExecutionGeneration() == 1 && !snapshot.Poisoned
	})
	if fixture.client.IsClosed() {
		t.Fatal("correlated late FINAL closed the actor session as unsolicited")
	}
	fixture.server.pathsMu.Lock()
	fixture.server.paths[fixture.serverRef.ID].mobilityClaim = fixture.serverClaim
	fixture.server.pathsMu.Unlock()
	next := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xbe)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, next)
	if err != nil {
		t.Fatalf("transaction after late FINAL rejection: %v", err)
	}
	if err := authority.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestEngineLeafMobilityLateFinalAcceptAutoRollsBack(t *testing.T) {
	dropper := &dropLeafAckOncePath{phase: proto.LeafMobilityPeerPlanAckPhaseFinal}
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, func(path *memoryPathConn) transport.PathConn {
		dropper.PathConn = path
		return dropper
	})
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xc3)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(ctx, fixture.clientRef, plan)
	if authority != nil || !errors.Is(err, ErrLeafMobilityOutcomeUnknown) {
		t.Fatalf("authority=%v error=%v want outcome unknown", authority, err)
	}
	if !dropper.dropped.Load() {
		t.Fatal("FINAL was not delayed")
	}
	eventuallyEngine(t, 2*time.Second, func() bool {
		return !fixture.clientResource.Snapshot().Poisoned && !fixture.serverResource.Snapshot().Poisoned
	})
	if fixture.client.IsClosed() || fixture.server.IsClosed() {
		t.Fatal("late accepted FINAL recovery closed a healthy session")
	}
}

func TestEngineLeafMobilityRecoveryDeadlineBoundsBlockedRollbackWriter(t *testing.T) {
	blocker := &blockLeafResolutionPath{reached: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(blocker.release) }) }
	t.Cleanup(release)
	dropper := &dropLeafAckOncePath{phase: proto.LeafMobilityPeerPlanAckPhaseFinal}
	fixture := newLeafMobilityEngineFixtureWithWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn { blocker.PathConn = path; return blocker },
		func(path *memoryPathConn) transport.PathConn { dropper.PathConn = path; return dropper },
	)
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xd1)
	fixture.client.limits.MigrationBudget = 50 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if authority, err := fixture.client.NegotiateLeafMobilityAuthority(ctx, fixture.clientRef, plan); authority != nil ||
		!errors.Is(err, ErrLeafMobilityOutcomeUnknown) {
		t.Fatalf("authority=%v error=%v", authority, err)
	}
	select {
	case <-blocker.reached:
	case <-time.After(time.Second):
		t.Fatal("recovery did not attempt rollback publication")
	}
	time.Sleep(1200 * time.Millisecond)
	fixture.client.leafTx.mu.Lock()
	outgoing := fixture.client.leafTx.outgoing
	fixture.client.leafTx.mu.Unlock()
	if outgoing == nil || len(fixture.client.leafTx.sendGate) != 1 {
		t.Fatal("recovery released transaction ownership before the pending writer exited")
	}
	if writes := blocker.writes.Load(); writes != 1 {
		t.Fatalf("blocked recovery accumulated %d concurrent rollback writers", writes)
	}
	if !fixture.clientResource.Snapshot().Poisoned {
		t.Fatal("blocked recovery writer released an unresolved resource")
	}
	release()
	eventuallyEngine(t, time.Second, func() bool {
		fixture.client.leafTx.mu.Lock()
		outgoing := fixture.client.leafTx.outgoing
		fixture.client.leafTx.mu.Unlock()
		return outgoing == nil && len(fixture.client.leafTx.sendGate) == 0
	})
}

func TestEngineLeafMobilityStaleExpiryCannotOvertakeResolution(t *testing.T) {
	blocker := &forwardThenBlockLeafResolutionPath{reached: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(blocker.release) }) }
	t.Cleanup(release)
	fixture := newLeafMobilityEngineFixtureWithWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn { blocker.PathConn = path; return blocker }, nil,
	)
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xdb)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
	if err != nil {
		t.Fatal(err)
	}
	authority.token.expiryMu.Lock()
	staleGeneration := authority.token.expiryGeneration
	authority.token.expiryMu.Unlock()
	resolved := make(chan error, 1)
	go func() { resolved <- authority.Rollback(context.Background()) }()
	select {
	case <-blocker.reached:
	case <-time.After(time.Second):
		t.Fatal("resolution writer did not reach the blocking adapter")
	}
	expired := make(chan struct{})
	go func() {
		authority.token.expireGeneration(staleGeneration)
		close(expired)
	}()
	select {
	case <-expired:
		t.Fatal("stale expiry callback crossed an active resolution")
	case <-time.After(20 * time.Millisecond):
	}
	release()
	select {
	case err := <-resolved:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("resolution did not finish after writer release")
	}
	select {
	case <-expired:
	case <-time.After(time.Second):
		t.Fatal("stale expiry callback did not retire")
	}
	if authority.State() != leafmobility.ResourceTransactionRolledBack || fixture.clientResource.Snapshot().Poisoned {
		t.Fatalf("stale expiry changed resolved authority: state=%d resource=%+v", authority.State(), fixture.clientResource.Snapshot())
	}
}

func TestEngineLeafMobilityRecoveryAckWaitsForForwardedWriter(t *testing.T) {
	blocker := &forwardThenBlockLeafResolutionPath{reached: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(blocker.release) }) }
	t.Cleanup(release)
	dropper := &dropLeafAckOncePath{phase: proto.LeafMobilityPeerPlanAckPhaseFinal}
	fixture := newLeafMobilityEngineFixtureWithWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn { blocker.PathConn = path; return blocker },
		func(path *memoryPathConn) transport.PathConn { dropper.PathConn = path; return dropper },
	)
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xdc)
	fixture.client.limits.MigrationBudget = 50 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if authority, err := fixture.client.NegotiateLeafMobilityAuthority(ctx, fixture.clientRef, plan); authority != nil ||
		!errors.Is(err, ErrLeafMobilityOutcomeUnknown) {
		t.Fatalf("authority=%v error=%v", authority, err)
	}
	select {
	case <-blocker.reached:
	case <-time.After(time.Second):
		t.Fatal("recovery did not forward rollback publication")
	}
	// The peer has already observed the frame and returned RELEASED, while the
	// adapter still owns the local Write call. Recovery must not publish its
	// terminal state or release the global transaction gate yet.
	time.Sleep(1200 * time.Millisecond)
	fixture.client.leafTx.mu.Lock()
	outgoing := fixture.client.leafTx.outgoing
	fixture.client.leafTx.mu.Unlock()
	if outgoing == nil || len(fixture.client.leafTx.sendGate) != 1 {
		t.Fatal("recovery ACK released transaction ownership before writer exit")
	}
	release()
	eventuallyEngine(t, time.Second, func() bool {
		fixture.client.leafTx.mu.Lock()
		outgoing := fixture.client.leafTx.outgoing
		fixture.client.leafTx.mu.Unlock()
		return outgoing == nil && len(fixture.client.leafTx.sendGate) == 0
	})
}

func TestEngineCloseWaitsForPendingLeafMobilityWriter(t *testing.T) {
	blocker := &blockLeafWritePath{reached: make(chan struct{}), release: make(chan struct{})}
	e := New(SideClient, NewClientFlowID(), Limits{})
	path, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = peer.Close() })
	blocker.PathConn = path
	id, err := e.AttachPath(blocker, transport.PathSpec{Transport: "memory"})
	if err != nil {
		t.Fatal(err)
	}
	ref, ok := e.PathRef(id)
	if !ok {
		t.Fatal("missing exact path ref")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err, pending := e.sendLeafMobilityFrameWithContext(ctx, func() ([]byte, error) {
		return e.sendLeafMobilityFrameAt(ref, proto.CtrlLeafMobilityPrepare, []byte{1}, nil)
	})
	if pending == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("pending=%v error=%v", pending, err)
	}
	select {
	case <-blocker.reached:
	default:
		t.Fatal("writer did not reach blocking adapter")
	}
	closed := make(chan error, 1)
	go func() { closed <- e.Close() }()
	select {
	case <-e.Closed():
		t.Fatal("Engine quiesced before pending OOB writer exited")
	case <-time.After(50 * time.Millisecond):
	}
	close(blocker.release)
	select {
	case <-e.Closed():
	case <-time.After(time.Second):
		t.Fatal("Engine did not quiesce after pending OOB writer exited")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not return after pending OOB writer exited")
	}
}

func TestEngineLeafMobilityRecoveryDoesNotReconcileAcceptedFinalTwice(t *testing.T) {
	dropper := &dropLeafAckOncePath{phase: proto.LeafMobilityPeerPlanAckPhaseFinal}
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, func(path *memoryPathConn) transport.PathConn {
		dropper.PathConn = path
		return dropper
	})
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xd2)
	fixture.client.limits.MigrationBudget = 50 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if authority, err := fixture.client.NegotiateLeafMobilityAuthority(ctx, fixture.clientRef, plan); authority != nil ||
		!errors.Is(err, ErrLeafMobilityOutcomeUnknown) {
		t.Fatalf("authority=%v error=%v", authority, err)
	}
	fixture.client.leafTx.messageSeq.Store(proto.MaxSeq)
	eventuallyEngine(t, 500*time.Millisecond, func() bool {
		return fixture.clientResource.Snapshot().Generation == 1
	})
	// A duplicate FINAL arrives while rollback publication remains impossible.
	// Recovery must stay in its publication phase instead of trying to apply
	// the accepted generation a second time and terminating early.
	time.Sleep(2 * leafMobilityRetryInterval)
	fixture.client.leafTx.mu.Lock()
	outgoing := fixture.client.leafTx.outgoing
	fixture.client.leafTx.mu.Unlock()
	if outgoing == nil {
		t.Fatal("duplicate FINAL terminated rollback-publication recovery early")
	}
	eventuallyEngine(t, 1500*time.Millisecond, func() bool {
		fixture.client.leafTx.mu.Lock()
		outgoing := fixture.client.leafTx.outgoing
		fixture.client.leafTx.mu.Unlock()
		return outgoing == nil && len(fixture.client.leafTx.sendGate) == 0
	})
	if !fixture.clientResource.Snapshot().Poisoned {
		t.Fatal("failed rollback publication released an unresolved resource")
	}
}

func TestEngineLeafMobilityLateReleasedFinishesResolution(t *testing.T) {
	dropper := &dropLeafAckOncePath{phase: proto.LeafMobilityPeerPlanAckPhaseReleased}
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, func(path *memoryPathConn) transport.PathConn {
		dropper.PathConn = path
		return dropper
	})
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xc4)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := authority.Rollback(ctx); !errors.Is(err, ErrLeafMobilityOutcomeUnknown) {
		t.Fatalf("rollback error=%v want outcome unknown", err)
	}
	if !dropper.dropped.Load() {
		t.Fatal("RELEASED was not delayed")
	}
	eventuallyEngine(t, 2*time.Second, func() bool {
		return !fixture.clientResource.Snapshot().Poisoned && !fixture.serverResource.Snapshot().Poisoned
	})
	if fixture.client.IsClosed() || fixture.server.IsClosed() {
		t.Fatal("late RELEASED recovery closed a healthy session")
	}
	if _, err := fixture.client.SendData([]byte("after-late-release")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, err := fixture.server.Recv(buf)
	if err != nil || string(buf[:n]) != "after-late-release" {
		t.Fatalf("payload=%q err=%v", buf[:n], err)
	}
}

func TestEngineLeafMobilityRecoveryRejectsResolutionReentry(t *testing.T) {
	dropper := &dropLeafAckPath{phase: proto.LeafMobilityPeerPlanAckPhaseReleased}
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, func(path *memoryPathConn) transport.PathConn {
		dropper.PathConn = path
		return dropper
	})
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xdd)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := authority.Rollback(ctx); !errors.Is(err, ErrLeafMobilityOutcomeUnknown) {
		t.Fatalf("initial resolution error=%v want outcome unknown", err)
	}
	sequence := fixture.client.leafTx.messageSeq.Load()
	retryCtx, retryCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer retryCancel()
	started := time.Now()
	if err := authority.Rollback(retryCtx); !errors.Is(err, ErrLeafMobilityOutcomeUnknown) {
		t.Fatalf("resolution reentry error=%v want outcome unknown", err)
	}
	if elapsed := time.Since(started); elapsed > 50*time.Millisecond {
		t.Fatalf("resolution reentry waited %v instead of failing before publication", elapsed)
	}
	if got := fixture.client.leafTx.messageSeq.Load(); got != sequence {
		t.Fatalf("resolution reentry allocated OOB sequence %d after %d", got, sequence)
	}
	if fixture.client.IsClosed() || fixture.server.IsClosed() {
		t.Fatal("rejected resolution reentry closed healthy session")
	}
}

func TestEngineLeafMobilityPendingResolutionWriterRejectsReentry(t *testing.T) {
	blocker := &forwardThenBlockLeafResolutionPath{reached: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(blocker.release) }) }
	t.Cleanup(release)
	fixture := newLeafMobilityEngineFixtureWithWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn { blocker.PathConn = path; return blocker }, nil,
	)
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xde)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := authority.Rollback(ctx); !errors.Is(err, ErrLeafMobilityOutcomeUnknown) {
		t.Fatalf("pending resolution error=%v want outcome unknown", err)
	}
	select {
	case <-blocker.reached:
	default:
		t.Fatal("resolution writer did not reach blocking adapter")
	}
	sequence := fixture.client.leafTx.messageSeq.Load()
	if err := authority.Rollback(context.Background()); !errors.Is(err, ErrLeafMobilityOutcomeUnknown) {
		t.Fatalf("pending-writer reentry error=%v want outcome unknown", err)
	}
	if got := fixture.client.leafTx.messageSeq.Load(); got != sequence {
		t.Fatalf("pending-writer reentry allocated OOB sequence %d after %d", got, sequence)
	}
	if len(fixture.client.leafTx.sendGate) != 1 {
		t.Fatal("pending-writer reentry released transaction gate")
	}
	const contenders = 32
	start := make(chan struct{})
	results := make(chan error, contenders)
	for range contenders {
		go func() {
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			results <- authority.Rollback(ctx)
		}()
	}
	close(start)
	release()
	for range contenders {
		if err := <-results; err == nil {
			t.Fatal("resolution reentry succeeded during abandoned/recovery handoff")
		}
	}
	if got := fixture.client.leafTx.messageSeq.Load(); got != sequence {
		t.Fatalf("handoff reentry allocated OOB sequence %d after %d", got, sequence)
	}
	eventuallyEngine(t, time.Second, func() bool {
		return authority.State() == leafmobility.ResourceTransactionRolledBack &&
			len(fixture.client.leafTx.sendGate) == 0
	})
}

func TestEngineLeafMobilityPlanDeadlineHandsResolutionToRecovery(t *testing.T) {
	dropper := &dropLeafAckOncePath{phase: proto.LeafMobilityPeerPlanAckPhaseReleased}
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, func(path *memoryPathConn) transport.PathConn {
		dropper.PathConn = path
		return dropper
	})
	fixture.client.limits.MigrationBudget = 100 * time.Millisecond
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xd8)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Rollback(context.Background()); !errors.Is(err, ErrLeafMobilityOutcomeUnknown) {
		t.Fatalf("rollback error=%v want outcome unknown", err)
	}
	if !dropper.dropped.Load() {
		t.Fatal("initial RELEASED was not dropped")
	}
	eventuallyEngine(t, 2*time.Second, func() bool {
		return !fixture.clientResource.Snapshot().Poisoned && !fixture.serverResource.Snapshot().Poisoned
	})
	if authority.State() != leafmobility.ResourceTransactionRolledBack {
		t.Fatalf("authority state=%d want rolled back", authority.State())
	}
}

func TestEngineLeafMobilityResponderOutcomeUnknownPoisonsOnlyResource(t *testing.T) {
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xd7)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
	if err != nil || authority == nil {
		t.Fatalf("authority=%v error=%v", authority, err)
	}
	fixture.server.leafTx.mu.Lock()
	incoming := fixture.server.leafTx.incoming[[16]byte(plan.TransactionID)]
	if incoming == nil || incoming.state != incomingLeafMobilityCommitted {
		fixture.server.leafTx.mu.Unlock()
		t.Fatalf("incoming=%v", incoming)
	}
	incoming.deadline = time.Now().Add(-time.Millisecond)
	fixture.server.leafTx.mu.Unlock()
	fixture.server.expireIncomingLeafMobilityTransactions(time.Now())
	if !fixture.serverResource.Snapshot().Poisoned {
		t.Fatal("uncertain committed responder resource was not poisoned")
	}
	if fixture.server.IsClosed() {
		t.Fatal("endpoint-scoped uncertain outcome closed the whole session")
	}
	if _, err := fixture.client.SendData([]byte("survives-resource-poison")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, err := fixture.server.Recv(buf)
	if err != nil || string(buf[:n]) != "survives-resource-poison" {
		t.Fatalf("payload=%q error=%v", buf[:n], err)
	}
	if err := authority.Rollback(context.Background()); err != nil {
		t.Fatalf("late correlated resolution: %v", err)
	}
	if fixture.serverResource.Snapshot().Poisoned {
		t.Fatal("late correlated resolution did not reconcile responder poison")
	}
	if fixture.client.IsClosed() || fixture.server.IsClosed() {
		t.Fatal("late correlated resolution closed a healthy session")
	}
}

func TestEngineLeafMobilityResponderOutcomeUnknownRecordRetires(t *testing.T) {
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xd9)
	if authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan); err != nil || authority == nil {
		t.Fatalf("authority=%v error=%v", authority, err)
	}
	now := time.Now()
	fixture.server.leafTx.mu.Lock()
	incoming := fixture.server.leafTx.incoming[[16]byte(plan.TransactionID)]
	if incoming == nil {
		fixture.server.leafTx.mu.Unlock()
		t.Fatal("missing committed responder transaction")
	}
	incoming.deadline = now.Add(-2 * time.Millisecond)
	incoming.retireAfter = now.Add(-time.Millisecond)
	fixture.server.leafTx.mu.Unlock()
	fixture.server.expireIncomingLeafMobilityTransactions(now)
	fixture.server.expireIncomingLeafMobilityTransactions(now)
	fixture.server.leafTx.mu.Lock()
	_, retained := fixture.server.leafTx.incoming[[16]byte(plan.TransactionID)]
	fixture.server.leafTx.mu.Unlock()
	if retained {
		t.Fatal("expired outcome-unknown responder record retained capacity")
	}
	if !fixture.serverResource.Snapshot().Poisoned {
		t.Fatal("retiring unresolved evidence cleared fail-closed resource")
	}
	if fixture.server.IsClosed() {
		t.Fatal("retiring endpoint-scoped unknown outcome closed session")
	}
}

func TestEngineLeafMobilityResponderPinsResolutionBeforeResponsePublication(t *testing.T) {
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xdf)
	if authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan); err != nil || authority == nil {
		t.Fatalf("authority=%v error=%v", authority, err)
	}
	now := time.Now()
	fixture.server.limits.MigrationBudget = 20 * time.Millisecond
	fixture.server.leafTx.mu.Lock()
	incoming := fixture.server.leafTx.incoming[[16]byte(plan.TransactionID)]
	if incoming == nil || incoming.state != incomingLeafMobilityCommitted {
		fixture.server.leafTx.mu.Unlock()
		t.Fatalf("incoming=%v", incoming)
	}
	incoming.deadline = now.Add(-time.Millisecond)
	incoming.retireAfter = now.Add(time.Second)
	resolution := incoming.commit
	resolution.Stage = proto.LeafMobilityPeerPlanCommitStageComplete
	fixture.server.leafTx.mu.Unlock()
	fixture.server.expireIncomingLeafMobilityTransactions(now)
	if !fixture.serverResource.Snapshot().Poisoned {
		t.Fatal("test did not establish outcome-unknown responder poison")
	}

	fixture.server.leafTx.responseGate <- struct{}{}
	err := fixture.server.handleLeafMobilityCommit(fixture.serverRef, 901, false, resolution)
	<-fixture.server.leafTx.responseGate
	if !errors.Is(err, errLeafMobilityResponseUnavailable) {
		t.Fatalf("resolution response error=%v want response unavailable", err)
	}
	if fixture.serverResource.Snapshot().Poisoned {
		t.Fatal("correlated terminal evidence remained coupled to response publication")
	}
	fixture.server.expireIncomingLeafMobilityTransactions(time.Now())
	if fixture.serverResource.Snapshot().Poisoned {
		t.Fatal("known terminal response was downgraded to outcome unknown on expiry")
	}

	opposite := resolution
	opposite.Stage = proto.LeafMobilityPeerPlanCommitStageRolledBack
	if err := fixture.server.handleLeafMobilityCommit(fixture.serverRef, 902, false, opposite); err == nil {
		t.Fatal("responder accepted a different terminal resolution after evidence was pinned")
	}
	fixture.server.leafTx.mu.Lock()
	retained := fixture.server.leafTx.incoming[[16]byte(plan.TransactionID)]
	fixture.server.leafTx.mu.Unlock()
	if retained == nil || retained.resolution != resolution || retained.resolutionSeq != 901 ||
		retained.state != incomingLeafMobilityTerminalPending {
		t.Fatalf("terminal evidence changed after conflict: incoming=%+v", retained)
	}
	if fixture.client.IsClosed() || fixture.server.IsClosed() {
		t.Fatal("local response publication failure closed healthy session")
	}
}

func TestEngineLeafMobilityPendingPrepareKeepsResourceReserved(t *testing.T) {
	blocker := &forwardThenBlockLeafPreparePath{reached: make(chan struct{}), release: make(chan struct{})}
	shared := leafmobility.MustNewResource(leafmobility.ScopeProcessLocal)
	fixture := newLeafMobilityEngineFixtureWithWrappers(
		t, shared, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn { blocker.PathConn = path; return blocker }, nil,
	)
	fixture.client.limits.MigrationBudget = 250 * time.Millisecond
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xc5)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := fixture.client.NegotiateLeafMobilityAuthority(ctx, fixture.clientRef, plan)
		result <- err
	}()
	select {
	case <-blocker.reached:
	case <-time.After(time.Second):
		t.Fatal("PREPARE was not forwarded before the write blocked")
	}
	if err := <-result; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("negotiation error=%v want deadline", err)
	}
	driver := &enginePlanDriver{operation: leafmobility.OperationTCPRepair, evidence: leafmobility.EvidenceDigest{0xc5}}
	other := leafmobility.MustNewDrivenClaim(leafmobility.Facts{
		Kind: leafmobility.KindRawTCP, Role: leafmobility.RoleDialer,
		Session: leafmobility.SessionStream, Generation: leafmobility.NextGeneration(),
	}, driver, shared)
	if _, err := leafmobility.ReserveAdmissions(other); !errors.Is(err, leafmobility.ErrAuthorityActive) {
		t.Fatalf("shared resource after pending PREPARE=%v want active transaction", err)
	}
	close(blocker.release)
	eventuallyEngine(t, time.Second, func() bool {
		hold, err := leafmobility.ReserveAdmissions(other)
		if err != nil {
			return false
		}
		hold.Release()
		return true
	})
}

func TestEngineLeafMobilityLostBoundControlDoesNotBlockSurvivorData(t *testing.T) {
	dropper := &dropLeafPreparePath{dropped: make(chan struct{})}
	fixture := newLeafMobilityEngineFixtureWithWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn { dropper.PathConn = path; return dropper }, nil,
	)
	clientB, serverB := newMemoryPathPair()
	clientBID, err := fixture.client.AttachPathBound(clientB, transport.PathSpec{Transport: "memory"}, PathBinding{
		LocalTXTargetID: fixture.ids["b"], PeerTXTargetID: fixture.ids["b"],
	})
	if err != nil {
		t.Fatal(err)
	}
	serverBID, err := fixture.server.AttachPathBound(serverB, transport.PathSpec{Transport: "memory"}, PathBinding{
		LocalTXTargetID: fixture.ids["b"], PeerTXTargetID: fixture.ids["b"],
	})
	if err != nil {
		t.Fatal(err)
	}
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xc6)
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := fixture.client.NegotiateLeafMobilityAuthority(ctx, fixture.clientRef, plan)
		result <- err
	}()
	select {
	case <-dropper.dropped:
	case <-time.After(time.Second):
		t.Fatal("bound PREPARE was not dropped")
	}
	if err := <-result; err == nil {
		t.Fatal("dropped PREPARE unexpectedly negotiated authority")
	}
	if err := fixture.client.RemovePath(fixture.clientRef.ID); err != nil {
		t.Fatal(err)
	}
	if err := fixture.server.RemovePath(fixture.serverRef.ID); err != nil {
		t.Fatal(err)
	}
	if fixture.client.ActivePath() != clientBID || fixture.server.ActivePath() != serverBID {
		t.Fatalf("survivor paths client=%d/%d server=%d/%d", fixture.client.ActivePath(), clientBID, fixture.server.ActivePath(), serverBID)
	}
	const survivorFrames = sendHistoryWindow + 64
	expected := make([]byte, 0, survivorFrames*4)
	for index := 0; index < survivorFrames; index++ {
		payload := []byte{byte(index >> 8), byte(index), 0xa5, 0x5a}
		expected = append(expected, payload...)
		if _, err := fixture.client.SendData(payload); err != nil {
			t.Fatal(err)
		}
	}
	type receiveResult struct {
		payload []byte
		err     error
	}
	received := make(chan receiveResult, 1)
	go func() {
		payload := make([]byte, 0, len(expected))
		for len(payload) < len(expected) {
			buf := make([]byte, len(expected)-len(payload))
			n, err := fixture.server.Recv(buf)
			if err != nil {
				received <- receiveResult{payload: payload, err: err}
				return
			}
			payload = append(payload, buf[:n]...)
		}
		received <- receiveResult{payload: payload}
	}()
	select {
	case got := <-received:
		if got.err != nil || !bytes.Equal(got.payload, expected) {
			t.Fatalf("payload-bytes=%d err=%v", len(got.payload), got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("survivor DATA blocked behind lost route-bound control")
	}
}

func TestEngineLeafMobilityResponderHoldLastsUntilReleased(t *testing.T) {
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xbd)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leafmobility.ReserveAdmissions(fixture.serverClaim); !errors.Is(err, leafmobility.ErrResourceAdmissionActive) {
		t.Fatalf("responder resource after FINAL=%v want held", err)
	}
	if err := authority.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	hold, err := leafmobility.ReserveAdmissions(fixture.serverClaim)
	if err != nil {
		t.Fatalf("responder resource remained held after RELEASED: %v", err)
	}
	hold.Release()
}

func TestEngineLeafMobilityCopiedPermitHasOneResolutionPublisher(t *testing.T) {
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xc0)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := authority.Consume()
	if err != nil {
		t.Fatal(err)
	}
	if err := permit.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := permit.Cutover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := permit.CommitDriver(context.Background()); err != nil {
		t.Fatal(err)
	}
	copyOfPermit := *permit
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, candidate := range []*LeafMobilityPermit{permit, &copyOfPermit} {
		go func(candidate *LeafMobilityPermit) {
			<-start
			results <- candidate.Complete(context.Background())
		}(candidate)
	}
	close(start)
	first, second := <-results, <-results
	if (first == nil) == (second == nil) {
		t.Fatalf("resolution results=(%v,%v), want exactly one publisher", first, second)
	}
	loser := first
	if loser == nil {
		loser = second
	}
	if errors.Is(loser, ErrLeafMobilityOutcomeUnknown) || fixture.clientResource.Snapshot().Poisoned {
		t.Fatalf("pre-publication loser poisoned resource: error=%v resource=%+v", loser, fixture.clientResource.Snapshot())
	}
	if authority.State() != leafmobility.ResourceTransactionCompleted {
		t.Fatalf("authority state=%d want released", authority.State())
	}
}

func TestEngineLeafMobilityConsumedAuthorityCannotPublishRollback(t *testing.T) {
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xc5)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
	if err != nil {
		t.Fatal(err)
	}
	copyOfAuthority := *authority
	permit, err := authority.Consume()
	if err != nil {
		t.Fatal(err)
	}
	assertRejected := func(stage string) {
		t.Helper()
		sequence := fixture.client.leafTx.messageSeq.Load()
		for _, candidate := range []*LeafMobilityAuthority{authority, &copyOfAuthority} {
			if err := candidate.Rollback(context.Background()); !errors.Is(err, leafmobility.ErrAuthorityConsumed) {
				t.Fatalf("%s stale authority rollback=%v", stage, err)
			}
		}
		if got := fixture.client.leafTx.messageSeq.Load(); got != sequence {
			t.Fatalf("%s stale authority published sequence %d after %d", stage, got, sequence)
		}
	}
	assertRejected("consumed")
	if err := permit.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertRejected("prepared")
	if err := permit.Cutover(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertRejected("cutover")
	if err := permit.CommitDriver(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertRejected("committed")
	if err := permit.Complete(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestEngineLeafMobilityOutcomeUnknownStillCleansLocalExecution(t *testing.T) {
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xc6)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := authority.Consume()
	if err != nil {
		t.Fatal(err)
	}
	if err := permit.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	permit.token.outcomeUnknownSerialized(errors.New("forced outcome unknown"))
	eventuallyEngine(t, time.Second, func() bool {
		state := permit.ExecutionState()
		return state == leafmobility.ExecutionRolledBack || state == leafmobility.ExecutionFailedClosed
	})
	closed := make(chan error, 1)
	go func() { closed <- fixture.client.Close() }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("outcome-unknown execution retained its claim lease")
	}
}

func TestEngineCloseIsBoundedWhileDriverRollbackIsBlocked(t *testing.T) {
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
	fixture.clientDriver.rollbackEntered = make(chan struct{})
	fixture.clientDriver.rollbackRelease = make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(fixture.clientDriver.rollbackRelease) }) }
	t.Cleanup(release)
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xc7)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := authority.Consume()
	if err != nil {
		t.Fatal(err)
	}
	if err := permit.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- fixture.client.Close() }()
	select {
	case <-fixture.clientDriver.rollbackEntered:
	case <-time.After(time.Second):
		t.Fatal("close did not request local rollback")
	}
	select {
	case err := <-closed:
		if err == nil {
			t.Fatal("Close unexpectedly reported full quiescence while rollback was blocked")
		}
	case <-time.After(time.Second):
		t.Fatal("Close exceeded its bounded shutdown wait")
	}
	release()
	select {
	case <-fixture.client.Closed():
	case <-time.After(2 * time.Second):
		t.Fatal("background shutdown did not finish after rollback release")
	}
}

func TestEngineLeafMobilityCommittedResolutionIgnoresCallerCancellationAndRetriesZeroFrame(t *testing.T) {
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xc1)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := authority.Consume()
	if err != nil {
		t.Fatal(err)
	}
	if err := permit.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := permit.Cutover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := permit.CommitDriver(context.Background()); err != nil {
		t.Fatal(err)
	}

	sequence := fixture.client.leafTx.messageSeq.Load()
	fixture.client.leafTx.messageSeq.Store(proto.MaxSeq)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	result := make(chan error, 1)
	go func() { result <- permit.Complete(canceled) }()
	select {
	case err := <-result:
		t.Fatalf("committed completion returned before retry: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	fixture.client.leafTx.messageSeq.Store(sequence)
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("engine-owned committed completion did not retry")
	}
	if permit.State() != leafmobility.ResourceTransactionCompleted || fixture.clientResource.Snapshot().Poisoned {
		t.Fatalf("permit=%d resource=%+v", permit.State(), fixture.clientResource.Snapshot())
	}
}

func TestEngineLeafMobilityCommittedResolutionSurvivesAdministrativePathRetirement(t *testing.T) {
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xc9)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := authority.Consume()
	if err != nil {
		t.Fatal(err)
	}
	if err := permit.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := permit.Cutover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := permit.CommitDriver(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := fixture.client.RetirePath(fixture.clientRef, errors.New("administrative retirement after commit")); err != nil {
		t.Fatal(err)
	}
	if err := permit.Complete(context.Background()); err != nil {
		t.Fatal(err)
	}
	if permit.State() != leafmobility.ResourceTransactionCompleted || permit.ExecutionState() != leafmobility.ExecutionCommitted {
		t.Fatalf("permit state=(%d,%d)", permit.State(), permit.ExecutionState())
	}
}

func TestEngineLeafMobilityRecoveryRetainsCommittedCarrierLease(t *testing.T) {
	dropper := &dropLeafAckPath{phase: proto.LeafMobilityPeerPlanAckPhaseReleased}
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, func(path *memoryPathConn) transport.PathConn {
		dropper.PathConn = path
		return dropper
	})
	fixture.client.limits.MigrationBudget = 150 * time.Millisecond
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xcb)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := authority.Consume()
	if err != nil {
		t.Fatal(err)
	}
	if err := permit.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := permit.Cutover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := permit.CommitDriver(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := permit.Complete(context.Background()); !errors.Is(err, ErrLeafMobilityOutcomeUnknown) {
		t.Fatalf("completion error=%v want outcome unknown", err)
	}
	retired := make(chan error, 1)
	go func() { retired <- fixture.clientClaim.Retire(plan.Binding) }()
	select {
	case err := <-retired:
		t.Fatalf("recovery released committed carrier early: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	select {
	case err := <-retired:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("recovery did not release committed carrier at terminal budget")
	}
}

func TestEngineLeafMobilityRollbackSurvivesAdministrativePathRetirement(t *testing.T) {
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xca)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := authority.Consume()
	if err != nil {
		t.Fatal(err)
	}
	if err := permit.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := fixture.client.RetirePath(fixture.clientRef, errors.New("administrative retirement before cutover")); err != nil {
		t.Fatal(err)
	}
	if err := permit.Cutover(context.Background()); err == nil {
		t.Fatal("cutover crossed logical path retirement")
	}
	if err := permit.RolledBack(context.Background()); err != nil {
		t.Fatal(err)
	}
	if permit.State() != leafmobility.ResourceTransactionRolledBack || permit.ExecutionState() != leafmobility.ExecutionRolledBack {
		t.Fatalf("permit state=(%d,%d)", permit.State(), permit.ExecutionState())
	}
}

func TestEngineLeafMobilityPermitWatchdogOwnsAbandonedTerminalWork(t *testing.T) {
	t.Run("prepared rolls back", func(t *testing.T) {
		fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
		fixture.client.limits.MigrationBudget = 400 * time.Millisecond
		plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xc2)
		authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
		if err != nil {
			t.Fatal(err)
		}
		permit, err := authority.Consume()
		if err != nil {
			t.Fatal(err)
		}
		if err := permit.Prepare(context.Background()); err != nil {
			t.Fatal(err)
		}
		eventuallyEngine(t, 2*time.Second, func() bool {
			return permit.State() == leafmobility.ResourceTransactionRolledBack &&
				permit.ExecutionState() == leafmobility.ExecutionRolledBack
		})
		if fixture.clientResource.Snapshot().Poisoned || fixture.serverResource.Snapshot().Poisoned {
			t.Fatal("watchdog rollback poisoned a resolved resource")
		}
	})

	t.Run("committed completes", func(t *testing.T) {
		fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
		fixture.client.limits.MigrationBudget = 400 * time.Millisecond
		plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xc3)
		authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
		if err != nil {
			t.Fatal(err)
		}
		permit, err := authority.Consume()
		if err != nil {
			t.Fatal(err)
		}
		if err := permit.Prepare(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := permit.Cutover(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := permit.CommitDriver(context.Background()); err != nil {
			t.Fatal(err)
		}
		eventuallyEngine(t, 2*time.Second, func() bool {
			return permit.State() == leafmobility.ResourceTransactionCompleted
		})
		if fixture.clientResource.Snapshot().Poisoned || fixture.serverResource.Snapshot().Poisoned {
			t.Fatal("watchdog completion poisoned a resolved resource")
		}
	})
}

func TestEngineCloseCancelsPreparedDriverLease(t *testing.T) {
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xc4)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := authority.Consume()
	if err != nil {
		t.Fatal(err)
	}
	if err := permit.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- fixture.client.Close() }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Engine.Close remained blocked on an abandoned driver lease")
	}
	if state := permit.ExecutionState(); state != leafmobility.ExecutionRolledBack && state != leafmobility.ExecutionFailedClosed {
		t.Fatalf("execution state after close=%d", state)
	}
}

func TestEngineCloseInvalidatesClaimAcrossValidationToDriverGap(t *testing.T) {
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xc8)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := authority.Consume()
	if err != nil {
		t.Fatal(err)
	}
	if err := permit.validateExecutionSource(); err != nil {
		t.Fatal(err)
	}
	if err := fixture.client.Close(); err != nil {
		t.Fatalf("close before driver: %v", err)
	}
	if err := permit.execution.Prepare(context.Background()); err == nil {
		t.Fatal("driver execution crossed engine close")
	}
	if calls := fixture.clientDriver.prepareCalls.Load(); calls != 0 {
		t.Fatalf("driver Prepare calls after close=%d", calls)
	}
}

func TestEngineRejectsLeafMobilityReservedFlagsBeforeStateMutation(t *testing.T) {
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xbe)
	binding := fixture.client.canonicalLeafMobilityBinding(plan, 1000)
	prepare := proto.LeafMobilityPeerPlanPrepare{
		LeafMobilityPeerPlanBinding: binding,
		ActorEndpointGeneration:     plan.EndpointGeneration,
		ActorPlanDigest:             proto.LeafMobilityPlanDigest(plan.LocalDigest),
	}
	payload, err := prepare.Encode()
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, proto.HeaderSize+len(payload))
	header := proto.Header{
		Version: proto.Version, Type: proto.FrameCtrl,
		Flags: proto.FlagsForCtrl(proto.CtrlLeafMobilityPrepare) | 0x100, Seq: 0,
	}
	if err := header.Encode(frame[:proto.HeaderSize]); err != nil {
		t.Fatal(err)
	}
	copy(frame[proto.HeaderSize:], payload)
	if _, err := fixture.clientWire.Write(frame); err != nil {
		t.Fatal(err)
	}
	eventuallyEngine(t, time.Second, fixture.server.IsClosed)
	fixture.server.leafTx.mu.Lock()
	defer fixture.server.leafTx.mu.Unlock()
	if len(fixture.server.leafTx.incoming) != 0 {
		t.Fatalf("reserved FLAGS allocated %d incoming transactions", len(fixture.server.leafTx.incoming))
	}
}

func TestEngineLeafMobilityBlockedPublicationHonorsContextAndRetainsGate(t *testing.T) {
	blocker := &blockLeafWritePath{reached: make(chan struct{}), release: make(chan struct{})}
	fixture := newLeafMobilityEngineFixtureWithWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn {
			blocker.PathConn = path
			return blocker
		},
		nil,
	)
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xb4)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	if authority, err := fixture.client.NegotiateLeafMobilityAuthority(ctx, fixture.clientRef, plan); authority != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("authority=%v error=%v", authority, err)
	}
	if time.Since(started) > 500*time.Millisecond {
		t.Fatalf("blocked publication ignored context for %v", time.Since(started))
	}
	select {
	case <-blocker.reached:
	default:
		t.Fatal("test did not block the publication")
	}
	if len(fixture.client.leafTx.sendGate) != 1 {
		t.Fatal("send gate was released while publication still owned by blocked writer")
	}
	close(blocker.release)
	eventuallyEngine(t, time.Second, func() bool { return len(fixture.client.leafTx.sendGate) == 0 })
}

func TestEngineLeafMobilityPublicationCallbackFailureRollsBackLedger(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{})
	t.Cleanup(func() { _ = e.Close() })
	path, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = peer.Close() })
	id, err := e.AttachPath(path, transport.PathSpec{Transport: "memory"})
	if err != nil {
		t.Fatal(err)
	}
	ref, ok := e.PathRef(id)
	if !ok {
		t.Fatal("missing exact path ref")
	}
	sentinel := errors.New("publication rejected")
	frame, err := e.sendLeafMobilityFrameAt(ref, proto.CtrlLeafMobilityCommit, []byte{1}, func([]byte) error {
		return sentinel
	})
	if frame != nil || !errors.Is(err, sentinel) {
		t.Fatalf("frame=%x error=%v", frame, err)
	}
	if got := atomic.LoadUint64(&e.sendSeq); got != 0 || e.sendPublishedNext.Load() != 0 {
		t.Fatalf("send sequence advanced to seq=%d published=%d", got, e.sendPublishedNext.Load())
	}
	e.sendHistMu.Lock()
	history := len(e.sendHist.entries)
	e.sendHistMu.Unlock()
	if history != 0 || len(e.sendControlSlots) != 0 || path.writes.Load() != 0 {
		t.Fatalf("rollback history=%d credits=%d writes=%d", history, len(e.sendControlSlots), path.writes.Load())
	}
}

func TestEngineLeafMobilityOOBTransactionDoesNotConsumeDataSequenceOrCredit(t *testing.T) {
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xc7)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	for name, endpoint := range map[string]*Engine{"client": fixture.client, "server": fixture.server} {
		if seq, published := atomic.LoadUint64(&endpoint.sendSeq), endpoint.sendPublishedNext.Load(); seq != 0 || published != 0 {
			t.Fatalf("%s DATA sequence=(%d,%d) after OOB transaction", name, seq, published)
		}
		endpoint.sendHistMu.Lock()
		history := len(endpoint.sendHist.entries)
		endpoint.sendHistMu.Unlock()
		if history != 0 || len(endpoint.sendControlSlots) != 0 {
			t.Fatalf("%s DATA replay state history=%d control-credit=%d", name, history, len(endpoint.sendControlSlots))
		}
	}
	if _, err := fixture.client.SendData([]byte("first-data-sequence")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, err := fixture.server.Recv(buf)
	if err != nil || string(buf[:n]) != "first-data-sequence" {
		t.Fatalf("payload=%q err=%v", buf[:n], err)
	}
	if got := atomic.LoadUint64(&fixture.client.sendSeq); got != 1 {
		t.Fatalf("first DATA advanced sequence to %d want 1", got)
	}
}

func TestEngineLeafMobilityAlteredOOBReplayClosesSession(t *testing.T) {
	capture := &captureLeafPreparePath{}
	fixture := newLeafMobilityEngineFixtureWithWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn { capture.PathConn = path; return capture }, nil,
	)
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xc8)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	altered := capture.captured()
	if len(altered) <= proto.HeaderSize {
		t.Fatal("PREPARE was not captured")
	}
	altered[len(altered)-1] ^= 0xff
	if _, err := fixture.clientWire.Write(altered); err != nil {
		t.Fatal(err)
	}
	eventuallyEngine(t, time.Second, fixture.server.IsClosed)
}

func TestEngineLeafMobilityLocalAckWriteFailureDoesNotCloseSession(t *testing.T) {
	sentinel := errors.New("local ACK write failed")
	failer := &failLeafAckPath{phase: proto.LeafMobilityPeerPlanAckPhasePrepared, err: sentinel}
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, func(path *memoryPathConn) transport.PathConn {
		failer.PathConn = path
		return failer
	})
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xd3)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if authority, err := fixture.client.NegotiateLeafMobilityAuthority(ctx, fixture.clientRef, plan); authority != nil || err == nil {
		t.Fatalf("authority=%v error=%v", authority, err)
	}
	time.Sleep(20 * time.Millisecond)
	if fixture.client.IsClosed() || fixture.server.IsClosed() {
		t.Fatal("local ACK write failure was misclassified as a peer protocol error")
	}
	if _, err := fixture.client.SendData([]byte("survives-local-ack-error")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, err := fixture.server.Recv(buf)
	if err != nil || string(buf[:n]) != "survives-local-ack-error" {
		t.Fatalf("payload=%q error=%v", buf[:n], err)
	}
}

func TestEngineLeafMobilityAbandonedTransactionStillPinsAckEvidence(t *testing.T) {
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xd4)
	prepare := proto.LeafMobilityPeerPlanPrepare{
		LeafMobilityPeerPlanBinding: fixture.client.canonicalLeafMobilityBinding(plan, 1000),
		ActorEndpointGeneration:     plan.EndpointGeneration,
		ActorPlanDigest:             proto.LeafMobilityPlanDigest(plan.LocalDigest),
	}
	digest, err := prepare.ProposalDigest()
	if err != nil {
		t.Fatal(err)
	}
	outgoing := &outgoingLeafMobilityTransaction{
		source:  fixture.clientRef,
		prepare: prepare,
		digest:  digest, prepared: make(chan leafMobilityAckEvent, 1), final: make(chan leafMobilityAckEvent, 1),
		released: make(chan leafMobilityAckEvent, 1),
	}
	outgoing.abandoned.Store(true)
	fixture.client.leafTx.mu.Lock()
	fixture.client.leafTx.outgoing = outgoing
	fixture.client.leafTx.mu.Unlock()
	t.Cleanup(func() {
		fixture.client.leafTx.mu.Lock()
		if fixture.client.leafTx.outgoing == outgoing {
			fixture.client.leafTx.outgoing = nil
		}
		fixture.client.leafTx.mu.Unlock()
	})
	ack := proto.LeafMobilityPeerPlanAck{
		LeafMobilityPeerPlanBinding: prepare.LeafMobilityPeerPlanBinding,
		Phase:                       proto.LeafMobilityPeerPlanAckPhasePrepared,
		Code:                        proto.LeafMobilityPeerPlanAckCodeReject,
		CurrentGeneration:           prepare.BaseGeneration,
		ActorEndpointGeneration:     prepare.ActorEndpointGeneration,
		ProposalDigest:              digest,
		Reason:                      "test rejection",
	}
	if err := fixture.client.handleLeafMobilityAck(fixture.clientRef, 100, false, ack); err != nil {
		t.Fatal(err)
	}
	if err := fixture.client.handleLeafMobilityAck(fixture.clientRef, 101, false, ack); err == nil {
		t.Fatal("abandoned transaction accepted a changed ACK message sequence")
	}
}

func TestEngineLeafMobilityAbandonedTransactionRejectsUncorrelatedFinalBeforePinning(t *testing.T) {
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xda)
	prepare := proto.LeafMobilityPeerPlanPrepare{
		LeafMobilityPeerPlanBinding: fixture.client.canonicalLeafMobilityBinding(plan, 1000),
		ActorEndpointGeneration:     plan.EndpointGeneration,
		ActorPlanDigest:             proto.LeafMobilityPlanDigest(plan.LocalDigest),
	}
	proposal, err := prepare.ProposalDigest()
	if err != nil {
		t.Fatal(err)
	}
	generation, err := prepare.ReservedGeneration()
	if err != nil {
		t.Fatal(err)
	}
	peerDigest := proto.LeafMobilityPeerDigest{1}
	reservation := proto.LeafMobilityReservationID{1}
	agreement, err := proto.ComputeLeafMobilityAgreementDigest(
		prepare.LeafMobilityPeerPlanBinding, generation, prepare.ActorEndpointGeneration,
		77, proposal, peerDigest, reservation,
	)
	if err != nil {
		t.Fatal(err)
	}
	commit := proto.LeafMobilityPeerPlanCommit{
		LeafMobilityPeerPlanBinding: prepare.LeafMobilityPeerPlanBinding,
		Stage:                       proto.LeafMobilityPeerPlanCommitStageCommit,
		Generation:                  generation,
		ActorEndpointGeneration:     prepare.ActorEndpointGeneration,
		PeerEndpointGeneration:      77,
		ProposalDigest:              proposal,
		PeerPlanDigest:              peerDigest,
		AgreementDigest:             agreement,
		ReservationID:               reservation,
	}
	outgoing := &outgoingLeafMobilityTransaction{
		source: fixture.clientRef, prepare: prepare, digest: proposal, commit: commit,
		prepared: make(chan leafMobilityAckEvent, 1), final: make(chan leafMobilityAckEvent, 1),
		released: make(chan leafMobilityAckEvent, 1),
	}
	outgoing.abandoned.Store(true)
	fixture.client.leafTx.mu.Lock()
	fixture.client.leafTx.outgoing = outgoing
	fixture.client.leafTx.mu.Unlock()
	t.Cleanup(func() {
		fixture.client.leafTx.mu.Lock()
		if fixture.client.leafTx.outgoing == outgoing {
			fixture.client.leafTx.outgoing = nil
		}
		fixture.client.leafTx.mu.Unlock()
	})
	forgedPeerDigest := proto.LeafMobilityPeerDigest{2}
	forgedReservation := proto.LeafMobilityReservationID{2}
	forgedAgreement, err := proto.ComputeLeafMobilityAgreementDigest(
		prepare.LeafMobilityPeerPlanBinding, generation, prepare.ActorEndpointGeneration,
		78, proposal, forgedPeerDigest, forgedReservation,
	)
	if err != nil {
		t.Fatal(err)
	}
	forged := proto.LeafMobilityPeerPlanAck{
		LeafMobilityPeerPlanBinding: prepare.LeafMobilityPeerPlanBinding,
		Phase:                       proto.LeafMobilityPeerPlanAckPhaseFinal,
		Code:                        proto.LeafMobilityPeerPlanAckCodeAccept,
		Stage:                       proto.LeafMobilityPeerPlanCommitStageCommit,
		CurrentGeneration:           generation,
		Generation:                  generation,
		ActorEndpointGeneration:     prepare.ActorEndpointGeneration,
		PeerEndpointGeneration:      78,
		ProposalDigest:              proposal,
		PeerPlanDigest:              forgedPeerDigest,
		AgreementDigest:             forgedAgreement,
		ReservationID:               forgedReservation,
	}
	if _, err := forged.Encode(); err != nil {
		t.Fatalf("forged ACK is not internally self-consistent: %v", err)
	}
	if err := fixture.client.handleLeafMobilityAck(fixture.clientRef, 102, false, forged); err == nil {
		t.Fatal("abandoned transaction pinned an ACK not correlated to local COMMIT")
	}
	if outgoing.finalSeq != 0 || outgoing.finalAck != (proto.LeafMobilityPeerPlanAck{}) {
		t.Fatalf("uncorrelated FINAL was pinned: seq=%d ack=%+v", outgoing.finalSeq, outgoing.finalAck)
	}
}

func TestEngineLeafMobilityTombstoneRejectsAlteredAckAfterOOBExpiry(t *testing.T) {
	serverCapture := &captureLeafOOBPath{}
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, func(path *memoryPathConn) transport.PathConn {
		serverCapture.PathConn = path
		return serverCapture
	})
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xd5)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	var original []byte
	for _, frame := range serverCapture.captured() {
		if leafMobilityAckPhase(frame) == proto.LeafMobilityPeerPlanAckPhaseFinal {
			original = frame
			break
		}
	}
	if len(original) == 0 {
		t.Fatal("did not capture FINAL ACK")
	}
	header, err := proto.DecodeHeader(original[:proto.HeaderSize])
	if err != nil {
		t.Fatal(err)
	}
	ack, err := proto.DecodeLeafMobilityPeerPlanAck(original[proto.HeaderSize:])
	if err != nil {
		t.Fatal(err)
	}
	ack.Code = proto.LeafMobilityPeerPlanAckCodeSuperseded
	ack.Reason = "altered terminal evidence"
	payload, err := ack.Encode()
	if err != nil {
		t.Fatal(err)
	}
	altered := make([]byte, proto.HeaderSize+len(payload))
	if err := header.Encode(altered[:proto.HeaderSize]); err != nil {
		t.Fatal(err)
	}
	copy(altered[proto.HeaderSize:], payload)
	fixture.client.leafTx.oobMu.Lock()
	delete(fixture.client.leafTx.oobSeen, leafMobilityOOBKey{source: fixture.clientRef, seq: header.Seq})
	fixture.client.leafTx.oobMu.Unlock()
	if _, err := fixture.serverWire.Write(altered); err != nil {
		t.Fatal(err)
	}
	eventuallyEngine(t, time.Second, fixture.client.IsClosed)
}

func TestEngineLeafMobilityOOBLedgerCapacityDropsNewFrameWithoutClosing(t *testing.T) {
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
	fixture.server.leafTx.oobMu.Lock()
	for index := 0; index < leafMobilityOOBRecordLimit; index++ {
		fixture.server.leafTx.oobSeen[leafMobilityOOBKey{
			source: PathRef{ID: uint32(index + 100), Owner: 1}, seq: uint64(index + 1),
		}] = leafMobilityOOBRecord{retireAfter: time.Now().Add(time.Minute)}
	}
	fixture.server.leafTx.oobMu.Unlock()
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xd6)
	lease := time.Until(plan.Deadline)
	if lease > leafmobility.MaxPlanHorizon {
		lease = leafmobility.MaxPlanHorizon
	}
	prepare := proto.LeafMobilityPeerPlanPrepare{
		LeafMobilityPeerPlanBinding: fixture.client.canonicalLeafMobilityBinding(plan, uint32(lease/time.Millisecond)),
		ActorEndpointGeneration:     plan.EndpointGeneration,
		ActorPlanDigest:             proto.LeafMobilityPlanDigest(plan.LocalDigest),
	}
	if _, err := fixture.client.sendLeafMobilityPrepare(fixture.clientRef, prepare); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if fixture.server.IsClosed() {
		t.Fatal("OOB ledger capacity pressure closed the session")
	}
	fixture.server.leafTx.mu.Lock()
	incoming := len(fixture.server.leafTx.incoming)
	fixture.server.leafTx.mu.Unlock()
	if incoming != 0 {
		t.Fatalf("capacity-dropped PREPARE created %d incoming transactions", incoming)
	}
}

func TestEngineLeafMobilitySemanticRetryWithNewOOBSequenceClosesSession(t *testing.T) {
	tests := []struct {
		name       string
		fromClient bool
		match      func([]byte) bool
	}{
		{
			name:       "prepare",
			fromClient: true,
			match: func(frame []byte) bool {
				header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
				return err == nil && proto.CtrlCodeFromFlags(header.Flags) == proto.CtrlLeafMobilityPrepare
			},
		},
		{
			name:       "commit",
			fromClient: true,
			match: func(frame []byte) bool {
				return leafMobilityCommitStage(frame) == proto.LeafMobilityPeerPlanCommitStageCommit
			},
		},
		{
			name:       "resolution",
			fromClient: true,
			match: func(frame []byte) bool {
				return leafMobilityCommitStage(frame) == proto.LeafMobilityPeerPlanCommitStageRolledBack
			},
		},
		{
			name: "ack",
			match: func(frame []byte) bool {
				return leafMobilityAckPhase(frame) == proto.LeafMobilityPeerPlanAckPhasePrepared
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clientCapture := &captureLeafOOBPath{}
			serverCapture := &captureLeafOOBPath{}
			fixture := newLeafMobilityEngineFixtureWithWrappers(
				t, leafmobility.Resource{}, leafmobility.Resource{},
				func(path *memoryPathConn) transport.PathConn { clientCapture.PathConn = path; return clientCapture },
				func(path *memoryPathConn) transport.PathConn { serverCapture.PathConn = path; return serverCapture },
			)
			plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xd0)
			authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
			if err != nil {
				t.Fatal(err)
			}
			if err := authority.Rollback(context.Background()); err != nil {
				t.Fatal(err)
			}
			capture := serverCapture
			wire := fixture.serverWire
			receiver := fixture.client
			if test.fromClient {
				capture = clientCapture
				wire = fixture.clientWire
				receiver = fixture.server
			}
			var retry []byte
			for _, frame := range capture.captured() {
				if len(frame) >= proto.HeaderSize && test.match(frame) {
					retry = frame
					break
				}
			}
			if len(retry) == 0 {
				t.Fatalf("did not capture %s frame", test.name)
			}
			header, err := proto.DecodeHeader(retry[:proto.HeaderSize])
			if err != nil {
				t.Fatal(err)
			}
			header.Seq++
			if err := header.Encode(retry[:proto.HeaderSize]); err != nil {
				t.Fatal(err)
			}
			if _, err := wire.Write(retry); err != nil {
				t.Fatal(err)
			}
			eventuallyEngine(t, time.Second, receiver.IsClosed)
		})
	}
}

func TestEngineLeafMobilityOOBReplayKeepsOriginalRoute(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{})
	t.Cleanup(func() { _ = e.Close() })
	first, firstPeer := newMemoryPathPair()
	second, secondPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = firstPeer.Close(); _ = secondPeer.Close() })
	firstID, err := e.AttachPath(first, transport.PathSpec{Transport: "memory"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.AttachPath(second, transport.PathSpec{Transport: "memory"}); err != nil {
		t.Fatal(err)
	}
	ref, ok := e.PathRef(firstID)
	if !ok {
		t.Fatal("missing original route")
	}
	first.dropWrites.Store(true)
	frame, err := e.sendLeafMobilityFrameAt(ref, proto.CtrlLeafMobilityPrepare, []byte{1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	first.dropWrites.Store(false)
	if err := e.replayLeafMobilityFrame(ref, frame); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-firstPeer.in:
		if string(got) != string(frame) {
			t.Fatal("original route received altered replay")
		}
	case <-time.After(time.Second):
		t.Fatal("original route did not receive pinned replay")
	}
	select {
	case <-secondPeer.in:
		t.Fatal("generic replay moved a leaf transaction to another route")
	default:
	}
}

func TestEngineLeafMobilitySimultaneousActorsResolveDeterministically(t *testing.T) {
	clientBlock := &blockLeafWritePath{reached: make(chan struct{}), release: make(chan struct{})}
	serverBlock := &blockLeafWritePath{reached: make(chan struct{}), release: make(chan struct{})}
	fixture := newLeafMobilityEngineFixtureWithWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn { clientBlock.PathConn = path; return clientBlock },
		func(path *memoryPathConn) transport.PathConn { serverBlock.PathConn = path; return serverBlock },
	)
	clientPlan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xb5)
	serverPlan := engineLeafPlan(t, fixture.server, fixture.serverRef, 0xb6)
	type outcome struct {
		authority *LeafMobilityAuthority
		err       error
	}
	clientResult := make(chan outcome, 1)
	serverResult := make(chan outcome, 1)
	go func() {
		authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, clientPlan)
		clientResult <- outcome{authority: authority, err: err}
	}()
	go func() {
		authority, err := fixture.server.NegotiateLeafMobilityAuthority(context.Background(), fixture.serverRef, serverPlan)
		serverResult <- outcome{authority: authority, err: err}
	}()
	for _, reached := range []<-chan struct{}{clientBlock.reached, serverBlock.reached} {
		select {
		case <-reached:
		case <-time.After(time.Second):
			t.Fatal("simultaneous actor did not publish prepare")
		}
	}
	close(clientBlock.release)
	close(serverBlock.release)
	clientOutcome := <-clientResult
	serverOutcome := <-serverResult
	if clientOutcome.err != nil || clientOutcome.authority == nil {
		t.Fatalf("client-priority outcome authority=%v error=%v clientClose=%v serverClose=%v clientGen=%d serverGen=%d",
			clientOutcome.authority, clientOutcome.err, fixture.client.CloseErr(), fixture.server.CloseErr(),
			fixture.clientResource.Snapshot().Generation, fixture.serverResource.Snapshot().Generation)
	}
	if serverOutcome.authority != nil ||
		(!errors.Is(serverOutcome.err, ErrLeafMobilityRejected) && !errors.Is(serverOutcome.err, ErrLeafMobilityAuthorityBusy)) {
		t.Fatalf("server outcome authority=%v error=%v", serverOutcome.authority, serverOutcome.err)
	}
	if err := clientOutcome.authority.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestEngineLeafMobilityBusyIsImmutableForTransactionID(t *testing.T) {
	capture := &captureLeafAckPath{}
	fixture := newLeafMobilityEngineFixtureWithWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn { capture.PathConn = path; return capture }, nil,
	)
	plan := engineLeafPlan(t, fixture.server, fixture.serverRef, 0xc9)
	lease := time.Until(plan.Deadline)
	if lease > leafmobility.MaxPlanHorizon {
		lease = leafmobility.MaxPlanHorizon
	}
	prepare := proto.LeafMobilityPeerPlanPrepare{
		LeafMobilityPeerPlanBinding: fixture.server.canonicalLeafMobilityBinding(plan, uint32(lease/time.Millisecond)),
		ActorEndpointGeneration:     plan.EndpointGeneration,
		ActorPlanDigest:             proto.LeafMobilityPlanDigest(plan.LocalDigest),
	}
	fixture.client.leafTx.mu.Lock()
	fixture.client.leafTx.outgoing = &outgoingLeafMobilityTransaction{
		prepare: proto.LeafMobilityPeerPlanPrepare{
			LeafMobilityPeerPlanBinding: proto.LeafMobilityPeerPlanBinding{
				ActorSide: proto.LeafMobilityActorClient,
			},
		},
	}
	fixture.client.leafTx.mu.Unlock()
	const prepareSeq = uint64(77)
	if err := fixture.client.handleLeafMobilityPrepare(fixture.clientRef, prepareSeq, false, prepare); err != nil {
		t.Fatal(err)
	}
	fixture.client.leafTx.mu.Lock()
	fixture.client.leafTx.outgoing = nil
	fixture.client.leafTx.mu.Unlock()
	if err := fixture.client.handleLeafMobilityPrepare(fixture.clientRef, prepareSeq, true, prepare); err != nil {
		t.Fatal(err)
	}
	frames := capture.captured()
	if len(frames) != 2 || !bytes.Equal(frames[0], frames[1]) {
		t.Fatalf("Busy replay frames=%d exact=%t", len(frames), len(frames) == 2 && bytes.Equal(frames[0], frames[1]))
	}
	header, err := proto.DecodeHeader(frames[0][:proto.HeaderSize])
	if err != nil || header.Seq == 0 {
		t.Fatalf("Busy OOB header=%+v error=%v", header, err)
	}
	ack, err := proto.DecodeLeafMobilityPeerPlanAck(frames[0][proto.HeaderSize:])
	if err != nil || ack.Code != proto.LeafMobilityPeerPlanAckCodeBusy {
		t.Fatalf("Busy ACK=%+v error=%v", ack, err)
	}
	fixture.client.leafTx.mu.Lock()
	incoming, rejected := len(fixture.client.leafTx.incoming), len(fixture.client.leafTx.rejected)
	fixture.client.leafTx.mu.Unlock()
	if incoming != 0 || rejected != 1 {
		t.Fatalf("post-Busy records incoming=%d rejected=%d", incoming, rejected)
	}
}

func TestEngineLeafMobilityInvalidBindingsCannotPoisonPeerLedgerCapacity(t *testing.T) {
	capture := &captureLeafAckPath{}
	fixture := newLeafMobilityEngineFixtureWithWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn { capture.PathConn = path; return capture }, nil,
	)
	plan := engineLeafPlan(t, fixture.server, fixture.serverRef, 0xca)
	base := proto.LeafMobilityPeerPlanPrepare{
		LeafMobilityPeerPlanBinding: fixture.server.canonicalLeafMobilityBinding(plan, 1000),
		ActorEndpointGeneration:     plan.EndpointGeneration,
		ActorPlanDigest:             proto.LeafMobilityPlanDigest(plan.LocalDigest),
	}
	for index := 0; index < leafMobilityRecordLimit*2; index++ {
		prepare := base
		value := index + 1
		prepare.TransactionID = [16]byte{byte(value >> 8), byte(value)}
		prepare.ResourceID = proto.LeafMobilityResourceID{byte(value >> 8), byte(value)}
		prepare.ClientGraph.Revision++
		if err := fixture.client.handleLeafMobilityPrepare(fixture.clientRef, uint64(index+1), false, prepare); err != nil {
			t.Fatalf("invalid prepare %d: %v", index, err)
		}
	}
	fixture.client.leafTx.peerLedger.mu.Lock()
	ledgerEntries := len(fixture.client.leafTx.peerLedger.entries)
	fixture.client.leafTx.peerLedger.mu.Unlock()
	if ledgerEntries != 0 {
		t.Fatalf("invalid bindings installed %d peer ledger entries", ledgerEntries)
	}
}

func TestEngineLeafMobilityClientPreemptsServerDuringIncomingPreflight(t *testing.T) {
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
	clientPlan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xc1)
	serverPlan := engineLeafPlan(t, fixture.server, fixture.serverRef, 0xc2)
	fixture.clientDriver.entered = make(chan struct{})
	fixture.clientDriver.release = make(chan struct{})
	type outcome struct {
		authority *LeafMobilityAuthority
		err       error
	}
	serverResult := make(chan outcome, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		authority, err := fixture.server.NegotiateLeafMobilityAuthority(ctx, fixture.serverRef, serverPlan)
		serverResult <- outcome{authority: authority, err: err}
	}()
	select {
	case <-fixture.clientDriver.entered:
	case <-time.After(time.Second):
		t.Fatal("server PREPARE did not enter client preflight")
	}
	clientResult := make(chan outcome, 1)
	go func() {
		authority, err := fixture.client.NegotiateLeafMobilityAuthority(ctx, fixture.clientRef, clientPlan)
		clientResult <- outcome{authority: authority, err: err}
	}()
	eventuallyEngine(t, time.Second, func() bool {
		fixture.client.leafTx.mu.Lock()
		defer fixture.client.leafTx.mu.Unlock()
		return fixture.client.leafTx.outgoing != nil
	})
	close(fixture.clientDriver.release)
	clientOutcome := <-clientResult
	serverOutcome := <-serverResult
	if clientOutcome.err != nil || clientOutcome.authority == nil {
		fixture.client.leafTx.mu.Lock()
		clientOutgoing, clientIncoming := fixture.client.leafTx.outgoing != nil, len(fixture.client.leafTx.incoming)
		fixture.client.leafTx.mu.Unlock()
		fixture.server.leafTx.mu.Lock()
		serverOutgoing, serverIncoming := fixture.server.leafTx.outgoing != nil, len(fixture.server.leafTx.incoming)
		fixture.server.leafTx.mu.Unlock()
		t.Fatalf("client outcome authority=%v error=%v client(out=%t,in=%d) server(out=%t,in=%d) serverOutcome=%v clientClose=%v serverClose=%v clientGen=%d serverGen=%d",
			clientOutcome.authority, clientOutcome.err, clientOutgoing, clientIncoming, serverOutgoing, serverIncoming, serverOutcome.err,
			fixture.client.CloseErr(), fixture.server.CloseErr(), fixture.clientResource.Snapshot().Generation, fixture.serverResource.Snapshot().Generation)
	}
	if serverOutcome.authority != nil ||
		(!errors.Is(serverOutcome.err, ErrLeafMobilityAuthorityBusy) && !errors.Is(serverOutcome.err, ErrLeafMobilityRejected)) {
		t.Fatalf("server outcome authority=%v error=%v", serverOutcome.authority, serverOutcome.err)
	}
	if err := clientOutcome.authority.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestEngineLeafMobilityOldOOBReplayOnReplacementRouteCannotAuthorizeOrClose(t *testing.T) {
	capture := &captureLeafPreparePath{}
	fixture := newLeafMobilityEngineFixtureWithWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn { capture.PathConn = path; return capture }, nil,
	)
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xb7)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	oldPrepare := capture.captured()
	if len(oldPrepare) == 0 {
		t.Fatal("prepare frame was not captured")
	}
	clientB, serverB := newMemoryPathPair()
	if _, err := fixture.client.AttachPathBound(clientB, transport.PathSpec{Transport: "memory"}, PathBinding{
		LocalTXTargetID: fixture.ids["a"], PeerTXTargetID: fixture.ids["a"],
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.server.AttachPathBound(serverB, transport.PathSpec{Transport: "memory"}, PathBinding{
		LocalTXTargetID: fixture.ids["a"], PeerTXTargetID: fixture.ids["a"],
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := clientB.Write(oldPrepare); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if fixture.server.IsClosed() {
		t.Fatal("old replay on another path closed the healthy session")
	}
	if _, err := fixture.client.SendData([]byte("still-live")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, err := fixture.server.Recv(buf)
	if err != nil || string(buf[:n]) != "still-live" {
		t.Fatalf("payload=%q err=%v", buf[:n], err)
	}
}

func TestEngineLeafMobilityQueuedReplayOnRetiredRouteDoesNotCloseSurvivor(t *testing.T) {
	clientCapture := &captureLeafOOBPath{}
	fixture := newLeafMobilityEngineFixtureWithWrappers(
		t, leafmobility.Resource{}, leafmobility.Resource{},
		func(path *memoryPathConn) transport.PathConn { clientCapture.PathConn = path; return clientCapture }, nil,
	)
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xd9)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	var queued leafMobilityMessage
	for _, frame := range clientCapture.captured() {
		if leafMobilityCommitStage(frame) != proto.LeafMobilityPeerPlanCommitStageCommit {
			continue
		}
		header, decodeErr := proto.DecodeHeader(frame[:proto.HeaderSize])
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		commit, decodeErr := proto.DecodeLeafMobilityPeerPlanCommit(frame[proto.HeaderSize:])
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		queued = leafMobilityMessage{
			kind: leafMobilityMessageCommit, source: fixture.serverRef, seq: header.Seq, replayed: true, commit: commit,
		}
		break
	}
	if queued.kind == 0 {
		t.Fatal("did not capture COMMIT for queued replay")
	}
	clientB, serverB := newMemoryPathPair()
	if _, err := fixture.client.AttachPathBound(clientB, transport.PathSpec{Transport: "memory"}, PathBinding{
		LocalTXTargetID: fixture.ids["b"], PeerTXTargetID: fixture.ids["b"],
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.server.AttachPathBound(serverB, transport.PathSpec{Transport: "memory"}, PathBinding{
		LocalTXTargetID: fixture.ids["b"], PeerTXTargetID: fixture.ids["b"],
	}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.client.RemovePath(fixture.clientRef.ID); err != nil {
		t.Fatal(err)
	}
	if err := fixture.server.RemovePath(fixture.serverRef.ID); err != nil {
		t.Fatal(err)
	}
	if !fixture.server.enqueueLeafMobilityMessageLocked(queued) {
		t.Fatal("could not enqueue old-route replay")
	}
	time.Sleep(20 * time.Millisecond)
	if fixture.client.IsClosed() || fixture.server.IsClosed() {
		t.Fatal("stale response write closed a session with a healthy survivor")
	}
	if _, err := fixture.client.SendData([]byte("queued-old-route-survivor")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, err := fixture.server.Recv(buf)
	if err != nil || string(buf[:n]) != "queued-old-route-survivor" {
		t.Fatalf("payload=%q error=%v", buf[:n], err)
	}
}

func TestEngineLeafMobilityRetainedRouteAbortReleasesResponseGate(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{})
	t.Cleanup(func() { _ = e.Close() })
	old, oldPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = oldPeer.Close() })
	blocker := &closeUnblocksLeafWritePath{
		PathConn: old, reached: make(chan struct{}), release: make(chan struct{}),
	}
	oldID, err := e.AttachPath(blocker, transport.PathSpec{Transport: "memory"})
	if err != nil {
		t.Fatal(err)
	}
	oldRef, ok := e.PathRef(oldID)
	if !ok {
		t.Fatal("missing old path ref")
	}
	healthy, healthyPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = healthyPeer.Close() })
	healthyID, err := e.AttachPath(healthy, transport.PathSpec{Transport: "memory"})
	if err != nil {
		t.Fatal(err)
	}
	healthyRef, ok := e.PathRef(healthyID)
	if !ok {
		t.Fatal("missing healthy path ref")
	}
	e.pathsMu.Lock()
	slot := e.paths[oldID]
	delete(e.paths, oldID)
	e.retainedPaths[oldID] = slot
	e.activeID = healthyID
	e.pathsMu.Unlock()

	frame := make([]byte, proto.HeaderSize)
	if err := (proto.Header{
		Version: proto.Version, Type: proto.FrameCtrl,
		Flags: proto.FlagsForCtrl(proto.CtrlLeafMobilityAck), Seq: 1,
	}).Encode(frame); err != nil {
		t.Fatal(err)
	}
	err = e.replayLeafMobilityResponse(oldRef, frame, time.Now().Add(20*time.Millisecond))
	if !errors.Is(err, errLeafMobilityResponseUnavailable) {
		t.Fatalf("retained route replay error=%v want response unavailable", err)
	}
	select {
	case <-blocker.reached:
	default:
		t.Fatal("test did not block retained-route writer")
	}
	eventuallyEngine(t, time.Second, func() bool { return len(e.leafTx.responseGate) == 0 })
	if err := e.replayLeafMobilityResponse(healthyRef, frame, time.Now().Add(time.Second)); err != nil {
		t.Fatalf("retained writer held response gate against healthy route: %v", err)
	}
}

func TestEngineLeafMobilityAuthorityBlocksAdmissionAcrossEngines(t *testing.T) {
	shared := leafmobility.MustNewResource(leafmobility.ScopeProcessLocal)
	fixture := newLeafMobilityEngineFixture(t, shared, leafmobility.Resource{}, nil)
	driver := &enginePlanDriver{operation: leafmobility.OperationTCPRepair, evidence: leafmobility.EvidenceDigest{0xb1}}
	claim := leafmobility.MustNewDrivenClaim(leafmobility.Facts{
		Kind: leafmobility.KindRawTCP, Role: leafmobility.RoleDialer,
		Session: leafmobility.SessionStream, Generation: leafmobility.NextGeneration(),
	}, driver, shared)
	other, otherRef := engineWithPlannableLeaf(t, claim, mustEngineCapability(t, driver), proto.LeafMobilityTCPRepair)
	binding := enginePathBinding(t, other, otherRef)
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xa5)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authority.Rollback(context.Background()) })
	candidate, remote := newMemoryPathPair()
	defer remote.Close()
	if _, err := other.PreparePathBound(candidate, transport.PathSpec{Transport: "memory"}, binding); !errors.Is(err, ErrLeafMobilityAuthorityBusy) {
		t.Fatalf("cross-engine admission error=%v want=%v", err, ErrLeafMobilityAuthorityBusy)
	}
}

func TestEngineLeafMobilityResourceGenerationSurvivesNewSession(t *testing.T) {
	resource := leafmobility.MustNewResource(leafmobility.ScopeEndpoint)
	peerLedger := NewLeafMobilityPeerLedger()
	first := newLeafMobilityEngineFixture(t, resource, leafmobility.Resource{}, nil)
	first.server.SetLeafMobilityPeerLedger(peerLedger)
	firstPlan := engineLeafPlan(t, first.client, first.clientRef, 0xa8)
	firstAuthority, err := first.client.NegotiateLeafMobilityAuthority(context.Background(), first.clientRef, firstPlan)
	if err != nil {
		t.Fatal(err)
	}
	if err := firstAuthority.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = first.client.Close()
	_ = first.server.Close()

	second := newLeafMobilityEngineFixture(t, resource, leafmobility.Resource{}, nil)
	second.server.SetLeafMobilityPeerLedger(peerLedger)
	secondPlan := engineLeafPlan(t, second.client, second.clientRef, 0xa9)
	if secondPlan.BaseGeneration != 1 {
		t.Fatalf("new session base=%d want=1", secondPlan.BaseGeneration)
	}
	secondAuthority, err := second.client.NegotiateLeafMobilityAuthority(context.Background(), second.clientRef, secondPlan)
	if err != nil {
		t.Fatal(err)
	}
	if resource.Snapshot().Generation != 2 {
		t.Fatalf("resource generation=%d want=2", resource.Snapshot().Generation)
	}
	if err := secondAuthority.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestEngineLeafMobilityActorTombstoneCapacityReturnsBusy(t *testing.T) {
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
	fixture.client.leafTx.mu.Lock()
	for i := 0; i < leafMobilityRecordLimit; i++ {
		var id [16]byte
		id[0], id[1] = byte(i), byte(i>>8)
		fixture.client.leafTx.actorTerminal[id] = actorLeafMobilityTombstone{
			retireAfter: time.Now().Add(time.Minute),
		}
	}
	fixture.client.leafTx.mu.Unlock()
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xbf)
	if authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan); authority != nil || !errors.Is(err, ErrLeafMobilityAuthorityBusy) {
		t.Fatalf("authority=%v error=%v", authority, err)
	}
	if fixture.clientClaim.ExecutionGeneration() != 0 {
		t.Fatalf("capacity rejection changed generation to %d", fixture.clientClaim.ExecutionGeneration())
	}
}

func TestEngineCloseSynchronouslyPoisonsConsumedLeafMobilityAuthority(t *testing.T) {
	fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
	plan := engineLeafPlan(t, fixture.client, fixture.clientRef, 0xa6)
	authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := authority.Consume()
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.client.Close(); err != nil {
		t.Fatal(err)
	}
	if authority.State() != leafmobility.ResourceTransactionOutcomeUnknown || permit.State() != leafmobility.ResourceTransactionOutcomeUnknown {
		t.Fatalf("states after Close authority=%d permit=%d", authority.State(), permit.State())
	}
	if len(fixture.client.leafTx.sendGate) != 0 {
		t.Fatal("Close retained leaf mobility send gate after the writer had exited")
	}
	if !fixture.clientResource.Snapshot().Poisoned {
		t.Fatal("consumed authority close did not keep the resource fail-closed")
	}
	if err := fixture.server.Close(); err != nil {
		t.Fatal(err)
	}
	if !fixture.serverResource.Snapshot().Poisoned {
		t.Fatal("responder close released a committed peer guard")
	}
}

func TestEngineLeafMobilityConsumeLinearizesWithClose(t *testing.T) {
	for iteration := 0; iteration < 25; iteration++ {
		fixture := newLeafMobilityEngineFixture(t, leafmobility.Resource{}, leafmobility.Resource{}, nil)
		plan := engineLeafPlan(t, fixture.client, fixture.clientRef, byte(0xd0+iteration))
		authority, err := fixture.client.NegotiateLeafMobilityAuthority(context.Background(), fixture.clientRef, plan)
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		permitResult := make(chan *LeafMobilityPermit, 1)
		errorResult := make(chan error, 1)
		closed := make(chan error, 1)
		go func() {
			<-start
			permit, err := authority.Consume()
			permitResult <- permit
			errorResult <- err
		}()
		go func() {
			<-start
			closed <- fixture.client.Close()
		}()
		close(start)
		permit, consumeErr := <-permitResult, <-errorResult
		if err := <-closed; err != nil {
			t.Fatal(err)
		}
		if permit != nil {
			if consumeErr != nil {
				t.Fatalf("iteration %d returned permit with error %v", iteration, consumeErr)
			}
			if permit.State() != leafmobility.ResourceTransactionOutcomeUnknown {
				t.Fatalf("iteration %d stale permit state=%d", iteration, permit.State())
			}
		} else if consumeErr == nil {
			t.Fatalf("iteration %d returned neither permit nor error", iteration)
		}
		if !fixture.clientResource.Snapshot().Poisoned {
			t.Fatalf("iteration %d released resource across Close/Consume race", iteration)
		}
		_ = fixture.server.Close()
	}
}

func newLeafMobilityEngineFixture(
	t *testing.T,
	clientResource leafmobility.Resource,
	serverResource leafmobility.Resource,
	wrapServer func(*memoryPathConn) transport.PathConn,
) leafMobilityEngineFixture {
	return newLeafMobilityEngineFixtureWithWrappers(t, clientResource, serverResource, nil, wrapServer)
}

func newLeafMobilityEngineFixtureWithWrappers(
	t *testing.T,
	clientResource leafmobility.Resource,
	serverResource leafmobility.Resource,
	wrapClient func(*memoryPathConn) transport.PathConn,
	wrapServer func(*memoryPathConn) transport.PathConn,
) leafMobilityEngineFixture {
	t.Helper()
	if clientResource.Snapshot().ID == (leafmobility.ResourceID{}) {
		clientResource = leafmobility.MustNewResource(leafmobility.ScopeEndpoint)
	}
	if serverResource.Snapshot().ID == (leafmobility.ResourceID{}) {
		serverResource = leafmobility.MustNewResource(leafmobility.ScopeEndpoint)
	}
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{}.Clamp())
	server := New(SideServer, flow, Limits{}.Clamp())
	clientInstance := proto.InstanceID{0xc1}
	serverInstance := proto.InstanceID{0xc2}
	client.SetLocalInstanceID(clientInstance)
	client.SetPeerInstanceID(serverInstance)
	server.SetLocalInstanceID(serverInstance)
	server.SetPeerInstanceID(clientInstance)
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	clientDriver := &enginePlanDriver{operation: leafmobility.OperationTCPRepair, evidence: leafmobility.EvidenceDigest{0xc1}}
	serverDriver := &enginePlanDriver{operation: leafmobility.OperationTCPRepair, evidence: leafmobility.EvidenceDigest{0xc2}}
	clientClaim := leafmobility.MustNewDrivenClaim(leafmobility.Facts{
		Kind: leafmobility.KindRawTCP, Role: leafmobility.RoleDialer,
		Session: leafmobility.SessionStream, Generation: leafmobility.NextGeneration(),
	}, clientDriver, clientResource)
	serverClaim := leafmobility.MustNewDrivenClaim(leafmobility.Facts{
		Kind: leafmobility.KindRawTCP, Role: leafmobility.RoleAcceptor,
		Session: leafmobility.SessionStream, Generation: leafmobility.NextGeneration(),
	}, serverDriver, serverResource)
	for _, configured := range []struct {
		engine *Engine
		driver leafmobility.Driver
	}{
		{client, clientDriver}, {server, serverDriver},
	} {
		if err := configured.engine.ConfigureLocalMobilityCapabilities(mustEngineCapability(t, configured.driver)); err != nil {
			t.Fatal(err)
		}
		if err := configured.engine.ConfigureLocalGraph(1, manifest); err != nil {
			t.Fatal(err)
		}
	}
	if err := client.AcceptPeerNegotiation(server.LocalNegotiation(), server.LocalGraphManifest()); err != nil {
		t.Fatal(err)
	}
	if err := server.AcceptPeerNegotiation(client.LocalNegotiation(), client.LocalGraphManifest()); err != nil {
		t.Fatal(err)
	}
	clientPath, serverBase := newMemoryPathPair()
	clientConn := transport.PathConn(clientPath)
	if wrapClient != nil {
		clientConn = wrapClient(clientPath)
	}
	serverPath := transport.PathConn(serverBase)
	if wrapServer != nil {
		serverPath = wrapServer(serverBase)
	}
	binding := PathBinding{LocalTXTargetID: ids["a"], PeerTXTargetID: ids["a"]}
	clientID, err := client.AttachPathBound(&claimedMemoryPath{PathConn: clientConn, claim: clientClaim}, transport.PathSpec{Transport: "memory"}, binding)
	if err != nil {
		t.Fatal(err)
	}
	serverID, err := server.AttachPathBound(&claimedMemoryPath{PathConn: serverPath, claim: serverClaim}, transport.PathSpec{Transport: "memory"}, binding)
	if err != nil {
		t.Fatal(err)
	}
	clientRef, clientOK := client.PathRef(clientID)
	serverRef, serverOK := server.PathRef(serverID)
	if !clientOK || !serverOK {
		t.Fatal("missing exact path refs")
	}
	return leafMobilityEngineFixture{
		client: client, server: server, clientRef: clientRef, serverRef: serverRef,
		clientWire: clientPath, serverWire: serverBase,
		clientClaim: clientClaim, serverClaim: serverClaim,
		clientDriver: clientDriver, serverDriver: serverDriver,
		clientResource: clientResource, serverResource: serverResource,
		binding: binding, ids: ids,
	}
}

func engineLeafPlan(t testing.TB, engine *Engine, ref PathRef, transaction byte) leafmobility.Plan {
	t.Helper()
	plan, err := engine.PlanLeafMobilityCandidate(
		context.Background(), ref, leafmobility.TransactionID{transaction}, proto.SenderDirectionClientToServer,
	)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Operation != leafmobility.OperationTCPRepair {
		t.Fatalf("plan=%+v", plan)
	}
	return plan
}

func enginePathBinding(t testing.TB, engine *Engine, ref PathRef) PathBinding {
	t.Helper()
	engine.pathsMu.RLock()
	slot := engine.paths[ref.ID]
	if slot == nil || slot.owner != ref.Owner {
		engine.pathsMu.RUnlock()
		t.Fatal("missing exact path")
	}
	binding := PathBinding{LocalTXTargetID: slot.localTXTargetID, PeerTXTargetID: slot.peerTXTargetID}
	engine.pathsMu.RUnlock()
	return binding
}

func eventuallyEngine(t testing.TB, timeout time.Duration, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition did not become true")
}
