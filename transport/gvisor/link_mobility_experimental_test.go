//go:build linux && amd64 && rendr_experimental_gvisor

package gvisor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
	basetcp "github.com/FrankoonG/rendr/transport/tcp"
)

func TestGVisorPacketLinkRebindPreservesBidirectionalPayload(t *testing.T) {
	listener := mustPacketListener(t)
	defer listener.Close()
	client, server := dialAndAccept(t, listener)
	defer client.Close()
	defer server.Close()

	clientPath := client.(*retainedPathConn)
	serverPath := server.(*retainedPathConn)
	clientObject := clientPath
	serverObject := serverPath
	clientLinkID := clientPath.link.id
	serverLinkID := serverPath.link.id
	clientVirtualLocal := client.LocalAddr()
	clientVirtualRemote := client.RemoteAddr()
	serverVirtualLocal := server.LocalAddr()
	serverVirtualRemote := server.RemoteAddr()
	clientOuterBefore := clientPath.link.active.conn.LocalAddr().String()
	serverOuterBefore := serverPath.link.active.conn.LocalAddr().String()
	clientIncarnation := clientPath.link.LeafMobilityIncarnation()
	serverIncarnation := serverPath.link.LeafMobilityIncarnation()

	const frames = 4096
	const payloadSize = 16 * 1024
	clientProgress := &atomic.Uint64{}
	serverProgress := &atomic.Uint64{}
	errorsCh := make(chan error, 4)
	var transfers sync.WaitGroup
	transfers.Add(4)
	go writeFrames(client, 0x31, frames, payloadSize, clientProgress, &transfers, errorsCh)
	go readFrames(server, 0x31, frames, payloadSize, &transfers, errorsCh)
	go writeFrames(server, 0x72, frames, payloadSize, serverProgress, &transfers, errorsCh)
	go readFrames(client, 0x72, frames, payloadSize, &transfers, errorsCh)
	waitForProgress(t, clientProgress, serverProgress, 32)

	executePacketLinkRebind(t, clientPath, 1)
	executePacketLinkRebind(t, serverPath, 2)

	done := make(chan struct{})
	go func() {
		transfers.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		var transferErr error
		select {
		case transferErr = <-errorsCh:
		default:
		}
		clientPath.link.mu.Lock()
		clientReplay, clientReplayBytes := len(clientPath.link.replayPackets), clientPath.link.replayBytes
		clientSend, clientReceive := clientPath.link.replaySequence, clientPath.link.receiveNext
		clientPath.link.mu.Unlock()
		serverPath.link.mu.Lock()
		serverReplay, serverReplayBytes := len(serverPath.link.replayPackets), serverPath.link.replayBytes
		serverSend, serverReceive := serverPath.link.replaySequence, serverPath.link.receiveNext
		serverPath.link.mu.Unlock()
		t.Fatalf("bidirectional transfer did not finish after packet-link rebind: progress=%d/%d,%d/%d replay=%d/%d,%d/%d outer-seq=%d/%d,%d/%d err=%v",
			clientProgress.Load(), frames, serverProgress.Load(), frames,
			clientReplay, clientReplayBytes, serverReplay, serverReplayBytes,
			clientSend, clientReceive, serverSend, serverReceive, transferErr)
	}
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}

	if clientPath != clientObject || serverPath != serverObject || clientPath.link.id != clientLinkID ||
		serverPath.link.id != serverLinkID {
		t.Fatal("packet-link rebind replaced the app-facing path or logical LinkID")
	}
	if client.LocalAddr() != clientVirtualLocal || client.RemoteAddr() != clientVirtualRemote ||
		server.LocalAddr() != serverVirtualLocal || server.RemoteAddr() != serverVirtualRemote {
		t.Fatalf("virtual TCP tuple changed client=%s->%s server=%s->%s",
			client.LocalAddr(), client.RemoteAddr(), server.LocalAddr(), server.RemoteAddr())
	}
	if after := clientPath.link.active.conn.LocalAddr().String(); after == clientOuterBefore {
		t.Fatalf("client outer tuple did not change: %s", after)
	}
	if after := serverPath.link.active.conn.LocalAddr().String(); after == serverOuterBefore {
		t.Fatalf("server outer tuple did not change: %s", after)
	}
	if got := clientPath.link.LeafMobilityIncarnation(); got != clientIncarnation+1 {
		t.Fatalf("client incarnation=%d want=%d", got, clientIncarnation+1)
	}
	if got := serverPath.link.LeafMobilityIncarnation(); got != serverIncarnation+1 {
		t.Fatalf("server incarnation=%d want=%d", got, serverIncarnation+1)
	}
	lateClient, lateServer := dialAndAccept(t, listener)
	defer lateClient.Close()
	defer lateServer.Close()
	assertRoundTrip(t, lateClient, lateServer, []byte("shared rendezvous survives accepted endpoint rebind"))
}

func TestGVisorPacketLinkConcurrentDelayedActivationConverges(t *testing.T) {
	listener := mustPacketListener(t)
	client, server := dialAndAccept(t, listener)
	defer client.Close()
	defer server.Close()
	clientPath := client.(*retainedPathConn)
	serverPath := server.(*retainedPathConn)
	clientFixture := newLinkExecutionFixture(t, clientPath, 3)
	serverFixture := newLinkExecutionFixture(t, serverPath, 4)
	fixtures := []linkExecutionFixture{clientFixture, serverFixture}
	refreshEvidence := make(map[*linkOwner]leafmobility.RefreshEvidence, len(fixtures))
	for index, path := range []*retainedPathConn{clientPath, serverPath} {
		trigger := sha256.Sum256([]byte{0xc1, byte(index + 1)})
		source, err := path.link.refreshState.Update(trigger)
		if err != nil {
			t.Fatal(err)
		}
		evidence, err := path.link.refreshEmitter.Observe(leafmobility.RefreshReasonRouteSourceChanged, source)
		if err != nil {
			t.Fatal(err)
		}
		refreshEvidence[path.link] = evidence
	}
	for _, fixture := range fixtures {
		if err := fixture.execution.Prepare(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := fixture.execution.Stage(context.Background()); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.execution.PublicationDigest(); err != nil {
			t.Fatal(err)
		}
		if err := fixture.transaction.MarkCommitPublished(); err != nil {
			t.Fatal(err)
		}
		disposition, err := fixture.execution.ResolveFinalAcceptance(true)
		if err != nil || disposition != leafmobility.FinalAcceptancePublishAllowed {
			t.Fatalf("ResolveFinalAcceptance disposition=%d err=%v", disposition, err)
		}
		if err := fixture.execution.Publish(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	clientPath.link.mu.Lock()
	clientCandidate := clientPath.link.active
	clientCandidateLocal := cloneAddr(clientPath.link.pendingRefresh.route.local)
	clientPath.link.mu.Unlock()
	serverPath.link.mu.Lock()
	serverCandidate := serverPath.link.active
	serverCandidateLocal := cloneAddr(serverPath.link.pendingRefresh.route.local)
	serverPath.link.mu.Unlock()
	clientLinkSecret := clientPath.link.secret
	serverLinkSecret := serverPath.link.secret
	barrier := newOuterCommitBarrier()
	trace := newFinalQualificationTrace(clientCandidateLocal, serverCandidateLocal)
	if err := clientCandidate.replaceWriter(&commitBarrierPacketWriter{
		packetWriter: clientCandidate.conn, source: clientCandidateLocal, secret: clientLinkSecret,
		sender:  clientPath.link.role,
		barrier: barrier, trace: trace,
	}); err != nil {
		t.Fatal(err)
	}
	if err := serverCandidate.replaceWriter(&commitBarrierPacketWriter{
		packetWriter: serverCandidate.conn, source: serverCandidateLocal, secret: serverLinkSecret,
		sender:  serverPath.link.role,
		barrier: barrier, trace: trace,
	}); err != nil {
		t.Fatal(err)
	}

	time.Sleep(2 * outerPredecessorDrain)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	activationErrors := make(chan error, len(fixtures))
	for _, fixture := range fixtures {
		fixture := fixture
		go func() { activationErrors <- fixture.execution.Activate(ctx) }()
	}
	barrier.releaseBoth(t)
	for range fixtures {
		if err := <-activationErrors; err != nil {
			t.Fatalf("concurrent delayed Activate: %v", err)
		}
	}
	for _, fixture := range fixtures {
		if err := fixture.execution.FinalizePublished(); err != nil {
			t.Fatal(err)
		}
		finishLinkResolution(t, fixture.transaction, leafmobility.ResolutionComplete)
	}
	assertRoundTrip(t, client, server, []byte("concurrent delayed rebind converged"))
	assertRoundTrip(t, server, client, []byte("concurrent delayed rebind reverse direction"))
	trace.requireCompleteFinalProof(t)
	for name, path := range map[string]*retainedPathConn{
		"client": client.(*retainedPathConn),
		"server": server.(*retainedPathConn),
	} {
		path.link.mu.Lock()
		active := path.link.active
		remote := cloneAddr(path.link.peerRemote)
		baseline := path.link.routeBaseline
		var pendingDigest [sha256.Size]byte
		pendingPresent := path.link.pendingRefresh != nil
		if pendingPresent {
			pendingDigest = path.link.pendingRefresh.route.digest
		}
		path.link.mu.Unlock()
		observation, err := path.link.observeOuterRoute(context.Background(), active, remote)
		if err != nil {
			t.Fatalf("%s final route observation: %v", name, err)
		}
		if baseline != ([sha256.Size]byte{}) && baseline != observation.digest {
			t.Fatalf("%s committed crossed route proof baseline=%x final=%x tuple=%s->%s mtu=%d",
				name, baseline, observation.digest, observation.local, observation.remote, observation.pathMTU)
		}
		if !pendingPresent || pendingDigest != observation.digest {
			t.Fatalf("%s pending successor route=%x want final=%x", name, pendingDigest, observation.digest)
		}
		if err := path.link.commitRefresh(refreshEvidence[path.link]); err != nil {
			t.Fatalf("%s commit final refresh baseline: %v", name, err)
		}
		path.link.mu.Lock()
		committedBaseline := path.link.routeBaseline
		pendingAfterCommit := path.link.pendingRefresh
		path.link.mu.Unlock()
		if committedBaseline != observation.digest || pendingAfterCommit != nil {
			t.Fatalf("%s committed refresh baseline=%x pending=%+v want=%x/nil",
				name, committedBaseline, pendingAfterCommit, observation.digest)
		}
		if !path.link.observeRefresh(context.Background()) {
			t.Fatalf("%s final successor immediately retriggered route refresh", name)
		}
	}
}

func TestGVisorPacketLinkAttemptRejectsPeerGenerationAdvanceBeforePublication(t *testing.T) {
	for _, test := range []struct {
		name  string
		phase string
	}{
		{name: "before-stage", phase: "before-stage"},
		{name: "during-stage", phase: "during-stage"},
		{name: "before-publish", phase: "before-publish"},
	} {
		t.Run(test.name, func(t *testing.T) {
			listener := mustPacketListener(t)
			client, server := dialAndAccept(t, listener)
			defer client.Close()
			defer server.Close()
			clientPath := client.(*retainedPathConn)
			serverPath := server.(*retainedPathConn)
			owner := clientPath.link
			fixture := newLinkExecutionFixture(t, clientPath, byte(0x90+len(test.name)))

			owner.mu.Lock()
			activeBefore := owner.active
			wireCountBefore := len(owner.wires)
			originalOpen := owner.openCandidate
			owner.mu.Unlock()
			var openCalls atomic.Uint64
			var opened *packetWire
			openedReady := make(chan struct{})
			releaseOpen := make(chan struct{})
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(releaseOpen) }) }
			t.Cleanup(release)
			owner.openCandidate = func(ctx context.Context, remote net.Addr) (*packetWire, routeObservation, error) {
				openCalls.Add(1)
				candidate, observation, err := originalOpen(ctx, remote)
				if err == nil && test.phase == "during-stage" {
					opened = candidate
					close(openedReady)
					select {
					case <-releaseOpen:
					case <-ctx.Done():
					}
				}
				return candidate, observation, err
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := fixture.execution.Prepare(ctx); err != nil {
				t.Fatal(err)
			}

			var stageErr error
			switch test.phase {
			case "before-stage":
				advanceTestPeerGeneration(owner, serverPath.link)
				stageErr = fixture.execution.Stage(ctx)
			case "during-stage":
				staged := make(chan error, 1)
				go func() { staged <- fixture.execution.Stage(ctx) }()
				select {
				case <-openedReady:
				case <-time.After(2 * time.Second):
					t.Fatal("candidate open did not reach the injected generation race")
				}
				advanceTestPeerGeneration(owner, serverPath.link)
				select {
				case stageErr = <-staged:
				case <-time.After(time.Second):
					t.Fatal("peer generation advance did not cancel blocked Stage")
				}
			case "before-publish":
				if err := fixture.execution.Stage(ctx); err != nil {
					t.Fatal(err)
				}
				if _, err := fixture.execution.PublicationDigest(); err != nil {
					t.Fatal(err)
				}
				if err := fixture.transaction.MarkCommitPublished(); err != nil {
					t.Fatal(err)
				}
				disposition, err := fixture.execution.ResolveFinalAcceptance(true)
				if err != nil || disposition != leafmobility.FinalAcceptancePublishAllowed {
					t.Fatalf("ResolveFinalAcceptance disposition=%d err=%v", disposition, err)
				}
				advanceTestPeerGeneration(owner, serverPath.link)
				stageErr = fixture.execution.Publish(ctx)
			}
			if stageErr == nil || !strings.Contains(stageErr.Error(), "packet-link source") {
				t.Fatalf("%s error=%v, want stale packet-link source", test.phase, stageErr)
			}
			if test.phase == "before-stage" && openCalls.Load() != 0 {
				t.Fatalf("stale source opened %d candidates before Stage", openCalls.Load())
			}
			if test.phase != "before-stage" && openCalls.Load() != 1 {
				t.Fatalf("%s candidate opens=%d want=1", test.phase, openCalls.Load())
			}
			if err := fixture.execution.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			if err := fixture.execution.FinalizeRolledBack(); err != nil {
				t.Fatal(err)
			}
			finishLinkResolution(t, fixture.transaction, leafmobility.ResolutionRolledBack)

			owner.mu.Lock()
			activeAfter := owner.active
			wireCountAfter := len(owner.wires)
			maintenance := owner.maintenance
			_, candidateRetained := owner.wires[opened]
			owner.mu.Unlock()
			if activeAfter != activeBefore || wireCountAfter != wireCountBefore || maintenance || candidateRetained {
				t.Fatalf("%s cleanup active_same=%t wires=%d/%d maintenance=%t candidate_retained=%t",
					test.phase, activeAfter == activeBefore, wireCountBefore, wireCountAfter, maintenance, candidateRetained)
			}
			assertRoundTrip(t, client, server, []byte("peer generation advance rollback preserves payload"))
			assertRoundTrip(t, server, client, []byte("peer generation advance rollback preserves reverse payload"))
		})
	}
}

func advanceTestPeerGeneration(local, peer *linkOwner) {
	local.mu.Lock()
	local.peerGeneration++
	local.signalChangedLocked()
	local.mu.Unlock()
	peer.mu.Lock()
	peer.localGeneration++
	peer.signalChangedLocked()
	peer.mu.Unlock()
}

func TestGVisorPacketLinkSourceChangeAfterQualificationAbortsPeerImmediately(t *testing.T) {
	listener := mustPacketListener(t)
	client, server := dialAndAccept(t, listener)
	defer client.Close()
	defer server.Close()
	clientPath := client.(*retainedPathConn)
	serverPath := server.(*retainedPathConn)
	owner, peer := clientPath.link, serverPath.link

	owner.mu.Lock()
	activeBefore := owner.active
	wireCountBefore := len(owner.wires)
	originalOpen := owner.openCandidate
	owner.mu.Unlock()
	arrived := make(chan struct{})
	releaseDone := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseDone) }) }
	t.Cleanup(release)
	var candidate *packetWire
	owner.openCandidate = func(ctx context.Context, remote net.Addr) (*packetWire, routeObservation, error) {
		wire, observation, err := originalOpen(ctx, remote)
		if err != nil {
			return nil, routeObservation{}, err
		}
		wire.conn = &gateQualificationDonePacketConn{
			PacketConn: wire.conn, secret: owner.secret, sender: peerOuterRole(owner.role),
			arrived: arrived, release: releaseDone,
		}
		candidate = wire
		return wire, observation, nil
	}

	fixture := newLinkExecutionFixture(t, clientPath, 0xa4)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := fixture.execution.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	stageResult := make(chan error, 1)
	go func() { stageResult <- fixture.execution.Stage(ctx) }()
	select {
	case <-arrived:
	case <-time.After(2 * time.Second):
		t.Fatal("candidate did not receive the peer's final qualification proof")
	}
	deadline := time.Now().Add(time.Second)
	for {
		peer.mu.Lock()
		pending := peer.pendingPeer
		qualified := pending != nil && pending.qualified
		peer.mu.Unlock()
		if qualified {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("peer did not retain the accepted candidate before source change")
		}
		time.Sleep(time.Millisecond)
	}
	peer.mu.Lock()
	replayBefore := len(peer.peerReplay)
	peer.mu.Unlock()

	advanceTestPeerGeneration(owner, peer)
	release()
	select {
	case err := <-stageResult:
		if err == nil || !errors.Is(err, errLinkAttemptSourceChanged) {
			t.Fatalf("Stage error=%v, want source-generation change", err)
		}
	case <-time.After(time.Second):
		t.Fatal("source-generation change did not terminate Stage")
	}
	owner.openCandidate = originalOpen
	if candidate == nil {
		t.Fatal("qualified candidate was not retained as rollback evidence")
	}
	if err := fixture.execution.Rollback(ctx); err != nil {
		t.Fatalf("authenticated rollback after source change: %v", err)
	}
	if err := fixture.execution.FinalizeRolledBack(); err != nil {
		t.Fatal(err)
	}
	finishLinkResolution(t, fixture.transaction, leafmobility.ResolutionRolledBack)

	peer.mu.Lock()
	pendingAfter := peer.pendingPeer
	replayAfter := len(peer.peerReplay)
	peer.mu.Unlock()
	owner.mu.Lock()
	activeAfter := owner.active
	wireCountAfter := len(owner.wires)
	maintenance := owner.maintenance
	_, candidateRetained := owner.wires[candidate]
	snapshot := snapshotLinkAttemptOwnerLocked(owner)
	receiveNext := owner.receiveNext
	owner.mu.Unlock()
	if pendingAfter != nil || replayAfter != replayBefore+1 {
		t.Fatalf("peer cleanup pending=%+v replay=%d/%d", pendingAfter, replayBefore, replayAfter)
	}
	if activeAfter != activeBefore || wireCountAfter != wireCountBefore || maintenance || candidateRetained {
		t.Fatalf("local cleanup active_same=%t wires=%d/%d maintenance=%t candidate_retained=%t",
			activeAfter == activeBefore, wireCountBefore, wireCountAfter, maintenance, candidateRetained)
	}

	maintenanceLease, err := owner.beginMaintenance(ctx, snapshot.incarnation)
	if err != nil {
		t.Fatalf("immediate retry maintenance: %v", err)
	}
	retryControl := outerControl{
		Transaction: linkTransaction{0xa5}, Agreement: linkAgreement{0xa5}, Nonce: linkNonce{0xa5},
		ReceiveNext: receiveNext,
	}
	retryCandidate, retryGeneration, _, err := owner.stageCandidate(
		ctx, maintenanceLease, retryControl, snapshot,
	)
	if err != nil {
		maintenanceLease.release()
		t.Fatalf("immediate retry was blocked by stale peer state: %v", err)
	}
	if err := owner.rollbackCandidate(
		ctx, maintenanceLease, retryCandidate, retryGeneration, retryControl, snapshot.remote,
	); err != nil {
		t.Fatalf("immediate retry cleanup: %v", err)
	}
	assertRoundTrip(t, client, server, []byte("post-qualification source change retained predecessor"))
	assertRoundTrip(t, server, client, []byte("post-qualification source change retained reverse payload"))
}

type outerCommitBarrier struct {
	arrived chan struct{}
	release chan struct{}
}

func newOuterCommitBarrier() *outerCommitBarrier {
	return &outerCommitBarrier{arrived: make(chan struct{}, 2), release: make(chan struct{})}
}

func (barrier *outerCommitBarrier) wait() {
	barrier.arrived <- struct{}{}
	<-barrier.release
}

func (barrier *outerCommitBarrier) releaseBoth(t testing.TB) {
	t.Helper()
	for range 2 {
		select {
		case <-barrier.arrived:
		case <-time.After(2 * time.Second):
			close(barrier.release)
			t.Fatal("concurrent activations did not both reach predecessor PATH_COMMIT")
		}
	}
	close(barrier.release)
}

type finalQualificationTrace struct {
	mu          sync.Mutex
	left, right net.Addr
	requests    map[finalQualificationBase]int
	proofs      map[finalQualificationProof]map[outerType]int
}

type finalQualificationBase struct {
	link           linkID
	generation     uint64
	purpose        outerQualificationPurpose
	round          uint32
	initiatorNonce linkNonce
	context        [outerQualificationContextSize]byte
	binding        linkAgreement
}

type finalQualificationProof struct {
	base           finalQualificationBase
	responderNonce linkNonce
}

func newFinalQualificationTrace(left, right net.Addr) *finalQualificationTrace {
	return &finalQualificationTrace{
		left: cloneAddr(left), right: cloneAddr(right),
		requests: make(map[finalQualificationBase]int),
		proofs:   make(map[finalQualificationProof]map[outerType]int),
	}
}

func (trace *finalQualificationTrace) record(
	source, remote net.Addr,
	datagram []byte,
	secret linkSecret,
	sender leafmobility.Role,
) {
	if trace == nil || len(datagram) != outerMaxDatagramSize {
		return
	}
	frame, err := decodeOuter(datagram, secret, sender)
	if err != nil || frame.Type < outerTypeQualificationRequest || frame.Type > outerTypeQualificationDone {
		return
	}
	finalTuple := addrEqual(source, trace.left) && addrEqual(remote, trace.right) ||
		addrEqual(source, trace.right) && addrEqual(remote, trace.left)
	if !finalTuple {
		return
	}
	qualification, err := parseOuterQualification(frame.Type, frame.Payload)
	if err != nil {
		return
	}
	base := finalQualificationBase{
		link: frame.LinkID, generation: frame.Generation, purpose: qualification.Purpose,
		round: qualification.Round, initiatorNonce: qualification.InitiatorNonce,
		context: qualification.Context, binding: qualification.Binding,
	}
	trace.mu.Lock()
	defer trace.mu.Unlock()
	if frame.Type == outerTypeQualificationRequest {
		trace.requests[base]++
		return
	}
	proof := finalQualificationProof{base: base, responderNonce: qualification.ResponderNonce}
	legs := trace.proofs[proof]
	if legs == nil {
		legs = make(map[outerType]int)
		trace.proofs[proof] = legs
	}
	legs[frame.Type]++
}

func (trace *finalQualificationTrace) requireCompleteFinalProof(t testing.TB) {
	t.Helper()
	trace.mu.Lock()
	defer trace.mu.Unlock()
	for proof, legs := range trace.proofs {
		if trace.requests[proof.base] == 0 {
			continue
		}
		complete := true
		for _, typ := range []outerType{
			outerTypeQualificationResponse, outerTypeQualificationConfirm, outerTypeQualificationDone,
		} {
			if legs[typ] == 0 {
				complete = false
				break
			}
		}
		if complete {
			return
		}
	}
	t.Fatalf("final active tuple lacks one complete authenticated 1232-byte qualification proof requests=%v proofs=%v",
		trace.requests, trace.proofs)
}

type commitBarrierPacketWriter struct {
	packetWriter
	source  net.Addr
	secret  linkSecret
	sender  leafmobility.Role
	barrier *outerCommitBarrier
	trace   *finalQualificationTrace
	once    sync.Once
}

func (writer *commitBarrierPacketWriter) WriteTo(datagram []byte, remote net.Addr) (int, error) {
	writer.trace.record(writer.source, remote, datagram, writer.secret, writer.sender)
	frame, err := decodeOuter(datagram, writer.secret, writer.sender)
	if err == nil && frame.Type == outerTypePathCommit {
		writer.once.Do(writer.barrier.wait)
	}
	return writer.packetWriter.WriteTo(datagram, remote)
}

func TestGVisorCommittedCandidateBecomesRefreshBaselineWithoutTickerDelay(t *testing.T) {
	owner, _, candidate, _, remote, control := newPublishQualificationPair(t)
	claim, err := newPacketLinkClaim(owner, leafmobility.RoleDialer)
	if err != nil {
		t.Fatal(err)
	}
	binding := leafmobility.Binding{
		FlowID: [16]byte{83, 1}, LocalTargetID: [16]byte{83, 2}, PeerTargetID: [16]byte{83, 3},
		PathID: 84, Owner: 183,
	}
	issuer := leafmobility.NewAuthorityIssuer()
	if err := issuer.BindClaim(claim, binding); err != nil {
		t.Fatal(err)
	}
	defer claim.Retire(binding)
	owner.observeRoute = func(_ context.Context, wire *packetWire, remote net.Addr) (routeObservation, error) {
		return newRouteObservation(
			outerUDPIPv4, wire.conn.LocalAddr().(*net.UDPAddr), remote.(*net.UDPAddr),
			outerRoutePlatformEvidence{outputInterface: 1, pathMTU: 1260, pathMTUKnown: true},
		)
	}

	refreshes := make(chan leafmobility.RefreshEvidence, 2)
	cancel, err := owner.subscribeRefresh(context.Background(), func(evidence leafmobility.RefreshEvidence) {
		refreshes <- evidence
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	trigger := sha256.Sum256([]byte("pre-migration route evidence"))
	source, err := owner.refreshState.Update(trigger)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := owner.refreshEmitter.Observe(leafmobility.RefreshReasonRouteSourceChanged, source)
	if err != nil {
		t.Fatal(err)
	}

	owner.mu.Lock()
	ownerSource := snapshotLinkAttemptOwnerLocked(owner)
	owner.maintenance = true
	owner.wires[candidate] = struct{}{}
	maintenance := &linkMaintenance{owner: owner, incarnation: owner.incarnation}
	candidateRoute, err := owner.observeOuterRoute(context.Background(), candidate, remote)
	owner.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	if err := owner.publishCandidate(ctx, maintenance, candidate, 2, control, candidateRoute, ownerSource); err != nil {
		t.Fatal(err)
	}
	if err := owner.activateCandidate(ctx, maintenance, candidate, 2, control); err != nil {
		t.Fatal(err)
	}
	if err := owner.commitRefresh(evidence); err != nil {
		t.Fatal(err)
	}
	owner.mu.Lock()
	active := owner.active
	currentRemote := cloneAddr(owner.peerRemote)
	baseline := owner.routeBaseline
	owner.mu.Unlock()
	observation, err := owner.observeOuterRoute(context.Background(), active, currentRemote)
	if err != nil {
		t.Fatal(err)
	}
	if baseline != observation.digest {
		t.Fatalf("commit baseline=%x want staged successor=%x", baseline, observation.digest)
	}
	if !owner.observeRefresh(context.Background()) {
		t.Fatal("immediate post-commit refresh observation failed")
	}
	select {
	case repeated := <-refreshes:
		t.Fatalf("committed successor immediately repeated route refresh: %+v", repeated)
	default:
	}
}

func TestGVisorPeerCommitLinearizesAgainstStaleRefreshObservation(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	wire := newPacketWire(conn, false)
	initialPeer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 43381}
	owner, err := newLinkOwner(
		linkID{84}, linkSecret{85}, leafmobility.RoleAcceptor,
		[4]byte{10, 64, 0, 84}, wire, initialPeer, nil, func([]byte) {},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.close()
	claim, err := newPacketLinkClaim(owner, leafmobility.RoleAcceptor)
	if err != nil {
		t.Fatal(err)
	}
	binding := leafmobility.Binding{
		FlowID: [16]byte{84, 1}, LocalTargetID: [16]byte{84, 2}, PeerTargetID: [16]byte{84, 3},
		PathID: 85, Owner: 184,
	}
	issuer := leafmobility.NewAuthorityIssuer()
	if err := issuer.BindClaim(claim, binding); err != nil {
		t.Fatal(err)
	}
	defer claim.Retire(binding)
	local := conn.LocalAddr().(*net.UDPAddr)
	initialRoute := mustOuterRouteObservation(t, outerUDPIPv4, local, initialPeer, 1, 1260)
	owner.observeRoute = func(context.Context, *packetWire, net.Addr) (routeObservation, error) {
		return initialRoute, nil
	}
	cancel, err := owner.subscribeRefresh(context.Background(), func(leafmobility.RefreshEvidence) {})
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	preCommitEvidence, err := owner.refreshEmitter.Observe(leafmobility.RefreshReasonLinkUnresponsive)
	if err != nil {
		t.Fatal(err)
	}

	stalePeer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 43382}
	// A relay can keep the server-visible tuple unchanged while authenticating
	// a new peer generation. The generation advance must still revoke evidence
	// minted for the predecessor.
	committedPeer := cloneAddr(initialPeer).(*net.UDPAddr)
	staleRoute := mustOuterRouteObservation(t, outerUDPIPv4, local, stalePeer, 1, 1260)
	committedRoute := initialRoute
	observationStarted := make(chan struct{})
	releaseObservation := make(chan struct{})
	var blockOnce atomic.Bool
	blockOnce.Store(true)
	owner.observeRoute = func(context.Context, *packetWire, net.Addr) (routeObservation, error) {
		if blockOnce.CompareAndSwap(true, false) {
			close(observationStarted)
			<-releaseObservation
			return staleRoute, nil
		}
		return committedRoute, nil
	}
	observed := make(chan struct{})
	go func() {
		owner.observeRefresh(context.Background())
		close(observed)
	}()
	select {
	case <-observationStarted:
	case <-time.After(time.Second):
		t.Fatal("stale refresh observation did not start")
	}
	control := outerControl{
		Transaction: linkTransaction{86}, Agreement: linkAgreement{87}, Nonce: linkNonce{88}, ReceiveNext: 1,
	}
	owner.mu.Lock()
	owner.pendingPeer = &peerCandidate{
		generation: 2, control: control, wire: wire, remote: cloneAddr(committedPeer), route: committedRoute,
		qualified: true, expires: time.Now().Add(time.Second),
	}
	owner.mu.Unlock()
	owner.handleDatagram(wire, committedPeer, mustOuterControl(t, owner, outerTypePathCommit, 2, control))
	if _, err := preCommitEvidence.ValidateFor(claim, 0); !errors.Is(err, leafmobility.ErrRefreshEvidenceStale) {
		t.Fatalf("pre-commit refresh evidence error=%v, want stale", err)
	}
	evidence, err := owner.refreshEmitter.Observe(leafmobility.RefreshReasonRouteSourceChanged)
	if err != nil {
		t.Fatal(err)
	}
	close(releaseObservation)
	select {
	case <-observed:
	case <-time.After(time.Second):
		t.Fatal("stale refresh observation did not finish")
	}
	if _, err := evidence.ValidateFor(claim, 0); err != nil {
		t.Fatalf("interleaved peer commit evidence became stale: %v", err)
	}
}

func TestGVisorPacketLinkPrePublishRollbackKeepsPredecessor(t *testing.T) {
	listener := mustPacketListener(t)
	defer listener.Close()
	client, server := dialAndAccept(t, listener)
	defer client.Close()
	defer server.Close()
	path := client.(*retainedPathConn)
	outerBefore := path.link.active.conn.LocalAddr().String()
	incarnationBefore := path.link.LeafMobilityIncarnation()

	fixture := newLinkExecutionFixture(t, path, 11)
	if err := fixture.execution.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := fixture.execution.Stage(context.Background()); err != nil {
		t.Fatal(err)
	}
	path.link.mu.Lock()
	activeBeforeRollback := path.link.active
	path.link.mu.Unlock()
	if err := fixture.execution.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := fixture.execution.FinalizeRolledBack(); err != nil {
		t.Fatal(err)
	}
	finishLinkResolution(t, fixture.transaction, leafmobility.ResolutionRolledBack)
	path.link.mu.Lock()
	activeAfterRollback := path.link.active
	path.link.mu.Unlock()
	if activeAfterRollback != activeBeforeRollback || activeAfterRollback.conn.LocalAddr().String() != outerBefore {
		t.Fatalf("rollback changed active predecessor from %s to %s", outerBefore, activeAfterRollback.conn.LocalAddr())
	}
	if got := path.link.LeafMobilityIncarnation(); got != incarnationBefore {
		t.Fatalf("rollback incarnation=%d want=%d", got, incarnationBefore)
	}
	peer := server.(*retainedPathConn).link
	peer.mu.Lock()
	pendingAfterRollback := peer.pendingPeer
	replaysAfterRollback := len(peer.peerReplay)
	peer.mu.Unlock()
	if pendingAfterRollback != nil || replaysAfterRollback != 1 {
		t.Fatalf("peer rollback state pending=%+v replay entries=%d", pendingAfterRollback, replaysAfterRollback)
	}
	path.link.mu.Lock()
	remote := cloneAddr(path.link.peerRemote)
	nextGeneration := path.link.localGeneration + 1
	path.link.mu.Unlock()
	candidate, _, err := path.link.openUDPCandidate(context.Background(), remote)
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.close()
	nextControl := outerControl{
		Transaction: linkTransaction{99}, Agreement: linkAgreement{99}, Nonce: linkNonce{99}, ReceiveNext: 1,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := path.link.challengeCandidate(ctx, candidate, remote, nextGeneration, nextControl); err != nil {
		t.Fatalf("fresh transaction was blocked by rolled-back peer candidate: %v", err)
	}
	assertRoundTrip(t, client, server, []byte("predecessor remains usable after rollback"))
}

func TestGVisorPacketLinkStageFailureRollsBackWithoutSharedDamage(t *testing.T) {
	listener := mustPacketListener(t)
	defer listener.Close()
	client1, server1 := dialAndAccept(t, listener)
	defer client1.Close()
	defer server1.Close()
	client2, server2 := dialAndAccept(t, listener)
	defer client2.Close()
	defer server2.Close()
	path := client1.(*retainedPathConn)
	outerBefore := path.link.active.conn.LocalAddr().String()
	originalFactory := path.link.openCandidate
	path.link.openCandidate = func(ctx context.Context, remote net.Addr) (*packetWire, routeObservation, error) {
		wire, observation, err := originalFactory(ctx, remote)
		if err != nil {
			return nil, routeObservation{}, err
		}
		if err := wire.replaceWriter(writeFailPacketWriter{}); err != nil {
			wire.close()
			return nil, routeObservation{}, err
		}
		return wire, observation, nil
	}

	fixture := newLinkExecutionFixture(t, path, 21)
	if err := fixture.execution.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := fixture.execution.Stage(context.Background()); err == nil {
		t.Fatal("Stage succeeded despite an injected zero-byte challenge failure")
	}
	if err := fixture.execution.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := fixture.execution.FinalizeRolledBack(); err != nil {
		t.Fatal(err)
	}
	finishLinkResolution(t, fixture.transaction, leafmobility.ResolutionRolledBack)
	if got := path.link.active.conn.LocalAddr().String(); got != outerBefore {
		t.Fatalf("failed Stage changed active outer tuple from %s to %s", outerBefore, got)
	}
	server1.(*retainedPathConn).link.mu.Lock()
	pending := server1.(*retainedPathConn).link.pendingPeer
	server1.(*retainedPathConn).link.mu.Unlock()
	if pending != nil {
		t.Fatalf("zero-byte challenge failure created peer pending state: %+v", pending)
	}
	assertRoundTrip(t, client1, server1, []byte("failed candidate left predecessor usable"))
	assertRoundTrip(t, client2, server2, []byte("failed candidate did not damage sibling session"))
}

func TestGVisorPacketLinkStageWriteHonorsContextCancellation(t *testing.T) {
	listener := mustPacketListener(t)
	client, server := dialAndAccept(t, listener)
	defer client.Close()
	defer server.Close()
	path := client.(*retainedPathConn)
	originalFactory := path.link.openCandidate
	created := make(chan *blockingPacketWriter, 1)
	path.link.openCandidate = func(ctx context.Context, remote net.Addr) (*packetWire, routeObservation, error) {
		wire, observation, err := originalFactory(ctx, remote)
		if err != nil {
			return nil, routeObservation{}, err
		}
		blocked := newBlockingPacketWriter(nil)
		if err := wire.replaceWriter(blocked); err != nil {
			wire.close()
			return nil, routeObservation{}, err
		}
		created <- blocked
		return wire, observation, nil
	}
	fixture := newLinkExecutionFixture(t, path, 23)
	if err := fixture.execution.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	stageResult := make(chan error, 1)
	go func() { stageResult <- fixture.execution.Stage(ctx) }()
	blocked := <-created
	select {
	case <-blocked.started:
	case <-time.After(time.Second):
		t.Fatal("Stage write did not block")
	}
	cancel()
	select {
	case err := <-stageResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Stage error=%v want context cancellation", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("Stage ignored context cancellation")
	}
	if err := fixture.execution.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := fixture.execution.FinalizeRolledBack(); err != nil {
		t.Fatal(err)
	}
	finishLinkResolution(t, fixture.transaction, leafmobility.ResolutionRolledBack)
}

func TestGVisorPacketLinkActivateWriteHonorsContextCancellation(t *testing.T) {
	listener := mustPacketListener(t)
	client, server := dialAndAccept(t, listener)
	defer client.Close()
	defer server.Close()
	path := client.(*retainedPathConn)
	fixture := newLinkExecutionFixture(t, path, 24)
	prepareAndPublishLinkFixture(t, fixture)
	path.link.mu.Lock()
	active := path.link.active
	path.link.mu.Unlock()
	blocked := newBlockingPacketWriter(nil)
	if err := active.replaceWriter(blocked); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	activateResult := make(chan error, 1)
	go func() { activateResult <- fixture.execution.Activate(ctx) }()
	select {
	case <-blocked.started:
	case <-time.After(time.Second):
		t.Fatal("Activate write did not block")
	}
	cancel()
	select {
	case err := <-activateResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Activate error=%v want context cancellation", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("Activate ignored context cancellation")
	}
	started := time.Now()
	if err := fixture.execution.FailClosed(context.Background()); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("FailClosed waited %v for failed Activate writer", elapsed)
	}
}

func TestGVisorPacketLinkRollbackWriteHonorsDeadline(t *testing.T) {
	listener := mustPacketListener(t)
	client, server := dialAndAccept(t, listener)
	defer client.Close()
	defer server.Close()
	path := client.(*retainedPathConn)
	fixture := newLinkExecutionFixture(t, path, 25)
	if err := fixture.execution.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := fixture.execution.Stage(context.Background()); err != nil {
		t.Fatal(err)
	}
	path.link.mu.Lock()
	var candidate *packetWire
	for wire := range path.link.wires {
		if wire != path.link.active && wire != path.link.predecessor && !wire.shared {
			candidate = wire
			break
		}
	}
	path.link.mu.Unlock()
	if candidate == nil {
		t.Fatal("staged candidate not found")
	}
	candidate.writeMu.RLock()
	original := candidate.writer
	candidate.writeMu.RUnlock()
	blocked := newBlockingPacketWriter(nil)
	if err := candidate.replaceWriter(blocked); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := fixture.execution.Rollback(context.Background()); err == nil {
		t.Fatal("Rollback succeeded despite a blocked ABORT writer")
	}
	if elapsed := time.Since(started); elapsed > outerWriteBound+500*time.Millisecond {
		t.Fatalf("Rollback exceeded bounded write deadline: %v", elapsed)
	}
	if err := candidate.replaceWriter(original); err != nil {
		t.Fatal(err)
	}
	if err := fixture.execution.Rollback(context.Background()); err != nil {
		t.Fatalf("Rollback retry after writer recovery: %v", err)
	}
	if err := fixture.execution.FinalizeRolledBack(); err != nil {
		t.Fatal(err)
	}
	finishLinkResolution(t, fixture.transaction, leafmobility.ResolutionRolledBack)
}

func TestGVisorPacketLinkPostSendStageFailureAbortsPeerCandidate(t *testing.T) {
	listener := mustPacketListener(t)
	client, server := dialAndAccept(t, listener)
	defer client.Close()
	defer server.Close()
	path := client.(*retainedPathConn)
	peer := server.(*retainedPathConn).link
	outerBefore := path.link.active.conn.LocalAddr().String()
	originalFactory := path.link.openCandidate
	var injected *failFirstReadPacketConn
	path.link.openCandidate = func(ctx context.Context, remote net.Addr) (*packetWire, routeObservation, error) {
		wire, observation, err := originalFactory(ctx, remote)
		if err != nil {
			return nil, routeObservation{}, err
		}
		injected = &failFirstReadPacketConn{PacketConn: wire.conn}
		wire.conn = injected
		return wire, observation, nil
	}

	fixture := newLinkExecutionFixture(t, path, 22)
	if err := fixture.execution.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := fixture.execution.Stage(context.Background()); err == nil {
		t.Fatalf("Stage succeeded despite an injected post-qualification read failure: read=%t conn=%T",
			injected != nil && injected.failed.Load(), injected)
	}
	if err := fixture.execution.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := fixture.execution.FinalizeRolledBack(); err != nil {
		t.Fatal(err)
	}
	finishLinkResolution(t, fixture.transaction, leafmobility.ResolutionRolledBack)
	if got := path.link.active.conn.LocalAddr().String(); got != outerBefore {
		t.Fatalf("failed Stage changed active outer tuple from %s to %s", outerBefore, got)
	}

	peer.mu.Lock()
	pending := peer.pendingPeer
	replays := len(peer.peerReplay)
	peer.mu.Unlock()
	if pending != nil || replays != 1 {
		t.Fatalf("post-send rollback state pending=%+v replay entries=%d", pending, replays)
	}

	path.link.mu.Lock()
	remote := cloneAddr(path.link.peerRemote)
	nextGeneration := path.link.localGeneration + 1
	path.link.mu.Unlock()
	candidate, _, err := path.link.openUDPCandidate(context.Background(), remote)
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.close()
	nextControl := outerControl{
		Transaction: linkTransaction{100}, Agreement: linkAgreement{100}, Nonce: linkNonce{100}, ReceiveNext: 1,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := path.link.challengeCandidate(ctx, candidate, remote, nextGeneration, nextControl); err != nil {
		t.Fatalf("fresh transaction was blocked after post-send rollback: %v", err)
	}
	assertRoundTrip(t, client, server, []byte("post-send rollback retained predecessor"))
}

func TestGVisorRefreshCallbackCannotBlockCarrierAndCancelDisablesSpecializedRetry(t *testing.T) {
	listener := mustPacketListener(t)
	client, server := dialAndAccept(t, listener)
	defer client.Close()
	defer server.Close()
	path := client.(*retainedPathConn)
	claim := path.LeafMobilityClaim()
	binding := leafmobility.Binding{
		FlowID: [16]byte{31, 1}, LocalTargetID: [16]byte{31, 2}, PeerTargetID: [16]byte{31, 3},
		PathID: 31, Owner: 131,
	}
	issuer := leafmobility.NewAuthorityIssuer()
	if err := issuer.BindClaim(claim, binding); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = claim.Retire(binding) })
	callbackBudget := newRefreshCallbackBudget(1)
	path.link.refreshCallbacks = callbackBudget
	callbackStarted := make(chan struct{})
	releaseCallback := make(chan struct{})
	cancel, err := path.SubscribeLeafMobilityRefresh(context.Background(), func(leafmobility.RefreshEvidence) {
		close(callbackStarted)
		<-releaseCallback
	})
	if err != nil {
		t.Fatal(err)
	}
	source, err := path.link.refreshState.Update([32]byte{9})
	if err != nil {
		t.Fatal(err)
	}
	emitted := make(chan struct{})
	go func() {
		path.link.emitRefresh(leafmobility.RefreshReasonRouteSourceChanged, source)
		close(emitted)
	}()
	select {
	case <-emitted:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("refresh callback blocked the carrier-facing publisher")
	}
	select {
	case <-callbackStarted:
	case <-time.After(time.Second):
		t.Fatal("refresh callback was not dispatched")
	}
	cancel()
	if path.link.publishWireFailure(leafmobility.RefreshReasonLocalWriteFailure) {
		t.Fatal("canceled refresh subscription still claimed specialized retry ownership")
	}
	if replacementCancel, subscribeErr := path.SubscribeLeafMobilityRefresh(
		context.Background(), func(leafmobility.RefreshEvidence) {},
	); subscribeErr == nil {
		replacementCancel()
		t.Fatal("blocked callback allowed the same owner to accumulate another detached callback")
	}
	path.link.refreshMu.Lock()
	dispatchDone := path.link.refreshDispatchDone
	path.link.refreshMu.Unlock()
	select {
	case <-dispatchDone:
	case <-time.After(time.Second):
		t.Fatal("explicit cancellation retained the refresh dispatch goroutine")
	}
	if snapshot := callbackBudget.snapshot(); snapshot.Active != 1 || snapshot.Rejected != 0 {
		t.Fatalf("blocked detached callback accounting=%+v", snapshot)
	}
	closeStarted := time.Now()
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(closeStarted); elapsed > 100*time.Millisecond {
		t.Fatalf("Close waited %v for canceled but blocked refresh callback", elapsed)
	}
	close(releaseCallback)
	deadline := time.Now().Add(time.Second)
	for callbackBudget.snapshot().Active != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if snapshot := callbackBudget.snapshot(); snapshot.Active != 0 {
		t.Fatalf("released detached callback retained accounting=%+v", snapshot)
	}
}

func TestGVisorPermanentlyBlockingRefreshCallbacksAreCircuitBrokenAndResourceBounded(t *testing.T) {
	listener := mustPacketListener(t)
	firstClient, firstServer := dialAndAccept(t, listener)
	secondClient, secondServer := dialAndAccept(t, listener)
	defer firstClient.Close()
	defer firstServer.Close()
	defer secondClient.Close()
	defer secondServer.Close()
	first := firstClient.(*retainedPathConn)
	second := secondClient.(*retainedPathConn)
	issuer := leafmobility.NewAuthorityIssuer()
	for index, path := range []*retainedPathConn{first, second} {
		binding := leafmobility.Binding{
			FlowID: [16]byte{byte(61 + index), 1}, LocalTargetID: [16]byte{byte(61 + index), 2},
			PeerTargetID: [16]byte{byte(61 + index), 3}, PathID: uint32(61 + index), Owner: uint64(161 + index),
		}
		if err := issuer.BindClaim(path.LeafMobilityClaim(), binding); err != nil {
			t.Fatal(err)
		}
		claim := path.LeafMobilityClaim()
		t.Cleanup(func() { _ = claim.Retire(binding) })
	}
	callbackBudget := newRefreshCallbackBudget(1)
	first.link.refreshCallbacks = callbackBudget
	second.link.refreshCallbacks = callbackBudget
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseFirst) }) }
	t.Cleanup(release)
	firstCancel, err := first.SubscribeLeafMobilityRefresh(context.Background(), func(leafmobility.RefreshEvidence) {
		close(firstStarted)
		<-releaseFirst
	})
	if err != nil {
		t.Fatal(err)
	}
	defer firstCancel()
	firstSource, err := first.link.refreshState.Update([32]byte{61})
	if err != nil {
		t.Fatal(err)
	}
	first.link.emitRefresh(leafmobility.RefreshReasonRouteSourceChanged, firstSource)
	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("permanently blocking refresh callback did not start")
	}

	var secondCalls atomic.Uint64
	secondCancel, err := second.SubscribeLeafMobilityRefresh(context.Background(), func(leafmobility.RefreshEvidence) {
		secondCalls.Add(1)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer secondCancel()
	secondSource, err := second.link.refreshState.Update([32]byte{62})
	if err != nil {
		t.Fatal(err)
	}
	second.link.emitRefresh(leafmobility.RefreshReasonRouteSourceChanged, secondSource)
	select {
	case <-second.link.done:
	case <-time.After(time.Second):
		t.Fatal("callback permit exhaustion did not circuit-break the second packet link")
	}
	if calls := secondCalls.Load(); calls != 0 {
		t.Fatalf("callback permit exhaustion invoked untrusted callback %d times", calls)
	}
	select {
	case <-first.link.done:
	case <-time.After(outerRefreshCallbackMax + time.Second):
		t.Fatal("permanently blocking callback did not trip its timeout circuit")
	}
	for name, path := range map[string]*retainedPathConn{"first": first, "second": second} {
		path.link.refreshMu.Lock()
		circuit, trips := path.link.refreshCircuit, path.link.refreshTrips
		dispatchDone := path.link.refreshDispatchDone
		path.link.refreshMu.Unlock()
		if !circuit || trips != 1 {
			t.Fatalf("%s refresh circuit/trips=%t/%d", name, circuit, trips)
		}
		select {
		case <-dispatchDone:
		case <-time.After(time.Second):
			t.Fatalf("%s retained an engine-owned refresh dispatcher", name)
		}
		started := time.Now()
		_ = path.Close()
		if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
			t.Fatalf("%s Close waited %v for untrusted callback", name, elapsed)
		}
	}
	if snapshot := callbackBudget.snapshot(); snapshot.Active != 1 || snapshot.Rejected != 1 {
		t.Fatalf("circuit-broken callback accounting=%+v", snapshot)
	}
	release()
	deadline := time.Now().Add(time.Second)
	for callbackBudget.snapshot().Active != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if snapshot := callbackBudget.snapshot(); snapshot.Active != 0 || snapshot.Rejected != 1 {
		t.Fatalf("released callback accounting=%+v", snapshot)
	}
}

func TestGVisorPeerRebindDoesNotEmitLocalRouteRefresh(t *testing.T) {
	listener := mustPacketListener(t)
	client, server := dialAndAccept(t, listener)
	defer client.Close()
	defer server.Close()
	clientPath := client.(*retainedPathConn)
	claim := clientPath.LeafMobilityClaim()
	binding := leafmobility.Binding{
		FlowID: [16]byte{32, 1}, LocalTargetID: [16]byte{32, 2}, PeerTargetID: [16]byte{32, 3},
		PathID: 32, Owner: 132,
	}
	issuer := leafmobility.NewAuthorityIssuer()
	if err := issuer.BindClaim(claim, binding); err != nil {
		t.Fatal(err)
	}
	defer claim.Retire(binding)
	events := make(chan leafmobility.RefreshEvidence, 1)
	cancel, err := clientPath.SubscribeLeafMobilityRefresh(context.Background(), func(evidence leafmobility.RefreshEvidence) {
		select {
		case events <- evidence:
		default:
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	clientPath.link.mu.Lock()
	remoteBefore := cloneAddr(clientPath.link.peerRemote)
	clientPath.link.mu.Unlock()

	executePacketLinkRebind(t, server.(*retainedPathConn), 33)
	clientPath.link.mu.Lock()
	remoteAfter := cloneAddr(clientPath.link.peerRemote)
	clientPath.link.mu.Unlock()
	if addrEqual(remoteBefore, remoteAfter) {
		t.Fatalf("peer rebind did not change authenticated remote tuple: %v", remoteAfter)
	}
	observeCtx, observeCancel := context.WithTimeout(context.Background(), time.Second)
	clientPath.link.observeRefresh(observeCtx)
	observeCancel()
	select {
	case <-events:
		t.Fatal("peer tuple rebind was misclassified as a local route/source change")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestGVisorPeerCommitClearsResponderWireFaultAndRestoresLiveness(t *testing.T) {
	listener := mustPacketListener(t)
	client, server := dialAndAccept(t, listener)
	defer client.Close()
	defer server.Close()
	clientPath := client.(*retainedPathConn)
	serverPath := server.(*retainedPathConn)

	serverPath.link.mu.Lock()
	serverPath.link.wireFault = true
	serverPath.link.livenessLastAck = time.Time{}
	serverPath.link.mu.Unlock()

	executePacketLinkRebind(t, clientPath, 34)

	serverPath.link.mu.Lock()
	fault := serverPath.link.wireFault
	lastAck := serverPath.link.livenessLastAck
	serverPath.link.mu.Unlock()
	if fault || lastAck.IsZero() || time.Since(lastAck) > time.Second {
		t.Fatalf("peer commit left responder fault/liveness=%t/%v", fault, lastAck)
	}
	assertRoundTrip(t, client, server, []byte("peer commit restored responder link"))
	assertRoundTrip(t, server, client, []byte("peer commit restored reverse link"))
}

func TestGVisorRefreshSubscribeLinearizesWithEndpointClose(t *testing.T) {
	requireOuterPacketSupport(t)
	for iteration := 0; iteration < 10; iteration++ {
		t.Run(fmt.Sprintf("iteration-%d", iteration), func(t *testing.T) {
			listener, err := ListenPacket("127.0.0.1:0", WithTrustedCarrier())
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			client, server := dialAndAccept(t, listener)
			defer client.Close()
			defer server.Close()
			path := client.(*retainedPathConn)
			claim := path.LeafMobilityClaim()
			binding := leafmobility.Binding{
				FlowID: [16]byte{byte(iteration + 1), 41}, LocalTargetID: [16]byte{41, 2},
				PeerTargetID: [16]byte{41, 3}, PathID: uint32(iteration + 1), Owner: 141,
			}
			issuer := leafmobility.NewAuthorityIssuer()
			if err := issuer.BindClaim(claim, binding); err != nil {
				t.Fatal(err)
			}

			type subscribeResult struct {
				cancel func()
				err    error
			}
			start := make(chan struct{})
			subscribed := make(chan subscribeResult, 1)
			closed := make(chan error, 1)
			go func() {
				<-start
				cancel, subscribeErr := path.SubscribeLeafMobilityRefresh(
					context.Background(), func(leafmobility.RefreshEvidence) {},
				)
				subscribed <- subscribeResult{cancel: cancel, err: subscribeErr}
			}()
			go func() {
				<-start
				closed <- client.Close()
			}()
			close(start)
			result := <-subscribed
			if err := <-closed; err != nil {
				t.Fatal(err)
			}
			if result.err != nil && result.cancel != nil {
				t.Fatalf("subscription returned cancel and error: %v", result.err)
			}
			if result.cancel != nil {
				defer result.cancel()
			}
			_ = claim.Retire(binding)

			path.link.refreshMu.Lock()
			done := path.link.refreshDone
			callback := path.link.refreshFn
			path.link.refreshMu.Unlock()
			if callback != nil {
				t.Fatal("closed endpoint retained refresh callback")
			}
			if done != nil {
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("closed endpoint retained refresh monitor")
				}
			}
		})
	}
}

type linkExecutionFixture struct {
	execution   *leafmobility.Execution
	transaction *leafmobility.ResourceTransaction
}

type failFirstReadPacketConn struct {
	net.PacketConn
	failed atomic.Bool
}

func (conn *failFirstReadPacketConn) ReadFrom(packet []byte) (int, net.Addr, error) {
	if !conn.failed.Load() {
		n, remote, err := conn.PacketConn.ReadFrom(packet)
		if err != nil {
			return n, remote, err
		}
		if conn.failed.CompareAndSwap(false, true) {
			return 0, nil, fmt.Errorf("injected packet-link response read failure")
		}
		return n, remote, nil
	}
	return conn.PacketConn.ReadFrom(packet)
}

type gateQualificationDonePacketConn struct {
	net.PacketConn
	secret  linkSecret
	sender  leafmobility.Role
	arrived chan struct{}
	release chan struct{}
	once    sync.Once
}

func (conn *gateQualificationDonePacketConn) ReadFrom(packet []byte) (int, net.Addr, error) {
	n, remote, err := conn.PacketConn.ReadFrom(packet)
	if err != nil {
		return n, remote, err
	}
	frame, decodeErr := decodeOuter(packet[:n], conn.secret, conn.sender)
	if decodeErr == nil && frame.Type == outerTypeQualificationDone {
		conn.once.Do(func() { close(conn.arrived) })
		<-conn.release
	}
	return n, remote, nil
}

// newLinkExecutionFixture exercises the leaf driver boundary after peer
// agreement verification. It deliberately constructs that boundary value;
// bilateral protocol coverage belongs to the engine-backed blackhole tests.
func newLinkExecutionFixture(t testing.TB, path *retainedPathConn, discriminator byte) linkExecutionFixture {
	t.Helper()
	claim := path.LeafMobilityClaim()
	binding := leafmobility.Binding{
		FlowID: [16]byte{discriminator, 1}, LocalTargetID: [16]byte{discriminator, 2},
		PeerTargetID: [16]byte{discriminator, 3}, PathID: uint32(discriminator) + 1,
		Owner: uint64(discriminator) + 100,
	}
	issuer := leafmobility.NewAuthorityIssuer()
	if err := issuer.BindClaim(claim, binding); err != nil {
		t.Fatal(err)
	}
	direction := proto.SenderDirectionClientToServer
	actor := proto.LeafMobilityActorClient
	if path.link.role == leafmobility.RoleAcceptor {
		direction = proto.SenderDirectionServerToClient
		actor = proto.LeafMobilityActorServer
	}
	plan, err := leafmobility.PlanCandidate(context.Background(), claim, leafmobility.PlanRequest{
		TransactionID: leafmobility.TransactionID{discriminator, 9}, Binding: binding,
		Direction: direction, Session: leafmobility.SessionStream, Deadline: time.Now().Add(10 * time.Second),
		LocalSupport: leafmobility.OperationGVisorLinkRebind,
		PeerSupport:  leafmobility.OperationGVisorLinkRebind,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Operation != leafmobility.OperationGVisorLinkRebind || plan.Scope != leafmobility.ScopeEndpoint {
		t.Fatalf("packet-link plan=%+v", plan)
	}
	transaction, err := claim.ReserveResourceTransaction(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := transaction.MarkPrepared(plan.BaseGeneration+1, plan.Deadline); err != nil {
		t.Fatal(err)
	}
	agreement := linkPeerAgreement(t, plan, actor)
	execution, err := issuer.ConsumeExecution(claim, transaction, plan, agreement)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = execution.FailClosed(context.Background())
		_ = claim.Retire(binding)
	})
	return linkExecutionFixture{execution: execution, transaction: transaction}
}

func executePacketLinkRebind(t testing.TB, path *retainedPathConn, discriminator byte) {
	t.Helper()
	fixture := newLinkExecutionFixture(t, path, discriminator)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := fixture.execution.Prepare(ctx); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := fixture.execution.Stage(ctx); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	publication, err := fixture.execution.PublicationDigest()
	if err != nil || publication == (proto.LeafMobilityPublicationDigest{}) {
		t.Fatalf("PublicationDigest=%x err=%v", publication, err)
	}
	if err := fixture.transaction.MarkCommitPublished(); err != nil {
		t.Fatal(err)
	}
	disposition, err := fixture.execution.ResolveFinalAcceptance(true)
	if err != nil || disposition != leafmobility.FinalAcceptancePublishAllowed {
		t.Fatalf("ResolveFinalAcceptance disposition=%d err=%v", disposition, err)
	}
	if err := fixture.execution.Publish(ctx); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if err := fixture.execution.Activate(ctx); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if err := fixture.execution.FinalizePublished(); err != nil {
		t.Fatal(err)
	}
	finishLinkResolution(t, fixture.transaction, leafmobility.ResolutionComplete)
}

func prepareAndPublishLinkFixture(t testing.TB, fixture linkExecutionFixture) {
	t.Helper()
	if err := fixture.execution.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := fixture.execution.Stage(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.execution.PublicationDigest(); err != nil {
		t.Fatal(err)
	}
	if err := fixture.transaction.MarkCommitPublished(); err != nil {
		t.Fatal(err)
	}
	disposition, err := fixture.execution.ResolveFinalAcceptance(true)
	if err != nil || disposition != leafmobility.FinalAcceptancePublishAllowed {
		t.Fatalf("ResolveFinalAcceptance disposition=%d err=%v", disposition, err)
	}
	if err := fixture.execution.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func finishLinkResolution(t testing.TB, transaction *leafmobility.ResourceTransaction, resolution leafmobility.Resolution) {
	t.Helper()
	if err := transaction.BeginResolution(resolution); err != nil {
		t.Fatal(err)
	}
	if err := transaction.FinishResolution(resolution); err != nil {
		t.Fatal(err)
	}
}

func linkPeerAgreement(
	t testing.TB,
	plan leafmobility.Plan,
	actor proto.LeafMobilityActorSide,
) leafmobility.PeerAgreement {
	t.Helper()
	clientTarget := proto.TargetID(plan.Binding.LocalTargetID)
	serverTarget := proto.TargetID(plan.Binding.PeerTargetID)
	if actor == proto.LeafMobilityActorServer {
		clientTarget, serverTarget = serverTarget, clientTarget
	}
	binding := proto.LeafMobilityPeerPlanBinding{
		CoordinatorSide:        proto.LeafMobilityActorClient,
		ActorSide:              actor,
		Direction:              plan.Direction,
		SessionKind:            proto.LeafMobilitySessionStream,
		Operation:              proto.LeafMobilityOperationGVisorLinkRebind,
		Fallback:               proto.LeafMobilityFallbackRedialAttach,
		LeaseMillis:            5_000,
		SessionEpoch:           proto.SessionEpoch(plan.Binding.FlowID),
		TransactionID:          [16]byte(plan.TransactionID),
		ClientGraph:            proto.GraphBinding{Revision: 1, Digest: proto.GraphDigest{1}},
		ServerGraph:            proto.GraphBinding{Revision: 1, Digest: proto.GraphDigest{2}},
		SubjectClientTargetID:  clientTarget,
		SubjectServerTargetID:  serverTarget,
		BaseGeneration:         plan.BaseGeneration,
		ResourceScope:          proto.LeafMobilityResourceEndpoint,
		ResourceID:             proto.LeafMobilityResourceID(plan.ResourceID),
		SubjectRouteGeneration: 1,
	}
	actorPlan := proto.LeafMobilityPlanDigest(plan.LocalDigest)
	prepare := proto.LeafMobilityPeerPlanPrepare{
		LeafMobilityPeerPlanBinding: binding,
		ActorEndpointGeneration:     plan.EndpointGeneration,
		ActorPlanDigest:             actorPlan,
	}
	proposal, err := prepare.ProposalDigest()
	if err != nil {
		t.Fatal(err)
	}
	peerDigest := proto.LeafMobilityPeerDigest{1}
	reservation := proto.LeafMobilityReservationID{2}
	peerGeneration := plan.EndpointGeneration + 1
	digest, err := proto.ComputeLeafMobilityAgreementDigest(
		binding, plan.BaseGeneration+1, plan.EndpointGeneration, peerGeneration,
		proposal, peerDigest, reservation,
	)
	if err != nil {
		t.Fatal(err)
	}
	return leafmobility.PeerAgreement{
		Binding: binding, Generation: plan.BaseGeneration + 1,
		ActorEndpointGeneration: plan.EndpointGeneration, PeerEndpointGeneration: peerGeneration,
		ActorPlanDigest: actorPlan, ProposalDigest: proposal, PeerPlanDigest: peerDigest,
		AgreementDigest: digest, ReservationID: reservation,
	}
}

func mustPacketListener(t testing.TB) *Listener {
	t.Helper()
	requireOuterPacketSupport(t)
	listener, err := ListenPacket("127.0.0.1:0", WithTrustedCarrier())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func writeFrames(
	path transport.PathConn,
	marker byte,
	frames int,
	payloadSize int,
	progress *atomic.Uint64,
	wait *sync.WaitGroup,
	errorsCh chan<- error,
) {
	defer wait.Done()
	for sequence := 0; sequence < frames; sequence++ {
		payload := mobilityPayload(marker, sequence, payloadSize)
		if _, err := path.Write(payload); err != nil {
			errorsCh <- fmt.Errorf("write marker=%x sequence=%d: %w", marker, sequence, err)
			return
		}
		progress.Store(uint64(sequence + 1))
	}
}

func readFrames(
	path transport.PathConn,
	marker byte,
	frames int,
	payloadSize int,
	wait *sync.WaitGroup,
	errorsCh chan<- error,
) {
	defer wait.Done()
	buffer := make([]byte, basetcp.MaxFrameSize)
	for sequence := 0; sequence < frames; sequence++ {
		n, err := path.Read(buffer)
		if err != nil {
			errorsCh <- fmt.Errorf("read marker=%x sequence=%d: %w", marker, sequence, err)
			return
		}
		want := mobilityPayload(marker, sequence, payloadSize)
		if !bytes.Equal(buffer[:n], want) {
			errorsCh <- fmt.Errorf("payload mismatch marker=%x sequence=%d got-sha=%x want-sha=%x",
				marker, sequence, sha256.Sum256(buffer[:n]), sha256.Sum256(want))
			return
		}
	}
}

func mobilityPayload(marker byte, sequence, size int) []byte {
	payload := make([]byte, size)
	payload[0] = marker
	binary.BigEndian.PutUint64(payload[1:9], uint64(sequence))
	for index := 9; index < len(payload); index++ {
		payload[index] = marker ^ byte(sequence) ^ byte(index)
	}
	return payload
}

func waitForProgress(t testing.TB, first, second *atomic.Uint64, minimum uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if first.Load() >= minimum && second.Load() >= minimum {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("transfer did not become active: first=%d second=%d", first.Load(), second.Load())
}
