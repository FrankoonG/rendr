//go:build linux && amd64 && rendr_experimental_gvisor

package gvisor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
	basetcp "github.com/FrankoonG/rendr/transport/tcp"
)

func TestGVisorIdleHealthyLinkDoesNotTriggerLivenessMigration(t *testing.T) {
	listener := mustPacketListener(t)
	client, server := dialAndAccept(t, listener)
	defer client.Close()
	defer server.Close()
	path := client.(*retainedPathConn)
	claim := path.LeafMobilityClaim()
	binding := leafmobility.Binding{
		FlowID: [16]byte{71, 1}, LocalTargetID: [16]byte{71, 2}, PeerTargetID: [16]byte{71, 3},
		PathID: 71, Owner: 171,
	}
	issuer := leafmobility.NewAuthorityIssuer()
	if err := issuer.BindClaim(claim, binding); err != nil {
		t.Fatal(err)
	}
	defer claim.Retire(binding)
	events := make(chan leafmobility.RefreshEvidence, 1)
	cancel, err := path.SubscribeLeafMobilityRefresh(context.Background(), func(evidence leafmobility.RefreshEvidence) {
		select {
		case events <- evidence:
		default:
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	path.link.mu.Lock()
	baselineAck := path.link.livenessLastAck
	path.link.mu.Unlock()
	select {
	case evidence := <-events:
		snapshot, validationErr := evidence.ValidateFor(claim, 0)
		path.link.mu.Lock()
		wireErr := path.link.active.error()
		fault := path.link.wireFault
		path.link.mu.Unlock()
		t.Fatalf("idle healthy packet link emitted mobility evidence snapshot=%+v validation=%v wire=%v fault=%t",
			snapshot, validationErr, wireErr, fault)
	case <-time.After(outerLivenessFailure + 2*outerLivenessTick):
	}
	path.link.mu.Lock()
	lastAck := path.link.livenessLastAck
	fault := path.link.wireFault
	path.link.mu.Unlock()
	if !lastAck.After(baselineAck) || fault {
		t.Fatalf("idle liveness baseline=%v last=%v fault=%t", baselineAck, lastAck, fault)
	}
}

func TestGVisorSlowIdleHealthyLinkDoesNotTriggerLivenessMigration(t *testing.T) {
	listener := mustPacketListener(t)
	relay := newPacketBlackholeRelay(t, listener.Addr())
	defer relay.Close()
	client, server := dialAndAcceptThroughRelay(t, listener, relay)
	defer client.Close()
	defer server.Close()
	relay.SetLivenessDelay(150 * time.Millisecond)
	path := client.(*retainedPathConn)
	claim := path.LeafMobilityClaim()
	binding := leafmobility.Binding{
		FlowID: [16]byte{72, 1}, LocalTargetID: [16]byte{72, 2}, PeerTargetID: [16]byte{72, 3},
		PathID: 72, Owner: 172,
	}
	issuer := leafmobility.NewAuthorityIssuer()
	if err := issuer.BindClaim(claim, binding); err != nil {
		t.Fatal(err)
	}
	defer claim.Retire(binding)
	events := make(chan leafmobility.RefreshEvidence, 1)
	cancel, err := path.SubscribeLeafMobilityRefresh(context.Background(), func(evidence leafmobility.RefreshEvidence) {
		select {
		case events <- evidence:
		default:
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	path.link.mu.Lock()
	baselineAck := path.link.livenessLastAck
	path.link.mu.Unlock()
	select {
	case evidence := <-events:
		t.Fatalf("slow idle packet link emitted mobility evidence: %+v", evidence)
	case <-time.After(outerLivenessFailure + 2*outerLivenessTick):
	}
	path.link.mu.Lock()
	lastAck, fault := path.link.livenessLastAck, path.link.wireFault
	path.link.mu.Unlock()
	if !lastAck.After(baselineAck) || fault {
		t.Fatalf("slow idle liveness baseline=%v last=%v fault=%t", baselineAck, lastAck, fault)
	}
}

func TestGVisorSilentBlackholeAutomaticallyRebindsActive128MiBTransfer(t *testing.T) {
	runGVisorOwnedEndpointBlackholeRebind(t, 4096, 16*1024)
}

func TestGVisorKernel5OwnedEndpointSilentBlackholeRebind(t *testing.T) {
	evidence := runGVisorOwnedEndpointBlackholeRebind(t, 2048, 16*1024)
	writeKernel5GVisorEvidence(t, evidence)
}

func runGVisorOwnedEndpointBlackholeRebind(
	t *testing.T,
	frames int,
	payloadSize int,
) kernel5GVisorEvidence {
	t.Helper()
	listener := mustPacketListener(t)
	relay := newPacketBlackholeRelay(t, listener.Addr())
	defer relay.Close()
	clientRaw, serverRaw := dialAndAcceptThroughRelay(t, listener, relay)
	clientPath := clientRaw.(*retainedPathConn)
	serverPath := serverRaw.(*retainedPathConn)
	var clientInjected atomic.Uint64
	var serverInjected atomic.Uint64
	clientInject := clientPath.link.inject
	serverInject := serverPath.link.inject
	clientPath.link.inject = func(packet []byte) {
		clientInjected.Add(1)
		clientInject(packet)
	}
	serverPath.link.inject = func(packet []byte) {
		serverInjected.Add(1)
		serverInject(packet)
	}
	serverRefreshCancel, err := serverPath.SubscribeLeafMobilityRefresh(
		context.Background(), func(leafmobility.RefreshEvidence) {},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer serverRefreshCancel()
	flowID := [16]byte{0x81, 0x82, 0x83, 0x84}
	limits := engine.DefaultLimits()
	limits.MigrationBudget = 15 * time.Second
	limits.ProbeInterval = 30 * time.Second
	clientEngine := engine.New(engine.SideClient, flowID, limits)
	serverEngine := engine.New(engine.SideServer, flowID, limits)
	defer func() { _ = clientEngine.Close() }()
	defer func() { _ = serverEngine.Close() }()
	dataTargetID, controlTargetID := configureGVisorEnginePair(t, clientEngine, serverEngine, clientPath, serverPath)
	binding := engine.PathBinding{LocalTXTargetID: dataTargetID, PeerTXTargetID: dataTargetID}
	spec := transport.PathSpec{Transport: "gvisor", Opts: map[string]string{"name": "gvisor-blackhole"}}
	clientPathID, err := clientEngine.AttachPathBound(clientPath, spec, binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := serverEngine.AttachPathBound(serverPath, spec, binding); err != nil {
		t.Fatal(err)
	}
	clientControlConn, serverControlConn := net.Pipe()
	clientControl := basetcp.Wrap(clientControlConn)
	serverControl := basetcp.Wrap(serverControlConn)
	controlBinding := engine.PathBinding{LocalTXTargetID: controlTargetID, PeerTXTargetID: controlTargetID}
	if _, err := clientEngine.AttachPathBound(
		clientControl, transport.PathSpec{Transport: "memory"}, controlBinding,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := serverEngine.AttachPathBound(
		serverControl, transport.PathSpec{Transport: "memory"}, controlBinding,
	); err != nil {
		t.Fatal(err)
	}
	clientRef, ok := clientEngine.PathRef(clientPathID)
	if !ok {
		t.Fatal("gVisor data path has no exact PathRef")
	}
	if status, exists := clientEngine.LeafMobilityInitiatorStatus(clientRef); !exists ||
		status.Phase != engine.LeafMobilityInitiatorIdle {
		clientPath.link.refreshMu.Lock()
		subscribed := clientPath.link.refreshFn != nil
		circuit := clientPath.link.refreshCircuit
		clientPath.link.refreshMu.Unlock()
		t.Fatalf("gVisor data path did not install its refresh subscriber: exists=%t status=%+v subscribed=%t circuit=%t",
			exists, status, subscribed, circuit)
	}
	clientObject := clientPath
	clientLinkID := clientPath.link.id
	clientClaim := clientPath.LeafMobilityClaim()
	claimBefore := clientClaim.Snapshot()
	virtualLocal := clientPath.LocalAddr()
	virtualRemote := clientPath.RemoteAddr()
	outerBefore := observedOuterLocalTuple(t, clientPath.link)
	baselineMigration := clientEngine.MigrationCount()

	clientProgress := &atomic.Uint64{}
	serverProgress := &atomic.Uint64{}
	errorsCh := make(chan error, 4)
	hashResults := make(chan streamHashResult, 2)
	cutoverGate := make(chan struct{})
	var releaseCutover sync.Once
	releaseGate := func() { releaseCutover.Do(func() { close(cutoverGate) }) }
	t.Cleanup(releaseGate)
	var transfers sync.WaitGroup
	transfers.Add(4)
	go writeEngineFrames(clientEngine, 0x41, frames, payloadSize, 64, cutoverGate, clientProgress, &transfers, errorsCh)
	go readEngineFrames(serverEngine, 0x41, frames, payloadSize, &transfers, errorsCh, hashResults)
	go writeEngineFrames(serverEngine, 0x82, frames, payloadSize, 64, cutoverGate, serverProgress, &transfers, errorsCh)
	go readEngineFrames(clientEngine, 0x82, frames, payloadSize, &transfers, errorsCh, hashResults)
	transferDone := make(chan struct{})
	go func() {
		transfers.Wait()
		close(transferDone)
	}()
	waitForProgress(t, clientProgress, serverProgress, 64)
	if relay.PreData() == 0 {
		t.Fatal("cutover had no captured pre-blackhole outer DATA")
	}
	clientFramesAtCutover := clientProgress.Load()
	serverFramesAtCutover := serverProgress.Load()
	select {
	case <-transferDone:
		t.Fatal("bidirectional transfer completed before blackhole cutover")
	default:
	}
	if clientProgress.Load() >= uint64(frames) || serverProgress.Load() >= uint64(frames) {
		t.Fatalf("transfer was not active at cutover: client=%d server=%d", clientProgress.Load(), serverProgress.Load())
	}

	droppedTuple := relay.DropEstablishedClient(t)
	cutoverStarted := time.Now()
	releaseGate()
	deadline := cutoverStarted.Add(6 * time.Second)
	var committedStatus engine.LeafMobilityInitiatorSnapshot
	for {
		status, exists := clientEngine.LeafMobilityInitiatorStatus(clientRef)
		if exists && status.Phase == engine.LeafMobilityInitiatorCommitted {
			if status.EvidenceGeneration == 0 || status.SourceEndpointGeneration == 0 ||
				status.ResultEndpointGeneration <= status.SourceEndpointGeneration ||
				status.EvidenceReason != leafmobility.RefreshReasonLinkUnresponsive ||
				status.Operation != leafmobility.OperationGVisorLinkRebind || status.Error != "" {
				t.Fatalf("automatic gVisor initiator status=%+v", status)
			}
			committedStatus = status
			break
		}
		if exists && terminalGVisorInitiatorFailure(status.Phase) {
			t.Fatalf("automatic gVisor initiator failed: %+v", status)
		}
		if time.Now().After(deadline) {
			clientPath.link.mu.Lock()
			closed, closing, fault := clientPath.link.closed, clientPath.link.closing, clientPath.link.wireFault
			pendingReplay := len(clientPath.link.replayPackets)
			lastAck := clientPath.link.livenessLastAck
			clientPath.link.mu.Unlock()
			clientPath.link.refreshMu.Lock()
			subscribed, circuit, trips := clientPath.link.refreshFn != nil,
				clientPath.link.refreshCircuit, clientPath.link.refreshTrips
			clientPath.link.refreshMu.Unlock()
			t.Fatalf("silent-blackhole rebind exceeded 5s contract; status=%+v exists=%t owner=%t/%t fault=%t replay=%d ack-age=%v refresh=%t/%t/%d callbacks=%+v",
				status, exists, closed, closing, fault, pendingReplay, time.Since(lastAck), subscribed, circuit, trips,
				clientPath.link.refreshCallbacks.snapshot())
		}
		time.Sleep(time.Millisecond)
	}
	cutoverElapsed := time.Since(cutoverStarted)
	if cutoverElapsed > 5*time.Second {
		t.Fatalf("silent-blackhole rebind took %v", cutoverElapsed)
	}

	select {
	case <-transferDone:
	case <-time.After(30 * time.Second):
		status, _ := clientEngine.LeafMobilityInitiatorStatus(clientRef)
		clientPath.link.mu.Lock()
		clientState := fmt.Sprintf(
			"local-gen=%d peer-gen=%d pending=%t fault=%t active=%v remote=%v replay=%d/%d seq=%d recv=%d ahead=%d activation=%d tx=%d/%d inject=%d",
			clientPath.link.localGeneration, clientPath.link.peerGeneration,
			clientPath.link.activationPending, clientPath.link.wireFault,
			clientPath.link.active.conn.LocalAddr(), clientPath.link.peerRemote,
			len(clientPath.link.replayPackets), clientPath.link.replayBytes, clientPath.link.replaySequence,
			clientPath.link.receiveNext, len(clientPath.link.receiveAhead),
			clientPath.link.replayActivations, clientPath.link.replayTransmitted, clientPath.link.replayTXBytes,
			clientInjected.Load(),
		)
		clientPath.link.mu.Unlock()
		serverPath.link.mu.Lock()
		serverState := fmt.Sprintf(
			"local-gen=%d peer-gen=%d pending=%t fault=%t active=%v remote=%v replay=%d/%d seq=%d recv=%d ahead=%d activation=%d tx=%d/%d inject=%d",
			serverPath.link.localGeneration, serverPath.link.peerGeneration,
			serverPath.link.activationPending, serverPath.link.wireFault,
			serverPath.link.active.conn.LocalAddr(), serverPath.link.peerRemote,
			len(serverPath.link.replayPackets), serverPath.link.replayBytes, serverPath.link.replaySequence,
			serverPath.link.receiveNext, len(serverPath.link.receiveAhead),
			serverPath.link.replayActivations, serverPath.link.replayTransmitted, serverPath.link.replayTXBytes,
			serverInjected.Load(),
		)
		serverPath.link.mu.Unlock()
		clientTCP, serverTCP := relay.TCPSummaries()
		stackTCP := listener.server.Stats().TCP
		t.Fatalf("bidirectional transfer stalled client-progress=%d server-progress=%d client-pre/post=%d/%d server-pre/post=%d/%d client-tcp=%+v server-tcp=%+v server-stack-valid/invalid/checksum/reset=%d/%d/%d/%d status=%+v client={%s} server={%s}",
			clientProgress.Load(), serverProgress.Load(), relay.PreData(), relay.PostData(),
			relay.ServerPreData(), relay.ServerPostData(), clientTCP, serverTCP,
			stackTCP.ValidSegmentsReceived.Value(), stackTCP.InvalidSegmentsReceived.Value(),
			stackTCP.ChecksumErrors.Value(), stackTCP.ResetsReceived.Value(), status, clientState, serverState)
	}
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	close(hashResults)
	measuredHashes := make(map[byte]string, 2)
	for result := range hashResults {
		measuredHashes[result.marker] = result.hash
	}
	outerAfter := observedOuterLocalTuple(t, clientPath.link)
	claimAfter := clientClaim.Snapshot()
	if outerAfter == outerBefore || outerAfter == droppedTuple {
		t.Fatalf("outer client tuple did not rebind: before=%s dropped=%s after=%s", outerBefore, droppedTuple, outerAfter)
	}
	if relay.PostData() == 0 || relay.ReplacementTuple() != outerAfter {
		t.Fatalf("relay post-cutover DATA=%d replacement=%s want=%s", relay.PostData(), relay.ReplacementTuple(), outerAfter)
	}
	if clientPath != clientObject || clientPath.link.id != clientLinkID ||
		clientPath.LocalAddr() != virtualLocal || clientPath.RemoteAddr() != virtualRemote {
		t.Fatal("automatic rebind replaced app path, LinkID, or virtual TCP tuple")
	}
	if claimAfter.ResourceID != claimBefore.ResourceID || claimAfter.Generation <= claimBefore.Generation {
		t.Fatalf("claim identity/generation before=%+v after=%+v", claimBefore, claimAfter)
	}
	if got := clientEngine.MigrationCount(); got != baselineMigration+1 {
		t.Fatalf("migration count=%d want=%d", got, baselineMigration+1)
	}
	if clientControl.Reads() == 0 || clientControl.Writes() == 0 ||
		serverControl.Reads() == 0 || serverControl.Writes() == 0 {
		t.Fatal("gVisor rebind did not use the bilateral sibling control route")
	}

	clientHash := measuredHashes[0x41]
	serverHash := measuredHashes[0x82]
	if clientHash != mobilityStreamHash(0x41, frames, payloadSize) ||
		serverHash != mobilityStreamHash(0x82, frames, payloadSize) {
		t.Fatalf("measured stream hashes client=%s server=%s", clientHash, serverHash)
	}
	clientPre, clientPost := relay.PreData(), relay.PostData()
	serverPre, serverPost := relay.ServerPreData(), relay.ServerPostData()
	transactionID := hex.EncodeToString(committedStatus.TransactionID[:])
	resourceID := fmt.Sprintf("%x", claimBefore.ResourceID)
	flow := hex.EncodeToString(flowID[:])
	migrationAfter := clientEngine.MigrationCount()

	type engineCloseResult struct {
		name string
		err  error
	}
	closeResults := make(chan engineCloseResult, 2)
	go func() { closeResults <- engineCloseResult{name: "client", err: clientEngine.Close()} }()
	go func() { closeResults <- engineCloseResult{name: "server", err: serverEngine.Close()} }()
	closeErrors := make(map[string]error, 2)
	for range 2 {
		result := <-closeResults
		closeErrors[result.name] = result.err
	}
	for name, closed := range map[string]<-chan struct{}{
		"client": clientEngine.Closed(), "server": serverEngine.Closed(),
	} {
		select {
		case <-closed:
		case <-time.After(testTimeout):
			t.Fatalf("%s engine did not quiesce after Close returned %v", name, closeErrors[name])
		}
		if err := closeErrors[name]; err != nil && !strings.Contains(err.Error(), "shutdown did not quiesce") {
			t.Fatalf("%s engine Close: %v", name, err)
		}
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("close packet listener: %v", err)
	}
	waitForCleanup(t, listener)
	relay.Close()
	select {
	case <-clientPath.link.done:
	case <-time.After(testTimeout):
		t.Fatal("client packet-link owner survived cleanup")
	}
	select {
	case <-serverPath.link.done:
	case <-time.After(testTimeout):
		t.Fatal("server packet-link owner survived cleanup")
	}

	return kernel5GVisorEvidence{
		Schema: "rendr-gvisor-kernel5-v1", Test: "TestGVisorKernel5OwnedEndpointSilentBlackholeRebind",
		FlowID: flow, LinkID: hex.EncodeToString(clientLinkID[:]), ClaimResourceID: resourceID,
		ClaimGenerationBefore: claimBefore.Generation, ClaimGenerationAfter: claimAfter.Generation,
		PathID: clientRef.ID, PathOwner: clientRef.Owner, LogicalStreamStable: true,
		VirtualLocal: fmt.Sprint(virtualLocal), VirtualRemote: fmt.Sprint(virtualRemote),
		OuterTupleBefore: outerBefore, OuterTupleDropped: droppedTuple, OuterTupleAfter: outerAfter,
		CutoverMilliseconds: cutoverElapsed.Milliseconds(), RebindWithin5Seconds: true,
		PayloadBytesEachDirection: uint64(frames * payloadSize), ClientToServerSHA256: clientHash,
		ServerToClientSHA256: serverHash, HashIdentical: true,
		ClientFramesAtCutover: clientFramesAtCutover, ServerFramesAtCutover: serverFramesAtCutover,
		TransferActiveAtCutover: true,
		ClientOuterDataBefore:   clientPre, ClientOuterDataAfter: clientPost,
		ServerOuterDataBefore: serverPre, ServerOuterDataAfter: serverPost,
		MigrationCountBefore: baselineMigration, MigrationCountAfter: migrationAfter,
		TransactionID: transactionID, BilateralControlObserved: true,
		ClientOwnerCleaned: true, ServerOwnerCleaned: true, ListenerCleaned: true,
	}
}

type kernel5GVisorEvidence struct {
	Schema                    string `json:"schema"`
	Nonce                     string `json:"nonce"`
	Test                      string `json:"test"`
	FlowID                    string `json:"flow_id"`
	LinkID                    string `json:"link_id"`
	ClaimResourceID           string `json:"claim_resource_id"`
	ClaimGenerationBefore     uint64 `json:"claim_generation_before"`
	ClaimGenerationAfter      uint64 `json:"claim_generation_after"`
	PathID                    uint32 `json:"path_id"`
	PathOwner                 uint64 `json:"path_owner"`
	LogicalStreamStable       bool   `json:"logical_stream_stable"`
	VirtualLocal              string `json:"virtual_local"`
	VirtualRemote             string `json:"virtual_remote"`
	OuterTupleBefore          string `json:"outer_tuple_before"`
	OuterTupleDropped         string `json:"outer_tuple_dropped"`
	OuterTupleAfter           string `json:"outer_tuple_after"`
	CutoverMilliseconds       int64  `json:"cutover_milliseconds"`
	RebindWithin5Seconds      bool   `json:"rebind_within_5_seconds"`
	PayloadBytesEachDirection uint64 `json:"payload_bytes_each_direction"`
	ClientToServerSHA256      string `json:"client_to_server_sha256"`
	ServerToClientSHA256      string `json:"server_to_client_sha256"`
	HashIdentical             bool   `json:"hash_identical"`
	ClientFramesAtCutover     uint64 `json:"client_frames_at_cutover"`
	ServerFramesAtCutover     uint64 `json:"server_frames_at_cutover"`
	TransferActiveAtCutover   bool   `json:"transfer_active_at_cutover"`
	ClientOuterDataBefore     uint64 `json:"client_outer_data_before"`
	ClientOuterDataAfter      uint64 `json:"client_outer_data_after"`
	ServerOuterDataBefore     uint64 `json:"server_outer_data_before"`
	ServerOuterDataAfter      uint64 `json:"server_outer_data_after"`
	MigrationCountBefore      uint64 `json:"migration_count_before"`
	MigrationCountAfter       uint64 `json:"migration_count_after"`
	TransactionID             string `json:"transaction_id"`
	BilateralControlObserved  bool   `json:"bilateral_control_observed"`
	ClientOwnerCleaned        bool   `json:"client_owner_cleaned"`
	ServerOwnerCleaned        bool   `json:"server_owner_cleaned"`
	ListenerCleaned           bool   `json:"listener_cleaned"`
}

func mobilityStreamHash(marker byte, frames, payloadSize int) string {
	hash := sha256.New()
	for sequence := 0; sequence < frames; sequence++ {
		_, _ = hash.Write(mobilityPayload(marker, sequence, payloadSize))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func writeKernel5GVisorEvidence(t testing.TB, evidence kernel5GVisorEvidence) {
	t.Helper()
	path := strings.TrimSpace(os.Getenv("RENDR_KERNEL5_GVISOR_EVIDENCE"))
	if path == "" {
		return
	}
	nonce := strings.TrimSpace(os.Getenv("RENDR_KERNEL5_GVISOR_NONCE"))
	if nonce == "" || len(nonce) > 256 || strings.IndexFunc(nonce, func(r rune) bool { return r < 0x20 }) >= 0 {
		t.Fatal("RENDR_KERNEL5_GVISOR_NONCE must be a non-empty printable value of at most 256 bytes")
	}
	evidence.Nonce = nonce
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatalf("open KERNEL-5 gVisor evidence: %v", err)
	}
	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	encodeErr := encoder.Encode(evidence)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(encodeErr, syncErr, closeErr); err != nil {
		t.Fatalf("write KERNEL-5 gVisor evidence: %v", err)
	}
}

func dialAndAcceptThroughRelay(
	t testing.TB,
	listener *Listener,
	relay *packetBlackholeRelay,
) (transport.PathConn, transport.PathConn) {
	t.Helper()
	type acceptResult struct {
		path transport.PathConn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		path, err := listener.Accept(context.Background())
		accepted <- acceptResult{path: path, err: err}
	}()
	client, err := listener.Factory().DialPath(context.Background(), transport.PathSpec{Address: relay.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-accepted:
		if result.err != nil {
			_ = client.Close()
			t.Fatal(result.err)
		}
		return client, result.path
	case <-time.After(testTimeout):
		_ = client.Close()
		t.Fatal("relay packet-link accept timed out")
		return nil, nil
	}
}

func configureGVisorEnginePair(
	t testing.TB,
	client *engine.Engine,
	server *engine.Engine,
	clientPath *retainedPathConn,
	serverPath *retainedPathConn,
) (proto.TargetID, proto.TargetID) {
	t.Helper()
	clientCapability, ok := leafmobility.CapabilityForClaim(clientPath.LeafMobilityClaim())
	if !ok {
		t.Fatal("client gVisor claim has no capability")
	}
	serverCapability, ok := leafmobility.CapabilityForClaim(serverPath.LeafMobilityClaim())
	if !ok {
		t.Fatal("server gVisor claim has no capability")
	}
	if err := client.ConfigureLocalMobilityCapabilities(clientCapability); err != nil {
		t.Fatal(err)
	}
	if err := server.ConfigureLocalMobilityCapabilities(serverCapability); err != nil {
		t.Fatal(err)
	}
	dataTargetID := proto.DeriveTargetID(proto.GraphNodeKindPath, "gvisor-data")
	controlTargetID := proto.DeriveTargetID(proto.GraphNodeKindPath, "gvisor-control")
	rootTargetID := proto.DeriveTargetID(proto.GraphNodeKindSelector, "gvisor-root")
	manifest := proto.GraphManifest{
		RootID: rootTargetID,
		Nodes: []proto.GraphNode{
			{ID: rootTargetID, Kind: proto.GraphNodeKindSelector, Name: "gvisor-root", Children: []proto.TargetID{dataTargetID, controlTargetID}},
			{ID: dataTargetID, Kind: proto.GraphNodeKindPath, Name: "gvisor-data"},
			{ID: controlTargetID, Kind: proto.GraphNodeKindPath, Name: "gvisor-control"},
		},
	}
	if err := client.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := server.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := client.AcceptPeerNegotiation(server.LocalNegotiation(), server.LocalGraphManifest()); err != nil {
		t.Fatal(err)
	}
	if err := server.AcceptPeerNegotiation(client.LocalNegotiation(), client.LocalGraphManifest()); err != nil {
		t.Fatal(err)
	}
	clientID, serverID := engine.NewInstanceID(), engine.NewInstanceID()
	client.SetLocalInstanceID(clientID)
	server.SetLocalInstanceID(serverID)
	if err := client.SetPeerInstanceID(serverID); err != nil {
		t.Fatal(err)
	}
	if err := server.SetPeerInstanceID(clientID); err != nil {
		t.Fatal(err)
	}
	return dataTargetID, controlTargetID
}

func writeEngineFrames(
	engine *engine.Engine,
	marker byte,
	frames int,
	payloadSize int,
	gateAfter int,
	gate <-chan struct{},
	progress *atomic.Uint64,
	wait *sync.WaitGroup,
	errorsCh chan<- error,
) {
	defer wait.Done()
	for sequence := 0; sequence < frames; sequence++ {
		payload := mobilityPayload(marker, sequence, payloadSize)
		n, err := engine.SendData(payload)
		if err == nil && n != len(payload) {
			err = fmt.Errorf("short engine write %d/%d", n, len(payload))
		}
		if err != nil {
			errorsCh <- fmt.Errorf("engine write marker=%x sequence=%d: %w", marker, sequence, err)
			return
		}
		progress.Store(uint64(sequence + 1))
		if sequence+1 == gateAfter && gate != nil {
			<-gate
		}
	}
}

func readEngineFrames(
	engine *engine.Engine,
	marker byte,
	frames int,
	payloadSize int,
	wait *sync.WaitGroup,
	errorsCh chan<- error,
	hashResults chan<- streamHashResult,
) {
	defer wait.Done()
	wantHash := sha256.New()
	for sequence := 0; sequence < frames; sequence++ {
		_, _ = wantHash.Write(mobilityPayload(marker, sequence, payloadSize))
	}
	wantBytes := frames * payloadSize
	gotHash := sha256.New()
	buffer := make([]byte, basetcp.MaxFrameSize)
	for received := 0; received < wantBytes; {
		limit := len(buffer)
		if remaining := wantBytes - received; remaining < limit {
			limit = remaining
		}
		n, err := engine.Recv(buffer[:limit])
		if err != nil {
			errorsCh <- fmt.Errorf("engine read marker=%x received=%d/%d: %w", marker, received, wantBytes, err)
			return
		}
		_, _ = gotHash.Write(buffer[:n])
		received += n
	}
	if !bytes.Equal(gotHash.Sum(nil), wantHash.Sum(nil)) {
		errorsCh <- fmt.Errorf("engine stream mismatch marker=%x got-sha=%x want-sha=%x",
			marker, gotHash.Sum(nil), wantHash.Sum(nil))
		return
	}
	hashResults <- streamHashResult{marker: marker, hash: hex.EncodeToString(gotHash.Sum(nil))}
}

type streamHashResult struct {
	marker byte
	hash   string
}

func terminalGVisorInitiatorFailure(phase engine.LeafMobilityInitiatorPhase) bool {
	switch phase {
	case engine.LeafMobilityInitiatorRolledBack, engine.LeafMobilityInitiatorRejected,
		engine.LeafMobilityInitiatorFailed, engine.LeafMobilityInitiatorExpired,
		engine.LeafMobilityInitiatorSubscriptionUnavailable, engine.LeafMobilityInitiatorFailClosed:
		return true
	default:
		return false
	}
}

type packetBlackholeRelay struct {
	conn      *net.UDPConn
	server    *net.UDPAddr
	done      chan struct{}
	wait      sync.WaitGroup
	closeOnce sync.Once
	closeErr  error

	mu             sync.Mutex
	client         *net.UDPAddr
	dropped        *net.UDPAddr
	replacement    *net.UDPAddr
	drop           bool
	preData        uint64
	postData       uint64
	serverPreData  uint64
	serverPostData uint64
	clientTCP      tcpPacketSummary
	serverTCP      tcpPacketSummary
	livenessDelay  time.Duration
}

func newPacketBlackholeRelay(t testing.TB, server net.Addr) *packetBlackholeRelay {
	t.Helper()
	serverUDP, ok := server.(*net.UDPAddr)
	if !ok {
		t.Fatalf("relay server address=%T", server)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	relay := &packetBlackholeRelay{
		conn: conn, server: cloneUDPAddr(serverUDP), done: make(chan struct{}),
	}
	relay.wait.Add(1)
	go relay.run()
	return relay
}

func (relay *packetBlackholeRelay) Addr() net.Addr { return relay.conn.LocalAddr() }

func (relay *packetBlackholeRelay) Close() error {
	if relay == nil {
		return nil
	}
	relay.closeOnce.Do(func() {
		close(relay.done)
		relay.closeErr = relay.conn.Close()
		relay.wait.Wait()
	})
	return relay.closeErr
}

func (relay *packetBlackholeRelay) run() {
	defer relay.wait.Done()
	buffer := make([]byte, outerHeaderSize+outerDataSequenceSize+packetMTU+outerAuthTagSize+1)
	for {
		n, source, err := relay.conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		packet := append([]byte(nil), buffer[:n]...)
		if addrEqual(source, relay.server) {
			relay.mu.Lock()
			header, _ := decodeOuterHeader(packet)
			if header.Type == outerTypeData {
				if relay.drop {
					relay.serverPostData++
				} else {
					relay.serverPreData++
				}
				relay.serverTCP.record(header.Payload, relay.drop)
			}
			client := cloneUDPAddr(relay.client)
			delay := relay.controlDelayLocked(header.Type)
			relay.mu.Unlock()
			if client != nil {
				if delay > 0 {
					time.Sleep(delay)
				}
				_, _ = relay.conn.WriteToUDP(packet, client)
			}
			continue
		}
		header, _ := decodeOuterHeader(packet)
		relay.mu.Lock()
		if relay.client == nil {
			relay.client = cloneUDPAddr(source)
		}
		if relay.drop && addrEqual(source, relay.dropped) {
			relay.mu.Unlock()
			continue
		}
		if relay.drop && !addrEqual(source, relay.dropped) {
			relay.client = cloneUDPAddr(source)
			relay.replacement = cloneUDPAddr(source)
		} else if !relay.drop {
			relay.client = cloneUDPAddr(source)
		}
		if header.Type == outerTypeData {
			if relay.drop {
				relay.postData++
			} else {
				relay.preData++
			}
			relay.clientTCP.record(header.Payload, relay.drop)
		}
		delay := relay.controlDelayLocked(header.Type)
		relay.mu.Unlock()
		if delay > 0 {
			time.Sleep(delay)
		}
		_, _ = relay.conn.WriteToUDP(packet, relay.server)
	}
}

func (relay *packetBlackholeRelay) controlDelayLocked(typ outerType) time.Duration {
	if typ == outerTypeLivenessChallenge || typ == outerTypeLivenessAck {
		return relay.livenessDelay
	}
	return 0
}

func (relay *packetBlackholeRelay) SetLivenessDelay(delay time.Duration) {
	relay.mu.Lock()
	relay.livenessDelay = delay
	relay.mu.Unlock()
}

func (relay *packetBlackholeRelay) DropEstablishedClient(t testing.TB) string {
	t.Helper()
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if relay.client == nil {
		t.Fatal("relay has no established client tuple")
	}
	relay.dropped = cloneUDPAddr(relay.client)
	relay.drop = true
	return relay.dropped.String()
}

func (relay *packetBlackholeRelay) PreData() uint64 {
	relay.mu.Lock()
	defer relay.mu.Unlock()
	return relay.preData
}

func (relay *packetBlackholeRelay) ServerPreData() uint64 {
	relay.mu.Lock()
	defer relay.mu.Unlock()
	return relay.serverPreData
}

func (relay *packetBlackholeRelay) ServerPostData() uint64 {
	relay.mu.Lock()
	defer relay.mu.Unlock()
	return relay.serverPostData
}

func (relay *packetBlackholeRelay) TCPSummaries() (tcpPacketSummary, tcpPacketSummary) {
	relay.mu.Lock()
	defer relay.mu.Unlock()
	return relay.clientTCP, relay.serverTCP
}

type tcpPacketSummary struct {
	postPayloadPackets uint64
	postPayloadBytes   uint64
	postACKOnly        uint64
	lastSequence       uint32
	lastAcknowledgment uint32
	lastWindow         uint16
	lastFlags          byte
	lastPayloadBytes   int
	payloadSeqChanges  uint64
	lastPayloadSeq     uint32
}

func (summary *tcpPacketSummary) record(outerPayload []byte, post bool) {
	if !post {
		return
	}
	data, err := parseOuterData(outerPayload)
	if err != nil || len(data.Packet) < 40 {
		return
	}
	ipHeader := int(data.Packet[0]&0x0f) * 4
	if ipHeader < 20 || len(data.Packet) < ipHeader+20 || data.Packet[9] != 6 {
		return
	}
	total := int(data.Packet[2])<<8 | int(data.Packet[3])
	if total > len(data.Packet) {
		total = len(data.Packet)
	}
	tcpHeader := int(data.Packet[ipHeader+12]>>4) * 4
	if tcpHeader < 20 || ipHeader+tcpHeader > total {
		return
	}
	summary.lastSequence = uint32(data.Packet[ipHeader+4])<<24 | uint32(data.Packet[ipHeader+5])<<16 |
		uint32(data.Packet[ipHeader+6])<<8 | uint32(data.Packet[ipHeader+7])
	summary.lastAcknowledgment = uint32(data.Packet[ipHeader+8])<<24 | uint32(data.Packet[ipHeader+9])<<16 |
		uint32(data.Packet[ipHeader+10])<<8 | uint32(data.Packet[ipHeader+11])
	summary.lastFlags = data.Packet[ipHeader+13]
	summary.lastWindow = uint16(data.Packet[ipHeader+14])<<8 | uint16(data.Packet[ipHeader+15])
	payloadBytes := total - ipHeader - tcpHeader
	if payloadBytes > 0 {
		if summary.postPayloadPackets != 0 && summary.lastPayloadSeq != summary.lastSequence {
			summary.payloadSeqChanges++
		}
		summary.lastPayloadSeq = summary.lastSequence
		summary.lastPayloadBytes = payloadBytes
		summary.postPayloadPackets++
		summary.postPayloadBytes += uint64(payloadBytes)
	} else if summary.lastFlags&0x10 != 0 {
		summary.postACKOnly++
	}
}

func (relay *packetBlackholeRelay) PostData() uint64 {
	relay.mu.Lock()
	defer relay.mu.Unlock()
	return relay.postData
}

func (relay *packetBlackholeRelay) ReplacementTuple() string {
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if relay.replacement == nil {
		return ""
	}
	return relay.replacement.String()
}

func cloneUDPAddr(value *net.UDPAddr) *net.UDPAddr {
	if value == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), value.IP...), Port: value.Port, Zone: value.Zone}
}
