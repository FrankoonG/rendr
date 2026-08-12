//go:build rendr_experimental_gvisor

package gvisor

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/transport"
)

const (
	publicK5GVisorSchema          = "rendr-gvisor-kernel5-public-app-v2"
	publicK5GVisorFrames          = 2048
	publicK5GVisorPayloadBytes    = 16 << 10
	publicK5GVisorCutoverFrames   = 64
	publicK5GVisorRecoveryLimit   = 5 * time.Second
	publicK5GVisorEvidenceEnv     = "RENDR_KERNEL5_GVISOR_EVIDENCE"
	publicK5GVisorEvidenceNonce   = "RENDR_KERNEL5_GVISOR_NONCE"
	publicK5GVisorDataFactoryName = "gvisor-public-data"
	publicK5GVisorControlName     = "gvisor-public-control"
)

func TestGVisorKernel5PublicRuntimeSilentBlackholeRebind(t *testing.T) {
	requireOuterPacketSupport(t)
	evidence := runPublicRuntimeGVisorBlackhole(t)
	writePublicK5GVisorEvidence(t, evidence)
}

func runPublicRuntimeGVisorBlackhole(t *testing.T) publicK5GVisorEvidence {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	packetListener, err := ListenPacket("127.0.0.1:0", WithTrustedCarrier())
	if err != nil {
		t.Fatal(err)
	}
	relay := newPacketBlackholeRelay(t, packetListener.Addr())
	controlListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		relay.Close()
		_ = packetListener.Close()
		t.Fatal(err)
	}

	runtimeConfig := rendr.DefaultRuntimeConfig()
	runtimeConfig.Selector.QualityDwell = 30 * time.Second
	runtimeConfig.Selector.QualityCooldown = 30 * time.Second
	runtimeConfig.Recovery.MigrationBudget = 15 * time.Second
	serverRuntime, err := rendr.NewRuntimeContext(ctx, runtimeConfig)
	if err != nil {
		t.Fatal(err)
	}
	responderListener := newPublicK5ResponderListener(packetListener)
	sessionListener, err := serverRuntime.Listen(rendr.ListenConfig{
		Streams: []rendr.StreamSource{{
			Name: publicK5GVisorControlName, Carrier: rendr.CarrierTCP, Listener: controlListener,
		}},
		Framed: []rendr.FramedSource{{
			Name: publicK5GVisorDataFactoryName, Carrier: rendr.CarrierUDP, Listener: responderListener,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	clientRuntime, err := rendr.NewRuntimeContext(ctx, runtimeConfig)
	if err != nil {
		t.Fatal(err)
	}
	observedFactory := newPublicK5ObservedFactory(packetListener.Factory())
	if err := clientRuntime.RegisterFramedFactory(publicK5GVisorDataFactoryName, rendr.FramedFactory{
		Carrier: rendr.CarrierUDP, Factory: observedFactory,
	}); err != nil {
		t.Fatal(err)
	}
	root := rendr.Selector("gvisor-public-root", []rendr.Target{
		rendr.Path("gvisor-data", rendr.PathSpec{
			Transport: publicK5GVisorDataFactoryName, Address: relay.Addr().String(),
		}),
		rendr.Path("control", rendr.PathSpec{
			Transport: "tcp", Address: controlListener.Addr().String(),
		}),
	})
	client, err := clientRuntime.Dial(ctx, rendr.SessionConfig{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	server, err := sessionListener.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	clientPath := observedFactory.path(t, ctx)
	serverOwner := publicK5ServerOwner(t, packetListener, clientPath.link.virtualIP)

	clientObserver, ok := client.(rendr.ConnectionObserver)
	if !ok {
		t.Fatalf("public client %T does not implement ConnectionObserver", client)
	}
	serverObserver, ok := server.(rendr.ConnectionObserver)
	if !ok {
		t.Fatalf("public server %T does not implement ConnectionObserver", server)
	}
	clientClaim := clientPath.LeafMobilityClaim()
	if clientClaim == nil {
		t.Fatal("public Runtime gVisor path has no ownership claim")
	}
	claimBefore := clientClaim.Snapshot()
	if claimBefore.Kind != leafmobility.KindGVisor || claimBefore.Role != leafmobility.RoleDialer ||
		claimBefore.Scope != leafmobility.ScopeEndpoint || claimBefore.Session != leafmobility.SessionAny ||
		!claimBefore.Operations.Has(leafmobility.OperationGVisorLinkRebind) ||
		claimBefore.ResourceID == (leafmobility.ResourceID{}) || claimBefore.Generation == 0 {
		t.Fatalf("public Runtime gVisor ownership facts=%+v", claimBefore)
	}
	binding, bound := clientClaim.Binding()
	if !bound {
		t.Fatal("public Runtime gVisor claim was not bound during initial session admission")
	}
	flowBefore := client.FlowID()
	peerFlow := server.FlowID()
	if flowBefore == ([16]byte{}) || peerFlow != flowBefore || binding.FlowID != flowBefore {
		t.Fatalf("public Runtime flow/binding mismatch client=%x server=%x binding=%x", flowBefore, peerFlow, binding.FlowID)
	}
	if binding.PathID == 0 || binding.Owner == 0 {
		t.Fatalf("public Runtime gVisor binding=%+v", binding)
	}

	clientObjectBefore := publicK5ObjectToken(client)
	serverObjectBefore := publicK5ObjectToken(server)
	appClient := &publicK5AppConn{Conn: client}
	appServer := &publicK5AppConn{Conn: server}
	appClientBefore := publicK5ObjectToken(appClient)
	appServerBefore := publicK5ObjectToken(appServer)
	localBefore, remoteBefore := client.LocalAddr().String(), client.RemoteAddr().String()
	clientControlBefore := publicK5PathCounters(t, client.Paths(), "control")
	serverControlBefore := publicK5PathCounters(t, server.Paths(), "control")
	migrationsBefore := clientObserver.MigrationCount()

	clientPath.link.mu.Lock()
	clientLinkBefore := clientPath.link.id
	clientIncarnationBefore := clientPath.link.incarnation
	clientOuterGenerationBefore := clientPath.link.localGeneration
	clientPeerGenerationBefore := clientPath.link.peerGeneration
	clientWireBefore := clientPath.link.active
	outerPeerBefore := clientPath.link.peerRemote.String()
	clientPath.link.mu.Unlock()
	outerTupleBefore := observedOuterLocalTuple(t, clientPath.link)
	serverOwner.mu.Lock()
	serverPeerBefore := serverOwner.peerRemote.String()
	serverOwner.mu.Unlock()
	claimExecutionBefore := clientClaim.ExecutionGeneration()

	events := make(chan publicK5MigrationEvent, 4)
	cancelEvents := clientObserver.OnMigrate(func(oldID, newID uint32, cause string) {
		events <- publicK5MigrationEvent{OldID: oldID, NewID: newID, Cause: cause, AtUnixNano: time.Now().UnixNano()}
	})
	defer cancelEvents()

	gate := make(chan struct{})
	var releaseGate sync.Once
	release := func() { releaseGate.Do(func() { close(gate) }) }
	defer release()
	clientGenerated := &atomic.Uint64{}
	serverGenerated := &atomic.Uint64{}
	clientReceived := newPublicK5HashWriter()
	serverReceived := newPublicK5HashWriter()
	copyResults := make(chan publicK5CopyResult, 4)
	totalBytes := int64(publicK5GVisorFrames * publicK5GVisorPayloadBytes)
	go publicK5Copy(copyResults, "client-write", appClient,
		newPublicK5PayloadReader(0x41, gate, clientGenerated))
	go publicK5Copy(copyResults, "server-read", serverReceived,
		io.LimitReader(appServer, totalBytes))
	go publicK5Copy(copyResults, "server-write", appServer,
		newPublicK5PayloadReader(0x82, gate, serverGenerated))
	go publicK5Copy(copyResults, "client-read", clientReceived,
		io.LimitReader(appClient, totalBytes))

	publicK5WaitForCutoverProgress(t, ctx, clientGenerated, serverGenerated, clientReceived, serverReceived)
	if relay.PreData() == 0 || relay.ServerPreData() == 0 {
		t.Fatalf("outer DATA before blackhole client/server=%d/%d", relay.PreData(), relay.ServerPreData())
	}
	clientGeneratedAtBlackhole := clientGenerated.Load() * publicK5GVisorPayloadBytes
	serverGeneratedAtBlackhole := serverGenerated.Load() * publicK5GVisorPayloadBytes
	clientReceivedAtBlackhole := clientReceived.bytes.Load()
	serverReceivedAtBlackhole := serverReceived.bytes.Load()
	outerTupleDropped := relay.DropEstablishedClient(t)
	blackholeUnixNano := time.Now().UnixNano()
	release()

	event := publicK5WaitForMigration(t, ctx, events)
	if event.OldID != binding.PathID || event.NewID != binding.PathID || event.Cause != "leaf-mobility" {
		clientPath.link.mu.Lock()
		linkFault, linkClosed, linkGeneration := clientPath.link.wireFault, clientPath.link.closed, clientPath.link.localGeneration
		clientPath.link.mu.Unlock()
		t.Fatalf("public migration event=%+v binding=%+v status=%+v link fault/closed/generation=%t/%t/%d",
			event, binding, client.Status(), linkFault, linkClosed, linkGeneration)
	}
	if elapsed := time.Duration(event.AtUnixNano - blackholeUnixNano); elapsed <= 0 || elapsed > publicK5GVisorRecoveryLimit {
		t.Fatalf("public gVisor rebind elapsed=%v", elapsed)
	}
	publicK5WaitForCommittedStatus(t, ctx, client, binding.PathID)

	results := make(map[string]publicK5CopyResult, 4)
	for range 4 {
		select {
		case result := <-copyResults:
			results[result.Name] = result
		case <-ctx.Done():
			t.Fatalf("public io.Copy transfer timed out: %v", ctx.Err())
		}
	}
	for _, name := range []string{"client-write", "server-read", "server-write", "client-read"} {
		result, exists := results[name]
		if !exists || result.Err != nil || result.Bytes != totalBytes {
			t.Fatalf("public io.Copy %s=%+v exists=%t", name, result, exists)
		}
	}
	select {
	case extra := <-events:
		t.Fatalf("unexpected second public migration event: %+v", extra)
	case <-time.After(50 * time.Millisecond):
	}

	claimAfter := clientClaim.Snapshot()
	statusAfter := publicK5PathStatus(t, client.Status(), binding.PathID)
	clientPath.link.mu.Lock()
	clientLinkAfter := clientPath.link.id
	clientIncarnationAfter := clientPath.link.incarnation
	clientOuterGenerationAfter := clientPath.link.localGeneration
	clientPeerGenerationAfter := clientPath.link.peerGeneration
	clientWireAfter := clientPath.link.active
	outerPeerAfter := clientPath.link.peerRemote.String()
	clientPath.link.mu.Unlock()
	outerTupleAfter := observedOuterLocalTuple(t, clientPath.link)
	serverOwner.mu.Lock()
	serverPeerAfter := serverOwner.peerRemote.String()
	committedPeer := serverOwner.committedPeer
	serverOwner.mu.Unlock()
	if committedPeer == nil {
		t.Fatal("server packet-link owner has no committed peer transaction")
	}
	transactionID := hex.EncodeToString(committedPeer.control.Transaction[:])
	agreementDigest := hex.EncodeToString(committedPeer.control.Agreement[:])

	clientControlAfter := publicK5PathCounters(t, client.Paths(), "control")
	serverControlAfter := publicK5PathCounters(t, server.Paths(), "control")
	if clientControlAfter.Reads <= clientControlBefore.Reads || clientControlAfter.Writes <= clientControlBefore.Writes ||
		serverControlAfter.Reads <= serverControlBefore.Reads || serverControlAfter.Writes <= serverControlBefore.Writes {
		t.Fatalf("sibling control route did not carry bilateral transaction client=%+v/%+v server=%+v/%+v",
			clientControlBefore, clientControlAfter, serverControlBefore, serverControlAfter)
	}

	flowAfter := client.FlowID()
	clientObjectAfter := publicK5ObjectToken(client)
	serverObjectAfter := publicK5ObjectToken(server)
	appClientAfter := publicK5ObjectToken(appClient)
	appServerAfter := publicK5ObjectToken(appServer)
	localAfter, remoteAfter := client.LocalAddr().String(), client.RemoteAddr().String()
	if clientObjectAfter != clientObjectBefore || serverObjectAfter != serverObjectBefore ||
		appClientAfter != appClientBefore || appServerAfter != appServerBefore ||
		flowAfter != flowBefore || localAfter != localBefore || remoteAfter != remoteBefore {
		t.Fatal("public application object, flow, or address changed across packet-link rebind")
	}
	if clientLinkAfter != clientLinkBefore || clientWireAfter == clientWireBefore || outerTupleAfter == outerTupleBefore ||
		outerTupleAfter == outerTupleDropped || relay.ReplacementTuple() != outerTupleAfter {
		t.Fatalf("outer packet link did not change in place: link=%x/%x wire=%p/%p tuple=%s/%s/%s replacement=%s",
			clientLinkBefore, clientLinkAfter, clientWireBefore, clientWireAfter,
			outerTupleBefore, outerTupleDropped, outerTupleAfter, relay.ReplacementTuple())
	}
	if claimAfter.ResourceID != claimBefore.ResourceID || claimAfter.Generation <= claimBefore.Generation ||
		clientClaim.ExecutionGeneration() != claimExecutionBefore+1 ||
		clientIncarnationAfter <= clientIncarnationBefore || clientOuterGenerationAfter != clientOuterGenerationBefore+1 {
		t.Fatalf("ownership generation before=%+v/%d/%d/%d after=%+v/%d/%d/%d",
			claimBefore, claimExecutionBefore, clientIncarnationBefore, clientOuterGenerationBefore,
			claimAfter, clientClaim.ExecutionGeneration(), clientIncarnationAfter, clientOuterGenerationAfter)
	}
	if statusAfter.Mobility.ID != rendr.MobilityGVisorPacketLinkRebind ||
		statusAfter.Mobility.State != rendr.MobilityStateCommitted ||
		statusAfter.Mobility.EndpointGeneration != claimAfter.Generation || statusAfter.Mobility.EvidenceGeneration == 0 {
		t.Fatalf("public mobility status=%+v claim=%+v", statusAfter.Mobility, claimAfter)
	}
	if clientObserver.MigrationCount() != migrationsBefore+1 || serverObserver.MigrationCount() > 1 {
		t.Fatalf("public migration counts client=%d/%d server=%d", migrationsBefore,
			clientObserver.MigrationCount(), serverObserver.MigrationCount())
	}

	clientOfferedHash := publicK5PayloadSHA256(0x41)
	serverOfferedHash := publicK5PayloadSHA256(0x82)
	clientReceivedHash := clientReceived.sum()
	serverReceivedHash := serverReceived.sum()
	if clientReceivedHash != serverOfferedHash || serverReceivedHash != clientOfferedHash ||
		clientReceived.bytes.Load() != uint64(totalBytes) || serverReceived.bytes.Load() != uint64(totalBytes) {
		t.Fatalf("public io.Copy integrity client=%d/%s server=%d/%s",
			clientReceived.bytes.Load(), clientReceivedHash, serverReceived.bytes.Load(), serverReceivedHash)
	}
	clientApp := appClient.snapshot()
	serverApp := appServer.snapshot()
	if clientApp.hasFailure() || serverApp.hasFailure() {
		t.Fatalf("application observed connection failure client=%+v server=%+v", clientApp, serverApp)
	}

	clientCloseBefore := publicK5OwnerCloseState(clientPath.link)
	serverCloseBefore := publicK5OwnerCloseState(serverOwner)
	if clientCloseBefore.WireFault || serverCloseBefore.WireFault ||
		clientCloseBefore.ReplayExhausted || serverCloseBefore.ReplayExhausted {
		t.Fatalf("packet-link was not live before application close: client=%+v server=%+v", clientCloseBefore, serverCloseBefore)
	}
	if err := appClient.Close(); err != nil {
		t.Fatalf("close public client connection: %v client_owner_before=%+v server_owner_before=%+v client_owner_after=%+v server_owner_after=%+v",
			err, clientCloseBefore, serverCloseBefore,
			publicK5OwnerCloseState(clientPath.link), publicK5OwnerCloseState(serverOwner))
	}
	if err := appServer.Close(); err != nil {
		t.Fatalf("close public server connection after client BYE: %v client_owner_before=%+v server_owner_before=%+v client_owner_after=%+v server_owner_after=%+v",
			err, clientCloseBefore, serverCloseBefore,
			publicK5OwnerCloseState(clientPath.link), publicK5OwnerCloseState(serverOwner))
	}
	if err := sessionListener.Close(); err != nil {
		t.Fatalf("close public Runtime listener: %v", err)
	}
	relay.Close()
	cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelCleanup()
	publicK5WaitClosed(t, cleanupCtx, clientPath.link.done, "client packet-link owner")
	publicK5WaitClosed(t, cleanupCtx, serverOwner.done, "server packet-link owner")
	publicK5WaitClosed(t, cleanupCtx, packetListener.closed, "gVisor listener admission")
	publicK5WaitClosed(t, cleanupCtx, packetListener.cleanupDone, "gVisor listener cleanup")

	packetListener.packetMu.RLock()
	linksAfter := len(packetListener.packetLinks)
	addressesAfter := len(packetListener.packetByIP)
	pendingAfter := len(packetListener.packetPending)
	packetListener.packetMu.RUnlock()
	clientReplayAfter := packetListener.clientReplayBudget.snapshot()
	serverReplayAfter := packetListener.serverReplayBudget.snapshot()
	refreshAfter := processRefreshCallbackBudget.snapshot()
	clientApp = appClient.snapshot()
	serverApp = appServer.snapshot()

	return publicK5GVisorEvidence{
		Schema: publicK5GVisorSchema, Test: "TestGVisorKernel5PublicRuntimeSilentBlackholeRebind",
		RuntimeClientObjectBefore: clientObjectBefore, RuntimeClientObjectAfter: clientObjectAfter,
		RuntimeServerObjectBefore: serverObjectBefore, RuntimeServerObjectAfter: serverObjectAfter,
		AppClientObjectBefore: appClientBefore, AppClientObjectAfter: appClientAfter,
		AppServerObjectBefore: appServerBefore, AppServerObjectAfter: appServerAfter,
		FlowIDBefore: hex.EncodeToString(flowBefore[:]), FlowIDAfter: hex.EncodeToString(flowAfter[:]),
		PeerFlowID:      hex.EncodeToString(peerFlow[:]),
		LocalAddrBefore: localBefore, LocalAddrAfter: localAfter,
		RemoteAddrBefore: remoteBefore, RemoteAddrAfter: remoteAfter,
		PathID: binding.PathID, PathOwner: binding.Owner,
		MigrationCountBefore: migrationsBefore, MigrationCountAfter: clientObserver.MigrationCount(),
		MigrationEventCount: 1, MigrationOldPathID: event.OldID, MigrationNewPathID: event.NewID,
		MigrationCause: event.Cause, BlackholeUnixNano: blackholeUnixNano, MigrationUnixNano: event.AtUnixNano,
		StatusMobilityID: string(statusAfter.Mobility.ID), StatusMobilityState: string(statusAfter.Mobility.State),
		StatusEndpointGeneration: statusAfter.Mobility.EndpointGeneration,
		StatusEvidenceGeneration: statusAfter.Mobility.EvidenceGeneration,
		ClaimKind:                uint8(claimBefore.Kind), ClaimRole: uint8(claimBefore.Role), ClaimScope: uint8(claimBefore.Scope),
		ClaimSession: uint8(claimBefore.Session), ClaimOperations: uint8(claimBefore.Operations),
		ClaimResourceIDBefore: fmt.Sprintf("%x", claimBefore.ResourceID), ClaimResourceIDAfter: fmt.Sprintf("%x", claimAfter.ResourceID),
		ClaimEndpointGenerationBefore: claimBefore.Generation, ClaimEndpointGenerationAfter: claimAfter.Generation,
		ClaimExecutionGenerationBefore: claimExecutionBefore, ClaimExecutionGenerationAfter: clientClaim.ExecutionGeneration(),
		ClaimBindingFlowID: fmt.Sprintf("%x", binding.FlowID), ClaimBindingLocalTargetID: fmt.Sprintf("%x", binding.LocalTargetID),
		ClaimBindingPeerTargetID: fmt.Sprintf("%x", binding.PeerTargetID),
		ClaimBindingPathID:       binding.PathID, ClaimBindingOwner: binding.Owner,
		LinkIDBefore: hex.EncodeToString(clientLinkBefore[:]), LinkIDAfter: hex.EncodeToString(clientLinkAfter[:]),
		OuterIncarnationBefore: clientIncarnationBefore, OuterIncarnationAfter: clientIncarnationAfter,
		OuterGenerationBefore: clientOuterGenerationBefore, OuterGenerationAfter: clientOuterGenerationAfter,
		PeerGenerationBefore: clientPeerGenerationBefore, PeerGenerationAfter: clientPeerGenerationAfter,
		OuterWireBefore: fmt.Sprintf("%p", clientWireBefore), OuterWireAfter: fmt.Sprintf("%p", clientWireAfter),
		OuterTupleBefore: outerTupleBefore, OuterTupleDropped: outerTupleDropped, OuterTupleAfter: outerTupleAfter,
		OuterPeerBefore: outerPeerBefore, OuterPeerAfter: outerPeerAfter,
		ServerPeerBefore: serverPeerBefore, ServerPeerAfter: serverPeerAfter,
		TransactionID: transactionID, AgreementDigest: agreementDigest,
		ClientOuterDataBefore: relay.PreData(), ClientOuterDataAfter: relay.PostData(),
		ServerOuterDataBefore: relay.ServerPreData(), ServerOuterDataAfter: relay.ServerPostData(),
		ClientGeneratedBytesAtBlackhole: clientGeneratedAtBlackhole,
		ServerGeneratedBytesAtBlackhole: serverGeneratedAtBlackhole,
		ClientReceivedBytesAtBlackhole:  clientReceivedAtBlackhole,
		ServerReceivedBytesAtBlackhole:  serverReceivedAtBlackhole,
		ClientOfferedBytes:              uint64(totalBytes), ClientReceivedBytes: serverReceived.bytes.Load(),
		ServerOfferedBytes: uint64(totalBytes), ServerReceivedBytes: clientReceived.bytes.Load(),
		ClientOfferedSHA256: clientOfferedHash, ClientReceivedSHA256: serverReceivedHash,
		ServerOfferedSHA256: serverOfferedHash, ServerReceivedSHA256: clientReceivedHash,
		CopyOperations: 4, CopyErrors: 0,
		ClientApp: clientApp, ServerApp: serverApp,
		ClientControlBefore: clientControlBefore, ClientControlAfter: clientControlAfter,
		ServerControlBefore: serverControlBefore, ServerControlAfter: serverControlAfter,
		ClientClaimRetired: clientClaim.Retired(), ServerClaimRetired: serverOwner.claim.Retired(),
		ClientOwnerClosed: true, ServerOwnerClosed: true, ListenerAdmissionClosed: true, ListenerCleanupClosed: true,
		ListenerLinksAfter: linksAfter, ListenerAddressesAfter: addressesAfter, ListenerPendingAfter: pendingAfter,
		ClientReplayOwnersAfter: clientReplayAfter.Owners, ClientReplayBytesAfter: clientReplayAfter.Bytes,
		ClientReplayEntriesAfter: clientReplayAfter.Entries,
		ServerReplayOwnersAfter:  serverReplayAfter.Owners, ServerReplayBytesAfter: serverReplayAfter.Bytes,
		ServerReplayEntriesAfter:    serverReplayAfter.Entries,
		RefreshCallbacksActiveAfter: refreshAfter.Active,
	}
}

type publicK5GVisorEvidence struct {
	Schema string `json:"schema"`
	Nonce  string `json:"nonce"`
	Test   string `json:"test"`

	RuntimeClientObjectBefore string `json:"runtime_client_object_before"`
	RuntimeClientObjectAfter  string `json:"runtime_client_object_after"`
	RuntimeServerObjectBefore string `json:"runtime_server_object_before"`
	RuntimeServerObjectAfter  string `json:"runtime_server_object_after"`
	AppClientObjectBefore     string `json:"app_client_object_before"`
	AppClientObjectAfter      string `json:"app_client_object_after"`
	AppServerObjectBefore     string `json:"app_server_object_before"`
	AppServerObjectAfter      string `json:"app_server_object_after"`
	FlowIDBefore              string `json:"flow_id_before"`
	FlowIDAfter               string `json:"flow_id_after"`
	PeerFlowID                string `json:"peer_flow_id"`
	LocalAddrBefore           string `json:"local_addr_before"`
	LocalAddrAfter            string `json:"local_addr_after"`
	RemoteAddrBefore          string `json:"remote_addr_before"`
	RemoteAddrAfter           string `json:"remote_addr_after"`
	PathID                    uint32 `json:"path_id"`
	PathOwner                 uint64 `json:"path_owner"`

	MigrationCountBefore uint64 `json:"migration_count_before"`
	MigrationCountAfter  uint64 `json:"migration_count_after"`
	MigrationEventCount  uint64 `json:"migration_event_count"`
	MigrationOldPathID   uint32 `json:"migration_old_path_id"`
	MigrationNewPathID   uint32 `json:"migration_new_path_id"`
	MigrationCause       string `json:"migration_cause"`
	BlackholeUnixNano    int64  `json:"blackhole_unix_nano"`
	MigrationUnixNano    int64  `json:"migration_unix_nano"`

	StatusMobilityID               string `json:"status_mobility_id"`
	StatusMobilityState            string `json:"status_mobility_state"`
	StatusEndpointGeneration       uint64 `json:"status_endpoint_generation"`
	StatusEvidenceGeneration       uint64 `json:"status_evidence_generation"`
	ClaimKind                      uint8  `json:"claim_kind"`
	ClaimRole                      uint8  `json:"claim_role"`
	ClaimScope                     uint8  `json:"claim_scope"`
	ClaimSession                   uint8  `json:"claim_session"`
	ClaimOperations                uint8  `json:"claim_operations"`
	ClaimResourceIDBefore          string `json:"claim_resource_id_before"`
	ClaimResourceIDAfter           string `json:"claim_resource_id_after"`
	ClaimEndpointGenerationBefore  uint64 `json:"claim_endpoint_generation_before"`
	ClaimEndpointGenerationAfter   uint64 `json:"claim_endpoint_generation_after"`
	ClaimExecutionGenerationBefore uint64 `json:"claim_execution_generation_before"`
	ClaimExecutionGenerationAfter  uint64 `json:"claim_execution_generation_after"`
	ClaimBindingFlowID             string `json:"claim_binding_flow_id"`
	ClaimBindingLocalTargetID      string `json:"claim_binding_local_target_id"`
	ClaimBindingPeerTargetID       string `json:"claim_binding_peer_target_id"`
	ClaimBindingPathID             uint32 `json:"claim_binding_path_id"`
	ClaimBindingOwner              uint64 `json:"claim_binding_owner"`

	LinkIDBefore           string `json:"link_id_before"`
	LinkIDAfter            string `json:"link_id_after"`
	OuterIncarnationBefore uint64 `json:"outer_incarnation_before"`
	OuterIncarnationAfter  uint64 `json:"outer_incarnation_after"`
	OuterGenerationBefore  uint64 `json:"outer_generation_before"`
	OuterGenerationAfter   uint64 `json:"outer_generation_after"`
	PeerGenerationBefore   uint64 `json:"peer_generation_before"`
	PeerGenerationAfter    uint64 `json:"peer_generation_after"`
	OuterWireBefore        string `json:"outer_wire_before"`
	OuterWireAfter         string `json:"outer_wire_after"`
	OuterTupleBefore       string `json:"outer_tuple_before"`
	OuterTupleDropped      string `json:"outer_tuple_dropped"`
	OuterTupleAfter        string `json:"outer_tuple_after"`
	OuterPeerBefore        string `json:"outer_peer_before"`
	OuterPeerAfter         string `json:"outer_peer_after"`
	ServerPeerBefore       string `json:"server_peer_before"`
	ServerPeerAfter        string `json:"server_peer_after"`
	TransactionID          string `json:"transaction_id"`
	AgreementDigest        string `json:"agreement_digest"`

	ClientOuterDataBefore           uint64                 `json:"client_outer_data_before"`
	ClientOuterDataAfter            uint64                 `json:"client_outer_data_after"`
	ServerOuterDataBefore           uint64                 `json:"server_outer_data_before"`
	ServerOuterDataAfter            uint64                 `json:"server_outer_data_after"`
	ClientGeneratedBytesAtBlackhole uint64                 `json:"client_generated_bytes_at_blackhole"`
	ServerGeneratedBytesAtBlackhole uint64                 `json:"server_generated_bytes_at_blackhole"`
	ClientReceivedBytesAtBlackhole  uint64                 `json:"client_received_bytes_at_blackhole"`
	ServerReceivedBytesAtBlackhole  uint64                 `json:"server_received_bytes_at_blackhole"`
	ClientOfferedBytes              uint64                 `json:"client_offered_bytes"`
	ClientReceivedBytes             uint64                 `json:"client_received_bytes"`
	ServerOfferedBytes              uint64                 `json:"server_offered_bytes"`
	ServerReceivedBytes             uint64                 `json:"server_received_bytes"`
	ClientOfferedSHA256             string                 `json:"client_offered_sha256"`
	ClientReceivedSHA256            string                 `json:"client_received_sha256"`
	ServerOfferedSHA256             string                 `json:"server_offered_sha256"`
	ServerReceivedSHA256            string                 `json:"server_received_sha256"`
	CopyOperations                  uint64                 `json:"copy_operations"`
	CopyErrors                      uint64                 `json:"copy_errors"`
	ClientApp                       publicK5AppObservation `json:"client_app"`
	ServerApp                       publicK5AppObservation `json:"server_app"`
	ClientControlBefore             publicK5PathCounter    `json:"client_control_before"`
	ClientControlAfter              publicK5PathCounter    `json:"client_control_after"`
	ServerControlBefore             publicK5PathCounter    `json:"server_control_before"`
	ServerControlAfter              publicK5PathCounter    `json:"server_control_after"`

	ClientClaimRetired          bool `json:"client_claim_retired"`
	ServerClaimRetired          bool `json:"server_claim_retired"`
	ClientOwnerClosed           bool `json:"client_owner_closed"`
	ServerOwnerClosed           bool `json:"server_owner_closed"`
	ListenerAdmissionClosed     bool `json:"listener_admission_closed"`
	ListenerCleanupClosed       bool `json:"listener_cleanup_closed"`
	ListenerLinksAfter          int  `json:"listener_links_after"`
	ListenerAddressesAfter      int  `json:"listener_addresses_after"`
	ListenerPendingAfter        int  `json:"listener_pending_after"`
	ClientReplayOwnersAfter     int  `json:"client_replay_owners_after"`
	ClientReplayBytesAfter      int  `json:"client_replay_bytes_after"`
	ClientReplayEntriesAfter    int  `json:"client_replay_entries_after"`
	ServerReplayOwnersAfter     int  `json:"server_replay_owners_after"`
	ServerReplayBytesAfter      int  `json:"server_replay_bytes_after"`
	ServerReplayEntriesAfter    int  `json:"server_replay_entries_after"`
	RefreshCallbacksActiveAfter int  `json:"refresh_callbacks_active_after"`
}

type publicK5AppObservation struct {
	ReadCalls   uint64 `json:"read_calls"`
	WriteCalls  uint64 `json:"write_calls"`
	CloseCalls  uint64 `json:"close_calls"`
	ReadErrors  uint64 `json:"read_errors"`
	WriteErrors uint64 `json:"write_errors"`
	CloseErrors uint64 `json:"close_errors"`
	EOFs        uint64 `json:"eofs"`
	ReadZeros   uint64 `json:"read_zeros"`
	Resets      uint64 `json:"resets"`
}

func (observation publicK5AppObservation) hasFailure() bool {
	return observation.ReadCalls == 0 || observation.WriteCalls == 0 ||
		observation.ReadErrors != 0 || observation.WriteErrors != 0 || observation.CloseErrors != 0 ||
		observation.EOFs != 0 || observation.ReadZeros != 0 || observation.Resets != 0
}

type publicK5PathCounter struct {
	Reads         uint64 `json:"reads"`
	Writes        uint64 `json:"writes"`
	ControlWrites uint64 `json:"control_writes"`
}

type publicK5MigrationEvent struct {
	OldID      uint32
	NewID      uint32
	Cause      string
	AtUnixNano int64
}

type publicK5CopyResult struct {
	Name  string
	Bytes int64
	Err   error
}

type publicK5OwnerCloseSnapshot struct {
	Closed            bool
	Closing           bool
	WireFault         bool
	LocalGeneration   uint64
	PeerGeneration    uint64
	CommittedPeer     uint64
	ReplayPackets     int
	ReplayBytes       int
	ReplaySequence    uint64
	ReplayActivations uint64
	ReplayTransmitted uint64
	ReplayTXBytes     uint64
	ReplayRequestGen  uint64
	ReplayRequestPeer uint64
	ReplayRequestNext uint64
	ReplayRequestRuns uint8
	ReplayExhausted   bool
	ReceiveNext       uint64
	PeerReceiveNext   uint64
}

type publicK5ObservedFactory struct {
	base   transport.PathFactory
	once   sync.Once
	pathCh chan *retainedPathConn
}

type publicK5ResponderListener struct {
	base *Listener
	mu   sync.Mutex
	stop []func()
}

func newPublicK5ResponderListener(base *Listener) *publicK5ResponderListener {
	return &publicK5ResponderListener{base: base}
}

func (listener *publicK5ResponderListener) AcceptPath(ctx context.Context) (transport.PathConn, error) {
	path, err := listener.base.AcceptPath(ctx)
	if err != nil {
		return nil, err
	}
	source, ok := path.(leafmobility.RefreshSource)
	if !ok {
		_ = path.Close()
		return nil, errors.New("gvisor public evidence: responder path has no mobility refresh source")
	}
	stop, err := source.SubscribeLeafMobilityRefresh(context.Background(), func(leafmobility.RefreshEvidence) {})
	if err != nil {
		_ = path.Close()
		return nil, fmt.Errorf("gvisor public evidence: suppress responder initiator: %w", err)
	}
	listener.mu.Lock()
	listener.stop = append(listener.stop, stop)
	listener.mu.Unlock()
	return path, nil
}

func (*publicK5ResponderListener) SessionKind() transport.PathSessionKind {
	return transport.PathSessionAny
}

func (listener *publicK5ResponderListener) Addr() net.Addr {
	return listener.base.Addr()
}

func (listener *publicK5ResponderListener) LeafMobilityImplementation() leafmobility.ImplementationEvidence {
	return gvisorLinkImplementationEvidence(listener)
}

func (listener *publicK5ResponderListener) Close() error {
	err := listener.base.Close()
	listener.mu.Lock()
	stops := append([]func(){}, listener.stop...)
	listener.stop = nil
	listener.mu.Unlock()
	for _, stop := range stops {
		stop()
	}
	return err
}

func newPublicK5ObservedFactory(base transport.PathFactory) *publicK5ObservedFactory {
	return &publicK5ObservedFactory{base: base, pathCh: make(chan *retainedPathConn, 1)}
}

func (factory *publicK5ObservedFactory) DialPath(ctx context.Context, spec transport.PathSpec) (transport.PathConn, error) {
	path, err := factory.base.DialPath(ctx, spec)
	if err != nil {
		return nil, err
	}
	retained, ok := path.(*retainedPathConn)
	if !ok || retained.link == nil {
		_ = path.Close()
		return nil, fmt.Errorf("gvisor public evidence: path type %T is not an owned packet link", path)
	}
	factory.once.Do(func() { factory.pathCh <- retained })
	return path, nil
}

func (factory *publicK5ObservedFactory) Probe(ctx context.Context, spec transport.PathSpec) (transport.PathQuality, error) {
	return factory.base.Probe(ctx, spec)
}

func (factory *publicK5ObservedFactory) LeafMobilityImplementation() leafmobility.ImplementationEvidence {
	return gvisorLinkImplementationEvidence(factory)
}

func (factory *publicK5ObservedFactory) path(t testing.TB, ctx context.Context) *retainedPathConn {
	t.Helper()
	select {
	case path := <-factory.pathCh:
		return path
	case <-ctx.Done():
		t.Fatalf("observe public Runtime gVisor path: %v", ctx.Err())
		return nil
	}
}

type publicK5AppConn struct {
	net.Conn
	readCalls   atomic.Uint64
	writeCalls  atomic.Uint64
	closeCalls  atomic.Uint64
	readErrors  atomic.Uint64
	writeErrors atomic.Uint64
	closeErrors atomic.Uint64
	eofs        atomic.Uint64
	readZeros   atomic.Uint64
	resets      atomic.Uint64
}

func (conn *publicK5AppConn) Read(buffer []byte) (int, error) {
	conn.readCalls.Add(1)
	n, err := conn.Conn.Read(buffer)
	if n == 0 && err == nil {
		conn.readZeros.Add(1)
	}
	conn.observeError(err, &conn.readErrors)
	return n, err
}

func (conn *publicK5AppConn) Write(buffer []byte) (int, error) {
	conn.writeCalls.Add(1)
	n, err := conn.Conn.Write(buffer)
	conn.observeError(err, &conn.writeErrors)
	return n, err
}

func (conn *publicK5AppConn) Close() error {
	conn.closeCalls.Add(1)
	err := conn.Conn.Close()
	if err != nil {
		conn.closeErrors.Add(1)
		if publicK5IsReset(err) {
			conn.resets.Add(1)
		}
	}
	return err
}

func (conn *publicK5AppConn) observeError(err error, counter *atomic.Uint64) {
	if err == nil {
		return
	}
	counter.Add(1)
	if errors.Is(err, io.EOF) {
		conn.eofs.Add(1)
	}
	if publicK5IsReset(err) {
		conn.resets.Add(1)
	}
}

func (conn *publicK5AppConn) snapshot() publicK5AppObservation {
	return publicK5AppObservation{
		ReadCalls: conn.readCalls.Load(), WriteCalls: conn.writeCalls.Load(), CloseCalls: conn.closeCalls.Load(),
		ReadErrors: conn.readErrors.Load(), WriteErrors: conn.writeErrors.Load(), CloseErrors: conn.closeErrors.Load(),
		EOFs: conn.eofs.Load(), ReadZeros: conn.readZeros.Load(), Resets: conn.resets.Load(),
	}
}

func publicK5IsReset(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, syscall.ECONNRESET) || strings.Contains(strings.ToLower(err.Error()), "reset")
}

type publicK5PayloadReader struct {
	marker   byte
	frame    int
	offset   int
	gate     <-chan struct{}
	progress *atomic.Uint64
}

func newPublicK5PayloadReader(marker byte, gate <-chan struct{}, progress *atomic.Uint64) *publicK5PayloadReader {
	return &publicK5PayloadReader{marker: marker, gate: gate, progress: progress}
}

func (reader *publicK5PayloadReader) Read(buffer []byte) (int, error) {
	if reader.frame == publicK5GVisorFrames {
		return 0, io.EOF
	}
	if reader.frame == publicK5GVisorCutoverFrames && reader.offset == 0 {
		<-reader.gate
	}
	payload := publicK5Payload(reader.marker, reader.frame)
	n := copy(buffer, payload[reader.offset:])
	reader.offset += n
	if reader.offset == len(payload) {
		reader.frame++
		reader.offset = 0
		reader.progress.Store(uint64(reader.frame))
	}
	return n, nil
}

type publicK5HashWriter struct {
	hash  hash.Hash
	bytes atomic.Uint64
}

func newPublicK5HashWriter() *publicK5HashWriter {
	return &publicK5HashWriter{hash: sha256.New()}
}

func (writer *publicK5HashWriter) Write(buffer []byte) (int, error) {
	n, err := writer.hash.Write(buffer)
	writer.bytes.Add(uint64(n))
	return n, err
}

func (writer *publicK5HashWriter) sum() string {
	return hex.EncodeToString(writer.hash.Sum(nil))
}

func publicK5Payload(marker byte, sequence int) []byte {
	payload := make([]byte, publicK5GVisorPayloadBytes)
	payload[0] = marker
	binary.BigEndian.PutUint64(payload[1:9], uint64(sequence))
	for index := 9; index < len(payload); index++ {
		payload[index] = marker ^ byte(sequence) ^ byte(index)
	}
	return payload
}

func publicK5PayloadSHA256(marker byte) string {
	hash := sha256.New()
	for sequence := 0; sequence < publicK5GVisorFrames; sequence++ {
		_, _ = hash.Write(publicK5Payload(marker, sequence))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func publicK5Copy(results chan<- publicK5CopyResult, name string, destination io.Writer, source io.Reader) {
	count, err := io.Copy(destination, source)
	results <- publicK5CopyResult{Name: name, Bytes: count, Err: err}
}

func publicK5OwnerCloseState(owner *linkOwner) publicK5OwnerCloseSnapshot {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	committedPeer := uint64(0)
	if owner.committedPeer != nil {
		committedPeer = owner.committedPeer.generation
	}
	return publicK5OwnerCloseSnapshot{
		Closed: owner.closed, Closing: owner.closing, WireFault: owner.wireFault,
		LocalGeneration: owner.localGeneration, PeerGeneration: owner.peerGeneration, CommittedPeer: committedPeer,
		ReplayPackets: len(owner.replayPackets), ReplayBytes: owner.replayBytes, ReplaySequence: owner.replaySequence,
		ReplayActivations: owner.replayActivations, ReplayTransmitted: owner.replayTransmitted, ReplayTXBytes: owner.replayTXBytes,
		ReplayRequestGen: owner.replayRequestGen, ReplayRequestPeer: owner.replayRequestPeer,
		ReplayRequestNext: owner.replayRequestNext, ReplayRequestRuns: owner.replayRequestRuns,
		ReplayExhausted: owner.replayExhausted, ReceiveNext: owner.receiveNext, PeerReceiveNext: owner.peerReceiveNext,
	}
}

func publicK5WaitForCutoverProgress(
	t testing.TB,
	ctx context.Context,
	clientGenerated, serverGenerated *atomic.Uint64,
	clientReceived, serverReceived *publicK5HashWriter,
) {
	t.Helper()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if clientGenerated.Load() == publicK5GVisorCutoverFrames &&
			serverGenerated.Load() == publicK5GVisorCutoverFrames &&
			clientReceived.bytes.Load() > 0 && serverReceived.bytes.Load() > 0 {
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("wait for active public io.Copy cutover: generated=%d/%d received=%d/%d err=%v",
				clientGenerated.Load(), serverGenerated.Load(), clientReceived.bytes.Load(), serverReceived.bytes.Load(), ctx.Err())
		}
	}
}

func publicK5WaitForMigration(t testing.TB, ctx context.Context, events <-chan publicK5MigrationEvent) publicK5MigrationEvent {
	t.Helper()
	select {
	case event := <-events:
		return event
	case <-ctx.Done():
		t.Fatalf("wait for public gVisor leaf-mobility event: %v", ctx.Err())
		return publicK5MigrationEvent{}
	}
}

func publicK5WaitForCommittedStatus(t testing.TB, ctx context.Context, conn rendr.Conn, pathID uint32) {
	t.Helper()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		status := publicK5PathStatus(t, conn.Status(), pathID)
		if status.Mobility.State == rendr.MobilityStateCommitted {
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("wait for public committed mobility status: %+v err=%v", status.Mobility, ctx.Err())
		}
	}
}

func publicK5PathStatus(t testing.TB, status rendr.Status, pathID uint32) rendr.PathStatus {
	t.Helper()
	for _, path := range status.Paths {
		if path.ID == pathID {
			return path
		}
	}
	t.Fatalf("public status has no path %d: %+v", pathID, status.Paths)
	return rendr.PathStatus{}
}

func publicK5PathCounters(t testing.TB, paths []rendr.PathInfo, name string) publicK5PathCounter {
	t.Helper()
	for _, path := range paths {
		if path.Spec.Opts["name"] == name {
			return publicK5PathCounter{Reads: path.Reads, Writes: path.Writes, ControlWrites: path.ControlWrites}
		}
	}
	t.Fatalf("public path inventory has no %q path: %+v", name, paths)
	return publicK5PathCounter{}
}

func publicK5ServerOwner(t testing.TB, listener *Listener, virtualIP [4]byte) *linkOwner {
	t.Helper()
	listener.packetMu.RLock()
	owner := listener.packetByIP[virtualIP]
	listener.packetMu.RUnlock()
	if owner == nil {
		t.Fatalf("packet listener has no server owner for virtual IP %v", virtualIP)
	}
	return owner
}

func publicK5ObjectToken(value any) string {
	reflected := reflect.ValueOf(value)
	if !reflected.IsValid() || reflected.Kind() != reflect.Pointer || reflected.IsNil() {
		return ""
	}
	return fmt.Sprintf("%T@%x", value, reflected.Pointer())
}

func publicK5WaitClosed(t testing.TB, ctx context.Context, closed <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-closed:
	case <-ctx.Done():
		t.Fatalf("%s did not close: %v", label, ctx.Err())
	}
}

func writePublicK5GVisorEvidence(t testing.TB, evidence publicK5GVisorEvidence) {
	t.Helper()
	path := strings.TrimSpace(os.Getenv(publicK5GVisorEvidenceEnv))
	if path == "" {
		return
	}
	nonce := strings.TrimSpace(os.Getenv(publicK5GVisorEvidenceNonce))
	if nonce == "" || len(nonce) > 256 || strings.IndexFunc(nonce, func(r rune) bool { return r < 0x20 }) >= 0 {
		t.Fatalf("%s must be a non-empty printable value of at most 256 bytes", publicK5GVisorEvidenceNonce)
	}
	evidence.Nonce = nonce
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatalf("open public KERNEL-5 gVisor evidence: %v", err)
	}
	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	encodeErr := encoder.Encode(evidence)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(encodeErr, syncErr, closeErr); err != nil {
		t.Fatalf("write public KERNEL-5 gVisor evidence: %v", err)
	}
}

var _ transport.PathFactory = (*publicK5ObservedFactory)(nil)
var _ leafmobility.ImplementationProvider = (*publicK5ObservedFactory)(nil)
var _ transport.PathListener = (*publicK5ResponderListener)(nil)
var _ leafmobility.ImplementationProvider = (*publicK5ResponderListener)(nil)
var _ net.Conn = (*publicK5AppConn)(nil)
