//go:build linux && amd64 && rendr_experimental_gvisor

package gvisor

import (
	"bytes"
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
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
	basetcp "github.com/FrankoonG/rendr/transport/tcp"
)

const (
	publicK5GVisorSchema          = "rendr-gvisor-kernel5-public-app-v3"
	publicK5GVisorFrames          = 2048
	publicK5GVisorPayloadBytes    = 16 << 10
	publicK5GVisorCutoverFrames   = 64
	publicK5PostCommitEpochBytes  = 256 << 10
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

func TestGVisorPublicRuntimeClientPrioritySurvivesServerLivenessLead(t *testing.T) {
	requireOuterPacketSupport(t)
	runPublicRuntimeGVisorBlackholeScenario(t, publicRuntimeGVisorScenario{
		serverLivenessLead: outerLivenessTick / 2,
	})
}

func runPublicRuntimeGVisorBlackhole(t *testing.T) publicK5GVisorEvidence {
	return runPublicRuntimeGVisorBlackholeScenario(t, publicRuntimeGVisorScenario{})
}

type publicRuntimeBlackholeRelay interface {
	Addr() net.Addr
	Close() error
	DropEstablishedClientAt(testing.TB) (string, time.Time)
	PreData() uint64
	PostData() uint64
	ServerPreData() uint64
	ServerPostData() uint64
	ReplacementTuple() string
	TCPSummaries() (tcpPacketSummary, tcpPacketSummary)
}

func (relay *packetBlackholeRelay) DropEstablishedClientAt(t testing.TB) (string, time.Time) {
	t.Helper()
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if relay.client == nil {
		t.Fatal("relay has no established client tuple")
	}
	relay.dropped = cloneUDPAddr(relay.client)
	relay.drop = true
	return relay.dropped.String(), time.Now()
}

type publicRuntimeGVisorScenario struct {
	packetOptions         []PacketOption
	relayFactory          func(testing.TB, net.Addr) publicRuntimeBlackholeRelay
	requireUnacknowledged bool
	requireCrossedActors  bool
	serverLivenessLead    time.Duration
	observation           *publicRuntimeGVisorObservation
}

type publicRuntimeGVisorObservation struct {
	ClientCreatedAtBefore time.Time
	ClientCreatedAtAfter  time.Time
	ServerCreatedAtBefore time.Time
	ServerCreatedAtAfter  time.Time
	ClientTXAtBlackhole   rendr.ReplayStats
	ServerTXAtBlackhole   rendr.ReplayStats
	StatusReason          rendr.MobilityReason
	StatusNegotiated      rendr.MobilityID
	ClientCrossed         rendr.MobilityStatus
	ServerCrossed         rendr.MobilityStatus
	Control               publicK5ControlSummary
	ProductionFactory     bool
	ProductionListener    bool
}

func runPublicRuntimeGVisorBlackholeScenario(t *testing.T, scenario publicRuntimeGVisorScenario) publicK5GVisorEvidence {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	packetOptions := scenario.packetOptions
	if len(packetOptions) == 0 {
		packetOptions = []PacketOption{WithTrustedCarrier()}
	}
	packetListener, err := ListenPacket("127.0.0.1:0", packetOptions...)
	if err != nil {
		t.Fatal(err)
	}
	relayFactory := scenario.relayFactory
	if relayFactory == nil {
		relayFactory = func(t testing.TB, server net.Addr) publicRuntimeBlackholeRelay {
			return newPacketBlackholeRelay(t, server)
		}
	}
	relay := relayFactory(t, packetListener.Addr())
	dataFactory := packetListener.Factory()
	productionFactory := reflect.TypeOf(dataFactory) == reflect.TypeOf((*Transport)(nil))
	productionListener := reflect.TypeOf(packetListener) == reflect.TypeOf((*Listener)(nil))
	for name, value := range map[string]any{"factory": dataFactory, "listener": packetListener} {
		provider, ok := value.(leafmobility.ImplementationProvider)
		if !ok {
			t.Fatalf("production gVisor %s %T has no mobility implementation provider", name, value)
		}
		capabilities, capabilityErr := leafmobility.CapabilitiesForImplementationProvider(provider)
		if capabilityErr != nil || len(capabilities) != 1 ||
			capabilities[0].Operation() != leafmobility.OperationGVisorLinkRebind {
			t.Fatalf("production gVisor %s capabilities=%v err=%v", name, capabilities, capabilityErr)
		}
	}
	if !productionFactory || !productionListener {
		t.Fatalf("T5.6 did not install production gVisor providers factory=%T listener=%T", dataFactory, packetListener)
	}
	observedClientPath := make(chan *retainedPathConn, 1)
	stopObservingClientPath := dataFactory.setPacketPathObserver(func(path *retainedPathConn) {
		select {
		case observedClientPath <- path:
		default:
		}
	})
	defer stopObservingClientPath()

	controlBaseListener, err := basetcp.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		_ = relay.Close()
		_ = packetListener.Close()
		t.Fatal(err)
	}
	controlTrace := &publicK5ControlTrace{}
	if scenario.requireCrossedActors {
		controlTrace.crossedPrepare = newPublicK5CrossedPrepareGate()
	}
	controlListener := &publicK5ControlListener{
		base: controlBaseListener, trace: controlTrace, writer: publicK5ControlServer,
	}

	runtimeConfig := rendr.DefaultRuntimeConfig()
	runtimeConfig.Selector.QualityDwell = 30 * time.Second
	runtimeConfig.Selector.QualityCooldown = 30 * time.Second
	runtimeConfig.Recovery.MigrationBudget = 15 * time.Second
	serverRuntime, err := rendr.NewRuntimeContext(ctx, runtimeConfig)
	if err != nil {
		t.Fatal(err)
	}
	sessionListener, err := serverRuntime.Listen(rendr.ListenConfig{
		Framed: []rendr.FramedSource{
			{Name: publicK5GVisorDataFactoryName, Carrier: rendr.CarrierUDP, Listener: packetListener},
			{Name: publicK5GVisorControlName, Carrier: rendr.CarrierTCP, Listener: controlListener},
		}},
	)
	if err != nil {
		t.Fatal(err)
	}

	clientRuntime, err := rendr.NewRuntimeContext(ctx, runtimeConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := clientRuntime.RegisterFramedFactory(publicK5GVisorDataFactoryName, rendr.FramedFactory{
		Carrier: rendr.CarrierUDP, Factory: dataFactory,
	}); err != nil {
		t.Fatal(err)
	}
	controlFactory := &publicK5ControlFactory{
		base: basetcp.New(), trace: controlTrace, writer: publicK5ControlClient,
	}
	if err := clientRuntime.RegisterFramedFactory(publicK5GVisorControlName, rendr.FramedFactory{
		Carrier: rendr.CarrierTCP, Factory: controlFactory,
	}); err != nil {
		t.Fatal(err)
	}
	root := rendr.Selector("gvisor-public-root", []rendr.Target{
		rendr.Path("gvisor-data", rendr.PathSpec{
			Transport: publicK5GVisorDataFactoryName, Address: relay.Addr().String(),
		}),
		rendr.Path("control", rendr.PathSpec{
			Transport: publicK5GVisorControlName, Address: controlListener.Addr().String(),
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
	publicK5WaitForAttachedPaths(t, ctx, client, []string{"gvisor-data", "control"}, 5*time.Second)
	publicK5WaitForAttachedPaths(t, ctx, server, []string{"gvisor-data", "control"}, 5*time.Second)
	dataPathID := publicK5PathID(t, client.Paths(), "gvisor-data")
	controlPathID := publicK5PathID(t, client.Paths(), "control")
	serverDataPathID := publicK5PathID(t, server.Paths(), "gvisor-data")
	serverControlPathID := publicK5PathID(t, server.Paths(), "control")
	var clientPath *retainedPathConn
	select {
	case clientPath = <-observedClientPath:
	case <-ctx.Done():
		t.Fatalf("observe production Runtime gVisor path: %v", ctx.Err())
	}
	serverOwner := publicK5ServerOwner(t, packetListener, clientPath.link.virtualIP)
	serverClaimBefore := serverOwner.claim.Snapshot()
	serverBinding, serverBound := serverOwner.claim.Binding()
	if !serverBound || serverBinding.PathID == 0 || serverBinding.Owner == 0 || serverClaimBefore.Generation == 0 {
		t.Fatalf("public Runtime server gVisor claim/binding is incomplete: claim=%+v binding=%+v bound=%t",
			serverClaimBefore, serverBinding, serverBound)
	}
	clientCandidateTrace := installPublicK5CandidateTrace(clientPath.link, "client")
	serverCandidateTrace := installPublicK5CandidateTrace(serverOwner, "server")

	clientObserver, ok := client.(rendr.ConnectionObserver)
	if !ok {
		t.Fatalf("public client %T does not implement ConnectionObserver", client)
	}
	serverObserver, ok := server.(rendr.ConnectionObserver)
	if !ok {
		t.Fatalf("public server %T does not implement ConnectionObserver", server)
	}
	clientCreatedAtBefore := clientObserver.Stats().CreatedAt
	serverCreatedAtBefore := serverObserver.Stats().CreatedAt
	if clientCreatedAtBefore.IsZero() || serverCreatedAtBefore.IsZero() {
		t.Fatal("public Runtime returned zero connection CreatedAt")
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
	if binding.PathID != dataPathID || serverBinding.PathID != serverDataPathID {
		t.Fatalf("public Runtime claim/path mismatch client=%+v/%d server=%+v/%d",
			binding, dataPathID, serverBinding, serverDataPathID)
	}
	clientFrozen := publicK5FreezeSelectorPathBindings(
		t, ctx, client, dataPathID, controlPathID, "client",
	)
	serverFrozen := publicK5FreezeSelectorPathBindings(
		t, ctx, server, serverDataPathID, serverControlPathID, "server",
	)
	if clientFrozen.Data.PathOwner != binding.Owner ||
		clientFrozen.Data.EndpointGeneration != claimBefore.Generation ||
		clientFrozen.Data.LocalTargetID != hex.EncodeToString(binding.LocalTargetID[:]) ||
		clientFrozen.Data.PeerTargetID != hex.EncodeToString(binding.PeerTargetID[:]) ||
		serverFrozen.Data.PathOwner != serverBinding.Owner ||
		serverFrozen.Data.EndpointGeneration != serverClaimBefore.Generation ||
		serverFrozen.Data.LocalTargetID != hex.EncodeToString(serverBinding.LocalTargetID[:]) ||
		serverFrozen.Data.PeerTargetID != hex.EncodeToString(serverBinding.PeerTargetID[:]) {
		t.Fatalf("pre-blackhole bindings do not match ownership claims client=%+v claim=%+v server=%+v claim=%+v",
			clientFrozen, binding, serverFrozen, serverBinding)
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

	events := make(chan publicK5MigrationEvent, 8)
	serverEvents := make(chan publicK5MigrationEvent, 8)
	clientMigrationSubscription := clientObserver.OnMigrationEvent(func(event rendr.MigrationEvent) {
		events <- publicK5MigrationEventFromRendr(event)
	})
	defer clientMigrationSubscription.Cancel()
	migrationsBefore := clientMigrationSubscription.AfterOrdinal()
	serverMigrationSubscription := serverObserver.OnMigrationEvent(func(event rendr.MigrationEvent) {
		serverEvents <- publicK5MigrationEventFromRendr(event)
	})
	defer serverMigrationSubscription.Cancel()
	serverMigrationsBefore := serverMigrationSubscription.AfterOrdinal()

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
	var clientTXAtBlackhole, serverTXAtBlackhole rendr.ReplayStats
	if scenario.requireUnacknowledged {
		release()
		clientTXAtBlackhole, serverTXAtBlackhole = publicK5WaitForUnacknowledgedData(
			t, ctx, clientObserver, serverObserver, clientGenerated, serverGenerated,
		)
	}
	clientGeneratedAtBlackhole := clientGenerated.Load() * publicK5GVisorPayloadBytes
	serverGeneratedAtBlackhole := serverGenerated.Load() * publicK5GVisorPayloadBytes
	clientReceivedAtBlackhole := clientReceived.bytes.Load()
	serverReceivedAtBlackhole := serverReceived.bytes.Load()
	outerTupleDropped, blackholeAt := relay.DropEstablishedClientAt(t)
	blackholeUnixNano := blackholeAt.UnixNano()
	if scenario.serverLivenessLead > 0 {
		publicK5SetLivenessLead(clientPath.link, serverOwner, scenario.serverLivenessLead)
	}
	release()
	var clientCrossed, serverCrossed rendr.MobilityStatus
	if scenario.requireCrossedActors {
		controller, ok := relay.(interface{ ReleaseReplacement(testing.TB) })
		if !ok {
			t.Fatalf("crossed-actor treatment relay %T cannot release held replacement tuples", relay)
		}
		clientCrossed, serverCrossed = publicK5WaitForCrossedInitiators(t, ctx, client, server)
		controller.ReleaseReplacement(t)
	}

	var event publicK5MigrationEvent
	migrationEvents := make([]publicK5MigrationEvent, 0, 4)
	for {
		event = publicK5WaitForMigration(t, ctx, events, func() string {
			return fmt.Sprintf(
				"client_status=%+v server_status=%+v client_owner=%s server_owner=%s client_candidates=%v server_candidates=%v relay_pre/post=%d/%d server_pre/post=%d/%d replacement=%q",
				client.Status(), server.Status(), publicK5OuterWireInventory(clientPath.link),
				publicK5OuterWireInventory(serverOwner), clientCandidateTrace.snapshot(), serverCandidateTrace.snapshot(),
				relay.PreData(), relay.PostData(), relay.ServerPreData(), relay.ServerPostData(), relay.ReplacementTuple(),
			)
		})
		migrationEvents = append(migrationEvents, event)
		if event.OldID == binding.PathID && event.NewID == binding.PathID && event.Cause == "leaf-mobility" {
			break
		}
		if len(migrationEvents) >= cap(migrationEvents) {
			clientPath.link.mu.Lock()
			linkFault, linkClosed, linkGeneration := clientPath.link.wireFault, clientPath.link.closed, clientPath.link.localGeneration
			clientPath.link.mu.Unlock()
			t.Fatalf("public gVisor leaf-mobility event absent after migrations=%+v binding=%+v status=%+v link fault/closed/generation=%t/%t/%d",
				migrationEvents, binding, client.Status(), linkFault, linkClosed, linkGeneration)
		}
	}
	if len(migrationEvents) > 1 {
		t.Logf("public gVisor rebind followed earlier migration events: %+v", migrationEvents[:len(migrationEvents)-1])
	}
	recoveryDuration := time.Duration(event.AtUnixNano - blackholeUnixNano)
	if event.CommittedAt.IsZero() || recoveryDuration <= 0 || recoveryDuration > publicK5GVisorRecoveryLimit {
		t.Fatalf("public gVisor rebind elapsed=%v", recoveryDuration)
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
	migrationEvents = publicK5DrainMigrationLedger(
		t, clientObserver, migrationsBefore, events, migrationEvents, "client",
	)
	serverMigrationEvents := publicK5DrainMigrationLedger(
		t, serverObserver, serverMigrationsBefore, serverEvents, nil, "server",
	)
	automaticMigrationCountAfter := clientObserver.MigrationCount()
	automaticServerMigrationCountAfter := serverObserver.MigrationCount()
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
	serverOuterTupleAfter := observedOuterLocalTuple(t, serverOwner)
	serverOwner.mu.Lock()
	serverPeerAfter := serverOwner.peerRemote.String()
	committedPeer := serverOwner.committedPeer
	serverOwner.mu.Unlock()
	if committedPeer == nil {
		t.Fatal("server packet-link owner has no committed peer transaction")
	}
	transactionID := hex.EncodeToString(committedPeer.control.Transaction[:])
	agreementDigest := hex.EncodeToString(committedPeer.control.Agreement[:])
	winnerTransaction := [16]byte(committedPeer.control.Transaction)
	winnerAgreement := [32]byte(committedPeer.control.Agreement)
	if statusAfter.Mobility.TransactionID != winnerTransaction {
		t.Fatalf("public mobility status transaction=%x owner transaction=%x",
			statusAfter.Mobility.TransactionID, winnerTransaction)
	}
	controlSummary := controlTrace.summarize(winnerTransaction, winnerAgreement)
	winnerPrepare, winnerPrepareOK := controlTrace.winningPrepare(winnerTransaction)
	if !winnerPrepareOK || winnerPrepare.TransactionID != winnerTransaction ||
		winnerPrepare.ActorEndpointGeneration != claimBefore.Generation {
		t.Fatalf("winning PREPARE is not bound to the source claim: prepare=%+v winner=%x claim=%+v",
			winnerPrepare, winnerTransaction, claimBefore)
	}
	genericFailovers, genericFailoverCause := publicK5ValidateMigrationEvents(
		t, migrationEvents, publicK5MigrationExpectation{
			Baseline: migrationsBefore, DataPathID: binding.PathID, FallbackPathID: controlPathID,
			PathOwner: binding.Owner, SourceEndpointGeneration: claimBefore.Generation,
			LocalTargetID:             hex.EncodeToString(binding.LocalTargetID[:]),
			PeerTargetID:              hex.EncodeToString(binding.PeerTargetID[:]),
			ResultEndpointGeneration:  claimAfter.Generation,
			RefreshEvidenceGeneration: statusAfter.Mobility.EvidenceGeneration,
			WinningTransaction:        winnerTransaction, BlackholeAt: blackholeAt,
			SpecializedAt:         event.CommittedAt,
			DataBindingBefore:     clientFrozen.Data,
			FallbackBindingBefore: clientFrozen.Control,
			RefreshIncarnation:    clientIncarnationBefore,
		},
	)
	serverGenericFailovers, serverGenericFailoverCause := publicK5ValidateResponderMigrationEvents(
		t, serverMigrationEvents, publicK5MigrationExpectation{
			Baseline: serverMigrationsBefore, DataPathID: serverDataPathID, FallbackPathID: serverControlPathID,
			PathOwner: serverBinding.Owner, SourceEndpointGeneration: serverClaimBefore.Generation,
			LocalTargetID:         hex.EncodeToString(serverBinding.LocalTargetID[:]),
			PeerTargetID:          hex.EncodeToString(serverBinding.PeerTargetID[:]),
			BlackholeAt:           blackholeAt,
			SpecializedAt:         event.CommittedAt,
			DataBindingBefore:     serverFrozen.Data,
			FallbackBindingBefore: serverFrozen.Control,
		},
	)
	if scenario.requireCrossedActors {
		if clientCrossed.TransactionID == ([16]byte{}) || serverCrossed.TransactionID == ([16]byte{}) ||
			clientCrossed.TransactionID == serverCrossed.TransactionID ||
			controlSummary.CrossedClientTransaction != winnerTransaction ||
			controlSummary.CrossedServerTransaction == ([16]byte{}) ||
			controlSummary.CrossedServerTransaction == winnerTransaction {
			t.Fatalf("production crossed arbitration status=%x/%x wire=%x/%x winner=%x",
				clientCrossed.TransactionID, serverCrossed.TransactionID,
				controlSummary.CrossedClientTransaction, controlSummary.CrossedServerTransaction,
				winnerTransaction)
		}
		if !controlSummary.valid() {
			t.Fatalf("sibling control path lacks exact winning/crossed transaction frames: %+v writes=%+v",
				controlSummary, controlTrace.snapshot())
		}
	}

	clientControlAfter := publicK5PathCounters(t, client.Paths(), "control")
	serverControlAfter := publicK5PathCounters(t, server.Paths(), "control")
	if clientControlAfter.ControlWrites <= clientControlBefore.ControlWrites ||
		serverControlAfter.ControlWrites <= serverControlBefore.ControlWrites {
		t.Fatalf("sibling control route did not carry bilateral transaction client=%+v/%+v server=%+v/%+v",
			clientControlBefore, clientControlAfter, serverControlBefore, serverControlAfter)
	}
	if genericFailovers == 1 && clientControlAfter.DataWrites <= clientControlBefore.DataWrites {
		t.Fatalf("generic selector fallback did not dispatch DATA on sibling: before=%+v after=%+v",
			clientControlBefore, clientControlAfter)
	}
	if genericFailovers == 0 && clientControlAfter.DataWrites != clientControlBefore.DataWrites {
		t.Fatalf("sibling carried DATA without a committed selector fallback: before=%+v after=%+v",
			clientControlBefore, clientControlAfter)
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
		t.Fatalf("outer packet link did not change in place: link=%x/%x wire=%p/%p tuple=%s/%s/%s replacement=%s server-local=%s client-owner=%s server-owner=%s client-status=%+v server-status=%+v client-candidates=%v server-candidates=%v",
			clientLinkBefore, clientLinkAfter, clientWireBefore, clientWireAfter,
			outerTupleBefore, outerTupleDropped, outerTupleAfter, relay.ReplacementTuple(), serverOuterTupleAfter,
			publicK5OuterWireInventory(clientPath.link), publicK5OuterWireInventory(serverOwner),
			client.Status(), server.Status(), clientCandidateTrace.snapshot(), serverCandidateTrace.snapshot())
	}
	if claimAfter.ResourceID != claimBefore.ResourceID || claimAfter.Generation <= claimBefore.Generation ||
		clientClaim.ExecutionGeneration() != claimExecutionBefore+1 ||
		clientIncarnationAfter <= clientIncarnationBefore || clientOuterGenerationAfter != clientOuterGenerationBefore+1 {
		t.Fatalf("ownership generation before=%+v/%d/%d/%d after=%+v/%d/%d/%d client_status=%+v server_status=%+v control=%+v client_candidates=%v server_candidates=%v",
			claimBefore, claimExecutionBefore, clientIncarnationBefore, clientOuterGenerationBefore,
			claimAfter, clientClaim.ExecutionGeneration(), clientIncarnationAfter, clientOuterGenerationAfter,
			client.Status(), server.Status(),
			controlSummary, clientCandidateTrace.snapshot(), serverCandidateTrace.snapshot())
	}
	if statusAfter.Mobility.ID != rendr.MobilityGVisorPacketLinkRebind ||
		statusAfter.Mobility.State != rendr.MobilityStateCommitted ||
		statusAfter.Mobility.EndpointGeneration != claimAfter.Generation || statusAfter.Mobility.EvidenceGeneration == 0 {
		t.Fatalf("public mobility status=%+v claim=%+v", statusAfter.Mobility, claimAfter)
	}
	if scenario.observation != nil && (statusAfter.Mobility.Reason != rendr.MobilityReasonLinkUnresponsive ||
		statusAfter.Mobility.Negotiated != rendr.MobilityGVisorPacketLinkRebind) {
		t.Fatalf("T5.6 public mobility reason/negotiation=%+v", statusAfter.Mobility)
	}
	if clientObserver.MigrationCount() < migrationsBefore+1 ||
		clientObserver.MigrationCount() != migrationsBefore+uint64(len(migrationEvents)) ||
		serverObserver.MigrationCount() != serverMigrationsBefore+uint64(len(serverMigrationEvents)) {
		t.Fatalf("public migration counts client=%d/%d events=%+v server=%d/%d events=%+v", migrationsBefore,
			clientObserver.MigrationCount(), migrationEvents, serverMigrationsBefore,
			serverObserver.MigrationCount(), serverMigrationEvents)
	}
	postCommitData := publicK5RunPostCommitDataEpoch(
		t, ctx, appClient, appServer, client, server, clientObserver, serverObserver,
		relay, controlTrace, events, serverEvents, event.CommittedAt,
		automaticMigrationCountAfter, automaticServerMigrationCountAfter,
	)

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
	if err := relay.Close(); err != nil {
		t.Fatalf("close public blackhole relay: %v", err)
	}
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
	clientCreatedAtAfter := clientObserver.Stats().CreatedAt
	serverCreatedAtAfter := serverObserver.Stats().CreatedAt
	if scenario.requireCrossedActors && !controlSummary.valid() {
		fresh := controlTrace.summarize(winnerTransaction, winnerAgreement)
		t.Fatalf("crossed transaction emitted a contradictory late control frame: summary=%+v writes=%+v",
			fresh, controlTrace.snapshot())
	}
	if scenario.observation != nil {
		scenario.observation.ClientCreatedAtBefore = clientCreatedAtBefore
		scenario.observation.ClientCreatedAtAfter = clientCreatedAtAfter
		scenario.observation.ServerCreatedAtBefore = serverCreatedAtBefore
		scenario.observation.ServerCreatedAtAfter = serverCreatedAtAfter
		scenario.observation.ClientTXAtBlackhole = clientTXAtBlackhole
		scenario.observation.ServerTXAtBlackhole = serverTXAtBlackhole
		scenario.observation.StatusReason = statusAfter.Mobility.Reason
		scenario.observation.StatusNegotiated = statusAfter.Mobility.Negotiated
		scenario.observation.ClientCrossed = clientCrossed
		scenario.observation.ServerCrossed = serverCrossed
		scenario.observation.Control = controlSummary
		scenario.observation.ProductionFactory = productionFactory
		scenario.observation.ProductionListener = productionListener
	}
	if err := clientMigrationSubscription.Err(); err != nil {
		t.Fatalf("client migration event subscription ended with %v", err)
	}
	if err := serverMigrationSubscription.Err(); err != nil {
		t.Fatalf("server migration event subscription ended with %v", err)
	}

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
		PathID: binding.PathID, PathOwner: binding.Owner, ControlPathID: controlPathID,
		ServerDataPathID: serverDataPathID, ServerPathOwner: serverBinding.Owner,
		ServerControlPathID:        serverControlPathID,
		ClientDataBindingBefore:    clientFrozen.Data,
		ClientControlBindingBefore: clientFrozen.Control,
		ServerDataBindingBefore:    serverFrozen.Data,
		ServerControlBindingBefore: serverFrozen.Control,
		MigrationCountBefore:       migrationsBefore, MigrationCountAfter: automaticMigrationCountAfter,
		MigrationEventCount: uint64(len(migrationEvents)), GenericFailoverEvents: uint64(genericFailovers),
		GenericFailoverCause:        genericFailoverCause,
		ServerMigrationCountBefore:  serverMigrationsBefore,
		ServerMigrationCountAfter:   automaticServerMigrationCountAfter,
		ServerGenericFailoverEvents: uint64(serverGenericFailovers),
		ServerGenericFailoverCause:  serverGenericFailoverCause,
		ClientMigrationEvents:       migrationEvents,
		ServerMigrationEvents:       serverMigrationEvents,
		MigrationOldPathID:          event.OldID, MigrationNewPathID: event.NewID,
		MigrationCause: event.Cause, BlackholeUnixNano: blackholeUnixNano, MigrationUnixNano: event.AtUnixNano,
		RecoveryNanoseconds: recoveryDuration.Nanoseconds(),
		StatusMobilityID:    string(statusAfter.Mobility.ID), StatusMobilityState: string(statusAfter.Mobility.State),
		StatusTransactionID:       hex.EncodeToString(statusAfter.Mobility.TransactionID[:]),
		StatusEndpointGeneration:  statusAfter.Mobility.EndpointGeneration,
		StatusEvidenceGeneration:  statusAfter.Mobility.EvidenceGeneration,
		ProductionFactoryProvider: productionFactory, ProductionListenerProvider: productionListener,
		ResponderInitiatorSuppressed: false,
		ClientCrossedTransactionID:   hex.EncodeToString(controlSummary.CrossedClientTransaction[:]),
		ServerCrossedTransactionID:   hex.EncodeToString(controlSummary.CrossedServerTransaction[:]),
		Control:                      controlSummary,
		ClaimKind:                    uint8(claimBefore.Kind), ClaimRole: uint8(claimBefore.Role), ClaimScope: uint8(claimBefore.Scope),
		ClaimSession: uint8(claimBefore.Session), ClaimOperations: uint8(claimBefore.Operations),
		ClaimResourceIDBefore: fmt.Sprintf("%x", claimBefore.ResourceID), ClaimResourceIDAfter: fmt.Sprintf("%x", claimAfter.ResourceID),
		ClaimEndpointGenerationBefore: claimBefore.Generation, ClaimEndpointGenerationAfter: claimAfter.Generation,
		ServerClaimEndpointGenerationBefore: serverClaimBefore.Generation,
		ClaimExecutionGenerationBefore:      claimExecutionBefore, ClaimExecutionGenerationAfter: clientClaim.ExecutionGeneration(),
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
		PostCommitData:     postCommitData,
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

func publicK5SetLivenessLead(client, server *linkOwner, lead time.Duration) {
	if client == nil || server == nil || lead <= 0 {
		return
	}
	now := time.Now()
	client.mu.Lock()
	clear(client.livenessPending)
	client.livenessLastAck = now
	client.livenessLastProbe = now
	client.mu.Unlock()
	server.mu.Lock()
	clear(server.livenessPending)
	server.livenessLastAck = now.Add(-lead)
	server.livenessLastProbe = now
	server.mu.Unlock()
}

func publicK5RunPostCommitDataEpoch(
	t testing.TB,
	ctx context.Context,
	appClient, appServer *publicK5AppConn,
	client, server rendr.Conn,
	clientObserver, serverObserver rendr.ConnectionObserver,
	relay publicRuntimeBlackholeRelay,
	controlTrace *publicK5ControlTrace,
	clientEvents, serverEvents <-chan publicK5MigrationEvent,
	automaticCommitAt time.Time,
	automaticClientMigrationCount, automaticServerMigrationCount uint64,
) publicK5PostCommitDataEpoch {
	t.Helper()
	clientController, ok := client.(rendr.MigrationController)
	if !ok {
		t.Fatalf("public client %T has no selector controller for post-commit DATA verification", client)
	}
	serverController, ok := server.(rendr.MigrationController)
	if !ok {
		t.Fatalf("public server %T has no selector controller for post-commit DATA verification", server)
	}
	clientDataPathID := publicK5PathID(t, client.Paths(), "gvisor-data")
	serverDataPathID := publicK5PathID(t, server.Paths(), "gvisor-data")
	startedAt := time.Now()
	epoch := publicK5PostCommitDataEpoch{
		StartedUnixNano: startedAt.UnixNano(), SelectTargetCalls: 2,
		ClientActiveBefore: clientObserver.ActivePath(), ServerActiveBefore: serverObserver.ActivePath(),
		ClientDataPathID: clientDataPathID, ServerDataPathID: serverDataPathID,
		ClientMigrationBefore: clientObserver.MigrationCount(), ServerMigrationBefore: serverObserver.MigrationCount(),
	}
	if automaticCommitAt.IsZero() || !startedAt.After(automaticCommitAt) {
		t.Fatalf("post-commit DATA epoch started before automatic repair: start=%v repair=%v",
			startedAt, automaticCommitAt)
	}
	if epoch.ClientMigrationBefore != automaticClientMigrationCount ||
		epoch.ServerMigrationBefore != automaticServerMigrationCount {
		t.Fatalf("migration committed between automatic ledger and post-commit epoch: client=%d/%d server=%d/%d",
			epoch.ClientMigrationBefore, automaticClientMigrationCount,
			epoch.ServerMigrationBefore, automaticServerMigrationCount)
	}
	if err := clientController.SelectTarget("gvisor-public-root", "gvisor-data"); err != nil {
		t.Fatalf("project repaired client leaf for post-commit DATA verification: %v", err)
	}
	clientChanged := epoch.ClientActiveBefore != clientDataPathID
	if err := serverController.SelectTarget("gvisor-public-root", "gvisor-data"); err != nil {
		t.Fatalf("project repaired server leaf for post-commit DATA verification: %v", err)
	}
	serverChanged := epoch.ServerActiveBefore != serverDataPathID
	publicK5WaitForActivePath(t, ctx, client, clientObserver, "gvisor-data", clientDataPathID)
	publicK5WaitForActivePath(t, ctx, server, serverObserver, "gvisor-data", serverDataPathID)
	epoch.ClientActiveAfter = clientObserver.ActivePath()
	epoch.ServerActiveAfter = serverObserver.ActivePath()
	epoch.ClientMigrationAfter = clientObserver.MigrationCount()
	epoch.ServerMigrationAfter = serverObserver.MigrationCount()
	clientDelta := epoch.ClientMigrationAfter - epoch.ClientMigrationBefore
	serverDelta := epoch.ServerMigrationAfter - epoch.ServerMigrationBefore
	if clientDelta != boolUint64(clientChanged) || serverDelta != boolUint64(serverChanged) {
		t.Fatalf("post-commit selector migration deltas client=%d server=%d active-before=%d/%d data=%d/%d",
			clientDelta, serverDelta, epoch.ClientActiveBefore, epoch.ServerActiveBefore,
			clientDataPathID, serverDataPathID)
	}
	epoch.ClientSelectionEvents = publicK5DrainMigrationLedger(
		t, clientObserver, epoch.ClientMigrationBefore, clientEvents, nil, "post-commit client",
	)
	epoch.ServerSelectionEvents = publicK5DrainMigrationLedger(
		t, serverObserver, epoch.ServerMigrationBefore, serverEvents, nil, "post-commit server",
	)
	publicK5ValidateExplicitProjectionLedger(
		t, epoch.ClientSelectionEvents, epoch.ClientMigrationBefore,
		epoch.ClientActiveBefore, clientDataPathID, clientChanged, "client",
	)
	publicK5ValidateExplicitProjectionLedger(
		t, epoch.ServerSelectionEvents, epoch.ServerMigrationBefore,
		epoch.ServerActiveBefore, serverDataPathID, serverChanged, "server",
	)
	publicK5WaitForReplayDrain(t, ctx, clientObserver, serverObserver)
	clientReplayAtStart := clientObserver.Stats().TXReplay
	serverReplayAtStart := serverObserver.Stats().TXReplay
	epoch.ClientPublishedNext = clientReplayAtStart.PublishedNext
	epoch.ServerPublishedNext = serverReplayAtStart.PublishedNext
	controlDataBefore := controlTrace.dataSnapshot()

	clientTCPBefore, serverTCPBefore := relay.TCPSummaries()
	epoch.ClientOuterDataBefore = relay.PostData()
	epoch.ServerOuterDataBefore = relay.ServerPostData()
	epoch.ClientInnerPayloadBefore = clientTCPBefore.postPayloadBytes
	epoch.ServerInnerPayloadBefore = serverTCPBefore.postPayloadBytes
	clientControlBefore := publicK5PathCounters(t, client.Paths(), "control")
	serverControlBefore := publicK5PathCounters(t, server.Paths(), "control")
	epoch.ClientControlDataBefore = clientControlBefore.DataWrites
	epoch.ServerControlDataBefore = serverControlBefore.DataWrites

	clientPayload := bytes.Repeat([]byte{0xa6, 0x51, 0x39, 0xc7}, publicK5PostCommitEpochBytes/4)
	serverPayload := bytes.Repeat([]byte{0x5a, 0xce, 0x83, 0x14}, publicK5PostCommitEpochBytes/4)
	clientReceived := newPublicK5HashWriter()
	serverReceived := newPublicK5HashWriter()
	results := make(chan publicK5CopyResult, 4)
	go publicK5Copy(results, "post-client-write", appClient, bytes.NewReader(clientPayload))
	go publicK5Copy(results, "post-server-read", serverReceived, io.LimitReader(appServer, int64(len(clientPayload))))
	go publicK5Copy(results, "post-server-write", appServer, bytes.NewReader(serverPayload))
	go publicK5Copy(results, "post-client-read", clientReceived, io.LimitReader(appClient, int64(len(serverPayload))))
	completed := make(map[string]publicK5CopyResult, 4)
	for range 4 {
		select {
		case result := <-results:
			completed[result.Name] = result
		case <-ctx.Done():
			t.Fatalf("post-commit DATA epoch timed out: %v", ctx.Err())
		}
	}
	for _, name := range []string{"post-client-write", "post-server-read", "post-server-write", "post-client-read"} {
		result, exists := completed[name]
		if !exists || result.Err != nil || result.Bytes != publicK5PostCommitEpochBytes {
			t.Fatalf("post-commit DATA operation %s=%+v exists=%t", name, result, exists)
		}
	}
	publicK5WaitForReplayDrain(t, ctx, clientObserver, serverObserver)
	epoch.ClientActiveFinal = clientObserver.ActivePath()
	epoch.ServerActiveFinal = serverObserver.ActivePath()
	epoch.ClientMigrationFinal = clientObserver.MigrationCount()
	epoch.ServerMigrationFinal = serverObserver.MigrationCount()

	clientTCPAfter, serverTCPAfter := relay.TCPSummaries()
	epoch.ClientOuterDataAfter = relay.PostData()
	epoch.ServerOuterDataAfter = relay.ServerPostData()
	epoch.ClientInnerPayloadAfter = clientTCPAfter.postPayloadBytes
	epoch.ServerInnerPayloadAfter = serverTCPAfter.postPayloadBytes
	clientControlAfter := publicK5PathCounters(t, client.Paths(), "control")
	serverControlAfter := publicK5PathCounters(t, server.Paths(), "control")
	controlDataAfter := controlTrace.dataSnapshot()
	epoch.ClientControlEpochSequences, epoch.ServerControlEpochSequences = publicK5ControlDataSequencesSince(
		controlDataBefore, controlDataAfter,
	)
	epoch.ClientControlDataAfter = clientControlAfter.DataWrites
	epoch.ServerControlDataAfter = serverControlAfter.DataWrites
	epoch.ClientOfferedBytes = uint64(len(clientPayload))
	epoch.ClientReceivedBytes = serverReceived.bytes.Load()
	epoch.ServerOfferedBytes = uint64(len(serverPayload))
	epoch.ServerReceivedBytes = clientReceived.bytes.Load()
	clientHash := sha256.Sum256(clientPayload)
	serverHash := sha256.Sum256(serverPayload)
	epoch.ClientOfferedSHA256 = hex.EncodeToString(clientHash[:])
	epoch.ClientReceivedSHA256 = serverReceived.sum()
	epoch.ServerOfferedSHA256 = hex.EncodeToString(serverHash[:])
	epoch.ServerReceivedSHA256 = clientReceived.sum()

	if epoch.ClientOuterDataAfter <= epoch.ClientOuterDataBefore ||
		epoch.ServerOuterDataAfter <= epoch.ServerOuterDataBefore ||
		epoch.ClientInnerPayloadAfter-epoch.ClientInnerPayloadBefore < epoch.ClientOfferedBytes ||
		epoch.ServerInnerPayloadAfter-epoch.ServerInnerPayloadBefore < epoch.ServerOfferedBytes {
		t.Fatalf("post-commit replacement tuple lacked DATA payload: %+v client-tcp=%+v/%+v server-tcp=%+v/%+v",
			epoch, clientTCPBefore, clientTCPAfter, serverTCPBefore, serverTCPAfter)
	}
	if epoch.ClientControlDataAfter != epoch.ClientControlDataBefore ||
		epoch.ServerControlDataAfter != epoch.ServerControlDataBefore {
		t.Fatalf("post-commit DATA escaped onto sibling TCP path client=%d/%d server=%d/%d published=%d/%d sequences=%v/%v active=%d/%d->%d/%d migrations=%d/%d->%d/%d",
			epoch.ClientControlDataBefore, epoch.ClientControlDataAfter,
			epoch.ServerControlDataBefore, epoch.ServerControlDataAfter,
			epoch.ClientPublishedNext, epoch.ServerPublishedNext,
			epoch.ClientControlEpochSequences, epoch.ServerControlEpochSequences,
			epoch.ClientActiveAfter, epoch.ServerActiveAfter, epoch.ClientActiveFinal, epoch.ServerActiveFinal,
			epoch.ClientMigrationAfter, epoch.ServerMigrationAfter,
			epoch.ClientMigrationFinal, epoch.ServerMigrationFinal)
	}
	if epoch.ClientActiveFinal != clientDataPathID || epoch.ServerActiveFinal != serverDataPathID ||
		epoch.ClientMigrationFinal != epoch.ClientMigrationAfter ||
		epoch.ServerMigrationFinal != epoch.ServerMigrationAfter {
		t.Fatalf("post-commit repaired leaf did not remain projected client=%d/%d server=%d/%d migrations=%d/%d->%d/%d",
			epoch.ClientActiveAfter, epoch.ClientActiveFinal,
			epoch.ServerActiveAfter, epoch.ServerActiveFinal,
			epoch.ClientMigrationAfter, epoch.ServerMigrationAfter,
			epoch.ClientMigrationFinal, epoch.ServerMigrationFinal)
	}
	if len(epoch.ClientControlEpochSequences) != 0 || len(epoch.ServerControlEpochSequences) != 0 {
		t.Fatalf("post-commit sibling observed DATA sequences client=%v server=%v",
			epoch.ClientControlEpochSequences, epoch.ServerControlEpochSequences)
	}
	if epoch.ClientReceivedBytes != epoch.ClientOfferedBytes || epoch.ServerReceivedBytes != epoch.ServerOfferedBytes ||
		epoch.ClientReceivedSHA256 != epoch.ClientOfferedSHA256 ||
		epoch.ServerReceivedSHA256 != epoch.ServerOfferedSHA256 {
		t.Fatalf("post-commit DATA integrity failed: %+v", epoch)
	}
	return epoch
}

func publicK5WaitForActivePath(
	t testing.TB,
	ctx context.Context,
	conn rendr.Conn,
	observer rendr.ConnectionObserver,
	name string,
	pathID uint32,
) {
	t.Helper()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		activeStatus := false
		for _, path := range conn.Status().Paths {
			if path.ID == pathID && path.Name == name && path.Active && path.State == rendr.PathAttached {
				activeStatus = true
				break
			}
		}
		if activeStatus && observer.ActivePath() == pathID {
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("wait for active path %q/%d: status=%+v active=%d err=%v",
				name, pathID, conn.Status(), observer.ActivePath(), ctx.Err())
		}
	}
}

func publicK5WaitForReplayDrain(
	t testing.TB,
	ctx context.Context,
	client, server rendr.ConnectionObserver,
) {
	t.Helper()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		clientReplay := client.Stats().TXReplay
		serverReplay := server.Stats().TXReplay
		if clientReplay.FramesInUse == 0 && clientReplay.BytesInUse == 0 &&
			serverReplay.FramesInUse == 0 && serverReplay.BytesInUse == 0 {
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("wait for post-commit replay drain client=%+v server=%+v err=%v",
				clientReplay, serverReplay, ctx.Err())
		}
	}
}

func boolUint64(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}

func publicK5WaitForUnacknowledgedData(
	t testing.TB,
	ctx context.Context,
	client, server rendr.ConnectionObserver,
	clientGenerated, serverGenerated *atomic.Uint64,
) (rendr.ReplayStats, rendr.ReplayStats) {
	t.Helper()
	ticker := time.NewTicker(100 * time.Microsecond)
	defer ticker.Stop()
	for {
		clientStats := client.Stats()
		serverStats := server.Stats()
		clientFrames := clientGenerated.Load()
		serverFrames := serverGenerated.Load()
		if clientFrames > publicK5GVisorCutoverFrames && serverFrames > publicK5GVisorCutoverFrames &&
			clientFrames < publicK5GVisorFrames && serverFrames < publicK5GVisorFrames &&
			clientStats.TXReplay.FramesInUse > 0 && clientStats.TXReplay.BytesInUse > 0 &&
			serverStats.TXReplay.FramesInUse > 0 && serverStats.TXReplay.BytesInUse > 0 {
			return clientStats.TXReplay, serverStats.TXReplay
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("wait for active unacknowledged T5.6 data: generated=%d/%d client=%+v server=%+v err=%v",
				clientFrames, serverFrames, clientStats.TXReplay, serverStats.TXReplay, ctx.Err())
			return rendr.ReplayStats{}, rendr.ReplayStats{}
		}
	}
}

type publicK5GVisorEvidence struct {
	Schema string `json:"schema"`
	Nonce  string `json:"nonce"`
	Test   string `json:"test"`

	RuntimeClientObjectBefore  string                       `json:"runtime_client_object_before"`
	RuntimeClientObjectAfter   string                       `json:"runtime_client_object_after"`
	RuntimeServerObjectBefore  string                       `json:"runtime_server_object_before"`
	RuntimeServerObjectAfter   string                       `json:"runtime_server_object_after"`
	AppClientObjectBefore      string                       `json:"app_client_object_before"`
	AppClientObjectAfter       string                       `json:"app_client_object_after"`
	AppServerObjectBefore      string                       `json:"app_server_object_before"`
	AppServerObjectAfter       string                       `json:"app_server_object_after"`
	FlowIDBefore               string                       `json:"flow_id_before"`
	FlowIDAfter                string                       `json:"flow_id_after"`
	PeerFlowID                 string                       `json:"peer_flow_id"`
	LocalAddrBefore            string                       `json:"local_addr_before"`
	LocalAddrAfter             string                       `json:"local_addr_after"`
	RemoteAddrBefore           string                       `json:"remote_addr_before"`
	RemoteAddrAfter            string                       `json:"remote_addr_after"`
	PathID                     uint32                       `json:"path_id"`
	PathOwner                  uint64                       `json:"path_owner"`
	ControlPathID              uint32                       `json:"control_path_id"`
	ServerDataPathID           uint32                       `json:"server_data_path_id"`
	ServerPathOwner            uint64                       `json:"server_path_owner"`
	ServerControlPathID        uint32                       `json:"server_control_path_id"`
	ClientDataBindingBefore    publicK5MigrationPathBinding `json:"client_data_binding_before"`
	ClientControlBindingBefore publicK5MigrationPathBinding `json:"client_control_binding_before"`
	ServerDataBindingBefore    publicK5MigrationPathBinding `json:"server_data_binding_before"`
	ServerControlBindingBefore publicK5MigrationPathBinding `json:"server_control_binding_before"`

	MigrationCountBefore        uint64                   `json:"migration_count_before"`
	MigrationCountAfter         uint64                   `json:"migration_count_after"`
	MigrationEventCount         uint64                   `json:"migration_event_count"`
	GenericFailoverEvents       uint64                   `json:"generic_failover_events"`
	GenericFailoverCause        string                   `json:"-"`
	MigrationOldPathID          uint32                   `json:"migration_old_path_id"`
	MigrationNewPathID          uint32                   `json:"migration_new_path_id"`
	MigrationCause              string                   `json:"migration_cause"`
	BlackholeUnixNano           int64                    `json:"blackhole_unix_nano"`
	MigrationUnixNano           int64                    `json:"migration_unix_nano"`
	RecoveryNanoseconds         int64                    `json:"recovery_nanoseconds"`
	ServerMigrationCountBefore  uint64                   `json:"server_migration_count_before"`
	ServerMigrationCountAfter   uint64                   `json:"server_migration_count_after"`
	ServerGenericFailoverEvents uint64                   `json:"server_generic_failover_events"`
	ServerGenericFailoverCause  string                   `json:"-"`
	ClientMigrationEvents       []publicK5MigrationEvent `json:"client_migration_events"`
	ServerMigrationEvents       []publicK5MigrationEvent `json:"server_migration_events"`

	StatusMobilityID                    string                 `json:"status_mobility_id"`
	StatusMobilityState                 string                 `json:"status_mobility_state"`
	StatusTransactionID                 string                 `json:"status_transaction_id"`
	StatusEndpointGeneration            uint64                 `json:"status_endpoint_generation"`
	StatusEvidenceGeneration            uint64                 `json:"status_evidence_generation"`
	ProductionFactoryProvider           bool                   `json:"production_factory_provider"`
	ProductionListenerProvider          bool                   `json:"production_listener_provider"`
	ResponderInitiatorSuppressed        bool                   `json:"responder_initiator_suppressed"`
	ClientCrossedTransactionID          string                 `json:"client_crossed_transaction_id,omitempty"`
	ServerCrossedTransactionID          string                 `json:"server_crossed_transaction_id,omitempty"`
	Control                             publicK5ControlSummary `json:"control"`
	ClaimKind                           uint8                  `json:"claim_kind"`
	ClaimRole                           uint8                  `json:"claim_role"`
	ClaimScope                          uint8                  `json:"claim_scope"`
	ClaimSession                        uint8                  `json:"claim_session"`
	ClaimOperations                     uint8                  `json:"claim_operations"`
	ClaimResourceIDBefore               string                 `json:"claim_resource_id_before"`
	ClaimResourceIDAfter                string                 `json:"claim_resource_id_after"`
	ClaimEndpointGenerationBefore       uint64                 `json:"claim_endpoint_generation_before"`
	ClaimEndpointGenerationAfter        uint64                 `json:"claim_endpoint_generation_after"`
	ServerClaimEndpointGenerationBefore uint64                 `json:"server_claim_endpoint_generation_before"`
	ClaimExecutionGenerationBefore      uint64                 `json:"claim_execution_generation_before"`
	ClaimExecutionGenerationAfter       uint64                 `json:"claim_execution_generation_after"`
	ClaimBindingFlowID                  string                 `json:"claim_binding_flow_id"`
	ClaimBindingLocalTargetID           string                 `json:"claim_binding_local_target_id"`
	ClaimBindingPeerTargetID            string                 `json:"claim_binding_peer_target_id"`
	ClaimBindingPathID                  uint32                 `json:"claim_binding_path_id"`
	ClaimBindingOwner                   uint64                 `json:"claim_binding_owner"`

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

	ClientClaimRetired          bool                        `json:"client_claim_retired"`
	ServerClaimRetired          bool                        `json:"server_claim_retired"`
	ClientOwnerClosed           bool                        `json:"client_owner_closed"`
	ServerOwnerClosed           bool                        `json:"server_owner_closed"`
	ListenerAdmissionClosed     bool                        `json:"listener_admission_closed"`
	ListenerCleanupClosed       bool                        `json:"listener_cleanup_closed"`
	ListenerLinksAfter          int                         `json:"listener_links_after"`
	ListenerAddressesAfter      int                         `json:"listener_addresses_after"`
	ListenerPendingAfter        int                         `json:"listener_pending_after"`
	ClientReplayOwnersAfter     int                         `json:"client_replay_owners_after"`
	ClientReplayBytesAfter      int                         `json:"client_replay_bytes_after"`
	ClientReplayEntriesAfter    int                         `json:"client_replay_entries_after"`
	ServerReplayOwnersAfter     int                         `json:"server_replay_owners_after"`
	ServerReplayBytesAfter      int                         `json:"server_replay_bytes_after"`
	ServerReplayEntriesAfter    int                         `json:"server_replay_entries_after"`
	RefreshCallbacksActiveAfter int                         `json:"refresh_callbacks_active_after"`
	PostCommitData              publicK5PostCommitDataEpoch `json:"post_commit_data"`
}

type publicK5PostCommitDataEpoch struct {
	StartedUnixNano int64 `json:"started_unix_nano"`

	SelectTargetCalls     uint64                   `json:"select_target_calls"`
	ClientActiveBefore    uint32                   `json:"client_active_before"`
	ClientActiveAfter     uint32                   `json:"client_active_after"`
	ServerActiveBefore    uint32                   `json:"server_active_before"`
	ServerActiveAfter     uint32                   `json:"server_active_after"`
	ClientDataPathID      uint32                   `json:"client_data_path_id"`
	ServerDataPathID      uint32                   `json:"server_data_path_id"`
	ClientMigrationBefore uint64                   `json:"client_migration_before"`
	ClientMigrationAfter  uint64                   `json:"client_migration_after"`
	ServerMigrationBefore uint64                   `json:"server_migration_before"`
	ServerMigrationAfter  uint64                   `json:"server_migration_after"`
	ClientActiveFinal     uint32                   `json:"client_active_final"`
	ServerActiveFinal     uint32                   `json:"server_active_final"`
	ClientMigrationFinal  uint64                   `json:"client_migration_final"`
	ServerMigrationFinal  uint64                   `json:"server_migration_final"`
	ClientSelectionEvents []publicK5MigrationEvent `json:"client_selection_events"`
	ServerSelectionEvents []publicK5MigrationEvent `json:"server_selection_events"`
	ClientPublishedNext   uint64                   `json:"client_published_next"`
	ServerPublishedNext   uint64                   `json:"server_published_next"`

	ClientOuterDataBefore       uint64   `json:"client_outer_data_before"`
	ClientOuterDataAfter        uint64   `json:"client_outer_data_after"`
	ServerOuterDataBefore       uint64   `json:"server_outer_data_before"`
	ServerOuterDataAfter        uint64   `json:"server_outer_data_after"`
	ClientInnerPayloadBefore    uint64   `json:"client_inner_payload_before"`
	ClientInnerPayloadAfter     uint64   `json:"client_inner_payload_after"`
	ServerInnerPayloadBefore    uint64   `json:"server_inner_payload_before"`
	ServerInnerPayloadAfter     uint64   `json:"server_inner_payload_after"`
	ClientControlDataBefore     uint64   `json:"client_control_data_before"`
	ClientControlDataAfter      uint64   `json:"client_control_data_after"`
	ServerControlDataBefore     uint64   `json:"server_control_data_before"`
	ServerControlDataAfter      uint64   `json:"server_control_data_after"`
	ClientControlEpochSequences []uint64 `json:"client_control_epoch_sequences"`
	ServerControlEpochSequences []uint64 `json:"server_control_epoch_sequences"`

	ClientOfferedBytes   uint64 `json:"client_offered_bytes"`
	ClientReceivedBytes  uint64 `json:"client_received_bytes"`
	ServerOfferedBytes   uint64 `json:"server_offered_bytes"`
	ServerReceivedBytes  uint64 `json:"server_received_bytes"`
	ClientOfferedSHA256  string `json:"client_offered_sha256"`
	ClientReceivedSHA256 string `json:"client_received_sha256"`
	ServerOfferedSHA256  string `json:"server_offered_sha256"`
	ServerReceivedSHA256 string `json:"server_received_sha256"`
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
	DataWrites    uint64 `json:"data_writes"`
	ControlWrites uint64 `json:"control_writes"`
}

type publicK5MigrationEvent struct {
	OldID                     uint32                             `json:"old_path_id"`
	NewID                     uint32                             `json:"new_path_id"`
	Cause                     string                             `json:"cause"`
	Ordinal                   uint64                             `json:"ordinal"`
	AtUnixNano                int64                              `json:"committed_at_unix_nano"`
	EvidenceKind              uint8                              `json:"evidence_kind"`
	TransactionID             string                             `json:"transaction_id"`
	RefreshEvidenceGeneration uint64                             `json:"refresh_evidence_generation"`
	SourceEndpointGeneration  uint64                             `json:"source_endpoint_generation"`
	ResultEndpointGeneration  uint64                             `json:"result_endpoint_generation"`
	TopologyEpoch             uint64                             `json:"topology_epoch"`
	HealthEpoch               uint64                             `json:"health_epoch"`
	Source                    publicK5MigrationPathBinding       `json:"source"`
	Result                    publicK5MigrationPathBinding       `json:"result"`
	Selector                  publicK5MigrationSelectorBinding   `json:"selector"`
	Leaf                      publicK5MigrationLeafBinding       `json:"leaf"`
	ProbeGenerations          []publicK5MigrationProbeGeneration `json:"probe_generations"`
	CommittedAt               time.Time                          `json:"-"`
}

type publicK5MigrationPathBinding struct {
	PathID             uint32 `json:"path_id"`
	PathOwner          uint64 `json:"path_owner"`
	PathGeneration     uint64 `json:"path_generation"`
	RouteGeneration    uint64 `json:"route_generation"`
	EndpointGeneration uint64 `json:"endpoint_generation"`
	PeerMobilityEpoch  uint64 `json:"peer_mobility_epoch"`
	HealthRevision     uint64 `json:"health_revision"`
	LocalTargetID      string `json:"local_target_id"`
	PeerTargetID       string `json:"peer_target_id"`
}

type publicK5MigrationSelectorBinding struct {
	SelectorID         string `json:"selector_id"`
	TargetID           string `json:"target_id"`
	Origin             string `json:"origin"`
	CutoverGeneration  uint64 `json:"cutover_generation"`
	CapturedAtUnixNano int64  `json:"captured_at_unix_nano"`
	ValidUntilUnixNano int64  `json:"valid_until_unix_nano"`
}

type publicK5MigrationLeafBinding struct {
	RefreshReason           string `json:"refresh_reason"`
	RefreshObservedUnixNano int64  `json:"refresh_observed_unix_nano"`
	RefreshSourceGeneration uint64 `json:"refresh_source_generation"`
	RefreshSourceUsable     bool   `json:"refresh_source_usable"`
	RefreshIncarnation      uint64 `json:"refresh_incarnation"`
}

type publicK5MigrationProbeGeneration struct {
	PathID             uint32 `json:"path_id"`
	PathOwner          uint64 `json:"path_owner"`
	PathGeneration     uint64 `json:"path_generation"`
	RouteGeneration    uint64 `json:"route_generation"`
	EndpointGeneration uint64 `json:"endpoint_generation"`
	PeerMobilityEpoch  uint64 `json:"peer_mobility_epoch"`
	HealthRevision     uint64 `json:"health_revision"`
}

func publicK5MigrationEventFromRendr(event rendr.MigrationEvent) publicK5MigrationEvent {
	probes := make([]publicK5MigrationProbeGeneration, len(event.Evidence.ProbeGenerations))
	for index, probe := range event.Evidence.ProbeGenerations {
		probes[index] = publicK5MigrationProbeGeneration{
			PathID: probe.PathID, PathOwner: probe.PathOwner, PathGeneration: probe.PathGeneration,
			RouteGeneration: probe.RouteGeneration, EndpointGeneration: probe.EndpointGeneration,
			PeerMobilityEpoch: probe.PeerMobilityEpoch, HealthRevision: probe.HealthRevision,
		}
	}
	return publicK5MigrationEvent{
		OldID: event.OldPathID, NewID: event.NewPathID, Cause: event.Cause,
		Ordinal: event.Ordinal, AtUnixNano: event.CommittedAt.UnixNano(), CommittedAt: event.CommittedAt,
		EvidenceKind: uint8(event.Evidence.Kind), TransactionID: hex.EncodeToString(event.Evidence.TransactionID[:]),
		RefreshEvidenceGeneration: event.Evidence.RefreshEvidenceGeneration,
		SourceEndpointGeneration:  event.Evidence.SourceEndpointGeneration,
		ResultEndpointGeneration:  event.Evidence.ResultEndpointGeneration,
		TopologyEpoch:             event.Evidence.TopologyEpoch, HealthEpoch: event.Evidence.HealthEpoch,
		Source: publicK5MigrationPathBindingFromRendr(event.Evidence.Source),
		Result: publicK5MigrationPathBindingFromRendr(event.Evidence.Result),
		Selector: publicK5MigrationSelectorBinding{
			SelectorID:         hex.EncodeToString(event.Evidence.Selector.SelectorID[:]),
			TargetID:           hex.EncodeToString(event.Evidence.Selector.TargetID[:]),
			Origin:             event.Evidence.Selector.Origin,
			CutoverGeneration:  event.Evidence.Selector.CutoverGeneration,
			CapturedAtUnixNano: publicK5UnixNano(event.Evidence.Selector.CapturedAt),
			ValidUntilUnixNano: publicK5UnixNano(event.Evidence.Selector.ValidUntil),
		},
		Leaf: publicK5MigrationLeafBinding{
			RefreshReason:           event.Evidence.Leaf.RefreshReason,
			RefreshObservedUnixNano: publicK5UnixNano(event.Evidence.Leaf.RefreshObservedAt),
			RefreshSourceGeneration: event.Evidence.Leaf.RefreshSourceGeneration,
			RefreshSourceUsable:     event.Evidence.Leaf.RefreshSourceUsable,
			RefreshIncarnation:      event.Evidence.Leaf.RefreshIncarnation,
		},
		ProbeGenerations: probes,
	}
}

func publicK5MigrationPathBindingFromRendr(binding rendr.MigrationPathBinding) publicK5MigrationPathBinding {
	return publicK5MigrationPathBinding{
		PathID: binding.PathID, PathOwner: binding.PathOwner, PathGeneration: binding.PathGeneration,
		RouteGeneration: binding.RouteGeneration, EndpointGeneration: binding.EndpointGeneration,
		PeerMobilityEpoch: binding.PeerMobilityEpoch, HealthRevision: binding.HealthRevision,
		LocalTargetID: hex.EncodeToString(binding.LocalTargetID[:]),
		PeerTargetID:  hex.EncodeToString(binding.PeerTargetID[:]),
	}
}

func publicK5UnixNano(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.UnixNano()
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

type publicK5ControlWriter uint8

const (
	publicK5ControlClient publicK5ControlWriter = iota + 1
	publicK5ControlServer
)

type publicK5ControlRecord struct {
	Writer      publicK5ControlWriter
	Code        proto.CtrlCode
	Transaction [16]byte
	Actor       proto.LeafMobilityActorSide
	Agreement   [32]byte
	AckPhase    proto.LeafMobilityPeerPlanAckPhase
	AckCode     proto.LeafMobilityPeerPlanAckCode
	CommitStage proto.LeafMobilityPeerPlanCommitStage
	Prepare     proto.LeafMobilityPeerPlanPrepare
	Ack         proto.LeafMobilityPeerPlanAck
	Commit      proto.LeafMobilityPeerPlanCommit
	Wire        []byte
}

type publicK5DataRecord struct {
	Writer   publicK5ControlWriter
	Sequence uint64
}

type publicK5ControlTrace struct {
	mu              sync.Mutex
	records         []publicK5ControlRecord
	dataRecords     []publicK5DataRecord
	malformed       uint64
	crossedPrepare  *publicK5CrossedPrepareGate
	oracleArmed     bool
	oracleWinner    [16]byte
	oracleAgreement [32]byte
	oracleInvalid   string
}

type publicK5ControlSummary struct {
	MobilityFrames                 uint64
	MalformedFrames                uint64
	AgreementMismatches            uint64
	OtherActorFrames               uint64
	WinningPrepareFrames           uint64
	WinningPreparedFrames          uint64
	WinningCommitFrames            uint64
	WinningFinalFrames             uint64
	WinningCompleteFrames          uint64
	WinningReleasedFrames          uint64
	CrossedServerTransactions      uint64
	CrossedServerPrepareFrames     uint64
	CrossedServerBusyFrames        uint64
	CrossedServerProgressionFrames uint64
	CrossedClientTransaction       [16]byte `json:"-"`
	CrossedServerTransaction       [16]byte `json:"-"`
	CrossedPrepareBarrier          bool
	CrossedPrepareInvalid          string
	OracleInvalid                  string `json:"-"`
	trace                          *publicK5ControlTrace
}

type publicK5CrossedPrepareGate struct {
	mu            sync.Mutex
	first         map[publicK5ControlWriter]proto.LeafMobilityPeerPlanPrepare
	firstWire     map[publicK5ControlWriter][]byte
	ready         chan struct{}
	closed        bool
	timeout       time.Duration
	invalidReason string
}

func newPublicK5CrossedPrepareGate() *publicK5CrossedPrepareGate {
	return &publicK5CrossedPrepareGate{
		first:     make(map[publicK5ControlWriter]proto.LeafMobilityPeerPlanPrepare, 2),
		firstWire: make(map[publicK5ControlWriter][]byte, 2),
		ready:     make(chan struct{}), timeout: 2 * time.Second,
	}
}

func (gate *publicK5CrossedPrepareGate) wait(writer publicK5ControlWriter, frame []byte) {
	if gate == nil {
		return
	}
	header, err := proto.DecodeHeader(frame)
	if err != nil || header.Type != proto.FrameCtrl ||
		proto.CtrlCodeFromFlags(header.Flags) != proto.CtrlLeafMobilityPrepare {
		return
	}
	prepare, err := proto.DecodeLeafMobilityPeerPlanPrepare(frame[proto.HeaderSize:])
	if err != nil {
		gate.invalidate("malformed_prepare: " + err.Error())
		return
	}
	if (writer == publicK5ControlClient && prepare.ActorSide != proto.LeafMobilityActorClient) ||
		(writer == publicK5ControlServer && prepare.ActorSide != proto.LeafMobilityActorServer) {
		gate.invalidate(fmt.Sprintf("actor_mismatch: writer=%d actor=%d", writer, prepare.ActorSide))
		return
	}
	gate.mu.Lock()
	if _, exists := gate.first[writer]; !exists {
		gate.first[writer] = prepare
		gate.firstWire[writer] = append([]byte(nil), frame...)
	}
	if len(gate.first) == 2 && !gate.closed {
		client := gate.first[publicK5ControlClient]
		server := gate.first[publicK5ControlServer]
		if reason := publicK5CrossedPreparePairInvalid(client, server); reason != "" && gate.invalidReason == "" {
			gate.invalidReason = reason
		}
		gate.closed = true
		close(gate.ready)
	}
	ready := gate.ready
	timeout := gate.timeout
	gate.mu.Unlock()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ready:
		return
	case <-timer.C:
		gate.invalidate("barrier_timeout")
	}
}

func (gate *publicK5CrossedPrepareGate) invalidate(reason string) {
	gate.mu.Lock()
	if gate.invalidReason == "" {
		gate.invalidReason = reason
	}
	gate.mu.Unlock()
}

func (gate *publicK5CrossedPrepareGate) result() (bool, string) {
	if gate == nil {
		return false, ""
	}
	gate.mu.Lock()
	completed := gate.closed && len(gate.first) == 2 && gate.invalidReason == ""
	invalidReason := gate.invalidReason
	gate.mu.Unlock()
	return completed, invalidReason
}

func (gate *publicK5CrossedPrepareGate) firstPair() (
	proto.LeafMobilityPeerPlanPrepare,
	proto.LeafMobilityPeerPlanPrepare,
	bool,
) {
	if gate == nil {
		return proto.LeafMobilityPeerPlanPrepare{}, proto.LeafMobilityPeerPlanPrepare{}, false
	}
	gate.mu.Lock()
	defer gate.mu.Unlock()
	client, clientOK := gate.first[publicK5ControlClient]
	server, serverOK := gate.first[publicK5ControlServer]
	return client, server, gate.closed && clientOK && serverOK && gate.invalidReason == ""
}

func (gate *publicK5CrossedPrepareGate) firstPairWire() ([]byte, []byte, bool) {
	if gate == nil {
		return nil, nil, false
	}
	gate.mu.Lock()
	defer gate.mu.Unlock()
	client, clientOK := gate.firstWire[publicK5ControlClient]
	server, serverOK := gate.firstWire[publicK5ControlServer]
	return append([]byte(nil), client...), append([]byte(nil), server...),
		gate.closed && clientOK && serverOK && gate.invalidReason == ""
}

func publicK5CrossedPreparePairInvalid(
	client, server proto.LeafMobilityPeerPlanPrepare,
) string {
	if client.ActorSide != proto.LeafMobilityActorClient || server.ActorSide != proto.LeafMobilityActorServer {
		return "crossed_actor_pair_mismatch"
	}
	if client.TransactionID == ([16]byte{}) || server.TransactionID == ([16]byte{}) ||
		client.TransactionID == server.TransactionID {
		return "crossed_transaction_identity_mismatch"
	}
	// Keep this predicate aligned with the production client-priority
	// arbitration identity. Direction, lease, actor-local resource ID and plan
	// digest may legitimately differ between the two endpoint proposals.
	if client.CoordinatorSide != server.CoordinatorSide ||
		client.SessionKind != server.SessionKind || client.Operation != server.Operation ||
		client.Fallback != server.Fallback || client.SessionEpoch != server.SessionEpoch ||
		client.ClientGraph != server.ClientGraph || client.ServerGraph != server.ServerGraph ||
		client.SubjectClientTargetID != server.SubjectClientTargetID ||
		client.SubjectServerTargetID != server.SubjectServerTargetID ||
		client.BaseGeneration != server.BaseGeneration || client.ResourceScope != server.ResourceScope ||
		client.SubjectRouteGeneration != server.SubjectRouteGeneration {
		return "crossed_arbitration_binding_mismatch"
	}
	return ""
}

func (trace *publicK5ControlTrace) record(writer publicK5ControlWriter, frame []byte) {
	header, err := proto.DecodeHeader(frame)
	if err != nil {
		return
	}
	if header.Type == proto.FrameData {
		trace.mu.Lock()
		trace.dataRecords = append(trace.dataRecords, publicK5DataRecord{Writer: writer, Sequence: header.Seq})
		trace.mu.Unlock()
		return
	}
	if header.Type != proto.FrameCtrl {
		return
	}
	code := proto.CtrlCodeFromFlags(header.Flags)
	if code != proto.CtrlLeafMobilityPrepare && code != proto.CtrlLeafMobilityAck && code != proto.CtrlLeafMobilityCommit {
		return
	}
	if err = proto.ValidateLeafMobilityCtrlFlags(header.Flags); err != nil {
		trace.recordMalformedLocked(err)
		return
	}
	record := publicK5ControlRecord{Writer: writer, Code: code, Wire: append([]byte(nil), frame...)}
	payload := frame[proto.HeaderSize:]
	switch code {
	case proto.CtrlLeafMobilityPrepare:
		message, decodeErr := proto.DecodeLeafMobilityPeerPlanPrepare(payload)
		if decodeErr == nil {
			record.Prepare = message
			record.Transaction = message.TransactionID
			record.Actor = message.ActorSide
		}
		err = decodeErr
	case proto.CtrlLeafMobilityAck:
		message, decodeErr := proto.DecodeLeafMobilityPeerPlanAck(payload)
		if decodeErr == nil {
			record.Ack = message
			record.Transaction = message.TransactionID
			record.Actor = message.ActorSide
			record.Agreement = message.AgreementDigest
			record.AckPhase = message.Phase
			record.AckCode = message.Code
			record.CommitStage = message.Stage
		}
		err = decodeErr
	case proto.CtrlLeafMobilityCommit:
		message, decodeErr := proto.DecodeLeafMobilityPeerPlanCommit(payload)
		if decodeErr == nil {
			record.Commit = message
			record.Transaction = message.TransactionID
			record.Actor = message.ActorSide
			record.Agreement = message.AgreementDigest
			record.CommitStage = message.Stage
		}
		err = decodeErr
	}
	trace.mu.Lock()
	defer trace.mu.Unlock()
	if err != nil {
		trace.malformed++
		if trace.oracleArmed && trace.oracleInvalid == "" {
			trace.oracleInvalid = "late_malformed_mobility_frame: " + err.Error()
		}
		return
	}
	if reason := trace.lateRecordInvalidLocked(record); reason != "" && trace.oracleInvalid == "" {
		trace.oracleInvalid = reason
	}
	trace.records = append(trace.records, record)
}

func (trace *publicK5ControlTrace) recordMalformedLocked(err error) {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	trace.malformed++
	if trace.oracleArmed && trace.oracleInvalid == "" {
		trace.oracleInvalid = "late_malformed_mobility_frame: " + err.Error()
	}
}

func (trace *publicK5ControlTrace) lateRecordInvalidLocked(record publicK5ControlRecord) string {
	if !trace.oracleArmed {
		return ""
	}
	if record.Transaction == trace.oracleWinner {
		for _, prior := range trace.records {
			if prior.Transaction == trace.oracleWinner && prior.Writer == record.Writer && bytes.Equal(prior.Wire, record.Wire) {
				return ""
			}
		}
		return "late_winner_frame_is_not_an_exact_replay"
	}
	if record.Actor != proto.LeafMobilityActorServer {
		return "late_non_winner_frame_has_non_server_actor"
	}
	allowed := (record.Code == proto.CtrlLeafMobilityPrepare && record.Writer == publicK5ControlServer) ||
		(record.Code == proto.CtrlLeafMobilityAck && record.Writer == publicK5ControlClient &&
			record.Ack.Phase == proto.LeafMobilityPeerPlanAckPhasePrepared &&
			record.Ack.Code == proto.LeafMobilityPeerPlanAckCodeBusy)
	if !allowed {
		return "late_server_transaction_progressed"
	}
	transactionSeen := false
	for _, prior := range trace.records {
		if prior.Transaction == record.Transaction {
			transactionSeen = true
		}
		if prior.Transaction != record.Transaction || prior.Code != record.Code {
			continue
		}
		if prior.Writer == record.Writer && bytes.Equal(prior.Wire, record.Wire) {
			return ""
		}
		return "late_server_retry_is_not_an_exact_replay"
	}
	if !transactionSeen {
		return "late_server_retry_started_after_oracle_seal"
	}
	return "late_server_retry_added_a_new_stage"
}

func (trace *publicK5ControlTrace) snapshot() []publicK5ControlRecord {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	return publicK5CloneControlRecords(trace.records)
}

func (trace *publicK5ControlTrace) winningPrepare(transaction [16]byte) (proto.LeafMobilityPeerPlanPrepare, bool) {
	if trace == nil || transaction == ([16]byte{}) {
		return proto.LeafMobilityPeerPlanPrepare{}, false
	}
	trace.mu.Lock()
	defer trace.mu.Unlock()
	for index := range trace.records {
		record := &trace.records[index]
		if record.Transaction == transaction && record.Code == proto.CtrlLeafMobilityPrepare &&
			record.Writer == publicK5ControlClient && record.Actor == proto.LeafMobilityActorClient {
			return record.Prepare, true
		}
	}
	return proto.LeafMobilityPeerPlanPrepare{}, false
}

func publicK5CloneControlRecords(records []publicK5ControlRecord) []publicK5ControlRecord {
	cloned := append([]publicK5ControlRecord(nil), records...)
	for index := range cloned {
		cloned[index].Wire = append([]byte(nil), cloned[index].Wire...)
	}
	return cloned
}

func (trace *publicK5ControlTrace) dataSnapshot() []publicK5DataRecord {
	if trace == nil {
		return nil
	}
	trace.mu.Lock()
	defer trace.mu.Unlock()
	return append([]publicK5DataRecord(nil), trace.dataRecords...)
}

func publicK5ControlDataSequencesSince(
	before, after []publicK5DataRecord,
) (client, server []uint64) {
	start := len(before)
	if start > len(after) {
		start = 0
	}
	for _, record := range after[start:] {
		switch record.Writer {
		case publicK5ControlClient:
			client = append(client, record.Sequence)
		case publicK5ControlServer:
			server = append(server, record.Sequence)
		}
	}
	return client, server
}

func (trace *publicK5ControlTrace) summarize(
	winner [16]byte,
	agreement [32]byte,
) publicK5ControlSummary {
	trace.mu.Lock()
	records := publicK5CloneControlRecords(trace.records)
	summary := publicK5SummarizeControlRecords(records, trace.malformed, trace.crossedPrepare, winner, agreement)
	if trace.oracleInvalid != "" {
		summary.OracleInvalid = trace.oracleInvalid
	}
	if trace.oracleArmed {
		if trace.oracleWinner != winner || trace.oracleAgreement != agreement {
			if trace.oracleInvalid == "" {
				trace.oracleInvalid = "oracle_identity_changed_after_arming"
			}
			summary.OracleInvalid = trace.oracleInvalid
		} else if !summary.valid() && trace.oracleInvalid == "" {
			trace.oracleInvalid = summary.invalidReason()
			summary.OracleInvalid = trace.oracleInvalid
		}
	} else if summary.valid() {
		trace.oracleArmed = true
		trace.oracleWinner = winner
		trace.oracleAgreement = agreement
	}
	trace.mu.Unlock()
	summary.trace = trace
	return summary
}

type publicK5WinnerChain struct {
	prepare  *publicK5ControlRecord
	prepared *publicK5ControlRecord
	commit   *publicK5ControlRecord
	final    *publicK5ControlRecord
	complete *publicK5ControlRecord
	released *publicK5ControlRecord
	next     int
}

type publicK5ServerLoserLedger struct {
	prepare *publicK5ControlRecord
	busy    *publicK5ControlRecord
}

func publicK5SummarizeControlRecords(
	records []publicK5ControlRecord,
	malformed uint64,
	gate *publicK5CrossedPrepareGate,
	winner [16]byte,
	agreement [32]byte,
) publicK5ControlSummary {
	barrierComplete, barrierInvalid := gate.result()
	crossedClient, crossedServer, pairOK := gate.firstPair()
	crossedClientWire, crossedServerWire, pairWireOK := gate.firstPairWire()
	summary := publicK5ControlSummary{
		MobilityFrames: uint64(len(records)), MalformedFrames: malformed,
		CrossedPrepareBarrier: barrierComplete, CrossedPrepareInvalid: barrierInvalid,
	}
	if pairOK {
		summary.CrossedClientTransaction = crossedClient.TransactionID
		summary.CrossedServerTransaction = crossedServer.TransactionID
	}
	setInvalid := func(reason string) {
		if summary.OracleInvalid == "" {
			summary.OracleInvalid = reason
		}
	}
	if malformed != 0 {
		setInvalid("malformed_mobility_frame")
	}

	var winnerChain publicK5WinnerChain
	serverLedgers := make(map[[16]byte]*publicK5ServerLoserLedger)
	var firstClientPrepare, firstServerPrepare *publicK5ControlRecord
	for index := range records {
		record := &records[index]
		if record.Code == proto.CtrlLeafMobilityPrepare {
			switch record.Writer {
			case publicK5ControlClient:
				if firstClientPrepare == nil {
					firstClientPrepare = record
				}
			case publicK5ControlServer:
				if firstServerPrepare == nil {
					firstServerPrepare = record
				}
			}
		}
		if record.Transaction == winner {
			if record.Code != proto.CtrlLeafMobilityPrepare && record.Agreement != agreement {
				summary.AgreementMismatches++
				setInvalid("winner_agreement_mismatch")
			}
			if reason := publicK5AddWinnerRecord(&winnerChain, record, &summary); reason != "" {
				setInvalid(reason)
			}
			continue
		}
		if record.Actor != proto.LeafMobilityActorServer {
			summary.OtherActorFrames++
			setInvalid("non_winner_frame_has_non_server_actor")
			continue
		}
		ledger := serverLedgers[record.Transaction]
		if ledger == nil {
			ledger = &publicK5ServerLoserLedger{}
			serverLedgers[record.Transaction] = ledger
		}
		switch {
		case record.Code == proto.CtrlLeafMobilityPrepare && record.Writer == publicK5ControlServer:
			summary.CrossedServerPrepareFrames++
			if reason := publicK5AcceptExactReplay(&ledger.prepare, record, "server_prepare"); reason != "" {
				setInvalid(reason)
			}
		case record.Code == proto.CtrlLeafMobilityAck && record.Writer == publicK5ControlClient &&
			record.Ack.Phase == proto.LeafMobilityPeerPlanAckPhasePrepared &&
			record.Ack.Code == proto.LeafMobilityPeerPlanAckCodeBusy:
			summary.CrossedServerBusyFrames++
			if ledger.prepare == nil {
				setInvalid("server_busy_preceded_its_prepare")
			}
			if reason := publicK5AcceptExactReplay(&ledger.busy, record, "server_busy"); reason != "" {
				setInvalid(reason)
			}
		default:
			summary.CrossedServerProgressionFrames++
			setInvalid("server_loser_transaction_progressed")
		}
	}

	summary.CrossedServerTransactions = uint64(len(serverLedgers))
	for transaction, ledger := range serverLedgers {
		if ledger.prepare == nil || ledger.busy == nil {
			setInvalid(fmt.Sprintf("server_loser_transaction_%x_is_orphaned", transaction))
			continue
		}
		if pairOK {
			if reason := publicK5CrossedPreparePairInvalid(crossedClient, ledger.prepare.Prepare); reason != "" {
				setInvalid("server_loser_arbitration_binding_mismatch: " + reason)
			}
		}
		if err := ledger.busy.Ack.ValidateForPrepare(ledger.prepare.Prepare); err != nil {
			setInvalid("server_busy_does_not_match_prepare: " + err.Error())
		}
	}
	if !pairOK {
		setInvalid("crossed_prepare_pair_unavailable")
	} else {
		if winner != crossedClient.TransactionID {
			setInvalid("winner_is_not_first_crossed_client_transaction")
		}
		if firstClientPrepare == nil || firstClientPrepare.Prepare != crossedClient || !pairWireOK ||
			!bytes.Equal(firstClientPrepare.Wire, crossedClientWire) {
			setInvalid("first_written_client_prepare_drifted_from_gate")
		}
		if firstServerPrepare == nil || firstServerPrepare.Prepare != crossedServer || !pairWireOK ||
			!bytes.Equal(firstServerPrepare.Wire, crossedServerWire) {
			setInvalid("first_written_server_prepare_drifted_from_gate")
		}
		ledger := serverLedgers[crossedServer.TransactionID]
		if ledger == nil || ledger.prepare == nil || ledger.prepare.Prepare != crossedServer {
			setInvalid("barrier_server_transaction_missing_from_loser_ledger")
		}
	}
	if reason := publicK5ValidateWinnerChain(winnerChain, crossedClient, pairOK, winner, agreement); reason != "" {
		setInvalid(reason)
	}
	return summary
}

func publicK5AddWinnerRecord(
	chain *publicK5WinnerChain,
	record *publicK5ControlRecord,
	summary *publicK5ControlSummary,
) string {
	if record.Actor != proto.LeafMobilityActorClient {
		return "winner_frame_has_wrong_actor"
	}
	var slot **publicK5ControlRecord
	var name string
	var stage int
	switch record.Code {
	case proto.CtrlLeafMobilityPrepare:
		if record.Writer != publicK5ControlClient {
			return "winner_prepare_has_wrong_writer"
		}
		summary.WinningPrepareFrames++
		slot, name, stage = &chain.prepare, "winner_prepare", 0
	case proto.CtrlLeafMobilityAck:
		if record.Writer != publicK5ControlServer {
			return "winner_ack_has_wrong_writer"
		}
		if record.Ack.Code != proto.LeafMobilityPeerPlanAckCodeAccept {
			return "winner_ack_was_not_accepted"
		}
		switch record.Ack.Phase {
		case proto.LeafMobilityPeerPlanAckPhasePrepared:
			summary.WinningPreparedFrames++
			slot, name, stage = &chain.prepared, "winner_prepared", 1
		case proto.LeafMobilityPeerPlanAckPhaseFinal:
			summary.WinningFinalFrames++
			slot, name, stage = &chain.final, "winner_final", 3
		case proto.LeafMobilityPeerPlanAckPhaseReleased:
			summary.WinningReleasedFrames++
			slot, name, stage = &chain.released, "winner_released", 5
		default:
			return "winner_ack_has_unknown_phase"
		}
	case proto.CtrlLeafMobilityCommit:
		if record.Writer != publicK5ControlClient {
			return "winner_commit_has_wrong_writer"
		}
		switch record.Commit.Stage {
		case proto.LeafMobilityPeerPlanCommitStageCommit:
			summary.WinningCommitFrames++
			slot, name, stage = &chain.commit, "winner_commit", 2
		case proto.LeafMobilityPeerPlanCommitStageComplete:
			summary.WinningCompleteFrames++
			slot, name, stage = &chain.complete, "winner_complete", 4
		case proto.LeafMobilityPeerPlanCommitStageAbort:
			return "winner_aborted"
		case proto.LeafMobilityPeerPlanCommitStageRolledBack:
			return "winner_rolled_back"
		default:
			return "winner_commit_has_unknown_stage"
		}
	default:
		return "winner_frame_has_unknown_code"
	}
	if *slot == nil {
		if chain.next != stage {
			return fmt.Sprintf("%s_is_out_of_order: got_stage=%d want_stage=%d", name, stage, chain.next)
		}
		chain.next++
	}
	return publicK5AcceptExactReplay(slot, record, name)
}

func publicK5AcceptExactReplay(
	slot **publicK5ControlRecord,
	record *publicK5ControlRecord,
	name string,
) string {
	if len(record.Wire) == 0 {
		return name + "_has_no_canonical_wire"
	}
	if *slot == nil {
		*slot = record
		return ""
	}
	if (*slot).Writer != record.Writer || !bytes.Equal((*slot).Wire, record.Wire) {
		return name + "_replay_is_not_byte_identical"
	}
	return ""
}

func publicK5ValidateWinnerChain(
	chain publicK5WinnerChain,
	gatePrepare proto.LeafMobilityPeerPlanPrepare,
	gateOK bool,
	winner [16]byte,
	agreement [32]byte,
) string {
	if chain.prepare == nil || chain.prepared == nil || chain.commit == nil || chain.final == nil ||
		chain.complete == nil || chain.released == nil {
		return "winner_chain_is_incomplete"
	}
	prepare := chain.prepare.Prepare
	prepared := chain.prepared.Ack
	commit := chain.commit.Commit
	final := chain.final.Ack
	complete := chain.complete.Commit
	released := chain.released.Ack
	if prepare.TransactionID != winner || !gateOK || prepare != gatePrepare {
		return "winner_prepare_does_not_match_gate"
	}
	if err := prepared.ValidateForPrepare(prepare); err != nil {
		return "winner_prepared_does_not_match_prepare: " + err.Error()
	}
	if err := commit.ValidateForPrepared(prepare, prepared); err != nil {
		return "winner_commit_does_not_match_prepared: " + err.Error()
	}
	if err := final.ValidateForCommit(commit); err != nil {
		return "winner_final_does_not_match_commit: " + err.Error()
	}
	if complete.Stage != proto.LeafMobilityPeerPlanCommitStageComplete {
		return "winner_terminal_is_not_complete"
	}
	if err := complete.ValidateForCommit(commit); err != nil {
		return "winner_complete_does_not_match_commit: " + err.Error()
	}
	if err := released.ValidateForCommit(complete); err != nil {
		return "winner_released_does_not_match_complete: " + err.Error()
	}
	if prepared.AgreementDigest != agreement || commit.AgreementDigest != agreement ||
		final.AgreementDigest != agreement || complete.AgreementDigest != agreement ||
		released.AgreementDigest != agreement {
		return "winner_chain_does_not_match_selected_agreement"
	}
	return ""
}

func (summary publicK5ControlSummary) valid() bool {
	if summary.trace != nil && summary.trace.oracleInvalidReason() != "" {
		return false
	}
	return summary.MobilityFrames > 0 && summary.MalformedFrames == 0 &&
		summary.AgreementMismatches == 0 && summary.OtherActorFrames == 0 &&
		summary.WinningPrepareFrames > 0 && summary.WinningPreparedFrames > 0 &&
		summary.WinningCommitFrames > 0 && summary.WinningFinalFrames > 0 &&
		summary.WinningCompleteFrames > 0 && summary.WinningReleasedFrames > 0 &&
		summary.CrossedServerTransactions > 0 && summary.CrossedServerPrepareFrames > 0 &&
		summary.CrossedServerBusyFrames > 0 && summary.CrossedServerProgressionFrames == 0 &&
		summary.CrossedClientTransaction != ([16]byte{}) && summary.CrossedServerTransaction != ([16]byte{}) &&
		summary.CrossedClientTransaction != summary.CrossedServerTransaction &&
		summary.CrossedPrepareBarrier && summary.CrossedPrepareInvalid == "" && summary.OracleInvalid == ""
}

func (trace *publicK5ControlTrace) oracleInvalidReason() string {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	return trace.oracleInvalid
}

func (summary publicK5ControlSummary) invalidReason() string {
	if summary.OracleInvalid != "" {
		return summary.OracleInvalid
	}
	return "armed_control_oracle_became_invalid"
}

type publicK5ControlPath struct {
	transport.PathConn
	trace  *publicK5ControlTrace
	writer publicK5ControlWriter
}

func (path *publicK5ControlPath) Write(frame []byte) (int, error) {
	path.trace.crossedPrepare.wait(path.writer, frame)
	n, err := path.PathConn.Write(frame)
	if err == nil && n == len(frame) {
		path.trace.record(path.writer, frame)
	}
	return n, err
}

func TestPublicK5CrossedPrepareGateDoesNotInjectTransportFailure(t *testing.T) {
	for _, test := range []struct {
		name       string
		writer     publicK5ControlWriter
		frame      func(testing.TB) []byte
		wantReason string
	}{
		{
			name: "malformed prepare", writer: publicK5ControlClient,
			frame:      func(t testing.TB) []byte { return publicK5MalformedPrepareFrame(t) },
			wantReason: "malformed_prepare:",
		},
		{
			name: "actor mismatch", writer: publicK5ControlClient,
			frame:      func(t testing.TB) []byte { return publicK5PrepareFrame(t, proto.LeafMobilityActorServer) },
			wantReason: "actor_mismatch:",
		},
		{
			name: "barrier timeout", writer: publicK5ControlClient,
			frame:      func(t testing.TB) []byte { return publicK5PrepareFrame(t, proto.LeafMobilityActorClient) },
			wantReason: "barrier_timeout",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			gate := newPublicK5CrossedPrepareGate()
			gate.timeout = 10 * time.Millisecond
			trace := &publicK5ControlTrace{crossedPrepare: gate}
			sink := &publicK5ControlGateSink{}
			path := &publicK5ControlPath{PathConn: sink, trace: trace, writer: test.writer}
			frame := test.frame(t)
			n, err := path.Write(frame)
			if err != nil || n != len(frame) || sink.writes.Load() != 1 {
				t.Fatalf("oracle changed transport write: bytes=%d/%d writes=%d error=%v", n, len(frame), sink.writes.Load(), err)
			}
			complete, invalid := gate.result()
			if complete || !strings.HasPrefix(invalid, test.wantReason) {
				t.Fatalf("gate result complete=%t invalid=%q want prefix %q", complete, invalid, test.wantReason)
			}
		})
	}
}

func TestPublicK5CrossedPrepareGateCompletesWithoutOracleFailure(t *testing.T) {
	gate := newPublicK5CrossedPrepareGate()
	trace := &publicK5ControlTrace{crossedPrepare: gate}
	sink := &publicK5ControlGateSink{}
	type writeResult struct {
		n   int
		err error
	}
	results := make(chan writeResult, 2)
	for _, writer := range []publicK5ControlWriter{publicK5ControlClient, publicK5ControlServer} {
		writer := writer
		actor := proto.LeafMobilityActorClient
		if writer == publicK5ControlServer {
			actor = proto.LeafMobilityActorServer
		}
		frame := publicK5PrepareFrame(t, actor)
		path := &publicK5ControlPath{PathConn: sink, trace: trace, writer: writer}
		go func() {
			n, err := path.Write(frame)
			results <- writeResult{n: n, err: err}
		}()
	}
	for range 2 {
		result := <-results
		if result.err != nil || result.n == 0 {
			t.Fatalf("healthy barrier write bytes=%d error=%v", result.n, result.err)
		}
	}
	complete, invalid := gate.result()
	if !complete || invalid != "" || sink.writes.Load() != 2 {
		t.Fatalf("healthy gate complete=%t invalid=%q writes=%d", complete, invalid, sink.writes.Load())
	}
	client, server, pairOK := gate.firstPair()
	if !pairOK || client.ActorSide != proto.LeafMobilityActorClient ||
		server.ActorSide != proto.LeafMobilityActorServer ||
		client.TransactionID == server.TransactionID {
		t.Fatalf("healthy gate first pair client=%+v server=%+v ok=%t", client, server, pairOK)
	}
}

func TestPublicK5CrossedElectionOracleSurvivesStatusRollover(t *testing.T) {
	gate := newPublicK5CrossedPrepareGate()
	client, firstServer := publicK5CaptureTestCrossedPair(t, gate)
	retryServer := firstServer
	retryServer.TransactionID[15]++
	retryServer.ResourceID[0]++
	retryServer.ActorPlanDigest[0]++
	election := publicK5CrossedElectionRecords(t, client, firstServer, retryServer)
	trace := &publicK5ControlTrace{crossedPrepare: gate, records: election.records}
	summary := trace.summarize(client.TransactionID, election.agreement)
	if !summary.valid() || summary.CrossedClientTransaction != client.TransactionID ||
		summary.CrossedServerTransaction != firstServer.TransactionID ||
		summary.CrossedServerTransactions != 2 {
		t.Fatalf("status-rollover oracle summary=%+v records=%+v", summary, election.records)
	}

	replayed := &publicK5ControlTrace{crossedPrepare: gate, records: publicK5CloneControlRecords(election.records)}
	replayed.records = append(replayed.records,
		publicK5CloneControlRecords([]publicK5ControlRecord{election.records[0], election.records[1], election.records[6], election.records[7]})...,
	)
	if replaySummary := replayed.summarize(client.TransactionID, election.agreement); !replaySummary.valid() {
		t.Fatalf("byte-identical legal replays were rejected: summary=%+v", replaySummary)
	}

	mutations := []struct {
		name   string
		winner [16]byte
		mutate func([]publicK5ControlRecord) []publicK5ControlRecord
	}{
		{
			name: "missing first busy", winner: client.TransactionID,
			mutate: func(records []publicK5ControlRecord) []publicK5ControlRecord {
				return append(records[:7:7], records[8:]...)
			},
		},
		{
			name: "first busy rebound to retry", winner: client.TransactionID,
			mutate: func(records []publicK5ControlRecord) []publicK5ControlRecord {
				records[7] = records[9]
				return records
			},
		},
		{
			name: "server transaction accepted", winner: client.TransactionID,
			mutate: func(records []publicK5ControlRecord) []publicK5ControlRecord {
				accepted := publicK5AcceptedPreparedAck(t, firstServer)
				records[7] = publicK5TestControlRecord(t, publicK5ControlClient, proto.CtrlLeafMobilityAck, accepted)
				return records
			},
		},
		{
			name: "server retry progressed", winner: client.TransactionID,
			mutate: func(records []publicK5ControlRecord) []publicK5ControlRecord {
				accepted := publicK5AcceptedPreparedAck(t, retryServer)
				commit := publicK5CommitForPrepared(accepted)
				return append(records, publicK5TestControlRecord(t, publicK5ControlServer, proto.CtrlLeafMobilityCommit, commit))
			},
		},
		{
			name: "winner prepare wrong actor", winner: client.TransactionID,
			mutate: func(records []publicK5ControlRecord) []publicK5ControlRecord {
				changed := client
				changed.ActorSide = proto.LeafMobilityActorServer
				records[0] = publicK5TestControlRecord(t, publicK5ControlClient, proto.CtrlLeafMobilityPrepare, changed)
				return records
			},
		},
		{
			name: "winner final wrong writer", winner: client.TransactionID,
			mutate: func(records []publicK5ControlRecord) []publicK5ControlRecord {
				records[3].Writer = publicK5ControlClient
				return records
			},
		},
		{
			name: "winner prepared busy", winner: client.TransactionID,
			mutate: func(records []publicK5ControlRecord) []publicK5ControlRecord {
				busy := publicK5RejectedPreparedAck(t, client, proto.LeafMobilityPeerPlanAckCodeBusy)
				records[1] = publicK5TestControlRecord(t, publicK5ControlServer, proto.CtrlLeafMobilityAck, busy)
				return records
			},
		},
		{
			name: "winner prepared rejected", winner: client.TransactionID,
			mutate: func(records []publicK5ControlRecord) []publicK5ControlRecord {
				reject := publicK5RejectedPreparedAck(t, client, proto.LeafMobilityPeerPlanAckCodeReject)
				records[1] = publicK5TestControlRecord(t, publicK5ControlServer, proto.CtrlLeafMobilityAck, reject)
				return records
			},
		},
		{
			name: "winner aborted", winner: client.TransactionID,
			mutate: func(records []publicK5ControlRecord) []publicK5ControlRecord {
				abort := election.commit
				abort.Stage = proto.LeafMobilityPeerPlanCommitStageAbort
				abort.PublicationDigest = proto.LeafMobilityPublicationDigest{}
				records[4] = publicK5TestControlRecord(t, publicK5ControlClient, proto.CtrlLeafMobilityCommit, abort)
				return records
			},
		},
		{
			name: "winner rolled back", winner: client.TransactionID,
			mutate: func(records []publicK5ControlRecord) []publicK5ControlRecord {
				rollback := election.commit
				rollback.Stage = proto.LeafMobilityPeerPlanCommitStageRolledBack
				records[4] = publicK5TestControlRecord(t, publicK5ControlClient, proto.CtrlLeafMobilityCommit, rollback)
				return records
			},
		},
		{
			name: "conflicting winner terminal", winner: client.TransactionID,
			mutate: func(records []publicK5ControlRecord) []publicK5ControlRecord {
				conflict := election.complete
				conflict.PublicationDigest[0] ^= 0xff
				return append(records, publicK5TestControlRecord(t, publicK5ControlClient, proto.CtrlLeafMobilityCommit, conflict))
			},
		},
		{
			name: "orphan retry prepare", winner: client.TransactionID,
			mutate: func(records []publicK5ControlRecord) []publicK5ControlRecord {
				return append(records[:9:9], records[10:]...)
			},
		},
		{
			name: "orphan retry busy", winner: client.TransactionID,
			mutate: func(records []publicK5ControlRecord) []publicK5ControlRecord {
				return append(records[:8:8], records[9:]...)
			},
		},
		{
			name: "winner stages reordered", winner: client.TransactionID,
			mutate: func(records []publicK5ControlRecord) []publicK5ControlRecord {
				records[1], records[2] = records[2], records[1]
				return records
			},
		},
		{
			name: "first written client prepare drift", winner: client.TransactionID,
			mutate: func(records []publicK5ControlRecord) []publicK5ControlRecord {
				changed := client
				changed.ActorPlanDigest[0] ^= 0xff
				records[0] = publicK5TestControlRecord(t, publicK5ControlClient, proto.CtrlLeafMobilityPrepare, changed)
				return records
			},
		},
		{
			name: "first written server prepare drift", winner: client.TransactionID,
			mutate: func(records []publicK5ControlRecord) []publicK5ControlRecord {
				changed := firstServer
				changed.ActorPlanDigest[0] ^= 0xff
				records[6] = publicK5TestControlRecord(t, publicK5ControlServer, proto.CtrlLeafMobilityPrepare, changed)
				return records
			},
		},
		{
			name: "winner not first client", winner: [16]byte{0xfe},
			mutate: func(records []publicK5ControlRecord) []publicK5ControlRecord { return records },
		},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			mutated := mutation.mutate(publicK5CloneControlRecords(election.records))
			candidate := (&publicK5ControlTrace{crossedPrepare: gate, records: mutated}).summarize(mutation.winner, election.agreement)
			if candidate.valid() {
				t.Fatalf("mutation survived oracle: summary=%+v records=%+v", candidate, mutated)
			}
		})
	}
}

func TestPublicK5CrossedElectionOracleLatchesLateContradictions(t *testing.T) {
	gate := newPublicK5CrossedPrepareGate()
	client, firstServer := publicK5CaptureTestCrossedPair(t, gate)
	retryServer := firstServer
	retryServer.TransactionID[15]++
	retryServer.ResourceID[0]++
	election := publicK5CrossedElectionRecords(t, client, firstServer, retryServer)

	tests := []struct {
		name   string
		mutate func(*publicK5ControlTrace)
	}{
		{
			name: "late server progression",
			mutate: func(trace *publicK5ControlTrace) {
				accepted := publicK5AcceptedPreparedAck(t, retryServer)
				commit := publicK5CommitForPrepared(accepted)
				record := publicK5TestControlRecord(t, publicK5ControlServer, proto.CtrlLeafMobilityCommit, commit)
				trace.record(record.Writer, record.Wire)
			},
		},
		{
			name: "late new retry",
			mutate: func(trace *publicK5ControlTrace) {
				late := retryServer
				late.TransactionID[14]++
				late.ResourceID[1]++
				record := publicK5TestControlRecord(t, publicK5ControlServer, proto.CtrlLeafMobilityPrepare, late)
				trace.record(record.Writer, record.Wire)
			},
		},
		{
			name: "late conflicting terminal",
			mutate: func(trace *publicK5ControlTrace) {
				conflict := election.complete
				conflict.PublicationDigest[0] ^= 0xff
				record := publicK5TestControlRecord(t, publicK5ControlClient, proto.CtrlLeafMobilityCommit, conflict)
				trace.record(record.Writer, record.Wire)
			},
		},
		{
			name: "late unknown terminal stage",
			mutate: func(trace *publicK5ControlTrace) {
				frame := append([]byte(nil), election.records[4].Wire...)
				frame[proto.HeaderSize+proto.LeafMobilityPeerPlanBindingSize+136] = 0xff
				trace.record(publicK5ControlClient, frame)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			trace := &publicK5ControlTrace{crossedPrepare: gate, records: publicK5CloneControlRecords(election.records)}
			earlier := trace.summarize(client.TransactionID, election.agreement)
			if !earlier.valid() {
				t.Fatalf("baseline did not arm oracle: %+v", earlier)
			}
			test.mutate(trace)
			if earlier.valid() {
				t.Fatalf("earlier summary remained valid after %s", test.name)
			}
			if fresh := trace.summarize(client.TransactionID, election.agreement); fresh.valid() || fresh.OracleInvalid == "" {
				t.Fatalf("fresh summary missed %s: %+v", test.name, fresh)
			}
		})
	}

	t.Run("late exact replay remains valid", func(t *testing.T) {
		trace := &publicK5ControlTrace{crossedPrepare: gate, records: publicK5CloneControlRecords(election.records)}
		earlier := trace.summarize(client.TransactionID, election.agreement)
		trace.record(election.records[0].Writer, election.records[0].Wire)
		trace.record(election.records[7].Writer, election.records[7].Wire)
		if !earlier.valid() {
			t.Fatalf("byte-identical late replay invalidated armed oracle: %+v", trace.summarize(client.TransactionID, election.agreement))
		}
	})
}

func TestPublicK5CrossedPrepareGateRejectsMismatchedArbitrationIdentity(t *testing.T) {
	clientFrame := publicK5PrepareFrame(t, proto.LeafMobilityActorClient)
	for _, test := range []struct {
		name   string
		mutate func(*proto.LeafMobilityPeerPlanPrepare)
	}{
		{
			name: "same transaction",
			mutate: func(server *proto.LeafMobilityPeerPlanPrepare) {
				client, err := proto.DecodeLeafMobilityPeerPlanPrepare(clientFrame[proto.HeaderSize:])
				if err != nil {
					t.Fatal(err)
				}
				server.TransactionID = client.TransactionID
			},
		},
		{name: "base generation", mutate: func(server *proto.LeafMobilityPeerPlanPrepare) { server.BaseGeneration++ }},
		{name: "subject route generation", mutate: func(server *proto.LeafMobilityPeerPlanPrepare) { server.SubjectRouteGeneration++ }},
		{name: "client graph", mutate: func(server *proto.LeafMobilityPeerPlanPrepare) { server.ClientGraph.Revision++ }},
	} {
		t.Run(test.name, func(t *testing.T) {
			gate := newPublicK5CrossedPrepareGate()
			serverFrame := publicK5MutatePrepareFrame(t, publicK5PrepareFrame(t, proto.LeafMobilityActorServer), test.mutate)
			publicK5CaptureTestCrossedFrames(gate, clientFrame, serverFrame)
			complete, invalid := gate.result()
			if complete || invalid == "" {
				t.Fatalf("mismatched pair completed=%t invalid=%q", complete, invalid)
			}
		})
	}
}

func TestPublicK5ExplicitProjectionEvidenceRejectsFactualProbeForgery(t *testing.T) {
	sourceTarget, resultTarget := strings.Repeat("1", 32), strings.Repeat("2", 32)
	committedAt := time.Now()
	event := publicK5MigrationEvent{
		OldID: 9, NewID: 7, Cause: "explicit", Ordinal: 1,
		AtUnixNano: committedAt.UnixNano(), CommittedAt: committedAt,
		EvidenceKind: uint8(rendr.MigrationEvidenceSelector), TransactionID: strings.Repeat("0", 32),
		TopologyEpoch: 2, HealthEpoch: 3, ProbeGenerations: []publicK5MigrationProbeGeneration{},
		Source: publicK5MigrationPathBinding{
			PathID: 9, PathOwner: 19, PathGeneration: 1, RouteGeneration: 1, EndpointGeneration: 1,
			PeerMobilityEpoch: 1, HealthRevision: 1, LocalTargetID: sourceTarget, PeerTargetID: sourceTarget,
		},
		Result: publicK5MigrationPathBinding{
			PathID: 7, PathOwner: 17, PathGeneration: 1, RouteGeneration: 1, EndpointGeneration: 1,
			PeerMobilityEpoch: 1, HealthRevision: 1, LocalTargetID: resultTarget, PeerTargetID: resultTarget,
		},
		Selector: publicK5MigrationSelectorBinding{
			SelectorID: strings.Repeat("3", 32), TargetID: resultTarget, Origin: "explicit", CutoverGeneration: 1,
		},
		Leaf: publicK5MigrationLeafBinding{},
	}
	if err := publicK5ValidateExplicitProjectionEvent(event, 9, 7); err != nil {
		t.Fatalf("factual explicit selector event was rejected: %v", err)
	}
	event.ProbeGenerations = []publicK5MigrationProbeGeneration{{
		PathID: 7, PathOwner: 17, PathGeneration: 1, RouteGeneration: 1, EndpointGeneration: 1,
	}}
	if err := publicK5ValidateExplicitProjectionEvent(event, 9, 7); err == nil {
		t.Fatal("explicit selector probe forgery was accepted")
	}
}

func publicK5CaptureTestCrossedPair(
	t testing.TB,
	gate *publicK5CrossedPrepareGate,
) (proto.LeafMobilityPeerPlanPrepare, proto.LeafMobilityPeerPlanPrepare) {
	t.Helper()
	clientFrame := publicK5PrepareFrame(t, proto.LeafMobilityActorClient)
	serverFrame := publicK5PrepareFrame(t, proto.LeafMobilityActorServer)
	publicK5CaptureTestCrossedFrames(gate, clientFrame, serverFrame)
	client, server, ok := gate.firstPair()
	if !ok {
		complete, invalid := gate.result()
		t.Fatalf("capture crossed prepare pair complete=%t invalid=%q", complete, invalid)
	}
	return client, server
}

func publicK5CaptureTestCrossedFrames(
	gate *publicK5CrossedPrepareGate,
	clientFrame, serverFrame []byte,
) {
	done := make(chan struct{}, 2)
	go func() {
		gate.wait(publicK5ControlClient, clientFrame)
		done <- struct{}{}
	}()
	go func() {
		gate.wait(publicK5ControlServer, serverFrame)
		done <- struct{}{}
	}()
	<-done
	<-done
}

type publicK5TestElection struct {
	records   []publicK5ControlRecord
	agreement [32]byte
	commit    proto.LeafMobilityPeerPlanCommit
	complete  proto.LeafMobilityPeerPlanCommit
}

func publicK5CrossedElectionRecords(
	t testing.TB,
	winner, firstServer, retryServer proto.LeafMobilityPeerPlanPrepare,
) publicK5TestElection {
	t.Helper()
	prepared := publicK5AcceptedPreparedAck(t, winner)
	commit := publicK5CommitForPrepared(prepared)
	final := prepared
	final.Phase = proto.LeafMobilityPeerPlanAckPhaseFinal
	final.Stage = proto.LeafMobilityPeerPlanCommitStageCommit
	final.CurrentGeneration = final.Generation
	final.PublicationDigest = commit.PublicationDigest
	complete := commit
	complete.Stage = proto.LeafMobilityPeerPlanCommitStageComplete
	released := final
	released.Phase = proto.LeafMobilityPeerPlanAckPhaseReleased
	released.Stage = proto.LeafMobilityPeerPlanCommitStageComplete
	firstBusy := publicK5RejectedPreparedAck(t, firstServer, proto.LeafMobilityPeerPlanAckCodeBusy)
	retryBusy := publicK5RejectedPreparedAck(t, retryServer, proto.LeafMobilityPeerPlanAckCodeBusy)
	return publicK5TestElection{
		agreement: [32]byte(prepared.AgreementDigest), commit: commit, complete: complete,
		records: []publicK5ControlRecord{
			publicK5TestControlRecord(t, publicK5ControlClient, proto.CtrlLeafMobilityPrepare, winner),
			publicK5TestControlRecord(t, publicK5ControlServer, proto.CtrlLeafMobilityAck, prepared),
			publicK5TestControlRecord(t, publicK5ControlClient, proto.CtrlLeafMobilityCommit, commit),
			publicK5TestControlRecord(t, publicK5ControlServer, proto.CtrlLeafMobilityAck, final),
			publicK5TestControlRecord(t, publicK5ControlClient, proto.CtrlLeafMobilityCommit, complete),
			publicK5TestControlRecord(t, publicK5ControlServer, proto.CtrlLeafMobilityAck, released),
			publicK5TestControlRecord(t, publicK5ControlServer, proto.CtrlLeafMobilityPrepare, firstServer),
			publicK5TestControlRecord(t, publicK5ControlClient, proto.CtrlLeafMobilityAck, firstBusy),
			publicK5TestControlRecord(t, publicK5ControlServer, proto.CtrlLeafMobilityPrepare, retryServer),
			publicK5TestControlRecord(t, publicK5ControlClient, proto.CtrlLeafMobilityAck, retryBusy),
		},
	}
}

func publicK5AcceptedPreparedAck(
	t testing.TB,
	prepare proto.LeafMobilityPeerPlanPrepare,
) proto.LeafMobilityPeerPlanAck {
	t.Helper()
	proposal, err := prepare.ProposalDigest()
	if err != nil {
		t.Fatal(err)
	}
	generation, err := prepare.ReservedGeneration()
	if err != nil {
		t.Fatal(err)
	}
	peerGeneration := prepare.ActorEndpointGeneration + 10
	peerDigest := proto.LeafMobilityPeerDigest{0x91, prepare.TransactionID[15]}
	reservation := proto.LeafMobilityReservationID{0xa1, prepare.TransactionID[15]}
	agreement, err := proto.ComputeLeafMobilityAgreementDigest(
		prepare.LeafMobilityPeerPlanBinding, generation, prepare.ActorEndpointGeneration,
		peerGeneration, proposal, peerDigest, reservation,
	)
	if err != nil {
		t.Fatal(err)
	}
	return proto.LeafMobilityPeerPlanAck{
		LeafMobilityPeerPlanBinding: prepare.LeafMobilityPeerPlanBinding,
		Phase:                       proto.LeafMobilityPeerPlanAckPhasePrepared,
		Code:                        proto.LeafMobilityPeerPlanAckCodeAccept,
		CurrentGeneration:           prepare.BaseGeneration,
		Generation:                  generation,
		ActorEndpointGeneration:     prepare.ActorEndpointGeneration,
		PeerEndpointGeneration:      peerGeneration,
		ProposalDigest:              proposal,
		PeerPlanDigest:              peerDigest,
		AgreementDigest:             agreement,
		ReservationID:               reservation,
	}
}

func publicK5RejectedPreparedAck(
	t testing.TB,
	prepare proto.LeafMobilityPeerPlanPrepare,
	code proto.LeafMobilityPeerPlanAckCode,
) proto.LeafMobilityPeerPlanAck {
	t.Helper()
	proposal, err := prepare.ProposalDigest()
	if err != nil {
		t.Fatal(err)
	}
	ack := proto.LeafMobilityPeerPlanAck{
		LeafMobilityPeerPlanBinding: prepare.LeafMobilityPeerPlanBinding,
		Phase:                       proto.LeafMobilityPeerPlanAckPhasePrepared,
		Code:                        code,
		CurrentGeneration:           prepare.BaseGeneration,
		ActorEndpointGeneration:     prepare.ActorEndpointGeneration,
		ProposalDigest:              proposal,
		Reason:                      "crossed transaction lost arbitration",
	}
	if err := ack.ValidateForPrepare(prepare); err != nil {
		t.Fatalf("build rejected prepared ACK: %v", err)
	}
	return ack
}

func publicK5CommitForPrepared(prepared proto.LeafMobilityPeerPlanAck) proto.LeafMobilityPeerPlanCommit {
	return proto.LeafMobilityPeerPlanCommit{
		LeafMobilityPeerPlanBinding: prepared.LeafMobilityPeerPlanBinding,
		Stage:                       proto.LeafMobilityPeerPlanCommitStageCommit,
		Generation:                  prepared.Generation,
		ActorEndpointGeneration:     prepared.ActorEndpointGeneration,
		PeerEndpointGeneration:      prepared.PeerEndpointGeneration,
		ProposalDigest:              prepared.ProposalDigest,
		PeerPlanDigest:              prepared.PeerPlanDigest,
		AgreementDigest:             prepared.AgreementDigest,
		ReservationID:               prepared.ReservationID,
		PublicationDigest:           proto.LeafMobilityPublicationDigest{0xb1, prepared.TransactionID[15]},
	}
}

type publicK5ControlEncoder interface {
	Encode() ([]byte, error)
}

func publicK5TestControlRecord(
	t testing.TB,
	writer publicK5ControlWriter,
	code proto.CtrlCode,
	message publicK5ControlEncoder,
) publicK5ControlRecord {
	t.Helper()
	payload, err := message.Encode()
	if err != nil {
		t.Fatal(err)
	}
	trace := &publicK5ControlTrace{}
	trace.record(writer, publicK5ControlFrame(t, code, payload))
	records := trace.snapshot()
	if len(records) != 1 || trace.malformed != 0 {
		t.Fatalf("build control record code=%s records=%d malformed=%d", code, len(records), trace.malformed)
	}
	return records[0]
}

type publicK5ControlGateSink struct {
	writes atomic.Uint64
}

func (*publicK5ControlGateSink) Read([]byte) (int, error) { return 0, io.EOF }
func (sink *publicK5ControlGateSink) Write(frame []byte) (int, error) {
	sink.writes.Add(1)
	return len(frame), nil
}
func (*publicK5ControlGateSink) Close() error                              { return nil }
func (*publicK5ControlGateSink) Quality() transport.PathQuality            { return transport.PathQuality{} }
func (*publicK5ControlGateSink) OnDeath(func(transport.DeathCause, error)) {}
func (*publicK5ControlGateSink) LocalAddr() string                         { return "gate-local" }
func (*publicK5ControlGateSink) RemoteAddr() string                        { return "gate-remote" }

func publicK5PrepareFrame(t testing.TB, actor proto.LeafMobilityActorSide) []byte {
	t.Helper()
	prepare := proto.LeafMobilityPeerPlanPrepare{
		LeafMobilityPeerPlanBinding: proto.LeafMobilityPeerPlanBinding{
			CoordinatorSide:        proto.LeafMobilityActorClient,
			ActorSide:              actor,
			Direction:              proto.SenderDirectionClientToServer,
			SessionKind:            proto.LeafMobilitySessionStream,
			Operation:              proto.LeafMobilityOperationGVisorLinkRebind,
			Fallback:               proto.LeafMobilityFallbackRedialAttach,
			LeaseMillis:            1000,
			SessionEpoch:           proto.SessionEpoch{0x11},
			TransactionID:          [16]byte{byte(actor), 0x21},
			ClientGraph:            proto.GraphBinding{Revision: 1, Digest: proto.GraphDigest{0x31}},
			ServerGraph:            proto.GraphBinding{Revision: 1, Digest: proto.GraphDigest{0x41}},
			SubjectClientTargetID:  proto.TargetID{0x51},
			SubjectServerTargetID:  proto.TargetID{0x61},
			BaseGeneration:         1,
			ResourceScope:          proto.LeafMobilityResourceSharedLink,
			ResourceID:             proto.LeafMobilityResourceID{0x71},
			SubjectRouteGeneration: 1,
		},
		ActorEndpointGeneration: 1,
		ActorPlanDigest:         proto.LeafMobilityPlanDigest{0x81},
	}
	payload, err := prepare.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return publicK5ControlFrame(t, proto.CtrlLeafMobilityPrepare, payload)
}

func publicK5MutatePrepareFrame(
	t testing.TB,
	frame []byte,
	mutate func(*proto.LeafMobilityPeerPlanPrepare),
) []byte {
	t.Helper()
	prepare, err := proto.DecodeLeafMobilityPeerPlanPrepare(frame[proto.HeaderSize:])
	if err != nil {
		t.Fatal(err)
	}
	mutate(&prepare)
	payload, err := prepare.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return publicK5ControlFrame(t, proto.CtrlLeafMobilityPrepare, payload)
}

func publicK5MalformedPrepareFrame(t testing.TB) []byte {
	t.Helper()
	return publicK5ControlFrame(t, proto.CtrlLeafMobilityPrepare, []byte{0xff})
}

func publicK5ControlFrame(t testing.TB, code proto.CtrlCode, payload []byte) []byte {
	t.Helper()
	frame := make([]byte, proto.HeaderSize+len(payload))
	header := proto.Header{Version: proto.Version, Type: proto.FrameCtrl, Flags: proto.FlagsForCtrl(code)}
	if err := header.Encode(frame[:proto.HeaderSize]); err != nil {
		t.Fatal(err)
	}
	copy(frame[proto.HeaderSize:], payload)
	return frame
}

type publicK5ControlFactory struct {
	base   transport.PathFactory
	trace  *publicK5ControlTrace
	writer publicK5ControlWriter
}

func (factory *publicK5ControlFactory) DialPath(ctx context.Context, spec transport.PathSpec) (transport.PathConn, error) {
	path, err := factory.base.DialPath(ctx, spec)
	if err != nil {
		return nil, err
	}
	return &publicK5ControlPath{PathConn: path, trace: factory.trace, writer: factory.writer}, nil
}

func (factory *publicK5ControlFactory) Probe(ctx context.Context, spec transport.PathSpec) (transport.PathQuality, error) {
	return factory.base.Probe(ctx, spec)
}

type publicK5ControlListener struct {
	base   transport.PathListener
	trace  *publicK5ControlTrace
	writer publicK5ControlWriter
}

func (listener *publicK5ControlListener) AcceptPath(ctx context.Context) (transport.PathConn, error) {
	path, err := listener.base.AcceptPath(ctx)
	if err != nil {
		return nil, err
	}
	return &publicK5ControlPath{PathConn: path, trace: listener.trace, writer: listener.writer}, nil
}

func (listener *publicK5ControlListener) SessionKind() transport.PathSessionKind {
	return listener.base.SessionKind()
}

func (listener *publicK5ControlListener) Addr() net.Addr { return listener.base.Addr() }

func (listener *publicK5ControlListener) Close() error { return listener.base.Close() }

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

func publicK5WaitForCrossedInitiators(
	t testing.TB,
	ctx context.Context,
	client, server rendr.Conn,
) (rendr.MobilityStatus, rendr.MobilityStatus) {
	t.Helper()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		clientMobility, clientOK := publicK5NamedMobility(client.Status(), "gvisor-data")
		serverMobility, serverOK := publicK5NamedMobility(server.Status(), "gvisor-data")
		clientReady := clientOK && publicK5CrossedMobilityActive(clientMobility)
		serverReady := serverOK && publicK5CrossedMobilityActive(serverMobility)
		if clientReady && serverReady {
			if clientMobility.TransactionID == serverMobility.TransactionID {
				t.Fatalf("crossed initiators reused transaction %x", clientMobility.TransactionID)
			}
			return clientMobility, serverMobility
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("wait for unsuppressed crossed gVisor initiators: client=%+v server=%+v err=%v",
				clientMobility, serverMobility, ctx.Err())
			return rendr.MobilityStatus{}, rendr.MobilityStatus{}
		}
	}
}

func publicK5CrossedMobilityActive(status rendr.MobilityStatus) bool {
	if status.TransactionID == ([16]byte{}) || status.Reason != rendr.MobilityReasonLinkUnresponsive ||
		status.Negotiated != rendr.MobilityGVisorPacketLinkRebind {
		return false
	}
	switch status.State {
	case rendr.MobilityStatePending, rendr.MobilityStateDeferred, rendr.MobilityStatePlanning,
		rendr.MobilityStateNegotiating, rendr.MobilityStateExecuting:
		return true
	default:
		return false
	}
}

func publicK5NamedMobility(status rendr.Status, name string) (rendr.MobilityStatus, bool) {
	for _, path := range status.Paths {
		if path.Name == name {
			return path.Mobility, true
		}
	}
	return rendr.MobilityStatus{}, false
}

func publicK5WaitForMigration(
	t testing.TB,
	ctx context.Context,
	events <-chan publicK5MigrationEvent,
	diagnostic func() string,
) publicK5MigrationEvent {
	t.Helper()
	select {
	case event := <-events:
		return event
	case <-ctx.Done():
		detail := ""
		if diagnostic != nil {
			detail = diagnostic()
		}
		t.Fatalf("wait for public gVisor leaf-mobility event: %v %s", ctx.Err(), detail)
		return publicK5MigrationEvent{}
	}
}

func publicK5DrainMigrationLedger(
	t testing.TB,
	observer rendr.ConnectionObserver,
	baseline uint64,
	events <-chan publicK5MigrationEvent,
	initial []publicK5MigrationEvent,
	actor string,
) []publicK5MigrationEvent {
	t.Helper()
	want := observer.MigrationCount() - baseline
	if want > uint64(cap(events)) || uint64(len(initial)) > want {
		t.Fatalf("%s migration count/event bounds baseline=%d count=%d initial=%+v",
			actor, baseline, observer.MigrationCount(), initial)
	}
	ledger := append([]publicK5MigrationEvent(nil), initial...)
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for uint64(len(ledger)) < want {
		select {
		case event := <-events:
			ledger = append(ledger, event)
		case <-deadline.C:
			t.Fatalf("%s migration callbacks did not catch up with baseline=%d count=%d events=%+v",
				actor, baseline, observer.MigrationCount(), ledger)
		}
	}
	select {
	case event := <-events:
		t.Fatalf("%s migration callback exceeds committed snapshot: baseline=%d count=%d event=%+v prior=%+v",
			actor, baseline, observer.MigrationCount(), event, ledger)
	case <-time.After(50 * time.Millisecond):
	}
	if got := observer.MigrationCount(); got != baseline+uint64(len(ledger)) {
		t.Fatalf("%s migration count changed while callbacks drained: baseline=%d count=%d events=%+v",
			actor, baseline, got, ledger)
	}
	ordered, err := publicK5NormalizeMigrationLedger(ledger, baseline)
	if err != nil {
		t.Fatalf("%s migration ledger: %v", actor, err)
	}
	return ordered
}

func publicK5NormalizeMigrationLedger(
	events []publicK5MigrationEvent,
	baseline uint64,
) ([]publicK5MigrationEvent, error) {
	ordered := append([]publicK5MigrationEvent(nil), events...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Ordinal < ordered[j].Ordinal })
	var previousAt time.Time
	for index, event := range ordered {
		wantOrdinal := baseline + uint64(index) + 1
		if event.Ordinal != wantOrdinal {
			return nil, fmt.Errorf("ordinal[%d]=%d, want %d in events=%+v", index, event.Ordinal, wantOrdinal, events)
		}
		if event.AtUnixNano <= 0 || event.CommittedAt.IsZero() ||
			event.AtUnixNano != event.CommittedAt.UnixNano() ||
			(index > 0 && !event.CommittedAt.After(previousAt)) {
			return nil, fmt.Errorf("commit time[%d]=%v is not strictly ordered in events=%+v", index, event.CommittedAt, events)
		}
		if event.Cause == "" {
			return nil, fmt.Errorf("event[%d] has empty cause: %+v", index, event)
		}
		previousAt = event.CommittedAt
	}
	return ordered, nil
}

func publicK5ValidateExplicitProjectionLedger(
	t testing.TB,
	events []publicK5MigrationEvent,
	baseline uint64,
	oldPathID, newPathID uint32,
	changed bool,
	actor string,
) {
	t.Helper()
	want := 0
	if changed {
		want = 1
	}
	if len(events) != want {
		t.Fatalf("post-commit %s projection events=%+v, want %d", actor, events, want)
	}
	if !changed {
		return
	}
	ordered, err := publicK5NormalizeMigrationLedger(events, baseline)
	if err != nil {
		t.Fatalf("post-commit %s projection ledger: %v", actor, err)
	}
	event := ordered[0]
	if err := publicK5ValidateExplicitProjectionEvent(event, oldPathID, newPathID); err != nil {
		t.Fatalf("post-commit %s projection event=%+v, want %d->%d explicit",
			actor, event, oldPathID, newPathID)
	}
}

func publicK5ValidateExplicitProjectionEvent(event publicK5MigrationEvent, oldPathID, newPathID uint32) error {
	if event.OldID != oldPathID || event.NewID != newPathID || event.Cause != "explicit" ||
		event.EvidenceKind != uint8(rendr.MigrationEvidenceSelector) || event.TopologyEpoch == 0 ||
		event.HealthEpoch == 0 ||
		!publicK5HasZeroLeafEvidence(event) || len(event.ProbeGenerations) != 0 {
		return fmt.Errorf("invalid explicit selector evidence: %+v", event)
	}
	if err := publicK5ValidateOwnedPathBinding("explicit source", event.Source, oldPathID, 0, 0, "", ""); err != nil {
		return err
	}
	if err := publicK5ValidateOwnedPathBinding("explicit result", event.Result, newPathID, 0, 0, "", ""); err != nil {
		return err
	}
	if event.Selector.Origin != "explicit" || !publicK5ValidNonzeroID(event.Selector.SelectorID) ||
		!publicK5ValidNonzeroID(event.Selector.TargetID) || event.Selector.TargetID != event.Result.LocalTargetID ||
		event.Selector.CutoverGeneration == 0 || event.Selector.CapturedAtUnixNano != 0 ||
		event.Selector.ValidUntilUnixNano != 0 || !publicK5ZeroLeafBinding(event.Leaf) {
		return fmt.Errorf("explicit selector binding is incomplete or claims probe freshness: %+v", event)
	}
	return nil
}

type publicK5FrozenSelectorBindings struct {
	Data    publicK5MigrationPathBinding
	Control publicK5MigrationPathBinding
}

func publicK5FreezeSelectorPathBindings(
	t testing.TB,
	ctx context.Context,
	conn rendr.Conn,
	dataPathID, controlPathID uint32,
	actor string,
) publicK5FrozenSelectorBindings {
	t.Helper()
	observer, ok := conn.(rendr.ConnectionObserver)
	if !ok {
		t.Fatalf("public %s %T does not implement ConnectionObserver", actor, conn)
	}
	controller, ok := conn.(rendr.MigrationController)
	if !ok {
		t.Fatalf("public %s %T does not implement MigrationController", actor, conn)
	}
	if active := observer.ActivePath(); active != dataPathID {
		t.Fatalf("public %s pre-blackhole active path=%d, want data path %d", actor, active, dataPathID)
	}

	events := make(chan publicK5MigrationEvent, 4)
	subscription := observer.OnMigrationEvent(func(event rendr.MigrationEvent) {
		events <- publicK5MigrationEventFromRendr(event)
	})
	defer subscription.Cancel()
	baseline := subscription.AfterOrdinal()
	if err := controller.SelectTarget("gvisor-public-root", "control"); err != nil {
		t.Fatalf("public %s select control for pre-blackhole binding freeze: %v", actor, err)
	}
	toControl := publicK5WaitForMigration(t, ctx, events, func() string {
		return fmt.Sprintf("actor=%s status=%+v", actor, conn.Status())
	})
	if err := controller.SelectTarget("gvisor-public-root", "gvisor-data"); err != nil {
		t.Fatalf("public %s restore data after pre-blackhole binding freeze: %v", actor, err)
	}
	toData := publicK5WaitForMigration(t, ctx, events, func() string {
		return fmt.Sprintf("actor=%s status=%+v", actor, conn.Status())
	})
	ordered := publicK5DrainMigrationLedger(
		t, observer, baseline, events, []publicK5MigrationEvent{toControl, toData}, actor+" pre-blackhole freeze",
	)
	if len(ordered) != 2 {
		t.Fatalf("public %s pre-blackhole freeze events=%+v, want two explicit selections", actor, ordered)
	}
	if err := publicK5ValidateExplicitProjectionEvent(ordered[0], dataPathID, controlPathID); err != nil {
		t.Fatalf("public %s pre-blackhole data-to-control event: %v", actor, err)
	}
	if err := publicK5ValidateExplicitProjectionEvent(ordered[1], controlPathID, dataPathID); err != nil {
		t.Fatalf("public %s pre-blackhole control-to-data event: %v", actor, err)
	}
	if !publicK5PathBindingFollows(ordered[0].Source, ordered[1].Result) ||
		!publicK5PathBindingFollows(ordered[0].Result, ordered[1].Source) {
		t.Fatalf("public %s pre-blackhole path identity changed during freeze: %+v", actor, ordered)
	}
	if observer.ActivePath() != dataPathID {
		t.Fatalf("public %s pre-blackhole freeze did not restore data path", actor)
	}

	subscription.Cancel()
	select {
	case <-subscription.Done():
	case <-ctx.Done():
		t.Fatalf("public %s pre-blackhole subscription did not quiesce: %v", actor, ctx.Err())
	}
	if err := subscription.Err(); err != nil {
		t.Fatalf("public %s pre-blackhole subscription ended with %v", actor, err)
	}
	return publicK5FrozenSelectorBindings{Data: ordered[1].Result, Control: ordered[1].Source}
}

func publicK5PathBindingFollows(
	before, after publicK5MigrationPathBinding,
) bool {
	return before.PathID == after.PathID && before.PathOwner == after.PathOwner &&
		before.PathGeneration == after.PathGeneration && before.RouteGeneration == after.RouteGeneration &&
		before.EndpointGeneration == after.EndpointGeneration && before.PeerMobilityEpoch == after.PeerMobilityEpoch &&
		before.LocalTargetID == after.LocalTargetID && before.PeerTargetID == after.PeerTargetID &&
		after.HealthRevision >= before.HealthRevision
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

func publicK5WaitForAttachedPaths(t testing.TB, ctx context.Context, conn rendr.Conn, names []string, within time.Duration) {
	t.Helper()
	deadline := time.NewTimer(within)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		status := conn.Status()
		attached := make(map[string]bool, len(status.Paths))
		for _, path := range status.Paths {
			if path.State == rendr.PathAttached && path.ID != 0 {
				attached[path.Name] = true
			}
		}
		complete := true
		for _, name := range names {
			if !attached[name] {
				complete = false
				break
			}
		}
		if complete {
			return
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatalf("public Runtime paths %v did not attach: status=%+v", names, status)
		case <-ctx.Done():
			t.Fatalf("public Runtime paths %v did not attach before context ended: status=%+v err=%v", names, status, ctx.Err())
		}
	}
}

func publicK5PathCounters(t testing.TB, paths []rendr.PathInfo, name string) publicK5PathCounter {
	t.Helper()
	for _, path := range paths {
		if path.Spec.Opts["name"] == name {
			return publicK5PathCounter{
				Reads: path.Reads, Writes: path.Writes,
				DataWrites: path.DataWrites, ControlWrites: path.ControlWrites,
			}
		}
	}
	t.Fatalf("public path inventory has no %q path: %+v", name, paths)
	return publicK5PathCounter{}
}

func publicK5PathID(t testing.TB, paths []rendr.PathInfo, name string) uint32 {
	t.Helper()
	for _, path := range paths {
		if path.Spec.Opts["name"] == name && path.ID != 0 {
			return path.ID
		}
	}
	t.Fatalf("public path inventory has no attached %q path: %+v", name, paths)
	return 0
}

func publicK5OuterWireInventory(owner *linkOwner) string {
	if owner == nil {
		return "nil"
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	wires := make([]string, 0, len(owner.wires))
	for wire := range owner.wires {
		local := "nil"
		if wire != nil && wire.conn != nil && wire.conn.LocalAddr() != nil {
			local = wire.conn.LocalAddr().String()
		}
		wires = append(wires, fmt.Sprintf("%s(active=%t predecessor=%t receiving=%t)",
			local, owner.active == wire, owner.predecessor == wire, wire != nil && wire.receiving.Load()))
	}
	return fmt.Sprintf("incarnation=%d local_generation=%d peer_generation=%d fault=%t/%d maintenance=%t activation_pending=%t pending_refresh=%t wires=%v",
		owner.incarnation, owner.localGeneration, owner.peerGeneration, owner.wireFault, owner.wireFaultReason,
		owner.maintenance, owner.activationPending, owner.pendingRefresh != nil, wires)
}

type publicK5CandidateAttempt struct {
	Actor                              string
	StartedAt, FinishedAt              int64
	Incarnation, LocalGen, PeerGen     uint64
	Remote, CandidateLocal, ErrorCause string
}

type publicK5CandidateTrace struct {
	mu       sync.Mutex
	attempts []publicK5CandidateAttempt
}

func installPublicK5CandidateTrace(owner *linkOwner, actor string) *publicK5CandidateTrace {
	trace := &publicK5CandidateTrace{}
	owner.mu.Lock()
	open := owner.openCandidate
	owner.openCandidate = func(ctx context.Context, remote net.Addr) (*packetWire, routeObservation, error) {
		owner.mu.Lock()
		source := snapshotLinkAttemptOwnerLocked(owner)
		owner.mu.Unlock()
		attempt := publicK5CandidateAttempt{
			Actor: actor, StartedAt: time.Now().UnixNano(), Incarnation: source.incarnation,
			LocalGen: source.localGeneration, PeerGen: source.peerGeneration,
		}
		if remote != nil {
			attempt.Remote = remote.String()
		}
		trace.mu.Lock()
		index := len(trace.attempts)
		trace.attempts = append(trace.attempts, attempt)
		trace.mu.Unlock()
		candidate, observation, err := open(ctx, remote)
		attempt.FinishedAt = time.Now().UnixNano()
		if candidate != nil && candidate.conn != nil && candidate.conn.LocalAddr() != nil {
			attempt.CandidateLocal = candidate.conn.LocalAddr().String()
		}
		if err != nil {
			attempt.ErrorCause = err.Error()
		} else if cause := context.Cause(ctx); cause != nil {
			attempt.ErrorCause = cause.Error()
		}
		trace.mu.Lock()
		trace.attempts[index] = attempt
		trace.mu.Unlock()
		return candidate, observation, err
	}
	owner.mu.Unlock()
	return trace
}

func (trace *publicK5CandidateTrace) snapshot() []publicK5CandidateAttempt {
	if trace == nil {
		return nil
	}
	trace.mu.Lock()
	defer trace.mu.Unlock()
	return append([]publicK5CandidateAttempt(nil), trace.attempts...)
}

func publicK5ValidateMigrationEvents(
	t testing.TB,
	events []publicK5MigrationEvent,
	expect publicK5MigrationExpectation,
) (int, string) {
	t.Helper()
	generic, cause, err := publicK5ClassifyMigrationEvents(events, expect)
	if err != nil {
		t.Fatal(err)
	}
	return generic, cause
}

type publicK5MigrationExpectation struct {
	Baseline                  uint64
	DataPathID                uint32
	FallbackPathID            uint32
	PathOwner                 uint64
	LocalTargetID             string
	PeerTargetID              string
	SourceEndpointGeneration  uint64
	ResultEndpointGeneration  uint64
	RefreshEvidenceGeneration uint64
	WinningTransaction        [16]byte
	BlackholeAt               time.Time
	SpecializedAt             time.Time
	DataBindingBefore         publicK5MigrationPathBinding
	FallbackBindingBefore     publicK5MigrationPathBinding
	RefreshIncarnation        uint64
}

func publicK5ClassifyMigrationEvents(
	events []publicK5MigrationEvent,
	expect publicK5MigrationExpectation,
) (int, string, error) {
	if len(events) == 0 || len(events) > 2 {
		return 0, "", fmt.Errorf("public gVisor migration events=%+v, want one specialized event and at most one generic fallback", events)
	}
	ordered, err := publicK5NormalizeMigrationLedger(events, expect.Baseline)
	if err != nil {
		return 0, "", err
	}
	generic, specialized := 0, 0
	genericCause := "none"
	for _, event := range ordered {
		switch {
		case event.OldID == expect.DataPathID && event.NewID == expect.DataPathID && event.Cause == "leaf-mobility":
			specialized++
			if err := publicK5ValidateSpecializedMigrationEvent(event, expect); err != nil {
				return 0, "", err
			}
		case event.OldID == expect.DataPathID && event.NewID == expect.FallbackPathID &&
			(event.Cause == "probe-starved-data" || event.Cause == "probe-wire-timeout"):
			generic++
			genericCause = event.Cause
			if !event.CommittedAt.After(expect.BlackholeAt) || !event.CommittedAt.Before(expect.SpecializedAt) {
				return 0, "", fmt.Errorf("public generic fallback is not between blackhole and specialized repair: event=%+v blackhole=%v specialized=%v",
					event, expect.BlackholeAt, expect.SpecializedAt)
			}
			if err := publicK5ValidateSelectorFallbackEvidence(event, expect); err != nil {
				return 0, "", err
			}
		default:
			return 0, "", fmt.Errorf("public gVisor observed an uncontracted migration event: %+v", event)
		}
	}
	if specialized != 1 || generic > 1 {
		return 0, "", fmt.Errorf("public gVisor migration classification specialized=%d generic=%d events=%+v", specialized, generic, events)
	}
	return generic, genericCause, nil
}

func publicK5ValidateResponderMigrationEvents(
	t testing.TB,
	events []publicK5MigrationEvent,
	expect publicK5MigrationExpectation,
) (int, string) {
	t.Helper()
	generic, cause, err := publicK5ClassifyResponderMigrationEvents(events, expect)
	if err != nil {
		t.Fatal(err)
	}
	return generic, cause
}

func publicK5ClassifyResponderMigrationEvents(
	events []publicK5MigrationEvent,
	expect publicK5MigrationExpectation,
) (int, string, error) {
	ordered, err := publicK5NormalizeMigrationLedger(events, expect.Baseline)
	if err != nil {
		return 0, "", err
	}
	if len(ordered) > 1 {
		return 0, "", fmt.Errorf(
			"public gVisor responder migrations=%+v, want at most one factual fallback", ordered,
		)
	}
	generic := 0
	cause := "none"
	for _, event := range ordered {
		if !event.CommittedAt.After(expect.BlackholeAt) {
			return 0, "", fmt.Errorf(
				"public responder migration predates blackhole: event=%+v blackhole=%v", event, expect.BlackholeAt,
			)
		}
		if !expect.SpecializedAt.IsZero() && !event.CommittedAt.Before(expect.SpecializedAt) {
			return 0, "", fmt.Errorf(
				"public responder fallback is not before specialized repair: event=%+v specialized=%v",
				event, expect.SpecializedAt,
			)
		}
		switch {
		case event.OldID == expect.DataPathID && event.NewID == expect.FallbackPathID &&
			(event.Cause == "probe-starved-data" || event.Cause == "probe-wire-timeout"):
			if err := publicK5ValidateSelectorFallbackEvidence(event, expect); err != nil {
				return 0, "", err
			}
			generic++
			cause = event.Cause
		default:
			return 0, "", fmt.Errorf("public responder observed an uncontracted migration event: %+v", event)
		}
	}
	if generic > 1 {
		return 0, "", fmt.Errorf("public responder migration classification generic=%d events=%+v", generic, ordered)
	}
	return generic, cause, nil
}

func publicK5ValidateSpecializedMigrationEvent(
	event publicK5MigrationEvent,
	expect publicK5MigrationExpectation,
) error {
	winner := hex.EncodeToString(expect.WinningTransaction[:])
	if event.EvidenceKind != uint8(rendr.MigrationEvidenceLeafMobility) ||
		event.TransactionID != winner || winner == strings.Repeat("0", 32) ||
		event.RefreshEvidenceGeneration == 0 ||
		event.RefreshEvidenceGeneration != expect.RefreshEvidenceGeneration ||
		event.SourceEndpointGeneration == 0 ||
		event.SourceEndpointGeneration != expect.SourceEndpointGeneration ||
		event.ResultEndpointGeneration == 0 ||
		event.ResultEndpointGeneration != expect.ResultEndpointGeneration ||
		event.SourceEndpointGeneration == event.ResultEndpointGeneration ||
		event.TopologyEpoch == 0 || event.HealthEpoch != 0 || len(event.ProbeGenerations) != 0 ||
		event.CommittedAt.IsZero() || !event.CommittedAt.Equal(expect.SpecializedAt) {
		return fmt.Errorf("public specialized event is not bound to the winning leaf transaction/status/claim: event=%+v expect=%+v", event, expect)
	}
	if err := publicK5ValidateFrozenPathBinding(
		"specialized source", event.Source, expect.DataBindingBefore,
		expect.SourceEndpointGeneration, expect.DataBindingBefore.HealthRevision,
	); err != nil {
		return err
	}
	if err := publicK5ValidateFrozenPathBinding(
		"specialized result", event.Result, expect.DataBindingBefore,
		expect.ResultEndpointGeneration, event.Source.HealthRevision,
	); err != nil {
		return err
	}
	if event.Source.PathGeneration != event.Result.PathGeneration ||
		event.Source.RouteGeneration != event.Result.RouteGeneration ||
		event.Source.PeerMobilityEpoch != event.Result.PeerMobilityEpoch ||
		event.Result.HealthRevision <= event.Source.HealthRevision ||
		event.Source.LocalTargetID != event.Result.LocalTargetID ||
		event.Source.PeerTargetID != event.Result.PeerTargetID ||
		!publicK5ZeroSelectorBinding(event.Selector) {
		return fmt.Errorf("public specialized event changed its logical path or forged selector evidence: %+v", event)
	}
	if event.Leaf.RefreshReason != "link_unresponsive" ||
		event.Leaf.RefreshObservedUnixNano < expect.BlackholeAt.UnixNano() ||
		event.Leaf.RefreshObservedUnixNano > event.AtUnixNano || event.Leaf.RefreshSourceGeneration == 0 ||
		!event.Leaf.RefreshSourceUsable || expect.RefreshIncarnation == 0 ||
		event.Leaf.RefreshIncarnation != expect.RefreshIncarnation {
		return fmt.Errorf("public specialized event has incomplete factual refresh evidence: %+v", event.Leaf)
	}
	return nil
}

func publicK5ValidateSelectorFallbackEvidence(
	event publicK5MigrationEvent,
	expect publicK5MigrationExpectation,
) error {
	if event.EvidenceKind != uint8(rendr.MigrationEvidenceSelector) || event.TopologyEpoch == 0 ||
		event.HealthEpoch == 0 ||
		!publicK5HasZeroLeafEvidence(event) || !publicK5ZeroLeafBinding(event.Leaf) {
		return fmt.Errorf("public selector fallback has contradictory evidence payload: %+v", event)
	}
	if err := publicK5ValidateFrozenPathBinding(
		"selector source", event.Source, expect.DataBindingBefore,
		expect.DataBindingBefore.EndpointGeneration, expect.DataBindingBefore.HealthRevision,
	); err != nil {
		return err
	}
	if err := publicK5ValidateFrozenPathBinding(
		"selector result", event.Result, expect.FallbackBindingBefore,
		expect.FallbackBindingBefore.EndpointGeneration, expect.FallbackBindingBefore.HealthRevision,
	); err != nil {
		return err
	}
	wantOrigin := "probe_failure"
	if event.Cause == "probe-starved-data" {
		wantOrigin = "probe_starved_data"
	}
	if event.Selector.Origin != wantOrigin || !publicK5ValidNonzeroID(event.Selector.SelectorID) ||
		!publicK5ValidNonzeroID(event.Selector.TargetID) || event.Selector.TargetID != event.Result.LocalTargetID ||
		event.Selector.TargetID != expect.FallbackBindingBefore.LocalTargetID ||
		event.Selector.CutoverGeneration == 0 || event.Selector.CapturedAtUnixNano <= 0 ||
		event.Selector.ValidUntilUnixNano <= event.Selector.CapturedAtUnixNano ||
		event.Selector.CapturedAtUnixNano > event.AtUnixNano ||
		event.AtUnixNano >= event.Selector.ValidUntilUnixNano {
		return fmt.Errorf("public selector fallback lacks exact policy/freshness binding: %+v", event.Selector)
	}
	if len(event.ProbeGenerations) != 2 {
		return fmt.Errorf("public selector fallback probe vector=%+v, want exactly the data and fallback paths", event.ProbeGenerations)
	}
	var sawData, sawFallback bool
	var previous publicK5MigrationProbeGeneration
	for index, probe := range event.ProbeGenerations {
		if probe.PathID == 0 || probe.PathOwner == 0 || probe.PathGeneration == 0 ||
			probe.RouteGeneration == 0 || probe.HealthRevision == 0 {
			return fmt.Errorf("public selector fallback has incomplete probe generation[%d]=%+v", index, probe)
		}
		if index > 0 && !publicK5ProbeGenerationLess(previous, probe) {
			return fmt.Errorf("public selector fallback probe vector is duplicate or unsorted: %+v", event.ProbeGenerations)
		}
		previous = probe
		var binding publicK5MigrationPathBinding
		switch probe.PathID {
		case expect.DataPathID:
			if sawData || probe.PathOwner != expect.DataBindingBefore.PathOwner ||
				probe.EndpointGeneration != expect.DataBindingBefore.EndpointGeneration {
				return fmt.Errorf("public selector fallback data binding mismatch: probe=%+v expect=%+v", probe, expect)
			}
			sawData = true
			binding = event.Source
		case expect.FallbackPathID:
			if sawFallback || probe.PathOwner != expect.FallbackBindingBefore.PathOwner ||
				probe.EndpointGeneration != expect.FallbackBindingBefore.EndpointGeneration {
				return fmt.Errorf("public selector fallback repeats fallback path: %+v", event.ProbeGenerations)
			}
			sawFallback = true
			binding = event.Result
		default:
			return fmt.Errorf("public selector fallback contains uncontracted path generation: %+v", probe)
		}
		if !publicK5PathBindingMatchesProbe(binding, probe) {
			return fmt.Errorf("public selector fallback path binding does not match probe generation: binding=%+v probe=%+v", binding, probe)
		}
	}
	if !sawData || !sawFallback {
		return fmt.Errorf("public selector fallback vector is incomplete: %+v", event.ProbeGenerations)
	}
	return nil
}

func publicK5HasZeroLeafEvidence(event publicK5MigrationEvent) bool {
	return event.TransactionID == strings.Repeat("0", 32) &&
		event.RefreshEvidenceGeneration == 0 && event.SourceEndpointGeneration == 0 &&
		event.ResultEndpointGeneration == 0
}

func publicK5ValidateOwnedPathBinding(
	label string,
	binding publicK5MigrationPathBinding,
	pathID uint32,
	owner, endpointGeneration uint64,
	localTargetID, peerTargetID string,
) error {
	if binding.PathID == 0 || binding.PathOwner == 0 || binding.PathGeneration == 0 ||
		binding.RouteGeneration == 0 || binding.HealthRevision == 0 ||
		!publicK5ValidNonzeroID(binding.LocalTargetID) || !publicK5ValidNonzeroID(binding.PeerTargetID) {
		return fmt.Errorf("%s path binding is incomplete: %+v", label, binding)
	}
	if binding.PathID != pathID || (owner != 0 && binding.PathOwner != owner) ||
		(endpointGeneration != 0 && binding.EndpointGeneration != endpointGeneration) ||
		(localTargetID != "" && binding.LocalTargetID != localTargetID) ||
		(peerTargetID != "" && binding.PeerTargetID != peerTargetID) {
		return fmt.Errorf("%s path binding mismatch: %+v", label, binding)
	}
	return nil
}

func publicK5ValidateFrozenPathBinding(
	label string,
	binding, frozen publicK5MigrationPathBinding,
	endpointGeneration, minimumHealthRevision uint64,
) error {
	if err := publicK5ValidateOwnedPathBinding(
		label+" frozen", frozen, frozen.PathID, frozen.PathOwner,
		frozen.EndpointGeneration, frozen.LocalTargetID, frozen.PeerTargetID,
	); err != nil {
		return err
	}
	if err := publicK5ValidateOwnedPathBinding(
		label, binding, frozen.PathID, frozen.PathOwner,
		endpointGeneration, frozen.LocalTargetID, frozen.PeerTargetID,
	); err != nil {
		return err
	}
	if binding.PathGeneration != frozen.PathGeneration ||
		binding.RouteGeneration != frozen.RouteGeneration ||
		binding.PeerMobilityEpoch != frozen.PeerMobilityEpoch ||
		binding.HealthRevision < minimumHealthRevision {
		return fmt.Errorf("%s does not match the pre-blackhole path incarnation: binding=%+v frozen=%+v", label, binding, frozen)
	}
	return nil
}

func publicK5PathBindingMatchesProbe(binding publicK5MigrationPathBinding, probe publicK5MigrationProbeGeneration) bool {
	return binding.PathID == probe.PathID && binding.PathOwner == probe.PathOwner &&
		binding.PathGeneration == probe.PathGeneration && binding.RouteGeneration == probe.RouteGeneration &&
		binding.EndpointGeneration == probe.EndpointGeneration &&
		binding.PeerMobilityEpoch == probe.PeerMobilityEpoch && binding.HealthRevision == probe.HealthRevision
}

func publicK5ValidNonzeroID(value string) bool {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 16 {
		return false
	}
	for _, octet := range decoded {
		if octet != 0 {
			return true
		}
	}
	return false
}

func publicK5ZeroSelectorBinding(binding publicK5MigrationSelectorBinding) bool {
	return binding.SelectorID == strings.Repeat("0", 32) && binding.TargetID == strings.Repeat("0", 32) &&
		binding.Origin == "" && binding.CutoverGeneration == 0 && binding.CapturedAtUnixNano == 0 &&
		binding.ValidUntilUnixNano == 0
}

func publicK5ZeroLeafBinding(binding publicK5MigrationLeafBinding) bool {
	return binding.RefreshReason == "" && binding.RefreshObservedUnixNano == 0 &&
		binding.RefreshSourceGeneration == 0 && !binding.RefreshSourceUsable && binding.RefreshIncarnation == 0
}

func publicK5ProbeGenerationLess(left, right publicK5MigrationProbeGeneration) bool {
	if left.PathID != right.PathID {
		return left.PathID < right.PathID
	}
	if left.PathOwner != right.PathOwner {
		return left.PathOwner < right.PathOwner
	}
	if left.PathGeneration != right.PathGeneration {
		return left.PathGeneration < right.PathGeneration
	}
	if left.RouteGeneration != right.RouteGeneration {
		return left.RouteGeneration < right.RouteGeneration
	}
	if left.EndpointGeneration != right.EndpointGeneration {
		return left.EndpointGeneration < right.EndpointGeneration
	}
	if left.PeerMobilityEpoch != right.PeerMobilityEpoch {
		return left.PeerMobilityEpoch < right.PeerMobilityEpoch
	}
	return left.HealthRevision < right.HealthRevision
}

func TestPublicK5MigrationEventClassifierBindsOnlyFactualBlackholeFallbacks(t *testing.T) {
	const dataPathID, fallbackPathID = uint32(7), uint32(9)
	blackholeAt := time.Now()
	genericAt := blackholeAt.Add(time.Millisecond)
	specializedAt := genericAt.Add(time.Millisecond)
	winner := [16]byte{1, 2, 3, 4}
	dataLocalTarget := strings.Repeat("1", 32)
	dataPeerTarget := strings.Repeat("2", 32)
	fallbackLocalTarget := strings.Repeat("3", 32)
	fallbackPeerTarget := strings.Repeat("4", 32)
	dataBindingBefore := publicK5MigrationPathBinding{
		PathID: dataPathID, PathOwner: 17, PathGeneration: 2, RouteGeneration: 3,
		EndpointGeneration: 3, PeerMobilityEpoch: 6, HealthRevision: 4,
		LocalTargetID: dataLocalTarget, PeerTargetID: dataPeerTarget,
	}
	fallbackBindingBefore := publicK5MigrationPathBinding{
		PathID: fallbackPathID, PathOwner: 19, PathGeneration: 2, RouteGeneration: 4,
		EndpointGeneration: 1, PeerMobilityEpoch: 8, HealthRevision: 6,
		LocalTargetID: fallbackLocalTarget, PeerTargetID: fallbackPeerTarget,
	}
	expect := publicK5MigrationExpectation{
		Baseline: 5, DataPathID: dataPathID, FallbackPathID: fallbackPathID, PathOwner: 17,
		LocalTargetID: dataLocalTarget, PeerTargetID: dataPeerTarget,
		SourceEndpointGeneration: 3, ResultEndpointGeneration: 4, RefreshEvidenceGeneration: 5,
		WinningTransaction: winner, BlackholeAt: blackholeAt, SpecializedAt: specializedAt,
		DataBindingBefore: dataBindingBefore, FallbackBindingBefore: fallbackBindingBefore,
		RefreshIncarnation: 9,
	}
	specialized := func(ordinal uint64) publicK5MigrationEvent {
		return publicK5MigrationEvent{
			OldID: dataPathID, NewID: dataPathID, Cause: "leaf-mobility", Ordinal: ordinal,
			AtUnixNano: specializedAt.UnixNano(), CommittedAt: specializedAt,
			EvidenceKind: uint8(rendr.MigrationEvidenceLeafMobility), TransactionID: hex.EncodeToString(winner[:]),
			RefreshEvidenceGeneration: 5, SourceEndpointGeneration: 3, ResultEndpointGeneration: 4,
			TopologyEpoch: 9, ProbeGenerations: []publicK5MigrationProbeGeneration{},
			Source: publicK5MigrationPathBinding{
				PathID: dataPathID, PathOwner: 17, PathGeneration: 2, RouteGeneration: 3,
				EndpointGeneration: 3, PeerMobilityEpoch: 6, HealthRevision: 5,
				LocalTargetID: dataLocalTarget, PeerTargetID: dataPeerTarget,
			},
			Result: publicK5MigrationPathBinding{
				PathID: dataPathID, PathOwner: 17, PathGeneration: 2, RouteGeneration: 3,
				EndpointGeneration: 4, PeerMobilityEpoch: 6, HealthRevision: 6,
				LocalTargetID: dataLocalTarget, PeerTargetID: dataPeerTarget,
			},
			Leaf: publicK5MigrationLeafBinding{
				RefreshReason: "link_unresponsive", RefreshObservedUnixNano: genericAt.UnixNano(),
				RefreshSourceGeneration: 8, RefreshSourceUsable: true, RefreshIncarnation: 9,
			},
			Selector: publicK5MigrationSelectorBinding{
				SelectorID: strings.Repeat("0", 32), TargetID: strings.Repeat("0", 32),
			},
		}
	}
	generic := func(cause string, ordinal uint64) publicK5MigrationEvent {
		return publicK5MigrationEvent{
			OldID: dataPathID, NewID: fallbackPathID, Cause: cause, Ordinal: ordinal,
			AtUnixNano: genericAt.UnixNano(), CommittedAt: genericAt,
			EvidenceKind: uint8(rendr.MigrationEvidenceSelector), TransactionID: strings.Repeat("0", 32),
			TopologyEpoch: 8, HealthEpoch: 11,
			Source: publicK5MigrationPathBinding{
				PathID: dataPathID, PathOwner: 17, PathGeneration: 2, RouteGeneration: 3,
				EndpointGeneration: 3, PeerMobilityEpoch: 6, HealthRevision: 5,
				LocalTargetID: dataLocalTarget, PeerTargetID: dataPeerTarget,
			},
			Result: publicK5MigrationPathBinding{
				PathID: fallbackPathID, PathOwner: 19, PathGeneration: 2, RouteGeneration: 4,
				EndpointGeneration: 1, PeerMobilityEpoch: 8, HealthRevision: 7,
				LocalTargetID: fallbackLocalTarget, PeerTargetID: fallbackPeerTarget,
			},
			Selector: publicK5MigrationSelectorBinding{
				SelectorID: strings.Repeat("5", 32), TargetID: fallbackLocalTarget,
				Origin:            map[bool]string{true: "probe_starved_data", false: "probe_failure"}[cause == "probe-starved-data"],
				CutoverGeneration: 10, CapturedAtUnixNano: blackholeAt.UnixNano(), ValidUntilUnixNano: specializedAt.UnixNano(),
			},
			ProbeGenerations: []publicK5MigrationProbeGeneration{
				{PathID: dataPathID, PathOwner: 17, PathGeneration: 2, RouteGeneration: 3, EndpointGeneration: 3, PeerMobilityEpoch: 6, HealthRevision: 5},
				{PathID: fallbackPathID, PathOwner: 19, PathGeneration: 2, RouteGeneration: 4, EndpointGeneration: 1, PeerMobilityEpoch: 8, HealthRevision: 7},
			},
		}
	}
	clone := func(event publicK5MigrationEvent) publicK5MigrationEvent {
		event.ProbeGenerations = append([]publicK5MigrationProbeGeneration(nil), event.ProbeGenerations...)
		return event
	}
	tests := []struct {
		name      string
		mutate    func(*publicK5MigrationEvent, *publicK5MigrationEvent)
		wantCount int
		wantCause string
		wantError bool
	}{
		{name: "factual binding", wantCount: 1, wantCause: "probe-wire-timeout"},
		{name: "old transaction", wantError: true, mutate: func(_ *publicK5MigrationEvent, s *publicK5MigrationEvent) { s.TransactionID = strings.Repeat("a", 32) }},
		{name: "loser transaction", wantError: true, mutate: func(_ *publicK5MigrationEvent, s *publicK5MigrationEvent) { s.TransactionID = strings.Repeat("b", 32) }},
		{name: "zero refresh generation", wantError: true, mutate: func(_ *publicK5MigrationEvent, s *publicK5MigrationEvent) { s.RefreshEvidenceGeneration = 0 }},
		{name: "stale refresh generation", wantError: true, mutate: func(_ *publicK5MigrationEvent, s *publicK5MigrationEvent) { s.RefreshEvidenceGeneration-- }},
		{name: "swapped endpoint generations", wantError: true, mutate: func(_ *publicK5MigrationEvent, s *publicK5MigrationEvent) {
			s.SourceEndpointGeneration, s.ResultEndpointGeneration = s.ResultEndpointGeneration, s.SourceEndpointGeneration
		}},
		{name: "equal endpoint generations", wantError: true, mutate: func(_ *publicK5MigrationEvent, s *publicK5MigrationEvent) {
			s.ResultEndpointGeneration = s.SourceEndpointGeneration
		}},
		{name: "zero source endpoint", wantError: true, mutate: func(_ *publicK5MigrationEvent, s *publicK5MigrationEvent) { s.SourceEndpointGeneration = 0 }},
		{name: "zero result endpoint", wantError: true, mutate: func(_ *publicK5MigrationEvent, s *publicK5MigrationEvent) { s.ResultEndpointGeneration = 0 }},
		{name: "leaf source binding generation mismatch", wantError: true, mutate: func(_ *publicK5MigrationEvent, s *publicK5MigrationEvent) { s.Source.EndpointGeneration++ }},
		{name: "leaf result binding target missing", wantError: true, mutate: func(_ *publicK5MigrationEvent, s *publicK5MigrationEvent) {
			s.Result.LocalTargetID = strings.Repeat("0", 32)
		}},
		{name: "leaf refresh reason changed", wantError: true, mutate: func(_ *publicK5MigrationEvent, s *publicK5MigrationEvent) {
			s.Leaf.RefreshReason = "route_source_changed"
		}},
		{name: "leaf refresh time missing", wantError: true, mutate: func(_ *publicK5MigrationEvent, s *publicK5MigrationEvent) { s.Leaf.RefreshObservedUnixNano = 0 }},
		{name: "leaf refresh predates blackhole", wantError: true, mutate: func(_ *publicK5MigrationEvent, s *publicK5MigrationEvent) {
			s.Leaf.RefreshObservedUnixNano = blackholeAt.UnixNano() - 1
		}},
		{name: "leaf refresh source generation missing", wantError: true, mutate: func(_ *publicK5MigrationEvent, s *publicK5MigrationEvent) { s.Leaf.RefreshSourceGeneration = 0 }},
		{name: "leaf refresh source unusable", wantError: true, mutate: func(_ *publicK5MigrationEvent, s *publicK5MigrationEvent) { s.Leaf.RefreshSourceUsable = false }},
		{name: "leaf refresh incarnation missing", wantError: true, mutate: func(_ *publicK5MigrationEvent, s *publicK5MigrationEvent) { s.Leaf.RefreshIncarnation = 0 }},
		{name: "leaf refresh incarnation mismatch", wantError: true, mutate: func(_ *publicK5MigrationEvent, s *publicK5MigrationEvent) { s.Leaf.RefreshIncarnation++ }},
		{name: "specialized kind mismatch", wantError: true, mutate: func(_ *publicK5MigrationEvent, s *publicK5MigrationEvent) {
			s.EvidenceKind = uint8(rendr.MigrationEvidenceRoute)
		}},
		{name: "specialized health epoch forged", wantError: true, mutate: func(_ *publicK5MigrationEvent, s *publicK5MigrationEvent) {
			s.HealthEpoch = 1
		}},
		{name: "leaf result health revision did not advance", wantError: true, mutate: func(_ *publicK5MigrationEvent, s *publicK5MigrationEvent) {
			s.Result.HealthRevision = s.Source.HealthRevision
		}},
		{name: "specialized selector vector", wantError: true, mutate: func(g *publicK5MigrationEvent, s *publicK5MigrationEvent) {
			s.ProbeGenerations = append([]publicK5MigrationProbeGeneration(nil), g.ProbeGenerations...)
		}},
		{name: "generic kind mismatch", wantError: true, mutate: func(g *publicK5MigrationEvent, _ *publicK5MigrationEvent) {
			g.EvidenceKind = uint8(rendr.MigrationEvidenceRoute)
		}},
		{name: "generic leaf transaction", wantError: true, mutate: func(g *publicK5MigrationEvent, _ *publicK5MigrationEvent) {
			g.TransactionID = hex.EncodeToString(winner[:])
		}},
		{name: "incomplete vector", wantError: true, mutate: func(g *publicK5MigrationEvent, _ *publicK5MigrationEvent) {
			g.ProbeGenerations = g.ProbeGenerations[:1]
		}},
		{name: "duplicate vector", wantError: true, mutate: func(g *publicK5MigrationEvent, _ *publicK5MigrationEvent) {
			g.ProbeGenerations[1] = g.ProbeGenerations[0]
		}},
		{name: "unsorted vector", wantError: true, mutate: func(g *publicK5MigrationEvent, _ *publicK5MigrationEvent) {
			g.ProbeGenerations[0], g.ProbeGenerations[1] = g.ProbeGenerations[1], g.ProbeGenerations[0]
		}},
		{name: "wrong owner", wantError: true, mutate: func(g *publicK5MigrationEvent, _ *publicK5MigrationEvent) { g.ProbeGenerations[0].PathOwner++ }},
		{name: "wrong source generation", wantError: true, mutate: func(g *publicK5MigrationEvent, _ *publicK5MigrationEvent) { g.ProbeGenerations[0].EndpointGeneration++ }},
		{name: "selector source binding owner changed", wantError: true, mutate: func(g *publicK5MigrationEvent, _ *publicK5MigrationEvent) { g.Source.PathOwner++ }},
		{name: "selector result binding route missing", wantError: true, mutate: func(g *publicK5MigrationEvent, _ *publicK5MigrationEvent) { g.Result.RouteGeneration = 0 }},
		{name: "selector source peer epoch missing", wantError: true, mutate: func(g *publicK5MigrationEvent, _ *publicK5MigrationEvent) { g.Source.PeerMobilityEpoch = 0 }},
		{name: "selector source target missing", wantError: true, mutate: func(g *publicK5MigrationEvent, _ *publicK5MigrationEvent) {
			g.Source.LocalTargetID = strings.Repeat("0", 32)
		}},
		{name: "selector identity missing", wantError: true, mutate: func(g *publicK5MigrationEvent, _ *publicK5MigrationEvent) {
			g.Selector.SelectorID = strings.Repeat("0", 32)
		}},
		{name: "selector target mismatch", wantError: true, mutate: func(g *publicK5MigrationEvent, _ *publicK5MigrationEvent) {
			g.Selector.TargetID = g.Source.LocalTargetID
		}},
		{name: "selector origin changed", wantError: true, mutate: func(g *publicK5MigrationEvent, _ *publicK5MigrationEvent) { g.Selector.Origin = "quality" }},
		{name: "selector cutover missing", wantError: true, mutate: func(g *publicK5MigrationEvent, _ *publicK5MigrationEvent) { g.Selector.CutoverGeneration = 0 }},
		{name: "selector capture missing", wantError: true, mutate: func(g *publicK5MigrationEvent, _ *publicK5MigrationEvent) { g.Selector.CapturedAtUnixNano = 0 }},
		{name: "selector freshness inverted", wantError: true, mutate: func(g *publicK5MigrationEvent, _ *publicK5MigrationEvent) {
			g.Selector.ValidUntilUnixNano = g.Selector.CapturedAtUnixNano
		}},
		{name: "selector freshness expired at commit", wantError: true, mutate: func(g *publicK5MigrationEvent, _ *publicK5MigrationEvent) {
			g.Selector.ValidUntilUnixNano = g.AtUnixNano
		}},
		{name: "selector coordinated fallback forgery", wantError: true, mutate: func(g *publicK5MigrationEvent, _ *publicK5MigrationEvent) {
			forgedTarget := strings.Repeat("e", 32)
			g.Result.PathOwner++
			g.Result.LocalTargetID = forgedTarget
			g.ProbeGenerations[1].PathOwner++
			g.Selector.TargetID = forgedTarget
		}},
		{name: "zero path generation", wantError: true, mutate: func(g *publicK5MigrationEvent, _ *publicK5MigrationEvent) { g.ProbeGenerations[0].PathGeneration = 0 }},
		{name: "zero route generation", wantError: true, mutate: func(g *publicK5MigrationEvent, _ *publicK5MigrationEvent) { g.ProbeGenerations[0].RouteGeneration = 0 }},
		{name: "zero health epoch", wantError: true, mutate: func(g *publicK5MigrationEvent, _ *publicK5MigrationEvent) { g.HealthEpoch = 0 }},
		{name: "zero health revision", wantError: true, mutate: func(g *publicK5MigrationEvent, _ *publicK5MigrationEvent) { g.ProbeGenerations[0].HealthRevision = 0 }},
		{name: "zero topology", wantError: true, mutate: func(g *publicK5MigrationEvent, _ *publicK5MigrationEvent) { g.TopologyEpoch = 0 }},
		{name: "unknown cause", wantError: true, mutate: func(g *publicK5MigrationEvent, _ *publicK5MigrationEvent) { g.Cause = "selector" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			g, s := clone(generic("probe-wire-timeout", 6)), clone(specialized(7))
			if test.mutate != nil {
				test.mutate(&g, &s)
			}
			count, cause, err := publicK5ClassifyMigrationEvents([]publicK5MigrationEvent{g, s}, expect)
			if (err != nil) != test.wantError {
				t.Fatalf("classification count=%d cause=%q error=%v", count, cause, err)
			}
			if err == nil && (count != test.wantCount || cause != test.wantCause) {
				t.Fatalf("classification count/cause=%d/%q want %d/%q", count, cause, test.wantCount, test.wantCause)
			}
		})
	}
	t.Run("callback arrival order is irrelevant", func(t *testing.T) {
		count, cause, err := publicK5ClassifyMigrationEvents([]publicK5MigrationEvent{
			specialized(7), generic("probe-wire-timeout", 6),
		}, expect)
		if err != nil || count != 1 || cause != "probe-wire-timeout" {
			t.Fatalf("reversed callback classification count/cause/error=%d/%q/%v", count, cause, err)
		}
	})
	t.Run("serialized commit time diverges from callback fact", func(t *testing.T) {
		g, s := generic("probe-wire-timeout", 6), specialized(7)
		g.AtUnixNano = specializedAt.UnixNano() + 1
		s.AtUnixNano = blackholeAt.UnixNano() - 1
		if count, cause, err := publicK5ClassifyMigrationEvents([]publicK5MigrationEvent{g, s}, expect); err == nil {
			t.Fatalf("divergent commit time passed classification count/cause=%d/%q", count, cause)
		}
	})
	t.Run("specialized only", func(t *testing.T) {
		count, cause, err := publicK5ClassifyMigrationEvents(
			[]publicK5MigrationEvent{specialized(expect.Baseline + 1)}, expect,
		)
		if err != nil || count != 0 || cause != "none" {
			t.Fatalf("specialized-only classification count/cause/error=%d/%q/%v", count, cause, err)
		}
	})
}

func TestPublicK5ResponderMigrationClassifierRejectsExtraCommit(t *testing.T) {
	const dataPathID, fallbackPathID = uint32(11), uint32(13)
	blackholeAt := time.Now()
	eventAt := blackholeAt.Add(time.Millisecond)
	dataLocalTarget, dataPeerTarget := strings.Repeat("6", 32), strings.Repeat("7", 32)
	fallbackLocalTarget, fallbackPeerTarget := strings.Repeat("8", 32), strings.Repeat("9", 32)
	dataBindingBefore := publicK5MigrationPathBinding{
		PathID: dataPathID, PathOwner: 23, PathGeneration: 1, RouteGeneration: 2,
		EndpointGeneration: 2, PeerMobilityEpoch: 3, HealthRevision: 2,
		LocalTargetID: dataLocalTarget, PeerTargetID: dataPeerTarget,
	}
	fallbackBindingBefore := publicK5MigrationPathBinding{
		PathID: fallbackPathID, PathOwner: 29, PathGeneration: 1, RouteGeneration: 3,
		EndpointGeneration: 1, PeerMobilityEpoch: 4, HealthRevision: 3,
		LocalTargetID: fallbackLocalTarget, PeerTargetID: fallbackPeerTarget,
	}
	expect := publicK5MigrationExpectation{
		Baseline: 9, DataPathID: dataPathID, FallbackPathID: fallbackPathID,
		PathOwner: 23, SourceEndpointGeneration: 2, BlackholeAt: blackholeAt,
		LocalTargetID: dataLocalTarget, PeerTargetID: dataPeerTarget,
		SpecializedAt: eventAt.Add(time.Second), DataBindingBefore: dataBindingBefore,
		FallbackBindingBefore: fallbackBindingBefore,
	}
	event := func(oldID, newID uint32, cause string, ordinal uint64) publicK5MigrationEvent {
		return publicK5MigrationEvent{
			OldID: oldID, NewID: newID, Cause: cause, Ordinal: ordinal,
			AtUnixNano: eventAt.UnixNano(), CommittedAt: eventAt,
			EvidenceKind: uint8(rendr.MigrationEvidenceSelector), TransactionID: strings.Repeat("0", 32),
			Source: publicK5MigrationPathBinding{
				PathID: dataPathID, PathOwner: 23, PathGeneration: 1, RouteGeneration: 2,
				EndpointGeneration: 2, PeerMobilityEpoch: 3, HealthRevision: 3,
				LocalTargetID: dataLocalTarget, PeerTargetID: dataPeerTarget,
			},
			Result: publicK5MigrationPathBinding{
				PathID: fallbackPathID, PathOwner: 29, PathGeneration: 1, RouteGeneration: 3,
				EndpointGeneration: 1, PeerMobilityEpoch: 4, HealthRevision: 4,
				LocalTargetID: fallbackLocalTarget, PeerTargetID: fallbackPeerTarget,
			},
			Selector: publicK5MigrationSelectorBinding{
				SelectorID: strings.Repeat("a", 32), TargetID: fallbackLocalTarget,
				Origin:            map[bool]string{true: "probe_starved_data", false: "probe_failure"}[cause == "probe-starved-data"],
				CutoverGeneration: 5, CapturedAtUnixNano: blackholeAt.UnixNano(), ValidUntilUnixNano: eventAt.Add(time.Second).UnixNano(),
			},
			TopologyEpoch: 4, HealthEpoch: 6, ProbeGenerations: []publicK5MigrationProbeGeneration{
				{PathID: dataPathID, PathOwner: 23, PathGeneration: 1, RouteGeneration: 2, EndpointGeneration: 2, PeerMobilityEpoch: 3, HealthRevision: 3},
				{PathID: fallbackPathID, PathOwner: 29, PathGeneration: 1, RouteGeneration: 3, EndpointGeneration: 1, PeerMobilityEpoch: 4, HealthRevision: 4},
			},
		}
	}
	expired := event(dataPathID, fallbackPathID, "probe-wire-timeout", 10)
	expired.Selector.ValidUntilUnixNano = expired.AtUnixNano
	forged := event(dataPathID, fallbackPathID, "probe-wire-timeout", 10)
	forgedTarget := strings.Repeat("b", 32)
	forged.Result.PathOwner++
	forged.Result.LocalTargetID = forgedTarget
	forged.ProbeGenerations[1].PathOwner++
	forged.Selector.TargetID = forgedTarget
	tests := []struct {
		name      string
		events    []publicK5MigrationEvent
		wantCount int
		wantCause string
		wantError bool
	}{
		{name: "no responder migration", wantCause: "none"},
		{name: "one factual fallback", events: []publicK5MigrationEvent{
			event(dataPathID, fallbackPathID, "probe-wire-timeout", 10),
		}, wantCount: 1, wantCause: "probe-wire-timeout"},
		{name: "specialized responder commit", events: []publicK5MigrationEvent{
			event(dataPathID, dataPathID, "leaf-mobility", 10),
		}, wantError: true},
		{name: "wrong cause", events: []publicK5MigrationEvent{
			event(dataPathID, fallbackPathID, "death", 10),
		}, wantError: true},
		{name: "wrong fallback", events: []publicK5MigrationEvent{
			event(dataPathID, fallbackPathID+1, "probe-starved-data", 10),
		}, wantError: true},
		{name: "two fallbacks", events: []publicK5MigrationEvent{
			event(dataPathID, fallbackPathID, "probe-starved-data", 10),
			event(dataPathID, fallbackPathID, "probe-wire-timeout", 11),
		}, wantError: true},
		{name: "ordinal gap", events: []publicK5MigrationEvent{
			event(dataPathID, fallbackPathID, "probe-wire-timeout", 11),
		}, wantError: true},
		{name: "selector freshness expired at commit", events: []publicK5MigrationEvent{expired}, wantError: true},
		{name: "coordinated fallback binding forgery", events: []publicK5MigrationEvent{forged}, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			count, cause, err := publicK5ClassifyResponderMigrationEvents(test.events, expect)
			if (err != nil) != test.wantError {
				t.Fatalf("classification count=%d cause=%q error=%v", count, cause, err)
			}
			if err == nil && (count != test.wantCount || cause != test.wantCause) {
				t.Fatalf("classification count/cause=%d/%q want %d/%q", count, cause, test.wantCount, test.wantCause)
			}
		})
	}
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

var _ transport.PathFactory = (*publicK5ControlFactory)(nil)
var _ transport.PathListener = (*publicK5ControlListener)(nil)
var _ transport.PathConn = (*publicK5ControlPath)(nil)
var _ net.Conn = (*publicK5AppConn)(nil)
