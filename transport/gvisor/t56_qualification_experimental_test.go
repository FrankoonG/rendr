//go:build linux && amd64 && rendr_experimental_gvisor

package gvisor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
	basetcp "github.com/FrankoonG/rendr/transport/tcp"
)

const (
	t56CaseID                    = "T5.6-gvisor-packet-carrier-unprivileged"
	t56EvidenceMarker            = "RENDR_T5_EVIDENCE_JSON="
	t56EvidenceSchema            = "tier5-capability-v3"
	t56ControlEvidenceSchema     = "tier5-control-v2"
	t56RunIDEnv                  = "RENDR_T56_RUN_ID"
	t56PSKEnv                    = "RENDR_T56_TEST_PSK"
	t56WrongPSKEnv               = "RENDR_T56_WRONG_PSK"
	t56ControlMobilityBudget     = 2 * time.Second
	t56ControlTransactionBudget  = 5 * time.Second
	t56ControlMargin             = 500 * time.Millisecond
	t56TerminalObservationMargin = 2 * time.Second
	t56ResourceIterations        = 8
	t56ResourceStageBudget       = 100 * time.Millisecond
	t56ResourceTransactionBudget = 5 * time.Second
)

var (
	t56LocalRunIDOnce sync.Once
	t56LocalRunID     string
)

func TestGVisorT56AutomaticPacketLinkRebindQualification(t *testing.T) {
	requireOuterPacketSupport(t)
	capability := t56CapabilityEvidence(t)
	psk := t56PSK(t, t56PSKEnv)
	defer clear(psk)

	var relay *t56OpaqueUDPRelay
	observation := &publicRuntimeGVisorObservation{}
	result := runPublicRuntimeGVisorBlackholeScenario(t, publicRuntimeGVisorScenario{
		packetOptions:         []PacketOption{WithPSK(psk)},
		requireUnacknowledged: true,
		requireCrossedActors:  true,
		observation:           observation,
		relayFactory: func(t testing.TB, server net.Addr) publicRuntimeBlackholeRelay {
			relay = newT56OpaqueUDPRelay(t, server)
			return relay
		},
	})
	if relay == nil {
		t.Fatal("T5.6 opaque relay was not constructed")
	}
	relayState := relay.snapshot()
	if !relayState.treatmentValid() {
		t.Fatalf("T5.6 opaque relay stimulus=%+v", relayState)
	}

	evidence := t56TreatmentEvidence(result, *observation, relayState, capability)
	t56EmitEvidence(t, evidence, psk)
}

func TestGVisorT56NoBlackholeHasZeroAutomaticMigrations(t *testing.T) {
	fixture := newT56EngineFixture(t, t56ControlMobilityBudget)
	closed := false
	defer func() {
		if !closed {
			if err := fixture.close(); err != nil {
				t.Errorf("cleanup healthy T5.6 control: %v", err)
			}
		}
	}()

	started := time.Now()
	deadline := started.Add(outerLivenessFailure + 2*outerLivenessTick)
	roundTrips := uint64(0)
	clientPayload := bytes.Repeat([]byte{0x31}, 1024)
	serverPayload := bytes.Repeat([]byte{0x62}, 1024)
	for time.Now().Before(deadline) {
		t56EngineRoundTrip(t, fixture.client, fixture.server, clientPayload)
		t56EngineRoundTrip(t, fixture.server, fixture.client, serverPayload)
		roundTrips++
		if fixture.client.MigrationCount() != 0 || fixture.server.MigrationCount() != 0 {
			t.Fatalf("healthy packet link migrated client/server=%d/%d",
				fixture.client.MigrationCount(), fixture.server.MigrationCount())
		}
		time.Sleep(outerLivenessTick / 2)
	}
	clientStatus, clientOK := fixture.client.LeafMobilityInitiatorStatus(fixture.clientRef)
	serverStatus, serverOK := fixture.server.LeafMobilityInitiatorStatus(fixture.serverRef)
	if !clientOK || clientStatus.Phase != engine.LeafMobilityInitiatorIdle ||
		!serverOK || serverStatus.Phase != engine.LeafMobilityInitiatorIdle {
		t.Fatalf("healthy packet-link automatic status client=%+v/%t server=%+v/%t",
			clientStatus, clientOK, serverStatus, serverOK)
	}
	state := fixture.relay.snapshot()
	if state.ClientForwardedBefore == 0 || state.ServerForwardedBefore == 0 || state.DroppedOld != 0 || state.DroppedTotal != 0 {
		t.Fatalf("healthy opaque relay observation=%+v", state)
	}
	clientMigrations := fixture.client.MigrationCount()
	serverMigrations := fixture.server.MigrationCount()
	if err := fixture.close(); err != nil {
		t.Fatalf("cleanup healthy T5.6 control: %v", err)
	}
	closed = true
	t56EmitEvidence(t, t56ControlEvidence(t, "healthy-no-blackhole", map[string]string{
		"observation_duration_ns":         strconv.FormatInt(time.Since(started).Nanoseconds(), 10),
		"payload_round_trips":             strconv.FormatUint(roundTrips, 10),
		"client_migrations":               strconv.FormatUint(clientMigrations, 10),
		"server_migrations":               strconv.FormatUint(serverMigrations, 10),
		"client_phase":                    t56InitiatorPhase(clientStatus.Phase),
		"server_phase":                    t56InitiatorPhase(serverStatus.Phase),
		"relay_client_packets":            strconv.FormatUint(state.ClientForwardedBefore, 10),
		"relay_server_packets":            strconv.FormatUint(state.ServerForwardedBefore, 10),
		"relay_dropped_packets":           strconv.FormatUint(state.DroppedOld+state.DroppedTotal, 10),
		"close_errors":                    "0",
		"control_no_blackhole_migrations": strconv.FormatUint(clientMigrations+serverMigrations, 10),
	}), nil)
}

func TestGVisorT56TotalBlackholeCannotCommit(t *testing.T) {
	fixture := newT56EngineFixture(t, t56ControlTransactionBudget)
	closed := false
	defer func() {
		if !closed {
			if err := fixture.close(); err != nil {
				t.Errorf("cleanup total-blackhole T5.6 control: %v", err)
			}
		}
	}()
	clientPath := fixture.clientPath
	payload := bytes.Repeat([]byte{0x74}, 16<<10)
	t56EngineRoundTrip(t, fixture.client, fixture.server, payload)
	t56EngineRoundTrip(t, fixture.server, fixture.client, payload)

	outerBefore := observedOuterLocalTuple(t, clientPath.link)
	claimBefore := clientPath.LeafMobilityClaim().Snapshot()
	incarnationBefore := clientPath.link.LeafMobilityIncarnation()
	activeBefore := fixture.client.ActivePath()
	migrationsBefore := fixture.client.MigrationCount()
	candidateOpen := t56BoundCandidateOpen(t, clientPath.link, t56ControlMobilityBudget)
	fixture.relay.DropAllClientTuples(t)
	started := time.Now()
	t56PublishLinkUnresponsive(t, clientPath)
	status := t56WaitInitiatorPhase(t, fixture.client, fixture.clientRef,
		t56ControlTransactionBudget+t56TerminalObservationMargin, engine.LeafMobilityInitiatorFailClosed)
	totalElapsed := time.Since(started)
	candidateElapsed, candidateErr, candidateCalls := candidateOpen.snapshot(t)
	if candidateCalls != 1 || candidateErr != nil {
		t.Fatalf("total-blackhole candidate open calls/error=%d/%v elapsed=%v, want one successful invocation",
			candidateCalls, candidateErr, candidateElapsed)
	}
	if candidateElapsed <= 0 || candidateElapsed > t56ControlMobilityBudget+t56ControlMargin {
		t.Fatalf("total-blackhole candidate open elapsed=%v budget=%v", candidateElapsed, t56ControlMobilityBudget)
	}
	if status.TransactionID == (leafmobility.TransactionID{}) || status.Error == "" ||
		!strings.Contains(status.Error, "driver execution failed: stage:") ||
		!strings.Contains(status.Error, "driver execution failed: rollback:") ||
		!t56StageFailureIsTimeout(status.Error) ||
		!t56RollbackFailureIsTimeout(status.Error) {
		t.Fatalf("total-blackhole engine transaction status=%+v", status)
	}
	transactionBudget := status.Deadline.Sub(status.ObservedAt)
	if status.ObservedAt.IsZero() || status.Deadline.IsZero() || transactionBudget != t56ControlTransactionBudget ||
		totalElapsed < t56ControlTransactionBudget || totalElapsed > t56ControlTransactionBudget+t56TerminalObservationMargin {
		t.Fatalf("total-blackhole transaction observed/deadline/elapsed=%v/%v/%v budget=%v",
			status.ObservedAt, status.Deadline, totalElapsed, t56ControlTransactionBudget)
	}
	wire := t56SummarizeFailClosedTransaction(t, fixture.controlTrace, status.TransactionID)
	state := fixture.relay.snapshot()
	if state.DroppedTotal == 0 || state.NewClientTuples == 0 {
		t.Fatalf("total-blackhole did not drop a replacement candidate: %+v", state)
	}
	fixture.relay.RestoreAllClientTuples(t)

	claimAfter := clientPath.LeafMobilityClaim().Snapshot()
	incarnationAfter := clientPath.link.LeafMobilityIncarnation()
	outerAfter := observedOuterLocalTuple(t, clientPath.link)
	if claimAfter.ResourceID != claimBefore.ResourceID || claimAfter.Generation != claimBefore.Generation ||
		incarnationAfter != incarnationBefore || outerAfter != outerBefore ||
		fixture.client.ActivePath() != activeBefore || fixture.client.MigrationCount() != migrationsBefore {
		t.Fatalf("total-blackhole changed predecessor claim/incarnation/tuple before=%+v/%d/%s after=%+v/%d/%s",
			claimBefore, incarnationBefore, outerBefore, claimAfter, incarnationAfter, outerAfter)
	}
	t56EngineRoundTrip(t, fixture.client, fixture.server, payload)
	t56EngineRoundTrip(t, fixture.server, fixture.client, payload)
	if err := fixture.close(); err != nil {
		t.Fatalf("cleanup total-blackhole T5.6 control: %v", err)
	}
	closed = true
	links, addresses, pending := t56ListenerPacketState(fixture.listener)
	cleanupComplete := t56Closed(fixture.client.Closed()) && t56Closed(fixture.server.Closed()) &&
		t56Closed(fixture.listener.cleanupDone) && links == 0 && addresses == 0 && pending == 0
	if !cleanupComplete {
		t.Fatalf("total-blackhole cleanup incomplete engines/listener=%t/%t/%t state=%d/%d/%d",
			t56Closed(fixture.client.Closed()), t56Closed(fixture.server.Closed()),
			t56Closed(fixture.listener.cleanupDone), links, addresses, pending)
	}
	t56EmitEvidence(t, t56ControlEvidence(t, "total-blackhole-stage", map[string]string{
		"candidate_open_budget_ns":        strconv.FormatInt(t56ControlMobilityBudget.Nanoseconds(), 10),
		"candidate_open_elapsed_ns":       strconv.FormatInt(candidateElapsed.Nanoseconds(), 10),
		"candidate_open_succeeded":        "true",
		"transaction_deadline_ns":         strconv.FormatInt(t56ControlTransactionBudget.Nanoseconds(), 10),
		"transaction_elapsed_ns":          strconv.FormatInt(totalElapsed.Nanoseconds(), 10),
		"transaction_id":                  hex.EncodeToString(status.TransactionID[:]),
		"initiator_phase":                 t56InitiatorPhase(status.Phase),
		"bilateral_prepare_frames":        strconv.FormatUint(wire.Prepare, 10),
		"bilateral_prepared_frames":       strconv.FormatUint(wire.Prepared, 10),
		"bilateral_commit_frames":         strconv.FormatUint(wire.Commit, 10),
		"bilateral_complete_frames":       strconv.FormatUint(wire.Complete, 10),
		"bilateral_rolled_back_frames":    strconv.FormatUint(wire.RolledBack, 10),
		"bilateral_released_frames":       strconv.FormatUint(wire.Released, 10),
		"stage_error_is_timeout":          "true",
		"rollback_error_is_timeout":       "true",
		"publication_evidence_available":  "false",
		"fail_closed_without_publication": "true",
		"rollback_acknowledged":           "false",
		"predecessor_roundtrip_restored":  "true",
		"engine_path_unchanged":           "true",
		"cleanup_complete":                strconv.FormatBool(cleanupComplete),
		"endpoint_generation_before":      strconv.FormatUint(claimBefore.Generation, 10),
		"endpoint_generation_after":       strconv.FormatUint(claimAfter.Generation, 10),
		"endpoint_incarnation_before":     strconv.FormatUint(incarnationBefore, 10),
		"endpoint_incarnation_after":      strconv.FormatUint(incarnationAfter, 10),
		"relay_total_drops":               strconv.FormatUint(state.DroppedTotal, 10),
		"relay_new_client_tuples":         strconv.FormatUint(state.NewClientTuples, 10),
		"listener_links_after":            strconv.Itoa(links),
		"listener_addresses_after":        strconv.Itoa(addresses),
		"listener_pending_after":          strconv.Itoa(pending),
		"close_errors":                    "0",
		"control_total_blackhole_commits": "0",
	}), nil)
}

func TestGVisorT56MissingAndWrongPSKCannotAllocateSession(t *testing.T) {
	requireOuterPacketSupport(t)
	missingPSKRejected := false
	if listener, err := ListenPacket("127.0.0.1:0"); listener != nil || !errors.Is(err, ErrPacketTrustRequired) {
		if listener != nil {
			if closeErr := listener.Close(); closeErr != nil {
				t.Fatalf("close unexpectedly admitted unconfigured listener: %v", closeErr)
			}
		}
		t.Fatalf("missing-PSK listener=(%v,%v)", listener, err)
	} else {
		missingPSKRejected = true
	}

	psk := t56PSK(t, t56PSKEnv)
	defer clear(psk)
	listener, err := ListenPacket("127.0.0.1:0", WithPSK(psk))
	if err != nil {
		t.Fatal(err)
	}
	listenerClosed := false
	defer func() {
		if !listenerClosed {
			if closeErr := listener.Close(); closeErr != nil {
				t.Errorf("close PSK control listener: %v", closeErr)
			}
		}
	}()
	unauthDatagrams, cookieChallenges := t56UnauthenticatedAdmissionAttempt(t, listener.Addr())
	listener.packetMu.RLock()
	unauthLinks, unauthAddresses, unauthPending :=
		len(listener.packetLinks), len(listener.packetByIP), len(listener.packetPending)
	listener.packetMu.RUnlock()
	if unauthLinks != 0 || unauthAddresses != 0 || unauthPending != 0 {
		t.Fatalf("unauthenticated admission allocated state links/addresses/pending=%d/%d/%d",
			unauthLinks, unauthAddresses, unauthPending)
	}

	relay := newT56OpaqueUDPRelay(t, listener.Addr())
	relayClosed := false
	defer func() {
		if !relayClosed {
			if closeErr := relay.Close(); closeErr != nil {
				t.Errorf("close PSK control relay: %v", closeErr)
			}
		}
	}()
	wrongPSK := t56PSK(t, t56WrongPSKEnv)
	defer clear(wrongPSK)
	if bytes.Equal(psk, wrongPSK) {
		t.Fatal("T5.6 configured and wrong packet authentication keys are equal")
	}
	wrong, err := NewPacket(WithPSK(wrongPSK))
	if err != nil {
		t.Fatal(err)
	}
	wrongBefore := relay.snapshot()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	path, dialErr := wrong.DialPath(ctx, transport.PathSpec{Address: relay.Addr().String()})
	if path != nil {
		if closeErr := path.Close(); closeErr != nil {
			t.Fatalf("close unexpectedly admitted wrong-auth path: %v", closeErr)
		}
	}
	if dialErr == nil || path != nil {
		t.Fatalf("wrong PSK DialPath=(%v,%v)", path, dialErr)
	}
	wrongAfter := relay.snapshot()
	wrongDatagrams := wrongAfter.ClientDatagrams - wrongBefore.ClientDatagrams
	wrongOpens := wrongAfter.ClientOpenDatagrams - wrongBefore.ClientOpenDatagrams
	wrongCookies := wrongAfter.ServerCookieDatagrams - wrongBefore.ServerCookieDatagrams
	wrongOpenACKs := wrongAfter.ServerOpenACKDatagrams - wrongBefore.ServerOpenACKDatagrams
	admissionReached := wrongDatagrams > 0 && wrongOpens > 0 && wrongCookies > 0
	if !admissionReached || wrongOpenACKs != 0 {
		t.Fatalf("wrong-PSK packet traversal datagrams/OPEN/COOKIE/OPEN_ACK=%d/%d/%d/%d",
			wrongDatagrams, wrongOpens, wrongCookies, wrongOpenACKs)
	}
	listener.packetMu.RLock()
	wrongLinks, wrongAddresses, wrongPending :=
		len(listener.packetLinks), len(listener.packetByIP), len(listener.packetPending)
	listener.packetMu.RUnlock()
	if wrongLinks != 0 || wrongAddresses != 0 || wrongPending != 0 {
		t.Fatalf("wrong-auth admission allocated state before close links/addresses/pending=%d/%d/%d",
			wrongLinks, wrongAddresses, wrongPending)
	}
	if err := relay.Close(); err != nil {
		t.Fatalf("close PSK control relay: %v", err)
	}
	relayClosed = true
	if err := listener.Close(); err != nil {
		t.Fatalf("close PSK control listener: %v", err)
	}
	listenerClosed = true
	select {
	case <-listener.cleanupDone:
	case <-time.After(2 * time.Second):
		t.Fatal("configured PSK listener cleanup did not join")
	}
	listener.packetMu.RLock()
	links, addresses, pending := len(listener.packetLinks), len(listener.packetByIP), len(listener.packetPending)
	listener.packetMu.RUnlock()
	if links != 0 || addresses != 0 || pending != 0 {
		t.Fatalf("unauthenticated or wrong PSK admission allocated state links/addresses/pending=%d/%d/%d",
			links, addresses, pending)
	}
	t56EmitEvidence(t, t56ControlEvidence(t, "psk-admission", map[string]string{
		"configured_listener":                   "true",
		"missing_psk_configuration_rejected":    strconv.FormatBool(missingPSKRejected),
		"missing_psk_listener_started":          "false",
		"unauthenticated_open_attempts":         "1",
		"unauthenticated_datagrams":             strconv.FormatUint(unauthDatagrams, 10),
		"cookie_challenges":                     strconv.FormatUint(cookieChallenges, 10),
		"wrong_auth_dial_attempts":              "1",
		"wrong_auth_datagrams_to_admission":     strconv.FormatUint(wrongDatagrams, 10),
		"wrong_auth_open_to_admission":          strconv.FormatUint(wrongOpens, 10),
		"wrong_auth_cookie_challenges":          strconv.FormatUint(wrongCookies, 10),
		"wrong_auth_open_acks":                  strconv.FormatUint(wrongOpenACKs, 10),
		"wrong_auth_admission_boundary_reached": strconv.FormatBool(admissionReached),
		"wrong_auth_rejected_before_allocation": "true",
		"unauthenticated_rejected":              "true",
		"wrong_auth_rejected":                   "true",
		"control_missing_psk_sessions":          strconv.Itoa(unauthLinks),
		"control_wrong_psk_sessions":            strconv.Itoa(wrongLinks),
		"unauthenticated_links_after":           strconv.Itoa(unauthLinks),
		"unauthenticated_addresses_after":       strconv.Itoa(unauthAddresses),
		"unauthenticated_pending_after":         strconv.Itoa(unauthPending),
		"wrong_auth_links_before_close":         strconv.Itoa(wrongLinks),
		"wrong_auth_addresses_before_close":     strconv.Itoa(wrongAddresses),
		"wrong_auth_pending_before_close":       strconv.Itoa(wrongPending),
		"listener_links_after":                  strconv.Itoa(links),
		"listener_addresses_after":              strconv.Itoa(addresses),
		"listener_pending_after":                strconv.Itoa(pending),
		"secret_derived_evidence":               "false",
		"close_errors":                          "0",
	}), psk, wrongPSK)
}

func TestGVisorT56RepeatedControlResourceSlope(t *testing.T) {
	requireOuterPacketSupport(t)
	runtime.GC()
	baseline := t56ReadResourceSample(t)
	samples := []t56ResourceSample{baseline}
	allClosed := true
	closeErrors := uint64(0)
	successCycles := uint64(0)
	nonCommitCycles := uint64(0)
	rolledBackTransactions := uint64(0)
	failedTransactions := uint64(0)
	failClosedTransactions := uint64(0)
	successGenerationAdvances := uint64(0)
	nonCommitGenerationStable := uint64(0)
	transactionGoroutinesJoined := true
	for iteration := 0; iteration < t56ResourceIterations; iteration++ {
		payload := bytes.Repeat([]byte{byte(iteration + 1)}, 2048)
		success := newT56EngineFixture(t, t56ResourceTransactionBudget)
		successBefore := success.clientPath.LeafMobilityClaim().Snapshot()
		success.relay.DropEstablishedClient(t)
		success.relay.ReleaseReplacement(t)
		t56PublishLinkUnresponsive(t, success.clientPath)
		successStatus := t56WaitInitiatorPhase(t, success.client, success.clientRef,
			t56ResourceTransactionBudget+t56ControlMargin, engine.LeafMobilityInitiatorCommitted)
		successAfter := success.clientPath.LeafMobilityClaim().Snapshot()
		if successStatus.TransactionID == (leafmobility.TransactionID{}) || successStatus.Error != "" ||
			success.client.MigrationCount() != 1 || successAfter.Generation <= successBefore.Generation {
			t.Fatalf("resource success iteration %d status=%+v migration=%d generation=%d->%d",
				iteration, successStatus, success.client.MigrationCount(), successBefore.Generation, successAfter.Generation)
		}
		t56EngineRoundTrip(t, success.client, success.server, payload)
		t56EngineRoundTrip(t, success.server, success.client, payload)
		successCycles++
		successGenerationAdvances++
		if err := success.close(); err != nil {
			allClosed = false
			transactionGoroutinesJoined = false
			closeErrors++
			t.Errorf("resource success iteration %d cleanup: %v", iteration, err)
		}

		failure := newT56EngineFixture(t, t56ResourceTransactionBudget)
		failureBefore := failure.clientPath.LeafMobilityClaim().Snapshot()
		candidateOpen := t56FailCandidateOpenAtBudget(t, failure.clientPath.link, t56ResourceStageBudget)
		t56PublishLinkUnresponsive(t, failure.clientPath)
		failureStatus := t56WaitInitiatorTerminalNonCommit(t, failure.client, failure.clientRef,
			t56ResourceTransactionBudget+t56TerminalObservationMargin)
		candidateElapsed, candidateErr, candidateCalls := candidateOpen.snapshot(t)
		if candidateCalls != 1 || !errors.Is(candidateErr, context.DeadlineExceeded) ||
			candidateElapsed < t56ResourceStageBudget ||
			candidateElapsed > t56ResourceStageBudget+t56ControlMargin ||
			failureStatus.TransactionID == (leafmobility.TransactionID{}) ||
			!strings.Contains(failureStatus.Error, "driver execution failed: stage:") ||
			!t56StageFailureIsTimeout(failureStatus.Error) {
			t.Fatalf("resource non-commit iteration %d status=%+v candidate-open=%d/%v/%v",
				iteration, failureStatus, candidateCalls, candidateElapsed, candidateErr)
		}
		switch failureStatus.Phase {
		case engine.LeafMobilityInitiatorRolledBack:
			rolledBackTransactions++
		case engine.LeafMobilityInitiatorFailed:
			if !t56RollbackFailureIsFactual(failureStatus.Error) {
				t.Fatalf("resource failed iteration %d has no factual rollback failure: %+v", iteration, failureStatus)
			}
			failedTransactions++
		case engine.LeafMobilityInitiatorFailClosed:
			if !t56RollbackFailureIsTimeout(failureStatus.Error) {
				t.Fatalf("resource fail-closed iteration %d has no rollback timeout: %+v", iteration, failureStatus)
			}
			failClosedTransactions++
		default:
			t.Fatalf("resource iteration %d unexpected non-commit phase=%s", iteration, t56InitiatorPhase(failureStatus.Phase))
		}
		if failureStatus.Deadline.Sub(failureStatus.ObservedAt) != t56ResourceTransactionBudget ||
			failureStatus.UpdatedAt.After(failureStatus.Deadline.Add(t56TerminalObservationMargin)) {
			t.Fatalf("resource non-commit iteration %d observed/deadline/updated=%v/%v/%v",
				iteration, failureStatus.ObservedAt, failureStatus.Deadline, failureStatus.UpdatedAt)
		}
		t56SummarizeNonCommitTransaction(t, failure.controlTrace, failureStatus.TransactionID)
		failureAfter := failure.clientPath.LeafMobilityClaim().Snapshot()
		if failure.client.MigrationCount() != 0 || failureAfter.Generation != failureBefore.Generation {
			t.Fatalf("resource non-commit iteration %d migration=%d generation=%d->%d",
				iteration, failure.client.MigrationCount(), failureBefore.Generation, failureAfter.Generation)
		}
		t56EngineRoundTrip(t, failure.client, failure.server, payload)
		t56EngineRoundTrip(t, failure.server, failure.client, payload)
		nonCommitCycles++
		nonCommitGenerationStable++
		if err := failure.close(); err != nil {
			allClosed = false
			transactionGoroutinesJoined = false
			closeErrors++
			t.Errorf("resource non-commit iteration %d cleanup: %v", iteration, err)
		}
		runtime.GC()
		time.Sleep(25 * time.Millisecond)
		samples = append(samples, t56ReadResourceSample(t))
	}
	final := samples[len(samples)-1]
	fdSlope := t56ResourceSlope(samples, func(sample t56ResourceSample) uint64 { return sample.FDs })
	goroutineSlope := t56ResourceSlope(samples, func(sample t56ResourceSample) uint64 { return sample.Goroutines })
	heapSlope := t56ResourceSlope(samples, func(sample t56ResourceSample) uint64 { return sample.HeapInuse })
	fdPeak, goroutinePeak, heapPeak := t56ResourcePeaks(samples)
	valid := allClosed && transactionGoroutinesJoined && closeErrors == 0 &&
		successCycles == t56ResourceIterations && nonCommitCycles == t56ResourceIterations &&
		rolledBackTransactions+failedTransactions+failClosedTransactions == t56ResourceIterations &&
		successGenerationAdvances == t56ResourceIterations && nonCommitGenerationStable == t56ResourceIterations &&
		final.FDs <= baseline.FDs+2 &&
		final.Goroutines <= baseline.Goroutines+4 && final.HeapInuse <= baseline.HeapInuse+(32<<20) &&
		fdSlope <= 1 && goroutineSlope <= 1 && heapSlope <= 4<<20
	evidence := t56ControlEvidence(t, "bounded-resource-slope", map[string]string{
		"control_resource_iterations":      strconv.Itoa(t56ResourceIterations),
		"successful_mobility_cycles":       strconv.FormatUint(successCycles, 10),
		"noncommit_failure_cycles":         strconv.FormatUint(nonCommitCycles, 10),
		"successful_transactions":          strconv.FormatUint(successCycles, 10),
		"noncommit_transactions":           strconv.FormatUint(nonCommitCycles, 10),
		"rolled_back_transactions":         strconv.FormatUint(rolledBackTransactions, 10),
		"failed_transactions":              strconv.FormatUint(failedTransactions, 10),
		"fail_closed_transactions":         strconv.FormatUint(failClosedTransactions, 10),
		"success_generation_advances":      strconv.FormatUint(successGenerationAdvances, 10),
		"noncommit_generation_stable":      strconv.FormatUint(nonCommitGenerationStable, 10),
		"transaction_goroutines_joined":    strconv.FormatBool(transactionGoroutinesJoined),
		"fd_baseline":                      strconv.FormatUint(baseline.FDs, 10),
		"fd_final":                         strconv.FormatUint(final.FDs, 10),
		"fd_peak":                          strconv.FormatUint(fdPeak, 10),
		"fd_slope_per_iteration":           strconv.FormatInt(fdSlope, 10),
		"goroutine_baseline":               strconv.FormatUint(baseline.Goroutines, 10),
		"goroutine_final":                  strconv.FormatUint(final.Goroutines, 10),
		"goroutine_peak":                   strconv.FormatUint(goroutinePeak, 10),
		"goroutine_slope_per_iteration":    strconv.FormatInt(goroutineSlope, 10),
		"heap_inuse_baseline_bytes":        strconv.FormatUint(baseline.HeapInuse, 10),
		"heap_inuse_final_bytes":           strconv.FormatUint(final.HeapInuse, 10),
		"heap_inuse_peak_bytes":            strconv.FormatUint(heapPeak, 10),
		"heap_inuse_slope_bytes_iteration": strconv.FormatInt(heapSlope, 10),
		"all_fixture_goroutines_joined":    strconv.FormatBool(allClosed),
		"close_errors":                     strconv.FormatUint(closeErrors, 10),
	})
	evidence["control_valid"] = strconv.FormatBool(valid)
	t56EmitEvidence(t, evidence)
	if !valid {
		t.Fatalf("bounded resource slope failed baseline=%+v final=%+v fd/goroutine/heap slopes=%d/%d/%d",
			baseline, final, fdSlope, goroutineSlope, heapSlope)
	}
}

type t56OpaqueUDPRelay struct {
	conn      *net.UDPConn
	server    *net.UDPAddr
	done      chan struct{}
	wait      sync.WaitGroup
	closeOnce sync.Once
	closeErr  error

	mu                     sync.Mutex
	client                 *net.UDPAddr
	dropped                *net.UDPAddr
	replacement            *net.UDPAddr
	dropOld                bool
	dropTotal              bool
	clientForwardedBefore  uint64
	clientForwardedAfter   uint64
	serverForwardedBefore  uint64
	serverForwardedAfter   uint64
	serverAfterDestination string
	droppedOld             uint64
	droppedTotal           uint64
	newClientTuples        uint64
	clientDatagrams        uint64
	serverDatagrams        uint64
	clientOpenDatagrams    uint64
	serverCookieDatagrams  uint64
	serverOpenACKDatagrams uint64
	clientTCP              tcpPacketSummary
	serverTCP              tcpPacketSummary
}

type t56OpaqueRelaySnapshot struct {
	EstablishedTuple       string
	DroppedTuple           string
	ReplacementTuple       string
	ClientForwardedBefore  uint64
	ClientForwardedAfter   uint64
	ServerForwardedBefore  uint64
	ServerForwardedAfter   uint64
	ServerAfterDestination string
	DroppedOld             uint64
	DroppedTotal           uint64
	NewClientTuples        uint64
	ClientDatagrams        uint64
	ServerDatagrams        uint64
	ClientOpenDatagrams    uint64
	ServerCookieDatagrams  uint64
	ServerOpenACKDatagrams uint64
}

func newT56OpaqueUDPRelay(t testing.TB, server net.Addr) *t56OpaqueUDPRelay {
	t.Helper()
	serverUDP, ok := server.(*net.UDPAddr)
	if !ok {
		t.Fatalf("opaque relay server address=%T", server)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	relay := &t56OpaqueUDPRelay{
		conn: conn, server: cloneUDPAddr(serverUDP), done: make(chan struct{}),
	}
	relay.wait.Add(1)
	go relay.run()
	return relay
}

func (relay *t56OpaqueUDPRelay) Addr() net.Addr { return relay.conn.LocalAddr() }

func (relay *t56OpaqueUDPRelay) Close() error {
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

// run routes datagrams solely by their observed UDP source tuple. It never
// parses outer headers or receives authentication material.
func (relay *t56OpaqueUDPRelay) run() {
	defer relay.wait.Done()
	buffer := make([]byte, 64<<10)
	for {
		n, source, err := relay.conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		packet := append([]byte(nil), buffer[:n]...)
		if addrEqual(source, relay.server) {
			relay.forwardServer(packet)
			continue
		}
		relay.forwardClient(packet, source)
	}
}

func (relay *t56OpaqueUDPRelay) forwardServer(packet []byte) {
	header, headerErr := decodeOuterHeader(packet)
	relay.mu.Lock()
	relay.serverDatagrams++
	if headerErr == nil {
		switch header.Type {
		case outerTypeCookie:
			relay.serverCookieDatagrams++
		case outerTypeOpenAck:
			relay.serverOpenACKDatagrams++
		}
	}
	client := cloneUDPAddr(relay.client)
	if relay.dropTotal {
		relay.droppedTotal++
		relay.mu.Unlock()
		return
	}
	post := relay.dropOld
	relay.mu.Unlock()
	if client == nil {
		return
	}
	if _, err := relay.conn.WriteToUDP(packet, client); err != nil {
		return
	}
	relay.mu.Lock()
	if header.Type == outerTypeData {
		if post {
			relay.serverForwardedAfter++
			relay.serverAfterDestination = client.String()
		} else {
			relay.serverForwardedBefore++
		}
		relay.serverTCP.record(header.Payload, post)
	}
	relay.mu.Unlock()
}

func (relay *t56OpaqueUDPRelay) forwardClient(packet []byte, source *net.UDPAddr) {
	header, headerErr := decodeOuterHeader(packet)
	relay.mu.Lock()
	relay.clientDatagrams++
	if headerErr == nil && header.Type == outerTypeOpen {
		relay.clientOpenDatagrams++
	}
	if relay.client == nil {
		relay.client = cloneUDPAddr(source)
	}
	if relay.dropTotal {
		if !addrEqual(source, relay.client) {
			relay.newClientTuples++
		}
		relay.droppedTotal++
		relay.mu.Unlock()
		return
	}
	if relay.dropOld && addrEqual(source, relay.dropped) {
		relay.droppedOld++
		relay.mu.Unlock()
		return
	}
	post := relay.dropOld
	if relay.dropOld && !addrEqual(source, relay.client) {
		relay.newClientTuples++
		relay.client = cloneUDPAddr(source)
		relay.replacement = cloneUDPAddr(source)
	} else if !relay.dropOld {
		relay.client = cloneUDPAddr(source)
	}
	relay.mu.Unlock()
	if _, err := relay.conn.WriteToUDP(packet, relay.server); err != nil {
		return
	}
	relay.mu.Lock()
	if header.Type == outerTypeData {
		if post {
			relay.clientForwardedAfter++
		} else {
			relay.clientForwardedBefore++
		}
		relay.clientTCP.record(header.Payload, post)
	}
	relay.mu.Unlock()
}

func (relay *t56OpaqueUDPRelay) DropEstablishedClient(t testing.TB) string {
	dropped, _ := relay.DropEstablishedClientAt(t)
	return dropped
}

func (relay *t56OpaqueUDPRelay) DropEstablishedClientAt(t testing.TB) (string, time.Time) {
	t.Helper()
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if relay.client == nil {
		t.Fatal("opaque relay has no established client tuple")
	}
	relay.dropped = cloneUDPAddr(relay.client)
	relay.dropOld = true
	relay.dropTotal = true
	return relay.dropped.String(), time.Now()
}

func (relay *t56OpaqueUDPRelay) ReleaseReplacement(t testing.TB) {
	t.Helper()
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if !relay.dropOld || !relay.dropTotal || relay.dropped == nil {
		t.Fatal("opaque relay has no held replacement blackhole")
	}
	relay.dropTotal = false
}

func (relay *t56OpaqueUDPRelay) DropAllClientTuples(t testing.TB) {
	t.Helper()
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if relay.client == nil {
		t.Fatal("opaque relay has no established client tuple")
	}
	relay.dropped = cloneUDPAddr(relay.client)
	relay.dropOld = true
	relay.dropTotal = true
}

func (relay *t56OpaqueUDPRelay) RestoreAllClientTuples(t testing.TB) {
	t.Helper()
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if !relay.dropOld || !relay.dropTotal || relay.dropped == nil {
		t.Fatal("opaque relay has no total client blackhole to restore")
	}
	relay.dropOld = false
	relay.dropTotal = false
}

func (relay *t56OpaqueUDPRelay) PreData() uint64 {
	return relay.snapshot().ClientForwardedBefore
}

func (relay *t56OpaqueUDPRelay) PostData() uint64 {
	return relay.snapshot().ClientForwardedAfter
}

func (relay *t56OpaqueUDPRelay) ServerPreData() uint64 {
	return relay.snapshot().ServerForwardedBefore
}

func (relay *t56OpaqueUDPRelay) ServerPostData() uint64 {
	return relay.snapshot().ServerForwardedAfter
}

func (relay *t56OpaqueUDPRelay) ReplacementTuple() string {
	return relay.snapshot().ReplacementTuple
}

func (relay *t56OpaqueUDPRelay) TCPSummaries() (tcpPacketSummary, tcpPacketSummary) {
	relay.mu.Lock()
	defer relay.mu.Unlock()
	return relay.clientTCP, relay.serverTCP
}

func (relay *t56OpaqueUDPRelay) snapshot() t56OpaqueRelaySnapshot {
	relay.mu.Lock()
	defer relay.mu.Unlock()
	stringAddr := func(address *net.UDPAddr) string {
		if address == nil {
			return ""
		}
		return address.String()
	}
	return t56OpaqueRelaySnapshot{
		EstablishedTuple: stringAddr(relay.dropped), DroppedTuple: stringAddr(relay.dropped),
		ReplacementTuple:      stringAddr(relay.replacement),
		ClientForwardedBefore: relay.clientForwardedBefore, ClientForwardedAfter: relay.clientForwardedAfter,
		ServerForwardedBefore: relay.serverForwardedBefore, ServerForwardedAfter: relay.serverForwardedAfter,
		ServerAfterDestination: relay.serverAfterDestination,
		DroppedOld:             relay.droppedOld, DroppedTotal: relay.droppedTotal, NewClientTuples: relay.newClientTuples,
		ClientDatagrams: relay.clientDatagrams, ServerDatagrams: relay.serverDatagrams,
		ClientOpenDatagrams: relay.clientOpenDatagrams, ServerCookieDatagrams: relay.serverCookieDatagrams,
		ServerOpenACKDatagrams: relay.serverOpenACKDatagrams,
	}
}

func (snapshot t56OpaqueRelaySnapshot) treatmentValid() bool {
	return snapshot.DroppedTuple != "" && snapshot.ReplacementTuple != "" &&
		snapshot.DroppedTuple != snapshot.ReplacementTuple &&
		snapshot.ClientForwardedBefore > 0 && snapshot.ClientForwardedAfter > 0 &&
		snapshot.ServerForwardedBefore > 0 && snapshot.ServerForwardedAfter > 0 &&
		snapshot.ServerAfterDestination == snapshot.ReplacementTuple &&
		snapshot.DroppedTotal > 0 && snapshot.NewClientTuples > 0
}

type t56EngineFixture struct {
	listener     *Listener
	relay        *t56OpaqueUDPRelay
	client       *engine.Engine
	server       *engine.Engine
	clientPath   *retainedPathConn
	serverPath   *retainedPathConn
	clientRef    engine.PathRef
	serverRef    engine.PathRef
	controlTrace *publicK5ControlTrace
	closeOnce    sync.Once
	closeErr     error
}

type t56ControlTracePath struct {
	transport.PathConn
	trace  *publicK5ControlTrace
	writer publicK5ControlWriter
}

func (path *t56ControlTracePath) Write(frame []byte) (int, error) {
	n, err := path.PathConn.Write(frame)
	if err == nil && n == len(frame) {
		path.trace.record(path.writer, frame)
	}
	return n, err
}

func newT56EngineFixture(t testing.TB, mobilityBudget time.Duration) *t56EngineFixture {
	t.Helper()
	requireOuterPacketSupport(t)
	if mobilityBudget <= 0 || mobilityBudget > engine.DefaultLimits().MigrationBudget {
		t.Fatalf("invalid T5.6 fixture mobility budget %v", mobilityBudget)
	}
	psk := t56PSK(t, t56PSKEnv)
	listener, err := ListenPacket("127.0.0.1:0", WithPSK(psk))
	clear(psk)
	if err != nil {
		t.Fatal(err)
	}
	relay := newT56OpaqueUDPRelay(t, listener.Addr())
	clientRaw, serverRaw := t56DialAndAccept(t, listener, relay)
	clientPath := clientRaw.(*retainedPathConn)
	serverPath := serverRaw.(*retainedPathConn)
	flowID := [16]byte{0x56, 0x01}
	limits := engine.DefaultLimits()
	limits.MigrationBudget = mobilityBudget
	limits.ProbeInterval = 30 * time.Second
	client := engine.New(engine.SideClient, flowID, limits)
	server := engine.New(engine.SideServer, flowID, limits)
	dataTargetID, controlTargetID := configureGVisorEnginePair(t, client, server, clientPath, serverPath)
	dataBinding := engine.PathBinding{LocalTXTargetID: dataTargetID, PeerTXTargetID: dataTargetID}
	spec := transport.PathSpec{Transport: "gvisor", Opts: map[string]string{"name": "gvisor-data"}}
	pathID, err := client.AttachPathBound(clientPath, spec, dataBinding)
	if err != nil {
		t.Fatal(err)
	}
	serverPathID, err := server.AttachPathBound(serverPath, spec, dataBinding)
	if err != nil {
		t.Fatal(err)
	}
	clientControlConn, serverControlConn := net.Pipe()
	controlTrace := &publicK5ControlTrace{}
	controlBinding := engine.PathBinding{LocalTXTargetID: controlTargetID, PeerTXTargetID: controlTargetID}
	clientControl := &t56ControlTracePath{
		PathConn: basetcp.Wrap(clientControlConn), trace: controlTrace, writer: publicK5ControlClient,
	}
	serverControl := &t56ControlTracePath{
		PathConn: basetcp.Wrap(serverControlConn), trace: controlTrace, writer: publicK5ControlServer,
	}
	if _, err := client.AttachPathBound(clientControl, transport.PathSpec{Transport: "control"}, controlBinding); err != nil {
		t.Fatal(err)
	}
	if _, err := server.AttachPathBound(serverControl, transport.PathSpec{Transport: "control"}, controlBinding); err != nil {
		t.Fatal(err)
	}
	ref, ok := client.PathRef(pathID)
	if !ok {
		t.Fatal("T5.6 client data path has no PathRef")
	}
	serverRef, ok := server.PathRef(serverPathID)
	if !ok {
		t.Fatal("T5.6 server data path has no PathRef")
	}
	return &t56EngineFixture{
		listener: listener, relay: relay, client: client, server: server,
		clientPath: clientPath, serverPath: serverPath, clientRef: ref, serverRef: serverRef,
		controlTrace: controlTrace,
	}
}

func (fixture *t56EngineFixture) close() error {
	if fixture == nil {
		return nil
	}
	fixture.closeOnce.Do(func() {
		type closeResult struct {
			name string
			err  error
		}
		results := make(chan closeResult, 2)
		go func() { results <- closeResult{name: "client engine", err: fixture.client.Close()} }()
		go func() { results <- closeResult{name: "server engine", err: fixture.server.Close()} }()
		remaining := 2
		initialTimer := time.NewTimer(5 * time.Second)
		for remaining > 0 {
			select {
			case result := <-results:
				remaining--
				if result.err != nil {
					fixture.closeErr = errors.Join(fixture.closeErr, fmt.Errorf("close %s: %w", result.name, result.err))
				}
			case <-initialTimer.C:
				fixture.closeErr = errors.Join(fixture.closeErr, errors.New("T5.6 engine cleanup timed out"))
				remaining = -remaining
			}
		}
		if !initialTimer.Stop() {
			select {
			case <-initialTimer.C:
			default:
			}
		}
		if remaining < 0 {
			remaining = -remaining
		}
		if err := fixture.relay.Close(); err != nil {
			fixture.closeErr = errors.Join(fixture.closeErr, fmt.Errorf("close T5.6 relay: %w", err))
		}
		if err := fixture.listener.Close(); err != nil {
			fixture.closeErr = errors.Join(fixture.closeErr, fmt.Errorf("close T5.6 listener: %w", err))
		}
		cleanupTimer := time.NewTimer(5 * time.Second)
		for remaining > 0 {
			select {
			case result := <-results:
				remaining--
				if result.err != nil {
					fixture.closeErr = errors.Join(fixture.closeErr, fmt.Errorf("close %s: %w", result.name, result.err))
				}
			case <-cleanupTimer.C:
				fixture.closeErr = errors.Join(fixture.closeErr, errors.New("T5.6 engine Close goroutines did not join"))
				remaining = 0
			}
		}
		if !cleanupTimer.Stop() {
			select {
			case <-cleanupTimer.C:
			default:
			}
		}
		for name, done := range map[string]<-chan struct{}{
			"client engine": fixture.client.Closed(), "server engine": fixture.server.Closed(),
		} {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				fixture.closeErr = errors.Join(fixture.closeErr, fmt.Errorf("%s did not quiesce", name))
			}
		}
		select {
		case <-fixture.listener.cleanupDone:
		case <-time.After(5 * time.Second):
			fixture.closeErr = errors.Join(fixture.closeErr, errors.New("T5.6 listener cleanup did not join"))
		}
	})
	return fixture.closeErr
}

func t56DialAndAccept(t testing.TB, listener *Listener, relay *t56OpaqueUDPRelay) (transport.PathConn, transport.PathConn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	type result struct {
		path transport.PathConn
		err  error
	}
	accepted := make(chan result, 1)
	go func() {
		path, err := listener.Accept(ctx)
		accepted <- result{path: path, err: err}
	}()
	client, err := listener.Factory().DialPath(ctx, transport.PathSpec{Address: relay.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-accepted:
		if result.err != nil {
			if closeErr := client.Close(); closeErr != nil {
				t.Errorf("close client after T5.6 accept failure: %v", closeErr)
			}
			t.Fatal(result.err)
		}
		return client, result.path
	case <-ctx.Done():
		if closeErr := client.Close(); closeErr != nil {
			t.Errorf("close client after T5.6 accept timeout: %v", closeErr)
		}
		select {
		case <-accepted:
		case <-time.After(time.Second):
			t.Error("T5.6 accept goroutine did not join after cancellation")
		}
		t.Fatal("T5.6 opaque relay accept timed out")
		return nil, nil
	}
}

func t56RandomPSK(t testing.TB) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatal(err)
	}
	return key
}

func t56PSK(t testing.TB, envName string) []byte {
	t.Helper()
	if configured := os.Getenv(envName); configured != "" {
		if len(configured) < 32 {
			t.Fatalf("%s must contain at least 32 bytes", envName)
		}
		return []byte(configured)
	}
	return t56RandomPSK(t)
}

func t56RunID(t testing.TB) string {
	t.Helper()
	if configured := strings.TrimSpace(os.Getenv(t56RunIDEnv)); configured != "" {
		return configured
	}
	t56LocalRunIDOnce.Do(func() {
		var value [16]byte
		if _, err := io.ReadFull(rand.Reader, value[:]); err != nil {
			t.Fatalf("generate local T5.6 run ID: %v", err)
		}
		t56LocalRunID = hex.EncodeToString(value[:])
	})
	return t56LocalRunID
}

func t56ControlEvidence(t testing.TB, controlID string, facts map[string]string) map[string]string {
	t.Helper()
	evidence := map[string]string{
		"schema":        t56ControlEvidenceSchema,
		"case_id":       t56CaseID,
		"test_name":     t.Name(),
		"run_id":        t56RunID(t),
		"control_id":    controlID,
		"control_valid": "true",
	}
	for key, value := range facts {
		if _, exists := evidence[key]; exists {
			t.Fatalf("T5.6 control evidence duplicates envelope key %q", key)
		}
		evidence[key] = value
	}
	return evidence
}

func t56EmitEvidence(t testing.TB, evidence map[string]string, secrets ...[]byte) {
	t.Helper()
	if evidence == nil {
		t.Fatal("T5.6 evidence is nil")
	}
	if existing := evidence["test_name"]; existing != "" && existing != t.Name() {
		t.Fatalf("T5.6 evidence test_name=%q want %q", existing, t.Name())
	}
	if existing := evidence["run_id"]; existing != "" && existing != t56RunID(t) {
		t.Fatalf("T5.6 evidence run_id=%q does not match this run", existing)
	}
	evidence["test_name"] = t.Name()
	evidence["run_id"] = t56RunID(t)
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	for _, envName := range []string{t56PSKEnv, t56WrongPSKEnv} {
		if configured := os.Getenv(envName); configured != "" {
			secrets = append(secrets, []byte(configured))
		}
	}
	for _, secret := range secrets {
		for _, form := range t56SecretForms(secret) {
			if len(form) != 0 && bytes.Contains(encoded, form) {
				t.Fatal("T5.6 evidence contains packet authentication material")
			}
		}
	}
	t.Logf("%s%s", t56EvidenceMarker, encoded)
}

func t56SecretForms(secret []byte) [][]byte {
	if len(secret) == 0 {
		return nil
	}
	return [][]byte{
		append([]byte(nil), secret...),
		[]byte(hex.EncodeToString(secret)),
		[]byte(base64.StdEncoding.EncodeToString(secret)),
		[]byte(base64.RawStdEncoding.EncodeToString(secret)),
		[]byte(base64.URLEncoding.EncodeToString(secret)),
		[]byte(base64.RawURLEncoding.EncodeToString(secret)),
	}
}

func t56EngineRoundTrip(t testing.TB, sender, receiver *engine.Engine, payload []byte) {
	t.Helper()
	if n, err := sender.SendData(payload); err != nil || n != len(payload) {
		t.Fatalf("T5.6 DATA send=(%d,%v), want (%d,nil)", n, err, len(payload))
	}
	received := make([]byte, len(payload))
	if n, err := receiver.Recv(received); err != nil || n != len(payload) || !bytes.Equal(received, payload) {
		t.Fatalf("T5.6 DATA receive=(%d,%v) equal=%t", n, err, bytes.Equal(received, payload))
	}
}

type t56CandidateStageObservation struct {
	done     chan struct{}
	once     sync.Once
	mu       sync.Mutex
	calls    uint64
	started  time.Time
	finished time.Time
	err      error
}

func t56BoundCandidateOpen(t testing.TB, owner *linkOwner, budget time.Duration) *t56CandidateStageObservation {
	t.Helper()
	if owner == nil || budget <= 0 {
		t.Fatalf("invalid T5.6 bounded candidate opener owner=%p budget=%v", owner, budget)
	}
	observation := &t56CandidateStageObservation{done: make(chan struct{})}
	owner.mu.Lock()
	base := owner.openCandidate
	if base == nil {
		owner.mu.Unlock()
		t.Fatal("T5.6 packet-link candidate opener is unavailable")
	}
	owner.openCandidate = func(ctx context.Context, remote net.Addr) (*packetWire, routeObservation, error) {
		started := time.Now()
		stageCtx, cancel := context.WithTimeout(ctx, budget)
		candidate, route, err := base(stageCtx, remote)
		cancel()
		finished := time.Now()
		observation.mu.Lock()
		observation.calls++
		observation.mu.Unlock()
		observation.once.Do(func() {
			observation.mu.Lock()
			observation.started = started
			observation.finished = finished
			observation.err = err
			observation.mu.Unlock()
			close(observation.done)
		})
		return candidate, route, err
	}
	owner.mu.Unlock()
	return observation
}

func t56FailCandidateOpenAtBudget(
	t testing.TB,
	owner *linkOwner,
	budget time.Duration,
) *t56CandidateStageObservation {
	t.Helper()
	if owner == nil || budget <= 0 {
		t.Fatalf("invalid T5.6 failing candidate opener owner=%p budget=%v", owner, budget)
	}
	observation := &t56CandidateStageObservation{done: make(chan struct{})}
	owner.mu.Lock()
	if owner.openCandidate == nil {
		owner.mu.Unlock()
		t.Fatal("T5.6 packet-link candidate opener is unavailable")
	}
	owner.openCandidate = func(ctx context.Context, _ net.Addr) (*packetWire, routeObservation, error) {
		started := time.Now()
		timer := time.NewTimer(budget)
		var err error
		select {
		case <-timer.C:
			err = context.DeadlineExceeded
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			err = context.Cause(ctx)
		}
		finished := time.Now()
		observation.mu.Lock()
		observation.calls++
		observation.mu.Unlock()
		observation.once.Do(func() {
			observation.mu.Lock()
			observation.started = started
			observation.finished = finished
			observation.err = err
			observation.mu.Unlock()
			close(observation.done)
		})
		return nil, routeObservation{}, err
	}
	owner.mu.Unlock()
	return observation
}

func (observation *t56CandidateStageObservation) snapshot(t testing.TB) (time.Duration, error, uint64) {
	t.Helper()
	select {
	case <-observation.done:
	case <-time.After(t56ControlTransactionBudget + t56ControlMargin):
		t.Fatal("T5.6 bounded candidate Stage was never invoked")
	}
	observation.mu.Lock()
	defer observation.mu.Unlock()
	return observation.finished.Sub(observation.started), observation.err, observation.calls
}

func t56PublishLinkUnresponsive(t testing.TB, path *retainedPathConn) {
	t.Helper()
	if path == nil || path.link == nil ||
		!path.link.publishWireFailure(leafmobility.RefreshReasonLinkUnresponsive) {
		t.Fatal("T5.6 packet-link refresh stimulus was not accepted")
	}
}

func t56WaitInitiatorPhase(
	t testing.TB,
	eng *engine.Engine,
	ref engine.PathRef,
	timeout time.Duration,
	want engine.LeafMobilityInitiatorPhase,
) engine.LeafMobilityInitiatorSnapshot {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last engine.LeafMobilityInitiatorSnapshot
	for time.Now().Before(deadline) {
		if status, ok := eng.LeafMobilityInitiatorStatus(ref); ok {
			last = status
			if status.Phase == want {
				return status
			}
			if t56TerminalNonCommitPhase(status.Phase) && status.Phase != want {
				t.Fatalf("T5.6 automatic transaction phase=%s, want %s: %+v",
					t56InitiatorPhase(status.Phase), t56InitiatorPhase(want), status)
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("T5.6 automatic transaction timed out waiting for %s; last=%+v", t56InitiatorPhase(want), last)
	return engine.LeafMobilityInitiatorSnapshot{}
}

func t56WaitInitiatorTerminalNonCommit(
	t testing.TB,
	eng *engine.Engine,
	ref engine.PathRef,
	timeout time.Duration,
) engine.LeafMobilityInitiatorSnapshot {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last engine.LeafMobilityInitiatorSnapshot
	for time.Now().Before(deadline) {
		if status, ok := eng.LeafMobilityInitiatorStatus(ref); ok {
			last = status
			switch status.Phase {
			case engine.LeafMobilityInitiatorRolledBack,
				engine.LeafMobilityInitiatorFailed,
				engine.LeafMobilityInitiatorFailClosed:
				return status
			case engine.LeafMobilityInitiatorCommitted:
				t.Fatalf("T5.6 failure stimulus committed unexpectedly: %+v", status)
			case engine.LeafMobilityInitiatorRejected,
				engine.LeafMobilityInitiatorExpired:
				t.Fatalf("T5.6 failure stimulus terminated before driver execution: %+v", status)
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("T5.6 automatic transaction timed out waiting for a non-commit terminal phase; last=%+v", last)
	return engine.LeafMobilityInitiatorSnapshot{}
}

type t56FailClosedWireSummary struct {
	Prepare    uint64
	Prepared   uint64
	Commit     uint64
	Complete   uint64
	RolledBack uint64
	Released   uint64
}

func t56SummarizeNonCommitTransaction(
	t testing.TB,
	trace *publicK5ControlTrace,
	transaction leafmobility.TransactionID,
) t56FailClosedWireSummary {
	t.Helper()
	if trace == nil || transaction == (leafmobility.TransactionID{}) {
		t.Fatal("T5.6 non-commit transaction trace is unavailable")
	}
	want := [16]byte(transaction)
	var summary t56FailClosedWireSummary
	for _, record := range trace.snapshot() {
		if record.Transaction != want {
			continue
		}
		if record.Actor != proto.LeafMobilityActorClient {
			t.Fatalf("T5.6 non-commit transaction has actor=%d, want client", record.Actor)
		}
		switch record.Code {
		case proto.CtrlLeafMobilityPrepare:
			if record.Writer != publicK5ControlClient {
				t.Fatal("T5.6 non-commit PREPARE was not written by client")
			}
			summary.Prepare++
		case proto.CtrlLeafMobilityAck:
			switch {
			case record.AckPhase == proto.LeafMobilityPeerPlanAckPhasePrepared &&
				record.AckCode == proto.LeafMobilityPeerPlanAckCodeAccept && record.Writer == publicK5ControlServer:
				summary.Prepared++
			case record.AckPhase == proto.LeafMobilityPeerPlanAckPhaseReleased &&
				record.AckCode == proto.LeafMobilityPeerPlanAckCodeAccept &&
				record.CommitStage == proto.LeafMobilityPeerPlanCommitStageRolledBack &&
				record.Writer == publicK5ControlServer:
				summary.Released++
			default:
				t.Fatalf("T5.6 non-commit transaction contains contradictory ACK %+v", record.Ack)
			}
		case proto.CtrlLeafMobilityCommit:
			if record.Writer != publicK5ControlClient {
				t.Fatal("T5.6 non-commit resolution was not written by client")
			}
			switch record.CommitStage {
			case proto.LeafMobilityPeerPlanCommitStageCommit:
				summary.Commit++
			case proto.LeafMobilityPeerPlanCommitStageComplete:
				summary.Complete++
			case proto.LeafMobilityPeerPlanCommitStageRolledBack:
				summary.RolledBack++
			default:
				t.Fatalf("T5.6 non-commit transaction contains stage=%d", record.CommitStage)
			}
		}
	}
	trace.mu.Lock()
	malformed := trace.malformed
	trace.mu.Unlock()
	if malformed != 0 || summary.Prepare == 0 || summary.Prepared == 0 ||
		summary.Commit != 0 || summary.Complete != 0 {
		t.Fatalf("T5.6 bilateral non-commit wire summary=%+v malformed=%d", summary, malformed)
	}
	return summary
}

func t56SummarizeFailClosedTransaction(
	t testing.TB,
	trace *publicK5ControlTrace,
	transaction leafmobility.TransactionID,
) t56FailClosedWireSummary {
	t.Helper()
	summary := t56SummarizeNonCommitTransaction(t, trace, transaction)
	if summary.RolledBack != 0 || summary.Released != 0 {
		t.Fatalf("T5.6 fail-closed transaction falsely acknowledged rollback: %+v", summary)
	}
	return summary
}

func t56RollbackFailureIsTimeout(statusError string) bool {
	const marker = "driver execution failed: rollback:"
	index := strings.Index(statusError, marker)
	if index < 0 {
		return false
	}
	rollbackError := statusError[index+len(marker):]
	return strings.Contains(rollbackError, context.DeadlineExceeded.Error()) ||
		strings.Contains(rollbackError, "i/o timeout")
}

func t56RollbackFailureIsFactual(statusError string) bool {
	return strings.Contains(statusError, "driver execution failed: rollback:") ||
		strings.Contains(statusError, leafmobility.ErrExecutionBusy.Error())
}

func TestT56RollbackFailureClassifier(t *testing.T) {
	for _, test := range []struct {
		name        string
		statusError string
		want        bool
	}{
		{name: "wrapped rollback", statusError: "driver execution failed: rollback: context deadline exceeded", want: true},
		{name: "rollback busy", statusError: "driver execution failed: stage: context deadline exceeded\nleafmobility: driver execution is busy", want: true},
		{name: "stage only", statusError: "driver execution failed: stage: context deadline exceeded", want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := t56RollbackFailureIsFactual(test.statusError); got != test.want {
				t.Fatalf("t56RollbackFailureIsFactual(%q)=%t, want %t", test.statusError, got, test.want)
			}
		})
	}
}

func t56StageFailureIsTimeout(statusError string) bool {
	const marker = "driver execution failed: stage:"
	index := strings.Index(statusError, marker)
	if index < 0 {
		return false
	}
	stageError := statusError[index+len(marker):]
	if lineEnd := strings.IndexByte(stageError, '\n'); lineEnd >= 0 {
		stageError = stageError[:lineEnd]
	}
	return strings.Contains(stageError, context.DeadlineExceeded.Error()) ||
		strings.Contains(stageError, "i/o timeout")
}

func t56ListenerPacketState(listener *Listener) (int, int, int) {
	if listener == nil {
		return 0, 0, 0
	}
	listener.packetMu.RLock()
	defer listener.packetMu.RUnlock()
	return len(listener.packetLinks), len(listener.packetByIP), len(listener.packetPending)
}

func t56Closed(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

func t56TerminalNonCommitPhase(phase engine.LeafMobilityInitiatorPhase) bool {
	switch phase {
	case engine.LeafMobilityInitiatorRolledBack,
		engine.LeafMobilityInitiatorRejected,
		engine.LeafMobilityInitiatorFailed,
		engine.LeafMobilityInitiatorExpired,
		engine.LeafMobilityInitiatorFailClosed:
		return true
	default:
		return false
	}
}

func t56InitiatorPhase(phase engine.LeafMobilityInitiatorPhase) string {
	switch phase {
	case engine.LeafMobilityInitiatorIdle:
		return "idle"
	case engine.LeafMobilityInitiatorPending:
		return "pending"
	case engine.LeafMobilityInitiatorPlanning:
		return "planning"
	case engine.LeafMobilityInitiatorBaseline:
		return "baseline"
	case engine.LeafMobilityInitiatorNegotiating:
		return "negotiating"
	case engine.LeafMobilityInitiatorExecuting:
		return "executing"
	case engine.LeafMobilityInitiatorCommitted:
		return "committed"
	case engine.LeafMobilityInitiatorRolledBack:
		return "rolled_back"
	case engine.LeafMobilityInitiatorRejected:
		return "rejected"
	case engine.LeafMobilityInitiatorFailed:
		return "failed"
	case engine.LeafMobilityInitiatorSuperseded:
		return "superseded"
	case engine.LeafMobilityInitiatorDeferred:
		return "deferred"
	case engine.LeafMobilityInitiatorExpired:
		return "expired"
	case engine.LeafMobilityInitiatorSubscriptionUnavailable:
		return "subscription_unavailable"
	case engine.LeafMobilityInitiatorFailClosed:
		return "fail_closed"
	default:
		return "invalid"
	}
}

func t56UnauthenticatedAdmissionAttempt(t testing.TB, listenerAddress net.Addr) (uint64, uint64) {
	t.Helper()
	remote, ok := listenerAddress.(*net.UDPAddr)
	if !ok {
		t.Fatalf("configured packet listener address=%T", listenerAddress)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	defer func() {
		if !closed {
			if closeErr := conn.Close(); closeErr != nil {
				t.Errorf("close unauthenticated admission socket: %v", closeErr)
			}
		}
	}()
	id, err := newLinkID()
	if err != nil {
		t.Fatal(err)
	}
	_, public, err := newLinkKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := newLinkNonce()
	if err != nil {
		t.Fatal(err)
	}
	send := func(cookie outerCookie) {
		t.Helper()
		wire, encodeErr := encodeOuter(outerFrame{
			Type: outerTypeOpen, Sender: leafmobility.RoleDialer, LinkID: id, Generation: 1,
			Payload: marshalOpen(public, nonce, cookie, outerProof{}),
		}, linkSecret{})
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		if n, writeErr := conn.WriteToUDP(wire, remote); writeErr != nil || n != len(wire) {
			t.Fatalf("send unauthenticated OPEN=(%d,%v), want (%d,nil)", n, writeErr, len(wire))
		}
	}
	send(outerCookie{})
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, outerMaxDatagramSize)
	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("read admission cookie: %v", err)
	}
	frame, err := decodeOuter(buffer[:n], linkSecret{}, leafmobility.RoleAcceptor)
	if err != nil || frame.Type != outerTypeCookie || frame.LinkID != id {
		t.Fatalf("unauthenticated admission cookie frame=%+v err=%v", frame, err)
	}
	cookie, err := parseOuterCookie(frame.Payload)
	if err != nil {
		t.Fatal(err)
	}
	send(cookie)
	if err := conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	n, _, err = conn.ReadFromUDP(buffer)
	if err == nil {
		response, _ := decodeOuterHeader(buffer[:n])
		t.Fatalf("configured PSK listener responded to proofless OPEN with type=%d", response.Type)
	}
	if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("proofless OPEN read error=%v, want timeout rejection", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close unauthenticated admission socket: %v", err)
	}
	closed = true
	return 2, 1
}

type t56ResourceSample struct {
	FDs        uint64
	Goroutines uint64
	HeapInuse  uint64
}

func t56ReadResourceSample(t testing.TB) t56ResourceSample {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("read T5.6 fd baseline: %v", err)
	}
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	return t56ResourceSample{
		FDs: uint64(len(entries)), Goroutines: uint64(runtime.NumGoroutine()), HeapInuse: memory.HeapInuse,
	}
}

func t56ResourceSlope(samples []t56ResourceSample, value func(t56ResourceSample) uint64) int64 {
	if len(samples) < 2 {
		return 0
	}
	var sumX, sumY, sumXY, sumXX float64
	for index, sample := range samples {
		x := float64(index)
		y := float64(value(sample))
		sumX += x
		sumY += y
		sumXY += x * y
		sumXX += x * x
	}
	n := float64(len(samples))
	return int64(math.Round((n*sumXY - sumX*sumY) / (n*sumXX - sumX*sumX)))
}

func t56ResourcePeaks(samples []t56ResourceSample) (uint64, uint64, uint64) {
	var fds, goroutines, heap uint64
	for _, sample := range samples {
		fds = max(fds, sample.FDs)
		goroutines = max(goroutines, sample.Goroutines)
		heap = max(heap, sample.HeapInuse)
	}
	return fds, goroutines, heap
}

func t56CapabilityEvidence(t testing.TB) map[string]string {
	t.Helper()
	evidence := map[string]string{
		"schema": t56EvidenceSchema, "case_id": t56CaseID, "goos": "linux",
		"euid": strconv.Itoa(os.Geteuid()), "capability_source": "proc_self_status",
		"prerequisite_valid": "false",
	}
	contents, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	wanted := map[string]string{
		"CapInh": "cap_inh", "CapPrm": "cap_prm", "CapEff": "cap_eff",
		"CapBnd": "cap_bnd", "CapAmb": "cap_amb",
	}
	values := make(map[string]uint64, len(wanted))
	for _, line := range strings.Split(string(contents), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		key, ok := wanted[strings.TrimSuffix(fields[0], ":")]
		if !ok {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 16, 64)
		if err != nil {
			t.Fatal(err)
		}
		values[key] = value
		evidence[key] = fmt.Sprintf("0x%016x", value)
	}
	if len(values) != len(wanted) {
		t.Fatal("T5.6 capability evidence is incomplete")
	}
	const netAdmin = uint64(1) << 12
	for key, value := range values {
		if value&netAdmin != 0 {
			t.Fatalf("T5.6 setpriv process retained CAP_NET_ADMIN in %s", key)
		}
	}
	evidence["cap_net_admin_absent"] = "true"
	evidence["setpriv_capability_drop_observed"] = "true"
	evidence["prerequisite_valid"] = "true"
	return evidence
}

func t56TreatmentEvidence(
	result publicK5GVisorEvidence,
	observation publicRuntimeGVisorObservation,
	relay t56OpaqueRelaySnapshot,
	evidence map[string]string,
) map[string]string {
	set := func(key string, value any) { evidence[key] = fmt.Sprint(value) }
	set("behavior", "automatic_gvisor_packet_link_rebind")
	set("session_protocol", fmt.Sprintf("framed_stream_v%d", proto.Version))
	set("group_executor", "selector")
	set("gvisor_endpoint_owner", "gvisor_from_session_start")
	set("kernel_tcp_to_gvisor_conversion", false)
	set("outer_carrier", "udp")
	set("packet_authentication", "psk")
	set("packet_trust_configured", true)
	set("relay_kind", "opaque_udp_tuple_router")
	set("relay_psk_access", false)
	set("relay_protocol_inspection", "outer_type_and_inner_tcp_headers")
	set("relay_authentication_verified", false)
	set("automatic_phase_select_target_calls", 0)
	set("automatic_phase_manual_migration_calls", 0)
	set("production_factory_provider", observation.ProductionFactory)
	set("production_listener_provider", observation.ProductionListener)
	set("test_wrapper_provider", false)
	set("responder_initiator_suppressed", false)
	set("crossed_actor_rule", "client_priority")
	set("crossed_actor_schedule", "first_prepare_bilateral_barrier")
	set("crossed_actor_schedule_injected", true)
	set("client_crossed_transaction_id", hex.EncodeToString(observation.Control.CrossedClientTransaction[:]))
	set("server_crossed_transaction_id", hex.EncodeToString(observation.Control.CrossedServerTransaction[:]))
	set("migration_count_before", result.MigrationCountBefore)
	set("migration_count_after", result.MigrationCountAfter)
	set("migration_event_count", result.MigrationEventCount)
	set("client_migration_ledger_json", t56MigrationLedgerJSON(result.ClientMigrationEvents))
	set("generic_failover_events", result.GenericFailoverEvents)
	set("generic_failover_cause", result.GenericFailoverCause)
	set("server_migration_count_before", result.ServerMigrationCountBefore)
	set("server_migration_count_after", result.ServerMigrationCountAfter)
	set("server_migration_event_count", len(result.ServerMigrationEvents))
	set("server_migration_ledger_json", t56MigrationLedgerJSON(result.ServerMigrationEvents))
	set("server_generic_failover_events", result.ServerGenericFailoverEvents)
	set("server_generic_failover_cause", result.ServerGenericFailoverCause)
	set("migration_old_path_id", result.MigrationOldPathID)
	set("migration_new_path_id", result.MigrationNewPathID)
	set("migration_cause", result.MigrationCause)
	set("blackhole_unix_nano", result.BlackholeUnixNano)
	set("migration_unix_nano", result.MigrationUnixNano)
	set("recovery_nanoseconds", result.RecoveryNanoseconds)
	set("path_id", result.PathID)
	set("path_owner", result.PathOwner)
	set("control_path_id", result.ControlPathID)
	set("server_data_path_id", result.ServerDataPathID)
	set("server_path_owner", result.ServerPathOwner)
	set("server_control_path_id", result.ServerControlPathID)
	set("client_data_binding_before_json", t56MigrationPathBindingJSON(result.ClientDataBindingBefore))
	set("client_control_binding_before_json", t56MigrationPathBindingJSON(result.ClientControlBindingBefore))
	set("server_data_binding_before_json", t56MigrationPathBindingJSON(result.ServerDataBindingBefore))
	set("server_control_binding_before_json", t56MigrationPathBindingJSON(result.ServerControlBindingBefore))
	set("status_mobility_id", result.StatusMobilityID)
	set("status_mobility_state", result.StatusMobilityState)
	set("status_mobility_reason", observation.StatusReason)
	set("status_mobility_negotiated", observation.StatusNegotiated)
	set("status_transaction_id", result.StatusTransactionID)
	set("transaction_id", result.TransactionID)
	set("agreement_digest", result.AgreementDigest)
	set("status_endpoint_generation", result.StatusEndpointGeneration)
	set("status_evidence_generation", result.StatusEvidenceGeneration)
	set("runtime_client_object_before", t56OpaqueToken(result.RuntimeClientObjectBefore))
	set("runtime_client_object_after", t56OpaqueToken(result.RuntimeClientObjectAfter))
	set("runtime_server_object_before", t56OpaqueToken(result.RuntimeServerObjectBefore))
	set("runtime_server_object_after", t56OpaqueToken(result.RuntimeServerObjectAfter))
	set("flow_id_before", result.FlowIDBefore)
	set("flow_id_after", result.FlowIDAfter)
	set("peer_flow_id", result.PeerFlowID)
	set("client_created_at_before", observation.ClientCreatedAtBefore.UnixNano())
	set("client_created_at_after", observation.ClientCreatedAtAfter.UnixNano())
	set("server_created_at_before", observation.ServerCreatedAtBefore.UnixNano())
	set("server_created_at_after", observation.ServerCreatedAtAfter.UnixNano())
	set("claim_kind", result.ClaimKind)
	set("claim_role", result.ClaimRole)
	set("claim_scope", result.ClaimScope)
	set("claim_operations", result.ClaimOperations)
	set("claim_resource_id_before", result.ClaimResourceIDBefore)
	set("claim_resource_id_after", result.ClaimResourceIDAfter)
	set("claim_endpoint_generation_before", result.ClaimEndpointGenerationBefore)
	set("claim_endpoint_generation_after", result.ClaimEndpointGenerationAfter)
	set("claim_binding_local_target_id", result.ClaimBindingLocalTargetID)
	set("claim_binding_peer_target_id", result.ClaimBindingPeerTargetID)
	set("server_claim_endpoint_generation_before", result.ServerClaimEndpointGenerationBefore)
	set("outer_incarnation_before", result.OuterIncarnationBefore)
	set("outer_incarnation_after", result.OuterIncarnationAfter)
	set("outer_generation_before", result.OuterGenerationBefore)
	set("outer_generation_after", result.OuterGenerationAfter)
	set("outer_tuple_before", result.OuterTupleBefore)
	set("outer_tuple_dropped", result.OuterTupleDropped)
	set("outer_tuple_after", result.OuterTupleAfter)
	set("relay_replacement_tuple", relay.ReplacementTuple)
	set("relay_client_packets_before", relay.ClientForwardedBefore)
	set("relay_client_packets_after", relay.ClientForwardedAfter)
	set("relay_server_packets_before", relay.ServerForwardedBefore)
	set("relay_server_packets_after", relay.ServerForwardedAfter)
	set("relay_server_after_destination", relay.ServerAfterDestination)
	set("relay_old_tuple_drops", relay.DroppedOld)
	set("relay_total_drops", relay.DroppedTotal)
	set("relay_new_client_tuples", relay.NewClientTuples)
	set("client_unacked_frames_at_blackhole", observation.ClientTXAtBlackhole.FramesInUse)
	set("client_unacked_bytes_at_blackhole", observation.ClientTXAtBlackhole.BytesInUse)
	set("server_unacked_frames_at_blackhole", observation.ServerTXAtBlackhole.FramesInUse)
	set("server_unacked_bytes_at_blackhole", observation.ServerTXAtBlackhole.BytesInUse)
	set("client_control_reads_before", result.ClientControlBefore.Reads)
	set("client_control_reads_after", result.ClientControlAfter.Reads)
	set("client_control_writes_before", result.ClientControlBefore.ControlWrites)
	set("client_control_writes_after", result.ClientControlAfter.ControlWrites)
	set("client_control_data_writes_before", result.ClientControlBefore.DataWrites)
	set("client_control_data_writes_after", result.ClientControlAfter.DataWrites)
	set("server_control_reads_before", result.ServerControlBefore.Reads)
	set("server_control_reads_after", result.ServerControlAfter.Reads)
	set("server_control_writes_before", result.ServerControlBefore.ControlWrites)
	set("server_control_writes_after", result.ServerControlAfter.ControlWrites)
	set("server_control_data_writes_before", result.ServerControlBefore.DataWrites)
	set("server_control_data_writes_after", result.ServerControlAfter.DataWrites)
	set("control_path_name", publicK5GVisorControlName)
	set("control_mobility_frames", observation.Control.MobilityFrames)
	set("control_malformed_frames", observation.Control.MalformedFrames)
	set("control_agreement_mismatches", observation.Control.AgreementMismatches)
	set("control_other_actor_frames", observation.Control.OtherActorFrames)
	set("control_winning_prepare_frames", observation.Control.WinningPrepareFrames)
	set("control_winning_prepared_frames", observation.Control.WinningPreparedFrames)
	set("control_winning_commit_frames", observation.Control.WinningCommitFrames)
	set("control_winning_final_frames", observation.Control.WinningFinalFrames)
	set("control_winning_complete_frames", observation.Control.WinningCompleteFrames)
	set("control_winning_released_frames", observation.Control.WinningReleasedFrames)
	set("control_crossed_server_transactions", observation.Control.CrossedServerTransactions)
	set("control_crossed_server_prepare_frames", observation.Control.CrossedServerPrepareFrames)
	set("control_crossed_server_busy_frames", observation.Control.CrossedServerBusyFrames)
	set("control_crossed_server_progression_frames", observation.Control.CrossedServerProgressionFrames)
	set("control_crossed_prepare_barrier", observation.Control.CrossedPrepareBarrier)
	set("post_commit_epoch_started_unix_nano", result.PostCommitData.StartedUnixNano)
	set("post_commit_select_target_calls", result.PostCommitData.SelectTargetCalls)
	set("post_commit_client_active_before", result.PostCommitData.ClientActiveBefore)
	set("post_commit_client_active_after", result.PostCommitData.ClientActiveAfter)
	set("post_commit_server_active_before", result.PostCommitData.ServerActiveBefore)
	set("post_commit_server_active_after", result.PostCommitData.ServerActiveAfter)
	set("post_commit_client_data_path_id", result.PostCommitData.ClientDataPathID)
	set("post_commit_server_data_path_id", result.PostCommitData.ServerDataPathID)
	set("post_commit_client_migration_before", result.PostCommitData.ClientMigrationBefore)
	set("post_commit_client_migration_after", result.PostCommitData.ClientMigrationAfter)
	set("post_commit_server_migration_before", result.PostCommitData.ServerMigrationBefore)
	set("post_commit_server_migration_after", result.PostCommitData.ServerMigrationAfter)
	set("post_commit_client_active_final", result.PostCommitData.ClientActiveFinal)
	set("post_commit_server_active_final", result.PostCommitData.ServerActiveFinal)
	set("post_commit_client_migration_final", result.PostCommitData.ClientMigrationFinal)
	set("post_commit_server_migration_final", result.PostCommitData.ServerMigrationFinal)
	set("post_commit_client_selection_ledger_json", t56MigrationLedgerJSON(result.PostCommitData.ClientSelectionEvents))
	set("post_commit_server_selection_ledger_json", t56MigrationLedgerJSON(result.PostCommitData.ServerSelectionEvents))
	set("post_commit_client_published_next", result.PostCommitData.ClientPublishedNext)
	set("post_commit_server_published_next", result.PostCommitData.ServerPublishedNext)
	set("post_commit_client_outer_data_before", result.PostCommitData.ClientOuterDataBefore)
	set("post_commit_client_outer_data_after", result.PostCommitData.ClientOuterDataAfter)
	set("post_commit_server_outer_data_before", result.PostCommitData.ServerOuterDataBefore)
	set("post_commit_server_outer_data_after", result.PostCommitData.ServerOuterDataAfter)
	set("post_commit_client_inner_payload_before", result.PostCommitData.ClientInnerPayloadBefore)
	set("post_commit_client_inner_payload_after", result.PostCommitData.ClientInnerPayloadAfter)
	set("post_commit_server_inner_payload_before", result.PostCommitData.ServerInnerPayloadBefore)
	set("post_commit_server_inner_payload_after", result.PostCommitData.ServerInnerPayloadAfter)
	set("post_commit_client_control_data_before", result.PostCommitData.ClientControlDataBefore)
	set("post_commit_client_control_data_after", result.PostCommitData.ClientControlDataAfter)
	set("post_commit_server_control_data_before", result.PostCommitData.ServerControlDataBefore)
	set("post_commit_server_control_data_after", result.PostCommitData.ServerControlDataAfter)
	set("post_commit_client_control_sequence_count", len(result.PostCommitData.ClientControlEpochSequences))
	set("post_commit_server_control_sequence_count", len(result.PostCommitData.ServerControlEpochSequences))
	set("post_commit_client_offered_bytes", result.PostCommitData.ClientOfferedBytes)
	set("post_commit_client_received_bytes", result.PostCommitData.ClientReceivedBytes)
	set("post_commit_server_offered_bytes", result.PostCommitData.ServerOfferedBytes)
	set("post_commit_server_received_bytes", result.PostCommitData.ServerReceivedBytes)
	set("post_commit_client_offered_sha256", result.PostCommitData.ClientOfferedSHA256)
	set("post_commit_client_received_sha256", result.PostCommitData.ClientReceivedSHA256)
	set("post_commit_server_offered_sha256", result.PostCommitData.ServerOfferedSHA256)
	set("post_commit_server_received_sha256", result.PostCommitData.ServerReceivedSHA256)
	set("client_offered_bytes", result.ClientOfferedBytes)
	set("client_received_bytes", result.ClientReceivedBytes)
	set("server_offered_bytes", result.ServerOfferedBytes)
	set("server_received_bytes", result.ServerReceivedBytes)
	set("client_offered_sha256", result.ClientOfferedSHA256)
	set("client_received_sha256", result.ClientReceivedSHA256)
	set("server_offered_sha256", result.ServerOfferedSHA256)
	set("server_received_sha256", result.ServerReceivedSHA256)
	set("copy_operations", result.CopyOperations)
	set("copy_errors", result.CopyErrors)
	set("application_errors", result.ClientApp.ReadErrors+result.ClientApp.WriteErrors+result.ClientApp.CloseErrors+
		result.ServerApp.ReadErrors+result.ServerApp.WriteErrors+result.ServerApp.CloseErrors)
	set("application_eofs", result.ClientApp.EOFs+result.ServerApp.EOFs)
	set("application_read_zeros", result.ClientApp.ReadZeros+result.ServerApp.ReadZeros)
	set("application_resets", result.ClientApp.Resets+result.ServerApp.Resets)
	set("client_claim_retired", result.ClientClaimRetired)
	set("server_claim_retired", result.ServerClaimRetired)
	set("client_owner_closed", result.ClientOwnerClosed)
	set("server_owner_closed", result.ServerOwnerClosed)
	set("listener_admission_closed", result.ListenerAdmissionClosed)
	set("listener_cleanup_closed", result.ListenerCleanupClosed)
	set("listener_links_after", result.ListenerLinksAfter)
	set("listener_addresses_after", result.ListenerAddressesAfter)
	set("listener_pending_after", result.ListenerPendingAfter)
	set("client_replay_owners_after", result.ClientReplayOwnersAfter)
	set("client_replay_bytes_after", result.ClientReplayBytesAfter)
	set("client_replay_entries_after", result.ClientReplayEntriesAfter)
	set("server_replay_owners_after", result.ServerReplayOwnersAfter)
	set("server_replay_bytes_after", result.ServerReplayBytesAfter)
	set("server_replay_entries_after", result.ServerReplayEntriesAfter)
	set("refresh_callbacks_active_after", result.RefreshCallbacksActiveAfter)
	return evidence
}

func t56MigrationLedgerJSON(events []publicK5MigrationEvent) string {
	encoded, err := json.Marshal(events)
	if err != nil {
		panic(fmt.Sprintf("encode T5.6 migration ledger: %v", err))
	}
	return string(encoded)
}

func t56MigrationPathBindingJSON(binding publicK5MigrationPathBinding) string {
	encoded, err := json.Marshal(binding)
	if err != nil {
		panic(fmt.Sprintf("encode T5.6 path binding: %v", err))
	}
	return string(encoded)
}

func t56OpaqueToken(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

var _ publicRuntimeBlackholeRelay = (*t56OpaqueUDPRelay)(nil)
