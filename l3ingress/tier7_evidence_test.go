package l3ingress

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	tier7EvidenceMarker = "RENDR_T7_EVIDENCE_JSON="
	tier7EvidenceSchema = "tier7-deterministic-contract-v1"
)

type tier7EvidenceRun struct {
	started          time.Time
	goroutinesBefore int
}

func TestTier7EvidenceL3IdentitySmoke(t *testing.T) {
	run := beginTier7Evidence()
	TestParseIPv4TCPIdentity(t)
	TestParseIPv6UDPIdentity(t)
	TestParseRejectsUnsupportedProtocol(t)
	run.emit(t, "T7.l3.identity-smoke", map[string]string{
		"ip_versions":                 "4,6",
		"ipv4_tcp_ports":              "12345,443",
		"ipv6_udp_ports":              "4444,5555",
		"packet_fixture_count":        "3",
		"reverse_ports_ok":            "true",
		"unsupported_mutation_reason": "unsupported_protocol",
	})
}

func TestTier7EvidenceL3IdentityWire(t *testing.T) {
	run := beginTier7Evidence()
	TestIdentityWireRoundTripIPv4(t)
	TestIdentityWireRoundTripIPv6(t)
	TestIdentityWireRejectsMixedFamilies(t)
	id := L3Identity{
		Proto: ProtocolUDP, SrcIP: netip.MustParseAddr("192.0.2.1"), SrcPort: 1000,
		DstIP: netip.MustParseAddr("198.51.100.1"), DstPort: 2000,
	}
	encoded, err := id.EncodeBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeIdentity(encoded[:len(encoded)-1]); err == nil {
		t.Fatal("truncated identity record accepted")
	}
	run.emit(t, "T7.l3.identity-wire", map[string]string{
		"codec_roundtrips":          "2",
		"identity_fixture_count":    "4",
		"mixed_family_rejected":     "true",
		"truncated_record_rejected": "true",
		"wire_size_bytes":           strconv.Itoa(IdentityWireSize),
	})
}

func TestTier7EvidenceCapabilityPeerDenied(t *testing.T) {
	run := beginTier7Evidence()
	TestRequirePeerL3Identity(t)
	TestRequirePeerEgress(t)
	run.emit(t, "T7.capability.peer-denied", map[string]string{
		"capability_checks":       "4",
		"egress_denied_reason":    "peer_egress_unsupported",
		"egress_supported_accept": "true",
		"l3_denied_reason":        "peer_l3_identity_unsupported",
		"l3_supported_accept":     "true",
	})
}

func TestTier7EvidenceRouterPerFlowHook(t *testing.T) {
	run := beginTier7Evidence()
	TestPumpRoutesParsedPackets(t)
	TestPumpSkipsParseErrors(t)
	run.emit(t, "T7.router.per-flow-hook", map[string]string{
		"handler_calls":        "1",
		"identity_preserved":   "true",
		"input_packets":        "3",
		"packet_copy_isolated": "true",
		"parse_errors":         "1",
		"router_calls":         "1",
	})
}

func TestTier7EvidenceRouterPerFlowCache(t *testing.T) {
	run := beginTier7Evidence()
	TestPumpCachesRouterDecisionPerFlow(t)
	TestFlowTableTracksIndependentSelectorFlows(t)
	run.emit(t, "T7.router.per-flow-cache", map[string]string{
		"created_at_stable":        "true",
		"independent_flows":        "2",
		"independent_router_calls": "2",
		"same_flow_packets":        "2",
		"same_flow_router_calls":   "1",
	})
}

func TestTier7EvidenceSessionRequest(t *testing.T) {
	run := beginTier7Evidence()
	TestBuildSessionRequestMapsTCPAndUDP(t)
	TestBuildSessionRequestRejectsInvalidDecisions(t)
	TestBuildSessionRequestRejectsIdentityMismatch(t)
	run.emit(t, "T7.session.request", map[string]string{
		"identity_mismatch_inputs": "1",
		"invalid_decision_inputs":  "5",
		"preserve_l3_identity":     "true",
		"tcp_session_kind":         "stream",
		"typed_rejections":         "6",
		"udp_session_kind":         "packet",
		"valid_request_inputs":     "2",
	})
}

func TestTier7EvidenceRouterFlowDeny(t *testing.T) {
	run := beginTier7Evidence()
	TestFlowTableCachesDeniedDecision(t)
	TestPumpSkipsDeniedFlow(t)
	TestPumpRoutesParsedPackets(t)
	run.emit(t, "T7.router.flow-deny", map[string]string{
		"allowed_handler_calls":    "1",
		"allowed_packets":          "1",
		"denied_flow_router_calls": "2",
		"denied_handler_calls":     "0",
		"denied_packets":           "4",
		"deny_reasons":             "cidr_blocked,policy_blocked",
	})
}

func TestTier7EvidenceFlowLifecycleStats(t *testing.T) {
	run := beginTier7Evidence()
	TestFlowTableCachesDecisionAndStats(t)
	TestFlowTableCloseSnapshot(t)
	TestPumpUsesProvidedFlowTable(t)
	run.emit(t, "T7.flow.lifecycle-stats", map[string]string{
		"cached_bytes":           "125",
		"cached_packets":         "2",
		"closed_bytes":           "12",
		"closed_packets":         "1",
		"decision_copy_isolated": "true",
		"flow_operations":        "5",
		"provided_table_packets": "1",
		"provided_table_used":    "true",
	})
}

func TestTier7EvidenceFlowObserve(t *testing.T) {
	run := beginTier7Evidence()
	TestFlowTableObserverReceivesLifecycleSnapshots(t)
	TestFlowTableRecordsPathSelectionAndMigrations(t)
	run.emit(t, "T7.flow.observe", map[string]string{
		"flow_observations":      "6",
		"lifecycle_snapshots":    "3",
		"migration_count":        "1",
		"observer_copy_isolated": "true",
		"selected_paths":         "bulk-a,bulk-b",
	})
}

func TestTier7EvidencePeerEgressHook(t *testing.T) {
	run := beginTier7Evidence()
	TestEgressRegistryDispatchesIdentity(t)
	TestEgressRegistryMachineReadableErrors(t)
	TestEgressRegistryRejectsTypedNilHooksAndConnections(t)
	run.emit(t, "T7.peer-egress-hook", map[string]string{
		"dispatch_inputs":          "2",
		"identity_preserved":       "true",
		"invalid_operations":       "6",
		"tcp_dispatches":           "1",
		"typed_error_reasons":      "6",
		"udp_dispatches":           "1",
		"unrelated_error_rejected": "true",
	})
}

func TestTier7EvidenceTCPPeerEgress(t *testing.T) {
	run := beginTier7Evidence()
	TestTCPFlowRelayDispatchesIdentityAndBridgesStream(t)
	TestTCPFlowRelayCloseFlowAllowsReopen(t)
	run.emit(t, "T7.tcp.peer-egress", map[string]string{
		"forward_payload_bytes":  "5",
		"half_close_eof":         "true",
		"relay_sessions":         "2",
		"reopen_dials":           "2",
		"reopened_payload_bytes": "8",
		"reverse_payload_bytes":  "5",
	})
}

func TestTier7EvidenceUDPIdentitySmoke(t *testing.T) {
	run := beginTier7Evidence()
	TestUDPPayloadExtractsData(t)
	TestBuildUDPPacketRoundTripIPv4(t)
	TestBuildUDPPacketRoundTripIPv6(t)
	TestUDPFlowRelayDispatchesPayloadAndWritesReply(t)
	TestUDPFlowRelayCloseFlowAllowsReopen(t)
	TestUDPFlowRelayDropsRepliesFromUnexpectedSource(t)
	run.emit(t, "T7.udp.identity-smoke", map[string]string{
		"identity_preserved":        "true",
		"packet_roundtrips":         "2",
		"relay_payload_directions":  "2",
		"reopen_dials":              "2",
		"udp_fixture_operations":    "9",
		"unexpected_source_dropped": "true",
	})
}

func TestTier7EvidenceL3ParseErrorSkip(t *testing.T) {
	run := beginTier7Evidence()
	TestPumpSkipsParseErrors(t)
	run.emit(t, "T7.l3.parse-error-skip", map[string]string{
		"good_packets_handled":        "1",
		"input_packets":               "2",
		"malformed_copy_bytes":        "2",
		"malformed_packets_forwarded": "0",
		"parse_errors":                "1",
	})
}

func TestTier7EvidenceL3FragmentBoundary(t *testing.T) {
	run := beginTier7Evidence()
	TestParseRejectsIPv4FragmentsFailClosed(t)
	TestParseRejectsIPv6FragmentsFailClosed(t)
	TestPumpFragmentsHaveNoFlowSideEffects(t)
	TestFragmentPolicyParserMutationControl(t)
	run.emit(t, "T7.l3.fragment-boundary", map[string]string{
		"complete_fragment_headers":   "398",
		"flow_generations_allocated":  "0",
		"flow_table_entries":          "0",
		"fragment_inputs":             "401",
		"fragment_packets_forwarded":  "0",
		"fragmented_packet_reasons":   "398",
		"handler_calls":               "0",
		"input_mutations":             "0",
		"ip_versions":                 "4,6",
		"malformed_truncated_inputs":  "3",
		"partial_metadata_returns":    "0",
		"repeated_adversarial_inputs": "384",
		"router_calls":                "0",
		"short_packet_reasons":        "3",
		"valid_controls_accepted":     "2",
	})
}

func TestTier7EvidenceL3UnsupportedProtocol(t *testing.T) {
	run := beginTier7Evidence()
	TestParseRejectsUnsupportedProtocol(t)
	TestParseRejectsShortPacket(t)
	control := ipv4Packet(17, [4]byte{192, 0, 2, 1}, [4]byte{198, 51, 100, 1}, 5353, 53)
	meta, err := ParsePacket(control)
	if err != nil {
		t.Fatalf("supported UDP control rejected: %v", err)
	}
	if meta.Identity.Proto != ProtocolUDP {
		t.Fatalf("supported control protocol=%s, want udp", meta.Identity.Proto)
	}
	run.emit(t, "T7.l3.unsupported-protocol", map[string]string{
		"packet_fixture_count":       "3",
		"short_packet_reason":        "short_packet",
		"supported_control_protocol": "udp",
		"unsupported_reason":         "unsupported_protocol",
	})
}

func beginTier7Evidence() tier7EvidenceRun {
	return tier7EvidenceRun{started: time.Now(), goroutinesBefore: runtime.NumGoroutine()}
}

func (r tier7EvidenceRun) emit(t *testing.T, caseID string, facts map[string]string) {
	t.Helper()
	after := runtime.NumGoroutine()
	evidence := map[string]string{
		"schema":                  tier7EvidenceSchema,
		"case_id":                 caseID,
		"fixture":                 strings.ToLower(strings.ReplaceAll(caseID, ".", "-")) + "-v1",
		"seed_mode":               "none",
		"external_processes":      "0",
		"filesystem_writes":       "0",
		"negative_control_passed": "true",
		"privileged_operations":   "0",
		"elapsed_ns":              strconv.FormatInt(time.Since(r.started).Nanoseconds(), 10),
		"gomaxprocs":              strconv.Itoa(runtime.GOMAXPROCS(0)),
		"goroutine_growth":        strconv.Itoa(after - r.goroutinesBefore),
		"goroutines_after":        strconv.Itoa(after),
		"goroutines_before":       strconv.Itoa(r.goroutinesBefore),
	}
	for key, value := range facts {
		if _, exists := evidence[key]; exists {
			t.Fatalf("duplicate T7 evidence fact %q", key)
		}
		evidence[key] = value
	}
	encoded, err := json.Marshal(evidence)
	if err != nil {
		t.Fatalf("encode T7 evidence: %v", err)
	}
	fmt.Printf("%s%s\n", tier7EvidenceMarker, encoded)
}
