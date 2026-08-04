package tier7

import (
	"fmt"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/manifest"
)

type contractMetadata struct {
	purpose           string
	entrypoint        string
	expectedTests     uint64
	roles             []string
	roleCapabilities  map[string][]string
	pathCount         int
	topologyIsolation string
	topologyMissing   string
}

var contractMetadataByID = map[string]contractMetadata{
	"T7.capability.local-probe": {
		purpose:       "Probe the local Linux kernel for TUN creation and return a machine-readable result with typed details when unavailable.",
		entrypoint:    "regress/internal/tier7/runner.go::runGoTests -> tun/config_test.go::TestProbeReturnsMachineReadableCapability",
		expectedTests: 1,
		roles:         []string{"go-test-process", "kernel-tun"},
		roleCapabilities: map[string][]string{
			"go-test-process": {"Linux"},
			"kernel-tun":      {"local /dev/net/tun open and TUNSETIFF probe target"},
		},
		pathCount:         0,
		topologyIsolation: "one Linux Go test process probes /dev/net/tun and TUNSETIFF against the local kernel; no rendr path or peer process is present",
	},
	"T7.tun.open-smoke": {
		purpose:           "Open and close an ephemeral real kernel TUN device when the local capability probe reports availability.",
		entrypoint:        "regress/internal/tier7/runner.go::runGoTests -> tun/device_linux_test.go::TestOpenCreatesEphemeralDeviceWhenAvailable",
		expectedTests:     1,
		roles:             []string{"go-test-process", "kernel-tun"},
		roleCapabilities:  map[string][]string{"go-test-process": {"CAP_NET_ADMIN", "Linux", "/dev/net/tun"}, "kernel-tun": {}},
		pathCount:         0,
		topologyIsolation: "one Linux Go test process creates one ephemeral TUN device in the local kernel; no rendr path or peer process is present",
	},
	"T7.tun.packet-io": {
		purpose:       "Configure an ephemeral real kernel TUN and read one kernel-routed IPv4 ICMP packet with the expected addresses.",
		entrypoint:    "regress/internal/tier7/runner.go::runGoTests -> tun/device_linux_test.go::TestDeviceReadsKernelRoutedIPv4Packet",
		expectedTests: 1,
		roles:         []string{"go-test-process", "kernel-tun"},
		roleCapabilities: map[string][]string{
			"go-test-process": {"/dev/net/tun", "CAP_NET_ADMIN", "Linux", "effective UID 0", "ip executable", "ping executable"},
			"kernel-tun":      {},
		},
		pathCount:         0,
		topologyIsolation: "one Linux Go test process configures one ephemeral TUN device and invokes local ping; no rendr path or peer process is present",
	},
	"T7.config.invalid-mtu": unitMetadata(
		"Reject an enabled TUN configuration whose MTU is one byte below the minimum and return the typed invalid-MTU reason.",
		"regress/internal/tier7/runner.go::runGoTests -> tun/config_test.go::TestConfigValidateRejectsSmallMTU", 1),
	"T7.l3.identity-smoke": unitMetadata(
		"Parse constructed IPv4 TCP and IPv6 UDP packets into exact source and destination identities.",
		"regress/internal/tier7/runner.go::runGoTests -> l3ingress/packet_test.go::TestParseIPv4TCPIdentity, l3ingress/packet_test.go::TestParseIPv6UDPIdentity", 2),
	"T7.l3.identity-wire": unitMetadata(
		"Round-trip IPv4 and IPv6 identities through the identity wire codec and reject a mixed-address-family identity.",
		"regress/internal/tier7/runner.go::runGoTests -> l3ingress/wire_test.go::TestIdentityWireRoundTripIPv4, TestIdentityWireRoundTripIPv6, TestIdentityWireRejectsMixedFamilies", 3),
	"T7.capability.peer-denied": unitMetadata(
		"Reject capability sets that omit peer L3 identity or peer egress support.",
		"regress/internal/tier7/runner.go::runGoTests -> l3ingress/wire_test.go::TestRequirePeerL3Identity, TestRequirePeerEgress", 2),
	"T7.capability.peer-advertise": missingTopologyMetadata(
		"Advertise L3 identity on stream dialing and advertise L3 identity plus packet mode on packet dialing.",
		"regress/internal/tier7/runner.go::runGoTests -> capabilities_test.go::TestDialerAdvertisesL3IdentityCapability, TestDialPacketAdvertisesL3IdentityAndPacketMode", 2,
		"the stream and packet subtests use different fixture transports, so one topology and path count are not frozen"),
	"T7.router.per-flow-hook": unitMetadata(
		"Parse an in-memory packet and invoke the configured per-flow router with its identity.",
		"regress/internal/tier7/runner.go::runGoTests -> l3ingress/pump_test.go::TestPumpRoutesParsedPackets", 1),
	"T7.router.per-flow-cache": unitMetadata(
		"Route repeated in-memory packets for one flow while invoking the router only once.",
		"regress/internal/tier7/runner.go::runGoTests -> l3ingress/pump_test.go::TestPumpCachesRouterDecisionPerFlow", 1),
	"T7.session.request": unitMetadata(
		"Map TCP and UDP flow decisions to stream and packet session requests, then reject invalid decisions and identity mismatches.",
		"regress/internal/tier7/runner.go::runGoTests -> l3ingress/session_test.go::TestBuildSessionRequestMapsTCPAndUDP, TestBuildSessionRequestRejectsInvalidDecisions, TestBuildSessionRequestRejectsIdentityMismatch", 3),
	"T7.session.start": missingTopologyMetadata(
		"Start separate loopback stream and packet sessions with L3 capability preservation and reject unsupported session requests.",
		"regress/internal/tier7/runner.go::runGoTests -> l3session/session_test.go::TestStarterStreamSessionPreservesL3Capability, TestStarterPacketSessionPreservesL3Capability, TestStarterRejectsUnsupportedRequest", 3,
		"the case aggregates separate TCP, UDP-flow, and no-network rejection fixtures, so one topology and path count are not frozen"),
	"T7.session.manager": missingTopologyMetadata(
		"Start and cache one loopback stream session per flow and propagate an undecided-flow planning error.",
		"regress/internal/tier7/runner.go::runGoTests -> l3session/manager_test.go::TestManagerStartsOneSessionPerFlow, TestManagerPropagatesPlanningErrors", 2,
		"the case aggregates a one-path loopback session test and a no-network planning-error test, so one topology and path count are not frozen"),
	"T7.session.lifecycle": unitMetadata(
		"Close and evict a fake cached stream session exactly once after a closed flow snapshot.",
		"regress/internal/tier7/runner.go::runGoTests -> l3session/manager_test.go::TestManagerClosesSessionOnFlowClose", 1),
	"T7.session.path-observe": loopbackMetadata(
		"Record initial path tcp-a, manually migrate a two-path stream session to tcp-b, and observe one migration in the flow snapshot.",
		"regress/internal/tier7/runner.go::runGoTests -> l3session/manager_test.go::TestManagerRecordsSessionPathSelectionAndMigrations", 1, 2,
		"one Go test process contains client, server, flow table, and manager around one loopback TCP listener"),
	"T7.router.flow-deny": unitMetadata(
		"Cache a denied flow decision and suppress handler delivery for denied in-memory packets.",
		"regress/internal/tier7/runner.go::runGoTests -> l3ingress/flow_table_test.go::TestFlowTableCachesDeniedDecision, l3ingress/pump_test.go::TestPumpSkipsDeniedFlow", 2),
	"T7.flow.lifecycle-stats": unitMetadata(
		"Cache flow decisions, update counters, publish a close snapshot, and use the caller-provided flow table in Pump.",
		"regress/internal/tier7/runner.go::runGoTests -> l3ingress/flow_table_test.go::TestFlowTableCachesDecisionAndStats, TestFlowTableCloseSnapshot, l3ingress/pump_test.go::TestPumpUsesProvidedFlowTable", 3),
	"T7.flow.observe": unitMetadata(
		"Deliver lifecycle snapshots to an observer and record selected-path and migration fields in flow state.",
		"regress/internal/tier7/runner.go::runGoTests -> l3ingress/flow_table_test.go::TestFlowTableObserverReceivesLifecycleSnapshots, TestFlowTableRecordsPathSelectionAndMigrations", 2),
	"T7.selector.per-flow": unitMetadata(
		"Track independent selector decisions and statistics for two constructed flows.",
		"regress/internal/tier7/runner.go::runGoTests -> l3ingress/flow_table_test.go::TestFlowTableTracksIndependentSelectorFlows", 1),
	"T7.peer-egress-hook": unitMetadata(
		"Dispatch a constructed L3 identity to a registered egress and return machine-readable errors for invalid egress operations.",
		"regress/internal/tier7/runner.go::runGoTests -> l3ingress/egress_test.go::TestEgressRegistryDispatchesIdentity, TestEgressRegistryMachineReadableErrors", 2),
	"T7.tcp.peer-egress": unitMetadata(
		"Dispatch TCP identity to an in-process egress, bridge a stream, close the flow, and allow the same identity to reopen.",
		"regress/internal/tier7/runner.go::runGoTests -> l3ingress/tcp_relay_test.go::TestTCPFlowRelayDispatchesIdentityAndBridgesStream, TestTCPFlowRelayCloseFlowAllowsReopen", 2),
	"T7.udp.identity-smoke": unitMetadata(
		"Extract UDP payloads, round-trip constructed IPv4 and IPv6 UDP packets, dispatch identity through a mock relay, write a reply, and reopen the flow.",
		"regress/internal/tier7/runner.go::runGoTests -> l3ingress/udp_packet_test.go::TestUDPPayloadExtractsData, TestBuildUDPPacketRoundTripIPv4, TestBuildUDPPacketRoundTripIPv6, l3ingress/udp_relay_test.go::TestUDPFlowRelayDispatchesPayloadAndWritesReply, TestUDPFlowRelayCloseFlowAllowsReopen", 5),
	"T7.udp.rendr-relay": loopbackMetadata(
		"Forward a constructed UDP query through one rendr UDP-flow packet path and rebuild the reverse-direction reply into an in-memory capture device.",
		"regress/internal/tier7/runner.go::runGoTests -> l3session/udp_relay_test.go::TestUDPRelayForwardsPayloadThroughRendrPacketSession", 1, 1,
		"one Go test process contains relay, capture device, client, and server around one loopback UDP-flow listener"),
	"T7.udp.migration": loopbackMetadata(
		"Manually migrate a two-path UDP-flow packet session from udp-a to udp-b while preserving payload replies and FlowID.",
		"regress/internal/tier7/runner.go::runGoTests -> l3session/udp_relay_test.go::TestUDPRelayPreservesFlowAcrossPacketMigration", 1, 2,
		"one Go test process contains relay, capture device, client, and server; both logical packet paths use one loopback UDP-flow listener"),
	"T7.tcp.rendr-relay": loopbackMetadata(
		"Bridge hello/world traffic between a net.Pipe endpoint and one rendr loopback TCP stream path.",
		"regress/internal/tier7/runner.go::runGoTests -> l3session/tcp_relay_test.go::TestTCPRelayBridgesEndpointThroughRendrStreamSession", 1, 1,
		"one Go test process contains net.Pipe application endpoints, relay, client, and server around one loopback TCP listener"),
	"T7.tcp.migration": loopbackMetadata(
		"Manually migrate a two-path TCP stream session from tcp-a to tcp-b while preserving two echo exchanges and FlowID.",
		"regress/internal/tier7/runner.go::runGoTests -> l3session/tcp_relay_test.go::TestTCPRelayPreservesFlowAcrossStreamMigration", 1, 2,
		"one Go test process contains net.Pipe application endpoints, relay, client, and server; both logical paths use one loopback TCP listener"),
	"T7.tcp.lifecycle-flags": unitMetadata(
		"Parse constructed TCP FIN and RST flags and close in-memory flow-table state when Pump receives a reset packet.",
		"regress/internal/tier7/runner.go::runGoTests -> l3ingress/packet_test.go::TestParseTCPCloseFlags, l3ingress/pump_test.go::TestPumpClosesFlowTableOnTCPReset", 2),
	"T7.l3.parse-error-skip": unitMetadata(
		"Feed a malformed in-memory L3 packet to Pump and assert that it is skipped without routing.",
		"regress/internal/tier7/runner.go::runGoTests -> l3ingress/pump_test.go::TestPumpSkipsParseErrors", 1),
	"T7.l3.fragment-boundary": unitMetadata(
		"Parse an IPv4 UDP first fragment carrying the more-fragments flag and reject a non-initial IPv4 fragment.",
		"regress/internal/tier7/runner.go::runGoTests -> l3ingress/packet_test.go::TestParseIPv4UDPMoreFragmentFirstFragment, TestParseRejectsIPv4NonInitialFragment", 2),
	"T7.l3.unsupported-protocol": unitMetadata(
		"Reject constructed packets with an unsupported L3 protocol or a truncated header.",
		"regress/internal/tier7/runner.go::runGoTests -> l3ingress/packet_test.go::TestParseRejectsUnsupportedProtocol, TestParseRejectsShortPacket", 2),
}

func unitMetadata(purpose, entrypoint string, expectedTests uint64) contractMetadata {
	return contractMetadata{
		purpose:           purpose,
		entrypoint:        entrypoint,
		expectedTests:     expectedTests,
		roles:             []string{"go-test-process"},
		roleCapabilities:  map[string][]string{"go-test-process": {}},
		topologyIsolation: "one Go test process uses constructed structs, packets, and in-memory fixtures without an external network peer",
	}
}

func loopbackMetadata(purpose, entrypoint string, expectedTests uint64, pathCount int, isolation string) contractMetadata {
	return contractMetadata{
		purpose:           purpose,
		entrypoint:        entrypoint,
		expectedTests:     expectedTests,
		roles:             []string{"go-test-process"},
		roleCapabilities:  map[string][]string{"go-test-process": {}},
		pathCount:         pathCount,
		topologyIsolation: isolation,
	}
}

func missingTopologyMetadata(purpose, entrypoint string, expectedTests uint64, reason string) contractMetadata {
	return contractMetadata{purpose: purpose, entrypoint: entrypoint, expectedTests: expectedTests, topologyMissing: reason}
}

func mustCaseSpec(id string, budget time.Duration) manifest.Spec {
	metadata, ok := contractMetadataByID[id]
	if !ok {
		panic(fmt.Sprintf("tier7: missing contract metadata for %q", id))
	}
	spec, err := manifest.NewCompleteSpec(manifest.RequiredWithBudget(id, "T7", budget), blockedGoTestContract(id, metadata))
	if err != nil {
		panic(err)
	}
	return spec
}

func blockedGoTestContract(id string, metadata contractMetadata) manifest.Contract {
	missing := []manifest.MissingDimension{
		{Dimension: manifest.ContractDimensionPayload, Reason: "semantic input and payload values remain test-local and no versioned payload profile is frozen by the runner"},
		{Dimension: manifest.ContractDimensionSeed, Reason: "fixture identity generation and any randomness are not surfaced or recorded by the runner"},
		{Dimension: manifest.ContractDimensionStimulus, Reason: "the runner emits no report.Case evidence for the semantic stimulus"},
		{Dimension: manifest.ContractDimensionOracle, Reason: "the runner emits no report.Case evidence for semantic assertions beyond the aggregate test result"},
		{Dimension: manifest.ContractDimensionNegativeControl, Reason: "the exact-go-test case has no embedded mutation or separately registered control that proves the runner reports FAIL or INVALID"},
		{Dimension: manifest.ContractDimensionResources, Reason: "per-role vCPU, RAM, and disk minima have not been calibrated"},
	}
	contract := manifest.Contract{
		SchemaVersion:     manifest.ContractSchemaVersion,
		State:             manifest.ContractStateBlocked,
		MissingDimensions: missing,
		Purpose:           metadata.purpose,
		Entrypoint:        metadata.entrypoint,
		Payload:           manifest.Profile{Applicability: manifest.ApplicabilityUnfrozen},
		Load: manifest.Profile{
			Applicability: manifest.ApplicabilityDefined,
			Name:          "exact-go-test-invocation",
			Version:       1,
			Params: []manifest.ProfileParam{{
				Name:  "expected_top_level_tests",
				Value: metadata.expectedTests,
				Unit:  manifest.UnitCount,
			}},
		},
		NegativeControl: manifest.NegativeControl{Kind: manifest.NegativeControlAbsent},
		Resources:       manifest.ResourceBudget{State: manifest.ResourceStateUnfrozen},
	}
	if metadata.topologyMissing != "" {
		contract.MissingDimensions = append(contract.MissingDimensions,
			manifest.MissingDimension{Dimension: manifest.ContractDimensionTopology, Reason: metadata.topologyMissing},
			manifest.MissingDimension{Dimension: manifest.ContractDimensionRoleCapabilities, Reason: "role capabilities cannot be frozen while the aggregate case topology is unfrozen"},
		)
		return contract
	}
	contract.Topology = manifest.Topology{
		Profile:   id + "-fixture-v1",
		Roles:     metadata.roles,
		Isolation: metadata.topologyIsolation,
		PathCount: metadata.pathCount,
	}
	contract.RoleCapabilities = metadata.roleCapabilities
	return contract
}
