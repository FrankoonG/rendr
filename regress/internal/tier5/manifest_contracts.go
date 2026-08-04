package tier5

import (
	"fmt"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/manifest"
)

var tier5Contracts = map[string]manifest.Contract{
	"T5.1-tcprepair-privileged": blockedTier5Contract(
		"Privileged same-tuple TCP_REPAIR transfer and socket-rebuild smoke.",
		"regress/internal/tier5/runner.go::Run -> runSelectedCases -> executeCase -> caseDefs[T5.1-tcprepair-privileged] -> regress/internal/smoke.RunG1TCPRepairSameTuple",
		manifest.Topology{
			Profile:   "tier5-tcprepair-ipv4-loopback-v1",
			Roles:     []string{"test-process"},
			Isolation: "one Linux process with a rendr-owned raw TCP client path and an IPv4 loopback server",
			PathCount: 1,
		},
		map[string][]string{
			"test-process": {"CAP_NET_ADMIN", "Linux", "TCP_REPAIR available"},
		},
		definedProfile("tier5-tcprepair-byte-pattern-v1",
			profileParam("bytes", 100<<20, manifest.UnitBytes),
		),
		definedProfile("tier5-tcprepair-transfer-v1",
			profileParam("migrations", 3, manifest.UnitCount),
			profileParam("paths", 1, manifest.UnitCount),
			profileParam("transfers", 1, manifest.UnitCount),
		),
		manifest.SeedPolicy{Mode: manifest.SeedModeNone},
		withAssertions(
			evidenceProfile("tier5-tcprepair-smoke-stimulus-v1", "repairs_done"),
			uintAtLeastTier5("repairs_done", 3),
		),
		withAssertions(
			evidenceProfile("tier5-tcprepair-smoke-oracle-v1", "sha256_match"),
			equalsTier5("sha256_match", "true"),
		),
		nil,
	),
	"T5.2-gvisor-privileged": blockedTier5Contract(
		"Privileged gVisor-owned stream endpoint migration smoke.",
		"regress/internal/tier5/runner.go::Run -> runSelectedCases -> executeCase -> caseDefs[T5.2-gvisor-privileged] -> regress/internal/smoke.RunG1",
		manifest.Topology{
			Profile:   "tier5-gvisor-owned-process-local-v1",
			Roles:     []string{"test-process"},
			Isolation: "one Linux process with two gVisor-owned virtual stream paths",
			PathCount: 2,
		},
		map[string][]string{
			"test-process": {"gVisor adapter available", "Linux"},
		},
		definedProfile("g1-position-stable-payload-v1",
			profileParam("bytes", 30<<20, manifest.UnitBytes),
		),
		definedProfile("tier5-gvisor-transfer-v1",
			profileParam("migrations", 3, manifest.UnitCount),
			profileParam("paths", 2, manifest.UnitCount),
			profileParam("transfers", 1, manifest.UnitCount),
		),
		manifest.SeedPolicy{Mode: manifest.SeedModeNone},
		withAssertions(
			evidenceProfile("g1-migration-stimulus-v1", "migration_calls_fired", "migrations_done", "requested_migrations"),
			uintAtLeastTier5("migration_calls_fired", 3),
			uintAtLeastTier5("migrations_done", 3),
			equalsTier5("requested_migrations", "3"),
		),
		withAssertions(
			evidenceProfile("g1-integrity-oracle-v1", "sha256_match"),
			equalsTier5("sha256_match", "true"),
		),
		nil,
	),
	"T5.3-tcprepair-unprivileged": blockedTier5Contract(
		"Verify that the TCP_REPAIR capability probe reports permission denial after CAP_NET_ADMIN is removed.",
		"regress/internal/tier5/runner.go::Run -> runSelectedCases -> executeCase -> probeUnprivileged -> regress/internal/tier5/gotest.go::runUnprivilegedGoTest -> regress/internal/tier5/probes_linux_test.go::TestTier5TCPRepairUnprivilegedPreflight",
		manifest.Topology{
			Profile:   "tier5-setpriv-capability-probe-v1",
			Roles:     []string{"probe-process"},
			Isolation: "setpriv child with CAP_NET_ADMIN removed from inheritable, permitted, effective, bounding, and ambient sets and with isolated Go caches",
			PathCount: 0,
		},
		map[string][]string{
			"probe-process": {"CAP_NET_ADMIN absent", "Linux", "proc self status readable", "setpriv available"},
		},
		manifest.Profile{Applicability: manifest.ApplicabilityNotApplicable},
		definedProfile("tier5-exact-go-test-v1",
			profileParam("top_level_tests", 1, manifest.UnitCount),
		),
		manifest.SeedPolicy{Mode: manifest.SeedModeNone},
		withAssertions(
			evidenceProfile("tier5-capability-drop-and-fallback-context-v1",
				"cap_net_admin_absent", "fallback_outcome", "gvisor_involved", "kernel_tcp_to_gvisor_conversion", "preflight_error_typed_eperm", "prerequisite_valid", "setpriv_available", "setpriv_capability_drop_observed", "setpriv_requested",
			),
			equalsTier5("cap_net_admin_absent", "true"),
			equalsTier5("fallback_outcome", "not_exercised"),
			equalsTier5("gvisor_involved", "false"),
			equalsTier5("kernel_tcp_to_gvisor_conversion", "false"),
			equalsTier5("prerequisite_valid", "true"),
			equalsTier5("setpriv_capability_drop_observed", "true"),
		),
		withAssertions(
			evidenceProfile("tier5-tcprepair-denial-oracle-v1", "tcp_repair_preflight"),
			equalsTier5("tcp_repair_preflight", "permission_denied"),
		),
		nil,
	),
	"T5.4-gvisor-unprivileged": blockedTier5Contract(
		"Verify that a gVisor-owned process-local stream session transfers and migrates without CAP_NET_ADMIN.",
		"regress/internal/tier5/runner.go::Run -> runSelectedCases -> executeCase -> probeGVisorUnprivileged -> regress/internal/tier5/gotest.go::runUnprivilegedGoTest -> regress/internal/tier5/probes_linux_test.go::TestTier5GVisorOwnedSessionUnprivileged",
		manifest.Topology{
			Profile:   "tier5-unprivileged-gvisor-owned-v1",
			Roles:     []string{"probe-process"},
			Isolation: "setpriv child without CAP_NET_ADMIN running one process-local gVisor-owned session over two virtual paths",
			PathCount: 2,
		},
		map[string][]string{
			"probe-process": {"CAP_NET_ADMIN absent", "gVisor adapter available", "Linux", "setpriv available"},
		},
		definedProfile("g1-position-stable-payload-v1",
			profileParam("bytes", 4<<20, manifest.UnitBytes),
		),
		definedProfile("tier5-unprivileged-gvisor-transfer-v1",
			profileParam("migrations", 2, manifest.UnitCount),
			profileParam("paths", 2, manifest.UnitCount),
			profileParam("transfers", 1, manifest.UnitCount),
		),
		manifest.SeedPolicy{Mode: manifest.SeedModeNone},
		withAssertions(
			evidenceProfile("tier5-gvisor-owned-stimulus-and-context-v1",
				"cap_net_admin_absent", "gvisor_endpoint_owner", "gvisor_packet_link_rebind_observed", "kernel_tcp_to_gvisor_conversion", "migration_calls_fired", "migrations_observed", "requested_migrations", "setpriv_capability_drop_observed",
			),
			equalsTier5("cap_net_admin_absent", "true"),
			equalsTier5("gvisor_endpoint_owner", "gvisor_from_session_start"),
			equalsTier5("gvisor_packet_link_rebind_observed", "false"),
			equalsTier5("kernel_tcp_to_gvisor_conversion", "false"),
			uintAtLeastTier5("migration_calls_fired", 2),
			uintAtLeastTier5("migrations_observed", 2),
			equalsTier5("requested_migrations", "2"),
		),
		withAssertions(
			evidenceProfile("tier5-gvisor-owned-oracle-v1", "sha256_match", "workload_result"),
			equalsTier5("sha256_match", "true"),
			equalsTier5("workload_result", "pass"),
		),
		nil,
	),
	"T5.5-tcprepair-gvisor-fallback-unprivileged": blockedTier5Contract(
		"Exercise TCP_REPAIR permission failures, preserve the original socket, and prove regression-orchestrated same-session redial/attach while rejecting the absent product-negotiated mobility plan or typed planning failure.",
		"regress/internal/tier5/runner.go::Run -> runSelectedCases -> executeCase -> probeTCPRepairFallbackUnprivileged -> regress/internal/tier5/gotest.go::runUnprivilegedGoTest -> regress/internal/tier5/probes_linux_test.go::TestTier5TCPRepairFailureRequiresNegotiatedFallback",
		manifest.Topology{
			Profile:   "tier5-unprivileged-manual-redial-attach-v1",
			Roles:     []string{"probe-process"},
			Isolation: "setpriv child without CAP_NET_ADMIN using an IPv4 loopback TCP listener, one initial factory path, and one explicitly attached replacement path",
			PathCount: 2,
		},
		map[string][]string{
			"probe-process": {"CAP_NET_ADMIN absent", "Linux", "setpriv available"},
		},
		manifest.Profile{Applicability: manifest.ApplicabilityUnfrozen},
		definedProfile("tier5-manual-redial-attach-v1",
			profileParam("bidirectional_round_trips", 4, manifest.UnitCount),
			profileParam("factory_dials", 2, manifest.UnitCount),
			profileParam("migrations", 1, manifest.UnitCount),
			profileParam("paths_after_attach", 2, manifest.UnitCount),
			profileParam("tcp_repair_permission_failures", 2, manifest.UnitCount),
		),
		manifest.SeedPolicy{Mode: manifest.SeedModeNone},
		withAssertions(
			evidenceProfile("tier5-manual-redial-attach-stimulus-v1",
				"attach_negotiation", "cap_net_admin_absent", "factory_dials", "fallback_outcome", "fallback_selection", "migration_count_delta", "original_socket_usable_after_preflight", "original_socket_usable_after_prepare_failure", "prepare_error_typed_eperm", "preflight_error_typed_eperm", "tcp_repair_preflight", "tcp_repair_prepare",
			),
			equalsTier5("cap_net_admin_absent", "true"),
			uintAtLeastTier5("factory_dials", 2),
			uintAtLeastTier5("migration_count_delta", 1),
			equalsTier5("original_socket_usable_after_preflight", "true"),
			equalsTier5("original_socket_usable_after_prepare_failure", "true"),
		),
		manifest.EvidenceProfile{},
		[]manifest.MissingDimension{
			{Dimension: manifest.ContractDimensionPayload, Reason: "The four round-trip strings have different byte lengths, and the case does not freeze a payload byte profile."},
			{Dimension: manifest.ContractDimensionOracle, Reason: "The current case deliberately reports failure because explicit AdminConn.AddPath redial/attach is neither a product-negotiated mobility plan nor a typed mobility-planning failure."},
		},
	),
	"T5.6-gvisor-packet-carrier-unprivileged": blockedTier5Contract(
		"Verify an unprivileged gVisor-owned stream endpoint over the external UDP packet carrier.",
		"regress/internal/tier5/runner.go::Run -> runSelectedCases -> executeCase -> probeGVisorPacketCarrierUnprivileged -> regress/internal/tier5/gotest.go::runUnprivilegedGoTest -> regress/internal/tier5/probes_linux_test.go::TestTier5GVisorPacketCarrierOwnedSessionUnprivileged",
		manifest.Topology{
			Profile:   "tier5-unprivileged-gvisor-packet-carrier-v1",
			Roles:     []string{"probe-process"},
			Isolation: "setpriv child without CAP_NET_ADMIN running one gVisor-owned stream session over two UDP packet-carrier paths",
			PathCount: 2,
		},
		map[string][]string{
			"probe-process": {"CAP_NET_ADMIN absent", "gVisor adapter available", "Linux", "setpriv available", "UDP loopback"},
		},
		definedProfile("g1-position-stable-payload-v1",
			profileParam("bytes", 4<<20, manifest.UnitBytes),
		),
		definedProfile("tier5-unprivileged-gvisor-packet-transfer-v1",
			profileParam("migrations", 2, manifest.UnitCount),
			profileParam("paths", 2, manifest.UnitCount),
			profileParam("transfers", 1, manifest.UnitCount),
		),
		manifest.SeedPolicy{Mode: manifest.SeedModeNone},
		withAssertions(
			evidenceProfile("tier5-gvisor-packet-stimulus-and-context-v1",
				"cap_net_admin_absent", "gvisor_endpoint_owner", "gvisor_packet_link_rebind_observed", "kernel_tcp_to_gvisor_conversion", "migration_calls_fired", "migrations_observed", "outer_carrier", "requested_migrations", "setpriv_capability_drop_observed",
			),
			equalsTier5("cap_net_admin_absent", "true"),
			equalsTier5("gvisor_endpoint_owner", "gvisor_from_session_start"),
			equalsTier5("gvisor_packet_link_rebind_observed", "false"),
			equalsTier5("kernel_tcp_to_gvisor_conversion", "false"),
			uintAtLeastTier5("migration_calls_fired", 2),
			uintAtLeastTier5("migrations_observed", 2),
			equalsTier5("outer_carrier", "udp"),
			equalsTier5("requested_migrations", "2"),
		),
		withAssertions(
			evidenceProfile("tier5-gvisor-packet-oracle-v1", "sha256_match", "workload_result"),
			equalsTier5("sha256_match", "true"),
			equalsTier5("workload_result", "pass"),
		),
		nil,
	),
}

func blockedTier5Contract(
	purpose string,
	entrypoint string,
	topology manifest.Topology,
	capabilities map[string][]string,
	payload manifest.Profile,
	load manifest.Profile,
	seed manifest.SeedPolicy,
	stimulus manifest.EvidenceProfile,
	oracle manifest.EvidenceProfile,
	extraMissing []manifest.MissingDimension,
) manifest.Contract {
	missing := append([]manifest.MissingDimension{
		{Dimension: manifest.ContractDimensionNegativeControl, Reason: "The executable case has no registered separate or embedded negative control for its current behavior."},
		{Dimension: manifest.ContractDimensionResources, Reason: "Per-role vCPU, RAM, and disk minima have not been calibrated for this case."},
	}, extraMissing...)
	return manifest.Contract{
		SchemaVersion:     manifest.ContractSchemaVersion,
		State:             manifest.ContractStateBlocked,
		MissingDimensions: missing,
		Purpose:           purpose,
		Entrypoint:        entrypoint,
		Topology:          topology,
		RoleCapabilities:  capabilities,
		Payload:           payload,
		Load:              load,
		Seed:              seed,
		Stimulus:          stimulus,
		Oracle:            oracle,
		NegativeControl: manifest.NegativeControl{
			Kind: manifest.NegativeControlAbsent,
		},
		Resources: manifest.ResourceBudget{
			State: manifest.ResourceStateUnfrozen,
		},
	}
}

func definedProfile(name string, params ...manifest.ProfileParam) manifest.Profile {
	return manifest.Profile{
		Applicability: manifest.ApplicabilityDefined,
		Name:          name,
		Version:       1,
		Params:        params,
	}
}

func profileParam(name string, value uint64, unit manifest.BaseUnit) manifest.ProfileParam {
	return manifest.ProfileParam{Name: name, Value: value, Unit: unit}
}

func evidenceProfile(name string, facts ...string) manifest.EvidenceProfile {
	return manifest.EvidenceProfile{Name: name, Version: 1, RequiredFacts: facts}
}

func withAssertions(profile manifest.EvidenceProfile, assertions ...manifest.EvidenceAssertion) manifest.EvidenceProfile {
	profile.Assertions = assertions
	return profile
}

func equalsTier5(fact, expected string) manifest.EvidenceAssertion {
	return manifest.EvidenceAssertion{Fact: fact, Predicate: manifest.EvidenceEquals, Expected: expected}
}

func uintAtLeastTier5(fact string, expected uint64) manifest.EvidenceAssertion {
	return manifest.EvidenceAssertion{Fact: fact, Predicate: manifest.EvidenceUintAtLeast, Expected: fmt.Sprint(expected)}
}

func mustTier5Spec(id string, budget time.Duration) manifest.Spec {
	contract, ok := tier5Contracts[id]
	if !ok {
		panic(fmt.Sprintf("tier5: no manifest contract metadata for %q", id))
	}
	spec, err := manifest.NewCompleteSpec(manifest.RequiredWithBudget(id, "T5", budget), contract)
	if err != nil {
		panic(fmt.Sprintf("tier5: invalid manifest contract for %q: %v", id, err))
	}
	return spec
}
