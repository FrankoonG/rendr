package tunfull

import (
	"fmt"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/manifest"
)

const (
	tunCapabilitiesReason = "the synthetic runner does not freeze capability requirements per topology role"
	tunControlReason      = "the executable case has no embedded or separately registered negative control"
	tunResourcesReason    = "minimum per-role vCPU, RAM, and disk allocations have not been calibrated"
	noCaseEvidenceReason  = "the successful runner emits no case-specific evidence facts for this dimension"
)

func completeTUNSpec(id string, budget time.Duration, long bool) manifest.Spec {
	base := tunSpec(id, budget, long)
	contract, ok := tunContract(id)
	if !ok {
		panic(fmt.Sprintf("tunfull: no manifest contract for %q", id))
	}
	spec, err := manifest.NewCompleteSpec(base, contract)
	if err != nil {
		panic(err)
	}
	return spec
}

func tunContract(id string) (manifest.Contract, bool) {
	seedless := manifest.SeedPolicy{Mode: manifest.SeedModeNone}
	missingSeed := func(reason string) (manifest.SeedPolicy, manifest.MissingDimension) {
		return manifest.SeedPolicy{}, missingTUN(manifest.ContractDimensionSeed, reason)
	}
	missingEvidence := func(dimension manifest.ContractDimension) manifest.MissingDimension {
		return missingTUN(dimension, noCaseEvidenceReason)
	}

	switch id {
	case caseKernelTUNPreflight:
		seed, seedMissing := missingSeed("the positive and capability-denied helper probes use a crypto/rand nonce that is not emitted as a recorded seed")
		stimulus := evidenceTUN("kernel-tun-positive-probe-and-scope",
			"case_payload_via_kernel_tun", "kernel_tun_cleanup_verified", "kernel_tun_fd_read_from_kernel", "kernel_tun_fd_write_to_kernel", "kernel_tun_gold", "kernel_tun_packet_integrity", "kernel_tun_packet_io",
		)
		stimulus.Assertions = []manifest.EvidenceAssertion{
			equalsTUN("case_payload_via_kernel_tun", "false"),
			equalsTUN("kernel_tun_cleanup_verified", "true"),
			equalsTUN("kernel_tun_fd_read_from_kernel", "true"),
			equalsTUN("kernel_tun_fd_write_to_kernel", "true"),
			equalsTUN("kernel_tun_gold", "false"),
			equalsTUN("kernel_tun_packet_integrity", "true"),
			equalsTUN("kernel_tun_packet_io", "true"),
		}
		oracle := evidenceTUN("kernel-tun-environment-gate-oracle", "kernel_tun_available", "kernel_tun_environment_gate_pass", "kernel_tun_negative_control_pass")
		oracle.Assertions = []manifest.EvidenceAssertion{
			equalsTUN("kernel_tun_available", "true"),
			equalsTUN("kernel_tun_environment_gate_pass", "true"),
			equalsTUN("kernel_tun_negative_control_pass", "true"),
		}
		return blockedTUNContract(
			"Prove this Linux process can create a kernel TUN interface, exchange one packet in each direction, clean it up, and reject a CAP_NET_ADMIN-denied helper probe.",
			"regress/internal/tunfull/runner.go::runKernelTUNPreflightManifestCase -> regress/internal/tunfull/kernel_tun_gate.go::runKernelTUNGate -> regress/internal/tunfull/kernel_tun_gate_linux.go::runKernelTUNProbe",
			manifest.Topology{Profile: "real-kernel-tun-positive-and-capability-denied-helper", Roles: []string{"kernel", "negative-helper", "positive-probe"}, Isolation: "one positive process plus one capability-dropped subprocess on the same Linux kernel", PathCount: 0},
			map[string][]string{
				"kernel":          {},
				"negative-helper": {"CAP_NET_ADMIN absent", "Linux"},
				"positive-probe":  {"CAP_NET_ADMIN", "Linux", "/dev/net/tun"},
			},
			profileTUN("kernel-tun-bidirectional-packet-io", paramTUN("read_marker_bytes", 47, manifest.UnitBytes), paramTUN("write_marker_bytes", 48, manifest.UnitBytes)),
			profileTUN("kernel-tun-preflight", paramTUN("negative_probes", 1, manifest.UnitCount), paramTUN("positive_probes", 1, manifest.UnitCount)),
			seed,
			stimulus,
			oracle,
			manifest.NegativeControl{Kind: manifest.NegativeControlEmbedded, EmbeddedID: "CAP_NET_ADMIN-denied kernel TUN helper probe"},
			seedMissing,
		), true
	case caseG1Smoke:
		return syntheticTUNContract(
			"Run a synthetic 30 MiB L3-session TCP stream transfer with three manual migrations and byte-hash assertions.",
			"regress/internal/tunfull/runner.go::runG1ManifestCase -> regress/internal/tunfull/runner.go::runG1Smoke",
			"net-pipe-to-l3-session-over-two-local-tcp-paths", 2,
			profileTUN("synthetic-position-pattern", paramTUN("payload_bytes", 30<<20, manifest.UnitBytes)),
			profileTUN("synthetic-g1-smoke", paramTUN("requested_migrations", 3, manifest.UnitCount)),
			seedless, manifest.EvidenceProfile{}, manifest.EvidenceProfile{},
			missingEvidence(manifest.ContractDimensionStimulus), missingEvidence(manifest.ContractDimensionOracle),
		), true
	case caseG2Smoke:
		return syntheticTUNContract(
			"Run a synthetic 30-second L3-session TCP echo loop with five manual migrations and a fixed one-second P99 ceiling.",
			"regress/internal/tunfull/runner.go::runG2ManifestCase -> regress/internal/tunfull/runner.go::runG2Smoke",
			"net-pipe-to-l3-session-over-two-local-tcp-paths", 2,
			profileTUN("synthetic-echo-record", paramTUN("payload_bytes", 8, manifest.UnitBytes)),
			profileTUN("synthetic-g2-smoke", paramTUN("duration_ns", uint64((30*time.Second).Nanoseconds()), manifest.UnitNanoseconds), paramTUN("interval_ns", uint64((100*time.Millisecond).Nanoseconds()), manifest.UnitNanoseconds), paramTUN("requested_migrations", 5, manifest.UnitCount)),
			seedless, manifest.EvidenceProfile{}, manifest.EvidenceProfile{},
			missingEvidence(manifest.ContractDimensionStimulus), missingEvidence(manifest.ContractDimensionOracle),
		), true
	case caseG3Smoke:
		return syntheticG3TUNContract("five-second 5,000 pps", "runG3ManifestCase", 5*time.Second, 5_000, 4, 3, 50*time.Millisecond), true
	case caseG4PathDeath:
		stimulus := evidenceTUN("internal-force-kill", "kill_attempted", "kill_path_id", "kill_path_removed")
		stimulus.Assertions = []manifest.EvidenceAssertion{
			equalsTUN("kill_attempted", "true"),
			equalsTUN("kill_path_removed", "true"),
		}
		oracle := evidenceTUN("synthetic-g4-echo-oracle", "application_losses", "failover_ms", "max_echo_rtt_ms", "post_kill_samples")
		oracle.Assertions = []manifest.EvidenceAssertion{
			equalsTUN("application_losses", "0"),
			uintAtMostTUN("failover_ms", 5000),
			uintAtLeastTUN("post_kill_samples", 1),
		}
		return syntheticTUNContract(
			"Run a synthetic six-second echo flow and remove its active in-process path through the ForceKillPathForTest hook after two seconds.",
			"regress/internal/tunfull/runner.go::runG4ManifestCase -> regress/internal/tunfull/runner.go::runG4PathDeath",
			"net-pipe-to-l3-session-over-two-local-tcp-paths", 2,
			profileTUN("synthetic-echo-record", paramTUN("payload_bytes", 8, manifest.UnitBytes)),
			profileTUN("synthetic-g4-path-kill", paramTUN("duration_ns", uint64((6*time.Second).Nanoseconds()), manifest.UnitNanoseconds), paramTUN("echo_interval_ns", uint64((10*time.Millisecond).Nanoseconds()), manifest.UnitNanoseconds), paramTUN("failover_budget_ns", uint64((5*time.Second).Nanoseconds()), manifest.UnitNanoseconds), paramTUN("kill_at_ns", uint64((2*time.Second).Nanoseconds()), manifest.UnitNanoseconds)),
			seedless,
			stimulus,
			oracle,
		), true
	case caseG5PathRecovery:
		return syntheticTUNContract(
			"Run a synthetic TCP session, remove its active path, manually add a replacement path, and verify 256 KiB of echoed bytes.",
			"regress/internal/tunfull/runner.go::runG5ManifestCase -> regress/internal/tunfull/runner.go::runG5PathRecovery",
			"net-pipe-to-l3-session-over-two-local-tcp-paths", 2,
			profileTUN("synthetic-post-add-pattern", paramTUN("payload_bytes", 256<<10, manifest.UnitBytes)),
			profileTUN("synthetic-g5-manual-recovery", paramTUN("manual_add_path_calls", 1, manifest.UnitCount), paramTUN("test_hook_path_kills", 1, manifest.UnitCount)),
			seedless, manifest.EvidenceProfile{}, manifest.EvidenceProfile{},
			missingEvidence(manifest.ContractDimensionStimulus), missingEvidence(manifest.ContractDimensionOracle),
		), true
	case caseT3XrayMatrix:
		seed, seedMissing := missingSeed("the fourteen nested matrix fixtures do not expose or record one reproducibility seed")
		stimulus := evidenceTUN("strict-go-test-json-selection", "expected_top_level_tests", "go_test_json")
		stimulus.Assertions = []manifest.EvidenceAssertion{
			equalsTUN("expected_top_level_tests", "14"),
			equalsTUN("go_test_json", "strict"),
		}
		oracle := evidenceTUN("strict-go-test-json-results", "passed_top_level_tests")
		oracle.Assertions = []manifest.EvidenceAssertion{equalsTUN("passed_top_level_tests", "14")}
		return blockedTUNContract(
			"Run the fourteen exact TestTUNT3 wrappers in the nested regress matrix module with strict go test JSON accounting.",
			"regress/internal/tunfull/runner.go::runT3XrayMatrixManifestCase -> regress/internal/tunfull/gotest.go::runT3XrayMatrix -> tunGoTestReportCase",
			manifest.Topology{}, nil,
			manifest.Profile{Applicability: manifest.ApplicabilityUnfrozen},
			profileTUN("exact-tun-t3-test-matrix", paramTUN("top_level_tests", 14, manifest.UnitCount)),
			seed,
			stimulus,
			oracle,
			manifest.NegativeControl{Kind: manifest.NegativeControlAbsent},
			missingTUN(manifest.ContractDimensionTopology, "the registry row spans fourteen fixture-defined topologies that are not frozen into one topology profile"),
			missingTUN(manifest.ContractDimensionRoleCapabilities, "role capabilities cannot be frozen until the fourteen fixture topologies are enumerated"),
			missingTUN(manifest.ContractDimensionPayload, "payload sizes are fixture-defined across fourteen tests and are not frozen in this runner"),
			seedMissing,
			missingTUN(manifest.ContractDimensionNegativeControl, tunControlReason),
		), true
	case caseT4G1:
		seed, seedMissing := missingSeed("the qdisc fixture chooses random ownership handles and does not record a reproducibility seed")
		return syntheticTUNContract(
			"Run a synthetic 1 GiB L3-session TCP transfer with ten manual migrations under the 50 Mbps loopback qdisc.",
			"regress/internal/tunfull/runner.go::runT4G1ManifestCase -> regress/internal/tunfull/runner.go::runT4WithBudget -> runG1Smoke",
			"net-pipe-to-l3-session-over-two-local-tcp-paths-with-loopback-qdisc", 2,
			profileTUN("synthetic-position-pattern", paramTUN("payload_bytes", 1<<30, manifest.UnitBytes)),
			profileTUN("synthetic-t4-g1", paramTUN("bandwidth_bps", 50_000_000, manifest.UnitBitsPerSecond), paramTUN("requested_migrations", 10, manifest.UnitCount)),
			seed, manifest.EvidenceProfile{}, manifest.EvidenceProfile{},
			seedMissing, missingEvidence(manifest.ContractDimensionStimulus), missingEvidence(manifest.ContractDimensionOracle),
		), true
	case caseT4G2:
		seed, seedMissing := missingSeed("the qdisc fixture chooses random ownership handles and does not record a reproducibility seed")
		return syntheticTUNContract(
			"Run a synthetic 30-minute selector TCP echo loop with thirty manual migrations under the 50 Mbps loopback qdisc.",
			"regress/internal/tunfull/runner.go::runT4G2ManifestCase -> regress/internal/tunfull/runner.go::runT4WithBudget -> runG2Smoke",
			"net-pipe-to-l3-session-over-two-local-tcp-paths-with-loopback-qdisc", 2,
			profileTUN("synthetic-echo-record", paramTUN("payload_bytes", 8, manifest.UnitBytes)),
			profileTUN("synthetic-t4-g2", paramTUN("bandwidth_bps", 50_000_000, manifest.UnitBitsPerSecond), paramTUN("duration_ns", uint64((30*time.Minute).Nanoseconds()), manifest.UnitNanoseconds), paramTUN("interval_ns", uint64((100*time.Millisecond).Nanoseconds()), manifest.UnitNanoseconds), paramTUN("requested_migrations", 30, manifest.UnitCount)),
			seed, manifest.EvidenceProfile{}, manifest.EvidenceProfile{},
			seedMissing, missingEvidence(manifest.ContractDimensionStimulus), missingEvidence(manifest.ContractDimensionOracle),
		), true
	case caseT4G3:
		return syntheticG3TUNContract("five-minute 100,000 pps", "runT4G3ManifestCase -> regress/internal/tunfull/runner.go::runT4WithBudget -> runG3Smoke", 5*time.Minute, 100_000, 32, 10, 20*time.Millisecond), true
	case caseT5AdapterMatrix:
		return syntheticTUNContract(
			"Run independent TCP_REPAIR, gVisor, and gVisor packet-carrier stream transfers; this is not a live fallback transition.",
			"regress/internal/tunfull/runner.go::runT5ManifestCase -> regress/internal/tunfull/runner.go::runT5AdapterMatrix -> runTUNStreamTransfer",
			"three-independent-local-adapter-sessions-with-two-paths-each", 6,
			profileTUN("synthetic-adapter-transfer", paramTUN("bytes_per_transfer", 8<<20, manifest.UnitBytes)),
			profileTUN("synthetic-adapter-matrix", paramTUN("gvisor_migrations", 2, manifest.UnitCount), paramTUN("gvisor_packet_migrations", 2, manifest.UnitCount), paramTUN("tcprepair_migrations", 1, manifest.UnitCount), paramTUN("transfers", 3, manifest.UnitCount)),
			seedless,
			manifest.EvidenceProfile{
				Name: "independent-adapter-execution-and-scope", Version: 1,
				RequiredFacts: []string{"gvisor_exercised", "gvisor_packet_exercised", "t5_semantics", "tcprepair_exercised"},
				Assertions: []manifest.EvidenceAssertion{
					equalsTUN("gvisor_exercised", "true"),
					equalsTUN("gvisor_packet_exercised", "true"),
					equalsTUN("t5_semantics", "independent_adapter_matrix_not_live_fallback"),
					equalsTUN("tcprepair_exercised", "true"),
				},
			},
			manifest.EvidenceProfile{},
			missingTUN(manifest.ContractDimensionOracle, "the successful row emits adapter-exercised observations but no separate transfer-integrity or pass-predicate evidence"),
		), true
	case caseT6Selector:
		return syntheticTUNContract(
			"Run separate synthetic interactive and bulk TCP flows and inspect internal selector-to-bond behavior and per-path write counters.",
			"regress/internal/tunfull/runner.go::runT6ManifestCase -> regress/internal/tunfull/runner.go::runT6Selector",
			"two-net-pipe-flows-with-three-local-tcp-paths-each", 6,
			profileTUN("synthetic-selector-payloads", paramTUN("bulk_write_bytes", 32<<10, manifest.UnitBytes), paramTUN("interactive_echo_bytes", 8, manifest.UnitBytes)),
			profileTUN("synthetic-selector-run", paramTUN("bulk_bond_writes", 24, manifest.UnitCount), paramTUN("bulk_warm_writes", 36, manifest.UnitCount), paramTUN("interactive_echoes", 8, manifest.UnitCount)),
			seedless, manifest.EvidenceProfile{}, manifest.EvidenceProfile{},
			missingEvidence(manifest.ContractDimensionStimulus), missingEvidence(manifest.ContractDimensionOracle),
		), true
	default:
		return manifest.Contract{}, false
	}
}

func syntheticG3TUNContract(label, entrypoint string, duration time.Duration, pps, paths, migrations int, p95 time.Duration) manifest.Contract {
	purpose := fmt.Sprintf(
		"Run a synthetic %s QUIC DATAGRAM L3-session packet stress with %d paths, %d requested migrations, a %s P95 ceiling, and 1,024-byte application records that include an 8-byte sequence prefix; it is multi-connection and does not prove RFC 9000 CID rebinding.",
		label, paths, migrations, p95,
	)
	load := profileTUN("synthetic-g3-packet-stress",
		paramTUN("duration_ns", uint64(duration.Nanoseconds()), manifest.UnitNanoseconds),
		paramTUN("p95_ceiling_ns", uint64(p95.Nanoseconds()), manifest.UnitNanoseconds),
		paramTUN("requested_migrations", uint64(migrations), manifest.UnitCount),
		paramTUN("target_pps", uint64(pps), manifest.UnitPacketsPerSecond),
	)
	var extraMissing []manifest.MissingDimension
	if pps == 100_000 {
		purpose += " The configured target is 100,000 pps for five minutes, but the runner accepts measured offered load at or above 95,000 pps rather than enforcing exactly 100,000 offered pps."
		load = manifest.Profile{Applicability: manifest.ApplicabilityUnfrozen}
		extraMissing = append(extraMissing, missingTUN(
			manifest.ContractDimensionLoad,
			"the runner accepts measured offered load at 95% of the configured 100,000 pps target, so an exact offered-load profile is not enforced",
		))
	}
	stimulus := evidenceTUN("synthetic-g3-load-path-writes-and-scope", "g3_semantics", "migration_attempts", "migrations_observed", "offered_pps", "offered_ratio", "per_path_wire_writes", "target_pps", "wire_writes")
	stimulus.Assertions = []manifest.EvidenceAssertion{
		equalsTUN("g3_semantics", "synthetic_l3session_quic_datagram_not_rfc9000_cid_gold"),
		equalsTUN("migration_attempts", fmt.Sprint(migrations)),
		uintAtLeastTUN("migrations_observed", uint64(migrations)),
		floatAtLeastTUN("offered_pps", float64(pps)*0.95),
		floatAtLeastTUN("offered_ratio", 0.95),
		equalsTUN("target_pps", fmt.Sprint(pps)),
		uintAtLeastTUN("wire_writes", 1),
	}
	oracle := evidenceTUN("synthetic-g3-packet-oracle", "corrupt_packets", "duplicate_packets", "latency_samples", "loss_pct", "malformed_packets", "out_of_range_packets", "peer_identity_match", "p95", "received", "sent")
	oracle.Assertions = []manifest.EvidenceAssertion{
		equalsTUN("corrupt_packets", "0"),
		equalsTUN("duplicate_packets", "0"),
		uintAtLeastTUN("latency_samples", 20),
		floatAtMostTUN("loss_pct", 0),
		equalsTUN("malformed_packets", "0"),
		equalsTUN("out_of_range_packets", "0"),
		equalsTUN("peer_identity_match", "true"),
		uintAtLeastTUN("received", 1),
		uintAtLeastTUN("sent", 1),
	}
	return syntheticTUNContract(
		purpose,
		"regress/internal/tunfull/runner.go::"+entrypoint,
		"capture-device-to-l3-session-and-peer-egress-over-local-quic-datagram-paths", paths,
		profileTUN("synthetic-g3-integrity-application-record",
			paramTUN("application_record_bytes", 1024, manifest.UnitBytes),
			paramTUN("body_bytes", 1016, manifest.UnitBytes),
			paramTUN("sequence_prefix_bytes", 8, manifest.UnitBytes),
		),
		load,
		manifest.SeedPolicy{Mode: manifest.SeedModeNone},
		stimulus,
		oracle,
		extraMissing...,
	)
}

func syntheticTUNContract(purpose, entrypoint, topology string, paths int, payload, load manifest.Profile, seed manifest.SeedPolicy, stimulus, oracle manifest.EvidenceProfile, missing ...manifest.MissingDimension) manifest.Contract {
	return blockedTUNContract(
		purpose, entrypoint,
		manifest.Topology{Profile: topology, Roles: []string{"application", "l3-session", "peer"}, Isolation: "one local Go process using net.Pipe, loopback sockets, and/or an in-memory capture device", PathCount: paths},
		nil, payload, load, seed, stimulus, oracle,
		manifest.NegativeControl{Kind: manifest.NegativeControlAbsent},
		append(missing,
			missingTUN(manifest.ContractDimensionRoleCapabilities, tunCapabilitiesReason),
			missingTUN(manifest.ContractDimensionNegativeControl, tunControlReason),
		)...,
	)
}

func blockedTUNContract(purpose, entrypoint string, topology manifest.Topology, capabilities map[string][]string, payload, load manifest.Profile, seed manifest.SeedPolicy, stimulus, oracle manifest.EvidenceProfile, control manifest.NegativeControl, missing ...manifest.MissingDimension) manifest.Contract {
	missing = append(missing, missingTUN(manifest.ContractDimensionResources, tunResourcesReason))
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
		NegativeControl:   control,
		Resources:         manifest.ResourceBudget{State: manifest.ResourceStateUnfrozen},
	}
}

func profileTUN(name string, params ...manifest.ProfileParam) manifest.Profile {
	return manifest.Profile{Applicability: manifest.ApplicabilityDefined, Name: name, Version: 1, Params: params}
}

func paramTUN(name string, value uint64, unit manifest.BaseUnit) manifest.ProfileParam {
	return manifest.ProfileParam{Name: name, Value: value, Unit: unit}
}

func evidenceTUN(name string, facts ...string) manifest.EvidenceProfile {
	return manifest.EvidenceProfile{Name: name, Version: 1, RequiredFacts: facts}
}

func missingTUN(dimension manifest.ContractDimension, reason string) manifest.MissingDimension {
	return manifest.MissingDimension{Dimension: dimension, Reason: reason}
}

func equalsTUN(fact, expected string) manifest.EvidenceAssertion {
	return manifest.EvidenceAssertion{Fact: fact, Predicate: manifest.EvidenceEquals, Expected: expected}
}

func uintAtLeastTUN(fact string, expected uint64) manifest.EvidenceAssertion {
	return manifest.EvidenceAssertion{Fact: fact, Predicate: manifest.EvidenceUintAtLeast, Expected: fmt.Sprint(expected)}
}

func uintAtMostTUN(fact string, expected uint64) manifest.EvidenceAssertion {
	return manifest.EvidenceAssertion{Fact: fact, Predicate: manifest.EvidenceUintAtMost, Expected: fmt.Sprint(expected)}
}

func floatAtLeastTUN(fact string, expected float64) manifest.EvidenceAssertion {
	return manifest.EvidenceAssertion{Fact: fact, Predicate: manifest.EvidenceFloatAtLeast, Expected: fmt.Sprint(expected)}
}

func floatAtMostTUN(fact string, expected float64) manifest.EvidenceAssertion {
	return manifest.EvidenceAssertion{Fact: fact, Predicate: manifest.EvidenceFloatAtMost, Expected: fmt.Sprint(expected)}
}
