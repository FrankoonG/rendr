package tier2

import (
	"fmt"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/manifest"
)

func mustManifestSpec(base manifest.Spec, contract manifest.Contract) manifest.Spec {
	spec, err := manifest.NewCompleteSpec(base, contract)
	if err != nil {
		panic(err)
	}
	return spec
}

func tier2ManifestContract(id string) manifest.Contract {
	contract := tier2BlockedContract()
	switch id {
	case "G1-smoke":
		contract.Purpose = "Run one deterministic 30 MiB TCP stream transfer with three requested rendr path migrations and verify application payload integrity."
		contract.Entrypoint = "regress/internal/tier2/runner.go::RunWithOptions -> runSelectedCases -> executeCase -> runSmokeCase -> smoke.RunG1"
		setLoopback(&contract, "two-path-tcp-stream", 2)
		contract.Payload = definedProfile("g1-positional-stream", param("payload_bytes", 30<<20, manifest.UnitBytes))
		contract.Load = definedProfile("g1-stream-smoke", param("migrations", 3, manifest.UnitCount), param("transfers", 1, manifest.UnitCount))
		contract.Seed = manifest.SeedPolicy{Mode: manifest.SeedModeNone}
		contract.Stimulus = evidence("g1-requested-migrations", "migration_calls_fired", "migrations_done", "requested_migrations")
		contract.Stimulus.Assertions = []manifest.EvidenceAssertion{
			uintAtLeast("migration_calls_fired", 3),
			uintAtLeast("migrations_done", 3),
			equals("requested_migrations", "3"),
		}
		contract.Oracle = evidence("g1-stream-integrity", "sha256_match")
		contract.Oracle.Assertions = []manifest.EvidenceAssertion{equals("sha256_match", "true")}
	case "G1-mixed-tcp-quic-smoke":
		contract.Purpose = "Run one deterministic 8 MiB framed stream transfer across one TCP-backed and one QUIC-backed path with one requested migration; no external carrier-cutover claim is made."
		contract.Entrypoint = "regress/internal/tier2/runner.go::RunWithOptions -> runSelectedCases -> executeCase -> runSmokeCase -> smoke.RunG1"
		setLoopback(&contract, "mixed-tcp-quic-stream", 2)
		contract.Payload = definedProfile("g1-positional-stream", param("payload_bytes", 8<<20, manifest.UnitBytes))
		contract.Load = definedProfile("g1-mixed-stream-smoke", param("migrations", 1, manifest.UnitCount), param("transfers", 1, manifest.UnitCount))
		contract.Seed = manifest.SeedPolicy{Mode: manifest.SeedModeNone}
		contract.Stimulus = evidence("g1-requested-migrations", "migration_calls_fired", "migrations_done", "requested_migrations")
		contract.Stimulus.Assertions = []manifest.EvidenceAssertion{
			uintAtLeast("migration_calls_fired", 1),
			uintAtLeast("migrations_done", 1),
			equals("requested_migrations", "1"),
		}
		contract.Oracle = evidence("g1-stream-integrity", "sha256_match")
		contract.Oracle.Assertions = []manifest.EvidenceAssertion{equals("sha256_match", "true")}
	case "G2-smoke":
		setG2Contract(&contract, "Run a 30-second selector TCP echo smoke with five requested path migrations and exact application-load accounting.", "selector-tcp-echo", 5, false)
	case "G2-race-tcp-smoke":
		setG2Contract(&contract, "Run a 30-second race-mode TCP echo smoke with migrations disabled and require peer receive-duplicate activity without application duplicates.", "race-tcp-echo", 0, true)
	case "G2-bond-tcp-smoke":
		setG2Contract(&contract, "Run a 30-second bond-mode TCP echo continuity smoke with five requested active-path swaps; aggregate-goodput semantics are not claimed.", "bond-tcp-echo", 5, false)
	case "G3-smoke":
		contract.Purpose = "Run a five-second packet smoke targeting 5,000 pps over four independent QUIC DATAGRAM paths in bond mode; each application record contains an 8-byte sequence prefix and a 1,024-byte body, and this does not prove RFC 9000 CID or NAT rebinding."
		contract.Entrypoint = "regress/internal/tier2/runner.go::RunWithOptions -> runSelectedCases -> executeCase -> runSmokeCase -> smoke.RunG3"
		setLoopback(&contract, "four-path-quic-datagram-bond", 4)
		contract.RoleCapabilities = map[string][]string{
			"client": {"Linux", "net.core.rmem_max >= 8388608 bytes"},
			"server": {"Linux", "net.core.rmem_max >= 8388608 bytes"},
		}
		contract.Payload = definedProfile("g3-sequence-integrity-application-record",
			param("application_record_bytes", 1032, manifest.UnitBytes),
			param("body_bytes", 1024, manifest.UnitBytes),
		)
		contract.Load = definedProfile("g3-datagram-smoke",
			param("duration_ns", uint64((5*time.Second).Nanoseconds()), manifest.UnitNanoseconds),
			param("loss_budget_ppm", 5000, manifest.UnitPartsPerMillion),
			param("migrations", 3, manifest.UnitCount),
			param("target_pps", 5000, manifest.UnitPacketsPerSecond),
		)
		contract.Seed = manifest.SeedPolicy{Mode: manifest.SeedModeNone}
		contract.Stimulus = evidence("g3-packet-load-and-path-counters", "migration_attempts", "migrations", "path_writers", "pps_sent", "sent", "target_pps", "wire_writes")
		contract.Stimulus.Assertions = []manifest.EvidenceAssertion{
			equals("migration_attempts", "3"),
			uintAtLeast("migrations", 3),
			uintAtLeast("path_writers", 2),
			floatAtLeast("pps_sent", 4750),
			equals("target_pps", "5000"),
			uintAtLeast("wire_writes", 1),
		}
		contract.Oracle = evidence("g3-application-packet-oracle", "corrupt_packets", "duplicate_packets", "latency_samples", "loss_budget_pct", "loss_pct", "malformed_packets", "missing_packets", "out_of_range_packets", "p95_ms", "received", "udp_snmp_status")
		contract.Oracle.Assertions = []manifest.EvidenceAssertion{
			equals("corrupt_packets", "0"),
			equals("duplicate_packets", "0"),
			uintAtLeast("latency_samples", 20),
			floatAtMost("loss_pct", 0.5),
			equals("malformed_packets", "0"),
			equals("out_of_range_packets", "0"),
			floatAtMost("p95_ms", 50),
			uintAtLeast("received", 1),
			equals("udp_snmp_status", "ok"),
		}
	case "G4":
		contract.Purpose = "Run a six-second TCP echo smoke, invoke the in-process ForceKillPathForTest hook at two seconds, and verify post-kill delivery within five seconds."
		contract.Entrypoint = "regress/internal/tier2/runner.go::RunWithOptions -> runSelectedCases -> executeCase -> runSmokeCase -> smoke.RunG4"
		setLoopback(&contract, "two-path-tcp-force-kill", 2)
		contract.Payload = definedProfile("g4-sequence-echo", param("record_bytes", 8, manifest.UnitBytes))
		contract.Load = definedProfile("g4-force-kill-smoke",
			param("duration_ns", uint64((6*time.Second).Nanoseconds()), manifest.UnitNanoseconds),
			param("echo_interval_ns", uint64((10*time.Millisecond).Nanoseconds()), manifest.UnitNanoseconds),
			param("failover_budget_ns", uint64((5*time.Second).Nanoseconds()), manifest.UnitNanoseconds),
			param("kill_at_ns", uint64((2*time.Second).Nanoseconds()), manifest.UnitNanoseconds),
		)
		contract.Seed = manifest.SeedPolicy{Mode: manifest.SeedModeNone}
		contract.Stimulus = evidence("g4-force-kill-hook", "kill_observed", "post_kill_samples")
		contract.Stimulus.Assertions = []manifest.EvidenceAssertion{
			equals("kill_observed", "true"),
			uintAtLeast("post_kill_samples", 1),
		}
		contract.Oracle = evidence("g4-echo-continuity", "application_lost", "echoes", "failover_ms", "max_rtt_ms")
		contract.Oracle.Assertions = []manifest.EvidenceAssertion{
			equals("application_lost", "0"),
			uintAtLeast("echoes", 1),
			uintAtMost("failover_ms", 5000),
		}
	case "G5":
		contract.Purpose = "Kill one local TCP path, manually add a fresh path, migrate to it, and verify 256 KiB of deterministic post-add traffic and internal recovered-path progress."
		contract.Entrypoint = "regress/internal/tier2/runner.go::RunWithOptions -> runSelectedCases -> executeCase -> runSmokeCase -> smoke.RunG5"
		setLoopback(&contract, "two-path-tcp-manual-recovery", 2)
		contract.Payload = definedProfile("g5-positional-post-add-stream", param("payload_bytes", 256<<10, manifest.UnitBytes))
		contract.Load = definedProfile("g5-manual-recovery-smoke", param("add_path_calls", 1, manifest.UnitCount), param("force_kill_calls", 1, manifest.UnitCount), param("migrate_calls", 1, manifest.UnitCount))
		contract.Seed = manifest.SeedPolicy{Mode: manifest.SeedModeNone}
		contract.Stimulus = evidence("g5-manual-path-recovery", "migration_count", "new_path_id", "new_path_write_delta")
		contract.Stimulus.Assertions = []manifest.EvidenceAssertion{
			uintAtLeast("migration_count", 1),
			uintAtLeast("new_path_id", 1),
			uintAtLeast("new_path_write_delta", 1),
		}
		contract.Oracle = evidence("g5-post-add-integrity", "payload_match", "post_add_bytes", "recv_dups")
		contract.Oracle.Assertions = []manifest.EvidenceAssertion{
			equals("payload_match", "true"),
			uintAtLeast("post_add_bytes", 256<<10),
			equals("recv_dups", "0"),
		}
	case "M11-udp-relay-smoke":
		contract.Purpose = "Round-trip 128 formatted UDP packets through a local rendr UDP-flow relay with two paths and one requested migration."
		contract.Entrypoint = "regress/internal/tier2/runner.go::RunWithOptions -> runSelectedCases -> executeCase -> runSmokeCase -> smoke.RunUDPRelay"
		setRelayLoopback(&contract, "udp-relay-two-path")
		contract.Payload = definedProfile("udp-relay-indexed-text", param("packet_bytes", 21, manifest.UnitBytes))
		contract.Load = definedProfile("udp-relay-smoke", param("migrations", 1, manifest.UnitCount), param("packets", 128, manifest.UnitCount))
		contract.Seed = manifest.SeedPolicy{Mode: manifest.SeedModeNone}
		contract.Stimulus = evidence("udp-relay-migration", "migration_count", "paths", "requested_migs")
		contract.Stimulus.Assertions = []manifest.EvidenceAssertion{
			uintAtLeast("migration_count", 1),
			equals("paths", "2"),
			equals("requested_migs", "1"),
		}
		contract.Oracle = evidence("udp-relay-completed-round-trips", "packets")
		contract.Oracle.Assertions = []manifest.EvidenceAssertion{equals("packets", "128")}
	case "M11-udp-relay-porthop-smoke":
		contract.Purpose = "Round-trip 128 UDP packets through a stable local relay destination while replacing the application UDP socket three times and requesting two rendr path migrations."
		contract.Entrypoint = "regress/internal/tier2/runner.go::RunWithOptions -> runSelectedCases -> executeCase -> runSmokeCase -> smoke.RunUDPRelayPortHop"
		setRelayLoopback(&contract, "udp-relay-two-path-porthop")
		contract.Payload = unfrozenProfile()
		contract.Load = definedProfile("udp-relay-porthop-smoke", param("migrations", 2, manifest.UnitCount), param("packets", 128, manifest.UnitCount), param("port_hops", 3, manifest.UnitCount))
		contract.Seed = manifest.SeedPolicy{}
		contract.Stimulus = evidence("udp-relay-porthop-and-migration", "migration_count", "paths", "port_hops", "requested_migs", "unique_ports")
		contract.Stimulus.Assertions = []manifest.EvidenceAssertion{
			uintAtLeast("migration_count", 2),
			equals("paths", "2"),
			uintAtLeast("port_hops", 3),
			equals("requested_migs", "2"),
			uintAtLeast("unique_ports", 4),
		}
		contract.Oracle = evidence("udp-relay-porthop-completed-round-trips", "packets")
		contract.Oracle.Assertions = []manifest.EvidenceAssertion{equals("packets", "128")}
		contract.MissingDimensions = append(contract.MissingDimensions,
			missing(manifest.ContractDimensionPayload, "each payload embeds an OS-assigned application address, so its byte length is not frozen"),
			missing(manifest.ContractDimensionSeed, "OS-assigned application UDP ports are not controlled by a fixed or recorded seed"),
		)
	default:
		panic(fmt.Sprintf("unknown T2 manifest contract %q", id))
	}
	return contract
}

func tier2BlockedContract() manifest.Contract {
	return manifest.Contract{
		SchemaVersion: manifest.ContractSchemaVersion,
		State:         manifest.ContractStateBlocked,
		MissingDimensions: []manifest.MissingDimension{
			missing(manifest.ContractDimensionNegativeControl, "the executable smoke case has no embedded or separately registered negative control"),
			missing(manifest.ContractDimensionResources, "per-role vCPU, RAM, and disk minima have not been calibrated"),
		},
		NegativeControl: manifest.NegativeControl{Kind: manifest.NegativeControlAbsent},
		Resources:       manifest.ResourceBudget{State: manifest.ResourceStateUnfrozen},
	}
}

func setG2Contract(contract *manifest.Contract, purpose, topology string, migrations uint64, race bool) {
	contract.Purpose = purpose + " The roughly 300 latency samples cannot meet the 1,000-sample P99 qualification minimum, so latency remains diagnostic and no qualified P99 threshold is claimed."
	contract.Entrypoint = "regress/internal/tier2/runner.go::RunWithOptions -> runSelectedCases -> executeCase -> runSmokeCase -> smoke.RunG2"
	setLoopback(contract, topology, 2)
	contract.Payload = definedProfile("g2-sequence-timestamp-echo", param("record_bytes", 12, manifest.UnitBytes))
	contract.Load = definedProfile("g2-echo-smoke",
		param("duration_ns", uint64((30*time.Second).Nanoseconds()), manifest.UnitNanoseconds),
		param("echo_interval_ns", uint64((100*time.Millisecond).Nanoseconds()), manifest.UnitNanoseconds),
		param("migrations", migrations, manifest.UnitCount),
	)
	contract.Seed = manifest.SeedPolicy{Mode: manifest.SeedModeNone}
	stimulusFacts := []string{"blackout_ms", "latency_evidence", "latency_samples", "migration_calls_fired", "migrations", "p99_minimum_samples", "p99_qualified", "planned_echoes", "requested_duration_ms", "requested_migrations", "scheduled_echoes", "write_completed_echoes"}
	if race {
		stimulusFacts = append(stimulusFacts, "recv_dups", "recv_dups_observer")
	}
	contract.Stimulus = evidence("g2-scheduled-echo-and-migration", stimulusFacts...)
	contract.Stimulus.Assertions = []manifest.EvidenceAssertion{
		equals("latency_evidence", "diagnostic"),
		equals("p99_minimum_samples", "1000"),
		equals("p99_qualified", "false"),
	}
	if migrations > 0 {
		contract.Stimulus.Assertions = append(contract.Stimulus.Assertions,
			uintAtLeast("migration_calls_fired", migrations),
			uintAtLeast("migrations", migrations),
		)
	}
	if race {
		contract.Stimulus.Assertions = append(contract.Stimulus.Assertions, uintAtLeast("recv_dups", 1))
	}
	contract.Oracle = evidence("g2-application-continuity-without-qualified-latency", "application_duplicates", "received_echoes", "transport_lost_echoes", "unoffered_echoes")
	contract.Oracle.Assertions = []manifest.EvidenceAssertion{
		equals("application_duplicates", "0"),
		uintAtLeast("received_echoes", 1),
		equals("transport_lost_echoes", "0"),
		equals("unoffered_echoes", "0"),
	}
}

func setLoopback(contract *manifest.Contract, profile string, paths int) {
	contract.Topology = manifest.Topology{Profile: profile, Roles: []string{"client", "server"}, Isolation: "single process loopback sockets", PathCount: paths}
	contract.RoleCapabilities = map[string][]string{"client": {}, "server": {}}
}

func setRelayLoopback(contract *manifest.Contract, profile string) {
	contract.Topology = manifest.Topology{Profile: profile, Roles: []string{"application", "echo", "relay-client", "relay-server"}, Isolation: "single process loopback UDP sockets", PathCount: 2}
	contract.RoleCapabilities = map[string][]string{"application": {}, "echo": {}, "relay-client": {}, "relay-server": {}}
}

func definedProfile(name string, params ...manifest.ProfileParam) manifest.Profile {
	return manifest.Profile{Applicability: manifest.ApplicabilityDefined, Name: name, Version: 1, Params: params}
}

func unfrozenProfile() manifest.Profile {
	return manifest.Profile{Applicability: manifest.ApplicabilityUnfrozen}
}

func param(name string, value uint64, unit manifest.BaseUnit) manifest.ProfileParam {
	return manifest.ProfileParam{Name: name, Value: value, Unit: unit}
}

func evidence(name string, facts ...string) manifest.EvidenceProfile {
	return manifest.EvidenceProfile{Name: name, Version: 1, RequiredFacts: facts}
}

func missing(dimension manifest.ContractDimension, reason string) manifest.MissingDimension {
	return manifest.MissingDimension{Dimension: dimension, Reason: reason}
}

func equals(fact, expected string) manifest.EvidenceAssertion {
	return manifest.EvidenceAssertion{Fact: fact, Predicate: manifest.EvidenceEquals, Expected: expected}
}

func uintAtLeast(fact string, expected uint64) manifest.EvidenceAssertion {
	return manifest.EvidenceAssertion{Fact: fact, Predicate: manifest.EvidenceUintAtLeast, Expected: fmt.Sprint(expected)}
}

func uintAtMost(fact string, expected uint64) manifest.EvidenceAssertion {
	return manifest.EvidenceAssertion{Fact: fact, Predicate: manifest.EvidenceUintAtMost, Expected: fmt.Sprint(expected)}
}

func floatAtLeast(fact string, expected float64) manifest.EvidenceAssertion {
	return manifest.EvidenceAssertion{Fact: fact, Predicate: manifest.EvidenceFloatAtLeast, Expected: fmt.Sprint(expected)}
}

func floatAtMost(fact string, expected float64) manifest.EvidenceAssertion {
	return manifest.EvidenceAssertion{Fact: fact, Predicate: manifest.EvidenceFloatAtMost, Expected: fmt.Sprint(expected)}
}
