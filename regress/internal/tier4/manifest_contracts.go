package tier4

import (
	"fmt"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/manifest"
)

const (
	tier4CapabilitiesReason = "the runner does not freeze capability requirements per topology role"
	tier4ControlReason      = "the executable case has no embedded or separately registered negative control"
	tier4ResourcesReason    = "minimum per-role vCPU, RAM, and disk allocations have not been calibrated"
)

func tier4Spec(id string, budget time.Duration) manifest.Spec {
	base := manifest.RequiredWithBudget(id, "T4", budget)
	contract, ok := tier4Contract(id)
	if !ok {
		panic(fmt.Sprintf("tier4: no manifest contract for %q", id))
	}
	spec, err := manifest.NewCompleteSpec(base, contract)
	if err != nil {
		panic(err)
	}
	return spec
}

func tier4Contract(id string) (manifest.Contract, bool) {
	base := func(purpose, entrypoint, topology string, roles []string, paths int, payload, load manifest.Profile, seed manifest.SeedPolicy, stimulus, oracle manifest.EvidenceProfile, missing ...manifest.MissingDimension) manifest.Contract {
		missing = append(missing,
			missingTier4(manifest.ContractDimensionRoleCapabilities, tier4CapabilitiesReason),
			missingTier4(manifest.ContractDimensionNegativeControl, tier4ControlReason),
			missingTier4(manifest.ContractDimensionResources, tier4ResourcesReason),
		)
		return manifest.Contract{
			SchemaVersion:     manifest.ContractSchemaVersion,
			State:             manifest.ContractStateBlocked,
			MissingDimensions: missing,
			Purpose:           purpose,
			Entrypoint:        entrypoint,
			Topology: manifest.Topology{
				Profile: topology, Roles: roles, Isolation: "one local Go process using loopback sockets", PathCount: paths,
			},
			Payload:         payload,
			Load:            load,
			Seed:            seed,
			Stimulus:        stimulus,
			Oracle:          oracle,
			NegativeControl: manifest.NegativeControl{Kind: manifest.NegativeControlAbsent},
			Resources:       manifest.ResourceBudget{State: manifest.ResourceStateUnfrozen},
		}
	}

	seedless := manifest.SeedPolicy{Mode: manifest.SeedModeNone}
	randomFixture := missingTier4(manifest.ContractDimensionSeed, "the qdisc fixture chooses random ownership handles and does not record a reproducibility seed")
	randomWireGuard := missingTier4(manifest.ContractDimensionSeed, "wireguard-go private keys are generated with crypto/rand and no seed is recorded")
	randomHysteria := missingTier4(manifest.ContractDimensionSeed, "the self-signed certificate key and serial are generated with crypto/rand and no seed is recorded")
	unspecifiedRelaySeed := missingTier4(manifest.ContractDimensionSeed, "the UDP relay fixture does not expose or record one reproducibility seed")

	switch id {
	case "G1-T4":
		stimulus := evidenceTier4("g1-manual-migrations", "migration_calls_fired", "migrations_done", "requested_migrations")
		stimulus.Assertions = []manifest.EvidenceAssertion{
			uintAtLeastTier4("migration_calls_fired", 10),
			uintAtLeastTier4("migrations_done", 10),
			equalsTier4("requested_migrations", "10"),
		}
		oracle := evidenceTier4("g1-application-hash", "sha256_match")
		oracle.Assertions = []manifest.EvidenceAssertion{equalsTier4("sha256_match", "true")}
		return base(
			"Run a 1 GiB deterministic TCP stream transfer while requesting ten rendr path migrations.",
			"regress/internal/tier4/runner.go::caseDefs[G1-T4].run -> regress/internal/smoke.RunG1",
			"two-local-rendr-tcp-paths-with-loopback-qdisc", []string{"client", "server"}, 2,
			profileTier4("g1-position-pattern", paramTier4("payload_bytes", 1<<30, manifest.UnitBytes)),
			profileTier4("g1-long-transfer", paramTier4("bandwidth_bps", 50_000_000, manifest.UnitBitsPerSecond), paramTier4("requested_migrations", 10, manifest.UnitCount)),
			manifest.SeedPolicy{},
			stimulus,
			oracle,
			randomFixture,
		), true
	case "G1-T4-quic":
		stimulus := evidenceTier4("g1-manual-migrations", "migration_calls_fired", "migrations_done", "requested_migrations")
		stimulus.Assertions = []manifest.EvidenceAssertion{
			uintAtLeastTier4("migration_calls_fired", 10),
			uintAtLeastTier4("migrations_done", 10),
			equalsTier4("requested_migrations", "10"),
		}
		oracle := evidenceTier4("g1-application-hash", "sha256_match")
		oracle.Assertions = []manifest.EvidenceAssertion{equalsTier4("sha256_match", "true")}
		return base(
			"Run a 1 GiB deterministic stream transfer over two QUIC stream paths while requesting ten rendr path migrations.",
			"regress/internal/tier4/runner.go::caseDefs[G1-T4-quic].run -> regress/internal/smoke.RunG1",
			"two-local-rendr-quic-stream-paths-with-loopback-qdisc", []string{"client", "server"}, 2,
			profileTier4("g1-position-pattern", paramTier4("payload_bytes", 1<<30, manifest.UnitBytes)),
			profileTier4("g1-long-transfer", paramTier4("bandwidth_bps", 50_000_000, manifest.UnitBitsPerSecond), paramTier4("requested_migrations", 10, manifest.UnitCount)),
			manifest.SeedPolicy{},
			stimulus,
			oracle,
			randomFixture,
		), true
	case "G2-T4":
		return pairedG2Tier4(base, "TCP selector", "G2-T4", "tcp", randomFixture), true
	case "G2-T4-quic":
		return pairedG2Tier4(base, "QUIC-stream selector", "G2-T4-quic", "quic", randomFixture), true
	case "G2-T4-bond-tcp":
		return pairedG2Tier4(base, "TCP bond", "G2-T4-bond-tcp", "tcp-bond", randomFixture), true
	case "G2-T4-race-tcp":
		stimulus := evidenceTier4("g2-race-traffic", "mode", "recv_dups", "requested_migrations")
		stimulus.Assertions = []manifest.EvidenceAssertion{
			equalsTier4("mode", "race"),
			uintAtLeastTier4("recv_dups", 1),
		}
		oracle := evidenceTier4("g2-race-echo-oracle", "application_duplicates", "p99_qualified", "received_echoes", "transport_lost_echoes")
		oracle.Assertions = []manifest.EvidenceAssertion{
			equalsTier4("application_duplicates", "0"),
			equalsTier4("p99_qualified", "true"),
			uintAtLeastTier4("received_echoes", 1000),
			equalsTier4("transport_lost_echoes", "0"),
		}
		return base(
			"Run a 30-minute two-path TCP race echo session with frame duplication and no requested migrations.",
			"regress/internal/tier4/runner.go::caseDefs[G2-T4-race-tcp].run -> regress/internal/smoke.RunG2",
			"single-race-session-with-two-local-tcp-paths-and-loopback-qdisc", []string{"client", "server"}, 2,
			profileTier4("g2-echo-record", paramTier4("payload_bytes", 12, manifest.UnitBytes)),
			profileTier4("g2-race-long-run", paramTier4("bandwidth_bps", 50_000_000, manifest.UnitBitsPerSecond), paramTier4("duration_ns", uint64((30*time.Minute).Nanoseconds()), manifest.UnitNanoseconds), paramTier4("interval_ns", uint64((100*time.Millisecond).Nanoseconds()), manifest.UnitNanoseconds), paramTier4("requested_migrations", 0, manifest.UnitCount)),
			manifest.SeedPolicy{},
			stimulus,
			oracle,
			randomFixture,
		), true
	case "M11-udp-relay-T4":
		stimulus := evidenceTier4("udp-relay-migrations", "migration_count", "requested_migs")
		stimulus.Assertions = []manifest.EvidenceAssertion{
			uintAtLeastTier4("migration_count", 3),
			equalsTier4("requested_migs", "3"),
		}
		oracle := evidenceTier4("udp-relay-round-trips", "packets")
		oracle.Assertions = []manifest.EvidenceAssertion{equalsTier4("packets", "10000")}
		return base(
			"Exercise 10,000 server-side UDP relay round trips across three rendr packet-path migrations.",
			"regress/internal/tier4/runner.go::caseDefs[M11-udp-relay-T4].run -> regress/internal/smoke.RunUDPRelay",
			"local-udp-application-and-two-path-rendr-relay", []string{"application", "client-relay", "server-relay"}, 2,
			manifest.Profile{Applicability: manifest.ApplicabilityUnfrozen},
			profileTier4("udp-relay-long-run", paramTier4("packets", 10_000, manifest.UnitCount), paramTier4("requested_migrations", 3, manifest.UnitCount)),
			manifest.SeedPolicy{},
			stimulus,
			oracle,
			missingTier4(manifest.ContractDimensionPayload, "packet strings vary with the packet index and no fixed numeric payload profile is frozen"),
			unspecifiedRelaySeed,
		), true
	case "M11-udp-relay-porthop-T4":
		stimulus := evidenceTier4("udp-relay-port-hops", "migration_count", "port_hops", "requested_migs", "unique_ports")
		stimulus.Assertions = []manifest.EvidenceAssertion{
			uintAtLeastTier4("migration_count", 3),
			uintAtLeastTier4("port_hops", 8),
			equalsTier4("requested_migs", "3"),
			uintAtLeastTier4("unique_ports", 9),
		}
		oracle := evidenceTier4("udp-relay-porthop-round-trips", "packets")
		oracle.Assertions = []manifest.EvidenceAssertion{equalsTier4("packets", "10000")}
		return base(
			"Exercise 10,000 UDP relay round trips across three rendr migrations and eight local application port hops.",
			"regress/internal/tier4/runner.go::caseDefs[M11-udp-relay-porthop-T4].run -> regress/internal/smoke.RunUDPRelayPortHop",
			"local-port-hopping-udp-application-and-two-path-rendr-relay", []string{"application", "client-relay", "server-relay"}, 2,
			manifest.Profile{Applicability: manifest.ApplicabilityUnfrozen},
			profileTier4("udp-relay-porthop-long-run", paramTier4("packets", 10_000, manifest.UnitCount), paramTier4("port_hops", 8, manifest.UnitCount), paramTier4("requested_migrations", 3, manifest.UnitCount)),
			manifest.SeedPolicy{},
			stimulus,
			oracle,
			missingTier4(manifest.ContractDimensionPayload, "packet strings include the runtime-selected local UDP address and have no fixed numeric payload profile"),
			unspecifiedRelaySeed,
		), true
	case "M11-wireguard-relay-T4":
		stimulus := evidenceTier4("wireguard-relay-migrations", "migration_count", "requested_migs")
		stimulus.Assertions = []manifest.EvidenceAssertion{
			uintAtLeastTier4("migration_count", 3),
			equalsTier4("requested_migs", "3"),
		}
		oracle := evidenceTier4("wireguard-relay-echoes", "bytes", "messages")
		oracle.Assertions = []manifest.EvidenceAssertion{
			equalsTier4("bytes", "262144"),
			equalsTier4("messages", "512"),
		}
		return base(
			"Carry 512 fixed-size echo messages through wireguard-go userspace endpoints over a two-path rendr UDP relay.",
			"regress/internal/tier4/runner.go::caseDefs[M11-wireguard-relay-T4].run -> regress/internal/smoke.RunWireGuardRelay",
			"two-local-wireguard-go-endpoints-over-two-path-rendr-relay", []string{"client-wireguard", "client-relay", "server-relay", "server-wireguard"}, 2,
			profileTier4("wireguard-echo-message", paramTier4("message_bytes", 512, manifest.UnitBytes)),
			profileTier4("wireguard-relay-run", paramTier4("messages", 512, manifest.UnitCount), paramTier4("requested_migrations", 3, manifest.UnitCount)),
			manifest.SeedPolicy{},
			stimulus,
			oracle,
			randomWireGuard,
		), true
	case "M11-hysteria2-relay-T4":
		stimulus := evidenceTier4("hysteria2-relay-migrations", "migration_count", "requested_migs")
		stimulus.Assertions = []manifest.EvidenceAssertion{
			uintAtLeastTier4("migration_count", 3),
			equalsTier4("requested_migs", "3"),
		}
		oracle := evidenceTier4("hysteria2-speedtest-result", "bytes")
		oracle.Assertions = []manifest.EvidenceAssertion{uintAtLeastTier4("bytes", 8<<20)}
		return base(
			"Run an 8 MiB Hysteria 2 CLI speedtest over a two-path rendr UDP relay with three migrations.",
			"regress/internal/tier4/runner.go::caseDefs[M11-hysteria2-relay-T4].run -> regress/internal/smoke.RunHysteriaRelay",
			"local-hysteria2-client-and-server-over-two-path-rendr-relay", []string{"client-relay", "hysteria-client", "hysteria-server", "server-relay"}, 2,
			profileTier4("hysteria2-speedtest-payload", paramTier4("payload_bytes", 8<<20, manifest.UnitBytes)),
			profileTier4("hysteria2-relay-run", paramTier4("requested_migrations", 3, manifest.UnitCount)),
			manifest.SeedPolicy{},
			stimulus,
			oracle,
			randomHysteria,
		), true
	case "G3-T4":
		stimulus := evidenceTier4("g3-paced-load-and-path-writes", "migration_attempts", "migrations", "path_writers", "pps_sent", "target_pps", "wire_writes")
		stimulus.Assertions = []manifest.EvidenceAssertion{
			equalsTier4("migration_attempts", "10"),
			uintAtLeastTier4("migrations", 10),
			uintAtLeastTier4("path_writers", 2),
			floatAtLeastTier4("pps_sent", 95_000),
			equalsTier4("target_pps", "100000"),
			uintAtLeastTier4("wire_writes", 1),
		}
		oracle := evidenceTier4("g3-packet-and-latency-oracle", "corrupt_packets", "duplicate_packets", "latency_samples", "loss_pct", "malformed_packets", "missing_packets", "out_of_range_packets", "p95_ms", "received", "sent", "udp_snmp_status")
		oracle.Assertions = []manifest.EvidenceAssertion{
			equalsTier4("corrupt_packets", "0"),
			equalsTier4("duplicate_packets", "0"),
			uintAtLeastTier4("latency_samples", 20),
			floatAtMostTier4("loss_pct", 0),
			equalsTier4("malformed_packets", "0"),
			equalsTier4("missing_packets", "0"),
			equalsTier4("out_of_range_packets", "0"),
			floatAtMostTier4("p95_ms", 20),
			uintAtLeastTier4("received", 1),
			uintAtLeastTier4("sent", 1),
			equalsTier4("udp_snmp_status", "ok"),
		}
		return base(
			"Run a five-minute multi-connection QUIC DATAGRAM capacity stress configured for a 100,000 pps target with ten rendr path migrations, strict zero loss, and a 20 ms P95 ceiling; successful rows require at least 95,000 measured offered pps, not an exact 100,000 pps offered load.",
			"regress/internal/tier4/runner.go::caseDefs[G3-T4].run -> regress/internal/smoke.RunG3",
			"eight-local-quic-datagram-connections-in-one-rendr-packet-session", []string{"receiver", "sender"}, 8,
			profileTier4("g3-integrity-application-record", paramTier4("application_record_bytes", 1032, manifest.UnitBytes), paramTier4("body_bytes", 1024, manifest.UnitBytes)),
			manifest.Profile{Applicability: manifest.ApplicabilityUnfrozen},
			seedless,
			stimulus,
			oracle,
			missingTier4(manifest.ContractDimensionLoad, "the runner accepts measured offered load at 95% of the configured 100,000 pps target, so an exact offered-load profile is not enforced"),
		), true
	default:
		return manifest.Contract{}, false
	}
}

func pairedG2Tier4(base func(string, string, string, []string, int, manifest.Profile, manifest.Profile, manifest.SeedPolicy, manifest.EvidenceProfile, manifest.EvidenceProfile, ...manifest.MissingDimension) manifest.Contract, label, id, topology string, seedMissing manifest.MissingDimension) manifest.Contract {
	stimulus := evidenceTier4("g2-paired-migration-treatment", "fd_identity_observed", "independent_path_observer", "treatment_migration_calls_fired", "treatment_migrations", "treatment_requested_migrations")
	stimulus.Assertions = []manifest.EvidenceAssertion{
		equalsTier4("fd_identity_observed", "false"),
		equalsTier4("independent_path_observer", "false"),
		uintAtLeastTier4("treatment_migration_calls_fired", 30),
		uintAtLeastTier4("treatment_migrations", 30),
		equalsTier4("treatment_requested_migrations", "30"),
	}
	oracle := evidenceTier4("g2-matched-latency-and-continuity", "baseline_application_duplicates", "baseline_received_echoes", "baseline_transport_lost_echoes", "paired_p99_qualified", "paired_reference_p99_ms", "treatment_application_duplicates", "treatment_received_echoes", "treatment_transport_lost_echoes")
	oracle.Assertions = []manifest.EvidenceAssertion{
		equalsTier4("baseline_application_duplicates", "0"),
		uintAtLeastTier4("baseline_received_echoes", 1000),
		equalsTier4("baseline_transport_lost_echoes", "0"),
		equalsTier4("paired_p99_qualified", "true"),
		equalsTier4("treatment_application_duplicates", "0"),
		uintAtLeastTier4("treatment_received_echoes", 1000),
		equalsTier4("treatment_transport_lost_echoes", "0"),
	}
	return base(
		"Run concurrent matched 30-minute "+label+" baseline and treatment echo arms; only the treatment requests thirty migrations. Application fd identity and an independent path observer are not implemented and are recorded only as false observational context.",
		"regress/internal/tier4/runner.go::caseDefs["+id+"].run -> regress/internal/smoke.RunG2Paired",
		"paired-"+topology+"-sessions-with-two-local-paths-per-arm-and-loopback-qdisc", []string{"baseline-client", "baseline-server", "treatment-client", "treatment-server"}, 4,
		profileTier4("g2-echo-record", paramTier4("payload_bytes", 12, manifest.UnitBytes)),
		profileTier4("g2-paired-long-run", paramTier4("bandwidth_bps", 50_000_000, manifest.UnitBitsPerSecond), paramTier4("duration_ns", uint64((30*time.Minute).Nanoseconds()), manifest.UnitNanoseconds), paramTier4("interval_ns", uint64((100*time.Millisecond).Nanoseconds()), manifest.UnitNanoseconds), paramTier4("treatment_migrations", 30, manifest.UnitCount)),
		manifest.SeedPolicy{},
		stimulus,
		oracle,
		seedMissing,
	)
}

func profileTier4(name string, params ...manifest.ProfileParam) manifest.Profile {
	return manifest.Profile{Applicability: manifest.ApplicabilityDefined, Name: name, Version: 1, Params: params}
}

func paramTier4(name string, value uint64, unit manifest.BaseUnit) manifest.ProfileParam {
	return manifest.ProfileParam{Name: name, Value: value, Unit: unit}
}

func evidenceTier4(name string, facts ...string) manifest.EvidenceProfile {
	return manifest.EvidenceProfile{Name: name, Version: 1, RequiredFacts: facts}
}

func missingTier4(dimension manifest.ContractDimension, reason string) manifest.MissingDimension {
	return manifest.MissingDimension{Dimension: dimension, Reason: reason}
}

func equalsTier4(fact, expected string) manifest.EvidenceAssertion {
	return manifest.EvidenceAssertion{Fact: fact, Predicate: manifest.EvidenceEquals, Expected: expected}
}

func uintAtLeastTier4(fact string, expected uint64) manifest.EvidenceAssertion {
	return manifest.EvidenceAssertion{Fact: fact, Predicate: manifest.EvidenceUintAtLeast, Expected: fmt.Sprint(expected)}
}

func floatAtLeastTier4(fact string, expected float64) manifest.EvidenceAssertion {
	return manifest.EvidenceAssertion{Fact: fact, Predicate: manifest.EvidenceFloatAtLeast, Expected: fmt.Sprint(expected)}
}

func floatAtMostTier4(fact string, expected float64) manifest.EvidenceAssertion {
	return manifest.EvidenceAssertion{Fact: fact, Predicate: manifest.EvidenceFloatAtMost, Expected: fmt.Sprint(expected)}
}
