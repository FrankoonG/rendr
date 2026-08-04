package tier1

import (
	"fmt"

	"github.com/FrankoonG/rendr/regress/internal/manifest"
)

func mustManifestSpec(base manifest.Spec, contract manifest.Contract) manifest.Spec {
	spec, err := manifest.NewCompleteSpec(base, contract)
	if err != nil {
		panic(err)
	}
	return spec
}

func tier1ManifestContract(id string) manifest.Contract {
	contract := tier1NoEvidenceContract()
	switch id {
	case "go-vet":
		contract.Purpose = "Run the root module's static and type analyzer gate."
		contract.Entrypoint = "regress/internal/tier1/runner.go::RunWithOptions -> runCaseDefs -> runCaseDefOutcome -> runCaseAttempts -> goVet -> runGo(go vet ./...)"
		contract.Topology = localProcessTopology("root-module-go-vet")
		contract.RoleCapabilities = localProcessCapabilities()
		contract.Payload = notApplicableProfile()
		contract.Load = unfrozenProfile()
		contract.Seed = manifest.SeedPolicy{Mode: manifest.SeedModeNone}
		contract.MissingDimensions = append(contract.MissingDimensions, missing(
			manifest.ContractDimensionLoad,
			"go vet discovers the ./... package set at runtime and the runner emits no frozen package count",
		))
	case "go-test":
		contract.Purpose = "Run the root module's closed package and top-level test inventory with at most five attempts; any first-attempt failure makes the case invalid even if a retry passes."
		contract.Entrypoint = "regress/internal/tier1/runner.go::RunWithOptions -> runCaseDefs -> runCaseDefOutcome -> runCaseAttempts -> goTest -> runTestContractSuite -> gotestjson.Executor.Run"
		setAggregateTestDimensionsMissing(&contract, "root tests span heterogeneous fixture topologies and OS-specific run sets", "root tests use heterogeneous fixture payloads", "root test load varies by the OS-specific closed inventory; max_attempts=5 and first-failure retention are runner policy rather than a frozen aggregate load profile", "individual root fixtures do not expose one frozen aggregate seed policy")
	case "regress-unit":
		contract.Purpose = "Run the nested regress module's closed fast unit and contract-test inventory once."
		contract.Entrypoint = "regress/internal/tier1/runner.go::RunWithOptions -> runCaseDefs -> runCaseDefOutcome -> runCaseAttempts -> regressUnit -> runTestContractSuite -> gotestjson.Executor.Run"
		setAggregateTestDimensionsMissing(&contract, "regress-unit spans heterogeneous unit-test fixtures and package-local topologies", "regress-unit uses heterogeneous fixture payloads", "the closed regress-unit run set contains heterogeneous test loads rather than one numeric profile", "individual regress-unit fixtures do not expose one frozen aggregate seed policy")
	case "go-test-race":
		contract.Purpose = "Run the Linux root module's closed package and top-level test inventory under the Go race detector with at most five attempts; any first-attempt failure makes the case invalid."
		contract.Entrypoint = "regress/internal/tier1/runner.go::RunWithOptions -> runCaseDefs -> runCaseDefOutcome -> runCaseAttempts -> goTestRace -> runTestContractSuite -> gotestjson.Executor.Run"
		setAggregateTestDimensionsMissing(&contract, "race-enabled root tests span heterogeneous fixture topologies", "race-enabled root tests use heterogeneous fixture payloads", "the race run set is closed but contains heterogeneous test loads; max_attempts=5 and first-failure retention are runner policy rather than a frozen aggregate load profile", "individual race-enabled fixtures do not expose one frozen aggregate seed policy")
	case "go-bench-smoke":
		contract.Purpose = "Discover the two root TCP stream benchmarks and execute each for one benchmark iteration."
		contract.Entrypoint = "regress/internal/tier1/runner.go::RunWithOptions -> runCaseDefs -> runCaseDefOutcome -> runCaseAttempts -> goBenchSmoke -> runBenchmarkContract -> go test -json -count=1 -run ^$ -bench <exact inventory> -benchtime=1x"
		contract.Topology = manifest.Topology{}
		contract.RoleCapabilities = nil
		contract.Payload = definedProfile("tcp-benchmark-chunk", manifest.ProfileParam{Name: "chunk_bytes", Value: 64 << 10, Unit: manifest.UnitBytes})
		contract.Load = definedProfile("root-benchmark-smoke",
			manifest.ProfileParam{Name: "benchmark_count", Value: 2, Unit: manifest.UnitCount},
			manifest.ProfileParam{Name: "iterations_per_benchmark", Value: 1, Unit: manifest.UnitCount},
		)
		contract.Seed = manifest.SeedPolicy{Mode: manifest.SeedModeNone}
		contract.MissingDimensions = append(contract.MissingDimensions,
			missing(manifest.ContractDimensionTopology, "the two benchmarks use one and two TCP paths, so this aggregate case has no single topology"),
			missing(manifest.ContractDimensionRoleCapabilities, "role capabilities cannot be scoped until the aggregate benchmark topology is split"),
		)
	case "const-proto-version":
		setSourceCheckContract(&contract,
			"Detect accidental drift of the stream protocol version literal.",
			"regress/internal/tier1/runner.go::RunWithOptions -> runCaseDefs -> runCaseDefOutcome -> runCaseAttempts -> constProtoVersion -> grepFile(proto/frame.go)",
			"stream-protocol-version-regex",
		)
	case "const-udpflow-version":
		setSourceCheckContract(&contract,
			"Detect accidental drift of the UDP flow header version literal.",
			"regress/internal/tier1/runner.go::RunWithOptions -> runCaseDefs -> runCaseDefOutcome -> runCaseAttempts -> constUDPFlowVersion -> grepFile(proto/udpflow.go)",
			"udpflow-version-regex",
		)
	case "const-migration-budget-90s":
		contract.Purpose = "Exercise runtime normalization of the default, zero, over-limit, and shorter migration budgets."
		contract.Entrypoint = "regress/internal/tier1/runner.go::RunWithOptions -> runCaseDefs -> runCaseDefOutcome -> runCaseAttempts -> constMigrationBudget -> validateMigrationBudgetContract"
		contract.Topology = localProcessTopology("migration-budget-runtime-check")
		contract.RoleCapabilities = localProcessCapabilities()
		contract.Payload = notApplicableProfile()
		contract.Load = definedProfile("migration-budget-configurations", manifest.ProfileParam{Name: "configuration_count", Value: 4, Unit: manifest.UnitCount})
		contract.Seed = manifest.SeedPolicy{Mode: manifest.SeedModeNone}
	case "const-mode-values":
		setSourceCheckContract(&contract,
			"Guard the legacy ModePrime, ModeBond, and ModeRace numeric literals.",
			"regress/internal/tier1/runner.go::RunWithOptions -> runCaseDefs -> runCaseDefOutcome -> runCaseAttempts -> constModeValues -> grepFile(mode.go)",
			"legacy-mode-values-regex",
		)
	case "const-mode-transition-table":
		setSourceCheckContract(&contract,
			"Guard the legacy runtime prohibition on race-to-bond and bond-to-race transitions.",
			"regress/internal/tier1/runner.go::RunWithOptions -> runCaseDefs -> runCaseDefOutcome -> runCaseAttempts -> constModeTransitionTable -> grepFile(conn_impl.go)",
			"legacy-mode-transition-regex",
		)
	default:
		panic(fmt.Sprintf("unknown T1 manifest contract %q", id))
	}
	return contract
}

func tier1NoEvidenceContract() manifest.Contract {
	return manifest.Contract{
		SchemaVersion: manifest.ContractSchemaVersion,
		State:         manifest.ContractStateBlocked,
		MissingDimensions: []manifest.MissingDimension{
			missing(manifest.ContractDimensionStimulus, "the T1 runner emits no report.Case.Evidence stimulus facts"),
			missing(manifest.ContractDimensionOracle, "the T1 runner emits no report.Case.Evidence oracle facts"),
			missing(manifest.ContractDimensionNegativeControl, "the executable case has no case-level negative control"),
			missing(manifest.ContractDimensionResources, "per-role vCPU, RAM, and disk minima have not been calibrated"),
		},
		NegativeControl: manifest.NegativeControl{Kind: manifest.NegativeControlAbsent},
		Resources:       manifest.ResourceBudget{State: manifest.ResourceStateUnfrozen},
	}
}

func setAggregateTestDimensionsMissing(contract *manifest.Contract, topology, payload, load, seed string) {
	contract.Topology = manifest.Topology{}
	contract.RoleCapabilities = nil
	contract.Payload = unfrozenProfile()
	contract.Load = unfrozenProfile()
	contract.Seed = manifest.SeedPolicy{}
	contract.MissingDimensions = append(contract.MissingDimensions,
		missing(manifest.ContractDimensionTopology, topology),
		missing(manifest.ContractDimensionRoleCapabilities, "capability requirements vary with the aggregate test fixtures and cannot be assigned to one frozen role set"),
		missing(manifest.ContractDimensionPayload, payload),
		missing(manifest.ContractDimensionLoad, load),
		missing(manifest.ContractDimensionSeed, seed),
	)
}

func setSourceCheckContract(contract *manifest.Contract, purpose, entrypoint, profile string) {
	contract.Purpose = purpose
	contract.Entrypoint = entrypoint
	contract.Topology = localProcessTopology(profile)
	contract.RoleCapabilities = localProcessCapabilities()
	contract.Payload = notApplicableProfile()
	contract.Load = definedProfile(profile, manifest.ProfileParam{Name: "source_files", Value: 1, Unit: manifest.UnitCount}, manifest.ProfileParam{Name: "required_matches", Value: 1, Unit: manifest.UnitCount})
	contract.Seed = manifest.SeedPolicy{Mode: manifest.SeedModeNone}
}

func localProcessTopology(profile string) manifest.Topology {
	return manifest.Topology{Profile: profile, Roles: []string{"runner"}, Isolation: "single host process", PathCount: 0}
}

func localProcessCapabilities() map[string][]string {
	return map[string][]string{"runner": {}}
}

func definedProfile(name string, params ...manifest.ProfileParam) manifest.Profile {
	return manifest.Profile{Applicability: manifest.ApplicabilityDefined, Name: name, Version: 1, Params: params}
}

func notApplicableProfile() manifest.Profile {
	return manifest.Profile{Applicability: manifest.ApplicabilityNotApplicable}
}

func unfrozenProfile() manifest.Profile {
	return manifest.Profile{Applicability: manifest.ApplicabilityUnfrozen}
}

func missing(dimension manifest.ContractDimension, reason string) manifest.MissingDimension {
	return manifest.MissingDimension{Dimension: dimension, Reason: reason}
}
