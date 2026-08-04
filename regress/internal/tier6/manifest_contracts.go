package tier6

import (
	"fmt"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/manifest"
)

type contractMetadata struct {
	purpose           string
	entrypoint        string
	expectedTests     uint64
	pathCount         int
	topologyIsolation string
	topologyMissing   string
}

var contractMetadataByID = map[string]contractMetadata{
	"T6.graph.compat-mode": {
		purpose:         "Exercise legacy flat-mode compilation, target constructors, root-plan precedence, and the root selector dial smoke.",
		entrypoint:      "regress/internal/tier6/runner.go::runRootTargetGraphTests -> target_test.go::TestLegacyRootTargetCompilesModes, TestTargetConstructorsExposeGroupKinds, TestDialerCompileDialPlanUsesRoot, TestDialerRootSelectorDialSmoke",
		expectedTests:   4,
		topologyMissing: "the case aggregates compile-only fixtures with a two-path loopback dial test, so one topology and path count are not frozen",
	},
	"T6.peak.A-to-bulk-bond": {
		purpose:           "Promote saturated selector traffic from path A to the B/C bond child and observe writes on both bond paths.",
		entrypoint:        "regress/internal/tier6/runner.go::runRootTargetGraphTests -> target_test.go::TestSelectorPeakTransferRuntimePromotesToBond",
		expectedTests:     1,
		pathCount:         3,
		topologyIsolation: "client and server share one Go test process and one loopback TCP listener; A, B, and C are logical rendr paths",
	},
	"T6.peak.nested-normal-to-C": {
		purpose:           "Choose path B inside the nested normal selector from injected quality while excluding peak path C from normal selection.",
		entrypoint:        "regress/internal/tier6/runner.go::runRootTargetGraphTests -> target_test.go::TestSelectorPeakTransferNormalSelectorUsesQuality",
		expectedTests:     1,
		pathCount:         3,
		topologyIsolation: "client and server share one Go test process and one loopback TCP listener; A and B are normal paths and C is a peak path",
	},
	"T6.failover.hot-standby": {
		purpose:           "Force-kill active path A, observe selection of standby path B, and deliver a two-byte stream payload.",
		entrypoint:        "regress/internal/tier6/runner.go::runRootTargetGraphTests -> target_test.go::TestSelectorHotStandbyFailover",
		expectedTests:     1,
		pathCount:         2,
		topologyIsolation: "client and server share one Go test process and one loopback TCP listener; A and B are logical rendr paths",
	},
	"T6.peak.composite-normal": {
		purpose:           "Keep selection within normal paths A/B after selected normal path C is force-killed, without selecting peak path D.",
		entrypoint:        "regress/internal/tier6/runner.go::runRootTargetGraphTests -> target_test.go::TestSelectorPeakTransferCompositeNormalDeathStaysNormal",
		expectedTests:     1,
		pathCount:         4,
		topologyIsolation: "client and server share one Go test process and one loopback TCP listener; A, B, and C are nested normal paths and D is a peak path",
	},
	"T6.peak.bad-speed": {
		purpose:           "Keep selector mode on path A when peak path C receives injected high RTT, jitter, and loss quality.",
		entrypoint:        "regress/internal/tier6/runner.go::runRootTargetGraphTests -> target_test.go::TestSelectorPeakTransferBadSpeedQualityGate",
		expectedTests:     1,
		pathCount:         2,
		topologyIsolation: "client and server share one Go test process and one loopback TCP listener; path C quality is injected through a test hook",
	},
	"T6.peak.stale-speed": {
		purpose:           "Keep selector mode on path A when peak path C receives stale injected quality evidence.",
		entrypoint:        "regress/internal/tier6/runner.go::runRootTargetGraphTests -> target_test.go::TestSelectorPeakTransferStaleSpeedEvidence",
		expectedTests:     1,
		pathCount:         2,
		topologyIsolation: "client and server share one Go test process and one loopback TCP listener; path C quality timestamp is injected through a test hook",
	},
	"T6.peak.probe-budget": {
		purpose:           "Promote to peak candidate P1 and assert that writes do not reach unselected candidates P2 or P3.",
		entrypoint:        "regress/internal/tier6/runner.go::runRootTargetGraphTests -> target_test.go::TestSelectorPeakTransferProbeBudgetUsesSinglePeakCandidate",
		expectedTests:     1,
		pathCount:         4,
		topologyIsolation: "client and server share one Go test process and one loopback TCP listener; A, P1, P2, and P3 are logical rendr paths",
	},
	"T6.peak.slow-peak-revert": {
		purpose:           "Promote from path A to a delay-wrapped peak path B, revert to A, and suppress immediate repeat promotion.",
		entrypoint:        "regress/internal/tier6/runner.go::runRootTargetGraphTests -> target_test.go::TestSelectorPeakTransferSlowPeakRevertsAndSuppresses",
		expectedTests:     1,
		pathCount:         2,
		topologyIsolation: "client and server share one Go test process and one loopback TCP listener; peak path B wraps writes with a fixed test delay",
	},
	"T6.peak.rx-peer-policy": {
		purpose:           "Promote the server sender from path A to B under receive-direction saturation while the client sender remains on A.",
		entrypoint:        "regress/internal/tier6/runner.go::runRootTargetGraphTests -> target_test.go::TestSelectorPeakTransferRxPromotesPeerSenderOnly",
		expectedTests:     1,
		pathCount:         2,
		topologyIsolation: "client and server share one Go test process and one loopback TCP listener; direction-specific active-path state is read from each endpoint",
	},
}

func mustCaseSpec(id string, budget time.Duration) manifest.Spec {
	metadata, ok := contractMetadataByID[id]
	if !ok {
		panic(fmt.Sprintf("tier6: missing contract metadata for %q", id))
	}
	contract := blockedGoTestContract(id, metadata)
	spec, err := manifest.NewCompleteSpec(manifest.RequiredWithBudget(id, "T6", budget), contract)
	if err != nil {
		panic(err)
	}
	return spec
}

func blockedGoTestContract(id string, metadata contractMetadata) manifest.Contract {
	missing := []manifest.MissingDimension{
		{Dimension: manifest.ContractDimensionPayload, Reason: "fixture payload bytes are test-local and no versioned payload profile is frozen by the runner"},
		{Dimension: manifest.ContractDimensionSeed, Reason: "fixture identity generation and any randomness are not surfaced or recorded by the runner"},
		{Dimension: manifest.ContractDimensionStimulus, Reason: "the runner emits no report.Case evidence for the semantic stimulus"},
		{Dimension: manifest.ContractDimensionOracle, Reason: "the runner emits no report.Case evidence for semantic assertions beyond the aggregate test result"},
		{Dimension: manifest.ContractDimensionNegativeControl, Reason: "the registry case has no separately evidenced negative control"},
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
		Roles:     []string{"client", "server"},
		Isolation: metadata.topologyIsolation,
		PathCount: metadata.pathCount,
	}
	contract.RoleCapabilities = map[string][]string{"client": {}, "server": {}}
	return contract
}
