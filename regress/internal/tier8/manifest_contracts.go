package tier8

import (
	"fmt"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/manifest"
)

type contractMetadata struct {
	purpose              string
	entrypoint           string
	roles                []string
	pathCount            int
	topologyIsolation    string
	payloadNotApplicable bool
}

var contractMetadataByID = map[string]contractMetadata{
	"T8.status.local-default": {
		purpose:              "Assert that the local status probe reports the rendr and L7 capability bits.",
		entrypoint:           "regress/internal/tier8/runner.go::runGoTest -> status_test.go::TestProbeLocalDefault",
		roles:                []string{"go-test-process"},
		topologyIsolation:    "one Go test process invokes the local capability probe without a network peer",
		payloadNotApplicable: true,
	},
	"T8.status.peer-rendr": {
		purpose:           "Dial one loopback TCP rendr path and assert peer identity plus attached primary-path status.",
		entrypoint:        "regress/internal/tier8/runner.go::runGoTest -> target_test.go::TestDialerStatusPeerRendr",
		roles:             []string{"client", "server"},
		pathCount:         1,
		topologyIsolation: "client and server share one Go test process and one loopback TCP listener",
	},
	"T8.primary.default-first-leaf": {
		purpose:           "Dial a two-leaf root selector and transfer a two-byte payload; the test does not assert which leaf became primary.",
		entrypoint:        "regress/internal/tier8/runner.go::runGoTest -> target_test.go::TestDialerRootSelectorDialSmoke",
		roles:             []string{"client", "server"},
		pathCount:         2,
		topologyIsolation: "client and server share one Go test process and one loopback TCP listener; both logical paths use that listener",
	},
	"T8.primary.explicit-path": {
		purpose:              "Compile a two-path selector with explicit primary B and assert that B is first in the dial plan.",
		entrypoint:           "regress/internal/tier8/runner.go::runGoTest -> target_test.go::TestDialerPrimaryExplicitPathReordersPlan",
		roles:                []string{"go-test-process"},
		pathCount:            2,
		topologyIsolation:    "one Go test process constructs a dial plan; no sockets are opened",
		payloadNotApplicable: true,
	},
	"T8.primary.explicit-group-resolve": {
		purpose:              "Compile a selector whose explicit primary is a B/C bond group and assert resolution to leaf B.",
		entrypoint:           "regress/internal/tier8/runner.go::runGoTest -> target_test.go::TestDialerPrimaryExplicitGroupResolvesLeaf",
		roles:                []string{"go-test-process"},
		pathCount:            3,
		topologyIsolation:    "one Go test process constructs a nested dial plan; no sockets are opened",
		payloadNotApplicable: true,
	},
	"T8.primary.prefer-fallback": {
		purpose:           "Prefer unavailable path A, establish fallback path B, and assert pending or unavailable status for A and active attached status for B.",
		entrypoint:        "regress/internal/tier8/runner.go::runGoTest -> target_test.go::TestDialerPrimaryPreferFallbackStatus",
		roles:             []string{"client", "server"},
		pathCount:         2,
		topologyIsolation: "client and server share one Go test process; A targets a closed loopback address and B targets a loopback rendr listener",
	},
	"T8.primary.require-fails": {
		purpose:              "Require unavailable primary path A and assert that Dial fails instead of using available path B.",
		entrypoint:           "regress/internal/tier8/runner.go::runGoTest -> target_test.go::TestDialerPrimaryRequireFails",
		roles:                []string{"client", "server"},
		pathCount:            2,
		topologyIsolation:    "client and unused server listener share one Go test process; A targets a closed loopback address and B targets the listener",
		payloadNotApplicable: true,
	},
	"T8.retry.forwarding-fixed": {
		purpose:              "Redirect optional path B from a native loopback listener to the rendr listener and observe B become attached through retry.",
		entrypoint:           "regress/internal/tier8/runner.go::runGoTest -> status_test.go::TestDialerOptionalPathRetryAttachesAfterForwardingFix",
		roles:                []string{"client", "native-server", "rendr-server"},
		pathCount:            2,
		topologyIsolation:    "all roles share one Go test process; separate native and rendr loopback TCP listeners back the switchable B factory",
		payloadNotApplicable: true,
	},
	"T8.retry.no-app-error": {
		purpose:           "Keep a two-byte application transfer working on path A while optional path B repeatedly targets a closed loopback address.",
		entrypoint:        "regress/internal/tier8/runner.go::runGoTest -> status_test.go::TestDialerOptionalPathFailureDoesNotSurfaceToApp",
		roles:             []string{"client", "server"},
		pathCount:         2,
		topologyIsolation: "client and server share one Go test process; A targets a loopback rendr listener and B targets a closed loopback address",
	},
}

func mustCaseSpec(id string, budget time.Duration) manifest.Spec {
	metadata, ok := contractMetadataByID[id]
	if !ok {
		panic(fmt.Sprintf("tier8: missing contract metadata for %q", id))
	}
	spec, err := manifest.NewCompleteSpec(manifest.RequiredWithBudget(id, "T8", budget), blockedGoTestContract(id, metadata))
	if err != nil {
		panic(err)
	}
	return spec
}

func blockedGoTestContract(id string, metadata contractMetadata) manifest.Contract {
	missing := []manifest.MissingDimension{
		{Dimension: manifest.ContractDimensionSeed, Reason: "fixture identity generation and any randomness are not surfaced or recorded by the runner"},
		{Dimension: manifest.ContractDimensionStimulus, Reason: "the runner emits no report.Case evidence for the semantic stimulus"},
		{Dimension: manifest.ContractDimensionOracle, Reason: "the runner emits no report.Case evidence for semantic assertions beyond the aggregate test result"},
		{Dimension: manifest.ContractDimensionNegativeControl, Reason: "the registry case has no separately evidenced negative control"},
		{Dimension: manifest.ContractDimensionResources, Reason: "per-role vCPU, RAM, and disk minima have not been calibrated"},
	}
	payload := manifest.Profile{Applicability: manifest.ApplicabilityNotApplicable}
	if !metadata.payloadNotApplicable {
		missing = append(missing, manifest.MissingDimension{
			Dimension: manifest.ContractDimensionPayload,
			Reason:    "fixture payload bytes are test-local and no versioned payload profile is frozen by the runner",
		})
		payload.Applicability = manifest.ApplicabilityUnfrozen
	}
	capabilities := make(map[string][]string, len(metadata.roles))
	for _, role := range metadata.roles {
		capabilities[role] = []string{}
	}
	return manifest.Contract{
		SchemaVersion:     manifest.ContractSchemaVersion,
		State:             manifest.ContractStateBlocked,
		MissingDimensions: missing,
		Purpose:           metadata.purpose,
		Entrypoint:        metadata.entrypoint,
		Topology: manifest.Topology{
			Profile:   id + "-fixture-v1",
			Roles:     metadata.roles,
			Isolation: metadata.topologyIsolation,
			PathCount: metadata.pathCount,
		},
		RoleCapabilities: capabilities,
		Payload:          payload,
		Load: manifest.Profile{
			Applicability: manifest.ApplicabilityDefined,
			Name:          "exact-go-test-invocation",
			Version:       1,
			Params: []manifest.ProfileParam{{
				Name:  "expected_top_level_tests",
				Value: 1,
				Unit:  manifest.UnitCount,
			}},
		},
		NegativeControl: manifest.NegativeControl{Kind: manifest.NegativeControlAbsent},
		Resources:       manifest.ResourceBudget{State: manifest.ResourceStateUnfrozen},
	}
}
