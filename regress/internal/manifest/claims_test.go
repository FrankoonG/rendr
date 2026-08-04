package manifest

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestClaimEvidenceRequirementsCoverEveryStructuredClaim(t *testing.T) {
	contract := completeContractInput(30 * time.Second)
	contract.ClaimBindings = nil
	original := cloneContract(contract)

	requirements, err := contract.ClaimEvidenceRequirements()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(contract, original) {
		t.Fatal("ClaimEvidenceRequirements mutated its input")
	}
	if len(requirements) == 0 || !sort.SliceIsSorted(requirements, func(i, j int) bool {
		return requirements[i].ClaimKey < requirements[j].ClaimKey
	}) {
		t.Fatalf("requirements are not a non-empty canonical sequence: %+v", requirements)
	}

	want := map[ClaimKey]ClaimEvidenceRequirement{
		"/topology/path_count": {
			Dimension: ContractDimensionTopology, Predicate: EvidenceUintEquals, Expected: "2",
		},
		"/role_capabilities/roles/0/capabilities/0": {
			Dimension: ContractDimensionRoleCapabilities, Predicate: EvidenceEquals, Expected: "net-admin",
		},
		"/payload/params/0/name": {
			Dimension: ContractDimensionPayload, Predicate: EvidenceEquals, Expected: "chunk_bytes",
		},
		"/load/params/1/value": {
			Dimension: ContractDimensionLoad, Predicate: EvidenceUintEquals, Expected: "1000",
		},
		"/seed/fixed_seed": {
			Dimension: ContractDimensionSeed, Predicate: EvidenceIntEquals, Expected: "42",
		},
		"/negative_control/embedded_id": {
			Dimension: ContractDimensionNegativeControl, Predicate: EvidenceEquals, Expected: "no-path-change",
		},
		"/resources/roles/0/vcpus": {
			Dimension: ContractDimensionResources, Predicate: EvidenceUintAtLeast, Expected: "2",
		},
	}
	seenDimensions := make(map[ContractDimension]bool)
	seenKeys := make(map[ClaimKey]bool)
	for _, requirement := range requirements {
		if seenKeys[requirement.ClaimKey] {
			t.Fatalf("duplicate requirement key %q", requirement.ClaimKey)
		}
		seenKeys[requirement.ClaimKey] = true
		seenDimensions[requirement.Dimension] = true
		if expected, ok := want[requirement.ClaimKey]; ok {
			expected.ClaimKey = requirement.ClaimKey
			if !reflect.DeepEqual(requirement, expected) {
				t.Fatalf("requirement %q=%+v want %+v", requirement.ClaimKey, requirement, expected)
			}
			delete(want, requirement.ClaimKey)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing representative requirements: %+v", want)
	}
	for _, dimension := range structuredClaimDimensions() {
		if !seenDimensions[dimension] {
			t.Fatalf("structured dimension %q has no claim requirements", dimension)
		}
	}
}

func TestEnforcedContractRejectsIncompleteOrMismatchedClaimBindings(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Contract)
		want   string
	}{
		{name: "all missing", mutate: func(c *Contract) { c.ClaimBindings = nil }, want: "missing claim binding"},
		{name: "one missing", mutate: func(c *Contract) { c.ClaimBindings = c.ClaimBindings[1:] }, want: "missing claim binding"},
		{name: "duplicate", mutate: func(c *Contract) {
			c.ClaimBindings = append(c.ClaimBindings, c.ClaimBindings[0])
		}, want: "is duplicated"},
		{name: "unknown key", mutate: func(c *Contract) {
			c.ClaimBindings[0].ClaimKey = "/unknown/value"
		}, want: "does not identify a structured claim"},
		{name: "wrong predicate", mutate: func(c *Contract) {
			index := claimBindingIndex(c.ClaimBindings, "/topology/path_count")
			c.ClaimBindings[index].Assertion.Predicate = EvidenceEquals
		}, want: "does not match required predicate"},
		{name: "wrong expected value", mutate: func(c *Contract) {
			c.ClaimBindings[0].Assertion.Expected += "-stale"
		}, want: "does not match structured claim value"},
		{name: "missing evidence fact", mutate: func(c *Contract) {
			c.ClaimBindings[0].Assertion.Fact = ""
		}, want: "assertion fact is missing"},
		{name: "stale structured value", mutate: func(c *Contract) {
			c.Topology.PathCount++
		}, want: "does not match structured claim value"},
		{name: "non-canonical order", mutate: func(c *Contract) {
			reverseClaimBindings(c.ClaimBindings)
		}, want: "not in canonical order"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contract := normalizedContract(t, 30*time.Second)
			tt.mutate(&contract)
			err := contract.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() err=%v want substring %q", err, tt.want)
			}
		})
	}
}

func TestClaimBindingsRejectEvidenceFactReuseAcrossDistinctClaims(t *testing.T) {
	tests := []struct {
		name     string
		contract Contract
	}{
		{name: "enforced", contract: completeContractInput(time.Second)},
		{name: "partial blocked", contract: blockedContractInput()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contract := tt.contract
			requirements, err := contract.ClaimEvidenceRequirements()
			if err != nil {
				t.Fatal(err)
			}
			contract.ClaimBindings = []ClaimEvidenceBinding{
				requirements[0].Bind("shared_fact"),
				requirements[1].Bind("shared_fact"),
			}
			if contract.State == ContractStateEnforced {
				bindAllClaimEvidence(&contract)
				contract.ClaimBindings[1].Assertion.Fact = contract.ClaimBindings[0].Assertion.Fact
			}
			if _, err := Normalize(contract); err == nil || !strings.Contains(err.Error(), "reuse evidence fact") {
				t.Fatalf("Normalize() err=%v", err)
			}
		})
	}
}

func TestBlockedCensusPreservesUnprovenContractsWithoutClaimBindings(t *testing.T) {
	const existingBlockedCount = 142
	specs := make([]Spec, existingBlockedCount)
	for i := range specs {
		base := RequiredWithBudget(fmt.Sprintf("blocked-%03d", i), "T2", time.Second)
		var err error
		specs[i], err = NewCompleteSpec(base, blockedContractInput())
		if err != nil {
			t.Fatalf("blocked contract %d: %v", i, err)
		}
		if specs[i].Contract.ClaimBindings != nil {
			t.Fatalf("blocked contract %d acquired fabricated claim bindings", i)
		}
	}
	if err := ValidateCensus(specs); err != nil {
		t.Fatalf("blocked census: %v", err)
	}
	assertions, err := specs[0].Contract.RuntimeClaimAssertions()
	if err != nil {
		t.Fatal(err)
	}
	if assertions != nil {
		t.Fatalf("unbound blocked contract exposed runtime assertions: %+v", assertions)
	}

	partial := blockedContractInput()
	requirements, err := partial.ClaimEvidenceRequirements()
	if err != nil {
		t.Fatal(err)
	}
	partial.ClaimBindings = []ClaimEvidenceBinding{bindingForRequirement(requirements[0])}
	normalized, err := Normalize(partial)
	if err != nil {
		t.Fatalf("valid partial blocked binding: %v", err)
	}
	assertions, err = normalized.RuntimeClaimAssertions()
	if err != nil || len(assertions) != 1 {
		t.Fatalf("partial blocked assertions=%+v err=%v", assertions, err)
	}

	complete := normalizedContract(t, time.Second)
	for _, binding := range complete.ClaimBindings {
		if strings.HasPrefix(string(binding.ClaimKey), "/payload/") {
			partial.ClaimBindings = []ClaimEvidenceBinding{binding}
			break
		}
	}
	if _, err := Normalize(partial); err == nil || !strings.Contains(err.Error(), "does not identify a structured claim") {
		t.Fatalf("blocked contract accepted binding for missing payload: %v", err)
	}
}

func TestRuntimeClaimAssertionsExposeTypedRunnerData(t *testing.T) {
	contract := normalizedContract(t, 30*time.Second)
	assertions, err := contract.RuntimeClaimAssertions()
	if err != nil {
		t.Fatal(err)
	}
	if len(assertions) != len(contract.ClaimBindings) {
		t.Fatalf("runtime assertions=%d bindings=%d", len(assertions), len(contract.ClaimBindings))
	}
	for i, runtimeAssertion := range assertions {
		binding := contract.ClaimBindings[i]
		if runtimeAssertion.ClaimKey != binding.ClaimKey || !reflect.DeepEqual(runtimeAssertion.Assertion, binding.Assertion) {
			t.Fatalf("runtime assertion %d=%+v binding=%+v", i, runtimeAssertion, binding)
		}
		if runtimeAssertion.Dimension == "" {
			t.Fatalf("runtime assertion %q has no dimension", runtimeAssertion.ClaimKey)
		}
		if err := EvaluateEvidenceAssertion(runtimeAssertion.Assertion, runtimeAssertion.Assertion.Expected); err != nil {
			t.Fatalf("evaluate %q: %v", runtimeAssertion.ClaimKey, err)
		}
	}
	assertions[0].Assertion.Fact = "mutated"
	if contract.ClaimBindings[0].Assertion.Fact == "mutated" {
		t.Fatal("runtime assertion result aliases contract bindings")
	}

	random := completeContractInput(time.Second)
	random.Seed = SeedPolicy{Mode: SeedModeRandomRecorded}
	bindAllClaimEvidence(&random)
	randomAssertions, err := random.RuntimeClaimAssertions()
	if err != nil {
		t.Fatal(err)
	}
	recorded := findRuntimeClaimAssertion(t, randomAssertions, "/seed/recorded_seed")
	if recorded.Assertion.Predicate != EvidenceInt || recorded.Assertion.Expected != "" {
		t.Fatalf("recorded seed assertion=%+v", recorded)
	}
	if err := EvaluateEvidenceAssertion(recorded.Assertion, "-12345"); err != nil {
		t.Fatalf("recorded seed rejected int64 evidence: %v", err)
	}
	if err := EvaluateEvidenceAssertion(recorded.Assertion, "not-recorded"); err == nil {
		t.Fatal("recorded seed accepted non-integer evidence")
	}
}

func TestCanonicalDigestBindsClaimEvidenceMapping(t *testing.T) {
	base := mustCompleteSpec(t, "claim-digest", time.Second)
	want := mustDigest(t, base)
	changed := CloneSpec(base)
	changed.Contract.ClaimBindings[0].Assertion.Fact += "_v2"
	if got := mustDigest(t, changed); got == want {
		t.Fatalf("claim evidence remapping did not change digest %q", got)
	}
}

func bindingForRequirement(requirement ClaimEvidenceRequirement) ClaimEvidenceBinding {
	return requirement.Bind("claim" + strings.ReplaceAll(string(requirement.ClaimKey), "/", "_"))
}

func claimBindingIndex(bindings []ClaimEvidenceBinding, key ClaimKey) int {
	for i, binding := range bindings {
		if binding.ClaimKey == key {
			return i
		}
	}
	panic(fmt.Sprintf("claim binding %q not found", key))
}

func findRuntimeClaimAssertion(t *testing.T, assertions []RuntimeClaimAssertion, key ClaimKey) RuntimeClaimAssertion {
	t.Helper()
	for _, assertion := range assertions {
		if assertion.ClaimKey == key {
			return assertion
		}
	}
	t.Fatalf("runtime assertion %q not found", key)
	return RuntimeClaimAssertion{}
}

func structuredClaimDimensions() []ContractDimension {
	return []ContractDimension{
		ContractDimensionTopology,
		ContractDimensionRoleCapabilities,
		ContractDimensionPayload,
		ContractDimensionLoad,
		ContractDimensionSeed,
		ContractDimensionNegativeControl,
		ContractDimensionResources,
	}
}
