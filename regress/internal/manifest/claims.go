package manifest

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ClaimKey is a canonical JSON-pointer-like path to one leaf in a normalized
// structured contract claim. Synthetic count leaves make set and map coverage
// exact instead of proving only the members the contract happened to name.
type ClaimKey string

// ClaimEvidenceBinding binds one structured claim leaf to the runtime evidence
// assertion that proves the executed case matched it.
type ClaimEvidenceBinding struct {
	ClaimKey  ClaimKey          `json:"claim_key"`
	Assertion EvidenceAssertion `json:"assertion"`
}

// ClaimEvidenceRequirement is the canonical assertion shape derived from a
// structured claim. Contract authors choose only the evidence Fact; Predicate
// and Expected must match this requirement exactly.
type ClaimEvidenceRequirement struct {
	ClaimKey  ClaimKey          `json:"claim_key"`
	Dimension ContractDimension `json:"dimension"`
	Predicate EvidencePredicate `json:"predicate"`
	Expected  string            `json:"expected,omitempty"`
}

// Bind maps r to an explicitly named runtime evidence fact. It copies only the
// required assertion shape; the case still has to emit and satisfy that fact.
func (r ClaimEvidenceRequirement) Bind(fact string) ClaimEvidenceBinding {
	return ClaimEvidenceBinding{
		ClaimKey: r.ClaimKey,
		Assertion: EvidenceAssertion{
			Fact:      fact,
			Predicate: r.Predicate,
			Expected:  r.Expected,
		},
	}
}

// RuntimeClaimAssertion is runner-facing evaluation data. The runner reads the
// named evidence fact, evaluates Assertion, and reports ClaimKey and Dimension
// when it fails.
type RuntimeClaimAssertion struct {
	ClaimKey  ClaimKey          `json:"claim_key"`
	Dimension ContractDimension `json:"dimension"`
	Assertion EvidenceAssertion `json:"assertion"`
}

// ClaimEvidenceRequirements returns the canonical structured-claim leaves for
// c without requiring bindings to exist yet. It validates and normalizes every
// other contract field and never mutates or fills c.
func (c Contract) ClaimEvidenceRequirements() ([]ClaimEvidenceRequirement, error) {
	normalized, err := normalizeContract(c, false)
	if err != nil {
		return nil, err
	}
	return claimEvidenceRequirements(normalized, contractMissingSet(normalized)), nil
}

// RuntimeClaimAssertions returns a canonical deep copy of the claim assertions
// a runner must evaluate. Enforced contracts contain every requirement;
// blocked contracts may truthfully return no assertions or a validated subset.
func (c Contract) RuntimeClaimAssertions() ([]RuntimeClaimAssertion, error) {
	normalized, err := Normalize(c)
	if err != nil {
		return nil, err
	}
	requirements := claimEvidenceRequirements(normalized, contractMissingSet(normalized))
	byKey := make(map[ClaimKey]ClaimEvidenceRequirement, len(requirements))
	for _, requirement := range requirements {
		byKey[requirement.ClaimKey] = requirement
	}
	if len(normalized.ClaimBindings) == 0 {
		return nil, nil
	}
	assertions := make([]RuntimeClaimAssertion, len(normalized.ClaimBindings))
	for i, binding := range normalized.ClaimBindings {
		requirement := byKey[binding.ClaimKey]
		assertions[i] = RuntimeClaimAssertion{
			ClaimKey:  binding.ClaimKey,
			Dimension: requirement.Dimension,
			Assertion: binding.Assertion,
		}
	}
	return assertions, nil
}

func normalizeClaimEvidenceBindings(bindings []ClaimEvidenceBinding) {
	for i := range bindings {
		bindings[i].ClaimKey = ClaimKey(strings.TrimSpace(string(bindings[i].ClaimKey)))
		normalizeEvidenceAssertion(&bindings[i].Assertion)
	}
	sort.Slice(bindings, func(i, j int) bool {
		return lessClaimEvidenceBinding(bindings[i], bindings[j])
	})
}

func lessClaimEvidenceBinding(left, right ClaimEvidenceBinding) bool {
	if left.ClaimKey != right.ClaimKey {
		return left.ClaimKey < right.ClaimKey
	}
	if left.Assertion.Fact != right.Assertion.Fact {
		return left.Assertion.Fact < right.Assertion.Fact
	}
	if left.Assertion.Predicate != right.Assertion.Predicate {
		return left.Assertion.Predicate < right.Assertion.Predicate
	}
	return left.Assertion.Expected < right.Assertion.Expected
}

func validateClaimEvidenceBindings(reasons *[]string, contract Contract, missing map[ContractDimension]struct{}) {
	requirements := claimEvidenceRequirements(contract, missing)
	byKey := make(map[ClaimKey]ClaimEvidenceRequirement, len(requirements))
	for _, requirement := range requirements {
		byKey[requirement.ClaimKey] = requirement
	}
	if !sort.SliceIsSorted(contract.ClaimBindings, func(i, j int) bool {
		return lessClaimEvidenceBinding(contract.ClaimBindings[i], contract.ClaimBindings[j])
	}) {
		*reasons = append(*reasons, "claim bindings are not in canonical order")
	}
	seen := make(map[ClaimKey]struct{}, len(contract.ClaimBindings))
	factOwners := make(map[string]ClaimKey, len(contract.ClaimBindings))
	for _, binding := range contract.ClaimBindings {
		validateCanonicalText(reasons, "claim binding key", string(binding.ClaimKey))
		validateEvidenceAssertions(reasons, fmt.Sprintf("claim binding %q", binding.ClaimKey), []EvidenceAssertion{binding.Assertion})
		if _, ok := seen[binding.ClaimKey]; ok {
			*reasons = append(*reasons, fmt.Sprintf("claim binding %q is duplicated", binding.ClaimKey))
		}
		seen[binding.ClaimKey] = struct{}{}
		if binding.Assertion.Fact != "" {
			if owner, ok := factOwners[binding.Assertion.Fact]; ok && owner != binding.ClaimKey {
				*reasons = append(*reasons, fmt.Sprintf(
					"claim bindings %q and %q reuse evidence fact %q",
					owner, binding.ClaimKey, binding.Assertion.Fact,
				))
			} else {
				factOwners[binding.Assertion.Fact] = binding.ClaimKey
			}
		}

		requirement, ok := byKey[binding.ClaimKey]
		if !ok {
			*reasons = append(*reasons, fmt.Sprintf("claim binding %q does not identify a structured claim", binding.ClaimKey))
			continue
		}
		if binding.Assertion.Predicate != requirement.Predicate {
			*reasons = append(*reasons, fmt.Sprintf(
				"claim binding %q predicate %q does not match required predicate %q",
				binding.ClaimKey, binding.Assertion.Predicate, requirement.Predicate,
			))
		}
		if binding.Assertion.Expected != requirement.Expected {
			*reasons = append(*reasons, fmt.Sprintf(
				"claim binding %q expected value %q does not match structured claim value %q",
				binding.ClaimKey, binding.Assertion.Expected, requirement.Expected,
			))
		}
	}
	if contract.State == ContractStateEnforced {
		for _, requirement := range requirements {
			if _, ok := seen[requirement.ClaimKey]; !ok {
				*reasons = append(*reasons, fmt.Sprintf("enforced contract is missing claim binding %q", requirement.ClaimKey))
			}
		}
	}
}

func cloneClaimEvidenceBindings(bindings []ClaimEvidenceBinding) []ClaimEvidenceBinding {
	if bindings == nil {
		return nil
	}
	return append([]ClaimEvidenceBinding(nil), bindings...)
}

func contractMissingSet(contract Contract) map[ContractDimension]struct{} {
	missing := make(map[ContractDimension]struct{}, len(contract.MissingDimensions))
	for _, value := range contract.MissingDimensions {
		missing[value.Dimension] = struct{}{}
	}
	return missing
}

func claimEvidenceRequirements(contract Contract, missing map[ContractDimension]struct{}) []ClaimEvidenceRequirement {
	requirements := make([]ClaimEvidenceRequirement, 0, 32)
	addString := func(dimension ContractDimension, key ClaimKey, expected string) {
		requirements = append(requirements, ClaimEvidenceRequirement{
			ClaimKey: key, Dimension: dimension, Predicate: EvidenceEquals, Expected: expected,
		})
	}
	addUintEquals := func(dimension ContractDimension, key ClaimKey, expected uint64) {
		requirements = append(requirements, ClaimEvidenceRequirement{
			ClaimKey: key, Dimension: dimension, Predicate: EvidenceUintEquals, Expected: strconv.FormatUint(expected, 10),
		})
	}
	addUintAtLeast := func(dimension ContractDimension, key ClaimKey, expected uint64) {
		requirements = append(requirements, ClaimEvidenceRequirement{
			ClaimKey: key, Dimension: dimension, Predicate: EvidenceUintAtLeast, Expected: strconv.FormatUint(expected, 10),
		})
	}
	addIntEquals := func(dimension ContractDimension, key ClaimKey, expected int64) {
		requirements = append(requirements, ClaimEvidenceRequirement{
			ClaimKey: key, Dimension: dimension, Predicate: EvidenceIntEquals, Expected: strconv.FormatInt(expected, 10),
		})
	}

	if !dimensionMissing(missing, ContractDimensionTopology) {
		addString(ContractDimensionTopology, "/topology/profile", contract.Topology.Profile)
		addString(ContractDimensionTopology, "/topology/isolation", contract.Topology.Isolation)
		if contract.Topology.PathCount >= 0 {
			addUintEquals(ContractDimensionTopology, "/topology/path_count", uint64(contract.Topology.PathCount))
		}
		addUintEquals(ContractDimensionTopology, "/topology/roles/count", uint64(len(contract.Topology.Roles)))
		for i, role := range contract.Topology.Roles {
			addString(ContractDimensionTopology, indexedClaimKey("/topology/roles", i), role)
		}
	}

	if !dimensionMissing(missing, ContractDimensionRoleCapabilities) {
		roles := sortedCapabilityRoles(contract.RoleCapabilities)
		addUintEquals(ContractDimensionRoleCapabilities, "/role_capabilities/roles/count", uint64(len(roles)))
		for i, role := range roles {
			prefix := indexedClaimKey("/role_capabilities/roles", i)
			addString(ContractDimensionRoleCapabilities, prefix+"/role", role)
			capabilities := contract.RoleCapabilities[role]
			addUintEquals(ContractDimensionRoleCapabilities, prefix+"/capabilities/count", uint64(len(capabilities)))
			for j, capability := range capabilities {
				addString(ContractDimensionRoleCapabilities, indexedClaimKey(prefix+"/capabilities", j), capability)
			}
		}
	}

	appendProfileClaimRequirements(&requirements, ContractDimensionPayload, "/payload", contract.Payload, missing)
	appendProfileClaimRequirements(&requirements, ContractDimensionLoad, "/load", contract.Load, missing)

	if !dimensionMissing(missing, ContractDimensionSeed) {
		addString(ContractDimensionSeed, "/seed/mode", string(contract.Seed.Mode))
		switch contract.Seed.Mode {
		case SeedModeFixed:
			if contract.Seed.FixedSeed != nil {
				addIntEquals(ContractDimensionSeed, "/seed/fixed_seed", *contract.Seed.FixedSeed)
			}
		case SeedModeRandomRecorded:
			requirements = append(requirements, ClaimEvidenceRequirement{
				ClaimKey: "/seed/recorded_seed", Dimension: ContractDimensionSeed, Predicate: EvidenceInt,
			})
		}
	}

	if !dimensionMissing(missing, ContractDimensionNegativeControl) {
		addString(ContractDimensionNegativeControl, "/negative_control/kind", string(contract.NegativeControl.Kind))
		switch contract.NegativeControl.Kind {
		case NegativeControlCase:
			addString(ContractDimensionNegativeControl, "/negative_control/case_id", contract.NegativeControl.CaseID)
		case NegativeControlEmbedded:
			addString(ContractDimensionNegativeControl, "/negative_control/embedded_id", contract.NegativeControl.EmbeddedID)
		case NegativeControlNotApplicable:
			addString(ContractDimensionNegativeControl, "/negative_control/reason", contract.NegativeControl.Reason)
		}
	}

	if !dimensionMissing(missing, ContractDimensionResources) {
		addString(ContractDimensionResources, "/resources/state", string(contract.Resources.State))
		if contract.Resources.Timeout >= 0 {
			addUintEquals(ContractDimensionResources, "/resources/timeout_ns", uint64(contract.Resources.Timeout))
		}
		addString(ContractDimensionResources, "/resources/exclusivity", string(contract.Resources.Exclusivity))
		roles := sortedResourceRoles(contract.Resources.Roles)
		addUintEquals(ContractDimensionResources, "/resources/roles/count", uint64(len(roles)))
		for i, role := range roles {
			prefix := indexedClaimKey("/resources/roles", i)
			addString(ContractDimensionResources, prefix+"/role", role)
			budget := contract.Resources.Roles[role]
			if budget.VCPUs >= 0 {
				addUintAtLeast(ContractDimensionResources, prefix+"/vcpus", uint64(budget.VCPUs))
			}
			addUintAtLeast(ContractDimensionResources, prefix+"/ram_bytes", budget.RAMBytes)
			addUintAtLeast(ContractDimensionResources, prefix+"/disk_bytes", budget.DiskBytes)
		}
	}

	sort.Slice(requirements, func(i, j int) bool {
		return requirements[i].ClaimKey < requirements[j].ClaimKey
	})
	return requirements
}

func appendProfileClaimRequirements(requirements *[]ClaimEvidenceRequirement, dimension ContractDimension, prefix string, profile Profile, missing map[ContractDimension]struct{}) {
	if dimensionMissing(missing, dimension) {
		return
	}
	*requirements = append(*requirements, ClaimEvidenceRequirement{
		ClaimKey: ClaimKey(prefix + "/applicability"), Dimension: dimension,
		Predicate: EvidenceEquals, Expected: string(profile.Applicability),
	})
	if profile.Applicability != ApplicabilityDefined {
		return
	}
	*requirements = append(*requirements,
		ClaimEvidenceRequirement{ClaimKey: ClaimKey(prefix + "/name"), Dimension: dimension, Predicate: EvidenceEquals, Expected: profile.Name},
		ClaimEvidenceRequirement{ClaimKey: ClaimKey(prefix + "/version"), Dimension: dimension, Predicate: EvidenceUintEquals, Expected: strconv.Itoa(profile.Version)},
		ClaimEvidenceRequirement{ClaimKey: ClaimKey(prefix + "/params/count"), Dimension: dimension, Predicate: EvidenceUintEquals, Expected: strconv.Itoa(len(profile.Params))},
	)
	for i, param := range profile.Params {
		paramPrefix := indexedClaimKey(ClaimKey(prefix+"/params"), i)
		*requirements = append(*requirements,
			ClaimEvidenceRequirement{ClaimKey: paramPrefix + "/name", Dimension: dimension, Predicate: EvidenceEquals, Expected: param.Name},
			ClaimEvidenceRequirement{ClaimKey: paramPrefix + "/value", Dimension: dimension, Predicate: EvidenceUintEquals, Expected: strconv.FormatUint(param.Value, 10)},
			ClaimEvidenceRequirement{ClaimKey: paramPrefix + "/unit", Dimension: dimension, Predicate: EvidenceEquals, Expected: string(param.Unit)},
		)
	}
}

func indexedClaimKey(prefix ClaimKey, index int) ClaimKey {
	return ClaimKey(fmt.Sprintf("%s/%d", prefix, index))
}

func sortedCapabilityRoles(values map[string][]string) []string {
	roles := make([]string, 0, len(values))
	for role := range values {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	return roles
}

func sortedResourceRoles(values map[string]RoleResourceBudget) []string {
	roles := make([]string, 0, len(values))
	for role := range values {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	return roles
}
