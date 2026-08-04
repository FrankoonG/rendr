package manifest

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

const ContractSchemaVersion = 4

// ContractState distinguishes facts enforced by a runnable case from census
// rows that truthfully record why the legacy case cannot yet be enforced.
type ContractState string

const (
	ContractStateEnforced ContractState = "enforced"
	ContractStateBlocked  ContractState = "blocked"
)

// ContractDimension is one independently auditable part of a contract.
type ContractDimension string

const (
	ContractDimensionPurpose          ContractDimension = "purpose"
	ContractDimensionEntrypoint       ContractDimension = "entrypoint"
	ContractDimensionTopology         ContractDimension = "topology"
	ContractDimensionRoleCapabilities ContractDimension = "role_capabilities"
	ContractDimensionPayload          ContractDimension = "payload"
	ContractDimensionLoad             ContractDimension = "load"
	ContractDimensionSeed             ContractDimension = "seed"
	ContractDimensionStimulus         ContractDimension = "stimulus"
	ContractDimensionOracle           ContractDimension = "oracle"
	ContractDimensionNegativeControl  ContractDimension = "negative_control"
	ContractDimensionResources        ContractDimension = "resources"
)

// MissingDimension records one unfrozen contract dimension and why it cannot
// yet be asserted. Entries are a canonical set keyed by Dimension.
type MissingDimension struct {
	Dimension ContractDimension `json:"dimension"`
	Reason    string            `json:"reason"`
}

// BaseUnit is the canonical unit of an integer profile parameter. Profiles use
// base units so equivalent values cannot acquire different manifest digests.
type BaseUnit string

const (
	UnitCount               BaseUnit = "count"
	UnitBytes               BaseUnit = "bytes"
	UnitNanoseconds         BaseUnit = "nanoseconds"
	UnitBitsPerSecond       BaseUnit = "bits_per_second"
	UnitBytesPerSecond      BaseUnit = "bytes_per_second"
	UnitPacketsPerSecond    BaseUnit = "packets_per_second"
	UnitOperationsPerSecond BaseUnit = "operations_per_second"
	UnitPartsPerMillion     BaseUnit = "parts_per_million"
)

// Exclusivity states whether a case may share its allocated execution host
// with another case. It is an enum rather than a bool so omission is invalid.
type Exclusivity string

const (
	ExclusivityShared    Exclusivity = "shared"
	ExclusivityExclusive Exclusivity = "exclusive"
)

// Applicability states whether a payload or load profile is defined, factually
// irrelevant, or not yet frozen. Unfrozen is valid only on a blocked contract.
type Applicability string

const (
	ApplicabilityDefined       Applicability = "defined"
	ApplicabilityNotApplicable Applicability = "not-applicable"
	ApplicabilityUnfrozen      Applicability = "unfrozen"
)

// SeedMode defines how a case chooses its reproducibility seed.
type SeedMode string

const (
	SeedModeNone           SeedMode = "none"
	SeedModeFixed          SeedMode = "fixed"
	SeedModeRandomRecorded SeedMode = "random-recorded"
)

// NegativeControlKind describes where a case's negative control lives.
type NegativeControlKind string

const (
	NegativeControlCase          NegativeControlKind = "case"
	NegativeControlEmbedded      NegativeControlKind = "embedded"
	NegativeControlAbsent        NegativeControlKind = "absent"
	NegativeControlNotApplicable NegativeControlKind = "not-applicable"
)

// ResourceState distinguishes a defined per-role budget from one that has not
// yet been frozen for a blocked census row.
type ResourceState string

const (
	ResourceStateDefined  ResourceState = "defined"
	ResourceStateUnfrozen ResourceState = "unfrozen"
)

// Contract is the schema-versioned claim made by one v1 regression case.
// Enforced contracts contain every applicable fact. Blocked contracts retain
// known facts and explicitly enumerate every dimension that remains unfrozen.
type Contract struct {
	SchemaVersion     int                    `json:"schema_version"`
	State             ContractState          `json:"state"`
	MissingDimensions []MissingDimension     `json:"missing_dimensions,omitempty"`
	Purpose           string                 `json:"purpose"`
	Entrypoint        string                 `json:"entrypoint"`
	Topology          Topology               `json:"topology"`
	RoleCapabilities  map[string][]string    `json:"role_capabilities"`
	Payload           Profile                `json:"payload"`
	Load              Profile                `json:"load"`
	Seed              SeedPolicy             `json:"seed"`
	Stimulus          EvidenceProfile        `json:"stimulus"`
	Oracle            EvidenceProfile        `json:"oracle"`
	NegativeControl   NegativeControl        `json:"negative_control"`
	Resources         ResourceBudget         `json:"resources"`
	ClaimBindings     []ClaimEvidenceBinding `json:"claim_bindings,omitempty"`
}

// Topology identifies the topology recipe and the roles it must isolate.
// PathCount may be zero for factual no-network cases.
type Topology struct {
	Profile   string   `json:"profile"`
	Roles     []string `json:"roles"`
	Isolation string   `json:"isolation"`
	PathCount int      `json:"path_count"`
}

// Profile references a versioned payload or offered-load recipe. Defined
// profiles use numeric base-unit parameters; other applicability states carry
// no profile fields.
type Profile struct {
	Applicability Applicability  `json:"applicability"`
	Name          string         `json:"name,omitempty"`
	Version       int            `json:"version,omitempty"`
	Params        []ProfileParam `json:"params,omitempty"`
}

// ProfileParam is one canonical profile input. Name is unique within a
// profile, Value is expressed in Unit, and Value is never a display quantity.
type ProfileParam struct {
	Name  string   `json:"name"`
	Value uint64   `json:"value"`
	Unit  BaseUnit `json:"unit"`
}

// SeedPolicy covers randomness that can change workload, topology, stimulus,
// or oracle outcomes. Protocol identity and cryptographic nonce generation are
// provenance, not scenario seeds, unless a case asserts behavior from them.
// FixedSeed is present only for SeedModeFixed.
type SeedPolicy struct {
	Mode      SeedMode `json:"mode"`
	FixedSeed *int64   `json:"fixed_seed,omitempty"`
}

// EvidencePredicate gives a machine-checkable meaning to an evidence value.
// RequiredFacts below are observational presence requirements and are never
// sufficient by themselves for an enforced oracle.
type EvidencePredicate string

const (
	EvidenceEquals       EvidencePredicate = "equals"
	EvidenceUintEquals   EvidencePredicate = "uint-equals"
	EvidenceUintAtLeast  EvidencePredicate = "uint-at-least"
	EvidenceUintAtMost   EvidencePredicate = "uint-at-most"
	EvidenceIntEquals    EvidencePredicate = "int-equals"
	EvidenceInt          EvidencePredicate = "int"
	EvidenceFloatAtLeast EvidencePredicate = "float-at-least"
	EvidenceFloatAtMost  EvidencePredicate = "float-at-most"
)

// EvidenceAssertion is one typed predicate over a report.Case evidence fact.
// Expected is textual because report evidence is textual; numeric predicates
// parse both sides before comparison.
type EvidenceAssertion struct {
	Fact      string            `json:"fact"`
	Predicate EvidencePredicate `json:"predicate"`
	Expected  string            `json:"expected"`
}

// EvidenceProfile names a versioned evidence collector. RequiredFacts only
// require non-empty observations. Assertions prove semantic values.
type EvidenceProfile struct {
	Name          string              `json:"name"`
	Version       int                 `json:"version"`
	RequiredFacts []string            `json:"required_facts"`
	Assertions    []EvidenceAssertion `json:"assertions,omitempty"`
}

// NegativeControl identifies a separate manifest case, an embedded control,
// a factual non-applicability reason, or an explicitly absent blocked fact.
type NegativeControl struct {
	Kind       NegativeControlKind `json:"kind"`
	CaseID     string              `json:"case_id,omitempty"`
	EmbeddedID string              `json:"embedded_id,omitempty"`
	Reason     string              `json:"reason,omitempty"`
}

// ResourceBudget is the minimum bounded allocation needed by a case.
type ResourceBudget struct {
	State       ResourceState                 `json:"state"`
	Timeout     time.Duration                 `json:"timeout_ns,omitempty"`
	Roles       map[string]RoleResourceBudget `json:"roles,omitempty"`
	Exclusivity Exclusivity                   `json:"exclusivity,omitempty"`
}

// RoleResourceBudget is the minimum isolated allocation for one topology
// role. Per-role declarations prevent aggregate allocations from hiding an
// undersized role.
type RoleResourceBudget struct {
	VCPUs     int    `json:"vcpus"`
	RAMBytes  uint64 `json:"ram_bytes"`
	DiskBytes uint64 `json:"disk_bytes"`
}

// NewCompleteSpec attaches a valid schema-v4 contract to existing Spec
// metadata. The compatibility name is retained while registries migrate; both
// enforced and truthful blocked contracts are accepted.
func NewCompleteSpec(base Spec, contract Contract) (Spec, error) {
	if base.Contract != nil {
		return Spec{}, fmt.Errorf("manifest: case %q already has a contract", base.ID)
	}
	normalized, err := Normalize(contract)
	if err != nil {
		return Spec{}, fmt.Errorf("manifest: case %q contract: %w", base.ID, err)
	}
	base.Contract = &normalized
	if err := validateStandaloneSpec(base); err != nil {
		return Spec{}, err
	}
	return CloneSpec(base), nil
}

// Normalize returns a deep canonical copy. It sorts set-like fields and never
// fills a missing claim or converts placeholder text into an enforced fact.
func Normalize(contract Contract) (Contract, error) {
	return normalizeContract(contract, true)
}

func normalizeContract(contract Contract, validateBindings bool) (Contract, error) {
	normalized := cloneContract(contract)
	normalized.State = ContractState(strings.TrimSpace(string(normalized.State)))
	normalized.Purpose = strings.TrimSpace(normalized.Purpose)
	normalized.Entrypoint = strings.TrimSpace(normalized.Entrypoint)
	normalized.Topology.Profile = strings.TrimSpace(normalized.Topology.Profile)
	normalized.Topology.Isolation = strings.TrimSpace(normalized.Topology.Isolation)
	normalizeStrings(normalized.Topology.Roles)

	for i := range normalized.MissingDimensions {
		normalized.MissingDimensions[i].Dimension = ContractDimension(strings.TrimSpace(string(normalized.MissingDimensions[i].Dimension)))
		normalized.MissingDimensions[i].Reason = strings.TrimSpace(normalized.MissingDimensions[i].Reason)
	}
	sort.Slice(normalized.MissingDimensions, func(i, j int) bool {
		if normalized.MissingDimensions[i].Dimension != normalized.MissingDimensions[j].Dimension {
			return normalized.MissingDimensions[i].Dimension < normalized.MissingDimensions[j].Dimension
		}
		return normalized.MissingDimensions[i].Reason < normalized.MissingDimensions[j].Reason
	})

	capabilities, err := normalizeStringMap(normalized.RoleCapabilities, "role capability scope")
	if err != nil {
		return Contract{}, err
	}
	normalized.RoleCapabilities = capabilities

	resourceRoles, err := normalizeResourceMap(normalized.Resources.Roles)
	if err != nil {
		return Contract{}, err
	}
	normalized.Resources.Roles = resourceRoles
	normalized.Resources.State = ResourceState(strings.TrimSpace(string(normalized.Resources.State)))

	normalizeProfile(&normalized.Payload)
	normalizeProfile(&normalized.Load)
	normalizeEvidenceProfile(&normalized.Stimulus)
	normalizeEvidenceProfile(&normalized.Oracle)
	normalized.Seed.Mode = SeedMode(strings.TrimSpace(string(normalized.Seed.Mode)))
	normalized.NegativeControl.Kind = NegativeControlKind(strings.TrimSpace(string(normalized.NegativeControl.Kind)))
	normalized.NegativeControl.CaseID = strings.TrimSpace(normalized.NegativeControl.CaseID)
	normalized.NegativeControl.EmbeddedID = strings.TrimSpace(normalized.NegativeControl.EmbeddedID)
	normalized.NegativeControl.Reason = strings.TrimSpace(normalized.NegativeControl.Reason)
	normalizeClaimEvidenceBindings(normalized.ClaimBindings)

	if err := normalized.validate(validateBindings); err != nil {
		return Contract{}, err
	}
	return normalized, nil
}

// Normalize returns a deep canonical copy of c.
func (c Contract) Normalize() (Contract, error) {
	return Normalize(c)
}

// Validate checks schema compatibility, canonical form, completeness, and the
// truthfulness rules for enforced and blocked contracts.
func (c Contract) Validate() error {
	return c.validate(true)
}

func (c Contract) validate(validateBindings bool) error {
	var reasons []string
	if c.SchemaVersion != ContractSchemaVersion {
		reasons = append(reasons, fmt.Sprintf("schema_version=%d, want %d", c.SchemaVersion, ContractSchemaVersion))
	}

	missing := validateMissingDimensions(&reasons, c.MissingDimensions)
	switch c.State {
	case ContractStateEnforced:
		if len(c.MissingDimensions) != 0 {
			reasons = append(reasons, "enforced contract must not list missing dimensions")
		}
	case ContractStateBlocked:
		if len(c.MissingDimensions) == 0 {
			reasons = append(reasons, "blocked contract must list at least one missing dimension with a reason")
		}
	default:
		reasons = append(reasons, fmt.Sprintf("unsupported contract state %q", c.State))
	}

	validateTextDimension(&reasons, ContractDimensionPurpose, c.Purpose, missing)
	validateTextDimension(&reasons, ContractDimensionEntrypoint, c.Entrypoint, missing)
	validateTopologyDimension(&reasons, c.Topology, missing)
	roleSet := makeRoleSet(c.Topology.Roles)
	validateCapabilitiesDimension(&reasons, c.RoleCapabilities, roleSet, missing)
	validateProfileDimension(&reasons, ContractDimensionPayload, "payload", c.Payload, c.State, missing)
	validateProfileDimension(&reasons, ContractDimensionLoad, "load", c.Load, c.State, missing)
	validateSeedDimension(&reasons, c.Seed, missing)
	validateEvidenceDimension(&reasons, ContractDimensionStimulus, "stimulus", c.Stimulus, missing)
	validateEvidenceDimension(&reasons, ContractDimensionOracle, "oracle", c.Oracle, missing)
	validateNegativeControlDimension(&reasons, c.NegativeControl, c.State, missing)
	validateResourceDimension(&reasons, c.Resources, roleSet, c.State, missing)

	if dimensionMissing(missing, ContractDimensionTopology) {
		if !dimensionMissing(missing, ContractDimensionRoleCapabilities) {
			reasons = append(reasons, "role_capabilities must also be missing when topology is missing")
		}
		if !dimensionMissing(missing, ContractDimensionResources) {
			reasons = append(reasons, "resources must also be missing when topology is missing")
		}
	}
	if validateBindings {
		validateClaimEvidenceBindings(&reasons, c, missing)
	}
	return errors.Join(stringErrors(reasons)...)
}

// CanonicalDigest returns a schema-tagged SHA-256 identity for every semantic
// Spec field. Set and map insertion order do not affect the result. Requires
// order remains significant because it defines prerequisite execution order.
func (s Spec) CanonicalDigest() (string, error) {
	canonical := CloneSpec(s)
	if canonical.Contract != nil {
		normalized, err := Normalize(*canonical.Contract)
		if err != nil {
			return "", fmt.Errorf("manifest: case %q contract: %w", canonical.ID, err)
		}
		canonical.Contract = &normalized
	}
	if err := validateStandaloneSpec(canonical); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("manifest: encode case %q canonical digest: %w", canonical.ID, err)
	}
	sum := sha256.Sum256(encoded)
	return fmt.Sprintf("sha256:%x", sum[:]), nil
}

func validateStandaloneSpec(spec Spec) error {
	if spec.ID == "" {
		return errors.New("manifest: case has empty ID")
	}
	if spec.Tier == "" {
		return fmt.Errorf("manifest: case %q has empty tier", spec.ID)
	}
	if spec.Suite != SuiteNormal && spec.Suite != SuiteTUN {
		return fmt.Errorf("manifest: case %q has unsupported suite %q", spec.ID, spec.Suite)
	}
	if !spec.Mandatory {
		return fmt.Errorf("manifest: case %q is not mandatory", spec.ID)
	}
	if spec.Budget <= 0 {
		return fmt.Errorf("manifest: case %q has non-positive budget %s", spec.ID, spec.Budget)
	}
	seen := make(map[string]struct{}, len(spec.Requires))
	for _, requiredID := range spec.Requires {
		if requiredID == "" {
			return fmt.Errorf("manifest: case %q has an empty prerequisite", spec.ID)
		}
		if _, ok := seen[requiredID]; ok {
			return fmt.Errorf("manifest: case %q has duplicate prerequisite %q", spec.ID, requiredID)
		}
		seen[requiredID] = struct{}{}
	}
	if spec.Contract == nil {
		return nil
	}
	if err := spec.Contract.Validate(); err != nil {
		return fmt.Errorf("manifest: case %q has invalid contract: %w", spec.ID, err)
	}
	if spec.Contract.Resources.State == ResourceStateDefined && spec.Contract.Resources.Timeout != spec.Budget {
		return fmt.Errorf(
			"manifest: case %q contract timeout %s does not match legacy budget %s",
			spec.ID, spec.Contract.Resources.Timeout, spec.Budget,
		)
	}
	if spec.Contract.NegativeControl.Kind == NegativeControlCase && spec.Contract.NegativeControl.CaseID == spec.ID {
		return fmt.Errorf("manifest: case %q cannot name itself as its negative control", spec.ID)
	}
	return nil
}

func cloneContract(c Contract) Contract {
	clone := c
	clone.MissingDimensions = cloneMissingDimensions(c.MissingDimensions)
	clone.Topology.Roles = cloneStrings(c.Topology.Roles)
	if c.RoleCapabilities != nil {
		clone.RoleCapabilities = make(map[string][]string, len(c.RoleCapabilities))
		for role, capabilities := range c.RoleCapabilities {
			clone.RoleCapabilities[role] = cloneStrings(capabilities)
		}
	}
	clone.Payload.Params = cloneParams(c.Payload.Params)
	clone.Load.Params = cloneParams(c.Load.Params)
	if c.Seed.FixedSeed != nil {
		seed := *c.Seed.FixedSeed
		clone.Seed.FixedSeed = &seed
	}
	clone.Stimulus.RequiredFacts = cloneStrings(c.Stimulus.RequiredFacts)
	clone.Stimulus.Assertions = cloneEvidenceAssertions(c.Stimulus.Assertions)
	clone.Oracle.RequiredFacts = cloneStrings(c.Oracle.RequiredFacts)
	clone.Oracle.Assertions = cloneEvidenceAssertions(c.Oracle.Assertions)
	clone.ClaimBindings = cloneClaimEvidenceBindings(c.ClaimBindings)
	if c.Resources.Roles != nil {
		clone.Resources.Roles = make(map[string]RoleResourceBudget, len(c.Resources.Roles))
		for role, budget := range c.Resources.Roles {
			clone.Resources.Roles[role] = budget
		}
	}
	return clone
}

func equalContracts(a, b *Contract) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	canonicalA, err := Normalize(*a)
	if err != nil {
		return false
	}
	canonicalB, err := Normalize(*b)
	if err != nil {
		return false
	}
	encodedA, err := json.Marshal(canonicalA)
	if err != nil {
		return false
	}
	encodedB, err := json.Marshal(canonicalB)
	return err == nil && string(encodedA) == string(encodedB)
}

func normalizeStringMap(input map[string][]string, label string) (map[string][]string, error) {
	if input == nil {
		return nil, nil
	}
	keys := make([]string, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	output := make(map[string][]string, len(keys))
	for _, rawKey := range keys {
		key := strings.TrimSpace(rawKey)
		if _, exists := output[key]; exists {
			return nil, fmt.Errorf("%s %q is duplicated after normalization", label, key)
		}
		values := cloneStrings(input[rawKey])
		normalizeStrings(values)
		output[key] = values
	}
	return output, nil
}

func normalizeResourceMap(input map[string]RoleResourceBudget) (map[string]RoleResourceBudget, error) {
	if input == nil {
		return nil, nil
	}
	keys := make([]string, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	output := make(map[string]RoleResourceBudget, len(keys))
	for _, rawKey := range keys {
		key := strings.TrimSpace(rawKey)
		if _, exists := output[key]; exists {
			return nil, fmt.Errorf("resource role %q is duplicated after normalization", key)
		}
		output[key] = input[rawKey]
	}
	return output, nil
}

func normalizeProfile(profile *Profile) {
	profile.Applicability = Applicability(strings.TrimSpace(string(profile.Applicability)))
	profile.Name = strings.TrimSpace(profile.Name)
	for i := range profile.Params {
		profile.Params[i].Name = strings.TrimSpace(profile.Params[i].Name)
		profile.Params[i].Unit = BaseUnit(strings.TrimSpace(string(profile.Params[i].Unit)))
	}
	sort.Slice(profile.Params, func(i, j int) bool {
		if profile.Params[i].Name != profile.Params[j].Name {
			return profile.Params[i].Name < profile.Params[j].Name
		}
		if profile.Params[i].Unit != profile.Params[j].Unit {
			return profile.Params[i].Unit < profile.Params[j].Unit
		}
		return profile.Params[i].Value < profile.Params[j].Value
	})
}

func normalizeEvidenceProfile(profile *EvidenceProfile) {
	profile.Name = strings.TrimSpace(profile.Name)
	normalizeStrings(profile.RequiredFacts)
	for i := range profile.Assertions {
		normalizeEvidenceAssertion(&profile.Assertions[i])
	}
	sort.Slice(profile.Assertions, func(i, j int) bool {
		if profile.Assertions[i].Fact != profile.Assertions[j].Fact {
			return profile.Assertions[i].Fact < profile.Assertions[j].Fact
		}
		if profile.Assertions[i].Predicate != profile.Assertions[j].Predicate {
			return profile.Assertions[i].Predicate < profile.Assertions[j].Predicate
		}
		return profile.Assertions[i].Expected < profile.Assertions[j].Expected
	})
}

func normalizeEvidenceAssertion(assertion *EvidenceAssertion) {
	assertion.Fact = strings.TrimSpace(assertion.Fact)
	assertion.Predicate = EvidencePredicate(strings.TrimSpace(string(assertion.Predicate)))
	assertion.Expected = strings.TrimSpace(assertion.Expected)
}

func cloneEvidenceAssertions(assertions []EvidenceAssertion) []EvidenceAssertion {
	if assertions == nil {
		return nil
	}
	return append([]EvidenceAssertion(nil), assertions...)
}

func normalizeStrings(values []string) {
	for i := range values {
		values[i] = strings.TrimSpace(values[i])
	}
	sort.Strings(values)
}

func validateMissingDimensions(reasons *[]string, values []MissingDimension) map[ContractDimension]struct{} {
	missing := make(map[ContractDimension]struct{}, len(values))
	if !sort.SliceIsSorted(values, func(i, j int) bool {
		if values[i].Dimension != values[j].Dimension {
			return values[i].Dimension < values[j].Dimension
		}
		return values[i].Reason < values[j].Reason
	}) {
		*reasons = append(*reasons, "missing dimensions are not in canonical order")
	}
	for _, value := range values {
		if !validContractDimension(value.Dimension) {
			*reasons = append(*reasons, fmt.Sprintf("unsupported missing dimension %q", value.Dimension))
		}
		if _, exists := missing[value.Dimension]; exists {
			*reasons = append(*reasons, fmt.Sprintf("missing dimension %q is duplicated", value.Dimension))
		}
		missing[value.Dimension] = struct{}{}
		validateCanonicalText(reasons, fmt.Sprintf("missing dimension %q reason", value.Dimension), value.Reason)
	}
	return missing
}

func validateTextDimension(reasons *[]string, dimension ContractDimension, value string, missing map[ContractDimension]struct{}) {
	if dimensionMissing(missing, dimension) {
		if value != "" {
			*reasons = append(*reasons, fmt.Sprintf("missing dimension %q must not contain an asserted value", dimension))
		}
		return
	}
	validateCanonicalText(reasons, string(dimension), value)
}

func validateTopologyDimension(reasons *[]string, topology Topology, missing map[ContractDimension]struct{}) {
	if dimensionMissing(missing, ContractDimensionTopology) {
		if topology.Profile != "" || len(topology.Roles) != 0 || topology.Isolation != "" || topology.PathCount != 0 {
			*reasons = append(*reasons, "missing dimension \"topology\" must not contain asserted topology facts")
		}
		return
	}
	validateCanonicalText(reasons, "topology profile", topology.Profile)
	validateCanonicalText(reasons, "topology isolation", topology.Isolation)
	if topology.PathCount < 0 {
		*reasons = append(*reasons, "topology path_count must not be negative")
	}
	validateStringSet(reasons, "topology roles", topology.Roles, true)
}

func validateCapabilitiesDimension(reasons *[]string, capabilities map[string][]string, roleSet map[string]struct{}, missing map[ContractDimension]struct{}) {
	if dimensionMissing(missing, ContractDimensionRoleCapabilities) {
		if capabilities != nil {
			*reasons = append(*reasons, "missing dimension \"role_capabilities\" must use a nil capability map")
		}
		return
	}
	if capabilities == nil {
		*reasons = append(*reasons, "role capabilities are unspecified")
		return
	}
	roles := make([]string, 0, len(capabilities))
	for role := range capabilities {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	for _, role := range roles {
		validateCanonicalText(reasons, "role capability scope", role)
		if _, ok := roleSet[role]; !ok {
			*reasons = append(*reasons, fmt.Sprintf("role capabilities reference unknown topology role %q", role))
		}
		values := capabilities[role]
		if values == nil {
			*reasons = append(*reasons, fmt.Sprintf("role %q capabilities are unspecified; use an explicit empty list when none are required", role))
			continue
		}
		validateStringSet(reasons, fmt.Sprintf("role %q capabilities", role), values, false)
	}
	for role := range roleSet {
		if _, ok := capabilities[role]; !ok {
			*reasons = append(*reasons, fmt.Sprintf("topology role %q has no capability declaration", role))
		}
	}
}

func validateProfileDimension(reasons *[]string, dimension ContractDimension, label string, profile Profile, state ContractState, missing map[ContractDimension]struct{}) {
	isMissing := dimensionMissing(missing, dimension)
	if isMissing {
		if profile.Applicability != ApplicabilityUnfrozen {
			*reasons = append(*reasons, fmt.Sprintf("missing dimension %q must use unfrozen applicability", dimension))
		}
		validateEmptyProfile(reasons, label, profile)
		return
	}
	switch profile.Applicability {
	case ApplicabilityDefined:
		validateDefinedProfile(reasons, label, profile)
	case ApplicabilityNotApplicable:
		validateEmptyProfile(reasons, label, profile)
	case ApplicabilityUnfrozen:
		if state != ContractStateBlocked {
			*reasons = append(*reasons, fmt.Sprintf("%s profile may be unfrozen only on a blocked contract", label))
		} else {
			*reasons = append(*reasons, fmt.Sprintf("unfrozen %s profile must be listed as missing", label))
		}
		validateEmptyProfile(reasons, label, profile)
	default:
		*reasons = append(*reasons, fmt.Sprintf("unsupported %s applicability %q", label, profile.Applicability))
	}
}

func validateDefinedProfile(reasons *[]string, label string, profile Profile) {
	validateCanonicalText(reasons, label+" profile name", profile.Name)
	if profile.Version <= 0 {
		*reasons = append(*reasons, label+" profile version must be positive")
	}
	if len(profile.Params) == 0 {
		*reasons = append(*reasons, label+" profile params are missing")
	}
	if !sort.SliceIsSorted(profile.Params, func(i, j int) bool {
		if profile.Params[i].Name != profile.Params[j].Name {
			return profile.Params[i].Name < profile.Params[j].Name
		}
		if profile.Params[i].Unit != profile.Params[j].Unit {
			return profile.Params[i].Unit < profile.Params[j].Unit
		}
		return profile.Params[i].Value < profile.Params[j].Value
	}) {
		*reasons = append(*reasons, label+" profile params are not in canonical order")
	}
	seen := make(map[string]struct{}, len(profile.Params))
	for _, param := range profile.Params {
		validateCanonicalText(reasons, label+" profile param name", param.Name)
		if _, ok := seen[param.Name]; ok {
			*reasons = append(*reasons, fmt.Sprintf("%s profile param %q is duplicated", label, param.Name))
		}
		seen[param.Name] = struct{}{}
		if !validBaseUnit(param.Unit) {
			*reasons = append(*reasons, fmt.Sprintf("%s profile param %q has non-canonical base unit %q", label, param.Name, param.Unit))
		}
	}
}

func validateEmptyProfile(reasons *[]string, label string, profile Profile) {
	if profile.Name != "" || profile.Version != 0 || len(profile.Params) != 0 {
		*reasons = append(*reasons, fmt.Sprintf("%s profile with applicability %q must not contain profile fields", label, profile.Applicability))
	}
}

func validateSeedDimension(reasons *[]string, policy SeedPolicy, missing map[ContractDimension]struct{}) {
	if dimensionMissing(missing, ContractDimensionSeed) {
		if policy.Mode != "" || policy.FixedSeed != nil {
			*reasons = append(*reasons, "missing dimension \"seed\" must not contain a seed policy")
		}
		return
	}
	switch policy.Mode {
	case SeedModeNone:
		if policy.FixedSeed != nil {
			*reasons = append(*reasons, "seedless policy must not contain fixed_seed")
		}
	case SeedModeFixed:
		if policy.FixedSeed == nil {
			*reasons = append(*reasons, "fixed seed policy has no fixed_seed")
		}
	case SeedModeRandomRecorded:
		if policy.FixedSeed != nil {
			*reasons = append(*reasons, "random-recorded seed policy must not contain fixed_seed")
		}
	default:
		*reasons = append(*reasons, fmt.Sprintf("unsupported seed policy mode %q", policy.Mode))
	}
}

func validateEvidenceDimension(reasons *[]string, dimension ContractDimension, label string, profile EvidenceProfile, missing map[ContractDimension]struct{}) {
	if dimensionMissing(missing, dimension) {
		if profile.Name != "" || profile.Version != 0 || len(profile.RequiredFacts) != 0 || len(profile.Assertions) != 0 {
			*reasons = append(*reasons, fmt.Sprintf("missing dimension %q must not contain evidence facts", dimension))
		}
		return
	}
	validateCanonicalText(reasons, label+" evidence profile name", profile.Name)
	if profile.Version <= 0 {
		*reasons = append(*reasons, label+" evidence profile version must be positive")
	}
	if len(profile.RequiredFacts) == 0 && len(profile.Assertions) == 0 {
		*reasons = append(*reasons, label+" evidence requirements are missing")
	}
	validateStringSet(reasons, label+" required facts", profile.RequiredFacts, false)
	validateEvidenceAssertions(reasons, label, profile.Assertions)
	if len(profile.Assertions) == 0 {
		*reasons = append(*reasons, fmt.Sprintf("declared %s evidence requires at least one typed assertion", label))
	}
}

func validateEvidenceAssertions(reasons *[]string, label string, assertions []EvidenceAssertion) {
	seen := make(map[string]struct{}, len(assertions))
	for _, assertion := range assertions {
		validateCanonicalText(reasons, label+" assertion fact", assertion.Fact)
		key := assertion.Fact + "\x00" + string(assertion.Predicate)
		if _, ok := seen[key]; ok {
			*reasons = append(*reasons, fmt.Sprintf("%s assertion for fact %q and predicate %q is duplicated", label, assertion.Fact, assertion.Predicate))
		}
		seen[key] = struct{}{}
		switch assertion.Predicate {
		case EvidenceEquals:
			validateCanonicalText(reasons, label+" assertion expected value", assertion.Expected)
		case EvidenceUintEquals, EvidenceUintAtLeast, EvidenceUintAtMost:
			validateCanonicalText(reasons, label+" assertion expected value", assertion.Expected)
			if _, err := strconv.ParseUint(assertion.Expected, 10, 64); err != nil {
				*reasons = append(*reasons, fmt.Sprintf("%s assertion %q expected value %q is not uint64", label, assertion.Fact, assertion.Expected))
			}
		case EvidenceIntEquals:
			validateCanonicalText(reasons, label+" assertion expected value", assertion.Expected)
			if _, err := strconv.ParseInt(assertion.Expected, 10, 64); err != nil {
				*reasons = append(*reasons, fmt.Sprintf("%s assertion %q expected value %q is not int64", label, assertion.Fact, assertion.Expected))
			}
		case EvidenceInt:
			if assertion.Expected != "" {
				*reasons = append(*reasons, fmt.Sprintf("%s assertion %q predicate %q must not contain an expected value", label, assertion.Fact, assertion.Predicate))
			}
		case EvidenceFloatAtLeast, EvidenceFloatAtMost:
			validateCanonicalText(reasons, label+" assertion expected value", assertion.Expected)
			value, err := strconv.ParseFloat(assertion.Expected, 64)
			if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
				*reasons = append(*reasons, fmt.Sprintf("%s assertion %q expected value %q is not finite float64", label, assertion.Fact, assertion.Expected))
			}
		default:
			*reasons = append(*reasons, fmt.Sprintf("%s assertion %q has unsupported predicate %q", label, assertion.Fact, assertion.Predicate))
		}
	}
}

// EvaluateEvidenceAssertion checks one normalized assertion against a textual
// report value. Validation should run before execution; this function still
// fails closed on malformed expected values.
func EvaluateEvidenceAssertion(assertion EvidenceAssertion, actual string) error {
	if strings.TrimSpace(actual) == "" {
		return fmt.Errorf("fact %q is missing", assertion.Fact)
	}
	switch assertion.Predicate {
	case EvidenceEquals:
		if actual != assertion.Expected {
			return fmt.Errorf("fact %q = %q, want %q", assertion.Fact, actual, assertion.Expected)
		}
	case EvidenceUintEquals, EvidenceUintAtLeast, EvidenceUintAtMost:
		got, err := strconv.ParseUint(actual, 10, 64)
		if err != nil {
			return fmt.Errorf("fact %q value %q is not uint64", assertion.Fact, actual)
		}
		want, err := strconv.ParseUint(assertion.Expected, 10, 64)
		if err != nil {
			return fmt.Errorf("fact %q expected value %q is not uint64", assertion.Fact, assertion.Expected)
		}
		if assertion.Predicate == EvidenceUintEquals && got != want {
			return fmt.Errorf("fact %q = %d, want %d", assertion.Fact, got, want)
		}
		if assertion.Predicate == EvidenceUintAtLeast && got < want {
			return fmt.Errorf("fact %q = %d, want at least %d", assertion.Fact, got, want)
		}
		if assertion.Predicate == EvidenceUintAtMost && got > want {
			return fmt.Errorf("fact %q = %d, want at most %d", assertion.Fact, got, want)
		}
	case EvidenceIntEquals, EvidenceInt:
		got, err := strconv.ParseInt(actual, 10, 64)
		if err != nil {
			return fmt.Errorf("fact %q value %q is not int64", assertion.Fact, actual)
		}
		if assertion.Predicate == EvidenceIntEquals {
			want, err := strconv.ParseInt(assertion.Expected, 10, 64)
			if err != nil {
				return fmt.Errorf("fact %q expected value %q is not int64", assertion.Fact, assertion.Expected)
			}
			if got != want {
				return fmt.Errorf("fact %q = %d, want %d", assertion.Fact, got, want)
			}
		} else if assertion.Expected != "" {
			return fmt.Errorf("fact %q predicate %q must not contain an expected value", assertion.Fact, assertion.Predicate)
		}
	case EvidenceFloatAtLeast, EvidenceFloatAtMost:
		got, err := parseFiniteFloat(actual)
		if err != nil {
			return fmt.Errorf("fact %q value %q is not finite float64", assertion.Fact, actual)
		}
		want, err := parseFiniteFloat(assertion.Expected)
		if err != nil {
			return fmt.Errorf("fact %q expected value %q is not finite float64", assertion.Fact, assertion.Expected)
		}
		if assertion.Predicate == EvidenceFloatAtLeast && got < want {
			return fmt.Errorf("fact %q = %g, want at least %g", assertion.Fact, got, want)
		}
		if assertion.Predicate == EvidenceFloatAtMost && got > want {
			return fmt.Errorf("fact %q = %g, want at most %g", assertion.Fact, got, want)
		}
	default:
		return fmt.Errorf("fact %q has unsupported predicate %q", assertion.Fact, assertion.Predicate)
	}
	return nil
}

func parseFiniteFloat(value string) (float64, error) {
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) {
		return 0, errors.New("not a finite float64")
	}
	return parsed, nil
}

func validateNegativeControlDimension(reasons *[]string, control NegativeControl, state ContractState, missing map[ContractDimension]struct{}) {
	isMissing := dimensionMissing(missing, ContractDimensionNegativeControl)
	if isMissing && control.Kind != NegativeControlAbsent {
		*reasons = append(*reasons, "missing dimension \"negative_control\" must use absent control kind")
	}
	switch control.Kind {
	case NegativeControlCase:
		validateCanonicalText(reasons, "negative control case_id", control.CaseID)
		rejectUnexpectedControlFields(reasons, control, false, true, true)
	case NegativeControlEmbedded:
		validateCanonicalText(reasons, "negative control embedded_id", control.EmbeddedID)
		rejectUnexpectedControlFields(reasons, control, true, false, true)
	case NegativeControlAbsent:
		if state != ContractStateBlocked {
			*reasons = append(*reasons, "absent negative control is valid only on a blocked contract")
		}
		if !isMissing {
			*reasons = append(*reasons, "absent negative control must be listed as missing")
		}
		rejectUnexpectedControlFields(reasons, control, true, true, true)
	case NegativeControlNotApplicable:
		validateCanonicalText(reasons, "negative control not-applicable reason", control.Reason)
		rejectUnexpectedControlFields(reasons, control, true, true, false)
	default:
		*reasons = append(*reasons, fmt.Sprintf("unsupported negative control kind %q", control.Kind))
	}
}

func rejectUnexpectedControlFields(reasons *[]string, control NegativeControl, rejectCase, rejectEmbedded, rejectReason bool) {
	if rejectCase && control.CaseID != "" {
		*reasons = append(*reasons, fmt.Sprintf("negative control kind %q must not contain case_id", control.Kind))
	}
	if rejectEmbedded && control.EmbeddedID != "" {
		*reasons = append(*reasons, fmt.Sprintf("negative control kind %q must not contain embedded_id", control.Kind))
	}
	if rejectReason && control.Reason != "" {
		*reasons = append(*reasons, fmt.Sprintf("negative control kind %q must not contain reason", control.Kind))
	}
}

func validateResourceDimension(reasons *[]string, budget ResourceBudget, roleSet map[string]struct{}, state ContractState, missing map[ContractDimension]struct{}) {
	isMissing := dimensionMissing(missing, ContractDimensionResources)
	if isMissing {
		if budget.State != ResourceStateUnfrozen {
			*reasons = append(*reasons, "missing dimension \"resources\" must use unfrozen resource state")
		}
		if budget.Timeout != 0 || budget.Roles != nil || budget.Exclusivity != "" {
			*reasons = append(*reasons, "unfrozen resources must not contain fabricated budget values")
		}
		return
	}
	if budget.State == ResourceStateUnfrozen {
		if state != ContractStateBlocked {
			*reasons = append(*reasons, "resources may be unfrozen only on a blocked contract")
		} else {
			*reasons = append(*reasons, "unfrozen resources must be listed as missing")
		}
		return
	}
	if budget.State != ResourceStateDefined {
		*reasons = append(*reasons, fmt.Sprintf("unsupported resource state %q", budget.State))
		return
	}
	if budget.Timeout <= 0 {
		*reasons = append(*reasons, "resource timeout must be positive")
	}
	if budget.Roles == nil {
		*reasons = append(*reasons, "resource role budgets are unspecified")
	}
	for role, allocation := range budget.Roles {
		validateCanonicalText(reasons, "resource role", role)
		if _, ok := roleSet[role]; !ok {
			*reasons = append(*reasons, fmt.Sprintf("resource budget references unknown topology role %q", role))
		}
		if allocation.VCPUs <= 0 {
			*reasons = append(*reasons, fmt.Sprintf("resource role %q vCPUs must be positive", role))
		}
		if allocation.RAMBytes == 0 {
			*reasons = append(*reasons, fmt.Sprintf("resource role %q RAM bytes must be positive", role))
		}
		if allocation.DiskBytes == 0 {
			*reasons = append(*reasons, fmt.Sprintf("resource role %q disk bytes must be positive", role))
		}
	}
	for role := range roleSet {
		if _, ok := budget.Roles[role]; !ok {
			*reasons = append(*reasons, fmt.Sprintf("topology role %q has no resource budget", role))
		}
	}
	if budget.Exclusivity != ExclusivityShared && budget.Exclusivity != ExclusivityExclusive {
		*reasons = append(*reasons, fmt.Sprintf("unsupported resource exclusivity %q", budget.Exclusivity))
	}
}

func validateStringSet(reasons *[]string, label string, values []string, requireNonEmpty bool) {
	if requireNonEmpty && len(values) == 0 {
		*reasons = append(*reasons, label+" are missing")
	}
	if !sort.StringsAreSorted(values) {
		*reasons = append(*reasons, label+" are not in canonical order")
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		validateCanonicalText(reasons, label+" entry", value)
		if _, ok := seen[value]; ok {
			*reasons = append(*reasons, fmt.Sprintf("%s entry %q is duplicated", label, value))
		}
		seen[value] = struct{}{}
	}
}

func validateCanonicalText(reasons *[]string, label, value string) {
	if value == "" {
		*reasons = append(*reasons, label+" is missing")
		return
	}
	if value != strings.TrimSpace(value) {
		*reasons = append(*reasons, label+" is not canonical")
	}
	if isPlaceholder(value) {
		*reasons = append(*reasons, label+" is a placeholder, not an enforceable fact")
	}
}

func isPlaceholder(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "unknown", "unfrozen", "todo", "tbd", "placeholder", "missing", "unset", "n/a":
		return true
	default:
		return false
	}
}

func makeRoleSet(roles []string) map[string]struct{} {
	set := make(map[string]struct{}, len(roles))
	for _, role := range roles {
		set[role] = struct{}{}
	}
	return set
}

func dimensionMissing(missing map[ContractDimension]struct{}, dimension ContractDimension) bool {
	_, ok := missing[dimension]
	return ok
}

func validContractDimension(dimension ContractDimension) bool {
	switch dimension {
	case ContractDimensionPurpose, ContractDimensionEntrypoint, ContractDimensionTopology,
		ContractDimensionRoleCapabilities, ContractDimensionPayload, ContractDimensionLoad,
		ContractDimensionSeed, ContractDimensionStimulus, ContractDimensionOracle,
		ContractDimensionNegativeControl, ContractDimensionResources:
		return true
	default:
		return false
	}
}

func validBaseUnit(unit BaseUnit) bool {
	switch unit {
	case UnitCount, UnitBytes, UnitNanoseconds, UnitBitsPerSecond, UnitBytesPerSecond,
		UnitPacketsPerSecond, UnitOperationsPerSecond, UnitPartsPerMillion:
		return true
	default:
		return false
	}
}

func cloneMissingDimensions(values []MissingDimension) []MissingDimension {
	if values == nil {
		return nil
	}
	clone := make([]MissingDimension, len(values))
	copy(clone, values)
	return clone
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	clone := make([]string, len(values))
	copy(clone, values)
	return clone
}

func cloneParams(params []ProfileParam) []ProfileParam {
	if params == nil {
		return nil
	}
	clone := make([]ProfileParam, len(params))
	copy(clone, params)
	return clone
}

func stringErrors(reasons []string) []error {
	errs := make([]error, len(reasons))
	for i, reason := range reasons {
		errs[i] = errors.New(reason)
	}
	return errs
}
