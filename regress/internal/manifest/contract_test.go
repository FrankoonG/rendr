package manifest

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	testRAMBytes  = 2 * 1024 * 1024 * 1024
	testDiskBytes = 8 * 1024 * 1024 * 1024
)

func TestNewCompleteSpecNormalizesWithoutInventingClaims(t *testing.T) {
	base := RequiredWithBudget("case.complete", "T2", 30*time.Second)
	input := completeContractInput(base.Budget)
	original := cloneContract(input)

	spec, err := NewCompleteSpec(base, input)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Contract == nil || spec.Contract.State != ContractStateEnforced {
		t.Fatalf("contract=%+v", spec.Contract)
	}
	if got, want := spec.Contract.Topology.Roles, []string{"client", "server"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("roles=%v want %v", got, want)
	}
	if got, want := spec.Contract.RoleCapabilities["client"], []string{"net-admin", "packet-capture"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("client capabilities=%v want %v", got, want)
	}
	if got, want := profileParamNames(spec.Contract.Payload), []string{"chunk_bytes", "payload_bytes"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("payload params=%v want %v", got, want)
	}
	if spec.Contract.Purpose != "prove lossless migration" || spec.Contract.Entrypoint != "internal/smoke.RunMigration" {
		t.Fatalf("text was not canonicalized: purpose=%q entrypoint=%q", spec.Contract.Purpose, spec.Contract.Entrypoint)
	}
	if !reflect.DeepEqual(input, original) {
		t.Fatal("NewCompleteSpec mutated its input contract")
	}
	if base.Contract != nil {
		t.Fatal("NewCompleteSpec mutated its input Spec")
	}
	if _, err := NewCompleteSpec(spec, input); err == nil || !strings.Contains(err.Error(), "already has a contract") {
		t.Fatalf("replacing an existing contract err=%v", err)
	}
}

func TestNormalizeRejectsDuplicateSetClaims(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Contract)
		want   string
	}{
		{name: "missing dimension", mutate: func(c *Contract) {
			makeBlocked(c, ContractDimensionPayload)
			c.MissingDimensions = append(c.MissingDimensions, MissingDimension{Dimension: ContractDimensionPayload, Reason: "second reason"})
		}, want: "missing dimension \"payload\" is duplicated"},
		{name: "topology role", mutate: func(c *Contract) {
			c.Topology.Roles = append(c.Topology.Roles, "client")
		}, want: "topology roles entry \"client\" is duplicated"},
		{name: "role after trimming", mutate: func(c *Contract) {
			c.RoleCapabilities[" client "] = []string{}
		}, want: "scope \"client\" is duplicated"},
		{name: "capability", mutate: func(c *Contract) {
			c.RoleCapabilities["client"] = append(c.RoleCapabilities["client"], "net-admin")
		}, want: "capabilities entry \"net-admin\" is duplicated"},
		{name: "resource role after trimming", mutate: func(c *Contract) {
			c.Resources.Roles[" client "] = RoleResourceBudget{VCPUs: 1, RAMBytes: 1, DiskBytes: 1}
		}, want: "resource role \"client\" is duplicated"},
		{name: "payload param", mutate: func(c *Contract) {
			c.Payload.Params = append(c.Payload.Params, ProfileParam{Name: "payload_bytes", Value: 2, Unit: UnitBytes})
		}, want: "payload profile param \"payload_bytes\" is duplicated"},
		{name: "evidence fact", mutate: func(c *Contract) {
			c.Stimulus.RequiredFacts = append(c.Stimulus.RequiredFacts, "path_changed")
		}, want: "stimulus required facts entry \"path_changed\" is duplicated"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contract := completeContractInput(30 * time.Second)
			tt.mutate(&contract)
			_, err := Normalize(contract)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Normalize() err=%v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestContractValidateRejectsIncompleteOrNonCanonicalClaims(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Contract)
		want   string
	}{
		{name: "schema", mutate: func(c *Contract) { c.SchemaVersion = 1 }, want: "schema_version"},
		{name: "state", mutate: func(c *Contract) { c.State = "" }, want: "unsupported contract state"},
		{name: "purpose", mutate: func(c *Contract) { c.Purpose = "" }, want: "purpose is missing"},
		{name: "placeholder", mutate: func(c *Contract) { c.Purpose = "TBD" }, want: "placeholder"},
		{name: "entrypoint", mutate: func(c *Contract) { c.Entrypoint = "" }, want: "entrypoint is missing"},
		{name: "topology profile", mutate: func(c *Contract) { c.Topology.Profile = "" }, want: "topology profile is missing"},
		{name: "topology roles", mutate: func(c *Contract) { c.Topology.Roles = nil }, want: "topology roles are missing"},
		{name: "negative path count", mutate: func(c *Contract) { c.Topology.PathCount = -1 }, want: "must not be negative"},
		{name: "role capabilities", mutate: func(c *Contract) { delete(c.RoleCapabilities, "server") }, want: "server\" has no capability declaration"},
		{name: "payload applicability", mutate: func(c *Contract) { c.Payload.Applicability = "" }, want: "unsupported payload applicability"},
		{name: "payload params", mutate: func(c *Contract) { c.Payload.Params = nil }, want: "payload profile params are missing"},
		{name: "seed mode", mutate: func(c *Contract) { c.Seed.Mode = "" }, want: "unsupported seed policy"},
		{name: "stimulus facts", mutate: func(c *Contract) { c.Stimulus.RequiredFacts = nil }, want: "stimulus required facts are missing"},
		{name: "control kind", mutate: func(c *Contract) { c.NegativeControl.Kind = "" }, want: "unsupported negative control"},
		{name: "resource state", mutate: func(c *Contract) { c.Resources.State = "" }, want: "unsupported resource state"},
		{name: "resource role", mutate: func(c *Contract) { delete(c.Resources.Roles, "server") }, want: "server\" has no resource budget"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contract := normalizedContract(t, 30*time.Second)
			tt.mutate(&contract)
			err := contract.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() err=%v, want substring %q", err, tt.want)
			}
		})
	}

	t.Run("enforced completeness", testEnforcedContractRequiresEveryDimension)
	t.Run("blocked truthfulness", testBlockedContractTruthfulness)
	t.Run("applicability and seed modes", testProfileApplicabilityAndSeedModes)
	t.Run("negative controls", testNegativeControlKindsAndRegistryReferences)
	t.Run("zero path topology", testZeroPathTopologyIsFactual)
}

func testEnforcedContractRequiresEveryDimension(t *testing.T) {
	dimensions := []ContractDimension{
		ContractDimensionPurpose,
		ContractDimensionEntrypoint,
		ContractDimensionTopology,
		ContractDimensionRoleCapabilities,
		ContractDimensionPayload,
		ContractDimensionLoad,
		ContractDimensionSeed,
		ContractDimensionStimulus,
		ContractDimensionOracle,
		ContractDimensionNegativeControl,
		ContractDimensionResources,
	}
	for _, dimension := range dimensions {
		t.Run(string(dimension), func(t *testing.T) {
			contract := normalizedContract(t, time.Second)
			clearDimension(&contract, dimension)
			if err := contract.Validate(); err == nil {
				t.Fatalf("enforced contract accepted missing %s", dimension)
			}
		})
	}
}

func testCensusAndReleaseValidation(t *testing.T) {
	legacy := RequiredWithBudget("legacy", "T2", time.Second)
	enforced := mustCompleteSpec(t, "enforced", time.Second)
	blocked := RequiredWithBudget("blocked", "T2", time.Second)
	contract := blockedContractInput()
	var err error
	blocked, err = NewCompleteSpec(blocked, contract)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		validate func([]Spec) error
		specs    []Spec
		want     string
	}{
		{name: "incremental accepts legacy", validate: Validate, specs: []Spec{legacy}},
		{name: "census rejects legacy", validate: ValidateCensus, specs: []Spec{legacy}, want: "no contract for census"},
		{name: "census accepts enforced", validate: ValidateCensus, specs: []Spec{enforced}},
		{name: "census accepts blocked", validate: ValidateCensus, specs: []Spec{blocked}},
		{name: "release accepts enforced", validate: ValidateRelease, specs: []Spec{enforced}},
		{name: "release rejects blocked", validate: ValidateRelease, specs: []Spec{blocked}, want: "blocked contract"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.validate(tt.specs)
			if tt.want == "" && err != nil {
				t.Fatal(err)
			}
			if tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)) {
				t.Fatalf("err=%v want substring %q", err, tt.want)
			}
		})
	}
}

func testBlockedContractTruthfulness(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Contract)
		want   string
	}{
		{name: "no missing dimensions", mutate: func(c *Contract) { c.MissingDimensions = nil }, want: "must list at least one"},
		{name: "empty reason", mutate: func(c *Contract) { c.MissingDimensions[0].Reason = "" }, want: "reason is missing"},
		{name: "unknown dimension", mutate: func(c *Contract) { c.MissingDimensions[0].Dimension = "mystery" }, want: "unsupported missing dimension"},
		{name: "missing payload claims defined facts", mutate: func(c *Contract) {
			c.Payload = normalizedContract(t, time.Second).Payload
		}, want: "must use unfrozen applicability"},
		{name: "unfrozen payload not listed", mutate: func(c *Contract) {
			c.MissingDimensions = c.MissingDimensions[1:]
		}, want: "must be listed as missing"},
		{name: "absent control not listed", mutate: func(c *Contract) {
			c.MissingDimensions = append(c.MissingDimensions[:1], c.MissingDimensions[2:]...)
		}, want: "absent negative control must be listed as missing"},
		{name: "resource values fabricated", mutate: func(c *Contract) {
			c.Resources.Timeout = time.Second
		}, want: "must not contain fabricated budget values"},
		{name: "missing purpose asserted", mutate: func(c *Contract) {
			c.MissingDimensions = append(c.MissingDimensions, MissingDimension{Dimension: ContractDimensionPurpose, Reason: "purpose audit pending"})
		}, want: "must not contain an asserted value"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contract := blockedContractInput()
			tt.mutate(&contract)
			_, err := Normalize(contract)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Normalize() err=%v want substring %q", err, tt.want)
			}
		})
	}

	enforced := completeContractInput(time.Second)
	enforced.MissingDimensions = []MissingDimension{{Dimension: ContractDimensionPayload, Reason: "profile audit pending"}}
	if _, err := Normalize(enforced); err == nil || !strings.Contains(err.Error(), "enforced contract must not list") {
		t.Fatalf("enforced missing-dimension err=%v", err)
	}
}

func testProfileApplicabilityAndSeedModes(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Contract)
		valid  bool
		want   string
	}{
		{name: "defined", mutate: func(*Contract) {}, valid: true},
		{name: "payload not applicable", mutate: func(c *Contract) {
			c.Payload = Profile{Applicability: ApplicabilityNotApplicable}
		}, valid: true},
		{name: "load not applicable", mutate: func(c *Contract) {
			c.Load = Profile{Applicability: ApplicabilityNotApplicable}
		}, valid: true},
		{name: "seed none", mutate: func(c *Contract) {
			c.Seed = SeedPolicy{Mode: SeedModeNone}
		}, valid: true},
		{name: "not applicable with profile fields", mutate: func(c *Contract) {
			c.Payload.Applicability = ApplicabilityNotApplicable
		}, want: "must not contain profile fields"},
		{name: "unfrozen enforced", mutate: func(c *Contract) {
			c.Payload = Profile{Applicability: ApplicabilityUnfrozen}
		}, want: "only on a blocked contract"},
		{name: "seed none with value", mutate: func(c *Contract) {
			c.Seed.Mode = SeedModeNone
		}, want: "seedless policy must not contain"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contract := completeContractInput(time.Second)
			tt.mutate(&contract)
			_, err := Normalize(contract)
			if tt.valid && err != nil {
				t.Fatal(err)
			}
			if !tt.valid && (err == nil || !strings.Contains(err.Error(), tt.want)) {
				t.Fatalf("err=%v want substring %q", err, tt.want)
			}
		})
	}
}

func testNegativeControlKindsAndRegistryReferences(t *testing.T) {
	tests := []struct {
		name    string
		control NegativeControl
		valid   bool
		want    string
	}{
		{name: "case", control: NegativeControl{Kind: NegativeControlCase, CaseID: "control"}, valid: true},
		{name: "embedded", control: NegativeControl{Kind: NegativeControlEmbedded, EmbeddedID: "no-stimulus"}, valid: true},
		{name: "not applicable", control: NegativeControl{Kind: NegativeControlNotApplicable, Reason: "static compile check has no treatment"}, valid: true},
		{name: "case missing id", control: NegativeControl{Kind: NegativeControlCase}, want: "case_id is missing"},
		{name: "case with embedded id", control: NegativeControl{Kind: NegativeControlCase, CaseID: "control", EmbeddedID: "extra"}, want: "must not contain embedded_id"},
		{name: "embedded missing id", control: NegativeControl{Kind: NegativeControlEmbedded}, want: "embedded_id is missing"},
		{name: "not applicable missing reason", control: NegativeControl{Kind: NegativeControlNotApplicable}, want: "reason is missing"},
		{name: "absent enforced", control: NegativeControl{Kind: NegativeControlAbsent}, want: "only on a blocked contract"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contract := completeContractInput(time.Second)
			contract.NegativeControl = tt.control
			_, err := Normalize(contract)
			if tt.valid && err != nil {
				t.Fatal(err)
			}
			if !tt.valid && (err == nil || !strings.Contains(err.Error(), tt.want)) {
				t.Fatalf("err=%v want substring %q", err, tt.want)
			}
		})
	}

	control := mustCompleteSpec(t, "control", time.Second)
	treatment := mustCompleteSpec(t, "treatment", time.Second)
	treatment.Contract.NegativeControl = NegativeControl{Kind: NegativeControlCase, CaseID: control.ID}
	if err := ValidateCensus([]Spec{control, treatment}); err != nil {
		t.Fatal(err)
	}
	treatment.Contract.NegativeControl.CaseID = "invented"
	if err := ValidateCensus([]Spec{control, treatment}); err == nil || !strings.Contains(err.Error(), "unknown case") {
		t.Fatalf("unknown control err=%v", err)
	}
}

func testZeroPathTopologyIsFactual(t *testing.T) {
	contract := completeContractInput(time.Second)
	contract.Topology.Profile = "in-process-unit"
	contract.Topology.Isolation = "process"
	contract.Topology.PathCount = 0
	contract.Payload = Profile{Applicability: ApplicabilityNotApplicable}
	contract.Load = Profile{Applicability: ApplicabilityNotApplicable}
	contract.Seed = SeedPolicy{Mode: SeedModeNone}
	contract.NegativeControl = NegativeControl{Kind: NegativeControlNotApplicable, Reason: "static validation has no treatment"}
	if _, err := Normalize(contract); err != nil {
		t.Fatalf("factual no-network contract rejected: %v", err)
	}
}

func TestLegacySpecRemainsValidAndDigestibleWithoutContract(t *testing.T) {
	legacy := RequiredWithBudget("legacy", "T1", time.Second)
	if err := Validate([]Spec{legacy}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateCensus([]Spec{legacy}); err == nil {
		t.Fatal("census accepted an uncontracted legacy spec")
	}
	digest, err := legacy.CanonicalDigest()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(digest, "sha256:") || len(digest) != len("sha256:")+64 {
		t.Fatalf("legacy digest=%q", digest)
	}
}

func TestNewCompleteSpecRejectsCrossFieldIncompleteness(t *testing.T) {
	base := RequiredWithBudget("case.complete", "T2", 30*time.Second)
	contract := normalizedContract(t, base.Budget)
	contract.Resources.Timeout++
	if _, err := NewCompleteSpec(base, contract); err == nil || !strings.Contains(err.Error(), "does not match legacy budget") {
		t.Fatalf("budget mismatch err=%v", err)
	}

	contract = normalizedContract(t, base.Budget)
	contract.NegativeControl = NegativeControl{Kind: NegativeControlCase, CaseID: base.ID}
	if _, err := NewCompleteSpec(base, contract); err == nil || !strings.Contains(err.Error(), "cannot name itself") {
		t.Fatalf("self negative-control err=%v", err)
	}

	partial := base
	partial.Contract = &Contract{SchemaVersion: ContractSchemaVersion, State: ContractStateEnforced}
	if err := Validate([]Spec{partial}); err == nil || !strings.Contains(err.Error(), "invalid contract") {
		t.Fatalf("legacy registry accepted a partial non-nil contract: %v", err)
	}
}

func testCloneSpecAndCloneSpecsAreDeep(t *testing.T) {
	original := mustCompleteSpec(t, "clone", time.Second)
	original.Requires = []string{"first", "second"}
	original.Contract.State = ContractStateBlocked
	original.Contract.MissingDimensions = []MissingDimension{{Dimension: ContractDimensionEntrypoint, Reason: "entrypoint audit pending"}}
	original.Contract.Entrypoint = ""

	clones := []Spec{CloneSpec(original), CloneSpecs([]Spec{original})[0]}
	for i := range clones {
		clone := &clones[i]
		clone.Requires[0] = "changed"
		clone.Contract.MissingDimensions[0].Reason = "changed"
		clone.Contract.Topology.Roles[0] = "changed"
		clone.Contract.RoleCapabilities["client"][0] = "changed"
		clone.Contract.RoleCapabilities["new"] = []string{"changed"}
		clone.Contract.Payload.Params[0].Name = "changed"
		clone.Contract.Load.Params[0].Name = "changed"
		*clone.Contract.Seed.FixedSeed = 99
		clone.Contract.Stimulus.RequiredFacts[0] = "changed"
		clone.Contract.Oracle.RequiredFacts[0] = "changed"
		allocation := clone.Contract.Resources.Roles["client"]
		allocation.VCPUs = 99
		clone.Contract.Resources.Roles["client"] = allocation
	}
	if original.Requires[0] != "first" || original.Contract.MissingDimensions[0].Reason != "entrypoint audit pending" ||
		original.Contract.Topology.Roles[0] != "client" || original.Contract.RoleCapabilities["client"][0] != "net-admin" ||
		original.Contract.RoleCapabilities["new"] != nil || original.Contract.Payload.Params[0].Name != "chunk_bytes" ||
		original.Contract.Load.Params[0].Name != "duration_ns" || *original.Contract.Seed.FixedSeed != 42 ||
		original.Contract.Stimulus.RequiredFacts[0] != "path_changed" || original.Contract.Oracle.RequiredFacts[0] != "application_errors_zero" ||
		original.Contract.Resources.Roles["client"].VCPUs != 2 {
		t.Fatal("deep clone mutation reached original spec")
	}
	if CloneSpecs(nil) != nil {
		t.Fatal("CloneSpecs(nil) did not preserve nil")
	}
}

func TestSpecCanonicalDigestStableAcrossSetAndMapOrder(t *testing.T) {
	base := mustCompleteSpec(t, "case.digest", 30*time.Second)
	base.Requires = []string{"setup-a", "setup-b"}
	want := mustDigest(t, base)

	reordered := CloneSpec(base)
	reverseStrings(reordered.Contract.Topology.Roles)
	reverseStrings(reordered.Contract.RoleCapabilities["client"])
	reverseParams(reordered.Contract.Payload.Params)
	reverseParams(reordered.Contract.Load.Params)
	reverseStrings(reordered.Contract.Stimulus.RequiredFacts)
	reverseStrings(reordered.Contract.Oracle.RequiredFacts)
	reordered.Contract.RoleCapabilities = map[string][]string{
		"server": reordered.Contract.RoleCapabilities["server"],
		"client": reordered.Contract.RoleCapabilities["client"],
	}
	reordered.Contract.Resources.Roles = map[string]RoleResourceBudget{
		"server": reordered.Contract.Resources.Roles["server"],
		"client": reordered.Contract.Resources.Roles["client"],
	}
	if got := mustDigest(t, reordered); got != want {
		t.Fatalf("set/map order changed digest: got %q want %q", got, want)
	}

	blocked := blockedContractInput()
	reverseMissing(blocked.MissingDimensions)
	spec, err := NewCompleteSpec(RequiredWithBudget("blocked.digest", "T2", time.Second), blocked)
	if err != nil {
		t.Fatal(err)
	}
	canonical := mustDigest(t, spec)
	reverseMissing(spec.Contract.MissingDimensions)
	if got := mustDigest(t, spec); got != canonical {
		t.Fatalf("missing-dimension order changed digest: got %q want %q", got, canonical)
	}
}

func TestSpecCanonicalDigestBindsEverySemanticDimension(t *testing.T) {
	base := mustCompleteSpec(t, "case.digest", 30*time.Second)
	base.Requires = []string{"setup-a", "setup-b"}
	want := mustDigest(t, base)
	tests := []struct {
		name   string
		mutate func(*Spec)
	}{
		{name: "id", mutate: func(s *Spec) { s.ID = "case.other" }},
		{name: "tier", mutate: func(s *Spec) { s.Tier = "T3" }},
		{name: "suite", mutate: func(s *Spec) { s.Suite = SuiteTUN }},
		{name: "requires value", mutate: func(s *Spec) { s.Requires[1] = "setup-c" }},
		{name: "requires sequence", mutate: func(s *Spec) { reverseStrings(s.Requires) }},
		{name: "long", mutate: func(s *Spec) { s.Long = !s.Long }},
		{name: "state missing reason", mutate: func(s *Spec) {
			s.Contract.State = ContractStateBlocked
			s.Contract.MissingDimensions = []MissingDimension{{Dimension: ContractDimensionEntrypoint, Reason: "entrypoint audit pending"}}
			s.Contract.Entrypoint = ""
		}},
		{name: "missing reason", mutate: func(s *Spec) {
			s.Contract.State = ContractStateBlocked
			s.Contract.MissingDimensions = []MissingDimension{{Dimension: ContractDimensionEntrypoint, Reason: "different reason"}}
			s.Contract.Entrypoint = ""
		}},
		{name: "purpose", mutate: func(s *Spec) { s.Contract.Purpose += " under path death" }},
		{name: "entrypoint", mutate: func(s *Spec) { s.Contract.Entrypoint += "V2" }},
		{name: "topology", mutate: func(s *Spec) { s.Contract.Topology.PathCount++ }},
		{name: "capabilities", mutate: func(s *Spec) {
			s.Contract.RoleCapabilities["client"] = append(s.Contract.RoleCapabilities["client"], "clock-sync")
		}},
		{name: "payload", mutate: func(s *Spec) { s.Contract.Payload.Params[0].Value++ }},
		{name: "load", mutate: func(s *Spec) { s.Contract.Load.Params[0].Value++ }},
		{name: "seed", mutate: func(s *Spec) { *s.Contract.Seed.FixedSeed++ }},
		{name: "stimulus", mutate: func(s *Spec) { s.Contract.Stimulus.RequiredFacts[0] += "_v2" }},
		{name: "oracle", mutate: func(s *Spec) { s.Contract.Oracle.RequiredFacts[0] += "_v2" }},
		{name: "control", mutate: func(s *Spec) { s.Contract.NegativeControl.EmbeddedID += "-v2" }},
		{name: "resource timeout", mutate: func(s *Spec) { s.Budget++; s.Contract.Resources.Timeout++ }},
		{name: "resource role", mutate: func(s *Spec) {
			allocation := s.Contract.Resources.Roles["client"]
			allocation.VCPUs++
			s.Contract.Resources.Roles["client"] = allocation
		}},
		{name: "resource exclusivity", mutate: func(s *Spec) { s.Contract.Resources.Exclusivity = ExclusivityExclusive }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changed := CloneSpec(base)
			tt.mutate(&changed)
			if got := mustDigest(t, changed); got == want {
				t.Fatalf("semantic mutation did not change digest %q", got)
			}
		})
	}

	blocked := CloneSpec(base)
	blocked.Contract.State = ContractStateBlocked
	blocked.Contract.MissingDimensions = []MissingDimension{{Dimension: ContractDimensionEntrypoint, Reason: "entrypoint audit pending"}}
	blocked.Contract.Entrypoint = ""
	blockedDigest := mustDigest(t, blocked)
	blocked.Contract.MissingDimensions[0].Reason = "entrypoint owner has not confirmed invocation"
	if got := mustDigest(t, blocked); got == blockedDigest {
		t.Fatalf("reason-only mutation did not change digest %q", got)
	}

	differentDimension := CloneSpec(base)
	differentDimension.Contract.State = ContractStateBlocked
	differentDimension.Contract.MissingDimensions = []MissingDimension{{Dimension: ContractDimensionPurpose, Reason: "purpose audit pending"}}
	differentDimension.Contract.Purpose = ""
	if got := mustDigest(t, differentDimension); got == blockedDigest {
		t.Fatalf("missing-dimension mutation did not change digest %q", got)
	}
}

func TestCompleteSpecsPreserveExactCaseAndInclusiveFromCaseSelection(t *testing.T) {
	registry := []Spec{
		mustCompleteSpec(t, "A", time.Second),
		mustCompleteSpec(t, "B", time.Second),
		mustCompleteSpec(t, "C", time.Second),
	}
	registry[1].Requires = []string{"A"}
	registry[2].Requires = []string{"B"}
	if err := ValidateRelease(registry); err != nil {
		t.Fatal(err)
	}
	exact, err := Select(registry, "B", "")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := specIDs(exact), []string{"B"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("--case selection=%v want %v", got, want)
	}
	resumed, err := Select(registry, "", "B")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := specIDs(resumed), []string{"B", "C"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("--from-case selection=%v want %v", got, want)
	}
	exact[0].Contract.RoleCapabilities["client"][0] = "mutated"
	if registry[1].Contract.RoleCapabilities["client"][0] == "mutated" {
		t.Fatal("selection result aliases canonical contract metadata")
	}

	t.Run("exported cloning is deep", testCloneSpecAndCloneSpecsAreDeep)
}

func TestMixedLegacyAndCompleteRegistrySupportsIncrementalMigration(t *testing.T) {
	legacy := RequiredWithBudget("legacy", "T2", time.Second)
	complete := mustCompleteSpec(t, "complete", time.Second)
	complete.Requires = []string{legacy.ID}
	registry := []Spec{legacy, complete}
	if err := Validate(registry); err != nil {
		t.Fatal(err)
	}
	if err := ValidateCensus(registry); err == nil || !strings.Contains(err.Error(), "no contract for census") {
		t.Fatalf("mixed registry census err=%v", err)
	}

	exact, err := Select(registry, complete.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := specIDs(exact), []string{complete.ID}; !reflect.DeepEqual(got, want) {
		t.Fatalf("mixed --case selection=%v want %v", got, want)
	}
	resumed, err := Select(registry, "", legacy.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := specIDs(resumed), []string{legacy.ID, complete.ID}; !reflect.DeepEqual(got, want) {
		t.Fatalf("mixed --from-case selection=%v want %v", got, want)
	}

	t.Run("census versus release", testCensusAndReleaseValidation)
}

func completeContractInput(timeout time.Duration) Contract {
	seed := int64(42)
	return Contract{
		SchemaVersion: ContractSchemaVersion,
		State:         ContractStateEnforced,
		Purpose:       "  prove lossless migration  ",
		Entrypoint:    " internal/smoke.RunMigration ",
		Topology: Topology{
			Profile:   " dual-path ",
			Roles:     []string{" server ", " client "},
			Isolation: " network-namespace ",
			PathCount: 2,
		},
		RoleCapabilities: map[string][]string{
			"server": {},
			"client": {" packet-capture ", " net-admin "},
		},
		Payload: Profile{
			Applicability: ApplicabilityDefined,
			Name:          " file-stream ",
			Version:       1,
			Params: []ProfileParam{
				{Name: " payload_bytes ", Value: 1024 * 1024, Unit: UnitBytes},
				{Name: " chunk_bytes ", Value: 32 * 1024, Unit: UnitBytes},
			},
		},
		Load: Profile{
			Applicability: ApplicabilityDefined,
			Name:          " paced-stream ",
			Version:       1,
			Params: []ProfileParam{
				{Name: " offered_pps ", Value: 1000, Unit: UnitPacketsPerSecond},
				{Name: " duration_ns ", Value: uint64((10 * time.Second).Nanoseconds()), Unit: UnitNanoseconds},
			},
		},
		Seed: SeedPolicy{Mode: SeedModeFixed, FixedSeed: &seed},
		Stimulus: EvidenceProfile{
			Name:          " path-migration ",
			Version:       1,
			RequiredFacts: []string{" stimulus_timestamp_ns ", " path_changed "},
		},
		Oracle: EvidenceProfile{
			Name:          " lossless-stream ",
			Version:       1,
			RequiredFacts: []string{" sha256_match ", " application_errors_zero ", " delivered_bytes "},
		},
		NegativeControl: NegativeControl{Kind: NegativeControlEmbedded, EmbeddedID: " no-path-change "},
		Resources: ResourceBudget{
			State:   ResourceStateDefined,
			Timeout: timeout,
			Roles: map[string]RoleResourceBudget{
				"client": {VCPUs: 2, RAMBytes: testRAMBytes, DiskBytes: testDiskBytes},
				"server": {VCPUs: 2, RAMBytes: testRAMBytes, DiskBytes: testDiskBytes},
			},
			Exclusivity: ExclusivityShared,
		},
	}
}

func blockedContractInput() Contract {
	contract := completeContractInput(time.Second)
	makeBlocked(&contract, ContractDimensionPayload, ContractDimensionNegativeControl, ContractDimensionResources)
	return contract
}

func makeBlocked(contract *Contract, dimensions ...ContractDimension) {
	contract.State = ContractStateBlocked
	contract.MissingDimensions = nil
	for _, dimension := range dimensions {
		contract.MissingDimensions = append(contract.MissingDimensions, MissingDimension{
			Dimension: dimension,
			Reason:    string(dimension) + " audit pending",
		})
		switch dimension {
		case ContractDimensionPurpose:
			contract.Purpose = ""
		case ContractDimensionEntrypoint:
			contract.Entrypoint = ""
		case ContractDimensionTopology:
			contract.Topology = Topology{}
		case ContractDimensionRoleCapabilities:
			contract.RoleCapabilities = nil
		case ContractDimensionPayload:
			contract.Payload = Profile{Applicability: ApplicabilityUnfrozen}
		case ContractDimensionLoad:
			contract.Load = Profile{Applicability: ApplicabilityUnfrozen}
		case ContractDimensionSeed:
			contract.Seed = SeedPolicy{}
		case ContractDimensionStimulus:
			contract.Stimulus = EvidenceProfile{}
		case ContractDimensionOracle:
			contract.Oracle = EvidenceProfile{}
		case ContractDimensionNegativeControl:
			contract.NegativeControl = NegativeControl{Kind: NegativeControlAbsent}
		case ContractDimensionResources:
			contract.Resources = ResourceBudget{State: ResourceStateUnfrozen}
		}
	}
	if containsDimension(dimensions, ContractDimensionTopology) {
		if !containsDimension(dimensions, ContractDimensionRoleCapabilities) {
			contract.MissingDimensions = append(contract.MissingDimensions, MissingDimension{Dimension: ContractDimensionRoleCapabilities, Reason: "topology roles are unfrozen"})
			contract.RoleCapabilities = nil
		}
		if !containsDimension(dimensions, ContractDimensionResources) {
			contract.MissingDimensions = append(contract.MissingDimensions, MissingDimension{Dimension: ContractDimensionResources, Reason: "topology roles are unfrozen"})
			contract.Resources = ResourceBudget{State: ResourceStateUnfrozen}
		}
	}
}

func containsDimension(values []ContractDimension, want ContractDimension) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func clearDimension(contract *Contract, dimension ContractDimension) {
	switch dimension {
	case ContractDimensionPurpose:
		contract.Purpose = ""
	case ContractDimensionEntrypoint:
		contract.Entrypoint = ""
	case ContractDimensionTopology:
		contract.Topology = Topology{}
	case ContractDimensionRoleCapabilities:
		contract.RoleCapabilities = nil
	case ContractDimensionPayload:
		contract.Payload = Profile{Applicability: ApplicabilityUnfrozen}
	case ContractDimensionLoad:
		contract.Load = Profile{Applicability: ApplicabilityUnfrozen}
	case ContractDimensionSeed:
		contract.Seed = SeedPolicy{}
	case ContractDimensionStimulus:
		contract.Stimulus = EvidenceProfile{}
	case ContractDimensionOracle:
		contract.Oracle = EvidenceProfile{}
	case ContractDimensionNegativeControl:
		contract.NegativeControl = NegativeControl{Kind: NegativeControlAbsent}
	case ContractDimensionResources:
		contract.Resources = ResourceBudget{State: ResourceStateUnfrozen}
	}
}

func normalizedContract(t *testing.T, timeout time.Duration) Contract {
	t.Helper()
	contract, err := Normalize(completeContractInput(timeout))
	if err != nil {
		t.Fatal(err)
	}
	return contract
}

func mustCompleteSpec(t *testing.T, id string, timeout time.Duration) Spec {
	t.Helper()
	spec, err := NewCompleteSpec(RequiredWithBudget(id, "T2", timeout), completeContractInput(timeout))
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func mustDigest(t *testing.T, spec Spec) string {
	t.Helper()
	digest, err := spec.CanonicalDigest()
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func profileParamNames(profile Profile) []string {
	names := make([]string, len(profile.Params))
	for i, param := range profile.Params {
		names[i] = param.Name
	}
	return names
}

func reverseStrings(values []string) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}

func reverseParams(values []ProfileParam) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}

func reverseMissing(values []MissingDimension) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}
