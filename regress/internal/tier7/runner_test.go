package tier7

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/caseexec"
	"github.com/FrankoonG/rendr/regress/internal/manifest"
	"github.com/FrankoonG/rendr/regress/internal/report"
)

var orderedCaseIDs = []string{
	"T7.capability.local-probe",
	"T7.tun.open-smoke",
	"T7.tun.packet-io",
	"T7.config.invalid-mtu",
	"T7.l3.identity-smoke",
	"T7.l3.identity-wire",
	"T7.capability.peer-denied",
	"T7.capability.peer-advertise",
	"T7.router.per-flow-hook",
	"T7.router.per-flow-cache",
	"T7.session.request",
	"T7.session.start",
	"T7.session.manager",
	"T7.session.lifecycle",
	"T7.session.path-observe",
	"T7.router.flow-deny",
	"T7.flow.lifecycle-stats",
	"T7.flow.observe",
	"T7.selector.per-flow",
	"T7.peer-egress-hook",
	"T7.tcp.peer-egress",
	"T7.udp.identity-smoke",
	"T7.udp.rendr-relay",
	"T7.udp.migration",
	"T7.tcp.rendr-relay",
	"T7.tcp.migration",
	"T7.tcp.lifecycle-flags",
	"T7.l3.parse-error-skip",
	"T7.l3.fragment-boundary",
	"T7.l3.unsupported-protocol",
}

func TestSpecsOrdered(t *testing.T) {
	specs := Specs()
	assertRequiredSpecs(t, specs)
	if err := manifest.ValidateCensus(specs); err != nil {
		t.Fatal(err)
	}
	if got := specIDs(specs); !reflect.DeepEqual(got, orderedCaseIDs) {
		t.Fatalf("Specs IDs = %v, want %v", got, orderedCaseIDs)
	}
	for i, spec := range specs {
		if spec.Contract == nil {
			t.Fatalf("spec %q has nil contract", spec.ID)
		}
		if got, want := expectedTestCount(*spec.Contract), uint64(len(caseDefs[i].expected)); got != want {
			t.Fatalf("spec %q expected test count = %d, want %d", spec.ID, got, want)
		}
	}
	for _, spec := range specs {
		contract := spec.Contract
		for _, dimension := range []manifest.ContractDimension{
			manifest.ContractDimensionStimulus,
			manifest.ContractDimensionOracle,
			manifest.ContractDimensionNegativeControl,
			manifest.ContractDimensionResources,
		} {
			if !hasMissingDimension(*contract, dimension) {
				t.Fatalf("spec %q is not blocked on %q", spec.ID, dimension)
			}
		}
		if got := contract.NegativeControl; got.Kind != manifest.NegativeControlAbsent || got.CaseID != "" || got.EmbeddedID != "" || got.Reason != "" {
			t.Fatalf("spec %q negative control = %+v, want absent", spec.ID, got)
		}
		if !reflect.DeepEqual(contract.Stimulus, manifest.EvidenceProfile{}) || !reflect.DeepEqual(contract.Oracle, manifest.EvidenceProfile{}) {
			t.Fatalf("spec %q invents evidence not emitted by the exact-go-test aggregator: stimulus=%+v oracle=%+v", spec.ID, contract.Stimulus, contract.Oracle)
		}
	}
	localProbe := specs[indexOfSpec(t, specs, "T7.capability.local-probe")].Contract
	if localProbe.Topology.PathCount != 0 || !hasRole(localProbe.Topology.Roles, "kernel-tun") || !hasCapability(localProbe.RoleCapabilities, "go-test-process", "Linux") || !hasCapability(localProbe.RoleCapabilities, "kernel-tun", "local /dev/net/tun open and TUNSETIFF probe target") {
		t.Fatalf("local probe does not describe its real kernel TUN probe: topology=%+v capabilities=%+v", localProbe.Topology, localProbe.RoleCapabilities)
	}
	for _, id := range []string{"T7.tun.open-smoke", "T7.tun.packet-io"} {
		if got := specs[indexOfSpec(t, specs, id)].Contract.Topology.PathCount; got != 0 {
			t.Fatalf("spec %q path count = %d, want 0 because it contains no rendr path", id, got)
		}
	}
	packetIO := specs[indexOfSpec(t, specs, "T7.tun.packet-io")].Contract
	if !hasCapability(packetIO.RoleCapabilities, "go-test-process", "CAP_NET_ADMIN") {
		t.Fatalf("packet I/O capabilities omit CAP_NET_ADMIN: %+v", packetIO.RoleCapabilities)
	}

	originalRequires := caseDefs[1].spec.Requires
	caseDefs[1].spec.Requires = []string{caseDefs[0].spec.ID}
	t.Cleanup(func() { caseDefs[1].spec.Requires = originalRequires })
	copied := Specs()
	copied[1].Requires[0] = "mutated"
	if got, want := caseDefs[1].spec.Requires[0], caseDefs[0].spec.ID; got != want {
		t.Fatalf("Specs result mutated caseDefs prerequisite to %q, want %q", got, want)
	}
	copied[2].Contract.MissingDimensions[0].Reason = "mutated"
	copied[2].Contract.Topology.Roles[0] = "mutated"
	copied[2].Contract.RoleCapabilities["go-test-process"] = []string{"mutated"}
	copied[2].Contract.Load.Params[0].Value++
	fresh := Specs()[2].Contract
	if fresh.MissingDimensions[0].Reason == "mutated" || fresh.Topology.Roles[0] == "mutated" ||
		!reflect.DeepEqual(fresh.RoleCapabilities["go-test-process"], specs[2].Contract.RoleCapabilities["go-test-process"]) || fresh.Load.Params[0].Value != 1 {
		t.Fatalf("Specs result aliases nested contract state: %+v", fresh)
	}
}

func TestSelectCaseDefs(t *testing.T) {
	t.Run("exact", func(t *testing.T) {
		defs, err := selectCaseDefs(Options{Case: orderedCaseIDs[5]})
		if err != nil {
			t.Fatal(err)
		}
		if got := defIDs(defs); !reflect.DeepEqual(got, orderedCaseIDs[5:6]) {
			t.Fatalf("selected IDs = %v, want %v", got, orderedCaseIDs[5:6])
		}
	})

	t.Run("inclusive resume", func(t *testing.T) {
		defs, err := selectCaseDefs(Options{FromCase: orderedCaseIDs[26]})
		if err != nil {
			t.Fatal(err)
		}
		if got := defIDs(defs); !reflect.DeepEqual(got, orderedCaseIDs[26:]) {
			t.Fatalf("selected IDs = %v, want %v", got, orderedCaseIDs[26:])
		}
	})

	t.Run("missing", func(t *testing.T) {
		if _, err := selectCaseDefs(Options{Case: "T7.missing"}); err == nil {
			t.Fatal("missing exact filter succeeded")
		}
		if _, err := selectCaseDefs(Options{FromCase: "T7.missing"}); err == nil {
			t.Fatal("missing resume filter succeeded")
		}
	})

	t.Run("prerequisite expansion", func(t *testing.T) {
		prerequisite := manifest.RequiredWithBudget("synthetic-prerequisite", "T7", time.Second)
		resume := manifest.RequiredWithBudget("synthetic-resume", "T7", time.Second)
		resume.Requires = []string{prerequisite.ID}
		target := manifest.RequiredWithBudget("synthetic-target", "T7", time.Second)
		target.Requires = []string{prerequisite.ID}
		registry := []caseDef{{spec: prerequisite}, {spec: resume}, {spec: target}}

		defs, err := selectCaseDefsFrom(registry, Options{Case: target.ID})
		if err != nil {
			t.Fatal(err)
		}
		if got, want := defIDs(defs), []string{prerequisite.ID, target.ID}; !reflect.DeepEqual(got, want) {
			t.Fatalf("exact IDs = %v, want %v", got, want)
		}

		defs, err = selectCaseDefsFrom(registry, Options{FromCase: resume.ID})
		if err != nil {
			t.Fatal(err)
		}
		if got, want := defIDs(defs), []string{prerequisite.ID, resume.ID, target.ID}; !reflect.DeepEqual(got, want) {
			t.Fatalf("resume IDs = %v, want %v", got, want)
		}
	})
}

func TestRunCaseDefsFailFastKeepsManifestRows(t *testing.T) {
	defs := []caseDef{
		{spec: manifest.RequiredWithBudget("first", "T7", time.Second)},
		{spec: manifest.RequiredWithBudget("second", "T7", time.Second)},
		{spec: manifest.RequiredWithBudget("third", "T7", time.Second)},
	}
	tests := []struct {
		name string
		row  report.Case
	}{
		{name: "failure", row: report.Case{Failure: "boom"}},
		{name: "invalid", row: report.Case{InvalidReason: "bad evidence"}},
		{name: "mandatory skip", row: report.Case{SkipReason: "missing capability"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			suite := report.New()
			runCaseDefs(context.Background(), suite, "", defs, func(_ context.Context, _ string, def caseDef) caseexec.Outcome {
				calls++
				if calls > 1 {
					t.Fatal("later executor was invoked")
				}
				rc := tc.row
				rc.Name = def.spec.ID
				rc.Tier = def.spec.Tier
				rc.Evidence = map[string]string{"cleanup": "preserved"}
				return caseexec.Outcome{Case: rc}
			})

			if calls != 1 {
				t.Fatalf("executor calls = %d, want 1", calls)
			}
			if got := reportCaseNames(suite.Cases); !reflect.DeepEqual(got, []string{"first", "second", "third"}) {
				t.Fatalf("report rows = %v", got)
			}
			if suite.Cases[0].Evidence["cleanup"] != "preserved" {
				t.Fatalf("failing row lost evidence: %+v", suite.Cases[0])
			}
			if got := suite.Cases[0]; got.ExecutionState != report.ExecutionStateExecuted || got.BlockedByCaseID != "" {
				t.Fatalf("executed failing row state = %q blocked by %q", got.ExecutionState, got.BlockedByCaseID)
			}
			for _, rc := range suite.Cases[1:] {
				if rc.Tier != "T7" || rc.ExecutionState != report.ExecutionStateNotRun || rc.BlockedByCaseID != "first" ||
					rc.InvalidReason != "not run after first failed" || rc.Failure != "" || rc.SkipReason != "" {
					t.Fatalf("not-run row = %+v", rc)
				}
			}
		})
	}
}

func TestRunCaseDefsStopsAfterUnsafeOutcome(t *testing.T) {
	defs := []caseDef{
		{spec: manifest.Spec{ID: "first", Tier: "T7"}},
		{spec: manifest.RequiredWithBudget("second", "T7", time.Second)},
	}
	calls := 0
	suite := report.New()
	runCaseDefs(context.Background(), suite, "", defs, func(_ context.Context, _ string, def caseDef) caseexec.Outcome {
		calls++
		return caseexec.Outcome{
			Case:     report.Case{Name: def.spec.ID, Tier: def.spec.Tier, InvalidReason: "process exit required"},
			MustStop: true,
		}
	})
	if calls != 1 {
		t.Fatalf("executor calls = %d, want 1", calls)
	}
	if got := suite.Cases[0]; got.ExecutionState != report.ExecutionStateExecuted || got.BlockedByCaseID != "" {
		t.Fatalf("executed stopping row state = %q blocked by %q", got.ExecutionState, got.BlockedByCaseID)
	}
	if got := suite.Cases[1]; got.ExecutionState != report.ExecutionStateNotRun || got.BlockedByCaseID != "first" ||
		got.InvalidReason != "not run after first failed" {
		t.Fatalf("next case result = %+v", got)
	}
}

func specIDs(specs []manifest.Spec) []string {
	ids := make([]string, len(specs))
	for i, spec := range specs {
		ids[i] = spec.ID
	}
	return ids
}

func assertRequiredSpecs(t *testing.T, specs []manifest.Spec) {
	t.Helper()
	if err := manifest.Validate(specs); err != nil {
		t.Fatal(err)
	}
	for _, spec := range specs {
		if !spec.Mandatory || spec.Suite != manifest.SuiteNormal || spec.Budget <= 0 {
			t.Fatalf("invalid required spec: %+v", spec)
		}
	}
}

func defIDs(defs []caseDef) []string {
	ids := make([]string, len(defs))
	for i, def := range defs {
		ids[i] = def.spec.ID
	}
	return ids
}

func reportCaseNames(cases []report.Case) []string {
	names := make([]string, len(cases))
	for i, rc := range cases {
		names[i] = rc.Name
	}
	return names
}

func expectedTestCount(contract manifest.Contract) uint64 {
	for _, param := range contract.Load.Params {
		if param.Name == "expected_top_level_tests" {
			return param.Value
		}
	}
	return 0
}

func hasMissingDimension(contract manifest.Contract, dimension manifest.ContractDimension) bool {
	for _, missing := range contract.MissingDimensions {
		if missing.Dimension == dimension {
			return true
		}
	}
	return false
}

func hasRole(roles []string, want string) bool {
	for _, role := range roles {
		if role == want {
			return true
		}
	}
	return false
}

func hasCapability(capabilities map[string][]string, role, want string) bool {
	for _, capability := range capabilities[role] {
		if capability == want {
			return true
		}
	}
	return false
}

func indexOfSpec(t *testing.T, specs []manifest.Spec, id string) int {
	t.Helper()
	for i, spec := range specs {
		if spec.ID == id {
			return i
		}
	}
	t.Fatalf("missing spec %q", id)
	return -1
}
