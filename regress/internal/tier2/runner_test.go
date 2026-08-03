package tier2

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/report"
	"github.com/FrankoonG/rendr/regress/internal/smoke"
)

var orderedCaseIDs = []string{
	"G1-smoke",
	"G1-mixed-tcp-quic-smoke",
	"G2-smoke",
	"G2-race-tcp-smoke",
	"G2-bond-tcp-smoke",
	"G3-smoke",
	"G4",
	"G5",
	"M11-udp-relay-smoke",
	"M11-udp-relay-porthop-smoke",
}

func TestSpecsOrder(t *testing.T) {
	got := make([]string, len(Specs()))
	for i, spec := range Specs() {
		got[i] = spec.ID
	}
	if !reflect.DeepEqual(got, orderedCaseIDs) {
		t.Fatalf("Specs IDs = %v, want %v", got, orderedCaseIDs)
	}
}

func TestSpecsHaveBoundedBudgets(t *testing.T) {
	for _, spec := range Specs() {
		if spec.Budget <= 0 {
			t.Errorf("spec %q budget = %s, want > 0", spec.ID, spec.Budget)
		}
	}
}

func TestCriticalSmokeMigrationRequests(t *testing.T) {
	if g1SmokeMigrations <= 0 {
		t.Fatalf("G1-smoke migrations = %d, want > 0", g1SmokeMigrations)
	}
	if g2SmokeMigrations <= 0 {
		t.Fatalf("G2/G2-bond smoke migrations = %d, want > 0", g2SmokeMigrations)
	}
	if g2RaceSmokeMigrations != -1 {
		t.Fatalf("G2-race smoke migrations = %d, want explicit disable sentinel", g2RaceSmokeMigrations)
	}
}

func TestSelectCaseDefsExact(t *testing.T) {
	defs, err := selectCaseDefs(Options{Case: orderedCaseIDs[3]})
	if err != nil {
		t.Fatal(err)
	}
	if got := caseDefIDs(defs); !reflect.DeepEqual(got, orderedCaseIDs[3:4]) {
		t.Fatalf("selected IDs = %v, want %v", got, orderedCaseIDs[3:4])
	}
}

func TestSelectCaseDefsInclusiveResume(t *testing.T) {
	defs, err := selectCaseDefs(Options{FromCase: orderedCaseIDs[7]})
	if err != nil {
		t.Fatal(err)
	}
	if got := caseDefIDs(defs); !reflect.DeepEqual(got, orderedCaseIDs[7:]) {
		t.Fatalf("selected IDs = %v, want %v", got, orderedCaseIDs[7:])
	}
}

func TestRunWithOptionsMissingFilter(t *testing.T) {
	suite := report.New()
	RunWithOptions(context.Background(), suite, "", Options{FromCase: "missing"})
	if len(suite.Cases) != 1 {
		t.Fatalf("cases = %d, want 1", len(suite.Cases))
	}
	got := suite.Cases[0]
	if got.Name != "T2-case-filter" || got.Tier != "T2" || got.Failure != `manifest: no case matched --from-case="missing"` {
		t.Fatalf("failure row = %+v", got)
	}
}

func TestAddRunPreservesSmokeEvidence(t *testing.T) {
	suite := report.New()
	addRun(context.Background(), suite, "evidence", "T2", time.Second, func(context.Context) smoke.Result {
		return smoke.Result{
			Detail: map[string]any{
				"requested_migrations": 3,
				"migrations_done":      uint64(3),
				"sha256_match":         true,
			},
		}
	})
	want := map[string]string{
		"requested_migrations": "3",
		"migrations_done":      "3",
		"sha256_match":         "true",
	}
	if got := suite.Cases[0].Evidence; !reflect.DeepEqual(got, want) {
		t.Fatalf("evidence = %#v, want %#v", got, want)
	}
}

func TestAddRunEnforcesBudget(t *testing.T) {
	suite := report.New()
	release := make(chan struct{})
	defer close(release)
	addRun(context.Background(), suite, "timeout", "T2", time.Millisecond, func(context.Context) smoke.Result {
		<-release
		return smoke.Result{}
	})
	if got := suite.Cases[0].Failure; !strings.Contains(got, "exceeded T2 budget") {
		t.Fatalf("failure = %q, want budget failure", got)
	}
}

func caseDefIDs(defs []caseDef) []string {
	ids := make([]string, len(defs))
	for i, def := range defs {
		ids[i] = def.spec.ID
	}
	return ids
}
