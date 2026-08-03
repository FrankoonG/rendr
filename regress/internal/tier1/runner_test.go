package tier1

import (
	"context"
	"reflect"
	"testing"

	"github.com/FrankoonG/rendr/regress/internal/report"
)

var orderedCaseIDs = []string{
	"go-vet",
	"go-test",
	"go-test-race",
	"go-bench-smoke",
	"const-proto-version",
	"const-udpflow-version",
	"const-migration-budget-90s",
	"const-mode-values",
	"const-mode-transition-table",
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

func TestSelectCaseDefsExact(t *testing.T) {
	defs, err := selectCaseDefs(Options{Case: orderedCaseIDs[2]})
	if err != nil {
		t.Fatal(err)
	}
	if got := caseDefIDs(defs); !reflect.DeepEqual(got, orderedCaseIDs[2:3]) {
		t.Fatalf("selected IDs = %v, want %v", got, orderedCaseIDs[2:3])
	}
}

func TestSelectCaseDefsInclusiveResume(t *testing.T) {
	defs, err := selectCaseDefs(Options{FromCase: orderedCaseIDs[6]})
	if err != nil {
		t.Fatal(err)
	}
	if got := caseDefIDs(defs); !reflect.DeepEqual(got, orderedCaseIDs[6:]) {
		t.Fatalf("selected IDs = %v, want %v", got, orderedCaseIDs[6:])
	}
}

func TestRunWithOptionsMissingFilter(t *testing.T) {
	suite := report.New()
	RunWithOptions(context.Background(), suite, "", Options{Case: "missing"})
	if len(suite.Cases) != 1 {
		t.Fatalf("cases = %d, want 1", len(suite.Cases))
	}
	got := suite.Cases[0]
	if got.Name != "T1-case-filter" || got.Tier != "T1" || got.Failure != `manifest: no case matched --case="missing"` {
		t.Fatalf("failure row = %+v", got)
	}
}

func caseDefIDs(defs []caseDef) []string {
	ids := make([]string, len(defs))
	for i, def := range defs {
		ids[i] = def.spec.ID
	}
	return ids
}
