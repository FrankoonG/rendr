package tier2

import (
	"context"
	"reflect"
	"testing"

	"github.com/FrankoonG/rendr/regress/internal/report"
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

func caseDefIDs(defs []caseDef) []string {
	ids := make([]string, len(defs))
	for i, def := range defs {
		ids[i] = def.spec.ID
	}
	return ids
}
