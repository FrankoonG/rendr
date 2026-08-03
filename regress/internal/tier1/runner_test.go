package tier1

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/manifest"
	"github.com/FrankoonG/rendr/regress/internal/report"
)

var orderedCaseIDs = []string{
	"go-vet",
	"go-test",
	"regress-unit",
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

func TestRunCaseDefPreservesRecoveredFailure(t *testing.T) {
	attempts := 0
	def := caseDef{
		spec:    manifest.RequiredWithBudget("flaky", "T1", time.Second),
		retries: 2,
		fn: func(context.Context, string) error {
			attempts++
			if attempts == 1 {
				return errors.New("first failure")
			}
			return nil
		},
	}
	rc := runCaseDef(context.Background(), "", def)
	if rc.Failure != "" || !strings.Contains(rc.InvalidReason, "first failure") || attempts != 2 {
		t.Fatalf("case=%+v attempts=%d", rc, attempts)
	}
	suite := report.New()
	suite.Add(rc)
	if !suite.AnyFailed() {
		t.Fatal("a retry-recovered case must still fail the release gate")
	}
}

func TestRunCaseDefUsesOneBudgetAcrossRetries(t *testing.T) {
	attempts := 0
	def := caseDef{
		spec:    manifest.RequiredWithBudget("timeout", "T1", 10*time.Millisecond),
		retries: 3,
		fn: func(ctx context.Context, _ string) error {
			attempts++
			<-ctx.Done()
			return ctx.Err()
		},
	}
	rc := runCaseDef(context.Background(), "", def)
	if rc.Failure == "" || attempts != 1 {
		t.Fatalf("case=%+v attempts=%d, want one budget-bounded attempt", rc, attempts)
	}
}

func TestRunCaseDefCleanFirstPass(t *testing.T) {
	def := caseDef{
		spec:    manifest.RequiredWithBudget("clean", "T1", time.Second),
		retries: 2,
		fn:      func(context.Context, string) error { return nil },
	}
	rc := runCaseDef(context.Background(), "", def)
	if rc.Failure != "" || rc.InvalidReason != "" || rc.SkipReason != "" {
		t.Fatalf("clean first pass = %+v", rc)
	}
}

func TestFilterRegressUnitPackages(t *testing.T) {
	input := []string{
		"example/regress/cmd/regress",
		"example/regress/internal/matrix",
		"example/regress/internal/matrix/driver",
		"example/regress/internal/smoke",
		"example/regress/internal/xrayglue",
		"example/regress/internal/report",
	}
	want := []string{"example/regress/cmd/regress", "example/regress/internal/report"}
	if got := filterRegressUnitPackages(input); !reflect.DeepEqual(got, want) {
		t.Fatalf("packages=%v want %v", got, want)
	}
}

func caseDefIDs(defs []caseDef) []string {
	ids := make([]string, len(defs))
	for i, def := range defs {
		ids[i] = def.spec.ID
	}
	return ids
}
