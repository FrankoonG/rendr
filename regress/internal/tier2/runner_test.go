package tier2

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/manifest"
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

func TestAddRunPreservesInvalidSmokeOutcome(t *testing.T) {
	suite := report.New()
	addRun(context.Background(), suite, "invalid", "T2", time.Second, func(context.Context) smoke.Result {
		return smoke.Result{InvalidReason: "offered load below target"}
	})
	if got := suite.Cases[0]; got.InvalidReason != "offered load below target" || got.Failure != "" {
		t.Fatalf("case=%+v want invalid-only outcome", got)
	}
}

func TestAddRunCancelsAndJoinsWorkloadBeforeReporting(t *testing.T) {
	tests := []struct {
		name        string
		budget      time.Duration
		withCancel  bool
		wantFailure string
	}{
		{name: "deadline", budget: 5 * time.Millisecond, wantFailure: "exceeded T2 budget"},
		{name: "parent cancel", budget: time.Second, withCancel: true, wantFailure: "case canceled: context canceled"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			trigger := func() {}
			if tt.withCancel {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				trigger = cancel
				defer cancel()
			}

			suite := report.New()
			started := make(chan struct{})
			unwindStarted := make(chan struct{})
			allowUnwind := make(chan struct{})
			unwound := make(chan struct{})
			returned := make(chan struct{})
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(allowUnwind) }) }
			defer release()

			go func() {
				addRun(ctx, suite, "quiescence", "T2", tt.budget, func(ctx context.Context) smoke.Result {
					close(started)
					<-ctx.Done()
					close(unwindStarted)
					<-allowUnwind
					close(unwound)
					return smoke.Result{Detail: map[string]any{"late_success": true}}
				})
				close(returned)
			}()

			waitForSignal(t, started, "workload start")
			trigger()
			waitForSignal(t, unwindStarted, "cancellation")
			select {
			case <-returned:
				t.Fatal("addRun returned before the canceled workload unwound")
			case <-time.After(20 * time.Millisecond):
			}

			release()
			waitForSignal(t, returned, "addRun return after workload unwind")
			select {
			case <-unwound:
			default:
				t.Fatal("addRun returned without joining the workload")
			}
			if len(suite.Cases) != 1 {
				t.Fatalf("cases = %d, want 1", len(suite.Cases))
			}
			if got := suite.Cases[0].Failure; !strings.Contains(got, tt.wantFailure) {
				t.Fatalf("failure = %q, want %q despite late success", got, tt.wantFailure)
			}
		})
	}
}

func waitForSignal(t *testing.T, signal <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", name)
	}
}

func TestRunSelectedCasesStopsAfterMandatoryOutcome(t *testing.T) {
	tests := []struct {
		name    string
		outcome report.Case
	}{
		{name: "failure", outcome: report.Case{Failure: "boom"}},
		{name: "invalid", outcome: report.Case{InvalidReason: "stimulus missing"}},
		{name: "mandatory skip", outcome: report.Case{SkipReason: "dependency unavailable"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defs := syntheticCaseDefs("T2")
			var called []string
			suite := report.New()
			runSelectedCases(context.Background(), suite, defs, func(_ context.Context, def caseDef) report.Case {
				called = append(called, def.spec.ID)
				rc := report.Case{Name: def.spec.ID, Tier: def.spec.Tier}
				if def.spec.ID == "synthetic.blocker" {
					rc.Failure = tt.outcome.Failure
					rc.InvalidReason = tt.outcome.InvalidReason
					rc.SkipReason = tt.outcome.SkipReason
				}
				return rc
			})

			if want := []string{"synthetic.first", "synthetic.blocker"}; !reflect.DeepEqual(called, want) {
				t.Fatalf("executed cases = %v, want %v", called, want)
			}
			assertFailFastRows(t, suite.Cases, "T2")
		})
	}
}

func syntheticCaseDefs(tier string) []caseDef {
	ids := []string{"synthetic.first", "synthetic.blocker", "synthetic.after"}
	defs := make([]caseDef, len(ids))
	for i, id := range ids {
		defs[i].spec = manifest.RequiredWithBudget(id, tier, time.Second)
	}
	return defs
}

func assertFailFastRows(t *testing.T, cases []report.Case, tier string) {
	t.Helper()
	wantIDs := []string{"synthetic.first", "synthetic.blocker", "synthetic.after"}
	gotIDs := make([]string, len(cases))
	for i, rc := range cases {
		gotIDs[i] = rc.Name
		if rc.Tier != tier {
			t.Fatalf("row %d tier = %q, want %q", i, rc.Tier, tier)
		}
	}
	if !reflect.DeepEqual(gotIDs, wantIDs) {
		t.Fatalf("report IDs = %v, want %v", gotIDs, wantIDs)
	}
	if got := cases[2].InvalidReason; got != "not run after synthetic.blocker failed" {
		t.Fatalf("trailing row invalid reason = %q", got)
	}
}

func caseDefIDs(defs []caseDef) []string {
	ids := make([]string, len(defs))
	for i, def := range defs {
		ids[i] = def.spec.ID
	}
	return ids
}
