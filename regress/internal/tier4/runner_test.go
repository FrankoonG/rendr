package tier4

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/chaos"
	"github.com/FrankoonG/rendr/regress/internal/manifest"
	"github.com/FrankoonG/rendr/regress/internal/report"
	"github.com/FrankoonG/rendr/regress/internal/smoke"
)

var orderedCaseIDs = []string{
	"G1-T4",
	"G1-T4-quic",
	"G2-T4",
	"G2-T4-race-tcp",
	"G2-T4-bond-tcp",
	"M11-udp-relay-T4",
	"M11-udp-relay-porthop-T4",
	"M11-wireguard-relay-T4",
	"M11-hysteria2-relay-T4",
	"G3-T4",
}

func TestRunReportsSelectionFailures(t *testing.T) {
	tests := []struct {
		name string
		opts Options
		want string
	}{
		{
			name: "missing",
			opts: Options{Case: "T4-missing"},
			want: `T4 case selection failed for case="T4-missing" from-case="": manifest: no case matched --case="T4-missing"`,
		},
		{
			name: "ambiguous",
			opts: Options{Case: orderedCaseIDs[0], FromCase: orderedCaseIDs[1]},
			want: `T4 case selection failed for case="G1-T4" from-case="G1-T4-quic": manifest: --case and --from-case are mutually exclusive`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := report.New()
			Run(context.Background(), suite, "", tt.opts)
			if len(suite.Cases) != 1 {
				t.Fatalf("reported cases = %v, want one selection failure", suite.Cases)
			}
			got := suite.Cases[0]
			if got.Name != "T4-case-filter" || got.Tier != "T4" || got.Failure != tt.want {
				t.Fatalf("selection failure = %+v, want T4-case-filter failure %q", got, tt.want)
			}
		})
	}
}

func TestSpecsOrdered(t *testing.T) {
	specs := Specs()
	if got := specIDs(specs); !reflect.DeepEqual(got, orderedCaseIDs) {
		t.Fatalf("Specs IDs = %v, want %v", got, orderedCaseIDs)
	}
	if err := manifest.Validate(specs); err != nil {
		t.Fatalf("Specs validation failed: %v", err)
	}
	wantBudgets := []time.Duration{
		7 * time.Minute, 7 * time.Minute,
		33 * time.Minute, 33 * time.Minute, 33 * time.Minute,
		5 * time.Minute, 5 * time.Minute, 5 * time.Minute, 5 * time.Minute,
		8 * time.Minute,
	}
	for i, spec := range specs {
		if !spec.Mandatory || spec.Suite != manifest.SuiteNormal || spec.Budget != wantBudgets[i] {
			t.Errorf("Specs()[%d] = %+v, want mandatory normal-suite budget %s", i, spec, wantBudgets[i])
		}
	}
	wantProfiles := []chaos.Profile{
		chaos.Realistic50M, chaos.Realistic50M, chaos.Realistic50M, chaos.Realistic50M, chaos.Realistic50M,
		{}, {}, {}, {}, {},
	}
	for i, def := range caseDefs {
		if !reflect.DeepEqual(def.profile, wantProfiles[i]) {
			t.Errorf("caseDefs[%d] profile = %+v, want %+v", i, def.profile, wantProfiles[i])
		}
	}
}

func TestSelectCaseDefs(t *testing.T) {
	tests := []struct {
		name    string
		opts    Options
		want    []string
		wantErr bool
	}{
		{name: "exact", opts: Options{Case: orderedCaseIDs[3]}, want: orderedCaseIDs[3:4]},
		{name: "inclusive resume", opts: Options{FromCase: orderedCaseIDs[7]}, want: orderedCaseIDs[7:]},
		{name: "missing exact", opts: Options{Case: "T4-missing"}, wantErr: true},
		{name: "missing resume", opts: Options{FromCase: "T4-missing"}, wantErr: true},
		{name: "ambiguous", opts: Options{Case: orderedCaseIDs[0], FromCase: orderedCaseIDs[1]}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defs, err := selectCaseDefs(tt.opts)
			if tt.wantErr {
				if err == nil {
					t.Fatal("selection succeeded, want error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := defIDs(defs); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("selected IDs = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestApplyCleanupResultFailsClosed(t *testing.T) {
	tests := []struct {
		name         string
		initial      report.Case
		wantFailure  string
		wantInvalid  string
		wantEvidence string
	}{
		{name: "passing case becomes invalid", wantInvalid: "chaos cleanup failed: cleanup boom"},
		{name: "product failure becomes untrusted", initial: report.Case{Failure: "case boom"}, wantInvalid: "chaos cleanup failed: cleanup boom", wantEvidence: "case boom"},
		{name: "existing invalidity is preserved", initial: report.Case{InvalidReason: "stimulus missing"}, wantInvalid: "stimulus missing; chaos cleanup failed: cleanup boom"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := tt.initial
			applyCleanupResult(&rc, func() error { return errors.New("cleanup boom") })
			if rc.Failure != tt.wantFailure || rc.InvalidReason != tt.wantInvalid {
				t.Fatalf("case=%+v want failure=%q invalid=%q", rc, tt.wantFailure, tt.wantInvalid)
			}
			if got := rc.Evidence["untrusted_case_failure"]; got != tt.wantEvidence {
				t.Fatalf("untrusted failure evidence=%q want %q", got, tt.wantEvidence)
			}
		})
	}

	t.Run("mid-run qdisc event invalidates a passing case", func(t *testing.T) {
		changes := make(chan error, 1)
		changes <- fmt.Errorf("%w: qdisc replaced", chaos.ErrStimulusInvalid)
		cleanupCalled := false
		fixture := &fakeChaosFixture{
			changes: changes,
			cleanup: func() error { cleanupCalled = true; return nil },
		}
		rc := runCaseWithChaosInterval(context.Background(), "event", time.Second, chaos.Realistic50M,
			func(ctx context.Context) smoke.Result {
				<-ctx.Done()
				return smoke.Result{}
			},
			func(chaos.Profile) (chaos.Fixture, error) { return fixture, nil }, time.Hour)
		if !cleanupCalled {
			t.Fatal("cleanup was not called after monitor invalidity")
		}
		if rc.Failure != "" || !strings.Contains(rc.InvalidReason, "qdisc replaced") {
			t.Fatalf("case=%+v, want qdisc event INVALID", rc)
		}
	})

	t.Run("periodic verification catches persistent replacement", func(t *testing.T) {
		var calls atomic.Int32
		fixture := &fakeChaosFixture{verify: func() error {
			if calls.Add(1) >= 1 {
				return fmt.Errorf("%w: fingerprint changed", chaos.ErrStimulusInvalid)
			}
			return nil
		}}
		rc := runCaseWithChaosInterval(context.Background(), "poll", time.Second, chaos.Realistic50M,
			func(ctx context.Context) smoke.Result {
				<-ctx.Done()
				return smoke.Result{}
			},
			func(chaos.Profile) (chaos.Fixture, error) { return fixture, nil }, time.Millisecond)
		if rc.Failure != "" || !strings.Contains(rc.InvalidReason, "fingerprint changed") {
			t.Fatalf("case=%+v, want periodic verification INVALID", rc)
		}
	})

	t.Run("final verification catches a last-moment replacement", func(t *testing.T) {
		fixture := &fakeChaosFixture{verify: func() error {
			return fmt.Errorf("%w: owned root absent", chaos.ErrStimulusInvalid)
		}}
		rc := runCaseWithChaosInterval(context.Background(), "final", time.Second, chaos.Realistic50M,
			func(context.Context) smoke.Result { return smoke.Result{Failure: "untrusted product failure"} },
			func(chaos.Profile) (chaos.Fixture, error) { return fixture, nil }, time.Hour)
		if rc.Failure != "" || !strings.Contains(rc.InvalidReason, "final verification failed") {
			t.Fatalf("case=%+v, want final verification INVALID", rc)
		}
		if got := rc.Evidence["untrusted_case_failure"]; got != "untrusted product failure" {
			t.Fatalf("untrusted failure evidence=%q", got)
		}
	})

	t.Run("fixture setup failure is invalid not product failure", func(t *testing.T) {
		rc := runCaseWithChaosInterval(context.Background(), "setup", time.Second, chaos.Realistic50M,
			func(context.Context) smoke.Result {
				t.Fatal("case ran after fixture setup failure")
				return smoke.Result{}
			},
			func(chaos.Profile) (chaos.Fixture, error) { return nil, errors.New("lock busy") }, time.Hour)
		if rc.Failure != "" || !strings.Contains(rc.InvalidReason, "lock busy") {
			t.Fatalf("case=%+v, want setup INVALID", rc)
		}
	})

	t.Run("budget expiry remains a case failure without monitor panic", func(t *testing.T) {
		fixture := &fakeChaosFixture{}
		rc := runCaseWithChaosInterval(context.Background(), "timeout", 2*time.Millisecond, chaos.Realistic50M,
			func(ctx context.Context) smoke.Result {
				<-ctx.Done()
				time.Sleep(10 * time.Millisecond)
				return smoke.Result{}
			},
			func(chaos.Profile) (chaos.Fixture, error) { return fixture, nil }, time.Hour)
		if !strings.Contains(rc.Failure, "case exceeded T4 budget") || rc.InvalidReason != "" {
			t.Fatalf("case=%+v, want timeout failure", rc)
		}
	})
}

func TestEvidenceFromDetailPreservesFacts(t *testing.T) {
	got := evidenceFromDetail(map[string]any{"migrations": 3, "sha_match": true})
	want := map[string]string{"migrations": "3", "sha_match": "true"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("evidence=%v want %v", got, want)
	}
	if evidenceFromDetail(nil) != nil {
		t.Fatal("nil detail should remain nil evidence")
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
			defs := syntheticCaseDefs("T4")
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
			assertFailFastRows(t, suite.Cases, "T4")
		})
	}
}

func TestCleanupCompletesBeforeFailFastDecision(t *testing.T) {
	defs := syntheticCaseDefs("T4")[:2]
	cleanupCalled := false
	runCalls := 0
	suite := report.New()
	runSelectedCases(context.Background(), suite, defs, func(ctx context.Context, def caseDef) report.Case {
		runCalls++
		return runCaseWithChaos(ctx, def.spec.ID, def.spec.Budget, chaos.Profile{}, func(context.Context) smoke.Result {
			return smoke.Result{}
		}, func(chaos.Profile) (chaos.Fixture, error) {
			return &fakeChaosFixture{cleanup: func() error {
				cleanupCalled = true
				return errors.New("cleanup boom")
			}}, nil
		})
	})

	if !cleanupCalled {
		t.Fatal("chaos cleanup was not called")
	}
	if runCalls != 1 {
		t.Fatalf("case runner calls = %d, want 1", runCalls)
	}
	if got := suite.Cases[0].InvalidReason; got != "chaos cleanup failed: cleanup boom" {
		t.Fatalf("first row invalid reason = %q", got)
	}
	if got := suite.Cases[1].InvalidReason; got != "not run after synthetic.first failed" {
		t.Fatalf("second row invalid reason = %q", got)
	}
}

type fakeChaosFixture struct {
	changes <-chan error
	verify  func() error
	cleanup func() error
}

func (f *fakeChaosFixture) Changes() <-chan error { return f.changes }

func (f *fakeChaosFixture) Verify() error {
	if f.verify == nil {
		return nil
	}
	return f.verify()
}

func (f *fakeChaosFixture) Cleanup() error {
	if f.cleanup == nil {
		return nil
	}
	return f.cleanup()
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

func specIDs(specs []manifest.Spec) []string {
	ids := make([]string, len(specs))
	for i, spec := range specs {
		ids[i] = spec.ID
	}
	return ids
}

func defIDs(defs []caseDef) []string {
	ids := make([]string, len(defs))
	for i, def := range defs {
		ids[i] = def.spec.ID
	}
	return ids
}
