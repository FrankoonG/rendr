package tier4

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/chaos"
	"github.com/FrankoonG/rendr/regress/internal/manifest"
	"github.com/FrankoonG/rendr/regress/internal/report"
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
		name        string
		initial     report.Case
		wantFailure string
		wantInvalid string
	}{
		{name: "passing case becomes invalid", wantInvalid: "chaos cleanup failed: cleanup boom"},
		{name: "failure retains both causes", initial: report.Case{Failure: "case boom"}, wantFailure: "case boom; chaos cleanup failed: cleanup boom"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := tt.initial
			applyCleanupResult(&rc, func() error { return errors.New("cleanup boom") })
			if rc.Failure != tt.wantFailure || rc.InvalidReason != tt.wantInvalid {
				t.Fatalf("case=%+v want failure=%q invalid=%q", rc, tt.wantFailure, tt.wantInvalid)
			}
		})
	}
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
