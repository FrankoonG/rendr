package tier7

import (
	"context"
	"reflect"
	"testing"
	"time"

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
	if got := specIDs(specs); !reflect.DeepEqual(got, orderedCaseIDs) {
		t.Fatalf("Specs IDs = %v, want %v", got, orderedCaseIDs)
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
			runCaseDefs(context.Background(), suite, "", defs, func(_ context.Context, _ string, def caseDef) report.Case {
				calls++
				if calls > 1 {
					t.Fatal("later executor was invoked")
				}
				rc := tc.row
				rc.Name = def.spec.ID
				rc.Tier = def.spec.Tier
				rc.Evidence = map[string]string{"cleanup": "preserved"}
				return rc
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
			for _, rc := range suite.Cases[1:] {
				if rc.Tier != "T7" || rc.InvalidReason != "not run after first failed" || rc.Failure != "" || rc.SkipReason != "" {
					t.Fatalf("not-run row = %+v", rc)
				}
			}
		})
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
