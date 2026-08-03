package tier3

import (
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/FrankoonG/rendr/regress/internal/gotestjson"
	"github.com/FrankoonG/rendr/regress/internal/manifest"
	"github.com/FrankoonG/rendr/regress/internal/report"
)

func TestSpecsFreezeCurrentMatrix(t *testing.T) {
	specs := Specs()
	if len(specs) != 44 {
		t.Fatalf("len(Specs())=%d, want 44", len(specs))
	}

	var t3, tunT3 int
	for i, spec := range specs {
		switch {
		case strings.HasPrefix(spec.ID, "TestTUNT3"):
			tunT3++
		case strings.HasPrefix(spec.ID, "TestT3"):
			t3++
		default:
			t.Fatalf("unexpected T3 spec ID %q", spec.ID)
		}
		if spec.Tier != "T3" {
			t.Fatalf("spec %q tier=%q, want T3", spec.ID, spec.Tier)
		}
		if spec.Suite != manifest.SuiteNormal || !spec.Mandatory || spec.Budget != matrixTestBudget {
			t.Fatalf("spec %q has invalid release metadata: %+v", spec.ID, spec)
		}
		if got := caseDefs[i].expected; !reflect.DeepEqual(got, []string{spec.ID}) {
			t.Fatalf("case %q expected tests=%v, want [%s]", spec.ID, got, spec.ID)
		}
	}
	if t3 != 30 || tunT3 != 14 {
		t.Fatalf("case families: TestT3=%d TestTUNT3=%d, want 30 and 14", t3, tunT3)
	}

	wantBoundaries := map[int]string{
		0:  "TestT3GlueAVMessOverRendrTransport",
		27: "TestTUNT3FreedomStreamOverTUN",
		40: "TestTUNT3PacketXrayBalancerUDPxUDPFlowOverTUN",
		41: "TestT3VlessVisionTLSxItself",
		43: "TestT3SS2022xVMess",
	}
	for i, want := range wantBoundaries {
		if got := specs[i].ID; got != want {
			t.Fatalf("Specs()[%d].ID=%q, want %q", i, got, want)
		}
	}

	specs[0].ID = "mutated"
	if got := Specs()[0].ID; got == "mutated" {
		t.Fatal("Specs exposed mutable package definitions")
	}
}

func TestSelectSpecs(t *testing.T) {
	all := Specs()

	t.Run("exact", func(t *testing.T) {
		selected, err := selectSpecs(Options{Case: all[12].ID})
		if err != nil {
			t.Fatal(err)
		}
		if got := specIDs(selected); !reflect.DeepEqual(got, []string{all[12].ID}) {
			t.Fatalf("selected=%v", got)
		}
	})

	t.Run("inclusive from-case", func(t *testing.T) {
		selected, err := selectSpecs(Options{FromCase: all[40].ID})
		if err != nil {
			t.Fatal(err)
		}
		if got, want := specIDs(selected), specIDs(all[40:]); !reflect.DeepEqual(got, want) {
			t.Fatalf("selected=%v, want %v", got, want)
		}
	})

	t.Run("missing", func(t *testing.T) {
		if _, err := selectSpecs(Options{Case: "TestT3Missing"}); err == nil {
			t.Fatal("missing exact case succeeded")
		}
		if _, err := selectSpecs(Options{FromCase: "TestT3Missing"}); err == nil {
			t.Fatal("missing from-case succeeded")
		}
	})
}

func TestExactTestPatternIsAnchoredAndQuoted(t *testing.T) {
	names := []string{"TestA[1]", "TestB+"}
	pattern := exactTestPattern(names)
	re := regexp.MustCompile(pattern)
	for _, name := range names {
		if !re.MatchString(name) {
			t.Errorf("pattern %q does not match selected %q", pattern, name)
		}
	}
	for _, name := range []string{"TestA1", "TestBB", "prefixTestB+", "TestB+/subtest"} {
		if re.MatchString(name) {
			t.Errorf("pattern %q unexpectedly matches %q", pattern, name)
		}
	}
}

func TestFilteredRunPatternMatchesOnlySelection(t *testing.T) {
	all := Specs()
	for _, tc := range []struct {
		name string
		opts Options
	}{
		{name: "exact", opts: Options{Case: all[17].ID}},
		{name: "inclusive from-case", opts: Options{FromCase: all[40].ID}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selected, err := selectCaseDefs(tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			pattern := regexp.MustCompile(exactTestPattern(expectedTestNames(selected)))
			selectedIDs := make(map[string]bool, len(selected))
			for _, def := range selected {
				selectedIDs[def.spec.ID] = true
			}
			for _, spec := range all {
				if got, want := pattern.MatchString(spec.ID), selectedIDs[spec.ID]; got != want {
					t.Errorf("pattern selection for %q=%v, want %v", spec.ID, got, want)
				}
			}
		})
	}
}

func TestGoTestReportCasesUseDefinitionOrder(t *testing.T) {
	defs := []caseDef{matrixCase("TestFirst"), matrixCase("TestSecond")}
	result := gotestjson.Result{Tests: []gotestjson.TestResult{
		{Name: "TestSecond", Status: gotestjson.StatusPassed},
		{Name: "TestFirst", Status: gotestjson.StatusPassed},
	}}

	cases := goTestReportCases(defs, result)
	if got := caseNames(cases); !reflect.DeepEqual(got, []string{"TestFirst", "TestSecond"}) {
		t.Fatalf("report order=%v", got)
	}
	for _, testCase := range cases {
		assertCasePasses(t, testCase)
	}
}

func TestGoTestReportCasesFailClosed(t *testing.T) {
	const name = "TestExpected"
	tests := []struct {
		name       string
		result     gotestjson.Result
		wantField  string
		wantDetail string
	}{
		{
			name: "zero tests",
			result: gotestjson.Result{
				Tests:  []gotestjson.TestResult{{Name: name, Status: gotestjson.StatusNotRun}},
				Issues: []gotestjson.Issue{{Code: gotestjson.IssueZeroTests, Detail: "no run events"}},
			},
			wantField: "invalid", wantDetail: string(gotestjson.IssueZeroTests),
		},
		{
			name: "malformed JSON",
			result: gotestjson.Result{
				Tests:  []gotestjson.TestResult{{Name: name, Status: gotestjson.StatusNotRun}},
				Issues: []gotestjson.Issue{{Code: gotestjson.IssueMalformedJSON, Detail: "truncated object"}},
			},
			wantField: "invalid", wantDetail: string(gotestjson.IssueMalformedJSON),
		},
		{
			name: "truncated capture",
			result: gotestjson.Result{
				Tests:            []gotestjson.TestResult{{Name: name, Status: gotestjson.StatusIncomplete}},
				CaptureTruncated: true,
				Issues:           []gotestjson.Issue{{Code: gotestjson.IssueCaptureLimit, Detail: "capture full"}},
			},
			wantField: "invalid", wantDetail: string(gotestjson.IssueCaptureLimit),
		},
		{
			name: "missing terminal event",
			result: gotestjson.Result{
				Tests:  []gotestjson.TestResult{{Name: name, Status: gotestjson.StatusIncomplete}},
				Issues: []gotestjson.Issue{{Code: gotestjson.IssueNoTerminal, Test: name}},
			},
			wantField: "invalid", wantDetail: string(gotestjson.IssueNoTerminal),
		},
		{
			name: "mandatory skip",
			result: gotestjson.Result{
				Tests:  []gotestjson.TestResult{{Name: name, Status: gotestjson.StatusSkipped}},
				Issues: []gotestjson.Issue{{Code: gotestjson.IssueMandatorySkip, Test: name}},
			},
			wantField: "skip", wantDetail: "mandatory top-level test",
		},
		{
			name: "unexpected test",
			result: gotestjson.Result{
				Tests:  []gotestjson.TestResult{{Name: name, Status: gotestjson.StatusPassed}},
				Issues: []gotestjson.Issue{{Code: gotestjson.IssueUnexpectedTest, Test: "TestOther"}},
			},
			wantField: "invalid", wantDetail: string(gotestjson.IssueUnexpectedTest),
		},
		{
			name: "command failure",
			result: gotestjson.Result{
				Tests:  []gotestjson.TestResult{{Name: name, Status: gotestjson.StatusNotRun}},
				Issues: []gotestjson.Issue{{Code: gotestjson.IssueCommandFailed, Detail: "exit status 2"}},
			},
			wantField: "invalid", wantDetail: string(gotestjson.IssueCommandFailed),
		},
		{
			name: "test failure",
			result: gotestjson.Result{
				Tests:  []gotestjson.TestResult{{Name: name, Status: gotestjson.StatusFailed, Output: "assertion failed\n"}},
				Issues: []gotestjson.Issue{{Code: gotestjson.IssueTestFailed, Test: name}},
			},
			wantField: "failure", wantDetail: "assertion failed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cases := goTestReportCases([]caseDef{matrixCase(name)}, tc.result)
			if len(cases) != 1 {
				t.Fatalf("len(cases)=%d, want 1", len(cases))
			}
			assertCaseField(t, cases[0], tc.wantField, tc.wantDetail)
		})
	}
}

func TestGoTestReportDiagnosticIsBounded(t *testing.T) {
	const name = "TestExpected"
	result := gotestjson.Result{
		Tests: []gotestjson.TestResult{{
			Name:   name,
			Status: gotestjson.StatusIncomplete,
			Output: strings.Repeat("x", 2*maxReportDiagnosticBytes),
		}},
		Issues: []gotestjson.Issue{{Code: gotestjson.IssueNoTerminal, Test: name}},
	}
	testCase := goTestReportCases([]caseDef{matrixCase(name)}, result)[0]
	if len(testCase.InvalidReason) > maxReportDiagnosticBytes {
		t.Fatalf("invalid diagnostic length=%d, max=%d", len(testCase.InvalidReason), maxReportDiagnosticBytes)
	}
	if !strings.Contains(testCase.InvalidReason, "diagnostic truncated") {
		t.Fatalf("bounded diagnostic lacks truncation marker: %q", testCase.InvalidReason)
	}
}

func specIDs(specs []manifest.Spec) []string {
	ids := make([]string, len(specs))
	for i, spec := range specs {
		ids[i] = spec.ID
	}
	return ids
}

func caseNames(cases []report.Case) []string {
	names := make([]string, len(cases))
	for i, testCase := range cases {
		names[i] = testCase.Name
	}
	return names
}

func assertCasePasses(t *testing.T, testCase report.Case) {
	t.Helper()
	if testCase.Failure != "" || testCase.InvalidReason != "" || testCase.SkipReason != "" {
		t.Fatalf("case unexpectedly did not pass: %+v", testCase)
	}
}

func assertCaseField(t *testing.T, testCase report.Case, field, detail string) {
	t.Helper()
	var got string
	switch field {
	case "failure":
		got = testCase.Failure
	case "invalid":
		got = testCase.InvalidReason
	case "skip":
		got = testCase.SkipReason
	default:
		t.Fatalf("unknown case field %q", field)
	}
	if got == "" || !strings.Contains(got, detail) {
		t.Fatalf("case field %s=%q, want detail %q; case=%+v", field, got, detail, testCase)
	}
	if testCase.Failure == "" && testCase.InvalidReason == "" && testCase.SkipReason == "" {
		t.Fatalf("case unexpectedly passed: %+v", testCase)
	}
}
