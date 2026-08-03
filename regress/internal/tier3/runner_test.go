package tier3

import (
	"bytes"
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/FrankoonG/rendr/regress/internal/manifest"
	"github.com/FrankoonG/rendr/regress/internal/report"
)

func TestSpecsFreezeCurrentMatrix(t *testing.T) {
	specs := Specs()
	if len(specs) != 44 {
		t.Fatalf("len(Specs())=%d, want 44", len(specs))
	}

	var t3, tunT3 int
	for _, spec := range specs {
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

func TestBuildRunPatternIsAnchoredAndQuoted(t *testing.T) {
	specs := []manifest.Spec{manifest.Required("TestA[1]", "T3"), manifest.Required("TestB+", "T3")}
	pattern := buildRunPattern(specs)
	re := regexp.MustCompile(pattern)
	for _, name := range []string{"TestA[1]", "TestB+"} {
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

func TestBuildGoTestArgsUsesOnlySelectedNames(t *testing.T) {
	selected := []manifest.Spec{manifest.Required("TestOne", "T3"), manifest.Required("TestTwo", "T3")}
	got := buildGoTestArgs(selected)
	want := []string{
		"test", "-json", "-count=1", "-timeout", "6m",
		"-run", "^(?:TestOne|TestTwo)$", "./internal/matrix/...",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args=%#v, want %#v", got, want)
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
			selected, err := selectSpecs(tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			pattern := regexp.MustCompile(buildRunPattern(selected))
			selectedIDs := make(map[string]bool, len(selected))
			for _, spec := range selected {
				selectedIDs[spec.ID] = true
			}
			for _, spec := range all {
				if got, want := pattern.MatchString(spec.ID), selectedIDs[spec.ID]; got != want {
					t.Errorf("pattern selection for %q=%v, want %v", spec.ID, got, want)
				}
			}
		})
	}
}

func TestParseTestEventsUsesDefinitionOrder(t *testing.T) {
	selected := syntheticSpecs("TestFirst", "TestSecond")
	stream := eventStream(t,
		event{Action: "run", Test: "TestSecond"},
		event{Action: "pass", Test: "TestSecond", Elapsed: 0.2},
		event{Action: "run", Test: "TestFirst"},
		event{Action: "pass", Test: "TestFirst", Elapsed: 0.1},
	)

	cases, err := parseTestEvents(stream, selected)
	if err != nil {
		t.Fatal(err)
	}
	if got := caseNames(cases); !reflect.DeepEqual(got, []string{"TestFirst", "TestSecond"}) {
		t.Fatalf("report order=%v", got)
	}
	for _, c := range cases {
		if c.Failure != "" || c.SkipReason != "" {
			t.Fatalf("case %q unexpectedly non-pass: %+v", c.Name, c)
		}
	}
}

func TestParseTestEventsFailsAbsentSelectedTest(t *testing.T) {
	selected := syntheticSpecs("TestPresent", "TestAbsent")
	stream := eventStream(t,
		event{Action: "run", Test: "TestPresent"},
		event{Action: "pass", Test: "TestPresent"},
	)

	cases, err := parseTestEvents(stream, selected)
	if err != nil {
		t.Fatal(err)
	}
	if cases[1].Failure == "" || cases[1].SkipReason != "" {
		t.Fatalf("absent selected test did not fail: %+v", cases[1])
	}
}

func TestParseTestEventsFailsWithoutTerminalEvent(t *testing.T) {
	selected := syntheticSpecs("TestInterrupted")
	stream := eventStream(t,
		event{Action: "run", Test: "TestInterrupted"},
		event{Action: "output", Test: "TestInterrupted", Output: "partial output\n"},
	)

	cases, err := parseTestEvents(stream, selected)
	if err != nil {
		t.Fatal(err)
	}
	if cases[0].Failure == "" || !strings.Contains(cases[0].Failure, "no terminal") {
		t.Fatalf("unterminated selected test did not fail: %+v", cases[0])
	}
	if cases[0].SkipReason != "" {
		t.Fatalf("unterminated selected test was skipped: %+v", cases[0])
	}
}

func TestParseTestEventsFailsZeroTests(t *testing.T) {
	cases, err := parseTestEvents(strings.NewReader(""), syntheticSpecs("TestExpected"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 1 || cases[0].Failure == "" {
		t.Fatalf("zero-test stream did not fail: %+v", cases)
	}
	if cases[0].SkipReason != "" {
		t.Fatalf("zero-test stream was skipped: %+v", cases[0])
	}
}

func syntheticSpecs(ids ...string) []manifest.Spec {
	specs := make([]manifest.Spec, len(ids))
	for i, id := range ids {
		specs[i] = manifest.Required(id, "T3")
	}
	return specs
}

func eventStream(t *testing.T, events ...event) *bytes.Reader {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, ev := range events {
		if err := enc.Encode(ev); err != nil {
			t.Fatal(err)
		}
	}
	return bytes.NewReader(buf.Bytes())
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
	for i, c := range cases {
		names[i] = c.Name
	}
	return names
}
