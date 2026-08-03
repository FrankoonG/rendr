package tier1

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/FrankoonG/rendr/regress/internal/gotestjson"
)

func TestContractsHaveDeterministicNonzeroCoverage(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		contracts []packageContract
	}{
		{name: "root windows", contracts: rootTestContracts("windows", false)},
		{name: "root linux", contracts: rootTestContracts("linux", false)},
		{name: "root linux race", contracts: rootTestContracts("linux", true)},
		{name: "regress windows", contracts: regressUnitContracts("windows")},
		{name: "regress linux", contracts: regressUnitContracts("linux")},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if err := validateContracts(testCase.contracts); err != nil {
				t.Fatal(err)
			}
			packages := 0
			tests := 0
			for _, contract := range testCase.contracts {
				if contract.Excluded {
					continue
				}
				packages++
				tests += len(testsToRun(contract))
			}
			if packages == 0 || tests == 0 {
				t.Fatalf("contract coverage packages=%d tests=%d", packages, tests)
			}
		})
	}
}

func TestRegressUnitRunsOnlyFastSmokeOracles(t *testing.T) {
	contract := contractByImportPath(regressUnitContracts("linux"), regressModule+"/internal/smoke")
	want := []string{
		"TestValidateRequestedMigrations",
		"TestG1OptsMigrationDefaultAndDisable",
		"TestFillG1PatternIsPositionStableAndNotChunkPeriodic",
		"TestVerifyNoTrailingPayload",
		"TestValidateG2EvidenceRejectsPartialMigrationStimulus",
		"TestValidateG2EvidenceRaceDuplicateSemantics",
		"TestG2OptsMigrationDefaultAndDisable",
		"TestG3OptsStrictLossAndMigrationDisable",
		"TestValidateG3MeasurementsRejectsFalseGreenEvidence",
		"TestValidateG3MeasurementsHonorsExplicitSmokeLossBudget",
		"TestValidateG4EvidenceNegativeControls",
		"TestValidateG4EvidenceAllowsMeasuredSubMillisecondFailover",
		"TestValidateG5PayloadRejectsMismatch",
		"TestValidateRecoveredPathProgressNegativeControl",
	}
	if !reflect.DeepEqual(contract.RunTests, want) {
		t.Fatalf("smoke run set=%v want=%v", contract.RunTests, want)
	}
	for _, name := range contract.RunTests {
		if strings.HasPrefix(name, "TestRun") || name == "TestTCPRepairUnavailableFallsBackToGVisor" {
			t.Fatalf("long or external smoke %q leaked into T1", name)
		}
	}
}

func TestValidateTestInventoryRejectsNonexistentAndRenamedTests(t *testing.T) {
	tests := []struct {
		name     string
		expected []string
		actual   []string
		want     string
	}{
		{name: "nonexistent", expected: []string{"TestExists", "TestDoesNotExist"}, actual: []string{"TestExists"}, want: "TestDoesNotExist"},
		{name: "renamed", expected: []string{"TestOldName"}, actual: []string{"TestNewName"}, want: "missing=[TestOldName] unexpected=[TestNewName]"},
		{name: "unexpected addition", expected: []string{"TestOne"}, actual: []string{"TestOne", "TestTwo"}, want: "unexpected=[TestTwo]"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			err := validateNameInventory("synthetic tests", testCase.expected, testCase.actual)
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error=%v want substring %q", err, testCase.want)
			}
		})
	}
}

func TestExpectedTestSkipIsNotPass(t *testing.T) {
	stream := strings.Join([]string{
		`{"Action":"run","Package":"example/test","Test":"TestRequired"}`,
		`{"Action":"skip","Package":"example/test","Test":"TestRequired"}`,
	}, "\n") + "\n"
	result, err := gotestjson.Parse(strings.NewReader(stream), []gotestjson.Expectation{{Name: "TestRequired"}})
	if err == nil || result.Passed() || !result.HasIssue(gotestjson.IssueMandatorySkip) {
		t.Fatalf("mandatory skip result=%+v err=%v", result, err)
	}
}

func TestValidateBenchmarkJSONAcceptsExpectedResults(t *testing.T) {
	expected := []benchmarkExpectation{
		{Name: "BenchmarkOne", Iterations: 1, Metrics: []string{"ns/op", "MB/s"}},
		{Name: "BenchmarkTwo", Iterations: 2, Metrics: []string{"ns/op"}},
	}
	stream := benchmarkJSONStream(
		benchmarkEvent{Action: "start", Package: "example/bench"},
		benchmarkEvent{Action: "run", Package: "example/bench", Test: "BenchmarkOne"},
		benchmarkEvent{Action: "output", Package: "example/bench", Test: "BenchmarkOne", Output: "BenchmarkOne-8    \t"},
		benchmarkEvent{Action: "output", Package: "example/bench", Test: "BenchmarkOne", Output: "1\t100 ns/op\t12.5 MB/s\n"},
		benchmarkEvent{Action: "run", Package: "example/bench", Test: "BenchmarkTwo"},
		benchmarkEvent{Action: "output", Package: "example/bench", Test: "BenchmarkTwo", Output: "BenchmarkTwo-8\t2\t200 ns/op\n"},
		benchmarkEvent{Action: "pass", Package: "example/bench"},
	)
	if err := validateBenchmarkJSON(strings.NewReader(stream), "example/bench", expected); err != nil {
		t.Fatal(err)
	}
}

func TestValidateBenchmarkJSONRejectsMissingAndZeroResults(t *testing.T) {
	expect := []benchmarkExpectation{{Name: "BenchmarkExpected", Iterations: 1, Metrics: []string{"ns/op", "MB/s"}}}
	tests := []struct {
		name   string
		events []benchmarkEvent
		want   string
	}{
		{
			name: "nonexistent benchmark",
			events: []benchmarkEvent{
				{Action: "start", Package: "example/bench"},
				{Action: "pass", Package: "example/bench"},
			},
			want: "run events=0",
		},
		{
			name: "zero iterations",
			events: []benchmarkEvent{
				{Action: "start", Package: "example/bench"},
				{Action: "run", Package: "example/bench", Test: "BenchmarkExpected"},
				{Action: "output", Package: "example/bench", Test: "BenchmarkExpected", Output: "BenchmarkExpected-8 0 100 ns/op 1 MB/s\n"},
				{Action: "pass", Package: "example/bench"},
			},
			want: "iterations=\"0\"",
		},
		{
			name: "zero metric",
			events: []benchmarkEvent{
				{Action: "start", Package: "example/bench"},
				{Action: "run", Package: "example/bench", Test: "BenchmarkExpected"},
				{Action: "output", Package: "example/bench", Test: "BenchmarkExpected", Output: "BenchmarkExpected-8 1 100 ns/op 0 MB/s\n"},
				{Action: "pass", Package: "example/bench"},
			},
			want: "not finite and positive",
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			err := validateBenchmarkJSON(strings.NewReader(benchmarkJSONStream(testCase.events...)), "example/bench", expect)
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error=%v want substring %q", err, testCase.want)
			}
		})
	}
}

func benchmarkJSONStream(events ...benchmarkEvent) string {
	var builder strings.Builder
	for _, event := range events {
		fmt.Fprintf(&builder, "{\"Action\":%q,\"Package\":%q,\"Test\":%q,\"Output\":%q}\n", event.Action, event.Package, event.Test, event.Output)
	}
	return builder.String()
}
