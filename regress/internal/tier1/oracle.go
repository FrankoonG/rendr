package tier1

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/gotestjson"
)

const maxOracleOutputBytes = 8 << 20

var tier1GoTestExecutor = gotestjson.Executor{
	WaitDelay: tier1CommandWaitDelay,
	Parser:    gotestjson.Parser{MaxOutputBytes: 16 << 10},
}

func runTestContractSuite(
	ctx context.Context,
	dir string,
	contracts []packageContract,
	race bool,
	testTimeout time.Duration,
) error {
	if err := validateContracts(contracts); err != nil {
		return err
	}

	actualPackages, err := listPackages(ctx, dir)
	if err != nil {
		return err
	}
	expectedPackages := make([]string, len(contracts))
	for i, contract := range contracts {
		expectedPackages[i] = contract.ImportPath
	}
	if err := validateNameInventory("module packages", expectedPackages, actualPackages); err != nil {
		return err
	}

	runnableCount := 0
	for _, contract := range contracts {
		if contract.Excluded {
			continue
		}
		actualTests, err := listPackageTests(ctx, dir, contract.Argument, race)
		if err != nil {
			return fmt.Errorf("inventory %s: %w", contract.ImportPath, err)
		}
		if err := validateNameInventory(contract.ImportPath+" tests", contract.Inventory, actualTests); err != nil {
			return err
		}
		runnableCount += len(testsToRun(contract))
	}
	if runnableCount == 0 {
		return fmt.Errorf("test contract has zero runnable tests")
	}

	for _, contract := range contracts {
		if contract.Excluded {
			continue
		}
		expected := testsToRun(contract)
		if len(expected) == 0 {
			args := []string{"test", "-count=1", "-run", "^$"}
			if race {
				args = append(args, "-race")
			}
			if testTimeout > 0 {
				args = append(args, "-timeout", testTimeout.String())
			}
			args = append(args, contract.Argument)
			if err := runGo(ctx, dir, args...); err != nil {
				return fmt.Errorf("compile package %s: %w", contract.ImportPath, err)
			}
			continue
		}

		result, runErr := tier1GoTestExecutor.Run(ctx, gotestjson.Request{
			Dir:         dir,
			Package:     contract.Argument,
			Pattern:     exactNamesPattern(expected),
			Expected:    testExpectations(expected),
			TestTimeout: testTimeout,
			Race:        race,
		})
		if runErr != nil || !result.Passed() {
			return fmt.Errorf("test package %s: %s", contract.ImportPath, goTestResultDiagnostic(result, runErr))
		}
	}
	return nil
}

func validateContracts(contracts []packageContract) error {
	if len(contracts) == 0 {
		return fmt.Errorf("test contract has no packages")
	}
	imports := make(map[string]bool, len(contracts))
	arguments := make(map[string]bool, len(contracts))
	for _, contract := range contracts {
		if strings.TrimSpace(contract.ImportPath) == "" || strings.TrimSpace(contract.Argument) == "" {
			return fmt.Errorf("test contract has empty package identity: %+v", contract)
		}
		if imports[contract.ImportPath] {
			return fmt.Errorf("test contract repeats import path %q", contract.ImportPath)
		}
		if arguments[contract.Argument] {
			return fmt.Errorf("test contract repeats package argument %q", contract.Argument)
		}
		imports[contract.ImportPath] = true
		arguments[contract.Argument] = true
		if contract.Excluded && (len(contract.Inventory) != 0 || len(contract.RunTests) != 0) {
			return fmt.Errorf("excluded package %s must not declare tests", contract.ImportPath)
		}
		if !contract.Excluded && len(contract.Inventory) > 0 && contract.RunTests != nil && len(contract.RunTests) == 0 {
			return fmt.Errorf("%s declares %d inventoried tests but an empty run set", contract.ImportPath, len(contract.Inventory))
		}
		if err := validateUniqueNames(contract.ImportPath+" inventory", contract.Inventory); err != nil {
			return err
		}
		if err := validateUniqueNames(contract.ImportPath+" run set", testsToRun(contract)); err != nil {
			return err
		}
		inventory := make(map[string]bool, len(contract.Inventory))
		for _, name := range contract.Inventory {
			inventory[name] = true
		}
		for _, name := range testsToRun(contract) {
			if !inventory[name] {
				return fmt.Errorf("%s run set names undeclared test %q", contract.ImportPath, name)
			}
		}
	}
	return nil
}

func listPackages(ctx context.Context, dir string) ([]string, error) {
	stdout, stderr, err := runCommandOutput(ctx, dir, "go", "list", "./...")
	if err != nil {
		return nil, fmt.Errorf("go list ./...: %w\n%s", err, outputExcerpt(stderr))
	}
	return strings.Fields(string(stdout)), nil
}

func listPackageTests(ctx context.Context, dir, packageArgument string, race bool) ([]string, error) {
	args := []string{"test"}
	if race {
		args = append(args, "-race")
	}
	args = append(args, "-list", "^(Test|Fuzz|Example)", packageArgument)
	out, err := runCommandCapture(ctx, dir, "go", args...)
	if err != nil {
		return nil, fmt.Errorf("go %s: %w\n%s", strings.Join(args, " "), err, outputExcerpt(out))
	}

	var names []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if isTopLevelTestName(line) {
			names = append(names, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse go test -list output: %w", err)
	}
	return names, nil
}

func listPackageBenchmarks(ctx context.Context, dir, packageArgument string) ([]string, error) {
	out, err := runCommandCapture(ctx, dir, "go", "test", "-list", "^Benchmark", packageArgument)
	if err != nil {
		return nil, fmt.Errorf("go test -list benchmarks: %w\n%s", err, outputExcerpt(out))
	}
	var names []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Benchmark") && !strings.ContainsAny(line, " \t") {
			names = append(names, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse benchmark list: %w", err)
	}
	return names, nil
}

func isTopLevelTestName(name string) bool {
	if name == "" || strings.ContainsAny(name, " \t") {
		return false
	}
	return strings.HasPrefix(name, "Test") || strings.HasPrefix(name, "Fuzz") || strings.HasPrefix(name, "Example")
}

func validateNameInventory(label string, expected, actual []string) error {
	if err := validateUniqueNames(label+" expected", expected); err != nil {
		return err
	}
	if err := validateUniqueNames(label+" actual", actual); err != nil {
		return err
	}
	want := append([]string(nil), expected...)
	got := append([]string(nil), actual...)
	sort.Strings(want)
	sort.Strings(got)
	if slicesEqual(want, got) {
		return nil
	}

	wantSet := make(map[string]bool, len(want))
	gotSet := make(map[string]bool, len(got))
	for _, name := range want {
		wantSet[name] = true
	}
	for _, name := range got {
		gotSet[name] = true
	}
	var missing, unexpected []string
	for _, name := range want {
		if !gotSet[name] {
			missing = append(missing, name)
		}
	}
	for _, name := range got {
		if !wantSet[name] {
			unexpected = append(unexpected, name)
		}
	}
	return fmt.Errorf("%s inventory mismatch: missing=%v unexpected=%v", label, missing, unexpected)
}

func validateUniqueNames(label string, names []string) error {
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("%s contains an empty name", label)
		}
		if seen[name] {
			return fmt.Errorf("%s repeats %q", label, name)
		}
		seen[name] = true
	}
	return nil
}

func slicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func exactNamesPattern(names []string) string {
	quoted := make([]string, len(names))
	for i, name := range names {
		quoted[i] = regexp.QuoteMeta(name)
	}
	return "^(?:" + strings.Join(quoted, "|") + ")$"
}

func testExpectations(names []string) []gotestjson.Expectation {
	expected := make([]gotestjson.Expectation, len(names))
	for i, name := range names {
		expected[i] = gotestjson.Expectation{Name: name}
	}
	return expected
}

func goTestResultDiagnostic(result gotestjson.Result, runErr error) string {
	var parts []string
	if runErr != nil {
		parts = append(parts, runErr.Error())
	}
	for _, issue := range result.Issues {
		parts = append(parts, issue.String())
	}
	for _, test := range result.Tests {
		if test.Status == gotestjson.StatusPassed || strings.TrimSpace(test.Output) == "" {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s output:\n%s", test.Name, strings.TrimSpace(test.Output)))
	}
	if len(parts) == 0 {
		parts = append(parts, "go test result was not a validated pass")
	}
	return outputExcerpt([]byte(strings.Join(parts, "\n")))
}

func runBenchmarkContract(ctx context.Context, root string) error {
	expectedNames := make([]string, len(benchmarkContract))
	for i, expectation := range benchmarkContract {
		expectedNames[i] = expectation.Name
	}
	actualNames, err := listPackageBenchmarks(ctx, root, ".")
	if err != nil {
		return err
	}
	if err := validateNameInventory("root benchmarks", expectedNames, actualNames); err != nil {
		return err
	}

	args := []string{
		"test", "-json", "-count=1", "-run", "^$",
		"-bench", exactNamesPattern(expectedNames), "-benchtime=1x",
		"-timeout", "60s", ".",
	}
	out, runErr := runCommandCapture(ctx, root, "go", args...)
	validationErr := validateBenchmarkJSON(bytes.NewReader(out), rendrModule, benchmarkContract)
	switch {
	case runErr != nil && validationErr != nil:
		return fmt.Errorf("go benchmark command failed: %w; oracle: %v\n%s", runErr, validationErr, outputExcerpt(out))
	case runErr != nil:
		return fmt.Errorf("go benchmark command failed: %w\n%s", runErr, outputExcerpt(out))
	case validationErr != nil:
		return validationErr
	default:
		return nil
	}
}

type benchmarkEvent struct {
	Action  string `json:"Action"`
	Package string `json:"Package"`
	Test    string `json:"Test"`
	Output  string `json:"Output"`
}

func validateBenchmarkJSON(r io.Reader, packagePath string, expected []benchmarkExpectation) error {
	if r == nil {
		return fmt.Errorf("nil benchmark JSON reader")
	}
	if strings.TrimSpace(packagePath) == "" || len(expected) == 0 {
		return fmt.Errorf("benchmark contract requires a package and at least one benchmark")
	}
	names := make([]string, len(expected))
	byName := make(map[string]benchmarkExpectation, len(expected))
	for i, expectation := range expected {
		if expectation.Iterations <= 0 || len(expectation.Metrics) == 0 {
			return fmt.Errorf("benchmark %q has invalid iteration/metric contract", expectation.Name)
		}
		names[i] = expectation.Name
		byName[expectation.Name] = expectation
	}
	if err := validateUniqueNames("benchmark contract", names); err != nil {
		return err
	}

	runs := make(map[string]int, len(expected))
	outputs := make(map[string]*strings.Builder, len(expected))
	packageStarted := false
	packagePassed := false
	var issues []string

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64<<10), maxOracleOutputBytes)
	line := 0
	for scanner.Scan() {
		line++
		var event benchmarkEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			issues = append(issues, fmt.Sprintf("malformed benchmark JSON line %d: %v", line, err))
			continue
		}
		if event.Package != "" && event.Package != packagePath {
			issues = append(issues, fmt.Sprintf("unexpected benchmark package %q", event.Package))
		}
		if event.Test == "" {
			switch event.Action {
			case "start":
				packageStarted = true
			case "pass":
				packagePassed = true
			case "fail":
				issues = append(issues, "benchmark package failed")
			}
			continue
		}
		if !strings.HasPrefix(event.Test, "Benchmark") {
			continue
		}
		if _, ok := byName[event.Test]; !ok {
			issues = append(issues, fmt.Sprintf("unexpected benchmark %q", event.Test))
			continue
		}
		switch event.Action {
		case "run":
			runs[event.Test]++
		case "output":
			builder := outputs[event.Test]
			if builder == nil {
				builder = &strings.Builder{}
				outputs[event.Test] = builder
			}
			if builder.Len()+len(event.Output) <= 64<<10 {
				builder.WriteString(event.Output)
			} else {
				issues = append(issues, fmt.Sprintf("benchmark %q output exceeded limit", event.Test))
			}
		case "fail", "skip":
			issues = append(issues, fmt.Sprintf("benchmark %q ended with %s", event.Test, event.Action))
		}
	}
	if err := scanner.Err(); err != nil {
		issues = append(issues, fmt.Sprintf("read benchmark JSON: %v", err))
	}
	if !packageStarted || !packagePassed {
		issues = append(issues, fmt.Sprintf("benchmark package terminal evidence start=%t pass=%t", packageStarted, packagePassed))
	}

	for _, expectation := range expected {
		if runs[expectation.Name] != 1 {
			issues = append(issues, fmt.Sprintf("benchmark %q run events=%d, want 1", expectation.Name, runs[expectation.Name]))
			continue
		}
		output := ""
		if builder := outputs[expectation.Name]; builder != nil {
			output = builder.String()
		}
		if err := validateBenchmarkResult(output, expectation); err != nil {
			issues = append(issues, err.Error())
		}
	}
	if len(issues) != 0 {
		return fmt.Errorf("benchmark JSON validation failed: %s", strings.Join(issues, "; "))
	}
	return nil
}

func validateBenchmarkResult(output string, expectation benchmarkExpectation) error {
	var matching [][]string
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || !benchmarkResultNameMatches(fields[0], expectation.Name) {
			continue
		}
		matching = append(matching, fields)
	}
	if len(matching) != 1 {
		return fmt.Errorf("benchmark %q result lines=%d, want 1", expectation.Name, len(matching))
	}
	fields := matching[0]
	iterations, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || iterations != expectation.Iterations {
		return fmt.Errorf("benchmark %q iterations=%q, want %d", expectation.Name, fields[1], expectation.Iterations)
	}
	if (len(fields)-2)%2 != 0 {
		return fmt.Errorf("benchmark %q has malformed metric fields %v", expectation.Name, fields[2:])
	}
	metrics := make(map[string]float64)
	for i := 2; i < len(fields); i += 2 {
		value, err := strconv.ParseFloat(fields[i], 64)
		if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value <= 0 {
			return fmt.Errorf("benchmark %q metric %s=%q is not finite and positive", expectation.Name, fields[i+1], fields[i])
		}
		metrics[fields[i+1]] = value
	}
	for _, unit := range expectation.Metrics {
		if metrics[unit] <= 0 {
			return fmt.Errorf("benchmark %q missing positive %s metric", expectation.Name, unit)
		}
	}
	return nil
}

func benchmarkResultNameMatches(got, expected string) bool {
	if got == expected {
		return true
	}
	if !strings.HasPrefix(got, expected+"-") {
		return false
	}
	_, err := strconv.Atoi(strings.TrimPrefix(got, expected+"-"))
	return err == nil
}

func runCommandCapture(ctx context.Context, dir, name string, args ...string) ([]byte, error) {
	cmd, tree := newTier1Command(ctx, name, args...)
	cmd.Dir = dir
	buffer := &limitedBuffer{limit: maxOracleOutputBytes}
	cmd.Stdout = buffer
	cmd.Stderr = buffer
	err := runTier1Command(cmd, tree)
	if buffer.truncated {
		if err == nil {
			err = fmt.Errorf("command output exceeded %d bytes", maxOracleOutputBytes)
		} else {
			err = fmt.Errorf("%w; command output exceeded %d bytes", err, maxOracleOutputBytes)
		}
	}
	return buffer.Bytes(), err
}

func runCommandOutput(ctx context.Context, dir, name string, args ...string) ([]byte, []byte, error) {
	cmd, tree := newTier1Command(ctx, name, args...)
	cmd.Dir = dir
	stdout := &limitedBuffer{limit: maxOracleOutputBytes}
	stderr := &limitedBuffer{limit: maxOracleOutputBytes}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := runTier1Command(cmd, tree)
	if stdout.truncated || stderr.truncated {
		if err == nil {
			err = fmt.Errorf("command output exceeded %d bytes", maxOracleOutputBytes)
		} else {
			err = fmt.Errorf("%w; command output exceeded %d bytes", err, maxOracleOutputBytes)
		}
	}
	return stdout.Bytes(), stderr.Bytes(), err
}

type limitedBuffer struct {
	mu        sync.Mutex
	limit     int
	value     bytes.Buffer
	truncated bool
}

func (b *limitedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	written := len(data)
	remaining := b.limit - b.value.Len()
	if remaining <= 0 {
		b.truncated = true
		return written, nil
	}
	if len(data) > remaining {
		_, _ = b.value.Write(data[:remaining])
		b.truncated = true
		return written, nil
	}
	_, _ = b.value.Write(data)
	return written, nil
}

func (b *limitedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.value.Bytes()...)
}

func outputExcerpt(output []byte) string {
	value := strings.TrimSpace(string(output))
	const limit = 16 << 10
	if len(value) <= limit {
		return value
	}
	return value[len(value)-limit:] + "\n...[earlier output truncated]"
}
