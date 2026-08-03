package tier5

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/FrankoonG/rendr/regress/internal/gotestjson"
	"github.com/FrankoonG/rendr/regress/internal/report"
)

const (
	maxReportDiagnosticBytes = 16 << 10
	tier5EvidenceMarker      = "RENDR_T5_EVIDENCE_JSON="
	tier5EvidenceSchema      = "tier5-capability-v1"
	capNetAdminBit           = 12
)

var tier5LookPath = exec.LookPath

var tier5GoTestExecutor = gotestjson.Executor{
	Parser: gotestjson.Parser{MaxOutputBytes: maxReportDiagnosticBytes},
}

type goTestProbe struct {
	caseID       string
	workDir      string
	packageName  string
	testName     string
	cacheName    string
	modCacheName string
	env          []string
	required     map[string]string
	requiredKeys []string
}

var unprivilegedProbeDefs = map[string]goTestProbe{
	"T5.3-tcprepair-unprivileged": {
		caseID:       "T5.3-tcprepair-unprivileged",
		workDir:      "regress",
		packageName:  "./internal/tier5",
		testName:     "TestTier5TCPRepairUnprivilegedPreflight",
		cacheName:    "go-build-nocap",
		modCacheName: "go-mod-nocap",
		required: map[string]string{
			"behavior":                        "tcp_repair_preflight_capability_probe",
			"fallback_outcome":                "not_exercised",
			"gvisor_involved":                 "false",
			"kernel_tcp_to_gvisor_conversion": "false",
			"tcp_repair_preflight":            "permission_denied",
		},
		requiredKeys: []string{"preflight_error_mentions_gvisor", "preflight_error_typed_eperm"},
	},
	"T5.4-gvisor-unprivileged": {
		caseID:       "T5.4-gvisor-unprivileged",
		workDir:      "regress",
		packageName:  "./internal/tier5",
		testName:     "TestTier5GVisorOwnedSessionUnprivileged",
		cacheName:    "go-build-gvisor-nocap",
		modCacheName: "go-mod-gvisor-nocap",
		required: map[string]string{
			"behavior":                           "gvisor_owned_process_local_session",
			"fallback_relation":                  "independent_gvisor_session",
			"group_executor":                     "legacy_prime",
			"gvisor_endpoint_owner":              "gvisor_from_session_start",
			"gvisor_packet_link_rebind_observed": "false",
			"kernel_tcp_to_gvisor_conversion":    "false",
			"leaf_mobility":                      "framed_path_switch",
			"outer_carrier":                      "process_local_veth",
			"session_protocol":                   "framed_stream_v2",
			"sha256_match":                       "true",
			"workload_result":                    "pass",
		},
		requiredKeys: []string{"migration_calls_fired", "migrations_observed", "requested_migrations"},
	},
	"T5.5-tcprepair-gvisor-fallback-unprivileged": {
		caseID:       "T5.5-tcprepair-gvisor-fallback-unprivileged",
		workDir:      "regress",
		packageName:  "./internal/tier5",
		testName:     "TestTier5TCPRepairFailureRequiresNegotiatedFallback",
		cacheName:    "go-build-tcprepair-gvisor-fallback-nocap",
		modCacheName: "go-mod-tcprepair-gvisor-fallback-nocap",
		required: map[string]string{
			"behavior":                                     "tcp_repair_failure_to_same_session_redial_attach",
			"group_executor":                               "legacy_prime",
			"gvisor_involved":                              "false",
			"kernel_tcp_to_gvisor_conversion":              "false",
			"original_socket_usable_after_preflight":       "true",
			"original_socket_usable_after_prepare_failure": "true",
			"session_protocol":                             "framed_stream_v2",
			"tcp_repair_preflight":                         "permission_denied",
			"tcp_repair_prepare":                           "permission_denied",
		},
		requiredKeys: []string{
			"fallback_outcome", "fallback_selection", "preflight_error_typed_eperm",
			"prepare_error_typed_eperm", "product_mobility_plan_observable", "typed_failure_observed",
		},
	},
	"T5.6-gvisor-packet-carrier-unprivileged": {
		caseID:       "T5.6-gvisor-packet-carrier-unprivileged",
		workDir:      "regress",
		packageName:  "./internal/tier5",
		testName:     "TestTier5GVisorPacketCarrierOwnedSessionUnprivileged",
		cacheName:    "go-build-gvisor-packet-nocap",
		modCacheName: "go-mod-gvisor-packet-nocap",
		required: map[string]string{
			"behavior":                           "gvisor_owned_udp_packet_carrier_session",
			"fallback_relation":                  "independent_gvisor_session",
			"group_executor":                     "legacy_prime",
			"gvisor_endpoint_owner":              "gvisor_from_session_start",
			"gvisor_packet_link_rebind_observed": "false",
			"kernel_tcp_to_gvisor_conversion":    "false",
			"leaf_mobility":                      "framed_path_switch_between_gvisor_owned_leaves",
			"outer_carrier":                      "udp",
			"session_protocol":                   "framed_stream_v2",
			"sha256_match":                       "true",
			"workload_result":                    "pass",
		},
		requiredKeys: []string{"migration_calls_fired", "migrations_observed", "requested_migrations"},
	},
}

func probeUnprivileged(ctx context.Context, rendrRoot string) report.Case {
	return runUnprivilegedGoTest(ctx, rendrRoot, unprivilegedProbeDefs["T5.3-tcprepair-unprivileged"])
}

func probeGVisorUnprivileged(ctx context.Context, rendrRoot string) report.Case {
	return runUnprivilegedGoTest(ctx, rendrRoot, unprivilegedProbeDefs["T5.4-gvisor-unprivileged"])
}

func probeTCPRepairFallbackUnprivileged(ctx context.Context, rendrRoot string) report.Case {
	return runUnprivilegedGoTest(ctx, rendrRoot, unprivilegedProbeDefs["T5.5-tcprepair-gvisor-fallback-unprivileged"])
}

func probeGVisorPacketCarrierUnprivileged(ctx context.Context, rendrRoot string) report.Case {
	return runUnprivilegedGoTest(ctx, rendrRoot, unprivilegedProbeDefs["T5.6-gvisor-packet-carrier-unprivileged"])
}

func runUnprivilegedGoTest(ctx context.Context, rendrRoot string, probe goTestProbe) report.Case {
	if _, err := tier5LookPath("setpriv"); err != nil {
		return report.Case{
			Name:          probe.caseID,
			Tier:          "T5",
			InvalidReason: "mandatory prerequisite unavailable: setpriv executable not found",
			Evidence: map[string]string{
				"prerequisite_valid": "false",
				"setpriv_available":  "false",
				"setpriv_requested":  "true",
			},
		}
	}
	request := probeGoTestRequest(rendrRoot, probe)
	if _, err := os.Stat(request.Dir); err != nil {
		return report.Case{Name: probe.caseID, Tier: "T5", InvalidReason: "bad go test working directory: " + err.Error()}
	}
	result, err := tier5GoTestExecutor.Run(ctx, request)
	if err != nil && result.Passed() {
		result.Issues = append(result.Issues, gotestjson.Issue{Code: gotestjson.IssueCommandFailed, Detail: err.Error()})
	}
	rc := goTestReportCase(probe.caseID, []string{probe.testName}, result)
	applyProbeEvidence(&rc, probe, result)
	return rc
}

func probeGoTestRequest(rendrRoot string, probe goTestProbe) gotestjson.Request {
	dir := rendrRoot
	if probe.workDir != "" {
		dir = filepath.Join(rendrRoot, probe.workDir)
	}
	env := append([]string(nil), probe.env...)
	env = append(env,
		"GOCACHE="+filepath.Join(os.TempDir(), probe.cacheName),
		"GOMODCACHE="+filepath.Join(os.TempDir(), probe.modCacheName),
	)
	return gotestjson.Request{
		Dir:           dir,
		Package:       probe.packageName,
		Pattern:       "^" + regexp.QuoteMeta(probe.testName) + "$",
		Expected:      []gotestjson.Expectation{{Name: probe.testName}},
		Env:           env,
		CommandPrefix: setprivCommandPrefix(),
	}
}

func setprivCommandPrefix() []string {
	return []string{
		"setpriv",
		"--bounding-set=-net_admin",
		"--inh-caps=-net_admin",
		"--ambient-caps=-net_admin",
	}
}

func goTestReportCase(caseName string, expected []string, result gotestjson.Result) report.Case {
	rc := report.Case{
		Name:     caseName,
		Tier:     "T5",
		Duration: result.Duration,
		Evidence: goTestEvidence(expected, result),
	}
	results := make(map[string]gotestjson.TestResult, len(result.Tests))
	expectedSet := make(map[string]bool, len(expected))
	for _, name := range expected {
		expectedSet[name] = true
	}

	var failures, skips, invalids []string
	for _, testResult := range result.Tests {
		if !expectedSet[testResult.Name] {
			invalids = append(invalids, fmt.Sprintf("unexpected parsed test result %q", testResult.Name))
			continue
		}
		if _, exists := results[testResult.Name]; exists {
			invalids = append(invalids, fmt.Sprintf("duplicate parsed test result %q", testResult.Name))
			continue
		}
		results[testResult.Name] = testResult
	}

	issues := append([]gotestjson.Issue(nil), result.Issues...)
	sort.SliceStable(issues, func(i, j int) bool {
		if issues[i].Code != issues[j].Code {
			return issues[i].Code < issues[j].Code
		}
		if issues[i].Test != issues[j].Test {
			return issues[i].Test < issues[j].Test
		}
		return issues[i].Detail < issues[j].Detail
	})
	for _, issue := range issues {
		testResult, known := results[issue.Test]
		switch issue.Code {
		case gotestjson.IssueTestFailed:
			if !known || testResult.Status != gotestjson.StatusFailed {
				failures = append(failures, issue.String())
			}
		case gotestjson.IssueMandatorySkip:
			if !known || testResult.Status != gotestjson.StatusSkipped {
				skips = append(skips, issue.String())
			}
		default:
			invalids = append(invalids, issue.String())
		}
	}

	for _, name := range expected {
		testResult, ok := results[name]
		if !ok {
			invalids = append(invalids, fmt.Sprintf("expected top-level test %q has no parsed result", name))
			continue
		}
		switch testResult.Status {
		case gotestjson.StatusPassed:
		case gotestjson.StatusFailed:
			failures = append(failures, testOutputDiagnostic("top-level test "+name+" failed", testResult))
		case gotestjson.StatusSkipped:
			skips = append(skips, testOutputDiagnostic("mandatory top-level test "+name+" skipped", testResult))
		case gotestjson.StatusNotRun:
			invalids = append(invalids, fmt.Sprintf("expected top-level test %q did not run", name))
		case gotestjson.StatusIncomplete:
			invalids = append(invalids, testOutputDiagnostic("top-level test "+name+" has no terminal event", testResult))
		default:
			invalids = append(invalids, fmt.Sprintf("top-level test %q has unknown status %q", name, testResult.Status))
		}
	}

	if result.CaptureTruncated && !result.HasIssue(gotestjson.IssueCaptureLimit) {
		invalids = append(invalids, "go test JSON capture was truncated")
	}
	if len(invalids) != 0 && strings.TrimSpace(result.CommandOutput) != "" {
		invalids = append(invalids, outputDiagnostic("go test command output", result.CommandOutput, result.CommandOutputTruncated))
	}
	rc.Failure = boundedDiagnostic(failures)
	rc.SkipReason = boundedDiagnostic(skips)
	rc.InvalidReason = boundedDiagnostic(invalids)
	return rc
}

func applyProbeEvidence(rc *report.Case, probe goTestProbe, result gotestjson.Result) {
	if rc.Evidence == nil {
		rc.Evidence = make(map[string]string)
	}
	rc.Evidence["setpriv_available"] = "true"
	rc.Evidence["setpriv_requested"] = "true"

	var invalids []string
	if rc.SkipReason != "" {
		invalids = append(invalids, "mandatory unprivileged probe skipped: "+rc.SkipReason)
		rc.SkipReason = ""
	}

	evidence, evidenceIssues := extractProbeEvidence(probe.testName, result)
	invalids = append(invalids, evidenceIssues...)
	for key, value := range evidence {
		if _, reserved := rc.Evidence[key]; reserved {
			invalids = append(invalids, fmt.Sprintf("probe evidence key %q collides with runner evidence", key))
			continue
		}
		rc.Evidence[key] = value
	}
	if len(evidenceIssues) == 0 {
		invalids = append(invalids, validateProbeEvidence(probe, evidence)...)
	}
	rc.InvalidReason = appendDiagnostic(rc.InvalidReason, invalids)
	if len(invalids) == 0 {
		rc.Failure = appendDiagnostic(rc.Failure, probeOutcomeFailures(probe, evidence))
	}
}

func extractProbeEvidence(testName string, result gotestjson.Result) (map[string]string, []string) {
	var matches []string
	for _, testResult := range result.Tests {
		if testResult.Name != testName {
			continue
		}
		for _, line := range strings.Split(testResult.Output, "\n") {
			index := strings.Index(line, tier5EvidenceMarker)
			if index < 0 {
				continue
			}
			matches = append(matches, strings.TrimSpace(line[index+len(tier5EvidenceMarker):]))
		}
	}
	if len(matches) == 0 {
		return nil, []string{"mandatory structured probe evidence is missing"}
	}
	if len(matches) != 1 {
		return nil, []string{fmt.Sprintf("structured probe evidence count=%d, want exactly 1", len(matches))}
	}
	var evidence map[string]string
	if err := json.Unmarshal([]byte(matches[0]), &evidence); err != nil {
		return nil, []string{"structured probe evidence is malformed JSON: " + err.Error()}
	}
	if evidence == nil {
		return nil, []string{"structured probe evidence is JSON null, want an object"}
	}
	return evidence, nil
}

func validateProbeEvidence(probe goTestProbe, evidence map[string]string) []string {
	var invalids []string
	requireExact := func(key, want string) {
		got, ok := evidence[key]
		if !ok {
			invalids = append(invalids, fmt.Sprintf("probe evidence missing %q", key))
			return
		}
		if got != want {
			invalids = append(invalids, fmt.Sprintf("probe evidence %s=%q, want %q", key, got, want))
		}
	}

	requireExact("schema", tier5EvidenceSchema)
	requireExact("case_id", probe.caseID)
	requireExact("goos", "linux")
	requireExact("capability_source", "proc_self_status")
	if _, err := strconv.Atoi(evidence["euid"]); err != nil {
		invalids = append(invalids, fmt.Sprintf("probe evidence euid=%q is not an integer", evidence["euid"]))
	}

	if evidence["prerequisite_valid"] != "true" {
		reason := evidence["prerequisite_error"]
		if reason == "" {
			reason = "unspecified capability prerequisite failure"
		}
		invalids = append(invalids, "mandatory capability prerequisite invalid: "+reason)
		return invalids
	}
	requireExact("cap_net_admin_absent", "true")
	requireExact("setpriv_capability_drop_observed", "true")

	const netAdminMask = uint64(1) << capNetAdminBit
	for _, key := range []string{"cap_inh", "cap_prm", "cap_eff", "cap_bnd", "cap_amb"} {
		raw, ok := evidence[key]
		if !ok {
			invalids = append(invalids, fmt.Sprintf("probe evidence missing %q", key))
			continue
		}
		value, err := strconv.ParseUint(strings.TrimPrefix(raw, "0x"), 16, 64)
		if err != nil {
			invalids = append(invalids, fmt.Sprintf("probe evidence %s=%q is not hexadecimal", key, raw))
			continue
		}
		if value&netAdminMask != 0 {
			invalids = append(invalids, fmt.Sprintf("mandatory unprivileged stimulus invalid: %s retains CAP_NET_ADMIN", key))
		}
	}

	for key, want := range probe.required {
		requireExact(key, want)
	}
	for _, key := range probe.requiredKeys {
		if strings.TrimSpace(evidence[key]) == "" {
			invalids = append(invalids, fmt.Sprintf("probe evidence missing non-empty %q", key))
		}
	}
	invalids = append(invalids, validateProbeMeasurements(probe.caseID, evidence)...)
	return invalids
}

func validateProbeMeasurements(caseID string, evidence map[string]string) []string {
	var invalids []string
	requireInt := func(key string, minimum int64) {
		value, err := strconv.ParseInt(evidence[key], 10, 64)
		if err != nil {
			invalids = append(invalids, fmt.Sprintf("probe evidence %s=%q is not an integer", key, evidence[key]))
			return
		}
		if value < minimum {
			invalids = append(invalids, fmt.Sprintf("probe evidence %s=%d, want >=%d", key, value, minimum))
		}
	}

	switch caseID {
	case "T5.4-gvisor-unprivileged", "T5.6-gvisor-packet-carrier-unprivileged":
		requireInt("requested_migrations", 2)
		requireInt("migration_calls_fired", 2)
		requireInt("migrations_observed", 2)
	case "T5.5-tcprepair-gvisor-fallback-unprivileged":
		invalids = append(invalids, validateT5FallbackOutcome(evidence, requireInt)...)
	}
	return invalids
}

func validateT5FallbackOutcome(evidence map[string]string, requireInt func(string, int64)) []string {
	var invalids []string
	requireExact := func(key, want string) {
		if got := evidence[key]; got != want {
			invalids = append(invalids, fmt.Sprintf("probe evidence %s=%q, want %q", key, got, want))
		}
	}
	switch evidence["fallback_outcome"] {
	case "negotiated_same_session_redial_attach":
		requireExact("attach_negotiation", "bridge_tag_existing_flow")
		requireExact("fallback_selection", "product_negotiated_before_data")
		requireExact("leaf_mobility", "redial_attach")
		requireExact("post_fallback_payload_ok", "true")
		requireExact("product_mobility_plan_observable", "true")
		requireExact("same_session_flow_id_stable", "true")
		requireExact("typed_failure_observed", "false")
		requireInt("factory_dials", 2)
		requireInt("client_path_count", 2)
		requireInt("server_path_count", 2)
		requireInt("listener_flow_count", 1)
		requireInt("migration_count_delta", 1)
	case "manual_same_session_redial_attach":
		requireExact("attach_negotiation", "bridge_tag_existing_flow")
		requireExact("fallback_selection", "regression_orchestrated_after_failure")
		requireExact("leaf_mobility", "redial_attach")
		requireExact("post_fallback_payload_ok", "true")
		requireExact("product_mobility_plan_observable", "false")
		requireExact("same_session_flow_id_stable", "true")
		requireExact("typed_failure_observed", "false")
		requireInt("factory_dials", 2)
		requireInt("client_path_count", 2)
		requireInt("server_path_count", 2)
		requireInt("listener_flow_count", 1)
		requireInt("migration_count_delta", 1)
	case "manual_redial_attach_failed":
		requireExact("attach_negotiation", "not_attempted")
		requireExact("fallback_selection", "regression_orchestrated_after_failure")
		requireExact("leaf_mobility", "not_selected")
		requireExact("product_mobility_plan_observable", "false")
		requireExact("typed_failure_observed", "false")
	case "typed_failure":
		requireExact("attach_negotiation", "typed_failure")
		requireExact("fallback_selection", "product_typed_planning_failure")
		requireExact("leaf_mobility", "not_selected")
		requireExact("original_socket_usable_after_typed_failure", "true")
		requireExact("product_mobility_plan_observable", "true")
		requireExact("same_session_flow_id_stable", "true")
		requireExact("typed_failure_stage", "mobility_planning")
		requireExact("typed_failure_observed", "true")
		if strings.TrimSpace(evidence["typed_failure_code"]) == "" {
			invalids = append(invalids, "probe evidence missing non-empty \"typed_failure_code\"")
		}
	default:
		invalids = append(invalids, fmt.Sprintf(
			"probe evidence fallback_outcome=%q proves neither factual redial/attach nor a typed planning failure",
			evidence["fallback_outcome"],
		))
	}
	return invalids
}

func probeOutcomeFailures(probe goTestProbe, evidence map[string]string) []string {
	if probe.caseID != "T5.5-tcprepair-gvisor-fallback-unprivileged" {
		return nil
	}
	switch evidence["fallback_outcome"] {
	case "negotiated_same_session_redial_attach", "typed_failure":
		return nil
	case "manual_same_session_redial_attach":
		return []string{
			"TCP fallback contract not met: same-session redial/attach required regression-orchestrated AdminConn.AddPath; product exposes no negotiated mobility plan or typed planning failure",
		}
	default:
		return []string{fmt.Sprintf("TCP fallback contract not met: outcome=%q", evidence["fallback_outcome"])}
	}
}

func appendDiagnostic(existing string, parts []string) string {
	if existing != "" {
		parts = append([]string{existing}, parts...)
	}
	return boundedDiagnostic(parts)
}

func goTestEvidence(expected []string, result gotestjson.Result) map[string]string {
	observed := make([]string, 0, len(result.Tests))
	for _, testResult := range result.Tests {
		observed = append(observed, testResult.Name+"="+string(testResult.Status))
	}
	issueCodes := make([]string, 0, len(result.Issues))
	for _, issue := range result.Issues {
		issueCodes = append(issueCodes, string(issue.Code))
	}
	sort.Strings(issueCodes)
	if len(issueCodes) == 0 {
		issueCodes = append(issueCodes, "none")
	}
	return map[string]string{
		"command":            quotedCommand(result.Command),
		"expected_tests":     strings.Join(expected, ","),
		"observed_tests":     strings.Join(observed, ","),
		"issue_codes":        strings.Join(issueCodes, ","),
		"capture_truncated":  strconv.FormatBool(result.CaptureTruncated),
		"json_validation_ok": strconv.FormatBool(result.Passed()),
	}
}

func quotedCommand(command []string) string {
	quoted := make([]string, len(command))
	for i, arg := range command {
		quoted[i] = strconv.Quote(arg)
	}
	return strings.Join(quoted, " ")
}

func testOutputDiagnostic(prefix string, result gotestjson.TestResult) string {
	return outputDiagnostic(prefix, result.Output, result.OutputTruncated)
}

func outputDiagnostic(prefix, output string, truncated bool) string {
	output = strings.TrimSpace(output)
	if output != "" {
		prefix += ":\n" + output
	}
	if truncated {
		prefix += "\n[output truncated]"
	}
	return prefix
}

func boundedDiagnostic(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	value := strings.ToValidUTF8(strings.Join(parts, "\n"), "?")
	if len(value) <= maxReportDiagnosticBytes {
		return value
	}
	const suffix = "\n...[diagnostic truncated]"
	limit := maxReportDiagnosticBytes - len(suffix)
	return strings.ToValidUTF8(value[:limit], "?") + suffix
}
