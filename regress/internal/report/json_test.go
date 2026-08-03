package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDocumentDigestIsStableAndCoversReportClaims(t *testing.T) {
	base := sealedTestSuite(t)
	first, err := base.ReportDigest()
	if err != nil {
		t.Fatal(err)
	}
	second, err := base.ReportDigest()
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("digest is unstable: %q != %q", first, second)
	}
	snapshot, err := base.Document()
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Invocation.SelectedCaseIDs[0] = "mutated"
	snapshot.Invocation.EnvironmentStart.Interfaces[0].Name = "mutated"
	snapshot.Invocation.EnvironmentStart.QDisc.State[0] = 'x'
	snapshot.Cases[0].Evidence["alpha"] = "mutated"
	if base.Invocation.SelectedCaseIDs[0] == "mutated" || base.Invocation.EnvironmentStart.Interfaces[0].Name == "mutated" ||
		base.Invocation.EnvironmentStart.QDisc.State[0] == 'x' || base.Cases[0].Evidence["alpha"] == "mutated" {
		t.Fatal("Document aliases mutable Suite state")
	}

	reorderedEvidence := sealedTestSuite(t)
	reorderedEvidence.Cases[0].Evidence = map[string]string{"zeta": "last", "alpha": "first"}
	if got, _ := reorderedEvidence.ReportDigest(); got != first {
		t.Fatalf("map insertion order changed digest: got %q want %q", got, first)
	}

	mutations := []struct {
		name   string
		mutate func(*Suite)
	}{
		{name: "outcome", mutate: func(s *Suite) { s.Cases[0].Failure = "changed" }},
		{name: "case digest", mutate: func(s *Suite) { s.Cases[0].CaseDigest = "sha256:" + strings.Repeat("c", 64) }},
		{name: "evidence", mutate: func(s *Suite) { s.Cases[0].Evidence["alpha"] = "changed" }},
		{name: "row order", mutate: func(s *Suite) { s.Cases[0], s.Cases[1] = s.Cases[1], s.Cases[0] }},
		{name: "invocation", mutate: func(s *Suite) { s.Invocation.ManifestDigest = "sha256:" + strings.Repeat("b", 64) }},
		{name: "revision", mutate: func(s *Suite) { s.Invocation.RevisionEnd.CommitSHA = "changed" }},
		{name: "environment", mutate: func(s *Suite) { s.Invocation.EnvironmentEnd.Hostname = "changed" }},
		{name: "completion", mutate: func(s *Suite) { s.Complete = false }},
		{name: "run failure", mutate: func(s *Suite) { s.RunFailure = "changed" }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			candidate := sealedTestSuite(t)
			mutation.mutate(candidate)
			got, err := candidate.ReportDigest()
			if err != nil {
				t.Fatal(err)
			}
			if got == first {
				t.Fatalf("mutation did not change report digest %q", got)
			}
		})
	}
}

func TestWriteJSONAndHumanReportsShareVerifiedDigest(t *testing.T) {
	suite := sealedTestSuite(t)
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "report.json")
	junitPath := filepath.Join(dir, "junit.xml")
	markdownPath := filepath.Join(dir, "SUMMARY.md")
	if err := suite.WriteJSON(jsonPath); err != nil {
		t.Fatal(err)
	}
	if err := suite.WriteJUnit(junitPath); err != nil {
		t.Fatal(err)
	}
	if err := suite.WriteMarkdown(markdownPath); err != nil {
		t.Fatal(err)
	}

	document, err := ReadJSON(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	want, err := suite.ReportDigest()
	if err != nil {
		t.Fatal(err)
	}
	if document.ReportDigest != want {
		t.Fatalf("JSON digest=%q want %q", document.ReportDigest, want)
	}
	for _, path := range []string{junitPath, markdownPath} {
		encoded, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(encoded), want) {
			t.Fatalf("%s does not reference report digest %q", filepath.Base(path), want)
		}
	}

	document.Cases[0].Evidence["alpha"] = "tampered"
	tampered, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jsonPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadJSON(jsonPath); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("tampered report read error=%v, want digest mismatch", err)
	}

	inconsistent, err := suite.Document()
	if err != nil {
		t.Fatal(err)
	}
	inconsistent.Cases[0].Failure = "failure hidden behind a pass state"
	inconsistent.State = "pass"
	inconsistent.ReportDigest, err = inconsistent.computeDigest()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(inconsistent)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jsonPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadJSON(jsonPath); err == nil || !strings.Contains(err.Error(), "inconsistent with contents") {
		t.Fatalf("self-consistent digest hid a false PASS: %v", err)
	}
}

func TestInvocationSchemaV5SeparatesRequestFromExecutionDependencies(t *testing.T) {
	suite := sealedTestSuite(t)
	suite.Invocation.Scope = "exact"
	suite.Invocation.Case = "case.two"
	suite.Invocation.ResumeCaseID = "case.one"
	suite.Invocation.RequestedCaseIDs = []string{"case.two"}
	suite.Invocation.RequestAnchor = "case.two"
	if failure := invocationIdentityFailure(suite); failure != "" {
		t.Fatalf("valid exact request with execution prerequisite failed: %s", failure)
	}

	tests := []struct {
		name   string
		mutate func(*Invocation)
		want   string
	}{
		{name: "missing requested set", mutate: func(inv *Invocation) { inv.RequestedCaseIDs = nil }, want: "requested case IDs are missing"},
		{name: "requested row not executed", mutate: func(inv *Invocation) { inv.RequestedCaseIDs = []string{"missing"} }, want: "not in the execution case IDs"},
		{name: "missing anchor", mutate: func(inv *Invocation) { inv.RequestAnchor = "" }, want: "request anchor is missing"},
		{name: "wrong exact request", mutate: func(inv *Invocation) { inv.RequestedCaseIDs = []string{"case.one"} }, want: "exact scope must request only its case"},
		{name: "wrong exact anchor", mutate: func(inv *Invocation) { inv.RequestAnchor = "case.one" }, want: "exact request anchor does not match"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate := sealedTestSuite(t)
			candidate.Invocation = suite.Invocation
			candidate.Invocation.SelectedCaseIDs = append([]string(nil), suite.Invocation.SelectedCaseIDs...)
			candidate.Invocation.RequestedCaseIDs = append([]string(nil), suite.Invocation.RequestedCaseIDs...)
			tt.mutate(&candidate.Invocation)
			if failure := invocationIdentityFailure(candidate); !strings.Contains(failure, tt.want) {
				t.Fatalf("failure=%q want substring %q", failure, tt.want)
			}
		})
	}
	missingRowDigest := sealedTestSuite(t)
	missingRowDigest.Cases[0].CaseDigest = ""
	if failure := invocationIdentityFailure(missingRowDigest); !strings.Contains(failure, "case digest is missing") {
		t.Fatalf("missing row digest failure=%q", failure)
	}
}

func sealedTestSuite(t *testing.T) *Suite {
	t.Helper()
	invocation := validV2TestInvocation("case.one", "case.two")
	invocation.SchemaVersion = 5
	invocation.EvidenceClass = "legacy_regression_component_not_v1_release_manifest"
	invocation.AllowNonLinux = true
	invocation.RequestedCaseIDs = []string{"case.one", "case.two"}
	invocation.RequestAnchor = "case.one"
	environment := validReportEnvironment(t, `[{"kind":"fq_codel"}]`)
	invocation.EnvironmentStart = environment
	invocation.EnvironmentEnd = environment
	suite := &Suite{
		Started:    time.Date(2026, time.August, 3, 12, 0, 0, 123, time.UTC),
		Invocation: invocation,
		Complete:   true,
		Cases: []Case{
			{Name: "case.one", Tier: "T1", CaseDigest: "sha256:" + strings.Repeat("1", 64), Duration: time.Second, Evidence: map[string]string{"alpha": "first", "zeta": "last"}},
			{Name: "case.two", Tier: "T1", CaseDigest: "sha256:" + strings.Repeat("2", 64), Duration: 2 * time.Second, Evidence: map[string]string{"count": "2"}},
		},
	}
	return suite
}
