package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSuiteFailureSemantics(t *testing.T) {
	tests := []struct {
		name string
		c    Case
		fail bool
	}{
		{name: "pass", c: Case{Name: "pass", Tier: "T"}},
		{name: "failure", c: Case{Name: "failure", Tier: "T", Failure: "boom"}, fail: true},
		{name: "invalid", c: Case{Name: "invalid", Tier: "T", InvalidReason: "stimulus missing"}, fail: true},
		{name: "mandatory skip", c: Case{Name: "skip", Tier: "T", SkipReason: "dependency missing"}, fail: true},
		{name: "optional skip", c: Case{Name: "optional", Tier: "T", SkipReason: "not requested", Optional: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New()
			s.Add(tt.c)
			if got := s.AnyFailed(); got != tt.fail {
				t.Fatalf("AnyFailed()=%v want %v", got, tt.fail)
			}
			if got := s.AnyFailedAt("T"); got != tt.fail {
				t.Fatalf("AnyFailedAt()=%v want %v", got, tt.fail)
			}
		})
	}
}

func TestMandatorySkipAndInvalidAreJUnitFailures(t *testing.T) {
	s := New()
	s.Add(Case{Name: "skip", Tier: "T", SkipReason: "missing"})
	s.Add(Case{Name: "invalid", Tier: "T", InvalidReason: "no stimulus"})
	s.Add(Case{Name: "optional", Tier: "T", SkipReason: "not selected", Optional: true})

	path := filepath.Join(t.TempDir(), "junit.xml")
	if err := s.WriteJUnit(path); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, want := range []string{`failures="2"`, `skipped="1"`, `message="mandatory case skipped"`, `message="invalid"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("JUnit missing %q:\n%s", want, text)
		}
	}
}

func TestEvidenceIsDeterministicInJUnitAndMarkdown(t *testing.T) {
	s := New()
	s.Complete = true
	s.Invocation = validTestInvocation(1)
	s.Add(Case{
		Name: "evidence|case",
		Tier: "T",
		Evidence: map[string]string{
			"zeta":  "last",
			"alpha": "first|value",
		},
	})
	dir := t.TempDir()
	junitPath := filepath.Join(dir, "junit.xml")
	markdownPath := filepath.Join(dir, "SUMMARY.md")
	if err := s.WriteJUnit(junitPath); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteMarkdown(markdownPath); err != nil {
		t.Fatal(err)
	}
	junit, err := os.ReadFile(junitPath)
	if err != nil {
		t.Fatal(err)
	}
	markdown, err := os.ReadFile(markdownPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(junit), "<system-out>alpha=first|value&#xA;zeta=last</system-out>") {
		t.Fatalf("JUnit evidence is absent or unordered:\n%s", junit)
	}
	if !strings.Contains(string(markdown), `evidence\|case`) || !strings.Contains(string(markdown), `alpha=first\|value; zeta=last`) {
		t.Fatalf("Markdown evidence is absent, unordered, or unescaped:\n%s", markdown)
	}
}

func TestIncompleteGreenReportIsPartial(t *testing.T) {
	s := New()
	s.Invocation = Invocation{
		SchemaVersion:  1,
		Suite:          "normal",
		Scope:          "exact",
		Case:           "green",
		ManifestDigest: "sha256:" + strings.Repeat("a", 64),
		SelectedCases:  1,
		RevisionStart:  Revision{CommitSHA: "commit", WorktreeSHA: "tree"},
	}
	s.Add(Case{Name: "green", Tier: "T"})
	dir := t.TempDir()
	junitPath := filepath.Join(dir, "junit.xml")
	markdownPath := filepath.Join(dir, "SUMMARY.md")
	if err := s.WriteJUnit(junitPath); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteMarkdown(markdownPath); err != nil {
		t.Fatal(err)
	}
	junit, _ := os.ReadFile(junitPath)
	markdown, _ := os.ReadFile(markdownPath)
	for _, want := range []string{
		`state="partial"`,
		`complete="false"`,
		`failures="1"`,
		`name="invocation-complete"`,
		`selected manifest did not complete`,
	} {
		if !strings.Contains(string(junit), want) {
			t.Fatalf("JUnit missing %q:\n%s", want, junit)
		}
	}
	if !strings.Contains(string(markdown), "**OVERALL: PARTIAL**") || strings.Contains(string(markdown), "**OVERALL: PASS**") {
		t.Fatalf("Markdown partial state is wrong:\n%s", markdown)
	}
	if !strings.Contains(string(markdown), "- Complete: `false`") {
		t.Fatalf("Markdown hides incomplete invocation:\n%s", markdown)
	}

	s.Complete = true
	s.Invocation.RevisionEnd = s.Invocation.RevisionStart
	if err := s.WriteJUnit(junitPath); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteMarkdown(markdownPath); err != nil {
		t.Fatal(err)
	}
	junit, _ = os.ReadFile(junitPath)
	if strings.Contains(string(junit), `name="invocation-complete"`) || !strings.Contains(string(junit), `failures="0"`) {
		t.Fatalf("complete JUnit retained the partial failure:\n%s", junit)
	}
	markdown, _ = os.ReadFile(markdownPath)
	if !strings.Contains(string(markdown), "**OVERALL: PASS**") {
		t.Fatalf("complete report did not pass:\n%s", markdown)
	}
}

func TestInvocationIdentityIsRecordedInJUnitAndMarkdown(t *testing.T) {
	s := New()
	s.Complete = true
	s.Invocation = Invocation{
		SchemaVersion:  1,
		Suite:          "tun-full",
		Scope:          "from-case",
		FromCase:       "TUN.case.two",
		Forced:         true,
		ManifestDigest: "sha256:" + strings.Repeat("b", 64),
		SelectedCases:  2,
		RevisionStart:  Revision{CommitSHA: "start-commit", WorktreeSHA: "start-tree"},
		RevisionEnd:    Revision{CommitSHA: "start-commit", WorktreeSHA: "start-tree"},
	}
	s.Add(Case{Name: "TUN.case.two", Tier: "T7"})

	dir := t.TempDir()
	junitPath := filepath.Join(dir, "junit.xml")
	markdownPath := filepath.Join(dir, "SUMMARY.md")
	if err := s.WriteJUnit(junitPath); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteMarkdown(markdownPath); err != nil {
		t.Fatal(err)
	}
	junit, err := os.ReadFile(junitPath)
	if err != nil {
		t.Fatal(err)
	}
	markdown, err := os.ReadFile(markdownPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`name="rendr-regression/tun-full/from-case"`,
		`complete="true"`,
		`invocation_suite="tun-full"`,
		`invocation_scope="from-case"`,
		`invocation_from_case="TUN.case.two"`,
		`invocation_forced="true"`,
		`manifest_digest="sha256:` + strings.Repeat("b", 64) + `"`,
		`revision_start_commit="start-commit"`,
		`revision_end_worktree="start-tree"`,
	} {
		if !strings.Contains(string(junit), want) {
			t.Fatalf("JUnit missing %q:\n%s", want, junit)
		}
	}
	for _, want := range []string{
		"- Suite: `tun-full`",
		"- Scope: `from-case`",
		"- From case: `TUN.case.two`",
		"- Forced: `true`",
		"- Manifest digest: `sha256:" + strings.Repeat("b", 64) + "`",
		"- Complete: `true`",
	} {
		if !strings.Contains(string(markdown), want) {
			t.Fatalf("Markdown missing %q:\n%s", want, markdown)
		}
	}
}

func TestRunFailureIsAStandardJUnitFailure(t *testing.T) {
	s := New()
	s.Complete = true
	s.Invocation = validTestInvocation(1)
	s.Add(Case{Name: "green", Tier: "T"})
	s.FailRun("worktree changed during invocation")
	path := filepath.Join(t.TempDir(), "junit.xml")
	if err := s.WriteJUnit(path); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, want := range []string{`state="fail"`, `failures="1"`, `name="invocation-complete"`, "worktree changed during invocation"} {
		if !strings.Contains(text, want) {
			t.Fatalf("JUnit missing %q:\n%s", want, text)
		}
	}
}

func TestCompleteReportWithoutInvocationIdentityFailsClosed(t *testing.T) {
	s := New()
	s.Complete = true
	s.Add(Case{Name: "green", Tier: "T"})
	path := filepath.Join(t.TempDir(), "junit.xml")
	if err := s.WriteJUnit(path); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, want := range []string{`state="fail"`, `failures="1"`, "invocation schema is missing", "start revision is incomplete"} {
		if !strings.Contains(text, want) {
			t.Fatalf("JUnit missing %q:\n%s", want, text)
		}
	}
}

func TestAtomicWriteReplacesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.txt")
	if err := os.WriteFile(path, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(path, []byte("complete")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "complete" {
		t.Fatalf("contents=%q want complete", got)
	}
}

func TestMarkdownIncludesBoundedSingleLineFailure(t *testing.T) {
	s := New()
	s.Complete = true
	s.Invocation = validTestInvocation(1)
	s.Cases = []Case{{Name: "broken", Tier: "T1", Failure: "first line\n" + strings.Repeat("x", 700)}}
	s.Invocation.SelectedCases = 1
	path := filepath.Join(t.TempDir(), "SUMMARY.md")
	if err := s.WriteMarkdown(path); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !strings.Contains(text, "FAIL: first line ") || !strings.Contains(text, "...") {
		t.Fatalf("failure summary missing or unbounded:\n%s", text)
	}
}

func validTestInvocation(selected int) Invocation {
	revision := Revision{CommitSHA: "commit", WorktreeSHA: "worktree"}
	return Invocation{
		SchemaVersion:  1,
		Suite:          "normal",
		Scope:          "full",
		ManifestDigest: "sha256:" + strings.Repeat("a", 64),
		SelectedCases:  selected,
		RevisionStart:  revision,
		RevisionEnd:    revision,
	}
}
