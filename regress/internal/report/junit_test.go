package report

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FrankoonG/rendr/regress/internal/environment"
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

func TestInvocationSchemaV2IsRecordedInJUnitAndMarkdown(t *testing.T) {
	s := New()
	s.Complete = true
	s.Invocation = validV2TestInvocation("T7.case.one", "T7.case.two")
	s.Invocation.Scope = "from-case"
	s.Invocation.Phase = "2"
	s.Invocation.Tier = "7"
	s.Invocation.Full = true
	s.Invocation.TUNFull = true
	s.Invocation.FromCase = "requested.resume.alias"
	s.Invocation.ResumeCaseID = "T7.case.one"
	s.Add(Case{Name: "T7.case.one", Tier: "T7"})
	s.Add(Case{Name: "T7.case.two", Tier: "T7"})

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

	var root struct {
		Schema          int    `xml:"invocation_schema,attr"`
		Phase           string `xml:"invocation_phase,attr"`
		Tier            string `xml:"invocation_tier,attr"`
		Full            bool   `xml:"invocation_full,attr"`
		TUNFull         bool   `xml:"invocation_tun_full,attr"`
		FromCase        string `xml:"invocation_from_case,attr"`
		ResumeCaseID    string `xml:"invocation_resume_case_id,attr"`
		CatalogDigest   string `xml:"catalog_digest,attr"`
		SelectedCaseIDs string `xml:"selected_case_ids,attr"`
	}
	if err := xml.Unmarshal(junit, &root); err != nil {
		t.Fatal(err)
	}
	if root.Schema != 2 || root.Phase != "2" || root.Tier != "7" || !root.Full || !root.TUNFull {
		t.Fatalf("JUnit selection dimensions = %+v", root)
	}
	if root.FromCase != "requested.resume.alias" || root.ResumeCaseID != "T7.case.one" {
		t.Fatalf("JUnit resume identity = %+v", root)
	}
	if root.CatalogDigest != "sha256:"+strings.Repeat("c", 64) {
		t.Fatalf("JUnit catalog digest = %q", root.CatalogDigest)
	}
	if root.SelectedCaseIDs != `["T7.case.one","T7.case.two"]` {
		t.Fatalf("JUnit selected CaseIDs = %q", root.SelectedCaseIDs)
	}

	for _, want := range []string{
		"- Schema version: `2`",
		"- Phase: `2`",
		"- Tier: `7`",
		"- Full: `true`",
		"- TUN full: `true`",
		"- From case: `requested.resume.alias`",
		"- Resume CaseID: `T7.case.one`",
		"- Catalog digest: `sha256:" + strings.Repeat("c", 64) + "`",
		"- Selected CaseIDs (ordered): `[\"T7.case.one\",\"T7.case.two\"]`",
	} {
		if !strings.Contains(string(markdown), want) {
			t.Fatalf("Markdown missing %q:\n%s", want, markdown)
		}
	}
}

func TestInvocationSchemaV2Validation(t *testing.T) {
	valid := validV2TestInvocation("case.one", "case.two")
	valid.Scope = "from-case"
	valid.FromCase = "case.two"
	valid.ResumeCaseID = "case.one"

	tests := []struct {
		name   string
		mutate func(*Invocation)
		want   string
	}{
		{
			name: "manifest digest is not sha256",
			mutate: func(inv *Invocation) {
				inv.ManifestDigest = "sha1:" + strings.Repeat("a", 40)
			},
			want: "selected manifest digest is missing or malformed",
		},
		{
			name: "catalog digest is not sha256",
			mutate: func(inv *Invocation) {
				inv.CatalogDigest = "sha1:" + strings.Repeat("c", 40)
			},
			want: "catalog digest is missing or malformed",
		},
		{
			name: "selected IDs are missing",
			mutate: func(inv *Invocation) {
				inv.SelectedCaseIDs = nil
			},
			want: "selected case IDs are missing",
		},
		{
			name: "selected ID is empty",
			mutate: func(inv *Invocation) {
				inv.SelectedCaseIDs[1] = " "
			},
			want: "selected case ID at index 1 is empty",
		},
		{
			name: "selected ID count differs",
			mutate: func(inv *Invocation) {
				inv.SelectedCases = 1
			},
			want: "selected case ID count 2 does not match selected case count 1",
		},
		{
			name: "selected ID is duplicated",
			mutate: func(inv *Invocation) {
				inv.SelectedCaseIDs[1] = inv.SelectedCaseIDs[0]
			},
			want: `selected case ID "case.one" is duplicated`,
		},
		{
			name: "canonical resume ID is missing",
			mutate: func(inv *Invocation) {
				inv.ResumeCaseID = ""
			},
			want: "canonical resume case ID is missing",
		},
		{
			name: "canonical resume ID is not first",
			mutate: func(inv *Invocation) {
				inv.ResumeCaseID = "case.two"
			},
			want: "canonical resume case ID is not the first selected case ID",
		},
		{
			name: "exact case is not selected",
			mutate: func(inv *Invocation) {
				inv.Scope = "exact"
				inv.Case = "case.missing"
				inv.FromCase = ""
			},
			want: `exact case "case.missing" is not in the selected case IDs`,
		},
		{
			name: "from-case is not selected",
			mutate: func(inv *Invocation) {
				inv.FromCase = "case.missing"
			},
			want: `from-case "case.missing" is not in the selected case IDs`,
		},
		{
			name: "exact scope has from-case filter",
			mutate: func(inv *Invocation) {
				inv.Scope = "exact"
				inv.Case = "case.two"
			},
			want: "exact scope unexpectedly has a from-case filter",
		},
		{
			name: "unfiltered scope has case filter",
			mutate: func(inv *Invocation) {
				inv.Scope = "full"
				inv.Case = "case.two"
				inv.FromCase = ""
			},
			want: `scope "full" unexpectedly has a case filter`,
		},
	}

	if failure := invocationIdentityFailure(&Suite{Invocation: valid}); failure != "" {
		t.Fatalf("valid v2 invocation failed validation: %s", failure)
	}
	exactWithPrerequisite := valid
	exactWithPrerequisite.Scope = "exact"
	exactWithPrerequisite.Case = "case.two"
	exactWithPrerequisite.FromCase = ""
	if failure := invocationIdentityFailure(&Suite{Invocation: exactWithPrerequisite}); failure != "" {
		t.Fatalf("valid exact invocation with prerequisite failed validation: %s", failure)
	}
	selectorWithPrerequisite := exactWithPrerequisite
	selectorWithPrerequisite.Scope = "selector"
	selectorWithPrerequisite.Case = "requested.selector.alias"
	if failure := invocationIdentityFailure(&Suite{Invocation: selectorWithPrerequisite}); failure != "" {
		t.Fatalf("valid selector invocation with prerequisite failed validation: %s", failure)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inv := valid
			inv.SelectedCaseIDs = append([]string(nil), valid.SelectedCaseIDs...)
			tt.mutate(&inv)
			failure := invocationIdentityFailure(&Suite{Invocation: inv})
			if !strings.Contains(failure, tt.want) {
				t.Fatalf("invocationIdentityFailure() = %q, want substring %q", failure, tt.want)
			}
		})
	}

	complete := Suite{
		Invocation: valid,
		Complete:   true,
		Cases:      []Case{{Name: "case.one"}, {Name: "wrong.row"}},
	}
	complete.Invocation.RevisionEnd = complete.Invocation.RevisionStart
	if failure := invocationIdentityFailure(&complete); !strings.Contains(failure, `selected case ID "case.two" does not match report row 1 name "wrong.row"`) {
		t.Fatalf("complete row mismatch failure = %q", failure)
	}
}

func TestInvocationSchemaV3EnvironmentIsRecordedInJUnitAndMarkdown(t *testing.T) {
	snapshot := validReportEnvironment(t, `[{"dev":"test0","kind":"fq_codel"}]`)
	s := New()
	s.Complete = true
	s.Invocation = validV2TestInvocation("case.one")
	s.Invocation.SchemaVersion = 3
	s.Invocation.AllowNonLinux = true
	s.Invocation.EnvironmentStart = snapshot
	s.Invocation.EnvironmentEnd = snapshot
	s.Add(Case{Name: "case.one", Tier: "T1"})

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

	var root struct {
		Schema        int    `xml:"invocation_schema,attr"`
		AllowNonLinux bool   `xml:"invocation_allow_non_linux,attr"`
		StartID       string `xml:"environment_start_identity,attr"`
		EndID         string `xml:"environment_end_identity,attr"`
		QDiscStart    string `xml:"qdisc_start_digest,attr"`
		QDiscEnd      string `xml:"qdisc_end_digest,attr"`
		Properties    struct {
			Items []struct {
				Name  string `xml:"name,attr"`
				Value string `xml:"value,attr"`
			} `xml:"property"`
		} `xml:"properties"`
	}
	if err := xml.Unmarshal(junit, &root); err != nil {
		t.Fatal(err)
	}
	if root.Schema != 3 || !root.AllowNonLinux || root.StartID != snapshot.IdentityDigest || root.EndID != snapshot.IdentityDigest {
		t.Fatalf("JUnit environment identity = %+v", root)
	}
	if root.QDiscStart != snapshot.QDisc.Digest || root.QDiscEnd != snapshot.QDisc.Digest {
		t.Fatalf("JUnit qdisc digests = start %q end %q", root.QDiscStart, root.QDiscEnd)
	}
	if len(root.Properties.Items) != 2 || root.Properties.Items[0].Name != "rendr.environment.start" || root.Properties.Items[1].Name != "rendr.environment.end" {
		t.Fatalf("JUnit environment properties = %+v", root.Properties.Items)
	}
	for _, property := range root.Properties.Items {
		if !strings.Contains(property.Value, `"hostname":"synthetic-host"`) || !strings.Contains(property.Value, `"vm_role":"client"`) {
			t.Fatalf("JUnit property %q lacks structured provenance: %s", property.Name, property.Value)
		}
	}
	for _, want := range []string{"- Allow non-Linux: `true`", "## Environment", "### Start", "### End", `"qdisc"`, `"vm_role":"client"`} {
		if !strings.Contains(string(markdown), want) {
			t.Fatalf("Markdown missing %q:\n%s", want, markdown)
		}
	}
}

func TestInvocationSchemaV3EnvironmentValidation(t *testing.T) {
	start := validReportEnvironment(t, `[{"dev":"test0","kind":"fq_codel"}]`)
	valid := validV2TestInvocation("case.one")
	valid.SchemaVersion = 3
	valid.AllowNonLinux = true
	valid.EnvironmentStart = start
	valid.EnvironmentEnd = start
	complete := func(inv Invocation) *Suite {
		return &Suite{Invocation: inv, Complete: true, Cases: []Case{{Name: "case.one"}}}
	}
	if failure := invocationIdentityFailure(complete(valid)); failure != "" {
		t.Fatalf("valid v3 invocation failed: %s", failure)
	}

	tests := []struct {
		name   string
		mutate func(*Invocation)
		want   string
	}{
		{
			name: "non-Linux bypass missing",
			mutate: func(inv *Invocation) {
				inv.AllowNonLinux = false
			},
			want: "non-Linux environment is missing the allow-non-linux bypass",
		},
		{
			name: "missing start",
			mutate: func(inv *Invocation) {
				inv.EnvironmentStart = environment.Snapshot{}
			},
			want: "start environment snapshot is missing",
		},
		{
			name: "missing end",
			mutate: func(inv *Invocation) {
				inv.EnvironmentEnd = environment.Snapshot{}
			},
			want: "end environment snapshot is missing",
		},
		{
			name: "stable identity drift",
			mutate: func(inv *Invocation) {
				drifted := inv.EnvironmentEnd
				drifted.Hostname = "other-host"
				inv.EnvironmentEnd = sealReportEnvironment(t, drifted)
			},
			want: "stable environment identity changed",
		},
		{
			name: "qdisc not restored",
			mutate: func(inv *Invocation) {
				inv.EnvironmentEnd = validReportEnvironment(t, `[{"dev":"test0","kind":"netem"}]`)
			},
			want: "qdisc state was not restored",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inv := valid
			tt.mutate(&inv)
			if failure := invocationIdentityFailure(complete(inv)); !strings.Contains(failure, tt.want) {
				t.Fatalf("validation failure = %q want substring %q", failure, tt.want)
			}
		})
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

func validV2TestInvocation(selectedCaseIDs ...string) Invocation {
	revision := Revision{CommitSHA: "commit", WorktreeSHA: "worktree"}
	invocation := Invocation{
		SchemaVersion:   2,
		Suite:           "normal",
		Scope:           "full",
		ManifestDigest:  "sha256:" + strings.Repeat("a", 64),
		CatalogDigest:   "sha256:" + strings.Repeat("c", 64),
		SelectedCases:   len(selectedCaseIDs),
		SelectedCaseIDs: append([]string(nil), selectedCaseIDs...),
		RevisionStart:   revision,
		RevisionEnd:     revision,
	}
	if len(selectedCaseIDs) != 0 {
		invocation.ResumeCaseID = selectedCaseIDs[0]
	}
	return invocation
}

func validReportEnvironment(t *testing.T, qdisc string) environment.Snapshot {
	t.Helper()
	return sealReportEnvironment(t, environment.Snapshot{
		SchemaVersion: environment.SnapshotSchemaVersion,
		Runtime: environment.Runtime{
			GoVersion: "go1.26.3",
			GOOS:      "windows",
			GOARCH:    "amd64",
		},
		Hostname:   "synthetic-host",
		NumCPU:     4,
		Interfaces: []environment.Interface{{Name: "test0", MTU: 1500}},
		QDisc:      environment.QDisc{Supported: true, State: []byte(qdisc)},
		Metadata:   environment.Metadata{VMRole: "client", CPUGroup: "CPU1/128-255"},
	})
}

func sealReportEnvironment(t *testing.T, snapshot environment.Snapshot) environment.Snapshot {
	t.Helper()
	sealed, err := environment.Seal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}
