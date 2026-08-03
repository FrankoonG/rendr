// Package report writes JUnit XML and a Markdown summary for the
// regress suite. The schema is the de-facto Surefire-compatible
// subset that GitHub Actions, Jenkins and most CI dashboards render
// without configuration.
package report

import (
	"bytes"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Case is one regress case (e.g. T1.go-vet, T2.G1-smoke, T3.stream.D-1×D-2).
type Case struct {
	Name     string
	Tier     string
	Duration time.Duration
	// Empty Failure => pass.
	Failure string
	// InvalidReason means the harness could not prove that the stimulus,
	// offered load, or oracle was valid. Invalid is always a failure.
	InvalidReason string
	// SkipReason set => the case was skipped (e.g. T5 adapter missing).
	// Skips fail by default; Optional must be explicit for a non-blocking skip.
	SkipReason string
	Optional   bool
	// Evidence records machine-produced stimulus, load, and oracle facts.
	// Writers sort keys so reports are deterministic.
	Evidence map[string]string
}

// Revision identifies one exact repository state. CommitSHA identifies HEAD;
// WorktreeSHA additionally covers tracked edits and non-ignored untracked
// files.
type Revision struct {
	CommitSHA   string
	WorktreeSHA string
}

// Invocation identifies the selected work represented by a report. Consumers
// must check Suite, Scope, ManifestDigest, and Complete before treating a green
// report as evidence for a release gate.
type Invocation struct {
	SchemaVersion  int
	Suite          string
	Scope          string
	Case           string
	FromCase       string
	Forced         bool
	ManifestDigest string
	SelectedCases  int
	RevisionStart  Revision
	RevisionEnd    Revision
}

// Suite collects cases across tiers and writes the final report.
type Suite struct {
	Started    time.Time
	Cases      []Case
	Invocation Invocation
	// RunFailure records a harness-level failure without changing the selected
	// manifest rows or their order.
	RunFailure string
	// Complete is set only after every case in the selected manifest has
	// been reconciled. A green but incomplete report is PARTIAL, never PASS.
	Complete bool
}

func New() *Suite { return &Suite{Started: time.Now()} }

// Add records one case outcome.
func (s *Suite) Add(c Case) { s.Cases = append(s.Cases, c) }

// FailRun records a harness-level failure. Multiple failures are retained in
// order so a later report write does not hide the first cause.
func (s *Suite) FailRun(reason string) {
	if reason == "" {
		return
	}
	if s.RunFailure == "" {
		s.RunFailure = reason
		return
	}
	s.RunFailure += "\n" + reason
}

func (c Case) failed() bool {
	return c.Failure != "" || c.InvalidReason != "" || (c.SkipReason != "" && !c.Optional)
}

// AnyFailed reports whether any case failed, was invalid, or was
// mandatorily skipped.
func (s *Suite) AnyFailed() bool {
	if s.RunFailure != "" {
		return true
	}
	for _, c := range s.Cases {
		if c.failed() {
			return true
		}
	}
	return false
}

// AnyFailedAt returns true if any case in tierPrefix failed (e.g. "T1").
func (s *Suite) AnyFailedAt(tierPrefix string) bool {
	for _, c := range s.Cases {
		if c.Tier == tierPrefix && c.failed() {
			return true
		}
	}
	return false
}

type xmlSuites struct {
	XMLName             xml.Name   `xml:"testsuites"`
	Name                string     `xml:"name,attr"`
	State               string     `xml:"state,attr"`
	Complete            bool       `xml:"complete,attr"`
	InvocationSchema    int        `xml:"invocation_schema,attr"`
	InvocationSuite     string     `xml:"invocation_suite,attr"`
	InvocationScope     string     `xml:"invocation_scope,attr"`
	InvocationCase      string     `xml:"invocation_case,attr,omitempty"`
	InvocationFromCase  string     `xml:"invocation_from_case,attr,omitempty"`
	InvocationForced    bool       `xml:"invocation_forced,attr"`
	ManifestDigest      string     `xml:"manifest_digest,attr"`
	SelectedCases       int        `xml:"selected_cases,attr"`
	RevisionStartCommit string     `xml:"revision_start_commit,attr"`
	RevisionStartTree   string     `xml:"revision_start_worktree,attr"`
	RevisionEndCommit   string     `xml:"revision_end_commit,attr"`
	RevisionEndTree     string     `xml:"revision_end_worktree,attr"`
	Time                float64    `xml:"time,attr"`
	Tests               int        `xml:"tests,attr"`
	Failures            int        `xml:"failures,attr"`
	Skipped             int        `xml:"skipped,attr"`
	Suites              []xmlSuite `xml:"testsuite"`
}

type xmlSuite struct {
	XMLName  xml.Name  `xml:"testsuite"`
	Name     string    `xml:"name,attr"`
	Tests    int       `xml:"tests,attr"`
	Failures int       `xml:"failures,attr"`
	Skipped  int       `xml:"skipped,attr"`
	Time     float64   `xml:"time,attr"`
	Cases    []xmlCase `xml:"testcase"`
}

type xmlCase struct {
	XMLName   xml.Name    `xml:"testcase"`
	Name      string      `xml:"name,attr"`
	Classname string      `xml:"classname,attr"`
	Time      float64     `xml:"time,attr"`
	Failure   *xmlFailure `xml:"failure,omitempty"`
	Skipped   *xmlSkipped `xml:"skipped,omitempty"`
	SystemOut string      `xml:"system-out,omitempty"`
}

type xmlFailure struct {
	Message string `xml:"message,attr"`
	Body    string `xml:",chardata"`
}

type xmlSkipped struct {
	Message string `xml:"message,attr"`
}

// WriteJUnit emits JUnit XML at path. Tier grouping = testsuite name.
func (s *Suite) WriteJUnit(path string) error {
	byTier := map[string][]Case{}
	tierOrder := []string{}
	for _, c := range s.Cases {
		if _, ok := byTier[c.Tier]; !ok {
			tierOrder = append(tierOrder, c.Tier)
		}
		byTier[c.Tier] = append(byTier[c.Tier], c)
	}

	out := xmlSuites{
		Name:                invocationName(s.Invocation),
		State:               reportState(s),
		Complete:            s.Complete,
		InvocationSchema:    s.Invocation.SchemaVersion,
		InvocationSuite:     s.Invocation.Suite,
		InvocationScope:     s.Invocation.Scope,
		InvocationCase:      s.Invocation.Case,
		InvocationFromCase:  s.Invocation.FromCase,
		InvocationForced:    s.Invocation.Forced,
		ManifestDigest:      s.Invocation.ManifestDigest,
		SelectedCases:       s.Invocation.SelectedCases,
		RevisionStartCommit: s.Invocation.RevisionStart.CommitSHA,
		RevisionStartTree:   s.Invocation.RevisionStart.WorktreeSHA,
		RevisionEndCommit:   s.Invocation.RevisionEnd.CommitSHA,
		RevisionEndTree:     s.Invocation.RevisionEnd.WorktreeSHA,
		Time:                time.Since(s.Started).Seconds(),
	}
	for _, tier := range tierOrder {
		cs := byTier[tier]
		xs := xmlSuite{Name: tier}
		for _, c := range cs {
			xc := xmlCase{
				Name:      c.Name,
				Classname: tier,
				Time:      c.Duration.Seconds(),
			}
			xs.Tests++
			out.Tests++
			if c.InvalidReason != "" {
				xc.Failure = &xmlFailure{Message: "invalid", Body: c.InvalidReason}
				xs.Failures++
				out.Failures++
			} else if c.SkipReason != "" && c.Optional {
				xc.Skipped = &xmlSkipped{Message: c.SkipReason}
				xs.Skipped++
				out.Skipped++
			} else if c.SkipReason != "" {
				xc.Failure = &xmlFailure{Message: "mandatory case skipped", Body: c.SkipReason}
				xs.Failures++
				out.Failures++
			} else if c.Failure != "" {
				xc.Failure = &xmlFailure{Message: "failed", Body: c.Failure}
				xs.Failures++
				out.Failures++
			}
			xc.SystemOut = formatEvidence(c.Evidence, "=", "\n")
			xs.Time += c.Duration.Seconds()
			xs.Cases = append(xs.Cases, xc)
		}
		out.Suites = append(out.Suites, xs)
	}
	if reason := invocationFailure(s); reason != "" {
		xs := xmlSuite{
			Name:     "invocation",
			Tests:    1,
			Failures: 1,
			Cases: []xmlCase{{
				Name:      "invocation-complete",
				Classname: "rendr.regress.invocation",
				Failure:   &xmlFailure{Message: "regression invocation is not valid evidence", Body: reason},
				SystemOut: formatInvocation(s.Invocation),
			}},
		}
		out.Tests++
		out.Failures++
		out.Suites = append(out.Suites, xs)
	}

	var buf bytes.Buffer
	if _, err := io.WriteString(&buf, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(&buf)
	enc.Indent("", "  ")
	if err := enc.Encode(out); err != nil {
		return err
	}
	if _, err := io.WriteString(&buf, "\n"); err != nil {
		return err
	}
	return writeAtomic(path, buf.Bytes())
}

// WriteMarkdown emits a human-readable SUMMARY.md.
func (s *Suite) WriteMarkdown(path string) error {
	var buf bytes.Buffer

	fmt.Fprintf(&buf, "# rendr regression — %s\n\n", s.Started.UTC().Format(time.RFC3339))
	fmt.Fprintf(&buf, "State: %s\n\n", reportState(s))
	fmt.Fprintln(&buf, "## Invocation")
	fmt.Fprintln(&buf)
	fmt.Fprintf(&buf, "- Suite: `%s`\n", escapeMarkdown(s.Invocation.Suite))
	fmt.Fprintf(&buf, "- Scope: `%s`\n", escapeMarkdown(s.Invocation.Scope))
	if s.Invocation.Case != "" {
		fmt.Fprintf(&buf, "- Case: `%s`\n", escapeMarkdown(s.Invocation.Case))
	}
	if s.Invocation.FromCase != "" {
		fmt.Fprintf(&buf, "- From case: `%s`\n", escapeMarkdown(s.Invocation.FromCase))
	}
	fmt.Fprintf(&buf, "- Forced: `%t`\n", s.Invocation.Forced)
	fmt.Fprintf(&buf, "- Manifest digest: `%s`\n", escapeMarkdown(s.Invocation.ManifestDigest))
	fmt.Fprintf(&buf, "- Selected cases: `%d`\n", s.Invocation.SelectedCases)
	fmt.Fprintf(&buf, "- Revision start: `%s`\n", escapeMarkdown(formatRevision(s.Invocation.RevisionStart)))
	fmt.Fprintf(&buf, "- Revision end: `%s`\n", escapeMarkdown(formatRevision(s.Invocation.RevisionEnd)))
	fmt.Fprintf(&buf, "- Complete: `%t`\n", s.Complete)
	if s.RunFailure != "" {
		fmt.Fprintf(&buf, "- Invocation failure: `%s`\n", escapeMarkdown(s.RunFailure))
	}
	fmt.Fprintln(&buf)
	fmt.Fprintf(&buf, "Total elapsed: %s\n\n", time.Since(s.Started).Round(time.Millisecond))

	byTier := map[string][]Case{}
	tierOrder := []string{}
	for _, c := range s.Cases {
		if _, ok := byTier[c.Tier]; !ok {
			tierOrder = append(tierOrder, c.Tier)
		}
		byTier[c.Tier] = append(byTier[c.Tier], c)
	}

	for _, tier := range tierOrder {
		fmt.Fprintf(&buf, "## %s\n\n", tier)
		fmt.Fprintln(&buf, "| Case | Time | Result | Evidence |")
		fmt.Fprintln(&buf, "|------|------|--------|----------|")
		for _, c := range byTier[tier] {
			result := "OK"
			if c.InvalidReason != "" {
				result = "INVALID: " + c.InvalidReason
			} else if c.SkipReason != "" && c.Optional {
				result = "SKIP (optional): " + c.SkipReason
			} else if c.SkipReason != "" {
				result = "FAIL (mandatory skip): " + c.SkipReason
			} else if c.Failure != "" {
				result = "FAIL: " + compactDiagnostic(c.Failure, 512)
			}
			evidence := escapeMarkdown(formatEvidence(c.Evidence, "=", "; "))
			fmt.Fprintf(&buf, "| %s | %s | %s | %s |\n", escapeMarkdown(c.Name), c.Duration.Round(time.Millisecond), escapeMarkdown(result), evidence)
		}
		fmt.Fprintln(&buf)
	}

	overall := strings.ToUpper(reportState(s))
	fmt.Fprintf(&buf, "**OVERALL: %s**\n", overall)
	return writeAtomic(path, buf.Bytes())
}

func compactDiagnostic(value string, limit int) string {
	value = strings.Join(strings.Fields(strings.ToValidUTF8(value, "?")), " ")
	if limit <= 0 || len(value) <= limit {
		return value
	}
	const suffix = "..."
	if limit <= len(suffix) {
		return suffix[:limit]
	}
	return value[:limit-len(suffix)] + suffix
}

func reportState(s *Suite) string {
	if s.AnyFailed() {
		return "fail"
	}
	if invocationIdentityFailure(s) != "" {
		return "fail"
	}
	if !s.Complete {
		return "partial"
	}
	return "pass"
}

func invocationFailure(s *Suite) string {
	var reasons []string
	if s.RunFailure != "" {
		reasons = append(reasons, s.RunFailure)
	}
	if identityFailure := invocationIdentityFailure(s); identityFailure != "" {
		reasons = append(reasons, identityFailure)
	}
	if !s.Complete {
		reasons = append(reasons, "selected manifest did not complete")
	}
	return strings.Join(reasons, "\n")
}

func invocationIdentityFailure(s *Suite) string {
	inv := s.Invocation
	var reasons []string
	if inv.SchemaVersion <= 0 {
		reasons = append(reasons, "invocation schema is missing")
	}
	if inv.Suite == "" {
		reasons = append(reasons, "invocation suite is missing")
	}
	if inv.Scope == "" {
		reasons = append(reasons, "invocation scope is missing")
	}
	if !validManifestDigest(inv.ManifestDigest) {
		reasons = append(reasons, "selected manifest digest is missing or malformed")
	}
	if inv.SelectedCases <= 0 {
		reasons = append(reasons, "selected case count is missing")
	}
	if inv.RevisionStart.CommitSHA == "" || inv.RevisionStart.WorktreeSHA == "" {
		reasons = append(reasons, "start revision is incomplete")
	}
	if inv.Scope == "exact" && inv.Case == "" {
		reasons = append(reasons, "exact scope is missing its case")
	}
	if inv.Scope == "from-case" && inv.FromCase == "" {
		reasons = append(reasons, "from-case scope is missing its resume point")
	}
	if s.Complete {
		if inv.RevisionEnd.CommitSHA == "" || inv.RevisionEnd.WorktreeSHA == "" {
			reasons = append(reasons, "end revision is incomplete")
		} else if inv.RevisionStart != inv.RevisionEnd {
			reasons = append(reasons, "start and end revisions differ")
		}
		if inv.SelectedCases != len(s.Cases) {
			reasons = append(reasons, fmt.Sprintf("selected case count %d does not match report rows %d", inv.SelectedCases, len(s.Cases)))
		}
	}
	return strings.Join(reasons, "\n")
}

const sha256HexLength = 64

func validManifestDigest(digest string) bool {
	if len(digest) != len("sha256:")+sha256HexLength || !strings.HasPrefix(digest, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256:"))
	return err == nil
}

func invocationName(inv Invocation) string {
	parts := []string{"rendr-regression"}
	if inv.Suite != "" {
		parts = append(parts, inv.Suite)
	}
	if inv.Scope != "" {
		parts = append(parts, inv.Scope)
	}
	return strings.Join(parts, "/")
}

func formatInvocation(inv Invocation) string {
	fields := map[string]string{
		"forced":                  fmt.Sprintf("%t", inv.Forced),
		"invocation_schema":       fmt.Sprintf("%d", inv.SchemaVersion),
		"manifest_digest":         inv.ManifestDigest,
		"revision_end_commit":     inv.RevisionEnd.CommitSHA,
		"revision_end_worktree":   inv.RevisionEnd.WorktreeSHA,
		"revision_start_commit":   inv.RevisionStart.CommitSHA,
		"revision_start_worktree": inv.RevisionStart.WorktreeSHA,
		"scope":                   inv.Scope,
		"selected_cases":          fmt.Sprintf("%d", inv.SelectedCases),
		"suite":                   inv.Suite,
	}
	if inv.Case != "" {
		fields["case"] = inv.Case
	}
	if inv.FromCase != "" {
		fields["from_case"] = inv.FromCase
	}
	return formatEvidence(fields, "=", "\n")
}

func formatRevision(revision Revision) string {
	if revision.CommitSHA == "" && revision.WorktreeSHA == "" {
		return "pending"
	}
	return fmt.Sprintf("commit=%s worktree=%s", revision.CommitSHA, revision.WorktreeSHA)
}

func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err == nil {
		return nil
	}
	// Windows cannot replace an existing destination with Rename. Removing
	// the old report first leaves either the new complete file or no file;
	// it never leaves a truncated report that can masquerade as success.
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return nil
}

func formatEvidence(evidence map[string]string, assignment, separator string) string {
	if len(evidence) == 0 {
		return ""
	}
	keys := make([]string, 0, len(evidence))
	for key := range evidence {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+assignment+evidence[key])
	}
	return strings.Join(parts, separator)
}

func escapeMarkdown(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\r", " ")
	return strings.ReplaceAll(value, "\n", " ")
}
