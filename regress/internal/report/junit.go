// Package report writes JUnit XML and a Markdown summary for the
// regress suite. The schema is the de-facto Surefire-compatible
// subset that GitHub Actions, Jenkins and most CI dashboards render
// without configuration.
package report

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
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

// Invocation identifies the selected work represented by a report. Schema v2
// binds the original selectors to the full catalog, ordered selected CaseIDs,
// and their canonical resume point. Consumers must also check Complete before
// treating a green report as evidence for a release gate.
type Invocation struct {
	SchemaVersion   int
	Suite           string
	Scope           string
	Phase           string
	Tier            string
	Full            bool
	TUNFull         bool
	Case            string
	FromCase        string
	ResumeCaseID    string
	Forced          bool
	ManifestDigest  string
	CatalogDigest   string
	SelectedCases   int
	SelectedCaseIDs []string
	RevisionStart   Revision
	RevisionEnd     Revision
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
	InvocationPhase     string     `xml:"invocation_phase,attr"`
	InvocationTier      string     `xml:"invocation_tier,attr"`
	InvocationFull      bool       `xml:"invocation_full,attr"`
	InvocationTUNFull   bool       `xml:"invocation_tun_full,attr"`
	InvocationCase      string     `xml:"invocation_case,attr,omitempty"`
	InvocationFromCase  string     `xml:"invocation_from_case,attr,omitempty"`
	InvocationResumeID  string     `xml:"invocation_resume_case_id,attr,omitempty"`
	InvocationForced    bool       `xml:"invocation_forced,attr"`
	ManifestDigest      string     `xml:"manifest_digest,attr"`
	CatalogDigest       string     `xml:"catalog_digest,attr"`
	SelectedCases       int        `xml:"selected_cases,attr"`
	SelectedCaseIDs     string     `xml:"selected_case_ids,attr"`
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
		InvocationPhase:     s.Invocation.Phase,
		InvocationTier:      s.Invocation.Tier,
		InvocationFull:      s.Invocation.Full,
		InvocationTUNFull:   s.Invocation.TUNFull,
		InvocationCase:      s.Invocation.Case,
		InvocationFromCase:  s.Invocation.FromCase,
		InvocationResumeID:  s.Invocation.ResumeCaseID,
		InvocationForced:    s.Invocation.Forced,
		ManifestDigest:      s.Invocation.ManifestDigest,
		CatalogDigest:       s.Invocation.CatalogDigest,
		SelectedCases:       s.Invocation.SelectedCases,
		SelectedCaseIDs:     formatCaseIDs(s.Invocation.SelectedCaseIDs),
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
	fmt.Fprintf(&buf, "- Schema version: `%d`\n", s.Invocation.SchemaVersion)
	fmt.Fprintf(&buf, "- Suite: `%s`\n", escapeMarkdown(s.Invocation.Suite))
	fmt.Fprintf(&buf, "- Scope: `%s`\n", escapeMarkdown(s.Invocation.Scope))
	fmt.Fprintf(&buf, "- Phase: `%s`\n", escapeMarkdown(s.Invocation.Phase))
	fmt.Fprintf(&buf, "- Tier: `%s`\n", escapeMarkdown(s.Invocation.Tier))
	fmt.Fprintf(&buf, "- Full: `%t`\n", s.Invocation.Full)
	fmt.Fprintf(&buf, "- TUN full: `%t`\n", s.Invocation.TUNFull)
	if s.Invocation.Case != "" {
		fmt.Fprintf(&buf, "- Case: `%s`\n", escapeMarkdown(s.Invocation.Case))
	}
	if s.Invocation.FromCase != "" {
		fmt.Fprintf(&buf, "- From case: `%s`\n", escapeMarkdown(s.Invocation.FromCase))
	}
	if s.Invocation.ResumeCaseID != "" {
		fmt.Fprintf(&buf, "- Resume CaseID: `%s`\n", escapeMarkdown(s.Invocation.ResumeCaseID))
	}
	fmt.Fprintf(&buf, "- Forced: `%t`\n", s.Invocation.Forced)
	fmt.Fprintf(&buf, "- Manifest digest: `%s`\n", escapeMarkdown(s.Invocation.ManifestDigest))
	fmt.Fprintf(&buf, "- Catalog digest: `%s`\n", escapeMarkdown(s.Invocation.CatalogDigest))
	fmt.Fprintf(&buf, "- Selected cases: `%d`\n", s.Invocation.SelectedCases)
	fmt.Fprintf(&buf, "- Selected CaseIDs (ordered): `%s`\n", escapeMarkdown(formatCaseIDs(s.Invocation.SelectedCaseIDs)))
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
	if inv.SchemaVersion >= 2 {
		// This package does not own the case registry, so it can validate digest
		// shape but cannot independently recompute the catalog digest.
		if !validManifestDigest(inv.CatalogDigest) {
			reasons = append(reasons, "catalog digest is missing or malformed")
		}
		if len(inv.SelectedCaseIDs) == 0 {
			reasons = append(reasons, "selected case IDs are missing")
		}
		seenIDs := make(map[string]bool, len(inv.SelectedCaseIDs))
		for i, id := range inv.SelectedCaseIDs {
			if strings.TrimSpace(id) == "" {
				reasons = append(reasons, fmt.Sprintf("selected case ID at index %d is empty", i))
			}
			if seenIDs[id] {
				reasons = append(reasons, fmt.Sprintf("selected case ID %q is duplicated", id))
			}
			seenIDs[id] = true
		}
		if len(inv.SelectedCaseIDs) != inv.SelectedCases {
			reasons = append(reasons, fmt.Sprintf(
				"selected case ID count %d does not match selected case count %d",
				len(inv.SelectedCaseIDs), inv.SelectedCases,
			))
		}
		if inv.ResumeCaseID == "" {
			reasons = append(reasons, "canonical resume case ID is missing")
		}
		if inv.ResumeCaseID != "" && (len(inv.SelectedCaseIDs) == 0 || inv.ResumeCaseID != inv.SelectedCaseIDs[0]) {
			reasons = append(reasons, "canonical resume case ID is not the first selected case ID")
		}
		switch inv.Scope {
		case "exact":
			if inv.Case != "" && !seenIDs[inv.Case] {
				reasons = append(reasons, fmt.Sprintf("exact case %q is not in the selected case IDs", inv.Case))
			}
			if inv.FromCase != "" {
				reasons = append(reasons, "exact scope unexpectedly has a from-case filter")
			}
		case "selector":
			if inv.FromCase != "" {
				reasons = append(reasons, "selector scope unexpectedly has a from-case filter")
			}
		case "from-case":
			if inv.FromCase != "" && !seenIDs[inv.FromCase] {
				reasons = append(reasons, fmt.Sprintf("from-case %q is not in the selected case IDs", inv.FromCase))
			}
			if inv.Case != "" {
				reasons = append(reasons, "from-case scope unexpectedly has a case filter")
			}
		default:
			if inv.Case != "" {
				reasons = append(reasons, fmt.Sprintf("scope %q unexpectedly has a case filter", inv.Scope))
			}
			if inv.FromCase != "" {
				reasons = append(reasons, fmt.Sprintf("scope %q unexpectedly has a from-case filter", inv.Scope))
			}
		}
	}
	if inv.RevisionStart.CommitSHA == "" || inv.RevisionStart.WorktreeSHA == "" {
		reasons = append(reasons, "start revision is incomplete")
	}
	if inv.Scope == "exact" && inv.Case == "" {
		reasons = append(reasons, "exact scope is missing its case")
	}
	if inv.Scope == "selector" && inv.Case == "" {
		reasons = append(reasons, "selector scope is missing its requested selector")
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
		} else if inv.SchemaVersion >= 2 && len(inv.SelectedCaseIDs) == len(s.Cases) {
			for i, row := range s.Cases {
				if row.Name != inv.SelectedCaseIDs[i] {
					reasons = append(reasons, fmt.Sprintf(
						"selected case ID %q does not match report row %d name %q",
						inv.SelectedCaseIDs[i], i, row.Name,
					))
				}
			}
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
		"catalog_digest":          inv.CatalogDigest,
		"forced":                  fmt.Sprintf("%t", inv.Forced),
		"full":                    fmt.Sprintf("%t", inv.Full),
		"invocation_schema":       fmt.Sprintf("%d", inv.SchemaVersion),
		"manifest_digest":         inv.ManifestDigest,
		"phase":                   inv.Phase,
		"revision_end_commit":     inv.RevisionEnd.CommitSHA,
		"revision_end_worktree":   inv.RevisionEnd.WorktreeSHA,
		"revision_start_commit":   inv.RevisionStart.CommitSHA,
		"revision_start_worktree": inv.RevisionStart.WorktreeSHA,
		"scope":                   inv.Scope,
		"selected_case_ids":       formatCaseIDs(inv.SelectedCaseIDs),
		"selected_cases":          fmt.Sprintf("%d", inv.SelectedCases),
		"suite":                   inv.Suite,
		"tier":                    inv.Tier,
		"tun_full":                fmt.Sprintf("%t", inv.TUNFull),
	}
	if inv.Case != "" {
		fields["case"] = inv.Case
	}
	if inv.FromCase != "" {
		fields["from_case"] = inv.FromCase
	}
	if inv.ResumeCaseID != "" {
		fields["resume_case_id"] = inv.ResumeCaseID
	}
	return formatEvidence(fields, "=", "\n")
}

func formatCaseIDs(ids []string) string {
	if ids == nil {
		ids = []string{}
	}
	encoded, err := json.Marshal(ids)
	if err != nil {
		panic(fmt.Sprintf("report: encode selected case IDs: %v", err))
	}
	return string(encoded)
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
