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

	"github.com/FrankoonG/rendr/regress/internal/environment"
)

const (
	// InvocationSchemaVersion is the only invocation schema allowed to carry
	// v1 release semantics. Older schemas remain readable as non-release
	// component reports only.
	InvocationSchemaVersion        = 6
	EvidenceClassV1ReleaseManifest = "v1_release_manifest"
	EvidenceContractStateKey       = "manifest_contract_state"
	ContractProofProven            = "proven"
	ContractProofUnproven          = "unproven"
	ContractProofNotRequired       = "not_required"
)

// ExecutionState distinguishes a case that produced execution evidence from a
// manifest row retained only to explain why execution stopped.
type ExecutionState string

type BlockerKind string

const (
	ExecutionStateExecuted ExecutionState = "executed"
	ExecutionStateNotRun   ExecutionState = "not_run"
	BlockerKindCase        BlockerKind    = "case"
	BlockerKindSignal      BlockerKind    = "signal"
	BlockerKindEnvironment BlockerKind    = "environment"
	BlockerKindRevision    BlockerKind    = "revision"
	BlockerKindHarness     BlockerKind    = "harness"
	BlockerKindGate        BlockerKind    = "gate"
)

// Case is one regress case (e.g. T1.go-vet, T2.G1-smoke, T3.stream.D-1×D-2).
type Case struct {
	Name            string         `json:"name"`
	Tier            string         `json:"tier"`
	CaseDigest      string         `json:"case_digest,omitempty"`
	ExecutionState  ExecutionState `json:"execution_state,omitempty"`
	BlockerKind     BlockerKind    `json:"blocker_kind,omitempty"`
	BlockedByCaseID string         `json:"blocked_by_case_id,omitempty"`
	BlockerReason   string         `json:"blocker_reason,omitempty"`
	Duration        time.Duration  `json:"duration_ns"`
	// Empty Failure => pass.
	Failure string `json:"failure,omitempty"`
	// InvalidReason means the harness could not prove that the stimulus,
	// offered load, or oracle was valid. Invalid is always a failure.
	InvalidReason string `json:"invalid_reason,omitempty"`
	// SkipReason set => the case was skipped (e.g. T5 adapter missing).
	// Skips fail by default; Optional must be explicit for a non-blocking skip.
	SkipReason string `json:"skip_reason,omitempty"`
	Optional   bool   `json:"optional,omitempty"`
	// Evidence records machine-produced stimulus, load, and oracle facts.
	// Writers sort keys so reports are deterministic.
	Evidence map[string]string `json:"evidence,omitempty"`
}

// Revision identifies one exact repository state. CommitSHA identifies HEAD;
// WorktreeSHA additionally covers tracked edits and non-ignored untracked
// files.
type Revision struct {
	CommitSHA   string `json:"commit_sha"`
	WorktreeSHA string `json:"worktree_sha"`
}

// Phase1Authorization identifies the immutable phase-1 proof that authorized
// a phase-2 invocation.
type Phase1Authorization struct {
	CommitSHA             string `json:"commit_sha"`
	WorktreeSHA           string `json:"worktree_sha"`
	ReportSetGeneration   string `json:"report_set_generation"`
	CanonicalReportDigest string `json:"canonical_report_digest"`
}

// Invocation identifies the selected work represented by a report. Schema v3
// added environment provenance; v4 separates a complete selected component
// from a complete release manifest; v5 separates requested cases from the
// prerequisite-expanded execution set; v6 binds contract-proof policy.
type Invocation struct {
	SchemaVersion          int                  `json:"schema_version"`
	Suite                  string               `json:"suite"`
	Scope                  string               `json:"scope"`
	Phase                  string               `json:"phase,omitempty"`
	Tier                   string               `json:"tier,omitempty"`
	Full                   bool                 `json:"full"`
	TUNFull                bool                 `json:"tun_full"`
	Case                   string               `json:"case,omitempty"`
	Selector               string               `json:"selector,omitempty"`
	FromCase               string               `json:"from_case,omitempty"`
	ResumeCaseID           string               `json:"resume_case_id,omitempty"`
	Forced                 bool                 `json:"forced"`
	AllowNonLinux          bool                 `json:"allow_non_linux"`
	ManifestDigest         string               `json:"manifest_digest"`
	CatalogDigest          string               `json:"catalog_digest"`
	SelectedCases          int                  `json:"selected_cases"`
	SelectedCaseIDs        []string             `json:"selected_case_ids"`
	RequestedCaseIDs       []string             `json:"requested_case_ids,omitempty"`
	RequestAnchor          string               `json:"request_anchor,omitempty"`
	RevisionStart          Revision             `json:"revision_start"`
	RevisionEnd            Revision             `json:"revision_end"`
	EnvironmentStart       environment.Snapshot `json:"environment_start"`
	EnvironmentEnd         environment.Snapshot `json:"environment_end"`
	EvidenceClass          string               `json:"evidence_class"`
	ReleaseManifest        bool                 `json:"release_manifest"`
	ContractProofRequired  bool                 `json:"contract_proof_required"`
	AllowUnprovenContracts bool                 `json:"allow_unproven_contracts"`
	Phase1Authorization    *Phase1Authorization `json:"phase1_authorization,omitempty"`
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
func (s *Suite) Add(c Case) {
	s.Cases = append(s.Cases, normalizeCaseExecution(c))
}

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
	state := c.normalizedExecutionState()
	return state == ExecutionStateNotRun || c.validateExecutionState() != nil ||
		c.Failure != "" || c.InvalidReason != "" || (c.SkipReason != "" && !c.Optional)
}

func normalizeCaseExecution(c Case) Case {
	if c.ExecutionState == "" {
		c.ExecutionState = ExecutionStateExecuted
	}
	return c
}

func (c Case) normalizedExecutionState() ExecutionState {
	if c.ExecutionState == "" {
		return ExecutionStateExecuted
	}
	return c.ExecutionState
}

func (c Case) validateExecutionState() error {
	switch c.normalizedExecutionState() {
	case ExecutionStateExecuted:
		if c.BlockerKind != "" || c.BlockedByCaseID != "" || c.BlockerReason != "" {
			return fmt.Errorf("executed case has blocker metadata kind=%q case=%q reason=%q", c.BlockerKind, c.BlockedByCaseID, c.BlockerReason)
		}
	case ExecutionStateNotRun:
		switch c.BlockerKind {
		case BlockerKindCase:
			if strings.TrimSpace(c.BlockedByCaseID) == "" {
				return fmt.Errorf("case-blocked not_run row is missing blocked_by_case_id")
			}
			if c.BlockerReason != "" {
				return fmt.Errorf("case-blocked not_run row has blocker_reason %q", c.BlockerReason)
			}
		case BlockerKindSignal, BlockerKindEnvironment, BlockerKindRevision, BlockerKindHarness, BlockerKindGate:
			if c.BlockedByCaseID != "" {
				return fmt.Errorf("%s-blocked not_run row has blocked_by_case_id %q", c.BlockerKind, c.BlockedByCaseID)
			}
			if strings.TrimSpace(c.BlockerReason) == "" {
				return fmt.Errorf("%s-blocked not_run row is missing blocker_reason", c.BlockerKind)
			}
		case "":
			return fmt.Errorf("not_run case is missing blocker_kind")
		default:
			return fmt.Errorf("not_run case has unsupported blocker_kind %q", c.BlockerKind)
		}
	default:
		return fmt.Errorf("unsupported execution state %q", c.ExecutionState)
	}
	return nil
}

func reportComplete(s *Suite) bool {
	if s == nil || !s.Complete {
		return false
	}
	for _, c := range s.Cases {
		if c.normalizedExecutionState() != ExecutionStateExecuted || c.validateExecutionState() != nil {
			return false
		}
	}
	return true
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
	XMLName                xml.Name       `xml:"testsuites"`
	Name                   string         `xml:"name,attr"`
	State                  string         `xml:"state,attr"`
	Complete               bool           `xml:"complete,attr"`
	InvocationSchema       int            `xml:"invocation_schema,attr"`
	InvocationSuite        string         `xml:"invocation_suite,attr"`
	InvocationScope        string         `xml:"invocation_scope,attr"`
	InvocationPhase        string         `xml:"invocation_phase,attr"`
	InvocationTier         string         `xml:"invocation_tier,attr"`
	InvocationFull         bool           `xml:"invocation_full,attr"`
	InvocationTUNFull      bool           `xml:"invocation_tun_full,attr"`
	InvocationCase         string         `xml:"invocation_case,attr,omitempty"`
	InvocationSelector     string         `xml:"invocation_selector,attr,omitempty"`
	InvocationFromCase     string         `xml:"invocation_from_case,attr,omitempty"`
	InvocationResumeID     string         `xml:"invocation_resume_case_id,attr,omitempty"`
	InvocationForced       bool           `xml:"invocation_forced,attr"`
	InvocationNonLinux     bool           `xml:"invocation_allow_non_linux,attr"`
	ManifestDigest         string         `xml:"manifest_digest,attr"`
	CatalogDigest          string         `xml:"catalog_digest,attr"`
	ReportDigest           string         `xml:"report_digest,attr"`
	SelectedCases          int            `xml:"selected_cases,attr"`
	SelectedCaseIDs        string         `xml:"selected_case_ids,attr"`
	RequestedCaseIDs       string         `xml:"requested_case_ids,attr,omitempty"`
	RequestAnchor          string         `xml:"request_anchor,attr,omitempty"`
	RevisionStartCommit    string         `xml:"revision_start_commit,attr"`
	RevisionStartTree      string         `xml:"revision_start_worktree,attr"`
	RevisionEndCommit      string         `xml:"revision_end_commit,attr"`
	RevisionEndTree        string         `xml:"revision_end_worktree,attr"`
	EnvironmentStartID     string         `xml:"environment_start_identity,attr,omitempty"`
	EnvironmentEndID       string         `xml:"environment_end_identity,attr,omitempty"`
	QDiscStartDigest       string         `xml:"qdisc_start_digest,attr,omitempty"`
	QDiscEndDigest         string         `xml:"qdisc_end_digest,attr,omitempty"`
	EvidenceClass          string         `xml:"evidence_class,attr,omitempty"`
	ReleaseManifest        bool           `xml:"release_manifest,attr"`
	ContractProofRequired  bool           `xml:"contract_proof_required,attr"`
	AllowUnprovenContracts bool           `xml:"allow_unproven_contracts,attr"`
	Phase1Commit           string         `xml:"phase1_commit,attr,omitempty"`
	Phase1Worktree         string         `xml:"phase1_worktree,attr,omitempty"`
	Phase1Generation       string         `xml:"phase1_report_generation,attr,omitempty"`
	Phase1Digest           string         `xml:"phase1_report_digest,attr,omitempty"`
	Time                   float64        `xml:"time,attr"`
	Tests                  int            `xml:"tests,attr"`
	Failures               int            `xml:"failures,attr"`
	Skipped                int            `xml:"skipped,attr"`
	Properties             *xmlProperties `xml:"properties,omitempty"`
	Suites                 []xmlSuite     `xml:"testsuite"`
}

type xmlProperties struct {
	Properties []xmlProperty `xml:"property"`
}

type xmlProperty struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
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
	XMLName        xml.Name    `xml:"testcase"`
	Name           string      `xml:"name,attr"`
	Classname      string      `xml:"classname,attr"`
	CaseDigest     string      `xml:"case_digest,attr,omitempty"`
	ExecutionState string      `xml:"execution_state,attr"`
	BlockerKind    string      `xml:"blocker_kind,attr,omitempty"`
	BlockedByCase  string      `xml:"blocked_by_case_id,attr,omitempty"`
	BlockerReason  string      `xml:"blocker_reason,attr,omitempty"`
	Time           float64     `xml:"time,attr"`
	Failure        *xmlFailure `xml:"failure,omitempty"`
	Skipped        *xmlSkipped `xml:"skipped,omitempty"`
	SystemOut      string      `xml:"system-out,omitempty"`
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
	encoded, err := s.marshalJUnit()
	if err != nil {
		return err
	}
	return writeAtomic(path, encoded)
}

func (s *Suite) marshalJUnit() ([]byte, error) {
	reportDigest, err := s.ReportDigest()
	if err != nil {
		return nil, err
	}
	properties, err := environmentProperties(s.Invocation)
	if err != nil {
		return nil, err
	}
	byTier := map[string][]Case{}
	tierOrder := []string{}
	for _, c := range s.Cases {
		if _, ok := byTier[c.Tier]; !ok {
			tierOrder = append(tierOrder, c.Tier)
		}
		byTier[c.Tier] = append(byTier[c.Tier], c)
	}

	out := xmlSuites{
		Name:                   invocationName(s.Invocation),
		State:                  reportState(s),
		Complete:               reportComplete(s),
		InvocationSchema:       s.Invocation.SchemaVersion,
		InvocationSuite:        s.Invocation.Suite,
		InvocationScope:        s.Invocation.Scope,
		InvocationPhase:        s.Invocation.Phase,
		InvocationTier:         s.Invocation.Tier,
		InvocationFull:         s.Invocation.Full,
		InvocationTUNFull:      s.Invocation.TUNFull,
		InvocationCase:         s.Invocation.Case,
		InvocationSelector:     s.Invocation.Selector,
		InvocationFromCase:     s.Invocation.FromCase,
		InvocationResumeID:     s.Invocation.ResumeCaseID,
		InvocationForced:       s.Invocation.Forced,
		InvocationNonLinux:     s.Invocation.AllowNonLinux,
		ManifestDigest:         s.Invocation.ManifestDigest,
		CatalogDigest:          s.Invocation.CatalogDigest,
		ReportDigest:           reportDigest,
		SelectedCases:          s.Invocation.SelectedCases,
		SelectedCaseIDs:        formatCaseIDs(s.Invocation.SelectedCaseIDs),
		RequestedCaseIDs:       formatCaseIDs(s.Invocation.RequestedCaseIDs),
		RequestAnchor:          s.Invocation.RequestAnchor,
		RevisionStartCommit:    s.Invocation.RevisionStart.CommitSHA,
		RevisionStartTree:      s.Invocation.RevisionStart.WorktreeSHA,
		RevisionEndCommit:      s.Invocation.RevisionEnd.CommitSHA,
		RevisionEndTree:        s.Invocation.RevisionEnd.WorktreeSHA,
		EnvironmentStartID:     s.Invocation.EnvironmentStart.IdentityDigest,
		EnvironmentEndID:       s.Invocation.EnvironmentEnd.IdentityDigest,
		QDiscStartDigest:       s.Invocation.EnvironmentStart.QDisc.Digest,
		QDiscEndDigest:         s.Invocation.EnvironmentEnd.QDisc.Digest,
		EvidenceClass:          s.Invocation.EvidenceClass,
		ReleaseManifest:        s.Invocation.ReleaseManifest,
		ContractProofRequired:  s.Invocation.ContractProofRequired,
		AllowUnprovenContracts: s.Invocation.AllowUnprovenContracts,
		Properties:             properties,
	}
	if authorization := s.Invocation.Phase1Authorization; authorization != nil {
		out.Phase1Commit = authorization.CommitSHA
		out.Phase1Worktree = authorization.WorktreeSHA
		out.Phase1Generation = authorization.ReportSetGeneration
		out.Phase1Digest = authorization.CanonicalReportDigest
	}
	for _, tier := range tierOrder {
		cs := byTier[tier]
		xs := xmlSuite{Name: tier}
		for _, c := range cs {
			c = normalizeCaseExecution(c)
			xc := xmlCase{
				Name:           c.Name,
				Classname:      tier,
				CaseDigest:     c.CaseDigest,
				ExecutionState: string(c.ExecutionState),
				BlockerKind:    string(c.BlockerKind),
				BlockedByCase:  c.BlockedByCaseID,
				BlockerReason:  c.BlockerReason,
				Time:           c.Duration.Seconds(),
			}
			xs.Tests++
			out.Tests++
			if stateErr := c.validateExecutionState(); stateErr != nil {
				xc.Failure = &xmlFailure{Message: "invalid execution state", Body: stateErr.Error()}
				xs.Failures++
				out.Failures++
			} else if c.ExecutionState == ExecutionStateNotRun {
				body := fmt.Sprintf("blocked by %s", c.BlockerKind)
				if c.BlockedByCaseID != "" {
					body += " " + c.BlockedByCaseID
				}
				if c.BlockerReason != "" {
					body += ": " + c.BlockerReason
				}
				xc.Failure = &xmlFailure{Message: "case not run", Body: body}
				xs.Failures++
				out.Failures++
			} else if c.InvalidReason != "" {
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
			xs.Time += xc.Time
			xs.Cases = append(xs.Cases, xc)
		}
		out.Time += xs.Time
		out.Suites = append(out.Suites, xs)
	}
	if reason := junitInvocationFailure(s); reason != "" {
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
		return nil, err
	}
	enc := xml.NewEncoder(&buf)
	enc.Indent("", "  ")
	if err := enc.Encode(out); err != nil {
		return nil, err
	}
	if _, err := io.WriteString(&buf, "\n"); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func junitInvocationFailure(s *Suite) string {
	if reason := invocationFailure(s); reason != "" {
		return reason
	}
	proof, err := ContractProofState(s)
	if err != nil {
		return "contract proof evidence is invalid: " + err.Error()
	}
	if reportComplete(s) && proof == ContractProofUnproven {
		return "selected manifest completed, but one or more case contracts remain unproven"
	}
	return ""
}

// WriteMarkdown emits a human-readable SUMMARY.md.
func (s *Suite) WriteMarkdown(path string) error {
	encoded, err := s.marshalMarkdown()
	if err != nil {
		return err
	}
	return writeAtomic(path, encoded)
}

func (s *Suite) marshalMarkdown() ([]byte, error) {
	reportDigest, err := s.ReportDigest()
	if err != nil {
		return nil, err
	}
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
	if s.Invocation.Selector != "" {
		fmt.Fprintf(&buf, "- Selector: `%s`\n", escapeMarkdown(s.Invocation.Selector))
	}
	if s.Invocation.FromCase != "" {
		fmt.Fprintf(&buf, "- From case: `%s`\n", escapeMarkdown(s.Invocation.FromCase))
	}
	if s.Invocation.ResumeCaseID != "" {
		fmt.Fprintf(&buf, "- Resume CaseID: `%s`\n", escapeMarkdown(s.Invocation.ResumeCaseID))
	}
	fmt.Fprintf(&buf, "- Forced: `%t`\n", s.Invocation.Forced)
	fmt.Fprintf(&buf, "- Allow non-Linux: `%t`\n", s.Invocation.AllowNonLinux)
	fmt.Fprintf(&buf, "- Manifest digest: `%s`\n", escapeMarkdown(s.Invocation.ManifestDigest))
	fmt.Fprintf(&buf, "- Catalog digest: `%s`\n", escapeMarkdown(s.Invocation.CatalogDigest))
	fmt.Fprintf(&buf, "- Report digest: `%s`\n", escapeMarkdown(reportDigest))
	fmt.Fprintf(&buf, "- Selected cases: `%d`\n", s.Invocation.SelectedCases)
	fmt.Fprintf(&buf, "- Selected CaseIDs (ordered): `%s`\n", escapeMarkdown(formatCaseIDs(s.Invocation.SelectedCaseIDs)))
	fmt.Fprintf(&buf, "- Requested CaseIDs (ordered): `%s`\n", escapeMarkdown(formatCaseIDs(s.Invocation.RequestedCaseIDs)))
	fmt.Fprintf(&buf, "- Request anchor: `%s`\n", escapeMarkdown(s.Invocation.RequestAnchor))
	fmt.Fprintf(&buf, "- Revision start: `%s`\n", escapeMarkdown(formatRevision(s.Invocation.RevisionStart)))
	fmt.Fprintf(&buf, "- Revision end: `%s`\n", escapeMarkdown(formatRevision(s.Invocation.RevisionEnd)))
	fmt.Fprintf(&buf, "- Complete: `%t`\n", reportComplete(s))
	fmt.Fprintf(&buf, "- Evidence class: `%s`\n", escapeMarkdown(s.Invocation.EvidenceClass))
	fmt.Fprintf(&buf, "- Release manifest: `%t`\n", s.Invocation.ReleaseManifest)
	fmt.Fprintf(&buf, "- Contract proof required: `%t`\n", s.Invocation.ContractProofRequired)
	fmt.Fprintf(&buf, "- Allow unproven contracts: `%t`\n", s.Invocation.AllowUnprovenContracts)
	if authorization := s.Invocation.Phase1Authorization; authorization != nil {
		fmt.Fprintf(&buf, "- Phase-1 authorization: `commit=%s worktree=%s generation=%s digest=%s`\n",
			escapeMarkdown(authorization.CommitSHA), escapeMarkdown(authorization.WorktreeSHA),
			escapeMarkdown(authorization.ReportSetGeneration), escapeMarkdown(authorization.CanonicalReportDigest))
	}
	if proof, err := ContractProofState(s); err == nil {
		fmt.Fprintf(&buf, "- Contract proof state: `%s`\n", proof)
	}
	if s.RunFailure != "" {
		fmt.Fprintf(&buf, "- Invocation failure: `%s`\n", escapeMarkdown(s.RunFailure))
	}
	fmt.Fprintln(&buf)
	if err := writeEnvironmentMarkdown(&buf, s.Invocation); err != nil {
		return nil, err
	}
	fmt.Fprintf(&buf, "Total elapsed: %s\n\n", totalCaseDuration(s.Cases).Round(time.Millisecond))

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
		fmt.Fprintln(&buf, "| Case | Execution | Blocker | Time | Result | Evidence |")
		fmt.Fprintln(&buf, "|------|-----------|---------|------|--------|----------|")
		for _, c := range byTier[tier] {
			c = normalizeCaseExecution(c)
			result := "OK"
			if stateErr := c.validateExecutionState(); stateErr != nil {
				result = "FAIL (invalid execution state): " + stateErr.Error()
			} else if c.ExecutionState == ExecutionStateNotRun {
				result = "FAIL (NOT_RUN): blocked by " + string(c.BlockerKind)
				if c.BlockedByCaseID != "" {
					result += " " + c.BlockedByCaseID
				}
				if c.BlockerReason != "" {
					result += ": " + c.BlockerReason
				}
			} else if c.InvalidReason != "" {
				result = "INVALID: " + c.InvalidReason
			} else if c.SkipReason != "" && c.Optional {
				result = "SKIP (optional): " + c.SkipReason
			} else if c.SkipReason != "" {
				result = "FAIL (mandatory skip): " + c.SkipReason
			} else if c.Failure != "" {
				result = "FAIL: " + compactDiagnostic(c.Failure, 512)
			}
			evidence := escapeMarkdown(formatEvidence(c.Evidence, "=", "; "))
			fmt.Fprintf(
				&buf,
				"| %s | %s | %s | %s | %s | %s |\n",
				escapeMarkdown(c.Name), escapeMarkdown(string(c.ExecutionState)), escapeMarkdown(formatCaseBlocker(c)),
				c.Duration.Round(time.Millisecond), escapeMarkdown(result), evidence,
			)
		}
		fmt.Fprintln(&buf)
	}

	overall := strings.ToUpper(reportState(s))
	fmt.Fprintf(&buf, "**OVERALL: %s**\n", overall)
	return buf.Bytes(), nil
}

func totalCaseDuration(cases []Case) time.Duration {
	var total time.Duration
	for _, c := range cases {
		total += c.Duration
	}
	return total
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
	if !reportComplete(s) {
		return "partial"
	}
	proof, err := ContractProofState(s)
	if err != nil {
		return "fail"
	}
	if proof == ContractProofUnproven {
		return "unproven"
	}
	return "pass"
}

// ContractProofState reports whether every executed row is backed by a fully
// enforced manifest contract. It is independent from product pass/fail state.
func ContractProofState(s *Suite) (string, error) {
	if s == nil {
		return "", fmt.Errorf("nil suite")
	}
	if !s.Invocation.ContractProofRequired {
		return ContractProofNotRequired, nil
	}
	state := ContractProofProven
	for i, row := range s.Cases {
		if row.normalizedExecutionState() != ExecutionStateExecuted {
			continue
		}
		contractState := ""
		if row.Evidence != nil {
			contractState = strings.TrimSpace(row.Evidence[EvidenceContractStateKey])
		}
		switch contractState {
		case "enforced":
		case "blocked":
			state = ContractProofUnproven
		case "":
			return "", fmt.Errorf("report row %d is missing %s", i, EvidenceContractStateKey)
		default:
			return "", fmt.Errorf("report row %d has unsupported contract state %q", i, contractState)
		}
	}
	return state, nil
}

func invocationFailure(s *Suite) string {
	var reasons []string
	if s.RunFailure != "" {
		reasons = append(reasons, s.RunFailure)
	}
	if identityFailure := invocationIdentityFailure(s); identityFailure != "" {
		reasons = append(reasons, identityFailure)
	}
	if !reportComplete(s) {
		reasons = append(reasons, "selected manifest did not complete")
	}
	return strings.Join(reasons, "\n")
}

func invocationIdentityFailure(s *Suite) string {
	inv := s.Invocation
	var reasons []string
	for i, c := range s.Cases {
		if err := c.validateExecutionState(); err != nil {
			reasons = append(reasons, fmt.Sprintf("report row %d execution state is invalid: %v", i, err))
		}
	}
	if inv.SchemaVersion <= 0 {
		reasons = append(reasons, "invocation schema is missing")
	} else if inv.SchemaVersion > InvocationSchemaVersion {
		reasons = append(reasons, fmt.Sprintf(
			"invocation schema %d is unsupported; current schema is %d",
			inv.SchemaVersion, InvocationSchemaVersion,
		))
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
	if inv.SchemaVersion >= 4 {
		if strings.TrimSpace(inv.EvidenceClass) == "" {
			reasons = append(reasons, "evidence class is missing")
		}
		if !inv.ReleaseManifest && inv.EvidenceClass == EvidenceClassV1ReleaseManifest {
			reasons = append(reasons, "release evidence class is set without a release manifest")
		}
	}
	if inv.SchemaVersion >= 5 {
		if len(inv.RequestedCaseIDs) == 0 {
			reasons = append(reasons, "requested case IDs are missing")
		}
		selectedIndex := make(map[string]int, len(inv.SelectedCaseIDs))
		for i, id := range inv.SelectedCaseIDs {
			selectedIndex[id] = i
		}
		seenRequested := make(map[string]bool, len(inv.RequestedCaseIDs))
		lastSelectedIndex := -1
		for i, id := range inv.RequestedCaseIDs {
			if strings.TrimSpace(id) == "" {
				reasons = append(reasons, fmt.Sprintf("requested case ID at index %d is empty", i))
			}
			if seenRequested[id] {
				reasons = append(reasons, fmt.Sprintf("requested case ID %q is duplicated", id))
			}
			seenRequested[id] = true
			selectedAt, ok := selectedIndex[id]
			if !ok {
				reasons = append(reasons, fmt.Sprintf("requested case ID %q is not in the execution case IDs", id))
				continue
			}
			if selectedAt <= lastSelectedIndex {
				reasons = append(reasons, "requested case IDs are not in execution order")
			}
			lastSelectedIndex = selectedAt
		}
		if strings.TrimSpace(inv.RequestAnchor) == "" {
			reasons = append(reasons, "request anchor is missing")
		}
		switch inv.Scope {
		case "exact":
			if len(inv.RequestedCaseIDs) != 1 || len(inv.RequestedCaseIDs) == 1 && inv.RequestedCaseIDs[0] != inv.Case {
				reasons = append(reasons, "exact scope must request only its case")
			}
			if inv.RequestAnchor != inv.Case {
				reasons = append(reasons, "exact request anchor does not match its case")
			}
		case "from-case":
			if len(inv.RequestedCaseIDs) != 0 && inv.RequestedCaseIDs[0] != inv.FromCase {
				reasons = append(reasons, "from-case requested set does not begin at its anchor")
			}
			if inv.RequestAnchor != inv.FromCase {
				reasons = append(reasons, "from-case request anchor does not match its filter")
			}
		case "selector":
			if inv.Case != "" {
				reasons = append(reasons, "selector scope unexpectedly has a case filter")
			}
			if inv.Selector == "" {
				reasons = append(reasons, "selector scope is missing its selector")
			}
			if inv.RequestAnchor != inv.Selector {
				reasons = append(reasons, "selector request anchor does not match its selector")
			}
		default:
			if inv.Selector != "" {
				reasons = append(reasons, fmt.Sprintf("scope %q unexpectedly has a selector filter", inv.Scope))
			}
			if len(inv.RequestedCaseIDs) != 0 && inv.RequestAnchor != inv.RequestedCaseIDs[0] {
				reasons = append(reasons, "request anchor is not the first requested case ID")
			}
		}
	}
	if inv.SchemaVersion >= 6 {
		if !inv.ContractProofRequired {
			reasons = append(reasons, "contract proof is not required by a v6 invocation")
		}
		if inv.AllowUnprovenContracts && !inv.ContractProofRequired {
			reasons = append(reasons, "unproven contracts are allowed without requiring contract proof")
		}
		if _, err := ContractProofState(s); err != nil {
			reasons = append(reasons, "contract proof evidence is invalid: "+err.Error())
		}
		if authorization := inv.Phase1Authorization; authorization != nil {
			if strings.TrimSpace(authorization.CommitSHA) == "" || strings.TrimSpace(authorization.WorktreeSHA) == "" {
				reasons = append(reasons, "phase-1 authorization revision is incomplete")
			}
			if len(authorization.ReportSetGeneration) != 32 {
				reasons = append(reasons, "phase-1 authorization generation is malformed")
			} else if _, err := hex.DecodeString(authorization.ReportSetGeneration); err != nil {
				reasons = append(reasons, "phase-1 authorization generation is malformed")
			}
			if !validManifestDigest(authorization.CanonicalReportDigest) {
				reasons = append(reasons, "phase-1 authorization digest is malformed")
			}
		}
	}
	if inv.ReleaseManifest {
		reasons = append(reasons, releaseManifestIdentityFailures(s)...)
	}
	if inv.SchemaVersion >= 3 {
		if inv.EnvironmentStart.IsZero() {
			reasons = append(reasons, "start environment snapshot is missing")
		} else if err := environment.Validate(inv.EnvironmentStart); err != nil {
			reasons = append(reasons, "start environment snapshot is incomplete: "+err.Error())
		} else if inv.EnvironmentStart.Runtime.GOOS != "linux" && !inv.AllowNonLinux {
			reasons = append(reasons, "non-Linux environment is missing the allow-non-linux bypass")
		}
		endRequired := s.Complete || len(s.Cases) != 0 || s.RunFailure != ""
		if inv.EnvironmentEnd.IsZero() {
			if endRequired {
				reasons = append(reasons, "end environment snapshot is missing")
			}
		} else if inv.EnvironmentStart.IsZero() {
			reasons = append(reasons, "end environment snapshot exists without a start snapshot")
		} else if err := environment.ValidatePair(inv.EnvironmentStart, inv.EnvironmentEnd); err != nil {
			reasons = append(reasons, "environment provenance mismatch: "+err.Error())
		}
	}
	if inv.RevisionStart.CommitSHA == "" || inv.RevisionStart.WorktreeSHA == "" {
		reasons = append(reasons, "start revision is incomplete")
	}
	if inv.Scope == "exact" && inv.Case == "" {
		reasons = append(reasons, "exact scope is missing its case")
	}
	if inv.Scope == "selector" && inv.SchemaVersion < 5 && inv.Case == "" {
		reasons = append(reasons, "selector scope is missing its requested selector")
	}
	if inv.Scope == "from-case" && inv.FromCase == "" {
		reasons = append(reasons, "from-case scope is missing its resume point")
	}
	projectionRequired := s.Complete || inv.ReleaseManifest || inv.SchemaVersion >= 6 && (len(s.Cases) != 0 || s.RunFailure != "")
	if projectionRequired {
		if inv.RevisionEnd.CommitSHA == "" || inv.RevisionEnd.WorktreeSHA == "" {
			reasons = append(reasons, "end revision is incomplete")
		} else if inv.RevisionStart != inv.RevisionEnd {
			reasons = append(reasons, "start and end revisions differ")
		}
		if inv.SelectedCases != len(s.Cases) {
			reasons = append(reasons, fmt.Sprintf("selected case count %d does not match report rows %d", inv.SelectedCases, len(s.Cases)))
		} else if inv.SchemaVersion >= 2 && len(inv.SelectedCaseIDs) == len(s.Cases) {
			projectionIndex := make(map[string]int, len(inv.SelectedCaseIDs))
			for i, id := range inv.SelectedCaseIDs {
				projectionIndex[id] = i
			}
			for i, row := range s.Cases {
				if row.Name != inv.SelectedCaseIDs[i] {
					reasons = append(reasons, fmt.Sprintf(
						"selected case ID %q does not match report row %d name %q",
						inv.SelectedCaseIDs[i], i, row.Name,
					))
				}
				if inv.SchemaVersion >= 5 && !validManifestDigest(row.CaseDigest) {
					reasons = append(reasons, fmt.Sprintf("report row %d case digest is missing or malformed", i))
				}
				if row.normalizedExecutionState() == ExecutionStateNotRun && row.BlockerKind == BlockerKindCase {
					blockerIndex, ok := projectionIndex[row.BlockedByCaseID]
					if !ok {
						reasons = append(reasons, fmt.Sprintf("report row %d case blocker %q is not selected", i, row.BlockedByCaseID))
					} else if blockerIndex >= i {
						reasons = append(reasons, fmt.Sprintf("report row %d case blocker %q is not an earlier row", i, row.BlockedByCaseID))
					} else if blockerIndex < len(s.Cases) && !s.Cases[blockerIndex].failed() {
						reasons = append(reasons, fmt.Sprintf("report row %d case blocker %q did not fail", i, row.BlockedByCaseID))
					}
				}
			}
		}
	}
	return strings.Join(reasons, "\n")
}

func releaseManifestIdentityFailures(s *Suite) []string {
	inv := s.Invocation
	var reasons []string
	if inv.SchemaVersion != InvocationSchemaVersion {
		reasons = append(reasons, fmt.Sprintf(
			"release manifest invocation schema is %d, want current schema %d",
			inv.SchemaVersion, InvocationSchemaVersion,
		))
	}
	if inv.Scope != "full" {
		reasons = append(reasons, "release manifest must use full scope")
	}
	if inv.EvidenceClass != EvidenceClassV1ReleaseManifest {
		reasons = append(reasons, "release manifest has a non-release evidence class")
	}
	if !s.Complete || !reportComplete(s) {
		reasons = append(reasons, "release manifest must contain a completed selected manifest")
	}
	if inv.Forced {
		reasons = append(reasons, "release manifest cannot use forced execution")
	}
	if inv.AllowNonLinux {
		reasons = append(reasons, "release manifest cannot allow non-Linux execution")
	}
	if inv.AllowUnprovenContracts {
		reasons = append(reasons, "release manifest cannot allow unproven contracts")
	}
	if !inv.ContractProofRequired {
		reasons = append(reasons, "release manifest must require contract proof")
	} else if proof, err := ContractProofState(s); err != nil {
		reasons = append(reasons, "release manifest contract proof is invalid: "+err.Error())
	} else if proof != ContractProofProven {
		reasons = append(reasons, fmt.Sprintf("release manifest contract proof is %s, want %s", proof, ContractProofProven))
	}

	if inv.Full == inv.TUNFull {
		reasons = append(reasons, "release manifest must select exactly one of full or TUN full")
	}
	if inv.Suite == "tun-full" {
		if !inv.TUNFull || inv.Full {
			reasons = append(reasons, "tun-full release manifest must use only the TUN-full invocation flag")
		}
	} else if !inv.Full || inv.TUNFull {
		reasons = append(reasons, "non-TUN release manifest must use only the full invocation flag")
	}
	if inv.Phase != "" || inv.Tier != "" || inv.Case != "" || inv.Selector != "" || inv.FromCase != "" {
		reasons = append(reasons, "release manifest cannot contain phase, tier, case, selector, or from-case filters")
	}
	if len(inv.RequestedCaseIDs) != len(inv.SelectedCaseIDs) {
		reasons = append(reasons, "release manifest requested case IDs do not exactly match selected case IDs")
	} else {
		for i := range inv.SelectedCaseIDs {
			if inv.RequestedCaseIDs[i] != inv.SelectedCaseIDs[i] {
				reasons = append(reasons, "release manifest requested case IDs do not exactly match selected case IDs")
				break
			}
		}
	}
	if inv.Phase1Authorization == nil {
		reasons = append(reasons, "release manifest is missing phase-1 authorization")
	}
	if len(inv.SelectedCaseIDs) == 0 || inv.RequestAnchor != inv.SelectedCaseIDs[0] {
		reasons = append(reasons, "release manifest request anchor is not the first selected case ID")
	}
	return reasons
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
		"allow_non_linux":          fmt.Sprintf("%t", inv.AllowNonLinux),
		"allow_unproven_contracts": fmt.Sprintf("%t", inv.AllowUnprovenContracts),
		"catalog_digest":           inv.CatalogDigest,
		"contract_proof_required":  fmt.Sprintf("%t", inv.ContractProofRequired),
		"evidence_class":           inv.EvidenceClass,
		"forced":                   fmt.Sprintf("%t", inv.Forced),
		"full":                     fmt.Sprintf("%t", inv.Full),
		"invocation_schema":        fmt.Sprintf("%d", inv.SchemaVersion),
		"manifest_digest":          inv.ManifestDigest,
		"phase":                    inv.Phase,
		"revision_end_commit":      inv.RevisionEnd.CommitSHA,
		"revision_end_worktree":    inv.RevisionEnd.WorktreeSHA,
		"revision_start_commit":    inv.RevisionStart.CommitSHA,
		"revision_start_worktree":  inv.RevisionStart.WorktreeSHA,
		"release_manifest":         fmt.Sprintf("%t", inv.ReleaseManifest),
		"request_anchor":           inv.RequestAnchor,
		"requested_case_ids":       formatCaseIDs(inv.RequestedCaseIDs),
		"scope":                    inv.Scope,
		"selected_case_ids":        formatCaseIDs(inv.SelectedCaseIDs),
		"selected_cases":           fmt.Sprintf("%d", inv.SelectedCases),
		"suite":                    inv.Suite,
		"tier":                     inv.Tier,
		"tun_full":                 fmt.Sprintf("%t", inv.TUNFull),
	}
	if authorization := inv.Phase1Authorization; authorization != nil {
		fields["phase1_commit"] = authorization.CommitSHA
		fields["phase1_worktree"] = authorization.WorktreeSHA
		fields["phase1_report_generation"] = authorization.ReportSetGeneration
		fields["phase1_report_digest"] = authorization.CanonicalReportDigest
	}
	if inv.Case != "" {
		fields["case"] = inv.Case
	}
	if inv.Selector != "" {
		fields["selector"] = inv.Selector
	}
	if inv.FromCase != "" {
		fields["from_case"] = inv.FromCase
	}
	if inv.ResumeCaseID != "" {
		fields["resume_case_id"] = inv.ResumeCaseID
	}
	if !inv.EnvironmentStart.IsZero() {
		if encoded, err := environment.Marshal(inv.EnvironmentStart); err == nil {
			fields["environment_start"] = encoded
		}
	}
	if !inv.EnvironmentEnd.IsZero() {
		if encoded, err := environment.Marshal(inv.EnvironmentEnd); err == nil {
			fields["environment_end"] = encoded
		}
	}
	return formatEvidence(fields, "=", "\n")
}

func environmentProperties(inv Invocation) (*xmlProperties, error) {
	var properties []xmlProperty
	for _, snapshot := range []struct {
		name  string
		value environment.Snapshot
	}{
		{name: "rendr.environment.start", value: inv.EnvironmentStart},
		{name: "rendr.environment.end", value: inv.EnvironmentEnd},
	} {
		if snapshot.value.IsZero() {
			continue
		}
		encoded, err := environment.Marshal(snapshot.value)
		if err != nil {
			return nil, err
		}
		properties = append(properties, xmlProperty{Name: snapshot.name, Value: encoded})
	}
	if len(properties) == 0 {
		return nil, nil
	}
	return &xmlProperties{Properties: properties}, nil
}

func writeEnvironmentMarkdown(buf *bytes.Buffer, inv Invocation) error {
	if inv.EnvironmentStart.IsZero() && inv.EnvironmentEnd.IsZero() {
		return nil
	}
	fmt.Fprintln(buf, "## Environment")
	fmt.Fprintln(buf)
	for _, snapshot := range []struct {
		label string
		value environment.Snapshot
	}{
		{label: "Start", value: inv.EnvironmentStart},
		{label: "End", value: inv.EnvironmentEnd},
	} {
		fmt.Fprintf(buf, "### %s\n\n", snapshot.label)
		if snapshot.value.IsZero() {
			fmt.Fprintln(buf, "`pending`")
			fmt.Fprintln(buf)
			continue
		}
		encoded, err := environment.Marshal(snapshot.value)
		if err != nil {
			return err
		}
		fmt.Fprintln(buf, "```json")
		fmt.Fprintln(buf, encoded)
		fmt.Fprintln(buf, "```")
		fmt.Fprintln(buf)
	}
	return nil
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

func formatCaseBlocker(c Case) string {
	if c.BlockerKind == "" {
		return ""
	}
	value := string(c.BlockerKind)
	if c.BlockedByCaseID != "" {
		value += ":" + c.BlockedByCaseID
	}
	if c.BlockerReason != "" {
		value += ":" + c.BlockerReason
	}
	return value
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
