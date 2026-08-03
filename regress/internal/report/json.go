package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/environment"
)

// JSONReportSchemaVersion identifies the canonical machine-readable report
// envelope. It is independent from Invocation.SchemaVersion.
const JSONReportSchemaVersion = 1

// Document is the content-addressed machine-readable form of one regression
// component. ReportDigest covers every field except ReportDigest itself.
type Document struct {
	SchemaVersion int        `json:"schema_version"`
	ReportDigest  string     `json:"report_digest"`
	State         string     `json:"state"`
	StartedAt     string     `json:"started_at"`
	Complete      bool       `json:"complete"`
	RunFailure    string     `json:"run_failure,omitempty"`
	Invocation    Invocation `json:"invocation"`
	Cases         []Case     `json:"cases"`
}

// Document returns a normalized snapshot and its canonical digest.
func (s *Suite) Document() (Document, error) {
	if s == nil {
		return Document{}, fmt.Errorf("report: nil suite")
	}
	invocation := s.Invocation
	if invocation.SelectedCaseIDs == nil {
		invocation.SelectedCaseIDs = []string{}
	} else {
		invocation.SelectedCaseIDs = append([]string(nil), invocation.SelectedCaseIDs...)
	}
	if invocation.RequestedCaseIDs == nil {
		invocation.RequestedCaseIDs = []string{}
	} else {
		invocation.RequestedCaseIDs = append([]string(nil), invocation.RequestedCaseIDs...)
	}
	invocation.EnvironmentStart = cloneEnvironmentSnapshot(invocation.EnvironmentStart)
	invocation.EnvironmentEnd = cloneEnvironmentSnapshot(invocation.EnvironmentEnd)
	cases := make([]Case, len(s.Cases))
	for i, source := range s.Cases {
		cases[i] = source
		if source.Evidence != nil {
			cases[i].Evidence = make(map[string]string, len(source.Evidence))
			for key, value := range source.Evidence {
				cases[i].Evidence[key] = value
			}
		}
	}
	document := Document{
		SchemaVersion: JSONReportSchemaVersion,
		State:         reportState(s),
		StartedAt:     s.Started.UTC().Format(time.RFC3339Nano),
		Complete:      s.Complete,
		RunFailure:    s.RunFailure,
		Invocation:    invocation,
		Cases:         cases,
	}
	digest, err := document.computeDigest()
	if err != nil {
		return Document{}, err
	}
	document.ReportDigest = digest
	return document, nil
}

func cloneEnvironmentSnapshot(snapshot environment.Snapshot) environment.Snapshot {
	clone := snapshot
	clone.CPU.Models = append([]string(nil), snapshot.CPU.Models...)
	clone.Interfaces = append([]environment.Interface(nil), snapshot.Interfaces...)
	clone.SocketSysctls = append([]environment.Sysctl(nil), snapshot.SocketSysctls...)
	clone.QDisc.State = append([]byte(nil), snapshot.QDisc.State...)
	return clone
}

// ReportDigest returns the digest embedded in Document.
func (s *Suite) ReportDigest() (string, error) {
	document, err := s.Document()
	if err != nil {
		return "", err
	}
	return document.ReportDigest, nil
}

// WriteJSON atomically writes the canonical machine-readable report.
func (s *Suite) WriteJSON(path string) error {
	document, err := s.Document()
	if err != nil {
		return err
	}
	// Emit the same compact canonical representation used by the digest. In
	// particular, indenting json.RawMessage environment fields would alter
	// their byte-level canonical form after a read-back.
	encoded, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("report: encode JSON document: %w", err)
	}
	encoded = append(encoded, '\n')
	return writeAtomic(path, encoded)
}

// ReadJSON reads one report and verifies its schema and content digest.
func ReadJSON(path string) (Document, error) {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return Document{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var document Document
	if err := decoder.Decode(&document); err != nil {
		return Document{}, fmt.Errorf("report: decode JSON document: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return Document{}, err
	}
	if err := document.VerifyDigest(); err != nil {
		return Document{}, err
	}
	return document, nil
}

// VerifyDigest verifies the report schema and content-addressed digest.
func (d Document) VerifyDigest() error {
	if d.SchemaVersion != JSONReportSchemaVersion {
		return fmt.Errorf("report: unsupported JSON schema version %d", d.SchemaVersion)
	}
	if !validManifestDigest(d.ReportDigest) {
		return fmt.Errorf("report: malformed report digest %q", d.ReportDigest)
	}
	want, err := d.computeDigest()
	if err != nil {
		return err
	}
	if d.ReportDigest != want {
		return fmt.Errorf("report: digest mismatch: got %s want %s", d.ReportDigest, want)
	}
	started, err := time.Parse(time.RFC3339Nano, d.StartedAt)
	if err != nil {
		return fmt.Errorf("report: invalid started_at %q: %w", d.StartedAt, err)
	}
	if canonical := started.UTC().Format(time.RFC3339Nano); d.StartedAt != canonical {
		return fmt.Errorf("report: non-canonical started_at %q, want %q", d.StartedAt, canonical)
	}
	suite := &Suite{
		Started:    started,
		Invocation: d.Invocation,
		Cases:      d.Cases,
		Complete:   d.Complete,
		RunFailure: d.RunFailure,
	}
	if wantState := reportState(suite); d.State != wantState {
		reason := invocationFailure(suite)
		if reason == "" && suite.AnyFailed() {
			reason = "one or more case rows failed"
		}
		return fmt.Errorf("report: state %q is inconsistent with contents; want %q (%s)", d.State, wantState, reason)
	}
	return nil
}

func (d Document) computeDigest() (string, error) {
	d.ReportDigest = ""
	encoded, err := json.Marshal(d)
	if err != nil {
		return "", fmt.Errorf("report: encode canonical document: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return fmt.Sprintf("sha256:%x", sum[:]), nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err == io.EOF {
		return nil
	} else if err != nil {
		return fmt.Errorf("report: decode trailing JSON: %w", err)
	}
	return fmt.Errorf("report: trailing JSON value")
}
