package report

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	ReportSetSchemaVersion = 1

	JUnitReportFileName    = "junit.xml"
	MarkdownReportFileName = "SUMMARY.md"
	JSONReportFileName     = "report.json"
	ReportSetManifestName  = "report-set.json"
	ReportSetLockName      = ".report-set.lock"
)

var reportSetArtifacts = []struct {
	name  string
	label string
}{
	{name: JUnitReportFileName, label: "JUnit"},
	{name: MarkdownReportFileName, label: "summary"},
	{name: JSONReportFileName, label: "JSON report"},
}

// SetArtifact binds one fixed report filename to the exact bytes in a
// published generation.
type SetArtifact struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// SetManifest is the commit marker for one complete report generation. A
// fixed report file is not valid evidence without this manifest.
type SetManifest struct {
	SchemaVersion         int           `json:"schema_version"`
	Generation            string        `json:"generation"`
	CanonicalReportDigest string        `json:"canonical_report_digest"`
	Artifacts             []SetArtifact `json:"artifacts"`
}

// VerifiedSet is returned only after the manifest, all companion hashes, and
// the canonical JSON report digest have been verified under the directory
// lock.
type VerifiedSet struct {
	Manifest SetManifest
	Report   Document
}

// ErrReportSetLeaseClosed is returned when an operation uses a released
// report-directory lease.
var ErrReportSetLeaseClosed = errors.New("report: report-set lease is closed")

// ReportSetLease holds exclusive ownership of a report directory across one
// invocation. Callers that perform more than one lifecycle operation should
// keep the lease until the invocation has published and verified its final
// generation.
type ReportSetLease struct {
	dir  string
	lock *reportSetLock
	gate chan struct{}
}

type reportSetPublishHook func(publishedFile string)

// AcquireReportSetLease waits for exclusive ownership of dir until ctx is
// canceled. The returned lease must be closed.
func AcquireReportSetLease(ctx context.Context, dir string) (*ReportSetLease, error) {
	if err := checkReportContext(ctx); err != nil {
		return nil, err
	}
	if dir == "" {
		return nil, errors.New("report: empty report directory")
	}
	absoluteDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve report directory: %w", err)
	}
	lock, err := acquireReportSetLock(ctx, absoluteDir)
	if err != nil {
		return nil, err
	}
	lease := &ReportSetLease{
		dir:  absoluteDir,
		lock: lock,
		gate: make(chan struct{}, 1),
	}
	lease.gate <- struct{}{}
	return lease, nil
}

// Close releases the report-directory lease. It is idempotent.
func (l *ReportSetLease) Close() error {
	if l == nil || l.gate == nil {
		return nil
	}
	<-l.gate
	defer l.leave()
	if l.lock == nil {
		return nil
	}
	err := l.lock.release()
	l.lock = nil
	return err
}

// Release is an alias for Close.
func (l *ReportSetLease) Release() error {
	return l.Close()
}

// Publish stages and publishes JUnit, Markdown, and JSON as one generation
// while retaining this invocation's exclusive directory lease.
func (l *ReportSetLease) Publish(ctx context.Context, s *Suite) error {
	return l.publish(ctx, s, nil)
}

func (l *ReportSetLease) publish(ctx context.Context, s *Suite, hook reportSetPublishHook) error {
	if err := l.enter(ctx); err != nil {
		return err
	}
	defer l.leave()
	if l.lock == nil {
		return ErrReportSetLeaseClosed
	}
	return publishReportSetLocked(ctx, s, l.dir, hook)
}

// Verify verifies one stable report generation while retaining this
// invocation's exclusive directory lease.
func (l *ReportSetLease) Verify(ctx context.Context) (VerifiedSet, error) {
	if err := l.enter(ctx); err != nil {
		return VerifiedSet{}, err
	}
	defer l.leave()
	if l.lock == nil {
		return VerifiedSet{}, ErrReportSetLeaseClosed
	}
	return verifyReportSetLocked(ctx, l.dir)
}

// Invalidate removes the validity marker and all fixed report artifacts while
// retaining this invocation's exclusive directory lease.
func (l *ReportSetLease) Invalidate(ctx context.Context) error {
	if err := l.enter(ctx); err != nil {
		return err
	}
	defer l.leave()
	if l.lock == nil {
		return ErrReportSetLeaseClosed
	}
	return removePublishedReportSetContext(ctx, l.dir)
}

func (l *ReportSetLease) enter(ctx context.Context) error {
	if l == nil || l.gate == nil {
		return ErrReportSetLeaseClosed
	}
	if err := checkReportContext(ctx); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-l.gate:
	}
	if err := checkReportContext(ctx); err != nil {
		l.leave()
		return err
	}
	return nil
}

func (l *ReportSetLease) leave() {
	l.gate <- struct{}{}
}

// Publish acquires a context-aware operation lease, publishes suite, and
// releases the lease. Use AcquireReportSetLease when ownership must span an
// entire invocation.
func Publish(ctx context.Context, dir string, s *Suite) (err error) {
	lease, err := AcquireReportSetLease(ctx, dir)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, lease.Close())
	}()
	return lease.Publish(ctx, s)
}

// Publish is the Suite-oriented form of the context-aware Publish API.
func (s *Suite) Publish(ctx context.Context, dir string) error {
	return Publish(ctx, dir, s)
}

// PublishSet preserves the pre-context API for existing callers.
func (s *Suite) PublishSet(dir string) error {
	return s.Publish(context.Background(), dir)
}

// PublishSetContext retains the report-set naming while allowing callers to
// cancel lock acquisition and publication.
func (s *Suite) PublishSetContext(ctx context.Context, dir string) error {
	return s.Publish(ctx, dir)
}

func publishReportSet(s *Suite, dir string, hook reportSetPublishHook) error {
	return publishReportSetContext(context.Background(), s, dir, hook)
}

func publishReportSetContext(ctx context.Context, s *Suite, dir string, hook reportSetPublishHook) (err error) {
	lease, err := AcquireReportSetLease(ctx, dir)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, lease.Close())
	}()
	return lease.publish(ctx, s, hook)
}

func publishReportSetLocked(ctx context.Context, s *Suite, dir string, hook reportSetPublishHook) (err error) {
	if err := checkReportContext(ctx); err != nil {
		return err
	}
	manifestPath := filepath.Join(dir, ReportSetManifestName)
	if removeErr := os.Remove(manifestPath); removeErr != nil && !os.IsNotExist(removeErr) {
		cleanupErr := removePublishedReportSet(dir)
		return errors.Join(fmt.Errorf("invalidate prior report-set manifest: %w", removeErr), cleanupErr)
	}

	committed := false
	defer func() {
		if !committed {
			err = errors.Join(err, removePublishedReportSet(dir))
		}
	}()

	if s == nil {
		return errors.New("report: cannot publish a nil suite")
	}
	document, err := s.Document()
	if err != nil {
		return fmt.Errorf("seal report document: %w", err)
	}
	rendered, err := renderReportSetArtifacts(document)
	if err != nil {
		return fmt.Errorf("render report set: %w", err)
	}
	if err := checkReportContext(ctx); err != nil {
		return err
	}
	generation, err := newReportSetGeneration()
	if err != nil {
		return err
	}
	stageDir, err := os.MkdirTemp(dir, ".report-set-stage-"+generation+"-")
	if err != nil {
		return fmt.Errorf("create report-set staging directory: %w", err)
	}
	defer os.RemoveAll(stageDir)

	stagePaths := map[string]string{
		JUnitReportFileName:    filepath.Join(stageDir, JUnitReportFileName),
		MarkdownReportFileName: filepath.Join(stageDir, MarkdownReportFileName),
		JSONReportFileName:     filepath.Join(stageDir, JSONReportFileName),
	}
	for _, artifact := range reportSetArtifacts {
		if err := checkReportContext(ctx); err != nil {
			return err
		}
		if err := writeAtomic(stagePaths[artifact.name], rendered[artifact.name]); err != nil {
			return fmt.Errorf("write staged %s: %w", artifact.label, err)
		}
	}

	staged := make(map[string][]byte, len(reportSetArtifacts))
	manifest := SetManifest{
		SchemaVersion: ReportSetSchemaVersion,
		Generation:    generation,
		Artifacts:     make([]SetArtifact, 0, len(reportSetArtifacts)),
	}
	for _, artifact := range reportSetArtifacts {
		data, readErr := os.ReadFile(stagePaths[artifact.name])
		if readErr != nil {
			return fmt.Errorf("read staged %s: %w", artifact.label, readErr)
		}
		staged[artifact.name] = data
		manifest.Artifacts = append(manifest.Artifacts, SetArtifact{
			Name:   artifact.name,
			SHA256: sha256Bytes(data),
			Size:   int64(len(data)),
		})
	}

	stagedDocument, err := decodeJSONDocument(staged[JSONReportFileName])
	if err != nil {
		return fmt.Errorf("verify staged JSON report: %w", err)
	}
	if stagedDocument.ReportDigest != document.ReportDigest {
		return fmt.Errorf(
			"staged JSON report digest %q does not match frozen report digest %q",
			stagedDocument.ReportDigest, document.ReportDigest,
		)
	}
	manifest.CanonicalReportDigest = stagedDocument.ReportDigest
	if err := manifest.validate(); err != nil {
		return fmt.Errorf("validate staged report-set manifest: %w", err)
	}

	for _, artifact := range reportSetArtifacts {
		if err := checkReportContext(ctx); err != nil {
			return err
		}
		if err := writeAtomic(filepath.Join(dir, artifact.name), staged[artifact.name]); err != nil {
			return fmt.Errorf("write %s: %w", artifact.label, err)
		}
		if hook != nil {
			hook(artifact.name)
		}
	}
	if _, err := verifyReportSetArtifacts(ctx, dir, manifest); err != nil {
		return fmt.Errorf("verify staged report-set publication: %w", err)
	}

	encodedManifest, err := encodeSetManifest(manifest)
	if err != nil {
		return err
	}
	if err := writeAtomic(manifestPath, encodedManifest); err != nil {
		return fmt.Errorf("write report-set manifest: %w", err)
	}
	if hook != nil {
		hook(ReportSetManifestName)
	}
	if _, err := verifyReportSetLocked(ctx, dir); err != nil {
		return fmt.Errorf("verify committed report set: %w", err)
	}
	committed = true
	return nil
}

// Verify acquires a context-aware operation lease and verifies one stable
// report generation.
func Verify(ctx context.Context, dir string) (verified VerifiedSet, err error) {
	lease, err := AcquireReportSetLease(ctx, dir)
	if err != nil {
		return VerifiedSet{}, err
	}
	defer func() {
		err = errors.Join(err, lease.Close())
	}()
	return lease.Verify(ctx)
}

// VerifySet preserves the pre-context API for existing callers.
func VerifySet(dir string) (VerifiedSet, error) {
	return Verify(context.Background(), dir)
}

// VerifySetContext retains the report-set naming while allowing callers to
// cancel lock acquisition and verification.
func VerifySetContext(ctx context.Context, dir string) (VerifiedSet, error) {
	return Verify(ctx, dir)
}

// Invalidate acquires a context-aware operation lease and removes any
// published report generation.
func Invalidate(ctx context.Context, dir string) (err error) {
	lease, err := AcquireReportSetLease(ctx, dir)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, lease.Close())
	}()
	return lease.Invalidate(ctx)
}

// InvalidateSet is the background-context compatibility form of Invalidate.
func InvalidateSet(dir string) error {
	return Invalidate(context.Background(), dir)
}

// InvalidateSetContext retains the report-set naming while allowing callers
// to cancel lock acquisition and invalidation.
func InvalidateSetContext(ctx context.Context, dir string) error {
	return Invalidate(ctx, dir)
}

func verifyReportSetLocked(ctx context.Context, dir string) (VerifiedSet, error) {
	if err := checkReportContext(ctx); err != nil {
		return VerifiedSet{}, err
	}
	manifestPath := filepath.Join(dir, ReportSetManifestName)
	encoded, err := os.ReadFile(manifestPath)
	if err != nil {
		return VerifiedSet{}, fmt.Errorf("read report-set manifest: %w", err)
	}
	manifest, err := decodeSetManifest(encoded)
	if err != nil {
		return VerifiedSet{}, err
	}
	document, err := verifyReportSetArtifacts(ctx, dir, manifest)
	if err != nil {
		return VerifiedSet{}, err
	}
	return VerifiedSet{Manifest: manifest, Report: document}, nil
}

func verifyReportSetArtifacts(ctx context.Context, dir string, manifest SetManifest) (Document, error) {
	if err := manifest.validate(); err != nil {
		return Document{}, err
	}
	contents := make(map[string][]byte, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		if err := checkReportContext(ctx); err != nil {
			return Document{}, err
		}
		data, err := os.ReadFile(filepath.Join(dir, artifact.Name))
		if err != nil {
			return Document{}, fmt.Errorf("read report-set artifact %s: %w", artifact.Name, err)
		}
		if int64(len(data)) != artifact.Size {
			return Document{}, fmt.Errorf("report-set artifact %s size mismatch: got %d want %d", artifact.Name, len(data), artifact.Size)
		}
		if got := sha256Bytes(data); got != artifact.SHA256 {
			return Document{}, fmt.Errorf("report-set artifact %s digest mismatch: got %s want %s", artifact.Name, got, artifact.SHA256)
		}
		contents[artifact.Name] = data
	}

	document, err := decodeJSONDocument(contents[JSONReportFileName])
	if err != nil {
		return Document{}, fmt.Errorf("verify canonical JSON report: %w", err)
	}
	if document.ReportDigest != manifest.CanonicalReportDigest {
		return Document{}, fmt.Errorf(
			"canonical report digest mismatch: JSON has %q, manifest has %q",
			document.ReportDigest, manifest.CanonicalReportDigest,
		)
	}
	if err := checkReportContext(ctx); err != nil {
		return Document{}, err
	}
	expected, err := renderReportSetArtifacts(document)
	if err != nil {
		return Document{}, fmt.Errorf("reconstruct report-set companions: %w", err)
	}
	for _, artifact := range reportSetArtifacts {
		if !bytes.Equal(contents[artifact.name], expected[artifact.name]) {
			return Document{}, fmt.Errorf("report-set artifact %s does not exactly correspond to canonical %s", artifact.name, JSONReportFileName)
		}
	}
	return document, nil
}

func renderReportSetArtifacts(document Document) (map[string][]byte, error) {
	suite, err := suiteFromDocument(document)
	if err != nil {
		return nil, fmt.Errorf("restore canonical report document: %w", err)
	}
	canonicalJSON, err := encodeJSONDocument(document)
	if err != nil {
		return nil, err
	}
	roundTrip, err := suite.Document()
	if err != nil {
		return nil, fmt.Errorf("normalize canonical report document: %w", err)
	}
	roundTripJSON, err := encodeJSONDocument(roundTrip)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonicalJSON, roundTripJSON) {
		return nil, errors.New("report document is not in normalized canonical form")
	}
	junit, err := suite.marshalJUnit()
	if err != nil {
		return nil, fmt.Errorf("render JUnit: %w", err)
	}
	markdown, err := suite.marshalMarkdown()
	if err != nil {
		return nil, fmt.Errorf("render Markdown: %w", err)
	}
	return map[string][]byte{
		JUnitReportFileName:    junit,
		MarkdownReportFileName: markdown,
		JSONReportFileName:     canonicalJSON,
	}, nil
}

func (m SetManifest) validate() error {
	if m.SchemaVersion != ReportSetSchemaVersion {
		return fmt.Errorf("report-set manifest schema is %d, want %d", m.SchemaVersion, ReportSetSchemaVersion)
	}
	if len(m.Generation) != 32 {
		return fmt.Errorf("report-set generation %q is malformed", m.Generation)
	}
	if _, err := hex.DecodeString(m.Generation); err != nil {
		return fmt.Errorf("report-set generation %q is malformed: %w", m.Generation, err)
	}
	if !validManifestDigest(m.CanonicalReportDigest) {
		return fmt.Errorf("canonical report digest %q is malformed", m.CanonicalReportDigest)
	}
	if len(m.Artifacts) != len(reportSetArtifacts) {
		return fmt.Errorf("report-set manifest has %d artifacts, want %d", len(m.Artifacts), len(reportSetArtifacts))
	}
	for i, want := range reportSetArtifacts {
		got := m.Artifacts[i]
		if got.Name != want.name {
			return fmt.Errorf("report-set artifact %d is %q, want %q", i, got.Name, want.name)
		}
		if got.Size <= 0 {
			return fmt.Errorf("report-set artifact %s has invalid size %d", got.Name, got.Size)
		}
		if !validManifestDigest(got.SHA256) {
			return fmt.Errorf("report-set artifact %s has malformed SHA-256 %q", got.Name, got.SHA256)
		}
	}
	return nil
}

func encodeSetManifest(manifest SetManifest) ([]byte, error) {
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode report-set manifest: %w", err)
	}
	return append(encoded, '\n'), nil
}

func decodeSetManifest(encoded []byte) (SetManifest, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var manifest SetManifest
	if err := decoder.Decode(&manifest); err != nil {
		return SetManifest{}, fmt.Errorf("decode report-set manifest: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return SetManifest{}, fmt.Errorf("decode report-set manifest: %w", err)
	}
	if err := manifest.validate(); err != nil {
		return SetManifest{}, err
	}
	return manifest, nil
}

func newReportSetGeneration() (string, error) {
	var generation [16]byte
	if _, err := rand.Read(generation[:]); err != nil {
		return "", fmt.Errorf("create report-set generation: %w", err)
	}
	return hex.EncodeToString(generation[:]), nil
}

func sha256Bytes(data []byte) string {
	digest := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", digest[:])
}

func removePublishedReportSet(dir string) error {
	return removePublishedReportSetContext(context.Background(), dir)
}

func removePublishedReportSetContext(ctx context.Context, dir string) error {
	paths := []string{ReportSetManifestName}
	for _, artifact := range reportSetArtifacts {
		paths = append(paths, artifact.name)
	}
	var removeErrors []error
	for _, name := range paths {
		if err := checkReportContext(ctx); err != nil {
			removeErrors = append(removeErrors, err)
			break
		}
		path := filepath.Join(dir, name)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			removeErrors = append(removeErrors, fmt.Errorf("remove %s: %w", path, err))
		}
	}
	return errors.Join(removeErrors...)
}
