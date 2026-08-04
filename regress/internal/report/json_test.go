package report

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/environment"
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
	legacy, err := base.Document()
	if err != nil {
		t.Fatal(err)
	}
	legacy.SchemaVersion = 1
	legacy.ReportDigest, err = legacy.computeDigest()
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.VerifyDigest(); err == nil || !strings.Contains(err.Error(), "unsupported JSON schema version 1") {
		t.Fatalf("legacy schema verification error=%v", err)
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

	t.Run("report set publication", testReportSetPublication)
	t.Run("missing and truncated report set files", testReportSetMissingAndTruncatedFiles)
	t.Run("failed publication invalidates fixed set", testFailedReportSetPublication)
	t.Run("competing writers serialize generations", testCompetingReportSetWriters)
	t.Run("invocation lease and context cancellation", testReportSetLeaseLifecycle)
	t.Run("semantic companion verification", testSemanticCompanionVerification)
	t.Run("deterministic companion rendering", testDeterministicCompanionRendering)
	t.Run("case execution state", testCaseExecutionState)
}

func testReportSetPublication(t *testing.T) {
	suite := sealedTestSuite(t)
	dir := t.TempDir()
	if err := suite.PublishSet(dir); err != nil {
		t.Fatal(err)
	}
	verified, err := VerifySet(dir)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest, err := suite.ReportDigest()
	if err != nil {
		t.Fatal(err)
	}
	if verified.Report.ReportDigest != wantDigest || verified.Manifest.CanonicalReportDigest != wantDigest {
		t.Fatalf("verified digests report=%q manifest=%q want=%q", verified.Report.ReportDigest, verified.Manifest.CanonicalReportDigest, wantDigest)
	}
	if len(verified.Manifest.Artifacts) != 3 {
		t.Fatalf("manifest artifacts=%+v", verified.Manifest.Artifacts)
	}
	for _, name := range []string{JUnitReportFileName, MarkdownReportFileName, JSONReportFileName, ReportSetManifestName, ReportSetLockName} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("published file %s: %v", name, err)
		}
	}
}

func testReportSetMissingAndTruncatedFiles(t *testing.T) {
	tests := []struct {
		name   string
		target string
		mutate func(*testing.T, string)
		want   string
	}{
		{name: "missing JUnit", target: JUnitReportFileName, mutate: removeReportSetTestFile, want: JUnitReportFileName},
		{name: "truncated JUnit", target: JUnitReportFileName, mutate: truncateReportSetTestFile, want: JUnitReportFileName},
		{name: "missing Markdown", target: MarkdownReportFileName, mutate: removeReportSetTestFile, want: MarkdownReportFileName},
		{name: "truncated Markdown", target: MarkdownReportFileName, mutate: truncateReportSetTestFile, want: MarkdownReportFileName},
		{name: "missing JSON", target: JSONReportFileName, mutate: removeReportSetTestFile, want: JSONReportFileName},
		{name: "truncated JSON", target: JSONReportFileName, mutate: truncateReportSetTestFile, want: JSONReportFileName},
		{name: "missing hash manifest", target: ReportSetManifestName, mutate: removeReportSetTestFile, want: "report-set manifest"},
		{name: "truncated hash manifest", target: ReportSetManifestName, mutate: truncateReportSetTestFile, want: "report-set manifest"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := sealedTestSuite(t).PublishSet(dir); err != nil {
				t.Fatal(err)
			}
			tt.mutate(t, filepath.Join(dir, tt.target))
			if _, err := VerifySet(dir); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("VerifySet error=%v, want substring %q", err, tt.want)
			}
		})
	}

	t.Run("wrong artifact hash", func(t *testing.T) {
		dir := t.TempDir()
		if err := sealedTestSuite(t).PublishSet(dir); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, ReportSetManifestName)
		encoded, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		manifest, err := decodeSetManifest(encoded)
		if err != nil {
			t.Fatal(err)
		}
		manifest.Artifacts[0].SHA256 = "sha256:" + strings.Repeat("0", 64)
		encoded, err = encodeSetManifest(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := writeAtomic(path, encoded); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifySet(dir); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
			t.Fatalf("VerifySet error=%v, want digest mismatch", err)
		}
	})

	t.Run("wrong canonical report digest", func(t *testing.T) {
		dir := t.TempDir()
		if err := sealedTestSuite(t).PublishSet(dir); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, ReportSetManifestName)
		encoded, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		manifest, err := decodeSetManifest(encoded)
		if err != nil {
			t.Fatal(err)
		}
		manifest.CanonicalReportDigest = "sha256:" + strings.Repeat("f", 64)
		encoded, err = encodeSetManifest(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := writeAtomic(path, encoded); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifySet(dir); err == nil || !strings.Contains(err.Error(), "canonical report digest mismatch") {
			t.Fatalf("VerifySet error=%v, want canonical digest mismatch", err)
		}
	})
}

func testFailedReportSetPublication(t *testing.T) {
	t.Run("partial fixed-file replacement", func(t *testing.T) {
		dir := t.TempDir()
		blockedSummary := filepath.Join(dir, MarkdownReportFileName)
		if err := os.Mkdir(blockedSummary, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(blockedSummary, "keep"), []byte("block replacement"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := sealedTestSuite(t).PublishSet(dir); err == nil || !strings.Contains(err.Error(), "write summary") {
			t.Fatalf("PublishSet error=%v, want summary failure", err)
		}
		for _, name := range []string{JUnitReportFileName, JSONReportFileName, ReportSetManifestName} {
			if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
				t.Fatalf("failed publication retained %s: %v", name, err)
			}
		}
		if _, err := VerifySet(dir); err == nil || !strings.Contains(err.Error(), "report-set manifest") {
			t.Fatalf("failed publication verified as a report set: %v", err)
		}
	})

	t.Run("staging failure invalidates prior generation", func(t *testing.T) {
		dir := t.TempDir()
		if err := sealedTestSuite(t).PublishSet(dir); err != nil {
			t.Fatal(err)
		}
		invalid := sealedTestSuite(t)
		invalid.Cases[0].ExecutionState = ExecutionStateNotRun
		if err := invalid.PublishSet(dir); err == nil || !strings.Contains(err.Error(), "blocker_kind") {
			t.Fatalf("PublishSet error=%v, want invalid execution state", err)
		}
		for _, name := range []string{JUnitReportFileName, MarkdownReportFileName, JSONReportFileName, ReportSetManifestName} {
			if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
				t.Fatalf("failed replacement retained prior %s: %v", name, err)
			}
		}
	})

	t.Run("manifest commit failure removes companions", func(t *testing.T) {
		dir := t.TempDir()
		var hookErr error
		err := publishReportSet(sealedTestSuite(t), dir, func(name string) {
			if name != JSONReportFileName {
				return
			}
			manifestDir := filepath.Join(dir, ReportSetManifestName)
			if hookErr = os.Mkdir(manifestDir, 0o700); hookErr != nil {
				return
			}
			hookErr = os.WriteFile(filepath.Join(manifestDir, "keep"), []byte("block manifest commit"), 0o600)
		})
		if hookErr != nil {
			t.Fatal(hookErr)
		}
		if err == nil || !strings.Contains(err.Error(), "write report-set manifest") {
			t.Fatalf("PublishSet error=%v, want manifest commit failure", err)
		}
		for _, name := range []string{JUnitReportFileName, MarkdownReportFileName, JSONReportFileName} {
			if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
				t.Fatalf("manifest failure retained companion %s: %v", name, err)
			}
		}
		if _, err := VerifySet(dir); err == nil {
			t.Fatal("manifest directory verified as a committed report set")
		}
	})
}

func testCompetingReportSetWriters(t *testing.T) {
	dir := t.TempDir()
	first := sealedTestSuite(t)
	first.Cases[0].Evidence["writer"] = "first"
	second := sealedTestSuite(t)
	second.Cases[0].Evidence["writer"] = "second"

	firstPaused := make(chan struct{})
	releaseFirst := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- publishReportSet(first, dir, func(name string) {
			if name == JUnitReportFileName {
				close(firstPaused)
				<-releaseFirst
			}
		})
	}()
	select {
	case <-firstPaused:
	case <-time.After(5 * time.Second):
		t.Fatal("first writer did not reach its interleaving point")
	}
	if _, err := os.Stat(filepath.Join(dir, ReportSetManifestName)); !os.IsNotExist(err) {
		close(releaseFirst)
		t.Fatalf("manifest became visible before the first generation completed: %v", err)
	}

	secondStarted := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		close(secondStarted)
		secondDone <- second.PublishSet(dir)
	}()
	<-secondStarted
	select {
	case err := <-secondDone:
		close(releaseFirst)
		<-firstDone
		t.Fatalf("competing writer bypassed report-directory lock: %v", err)
	case <-time.After(150 * time.Millisecond):
	}

	close(releaseFirst)
	if err := waitReportSetWriter(t, firstDone); err != nil {
		t.Fatalf("first writer: %v", err)
	}
	if err := waitReportSetWriter(t, secondDone); err != nil {
		t.Fatalf("second writer: %v", err)
	}
	verified, err := VerifySet(dir)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest, err := second.ReportDigest()
	if err != nil {
		t.Fatal(err)
	}
	if verified.Report.ReportDigest != wantDigest {
		t.Fatalf("final generation digest=%q want second writer %q", verified.Report.ReportDigest, wantDigest)
	}
}

func testReportSetLeaseLifecycle(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	lease, err := AcquireReportSetLease(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			if err := lease.Close(); err != nil {
				t.Errorf("close report-set lease: %v", err)
			}
		}
	})

	first := sealedTestSuite(t)
	first.Cases[0].Evidence["lease"] = "first"
	if err := lease.Publish(ctx, first); err != nil {
		t.Fatal(err)
	}
	verified, err := lease.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	wantFirst, err := first.ReportDigest()
	if err != nil {
		t.Fatal(err)
	}
	if verified.Report.ReportDigest != wantFirst {
		t.Fatalf("leased report digest=%q want %q", verified.Report.ReportDigest, wantFirst)
	}

	waitCtx, cancel := context.WithTimeout(ctx, 75*time.Millisecond)
	defer cancel()
	started := time.Now()
	if err := Invalidate(waitCtx, dir); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("competing invalidation error=%v, want context deadline", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("context-aware lock took %s to cancel", elapsed)
	}
	if _, err := lease.Verify(ctx); err != nil {
		t.Fatalf("canceled competing invalidation changed leased report: %v", err)
	}

	if err := lease.Invalidate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := lease.Verify(ctx); err == nil || !strings.Contains(err.Error(), "report-set manifest") {
		t.Fatalf("invalidated report verified: %v", err)
	}
	second := sealedTestSuite(t)
	second.Cases[0].Evidence["lease"] = "second"
	if err := lease.Publish(ctx, second); err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	closed = true
	if _, err := lease.Verify(ctx); !errors.Is(err, ErrReportSetLeaseClosed) {
		t.Fatalf("closed lease verification error=%v, want ErrReportSetLeaseClosed", err)
	}
	if _, err := Verify(ctx, dir); err != nil {
		t.Fatalf("released directory could not be verified: %v", err)
	}
	if err := Invalidate(ctx, dir); err != nil {
		t.Fatalf("invalidate released report: %v", err)
	}
	if err := InvalidateSetContext(ctx, dir); err != nil {
		t.Fatalf("idempotent context invalidation: %v", err)
	}
	for _, name := range []string{JUnitReportFileName, MarkdownReportFileName, JSONReportFileName, ReportSetManifestName} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("invalidation retained %s: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, ReportSetLockName)); err != nil {
		t.Fatalf("invalidation removed report-set lock: %v", err)
	}

	sameLeaseDir := t.TempDir()
	sameLease, err := AcquireReportSetLease(ctx, sameLeaseDir)
	if err != nil {
		t.Fatal(err)
	}
	writerPaused := make(chan struct{})
	releaseWriter := make(chan struct{})
	writerDone := make(chan error, 1)
	leasingSuite := sealedTestSuite(t)
	releasedWriter := false
	defer func() {
		if !releasedWriter {
			close(releaseWriter)
		}
		_ = sameLease.Close()
	}()
	go func() {
		writerDone <- sameLease.publish(ctx, leasingSuite, func(name string) {
			if name == JUnitReportFileName {
				close(writerPaused)
				<-releaseWriter
			}
		})
	}()
	select {
	case <-writerPaused:
	case <-time.After(5 * time.Second):
		t.Fatal("leased publisher did not reach its interleaving point")
	}
	sameLeaseWait, cancelSameLeaseWait := context.WithTimeout(ctx, 75*time.Millisecond)
	defer cancelSameLeaseWait()
	if _, err := sameLease.Verify(sameLeaseWait); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("same-lease verification error=%v, want context deadline", err)
	}
	close(releaseWriter)
	releasedWriter = true
	if err := waitReportSetWriter(t, writerDone); err != nil {
		t.Fatalf("leased publisher: %v", err)
	}
	if err := sameLease.Close(); err != nil {
		t.Fatal(err)
	}

	canceled, cancelImmediately := context.WithCancel(ctx)
	cancelImmediately()
	missingDir := filepath.Join(t.TempDir(), "canceled")
	if err := Publish(canceled, missingDir, sealedTestSuite(t)); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled publication error=%v, want context canceled", err)
	}
	if _, err := os.Stat(missingDir); !os.IsNotExist(err) {
		t.Fatalf("pre-canceled lock created report directory: %v", err)
	}
}

func testSemanticCompanionVerification(t *testing.T) {
	tests := []struct {
		name        string
		artifact    string
		old         string
		replacement string
	}{
		{name: "JUnit", artifact: JUnitReportFileName, old: `name="case.one"`, replacement: `name="case.tampered"`},
		{name: "Markdown", artifact: MarkdownReportFileName, old: "| case.one |", replacement: "| case.tampered |"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := sealedTestSuite(t).PublishSet(dir); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, tt.artifact)
			encoded, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			tampered := bytes.Replace(encoded, []byte(tt.old), []byte(tt.replacement), 1)
			if bytes.Equal(tampered, encoded) {
				t.Fatalf("%s mutation target %q was absent", tt.artifact, tt.old)
			}
			if err := writeAtomic(path, tampered); err != nil {
				t.Fatal(err)
			}
			rehashReportSetTestArtifact(t, dir, tt.artifact, tampered)
			if _, err := VerifySet(dir); err == nil || !strings.Contains(err.Error(), tt.artifact+" does not exactly correspond") {
				t.Fatalf("semantic %s tampering verification error=%v", tt.artifact, err)
			}
		})
	}
}

func rehashReportSetTestArtifact(t *testing.T, dir, artifactName string, contents []byte) {
	t.Helper()
	manifestPath := filepath.Join(dir, ReportSetManifestName)
	encoded, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := decodeSetManifest(encoded)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for i := range manifest.Artifacts {
		if manifest.Artifacts[i].Name != artifactName {
			continue
		}
		manifest.Artifacts[i].SHA256 = sha256Bytes(contents)
		manifest.Artifacts[i].Size = int64(len(contents))
		found = true
		break
	}
	if !found {
		t.Fatalf("manifest has no artifact %q", artifactName)
	}
	encoded, err = encodeSetManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(manifestPath, encoded); err != nil {
		t.Fatal(err)
	}
}

func testDeterministicCompanionRendering(t *testing.T) {
	suite := sealedTestSuite(t)
	suite.Cases[1].Tier = "T2"
	first, err := suite.marshalJUnit()
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	second, err := suite.marshalJUnit()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("JUnit rendering changed without a canonical report change:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
	var root struct {
		Time   float64 `xml:"time,attr"`
		Suites []struct {
			Time float64 `xml:"time,attr"`
		} `xml:"testsuite"`
	}
	if err := xml.Unmarshal(first, &root); err != nil {
		t.Fatal(err)
	}
	if root.Time != 3 {
		t.Fatalf("JUnit total time=%v want 3", root.Time)
	}
	var suiteTotal float64
	for _, child := range root.Suites {
		suiteTotal += child.Time
	}
	if root.Time != suiteTotal {
		t.Fatalf("JUnit total time=%v, child suite total=%v", root.Time, suiteTotal)
	}
}

func testCaseExecutionState(t *testing.T) {
	t.Run("Add defaults to executed", func(t *testing.T) {
		suite := New()
		suite.Add(Case{Name: "case.one", Tier: "T1"})
		if got := suite.Cases[0].ExecutionState; got != ExecutionStateExecuted {
			t.Fatalf("execution state=%q want %q", got, ExecutionStateExecuted)
		}
	})

	t.Run("not run is preserved and cannot complete", func(t *testing.T) {
		suite := sealedTestSuite(t)
		suite.Cases[0].Failure = "synthetic blocker"
		suite.Cases[1].ExecutionState = ExecutionStateNotRun
		suite.Cases[1].BlockerKind = BlockerKindCase
		suite.Cases[1].BlockedByCaseID = suite.Cases[0].Name
		suite.Cases[1].Optional = true
		document, err := suite.Document()
		if err != nil {
			t.Fatal(err)
		}
		if document.Complete || document.State != "fail" || !suite.AnyFailed() {
			t.Fatalf("not-run document complete=%t state=%q AnyFailed=%t", document.Complete, document.State, suite.AnyFailed())
		}
		row := document.Cases[1]
		if row.ExecutionState != ExecutionStateNotRun || row.BlockedByCaseID != suite.Cases[0].Name {
			t.Fatalf("not-run row=%+v", row)
		}

		dir := t.TempDir()
		if err := suite.PublishSet(dir); err != nil {
			t.Fatal(err)
		}
		verified, err := VerifySet(dir)
		if err != nil {
			t.Fatal(err)
		}
		if verified.Report.Complete || verified.Report.State != "fail" || verified.Report.Cases[1].ExecutionState != ExecutionStateNotRun {
			t.Fatalf("verified not-run report=%+v", verified.Report)
		}
		junit, err := os.ReadFile(filepath.Join(dir, JUnitReportFileName))
		if err != nil {
			t.Fatal(err)
		}
		markdown, err := os.ReadFile(filepath.Join(dir, MarkdownReportFileName))
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{`complete="false"`, `execution_state="not_run"`, `blocker_kind="case"`, `blocked_by_case_id="case.one"`, "case not run"} {
			if !strings.Contains(string(junit), want) {
				t.Fatalf("JUnit missing %q:\n%s", want, junit)
			}
		}
		for _, want := range []string{"- Complete: `false`", "| case.two | not_run | case:case.one |", "FAIL (NOT_RUN)", "**OVERALL: FAIL**"} {
			if !strings.Contains(string(markdown), want) {
				t.Fatalf("Markdown missing %q:\n%s", want, markdown)
			}
		}
	})

	t.Run("malformed states are rejected", func(t *testing.T) {
		tests := []Case{
			{Name: "unknown", ExecutionState: "invented"},
			{Name: "missing blocker", ExecutionState: ExecutionStateNotRun},
			{Name: "signal missing reason", ExecutionState: ExecutionStateNotRun, BlockerKind: BlockerKindSignal},
			{Name: "executed blocker", ExecutionState: ExecutionStateExecuted, BlockedByCaseID: "other"},
		}
		for _, row := range tests {
			t.Run(row.Name, func(t *testing.T) {
				suite := sealedTestSuite(t)
				suite.Cases[0].ExecutionState = row.ExecutionState
				suite.Cases[0].BlockerKind = row.BlockerKind
				suite.Cases[0].BlockedByCaseID = row.BlockedByCaseID
				suite.Cases[0].BlockerReason = row.BlockerReason
				if _, err := suite.ReportDigest(); err == nil || !strings.Contains(err.Error(), "execution state") {
					t.Fatalf("ReportDigest error=%v", err)
				}
			})
		}
	})

	t.Run("case blocker must reference an earlier failed row", func(t *testing.T) {
		suite := sealedTestSuite(t)
		suite.Cases[1].ExecutionState = ExecutionStateNotRun
		suite.Cases[1].BlockerKind = BlockerKindCase
		suite.Cases[1].BlockedByCaseID = suite.Cases[0].Name
		if failure := invocationIdentityFailure(suite); !strings.Contains(failure, "did not fail") {
			t.Fatalf("passing blocker identity failure=%q", failure)
		}
		suite.Cases[0].Failure = "synthetic blocker"
		if failure := invocationIdentityFailure(suite); failure != "" {
			t.Fatalf("failed blocker identity failure=%q", failure)
		}
	})
}

func removeReportSetTestFile(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

func truncateReportSetTestFile(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data[:len(data)/2], 0o600); err != nil {
		t.Fatal(err)
	}
}

func waitReportSetWriter(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("report-set writer did not finish")
		return nil
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

	t.Run("v6 contract proof is distinct from execution success", func(t *testing.T) {
		proven := sealedTestSuite(t)
		proven.Invocation.SchemaVersion = 6
		proven.Invocation.ContractProofRequired = true
		for i := range proven.Cases {
			proven.Cases[i].Evidence[EvidenceContractStateKey] = "enforced"
		}
		if failure := invocationIdentityFailure(proven); failure != "" {
			t.Fatalf("proven invocation failure=%q", failure)
		}
		if state := reportState(proven); state != "pass" {
			t.Fatalf("proven state=%q", state)
		}

		unproven := sealedTestSuite(t)
		unproven.Invocation.SchemaVersion = 6
		unproven.Invocation.ContractProofRequired = true
		unproven.Invocation.AllowUnprovenContracts = true
		for i := range unproven.Cases {
			unproven.Cases[i].Evidence[EvidenceContractStateKey] = "blocked"
		}
		if failure := invocationIdentityFailure(unproven); failure != "" {
			t.Fatalf("unproven invocation failure=%q", failure)
		}
		if state := reportState(unproven); state != "unproven" {
			t.Fatalf("unproven state=%q", state)
		}
		junitPath := filepath.Join(t.TempDir(), "junit.xml")
		if err := unproven.WriteJUnit(junitPath); err != nil {
			t.Fatal(err)
		}
		junit, err := os.ReadFile(junitPath)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(junit), `state="unproven"`) ||
			!strings.Contains(string(junit), `failures="1"`) ||
			!strings.Contains(string(junit), "case contracts remain unproven") {
			t.Fatalf("unproven JUnit is not fail-visible:\n%s", junit)
		}

		missing := sealedTestSuite(t)
		missing.Invocation.SchemaVersion = 6
		missing.Invocation.ContractProofRequired = true
		if failure := invocationIdentityFailure(missing); !strings.Contains(failure, "missing "+EvidenceContractStateKey) {
			t.Fatalf("missing contract state failure=%q", failure)
		}
		if state := reportState(missing); state != "fail" {
			t.Fatalf("missing contract state report state=%q", state)
		}

		release := sealedTestSuite(t)
		release.Invocation.SchemaVersion = 6
		release.Invocation.Scope = "full"
		release.Invocation.Full = true
		release.Invocation.ContractProofRequired = true
		release.Invocation.AllowUnprovenContracts = true
		release.Invocation.ReleaseManifest = true
		release.Invocation.EvidenceClass = EvidenceClassV1ReleaseManifest
		for i := range release.Cases {
			release.Cases[i].Evidence[EvidenceContractStateKey] = "blocked"
		}
		if failure := invocationIdentityFailure(release); !strings.Contains(failure, "release manifest cannot allow unproven contracts") {
			t.Fatalf("release allowance failure=%q", failure)
		}
	})
}

func TestReleaseManifestRequiresCurrentUnbypassedFullIdentity(t *testing.T) {
	for _, tunFull := range []bool{false, true} {
		name := "normal full"
		if tunFull {
			name = "TUN full"
		}
		t.Run("valid "+name, func(t *testing.T) {
			suite := validReleaseSuite(t, tunFull)
			if failure := invocationIdentityFailure(suite); failure != "" {
				t.Fatalf("valid release identity failed: %s", failure)
			}
			document, err := suite.Document()
			if err != nil {
				t.Fatal(err)
			}
			if document.State != "pass" {
				t.Fatalf("valid release state=%q, want pass", document.State)
			}
		})
	}

	tests := []struct {
		name   string
		mutate func(*Suite)
		want   string
	}{
		{
			name: "partial release",
			mutate: func(s *Suite) {
				s.Complete = false
			},
			want: "release manifest must contain a completed selected manifest",
		},
		{
			name: "partial selected identity",
			mutate: func(s *Suite) {
				s.Complete = false
				s.Cases = s.Cases[:1]
			},
			want: "selected case count 2 does not match report rows 1",
		},
		{
			name: "v4 downgrade",
			mutate: func(s *Suite) {
				s.Invocation.SchemaVersion = 4
			},
			want: "release manifest invocation schema is 4, want current schema 6",
		},
		{
			name: "v5 downgrade",
			mutate: func(s *Suite) {
				s.Invocation.SchemaVersion = 5
			},
			want: "release manifest invocation schema is 5, want current schema 6",
		},
		{
			name: "future schema",
			mutate: func(s *Suite) {
				s.Invocation.SchemaVersion = InvocationSchemaVersion + 1
			},
			want: "invocation schema 7 is unsupported",
		},
		{
			name: "forced bypass",
			mutate: func(s *Suite) {
				s.Invocation.Forced = true
			},
			want: "release manifest cannot use forced execution",
		},
		{
			name: "non-linux bypass",
			mutate: func(s *Suite) {
				s.Invocation.AllowNonLinux = true
			},
			want: "release manifest cannot allow non-Linux execution",
		},
		{
			name: "unproven bypass",
			mutate: func(s *Suite) {
				s.Invocation.AllowUnprovenContracts = true
			},
			want: "release manifest cannot allow unproven contracts",
		},
		{
			name: "contract proof disabled",
			mutate: func(s *Suite) {
				s.Invocation.ContractProofRequired = false
			},
			want: "release manifest must require contract proof",
		},
		{
			name: "contract proof unproven",
			mutate: func(s *Suite) {
				s.Cases[0].Evidence[EvidenceContractStateKey] = "blocked"
			},
			want: "release manifest contract proof is unproven, want proven",
		},
		{
			name: "phase 1 authorization missing",
			mutate: func(s *Suite) {
				s.Invocation.Phase1Authorization = nil
			},
			want: "release manifest is missing phase-1 authorization",
		},
		{
			name: "phase 1 authorization malformed",
			mutate: func(s *Suite) {
				s.Invocation.Phase1Authorization.ReportSetGeneration = "bad"
			},
			want: "phase-1 authorization generation is malformed",
		},
		{
			name: "full flag missing",
			mutate: func(s *Suite) {
				s.Invocation.Full = false
			},
			want: "release manifest must select exactly one of full or TUN full",
		},
		{
			name: "contradictory full flags",
			mutate: func(s *Suite) {
				s.Invocation.TUNFull = true
			},
			want: "release manifest must select exactly one of full or TUN full",
		},
		{
			name: "TUN flag on normal suite",
			mutate: func(s *Suite) {
				s.Invocation.Full = false
				s.Invocation.TUNFull = true
			},
			want: "non-TUN release manifest must use only the full invocation flag",
		},
		{
			name: "normal flag on TUN suite",
			mutate: func(s *Suite) {
				s.Invocation.Suite = "tun-full"
			},
			want: "tun-full release manifest must use only the TUN-full invocation flag",
		},
		{
			name: "filtered full invocation",
			mutate: func(s *Suite) {
				s.Invocation.Tier = "T1"
			},
			want: "release manifest cannot contain phase, tier, case, selector, or from-case filters",
		},
		{
			name: "partial requested identity",
			mutate: func(s *Suite) {
				s.Invocation.RequestedCaseIDs = s.Invocation.RequestedCaseIDs[:1]
			},
			want: "release manifest requested case IDs do not exactly match selected case IDs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suite := validReleaseSuite(t, false)
			tt.mutate(suite)
			if failure := invocationIdentityFailure(suite); !strings.Contains(failure, tt.want) {
				t.Fatalf("release identity failure=%q, want substring %q", failure, tt.want)
			}
			document, err := suite.Document()
			if err != nil {
				t.Fatal(err)
			}
			if document.State != "fail" {
				t.Fatalf("invalid release state=%q, want fail", document.State)
			}
		})
	}
}

func validReleaseSuite(t *testing.T, tunFull bool) *Suite {
	t.Helper()
	suite := sealedTestSuite(t)
	suite.Invocation.SchemaVersion = InvocationSchemaVersion
	suite.Invocation.Scope = "full"
	suite.Invocation.Full = !tunFull
	suite.Invocation.TUNFull = tunFull
	if tunFull {
		suite.Invocation.Suite = "tun-full"
	}
	suite.Invocation.AllowNonLinux = false
	suite.Invocation.EvidenceClass = EvidenceClassV1ReleaseManifest
	suite.Invocation.ReleaseManifest = true
	suite.Invocation.ContractProofRequired = true
	suite.Invocation.AllowUnprovenContracts = false
	suite.Invocation.Phase1Authorization = &Phase1Authorization{
		CommitSHA:             suite.Invocation.RevisionStart.CommitSHA,
		WorktreeSHA:           suite.Invocation.RevisionStart.WorktreeSHA,
		ReportSetGeneration:   strings.Repeat("a", 32),
		CanonicalReportDigest: "sha256:" + strings.Repeat("b", 64),
	}
	environmentSnapshot := validLinuxReportEnvironment(t)
	suite.Invocation.EnvironmentStart = environmentSnapshot
	suite.Invocation.EnvironmentEnd = environmentSnapshot
	for i := range suite.Cases {
		suite.Cases[i].Evidence[EvidenceContractStateKey] = "enforced"
	}
	return suite
}

func validLinuxReportEnvironment(t *testing.T) environment.Snapshot {
	t.Helper()
	sysctlNames := []string{
		"net.core.rmem_default",
		"net.core.rmem_max",
		"net.core.wmem_default",
		"net.core.wmem_max",
		"net.ipv4.tcp_congestion_control",
		"net.ipv4.tcp_mtu_probing",
		"net.ipv4.tcp_rmem",
		"net.ipv4.tcp_wmem",
		"net.ipv4.udp_rmem_min",
		"net.ipv4.udp_wmem_min",
	}
	sysctls := make([]environment.Sysctl, 0, len(sysctlNames))
	for _, name := range sysctlNames {
		sysctls = append(sysctls, environment.Sysctl{Name: name, Value: "4096 87380 6291456"})
	}
	return sealReportEnvironment(t, environment.Snapshot{
		SchemaVersion: environment.SnapshotSchemaVersion,
		Runtime: environment.Runtime{
			GoVersion: "go1.26.3",
			GOOS:      "linux",
			GOARCH:    "amd64",
		},
		Hostname:      "synthetic-regress-vm",
		KernelRelease: "6.8.0-test",
		BootID:        "00000000-0000-4000-8000-000000000001",
		NumCPU:        8,
		CPU: environment.CPU{
			Models:         []string{"Synthetic CPU"},
			OnlineSet:      "0-7",
			ProcessAllowed: "0-3",
		},
		TotalMemoryBytes: 8 << 30,
		Clocksource:      "tsc",
		Interfaces:       []environment.Interface{{Name: "test0", MTU: 1500}},
		SocketSysctls:    sysctls,
		QDisc:            environment.QDisc{Supported: true, State: []byte(`[{"kind":"fq_codel"}]`)},
		Metadata:         environment.Metadata{VMRole: "client", CPUGroup: "CPU1/128-255"},
	})
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
