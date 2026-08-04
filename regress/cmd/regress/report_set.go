package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/FrankoonG/rendr/regress/internal/manifest"
	"github.com/FrankoonG/rendr/regress/internal/report"
)

const phase1ProofDirectoryName = "phase1-proofs"

func phase1ProofRoot(reportDir string) string {
	return filepath.Join(reportDir, phase1ProofDirectoryName)
}

func phase1ProofDir(reportDir, generation string) string {
	return filepath.Join(phase1ProofRoot(reportDir), generation)
}

func writeReports(suite *report.Suite, dir string) error {
	return suite.Publish(context.Background(), dir)
}

func requirePassingFinalReport(dir string, suite *report.Suite, expected []manifest.Spec) error {
	verified, err := report.Verify(context.Background(), dir)
	if err != nil {
		return fmt.Errorf("cannot verify finalized report set: %w", err)
	}
	return requirePassingVerifiedSet(verified, suite, expected)
}

func requirePassingFinalReportStore(ctx context.Context, reports invocationReportStore, suite *report.Suite, expected []manifest.Spec) error {
	_, err := verifyPassingFinalReportStore(ctx, reports, suite, expected)
	return err
}

func verifyPassingFinalReportStore(ctx context.Context, reports invocationReportStore, suite *report.Suite, expected []manifest.Spec) (report.VerifiedSet, error) {
	verified, err := reports.verify(ctx)
	if err != nil {
		return report.VerifiedSet{}, fmt.Errorf("cannot verify finalized report set: %w", err)
	}
	if err := requirePassingVerifiedSet(verified, suite, expected); err != nil {
		return report.VerifiedSet{}, err
	}
	return verified, nil
}

func publishPhase1Proof(ctx context.Context, reportDir string, suite *report.Suite, expected []manifest.Spec) (verified report.VerifiedSet, err error) {
	root := phase1ProofRoot(reportDir)
	if err := os.MkdirAll(root, 0o755); err != nil {
		return report.VerifiedSet{}, fmt.Errorf("create phase 1 proof root: %w", err)
	}
	stageDir, err := os.MkdirTemp(root, ".phase1-proof-stage-")
	if err != nil {
		return report.VerifiedSet{}, fmt.Errorf("create phase 1 proof staging directory: %w", err)
	}
	defer func() {
		if stageDir != "" {
			err = errors.Join(err, os.RemoveAll(stageDir))
		}
	}()
	if err := report.Publish(ctx, stageDir, suite); err != nil {
		return report.VerifiedSet{}, fmt.Errorf("publish phase 1 proof: %w", err)
	}
	verified, err = report.Verify(ctx, stageDir)
	if err != nil {
		return report.VerifiedSet{}, fmt.Errorf("verify phase 1 proof: %w", err)
	}
	if err := requirePassingVerifiedSet(verified, suite, expected); err != nil {
		return report.VerifiedSet{}, fmt.Errorf("validate phase 1 proof: %w", err)
	}
	targetDir := phase1ProofDir(reportDir, verified.Manifest.Generation)
	if _, err := os.Lstat(targetDir); err == nil {
		return report.VerifiedSet{}, fmt.Errorf("phase 1 proof generation already exists: %s", verified.Manifest.Generation)
	} else if !os.IsNotExist(err) {
		return report.VerifiedSet{}, fmt.Errorf("inspect phase 1 proof generation: %w", err)
	}
	if err := os.Rename(stageDir, targetDir); err != nil {
		return report.VerifiedSet{}, fmt.Errorf("commit phase 1 proof generation: %w", err)
	}
	stageDir = ""
	verified, err = report.Verify(ctx, targetDir)
	if err != nil {
		return report.VerifiedSet{}, fmt.Errorf("verify committed phase 1 proof: %w", err)
	}
	if err := requirePassingVerifiedSet(verified, suite, expected); err != nil {
		return report.VerifiedSet{}, fmt.Errorf("validate committed phase 1 proof: %w", err)
	}
	return verified, nil
}

func requirePassingVerifiedSet(verified report.VerifiedSet, suite *report.Suite, expected []manifest.Spec) error {
	final := verified.Report
	wantDigest, err := suite.ReportDigest()
	if err != nil {
		return fmt.Errorf("cannot seal in-memory final report: %w", err)
	}
	if final.ReportDigest != wantDigest {
		return fmt.Errorf("finalized report digest %q does not match in-memory result %q", final.ReportDigest, wantDigest)
	}
	if !final.Complete {
		return errors.New("finalized report is incomplete, refusing a zero exit")
	}
	if final.Invocation.SchemaVersion != invocationSchemaVersion {
		return fmt.Errorf("finalized report invocation schema is %d, want %d", final.Invocation.SchemaVersion, invocationSchemaVersion)
	}
	if err := validatePersistedManifestEvidence(final, expected); err != nil {
		return err
	}
	switch final.State {
	case "pass":
		return nil
	case "unproven":
		if final.Invocation.AllowUnprovenContracts && !final.Invocation.ReleaseManifest {
			want := v1M1UnprovenCatalogDigests[final.Invocation.Suite]
			if want != "" && final.Invocation.CatalogDigest == want {
				return nil
			}
			return fmt.Errorf("unproven baseline catalog digest is %q, want frozen digest %q", final.Invocation.CatalogDigest, want)
		}
		return errors.New("finalized report contains unproven manifest contracts, refusing a zero exit")
	default:
		return fmt.Errorf("finalized report state is %q, refusing a zero exit", final.State)
	}
}

func validatePersistedManifestEvidence(final report.Document, expected []manifest.Spec) error {
	if len(expected) == 0 {
		return errors.New("finalized report has no trusted selected manifest")
	}
	if final.Invocation.ReleaseManifest {
		if err := validateTrustedReleaseManifest(expected); err != nil {
			return err
		}
	}
	wantManifestDigest, err := selectedManifestDigest(expected)
	if err != nil {
		return fmt.Errorf("digest trusted selected manifest: %w", err)
	}
	wantCatalogDigest, err := suiteRegistryDigest(expected[0].Suite)
	if err != nil {
		return fmt.Errorf("digest trusted suite catalog: %w", err)
	}
	wantIDs := manifestIDs(expected)
	if final.Invocation.Suite != expected[0].Suite || final.Invocation.ManifestDigest != wantManifestDigest ||
		final.Invocation.CatalogDigest != wantCatalogDigest || final.Invocation.SelectedCases != len(expected) ||
		!equalStrings(final.Invocation.SelectedCaseIDs, wantIDs) {
		return errors.New("finalized report identity does not match the trusted selected manifest")
	}
	if requiresPhase1Authorization(expected) && !final.Invocation.Forced {
		if final.Invocation.Phase1Authorization == nil {
			return errors.New("finalized phase-2 report is missing phase-1 authorization")
		}
		authorization := final.Invocation.Phase1Authorization
		if authorization.CommitSHA != final.Invocation.RevisionStart.CommitSHA ||
			authorization.WorktreeSHA != final.Invocation.RevisionStart.WorktreeSHA {
			return errors.New("finalized phase-2 authorization revision does not match the invocation")
		}
		if !validPhase1ProofGeneration(authorization.ReportSetGeneration) || !validSHA256Digest(authorization.CanonicalReportDigest) {
			return errors.New("finalized phase-2 authorization proof identity is malformed")
		}
	}
	rows := cloneReportCases(final.Cases)
	if len(rows) != len(expected) {
		return fmt.Errorf("finalized report has %d rows, want %d trusted rows", len(rows), len(expected))
	}
	for i, spec := range expected {
		if spec.Contract == nil {
			return fmt.Errorf("trusted case %q has no contract", spec.ID)
		}
		digest, err := spec.CanonicalDigest()
		if err != nil {
			return fmt.Errorf("digest trusted case %q: %w", spec.ID, err)
		}
		if rows[i].CaseDigest != digest {
			return fmt.Errorf("finalized case %q digest does not match the trusted manifest", spec.ID)
		}
		if rows[i].Evidence[report.EvidenceContractStateKey] != string(spec.Contract.State) {
			return fmt.Errorf("finalized case %q contract state is self-attested or stale", spec.ID)
		}
	}
	if err := reconcileReportRows(expected, rows); err != nil {
		return fmt.Errorf("revalidate finalized manifest evidence: %w", err)
	}
	return nil
}

func validPhase1ProofGeneration(generation string) bool {
	if len(generation) != 32 {
		return false
	}
	_, err := hex.DecodeString(generation)
	return err == nil
}

func validSHA256Digest(digest string) bool {
	const prefix = "sha256:"
	if len(digest) != len(prefix)+64 || digest[:len(prefix)] != prefix {
		return false
	}
	_, err := hex.DecodeString(digest[len(prefix):])
	return err == nil
}

func validateTrustedReleaseManifest(expected []manifest.Spec) error {
	if err := manifest.ValidateRelease(expected); err != nil {
		return fmt.Errorf("trusted release manifest is invalid: %w", err)
	}
	normalSpecs, tunCatalog, err := loadCatalogs()
	if err != nil {
		return fmt.Errorf("load trusted release catalog: %w", err)
	}
	var full []manifest.Spec
	switch expected[0].Suite {
	case manifest.SuiteNormal:
		full = normalSpecs
	case manifest.SuiteTUN:
		full = tunCatalog.specs
	default:
		return fmt.Errorf("trusted release suite %q is unsupported", expected[0].Suite)
	}
	if !equalStrings(manifestIDs(expected), manifestIDs(full)) {
		return errors.New("release manifest does not contain the complete trusted executable catalog")
	}
	return nil
}
