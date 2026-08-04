package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/catalog"
	"github.com/FrankoonG/rendr/regress/internal/manifest"
	"github.com/FrankoonG/rendr/regress/internal/report"
)

func TestRequirePassingVerifiedSetRejectsAuthorityBypasses(t *testing.T) {
	spec, evidence := syntheticEnforcedSpec(t, "final.authority", "T1")
	expected := []manifest.Spec{spec}

	t.Run("in-memory digest mismatch", func(t *testing.T) {
		suite, verified := publishFinalSuite(t, expected, []report.Case{{Name: spec.ID, Tier: spec.Tier, Evidence: evidence}}, runFlags{caseID: spec.ID})
		suite.Cases[0].Evidence["post_publish_mutation"] = "true"
		if err := requirePassingVerifiedSet(verified, suite, expected); err == nil || !strings.Contains(err.Error(), "in-memory") {
			t.Fatalf("digest mismatch error=%v", err)
		}
	})

	t.Run("invocation schema downgrade", func(t *testing.T) {
		suite, verified := publishFinalSuite(t, expected, []report.Case{{Name: spec.ID, Tier: spec.Tier, Evidence: evidence}}, runFlags{caseID: spec.ID})
		verified.Report.Invocation.SchemaVersion = invocationSchemaVersion - 1
		if err := requirePassingVerifiedSet(verified, suite, expected); err == nil || !strings.Contains(err.Error(), "invocation schema") {
			t.Fatalf("schema downgrade error=%v", err)
		}
	})

	t.Run("trusted manifest mismatch", func(t *testing.T) {
		suite, verified := publishFinalSuite(t, expected, []report.Case{{Name: spec.ID, Tier: spec.Tier, Evidence: evidence}}, runFlags{caseID: spec.ID})
		other, _ := syntheticEnforcedSpec(t, "final.other", "T1")
		if err := requirePassingVerifiedSet(verified, suite, []manifest.Spec{other}); err == nil || !strings.Contains(err.Error(), "trusted selected manifest") {
			t.Fatalf("trusted manifest mismatch error=%v", err)
		}
	})

	t.Run("self-attested contract state without evidence", func(t *testing.T) {
		digest, err := spec.CanonicalDigest()
		if err != nil {
			t.Fatal(err)
		}
		row := report.Case{
			Name: spec.ID, Tier: spec.Tier, CaseDigest: digest,
			Evidence: map[string]string{report.EvidenceContractStateKey: string(manifest.ContractStateEnforced)},
		}
		suite, verified := publishFinalSuiteWithoutReconcile(t, expected, []report.Case{row}, runFlags{caseID: spec.ID})
		if err := requirePassingVerifiedSet(verified, suite, expected); err == nil || !strings.Contains(err.Error(), "revalidate finalized manifest evidence") {
			t.Fatalf("self-attested proof error=%v", err)
		}
	})

	t.Run("failed final state", func(t *testing.T) {
		row := report.Case{Name: spec.ID, Tier: spec.Tier, Evidence: evidence, Failure: "synthetic product failure"}
		suite, verified := publishFinalSuite(t, expected, []report.Case{row}, runFlags{caseID: spec.ID})
		if err := requirePassingVerifiedSet(verified, suite, expected); err == nil || !strings.Contains(err.Error(), `state is "fail"`) {
			t.Fatalf("failed-state error=%v", err)
		}
	})
}

func TestRequirePassingVerifiedSetPinsFrozenUnprovenCatalog(t *testing.T) {
	spec := catalog.NormalFull()[0]
	expected := []manifest.Spec{spec}
	row := report.Case{Name: spec.ID, Tier: spec.Tier, Evidence: syntheticContractEvidence(spec)}
	suite, verified := publishFinalSuite(t, expected, []report.Case{row}, runFlags{
		caseID: spec.ID, allowUnprovenContracts: true,
	})
	if err := requirePassingVerifiedSet(verified, suite, expected); err != nil {
		t.Fatalf("frozen unproven baseline rejected: %v", err)
	}

	previous := v1M1UnprovenCatalogDigests[manifest.SuiteNormal]
	v1M1UnprovenCatalogDigests[manifest.SuiteNormal] = "sha256:" + strings.Repeat("0", 64)
	t.Cleanup(func() { v1M1UnprovenCatalogDigests[manifest.SuiteNormal] = previous })
	if err := requirePassingVerifiedSet(verified, suite, expected); err == nil || !strings.Contains(err.Error(), "frozen digest") {
		t.Fatalf("drifted frozen catalog error=%v", err)
	}
}

func TestValidateTrustedReleaseManifestRejectsPartialCatalog(t *testing.T) {
	spec, _ := syntheticEnforcedSpec(t, "release.partial", "T1")
	if err := validateTrustedReleaseManifest([]manifest.Spec{spec}); err == nil || !strings.Contains(err.Error(), "complete trusted") {
		t.Fatalf("partial release manifest error=%v", err)
	}
}

func TestPersistedPhase2EvidenceRequiresAuthorizationLineage(t *testing.T) {
	spec, evidence := syntheticEnforcedSpec(t, "phase2.authority", "T3")
	expected := []manifest.Spec{spec}
	suite, verified := publishFinalSuite(t, expected, []report.Case{{Name: spec.ID, Tier: spec.Tier, Evidence: evidence}}, runFlags{caseID: spec.ID})
	if err := requirePassingVerifiedSet(verified, suite, expected); err == nil || !strings.Contains(err.Error(), "missing phase-1 authorization") {
		t.Fatalf("missing phase-1 authorization error=%v", err)
	}

	authorization := &report.Phase1Authorization{
		CommitSHA:             verified.Report.Invocation.RevisionStart.CommitSHA,
		WorktreeSHA:           verified.Report.Invocation.RevisionStart.WorktreeSHA,
		ReportSetGeneration:   strings.Repeat("a", 32),
		CanonicalReportDigest: "sha256:" + strings.Repeat("b", 64),
	}
	verified.Report.Invocation.Phase1Authorization = authorization
	if err := validatePersistedManifestEvidence(verified.Report, expected); err != nil {
		t.Fatalf("well-formed persisted authorization rejected: %v", err)
	}
	authorization.CommitSHA = "wrong"
	if err := validatePersistedManifestEvidence(verified.Report, expected); err == nil || !strings.Contains(err.Error(), "revision") {
		t.Fatalf("wrong authorization revision error=%v", err)
	}
	authorization.CommitSHA = verified.Report.Invocation.RevisionStart.CommitSHA
	authorization.ReportSetGeneration = "bad"
	if err := validatePersistedManifestEvidence(verified.Report, expected); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("malformed authorization generation error=%v", err)
	}
}

func publishFinalSuite(t *testing.T, expected []manifest.Spec, rows []report.Case, cfg runFlags) (*report.Suite, report.VerifiedSet) {
	t.Helper()
	rows = cloneReportCases(rows)
	if err := reconcileReportRows(expected, rows); err != nil {
		t.Fatal(err)
	}
	return publishFinalSuiteWithoutReconcile(t, expected, rows, cfg)
}

func publishFinalSuiteWithoutReconcile(t *testing.T, expected []manifest.Spec, rows []report.Case, cfg runFlags) (*report.Suite, report.VerifiedSet) {
	t.Helper()
	identity, err := buildInvocationIdentity(cfg, expected[0].Suite, expected)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := captureTestLinuxEnvironment(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	revision := report.Revision{CommitSHA: "final-commit", WorktreeSHA: strings.Repeat("b", 64)}
	identity.EnvironmentStart = snapshot
	identity.EnvironmentEnd = snapshot
	identity.RevisionStart = revision
	identity.RevisionEnd = revision
	suite := report.New()
	suite.Invocation = identity
	suite.Cases = cloneReportCases(rows)
	suite.Complete = true
	suite.Started = time.Unix(1, 0).UTC()
	dir := t.TempDir()
	if err := report.Publish(context.Background(), dir, suite); err != nil {
		t.Fatal(err)
	}
	verified, err := report.Verify(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	return suite, verified
}
