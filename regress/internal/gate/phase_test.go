package gate

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testReportSetGeneration = "0123456789abcdef0123456789abcdef"

var testCanonicalReportDigest = "sha256:" + strings.Repeat("a", 64)

func TestWriteRejectsMissingRevisionIdentity(t *testing.T) {
	dir := t.TempDir()
	state := validGateState("green")
	state.CommitSHA = ""
	if err := Write(dir, state); err == nil || !strings.Contains(err.Error(), "revision identity") {
		t.Fatalf("Write error=%v, want missing revision identity", err)
	}
	if _, err := os.Stat(filepath.Join(dir, StateFileName)); !os.IsNotExist(err) {
		t.Fatalf("invalid state created a gate file: %v", err)
	}
}

func TestCheckPhase2AllowsBoundGreenState(t *testing.T) {
	root := newTestRepo(t)
	revision, err := CurrentRevision(root)
	if err != nil {
		t.Fatal(err)
	}
	state := validGateState("green")
	state.CommitSHA = revision.CommitSHA
	state.WorktreeSHA = revision.WorktreeSHA
	dir := t.TempDir()
	if err := Write(dir, state); err != nil {
		t.Fatal(err)
	}
	if err := CheckPhase2Allowed(dir, root); err != nil {
		t.Fatalf("CheckPhase2Allowed error=%v", err)
	}
}

func TestCurrentRevisionChangesWithUntrackedContent(t *testing.T) {
	root := newTestRepo(t)
	before, err := CurrentRevision(root)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "gate-fingerprint-test.tmp")
	if err := os.WriteFile(path, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	one, err := CurrentRevision(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	two, err := CurrentRevision(root)
	if err != nil {
		t.Fatal(err)
	}
	if before.WorktreeSHA == one.WorktreeSHA || one.WorktreeSHA == two.WorktreeSHA {
		t.Fatalf("fingerprints did not track untracked content: before=%s one=%s two=%s", before.WorktreeSHA, one.WorktreeSHA, two.WorktreeSHA)
	}
}

func TestCurrentRevisionChangesWithTrackedContent(t *testing.T) {
	root := newTestRepo(t)
	before, err := CurrentRevision(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tracked.txt"), []byte("changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := CurrentRevision(root)
	if err != nil {
		t.Fatal(err)
	}
	if before.WorktreeSHA == after.WorktreeSHA {
		t.Fatal("fingerprint did not track a tracked-file edit")
	}
}

func TestWriteAtomicallyReplacesState(t *testing.T) {
	dir := t.TempDir()
	first := validGateState("running")
	first.CommitSHA = "one"
	first.WorktreeSHA = "tree-one"
	first.At = time.Unix(1, 0)
	second := validGateState("green")
	second.CommitSHA = "two"
	second.WorktreeSHA = "tree-two"
	second.At = time.Unix(2, 0)
	if err := Write(dir, first); err != nil {
		t.Fatal(err)
	}
	if err := Write(dir, second); err != nil {
		t.Fatal(err)
	}
	got, err := Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.SchemaVersion != second.SchemaVersion || got.CommitSHA != second.CommitSHA ||
		got.WorktreeSHA != second.WorktreeSHA || got.ReportSetGeneration != second.ReportSetGeneration ||
		got.CanonicalReportDigest != second.CanonicalReportDigest || got.Status != second.Status ||
		!got.At.Equal(second.At) {
		t.Fatalf("state=%+v want %+v", *got, second)
	}
	temps, err := filepath.Glob(filepath.Join(dir, "."+StateFileName+"-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(temps) != 0 {
		t.Fatalf("temporary state files leaked: %v", temps)
	}
}

func TestRunningAndRedMayOmitReportIdentity(t *testing.T) {
	for _, status := range []string{"running", "red"} {
		t.Run(status, func(t *testing.T) {
			dir := t.TempDir()
			state := validGateState(status)
			if err := Write(dir, state); err != nil {
				t.Fatal(err)
			}
			got, err := Read(dir)
			if err != nil {
				t.Fatal(err)
			}
			if got.ReportSetGeneration != "" || got.CanonicalReportDigest != "" {
				t.Fatalf("state unexpectedly has report identity: %+v", *got)
			}
			encoded, err := os.ReadFile(filepath.Join(dir, StateFileName))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(encoded), "report_set_generation") || strings.Contains(string(encoded), "canonical_report_digest") {
				t.Fatalf("optional report identity was serialized:\n%s", encoded)
			}
		})
	}
}

func TestWriteValidationFailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		want   string
		mutate func(*State)
	}{
		{name: "legacy schema", want: "schema version", mutate: func(s *State) { s.SchemaVersion = 1 }},
		{name: "unknown status", want: "status", mutate: func(s *State) { s.Status = "pass" }},
		{name: "missing timestamp", want: "timestamp", mutate: func(s *State) { s.At = time.Time{} }},
		{name: "green missing generation", want: "report-set generation", mutate: func(s *State) { s.ReportSetGeneration = "" }},
		{name: "green missing digest", want: "canonical report digest", mutate: func(s *State) { s.CanonicalReportDigest = "" }},
		{name: "malformed generation", want: "generation", mutate: func(s *State) { s.ReportSetGeneration = "not-a-generation" }},
		{name: "malformed digest", want: "digest", mutate: func(s *State) { s.CanonicalReportDigest = "sha256:not-a-digest" }},
		{
			name: "running partial report identity",
			want: "requires canonical report digest",
			mutate: func(s *State) {
				s.Status = "running"
				s.CanonicalReportDigest = ""
			},
		},
		{
			name: "red partial report identity",
			want: "requires report-set generation",
			mutate: func(s *State) {
				s.Status = "red"
				s.ReportSetGeneration = ""
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := validGateState("green")
			tt.mutate(&state)
			dir := t.TempDir()
			err := Write(dir, state)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Write error=%v, want %q", err, tt.want)
			}
			if _, statErr := os.Stat(filepath.Join(dir, StateFileName)); !os.IsNotExist(statErr) {
				t.Fatalf("invalid state created a gate file: %v", statErr)
			}
		})
	}
}

func TestReadValidationFailsClosed(t *testing.T) {
	legacy := validGateState("green")
	legacy.SchemaVersion = 1
	missingBinding := validGateState("green")
	missingBinding.ReportSetGeneration = ""
	missingBinding.CanonicalReportDigest = ""
	malformedDigest := validGateState("green")
	malformedDigest.CanonicalReportDigest = "sha256:not-a-digest"
	validJSON := marshalGateState(t, validGateState("green"))
	tests := []struct {
		name    string
		encoded []byte
		want    string
	}{
		{name: "legacy schema", encoded: marshalGateState(t, legacy), want: "schema version"},
		{name: "green missing report binding", encoded: marshalGateState(t, missingBinding), want: "report-set generation"},
		{name: "malformed digest", encoded: marshalGateState(t, malformedDigest), want: "canonical report digest"},
		{
			name:    "unknown field",
			encoded: []byte(strings.TrimSuffix(string(validJSON), "}") + `,"unexpected":true}`),
			want:    "unknown field",
		},
		{name: "trailing JSON", encoded: append(append([]byte(nil), validJSON...), []byte("\n{}")...), want: "multiple JSON values"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, StateFileName), tt.encoded, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Read(dir); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Read error=%v, want %q", err, tt.want)
			}
		})
	}
}

func validGateState(status string) State {
	state := State{
		SchemaVersion: StateSchemaVersion,
		CommitSHA:     "commit",
		WorktreeSHA:   "worktree",
		Status:        status,
		At:            time.Unix(1, 0),
	}
	if status == "green" {
		state.ReportSetGeneration = testReportSetGeneration
		state.CanonicalReportDigest = testCanonicalReportDigest
	}
	return state
}

func marshalGateState(t *testing.T, state State) []byte {
	t.Helper()
	encoded, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func newTestRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	runGit(t, root, "init", "--quiet")
	runGit(t, root, "config", "user.name", "rendr regression test")
	runGit(t, root, "config", "user.email", "regress@example.invalid")
	if err := os.WriteFile(filepath.Join(root, "tracked.txt"), []byte("initial\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "add", "tracked.txt")
	runGit(t, root, "commit", "--quiet", "-m", "initial")
	return root
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v (%s)", args, err, strings.TrimSpace(string(out)))
	}
}
