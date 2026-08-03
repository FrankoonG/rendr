package gate

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCheckPhase2RejectsMissingRevisionIdentity(t *testing.T) {
	dir := t.TempDir()
	if err := Write(dir, State{Status: "green", At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	err := CheckPhase2Allowed(dir, newTestRepo(t))
	if err == nil || !strings.Contains(err.Error(), "missing revision identity") {
		t.Fatalf("err=%v", err)
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
	first := State{CommitSHA: "one", WorktreeSHA: "tree-one", Status: "running", At: time.Unix(1, 0)}
	second := State{CommitSHA: "two", WorktreeSHA: "tree-two", Status: "green", At: time.Unix(2, 0)}
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
	if *got != second {
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
