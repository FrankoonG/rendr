// Package gate enforces the two-phase contract from
// docs/regression-suite.md §4: phase 1 (rendr self-check, T1+T2) must
// be validated green for the current commit before phase 2 (T3-T5)
// is allowed to run.
//
// State is persisted in <report-dir>/last_phase1.json. --force-phase2
// bypasses the check (local debug only; CI must not pass it).
package gate

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const StateFileName = "last_phase1.json"

// State recorded after each phase-1 run. Phase-2 entry verifies the
// current git HEAD matches CommitSHA and Status == "green".
type State struct {
	CommitSHA   string    `json:"commit_sha"`
	WorktreeSHA string    `json:"worktree_sha"`
	Status      string    `json:"status"` // "running" | "green" | "red"
	At          time.Time `json:"at"`
}

// Revision binds a phase result to both HEAD and all non-ignored source
// changes, including untracked files.
type Revision struct {
	CommitSHA   string
	WorktreeSHA string
}

// Write records the phase-1 outcome.
func Write(reportDir string, s State) error {
	if err := os.MkdirAll(reportDir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	path := filepath.Join(reportDir, StateFileName)
	tmp, err := os.CreateTemp(reportDir, "."+StateFileName+"-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()
	if _, err := tmp.Write(b); err != nil {
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
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Rename(tmpPath, path)
}

// Read returns the persisted state. Returns os.ErrNotExist if no
// phase-1 has been recorded yet.
func Read(reportDir string) (*State, error) {
	b, err := os.ReadFile(filepath.Join(reportDir, StateFileName))
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// CurrentRevision returns the full commit and a content hash for tracked
// changes plus non-ignored untracked files in repoPath. Git lookup failures
// fail closed.
func CurrentRevision(repoPath string) (Revision, error) {
	root, err := gitOutputAt(repoPath, "rev-parse", "--show-toplevel")
	if err != nil {
		return Revision{}, fmt.Errorf("locate repository: %w", err)
	}
	root = strings.TrimSpace(root)
	head, err := gitOutputAt(root, "rev-parse", "HEAD")
	if err != nil {
		return Revision{}, fmt.Errorf("resolve HEAD: %w", err)
	}
	head = strings.TrimSpace(head)
	if head == "" {
		return Revision{}, errors.New("resolve HEAD: empty commit")
	}

	h := sha256.New()
	hashField(h, []byte("commit"))
	hashField(h, []byte(head))
	diff, err := gitBytesAt(root, "diff", "--binary", "HEAD", "--", ".")
	if err != nil {
		return Revision{}, fmt.Errorf("hash tracked changes: %w", err)
	}
	hashField(h, []byte("tracked-diff"))
	hashField(h, diff)
	untrackedRaw, err := gitBytesAt(root, "ls-files", "--others", "--exclude-standard", "-z")
	if err != nil {
		return Revision{}, fmt.Errorf("list untracked files: %w", err)
	}
	var untracked []string
	for _, raw := range strings.Split(string(untrackedRaw), "\x00") {
		if raw != "" {
			untracked = append(untracked, raw)
		}
	}
	sort.Strings(untracked)
	for _, rel := range untracked {
		path := filepath.Join(root, filepath.FromSlash(rel))
		info, err := os.Lstat(path)
		if err != nil {
			return Revision{}, fmt.Errorf("stat untracked file %s: %w", rel, err)
		}
		var contents []byte
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return Revision{}, fmt.Errorf("read untracked symlink %s: %w", rel, err)
			}
			contents = []byte(target)
		} else if info.Mode().IsRegular() {
			contents, err = os.ReadFile(path)
			if err != nil {
				return Revision{}, fmt.Errorf("hash untracked file %s: %w", rel, err)
			}
		} else {
			return Revision{}, fmt.Errorf("hash untracked file %s: unsupported mode %s", rel, info.Mode())
		}
		hashField(h, []byte("untracked"))
		hashField(h, []byte(rel))
		hashField(h, []byte(info.Mode().String()))
		hashField(h, contents)
	}
	return Revision{CommitSHA: head, WorktreeSHA: fmt.Sprintf("%x", h.Sum(nil))}, nil
}

func hashField(h interface{ Write([]byte) (int, error) }, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = h.Write(size[:])
	_, _ = h.Write(value)
}

// CheckPhase2Allowed returns nil when phase-2 may run. Otherwise an
// error explains why (no state, stale state, or red state).
func CheckPhase2Allowed(reportDir, repoPath string) error {
	s, err := Read(reportDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("phase 1 has never been run; run --phase=1 first")
		}
		return fmt.Errorf("phase 1 state unreadable: %w", err)
	}
	if s.Status != "green" {
		return fmt.Errorf("phase 1 last outcome was %q (at %s)", s.Status, s.At.Format(time.RFC3339))
	}
	if s.CommitSHA == "" || s.WorktreeSHA == "" {
		return errors.New("phase 1 state is missing revision identity; rerun phase 1")
	}
	current, err := CurrentRevision(repoPath)
	if err != nil {
		return fmt.Errorf("cannot verify current revision: %w", err)
	}
	if s.CommitSHA != current.CommitSHA {
		return fmt.Errorf("phase 1 state was recorded for commit %s but current HEAD is %s", s.CommitSHA, current.CommitSHA)
	}
	if s.WorktreeSHA != current.WorktreeSHA {
		return errors.New("worktree changed since phase 1; rerun phase 1")
	}
	return nil
}

func gitOutputAt(dir string, args ...string) (string, error) {
	b, err := gitBytesAt(dir, args...)
	return string(b), err
}

func gitBytesAt(dir string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return out, nil
}
