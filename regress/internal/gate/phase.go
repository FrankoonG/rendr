// Package gate enforces the two-phase contract from
// docs/regression-suite.md §4: phase 1 (rendr self-check, T1+T2) must
// be validated green for the current commit before phase 2 (T3-T5)
// is allowed to run.
//
// State is persisted in <report-dir>/last_phase1.json. --force-phase2
// bypasses the check (local debug only; CI must not pass it).
package gate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const StateFileName = "last_phase1.json"

// State recorded after each phase-1 run. Phase-2 entry verifies the
// current git HEAD matches CommitSHA and Status == "green".
type State struct {
	CommitSHA string    `json:"commit_sha"`
	Status    string    `json:"status"` // "green" | "red"
	At        time.Time `json:"at"`
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
	return os.WriteFile(filepath.Join(reportDir, StateFileName), b, 0o644)
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

// HeadCommit returns the current git HEAD short SHA, or "" if not in
// a git repo. Used to bind phase-1 state to a specific revision.
func HeadCommit() string {
	cmd := exec.Command("git", "rev-parse", "--short", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// CheckPhase2Allowed returns nil when phase-2 may run. Otherwise an
// error explains why (no state, stale state, or red state).
func CheckPhase2Allowed(reportDir string) error {
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
	head := HeadCommit()
	if head != "" && s.CommitSHA != "" && s.CommitSHA != head {
		return fmt.Errorf("phase 1 state was recorded for commit %s but current HEAD is %s", s.CommitSHA, head)
	}
	return nil
}
