package chaos

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Profile is one chaos configuration. Zero-value means no qdisc is applied.
type Profile struct {
	// Bandwidth is in bits per second. Zero leaves bandwidth uncapped.
	Bandwidth int64
	// LossPct is application-visible packet loss percentage, 0-100.
	LossPct float64
	// Delay is the base one-way delay added to every packet.
	Delay time.Duration
	// Jitter is the random component layered on Delay.
	Jitter time.Duration
}

// Realistic50M is the default 50 Mbps regression profile.
var Realistic50M = Profile{Bandwidth: 50_000_000}

// LossyWAN models a lossy intercontinental hop.
var LossyWAN = Profile{
	Bandwidth: 50_000_000,
	LossPct:   1.0,
	Delay:     80 * time.Millisecond,
	Jitter:    20 * time.Millisecond,
}

// ErrStimulusInvalid marks fixture interference or lost ownership. A result
// produced after this error is not evidence about rendr and must be INVALID.
var ErrStimulusInvalid = errors.New("chaos stimulus invalid")

// Fixture owns one applied qdisc stimulus. Changes reports asynchronous
// kernel notifications for qdisc changes on the shaped interface. Verify is a
// synchronous state check; Cleanup removes only the qdisc still owned by this
// fixture.
type Fixture interface {
	Changes() <-chan error
	Verify() error
	Cleanup() error
}

// Apply preserves the original cleanup-only API for callers that do not yet
// need continuous verification. Cleanup still fails closed if ownership was
// lost before it ran.
func Apply(p Profile) (func() error, error) {
	fixture, err := ApplyChecked(p)
	if err != nil {
		return nil, err
	}
	return fixture.Cleanup, nil
}

type tcRunFunc func(args ...string) ([]byte, error)

type fixtureLock interface {
	Release() error
}

type qdiscWatcher interface {
	Changes() <-chan error
	Close() error
}

type fixtureDeps struct {
	run         tcRunFunc
	acquireLock func() (fixtureLock, error)
	handles     func() (root, child string, err error)
	watch       func() (qdiscWatcher, error)
}

type managedFixture struct {
	mu sync.Mutex

	profile     Profile
	run         tcRunFunc
	lock        fixtureLock
	watcher     qdiscWatcher
	rootHandle  string
	childHandle string
	fingerprint []byte
	cleaned     bool
}

type noOpFixture struct{}

func (noOpFixture) Changes() <-chan error { return nil }
func (noOpFixture) Verify() error         { return nil }
func (noOpFixture) Cleanup() error        { return nil }

func applyWithDeps(p Profile, deps fixtureDeps) (Fixture, error) {
	if err := validateProfile(p); err != nil {
		return nil, err
	}
	if profileIsNoOp(p) {
		return noOpFixture{}, nil
	}
	if deps.run == nil || deps.acquireLock == nil || deps.handles == nil || deps.watch == nil {
		return nil, errors.New("chaos fixture dependencies are incomplete")
	}

	lock, err := deps.acquireLock()
	if err != nil {
		return nil, fmt.Errorf("acquire loopback qdisc ownership: %w", err)
	}
	releaseOnError := true
	defer func() {
		if releaseOnError {
			_ = lock.Release()
		}
	}()

	before, err := probeQdiscs(deps.run)
	if err != nil {
		return nil, fmt.Errorf("probe loopback qdisc before apply: %w", err)
	}
	if active := activeRoot(before.records); active != nil {
		return nil, fmt.Errorf("%w: loopback already has root qdisc kind=%s handle=%s", ErrStimulusInvalid, active.Kind, active.Handle)
	}

	rootHandle, childHandle, err := deps.handles()
	if err != nil {
		return nil, fmt.Errorf("allocate qdisc ownership handles: %w", err)
	}
	if err := validateHandles(rootHandle, childHandle); err != nil {
		return nil, err
	}

	rootKind := "netem"
	if p.Bandwidth > 0 {
		rootKind = "tbf"
		if err := runTC(deps.run, tbfArgs(p, rootHandle)); err != nil {
			return nil, fmt.Errorf("install tbf root: %w", err)
		}
	} else if err := runTC(deps.run, netemArgs(p, rootHandle, "")); err != nil {
		return nil, fmt.Errorf("install netem root: %w", err)
	}

	installedRoot := true
	rollback := func() {
		if installedRoot {
			_ = deleteOwnedRoot(deps.run, rootHandle)
		}
	}

	if p.Bandwidth > 0 && hasNetem(p) {
		parent := strings.TrimSuffix(rootHandle, ":") + ":1"
		if err := runTC(deps.run, netemArgs(p, childHandle, parent)); err != nil {
			rollback()
			return nil, fmt.Errorf("install netem child: %w", err)
		}
	}

	after, err := probeQdiscs(deps.run)
	if err != nil {
		rollback()
		return nil, fmt.Errorf("probe loopback qdisc after apply: %w", err)
	}
	if err := validateOwnedState(after, p, rootKind, rootHandle, childHandle); err != nil {
		rollback()
		return nil, err
	}

	watcher, err := deps.watch()
	if err != nil {
		rollback()
		return nil, fmt.Errorf("watch loopback qdisc: %w", err)
	}

	fixture := &managedFixture{
		profile:     p,
		run:         deps.run,
		lock:        lock,
		watcher:     watcher,
		rootHandle:  rootHandle,
		childHandle: childHandle,
		fingerprint: after.canonical,
	}
	// Close the bind-to-watch race with one synchronous state check.
	if err := fixture.Verify(); err != nil {
		_ = watcher.Close()
		rollback()
		return nil, err
	}

	installedRoot = false
	releaseOnError = false
	return fixture, nil
}

func (f *managedFixture) Changes() <-chan error {
	if f == nil || f.watcher == nil {
		return nil
	}
	return f.watcher.Changes()
}

func (f *managedFixture) Verify() error {
	if f == nil {
		return fmt.Errorf("%w: nil fixture", ErrStimulusInvalid)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.verifyLocked()
}

func (f *managedFixture) verifyLocked() error {
	if f.cleaned {
		return fmt.Errorf("%w: fixture was already cleaned", ErrStimulusInvalid)
	}
	current, err := probeQdiscs(f.run)
	if err != nil {
		return fmt.Errorf("%w: probe loopback qdisc: %v", ErrStimulusInvalid, err)
	}
	rootKind := "netem"
	if f.profile.Bandwidth > 0 {
		rootKind = "tbf"
	}
	if err := validateOwnedState(current, f.profile, rootKind, f.rootHandle, f.childHandle); err != nil {
		return err
	}
	if !bytes.Equal(current.canonical, f.fingerprint) {
		return fmt.Errorf("%w: loopback qdisc fingerprint changed (expected=%s current=%s)",
			ErrStimulusInvalid, shortFingerprint(f.fingerprint), shortFingerprint(current.canonical))
	}
	return nil
}

func (f *managedFixture) Cleanup() error {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cleaned {
		return nil
	}
	f.cleaned = true

	var errs []error
	if f.watcher != nil {
		changes := f.watcher.Changes()
		if err := f.watcher.Close(); err != nil {
			errs = append(errs, fmt.Errorf("stop qdisc watcher: %w", err))
		}
		for err := range changes {
			if err != nil {
				errs = append(errs, err)
			}
		}
	}
	// Never issue a broad root delete after ownership has been lost. This is
	// the key guard against deleting a qdisc installed by another process.
	if err := f.verifyForCleanupLocked(); err != nil {
		errs = append(errs, err)
	} else if err := deleteOwnedRoot(f.run, f.rootHandle); err != nil {
		current, probeErr := probeQdiscs(f.run)
		if probeErr == nil && !bytes.Equal(current.canonical, f.fingerprint) {
			errs = append(errs, fmt.Errorf("%w: owned qdisc changed while cleanup deleted it: %v", ErrStimulusInvalid, err))
		} else {
			errs = append(errs, err)
			if probeErr != nil {
				errs = append(errs, fmt.Errorf("probe after qdisc delete failure: %w", probeErr))
			}
		}
	} else if err := verifyOwnedHandlesAbsent(f.run, f.rootHandle, f.childHandle); err != nil {
		errs = append(errs, err)
	}
	if f.lock != nil {
		if err := f.lock.Release(); err != nil {
			errs = append(errs, fmt.Errorf("release qdisc ownership lock: %w", err))
		}
	}
	return errors.Join(errs...)
}

func (f *managedFixture) verifyForCleanupLocked() error {
	// Cleanup sets cleaned first to make repeated calls idempotent, so use the
	// same checks without the lifecycle guard.
	current, err := probeQdiscs(f.run)
	if err != nil {
		return fmt.Errorf("%w: cleanup probe failed: %v", ErrStimulusInvalid, err)
	}
	rootKind := "netem"
	if f.profile.Bandwidth > 0 {
		rootKind = "tbf"
	}
	if err := validateOwnedState(current, f.profile, rootKind, f.rootHandle, f.childHandle); err != nil {
		return err
	}
	if !bytes.Equal(current.canonical, f.fingerprint) {
		return fmt.Errorf("%w: loopback qdisc changed before cleanup (expected=%s current=%s)",
			ErrStimulusInvalid, shortFingerprint(f.fingerprint), shortFingerprint(current.canonical))
	}
	return nil
}

type qdiscRecord struct {
	Kind   string `json:"kind"`
	Handle string `json:"handle"`
	Parent string `json:"parent"`
	Root   bool   `json:"root"`
}

type qdiscSnapshot struct {
	records   []qdiscRecord
	canonical []byte
}

func probeQdiscs(run tcRunFunc) (qdiscSnapshot, error) {
	out, err := run("-j", "-details", "qdisc", "show", "dev", "lo")
	if err != nil {
		return qdiscSnapshot{}, commandError("tc qdisc show", out, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(out))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return qdiscSnapshot{}, fmt.Errorf("decode tc JSON: %w (output=%q)", err, boundedOutput(out))
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return qdiscSnapshot{}, fmt.Errorf("canonicalize tc JSON: %w", err)
	}
	var records []qdiscRecord
	if err := json.Unmarshal(canonical, &records); err != nil {
		return qdiscSnapshot{}, fmt.Errorf("decode qdisc records: %w", err)
	}
	return qdiscSnapshot{records: records, canonical: canonical}, nil
}

func activeRoot(records []qdiscRecord) *qdiscRecord {
	for i := range records {
		r := &records[i]
		if r.Root && !(r.Kind == "noqueue" && (r.Handle == "" || r.Handle == "0:")) {
			return r
		}
	}
	return nil
}

func validateOwnedState(s qdiscSnapshot, p Profile, rootKind, rootHandle, childHandle string) error {
	rootFound := false
	childFound := !hasNetem(p) || p.Bandwidth <= 0
	parent := strings.TrimSuffix(rootHandle, ":") + ":1"
	for _, r := range s.records {
		if r.Handle == rootHandle && r.Kind == rootKind && r.Root {
			rootFound = true
		}
		if p.Bandwidth > 0 && hasNetem(p) && r.Handle == childHandle && r.Kind == "netem" && r.Parent == parent {
			childFound = true
		}
	}
	if !rootFound {
		return fmt.Errorf("%w: owned root qdisc kind=%s handle=%s is absent or replaced", ErrStimulusInvalid, rootKind, rootHandle)
	}
	if !childFound {
		return fmt.Errorf("%w: owned netem child handle=%s parent=%s is absent or replaced", ErrStimulusInvalid, childHandle, parent)
	}
	return nil
}

func verifyOwnedHandlesAbsent(run tcRunFunc, rootHandle, childHandle string) error {
	current, err := probeQdiscs(run)
	if err != nil {
		return fmt.Errorf("verify qdisc cleanup: %w", err)
	}
	for _, r := range current.records {
		if r.Handle == rootHandle || (childHandle != "" && r.Handle == childHandle) {
			return fmt.Errorf("qdisc cleanup left owned handle %s installed", r.Handle)
		}
	}
	return nil
}

func tbfArgs(p Profile, rootHandle string) []string {
	burst := p.Bandwidth / 800
	if p.Bandwidth >= 50_000_000 && burst < 4<<20 {
		burst = 4 << 20
	}
	if burst < 128<<10 {
		burst = 128 << 10
	}
	return []string{"qdisc", "add", "dev", "lo", "root", "handle", rootHandle,
		"tbf", "rate", fmt.Sprintf("%dbit", p.Bandwidth), "burst", strconv.FormatInt(burst, 10), "latency", "1s"}
}

func netemArgs(p Profile, handle, parent string) []string {
	args := []string{"qdisc", "add", "dev", "lo"}
	if parent == "" {
		args = append(args, "root")
	} else {
		args = append(args, "parent", parent)
	}
	args = append(args, "handle", handle, "netem")
	if p.Delay > 0 {
		args = append(args, "delay", fmt.Sprintf("%dms", p.Delay.Milliseconds()))
		if p.Jitter > 0 {
			args = append(args, fmt.Sprintf("%dms", p.Jitter.Milliseconds()))
		}
	}
	if p.LossPct > 0 {
		args = append(args, "loss", fmt.Sprintf("%.2f%%", p.LossPct))
	}
	return args
}

func runTC(run tcRunFunc, args []string) error {
	out, err := run(args...)
	if err != nil {
		return commandError("tc "+strings.Join(args, " "), out, err)
	}
	return nil
}

func deleteOwnedRoot(run tcRunFunc, rootHandle string) error {
	args := []string{"qdisc", "del", "dev", "lo", "root", "handle", rootHandle}
	if err := runTC(run, args); err != nil {
		return fmt.Errorf("delete owned root qdisc: %w", err)
	}
	return nil
}

func commandError(operation string, out []byte, err error) error {
	return fmt.Errorf("%s: %w (output=%q)", operation, err, boundedOutput(out))
}

func boundedOutput(out []byte) string {
	const limit = 1024
	trimmed := strings.TrimSpace(string(out))
	if len(trimmed) <= limit {
		return trimmed
	}
	return trimmed[:limit] + "...[truncated]"
}

func shortFingerprint(value []byte) string {
	sum := sha256.Sum256(value)
	return fmt.Sprintf("%x", sum[:8])
}

func validateProfile(p Profile) error {
	if p.Bandwidth < 0 || p.LossPct < 0 || p.LossPct > 100 || p.Delay < 0 || p.Jitter < 0 {
		return fmt.Errorf("invalid chaos profile: %+v", p)
	}
	if p.Jitter > 0 && p.Delay == 0 {
		return errors.New("invalid chaos profile: jitter requires delay")
	}
	return nil
}

func validateHandles(root, child string) error {
	valid := func(handle string) bool {
		if !strings.HasSuffix(handle, ":") || len(handle) < 2 || len(handle) > 5 {
			return false
		}
		major := strings.TrimSuffix(handle, ":")
		_, err := strconv.ParseUint(major, 16, 16)
		return err == nil && major != "0" && !strings.EqualFold(major, "ffff")
	}
	if !valid(root) || !valid(child) || root == child {
		return fmt.Errorf("invalid qdisc ownership handles root=%q child=%q", root, child)
	}
	return nil
}

func profileIsNoOp(p Profile) bool {
	return p.Bandwidth == 0 && p.LossPct == 0 && p.Delay == 0
}

func hasNetem(p Profile) bool {
	return p.LossPct > 0 || p.Delay > 0
}
