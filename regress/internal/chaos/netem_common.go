package chaos

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	tcCommandTimeout = time.Second
	tcCommandWait    = 250 * time.Millisecond
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

var contaminatedFixtureLocks struct {
	sync.Mutex
	locks []fixtureLock
}

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
	cleanupDone chan struct{}
	cleanupErr  error
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
	retainOnError := false
	defer func() {
		if releaseOnError {
			_ = lock.Release()
		} else if retainOnError {
			retainContaminatedLock(lock)
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
	}
	ownership := qdiscOwnership{
		rootKind:    rootKind,
		rootHandle:  rootHandle,
		childHandle: childHandle,
	}
	failAfterMutation := func(cause error) (Fixture, error) {
		absenceProved, rollbackErr := removeOwnedRootAndProveAbsence(deps.run, ownership)
		if !absenceProved {
			releaseOnError = false
			retainOnError = true
		}
		return nil, errors.Join(cause, rollbackErr)
	}

	rootArgs := netemArgs(p, rootHandle, "")
	if p.Bandwidth > 0 {
		rootArgs = tbfArgs(p, rootHandle)
	}
	if err := runTC(deps.run, rootArgs); err != nil {
		return failAfterMutation(fmt.Errorf("install %s root: %w", rootKind, err))
	}

	if p.Bandwidth > 0 && hasNetem(p) {
		parent := strings.TrimSuffix(rootHandle, ":") + ":1"
		if err := runTC(deps.run, netemArgs(p, childHandle, parent)); err != nil {
			return failAfterMutation(fmt.Errorf("install netem child: %w", err))
		}
	}

	after, err := probeQdiscs(deps.run)
	if err != nil {
		return failAfterMutation(fmt.Errorf("probe loopback qdisc after apply: %w", err))
	}
	if err := validateOwnedState(after, p, rootKind, rootHandle, childHandle); err != nil {
		return failAfterMutation(err)
	}

	watcher, err := deps.watch()
	if err != nil {
		return failAfterMutation(fmt.Errorf("watch loopback qdisc: %w", err))
	}

	fixture := &managedFixture{
		profile:     p,
		run:         deps.run,
		lock:        lock,
		watcher:     watcher,
		rootHandle:  rootHandle,
		childHandle: childHandle,
		fingerprint: after.canonical,
		cleanupDone: make(chan struct{}),
	}
	// Close the bind-to-watch race with one synchronous state check.
	if err := fixture.Verify(); err != nil {
		_ = watcher.Close()
		return failAfterMutation(err)
	}

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
	if f.cleaned {
		f.mu.Unlock()
		return fmt.Errorf("%w: fixture was already cleaned", ErrStimulusInvalid)
	}
	f.mu.Unlock()
	return f.verifyCurrent()
}

func (f *managedFixture) verifyCurrent() error {
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

func (f *managedFixture) Cleanup() (result error) {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	if f.cleanupDone == nil {
		f.cleanupDone = make(chan struct{})
	}
	if f.cleaned {
		done := f.cleanupDone
		f.mu.Unlock()
		<-done
		f.mu.Lock()
		err := f.cleanupErr
		f.mu.Unlock()
		return err
	}
	f.cleaned = true
	done := f.cleanupDone
	f.mu.Unlock()
	defer func() {
		recovered := recover()
		if recovered != nil {
			result = fmt.Errorf("cleanup panic: %v", recovered)
		}
		f.mu.Lock()
		f.cleanupErr = result
		close(done)
		f.mu.Unlock()
		if recovered != nil {
			panic(recovered)
		}
	}()

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
	absenceProved := false
	// Never issue a broad root delete after ownership has been lost. Exact
	// fingerprint verification guards against deleting another owner's qdisc.
	if err := f.verifyForCleanup(); err != nil {
		errs = append(errs, err)
	}
	rootKind := "netem"
	if f.profile.Bandwidth > 0 {
		rootKind = "tbf"
	}
	var removeErr error
	absenceProved, removeErr = removeOwnedRootAndProveAbsence(f.run, qdiscOwnership{
		rootKind:    rootKind,
		rootHandle:  f.rootHandle,
		childHandle: f.childHandle,
		fingerprint: f.fingerprint,
	})
	if removeErr != nil {
		errs = append(errs, removeErr)
	}
	if absenceProved && f.lock != nil {
		if err := f.lock.Release(); err != nil {
			errs = append(errs, fmt.Errorf("release qdisc ownership lock: %w", err))
		}
	} else if f.lock != nil {
		retainContaminatedLock(f.lock)
	}
	return errors.Join(errs...)
}

func (f *managedFixture) verifyForCleanup() error {
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

func runExternalCommand(limit time.Duration, binary string, args ...string) ([]byte, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("invalid command timeout %s", limit)
	}
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	configureExternalCommand(cmd)
	cmd.WaitDelay = tcCommandWait
	output, err := cmd.CombinedOutput()
	cleanupErr := cleanupExternalCommand(cmd, tcCommandWait)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return output, errors.Join(
			fmt.Errorf("%s command exceeded %s: %w", binary, limit, ctxErr),
			cleanupErr,
		)
	}
	return output, errors.Join(err, cleanupErr)
}

type qdiscOwnership struct {
	rootKind    string
	rootHandle  string
	childHandle string
	fingerprint []byte
}

type qdiscOwnershipState uint8

const (
	qdiscContaminated qdiscOwnershipState = iota
	qdiscAbsent
	qdiscOwned
)

func (o qdiscOwnership) classify(snapshot qdiscSnapshot) qdiscOwnershipState {
	if handlesAbsent(snapshot.records, o.rootHandle, o.childHandle) {
		return qdiscAbsent
	}
	active := activeRoot(snapshot.records)
	if o.fingerprint != nil {
		if bytes.Equal(snapshot.canonical, o.fingerprint) {
			return qdiscOwned
		}
		return qdiscContaminated
	}
	if active != nil && active.Root && active.Kind == o.rootKind && active.Handle == o.rootHandle {
		return qdiscOwned
	}
	return qdiscContaminated
}

func removeOwnedRootAndProveAbsence(run tcRunFunc, ownership qdiscOwnership) (bool, error) {
	var mutationErrs []error
	for attempts := 0; attempts < 2; attempts++ {
		current, err := probeQdiscs(run)
		if err != nil {
			return false, errors.Join(errors.Join(mutationErrs...),
				fmt.Errorf("%w: cannot probe qdisc ownership during rollback: %v", ErrStimulusInvalid, err))
		}
		switch ownership.classify(current) {
		case qdiscAbsent:
			if active := activeRoot(current.records); active != nil {
				return true, errors.Join(errors.Join(mutationErrs...),
					fmt.Errorf("%w: generated qdisc is absent but an external root is present (kind=%s handle=%s)",
						ErrStimulusInvalid, active.Kind, active.Handle))
			}
			return true, errors.Join(mutationErrs...)
		case qdiscContaminated:
			return false, errors.Join(errors.Join(mutationErrs...),
				fmt.Errorf("%w: qdisc ownership is contaminated during rollback; external root is present or owned fingerprint changed (root=%s fingerprint=%s)",
					ErrStimulusInvalid, ownership.rootHandle, shortFingerprint(current.canonical)))
		}

		if err := deleteOwnedRoot(run, ownership.rootHandle); err != nil {
			mutationErrs = append(mutationErrs, err)
		}
	}

	current, err := probeQdiscs(run)
	if err != nil {
		return false, errors.Join(errors.Join(mutationErrs...),
			fmt.Errorf("%w: cannot prove qdisc absence after rollback: %v", ErrStimulusInvalid, err))
	}
	if ownership.classify(current) == qdiscAbsent {
		return true, errors.Join(mutationErrs...)
	}
	return false, errors.Join(errors.Join(mutationErrs...),
		fmt.Errorf("%w: qdisc rollback did not prove absence (root=%s fingerprint=%s)",
			ErrStimulusInvalid, ownership.rootHandle, shortFingerprint(current.canonical)))
}

func handlesAbsent(records []qdiscRecord, rootHandle, childHandle string) bool {
	for _, record := range records {
		if record.Handle == rootHandle || (childHandle != "" && record.Handle == childHandle) {
			return false
		}
	}
	return true
}

func retainContaminatedLock(lock fixtureLock) {
	contaminatedFixtureLocks.Lock()
	contaminatedFixtureLocks.locks = append(contaminatedFixtureLocks.locks, lock)
	contaminatedFixtureLocks.Unlock()
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
