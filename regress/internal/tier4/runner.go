// Package tier4 implements the long-run regression tier — the
// release-tag verification path. T4 is opt-in via --tier=4.
package tier4

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/regress/internal/caseexec"
	"github.com/FrankoonG/rendr/regress/internal/chaos"
	"github.com/FrankoonG/rendr/regress/internal/manifest"
	"github.com/FrankoonG/rendr/regress/internal/report"
	"github.com/FrankoonG/rendr/regress/internal/smoke"
)

// Options filters the long-run matrix for targeted debug runs.
type Options struct {
	Case     string
	FromCase string
}

type caseDef struct {
	spec       manifest.Spec
	profile    chaos.Profile
	run        func(context.Context) smoke.Result
	oracle     func(smoke.Result) error
	skipReason func() string
	preflight  func() error
}

var caseDefs = []caseDef{
	{
		spec:    tier4Spec("G1-T4", 7*time.Minute),
		profile: chaos.Realistic50M,
		run: func(ctx context.Context) smoke.Result {
			return smoke.RunG1(ctx, smoke.G1Opts{Size: 1 << 30, Migrations: 10, Paths: 2, Transport: "tcp"})
		},
	},
	{
		spec:    tier4Spec("G1-T4-quic", 7*time.Minute),
		profile: chaos.Realistic50M,
		run: func(ctx context.Context) smoke.Result {
			return smoke.RunG1(ctx, smoke.G1Opts{Size: 1 << 30, Migrations: 10, Paths: 2, Transport: "quic"})
		},
	},
	{
		spec:    tier4Spec("G2-T4", 33*time.Minute),
		profile: chaos.Realistic50M,
		run: func(ctx context.Context) smoke.Result {
			return smoke.RunG2Paired(ctx, smoke.G2Opts{
				Duration:     30 * time.Minute,
				Migrations:   30,
				Paths:        2,
				Transport:    "tcp",
				Mode:         rendr.ModePrime,
				Interval:     100 * time.Millisecond,
				P99CeilingMs: 200,
			})
		},
	},
	{
		spec:    tier4Spec("G2-T4-quic", 33*time.Minute),
		profile: chaos.Realistic50M,
		run: func(ctx context.Context) smoke.Result {
			return smoke.RunG2Paired(ctx, smoke.G2Opts{
				Duration:     30 * time.Minute,
				Migrations:   30,
				Paths:        2,
				Transport:    "quic",
				Mode:         rendr.ModePrime,
				Interval:     100 * time.Millisecond,
				P99CeilingMs: 200,
			})
		},
	},
	{
		spec:    tier4Spec("G2-T4-race-tcp", 33*time.Minute),
		profile: chaos.Realistic50M,
		run: func(ctx context.Context) smoke.Result {
			return smoke.RunG2(ctx, smoke.G2Opts{
				Duration:     30 * time.Minute,
				Migrations:   -1,
				Paths:        2,
				Transport:    "tcp",
				Mode:         rendr.ModeRace,
				Interval:     100 * time.Millisecond,
				P99CeilingMs: 200,
			})
		},
	},
	{
		spec:    tier4Spec("G2-T4-bond-tcp", 33*time.Minute),
		profile: chaos.Realistic50M,
		run: func(ctx context.Context) smoke.Result {
			return smoke.RunG2Paired(ctx, smoke.G2Opts{
				Duration:     30 * time.Minute,
				Migrations:   30,
				Paths:        2,
				Transport:    "tcp",
				Mode:         rendr.ModeBond,
				Interval:     100 * time.Millisecond,
				P99CeilingMs: 200,
			})
		},
	},
	{
		spec:    tier4Spec("M11-udp-relay-T4", 5*time.Minute),
		profile: chaos.Realistic50M,
		run: func(ctx context.Context) smoke.Result {
			return smoke.RunUDPRelay(ctx, smoke.UDPRelayOpts{Packets: 10_000, Paths: 2, Migrations: 3, Server: true})
		},
		oracle: validateInFlightMigrationEvidence,
	},
	{
		spec:    tier4Spec("M11-udp-relay-porthop-T4", 5*time.Minute),
		profile: chaos.Realistic50M,
		run: func(ctx context.Context) smoke.Result {
			return smoke.RunUDPRelayPortHop(ctx, smoke.UDPRelayOpts{Packets: 10_000, Paths: 2, Migrations: 3, PortHops: 8})
		},
		oracle: validateInFlightMigrationEvidence,
	},
	{
		spec:    tier4Spec("M11-wireguard-relay-T4", 5*time.Minute),
		profile: chaos.Realistic50M,
		run: func(ctx context.Context) smoke.Result {
			return smoke.RunWireGuardRelay(ctx, smoke.WireGuardRelayOpts{Messages: 512, MessageSize: 512, Paths: 2, Migrations: 3})
		},
		oracle: validateInFlightMigrationEvidence,
		skipReason: func() string {
			if runtime.GOOS != "linux" {
				return "Linux only (wireguard-go UDP endpoint smoke is validated on Linux regress hosts)"
			}
			return ""
		},
	},
	{
		spec:    tier4Spec("M11-hysteria2-relay-T4", 5*time.Minute),
		profile: chaos.Realistic50M,
		run: func(ctx context.Context) smoke.Result {
			return smoke.RunHysteriaRelay(ctx, smoke.HysteriaRelayOpts{Paths: 2, Migrations: 3, DataSize: 8 << 20})
		},
		skipReason: func() string {
			if runtime.GOOS != "linux" {
				return "Linux only (Hysteria 2 relay smoke is validated on Linux regress hosts)"
			}
			if !smoke.HysteriaAvailable() {
				return "hysteria binary not found"
			}
			return ""
		},
	},
	{
		spec:      tier4Spec("G3-T4", 8*time.Minute),
		preflight: smoke.G3UDPBufferPreflight,
		run: func(ctx context.Context) smoke.Result {
			return smoke.RunG3(ctx, smoke.G3Opts{
				Duration:     5 * time.Minute,
				PPS:          100_000,
				PayloadLen:   1024,
				Migrations:   10,
				Paths:        8,
				P95CeilingMs: 20,
				LossPct:      0,
			})
		},
		skipReason: func() string {
			if runtime.GOOS != "linux" {
				return "Linux only (100k pps QUIC DATAGRAM needs effective 8MiB UDP socket buffers)"
			}
			return ""
		},
	},
}

// Specs returns the ordered T4 case manifest.
func Specs() []manifest.Spec {
	specs := make([]manifest.Spec, len(caseDefs))
	for i, def := range caseDefs {
		specs[i] = manifest.CloneSpec(def.spec)
	}
	return specs
}

func selectCaseDefs(opts Options) ([]caseDef, error) {
	return selectCaseDefsFrom(caseDefs, opts)
}

func selectCaseDefsFrom(registry []caseDef, opts Options) ([]caseDef, error) {
	specs := make([]manifest.Spec, len(registry))
	for i, def := range registry {
		specs[i] = manifest.CloneSpec(def.spec)
	}
	selected, err := manifest.SelectWithPrerequisites(specs, opts.Case, opts.FromCase)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]caseDef, len(registry))
	for _, def := range registry {
		byID[def.spec.ID] = def
	}
	defs := make([]caseDef, 0, len(selected))
	for _, spec := range selected {
		def := byID[spec.ID]
		def.spec = spec
		defs = append(defs, def)
	}
	return defs, nil
}

// Run executes T4 cases with their per-case budgets and chaos profiles.
func Run(ctx context.Context, suite *report.Suite, _ string, opts Options) {
	defs, err := selectCaseDefs(opts)
	if err != nil {
		suite.Add(report.Case{
			Name:    "T4-case-filter",
			Tier:    "T4",
			Failure: fmt.Sprintf("T4 case selection failed for case=%q from-case=%q: %v", opts.Case, opts.FromCase, err),
		})
		return
	}
	runSelectedCases(ctx, suite, defs, executeCaseOutcome)
}

type caseExecutor func(context.Context, caseDef) caseexec.Outcome

func runSelectedCases(ctx context.Context, suite *report.Suite, defs []caseDef, execute caseExecutor) {
	failedCaseID := ""
	for _, def := range defs {
		if failedCaseID != "" {
			suite.Add(notRunCase(def.spec, failedCaseID))
			continue
		}
		outcome := execute(ctx, def)
		rc := outcome.Case
		suite.Add(rc)
		if outcome.MustStop || mandatoryCaseFailed(def.spec, rc) {
			failedCaseID = def.spec.ID
		}
	}
}

func executeCase(ctx context.Context, def caseDef) report.Case {
	return executeCaseOutcome(ctx, def).Case
}

var tier4CaseJoinTimeout = caseexec.DefaultJoinTimeout

func executeCaseOutcome(ctx context.Context, def caseDef) caseexec.Outcome {
	outcome := caseexec.Run(ctx, caseexec.Config{
		Name:        def.spec.ID,
		Tier:        def.spec.Tier,
		Budget:      def.spec.Budget,
		JoinTimeout: tier4CaseJoinTimeout,
	}, func(cctx context.Context) (rc report.Case) {
		defer func() {
			if recovered := recover(); recovered != nil {
				rc = report.Case{Name: def.spec.ID, Tier: def.spec.Tier, Failure: fmt.Sprintf("runner panic: %v", recovered)}
			}
		}()
		if def.skipReason != nil {
			if reason := def.skipReason(); reason != "" {
				return report.Case{Name: def.spec.ID, Tier: def.spec.Tier, SkipReason: reason}
			}
		}
		if def.preflight != nil {
			if err := def.preflight(); err != nil {
				return report.Case{
					Name:          def.spec.ID,
					Tier:          def.spec.Tier,
					InvalidReason: "case preflight failed: " + err.Error(),
				}
			}
		}
		return runCaseWithChaosBody(cctx, def.spec.ID, def.spec.Budget, def.profile, withCaseOracle(def.run, def.oracle), chaos.ApplyChecked, chaosVerifyInterval)
	})
	enforceChaosTeardownOutcome(&outcome)
	return outcome
}

func withCaseOracle(run func(context.Context) smoke.Result, oracle func(smoke.Result) error) func(context.Context) smoke.Result {
	if oracle == nil {
		return run
	}
	return func(ctx context.Context) smoke.Result {
		result := run(ctx)
		if result.Failure != "" || result.InvalidReason != "" {
			return result
		}
		if err := oracle(result); err != nil {
			result.InvalidReason = "case oracle rejected evidence: " + err.Error()
		}
		return result
	}
}

func validateInFlightMigrationEvidence(result smoke.Result) error {
	requested, err := detailCount(result.Detail, "requested_migs")
	if err != nil {
		return err
	}
	expected, err := detailCount(result.Detail, "expected_inflight_migrations")
	if err != nil {
		return err
	}
	observed, err := detailCount(result.Detail, "inflight_migrations")
	if err != nil {
		return err
	}
	migrations, err := detailCount(result.Detail, "migration_count")
	if err != nil {
		return err
	}
	if requested == 0 {
		return fmt.Errorf("requested_migs must be positive")
	}
	if expected != requested {
		return fmt.Errorf("expected_inflight_migrations=%d does not match requested_migs=%d", expected, requested)
	}
	if observed != expected {
		return fmt.Errorf("inflight_migrations=%d want exactly expected_inflight_migrations=%d", observed, expected)
	}
	if migrations < observed {
		return fmt.Errorf("migration_count=%d is below inflight_migrations=%d", migrations, observed)
	}
	return nil
}

func detailCount(detail map[string]any, key string) (uint64, error) {
	value, ok := detail[key]
	if !ok {
		return 0, fmt.Errorf("missing %s", key)
	}
	switch count := value.(type) {
	case int:
		if count < 0 {
			return 0, fmt.Errorf("%s=%d is negative", key, count)
		}
		return uint64(count), nil
	case uint64:
		return count, nil
	default:
		return 0, fmt.Errorf("%s has non-integer type %T", key, value)
	}
}

// runCase gives cooperative workload and monitor teardown a bounded grace,
// then starts fixture cleanup regardless. Any unjoined component makes the
// tier unsafe to continue in this process.
func runCase(ctx context.Context, name string, budget time.Duration, prof chaos.Profile, fn func(context.Context) smoke.Result) report.Case {
	return runCaseWithChaos(ctx, name, budget, prof, fn, chaos.ApplyChecked)
}

const (
	chaosVerifyInterval         = time.Second
	maxChaosCleanupStartDelay   = 250 * time.Millisecond
	maxChaosTeardownQuiesce     = 500 * time.Millisecond
	maxChaosCleanupWait         = 5 * time.Second
	chaosCleanupStateEvidence   = "chaos_cleanup_state"
	chaosCleanupLimitEvidence   = "chaos_cleanup_limit"
	chaosTeardownUnsafeEvidence = "chaos_teardown_unsafe"
	chaosCleanupStateComplete   = "complete"
	chaosCleanupStateFailed     = "failed"
	chaosCleanupStateUnjoined   = "unjoined"
)

type chaosApplyFunc func(chaos.Profile) (chaos.Fixture, error)

func runCaseWithChaos(ctx context.Context, name string, budget time.Duration, prof chaos.Profile, fn func(context.Context) smoke.Result, apply chaosApplyFunc) report.Case {
	return runCaseWithChaosInterval(ctx, name, budget, prof, fn, apply, chaosVerifyInterval)
}

func runCaseWithChaosInterval(ctx context.Context, name string, budget time.Duration, prof chaos.Profile, fn func(context.Context) smoke.Result, apply chaosApplyFunc, verifyInterval time.Duration) report.Case {
	return runCaseWithChaosOutcomeInterval(ctx, name, budget, prof, fn, apply, verifyInterval).Case
}

func runCaseWithChaosOutcomeInterval(ctx context.Context, name string, budget time.Duration, prof chaos.Profile, fn func(context.Context) smoke.Result, apply chaosApplyFunc, verifyInterval time.Duration) caseexec.Outcome {
	outcome := caseexec.Run(ctx, caseexec.Config{
		Name:        name,
		Tier:        "T4",
		Budget:      budget,
		JoinTimeout: tier4CaseJoinTimeout,
	}, func(cctx context.Context) report.Case {
		return runCaseWithChaosBody(cctx, name, budget, prof, fn, apply, verifyInterval)
	})
	enforceChaosTeardownOutcome(&outcome)
	return outcome
}

func runCaseWithChaosBody(ctx context.Context, name string, budget time.Duration, prof chaos.Profile, fn func(context.Context) smoke.Result, apply chaosApplyFunc, verifyInterval time.Duration) report.Case {
	started := time.Now()
	fmt.Printf("  > T4/%s (budget %s, chaos %s) — start\n", name, budget, profDesc(prof))
	rc := report.Case{Name: name, Tier: "T4"}
	fixture, err := applyChaosFixture(apply, prof)
	if err != nil {
		rc.InvalidReason = "chaos fixture setup failed: " + err.Error()
		fmt.Printf("  > T4/%s — INVALID: %s\n", name, rc.InvalidReason)
		return rc
	}
	if fixture == nil {
		rc.InvalidReason = "chaos fixture setup failed: apply returned a nil fixture"
		fmt.Printf("  > T4/%s — INVALID: %s\n", name, rc.InvalidReason)
		return rc
	}
	cctx, cancel := context.WithCancel(ctx)
	timing := chaosTeardownTimingFor(tier4CaseJoinTimeout)
	cleanup := newChaosCleanup(fixture.Cleanup)
	startChaosCleanupOnCancel(cctx, cleanup, timing.cleanupStartDelay)
	monitorFailures, monitorDone := monitorChaosFixture(cctx, fixture, verifyInterval)
	result, workloadDone := startChaosWorkload(cctx, fn)
	select {
	case r := <-result:
		rc.Duration = r.Duration
		rc.Failure = r.Failure
		rc.InvalidReason = r.InvalidReason
		rc.Evidence = evidenceFromDetail(r.Detail)
		if rc.Duration == 0 {
			rc.Duration = time.Since(started)
		}
	case err := <-monitorFailures:
		rc.Duration = time.Since(started)
		markChaosInvalid(&rc, "chaos stimulus changed during case: "+err.Error())
	case <-cctx.Done():
		rc.Duration = time.Since(started)
		rc.Failure = "case stopped during T4 execution: " + cctx.Err().Error()
	}
	cancel()
	finalizeChaosTeardown(&rc, fixture, cleanup, workloadDone, monitorDone, monitorFailures, time.Now(), timing)
	enforceChaosTeardownCase(&rc)
	rc.Duration = time.Since(started)
	if rc.Failure != "" {
		fmt.Printf("  > T4/%s (took %s) — FAIL: %s\n", name, rc.Duration, rc.Failure)
	} else if rc.InvalidReason != "" {
		fmt.Printf("  > T4/%s (took %s) — INVALID: %s\n", name, rc.Duration, rc.InvalidReason)
	} else {
		fmt.Printf("  > T4/%s (took %s) — OK\n", name, rc.Duration)
	}
	return rc
}

type chaosTeardownTiming struct {
	cleanupStartDelay time.Duration
	cleanupWait       time.Duration
	quiesceWait       time.Duration
}

func chaosTeardownTimingFor(joinTimeout time.Duration) chaosTeardownTiming {
	if joinTimeout <= 0 {
		joinTimeout = caseexec.DefaultJoinTimeout
	}
	startDelay := minDuration(joinTimeout/4, maxChaosCleanupStartDelay)
	cleanupWait := minDuration(joinTimeout/2, maxChaosCleanupWait)
	quiesceWait := minDuration(joinTimeout*3/4, maxChaosTeardownQuiesce)
	if startDelay <= 0 {
		startDelay = time.Nanosecond
	}
	if cleanupWait <= 0 {
		cleanupWait = time.Nanosecond
	}
	if quiesceWait < startDelay {
		quiesceWait = startDelay
	}
	return chaosTeardownTiming{
		cleanupStartDelay: startDelay,
		cleanupWait:       cleanupWait,
		quiesceWait:       quiesceWait,
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

type chaosCleanup struct {
	cleanup func() error
	once    sync.Once
	started chan struct{}
	done    chan struct{}
	mu      sync.Mutex
	err     error
}

func newChaosCleanup(cleanup func() error) *chaosCleanup {
	return &chaosCleanup{
		cleanup: cleanup,
		started: make(chan struct{}),
		done:    make(chan struct{}),
	}
}

func (c *chaosCleanup) Start() {
	if c == nil {
		return
	}
	c.once.Do(func() {
		close(c.started)
		go func() {
			err := invokeCleanup(c.cleanup)
			c.mu.Lock()
			c.err = err
			c.mu.Unlock()
			close(c.done)
		}()
	})
}

func (c *chaosCleanup) Wait(limit time.Duration) (error, bool) {
	if c == nil {
		return nil, true
	}
	c.Start()
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case <-c.done:
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.err, true
	case <-timer.C:
		return nil, false
	}
}

func (c *chaosCleanup) Started() bool {
	if c == nil {
		return false
	}
	select {
	case <-c.started:
		return true
	default:
		return false
	}
}

func invokeCleanup(cleanup func() error) (err error) {
	if cleanup == nil {
		return nil
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("cleanup panicked: %v", recovered)
		}
	}()
	return cleanup()
}

func startChaosCleanupOnCancel(ctx context.Context, cleanup *chaosCleanup, delay time.Duration) {
	go func() {
		select {
		case <-ctx.Done():
		case <-cleanup.started:
			return
		}
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
			cleanup.Start()
		case <-cleanup.started:
		}
	}()
}

func applyChaosFixture(apply chaosApplyFunc, profile chaos.Profile) (fixture chaos.Fixture, err error) {
	if apply == nil {
		return nil, fmt.Errorf("apply function is nil")
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			fixture = nil
			err = fmt.Errorf("apply panicked: %v", recovered)
		}
	}()
	return apply(profile)
}

func startChaosWorkload(ctx context.Context, fn func(context.Context) smoke.Result) (<-chan smoke.Result, <-chan struct{}) {
	result := make(chan smoke.Result, 1)
	done := make(chan struct{})
	go func() {
		r := invokeChaosWorkload(ctx, fn)
		close(done)
		result <- r
	}()
	return result, done
}

func invokeChaosWorkload(ctx context.Context, fn func(context.Context) smoke.Result) (result smoke.Result) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result = smoke.Result{Failure: fmt.Sprintf("runner panic: %v", recovered)}
		}
	}()
	if fn == nil {
		return smoke.Result{Failure: "runner panic: nil workload"}
	}
	return fn(ctx)
}

func finalizeChaosTeardown(
	rc *report.Case,
	fixture chaos.Fixture,
	cleanup *chaosCleanup,
	workloadDone, monitorDone <-chan struct{},
	monitorFailures <-chan error,
	canceledAt time.Time,
	timing chaosTeardownTiming,
) {
	cleanupDeadline := canceledAt.Add(timing.cleanupStartDelay)
	workloadJoined, monitorJoined := waitForChaosQuiescence(workloadDone, monitorDone, cleanupDeadline)
	if monitorJoined {
		drainChaosMonitorFailures(rc, monitorFailures)
	}

	if workloadJoined && monitorJoined && !cleanup.Started() {
		remaining := time.Until(cleanupDeadline)
		if remaining > 0 {
			verifyErr, completed := runBoundedError(fixture.Verify, remaining)
			switch {
			case !completed:
				appendChaosUnsafe(rc, fmt.Sprintf("chaos final verification did not return within %s", timing.cleanupStartDelay))
			case verifyErr != nil:
				markChaosInvalid(rc, "chaos final verification failed: "+verifyErr.Error())
			}
		} else {
			markChaosInvalid(rc, "chaos final verification skipped because bounded teardown grace was exhausted")
		}
	}

	cleanup.Start()
	cleanupErr, cleanupJoined := cleanup.Wait(timing.cleanupWait)
	ensureEvidence(rc)[chaosCleanupLimitEvidence] = timing.cleanupWait.String()
	switch {
	case !cleanupJoined:
		ensureEvidence(rc)[chaosCleanupStateEvidence] = chaosCleanupStateUnjoined
		appendChaosUnsafe(rc, fmt.Sprintf("chaos cleanup did not return within %s", timing.cleanupWait))
	case cleanupErr != nil:
		ensureEvidence(rc)[chaosCleanupStateEvidence] = chaosCleanupStateFailed
		appendChaosUnsafe(rc, "chaos cleanup failed: "+cleanupErr.Error())
	default:
		ensureEvidence(rc)[chaosCleanupStateEvidence] = chaosCleanupStateComplete
	}

	workloadJoined, monitorJoined = waitForChaosQuiescence(workloadDone, monitorDone, canceledAt.Add(timing.quiesceWait))
	if monitorJoined {
		drainChaosMonitorFailures(rc, monitorFailures)
	}
	if !workloadJoined {
		appendChaosUnsafe(rc, fmt.Sprintf("canceled workload did not return within bounded teardown grace %s; Go cannot terminate it, so the regress process must exit before any later case runs", timing.quiesceWait))
	}
	if !monitorJoined {
		appendChaosUnsafe(rc, fmt.Sprintf("chaos monitor did not return within bounded teardown grace %s", timing.quiesceWait))
	}
}

func waitForChaosQuiescence(workloadDone, monitorDone <-chan struct{}, deadline time.Time) (bool, bool) {
	workloadJoined := channelClosed(workloadDone)
	monitorJoined := channelClosed(monitorDone)
	workloadWait := workloadDone
	monitorWait := monitorDone
	if workloadJoined {
		workloadWait = nil
	}
	if monitorJoined {
		monitorWait = nil
	}
	for !workloadJoined || !monitorJoined {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		timer := time.NewTimer(remaining)
		select {
		case <-workloadWait:
			workloadJoined = true
			workloadWait = nil
		case <-monitorWait:
			monitorJoined = true
			monitorWait = nil
		case <-timer.C:
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
	return workloadJoined || channelClosed(workloadDone), monitorJoined || channelClosed(monitorDone)
}

func channelClosed(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

func runBoundedError(fn func() error, limit time.Duration) (error, bool) {
	result := make(chan error, 1)
	go func() {
		var err error
		defer func() {
			if recovered := recover(); recovered != nil {
				err = fmt.Errorf("panic: %v", recovered)
			}
			result <- err
		}()
		if fn == nil {
			err = fmt.Errorf("operation is nil")
			return
		}
		err = fn()
	}()
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case err := <-result:
		return err, true
	case <-timer.C:
		return nil, false
	}
}

func drainChaosMonitorFailures(rc *report.Case, failures <-chan error) {
	for {
		select {
		case err := <-failures:
			if err != nil {
				markChaosInvalid(rc, "chaos stimulus changed during case: "+err.Error())
			}
		default:
			return
		}
	}
}

func ensureEvidence(rc *report.Case) map[string]string {
	if rc.Evidence == nil {
		rc.Evidence = make(map[string]string)
	}
	return rc.Evidence
}

func appendChaosUnsafe(rc *report.Case, reason string) {
	if rc == nil || reason == "" {
		return
	}
	evidence := ensureEvidence(rc)
	for _, existing := range strings.Split(evidence[chaosTeardownUnsafeEvidence], "; ") {
		if existing == reason {
			return
		}
	}
	if evidence[chaosTeardownUnsafeEvidence] == "" {
		evidence[chaosTeardownUnsafeEvidence] = reason
	} else {
		evidence[chaosTeardownUnsafeEvidence] += "; " + reason
	}
}

func enforceChaosTeardownCase(rc *report.Case) bool {
	if rc == nil || rc.Evidence == nil {
		return false
	}
	reason := rc.Evidence[chaosTeardownUnsafeEvidence]
	if reason == "" {
		return false
	}
	markChaosInvalid(rc, reason)
	return true
}

func enforceChaosTeardownOutcome(outcome *caseexec.Outcome) {
	if outcome != nil && enforceChaosTeardownCase(&outcome.Case) {
		outcome.MustStop = true
	}
}

func mandatoryCaseFailed(spec manifest.Spec, rc report.Case) bool {
	return spec.Mandatory && (rc.Failure != "" || rc.InvalidReason != "" || rc.SkipReason != "")
}

func notRunCase(spec manifest.Spec, failedCaseID string) report.Case {
	return report.Case{
		Name:            spec.ID,
		Tier:            spec.Tier,
		ExecutionState:  report.ExecutionStateNotRun,
		BlockerKind:     report.BlockerKindCase,
		BlockedByCaseID: failedCaseID,
		InvalidReason:   fmt.Sprintf("not run after %s failed", failedCaseID),
	}
}

func evidenceFromDetail(detail map[string]any) map[string]string {
	if len(detail) == 0 {
		return nil
	}
	evidence := make(map[string]string, len(detail))
	for key, value := range detail {
		evidence[key] = fmt.Sprint(value)
	}
	return evidence
}

func applyCleanupResult(rc *report.Case, cleanup func() error) {
	if rc == nil || cleanup == nil {
		return
	}
	if err := invokeCleanup(cleanup); err != nil {
		markChaosInvalid(rc, "chaos cleanup failed: "+err.Error())
	}
}

func markChaosInvalid(rc *report.Case, reason string) {
	if rc == nil || reason == "" {
		return
	}
	if rc.Failure != "" {
		if rc.Evidence == nil {
			rc.Evidence = make(map[string]string)
		}
		if existing := rc.Evidence["untrusted_case_failure"]; existing == "" {
			rc.Evidence["untrusted_case_failure"] = rc.Failure
		} else if existing != rc.Failure {
			rc.Evidence["untrusted_teardown_failure"] = rc.Failure
		}
		rc.Failure = ""
	}
	if rc.InvalidReason == reason || strings.HasSuffix(rc.InvalidReason, "; "+reason) {
		return
	}
	for _, existing := range strings.Split(rc.InvalidReason, "; ") {
		if existing == reason {
			return
		}
	}
	if rc.InvalidReason == "" {
		rc.InvalidReason = reason
	} else {
		rc.InvalidReason += "; " + reason
	}
}

func monitorChaosFixture(ctx context.Context, fixture chaos.Fixture, interval time.Duration) (<-chan error, <-chan struct{}) {
	failures := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if recovered := recover(); recovered != nil {
				reportChaosMonitorFailure(failures, fmt.Errorf("chaos monitor panicked: %v", recovered))
			}
		}()
		changes := fixture.Changes()
		var ticker *time.Ticker
		var ticks <-chan time.Time
		if interval > 0 {
			ticker = time.NewTicker(interval)
			ticks = ticker.C
			defer ticker.Stop()
		}
		for {
			select {
			case <-ctx.Done():
				return
			case err, ok := <-changes:
				if !ok {
					reportChaosMonitorFailure(failures, fmt.Errorf("qdisc event watcher stopped unexpectedly"))
					return
				}
				if err == nil {
					err = fmt.Errorf("qdisc event watcher reported an unspecified change")
				}
				reportChaosMonitorFailure(failures, err)
				return
			case <-ticks:
				if err := fixture.Verify(); err != nil {
					reportChaosMonitorFailure(failures, err)
					return
				}
			}
		}
	}()
	return failures, done
}

func reportChaosMonitorFailure(failures chan<- error, err error) {
	select {
	case failures <- err:
	default:
	}
}

func profDesc(p chaos.Profile) string {
	if p.Bandwidth == 0 && p.LossPct == 0 && p.Delay == 0 {
		return "clean"
	}
	return fmt.Sprintf("%dMbit/loss%.1f%%/delay%dms", p.Bandwidth/1_000_000, p.LossPct, p.Delay.Milliseconds())
}
