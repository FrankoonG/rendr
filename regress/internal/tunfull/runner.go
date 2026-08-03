// Package tunfull defines synthetic L3/session translations of the existing
// regression surface. It does not replace private real-kernel TUN Gold cases.
package tunfull

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"runtime"
	"sort"
	"strings"
	"time"

	rendr "github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/l3ingress"
	"github.com/FrankoonG/rendr/l3session"
	"github.com/FrankoonG/rendr/regress/internal/chaos"
	"github.com/FrankoonG/rendr/regress/internal/manifest"
	"github.com/FrankoonG/rendr/regress/internal/report"
	"github.com/FrankoonG/rendr/transport/tcprepair"
	"github.com/FrankoonG/rendr/tun"
)

// Options filters the synthetic TUN/L3-session matrix.
type Options struct {
	Case     string
	FromCase string
}

const (
	caseKernelTUNPreflight = "TUN-full.preflight-kernel-tun"
	caseG1Smoke            = "TUN-full.G1-smoke"
	caseG2Smoke            = "TUN-full.G2-smoke"
	caseG3Smoke            = "TUN-full.G3-smoke"
	caseG4PathDeath        = "TUN-full.G4-path-death"
	caseG5PathRecovery     = "TUN-full.G5-path-recovery"
	caseT3XrayStreamSmoke  = "TUN-full.T3-xray-stream-smoke"
	caseT3XrayMatrix       = "TUN-full.T3-xray-matrix"
	caseT4LongRun          = "TUN-full.T4-long-run"
	caseT4G1               = "TUN-full.T4-G1-1GiB-tcp"
	caseT4G2Prime          = "TUN-full.T4-G2-30m-prime"
	caseT4G2               = "TUN-full.T4-G2-30m-selector"
	caseT4G3               = "TUN-full.T4-G3-100k-pps"
	caseT5Fallback         = "TUN-full.T5-fallback"
	caseT5AdapterMatrix    = "TUN-full.T5-adapter-matrix"
	caseT6Selector         = "TUN-full.T6-selector"
)

type caseRun func(context.Context, string, manifest.Spec) report.Case

type caseDef struct {
	spec manifest.Spec
	run  caseRun
}

// Alias is non-executable catalog metadata retained for historical CLI IDs.
// Before places the alias immediately before a canonical case in --list and
// defines the inclusive --from-case continuation point.
type Alias struct {
	ID        string
	Before    string
	ExpandsTo []string
}

// caseDefs contains executable cases only. Every entry is mandatory, appears
// once in Specs, executes once, and produces exactly one report row.
var caseDefs = []caseDef{
	{spec: tunSpec(caseKernelTUNPreflight, 30*time.Second, false), run: runKernelTUNPreflightManifestCase},
	{spec: tunSpec(caseG1Smoke, 2*time.Minute, false), run: runG1ManifestCase},
	{spec: tunSpec(caseG2Smoke, 2*time.Minute, false), run: runG2ManifestCase},
	{spec: tunSpec(caseG3Smoke, 2*time.Minute, false), run: runG3ManifestCase},
	{spec: tunSpec(caseG4PathDeath, 30*time.Second, false), run: runG4ManifestCase},
	{spec: tunSpec(caseG5PathRecovery, time.Minute, false), run: runG5ManifestCase},
	{spec: tunSpec(caseT3XrayMatrix, 12*time.Minute, true), run: runT3XrayMatrixManifestCase},
	{spec: tunSpec(caseT4G1, 7*time.Minute, true), run: runT4G1ManifestCase},
	{spec: tunSpec(caseT4G2, 33*time.Minute, true), run: runT4G2ManifestCase},
	{spec: tunSpec(caseT4G3, 8*time.Minute, true), run: runT4G3ManifestCase},
	{spec: tunSpec(caseT5AdapterMatrix, 5*time.Minute, false), run: runT5ManifestCase},
	{spec: tunSpec(caseT6Selector, 2*time.Minute, false), run: runT6ManifestCase},
}

var aliases = []Alias{
	{ID: caseT3XrayStreamSmoke, Before: caseT3XrayMatrix, ExpandsTo: []string{caseT3XrayMatrix}},
	{ID: caseT4LongRun, Before: caseT4G1, ExpandsTo: []string{caseT4G1, caseT4G2, caseT4G3}},
	{ID: caseT4G2Prime, Before: caseT4G2, ExpandsTo: []string{caseT4G2}},
	{ID: caseT5Fallback, Before: caseT5AdapterMatrix, ExpandsTo: []string{caseT5AdapterMatrix}},
}

func tunSpec(id string, budget time.Duration, long bool) manifest.Spec {
	spec := manifest.Spec{
		ID:        id,
		Tier:      "T7",
		Suite:     manifest.SuiteTUN,
		Mandatory: true,
		Long:      long,
		Budget:    budget,
	}
	if strings.HasPrefix(id, "TUN-full.") && id != caseKernelTUNPreflight {
		spec.Requires = []string{caseKernelTUNPreflight}
	}
	return spec
}

// Specs returns the canonical executable TUN synthetic-suite manifest.
func Specs() []manifest.Spec {
	return specsFrom(caseDefs)
}

// Aliases returns non-executable compatibility metadata. Aliases never enter
// manifest validation, selected-case counts, or report rows.
func Aliases() []Alias {
	result := make([]Alias, len(aliases))
	for i, alias := range aliases {
		result[i] = alias
		result[i].ExpandsTo = append([]string(nil), alias.ExpandsTo...)
	}
	return result
}

func specsFrom(defs []caseDef) []manifest.Spec {
	specs := make([]manifest.Spec, len(defs))
	for i, def := range defs {
		specs[i] = def.spec
		specs[i].Requires = append([]string(nil), def.spec.Requires...)
	}
	return specs
}

func selectCaseDefs(opts Options) ([]caseDef, error) {
	return selectCaseDefsFrom(caseDefs, opts)
}

func selectCaseDefsFrom(defs []caseDef, opts Options) ([]caseDef, error) {
	if err := validateCaseDefs(defs); err != nil {
		return nil, err
	}
	selected, err := manifest.Select(specsFrom(defs), opts.Case, opts.FromCase)
	if err != nil {
		return nil, err
	}

	byID := make(map[string]caseDef, len(defs))
	for _, def := range defs {
		byID[def.spec.ID] = def
	}
	result := make([]caseDef, 0, len(selected))
	for _, spec := range selected {
		result = append(result, byID[spec.ID])
	}
	return result, nil
}

func validateCaseDefs(defs []caseDef) error {
	if err := manifest.Validate(specsFrom(defs)); err != nil {
		return err
	}
	for _, def := range defs {
		spec := def.spec
		if !spec.Mandatory {
			return fmt.Errorf("tunfull: case %q is not mandatory", spec.ID)
		}
		if spec.Suite != manifest.SuiteTUN {
			return fmt.Errorf("tunfull: case %q has suite %q", spec.ID, spec.Suite)
		}
		if spec.Budget <= 0 {
			return fmt.Errorf("tunfull: case %q has no execution budget", spec.ID)
		}
		if def.run == nil {
			return fmt.Errorf("tunfull: case %q has no runner", spec.ID)
		}
	}
	return nil
}

// Run executes selected synthetic TUN/L3-session cases in manifest order.
func Run(ctx context.Context, suite *report.Suite, rendrRoot string, opts Options) {
	defs, err := selectCaseDefs(opts)
	if err != nil {
		suite.Add(report.Case{
			Name: "TUN-full-case-filter",
			Tier: "T7",
			Failure: fmt.Sprintf(
				"TUN synthetic L3/session case selection failed for case=%q from-case=%q: %v",
				opts.Case,
				opts.FromCase,
				err,
			),
		})
		return
	}
	runCaseDefs(ctx, suite, rendrRoot, defs)
}

func runCaseDefs(ctx context.Context, suite *report.Suite, rendrRoot string, defs []caseDef) {
	failedCaseID := ""
	for _, def := range defs {
		if failedCaseID != "" {
			suite.Add(notRunCase(def.spec, failedCaseID))
			continue
		}
		rc := runManifestCase(ctx, rendrRoot, def)
		suite.Add(rc)
		if mandatoryCaseFailed(def.spec, rc) {
			failedCaseID = def.spec.ID
		}
	}
}

func mandatoryCaseFailed(spec manifest.Spec, rc report.Case) bool {
	return spec.Mandatory && (rc.Failure != "" || rc.InvalidReason != "" || rc.SkipReason != "")
}

func notRunCase(spec manifest.Spec, failedCaseID string) report.Case {
	rc := report.Case{
		Name:          spec.ID,
		Tier:          spec.Tier,
		InvalidReason: fmt.Sprintf("not run after %s failed", failedCaseID),
	}
	markSyntheticEvidence(&rc)
	return rc
}

// NotRunCase creates the canonical synthetic-suite placeholder used when the
// CLI stops after a mandatory failure. It preserves one row per selected spec.
func NotRunCase(spec manifest.Spec, failedCaseID string) report.Case {
	return notRunCase(spec, failedCaseID)
}

func runManifestCase(ctx context.Context, rendrRoot string, def caseDef) report.Case {
	start := time.Now()
	cctx, cancel := context.WithTimeout(ctx, def.spec.Budget)
	done := make(chan report.Case, 1)
	workloadDone := make(chan struct{})
	go func() {
		defer close(workloadDone)
		defer func() {
			if recovered := recover(); recovered != nil {
				done <- report.Case{Failure: fmt.Sprintf("runner panic: %v", recovered)}
			}
		}()
		done <- def.run(cctx, rendrRoot, def.spec)
	}()

	var rc report.Case
	timedOut := false
	var timeoutErr error
	select {
	case rc = <-done:
		if err := cctx.Err(); err != nil {
			budgetFailure := fmt.Sprintf("case exceeded TUN synthetic-suite budget %s: %v", def.spec.Budget, err)
			if rc.Failure == "" {
				rc.Failure = budgetFailure
			} else {
				rc.Failure = budgetFailure + ": " + rc.Failure
			}
		}
	case <-cctx.Done():
		timedOut = true
		timeoutErr = cctx.Err()
	}
	cancel()
	<-workloadDone
	if timedOut {
		rc = <-done
		budgetFailure := fmt.Sprintf("case exceeded TUN synthetic-suite budget %s: %v", def.spec.Budget, timeoutErr)
		if rc.Failure == "" {
			rc.Failure = budgetFailure
		} else {
			rc.Failure = budgetFailure + ": " + rc.Failure
		}
	}
	if rc.Duration == 0 {
		rc.Duration = time.Since(start)
	}
	contractFailures := make([]string, 0, 2)
	if rc.Name != "" && rc.Name != def.spec.ID {
		contractFailures = append(contractFailures, fmt.Sprintf("runner reported case %q", rc.Name))
	}
	if rc.Tier != "" && rc.Tier != def.spec.Tier {
		contractFailures = append(contractFailures, fmt.Sprintf("runner reported tier %q", rc.Tier))
	}
	if len(contractFailures) > 0 {
		contractFailure := strings.Join(contractFailures, "; ")
		if rc.Failure == "" {
			rc.Failure = contractFailure
		} else {
			rc.Failure = contractFailure + ": " + rc.Failure
		}
	}
	rc.Name = def.spec.ID
	rc.Tier = def.spec.Tier
	markSyntheticEvidence(&rc)
	return rc
}

const (
	syntheticEvidenceClass = "synthetic_l3_session_smoke"
	realTUNGoldFixture     = "private_T7.kernel_fixture_required"
)

func markSyntheticEvidence(rc *report.Case) {
	if rc == nil {
		return
	}
	if rc.Evidence == nil {
		rc.Evidence = make(map[string]string, 3)
	}
	if rc.Evidence["evidence_class"] == "" {
		rc.Evidence["evidence_class"] = syntheticEvidenceClass
	}
	if rc.Evidence["kernel_tun_gold"] == "" {
		rc.Evidence["kernel_tun_gold"] = "false"
	}
	if rc.Evidence["required_gold_fixture"] == "" {
		rc.Evidence["required_gold_fixture"] = realTUNGoldFixture
	}
}

var probeKernelTUN = tun.Probe

func runKernelTUNPreflightManifestCase(_ context.Context, _ string, spec manifest.Spec) report.Case {
	started := time.Now()
	capability := probeKernelTUN()
	rc := report.Case{
		Name:     spec.ID,
		Tier:     spec.Tier,
		Duration: time.Since(started),
		Evidence: map[string]string{
			"kernel_tun_available": fmt.Sprintf("%t", capability.Available),
			"kernel_tun_reason":    string(capability.Reason),
		},
	}
	if !capability.Available {
		detail := string(capability.Reason)
		if capability.Err != nil {
			detail = capability.Err.Error()
		}
		rc.InvalidReason = "kernel TUN preflight unavailable: " + detail +
			"; this synthetic L3/session suite cannot count as TUN release evidence"
	}
	return rc
}

func runG1ManifestCase(ctx context.Context, _ string, spec manifest.Spec) report.Case {
	return runG1Smoke(ctx, g1SmokeOptions{name: spec.ID, size: 30 << 20, paths: 2, migrations: 3})
}

func runG2ManifestCase(ctx context.Context, _ string, spec manifest.Spec) report.Case {
	return runG2Smoke(ctx, g2SmokeOptions{
		name: spec.ID, duration: 30 * time.Second, interval: 100 * time.Millisecond, paths: 2, migrations: 5,
	})
}

func runG3ManifestCase(ctx context.Context, _ string, spec manifest.Spec) report.Case {
	return runG3Smoke(ctx, g3Options{
		name: spec.ID, duration: 5 * time.Second, pps: 5000, payloadLen: 1024,
		paths: 4, migrations: 3, lossPct: 0, p95Ceiling: 50 * time.Millisecond,
	})
}

func runG4ManifestCase(ctx context.Context, _ string, spec manifest.Spec) report.Case {
	return runG4PathDeath(ctx, g4Options{
		name: spec.ID, duration: 6 * time.Second, killAt: 2 * time.Second,
		echoInt: 10 * time.Millisecond, paths: 2, budget: 5 * time.Second,
	})
}

func runG5ManifestCase(ctx context.Context, _ string, spec manifest.Spec) report.Case {
	return runG5PathRecovery(ctx, g5Options{name: spec.ID, paths: 2, postAddBytes: 256 << 10})
}

func runT3XrayMatrixManifestCase(ctx context.Context, rendrRoot string, spec manifest.Spec) report.Case {
	return runT3XrayMatrix(ctx, rendrRoot, spec.ID)
}

func runT4G1ManifestCase(ctx context.Context, _ string, spec manifest.Spec) report.Case {
	return runT4WithBudget(ctx, spec.ID, spec.Budget, chaos.Realistic50M, func(c context.Context) report.Case {
		return runG1Smoke(c, g1SmokeOptions{name: spec.ID, size: 1 << 30, paths: 2, migrations: 10})
	})
}

func runT4G2ManifestCase(ctx context.Context, _ string, spec manifest.Spec) report.Case {
	return runT4WithBudget(ctx, spec.ID, spec.Budget, chaos.Realistic50M, func(c context.Context) report.Case {
		return runG2Smoke(c, g2SmokeOptions{
			name: spec.ID, duration: 30 * time.Minute, interval: 100 * time.Millisecond, paths: 2, migrations: 30,
		})
	})
}

func runT4G3ManifestCase(ctx context.Context, _ string, spec manifest.Spec) report.Case {
	return runT4WithBudget(ctx, spec.ID, spec.Budget, chaos.Profile{}, func(c context.Context) report.Case {
		return runG3Smoke(c, g3Options{
			name: spec.ID, duration: 5 * time.Minute, pps: 100_000, payloadLen: 1024,
			paths: 32, migrations: 10, lossPct: 0, p95Ceiling: 20 * time.Millisecond,
		})
	})
}

func runT5ManifestCase(ctx context.Context, _ string, spec manifest.Spec) report.Case {
	rc := runT5AdapterMatrix(ctx, t5AdapterMatrixOptions{name: spec.ID})
	if rc.Evidence == nil {
		rc.Evidence = make(map[string]string)
	}
	rc.Evidence["t5_semantics"] = "independent_adapter_matrix_not_live_fallback"
	return rc
}

func runT6ManifestCase(ctx context.Context, _ string, spec manifest.Spec) report.Case {
	return runT6Selector(ctx, t6SelectorOptions{name: spec.ID})
}

// UnimplementedCase returns the explicit guard case used until real
// TUN full baseline cases are implemented.
func UnimplementedCase(name string) report.Case {
	if name == "" {
		name = "TUN-full-not-implemented"
	}
	return report.Case{
		Name:     name,
		Tier:     "T7",
		Duration: 0 * time.Second,
		Failure:  "--tun-full baseline is not implemented yet; T7 feature tests are not a full TUN regression",
	}
}

var tunChaosApply = chaos.Apply

func runT4WithBudget(ctx context.Context, name string, budget time.Duration, prof chaos.Profile, fn func(context.Context) report.Case) report.Case {
	start := time.Now()
	cleanup, err := tunChaosApply(prof)
	if err != nil {
		return report.Case{
			Name:          name,
			Tier:          "T7",
			Duration:      time.Since(start),
			InvalidReason: "chaos fixture setup failed: " + err.Error(),
		}
	}
	cctx, cancel := context.WithTimeout(ctx, budget)
	var result report.Case
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				result = failedCase(name, start, fmt.Errorf("runner panic: %v", recovered))
			}
		}()
		result = fn(cctx)
	}()
	budgetErr := cctx.Err()
	cancel()
	if budgetErr != nil {
		budgetFailure := fmt.Sprintf("case exceeded T4 budget %s: %v", budget, budgetErr)
		if result.Failure == "" {
			result.Failure = budgetFailure
		} else {
			result.Failure = budgetFailure + ": " + result.Failure
		}
	}
	if result.Name == "" {
		result.Name = name
	}
	if result.Tier == "" {
		result.Tier = "T7"
	}
	if result.Duration == 0 {
		result.Duration = time.Since(start)
	}
	applyT4CleanupResult(&result, cleanup)
	return result
}

func applyT4CleanupResult(rc *report.Case, cleanup func() error) {
	if rc == nil || cleanup == nil {
		return
	}
	if err := cleanup(); err != nil {
		markTUNChaosInvalid(rc, "chaos cleanup failed: "+err.Error())
	}
}

func markTUNChaosInvalid(rc *report.Case, reason string) {
	if rc == nil || reason == "" {
		return
	}
	if rc.Failure != "" {
		if rc.Evidence == nil {
			rc.Evidence = make(map[string]string)
		}
		rc.Evidence["untrusted_case_failure"] = rc.Failure
		rc.Failure = ""
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

type g1SmokeOptions struct {
	name       string
	size       int64
	paths      int
	migrations int
}

type g2SmokeOptions struct {
	name       string
	duration   time.Duration
	interval   time.Duration
	paths      int
	migrations int
}

type g4Options struct {
	name     string
	duration time.Duration
	killAt   time.Duration
	echoInt  time.Duration
	paths    int
	budget   time.Duration
}

type g5Options struct {
	name         string
	paths        int
	postAddBytes int64
}

type g3Options struct {
	name       string
	duration   time.Duration
	pps        int
	payloadLen int
	paths      int
	migrations int
	lossPct    float64
	p95Ceiling time.Duration
}

type t6SelectorOptions struct {
	name           string
	bulkWarmWrites int
	bulkBondWrites int
}

type t5AdapterMatrixOptions struct {
	name       string
	size       int64
	migrations int
}

func runG1Smoke(ctx context.Context, opts g1SmokeOptions) report.Case {
	start := time.Now()
	if opts.name == "" {
		opts.name = "TUN-full.G1-smoke"
	}
	if opts.size <= 0 {
		opts.size = 30 << 20
	}
	if opts.paths < 2 {
		opts.paths = 2
	}
	if opts.migrations < 0 {
		opts.migrations = 0
	}
	ln, err := rendr.ListenTCP("127.0.0.1:0")
	if err != nil {
		return failedCase(opts.name, start, fmt.Errorf("listen: %w", err))
	}
	defer ln.Close()

	accepted := make(chan rendr.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		actx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		c, err := ln.Accept(actx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- c
	}()

	id := g1Identity()
	root := g1Root(ln.Addr().String(), opts.paths)
	manager := &l3session.Manager{}
	relay := &l3session.TCPRelay{Manager: manager}
	app, endpoint := net.Pipe()
	defer app.Close()

	relayErr := make(chan error, 1)
	go func() {
		relayErr <- relay.Serve(ctx, g1Event(id, root), endpoint)
	}()

	var server rendr.Conn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		return failedCase(opts.name, start, fmt.Errorf("accept: %w", err))
	case <-time.After(15 * time.Second):
		return failedCase(opts.name, start, fmt.Errorf("accept timeout"))
	}
	defer server.Close()

	sess, err := waitStreamSession(ctx, manager, id)
	if err != nil {
		return failedCase(opts.name, start, err)
	}
	admin, ok := sess.Conn.(rendr.AdminConn)
	if !ok {
		return failedCase(opts.name, start, fmt.Errorf("session conn is not rendr.AdminConn"))
	}
	waitPaths(ctx, admin, opts.paths)

	recvErr := make(chan error, 1)
	hRecv := sha256.New()
	go func() {
		buf := make([]byte, 256*1024)
		var got int64
		for got < opts.size {
			n, err := server.Read(buf)
			if err != nil {
				recvErr <- err
				return
			}
			hRecv.Write(buf[:n])
			got += int64(n)
		}
		recvErr <- nil
	}()

	migPts := make([]int64, opts.migrations)
	for i := 0; i < opts.migrations; i++ {
		migPts[i] = opts.size * int64(i+1) / int64(opts.migrations+1)
	}
	hSent := sha256.New()
	buf := make([]byte, 256*1024)
	var written int64
	var migIdx int
	for written < opts.size {
		end := written + int64(len(buf))
		if end > opts.size {
			end = opts.size
		}
		chunk := buf[:end-written]
		fillPattern(chunk, written)
		if err := writeAll(app, chunk); err != nil {
			return failedCase(opts.name, start, fmt.Errorf("write at %d: %w", written, err))
		}
		hSent.Write(chunk)
		written += int64(len(chunk))
		for migIdx < len(migPts) && written >= migPts[migIdx] {
			next := nextPath(admin)
			if next != 0 {
				if err := admin.Migrate(next); err != nil {
					return failedCase(opts.name, start, fmt.Errorf("migrate %d: %w", migIdx, err))
				}
			}
			migIdx++
		}
	}

	if err := <-recvErr; err != nil {
		return failedCase(opts.name, start, fmt.Errorf("recv: %w", err))
	}
	_ = app.Close()
	select {
	case err := <-relayErr:
		if err != nil {
			return failedCase(opts.name, start, fmt.Errorf("relay: %w", err))
		}
	case <-time.After(5 * time.Second):
		return failedCase(opts.name, start, fmt.Errorf("relay shutdown timeout"))
	}

	sentHex := fmt.Sprintf("%x", hSent.Sum(nil))
	recvHex := fmt.Sprintf("%x", hRecv.Sum(nil))
	if sentHex != recvHex {
		return failedCase(opts.name, start, fmt.Errorf("SHA-256 mismatch: sent=%s recv=%s", sentHex, recvHex))
	}
	if opts.migrations > 0 && admin.MigrationCount() < uint64(opts.migrations) {
		return failedCase(opts.name, start, fmt.Errorf("MigrationCount=%d, want >= %d", admin.MigrationCount(), opts.migrations))
	}
	return report.Case{Name: opts.name, Tier: "T7", Duration: time.Since(start)}
}

func failedCase(name string, start time.Time, err error) report.Case {
	return report.Case{Name: name, Tier: "T7", Duration: time.Since(start), Failure: err.Error()}
}

func g1Identity() l3ingress.L3Identity {
	return l3ingress.L3Identity{
		Proto:   l3ingress.ProtocolTCP,
		SrcIP:   netip.MustParseAddr("10.0.0.2"),
		SrcPort: 40000,
		DstIP:   netip.MustParseAddr("198.51.100.20"),
		DstPort: 443,
	}
}

func g1Root(addr string, paths int) rendr.Target {
	children := make([]rendr.Target, 0, paths)
	for i := 0; i < paths; i++ {
		name := fmt.Sprintf("tun-g1-%d", i+1)
		children = append(children, rendr.Path(name, rendr.PathSpec{Transport: "tcp", Address: addr}))
	}
	return rendr.Selector("tun-full-g1", children)
}

func g1Event(id l3ingress.L3Identity, root rendr.Target) l3ingress.PacketEvent {
	return l3ingress.PacketEvent{
		Meta: l3ingress.PacketMeta{Identity: id},
		Flow: l3ingress.FlowMeta{L3Identity: id, Direction: l3ingress.DirectionIngress},
		Decision: l3ingress.FlowDecision{
			Peer:   "peer-a",
			Root:   root,
			Egress: "direct",
		},
		Decided: true,
	}
}

func waitStreamSession(ctx context.Context, manager *l3session.Manager, id l3ingress.L3Identity) (*l3session.Session, error) {
	deadline := time.After(15 * time.Second)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if sess, ok := manager.Session(id); ok && sess.Conn != nil {
			return sess, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline:
			return nil, fmt.Errorf("stream session timeout")
		case <-tick.C:
		}
	}
}

func waitPaths(ctx context.Context, admin rendr.AdminConn, want int) {
	deadline := time.After(5 * time.Second)
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for len(admin.Paths()) < want {
		select {
		case <-ctx.Done():
			return
		case <-deadline:
			return
		case <-tick.C:
		}
	}
}

func nextPath(admin rendr.AdminConn) uint32 {
	cur := admin.ActivePath()
	for _, p := range admin.Paths() {
		if p.ID != cur {
			return p.ID
		}
	}
	return 0
}

func fillPattern(buf []byte, offset int64) {
	for i := range buf {
		buf[i] = byte((offset+int64(i))*17 + 3)
	}
}

func writeAll(w net.Conn, buf []byte) error {
	for len(buf) > 0 {
		n, err := w.Write(buf)
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("short write")
		}
		buf = buf[n:]
	}
	return nil
}

func runG2Smoke(ctx context.Context, opts g2SmokeOptions) report.Case {
	start := time.Now()
	if opts.name == "" {
		opts.name = "TUN-full.G2-smoke"
	}
	if opts.duration <= 0 {
		opts.duration = 30 * time.Second
	}
	if opts.interval <= 0 {
		opts.interval = 100 * time.Millisecond
	}
	if opts.paths < 2 {
		opts.paths = 2
	}
	if opts.migrations < 0 {
		opts.migrations = 0
	}

	ln, err := rendr.ListenTCP("127.0.0.1:0")
	if err != nil {
		return failedCase(opts.name, start, fmt.Errorf("listen: %w", err))
	}
	defer ln.Close()

	accepted := make(chan rendr.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		actx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		c, err := ln.Accept(actx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- c
	}()

	id := g1Identity()
	root := g1Root(ln.Addr().String(), opts.paths)
	manager := &l3session.Manager{}
	relay := &l3session.TCPRelay{Manager: manager}
	app, endpoint := net.Pipe()
	defer app.Close()

	relayErr := make(chan error, 1)
	go func() {
		relayErr <- relay.Serve(ctx, g1Event(id, root), endpoint)
	}()

	var server rendr.Conn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		return failedCase(opts.name, start, fmt.Errorf("accept: %w", err))
	case <-time.After(15 * time.Second):
		return failedCase(opts.name, start, fmt.Errorf("accept timeout"))
	}
	defer server.Close()

	sess, err := waitStreamSession(ctx, manager, id)
	if err != nil {
		return failedCase(opts.name, start, err)
	}
	admin, ok := sess.Conn.(rendr.AdminConn)
	if !ok {
		return failedCase(opts.name, start, fmt.Errorf("session conn is not rendr.AdminConn"))
	}
	waitPaths(ctx, admin, opts.paths)

	echoErr := make(chan error, 1)
	go func() {
		var msg [8]byte
		for {
			if err := readAll(server, msg[:]); err != nil {
				echoErr <- err
				return
			}
			if err := writeAll(server, msg[:]); err != nil {
				echoErr <- err
				return
			}
		}
	}()

	deadline := time.Now().Add(opts.duration)
	nextMig := make([]time.Time, opts.migrations)
	for i := range nextMig {
		nextMig[i] = start.Add(opts.duration * time.Duration(i+1) / time.Duration(opts.migrations+1))
	}
	var migIdx int
	var seq uint64
	rtts := make([]time.Duration, 0, int(opts.duration/opts.interval)+1)
	ticker := time.NewTicker(opts.interval)
	defer ticker.Stop()
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return failedCase(opts.name, start, ctx.Err())
		case <-ticker.C:
		}
		var msg [8]byte
		binary.BigEndian.PutUint64(msg[:], seq)
		sentAt := time.Now()
		if err := writeAll(app, msg[:]); err != nil {
			return failedCase(opts.name, start, fmt.Errorf("write seq %d: %w", seq, err))
		}
		var got [8]byte
		if err := readAll(app, got[:]); err != nil {
			return failedCase(opts.name, start, fmt.Errorf("read seq %d: %w", seq, err))
		}
		if binary.BigEndian.Uint64(got[:]) != seq {
			return failedCase(opts.name, start, fmt.Errorf("echo seq mismatch: got %d want %d", binary.BigEndian.Uint64(got[:]), seq))
		}
		rtts = append(rtts, time.Since(sentAt))
		seq++
		for migIdx < len(nextMig) && time.Now().After(nextMig[migIdx]) {
			next := nextPath(admin)
			if next != 0 {
				if err := admin.Migrate(next); err != nil {
					return failedCase(opts.name, start, fmt.Errorf("migrate %d: %w", migIdx, err))
				}
			}
			migIdx++
		}
	}
	if len(rtts) == 0 {
		return failedCase(opts.name, start, fmt.Errorf("no echoes completed"))
	}
	if opts.migrations > 0 && admin.MigrationCount() < uint64(opts.migrations) {
		return failedCase(opts.name, start, fmt.Errorf("MigrationCount=%d, want >= %d", admin.MigrationCount(), opts.migrations))
	}
	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
	if p99 := percentile(rtts, 0.99); p99 > time.Second {
		return failedCase(opts.name, start, fmt.Errorf("P99 RTT %s exceeds 1s", p99))
	}

	_ = app.Close()
	select {
	case err := <-relayErr:
		if err != nil {
			return failedCase(opts.name, start, fmt.Errorf("relay: %w", err))
		}
	case <-time.After(5 * time.Second):
		return failedCase(opts.name, start, fmt.Errorf("relay shutdown timeout"))
	}
	select {
	case err := <-echoErr:
		if err != nil && !isClosedRelayErr(err) {
			return failedCase(opts.name, start, fmt.Errorf("echo: %w", err))
		}
	default:
	}
	return report.Case{Name: opts.name, Tier: "T7", Duration: time.Since(start)}
}

func readAll(r net.Conn, buf []byte) error {
	for len(buf) > 0 {
		n, err := r.Read(buf)
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("short read")
		}
		buf = buf[n:]
	}
	return nil
}

func percentile(sorted []time.Duration, q float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1) * q)
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func isClosedRelayErr(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe)
}

func runG4PathDeath(ctx context.Context, opts g4Options) report.Case {
	start := time.Now()
	if opts.name == "" {
		opts.name = "TUN-full.G4-path-death"
	}
	if opts.duration <= 0 {
		opts.duration = 6 * time.Second
	}
	if opts.killAt <= 0 {
		opts.killAt = 2 * time.Second
	}
	if opts.echoInt <= 0 {
		opts.echoInt = 10 * time.Millisecond
	}
	if opts.paths < 2 {
		opts.paths = 2
	}
	if opts.budget <= 0 {
		opts.budget = 5 * time.Second
	}

	env, err := startTUNStream(ctx, opts.paths)
	if err != nil {
		return failedCase(opts.name, start, err)
	}
	defer env.close()

	killer, ok := env.admin.(interface {
		ForceKillPathForTest(id uint32) error
	})
	if !ok {
		return failedCase(opts.name, start, fmt.Errorf("session conn lacks ForceKillPathForTest test hook"))
	}
	echoErr := startStreamEcho(env.server, 8)

	killDone := make(chan time.Time, 1)
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(opts.killAt):
		}
		cur := env.admin.ActivePath()
		if cur != 0 {
			_ = killer.ForceKillPathForTest(cur)
		}
		killDone <- time.Now()
	}()

	endAt := time.Now().Add(opts.duration)
	var seq uint64
	var lost int
	var maxRTT time.Duration
	var killStamp time.Time
	var firstPostKill time.Time
	for time.Now().Before(endAt) {
		var tx [8]byte
		binary.BigEndian.PutUint64(tx[:], seq)
		echoStart := time.Now()
		if err := writeAll(env.app, tx[:]); err != nil {
			return failedCase(opts.name, start, fmt.Errorf("write seq %d: %w", seq, err))
		}
		var rx [8]byte
		if err := readAll(env.app, rx[:]); err != nil {
			return failedCase(opts.name, start, fmt.Errorf("read seq %d: %w", seq, err))
		}
		if binary.BigEndian.Uint64(rx[:]) != seq {
			lost++
		}
		if rtt := time.Since(echoStart); rtt > maxRTT {
			maxRTT = rtt
		}
		select {
		case s := <-killDone:
			killStamp = s
			killDone = nil
		default:
		}
		if !killStamp.IsZero() && firstPostKill.IsZero() && time.Now().After(killStamp) {
			firstPostKill = time.Now()
		}
		seq++
		select {
		case <-ctx.Done():
			return failedCase(opts.name, start, ctx.Err())
		case <-time.After(opts.echoInt):
		}
	}

	if lost > 0 {
		return failedCase(opts.name, start, fmt.Errorf("application-visible echo loss: %d", lost))
	}
	if killStamp.IsZero() {
		return failedCase(opts.name, start, fmt.Errorf("path kill did not run"))
	}
	if firstPostKill.IsZero() {
		return failedCase(opts.name, start, fmt.Errorf("no echo completed after path kill"))
	}
	if failover := firstPostKill.Sub(killStamp); failover > opts.budget {
		return failedCase(opts.name, start, fmt.Errorf("failover %s exceeds %s budget", failover, opts.budget))
	}
	_ = env.app.Close()
	if err := env.waitRelay(5 * time.Second); err != nil {
		return failedCase(opts.name, start, err)
	}
	select {
	case err := <-echoErr:
		if err != nil && !isClosedRelayErr(err) {
			return failedCase(opts.name, start, fmt.Errorf("echo: %w", err))
		}
	default:
	}
	_ = maxRTT
	return report.Case{Name: opts.name, Tier: "T7", Duration: time.Since(start)}
}

func runG5PathRecovery(ctx context.Context, opts g5Options) report.Case {
	start := time.Now()
	if opts.name == "" {
		opts.name = "TUN-full.G5-path-recovery"
	}
	if opts.paths < 2 {
		opts.paths = 2
	}
	if opts.postAddBytes <= 0 {
		opts.postAddBytes = 256 << 10
	}

	env, err := startTUNStream(ctx, opts.paths)
	if err != nil {
		return failedCase(opts.name, start, err)
	}
	defer env.close()

	killer, ok := env.admin.(interface {
		ForceKillPathForTest(id uint32) error
	})
	if !ok {
		return failedCase(opts.name, start, fmt.Errorf("session conn lacks ForceKillPathForTest test hook"))
	}
	cur := env.admin.ActivePath()
	if cur == 0 {
		return failedCase(opts.name, start, fmt.Errorf("no active path"))
	}
	if err := killer.ForceKillPathForTest(cur); err != nil {
		return failedCase(opts.name, start, fmt.Errorf("kill active: %w", err))
	}
	echoErr := startStreamEcho(env.server, 4096)
	time.Sleep(300 * time.Millisecond)

	newID, err := env.admin.AddPath(rendr.PathSpec{Transport: "tcp", Address: env.addr})
	if err != nil {
		return failedCase(opts.name, start, fmt.Errorf("AddPath: %w", err))
	}
	if newID == 0 {
		return failedCase(opts.name, start, fmt.Errorf("AddPath returned id=0"))
	}

	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte(i)
	}
	rx := make([]byte, 4096)
	var written int64
	for written < opts.postAddBytes {
		toWrite := opts.postAddBytes - written
		if toWrite > int64(len(payload)) {
			toWrite = int64(len(payload))
		}
		chunk := payload[:toWrite]
		if err := writeAll(env.app, chunk); err != nil {
			return failedCase(opts.name, start, fmt.Errorf("post-add write: %w", err))
		}
		got := int64(0)
		for got < toWrite {
			n, err := env.app.Read(rx[got:toWrite])
			if err != nil {
				return failedCase(opts.name, start, fmt.Errorf("post-add read: %w", err))
			}
			got += int64(n)
		}
		if string(rx[:toWrite]) != string(chunk) {
			return failedCase(opts.name, start, fmt.Errorf("post-add payload mismatch at byte %d", written))
		}
		written += toWrite
	}
	if stats := env.admin.Stats(); stats.RecvDups > 0 {
		return failedCase(opts.name, start, fmt.Errorf("RecvDups=%d after path re-add (expected 0)", stats.RecvDups))
	}

	_ = env.app.Close()
	if err := env.waitRelay(5 * time.Second); err != nil {
		return failedCase(opts.name, start, err)
	}
	select {
	case err := <-echoErr:
		if err != nil && !isClosedRelayErr(err) {
			return failedCase(opts.name, start, fmt.Errorf("echo: %w", err))
		}
	default:
	}
	return report.Case{Name: opts.name, Tier: "T7", Duration: time.Since(start)}
}

func runT5AdapterMatrix(ctx context.Context, opts t5AdapterMatrixOptions) report.Case {
	start := time.Now()
	if opts.name == "" {
		opts.name = caseT5AdapterMatrix
	}
	if opts.size <= 0 {
		opts.size = 8 << 20
	}
	if opts.migrations <= 0 {
		opts.migrations = 2
	}

	if err := tcprepair.Available(); err == nil {
		ln, err := rendr.ListenTCP("127.0.0.1:0")
		if err != nil {
			return failedCase(opts.name, start, fmt.Errorf("tcprepair listen: %w", err))
		}
		if err := runTUNStreamTransfer(ctx, ln, t5Root(ln.Addr().String(), "tcprepair", "tun-t5-tcprepair", 2), t5Identity(44000), opts.size, 1); err != nil {
			_ = ln.Close()
			return failedCase(opts.name, start, fmt.Errorf("tcprepair path: %w", err))
		}
		_ = ln.Close()
	} else if !strings.Contains(err.Error(), "gvisor fallback") {
		return failedCase(opts.name, start, fmt.Errorf("tcprepair unavailable error does not name gvisor fallback: %w", err))
	}

	ln, err := rendr.ListenGVisor("")
	if err != nil {
		return failedCase(opts.name, start, fmt.Errorf("gvisor listen: %w", err))
	}
	if err := runTUNStreamTransfer(ctx, ln, t5Root(ln.Addr().String(), "gvisor", "tun-t5-gvisor", 2), t5Identity(45000), opts.size, opts.migrations); err != nil {
		_ = ln.Close()
		return failedCase(opts.name, start, fmt.Errorf("gvisor path: %w", err))
	}
	_ = ln.Close()

	packetLn, err := rendr.ListenGVisorPacket("127.0.0.1:0")
	if err != nil {
		return failedCase(opts.name, start, fmt.Errorf("gvisor packet listen: %w", err))
	}
	if err := runTUNStreamTransfer(ctx, packetLn, t5Root(packetLn.Addr().String(), "gvisor", "tun-t5-gvisor-packet", 2), t5Identity(46000), opts.size, opts.migrations); err != nil {
		_ = packetLn.Close()
		return failedCase(opts.name, start, fmt.Errorf("gvisor packet path: %w", err))
	}
	_ = packetLn.Close()

	return report.Case{Name: opts.name, Tier: "T7", Duration: time.Since(start)}
}

func runT6Selector(ctx context.Context, opts t6SelectorOptions) report.Case {
	start := time.Now()
	if opts.name == "" {
		opts.name = "TUN-full.T6-selector"
	}
	if opts.bulkWarmWrites <= 0 {
		opts.bulkWarmWrites = 36
	}
	if opts.bulkBondWrites <= 0 {
		opts.bulkBondWrites = 24
	}

	ln, err := rendr.ListenTCP("127.0.0.1:0")
	if err != nil {
		return failedCase(opts.name, start, fmt.Errorf("listen: %w", err))
	}
	defer ln.Close()

	addr := ln.Addr().String()
	interactiveID := t6Identity(42000, 22)
	bulkID := t6Identity(43000, 443)
	interactiveRoot := t6SelectorRoot(addr, "tun-t6-int")
	bulkRoot := t6SelectorRoot(addr, "tun-t6-bulk")
	table := l3ingress.NewFlowTable(func(_ context.Context, flow l3ingress.FlowMeta) (l3ingress.FlowDecision, error) {
		switch flow.L3Identity {
		case interactiveID:
			return l3ingress.FlowDecision{
				Peer:   "peer-low",
				Root:   interactiveRoot,
				Egress: "direct",
				Labels: map[string]string{"class": "interactive"},
			}, nil
		case bulkID:
			return l3ingress.FlowDecision{
				Peer:   "peer-bulk",
				Root:   bulkRoot,
				Egress: "bond",
				Labels: map[string]string{"class": "bulk"},
			}, nil
		default:
			return l3ingress.FlowDecision{}, fmt.Errorf("unexpected flow identity: %+v", flow.L3Identity)
		}
	}, l3ingress.FlowTableOptions{})
	manager := &l3session.Manager{
		FlowTable: table,
		Starter: l3session.Starter{Options: []l3session.DialerOption{
			func(_ l3ingress.SessionRequest, d *rendr.Dialer) error {
				d.ProbeInterval = time.Hour
				return nil
			},
		}},
	}
	relay := &l3session.TCPRelay{Manager: manager, BufferSize: 64 << 10}

	intApp, intEndpoint := net.Pipe()
	defer intApp.Close()
	intRelayErr := make(chan error, 1)
	if err := startT6Flow(ctx, table, relay, interactiveID, intEndpoint, intRelayErr); err != nil {
		return failedCase(opts.name, start, fmt.Errorf("interactive flow: %w", err))
	}
	intServer, err := acceptOneStream(ctx, ln)
	if err != nil {
		return failedCase(opts.name, start, fmt.Errorf("accept interactive: %w", err))
	}
	defer intServer.Close()
	intEchoErr := startStreamEcho(intServer, 1024)
	intSess, err := waitStreamSession(ctx, manager, interactiveID)
	if err != nil {
		return failedCase(opts.name, start, fmt.Errorf("interactive session: %w", err))
	}
	intAdmin, ok := intSess.Conn.(rendr.AdminConn)
	if !ok {
		return failedCase(opts.name, start, fmt.Errorf("interactive session conn is not rendr.AdminConn"))
	}
	waitPaths(ctx, intAdmin, 3)
	intIDs := idsByPathName(intAdmin.Paths())
	if intIDs["tun-t6-int-A"] == 0 || intIDs["tun-t6-int-B"] == 0 || intIDs["tun-t6-int-C"] == 0 {
		return failedCase(opts.name, start, fmt.Errorf("interactive path names missing: %v", intIDs))
	}

	bulkApp, bulkEndpoint := net.Pipe()
	defer bulkApp.Close()
	bulkRelayErr := make(chan error, 1)
	if err := startT6Flow(ctx, table, relay, bulkID, bulkEndpoint, bulkRelayErr); err != nil {
		return failedCase(opts.name, start, fmt.Errorf("bulk flow: %w", err))
	}
	bulkServer, err := acceptOneStream(ctx, ln)
	if err != nil {
		return failedCase(opts.name, start, fmt.Errorf("accept bulk: %w", err))
	}
	defer bulkServer.Close()
	bulkDrainErr := startStreamDrain(bulkServer)
	bulkSess, err := waitStreamSession(ctx, manager, bulkID)
	if err != nil {
		return failedCase(opts.name, start, fmt.Errorf("bulk session: %w", err))
	}
	bulkAdmin, ok := bulkSess.Conn.(rendr.AdminConn)
	if !ok {
		return failedCase(opts.name, start, fmt.Errorf("bulk session conn is not rendr.AdminConn"))
	}
	waitPaths(ctx, bulkAdmin, 3)
	bulkIDs := idsByPathName(bulkAdmin.Paths())
	if bulkIDs["tun-t6-bulk-A"] == 0 || bulkIDs["tun-t6-bulk-B"] == 0 || bulkIDs["tun-t6-bulk-C"] == 0 {
		return failedCase(opts.name, start, fmt.Errorf("bulk path names missing: %v", bulkIDs))
	}

	for i := 0; i < 8; i++ {
		var msg [8]byte
		binary.BigEndian.PutUint64(msg[:], uint64(i))
		if err := writeAll(intApp, msg[:]); err != nil {
			return failedCase(opts.name, start, fmt.Errorf("interactive write: %w", err))
		}
		var got [8]byte
		if err := readAll(intApp, got[:]); err != nil {
			return failedCase(opts.name, start, fmt.Errorf("interactive read: %w", err))
		}
		if got != msg {
			return failedCase(opts.name, start, fmt.Errorf("interactive echo mismatch"))
		}
	}
	if got := intAdmin.Mode(); got != rendr.ModePrime {
		return failedCase(opts.name, start, fmt.Errorf("interactive mode=%v want prime", got))
	}
	if got := intAdmin.ActivePath(); got != intIDs["tun-t6-int-A"] {
		return failedCase(opts.name, start, fmt.Errorf("interactive active=%d want A=%d", got, intIDs["tun-t6-int-A"]))
	}

	chunk := make([]byte, 32<<10)
	for i := 0; i < opts.bulkWarmWrites; i++ {
		fillPattern(chunk, int64(i*len(chunk)))
		if err := writeAll(bulkApp, chunk); err != nil {
			return failedCase(opts.name, start, fmt.Errorf("bulk warm write %d: %w", i, err))
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := waitForAdminMode(bulkAdmin, rendr.ModeBond, 3*time.Second); err != nil {
		return failedCase(opts.name, start, fmt.Errorf("bulk peak transfer: %w", err))
	}
	before := writesByPathName(bulkAdmin.Paths())
	for i := 0; i < opts.bulkBondWrites; i++ {
		fillPattern(chunk, int64((opts.bulkWarmWrites+i)*len(chunk)))
		if err := writeAll(bulkApp, chunk); err != nil {
			return failedCase(opts.name, start, fmt.Errorf("bulk bond write %d: %w", i, err))
		}
	}
	after := writesByPathName(bulkAdmin.Paths())
	if after["tun-t6-bulk-B"] <= before["tun-t6-bulk-B"] || after["tun-t6-bulk-C"] <= before["tun-t6-bulk-C"] {
		return failedCase(opts.name, start, fmt.Errorf("bulk bond did not use both peak paths: before=%v after=%v", before, after))
	}

	if snap, ok := table.Snapshot(interactiveID); !ok {
		return failedCase(opts.name, start, fmt.Errorf("missing interactive flow snapshot"))
	} else if snap.MigrationCount != 0 || snap.Decision.Labels["class"] != "interactive" {
		return failedCase(opts.name, start, fmt.Errorf("interactive flow was polluted by bulk selector: %+v", snap))
	}
	if snap, ok := table.Snapshot(bulkID); !ok {
		return failedCase(opts.name, start, fmt.Errorf("missing bulk flow snapshot"))
	} else if snap.MigrationCount == 0 || snap.Decision.Labels["class"] != "bulk" {
		return failedCase(opts.name, start, fmt.Errorf("bulk flow did not record selector migration: %+v", snap))
	}

	_ = intApp.Close()
	_ = bulkApp.Close()
	if err := waitRelayErr(intRelayErr, 5*time.Second); err != nil {
		return failedCase(opts.name, start, fmt.Errorf("interactive relay: %w", err))
	}
	if err := waitRelayErr(bulkRelayErr, 5*time.Second); err != nil {
		return failedCase(opts.name, start, fmt.Errorf("bulk relay: %w", err))
	}
	select {
	case err := <-intEchoErr:
		if err != nil && !isClosedRelayErr(err) {
			return failedCase(opts.name, start, fmt.Errorf("interactive echo: %w", err))
		}
	default:
	}
	select {
	case err := <-bulkDrainErr:
		if err != nil && !isClosedRelayErr(err) {
			return failedCase(opts.name, start, fmt.Errorf("bulk drain: %w", err))
		}
	default:
	}
	return report.Case{Name: opts.name, Tier: "T7", Duration: time.Since(start)}
}

type tunStreamEnv struct {
	ln       rendr.Listener
	server   rendr.Conn
	app      net.Conn
	admin    rendr.AdminConn
	addr     string
	relayErr chan error
}

func startTUNStream(ctx context.Context, paths int) (*tunStreamEnv, error) {
	if paths < 2 {
		paths = 2
	}
	ln, err := rendr.ListenTCP("127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}

	accepted := make(chan rendr.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		actx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		c, err := ln.Accept(actx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- c
	}()

	id := g1Identity()
	root := g1Root(ln.Addr().String(), paths)
	manager := &l3session.Manager{}
	relay := &l3session.TCPRelay{Manager: manager}
	app, endpoint := net.Pipe()
	relayErr := make(chan error, 1)
	go func() {
		relayErr <- relay.Serve(ctx, g1Event(id, root), endpoint)
	}()

	var server rendr.Conn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		_ = app.Close()
		_ = ln.Close()
		return nil, fmt.Errorf("accept: %w", err)
	case <-time.After(15 * time.Second):
		_ = app.Close()
		_ = ln.Close()
		return nil, fmt.Errorf("accept timeout")
	}

	sess, err := waitStreamSession(ctx, manager, id)
	if err != nil {
		_ = app.Close()
		_ = server.Close()
		_ = ln.Close()
		return nil, err
	}
	admin, ok := sess.Conn.(rendr.AdminConn)
	if !ok {
		_ = app.Close()
		_ = server.Close()
		_ = ln.Close()
		return nil, fmt.Errorf("session conn is not rendr.AdminConn")
	}
	waitPaths(ctx, admin, paths)
	return &tunStreamEnv{
		ln:       ln,
		server:   server,
		app:      app,
		admin:    admin,
		addr:     ln.Addr().String(),
		relayErr: relayErr,
	}, nil
}

func (e *tunStreamEnv) close() {
	if e == nil {
		return
	}
	if e.app != nil {
		_ = e.app.Close()
	}
	if e.server != nil {
		_ = e.server.Close()
	}
	if e.ln != nil {
		_ = e.ln.Close()
	}
}

func (e *tunStreamEnv) waitRelay(timeout time.Duration) error {
	if e == nil || e.relayErr == nil {
		return nil
	}
	select {
	case err := <-e.relayErr:
		if err != nil {
			return fmt.Errorf("relay: %w", err)
		}
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("relay shutdown timeout")
	}
}

func startStreamEcho(c net.Conn, bufferSize int) <-chan error {
	errCh := make(chan error, 1)
	go func() {
		if bufferSize <= 0 {
			bufferSize = 4096
		}
		buf := make([]byte, bufferSize)
		for {
			n, err := c.Read(buf)
			if err != nil {
				errCh <- err
				return
			}
			if err := writeAll(c, buf[:n]); err != nil {
				errCh <- err
				return
			}
		}
	}()
	return errCh
}

func runTUNStreamTransfer(ctx context.Context, ln rendr.Listener, root rendr.Target, id l3ingress.L3Identity, size int64, migrations int) error {
	if size <= 0 {
		size = 8 << 20
	}
	if migrations < 0 {
		migrations = 0
	}
	manager := &l3session.Manager{}
	relay := &l3session.TCPRelay{Manager: manager, BufferSize: 64 << 10}
	app, endpoint := net.Pipe()
	defer app.Close()

	relayErr := make(chan error, 1)
	go func() {
		relayErr <- relay.Serve(ctx, g1Event(id, root), endpoint)
	}()

	server, err := acceptOneStream(ctx, ln)
	if err != nil {
		return fmt.Errorf("accept: %w", err)
	}
	defer server.Close()

	sess, err := waitStreamSession(ctx, manager, id)
	if err != nil {
		return err
	}
	admin, ok := sess.Conn.(rendr.AdminConn)
	if !ok {
		return fmt.Errorf("session conn is not rendr.AdminConn")
	}
	waitPaths(ctx, admin, 2)

	recvErr := make(chan error, 1)
	hRecv := sha256.New()
	go func() {
		buf := make([]byte, 128*1024)
		var got int64
		for got < size {
			n, err := server.Read(buf)
			if err != nil {
				recvErr <- err
				return
			}
			hRecv.Write(buf[:n])
			got += int64(n)
		}
		recvErr <- nil
	}()

	migPts := make([]int64, migrations)
	for i := 0; i < migrations; i++ {
		migPts[i] = size * int64(i+1) / int64(migrations+1)
	}
	hSent := sha256.New()
	buf := make([]byte, 128*1024)
	var written int64
	var migIdx int
	for written < size {
		end := written + int64(len(buf))
		if end > size {
			end = size
		}
		chunk := buf[:end-written]
		fillPattern(chunk, written)
		if err := writeAll(app, chunk); err != nil {
			return fmt.Errorf("write at %d: %w", written, err)
		}
		hSent.Write(chunk)
		written += int64(len(chunk))
		for migIdx < len(migPts) && written >= migPts[migIdx] {
			next := nextPath(admin)
			if next != 0 {
				if err := admin.Migrate(next); err != nil {
					return fmt.Errorf("migrate %d: %w", migIdx, err)
				}
			}
			migIdx++
		}
	}
	if err := <-recvErr; err != nil {
		return fmt.Errorf("recv: %w", err)
	}
	if sentHex, recvHex := fmt.Sprintf("%x", hSent.Sum(nil)), fmt.Sprintf("%x", hRecv.Sum(nil)); sentHex != recvHex {
		return fmt.Errorf("SHA-256 mismatch: sent=%s recv=%s", sentHex, recvHex)
	}
	if migrations > 0 && admin.MigrationCount() < uint64(migrations) {
		return fmt.Errorf("MigrationCount=%d, want >= %d", admin.MigrationCount(), migrations)
	}
	_ = app.Close()
	if err := waitRelayErr(relayErr, 5*time.Second); err != nil {
		return err
	}
	return nil
}

func t5Root(addr, transportName, prefix string, paths int) rendr.Target {
	children := make([]rendr.Target, 0, paths)
	for i := 0; i < paths; i++ {
		name := fmt.Sprintf("%s-%d", prefix, i+1)
		children = append(children, rendr.Path(name, rendr.PathSpec{
			Transport: transportName,
			Address:   addr,
			Opts:      map[string]string{"name": name},
		}))
	}
	return rendr.Selector(prefix+"-root", children)
}

func t5Identity(srcPort uint16) l3ingress.L3Identity {
	return l3ingress.L3Identity{
		Proto:   l3ingress.ProtocolTCP,
		SrcIP:   netip.MustParseAddr("10.0.0.2"),
		SrcPort: srcPort,
		DstIP:   netip.MustParseAddr("198.51.100.50"),
		DstPort: 443,
	}
}

func startStreamDrain(c net.Conn) <-chan error {
	errCh := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, c)
		errCh <- err
	}()
	return errCh
}

func startT6Flow(ctx context.Context, table *l3ingress.FlowTable, relay *l3session.TCPRelay, id l3ingress.L3Identity, endpoint net.Conn, relayErr chan<- error) error {
	decision, _, _, err := table.Resolve(ctx, l3ingress.FlowMeta{
		L3Identity: id,
		Direction:  l3ingress.DirectionIngress,
	}, 1)
	if err != nil {
		_ = endpoint.Close()
		return err
	}
	ev := l3ingress.PacketEvent{
		Meta: l3ingress.PacketMeta{Identity: id},
		Flow: l3ingress.FlowMeta{
			L3Identity: id,
			Direction:  l3ingress.DirectionIngress,
		},
		Decision: decision,
		Decided:  true,
	}
	go func() {
		relayErr <- relay.Serve(ctx, ev, endpoint)
	}()
	return nil
}

func acceptOneStream(ctx context.Context, ln rendr.Listener) (rendr.Conn, error) {
	actx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return ln.Accept(actx)
}

func t6Identity(srcPort, dstPort uint16) l3ingress.L3Identity {
	return l3ingress.L3Identity{
		Proto:   l3ingress.ProtocolTCP,
		SrcIP:   netip.MustParseAddr("10.0.0.2"),
		SrcPort: srcPort,
		DstIP:   netip.MustParseAddr("198.51.100.60"),
		DstPort: dstPort,
	}
}

func t6SelectorRoot(addr, prefix string) rendr.Target {
	spec := func(name string) rendr.PathSpec {
		return rendr.PathSpec{
			Transport: "tcp",
			Address:   addr,
			Opts:      map[string]string{"name": name},
		}
	}
	bulk := rendr.Bond(prefix+"-bulk", []rendr.Target{
		rendr.Path(prefix+"-B", spec(prefix+"-B")),
		rendr.Path(prefix+"-C", spec(prefix+"-C")),
	})
	return rendr.Selector(prefix+"-root", []rendr.Target{
		rendr.Path(prefix+"-A", spec(prefix+"-A")),
		bulk,
	}, rendr.PeakTransfer{
		Targets:         []string{prefix + "-bulk"},
		SaturationFor:   200 * time.Millisecond,
		ReturnFor:       2 * time.Second,
		SaturationRatio: 0.8,
		ReturnRatio:     0.2,
	})
}

func idsByPathName(paths []rendr.PathInfo) map[string]uint32 {
	out := make(map[string]uint32, len(paths))
	for _, p := range paths {
		if name := pathInfoName(p); name != "" {
			out[name] = p.ID
		}
	}
	return out
}

func writesByPathName(paths []rendr.PathInfo) map[string]uint64 {
	out := make(map[string]uint64, len(paths))
	for _, p := range paths {
		if name := pathInfoName(p); name != "" {
			out[name] = p.Writes
		}
	}
	return out
}

func pathInfoName(p rendr.PathInfo) string {
	if p.Spec.Opts == nil {
		return ""
	}
	return p.Spec.Opts["name"]
}

func waitForAdminMode(admin rendr.AdminConn, want rendr.Mode, within time.Duration) error {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if admin.Mode() == want {
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("mode=%v want %v", admin.Mode(), want)
}

func waitRelayErr(ch <-chan error, timeout time.Duration) error {
	select {
	case err := <-ch:
		if err != nil && !isClosedRelayErr(err) {
			return err
		}
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("relay shutdown timeout")
	}
}

func runG3Smoke(ctx context.Context, opts g3Options) report.Case {
	start := time.Now()
	if opts.name == "" {
		opts.name = caseG3Smoke
	}
	if opts.duration <= 0 {
		opts.duration = 5 * time.Second
	}
	if opts.pps <= 0 {
		opts.pps = 5000
	}
	if opts.payloadLen == 0 {
		opts.payloadLen = 1024
	}
	if opts.paths < 1 {
		opts.paths = 4
	}
	if opts.migrations == 0 {
		opts.migrations = 3
	}
	if opts.lossPct < 0 {
		return invalidTUNG3Case(opts.name, start, fmt.Sprintf("loss budget %.3f%% must be >=0", opts.lossPct), nil)
	}
	if opts.p95Ceiling <= 0 {
		opts.p95Ceiling = 50 * time.Millisecond
	}
	if opts.migrations < 1 {
		return invalidTUNG3Case(opts.name, start, "migration stimulus must request at least one transition", nil)
	}
	if opts.paths < 2 {
		return invalidTUNG3Case(opts.name, start, fmt.Sprintf("paths=%d, want >=2 for migration evidence", opts.paths), nil)
	}
	if opts.payloadLen < 24 {
		return invalidTUNG3Case(opts.name, start,
			fmt.Sprintf("payload length=%d, want >=24 for sequence, timestamp, and integrity marker", opts.payloadLen), nil)
	}
	targetPacketsFloat := float64(opts.pps) * opts.duration.Seconds()
	if targetPacketsFloat < 1 || targetPacketsFloat > tunG3MaximumPackets {
		return invalidTUNG3Case(opts.name, start,
			fmt.Sprintf("target packet count %.0f outside [1,%d]", targetPacketsFloat, tunG3MaximumPackets), nil)
	}
	packetInterval := time.Second / time.Duration(opts.pps)
	if packetInterval <= 0 {
		return invalidTUNG3Case(opts.name, start, fmt.Sprintf("target pps=%d produces a zero pacing interval", opts.pps), nil)
	}

	ln, err := rendr.ListenQUICDatagram("127.0.0.1:0", nil)
	if err != nil {
		return failedCase(opts.name, start, fmt.Errorf("ListenQUICDatagram: %w", err))
	}
	defer ln.Close()

	accepted := make(chan rendr.PacketConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		actx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		pc, err := ln.AcceptPacket(actx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- pc
	}()

	id := l3ingress.L3Identity{
		Proto:   l3ingress.ProtocolUDP,
		SrcIP:   netip.MustParseAddr("10.0.0.2"),
		SrcPort: 40000,
		DstIP:   netip.MustParseAddr("198.51.100.53"),
		DstPort: 53,
	}
	root := g3Root(ln.Addr().String(), opts.paths)
	manager := &l3session.Manager{
		Starter: l3session.Starter{Options: []l3session.DialerOption{
			func(_ l3ingress.SessionRequest, d *rendr.Dialer) error {
				d.BondStuckRTTMultiplier = 1_000_000
				return nil
			},
		}},
	}
	dev := &captureDevice{}
	relay := &l3session.UDPRelay{Device: dev, Manager: manager, BufferSize: opts.payloadLen + 64}
	defer relay.Close()

	payload := make([]byte, opts.payloadLen)
	binary.BigEndian.PutUint64(payload[:8], ^uint64(0))
	binary.BigEndian.PutUint64(payload[len(payload)-8:], ^uint64(0)^tunG3PacketIntegrityMask)
	packet, meta, err := udpPacketEventParts(id, payload)
	if err != nil {
		return failedCase(opts.name, start, err)
	}
	event := l3ingress.PacketEvent{
		Packet: packet,
		Meta:   meta,
		Flow:   l3ingress.FlowMeta{L3Identity: id, Direction: l3ingress.DirectionIngress},
		Decision: l3ingress.FlowDecision{
			Peer:   "peer-a",
			Root:   root,
			Egress: "direct",
		},
		Decided: true,
	}
	if err := relay.HandlePacket(ctx, l3ingress.PacketEvent{
		Packet: event.Packet,
		Meta:   event.Meta,
		Flow:   event.Flow,
		Decision: l3ingress.FlowDecision{
			Peer:   event.Decision.Peer,
			Root:   event.Decision.Root,
			Egress: event.Decision.Egress,
		},
		Decided: event.Decided,
	}); err != nil {
		return failedCase(opts.name, start, fmt.Errorf("start relay: %w", err))
	}

	var server rendr.PacketConn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		return failedCase(opts.name, start, fmt.Errorf("accept: %w", err))
	case <-time.After(15 * time.Second):
		return failedCase(opts.name, start, fmt.Errorf("accept timeout"))
	}
	defer server.Close()

	sess, ok := manager.Session(id)
	if !ok || sess.PacketConn == nil {
		return failedCase(opts.name, start, fmt.Errorf("missing packet session"))
	}
	admin, ok := sess.PacketConn.(rendr.AdminPacketConn)
	if !ok {
		return failedCase(opts.name, start, fmt.Errorf("session packet conn is not rendr.AdminPacketConn"))
	}
	waitPacketPaths(ctx, admin, opts.paths)
	if serverAdmin, ok := server.(rendr.AdminPacketConn); ok {
		waitPacketPaths(ctx, serverAdmin, opts.paths)
	}

	peerPacketConn := newTunG3PeerPacketConn()
	peerEgress := &tunG3PeerEgress{conn: peerPacketConn}
	egresses := l3ingress.NewEgressRegistry()
	if err := egresses.Register("direct", peerEgress); err != nil {
		return failedCase(opts.name, start, fmt.Errorf("register peer egress: %w", err))
	}
	peerCtx, peerCancel := context.WithCancel(ctx)
	defer peerCancel()
	peerErr := make(chan error, 1)
	go func() {
		peerErr <- (&l3session.UDPPeerRelay{
			PacketConn: server,
			Egresses:   egresses,
			BufferSize: opts.payloadLen + 128,
		}).Run(peerCtx)
	}()

	// The first packet creates the L3 session. Consume it before taking
	// counters so bootstrap traffic cannot masquerade as measured load. The
	// packet must traverse the production peer envelope decoder and egress
	// registry before it reaches this fixture-owned observer.
	var bootstrap []byte
	select {
	case bootstrap = <-peerPacketConn.bootstrap:
	case err := <-peerErr:
		if err == nil {
			err = errors.New("peer relay stopped before bootstrap")
		}
		return failedCase(opts.name, start, fmt.Errorf("peer relay before bootstrap: %w", err))
	case <-time.After(5 * time.Second):
		return failedCase(opts.name, start, fmt.Errorf("peer egress bootstrap timeout"))
	}
	if len(bootstrap) != opts.payloadLen || binary.BigEndian.Uint64(bootstrap[:8]) != ^uint64(0) ||
		binary.BigEndian.Uint64(bootstrap[len(bootstrap)-8:]) != ^uint64(0)^tunG3PacketIntegrityMask {
		return invalidTUNG3Case(opts.name, start,
			fmt.Sprintf("peer egress bootstrap mismatch: bytes=%d sequence=%d", len(bootstrap), binary.BigEndian.Uint64(bootstrap[:8])), nil)
	}
	peerDials, peerIdentity := peerEgress.snapshot()
	if peerDials != 1 || peerIdentity != id || peerPacketConn.bootstrapCount.Load() != 1 {
		return invalidTUNG3Case(opts.name, start,
			fmt.Sprintf("peer egress dispatch evidence mismatch: dials=%d bootstrap=%d identity=%s want=%s",
				peerDials, peerPacketConn.bootstrapCount.Load(), peerIdentity, id), nil)
	}

	pathsBefore := admin.Stats().Paths
	if len(pathsBefore) != opts.paths {
		return invalidTUNG3Case(opts.name, start,
			fmt.Sprintf("path attach evidence=%d, want exactly %d", len(pathsBefore), opts.paths), nil)
	}
	pathWritesBefore := make(map[uint32]uint64, len(pathsBefore))
	for _, path := range pathsBefore {
		pathWritesBefore[path.ID] = path.Writes
	}

	expected := int(math.Ceil(targetPacketsFloat*1.25)) + 1
	sendEpoch := time.Now()
	collector := newTunG3Collector(expected, opts.payloadLen, sendEpoch)
	peerPacketConn.setObserver(collector.observe)

	startMig := admin.MigrationCount()
	targetPackets := int64(math.Ceil(targetPacketsFloat))
	migrationAttempts := 0
	migrationErrors := 0
	nextMigration := 1
	sendStarted := time.Now()
	nextTick := sendStarted
	endAt := sendStarted.Add(opts.duration)
	payloadOffset := meta.PayloadOffset + 8
	var sent int64
	writeFailure := ""
	for time.Now().Before(endAt) {
		if err := ctx.Err(); err != nil {
			writeFailure = "sender context: " + err.Error()
			break
		}
		for nextMigration <= opts.migrations && sent >= targetPackets*int64(nextMigration)/int64(opts.migrations+1) {
			migrationAttempts++
			next := nextPacketPath(admin)
			if next == 0 {
				migrationErrors++
			} else if err := admin.Migrate(next); err != nil {
				migrationErrors++
			}
			nextMigration++
		}
		paceUntil(nextTick)
		if !time.Now().Before(endAt) {
			break
		}
		nextTick = nextTick.Add(packetInterval)
		binary.BigEndian.PutUint64(payload[:8], uint64(sent))
		binary.BigEndian.PutUint64(payload[8:16], uint64(time.Since(sendEpoch)))
		binary.BigEndian.PutUint64(payload[len(payload)-8:], uint64(sent)^tunG3PacketIntegrityMask)
		copy(packet[payloadOffset:payloadOffset+len(payload)], payload)
		if err := relay.HandlePacket(ctx, event); err != nil {
			writeFailure = fmt.Sprintf("send seq %d: %v", sent, err)
			break
		}
		sent++
	}
	sendElapsed := time.Since(sendStarted)
	drainDeadline := time.Now().Add(5 * time.Second)
	for collector.deliveredPackets() < sent && time.Now().Before(drainDeadline) {
		time.Sleep(time.Millisecond)
	}
	relay.CloseFlow(id)
	peerCancel()
	peerRunErr := waitRelayErr(peerErr, 5*time.Second)
	receivedOutcome := collector.snapshot()

	sort.Slice(receivedOutcome.latencies, func(i, j int) bool {
		return receivedOutcome.latencies[i] < receivedOutcome.latencies[j]
	})
	p95 := percentile(receivedOutcome.latencies, 0.95)
	migrations := admin.MigrationCount() - startMig
	perPathWrites := make(map[uint32]uint64, len(pathWritesBefore))
	var wireWrites uint64
	for _, path := range admin.Stats().Paths {
		before, expectedPath := pathWritesBefore[path.ID]
		if !expectedPath || path.Writes < before {
			continue
		}
		delta := path.Writes - before
		perPathWrites[path.ID] = delta
		wireWrites += delta
	}
	for pathID := range pathWritesBefore {
		if _, ok := perPathWrites[pathID]; !ok {
			perPathWrites[pathID] = 0
		}
	}
	received := receivedOutcome.uniquePackets
	lossPct := math.NaN()
	if sent > 0 {
		lossPct = float64(sent-received) / float64(sent) * 100
	}
	offeredPPS := float64(0)
	if sendElapsed > 0 {
		offeredPPS = float64(sent) / sendElapsed.Seconds()
	}
	rc := report.Case{
		Name:     opts.name,
		Tier:     "T7",
		Duration: time.Since(start),
		Evidence: map[string]string{
			"target_pps":           fmt.Sprintf("%d", opts.pps),
			"offered_pps":          fmt.Sprintf("%.3f", offeredPPS),
			"offered_ratio":        fmt.Sprintf("%.6f", offeredPPS/float64(opts.pps)),
			"send_elapsed":         sendElapsed.String(),
			"sent":                 fmt.Sprintf("%d", sent),
			"received":             fmt.Sprintf("%d", received),
			"loss_pct":             fmt.Sprintf("%.6f", lossPct),
			"loss_budget_pct":      fmt.Sprintf("%.6f", opts.lossPct),
			"latency_samples":      fmt.Sprintf("%d", len(receivedOutcome.latencies)),
			"p95":                  p95.String(),
			"migration_attempts":   fmt.Sprintf("%d", migrationAttempts),
			"migration_errors":     fmt.Sprintf("%d", migrationErrors),
			"migrations_observed":  fmt.Sprintf("%d", migrations),
			"malformed_packets":    fmt.Sprintf("%d", receivedOutcome.malformedPackets),
			"corrupt_packets":      fmt.Sprintf("%d", receivedOutcome.corruptPackets),
			"duplicate_packets":    fmt.Sprintf("%d", receivedOutcome.duplicatePackets),
			"out_of_range_packets": fmt.Sprintf("%d", receivedOutcome.outOfRangePackets),
			"per_path_wire_writes": formatTUNG3PathWrites(perPathWrites),
			"wire_writes":          fmt.Sprintf("%d", wireWrites),
			"peer_egress":          "direct",
			"peer_egress_dials":    fmt.Sprintf("%d", peerDials),
			"peer_egress_packets":  fmt.Sprintf("%d", collector.processedPackets()),
			"peer_identity_match":  fmt.Sprintf("%t", peerIdentity == id),
			"g3_semantics":         "synthetic_l3session_quic_datagram_not_rfc9000_cid_gold",
		},
	}
	if writeFailure != "" {
		rc.Failure = writeFailure
		return rc
	}
	if receivedOutcome.err != nil {
		rc.Failure = "receiver: " + receivedOutcome.err.Error()
		return rc
	}
	if peerRunErr != nil {
		rc.Failure = "peer relay: " + peerRunErr.Error()
		return rc
	}
	rc.InvalidReason, rc.Failure = validateTUNG3Measurements(opts, tunG3Measurements{
		sent:               sent,
		received:           received,
		sendElapsed:        sendElapsed,
		latencySamples:     len(receivedOutcome.latencies),
		p95:                p95,
		migrationAttempts:  migrationAttempts,
		migrationErrors:    migrationErrors,
		migrationsObserved: migrations,
		malformedPackets:   receivedOutcome.malformedPackets,
		corruptPackets:     receivedOutcome.corruptPackets,
		duplicatePackets:   receivedOutcome.duplicatePackets,
		outOfRangePackets:  receivedOutcome.outOfRangePackets,
		perPathWrites:      perPathWrites,
		wireWrites:         wireWrites,
	})
	return rc
}

func invalidTUNG3Case(name string, started time.Time, reason string, evidence map[string]string) report.Case {
	return report.Case{Name: name, Tier: "T7", Duration: time.Since(started), InvalidReason: reason, Evidence: evidence}
}

func isNetTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func g3Root(addr string, paths int) rendr.Target {
	children := make([]rendr.Target, 0, paths)
	for i := 0; i < paths; i++ {
		children = append(children, rendr.Path(fmt.Sprintf("tun-g3-%d", i+1), rendr.PathSpec{
			Transport: "quic",
			Address:   addr,
			Opts:      map[string]string{"mode": "datagram"},
		}))
	}
	return rendr.Bond("tun-full-g3", children)
}

func udpPacketEventParts(id l3ingress.L3Identity, payload []byte) ([]byte, l3ingress.PacketMeta, error) {
	packet, err := l3ingress.BuildUDPPacket(id, payload)
	if err != nil {
		return nil, l3ingress.PacketMeta{}, fmt.Errorf("build UDP packet: %w", err)
	}
	meta, err := l3ingress.ParsePacket(packet)
	if err != nil {
		return nil, l3ingress.PacketMeta{}, fmt.Errorf("parse UDP packet: %w", err)
	}
	return packet, meta, nil
}

func waitPacketPaths(ctx context.Context, admin rendr.AdminPacketConn, want int) {
	deadline := time.After(5 * time.Second)
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for len(admin.Paths()) < want {
		select {
		case <-ctx.Done():
			return
		case <-deadline:
			return
		case <-tick.C:
		}
	}
}

func nextPacketPath(admin rendr.AdminPacketConn) uint32 {
	cur := admin.ActivePath()
	for _, p := range admin.Paths() {
		if p.ID != cur {
			return p.ID
		}
	}
	return 0
}

func startPacketEcho(pc rendr.PacketConn, bufferSize int) <-chan error {
	errCh := make(chan error, 1)
	go func() {
		if bufferSize <= 0 {
			bufferSize = 2048
		}
		buf := make([]byte, bufferSize)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				errCh <- err
				return
			}
			if _, err := pc.WriteTo(buf[:n], addr); err != nil {
				errCh <- err
				return
			}
		}
	}()
	return errCh
}

type captureDevice struct {
	writes  chan []byte
	onWrite func([]byte)
}

func (d *captureDevice) Read([]byte) (int, error) { return 0, io.EOF }
func (d *captureDevice) Write(p []byte) (int, error) {
	if d.onWrite != nil {
		d.onWrite(p)
		return len(p), nil
	}
	if d.writes != nil {
		d.writes <- append([]byte(nil), p...)
	}
	return len(p), nil
}
func (d *captureDevice) Close() error { return nil }
func (d *captureDevice) Name() string { return "tun-full-capture0" }
func (d *captureDevice) MTU() int     { return 1500 }

func paceUntil(target time.Time) {
	for {
		now := time.Now()
		if !now.Before(target) {
			return
		}
		remaining := target.Sub(now)
		switch {
		case remaining > 250*time.Microsecond:
			time.Sleep(remaining - 100*time.Microsecond)
		case remaining > 50*time.Microsecond:
			runtime.Gosched()
		default:
		}
	}
}
