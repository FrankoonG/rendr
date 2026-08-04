// Package tier7 implements TUN ingress / L3 identity regression gates.
package tier7

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/caseexec"
	"github.com/FrankoonG/rendr/regress/internal/gotestjson"
	"github.com/FrankoonG/rendr/regress/internal/manifest"
	"github.com/FrankoonG/rendr/regress/internal/report"
)

// Options filters the tier7 TUN/l3ingress matrix.
type Options struct {
	Case     string
	FromCase string
}

type caseDef struct {
	spec     manifest.Spec
	pkg      string
	expected []string
}

var caseDefs = []caseDef{
	{mustCaseSpec("T7.capability.local-probe", 30*time.Second), "./tun", []string{"TestProbeReturnsMachineReadableCapability"}},
	{mustCaseSpec("T7.tun.open-smoke", 30*time.Second), "./tun", []string{"TestOpenCreatesEphemeralDeviceWhenAvailable"}},
	{mustCaseSpec("T7.tun.packet-io", 30*time.Second), "./tun", []string{"TestDeviceReadsKernelRoutedIPv4Packet"}},
	{mustCaseSpec("T7.config.invalid-mtu", 30*time.Second), "./tun", []string{"TestConfigValidateRejectsSmallMTU"}},
	{mustCaseSpec("T7.l3.identity-smoke", 30*time.Second), "./l3ingress", []string{"TestParseIPv4TCPIdentity", "TestParseIPv6UDPIdentity"}},
	{mustCaseSpec("T7.l3.identity-wire", 30*time.Second), "./l3ingress", []string{"TestIdentityWireRoundTripIPv4", "TestIdentityWireRoundTripIPv6", "TestIdentityWireRejectsMixedFamilies"}},
	{mustCaseSpec("T7.capability.peer-denied", 30*time.Second), "./l3ingress", []string{"TestRequirePeerL3Identity", "TestRequirePeerEgress"}},
	{mustCaseSpec("T7.capability.peer-advertise", 30*time.Second), ".", []string{"TestDialerAdvertisesL3IdentityCapability", "TestDialPacketAdvertisesL3IdentityAndPacketMode"}},
	{mustCaseSpec("T7.router.per-flow-hook", 30*time.Second), "./l3ingress", []string{"TestPumpRoutesParsedPackets"}},
	{mustCaseSpec("T7.router.per-flow-cache", 30*time.Second), "./l3ingress", []string{"TestPumpCachesRouterDecisionPerFlow"}},
	{mustCaseSpec("T7.session.request", 30*time.Second), "./l3ingress", []string{"TestBuildSessionRequestMapsTCPAndUDP", "TestBuildSessionRequestRejectsInvalidDecisions", "TestBuildSessionRequestRejectsIdentityMismatch"}},
	{mustCaseSpec("T7.session.start", 30*time.Second), "./l3session", []string{"TestStarterStreamSessionPreservesL3Capability", "TestStarterPacketSessionPreservesL3Capability", "TestStarterRejectsUnsupportedRequest"}},
	{mustCaseSpec("T7.session.manager", 30*time.Second), "./l3session", []string{"TestManagerStartsOneSessionPerFlow", "TestManagerPropagatesPlanningErrors"}},
	{mustCaseSpec("T7.session.lifecycle", 30*time.Second), "./l3session", []string{"TestManagerClosesSessionOnFlowClose"}},
	{mustCaseSpec("T7.session.path-observe", 30*time.Second), "./l3session", []string{"TestManagerRecordsSessionPathSelectionAndMigrations"}},
	{mustCaseSpec("T7.router.flow-deny", 30*time.Second), "./l3ingress", []string{"TestFlowTableCachesDeniedDecision", "TestPumpSkipsDeniedFlow"}},
	{mustCaseSpec("T7.flow.lifecycle-stats", 30*time.Second), "./l3ingress", []string{"TestFlowTableCachesDecisionAndStats", "TestFlowTableCloseSnapshot", "TestPumpUsesProvidedFlowTable"}},
	{mustCaseSpec("T7.flow.observe", 30*time.Second), "./l3ingress", []string{"TestFlowTableObserverReceivesLifecycleSnapshots", "TestFlowTableRecordsPathSelectionAndMigrations"}},
	{mustCaseSpec("T7.selector.per-flow", 30*time.Second), "./l3ingress", []string{"TestFlowTableTracksIndependentSelectorFlows"}},
	{mustCaseSpec("T7.peer-egress-hook", 30*time.Second), "./l3ingress", []string{"TestEgressRegistryDispatchesIdentity", "TestEgressRegistryMachineReadableErrors"}},
	{mustCaseSpec("T7.tcp.peer-egress", 30*time.Second), "./l3ingress", []string{"TestTCPFlowRelayDispatchesIdentityAndBridgesStream", "TestTCPFlowRelayCloseFlowAllowsReopen"}},
	{mustCaseSpec("T7.udp.identity-smoke", 30*time.Second), "./l3ingress", []string{"TestUDPPayloadExtractsData", "TestBuildUDPPacketRoundTripIPv4", "TestBuildUDPPacketRoundTripIPv6", "TestUDPFlowRelayDispatchesPayloadAndWritesReply", "TestUDPFlowRelayCloseFlowAllowsReopen"}},
	{mustCaseSpec("T7.udp.rendr-relay", 30*time.Second), "./l3session", []string{"TestUDPRelayForwardsPayloadThroughRendrPacketSession"}},
	{mustCaseSpec("T7.udp.migration", 30*time.Second), "./l3session", []string{"TestUDPRelayPreservesFlowAcrossPacketMigration"}},
	{mustCaseSpec("T7.tcp.rendr-relay", 30*time.Second), "./l3session", []string{"TestTCPRelayBridgesEndpointThroughRendrStreamSession"}},
	{mustCaseSpec("T7.tcp.migration", 30*time.Second), "./l3session", []string{"TestTCPRelayPreservesFlowAcrossStreamMigration"}},
	{mustCaseSpec("T7.tcp.lifecycle-flags", 30*time.Second), "./l3ingress", []string{"TestParseTCPCloseFlags", "TestPumpClosesFlowTableOnTCPReset"}},
	{mustCaseSpec("T7.l3.parse-error-skip", 30*time.Second), "./l3ingress", []string{"TestPumpSkipsParseErrors"}},
	{mustCaseSpec("T7.l3.fragment-boundary", 30*time.Second), "./l3ingress", []string{"TestParseIPv4UDPMoreFragmentFirstFragment", "TestParseRejectsIPv4NonInitialFragment"}},
	{mustCaseSpec("T7.l3.unsupported-protocol", 30*time.Second), "./l3ingress", []string{"TestParseRejectsUnsupportedProtocol", "TestParseRejectsShortPacket"}},
}

// Specs returns the ordered T7 case manifest.
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

func Run(ctx context.Context, suite *report.Suite, rendrRoot string, opts Options) {
	defs, err := selectCaseDefs(opts)
	if err != nil {
		failure := fmt.Sprintf("no T7 case matched case=%q from-case=%q", opts.Case, opts.FromCase)
		if opts.FromCase == "" {
			failure = fmt.Sprintf("no T7 case matched %q", opts.Case)
		}
		suite.Add(report.Case{Name: "T7-case-filter", Tier: "T7", Failure: failure})
		return
	}
	runCaseDefs(ctx, suite, rendrRoot, defs, func(ctx context.Context, rendrRoot string, def caseDef) caseexec.Outcome {
		return runCase(ctx, def.spec.ID, def.spec.Budget, func(c context.Context) report.Case {
			return runGoTests(c, rendrRoot, def)
		})
	})
}

type caseExecutor func(context.Context, string, caseDef) caseexec.Outcome

func runCaseDefs(ctx context.Context, suite *report.Suite, rendrRoot string, defs []caseDef, execute caseExecutor) {
	failedCaseID := ""
	for _, def := range defs {
		if failedCaseID != "" {
			suite.Add(notRunCase(def.spec, failedCaseID))
			continue
		}
		outcome := execute(ctx, rendrRoot, def)
		rc := outcome.Case
		suite.Add(rc)
		if outcome.MustStop || mandatoryCaseFailed(def.spec, rc) {
			failedCaseID = def.spec.ID
		}
	}
}

func runCase(ctx context.Context, name string, budget time.Duration, fn func(context.Context) report.Case) caseexec.Outcome {
	fmt.Printf("  > T7/%s (budget %s) - start\n", name, budget)
	outcome := caseexec.Run(ctx, caseexec.Config{
		Name:        name,
		Tier:        "T7",
		Budget:      budget,
		JoinTimeout: caseexec.DefaultJoinTimeout,
	}, fn)
	rc := outcome.Case
	if rc.InvalidReason != "" {
		fmt.Printf("  > T7/%s (took %s) - INVALID: %s\n", name, rc.Duration, rc.InvalidReason)
	} else if rc.Failure != "" {
		fmt.Printf("  > T7/%s (took %s) - FAIL: %s\n", name, rc.Duration, rc.Failure)
	} else if rc.SkipReason != "" {
		fmt.Printf("  > T7/%s - SKIP: %s\n", name, rc.SkipReason)
	} else {
		fmt.Printf("  > T7/%s (took %s) - OK\n", name, rc.Duration)
	}
	return outcome
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

func runGoTests(ctx context.Context, rendrRoot string, def caseDef) report.Case {
	if _, err := os.Stat(rendrRoot); err != nil {
		return report.Case{Name: def.spec.ID, Tier: "T7", InvalidReason: "bad rendr root: " + err.Error()}
	}
	result, err := tier7GoTestExecutor.Run(ctx, gotestjson.Request{
		Dir:      rendrRoot,
		Package:  def.pkg,
		Pattern:  exactTestPattern(def.expected),
		Expected: testExpectations(def.expected),
		Env:      []string{"GOCACHE=" + filepath.Join(os.TempDir(), "go-build-rendr-t7")},
	})
	if err != nil && result.Passed() {
		result.Issues = append(result.Issues, gotestjson.Issue{Code: gotestjson.IssueCommandFailed, Detail: err.Error()})
	}
	return goTestReportCase(def.spec.ID, "T7", def.expected, result)
}
