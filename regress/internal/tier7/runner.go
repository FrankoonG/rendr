// Package tier7 implements TUN ingress / L3 identity regression gates.
package tier7

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

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
	{manifest.RequiredWithBudget("T7.capability.local-probe", "T7", 30*time.Second), "./tun", []string{"TestProbeReturnsMachineReadableCapability"}},
	{manifest.RequiredWithBudget("T7.tun.open-smoke", "T7", 30*time.Second), "./tun", []string{"TestOpenCreatesEphemeralDeviceWhenAvailable"}},
	{manifest.RequiredWithBudget("T7.tun.packet-io", "T7", 30*time.Second), "./tun", []string{"TestDeviceReadsKernelRoutedIPv4Packet"}},
	{manifest.RequiredWithBudget("T7.config.invalid-mtu", "T7", 30*time.Second), "./tun", []string{"TestConfigValidateRejectsSmallMTU"}},
	{manifest.RequiredWithBudget("T7.l3.identity-smoke", "T7", 30*time.Second), "./l3ingress", []string{"TestParseIPv4TCPIdentity", "TestParseIPv6UDPIdentity"}},
	{manifest.RequiredWithBudget("T7.l3.identity-wire", "T7", 30*time.Second), "./l3ingress", []string{"TestIdentityWireRoundTripIPv4", "TestIdentityWireRoundTripIPv6", "TestIdentityWireRejectsMixedFamilies"}},
	{manifest.RequiredWithBudget("T7.capability.peer-denied", "T7", 30*time.Second), "./l3ingress", []string{"TestRequirePeerL3Identity", "TestRequirePeerEgress"}},
	{manifest.RequiredWithBudget("T7.capability.peer-advertise", "T7", 30*time.Second), ".", []string{"TestDialerAdvertisesL3IdentityCapability", "TestDialPacketAdvertisesL3IdentityAndPacketMode"}},
	{manifest.RequiredWithBudget("T7.router.per-flow-hook", "T7", 30*time.Second), "./l3ingress", []string{"TestPumpRoutesParsedPackets"}},
	{manifest.RequiredWithBudget("T7.router.per-flow-cache", "T7", 30*time.Second), "./l3ingress", []string{"TestPumpCachesRouterDecisionPerFlow"}},
	{manifest.RequiredWithBudget("T7.session.request", "T7", 30*time.Second), "./l3ingress", []string{"TestBuildSessionRequestMapsTCPAndUDP", "TestBuildSessionRequestRejectsInvalidDecisions", "TestBuildSessionRequestRejectsIdentityMismatch"}},
	{manifest.RequiredWithBudget("T7.session.start", "T7", 30*time.Second), "./l3session", []string{"TestStarterStreamSessionPreservesL3Capability", "TestStarterPacketSessionPreservesL3Capability", "TestStarterRejectsUnsupportedRequest"}},
	{manifest.RequiredWithBudget("T7.session.manager", "T7", 30*time.Second), "./l3session", []string{"TestManagerStartsOneSessionPerFlow", "TestManagerPropagatesPlanningErrors"}},
	{manifest.RequiredWithBudget("T7.session.lifecycle", "T7", 30*time.Second), "./l3session", []string{"TestManagerClosesSessionOnFlowClose"}},
	{manifest.RequiredWithBudget("T7.session.path-observe", "T7", 30*time.Second), "./l3session", []string{"TestManagerRecordsSessionPathSelectionAndMigrations"}},
	{manifest.RequiredWithBudget("T7.router.flow-deny", "T7", 30*time.Second), "./l3ingress", []string{"TestFlowTableCachesDeniedDecision", "TestPumpSkipsDeniedFlow"}},
	{manifest.RequiredWithBudget("T7.flow.lifecycle-stats", "T7", 30*time.Second), "./l3ingress", []string{"TestFlowTableCachesDecisionAndStats", "TestFlowTableCloseSnapshot", "TestPumpUsesProvidedFlowTable"}},
	{manifest.RequiredWithBudget("T7.flow.observe", "T7", 30*time.Second), "./l3ingress", []string{"TestFlowTableObserverReceivesLifecycleSnapshots", "TestFlowTableRecordsPathSelectionAndMigrations"}},
	{manifest.RequiredWithBudget("T7.selector.per-flow", "T7", 30*time.Second), "./l3ingress", []string{"TestFlowTableTracksIndependentSelectorFlows"}},
	{manifest.RequiredWithBudget("T7.peer-egress-hook", "T7", 30*time.Second), "./l3ingress", []string{"TestEgressRegistryDispatchesIdentity", "TestEgressRegistryMachineReadableErrors"}},
	{manifest.RequiredWithBudget("T7.tcp.peer-egress", "T7", 30*time.Second), "./l3ingress", []string{"TestTCPFlowRelayDispatchesIdentityAndBridgesStream", "TestTCPFlowRelayCloseFlowAllowsReopen"}},
	{manifest.RequiredWithBudget("T7.udp.identity-smoke", "T7", 30*time.Second), "./l3ingress", []string{"TestUDPPayloadExtractsData", "TestBuildUDPPacketRoundTripIPv4", "TestBuildUDPPacketRoundTripIPv6", "TestUDPFlowRelayDispatchesPayloadAndWritesReply", "TestUDPFlowRelayCloseFlowAllowsReopen"}},
	{manifest.RequiredWithBudget("T7.udp.rendr-relay", "T7", 30*time.Second), "./l3session", []string{"TestUDPRelayForwardsPayloadThroughRendrPacketSession"}},
	{manifest.RequiredWithBudget("T7.udp.migration", "T7", 30*time.Second), "./l3session", []string{"TestUDPRelayPreservesFlowAcrossPacketMigration"}},
	{manifest.RequiredWithBudget("T7.tcp.rendr-relay", "T7", 30*time.Second), "./l3session", []string{"TestTCPRelayBridgesEndpointThroughRendrStreamSession"}},
	{manifest.RequiredWithBudget("T7.tcp.migration", "T7", 30*time.Second), "./l3session", []string{"TestTCPRelayPreservesFlowAcrossStreamMigration"}},
	{manifest.RequiredWithBudget("T7.tcp.lifecycle-flags", "T7", 30*time.Second), "./l3ingress", []string{"TestParseTCPCloseFlags", "TestPumpClosesFlowTableOnTCPReset"}},
	{manifest.RequiredWithBudget("T7.l3.parse-error-skip", "T7", 30*time.Second), "./l3ingress", []string{"TestPumpSkipsParseErrors"}},
	{manifest.RequiredWithBudget("T7.l3.fragment-boundary", "T7", 30*time.Second), "./l3ingress", []string{"TestParseIPv4UDPMoreFragmentFirstFragment", "TestParseRejectsIPv4NonInitialFragment"}},
	{manifest.RequiredWithBudget("T7.l3.unsupported-protocol", "T7", 30*time.Second), "./l3ingress", []string{"TestParseRejectsUnsupportedProtocol", "TestParseRejectsShortPacket"}},
}

// Specs returns the ordered T7 case manifest.
func Specs() []manifest.Spec {
	specs := make([]manifest.Spec, len(caseDefs))
	for i, def := range caseDefs {
		specs[i] = def.spec
	}
	return specs
}

func selectCaseDefs(opts Options) ([]caseDef, error) {
	selected, err := manifest.Select(Specs(), opts.Case, opts.FromCase)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]caseDef, len(caseDefs))
	for _, def := range caseDefs {
		byID[def.spec.ID] = def
	}
	defs := make([]caseDef, 0, len(selected))
	for _, spec := range selected {
		defs = append(defs, byID[spec.ID])
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
	for _, def := range defs {
		def := def
		runCase(ctx, suite, def.spec.ID, def.spec.Budget, func(c context.Context) report.Case {
			return runGoTests(c, rendrRoot, def)
		})
	}
}

func runCase(ctx context.Context, suite *report.Suite, name string, budget time.Duration, fn func(context.Context) report.Case) {
	fmt.Printf("  > T7/%s (budget %s) - start\n", name, budget)
	cctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	start := time.Now()
	done := make(chan report.Case, 1)
	go func() { done <- fn(cctx) }()
	var rc report.Case
	select {
	case rc = <-done:
		if rc.Duration == 0 {
			rc.Duration = time.Since(start)
		}
	case <-cctx.Done():
		rc = report.Case{
			Name:     name,
			Tier:     "T7",
			Duration: time.Since(start),
			Failure:  "case exceeded T7 budget: " + cctx.Err().Error(),
		}
	}
	if rc.InvalidReason != "" {
		fmt.Printf("  > T7/%s (took %s) - INVALID: %s\n", name, rc.Duration, rc.InvalidReason)
	} else if rc.Failure != "" {
		fmt.Printf("  > T7/%s (took %s) - FAIL: %s\n", name, rc.Duration, rc.Failure)
	} else if rc.SkipReason != "" {
		fmt.Printf("  > T7/%s - SKIP: %s\n", name, rc.SkipReason)
	} else {
		fmt.Printf("  > T7/%s (took %s) - OK\n", name, rc.Duration)
	}
	suite.Add(rc)
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
