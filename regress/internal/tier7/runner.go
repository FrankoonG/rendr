// Package tier7 implements TUN ingress / L3 identity regression gates.
package tier7

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/report"
)

// Options filters the tier7 TUN/l3ingress matrix.
type Options struct {
	Case string
}

func Run(ctx context.Context, suite *report.Suite, rendrRoot string, opts Options) {
	matched := false
	run := func(name string, budget time.Duration, fn func(context.Context) report.Case) {
		if !caseMatches(opts.Case, name) {
			return
		}
		matched = true
		runCase(ctx, suite, name, budget, fn)
	}
	defer func() {
		if opts.Case != "" && !matched {
			suite.Add(report.Case{
				Name:    "T7-case-filter",
				Tier:    "T7",
				Failure: fmt.Sprintf("no T7 case matched %q", opts.Case),
			})
		}
	}()

	run("T7.capability.local-probe", 30*time.Second, func(c context.Context) report.Case {
		return runGoTests(c, rendrRoot, "T7.capability.local-probe", "./tun", "^TestProbeReturnsMachineReadableCapability$")
	})
	run("T7.tun.open-smoke", 30*time.Second, func(c context.Context) report.Case {
		return runGoTests(c, rendrRoot, "T7.tun.open-smoke", "./tun", "^TestOpenCreatesEphemeralDeviceWhenAvailable$")
	})
	run("T7.config.invalid-mtu", 30*time.Second, func(c context.Context) report.Case {
		return runGoTests(c, rendrRoot, "T7.config.invalid-mtu", "./tun", "^TestConfigValidateRejectsSmallMTU$")
	})
	run("T7.l3.identity-smoke", 30*time.Second, func(c context.Context) report.Case {
		return runGoTests(c, rendrRoot, "T7.l3.identity-smoke", "./l3ingress", "^TestParseIPv4TCPIdentity|TestParseIPv6UDPIdentity$")
	})
	run("T7.l3.identity-wire", 30*time.Second, func(c context.Context) report.Case {
		return runGoTests(c, rendrRoot, "T7.l3.identity-wire", "./l3ingress", "^TestIdentityWireRoundTripIPv4|TestIdentityWireRoundTripIPv6|TestIdentityWireRejectsMixedFamilies$")
	})
	run("T7.capability.peer-denied", 30*time.Second, func(c context.Context) report.Case {
		return runGoTests(c, rendrRoot, "T7.capability.peer-denied", "./l3ingress", "^TestRequirePeerL3Identity|TestRequirePeerEgress$")
	})
	run("T7.router.per-flow-hook", 30*time.Second, func(c context.Context) report.Case {
		return runGoTests(c, rendrRoot, "T7.router.per-flow-hook", "./l3ingress", "^TestPumpRoutesParsedPackets$")
	})
	run("T7.router.per-flow-cache", 30*time.Second, func(c context.Context) report.Case {
		return runGoTests(c, rendrRoot, "T7.router.per-flow-cache", "./l3ingress", "^TestPumpCachesRouterDecisionPerFlow$")
	})
	run("T7.router.flow-deny", 30*time.Second, func(c context.Context) report.Case {
		return runGoTests(c, rendrRoot, "T7.router.flow-deny", "./l3ingress", "^TestFlowTableCachesDeniedDecision|TestPumpSkipsDeniedFlow$")
	})
	run("T7.flow.lifecycle-stats", 30*time.Second, func(c context.Context) report.Case {
		return runGoTests(c, rendrRoot, "T7.flow.lifecycle-stats", "./l3ingress", "^TestFlowTableCachesDecisionAndStats|TestFlowTableCloseSnapshot|TestPumpUsesProvidedFlowTable$")
	})
	run("T7.peer-egress-hook", 30*time.Second, func(c context.Context) report.Case {
		return runGoTests(c, rendrRoot, "T7.peer-egress-hook", "./l3ingress", "^TestEgressRegistryDispatchesIdentity|TestEgressRegistryMachineReadableErrors$")
	})
	run("T7.udp.identity-smoke", 30*time.Second, func(c context.Context) report.Case {
		return runGoTests(c, rendrRoot, "T7.udp.identity-smoke", "./l3ingress", "^TestUDPPayloadExtractsData|TestBuildUDPPacketRoundTripIPv4|TestBuildUDPPacketRoundTripIPv6|TestUDPFlowRelayDispatchesPayloadAndWritesReply|TestUDPFlowRelayCloseFlowAllowsReopen$")
	})
	run("T7.tcp.lifecycle-flags", 30*time.Second, func(c context.Context) report.Case {
		return runGoTests(c, rendrRoot, "T7.tcp.lifecycle-flags", "./l3ingress", "^TestParseTCPCloseFlags|TestPumpClosesFlowTableOnTCPReset$")
	})
	run("T7.l3.parse-error-skip", 30*time.Second, func(c context.Context) report.Case {
		return runGoTests(c, rendrRoot, "T7.l3.parse-error-skip", "./l3ingress", "^TestPumpSkipsParseErrors$")
	})
	run("T7.l3.fragment-boundary", 30*time.Second, func(c context.Context) report.Case {
		return runGoTests(c, rendrRoot, "T7.l3.fragment-boundary", "./l3ingress", "^TestParseIPv4UDPMoreFragmentFirstFragment|TestParseRejectsIPv4NonInitialFragment$")
	})
	run("T7.l3.unsupported-protocol", 30*time.Second, func(c context.Context) report.Case {
		return runGoTests(c, rendrRoot, "T7.l3.unsupported-protocol", "./l3ingress", "^TestParseRejectsUnsupportedProtocol|TestParseRejectsShortPacket$")
	})
}

func caseMatches(filter, name string) bool {
	return filter == "" || filter == name
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
	if rc.Failure != "" {
		fmt.Printf("  > T7/%s (took %s) - FAIL: %s\n", name, rc.Duration, rc.Failure)
	} else if rc.SkipReason != "" {
		fmt.Printf("  > T7/%s - SKIP: %s\n", name, rc.SkipReason)
	} else {
		fmt.Printf("  > T7/%s (took %s) - OK\n", name, rc.Duration)
	}
	suite.Add(rc)
}

func runGoTests(ctx context.Context, rendrRoot, name, pkg, pattern string) report.Case {
	if _, err := os.Stat(rendrRoot); err != nil {
		return report.Case{Name: name, Tier: "T7", Failure: "bad rendr root: " + err.Error()}
	}
	cmd := exec.CommandContext(ctx, "go", "test", pkg, "-run", pattern, "-count=1")
	cmd.Dir = rendrRoot
	cmd.Env = append(os.Environ(), "GOCACHE="+filepath.Join(os.TempDir(), "go-build-rendr-t7"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return report.Case{Name: name, Tier: "T7", Failure: fmt.Sprintf("%v (%s)", err, strings.TrimSpace(string(out)))}
	}
	return report.Case{Name: name, Tier: "T7"}
}
