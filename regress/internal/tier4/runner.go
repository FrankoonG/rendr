// Package tier4 implements the long-run regression tier — the
// release-tag verification path. T4 is opt-in via --tier=4.
package tier4

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/regress/internal/chaos"
	"github.com/FrankoonG/rendr/regress/internal/report"
	"github.com/FrankoonG/rendr/regress/internal/smoke"
)

// Options filters the long-run matrix for targeted debug runs.
type Options struct {
	Case string
}

// Run executes T4 cases with per-case budgets enforced by select.
// Default chaos profile is Realistic50M (50 Mbps baseline) per the
// project-wide bandwidth policy; G3-T4 opts out because it tests
// raw packet throughput at 100k pps × 1 KB = 800 Mbps which is well
// above any realistic link.
func Run(ctx context.Context, suite *report.Suite, _ string, opts Options) {
	const T4Budget = 33 * time.Minute
	matched := false
	run := func(name string, budget time.Duration, prof chaos.Profile, fn func(context.Context) smoke.Result) {
		if !caseMatches(opts.Case, name) {
			return
		}
		matched = true
		runCase(ctx, suite, name, budget, prof, fn)
	}
	defer func() {
		if opts.Case != "" && !matched {
			suite.Add(report.Case{
				Name:    "T4-case-filter",
				Tier:    "T4",
				Failure: fmt.Sprintf("no T4 case matched %q", opts.Case),
			})
		}
	}()

	// G1-T4 runs at the same 50 Mbps baseline as the long-lived G2
	// cases. The prior 200 Mbps workaround was only needed while the
	// tbf burst was too small for loopback/GSO-shaped TCP and caused
	// qdisc-induced ETIMEDOUT; chaos.Realistic50M now uses a larger
	// burst floor while preserving the steady-state 50 Mbps cap.
	g1ChaosProf := chaos.Realistic50M
	run("G1-T4", 7*time.Minute, g1ChaosProf, func(c context.Context) smoke.Result {
		return smoke.RunG1(c, smoke.G1Opts{
			Size:       1 << 30,
			Migrations: 10,
			Paths:      2,
			Transport:  "tcp",
		})
	})
	run("G1-T4-quic", 7*time.Minute, g1ChaosProf, func(c context.Context) smoke.Result {
		return smoke.RunG1(c, smoke.G1Opts{
			Size:       1 << 30,
			Migrations: 10,
			Paths:      2,
			Transport:  "quic",
		})
	})

	run("G2-T4", T4Budget, chaos.Realistic50M, func(c context.Context) smoke.Result {
		return smoke.RunG2(c, smoke.G2Opts{
			Duration:     30 * time.Minute,
			Migrations:   30,
			Paths:        2,
			Transport:    "tcp",
			Mode:         rendr.ModePrime,
			Interval:     100 * time.Millisecond,
			P99CeilingMs: 200, // chaos 80ms one-way base + jitter — relax from clean 50ms
		})
	})
	// Mode-matrix long-run coverage: race + bond on TCP.
	run("G2-T4-race-tcp", T4Budget, chaos.Realistic50M, func(c context.Context) smoke.Result {
		return smoke.RunG2(c, smoke.G2Opts{
			Duration:     30 * time.Minute,
			Migrations:   0,
			Paths:        2,
			Transport:    "tcp",
			Mode:         rendr.ModeRace,
			Interval:     100 * time.Millisecond,
			P99CeilingMs: 200,
		})
	})
	run("G2-T4-bond-tcp", T4Budget, chaos.Realistic50M, func(c context.Context) smoke.Result {
		return smoke.RunG2(c, smoke.G2Opts{
			Duration:     30 * time.Minute,
			Migrations:   30,
			Paths:        2,
			Transport:    "tcp",
			Mode:         rendr.ModeBond,
			Interval:     100 * time.Millisecond,
			P99CeilingMs: 200,
		})
	})
	run("M11-udp-relay-T4", 5*time.Minute, chaos.Profile{}, func(c context.Context) smoke.Result {
		return smoke.RunUDPRelay(c, smoke.UDPRelayOpts{
			Packets:    10_000,
			Paths:      2,
			Migrations: 3,
			Server:     true,
		})
	})
	run("M11-udp-relay-porthop-T4", 5*time.Minute, chaos.Profile{}, func(c context.Context) smoke.Result {
		return smoke.RunUDPRelayPortHop(c, smoke.UDPRelayOpts{
			Packets:    10_000,
			Paths:      2,
			Migrations: 3,
			PortHops:   8,
		})
	})
	if runtime.GOOS == "linux" {
		run("M11-wireguard-relay-T4", 5*time.Minute, chaos.Profile{}, func(c context.Context) smoke.Result {
			return smoke.RunWireGuardRelay(c, smoke.WireGuardRelayOpts{
				Messages:    512,
				MessageSize: 512,
				Paths:       2,
				Migrations:  3,
			})
		})
	} else if caseMatches(opts.Case, "M11-wireguard-relay-T4") {
		matched = true
		suite.Add(report.Case{
			Name:       "M11-wireguard-relay-T4",
			Tier:       "T4",
			SkipReason: "Linux only (wireguard-go UDP endpoint smoke is validated on Linux regress hosts)",
		})
	}

	if runtime.GOOS == "linux" {
		// G3-T4 deliberately runs without any chaos profile (Profile{})
		// because 100k pps × 1 KB ≈ 800 Mbps would be 16× over the
		// 50 Mbps baseline — that's a bandwidth saturation test, not a
		// throughput test.
		run("G3-T4", 3*time.Minute, chaos.Profile{}, func(c context.Context) smoke.Result {
			return smoke.RunG3(c, smoke.G3Opts{
				Duration:   30 * time.Second,
				PPS:        100_000,
				PayloadLen: 1024,
				Migrations: 10,
				// The validated 100k pps QUIC DATAGRAM contract on the
				// Linux regress host is the 8-path bond shape documented
				// in plan/README. Lower path counts are still useful for
				// smoke and local profiling, but the release gate should
				// match the empirically-proven configuration.
				Paths:        8,
				P95CeilingMs: 20,
				LossPct:      0,
			})
		})
	} else {
		if caseMatches(opts.Case, "G3-T4") {
			matched = true
			suite.Add(report.Case{
				Name:       "G3-T4",
				Tier:       "T4",
				SkipReason: "Linux only (100k pps QUIC DATAGRAM needs net.core.rmem_max=8MiB)",
			})
		}
	}
}

func caseMatches(filter, name string) bool {
	return filter == "" || filter == name || strings.EqualFold(filter, name)
}

// runCase enforces the per-case budget via select-on-Done. Smoke.RunG1
// /G2/G3 only honor ctx at Accept() and path-attach; the hot loop
// blocks on rendr.Conn which won't unblock from ctx if the engine
// deadlocks. select guarantees forward progress: smoke goroutine
// leaks but container teardown bounds the leak. Also prints
// per-case start/end so a stuck case is visible in real-time stdout.
//
// When prof is non-zero, chaos.Apply installs a tc qdisc on `lo`
// before the case runs and the cleanup is deferred. Failure to
// install chaos surfaces as a case failure (rather than a silent
// skip) so a misconfigured container doesn't quietly degrade T4
// into a clean-baseline run.
func runCase(ctx context.Context, suite *report.Suite, name string, budget time.Duration, prof chaos.Profile, fn func(context.Context) smoke.Result) {
	fmt.Printf("  > T4/%s (budget %s, chaos %s) — start\n", name, budget, profDesc(prof))
	rc := report.Case{Name: name, Tier: "T4"}
	cleanup, err := chaos.Apply(prof)
	if err != nil {
		rc.Failure = "chaos.Apply failed: " + err.Error()
		fmt.Printf("  > T4/%s — FAIL: %s\n", name, rc.Failure)
		suite.Add(rc)
		return
	}
	defer func() {
		if cleanup != nil {
			if err := cleanup(); err != nil {
				// Don't fail the case for this; just surface in stdout
				// so the operator can `tc qdisc show dev lo` and clean
				// up a leaked rule before the next run.
				fmt.Printf("  > T4/%s — chaos cleanup failed: %v\n", name, err)
			}
		}
	}()

	cctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	start := time.Now()
	done := make(chan smoke.Result, 1)
	go func() {
		done <- fn(cctx)
	}()
	select {
	case r := <-done:
		rc.Duration = r.Duration
		rc.Failure = r.Failure
		if rc.Duration == 0 {
			rc.Duration = time.Since(start)
		}
	case <-cctx.Done():
		rc.Duration = time.Since(start)
		rc.Failure = "case exceeded T4 budget (" + budget.String() + "): " + cctx.Err().Error()
	}
	if rc.Failure != "" {
		fmt.Printf("  > T4/%s (took %s) — FAIL: %s\n", name, rc.Duration, rc.Failure)
	} else {
		fmt.Printf("  > T4/%s (took %s) — OK\n", name, rc.Duration)
	}
	suite.Add(rc)
}

func profDesc(p chaos.Profile) string {
	if p.Bandwidth == 0 && p.LossPct == 0 && p.Delay == 0 {
		return "clean"
	}
	return fmt.Sprintf("%dMbit/loss%.1f%%/delay%dms", p.Bandwidth/1_000_000, p.LossPct, p.Delay.Milliseconds())
}
