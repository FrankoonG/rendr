//go:build linux

// Package chaos applies Linux tc qdisc rules to the loopback interface
// inside the regress container so tests can run against a realistic
// network profile (bandwidth-limited, with optional loss / delay /
// jitter) instead of the docker default "infinite bandwidth zero
// latency" loopback that CLAUDE.md warns about:
//
//	"带宽限速是 resilience / recovery 类测试的必备前置——docker
//	 默认网络太快，跑出来的数据没意义"
//
// Profile is the declarative shape (bandwidth bits/sec, loss percent,
// delay base+jitter). Apply installs a tc tbf+netem qdisc stack on
// `lo`; the returned cleanup MUST be deferred so a leaked qdisc
// doesn't poison subsequent regress runs.
//
// Linux-only by build tag. Container needs CAP_NET_ADMIN
// (scripts/regress.sh's --cap-add=NET_ADMIN provides it).
package chaos

import (
	"fmt"
	"os/exec"
	"strconv"
	"time"
)

// Profile is one chaos configuration. Zero-value = no qdisc applied
// (the caller should skip the harness entirely in that case).
type Profile struct {
	// Bandwidth in bits per second (e.g. 50_000_000 = 50 Mbps).
	// Zero leaves bandwidth uncapped.
	Bandwidth int64
	// LossPct is application-visible packet loss percentage, 0-100.
	LossPct float64
	// Delay is the base one-way delay added to every packet.
	Delay time.Duration
	// Jitter is the +/- random component layered on Delay.
	Jitter time.Duration
}

// Realistic50M is the recommended default per project convention:
// 50 Mbps bandwidth, no loss, no added delay. Models a typical
// residential broadband link.
var Realistic50M = Profile{Bandwidth: 50_000_000}

// LossyWAN models a lossy intercontinental hop: 50 Mbps + 1% loss
// + 80 ms base delay + 20 ms jitter. Used for resilience tests.
var LossyWAN = Profile{
	Bandwidth: 50_000_000,
	LossPct:   1.0,
	Delay:     80 * time.Millisecond,
	Jitter:    20 * time.Millisecond,
}

// Apply installs the profile on `lo`. Returns a cleanup function
// that removes the qdisc; caller MUST defer it.
//
// The qdisc stack is `tbf` (bandwidth shaper) at the root, with
// `netem` (loss/delay/jitter) chained underneath via a child class.
// This is the canonical ordering: shape first, then degrade — so
// the bandwidth limit reflects the link cap and netem injects the
// link's behavior.
func Apply(p Profile) (cleanup func() error, err error) {
	if p.Bandwidth <= 0 && p.LossPct <= 0 && p.Delay <= 0 {
		// No-op profile; nothing to install.
		return func() error { return nil }, nil
	}

	// Clear any prior root qdisc first (idempotent setup).
	_ = exec.Command("tc", "qdisc", "del", "dev", "lo", "root").Run()

	if p.Bandwidth > 0 {
		// tbf params: rate, burst, latency. Latency=1s deliberately
		// gives the tbf queue about rate*1s of headroom (6 MB at
		// 50 Mbps). At the 50 Mbps regression baseline and above,
		// burst must also be large enough for loopback/GSO-shaped TCP:
		// the original rate/100 burst (62.5 KB at 50 Mbps) consistently
		// manufactured TCP loss on lo and made G1-T4 abort at ~2m17s
		// with ETIMEDOUT after only ~10 MiB written. A 4 MiB floor at
		// 50 Mbps+ preserves the steady-state cap while avoiding
		// qdisc-induced drops that do not model a clean broadband
		// bottleneck. Lower-rate unit tests keep the small burst so
		// short samples still observe shaping.
		burst := p.Bandwidth / 800 // bytes ≈ rate-bits / 8 / 100
		if p.Bandwidth >= 50_000_000 && burst < 4<<20 {
			burst = 4 << 20
		}
		if burst < 128<<10 {
			burst = 128 << 10
		}
		args := []string{"qdisc", "add", "dev", "lo", "root", "handle", "1:",
			"tbf",
			"rate", fmt.Sprintf("%dbit", p.Bandwidth),
			"burst", strconv.FormatInt(burst, 10),
			"latency", "1s",
		}
		if out, err := exec.Command("tc", args...).CombinedOutput(); err != nil {
			return nil, fmt.Errorf("tc tbf: %w (%s)", err, out)
		}
	}

	if p.LossPct > 0 || p.Delay > 0 {
		netemArgs := []string{"qdisc", "add", "dev", "lo"}
		if p.Bandwidth > 0 {
			netemArgs = append(netemArgs, "parent", "1:1", "handle", "10:")
		} else {
			netemArgs = append(netemArgs, "root", "handle", "10:")
		}
		netemArgs = append(netemArgs, "netem")
		if p.Delay > 0 {
			netemArgs = append(netemArgs, "delay", fmt.Sprintf("%dms", p.Delay.Milliseconds()))
			if p.Jitter > 0 {
				netemArgs = append(netemArgs, fmt.Sprintf("%dms", p.Jitter.Milliseconds()))
			}
		}
		if p.LossPct > 0 {
			netemArgs = append(netemArgs, "loss", fmt.Sprintf("%.2f%%", p.LossPct))
		}
		if out, err := exec.Command("tc", netemArgs...).CombinedOutput(); err != nil {
			// Roll back tbf if it was installed.
			_ = exec.Command("tc", "qdisc", "del", "dev", "lo", "root").Run()
			return nil, fmt.Errorf("tc netem: %w (%s)", err, out)
		}
	}

	cleanup = func() error {
		out, err := exec.Command("tc", "qdisc", "del", "dev", "lo", "root").CombinedOutput()
		if err != nil {
			return fmt.Errorf("tc qdisc del lo root: %w (%s)", err, out)
		}
		return nil
	}
	return cleanup, nil
}
