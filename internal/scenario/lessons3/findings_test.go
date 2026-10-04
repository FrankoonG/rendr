//go:build rendr_findings

package lessons3

import (
	"testing"
	"time"
)

// Reproductions of product findings reported to the integrator. They fail
// on the current code by design, so they are kept out of the default build;
// run them with
//
//	go test -tags rendr_findings -run 'Counted|GuardEdges' ./internal/scenario/lessons3/
//
// Each becomes a normal test (this file loses its build tag) once the
// product is fixed or the design section it cites is amended. Their
// scenario helpers (successorDies, runGuardBulk) are shared with the
// required tests and stay untagged.

// TestSuccessorDeathCountedOnBothEnds_L22: the scenarios of
// TestSuccessorDiesFallsBackToPredecessor_L22, checking that both ends
// count the same selector migrations (design §7.6: the passive counts from
// the SCHED cause bits, "both ends therefore count the same selector
// migrations"). The dialer counts {Death: 1, Quality: 1}: the quality
// switch to B and B's death. The passive counts a SCHED only when the lane
// it names becomes its sender (passiveRouteLocked: the named lane must be
// usable), and B is already dead on the passive whenever the quality SCHED
// arrives — b dies in the instant of the switch, and the quality SCHED
// travels over A. Which SCHEDs reach the passive at all depends on
// goroutine scheduling: A's writer carries the quality SCHED only if it
// fills a batch before B's death step publishes the next epoch, which then
// supersedes it. Each case therefore fixes the order with hooks:
//
//   - retiring-quality-sched-first: B's death step is held until A carried
//     the quality SCHED. The passive applies it (B dead: nothing named,
//     nothing counted), then the death SCHED naming A, which it already
//     names: {0, 0, 0}.
//   - retiring-quality-sched-never-sent: A's writer is held across the
//     switch and B's death, so the first SCHED A carries is the death SCHED
//     naming A: {0, 0, 0}.
//   - retired-quality-sched-first: the quality SCHED reaches the passive
//     (B dead: nothing counted); the death SCHED names the race winner, a
//     new carrier of a: {Death: 1}. Without hooks this order is the only
//     one: B's death step publishes nothing (no fallback), and A's writer
//     carries the quality SCHED before its CLOSE.
//
// A passive rule that counts whenever an applied SCHED names a different
// carrier ID than the previous one, usable or not, fixes the first and the
// third case but not the second: there the dialer superseded the quality
// SCHED before any lane carried it, so no passive-side rule can learn of
// the quality switch. Holding §7.6's sentence needs the SCHED to carry the
// dialer's cumulative selector migration counts (a wire change); otherwise
// §7.6 must say that the ends may differ when a SCHED is superseded before
// it is sent.
func TestSuccessorDeathCountedOnBothEnds_L22(t *testing.T) {
	for _, tc := range []struct {
		name string
		sc   successorCase
	}{
		{"retiring-quality-sched-first", successorCase{order: schedFirst}},
		{"retiring-quality-sched-never-sent", successorCase{order: schedNeverSent}},
		{"retired-quality-sched-first", successorCase{retired: true, order: schedFirst}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dialer, passive := successorDies(t, tc.sc)
			if !t.Failed() && passive != dialer {
				t.Errorf("passive migrations %+v, dialer %+v: the ends disagree", passive, dialer)
			}
		})
	}
}

// TestDownloadGuardEdges_L29: two bulk downloads in the shape of
// TestBulkDownloadNoQualitySwitch_L29 in which the self-load guard misses
// part of the dialer's self-induced queueing, so the idle path wins a
// quality switch (design §8.2, §8.5: no self-induced switch). Once the
// guard covers them, both cases join TestBulkDownloadNoQualitySwitch_L29
// (its start phase and rate are favourable: the bulk starts halfway
// between two probe PINGs, at 2 MiB/s).
//
//   - low-bdp: 512 KiB/s at a 20 ms RTT. The passive's capacity cap sits at
//     its 128 KiB floor (2·rate·(minRTT + PingBusy + 50 ms) ≈ 122 KiB), so
//     the dialer's whole gauge estimate — the reverse bound rxRate × srtt,
//     a download has no forward in-flight — stays around the 64 KiB load
//     threshold (≈ 44–67 KiB in an instrumented run) although the passive
//     is backlogged. A probe sample whose PING commit and PONG arrival both
//     fall below the threshold counts as unloaded with up to ≈ 240 ms of
//     self-queueing, and one such sample lifts a's mean far above b's.
//   - start-at-probe-ping: the G1-shaped download (2 MiB/s; 1 MiB/s under
//     -race) starts the moment a's probe carrier committed a PING. Its PONG
//     enters the down bottleneck one one-way delay later, behind the rest
//     of the passive's first 128 KiB (the capacity floor) of bulk, which
//     takes 62.5 ms to drain at 2 MiB/s: the PONG waits about 52 ms and the
//     sample measures about 72.6 ms. When it arrives the gauge holds
//     nothing at all — no forward in-flight (a download), a reverse bound
//     of 0 (rxRate is refreshed only when the dialer's own session carrier
//     receives a PONG, which queues behind the same bulk) and no backlog
//     (no BUSY PING has arrived) — so the sample is unloaded. With only the
//     4 unloaded samples of the idle phase before it in a's window, it
//     lifts a's mean to about 30 ms, enough for b (20 ms) to qualify by
//     Band and Floor; the switch follows one dwell later (a's later samples
//     are loaded and do not dilute it). The window exists only while the
//     first capacity drains slower than about one one-way delay (128 KiB
//     per 10 ms, ≈ 12.8 MB/s at a 20 ms RTT) and a's window holds few
//     unloaded samples: at G1-sel's 200 Mbit/s the first sample measures
//     20.0 ms, at 50 Mbit/s 31 ms, and neither switches. A fix must also
//     cover the zero reverse bound — e.g. classify a probe sample only one
//     session srtt after its arrival, or carry the load state forward;
//     reporting BUSY at the first cap-block alone is not enough (Loaded
//     also needs in-flight ≥ 64 KiB).
func TestDownloadGuardEdges_L29(t *testing.T) {
	t.Run("low-bdp", func(t *testing.T) {
		gb := guardBulk{download: true, rate: 512 * kib, dur: 60 * time.Second}
		checkGuarded(t, gb, runGuardBulk(t, gb))
	})
	t.Run("start-at-probe-ping", func(t *testing.T) {
		gb := guardBulk{download: true, rate: guardRate(), dur: 30 * time.Second, atProbePing: true}
		checkGuarded(t, gb, runGuardBulk(t, gb))
	})
}
