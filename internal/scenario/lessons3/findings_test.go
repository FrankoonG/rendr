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
//	go test -tags rendr_findings -run 'GuardEdges' ./internal/scenario/lessons3/
//
// Each becomes a normal test (this file loses its build tag) once the
// product is fixed or the design section it cites is amended. Their
// scenario helper (runGuardBulk) is shared with the required tests and
// stays untagged. TestSuccessorDeathCountedOnBothEnds_L22 left this file
// when the SCHED began to carry the dialer's cumulative migration counts
// (design §0.13 A3); it is in l22_test.go.

// TestDownloadGuardEdges_L29: a bulk download in the shape of
// TestBulkDownloadNoQualitySwitch_L29 in which the self-load guard misses
// part of the dialer's self-induced queueing, so the idle path wins a
// quality switch (design §8.2, §8.5: no self-induced switch). Its low-bdp
// sibling joined TestBulkDownloadNoQualitySwitch_L29 once a BUSY peer
// counted at least the capacity floor (§0.13 A5).
//
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
	t.Run("start-at-probe-ping", func(t *testing.T) {
		gb := guardBulk{download: true, rate: guardRate(), dur: 30 * time.Second, atProbePing: true}
		checkGuarded(t, gb, runGuardBulk(t, gb))
	})
}
