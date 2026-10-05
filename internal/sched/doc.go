// Package sched holds rendr's pure scheduling policy: the selector RTT
// evidence aggregator (plan §4) with the self-load guard's loaded tagging,
// factory ranking, the selector quality rule (band, floor, dwell,
// cooldown), the failover race (JoinStagger), the redial cadence (plan
// §3.6), the bond rescue threshold and the estimator formulas (death
// deadline, write-stall window, capacity cap, advertised window).
//
// Everything here is deterministic: no goroutines, no locks, no I/O and no
// clock of its own. Every function that depends on time takes now and
// returns values or the next time something can change. Random jitter is
// passed in as u ∈ [0,1). The same code therefore runs in the per-session
// actor (M1), in a Runtime-level timer driver (M3) and in table and
// statistical tests with virtual time.
package sched
