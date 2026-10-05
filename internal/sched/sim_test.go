package sched

import (
	"math"
	"math/rand/v2"
	"time"
)

// This file is a virtual-time model of the dialer side of plan §3.9: one
// probe carrier per factory sends a PING every Probe.Interval, its PONG
// arrives one RTT later and becomes an aggregator sample, and the session
// actor evaluates the selector after every new sample (a new health
// snapshot) and at every Verdict.Wake. A Switch verdict is applied at once
// (the decision instant; the JOIN is not modelled) followed by
// Switched(now, true), exactly as the actor does on JOIN_ACK OK.

// Plan §4 defaults used by every selector test of this package.
const (
	defBand     = 0.25
	defFloor    = 5 * time.Millisecond
	defDwell    = 3 * time.Second
	defCooldown = 15 * time.Second
	defInterval = 2 * time.Second
	defFresh    = 10 * time.Second
)

// simEpoch is the virtual time origin of every model run.
var simEpoch = time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)

func defaultSelectorParams() SelectorParams {
	return SelectorParams{Band: defBand, Floor: defFloor, Dwell: defDwell, Cooldown: defCooldown, Fresh: defFresh}
}

// simPath is one factory's probe carrier. rtt and loaded receive the sample
// number k (0-based) and the PING send time (offset from simEpoch).
type simPath struct {
	phase  time.Duration
	rtt    func(k int, send time.Duration) time.Duration
	loaded func(k int, send time.Duration) bool // nil: never loaded
	until  time.Duration                        // > 0: no PING is sent at or after until
}

type simConfig struct {
	sel      SelectorParams
	agg      AggParams
	interval time.Duration
	dur      time.Duration // the run covers events at offsets in [0, dur]
	active   int           // initially active factory
	classes  []uint8       // kind class per factory (Selector.SetClasses); nil: all 0
	paths    []simPath
	// observe, if set, sees every evaluation: the instant, the active
	// factory evaluated, the summaries and the verdict (before a switch is
	// applied).
	observe func(now time.Time, active int, sums []Summary, v Verdict)
}

type simSwitch struct {
	at       time.Duration
	from, to int
}

type simResult struct {
	switches []simSwitch
	steps    int      // event instants processed (sample arrivals and wakes)
	evals    int      // Evaluate calls (a switch adds one re-evaluation)
	samples  []uint64 // accepted unloaded samples per path
	loaded   []uint64 // accepted loaded samples per path
	shifts   []uint64 // level shifts per path
	allFresh int      // steps at which every factory was EvFresh
	final    []Summary
	finalAct int
}

// runSim drives the model until cfg.dur and returns what happened.
func runSim(cfg simConfig) simResult {
	n := len(cfg.paths)
	aggs := make([]Aggregator, n)
	for i := range aggs {
		aggs[i] = NewAggregator(cfg.agg)
	}
	sums := make([]Summary, n)
	sel := NewSelector(cfg.sel)
	sel.SetClasses(cfg.classes)
	sent := make([]int, n)
	arrive := make([]time.Duration, n)
	rtt := make([]time.Duration, n)
	load := make([]bool, n)
	var res simResult
	schedule := func(i int) {
		p := cfg.paths[i]
		send := p.phase + time.Duration(sent[i])*cfg.interval
		if p.until > 0 && send >= p.until {
			arrive[i] = math.MaxInt64 // the probe carrier stopped
			return
		}
		rtt[i] = p.rtt(sent[i], send)
		load[i] = p.loaded != nil && p.loaded(sent[i], send)
		arrive[i] = send + rtt[i]
		sent[i]++
	}
	for i := range cfg.paths {
		schedule(i)
	}
	active := cfg.active
	wake := time.Duration(-1)
	for {
		t := time.Duration(math.MaxInt64)
		for _, a := range arrive {
			if a < t {
				t = a
			}
		}
		if wake >= 0 && wake < t {
			t = wake
		}
		if t > cfg.dur {
			break
		}
		now := simEpoch.Add(t)
		res.steps++
		for i := range arrive {
			if arrive[i] == t {
				if !aggs[i].Add(now, rtt[i], load[i]) {
					// Arrivals of one path are in time order and every RTT
					// is positive: a rejection is a bug of the model.
					panic("sim: sample rejected")
				}
				sums[i] = aggs[i].Summary()
				schedule(i)
			}
		}
		v := sel.Evaluate(now, active, sums, nil)
		res.evals++
		if cfg.observe != nil {
			cfg.observe(now, active, sums, v)
		}
		fresh := true
		for i := range sums {
			fresh = fresh && Classify(sums[i], now, cfg.sel.Fresh).State == EvFresh
		}
		if fresh {
			res.allFresh++
		}
		if v.Switch {
			res.switches = append(res.switches, simSwitch{at: t, from: active, to: v.To})
			active = v.To
			sel.Switched(now, true)
			v = sel.Evaluate(now, active, sums, nil)
			res.evals++
			if cfg.observe != nil {
				cfg.observe(now, active, sums, v)
			}
		}
		wake = -1
		if !v.Wake.IsZero() {
			if w := v.Wake.Sub(simEpoch); w > t {
				wake = w
			}
		}
	}
	res.final = sums
	res.finalAct = active
	for i := range aggs {
		u, l, s := aggs[i].Counts()
		res.samples = append(res.samples, u)
		res.loaded = append(res.loaded, l)
		res.shifts = append(res.shifts, s)
	}
	return res
}

// normalRTT returns an RTT source drawing N(mean, sd) per sample from a PCG
// stream fixed by (seed, stream), truncated below at 1 ms (a delay line
// cannot answer faster than that and the aggregator rejects rtt ≤ 0).
func normalRTT(seed, stream uint64, mean, sd time.Duration) func(int, time.Duration) time.Duration {
	r := rand.New(rand.NewPCG(seed, stream))
	return func(int, time.Duration) time.Duration {
		d := time.Duration(float64(mean) + r.NormFloat64()*float64(sd))
		if d < time.Millisecond {
			d = time.Millisecond
		}
		return d
	}
}

// constRTT returns an RTT source with a fixed value.
func constRTT(d time.Duration) func(int, time.Duration) time.Duration {
	return func(int, time.Duration) time.Duration { return d }
}

// stepRTT returns before for PINGs sent before at and after for the others:
// a delay change applied at time at affects every PING sent from then on.
func stepRTT(before, after time.Duration, at time.Duration) func(int, time.Duration) time.Duration {
	return func(_ int, send time.Duration) time.Duration {
		if send < at {
			return before
		}
		return after
	}
}
