package realsock

import (
	"fmt"
	"slices"
	"strconv"
	"testing"
	"time"
)

// The judge of TestL4UQuietTailDiag (l4u_tail_linux_test.go; M6 delegate
// decisions after wave D, "G10 criterion 7, the quiet-path tail (C1)"):
// a pure function of the measured round trips, so that its bounds are
// proven on every host, while the diagnostic itself runs only on a quiet
// Linux pool worker.

const (
	// tailMargin: an echo is in the tail when its round trip exceeds the
	// direct baseline's median by more than this — ENet's retransmission
	// margin at a low delay variance, the one criterion 7 meets (C1).
	tailMargin = 4 * time.Millisecond
	// tailShareMax bounds the tail's share of the echoes sent (lost ones
	// count as in the tail: ENet retransmits them too).
	tailShareMax = 0.0005
	// tailAddedP99Max bounds rendr's added p99: the echoes' p99 through
	// rendr less the direct baseline's.
	tailAddedP99Max = 500 * time.Microsecond
)

// tailCfg is the diagnostic's configuration from its environment.
type tailCfg struct {
	on   bool // RENDR_TAIL_DIAG=1: the diagnostic runs (else it is skipped)
	secs int  // RENDR_TAIL_SECS: the measured span in seconds (default 60)
	spin bool // RENDR_TAIL_PACE is not "sleep": the bursts' groups are paced by spinning
}

// tailDiagConfig reads the diagnostic's environment through getenv.
func tailDiagConfig(getenv func(string) string) (tailCfg, error) {
	c := tailCfg{on: getenv("RENDR_TAIL_DIAG") == "1", secs: 60, spin: getenv("RENDR_TAIL_PACE") != "sleep"}
	if v := getenv("RENDR_TAIL_SECS"); v != "" {
		k, err := strconv.Atoi(v)
		if err != nil || k < 1 {
			return c, fmt.Errorf("RENDR_TAIL_SECS=%q: want a positive number of seconds", v)
		}
		c.secs = k
	}
	return c, nil
}

// tailVerdict is the judge's result.
type tailVerdict struct {
	sent, lost, over        int           // echoes through rendr sent in the window; lost; arrived beyond baseMedian + tailMargin
	share                   float64       // (over + lost) / sent
	baseMedian              time.Duration // the direct baseline's median round trip
	addP50, addP99, addP999 time.Duration // rendr's quantile less the baseline's
	fails                   []string      // the bounds exceeded (none: PASS)
}

// tailQuantile is the nearest-rank q-quantile of the sorted s (s not
// empty, 0 < q ≤ 1).
func tailQuantile(s []time.Duration, q float64) time.Duration {
	k := int(q*float64(len(s))+0.999999999) - 1
	return s[min(max(k, 0), len(s)-1)]
}

// tailJudge judges the round trips through rendr (rendr: the arrived
// echoes; lost: those that never came back) against the direct baseline's
// (base): the share of the sent echoes in the tail — lost, or beyond the
// baseline's median plus tailMargin — must not exceed tailShareMax, and
// rendr's p99 less the baseline's must not exceed tailAddedP99Max.
func tailJudge(rendr []time.Duration, lost int, base []time.Duration) tailVerdict {
	v := tailVerdict{sent: len(rendr) + lost, lost: lost}
	if len(base) == 0 || v.sent == 0 {
		v.fails = append(v.fails, fmt.Sprintf("no measurement: %d echoes through rendr, %d baseline round trips", v.sent, len(base)))
		return v
	}
	b := slices.Clone(base)
	slices.Sort(b)
	v.baseMedian = tailQuantile(b, 0.5)
	for _, d := range rendr {
		if d > v.baseMedian+tailMargin {
			v.over++
		}
	}
	v.share = float64(v.over+v.lost) / float64(v.sent)
	if v.share > tailShareMax {
		v.fails = append(v.fails, fmt.Sprintf("%.4f %% of the echoes through rendr were lost (%d) or arrived more than %v above the baseline's median %v (%d), above %.2f %%",
			100*v.share, v.lost, tailMargin, v.baseMedian, v.over, 100*tailShareMax))
	}
	if len(rendr) == 0 {
		v.fails = append(v.fails, "no echo through rendr arrived")
		return v
	}
	r := slices.Clone(rendr)
	slices.Sort(r)
	v.addP50 = tailQuantile(r, 0.5) - v.baseMedian
	v.addP99 = tailQuantile(r, 0.99) - tailQuantile(b, 0.99)
	v.addP999 = tailQuantile(r, 0.999) - tailQuantile(b, 0.999)
	if v.addP99 > tailAddedP99Max {
		v.fails = append(v.fails, fmt.Sprintf("rendr added %v at p99, above %v", v.addP99, tailAddedP99Max))
	}
	return v
}

// TestL4UTailJudge (the diagnostic's judge; C1): the tail is measured
// against the baseline's median (not rendr's own), strictly beyond
// tailMargin; a lost echo counts in the tail; the share bound and the p99
// bound are exceeded only strictly; the added quantiles are rendr's less
// the baseline's.
func TestL4UTailJudge(t *testing.T) {
	const us = time.Microsecond
	fill := func(n int, d time.Duration) []time.Duration {
		s := make([]time.Duration, n)
		for i := range s {
			s[i] = d
		}
		return s
	}
	with := func(s []time.Duration, ds ...time.Duration) []time.Duration {
		s = slices.Clone(s)
		copy(s, ds)
		return s
	}
	base := fill(2000, 100*us)
	for _, c := range []struct {
		name   string
		rendr  []time.Duration
		lost   int
		base   []time.Duration
		over   int
		share  float64
		addP99 time.Duration
		fail   bool
	}{
		{name: "equal", rendr: fill(2000, 100*us), base: base},
		{name: "one in 2000 beyond the margin: 0.05 %, not above", rendr: with(fill(2000, 100*us), 100*us+tailMargin+1), base: base, over: 1, share: 0.0005},
		{name: "two in 2000: 0.1 %", rendr: with(fill(2000, 100*us), 9*time.Millisecond, 9*time.Millisecond), base: base, over: 2, share: 0.001, fail: true},
		{name: "exactly the margin is not beyond it", rendr: with(fill(2000, 100*us), 100*us+tailMargin, 100*us+tailMargin), base: base},
		{name: "a lost echo is in the tail", rendr: with(fill(1999, 100*us), 9*time.Millisecond), lost: 1, base: base, over: 1, share: 0.001, fail: true},
		{name: "the margin is the baseline's, not rendr's", rendr: fill(2000, 100*us+tailMargin+1), base: base, over: 2000, share: 1, addP99: tailMargin + 1, fail: true},
		{name: "added p99 at the bound", rendr: fill(2000, 100*us+tailAddedP99Max), base: base, addP99: tailAddedP99Max},
		{name: "added p99 beyond the bound", rendr: fill(2000, 100*us+tailAddedP99Max+1), base: base, addP99: tailAddedP99Max + 1, fail: true},
		{name: "added p99 is the quantiles' difference", rendr: fill(2000, 700*us), base: with(fill(2000, 100*us), fill(25, 400*us)...), addP99: 300 * us},
		{name: "no baseline", rendr: fill(10, 100*us), fail: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			v := tailJudge(c.rendr, c.lost, c.base)
			if v.over != c.over || v.share != c.share || (len(v.fails) != 0) != c.fail || (len(c.base) > 0 && v.addP99 != c.addP99) {
				t.Fatalf("tailJudge: over %d, share %v, added p99 %v, fails %q; want over %d, share %v, added p99 %v, fail %v",
					v.over, v.share, v.addP99, v.fails, c.over, c.share, c.addP99, c.fail)
			}
		})
	}
	// The environment: off unless RENDR_TAIL_DIAG is exactly 1 (the
	// ordinary lanes never run the diagnostic); 60 s and spinning by
	// default.
	for _, c := range []struct {
		env  map[string]string
		want tailCfg
		err  bool
	}{
		{env: nil, want: tailCfg{secs: 60, spin: true}},
		{env: map[string]string{"RENDR_TAIL_DIAG": "true"}, want: tailCfg{secs: 60, spin: true}},
		{env: map[string]string{"RENDR_TAIL_DIAG": "1"}, want: tailCfg{on: true, secs: 60, spin: true}},
		{env: map[string]string{"RENDR_TAIL_DIAG": "1", "RENDR_TAIL_SECS": "300", "RENDR_TAIL_PACE": "sleep"}, want: tailCfg{on: true, secs: 300}},
		{env: map[string]string{"RENDR_TAIL_DIAG": "1", "RENDR_TAIL_SECS": "0"}, err: true},
	} {
		got, err := tailDiagConfig(func(k string) string { return c.env[k] })
		if (err != nil) != c.err || (err == nil && got != c.want) {
			t.Fatalf("tailDiagConfig(%v) = %+v, %v; want %+v (error %v)", c.env, got, err, c.want, c.err)
		}
	}

	// Nearest rank: the 0.99-quantile of 1 … 100 is 99, the median 50.
	s := make([]time.Duration, 100)
	for i := range s {
		s[i] = time.Duration(i + 1)
	}
	if p50, p99, p100 := tailQuantile(s, 0.5), tailQuantile(s, 0.99), tailQuantile(s, 1); p50 != 50 || p99 != 99 || p100 != 100 {
		t.Fatalf("tailQuantile of 1 … 100: p50 %d, p99 %d, p100 %d; want 50, 99, 100", p50, p99, p100)
	}
}
