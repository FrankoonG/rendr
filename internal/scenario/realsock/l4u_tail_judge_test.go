package realsock

import (
	"fmt"
	"slices"
	"strconv"
	"testing"
	"time"
)

// The judge and the load proof of TestL4UQuietTailDiag
// (l4u_tail_linux_test.go; M6 delegate decisions after wave D, "G10
// criterion 7, the quiet-path tail (C1)"): pure functions of the measured
// run, so that their bounds are proven on every host, while the diagnostic
// itself runs only on a quiet Linux pool worker.

// The diagnostic's load: ML-100's down shape and the echo flows.
const (
	tailEchoEvery  = 4 * time.Millisecond
	tailEchoSize   = 48
	tailKeepEvery  = 100 * time.Millisecond
	tailKeepSize   = 32
	tailShard      = 1408
	tailFrameDgram = 203
	tailGroup      = 46
	tailFrameEvery = time.Second / 60
)

// tailGroupGap spaces a burst's groups: 46 datagrams at 71 kpps.
var tailGroupGap = tailGroup * time.Second / 71000

const (
	// tailMargin: an echo is in the tail when its round trip exceeds the
	// direct baseline's median by more than this — ENet's retransmission
	// margin at a low delay variance, the one criterion 7 meets (C1).
	tailMargin = 4 * time.Millisecond
	// tailShareMax bounds the tail's share of the echoes sent (lost ones
	// count as in the tail: ENet retransmits them too).
	tailShareMax = 0.0005
	// tailBaseShareMax bounds the direct baseline's own tail share (its
	// lost echoes included): above it the host was not quiet and the run
	// is INVALID. At most half of tailShareMax, so that a FAIL names rendr
	// for at least half of its tail.
	tailBaseShareMax = tailShareMax / 2
	// tailAddedP99Max bounds rendr's added p99: the echoes' p99 through
	// rendr less the direct baseline's.
	tailAddedP99Max = 500 * time.Microsecond
	// tailLateMax: a frame that starts later than this after its due
	// instant missed its schedule.
	tailLateMax = 2 * time.Millisecond
	// tailBurstSpanMax bounds a burst's first-to-last write: ML-100's
	// 71 kpps within 25 % (202 gaps at 71,000 per second, 2.85 ms; the
	// bound 3.56 ms).
	tailBurstSpanMax = (tailFrameDgram - 1) * time.Second / 71000 * 5 / 4
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

// tailLoad is the load a run of the diagnostic produced: the load proof's
// material.
type tailLoad struct {
	frames, due int             // video frames written; due over the warm-up and the window
	late, burst []time.Duration // per frame: its start after its due instant; its first-to-last write
	sent, got   int             // video datagrams written; received by the client
	echoDue     int             // echoes due in the window per echo client: its span / tailEchoEvery
	echoes      int             // echoes the client through rendr sent in the window
	baseEchoes  int             // echoes the baseline's client sent in the window
}

// tailLoadProof returns why a run's load was not the designed one, each
// reason making the run INVALID (none: the load was carried): fewer than
// 99 % of the frames due; more than 1 % of the frames starting more than
// tailLateMax late, or writing their burst slower than tailBurstSpanMax
// (ML-100's 71 kpps); less than 90 % of the video datagrams delivered;
// either echo client sending fewer than 99 % of the window's echoes.
func tailLoadProof(l tailLoad) []string {
	var why []string
	if l.frames < l.due*99/100 {
		why = append(why, fmt.Sprintf("the video generator wrote %d of about %d frames", l.frames, l.due))
	}
	if n := tailBeyond(l.late, tailLateMax); n > l.frames/100 {
		why = append(why, fmt.Sprintf("%d of %d frames started more than %v late", n, l.frames, tailLateMax))
	}
	if n := tailBeyond(l.burst, tailBurstSpanMax); n > l.frames/100 {
		why = append(why, fmt.Sprintf("%d of %d bursts took more than %v from their first write to their last (ML-100's 71 kpps within 25 %%)", n, l.frames, tailBurstSpanMax))
	}
	if l.got < l.sent*9/10 {
		why = append(why, fmt.Sprintf("the video flow delivered %d of %d datagrams (the load was not carried; see the counters above)", l.got, l.sent))
	}
	for _, e := range []struct {
		name string
		n    int
	}{{"through rendr", l.echoes}, {"of the direct baseline", l.baseEchoes}} {
		if e.n < l.echoDue*99/100 {
			why = append(why, fmt.Sprintf("the echo client %s sent %d of the window's %d echoes", e.name, e.n, l.echoDue))
		}
	}
	return why
}

// tailBeyond counts the values of s strictly above bound.
func tailBeyond(s []time.Duration, bound time.Duration) (n int) {
	for _, d := range s {
		if d > bound {
			n++
		}
	}
	return n
}

// tailVerdict is the judge's result.
type tailVerdict struct {
	sent, lost, over             int           // echoes through rendr sent in the window; lost; arrived beyond baseMedian + tailMargin
	share                        float64       // (over + lost) / sent
	baseSent, baseLost, baseOver int           // the same for the direct baseline
	baseShare                    float64       // (baseOver + baseLost) / baseSent
	baseMedian                   time.Duration // the direct baseline's median round trip
	addP50, addP99, addP999      time.Duration // rendr's quantile less the baseline's
	invalid                      []string      // why the run measured nothing about rendr (the host was not quiet, no baseline)
	fails                        []string      // the bounds exceeded (none and no invalid: PASS)
}

// tailQuantile is the nearest-rank q-quantile of the sorted s (s not
// empty, 0 < q ≤ 1).
func tailQuantile(s []time.Duration, q float64) time.Duration {
	k := int(q*float64(len(s))+0.999999999) - 1
	return s[min(max(k, 0), len(s)-1)]
}

// tailJudge judges the round trips through rendr (rendr: the arrived
// echoes; lost: those that never came back) against the direct baseline's
// (base and baseLost, the same): the share of the sent echoes in the tail
// — lost, or beyond the baseline's median plus tailMargin — must not
// exceed tailShareMax, and rendr's p99 less the baseline's must not exceed
// tailAddedP99Max. The run is INVALID when the baseline itself has more
// than tailBaseShareMax of its echoes in that tail (the host was not
// quiet: a FAIL could be the host's), or when there is no measurement.
func tailJudge(rendr []time.Duration, lost int, base []time.Duration, baseLost int) tailVerdict {
	v := tailVerdict{sent: len(rendr) + lost, lost: lost, baseSent: len(base) + baseLost, baseLost: baseLost}
	if len(base) == 0 || v.sent == 0 {
		v.invalid = append(v.invalid, fmt.Sprintf("no measurement: %d echoes through rendr, %d baseline round trips (%d baseline echoes lost)", v.sent, len(base), baseLost))
		return v
	}
	b := slices.Clone(base)
	slices.Sort(b)
	v.baseMedian = tailQuantile(b, 0.5)
	for _, d := range b {
		if d > v.baseMedian+tailMargin {
			v.baseOver++
		}
	}
	v.baseShare = float64(v.baseOver+v.baseLost) / float64(v.baseSent)
	if v.baseShare > tailBaseShareMax {
		v.invalid = append(v.invalid, fmt.Sprintf("the direct baseline itself had %.4f %% of its echoes in the tail (%d lost, %d more than %v above its median %v), above %.3f %%: the host was not quiet",
			100*v.baseShare, v.baseLost, v.baseOver, tailMargin, v.baseMedian, 100*tailBaseShareMax))
	}
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

// TestL4UTailJudge (the diagnostic's judge and load proof; C1): the tail
// is measured against the baseline's median (not rendr's own), strictly
// beyond tailMargin; a lost echo counts in the tail; the share bound and
// the p99 bound are exceeded only strictly; the added quantiles are
// rendr's less the baseline's; a baseline with its own tail beyond half
// the share bound (lost echoes included) makes the run INVALID, not a
// FAIL; the load proof holds each of its rules strictly; the diagnostic is
// off unless RENDR_TAIL_DIAG is exactly 1.
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
		name     string
		rendr    []time.Duration
		lost     int
		base     []time.Duration
		baseLost int
		over     int
		share    float64
		addP99   time.Duration
		fail     bool
		invalid  bool
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
		{name: "a baseline tail at half the share bound is a quiet host", rendr: fill(2000, 100*us), base: with(fill(4000, 100*us), 9*time.Millisecond)},
		{name: "a baseline tail beyond half the share bound: INVALID, not a verdict", rendr: with(fill(2000, 100*us), 9*time.Millisecond, 9*time.Millisecond), base: with(base, 9*time.Millisecond), over: 2, share: 0.001, fail: true, invalid: true},
		{name: "a lost baseline echo is in its tail", rendr: fill(2000, 100*us), base: base, baseLost: 1, invalid: true},
		{name: "no baseline: INVALID", rendr: fill(10, 100*us), invalid: true},
		{name: "no echo through rendr: INVALID", base: base, invalid: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			v := tailJudge(c.rendr, c.lost, c.base, c.baseLost)
			if v.over != c.over || v.share != c.share || (len(v.fails) != 0) != c.fail || (len(v.invalid) != 0) != c.invalid || (len(c.base) > 0 && v.addP99 != c.addP99) {
				t.Fatalf("tailJudge: over %d, share %v, added p99 %v, fails %q, invalid %q; want over %d, share %v, added p99 %v, fail %v, invalid %v",
					v.over, v.share, v.addP99, v.fails, v.invalid, c.over, c.share, c.addP99, c.fail, c.invalid)
			}
		})
	}

	// The load proof: a 62-s run of the designed load (60 s in the window)
	// is the load; each rule is exceeded only strictly.
	const frames, echoes = 3720, 15000
	ok := tailLoad{frames: frames, due: frames, late: fill(frames, 100*us), burst: fill(frames, 2700*us),
		sent: frames * tailFrameDgram, got: frames * tailFrameDgram, echoDue: echoes, echoes: echoes, baseEchoes: echoes}
	for _, c := range []struct {
		name    string
		mod     func(l *tailLoad)
		invalid bool
	}{
		{name: "the designed load", mod: func(*tailLoad) {}},
		{name: "99 % of the frames due", mod: func(l *tailLoad) { l.frames = frames * 99 / 100 }},
		{name: "fewer than 99 % of the frames due", mod: func(l *tailLoad) { l.frames = frames*99/100 - 1 }, invalid: true},
		{name: "1 % of the frames late", mod: func(l *tailLoad) { l.late = with(l.late, fill(frames/100, tailLateMax+1)...) }},
		{name: "more than 1 % of the frames late", mod: func(l *tailLoad) { l.late = with(l.late, fill(frames/100+1, tailLateMax+1)...) }, invalid: true},
		{name: "every frame exactly tailLateMax late", mod: func(l *tailLoad) { l.late = fill(frames, tailLateMax) }},
		{name: "1 % of the bursts slower than 71 kpps within 25 %", mod: func(l *tailLoad) { l.burst = with(l.burst, fill(frames/100, tailBurstSpanMax+1)...) }},
		{name: "more than 1 % of the bursts slower", mod: func(l *tailLoad) { l.burst = with(l.burst, fill(frames/100+1, tailBurstSpanMax+1)...) }, invalid: true},
		{name: "every burst exactly at the span bound", mod: func(l *tailLoad) { l.burst = fill(frames, tailBurstSpanMax) }},
		{name: "90 % of the video delivered", mod: func(l *tailLoad) { l.got = l.sent * 9 / 10 }},
		{name: "less than 90 % of the video delivered", mod: func(l *tailLoad) { l.got = l.sent*9/10 - 1 }, invalid: true},
		{name: "99 % of the echoes sent by both clients", mod: func(l *tailLoad) { l.echoes, l.baseEchoes = echoes*99/100, echoes*99/100 }},
		{name: "the echo client through rendr short of 99 %", mod: func(l *tailLoad) { l.echoes = echoes*99/100 - 1 }, invalid: true},
		{name: "the baseline's echo client short of 99 %", mod: func(l *tailLoad) { l.baseEchoes = echoes*99/100 - 1 }, invalid: true},
	} {
		t.Run("load/"+c.name, func(t *testing.T) {
			l := ok
			l.late, l.burst = slices.Clone(ok.late), slices.Clone(ok.burst)
			c.mod(&l)
			if why := tailLoadProof(l); (len(why) != 0) != c.invalid || len(why) > 1 {
				t.Fatalf("tailLoadProof: %q; want invalid %v (one reason at most)", why, c.invalid)
			}
		})
	}
	if tailBurstSpanMax < 3550*us || tailBurstSpanMax > 3560*us {
		t.Fatalf("tailBurstSpanMax %v: want 1.25 × 202/71,000 s (3.556 ms)", tailBurstSpanMax)
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
