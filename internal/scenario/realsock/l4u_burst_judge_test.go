package realsock

import (
	"fmt"
	"math"
	"math/rand/v2"
	"slices"
	"strconv"
	"testing"
	"time"
)

// The plan, judge and load proof of TestL4UBurstDiag
// (l4u_burst_linux_test.go; M6 delegate decisions during wave E, item rc4,
// "rendr's p99 under ML-100's bursts"): pure functions of the measured
// run, so that their bounds are proven on every host, while the
// diagnostic itself runs only on a quiet Linux pool worker.

// ML-100's video shape (m6-design §B3.1, as the G10 harness generates it:
// 1,376 data bytes per 1,408-byte shard, FEC blocks of at most 212 data
// shards with ⌈0.2 × data⌉ parity each, a 4× IDR every 600 frames and a
// requested one every 30 s).
const (
	burstMeanFrame = 208333
	burstShardData = 1376
	burstBlockData = 212
	burstSigma     = 0.25
	burstIDRScale  = 4
	burstIDREvery  = 600
	burstReqEvery  = 1800 // 30 s at 60 fps
	burstClipLo    = 0.25
	burstClipHi    = 3.0
)

// The control flow (ENet's shape, §B3.1): an input of 48 bytes from the
// client every 4 ms, a 40-byte ack from the host for each input, a
// 256-byte feedback from the host every 100 ms.
const (
	burstInputEvery = 4 * time.Millisecond
	burstInputSize  = 48
	burstAckSize    = 40
	burstFeedEvery  = 100 * time.Millisecond
	burstFeedSize   = 256
	// burstHeader is the diagnostic's own header: seq 8, send instant 8,
	// frame 4, position in the frame 2, the frame's datagrams 2.
	burstHeader = 24
)

const (
	// burstAddedP99Max bounds rendr's added p99 on loopback for every
	// judged class (video down, control down, control up): rendr's p99
	// less the direct path's, on the same schedule at the same time (the
	// rc4 target: well below 1 ms on loopback; I2's echo bound).
	burstAddedP99Max = 500 * time.Microsecond
	// burstQuietMargin and burstQuietShareMax: the direct path is not
	// quiet (the run is INVALID) when more than burstQuietShareMax of its
	// datagrams of a class arrived more than burstQuietMargin above its
	// median, or were lost.
	burstQuietMargin   = 4 * time.Millisecond
	burstQuietShareMax = 0.00025
	// burstLossShareMax: rendr may lose at most this share more than the
	// direct path of a class (loopback with 4-MiB and larger buffers
	// loses none).
	burstLossShareMax = 0.0001
)

// burstFrame is one video frame of the plan: its datagrams and kind.
type burstFrame struct {
	n   int  // datagrams (data and parity shards)
	idr bool // a periodic or requested IDR
}

// burstShards returns the datagrams of a frame of size bytes: its data
// shards in blocks of at most burstBlockData, each block with
// ⌈0.2 × its data⌉ parity shards.
func burstShards(size int) int {
	d := (size + burstShardData - 1) / burstShardData
	n := 0
	for d > 0 {
		b := min(d, burstBlockData)
		n += b + (b+4)/5
		d -= b
	}
	return n
}

// burstPlan returns count frames of shape: "fixed" is the wave-D tail
// diagnostic's 203 datagrams per frame; "ml100" draws ML-100's sizes
// (lognormal, mean 1, σ 0.25, clipped to [0.25, 3]) from a fixed seed, so
// that the paths compared carry the same frames, with an IDR of 4× the
// mean every 600 frames and a requested one every 30 s.
func burstPlan(shape string, count int) ([]burstFrame, error) {
	out := make([]burstFrame, count)
	switch shape {
	case "fixed":
		for i := range out {
			out[i] = burstFrame{n: tailFrameDgram}
		}
	case "ml100":
		rng := rand.New(rand.NewPCG(0x6d6c313030, 0x72633400))
		idr := burstShards(burstIDRScale * burstMeanFrame)
		for i := range out {
			x := math.Exp(burstSigma*rng.NormFloat64() - burstSigma*burstSigma/2)
			x = min(max(x, burstClipLo), burstClipHi)
			out[i] = burstFrame{n: burstShards(int(x * burstMeanFrame))}
			if i%burstIDREvery == 0 || i%burstReqEvery == burstReqEvery/2 {
				out[i] = burstFrame{n: idr, idr: true}
			}
		}
	default:
		return nil, fmt.Errorf("RENDR_TAIL_SHAPE=%q: want ml100 or fixed", shape)
	}
	return out, nil
}

// burstSpanMax bounds a frame's first-to-last write: 71 kpps within 25 %.
func burstSpanMax(n int) time.Duration {
	return time.Duration(max(n-1, 0)) * time.Second / 71000 * 5 / 4
}

// burstCfg is the burst diagnostic's own configuration (the switches of
// tailCfg apply too).
type burstCfg struct {
	shape string        // RENDR_TAIL_SHAPE: ml100 (default) or fixed
	prof  string        // RENDR_TAIL_PROF: a directory for the profiles ("" none)
	trace time.Duration // RENDR_TAIL_TRACE: the runtime trace's span in seconds when profiling (default 1; 0 none)
}

// burstDiagConfig reads the burst diagnostic's environment.
func burstDiagConfig(getenv func(string) string) (burstCfg, error) {
	c := burstCfg{shape: "ml100", prof: getenv("RENDR_TAIL_PROF"), trace: time.Second}
	if v := getenv("RENDR_TAIL_SHAPE"); v != "" {
		c.shape = v
	}
	if _, err := burstPlan(c.shape, 0); err != nil {
		return c, err
	}
	if v := getenv("RENDR_TAIL_TRACE"); v != "" {
		k, err := strconv.Atoi(v)
		if err != nil || k < 0 || k > 10 {
			return c, fmt.Errorf("RENDR_TAIL_TRACE=%q: want 0 … 10 seconds", v)
		}
		c.trace = time.Duration(k) * time.Second
	}
	return c, nil
}

// burstClass is one class's measurement on one path: the one-way delays of
// the datagrams sent in the window that arrived, and how many of them were
// sent.
type burstClass struct {
	delays []time.Duration
	sent   int
}

// burstVerdict is one class's comparison of rendr with the direct path.
type burstVerdict struct {
	name                    string
	rP50, rP99, rP999, rMax time.Duration // rendr's quantiles
	dP50, dP99, dP999, dMax time.Duration // the direct path's
	addP50, addP99, addP999 time.Duration // rendr's less the direct path's
	rLost, dLost            int
	rSent, dSent            int
	dOver                   int     // direct datagrams beyond its median + burstQuietMargin
	dShare                  float64 // (dOver + dLost) / dSent
	invalid, fails          []string
}

// burstJudge compares one class of rendr's path with the direct path's:
// INVALID when either measured nothing or the direct path was not quiet;
// FAIL when rendr's p99 less the direct path's exceeds burstAddedP99Max,
// or rendr lost a larger share than the direct path by more than
// burstLossShareMax.
func burstJudge(name string, r, d burstClass) burstVerdict {
	v := burstVerdict{name: name, rSent: r.sent, dSent: d.sent, rLost: r.sent - len(r.delays), dLost: d.sent - len(d.delays)}
	if len(r.delays) == 0 || len(d.delays) == 0 || r.sent < len(r.delays) || d.sent < len(d.delays) {
		v.invalid = append(v.invalid, fmt.Sprintf("%s: no measurement (%d of %d through rendr, %d of %d direct)", name, len(r.delays), r.sent, len(d.delays), d.sent))
		return v
	}
	rs, ds := slices.Clone(r.delays), slices.Clone(d.delays)
	slices.Sort(rs)
	slices.Sort(ds)
	v.rP50, v.rP99, v.rP999, v.rMax = tailQuantile(rs, 0.5), tailQuantile(rs, 0.99), tailQuantile(rs, 0.999), rs[len(rs)-1]
	v.dP50, v.dP99, v.dP999, v.dMax = tailQuantile(ds, 0.5), tailQuantile(ds, 0.99), tailQuantile(ds, 0.999), ds[len(ds)-1]
	v.addP50, v.addP99, v.addP999 = v.rP50-v.dP50, v.rP99-v.dP99, v.rP999-v.dP999
	k, _ := slices.BinarySearch(ds, v.dP50+burstQuietMargin+1)
	v.dOver = len(ds) - k
	v.dShare = float64(v.dOver+v.dLost) / float64(v.dSent)
	if v.dShare > burstQuietShareMax {
		v.invalid = append(v.invalid, fmt.Sprintf("%s: the direct path had %.4f %% of its datagrams lost (%d) or more than %v above its median %v (%d), above %.3f %%: the host was not quiet",
			name, 100*v.dShare, v.dLost, burstQuietMargin, v.dP50, v.dOver, 100*burstQuietShareMax))
	}
	if v.addP99 > burstAddedP99Max {
		v.fails = append(v.fails, fmt.Sprintf("%s: rendr added %v at p99 (%v against %v), above %v", name, v.addP99, v.rP99, v.dP99, burstAddedP99Max))
	}
	if rl, dl := float64(v.rLost)/float64(v.rSent), float64(v.dLost)/float64(v.dSent); rl-dl > burstLossShareMax {
		v.fails = append(v.fails, fmt.Sprintf("%s: rendr lost %d of %d (%.4f %%), the direct path %d of %d", name, v.rLost, v.rSent, 100*rl, v.dLost, v.dSent))
	}
	return v
}

// burstLoad is the load a run produced on one path: the video frames due
// and written, each frame's start after its due instant and its
// first-to-last write, and the frames' datagram counts.
type burstLoad struct {
	name        string
	due, frames int
	late, span  []time.Duration
	sizes       []int // each written frame's datagrams (span's bound)
}

// burstLoadProof returns why a path's load was not the designed one: fewer
// than 99 % of the frames due written; more than 1 % of them starting more
// than tailLateMax late, or writing their datagrams slower than 71 kpps
// within 25 %.
func burstLoadProof(l burstLoad) []string {
	var why []string
	if l.frames < l.due*99/100 {
		why = append(why, fmt.Sprintf("%s: the video generator wrote %d of about %d frames", l.name, l.frames, l.due))
	}
	if n := tailBeyond(l.late, tailLateMax); n > l.frames/100 {
		why = append(why, fmt.Sprintf("%s: %d of %d frames started more than %v late", l.name, n, l.frames, tailLateMax))
	}
	slow := 0
	for i, s := range l.span {
		if i < len(l.sizes) && s > burstSpanMax(l.sizes[i]) {
			slow++
		}
	}
	if slow > l.frames/100 {
		why = append(why, fmt.Sprintf("%s: %d of %d frames wrote their datagrams slower than 71 kpps within 25 %%", l.name, slow, l.frames))
	}
	return why
}

// TestL4UBurstJudge (rc4's burst diagnostic: its plan, judge, load proof
// and switches): the ML-100 plan is ML-100's (mean, IDRs, block split) and
// the same on every call; the added quantiles are rendr's less the direct
// path's; the p99 bound and the loss bound are exceeded only strictly; a
// direct path that is not quiet makes the run INVALID, not a verdict; the
// load proof holds each rule strictly; the switches parse.
func TestL4UBurstJudge(t *testing.T) {
	const us = time.Microsecond
	if n := burstShards(4 * burstMeanFrame); n != 729 {
		t.Fatalf("an IDR has %d datagrams, want 729 (G10's records)", n)
	}
	if n := burstShards(212 * burstShardData); n != 212+43 {
		t.Fatalf("one full block: %d datagrams, want 255", n)
	}
	p, err := burstPlan("ml100", 36000)
	if err != nil {
		t.Fatal(err)
	}
	q, _ := burstPlan("ml100", 36000)
	if !slices.Equal(p, q) {
		t.Fatal("burstPlan: two calls differ (the paths would carry different frames)")
	}
	var total, idrs int
	for i, f := range p {
		total += f.n
		if f.idr != (i%burstIDREvery == 0 || i%burstReqEvery == burstReqEvery/2) {
			t.Fatalf("frame %d: idr %v", i, f.idr)
		}
		if f.idr {
			idrs++
		}
	}
	if mean := float64(total) / float64(len(p)); mean < 180 || mean > 190 || idrs != 80 {
		t.Fatalf("ML-100 plan: %.1f datagrams per frame, %d IDRs in 10 min; want ≈ 184 (151 data + 31 parity, IDRs included) and 80", mean, idrs)
	}
	if f, _ := burstPlan("fixed", 3); !slices.Equal(f, []burstFrame{{n: 203}, {n: 203}, {n: 203}}) {
		t.Fatalf("fixed plan %v", f)
	}

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
	cls := func(ds []time.Duration, lost int) burstClass { return burstClass{delays: ds, sent: len(ds) + lost} }
	base := fill(10000, 100*us)
	for _, c := range []struct {
		name    string
		r, d    burstClass
		addP99  time.Duration
		fail    bool
		invalid bool
	}{
		{name: "equal", r: cls(fill(10000, 100*us), 0), d: cls(base, 0)},
		{name: "added p99 at the bound", r: cls(fill(10000, 100*us+burstAddedP99Max), 0), d: cls(base, 0), addP99: burstAddedP99Max},
		{name: "added p99 beyond the bound", r: cls(fill(10000, 100*us+burstAddedP99Max+1), 0), d: cls(base, 0), addP99: burstAddedP99Max + 1, fail: true},
		{name: "added p99 is the quantiles' difference", r: cls(fill(10000, 700*us), 0), d: cls(with(base, fill(101, 400*us)...), 0), addP99: 300 * us},
		{name: "rendr's loss at the loss bound", r: cls(fill(9999, 100*us), 1), d: cls(base, 0)},
		{name: "rendr's loss beyond the loss bound", r: cls(fill(9998, 100*us), 2), d: cls(base, 0), fail: true},
		{name: "a direct path quiet at its bound", r: cls(fill(10000, 100*us), 0), d: cls(with(fill(8000, 100*us), 100*us+burstQuietMargin+1, 100*us+burstQuietMargin+1), 0)},
		{name: "exactly the quiet margin is not beyond it", r: cls(fill(10000, 100*us), 0), d: cls(with(base, fill(10, 100*us+burstQuietMargin)...), 0)},
		{name: "a direct path not quiet: INVALID", r: cls(fill(10000, 100*us), 0), d: cls(with(base, fill(3, 9*time.Millisecond)...), 0), invalid: true},
		{name: "a lost direct datagram counts in its tail", r: cls(fill(10000, 100*us), 0), d: cls(fill(9997, 100*us), 3), invalid: true},
		{name: "nothing through rendr: INVALID", r: cls(nil, 10), d: cls(base, 0), invalid: true},
		{name: "nothing direct: INVALID", r: cls(base, 0), d: cls(nil, 0), invalid: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			v := burstJudge("video", c.r, c.d)
			if (len(v.fails) != 0) != c.fail || (len(v.invalid) != 0) != c.invalid || (len(v.invalid) == 0 && v.addP99 != c.addP99) {
				t.Fatalf("burstJudge: added p99 %v, fails %q, invalid %q; want added p99 %v, fail %v, invalid %v", v.addP99, v.fails, v.invalid, c.addP99, c.fail, c.invalid)
			}
		})
	}

	// The load proof: 3,600 frames of 200 datagrams due and written on
	// schedule is the load; each rule is exceeded only strictly.
	const frames = 3600
	sizes := make([]int, frames)
	for i := range sizes {
		sizes[i] = 200
	}
	ok := burstLoad{name: "rendr", due: frames, frames: frames, late: fill(frames, 100*us), span: fill(frames, 2800*us), sizes: sizes}
	for _, c := range []struct {
		name    string
		mod     func(l *burstLoad)
		invalid bool
	}{
		{name: "the designed load", mod: func(*burstLoad) {}},
		{name: "99 % of the frames due", mod: func(l *burstLoad) { l.frames = frames * 99 / 100 }},
		{name: "fewer than 99 % of the frames due", mod: func(l *burstLoad) { l.frames = frames*99/100 - 1 }, invalid: true},
		{name: "1 % of the frames late", mod: func(l *burstLoad) { l.late = with(l.late, fill(frames/100, tailLateMax+1)...) }},
		{name: "more than 1 % of the frames late", mod: func(l *burstLoad) { l.late = with(l.late, fill(frames/100+1, tailLateMax+1)...) }, invalid: true},
		{name: "1 % of the frames slow", mod: func(l *burstLoad) { l.span = with(l.span, fill(frames/100, burstSpanMax(200)+1)...) }},
		{name: "more than 1 % of the frames slow", mod: func(l *burstLoad) { l.span = with(l.span, fill(frames/100+1, burstSpanMax(200)+1)...) }, invalid: true},
		{name: "every frame exactly at its span bound", mod: func(l *burstLoad) { l.span = fill(frames, burstSpanMax(200)) }},
	} {
		t.Run("load/"+c.name, func(t *testing.T) {
			l := ok
			l.late, l.span = slices.Clone(ok.late), slices.Clone(ok.span)
			c.mod(&l)
			if why := burstLoadProof(l); (len(why) != 0) != c.invalid || len(why) > 1 {
				t.Fatalf("burstLoadProof: %q; want invalid %v (one reason at most)", why, c.invalid)
			}
		})
	}
	if b := burstSpanMax(203); b != tailBurstSpanMax {
		t.Fatalf("burstSpanMax(203) %v, want the tail diagnostic's %v", b, tailBurstSpanMax)
	}

	// The switches.
	for _, c := range []struct {
		env  map[string]string
		want burstCfg
		err  bool
	}{
		{env: nil, want: burstCfg{shape: "ml100", trace: time.Second}},
		{env: map[string]string{"RENDR_TAIL_SHAPE": "fixed", "RENDR_TAIL_PROF": "artifacts", "RENDR_TAIL_TRACE": "0"}, want: burstCfg{shape: "fixed", prof: "artifacts"}},
		{env: map[string]string{"RENDR_TAIL_SHAPE": "idr"}, err: true},
		{env: map[string]string{"RENDR_TAIL_TRACE": "11"}, err: true},
	} {
		got, err := burstDiagConfig(func(k string) string { return c.env[k] })
		if (err != nil) != c.err || (err == nil && got != c.want) {
			t.Fatalf("burstDiagConfig(%v) = %+v, %v; want %+v (error %v)", c.env, got, err, c.want, c.err)
		}
	}
}
