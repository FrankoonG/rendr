package lessons3

import (
	"fmt"
	"io"
	"math"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The selector self-load guard (design §8, P1, W11): bulk transfers queue
// at their own bottleneck and raise the RTT that the path's probe carrier
// measures; those samples are tagged loaded and kept out of the evidence,
// so a Peer's own traffic never causes a quality switch, in either
// direction. Application-limited traffic leaves the samples unloaded, so a
// genuine degradation still switches.
//
// The bulk scenarios use two paths with equal base delay (10 ms one way,
// G1-sel's 20 ms RTT), each a rate-limited bottleneck per direction,
// default selector and probe timings (Dwell 3 s, Cooldown 15 s,
// Probe.Interval 2 s, Probe.Fresh 10 s), and an active carrier on a. After
// an idle phase that gives both paths unloaded samples, the bulk runs at
// the link rate for 60 virtual seconds. The rate, 2 MiB/s (1 MiB/s under
// -race), keeps G1-sel's proportions: the sender's capacity cap is well
// above the 128 KiB floor, so the reverse bound of a download is well above
// the 64 KiB load threshold (§8.3).

// guardRate is the link rate of the G1-shaped bulk scenarios.
func guardRate() float64 {
	if raceEnabled {
		return mib
	}
	return 2 * mib
}

// guardBulk is one bulk scenario of the self-load guard.
type guardBulk struct {
	download bool          // passive → dialer; else dialer → passive
	disabled bool          // LoadThreshold = MaxInt64: the guard never fires (control)
	rate     float64       // link rate (bytes/s)
	dur      time.Duration // bulk duration
	// atProbePing starts the bulk the moment a's probe carrier committed a
	// PING; otherwise it starts about halfway between two of them.
	atProbePing bool
	// lead (with atProbePing): a first transfer of lead × rate bytes, in the
	// bulk's direction, starts at one of a's probe PINGs; the bulk starts at
	// the next one, after the pause the first transfer leaves.
	lead time.Duration
	// keepalive: a second selector session of the same Peer, also on a,
	// echoes 256 bytes every 20 ms throughout (about 25 KB/s each way: less
	// than the load threshold per probe interval).
	keepalive bool
}

// guardResult is what a bulk scenario observed.
type guardResult struct {
	dialer, passive rendr.MigrationCounts
	a               rendr.FactoryStatus   // the active path's evidence at the end
	srtt            time.Duration         // the session carrier's smoothed RTT on a in mid-bulk
	carried         int64                 // bulk bytes delivered while the bulk ran
	throttled       int64                 // bytes a's bottleneck paced
	onsetLoaded     bool                  // atProbePing: a's sample of the PING the bulk started at was loaded
	pause           time.Duration         // lead: from the first transfer's last byte to the bulk's start
	keepalive       rendr.MigrationCounts // the keepalive session's dialer end
}

// awaitProbePing waits until a's probe carrier committed a PING.
func awaitProbePing(t *testing.T, a *rendrtest.Link) {
	t.Helper()
	for ok := false; !ok; {
		before := a.Stats().Probe.FramesCaptured
		select {
		case <-a.CaptureNextFrame(rendrtest.Up, rendrtest.FramePing):
		case <-time.After(3 * time.Second):
			t.Fatal("a's probe carrier sent no PING for 3 s")
		}
		synctest.Wait() // the link counts the capture right after handing it over
		ok = a.Stats().Probe.FramesCaptured > before
	}
}

func runGuardBulk(t *testing.T, gb guardBulk) guardResult {
	var res guardResult
	synctest.Test(t, func(t *testing.T) {
		const delay = 10 * time.Millisecond
		var ov *testhooks.Overrides
		if gb.disabled {
			ov = &testhooks.Overrides{LoadThreshold: math.MaxInt64}
		}
		w := newWorld(t, worldConfig{
			links: []linkSpec{{name: "a", delay: delay, rate: gb.rate}, {name: "b", delay: delay, rate: gb.rate}},
			dov:   ov,
		})
		a := w.link("a")
		p := w.peer()
		dc, pc := w.open(p, rendr.ModeSelector)
		first := mustActive(t, dc, "dialer")
		if first.Name != "a" {
			t.Fatalf("initial active %+v, want a carrier of a", first)
		}
		var ka *flow
		var kc, kp *rendr.Conn
		echoed := make(chan error, 1)
		if gb.keepalive {
			kc, kp = w.open(p, rendr.ModeSelector)
			if cs := mustActive(t, kc, "keepalive dialer"); cs.Name != "a" {
				t.Fatalf("keepalive session active %+v, want a carrier of a", cs)
			}
			w.goBG(func() { echoed <- echo(kp) })
			ka = w.startFlow("keepalive", kc, kc, 289, flowOpts{chunk: 256, gap: 20 * time.Millisecond})
		}
		// Idle: both paths collect unloaded probe samples. Probing started
		// at the Dial, so a's probe PINGs fall about every 2 s after it; 7 s
		// after the Dial is about halfway between two of them.
		time.Sleep(7 * time.Second)
		for i, fs := range p.Status().Factories {
			if fs.Evidence != rendr.EvidenceFresh || fs.Samples < 3 {
				t.Fatalf("before the bulk: factory %d %+v, want fresh evidence", i, fs)
			}
		}
		from, to := dc, pc
		if gb.download {
			from, to = pc, dc
		}
		var onset rendr.FactoryStatus
		if gb.atProbePing {
			if gb.lead > 0 {
				awaitProbePing(t, a)
				lead := w.startFlow("lead", from, to, 290, flowOpts{n: int64(gb.rate * gb.lead.Seconds()), keepOpen: true})
				lead.wait(t, 10*time.Second)
				leadEnd := time.Now()
				awaitProbePing(t, a)
				res.pause = time.Since(leadEnd)
			} else {
				awaitProbePing(t, a)
			}
			onset = p.Status().Factories[0]
		}
		start := time.Now()
		bulk := w.startFlow("bulk", from, to, 291, flowOpts{})
		if gb.atProbePing {
			// a's next sample is the one of the PING the bulk started at.
			waitFor(t, time.Second, "a's sample of the PING the bulk started at", func() bool {
				return p.Status().Factories[0].Samples > onset.Samples
			})
			res.onsetLoaded = p.Status().Factories[0].LoadedSamples > onset.LoadedSamples
		}
		time.Sleep(time.Until(start.Add(gb.dur / 2)))
		if cs, ok := carrierByID(dc, first.ID); ok {
			res.srtt = cs.SRTT
		}
		time.Sleep(time.Until(start.Add(gb.dur)))
		res.carried = bulk.recvd.Load()
		bulk.stop()
		bulk.wait(t, 60*time.Second)
		res.dialer, res.passive = dc.Status().Migrations, pc.Status().Migrations
		res.a = p.Status().Factories[0]
		res.throttled = a.Stats().Throttled
		if ka != nil {
			ka.stop()
			ka.wait(t, 30*time.Second)
			if err := <-echoed; err != nil {
				t.Fatal(err)
			}
			res.keepalive = kc.Status().Migrations
			finishSession(t, kc, kp)
		}
		finishSession(t, dc, pc)
		w.finish()
	})
	return res
}

// checkGuarded asserts the three parts of a guarded bulk scenario: the
// stimulus (a's bottleneck queueing raised its RTT to at least three times
// the base, enough to qualify b as a challenger by Band and Floor), the
// load (the bulk ran at the link rate) and the guard's effect (no quality
// switch on either end; a's loaded samples were excluded).
func checkGuarded(t *testing.T, gb guardBulk, r guardResult) {
	t.Helper()
	t.Logf("bulk %d bytes, mid-bulk srtt on a %v, a %+v, migrations %+v / %+v", r.carried, r.srtt, r.a, r.dialer, r.passive)
	if r.srtt < 60*time.Millisecond || r.throttled == 0 {
		t.Fatalf("stimulus: mid-bulk srtt on a %v, %d bytes paced; want queueing far above the 20 ms base RTT", r.srtt, r.throttled)
	}
	if want := int64(0.9 * gb.rate * gb.dur.Seconds()); r.carried < want {
		t.Fatalf("load: %d bytes in %v, want ≥ %d (90%% of the link rate)", r.carried, gb.dur, want)
	}
	if r.dialer.Quality != 0 || r.passive.Quality != 0 || r.dialer.Death+r.dialer.Explicit != 0 || r.keepalive != (rendr.MigrationCounts{}) {
		t.Fatalf("migrations dialer %+v, passive %+v, keepalive session %+v: the bulk caused a switch", r.dialer, r.passive, r.keepalive)
	}
	if r.a.LoadedSamples == 0 {
		t.Fatalf("a's probe evidence %+v: no sample was tagged loaded", r.a)
	}
}

// TestBulkDownloadNoQualitySwitch_L29: the passive sends bulk to the dialer
// at the link rate for 60 s (G1-sel's shape, §8.3). The dialer itself has
// nothing in flight; the guard sees the reverse bound rxRate × srtt and the
// passive's BUSY flag: a's samples are loaded, its evidence is held at its
// pre-load value, and the idle path b with the same base RTT never wins.
// The guard-disabled control run (LoadThreshold = MaxInt64) shows that the
// same stimulus does cause a quality switch without the guard (L60).
//
// The low-bdp case is a 512 KiB/s download at a 20 ms RTT: the passive's
// capacity sits at its 128 KiB floor, so the reverse bound rxRate × srtt
// alone hovered around the load threshold while the passive was saturated;
// a peer that reports BUSY now counts at least the capacity floor (design
// §0.13 A5). Both cases start halfway between two of a's probe PINGs; a
// download that starts right at a probe PING is TestDownloadGuardEdges_L29.
func TestBulkDownloadNoQualitySwitch_L29(t *testing.T) {
	t.Run("guarded", func(t *testing.T) {
		gb := guardBulk{download: true, rate: guardRate(), dur: 60 * time.Second}
		checkGuarded(t, gb, runGuardBulk(t, gb))
	})
	t.Run("low-bdp", func(t *testing.T) {
		gb := guardBulk{download: true, rate: 512 * kib, dur: 60 * time.Second}
		checkGuarded(t, gb, runGuardBulk(t, gb))
	})
	t.Run("guard-disabled-control", func(t *testing.T) {
		gb := guardBulk{download: true, disabled: true, rate: guardRate(), dur: 60 * time.Second}
		r := runGuardBulk(t, gb)
		t.Logf("control: bulk %d bytes, mid-bulk srtt on a %v, migrations %+v / %+v, a %+v", r.carried, r.srtt, r.dialer, r.passive, r.a)
		if r.dialer.Quality < 1 || r.passive.Quality != r.dialer.Quality {
			t.Fatalf("control: migrations dialer %+v, passive %+v; want the unguarded bulk to cause a quality switch", r.dialer, r.passive)
		}
		if r.a.LoadedSamples != 0 {
			t.Fatalf("control: %d samples tagged loaded with the guard disabled", r.a.LoadedSamples)
		}
	})
}

// TestDownloadGuardEdges_L29: downloads in the shape of
// TestBulkDownloadNoQualitySwitch_L29 that start right at one of a's probe
// PINGs (design §0.13 A7a, §8.2 volume rule). The PING's PONG enters the
// down bottleneck one one-way delay after the commit, behind the rest of
// the passive's first burst (its capacity: the 128 KiB floor after an idle
// phase), and waits for it to drain: about 52 ms at 2 MiB/s, so the sample
// measures about 72 ms against a base of 20 ms. When the PONG arrives the
// gauge still holds nothing — no forward bytes in flight (a download), a
// reverse bound of 0 (rxRate is refreshed only when the dialer's own
// session carrier receives a PONG, behind the same burst) and no backlog
// (the passive's first BUSY PING is still on its way) — so the
// instantaneous rule took the sample as unloaded; with only the few
// unloaded samples of the idle phase in a's window it lifted a's mean
// enough for b (20 ms) to qualify, and the switch followed one dwell
// later. The volume rule tags it loaded: the burst itself crossed a's
// session carrier during the flight. Every subtest requires that sample to
// be loaded and no switch; on the code before the volume rule each fails
// with one quality switch on each end (L60: the stimulus is real). The
// guard-disabled control of TestBulkDownloadNoQualitySwitch_L29 disables
// the volume rule too (it shares LoadThreshold).
//
//   - start-at-probe-ping: the download starts after the idle phase.
//   - restart-at-probe-ping: a first transfer of 1.75 s at the link rate
//     starts at one probe PING and the download restarts at the next one,
//     after a pause of about 0.24 s: the first transfer dominates the
//     interval before the commit, but nothing moved after its backlog
//     ended, so the volume rule does not take the traffic for established
//     application-limited flow (the restart's capacity, grown during the
//     first transfer, queues about 512 KiB ahead of the PONG).
//   - restart-short-pause: the same with a first transfer of 1.97 s, which
//     leaves a pause of about 17 ms: shorter than LoadThreshold takes at the
//     link rate (31 ms at 2 MiB/s, 62 ms at 1 MiB/s), so the silence before
//     the commit does not reveal the restart, and long enough for the first
//     transfer's backlog report to have cleared, so the instantaneous rule
//     does not either. A volume rule that only asked whether the interval's
//     rate fills a flight without a silence misses it.
//   - restart-with-keepalives: a first transfer of 1.5 s, while a second
//     session of the same Peer echoes 256 bytes every 20 ms on a throughout:
//     the carriers are never silent for long, but less than LoadThreshold
//     moved after the first transfer's backlog ended, so the traffic is not
//     established. A rule that estimated that volume from the interval's
//     rate took it for established and switched.
//
// The window exists only while the first capacity drains slower than about
// one one-way delay (128 KiB per 10 ms, about 12.8 MB/s at a 20 ms RTT): at
// G1-sel's 200 Mbit/s the first sample measures 20.0 ms.
func TestDownloadGuardEdges_L29(t *testing.T) {
	for _, tc := range []struct {
		name      string
		lead      time.Duration
		keepalive bool
	}{
		{"start-at-probe-ping", 0, false},
		{"restart-at-probe-ping", 1750 * time.Millisecond, false},
		{"restart-short-pause", 1970 * time.Millisecond, false},
		{"restart-with-keepalives", 1500 * time.Millisecond, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gb := guardBulk{download: true, rate: guardRate(), dur: 30 * time.Second, atProbePing: true, lead: tc.lead, keepalive: tc.keepalive}
			// The first transfer starts after an idle phase at the capacity
			// floor; how long its ramp takes depends on the phase of the
			// PINGs that prove the rate, a scheduling detail of the bubble,
			// and varies by about one RTT (20 ms) — about as much as the
			// short pause's whole window. A run whose pause misses the
			// window is repeated, at most edgeAttempts times; the
			// assertions below apply to the run whose stimulus holds.
			var r guardResult
			for attempt := 1; ; attempt++ {
				r = runGuardBulk(t, gb)
				if tc.lead > 0 {
					t.Logf("pause between the transfers %v", r.pause)
				}
				miss := edgeStimulus(tc.name, gb, r.pause)
				if miss == "" {
					break
				}
				if attempt == edgeAttempts {
					t.Fatalf("stimulus: %s (attempt %d of %d)", miss, attempt, edgeAttempts)
				}
				t.Logf("stimulus missed in attempt %d: %s; the run is repeated", attempt, miss)
			}
			checkGuarded(t, gb, r)
			if !r.onsetLoaded {
				t.Fatalf("a's sample of the PING the download started at was unloaded: %+v", r.a)
			}
		})
	}
}

// edgeAttempts bounds the runs of one TestDownloadGuardEdges_L29 case whose
// stimulus misses its window (a miss happened in about 1 of 10 runs of
// restart-short-pause).
const edgeAttempts = 4

// edgeStimulus reports why a run of case name with pause between the
// transfers misses the case's stimulus ("" when it holds).
func edgeStimulus(name string, gb guardBulk, pause time.Duration) string {
	if gb.lead <= 0 {
		return ""
	}
	if pause <= 0 || pause >= time.Second {
		return fmt.Sprintf("pause %v between the transfers, want a fraction of the 2 s probe interval", pause)
	}
	// The short pause must stay where only the volume moved since the
	// backlog ended reveals the restart: after the first transfer's backlog
	// report cleared (it had not at 8 ms at 2 MiB/s, nor at 2 ms at
	// 1 MiB/s) and shorter than LoadThreshold takes at the link rate.
	if short := time.Duration(float64(64*kib) / gb.rate * float64(time.Second)); name == "restart-short-pause" && (pause < 12*time.Millisecond || pause >= short) {
		return fmt.Sprintf("pause %v, want at least 12 ms and less than %v", pause, short)
	}
	return ""
}

// TestBulkUploadNoQualitySwitch_L29: the mirrored case (§8.3 "upload bulk
// A→B"): the dialer sends bulk at the link rate for 60 s; its own carrier
// holds at least the capacity floor unproven and is cap-blocked, so a's
// samples are loaded and no quality switch follows.
func TestBulkUploadNoQualitySwitch_L29(t *testing.T) {
	gb := guardBulk{rate: guardRate(), dur: 60 * time.Second}
	checkGuarded(t, gb, runGuardBulk(t, gb))
}

// TestAppLimitedDegradationSwitches_L29: the moved M1a scenario
// TestSelectorMigratesOnDegradation in virtual time (§8.1 item 2, §8.3):
// the dialer echoes 256 KiB/s through the passive over p1 (2 ms one way;
// p2: 5 ms) with the fixture's timings (§11.3); halfway p1 degrades to
// 150 ms one way. The flow stays application-limited — its writes return
// at once and its in-flight stays below the capacity cap, so no carrier is
// backlogged — so p1's samples stay unloaded although about 90 KiB is
// unproven in flight, and the selector migrates to p2.
func TestAppLimitedDegradationSwitches_L29(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ov := &testhooks.Overrides{
			DeadMin: time.Second, DeadMax: 2 * time.Second, WriteStall: time.Second, PingIdle: 500 * time.Millisecond,
			ProbeInterval: 200 * time.Millisecond, ProbeFresh: 2 * time.Second,
			SelectorDwell: time.Second, SelectorCooldown: 2 * time.Second, RetireGrace: 500 * time.Millisecond,
		}
		w := newWorld(t, worldConfig{
			links: []linkSpec{{name: "p1", delay: 2 * time.Millisecond}, {name: "p2", delay: 5 * time.Millisecond}},
			dov:   ov,
		})
		p := w.peer()
		dc, pc := w.open(p, rendr.ModeSelector)
		if cs := mustActive(t, dc, "dialer"); cs.Name != "p1" {
			t.Fatalf("initial active %+v, want p1", cs)
		}
		echoed := make(chan error, 1)
		w.goBG(func() { echoed <- echo(pc) })
		const rate, dur = 256 * kib, 10 * time.Second
		f := w.startFlow("echo", dc, dc, 292, flowOpts{chunk: 4 * kib, gap: time.Duration(float64(time.Second) * 4 * kib / rate)})
		time.Sleep(dur / 2)
		mark := w.dev.mark()
		degraded := time.Now()
		w.link("p1").SetDelay(150*time.Millisecond, 0)
		ev := w.dev.wait(t, mark, dur/2, "the quality switch off the degraded p1", isKind(rendr.EventMigration, dc.ID()))
		if cs := mustActive(t, dc, "dialer"); ev.Cause != rendr.CauseQuality || cs.Name != "p2" || ev.To != cs.ID {
			t.Fatalf("migration %+v, active %+v; want a quality switch to p2", ev, cs)
		}
		t.Logf("switched to p2 %v after the degradation", ev.Time.Sub(degraded))
		time.Sleep(degraded.Add(dur / 2).Sub(time.Now()))
		f.stop()
		f.wait(t, 30*time.Second)
		if err := <-echoed; err != nil {
			t.Fatal(err)
		}
		if want := int64(0.9 * rate * dur.Seconds()); f.recvd.Load() < want {
			t.Fatalf("offered load %d bytes echoed, want ≥ %d (%d KiB/s for %v)", f.recvd.Load(), want, rate/kib, dur)
		}
		if s := w.link("p1").Stats().Session; s.MaxDelay < 150*time.Millisecond {
			t.Fatalf("stimulus: no session carrier on p1 was delayed 150 ms: %+v", s)
		}
		p1 := p.Status().Factories[0]
		if p1.LoadedSamples != 0 {
			t.Fatalf("p1 %+v: the application-limited echo was taken for self-load", p1)
		}
		wantMigrations(t, "dialer", dc, rendr.MigrationCounts{Quality: 1})
		waitFor(t, time.Second, "the passive counting the quality switch", func() bool {
			return pc.Status().Migrations == rendr.MigrationCounts{Quality: 1}
		})
		finishSession(t, dc, pc)
		w.finish()
	})
}

// TestAppLimitedAboveCapFloorSwitches_L29: the application-limited case of
// §8.1 item 2 with a flow whose in-flight outgrows its capacity once the
// path degrades (the volume rule's backlog clause, design §0.13 A7a). The
// dialer echoes 1 MiB/s in 64 KiB writes through the passive over a (5 ms
// one way; b: 15 ms), both 50 Mbit/s, default timings; after 20 s a
// degrades to 150 ms one way. About 300 KiB is then unproven in flight
// each way, more than the capacity a carrier derives from its 10 ms
// minimum RTT, so the writers wait at their caps now and then: the
// carriers cycle through backlog episodes and the samples committed in one
// are loaded. The first sample after the degradation, committed about
// 0.2 s after an episode ended, carries about 0.7 MiB in its flight but is
// unloaded — the flow moved far more than LoadThreshold since that episode
// ended — and with a's earlier samples at about 28 ms (they wait behind the
// echo's 64 KiB writes at the 50 Mbit/s bottleneck) it lets b (30 ms)
// qualify: the selector switches within Dwell + 2·Probe.Interval + the
// degraded RTT of the degradation (plan §3.9's bound), as without the
// volume rule. A backlog clause that loaded every sample committed within
// one flight of the end of an episode switched in 8 of 20 runs within 20 s,
// none within 9 s.
func TestAppLimitedAboveCapFloorSwitches_L29(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const linkRate = 50e6 / 8
		w := newWorld(t, worldConfig{
			links: []linkSpec{{name: "a", delay: 5 * time.Millisecond, rate: linkRate}, {name: "b", delay: 15 * time.Millisecond, rate: linkRate}},
		})
		p := w.peer()
		dc, pc := w.open(p, rendr.ModeSelector)
		if cs := mustActive(t, dc, "dialer"); cs.Name != "a" {
			t.Fatalf("initial active %+v, want a", cs)
		}
		echoed := make(chan error, 1)
		w.goBG(func() { echoed <- echo(pc) })
		const rate, chunk = mib, 64 * kib
		start := time.Now()
		f := w.startFlow("echo", dc, dc, 294, flowOpts{chunk: chunk, gap: time.Duration(float64(time.Second) * chunk / rate)})
		time.Sleep(20 * time.Second)
		before := p.Status().Factories[0]
		if before.Evidence != rendr.EvidenceFresh || before.LoadedSamples != 0 {
			t.Fatalf("before the degradation: a %+v, want fresh unloaded evidence", before)
		}
		mark := w.dev.mark()
		degraded := time.Now()
		w.link("a").SetDelay(150*time.Millisecond, 0)
		bound := 3*time.Second + 2*2*time.Second + 300*time.Millisecond // Dwell + 2·Probe.Interval + RTT
		ev := w.dev.wait(t, mark, bound, "the quality switch off the degraded a", isKind(rendr.EventMigration, dc.ID()))
		if cs := mustActive(t, dc, "dialer"); ev.Cause != rendr.CauseQuality || cs.Name != "b" || ev.To != cs.ID {
			t.Fatalf("migration %+v, active %+v; want a quality switch to b", ev, cs)
		}
		t.Logf("switched to b %v after the degradation", ev.Time.Sub(degraded))
		time.Sleep(time.Second)
		after := p.Status().Factories[0]
		f.stop()
		f.wait(t, 30*time.Second)
		if err := <-echoed; err != nil {
			t.Fatal(err)
		}
		if want := int64(0.9 * rate * time.Since(start).Seconds()); f.recvd.Load() < want {
			t.Fatalf("load: %d bytes echoed in %v, want ≥ %d", f.recvd.Load(), time.Since(start), want)
		}
		if s := w.link("a").Stats().Session; s.MaxDelay < 150*time.Millisecond {
			t.Fatalf("stimulus: no session carrier on a was delayed 150 ms: %+v", s)
		}
		if after.LoadedSamples == 0 {
			t.Fatalf("stimulus: a %+v: no backlog episode loaded a sample after the degradation", after)
		}
		wantMigrations(t, "dialer", dc, rendr.MigrationCounts{Quality: 1})
		waitFor(t, time.Second, "the passive counting the quality switch", func() bool {
			return pc.Status().Migrations == rendr.MigrationCounts{Quality: 1}
		})
		finishSession(t, dc, pc)
		w.finish()
	})
}

// echo copies everything the passive application reads back to the dialer
// until io.EOF, then half-closes.
func echo(c *rendr.Conn) error {
	buf := make([]byte, 32*kib)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			if _, werr := c.Write(buf[:n]); werr != nil {
				return fmt.Errorf("echo: write: %w", werr)
			}
		}
		switch {
		case err == io.EOF:
			return c.CloseWrite()
		case err != nil:
			return fmt.Errorf("echo: read: %w", err)
		}
	}
}
