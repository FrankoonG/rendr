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
}

// guardResult is what a bulk scenario observed.
type guardResult struct {
	dialer, passive rendr.MigrationCounts
	a               rendr.FactoryStatus // the active path's evidence at the end
	srtt            time.Duration       // the session carrier's smoothed RTT on a in mid-bulk
	carried         int64               // bulk bytes delivered while the bulk ran
	throttled       int64               // bytes a's bottleneck paced
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
		// Idle: both paths collect unloaded probe samples. Probing started
		// at the Dial, so a's probe PINGs fall about every 2 s after it; 7 s
		// after the Dial is about halfway between two of them.
		time.Sleep(7 * time.Second)
		for i, fs := range p.Status().Factories {
			if fs.Evidence != rendr.EvidenceFresh || fs.Samples < 3 {
				t.Fatalf("before the bulk: factory %d %+v, want fresh evidence", i, fs)
			}
		}
		if gb.atProbePing {
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
		from, to := dc, pc
		if gb.download {
			from, to = pc, dc
		}
		bulk := w.startFlow("bulk", from, to, 291, flowOpts{})
		time.Sleep(gb.dur / 2)
		if cs, ok := carrierByID(dc, first.ID); ok {
			res.srtt = cs.SRTT
		}
		time.Sleep(gb.dur / 2)
		res.carried = bulk.recvd.Load()
		bulk.stop()
		bulk.wait(t, 60*time.Second)
		res.dialer, res.passive = dc.Status().Migrations, pc.Status().Migrations
		res.a = p.Status().Factories[0]
		res.throttled = a.Stats().Throttled
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
	if r.dialer.Quality != 0 || r.passive.Quality != 0 || r.dialer.Death+r.dialer.Explicit != 0 {
		t.Fatalf("migrations dialer %+v, passive %+v: the bulk caused a switch", r.dialer, r.passive)
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
// §0.13 A5). The start phase of both cases (halfway between two of a's
// probe PINGs) is the favourable one: a download that starts right after a
// probe PING commit still switches (the rendr_findings test
// TestDownloadGuardEdges_L29, recorded as open in §0.13).
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
