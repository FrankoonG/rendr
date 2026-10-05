package lessons1

import (
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestWindow100msScaled_L15 is M1c's window-100ms case (one path with a
// 100 ms RTT, a bulk transfer from the passive B to the dialer A, steady
// goodput of at least 90% of min(path rate, Window/RTT) once the first 2 s
// are excluded, every byte intact) scaled down in rate so the bubble stays
// fast: a 2 MiB window and 14 MiB/s keep the bandwidth-delay product at 0.70
// of the window (window-100ms: 6.0 MB of 8 MiB, 0.71) and the byte clock's
// step at one eighth of it. The link takes a whole capacity at once, as
// the gold case's 16 MiB send buffers do. Before the byte clock the sender
// proved each burst only with the cap-hit PING queued behind it and the
// path ran at R·C/(C + R·RTT), about 59% here (57% predicted for
// window-100ms). The sender's PINGs stay within one per clock step of DATA
// plus its PingBusy cadence, the session neither migrates nor retransmits,
// and both ends finish with io.EOF.
func TestWindow100msScaled_L15(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			window = 2 << 20
			rate   = 14 << 20 // bytes/s: 1.4 MiB per 100 ms
			rtt    = 100 * time.Millisecond
			warmup = 2 * time.Second // excluded (M1c E21)
		)
		n := int64(64 << 20)
		if lessonsRace {
			n = 48 << 20
		}
		o := opts{dcfg: rendr.Config{Window: window}, pcfg: rendr.Config{Window: window}, buffer: 16 << 20}
		f := newFixture(t, o, "w")
		l := f.link("w")
		l.SetDelay(rtt/2, 0)
		l.SetRate(rate)
		dc, pc := f.open(f.peer("w"), rendr.DialOptions{})
		var g gauge
		errs := make(chan error, 2)
		start := time.Now()
		go func() { errs <- sendAndClose(pc, n, 100) }() // B → A
		go func() { errs <- readStream(dc, n, 100, &g) }()
		time.Sleep(warmup)
		atWarm, warmAt := g.get(), time.Now()
		reached(t, &g, n, 2*time.Minute)
		doneAt := time.Now()
		for range 2 {
			if err := recv(t, errs, time.Minute, "the transfer"); err != nil {
				t.Fatalf("transfer: %v", err)
			}
		}
		synctest.Wait()

		// Load: a steady state of at least a second after the warm-up, the
		// whole stream delivered (readStream verified every byte and EOF).
		if doneAt.Sub(warmAt) < time.Second {
			t.Fatalf("load: the transfer ended %v after the start, want ≥ 1 s of steady state after %v", doneAt.Sub(start), warmup)
		}
		// Stimulus: the path was shaped (every byte passed the rate limit).
		if th := l.Stats().Throttled; th < n {
			t.Fatalf("stimulus: %d bytes passed the rate limiter, want ≥ %d", th, n)
		}
		bound := min(float64(rate), float64(window)/rtt.Seconds())
		steady := float64(n-atWarm) / doneAt.Sub(warmAt).Seconds()
		pt := f.wire.sessionTaps(passiveSide, "w")
		if len(pt) != 1 {
			t.Fatalf("%d session carriers on the passive, want 1", len(pt))
		}
		pings := f.wire.count(func(fr frame) bool {
			return fr.tap == pt[0] && fr.out && fr.fate == fateWritten && fr.typ == wire.TypePing
		})
		st := pc.Status()
		c, _ := carrierIn(st, rendr.CarrierActive)
		t.Logf("%d MiB in %v: steady %.2f MiB/s = %.1f%% of %.1f MiB/s; %d PINGs from the sender (%.2f per MiB); its carrier: cap %d KiB, rate %.1f MiB/s, srtt %v",
			n>>20, doneAt.Sub(start), steady/(1<<20), 100*steady/bound, bound/(1<<20), pings, float64(pings)/float64(n>>20), c.Cap>>10, c.Rate/(1<<20), c.SRTT)
		if steady < 0.9*bound {
			t.Fatalf("steady goodput %.2f MiB/s, want ≥ 90%% of min(path rate, Window/RTT) = %.2f MiB/s", steady/(1<<20), 0.9*bound/(1<<20))
		}
		// PING overhead: one per clock step of DATA (a window's eighth, the
		// capacity being the window), one cap-hit PING per refill (as many),
		// one per PingBusy (50 ms) of the transfer, and the ramp.
		step := float64(window / 8)
		if limit := 2*float64(n)/step + float64(doneAt.Sub(start)/(50*time.Millisecond)) + 16; float64(pings) > limit {
			t.Fatalf("the sender wrote %d PINGs for %d MiB, want ≤ %.0f", pings, n>>20, limit)
		}
		for _, x := range []*rendr.Conn{dc, pc} {
			if s := x.Status(); s.Migrations != noMigrations || s.RetransmittedBytes != 0 || len(deadCarriers(s)) != 0 {
				t.Fatalf("%v: migrations %+v, retransmitted %d, dead carriers %+v", s.Role, s.Migrations, s.RetransmittedBytes, deadCarriers(s))
			}
		}
		if err := dc.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		readEOF(t, pc, "passive")
		finish(t, dc, pc)
		f.close()
	})
}
