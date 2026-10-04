package carrier

import (
	"math"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Tests of the self-load guard's volume rule (design §8.2 as amended for
// §0.13 A7a; Health.volumeLoaded): a probe sample is loaded when the
// factory's session carriers moved at least LoadThreshold of DATA between
// its PING's commit and its PONG's arrival, unless that traffic was
// established application-limited traffic before the commit. Helpers use
// the vr prefix (V16: h* and pr* are taken).

// TestGaugeVolumeCountsSessionData_L29: a dialer session carrier started
// with a Gauge counts every DATA payload byte it writes (once per batch,
// when the write returned) and receives (once per frame, small and big
// frames alike) in the gauge, exactly as its own TxBytes and RxBytes, and
// stamps the latest movement; a second carrier that moves as much without a
// Gauge adds nothing. The gauge stamps the end of a backlog when its count
// falls to zero.
func TestGaugeVolumeCountsSessionData_L29(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		g := NewGauge()
		c, p := hPair(t, env, nil)
		p.autoPong(nil)
		src := newSource(env, ChunkSize, true)
		c.Start(src, &hBell{}, StartOptions{Gauge: g})
		other, op := hPair(t, env, nil) // no Gauge: no volume
		op.autoPong(nil)
		osrc := newSource(env, ChunkSize, true)
		other.Start(osrc, &hBell{}, StartOptions{})

		if s := g.read(64 << 10); s.tx != 0 || s.rx != 0 || !s.movedAt.IsZero() || !s.calmAt.IsZero() {
			t.Fatalf("idle gauge %+v", s)
		}
		const sent = 700 << 10 // several batches: the capacity floor releases 128 KiB per PONG
		src.offer(sent)
		c.Wake()
		osrc.offer(sent)
		other.Wake()
		var off uint64
		for _, n := range []int{100, 16 << 10, 1 << 10, 40 << 10, 7} { // dispatch and big-DATA paths
			for _, pp := range []*wirePeer{p, op} {
				if err := pp.send(wire.TypeData, 0, wire.SessionHandle, dataPayload(off, n)); err != nil {
					t.Fatalf("peer send: %v", err)
				}
			}
			off += uint64(n)
		}
		time.Sleep(time.Second)
		synctest.Wait()
		last := time.Now()
		st := c.Stats()
		s := g.read(64 << 10)
		if st.TxBytes != sent || s.tx != st.TxBytes || st.RxBytes != off || s.rx != st.RxBytes {
			t.Fatalf("gauge tx %d rx %d, carrier tx %d rx %d; want tx %d rx %d", s.tx, s.rx, st.TxBytes, st.RxBytes, sent, off)
		}
		if s.movedAt.IsZero() || s.movedAt.After(last) {
			t.Fatalf("latest movement stamped at %v (now %v)", s.movedAt, last)
		}
		if ost := other.Stats(); ost.TxBytes != sent || ost.RxBytes != off {
			t.Fatalf("carrier without a gauge moved tx %d rx %d, want %d and %d", ost.TxBytes, ost.RxBytes, sent, off)
		}

		// The end of a backlog is stamped when the count falls to zero.
		g2 := NewGauge()
		time.Sleep(time.Second)
		g2.SetBacklog(true)
		g2.SetBacklog(true)
		g2.SetBacklog(false)
		if s := g2.read(64 << 10); !s.backlogged || !s.calmAt.IsZero() {
			t.Fatalf("one of two carriers left the backlog: %+v", s)
		}
		time.Sleep(time.Second)
		ended := time.Now()
		g2.SetBacklog(false)
		if s := g2.read(64 << 10); s.backlogged || !s.calmAt.Equal(ended) {
			t.Fatalf("the last carrier left the backlog at %v: %+v", ended, s)
		}
	})
}

// TestVolumeRuleHelpers: the readings the volume rule compares. grown never
// wraps (a PONG that raced its PingCommitted callback carries an earlier
// counter reading than the commit); since reports forever for an event
// that never happened and 0 for one stamped a moment after the commit.
func TestVolumeRuleHelpers(t *testing.T) {
	if grown(10, 4) != 6 || grown(4, 10) != 0 || grown(7, 7) != 0 {
		t.Fatalf("grown: %d %d %d", grown(10, 4), grown(4, 10), grown(7, 7))
	}
	now := time.Now()
	if since(now, time.Time{}) != forever || since(now, now.Add(time.Millisecond)) != 0 || since(now, now.Add(-time.Second)) != time.Second {
		t.Fatalf("since: %v %v %v", since(now, time.Time{}), since(now, now.Add(time.Millisecond)), since(now, now.Add(-time.Second)))
	}
}

// vrRig is a health rig (two factories over 10 ms one-way links: probe
// PINGs of factory 0 are committed at about 0.02 + 2k s and answered 20 ms
// later) plus one dialer session carrier that feeds factory 0's Gauge: a
// real carrier over a net.Pipe whose far end is a scripted wirePeer. The
// tests move DATA both ways on it — rx: the peer sends DATA frames; tx: a
// bulk source offers bytes — and set the peer's PING BUSY flag; no test
// code touches the gauge. The peer answers the carrier's PINGs at once, so
// its reverse bound rxRate·srtt stays negligible: the instantaneous rule
// loads the gauge only while the peer reports BUSY (§0.13 A5), and every
// other loaded sample comes from the volume rule.
type vrRig struct {
	*prRig
	c      *Conn
	p      *wirePeer
	src    *hSource
	g      *Gauge
	off    uint64 // next stream offset the peer sends
	pingID uint32 // the peer's PING ids
	bg     sync.WaitGroup
}

func newVrRig(t *testing.T, edit func(env *Env, p *HealthParams)) *vrRig {
	t.Helper()
	r := &vrRig{prRig: newPrRig(t, 2, edit)}
	r.h.Use()
	senv := hEnv()
	r.c, r.p = hPair(t, senv, nil)
	r.p.autoPong(nil)
	r.src = newSource(senv, ChunkSize, true)
	r.g = r.h.Gauges()[0]
	r.c.Start(r.src, &hBell{}, StartOptions{Gauge: r.g})
	return r
}

// rx makes the peer send n DATA bytes to the session carrier in frames of
// at most seg bytes (test goroutine).
func (r *vrRig) rx(n, seg int) {
	r.t.Helper()
	if err := r.rxErr(n, seg); err != nil {
		r.t.Fatalf("peer send: %v", err)
	}
}

// rxErr is rx for the bubble's other goroutines. One goroutine at a time
// sends DATA (off is not shared).
func (r *vrRig) rxErr(n, seg int) error {
	for n > 0 {
		k := min(n, seg)
		if err := r.p.send(wire.TypeData, 0, wire.SessionHandle, dataPayload(r.off, k)); err != nil {
			return err
		}
		r.off += uint64(k)
		n -= k
	}
	return nil
}

// tx offers n bytes to the session carrier's bulk source.
func (r *vrRig) tx(n int) {
	r.src.offer(uint64(n))
	r.c.Wake()
}

// busy makes the peer report its send backlog (PING BUSY) on or off.
func (r *vrRig) busy(on bool) {
	r.t.Helper()
	r.pingID++
	if err := r.p.ping(r.pingID, on); err != nil {
		r.t.Fatalf("peer PING: %v", err)
	}
	synctest.Wait()
}

// stream makes the peer send seg bytes every gap from now until until, on
// a goroutine of the bubble that the test joins with wait.
func (r *vrRig) stream(seg int, gap time.Duration, until time.Time) {
	r.bg.Add(1)
	go func() {
		defer r.bg.Done()
		for time.Now().Before(until) {
			if err := r.rxErr(seg, seg); err != nil {
				r.t.Errorf("peer send: %v", err)
				return
			}
			time.Sleep(gap)
		}
	}()
}

// probePing waits until factory 0's probe carrier committed its next PING
// (it is the only carrier on its link).
func (r *vrRig) probePing() {
	r.t.Helper()
	select {
	case <-r.links[0].CaptureNextFrame(rendrtest.Up, rendrtest.FramePing):
	case <-time.After(3 * time.Second):
		r.t.Fatal("factory 0 sent no probe PING for 3 s")
	}
	synctest.Wait() // the PingCommitted callback ran
}

// nextSample waits for factory 0's next probe sample after the snapshot
// before and reports whether it was loaded and whether the gauge's
// instantaneous rule could have loaded it (the gauge loaded at its arrival
// or its epoch changed since epoch).
func (r *vrRig) nextSample(before FactoryInfo, epoch uint64) (loaded, instantaneous bool) {
	r.t.Helper()
	for range 400 {
		time.Sleep(5 * time.Millisecond)
		synctest.Wait()
		if info := r.h.Snapshot().Info[0]; info.Samples > before.Samples {
			on, e := r.g.Loaded(64 << 10)
			return info.LoadedSamples > before.LoadedSamples, on || e != epoch
		}
	}
	r.t.Fatalf("no probe sample of factory 0 within 2 s after %+v", before)
	return false, false
}

// TestHealthVolumeRule_L29: for each traffic pattern on factory 0's session
// carrier, the sample of a probe PING whose flight carries a burst is
// loaded exactly when the volume rule says so, while the instantaneous
// rule has no backlog to see in that flight. The burst is the 128 KiB a
// download (rx) or an upload (tx) puts on the wire first (the capacity
// floor): the A7a shape at the carrier layer.
//
//   - onset-rx, onset-tx: no DATA before; the burst is the whole flight's
//     volume — loaded, in either direction.
//   - below-threshold: a 32 KiB burst — unloaded.
//   - guard-disabled: LoadThreshold = MaxInt64 (the guard-disabled control
//     of the scenario tests) — unloaded.
//   - regular-bursts: 64 KiB every 500 ms before it, never backlogged
//     (application-limited messages) — established, unloaded.
//   - trickle-then-burst: 1 KiB every 100 ms before it (less than the
//     threshold per probe interval and per flight) — not established,
//     loaded.
//   - backlogged-predecessor: the same messages, but the peer reported
//     BUSY for a while in the interval before the commit (a saturating
//     transfer before a pause) — not established, loaded.
//   - steady-flow: 16 KiB every 4 ms (4 MiB/s, 80 KiB per 20 ms flight)
//     running through the commit and the flight, with a BUSY episode early
//     in the interval — established, unloaded, although the flight moved
//     more than the threshold.
//   - silent-before-commit: the same flow, stopped 100 ms before the commit
//     (longer than the threshold takes at its rate) — loaded.
func TestHealthVolumeRule_L29(t *testing.T) {
	type pattern struct {
		name     string
		disabled bool
		before   func(r *vrRig) // from 0.3 s until the 4.02 s probe PING
		burst    func(r *vrRig) // right after the 4.02 s probe PING's commit
		moved    uint64         // stimulus: at least this much DATA moved in the flight
		loaded   bool
	}
	burstRx := func(n int) func(r *vrRig) { return func(r *vrRig) { r.rx(n, 16<<10) } }
	messages := func(withBusy bool) func(r *vrRig) {
		return func(r *vrRig) {
			for k := range 7 { // 0.75, 1.25, …, 3.75 s: never inside a probe flight
				r.until(750*time.Millisecond + time.Duration(k)*500*time.Millisecond)
				r.rx(64<<10, 16<<10)
				if withBusy && k == 3 { // 2.25 s: BUSY until 2.75 s
					r.busy(true)
				}
				if withBusy && k == 4 {
					r.busy(false)
				}
			}
		}
	}
	trickle := func(r *vrRig) { // 1 KiB every 100 ms (G2-shaped), never in a probe flight
		for k := range 36 {
			r.until(450*time.Millisecond + time.Duration(k)*100*time.Millisecond)
			r.rx(1<<10, 1<<10)
		}
	}
	steady := func(stop time.Duration) func(r *vrRig) {
		return func(r *vrRig) {
			r.until(2100 * time.Millisecond)
			r.stream(16<<10, 4*time.Millisecond, r.start.Add(stop))
			r.until(2500 * time.Millisecond)
			r.busy(true)
			r.until(2800 * time.Millisecond)
			r.busy(false)
			if stop < 4*time.Second {
				r.until(stop + 10*time.Millisecond)
				r.bg.Wait() // the flow ended before the commit
			}
		}
	}
	for _, pt := range []pattern{
		{name: "onset-rx", burst: burstRx(128 << 10), moved: 128 << 10, loaded: true},
		{name: "onset-tx", burst: func(r *vrRig) { r.tx(128 << 10) }, moved: 128 << 10, loaded: true},
		{name: "below-threshold", burst: burstRx(32 << 10), moved: 32 << 10},
		{name: "guard-disabled", disabled: true, burst: burstRx(128 << 10), moved: 128 << 10},
		{name: "regular-bursts", before: messages(false), burst: burstRx(128 << 10), moved: 128 << 10},
		{name: "trickle-then-burst", before: trickle, burst: burstRx(128 << 10), moved: 128 << 10, loaded: true},
		{name: "backlogged-predecessor", before: messages(true), burst: burstRx(128 << 10), moved: 128 << 10, loaded: true},
		{name: "steady-flow", before: steady(4100 * time.Millisecond), burst: burstRx(0), moved: 64 << 10},
		{name: "silent-before-commit", before: steady(3920 * time.Millisecond), burst: burstRx(128 << 10), moved: 128 << 10, loaded: true},
	} {
		t.Run(pt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := newVrRig(t, func(_ *Env, p *HealthParams) {
					if pt.disabled {
						p.LoadThreshold = math.MaxInt64
					}
				})
				r.until(300 * time.Millisecond)
				if pt.before != nil {
					pt.before(r)
				}
				r.until(3990 * time.Millisecond)
				if s := r.h.Snapshot().Info[0]; s.Samples != 2 || s.LoadedSamples != 0 {
					t.Fatalf("before the burst: factory 0 %+v, want 2 unloaded samples", s)
				}
				r.probePing()
				if d := r.since(); d < 4010*time.Millisecond || d > 4030*time.Millisecond {
					t.Fatalf("probe PING committed at %v, want about 4.02 s", d)
				}
				before := r.h.Snapshot().Info[0]
				gs := r.g.read(64 << 10)
				pt.burst(r)
				loaded, inst := r.nextSample(before, gs.epoch)
				ge := r.g.read(64 << 10)
				moved := grown(ge.tx, gs.tx) + grown(ge.rx, gs.rx)
				t.Logf("%s: moved %d in the flight, loaded %v (gauge loaded at the commit %v, instantaneous %v)", pt.name, moved, loaded, gs.loaded, inst)
				if gs.loaded || inst {
					t.Fatalf("the instantaneous rule saw a load at the commit (%v) or in the flight (%v): the case does not isolate the volume rule", gs.loaded, inst)
				}
				if moved < pt.moved {
					t.Fatalf("stimulus: %d bytes moved in the flight, want at least %d", moved, pt.moved)
				}
				if loaded != pt.loaded {
					t.Fatalf("sample loaded %v, want %v", loaded, pt.loaded)
				}
				if s := r.h.Snapshot(); pt.loaded == (s.Sum[0].N == 3) {
					t.Fatalf("window holds %d samples: a loaded sample must stay out of it, an unloaded one in it", s.Sum[0].N)
				}
				r.bg.Wait()
			})
		})
	}
}

// TestHealthVolumeLightInteractive_L29: G2/G9-shaped interactive traffic
// (1 KiB each way every 100 ms) moves only a few KiB in a probe flight of
// 20 ms or, after the path's RTT rose to 100 ms, 100 ms: every sample stays
// unloaded, so the RTT rise reaches the evidence.
func TestHealthVolumeLightInteractive_L29(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newVrRig(t, nil)
		stop := r.start.Add(9 * time.Second)
		r.bg.Add(1)
		go func() {
			defer r.bg.Done()
			for time.Now().Before(stop) {
				r.tx(1 << 10)
				if err := r.rxErr(1<<10, 1<<10); err != nil {
					t.Errorf("peer send: %v", err)
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
		}()
		r.until(4500 * time.Millisecond)
		mid := r.g.read(64 << 10)
		if s := r.h.Snapshot(); s.Info[0].Samples != 3 || s.Sum[0].Mean != 20*time.Millisecond {
			t.Fatalf("at 20 ms: factory 0 %+v, window %+v", s.Info[0], s.Sum[0])
		}
		r.links[0].SetDelay(50*time.Millisecond, 0)
		r.until(9 * time.Second)
		r.bg.Wait()
		end := r.g.read(64 << 10)
		s := r.h.Snapshot()
		if s.Info[0].LoadedSamples != 0 || s.Info[0].Samples != 5 {
			t.Fatalf("factory 0 %+v: interactive traffic loaded a sample", s.Info[0])
		}
		if s.Sum[0].Mean < 90*time.Millisecond {
			t.Fatalf("window %+v: the 100 ms samples did not reach the evidence", s.Sum[0])
		}
		if tx, rx := end.tx-mid.tx, end.rx-mid.rx; tx < 40<<10 || rx < 40<<10 {
			t.Fatalf("stimulus: %d bytes written and %d received in 4.5 s, want about 45 KiB each", tx, rx)
		}
	})
}
