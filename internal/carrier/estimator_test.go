package carrier

import (
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// rateConn is a slow receiver: it reads at most chunk bytes at a time and
// sleeps so that it drains at most rate bytes/s (virtual time).
type rateConn struct {
	net.Conn
	rate  float64
	chunk int
}

func (r rateConn) Read(p []byte) (int, error) {
	if len(p) > r.chunk {
		p = p[:r.chunk]
	}
	n, err := r.Conn.Read(p)
	if n > 0 {
		time.Sleep(time.Duration(float64(n) / r.rate * float64(time.Second)))
	}
	return n, err
}

// hObserver records probe PING commits and PONGs.
type hObserver struct {
	mu      sync.Mutex
	commits []time.Time
	pongs   []time.Duration
}

func (o *hObserver) PingCommitted(c *Conn, id uint32, at time.Time) {
	o.mu.Lock()
	o.commits = append(o.commits, at)
	o.mu.Unlock()
}

func (o *hObserver) Pong(c *Conn, id uint32, rtt time.Duration, at time.Time) {
	o.mu.Lock()
	o.pongs = append(o.pongs, rtt)
	o.mu.Unlock()
}

func (o *hObserver) counts() (commits, pongs int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.commits), len(o.pongs)
}

func (o *hObserver) snapshot() (commits []time.Time, pongs []time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]time.Time(nil), o.commits...), append([]time.Duration(nil), o.pongs...)
}

// TestRTTFromWriteCommit_L23: the first PING's write is blocked for 1.5 s
// and the peer answers 7 ms after receiving it: the RTT is 7 ms (counted
// from the write's return, not from queueing), the carrier is not judged
// dead, and a PONG that arrives before the write returned is ignored (no
// sample).
func TestRTTFromWriteCommit_L23(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		var calls atomic.Int32
		c, p := hPair(t, env, func(nc net.Conn) net.Conn {
			return &hookConn{Conn: nc, onWrite: func(nc net.Conn, b []byte) (int, error) {
				if calls.Add(1) == 1 {
					time.Sleep(1500 * time.Millisecond) // the bytes leave only now
				}
				return nc.Write(b)
			}}
		})
		p.autoPong(func(uint32) time.Duration { return 7 * time.Millisecond })
		obs := &hObserver{}
		start := time.Now()
		c.Start(nil, &hBell{}, StartOptions{Probe: true, Observer: obs})
		time.Sleep(500 * time.Millisecond)
		// An early PONG for the PING that is still inside its write.
		if err := p.pong(wire.Ping{ID: 1, Nonce: c.salt ^ 1}); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if s := c.SRTT(); s != 0 {
			t.Fatalf("a PONG before the commit gave an RTT sample: %v", s)
		}
		if _, pongs := obs.counts(); pongs != 0 {
			t.Fatal("observer got a PONG before the commit")
		}
		time.Sleep(time.Second + 20*time.Millisecond) // the write returns at 1.5 s, the PONG 7 ms later
		synctest.Wait()
		if s := c.SRTT(); s != 7*time.Millisecond {
			t.Fatalf("srtt %v, want 7ms from the write commit", s)
		}
		commits, pongs := obs.snapshot()
		if len(commits) != 1 || len(pongs) != 1 || commits[0].Sub(start) != 1500*time.Millisecond || pongs[0] != 7*time.Millisecond {
			t.Fatalf("observer: commits %v pongs %v", commits, pongs)
		}
		time.Sleep(5 * time.Second)
		if dead, cause, _, _ := c.Death(); dead {
			t.Fatalf("judged dead: %v", cause)
		}
		c.Kill(CauseLocalClose, "test end")
		hWait(t, c)
		p.close()
	})
}

// TestPongRacingItsWriteKeepsCarrierAlive_L23: when every PONG arrives
// before its PING's Write call returned (the bytes left early), the PONGs
// give no RTT evidence, yet they prove liveness: the carrier is not judged
// dead, its PING records do not pile up, and its PINGs keep going.
func TestPongRacingItsWriteKeepsCarrierAlive_L23(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		env.Timing.PingIdle = 5 * time.Second // longer than the death deadline (DeadMin 3 s)
		c, p := hPair(t, env, func(nc net.Conn) net.Conn {
			return &hookConn{Conn: nc, onWrite: func(nc net.Conn, b []byte) (int, error) {
				n, err := nc.Write(b)
				time.Sleep(10 * time.Millisecond) // the Write call returns after the PONG arrived
				return n, err
			}}
		})
		p.autoPong(nil)
		c.Start(&hEP{}, &hBell{}, StartOptions{})
		time.Sleep(12 * time.Second)
		if dead, cause, detail, _ := c.Death(); dead {
			t.Fatalf("judged dead: %v %s", cause, detail)
		}
		c.mu.Lock()
		records, srtt := c.st.n, c.st.srtt
		c.mu.Unlock()
		if records > 1 || srtt != 0 || p.count(wire.TypePing) != 3 {
			t.Fatalf("records %d, srtt %v, PINGs %d", records, srtt, p.count(wire.TypePing))
		}
	})
}

// TestPongBoundToIncarnation_L23: carrier A sends PING 7 and dies; a PONG
// carrying A's PING 7 (id and nonce) that later arrives on A' (a new
// incarnation whose first PING is also 7) or on another carrier B gives no
// evidence; A' and B still accept their own PONGs.
func TestPongBoundToIncarnation_L23(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		env.Presets.FirstPingID = 7
		a, pa := hPair(t, env, nil)
		var capture wire.Ping
		var got atomic.Bool
		pa.setHandler(func(f wire.Frame) {
			if f.Type == wire.TypePing && got.CompareAndSwap(false, true) {
				capture, _ = wire.ParsePing(f.Payload)
			}
		})
		a.Start(nil, &hBell{}, StartOptions{Probe: true, Observer: &hObserver{}})
		synctest.Wait()
		a.Kill(CauseLocalClose, "incarnation ended")
		hWait(t, a)
		pa.close()
		if !got.Load() || capture.ID != 7 {
			t.Fatalf("captured PING %+v", capture)
		}

		obs2, obsB := &hObserver{}, &hObserver{}
		a2, p2 := hPair(t, env, nil)
		b, pb := hPair(t, env, nil)
		a2.Start(nil, &hBell{}, StartOptions{Probe: true, Observer: obs2})
		b.Start(nil, &hBell{}, StartOptions{Probe: true, Observer: obsB})
		synctest.Wait()
		if err := p2.pong(capture); err != nil {
			t.Fatal(err)
		}
		if err := pb.pong(capture); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		for name, c := range map[string]*Conn{"A'": a2, "B": b} {
			if c.SRTT() != 0 || c.Stats().MinRTT != 0 {
				t.Fatalf("%s took evidence from A's PONG", name)
			}
		}
		if _, n := obs2.counts(); n != 0 {
			t.Fatal("A' observer saw A's PONG")
		}
		if _, n := obsB.counts(); n != 0 {
			t.Fatal("B observer saw A's PONG")
		}
		// The genuine answers still count.
		p2.later(10*time.Millisecond, func() { _ = p2.pong(wire.Ping{ID: 7, Nonce: a2.salt ^ 7}) })
		time.Sleep(20 * time.Millisecond)
		if s := a2.SRTT(); s != 10*time.Millisecond {
			t.Fatalf("A' srtt %v after its own PONG", s)
		}
		for _, c := range []*Conn{a2, b} {
			c.Kill(CauseLocalClose, "test end")
			hWait(t, c)
		}
		p2.close()
		pb.close()
	})
}

// TestFirstPingImmediate_L23: a started carrier writes its first PING at
// once (well within 200 ms); a held carrier writes nothing — not even a
// PONG for PINGs it received — until its first frame exists, and then the
// first frame leads, followed by one PONG (latest) and the first PING.
func TestFirstPingImmediate_L23(t *testing.T) {
	t.Run("session and probe", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			for _, o := range []StartOptions{{}, {Probe: true, Observer: &hObserver{}}} {
				env := hEnv()
				c, p := hPair(t, env, nil)
				start := time.Now()
				var at time.Time
				p.setHandler(func(f wire.Frame) {
					if f.Type == wire.TypePing && at.IsZero() {
						at = time.Now()
					}
				})
				c.Start(&hEP{}, &hBell{}, o)
				synctest.Wait()
				c.Kill(CauseLocalClose, "test end")
				hWait(t, c)
				p.close()
				if fr := p.received(); len(fr) == 0 || fr[0].Type != wire.TypePing || at.Sub(start) != 0 {
					t.Fatalf("first frame %v at %v", fr, at.Sub(start))
				}
			}
		})
	})
	t.Run("held", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			env := hEnv()
			c, p := hPair(t, env, nil)
			ep := &hEP{}
			c.Start(ep, &hBell{}, StartOptions{Hold: true})
			for id := uint32(1); id <= 3; id++ {
				if err := p.ping(id, false); err != nil {
					t.Fatal(err)
				}
			}
			time.Sleep(time.Second)
			synctest.Wait()
			if n := len(p.received()); n != 0 {
				t.Fatalf("a held carrier wrote %d frames", n)
			}
			var once atomic.Bool
			ep.setFill(func(c *Conn, b *Batch) {
				if once.CompareAndSwap(false, true) {
					b.AddOpenAck(wire.SessionHandle, &wire.OpenAck{Status: wire.StatusOK, Window: 1 << 20})
				}
			})
			c.Wake()
			synctest.Wait()
			fr := p.received()
			if len(fr) != 3 || fr[0].Type != wire.TypeOpenAck || fr[1].Type != wire.TypePong || fr[2].Type != wire.TypePing {
				t.Fatalf("frames %v, want OPEN_ACK, PONG, PING", fr)
			}
			if pg, _ := wire.ParsePing(fr[1].Payload); pg.ID != 3 {
				t.Fatalf("PONG for PING %d, want the latest (3)", pg.ID)
			}
			c.Kill(CauseLocalClose, "test end")
			hWait(t, c)
			p.close()
		})
	})
}

// TestPongDelayBoundary_L25: with the death deadline fixed at 1 s
// (DeadMin = DeadMax), PONGs delayed by 0.9·D keep the carrier alive over
// many PINGs, while PONGs delayed by more than D kill it with ping_timeout
// exactly D after the unanswered PING's commit.
func TestPongDelayBoundary_L25(t *testing.T) {
	for _, tc := range []struct {
		name  string
		delay time.Duration
		alive bool
	}{{"0.9D", 900 * time.Millisecond, true}, {"1.1D", 1100 * time.Millisecond, false}} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env := hEnv()
				env.Timing.DeadMin, env.Timing.DeadMax = time.Second, time.Second
				env.Timing.PingIdle = 2 * time.Second
				c, p := hPair(t, env, nil)
				p.autoPong(func(uint32) time.Duration { return tc.delay })
				start := time.Now()
				c.Start(&hEP{}, &hBell{}, StartOptions{})
				time.Sleep(20 * time.Second)
				dead, cause, _, at := c.Death()
				if tc.alive {
					if dead {
						t.Fatalf("died: %v", cause)
					}
					if s := c.SRTT(); s != tc.delay || p.count(wire.TypePing) < 9 {
						t.Fatalf("srtt %v after %d PINGs", s, p.count(wire.TypePing))
					}
					c.Kill(CauseLocalClose, "test end")
				} else if !dead || cause != CausePingTimeout || at.Sub(start) != time.Second {
					t.Fatalf("death %v %v after %v, want ping_timeout after 1s", dead, cause, at.Sub(start))
				}
				hWait(t, c)
				p.close()
			})
		})
	}
}

// TestBondCapacityEvidenceOnlyUnderBacklog_L32: sparse, demand-limited
// writes never produce capacity evidence (the rate stays 0 and the cap at
// its 128 KiB floor, no PING says BUSY), while a backlogged writer facing a
// 10 MB/s receiver measures a rate near the drain rate and raises its cap.
func TestBondCapacityEvidenceOnlyUnderBacklog_L32(t *testing.T) {
	const drain = 10e6
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		a, b := net.Pipe()
		c := hConn(env, newSendBuf(a, 64)) // a 1 MiB send buffer, like a socket's
		p := startPeer(rateConn{Conn: b, rate: drain, chunk: 16 << 10}, env.Presets.firstFseq())
		hCleanup(t, c, p)
		p.autoPong(nil)
		src := newSource(env, 4<<10, true)
		c.Start(src, &hBell{}, StartOptions{})
		for range 50 { // 1 KiB every 100 ms for 5 s
			src.offer(1 << 10)
			c.Wake()
			time.Sleep(100 * time.Millisecond)
		}
		synctest.Wait()
		s := c.Stats()
		if s.Rate != 0 || s.Cap != env.Timing.CapFloor || s.Backlogged || p.dataBytes() != 50<<10 {
			t.Fatalf("sparse writes: rate %v cap %d backlogged %v delivered %d", s.Rate, s.Cap, s.Backlogged, p.dataBytes())
		}
		for _, f := range p.received() {
			if f.Type == wire.TypePing && f.Flags&wire.FlagPingBusy != 0 {
				t.Fatal("a demand-limited writer sent BUSY")
			}
		}

		src.offer(1 << 30) // backlog: more than the receiver can drain
		c.Wake()
		time.Sleep(3 * time.Second)
		s = c.Stats()
		if s.Rate < 0.5*drain || s.Rate > 1.2*drain || s.Cap <= env.Timing.CapFloor || !s.Backlogged {
			t.Fatalf("backlogged: rate %.0f (drain %.0f) cap %d backlogged %v", s.Rate, drain, s.Cap, s.Backlogged)
		}
		if got := p.dataBytes(); got < 2*drain {
			t.Fatalf("only %d bytes delivered under backlog", got)
		}
		c.Kill(CauseLocalClose, "test end")
		hWait(t, c)
		p.close()
		src.chunk.Release()
	})
}

// TestRateEstimateBoundedByDrain_L32: one PONG is held 500 ms on the return
// path while the writer keeps submitting at the drain rate, so the PONGs
// behind it arrive in a burst that proves 500 ms of data at once; the rate
// estimate never exceeds the receiver's drain rate (plus sampling slack) at
// any moment. (A sample divided by the PONG arrival span alone would read
// the burst as ≈ 10× the drain rate.)
func TestRateEstimateBoundedByDrain_L32(t *testing.T) {
	const drain = 10e6
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		a, b := net.Pipe()
		c := hConn(env, newSendBuf(a, 64)) // a 1 MiB send buffer, like a socket's
		p := startPeer(rateConn{Conn: b, rate: drain, chunk: 16 << 10}, env.Presets.firstFseq())
		hCleanup(t, c, p)
		var pongTimes []time.Time
		var pmu sync.Mutex
		p.setHandler(func(f wire.Frame) {
			if f.Type != wire.TypePing {
				return
			}
			pg, _ := wire.ParsePing(f.Payload)
			d := time.Microsecond
			if pg.ID == 20 {
				d = 500 * time.Millisecond
			}
			p.later(d, func() {
				pmu.Lock()
				pongTimes = append(pongTimes, time.Now())
				pmu.Unlock()
				_ = p.pong(pg)
			})
		})
		src := newSource(env, 16<<10, false) // not cap-limited: the writer keeps submitting while the PONGs are held
		src.offer(1 << 30)
		c.Start(src, &hBell{}, StartOptions{})
		var maxRate float64
		for range 600 { // 3 s, sampled every 5 ms
			time.Sleep(5 * time.Millisecond)
			maxRate = max(maxRate, c.Stats().Rate)
		}
		if maxRate > 1.2*drain || maxRate < 0.5*drain {
			t.Fatalf("rate peaked at %.0f with a drain rate of %.0f", maxRate, drain)
		}
		c.Kill(CauseLocalClose, "test end")
		hWait(t, c)
		p.close()
		// Stimulus: a ≥ 500 ms gap in the PONGs, then a burst.
		gap, burst := time.Duration(0), 0
		for i := 1; i < len(pongTimes); i++ {
			if d := pongTimes[i].Sub(pongTimes[i-1]); d > gap {
				gap = d
				burst = 0
				for j := i; j < len(pongTimes) && pongTimes[j].Equal(pongTimes[i]); j++ {
					burst++
				}
			}
		}
		if gap < 450*time.Millisecond || burst < 3 {
			t.Fatalf("no delayed-PONG burst: gap %v burst %d", gap, burst)
		}
		src.chunk.Release()
	})
}

// TestBacklogFractionCountsCapBlocked_L32 (D15): writes that complete at
// once but leave the writer waiting at its capacity cap (PONGs 200 ms
// away) make the writer backlogged: its PINGs carry BUSY. A writer that is
// neither writing nor cap-blocked never says BUSY.
func TestBacklogFractionCountsCapBlocked_L32(t *testing.T) {
	for _, tc := range []struct {
		name   string
		bulk   bool
		wantOn bool
	}{{"cap-blocked", true, true}, {"idle", false, false}} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env := hEnv()
				c, p := hPair(t, env, nil)
				p.autoPong(func(uint32) time.Duration { return 200 * time.Millisecond })
				src := newSource(env, ChunkSize, true)
				if tc.bulk {
					src.offer(1 << 30)
				}
				c.Start(src, &hBell{}, StartOptions{})
				time.Sleep(2 * time.Second)
				busy := 0
				for _, f := range p.received() {
					if f.Type == wire.TypePing && f.Flags&wire.FlagPingBusy != 0 {
						busy++
					}
				}
				s := c.Stats()
				if tc.wantOn != (busy > 0) || tc.wantOn != s.Backlogged {
					t.Fatalf("BUSY PINGs %d, Backlogged %v", busy, s.Backlogged)
				}
				if tc.bulk && (p.dataBytes() < 4*env.Timing.CapFloor || src.pending() == 0) {
					t.Fatalf("load not reached: delivered %d, pending %d", p.dataBytes(), src.pending())
				}
				c.Kill(CauseLocalClose, "test end")
				hWait(t, c)
				p.close()
				src.chunk.Release()
			})
		})
	}
}

// TestCapBlockedWriterResumesOnPong_L32 (C5): a writer blocked at its
// capacity cap, with no other wake source (the PING timer a second away and
// no endpoint wake), resumes in the same instant as the PONG that proves
// its in-flight bytes arrives — one RTT after its cap-hit PING.
func TestCapBlockedWriterResumesOnPong_L32(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		env.Timing.PingBusy, env.Timing.PingIdle = time.Second, 10*time.Second
		c, p := hPair(t, env, nil)
		const rtt = 30 * time.Millisecond
		var pongAt []time.Time
		var resumed time.Time
		var mu sync.Mutex
		floor := uint64(env.Timing.CapFloor)
		p.setHandler(func(f wire.Frame) {
			switch f.Type {
			case wire.TypePing:
				pg, _ := wire.ParsePing(f.Payload)
				p.later(rtt, func() {
					mu.Lock()
					pongAt = append(pongAt, time.Now())
					mu.Unlock()
					_ = p.pong(pg)
				})
			case wire.TypeData:
				mu.Lock()
				if binary.BigEndian.Uint64(f.Payload) >= floor && resumed.IsZero() {
					resumed = time.Now()
				}
				mu.Unlock()
			}
		})
		src := newSource(env, ChunkSize, true)
		src.offer(1 << 20)
		start := time.Now()
		c.Start(src, &hBell{}, StartOptions{})
		time.Sleep(500 * time.Millisecond)
		c.Kill(CauseLocalClose, "test end")
		hWait(t, c)
		p.close()
		if resumed.IsZero() {
			t.Fatal("the cap-blocked writer never resumed")
		}
		if got := resumed.Sub(start); got != rtt {
			t.Fatalf("resumed %v after the start, want one RTT (%v): PONG times %v", got, rtt, pongAt)
		}
		src.chunk.Release()
	})
}

// TestPingBusyFlagTransitions (§8.5): the BUSY flag of our PINGs follows
// the writer's backlog (off while idle, on under bulk, off again after),
// the peer's BUSY flag becomes Stats.PeerBusy, and the factory gauge sees
// exactly these backlog transitions (and an epoch per 0 → 1 transition).
func TestPingBusyFlagTransitions(t *testing.T) {
	const drain = 10e6
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		env.Timing.PingIdle = 200 * time.Millisecond
		a, b := net.Pipe()
		c := hConn(env, newSendBuf(a, 64)) // a 1 MiB send buffer, like a socket's
		p := startPeer(rateConn{Conn: b, rate: drain, chunk: 16 << 10}, env.Presets.firstFseq())
		hCleanup(t, c, p)
		p.autoPong(nil)
		g := NewGauge()
		src := newSource(env, ChunkSize, true)
		c.Start(src, &hBell{}, StartOptions{Gauge: g})
		lastBusy := func() bool {
			fr := p.received()
			for i := len(fr) - 1; i >= 0; i-- {
				if fr[i].Type == wire.TypePing {
					return fr[i].Flags&wire.FlagPingBusy != 0
				}
			}
			t.Fatal("no PING")
			return false
		}
		time.Sleep(time.Second)
		if lastBusy() || c.Stats().Backlogged {
			t.Fatal("idle carrier says BUSY")
		}
		if on, epoch := g.Loaded(0); on || epoch != 0 {
			t.Fatalf("idle gauge loaded %v epoch %d", on, epoch)
		}
		src.offer(20 << 20) // 2 s of bulk at the drain rate
		c.Wake()
		time.Sleep(time.Second)
		if !lastBusy() || !c.Stats().Backlogged {
			t.Fatal("backlogged carrier does not say BUSY")
		}
		if on, epoch := g.Loaded(0); !on || epoch != 1 {
			t.Fatalf("bulk gauge loaded %v epoch %d", on, epoch)
		}
		time.Sleep(3 * time.Second) // drained
		if src.pending() != 0 || lastBusy() || c.Stats().Backlogged {
			t.Fatalf("after the bulk: pending %d, BUSY %v", src.pending(), lastBusy())
		}
		if on, epoch := g.Loaded(0); on || epoch != 1 {
			t.Fatalf("drained gauge loaded %v epoch %d", on, epoch)
		}
		// The peer's BUSY flag.
		if err := p.ping(50, true); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if !c.Stats().PeerBusy {
			t.Fatal("PeerBusy not set by a BUSY PING")
		}
		if on, epoch := g.Loaded(0); !on || epoch != 2 {
			t.Fatalf("peer-busy gauge loaded %v epoch %d", on, epoch)
		}
		if err := p.ping(51, false); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if c.Stats().PeerBusy {
			t.Fatal("PeerBusy kept after a PING without BUSY")
		}
		c.Kill(CauseLocalClose, "test end")
		hWait(t, c)
		if on, _ := g.Loaded(0); on || g.inflight.Load() != 0 || g.backlogged.Load() != 0 {
			t.Fatalf("gauge after the carrier ended: inflight %d backlogged %d", g.inflight.Load(), g.backlogged.Load())
		}
		p.close()
		src.chunk.Release()
	})
}

// TestGaugeContributionTracksCarrier (§8.2): a carrier's gauge contribution
// is its unproven forward bytes plus the reverse bound rxRate·srtt; it
// follows commits and PONGs and is withdrawn completely when the carrier
// ends.
func TestGaugeContributionTracksCarrier(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		c, p := hPair(t, env, nil)
		g := NewGauge()
		src := newSource(env, ChunkSize, true)
		c.Start(src, &hBell{}, StartOptions{Gauge: g})
		synctest.Wait()
		src.offer(100 << 10) // nobody answers PINGs: everything stays unproven
		c.Wake()
		synctest.Wait()
		if got := g.inflight.Load(); got != 100<<10 || c.Inflight() != 100<<10 {
			t.Fatalf("gauge %d, carrier inflight %d, want %d", got, c.Inflight(), 100<<10)
		}
		// Reverse traffic: rxRate·srtt joins the contribution at the next
		// PONG.
		p.autoPong(func(uint32) time.Duration { return 20 * time.Millisecond })
		for i := range 20 {
			_ = p.sendFrames(hFrame{t: wire.TypeData, handle: wire.SessionHandle, payload: dataPayload(uint64(i)*(32<<10), 32<<10)})
			time.Sleep(10 * time.Millisecond)
		}
		synctest.Wait()
		st := c.Stats()
		want := st.Inflight + int64(st.RxRate*st.SRTT.Seconds())
		if st.RxRate == 0 || st.SRTT == 0 || g.inflight.Load() != want {
			t.Fatalf("gauge %d, want inflight %d + rxRate %.0f × srtt %v", g.inflight.Load(), st.Inflight, st.RxRate, st.SRTT)
		}
		c.Kill(CauseLocalClose, "test end")
		hWait(t, c)
		if g.inflight.Load() != 0 || g.backlogged.Load() != 0 {
			t.Fatalf("gauge after the end: inflight %d backlogged %d", g.inflight.Load(), g.backlogged.Load())
		}
		p.close()
		src.chunk.Release()
	})
}

// TestReceiverPingCadence_P12 (F12): a carrier that only receives DATA
// PINGs every PingBusy while DATA arrives (so a silent drop of the path is
// detected within the deadline, not after PingIdle), and falls back to
// PingIdle once the DATA stops.
func TestReceiverPingCadence_P12(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		c, p := hPair(t, env, nil)
		p.autoPong(nil)
		c.Start(&hEP{}, &hBell{}, StartOptions{})
		synctest.Wait()
		base := p.count(wire.TypePing)
		var off uint64
		for range 100 { // 1 s of DATA every 10 ms
			_ = p.sendFrames(hFrame{t: wire.TypeData, handle: wire.SessionHandle, payload: dataPayload(off, 1000)})
			off += 1000
			time.Sleep(10 * time.Millisecond)
		}
		if n := p.count(wire.TypePing) - base; n < 18 || n > 21 {
			t.Fatalf("%d PINGs in 1 s of received DATA, want ≈ 20 (PingBusy)", n)
		}
		mid := p.count(wire.TypePing)
		time.Sleep(5 * time.Second)
		if n := p.count(wire.TypePing) - mid; n > 1 {
			t.Fatalf("%d PINGs in 5 idle seconds, want at most 1 (PingIdle)", n)
		}
		c.Kill(CauseLocalClose, "test end")
		hWait(t, c)
		p.close()
	})
}

// TestOldestPingDecidesDeath_L25 (plan §3.6): while received DATA keeps the
// cadence at PingBusy, the peer answers the first PINGs and then stops; the
// carrier dies with ping_timeout exactly D after the first unanswered
// PING's commit, although newer PINGs keep going out behind it — the
// oldest committed, unanswered PING decides, not the newest.
func TestOldestPingDecidesDeath_L25(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		env.Timing.DeadMin, env.Timing.DeadMax = time.Second, time.Second
		c, p := hPair(t, env, nil)
		const answered = 10
		var mu sync.Mutex
		var firstUnanswered time.Time
		behind := 0 // PINGs written after the first unanswered one
		p.setHandler(func(f wire.Frame) {
			if f.Type != wire.TypePing {
				return
			}
			pg, _ := wire.ParsePing(f.Payload)
			if pg.ID <= answered {
				p.later(time.Microsecond, func() { _ = p.pong(pg) })
				return
			}
			mu.Lock()
			if firstUnanswered.IsZero() {
				firstUnanswered = time.Now() // net.Pipe: the write returns (commits) as the peer reads it
			} else {
				behind++
			}
			mu.Unlock()
		})
		c.Start(&hEP{}, &hBell{}, StartOptions{})
		var off uint64
		for { // DATA every 10 ms keeps the cadence at PingBusy (P12)
			if dead, _, _, _ := c.Death(); dead {
				break
			}
			_ = p.sendFrames(hFrame{t: wire.TypeData, handle: wire.SessionHandle, payload: dataPayload(off, 1000)})
			off += 1000
			time.Sleep(10 * time.Millisecond)
		}
		hWait(t, c)
		p.close()
		_, cause, _, at := c.Death()
		mu.Lock()
		defer mu.Unlock()
		if firstUnanswered.IsZero() || behind < 5 {
			t.Fatalf("stimulus missing: first unanswered PING at %v, %d PINGs behind it", firstUnanswered, behind)
		}
		if cause != CausePingTimeout || at.Sub(firstUnanswered) != time.Second {
			t.Fatalf("death %v %v after the first unanswered PING, want ping_timeout after D = 1s (%d newer PINGs outstanding)", cause, at.Sub(firstUnanswered), behind)
		}
	})
}

// TestFullPingRingResumesOnPong_L25: on a path whose RTT (1 s) exceeds 16
// PING intervals, the record ring fills and further PINGs wait; the PONG
// that frees a record wakes the writer, so the next PING goes out in the
// same instant — not at the death-deadline timer the writer slept on.
func TestFullPingRingResumesOnPong_L25(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		c, p := hPair(t, env, nil)
		const rtt = time.Second
		var mu sync.Mutex
		pingAt := map[uint32]time.Time{}
		p.setHandler(func(f wire.Frame) {
			if f.Type != wire.TypePing {
				return
			}
			pg, _ := wire.ParsePing(f.Payload)
			mu.Lock()
			pingAt[pg.ID] = time.Now()
			mu.Unlock()
			p.later(rtt, func() { _ = p.pong(pg) })
		})
		src := newSource(env, 4<<10, false)
		src.offer(4 << 10) // unproven in flight until a PONG proves it: PINGs every PingBusy
		start := time.Now()
		c.Start(src, &hBell{}, StartOptions{})
		time.Sleep(rtt + 100*time.Millisecond)
		c.Kill(CauseLocalClose, "test end")
		hWait(t, c)
		p.close()
		src.chunk.Release()
		mu.Lock()
		defer mu.Unlock()
		pb := env.Timing.PingBusy
		for id := uint32(1); id <= pingRingSize; id++ {
			if got := pingAt[id].Sub(start); got != time.Duration(id-1)*pb {
				t.Fatalf("PING %d at %v, want %v: the ring did not fill at the PingBusy cadence", id, got, time.Duration(id-1)*pb)
			}
		}
		if got := pingAt[pingRingSize+1].Sub(start); got != rtt {
			t.Fatalf("PING %d at %v, want the instant the first PONG freed a record (%v)", pingRingSize+1, got, rtt)
		}
	})
}

// capRaceEP is the endpoint of TestCapWakeRacesFill_L32: it fills exactly
// the 128 KiB cap; once armed, a Fill finds the cap reached and, before
// that Fill returns, lets the PONG that proves every byte arrive (the
// reader applies it while the writer is still inside Fill); afterwards it
// sends more DATA whenever there is room under the cap.
type capRaceEP struct {
	hEP
	chunk *Buf
	off   uint64
	armed atomic.Bool
	raced atomic.Bool
	race  func() // delivers the PONG and waits until the reader applied it
}

func (e *capRaceEP) Fill(c *Conn, b *Batch) {
	switch {
	case e.off < 128<<10:
		for e.off < 128<<10 && b.AddData(wire.SessionHandle, e.off, e.chunk.B[:ChunkSize], e.chunk, false) {
			e.off += ChunkSize
		}
	case e.armed.Load() && !e.raced.Load():
		if c.Inflight() >= c.Capacity() {
			b.MarkCapBlocked()
			e.raced.Store(true)
			e.race()
		}
	case e.raced.Load() && e.off < 192<<10 && c.Inflight() < c.Capacity():
		if b.AddData(wire.SessionHandle, e.off, e.chunk.B[:ChunkSize], e.chunk, false) {
			e.off += ChunkSize
		}
	}
}

// TestCapWakeRacesFill_L32 (C5, §3.5): the PONG that proves every in-flight
// byte is applied while the writer is inside a Fill that already decided
// "cap-blocked" (after a round that was not cap-blocked, with no cap-hit
// PING pending): the writer still resumes in that same instant instead of
// sleeping until its next PING (PingBusy = 1 s here), because the
// cap-blocked flag is published before Fill evaluates the cap.
func TestCapWakeRacesFill_L32(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		env.Timing.PingBusy = time.Second
		c, p := hPair(t, env, nil)
		ep := &capRaceEP{chunk: env.Bufs.Get(ChunkSize, nil)}
		var mu sync.Mutex
		var pings []wire.Ping
		var resumed time.Time
		p.setHandler(func(f wire.Frame) {
			mu.Lock()
			defer mu.Unlock()
			switch f.Type {
			case wire.TypePing:
				pg, _ := wire.ParsePing(f.Payload)
				pings = append(pings, pg)
			case wire.TypeData:
				if binary.BigEndian.Uint64(f.Payload) >= 128<<10 && resumed.IsZero() {
					resumed = time.Now()
				}
			}
		})
		ep.race = func() {
			mu.Lock()
			pg := pings[len(pings)-1] // the PING sent after the 128 KiB: its mark covers them
			mu.Unlock()
			_ = p.pong(pg)
			synctest.Wait() // the reader applied the PONG; this writer is still inside Fill
		}
		start := time.Now()
		c.Start(ep, &hBell{}, StartOptions{})
		time.Sleep(1500 * time.Millisecond) // PING 1 + 128 KiB at 0; PING 2 alone at 1 s
		ep.armed.Store(true)
		c.Wake() // new data waits: the next Fill finds the cap reached
		raceAt := time.Now()
		time.Sleep(time.Second)
		inflight := c.Inflight()
		c.Kill(CauseLocalClose, "test end")
		hWait(t, c)
		p.close()
		ep.chunk.Release()
		mu.Lock()
		defer mu.Unlock()
		if !ep.raced.Load() || len(pings) < 2 || raceAt.Sub(start) != 1500*time.Millisecond || inflight != 64<<10 {
			t.Fatalf("stimulus missing: raced %v, PINGs %d, in flight %d afterwards", ep.raced.Load(), len(pings), inflight)
		}
		if resumed.IsZero() || !resumed.Equal(raceAt) {
			t.Fatalf("DATA resumed %v after the PONG arrived inside Fill, want at once", resumed.Sub(raceAt))
		}
	})
}

// TestGaugeNotFedAfterKillRacesStart (§8.2): a Kill that lands between
// Start's death check and Start installing the factory gauge ends the
// carrier's self-load accounting first; frames the reader still handles
// before the closer's Close (a PING with BUSY here) add nothing, so a dead
// carrier never leaves its factory's gauge backlogged.
func TestGaugeNotFedAfterKillRacesStart(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		c, p := hPair(t, env, nil)
		g := NewGauge()
		// The window replayed step by step: Start passed its death check,
		// the racing Kill records the death, Start installs the gauge, and
		// the reader handles a BUSY PING.
		if !c.setDeath(CauseLocalClose, "raced Start") {
			t.Fatal("setDeath lost")
		}
		c.mu.Lock()
		c.st.gauge = g
		c.mu.Unlock()
		c.onPing(true, &wire.Ping{ID: 1}, time.Now())
		if !c.Stats().PeerBusy {
			t.Fatal("stimulus missing: the BUSY PING was not applied")
		}
		if g.backlogged.Load() != 0 || g.inflight.Load() != 0 {
			t.Fatalf("a dead carrier fed the gauge: backlogged %d, inflight %d", g.backlogged.Load(), g.inflight.Load())
		}
		c.startCloser(closeKill, nil, time.Time{}) // the rest of the racing Kill
		hWait(t, c)
		p.close()
	})
}

// TestGaugeBusyPeerHoldsCapFloor_L29 (design §0.13 A5, §8.2): while the
// peer reports BUSY, a carrier counts at least CapFloor as its reverse
// bound, so a saturated download whose rxRate × srtt stays below the load
// threshold — a path whose bandwidth-delay product is below the floor —
// still loads the gauge; without the peer's BUSY the same reverse traffic
// does not (the backlog gate of the guard is unchanged).
func TestGaugeBusyPeerHoldsCapFloor_L29(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		c, p := hPair(t, env, nil)
		p.keep()
		g := NewGauge()
		c.Start(&hEP{}, &hBell{}, StartOptions{Gauge: g})
		p.autoPong(func(uint32) time.Duration { return 20 * time.Millisecond })
		// A trickle of reverse DATA: rxRate × srtt stays far below the
		// threshold.
		for i := range 20 {
			_ = p.sendFrames(hFrame{t: wire.TypeData, handle: wire.SessionHandle, payload: dataPayload(uint64(i)*(1<<10), 1<<10)})
			time.Sleep(10 * time.Millisecond)
		}
		synctest.Wait()
		const threshold = 64 << 10
		st := c.Stats()
		rev := int64(st.RxRate * st.SRTT.Seconds())
		if st.RxRate == 0 || st.SRTT == 0 || rev >= threshold || st.PeerBusy {
			t.Fatalf("stimulus: rxRate %.0f B/s × srtt %v = %d bytes, peer BUSY %v; want a small reverse bound and no BUSY", st.RxRate, st.SRTT, rev, st.PeerBusy)
		}
		if loaded, _ := g.Loaded(threshold); loaded || g.inflight.Load() != rev {
			t.Fatalf("without the peer's BUSY: gauge loaded %v with %d bytes, want unloaded with %d", loaded, g.inflight.Load(), rev)
		}
		// The peer reports BUSY: the reverse bound becomes the floor.
		if err := p.ping(900, true); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if st := c.Stats(); !st.PeerBusy {
			t.Fatal("the peer's BUSY PING was not recorded")
		}
		if loaded, _ := g.Loaded(threshold); !loaded || g.inflight.Load() != env.Timing.CapFloor {
			t.Fatalf("with the peer's BUSY: gauge loaded %v with %d bytes, want loaded with the floor %d", loaded, g.inflight.Load(), env.Timing.CapFloor)
		}
		// BUSY clears: back to the measured bound, unloaded.
		if err := p.ping(901, false); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if loaded, _ := g.Loaded(threshold); loaded || g.inflight.Load() >= threshold {
			t.Fatalf("after BUSY cleared: gauge loaded %v with %d bytes", loaded, g.inflight.Load())
		}
		c.Kill(CauseLocalClose, "test end")
		hWait(t, c)
		if g.inflight.Load() != 0 || g.backlogged.Load() != 0 {
			t.Fatalf("gauge after the end: inflight %d backlogged %d", g.inflight.Load(), g.backlogged.Load())
		}
		p.close()
	})
}
