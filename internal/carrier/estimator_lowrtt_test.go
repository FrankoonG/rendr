package carrier

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Backlog judgement below a 5 ms RTT (design §0.9 X4, §4.10, D15). In a
// cap-limited flow every PING is a cap-hit PING one RTT after the previous
// commit, and a backlog interval can only be judged once it spans 5 ms: the
// PINGs in between carry the latest judged state on and must not restart
// the interval. Names in this file use the lt prefix.

// ltRef is one 64 KiB period of the hSource pattern.
var ltRef = func() []byte {
	b := make([]byte, ChunkSize)
	for i := range b {
		b[i] = hPattern(uint64(i))
	}
	return b
}()

// ltSink is the passive endpoint of a session carrier pair: its first Fill
// places OPEN_ACK(OK) (the carrier is held until then); it sends no DATA,
// checks every DATA byte it receives against the hSource pattern in stream
// order, and notes when the want-th byte arrived.
type ltSink struct {
	hEP
	want   uint64
	placed bool // touched only by the passive carrier's writer goroutine
	done   chan struct{}

	mu     sync.Mutex
	next   uint64
	bad    string
	doneAt time.Time
}

func newLtSink(want uint64) *ltSink { return &ltSink{want: want, done: make(chan struct{})} }

func (s *ltSink) Fill(c *Conn, b *Batch) {
	if !s.placed {
		s.placed = b.AddOpenAck(wire.SessionHandle, &wire.OpenAck{Status: wire.StatusOK, Window: 8 << 20})
	}
}

func (s *ltSink) Data(c *Conn, off uint64, p []byte, buf *Buf) error {
	defer buf.Release()
	s.mu.Lock()
	defer s.mu.Unlock()
	in := int(off % ChunkSize)
	switch {
	case s.bad != "":
	case off != s.next:
		s.bad = fmt.Sprintf("DATA at %d, want %d", off, s.next)
	case in+len(p) > ChunkSize || !bytes.Equal(p, ltRef[in:in+len(p)]):
		s.bad = fmt.Sprintf("DATA at %d does not carry the pattern", off)
	default:
		s.next += uint64(len(p))
		if s.next == s.want {
			s.doneAt = time.Now()
			close(s.done)
		}
	}
	return nil
}

// result returns the bytes verified in order, the first violation ("" if
// none) and when the last wanted byte arrived (zero: not yet).
func (s *ltSink) result() (next uint64, bad string, doneAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.next, s.bad, s.doneAt
}

// ltLinkPair establishes one session carrier pair over a new link with the
// given rate and one-way delay: the dialer's Establish (OPEN) against a
// passive end that runs ReadHello and starts its carrier held with sink.
// The dialer's carrier is returned unstarted. A cleanup kills both carriers
// and closes the link, so a failed test still leaves its bubble empty.
func ltLinkPair(t *testing.T, envD, envP *Env, rate float64, delay time.Duration, sink Endpoint) (dialer, passive *Conn) {
	t.Helper()
	pass := make(chan *Conn, 1)
	link := rendrtest.NewLink(rendrtest.LinkConfig{Name: "lan", Accept: func(nc net.Conn) error {
		h, err := ReadHello(envP, nc, time.Now().Add(10*time.Second), 4096, nil)
		if err != nil {
			pass <- nil
			return nil // ReadHello closed nc
		}
		h.Conn.Start(sink, &hBell{}, StartOptions{Hold: true})
		pass <- h.Conn
		return nil
	}})
	link.SetRate(rate)
	link.SetDelay(delay, 0)
	var conns []*Conn
	t.Cleanup(func() {
		for _, c := range conns {
			c.Kill(CauseLocalClose, "test end")
			<-c.Done()
		}
		link.Close()
	})
	est, err := Establish(context.Background(), envD, Factory{Name: "lan", Dial: link.Dial}, envD.IDs.Next(), wire.TypeOpen, openPayload(0), nil)
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}
	conns = append(conns, est.Conn)
	pc := <-pass
	if pc == nil {
		t.Fatal("the passive handshake failed")
	}
	conns = append(conns, pc)
	if est.Resp.Type != wire.TypeOpenAck {
		t.Fatalf("response %v, want OPEN_ACK", est.Resp.Type)
	}
	return est.Conn, pc
}

// TestCapLimitedFlowReachesLinkRate_L32 (design §0.9 X4): a bulk transfer
// that starts at the 128 KiB capacity floor, between two real carriers over
// a 64 MiB/s link with a 0.5 ms or 1 ms one-way delay, or a 512 MiB/s link
// with a 0.25 ms one — an RTT at the floor of about 3–4 ms, or under 1 ms on
// the fast link: below the 5 ms a backlog interval needs, with every PING a
// cap-hit PING — reaches at least 90% of the link rate, every byte intact
// and in order, with a rate estimate that never exceeds the link rate (plus
// sampling slack): the PINGs accumulate one backlog interval until it can
// be judged, so the sender says BUSY, takes a rate sample and raises its
// capacity above the floor. (With the interval restarted at every PING
// commit the sender stayed at 128 KiB per RTT: about 50% of the 64 MiB/s
// link at 1 ms and 65% at 0.5 ms. The fast link also needs the busy time of
// the unjudged PING intervals: with only the last RTT's counted, it stays
// under 25% of a 5 ms interval there, though not at 3–4 ms;
// TestBusyJudgedBelowMinSampleRTT_L32 pins that accumulation directly.)
func TestCapLimitedFlowReachesLinkRate_L32(t *testing.T) {
	for _, tc := range []struct {
		rate  float64       // bytes/s per direction
		delay time.Duration // one way
		total uint64        // bytes: half a second at 64 MiB/s, an eighth at 512 MiB/s
	}{
		{64 << 20, 500 * time.Microsecond, 32 << 20},
		{64 << 20, time.Millisecond, 32 << 20},
		{512 << 20, 250 * time.Microsecond, 64 << 20},
	} {
		rate, delay, total := tc.rate, tc.delay, tc.total
		t.Run(fmt.Sprintf("%dMiBps/%v", int(rate)>>20, delay), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				envD, envP := phEnvs()
				sink := newLtSink(total)
				dc, pc := ltLinkPair(t, envD, envP, rate, delay, sink)
				src := newSource(envD, ChunkSize, true)
				defer src.chunk.Release()
				var floorHits atomic.Int32 // rounds that waited at the 128 KiB floor
				src.setFill(func(c *Conn, b *Batch) {
					src.fillData(c, b)
					if b.CapBlocked() && c.Capacity() == envD.Timing.CapFloor {
						floorHits.Add(1)
					}
				})
				src.offer(total)
				start := time.Now()
				dc.Start(src, &hBell{}, StartOptions{})
				var maxCap int64
				var maxRate float64
				var backlogged bool
				for timeout := time.After(10 * time.Second); ; {
					select {
					case <-sink.done:
					case <-timeout:
						next, bad, _ := sink.result()
						t.Fatalf("stalled: %d of %d bytes after %v (%s), stats %+v", next, total, time.Since(start), bad, dc.Stats())
					case <-time.After(time.Millisecond): // sample the sender's estimator
						st := dc.Stats()
						maxCap = max(maxCap, st.Cap)
						maxRate = max(maxRate, st.Rate)
						backlogged = backlogged || st.Backlogged
						continue
					}
					break
				}
				next, bad, doneAt := sink.result()
				st := dc.Stats()
				took := doneAt.Sub(start)
				got := float64(total) / took.Seconds()
				t.Logf("%d MiB in %v: %.1f MiB/s of a %d MiB/s link; cap peaked at %d KiB, rate at %.1f MiB/s (peak %.1f), srtt %v, minRTT %v",
					total>>20, took, got/(1<<20), int(rate)>>20, maxCap>>10, st.Rate/(1<<20), maxRate/(1<<20), st.SRTT, st.MinRTT)
				if bad != "" || next != total {
					t.Fatalf("data: %d bytes in order, violation %q", next, bad)
				}
				for _, c := range []*Conn{dc, pc} {
					if dead, cause, detail, _ := c.Death(); dead {
						t.Fatalf("carrier %d died: %v %s", c.ID(), cause, detail)
					}
				}
				// Stimulus: the flow waited at the floor before the cap rose.
				if floorHits.Load() == 0 {
					t.Fatal("stimulus missing: the flow was never cap-limited at the floor")
				}
				if !backlogged || st.Rate <= 0 || maxCap <= envD.Timing.CapFloor {
					t.Fatalf("the sender never judged its backlog: Backlogged seen %v, rate %.0f, cap peaked at %d (floor %d)", backlogged, st.Rate, maxCap, envD.Timing.CapFloor)
				}
				if maxRate > 1.2*rate {
					t.Fatalf("the rate estimate peaked at %.1f MiB/s on a %d MiB/s link", maxRate/(1<<20), int(rate)>>20)
				}
				if got < 0.9*rate {
					t.Fatalf("throughput %.1f MiB/s, want ≥ 90%% of the %d MiB/s link", got/(1<<20), int(rate)>>20)
				}
				dc.Kill(CauseLocalClose, "test end")
				pc.Kill(CauseLocalClose, "test end")
				hWait(t, dc)
				hWait(t, pc)
				synctest.Wait()
				if envD.Budget.Used() != 0 || envP.Budget.Used() != 0 {
					t.Fatalf("budget %d + %d after the end", envD.Budget.Used(), envP.Budget.Used())
				}
			})
		})
	}
}

// ltPing is one PING the peer received: when (after the carrier's Start)
// and its BUSY flag.
type ltPing struct {
	at   time.Duration
	busy bool
}

// ltPings records every PING the peer receives and answers it with its
// PONG rtt later.
type ltPings struct {
	mu    sync.Mutex
	start time.Time
	list  []ltPing
}

func ltAnswer(p *wirePeer, start time.Time, rtt time.Duration) *ltPings {
	r := &ltPings{start: start}
	p.setHandler(func(f wire.Frame) {
		if f.Type != wire.TypePing {
			return
		}
		pg, err := wire.ParsePing(f.Payload)
		if err != nil {
			return
		}
		r.mu.Lock()
		r.list = append(r.list, ltPing{time.Since(r.start), f.Flags&wire.FlagPingBusy != 0})
		r.mu.Unlock()
		p.later(rtt, func() { _ = p.pong(pg) })
	})
	return r
}

func (r *ltPings) snapshot() []ltPing {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]ltPing(nil), r.list...)
}

// TestBusyJudgedBelowMinSampleRTT_L32 (design §0.9 X4, D15, §8.2): a
// cap-limited bulk flow whose PONGs come back 0.5–4.5 ms after its PINGs —
// every PING a cap-hit PING one RTT after the previous commit — says BUSY:
// exactly the first PING whose backlog interval spans 5 ms (counted from
// Start through the earlier, unjudged PINGs) carries it; its PONG gives the
// first rate sample, which lifts the capacity above the floor; the factory
// gauge loads once (one epoch) and the flag holds without flapping while
// the flow lasts; the first judged interval after the flow clears it, and
// the gauge with it. Every byte arrives intact. A demand-limited flow at
// the same RTT never says BUSY and takes no rate sample.
func TestBusyJudgedBelowMinSampleRTT_L32(t *testing.T) {
	for _, rtt := range []time.Duration{500 * time.Microsecond, time.Millisecond, 2 * time.Millisecond, 4500 * time.Microsecond} {
		t.Run("bulk/"+rtt.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				env := hEnv()
				env.Timing.Window = 1 << 20 // the capacity ceiling bounds the work per round trip
				c, p := hPair(t, env, nil)
				p.keep()
				g := NewGauge()
				src := newSource(env, ChunkSize, true)
				defer src.chunk.Release()
				const total = 4 << 20
				src.offer(total)
				start := time.Now()
				pings := ltAnswer(p, start, rtt)
				c.Start(src, &hBell{}, StartOptions{Gauge: g})

				// PINGs leave at 0 (the first and a cap-hit one) and then one
				// RTT apart (cap-hit PINGs); the first at or after 5 ms judges
				// the interval that began at Start.
				judgedAt := (minRateSample + rtt - 1) / rtt * rtt
				time.Sleep(judgedAt)
				synctest.Wait()
				ps := pings.snapshot()
				last := ps[len(ps)-1]
				if last.at != judgedAt || !last.busy {
					t.Fatalf("PINGs %v: want a BUSY PING at %v", ps, judgedAt)
				}
				for _, pg := range ps[:len(ps)-1] {
					if pg.busy {
						t.Fatalf("PINGs %v: BUSY before an interval of 5 ms was judged", ps)
					}
				}
				if len(ps) != int(judgedAt/rtt)+2 {
					t.Fatalf("PINGs %v: want the first two at 0, then one per RTT", ps)
				}
				st := c.Stats()
				if on, epoch := g.Loaded(0); !on || epoch != 1 || !st.Backlogged || st.Rate != 0 || st.Cap != env.Timing.CapFloor {
					t.Fatalf("at the BUSY PING: gauge loaded %v epoch %d, stats %+v (want backlogged, still at the floor)", on, epoch, st)
				}
				time.Sleep(rtt) // its PONG: the first rate sample
				synctest.Wait()
				if st := c.Stats(); st.Rate <= 0 || st.Cap <= env.Timing.CapFloor {
					t.Fatalf("after the BUSY PING's PONG: rate %.0f, cap %d (floor %d)", st.Rate, st.Cap, env.Timing.CapFloor)
				}

				for limit := time.After(time.Second); p.dataBytes() < total; {
					select {
					case <-limit:
						t.Fatalf("stalled: %d of %d bytes", p.dataBytes(), total)
					case <-time.After(rtt):
					}
				}
				flowEnd := time.Since(start)
				time.Sleep(200 * time.Millisecond) // idle: the next judged interval clears BUSY
				synctest.Wait()
				st = c.Stats()
				if on, epoch := g.Loaded(0); on || epoch != 1 || g.backlogged.Load() != 0 || st.Backlogged || st.Inflight != 0 {
					t.Fatalf("after the flow: gauge loaded %v epoch %d backlogged %d, stats %+v", on, epoch, g.backlogged.Load(), st)
				}
				// One run of BUSY PINGs (no flapping): every PING from the
				// judged one through the end of the flow, cleared after it.
				ps = pings.snapshot()
				runs, prev := 0, false
				for _, pg := range ps {
					if pg.busy && !prev {
						runs++
					}
					if !pg.busy && pg.at >= judgedAt && pg.at <= flowEnd {
						t.Fatalf("PING at %v without BUSY during the flow (judged at %v, ended by %v): %v", pg.at, judgedAt, flowEnd, ps)
					}
					prev = pg.busy
				}
				if runs != 1 || ps[len(ps)-1].busy || ps[len(ps)-1].at <= flowEnd {
					t.Fatalf("%d runs of BUSY PINGs, last PING %+v (flow ended by %v): want one run, cleared after the flow: %v", runs, ps[len(ps)-1], flowEnd, ps)
				}
				hCheckData(t, p, total)
				if dead, cause, detail, _ := c.Death(); dead {
					t.Fatalf("died: %v %s", cause, detail)
				}
			})
		})
	}
	t.Run("demand-limited/1ms", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			env := hEnv()
			c, p := hPair(t, env, nil)
			p.keep()
			g := NewGauge()
			src := newSource(env, ChunkSize, true)
			defer src.chunk.Release()
			start := time.Now()
			pings := ltAnswer(p, start, time.Millisecond)
			c.Start(src, &hBell{}, StartOptions{Gauge: g})
			for range 100 { // 8 KiB every 2 ms: far below 128 KiB per RTT
				src.offer(8 << 10)
				c.Wake()
				time.Sleep(2 * time.Millisecond)
			}
			time.Sleep(200 * time.Millisecond)
			synctest.Wait()
			ps := pings.snapshot()
			for _, pg := range ps {
				if pg.busy {
					t.Fatalf("a demand-limited writer said BUSY: %v", ps)
				}
			}
			st := c.Stats()
			if on, epoch := g.Loaded(0); on || epoch != 0 || st.Backlogged || st.Rate != 0 || st.Cap != env.Timing.CapFloor {
				t.Fatalf("gauge loaded %v epoch %d, stats %+v", on, epoch, st)
			}
			// Stimulus: the flow went out and its PINGs (PingBusy cadence
			// while DATA is unproven) judged several intervals.
			if len(ps) < 5 || st.SRTT != time.Millisecond {
				t.Fatalf("stimulus missing: PINGs %v, srtt %v", ps, st.SRTT)
			}
			hCheckData(t, p, 800<<10)
		})
	})
}
