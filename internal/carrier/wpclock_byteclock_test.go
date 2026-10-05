package carrier

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Byte-clocked PINGs inside a burst (design §0.13 A7b, §4.10). Names in this
// file use the bc prefix.

// bcState reads the carrier's PING count and outstanding records.
func bcState(c *Conn) (pings uint32, outstanding int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.st.nextPingID - c.env.Presets.firstPingID(), c.st.n
}

// bcPreset gives an unstarted carrier the estimate of a measured path:
// rate (bytes/s) and minRTT (and srtt). With a CapFloor above
// 2·rate·(minRTT + 100 ms) the floor sets the capacity, and with it the
// clock step, while rate·minRTT, the bandwidth-delay product, decides
// whether the clock runs at all.
func bcPreset(c *Conn, rate float64, minRTT time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.st.rate, c.st.minRTT, c.st.srtt, c.st.rttSeen = rate, minRTT, minRTT, true
}

// bcPath is one long-path transfer: total bytes from the dialer (and,
// duplex, as many back from the passive) over a link of rate bytes/s per
// direction and the given RTT, with a capacity ceiling of window.
type bcPath struct {
	rtt    time.Duration
	rate   float64
	window int64
	total  uint64
	buf    int // the link's buffer per direction; 0: 64 MiB, which takes a whole capacity at once as a socket buffer would
	duplex bool
}

func (tc bcPath) String() string {
	s := fmt.Sprintf("rtt%v/%gMiBps/w%dMiB", tc.rtt, tc.rate/(1<<20), tc.window>>20)
	if tc.buf != 0 {
		s += fmt.Sprintf("/buf%dKiB", tc.buf>>10)
	}
	return s
}

// bcRun is the outcome of one long-path transfer.
type bcRun struct {
	steady, steadyBack float64 // bytes/s after the warm-up: the dialer's flow, the passive's (duplex)
	peak, peakBack     float64 // rate estimates: the dialer's, the passive's
	pings              uint32  // PINGs the dialer sent
	maxOut             int     // the dialer's outstanding PING records, at most
	longest            time.Duration
	took               time.Duration
	stats              Stats // the dialer's carrier at the end
}

// bcWarmup is excluded from the steady state (M1c E21).
const bcWarmup = 2 * time.Second

// bcLongPath runs one cap-limited transfer (bcPath) and reports, besides
// throughput, rate peaks and PINGs, the longest conn Write of the dialer
// (longest: positive once the link's buffer filled and writes blocked). It
// fails t unless every byte arrives intact and in order, no carrier dies,
// and at least a second of steady state follows the warm-up.
func bcLongPath(t *testing.T, tc bcPath) bcRun {
	t.Helper()
	rtt, rate, window, total, duplex := tc.rtt, tc.rate, tc.window, tc.total, tc.duplex
	buf := tc.buf
	if buf == 0 {
		buf = 64 << 20
	}
	envD, envP := phEnvs()
	envD.Timing.Window, envP.Timing.Window = window, window
	sink := newLtSink(total)
	var ep Endpoint = sink
	if duplex {
		back := newSource(envP, ChunkSize, true)
		defer back.chunk.Release()
		back.offer(total)
		ep = &lrDuplex{ltSink: sink, src: back}
	}
	var longest atomic.Int64
	timed := func(nc net.Conn) net.Conn {
		return &hookConn{Conn: nc, onWrite: func(nc net.Conn, p []byte) (int, error) {
			start := time.Now()
			n, err := nc.Write(p)
			if d := int64(time.Since(start)); d > longest.Load() {
				longest.Store(d) // the dialer's writer is the only writer after the handshake
			}
			return n, err
		}}
	}
	dc, pc := lrLinkPairWrap(t, envD, envP, rate, rtt/2, buf, ep, timed)
	src := newSource(envD, ChunkSize, true)
	defer src.chunk.Release()
	src.offer(total)
	start := time.Now()
	dc.Start(src, &hBell{}, StartOptions{})

	var r bcRun
	var fwdAt, backAt uint64 // bytes delivered at the end of the warm-up
	var backDone time.Time
	warm := false
	for limit := time.After(time.Minute); ; {
		select {
		case <-limit:
			next, bad, _ := sink.result()
			t.Fatalf("stalled: %d of %d bytes after %v (%s), the passive's flow %d bytes, stats %+v", next, total, time.Since(start), bad, src.rxBytes.Load(), dc.Stats())
		case <-time.After(time.Millisecond):
			r.peak = max(r.peak, dc.Stats().Rate)
			r.peakBack = max(r.peakBack, pc.Stats().Rate)
			_, n := bcState(dc)
			r.maxOut = max(r.maxOut, n)
			if !warm && time.Since(start) >= bcWarmup {
				warm = true
				fwdAt, _, _ = sink.result()
				backAt = uint64(src.rxBytes.Load())
			}
			if duplex && backDone.IsZero() && uint64(src.rxBytes.Load()) >= total {
				backDone = time.Now()
			}
			if _, _, done := sink.result(); done.IsZero() || (duplex && backDone.IsZero()) {
				continue
			}
		}
		break
	}
	next, bad, doneAt := sink.result()
	if bad != "" || next != total {
		t.Fatalf("data: %d bytes in order, violation %q", next, bad)
	}
	if duplex && uint64(src.rxBytes.Load()) != total {
		t.Fatalf("the passive's flow: %d of %d bytes", src.rxBytes.Load(), total)
	}
	end := start.Add(bcWarmup + time.Second)
	if !warm || doneAt.Before(end) || (duplex && backDone.Before(end)) {
		t.Fatalf("load: the transfer ended %v after the start (the passive's %v), want ≥ 1 s of steady state after the %v warm-up",
			doneAt.Sub(start), backDone.Sub(start), bcWarmup)
	}
	for _, c := range []*Conn{dc, pc} {
		if dead, cause, detail, _ := c.Death(); dead {
			t.Fatalf("carrier %d died: %v %s", c.ID(), cause, detail)
		}
	}
	r.steady = float64(total-fwdAt) / doneAt.Sub(start.Add(bcWarmup)).Seconds()
	if duplex {
		r.steadyBack = float64(total-backAt) / backDone.Sub(start.Add(bcWarmup)).Seconds()
	}
	r.pings, _ = bcState(dc)
	r.longest = time.Duration(longest.Load())
	r.took = doneAt.Sub(start)
	if backDone.After(doneAt) {
		r.took = backDone.Sub(start)
	}
	r.stats = dc.Stats()
	return r
}

// bcPingLimit bounds the PINGs of a cap-limited transfer of total bytes
// that took took with clock step step: the byte clock adds at most one PING
// per step of DATA, each refill after a PONG at most its cap-hit PING (no
// more refills than PONGs that proved a step), the cadence one per PingBusy,
// and the ramp from the floor a few.
func bcPingLimit(total uint64, step int64, took, pingBusy time.Duration) float64 {
	return 2*float64(total)/float64(step) + float64(took/pingBusy) + 16
}

// TestByteClockFillsLongPath_L15_L32: a cap-limited bulk transfer over one
// carrier on a rate-limited long path keeps the path busy: at least 90% of
// min(link rate, Window/RTT) in steady state (the first 2 s excluded).
// Before the byte clock the only PING proving a burst was the cap-hit PING
// queued behind all of it, so each burst's capacity came back one round
// trip after the burst drained and the path ran at R·C/(C + R·RTT): 12.7 of
// 16 MiB/s (79%) at 100 ms, 5.9 of 8 MiB/s (73%) at 400 ms, with an 8 MiB
// window and a link buffer that takes a whole burst at once (64 MiB, as a
// socket buffer would). With a PING after every clock step the PONGs return
// while the burst drains.
//
// The rate estimate stays within the drain rate (5% slack): every PING
// placed while the clock runs ends its batch, so its PONG's arrival matches
// its mark. A PING in front of DATA reached the peer only with the first
// link quantum of that DATA, and the short samples of a clocked flow
// starting at its PONG overstated the rate: a cadence PING in front of a
// refill of a batch or two, sampled up to the lone cap-hit PING behind the
// refill, read a 4 MiB/s link as 6.0 MiB/s (200 ms) and a 2 MiB/s one as
// 3.0 MiB/s (300 ms), and the first two rows as 1.17× and 1.07×; behind a
// 1 MiB link buffer, where writes block (stimulus: the dialer's longest
// Write), a PONG frees capacity during a write, and the cap-hit PING
// requested at its end, in front of the next round's DATA, read 4 MiB/s at
// 50 ms as 7.8 MiB/s. The dialer's PINGs stay within one per clock step of
// DATA plus its cadence (bcPingLimit), and the PING records never fill the
// ring. Every byte arrives intact, and no carrier dies.
func TestByteClockFillsLongPath_L15_L32(t *testing.T) {
	for _, tc := range []bcPath{
		{rtt: 100 * time.Millisecond, rate: 16 << 20, window: 8 << 20, total: 64 << 20},
		{rtt: 400 * time.Millisecond, rate: 8 << 20, window: 8 << 20, total: 40 << 20},
		{rtt: 200 * time.Millisecond, rate: 4 << 20, window: 8 << 20, total: 24 << 20},
		{rtt: 300 * time.Millisecond, rate: 2 << 20, window: 2 << 20, total: 12 << 20},
		{rtt: 50 * time.Millisecond, rate: 4 << 20, window: 2 << 20, total: 24 << 20, buf: 1 << 20},
	} {
		t.Run(tc.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := bcLongPath(t, tc)
				bound := min(tc.rate, float64(tc.window)/tc.rtt.Seconds())
				step := max(clockStepMin, r.stats.Cap/clockStepDiv)
				t.Logf("%d MiB in %v: steady %.2f MiB/s = %.1f%% of %.1f MiB/s; rate peak %.2f MiB/s (%.3f×); %d PINGs (%.2f per MiB, clock step %d KiB), at most %d records outstanding; longest write %v; srtt %v, cap %d KiB",
					tc.total>>20, r.took, r.steady/(1<<20), 100*r.steady/bound, bound/(1<<20), r.peak/(1<<20), r.peak/tc.rate,
					r.pings, float64(r.pings)/float64(tc.total>>20), step>>10, r.maxOut, r.longest, r.stats.SRTT, r.stats.Cap>>10)
				if tc.buf != 0 && r.longest < time.Millisecond {
					t.Fatalf("stimulus: the dialer's longest Write took %v behind a %d KiB link buffer, want blocking writes", r.longest, tc.buf>>10)
				}
				if r.steady < 0.9*bound {
					t.Fatalf("steady throughput %.2f MiB/s, want ≥ 90%% of min(link rate, Window/RTT) = %.2f MiB/s", r.steady/(1<<20), 0.9*bound/(1<<20))
				}
				if r.peak > 1.05*tc.rate {
					t.Fatalf("the rate estimate peaked at %.2f MiB/s on a %g MiB/s link (%.2f×, bound 1.05×)", r.peak/(1<<20), tc.rate/(1<<20), r.peak/tc.rate)
				}
				if limit := bcPingLimit(tc.total, step, r.took, hTiming().PingBusy); float64(r.pings) > limit {
					t.Fatalf("%d PINGs for %d MiB (%.2f per MiB), want ≤ %.0f", r.pings, tc.total>>20, float64(r.pings)/float64(tc.total>>20), limit)
				}
				if r.maxOut >= pingRingSize {
					t.Fatalf("%d PING records outstanding: the ring filled, a PING that releases capacity waited", r.maxOut)
				}
			})
		})
	}
}

// TestByteClockDuplexRateBounded_L32: bulk both ways over one carrier on
// the 100 ms and 400 ms paths of TestByteClockFillsLongPath_L15_L32, so
// each side's PONGs queue behind the other side's bulk and arrive in
// clusters (ACK compression). With a PONG proving new bytes every clock
// step, a rate sample over 5 ms of such arrivals read a 16 MiB/s link at
// 100 ms as up to 72 MiB/s, and the PONGs queued behind a peer's last
// burst, released after the peer's BUSY cleared, as 118 MiB/s; the estimate
// before the byte clock peaked at 56.9 MiB/s (3.6×; design §0.13 A1 allows
// 4×). Samples span half an RTT while the peer is BUSY, and a shorter one
// at most doubles the estimate (rateSpan): both sides' rate estimates stay
// within 3× of the link rate. Both flows arrive intact, no carrier dies,
// the dialer's PINGs stay within bcPingLimit and its records never fill the
// ring. (The two directions' throughput is logged, not judged: the side
// whose PONGs wait behind the other side's queue gets a capacity sized for
// its minimum RTT and falls behind, before the byte clock as after it.)
func TestByteClockDuplexRateBounded_L32(t *testing.T) {
	for _, tc := range []bcPath{
		{rtt: 100 * time.Millisecond, rate: 16 << 20, window: 8 << 20, total: 64 << 20, duplex: true},
		{rtt: 400 * time.Millisecond, rate: 8 << 20, window: 8 << 20, total: 40 << 20, duplex: true},
	} {
		t.Run(tc.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := bcLongPath(t, tc)
				bound := min(tc.rate, float64(tc.window)/tc.rtt.Seconds())
				step := max(clockStepMin, r.stats.Cap/clockStepDiv)
				t.Logf("%d MiB each way in %v: steady %.2f MiB/s (%.1f%%) and %.2f MiB/s (%.1f%%) back; rate peaks %.1f and %.1f MiB/s; %d PINGs (%.2f per MiB), at most %d records outstanding; srtt %v, cap %d KiB",
					tc.total>>20, r.took, r.steady/(1<<20), 100*r.steady/bound, r.steadyBack/(1<<20), 100*r.steadyBack/bound,
					r.peak/(1<<20), r.peakBack/(1<<20), r.pings, float64(r.pings)/float64(tc.total>>20), r.maxOut, r.stats.SRTT, r.stats.Cap>>10)
				for _, x := range []struct {
					who  string
					peak float64
				}{{"dialer", r.peak}, {"passive", r.peakBack}} {
					if x.peak > 3*tc.rate {
						t.Fatalf("the %s's rate estimate peaked at %.1f MiB/s on a %g MiB/s link (bound 3×)", x.who, x.peak/(1<<20), tc.rate/(1<<20))
					}
				}
				if limit := bcPingLimit(tc.total, step, r.took, hTiming().PingBusy); float64(r.pings) > limit {
					t.Fatalf("%d PINGs for %d MiB (%.2f per MiB), want ≤ %.0f", r.pings, tc.total>>20, float64(r.pings)/float64(tc.total>>20), limit)
				}
				if r.maxOut >= pingRingSize {
					t.Fatalf("%d PING records outstanding: the ring filled", r.maxOut)
				}
			})
		})
	}
}

// bcWrite is one physical Write of a carrier: its frames in order.
type bcWrite struct {
	at     time.Duration // after the test's start
	frames []wire.Frame
}

// bcWrites records every Write of a carrier (the writer issues exactly one
// per batch on a conn that is not an OwnedTCP) as decoded frames.
type bcWrites struct {
	mu     sync.Mutex
	start  time.Time
	writes []bcWrite
}

func (r *bcWrites) wrap(nc net.Conn) net.Conn {
	return &hookConn{Conn: nc, onWrite: func(nc net.Conn, p []byte) (int, error) {
		w := bcWrite{at: time.Since(r.start)}
		for b := p; len(b) > 0; {
			f, k, err := wire.DecodeFrame(b)
			if err != nil {
				break
			}
			cp := wire.Frame{Header: f.Header}
			cp.Payload = append([]byte(nil), f.Payload[:min(len(f.Payload), wire.PingFixedLen)]...)
			w.frames = append(w.frames, cp)
			b = b[k:]
		}
		r.mu.Lock()
		r.writes = append(r.writes, w)
		r.mu.Unlock()
		return nc.Write(p)
	}}
}

func (r *bcWrites) snapshot() []bcWrite {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]bcWrite(nil), r.writes...)
}

// bcShape summarizes a Write: "P" for a PING, "D<end KiB>" for a DATA frame
// (its end offset), "O" for a PONG, "?" for anything else.
func bcShape(w bcWrite) string {
	s := ""
	for _, f := range w.frames {
		switch f.Type {
		case wire.TypePing:
			s += "P "
		case wire.TypePong:
			s += "O "
		case wire.TypeData:
			off, _ := wire.ParseDataOffset(f.Payload)
			s += fmt.Sprintf("D%d ", (off+uint64(f.Len)-wire.DataPrefixLen)>>10)
		default:
			s += "? "
		}
	}
	return s
}

// TestByteClockPingEndsFullBatchesOnly_L11 pins where a byte-clocked PING
// goes, on a carrier whose estimate says 5 MiB/s at a 100 ms minimum RTT (a
// 500 KiB bandwidth-delay product: the clock runs). With the capacity at
// 3 MiB (a clock step of 384 KiB) and 968 KiB offered at once, the burst is
// three full batches and a 200 KiB tail: the first PING goes in front of
// batch 1, the clock PING ends batch 2 (512 KiB written since that PING),
// batch 3 carries none (256 KiB since), and neither does the tail, although
// the clock passed its step there (456 KiB): Fill stopped it short of the
// batch limit, so it ends the burst. The burst's last 456 KiB therefore
// wait for the PingBusy cadence (a writer that stops with DATA unproven
// keeps PINGing; L11, P12): the PONGs one RTT later prove 512 KiB, and the
// cadence PING's proves the rest. A burst of one full batch after an idle
// period gets no clock PING either, even when that batch alone reaches the
// step (2 MiB of capacity, a 256 KiB step): it is the first batch of its
// burst. A full batch that also reaches the capacity ends with its clock
// PING and is followed by no cap-hit PING (the clock PING proves all of
// it). On a path whose bandwidth-delay product is below one step (2 MiB/s
// at 10 ms: 20 KiB) the clock does not run, even while a standing queue
// holds its srtt at 200 ms (the gate reads the minimum RTT: 2 MiB/s × srtt
// would pass the step): a burst of a capacity's full batches carries no
// clock PING, and its cap-hit PING follows it alone, as before the byte
// clock. Every byte arrives intact.
func TestByteClockPingEndsFullBatchesOnly_L11(t *testing.T) {
	const (
		rtt  = 100 * time.Millisecond // the PONG delay: the minimum RTT stays at the preset
		rate = 5 << 20
	)
	t.Run("tail", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			env := hEnv()
			env.Timing.CapFloor = 3 << 20 // the capacity, and the clock step 384 KiB, from the start
			rec := &bcWrites{start: time.Now()}
			c, p := hPair(t, env, rec.wrap)
			bcPreset(c, rate, rtt)
			p.keep()
			p.autoPong(func(uint32) time.Duration { return rtt })
			src := newSource(env, ChunkSize, true)
			defer src.chunk.Release()
			const total = 968 << 10
			src.offer(total)
			c.Start(src, &hBell{}, StartOptions{})
			time.Sleep(env.Timing.PingBusy - time.Millisecond) // before the cadence PING
			synctest.Wait()
			if got := c.Inflight(); got != total {
				t.Fatalf("in flight before any PONG: %d, want %d", got, total)
			}
			time.Sleep(rtt - env.Timing.PingBusy + 2*time.Millisecond) // the PONGs of the burst's PINGs arrived
			synctest.Wait()
			if got := c.Inflight(); got != total-512<<10 {
				t.Fatalf("in flight after the burst's PONGs: %d, want the %d bytes after the clock PING", got, total-512<<10)
			}
			time.Sleep(time.Second)
			synctest.Wait()
			ws := rec.snapshot()
			want := []string{
				"P D64 D128 D192 D256 ",
				"D320 D384 D448 D512 P ",
				"D576 D640 D704 D768 ",
				"D832 D896 D960 D968 ",
			}
			if len(ws) < len(want)+1 {
				t.Fatalf("%d writes, want at least %d", len(ws), len(want)+1)
			}
			for i, s := range want {
				if got := bcShape(ws[i]); got != s || ws[i].at != 0 {
					t.Fatalf("write %d at %v: %q, want %q at 0", i+1, ws[i].at, got, s)
				}
			}
			// The cadence PING, PingBusy after the clock PING's commit, proves
			// the tail.
			if got := bcShape(ws[len(want)]); got != "P " || ws[len(want)].at != env.Timing.PingBusy {
				t.Fatalf("write %d at %v: %q, want the cadence PING alone at %v", len(want)+1, ws[len(want)].at, got, env.Timing.PingBusy)
			}
			if got := c.Inflight(); got != 0 {
				t.Fatalf("in flight at the end: %d", got)
			}
			hCheckData(t, p, total)
		})
	})
	t.Run("single-batch-burst", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			env := hEnv()
			env.Timing.CapFloor = 2 << 20 // a clock step of 256 KiB: one full batch reaches it
			rec := &bcWrites{start: time.Now()}
			c, p := hPair(t, env, rec.wrap)
			bcPreset(c, rate, rtt)
			p.keep()
			p.autoPong(func(uint32) time.Duration { return rtt })
			src := newSource(env, ChunkSize, true)
			defer src.chunk.Release()
			src.offer(512 << 10) // two full batches: the second ends with a clock PING
			c.Start(src, &hBell{}, StartOptions{})
			time.Sleep(time.Second) // proven; the writer sleeps
			synctest.Wait()
			if got := c.Inflight(); got != 0 {
				t.Fatalf("in flight after the first burst: %d", got)
			}
			mark := len(rec.snapshot())
			src.offer(256 << 10) // one full batch: a burst of its own
			c.Wake()
			time.Sleep(time.Second)
			synctest.Wait()
			ws := rec.snapshot()
			if got := bcShape(ws[1]); got != "D320 D384 D448 D512 P " {
				t.Fatalf("the first burst's second batch %q, want it to end with a clock PING", got)
			}
			if len(ws) < mark+1 {
				t.Fatalf("no write after the idle period")
			}
			if got := bcShape(ws[mark]); got != "D576 D640 D704 D768 " {
				t.Fatalf("the single-batch burst wrote %q, want its DATA without a PING", got)
			}
			hCheckData(t, p, 768<<10)
		})
	})
	t.Run("capped-batch", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			env := hEnv()
			env.Timing.CapFloor = 1 << 20 // a 1 MiB capacity: four full batches reach it; a clock step of 128 KiB
			rec := &bcWrites{start: time.Now()}
			c, p := hPair(t, env, rec.wrap)
			bcPreset(c, 2<<20, rtt) // 2·2 MiB/s·200 ms stays below the floor; a 200 KiB product
			p.keep()
			p.autoPong(func(uint32) time.Duration { return rtt })
			src := newSource(env, ChunkSize, true)
			defer src.chunk.Release()
			src.offer(2 << 20) // more than the capacity: the fourth batch ends at the cap
			c.Start(src, &hBell{}, StartOptions{})
			time.Sleep(10 * time.Millisecond) // before the cadence PING and the first PONG
			synctest.Wait()
			// The fourth batch is full, cap-blocked and ends with a clock
			// PING, which proves all of it: no cap-hit PING follows it.
			ws := rec.snapshot()
			want := []string{
				"P D64 D128 D192 D256 ",
				"D320 D384 D448 D512 P ",
				"D576 D640 D704 D768 P ",
				"D832 D896 D960 D1024 P ",
			}
			if len(ws) != len(want) {
				var got []string
				for _, w := range ws {
					got = append(got, bcShape(w))
				}
				t.Fatalf("writes before the first PONG %q, want %q", got, want)
			}
			for i, w := range want {
				if got := bcShape(ws[i]); got != w {
					t.Fatalf("write %d %q, want %q", i+1, got, w)
				}
			}
			if got := c.Inflight(); got != 1<<20 {
				t.Fatalf("in flight at the cap: %d", got)
			}
		})
	})
	t.Run("short-path", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			env := hEnv()
			env.Timing.CapFloor = 1 << 20 // a 1 MiB capacity and a 128 KiB step, as in capped-batch
			rec := &bcWrites{start: time.Now()}
			c, p := hPair(t, env, rec.wrap)
			bcPreset(c, 2<<20, 10*time.Millisecond) // a 20 KiB bandwidth-delay product; the floor sets the capacity
			c.mu.Lock()
			c.st.srtt = 200 * time.Millisecond // a standing queue: rate·srtt would pass a step, the gate reads minRTT
			c.mu.Unlock()
			p.keep()
			p.autoPong(func(uint32) time.Duration { return 10 * time.Millisecond })
			src := newSource(env, ChunkSize, true)
			defer src.chunk.Release()
			src.offer(2 << 20) // more than the capacity: the fourth batch ends at the cap
			c.Start(src, &hBell{}, StartOptions{})
			time.Sleep(5 * time.Millisecond)
			synctest.Wait()
			ws := rec.snapshot()
			want := []string{
				"P D64 D128 D192 D256 ",
				"D320 D384 D448 D512 ",
				"D576 D640 D704 D768 ",
				"D832 D896 D960 D1024 ",
				"P ", // the cap-hit PING
			}
			if len(ws) != len(want) {
				var got []string
				for _, w := range ws {
					got = append(got, bcShape(w))
				}
				t.Fatalf("writes before the first PONG %q, want %q", got, want)
			}
			for i, w := range want {
				if got := bcShape(ws[i]); got != w {
					t.Fatalf("write %d %q, want %q", i+1, got, w)
				}
			}
		})
	})
}

// TestByteClockPingsUseRingPastCadence_L25: on a path whose PONGs take 1 s,
// the PING cadence fills its share of the record ring (pingCadenceMax) and
// waits; a burst written then still gets its byte-clocked PINGs, in the
// records past the cadence's share, so the capacity they prove comes back
// a clock step at a time when their PONGs arrive, without waiting for the
// cadence's records to drain. The carrier does not die (the oldest record
// decides the deadline, 3 s here).
func TestByteClockPingsUseRingPastCadence_L25(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		env.Timing.CapFloor = 4 << 20 // the capacity, and the clock step 512 KiB, from the start
		const rtt = time.Second
		c, p := hPair(t, env, nil)
		bcPreset(c, 1<<20, rtt) // a 1 MiB bandwidth-delay product: the clock runs
		p.autoPong(func(uint32) time.Duration { return rtt })
		src := newSource(env, ChunkSize, true)
		defer src.chunk.Release()
		src.offer(4 << 10) // unproven for a second: the cadence is PingBusy
		start := time.Now()
		c.Start(src, &hBell{}, StartOptions{})
		time.Sleep(900 * time.Millisecond)
		synctest.Wait()
		if pings, n := bcState(c); pings != pingCadenceMax || n != pingCadenceMax {
			t.Fatalf("stimulus: %d PINGs, %d outstanding before the burst, want the cadence's full share %d", pings, n, pingCadenceMax)
		}
		src.offer(2 << 20) // eight full batches
		c.Wake()
		synctest.Wait()
		pings, n := bcState(c)
		if pings != pingCadenceMax+4 || n != pingCadenceMax+4 {
			t.Fatalf("after the burst: %d PINGs, %d outstanding, want the cadence's %d plus 4 clock PINGs", pings, n, pingCadenceMax)
		}
		if got := c.Inflight(); got != 4<<10+2<<20 {
			t.Fatalf("in flight after the burst: %d", got)
		}
		// One second later the PONGs of the clock PINGs arrive with the
		// cadence's: the whole burst is proven at once, not a cadence round
		// trip later.
		time.Sleep(time.Until(start.Add(900*time.Millisecond + rtt + time.Millisecond)))
		synctest.Wait()
		if got := c.Inflight(); got != 0 {
			t.Fatalf("in flight one RTT after the burst: %d, want 0", got)
		}
		if dead, cause, detail, _ := c.Death(); dead {
			t.Fatalf("died: %v %s", cause, detail)
		}
		c.Kill(CauseLocalClose, "test end")
		hWait(t, c)
		p.close()
	})
}

// TestByteClockRoundZeroAllocs_L41_L54 extends the writer half of the
// allocation gate (TestCarrierRoundZeroAllocs_L41_L54) to the byte clock:
// over an OwnedTCP loopback pair on a path whose estimate lets the clock run
// (100 MiB/s at 100 ms: a 1 MiB step), a round inside a burst — carrier
// control computing the round's step, Fill appending an ACK and a full
// batch of DATA, the clock PING ending the batch, seal and the vectored
// write — and a round that starts a burst with the cadence PING due, which
// carrier control leaves to the end of the batch, allocate nothing.
// Asserted in the non-race lane only.
func TestByteClockRoundZeroAllocs_L41_L54(t *testing.T) {
	defer g10NoLeak(t)()
	env := hEnv()
	cl, sv := tcpPair(t)
	defer sv.Close()
	go func() { // the receiver discards everything (no allocation per read)
		buf := make([]byte, 1<<20)
		for {
			if _, err := sv.Read(buf); err != nil {
				return
			}
		}
	}()
	c := hConn(env, NewOwnedTCP(cl))
	ep := &allocEP{chunk: env.Bufs.Get(ChunkSize, nil)}
	defer ep.chunk.Release()
	c.ep = ep
	c.writerInit()
	bcPreset(c, 100<<20, 100*time.Millisecond)
	one := func(cadence bool) {
		// The records of earlier rounds answered. Clock round: inside a
		// burst, a step written since the latest PING, the cadence PING not
		// due. Cadence round: the first of a burst, the cadence PING due.
		now := time.Now()
		c.mu.Lock()
		c.st.head, c.st.n = 0, 0
		c.st.pingSent, c.st.lastCommit = true, now
		if cadence {
			c.st.lastCommit = now.Add(-time.Second)
		}
		c.mu.Unlock()
		c.wr.burst, c.wr.clock = 1, 1<<20
		if cadence {
			c.wr.burst, c.wr.clock = 0, 0
		}
		if !c.writeRound(&c.wr) {
			_, cause, detail, _ := c.Death()
			t.Fatalf("writer round ended the carrier: %v %s", cause, detail)
		}
		if !c.wr.ping || !c.wr.pingAtEnd {
			t.Fatalf("a round (cadence %v) without its PING at the end of the batch", cadence)
		}
	}
	round := func() {
		one(false)
		one(true)
	}
	for range 20 { // warm up: the poller's deadline timer, the iovec pool
		round()
	}
	allocs := testing.AllocsPerRun(100, round)
	pings, _ := bcState(c)
	c.Kill(CauseLocalClose, "test end")
	<-c.Done()
	if pings != 2*121 {
		t.Fatalf("%d PINGs in %d rounds", pings, 2*121)
	}
	if carrierRace {
		t.Logf("race lane: %v allocations per pair of rounds (not asserted)", allocs)
		return
	}
	if allocs != 0 {
		t.Fatalf("%v allocations per pair of writer rounds ending with a PING", allocs)
	}
}
