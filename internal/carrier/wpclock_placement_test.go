package carrier

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Where the PINGs of a clocked flow go, the PONG watermark of an early PONG,
// the record ring past the cadence's share, and the rate filter's span and
// jump rules (design §0.13 A1, A7b; §4.10). Names in this file use the bc
// prefix of the byte-clock tests.

// bcShapes returns the shapes of writes ws (bcShape).
func bcShapes(ws []bcWrite) []string {
	out := make([]string, len(ws))
	for i, w := range ws {
		out[i] = bcShape(w)
	}
	return out
}

// TestByteClockDuePingEndsBatch_L32 pins where a cadence or requested PING
// goes. While the byte clock runs (a 5 MiB/s estimate at a 100 ms minimum
// RTT: a 500 KiB bandwidth-delay product), it follows the DATA of its round,
// like a byte-clocked PING, so its PONG's arrival matches its mark: in front
// of the DATA it reached the peer only with the first unit of those bytes,
// and the short samples of a clocked flow read the path up to 2× too fast
// (TestByteClockFillsLongPath_L15_L32).
//
//   - cadence: 256 KiB more DATA waits when the PingBusy cadence PING falls
//     due (50 ms after the first); the round writes that DATA, then the
//     PING, whose PONG proves all 512 KiB.
//   - requested: with a 2 MiB/s estimate (a 200 KiB product; the capacity
//     sits at a 1 MiB + 64 KiB floor), the write of the batch that reaches
//     the capacity blocks for 110 ms, during which the PONGs of the burst's
//     clock PINGs (one 100 ms RTT) free capacity; the cap-hit PING
//     requested at the end of that write finds DATA in its round and
//     follows it.
//   - full-batch: a due PING that does not fit behind the round's DATA (64
//     one-KiB frames fill the batch) goes first in the next round, which is
//     full as well: it is not deferred again.
//   - clock-off: on a short path (2 MiB/s at 10 ms: a 20 KiB product) the
//     cadence PING precedes its round's DATA, as before the byte clock.
func TestByteClockDuePingEndsBatch_L32(t *testing.T) {
	const (
		rtt  = 100 * time.Millisecond
		rate = 5 << 20
	)
	t.Run("cadence", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			env := hEnv()
			env.Timing.CapFloor = 3 << 20 // a 384 KiB clock step
			rec := &bcWrites{start: time.Now()}
			c, p := hPair(t, env, rec.wrap)
			bcPreset(c, rate, rtt)
			p.keep()
			p.autoPong(func(uint32) time.Duration { return rtt })
			src := newSource(env, ChunkSize, true)
			defer src.chunk.Release()
			src.offer(256 << 10)
			c.Start(src, &hBell{}, StartOptions{})
			time.Sleep(env.Timing.PingBusy - time.Millisecond)
			src.offer(256 << 10) // no wake: the writer runs at the cadence PING's time
			time.Sleep(rtt + 2*time.Millisecond)
			synctest.Wait()
			got := bcShapes(rec.snapshot())
			want := []string{"P D64 D128 D192 D256 ", "D320 D384 D448 D512 P "}
			if len(got) < 2 || got[0] != want[0] || got[1] != want[1] {
				t.Fatalf("writes %q, want %q first", got, want)
			}
			if ws := rec.snapshot(); ws[1].at != env.Timing.PingBusy {
				t.Fatalf("second write at %v, want the cadence PING's time %v", ws[1].at, env.Timing.PingBusy)
			}
			// The cadence PING's PONG, one RTT after it, proved the DATA in
			// front of it as well.
			if got := c.Inflight(); got != 0 {
				t.Fatalf("in flight after the cadence PING's PONG: %d, want 0", got)
			}
			hCheckData(t, p, 512<<10)
		})
	})
	t.Run("requested", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			env := hEnv()
			env.Timing.CapFloor = 1<<20 + 64<<10 // four full batches and 64 KiB reach it; a 136 KiB clock step
			rec := &bcWrites{start: time.Now()}
			var writes atomic.Int32
			c, p := hPair(t, env, func(nc net.Conn) net.Conn {
				inner := rec.wrap(nc)
				return &hookConn{Conn: inner, onWrite: func(nc net.Conn, b []byte) (int, error) {
					n, err := nc.Write(b)
					if writes.Add(1) == 5 {
						time.Sleep(rtt + 10*time.Millisecond) // the bytes left; the burst's PONGs overtake the Write's return
					}
					return n, err
				}}
			})
			bcPreset(c, 2<<20, rtt) // 2·2 MiB/s·200 ms stays below the floor; a 200 KiB product
			p.keep()
			p.autoPong(func(uint32) time.Duration { return rtt })
			src := newSource(env, ChunkSize, true)
			defer src.chunk.Release()
			src.offer(2 << 20)
			c.Start(src, &hBell{}, StartOptions{})
			time.Sleep(rtt + 15*time.Millisecond)
			synctest.Wait()
			got := bcShapes(rec.snapshot())
			want := []string{
				"P D64 D128 D192 D256 ",
				"D320 D384 D448 D512 P ",
				"D576 D640 D704 D768 P ",
				"D832 D896 D960 D1024 P ",
				"D1088 ",                     // cap-blocked: the cap-hit PING is requested
				"D1152 D1216 D1280 D1344 P ", // capacity freed during the write: the requested PING follows the DATA
			}
			if len(got) < len(want) {
				t.Fatalf("writes %q, want %q first", got, want)
			}
			for i, w := range want {
				if got[i] != w {
					t.Fatalf("writes %q, want %q first (write %d differs)", got, want, i+1)
				}
			}
			if ws := rec.snapshot(); ws[5].at != rtt+10*time.Millisecond {
				t.Fatalf("write 6 at %v, want right after the blocked write returned (%v)", ws[5].at, rtt+10*time.Millisecond)
			}
		})
	})
	t.Run("full-batch", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			env := hEnv()
			env.Timing.CapFloor = 3 << 20
			rec := &bcWrites{start: time.Now()}
			c, p := hPair(t, env, rec.wrap)
			bcPreset(c, rate, rtt)
			p.keep()
			p.autoPong(func(uint32) time.Duration { return rtt })
			src := newSource(env, 1<<10, true) // one-KiB DATA frames: 64 fill a batch's frames, not its budget
			defer src.chunk.Release()
			src.offer(64 << 10)
			c.Start(src, &hBell{}, StartOptions{})
			time.Sleep(env.Timing.PingBusy - time.Millisecond)
			synctest.Wait()
			first := len(rec.snapshot())
			src.offer(128 << 10) // two rounds of 64 frames when the cadence PING falls due
			time.Sleep(2 * time.Millisecond)
			synctest.Wait()
			ws := rec.snapshot()[first:]
			if len(ws) < 2 {
				t.Fatalf("%d writes at the cadence PING's time, want at least 2", len(ws))
			}
			pingAt := func(w bcWrite) int {
				for i, f := range w.frames {
					if f.Type == wire.TypePing {
						return i
					}
				}
				return -1
			}
			if n, at := len(ws[0].frames), pingAt(ws[0]); n != MaxBatchFrames || at >= 0 {
				t.Fatalf("first write at the cadence time: %d frames, PING at %d; want %d DATA frames and no room for the PING", n, at, MaxBatchFrames)
			}
			if at := pingAt(ws[1]); at != 0 || len(ws[1].frames) != MaxBatchFrames {
				t.Fatalf("second write: PING at %d of %d frames, want the PING first in a full batch", at, len(ws[1].frames))
			}
			hCheckData(t, p, 64<<10+128<<10)
		})
	})
	t.Run("clock-off", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			env := hEnv()
			env.Timing.CapFloor = 1 << 20 // a 128 KiB step
			rec := &bcWrites{start: time.Now()}
			c, p := hPair(t, env, rec.wrap)
			bcPreset(c, 2<<20, 10*time.Millisecond) // a 20 KiB bandwidth-delay product
			p.keep()
			p.autoPong(func(uint32) time.Duration { return 10 * time.Millisecond })
			src := newSource(env, ChunkSize, true)
			defer src.chunk.Release()
			src.offer(256 << 10)
			c.Start(src, &hBell{}, StartOptions{})
			time.Sleep(env.Timing.PingBusy - time.Millisecond)
			src.offer(256 << 10)
			time.Sleep(2 * time.Millisecond)
			synctest.Wait()
			got := bcShapes(rec.snapshot())
			want := []string{"P D64 D128 D192 D256 ", "P D320 D384 D448 D512 "}
			if len(got) < 2 || got[0] != want[0] || got[1] != want[1] {
				t.Fatalf("writes %q, want %q first", got, want)
			}
		})
	})
}

// TestByteClockEarlyPongBoundedBySubmitted_L23: the PONG of a byte-clocked
// PING, which ends its batch and counts that batch's DATA in its mark,
// arrives while the batch's Write has not returned (the conn returns 10 ms
// after the bytes left; L23: such a PONG is no evidence, but it proves
// delivery). The PONG watermark never passes what was submitted, so the
// bytes in flight, the carrier's Stats and its self-load contribution never
// read negative while the Write is in progress; once it returns, the batch
// counts as proven (nothing in flight). Before, the watermark ran a whole
// batch ahead of the submitted bytes until the commit (−256 KiB in flight).
func TestByteClockEarlyPongBoundedBySubmitted_L23(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		var cc atomic.Pointer[Conn]
		g := NewGauge()
		var mu sync.Mutex
		minInflight, minStats, minGauge := int64(1<<62), int64(1<<62), int64(1<<62)
		early := 0
		c, p := hPair(t, env, func(nc net.Conn) net.Conn {
			return &hookConn{Conn: nc, onWrite: func(nc net.Conn, b []byte) (int, error) {
				n, err := nc.Write(b)
				time.Sleep(10 * time.Millisecond) // the PONG of this write's PING arrives meanwhile
				if c := cc.Load(); c != nil {
					raced := 0
					c.mu.Lock()
					in := c.st.inflight()
					for i := range c.st.n {
						if r := c.st.record(i); r.early && r.committedAt.IsZero() {
							raced++
						}
					}
					c.mu.Unlock()
					s := c.Stats().Inflight
					mu.Lock()
					early += raced
					minInflight, minStats, minGauge = min(minInflight, in), min(minStats, s), min(minGauge, g.inflight.Load())
					mu.Unlock()
				}
				return n, err
			}}
		})
		cc.Store(c)
		bcPreset(c, 10<<20, 100*time.Millisecond) // a 4 MiB capacity: a 512 KiB step, the second batch's end
		p.autoPong(nil)                           // 1 µs
		src := newSource(env, ChunkSize, true)
		defer src.chunk.Release()
		src.offer(512 << 10)
		c.Start(src, &hBell{}, StartOptions{Gauge: g})
		time.Sleep(25 * time.Millisecond) // both Writes returned; no cadence PING yet
		synctest.Wait()
		if pings, _ := bcState(c); pings != 2 {
			t.Fatalf("stimulus: %d PINGs, want the first and the clock PING ending the second batch", pings)
		}
		mu.Lock()
		defer mu.Unlock()
		if early == 0 {
			t.Fatal("stimulus: no PONG arrived while its PING's Write was in progress")
		}
		if minInflight < 0 || minStats < 0 || minGauge < 0 {
			t.Fatalf("during an early PONG: in flight %d, Stats.Inflight %d, gauge %d; want none negative", minInflight, minStats, minGauge)
		}
		if got := c.Inflight(); got != 0 {
			t.Fatalf("in flight once the Writes returned: %d, want 0 (the clock PING's early PONG proved its batch)", got)
		}
	})
}

// TestByteClockCapHitPastCadenceShare_L25: on a path whose PONGs take 1 s
// the PING cadence fills its share of the record ring (16) and waits. A
// burst that then reaches the capacity cap still gets its cap-hit PING (the
// 17th record): a requested PING may use the ring past the cadence's share,
// so the capacity it proves comes back one RTT after the burst, not after
// the cadence's records drained.
func TestByteClockCapHitPastCadenceShare_L25(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		const rtt = time.Second
		c, p := hPair(t, env, nil)
		p.autoPong(func(uint32) time.Duration { return rtt })
		src := newSource(env, ChunkSize, true)
		defer src.chunk.Release()
		src.offer(4 << 10) // unproven for a second: PINGs every PingBusy
		c.Start(src, &hBell{}, StartOptions{})
		time.Sleep(900 * time.Millisecond)
		synctest.Wait()
		if pings, n := bcState(c); pings != pingCadenceMax || n != pingCadenceMax {
			t.Fatalf("stimulus: %d PINGs, %d outstanding, want the cadence's full share %d", pings, n, pingCadenceMax)
		}
		src.offer(1 << 20) // more than the 128 KiB cap
		c.Wake()
		synctest.Wait()
		if got := c.Inflight(); got != env.Timing.CapFloor {
			t.Fatalf("stimulus: %d bytes in flight after the burst, want the %d-byte cap", got, env.Timing.CapFloor)
		}
		if pings, n := bcState(c); pings != pingCadenceMax+1 || n != pingCadenceMax+1 {
			t.Fatalf("after the capped burst: %d PINGs, %d outstanding, want the cap-hit PING past the cadence's %d", pings, n, pingCadenceMax)
		}
	})
}

// TestByteClockFullRingWakesRequestedPing_L25: with every record of the
// ring outstanding (32: no PING may be encoded) a writer that reached its
// capacity cap waits with its cap-hit PING requested. The PONG that frees
// a record of the full ring wakes it, and the requested PING goes out in
// the same instant — not at the death-deadline timer the writer slept on.
func TestByteClockFullRingWakesRequestedPing_L25(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		c, p := hPair(t, env, nil)
		start := time.Now()
		var oldest wire.Ping
		c.mu.Lock()
		st := &c.st
		for range pingRingSize { // records of PINGs written before (their PONGs not yet back)
			id := st.nextPingID
			st.nextPingID++
			st.push(pingRecord{id: id, nonce: c.salt ^ uint64(id), committedAt: start})
			if id == c.env.Presets.firstPingID() {
				oldest = wire.Ping{ID: id, Nonce: c.salt ^ uint64(id)}
			}
		}
		st.pingSent, st.lastCommit = true, start
		c.mu.Unlock()
		var mu sync.Mutex
		var pingAt []time.Duration
		p.setHandler(func(f wire.Frame) {
			if f.Type == wire.TypePing {
				mu.Lock()
				pingAt = append(pingAt, time.Since(start))
				mu.Unlock()
			}
		})
		src := newSource(env, ChunkSize, true)
		defer src.chunk.Release()
		src.offer(1 << 20) // the 128 KiB cap stops it at once
		c.Start(src, &hBell{}, StartOptions{})
		time.Sleep(500 * time.Millisecond)
		synctest.Wait()
		c.mu.Lock()
		req, n := c.st.pingReq, c.st.n
		c.mu.Unlock()
		if got := c.Inflight(); got != env.Timing.CapFloor || !req || n != pingRingSize || len(pingAt) != 0 {
			t.Fatalf("stimulus: in flight %d, PING requested %v, %d records, %d PINGs written; want the cap reached and a requested PING waiting on the full ring", got, req, n, len(pingAt))
		}
		const pongAt = 500 * time.Millisecond
		if err := p.pong(oldest); err != nil { // frees the oldest record
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond)
		synctest.Wait()
		mu.Lock()
		defer mu.Unlock()
		if len(pingAt) != 1 || pingAt[0] != pongAt {
			t.Fatalf("PINGs written at %v, want the requested PING at the PONG's instant %v", pingAt, pongAt)
		}
	})
}

// bcSample applies one PONG to an unstarted carrier whose estimator holds
// rate (bytes/s) and srtt = minRTT, a rate interval that started at t0 with
// nothing proven, and one busy PING committed at t0 whose mark proves
// bytes; the PONG arrives at t0+span. It returns the rate afterwards and the
// decayed rate a sample over span starts from.
func bcSample(t *testing.T, rate float64, srtt time.Duration, peerBusy bool, bytes uint64, span time.Duration) (after, decayed float64) {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c := hConn(hEnv(), a)
	c.mu.Lock()
	defer c.mu.Unlock()
	st := &c.st
	t0 := time.Now()
	st.rate, st.srtt, st.minRTT, st.rttSeen, st.peerBusy = rate, srtt, srtt, true, peerBusy
	st.submitted = bytes
	st.rateAt, st.rateCommitAt = t0, t0
	id := st.nextPingID
	st.nextPingID++
	st.push(pingRecord{id: id, nonce: c.salt ^ uint64(id), mark: bytes, committedAt: t0, busy: true})
	if matched, _, _ := c.onPongLocked(&wire.Ping{ID: id, Nonce: c.salt ^ uint64(id)}, t0.Add(span)); !matched {
		t.Fatal("the PONG matched no record")
	}
	return st.rate, rate * decay(span)
}

// TestRateSampleJumpCapAndSpan_L32 pins the rate filter's rules for the
// short samples of byte-clocked PONGs (design §0.13 A1, A7b): one busy
// sample proving 1 MiB is applied to an estimate at a 100 ms smoothed RTT.
//   - at the capacity floor (an estimate of 100 kB/s, whose capacity
//     formula stays below the 128 KiB floor), a 20 ms sample sets the
//     estimate whatever it reads (52 MB/s): before the first real evidence
//     a rise takes one sample, not a doubling per sample;
//   - above the floor (4 MB/s), a sample shorter than half the smoothed
//     RTT may at most double the decayed estimate;
//   - one spanning at least half the smoothed RTT is taken as it reads;
//   - while the peer reports BUSY, a sample shorter than half the smoothed
//     RTT is not taken at all: the interval runs on, the estimate untouched.
func TestRateSampleJumpCapAndSpan_L32(t *testing.T) {
	const (
		srtt  = 100 * time.Millisecond
		bytes = 1 << 20
	)
	near := func(a, b float64) bool { return a > 0.999*b && a < 1.001*b }
	if got, _ := bcSample(t, 100e3, srtt, false, bytes, 20*time.Millisecond); !near(got, bytes/0.020) {
		t.Fatalf("at the floor: rate %.0f after a 20 ms sample of %.0f, want the sample", got, bytes/0.020)
	}
	if got, dec := bcSample(t, 4e6, srtt, false, bytes, 20*time.Millisecond); !near(got, 2*dec) {
		t.Fatalf("above the floor: rate %.0f after a 20 ms sample of %.0f, want twice the decayed %.0f", got, bytes/0.020, dec)
	}
	// srtt after the PONG: (7·100 + 60)/8 = 95 ms; half of it is below 60 ms.
	if got, _ := bcSample(t, 4e6, srtt, false, bytes, 60*time.Millisecond); !near(got, bytes/0.060) {
		t.Fatalf("a 60 ms sample: rate %.0f, want the sample %.0f", got, bytes/0.060)
	}
	// srtt after the PONG: (7·100 + 40)/8 = 92.5 ms; 40 ms is below half of it.
	if got, _ := bcSample(t, 4e6, srtt, true, bytes, 40*time.Millisecond); got != 4e6 {
		t.Fatalf("peer BUSY, a 40 ms sample: rate %.0f, want it not taken (4000000)", got)
	}
	if got, _ := bcSample(t, 4e6, srtt, true, bytes, 60*time.Millisecond); !near(got, bytes/0.060) {
		t.Fatalf("peer BUSY, a 60 ms sample: rate %.0f, want the sample %.0f", got, bytes/0.060)
	}
}
