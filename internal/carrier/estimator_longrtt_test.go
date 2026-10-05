package carrier

import (
	"context"
	"fmt"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Rate samples on long-RTT paths (design §0.13 Revision 8 A1, §4.10; L15,
// L32). Names in this file use the lr prefix.

// lrLinkPair is ltLinkPair with a link buffer of buf bytes per direction.
func lrLinkPair(t *testing.T, envD, envP *Env, rate float64, delay time.Duration, buf int, sink Endpoint) (dialer, passive *Conn) {
	t.Helper()
	pass := make(chan *Conn, 1)
	link := rendrtest.NewLink(rendrtest.LinkConfig{Name: "wan", Buffer: buf, Accept: func(nc net.Conn) error {
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
	est, err := Establish(context.Background(), envD, Factory{Name: "wan", Dial: link.Dial}, envD.IDs.Next(), wire.TypeOpen, openPayload(0), nil)
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}
	conns = append(conns, est.Conn)
	pc := <-pass
	if pc == nil {
		t.Fatal("the passive handshake failed")
	}
	conns = append(conns, pc)
	return est.Conn, pc
}

// lrDuplex is the passive endpoint of a duplex flow: its first Fill places
// OPEN_ACK(OK) (ltSink), later ones bulk DATA from src; DATA it receives is
// checked like ltSink's.
type lrDuplex struct {
	*ltSink
	src *hSource
}

func (d *lrDuplex) Fill(c *Conn, b *Batch) {
	if !d.placed {
		if d.ltSink.Fill(c, b); !d.placed {
			return
		}
	}
	d.src.fillData(c, b)
}

// TestCapLimitedFlowLongRTT_L15_L32: a bulk transfer over one carrier whose
// RTT is at least PingBusy — on and off multiples of PingBusy (50 ms) —
// raises its capacity from the 128 KiB floor. On such a path busy PINGs go
// out between the cap-hit PINGs, and their PONGs, which prove nothing new,
// arrive just before the PONG that proves the burst: when the two arrive
// less than 5 ms apart (RTT mod PingBusy < 5 ms) that proof was too young
// to sample, and restarting the rate interval at the next PONG that proved
// nothing new threw it away — every round trip. The rate stayed at or near
// 0 and the carrier moved about 128 KiB per RTT whatever its window (1.3
// MB/s at a 100 ms RTT). Over a link without a rate limit the capacity must
// now reach the window within a dozen round trips; over a rate-limited
// link, one way or both ways at once, the estimate must reach the link rate
// without exceeding it by more than the sampling slack, and the capacity
// the matching cap. Every byte arrives intact and in order. (Throughput on
// a rate-limited path stays below the link rate by the capacity cycle —
// a cap-blocked writer's proof is its cap-hit PING, queued behind the whole
// burst — which design §0.13 A1 records; the floor this fixes is far below.)
func TestCapLimitedFlowLongRTT_L15_L32(t *testing.T) {
	for _, tc := range []struct {
		rtt    time.Duration
		rate   float64 // bytes/s per direction; 0: unlimited (the window limits)
		window int64
		total  uint64
		duplex bool // the passive sends total bytes back at the same time
	}{
		{50 * time.Millisecond, 0, 4 << 20, 96 << 20, false},
		{100 * time.Millisecond, 0, 4 << 20, 64 << 20, false},
		{102 * time.Millisecond, 0, 4 << 20, 64 << 20, false},
		{105 * time.Millisecond, 0, 4 << 20, 64 << 20, false},
		{200 * time.Millisecond, 0, 4 << 20, 48 << 20, false},
		{400 * time.Millisecond, 0, 4 << 20, 32 << 20, false},
		{100 * time.Millisecond, 16 << 20, 8 << 20, 48 << 20, false},
		{105 * time.Millisecond, 16 << 20, 8 << 20, 48 << 20, false},
		{400 * time.Millisecond, 8 << 20, 8 << 20, 32 << 20, false},
		{100 * time.Millisecond, 16 << 20, 8 << 20, 48 << 20, true},
		{400 * time.Millisecond, 8 << 20, 8 << 20, 32 << 20, true},
	} {
		rtt, rate, window, total := tc.rtt, tc.rate, tc.window, tc.total
		name := fmt.Sprintf("rtt%v/unlimited", rtt)
		if rate > 0 {
			name = fmt.Sprintf("rtt%v/%dMiBps", rtt, int(rate)>>20)
		}
		if tc.duplex {
			name += "/duplex"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				envD, envP := phEnvs()
				envD.Timing.Window, envP.Timing.Window = window, window
				sink := newLtSink(total)
				var back *hSource // the passive's source (duplex)
				var ep Endpoint = sink
				if tc.duplex {
					back = newSource(envP, ChunkSize, true)
					defer back.chunk.Release()
					back.offer(total)
					ep = &lrDuplex{ltSink: sink, src: back}
				}
				dc, pc := lrLinkPair(t, envD, envP, rate, rtt/2, 64<<20, ep)
				src := newSource(envD, ChunkSize, true)
				defer src.chunk.Release()
				src.offer(total)
				start := time.Now()
				dc.Start(src, &hBell{}, StartOptions{})
				var maxRate, maxBack float64
				var capAt time.Duration // when the capacity first reached the window
				var halfAt time.Time    // when half the bytes had arrived
				for timeout := time.After(60 * time.Second); ; {
					select {
					case <-sink.done:
					case <-timeout:
						next, bad, _ := sink.result()
						t.Fatalf("stalled: %d of %d bytes after %v (%s), stats %+v", next, total, time.Since(start), bad, dc.Stats())
					case <-time.After(time.Millisecond):
						st := dc.Stats()
						maxRate = max(maxRate, st.Rate)
						maxBack = max(maxBack, pc.Stats().Rate)
						if capAt == 0 && st.Cap >= window {
							capAt = time.Since(start)
						}
						if next, _, _ := sink.result(); halfAt.IsZero() && next >= total/2 {
							halfAt = time.Now()
						}
						continue
					}
					break
				}
				next, bad, doneAt := sink.result()
				st := dc.Stats()
				took := doneAt.Sub(start)
				second := float64(total/2) / doneAt.Sub(halfAt).Seconds() // the second half: past the ramp
				t.Logf("%d MiB in %v; second half %.1f MiB/s; cap %d KiB (window reached at %v); rate %.1f MiB/s (peak %.1f; the passive's peak %.1f), srtt %v, minRTT %v",
					total>>20, took, second/(1<<20), st.Cap>>10, capAt, st.Rate/(1<<20), maxRate/(1<<20), maxBack/(1<<20), st.SRTT, st.MinRTT)
				if bad != "" || next != total {
					t.Fatalf("data: %d bytes in order, violation %q", next, bad)
				}
				for _, c := range []*Conn{dc, pc} {
					if dead, cause, detail, _ := c.Death(); dead {
						t.Fatalf("carrier %d died: %v %s", c.ID(), cause, detail)
					}
				}
				if rate == 0 {
					// The window, not the floor, limits the flow: the capacity
					// reaches it within a dozen round trips plus a second.
					if capAt == 0 || capAt > 12*rtt+time.Second {
						t.Fatalf("the capacity reached the %d KiB window at %v (0: never), want within %v: rate %.0f B/s, cap %d",
							window>>10, capAt, 12*rtt+time.Second, st.Rate, st.Cap)
					}
					return
				}
				if tc.duplex {
					// The passive's flow arrives whole; its estimate is watched
					// to the end.
					for limit := time.After(60 * time.Second); src.rxBytes.Load() < int64(total); {
						select {
						case <-limit:
							t.Fatalf("the passive's flow: %d of %d bytes", src.rxBytes.Load(), total)
						case <-time.After(time.Millisecond):
							maxBack = max(maxBack, pc.Stats().Rate)
						}
					}
					if maxBack < 0.8*rate {
						t.Fatalf("the passive's rate estimate peaked at %.1f MiB/s on a %d MiB/s link", maxBack/(1<<20), int(rate)>>20)
					}
				}
				// One way, a sample stays within the drain rate plus the
				// sampling slack. Both ways, PONGs queue behind the peer's bulk
				// and arrive compressed (ACK compression; the PONG carries no
				// peer receive time), so a sample can exceed the link rate
				// several times over (design §0.13 A1 records it: 1.7× before
				// A1 and 3.6× after it in this case); the bound catches a
				// regression to unbounded samples.
				slack := 1.2
				if tc.duplex {
					slack = 4
				}
				for _, x := range []struct {
					who  string
					peak float64
				}{{"dialer", maxRate}, {"passive", maxBack}} {
					if x.peak > slack*rate {
						t.Fatalf("the %s's rate estimate peaked at %.1f MiB/s on a %d MiB/s link (bound %.1f×)", x.who, x.peak/(1<<20), int(rate)>>20, slack)
					}
				}
				// The estimate reached the link rate, and the capacity its cap.
				want := min(window, int64(2*0.8*rate*(st.MinRTT+envD.Timing.PingBusy+50*time.Millisecond).Seconds()))
				if st.Rate < 0.8*rate || st.Cap < want {
					t.Fatalf("rate %.1f MiB/s on a %d MiB/s link, cap %d KiB: want ≥ 80%% of the link and a cap ≥ %d KiB",
						st.Rate/(1<<20), int(rate)>>20, st.Cap>>10, want>>10)
				}
				// Far above the floor's 128 KiB per RTT.
				if floor := float64(envD.Timing.CapFloor) / rtt.Seconds(); second < 4*floor {
					t.Fatalf("second-half throughput %.1f MiB/s, under 4× the floor's %.1f MiB/s", second/(1<<20), floor/(1<<20))
				}
			})
		})
	}
}
