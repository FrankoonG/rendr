package carrier

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Liveness, MTU probe, rebind and held-carrier tests of datagram carriers
// (M2-D22…M2-D24, M2-D27; M2 design §A5.11, §A5.13, Revision 1 R1-8,
// R1-13, R1-14; §A8.2 WP3a rows).

// withTiming applies f to both sides' Timing before Start.
func withTiming(f func(*Timing), sides ...*dgSide) {
	for _, s := range sides {
		f(&s.env.Timing)
		s.c.tm = s.env.Timing.withDefaults()
	}
}

// pingWrites returns the PINGs (with their write times and datagram
// lengths) among recorded writes.
type pingWrite struct {
	p   wire.Ping
	at  time.Time
	len int
	n   int // frames in its datagram
}

func pingWrites(ws []dgWrite) (out []pingWrite) {
	for _, w := range ws {
		fs, _ := dgDecode(w.b)
		for _, f := range fs {
			if f.Type == wire.TypePing {
				p, _ := wire.ParsePing(f.Payload)
				out = append(out, pingWrite{p: p, at: w.at, len: len(w.b), n: len(fs)})
			}
		}
	}
	return out
}

// isPingDatagram reports datagrams that carry a PING other than a rebind
// challenge.
func isPingDatagram(d []byte) bool {
	for _, p := range pingsOf(d, false) {
		if p.ID != 0 {
			return true
		}
	}
	return false
}

// TestPingRetryOnLoss_L24_L25: an unanswered PING is retried one RTO after
// its commit, and a lost retry one RTO after that — one unpadded PING per
// RTO, never a burst (PA-10, R1-13) — so an idle datagram carrier whose
// cadence is PingIdle (longer than the death deadline) survives the loss of
// a PING; the death rule itself is unchanged.
func TestPingRetryOnLoss_L24_L25(t *testing.T) {
	for _, lose := range []int{1, 2} {
		t.Run(fmt.Sprintf("%d lost", lose), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a, b := dgPair(t, 1200)
				a.io.setDelay(5 * time.Millisecond)
				b.io.setDelay(5 * time.Millisecond)
				a.io.setRec(true)
				a.start(StartOptions{})
				b.start(StartOptions{})
				time.Sleep(10 * time.Second) // past youth: the cadence is PingIdle (10 s) > D (3 s)
				var lost atomic.Int32
				a.io.setFilter(dropFirst(isPingDatagram, lose, &lost))
				time.Sleep(20 * time.Second)
				if dead, cause, detail, _ := a.c.Death(); dead {
					t.Fatalf("carrier died: %v %q", cause, detail)
				}
				if int(lost.Load()) != lose {
					t.Fatalf("lost %d PINGs, want %d", lost.Load(), lose)
				}
				a.c.mu.Lock()
				rto := a.c.relRTOLocked()
				a.c.mu.Unlock()
				ps := pingWrites(a.io.recorded())
				i := 0
				for i < len(ps) && ps[i].at.Sub(ps[0].at) < 10*time.Second {
					i++
				}
				if i+lose+1 >= len(ps) {
					t.Fatalf("%d PINGs, want the lost ones, their retries and the next cadence PING", len(ps))
				}
				for k := 1; k <= lose; k++ {
					if d := ps[i+k].at.Sub(ps[i+k-1].at); d != rto || ps[i+k].p.Pad != 0 {
						t.Fatalf("retry %d %v after the PING before it (pad %d), want one RTO (%v)", k, d, ps[i+k].p.Pad, rto)
					}
				}
				// The answered retry ends the retries: the next PING is the
				// cadence's, not a burst behind it.
				if d := ps[i+lose+1].at.Sub(ps[i+lose].at); d < rto {
					t.Fatalf("a PING %v after the answered retry, want none within an RTO (%v)", d, rto)
				}
			})
		})
	}
}

// TestIdleDatagramCarrierSurvivesLoss_L25: an idle datagram carrier — a
// session carrier at PingIdle, a probe carrier at Probe.Interval 10 s (R1-13)
// — over a path with 1 % loss each way lives for 10 virtual minutes: its
// PING retries reach the peer well inside the death deadline (PA-10). The
// stimulus is proven: PINGs or PONGs were lost.
func TestIdleDatagramCarrierSurvivesLoss_L25(t *testing.T) {
	for _, tc := range []struct {
		name   string
		dialer StartOptions
		pass   StartOptions
		seeds  [2]uint64
	}{
		{"session carrier", StartOptions{}, StartOptions{}, [2]uint64{7, 8}},
		{"probe carrier", StartOptions{Probe: true}, StartOptions{Sessionless: true}, [2]uint64{21, 22}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a, b := dgPair(t, 1200)
				withTiming(func(tm *Timing) { tm.ProbeInterval = 10 * time.Second }, a, b)
				a.io.setDelay(5 * time.Millisecond)
				b.io.setDelay(5 * time.Millisecond)
				var la, lb atomic.Int64
				a.io.setFilter(lossy(0.01, tc.seeds[0], &la))
				b.io.setFilter(lossy(0.01, tc.seeds[1], &lb))
				a.ep, b.ep = nil, nil
				a.start(tc.dialer)
				b.start(tc.pass)
				time.Sleep(10 * time.Minute)
				for _, s := range []*dgSide{a, b} {
					if dead, cause, detail, _ := s.c.Death(); dead {
						t.Fatalf("carrier died: %v %q (losses %d/%d)", cause, detail, la.Load(), lb.Load())
					}
				}
				if la.Load()+lb.Load() == 0 {
					t.Fatal("no loss happened: the stimulus is not proven")
				}
			})
		})
	}
}

// TestMTUProbe_L37: every MTUProbeEvery-th PING of the PacketPing cadence
// is padded to the budget and travels alone; three consecutive probes
// unanswered by their own PONG kill the carrier (ping_timeout, "mtu probe")
// about 40 s after it attached, one lost probe does not; a PONG to a probe
// is padded to at most the answering side's budget (M2-D24, PA-9).
func TestMTUProbe_L37(t *testing.T) {
	setup := func(t *testing.T) (*dgSide, *dgSide) {
		a, b := dgPair(t, 1200)
		withTiming(func(tm *Timing) { tm.PacketActive = time.Hour }, a, b)
		a.io.setDelay(5 * time.Millisecond)
		b.io.setDelay(5 * time.Millisecond)
		var want, size atomic.Int32
		want.Store(1) // one DGRAM: both carriers stay packet-active
		size.Store(10)
		a.ep.setFill(dgramFill(&want, &size))
		a.io.setRec(true)
		b.io.setRec(true)
		return a, b
	}
	t.Run("padded and alone", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			a, b := setup(t)
			a.start(StartOptions{})
			b.start(StartOptions{})
			time.Sleep(25 * time.Second)
			var probes []pingWrite
			for _, p := range pingWrites(a.io.recorded()) {
				if p.p.Pad > 0 {
					probes = append(probes, p)
				}
			}
			if len(probes) < 2 {
				t.Fatalf("%d probes in 25 s, want ≥ 2", len(probes))
			}
			for _, p := range probes {
				if p.len != 1200 || p.n != 1 || p.p.Pad != 1200-wire.FrameOverhead-wire.PingFixedLen {
					t.Fatalf("probe datagram of %d bytes, %d frames, pad %d; want 1200 bytes alone", p.len, p.n, p.p.Pad)
				}
			}
			if dead, cause, detail, _ := a.c.Death(); dead {
				t.Fatalf("carrier died: %v %q", cause, detail)
			}
		})
	})
	t.Run("three strikes kill", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			a, b := setup(t)
			a.io.setFilter(func(d []byte) bool { return len(d) <= 800 }) // a path MTU below the budget
			t0 := time.Now()
			a.start(StartOptions{})
			b.start(StartOptions{})
			hWait(t, a.c)
			_, cause, detail, at := a.c.Death()
			if cause != CausePingTimeout || !strings.Contains(detail, "mtu probe") {
				t.Fatalf("cause %v %q, want ping_timeout mtu probe", cause, detail)
			}
			if d := at.Sub(t0); d < 35*time.Second || d > 45*time.Second {
				t.Fatalf("killed %v after attach, want ≈ 40 s", d)
			}
		})
	})
	t.Run("one lost probe", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			a, b := setup(t)
			var lost atomic.Int32
			a.io.setFilter(dropFirst(func(d []byte) bool { return len(d) > 800 }, 1, &lost))
			a.start(StartOptions{})
			b.start(StartOptions{})
			time.Sleep(70 * time.Second)
			if dead, cause, detail, _ := a.c.Death(); dead || lost.Load() != 1 {
				t.Fatalf("death %v %v %q, lost %d", dead, cause, detail, lost.Load())
			}
		})
	})
	t.Run("PONG pad clamp", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			a, b := setup(t)
			b.c.dg.budget.Store(900) // b's send budget shrank; its receive limit is still 1200
			a.start(StartOptions{})
			b.start(StartOptions{})
			time.Sleep(15 * time.Second)
			var padded int
			for _, w := range b.io.recorded() {
				for _, p := range pingsOf(w.b, true) {
					if p.Pad > 0 {
						padded++
						if p.Pad != 900-wire.FrameOverhead-wire.PingFixedLen || len(w.b) != 900 {
							t.Fatalf("PONG pad %d in a datagram of %d, want clamped to the 900-byte budget", p.Pad, len(w.b))
						}
					}
				}
			}
			if padded == 0 {
				t.Fatal("no padded PONG answered the probe")
			}
		})
	})
}

// TestPacketPingCadence_L30: a datagram carrier PINGs every PacketPing while
// packet-active (a DGRAM within PacketActive) and every PingIdle otherwise;
// the end of the activity adds no PING (L30: silence triggers nothing), and
// a DGRAM that makes an idle carrier packet-active brings its next PING
// forward to the PacketPing cadence (M2-D23).
func TestPacketPingCadence_L30(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := dgPair(t, 1200)
		withTiming(func(tm *Timing) { tm.PacketActive = 3 * time.Second }, a, b)
		a.io.setDelay(5 * time.Millisecond)
		b.io.setDelay(5 * time.Millisecond)
		var want, size atomic.Int32
		size.Store(100)
		a.ep.setFill(dgramFill(&want, &size))
		a.io.setRec(true)
		b.io.setRec(true)
		t0 := time.Now()
		a.start(StartOptions{})
		b.start(StartOptions{})
		time.Sleep(20 * time.Second) // idle past youth: b PINGs at PingIdle
		t1 := time.Now()
		for range 20 { // 10 s of DGRAMs, every 500 ms
			want.Store(1)
			a.c.Wake()
			time.Sleep(500 * time.Millisecond)
		}
		t2 := time.Now()
		time.Sleep(40 * time.Second)
		pa := pingWrites(a.io.recorded())
		count := func(ps []pingWrite, from, to time.Time) (n int) {
			for _, p := range ps {
				if !p.at.Before(from) && p.at.Before(to) {
					n++
				}
			}
			return n
		}
		if n := count(pa, t1.Add(time.Second), t2); n < 8 || n > 10 {
			t.Fatalf("%d PINGs in 9 s of activity, want ≈ 9 (PacketPing 1 s)", n)
		}
		after := t2.Add(3 * time.Second) // PacketActive after the last DGRAM
		var prev time.Time
		for _, p := range pa {
			if p.at.Before(after) {
				prev = p.at
				continue
			}
			if p.at.Sub(prev) < 10*time.Second {
				t.Fatalf("PINGs %v apart after the activity, want PingIdle (10 s)", p.at.Sub(prev))
			}
			prev = p.at
		}
		if n := count(pa, t0, t1); n > 8 {
			t.Fatalf("%d PINGs in 20 s with youth then idle, want ≤ 8", n)
		}
		pb := pingWrites(b.io.recorded())
		var first time.Time
		for _, p := range pb {
			if !p.at.Before(t1) {
				first = p.at
				break
			}
		}
		if first.IsZero() || first.Sub(t1) > 1100*time.Millisecond {
			t.Fatalf("b's first PING %v after the DGRAMs began, want ≤ PacketPing", first.Sub(t1))
		}
	})
}

// TestPingIDSkipsZero_L14: a datagram carrier's PING ids skip 0 when they
// wrap — id 0 is the rebind challenge (M2-D27).
func TestPingIDSkipsZero_L14(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p := rawPair(t, 1200, true)
		s.c.st.nextPingID = 0xfffffffe
		s.start(StartOptions{})
		var ids []uint32
		for range 4 {
			time.Sleep(time.Second)
			for _, d := range p.read() {
				for _, pg := range pingsOf(d, false) {
					ids = append(ids, pg.ID)
					p.send(pingFrame(wire.TypePong, pg)) // answered: no retry, no death
				}
			}
		}
		if len(ids) < 4 || ids[0] != 0xfffffffe || ids[1] != 0xffffffff || ids[2] != 1 || ids[3] != 2 {
			t.Fatalf("PING ids %#x, want fffffffe ffffffff 1 2", ids)
		}
	})
}

// rebindAnswer makes a raw peer answer every PING that reached it —
// rebind challenges included — and returns the challenges answered.
func rebindAnswer(p *rawPeer) (answered int) {
	for _, d := range p.read() {
		for _, pg := range pingsOf(d, false) {
			p.send(pingFrame(wire.TypePong, pg))
			if pg.ID == 0 {
				answered++
			}
		}
	}
	return answered
}

// challenges counts the rebind challenges among recorded writes and returns
// their destinations.
func challenges(ws []dgWrite) (out []PeerKey) {
	for _, w := range ws {
		for _, pg := range pingsOf(w.b, false) {
			if pg.ID == 0 {
				out = append(out, w.dst)
			}
		}
	}
	return out
}

// TestRebindNonce_L59: a passive raw-UDP flow moves its peer only after the
// candidate source returned the challenge's nonce (M2-D27): a legitimate
// move commits (Rebinds 1; replies follow); a replayed datagram, a forged
// source with a bad CRC and a PONG from another source change nothing; a
// lost challenge is resent at the RTO and the rebind completes within
// 2·RTO + RTT (R1-14); challenges are max(RTO, 1 s) apart, expire at 2 s,
// and at most 10 rebinds commit per minute.
func TestRebindNonce_L59(t *testing.T) {
	setup := func(t *testing.T) (*dgSide, *rawPeer) {
		s, p := rawPair(t, 1200, false)
		s.io.rebind = true
		s.io.setRec(true)
		s.start(StartOptions{})
		synctest.Wait()
		p.read()
		return s, p
	}
	t.Run("legitimate move", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, p := setup(t)
			p.io.moveTo(fakeAddr(9))
			p.send(pingFrame(wire.TypePing, wire.Ping{ID: 5, Nonce: 1}))
			synctest.Wait()
			if n := rebindAnswer(p); n != 1 {
				t.Fatalf("%d challenges reached the new address", n)
			}
			synctest.Wait()
			if st := s.c.Stats(); st.Rebinds != 1 || s.env.Dgram.Rebinds.Load() != 1 || s.io.cur != fakeAddr(9) {
				t.Fatalf("rebinds %d (Runtime %d), peer %v", st.Rebinds, s.env.Dgram.Rebinds.Load(), s.io.cur)
			}
			p.read()
			p.send(pingFrame(wire.TypePing, wire.Ping{ID: 6, Nonce: 1}))
			synctest.Wait()
			var pong bool
			for _, d := range p.read() {
				for _, pg := range pingsOf(d, true) {
					pong = pong || pg.ID == 6
				}
			}
			if !pong {
				t.Fatal("replies do not follow the committed rebind")
			}
		})
	})
	t.Run("replay, forged CRC, foreign PONG", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, p := setup(t)
			old := p.datagram(pingFrame(wire.TypePing, wire.Ping{ID: 5, Nonce: 1}))
			_ = p.io.WriteDatagram(old)
			synctest.Wait()
			s.io.inject(fakeAddr(20), old) // a replay from another source: a window duplicate
			bad := p.datagram(pingFrame(wire.TypePing, wire.Ping{ID: 6, Nonce: 1}))
			bad[len(bad)-1] ^= 1
			s.io.inject(fakeAddr(21), bad) // a forged source with a bad CRC
			synctest.Wait()
			if n := len(challenges(s.io.recorded())); n != 0 {
				t.Fatalf("%d challenges for a replay and a forgery", n)
			}
			// A real candidate; its challenge answered from a third source.
			p.io.moveTo(fakeAddr(9))
			p.send(pingFrame(wire.TypePing, wire.Ping{ID: 7, Nonce: 1}))
			synctest.Wait()
			var nonce uint64
			for _, d := range p.read() {
				for _, pg := range pingsOf(d, false) {
					if pg.ID == 0 {
						nonce = pg.Nonce
					}
				}
			}
			if nonce == 0 {
				t.Fatal("no challenge to the candidate")
			}
			s.io.inject(fakeAddr(22), p.datagram(pingFrame(wire.TypePong, wire.Ping{ID: 0, Nonce: nonce})))
			synctest.Wait()
			if st := s.c.Stats(); st.Rebinds != 0 || s.io.cur != fakeAddr(2) {
				t.Fatalf("rebinds %d, peer %v: a PONG from another source committed", st.Rebinds, s.io.cur)
			}
		})
	})
	t.Run("lost challenge resent", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, p := setup(t)
			var lost atomic.Int32
			s.io.setFilter(dropFirst(func(d []byte) bool {
				for _, pg := range pingsOf(d, false) {
					if pg.ID == 0 {
						return true
					}
				}
				return false
			}, 1, &lost))
			p.io.moveTo(fakeAddr(9))
			t0 := time.Now()
			p.send(pingFrame(wire.TypePing, wire.Ping{ID: 5, Nonce: 1}))
			for s.c.Stats().Rebinds == 0 && time.Since(t0) < 3*time.Second {
				time.Sleep(10 * time.Millisecond)
				rebindAnswer(p)
			}
			s.c.mu.Lock()
			rto := s.c.relRTOLocked()
			s.c.mu.Unlock()
			if lost.Load() != 1 || s.c.Stats().Rebinds != 1 || time.Since(t0) > 2*rto+20*time.Millisecond {
				t.Fatalf("lost %d, rebinds %d after %v, want 1 and 1 within 2·RTO", lost.Load(), s.c.Stats().Rebinds, time.Since(t0))
			}
		})
	})
	t.Run("expiry", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, p := setup(t)
			p.io.moveTo(fakeAddr(9))
			p.send(pingFrame(wire.TypePing, wire.Ping{ID: 5, Nonce: 1}))
			synctest.Wait()
			var nonce uint64
			for _, d := range p.read() {
				for _, pg := range pingsOf(d, false) {
					if pg.ID == 0 {
						nonce = pg.Nonce
					}
				}
			}
			time.Sleep(2500 * time.Millisecond)
			p.send(pingFrame(wire.TypePong, wire.Ping{ID: 0, Nonce: nonce}))
			synctest.Wait()
			if st := s.c.Stats(); nonce == 0 || st.Rebinds != 0 {
				t.Fatalf("nonce %#x, rebinds %d after the expiry", nonce, st.Rebinds)
			}
		})
	})
	t.Run("rate limits", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, p := setup(t)
			id := uint32(10)
			move := func(a byte) {
				p.io.moveTo(fakeAddr(a))
				id++
				p.send(pingFrame(wire.TypePing, wire.Ping{ID: id, Nonce: 1}))
				synctest.Wait()
				rebindAnswer(p)
				synctest.Wait()
			}
			move(30)
			move(31) // within 1 s of the last challenge: no new one
			if r := s.c.Stats().Rebinds; r != 1 || s.io.cur != fakeAddr(30) {
				t.Fatalf("rebinds %d, peer %v: the spacing was not kept", r, s.io.cur)
			}
			wait := func(d time.Duration) { // the peer keeps answering PINGs: the carrier lives
				for end := time.Now().Add(d); time.Now().Before(end); {
					time.Sleep(100 * time.Millisecond)
					rebindAnswer(p)
				}
			}
			for i := range byte(10) {
				wait(1100 * time.Millisecond)
				move(40 + i)
			}
			if r := s.c.Stats().Rebinds; r != 10 {
				t.Fatalf("rebinds %d within a minute, want 10 (the limit)", r)
			}
			if s.io.cur != fakeAddr(48) {
				t.Fatalf("peer %v, want the tenth commit's 48", s.io.cur)
			}
			p.io.moveTo(fakeAddr(48)) // back at the committed address: the carrier lives through the minute
			wait(time.Minute)
			move(60)
			if r := s.c.Stats().Rebinds; r != 11 {
				t.Fatalf("rebinds %d after the minute, want 11", r)
			}
		})
	})
}

// TestChallengePongSlot: a PING with id 0 is answered through its own slot
// (PONG id 0, same nonce), never displacing the regular latest-wins PONG.
func TestChallengePongSlot(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p := rawPair(t, 1200, true)
		s.start(StartOptions{})
		synctest.Wait()
		p.read()
		p.send(pingFrame(wire.TypePing, wire.Ping{ID: 7, Nonce: 70}), pingFrame(wire.TypePing, wire.Ping{ID: 0, Nonce: 99}))
		synctest.Wait()
		got := map[uint32]uint64{}
		for _, d := range p.read() {
			for _, pg := range pingsOf(d, true) {
				got[pg.ID] = pg.Nonce
			}
		}
		if got[7] != 70 || got[0] != 99 || len(got) != 2 {
			t.Fatalf("PONGs %v, want id 7 nonce 70 and id 0 nonce 99", got)
		}
	})
}

// TestHeldDatagramCarrier: a held passive datagram carrier answers before
// its first response — a PONG for a PING, a RACK for a REL — and never
// writes a PING or a session frame while held; at the verdict its first
// response leaves with the first PING behind it in the same round (M2-D22,
// R1-8). (The H2 repeat of a duplicate H1 is the root's
// TestHeldCarrierRepeatsH2E2E.)
func TestHeldDatagramCarrier(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p := rawPair(t, 1200, false)
		var verdict atomic.Bool
		s.ep.setFill(func(c *Conn, b *Batch) {
			if verdict.Load() {
				b.AddOpenAck(wire.SessionHandle, &wire.OpenAck{Status: wire.StatusOK})
			}
		})
		s.start(StartOptions{Hold: true})
		synctest.Wait()
		first := s.env.Presets.firstCseq()
		p.send(pingFrame(wire.TypePing, wire.Ping{ID: 3, Nonce: 30}))
		p.send(relFrame(first, wire.TypeFin, 0, wire.SessionHandle, finInner(0)))
		time.Sleep(5 * time.Second)
		var pong, rack bool
		for _, d := range p.read() {
			fs, _ := dgDecode(d)
			for _, f := range fs {
				switch f.Type {
				case wire.TypePong:
					pong = true
				case wire.TypeRack:
					rack = true
				default:
					t.Fatalf("a held carrier wrote %v", f.Type)
				}
			}
		}
		if !pong || !rack {
			t.Fatalf("held: PONG %v RACK %v, want both", pong, rack)
		}
		verdict.Store(true)
		s.c.Wake()
		synctest.Wait()
		ds := p.read()
		if len(ds) == 0 {
			t.Fatal("nothing written at the verdict")
		}
		fs, _ := dgDecode(ds[0])
		if len(fs) < 2 || fs[0].Type != wire.TypeRel || fs[1].Type != wire.TypePing {
			t.Fatalf("first datagram after the verdict %v, want REL{OPEN_ACK} then the first PING", fs)
		}
		if h, _, _ := wire.ParseRel(fs[0].Payload); h.Type != wire.TypeOpenAck {
			t.Fatalf("first REL %v, want OPEN_ACK", h.Type)
		}
	})
}

// allocDgEP is a packet endpoint that allocates nothing: Fill places one
// DGRAM (and, when rel, one FIN) per round; Datagram and Control count.
type allocDgEP struct {
	chunk *Buf
	rel   bool
	seq   uint64
	n     atomic.Int64
}

func (e *allocDgEP) Handle() uint32 { return wire.SessionHandle }
func (e *allocDgEP) Fill(c *Conn, b *Batch) {
	if b.AddDgram(wire.SessionHandle, e.seq, e.chunk.B[:1000], e.chunk) {
		e.seq++
	}
	if e.rel {
		b.AddFin(wire.SessionHandle, e.seq)
	}
}
func (e *allocDgEP) Data(*Conn, uint64, []byte, *Buf) error { return nil }
func (e *allocDgEP) Control(*Conn, wire.Header, []byte) error {
	e.n.Add(1)
	return nil
}
func (e *allocDgEP) WriteBlocked(*Conn) {}
func (e *allocDgEP) Datagram(_ *Conn, _ uint64, _ []byte, buf *Buf) error {
	e.n.Add(1)
	buf.Release()
	return nil
}

// TestDatagramCarrierRoundZeroAllocs_L41_L54: a datagram carrier's steady
// state allocates nothing — the writer round (Fill, REL seal, packing into
// the reused scratch after a flow header's headroom, the physical write)
// and the reader (window, dispatch, REL receive, RACK) over an in-memory
// pair, with REL/RACK active and idle (L41, L54; non-race lane).
func TestDatagramCarrierRoundZeroAllocs_L41_L54(t *testing.T) {
	if carrierRace {
		t.Skip("allocation gates run in the non-race lane (sync.Pool drops items under -race)")
	}
	for _, rel := range []bool{false, true} {
		name := "idle REL"
		if rel {
			name = "REL and RACK"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a, b := dgPair(t, 1200)
				a.io.hr = wire.FlowHeaderLen
				epA := &allocDgEP{chunk: a.env.Bufs.Get(ChunkSize, nil), rel: rel}
				epB := &allocDgEP{chunk: b.env.Bufs.Get(ChunkSize, nil)}
				defer epA.chunk.Release()
				defer epB.chunk.Release()
				for _, x := range []struct {
					s  *dgSide
					ep *allocDgEP
				}{{a, epA}, {b, epB}} {
					x.s.c.ep, x.s.c.pep = x.ep, x.ep
					x.s.c.mu.Lock()
					x.s.c.st.pingSent = true // no first PING: the cadence is far away
					x.s.c.st.lastCommit = time.Now()
					x.s.c.mu.Unlock()
					x.s.c.writerInit()
				}
				ra := &dgReader{buf: a.c.dbufs().Get(a.io.ReadSize(), nil)}
				rb := &dgReader{buf: b.c.dbufs().Get(b.io.ReadSize(), nil)}
				defer ra.buf.Release()
				defer rb.buf.Release()
				round := func() {
					if !a.c.writeRound(&a.c.wr) {
						t.Fatal("a's round ended the carrier")
					}
					for b.io.n > 0 {
						if !b.c.dgReadOne(rb) {
							t.Fatal("b's read ended the carrier")
						}
					}
					if rel {
						epB.rel = false
						if !b.c.writeRound(&b.c.wr) {
							t.Fatal("b's round ended the carrier")
						}
						for a.io.n > 0 {
							if !a.c.dgReadOne(ra) {
								t.Fatal("a's read ended the carrier")
							}
						}
					}
				}
				for range 20 {
					round()
				}
				if allocs := testing.AllocsPerRun(200, round); allocs != 0 {
					t.Fatalf("%.1f allocations per round, want 0", allocs)
				}
				if rel && a.c.RelRoom() != wire.RelWindow {
					t.Fatalf("RelRoom %d: RACKs did not keep up", a.c.RelRoom())
				}
				if epB.n.Load() == 0 {
					t.Fatal("nothing was delivered")
				}
				for _, s := range []*dgSide{a, b} {
					s.c.wr.dscratch.Release()
					s.c.wr.dscratch = nil
					s.c.wr.timer.Stop()
					s.c.wd1.Stop()
					s.c.wd2.Stop()
				}
			})
		})
	}
}
