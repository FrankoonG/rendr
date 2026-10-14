package carrier

import (
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// The pace of the PINGs that prove a forward jump (m5 PA-85, amending m3
// FSEQJUMP's "at most one per RTO"; plan:332, L43): dgJumpPingLocked asks
// for one when a claim begins, then once per smoothed RTT (at least
// minRateSample) for at most the ping timeout, at M3's RTO pace after it,
// and at least an RTO and D/16 apart while the cadence's share of the PING
// ring is outstanding.

// fjRTT gives the carrier a smoothed RTT of rtt: every PING it wrote since
// its start is answered rtt after it was read, so its first RTT sample is
// rtt. It returns the carrier's srtt and REL RTO, with no PING outstanding.
func fjRTT(t *testing.T, s *dgSide, p *rawPeer, rtt time.Duration) (srtt, rto time.Duration) {
	t.Helper()
	_, pings := fjPings(p.read(), false)
	if len(pings) == 0 {
		t.Fatal("stimulus: the carrier wrote no PING after its start")
	}
	time.Sleep(rtt)
	for _, pg := range pings {
		p.send(pingFrame(wire.TypePong, pg))
	}
	synctest.Wait()
	if _, more := fjPings(p.read(), false); len(more) != 0 {
		t.Fatalf("stimulus: the carrier wrote PINGs %+v while its first was answered", more)
	}
	s.c.mu.Lock()
	srtt, rto, n := s.c.st.srtt, s.c.relRTOLocked(), s.c.st.n
	s.c.mu.Unlock()
	if srtt != rtt || n != 0 {
		t.Fatalf("stimulus: srtt %v with %d PINGs outstanding, want %v and none", srtt, n, rtt)
	}
	return srtt, rto
}

// fjRun sends the scripted peer's DGRAMs through send, one per step from
// now while more holds (it is asked before each), and records when the
// carrier wrote each PING (relative to start) and the newest one. After
// the last DGRAM no time passes.
func fjRun(p *rawPeer, start time.Time, step time.Duration, more func(i int) bool, send func(i int)) (at []time.Duration, last wire.Ping) {
	for i := 0; more(i); i++ {
		if i > 0 {
			time.Sleep(step)
		}
		send(i)
		synctest.Wait()
		_, pings := fjPings(p.read(), false)
		for _, pg := range pings {
			at = append(at, time.Since(start))
			last = pg
		}
	}
	return at, last
}

// TestDatagramJumpProofPacedByRTT_L43: the PING that proves a forward jump
// is asked for when the jump is first seen and again once per smoothed RTT
// while jumped frames keep coming — never at the RTO, never more often —
// so a lost proof costs a round trip, not RelRTOMin (m5 PA-85, the cause of
// C-P's F-5). The carrier's srtt is 20 ms (its first PING answered 20 ms
// late) and its RTO 200 ms; the peer's direction jumps by a window and
// 5000 frames and sends one DGRAM per millisecond for 100 ms while every
// PING of the carrier is lost (never answered). PASS: the carrier writes
// its first PING at the first jumped DGRAM, then one each 20 ms (20 to
// 21 ms apart), six in all, none in between; every jumped DGRAM is dropped
// and counted; the PONG to the newest PING proves the jump; a jump right
// after it, at the instant of the last request, is a new claim and asks at
// once; the carrier lives.
func TestDatagramJumpProofPacedByRTT_L43(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p := rawPair(t, 1200, true)
		s.start(StartOptions{})
		synctest.Wait()
		srtt, rto := fjRTT(t, s, p, 20*time.Millisecond)
		if rto < 5*srtt {
			t.Fatalf("stimulus: RTO %v is not well above srtt %v", rto, srtt)
		}
		d0 := s.c.Stats().Dropped
		p.fseq += fjOutage // lost in the outage
		const span = 101   // jumped DGRAMs, one per millisecond: 0 … 100 ms
		at, last := fjRun(p, time.Now(), time.Millisecond, func(i int) bool { return i < span }, func(i int) {
			p.send(dgramFrame(uint64(10+i), 100))
		})
		t.Logf("srtt %v, RTO %v: the carrier's PINGs at %v", srtt, rto, at)
		if len(at) == 0 || at[0] != 0 {
			t.Fatalf("PINGs at %v: want the first at the first jumped DGRAM", at)
		}
		for k := 1; k < len(at); k++ {
			if g := at[k] - at[k-1]; g < srtt || g > srtt+time.Millisecond {
				t.Fatalf("PINGs at %v: %v between two, want srtt %v to 1 ms more", at, g, srtt)
			}
		}
		if want := int((span-1)*time.Millisecond/srtt) + 1; len(at) != want {
			t.Fatalf("PINGs at %v: %d in %d ms, want %d (one per srtt)", at, len(at), span-1, want)
		}
		if d := s.c.Stats().Dropped - d0; d != span {
			t.Fatalf("dropped %d of the %d jumped DGRAMs", d, span)
		}
		// The proof, then a new jump at the instant of the last request.
		p.send(dgramFrame(200, 100), pingFrame(wire.TypePong, last))
		synctest.Wait()
		if got := fjDelivered(s.ep); !slices.Equal(got, []uint64{200}) {
			t.Fatalf("delivered %v, want [200]: the PONG to the newest PING did not prove the jump", got)
		}
		p.read()
		p.fseq += fjOutage
		p.send(dgramFrame(201, 100))
		synctest.Wait()
		if ids, _ := fjPings(p.read(), false); len(ids) != 1 {
			t.Fatalf("PINGs %v after a new jump right after a proven one, want one at once", ids)
		}
		if dead, cause, detail, _ := s.c.Death(); dead {
			t.Fatalf("carrier died: %v %q", cause, detail)
		}
	})
}

// TestDatagramJumpProofFloor_L43: below minRateSample (5 ms) the smoothed
// RTT no longer paces the proof PINGs (m5 PA-85): a carrier whose PINGs
// come back at once (srtt 0, as on a fast loopback, or before its first RTT
// sample) and whose peer's direction jumps and sends a DGRAM per
// millisecond for 20 ms writes a PING at the first jumped DGRAM and then
// one each 5 ms (five in all), not one per jumped DGRAM.
func TestDatagramJumpProofFloor_L43(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p := rawPair(t, 1200, true)
		s.start(StartOptions{})
		synctest.Wait()
		fjRTT(t, s, p, 0)
		p.fseq += fjOutage
		const span = 21
		at, _ := fjRun(p, time.Now(), time.Millisecond, func(i int) bool { return i < span }, func(i int) {
			p.send(dgramFrame(uint64(10+i), 100))
		})
		var want []time.Duration
		for k := time.Duration(0); k < span*time.Millisecond; k += minRateSample {
			want = append(want, k)
		}
		if !slices.Equal(at, want) {
			t.Fatalf("PINGs at %v, want %v: one per %v", at, want, minRateSample)
		}
	})
}

// fjAnswer is a PONG the scripted peer sends at a given time.
type fjAnswer struct {
	at time.Time
	p  wire.Ping
}

// TestDatagramJumpProofBounded_L43: a jump claim asks for PINGs at the
// round trip's pace for no longer than the ping timeout (the death
// deadline D, 3 s here) since it began (m5 PA-85): a genuine jump is proven
// by then or its carrier is dead, so a longer claim is another carrier
// direction's frames, which from then on ask at M3's pace (once per RTO)
// and never draw a PING per round trip for as long as they come. The
// carrier's srtt is 20 ms and its RTO 200 ms; its peer answers every PING
// 20 ms after it was written (the carrier lives and its genuine direction
// is in order), while frames of another direction (fseqs 2^20 ahead)
// arrive every millisecond for 2·D + 100 ms. PASS: in the claim's first
// D − 50 ms the carrier writes at least a PING per two round trips; from
// D + 50 ms to 2·D its PINGs go an RTO apart (to a millisecond more);
// every foreign frame is dropped and counted; after a pause of D + 100 ms
// without one, foreign frames for 100 ms begin a new claim: a PING at the
// first of them and a round trip apart after it (five in the 100 ms); the
// carrier lives.
func TestDatagramJumpProofBounded_L43(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const rtt = 20 * time.Millisecond
		s, p := rawPair(t, 1200, true)
		s.start(StartOptions{})
		synctest.Wait()
		_, rto := fjRTT(t, s, p, rtt)
		s.c.mu.Lock()
		dl := sched.DeathDeadline(s.c.st.srtt, s.c.st.inflight(), s.c.st.rate, s.c.tm.DeadMin, s.c.tm.DeadMax)
		s.c.mu.Unlock()
		foreign := &rawPeer{io: p.io, fseq: p.fseq + 1<<20}
		d0 := s.c.Stats().Dropped
		start := time.Now()
		var at []time.Duration
		var due []fjAnswer
		sent := 0
		// step answers the PONGs due, sends a foreign DGRAM when asked to,
		// and schedules the answer to every PING the carrier wrote.
		step := func(frame bool) {
			now := time.Now()
			k := 0
			for _, a := range due {
				if a.at.After(now) {
					due[k] = a
					k++
					continue
				}
				p.send(pingFrame(wire.TypePong, a.p))
			}
			due = due[:k]
			if frame {
				foreign.send(dgramFrame(uint64(1000+sent), 100))
				sent++
			}
			synctest.Wait()
			_, pings := fjPings(p.read(), false)
			for _, pg := range pings {
				at = append(at, time.Since(start))
				due = append(due, fjAnswer{at: time.Now().Add(rtt), p: pg})
			}
		}
		run := func(d time.Duration, frames bool) {
			for from := time.Now(); time.Since(from) < d; {
				step(frames)
				time.Sleep(time.Millisecond)
			}
		}
		within := func(from, to time.Duration) (out []time.Duration) {
			for _, a := range at {
				if a >= from && a < to {
					out = append(out, a)
				}
			}
			return out
		}
		run(2*dl+100*time.Millisecond, true)
		claim, spent := within(0, dl-50*time.Millisecond), within(dl+50*time.Millisecond, 2*dl)
		t.Logf("D %v, srtt %v, RTO %v: %d PINGs in the claim's first %v; from %v to %v at %v; %d foreign frames",
			dl, rtt, rto, len(claim), dl-50*time.Millisecond, dl+50*time.Millisecond, 2*dl, spent, sent)
		if min := int((dl - 50*time.Millisecond) / (2 * rtt)); len(claim) < min {
			t.Fatalf("%d PINGs while the claim lasted, want at least %d (one per round trip)", len(claim), min)
		}
		if len(spent) < 2 {
			t.Fatalf("PINGs %v after the claim's ping timeout, want them at M3's pace (once per RTO)", spent)
		}
		for k := 1; k < len(spent); k++ {
			if g := spent[k] - spent[k-1]; g < rto || g > rto+time.Millisecond {
				t.Fatalf("PINGs %v after the claim's ping timeout: %v between two, want the RTO %v to 1 ms more", spent, g, rto)
			}
		}
		// A pause of a ping timeout without a foreign frame ends the claim:
		// the next ones begin a new one, paced by the round trip again.
		run(dl+100*time.Millisecond, false)
		from := time.Since(start)
		run(100*time.Millisecond, true)
		again := within(from, time.Since(start))
		var want []time.Duration
		for k := time.Duration(0); k < 100*time.Millisecond; k += rtt {
			want = append(want, from+k)
		}
		if !slices.Equal(again, want) {
			t.Fatalf("PINGs at %v after the pause, want %v: a new claim at the first foreign frame, a round trip apart", again, want)
		}
		if d := s.c.Stats().Dropped - d0; d != uint64(sent) {
			t.Fatalf("dropped %d frames of %d foreign DGRAMs", d, sent)
		}
		if dead, cause, detail, _ := s.c.Death(); dead {
			t.Fatalf("carrier died: %v %q", cause, detail)
		}
	})
}

// TestDatagramJumpProofRingShare_L43: round-trip-paced proof PINGs stop
// short of filling the PING ring (m5 PA-85): once the cadence's share of
// the ring (pingCadenceMax) is outstanding, the requests go an RTO (M3's
// pace) and D/16 apart (D the ping timeout), so the other 16 records last
// the whole claim and a PING still goes out when a reverse path that lost
// them comes back (a full ring encodes none: the carrier would die of
// ping_timeout with its path back). The carrier's srtt is 20 ms and its
// RTO 200 ms; the peer's direction jumps by a window and 5000 frames and
// sends a DGRAM per step while every PING of the carrier is lost: for 1 s
// with the default D of 3 s (D/16 below the RTO), and for 8 s with DeadMin
// and DeadMax 10 s (D/16 = 625 ms; at the RTO alone the ring would be full
// after 3.5 s). PASS: the first pingCadenceMax PINGs go a round trip apart
// (20 ms to a step more), the later ones max(RTO, D/16) apart (to a step
// more); the ring is never full; after the loss the first PING the carrier
// writes is answered at once and its PONG proves the jump within
// max(RTO, D/16) and two steps; the carrier lives.
func TestDatagramJumpProofRingShare_L43(t *testing.T) {
	for _, tc := range []struct {
		name       string
		dead, loss time.Duration // DeadMin = DeadMax (0: the default), the PINGs' loss
		step       time.Duration
	}{
		{"default", 0, time.Second, time.Millisecond},
		{"deadmin10s", 10 * time.Second, 8 * time.Second, 2 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s, p := rawPairWith(t, 1200, true, func(env *Env) {
					if tc.dead > 0 {
						env.Timing.DeadMin, env.Timing.DeadMax = tc.dead, tc.dead
					}
				})
				s.start(StartOptions{})
				synctest.Wait()
				srtt, rto := fjRTT(t, s, p, 20*time.Millisecond)
				s.c.mu.Lock()
				dl := sched.DeathDeadline(s.c.st.srtt, s.c.st.inflight(), s.c.st.rate, s.c.tm.DeadMin, s.c.tm.DeadMax)
				s.c.mu.Unlock()
				every := max(rto, dl/(pingRingSize-pingCadenceMax))
				p.fseq += fjOutage
				start := time.Now()
				seq := uint64(10)
				full := false
				at, _ := fjRun(p, start, tc.step, func(int) bool { return time.Since(start) < tc.loss }, func(int) {
					p.send(dgramFrame(seq, 100))
					seq++
					s.c.mu.Lock()
					full = full || s.c.st.n >= pingRingSize
					s.c.mu.Unlock()
				})
				t.Logf("D %v, srtt %v, RTO %v: %d PINGs while they were lost, at %v", dl, srtt, rto, len(at), at)
				if len(at) <= pingCadenceMax {
					t.Fatalf("stimulus: %d PINGs while they were lost, want more than the cadence's share %d", len(at), pingCadenceMax)
				}
				if full {
					t.Fatalf("the PING ring was full while the PINGs were lost")
				}
				for k := 1; k < len(at); k++ {
					g, lo := at[k]-at[k-1], srtt
					if k >= pingCadenceMax {
						lo = every
					}
					if g < lo || g > lo+tc.step {
						t.Fatalf("PINGs at %v: %v between PINGs %d and %d, want %v to a step more", at, g, k-1, k, lo)
					}
				}
				// The reverse path is back: the first PING the carrier writes
				// is answered at once, and its PONG proves the jump.
				end := time.Now()
				var proved bool
				for !proved && time.Since(end) < every+2*tc.step {
					time.Sleep(tc.step)
					p.send(dgramFrame(seq, 100))
					seq++
					synctest.Wait()
					if _, pings := fjPings(p.read(), false); len(pings) > 0 {
						p.send(dgramFrame(seq, 100), pingFrame(wire.TypePong, pings[len(pings)-1]))
						synctest.Wait()
						proved = slices.Contains(fjDelivered(s.ep), seq)
						seq++
					}
				}
				if !proved {
					t.Fatalf("the jump was not proven within %v after the reverse path came back (delivered %v)", every+2*tc.step, fjDelivered(s.ep))
				}
				if dead, cause, detail, _ := s.c.Death(); dead {
					t.Fatalf("carrier died: %v %q", cause, detail)
				}
			})
		})
	}
}
