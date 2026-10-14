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
// FSEQJUMP's "at most one per RTO"; plan:333, L43): dgJumpPingLocked asks
// for one when a claim begins, then once per smoothed RTT (at least
// minRateSample); at M3's RTO pace once the claim is a ping timeout old
// while the carrier still accepts frames (a foreign claim); and, while the
// cadence's share of the PING ring is outstanding, with the free records
// spread evenly over the time left to the carrier's death deadline.

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
// by then or its carrier is dead, so a longer claim on a carrier that
// still accepts frames of its own direction is another carrier
// direction's frames, which from then on ask at M3's pace (once per RTO)
// and never draw a PING per round trip for as long as they come. The
// carrier's srtt is 20 ms and its RTO 200 ms; its peer answers every PING
// 20 ms after it was written (the carrier lives and accepts its genuine
// direction's PONGs, in order), while frames of another direction (fseqs
// 2^20 ahead) arrive every millisecond for 2·D + 100 ms. PASS: in the
// claim's first D − 50 ms the carrier writes at least a PING per two round
// trips; from D + 50 ms to 2·D its PINGs go an RTO apart (to a millisecond
// more); every foreign frame is dropped and counted; after a pause of
// D + 100 ms without one, foreign frames for 100 ms begin a new claim: a
// PING at the first of them and a round trip apart after it (five in the
// 100 ms); the carrier lives.
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
// the ring (pingCadenceMax) is outstanding, the requests spread the free
// records evenly over the time left to the carrier's death deadline (its
// oldest unanswered PING's), never closer than a round trip, so a PING
// still goes out when a reverse path that lost them comes back before the
// death (a full ring encodes none: the carrier would die of ping_timeout
// with its path back), and no RTO paces them. The peer's direction jumps by
// a window and 5000 frames and sends a DGRAM per step while every PING of
// the carrier is lost: with an srtt of 20 ms and an RTO of 200 ms for 1 s
// at the default D of 3 s (the later PINGs about 159 ms apart: at the
// round trip's pace the ring would be full after 640 ms) and for 8 s with
// DeadMin and DeadMax 10 s (about 571 ms apart), and with an srtt of
// 150 ms (RTO 450 ms) for 2.8 s at the default D (the ring holds a PING
// per round trip until the death: they stay a round trip apart, never an
// RTO). PASS: the first pingCadenceMax PINGs go a round trip apart (to a
// step more); each later one follows the one before it, at t, by
// max(srtt, (A − t)/(f + 1)) to a step more, where A is the death deadline
// of the first PING (its time plus D) and f the records still free
// (pingRingSize less the PINGs before it); the ring is never full; after
// the loss the first PING the carrier writes is answered at once and its
// PONG proves the jump within the next such spacing and two steps; the
// carrier lives.
func TestDatagramJumpProofRingShare_L43(t *testing.T) {
	for _, tc := range []struct {
		name       string
		rtt        time.Duration
		dead, loss time.Duration // DeadMin = DeadMax (0: the default), the PINGs' loss
		step       time.Duration
	}{
		{"default", 20 * time.Millisecond, 0, time.Second, time.Millisecond},
		{"deadmin10s", 20 * time.Millisecond, 10 * time.Second, 8 * time.Second, 2 * time.Millisecond},
		{"rtt150", 150 * time.Millisecond, 0, 2800 * time.Millisecond, 5 * time.Millisecond},
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
				srtt, rto := fjRTT(t, s, p, tc.rtt)
				s.c.mu.Lock()
				dl := sched.DeathDeadline(s.c.st.srtt, s.c.st.inflight(), s.c.st.rate, s.c.tm.DeadMin, s.c.tm.DeadMax)
				s.c.mu.Unlock()
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
				// spacing is the least gap after a PING at from with k PINGs
				// outstanding: a round trip, and once the cadence's share is
				// outstanding the free records spread to the death deadline.
				death := at[0] + dl
				spacing := func(from time.Duration, k int) time.Duration {
					if k < pingCadenceMax {
						return srtt
					}
					return max(srtt, (death-from)/time.Duration(pingRingSize-k+1))
				}
				for k := 1; k < len(at); k++ {
					g, lo := at[k]-at[k-1], spacing(at[k-1], k)
					if g < lo || g > lo+tc.step {
						t.Fatalf("PINGs at %v: %v between PINGs %d and %d, want %v to a step more", at, g, k-1, k, lo)
					}
				}
				// The reverse path is back: the first PING the carrier writes
				// is answered at once, and its PONG proves the jump.
				every := spacing(at[len(at)-1], len(at))
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

// TestDatagramJumpProofForeignThenGenuine_L43: a claim that frames of
// another direction kept going for longer than a ping timeout asks at M3's
// pace only while the carrier still accepts frames of its own direction;
// when its own direction jumps too, the carrier accepts nothing more, and
// from an RTO and a round trip after the last frame it accepted its PINGs
// go a round trip apart again, so a lost proof costs a round trip, not an
// RTO, inside a foreign claim as well (m5 PA-85: the proving PING is never
// left to the RTO cadence). The carrier's srtt is 20 ms and its RTO 200 ms
// (D 3 s); frames of another direction (fseqs 2^20 ahead) arrive every
// millisecond throughout. For D + 700 ms the peer answers each PING in
// order, alternately 20 and 30 ms after it was written (a jitter below a
// round trip); then the peer's direction jumps by a window and 5000
// frames, its DGRAMs arrive every millisecond, and the answers still due
// and every PING of the carrier are lost until eight round trips after S,
// the time an RTO and a round trip after the last answer the carrier
// accepted; then the peer answers the newest PING in a jumped datagram.
// PASS: from D + 50 ms to the jump the PINGs go an RTO apart (to a
// millisecond more: the claim is foreign, and the jitter does not
// interrupt the carrier's evidence); the first PING at or after S comes
// within a round trip and a millisecond of it, the later ones a round trip
// apart (to a millisecond more), at least six; fewer than pingCadenceMax
// PINGs are outstanding at the end of the loss (the ring's share plays no
// part); the PONG in the jumped datagram proves the jump (its DGRAM is
// delivered); every foreign and unproven jumped frame is dropped and
// counted; the carrier lives.
func TestDatagramJumpProofForeignThenGenuine_L43(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p := rawPair(t, 1200, true)
		s.start(StartOptions{})
		synctest.Wait()
		_, rto := fjRTT(t, s, p, 20*time.Millisecond)
		s.c.mu.Lock()
		dl := sched.DeathDeadline(s.c.st.srtt, s.c.st.inflight(), s.c.st.rate, s.c.tm.DeadMin, s.c.tm.DeadMax)
		s.c.mu.Unlock()
		foreign := &rawPeer{io: p.io, fseq: p.fseq + 1<<20}
		d0 := s.c.Stats().Dropped
		start := time.Now()
		var (
			at         []time.Duration // when the carrier wrote each PING
			newest     wire.Ping
			due        []fjAnswer
			answers    int           // answers the peer scheduled
			lastAnswer time.Duration // when the peer last sent an answer in order
			jumped     bool          // the peer's direction jumped: its frames are ahead
			drops      int           // frames sent that the carrier must drop
		)
		// step sends the answers due and a foreign DGRAM (and a jumped one
		// once the peer's direction jumped), then schedules an answer to
		// every PING the carrier wrote, alternately 20 and 30 ms late,
		// until the jump.
		step := func() {
			now := time.Now()
			k := 0
			for _, a := range due {
				if a.at.After(now) {
					due[k] = a
					k++
					continue
				}
				p.send(pingFrame(wire.TypePong, a.p))
				lastAnswer = time.Since(start)
			}
			due = due[:k]
			foreign.send(dgramFrame(uint64(1000+drops), 100))
			drops++
			if jumped {
				p.send(dgramFrame(uint64(1000+drops), 100))
				drops++
			}
			synctest.Wait()
			_, pings := fjPings(p.read(), false)
			for _, pg := range pings {
				at = append(at, time.Since(start))
				newest = pg
				if !jumped {
					delay := 20 * time.Millisecond
					if answers%2 == 1 {
						delay += 10 * time.Millisecond
					}
					answers++
					due = append(due, fjAnswer{at: time.Now().Add(delay), p: pg})
				}
			}
		}
		run := func(d time.Duration) {
			for from := time.Now(); time.Since(from) < d; {
				step()
				time.Sleep(time.Millisecond)
			}
		}
		run(dl + 700*time.Millisecond)
		// The peer's direction jumps: the answers still due are lost, with
		// everything else it sends until the proof.
		jump := time.Since(start)
		p.fseq += fjOutage
		due, jumped = nil, true
		s.c.mu.Lock()
		srtt, rtoNow := s.c.st.srtt, s.c.relRTOLocked()
		s.c.mu.Unlock()
		if rtoNow != rto {
			t.Fatalf("stimulus: the RTO moved from %v to %v with the answers' jitter", rto, rtoNow)
		}
		sw := lastAnswer + rto + srtt // S: the carrier's evidence of its own direction runs out
		run(sw + 8*srtt - time.Since(start))
		s.c.mu.Lock()
		n := s.c.st.n
		s.c.mu.Unlock()
		var foreignPINGs, after []time.Duration
		for _, a := range at {
			switch {
			case a >= sw:
				after = append(after, a)
			case a >= dl+50*time.Millisecond && a < jump:
				foreignPINGs = append(foreignPINGs, a)
			}
		}
		t.Logf("D %v, srtt %v, RTO %v: PINGs of the foreign claim from D + 50 ms at %v; the jump at %v, the last answer at %v, S at %v; PINGs from S at %v; %d outstanding",
			dl, srtt, rto, foreignPINGs, jump, lastAnswer, sw, after, n)
		if len(foreignPINGs) < 3 {
			t.Fatalf("stimulus: PINGs %v of the foreign claim after its ping timeout, want three or more", foreignPINGs)
		}
		for k := 1; k < len(foreignPINGs); k++ {
			if g := foreignPINGs[k] - foreignPINGs[k-1]; g < rto || g > rto+time.Millisecond {
				t.Fatalf("PINGs %v of the foreign claim: %v between two, want the RTO %v to 1 ms more", foreignPINGs, g, rto)
			}
		}
		if n >= pingCadenceMax {
			t.Fatalf("stimulus: %d PINGs outstanding after the loss: the ring's share plays a part", n)
		}
		if len(after) < 6 || after[0] > sw+srtt+time.Millisecond {
			t.Fatalf("PINGs from S (%v) at %v: want the first within a round trip (%v) and a millisecond, and at least six", sw, after, srtt)
		}
		for k := 1; k < len(after); k++ {
			if g := after[k] - after[k-1]; g < srtt || g > srtt+time.Millisecond {
				t.Fatalf("PINGs from S (%v) at %v: %v between two, want srtt %v to 1 ms more", sw, after, g, srtt)
			}
		}
		// The proof: the newest PING's PONG in a jumped datagram.
		p.send(dgramFrame(9999, 100), pingFrame(wire.TypePong, newest))
		synctest.Wait()
		if got := fjDelivered(s.ep); !slices.Equal(got, []uint64{9999}) {
			t.Fatalf("delivered %v, want [9999]: the PONG to the newest PING did not prove the jump", got)
		}
		if d := s.c.Stats().Dropped - d0; d != uint64(drops) {
			t.Fatalf("dropped %d frames of %d foreign and unproven jumped DGRAMs", d, drops)
		}
		if dead, cause, detail, _ := s.c.Death(); dead {
			t.Fatalf("carrier died: %v %q", cause, detail)
		}
	})
}
