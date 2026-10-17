package l4

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// M6 WP6 (m6-design §A5.4, §A8.3–§A8.5, §A12, §A16.1): the opening stage,
// the open bound, holds and the reopen rate limit, the expiry race, the
// stop, many flows, and a reader that never blocks.

// pwDefaultGrace is the kit's override that restores the default
// NoPathGrace (15 s; the kit's is 5 s), so that an open waits for the
// passive's answer (AcceptTimeout 10 s) or the ingress's 12-s bound
// instead of ending ErrNoPath first.
func pwDefaultGrace(ov *testhooks.Overrides) { ov.NoPathGrace = 15 * time.Second }

// pwWaitFor polls cond every millisecond (virtual), each poll after every
// other goroutine of the bubble settled, for at most d; it returns the
// time it took and whether cond held.
func pwWaitFor(d time.Duration, cond func() bool) (time.Duration, bool) {
	start := time.Now()
	for {
		synctest.Wait()
		if cond() {
			return time.Since(start), true
		}
		if time.Since(start) >= d {
			return time.Since(start), false
		}
		time.Sleep(time.Millisecond)
	}
}

// TestPortForwardOpenBound (M6-D27, R1-3): an open stuck at the passive
// (its OPEN pending there, AcceptTimeout 30 s) is withdrawn by the ingress
// at exactly 12 s — Failed, LastErr context.DeadlineExceeded, the source
// held — while one that the passive answers CAPACITY at its default
// AcceptTimeout (10 s, a passive that never accepts packet sessions) is
// seen as ErrCapacity, inside the bound.
func TestPortForwardOpenBound(t *testing.T) {
	t.Run("stuck", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			never := make(chan struct{})
			w := newPWWorld(t, pwOpts{pf: pfOpts{ov: pwDefaultGrace}, acceptTimeout: 30 * time.Second,
				gate: func(int, Request) <-chan struct{} { return never }})
			w.serve()
			pfSend(t, w.client(), pwTagged(30, 0xC0, 0))
			took, ok := pwWaitFor(20*time.Second, func() bool { return pwStatus(w.pf).Failed == 1 })
			st := pwStatus(w.pf)
			if !ok || took != ingressOpenBound || !errors.Is(st.LastErr, context.DeadlineExceeded) || st.Held != 1 {
				t.Fatalf("the stuck open failed after %v (%v): %s; want at %v with context.DeadlineExceeded, held", took, ok, pwDescribe(st), ingressOpenBound)
			}
			close(never)
		})
	})
	t.Run("capacity", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := newPWWorld(t, pwOpts{pf: pfOpts{ov: pwDefaultGrace}, noAccept: true})
			w.serve()
			pfSend(t, w.client(), pwTagged(30, 0xC1, 0))
			took, ok := pwWaitFor(20*time.Second, func() bool { return pwStatus(w.pf).Failed == 1 })
			st := pwStatus(w.pf)
			if !ok || took < 10*time.Second || took > 10*time.Second+2*pfOneWay || !errors.Is(st.LastErr, rendr.ErrCapacity) || st.Held != 1 {
				t.Fatalf("the open failed after %v (%v): %s; want ErrCapacity at the passive's AcceptTimeout (10 s), held", took, ok, pwDescribe(st))
			}
		})
	})
}

// TestPortForwardReopenHold_L58 (M6-D28, R1-2; L58, L73): a flow whose
// passive end fails 1 s after its open (a fatal error of its egress conn:
// the passive closes the session, the ingress reads io.EOF) holds its
// source for 5 s: a client retransmitting every 200 ms for 20 s costs one
// OPEN per hold cycle (≈ 6 s: at most 4), not one per datagram; the
// datagrams of the hold are DropHeld.
func TestPortForwardReopenHold_L58(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newPWWorld(t, pwOpts{target: func(fl *pwFlow) {
			buf := make([]byte, 64<<10)
			if _, err := fl.app.Read(buf); err != nil {
				return
			}
			time.Sleep(time.Second)
			fl.local.Inject(errors.New("egress socket broke"), true) // not an Errno: fatal
			for {
				if _, err := fl.app.Read(buf); err != nil {
					return
				}
			}
		}})
		w.serve()
		c := w.client()
		start := time.Now()
		maxHeld := 0
		for time.Since(start) < 20*time.Second {
			pfSend(t, c, pwTagged(30, 0xC2, 0))
			time.Sleep(200 * time.Millisecond)
			maxHeld = max(maxHeld, pwStatus(w.pf).Held)
		}
		opens, _, _, flows := w.pas.snapshot()
		st := pwStatus(w.pf)
		t.Logf("%d OPENs in 20 s; %s", opens, pwDescribe(st))
		if opens < 3 || opens > 4 || maxHeld != 1 || st.DropHeld == 0 || st.Ended.PeerClosed < uint64(opens-1) {
			t.Fatalf("%d OPENs, held %d at most: %s; want one OPEN per 5-s hold after each early end", opens, maxHeld, pwDescribe(st))
		}
		for _, fl := range flows[:opens-1] {
			if r := <-fl.res; r.LocalErr == nil {
				t.Fatalf("a passive forward ended without its local error: %+v", r)
			}
		}
	})
}

// TestPortForwardOpenSpansCarrierDeath (R1-3; verification 20): an OPEN
// sent on the live trunk just before that carrier is killed is lost with
// it; the core's failover and the OPEN's retransmission complete the open
// inside the 12-s bound, the flow opens without a hold (no failure), the
// first datagram that rode the OPEN reaches the target exactly once, and
// the flow carries the next datagram.
func TestPortForwardOpenSpansCarrierDeath(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newPWWorld(t, pwOpts{pf: pfOpts{links: 2}})
		w.serve()
		if !pwRoundTrip(t, w.client(), pwTagged(30, 0xC3, 0), 5*time.Second) {
			t.Fatal("warm-up flow did not open")
		}
		time.Sleep(2 * time.Second)
		var live *rendrtest.DatagramLink // the link of the warm flow's trunk: the newcomer's OPEN rides it
		for _, fi := range w.pf.Flows() {
			for _, cs := range fi.Session.Carriers {
				if cs.DeathCause == 0 {
					live = w.links[cs.Name[1]-'a']
				}
			}
		}
		if live == nil {
			t.Fatal("kit: no live carrier")
		}
		c := w.client()
		start := time.Now()
		pfSend(t, c, pwTagged(30, 0xC4, 0))
		synctest.Wait()                    // the OPEN is on its way on the live trunk
		live.Blackhole(rendrtest.Up, true) // the OPEN in flight is lost; the carrier dies silently
		live.Blackhole(rendrtest.Down, true)
		_, ok := pwWaitFor(ingressOpenBound, func() bool { return pwStatus(w.pf).Opened == 2 })
		took := time.Since(start)
		st := pwStatus(w.pf)
		t.Logf("opened %v after the first datagram; %s", took, pwDescribe(st))
		if !ok || took < time.Second || took > ingressOpenBound || st.Failed != 0 || st.Held != 0 {
			t.Fatalf("the open across the carrier death: after %v (%v), %s", time.Since(start), ok, pwDescribe(st))
		}
		fl := w.pas.flowOf(0xC4)
		if fl == nil || fl.rxCount.Load() != 1 {
			t.Fatalf("the first datagram reached the target %v times, want once", fl)
		}
		pfExpect(t, c, pwTagged(30, 0xC4, 0)) // its echo
		if !pwRoundTrip(t, c, pwTagged(30, 0xC4, 1), time.Second) {
			t.Fatal("the flow does not carry its next datagram")
		}
	})
}

// TestPortForwardOpeningBound_L48 (M6-D27; L48): while the passive holds
// every OPEN pending, 300 new clients put exactly 256 flows into the
// opening stage (256 flow goroutines in DialUDP) and the other 44
// datagrams are DropOpening; once the passive confirms, every open
// completes, and the refused clients' next datagrams open their flows.
func TestPortForwardOpeningBound_L48(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate := make(chan struct{})
		w := newPWWorld(t, pwOpts{gate: func(int, Request) <-chan struct{} { return gate }})
		w.serve()
		cs := pwClients(w, 300)
		for i, c := range cs {
			pfSend(t, c, pwTagged(30, 0xC5, i))
		}
		time.Sleep(2 * time.Second)
		st := pwStatus(w.pf)
		if st.Opening != ingressOpeningMax || st.DropOpening != 300-ingressOpeningMax || pwFlowGoroutines() != ingressOpeningMax || st.Opened != 0 {
			t.Fatalf("during the stall: %s, %d flow goroutines", pwDescribe(st), pwFlowGoroutines())
		}
		close(gate)
		if _, ok := pwWaitFor(5*time.Second, func() bool { return pwStatus(w.pf).Opened == ingressOpeningMax }); !ok {
			t.Fatalf("after the stall: %s", pwDescribe(pwStatus(w.pf)))
		}
		for i, c := range cs {
			pfSend(t, c, pwTagged(30, 0xC5, 1000+i))
		}
		if _, ok := pwWaitFor(5*time.Second, func() bool { return pwStatus(w.pf).Flows == 300 }); !ok {
			t.Fatalf("after the retries: %s", pwDescribe(pwStatus(w.pf)))
		}
		pwUnits(t, w.pf)
	})
}

// TestPortForwardRefusedHold_L48_L72 (M6-D28; L48, L72): against a
// refusing passive (every OPEN refused CodeNotAllowed), 10 clients that
// retransmit every 100 ms for 30 s (15 s in the race lane) cause at most
// ⌈30 s / 5 s⌉ = 6 OPENs (3) each while the table has room; LastErr is the *RejectError and ByCode
// counts every failure. With more retransmitting clients than MaxFlows
// (10 against 4), the holds never exceed the table: Held ≤ MaxFlows at
// every step.
func TestPortForwardRefusedHold_L48_L72(t *testing.T) {
	refuse := func(counts *[16]atomic.Int64) func(int, Request) RejectCode {
		return func(_ int, r Request) RejectCode {
			counts[tagOf(r.First)%16].Add(1)
			return CodeNotAllowed
		}
	}
	t.Run("room", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var counts [16]atomic.Int64
			w := newPWWorld(t, pwOpts{decide: refuse(&counts)})
			w.serve()
			cs := pwClients(w, 10)
			period, most := 30*time.Second, int64(6)
			if raceEnabled {
				period, most = 15*time.Second, 3
			}
			for start := time.Now(); time.Since(start) < period; {
				for i, c := range cs {
					pfSend(t, c, pwTagged(30, byte(i), 0))
				}
				time.Sleep(100 * time.Millisecond)
			}
			for i := range cs {
				if n := counts[i].Load(); n < most-1 || n > most {
					t.Fatalf("client %d caused %d OPENs in %v, want at most %d (one per 5-s hold)", i, n, period, most)
				}
			}
			st := pwStatus(w.pf)
			var re *rendr.RejectError
			if !errors.As(st.LastErr, &re) || re.Code != uint32(CodeNotAllowed) || st.ByCode[CodeNotAllowed] != st.Failed || st.Opened != 0 {
				t.Fatalf("status %s", pwDescribe(st))
			}
		})
	})
	t.Run("bounded", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var counts [16]atomic.Int64
			w := newPWWorld(t, pwOpts{decide: refuse(&counts), pfwd: func(f *PortForward) { f.MaxFlows = 4 }})
			w.serve()
			cs := pwClients(w, 10)
			maxHeld := 0
			period := 30 * time.Second
			if raceEnabled {
				period = 10 * time.Second
			}
			for start := time.Now(); time.Since(start) < period; {
				for i, c := range cs {
					pfSend(t, c, pwTagged(30, byte(i), 0))
				}
				time.Sleep(100 * time.Millisecond)
				if n, _ := pwEntries(w.pf); n > 4 {
					t.Fatalf("%d entries in a table of 4", n)
				}
				maxHeld = max(maxHeld, pwStatus(w.pf).Held)
				if g := pwFlowGoroutines(); g > 4 {
					t.Fatalf("%d flow goroutines for a table of 4", g)
				}
			}
			if maxHeld != 4 {
				t.Fatalf("held at most %d, want the table full of holds (4)", maxHeld)
			}
			pwUnits(t, w.pf)
		})
	})
}

// pwEnding wraps a flow's session: once end is called, WriteTo returns
// rendr.ErrIdleTimeout at once (the session's end as the reader sees it)
// while ReadFrom keeps waiting until release closes the real session, and
// then returns ErrIdleTimeout too: the expiry race of §A5.4 held open.
type pwEnding struct {
	ingressSession
	ended atomic.Bool
}

func (s *pwEnding) WriteTo(b []byte, a net.Addr) (int, error) {
	if s.ended.Load() {
		return 0, rendr.ErrIdleTimeout
	}
	return s.ingressSession.WriteTo(b, a)
}

func (s *pwEnding) ReadFrom(b []byte) (int, net.Addr, error) {
	n, a, err := s.ingressSession.ReadFrom(b)
	if err != nil && s.ended.Load() {
		return 0, nil, rendr.ErrIdleTimeout
	}
	return n, a, err
}

// TestPortForwardIdleRace_L39 (M6-D13, R1-19, §A5.4; L39, L40): a datagram
// at the instant its flow's session ends never vanishes. 100 flows with a
// 10-s idle limit get a datagram at the expiry instant (calibrated), 1 ms
// before and 1 ms after it: each is delivered — to the old session or to a
// new flow that replaced the entry (Replaced) or was opened for it — or
// counted (the ended sessions' drops at either end, the ingress's drop
// counters): delivered + counted = sent, and the MaxFlows units equal the
// table's entries. Held open by a wrapped session (its WriteTo reports the
// end before its goroutine sees it): the replacement carries the datagram
// to the new flow's target; with the opening stage full the entry goes,
// its unit is released and the datagram is DropOpening.
func TestPortForwardIdleRace_L39(t *testing.T) {
	idle := func(f *PortForward) { f.Idle = FlowIdle{Short: 10 * time.Second, Stream: 10 * time.Second} }
	t.Run("expiry instant", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := newPWWorld(t, pwOpts{target: pwSink, pfwd: idle})
			w.serve()
			// Calibration: the end of a flow whose last datagram crossed at t1.
			cal := w.client()
			pfSend(t, cal, pwTagged(30, 0xD0, 0))
			time.Sleep(time.Second)
			pfSend(t, cal, pwTagged(30, 0xD0, 1))
			lifetime, ok := pwWaitFor(30*time.Second, func() bool { return pwStatus(w.pf).Ended.Idle == 1 })
			if !ok {
				t.Fatal("calibration: the flow did not end")
			}
			t.Logf("calibration: the flow ends %v after its last datagram", lifetime)
			const n = 100
			cs := pwClients(w, n)
			for i, c := range cs {
				pfSend(t, c, pwTagged(30, byte(i), 0))
			}
			time.Sleep(time.Second)
			for i, c := range cs {
				pfSend(t, c, pwTagged(30, byte(i), 1))
			}
			start := time.Now()
			for _, d := range []time.Duration{-time.Millisecond, 0, time.Millisecond} {
				time.Sleep(time.Until(start.Add(lifetime + d)))
				for i, c := range cs {
					if (i%3)-1 == int(d/time.Millisecond) {
						pfSend(t, c, pwTagged(30, byte(i), 2))
					}
				}
			}
			time.Sleep(2 * time.Second)
			pwUnits(t, w.pf)
			w.stop()
			synctest.Wait()
			_, _, _, flows := w.pas.snapshot()
			var delivered, passiveDrops uint64
			for _, fl := range flows {
				if tagOf(fl.received()[0]) == 0xD0 {
					continue
				}
				<-fl.res
				delivered += uint64(fl.rxCount.Load())
				passiveDrops += sessionDrops(fl.pc.Status().Packet)
			}
			st := pwStatus(w.pf)
			counted := st.SessionDrops + passiveDrops + st.DropFull + st.DropOpening + st.DropOpenQueue + st.DropOpenAge + st.DropHeld + st.TooLarge
			t.Logf("sent %d, delivered %d, counted %d (ingress session drops %d, passive %d); %s", 3*n, delivered, counted, st.SessionDrops, passiveDrops, pwDescribe(st))
			if delivered+counted != 3*n {
				t.Fatalf("delivered %d + counted %d != sent %d", delivered, counted, 3*n)
			}
			if st.Ended.Idle < n/3+1 {
				t.Fatalf("stimulus: %d idle ends, want at least the flows of the late datagrams (and the calibration's) to have expired", st.Ended.Idle)
			}
		})
	})
	t.Run("held open", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var mu sync.Mutex
			sessions := map[byte]*pwEnding{}
			pwDialHook(t, func(first []byte, s ingressSession) ingressSession {
				e := &pwEnding{ingressSession: s}
				mu.Lock()
				sessions[tagOf(first)] = e
				mu.Unlock()
				return e
			})
			gate := make(chan struct{})
			w := newPWWorld(t, pwOpts{target: pwSink, pfwd: idle, gate: func(_ int, r Request) <-chan struct{} {
				if tagOf(r.First) == 0xD3 {
					return gate
				}
				return nil
			}})
			w.serve()
			a, b := w.client(), w.client()
			pfSend(t, a, pwTagged(30, 0xD1, 0))
			pfSend(t, b, pwTagged(30, 0xD2, 0))
			time.Sleep(100 * time.Millisecond)
			mu.Lock()
			sa, sb := sessions[0xD1], sessions[0xD2]
			mu.Unlock()
			// With room: the datagram that met the end opens a new flow.
			sa.ended.Store(true)
			pfSend(t, a, pwTagged(30, 0xD1, 1))
			time.Sleep(100 * time.Millisecond)
			st := pwStatus(w.pf)
			if st.Replaced != 1 || st.Opened != 3 || pwFlowsTagged(w.pas, 0xD1) != 2 {
				t.Fatalf("with room: %s, %d sessions of a", pwDescribe(st), pwFlowsTagged(w.pas, 0xD1))
			}
			var replacement *pwFlow
			_, _, _, flows := w.pas.snapshot()
			for _, fl := range flows[2:] {
				if rx := fl.received(); len(rx) == 1 && tagOf(rx[0]) == 0xD1 && pwSeq(rx[0]) == 1 {
					replacement = fl
				}
			}
			if replacement == nil {
				t.Fatal("the datagram that met the end did not reach the new flow's target")
			}
			sa.ingressSession.Close() // the old flow's goroutine reads the end
			// The opening stage full: the entry goes and its unit with it.
			for i := range ingressOpeningMax {
				pfSend(t, w.client(), pwTagged(30, 0xD3, i))
			}
			time.Sleep(100 * time.Millisecond)
			if st := pwStatus(w.pf); st.Opening != ingressOpeningMax {
				t.Fatalf("the opening stage: %s", pwDescribe(st))
			}
			sb.ended.Store(true)
			pfSend(t, b, pwTagged(30, 0xD2, 1))
			synctest.Wait()
			st = pwStatus(w.pf)
			if st.DropOpening != 1 || st.Replaced != 1 {
				t.Fatalf("with the opening stage full: %s", pwDescribe(st))
			}
			if _, ok := pwSnapshot(w.pf)[pwAddr(b)]; ok {
				t.Fatal("the entry stayed in the table")
			}
			pwUnits(t, w.pf)
			sb.ingressSession.Close()
			close(gate)
			if _, ok := pwWaitFor(5*time.Second, func() bool { return pwStatus(w.pf).Opening == 0 }); !ok {
				t.Fatalf("after the gate: %s", pwDescribe(pwStatus(w.pf)))
			}
			pwUnits(t, w.pf)
			if st := pwStatus(w.pf); st.Ended.Idle != 2 {
				t.Fatalf("the two old flows' ends: %+v", st.Ended)
			}
		})
	})
}

// TestPortForwardStopJoins_L52_L66 (M6-D21, A8.1, §A5.4; L52, L66): ctx
// cancelled with 500 flows, 100 of them opening (their OPENs held at the
// passive): ServeUDP returns within 2 s, after every flow ended — every
// open flow's session closed (each passive forward reads io.EOF), every
// open withdrawn (no pending session left at the passive), no flow
// goroutine, no MaxFlows unit, no gauge — and the socket closed exactly
// once. In real time, the same with 50 flows, 10 opening, and
// rendrtest.AssertNoLeak after the world closed (the non-race lanes;
// racebudget).
func TestPortForwardStopJoins_L52_L66(t *testing.T) {
	run := func(t *testing.T, n, gated int) {
		gate := make(chan struct{})
		var pending atomic.Int64
		w := newPWWorld(t, pwOpts{
			wrap: func(s UDPSocket) UDPSocket { return &pwCountSock{UDPSocket: s} },
			gate: func(_ int, r Request) <-chan struct{} {
				if pwSeq(r.First) >= n-gated {
					pending.Add(1)
					return gate
				}
				return nil
			}})
		w.serve()
		cs := pwClients(w, n)
		for i, c := range cs {
			pfSend(t, c, pwTagged(30, byte(i), i))
			if i%50 == 49 {
				time.Sleep(50 * time.Millisecond)
			}
		}
		end := time.Now().Add(20 * time.Second)
		for st := pwStatus(w.pf); st.Flows != n-gated || st.Opening != gated || pending.Load() != int64(gated); st = pwStatus(w.pf) {
			if time.Now().After(end) {
				t.Fatalf("before the stop: %s, %d pending", pwDescribe(st), pending.Load())
			}
			time.Sleep(10 * time.Millisecond)
		}
		start := time.Now()
		err := w.stop()
		took := time.Since(start)
		cs0 := w.sock.(*pwCountSock)
		st := pwStatus(w.pf)
		t.Logf("ServeUDP returned %v after %v; %s", err, took, pwDescribe(st))
		if !errors.Is(err, context.Canceled) || took > 2*time.Second || cs0.closes.Load() != 1 {
			t.Fatalf("ServeUDP = %v after %v, socket closed %d times", err, took, cs0.closes.Load())
		}
		if st.Flows != 0 || st.Opening != 0 || st.Held != 0 || w.pf.flows.Load() != 0 || w.pf.opening.Load() != 0 || st.Ended.Stopped != uint64(n-gated) {
			t.Fatalf("after the stop: %s, units %d", pwDescribe(st), w.pf.flows.Load())
		}
		if g := pwFlowGoroutines(); g != 0 {
			t.Fatalf("%d flow goroutines after ServeUDP returned", g)
		}
		_, _, _, flows := w.pas.snapshot()
		for _, fl := range flows {
			select {
			case <-fl.res:
			case <-time.After(10 * time.Second):
				t.Fatalf("a passive forward still runs after the stop: %+v", fl.pc.Status())
			}
		}
		close(gate)
		w.close()
	}
	t.Run("synctest", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) { run(t, 500, 100) })
	})
	if raceEnabled {
		return // racebudget: the bubble's own join check stands for the real-time row there
	}
	t.Run("real time", func(t *testing.T) {
		check := rendrtest.AssertNoLeak(t)
		run(t, 50, 10)
		check()
	})
}

// TestPortForwardManyFlowsAcrossTrunks (§A12; L54): 1,000 flows (200 in
// the race lane) on one datagram factory: the dialer spreads them over at
// least ⌈flows / 64⌉ datagram trunks (64 sessions each), every flow opens,
// and every datagram is delivered both ways — none lost outside a
// counter (every counter is 0).
func TestPortForwardManyFlowsAcrossTrunks(t *testing.T) {
	n := 1000
	if raceEnabled {
		n = 200
	}
	synctest.Test(t, func(t *testing.T) {
		w := newPWWorld(t, pwOpts{})
		w.serve()
		cs := pwClients(w, n)
		for round := range 2 {
			for i, c := range cs {
				pfSend(t, c, pwTagged(30+i%100, byte(i), round))
				time.Sleep(2 * time.Millisecond)
			}
			for i, c := range cs {
				pfExpect(t, c, pwTagged(30+i%100, byte(i), round))
			}
		}
		st := pwStatus(w.pf)
		carriers := w.links[0].Stats().Carriers
		t.Logf("%d flows over %d carriers; %s", n, carriers, pwDescribe(st))
		if want := (n + 63) / 64; carriers < want {
			t.Fatalf("%d carriers for %d flows, want at least %d trunks", carriers, n, want)
		}
		if st.Opened != uint64(n) || st.ToSession != uint64(2*n) || st.ToClient != uint64(2*n) || st.DropFull+st.DropOpening+st.DropOpenQueue+st.DropOpenAge+st.DropHeld+st.TooLarge != 0 {
			t.Fatalf("status %s", pwDescribe(st))
		}
	})
}

// pwBlocking wraps a flow's session: while block is set, WriteTo waits
// until it is cleared (a fake that would hold whoever calls it).
type pwBlocking struct {
	ingressSession
	mu      sync.Mutex
	cond    *sync.Cond
	block   bool
	waiting int
}

func newPWBlocking(s ingressSession) *pwBlocking {
	b := &pwBlocking{ingressSession: s}
	b.cond = sync.NewCond(&b.mu)
	return b
}

func (s *pwBlocking) WriteTo(p []byte, a net.Addr) (int, error) {
	s.mu.Lock()
	for s.block {
		s.waiting++
		s.cond.Wait()
		s.waiting--
	}
	s.mu.Unlock()
	return s.ingressSession.WriteTo(p, a)
}

func (s *pwBlocking) set(on bool) {
	s.mu.Lock()
	s.block = on
	s.cond.Broadcast()
	s.mu.Unlock()
}

func (s *pwBlocking) blocked() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.waiting
}

// TestPortForwardNeverBlocks_L40 (M6-D26, R1-13; L40): one client whose
// socket never takes its replies (writes to it block) while its target
// floods it, so its session's receive queue fills and drops (counted):
// the reader keeps serving 10 other flows at their rate, every datagram of
// theirs crossing both ways. And the table's lock is never held across a
// call into the session: with a session whose WriteTo blocks (a fake in
// the dial hook), Flows returns while the reader waits in that WriteTo;
// while a flow's open-queue flush waits in it, the reader serves another
// flow and Flows returns.
func TestPortForwardNeverBlocks_L40(t *testing.T) {
	t.Run("client never reads", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := newPWWorld(t, pwOpts{
				pf:   pfOpts{dcfg: rendr.Config{Packet: rendr.PacketPolicy{Queue: 64 << 10}}}, // the dialer's receive queue: 64 KiB
				wrap: func(s UDPSocket) UDPSocket { return &pwCountSock{UDPSocket: s} },
				target: func(fl *pwFlow) {
					if tagOf(fl.req.First) == 0xE0 {
						for k := range 300 { // beyond the dialer's 64-KiB receive queue, well within the link's
							fl.app.Write(pwTagged(1000, 0xE0, k))
						}
					}
					pwEcho(fl)
				}})
			w.serve()
			slow := w.client()
			cs := w.sock.(*pwCountSock)
			release := cs.blockWrites(pwAddr(slow))
			pfSend(t, slow, pwTagged(30, 0xE0, 0))
			others := pwClients(w, 10)
			for k := range 50 {
				for i, c := range others {
					pfSend(t, c, pwTagged(30, byte(i), k))
				}
				time.Sleep(20 * time.Millisecond)
				for i, c := range others {
					pfExpect(t, c, pwTagged(30, byte(i), k))
				}
			}
			var slowSession *pwFlow
			_, _, _, flows := w.pas.snapshot()
			for _, fl := range flows {
				if tagOf(fl.req.First) == 0xE0 {
					slowSession = fl
				}
			}
			var drops uint64
			for _, fi := range w.pf.Flows() {
				if fi.Client == pwAddr(slow) && fi.Session.Packet != nil {
					drops = fi.Session.Packet.DropRecvQueue
				}
			}
			if cs.blockedWrites() != 1 || slowSession == nil || drops == 0 {
				t.Fatalf("stimulus: %d blocked writes to the slow client, its session's receive drops %d", cs.blockedWrites(), drops)
			}
			release()
		})
	})
	t.Run("lock never held", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var mu sync.Mutex
			var sessions []*pwBlocking
			var blockNext atomic.Bool
			pwDialHook(t, func(_ []byte, s ingressSession) ingressSession {
				b := newPWBlocking(s)
				b.block = blockNext.Load()
				mu.Lock()
				sessions = append(sessions, b)
				mu.Unlock()
				return b
			})
			gate := make(chan struct{})
			w := newPWWorld(t, pwOpts{gate: func(_ int, r Request) <-chan struct{} {
				if tagOf(r.First) == 0xE3 {
					return gate
				}
				return nil
			}})
			w.serve()
			a, other := w.client(), w.client()
			if !pwRoundTrip(t, a, pwTagged(30, 0xE1, 0), time.Second) || !pwRoundTrip(t, other, pwTagged(30, 0xE2, 0), time.Second) {
				t.Fatal("the flows did not open")
			}
			mu.Lock()
			sa := sessions[0]
			mu.Unlock()
			// flowsReturn checks that every table lock is free (TryLock: a
			// goroutine waiting for a sync.Mutex is not durably blocked, so a
			// held lock would hang the bubble instead of failing the row) and
			// that Flows then returns. On a failure it first releases the
			// blocking sessions, so the row ends instead of hanging.
			flowsReturn := func(what string, release ...*pwBlocking) {
				t.Helper()
				w.pf.mu.Lock()
				for s := range w.pf.serves {
					if !s.tab.mu.TryLock() {
						w.pf.mu.Unlock()
						for _, b := range release {
							b.set(false)
						}
						t.Fatalf("%s: the table's lock is held", what)
					}
					s.tab.mu.Unlock()
				}
				w.pf.mu.Unlock()
				if fs := w.pf.Flows(); len(fs) == 0 {
					t.Fatalf("%s: Flows lists nothing", what)
				}
			}
			// The reader waits in a's WriteTo.
			sa.set(true)
			pfSend(t, a, pwTagged(30, 0xE1, 1))
			synctest.Wait()
			if sa.blocked() != 1 {
				t.Fatal("stimulus: the reader is not in the blocking WriteTo")
			}
			flowsReturn("the reader in WriteTo", sa)
			sa.set(false)
			pfExpect(t, a, pwTagged(30, 0xE1, 1))
			// A flush waits in WriteTo: c's OPEN is held, its datagrams queue,
			// and its session blocks from the start.
			c := w.client()
			pfSend(t, c, pwTagged(30, 0xE3, 0))
			pfSend(t, c, pwTagged(30, 0xE3, 1))
			pfSend(t, c, pwTagged(30, 0xE3, 2))
			synctest.Wait()
			blockNext.Store(true) // c's session, made once its OPEN is answered
			close(gate)
			time.Sleep(100 * time.Millisecond)
			mu.Lock()
			sc := sessions[len(sessions)-1]
			mu.Unlock()
			if sc.blocked() != 1 {
				t.Fatal("stimulus: the flush is not in the blocking WriteTo")
			}
			flowsReturn("a flush in WriteTo", sc)
			if !pwRoundTrip(t, other, pwTagged(30, 0xE2, 1), time.Second) {
				t.Fatal("the reader stopped serving another flow during a flush")
			}
			sc.set(false)
			for k := range 3 {
				pfExpect(t, c, pwTagged(30, 0xE3, k)) // the flush's order kept
			}
		})
	})
}

// TestPortForwardPeerClosedStops (A8.1): ServeUDP returns net.ErrClosed
// once the Peer is closed (a new client's DialUDP returns net.ErrClosed)
// or the dialer's Runtime is (its sessions end net.ErrClosed, and the next
// open does too): every flow ended (Stopped), no flow goroutine, no unit,
// the socket closed exactly once; nothing is counted Failed.
func TestPortForwardPeerClosedStops(t *testing.T) {
	for _, r := range []struct {
		name  string
		close func(w *pwWorld)
	}{
		{"peer", func(w *pwWorld) { w.peer.Close() }},
		{"runtime", func(w *pwWorld) { w.d.Close() }},
	} {
		t.Run(r.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newPWWorld(t, pwOpts{wrap: func(s UDPSocket) UDPSocket { return &pwCountSock{UDPSocket: s} }})
				w.serve()
				for _, c := range pwClients(w, 3) {
					if !pwRoundTrip(t, c, pwTagged(30, 0xE8, 0), time.Second) {
						t.Fatal("a flow did not open")
					}
				}
				r.close(w)
				synctest.Wait()
				pfSend(t, w.client(), pwTagged(30, 0xE9, 0))
				var err error
				select {
				case err = <-w.served:
					w.served = nil
				case <-time.After(5 * time.Second):
					t.Fatalf("ServeUDP did not return: %s", pwDescribe(pwStatus(w.pf)))
				}
				cs := w.sock.(*pwCountSock)
				st := pwStatus(w.pf)
				if !errors.Is(err, net.ErrClosed) || cs.closes.Load() != 1 || st.Flows+st.Opening+st.Held != 0 || w.pf.flows.Load() != 0 || st.Failed != 0 || pwFlowGoroutines() != 0 {
					t.Fatalf("ServeUDP = %v, %d Closes; %s", err, cs.closes.Load(), pwDescribe(st))
				}
				if st.Ended.Stopped != 3 {
					t.Fatalf("the open flows' ends: %+v, want 3 Stopped", st.Ended)
				}
			})
		})
	}
}
