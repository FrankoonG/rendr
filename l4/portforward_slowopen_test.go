package l4

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestPortForwardSlowOpenNotIdle_L48_L72 (M6-D27, M6-D29; L48, L72): a
// client's datagrams that wait for a slow open count as its activity. O-1
// (a), MaxFlows 1, a silent target: the passive holds flow a's OPEN 1.7 s;
// a sends at 0 (it rides the OPEN) and at 1.5 s (queued). While opening and
// once open, FlowInfo.Last is the 1.5-s datagram, and the target receives
// both. A newcomer 250 ms after a's latest datagram finds no victim idle
// for 1 s (DropFull, nothing evicted), and so does its next datagram 1 s
// after that datagram, a's open then 0.8 s old (the floor counts from the
// later of the two, CP2); once a has been idle for 1 s since its open, the
// newcomer's next datagram evicts it.
//
// The held part: a refused client's datagram dropped during its hold moves
// its FlowInfo.Last too.
func TestPortForwardSlowOpenNotIdle_L48_L72(t *testing.T) {
	t.Run("opening", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			pfRule(t, promoteActive)
			gate := make(chan struct{})
			w := newPWWorld(t, pwOpts{target: pwSink,
				gate: func(n int, _ Request) <-chan struct{} {
					if n == 0 {
						return gate
					}
					return nil
				},
				pfwd: func(f *PortForward) { f.MaxFlows = 1 }})
			w.serve()
			a := w.client()
			pfSend(t, a, pwTagged(30, 0xA1, 0)) // rides the OPEN, held at the passive
			time.Sleep(1500 * time.Millisecond)
			t1 := time.Now()
			pfSend(t, a, pwTagged(30, 0xA1, 1)) // waits in the opening queue
			synctest.Wait()
			if fi := pwSnapshot(w.pf)[pwAddr(a)]; fi.State != FlowOpening || fi.Last.Before(t1) {
				t.Fatalf("while opening: %+v; want FlowOpening, Last at its 1.5-s datagram (%v)", fi, t1)
			}
			time.Sleep(200 * time.Millisecond)
			gated := time.Now()
			close(gate) // the open completes at 1.7 s (within the next 50 ms)
			time.Sleep(50 * time.Millisecond)
			fl := w.pas.flowOf(0xA1)
			if fl == nil || fl.rxCount.Load() != 2 {
				t.Fatalf("stimulus: the target must receive both of a's datagrams (%s)", pwDescribe(pwStatus(w.pf)))
			}
			fi := pwSnapshot(w.pf)[pwAddr(a)]
			if fi.State != FlowOpen || fi.Stream || fi.Last.Before(t1) {
				t.Fatalf("once open: %+v; want FlowOpen, not a stream, Last at its 1.5-s datagram (%v)", fi, t1)
			}
			b := w.client()
			pfSend(t, b, pwTagged(30, 0xB1, 0)) // a idle 250 ms
			synctest.Wait()
			time.Sleep(100 * time.Millisecond)
			if st := pwStatus(w.pf); st.DropFull != 1 || st.Evicted != 0 || st.Ended.Evicted != 0 || st.Opened != 1 {
				t.Fatalf("a newcomer 250 ms after a's latest datagram: %s; want DropFull 1, nothing evicted", pwDescribe(st))
			}
			time.Sleep(time.Until(t1.Add(ingressEvictIdle + 10*time.Millisecond)))
			pfSend(t, b, pwTagged(30, 0xB1, 1)) // a's latest datagram 1 s old, its open 0.8 s
			synctest.Wait()
			time.Sleep(100 * time.Millisecond)
			if st := pwStatus(w.pf); st.DropFull != 2 || st.Evicted != 0 || st.Ended.Evicted != 0 || st.Opened != 1 {
				t.Fatalf("a newcomer 1 s after a's latest datagram, 0.8 s after its open: %s; want DropFull 2, nothing evicted", pwDescribe(st))
			}
			time.Sleep(time.Until(gated.Add(50*time.Millisecond + ingressEvictIdle + 10*time.Millisecond)))
			pfSend(t, b, pwTagged(30, 0xB1, 2)) // a idle 1 s since its open
			synctest.Wait()
			time.Sleep(100 * time.Millisecond)
			st := pwStatus(w.pf)
			if st.Evicted != 1 || st.Ended.Evicted != 1 || st.DropFull != 2 || pwSnapshot(w.pf)[pwAddr(b)].State != FlowOpen {
				t.Fatalf("control: a newcomer once a was idle 1 s since its open: %s; want a evicted, b open", pwDescribe(st))
			}
			pwUnits(t, w.pf)
		})
	})
	t.Run("held", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := newPWWorld(t, pwOpts{decide: func(int, Request) RejectCode { return CodeNotAllowed }})
			w.serve()
			c := w.client()
			pfSend(t, c, pwTagged(30, 0xC1, 0))
			time.Sleep(time.Second)
			t1 := time.Now()
			pfSend(t, c, pwTagged(30, 0xC1, 1)) // dropped: the client is held
			synctest.Wait()
			fi := pwSnapshot(w.pf)[pwAddr(c)]
			if st := pwStatus(w.pf); fi.State != FlowHeld || st.DropHeld != 2 || fi.Last.Before(t1) {
				t.Fatalf("held: %+v, %s; want FlowHeld, DropHeld 2, Last at its 1-s datagram (%v)", fi, pwDescribe(st), t1)
			}
		})
	})
}

// TestPortForwardEvictsNoSlowOpenedFlow (M6-D29, O-1 (a); L48, L72; CP2):
// a full table's victim floor (idle ≥ 1 s) and its least-recently-active
// order count from the later of a flow's last datagram and its open's
// completion, so a one-datagram flow whose Confirm was slow is not the
// oldest victim the instant it opens, while its target's reply is on its
// way. MaxFlows 2; the passive holds the slow flow x's OPEN (its one
// datagram rode it).
//
//   - reply in flight: an echo target 50 ms away (it answers each datagram
//     50 ms after it, as CP2's replies came 20–50 ms after the open); x
//     sends at 0 and is confirmed at 3 s; a short flow y sends one query at
//     0.5 s, answered. A newcomer right after x opens, x's reply not yet at
//     the ingress, evicts y (idle 2.4 s), not x (its datagram 3 s old), and
//     x's reply reaches x's client.
//   - order: a silent target; y sends at 0 and 3 s, x at 0.2 s (confirmed
//     at 3.5 s). A newcomer right after x opens finds no victim (x opened
//     an instant ago, y active 0.5 s ago): DropFull. Its next datagram
//     1.5 s after x's open evicts y (active 2 s ago), not x (opened 1.5 s
//     ago, its one datagram 4.8 s old).
func TestPortForwardEvictsNoSlowOpenedFlow(t *testing.T) {
	world := func(t *testing.T, target func(*pwFlow), slow byte, gate <-chan struct{}) *pwWorld {
		return newPWWorld(t, pwOpts{target: target,
			gate: func(_ int, r Request) <-chan struct{} {
				if tagOf(r.First) == slow {
					return gate
				}
				return nil
			},
			pfwd: func(f *PortForward) { f.MaxFlows = 2 }})
	}
	// opened waits (1-ms steps) until c's flow is open and returns when.
	opened := func(t *testing.T, w *pwWorld, c *rendrtest.DatagramConn) time.Time {
		t.Helper()
		if _, ok := pwWaitFor(5*time.Second, func() bool { return pwSnapshot(w.pf)[pwAddr(c)].State == FlowOpen }); !ok {
			t.Fatalf("stimulus: the slow flow did not open: %s", pwDescribe(pwStatus(w.pf)))
		}
		return time.Now()
	}
	t.Run("reply in flight", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			pfRule(t, promoteActive)
			gate := make(chan struct{})
			w := world(t, func(fl *pwFlow) {
				buf := make([]byte, 64<<10)
				for {
					n, err := fl.app.Read(buf)
					if err != nil {
						return
					}
					fl.record(buf[:n])
					time.Sleep(50 * time.Millisecond)
					fl.app.Write(buf[:n])
				}
			}, 0xA1, gate)
			w.serve()
			t0 := time.Now()
			x, y := w.client(), w.client()
			pfSend(t, x, pwTagged(30, 0xA1, 0)) // rides the OPEN, held at the passive
			time.Sleep(500 * time.Millisecond)
			pfSend(t, y, pwTagged(30, 0xB1, 0))
			pfExpect(t, y, pwTagged(30, 0xB1, 0)) // y: one query, answered (short)
			time.Sleep(time.Until(t0.Add(3 * time.Second)))
			close(gate) // x's Confirm, 3 s after its datagram
			at := opened(t, w, x)
			if st := pwStatus(w.pf); st.ToClient != 1 || st.Flows != 2 || st.Evicted != 0 {
				t.Fatalf("premise: x open, its reply still on its way: %s", pwDescribe(st))
			}
			ny := pwSnapshot(w.pf)[pwAddr(y)].Last
			pfSend(t, w.client(), pwTagged(30, 0xC1, 0)) // the newcomer
			synctest.Wait()
			tab, st := pwSnapshot(w.pf), pwStatus(w.pf)
			if fi, ok := tab[pwAddr(x)]; !ok || fi.State != FlowOpen {
				t.Fatalf("a newcomer %v after x opened evicted x (its one datagram 3 s old, its reply in flight): x %+v (in the table: %v), %s",
					time.Since(at), fi, ok, pwDescribe(st))
			}
			if _, ok := tab[pwAddr(y)]; ok || st.Evicted != 1 || st.Ended.Evicted != 1 || st.DropFull != 0 {
				t.Fatalf("want y (idle %v) evicted for the newcomer: %s", time.Since(ny), pwDescribe(st))
			}
			pfExpect(t, x, pwTagged(30, 0xA1, 0)) // x's reply delivered
			pwUnits(t, w.pf)
		})
	})
	t.Run("order", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			pfRule(t, promoteActive)
			gate := make(chan struct{})
			w := world(t, pwSink, 0xA2, gate)
			w.serve()
			t0 := time.Now()
			x, y := w.client(), w.client()
			pfSend(t, y, pwTagged(30, 0xB2, 0))
			time.Sleep(200 * time.Millisecond)
			pfSend(t, x, pwTagged(30, 0xA2, 0)) // rides the OPEN, held at the passive
			time.Sleep(time.Until(t0.Add(3 * time.Second)))
			pfSend(t, y, pwTagged(30, 0xB2, 1)) // y active at 3 s
			time.Sleep(500 * time.Millisecond)
			close(gate) // x's Confirm, 3.3 s after its datagram
			at := opened(t, w, x)
			n := w.client()
			pfSend(t, n, pwTagged(30, 0xC2, 0))
			synctest.Wait()
			st := pwStatus(w.pf)
			if fi, ok := pwSnapshot(w.pf)[pwAddr(x)]; !ok || fi.State != FlowOpen || st.Evicted != 0 || st.DropFull != 1 {
				t.Fatalf("a newcomer %v after x opened (x's one datagram 3.3 s old, y active 0.5 s ago): x %+v (in the table: %v), %s; want no victim (DropFull 1)",
					time.Since(at), fi, ok, pwDescribe(st))
			}
			time.Sleep(time.Until(at.Add(1500 * time.Millisecond)))
			pfSend(t, n, pwTagged(30, 0xC2, 1))
			synctest.Wait()
			tab, st := pwSnapshot(w.pf), pwStatus(w.pf)
			if fi, ok := tab[pwAddr(x)]; !ok || fi.State != FlowOpen {
				t.Fatalf("x (opened 1.5 s ago) evicted before y (active 2 s ago): x %+v (in the table: %v), %s", fi, ok, pwDescribe(st))
			}
			if _, ok := tab[pwAddr(y)]; ok || st.Evicted != 1 || st.Ended.Evicted != 1 || st.DropFull != 1 {
				t.Fatalf("want y, the least recently active, evicted: %s", pwDescribe(st))
			}
			if fl := w.pas.flowOf(0xA2); fl == nil || fl.rxCount.Load() != 1 {
				t.Fatalf("stimulus: x's target must receive its one datagram (%s)", pwDescribe(st))
			}
			pwUnits(t, w.pf)
		})
	})
}
