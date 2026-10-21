package l4

import (
	"testing"
	"testing/synctest"
	"time"
)

// TestPortForwardSlowOpenNotIdle_L48_L72 (M6-D27, M6-D29; L48, L72): a
// client's datagrams that wait for a slow open count as its activity. O-1
// (a), MaxFlows 1, a silent target: the passive holds flow a's OPEN 1.7 s;
// a sends at 0 (it rides the OPEN) and at 1.5 s (queued). While opening and
// once open, FlowInfo.Last is the 1.5-s datagram, and the target receives
// both. A newcomer 250 ms after a's latest datagram finds no victim idle
// for 1 s (DropFull, nothing evicted); once a has been idle for 1 s since
// that datagram, the newcomer's next datagram evicts it.
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
			close(gate) // the open completes at 1.7 s
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
			pfSend(t, b, pwTagged(30, 0xB1, 1)) // a idle 1 s since its latest datagram
			synctest.Wait()
			time.Sleep(100 * time.Millisecond)
			st := pwStatus(w.pf)
			if st.Evicted != 1 || st.Ended.Evicted != 1 || st.DropFull != 1 || pwSnapshot(w.pf)[pwAddr(b)].State != FlowOpen {
				t.Fatalf("control: a newcomer once a was idle 1 s: %s; want a evicted, b open", pwDescribe(st))
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
