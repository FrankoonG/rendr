package l4

import (
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// pwSessions records every session the ingress opens for the rest of the
// test (pwDialHook); all returns them.
func pwSessions(t testing.TB) (all func() []ingressSession) {
	var mu sync.Mutex
	var ss []ingressSession
	pwDialHook(t, func(_ []byte, s ingressSession) ingressSession {
		mu.Lock()
		ss = append(ss, s)
		mu.Unlock()
		return s
	})
	return func() []ingressSession {
		mu.Lock()
		defer mu.Unlock()
		return append([]ingressSession(nil), ss...)
	}
}

// pwFinalDrops sums the drop counters of ss now (sessionDrops).
func pwFinalDrops(ss []ingressSession) (n uint64) {
	for _, s := range ss {
		if pk := s.Status().Packet; pk != nil {
			n += sessionDrops(pk)
		}
	}
	return n
}

// pwDelivered counts the datagrams the kit passive's targets received
// (read while no passive forward has ended: the kit's pipe drops what its
// reader had not taken when the forward's end closes it).
func pwDelivered(p *pwPassive) (n uint64) {
	_, _, _, flows := p.snapshot()
	for _, fl := range flows {
		n += uint64(fl.rxCount.Load())
	}
	return n
}

// pwWritten waits for every passive forward's end (at most d) and counts
// what the kit passive wrote to the targets: each first datagram that
// rode the OPEN and the forwards' ToLocal (what a socket would have sent).
func pwWritten(t testing.TB, p *pwPassive, d time.Duration) (n uint64) {
	t.Helper()
	_, _, _, flows := p.snapshot()
	for _, fl := range flows {
		select {
		case r := <-fl.res:
			fl.res <- r
			n += r.ToLocal
			if len(fl.req.First) > 0 {
				n++
			}
		case <-time.After(d):
			t.Fatalf("passive flow %d still runs", fl.id)
		}
	}
	return n
}

// TestPortForwardStopSessionDropsFinal_L39 (R1-38; L39): a flow that the
// ingress's stop closed reads its session's drop counters only once the
// session can hold no datagram any more — at its end (Done), or after the
// largest Packet.MaxAge (ingressSettle) — so SessionDrops holds the
// datagrams the session accepted before the close and dropped after it,
// and the client → target ledger closes: ToSession = delivered +
// SessionDrops.
//
//   - outage: three open flows; every link killed and refusing redials;
//     each client sends five datagrams, which their sessions queue (no
//     carrier); ServeUDP stops. The sessions drop them at Packet.MaxAge
//     (DropNoPath), after the close: SessionDrops is 15 when ServeUDP has
//     returned, equal to the sessions' final counters (also 5 s later),
//     and the stop took at most ingressSettle.
//   - live: the same with live links, ServeUDP stopped right after the
//     writes: everything is delivered, SessionDrops 0, and the stop waits
//     only for the sessions' ends (well below ingressSettle).
//   - eviction: at the default MaxAge (100 ms) an evicted flow — idle for
//     at least 1 s — holds no datagram at its eviction, so the sample taken
//     then is final (the documented bound of SessionDrops: no wait at an
//     eviction, R1-5).
func TestPortForwardStopSessionDropsFinal_L39(t *testing.T) {
	const n = 5
	t.Run("outage", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			sessions := pwSessions(t)
			w := newPWWorld(t, pwOpts{target: pwSink})
			w.serve()
			cs := pwClients(w, 3)
			for i, c := range cs {
				pfSend(t, c, pwTagged(30, byte(0xA0+i), 0))
			}
			time.Sleep(100 * time.Millisecond)
			if st := pwStatus(w.pf); st.Flows != 3 || pwDelivered(w.pas) != 3 {
				t.Fatalf("flows not open: %s, %d delivered", pwDescribe(st), pwDelivered(w.pas))
			}
			for _, l := range w.links {
				l.Refuse(true)
				l.Kill()
			}
			time.Sleep(50 * time.Millisecond)
			for i, c := range cs {
				for k := 1; k <= n; k++ {
					pfSend(t, c, pwTagged(30, byte(0xA0+i), k))
				}
			}
			time.Sleep(10 * time.Millisecond)
			start := time.Now()
			w.stop()
			took := time.Since(start)
			st := pwStatus(w.pf)
			final := pwFinalDrops(sessions())
			delivered := pwDelivered(w.pas)
			t.Logf("stop took %v; ToSession %d, delivered %d, SessionDrops %d, the sessions' drops %d; %s", took, st.ToSession, delivered, st.SessionDrops, final, pwDescribe(st))
			if st.SessionDrops != final || st.SessionDrops != 3*n || st.ToSession != delivered+st.SessionDrops || st.Ended.Stopped != 3 {
				t.Fatalf("SessionDrops %d, the sessions' final drops %d (want %d); ToSession %d = delivered %d + SessionDrops?", st.SessionDrops, final, 3*n, st.ToSession, delivered)
			}
			if took > ingressSettle+50*time.Millisecond {
				t.Fatalf("the stop took %v, more than ingressSettle %v", took, ingressSettle)
			}
			time.Sleep(5 * time.Second)
			if later := pwFinalDrops(sessions()); later != st.SessionDrops {
				t.Fatalf("the sessions dropped %d after ServeUDP returned (SessionDrops %d)", later-st.SessionDrops, st.SessionDrops)
			}
		})
	})
	t.Run("live", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			sessions := pwSessions(t)
			w := newPWWorld(t, pwOpts{target: pwSink})
			w.serve()
			cs := pwClients(w, 3)
			for i, c := range cs {
				pfSend(t, c, pwTagged(30, byte(0xA0+i), 0))
			}
			time.Sleep(100 * time.Millisecond)
			for i, c := range cs {
				for k := 1; k <= n; k++ {
					pfSend(t, c, pwTagged(30, byte(0xA0+i), k))
				}
			}
			synctest.Wait()
			start := time.Now()
			w.stop()
			took := time.Since(start)
			st := pwStatus(w.pf)
			delivered := pwWritten(t, w.pas, 5*time.Second)
			t.Logf("stop took %v; ToSession %d, delivered %d; %s", took, st.ToSession, delivered, pwDescribe(st))
			if st.ToSession != 3*(n+1) || delivered != st.ToSession || st.SessionDrops != 0 || pwFinalDrops(sessions()) != 0 || st.Ended.Stopped != 3 {
				t.Fatalf("live stop: ToSession %d, delivered %d, SessionDrops %d", st.ToSession, delivered, st.SessionDrops)
			}
			if took >= time.Second {
				t.Fatalf("the stop with live carriers took %v: it waits for the sessions' ends, not for ingressSettle", took)
			}
		})
	})
	t.Run("eviction", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			sessions := pwSessions(t)
			w := newPWWorld(t, pwOpts{target: pwSink, pfwd: func(f *PortForward) { f.MaxFlows = 1 }})
			w.serve()
			a := w.client()
			pfSend(t, a, pwTagged(30, 0xA1, 0))
			time.Sleep(100 * time.Millisecond)
			for _, l := range w.links {
				l.Refuse(true)
				l.Kill()
			}
			time.Sleep(50 * time.Millisecond)
			for k := 1; k <= n; k++ {
				pfSend(t, a, pwTagged(30, 0xA1, k))
			}
			time.Sleep(1500 * time.Millisecond) // a is idle ≥ 1 s: a victim
			pfSend(t, w.client(), pwTagged(30, 0xB1, 0))
			synctest.Wait()
			st := pwStatus(w.pf)
			ss := sessions()
			final := pwFinalDrops(ss[:1])
			delivered := pwDelivered(w.pas)
			t.Logf("after the eviction: SessionDrops %d, a's session's drops %d, delivered %d; %s", st.SessionDrops, final, delivered, pwDescribe(st))
			if st.Evicted != 1 || st.Ended.Evicted != 1 || st.SessionDrops != n || final != n || st.ToSession != delivered+st.SessionDrops {
				t.Fatalf("eviction: Evicted %d, SessionDrops %d, a's drops %d (want %d), ToSession %d, delivered %d", st.Evicted, st.SessionDrops, final, n, st.ToSession, delivered)
			}
		})
	})
}
