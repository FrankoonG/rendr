package l4

import (
	"bytes"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The counting rows of m6-design's delegate decisions after wave D (C4,
// C5 A2): a datagram a flow's session accepted and handed to a carrier,
// and then lost at an end the peer or the path decided, is counted
// (SessionUnreported) at the ingress and at the Server; an oversize
// datagram queued at a slow open counts TooLarge, never DropOpenAge.

// ucSession returns the packet counters of c's open flow at the ingress
// (zero when it has none).
func ucSession(w *pwWorld, c *rendrtest.DatagramConn) rendr.PacketCounters {
	if fi, ok := pwSnapshot(w.pf)[pwAddr(c)]; ok && fi.State == FlowOpen && fi.Session.Packet != nil {
		return *fi.Session.Packet
	}
	return rendr.PacketCounters{}
}

// ucWantSession waits (at most d) until c's flow session has handed sent
// datagrams to a carrier and the peer reported peer of them.
func ucWantSession(t testing.TB, w *pwWorld, c *rendrtest.DatagramConn, sent, peer uint64, d time.Duration) {
	t.Helper()
	if _, ok := pwWaitFor(d, func() bool { p := ucSession(w, c); return p.Sent == sent && p.PeerReceived == peer }); !ok {
		p := ucSession(w, c)
		t.Fatalf("stimulus: the flow's session has Sent %d, PeerReceived %d; want %d and %d", p.Sent, p.PeerReceived, sent, peer)
	}
}

// ucOpen waits until c's flow is open at the ingress.
func ucOpen(t testing.TB, w *pwWorld, c *rendrtest.DatagramConn) {
	t.Helper()
	if _, ok := pwWaitFor(5*time.Second, func() bool { return pwSnapshot(w.pf)[pwAddr(c)].State == FlowOpen }); !ok {
		t.Fatalf("the flow did not open: %s", pwDescribe(pwStatus(w.pf)))
	}
}

// ucCounted is every ingress counter a client datagram can end in besides
// its delivery.
func ucCounted(st UDPForwardStatus) uint64 {
	return st.DropFull + st.DropOpening + st.DropOpenQueue + st.DropOpenAge + st.DropHeld + st.TooLarge + st.SessionDrops + st.SessionUnreported
}

// ucLedger is the ingress ledger of the flow whose target first received a
// datagram tagged tag, sent datagrams from its client: it waits for the
// passive forward's end (its session's drops then final) and returns what
// the target received and what the ingress and the passive session counted.
func ucLedger(t testing.TB, w *pwWorld, tag byte) (delivered, counted uint64) {
	t.Helper()
	fl := w.pas.flowOf(tag)
	if fl == nil {
		t.Fatalf("no flow of tag %#x reached the passive", tag)
	}
	<-fl.res
	return uint64(fl.rxCount.Load()), ucCounted(pwStatus(w.pf)) + sessionDrops(fl.pc.Status().Packet)
}

// TestPortForwardSessionLostCountsAccepted_L39 (L39; m6-design's delegate
// decisions after wave D, C4): a datagram a flow's session accepted
// (WriteTo, ToSession) and handed to a carrier is delivered or counted,
// also when the flow then ends without the peer's last report. Each row
// sends 3 datagrams on one flow (the first rides the OPEN; the second is
// delivered and reported by the peer); the third is handed to the carrier
// (Sent, the stimulus) and then lost:
//   - the passive restarted: it is in flight when the paths die, and the
//     rejoin meets a passive that answers UNKNOWN_SESSION (ErrSessionLost);
//   - the passive's idle end crosses it: it is sent one way before the
//     passive's AbortIdle reaches the ingress (PeerIdle);
//   - the passive's Runtime closed while it was in flight (GoingAway);
//   - at the Server, the dialer vanished (its paths died with the target's
//     third datagram in flight, and it never came back; the Server's flow
//     ends ErrNoPath at PassiveRetain): the mirror case.
//
// delivered + counted = sent at the side that sent, where counted holds
// SessionUnreported: the session's Sent − PeerReceived at such an end. That
// count is an upper bound: in the row "received, not yet reported" the
// third datagram reaches the restarted passive's target within its report
// delay (PacketPing) and is counted as well, delivered + counted = sent + 1
// (lost ≤ counted ≤ lost + unreported). At an end this side decided (its
// own idle limit) a datagram lost in flight earlier is not in the count.
func TestPortForwardSessionLostCountsAccepted_L39(t *testing.T) {
	// lose opens a flow of tag, delivers its first two datagrams (the
	// second reported by the passive), then calls end, which sends the
	// third and ends the flow.
	lose := func(t *testing.T, o pwOpts, tag byte, end func(w *pwWorld, c *rendrtest.DatagramConn)) *pwWorld {
		if o.target == nil {
			o.target = pwSink
		}
		w := newPWWorld(t, o)
		w.serve()
		c := w.client()
		pfSend(t, c, pwTagged(30, tag, 0)) // rides the OPEN
		ucOpen(t, w, c)
		pfSend(t, c, pwTagged(30, tag, 1))
		time.Sleep(2 * time.Second)                    // the passive's report (PacketPing, 1 s)
		ucWantSession(t, w, c, 1, 1, time.Millisecond) // delivered and reported
		end(w, c)
		return w
	}
	// sendThird sends the third datagram and waits until the session handed
	// it to the carrier: it is in flight (one way: 5 ms).
	sendThird := func(t *testing.T, w *pwWorld, c *rendrtest.DatagramConn, tag byte) {
		pfSend(t, c, pwTagged(30, tag, 2))
		ucWantSession(t, w, c, 2, 1, time.Millisecond)
	}
	check := func(t *testing.T, w *pwWorld, tag byte, extra uint64) {
		t.Helper()
		delivered, counted := ucLedger(t, w, tag)
		st := pwStatus(w.pf)
		t.Logf("sent 3, delivered %d, counted %d (SessionUnreported %d, SessionDrops %d); ended %+v", delivered, counted, st.SessionUnreported, st.SessionDrops, st.Ended)
		if st.ToSession != 3 {
			t.Fatalf("stimulus: ToSession %d, want the 3 datagrams accepted (%s)", st.ToSession, pwDescribe(st))
		}
		if delivered+counted != 3+extra {
			t.Fatalf("delivered %d + counted %d != sent 3 + %d (%s)", delivered, counted, extra, pwDescribe(st))
		}
	}

	t.Run("passive restart (SessionLost)", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := lose(t, pwOpts{}, 0xE0, func(w *pwWorld, c *rendrtest.DatagramConn) {
				w.restart()
				sendThird(t, w, c, 0xE0)
				w.links[0].Kill() // lost in flight; the rejoin meets the new passive
			})
			if _, ok := pwWaitFor(time.Minute, func() bool { return pwStatus(w.pf).Ended.SessionLost == 1 }); !ok {
				t.Fatalf("the flow did not end ErrSessionLost: %s", pwDescribe(pwStatus(w.pf)))
			}
			check(t, w, 0xE0, 0)
		})
	})

	t.Run("received, not yet reported (the bound)", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := lose(t, pwOpts{}, 0xE1, func(w *pwWorld, c *rendrtest.DatagramConn) {
				w.restart()
				pfSend(t, c, pwTagged(30, 0xE1, 2))
				time.Sleep(100 * time.Millisecond) // received by the old passive, its report still delayed
				if fl := w.pas.flowOf(0xE1); fl == nil || fl.rxCount.Load() != 3 {
					t.Fatal("stimulus: the third datagram did not reach the target")
				}
				ucWantSession(t, w, c, 2, 1, time.Millisecond) // unreported
				w.links[0].Kill()
			})
			if _, ok := pwWaitFor(time.Minute, func() bool { return pwStatus(w.pf).Ended.SessionLost == 1 }); !ok {
				t.Fatalf("the flow did not end ErrSessionLost: %s", pwDescribe(pwStatus(w.pf)))
			}
			check(t, w, 0xE1, 1)
		})
	})

	t.Run("passive idle end (PeerIdle)", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := newPWWorld(t, pwOpts{
				target:      pwSink,
				passiveIdle: FlowIdle{Short: 10 * time.Second, Stream: 10 * time.Second},
				pfwd:        func(f *PortForward) { f.Idle = FlowIdle{Short: time.Minute, Stream: time.Minute} },
			})
			w.serve()
			// Calibration: when the passive's end reaches the ingress after
			// a flow's second datagram (its first rode the OPEN).
			cal := w.client()
			pfSend(t, cal, pwTagged(30, 0xD0, 0))
			ucOpen(t, w, cal)
			pfSend(t, cal, pwTagged(30, 0xD0, 1))
			lifetime, ok := pwWaitFor(time.Minute, func() bool { return pwStatus(w.pf).Ended.PeerIdle == 1 })
			if !ok {
				t.Fatalf("calibration: %s", pwDescribe(pwStatus(w.pf)))
			}
			t.Logf("calibration: the passive's end reaches the ingress %v after a flow's second datagram", lifetime)
			// The row's flow: the same two datagrams, then the third one way
			// before the passive's end reaches the ingress.
			c := w.client()
			pfSend(t, c, pwTagged(30, 0xE2, 0))
			ucOpen(t, w, c)
			pfSend(t, c, pwTagged(30, 0xE2, 1))
			t1 := time.Now()
			time.Sleep(2 * time.Second)
			ucWantSession(t, w, c, 1, 1, time.Millisecond)
			time.Sleep(time.Until(t1.Add(lifetime - pfOneWay)))
			pfSend(t, c, pwTagged(30, 0xE2, 2))
			ucWantSession(t, w, c, 2, 1, time.Millisecond) // handed to the carrier, in flight
			if _, ok := pwWaitFor(time.Minute, func() bool { return pwStatus(w.pf).Ended.PeerIdle == 2 }); !ok {
				t.Fatalf("the flow did not end AbortIdle: %s", pwDescribe(pwStatus(w.pf)))
			}
			delivered, counted := ucLedger(t, w, 0xE2)
			calFlow := w.pas.flowOf(0xD0)
			<-calFlow.res
			delivered += uint64(calFlow.rxCount.Load())
			counted += sessionDrops(calFlow.pc.Status().Packet)
			st := pwStatus(w.pf)
			t.Logf("sent 5, delivered %d, counted %d (SessionUnreported %d); ended %+v", delivered, counted, st.SessionUnreported, st.Ended)
			if st.ToSession != 5 || delivered != 4 {
				t.Fatalf("stimulus: ToSession %d, delivered %d; want 5 accepted and the one that crossed the passive's end lost (%s)", st.ToSession, delivered, pwDescribe(st))
			}
			if delivered+counted != 5 {
				t.Fatalf("delivered %d + counted %d != sent 5 (%s)", delivered, counted, pwDescribe(st))
			}
		})
	})

	t.Run("passive Runtime closed (GoingAway)", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := lose(t, pwOpts{}, 0xE3, func(w *pwWorld, c *rendrtest.DatagramConn) {
				sendThird(t, w, c, 0xE3)
				w.p.Close() // the datagram arrives after the passive Runtime's end
			})
			if _, ok := pwWaitFor(time.Minute, func() bool { return pwStatus(w.pf).Ended.GoingAway == 1 }); !ok {
				t.Fatalf("the flow did not end AbortGoingAway: %s", pwDescribe(pwStatus(w.pf)))
			}
			check(t, w, 0xE3, 0)
		})
	})

	t.Run("own idle end, an earlier loss in flight (not counted)", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			o := pwOpts{pfwd: func(f *PortForward) { f.Idle = FlowIdle{Short: 10 * time.Second, Stream: 10 * time.Second} }}
			w := lose(t, o, 0xE4, func(w *pwWorld, c *rendrtest.DatagramConn) {
				w.links[0].Blackhole(rendrtest.Up, true)
				sendThird(t, w, c, 0xE4)
				w.links[0].Blackhole(rendrtest.Up, false)
				time.Sleep(2 * time.Second)
				ucWantSession(t, w, c, 2, 1, time.Millisecond) // lost, never reported
			})
			if _, ok := pwWaitFor(time.Minute, func() bool { return pwStatus(w.pf).Ended.Idle == 1 }); !ok {
				t.Fatalf("the flow did not end idle: %s", pwDescribe(pwStatus(w.pf)))
			}
			if st := pwStatus(w.pf); st.SessionUnreported != 0 {
				t.Fatalf("SessionUnreported %d at the ingress's own idle end, want 0 (%s)", st.SessionUnreported, pwDescribe(st))
			}
		})
	})

	t.Run("server, the dialer vanished (NoPath)", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := newSUWorld(t, suOpts{})
			ts := newSUTargets(rendrtest.DatagramPipeConfig{})
			s := &Server{UDP: true, Dial: ts.dial, UDPIdle: FlowIdle{Short: -1}}
			sv := suServe(w, s)
			pc := suDial(t, w, pfTarget, nil)
			app := ts.next(t, time.Minute)
			u := pfData(40, 0xF0)
			if _, err := pc.WriteTo(u, nil); err != nil {
				t.Fatalf("WriteTo: %v", err)
			}
			pfExpect(t, app, u)
			r0, r1 := pfData(50, 0xF1), pfData(60, 0xF2)
			pfSend(t, app, r0)
			if got, err := pfRecvPC(t, pc); err != nil || !bytes.Equal(got, r0) {
				t.Fatalf("the target's first datagram: %d bytes, %v", len(got), err)
			}
			time.Sleep(2 * time.Second) // the dialer's report (PacketPing, 1 s)
			// The dialer vanishes: no carrier comes back, and the target's
			// second datagram is in flight when its paths die.
			w.links[0].Refuse(true)
			pfSend(t, app, r1)
			synctest.Wait()
			if got := s.Status().UDP.FromTarget; got != 2 {
				t.Fatalf("stimulus: FromTarget %d, want both of the target's datagrams accepted", got)
			}
			w.links[0].Kill()
			w.d.Close()
			waitFor(t, time.Minute, "the Server's flow ends ErrNoPath", func() bool { return s.Status().UDP.Ended.NoPath == 1 })
			waitFor(t, time.Minute, "HandleUDP returned", func() bool { all, _ := suHandlers(); return all == 0 })
			st := s.Status().UDP
			delivered := pc.Status().Packet.Received
			counted := st.SessionDrops + st.SessionUnreported + st.TooLarge
			t.Logf("the target sent %d, the dialer received %d, counted %d (SessionUnreported %d, SessionDrops %d); ended %+v", st.FromTarget, delivered, counted, st.SessionUnreported, st.SessionDrops, st.Ended)
			if delivered != 1 || st.SessionDrops != 0 {
				t.Fatalf("stimulus: the dialer received %d, SessionDrops %d: want the second datagram handed to the carrier and lost in flight", delivered, st.SessionDrops)
			}
			if delivered+counted != st.FromTarget {
				t.Fatalf("delivered %d + counted %d != sent %d", delivered, counted, st.FromTarget)
			}
			sv.stop(t)
		})
	})
}

// TestPortForwardSlowOpenOversizeCounted_L37 (L37, L71; m6-design's
// delegate decisions after wave D, C5 A2): at the default budget
// (MaxPayload 1,198) a client's 1,199-byte first datagram cannot ride the
// OPEN and waits in the opening queue; the passive confirms 1.05 s later,
// so at the flush it is older than the queue's 1 s. It is TooLarge (1,
// TooLargeMax 1,199), never DropOpenAge: the flush checks a queued
// datagram's size before its age. The 100-byte datagram sent 100 ms after
// it is flushed in time and echoed.
func TestPortForwardSlowOpenOversizeCounted_L37(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newPWWorld(t, pwOpts{pf: pfOpts{mtu: 1223}, gate: func(int, Request) <-chan struct{} {
			ch := make(chan struct{})
			time.AfterFunc(1050*time.Millisecond, func() { close(ch) })
			return ch
		}})
		w.serve()
		c := w.client()
		start := time.Now()
		pfSend(t, c, pwTagged(1199, 0x90, 0))
		time.Sleep(100 * time.Millisecond)
		small := pwTagged(100, 0x90, 1)
		pfSend(t, c, small)
		got, ok, err := pwRecvWithin(c, 2*time.Second)
		if err != nil || !ok || !bytes.Equal(got, small) {
			t.Fatalf("the 100-byte datagram's echo: ok %v, err %v, %d bytes (%s)", ok, err, len(got), pwDescribe(pwStatus(w.pf)))
		}
		if took := time.Since(start); took <= ingressQueueAge+50*time.Millisecond {
			t.Fatalf("stimulus: the echo came %v after the first send, want the open to outlast the queue's age (%v)", took, ingressQueueAge)
		}
		st := pwStatus(w.pf)
		if st.MaxPayload != 1198 || st.FirstInOpen != 0 || st.Opened != 1 {
			t.Fatalf("stimulus: MaxPayload %d (want the default budget, 1,198), FirstInOpen %d, Opened %d", st.MaxPayload, st.FirstInOpen, st.Opened)
		}
		if st.TooLarge != 1 || st.TooLargeMax != 1199 || st.DropOpenAge != 0 || st.DropOpenQueue != 0 || st.ToSession != 1 {
			t.Fatalf("TooLarge %d, TooLargeMax %d, DropOpenAge %d, DropOpenQueue %d, ToSession %d; want 1, 1199, 0, 0, 1 (%s)",
				st.TooLarge, st.TooLargeMax, st.DropOpenAge, st.DropOpenQueue, st.ToSession, pwDescribe(st))
		}
		if fl := w.pas.flowOf(0x90); fl == nil || fl.rxCount.Load() != 1 {
			t.Fatal("the target must receive the 100-byte datagram only")
		}
	})
}
