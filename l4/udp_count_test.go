package l4

import (
	"bytes"
	"net"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The counting rows of m6-design's delegate decisions after wave D (C4,
// C5 A2): a datagram a flow's session accepted and handed to a carrier,
// and then lost at an end the peer or the path decided, is counted
// (SessionUnreported) at the ingress and at the Server, and an end this
// side decided adds nothing; an oversize datagram queued at a slow open
// counts TooLarge, never DropOpenAge.

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
// datagram tagged tag: it waits for the passive forward's end (its
// session's drops then final) and returns what the passive wrote to the
// target — the first datagram, which rode the OPEN, and the forward's
// ToLocal (the kit's target pipe drops what its reader had not taken when
// the forward's end closes it, which a socket would have sent) — and what
// the ingress and the passive session counted.
func ucLedger(t testing.TB, w *pwWorld, tag byte) (delivered, counted uint64) {
	t.Helper()
	fl := w.pas.flowOf(tag)
	if fl == nil {
		t.Fatalf("no flow of tag %#x reached the passive", tag)
	}
	r := <-fl.res
	fl.res <- r
	delivered = r.ToLocal
	if len(fl.req.First) > 0 {
		delivered++
	}
	return delivered, ucCounted(pwStatus(w.pf)) + sessionDrops(fl.pc.Status().Packet)
}

// ucLose opens a flow of tag through the ingress (the target a sink unless
// o names one), delivers its first two datagrams — the first rides the
// OPEN, the second is reported by the passive — and calls end, which sends
// the third and ends the flow.
func ucLose(t *testing.T, o pwOpts, tag byte, end func(w *pwWorld, c *rendrtest.DatagramConn)) *pwWorld {
	t.Helper()
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

// ucSendThird sends the third datagram of tag and waits until the session
// handed it to the carrier: it is in flight (one way: 5 ms).
func ucSendThird(t testing.TB, w *pwWorld, c *rendrtest.DatagramConn, tag byte) {
	t.Helper()
	pfSend(t, c, pwTagged(30, tag, 2))
	ucWantSession(t, w, c, 2, 1, time.Millisecond)
}

// ucCheck checks the ingress ledger of the 3 datagrams of tag: the passive
// wrote delivered of them to the target, and delivered + counted = 3 +
// extra.
func ucCheck(t testing.TB, w *pwWorld, tag byte, delivered, extra uint64) {
	t.Helper()
	got, counted := ucLedger(t, w, tag)
	st := pwStatus(w.pf)
	t.Logf("sent 3, delivered %d, counted %d (SessionUnreported %d, SessionDrops %d); ended %+v", got, counted, st.SessionUnreported, st.SessionDrops, st.Ended)
	if st.ToSession != 3 || got != delivered {
		t.Fatalf("stimulus: ToSession %d, delivered %d; want the 3 datagrams accepted and %d delivered (%s)", st.ToSession, got, delivered, pwDescribe(st))
	}
	if got+counted != 3+extra {
		t.Fatalf("delivered %d + counted %d != sent 3 + %d (%s)", got, counted, extra, pwDescribe(st))
	}
}

// ucEnded waits until the ingress counted one flow end in field.
func ucEnded(t testing.TB, w *pwWorld, what string, field func(FlowEnds) uint64) {
	t.Helper()
	if _, ok := pwWaitFor(time.Minute, func() bool { return field(pwStatus(w.pf).Ended) == 1 }); !ok {
		t.Fatalf("the flow did not end %s: %s", what, pwDescribe(pwStatus(w.pf)))
	}
}

// ucSrv is one flow through a Server whose dialer is a bare DialUDP
// session, after one datagram each way (the target's reported by the
// dialer).
type ucSrv struct {
	w   *suWorld
	ts  *suTargets
	s   *Server
	sv  *served
	pc  *rendr.PacketConn       // the dialer's session
	app *rendrtest.DatagramConn // the target
}

func ucServer(t testing.TB, idle FlowIdle) *ucSrv {
	t.Helper()
	x := &ucSrv{w: newSUWorld(t, suOpts{}), ts: newSUTargets(rendrtest.DatagramPipeConfig{})}
	x.s = &Server{UDP: true, Dial: x.ts.dial, UDPIdle: idle}
	x.sv = suServe(x.w, x.s)
	x.pc = suDial(t, x.w, pfTarget, nil)
	x.app = x.ts.next(t, time.Minute)
	u := pfData(40, 0xF0)
	if _, err := x.pc.WriteTo(u, nil); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	pfExpect(t, x.app, u)
	r0 := pfData(50, 0xF1)
	pfSend(t, x.app, r0)
	if got, err := pfRecvPC(t, x.pc); err != nil || !bytes.Equal(got, r0) {
		t.Fatalf("the target's first datagram: %d bytes, %v", len(got), err)
	}
	time.Sleep(2 * time.Second) // the dialer's report (PacketPing, 1 s)
	return x
}

// ucR1 is the target's second datagram.
var ucR1 = pfData(60, 0xF2)

// second sends the target's second datagram and waits until the Server's
// forward handed it to the session: it is in flight.
func (x *ucSrv) second(t testing.TB) {
	t.Helper()
	pfSend(t, x.app, ucR1)
	synctest.Wait()
	if got := x.s.Status().UDP.FromTarget; got != 2 {
		t.Fatalf("stimulus: FromTarget %d, want both of the target's datagrams accepted", got)
	}
}

// ended waits until the Server counted one flow end in field.
func (x *ucSrv) ended(t testing.TB, what string, field func(FlowEnds) uint64) {
	t.Helper()
	waitFor(t, time.Minute, "the Server's flow ends "+what, func() bool { return field(x.s.Status().UDP.Ended) == 1 })
}

// handled waits until the flow's handler returned (after the session's
// end, unless Serve stopped) and returns the UDP status.
func (x *ucSrv) handled(t testing.TB) UDPServerStatus {
	t.Helper()
	waitFor(t, time.Minute, "HandleUDP returned", func() bool { all, _ := suHandlers(); return all == 0 })
	return x.s.Status().UDP
}

// readSecond requires the dialer to read the target's second datagram
// (before the session's end can come: the FIN is delivered after it).
func (x *ucSrv) readSecond(t testing.TB) {
	t.Helper()
	if got, err := pfRecvPC(t, x.pc); err != nil || !bytes.Equal(got, ucR1) {
		t.Fatalf("the target's second datagram at the dialer: %d bytes, %v", len(got), err)
	}
}

// check checks the Server's ledger of the target's 2 datagrams: the dialer
// read delivered of them, and delivered + counted = 2.
func (x *ucSrv) check(t testing.TB, st UDPServerStatus, delivered uint64) {
	t.Helper()
	counted := st.SessionDrops + st.SessionUnreported + st.TooLarge
	t.Logf("the target sent %d, the dialer read %d, counted %d (SessionUnreported %d, SessionDrops %d); ended %+v", st.FromTarget, delivered, counted, st.SessionUnreported, st.SessionDrops, st.Ended)
	if st.FromTarget != 2 {
		t.Fatalf("stimulus: FromTarget %d, want 2", st.FromTarget)
	}
	if delivered+counted != st.FromTarget {
		t.Fatalf("delivered %d + counted %d != sent %d", delivered, counted, st.FromTarget)
	}
}

// TestPortForwardSessionLostCountsAccepted_L39 (L39; m6-design's delegate
// decisions after wave D, C4): a datagram a flow's session accepted
// (WriteTo, ToSession) and handed to a carrier is delivered or counted,
// also when the flow then ends without the peer's last report. Each
// ingress row sends 3 datagrams on one flow (the first rides the OPEN; the
// second is delivered and reported by the peer); the third is handed to
// the carrier (Sent, the stimulus) and then lost:
//   - the passive restarted: it is in flight when the paths die, and the
//     rejoin meets a passive that answers UNKNOWN_SESSION (ErrSessionLost);
//   - the passive vanished (R9's shape): its Runtime closed while its
//     GoingAway could not cross, the third reaches it there, and the rejoin
//     meets the new passive (ErrSessionLost);
//   - the passive's idle end crosses it: it leaves within a millisecond of
//     the passive's end, which takes one way to reach the ingress
//     (PeerIdle);
//   - the passive's Runtime closed while it was in flight (GoingAway);
//   - the passive closed the flow's session while it was in flight: it
//     reaches a closed session, which discards it uncounted (M2-D37) and
//     reports it only after the ingress's flow ended (PeerClosed).
//
// At the Server, the mirror cases: the dialer vanished (its paths died with
// the target's second datagram in flight, and it never came back: ErrNoPath
// at PassiveRetain), and the dialer closed its session with it in flight
// (PeerClosed; the dialer reports it in its final PACKs, after the forward
// ended, which is when the Server takes the count).
//
// delivered + counted = sent at the side that sent, where counted holds
// SessionUnreported: the session's Sent − PeerReceived at such an end. That
// count is an upper bound: in the row "received, not yet reported" the
// third datagram reaches the restarted passive's target within its report
// delay (PacketPing) and is counted as well, delivered + counted = sent + 1
// (lost ≤ counted ≤ lost + unreported).
func TestPortForwardSessionLostCountsAccepted_L39(t *testing.T) {
	t.Run("passive restart (SessionLost)", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := ucLose(t, pwOpts{}, 0xE0, func(w *pwWorld, c *rendrtest.DatagramConn) {
				w.restart()
				ucSendThird(t, w, c, 0xE0)
				w.links[0].Kill() // lost in flight; the rejoin meets the new passive
			})
			ucEnded(t, w, "ErrSessionLost", func(e FlowEnds) uint64 { return e.SessionLost })
			ucCheck(t, w, 0xE0, 2, 0)
		})
	})

	t.Run("passive vanished (SessionLost)", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := ucLose(t, pwOpts{}, 0xE6, func(w *pwWorld, c *rendrtest.DatagramConn) {
				w.restart() // the next carriers reach a new passive
				w.links[0].Blackhole(rendrtest.Down, true)
				w.p.Close() // its GoingAway never crosses
				ucSendThird(t, w, c, 0xE6)
				time.Sleep(100 * time.Millisecond) // it reached the old passive, gone
				w.links[0].Blackhole(rendrtest.Down, false)
				w.links[0].Kill() // the rejoin meets the new passive: UNKNOWN_SESSION
			})
			ucEnded(t, w, "ErrSessionLost", func(e FlowEnds) uint64 { return e.SessionLost })
			ucCheck(t, w, 0xE6, 2, 0)
		})
	})

	t.Run("received, not yet reported (the bound)", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := ucLose(t, pwOpts{}, 0xE1, func(w *pwWorld, c *rendrtest.DatagramConn) {
				w.restart()
				pfSend(t, c, pwTagged(30, 0xE1, 2))
				time.Sleep(100 * time.Millisecond) // received by the old passive, its report still delayed
				if fl := w.pas.flowOf(0xE1); fl == nil || fl.rxCount.Load() != 3 {
					t.Fatal("stimulus: the third datagram did not reach the target")
				}
				ucWantSession(t, w, c, 2, 1, time.Millisecond) // unreported
				w.links[0].Kill()
			})
			ucEnded(t, w, "ErrSessionLost", func(e FlowEnds) uint64 { return e.SessionLost })
			ucCheck(t, w, 0xE1, 3, 1)
		})
	})

	t.Run("passive idle end (PeerIdle)", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			o := pwOpts{
				passiveIdle: FlowIdle{Short: 10 * time.Second, Stream: 10 * time.Second},
				pfwd:        func(f *PortForward) { f.Idle = FlowIdle{Short: time.Minute, Stream: time.Minute} },
			}
			w := ucLose(t, o, 0xE2, func(w *pwWorld, c *rendrtest.DatagramConn) {
				// The stimulus starts from the passive's end itself (its
				// moment varies by up to PacketPing with the PACK's
				// placement): its AbortIdle takes one way (5 ms) to the
				// ingress, the third datagram leaves within 1 ms.
				fl := w.pas.flowOf(0xE2)
				if _, ok := pwWaitFor(time.Minute, func() bool { return len(fl.res) == 1 }); !ok {
					t.Fatal("stimulus: the passive's forward did not end")
				}
				ucSendThird(t, w, c, 0xE2)
			})
			ucEnded(t, w, "AbortIdle", func(e FlowEnds) uint64 { return e.PeerIdle })
			ucCheck(t, w, 0xE2, 2, 0)
		})
	})

	t.Run("passive Runtime closed (GoingAway)", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := ucLose(t, pwOpts{}, 0xE3, func(w *pwWorld, c *rendrtest.DatagramConn) {
				ucSendThird(t, w, c, 0xE3)
				w.p.Close() // the datagram arrives after the passive Runtime's end
			})
			ucEnded(t, w, "AbortGoingAway", func(e FlowEnds) uint64 { return e.GoingAway })
			ucCheck(t, w, 0xE3, 2, 0)
		})
	})

	t.Run("passive closed (PeerClosed)", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := ucLose(t, pwOpts{}, 0xE5, func(w *pwWorld, c *rendrtest.DatagramConn) {
				time.Sleep(4 * time.Second) // past the reopen hold: the end removes the flow
				ucSendThird(t, w, c, 0xE5)
				w.pas.flowOf(0xE5).pc.Close() // the passive closes first
			})
			ucEnded(t, w, "io.EOF", func(e FlowEnds) uint64 { return e.PeerClosed })
			if pk := w.pas.flowOf(0xE5).pc.Status().Packet; pk.Received != 2 {
				t.Fatalf("stimulus: the passive session received %d datagrams, want the third too (after its Close)", pk.Received)
			}
			ucCheck(t, w, 0xE5, 2, 0)
		})
	})

	t.Run("server, the dialer vanished (NoPath)", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			x := ucServer(t, FlowIdle{Short: -1})
			// The dialer vanishes: no carrier comes back, and the target's
			// second datagram is in flight when its paths die.
			x.w.links[0].Refuse(true)
			x.second(t)
			x.w.links[0].Kill()
			x.w.d.Close()
			x.ended(t, "ErrNoPath", func(e FlowEnds) uint64 { return e.NoPath })
			st := x.handled(t)
			if pk := x.pc.Status().Packet; pk.Received != 1 || st.SessionDrops != 0 {
				t.Fatalf("stimulus: the dialer received %d, SessionDrops %d: want the second datagram handed to the carrier and lost in flight", pk.Received, st.SessionDrops)
			}
			x.check(t, st, 1)
			x.sv.stop(t)
		})
	})

	t.Run("server, the dialer closed (PeerClosed)", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			x := ucServer(t, FlowIdle{Short: -1})
			x.second(t)
			x.pc.Close() // the dialer closes first: the second reaches a closed session
			x.ended(t, "io.EOF", func(e FlowEnds) uint64 { return e.PeerClosed })
			st := x.handled(t)
			if pk := x.pc.Status().Packet; pk.Received != 2 {
				t.Fatalf("stimulus: the dialer's session received %d, want the second datagram too (after its Close)", pk.Received)
			}
			x.check(t, st, 1)
			x.sv.stop(t)
		})
	})
}

// TestSessionUnreportedOwnEnds_L39 (L39; m6-design's delegate decisions
// after wave D): an end this side decided adds nothing to
// SessionUnreported. Before a stop or a local failure, the datagram its
// session already sent reaches the peer ahead of the FIN and is delivered;
// a datagram lost in flight earlier (blackholed) is not this end's, at the
// ingress's and the Server's own idle end and at an eviction: there the
// count stays 0 while Sent − PeerReceived is 1.
func TestSessionUnreportedOwnEnds_L39(t *testing.T) {
	t.Run("ingress idle end, an earlier loss", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			o := pwOpts{pfwd: func(f *PortForward) { f.Idle = FlowIdle{Short: 10 * time.Second, Stream: 10 * time.Second} }}
			w := ucLose(t, o, 0xE4, func(w *pwWorld, c *rendrtest.DatagramConn) {
				w.links[0].Blackhole(rendrtest.Up, true)
				ucSendThird(t, w, c, 0xE4)
				w.links[0].Blackhole(rendrtest.Up, false)
				time.Sleep(2 * time.Second)
				ucWantSession(t, w, c, 2, 1, time.Millisecond) // lost, never reported
			})
			ucEnded(t, w, "idle", func(e FlowEnds) uint64 { return e.Idle })
			if st := pwStatus(w.pf); st.SessionUnreported != 0 {
				t.Fatalf("SessionUnreported %d at the ingress's own idle end, want 0 (%s)", st.SessionUnreported, pwDescribe(st))
			}
		})
	})

	t.Run("ingress stop, a datagram in flight", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := ucLose(t, pwOpts{}, 0xE7, func(w *pwWorld, c *rendrtest.DatagramConn) {
				ucSendThird(t, w, c, 0xE7)
				w.stop() // the FIN follows the third datagram
			})
			ucEnded(t, w, "stopped", func(e FlowEnds) uint64 { return e.Stopped })
			ucCheck(t, w, 0xE7, 3, 0)
		})
	})

	t.Run("ingress eviction, an earlier loss", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			pfRule(t, promoteActive)
			o := pwOpts{pfwd: func(f *PortForward) { f.MaxFlows = 1 }}
			w := ucLose(t, o, 0xE8, func(w *pwWorld, c *rendrtest.DatagramConn) {
				w.links[0].Blackhole(rendrtest.Up, true)
				ucSendThird(t, w, c, 0xE8)
				w.links[0].Blackhole(rendrtest.Up, false)
				time.Sleep(2 * time.Second) // idle ≥ 1 s, a one-way flow: a victim
				ucWantSession(t, w, c, 2, 1, time.Millisecond)
				pfSend(t, w.client(), pwTagged(30, 0xE9, 0)) // the newcomer takes its place
			})
			ucEnded(t, w, "evicted", func(e FlowEnds) uint64 { return e.Evicted })
			if st := pwStatus(w.pf); st.SessionUnreported != 0 {
				t.Fatalf("SessionUnreported %d at an eviction, want 0 (%s)", st.SessionUnreported, pwDescribe(st))
			}
		})
	})

	t.Run("server idle end, an earlier loss", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			x := ucServer(t, FlowIdle{Short: 10 * time.Second, Stream: 10 * time.Second})
			x.w.links[0].Blackhole(rendrtest.Down, true)
			x.second(t)
			time.Sleep(100 * time.Millisecond) // lost in flight
			x.w.links[0].Blackhole(rendrtest.Down, false)
			x.ended(t, "idle", func(e FlowEnds) uint64 { return e.Idle })
			st := x.handled(t)
			if pk := x.pc.Status().Packet; pk.Received != 1 || st.SessionUnreported != 0 {
				t.Fatalf("the dialer received %d (want 1: the second lost), SessionUnreported %d at the Server's own idle end, want 0", pk.Received, st.SessionUnreported)
			}
			x.sv.stop(t)
		})
	})

	t.Run("server stop, a datagram in flight", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			x := ucServer(t, FlowIdle{Short: -1})
			x.second(t)
			x.sv.stop(t) // the FIN follows the second datagram
			x.ended(t, "stopped", func(e FlowEnds) uint64 { return e.Stopped })
			x.readSecond(t)
			x.check(t, x.handled(t), 2)
		})
	})

	t.Run("server local failure, a datagram in flight", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			x := ucServer(t, FlowIdle{Short: -1})
			x.second(t)
			x.ts.srv[0].Inject(suWriteErr(syscall.Errno(10009)), true) // WSAEBADF: the forward ends at once
			x.ended(t, "local", func(e FlowEnds) uint64 { return e.Local })
			x.readSecond(t)
			x.check(t, x.handled(t), 2)
			x.sv.stop(t)
		})
	})
}

// ucEndAtWrite is a flow session whose first WriteTo meets its end: it
// closes the session there, so that WriteTo and every later one fail.
type ucEndAtWrite struct {
	ingressSession
	once sync.Once
}

func (s *ucEndAtWrite) WriteTo(b []byte, a net.Addr) (int, error) {
	s.once.Do(func() { s.ingressSession.Close() })
	return s.ingressSession.WriteTo(b, a)
}

// TestPortForwardSlowOpenOversizeCounted_L37 (L37, L71; m6-design's
// delegate decisions after wave D, C5 A2): at the default budget
// (MaxPayload 1,198) a client's 1,199-byte first datagram cannot ride the
// OPEN and waits in the opening queue; the passive confirms 1.05 s later,
// so at the flush it is older than the queue's 1 s. It is TooLarge (1,
// TooLargeMax 1,199), never DropOpenAge: the flush checks a queued
// datagram's size before its age. A datagram of exactly MaxPayload and a
// 100-byte one sent 100 ms after it are flushed in time and echoed. When
// the session ends at the flush's first write, an oversize datagram behind
// it is still TooLarge, the others DropOpenQueue.
func TestPortForwardSlowOpenOversizeCounted_L37(t *testing.T) {
	gate := func(d time.Duration) func(int, Request) <-chan struct{} {
		return func(int, Request) <-chan struct{} {
			ch := make(chan struct{})
			time.AfterFunc(d, func() { close(ch) })
			return ch
		}
	}
	t.Run("oversize before age", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := newPWWorld(t, pwOpts{pf: pfOpts{mtu: 1223}, gate: gate(1050 * time.Millisecond)})
			w.serve()
			c := w.client()
			start := time.Now()
			pfSend(t, c, pwTagged(1199, 0x90, 0))
			time.Sleep(100 * time.Millisecond)
			edge, small := pwTagged(1198, 0x90, 1), pwTagged(100, 0x90, 2)
			pfSend(t, c, edge)
			pfSend(t, c, small)
			for _, want := range [][]byte{edge, small} {
				got, ok, err := pwRecvWithin(c, 2*time.Second)
				if err != nil || !ok || !bytes.Equal(got, want) {
					t.Fatalf("the %d-byte datagram's echo: ok %v, err %v, %d bytes (%s)", len(want), ok, err, len(got), pwDescribe(pwStatus(w.pf)))
				}
			}
			if took := time.Since(start); took <= ingressQueueAge+50*time.Millisecond {
				t.Fatalf("stimulus: the echo came %v after the first send, want the open to outlast the queue's age (%v)", took, ingressQueueAge)
			}
			st := pwStatus(w.pf)
			if st.MaxPayload != 1198 || st.FirstInOpen != 0 || st.Opened != 1 {
				t.Fatalf("stimulus: MaxPayload %d (want the default budget, 1,198), FirstInOpen %d, Opened %d", st.MaxPayload, st.FirstInOpen, st.Opened)
			}
			if st.TooLarge != 1 || st.TooLargeMax != 1199 || st.DropOpenAge != 0 || st.DropOpenQueue != 0 || st.ToSession != 2 {
				t.Fatalf("TooLarge %d, TooLargeMax %d, DropOpenAge %d, DropOpenQueue %d, ToSession %d; want 1, 1199, 0, 0, 2 (%s)",
					st.TooLarge, st.TooLargeMax, st.DropOpenAge, st.DropOpenQueue, st.ToSession, pwDescribe(st))
			}
			if fl := w.pas.flowOf(0x90); fl == nil || fl.rxCount.Load() != 2 {
				t.Fatal("the target must receive the 1,198-byte and the 100-byte datagrams only")
			}
		})
	})
	t.Run("oversize behind the session's end", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			pwDialHook(t, func(_ []byte, s ingressSession) ingressSession { return &ucEndAtWrite{ingressSession: s} })
			w := newPWWorld(t, pwOpts{pf: pfOpts{mtu: 1223}, gate: gate(200 * time.Millisecond)})
			w.serve()
			c := w.client()
			pfSend(t, c, pwTagged(30, 0x91, 0))   // rides the OPEN
			pfSend(t, c, pwTagged(100, 0x91, 1))  // the flush's first write: the session ends
			pfSend(t, c, pwTagged(1199, 0x91, 2)) // oversize, behind the end
			pfSend(t, c, pwTagged(100, 0x91, 3))  // behind the end
			ucEnded(t, w, "stopped (the session closed)", func(e FlowEnds) uint64 { return e.Stopped })
			st := pwStatus(w.pf)
			if st.FirstInOpen != 1 || st.ToSession != 1 {
				t.Fatalf("stimulus: FirstInOpen %d, ToSession %d; want the first datagram in the OPEN and nothing flushed (%s)", st.FirstInOpen, st.ToSession, pwDescribe(st))
			}
			if st.TooLarge != 1 || st.TooLargeMax != 1199 || st.DropOpenQueue != 2 || st.DropOpenAge != 0 {
				t.Fatalf("TooLarge %d, TooLargeMax %d, DropOpenQueue %d, DropOpenAge %d; want 1, 1199, 2, 0 (%s)",
					st.TooLarge, st.TooLargeMax, st.DropOpenQueue, st.DropOpenAge, pwDescribe(st))
			}
		})
	})
}
