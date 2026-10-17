package l4

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// M6 WP6 (m6-design §A8, §A16.1): PortForward.ServeUDP over real packet
// sessions between two Runtimes in a synctest bubble (the kit of
// pwkit_test.go).

// TestPortForwardDemuxBySource_L38_L70 (M6-D24, M6-D26; L38, L70): 64
// clients of one ingress socket, each with its own source address, send a
// datagram at once: each opens exactly one flow (one session at the
// passive, whose target sees it on its own egress socket), and each gets
// back exactly its own echo — never another client's, so a reply goes to
// the flow's client, not to the socket's latest source. The same sources
// again reuse their flows: no new session, the second datagram reaches the
// same egress socket as the first.
func TestPortForwardDemuxBySource_L38_L70(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newPWWorld(t, pwOpts{})
		w.serve()
		const n = 64
		cs := make([]*rendrtest.DatagramConn, n)
		for i := range cs {
			cs[i] = w.client()
		}
		for round := range 2 {
			for i, c := range cs {
				pfSend(t, c, pwTagged(40+i, byte(i), round))
			}
			for i, c := range cs {
				pfExpect(t, c, pwTagged(40+i, byte(i), round))
			}
			pwNoneAll(t, cs...)
		}
		opens, _, firstSent, flows := w.pas.snapshot()
		if opens != n || len(flows) != n || firstSent != n {
			t.Fatalf("the passive served %d OPENs, %d flows, %d first datagrams; want %d each", opens, len(flows), firstSent, n)
		}
		for _, fl := range flows {
			rx := fl.received()
			if len(rx) != 2 || tagOf(rx[0]) != tagOf(rx[1]) || pwSeq(rx[0]) != 0 || pwSeq(rx[1]) != 1 {
				t.Fatalf("egress flow %d received %d datagrams (tags %v): want one source's two datagrams in order", fl.id, len(rx), pwTags(rx))
			}
		}
		st := pwStatus(w.pf)
		if st.Opened != n || st.Flows != n || st.ToSession != 2*n || st.ToClient != 2*n || st.FirstInOpen != n || st.Failed != 0 {
			t.Fatalf("status %s", pwDescribe(st))
		}
		pwUnits(t, w.pf)
		if err := w.stop(); !errors.Is(err, context.Canceled) {
			t.Fatalf("ServeUDP returned %v after its ctx ended, want context.Canceled", err)
		}
		if st := pwStatus(w.pf); st.Flows != 0 || st.Ended.Stopped != n || w.pf.flows.Load() != 0 {
			t.Fatalf("after the stop: %s, %d units", pwDescribe(st), w.pf.flows.Load())
		}
	})
}

func pwTags(rx [][]byte) []byte {
	var out []byte
	for _, b := range rx {
		out = append(out, tagOf(b))
	}
	return out
}

// pwRoundTrip sends b from c until its echo arrives (every 100 ms, at most
// for d) and reports whether it did; stale echoes of earlier tries are
// read past.
func pwRoundTrip(t testing.TB, c *rendrtest.DatagramConn, b []byte, d time.Duration) bool {
	t.Helper()
	for end := time.Now().Add(d); time.Now().Before(end); {
		pfSend(t, c, b)
		for {
			got, ok, err := pwRecvWithin(c, 100*time.Millisecond)
			if err != nil {
				t.Fatalf("client read: %v", err)
			}
			if !ok {
				break
			}
			if bytes.Equal(got, b) {
				return true
			}
		}
	}
	return false
}

// TestPortForwardOneSessionAcrossKills_L10_L27_L70 (M6-D12, A5.2; L10,
// L27, L70): one flow over two datagram links, in each mode, survives six
// carrier kills (each of a link that carries the flow, stimulus proved by
// the links' Killed counters): after each kill the flow's datagrams cross
// both ways again, and through the whole row the passive served exactly
// one session and its target saw every datagram on the same egress socket
// (one pwFlow): no carrier event ever re-opens the flow at the ingress
// (Opened 1, Replaced 0, no end).
func TestPortForwardOneSessionAcrossKills_L10_L27_L70(t *testing.T) {
	for _, mode := range []rendr.Mode{rendr.ModeSelector, rendr.ModeBond, rendr.ModeRace} {
		t.Run(mode.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newPWWorld(t, pwOpts{pf: pfOpts{links: 2}, pfwd: func(f *PortForward) { f.Options.Mode = mode }})
				w.serve()
				c := w.client()
				k := 0
				next := func() []byte { k++; return pwTagged(64, 0x51, k) }
				if !pwRoundTrip(t, c, next(), 5*time.Second) {
					t.Fatal("the flow did not open")
				}
				killed := uint64(0)
				for i := range 6 {
					time.Sleep(3 * time.Second) // the redialled carriers join
					l := w.links[i%2]
					before := l.Stats().Session.Killed
					l.Kill()
					if l.Stats().Session.Killed == before {
						l = w.links[(i+1)%2]
						l.Kill()
					}
					killed++
					for range 5 {
						if !pwRoundTrip(t, c, next(), 10*time.Second) {
							t.Fatalf("kill %d: the flow does not carry datagrams any more: %s", i+1, pwDescribe(pwStatus(w.pf)))
						}
					}
				}
				var dead uint64
				for _, l := range w.links {
					dead += l.Stats().Session.Killed
				}
				if dead < killed {
					t.Fatalf("stimulus: %d session carriers killed, want at least %d", dead, killed)
				}
				opens, _, _, flows := w.pas.snapshot()
				st := pwStatus(w.pf)
				if opens != 1 || len(flows) != 1 || st.Opened != 1 || st.Replaced != 0 || st.Ended != (FlowEnds{}) || st.Flows != 1 {
					t.Fatalf("the passive served %d OPENs (%d flows); ingress %s", opens, len(flows), pwDescribe(st))
				}
				if got := flows[0].rxCount.Load(); got < int64(k) {
					t.Fatalf("the egress socket received %d datagrams, want all %d (each sent at least once)", got, k)
				}
			})
		})
	}
}

// TestPortForwardOpenQueue_L40 (M6-D27, R1-13, R1-15; L40): the datagrams
// of an opening flow (its OPEN held pending at the passive by a gate) wait
// in its entry and are flushed in order once it opens: at most 8 of them,
// and at most 16 KiB charged at the copies' pool classes (512 B, 2 KiB,
// 16 KiB, 64 KiB), the oldest dropped first (DropOpenQueue); one whose
// class alone exceeds 16 KiB is dropped without touching the others; at
// the flush a datagram queued more than 1 s ago is DropOpenAge (a first
// datagram that rode the OPEN is outside that rule; one that did not ride
// follows it). Every client datagram is delivered or counted exactly once.
func TestPortForwardOpenQueue_L40(t *testing.T) {
	type send struct {
		n     int           // size
		after time.Duration // sleep before it
	}
	rows := []struct {
		name      string
		first     int // the first datagram's size
		sends     []send
		wait      time.Duration // after the last send, before the gate opens
		want      []int         // the sequence numbers the target receives after the first (k of pwTagged)
		firstGets bool          // the first datagram reaches the target
		queue     uint64        // DropOpenQueue
		age       uint64        // DropOpenAge
	}{
		{"8 of 10", 20, rep(10, send{n: 30}), 0, []int{3, 4, 5, 6, 7, 8, 9, 10}, true, 2, 0},
		{"pool classes", 20, rep(7, send{n: 2049}), 0, []int{7}, true, 6, 0},
		{"2 KiB class fits 8", 20, rep(8, send{n: 2048}), 0, []int{1, 2, 3, 4, 5, 6, 7, 8}, true, 0, 0},
		{"one above 16 KiB", 20, []send{{n: 100}, {n: 16385}, {n: 100}}, 0, []int{1, 3}, true, 1, 0},
		{"age", 20, []send{{n: 50}, {n: 50}, {n: 50, after: 600 * time.Millisecond}, {n: 50}}, 600 * time.Millisecond, []int{3, 4}, true, 0, 2},
		{"a first that does not ride ages", 600, []send{{n: 50, after: 600 * time.Millisecond}}, 600 * time.Millisecond, []int{1}, false, 0, 1},
		{"a first that rides does not age", 20, nil, 1500 * time.Millisecond, nil, true, 0, 0},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				gate := make(chan struct{})
				w := newPWWorld(t, pwOpts{pf: pfOpts{mtu: 9000}, target: pwSink, gate: func(int, Request) <-chan struct{} { return gate }})
				w.serve()
				c := w.client()
				pfSend(t, c, pwTagged(r.first, 0x60, 0))
				synctest.Wait()
				for i, s := range r.sends {
					time.Sleep(s.after)
					pfSend(t, c, pwTagged(s.n, 0x60, i+1))
				}
				time.Sleep(r.wait)
				synctest.Wait()
				if st := pwStatus(w.pf); st.Opening != 1 || st.Flows != 0 {
					t.Fatalf("before the gate: %s", pwDescribe(st))
				}
				close(gate)
				time.Sleep(time.Second)
				_, _, _, flows := w.pas.snapshot()
				if len(flows) != 1 {
					t.Fatalf("%d flows at the passive", len(flows))
				}
				rx := flows[0].received()
				var got []int
				gotFirst := false
				for _, b := range rx {
					if pwSeq(b) == 0 {
						gotFirst = true
						continue
					}
					got = append(got, pwSeq(b))
				}
				if !equalInts(got, r.want) || gotFirst != r.firstGets {
					t.Fatalf("the target received %v (the first: %v), want %v (the first: %v)", got, gotFirst, r.want, r.firstGets)
				}
				st := pwStatus(w.pf)
				if st.DropOpenQueue != r.queue || st.DropOpenAge != r.age {
					t.Fatalf("DropOpenQueue %d, DropOpenAge %d; want %d and %d (%s)", st.DropOpenQueue, st.DropOpenAge, r.queue, r.age, pwDescribe(st))
				}
				sent := uint64(1 + len(r.sends))
				if acc := st.ToSession + st.DropOpenQueue + st.DropOpenAge + st.TooLarge; acc != sent || uint64(len(rx)) != st.ToSession {
					t.Fatalf("accounting: %d sent, %d delivered, %d counted (%s), the target got %d", sent, st.ToSession, acc-st.ToSession, pwDescribe(st), len(rx))
				}
			})
		})
	}
}

func rep[T any](n int, v T) []T {
	out := make([]T, n)
	for i := range out {
		out[i] = v
	}
	return out
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestPortForwardFirstInOpenSavesRTT (M6-D4; L37): a first datagram that
// rides the OPEN saves the flow one round trip (two one-way delays, synctest
// exact) against a 600-byte one that cannot ride and follows the open:
//   - cold (the flow's OPEN dials the carrier: PREFACE and OPEN in one
//     datagram), a target that answers at once: the echo arrives one round
//     trip earlier;
//   - warm (the flow's session joins the live datagram trunk), a target
//     that answers after 50 ms (a resolver's lookup): the first datagram
//     reaches the target, and the echo the client, one round trip earlier;
//   - warm, a target that answers at once: the first datagram reaches the
//     target one round trip earlier; the echo is never later riding, its
//     saving logged only: a passive packet session on a shared trunk sends
//     its first datagram after the dialer's first frame behind OPEN_ACK has
//     arrived (1.5 round trips after the OPEN; core behaviour, M3), so such
//     an answer reaches the client two round trips after the client's
//     datagram either way (an open item for G11-dns's criterion).
//
// FirstInOpen counts the riding first datagrams, and the passive wrote
// exactly those to their targets before Confirm.
func TestPortForwardFirstInOpenSavesRTT(t *testing.T) {
	for _, r := range []struct {
		name   string
		warm   bool
		answer time.Duration
	}{{"cold", false, 0}, {"warm, slow answer", true, 50 * time.Millisecond}, {"warm, instant answer", true, 0}} {
		t.Run(r.name, func(t *testing.T) {
			first := func(n int, tag byte) (atTarget, echo time.Duration, firstInOpen uint64, firstSent int) {
				synctest.Test(t, func(t *testing.T) {
					var mu sync.Mutex
					arrived := map[byte]time.Time{}
					w := newPWWorld(t, pwOpts{target: func(fl *pwFlow) {
						buf := make([]byte, 64<<10)
						for {
							k, err := fl.app.Read(buf)
							if err != nil {
								return
							}
							mu.Lock()
							if _, ok := arrived[tagOf(buf[:k])]; !ok {
								arrived[tagOf(buf[:k])] = time.Now()
							}
							mu.Unlock()
							fl.record(buf[:k])
							time.Sleep(r.answer)
							fl.app.Write(buf[:k])
						}
					}})
					w.serve()
					if r.warm {
						if !pwRoundTrip(t, w.client(), pwTagged(30, 0x70, 0), 5*time.Second) {
							t.Fatal("warm-up flow did not open")
						}
						time.Sleep(time.Second)
					}
					c := w.client()
					start := time.Now()
					b := pwTagged(n, tag, 0)
					pfSend(t, c, b)
					pfExpect(t, c, b)
					echo = time.Since(start)
					mu.Lock()
					atTarget = arrived[tag].Sub(start)
					mu.Unlock()
					_, _, firstSent, _ = w.pas.snapshot()
					firstInOpen = pwStatus(w.pf).FirstInOpen
				})
				return
			}
			rideAt, rideEcho, rideFIO, rideSent := first(100, 0x71)
			followAt, followEcho, followFIO, followSent := first(600, 0x72)
			t.Logf("at the target %v riding, %v following; echo %v riding, %v following", rideAt, followAt, rideEcho, followEcho)
			warm := map[bool]uint64{true: 1, false: 0}[r.warm]
			if rideFIO != 1+warm || followFIO != warm || rideSent != int(1+warm) || followSent != int(warm) {
				t.Fatalf("FirstInOpen %d and %d, the passive's first datagrams %d and %d", rideFIO, followFIO, rideSent, followSent)
			}
			if followAt-rideAt != 2*pfOneWay {
				t.Fatalf("the first datagram reached the target %v (riding) and %v (following) after it was sent: want exactly one round trip (%v) saved", rideAt, followAt, 2*pfOneWay)
			}
			if (!r.warm || r.answer > 0) && followEcho-rideEcho != 2*pfOneWay {
				t.Fatalf("the first echo took %v riding and %v following the open: want exactly one round trip (%v) saved", rideEcho, followEcho, 2*pfOneWay)
			}
			if rideEcho > followEcho {
				t.Fatalf("the first echo took %v riding and %v following the open: riding must never cost time", rideEcho, followEcho)
			}
		})
	}
}

// TestPortForwardTooLarge_L37_L71 (M6-D32, A4.3, R1-9; L37, L71): a client
// datagram above the flow's MaxPayload (1,375 here) is dropped and counted
// where it was read, whole (TooLarge; TooLargeMax is the largest size,
// exact, since the ingress reads 64 KiB); the flow lives and the next
// datagram crosses. The same when it is a new client's first datagram: it
// cannot ride, so it is the entry's first queued datagram, counted at the
// flush, and the flow opens and carries the next datagram.
func TestPortForwardTooLarge_L37_L71(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newPWWorld(t, pwOpts{})
		w.serve()
		c := w.client()
		if !pwRoundTrip(t, c, pwTagged(100, 0x80, 0), 5*time.Second) {
			t.Fatal("the flow did not open")
		}
		mp := pwStatus(w.pf).MaxPayload
		if mp != pfMTU-25 {
			t.Fatalf("MaxPayload %d, want %d", mp, pfMTU-25)
		}
		pfSend(t, c, pwTagged(mp, 0x80, 1))
		pfExpect(t, c, pwTagged(mp, 0x80, 1))
		pfSend(t, c, pwTagged(mp+1, 0x80, 2))
		pfSend(t, c, pwTagged(60000, 0x80, 3))
		pfSend(t, c, pwTagged(3000, 0x80, 4))
		pfSend(t, c, pwTagged(10, 0x80, 5))
		pfExpect(t, c, pwTagged(10, 0x80, 5))
		if st := pwStatus(w.pf); st.TooLarge != 3 || st.TooLargeMax != 60000 || st.Flows != 1 || st.Opened != 1 {
			t.Fatalf("after three oversize datagrams: %s", pwDescribe(st))
		}
		// A new client's first datagram is oversize.
		c2 := w.client()
		pfSend(t, c2, pwTagged(2000, 0x81, 0))
		pfSend(t, c2, pwTagged(10, 0x81, 1))
		pfExpect(t, c2, pwTagged(10, 0x81, 1))
		st := pwStatus(w.pf)
		if st.TooLarge != 4 || st.TooLargeMax != 60000 || st.Flows != 2 || st.Opened != 2 || st.FirstInOpen != 1 {
			t.Fatalf("after an oversize first datagram: %s", pwDescribe(st))
		}
		_, _, _, flows := w.pas.snapshot()
		for _, fl := range flows {
			for _, b := range fl.received() {
				if len(b) > mp {
					t.Fatalf("a %d-byte datagram reached the target", len(b))
				}
			}
		}
	})
}

// TestPortForwardIdleReopen_L58_L70 (M6-D11, A5.3; L58, L70): a flow that
// ended at its idle limit (here 10 s) leaves the table, and the same
// client's next datagram opens a new session — a new egress socket at the
// target — and crosses: a dead flow is never reattached.
func TestPortForwardIdleReopen_L58_L70(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newPWWorld(t, pwOpts{pfwd: func(f *PortForward) { f.Idle = FlowIdle{Short: 10 * time.Second, Stream: 10 * time.Second} }})
		w.serve()
		c := w.client()
		if !pwRoundTrip(t, c, pwTagged(40, 0x90, 0), 5*time.Second) {
			t.Fatal("the flow did not open")
		}
		// The end comes 10 s after the last datagram, up to PacketPing later
		// (the idle clock follows a received datagram lazily).
		if took, ok := pwWaitFor(15*time.Second, func() bool { return pwStatus(w.pf).Ended.Idle == 1 }); !ok || took < 10*time.Second || pwStatus(w.pf).Flows != 0 {
			t.Fatalf("after %v idle: %s", took, pwDescribe(pwStatus(w.pf)))
		}
		if n, _ := pwEntries(w.pf); n != 0 {
			t.Fatalf("%d entries left after the idle end", n)
		}
		pfSend(t, c, pwTagged(40, 0x90, 1))
		pfExpect(t, c, pwTagged(40, 0x90, 1))
		opens, _, _, flows := w.pas.snapshot()
		if opens != 2 || len(flows) != 2 || flows[1].rxCount.Load() != 1 || flows[0].rxCount.Load() != 1 {
			t.Fatalf("the passive served %d OPENs and %d flows: want a second session for the second datagram", opens, len(flows))
		}
		if st := pwStatus(w.pf); st.Opened != 2 || st.Flows != 1 {
			t.Fatalf("after the reopen: %s", pwDescribe(st))
		}
	})
}

// TestPortForwardSourceChurn_L70 (M6-D24, A5.2; L70, L72): a client that
// moves to a new source port every second for 60 s (40 s in the race
// lane), sending 10 datagrams a second, gets one flow per port (one open
// each, each its own egress socket);
// the old flows end at their Short limit (30 s: one exchange a second for
// a second never makes a stream under the rule in force), so the table
// stays bounded (at most 32 entries at any second); at least 99 % of the
// datagrams cross both ways.
func TestPortForwardSourceChurn_L70(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newPWWorld(t, pwOpts{})
		w.serve()
		ports, per := 60, 10
		if raceEnabled {
			ports = 40 // racebudget: still 8 ports beyond the 32 entries the table may hold
		}
		sent, back := 0, 0
		maxEntries := 0
		for p := range ports {
			c := w.hub.Client(pwSrc(1000 + p))
			for k := range per {
				pfSend(t, c, pwTagged(80, byte(p), k))
				sent++
				time.Sleep(100 * time.Millisecond)
				for {
					_, ok, err := pwRecvWithin(c, time.Millisecond)
					if err != nil {
						t.Fatal(err)
					}
					if !ok {
						break
					}
					back++
				}
			}
			n, _ := pwEntries(w.pf)
			maxEntries = max(maxEntries, n)
			c.Close()
		}
		opens, _, _, flows := w.pas.snapshot()
		var at int64
		for _, fl := range flows {
			at += fl.rxCount.Load()
		}
		st := pwStatus(w.pf)
		t.Logf("%d sent, %d at the targets, %d echoes read; table at most %d entries; %s", sent, at, back, maxEntries, pwDescribe(st))
		if opens != ports || st.Opened != uint64(ports) {
			t.Fatalf("%d OPENs at the passive, %d opened: want one flow per port (%d)", opens, st.Opened, ports)
		}
		if maxEntries > 32 || st.Ended.Idle < uint64(ports-32) {
			t.Fatalf("table at most %d entries, %d idle ends: want the old flows gone at Short", maxEntries, st.Ended.Idle)
		}
		if float64(at) < 0.99*float64(sent) || float64(back) < 0.99*float64(sent) {
			t.Fatalf("delivery: %d of %d to the targets, %d back", at, sent, back)
		}
	})
}

// TestPortForwardLoopbackOnly (M6-D22, plan:58, M4-D44): a socket bound to
// a non-loopback or unspecified address is refused with ErrNonLoopback
// before the first read, its socket closed, unless AllowNonLoopback; IPv4
// and IPv6 loopback (an IPv4-mapped one too) and, for ServeTCP's check, a
// Unix-domain address are accepted.
func TestPortForwardLoopbackOnly(t *testing.T) {
	rows := []struct {
		addr string
		ok   bool
	}{
		{"127.0.0.1:40000", true}, {"127.1.2.3:40000", true}, {"[::1]:40000", true}, {"[::ffff:127.0.0.1]:40000", true},
		{"192.0.2.1:40000", false}, {"0.0.0.0:40000", false}, {"[::]:40000", false}, {"[2001:db8::1]:40000", false},
	}
	for _, r := range rows {
		for _, allow := range []bool{false, true} {
			synctest.Test(t, func(t *testing.T) {
				w := newPWWorld(t, pwOpts{hub: rendrtest.UDPSocketHubConfig{Addr: netip.MustParseAddrPort(r.addr)},
					pfwd: func(f *PortForward) { f.AllowNonLoopback = allow },
					wrap: func(s UDPSocket) UDPSocket { return &pwCountSock{UDPSocket: s} }})
				w.serve()
				synctest.Wait()
				cs := w.sock.(*pwCountSock)
				if !r.ok && !allow {
					var err error
					select {
					case err = <-w.served:
						w.served = nil
					default:
						t.Fatalf("%s: ServeUDP serves a non-loopback socket without AllowNonLoopback (%d reads)", r.addr, cs.reads.Load())
					}
					if !errors.Is(err, ErrNonLoopback) || cs.closes.Load() != 1 || cs.reads.Load() != 0 {
						t.Fatalf("%s: ServeUDP = %v, %d Closes, %d reads; want ErrNonLoopback, closed once before any read", r.addr, err, cs.closes.Load(), cs.reads.Load())
					}
					return
				}
				// Accepted: it reads and forwards.
				c := w.client()
				if !pwRoundTrip(t, c, pwTagged(20, 1, 0), 5*time.Second) {
					t.Fatalf("%s (allow %v): no forwarding", r.addr, allow)
				}
				if err := w.stop(); !errors.Is(err, context.Canceled) || cs.closes.Load() != 1 {
					t.Fatalf("%s: ServeUDP = %v, %d Closes", r.addr, err, cs.closes.Load())
				}
			})
		}
	}
	// The check itself, for both Serve calls' address kinds.
	for _, r := range []struct {
		a  net.Addr
		ok bool
	}{
		{&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 80}, true},
		{&net.TCPAddr{IP: net.IPv6loopback, Port: 80}, true},
		{&net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 80}, false},
		{&net.TCPAddr{IP: net.IPv4zero, Port: 80}, false},
		{&net.TCPAddr{Port: 80}, false},
		{&net.UnixAddr{Name: "/run/x.sock", Net: "unix"}, true},
		{(*net.TCPAddr)(nil), false},
		{nil, false},
	} {
		if got := (&PortForward{}).checkIngress(r.a); (got == nil) != r.ok || (got != nil && !errors.Is(got, ErrNonLoopback)) {
			t.Errorf("checkIngress(%v) = %v, want ok %v", r.a, got, r.ok)
		}
		if got := (&PortForward{AllowNonLoopback: true}).checkIngress(r.a); got != nil {
			t.Errorf("checkIngress(%v) with AllowNonLoopback = %v", r.a, got)
		}
	}
	// Real sockets: the checks run before the first read, so a cancelled
	// ctx shows which socket passed them.
	pf := &PortForward{Peer: &rendr.Peer{}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, r := range []struct {
		addr string
		ok   bool
	}{{"127.0.0.1:0", true}, {"0.0.0.0:0", false}} {
		uc, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort(r.addr)))
		if err != nil {
			t.Fatal(err)
		}
		err = pf.ServeUDP(ctx, uc, pfTarget)
		if want := map[bool]error{true: context.Canceled, false: ErrNonLoopback}[r.ok]; !errors.Is(err, want) {
			t.Errorf("real socket on %s: ServeUDP = %v, want %v", r.addr, err, want)
		}
		if uc.SetReadDeadline(time.Time{}) == nil {
			t.Errorf("real socket on %s: not closed by ServeUDP", r.addr)
		}
	}
}

// pwConnectedSock is a hub socket that reports a remote address.
type pwConnectedSock struct {
	UDPSocket
	raddr net.Addr
}

func (s *pwConnectedSock) RemoteAddr() net.Addr { return s.raddr }

// TestPortForwardConnectedRefused (M6-D22, R1-19; L57): a socket whose
// RemoteAddr method reports an address is connected and refused before
// the first read (closed once); a nil RemoteAddr — the hub's, or a typed
// nil *net.UDPAddr — is an unconnected socket; a real connected
// *net.UDPConn is refused. An invalid target, or no Peer, fails before any
// check of the socket, which is closed as well.
func TestPortForwardConnectedRefused(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pf := &PortForward{Peer: &rendr.Peer{}}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		for _, r := range []struct {
			name  string
			raddr net.Addr
			err   error
		}{
			{"connected", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}, errConnectedSocket},
			{"typed nil", (*net.UDPAddr)(nil), context.Canceled},
			{"nil", nil, context.Canceled},
		} {
			hub := rendrtest.NewUDPSocketHub(rendrtest.UDPSocketHubConfig{})
			cs := &pwCountSock{UDPSocket: hub.Socket()}
			if err := pf.ServeUDP(ctx, &pwConnectedSock{UDPSocket: cs, raddr: r.raddr}, pfTarget); !errors.Is(err, r.err) || cs.closes.Load() != 1 {
				t.Errorf("%s: ServeUDP = %v, %d Closes; want %v", r.name, err, cs.closes.Load(), r.err)
			}
			if r.err == errConnectedSocket && cs.reads.Load() != 0 {
				t.Errorf("%s: %d reads before the refusal", r.name, cs.reads.Load())
			}
		}
		for _, r := range []struct {
			name   string
			pf     *PortForward
			target string
			err    error
		}{
			{"no peer", &PortForward{}, pfTarget, errNoPeer},
			{"bad target", pf, "no-port", ErrBadAddress},
			{"port 0", pf, "192.0.2.1:0", ErrBadAddress},
		} {
			hub := rendrtest.NewUDPSocketHub(rendrtest.UDPSocketHubConfig{})
			cs := &pwCountSock{UDPSocket: hub.Socket()}
			if err := r.pf.ServeUDP(ctx, cs, r.target); !errors.Is(err, r.err) || cs.closes.Load() != 1 || cs.reads.Load() != 0 {
				t.Errorf("%s: ServeUDP = %v, %d Closes, %d reads; want %v", r.name, err, cs.closes.Load(), cs.reads.Load(), r.err)
			}
		}
	})
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	uc, err := net.DialUDP("udp4", nil, srv.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := (&PortForward{Peer: &rendr.Peer{}}).ServeUDP(ctx, uc, pfTarget); !errors.Is(err, errConnectedSocket) {
		t.Errorf("a connected *net.UDPConn: ServeUDP = %v, want refused", err)
	}
	if uc.SetReadDeadline(time.Time{}) == nil {
		t.Error("the connected socket was not closed")
	}
}

// TestPortForwardMaxFlowsDefault (R1-19): MaxFlows 0 or negative is
// DefaultMaxFlows (4,096), a positive value is used as given (no upper
// clamp); the same for MaxConns' default.
func TestPortForwardMaxFlowsDefault(t *testing.T) {
	for _, r := range []struct{ in, want int }{{0, DefaultMaxFlows}, {-1, DefaultMaxFlows}, {1, 1}, {64, 64}, {100000, 100000}} {
		if got := (&PortForward{MaxFlows: r.in}).maxFlows(); got != r.want {
			t.Errorf("MaxFlows %d → %d, want %d", r.in, got, r.want)
		}
	}
	if DefaultMaxFlows != 4096 {
		t.Errorf("DefaultMaxFlows = %d, want 4096", DefaultMaxFlows)
	}
	if got := (&PortForward{}).maxConns(); got != DefaultMaxConns {
		t.Errorf("MaxConns 0 → %d, want %d", got, DefaultMaxConns)
	}
}

// TestPortForwardFlowsSnapshot (M6-D30, R1-22): Flows reports every table
// entry — opening (its OPEN held at the passive), open (a stream after a
// 3-s exchange, with its SessionStatus), held (refused) — with its client,
// target, state, class and times; Status counts the same states.
func TestPortForwardFlowsSnapshot(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate := make(chan struct{})
		w := newPWWorld(t, pwOpts{
			decide: func(_ int, r Request) RejectCode {
				if tagOf(r.First) == 0xA3 {
					return CodeNotAllowed
				}
				return 0
			},
			gate: func(_ int, r Request) <-chan struct{} {
				if tagOf(r.First) == 0xA2 {
					return gate
				}
				return nil
			},
		})
		start := time.Now()
		w.serve()
		open, opening, held := w.client(), w.client(), w.client()
		for k := range 7 {
			if !pwRoundTrip(t, open, pwTagged(30, 0xA1, k), time.Second) {
				t.Fatal("the open flow did not answer")
			}
			time.Sleep(500 * time.Millisecond)
		}
		pfSend(t, opening, pwTagged(30, 0xA2, 0))
		pfSend(t, held, pwTagged(30, 0xA3, 0))
		time.Sleep(100 * time.Millisecond)
		fs := w.pf.Flows()
		by := map[netip.AddrPort]FlowInfo{}
		for _, fi := range fs {
			by[fi.Client] = fi
		}
		addr := func(c *rendrtest.DatagramConn) netip.AddrPort { return c.LocalAddr().(*net.UDPAddr).AddrPort() }
		o, g, h := by[addr(open)], by[addr(opening)], by[addr(held)]
		if len(fs) != 3 || o.State != FlowOpen || g.State != FlowOpening || h.State != FlowHeld {
			t.Fatalf("Flows: %+v", fs)
		}
		if !o.Stream || g.Stream || h.Stream || o.Target != pfTarget || g.Target != pfTarget {
			t.Fatalf("classes or targets: open %+v, opening %+v, held %+v", o, g, h)
		}
		if o.Session.ID == (rendr.SessionID{}) || o.Session.Kind != rendr.KindPacket || g.Session.ID != (rendr.SessionID{}) || h.Session.ID != (rendr.SessionID{}) {
			t.Fatalf("sessions: open %+v, opening %+v, held %+v", o.Session.ID, g.Session.ID, h.Session.ID)
		}
		if !o.Since.Equal(start) || !o.Last.After(o.Since.Add(3*time.Second)) || !g.Since.After(o.Last) || g.Last != g.Since {
			t.Fatalf("times: open %v–%v, opening %v–%v (start %v)", o.Since, o.Last, g.Since, g.Last, start)
		}
		st := pwStatus(w.pf)
		if st.Flows != 1 || st.Opening != 1 || st.Held != 1 || st.Failed != 1 || st.ByCode[CodeNotAllowed] != 1 {
			t.Fatalf("status: %s", pwDescribe(st))
		}
		var re *rendr.RejectError
		if !errors.As(st.LastErr, &re) {
			t.Fatalf("LastErr %v, want the *RejectError", st.LastErr)
		}
		close(gate)
	})
}

// TestPortForwardOldPassive_L49 (PA-89, R1-3; L49): a passive that never
// serves packet sessions (a Server without UDP, a v2.0.0 l4.Serve: no
// AcceptPacket) answers the first OPEN CAPACITY at its AcceptTimeout
// (10 s): the ingress sees ErrCapacity at 10 s, inside its 12-s open
// bound, and holds the source for 5 s, so a client retransmitting every
// 100 ms for 30 s costs two OPENs (at 0 s and after the hold, ≈ 15 s), not
// a storm; its datagrams meanwhile are queued (aged) or DropHeld.
func TestPortForwardOldPassive_L49(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newPWWorld(t, pwOpts{noAccept: true, pf: pfOpts{ov: func(ov *testhooks.Overrides) { ov.NoPathGrace = 15 * time.Second }}})
		w.serve()
		c := w.client()
		start := time.Now()
		var failedAt time.Duration
		for time.Since(start) < 30*time.Second {
			pfSend(t, c, pwTagged(30, 0xB0, 0))
			time.Sleep(100 * time.Millisecond)
			if failedAt == 0 && pwStatus(w.pf).Failed == 1 {
				failedAt = time.Since(start)
			}
		}
		st := pwStatus(w.pf)
		t.Logf("first failure at %v; %s", failedAt, pwDescribe(st))
		if failedAt < 10*time.Second || failedAt > 10*time.Second+200*time.Millisecond {
			t.Fatalf("the first open failed at %v, want at the passive's AcceptTimeout (10 s)", failedAt)
		}
		if !errors.Is(st.LastErr, rendr.ErrCapacity) || st.Failed != 2 || st.Opened != 0 || st.DropHeld == 0 {
			t.Fatalf("status %s: want two ErrCapacity failures and held datagrams", pwDescribe(st))
		}
	})
}
