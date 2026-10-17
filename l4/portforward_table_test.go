package l4

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// M6 WP6 (m6-design §A8.5, §A8.6, §A12, §A16.1): the full table under both
// rules of O-1 (R1-7: promoteOnReply, the owner's literal rule, through
// the test hook; promoteActive, O-1 (a), the rule in force since the
// delegate decision of 2026-10-17), holds and the reopen rate limit.

// pwAddr is a hub client's source address.
func pwAddr(c *rendrtest.DatagramConn) netip.AddrPort { return c.LocalAddr().(*net.UDPAddr).AddrPort() }

// pwFill opens one flow per client (its first datagram tagged tag, k 0)
// and waits until every one is open.
func pwFill(t testing.TB, w *pwWorld, cs []*rendrtest.DatagramConn, tag byte) {
	t.Helper()
	for _, c := range cs {
		pfSend(t, c, pwTagged(30, tag, 0))
	}
	start := time.Now()
	for time.Since(start) < 5*time.Second {
		if _, by := pwEntries(w.pf); by[FlowOpen] >= len(cs) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // the answers (echo targets) are back
	if _, by := pwEntries(w.pf); by[FlowOpen] < len(cs) {
		t.Fatalf("%d of %d flows open: %s", by[FlowOpen], len(cs), pwDescribe(pwStatus(w.pf)))
	}
}

// pwClients returns n fresh hub clients.
func pwClients(w *pwWorld, n int) []*rendrtest.DatagramConn {
	cs := make([]*rendrtest.DatagramConn, n)
	for i := range cs {
		cs[i] = w.client()
	}
	return cs
}

// pwSnapshot maps the table's clients to their FlowInfo.
func pwSnapshot(f *PortForward) map[netip.AddrPort]FlowInfo {
	m := map[netip.AddrPort]FlowInfo{}
	for _, fi := range f.Flows() {
		m[fi.Client] = fi
	}
	return m
}

// pwPeerClosed counts the kit passive's flows whose forward ended with
// io.EOF (the ingress closed the flow: an eviction or a stop).
func pwPeerClosed(p *pwPassive) (ended, eof int) {
	_, _, _, flows := p.snapshot()
	for _, fl := range flows {
		select {
		case r := <-fl.res:
			ended++
			if errors.Is(r.SessionErr, io.EOF) {
				eof++
			}
			fl.res <- r
		default:
		}
	}
	return ended, eof
}

// TestPortForwardFullRefuses_L48_L72 (M6-D29, R1-7; L48, L72): under the
// owner's literal rule (promoteOnReply) a full table refuses new flows and
// never ends a session to make room. A table of 64 full of open flows that
// never saw a reply (so neither streams nor recently active: the flows a
// promoteActive table may evict): a flood of 200 new sources is DropFull
// exactly, no open flow ends (no Evicted, no end at the passive), and every
// open flow still carries its next datagram. A held entry makes room: in a
// table of 8 (the sample covers it) with 7 open flows and one refused
// source, a newcomer takes the held entry's place (an early end of its
// hold, not an eviction), and the next newcomer is DropFull again.
func TestPortForwardFullRefuses_L48_L72(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pfRule(t, promoteOnReply)
		w := newPWWorld(t, pwOpts{target: pwSink, pfwd: func(f *PortForward) { f.MaxFlows = 64 }})
		w.serve()
		cs := pwClients(w, 64)
		pwFill(t, w, cs, 0x10)
		time.Sleep(2 * time.Second) // every flow idle ≥ 1 s
		for i := range 200 {
			c := w.client()
			pfSend(t, c, pwTagged(30, 0x11, i))
			time.Sleep(10 * time.Millisecond)
		}
		synctest.Wait()
		st := pwStatus(w.pf)
		if st.DropFull != 200 || st.Evicted != 0 || st.Flows != 64 || st.Opened != 64 || st.Ended != (FlowEnds{}) {
			t.Fatalf("after the flood: %s", pwDescribe(st))
		}
		if ended, _ := pwPeerClosed(w.pas); ended != 0 {
			t.Fatalf("%d flows ended at the passive during the flood", ended)
		}
		for i, c := range cs {
			pfSend(t, c, pwTagged(30, 0x10, 1+i))
		}
		time.Sleep(100 * time.Millisecond)
		_, _, _, flows := w.pas.snapshot()
		for _, fl := range flows {
			if fl.rxCount.Load() != 2 {
				t.Fatalf("an open flow's target received %d datagrams after the flood, want 2", fl.rxCount.Load())
			}
		}
		pwUnits(t, w.pf)
	})
	synctest.Test(t, func(t *testing.T) {
		pfRule(t, promoteOnReply)
		w := newPWWorld(t, pwOpts{target: pwSink, pfwd: func(f *PortForward) { f.MaxFlows = 8 },
			decide: func(_ int, r Request) RejectCode {
				if tagOf(r.First) == 0x13 {
					return CodeNotAllowed
				}
				return 0
			}})
		w.serve()
		pwFill(t, w, pwClients(w, 7), 0x12)
		refused := w.client()
		pfSend(t, refused, pwTagged(30, 0x13, 0))
		time.Sleep(100 * time.Millisecond)
		if st := pwStatus(w.pf); st.Held != 1 || st.Flows != 7 {
			t.Fatalf("before the newcomer: %s", pwDescribe(st))
		}
		newcomer := w.client()
		pfSend(t, newcomer, pwTagged(30, 0x14, 0))
		time.Sleep(100 * time.Millisecond)
		snap := pwSnapshot(w.pf)
		if fi, ok := snap[pwAddr(newcomer)]; !ok || fi.State != FlowOpen {
			t.Fatalf("the newcomer did not take the held entry's place: %+v", snap)
		}
		if _, ok := snap[pwAddr(refused)]; ok {
			t.Fatal("the held entry is still in the table")
		}
		st := pwStatus(w.pf)
		if st.Held != 0 || st.Flows != 8 || st.Evicted != 0 || st.DropFull != 0 || st.Opened != 8 {
			t.Fatalf("after the newcomer: %s", pwDescribe(st))
		}
		pfSend(t, w.client(), pwTagged(30, 0x15, 0))
		synctest.Wait()
		if st := pwStatus(w.pf); st.DropFull != 1 || st.Flows != 8 {
			t.Fatalf("a second newcomer in a table of open flows: %s", pwDescribe(st))
		}
		if pwFlowGoroutines() != 8 {
			t.Fatalf("%d flow goroutines for 8 entries (the held one's must have returned)", pwFlowGoroutines())
		}
		pwUnits(t, w.pf)
	})
}

// pwEvictStep sends one newcomer's query, waits one step, and checks the
// eviction it caused against the table before it (O-1 (a), M6-D29, R1-5):
// at most one entry left the table; a victim was an open flow that never
// became a stream and whose last datagram was at least 1 s old (or a held
// entry); its goroutine has returned (flow goroutines ≤ entries); and it
// reports the victim's client (invalid: none).
func pwEvictStep(t testing.TB, w *pwWorld, c *rendrtest.DatagramConn, b []byte) netip.AddrPort {
	t.Helper()
	before := pwSnapshot(w.pf)
	now := time.Now()
	pfSend(t, c, b)
	synctest.Wait()
	after := pwSnapshot(w.pf)
	var gone []FlowInfo
	for k, fi := range before {
		if _, ok := after[k]; !ok {
			gone = append(gone, fi)
		}
	}
	if len(gone) > 1 {
		t.Fatalf("%d entries left the table at one newcomer: %+v", len(gone), gone)
	}
	if g, n := pwFlowGoroutines(), len(after); g > n {
		t.Fatalf("%d flow goroutines for %d entries (an evicted entry's goroutine still runs)", g, n)
	}
	if len(gone) == 0 {
		return netip.AddrPort{}
	}
	v := gone[0]
	if v.State != FlowHeld && (v.State != FlowOpen || v.Stream || now.Sub(v.Last) < ingressEvictIdle) {
		t.Fatalf("victim %+v at %v: want a held entry or an open non-stream flow idle ≥ 1 s", v, now)
	}
	return v.Client
}

// TestPortForwardEvictShortIdle_L48_L72 (M6-D29, R1-5, R1-7; L48, L72):
// under O-1 (a) (promoteActive) a full table makes room for a newcomer by
// evicting an open flow that never became a stream and has been idle for
// at least 1 s — the least recently active of the ≤ 8 sampled — or a held
// entry; the victim's session is closed (its passive forward ends with
// io.EOF, PeerClosed) and its goroutine has returned within the step
// (flow goroutines ≤ entries at every step); a flow whose answer is still
// in flight (its last datagram < 1 s ago) is never a victim; with no
// victim the newcomer is DropFull, exactly.
func TestPortForwardEvictShortIdle_L48_L72(t *testing.T) {
	t.Run("flood", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			pfRule(t, promoteActive)
			w := newPWWorld(t, pwOpts{pfwd: func(f *PortForward) { f.MaxFlows = 64 }})
			w.serve()
			pwFill(t, w, pwClients(w, 64), 0x20) // one-shot queries, answered: short under (a)
			time.Sleep(1500 * time.Millisecond)
			evicted := 0
			flood := 150
			if raceEnabled {
				flood = 100
			}
			for i := range flood {
				if v := pwEvictStep(t, w, w.client(), pwTagged(30, 0x21, i)); v.IsValid() {
					evicted++
				}
				time.Sleep(20 * time.Millisecond)
			}
			time.Sleep(100 * time.Millisecond)
			st := pwStatus(w.pf)
			t.Logf("%d evicted; %s", evicted, pwDescribe(st))
			if st.Evicted != uint64(evicted) || st.Evicted+st.DropFull != uint64(flood) || st.Ended.Evicted != st.Evicted || st.Flows+st.Opening != 64 {
				t.Fatalf("status %s, %d victims seen", pwDescribe(st), evicted)
			}
			// The first 64 newcomers find victims among the 64 flows that are
			// idle ≥ 1 s; later ones find the newcomers' own young flows
			// mostly (< 1 s): evictions and DropFull both happen.
			if st.Evicted < 64 {
				t.Fatalf("stimulus: %d evictions (%d DropFull): want at least 64", st.Evicted, st.DropFull)
			}
			if _, eof := pwPeerClosed(w.pas); eof != evicted {
				t.Fatalf("%d passive forwards ended with io.EOF, want the %d victims (their sessions closed)", eof, evicted)
			}
			pwUnits(t, w.pf)
		})
	})
	t.Run("least recently active", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			pfRule(t, promoteActive)
			w := newPWWorld(t, pwOpts{pfwd: func(f *PortForward) { f.MaxFlows = 8 }})
			w.serve()
			cs := pwClients(w, 8)
			for i, c := range cs {
				pfSend(t, c, pwTagged(30, 0x22, i))
				time.Sleep(100 * time.Millisecond)
			}
			time.Sleep(1200 * time.Millisecond) // every flow idle ≥ 1 s; cs[0] the least recently active
			if v := pwEvictStep(t, w, w.client(), pwTagged(30, 0x23, 0)); v != pwAddr(cs[0]) {
				t.Fatalf("victim %v, want the least recently active flow %v", v, pwAddr(cs[0]))
			}
			// Refresh cs[1] (now the oldest): the next victim is cs[2].
			pfSend(t, cs[1], pwTagged(30, 0x22, 100))
			time.Sleep(time.Second)
			if v := pwEvictStep(t, w, w.client(), pwTagged(30, 0x23, 1)); v != pwAddr(cs[2]) {
				t.Fatalf("victim %v, want %v (cs[1] was active since)", v, pwAddr(cs[2]))
			}
		})
	})
	t.Run("held first", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			pfRule(t, promoteActive)
			w := newPWWorld(t, pwOpts{pfwd: func(f *PortForward) { f.MaxFlows = 8 },
				decide: func(_ int, r Request) RejectCode {
					if tagOf(r.First) == 0x27 {
						return CodeNotAllowed
					}
					return 0
				}})
			w.serve()
			cs := pwClients(w, 7)
			pwFill(t, w, cs, 0x26)
			refused := w.client()
			pfSend(t, refused, pwTagged(30, 0x27, 0))
			time.Sleep(1500 * time.Millisecond) // the open flows idle ≥ 1 s, the hold younger than them all
			if st := pwStatus(w.pf); st.Held != 1 || st.Flows != 7 || pwFlowGoroutines() != 8 {
				t.Fatalf("before the newcomer: %s, %d goroutines", pwDescribe(st), pwFlowGoroutines())
			}
			if v := pwEvictStep(t, w, w.client(), pwTagged(30, 0x28, 0)); v != pwAddr(refused) {
				t.Fatalf("victim %v, want the held entry %v before any idle flow", v, pwAddr(refused))
			}
			if st := pwStatus(w.pf); st.Evicted != 0 || st.Held != 0 || st.Flows+st.Opening != 8 {
				t.Fatalf("a held entry made room: %s (its end is not an eviction)", pwDescribe(st))
			}
		})
	})
	t.Run("in flight", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			pfRule(t, promoteActive)
			w := newPWWorld(t, pwOpts{pfwd: func(f *PortForward) { f.MaxFlows = 8 }})
			w.serve()
			pwFill(t, w, pwClients(w, 8), 0x24)
			time.Sleep(900 * time.Millisecond) // every flow's last datagram < 1 s ago
			for i := range 5 {
				if v := pwEvictStep(t, w, w.client(), pwTagged(30, 0x25, i)); v.IsValid() {
					t.Fatalf("victim %v whose answer is < 1 s old", v)
				}
			}
			if st := pwStatus(w.pf); st.DropFull != 5 || st.Evicted != 0 {
				t.Fatalf("no victim: %s", pwDescribe(st))
			}
			time.Sleep(200 * time.Millisecond)
			if v := pwEvictStep(t, w, w.client(), pwTagged(30, 0x25, 9)); !v.IsValid() {
				t.Fatal("no victim once the flows were idle for 1 s")
			}
		})
	})
}

// TestPortForwardStreamNeverEvicted_L72 (M6-D29, R1-7; L72): under both
// rules, 4 stream flows — 3 exchanging every 200 ms and one, once a stream,
// only a keepalive every 25 s (WireGuard's) — keep 100 % delivery through
// a 60-s flood (30 s in the race lane) of one-shot newcomers into a table of 16: they stay in the
// table, open and streams, on their first and only session (one flow each
// at the passive), while the flood evicts one-shot flows (O-1 (a)) or is
// refused (the literal rule).
func TestPortForwardStreamNeverEvicted_L72(t *testing.T) {
	for _, rule := range []promoteMode{promoteActive, promoteOnReply} {
		t.Run(map[promoteMode]string{promoteActive: "active rule", promoteOnReply: "reply rule"}[rule], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				pfRule(t, rule)
				w := newPWWorld(t, pwOpts{pfwd: func(f *PortForward) { f.MaxFlows = 16 }})
				w.serve()
				streams := pwClients(w, 4)
				k := 0
				exchange := func(c *rendrtest.DatagramConn, i int) {
					k++
					b := pwTagged(40, byte(0x30+i), k)
					if !pwRoundTrip(t, c, b, time.Second) {
						t.Fatalf("stream %d lost its echo at %v: %s", i, time.Now(), pwDescribe(pwStatus(w.pf)))
					}
				}
				for range 15 { // 3 s both ways: streams under either rule
					for i, c := range streams {
						exchange(c, i)
					}
					time.Sleep(200 * time.Millisecond)
				}
				pwFill(t, w, pwClients(w, 12), 0x40)
				period := 60 * time.Second
				if raceEnabled {
					period = 30 * time.Second // the keepalive still crosses twice (at 0 s and 25 s)
				}
				start := time.Now()
				for n := 0; time.Since(start) < period; n++ {
					pfSend(t, w.client(), pwTagged(30, 0x41, n))
					if n%2 == 0 {
						for i, c := range streams[:3] {
							exchange(c, i)
						}
					}
					if n%250 == 0 {
						exchange(streams[3], 3) // every 25 s
					}
					time.Sleep(100 * time.Millisecond)
				}
				snap := pwSnapshot(w.pf)
				for i, c := range streams {
					if fi, ok := snap[pwAddr(c)]; !ok || fi.State != FlowOpen || !fi.Stream {
						t.Fatalf("stream %d: %+v (in the table: %v)", i, fi, ok)
					}
				}
				for i := range streams {
					if n := pwFlowsTagged(w.pas, byte(0x30+i)); n != 1 {
						t.Fatalf("stream %d has %d sessions at the passive, want 1", i, n)
					}
				}
				st := pwStatus(w.pf)
				t.Logf("%s", pwDescribe(st))
				if rule == promoteActive && st.Evicted == 0 || rule == promoteOnReply && (st.Evicted != 0 || st.DropFull == 0) {
					t.Fatalf("stimulus: %s", pwDescribe(st))
				}
			})
		})
	}
}

// pwFlowsTagged counts the kit passive's flows whose first datagram was
// tagged tag.
func pwFlowsTagged(p *pwPassive, tag byte) int {
	_, _, _, flows := p.snapshot()
	n := 0
	for _, fl := range flows {
		if rx := fl.received(); len(rx) > 0 && tagOf(rx[0]) == tag {
			n++
		}
	}
	return n
}

// TestPortForwardReusedSourceStaysShort_L72 (M6-D9, R1-23; L72): under O-1
// (a), 2,000 one-shot queries from a 512-port space at 100 a second (1,000
// from 256 ports in the race lane; each port reused after 5.12 s (2.56 s), while its flow still lives at Short): every
// reused port lands on its live flow after a gap of ≥ 2 s, which starts a
// new activity period, so no flow ever becomes a stream at either end;
// the same flows serve the reused ports (512 sessions).
func TestPortForwardReusedSourceStaysShort_L72(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pfRule(t, promoteActive)
		w := newPWWorld(t, pwOpts{passiveDefaults: true}) // the passive's classes apply too: no promotion there either
		w.serve()
		ports, queries := 512, 2000
		if raceEnabled {
			ports, queries = 256, 1000 // each port still reused after ≥ 2 s (2.56 s)
		}
		cs := pwClients(w, ports)
		for q := range queries {
			pfSend(t, cs[q%ports], pwTagged(40, byte(q%ports), q))
			time.Sleep(10 * time.Millisecond)
		}
		time.Sleep(time.Second)
		streams := 0
		for _, fi := range w.pf.Flows() {
			if fi.Stream {
				streams++
			}
		}
		opens, _, _, flows := w.pas.snapshot()
		st := pwStatus(w.pf)
		t.Logf("%d streams at the ingress; %d OPENs; %s", streams, opens, pwDescribe(st))
		if streams != 0 {
			t.Fatalf("%d flows became streams at the ingress through source reuse", streams)
		}
		if opens != ports || st.Opened != uint64(ports) || st.ToSession != uint64(queries) || st.ToClient != uint64(queries) {
			t.Fatalf("%d OPENs, %s: want the %d flows to carry all %d queries and answers", opens, pwDescribe(st), ports, queries)
		}
		w.stop()
		passiveStreams := 0
		for _, fl := range flows {
			if r := <-fl.res; r.Stream {
				passiveStreams++
			}
		}
		if passiveStreams != 0 {
			t.Fatalf("%d flows became streams at the passive through source reuse", passiveStreams)
		}
	})
}

// TestPortForwardHoldExpires (M6-D28, R1-22): a refused source's entry
// stays held for exactly 5 s (its datagrams none meanwhile), then it is
// removed: Held 0, no entry, its goroutine returned, its unit released.
func TestPortForwardHoldExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newPWWorld(t, pwOpts{decide: func(int, Request) RejectCode { return CodeNotAllowed }})
		w.serve()
		c := w.client()
		pfSend(t, c, pwTagged(30, 0x50, 0))
		synctest.Wait()
		for pwStatus(w.pf).Held == 0 {
			time.Sleep(time.Millisecond)
			synctest.Wait() // the hold begins at the instant the refusal arrives
		}
		heldAt := time.Now()
		time.Sleep(ingressHold - time.Millisecond)
		synctest.Wait()
		if st := pwStatus(w.pf); st.Held != 1 || pwFlowGoroutines() != 1 {
			t.Fatalf("1 ms before the hold's end: %s, %d goroutines", pwDescribe(st), pwFlowGoroutines())
		}
		time.Sleep(time.Millisecond)
		synctest.Wait()
		if st := pwStatus(w.pf); st.Held != 0 || pwFlowGoroutines() != 0 || w.pf.flows.Load() != 0 {
			t.Fatalf("at the hold's end (%v after it began): %s, %d goroutines, %d units", time.Since(heldAt), pwDescribe(st), pwFlowGoroutines(), w.pf.flows.Load())
		}
		if n, _ := pwEntries(w.pf); n != 0 {
			t.Fatalf("%d entries after the hold", n)
		}
		if _, rejects, _, _ := w.pas.snapshot(); rejects != 1 {
			t.Fatalf("%d refusals at the passive, want 1", rejects)
		}
	})
}
