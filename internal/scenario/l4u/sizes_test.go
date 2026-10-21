package l4u

import (
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/l4"
)

// The size rows that need stream members (M6 design §A4.1, §A16.2; L37):
// a Peer of stream carriers only carries every datagram up to
// Packet.MaxPayload, and a bond with a stream member puts the datagrams
// too wide for its datagram member on the stream member. Neither ever
// drops a datagram for its size.

// fullPayload is Packet.MaxPayload's default: the MaxPayload of a session
// that may use stream members (§A4.1).
const fullPayload = 65507

// TestL4UStreamCarrierFallback_L37 (§A4.1 "stream carriers only", L37):
// one UDP flow through the ingress over a Peer of two stream Links s1 and
// s2 (selector), 9,000-byte test datagrams at 100 per second each way for
// 30 s (the client's, echoed by the target; lane.fallbackSpan, 14 s and
// two kills under the race detector), once the flow is open (its first
// datagram echoed). Stimulus: at 6, 12, 18 and 24 s the Link of the
// session's active carrier is killed (both conns closed; the bytes in its
// buffers lost), and each kill ends the carrier it was carrying the flow
// on.
//
// PASS: the flow's MaxPayload is 65,507 at both ends (stream members
// carry every datagram) and no datagram is ever dropped for its size
// (TooLarge 0 at both ends, the session's DropTooLarge 0); every datagram
// arrives whole and once (PacketIntegrity; 9,000 bytes each); a datagram
// lost in either direction was sent within [kill − 200 ms, kill + 200 ms]
// of a kill (G3's window, plan:750) and every other one arrived; the kills
// are invisible to both applications: one flow, one session (the same
// session ID at the start and the end, Opened 1, Confirmed 1, one target
// dial: one egress address), the client never sees an error, and the flow
// is never interrupted for long: in each direction the largest arrival gap
// in [kill − 1 s, kill + 1 s], less the 10-ms send interval, stays below
// 200 ms (G10's CLOSE bound; the session was without a carrier for less
// than that).
func TestL4UStreamCarrierFallback_L37(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			size  = 9000
			rate  = 100
			port  = 9000
			slack = 200 * time.Millisecond
		)
		w := newWorld(t, worldOpts{}, linkSpec{name: "s1", stream: true}, linkSpec{name: "s2", stream: true})
		up, down := newLedger("client → target", 1), newLedger("target → client", 1)
		w.target(port, echoApp(func(e *egress, b []byte, at time.Time) {
			up.arrive(b, at)
			down.mark(b, at)
		}))
		pf := &l4.PortForward{Peer: w.peer("s1", "s2")}
		in := w.forward(pf, targetAddr(port), hubCfg(0))
		src := clientSrc(0)
		c := in.client(src)
		rd := startReader(c, down.arrive)
		openEcho(t, c, up, down, size)

		start := time.Now()
		span := lane.fallbackSpan
		g := startGen(c, up, w.quit, rate, []int{size}, start.Add(span))
		var fi l4.FlowInfo
		waitFor(t, 5*time.Second, "the flow open", func() bool {
			var ok bool
			fi, ok = flowOf(pf, src)
			return ok && fi.State == l4.FlowOpen
		})
		id := fi.Session.ID
		var kills []window
		var killAt []time.Time
		for k := 1; k <= int((span-time.Second)/(6*time.Second)); k++ {
			sleepUntil(start.Add(time.Duration(k) * 6 * time.Second))
			fi, _ = flowOf(pf, src)
			a, ok := activeOf(fi.Session)
			if !ok {
				t.Fatalf("kill %d: the flow's session has no active carrier: %+v", k, fi.Session)
			}
			at := time.Now()
			if n := w.slinks[a.Name].Kill(); n == 0 {
				t.Fatalf("stimulus: kill %d of %s closed no carrier", k, a.Name)
			}
			kills = append(kills, window{at.Add(-slack), at.Add(slack)})
			killAt = append(killAt, at)
			waitFor(t, 2*time.Second, "the killed carrier dead and another active", func() bool {
				fi, _ = flowOf(pf, src)
				dead, _ := carrierOf(fi.Session, a.ID)
				b, ok := activeOf(fi.Session)
				return dead.State == rendr.CarrierDead && ok && b.ID != a.ID
			})
			t.Logf("kill %d at +%v: %s's carrier %d dead (%v); active %v", k, at.Sub(start), a.Name, a.ID, mustCarrier(fi.Session, a.ID).DeathCause, mustActive(fi.Session).Name)
		}
		g.wait(t, up.name)
		time.Sleep(time.Second) // the last echoes arrive

		fi, ok := flowOf(pf, src)
		if !ok || fi.State != l4.FlowOpen || fi.Session.ID != id {
			t.Fatalf("the flow after the kills: %+v (found %v), want the session %v still open", fi, ok, id)
		}
		if fi.Session.MaxPayload != fullPayload {
			t.Fatalf("the dialer session's MaxPayload is %d, want %d (stream members only)", fi.Session.MaxPayload, fullPayload)
		}
		if p := fi.Session.Packet; p == nil || p.DropTooLarge != 0 {
			t.Fatalf("the dialer session dropped datagrams for their size: %+v", p)
		}
		end := time.Now()
		for _, l := range []*ledger{up, down} {
			l.integrity(t)
			lost := l.lossesOutside(t, end, kills, start)
			t.Logf("%s: %d sent, %d arrived, %d lost inside the kill windows", l.name, l.sentCount(), l.arrived(), lost)
			if l.sentCount() < rate*int(span/time.Second)*99/100 && l == up {
				t.Fatalf("load: %s sent %d datagrams, want about %d", l.name, l.sentCount(), rate*int(span/time.Second))
			}
		}
		for _, at := range killAt {
			for _, l := range []*ledger{up, down} {
				g := maxGap(l, at.Add(-time.Second), at.Add(time.Second))
				t.Logf("kill at +%v: %s's largest arrival gap %v", at.Sub(start), l.name, g)
				if g-time.Second/rate >= slack {
					t.Fatalf("kill at +%v: %s's datagrams stopped arriving for %v, want an interruption below %v", at.Sub(start), l.name, g, slack)
				}
			}
		}
		oneFlow(t, w, pf, port, 1)
		if st := w.srv.Status().UDP; st.MaxPayload != fullPayload || st.TooLarge != 0 {
			t.Fatalf("the Server's UDP status %+v: want MaxPayload %d and TooLarge 0", st, fullPayload)
		}
		if st := pf.Status().UDP; st.MaxPayload != fullPayload || st.TooLarge != 0 {
			t.Fatalf("the PortForward's UDP status %+v: want MaxPayload %d and TooLarge 0", plainF(st), fullPayload)
		}
		select {
		case <-rd.done:
			t.Fatalf("the client's socket failed while the flow lived: %v", rd.err)
		default:
		}
		w.noViolation()
		w.close()
	})
}

// TestL4UMixedBondOversize_L37 (§A4.1 "bond or race with a stream
// factory", M2-D43, L37): one UDP flow through the ingress over a Peer of
// one datagram factory u1 (frame budget 1,463: 1,438-byte datagrams) and
// one stream factory s1, bond mode; the client sends 1,000- and 3,000-byte
// test datagrams alternately, 200 per second for 20 s (lane.bondSpan: 8 s
// under the race detector), and the target echoes each. The flow opens with
// one 1,000-byte datagram and the load starts once both members are live:
// a datagram wider than the datagram member written while the stream
// member is still joining has no carrier and is dropped (DropTooLarge), a
// start-up gap this row does not judge: the documented limitation
// TestL4UMixedBondJoiningOversize_L37 pins.
//
// PASS: the flow's MaxPayload is 65,507 at both ends (the bond has a
// stream member); every datagram of both sizes arrives whole and once in
// both directions — none is dropped for its size (TooLarge 0 at both
// ends, the dialer session's DropTooLarge 0, the datagram link refused
// nothing as oversize); the 3,000-byte ones ride the stream member: the
// datagram member's DGRAM bytes in each direction (the dialer's
// TxBytes and RxBytes of it) stay within the 1,000-byte datagrams' total,
// the stream member's reach the 3,000-byte ones' total, and the datagram
// member carried a share of the 1,000-byte ones (both members are used:
// the stimulus).
func TestL4UMixedBondOversize_L37(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			rate  = 200
			port  = 9001
			small = 1000
			large = 3000
		)
		w := newWorld(t, worldOpts{}, linkSpec{name: "u1"}, linkSpec{name: "s1", stream: true})
		up, down := newLedger("client → target", 2), newLedger("target → client", 2)
		w.target(port, echoApp(func(e *egress, b []byte, at time.Time) {
			up.arrive(b, at)
			down.mark(b, at)
		}))
		pf := &l4.PortForward{Peer: w.peer("u1", "s1"), Options: rendr.DialOptions{Mode: rendr.ModeBond}}
		in := w.forward(pf, targetAddr(port), hubCfg(0))
		src := clientSrc(0)
		c := in.client(src)
		rd := startReader(c, down.arrive)
		// The flow opens with a small datagram, and the load starts once
		// both members are live: a datagram wider than the datagram member
		// written while the stream member is still joining has no carrier
		// and is dropped (DropTooLarge; TestL4UMixedBondJoiningOversize_L37).
		openEcho(t, c, up, down, small)
		var fi l4.FlowInfo
		waitFor(t, 10*time.Second, "both members live", func() bool {
			var ok bool
			fi, ok = flowOf(pf, src)
			return ok && fi.State == l4.FlowOpen && len(liveOf(fi.Session)) == 2
		})

		start := time.Now()
		span := lane.bondSpan
		g := startGen(c, up, w.quit, rate, []int{large, small}, start.Add(span))
		g.wait(t, up.name)
		time.Sleep(time.Second)
		end := time.Now()

		fi, _ = flowOf(pf, src)
		for _, l := range []*ledger{up, down} {
			l.integrity(t)
			if ls := l.losses(end); len(ls) != 0 {
				t.Fatalf("%s: %d of %d datagrams lost (first: seq %d at +%v); want none dropped", l.name, len(ls), l.sentCount(), ls[0].seq, ls[0].sent.Sub(start))
			}
		}
		n := up.sentCount()
		if n < rate*int(span/time.Second)*99/100 {
			t.Fatalf("load: %d datagrams sent, want about %d", n, rate*int(span/time.Second))
		}
		m := n - 1 // the generator's datagrams after the small first one (openEcho)
		nSmall, nLarge := uint64(m/2+1), uint64((m+1)/2)
		var dg, st rendr.CarrierStatus
		for _, cs := range fi.Session.Carriers {
			switch cs.Kind {
			case rendr.KindDatagram:
				dg.TxBytes += cs.TxBytes
				dg.RxBytes += cs.RxBytes
			case rendr.KindStream:
				st.TxBytes += cs.TxBytes
				st.RxBytes += cs.RxBytes
			}
		}
		t.Logf("%d small and %d large datagrams each way; datagram member tx %d rx %d bytes, stream member tx %d rx %d bytes",
			nSmall, nLarge, dg.TxBytes, dg.RxBytes, st.TxBytes, st.RxBytes)
		if dg.TxBytes > nSmall*small || dg.RxBytes > nSmall*small {
			t.Fatalf("the datagram member carried %d bytes out and %d in, more than the %d small datagrams' %d: a large one rode it",
				dg.TxBytes, dg.RxBytes, nSmall, nSmall*small)
		}
		if st.TxBytes < nLarge*large || st.RxBytes < nLarge*large {
			t.Fatalf("the stream member carried %d bytes out and %d in, less than the %d large datagrams' %d", st.TxBytes, st.RxBytes, nLarge, nLarge*large)
		}
		if dg.TxBytes == 0 || dg.RxBytes == 0 {
			t.Fatalf("stimulus: the datagram member carried nothing (tx %d, rx %d): the bond used only its stream member", dg.TxBytes, dg.RxBytes)
		}
		if fi.Session.MaxPayload != fullPayload {
			t.Fatalf("the dialer session's MaxPayload is %d, want %d (a bond with a stream member)", fi.Session.MaxPayload, fullPayload)
		}
		if p := fi.Session.Packet; p == nil || p.DropTooLarge != 0 {
			t.Fatalf("the dialer session dropped datagrams for their size: %+v", p)
		}
		if s := w.dlink("u1").Stats().All; s.Oversize != 0 {
			t.Fatalf("the datagram link refused %d datagrams as larger than its MTU", s.Oversize)
		}
		oneFlow(t, w, pf, port, 1)
		if st := w.srv.Status().UDP; st.MaxPayload != fullPayload || st.TooLarge != 0 {
			t.Fatalf("the Server's UDP status %+v: want MaxPayload %d and TooLarge 0", st, fullPayload)
		}
		if st := pf.Status().UDP; st.MaxPayload != fullPayload || st.TooLarge != 0 {
			t.Fatalf("the PortForward's UDP status %+v: want MaxPayload %d and TooLarge 0", plainF(st), fullPayload)
		}
		select {
		case <-rd.done:
			t.Fatalf("the client's socket failed while the flow lived: %v", rd.err)
		default:
		}
		w.noViolation()
		w.close()
	})
}

// oneFlow requires that every flow of the row toward port was opened once:
// the PortForward opened flows sessions and none failed, re-opened or was
// replaced, the Server confirmed as many, and the target saw one egress
// address per flow (F79: one source per flow for its whole life).
func oneFlow(t testing.TB, w *world, pf *l4.PortForward, port uint16, flows int) {
	t.Helper()
	ps, ss := pf.Status().UDP, w.srv.Status().UDP
	es := w.egressesOf(port)
	if ps.Opened != uint64(flows) || ps.Failed != 0 || ps.Replaced != 0 || ps.Evicted != 0 || ss.Confirmed != uint64(flows) || len(es) != flows {
		t.Fatalf("flows: the PortForward opened %d (failed %d, replaced %d, evicted %d), the Server confirmed %d, %d target dials; want %d each and no failure",
			ps.Opened, ps.Failed, ps.Replaced, ps.Evicted, ss.Confirmed, len(es), flows)
	}
}

// mustCarrier is carrierOf for log lines.
func mustCarrier(st rendr.SessionStatus, id rendr.CarrierID) rendr.CarrierStatus {
	c, _ := carrierOf(st, id)
	return c
}

// mustActive is activeOf for log lines.
func mustActive(st rendr.SessionStatus) rendr.CarrierStatus {
	c, _ := activeOf(st)
	return c
}
