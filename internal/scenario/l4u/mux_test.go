package l4u

import (
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/l4"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Two rules of L4 UDP flows that many sessions on one datagram MUX trunk
// must keep at once (found by TestL4UDNSChurnMiniature_L48_L72's recipe
// arm; core defects A and B of the M6 delegate decision of 2026-10-21,
// whose carrier rows are TestMuxDgramIdleEndReachesPeer_L30 and
// TestMuxFirstReplyAgesFromPlaceable_L40): a flow's idle end reaches the
// other end (M6-D10), and a reply the target writes as the flow opens
// reaches the client (M6-D18, TestServerUDPFirstSentOnce_L47's reply
// rule). A datagram trunk's REL window (8 frames) is shared by every view
// on it, so both rules are exercised where 64 views open or end in one
// instant.

// idleStall is how long TestL4UIdleEndsReachPassive_L30_L52 stalls the
// passive → dialer direction around the idle ends.
const idleStall = 200 * time.Millisecond

// TestL4UIdleEndsReachPassive_L30_L52 (M6-D10, §A5.3 "idle here"; L30,
// L52): 64 flows through one ingress with Idle{10 s, 10 s} over one
// DatagramLink (one trunk of 64 views), each opened with one datagram
// toward a target that never answers. Once every flow is open at both
// ends, every client sends one more datagram in one instant and is then
// silent: each dialer session's last activity is that instant, so the
// ingress ends all 64 by idle in one instant, 10 s later. From 5 ms before
// that instant the link's passive → dialer direction is stalled for 200 ms
// (held, then delivered: nothing is lost), so the trunk's REL window
// cannot drain while the 64 ends are placed: whatever order the scheduler
// runs them in (-cpu 1 or 4), at most 8 RSTs leave at once and the other
// 56 views end with their RST waiting for REL room. Each end must still
// reach the passive as *AbortError{AbortIdle} (its forward ends, the
// egress socket closes and the Server's MaxFlows unit is released)
// instead of leaving the passive session orphaned until PassiveRetain or
// its own, longer, idle limit (the Server's default classes: 30 s).
//
// Stimulus: the stall held datagrams (link Held grew), and every dialer
// session's last datagram was the instant's.
//
// PASS: within 10 s + PacketPing + the stall + 2 s of the flows' last
// datagram the ingress ended all 64 at its idle limit (Ended.Idle 64), and
// the Server ended all 64 by the peer's idle end (UDP.Ended.PeerIdle 64,
// Live 0), the passive Runtime holding no orphaned session.
func TestL4UIdleEndsReachPassive_L30_L52(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const flows = 64
		w := newWorld(t, worldOpts{}, linkSpec{name: "u1"})
		var mu sync.Mutex
		got := 0
		w.target(dnsPort, func(e *egress) { // a target that only reads: no reply
			buf := make([]byte, 2048)
			for {
				if _, err := e.conn.Read(buf); err != nil {
					return
				}
				mu.Lock()
				got++
				mu.Unlock()
			}
		})
		pf := &l4.PortForward{Peer: w.peer("u1"), Idle: l4.FlowIdle{Short: 10 * time.Second, Stream: 10 * time.Second}}
		in := w.forward(pf, targetAddr(dnsPort), hubCfg(0))
		cs := make([]*rendrtest.DatagramConn, flows)
		for i := range cs {
			cs[i] = in.client(clientSrc(i))
			if _, err := cs[i].Write(make([]byte, 40)); err != nil {
				t.Fatalf("flow %d: %v", i, err)
			}
		}
		waitFor(t, 5*time.Second, "every flow open at both ends", func() bool {
			open := 0
			for _, fi := range pf.Flows() {
				if fi.State == l4.FlowOpen {
					open++
				}
			}
			return open == flows && w.srv.Status().UDP.Live == flows
		})
		time.Sleep(time.Second)
		for i, c := range cs { // the last datagram of every flow, in one instant
			if _, err := c.Write(make([]byte, 40)); err != nil {
				t.Fatalf("flow %d: %v", i, err)
			}
		}
		last := time.Now()
		waitFor(t, time.Second, "every flow's two datagrams at the target", func() bool {
			mu.Lock()
			defer mu.Unlock()
			return got == 2*flows
		})
		l := w.dlink("u1")
		sleepUntil(last.Add(10*time.Second - 5*time.Millisecond))
		held0 := l.Stats().Session.Held
		l.Stall(rendrtest.Down, true)
		sleepUntil(last.Add(10*time.Second - 5*time.Millisecond + idleStall))
		l.Stall(rendrtest.Down, false)
		if l.Stats().Session.Held == held0 {
			t.Fatalf("stimulus: the stall of the passive → dialer direction held no datagram")
		}
		sleepUntil(last.Add(10*time.Second + time.Second + idleStall + 2*time.Second))
		ps, ss, sc := pf.Status().UDP, w.srv.Status().UDP, w.p.Status().Sessions
		t.Logf("ingress %+v; passive %+v live %d; passive sessions %+v", ps.Ended, ss.Ended, ss.Live, sc)
		if ps.Ended.Idle != flows {
			t.Fatalf("the ingress ended %d flows at its idle limit, want %d: %+v", ps.Ended.Idle, flows, ps.Ended)
		}
		if ss.Ended.PeerIdle != flows || ss.Live != 0 || sc.Orphaned != 0 {
			t.Fatalf("M6-D10: the passive ended %d of %d flows by the peer's idle end (%d still live, %d sessions orphaned): an idle end did not cross",
				ss.Ended.PeerIdle, flows, ss.Live, sc.Orphaned)
		}
		w.close()
	})
}

// TestL4UFirstReplyAtConfirm_L40 (M6-D18; L40, L47): 64 flows through one
// ingress opened in one instant over a Peer of two DatagramLinks; every
// flow's first datagram rides its OPEN, and each target answers it once,
// as soon as all 64 first datagrams were written to the targets — for the
// last flows that is the instant of their Confirm, while the trunk's REL
// window still carries the other views' OPEN_ACKs. The answer waits in the
// passive session until its view may send and must then cross; it must
// not age out at the passive (Packet.MaxAge) while the view is held.
//
// PASS: every client receives its answer within a second.
func TestL4UFirstReplyAtConfirm_L40(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const flows = 64
		w := newWorld(t, worldOpts{}, linkSpec{name: "u1"}, linkSpec{name: "u2"})
		var mu sync.Mutex
		learned := 0
		all := make(chan struct{})
		w.target(dnsPort, func(e *egress) {
			buf := make([]byte, 2048)
			n, err := e.conn.Read(buf)
			if err != nil {
				return
			}
			mu.Lock()
			if learned++; learned == flows {
				close(all)
			}
			mu.Unlock()
			select {
			case <-all:
			case <-w.quit:
				return
			}
			e.conn.Write(buf[:n])
			for {
				if _, err := e.conn.Read(buf); err != nil {
					return
				}
			}
		})
		pf := &l4.PortForward{Peer: w.peer("u1", "u2")}
		in := w.forward(pf, targetAddr(dnsPort), hubCfg(0))
		answered := make([]chan struct{}, flows)
		for i := range flows {
			c := in.client(clientSrc(i))
			ch := make(chan struct{})
			answered[i] = ch
			var once sync.Once
			readAll(c, func([]byte, time.Time) { once.Do(func() { close(ch) }) })
			if _, err := c.Write(make([]byte, 100)); err != nil {
				t.Fatalf("flow %d: %v", i, err)
			}
		}
		select {
		case <-all:
		case <-time.After(5 * time.Second):
			mu.Lock()
			n := learned
			mu.Unlock()
			t.Fatalf("stimulus: %d of %d first datagrams reached the targets", n, flows)
		}
		time.Sleep(time.Second)
		lost := 0
		for i, ch := range answered {
			select {
			case <-ch:
			default:
				lost++
				t.Logf("flow %d: no answer within a second", i)
			}
		}
		if lost != 0 {
			t.Fatalf("M6-D18: %d of %d answers written at their flow's Confirm never reached the client (ToClient %d of FromTarget %d)",
				lost, flows, pf.Status().UDP.ToClient, w.srv.Status().UDP.FromTarget)
		}
		w.close()
	})
}
