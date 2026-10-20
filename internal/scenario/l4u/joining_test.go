package l4u

import (
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/l4"
)

// TestL4UMixedRaceJoiningOversize_L37 (§A4.1 "bond or race with a stream
// factory"; the M6 delegate decision of 2026-10-21 on a mixed session's
// joining stream member; l4's "Sizes" text; L37): the documented
// limitation, in race mode. One UDP flow through the ingress over a Peer of
// one datagram factory u1 (frame budget 1,463: 1,438-byte datagrams) and
// one stream factory s1. The flow's first datagram is 3,000 bytes, wider
// than the datagram member, so it cannot ride the OPEN and is flushed when
// the flow opens; from the instant the flow is open at the ingress the
// client sends 3,000- and 1,000-byte test datagrams alternately, 200 per
// second for 2 s, and the target echoes each. The session opens on u1 and
// s1 joins about one round trip (20 ms) later.
//
// Stimulus: the flow's MaxPayload is 65,507 at both ends (the session has
// a stream factory), and the stream member was not yet live when the flow
// opened.
//
// PASS (the documented behaviour): the wide datagrams the dialer wrote
// before the stream member was live — the first datagram among them — are
// dropped, exactly as many as the dialer session's DropTooLarge, and
// nothing else is lost: every lost datagram is a 3,000-byte one sent
// within two round trips of the open, every later one arrives whole and
// once in both directions, no datagram is counted TooLarge (its size is
// within MaxPayload) and the flow stays the one open flow. The row fails
// when the core starts keeping such a datagram for the joining member: l4's
// "Sizes" text changes with it.
func TestL4UMixedRaceJoiningOversize_L37(t *testing.T) {
	joiningOversize(t, rendr.ModeRace)
}

// joiningOversize is the row of TestL4UMixedRaceJoiningOversize_L37 in
// mode m (bond or race): the limitation l4's "Sizes" text documents.
func joiningOversize(t *testing.T, m rendr.Mode) {
	synctest.Test(t, func(t *testing.T) {
		const (
			rate  = 200
			port  = 9003
			small = 1000
			large = 3000
			span  = 2 * time.Second
			join  = 4 * oneWay // two round trips: the stream member joins in about one
		)
		w := newWorld(t, worldOpts{}, linkSpec{name: "u1"}, linkSpec{name: "s1", stream: true})
		up, down := newLedger("client → target", 5), newLedger("target → client", 5)
		w.target(port, echoApp(func(e *egress, b []byte, at time.Time) {
			up.arrive(b, at)
			down.mark(b, at)
		}))
		pf := &l4.PortForward{Peer: w.peer("u1", "s1"), Options: rendr.DialOptions{Mode: m}}
		in := w.forward(pf, targetAddr(port), hubCfg(0))
		src := clientSrc(0)
		c := in.client(src)
		rd := startReader(c, down.arrive)
		if _, err := c.Write(up.next(nil, large, time.Now())); err != nil {
			t.Fatalf("the first datagram: %v", err)
		}
		var fi l4.FlowInfo
		waitFor(t, 5*time.Second, "the flow open at the ingress", func() bool {
			var ok bool
			fi, ok = flowOf(pf, src)
			return ok && fi.State == l4.FlowOpen
		})
		live := len(liveOf(fi.Session))
		start := time.Now()
		// seq 0 is the first datagram; the generator's seq k ≥ 1 is large
		// when k is odd.
		g := startGen(c, up, w.quit, rate, []int{large, small}, start.Add(span))
		g.wait(t, up.name)
		time.Sleep(time.Second)
		end := time.Now()

		fi, ok := flowOf(pf, src)
		t.Logf("%v: live members at the open %d; %+v; ingress %+v", m, live, fi.Session.Packet, plainF(pf.Status().UDP))
		if fi.Session.MaxPayload != fullPayload {
			t.Fatalf("stimulus: the dialer session's MaxPayload is %d, want %d (a stream factory)", fi.Session.MaxPayload, fullPayload)
		}
		if live != 1 {
			t.Fatalf("stimulus: %d live members when the flow opened, want the datagram member alone (the stream member still joining)", live)
		}
		up.integrity(t)
		down.integrity(t)
		if ls := down.losses(end); len(ls) != 0 {
			t.Fatalf("%s: %d of %d datagrams lost (first: seq %d)", down.name, len(ls), down.sentCount(), ls[0].seq)
		}
		ls := up.losses(end)
		if len(ls) == 0 || ls[0].seq != 0 {
			t.Fatalf("%s: losses %v; want the first datagram (seq 0) among them: the limitation l4 documents", up.name, ls)
		}
		for _, x := range ls {
			if wide := x.seq == 0 || x.seq%2 == 1; !wide || !x.sent.Before(start.Add(join)) {
				t.Fatalf("%s: seq %d (wide %v) sent at +%v of the open was lost; want only wide datagrams sent within %v of it", up.name, x.seq, wide, x.sent.Sub(start), join)
			}
		}
		p := fi.Session.Packet
		if p == nil || p.DropTooLarge != uint64(len(ls)) || p.DropQueue+p.DropAge+p.DropNoPath != 0 {
			t.Fatalf("the dialer session's counters %+v: want DropTooLarge = %d (the losses) and no other drop", p, len(ls))
		}
		if ps, ss := pf.Status().UDP, w.srv.Status().UDP; ps.TooLarge != 0 || ss.TooLarge != 0 {
			t.Fatalf("TooLarge %d at the ingress and %d at the passive, want 0", ps.TooLarge, ss.TooLarge)
		}
		if !ok || fi.State != l4.FlowOpen {
			t.Fatalf("the flow is %+v (found %v), want it open", fi.State, ok)
		}
		oneFlow(t, w, pf, port, 1)
		select {
		case <-rd.done:
			t.Fatalf("the client's socket failed while the flow lived: %v", rd.err)
		default:
		}
		w.noViolation()
		w.close()
	})
}
