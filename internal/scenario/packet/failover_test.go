package packet

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The msess packet failover tests, re-ported from M1a (d51fe14,
// internal/msess testPacketFailover; plan:569, m1b §11.3; M2 design §A8.3).
// Three DatagramLinks with a 3-ms one-way delay; the dialer sends 50 test
// datagrams per second for 8 s through a packet session and the passive
// echoes each one back. At mid-run the victim — the selector's active
// carrier's link, or the bond's p2 — refuses dials and stalls silently in
// both directions: nothing arrives, nothing errors (a QUIC path under 100 %
// loss). The time scales are msess's (DeadMin 1 s, PingIdle 0.5 s, and the
// largest PacketPing they allow, DeadMin/2).
//
// Stimulus: the victim held session datagrams (its Held counter), and the
// victim carrier died on both ends. Load: the dialer kept its rate, and in
// the last 2 s at least 75 % of it was answered. Integrity: every reply
// was the datagram sent (seq, size, CRC-32C, body), at most once, from the
// session's RemoteAddr. Selector: the largest reply gap is at most
// PacketPing + D + 2·RTT + 50 ms (death detection of a silent carrier,
// PA-13, plus the redial; the 50 ms cover the 20-ms send interval) and the
// active carrier was replaced. Bond: every loss comes from the victim's
// share until its death — a request the dialer placed on p2 before its
// verdict, or a reply the passive placed on p2 before it left it — and the
// bytes lost fit in what each side placed on p2 after the stall. Both: the
// loss is bounded as in msess (rate × (gap + D) + rate/2); one session, one
// stable logical address on each end and one PendingPacket on the passive
// (the M2 analogue of msess's "one exit socket", O-45); no session on the
// passive 5 s after the dialer's Close, which ends both cleanly.
func TestPacketSelectorFailover(t *testing.T) {
	synctest.Test(t, func(t *testing.T) { packetFailover(t, rendr.ModeSelector) })
}

// TestPacketBondFailover: see TestPacketSelectorFailover.
func TestPacketBondFailover(t *testing.T) {
	synctest.Test(t, func(t *testing.T) { packetFailover(t, rendr.ModeBond) })
}

// msessTun are the msess fixture's time scales (M1's internal/scenario
// tun) with PacketPing at its largest legal value, DeadMin/2.
var msessTun = testhooks.Overrides{
	DeadMin:          time.Second,
	DeadMax:          2 * time.Second,
	WriteStall:       time.Second,
	PingIdle:         500 * time.Millisecond,
	PacketPing:       500 * time.Millisecond,
	ProbeInterval:    200 * time.Millisecond,
	ProbeFresh:       2 * time.Second,
	SelectorDwell:    time.Second,
	SelectorCooldown: 2 * time.Second,
	NoPathGrace:      5 * time.Second,
	RetireGrace:      500 * time.Millisecond,
	Linger:           10 * time.Second,
	RetainSlack:      2 * time.Second,
}

// echoer returns every datagram of a packet session to its source and
// records when it echoed each seq.
type echoer struct {
	pc   *rendr.PacketConn
	v    *rendrtest.PacketVerifier
	done chan struct{}
	err  error

	mu     sync.Mutex
	echoed map[uint64]time.Time // seq → when WriteTo accepted its echo
	reads  atomic.Int64
	writes atomic.Int64
}

func startEcho(pc *rendr.PacketConn, seed uint64) *echoer {
	e := &echoer{pc: pc, v: rendrtest.NewPacketVerifier(seed), done: make(chan struct{}), echoed: map[uint64]time.Time{}}
	go e.run()
	return e
}

// run echoes until io.EOF (the dialer's clean end), then closes pc. A
// failure (an error other than io.EOF, an address other than RemoteAddr, a
// damaged datagram) is kept in err.
func (e *echoer) run() {
	defer close(e.done)
	defer e.pc.Close()
	buf := make([]byte, e.pc.MaxPayload()+1)
	want := e.pc.RemoteAddr()
	echo := true
	for {
		n, addr, err := e.pc.ReadFrom(buf)
		if err == io.EOF {
			return
		}
		if err != nil {
			e.err = err
			return
		}
		e.reads.Add(1)
		if addr != want {
			e.err = errors.New("the echo's ReadFrom reported another address than RemoteAddr")
			return
		}
		if verr := e.v.Add(buf[:n], time.Now()); verr != nil {
			e.err = verr
			return
		}
		if !echo {
			continue
		}
		if _, werr := e.pc.WriteTo(buf[:n], addr); errors.Is(werr, net.ErrClosed) {
			echo = false // the dialer's FIN closed both directions
		} else if werr != nil {
			e.err = werr
			return
		}
		e.writes.Add(1)
		e.mu.Lock()
		e.echoed[seqOf(buf)] = time.Now()
		e.mu.Unlock()
	}
}

// echoedAt returns when seq was echoed (false: it never reached the echo).
func (e *echoer) echoedAt(seq uint64) (time.Time, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	at, ok := e.echoed[seq]
	return at, ok
}

func packetFailover(t *testing.T, mode rendr.Mode) {
	const (
		oneWay = 3 * time.Millisecond
		pps    = 50
		dur    = 8 * time.Second
		size   = 64
		tail   = 2 * time.Second // msess's tailWindow
	)
	// D is the death bound of a carrier whose srtt is far below DeadMin/3.
	d := msessTun.DeadMin
	gapBound := msessTun.PacketPing + d + 4*oneWay + 50*time.Millisecond
	w := newWorld(t, worldOpts{ov: msessTun, oneWay: oneWay, mtu: 1400}, "p1", "p2", "p3")
	dc, pc := w.open(w.peer("p1", "p2", "p3"), rendr.DialOptions{Mode: mode})
	addrs := [4]net.Addr{dc.LocalAddr(), dc.RemoteAddr(), pc.LocalAddr(), pc.RemoteAddr()}
	if mode == rendr.ModeBond {
		waitFor(t, 10*time.Second, "three members on both ends", func() bool {
			return len(liveOf(dc.Status())) == 3 && len(liveOf(pc.Status())) == 3
		})
	}
	e := startEcho(pc, 1)
	f := startFlow(dc, dc, flowCfg{name: "echo", seed: 1, rate: pps, size: size})

	// Mid-run: the victim refuses dials and stalls silently.
	sleepUntil(f.start.Add(dur / 2))
	var victim rendr.CarrierStatus
	if mode == rendr.ModeSelector {
		var ok bool
		if victim, ok = activeOf(dc.Status()); !ok {
			t.Fatalf("stimulus: no active carrier at fault time: %+v", dc.Status())
		}
	} else {
		var ok bool
		if victim, ok = liveNamed(dc.Status(), "p2"); !ok {
			t.Fatalf("stimulus: no p2 member at fault time: %+v", dc.Status())
		}
	}
	pvictim, ok := carrierOf(pc.Status(), victim.ID)
	if !ok {
		t.Fatalf("the passive does not know carrier %d: %+v", victim.ID, pc.Status().Carriers)
	}
	vl := w.link(victim.Name)
	held0 := vl.Stats().Session.Held
	// The TxBytes snapshots above are taken two one-way delays before the
	// stall: what either end placed on the victim before them has crossed
	// it when the stall starts, so every datagram the stall loses was
	// placed after them and counts in the deltas checked below (a
	// datagram placed just before a snapshot and still in flight was lost
	// without counting: a premise flake of the Linux race lane).
	time.Sleep(2 * oneWay)
	vl.Refuse(true)
	stall := time.Now()
	for _, dir := range bothDirs {
		vl.Stall(dir, true)
	}

	sleepUntil(f.start.Add(dur))
	f.halt(t)
	end := time.Now()
	time.Sleep(500 * time.Millisecond)

	// Stimulus: the stall held session datagrams; the victim died on both
	// ends.
	if h := vl.Stats().Session.Held; h == held0 {
		t.Fatalf("stimulus: no session datagram was held on the stalled %s", vl.Name())
	}
	var died [2]time.Time
	for i, c := range []*rendr.PacketConn{dc, pc} {
		cs, ok := carrierOf(c.Status(), victim.ID)
		if !ok || cs.State != rendr.CarrierDead {
			t.Fatalf("%s: the victim carrier %d is %+v (found %v), want dead", side(i), victim.ID, cs, ok)
		}
		ev, ok := [2]*eventLog{w.dev, w.pev}[i].downOf(victim.ID)
		if !ok {
			t.Fatalf("%s: no CarrierDown for the victim %d", side(i), victim.ID)
		}
		died[i] = ev.Time
		t.Logf("%s: victim %d (%s) dead +%v: %v %q", side(i), victim.ID, victim.Name, ev.Time.Sub(stall), cs.DeathCause, cs.DeathDetail)
	}

	// Load and the reply gap.
	sent := int(f.accepted.Load())
	if want := int(0.95 * pps * dur.Seconds()); sent < want {
		t.Fatalf("load: %d datagrams sent, want ≥ %d", sent, want)
	}
	gap := f.maxGap(f.start, end)
	ls := f.losses()
	replies := 0
	f.mu.Lock()
	for _, a := range f.order {
		if a.After(end.Add(-tail)) && !a.After(end) {
			replies++
		}
	}
	f.mu.Unlock()
	t.Logf("gap=%v lost=%d/%d tail=%d (bound %v)", gap, len(ls), sent, replies, gapBound)
	if gap > gapBound { // the bond's gap stays short: its survivors keep answering
		t.Fatalf("the largest reply gap is %v, want ≤ PacketPing + D + 2·RTT + 50 ms = %v", gap, gapBound)
	}
	rate := float64(sent) / dur.Seconds()
	if maxLost := int(rate*(gap+d).Seconds() + rate/2); len(ls) > maxLost {
		t.Fatalf("lost %d of %d datagrams, want ≤ %d (gap %v)", len(ls), sent, maxLost, gap)
	}
	if want := int(0.75 * rate * tail.Seconds()); replies < want {
		t.Fatalf("%d replies in the last %v, want ≥ %d", replies, tail, want)
	}
	if len(ls) == 0 && mode == rendr.ModeSelector {
		t.Fatalf("stimulus: the stall of the active carrier cost no datagram")
	}

	// Where each loss came from.
	if mode == rendr.ModeSelector {
		if a, ok := activeOf(dc.Status()); !ok || a.ID == victim.ID || a.Name == victim.Name {
			t.Fatalf("the active carrier %d on %s was never replaced: %+v (found %v)", victim.ID, victim.Name, a, ok)
		}
		recovery := f.firstArrivalWrittenFrom(stall)
		for _, l := range ls {
			if l.wrote.Before(stall.Add(-2*oneWay)) || l.wrote.After(recovery) {
				t.Fatalf("seq %d, written at %+v of the stall, was lost: outside [−2·%v, recovery +%v]",
					l.seq, l.wrote.Sub(stall), oneWay, recovery.Sub(stall))
			}
		}
	} else {
		// A request is lost on the way up when the passive never got it:
		// the dialer placed it on p2 between the stall and its verdict. A
		// reply is lost on the way down: the passive placed it on p2
		// before it left p2, at the earlier of its own verdict and the
		// dialer's SCHED that removed p2 (plan:152; the SCHED arrives one
		// way after the dialer's verdict, 50 ms cover its handling). At
		// msess's scales both ends die within a few ms of each other, so
		// the SCHED rule is rarely the binding one here (TestG3Miniature's
		// bond covers it).
		leave := died[1]
		if sched := died[0].Add(oneWay + 50*time.Millisecond); sched.Before(leave) {
			leave = sched
		}
		up, down := 0, 0
		for _, l := range ls {
			at, echoed := e.echoedAt(uint64(l.seq))
			switch {
			case !echoed && (l.wrote.Before(stall.Add(-oneWay)) || l.wrote.After(died[0])):
				t.Fatalf("request %d, written at %+v of the stall, was lost outside p2's share [−%v, +%v]",
					l.seq, l.wrote.Sub(stall), oneWay, died[0].Sub(stall))
			case echoed && (at.Before(stall.Add(-oneWay)) || at.After(leave)):
				t.Fatalf("the reply to %d, echoed at %+v of the stall, was lost outside p2's share [−%v, +%v]",
					l.seq, at.Sub(stall), oneWay, leave.Sub(stall))
			case echoed:
				down++
			default:
				up++
			}
		}
		dv, _ := carrierOf(dc.Status(), victim.ID)
		pv, _ := carrierOf(pc.Status(), victim.ID)
		if uint64(up*size) > dv.TxBytes-victim.TxBytes || uint64(down*size) > pv.TxBytes-pvictim.TxBytes {
			t.Fatalf("%d requests and %d replies lost, but after the stall the dialer placed %d bytes and the passive %d on p2",
				up, down, dv.TxBytes-victim.TxBytes, pv.TxBytes-pvictim.TxBytes)
		}
		t.Logf("lost: %d requests, %d replies; p2 dial failures %d", up, down, vl.Stats().DialFailures)
	}

	// Integrity and the counters: every reply intact, the dialer's
	// datagrams sent or counted, the passive read every one it received.
	f.integrity(t)
	f.nonBlocking(t)
	waitFor(t, 5*time.Second, "the accounting to settle", func() bool {
		ds, ps := dc.Status().Packet, pc.Status().Packet
		return ds.Sent+drops(ds) == uint64(sent) && ps.Received == uint64(e.reads.Load()) &&
			ps.Sent+drops(ps) == uint64(e.writes.Load()) && ds.Received == uint64(f.read.Load())
	})
	if ds := dc.Status().Packet; ds.Sent < uint64(sent)-uint64(len(ls)) {
		t.Fatalf("the dialer sent %d of %d datagrams, %d of them answered", ds.Sent, sent, sent-len(ls))
	}
	attribution(t, w, dc, pc)

	// One session, one PendingPacket, the same logical addresses.
	if n := w.pendings(); n != 1 {
		t.Fatalf("the passive was offered %d PendingPackets for one packet session", n)
	}
	if n := sessionsOf(w.p); n != 1 {
		t.Fatalf("the passive holds %d sessions, want 1", n)
	}
	if now := [4]net.Addr{dc.LocalAddr(), dc.RemoteAddr(), pc.LocalAddr(), pc.RemoteAddr()}; now != addrs || addrs[0] != addrs[3] || addrs[1] != addrs[2] {
		t.Fatalf("logical addresses %v, at open %v", now, addrs)
	}

	// The dialer's Close ends both cleanly; no session on the passive 5 s
	// later.
	dc.Close()
	f.waitReader(t, 5*time.Second, net.ErrClosed)
	waitFor(t, 5*time.Second, "no session on the passive after Close", func() bool { return sessionsOf(w.p) == 0 })
	<-e.done
	if e.err != nil {
		t.Fatalf("echo: %v", e.err)
	}
	if res := e.v.Result(); res.Duplicates+res.Corrupt+res.BadSize != 0 {
		t.Fatalf("the passive received damaged or repeated datagrams: %+v", res)
	}
	for _, c := range []*rendr.PacketConn{dc, pc} {
		<-c.Done()
		if st := c.Status(); st.Err != io.EOF {
			t.Fatalf("%v session ended with %v, want io.EOF", st.Role, st.Err)
		}
	}
	w.noViolation()
	w.close()
}
