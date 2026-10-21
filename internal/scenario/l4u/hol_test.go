package l4u

import (
	"context"
	"fmt"
	"io"
	"net"
	"slices"
	"sort"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/l4"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Head-of-line blocking across flows (M6 delegate decisions after wave D,
// "G10 criterion 7, the quiet-path tail (C1)"; L40, L55, L08): two UDP
// flows of one Peer in the same direction, one carrying ML-100's keyframe
// bursts and one a low-rate control stream, share one datagram MUX trunk.
// A datagram rendr is handed is placed on the carrier at once (L40: a
// packet session never waits; L55: batching never waits for a batch to
// fill), so the carrier sees the two flows' datagrams in the order they
// were written: no datagram of the low-rate flow is delivered after a
// datagram of the bursty flow written after it, whatever is queued ahead
// of it, and on an idle path it crosses at once.

const (
	holRate      = 200e6 / 8 // the bottleneck: 200 Mbit/s, in bytes per second
	holBurstLen  = 729       // datagrams per burst (an IDR of ML-100's profile)
	holBigSize   = 1408      // ML-100's video shard
	holSmallSize = 40        // the control flow's datagram (an ENet ack)
	holEvery     = 4 * time.Millisecond
	holBigPort   = 47998
	holSmallPort = 47999
	// holQuietMax is the defect bound of the wave-D audit: on a path that
	// is not saturated no datagram is held longer than about 1 ms.
	holQuietMax = time.Millisecond
	// holBatchFrames is one trunk round's batch (carrier.MaxBatchFrames at
	// v2.0.0): on a sender that blocks, a datagram that became ready during
	// a round waits for the rest of that round's batch and then goes first
	// (the trunk serves the least recently served view first; the wave-D
	// audit's bound).
	holBatchFrames = 64
	// holBatchWait bounds a low-rate datagram's added delay behind a burst
	// in the paced arms: one round's batch of frames of at most kitMTU
	// bytes at holRate (3.75 ms), plus holQuietMax.
	holBatchWait = holBatchFrames*kitMTU*time.Second/holRate + holQuietMax
	// holBurstDrain is a burst's time at holRate, each datagram counted at
	// kitMTU bytes (its carrier datagram is at most that).
	holBurstDrain = holBurstLen * kitMTU * time.Second / holRate
)

// holStep spaces a burst's datagrams: 71 kpps, ML-100's rate inside a
// burst (about 800 Mbit/s, four times the bottleneck: the burst queues).
var holStep = time.Second / 71000

// holBursts are the bursts' starts after the schedule's origin, each at
// another phase of the low-rate flow's 4-ms grid; holSpan is the
// low-rate flow's span (it runs from the origin, before the first burst,
// until well after the last burst drained: a 729-datagram burst takes
// about 43 ms of the bottleneck). The race lane runs the first burst only
// (M5's racebudget rule through the package's race switch).
var (
	holBursts = []time.Duration{20*time.Millisecond + 300*time.Microsecond, 130*time.Millisecond + 1700*time.Microsecond, 240*time.Millisecond + 3100*time.Microsecond}
	holSpan   = 350 * time.Millisecond
)

// holArm is one arm of TestL4UNoHeadOfLineAcrossFlows_L40_L55.
type holArm struct {
	name string
	down bool // target → client (the passive sends, ML-100's video direction); else client → target
	// paced: the carrier conns' WriteTo returns only once its datagram
	// crossed the 200-Mbit/s bottleneck (a send buffer of one datagram,
	// the link itself unlimited): the queue builds inside rendr, where only
	// the trunk's per-view scheduling keeps the write order across flows.
	// Else the link is a FIFO bottleneck that queues (WriteTo never
	// blocks): the queue builds in the link.
	paced bool
}

// TestL4UNoHeadOfLineAcrossFlows_L40_L55 (M6 delegate decisions after wave
// D, C1's head-of-line guard; L40, L55, L08): one PortForward on a Peer of
// one rendrtest DatagramLink (200 Mbit/s, 10 ms each way) serves two
// target ports; one flow carries bursts of 729 × 1,408-byte datagrams
// written at 71 kpps, the other 40-byte datagrams written every 4 ms, in
// the same direction, both on the same datagram MUX trunk. Four arms:
// either direction, and either a FIFO link that queues or carrier conns
// whose WriteTo returns only once the datagram crossed the bottleneck.
//
// Stimulus: each burst arrives four times faster than the bottleneck
// drains; low-rate datagrams are written while bursty datagrams written
// before them are still on their way (at least two per burst), and others
// while the path is idle (at least ten).
//
// PASS: every datagram of both flows arrives once and intact; no
// low-rate datagram arrives after a bursty datagram written after it (the
// FIFO order of the writes); a low-rate datagram written while no bursty
// datagram is on its way arrives within its 10-ms delay plus holQuietMax;
// in the paced arms (the queue inside rendr) a low-rate datagram written
// behind a burst waits at most holBatchWait beyond the link's delay (the
// rest of one trunk round at the path rate, plus holQuietMax); no bursty
// datagram takes longer than its burst's drain at the path rate after the
// burst's last write, plus the link's delay and holQuietMax; the two flows
// are one session each on one shared carrier and their sessions dropped
// nothing. The low-rate flow's added delay (beyond the link's 10 ms) is
// logged, as is the bursty flow's.
func TestL4UNoHeadOfLineAcrossFlows_L40_L55(t *testing.T) {
	for _, a := range []holArm{
		{name: "down/fifo", down: true},
		{name: "down/paced", down: true, paced: true},
		{name: "up/fifo"},
		{name: "up/paced", paced: true},
	} {
		t.Run(a.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { holRun(t, a) })
		})
	}
}

// holRun is one arm.
func holRun(t *testing.T, a holArm) {
	bursts, span := holBursts, holSpan
	if raceEnabled {
		bursts, span = bursts[:1], 130*time.Millisecond
	}
	w := newWorld(t, worldOpts{})
	p := holPeer(w, a.paced)
	big, small := newLedger("bursty flow", 71), newLedger("low-rate flow", 72)
	type role struct {
		port  uint16
		l     *ledger
		ready chan *egress
	}
	roles := []role{{holBigPort, big, make(chan *egress, 1)}, {holSmallPort, small, make(chan *egress, 1)}}
	pf := &l4.PortForward{Peer: p}
	clients := make([]*rendrtest.DatagramConn, len(roles))
	for i, r := range roles {
		up := r.l
		if a.down {
			up = nil // the target only sends
		}
		w.target(r.port, holTarget(r.ready, up))
		in := w.forward(pf, targetAddr(r.port), hubCfg(i))
		clients[i] = in.client(clientSrc(i))
		if a.down {
			startReader(clients[i], r.l.arrive)
		}
		if _, err := clients[i].Write([]byte("opener..")); err != nil {
			t.Fatalf("%s: the opener: %v", r.l.name, err)
		}
	}
	egs := make([]*egress, len(roles))
	for i, r := range roles {
		select {
		case egs[i] = <-r.ready:
		case <-time.After(5 * time.Second):
			t.Fatalf("premise: %s did not open within 5 s: %+v", r.l.name, plainF(pf.Status().UDP))
		}
	}
	waitFor(t, 5*time.Second, "both flows open at the ingress", func() bool {
		for i := range roles {
			if fi, ok := flowOf(pf, clientSrc(i)); !ok || fi.State != l4.FlowOpen {
				return false
			}
		}
		return true
	})
	var ids [2]rendr.CarrierID
	for i := range roles {
		fi, _ := flowOf(pf, clientSrc(i))
		c, ok := activeOf(fi.Session)
		if !ok {
			t.Fatalf("premise: %s has no active carrier: %+v", roles[i].l.name, fi.Session.Carriers)
		}
		ids[i] = c.ID
	}
	if ids[0] != ids[1] || w.d.Status().Mux.Views != 2 {
		t.Fatalf("premise: the flows ride carriers %v (%d mux views), want one shared datagram trunk", ids, w.d.Status().Mux.Views)
	}

	// The schedule, from origin t0: the low-rate flow every 4 ms over the
	// span, the bursts at their starts, datagram j of a burst j·holStep
	// after it.
	t0 := time.Now().Add(100 * time.Millisecond)
	wr := func(i int) io.Writer {
		if a.down {
			return egs[i].conn
		}
		return clients[i]
	}
	gb := holWriter(w.quit, wr(0), big, holBigSize, func(k int) (time.Time, bool) {
		if k >= len(bursts)*holBurstLen {
			return time.Time{}, false
		}
		return t0.Add(bursts[k/holBurstLen] + time.Duration(k%holBurstLen)*holStep), true
	})
	gs := holWriter(w.quit, wr(1), small, holSmallSize, func(k int) (time.Time, bool) {
		at := time.Duration(k) * holEvery
		return t0.Add(at), at < span
	})
	gb.wait(t, big.name)
	gs.wait(t, small.name)
	end := t0.Add(span)
	sleepUntil(end.Add(100 * time.Millisecond)) // the last datagrams' delay and more

	for _, l := range []*ledger{big, small} {
		l.integrity(t)
		if ls := l.losses(end); len(ls) != 0 {
			t.Fatalf("%s: %d of %d datagrams lost (first: seq %d sent at +%v)", l.name, len(ls), l.sentCount(), ls[0].seq, ls[0].sent.Sub(t0))
		}
	}
	if n := big.sentCount(); n != len(bursts)*holBurstLen {
		t.Fatalf("stimulus: %d bursty datagrams written, want %d", n, len(bursts)*holBurstLen)
	}
	r := holJudge(big.holSamples(), small.holSamples(), oneWay)
	t.Logf("%s: low-rate flow, %d datagrams: added delay p50 %v, p99 %v, max %v (behind a burst: %d, max %v; on an idle path: %d, max %v); bursty flow: max delay %v (link %v one way)",
		a.name, r.small, r.addP50, r.addP99, r.addMax, r.behind, r.behindMax, r.quiet, r.quietMax, r.bigMax, oneWay)
	if r.behind < 2*len(bursts) || r.quiet < 10 {
		t.Fatalf("stimulus: %d low-rate datagrams written behind a burst (want at least %d), %d on an idle path (want at least 10)", r.behind, 2*len(bursts), r.quiet)
	}
	if len(r.overtaken) != 0 {
		t.Fatalf("head-of-line: %d low-rate datagrams arrived after a bursty datagram written after them; first: %s", len(r.overtaken), r.overtaken[0].describe(t0))
	}
	if r.quietMax > holQuietMax {
		t.Fatalf("a low-rate datagram written on an idle path was held %v beyond the link's delay, above %v (L55: no hold waits for more datagrams, a timer or a batch)", r.quietMax, holQuietMax)
	}
	if a.paced && r.behindMax > holBatchWait {
		t.Fatalf("a low-rate datagram written behind a burst waited %v beyond the link's delay, above %v: the rest of one trunk round (%d frames of at most %d bytes at the path rate) plus %v (L40, L55: on a sender that blocks a ready datagram waits for one round, not for more datagrams or a timer)",
			r.behindMax, holBatchWait, holBatchFrames, kitMTU, holQuietMax)
	}
	if bound := holBurstDrain - time.Duration(holBurstLen-1)*holStep + oneWay + holQuietMax; r.bigMax > bound {
		t.Fatalf("a bursty datagram took %v, above %v: its burst's drain at the path rate after the burst's last write, plus the link's delay and %v (L55: rendr held datagrams of a backlog)", r.bigMax, bound, holQuietMax)
	}
	for i := range roles {
		fi, _ := flowOf(pf, clientSrc(i))
		if pc := fi.Session.Packet; pc == nil || pc.DropQueue+pc.DropAge+pc.DropTooLarge+pc.DropNoPath+pc.DropRecvQueue != 0 {
			t.Fatalf("%s: the dialer session's counters %+v, want no drop", roles[i].l.name, pc)
		}
	}
	if f, s := pf.Status().UDP, w.srv.Status().UDP; f.Opened != 2 || s.Confirmed != 2 || f.Ended != (l4.FlowEnds{}) || s.Ended != (l4.FlowEnds{}) {
		t.Fatalf("flows: %d opened, %d confirmed, ended %+v at the ingress and %+v at the Server; want two, none ended", f.Opened, s.Confirmed, f.Ended, s.Ended)
	}
	w.close()
	if f, s := pf.Status().UDP.SessionDrops, w.srv.Status().UDP.SessionDrops; f != 0 || s != 0 {
		t.Fatalf("the flows' sessions dropped %d datagrams at the ingress and %d at the Server, want none", f, s)
	}
}

// holPeer adds the arm's DatagramLink u1 (10 ms each way; a 200-Mbit/s
// FIFO bottleneck each way, or paced carrier conns at both ends) to w and
// returns a Peer over it. The world closes the link and the Peer.
func holPeer(w *world, paced bool) *rendr.Peer {
	w.t.Helper()
	accept := w.ln.HandlePacket
	if paced {
		accept = func(pc net.PacketConn, peer net.Addr) error { return w.ln.HandlePacket(newHolPaced(pc), peer) }
	}
	l := rendrtest.NewDatagramLink(rendrtest.DatagramLinkConfig{Name: "u1", MTU: kitLinkMTU, Queue: 16384, Accept: accept})
	for _, d := range bothDirs {
		l.SetDelay(d, oneWay, 0)
		if !paced {
			l.SetRate(d, holRate)
		}
	}
	w.dlinks["u1"] = l
	w.specs = append(w.specs, linkSpec{name: "u1"})
	dial := func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		pc, ad, err := l.Dial(ctx)
		if err != nil || !paced {
			return pc, ad, err
		}
		return newHolPaced(pc), ad, nil
	}
	p, err := w.d.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{rendr.DatagramCarrier{Name: "u1", MTU: kitMTU, Dial: dial}}})
	if err != nil {
		w.t.Fatalf("NewPeer: %v", err)
	}
	w.mu.Lock()
	w.peers = append(w.peers, p)
	w.mu.Unlock()
	return p
}

// holPaced is a carrier conn of the paced arm: WriteTo takes its
// datagram's time at holRate (len/holRate) and then hands it to the
// unlimited link, one call at a time (a channel, so that a second writer
// waits durably inside the bubble).
type holPaced struct {
	net.PacketConn
	turn chan struct{}
}

func newHolPaced(pc net.PacketConn) *holPaced {
	return &holPaced{PacketConn: pc, turn: make(chan struct{}, 1)}
}

func (c *holPaced) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.turn <- struct{}{}
	defer func() { <-c.turn }()
	time.Sleep(time.Duration(float64(len(b)) * float64(time.Second) / holRate))
	return c.PacketConn.WriteTo(b, addr)
}

// holTarget is the arms' target application: it reads the flow's opener,
// hands its egress to ready and then reads the flow's datagrams, each
// verified by l (nil: the target only sends, the row's writer uses
// e.conn).
func holTarget(ready chan<- *egress, l *ledger) targetApp {
	return func(e *egress) {
		buf := make([]byte, 64<<10)
		if _, err := e.conn.Read(buf); err != nil {
			return
		}
		ready <- e
		for {
			n, err := e.conn.Read(buf)
			if err != nil {
				return
			}
			if l != nil {
				l.arrive(buf[:n], time.Now())
			}
		}
	}
}

// holWriter writes l's datagrams of size bytes to wr, datagram k at due(k)
// (false: the schedule ended), each at its own instant, until quit.
func holWriter(quit <-chan struct{}, wr io.Writer, l *ledger, size int, due func(k int) (time.Time, bool)) *gen {
	g := &gen{done: make(chan struct{})}
	go func() {
		defer close(g.done)
		buf := make([]byte, size)
		for k := 0; ; k++ {
			at, ok := due(k)
			if !ok || !pace(quit, at) {
				return
			}
			if _, err := wr.Write(l.next(buf, size, time.Now())); err != nil {
				if g.errs++; g.err == nil {
					g.err = err
				}
			}
		}
	}()
	return g
}

// holSample is one datagram: its write and its arrival (zero: none).
type holSample struct{ w, a time.Time }

// holSamples returns the ledger's datagrams in seq order (their write
// order).
func (l *ledger) holSamples() []holSample {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]holSample, len(l.sent))
	for seq, at := range l.sent {
		out[seq].w = at
		if seq < len(l.arr) {
			out[seq].a = l.arr[seq]
		}
	}
	return out
}

// holOvertake is one head-of-line violation: low-rate datagram seq,
// written at w and arrived at a, after the bursty datagram big, written at
// bw (after w), arrived at ba.
type holOvertake struct {
	seq, big     int
	w, a, bw, ba time.Time
}

func (o holOvertake) describe(t0 time.Time) string {
	return fmt.Sprintf("low-rate seq %d written at +%v arrived at +%v, bursty seq %d written at +%v arrived at +%v",
		o.seq, o.w.Sub(t0), o.a.Sub(t0), o.big, o.bw.Sub(t0), o.ba.Sub(t0))
}

// holResult is holJudge's verdict material.
type holResult struct {
	small                  int             // low-rate datagrams that arrived
	overtaken              []holOvertake   // the head-of-line violations
	behind, quiet          int             // low-rate datagrams written behind a bursty one on its way; on an idle path
	behindMax, quietMax    time.Duration   // their largest added delay
	addP50, addP99, addMax time.Duration   // the low-rate flow's added delay (beyond oneWay)
	bigMax                 time.Duration   // the bursty flow's largest delay
	added                  []time.Duration // every low-rate added delay, in write order
}

// holJudge compares the flows: for each low-rate datagram that arrived,
// the earliest arrival of a bursty datagram written strictly after it
// (a suffix minimum over the bursty flow in write order) must not precede
// its own; it is "behind" when a bursty datagram written before it had not
// arrived at its write, "quiet" when none was on its way. Datagrams that
// never arrived are the ledger's losses (judged apart).
func holJudge(big, small []holSample, oneWay time.Duration) holResult {
	var r holResult
	n := len(big)
	sufMin := make([]time.Time, n+1)
	sufIdx := make([]int, n+1)
	sufIdx[n] = -1
	for j := n - 1; j >= 0; j-- {
		sufMin[j], sufIdx[j] = sufMin[j+1], sufIdx[j+1]
		if a := big[j].a; !a.IsZero() && (sufMin[j].IsZero() || a.Before(sufMin[j])) {
			sufMin[j], sufIdx[j] = a, j
		}
		if a := big[j].a; !a.IsZero() {
			r.bigMax = max(r.bigMax, a.Sub(big[j].w))
		}
	}
	// lastOut[j]: the latest arrival among bursty datagrams 0 … j.
	lastOut := make([]time.Time, n)
	for j := range big {
		if j > 0 {
			lastOut[j] = lastOut[j-1]
		}
		if a := big[j].a; a.After(lastOut[j]) {
			lastOut[j] = a
		}
	}
	for seq, s := range small {
		if s.a.IsZero() {
			continue
		}
		r.small++
		add := s.a.Sub(s.w) - oneWay
		r.added = append(r.added, add)
		r.addMax = max(r.addMax, add)
		j := sort.Search(n, func(i int) bool { return big[i].w.After(s.w) }) // the first bursty datagram written after s
		if j < n && !sufMin[j].IsZero() && s.a.After(sufMin[j]) {
			k := sufIdx[j]
			r.overtaken = append(r.overtaken, holOvertake{seq: seq, big: k, w: s.w, a: s.a, bw: big[k].w, ba: big[k].a})
		}
		// Bursty datagrams written at or before s: 0 … j−1.
		if j > 0 && lastOut[j-1].After(s.w) {
			r.behind++
			r.behindMax = max(r.behindMax, add)
		} else {
			r.quiet++
			r.quietMax = max(r.quietMax, add)
		}
	}
	if len(r.added) > 0 {
		s := slices.Clone(r.added)
		slices.Sort(s)
		r.addP50, r.addP99 = s[(len(s)-1)/2], s[(len(s)-1)*99/100]
	}
	return r
}
