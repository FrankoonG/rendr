package lessons5

import (
	"bytes"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// noDialWait is a Config whose Dials do not wait for probe samples.
func noDialWait() rendr.Config {
	return rendr.Config{Probe: rendr.ProbePolicy{DialWait: -1}}
}

// tailLoss arms the tail-loss stimulus on l in direction d for frames of
// type t: the first copy of the next datagram carrying one is dropped, and
// it and the next one carrying t (the resend) are captured.
type tailLoss struct {
	first, resend <-chan capture
	lostBefore    uint64
	l             *rendrtest.DatagramLink
}

func armTailLoss(l *rendrtest.DatagramLink, d rendrtest.Dir, t rendrtest.FrameType, stop <-chan struct{}) *tailLoss {
	tl := &tailLoss{l: l, lostBefore: l.Stats().Session.Lost}
	tl.first = stamp(l.CaptureNext(d, t), stop)
	tl.resend = stamp(l.CaptureNext(d, t), stop)
	l.DropNext(d, t, 1)
	return tl
}

// verify requires that the first copy was captured and lost on the link
// and that the resend carried a byte-identical REL payload in a new frame
// (a new fseq); it returns both captures.
func (tl *tailLoss) verify(t *testing.T, it wire.Type) (first, resend capture) {
	t.Helper()
	select {
	case first = <-tl.first:
	default:
		t.Fatalf("stimulus: no %v was captured", it)
	}
	select {
	case resend = <-tl.resend:
	default:
		t.Fatalf("the lost %v was never resent", it)
	}
	if lost := tl.l.Stats().Session.Lost - tl.lostBefore; lost < 1 {
		t.Fatalf("stimulus: the link lost no session datagram (Lost +%d)", lost)
	}
	p1, f1, ok1 := relOf(first.b, it)
	p2, f2, ok2 := relOf(resend.b, it)
	if !ok1 || !ok2 {
		t.Fatalf("captured datagrams hold no REL{%v}: %x / %x", it, first.b, resend.b)
	}
	if !bytes.Equal(p1, p2) {
		t.Fatalf("the resent REL payload differs from the lost one:\n%x\n%x", p1, p2)
	}
	if f1 == f2 {
		t.Fatalf("the resend reused fseq %d (a REL resend is a new frame, M2-D16)", f1)
	}
	return first, resend
}

// TestControlTailLoss_L12: the reliable control sublayer repairs the loss
// of the last frame of an exchange — nothing follows that could reveal the
// gap, so only REL's own timer can. The first copy of the packet FIN, of a
// SCHED and of an OPEN_ACK is dropped on the link: the REL is resent with a
// byte-identical payload in a new frame, and the exchange completes within
// 1 s of the loss (the passive's io.EOF; the SCHED epochs and their echo
// converge; DialPacket returns), with every datagram of the session intact.
func TestControlTailLoss_L12(t *testing.T) {
	t.Run("FIN", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			stop := make(chan struct{})
			defer close(stop)
			w := newWorld(t, worldOpts{}, "a")
			l := w.links[0]
			l.SetDelay(rendrtest.Up, 10*time.Millisecond, 0)
			l.SetDelay(rendrtest.Down, 10*time.Millisecond, 0)
			dc, pc := w.open(w.peer(w.dgCarrier(l, 1400)), rendr.DialOptions{})
			r := readPackets(pc, 1)
			wr := writePackets(dc, 1, 0, 100, time.Millisecond, nil)
			wr.wait(t, 5*time.Second, "datagrams before the FIN")
			waitFor(t, time.Second, "100 datagrams", func() bool { return r.n.Load() == 100 })
			time.Sleep(time.Second) // the cadence PACKs are out: nothing else is due
			retx := retransmits(dc.Status())
			tl := armTailLoss(l, rendrtest.Up, rendrtest.FrameFin, stop)
			dc.Close()
			res := r.wait(t, 5*time.Second, "the passive")
			first, resend := tl.verify(t, wire.TypeFin)
			if d := r.endAt.Sub(first.at); d > time.Second {
				t.Fatalf("io.EOF %v after the FIN's first copy was lost, want within 1 s", d)
			}
			if res.Unique != 100 || len(res.Missing) != 0 {
				t.Fatalf("before io.EOF: %+v, want all 100 datagrams", res)
			}
			if got := retransmits(dc.Status()); got <= retx {
				t.Fatalf("the dialer's carrier counted no REL retransmission (%d → %d)", retx, got)
			}
			t.Logf("FIN lost at %v, resent %v later, io.EOF %v after the loss",
				first.at.Format("05.000"), resend.at.Sub(first.at), r.endAt.Sub(first.at))
			pc.Close()
			waitDone(t, 5*time.Second, dc, pc)
			w.noViolation()
			w.close()
		})
	})

	t.Run("SCHED", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			stop := make(chan struct{})
			defer close(stop)
			w := newWorld(t, worldOpts{dcfg: noDialWait()}, "a", "b")
			la, lb := w.links[0], w.links[1]
			for _, l := range w.links {
				l.SetDelay(rendrtest.Up, 10*time.Millisecond, 0)
				l.SetDelay(rendrtest.Down, 10*time.Millisecond, 0)
			}
			dc, pc := w.open(w.peer(w.dgCarrier(la, 1400), w.dgCarrier(lb, 1400)), rendr.DialOptions{})
			act, ok := activeOf(dc.Status())
			if !ok || act.Name != "a" {
				t.Fatalf("the session did not start on a: %+v", dc.Status().Carriers)
			}
			waitFor(t, 5*time.Second, "the first epoch echoed", func() bool {
				ds := dc.Status()
				return ds.SchedEchoed == ds.SchedEpoch && pc.Status().SchedEpoch == ds.SchedEpoch
			})
			epoch := dc.Status().SchedEpoch
			r := readPackets(pc, 2)
			// The death of a moves the session to b: the dialer publishes a
			// new epoch there, and its first copy is lost.
			tl := armTailLoss(lb, rendrtest.Up, rendrtest.FrameSched, stop)
			la.Refuse(true)
			la.Kill()
			waitFor(t, 5*time.Second, "the epochs converge", func() bool {
				ds := dc.Status()
				return ds.SchedEpoch > epoch && ds.SchedEchoed == ds.SchedEpoch && pc.Status().SchedEpoch == ds.SchedEpoch
			})
			converged := time.Now()
			first, resend := tl.verify(t, wire.TypeSched)
			if d := converged.Sub(first.at); d > time.Second {
				t.Fatalf("the epochs converged %v after the SCHED's first copy was lost, want within 1 s", d)
			}
			if act, ok := activeOf(dc.Status()); !ok || act.Name != "b" {
				t.Fatalf("the session is not on b: %+v", dc.Status().Carriers)
			}
			if m := dc.Status().Migrations; m.Death != 1 {
				t.Fatalf("migrations %+v, want one death", m)
			}
			// Load across the new epoch: both directions on b.
			wr := writePackets(dc, 2, 0, 200, time.Millisecond, nil)
			back := readPackets(dc, 3)
			wb := writePackets(pc, 3, 0, 200, time.Millisecond, nil)
			wr.wait(t, 5*time.Second, "dialer → passive")
			wb.wait(t, 5*time.Second, "passive → dialer")
			waitFor(t, 2*time.Second, "200 datagrams each way", func() bool { return r.n.Load() == 200 && back.n.Load() == 200 })
			t.Logf("SCHED epoch %d lost at %v, resent %v later; converged %v after the loss",
				dc.Status().SchedEpoch, first.at.Format("05.000"), resend.at.Sub(first.at), converged.Sub(first.at))
			dc.Close()
			r.wait(t, 5*time.Second, "dialer → passive")
			back.waitClosed(t, 5*time.Second, "passive → dialer")
			pc.Close()
			waitDone(t, 5*time.Second, dc, pc)
			w.noViolation()
			w.close()
		})
	})

	t.Run("OPEN_ACK", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			stop := make(chan struct{})
			defer close(stop)
			w := newWorld(t, worldOpts{}, "a")
			l := w.links[0]
			l.SetDelay(rendrtest.Up, 10*time.Millisecond, 0)
			l.SetDelay(rendrtest.Down, 10*time.Millisecond, 0)
			tl := armTailLoss(l, rendrtest.Down, rendrtest.FrameOpenAck, stop)
			res := dialAsync(w.peer(w.dgCarrier(l, 1400)), rendr.DialOptions{})
			pc, err := w.pending().Confirm()
			if err != nil {
				t.Fatalf("Confirm: %v", err)
			}
			d := <-res
			if d.err != nil {
				t.Fatalf("DialPacket: %v", d.err)
			}
			dc := d.c
			first, resend := tl.verify(t, wire.TypeOpenAck)
			if lat := d.at.Sub(first.at); lat > time.Second {
				t.Fatalf("DialPacket returned %v after the OPEN_ACK's first copy was lost, want within 1 s", lat)
			}
			if pc.Status().Carriers[0].Retransmits == 0 {
				t.Fatalf("the passive's carrier counted no REL retransmission: %+v", pc.Status().Carriers)
			}
			r := readPackets(pc, 4)
			back := readPackets(dc, 5)
			wr := writePackets(dc, 4, 0, 200, time.Millisecond, nil)
			wb := writePackets(pc, 5, 0, 200, time.Millisecond, nil)
			wr.wait(t, 5*time.Second, "dialer → passive")
			wb.wait(t, 5*time.Second, "passive → dialer")
			waitFor(t, 2*time.Second, "200 datagrams each way", func() bool { return r.n.Load() == 200 && back.n.Load() == 200 })
			t.Logf("OPEN_ACK lost at %v, resent %v later; DialPacket returned %v after the loss",
				first.at.Format("05.000"), resend.at.Sub(first.at), d.at.Sub(first.at))
			dc.Close()
			r.wait(t, 5*time.Second, "dialer → passive")
			back.waitClosed(t, 5*time.Second, "passive → dialer")
			pc.Close()
			waitDone(t, 5*time.Second, dc, pc)
			w.noViolation()
			w.close()
		})
	})
}

// relRetx is one REL retransmission reported by Hooks.RelRetransmit.
type relRetx struct {
	carrier rendr.CarrierID
	cseq    uint32
	at      time.Time
}

// retxLog records REL retransmissions.
type retxLog struct {
	mu  sync.Mutex
	all []relRetx
}

func (l *retxLog) add(c, cseq uint32) {
	l.mu.Lock()
	l.all = append(l.all, relRetx{rendr.CarrierID(c), cseq, time.Now()})
	l.mu.Unlock()
}

func (l *retxLog) snapshot() []relRetx {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]relRetx(nil), l.all...)
}

// TestControlPermanentLoss_L12: a carrier that loses every REL — here the
// active carrier of a closing packet session, whose FIN can never arrive
// over it while its PINGs and PONGs pass, so it lives on. REL resends only
// the oldest unacknowledged frame (single flight), once per backed-off
// RTO: the gaps double from the first RTO up to RelRTOMax (2 s). When the
// carrier dies its resends stop; the session places the FIN again on the
// replacement carrier, which delivers it, and the session ends cleanly with
// every datagram delivered. Never do two carriers resend: no other carrier
// retransmits while the first lives, and the first never after its death.
func TestControlPermanentLoss_L12(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		stop := make(chan struct{})
		defer close(stop)
		log := &retxLog{}
		hooks := &testhooks.Hooks{RelRetransmit: log.add}
		w := newWorld(t, worldOpts{dcfg: noDialWait(), dHooks: hooks}, "a", "b")
		la, lb := w.links[0], w.links[1]
		for _, l := range w.links {
			l.SetDelay(rendrtest.Up, 5*time.Millisecond, 0)
			l.SetDelay(rendrtest.Down, 5*time.Millisecond, 0)
		}
		dc, pc := w.open(w.peer(w.dgCarrier(la, 1400), w.dgCarrier(lb, 1400)), rendr.DialOptions{})
		act, ok := activeOf(dc.Status())
		if !ok || act.Name != "a" {
			t.Fatalf("the session did not start on a: %+v", dc.Status().Carriers)
		}
		r := readPackets(pc, 6)
		wr := writePackets(dc, 6, 0, 300, time.Millisecond, nil)
		wr.wait(t, 5*time.Second, "datagrams before the FIN")
		waitFor(t, time.Second, "300 datagrams", func() bool { return r.n.Load() == 300 })
		time.Sleep(time.Second)
		before := len(log.snapshot())
		lostBefore := la.Stats().Session.Lost

		// From now on a loses every dialer datagram that carries a REL.
		fin := stamp(la.CaptureNext(rendrtest.Up, rendrtest.FrameFin), stop)
		la.DropNext(rendrtest.Up, rendrtest.FrameRel, 1<<30)
		dc.Close()
		time.Sleep(6500 * time.Millisecond)
		select {
		case <-r.done:
			t.Fatalf("the passive's reader ended before a's death: %v", r.err)
		default:
		}
		if _, ok := carrierOf(dc.Status(), act.ID); !ok {
			t.Fatalf("a's carrier is gone from the status: %+v", dc.Status().Carriers)
		}
		if c, _ := carrierOf(dc.Status(), act.ID); c.State == rendr.CarrierDead {
			t.Fatalf("the carrier on a died of REL loss alone (%v %q): its PINGs pass", c.DeathCause, c.DeathDetail)
		}
		la.Refuse(true)
		la.Kill()
		killAt := time.Now()
		res := r.wait(t, 5*time.Second, "the passive")
		pc.Close()
		waitDone(t, 5*time.Second, dc, pc)
		eofAfter := r.endAt.Sub(killAt)
		time.Sleep(5 * time.Second) // a resend that would follow the death has its chance

		var first capture
		select {
		case first = <-fin:
		default:
			t.Fatal("stimulus: no FIN was written on a")
		}
		all := log.snapshot()[before:]
		var onA []relRetx
		for _, x := range all {
			switch {
			case x.carrier == act.ID:
				onA = append(onA, x)
			case !x.at.After(killAt):
				t.Fatalf("carrier %d resent cseq %d at %v while a's carrier was alive: two resenders", x.carrier, x.cseq, x.at.Sub(first.at))
			}
		}
		if lost := la.Stats().Session.Lost - lostBefore; lost < uint64(len(onA))+1 {
			t.Fatalf("stimulus: a lost %d session datagrams, want the FIN and its %d resends", lost, len(onA))
		}
		// The schedule: the first RTO (RelRTOMin 200 ms: the carrier has RTT
		// samples), then doubling gaps capped at 2 s: 0.2, 0.6, 1.4, 3.0,
		// 5.0 s after the FIN — five resends before the death at 6.5 s.
		if len(onA) < 4 || len(onA) > 6 {
			t.Fatalf("%d resends on a in 6.5 s, at %v after the FIN; want 5 (0.2, 0.6, 1.4, 3.0, 5.0 s)", len(onA), gaps(first.at, onA))
		}
		prev := first.at
		var gap time.Duration
		for i, x := range onA {
			if x.cseq != onA[0].cseq {
				t.Fatalf("resend %d is cseq %d, the first was %d: only the oldest unacknowledged REL is resent", i, x.cseq, onA[0].cseq)
			}
			if x.at.After(killAt) {
				t.Fatalf("resend %d on a at %v, after its death at %v", i, x.at.Sub(first.at), killAt.Sub(first.at))
			}
			g := x.at.Sub(prev)
			want := 200 * time.Millisecond
			if i > 0 {
				want = min(2*gap, 2*time.Second)
			}
			if g < want-5*time.Millisecond || g > want+50*time.Millisecond {
				t.Fatalf("resend %d came %v after the previous copy, want ≈ %v (backed-off RTO); resends at %v after the FIN", i, g, want, gaps(first.at, onA))
			}
			prev, gap = x.at, g
		}
		if res.Unique != 300 || len(res.Missing) != 0 {
			t.Fatalf("before io.EOF: %+v, want all 300 datagrams", res)
		}
		if eofAfter > 2*time.Second {
			t.Fatalf("io.EOF %v after a's death: the FIN was not placed on the replacement carrier at once", eofAfter)
		}
		var onB bool
		for _, c := range dc.Status().Carriers {
			if c.Name == "b" {
				onB = true
			}
		}
		if !onB {
			t.Fatalf("no carrier on b: %+v", dc.Status().Carriers)
		}
		t.Logf("FIN at %v; %d resends on a: %v; a killed at +%v; io.EOF %v later", first.at.Format("05.000"), len(onA),
			gaps(first.at, onA), killAt.Sub(first.at), eofAfter)
		w.noViolation()
		w.close()
	})
}

// gaps formats the times of resends relative to t0.
func gaps(t0 time.Time, xs []relRetx) []time.Duration {
	out := make([]time.Duration, len(xs))
	for i, x := range xs {
		out[i] = x.at.Sub(t0)
	}
	return out
}
