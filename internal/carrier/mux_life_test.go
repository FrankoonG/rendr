package carrier

import (
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// WP8 tests of a view's life on a MUX trunk: Done after the last call,
// the end record, view- and trunk-scoped kills, the fan-outs, the refusal
// ring and the handle state machine (M3 design §A5.1, §A5.4, §A5.6,
// §A5.7, §A5.12; M3-D12 … M3-D15; R1-2, R1-3, R1-4, R1-16).

// blockEP is a dEP whose Control and WriteBlocked calls can be held.
type blockEP struct {
	dEP
	inCtl, outCtl chan struct{}
	inWB, outWB   chan struct{}
}

func (e *blockEP) Control(c *Conn, h wire.Header, p []byte) error {
	if e.inCtl != nil && h.Type == wire.TypeFin {
		close(e.inCtl)
		<-e.outCtl
	}
	return e.dEP.Control(c, h, p)
}

func (e *blockEP) WriteBlocked(c *Conn) {
	if e.inWB != nil {
		select {
		case <-e.inWB:
		default:
			close(e.inWB)
			<-e.outWB
		}
	}
	e.dEP.WriteBlocked(c)
}

// liveRawView opens view h on a dialer against a raw peer, answers OK and
// attaches it with ep running a fresh source (the go frame first).
func liveRawView(t *testing.T, s *muxSide, p *wirePeer, h uint32, ep *blockEP, bell *hBell) (*Conn, *vSource) {
	t.Helper()
	v, wait := s.openRaw(t, wire.TypeOpen, byte(h))
	synctest.Wait()
	_ = p.send(wire.TypeOpenAck, 0, h, okAck(wire.TypeOpenAck))
	if _, err := wait(); err != nil {
		t.Fatal(err)
	}
	src := newVSource(s.env)
	ep.setFill(src.fill)
	v.Start(ep, bell, StartOptions{})
	synctest.Wait()
	return v, src
}

// rstPayload is an RST payload.
func rstPayload(code uint32) []byte {
	b := make([]byte, wire.RstFixedLen)
	wire.PutRst(b, &wire.Rst{Code: code})
	return b
}

// TestViewDoneAfterLastCall_L52 (M3-D13, R1-16; L52): a view's Done closes
// only when the view ended and no reader, writer or watchdog call into its
// endpoint is in progress — the call that brings the count to 0 closes it.
func TestViewDoneAfterLastCall_L52(t *testing.T) {
	t.Run("reader call", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, p := muxRawDialer(t, nil)
			ep := &blockEP{inCtl: make(chan struct{}), outCtl: make(chan struct{})}
			v, _ := liveRawView(t, s, p, 2, ep, &hBell{})
			_ = p.send(wire.TypeFin, 0, 2, finInner(0))
			<-ep.inCtl
			v.Kill(CauseLocalClose, "the session ended")
			synctest.Wait()
			if dead, _, _, _ := v.Death(); !dead {
				t.Fatal("no end record after Kill")
			}
			if isDone(v.Done()) {
				t.Fatal("Done closed while the reader's call into the view runs")
			}
			close(ep.outCtl)
			synctest.Wait()
			if !isDone(v.Done()) {
				t.Fatal("Done still open after the last call returned")
			}
		})
	})
	t.Run("trunk death", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, p := muxRawDialer(t, nil)
			ep := &blockEP{inCtl: make(chan struct{}), outCtl: make(chan struct{})}
			v, _ := liveRawView(t, s, p, 2, ep, &hBell{})
			_ = p.send(wire.TypeFin, 0, 2, finInner(0))
			<-ep.inCtl
			s.c.KillTrunk(CauseTransportError, "the path died")
			waitDone(t, s.c.trunk.tdone, "trunk") // the reader stuck in the call is abandoned
			synctest.Wait()
			if isDone(v.Done()) {
				t.Fatal("the view's Done closed at the trunk's while the reader's call into it runs")
			}
			close(ep.outCtl)
			synctest.Wait()
			if !isDone(v.Done()) {
				t.Fatal("Done still open after the last call returned")
			}
		})
	})
	t.Run("watchdog call", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, p := muxRawDialer(t, nil)
			ep := &blockEP{inWB: make(chan struct{}), outWB: make(chan struct{})}
			v, src := liveRawView(t, s, p, 2, ep, &hBell{})
			s.tap.hold()
			src.offer(1 << 20)
			v.Wake()
			<-ep.inWB // the watchdog's WriteBlocked call into the view runs
			v.Kill(CauseLocalClose, "the session ended")
			synctest.Wait()
			if isDone(v.Done()) {
				t.Fatal("Done closed while the watchdog's call into the view runs")
			}
			close(ep.outWB)
			synctest.Wait()
			if !isDone(v.Done()) {
				t.Fatal("Done still open after the watchdog's call returned")
			}
			s.tap.release()
		})
	})
	t.Run("OnDone in the close window", func(t *testing.T) {
		// The end is decided under trunk.mx (finishLocked: no call in
		// progress) and Done closes later, at runPost once mx is released.
		// An OnDone registered in between must ring once, after the close
		// (R1-7): a ring while Done is still open would be lost.
		synctest.Test(t, func(t *testing.T) {
			s, p := muxRawDialer(t, nil)
			v, _ := liveRawView(t, s, p, 2, &blockEP{}, &hBell{})
			var pl postList
			s.c.mx.Lock()
			s.c.finishLocked(v, &pl)
			s.c.mx.Unlock()
			b := &hBell{}
			v.OnDone(b)
			if n := b.n.Load(); n != 0 && !isDone(v.Done()) {
				t.Fatalf("OnDone rang %d time(s) while Done was still open", n)
			}
			s.c.runPost(&pl)
			if !isDone(v.Done()) || b.n.Load() != 1 {
				t.Fatalf("after the close: Done %v, OnDone rang %d times, want once", isDone(v.Done()), b.n.Load())
			}
		})
	})
}

// TestViewEndRecord (R1-3, M3-D62): every publisher of a view's end record
// publishes once — Kill with its cause, the DETACH exchange (retired),
// WriteAndClose (local_close once its frame was placed), a refusal on both
// sides (local_close) — and a view without one reports its trunk's death.
func TestViewEndRecord(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d, p := muxPair(t, nil)
		k, _ := d.open(t, wire.TypeOpen, 2)
		r, _ := d.open(t, wire.TypeOpen, 3)
		w, _ := d.open(t, wire.TypeOpen, 4)
		synctest.Wait()

		if !k.c.Kill(CauseWriteStall, "a session reason") || k.c.Kill(CauseLocalClose, "again") {
			t.Fatal("Kill did not publish exactly once")
		}
		r.c.Retire(wire.CloseRetire)
		w.c.WriteAndClose(wire.TypeRst, 0, 99, rstPayload(wire.RstWithdrawn), time.Time{})
		synctest.Wait()
		checks := []struct {
			mv     *mView
			cause  Cause
			detail string
		}{
			{k, CauseWriteStall, "a session reason"},
			{r, CauseRetired, "exchange complete"},
			{w, CauseLocalClose, "RST"},
		}
		for _, c := range checks {
			dead, cause, detail, _ := c.mv.c.Death()
			if !dead || cause != c.cause || !strings.Contains(detail, c.detail) {
				t.Fatalf("view %d: dead %v cause %v (%s), want %v (%s)", c.mv.c.Handle(), dead, cause, detail, c.cause, c.detail)
			}
			if n := c.mv.bell.n.Load(); n < 1 {
				t.Fatalf("view %d: its owner was not rung at the end", c.mv.c.Handle())
			}
		}
		if got := forHandle(d.tap.log(), 4); len(got) < 2 || got[len(got)-2].h.Type != wire.TypeRst || got[len(got)-1].h.Type != wire.TypeDetach {
			t.Fatalf("WriteAndClose on view 4 placed %v, want the RST, then DETACH", types(got))
		}

		// A refusal: both sides' views end local_close, without DETACH.
		p.admit = func(s *muxSide, v *Conn, h wire.Header, pl []byte) { s.startAdmitted(v, h, wire.StatusRejected) }
		ref, est := d.open(t, wire.TypeOpen, 5)
		synctest.Wait()
		if est.Payload[0] != byte(wire.StatusRejected) {
			t.Fatalf("view 5 answered %d", est.Payload[0])
		}
		for _, v := range []*Conn{ref.c, p.view(5).c} {
			if dead, cause, _, _ := v.Death(); !dead || cause != CauseLocalClose {
				t.Fatalf("refused view: dead %v cause %v, want local_close", dead, cause)
			}
		}

		// A view with no record of its own reports the trunk's.
		p.admit = nil
		live, _ := d.open(t, wire.TypeOpen, 6)
		synctest.Wait()
		if dead, _, _, _ := live.c.Death(); dead {
			t.Fatal("a live view reports a death")
		}
		d.c.KillTrunk(CauseTransportError, "the path died")
		if dead, cause, _, _ := live.c.Death(); !dead || cause != CauseTransportError {
			t.Fatalf("after the trunk's death: dead %v cause %v, want the trunk's transport_error", dead, cause)
		}
		if _, cause, _, _ := k.c.Death(); cause != CauseWriteStall {
			t.Fatalf("view 2's own record changed to %v", cause)
		}
	})
}

// TestKillTrunkIsTrunkWide (R1-2, M3-D61): KillTrunk on any view kills the
// physical carrier and so every view; Kill on a view of a started MUX
// trunk ends that view only (its DETACH placed; the trunk and the other
// views live).
func TestKillTrunkIsTrunkWide(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d, _ := muxPair(t, nil)
		for h := uint32(2); h <= 4; h++ {
			d.open(t, wire.TypeOpen, byte(h))
		}
		synctest.Wait()
		d.view(3).c.Kill(CauseLocalClose, "the session ended")
		synctest.Wait()
		if dead, cause, detail, _ := d.c.KillTrunkDeath(); dead {
			t.Fatalf("Kill on a view killed the trunk (%v: %s)", cause, detail)
		}
		for _, h := range []uint32{1, 2, 4} {
			if dead, _, _, _ := d.view(h).c.Death(); dead {
				t.Fatalf("Kill on view 3 ended view %d", h)
			}
		}
		if !d.view(3).c.CloseSent() {
			t.Fatal("view 3: no DETACH after Kill")
		}
		d.view(2).c.KillTrunk(CauseProtocolViolation, "a violation")
		for _, h := range []uint32{1, 2, 4} {
			if dead, cause, _, _ := d.view(h).c.Death(); !dead || cause != CauseProtocolViolation {
				t.Fatalf("KillTrunk: view %d dead %v cause %v", h, dead, cause)
			}
		}
		waitDone(t, d.c.trunk.tdone, "trunk")
	})
}

// TestMuxDeathFanOut (M3-D14): a trunk death rings every view's owner once
// and every view's Done closes (once its calls drained).
func TestMuxDeathFanOut(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d, _ := muxPair(t, nil)
		for h := uint32(2); h <= 4; h++ {
			d.open(t, wire.TypeOpen, byte(h))
		}
		synctest.Wait()
		before := map[uint32]int32{}
		for h := uint32(1); h <= 4; h++ {
			before[h] = d.view(h).bell.n.Load()
		}
		d.view(4).c.KillTrunk(CauseTransportError, "the conn failed")
		synctest.Wait()
		for h := uint32(1); h <= 4; h++ {
			mv := d.view(h)
			if n := mv.bell.n.Load() - before[h]; n != 1 {
				t.Fatalf("view %d rung %d times by the trunk's death, want once", h, n)
			}
			if !isDone(mv.c.Done()) || mv.done.n.Load() != 1 {
				t.Fatalf("view %d: Done %v, OnDone %d", h, isDone(mv.c.Done()), mv.done.n.Load())
			}
		}
	})
}

// TestMuxWriteBlockedFanOut_L08 (M3-D14, L08): a blocked batch write is
// reported to every attached view's endpoint once, so each session moves
// its duties off the trunk.
func TestMuxWriteBlockedFanOut_L08(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p := muxRawDialer(t, nil)
		openLive(t, s, p, 2, 3)
		s.tap.hold()
		s.view(2).src.offer(1 << 20)
		s.view(2).c.Wake()
		time.Sleep(time.Second)
		synctest.Wait()
		for h := uint32(1); h <= 3; h++ {
			if n := s.view(h).ep.blocked.Load(); n != 1 {
				t.Fatalf("view %d: WriteBlocked %d times, want once", h, n)
			}
		}
		if !s.c.WriteBlocked() {
			t.Fatal("the trunk does not report WriteBlocked")
		}
		s.tap.release()
	})
}

// TestMuxRefusalRing_L48 (M3-D12, R1-4; L48): the refusal ring holds what a
// compliant dialer can have outstanding: with every answer still unwritten
// a dialer that ignores its count places MuxMaxViews refused handles and
// the trunk lives; the next refused handle kills it ("mux flood"). The view
// cap (views plus queued answers) answers CAPACITY CodeMuxFull.
func TestMuxRefusalRing_L48(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const maxViews = 8
		s, p := muxRawPassive(t, func(env *Env) { env.Timing.MuxMaxViews = maxViews })
		var admitted atomic.Int32
		s.admit = func(s *muxSide, v *Conn, h wire.Header, pl []byte) {
			admitted.Add(1)
			v.Refuse(v.Handle(), Answer{Type: wire.TypeOpenAck, Status: wire.StatusCapacity, Code: wire.CodeBacklog})
		}
		s.tap.hold() // no answer is placed: the writer is held inside a write
		s.v1.src.offer(1000)
		s.c.Wake()
		synctest.Wait()
		for h := uint32(2); h < 2+maxViews; h++ {
			_ = p.send(wire.TypeOpen, 0, h, mOpenPayload(byte(h), false))
		}
		synctest.Wait()
		if dead, cause, detail, _ := s.c.KillTrunkDeath(); dead {
			t.Fatalf("the trunk died after %d refused handles (%v: %s), want alive", maxViews, cause, detail)
		}
		s.c.mx.Lock()
		refN := s.c.refN
		s.c.mx.Unlock()
		if refN != maxViews || admitted.Load() != maxViews-1 {
			t.Fatalf("%d queued answers, %d admissions; want %d and %d (the last one at the cap: CodeMuxFull)", refN, admitted.Load(), maxViews, maxViews-1)
		}
		_ = p.send(wire.TypeOpen, 0, 2+maxViews, mOpenPayload(99, false))
		synctest.Wait()
		dead, cause, detail, _ := s.c.KillTrunkDeath()
		if !dead || cause != CauseProtocolViolation || !strings.Contains(detail, "mux flood") {
			t.Fatalf("after %d refused handles: dead %v cause %v (%s), want protocol_violation mux flood", maxViews+1, dead, cause, detail)
		}
		s.tap.release()
	})
	t.Run("answers drain", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, p := muxRawPassive(t, func(env *Env) { env.Timing.MuxMaxViews = 4 })
			for h := uint32(2); h < 12; h++ { // views fill the cap; later handles get CodeMuxFull
				_ = p.send(wire.TypeOpen, 0, h, mOpenPayload(byte(h), false))
				synctest.Wait()
			}
			full := 0
			for _, f := range p.received() {
				if f.Type == wire.TypeOpenAck {
					a, err := wire.ParseOpenAck(f.Payload)
					if err == nil && a.Status == wire.StatusCapacity && a.Code == wire.CodeMuxFull {
						full++
					}
				}
			}
			if full != 7 { // views 1, 2, 3, 4 fill the cap of 4
				t.Fatalf("%d CodeMuxFull answers, want 7", full)
			}
			if dead, cause, detail, _ := s.c.KillTrunkDeath(); dead {
				t.Fatalf("trunk died: %v %s", cause, detail)
			}
		})
	})
}

// TestMuxViolationNeighboursMigrate_L43 (M3-D15, carrier half; L43): one
// view's endpoint error — an ACK beyond sent, CRC valid — kills the whole
// trunk with protocol_violation: every view on it sees the death and its
// owner is rung (the sessions migrate; WP10's half proves that).
func TestMuxViolationNeighboursMigrate_L43(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d, p := muxPair(t, nil)
		for h := uint32(2); h <= 4; h++ {
			d.open(t, wire.TypeOpen, byte(h))
		}
		synctest.Wait()
		pe := p.view(3).ep
		pe.mu.Lock()
		pe.ctrlErr = errors.New("ACK beyond sent")
		pe.mu.Unlock()
		mv := d.view(3)
		mv.src.addCtl(hFrame{t: wire.TypeAck, payload: ackPayload()})
		mv.c.Wake()
		synctest.Wait()
		dead, cause, _, _ := p.c.KillTrunkDeath()
		if !dead || cause != CauseProtocolViolation {
			t.Fatalf("passive trunk: dead %v cause %v, want protocol_violation", dead, cause)
		}
		for h := uint32(1); h <= 4; h++ {
			pv := p.view(h)
			if dead, cause, _, _ := pv.c.Death(); !dead || cause != CauseProtocolViolation || pv.bell.n.Load() == 0 {
				t.Fatalf("passive view %d: dead %v cause %v, rung %d", h, dead, cause, pv.bell.n.Load())
			}
			if dead, _, _, _ := d.view(h).c.Death(); !dead {
				t.Fatalf("dialer view %d survived its trunk", h)
			}
		}
	})
}

// TestMuxViewHookOffCaller (§A4.2, M3-D20; WP8 ↔ WP9): the pool's view
// hook runs once per view at its Done, and never on the goroutine of a view
// Kill, Retire or WriteAndClose: those may close Done inline and may be
// called under Pool.mu (or Session.mu), which the hook takes. Here the
// caller holds the hook's lock while it kills a view: an inline hook would
// deadlock (synctest reports it).
func TestMuxViewHookOffCaller(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p := muxRawDialer(t, nil)
		lock := make(chan struct{}, 1) // the pool's mutex
		var seen []uint32
		s.c.onViewDone(func(v *Conn) {
			lock <- struct{}{}
			seen = append(seen, v.Handle())
			<-lock
		})
		v2, err := s.c.openView(wire.TypeOpen, mOpenPayload(2, false), 2)
		if err != nil {
			t.Fatal(err)
		}
		lock <- struct{}{}
		v2.Kill(CauseLocalClose, "the attempt ended under the pool's lock")
		if !isDone(v2.Done()) {
			t.Fatal("an opening view's Kill did not close its Done")
		}
		<-lock
		synctest.Wait()
		openLive(t, s, p, 3)
		v3 := s.view(3).c
		lock <- struct{}{}
		v3.Retire(wire.CloseRetire)
		<-lock
		synctest.Wait()
		_ = p.send(wire.TypeDetach, 0, 0, detachPayload(3, wire.DetachRetired))
		synctest.Wait()
		waitDone(t, v3.Done(), "view 3")
		synctest.Wait()
		lock <- struct{}{}
		got := append([]uint32(nil), seen...)
		<-lock
		if len(got) != 2 || got[0] != 2 || got[1] != 3 {
			t.Fatalf("view hook calls %v, want [2 3] (once per view)", got)
		}
	})
}
