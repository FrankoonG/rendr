package carrier

import (
	"fmt"
	"math/rand/v2"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestHandleStateMachine (carrier half; M3 design §A5.4, R1-9): a table
// over the carrier's rows of the dialer's and the passive's handle
// lifecycle, then a random walk of 1000 seeds over a stream trunk pair —
// opens, planned retirements, kills and last frames on either side,
// traffic, crossing in every order — that asserts after every step: each
// handle is in one state, gone and dead are terminal, nothing is placed
// for a handle after its sender's DETACH, the dialer's view count reaches
// 0 only with no view left, no endpoint call starts after a view's Done,
// and no compliant interleaving kills a trunk.
func TestHandleStateMachine(t *testing.T) {
	t.Run("dialer rows", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) { dialerRows(t) })
	})
	t.Run("passive rows", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) { passiveRows(t) })
	})
	seeds := 1000
	if carrierRace {
		// R1-23 lever 1 (I3): the walk took 25.6 s of the Linux race lane's
		// carrier package; the race lane walks a quarter of the seeds with
		// the same checks, the non-race lanes all of them.
		seeds = 250
	}
	if testing.Short() {
		seeds = 100
	}
	t.Run("random walk", func(t *testing.T) {
		for seed := 0; seed < seeds; seed++ {
			synctest.Test(t, func(t *testing.T) { randomWalk(t, uint64(seed)) })
			if t.Failed() {
				t.Fatalf("seed %d failed", seed)
			}
		}
	})
}

func wantState(t *testing.T, v *Conn, want viewState, row string) {
	t.Helper()
	if got := viewStateOf(v); got != want {
		t.Fatalf("%s: state %d, want %d", row, got, want)
	}
}

func dialerRows(t *testing.T) {
	s, p := muxRawDialer(t, nil)
	n0 := s.c.viewCount()
	// opening; the attempt ends before placement: gone, a handle gap.
	v2, err := s.c.openView(wire.TypeOpen, mOpenPayload(2, false), 2)
	if err != nil {
		t.Fatal(err)
	}
	wantState(t, v2, viewOpening, "openView")
	if s.c.viewCount() != n0+1 {
		t.Fatal("openView did not count the view")
	}
	v2.Kill(CauseLocalClose, "withdrawn before placement")
	synctest.Wait()
	wantState(t, v2, viewGone, "opening + abandoned")
	if len(forHandle(p.received2(), 2)) != 0 {
		t.Fatal("an abandoned opening view placed a frame")
	}
	if s.c.viewCount() != n0 {
		t.Fatal("the gone view still counts")
	}
	// awaiting → OK → attached-pending → Start → live.
	v3, wait := s.openRaw(t, wire.TypeOpen, 3)
	synctest.Wait()
	wantState(t, v3, viewAwaiting, "first frame placed")
	_ = p.send(wire.TypeOpenAck, 0, 3, okAck(wire.TypeOpenAck))
	if _, err := wait(); err != nil {
		t.Fatal(err)
	}
	wantState(t, v3, viewAttachedPending, "OK response")
	mv3 := s.attach(v3)
	synctest.Wait()
	wantState(t, v3, viewLive, "Start")
	// awaiting → refusal → gone, no DETACH.
	v4, wait4 := s.openRaw(t, wire.TypeOpen, 4)
	synctest.Wait()
	b := make([]byte, wire.OpenAckFixedLen)
	n := wire.PutOpenAck(b, &wire.OpenAck{Status: wire.StatusRejected, Code: 1})
	_ = p.send(wire.TypeOpenAck, 0, 4, b[:n])
	if _, err := wait4(); err != nil {
		t.Fatal(err)
	}
	wantState(t, v4, viewGone, "refusal")
	// awaiting → abandoned → retiring (DETACH placed).
	v5, _ := s.openRaw(t, wire.TypeOpen, 5)
	synctest.Wait()
	v5.Kill(CauseLocalClose, "abandoned")
	synctest.Wait()
	wantState(t, v5, viewRetiring, "awaiting + abandoned")
	if got := forHandle(p.received2(), 5); len(got) != 2 || got[1].h.Type != wire.TypeDetach {
		t.Fatalf("abandoned awaiting view placed %v, want OPEN, DETACH", types(got))
	}
	// retiring (abandoned awaiting) + the OK response that crossed our
	// DETACH → still retiring, the trunk lives; + the peer's DETACH → gone
	// (E6, R1-5).
	_ = p.send(wire.TypeOpenAck, 0, 5, okAck(wire.TypeOpenAck))
	synctest.Wait()
	if dead, cause, detail, _ := s.c.KillTrunkDeath(); dead {
		t.Fatalf("an OK response crossing our DETACH killed the trunk (%v: %s)", cause, detail)
	}
	wantState(t, v5, viewRetiring, "abandoned + crossing OK response")
	_ = p.send(wire.TypeDetach, 0, 0, detachPayload(5, wire.DetachEnded))
	synctest.Wait()
	wantState(t, v5, viewGone, "abandoned + crossing OK response + peer DETACH")
	// attached-pending + the peer's DETACH → retiring, our DETACH, PeerClosed.
	v6, wait6 := s.openRaw(t, wire.TypeOpen, 6)
	synctest.Wait()
	_ = p.send(wire.TypeOpenAck, 0, 6, okAck(wire.TypeOpenAck))
	if _, err := wait6(); err != nil {
		t.Fatal(err)
	}
	_ = p.send(wire.TypeDetach, 0, 0, detachPayload(6, wire.DetachEnded))
	synctest.Wait()
	if !v6.PeerClosed() {
		t.Fatal("attached-pending + peer DETACH: PeerClosed false")
	}
	wantState(t, v6, viewGone, "attached-pending + peer DETACH (both DETACHes)")
	// live + the peer's DETACH → retiring → our DETACH → gone.
	_ = p.send(wire.TypeDetach, 0, 0, detachPayload(3, wire.DetachEnded))
	synctest.Wait()
	wantState(t, v3, viewGone, "live + peer DETACH")
	if !isDone(v3.Done()) || mv3.done.n.Load() != 1 {
		t.Fatal("live + peer DETACH: Done not closed once")
	}
	// live + trunk death → dead (the trunk's record).
	v7, wait7 := s.openRaw(t, wire.TypeOpen, 7)
	synctest.Wait()
	_ = p.send(wire.TypeOpenAck, 0, 7, okAck(wire.TypeOpenAck))
	if _, err := wait7(); err != nil {
		t.Fatal(err)
	}
	s.attach(v7)
	synctest.Wait()
	// awaiting → abandoned while the writer is blocked (our DETACH still
	// queued) + a refusal that crossed it → gone; the queued DETACH is
	// never placed (the refusal ended the handle, M3-D7).
	v8, wait8 := s.openRaw(t, wire.TypeOpen, 8)
	synctest.Wait()
	wantState(t, v8, viewAwaiting, "OPEN 8 placed")
	s.tap.hold()
	s.v1.src.offer(4 << 10)
	s.c.Wake()
	synctest.Wait() // the writer is blocked in its Write
	v8.Kill(CauseLocalClose, "withdrawn")
	if _, err := wait8(); err == nil {
		t.Fatal("a withdrawn attempt returned no error")
	}
	b8 := make([]byte, wire.OpenAckFixedLen)
	n8 := wire.PutOpenAck(b8, &wire.OpenAck{Status: wire.StatusCapacity, Code: wire.CodeBacklog})
	_ = p.send(wire.TypeOpenAck, 0, 8, b8[:n8])
	synctest.Wait()
	wantState(t, v8, viewGone, "abandoned (DETACH queued) + crossing refusal")
	s.tap.release()
	synctest.Wait()
	if got := forHandle(p.received2(), 8); len(got) != 1 || got[0].h.Type != wire.TypeOpen {
		t.Fatalf("abandoned view refused before its DETACH left placed %v, want OPEN only", types(got))
	}
	if dead, cause, detail, _ := s.c.KillTrunkDeath(); dead {
		t.Fatalf("trunk died: %v %s", cause, detail)
	}
	s.c.KillTrunk(CauseTransportError, "the path died")
	synctest.Wait()
	if dead, cause, _, _ := v7.Death(); !dead || cause != CauseTransportError {
		t.Fatalf("trunk death: view 7 dead %v cause %v", dead, cause)
	}
	waitDone(t, v7.Done(), "view 7")
	wantState(t, v7, viewDead, "live + trunk death")
	wantState(t, v3, viewGone, "gone stays gone at the trunk's death")
}

func passiveRows(t *testing.T) {
	s, p := muxRawPassive(t, nil)
	s.admit = func(s *muxSide, v *Conn, h wire.Header, pl []byte) {
		switch v.Handle() {
		case 4:
			v.Refuse(v.Handle(), Answer{Type: wire.TypeOpenAck, Status: wire.StatusCapacity, Code: wire.CodeBacklog})
		case 5:
			s.startAdmitted(v, h, wire.StatusRejected)
		case 2, 6, 8:
			mv := &mView{c: v, ep: &dEP{}, src: newVSource(s.env), bell: &hBell{}, done: &hBell{}}
			mv.ep.fill = mv.src.fill // no verdict yet
			s.add(mv)
			v.Start(mv.ep, mv.bell, StartOptions{})
		default:
			s.startAdmitted(v, h, wire.StatusOK)
		}
	}
	_ = p.send(wire.TypeOpen, 0, 2, mOpenPayload(2, false))
	_ = p.send(wire.TypeJoin, 0, 3, mJoinPayload(3))
	synctest.Wait()
	wantState(t, s.view(2).c, viewPending, "OPEN admitted")
	wantState(t, s.view(3).c, viewHeld, "JOIN admitted and answered OK")
	// pending + the session's OK → held; + the go frame → live.
	src := s.view(2).src
	src.mu.Lock()
	src.resp, src.respSt = wire.TypeOpenAck, wire.StatusOK
	src.mu.Unlock()
	s.view(2).c.Wake()
	synctest.Wait()
	wantState(t, s.view(2).c, viewHeld, "Confirm")
	releaseHeld(p, 2)
	synctest.Wait()
	wantState(t, s.view(2).c, viewLive, "go frame")
	// refused at admission: no view, an answer.
	_ = p.send(wire.TypeOpen, 0, 4, mOpenPayload(4, false))
	synctest.Wait()
	if s.c.route(4) != nil {
		t.Fatal("a refused handle became a view")
	}
	if got := forHandle(p.received2(), 4); len(got) != 1 || got[0].h.Type != wire.TypeOpenAck {
		t.Fatalf("refused handle: %v, want its OPEN_ACK", types(got))
	}
	// a refusal response: gone, no DETACH.
	_ = p.send(wire.TypeOpen, 0, 5, mOpenPayload(5, false))
	synctest.Wait()
	if s.view(5) == nil {
		_, cause, detail, _ := s.c.KillTrunkDeath()
		t.Fatalf("OPEN(5) not admitted (trunk %v: %s)", cause, detail)
	}
	wantState(t, s.view(5).c, viewGone, "refusal response")
	if got := forHandle(p.received2(), 5); len(got) != 1 {
		t.Fatalf("refused view placed %v, want its OPEN_ACK only", types(got))
	}
	// held + its session ends → DETACH only.
	s.view(3).c.Kill(CauseLocalClose, "IdleTimeout")
	synctest.Wait()
	if got := forHandle(p.received2(), 3); len(got) != 2 || got[0].h.Type != wire.TypeJoinAck || got[1].h.Type != wire.TypeDetach {
		t.Fatalf("held view ending placed %v, want JOIN_ACK, DETACH", types(got))
	}
	// pending + the dialer's DETACH → the view ends, we answer DETACH.
	_ = p.send(wire.TypeOpen, 0, 6, mOpenPayload(6, false))
	synctest.Wait()
	_ = p.send(wire.TypeDetach, 0, 0, detachPayload(6, wire.DetachEnded))
	synctest.Wait()
	wantState(t, s.view(6).c, viewGone, "pending + peer DETACH")
	if got := forHandle(p.received2(), 6); len(got) != 1 || got[0].h.Type != wire.TypeDetach {
		t.Fatalf("pending view after the dialer's DETACH placed %v, want DETACH only", types(got))
	}
	// held + WriteAndClose (its session's verdict) → its frame dropped,
	// DETACH(ended) only: a held view places nothing before the go frame
	// but its DETACH (M3-D8, R1-9).
	_ = p.send(wire.TypeOpen, 0, 7, mOpenPayload(7, false))
	synctest.Wait()
	wantState(t, s.view(7).c, viewHeld, "OPEN 7 answered OK")
	s.view(7).c.WriteAndClose(wire.TypeRst, 0, 7, rstPayload(wire.RstWithdrawn), time.Time{})
	synctest.Wait()
	if got := forHandle(p.received2(), 7); len(got) != 2 || got[0].h.Type != wire.TypeOpenAck || got[1].h.Type != wire.TypeDetach {
		t.Fatalf("held view's WriteAndClose placed %v, want OPEN_ACK, DETACH", types(got))
	}
	if dead, cause, _, _ := s.view(7).c.Death(); !dead || cause != CauseLocalClose {
		t.Fatalf("held view after WriteAndClose: dead %v cause %v, want local_close", dead, cause)
	}
	if dead, cause, detail, _ := s.c.KillTrunkDeath(); dead {
		t.Fatalf("trunk died: %v %s", cause, detail)
	}
	// pending (no verdict yet) + Kill → the safety-net refusal: CAPACITY
	// with a code that does not mark the dialer's trunk full (not
	// CodeMuxFull), and no DETACH (M3-D7).
	_ = p.send(wire.TypeOpen, 0, 8, mOpenPayload(8, false))
	synctest.Wait()
	wantState(t, s.view(8).c, viewPending, "OPEN 8 admitted")
	s.view(8).c.Kill(CauseLocalClose, "the session ended before its verdict")
	synctest.Wait()
	got8 := forHandle(p.received2(), 8)
	if len(got8) != 1 || got8[0].h.Type != wire.TypeOpenAck {
		t.Fatalf("killed pending view placed %v, want its OPEN_ACK only", types(got8))
	}
	if a, err := wire.ParseOpenAck(got8[0].p); err != nil || a.Status != wire.StatusCapacity || a.Code == wire.CodeMuxFull {
		t.Fatalf("killed pending view answered %+v (%v), want CAPACITY without CodeMuxFull", a, err)
	}
	// live + trunk death → dead.
	s.c.KillTrunk(CauseTransportError, "the path died")
	waitDone(t, s.view(2).c.Done(), "view 2")
	wantState(t, s.view(2).c, viewDead, "live + trunk death")
}

// checkEP is a dEP that records an endpoint call that starts after its
// view's Done closed.
type checkEP struct {
	dEP
	late *atomic.Int32
}

func (e *checkEP) check(c *Conn) {
	if isDone(c.Done()) {
		e.late.Add(1)
	}
}
func (e *checkEP) Fill(c *Conn, b *Batch) { e.check(c); e.dEP.Fill(c, b) }
func (e *checkEP) Data(c *Conn, off uint64, p []byte, buf *Buf) error {
	e.check(c)
	return e.dEP.Data(c, off, p, buf)
}
func (e *checkEP) Control(c *Conn, h wire.Header, p []byte) error {
	e.check(c)
	return e.dEP.Control(c, h, p)
}
func (e *checkEP) WriteBlocked(c *Conn) { e.check(c); e.dEP.WriteBlocked(c) }

// noFrameAfterDetach checks one direction's frame log: nothing for a handle
// follows its DETACH.
func noFrameAfterDetach(log []tapRec) error {
	detached := map[uint32]bool{}
	for i, r := range log {
		if r.h.Type == wire.TypeDetach {
			d, err := wire.ParseDetach(r.p)
			if err != nil {
				return err
			}
			if detached[d.Handle] {
				return fmt.Errorf("frame %d: a second DETACH(%d)", i, d.Handle)
			}
			detached[d.Handle] = true
			continue
		}
		if h := r.h.Handle; h != 0 && detached[h] {
			return fmt.Errorf("frame %d: %v for handle %d after its DETACH", i, r.h.Type, h)
		}
	}
	return nil
}

func randomWalk(t *testing.T, seed uint64) {
	rng := rand.New(rand.NewPCG(seed, seed*7919+1))
	var late atomic.Int32
	d, p := muxPair(t, nil)
	p.admit = func(s *muxSide, v *Conn, h wire.Header, pl []byte) {
		mv := &mView{c: v, ep: &dEP{}, src: newVSource(s.env), bell: &hBell{}, done: &hBell{}}
		ce := &checkEP{late: &late}
		st := wire.StatusOK
		if rng.IntN(8) == 0 {
			st = wire.StatusRejected
		}
		mv.src.resp, mv.src.respSt = respTypeOf(h.Type), st
		ce.fill = mv.src.fill
		v.OnDone(mv.done)
		s.add(mv)
		v.Start(ce, mv.bell, StartOptions{})
	}
	terminal := map[*Conn]bool{}
	var all []*Conn
	next := byte(2)
	pick := func(s *muxSide) *mView {
		s.mu.Lock()
		defer s.mu.Unlock()
		var vs []*mView
		for h, mv := range s.views {
			if h != wire.SessionHandle {
				vs = append(vs, mv)
			}
		}
		if len(vs) == 0 {
			return nil
		}
		return vs[rng.IntN(len(vs))]
	}
	for step := 0; step < 14; step++ {
		switch op := rng.IntN(9); {
		case op <= 2 && next < 12:
			kind := wire.TypeOpen
			if rng.IntN(3) == 0 {
				kind = wire.TypeJoin
			}
			pl := mOpenPayload(next, false)
			if kind == wire.TypeJoin {
				pl = mJoinPayload(next)
			}
			v, err := d.c.openView(kind, pl, uintptr(next))
			if err != nil {
				t.Fatal(err)
			}
			all = append(all, v)
			next++
			mv := &mView{c: v, ep: &dEP{}, src: newVSource(d.env), bell: &hBell{}, done: &hBell{}}
			ce := &checkEP{late: &late}
			ce.fill = mv.src.fill
			go func() {
				est, err := v.awaitResponse(t.Context(), nil)
				if err == nil && est.Payload[0] == byte(wire.StatusOK) {
					v.OnDone(mv.done)
					d.add(mv)
					v.Start(ce, mv.bell, StartOptions{})
				}
			}()
		case op == 3:
			if mv := pick(d); mv != nil {
				mv.c.Retire(wire.CloseRetire)
			}
		case op == 4:
			if mv := pick(p); mv != nil {
				mv.c.Retire(wire.CloseRetire)
			}
		case op == 5:
			if mv := pick(d); mv != nil {
				mv.c.Kill(CauseLocalClose, "random")
			}
		case op == 6:
			if mv := pick(p); mv != nil {
				mv.c.WriteAndClose(wire.TypeRst, 0, 0, rstPayload(wire.RstWithdrawn), time.Time{})
			}
		case op == 7:
			for _, s := range []*muxSide{d, p} {
				if mv := pick(s); mv != nil {
					mv.src.offer(uint64(1 + rng.IntN(200000)))
					mv.c.Wake()
				}
			}
		default:
			time.Sleep(time.Duration(rng.IntN(1500)) * time.Millisecond)
		}
		synctest.Wait()
		for _, s := range []*muxSide{d, p} {
			s.c.mx.Lock()
			for h, v := range s.c.views {
				if v.handle != h {
					t.Fatalf("table entry %d holds view %d", h, v.handle)
				}
			}
			s.c.mx.Unlock()
			s.mu.Lock()
			for _, mv := range s.views {
				all = append(all, mv.c)
			}
			s.mu.Unlock()
		}
		for _, v := range all {
			st := viewStateOf(v)
			if st == viewGone || st == viewDead {
				terminal[v] = true
			} else if terminal[v] {
				t.Fatalf("seed %d step %d: view %d left a terminal state (now %d)", seed, step, v.handle, st)
			}
		}
		for _, s := range []*muxSide{d, p} {
			if err := noFrameAfterDetach(s.tap.log()); err != nil {
				t.Fatalf("seed %d step %d, %s: %v", seed, step, map[bool]string{true: "dialer", false: "passive"}[s == d], err)
			}
			if dead, cause, detail, _ := s.c.KillTrunkDeath(); dead {
				t.Fatalf("seed %d step %d: a trunk died (%v: %s)", seed, step, cause, detail)
			}
		}
		open := 0
		for _, v := range dedup(all) {
			if v.trunk == d.c.trunk && !isDone(v.Done()) {
				open++
			}
		}
		if n := d.c.viewCount(); n != open {
			t.Fatalf("seed %d step %d: dialer view count %d, views with Done open %d", seed, step, n, open)
		}
		if late.Load() != 0 {
			t.Fatalf("seed %d step %d: an endpoint call started after its view's Done", seed, step)
		}
	}
}

func dedup(vs []*Conn) []*Conn {
	seen := map[*Conn]bool{}
	var out []*Conn
	for _, v := range vs {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
