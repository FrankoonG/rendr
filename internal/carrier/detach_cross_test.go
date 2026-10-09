package carrier

import (
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestPassiveResponseCrossesPeerDetach_R1_9 (M3 design §A5.4, M3-D7,
// R1-9; DEFECT A of the regress case gold/G6-mixed-nat): a passive view's
// first response is placed by its session's Fill while the reader
// dispatches the dialer's DETACH for the handle. In G6 the dialer's attempt
// deadline (DialTimeout) and the passive's AcceptTimeout are both 10 s, so
// the dialer abandons the awaiting view (its DETACH) as the passive's
// session places its CAPACITY refusal. The Fill is held inside the call,
// after it placed the response, until the reader dispatched the DETACH
// (AfterDetach), so the dispatch lands inside the call deterministically.
//
// A refusal ends the handle (M3-D7): the wire carries the refusal and no
// DETACH after it, the view is gone with its end record "closed after a
// refusal", its Done closes and the trunk lives. Before the fix the peer's
// DETACH cleared the view's response flag, the writer no longer recognised
// the refusal it placed, and the view's DETACH(ended) followed it: the
// dialer, which ends the handle at the refusal, killed the trunk with
// protocol_violation "DETACH for an unknown handle". An OK response crosses
// as before: the passive places it and then its DETACH (the dialer's
// retiring view ignores the OK, and the DETACH completes the exchange).
func TestPassiveResponseCrossesPeerDetach_R1_9(t *testing.T) {
	rows := []struct {
		name  string
		first wire.Type
		st    wire.AckStatus
		dgram bool
		want  []wire.Type // the frames for the handle on the wire
	}{
		{"stream OPEN, AcceptTimeout's CAPACITY", wire.TypeOpen, wire.StatusCapacity, false, []wire.Type{wire.TypeOpenAck}},
		{"stream OPEN, REJECTED", wire.TypeOpen, wire.StatusRejected, false, []wire.Type{wire.TypeOpenAck}},
		{"stream JOIN, UNKNOWN_SESSION", wire.TypeJoin, wire.StatusUnknownSession, false, []wire.Type{wire.TypeJoinAck}},
		{"datagram OPEN, AcceptTimeout's CAPACITY", wire.TypeOpen, wire.StatusCapacity, true, []wire.Type{wire.TypeOpenAck}},
		{"stream OPEN, OK", wire.TypeOpen, wire.StatusOK, false, []wire.Type{wire.TypeOpenAck, wire.TypeDetach}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { responseCrossesDetach(t, row.first, row.st, row.dgram, row.want) })
		})
	}
}

func responseCrossesDetach(t *testing.T, first wire.Type, st wire.AckStatus, dgram bool, want []wire.Type) {
	const h = 2
	dispatched := make(chan struct{})
	var once sync.Once
	mod := func(env *Env) {
		var hk testhooks.Hooks
		if env.Hooks != nil {
			hk = *env.Hooks
		}
		hk.AfterDetach = func(_, hh uint32, sent bool) {
			if hh == h && !sent {
				once.Do(func() { close(dispatched) })
			}
		}
		env.Hooks = &hk
	}
	var (
		s      *muxSide
		sendF  func(t wire.Type, h uint32, p []byte)
		onWire func() []tapRec
	)
	if dgram {
		var p *rawPeer
		s, p = dgMuxRaw(t, 1200, false, mod)
		var rs relSeq
		var out [][]byte
		sendF = func(typ wire.Type, hh uint32, pl []byte) { p.send(rs.rel(typ, 0, hh, pl)) }
		onWire = func() []tapRec { out = append(out, p.read()...); return dgFramesOf(out) }
	} else {
		var p *wirePeer
		s, p = muxRawPassive(t, mod)
		sendF = func(typ wire.Type, hh uint32, pl []byte) { _ = p.send(typ, 0, hh, pl) }
		onWire = p.received2
	}
	var mv *mView
	s.admit = func(s *muxSide, v *Conn, hdr wire.Header, pl []byte) {
		// The session attaches the view and decides later (no verdict yet).
		mv = &mView{c: v, ep: &dEP{}, src: newVSource(s.env), bell: &hBell{}, done: &hBell{}}
		mv.ep.fill = mv.src.fill
		v.OnDone(mv.done)
		s.add(mv)
		v.Start(mv.ep, mv.bell, StartOptions{})
	}
	pl := mOpenPayload(h, dgram)
	if first == wire.TypeJoin {
		pl = mJoinPayload(h)
	}
	sendF(first, h, pl)
	synctest.Wait()
	if mv == nil {
		_, cause, detail, _ := s.c.KillTrunkDeath()
		t.Fatalf("handle %d not admitted (trunk %v: %s)", h, cause, detail)
	}
	// The session's verdict: its next Fill places the response, then waits
	// inside the call until the reader dispatched the dialer's DETACH.
	held := make(chan struct{})
	mv.src.mu.Lock()
	mv.src.resp, mv.src.respSt = respTypeOf(first), st
	mv.src.hook = func(c *Conn, b *Batch) {
		select {
		case <-held:
			return // once
		default:
		}
		close(held)
		<-dispatched
	}
	mv.src.mu.Unlock()
	mv.c.Wake()
	synctest.Wait()
	select {
	case <-held:
	default:
		t.Fatal("the session's Fill was not called after its verdict")
	}
	sendF(wire.TypeDetach, 0, detachPayload(h, wire.DetachEnded))
	synctest.Wait()
	select {
	case <-dispatched:
	default:
		t.Fatal("the dialer's DETACH was not dispatched")
	}
	time.Sleep(10 * time.Millisecond) // the following rounds (a queued DETACH would be placed by now)
	synctest.Wait()
	var got []wire.Type
	seen := map[wire.Type]bool{}
	for _, r := range forEff(onWire(), h) {
		if typ := r.eff().Type; !seen[typ] { // a datagram trunk retransmits an unacknowledged REL
			seen[typ] = true
			got = append(got, typ)
		}
	}
	if len(got) != len(want) || (len(got) > 0 && got[0] != want[0]) || (len(got) > 1 && got[1] != want[1]) {
		t.Fatalf("the passive placed %v for handle %d, want %v", got, h, want)
	}
	if dead, cause, detail, _ := s.c.KillTrunkDeath(); dead {
		t.Fatalf("the trunk died: %v %s", cause, detail)
	}
	if st == wire.StatusOK {
		return // the view retires with the exchange (our DETACH placed, the peer's in)
	}
	wantState(t, mv.c, viewGone, "refusal crossing the peer's DETACH")
	waitDone(t, mv.c.Done(), "the refused view")
	if dead, cause, detail, _ := mv.c.Death(); !dead || cause != CauseLocalClose || detail != "closed after a refusal" {
		t.Fatalf("the refused view's end record: dead %v, %v %q; want local_close \"closed after a refusal\"", dead, cause, detail)
	}
}
