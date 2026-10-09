package carrier

import (
	"fmt"
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
// refusal", its Done closes, the handle takes no tolerance entry (the
// dialer's DETACH was its last frame) and the trunk lives. Before the fix the peer's
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
	// The dialer's DETACH was the handle's last frame: nothing crosses the
	// refusal, so the handle takes no slot of the tolerance ring (an entry
	// would only push out one a retired view still needs).
	tr := mv.c.trunk
	tr.mx.Lock()
	tol := tr.toleratedLocked(h, wire.TypeDetach, false)
	tr.mx.Unlock()
	if tol {
		t.Fatalf("handle %d took a tolerance entry after the dialer's DETACH was in", h)
	}
}

// TestPassiveResponseCrossesKill_R1_9 (M3 design §A5.4, M3-D7, R1-9; the
// second crossing of DEFECT A): a passive view's session places its first
// response in a Fill while the session kills the view (Kill: its end phase
// kills a lane whose CLOSE is not written by the close bound, and G6's
// backlogged writers place a pending session's refusal late). Kill sees a
// view that has not answered and queues a refusal for it (abandonLocked:
// the dialer awaiting a response must get one), but the Fill had already
// placed the response: the dialer must see exactly one response for the
// handle. Before the fix the queued refusal was placed too — after a
// refusal the dialer (which ends the handle at the first one, M3-D7)
// killed the trunk for a response of an ended view; after an OK it got a
// second response and a DETACH. The Kill is made inside the Fill, after
// the response was placed, so the crossing is deterministic.
//
// A refusal ends the handle (one response, no DETACH, the view gone, its
// end record the Kill's, its handle tolerated for the dialer's crossing
// RST or DETACH); an OK is followed by our DETACH(ended) only (a killed
// held view places nothing else, R1-9). The trunk lives.
func TestPassiveResponseCrossesKill_R1_9(t *testing.T) {
	rows := []struct {
		name  string
		first wire.Type
		st    wire.AckStatus
		dgram bool
		want  []wire.Type
	}{
		{"stream OPEN, AcceptTimeout's CAPACITY", wire.TypeOpen, wire.StatusCapacity, false, []wire.Type{wire.TypeOpenAck}},
		{"stream JOIN, UNKNOWN_SESSION", wire.TypeJoin, wire.StatusUnknownSession, false, []wire.Type{wire.TypeJoinAck}},
		{"datagram OPEN, REJECTED", wire.TypeOpen, wire.StatusRejected, true, []wire.Type{wire.TypeOpenAck}},
		{"stream OPEN, OK", wire.TypeOpen, wire.StatusOK, false, []wire.Type{wire.TypeOpenAck, wire.TypeDetach}},
		{"datagram OPEN, OK", wire.TypeOpen, wire.StatusOK, true, []wire.Type{wire.TypeOpenAck, wire.TypeDetach}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { responseCrossesKill(t, row.first, row.st, row.dgram, row.want) })
		})
	}
}

func responseCrossesKill(t *testing.T, first wire.Type, st wire.AckStatus, dgram bool, want []wire.Type) {
	const h = 2
	var (
		s      *muxSide
		sendF  func(t wire.Type, h uint32, p []byte)
		onWire func() []wire.Type // the frames for h, each REL once
	)
	if dgram {
		var p *rawPeer
		s, p = dgMuxRaw(t, 1200, false, nil)
		var rs relSeq
		sendF = func(typ wire.Type, hh uint32, pl []byte) { p.send(rs.rel(typ, 0, hh, pl)) }
		onWire = func() []wire.Type { return dgRelTypesFor(p.read(), h) }
	} else {
		var p *wirePeer
		s, p = muxRawPassive(t, nil)
		sendF = func(typ wire.Type, hh uint32, pl []byte) { _ = p.send(typ, 0, hh, pl) }
		onWire = func() []wire.Type {
			var out []wire.Type
			for _, r := range forEff(p.received2(), h) {
				out = append(out, r.eff().Type)
			}
			return out
		}
	}
	var mv *mView
	s.admit = func(s *muxSide, v *Conn, hdr wire.Header, pl []byte) {
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
	// The session's verdict: its next Fill places the response, then the
	// session kills the view inside the call.
	killed := false
	mv.src.mu.Lock()
	mv.src.resp, mv.src.respSt = respTypeOf(first), st
	mv.src.noGo = true
	mv.src.hook = func(c *Conn, b *Batch) {
		if killed {
			return
		}
		killed = true
		c.Kill(CauseLocalClose, "killed while its response was placed")
	}
	mv.src.mu.Unlock()
	mv.c.Wake()
	synctest.Wait()
	if !killed {
		t.Fatal("the session's Fill was not called after its verdict")
	}
	time.Sleep(10 * time.Millisecond) // the following rounds (a queued refusal or DETACH would be placed by now)
	synctest.Wait()
	got := onWire()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("the passive placed %v for handle %d, want %v", got, h, want)
	}
	if dead, cause, detail, _ := s.c.KillTrunkDeath(); dead {
		t.Fatalf("the trunk died: %v %s", cause, detail)
	}
	if dead, cause, detail, _ := mv.c.Death(); !dead || cause != CauseLocalClose || detail != "killed while its response was placed" {
		t.Fatalf("the view's end record: dead %v, %v %q; want the Kill's", dead, cause, detail)
	}
	waitDone(t, mv.c.Done(), "the killed view")
	if st == wire.StatusOK {
		return // retiring: our DETACH placed, the peer's awaited (or the bound)
	}
	wantState(t, mv.c, viewGone, "refusal crossing a Kill")
	tr := mv.c.trunk
	tr.mx.Lock()
	tol := tr.toleratedLocked(h, wire.TypeDetach, false)
	tr.mx.Unlock()
	if !tol {
		t.Fatalf("handle %d not tolerated after its refusal: the dialer's crossing DETACH would kill the trunk", h)
	}
}

// dgRelTypesFor returns the inner types of the RELs for handle h in the
// datagrams ds, each REL once (a datagram trunk retransmits a REL until
// its RACK, which the raw peer never sends).
func dgRelTypesFor(ds [][]byte, h uint32) []wire.Type {
	var out []wire.Type
	seen := map[uint32]bool{}
	for _, d := range ds {
		fs, _ := dgDecode(d)
		for _, f := range fs {
			if f.Type != wire.TypeRel {
				continue
			}
			rh, inner, err := wire.ParseRel(f.Payload)
			if err != nil || seen[rh.Cseq] {
				continue
			}
			if hh := rh.Handle; rh.Type == wire.TypeDetach {
				if d, err := wire.ParseDetach(inner); err != nil || d.Handle != h {
					continue
				}
			} else if hh != h {
				continue
			}
			seen[rh.Cseq] = true
			out = append(out, rh.Type)
		}
	}
	return out
}
