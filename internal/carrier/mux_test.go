package carrier

import (
	"bytes"
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// WP8 tests of the mux core: dispatch by handle, the frame legality of
// §A3.3, first frames in allocation order, the response hold and DETACH
// (M3 design §A3.2–§A3.4, §A5.2, §A5.4, §A5.5; M3-D4 … M3-D9).

// releaseHeld sends the dialer's go frame (an ACK) for each handle.
func releaseHeld(p *wirePeer, hs ...uint32) {
	for _, h := range hs {
		_ = p.send(wire.TypeAck, 0, h, ackPayload())
	}
}

// TestMuxDispatchByHandle_L43 (M3-D9): frames for three admitted views and
// view 1 in a mixed order — last-hit cache hits and table misses — reach
// exactly their own view's endpoint in order; route agrees with the table;
// when a view leaves (the peer's DETACH), the cache no longer dispatches
// its handle: the next frame for it is a violation (L43).
func TestMuxDispatchByHandle_L43(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p := muxRawPassive(t, nil)
		for h := uint32(2); h <= 4; h++ {
			_ = p.send(wire.TypeOpen, 0, h, mOpenPayload(byte(h), false))
		}
		synctest.Wait()
		releaseHeld(p, 2, 3, 4)
		synctest.Wait()
		off := map[uint32]uint64{}
		order := []uint32{2, 2, 3, 4, 4, 2, 3, 3, 1, 4, 1, 1, 2}
		for _, h := range order {
			_ = p.send(wire.TypeData, 0, h, dataPayload(off[h], 100))
			off[h] += 100
		}
		synctest.Wait()
		for h := uint32(1); h <= 4; h++ {
			mv := s.view(h)
			if mv == nil {
				t.Fatalf("view %d not admitted", h)
			}
			got := mv.ep.received()
			var want uint64
			for _, d := range got {
				if d.off != want || d.n != 100 {
					t.Fatalf("view %d: DATA at %d (%d bytes), want %d (100)", h, d.off, d.n, want)
				}
				want += 100
			}
			if want != off[h] {
				t.Fatalf("view %d got %d bytes, want %d", h, want, off[h])
			}
			s.c.mx.Lock()
			tbl := s.c.lookupLocked(h)
			s.c.mx.Unlock()
			if r := s.c.route(h); r != tbl || r != mv.c {
				t.Fatalf("route(%d) = %p, table %p, view %p", h, r, tbl, mv.c)
			}
		}
		// The cached view leaves.
		_ = p.send(wire.TypeData, 0, 3, dataPayload(off[3], 10))
		synctest.Wait()
		if s.c.last.Load() != s.view(3).c {
			t.Fatal("view 3 is not the last hit")
		}
		_ = p.send(wire.TypeDetach, 0, 0, detachPayload(3, wire.DetachEnded))
		synctest.Wait()
		n3 := len(s.view(3).ep.received())
		_ = p.send(wire.TypeData, 0, 3, dataPayload(off[3]+10, 10))
		synctest.Wait()
		if dead, cause, _, _ := s.c.Death(); !dead || cause != CauseProtocolViolation {
			t.Fatalf("a frame after the peer's DETACH: trunk dead %v cause %v, want protocol_violation", dead, cause)
		}
		if n := len(s.view(3).ep.received()); n != n3 {
			t.Fatalf("view 3 got a frame after the peer's DETACH (%d → %d)", n3, n)
		}
	})
}

// legalRow is one row of TestMuxLegality_L43_L14: a script against a MUX
// trunk (role dialer or passive) through a raw peer; want "" means the
// trunk must stay alive with nothing dropped, "illegal" a violation on a
// stream trunk and a counted drop on a datagram trunk.
type legalRow struct {
	name   string
	dialer bool
	run    func(t *testing.T, s *muxSide, send func(typ wire.Type, h uint32, p []byte))
	want   string
	check  func(t *testing.T, s *muxSide, log []tapRec)
}

// TestMuxLegality_L43_L14 (§A3.3, M3-D5, M3-D7; L43, L14): every row of
// the frame legality table on a stream trunk (a violation kills the trunk)
// and on a datagram trunk (dropped and counted, the trunk lives), and a
// refusal ends the handle without a DETACH.
func TestMuxLegality_L43_L14(t *testing.T) {
	fin := finInner(0)
	dgMode := false // the session kind follows the trunk's: packet sessions on datagram trunks
	open := func(h uint32) []byte { return mOpenPayload(byte(h), dgMode) }
	rows := []legalRow{
		{name: "passive OPEN above every handle is admitted", run: func(t *testing.T, s *muxSide, send func(wire.Type, uint32, []byte)) {
			send(wire.TypeOpen, 5, open(5))
		}, check: func(t *testing.T, s *muxSide, _ []tapRec) {
			if s.view(5) == nil {
				t.Fatal("OPEN(5) not admitted")
			}
		}},
		{name: "passive stream OPEN on a datagram trunk is refused CodeBadKind", run: func(t *testing.T, s *muxSide, send func(wire.Type, uint32, []byte)) {
			send(wire.TypeOpen, 2, mOpenPayload(2, false))
		}, check: func(t *testing.T, s *muxSide, log []tapRec) {
			badKind := false
			for _, r := range log {
				if e := r.eff(); e.Type == wire.TypeOpenAck && e.Handle == 2 {
					a, err := wire.ParseOpenAck(r.p)
					badKind = err == nil && a.Status == wire.StatusBadRequest && a.Code == wire.CodeBadKind
				}
			}
			if s.c.dg != nil && (!badKind || s.view(2) != nil) {
				t.Fatal("a stream OPEN on a datagram trunk was not refused BAD_REQUEST CodeBadKind")
			}
			if s.c.dg == nil && s.view(2) == nil {
				t.Fatal("a stream OPEN on a stream trunk was not admitted")
			}
		}},
		{name: "passive OPEN at or below the largest handle", want: "illegal", run: func(t *testing.T, s *muxSide, send func(wire.Type, uint32, []byte)) {
			send(wire.TypeOpen, 5, open(5))
			send(wire.TypeOpen, 3, open(3))
		}},
		{name: "passive OPEN for handle 1", want: "illegal", run: func(t *testing.T, s *muxSide, send func(wire.Type, uint32, []byte)) {
			send(wire.TypeOpen, 1, open(1))
		}},
		{name: "passive OPEN_ACK from the dialer", want: "illegal", run: func(t *testing.T, s *muxSide, send func(wire.Type, uint32, []byte)) {
			send(wire.TypeOpen, 2, open(2))
			send(wire.TypeOpenAck, 2, okAck(wire.TypeOpenAck))
		}},
		{name: "passive frame for a handle never opened", want: "illegal", run: func(t *testing.T, s *muxSide, send func(wire.Type, uint32, []byte)) {
			send(wire.TypeFin, 9, fin)
		}},
		{name: "passive frame after the peer's DETACH", want: "illegal", run: func(t *testing.T, s *muxSide, send func(wire.Type, uint32, []byte)) {
			send(wire.TypeOpen, 2, open(2))
			synctest.Wait()
			send(wire.TypeFin, 2, fin) // the go frame
			synctest.Wait()
			send(wire.TypeDetach, 2, nil)
			send(wire.TypeFin, 2, fin)
		}},
		{name: "passive DETACH for an unknown handle", want: "illegal", run: func(t *testing.T, s *muxSide, send func(wire.Type, uint32, []byte)) {
			send(wire.TypeDetach, 7, nil)
		}},
		{name: "passive second DETACH", want: "illegal", run: func(t *testing.T, s *muxSide, send func(wire.Type, uint32, []byte)) {
			send(wire.TypeOpen, 2, open(2))
			synctest.Wait()
			send(wire.TypeFin, 2, fin)
			synctest.Wait()
			send(wire.TypeDetach, 2, nil)
			send(wire.TypeDetach, 2, nil)
		}},
		{name: "passive refused handle: the crossing RST and DETACH are dropped silently", run: func(t *testing.T, s *muxSide, send func(wire.Type, uint32, []byte)) {
			s.admit = func(s *muxSide, v *Conn, h wire.Header, p []byte) {
				v.Refuse(v.Handle(), Answer{Type: wire.TypeOpenAck, Status: wire.StatusCapacity, Code: wire.CodeBacklog})
			}
			send(wire.TypeOpen, 2, open(2))
			var rst [wire.RstFixedLen]byte
			wire.PutRst(rst[:], &wire.Rst{Code: wire.RstWithdrawn})
			send(wire.TypeRst, 2, rst[:])
			send(wire.TypeDetach, 2, nil)
		}},
		{name: "dialer OPEN from the passive", dialer: true, want: "illegal", run: func(t *testing.T, s *muxSide, send func(wire.Type, uint32, []byte)) {
			send(wire.TypeOpen, 2, open(2))
		}},
		{name: "dialer response once", dialer: true, want: "illegal", run: func(t *testing.T, s *muxSide, send func(wire.Type, uint32, []byte)) {
			_, wait := s.openRaw(t, wire.TypeOpen, 2)
			synctest.Wait()
			send(wire.TypeOpenAck, 2, okAck(wire.TypeOpenAck))
			if _, err := wait(); err != nil {
				t.Fatalf("attempt: %v", err)
			}
			send(wire.TypeOpenAck, 2, okAck(wire.TypeOpenAck))
		}},
		{name: "dialer frame before the go frame", dialer: true, want: "illegal", run: func(t *testing.T, s *muxSide, send func(wire.Type, uint32, []byte)) {
			_, wait := s.openRaw(t, wire.TypeOpen, 2)
			synctest.Wait()
			send(wire.TypeOpenAck, 2, okAck(wire.TypeOpenAck))
			if _, err := wait(); err != nil {
				t.Fatalf("attempt: %v", err)
			}
			send(wire.TypeFin, 2, fin) // attached-pending: the passive broke its hold
		}},
		{name: "dialer frame for a handle never allocated", dialer: true, want: "illegal", run: func(t *testing.T, s *muxSide, send func(wire.Type, uint32, []byte)) {
			send(wire.TypeFin, 9, fin)
		}},
		{name: "dialer DETACH for a view awaiting its response", dialer: true, want: "illegal", run: func(t *testing.T, s *muxSide, send func(wire.Type, uint32, []byte)) {
			s.openRaw(t, wire.TypeOpen, 2)
			synctest.Wait()
			send(wire.TypeDetach, 2, nil)
		}},
		{name: "dialer refusal ends the handle without DETACH", dialer: true, want: "illegal", run: func(t *testing.T, s *muxSide, send func(wire.Type, uint32, []byte)) {
			v, wait := s.openRaw(t, wire.TypeOpen, 2)
			synctest.Wait()
			b := make([]byte, wire.OpenAckFixedLen)
			n := wire.PutOpenAck(b, &wire.OpenAck{Status: wire.StatusCapacity, Code: wire.CodeBacklog})
			send(wire.TypeOpenAck, 2, b[:n])
			est, err := wait()
			if err != nil || est.Payload[0] != byte(wire.StatusCapacity) {
				t.Fatalf("refused attempt: %v %v", est, err)
			}
			if dead, cause, _, _ := v.Death(); !dead || cause != CauseLocalClose {
				t.Fatalf("refused view: dead %v cause %v", dead, cause)
			}
			v.Kill(CauseLocalClose, "the session discards the refused view")
			v.Retire(wire.CloseRetire)
			synctest.Wait()
			send(wire.TypeFin, 2, fin) // the handle ended on both sides
		}, check: func(t *testing.T, s *muxSide, log []tapRec) {
			for _, r := range log {
				if e := r.eff(); e.Type == wire.TypeDetach {
					t.Fatalf("a DETACH after a refusal (M3-D7): %+v", r)
				}
			}
		}},
	}
	for _, row := range rows {
		for _, dg := range []bool{false, true} {
			name := row.name + "/stream"
			if dg {
				name = row.name + "/datagram"
			}
			t.Run(name, func(t *testing.T) {
				dgMode = dg
				synctest.Test(t, func(t *testing.T) { runLegalRow(t, row, dg) })
			})
		}
	}
	// A dedicated carrier keeps every M1/M2 rule: DETACH and a second
	// handle are violations.
	for _, tc := range []struct {
		name string
		typ  wire.Type
		h    uint32
		p    []byte
	}{
		{"DETACH on a dedicated carrier", wire.TypeDetach, 0, detachPayload(1, wire.DetachEnded)},
		{"handle 2 on a dedicated carrier", wire.TypeFin, 2, fin},
		{"OPEN on a dedicated carrier", wire.TypeOpen, 1, mOpenPayload(1, false)},
		{"OPEN for a new handle on a dedicated carrier", wire.TypeOpen, 2, mOpenPayload(2, false)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c, p := hPair(t, hEnv(), nil)
				c.Start(&hEP{}, &hBell{}, StartOptions{})
				_ = p.send(tc.typ, 0, tc.h, tc.p)
				synctest.Wait()
				if dead, cause, _, _ := c.Death(); !dead || cause != CauseProtocolViolation {
					t.Fatalf("dead %v cause %v, want protocol_violation", dead, cause)
				}
			})
		})
	}
}

func runLegalRow(t *testing.T, row legalRow, dg bool) {
	var s *muxSide
	var send func(typ wire.Type, h uint32, p []byte)
	var outLog func() []tapRec
	if !dg {
		var p *wirePeer
		if row.dialer {
			s, p = muxRawDialer(t, nil)
		} else {
			s, p = muxRawPassive(t, nil)
		}
		send = func(typ wire.Type, h uint32, pl []byte) {
			if typ == wire.TypeDetach {
				_ = p.send(typ, 0, 0, detachPayload(h, wire.DetachEnded))
				return
			}
			_ = p.send(typ, 0, h, pl)
		}
		outLog = s.tap.log
	} else {
		var p *rawPeer
		s, p = dgMuxRaw(t, 1200, row.dialer, nil)
		var rs relSeq
		var out [][]byte
		send = func(typ wire.Type, h uint32, pl []byte) {
			switch typ {
			case wire.TypeDetach:
				p.send(rs.rel(wire.TypeDetach, 0, 0, detachPayload(h, wire.DetachEnded)))
			case wire.TypeOpen, wire.TypeOpenAck, wire.TypeJoin, wire.TypeJoinAck, wire.TypeFin, wire.TypeRst:
				p.send(rs.rel(typ, 0, h, pl))
			default:
				p.send(rawFrame{t: typ, handle: h, payload: pl})
			}
		}
		outLog = func() []tapRec {
			out = append(out, p.read()...)
			return dgFramesOf(out)
		}
	}
	dropped0 := s.c.Stats().Dropped
	row.run(t, s, send)
	synctest.Wait()
	dead, cause, detail, _ := s.c.KillTrunkDeath()
	switch {
	case row.want == "" && dead:
		t.Fatalf("trunk died (%v: %s); the row is legal", cause, detail)
	case row.want == "" && dg && s.c.Stats().Dropped != dropped0:
		t.Fatalf("Dropped %d → %d; the row is legal", dropped0, s.c.Stats().Dropped)
	case row.want != "" && !dg && (!dead || cause != CauseProtocolViolation):
		t.Fatalf("stream: dead %v cause %v, want protocol_violation", dead, cause)
	case row.want != "" && dg && dead:
		t.Fatalf("datagram: trunk died (%v: %s), want a counted drop", cause, detail)
	case row.want != "" && dg && s.c.Stats().Dropped <= dropped0:
		t.Fatalf("datagram: Dropped %d → %d, want a counted drop", dropped0, s.c.Stats().Dropped)
	}
	if row.check != nil {
		row.check(t, s, outLog())
	}
}

// KillTrunkDeath returns the physical carrier's death record (a view's
// own end record aside).
func (c *Conn) KillTrunkDeath() (bool, Cause, string, time.Time) {
	r := c.death.Load()
	if r == nil {
		return false, CauseNone, "", time.Time{}
	}
	return true, r.cause, r.detail, r.at
}

// TestMuxConcurrentOpenOrder_L14 (§A3.2, E1): first frames are placed in
// allocation order: while the attempt of handle 2 is held before its first
// frame is released (BeforeOpenView), the already released OPENs of
// handles 3 and 4 wait behind it; released, the three leave in order 2, 3,
// 4 — a later handle never overtakes an earlier one (the passive accepts
// only a handle above every handle seen).
func TestMuxConcurrentOpenOrder_L14(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate := make(chan struct{})
		s, p := muxRawDialer(t, func(env *Env) {
			env.Hooks = &testhooks.Hooks{BeforeOpenView: func(_, h uint32) {
				if h == 2 {
					<-gate
				}
			}}
		})
		s.openRaw(t, wire.TypeOpen, 2)
		s.openRaw(t, wire.TypeOpen, 3)
		s.openRaw(t, wire.TypeOpen, 4)
		synctest.Wait()
		if n := p.count(wire.TypeOpen); n != 0 {
			t.Fatalf("%d OPENs placed while handle 2 is held", n)
		}
		close(gate)
		synctest.Wait()
		var hs []uint32
		for _, f := range p.received() {
			if f.Type == wire.TypeOpen {
				hs = append(hs, f.Handle)
			}
		}
		if len(hs) != 3 || hs[0] != 2 || hs[1] != 3 || hs[2] != 4 {
			t.Fatalf("OPEN order %v, want [2 3 4]", hs)
		}
	})
}

// TestMuxResponseHold (M3-D8, PA-27): after the OK response of a view
// admitted on a started trunk the passive places nothing for it — its
// endpoint has data and control frames ready — until the dialer's first
// frame for it (the go frame); then they flow. Handle 1 is not held. Both
// trunk kinds.
func TestMuxResponseHold(t *testing.T) {
	t.Run("stream", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			// A real handshake (Establish, ReadHello, OptMux) through
			// rendrtest.Tamper, whose frame tap (Log) shows what each side
			// placed for each handle.
			envD, envP := phEnvs()
			a, a2 := net.Pipe()
			b2, b := net.Pipe()
			tp := rendrtest.NewTamper(a2, b2)
			defer tp.Close()
			var admitted atomic.Pointer[mView]
			envP.Admit = func(v *Conn, h wire.Header, p []byte) {
				mv := &mView{c: v, ep: &dEP{}, src: newVSource(envP), bell: &hBell{}}
				mv.src.resp, mv.src.respSt = wire.TypeOpenAck, wire.StatusOK
				mv.src.offer(5000)
				mv.src.addCtl(hFrame{t: wire.TypeFin, payload: finInner(5000)})
				mv.ep.fill = mv.src.fill
				admitted.Store(mv)
				v.Start(mv.ep, mv.bell, StartOptions{})
			}
			p1 := newVSource(envP)
			p1.resp, p1.respSt = wire.TypeOpenAck, wire.StatusOK
			p1.offer(1000) // handle 1 is not held: its data follows its response at once
			pass := phPassive(envP, b, nil, func(h *Hello) {
				ep := &dEP{}
				ep.fill = p1.fill
				h.Conn.Start(ep, &hBell{}, StartOptions{Hold: true})
			})
			f := Factory{Name: "pipe", Mux: true, Dial: func(context.Context) (net.Conn, error) { return a, nil }}
			est, err := Establish(context.Background(), envD, f, envD.IDs.Next(), wire.TypeOpen, mOpenPayload(1, false), nil)
			ph := <-pass
			if err != nil || ph.err != nil || !est.Conn.Mux() || !ph.h.Conn.Mux() {
				t.Fatalf("handshake: %v %v (mux %v)", err, ph.err, err == nil && est.Conn.Mux())
			}
			defer func() {
				est.Conn.KillTrunk(CauseLocalClose, "test end")
				ph.h.Conn.KillTrunk(CauseLocalClose, "test end")
				<-est.Conn.trunk.tdone
				<-ph.h.Conn.trunk.tdone
			}()
			d1 := &dEP{}
			est.Conn.Start(d1, &hBell{}, StartOptions{})
			synctest.Wait()
			v, err := est.Conn.openView(wire.TypeOpen, mOpenPayload(2, false), 2)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := v.awaitResponse(context.Background(), nil); err != nil {
				t.Fatal(err)
			}
			time.Sleep(time.Second) // the passive holds; nothing for handle 2 follows its OPEN_ACK
			synctest.Wait()
			var got []rendrtest.FrameRec
			for _, r := range tp.Log(rendrtest.Down) {
				if r.Handle == 2 {
					got = append(got, r)
				}
			}
			if len(got) != 1 || got[0].Type != rendrtest.FrameType(wire.TypeOpenAck) {
				t.Fatalf("before the go frame the passive placed %v for handle 2, want only its OPEN_ACK", got)
			}
			if mv := admitted.Load(); mv == nil || !mv.c.HeldAfterResponse() {
				t.Fatal("HeldAfterResponse false after the OK response")
			}
			var h1 int
			for _, r := range tp.Log(rendrtest.Down) {
				if r.Handle == 1 && r.Type == rendrtest.FrameType(wire.TypeData) {
					h1 += r.Len - wire.DataPrefixLen
				}
			}
			if h1 != 1000 {
				t.Fatalf("handle 1 placed %d DATA bytes, want its 1000 at once (handle 1 is not held)", h1)
			}
			src := newVSource(envD)
			ep := &dEP{}
			ep.fill = src.fill
			v.Start(ep, &hBell{}, StartOptions{}) // the go frame (an ACK) first
			synctest.Wait()
			var data int
			fin, goFirst := false, false
			for _, r := range tp.Log(rendrtest.Up) {
				if r.Handle == 2 && r.Type != rendrtest.FrameType(wire.TypeOpen) {
					goFirst = goFirst || r.Type == rendrtest.FrameType(wire.TypeAck)
					break
				}
			}
			for _, r := range tp.Log(rendrtest.Down) {
				if r.Handle != 2 {
					continue
				}
				if r.Type == rendrtest.FrameType(wire.TypeData) {
					data += r.Len - wire.DataPrefixLen
				}
				fin = fin || r.Type == rendrtest.FrameType(wire.TypeFin)
			}
			if !goFirst || data != 5000 || !fin {
				t.Fatalf("after the go frame (first frame an ACK: %v): %d DATA bytes, FIN %v", goFirst, data, fin)
			}
		})
	})
	t.Run("datagram", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, p := dgMuxRaw(t, 1200, false, nil)
			s.admit = func(s *muxSide, v *Conn, h wire.Header, pl []byte) {
				mv := s.startAdmitted(v, h, wire.StatusOK)
				mv.src.addCtl(hFrame{t: wire.TypeFin, payload: finInner(7)})
			}
			var rs relSeq
			p.send(rs.rel(wire.TypeOpen, 0, 2, mOpenPayload(2, true)))
			synctest.Wait()
			time.Sleep(time.Second)
			synctest.Wait()
			var out [][]byte
			out = append(out, p.read()...)
			got := forEff(dgFramesOf(out), 2)
			if len(got) == 0 || got[0].eff().Type != wire.TypeOpenAck {
				t.Fatalf("no OPEN_ACK for handle 2: %v", got)
			}
			for _, r := range got {
				if r.eff().Type != wire.TypeOpenAck {
					t.Fatalf("the held view placed %v before the go frame", r.eff().Type)
				}
			}
			p.send(rawFrame{t: wire.TypePack, handle: 2, payload: packPayload()}) // the go frame: a plain PACK
			synctest.Wait()
			out = append(out, p.read()...)
			fin := false
			for _, r := range forEff(dgFramesOf(out), 2) {
				fin = fin || r.eff().Type == wire.TypeFin
			}
			if !fin {
				t.Fatal("the FIN never followed the go frame")
			}
		})
	})
}

func packPayload() []byte {
	b := make([]byte, wire.PackLen)
	wire.PutPack(b, &wire.Pack{})
	return b
}

// forEff returns the records whose effective handle is h (DETACH naming h
// included).
func forEff(log []tapRec, h uint32) []tapRec {
	var out []tapRec
	for _, r := range log {
		e := r.eff()
		if e.Handle == h && e.Handle != 0 {
			out = append(out, r)
		} else if e.Type == wire.TypeDetach {
			if d, err := wire.ParseDetach(r.p); err == nil && d.Handle == h {
				out = append(out, r)
			}
		}
	}
	return out
}

func types(rs []tapRec) []wire.Type {
	var out []wire.Type
	for _, r := range rs {
		out = append(out, r.eff().Type)
	}
	return out
}

// received2 returns the peer's frames as tap records.
func (p *wirePeer) received2() []tapRec {
	var out []tapRec
	for _, f := range p.received() {
		out = append(out, tapRec{h: f.Header, p: f.Payload})
	}
	return out
}

// TestMuxFramesAfterOurDetach (M3-D6, E10): after we placed DETACH(h) and
// before the peer's, the peer's frames for h are dispatched to the
// retiring lane (M1's retirement semantics), never a violation; the
// peer's DETACH then completes the exchange.
func TestMuxFramesAfterOurDetach(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p := muxRawDialer(t, nil)
		v, wait := s.openRaw(t, wire.TypeOpen, 2)
		synctest.Wait()
		_ = p.send(wire.TypeOpenAck, 0, 2, okAck(wire.TypeOpenAck))
		if _, err := wait(); err != nil {
			t.Fatal(err)
		}
		mv := s.attach(v)
		synctest.Wait()
		v.Retire(wire.CloseRetire)
		synctest.Wait()
		if !v.CloseSent() {
			t.Fatal("our DETACH not placed")
		}
		_ = p.send(wire.TypeData, 0, 2, dataPayload(0, 300))
		_ = p.send(wire.TypeFin, 0, 2, finInner(300))
		synctest.Wait()
		if dead, cause, detail, _ := s.c.KillTrunkDeath(); dead {
			t.Fatalf("trunk died (%v: %s): frames after our DETACH are legal", cause, detail)
		}
		if got := mv.ep.received(); len(got) != 1 || got[0].n != 300 {
			t.Fatalf("the retiring lane got %v, want the 300 DATA bytes", got)
		}
		_ = p.send(wire.TypeDetach, 0, 0, detachPayload(2, wire.DetachRetired))
		synctest.Wait()
		if dead, cause, _, _ := v.Death(); !dead || cause != CauseRetired {
			t.Fatalf("after both DETACHes: dead %v cause %v, want retired", dead, cause)
		}
		waitDone(t, v.Done(), "view 2")
	})
}

// detachCase runs one DETACH order on a fresh view of a pair: "ours"
// (the dialer retires), "theirs" (the passive retires), "crossing" (both,
// with both writers held until both DETACHes are placed). On a lossy link
// (lossy) a view may also retire at the DETACH bound while its REL{DETACH}
// is still being retransmitted (§A5.5); it reports whether both ends
// retired by the exchange.
func detachCase(t *testing.T, d, p *muxSide, h uint32, order string, lossy bool) bool {
	dv := d.view(h)
	pv := p.view(h)
	switch order {
	case "ours":
		dv.c.Retire(wire.CloseRetire)
	case "theirs":
		pv.c.Retire(wire.CloseRetire)
	case "crossing":
		if d.tap != nil {
			d.tap.hold()
			p.tap.hold()
		}
		dv.c.Retire(wire.CloseRetire)
		pv.c.Retire(wire.CloseRetire)
		synctest.Wait()
		if d.tap != nil {
			d.tap.release()
			p.tap.release()
		}
	}
	synctest.Wait()
	time.Sleep(3 * time.Second) // the DETACH bound (≤ 2 s) would end a lost exchange
	synctest.Wait()
	exchanged := true
	for _, mv := range []*mView{dv, pv} {
		dead, cause, detail, _ := mv.c.Death()
		ex := strings.Contains(detail, "exchange complete")
		exchanged = exchanged && ex
		if !dead || cause != CauseRetired || (!ex && !lossy) {
			t.Fatalf("%s: view %d dead %v cause %v (%s), want retired by the exchange", order, h, dead, cause, detail)
		}
		if !isDone(mv.c.Done()) || mv.done.n.Load() != 1 {
			t.Fatalf("%s: view %d Done %v, OnDone rang %d times, want once", order, h, isDone(mv.c.Done()), mv.done.n.Load())
		}
	}
	return exchanged
}

// TestMuxDetachBothOrders_L12 (§A3.4, E7; L12): ours first, theirs first
// and crossing DETACHes each complete both retirements (view Done once,
// end record retired, both trunks alive); on a datagram trunk at 1 % loss
// the REL{DETACH}s are retransmitted until both exchanges complete.
func TestMuxDetachBothOrders_L12(t *testing.T) {
	t.Run("stream", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			d, p := muxPair(t, nil)
			for i, order := range []string{"ours", "theirs", "crossing"} {
				h := uint32(2 + i)
				d.open(t, wire.TypeOpen, byte(h))
				synctest.Wait()
				detachCase(t, d, p, h, order, false)
			}
			for _, s := range []*muxSide{d, p} {
				if dead, cause, detail, _ := s.c.KillTrunkDeath(); dead {
					t.Fatalf("trunk died: %v %s", cause, detail)
				}
			}
		})
	})
	t.Run("datagram-1pct-loss", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			d, p, ia, ib := dgMuxPair(t, 1200, nil)
			var lost atomic.Int64
			ia.setFilter(lossy(0.01, 7, &lost))
			ib.setFilter(lossy(0.01, 11, &lost))
			orders := []string{"ours", "theirs", "crossing"}
			exchanged := 0
			for i := 0; i < 45; i++ {
				h := uint32(2 + i)
				d.open(t, wire.TypeOpen, byte(h))
				synctest.Wait()
				if detachCase(t, d, p, h, orders[i%3], true) {
					exchanged++
				}
			}
			if exchanged < 40 {
				t.Fatalf("%d of 45 exchanges completed at 1 %% loss", exchanged)
			}
			if lost.Load() == 0 {
				t.Fatal("no datagram was lost: the row tests nothing")
			}
			if d.c.Stats().Retransmits+p.c.Stats().Retransmits == 0 {
				t.Fatal("no REL retransmission at 1 % loss")
			}
			for _, s := range []*muxSide{d, p} {
				if dead, cause, detail, _ := s.c.KillTrunkDeath(); dead {
					t.Fatalf("trunk died: %v %s", cause, detail)
				}
			}
		})
	})
}

// TestMuxDetachBound (§A5.5): a peer that never answers our DETACH: the
// view retires at the DETACH bound (end record retired, Done closed) and
// the trunk lives; the peer's late DETACH is then dropped, not a
// violation.
func TestMuxDetachBound(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p := muxRawDialer(t, nil)
		v, wait := s.openRaw(t, wire.TypeOpen, 2)
		synctest.Wait()
		_ = p.send(wire.TypeOpenAck, 0, 2, okAck(wire.TypeOpenAck))
		if _, err := wait(); err != nil {
			t.Fatal(err)
		}
		s.attach(v)
		synctest.Wait()
		start := time.Now()
		v.Retire(wire.CloseRetire)
		waitDone(t, v.Done(), "view 2")
		if el := time.Since(start); el > drainMax+10*time.Millisecond {
			t.Fatalf("retired after %v, want within the bound (≤ %v)", el, drainMax)
		}
		dead, cause, detail, _ := v.Death()
		if !dead || cause != CauseRetired || !strings.Contains(detail, "bound") {
			t.Fatalf("dead %v cause %v (%s), want retired at the DETACH bound", dead, cause, detail)
		}
		_ = p.send(wire.TypeDetach, 0, 0, detachPayload(2, wire.DetachRetired))
		synctest.Wait()
		if dead, cause, detail, _ := s.c.KillTrunkDeath(); dead {
			t.Fatalf("trunk died (%v: %s)", cause, detail)
		}
	})
}

// TestMuxCloseWithLiveViews (E12, R1-3): the peer's CLOSE with live views:
// every view reports PeerClosed and every view's owner is rung.
func TestMuxCloseWithLiveViews(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d, p := muxPair(t, nil)
		for h := uint32(2); h <= 3; h++ {
			d.open(t, wire.TypeOpen, byte(h))
		}
		synctest.Wait()
		rings := map[uint32]int32{}
		for h := uint32(1); h <= 3; h++ {
			rings[h] = d.view(h).bell.n.Load()
		}
		p.c.trunk.retireTrunk(wire.CloseRetire)
		synctest.Wait()
		for h := uint32(1); h <= 3; h++ {
			mv := d.view(h)
			if !mv.c.PeerClosed() {
				t.Fatalf("view %d: PeerClosed false after the trunk's CLOSE", h)
			}
			if mv.bell.n.Load() <= rings[h] {
				t.Fatalf("view %d: its owner was not rung", h)
			}
		}
	})
}

// TestMuxLateFillBeforeDetach (E14): a Fill running while its view is
// killed completes into the batch before the DETACH; nothing follows the
// DETACH for the handle.
func TestMuxLateFillBeforeDetach(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p := muxRawDialer(t, nil)
		v, wait := s.openRaw(t, wire.TypeOpen, 2)
		synctest.Wait()
		_ = p.send(wire.TypeOpenAck, 0, 2, okAck(wire.TypeOpenAck))
		if _, err := wait(); err != nil {
			t.Fatal(err)
		}
		mv := s.attach(v)
		synctest.Wait()
		in, out := make(chan struct{}), make(chan struct{})
		var once atomic.Bool
		mv.src.hook = func(c *Conn, b *Batch) {
			if once.CompareAndSwap(false, true) {
				close(in)
				<-out
				b.AddFin(c.Handle(), 0) // placed by the late Fill
			}
		}
		v.Wake()
		<-in
		v.Kill(CauseLocalClose, "the session ended")
		close(out)
		synctest.Wait()
		got := forHandle(p.received2(), 2)
		fi, di := -1, -1
		for i, r := range got {
			switch {
			case r.h.Type == wire.TypeFin && fi < 0:
				fi = i
			case r.h.Type == wire.TypeDetach:
				di = i
			}
		}
		if fi < 0 || di < 0 || fi > di || di != len(got)-1 {
			t.Fatalf("frames for handle 2: %v; want the late Fill's FIN before the DETACH and nothing after it", types(got))
		}
	})
}

// TestMuxAdmitLargeOpen (§A5.6, readMux): an OPEN for a new handle whose
// metadata exceeds the reader's stage is read whole, CRC-checked and
// admitted (a trunk's later OPENs may carry up to wire.MaxMetadata bytes).
func TestMuxAdmitLargeOpen(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p := muxRawPassive(t, nil)
		var got []byte
		s.admit = func(s *muxSide, v *Conn, h wire.Header, pl []byte) {
			o, err := wire.ParseOpen(pl, wire.MaxMetadata)
			if err == nil {
				got = append([]byte(nil), o.Metadata...)
			}
			s.startAdmitted(v, h, wire.StatusOK)
		}
		meta := bytes.Repeat([]byte{0x5a}, 40<<10)
		o := wire.Open{SID: [16]byte{9, 15: 9}, Kind: wire.KindStream, Mode: 1, Window: 1 << 20, Metadata: meta}
		b := make([]byte, wire.OpenFixedLen+len(meta))
		n := wire.PutOpen(b, &o)
		_ = p.send(wire.TypeOpen, 0, 2, b[:n])
		synctest.Wait()
		if s.view(2) == nil || !bytes.Equal(got, meta) {
			_, cause, detail, _ := s.c.KillTrunkDeath()
			t.Fatalf("the large OPEN was not admitted intact (view %v, %d metadata bytes; trunk %v %s)", s.view(2) != nil, len(got), cause, detail)
		}
	})
}
