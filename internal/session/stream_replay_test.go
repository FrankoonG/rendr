package session

import (
	"bytes"
	"io"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestAckedDataNeverResent_L10: once the peer acknowledged everything, a
// carrier death requeues nothing and the survivor writes zero DATA frames;
// only the unacknowledged part of a later write is replayed, from the ACK
// front, on the survivor.
func TestAckedDataNeverResent_L10(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := stNewPair(stOpt{}, stOpt{}, 2)
		msg := stPattern(0, 1<<20)
		if n, err := p.a.Write(msg); n != len(msg) || err != nil {
			t.Fatal(err)
		}
		done := stReadAsync(p.b, len(msg))
		for len(done) == 0 {
			p.pump(true)
			synctest.Wait()
		}
		if r := <-done; r.err != nil || !bytes.Equal(r.b, msg) {
			t.Fatalf("transfer: %v", r.err)
		}
		p.pump(true) // the final ACKs
		if b := stLocked(p.a, func(st *stream) uint64 { return st.sBase }); b != uint64(len(msg)) {
			t.Fatalf("front %d, want everything acknowledged (%d)", b, len(msg))
		}
		sent1 := 0
		for _, f := range p.traceAB {
			sent1 += f.n
		}
		if sent1 < len(msg) {
			t.Fatalf("link 1 carried %d DATA bytes, want the whole transfer (stimulus)", sent1)
		}

		// Kill the carrier that carried it; route the survivor.
		if q := stKillLane(p.a, p.al[0]); q != 0 {
			t.Fatalf("death requeued %d acknowledged bytes", q)
		}
		stKillLane(p.b, p.bl[0])
		p.cut[0] = true
		stRoute(p.a, p.al[1], true)
		stRoute(p.b, p.bl[1], true)
		p.traceAB = nil
		p.pump(true)
		if n := stCount(p.traceAB, wire.TypeData); n != 0 {
			t.Fatalf("the survivor wrote %d DATA frames of acknowledged bytes, want 0", n)
		}
		if r := stLocked(p.a, func(st *stream) uint64 { return st.retxBytes }); r != 0 {
			t.Fatalf("RetransmittedBytes = %d, want 0", r)
		}

		// Control: unacknowledged bytes in flight on the dying carrier are
		// replayed from the ACK front, and only they.
		more := stPattern(1<<20, 100<<10)
		if n, err := p.a.Write(more); n != len(more) || err != nil {
			t.Fatal(err)
		}
		fs, b := stFill(p.al[1], time.Now()) // written, then lost with the carrier
		b.ReleaseRefs()
		if stCount(fs, wire.TypeData) == 0 {
			t.Fatal("no DATA in flight on the second carrier")
		}
		l3, _ := stAddLane(p.a, 3, false)
		lb3, _ := stAddLane(p.b, 3, false)
		p.al, p.bl, p.cut, p.stall = append(p.al, l3), append(p.bl, lb3), append(p.cut, false), append(p.stall, false)
		p.ap, p.bp = append(p.ap, nil), append(p.bp, nil)
		if q := stKillLane(p.a, p.al[1]); q != uint64(len(more)) {
			t.Fatalf("death requeued %d bytes, want the %d unacknowledged ones", q, len(more))
		}
		stKillLane(p.b, p.bl[1])
		p.cut[1] = true
		stRoute(p.a, l3, true)
		stRoute(p.b, lb3, true)
		p.traceAB = nil
		p.pump(true)
		for _, f := range p.traceAB {
			if f.typ == wire.TypeData && (!f.retx || f.off < 1<<20) {
				t.Fatalf("replay frame %v: not a retransmission or below the ACK front", f)
			}
		}
		if got := stReadN(t, p.b, len(more)); !bytes.Equal(got, more) {
			t.Fatal("replayed bytes corrupted")
		}
		if r := stLocked(p.a, func(st *stream) uint64 { return st.retxBytes }); r != uint64(len(more)) {
			t.Fatalf("RetransmittedBytes = %d, want %d", r, len(more))
		}
		p.close(t)
	})
}

// TestReplayOrderBeforeNewDataAndFIN_L10: x is lost with its carrier and
// requeued; y is written and CloseWrite called while the replay is still
// pending (also with CloseWrite inside y's copy). On the successor the
// wire order is x (retransmitted), then y, then FIN: the replay completes
// before new data and the FIN. When x and the FIN both went out on the
// dying carrier (no y), the requeued FIN — due again at once, sNext is
// past it — still waits for the whole replay, which spans several batches.
func TestReplayOrderBeforeNewDataAndFIN_L10(t *testing.T) {
	for _, tc := range []struct {
		name        string
		closeInCopy bool // CloseWrite during y's copy
		finLost     bool // x and the FIN went out on the dying carrier; no y
	}{
		{"CloseWrite after y", false, false},
		{"CloseWrite during y's copy", true, false},
		{"FIN lost with the carrier", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				testReplayOrder(t, tc.closeInCopy, tc.finLost)
			})
		})
	}
}

func testReplayOrder(t *testing.T, closeInCopy, finLost bool) {
	p := stNewPair(stOpt{}, stOpt{}, 2)
	x := stPattern(0, 300<<10)
	if finLost {
		x = stPattern(0, 400<<10) // more than one 256 KiB batch to replay
	}
	if n, err := p.a.Write(x); n != len(x) || err != nil {
		t.Fatal(err)
	}
	if finLost {
		_ = p.a.CloseWrite()
	}
	fins := 0
	for { // x (and the FIN) go out on link 1 and are lost with the carrier
		fs, b := stFill(p.al[0], time.Now())
		b.ReleaseRefs()
		if len(fs) == 0 {
			break
		}
		fins += stCount(fs, wire.TypeFin)
	}
	if finLost != (fins == 1) {
		t.Fatalf("%d FINs went out on the dying carrier (stimulus)", fins)
	}
	if q := stKillLane(p.a, p.al[0]); q != uint64(len(x)) {
		t.Fatalf("requeued %d, want %d", q, len(x))
	}
	stKillLane(p.b, p.bl[0])
	p.cut[0] = true

	var y []byte
	if !finLost {
		y = stPattern(uint64(len(x)), 200<<10)
		if closeInCopy {
			var once sync.Once
			stSetCopyHook(t, p.a, func() { once.Do(func() { _ = p.a.CloseWrite() }) })
		}
		if n, err := p.a.Write(y); n != len(y) || err != nil {
			t.Fatalf("Write(y) = (%d, %v)", n, err)
		}
		if !closeInCopy {
			_ = p.a.CloseWrite()
		}
	}
	stRoute(p.a, p.al[1], true)
	stRoute(p.b, p.bl[1], true)
	p.pump(true)

	var last uint64
	fin, phase := false, 0 // 0: replay of x, 1: y
	for _, f := range p.traceAB {
		switch f.typ {
		case wire.TypeData:
			if fin {
				t.Fatalf("%v after the FIN", f)
			}
			if f.off < last {
				t.Fatalf("%v out of order after offset %d", f, last)
			}
			if f.off < uint64(len(x)) != f.retx || (phase == 1 && f.retx) {
				t.Fatalf("%v: x must be a retransmission completed before any byte of y", f)
			}
			if !f.retx {
				phase = 1
			}
			last = f.off + uint64(f.n)
		case wire.TypeFin:
			if fin || f.off != uint64(len(x)+len(y)) || last != f.off {
				t.Fatalf("FIN %v after DATA up to %d (repeated: %v)", f, last, fin)
			}
			fin = true
		}
	}
	if !fin {
		t.Fatal("no FIN on the successor")
	}
	want := append(bytes.Clone(x), y...)
	if got := stReadN(t, p.b, len(want)); !bytes.Equal(got, want) {
		t.Fatal("x‖y corrupted")
	}
	if _, err := p.b.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("after x‖y: %v, want io.EOF", err)
	}
	p.close(t)
}

// TestFillAfterLaneGoneAppendsNothing_L10 (C1, R20): once the actor's death
// step marked a lane dead, laneGoneLocked requeued its spans and re-armed
// the FIN, and the step published the fallback SCHED, a Fill of that lane
// (a dying writer that was already inside Fill's lock wait) appends
// nothing — no DATA, FIN or control frame — and changes neither retx nor
// fin.lane; the successor then carries the SCHED, every byte and the FIN.
func TestFillAfterLaneGoneAppendsNothing_L10(t *testing.T) {
	p := stNewPair(stOpt{}, stOpt{}, 2)
	msg := stPattern(0, 200<<10)
	if n, err := p.a.Write(msg); n != len(msg) || err != nil {
		t.Fatal(err)
	}
	_ = p.a.CloseWrite()
	fs, b := stFill(p.al[0], time.Now()) // DATA and the FIN go out on lane 1 ...
	b.ReleaseRefs()
	if stCount(fs, wire.TypeFin) != 1 || stCount(fs, wire.TypeData) == 0 {
		t.Fatalf("lane 1 sent %v, want DATA and the FIN", fs)
	}
	if !p.al[0].finHere {
		t.Fatal("finHere not set on the FIN's lane")
	}
	stKillLane(p.a, p.al[0]) // ... and are lost with its carrier
	// The same death step publishes the fallback: SCHED{lane 2}, cause death.
	p.a.mu.Lock()
	p.a.ctl.epoch++
	p.a.ctl.set = wire.Sched{Epoch: p.a.ctl.epoch, N: 1, IDs: [16]uint32{p.al[1].id}}
	p.a.ctl.cause = wire.SchedDeath
	p.a.mu.Unlock()
	type snap struct {
		retx    []span
		finLane *lane
		sNext   uint64
	}
	take := func() snap {
		return stLocked(p.a, func(st *stream) snap {
			return snap{append([]span(nil), st.retx.s...), st.fin.lane, st.sNext}
		})
	}
	before := take()
	if before.finLane != nil || len(before.retx) == 0 || p.al[0].finHere {
		t.Fatalf("death step left retx %v and fin.lane set=%v", before.retx, before.finLane != nil)
	}
	for range 3 {
		fs, b := stFill(p.al[0], time.Now())
		b.ReleaseRefs()
		if len(fs) != 0 {
			t.Fatalf("Fill on the dead lane appended %v", fs)
		}
		if after := take(); after.finLane != nil || after.sNext != before.sNext || len(after.retx) != len(before.retx) || after.retx[0] != before.retx[0] {
			t.Fatalf("Fill on the dead lane changed the stream: %+v → %+v", before, after)
		}
	}
	stKillLane(p.b, p.bl[0])
	p.cut[0] = true
	stRoute(p.a, p.al[1], true)
	stRoute(p.b, p.bl[1], true)
	p.traceAB = nil
	p.pump(true)
	if n := stCount(p.traceAB, wire.TypeSched); n != 1 {
		t.Fatalf("%d SCHED frames on the successor, want the fallback's one", n)
	}
	if got := stReadN(t, p.b, len(msg)); !bytes.Equal(got, msg) {
		t.Fatal("successor delivery corrupted")
	}
	if _, err := p.b.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("after the replay: %v, want io.EOF (FIN re-sent on the successor)", err)
	}
	if n := stCount(p.traceAB, wire.TypeFin); n != 1 {
		t.Fatalf("%d FINs on the successor, want 1", n)
	}
	p.close(t)
}
