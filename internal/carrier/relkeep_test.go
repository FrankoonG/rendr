package carrier

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestMuxRelKeepsFirstFrameRoom_L12 (m6 item rc3; L12; rel.go
// relFirstKeep): on a datagram MUX trunk that takes new views and whose REL
// window the reliable frames of open views keep busy, a view's first frame
// finds room at once. A pair over a 10-ms link (RTT 20 ms): 16 views opened
// a second before; a 17th opened 70 ms before t0 (the trunk takes new
// views: a first frame sealed within the REL RTO on each side); at t0 the
// 16 views on the side under test each place one FIN (a frame of an open
// view); then a new view's first frame comes due between two RACKs.
//
//   - dialer: the dialer's views place the FINs and, at t0, a new view's
//     OPEN is queued. PASS: the t0 flight carries exactly wire.RelWindow −
//     relFirstKeep FINs, and Conn.RelRoom then reports 0 (the room a frame
//     of an open view can take); the OPEN leaves at t0 (not at the RACK,
//     t0 + 20 ms); a view whose FIN the kept room refused is not called
//     again until a RACK frees more room (no re-readying within the kept
//     room); every FIN arrives within ⌈16/6⌉ RTTs + RTO.
//   - passive: the passive's views place the FINs at t0 and the dialer's
//     OPEN of a new view reaches the passive at t0 + 10 ms. PASS: its
//     OPEN_ACK leaves when the OPEN is admitted (not when the dialer's RACK
//     of the FINs arrives, t0 + 20 ms); every FIN arrives within ⌈16/6⌉
//     RTTs + RTO.
//   - quiet: without the 17th view the dialer sealed no first frame within
//     its REL RTO and keeps nothing. PASS: the t0 flight carries
//     wire.RelWindow FINs.
//
// A dedicated carrier's dialer seals no first frame (its OPEN rides the
// handshake) and keeps nothing (TestRelWindow_L12 still places
// wire.RelWindow RELs in one flight), and DOWNs are not held to the kept
// room (TestDownBurstPaced_PA86: wire.RelWindow DOWNs a flight).
func TestMuxRelKeepsFirstFrameRoom_L12(t *testing.T) {
	for _, arm := range []string{"dialer", "passive", "quiet"} {
		t.Run(arm, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { relKeepRow(t, arm) })
		})
	}
}

func relKeepRow(t *testing.T, arm string) {
	dialerSide, quiet := arm != "passive", arm == "quiet"
	const delay = 10 * time.Millisecond
	d, p, ia, ib := dgMuxPair(t, 1200, nil)
	ia.setDelay(delay)
	ib.setDelay(delay)
	var hs []uint32
	for i := 0; i < 16; i++ {
		h := uint32(2 + i)
		d.open(t, wire.TypeOpen, byte(h))
		hs = append(hs, h)
	}
	time.Sleep(time.Second) // RTT samples
	synctest.Wait()
	if !quiet {
		d.open(t, wire.TypeOpen, byte(2+len(hs))) // the 17th view: the trunk takes new views
		time.Sleep(50 * time.Millisecond)         // its go PACK acknowledged
		synctest.Wait()
	}
	busy, peer, busyIO := d, p, ia
	if !dialerSide {
		busy, peer, busyIO = p, d, ib
	}
	busy.c.mu.Lock()
	rto := busy.c.relRTOLocked()
	free := busy.c.dg.rel.room()
	busy.c.mu.Unlock()
	if free != wire.RelWindow {
		t.Fatalf("premise: %d free RELs before t0, want the whole window %d", free, wire.RelWindow)
	}
	busyIO.setRec(true)
	t0 := time.Now()
	for _, h := range hs {
		mv := busy.view(h)
		mv.src.addCtl(hFrame{t: wire.TypeFin, payload: finInner(0)})
		mv.c.Wake()
	}
	synctest.Wait()
	// The t0 flight: the frames of open views leave the kept room free.
	fins := 0
	for _, r := range dgFramesOf(writesAt(busyIO.recorded(), t0)) {
		if r.h.Type == wire.TypeRel && r.inner.Type == wire.TypeFin {
			fins++
		}
	}
	if quiet {
		if fins != wire.RelWindow {
			t.Fatalf("the t0 flight of a trunk that took no view within its RTO carries %d FINs, want the whole window %d", fins, wire.RelWindow)
		}
		return
	}
	if want := wire.RelWindow - relFirstKeep; fins != want {
		t.Fatalf("the t0 flight carries %d FINs, want %d (the window less the room kept for first frames)", fins, want)
	}
	if r := busy.c.RelRoom(); r != 0 {
		t.Fatalf("RelRoom %d with only the kept room free, want 0 (the room a frame of an open view can take)", r)
	}
	fills := make(map[uint32]int64, len(hs))
	for _, h := range hs {
		fills[h] = busy.view(h).src.fills.Load()
	}

	// A new view's first frame comes due now (dialer: its OPEN; passive:
	// the dialer's OPEN, whose OPEN_ACK the passive owes when it arrives).
	h := uint32(3 + len(hs))
	v, err := d.c.openView(wire.TypeOpen, mOpenPayload(byte(h), true), uintptr(h))
	if err != nil {
		t.Fatalf("openView: %v", err)
	}
	resp := make(chan error, 1)
	go func() {
		_, err := v.awaitResponse(context.Background(), nil)
		resp <- err
	}()
	synctest.Wait()
	first, at := wire.TypeOpen, t0
	if !dialerSide {
		first = wire.TypeOpenAck
		time.Sleep(delay) // the OPEN's way to the passive
		synctest.Wait()
		at = t0.Add(delay)
	}
	sent := false
	for _, r := range dgFramesOf(writesAt(busyIO.recorded(), at)) {
		sent = sent || (r.h.Type == wire.TypeRel && r.inner.Type == first && r.inner.Handle == h)
	}
	if !sent {
		t.Fatalf("the %v of view %d did not leave at +%v with the window's other RELs outstanding: it waits for a RACK", first, h, at.Sub(t0))
	}
	if dialerSide {
		for _, hh := range hs {
			if n := busy.view(hh).src.fills.Load(); n != fills[hh] {
				t.Fatalf("view %d was called %d more times while only the kept room was free", hh, n-fills[hh])
			}
		}
	}
	if err := <-resp; err != nil {
		t.Fatalf("awaitResponse: %v", err)
	}
	// Every FIN still arrives: 16 frames of open views, 6 a round trip.
	bound := 3*(2*delay) + rto + 2*time.Millisecond
	for {
		all := true
		for _, hh := range hs {
			got := false
			for _, c := range peer.view(hh).ep.controls() {
				got = got || c.Type == wire.TypeFin
			}
			all = all && got
		}
		if all {
			break
		}
		if time.Since(t0) > bound {
			t.Fatalf("not every FIN arrived within ⌈16/6⌉·RTT + RTO = %v", bound)
		}
		time.Sleep(time.Millisecond)
	}
}

// writesAt returns the bytes of the recorded writes made at instant at.
func writesAt(ws []dgWrite, at time.Time) [][]byte {
	var out [][]byte
	for _, w := range ws {
		if w.at.Equal(at) {
			out = append(out, w.b)
		}
	}
	return out
}

// TestBatchRelKeepFirstFrames_L12_PA86 (rel.go relFirstKeep, relKeeps): a
// datagram round with 2 REL frames of room, both kept for first frames.
// PASS: a frame of an open view (FIN) is refused and RelRoom reports 0,
// while an OPEN_ACK (a first frame) is placed; and with a DOWN pending,
// an OPEN placed by the same round goes behind the DOWN (the PA-86 fence:
// the kept room does not hold a DOWN back), both in that round's two
// RELs.
func TestBatchRelKeepFirstFrames_L12_PA86(t *testing.T) {
	round := func() *Batch {
		b := NewBatch(0)
		b.Reset(time.Now())
		b.SetDatagram(1200, relFirstKeep)
		b.relKeep = relFirstKeep
		return b
	}
	b := round()
	if b.AddFin(2, 0) || !b.relRefused() || b.RelRoom() != 0 {
		t.Fatalf("FIN in the kept room: refused %v, RelRoom %d; want refused and 0", b.relRefused(), b.RelRoom())
	}
	if !b.AddOpenAck(3, &wire.OpenAck{Status: wire.StatusOK, Window: 1 << 20}) || b.relCount() != 1 {
		t.Fatalf("OPEN_ACK in the kept room: %d RELs, want it placed", b.relCount())
	}
	b.ReleaseRefs()

	b = round()
	q := &downQueue{}
	q.ids[0], q.n = 77, 1
	q.pend.Store(1)
	b.downs = q
	if !b.addFirst(wire.TypeOpen, 4, mOpenPayload(4, true)) {
		t.Fatal("the OPEN beside a pending DOWN was refused")
	}
	var types []wire.Type
	for k := range b.relCount() {
		types = append(types, wire.Type(b.relPayload(k, uint32(10+k))[4]))
	}
	if len(types) != 2 || types[0] != wire.TypeDown || types[1] != wire.TypeOpen || q.pend.Load() != 0 {
		t.Fatalf("the round's RELs %v (DOWNs pending %d), want [DOWN OPEN] and none pending", types, q.pend.Load())
	}
	b.ReleaseRefs()
}
