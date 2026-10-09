package adversarial

import (
	"fmt"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// confusions are the handle confusions of TestAdvMuxHandleConfusion_L43_L14.
var confusions = []string{"open-used", "data-unopened", "detach-unknown", "after-detach"}

// TestAdvMuxHandleConfusion_L43_L14: a broken peer — the handle rewritten
// with a recomputed CRC (Tamper.RewriteHandle on a stream trunk, the
// harness's dflip.rewrite on a datagram trunk), so the frame passes the
// CRC and fseq checks — confuses the handles of a MUX trunk that four busy
// sessions share (§A3.3; selector, bond and race sessions):
//
//   - "open-used": a fifth session's OPEN or JOIN on the trunk names
//     handle 1, a live view's (not above the trunk's maxHandle);
//   - "data-unopened": a DATA frame (a DGRAM) names handle 9, which the
//     trunk never opened;
//   - "detach-unknown": the DETACH an idle fifth session's view places at
//     its clean end ends handle 9 instead of its own;
//   - "after-detach": an idle fifth session ends cleanly (its handle
//     retires on both ends); a sixth session then opens a view on the
//     trunk with a new handle — handles are never reused (M3-D4) — and the
//     trunk lives; then a DATA frame (a DGRAM) names the retired handle.
//
// Stream trunks: the passive kills the trunk at that frame
// (protocol_violation naming the handle rule); every busy session migrates
// (migrated) and its stream arrives intact; the fifth session of
// "open-used" opens on another carrier and works. Datagram trunks: the
// passive drops and counts the frame (the trunk's Dropped), nothing dies,
// at most the rewritten DGRAM is lost, the fifth session of "open-used"
// opens (its REL is retransmitted unchanged), and every verifier sees its
// own datagrams once.
func TestAdvMuxHandleConfusion_L43_L14(t *testing.T) {
	for _, kind := range confusions {
		t.Run("stream/"+kind, func(t *testing.T) {
			eachSetupOf(t, muxSetups(), func(t *testing.T, s setup) { confuseStream(t, s, kind) })
		})
	}
	for _, kind := range confusions {
		t.Run("datagram/"+kind, func(t *testing.T) {
			eachSetupOf(t, muxSetups(), func(t *testing.T, s setup) { confuseDatagram(t, s, kind) })
		})
	}
}

// handleOn returns the handle of the session's live row of carrier id
// (status st); 0 when it has none.
func handleOn(st rendr.SessionStatus, id rendr.CarrierID) uint32 {
	for _, c := range st.Carriers {
		if c.ID == id && c.State != rendr.CarrierDead {
			return c.Handle
		}
	}
	return 0
}

// confusionWants are the details a stream trunk's passive may name for
// each confusion: the trunk's handle rules.
var confusionWants = map[string][]string{
	"open-used":      {"handle"},
	"data-unopened":  {"never opened"},
	"detach-unknown": {"handle"},
	"after-detach":   {"handle"},
}

// confuseStream is one stream row of TestAdvMuxHandleConfusion_L43_L14.
func confuseStream(t *testing.T, s setup, kind string) {
	n := rowBytes()
	w := newWorld(t, s, worldOpts{})
	peer := w.streamPeer()
	xs := w.openN(peer)
	var extra *pair
	if kind == "detach-unknown" || kind == "after-detach" {
		extra = w.open(peer)
	}
	fs := make([]*sflow, len(xs))
	for i, x := range xs {
		fs[i] = startFlow(x.d, x.p, n, 4380+uint64(i))
	}
	x := xs[0]
	fs[0].reached(t, n/4, "a quarter of the transfer")
	id := target(t, s, x.d.Status())
	tm := w.tamperOf(id)
	switch kind {
	case "open-used":
		tm.RewriteHandle(rendrtest.Up, rendrtest.NextOfType(rendrtest.FrameOpen), 1, true)
		tm.RewriteHandle(rendrtest.Up, rendrtest.NextOfType(rendrtest.FrameJoin), 1, true)
		// A new session whose OPEN or JOIN crosses the trunk (see
		// newViewOn: the pool may place it elsewhere; that one ends).
		for k := 0; ; k++ {
			extra = w.open(peer)
			if tm.Stats().Rewritten > 0 {
				break
			}
			if k == 3 {
				t.Fatalf("premise: four new sessions placed no OPEN or JOIN on trunk %d", id)
			}
			t.Logf("a new session placed no view on trunk %d: %+v", id, extra.d.Status().Carriers)
			extra.endClean(t)
		}
	case "data-unopened":
		tm.RewriteHandle(rendrtest.Up, rendrtest.NextOfType(rendrtest.FrameData), 9, true)
	case "detach-unknown":
		if handleOn(extra.d.Status(), id) == 0 {
			t.Fatalf("premise: the idle session has no view on trunk %d", id)
		}
		tm.RewriteHandle(rendrtest.Up, rendrtest.NextOfType(rendrtest.FrameDetach), 9, true)
		extra.endClean(t)
		extra = nil
	case "after-detach":
		h := handleOn(extra.d.Status(), id)
		if h == 0 {
			t.Fatalf("premise: the idle session has no view on trunk %d", id)
		}
		extra.endClean(t)
		extra = nil
		waitFor(t, 10*time.Second, "both DETACHes of the idle session's handle", func() bool {
			return hasType(tm.Log(rendrtest.Up), rendrtest.FrameDetach) && hasType(tm.Log(rendrtest.Down), rendrtest.FrameDetach)
		})
		// A session opened within about a second of a retirement on the
		// trunk tends to get a fresh trunk for one member (newViewOn).
		time.Sleep(time.Second)
		sixth := newViewOn(t, w, peer, id)
		if h6 := handleOn(sixth.d.Status(), id); h6 <= h {
			t.Fatalf("the sixth session's handle on trunk %d is %d, want one above the retired %d (handles are never reused)", id, h6, h)
		}
		if d := w.deaths(); len(d[0])+len(d[1]) != 0 {
			t.Fatalf("a new view after a retired handle killed carriers: dialer %+v, passive %+v", d[0], d[1])
		}
		xs = append(xs, sixth)
		fs = append(fs, startFlow(sixth.d, sixth.p, n/2, 4389))
		tm.RewriteHandle(rendrtest.Up, rendrtest.NextOfType(rendrtest.FrameData), h, true)
	}
	rewritten := stat(func(st rendrtest.TamperStats) int { return st.Rewritten })
	waitFor(t, 10*time.Second, "the rewrite (stimulus)", func() bool { return rewritten(tm) > 0 })
	if hit := w.hit(t, rewritten); hit.tm != tm {
		t.Fatalf("the rewrite fired on carrier %d, not on trunk %d", hit.id, id)
	}
	violated(t, "the confused trunk", endDead(t, "the passive", x.p.Status, id), confusionWants[kind]...)
	for i, f := range fs {
		f.wait(t, 2*time.Minute, fmt.Sprintf("session %d's transfer across the confusion", i))
	}
	if k := rewritten(tm); k != 1 {
		t.Fatalf("the rewrite fired %d times, want once", k)
	}
	migrated(t, s, xs, kill{id: id, cause: rendr.CauseProtocolViolation}, 1, 0)
	if extra != nil { // "open-used": the fifth session opened elsewhere
		f := startFlow(extra.d, extra.p, n/4, 4388)
		f.wait(t, time.Minute, "the fifth session's transfer")
		extra.endClean(t)
	}
	for _, y := range xs {
		y.endClean(t)
	}
	w.close()
}

// newViewOn opens a session over peer that has a view on trunk id. The
// pool may place a session's member on a freshly dialled trunk although
// id has room (a race session opened right after a view on id retired:
// most of the time; a second later about one in eight; a selector or bond
// fifth session now and then — a placement question for the pool, not
// this row's); such a session ends cleanly and another one is opened, at
// most four in all.
func newViewOn(t testing.TB, w *world, peer *rendr.Peer, id rendr.CarrierID) *pair {
	t.Helper()
	for range 4 {
		y := w.open(peer)
		if d := w.deaths(); len(d[0])+len(d[1]) != 0 {
			t.Fatalf("carriers died as a new session opened a view on trunk %d after a retired handle (a reused handle?): dialer %+v, passive %+v", id, d[0], d[1])
		}
		if handleOn(y.d.Status(), id) != 0 {
			return y
		}
		t.Logf("a new session has no view on trunk %d: %+v", id, y.d.Status().Carriers)
		y.endClean(t)
	}
	t.Fatalf("premise: four new sessions had no view on trunk %d", id)
	return nil
}

// hasType reports whether the frame tap log holds a frame of type typ.
func hasType(log []rendrtest.FrameRec, typ rendrtest.FrameType) bool {
	for _, r := range log {
		if r.Type == typ {
			return true
		}
	}
	return false
}

// confuseDatagram is one datagram row of TestAdvMuxHandleConfusion_L43_L14.
func confuseDatagram(t *testing.T, s setup, kind string) {
	w := newWorld(t, s, worldOpts{})
	peer := w.datagramPeer()
	xs := w.openPacketN(peer)
	var extra *ppair
	var fe *pflow
	if kind == "detach-unknown" || kind == "after-detach" {
		extra = w.openPacket(peer)
		fe = startPacketFlow(t, "idle", extra.d, extra.p, 4399, 0, 0)
	}
	ups := startPacketFlows(t, xs, 4390, packetRate)
	time.Sleep(time.Second)
	x := xs[0]
	id := target(t, s, x.d.Status())
	d0 := carrierDropped(x, id)
	lossy := false // the rewritten frame is a session's datagram
	switch kind {
	case "open-used":
		w.flip.rewrite(wire.TypeOpen, 1, id)
		extra = w.openPacket(peer)
		fe = startPacketFlow(t, "fifth", extra.d, extra.p, 4398, packetRate, 0)
	case "data-unopened":
		w.flip.rewrite(wire.TypeDgram, 9, id)
		lossy = true
	case "detach-unknown":
		if handleOn(extra.d.Status(), id) == 0 {
			t.Fatalf("premise: the idle session has no view on trunk %d", id)
		}
		w.flip.rewrite(wire.TypeDetach, 9, id)
		extra.endPacket(t, fe)
		extra = nil
	case "after-detach":
		h := handleOn(extra.d.Status(), id)
		if h == 0 {
			t.Fatalf("premise: the idle session has no view on trunk %d", id)
		}
		extra.endPacket(t, fe)
		extra = nil
		sixth := w.openPacket(peer)
		if h6 := handleOn(sixth.d.Status(), id); h6 <= h {
			t.Fatalf("the sixth session's handle on trunk %d is %d, want one above the retired %d (handles are never reused)", id, h6, h)
		}
		xs = append(xs, sixth)
		ups = append(ups, startPacketFlow(t, "sixth", sixth.d, sixth.p, 4397, packetRate, 0))
		w.flip.rewrite(wire.TypeDgram, h, id)
		lossy = true
	}
	waitFor(t, 10*time.Second, "the rewrite (stimulus)", func() bool { _, n := w.flip.rewritten(); return n > 0 })
	time.Sleep(time.Second)
	if hit, n := w.flip.rewritten(); hit != id || n != 1 {
		t.Fatalf("stimulus: the rewrite fired %d times on carrier %d, want once on trunk %d", n, hit, id)
	}
	if d := carrierDropped(x, id) - d0; d == 0 {
		t.Fatalf("the passive's trunk %d did not count the confused frame as dropped", id)
	}
	w.noDeaths()
	all := ups
	if extra != nil {
		xs, all = append(xs, extra), append(all, fe)
	}
	haltAll(t, all)
	time.Sleep(time.Second)
	var lost int64
	for _, f := range all {
		lost += f.lost()
	}
	if lost > 0 && !lossy || lost > 1 {
		t.Fatalf("load: the sessions lost %d datagrams, want at most the rewritten one", lost)
	}
	endPackets(t, xs, all)
	w.close()
}
