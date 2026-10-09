package adversarial

import (
	"fmt"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Datagram carriers: damage and replay lose datagrams, never deliver them
// damaged or twice, and never kill a carrier — except a replayed REL
// beyond the receiver's window, a CRC-valid protocol violation (M2-D14).

// dgInfo summarises one datagram a dialer conn wrote.
type dgInfo struct {
	preface bool           // a handshake datagram (PREFACE first)
	dgram   bool           // it carries a DGRAM frame
	rels    []wire.RelHead // its REL frames
	frames  int            // its frames after any PREFACE
}

// drops is what a receiving carrier counts as dropped when it refuses the
// datagram: a PREFACE datagram it does not know as its own H1 once, else
// each frame the fseq window refuses.
func (d dgInfo) drops() uint64 {
	if d.preface {
		return 1
	}
	return uint64(d.frames)
}

// inspect parses datagram b's top-level frames.
func inspect(b []byte) dgInfo {
	var d dgInfo
	if wire.IsPreface(b) {
		d.preface = true
		b = b[wire.PrefaceLen:]
	}
	for len(b) > 0 {
		f, n, err := wire.DecodeFrame(b)
		if err != nil {
			break
		}
		d.frames++
		switch f.Type {
		case wire.TypeDgram:
			d.dgram = true
		case wire.TypeRel:
			if h, _, err := wire.ParseRel(f.Payload); err == nil {
				d.rels = append(d.rels, h)
			}
		}
		b = b[n:]
	}
	return d
}

// fseqOf returns the fseq of the first frame of datagram b (after any
// PREFACE; 0 when b has none).
func fseqOf(b []byte) uint32 {
	if wire.IsPreface(b) {
		b = b[wire.PrefaceLen:]
	}
	h, err := wire.ParseHeader(b)
	if err != nil {
		return 0
	}
	return h.Fseq
}

// replayFrom re-sends datagram i of rec — the recording of the dialer conn
// of src's latest carrier (dflipConn.written) — into dst's latest carrier,
// Up: by DatagramLink.ReplayInto while src keeps it (its first 16 and
// latest 128 datagrams), else by DatagramLink.InjectRaw of the recorded
// copy, the same arrival. Either counts as Injected on dst.
func replayFrom(src, dst *rendrtest.DatagramLink, rec [][]byte, i int) {
	if i < 16 || i >= len(rec)-100 {
		src.ReplayInto(dst, i)
		return
	}
	dst.InjectRaw(rendrtest.Up, rec[i])
}

// linkOf returns the factory name of the dialer's carrier id.
func linkOf(t testing.TB, st rendr.SessionStatus, id rendr.CarrierID) string {
	t.Helper()
	c, ok := carrierOf(st, id)
	if !ok {
		t.Fatalf("no carrier %d in %+v", id, st.Carriers)
	}
	return c.Name
}

// droppedOf sums Dropped over the distinct carriers of one end of xs (a
// shared carrier once): the passive ends, or the dialer ends.
func droppedOf(xs []*ppair, dialer bool) uint64 {
	seen := map[rendr.CarrierID]bool{}
	var n uint64
	for _, x := range xs {
		st := x.p.Status()
		if dialer {
			st = x.d.Status()
		}
		for _, c := range st.Carriers {
			if !seen[c.ID] {
				seen[c.ID] = true
				n += c.Dropped
			}
		}
	}
	return n
}

// carrierDropped returns the passive's Dropped of carrier id in x.
func carrierDropped(x *ppair, id rendr.CarrierID) uint64 {
	c, _ := carrierOf(x.p.Status(), id)
	return c.Dropped
}

// seqCounts sums the passive ends' seq-window verdicts over xs: the
// datagrams SeqWindow refused as duplicates and as late.
func seqCounts(xs []*ppair) (dup, late uint64) {
	for _, x := range xs {
		k := x.p.Status().Packet
		dup += k.Duplicates
		late += k.DropLate
	}
	return dup, late
}

// lostOf sums the flows' missing datagrams.
func lostOf(fs []*pflow) int64 {
	var n int64
	for _, f := range fs {
		n += f.lost()
	}
	return n
}

// haltAll stops every flow and checks its integrity.
func haltAll(t testing.TB, fs []*pflow) {
	t.Helper()
	for _, f := range fs {
		f.halt(t)
	}
	for _, f := range fs {
		f.integrity(t)
	}
}

// noDeaths requires that no carrier of either Runtime died or violated.
func (w *world) noDeaths() {
	w.t.Helper()
	w.noViolation()
	if d := w.deaths(); len(d[0])+len(d[1]) != 0 {
		w.t.Fatalf("carriers died: dialer %+v, passive %+v", d[0], d[1])
	}
}

// noNewState requires that the passive Runtime holds the sessions and
// flows it held before (p0), no handshake and an empty backlog: a replay
// made no state.
func (w *world) noNewState(p0 rendr.Status) {
	w.t.Helper()
	if p1 := w.p.Status(); p1.Sessions != p0.Sessions || p1.Handshakes != 0 || p1.AcceptBacklog != [2]int{} || p1.Datagram.Flows != p0.Datagram.Flows {
		w.t.Fatalf("the replays made state on the passive: %+v (before %+v)", p1, p0)
	}
}

// TestAdvDatagramFlipsAreLoss_L43: on datagram carriers a path flips one
// random bit in 1 % of the datagrams of both directions (1,000 datagrams
// per second dialer → passive and 200 back per session, for four
// seconds): every damaged datagram is dropped and counted by the carrier
// that received it (the receivers' Dropped equal the flips), no carrier
// dies, and every verifier sees no damaged, foreign or duplicated
// datagram; at most the damaged datagrams are missing.
func TestAdvDatagramFlipsAreLoss_L43(t *testing.T) {
	eachSetup(t, func(t *testing.T, s setup) {
		w := newWorld(t, s, worldOpts{})
		xs := w.openPacketN(w.datagramPeer())
		var ups, downs []*pflow
		for i, x := range xs {
			ups = append(ups, startPacketFlow(t, fmt.Sprintf("A%d → B%d", i, i), x.d, x.p, 4330+2*uint64(i), 1000, 0))
			downs = append(downs, startPacketFlow(t, fmt.Sprintf("B%d → A%d", i, i), x.p, x.d, 4331+2*uint64(i), 200, 0))
		}
		time.Sleep(time.Second)
		w.flip.random(rendrtest.Up, 0.01)
		w.flip.random(rendrtest.Down, 0.01)
		time.Sleep(4 * time.Second)
		w.flip.random(rendrtest.Up, 0)
		w.flip.random(rendrtest.Down, 0)
		fu, nu := w.flip.randomFlips(rendrtest.Up)
		fd, nd := w.flip.randomFlips(rendrtest.Down)
		t.Logf("random flips: %d of %d datagrams dialer → passive, %d of %d back", fu, nu, fd, nd)
		// The flips of a direction follow its own seeded draws, one per
		// datagram written while its share is set: a session's about 4,000
		// and 825 datagrams (a 1 % mean of 40 and 8) flip 62 and 4 to 5
		// with these seeds — the few datagrams at the window's edges move
		// the back count by one; the MUX rows' four sessions draw four
		// times as many. The floors prove the stimulus with that margin;
		// the exact accounting below is the row's assertion.
		if fu < 20 || fd < 3 {
			t.Fatalf("stimulus: %d flips dialer → passive and %d back", fu, fd)
		}
		time.Sleep(time.Second)
		haltAll(t, append(ups, downs...))
		time.Sleep(time.Second)
		w.noDeaths()
		if dp, dd := droppedOf(xs, false), droppedOf(xs, true); dp != uint64(fu) || dd != uint64(fd) {
			t.Fatalf("dropped %d at the passive and %d at the dialer, want the %d and %d damaged datagrams", dp, dd, fu, fd)
		}
		if lu, ld := lostOf(ups), lostOf(downs); lu > int64(fu) || ld > int64(fd) {
			t.Fatalf("lost %d and %d datagrams, more than the %d and %d damaged ones", lu, ld, fu, fd)
		}
		endPackets(t, xs, ups)
		w.close()
	})
}

// TestAdvDatagramReplay_L43_L39: a path replays datagrams of a carrier into
// that same carrier (DatagramLink.ReplayInto; the latest carrier on the
// first session's link): its handshake datagram (H1, PREFACE ‖ REL{OPEN or
// JOIN}), its first REL after the handshake and its first DGRAM — all
// three behind the fseq window's top after three seconds — and a DGRAM
// from its latest hundred, inside the window. The receiving carrier
// answers the H1 copy with its stored H2 and drops nothing for it (no new
// handshake, flow or session), drops and counts every frame of the three
// other datagrams in its fseq window — exactly those, so the in-window
// copy never reaches the session's seq window (DropLate and, outside race,
// Duplicates unchanged) —, the application sees each datagram once, and
// nothing dies. (A MUX trunk's first datagrams carry the other sessions'
// OPENs and SCHEDs: its first DGRAM may come after the 16 the link keeps
// for ReplayInto; replayFrom re-sends it from the conn's own record.)
func TestAdvDatagramReplay_L43_L39(t *testing.T) {
	eachSetup(t, func(t *testing.T, s setup) {
		w := newWorld(t, s, worldOpts{record: true})
		xs := w.openPacketN(w.datagramPeer())
		ups := startPacketFlows(t, xs, 4340, packetRate)
		time.Sleep(3 * time.Second)
		name := linkOf(t, xs[0].d.Status(), target(t, s, xs[0].d.Status()))
		l, c := w.dlink(name), w.latestOn(name)
		y := ownerOf(t, xs, c.id)
		sent := c.written()
		picks := []int{0, -1, -1, -1} // H1, the first REL, the first DGRAM, a recent DGRAM
		for i := 1; i < min(64, len(sent)); i++ {
			d := inspect(sent[i])
			if picks[1] < 0 && !d.preface && len(d.rels) > 0 {
				picks[1] = i
			}
			if picks[2] < 0 && d.dgram {
				picks[2] = i
			}
		}
		for i := len(sent) - 1; i >= len(sent)-100 && picks[3] < 0; i-- {
			if inspect(sent[i]).dgram {
				picks[3] = i
			}
		}
		if !inspect(sent[0]).preface || picks[1] < 0 || picks[2] < 0 || picks[3] < 0 {
			t.Fatalf("no datagram to replay for each kind: %v of %d", picks, len(sent))
		}
		var want uint64
		for _, i := range picks[1:] {
			want += uint64(inspect(sent[i]).frames)
		}
		d0, p0 := carrierDropped(y, c.id), w.p.Status()
		dup0, late0 := seqCounts(xs)
		inj0 := l.Stats().Session.Injected
		for _, i := range picks {
			replayFrom(l, l, sent, i)
		}
		if n := l.Stats().Session.Injected - inj0; n != uint64(len(picks)) {
			t.Fatalf("stimulus: %d datagrams replayed, want %d", n, len(picks))
		}
		time.Sleep(time.Second)
		if d := carrierDropped(y, c.id) - d0; d != want {
			t.Fatalf("the carrier dropped %d frames, want the %d frames of the 3 replayed frame datagrams", d, want)
		}
		if dup1, late1 := seqCounts(xs); late1 != late0 || s.mode != rendr.ModeRace && dup1 != dup0 {
			t.Fatalf("replayed datagrams passed the fseq window: seq-window duplicates %d → %d, late %d → %d", dup0, dup1, late0, late1)
		}
		w.noNewState(p0)
		w.noDeaths()
		haltAll(t, ups)
		endPackets(t, xs, ups)
		w.close()
	})
}

// fseqPreset numbers every carrier direction's frames from the same fseq
// (both Runtimes, L14), so that a datagram replayed from one carrier into
// another meets the receiver's fseq window at a known place: the preset
// rows choose replays that are behind it or inside it.
const fseqPreset = 0x10000

// fseqMode is how the Runtimes of a cross-carrier replay row number their
// carriers' frames.
type fseqMode struct {
	name string
	ov   testhooks.Overrides
}

// fseqModes: "preset" (fseqPreset on both Runtimes) and "derived" (the
// production starts, each carrier direction's own: a replayed datagram
// lands behind or ahead of the receiver's window by chance, and one ahead
// by a window or more is dropped unless its datagram proves the jump, m3
// FSEQJUMP).
var fseqModes = []fseqMode{
	{"preset", testhooks.Overrides{FirstFseq: fseqPreset}},
	{"derived", testhooks.Overrides{}},
}

// TestAdvDatagramReplayAcrossCarriers_L43: datagrams of one carrier of a
// session replayed into another carrier of the same session.
//
//   - "dgram" (DatagramLink.ReplayInto): bond and race: the latest DGRAMs
//     of the member on "a" into the member on "b" (their fseqs are close:
//     inside b's window); selector: the first DGRAMs of the carrier that
//     died into its successor on the other link (behind its window). Each
//     is refused by the fseq window or deduplicated by seq (0 delivered
//     twice), no carrier dies, and at most the replayed datagrams' fseqs
//     cost genuine datagrams.
//   - "flow" (DatagramHub.ReplayFlow; bond and race, whose sessions hold
//     two raw-UDP flows at once): the first 16 datagrams of the member on
//     "a" — its H1 among them — re-sent on b's flow with b's flow header
//     into the passive's FromPacketConn source. b's carrier drops and
//     counts each one exactly (the foreign H1 once, every other frame in
//     its fseq window), no flow, session or handshake appears, the seq
//     window never sees them, nothing dies and nothing genuine is lost.
//   - "rel" (preset only): bond and race: the member on "b" is killed six
//     times, so the member on "a" carries a dozen more RELs (each member
//     set change publishes a SCHED on it) than the fresh member on "b" has
//     received; a's latest SCHED REL replayed into b is beyond b's REL
//     window, a CRC-valid violation: the passive kills b ("beyond the
//     window"), the session survives (b rejoins) and keeps its datagrams
//     intact. Selector: the dead carrier's first REL replayed into its
//     successor is behind the successor's window and absorbed (a selector
//     session has one data carrier at a time, which never runs ahead of a
//     later one's REL window). With derived starts whether the REL gets
//     past the fseq window at all is chance, so the row has no derived
//     variant.
//
// The derived variants of "dgram" and "flow" hold the preset expectations.
func TestAdvDatagramReplayAcrossCarriers_L43(t *testing.T) {
	for _, m := range fseqModes {
		t.Run(m.name, func(t *testing.T) {
			t.Run("dgram", func(t *testing.T) {
				eachSetup(t, func(t *testing.T, s setup) { replayAcrossCarriers(t, s, m.ov) })
			})
			t.Run("flow", func(t *testing.T) {
				for _, s := range setups() {
					if !s.members() {
						continue // one flow at a time (see above); AcrossSessions/flow covers selector
					}
					t.Run(s.name, func(t *testing.T) {
						synctest.Test(t, func(t *testing.T) { replayAcrossFlows(t, s, m.ov) })
					})
				}
			})
			if m.ov.FirstFseq != 0 {
				t.Run("rel", func(t *testing.T) {
					eachSetup(t, func(t *testing.T, s setup) { replayRelAcrossCarriers(t, s, m.ov) })
				})
			}
		})
	}
}

// replayAcrossCarriers is TestAdvDatagramReplayAcrossCarriers_L43/dgram.
func replayAcrossCarriers(t *testing.T, s setup, ov testhooks.Overrides) {
	w := newWorld(t, s, worldOpts{ov: ov, record: true})
	xs := w.openPacketN(w.datagramPeer())
	ups := startPacketFlows(t, xs, 4360, packetRate)
	time.Sleep(2 * time.Second)
	src, dst, rec, picks := acrossCarriers(t, w, xs, false)
	v := w.latestOn(dst.Name())
	y := ownerOf(t, xs, v.id)
	d0, lost0 := carrierDropped(y, v.id), lostOf(ups)
	dup0, _ := seqCounts(xs)
	inj0 := dst.Stats().Session.Injected
	for _, i := range picks {
		replayFrom(src, dst, rec, i)
	}
	if n := dst.Stats().Session.Injected - inj0; n != uint64(len(picks)) {
		t.Fatalf("stimulus: %d datagrams replayed, want %d", n, len(picks))
	}
	time.Sleep(time.Second)
	w.noViolation()
	// Nothing died but the selector's carriers the row cut; every replayed
	// DGRAM was refused by the fseq window (counted per frame) or
	// deduplicated by seq (outside race, whose copies count as Duplicates
	// anyway).
	d := w.deaths()
	if s.members() && len(d[0])+len(d[1]) != 0 || !s.members() && (len(d[0]) != len(xs) || len(d[1]) != len(xs)) {
		t.Fatalf("carriers died: dialer %+v, passive %+v", d[0], d[1])
	}
	dup1, _ := seqCounts(xs)
	if absorbed := carrierDropped(y, v.id) - d0 + dup1 - dup0; s.mode != rendr.ModeRace && absorbed < uint64(len(picks)) {
		t.Fatalf("the passive absorbed %d of the %d replayed datagrams (dropped or duplicates)", absorbed, len(picks))
	}
	haltAll(t, ups)
	time.Sleep(time.Second)
	// A replayed fseq inside the window may take the slot of a genuine
	// frame still on its way; nothing beyond that is lost.
	if lost := lostOf(ups); lost > lost0+int64(len(picks)) {
		t.Fatalf("load: %d datagrams lost, %d before the %d replays", lost, lost0, len(picks))
	}
	endPackets(t, xs, ups)
	w.close()
}

// replayAcrossFlows is TestAdvDatagramReplayAcrossCarriers_L43/flow.
func replayAcrossFlows(t *testing.T, s setup, ov testhooks.Overrides) {
	w := newWorld(t, s, worldOpts{ov: ov, record: true, hub: true})
	xs := w.openPacketN(w.hubPeer("a", "b"))
	ups := startPacketFlows(t, xs, 4362, packetRate)
	time.Sleep(2 * time.Second)
	replayFlow(t, w, xs, ups, w.latestHub("a"), w.latestHub("b"), xs)
	endPackets(t, xs, ups)
	w.close()
}

// replayFlow re-sends the first 16 datagrams of hub client from on client
// to's flow (DatagramHub.ReplayFlow) and requires: exactly the expected
// drops on to's carrier (a foreign H1 once, every other frame in the fseq
// window); no flow, session or handshake made; the seq windows of to's
// sessions (rx) untouched (DropLate, and Duplicates outside race); no
// death; no genuine datagram lost; every flow of fs intact.
func replayFlow(t *testing.T, w *world, all []*ppair, fs []*pflow, from, to *dflipConn, rx []*ppair) {
	t.Helper()
	sent := from.written()
	if len(sent) < 16 {
		t.Fatalf("hub client %d wrote %d datagrams, want at least 16", from.hub, len(sent))
	}
	var want uint64
	for _, b := range sent[:16] {
		want += inspect(b).drops()
	}
	y := ownerOf(t, all, to.id)
	d0, p0, lost0 := carrierDropped(y, to.id), w.p.Status(), lostOf(fs)
	dup0, late0 := seqCounts(rx)
	w.hub.ReplayFlow(from.hub, to.hub)
	if n := w.hub.Stats().Replayed; n != 16 {
		t.Fatalf("stimulus: %d datagrams replayed, want 16", n)
	}
	time.Sleep(time.Second)
	if d := carrierDropped(y, to.id) - d0; d != want {
		t.Fatalf("the carrier on the replayed flow dropped %d frames and datagrams, want the %d of the 16 replayed datagrams", d, want)
	}
	if dup1, late1 := seqCounts(rx); late1 != late0 || w.s.mode != rendr.ModeRace && dup1 != dup0 {
		t.Fatalf("replayed datagrams passed the fseq window: seq-window duplicates %d → %d, late %d → %d", dup0, dup1, late0, late1)
	}
	w.noNewState(p0)
	w.noDeaths()
	haltAll(t, fs)
	time.Sleep(time.Second)
	if lost := lostOf(fs); lost > lost0 {
		t.Fatalf("load: %d datagrams lost, %d before the replay", lost, lost0)
	}
}

// replayRelAcrossCarriers is TestAdvDatagramReplayAcrossCarriers_L43/rel.
func replayRelAcrossCarriers(t *testing.T, s setup, ov testhooks.Overrides) {
	w := newWorld(t, s, worldOpts{ov: ov, record: true})
	xs := w.openPacketN(w.datagramPeer())
	ups := startPacketFlows(t, xs, 4361, 100)
	time.Sleep(time.Second)
	src, dst, rec, picks := acrossCarriers(t, w, xs, true)
	v := w.latestOn(dst.Name())
	y := ownerOf(t, xs, v.id)
	inj0 := dst.Stats().Session.Injected
	replayFrom(src, dst, rec, picks[0])
	if n := dst.Stats().Session.Injected - inj0; n != 1 {
		t.Fatalf("stimulus: %d datagrams replayed, want 1", n)
	}
	if s.members() {
		violated(t, "b's carrier", endDead(t, "the passive", y.p.Status, v.id), "beyond the window")
		waitFor(t, 10*time.Second, "b rejoining", func() bool { return len(liveOf(y.d.Status())) == 2 })
	} else {
		time.Sleep(time.Second)
		w.noViolation()
	}
	time.Sleep(time.Second)
	haltAll(t, ups)
	for _, up := range ups {
		if r := float64(up.accepted.Load()-up.lost()) / float64(up.accepted.Load()); r < 0.8 {
			t.Fatalf("load: %s: %.2f of the datagrams arrived (%d lost of %d)", up.name, r, up.lost(), up.accepted.Load())
		}
	}
	endPackets(t, xs, ups)
	w.close()
}

// acrossCarriers prepares a replay from one carrier of the first session
// of xs into another and returns the source link, the destination link,
// the recording of the source link's latest carrier and the indices in it
// to replay (replayFrom). Bond and race: the member on "a" into
// the member on "b" — rel: after six kills of b, a's latest datagram with
// a SCHED REL; else a's five latest DGRAMs. Selector: the active carrier's
// link is killed and refused, the sessions fail over to the other link,
// and the dead carrier's first REL (rel) or its five first DGRAMs are
// replayed into the successor.
func acrossCarriers(t testing.TB, w *world, xs []*ppair, rel bool) (src, dst *rendrtest.DatagramLink, rec [][]byte, picks []int) {
	t.Helper()
	x := xs[0]
	if w.s.members() {
		src, dst = w.dlink("a"), w.dlink("b")
		if rel {
			for k := 0; k < 6; k++ {
				dst.Kill()
				waitFor(t, 10*time.Second, "b rejoining", func() bool {
					for _, y := range xs {
						if len(liveOf(y.d.Status())) != 2 || len(liveOf(y.p.Status())) != 2 {
							return false
						}
					}
					return true
				})
				time.Sleep(50 * time.Millisecond)
			}
		}
		sent := w.latestOn("a").written()
		// MUX trunks with preset starts: each trunk direction numbers the
		// frames of four sessions from fseqPreset, at its own pace, so a's
		// latest fseqs may lie ahead of b's window, where a replay moves the
		// window (one less than a window ahead) or is a forward jump: the
		// "dgram" picks are a's latest DGRAMs at or behind b's newest fseq,
		// the dedicated pair's premise. (Derived starts put them anywhere.)
		top, behind := uint32(0), false
		if !rel && w.s.mux && w.o.ov.FirstFseq != 0 {
			bs := w.latestOn("b").written()
			top, behind = fseqOf(bs[len(bs)-1]), true
		}
		for i := len(sent) - 1; i >= 0 && (behind || i >= len(sent)-100) && len(picks) < 5; i-- {
			d := inspect(sent[i])
			switch {
			case rel && len(d.rels) > 0 && d.rels[0].Type == wire.TypeSched:
				return src, dst, sent, []int{i}
			case !rel && d.dgram && (!behind || int32(fseqOf(sent[i])-top) <= 0):
				picks = append(picks, i)
			}
		}
		if rel || len(picks) == 0 {
			t.Fatalf("no datagram of a to replay (rel %v)", rel)
		}
		return src, dst, sent, picks
	}
	name := linkOf(t, x.d.Status(), target(t, w.s, x.d.Status()))
	src = w.dlink(name)
	other := "a"
	if name == "a" {
		other = "b"
	}
	dst = w.dlink(other)
	src.Refuse(true)
	src.Kill()
	waitFor(t, 10*time.Second, "the failover to link "+other, func() bool {
		for _, y := range xs {
			ok := false
			for _, c := range liveOf(y.d.Status()) {
				ok = ok || c.State == rendr.CarrierActive && c.Name == other
			}
			if !ok {
				return false
			}
		}
		return true
	})
	time.Sleep(time.Second) // the successor runs well past the replays' fseqs
	sent := w.latestOn(name).written()
	// The first DGRAMs of the record (replayFrom re-sends any of it): a MUX
	// trunk's first datagrams carry the other sessions' OPENs, SCHEDs and
	// ACKs, so its first DGRAM may come after the 16 the link keeps (seen
	// under -race).
	for i := 1; i < len(sent) && len(picks) < 5; i++ {
		d := inspect(sent[i])
		switch {
		case rel && !d.preface && len(d.rels) > 0:
			return src, dst, sent, []int{i}
		case !rel && d.dgram:
			picks = append(picks, i)
		}
	}
	if rel || len(picks) == 0 {
		t.Fatalf("no datagram of the dead carrier to replay (rel %v)", rel)
	}
	return src, dst, sent, picks
}

// TestAdvDatagramReplayAcrossSessions_L43: session A's datagrams replayed
// into session B's dedicated datagram carrier (A on links a and b, B on c
// and d, B started a second earlier; R1-35).
//
//   - "link" (DatagramLink.ReplayInto): A's first eight datagrams — its H1
//     among them — and its eight latest into B's carrier on its link;
//   - "flow" (DatagramHub.ReplayFlow): both sessions on raw-UDP flows into
//     the passive's FromPacketConn source; A's first 16 datagrams re-sent
//     on B's flow with B's flow header.
//
// They fail B's fseq window (behind it: late or duplicate) or, the H1, are
// no PREFACE B's carrier knows: B's carrier drops and counts each one
// exactly and lives, B's seq window never sees them, B's verifier sees no
// foreign datagram, no flow or session appears, and A is unaffected; so
// on a datagram MUX trunk, where a replayed frame may also carry a handle
// B's trunk never opened. The derived variants hold the preset
// expectations. "stream" (replayAcrossStreamSessions) has its own
// expectation: on stream carriers — a stream MUX trunk among them — B's
// carrier dies.
func TestAdvDatagramReplayAcrossSessions_L43(t *testing.T) {
	for _, m := range fseqModes {
		t.Run(m.name, func(t *testing.T) {
			for _, hub := range []bool{false, true} {
				name := "link"
				if hub {
					name = "flow"
				}
				t.Run(name, func(t *testing.T) {
					eachSetup(t, func(t *testing.T, s setup) { replayAcrossSessions(t, s, m.ov, hub) })
				})
			}
		})
	}
	t.Run("stream", func(t *testing.T) {
		eachSetup(t, replayAcrossStreamSessions)
	})
}

// replayAcrossStreamSessions is TestAdvDatagramReplayAcrossSessions_L43/
// stream, its own expectation (R1-35): the packet sessions A and B, a Peer
// each, on stream carriers — dedicated, or a stream MUX trunk per link
// each — send 500 datagrams per second dialer → passive; then A's frames,
// its DGRAMs among its ACKs, PINGs and SCHEDs, are forwarded into B's
// attacked carrier from B's next frame boundary on
// (Tamper.Splice: a stream relay that replays one session's datagrams into
// another's carrier). B's passive kills that carrier (protocol_violation
// "fseq": A's frames continue A's sequence) before any of A's datagrams
// reaches B: B's verifiers see none of them. B's sessions migrate — Death
// 1 for the attacked one, and for each of its neighbours on the shared
// trunk (a packet member that placed a DGRAM within the last PacketPing
// counts, M2-D44) — and lose at most what was in flight on the dead
// carrier; A's sessions are untouched and lose nothing.
func replayAcrossStreamSessions(t *testing.T, s setup) {
	w := newWorld(t, s, worldOpts{})
	as, bs := w.openPacketN(w.streamPeer()), w.openPacketN(w.streamPeer())
	fa := startPacketFlows(t, as, 4372, packetRate)
	fb := startPacketFlows(t, bs, 4352, packetRate)
	time.Sleep(time.Second)
	ta, tb := w.tamperOf(target(t, s, as[0].d.Status())), w.tamperOf(target(t, s, bs[0].d.Status()))
	tb.Splice(rendrtest.Up, ta, 0)
	waitFor(t, 5*time.Second, "A's frames forwarded into B's carrier (stimulus)", func() bool { return tb.Stats().SplicedBytes > 0 })
	hit := w.hit(t, spliced)
	if hit.tm != tb {
		t.Fatalf("the splice started on carrier %d, not B's", hit.id)
	}
	violated(t, "B's carrier", endDead(t, "B's passive", bs[0].p.Status, hit.id), "fseq")
	if !hasSpliced(tb.Log(rendrtest.Up)) {
		t.Fatal("stimulus: none of A's frames was forwarded into B's carrier")
	}
	time.Sleep(time.Second)
	fs := append(slices.Clone(fa), fb...)
	haltAll(t, fs) // every verifier: no foreign, damaged or duplicated datagram
	time.Sleep(time.Second)
	for i, f := range fa {
		if k := f.lost(); k != 0 {
			t.Fatalf("load: A's session %d lost %d datagrams", i, k)
		}
	}
	for _, f := range fb {
		// Only what was in flight on the dead carrier: at most its link
		// queue and one round trip (50), as flipStreamDgram.
		if f.lost() > 50 {
			t.Fatalf("load: %s lost %d of %d datagrams", f.name, f.lost(), f.accepted.Load())
		}
	}
	deathsAre(t, s, bs[0].d.Status, bs[0].p.Status, 1)
	neighboursPacket(t, s, bs, 0, 1)
	for i, x := range as {
		untouchedPacket(t, fmt.Sprintf("A's session %d", i), x)
	}
	endPackets(t, slices.Concat(as, bs), fs)
	w.close()
}

// hasSpliced reports whether a frame tap log holds a frame forwarded from
// another tamper (Spliced): A's DGRAMs mostly, and B's carrier dies at the
// first of A's frames, whatever its type.
func hasSpliced(log []rendrtest.FrameRec) bool {
	for _, r := range log {
		if r.Spliced {
			return true
		}
	}
	return false
}

// replayAcrossSessions is one form of TestAdvDatagramReplayAcrossSessions_L43.
func replayAcrossSessions(t *testing.T, s setup, ov testhooks.Overrides, hub bool) {
	w := newWorld(t, s, worldOpts{ov: ov, record: true, links: 4, hub: hub})
	peer := func(names ...string) *rendr.Peer {
		if hub {
			return w.hubPeer(names...)
		}
		return w.datagramPeer(names...)
	}
	bs := w.openPacketN(peer("c", "d"))
	fb := startPacketFlows(t, bs, 4351, packetRate)
	time.Sleep(time.Second)
	as := w.openPacketN(peer("a", "b"))
	fa := startPacketFlows(t, as, 4371, packetRate)
	time.Sleep(2 * time.Second)
	sa := linkOf(t, as[0].d.Status(), target(t, s, as[0].d.Status()))
	sb := linkOf(t, bs[0].d.Status(), target(t, s, bs[0].d.Status()))
	all, fs := append(as, bs...), append(fa, fb...)
	if hub {
		replayFlow(t, w, all, fs, w.latestHub(sa), w.latestHub(sb), bs)
	} else {
		src, dst := w.dlink(sa), w.dlink(sb)
		ca, cb := w.latestOn(sa), w.latestOn(sb)
		y := ownerOf(t, bs, cb.id)
		sent := ca.written()
		var picks []int
		var want uint64
		for i := range min(8, len(sent)) {
			picks = append(picks, i)
		}
		for i := len(sent) - 8; i < len(sent); i++ {
			picks = append(picks, i)
		}
		for _, i := range picks {
			want += inspect(sent[i]).drops()
		}
		d0, p0, lost0 := carrierDropped(y, cb.id), w.p.Status(), lostOf(fs)
		dup0, late0 := seqCounts(bs)
		for _, i := range picks {
			src.ReplayInto(dst, i)
		}
		if n := dst.Stats().Replayed; n != uint64(len(picks)) {
			t.Fatalf("stimulus: %d datagrams replayed, want %d", n, len(picks))
		}
		time.Sleep(time.Second)
		if d := carrierDropped(y, cb.id) - d0; d != want {
			t.Fatalf("B's carrier dropped %d frames and datagrams, want the %d of the %d replayed datagrams", d, want, len(picks))
		}
		if dup1, late1 := seqCounts(bs); late1 != late0 || s.mode != rendr.ModeRace && dup1 != dup0 {
			t.Fatalf("replayed datagrams passed B's fseq window: seq-window duplicates %d → %d, late %d → %d", dup0, dup1, late0, late1)
		}
		w.noNewState(p0)
		w.noDeaths()
		haltAll(t, fs)
		time.Sleep(time.Second)
		if lost := lostOf(fs); lost > lost0 {
			t.Fatalf("load: %d datagrams lost, %d before the replays", lost, lost0)
		}
	}
	for i, x := range all {
		untouchedPacket(t, fmt.Sprintf("session %d", i), x)
	}
	endPackets(t, all, fs)
	w.close()
}

// untouchedPacket requires that packet session x lost no carrier and
// counted no migration on either end.
func untouchedPacket(t testing.TB, what string, x *ppair) {
	t.Helper()
	for _, st := range []rendr.SessionStatus{x.d.Status(), x.p.Status()} {
		if d := deadOf(st); len(d) != 0 || st.Migrations != (rendr.MigrationCounts{}) {
			t.Fatalf("%s (%v) was touched: dead %+v, migrations %+v", what, st.Role, d, st.Migrations)
		}
	}
}
