package adversarial

import (
	"testing"
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

// linkOf returns the factory name of the dialer's carrier id.
func linkOf(t testing.TB, st rendr.SessionStatus, id rendr.CarrierID) string {
	t.Helper()
	c, ok := carrierOf(st, id)
	if !ok {
		t.Fatalf("no carrier %d in %+v", id, st.Carriers)
	}
	return c.Name
}

// sumDropped sums Dropped over the carriers st lists.
func sumDropped(st rendr.SessionStatus) uint64 {
	var n uint64
	for _, c := range st.Carriers {
		n += c.Dropped
	}
	return n
}

// TestAdvDatagramFlipsAreLoss_L43: on datagram carriers a path flips one
// random bit in 1 % of the datagrams of both directions (1,000 datagrams
// per second dialer → passive, 200 back, for four seconds): every damaged
// datagram is dropped and counted by the carrier that received it (the
// receivers' Dropped equal the flips), no carrier dies, and both verifiers
// see no damaged, foreign or duplicated datagram; at most the damaged
// datagrams are missing.
func TestAdvDatagramFlipsAreLoss_L43(t *testing.T) {
	eachSetup(t, func(t *testing.T, s setup) {
		w := newWorld(t, s, worldOpts{})
		x := w.openPacket(w.datagramPeer())
		up := startPacketFlow("A → B", x.d, x.p, 4330, 1000, 0)
		down := startPacketFlow("B → A", x.p, x.d, 4331, 200, 0)
		time.Sleep(time.Second)
		w.flip.random(rendrtest.Up, 0.01)
		w.flip.random(rendrtest.Down, 0.01)
		time.Sleep(4 * time.Second)
		w.flip.random(rendrtest.Up, 0)
		w.flip.random(rendrtest.Down, 0)
		fu, fd := w.flip.randomFlips(rendrtest.Up), w.flip.randomFlips(rendrtest.Down)
		if fu < 20 || fd < 5 {
			t.Fatalf("stimulus: %d flips dialer → passive and %d back", fu, fd)
		}
		time.Sleep(time.Second)
		up.halt(t)
		down.halt(t)
		time.Sleep(time.Second)
		w.noViolation()
		if d := w.deaths(); len(d[0])+len(d[1]) != 0 {
			t.Fatalf("carriers died: dialer %+v, passive %+v", d[0], d[1])
		}
		if dp, dd := sumDropped(x.p.Status()), sumDropped(x.d.Status()); dp != uint64(fu) || dd != uint64(fd) {
			t.Fatalf("dropped %d at the passive and %d at the dialer, want the %d and %d damaged datagrams", dp, dd, fu, fd)
		}
		up.integrity(t)
		down.integrity(t)
		if lu, ld := up.lost(), down.lost(); lu > int64(fu) || ld > int64(fd) {
			t.Fatalf("lost %d and %d datagrams, more than the %d and %d damaged ones", lu, ld, fu, fd)
		}
		x.endPacket(t, up)
		w.close()
	})
}

// TestAdvDatagramReplay_L43_L39: a path replays datagrams of a carrier into
// that same carrier (DatagramLink.ReplayInto): its handshake datagram (H1,
// PREFACE ‖ REL{OPEN or JOIN}), its first REL after the handshake and its
// first DGRAM — all three far behind the fseq window after three seconds —
// and a DGRAM from its latest hundred, inside the window. The receiving
// carrier drops and counts the three frame datagrams (late or duplicate in
// the fseq window), answers the H1 copy at most with its stored H2 (no new
// handshake, flow or session), the application sees each datagram once,
// and nothing dies.
func TestAdvDatagramReplay_L43_L39(t *testing.T) {
	eachSetup(t, func(t *testing.T, s setup) {
		w := newWorld(t, s, worldOpts{record: true})
		x := w.openPacket(w.datagramPeer())
		up := startPacketFlow("A → B", x.d, x.p, 4340, packetRate, 0)
		time.Sleep(3 * time.Second)
		id := target(t, s, x.d.Status())
		l := w.dlink(linkOf(t, x.d.Status(), id))
		sent := w.dconnOf(id).written()
		picks := []int{0, -1, -1, -1} // H1, the first REL, the first DGRAM, a recent DGRAM
		for i := 1; i < min(16, len(sent)); i++ {
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
		pc0, _ := carrierOf(x.p.Status(), id)
		p0 := w.p.Status()
		for _, i := range picks {
			l.ReplayInto(l, i)
		}
		if n := l.Stats().Replayed; n != uint64(len(picks)) {
			t.Fatalf("stimulus: %d datagrams replayed, want %d", n, len(picks))
		}
		time.Sleep(time.Second)
		pc1, _ := carrierOf(x.p.Status(), id)
		if d := pc1.Dropped - pc0.Dropped; d < 3 {
			t.Fatalf("the carrier counted %d of the 3 replayed frame datagrams as dropped", d)
		}
		if p1 := w.p.Status(); p1.Sessions != p0.Sessions || p1.Handshakes != 0 || p1.AcceptBacklog != [2]int{} || p1.Datagram.Flows != 0 {
			t.Fatalf("the replays made state on the passive: %+v (before %+v)", p1, p0)
		}
		w.noViolation()
		if d := w.deaths(); len(d[0])+len(d[1]) != 0 {
			t.Fatalf("carriers died: dialer %+v, passive %+v", d[0], d[1])
		}
		up.halt(t)
		up.integrity(t)
		x.endPacket(t, up)
		w.close()
	})
}

// fseqPreset numbers every carrier direction's frames from the same fseq
// (both Runtimes, L14), so that a datagram replayed from one carrier into
// another meets the receiver's fseq window at a known place: the rows
// below choose replays that are behind it or inside it, never far ahead
// (see the WP14 report: with derived per-carrier starts a replay lands
// ahead of the window about half the time).
const fseqPreset = 0x10000

// TestAdvDatagramReplayAcrossCarriers_L43: datagrams of one carrier of a
// session replayed into another carrier of the same session.
//
//   - "dgram": bond and race: the latest DGRAMs of the member on "a" into
//     the member on "b" (their fseqs are close: inside b's window); selector:
//     the first DGRAMs of the carrier that died into its successor on the
//     other link (behind its window). Duplicates by seq are dropped (0
//     delivered twice), no carrier dies.
//   - "rel": bond and race: the member on "b" is killed six times, so the
//     member on "a" carries a dozen more RELs (each member set change
//     publishes a SCHED on it) than the fresh member on "b" has received;
//     a's latest SCHED REL replayed into b is beyond b's REL window, a
//     CRC-valid violation: the passive kills b ("beyond the window"), the
//     session survives (b rejoins) and keeps its datagrams intact.
//     Selector: the dead carrier's first REL replayed into its successor
//     is behind the successor's window and absorbed (a selector session
//     has one data carrier at a time, which never runs ahead of a later
//     one's REL window).
func TestAdvDatagramReplayAcrossCarriers_L43(t *testing.T) {
	t.Run("dgram", func(t *testing.T) {
		eachSetup(t, func(t *testing.T, s setup) {
			w := newWorld(t, s, worldOpts{ov: testhooks.Overrides{FirstFseq: fseqPreset}, record: true})
			x := w.openPacket(w.datagramPeer())
			up := startPacketFlow("A → B", x.d, x.p, 4360, packetRate, 0)
			time.Sleep(2 * time.Second)
			src, dst, picks := acrossCarriers(t, w, x, false)
			p0 := x.p.Status()
			for _, i := range picks {
				src.ReplayInto(dst, i)
			}
			if n := dst.Stats().Replayed; n != uint64(len(picks)) {
				t.Fatalf("stimulus: %d datagrams replayed, want %d", n, len(picks))
			}
			time.Sleep(time.Second)
			w.noViolation()
			// Nothing died but the selector's carrier the row cut; every
			// replayed DGRAM was refused by the fseq window (counted per
			// frame) or deduplicated by seq (outside race, whose copies
			// count as Duplicates anyway).
			d := w.deaths()
			if s.members() && len(d[0])+len(d[1]) != 0 || !s.members() && (len(d[0]) != 1 || len(d[1]) != 1) {
				t.Fatalf("carriers died: dialer %+v, passive %+v", d[0], d[1])
			}
			p1 := x.p.Status()
			absorbed := sumDropped(p1) - sumDropped(p0) + p1.Packet.Duplicates - p0.Packet.Duplicates
			if s.mode != rendr.ModeRace && absorbed < uint64(len(picks)) {
				t.Fatalf("the passive absorbed %d of the %d replayed datagrams (dropped or duplicates)", absorbed, len(picks))
			}
			up.halt(t)
			up.integrity(t)
			x.endPacket(t, up)
			w.close()
		})
	})
	t.Run("rel", func(t *testing.T) {
		eachSetup(t, func(t *testing.T, s setup) {
			w := newWorld(t, s, worldOpts{ov: testhooks.Overrides{FirstFseq: fseqPreset}, record: true})
			x := w.openPacket(w.datagramPeer())
			up := startPacketFlow("A → B", x.d, x.p, 4361, 100, 0)
			time.Sleep(time.Second)
			src, dst, picks := acrossCarriers(t, w, x, true)
			var victim rendr.CarrierID
			if s.members() {
				for _, c := range liveOf(x.p.Status()) {
					if dc, ok := carrierOf(x.d.Status(), c.ID); ok && dc.Name == "b" {
						victim = c.ID
					}
				}
			}
			src.ReplayInto(dst, picks[0])
			if n := dst.Stats().Replayed; n != 1 {
				t.Fatalf("stimulus: %d datagrams replayed, want 1", n)
			}
			if s.members() {
				violated(t, "b's carrier", endDead(t, "the passive", x.p.Status, victim), "beyond the window")
				waitFor(t, 10*time.Second, "b rejoining", func() bool { return len(liveOf(x.d.Status())) == 2 })
			} else {
				time.Sleep(time.Second)
				w.noViolation()
			}
			time.Sleep(time.Second)
			up.halt(t)
			up.integrity(t)
			if r := float64(up.accepted.Load()-up.lost()) / float64(up.accepted.Load()); r < 0.8 {
				t.Fatalf("load: %.2f of the datagrams arrived (%d lost of %d)", r, up.lost(), up.accepted.Load())
			}
			x.endPacket(t, up)
			w.close()
		})
	})
}

// acrossCarriers prepares a replay from one carrier of session x into
// another and returns the source link, the destination link and the
// indices (in the source carrier's datagrams) to replay. Bond and race:
// the member on "a" into the member on "b" — rel: after six kills of b,
// a's latest datagram with a SCHED REL; else a's five latest DGRAMs.
// Selector: the active carrier's link is killed and refused, the session
// fails over to the other link, and the dead carrier's first REL (rel) or
// its five first DGRAMs are replayed into the successor.
func acrossCarriers(t testing.TB, w *world, x *ppair, rel bool) (src, dst *rendrtest.DatagramLink, picks []int) {
	t.Helper()
	id := target(t, w.s, x.d.Status())
	if w.s.members() {
		src, dst = w.dlink("a"), w.dlink("b")
		if rel {
			for k := 0; k < 6; k++ {
				dst.Kill()
				waitFor(t, 10*time.Second, "b rejoining", func() bool {
					return len(liveOf(x.d.Status())) == 2 && len(liveOf(x.p.Status())) == 2
				})
				time.Sleep(50 * time.Millisecond)
			}
		}
		sent := w.dconnOf(id).written()
		for i := len(sent) - 1; i >= len(sent)-100 && i >= 0 && len(picks) < 5; i-- {
			d := inspect(sent[i])
			switch {
			case rel && len(d.rels) > 0 && d.rels[0].Type == wire.TypeSched:
				return src, dst, []int{i}
			case !rel && d.dgram:
				picks = append(picks, i)
			}
		}
		if rel || len(picks) == 0 {
			t.Fatalf("no datagram of a to replay (rel %v)", rel)
		}
		return src, dst, picks
	}
	name := linkOf(t, x.d.Status(), id)
	src = w.dlink(name)
	other := "a"
	if name == "a" {
		other = "b"
	}
	dst = w.dlink(other)
	src.Refuse(true)
	src.Kill()
	waitFor(t, 10*time.Second, "the failover to link "+other, func() bool {
		for _, c := range liveOf(x.d.Status()) {
			if c.State == rendr.CarrierActive && c.Name == other {
				return true
			}
		}
		return false
	})
	time.Sleep(time.Second) // the successor runs well past the replays' fseqs
	sent := w.dconnOf(id).written()
	for i := 1; i < min(16, len(sent)) && len(picks) < 5; i++ {
		d := inspect(sent[i])
		switch {
		case rel && !d.preface && len(d.rels) > 0:
			return src, dst, []int{i}
		case !rel && d.dgram:
			picks = append(picks, i)
		}
	}
	if rel || len(picks) == 0 {
		t.Fatalf("no datagram of the dead carrier to replay (rel %v)", rel)
	}
	return src, dst, picks
}

// TestAdvDatagramReplayAcrossSessions_L43: session A's datagrams replayed
// into session B's dedicated datagram carrier (A on links a and b, B on c
// and d, B started a second earlier; R1-35): A's first eight datagrams —
// its H1 among them — and its eight latest. They fail B's fseq window
// (behind it: late or duplicate) or, the H1, are no PREFACE B's carrier
// knows: B's carrier drops and counts each one and lives, B's verifier
// sees no foreign datagram, and A is unaffected. (The MUX half adds the
// datagram MUX trunk and the stream MUX trunk, whose carrier dies.)
func TestAdvDatagramReplayAcrossSessions_L43(t *testing.T) {
	eachSetup(t, func(t *testing.T, s setup) {
		w := newWorld(t, s, worldOpts{ov: testhooks.Overrides{FirstFseq: fseqPreset}, record: true, links: 4})
		b := w.openPacket(w.datagramPeer("c", "d"))
		fb := startPacketFlow("B", b.d, b.p, 4351, packetRate, 0)
		time.Sleep(time.Second)
		a := w.openPacket(w.datagramPeer("a", "b"))
		fa := startPacketFlow("A", a.d, a.p, 4350, packetRate, 0)
		time.Sleep(2 * time.Second)
		ida, idb := target(t, s, a.d.Status()), target(t, s, b.d.Status())
		src, dst := w.dlink(linkOf(t, a.d.Status(), ida)), w.dlink(linkOf(t, b.d.Status(), idb))
		sent := w.dconnOf(ida).written()
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
		pb0, _ := carrierOf(b.p.Status(), idb)
		k0 := *b.p.Status().Packet
		for _, i := range picks {
			src.ReplayInto(dst, i)
		}
		if n := dst.Stats().Replayed; n != uint64(len(picks)) {
			t.Fatalf("stimulus: %d datagrams replayed, want %d", n, len(picks))
		}
		time.Sleep(time.Second)
		pb1, _ := carrierOf(b.p.Status(), idb)
		if d := pb1.Dropped - pb0.Dropped; d != want {
			t.Fatalf("B's carrier dropped %d frames and datagrams, want the %d of the %d replayed datagrams", d, want, len(picks))
		}
		if k1 := *b.p.Status().Packet; k1.DropLate != k0.DropLate || s.mode != rendr.ModeRace && k1.Duplicates != k0.Duplicates {
			t.Fatalf("replayed datagrams passed B's fseq window: before %+v, after %+v", k0, k1)
		}
		w.noViolation()
		if d := w.deaths(); len(d[0])+len(d[1]) != 0 {
			t.Fatalf("carriers died: dialer %+v, passive %+v", d[0], d[1])
		}
		untouchedPacket(t, "A", a)
		fa.halt(t)
		fb.halt(t)
		fa.integrity(t)
		fb.integrity(t)
		a.endPacket(t, fa)
		b.endPacket(t, fb)
		w.close()
	})
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
