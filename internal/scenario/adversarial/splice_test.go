package adversarial

import (
	"context"
	"fmt"
	"net"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Splices: the bytes of one carrier forwarded into another (a relay that
// mixes up its connections). The receiving end of the spliced carrier
// kills it at the first foreign frame — its fseq continues another
// carrier's sequence, or a frame cut in the middle fails its CRC — before
// any endpoint sees the other carrier's payload; the sessions on both
// carriers keep every byte.

// twoSessions opens the sessions X (xs) and Y (ys) — s.sessions each, on
// a Peer each (dedicated: every session on carriers of its own; MUX: X's
// on one trunk, Y's on another) — and starts n bytes dialer → passive on
// every one; it returns once X's and Y's first sessions delivered a
// quarter. The rows splice a carrier of xs[0] into one of ys[0].
func twoSessions(t *testing.T, w *world, n int64) (xs, ys []*pair, fxs, fys []*sflow) {
	return twoSessionsN(t, w, n, w.s.sessions, w.s.sessions)
}

// twoSessionsN is twoSessions with nx sessions in X and ny in Y.
func twoSessionsN(t *testing.T, w *world, n int64, nx, ny int) (xs, ys []*pair, fxs, fys []*sflow) {
	px, py := w.streamPeer(), w.streamPeer()
	for range nx {
		xs = append(xs, w.open(px))
	}
	for range ny {
		ys = append(ys, w.open(py))
	}
	for i, x := range xs {
		fxs = append(fxs, startFlow(x.d, x.p, n, 4310+uint64(2*i)))
	}
	for i, y := range ys {
		fys = append(fys, startFlow(y.d, y.p, n, 4311+uint64(2*i)))
	}
	fxs[0].reached(t, n/4, "a quarter of X")
	fys[0].reached(t, n/4, "a quarter of Y")
	return xs, ys, fxs, fys
}

// spliceEnd waits for every transfer of X and Y, requires X's sessions
// untouched (X only lent its frames) and Y's first session's one Death
// migration (and its neighbours', migrated) after Y's carrier k died, and
// ends every session cleanly.
func spliceEnd(t *testing.T, w *world, xs, ys []*pair, fxs, fys []*sflow, k kill) {
	t.Helper()
	for i, f := range fxs {
		f.wait(t, 2*time.Minute, fmt.Sprintf("X's session %d", i))
	}
	for i, f := range fys {
		f.wait(t, 2*time.Minute, fmt.Sprintf("Y's session %d, its carrier fed X's frames", i))
	}
	for i, x := range xs {
		untouched(t, fmt.Sprintf("X's session %d", i), x)
	}
	migrated(t, w.s, ys, k, 1, 0)
	for _, x := range slices.Concat(xs, ys) {
		x.endClean(t)
	}
	w.close()
}

// untouched requires that session x lost no carrier and counted no
// migration on either end.
func untouched(t testing.TB, what string, x *pair) {
	t.Helper()
	for _, st := range []rendr.SessionStatus{x.d.Status(), x.p.Status()} {
		if d := deadOf(st); len(d) != 0 || st.Migrations != (rendr.MigrationCounts{}) {
			t.Fatalf("%s (%v) was touched: dead %+v, migrations %+v", what, st.Role, d, st.Migrations)
		}
	}
}

// spliced counts the Splice operations that started on a tamper.
func spliced(tm *rendrtest.Tamper) int { return tm.Stats().Spliced }

// TestAdvSpliceTwoSessions_L41_L43: the dialer → passive bytes of session
// X's carrier are spliced into session Y's carrier (dedicated pair; the
// MUX half splices two trunks): "boundary" from Y's next frame boundary
// on, "midframe" 15 bytes into one of Y's frames (Y's tamper holds Up at a
// frame boundary, so the cut point is known: inside the next frame's
// header or payload, whatever its type). Y's passive kills Y's carrier at
// the first spliced frame — fseq at a boundary (X's frames continue X's
// sequence), CRC or header check in the middle of a frame — and Y's
// verifier proves that none of X's payload reached Y's application; X's
// carrier lives on untouched (it only lent its frames), Y redials or
// carries on with its other member, and both streams arrive intact.
func TestAdvSpliceTwoSessions_L41_L43(t *testing.T) {
	for _, mid := range []bool{false, true} {
		name := "boundary"
		if mid {
			name = "midframe"
		}
		t.Run(name, func(t *testing.T) {
			eachSetup(t, func(t *testing.T, s setup) { spliceRow(t, s, mid, s.sessions, s.sessions) })
		})
	}
}

// TestAdvMuxSpliceCrossTrunk_L43: the dialer → passive bytes of MUX trunk
// T1 — four sessions, handles 1 to 4 — are spliced into trunk T2 — three
// sessions of another Peer, handles 1 to 3 — on the same link, at T2's
// next frame boundary and 15 bytes into one of its frames (selector, bond
// and race sessions). T2's passive kills T2 at the first spliced frame —
// fseq at a boundary (T1's frames continue T1's sequence), whichever
// check meets the cut frame in the middle — before any view of T2 sees
// T1's payload: T1's frames carry handles T2's views have (1 to 3) and one
// T2 never opened (4), and T2's three verifiers read their own streams
// only. T1's sessions are untouched, T2's migrate (migrated), and every
// stream arrives intact.
func TestAdvMuxSpliceCrossTrunk_L43(t *testing.T) {
	for _, mid := range []bool{false, true} {
		name := "boundary"
		if mid {
			name = "midframe"
		}
		t.Run(name, func(t *testing.T) {
			for _, s := range muxSetups() {
				t.Run(s.name, func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) { spliceRow(t, s, mid, 4, 3) })
				})
			}
		})
	}
}

// spliceRow splices the dialer → passive frames of X's carrier (nx
// sessions) into Y's (ny sessions): TestAdvSpliceTwoSessions_L41_L43 and
// TestAdvMuxSpliceCrossTrunk_L43.
func spliceRow(t *testing.T, s setup, mid bool, nx, ny int) {
	n := rowBytes()
	w := newWorld(t, s, worldOpts{})
	xs, ys, fxs, fys := twoSessionsN(t, w, n, nx, ny)
	x, y := xs[0], ys[0]
	tx, ty := w.tamperOf(target(t, s, x.d.Status())), w.tamperOf(target(t, s, y.d.Status()))
	if s.mux {
		// The two trunks carry the views the row names: X's handles 1 to
		// nx, Y's 1 to ny.
		for _, c := range []struct {
			name string
			tm   *rendrtest.Tamper
			k    int
		}{{"X", tx, nx}, {"Y", ty, ny}} {
			hs := map[uint32]bool{}
			for _, r := range c.tm.Log(rendrtest.Up) {
				if r.Handle != 0 {
					hs[r.Handle] = true
				}
			}
			if len(hs) != c.k || !hs[1] || !hs[uint32(c.k)] {
				t.Fatalf("%s's trunk carried the handles %v, want 1 to %d", c.name, hs, c.k)
			}
		}
	}
	want := []string{"fseq"}
	if mid {
		ty.Hold(rendrtest.Up)
		waitFor(t, 5*time.Second, "Y's Up held at a frame boundary", func() bool { return ty.Stats().Held == 1 })
		log := ty.Log(rendrtest.Up)
		last := log[len(log)-1]
		ty.Splice(rendrtest.Up, tx, last.Off+17+int64(last.Len)+15)
		ty.Release(rendrtest.Up)
		want = nil // the cut frame fails whichever check meets X's bytes first
	} else {
		ty.Splice(rendrtest.Up, tx, 0)
	}
	waitFor(t, 5*time.Second, "X's frames forwarded into Y's carrier (stimulus)", func() bool { return ty.Stats().SplicedBytes > 0 })
	hit := w.hit(t, spliced)
	if hit.tm != ty {
		t.Fatalf("the splice started on carrier %d, not Y's", hit.id)
	}
	violated(t, "Y's spliced carrier", endDead(t, "Y's passive", y.p.Status, hit.id), want...)
	var own, foreign int
	for _, r := range ty.Log(rendrtest.Up) {
		if r.Spliced {
			foreign++
		} else {
			own++
		}
	}
	if foreign == 0 || own == 0 {
		t.Fatalf("stimulus: Y's carrier forwarded %d own and %d of X's frames", own, foreign)
	}
	spliceEnd(t, w, xs, ys, fxs, fys, kill{id: hit.id, cause: rendr.CauseProtocolViolation})
}

// TestAdvRelaySplice_L43_L69: a relay in the path of a carrier mixes up its
// connections mid-stream (L69).
//
//   - "switch": the relay reconnects its upstream: it dials a fresh
//     connection to the passive and forwards the dialer's remaining bytes
//     (frames in the middle of the carrier's stream) into it. The fresh
//     connection fails its handshake — its first bytes are not "RND2", so
//     the passive's handshake slot closes it without answering, before any
//     session state (L48) —; the carrier the relay spliced dies on both
//     ends (the old upstream was closed, the dialer's relay connection
//     ends), the session continues on another or a redialled carrier, and
//     the stream arrives intact.
//   - "reverse": the dialer is fed another carrier's bytes: session X's
//     passive → dialer frames are spliced into session Y's carrier; Y's
//     dialer kills it (protocol_violation "fseq") and X is untouched.
func TestAdvRelaySplice_L43_L69(t *testing.T) {
	t.Run("switch", func(t *testing.T) {
		eachSetup(t, func(t *testing.T, s setup) {
			n := rowBytes()
			w := newWorld(t, s, worldOpts{})
			xs := w.openN(w.streamPeer())
			x := xs[0]
			var fs []*sflow
			for i, y := range xs {
				fs = append(fs, startFlow(y.d, y.p, n, 4320+uint64(i)))
			}
			fs[0].reached(t, n/4, "a quarter of the transfer")
			id := target(t, s, x.d.Status())
			tm := w.tamperOf(id)
			var lname string
			for _, c := range liveOf(x.d.Status()) {
				if c.ID == id {
					lname = c.Name
				}
			}
			l := w.link(lname)
			fresh := l.NextSeq()
			before := w.p.Status()
			tm.SwitchUpstream(func() (net.Conn, error) { return l.Dial(context.Background()) })
			if st := tm.Stats(); st.Switched != 1 {
				t.Fatalf("stimulus: %+v, want one upstream switch", st)
			}
			for i, get := range []func() rendr.SessionStatus{x.d.Status, x.p.Status} {
				if c := endDead(t, side(i), get, id); c.DeathCause != rendr.CauseTransportError {
					t.Fatalf("%s: the spliced carrier died of %v %q, want transport_error", side(i), c.DeathCause, c.DeathDetail)
				}
			}
			// The fresh connection: closed by the passive, which never
			// answered on it and kept no state for it.
			waitFor(t, 10*time.Second, "the passive closing the fresh connection", func() bool {
				cs := l.Carriers()
				return len(cs) > fresh && cs[fresh].Closed
			})
			if c := l.Carriers()[fresh]; c.Session || c.Down != 0 || c.Up == 0 {
				t.Fatalf("the fresh connection %+v: want the dialer's bytes up, nothing down, no session frame first", c)
			}
			waitFor(t, 10*time.Second, "no handshake left on the passive", func() bool { return w.p.Status().Handshakes == 0 })
			// The sessions that lost the spliced carrier may be orphaned
			// until their redial attaches (every session of a MUX trunk):
			// the passive's sessions return to what they were, and nothing
			// waits in its backlog.
			waitFor(t, 10*time.Second, "the passive's sessions as before the switch", func() bool { return w.p.Status().Sessions == before.Sessions })
			if st := w.p.Status(); st.AcceptBacklog != [2]int{} {
				t.Fatalf("the passive kept state from the fresh connection: sessions %+v (before %+v), backlog %v",
					st.Sessions, before.Sessions, st.AcceptBacklog)
			}
			for i, f := range fs {
				f.wait(t, 2*time.Minute, fmt.Sprintf("session %d's transfer across the relay's switch", i))
			}
			w.noViolation()
			migrated(t, s, xs, kill{id: id, cause: rendr.CauseTransportError}, 1, 0)
			for _, y := range xs {
				y.endClean(t)
			}
			w.close()
		})
	})
	t.Run("reverse", func(t *testing.T) {
		eachSetup(t, func(t *testing.T, s setup) {
			n := rowBytes()
			w := newWorld(t, s, worldOpts{})
			xs, ys, fxs, fys := twoSessions(t, w, n)
			x, y := xs[0], ys[0]
			tx, ty := w.tamperOf(target(t, s, x.d.Status())), w.tamperOf(target(t, s, y.d.Status()))
			ty.Splice(rendrtest.Down, tx, 0)
			waitFor(t, 5*time.Second, "X's frames forwarded into Y's carrier (stimulus)", func() bool { return ty.Stats().SplicedBytes > 0 })
			hit := w.hit(t, spliced)
			if hit.tm != ty {
				t.Fatalf("the splice started on carrier %d, not Y's", hit.id)
			}
			violated(t, "Y's spliced carrier", endDead(t, "Y's dialer", y.d.Status, hit.id), "fseq")
			spliceEnd(t, w, xs, ys, fxs, fys, kill{id: hit.id, cause: rendr.CauseProtocolViolation, dialer: true})
		})
	})
}
