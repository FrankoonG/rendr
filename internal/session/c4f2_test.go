package session

import (
	"bytes"
	"io"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Datagrams only a stream member can carry in a passive packet bond whose
// stream member was confirmed but not yet routed by the dialer's SCHED
// (C4-F2; L37, M2-D43, plan:147): they wait in txBig within MaxAge, and
// are dropped as too large only when no stream member exists.

// cfDgrams returns the DGRAM frames of fs.
func cfDgrams(fs []dpFrame) []dpFrame {
	var out []dpFrame
	for _, f := range fs {
		if f.typ == wire.TypeDgram {
			out = append(out, f)
		}
	}
	return out
}

// TestPacketBigHeldForSched_L37: on the passive, a stream member confirmed
// but not yet routed by a SCHED (pktMemberConfirmedLocked) makes the bond
// mixed at once: a datagram only it can carry goes straight to txBig and
// waits there (the datagram member neither places nor drops it, the member
// is not woken, a routing change meanwhile keeps it); the first one rings
// the actor to arm MaxAge, and the actor's ageing drops what waited longer
// than MaxAge as DropAge and returns the next expiry. Once the SCHED routes
// the member it places what is left, intact. A later SCHED that drops the
// member leaves no stream member: a big datagram is dropped as too large
// (L37).
func TestPacketBigHeldForSched_L37(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const maxAge = 50 * time.Millisecond
		s := dpSession(dpOpt{role: RolePassive, mode: ModeBond, maxPayload: wire.MaxPacketPayload, maxAge: maxAge})
		ld, _ := dpAddLane(s, 1, true, true)
		lst, pst := dpAddLane(s, 2, false, false)
		dpIdle(ld)
		queued := func() [2]int {
			return dpLocked(s, func(_ *stream, pk *packet) [2]int { return [2]int{pk.tx.n, pk.txBig.n} })
		}
		held := func() bool { return dpLocked(s, func(_ *stream, pk *packet) bool { return pk.mixed && pk.bigHeld }) }
		lj, _ := dpAddLane(s, 4, false, true) // a datagram JOIN member awaiting its SCHED
		wpLocked(s, func() bool { s.pktMemberConfirmedLocked(lj); return true })
		dpWrite(t, s, 1, 500)
		if held() {
			t.Fatal("held without a stream member (only a datagram member awaits its SCHED)")
		}
		wpLocked(s, func() bool { s.pktMemberConfirmedLocked(lst); return true })
		if !held() || !wpLocked(s, func() bool { return lst.awaitSched }) {
			t.Fatal("a confirmed member awaiting its SCHED does not make the bond mixed and held")
		}
		select {
		case <-s.mb.bell:
		default:
		}
		ws := pst.wakeCount()
		dpWrite(t, s, 2, 3000)
		if q := queued(); q != [2]int{1, 1} {
			t.Fatalf("queued tx %d txBig %d; want the big datagram in txBig at its WriteTo", q[0], q[1])
		}
		select {
		case <-s.mb.bell:
		default:
			t.Fatal("the first held datagram did not ring the actor (MaxAge unarmed)")
		}
		time.Sleep(maxAge / 2)
		dpWrite(t, s, 3, 3000)
		dpAddLane(s, 3, true, true) // a routing change meanwhile: another datagram member
		got := cfDgrams(dpFrames(dpFill(ld, time.Now())))
		if len(got) != 1 || len(got[0].body) != 500 || pst.wakeCount() != ws || queued() != [2]int{0, 2} {
			t.Fatalf("datagram member placed %v, stream member woken %d times, queued %v; want only the small one, no wake, 2 held", got, pst.wakeCount()-ws, queued())
		}
		time.Sleep(maxAge/2 + time.Millisecond)
		now := time.Now()
		next := wpLocked(s, func() time.Time { return s.pktAgeBigLocked(now) })
		c := dpCtr(s)
		if c.DropAge != 1 || c.DropTooLarge != 0 || next.IsZero() || next.Sub(now) > maxAge/2 {
			t.Fatalf("after MaxAge: counters %+v, next expiry in %v; want the first big DropAge, the next within MaxAge/2", c, next.Sub(now))
		}
		dpRoute(s, lst, true) // the SCHED lists it
		if held() || wpLocked(s, func() bool { return lst.awaitSched }) {
			t.Fatal("still held after the SCHED routed the member")
		}
		got = cfDgrams(dpFrames(dpFill(lst, time.Now())))
		if len(got) != 1 || dpID(got[0].body) != 3 || !bytes.Equal(got[0].body, dpPayload(3, 3000)) {
			t.Fatalf("the routed stream member placed %v, want datagram 3 intact", got)
		}
		dpRoute(s, lst, false) // a later SCHED drops it: no stream member is left
		if dpLocked(s, func(_ *stream, pk *packet) bool { return pk.mixed }) {
			t.Fatal("still mixed after the SCHED dropped the only stream member")
		}
		dpWrite(t, s, 4, 3000)
		dpFill(ld, time.Now())
		if c := dpCtr(s); c.DropTooLarge != 1 || c.Sent != 2 || c.DropAge != 1 || queued() != [2]int{0, 0} {
			t.Fatalf("counters %+v, queued %v; want datagram 4 dropped as too large", c, queued())
		}
		dpEnd(s, io.EOF)
	})
}

// TestPacketBigHeldAgesBeforeFin_L37: Close while a datagram waits in a
// held txBig: the FIN waits for it (the final seq follows every placed
// datagram, M2-D34), and when the actor's ageing drops it at MaxAge the
// datagram member is woken and places the FIN with the final seq after
// the one datagram sent.
func TestPacketBigHeldAgesBeforeFin_L37(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const maxAge = 50 * time.Millisecond
		s := dpSession(dpOpt{role: RolePassive, mode: ModeBond, maxPayload: wire.MaxPacketPayload, maxAge: maxAge})
		ld, pd := dpAddLane(s, 1, true, true)
		lst, _ := dpAddLane(s, 2, false, false)
		dpIdle(ld)
		wpLocked(s, func() bool { s.pktMemberConfirmedLocked(lst); return true })
		dpWrite(t, s, 1, 500)
		dpWrite(t, s, 2, 3000)
		dpClose(s)
		fs := dpFrames(dpFill(ld, time.Now()))
		if len(cfDgrams(fs)) != 1 || dpCount(fs, wire.TypeFin) != 0 {
			t.Fatalf("datagram member placed %v; want the small datagram and no FIN while txBig holds one", fs)
		}
		dpIdle(ld)
		wd := pd.wakeCount()
		time.Sleep(maxAge + time.Millisecond)
		now := time.Now()
		if next := wpLocked(s, func() time.Time { return s.pktAgeBigLocked(now) }); !next.IsZero() {
			t.Fatalf("next expiry %v with nothing held", next)
		}
		if c := dpCtr(s); c.DropAge != 1 || c.Sent != 1 || c.DropTooLarge != 0 {
			t.Fatalf("counters %+v; want the big datagram DropAge", c)
		}
		if pd.wakeCount() == wd {
			t.Fatal("the datagram member was not woken for the FIN")
		}
		fs = dpFrames(dpFill(ld, time.Now()))
		if dpCount(fs, wire.TypeFin) != 1 {
			t.Fatalf("datagram member placed %v; want the FIN", fs)
		}
		for _, f := range fs {
			if f.typ == wire.TypeFin && f.fin != 1 {
				t.Fatalf("FIN final seq %d, want 1", f.fin)
			}
		}
		dpEnd(s, io.EOF)
	})
}
