package session

import (
	"io"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// dpReturn hands every DGRAM of b back to l's endpoint as a dying carrier's
// writer does (carrier.DgramReturner: a reference of its own on each
// chunk), then releases the batch's references.
func dpReturn(l *lane, b *carrier.Batch) {
	for i := range b.Len() {
		if f := b.Frame(i); f.Header.Type == wire.TypeDgram {
			f.Chunk.Ref()
			(*plane)(l).Unsent(nil, f.Seq, f.Body, f.Chunk)
		}
	}
	b.ReleaseRefs()
}

// TestPacketUnsentReplaced_L39 (M5 pktloss; L39, M2-D35): the DGRAMs a
// dying carrier hands back unwritten. A returned DGRAM leaves Sent and
// wakes a live data lane although nothing new is queued; that lane places
// it again with its seq, before the datagrams queued behind it, and Sent
// counts it again. One not placed again within MaxAge is DropAge at the
// next Fill, or DropNoPath at the actor's ageing while no data lane exists
// (whose deadline it sets); at the end it is DropQueue, also when it comes
// back after the end; beyond maxRedo waiting it is DropQueue at once. The
// send-side identity holds throughout and every chunk is released at the
// end (the budget returns to 0). Mutants: no Sent decrement; no wake; no
// ageing at Fill; no no-path ageing; no release at the end; no bound.
func TestPacketUnsentReplaced_L39(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const maxAge = 100 * time.Millisecond
		bud := carrier.NewBudget(1 << 30)
		s := dpSession(dpOpt{mode: ModeBond, maxAge: maxAge, budget: bud})
		l1, _ := dpAddLane(s, 1, true, true)
		l2, p2 := dpAddLane(s, 2, true, true)
		dpIdle(l1)
		dpIdle(l2)
		writes := uint64(0)
		write := func(id uint64) {
			dpWrite(t, s, id, 100)
			writes++
		}
		identity := func(when string) PacketCounters {
			t.Helper()
			c := dpCtr(s)
			redo := dpLocked(s, func(_ *stream, pk *packet) uint64 { return uint64(pk.redoN() + pk.tx.n) })
			if c.Sent+c.DropAge+c.DropNoPath+c.DropQueue+c.DropTooLarge+redo != writes {
				t.Fatalf("%s: %+v with %d waiting, want the %d written", when, c, redo, writes)
			}
			return c
		}

		// Placed on l1, whose carrier dies (its death step first, as when
		// the actor runs before the writer returns the round): returned,
		// l2 is woken with nothing new queued and places it first, seq
		// unchanged.
		write(1)
		b := dpFill(l1, time.Now())
		if fs := dpFrames(b); dpCount(fs, wire.TypeDgram) != 1 || dpCtr(s).Sent != 1 {
			t.Fatalf("first placement: %v, %+v", fs, dpCtr(s))
		}
		dpKill(s, l1)
		dpIdle(l2) // the wakes of the write and of the death ran their rounds: l2 is idle
		w0 := p2.wakeCount()
		dpReturn(l1, b)
		if c := identity("returned"); c.Sent != 0 || p2.wakeCount() == w0 {
			t.Fatalf("returned: %+v, l2 woken %v: want Sent 0 and the idle member woken", c, p2.wakeCount() != w0)
		}
		write(2)
		fs := dpFrames(dpFill(l2, time.Now()))
		if dpCount(fs, wire.TypeDgram) != 2 {
			t.Fatalf("placed again: %v", fs)
		}
		var got []dpFrame
		for _, f := range fs {
			if f.typ == wire.TypeDgram {
				got = append(got, f)
			}
		}
		if got[0].seq != 0 || dpID(got[0].body) != 1 || got[1].seq != 1 || dpID(got[1].body) != 2 {
			t.Fatalf("placed again: %v, want seq 0 (id 1) then seq 1 (id 2)", got)
		}
		if c := identity("placed again"); c.Sent != 2 {
			t.Fatalf("placed again: %+v, want Sent 2", c)
		}
		dpIdle(l2)

		// Returned and not placed within MaxAge: DropAge at the next Fill.
		write(3)
		dpReturn(l2, dpFill(l2, time.Now()))
		time.Sleep(maxAge + 50*time.Millisecond)
		if fs := dpFrames(dpFill(l2, time.Now())); dpCount(fs, wire.TypeDgram) != 0 {
			t.Fatalf("an aged returned datagram was placed: %v", fs)
		}
		if c := identity("aged at Fill"); c.DropAge != 1 || c.Sent != 2 {
			t.Fatalf("aged at Fill: %+v, want DropAge 1", c)
		}
		dpIdle(l2)

		// No data lane: the actor's ageing counts it DropNoPath and arms
		// its deadline.
		write(4)
		b = dpFill(l2, time.Now())
		dpRoute(s, l2, false)
		t0 := time.Now()
		dpReturn(l2, b)
		age := func() time.Time {
			s.mu.Lock()
			defer s.mu.Unlock()
			return s.pktAgeLocked(time.Now())
		}
		if next, want := age(), t0.Add(maxAge+1); !next.Equal(want) {
			t.Fatalf("pktAgeLocked returned %v, want the returned datagram's age-out %v", next.Sub(t0), want.Sub(t0))
		}
		time.Sleep(maxAge + 1)
		if next := age(); !next.IsZero() {
			t.Fatalf("pktAgeLocked returned %v with nothing waiting", next)
		}
		if c := identity("no path"); c.DropNoPath != 1 {
			t.Fatalf("no path: %+v, want DropNoPath 1", c)
		}

		// Bounded: beyond maxRedo waiting, DropQueue at once.
		dpRoute(s, l2, true)
		dpIdle(l2)
		var bs []*carrier.Batch
		for n := 0; n <= maxRedo; {
			for range carrier.MaxBatchFrames {
				write(100 + writes)
			}
			b := dpFill(l2, time.Now())
			n += dpCount(dpFrames(b), wire.TypeDgram)
			bs = append(bs, b)
			l2.port.(*dpPort).b = carrier.NewBatch(0) // keep b: the next Fill gets a fresh batch
		}
		dpRoute(s, l2, false)
		for _, b := range bs {
			dpReturn(l2, b)
		}
		c := identity("bounded")
		if waiting := dpLocked(s, func(_ *stream, pk *packet) int { return pk.redoN() }); waiting != maxRedo || c.DropQueue == 0 {
			t.Fatalf("bounded: %d waiting, %+v: want %d and the rest DropQueue", waiting, c, maxRedo)
		}

		// The end: every waiting one DropQueue; one returned after the end
		// too; every chunk released.
		dpEnd(s, io.EOF)
		b = carrier.NewBatch(0)
		b.Reset(time.Now())
		buf := carrier.NewBufPool().Get(carrier.ChunkSize, bud)
		dropq := dpCtr(s).DropQueue
		buf.Ref()
		(*plane)(l2).Unsent(nil, 1<<20, buf.B[:100], buf)
		if c := dpCtr(s); c.DropQueue != dropq+1 {
			t.Fatalf("returned after the end: %+v, want DropQueue +1", c)
		}
		buf.Release()
		identity("ended")
		if used := bud.Used(); used != 0 {
			t.Fatalf("budget %d after the end, want every chunk released", used)
		}
	})
}

// TestPacketRaceUnsentReplaced_L39: a race session's returned DGRAM (M5
// pktloss; M3-D32). While another placement of the datagram may have left
// (the other member placed its copy) the returned copy is not placed again
// and Race.Copies loses it; when it was the only one and its descriptor
// left the ring, it waits, and a member that becomes a data lane later —
// idle, with nothing new queued — is woken for it and places it once, seq
// unchanged. Mutants: a covered copy placed again; a race wake that
// ignores the waiting DGRAM.
func TestPacketRaceUnsentReplaced_L39(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := dpSession(dpOpt{mode: ModeRace})
		l1, _ := dpAddLane(s, 1, true, true)
		l2, _ := dpAddLane(s, 2, true, true)
		l1.c, l2.c = &carrier.Conn{}, &carrier.Conn{} // bare identities: no death record
		dpIdle(l1)
		dpIdle(l2)
		copies := func() uint64 { return dpLocked(s, func(_ *stream, pk *packet) uint64 { return pk.copies }) }
		waiting := func() int { return dpLocked(s, func(_ *stream, pk *packet) int { return pk.redoN() }) }

		// Covered: both members placed seq 0; l1's copy comes back.
		dpWrite(t, s, 1, 100)
		b1 := dpFill(l1, time.Now())
		dpIdle(l2)
		if c := dpCtr(s); c.Sent != 1 || copies() != 1 {
			t.Fatalf("placed on both: %+v, copies %d", c, copies())
		}
		dpReturn(l1, b1)
		if c := dpCtr(s); c.Sent != 1 || copies() != 0 || waiting() != 0 {
			t.Fatalf("covered copy returned: %+v, copies %d, %d waiting: want it dropped from the copies", c, copies(), waiting())
		}

		// Not covered: l2 is the only member; its copy comes back and waits
		// for a member that becomes a data lane later.
		dpKill(s, l1)
		dpIdle(l2)
		dpWrite(t, s, 2, 100)
		b2 := dpFill(l2, time.Now())
		dpKill(s, l2)
		dpReturn(l2, b2)
		if c := dpCtr(s); c.Sent != 1 || waiting() != 1 {
			t.Fatalf("returned alone: %+v, %d waiting", c, waiting())
		}
		l3, p3 := dpAddLane(s, 3, false, true)
		l3.c = &carrier.Conn{}
		dpIdle(l3)
		w0 := p3.wakeCount()
		dpRoute(s, l3, true)
		if p3.wakeCount() == w0 {
			t.Fatal("the new data member was not woken for the returned DGRAM")
		}
		fs := dpFrames(dpFill(l3, time.Now()))
		if dpCount(fs, wire.TypeDgram) != 1 || fs[len(fs)-1].seq != 1 || dpID(fs[len(fs)-1].body) != 2 {
			t.Fatalf("placed again: %v, want seq 1 (id 2) once", fs)
		}
		if c := dpCtr(s); c.Sent != 2 || waiting() != 0 {
			t.Fatalf("placed again: %+v, %d waiting", c, waiting())
		}
		dpEnd(s, io.EOF)
	})
}
