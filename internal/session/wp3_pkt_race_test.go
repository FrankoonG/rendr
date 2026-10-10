package session

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// WP3 (M3 design §A6.4, §A6.8): the packet race — per-lane cursors over the
// one tx ring, the seq fixed at the first placement, the head that waits for
// every live lane, the MaxAge and budget skips — and KL-13's headroom of a
// stream member in a mixed packet bond. Packet harness (fake ports, "dp"
// helpers); race membership is set up as bond's.

// rcPktRace makes every lane of s a race data member and recomputes the
// routing summary (as the actor's routing change does).
func rcPktRace(s *Session) {
	rcRaceLanes(s)
	s.mu.Lock()
	s.pktRecomputeLocked()
	s.mu.Unlock()
}

// rcPktSender is a race dialer with one lane per entry of dgram.
func rcPktSender(o dpOpt, dgram ...bool) (*Session, []*lane, []*dpPort) {
	o.mode = ModeRace
	s := dpSession(o)
	var ls []*lane
	var ps []*dpPort
	for i, dg := range dgram {
		l, p := dpAddLane(s, uint32(i+1), true, dg)
		ls, ps = append(ls, l), append(ps, p)
	}
	rcPktRace(s)
	return s, ls, ps
}

// rcDgrams returns the DGRAM frames of b as seq → body length.
func rcDgrams(b *carrier.Batch) (seqs []uint64, lens []int) {
	for _, f := range dpFrames(b) {
		if f.typ == wire.TypeDgram {
			seqs, lens = append(seqs, f.seq), append(lens, len(f.body))
		}
	}
	return seqs, lens
}

// rcTx returns (pos, n) of s's tx ring.
func rcTx(s *Session) (uint64, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pk.tx.pos, s.pk.tx.n
}

// TestRacePacketCursor_L39: every member places every datagram from its own
// cursor; the seq is fixed at the first placement and the copies reuse it;
// the tx head waits until every live member passed a datagram (and moves
// when the member holding it dies); the receiver delivers each datagram
// once and counts the copies as Duplicates; each member places the FIN
// once with the same final seq.
func TestRacePacketCursor_L39(t *testing.T) {
	p := dpNewPair(dpOpt{mode: ModeRace}, dpOpt{mode: ModeRace}, true, true)
	rcPktRace(p.a.s)
	rcPktRace(p.b.s)
	a := p.a.s
	for i := range 10 {
		dpWrite(t, a, uint64(i), 200)
	}
	ba := dpFill(p.a.ls[0], time.Now())
	seqA, _ := rcDgrams(ba)
	if err := dpDeliver(ba, p.b.ls[0], 0, nil); err != nil {
		t.Fatal(err)
	}
	ba.ReleaseRefs()
	if len(seqA) != 10 || seqA[0] != 0 || seqA[9] != 9 {
		t.Fatalf("lane 0 placed seqs %v, want 0…9", seqA)
	}
	if pos, n := rcTx(a); pos != 0 || n != 10 {
		t.Fatalf("tx head at %d with %d queued, want 0 and 10: lane 1 has not placed them", pos, n)
	}
	bb := dpFill(p.a.ls[1], time.Now())
	seqB, _ := rcDgrams(bb)
	if err := dpDeliver(bb, p.b.ls[1], 1, nil); err != nil {
		t.Fatal(err)
	}
	bb.ReleaseRefs()
	for i := range seqA {
		if i >= len(seqB) || seqB[i] != seqA[i] {
			t.Fatalf("lane 1 placed seqs %v, want the copies' seqs %v", seqB, seqA)
		}
	}
	if pos, n := rcTx(a); pos != 10 || n != 0 {
		t.Fatalf("tx head at %d with %d queued after both lanes, want 10 and 0", pos, n)
	}
	if c := dpCtr(a); c.Sent != 10 || a.Status().Race.Copies != 10 {
		t.Fatalf("Sent %d Copies %d, want 10 and 10", c.Sent, a.Status().Race.Copies)
	}
	got, _ := dpReadAll(t, p.b.s)
	if len(got) != 10 {
		t.Fatalf("the application read %d datagrams, want each of 10 once", len(got))
	}
	if c := dpCtr(p.b.s); c.Received != 10 || c.Duplicates != 10 {
		t.Fatalf("receiver Received %d Duplicates %d, want 10 and 10", c.Received, c.Duplicates)
	}

	// The head waits for a write-blocked member and moves at its death.
	for i := range 5 {
		dpWrite(t, a, uint64(10+i), 200)
	}
	dpFill(p.a.ls[0], time.Now()).ReleaseRefs()
	if _, n := rcTx(a); n != 5 {
		t.Fatalf("%d queued, want 5 waiting for lane 1", n)
	}
	dpKill(a, p.a.ls[1])
	if pos, n := rcTx(a); pos != 15 || n != 0 {
		t.Fatalf("after lane 1's death the head is at %d with %d queued, want 15 and 0", pos, n)
	}
	if c := dpCtr(a); c.Sent != 15 || c.DropAge+c.DropQueue+c.DropTooLarge+c.DropNoPath != 0 {
		t.Fatalf("counters %+v: placed datagrams must not count as drops", c)
	}

	// Close: the FIN once per member, at the final seq.
	dpClose(a)
	fs := dpFrames(dpFill(p.a.ls[0], time.Now()))
	var fins []uint64
	for _, f := range fs {
		if f.typ == wire.TypeFin {
			fins = append(fins, f.fin)
		}
	}
	if len(fins) != 1 || fins[0] != 15 {
		t.Fatalf("FINs %v, want one at final seq 15", fins)
	}
	if fs := dpFrames(dpFill(p.a.ls[0], time.Now())); len(fs) != 0 {
		t.Fatalf("the member placed %v again", fs)
	}
	dpEnd(a, errClosed)
	dpEnd(p.b.s, errClosed)
}

// TestRacePacketFinCoversSkipped: a member whose cursor reached the end
// does not place the FIN while a queued datagram it skipped as too large
// still waits for another member (its seq would follow the FIN's final);
// once that member placed it, the FIN covers it.
func TestRacePacketFinCoversSkipped(t *testing.T) {
	a, ls, _ := rcPktSender(dpOpt{}, true, true)
	ls[0].port.(*dpPort).set(func(f *dpPort) { f.budget = 600 })
	dpWrite(t, a, 1, 1000)
	dpClose(a)
	b0 := dpFill(ls[0], time.Now())
	for _, f := range dpFrames(b0) {
		if f.typ == wire.TypeDgram || f.typ == wire.TypeFin {
			t.Fatalf("the small member placed %v before the big datagram had a seq", f)
		}
	}
	b0.ReleaseRefs()
	var b1 []dpFrame
	for _, f := range dpFrames(dpFill(ls[1], time.Now())) {
		if f.typ != wire.TypePack { // every race member carries a PACK copy (PA-33 as amended)
			b1 = append(b1, f)
		}
	}
	if len(b1) != 2 || b1[0].typ != wire.TypeDgram || b1[0].seq != 0 || b1[1].typ != wire.TypeFin || b1[1].fin != 1 {
		t.Fatalf("the big member placed %v, want DGRAM(0) then FIN(1)", b1)
	}
	if fs := dpFrames(dpFill(ls[0], time.Now())); len(fs) != 1 || fs[0].typ != wire.TypeFin || fs[0].fin != 1 {
		t.Fatalf("the small member placed %v, want FIN(1)", fs)
	}
	dpEnd(a, errClosed)

	// An aged datagram the small member skipped never gets a seq: a
	// control pass (quota 0, no head step before it) places the FIN once
	// it is older than MaxAge, not before.
	a, ls, _ = rcPktSender(dpOpt{maxAge: 100 * time.Millisecond}, true, true)
	ls[0].port.(*dpPort).set(func(f *dpPort) { f.budget = 600 })
	dpWrite(t, a, 1, 1000)
	dpClose(a)
	now := time.Now()
	dpFill(ls[0], now).ReleaseRefs() // its cursor passes the big datagram
	ctl := func(at time.Time) []dpFrame {
		b := carrier.NewBatch(0)
		b.Reset(at)
		b.SetDatagram(600, wire.RelWindow)
		b.SetQuota(0)
		(*plane)(ls[0]).Fill(nil, b)
		defer b.ReleaseRefs()
		return dpFrames(b)
	}
	if fs := ctl(now.Add(50 * time.Millisecond)); len(fs) != 0 {
		t.Fatalf("a control pass before MaxAge placed %v, want nothing (the big datagram may still take a seq)", fs)
	}
	if fs := ctl(now.Add(time.Second)); len(fs) != 1 || fs[0].typ != wire.TypeFin || fs[0].fin != 0 {
		t.Fatalf("a control pass after MaxAge placed %v, want FIN(0)", fs)
	}
	dpEnd(a, errClosed)
}

// TestRacePacketSkipStale_L40: a member never places a copy older than
// MaxAge: a slow member that comes back after MaxAge skips what the fast
// one placed (not counted as a drop: it was sent) and resumes with fresh
// datagrams; a datagram no member placed before MaxAge counts DropAge once.
func TestRacePacketSkipStale_L40(t *testing.T) {
	a, ls, _ := rcPktSender(dpOpt{maxAge: 100 * time.Millisecond}, true, true)
	for i := range 5 {
		dpWrite(t, a, uint64(i), 300)
	}
	now := time.Now()
	dpFill(ls[0], now).ReleaseRefs()
	if seqs, _ := rcDgrams(dpFill(ls[1], now.Add(200*time.Millisecond))); len(seqs) != 0 {
		t.Fatalf("the slow member placed stale copies %v", seqs)
	}
	if _, n := rcTx(a); n != 0 {
		t.Fatalf("%d stale datagrams still queued", n)
	}
	if c := dpCtr(a); c.Sent != 5 || c.DropAge != 0 {
		t.Fatalf("Sent %d DropAge %d, want 5 and 0 (placed by the fast member)", c.Sent, c.DropAge)
	}
	dpWrite(t, a, 5, 300)
	if seqs, _ := rcDgrams(dpFill(ls[1], time.Now())); len(seqs) != 1 || seqs[0] != 5 {
		t.Fatalf("the slow member placed %v, want the fresh datagram's first placement (seq 5)", seqs)
	}
	// Never placed before MaxAge: one DropAge.
	dpWrite(t, a, 6, 300)
	dpFill(ls[0], time.Now().Add(time.Second)).ReleaseRefs()
	dpFill(ls[1], time.Now().Add(time.Second)).ReleaseRefs()
	if c := dpCtr(a); c.DropAge != 1 || c.Sent != 6 {
		t.Fatalf("DropAge %d Sent %d, want 1 and 6", c.DropAge, c.Sent)
	}
	dpEnd(a, errClosed)
}

// TestRacePacketBigFilter_L37: a datagram member skips a datagram above its
// budget and places what follows (its own cursor); a member that can carry
// it places it; it counts DropTooLarge only when no live member could carry
// it (every live member passed it unplaced).
func TestRacePacketBigFilter_L37(t *testing.T) {
	a, ls, _ := rcPktSender(dpOpt{}, true, true)
	ls[0].port.(*dpPort).set(func(f *dpPort) { f.budget = 600 }) // DgramMax 575
	for i, n := range []int{500, 1000, 500} {
		dpWrite(t, a, uint64(i), n)
	}
	_, lens := rcDgrams(dpFill(ls[0], time.Now()))
	if len(lens) != 2 || lens[0] != 500 || lens[1] != 500 {
		t.Fatalf("the small member placed %v, want 500 and 500 (the 1000-byte one skipped)", lens)
	}
	seqs, lens := rcDgrams(dpFill(ls[1], time.Now()))
	if len(lens) != 3 || lens[1] != 1000 || seqs[0] != 0 || seqs[1] != 2 || seqs[2] != 1 {
		t.Fatalf("the big member placed seqs %v lens %v, want 0, 2 (first placement), 1", seqs, lens)
	}
	if c := dpCtr(a); c.Sent != 3 || c.DropTooLarge != 0 {
		t.Fatalf("Sent %d DropTooLarge %d", c.Sent, c.DropTooLarge)
	}
	dpKill(a, ls[1])
	dpWrite(t, a, 3, 1000)
	dpWrite(t, a, 4, 300)
	if _, lens := rcDgrams(dpFill(ls[0], time.Now())); len(lens) != 1 || lens[0] != 300 {
		t.Fatalf("the small member placed %v, want the 300-byte one", lens)
	}
	if c := dpCtr(a); c.DropTooLarge != 1 || c.Sent != 4 {
		t.Fatalf("DropTooLarge %d Sent %d, want 1 and 4", c.DropTooLarge, c.Sent)
	}
	if _, n := rcTx(a); n != 0 {
		t.Fatalf("%d datagrams still queued", n)
	}
	dpEnd(a, errClosed)
}

// TestPacketStreamLaneHeadroom_KL13 (M3-D52, R1-28): in a mixed packet bond
// the two lanes' Fill calls run in a fixed order at the stream link's
// saturation — the datagram member's Fill, then the stream member's with
// small datagrams still queued, then a datagram only the stream member can
// carry is enqueued. The stream member pulls small datagrams (it aggregates)
// but leaves MaxPayload + 25 bytes of its capacity, so its next Fill places
// the big datagram; with M2's rule it filled its capacity, the big datagram
// waited for capacity the saturated link never freed and aged out
// (DropAge).
func TestPacketStreamLaneHeadroom_KL13(t *testing.T) {
	const capacity = 20000
	s := dpSession(dpOpt{mode: ModeBond, maxAge: 100 * time.Millisecond})
	u, up := dpAddLane(s, 1, true, true)   // datagram member: DgramMax 975
	st, sp := dpAddLane(s, 2, true, false) // stream member
	up.set(func(f *dpPort) { f.budget = 1000 })
	sp.set(func(f *dpPort) { f.capacity = capacity })
	s.mu.Lock()
	s.pktRecomputeLocked()
	mixed, maxPayload := s.pk.mixed, s.pk.maxPayload
	s.mu.Unlock()
	if !mixed {
		t.Fatal("premise: the bond is not mixed")
	}
	for i := range 200 {
		dpWrite(t, s, uint64(i), 900)
	}
	now := time.Now()
	nu, _ := rcDgrams(dpFill(u, now)) // 1. the datagram member's batch
	b := dpFill(st, now)              // 2. the stream member, small datagrams queued
	_, lens := rcDgrams(b)
	placed := 0
	for _, n := range lens {
		placed += n
	}
	b.ReleaseRefs()
	if len(nu) == 0 || placed == 0 {
		t.Fatalf("premise: datagram member %d, stream member %d bytes", len(nu), placed)
	}
	if left := capacity - placed; left < maxPayload+wire.DgramOverhead {
		t.Fatalf("the stream member left %d bytes of capacity, want ≥ MaxPayload + 25 = %d", left, maxPayload+wire.DgramOverhead)
	}
	// The stream link is saturated: what it took stays in flight.
	sp.set(func(f *dpPort) { f.inflight = int64(placed) })
	dpWrite(t, s, 1000, 1200) // 3. only the stream member can carry it
	_, lens = rcDgrams(dpFill(st, now))
	big := false
	for _, n := range lens {
		big = big || n == 1200
	}
	if !big {
		t.Fatalf("the stream member's next Fill placed %v, want the 1200-byte datagram", lens)
	}
	if n := dpLocked(s, func(_ *stream, pk *packet) int { return pk.txBig.n }); n != 0 {
		t.Fatalf("%d big datagrams still wait for the stream member's capacity", n)
	}
	dpEnd(s, errClosed)
}

// TestRaceFillZeroAllocs_L41_L54: a warmed race Fill allocates nothing per
// frame or datagram — stream (two members sending copies of 256 KiB from
// their cursors, then the ACK) and packet (two members placing 32
// datagrams, the copies reusing their seqs, the head advancing).
func TestRaceFillZeroAllocs_L41_L54(t *testing.T) {
	s := rcSender(stOpt{window: 8 << 20})
	la, _ := stAddLane(s, 1, true)
	lb, _ := stAddLane(s, 2, true)
	rcRaceLanes(s)
	src := stPattern(0, 64<<10)
	b := carrier.NewBatch(0)
	stream := func() {
		for range 4 {
			if n, err := s.Write(src); n != len(src) || err != nil {
				panic("Write")
			}
		}
		for _, l := range []*lane{la, lb} {
			b.Reset(time.Now())
			l.Fill(nil, b)
			if b.Len() < 4 {
				panic("a race member must place its copy")
			}
			b.ReleaseRefs()
		}
		next := stLocked(s, func(st *stream) uint64 { return st.sNext })
		if err := stSendAck(la, 0, next, 8<<20); err != nil {
			panic(err)
		}
	}
	for range 16 {
		stream()
	}
	if !streamRaceEnabled {
		if a := testing.AllocsPerRun(100, stream); a != 0 {
			t.Fatalf("stream race Fill: %v allocations per 256 KiB round, want 0", a)
		}
	}
	stEnd(s, errClosed)

	ps, ls, _ := rcPktSender(dpOpt{}, true, true)
	body := dpPayload(1, 200)
	packet := func() {
		for range 32 {
			if n, err := ps.WriteTo(body); n != len(body) || err != nil {
				panic("WriteTo")
			}
		}
		for _, l := range ls {
			b := dpFill(l, time.Now())
			n := 0
			for i := range b.Len() {
				if b.Frame(i).Header.Type == wire.TypeDgram {
					n++
				}
			}
			if n != 32 {
				panic("a race member must place 32 datagrams")
			}
			b.ReleaseRefs()
		}
	}
	for range 16 {
		packet()
	}
	if !streamRaceEnabled {
		if a := testing.AllocsPerRun(100, packet); a != 0 {
			t.Fatalf("packet race Fill: %v allocations per 32 datagrams, want 0", a)
		}
	}
	dpEnd(ps, errClosed)
}

// TestRaceWakeEveryMember (M3-D30, R1-29): every race member places every
// datagram, so one WriteTo wakes every idle member that is not
// write-blocked, not only the selector's or the first data lane; a member
// whose cursor is at the queue's end is passed by a wake until its FIN is
// due.
func TestRaceWakeEveryMember(t *testing.T) {
	a, ls, ps := rcPktSender(dpOpt{}, true, true, true)
	ps[1].set(func(f *dpPort) { f.blocked = true })
	a.mu.Lock()
	for _, l := range ls {
		l.idle = true
	}
	a.mu.Unlock()
	wakes := func() (w [3]int) {
		for i, p := range ps {
			w[i] = p.wakeCount()
		}
		return w
	}
	w0 := wakes()
	dpWrite(t, a, 1, 200)
	if w := wakes(); w[0]-w0[0] != 1 || w[1] != w0[1] || w[2]-w0[2] != 1 {
		t.Fatalf("one WriteTo woke the members %v times, want once each but the write-blocked member 1", [3]int{w[0] - w0[0], w[1] - w0[1], w[2] - w0[2]})
	}
	// Member 0 places the datagram and goes idle: a wake with nothing due
	// for it passes it; the FIN is due once the session closes.
	dpIdle(ls[0])
	w0 = wakes()
	a.mu.Lock()
	a.pktWakeDataLocked(time.Now())
	a.mu.Unlock()
	if w := wakes(); w[0] != w0[0] {
		t.Fatal("a wake woke member 0 with its cursor at the end and no FIN due")
	}
	dpClose(a)
	if w := wakes(); w[0]-w0[0] != 1 {
		t.Fatalf("Close woke member 0 %d times, want once (its FIN is due)", w[0]-w0[0])
	}
	dpEnd(a, errClosed)
}

// TestRacePacketPlacedNotDropped (M3-D32, §A6.4): the slow member holds the
// tx head, so datagrams the fast member placed leave the queue by eviction
// (a full Packet.Queue), by ageing at WriteTo and at the session's end; on
// none of these paths does a placed datagram count as a drop, while every
// never-placed one does, and the send-side identity accepted = Sent +
// drops + queued unplaced holds throughout.
func TestRacePacketPlacedNotDropped(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const size = 1000
		a, ls, _ := rcPktSender(dpOpt{queue: 16 << 10, maxAge: 100 * time.Millisecond}, true, true)
		accepted := 0
		write := func() {
			t.Helper()
			dpWrite(t, a, uint64(accepted), size)
			accepted++
		}
		identity := func(what string) PacketCounters {
			t.Helper()
			unplaced := dpLocked(a, func(_ *stream, pk *packet) (n int) {
				q := &pk.tx
				for p := q.pos; p < q.pos+uint64(q.n); p++ {
					if q.seq == nil || q.seq[q.raceIdx(p)] == 0 {
						n++
					}
				}
				return n
			})
			c := dpCtr(a)
			if got := c.Sent + c.DropQueue + c.DropAge + c.DropTooLarge + c.DropNoPath + uint64(unplaced); got != uint64(accepted) {
				t.Fatalf("%s: Sent + drops + %d unplaced queued = %d, want %d accepted (%+v)", what, unplaced, got, accepted, c)
			}
			return c
		}
		// Eviction: each datagram placed by member 0 before the next
		// WriteTo; the queue (about 16 datagrams) overflows many times.
		for range 64 {
			write()
			dpFill(ls[0], time.Now()).ReleaseRefs()
		}
		if _, n := rcTx(a); n == 0 || n >= 64 {
			t.Fatalf("premise: %d datagrams queued, want the queue full and evicting", n)
		}
		if c := identity("placed, evicted"); c.DropQueue != 0 || c.Sent != 64 {
			t.Fatalf("evicted placed datagrams: %+v, want Sent 64 and DropQueue 0", c)
		}
		// Never placed: evicted by the next ones, counted.
		for range 24 {
			write()
		}
		if c := identity("unplaced, evicted"); c.DropQueue == 0 {
			t.Fatalf("never-placed datagrams were evicted uncounted: %+v", c)
		}
		before := dpCtr(a).DropQueue
		// Ageing at WriteTo: everything queued placed, then two unplaced
		// ones; after MaxAge the next WriteTo ages them all out.
		dpFill(ls[0], time.Now()).ReleaseRefs()
		write()
		write()
		time.Sleep(200 * time.Millisecond)
		write()
		if c := identity("aged at WriteTo"); c.DropAge != 2 || c.DropQueue != before {
			t.Fatalf("ageing at WriteTo: %+v, want DropAge 2 (the unplaced) and DropQueue %d", c, before)
		}
		// The end: one placed, three unplaced still queued.
		dpFill(ls[0], time.Now()).ReleaseRefs()
		write()
		write()
		write()
		dpEnd(a, errClosed)
		if c := identity("the end"); c.DropQueue != before+3 {
			t.Fatalf("the end: DropQueue %d, want %d + the 3 never placed", c.DropQueue, before)
		}
	})
}

// TestRacePacketRefusedCopies_L35 (M3-D35, R1-31): a race member's
// transport refusing its placements as too large (an MTU shrink, L37) is
// charged to the copies first — the other member's placement went out —
// so the datagrams stay Sent; only refusals beyond every copy (both
// members refused) move from Sent to DropTooLarge; Sent + DropTooLarge is
// unchanged.
func TestRacePacketRefusedCopies_L35(t *testing.T) {
	a, ls, _ := rcPktSender(dpOpt{}, true, true)
	for i := range 4 {
		dpWrite(t, a, uint64(i), 300)
	}
	for _, l := range ls {
		dpFill(l, time.Now()).ReleaseRefs()
	}
	if st := a.Status(); st.Packet.Sent != 4 || st.Race.Copies != 4 {
		t.Fatalf("premise: Sent %d Copies %d", st.Packet.Sent, st.Race.Copies)
	}
	for _, tc := range []struct {
		refused, sent, tooLarge, copies uint64
	}{
		{0, 4, 0, 4},
		{3, 4, 0, 1}, // one member refused three copies
		{4, 4, 0, 0}, // one member refused every placement
		{6, 2, 2, 0}, // both refused two datagrams
	} {
		var sn statusSnap // the actor's published refusals of dead carriers (R1-31)
		if cur := a.snap.Load(); cur != nil {
			sn = *cur
		}
		sn.refusedGone = tc.refused
		a.snap.Store(&sn)
		st := a.Status()
		if st.Packet.Sent != tc.sent || st.Packet.DropTooLarge != tc.tooLarge || st.Race.Copies != tc.copies {
			t.Fatalf("refused %d: Sent %d DropTooLarge %d Copies %d, want %d, %d, %d",
				tc.refused, st.Packet.Sent, st.Packet.DropTooLarge, st.Race.Copies, tc.sent, tc.tooLarge, tc.copies)
		}
		if st.Packet.Sent+st.Packet.DropTooLarge != 4 {
			t.Fatalf("refused %d: Sent + DropTooLarge = %d, want 4", tc.refused, st.Packet.Sent+st.Packet.DropTooLarge)
		}
	}
	dpEnd(a, errClosed)
}
