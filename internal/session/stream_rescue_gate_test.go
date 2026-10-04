package session

import (
	"bytes"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Which stuck heads the holder duplicates itself, and the rescue after its
// own duplicate, step by step (design §4.11, §0.8 V3; L34). The receiver
// can only have dropped bytes it held out of order, and it holds bytes out
// of order only if DATA went out on more than one data lane since
// everything sent was last acknowledged: a single lane delivers in order,
// and so does the replay of a lane that died or left the send set. So the
// holder of a stuck head sends its own duplicate only while it is the only
// data lane and such interleaved DATA is still unacknowledged; a head stuck
// behind a reader that pauses, or behind the holder's own stalled carrier,
// costs no duplicate on a bond that only ever sent on one lane. And since
// the holder may be the stalled one, its own duplicate does not use up the
// stuck head: once another data lane exists, that lane rescues the same
// head once more. These tests run the actor's real rescue check
// (rescueLocked) on stream-harness sessions and reuse the rs helpers of
// stream_rescue_holder_test.go.

// rsDataFrames returns the DATA frames of one Fill of l at now; the batch
// is released (its frames are not delivered).
func rsDataFrames(l *lane, now time.Time) []stFrame {
	fs, b := stFill(l, now)
	b.ReleaseRefs()
	var out []stFrame
	for _, f := range fs {
		if f.typ == wire.TypeData {
			out = append(out, f)
		}
	}
	return out
}

// rsSent returns the sender's acknowledged front sBase and its first
// never-sent offset sNext.
func rsSent(s *Session) (sBase, sNext uint64) {
	v := stLocked(s, func(st *stream) [2]uint64 { return [2]uint64{st.sBase, st.sNext} })
	return v[0], v[1]
}

// rsRecv returns the receiver's rRead, rTail and oooDropped.
func rsRecv(s *Session) (rRead, rTail, dropped uint64) {
	v := stLocked(s, func(st *stream) [3]uint64 { return [3]uint64{st.rRead, st.rTail, st.oooDropped} })
	return v[0], v[1], v[2]
}

// rsPump is stPair.pump with settle that also returns how many DATA
// frames each of the sender's lanes placed.
func rsPump(p *stPair) []int {
	per := make([]int, len(p.al))
	now := time.Now()
	for {
		moved := 0
		var wake time.Time
		for i := range p.al {
			for _, aToB := range [2]bool{true, false} {
				before := len(p.traceAB)
				k, w := p.step(i, aToB, now)
				per[i] += stCount(p.traceAB[before:], wire.TypeData)
				moved += k
				if !w.IsZero() && (wake.IsZero() || w.Before(wake)) {
					wake = w
				}
			}
		}
		if moved > 0 {
			continue
		}
		if wake.IsZero() || !now.Before(wake) {
			return per
		}
		now = wake
	}
}

// TestStreamRescueHolderAloneNeedsInterleaving_L34 (§4.11, V3): the
// receiver delivered every byte in order and its application reads
// nothing, so the head stays stuck with every byte unacknowledged, and the
// holder is the only data lane. (1) The bond only ever sent on that lane:
// the receiver cannot have dropped anything, so no rescue is set and the
// holder sends no duplicate, however often the check runs. (2) Both lanes
// sent interleaved DATA, all of it acknowledged, then lane 2 died and lane
// 1 alone sent the bytes now stuck: nothing interleaved is outstanding, so
// again no duplicate. (3) The control: lane 2 dies while interleaved DATA
// is still unacknowledged; the receiver may hold or have dropped some of
// it out of order, so the holder duplicates its stuck head itself. In each
// case the bytes read back exact once the reader resumes.
func TestStreamRescueHolderAloneNeedsInterleaving_L34(t *testing.T) {
	const (
		w = 4 << 20
		n = 200 << 10
	)
	// open builds a bond pair whose sender lanes pull at most one segment
	// per Fill, so the pump alternates them frame by frame.
	open := func(links int) (*stPair, *actor) {
		p := stNewPair(stOpt{mode: ModeBond, window: w}, stOpt{mode: ModeBond, window: w}, links)
		for _, fp := range p.ap {
			fp.set(func(f *stPort) { f.capacity = chunkSize })
		}
		return p, rsActor(p.a)
	}
	// stuck writes n bytes at off, delivers them all in order and checks
	// the stimulus: everything sent and received, nothing read, so the head
	// stays at off with every byte of the round unacknowledged. It returns
	// the bytes and the DATA frames each sender lane placed.
	stuck := func(t *testing.T, p *stPair, off uint64) ([]byte, []int) {
		t.Helper()
		msg := stPattern(off, n)
		if k, err := p.a.Write(msg); k != n || err != nil {
			t.Fatalf("Write = (%d, %v)", k, err)
		}
		per := rsPump(p)
		base, next := rsSent(p.a)
		rRead, rTail, dropped := rsRecv(p.b)
		if base != off || next != off+n || rRead != off || rTail != off+n || dropped != 0 {
			t.Fatalf("stimulus: sender sBase %d sNext %d, receiver rRead %d rTail %d dropped %d; want the head stuck at %d with %d bytes received in order and unread",
				base, next, rRead, rTail, dropped, off, n)
		}
		return msg, per
	}
	// noRescue runs the rescue check three times and requires that it
	// neither sets a rescue nor makes the holder send anything.
	noRescue := func(t *testing.T, p *stPair, a *actor, why string) {
		t.Helper()
		now := time.Now()
		for range 3 {
			if r := rsRescueStep(a); r.set {
				t.Fatalf("%s: rescue %+v set for a head the receiver holds in order", why, r)
			}
			if ds := rsDataFrames(p.al[0], now); len(ds) != 0 {
				t.Fatalf("%s: the holder sent %v", why, ds)
			}
		}
		if retx := stLocked(p.a, func(st *stream) uint64 { return st.retxBytes }); retx != 0 {
			t.Fatalf("%s: %d bytes retransmitted", why, retx)
		}
	}
	// readBack reads msg and checks that the sender's front reaches end.
	readBack := func(t *testing.T, p *stPair, msg []byte, end uint64) {
		t.Helper()
		if got := stReadN(t, p.b, len(msg)); !bytes.Equal(got, msg) {
			t.Fatal("the stream read back corrupted")
		}
		p.pump(true)
		if base, _ := rsSent(p.a); base != end {
			t.Fatalf("sender sBase %d after the reader caught up, want %d", base, end)
		}
	}
	interleaved := func(t *testing.T, per []int) {
		t.Helper()
		if len(per) < 2 || per[0] == 0 || per[1] == 0 {
			t.Fatalf("stimulus: DATA frames per sender lane %v, want both lanes interleaved", per)
		}
	}

	t.Run("single-lane", func(t *testing.T) {
		p, a := open(1)
		msg, _ := stuck(t, p, 0)
		noRescue(t, p, a, "a bond that only sent on one lane")
		readBack(t, p, msg, n)
		p.close(t)
	})

	t.Run("interleaved-acknowledged", func(t *testing.T) {
		p, a := open(2)
		first, per := stuck(t, p, 0)
		interleaved(t, per)
		readBack(t, p, first, n)
		stKillLane(p.a, p.al[1])
		stKillLane(p.b, p.bl[1])
		msg, _ := stuck(t, p, n)
		noRescue(t, p, a, "interleaved DATA acknowledged before the holder was alone")
		readBack(t, p, msg, 2*n)
		p.close(t)
	})

	t.Run("interleaved-outstanding", func(t *testing.T) {
		p, a := open(2)
		msg, per := stuck(t, p, 0)
		interleaved(t, per)
		stKillLane(p.a, p.al[1])
		stKillLane(p.b, p.bl[1])
		r := rsRescueStep(a)
		if !r.set || r.holder != p.al[0] || r.sp.off != 0 {
			t.Fatalf("pending rescue %+v (holder lane 1: %v), want lane 1's segment at 0", r, r.holder == p.al[0])
		}
		ds := rsDataFrames(p.al[0], time.Now())
		if len(ds) == 0 || ds[0].off != 0 || ds[0].n != int(r.sp.n) || !ds[0].retx {
			t.Fatalf("the holder alone sent %v, want its own duplicate of [0,+%d) first", ds, r.sp.n)
		}
		readBack(t, p, msg, n)
		p.close(t)
	})
}

// rsSettle runs l's Fill until it appends nothing, as its writer does after
// writes that never arrive, and requires that it sends no DATA.
func rsSettle(t *testing.T, l *lane) {
	t.Helper()
	for {
		fs, b := stFill(l, time.Now())
		b.ReleaseRefs()
		if len(fs) == 0 {
			return
		}
		if k := stCount(fs, wire.TypeData); k != 0 {
			t.Fatalf("lane %d sent %v while settling (setup)", l.id, fs)
		}
	}
}

// rsStalledHolder builds a bond pair with links lanes, writes n bytes and
// lets the sender's lane 1 pull all of them into a stalled carrier (its
// batch is never delivered) while every other lane is an idle data lane;
// lane 1 then goes idle, as its writer does after writes that never arrive.
// The sender's ACK duty moves to a confirmed lane outside the send set (id
// 9, the fastest), so the re-ACK of an attach or a death wakes that lane:
// only the actor's rescue step wakes the lanes that may send a rescue.
func rsStalledHolder(t *testing.T, links, n int) (*stPair, *actor, []byte) {
	t.Helper()
	p := stNewPair(stOpt{mode: ModeBond, window: 4 << 20}, stOpt{mode: ModeBond, window: 4 << 20}, links)
	duty, fd := stAddLane(p.a, 9, false)
	fd.set(func(f *stPort) { f.srtt = time.Millisecond })
	p.a.mu.Lock()
	p.a.refreshOrderLocked(time.Now(), true)
	cur := p.a.st.ackLane
	p.a.mu.Unlock()
	if cur != nil && cur != duty {
		cp := cur.port.(*stPort)
		cp.set(func(f *stPort) { f.blocked = true })
		cur.WriteBlocked(nil)
		cp.set(func(f *stPort) { f.blocked = false })
	}
	if l := stLocked(p.a, func(st *stream) *lane { return st.ackLane }); l != duty {
		t.Fatal("the sender's ACK duty did not move to lane 9 (setup)")
	}
	a := rsActor(p.a)
	msg := stPattern(0, n)
	if k, err := p.a.Write(msg); k != n || err != nil {
		t.Fatalf("Write = (%d, %v)", k, err)
	}
	if ds := rsDataFrames(p.al[0], time.Now()); len(ds) == 0 {
		t.Fatal("lane 1 pulled nothing (setup)")
	}
	for _, l := range append([]*lane{duty}, p.al...) {
		rsSettle(t, l)
	}
	if _, next := rsSent(p.a); next != uint64(n) {
		t.Fatalf("sNext %d after lane 1's pull, want %d (setup)", next, n)
	}
	if _, rTail, _ := rsRecv(p.b); rTail != 0 {
		t.Fatalf("the receiver got %d bytes through the stalled carrier", rTail)
	}
	return p, a, msg
}

// rsAttach attaches lane id on both ends as the actor's attach does — a
// data lane on the sender, a receiving lane on the receiver — and lets the
// sender's writer find nothing and go idle.
func rsAttach(t *testing.T, p *stPair, id uint32) (sender, receiver *lane, port *stPort) {
	t.Helper()
	sender, port = stAddLane(p.a, id, true)
	receiver, _ = stAddLane(p.b, id, false)
	rsSettle(t, sender)
	return sender, receiver, port
}

// rsRescueVia requires the rescue step to name lane 1's head [0, C) again,
// to wake l and to keep the holder out (L34); l's duplicate goes first and
// is delivered on the receiver's lane to: the receiver's in-order end then
// passes the head, whose bytes read back exact.
func rsRescueVia(t *testing.T, p *stPair, a *actor, l, to *lane, fp *stPort, msg []byte) {
	t.Helper()
	wakes := fp.wakeCount()
	r := rsRescueStep(a)
	if !r.set || r.holder != p.al[0] || r.sp.off != 0 || r.sp.n != chunkSize {
		t.Fatalf("pending rescue %+v (holder lane 1: %v), want lane 1's head [0,+%d) with lane %d a data lane",
			r, r.holder == p.al[0], chunkSize, l.id)
	}
	if fp.wakeCount() == wakes {
		t.Fatalf("the rescue step did not wake lane %d", l.id)
	}
	if ds := rsDataFrames(p.al[0], time.Now()); len(ds) != 0 {
		t.Fatalf("the holder sent %v with another data lane present (L34)", ds)
	}
	fs, b := stFill(l, time.Now())
	f, ok := rsFirstData(fs)
	if !ok || f.off != 0 || f.n != chunkSize || !f.retx {
		b.ReleaseRefs()
		t.Fatalf("lane %d sent %v, want the duplicate of [0,+%d) first", l.id, fs, chunkSize)
	}
	if err := stDeliver(b, to); err != nil {
		t.Fatal(err)
	}
	b.ReleaseRefs()
	if _, rTail, _ := rsRecv(p.b); rTail < chunkSize {
		t.Fatalf("the receiver's in-order end %d did not pass the rescued head", rTail)
	}
	if got := stReadN(t, p.b, chunkSize); !bytes.Equal(got, msg[:chunkSize]) {
		t.Fatal("the rescued head read back corrupted")
	}
}

// TestStreamRescueOnceMoreAfterHolderDuplicate_L34 (§4.11, L34, V3): the
// holder of the stuck head [0, C) is stalled — nothing it sends arrives —
// so its own duplicate of the head rescues nothing. (1) The holder sent
// while lane 2 was a data lane, then lane 2 dies: the holder, the only data
// lane, is woken by the rescue step and duplicates the head into its own
// stall, and no further rescue follows while it stays alone; then lane 3
// attaches and the rescue step names the same head again on lane 3, whose
// duplicate arrives. That is the bound: the head stays stuck (its ACK never
// comes back), yet no third rescue follows — lane 3 sends nothing more,
// and when lane 3 dies, lane 4 only replays lane 3's requeued duplicate
// once (L10). (2) The rescue is set while lane 2 is a data lane, but lane 2
// dies before its writer took it: the holder, alone now, sends it itself,
// and lane 3, attaching afterwards, again rescues the head once more. (3)
// The holder was the only data lane from the start: the receiver cannot
// have dropped anything, so while it is alone there is no rescue and it is
// not even woken — until lane 3 attaches and rescues the head.
func TestStreamRescueOnceMoreAfterHolderDuplicate_L34(t *testing.T) {
	const n = 200 << 10
	now := time.Now()
	// holderDuplicates requires the rescue step to leave a rescue of lane
	// 1's head pending and to wake lane 1, its only possible sender, which
	// then sends it into its stall.
	holderDuplicates := func(t *testing.T, p *stPair, a *actor) {
		t.Helper()
		wakes := p.ap[0].wakeCount()
		r := rsRescueStep(a)
		if !r.set || r.holder != p.al[0] || r.sp.off != 0 || r.sp.n != chunkSize {
			t.Fatalf("pending rescue %+v (holder lane 1: %v), want lane 1's head [0,+%d) with lane 1 the only data lane",
				r, r.holder == p.al[0], chunkSize)
		}
		if p.ap[0].wakeCount() == wakes {
			t.Fatal("the rescue step did not wake the holder, the only lane that may send the duplicate")
		}
		ds := rsDataFrames(p.al[0], now)
		if len(ds) == 0 || ds[0].off != 0 || ds[0].n != chunkSize || !ds[0].retx {
			t.Fatalf("the holder sent %v, want its own duplicate of [0,+%d) (stimulus)", ds, chunkSize)
		}
	}
	// alone requires that no rescue follows the holder's own duplicate
	// while it is the only data lane.
	alone := func(t *testing.T, p *stPair, a *actor) {
		t.Helper()
		for range 3 {
			if r := rsRescueStep(a); r.set {
				t.Fatalf("rescue %+v set again at the same head while the holder is alone", r)
			}
			if ds := rsDataFrames(p.al[0], now); len(ds) != 0 {
				t.Fatalf("the holder sent %v again at the same head", ds)
			}
		}
	}

	t.Run("member-died", func(t *testing.T) {
		p, a, msg := rsStalledHolder(t, 2, n)
		if req := stKillLane(p.a, p.al[1]); req != 0 {
			t.Fatalf("lane 2 requeued %d bytes: it never sent any", req)
		}
		stKillLane(p.b, p.bl[1])
		holderDuplicates(t, p, a)
		alone(t, p, a)
		l3, r3, f3 := rsAttach(t, p, 3)
		rsRescueVia(t, p, a, l3, r3, f3, msg)
		// The bound: the head is still stuck, as no ACK is delivered.
		for range 3 {
			if r := rsRescueStep(a); r.set {
				t.Fatalf("a third rescue %+v at the same head", r)
			}
			if ds := rsDataFrames(l3, now); len(ds) != 0 {
				t.Fatalf("lane 3 sent %v again at the same head", ds)
			}
		}
		// Lane 3 dies: its duplicate is requeued like any span it sent, and
		// lane 4 replays it once (L10) — a replay, not a third rescue.
		if req := stKillLane(p.a, l3); req != chunkSize {
			t.Fatalf("lane 3 requeued %d bytes, want its duplicate's %d", req, chunkSize)
		}
		stKillLane(p.b, r3)
		l4, _ := stAddLane(p.a, 4, true)
		stAddLane(p.b, 4, false)
		if r := rsRescueStep(a); r.set {
			t.Fatalf("a third rescue %+v at the same head after lane 4 attached", r)
		}
		if ds := rsDataFrames(l4, now); len(ds) != 1 || ds[0].off != 0 || ds[0].n != chunkSize || !ds[0].retx {
			t.Fatalf("lane 4 sent %v, want only the replay of lane 3's [0,+%d)", ds, chunkSize)
		}
		for range 3 {
			if r := rsRescueStep(a); r.set {
				t.Fatalf("a third rescue %+v at the same head", r)
			}
			if ds := rsDataFrames(l4, now); len(ds) != 0 {
				t.Fatalf("lane 4 sent %v again at the same head", ds)
			}
		}
		if base, _ := rsSent(p.a); base != 0 {
			t.Fatalf("sBase %d: the head moved (stimulus)", base)
		}
		p.close(t)
	})

	t.Run("pending-falls-to-holder", func(t *testing.T) {
		p, a, msg := rsStalledHolder(t, 2, n)
		w2 := p.ap[1].wakeCount()
		r := rsRescueStep(a)
		if !r.set || r.holder != p.al[0] || r.sp.off != 0 {
			t.Fatalf("pending rescue %+v, want lane 1's head with lane 2 to send it", r)
		}
		if p.ap[1].wakeCount() == w2 {
			t.Fatal("the rescue step did not wake lane 2")
		}
		if ds := rsDataFrames(p.al[0], now); len(ds) != 0 {
			t.Fatalf("the holder sent %v while lane 2 is a data lane (L34)", ds)
		}
		// Lane 2 dies before its writer ran: the rescue is still pending.
		stKillLane(p.a, p.al[1])
		stKillLane(p.b, p.bl[1])
		holderDuplicates(t, p, a)
		alone(t, p, a)
		l3, r3, f3 := rsAttach(t, p, 3)
		rsRescueVia(t, p, a, l3, r3, f3, msg)
		p.close(t)
	})

	t.Run("single-lane-start", func(t *testing.T) {
		p, a, msg := rsStalledHolder(t, 1, n)
		wakes := p.ap[0].wakeCount()
		for range 3 {
			if r := rsRescueStep(a); r.set {
				t.Fatalf("rescue %+v set with the holder the only lane it ever sent on", r)
			}
			if ds := rsDataFrames(p.al[0], now); len(ds) != 0 {
				t.Fatalf("the holder sent %v", ds)
			}
		}
		if p.ap[0].wakeCount() != wakes {
			t.Fatal("the rescue step woke the holder although it may not send a duplicate")
		}
		l3, r3, f3 := rsAttach(t, p, 3)
		rsRescueVia(t, p, a, l3, r3, f3, msg)
		p.close(t)
	})
}
