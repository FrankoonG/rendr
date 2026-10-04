package session

import (
	"bytes"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Holder-alone rescue, step by step (design §4.11, §0.8 V3; L34). The
// receiver drops out-of-order bytes at its 2·W receive cap (D13, V3); the
// sender still holds them unacknowledged, but only a retransmission brings
// them back, and stream carriers have no retransmission timer. Once the
// lane holding them is the only data lane, the rescue duplicate must leave
// on that lane itself; while another data lane exists the holder stays
// excluded (L34). These tests run the actor's real rescue check
// (rescueLocked) on stream-harness sessions, so every decision is
// deterministic. Package-level helpers of the rescue tests start with "rs".

// rsActor returns an actor for the stream-harness session s, with the
// rescue bookkeeping a dialer starts with (no sBase rescued yet).
func rsActor(s *Session) *actor {
	s.mu.Lock()
	s.ctl.rescuedBase = ^uint64(0)
	s.mu.Unlock()
	return newActor(s)
}

// rsRescueStep runs the actor's rescue check as one actor step does once
// RescueWait has passed since the last advance of the acknowledged front,
// and returns the rescue left pending.
func rsRescueStep(a *actor) rescueSlot {
	s := a.s
	s.mu.Lock()
	defer s.mu.Unlock()
	a.rescueLocked(s.st.lastAdvance.Add(time.Hour))
	return s.st.rescue
}

// rsFirstData returns the first DATA frame of fs, if any.
func rsFirstData(fs []stFrame) (stFrame, bool) {
	for _, f := range fs {
		if f.typ == wire.TypeData {
			return f, true
		}
	}
	return stFrame{}, false
}

// TestStreamRescueHolderAlone_L34 (§4.11, V3, D13): a bond pair sends
// 600-byte frames over two lanes, one frame per lane in turn; lane 2's
// frames stay in flight, so lane 1's arrive isolated, a run each, until the
// receive cap drops the rest. Then lane 2 dies with its frames: they are
// requeued and replayed on lane 1, the receiver delivers up to the first
// frame it dropped and stalls there, on a healthy lane that is now the only
// data lane and holds every dropped byte. Each stall is resolved by the
// actor's rescue step: it names lane 1 the holder, wakes it although it is
// the holder, and lane 1 sends the duplicate itself. The whole stream is
// read back byte-exact, every byte is acknowledged and every buffer
// returns. Without the holder's own duplicate nothing ever resends a
// dropped byte: the session would stall for good.
func TestStreamRescueHolderAlone_L34(t *testing.T) {
	const (
		w     = 256 << 10
		seg   = 600
		total = 160 << 10
	)
	p := stNewPair(stOpt{mode: ModeBond, window: w, segment: seg}, stOpt{window: w}, 2)
	stWatchCopies(t, p.b)
	for _, fp := range p.ap {
		fp.set(func(f *stPort) { f.capacity = seg }) // one frame per Fill
	}
	a := rsActor(p.a)
	data := stPattern(0, total)
	if n, err := p.a.Write(data); n != total || err != nil {
		t.Fatalf("Write = (%d, %v)", n, err)
	}
	now := time.Now()
	sent2 := 0
	for {
		n1, _ := p.step(0, true, now) // lane 1: delivered at once
		b := p.batch
		b.Reset(now)
		p.al[1].Fill(nil, b) // lane 2: in flight until its carrier dies
		n2 := b.Len()
		sent2 += stCount(stFrames(b), wire.TypeData)
		b.ReleaseRefs()
		if n1 == 0 && n2 == 0 {
			break
		}
	}
	recv := func() [3]uint64 {
		return stLocked(p.b, func(st *stream) [3]uint64 { return [3]uint64{st.rRead, st.rTail, st.oooDropped} })
	}
	dropped := recv()[2]
	if dropped == 0 || sent2 == 0 || stLocked(p.a, func(st *stream) uint64 { return st.sNext }) != total {
		t.Fatalf("stimulus: %d bytes dropped by the receiver, %d frames in flight on lane 2, want both with every byte sent", dropped, sent2)
	}
	if req := stKillLane(p.a, p.al[1]); req == 0 {
		t.Fatal("lane 2 died holding no unacknowledged span: nothing to replay (stimulus)")
	}
	stKillLane(p.b, p.bl[1])

	var got []byte
	readAll := func() {
		for {
			p.pump(true) // the replay, ACKs back, and anything the sender may send
			v := recv()
			n := int(v[1] - v[0])
			if n == 0 {
				return
			}
			got = append(got, stReadN(t, p.b, n)...)
		}
	}
	rescues := 0
	for readAll(); len(got) < total; readAll() {
		// Stalled at a dropped frame: nothing moves by itself.
		stuck := recv()[1]
		if p.pump(true); recv()[1] != stuck {
			t.Fatalf("progress at %d without a rescue", stuck)
		}
		wakes := p.ap[0].wakeCount()
		r := rsRescueStep(a)
		if !r.set || r.holder != p.al[0] || r.sp.off != stuck {
			t.Fatalf("stalled at %d with lane 1 the only data lane: pending rescue %+v (holder lane 1: %v), want lane 1's segment at %d",
				stuck, r, r.holder == p.al[0], stuck)
		}
		if p.ap[0].wakeCount() == wakes {
			t.Fatal("the rescue step did not wake the holder, the only lane that can send the duplicate")
		}
		fs, b := stFill(p.al[0], now)
		f, ok := rsFirstData(fs)
		if !ok || f.off != r.sp.off || f.n != int(r.sp.n) || !f.retx {
			b.ReleaseRefs()
			t.Fatalf("the holder sent %v, want the duplicate of [%d,+%d) first", fs, r.sp.off, r.sp.n)
		}
		if err := stDeliver(b, p.bl[0]); err != nil {
			t.Fatal(err)
		}
		b.ReleaseRefs()
		if recv()[1] <= stuck {
			t.Fatalf("the holder's duplicate of [%d,+%d) did not advance the receiver", r.sp.off, r.sp.n)
		}
		if rr := stLocked(p.a, func(st *stream) rescueSlot { return st.rescue }); rr.set {
			t.Fatalf("rescue %+v still pending after the duplicate was sent", rr)
		}
		rescues++
	}
	if !bytes.Equal(got, data) {
		t.Fatal("the stream read back corrupted")
	}
	if base := stLocked(p.a, func(st *stream) uint64 { return st.sBase }); base != total {
		t.Fatalf("sender sBase %d, want %d: not every byte acknowledged", base, total)
	}
	if errs := p.errors(); len(errs) != 0 {
		t.Fatalf("violations: %v", errs)
	}
	if rescues == 0 {
		t.Fatal("stimulus missing: the holder never had to resend")
	}
	t.Logf("%d bytes dropped by the receiver; %d frames replayed from the dead lane; %d holder rescues", recv()[2], sent2, rescues)
	p.close(t)
}

// TestStreamRescueExclusionFollowsLanes_L34 (§4.11, L34, V3): which lanes
// may send a pending rescue duplicate follows the data lanes at every Fill,
// and the actor's step wakes them. The passive sends here, over members 1
// and 2; its third lane is confirmed but outside the send set, and it holds
// the ACK duty (member 1's write blocked once), so the re-ACK of a death
// wakes that lane, not the holder. (1) With member 2 a data lane, the
// holder of the stuck head (member 1) is excluded and the rescue step wakes
// member 2. (2) Member 2 dies before its writer took the duplicate: the
// holder is the only data lane and idle — nothing but the actor's next step
// wakes it — and its Fill sends the duplicate first. (3) A holder-alone
// rescue is pending when a new member attaches: the holder is excluded
// again and the new member sends the duplicate.
func TestStreamRescueExclusionFollowsLanes_L34(t *testing.T) {
	const w = 4 << 20
	p := stNewPair(stOpt{mode: ModeBond, window: w}, stOpt{mode: ModeBond, window: w}, 2)
	s := p.b
	m1, m2 := p.bl[0], p.bl[1]
	f1, f2 := p.bp[0], p.bp[1]
	duty, fd := stAddLane(s, 3, false) // confirmed, not in the send set
	fd.set(func(f *stPort) { f.srtt = time.Millisecond })
	a := rsActor(s)
	msg := stPattern(0, 200<<10)
	if n, err := s.Write(msg); n != len(msg) || err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	// Member 1 pulls everything in one batch; its carrier delivers nothing
	// (stalled). Its write blocks once: the ACK duty moves to lane 3. Member
	// 2's writer and lane 3's find nothing more and go idle.
	fs, b := stFill(m1, now)
	b.ReleaseRefs()
	if stCount(fs, wire.TypeData) == 0 || stLocked(s, func(st *stream) uint64 { return st.sNext }) != uint64(len(msg)) {
		t.Fatalf("member 1 pulled %v, want the whole message", fs)
	}
	s.mu.Lock()
	s.refreshOrderLocked(now, true)
	s.mu.Unlock()
	f1.set(func(f *stPort) { f.blocked = true })
	m1.WriteBlocked(nil)
	f1.set(func(f *stPort) { f.blocked = false })
	if l := stLocked(s, func(st *stream) *lane { return st.ackLane }); l != duty {
		t.Fatal("the ACK duty did not move to lane 3 (setup)")
	}
	for _, l := range []*lane{m2, duty} {
		fs, b := stFill(l, now)
		b.ReleaseRefs()
		if stCount(fs, wire.TypeData) != 0 {
			t.Fatalf("lane %d pulled %v with nothing left to send", l.id, fs)
		}
	}

	// (1) Member 2 is a data lane: the holder is excluded.
	w2 := f2.wakeCount()
	r := rsRescueStep(a)
	if !r.set || r.holder != m1 || r.sp.off != 0 || r.sp.n != chunkSize {
		t.Fatalf("pending rescue %+v (holder member 1: %v), want member 1's first segment", r, r.holder == m1)
	}
	if f2.wakeCount() == w2 {
		t.Fatal("the rescue step did not wake member 2")
	}
	fs, b = stFill(m1, now)
	b.ReleaseRefs()
	if stCount(fs, wire.TypeData) != 0 {
		t.Fatalf("the holder sent %v while another data lane exists", fs)
	}

	// (2) Member 2 dies before its writer ran: the holder takes the
	// duplicate, woken by the actor's next step (the death's re-ACK woke
	// lane 3, which holds the ACK duty).
	if req := stKillLane(s, m2); req != 0 {
		t.Fatalf("member 2 requeued %d bytes: it never sent any", req)
	}
	if !stLocked(s, func(*stream) bool { return m1.idle }) {
		t.Fatal("the holder was woken by the death step: the actor's wake is not isolated (setup)")
	}
	w1 := f1.wakeCount()
	if r = rsRescueStep(a); !r.set || r.holder != m1 || r.sp.off != 0 {
		t.Fatalf("pending rescue %+v after member 2's death, want the same one", r)
	}
	if f1.wakeCount() == w1 {
		t.Fatal("the actor did not wake the holder, now the only lane that can send the duplicate")
	}
	fs, b = stFill(m1, now)
	b.ReleaseRefs()
	if f, ok := rsFirstData(fs); !ok || f.off != 0 || f.n != chunkSize || !f.retx {
		t.Fatalf("the holder alone sent %v, want the duplicate of [0,+%d) first", fs, chunkSize)
	}
	if rr := stLocked(s, func(st *stream) rescueSlot { return st.rescue }); rr.set {
		t.Fatalf("rescue %+v still pending after the duplicate was sent", rr)
	}

	// (3) A holder-alone rescue is pending when a member attaches.
	if err := stSendAck(m1, 0, chunkSize, w); err != nil {
		t.Fatal(err)
	}
	if r = rsRescueStep(a); !r.set || r.holder != m1 || r.sp.off != chunkSize {
		t.Fatalf("pending rescue %+v at the new head, want member 1's segment at %d", r, chunkSize)
	}
	m4, _ := stAddLane(s, 4, true)
	fs, b = stFill(m1, now)
	b.ReleaseRefs()
	if stCount(fs, wire.TypeData) != 0 {
		t.Fatalf("the holder sent %v after another data lane attached", fs)
	}
	fs, b = stFill(m4, now)
	b.ReleaseRefs()
	if f, ok := rsFirstData(fs); !ok || f.off != chunkSize || !f.retx {
		t.Fatalf("the new member sent %v, want the duplicate at %d first", fs, chunkSize)
	}
	p.close(t)
}
