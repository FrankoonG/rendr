package session

import (
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// WP3's Fill changes for mux (M3 design §A5.3, R1-1 rule 5, M3-D11): the
// capacity line subtracts the payload earlier views placed in the batch
// (Batch.Taken), and a call under a payload quota of 0 — the MUX writer's
// control pass — places control frames only and decides neither the lane's
// idleness nor its cap mark. The batches are driven as a MUX writer drives
// them (Batch.SetQuota around each call).

// rcTaken fills b with payload of another view (a lane of another session)
// and starts this call's quota: b.Taken() is then that payload.
func rcTaken(t *testing.T, b *carrier.Batch, payload int) {
	t.Helper()
	o := rcSender(stOpt{window: 4 << 20, segment: 16 << 10})
	t.Cleanup(func() { stEnd(o, errClosed) })
	ol, _ := stAddLane(o, 9, true)
	rcWrite(t, o, stPattern(0, payload))
	b.SetQuota(-1)
	ol.Fill(nil, b)
	b.SetQuota(1 << 20)
	if b.Taken() != payload {
		t.Fatalf("premise: Taken %d, want %d", b.Taken(), payload)
	}
}

// TestFillTakenCapacity (M3-D11): a lane never places beyond its carrier's
// Capacity − Inflight − Taken: a stream lane (selector and race; segments
// of 16 KiB, so the soft cap is exact) and a packet session's stream lane
// (selector's and race's), each after another view placed payload in the same
// batch.
func TestFillTakenCapacity(t *testing.T) {
	for _, mode := range []Mode{ModeSelector, ModeRace} {
		s := rcSenderMode(stOpt{window: 4 << 20, segment: 16 << 10}, mode)
		l, fp := stAddLane(s, 1, true)
		if mode == ModeRace {
			rcRaceLane(s, l)
		}
		fp.set(func(f *stPort) { f.capacity = 96 << 10; f.inflight = 16 << 10 })
		rcWrite(t, s, stPattern(0, 256<<10))
		b := carrier.NewBatch(0)
		b.Reset(time.Now())
		rcTaken(t, b, 48<<10)
		before := b.Len()
		l.Fill(nil, b)
		placed := 0
		for i := before; i < b.Len(); i++ {
			if f := b.Frame(i); f.Header.Type == wire.TypeData {
				placed += len(f.Body)
			}
		}
		if want := 96<<10 - 16<<10 - 48<<10; placed != want {
			t.Fatalf("%v: placed %d bytes, want Capacity − Inflight − Taken = %d", mode, placed, want)
		}
		if !b.CapBlocked() {
			t.Fatalf("%v: the lane stopped at its capacity without marking the batch cap-blocked", mode)
		}
		b.ReleaseRefs()
		stEnd(s, errClosed)
	}

	// A packet session's stream lane: 1,000-byte datagrams.
	ps := dpSession(dpOpt{})
	l, fp := dpAddLane(ps, 1, true, false)
	fp.set(func(f *dpPort) { f.capacity = 10000 })
	for i := range 20 {
		dpWrite(t, ps, uint64(i), 1000)
	}
	b := carrier.NewBatch(0)
	b.Reset(time.Now())
	rcTaken(t, b, 6000)
	before := b.Len()
	(*plane)(l).Fill(nil, b)
	n := 0
	for i := before; i < b.Len(); i++ {
		if b.Frame(i).Header.Type == wire.TypeDgram {
			n++
		}
	}
	if n != 4 {
		t.Fatalf("packet stream lane placed %d datagrams, want 4 = (10000 − 6000)/1000", n)
	}
	b.ReleaseRefs()
	dpEnd(ps, errClosed)

	// A packet race session's stream lane (its own cursor, M3-D32): the
	// same share, and at it the lane marks the batch cap-blocked and
	// itself (capMarked), so the PONG that frees capacity wakes it (§4.10).
	rs, rls, rps := rcPktSender(dpOpt{}, false)
	rps[0].set(func(f *dpPort) { f.capacity = 10000 })
	for i := range 20 {
		dpWrite(t, rs, uint64(i), 1000)
	}
	b.Reset(time.Now())
	rcTaken(t, b, 6000)
	before = b.Len()
	(*plane)(rls[0]).Fill(nil, b)
	n = 0
	for i := before; i < b.Len(); i++ {
		if b.Frame(i).Header.Type == wire.TypeDgram {
			n++
		}
	}
	marked := dpLocked(rs, func(*stream, *packet) bool { return rls[0].capMarked })
	if n != 4 || !b.CapBlocked() || !marked {
		t.Fatalf("race packet stream lane placed %d datagrams (want 4), cap-blocked %v, capMarked %v", n, b.CapBlocked(), marked)
	}
	b.ReleaseRefs()
	dpEnd(rs, errClosed)
}

// TestFillQuotaZeroKeepsIdle (R1-1 rule 5): a lane with DATA (or datagrams)
// queued, called under a quota of 0, places its control frames only (here
// the ACK it owes), leaves l.idle as it was — the DRR call that
// follows decides it — and marks nothing cap-blocked; the next call with a
// quota places the DATA.
func TestFillQuotaZeroKeepsIdle(t *testing.T) {
	for _, mode := range []Mode{ModeSelector, ModeRace} {
		s := rcSenderMode(stOpt{window: 4 << 20}, mode)
		l, fp := stAddLane(s, 1, true)
		if mode == ModeRace {
			rcRaceLane(s, l)
		}
		fp.set(func(f *stPort) { f.capacity = 1 }) // at the cap: a payload call would mark it
		rcWrite(t, s, stPattern(0, 64<<10))
		for _, idle := range []bool{false, true} {
			s.mu.Lock()
			l.idle = idle
			s.ackBumpForTest()
			s.mu.Unlock()
			b := carrier.NewBatch(0)
			b.Reset(time.Now())
			b.SetQuota(0)
			l.Fill(nil, b)
			fs := stFrames(b)
			got := stLocked(s, func(*stream) bool { return l.idle })
			if got != idle || b.CapBlocked() || stCount(fs, wire.TypeData) != 0 || stCount(fs, wire.TypeAck) != 1 {
				t.Fatalf("%v idle=%v: quota 0 placed %v, idle → %v, cap-blocked %v", mode, idle, fs, got, b.CapBlocked())
			}
			b.ReleaseRefs()
		}
		fp.set(func(f *stPort) { f.capacity = 1 << 30 })
		b := carrier.NewBatch(0)
		b.Reset(time.Now())
		b.SetQuota(64 << 10)
		l.Fill(nil, b)
		if fs := stFrames(b); stCount(fs, wire.TypeData) == 0 {
			t.Fatalf("%v: the DRR call placed %v, want the DATA", mode, fs)
		}
		b.ReleaseRefs()
		stEnd(s, errClosed)
	}

	// A packet lane: datagrams queued, nothing else owed (its PACK went
	// out in a first control pass): a control pass places nothing and keeps
	// both its idleness and its cap mark.
	ps := dpSession(dpOpt{})
	l, fp := dpAddLane(ps, 1, true, false)
	fp.set(func(f *dpPort) { f.capacity = 1 })
	dpWrite(t, ps, 1, 500)
	b := carrier.NewBatch(0)
	for i, st := range [][2]bool{{false, false}, {false, true}, {true, false}} {
		ps.mu.Lock()
		l.idle, l.capMarked = st[0], st[1]
		ps.mu.Unlock()
		b.Reset(time.Now())
		b.SetQuota(0)
		(*plane)(l).Fill(nil, b)
		v := dpLocked(ps, func(*stream, *packet) [2]bool { return [2]bool{l.idle, l.capMarked} })
		if i > 0 && (b.Len() != 0 || v != st || b.CapBlocked()) {
			t.Fatalf("packet lane under quota 0 from idle %v capMarked %v: %d frames, idle %v capMarked %v, cap-blocked %v",
				st[0], st[1], b.Len(), v[0], v[1], b.CapBlocked())
		}
		b.ReleaseRefs()
	}
	dpEnd(ps, errClosed)
}

// rcSenderMode is rcSender in the given mode.
func rcSenderMode(o stOpt, mode Mode) *Session {
	o.mode = mode
	s := stSession(o)
	s.mu.Lock()
	s.peerWindowLocked(1 << 30)
	s.mu.Unlock()
	return s
}

// ackBumpForTest makes every lane owe an ACK (an urgent bump's ackGen
// increment, without its wakes). s.mu held.
func (s *Session) ackBumpForTest() {
	s.st.ackGen++
	s.ensureAckLaneLocked()
}
