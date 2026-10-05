package session

import (
	"bytes"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestGapLaneWakes_L34 (design §0.13 A4, §0.14 B14): a bond receiver's ACK
// duty lane has stalled — its path delivers nothing in either direction
// while its conn still accepts writes, so WriteBlocked never moves the
// duty, and every ACK it places is lost — and the receiver holds
// out-of-order data that another lane delivered beyond the in-order end:
// that lane is the gap lane and carries a copy of every ACK over the path
// that evidently delivers. Each producer of an ACK must wake the idle gap
// lane, whose writer then places the ACK by itself, without waiting for
// another frame or timer:
//
//   - "bump": an urgent bump (the application read AckEvery bytes) wakes it
//     and the ACK leaves at once (bumpNowLocked);
//   - "ack-delay": a smaller read arms the ACK delay; the wake lets the gap
//     lane's writer arm its timer, and the ACK leaves exactly at ackDelayAt
//     (ackCadenceLocked);
//   - "gap-data": DATA beyond the in-order end on a lane that owes an ACK
//     makes it the gap lane and wakes it, and the ACK of the read that the
//     stalled duty lane reported leaves at once (gapAckLocked).
//
// The writers are emulated in a synctest bubble (stRunWriter): a writer
// runs Fill only when woken or at its batch's WakeAt time, so a missing
// wake leaves the gap lane asleep and its ACK never placed.
func TestGapLaneWakes_L34(t *testing.T) {
	t.Run("bump", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := g8NewGapRig()
			defer r.close(t)
			r.inOrderThenStall(t)
			r.beyondGap(t)
			synctest.Wait()
			r.requireIdleGap(t)
			from, at := r.mark(), time.Now()
			r.read(t, 64<<10) // AckEvery bytes: an urgent bump
			synctest.Wait()
			r.requireGapAck(t, from, at, 64<<10, "an urgent bump")
		})
	})
	t.Run("ack-delay", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := g8NewGapRig()
			defer r.close(t)
			r.inOrderThenStall(t)
			r.beyondGap(t)
			synctest.Wait()
			r.requireIdleGap(t)
			from := r.mark()
			r.read(t, 1000) // below AckEvery: the ACK delay is armed
			at := stLocked(r.s, func(st *stream) time.Time { return st.ackDelayAt })
			if at.IsZero() || at.Sub(time.Now()) != g8AckDelay {
				t.Fatalf("ACK delay armed at %v from now, want %v (stimulus)", at.Sub(time.Now()), g8AckDelay)
			}
			synctest.Wait()
			if a := r.acksOn(r.gap.id, from); len(a) != 0 {
				t.Fatalf("the gap lane placed %+v before ackDelayAt", a)
			}
			time.Sleep(time.Until(at))
			synctest.Wait()
			r.requireGapAck(t, from, at, 1000, "the armed ACK delay")
		})
	})
	t.Run("gap-data", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := g8NewGapRig()
			defer r.close(t)
			r.inOrderThenStall(t)
			from := r.mark()
			r.read(t, 64<<10) // the duty lane places ACK(64 KiB), lost in its stalled path
			synctest.Wait()
			if a := r.acksOn(r.duty.id, from); len(a) != 1 || a[0].ack.Delivered != 64<<10 {
				t.Fatalf("duty lane ACKs %+v after the read, want ACK(64 KiB) (stimulus)", a)
			}
			s := r.snapshot()
			if !s.duty || s.gapSet || s.held || !s.idle || !s.owes {
				t.Fatalf("before the DATA beyond the gap: %+v; want the duty on the stalled lane, no gap lane, nothing held out of order, and lane 2 idle and owing an ACK", s)
			}
			from, at := r.mark(), time.Now()
			r.beyondGap(t)
			synctest.Wait()
			r.requireGapAck(t, from, at, 64<<10, "gap-lane DATA")
		})
	})
}

// g8AckDelay is the receiver's ACK delay in TestGapLaneWakes_L34.
const g8AckDelay = 20 * time.Millisecond

// g8GapRig is a bond passive receiver with two lanes whose writers are
// emulated (stRunWriter) and whose conns accept every write: lane 1 holds
// the ACK duty (lowest srtt) and is the one whose path stalls, lane 2 is
// the one that becomes the gap lane. Every placed ACK is recorded; where
// the bytes go does not matter (no peer runs).
type g8GapRig struct {
	s           *Session
	duty, gap   *lane
	dutyP, gapP *stPort
	stop        chan struct{}
	wg          sync.WaitGroup
	rd          uint64 // the next stream offset the application reads
	mu          sync.Mutex
	acks        []g8Ack
}

// g8Ack is one ACK frame a lane's writer placed.
type g8Ack struct {
	lane uint32
	at   time.Time
	ack  wire.Ack
}

// g8NewGapRig builds the rig inside the caller's bubble and starts both
// writers.
func g8NewGapRig() *g8GapRig {
	s := stSession(stOpt{role: RolePassive, mode: ModeBond, ackDelay: g8AckDelay})
	r := &g8GapRig{s: s, stop: make(chan struct{})}
	r.duty, r.dutyP = stAddLane(s, 1, true)
	r.gap, r.gapP = stAddLane(s, 2, true)
	r.dutyP.set(func(f *stPort) { f.srtt = 5 * time.Millisecond })
	r.gapP.set(func(f *stPort) { f.srtt = 10 * time.Millisecond })
	s.mu.Lock()
	s.refreshOrderLocked(time.Now(), true)
	s.st.ackLane = nil
	s.ensureAckLaneLocked()
	s.mu.Unlock()
	for _, w := range []struct {
		l *lane
		p *stPort
	}{{r.duty, r.dutyP}, {r.gap, r.gapP}} {
		id := w.l.id
		stRunWriter(&r.wg, w.l, w.p, r.stop, func(b *carrier.Batch) error {
			r.record(id, b)
			return nil
		})
	}
	return r
}

func (r *g8GapRig) record(id uint32, b *carrier.Batch) {
	fs := stFrames(b)
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, f := range fs {
		if f.typ == wire.TypeAck {
			r.acks = append(r.acks, g8Ack{lane: id, at: f.at, ack: f.ack})
		}
	}
}

// mark returns the number of ACKs placed so far.
func (r *g8GapRig) mark() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.acks)
}

// acksOn returns the ACKs lane id placed since mark from.
func (r *g8GapRig) acksOn(id uint32, from int) []g8Ack {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []g8Ack
	for _, a := range r.acks[from:] {
		if a.lane == id {
			out = append(out, a)
		}
	}
	return out
}

// inOrderThenStall delivers [0, 128 KiB) in order on the duty lane (the
// first in-order DATA after the attaches is acknowledged at once, on the
// duty lane only); then the duty lane's path stalls: nothing more arrives
// on it, so the bytes it carries next, [128 KiB, 192 KiB), are the gap.
func (r *g8GapRig) inOrderThenStall(t *testing.T) {
	t.Helper()
	synctest.Wait()
	if err := stDeliverRange(r.duty, 0, stPattern(0, 128<<10)); err != nil {
		t.Fatal(err)
	}
	synctest.Wait()
	if d := stLocked(r.s, func(st *stream) *lane { return st.ackLane }); d != r.duty {
		t.Fatal("the lowest-srtt lane does not hold the ACK duty (stimulus)")
	}
}

// beyondGap delivers [192 KiB, 224 KiB) on lane 2: beyond the in-order end
// (128 KiB), so it is held out of order and lane 2 becomes the gap lane.
func (r *g8GapRig) beyondGap(t *testing.T) {
	t.Helper()
	if err := stDeliverData(r.gap, 192<<10, stPattern(192<<10, 32<<10)); err != nil {
		t.Fatal(err)
	}
}

// read reads exactly n in-order bytes in one Read call (one commit, one
// run of the ACK cadence) and checks them.
func (r *g8GapRig) read(t *testing.T, n int) {
	t.Helper()
	buf := make([]byte, n)
	if k, err := r.s.Read(buf); k != n || err != nil {
		t.Fatalf("Read = (%d, %v), want %d bytes in one call (stimulus)", k, err, n)
	}
	if !bytes.Equal(buf, stPattern(r.rd, n)) {
		t.Fatalf("Read at %d returned other bytes", r.rd)
	}
	r.rd += uint64(n)
}

// g8GapSnapshot is the receiver's ACK routing as the stimulus checks see
// it: duty — lane 1 holds the duty and its conn accepts writes; gapSet —
// lane 2 is the gap lane; held — out-of-order data is held; idle — lane 2's
// writer went idle; owes — lane 2 has not placed the current ACK.
type g8GapSnapshot struct {
	duty, gapSet, held, idle, owes bool
}

func (r *g8GapRig) snapshot() g8GapSnapshot {
	blocked := false
	r.dutyP.set(func(f *stPort) { blocked = f.blocked })
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	st := &r.s.st
	return g8GapSnapshot{
		duty:   st.ackLane == r.duty && !blocked,
		gapSet: st.gapLane == r.gap,
		held:   len(st.ooq.s) > 0,
		idle:   r.gap.idle,
		owes:   r.gap.ackSent != st.ackGen,
	}
}

// requireIdleGap checks the state before a stimulus: the duty stays on the
// stalled lane, lane 2 is the gap lane, went idle and placed the current
// ACK (when it became the gap lane), out-of-order data is held.
func (r *g8GapRig) requireIdleGap(t *testing.T) {
	t.Helper()
	if s := r.snapshot(); !s.duty || !s.gapSet || !s.held || !s.idle || s.owes {
		t.Fatalf("before the stimulus: %+v; want the duty on the stalled lane, lane 2 the gap lane, idle and up to date, and out-of-order data held", s)
	}
}

// requireGapAck checks that after mark from the gap lane placed exactly
// one ACK, at time at, acknowledging delivered bytes, by itself: no other
// frame reached the receiver since the stimulus. The duty stays on the
// stalled lane, whose copy of the ACK is lost.
func (r *g8GapRig) requireGapAck(t *testing.T, from int, at time.Time, delivered uint64, what string) {
	t.Helper()
	a := r.acksOn(r.gap.id, from)
	if len(a) != 1 || !a[0].at.Equal(at) || a[0].ack.Delivered != delivered {
		got := []string{}
		for _, x := range a {
			got = append(got, stFrame{typ: wire.TypeAck, ack: x.ack}.String()+" at +"+x.at.Sub(at).String())
		}
		t.Fatalf("after %s the gap lane placed %q; want one ACK(%d) at +0s, placed by its own writer (no wake: the idle gap lane sleeps and the ACK stays in the stalled path)", what, got, delivered)
	}
	if s := r.snapshot(); !s.duty || !s.gapSet || s.owes {
		t.Fatalf("after %s: %+v; want the duty still on the stalled lane and the gap lane up to date", what, s)
	}
}

// close stops the writers and ends the stream; every buffer returns.
func (r *g8GapRig) close(t *testing.T) {
	t.Helper()
	close(r.stop)
	r.wg.Wait()
	stEnd(r.s, errClosed)
	if u := r.s.env.Carrier.Budget.Used(); u != 0 {
		t.Errorf("Budget.Used = %d after the end, want 0", u)
	}
}
