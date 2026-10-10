package session

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// The passive's pre-verdict rule at the session level (M4 design §A5.1,
// §A5.2; M4-D2, M4-D5, M4-D6; WP9b): lane.Data on a pending passive
// session. The end-to-end rows through a Runtime admission are in the root
// package (wp9b_early_*_test.go).

// ebPending returns a pending passive session as NewPending leaves it — the
// stream initialized, nothing advertised (rightEdge = FirstOffset), state
// pending — with earlyOpen set when some OPEN carried EARLY.
func ebPending(first uint64, earlyOpen bool, budget *carrier.Budget) *Session {
	if budget == nil {
		budget = carrier.NewBudget(1 << 30)
	}
	env := &Env{Carrier: &carrier.Env{
		Bufs: carrier.NewBufPool(), Budget: budget,
		Timing: carrier.Timing{PingBusy: 50 * time.Millisecond, BatchBudget: 256 << 10},
	}}
	s := &Session{env: env, p: Params{
		Role: RolePassive, Mode: ModeSelector, Window: 1 << 20,
		AckEvery: 64 << 10, AckDelay: 20 * time.Millisecond, FirstOffset: first, FirstEpoch: 1,
	}}
	s.mb.init()
	s.mu.Lock()
	s.initStreamLocked()
	s.ctl.state = StatePending
	s.st.earlyOpen = earlyOpen
	s.mu.Unlock()
	return s
}

// ebLane adds a lane whose own first frame was an OPEN(EARLY) (early) or
// not — a duplicate OPEN without the flag, or a JOIN lane, which is never
// early (onAdoptLocked sets early only from the adopted OPEN's flag).
func ebLane(s *Session, id uint32, early bool) *lane {
	l, _ := stAddLane(s, id, false)
	s.mu.Lock()
	l.early = early
	s.mu.Unlock()
	return l
}

// ebConfirm opens the session as onConfirmLocked does for the stream (the
// state, then the OPEN_ACK window) and returns that window.
func ebConfirm(s *Session) uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ctl.state = StateOpen
	return s.openWindowLocked()
}

// ebState returns rTail − FirstOffset, earlyBytes and the receive charge.
func ebState(s *Session) (tail, early uint64, charge int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.rTail - s.p.FirstOffset, s.st.earlyBytes, s.st.oooCap
}

// TestEarlyOnJoinCarrierKills: pre-verdict DATA on a lane that did not
// open with OPEN(EARLY) — a JOIN lane, also on a session whose first OPEN
// was EARLY (st.earlyOpen) — is errDataBeforeOpen, the error with which
// the carrier reader kills its carrier (protocol_violation); the pending
// session keeps what it held and its EARLY lane still takes early DATA,
// and Confirm opens it with every byte readable once. (A real JOIN for a
// pending session is refused BAD_REQUEST before it becomes a lane:
// TestEarlyJoinBeforeVerdictRefused in the root package.)
func TestEarlyOnJoinCarrierKills(t *testing.T) {
	s := ebPending(0, true, nil)
	defer stEnd(s, errors.New("test over"))
	open := ebLane(s, 1, true)
	join := ebLane(s, 2, false)
	want := stPattern(0, 3000)
	if err := stDeliverData(open, 0, want[:1000]); err != nil {
		t.Fatalf("early DATA on the EARLY lane: %v", err)
	}
	for _, c := range []struct {
		off uint64
		n   int
	}{{0, 1000}, {1000, 500}, {0, 20 << 10}} {
		p := stPattern(c.off, c.n)
		if err := stDeliverData(join, c.off, p); !errors.Is(err, errDataBeforeOpen) {
			t.Fatalf("DATA(%d, %d) on the JOIN lane: %v, want errDataBeforeOpen", c.off, c.n, err)
		}
	}
	if tail, early, _ := ebState(s); tail != 1000 || early != 1000 {
		t.Fatalf("after the JOIN lane's DATA: tail %d early %d, want 1000 each", tail, early)
	}
	if err := stDeliverData(open, 1000, want[1000:]); err != nil {
		t.Fatalf("the EARLY lane after the violation: %v", err)
	}
	if w := ebConfirm(s); w < wire.EarlyWindow {
		t.Fatalf("window %d, want ≥ %d", w, wire.EarlyWindow)
	}
	if got := stReadN(t, s, len(want)); !bytes.Equal(got, want) {
		t.Fatal("bytes differ")
	}
	if st := s.Status(); st.EarlyBytes != uint64(len(want)) || st.DeliveredBytes != uint64(len(want)) {
		t.Fatalf("EarlyBytes %d delivered %d, want %d each", st.EarlyBytes, st.DeliveredBytes, len(want))
	}
}

// TestEarlyRecvRule: the bounds of earlyDataLocked. The early span is
// [FirstOffset, FirstOffset + EarlyWindow) — also with a non-zero first
// offset (the testhooks preset): DATA ending exactly at its end is taken,
// one byte beyond is errDataBeforeOpen and leaves the held bytes intact; a
// wrapping or empty frame is refused; out-of-order early DATA is held and
// counted, duplicates are not counted again, a differing copy is
// errConflict (L13); early bytes are charged and released with the
// session's receive state; after the verdict EarlyBytes is frozen; an
// ended session discards early DATA without an error (M4-D8).
func TestEarlyRecvRule(t *testing.T) {
	for _, first := range []uint64{0, 1<<40 + 12345} {
		budget := carrier.NewBudget(1 << 30)
		s := ebPending(first, true, budget)
		l := ebLane(s, 1, true)
		end := first + wire.EarlyWindow
		want := stPattern(first, wire.EarlyWindow)
		at := func(o uint64) uint64 { return o - first }

		// Out of order first, then a duplicate, then a conflict.
		if err := stDeliverData(l, end-1000, want[at(end-1000):]); err != nil {
			t.Fatalf("first %d: out-of-order tail: %v", first, err)
		}
		if err := stDeliverData(l, end-1000, want[at(end-1000):]); err != nil {
			t.Fatalf("first %d: duplicate: %v", first, err)
		}
		bad := bytes.Clone(want[at(end-1000):at(end-900)])
		bad[3] ^= 1
		if err := stDeliverData(l, end-1000, bad); !errors.Is(err, errConflict) {
			t.Fatalf("first %d: conflicting copy: %v, want errConflict", first, err)
		}
		// Beyond the span, wrapping and empty frames.
		for _, c := range []struct {
			off uint64
			p   []byte
		}{
			{end - 10, stPattern(end-10, 11)},
			{end, stPattern(end, 1)},
			{first + 1<<20, stPattern(first+1<<20, 100)},
			{^uint64(0) - 5, make([]byte, 10)},
		} {
			if err := stDeliverData(l, c.off, c.p); !errors.Is(err, errDataBeforeOpen) {
				t.Fatalf("first %d: DATA(%d, %d): %v, want errDataBeforeOpen", first, c.off, len(c.p), err)
			}
		}
		if err := stDeliverData(l, first, nil); err == nil {
			t.Fatalf("first %d: an empty frame was taken", first)
		}
		if tail, early, _ := ebState(s); tail != 0 || early != 1000 {
			t.Fatalf("first %d: tail %d early %d, want 0 and 1000 (held out of order)", first, tail, early)
		}
		// The rest of the span, in frames of 16 KiB + 1 (by reference)
		// and smaller ones (copied).
		for off := first; off < end-1000; {
			n := min(int(end-1000-off), 16<<10+1)
			if err := stDeliverData(l, off, want[at(off):at(off)+uint64(n)]); err != nil {
				t.Fatalf("first %d: DATA(%d, %d): %v", first, off, n, err)
			}
			off += uint64(n)
		}
		tail, early, charge := ebState(s)
		if tail != wire.EarlyWindow || early != wire.EarlyWindow {
			t.Fatalf("first %d: tail %d early %d, want %d each", first, tail, early, wire.EarlyWindow)
		}
		if charge < wire.EarlyWindow || budget.Used() != charge {
			t.Fatalf("first %d: charge %d budget %d, want equal and ≥ %d", first, charge, budget.Used(), wire.EarlyWindow)
		}
		s.mu.Lock()
		state, delivered, dup := s.ctl.state, s.st.delivered, s.st.dupBytes
		s.mu.Unlock()
		if state != StatePending || delivered != 0 || dup != 1000 {
			t.Fatalf("first %d: state %v delivered %d dup %d, want pending, 0, 1000", first, state, delivered, dup)
		}
		if w := ebConfirm(s); w < wire.EarlyWindow {
			t.Fatalf("first %d: window %d, want ≥ %d", first, w, wire.EarlyWindow)
		}
		// After the verdict: ordinary DATA, EarlyBytes frozen.
		more := stPattern(end, 5000)
		if err := stDeliverData(l, end, more); err != nil {
			t.Fatalf("first %d: DATA after Confirm: %v", first, err)
		}
		if got := stReadN(t, s, wire.EarlyWindow+len(more)); !bytes.Equal(got, append(bytes.Clone(want), more...)) {
			t.Fatalf("first %d: bytes differ", first)
		}
		if st := s.Status(); st.EarlyBytes != wire.EarlyWindow {
			t.Fatalf("first %d: EarlyBytes %d after the verdict, want %d (frozen)", first, st.EarlyBytes, wire.EarlyWindow)
		}
		stEnd(s, errors.New("test over"))
		if u := budget.Used(); u != 0 {
			t.Fatalf("first %d: %d bytes still charged after the end", first, u)
		}
	}

	// Refusal: the held bytes are released with the receive state, and
	// early DATA arriving after the verdict is discarded without an error.
	budget := carrier.NewBudget(1 << 30)
	s := ebPending(0, true, budget)
	l := ebLane(s, 1, true)
	if err := stDeliverData(l, 0, stPattern(0, 40000)); err != nil {
		t.Fatal(err)
	}
	if budget.Used() == 0 {
		t.Fatal("premise: nothing charged")
	}
	stEnd(s, ErrCapacity)
	if u := budget.Used(); u != 0 {
		t.Fatalf("%d bytes still charged after the refusal", u)
	}
	if err := stDeliverData(l, 40000, stPattern(40000, 20000)); err != nil {
		t.Fatalf("early DATA after the verdict: %v, want discarded", err)
	}
	if u := budget.Used(); u != 0 {
		t.Fatalf("the discarded DATA charged %d bytes", u)
	}
}

// TestEarlyOpenWindowFloor: Confirm's window is at least the early span for
// a session that took an OPEN(EARLY) — also with no early byte arrived yet
// and the Budget full (AdvertiseWindow 0) — and the normal window
// otherwise (M4-D6).
func TestEarlyOpenWindowFloor(t *testing.T) {
	for _, earlyOpen := range []bool{false, true} {
		budget := carrier.NewBudget(1 << 30)
		budget.Acquire(budget.Max())
		s := ebPending(0, earlyOpen, budget)
		w := ebConfirm(s)
		switch {
		case earlyOpen && w < wire.EarlyWindow:
			t.Fatalf("EARLY under pressure: window %d, want ≥ %d", w, wire.EarlyWindow)
		case !earlyOpen && w != 0:
			t.Fatalf("premise: without EARLY under pressure the window is %d, want 0", w)
		}
		budget.Release(budget.Max())
		stEnd(s, errors.New("test over"))
	}
}

// TestEarlyPendingSparseBounded_L48: sparse out-of-order early DATA — one
// byte at every other offset of the early span, each of which would take
// a 16 KiB run — cannot make a pending session hold more than about twice
// the early span: beyond earlyRecvLimit it is dropped (V3: counted, never
// a violation). The in-order span that follows is taken whole, the held
// sparse segments are shed as needed, and after Confirm every byte reads
// back once and in order.
func TestEarlyPendingSparseBounded_L48(t *testing.T) {
	budget := carrier.NewBudget(1 << 30)
	s := ebPending(0, true, budget)
	defer stEnd(s, errors.New("test over"))
	l := ebLane(s, 1, true)
	want := stPattern(0, wire.EarlyWindow)
	sent := 0
	for off := uint64(2); off < wire.EarlyWindow; off += 2 {
		if err := stDeliverData(l, off, want[off:off+1]); err != nil {
			t.Fatalf("sparse DATA(%d): %v", off, err)
		}
		sent++
	}
	s.mu.Lock()
	charge, dropped, segs := s.st.oooCap, s.st.oooDropped, len(s.st.ooq.s)
	s.mu.Unlock()
	if charge > earlyRecvLimit || budget.Used() != charge {
		t.Fatalf("sparse early DATA charges %d (budget %d), want ≤ %d", charge, budget.Used(), earlyRecvLimit)
	}
	if dropped == 0 || segs == 0 {
		t.Fatalf("premise: %d sparse frames held in %d segments, %d dropped: want some of each", sent, segs, dropped)
	}
	for off := 0; off < wire.EarlyWindow; off += 16 << 10 {
		if err := stDeliverData(l, uint64(off), want[off:off+16<<10]); err != nil {
			t.Fatalf("in-order DATA(%d): %v", off, err)
		}
		if c := stLocked(s, func(st *stream) int64 { return st.oooCap }); c > earlyRecvLimit+int64(carrier.BigData+carrier.ClassSlack) {
			t.Fatalf("charge %d after in-order DATA(%d), want about ≤ %d", c, off, earlyRecvLimit)
		}
	}
	if tail, early, _ := ebState(s); tail != wire.EarlyWindow || early != wire.EarlyWindow {
		t.Fatalf("tail %d early %d, want %d each", tail, early, wire.EarlyWindow)
	}
	ebConfirm(s)
	if got := stReadN(t, s, wire.EarlyWindow); !bytes.Equal(got, want) {
		t.Fatal("bytes differ")
	}
}
