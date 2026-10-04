package session

import (
	"bytes"
	"errors"
	"math/rand/v2"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestNoReaderBoundsAck_L15: with no application reader, the receiver
// accepts exactly one window, its ACKs never acknowledge more than the
// application consumed (Delivered stays at the start, Delivered + Window
// at most W), the sender's Write blocks without error once its send
// buffer is full, and nothing is a violation. A reader then drains all.
func TestNoReaderBoundsAck_L15(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const w = 256 << 10
		p := stNewPair(stOpt{window: w}, stOpt{window: w}, 1)
		stop := make(chan struct{})
		var wg sync.WaitGroup
		p.runPair(&wg, stop)
		defer func() {
			select {
			case <-stop:
			default:
				close(stop)
			}
			wg.Wait()
		}()
		msg := stPattern(0, 2*w)
		wres := make(chan stIO, 1)
		go func() {
			n, err := p.a.Write(msg)
			wres <- stIO{n, err}
		}()
		synctest.Wait()
		if len(wres) != 0 {
			r := <-wres
			t.Fatalf("Write of 2·W returned (%d, %v) with no reader", r.n, r.err)
		}
		rx := stLocked(p.b, func(st *stream) [3]uint64 { return [3]uint64{st.rRead, st.rTail, st.rightEdge} })
		if rx[0] != 0 || rx[1] != w || rx[2] != w {
			t.Fatalf("receiver rRead=%d rTail=%d edge=%d, want 0, W, W", rx[0], rx[1], rx[2])
		}
		tx := stLocked(p.a, func(st *stream) [3]uint64 { return [3]uint64{st.sBase, st.sNext, st.end} })
		if tx != [3]uint64{0, w, w} {
			t.Fatalf("sender sBase/sNext/end = %v, want 0, W, W", tx)
		}
		p.mu.Lock()
		acks := 0
		for _, f := range p.traceBA {
			if f.typ != wire.TypeAck {
				continue
			}
			acks++
			if f.ack.Delivered != 0 || uint64(f.ack.Delivered)+uint64(f.ack.Window) > w {
				p.mu.Unlock()
				t.Fatalf("ACK %v acknowledges unread bytes or opens beyond W", f)
			}
		}
		p.mu.Unlock()
		if acks == 0 {
			t.Fatal("the receiver sent no ACK (stimulus)")
		}
		if errs := p.errors(); len(errs) != 0 {
			t.Fatalf("violations without a reader: %v", errs)
		}
		if u := p.b.env.Carrier.Budget.Used(); u > w+w/4 {
			t.Fatalf("receiver holds %d bytes of buffers for a %d-byte window", u, w)
		}

		got := stReadAsync(p.b, len(msg))
		r := <-wres
		if r.n != len(msg) || r.err != nil {
			t.Fatalf("Write once a reader appeared = (%d, %v)", r.n, r.err)
		}
		if g := <-got; g.err != nil || !bytes.Equal(g.b, msg) {
			t.Fatalf("read: %v", g.err)
		}
		close(stop)
		wg.Wait()
		p.close(t)
	})
}

// TestHeldHeadBoundsHeap_L15: the peer withholds the first byte and sends
// 64 MiB (16 MiB under -race) in frames of 1 B–64 KiB at random offsets,
// overlapping and repeating; frames beyond the window are violations that
// kill their carrier. The receive memory stays below 2·W plus one run (the
// out-of-order cap, D13); the excess is dropped and counted.
func TestHeldHeadBoundsHeap_L15(t *testing.T) {
	const w = 1 << 20
	total := 64 << 20
	if streamRaceEnabled {
		total = 16 << 20
	}
	s := stSession(stOpt{role: RolePassive, window: w})
	budget := s.env.Carrier.Budget
	l, _ := stAddLane(s, 1, false)
	ids := uint32(1)
	rng := rand.New(rand.NewPCG(15, 15))
	fed, kills := 0, 0
	var maxUsed int64
	for fed < total {
		var off uint64
		var size int
		if rng.IntN(2) == 0 { // a sparse tiny frame: one new run each
			off, size = 1+2*uint64(rng.IntN(w/2-1)), 1+rng.IntN(64)
		} else {
			off, size = 1+uint64(rng.IntN(w+w/16)), 1+rng.IntN(64<<10)
		}
		err := stDeliverData(l, off, stPattern(off, size))
		switch {
		case err == nil:
		case errors.Is(err, errWindow) && off+uint64(size) > w:
			kills++ // that carrier dies; the peer continues on another
			ids++
			l, _ = stAddLane(s, ids, false)
		default:
			t.Fatalf("frame [%d,+%d): %v", off, size, err)
		}
		fed += size
		maxUsed = max(maxUsed, budget.Used())
	}
	st := stLocked(s, func(st *stream) [4]uint64 {
		return [4]uint64{st.rRead, st.rTail, st.oooDropped, uint64(st.oooCap)}
	})
	t.Logf("fed %d MiB, %d carrier kills, peak %d KiB, dropped %d KiB", fed>>20, kills, maxUsed>>10, st[2]>>10)
	if maxUsed > 2*w+runCap {
		t.Fatalf("receive memory peaked at %d bytes, want ≤ 2·W + one run = %d", maxUsed, 2*w+runCap)
	}
	if st[0] != 0 || st[1] != 0 {
		t.Fatalf("rRead %d rTail %d with the head withheld, want 0", st[0], st[1])
	}
	if st[2] == 0 || kills == 0 || st[3] == 0 {
		t.Fatalf("stimulus missing: dropped %d, kills %d, cap %d", st[2], kills, st[3])
	}
	// The head arrives: the contiguous prefix is readable and intact.
	if err := l.Data(nil, 0, stPattern(0, 1), nil); err != nil {
		t.Fatal(err)
	}
	n := stLocked(s, func(st *stream) int { return int(st.rTail) })
	if got := stReadN(t, s, n); !bytes.Equal(got, stPattern(0, n)) {
		t.Fatal("reordered bytes corrupted")
	}
	stEnd(s, errClosed)
	if u := budget.Used(); u != 0 {
		t.Fatalf("Budget.Used = %d after the end", u)
	}
}

// TestRightEdgeNeverRetracts_L15 (P10): under memory pressure a newly
// placed ACK advertises less (or zero) but the right edge — the largest
// edge ever advertised, the receiver's fatal threshold — never moves left,
// so bytes the sender honestly sent up to it are accepted. Once the window
// fell below 64 KiB the actor is rung (W6) and re-advertisement keeps
// asking until an ACK carrying at least 64 KiB was actually placed.
func TestRightEdgeNeverRetracts_L15(t *testing.T) {
	const w = 8 << 20
	budget := carrier.NewBudget(64 << 20)
	s := stSession(stOpt{role: RolePassive, window: w, budget: budget})
	l, _ := stAddLane(s, 1, false)
	var edges []uint64
	place := func() wire.Ack {
		t.Helper()
		s.mu.Lock()
		s.bumpNowLocked()
		s.mu.Unlock()
		fs, b := stFill(l, time.Now())
		b.ReleaseRefs()
		for _, f := range fs {
			if f.typ == wire.TypeAck {
				e := f.ack.Delivered + uint64(f.ack.Window)
				if n := len(edges); n > 0 && e < edges[n-1] {
					t.Fatalf("advertised edge retracted: %d after %d", e, edges[n-1])
				}
				edges = append(edges, e)
				return f.ack
			}
		}
		t.Fatal("no ACK placed")
		return wire.Ack{}
	}
	pressure := func(frac float64) func() {
		n := int64(frac*float64(budget.Max())) - budget.Used()
		budget.Acquire(n)
		return func() { budget.Release(n) }
	}
	takeBell := func() bool {
		select {
		case <-s.mb.bell:
			return true
		default:
			return false
		}
	}

	if a := place(); a.Window != w {
		t.Fatalf("unpressured window %d, want W", a.Window)
	}
	if err := stDeliverRange(l, 0, stPattern(0, 4<<20)); err != nil {
		t.Fatal(err)
	}
	stReadN(t, s, 1<<20)
	undo := pressure(0.9) // AdvertiseWindow → max(64 KiB, W·0.4) < W
	a := place()
	if a.Delivered != 1<<20 || a.Window != w-1<<20 {
		t.Fatalf("pressured ACK %+v: the edge must stay at W (window W − 1 MiB), not retract", a)
	}
	// Honest bytes up to the old edge are still accepted under pressure.
	if err := stDeliverRange(l, 4<<20, stPattern(4<<20, w-4<<20)); err != nil {
		t.Fatalf("bytes up to the advertised edge rejected under pressure: %v", err)
	}
	if err := l.Data(nil, w, []byte{1}, nil); !errors.Is(err, errWindow) {
		t.Fatalf("a byte beyond the largest edge = %v, want the window violation", err)
	}
	undo()
	stReadN(t, s, w-1<<20)
	undo = pressure(1.0) // advertise 0
	takeBell()
	if a := place(); a.Window != 0 || a.Delivered != w {
		t.Fatalf("ACK at 100%% = %+v, want window 0 at the old edge", a)
	}
	if !takeBell() {
		t.Fatal("the ACK that took the window below 64 KiB did not ring the actor (W6)")
	}
	s.mu.Lock()
	again := s.readvertiseLocked(time.Now())
	s.mu.Unlock()
	if !again {
		t.Fatal("readvertise reports nothing to do while the advertised window is 0")
	}
	undo()
	s.mu.Lock()
	gen := s.st.ackGen
	again = s.readvertiseLocked(time.Now())
	bumped := s.st.ackGen != gen
	s.mu.Unlock()
	if !again || !bumped {
		t.Fatalf("readvertise after the pressure ended: keep=%v bumped=%v, want true, true (until an ACK is placed)", again, bumped)
	}
	fs, b := stFill(l, time.Now())
	b.ReleaseRefs()
	if len(fs) != 1 || fs[0].ack.Window != w {
		t.Fatalf("re-advertised ACK %v, want the full window", fs)
	}
	s.mu.Lock()
	again = s.readvertiseLocked(time.Now())
	s.mu.Unlock()
	if again {
		t.Fatal("readvertise still active after a full window was placed")
	}
	stEnd(s, errClosed)
	if u := budget.Used(); u != 0 {
		t.Fatalf("Budget.Used = %d after the end", u)
	}
}
