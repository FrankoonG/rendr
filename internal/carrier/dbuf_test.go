package carrier

import (
	"testing"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestDatagramBufPool (M2-D28; M2 design Revision 1, R1-20): the datagram
// pool's classes are 2 KiB … 64 KiB, each + ClassSlack: Get returns the
// smallest class that holds n for every class edge and for the buffers the
// datagram carriers take (a QUIC or default raw-UDP reader buffer and writer
// scratch in the 2 KiB class, the largest datagram buffer in the 64 KiB
// class). A Buf charges its class capacity once — Get forced, TryGet
// refused without a charge — and uncharges it once at its last Release; it
// returns to the pool it came from, so interleaved use of the stream and
// datagram pools never hands one pool's buffer out of the other (the stream
// classes stay 16 KiB … 1 MiB). A size above the largest class panics, and
// steady-state Get, TryGet, Ref and Release allocate nothing (asserted in
// the non-race lane, as TestBufPoolZeroAllocs_L41).
func TestDatagramBufPool(t *testing.T) {
	p := NewDatagramBufPool()
	const top = 64<<10 + ClassSlack // the largest datagram class
	if got := dgramLayout.limit(); got != top || dgramLayout.size(0) != 2<<10+ClassSlack {
		t.Fatalf("datagram classes %d … %d, want 2 KiB+64 … 64 KiB+64", dgramLayout.size(0), got)
	}

	// Class edges: Get(n) is the smallest class 2^k + 64 (k = 11..16) that
	// holds n.
	sizes := []int{0, 1, top}
	for k := minDgramShift; k <= maxDgramShift; k++ {
		for d := -2; d <= 2; d++ {
			sizes = append(sizes, 1<<k+ClassSlack+d, 1<<k+d)
		}
	}
	for _, n := range sizes {
		if n < 0 || n > top {
			continue
		}
		b := p.Get(n, nil)
		k := minDgramShift
		for 1<<k+ClassSlack < n {
			k++
		}
		if want := 1<<k + ClassSlack; len(b.B) != want || cap(b.B) != want || b.pool != p {
			t.Errorf("Get(%d): len %d cap %d (pool %p), want the 2^%d+64 class of the datagram pool", n, len(b.B), cap(b.B), b.pool, k)
		}
		b.Release()
	}

	// The buffers datagram carriers take (M2-D60, R1-6; §A7.2: a QUIC or
	// default raw-UDP carrier's reader and writer buffers are 2 KiB classes).
	carriers := []struct {
		name string
		n    int
		want int
	}{
		{"QUIC reader buffer: budget 1152 + 1", 1152 + 1, 2<<10 + ClassSlack},
		{"QUIC writer scratch: budget 1152", 1152, 2<<10 + ClassSlack},
		{"raw-UDP reader buffer: default MTU 1223 + flow header + 1", 1223 + wire.FlowHeaderLen + 1, 2<<10 + ClassSlack},
		{"raw-UDP writer scratch: 1223 + flow header", 1223 + wire.FlowHeaderLen, 2<<10 + ClassSlack},
		{"probe carrier reader buffer: MinFrameBudget + flow header + 1", wire.MinFrameBudget + wire.FlowHeaderLen + 1, 2<<10 + ClassSlack},
		{"a 9000-byte jumbo budget", 9000 + wire.FlowHeaderLen + 1, 16<<10 + ClassSlack},
		{"the largest datagram buffer: MaxDatagram + flow header + 1", wire.MaxDatagram + wire.FlowHeaderLen + 1, top},
	}
	for _, c := range carriers {
		b := p.Get(c.n, nil)
		if len(b.B) != c.want {
			t.Errorf("%s (%d bytes): class of %d bytes, want %d", c.name, c.n, len(b.B), c.want)
		}
		b.Release()
	}
	mustPanic(t, "Get(-1)", func() { p.Get(-1, nil) })
	mustPanic(t, "Get(top+1)", func() { p.Get(top+1, nil) })
	mustPanic(t, "TryGet(top+1)", func() { p.TryGet(top+1, NewBudget(1<<30)) })

	// Charges: the class capacity, once; forced by Get, refused by TryGet.
	bud := NewBudget(1 << 30)
	b := p.Get(1500, bud)
	if bud.Used() != 2<<10+ClassSlack || b.refs.Load() != 1 {
		t.Fatalf("Get(1500): charged %d, refs %d; want %d, 1", bud.Used(), b.refs.Load(), 2<<10+ClassSlack)
	}
	b.Ref()
	b.Release()
	if bud.Used() != 2<<10+ClassSlack {
		t.Fatalf("after Ref and one Release: charged %d", bud.Used())
	}
	b.Release()
	if bud.Used() != 0 || b.refs.Load() != 0 {
		t.Fatalf("after the last Release: charged %d, refs %d", bud.Used(), b.refs.Load())
	}
	small := NewBudget(4<<10 + ClassSlack)
	a := p.TryGet(3000, small) // the 4 KiB class: exactly the budget
	if a == nil || small.Used() != small.Max() || len(a.B) != 4<<10+ClassSlack {
		t.Fatalf("TryGet within the budget: %v, charged %d", a, small.Used())
	}
	if c := p.TryGet(1, small); c != nil || small.Used() != small.Max() {
		t.Fatalf("TryGet beyond the budget: %v, charged %d", c, small.Used())
	}
	forced := p.Get(1, small) // a forced charge (the Stages account of a reader buffer)
	if small.Used() != small.Max()+2<<10+ClassSlack {
		t.Fatalf("forced Get: charged %d", small.Used())
	}
	forced.Release()
	a.Release()
	if small.Used() != 0 {
		t.Fatalf("budget %d after every release", small.Used())
	}

	// Each Buf returns to its own pool: interleaved stream and datagram
	// buffers of every class keep their own sizes (a datagram buffer
	// handed out by the stream pool would be too short for its class).
	sp := NewBufPool()
	for i := range 300 {
		dn := 1 << (minDgramShift + i%numDgramClass)
		sn := 1 << (minClassShift + i%numClasses)
		d, s := p.Get(dn, bud), sp.Get(sn, bud)
		if len(d.B) != dn+ClassSlack || d.pool != p || len(s.B) != sn+ClassSlack || s.pool != sp {
			t.Fatalf("cycle %d: datagram Get(%d) len %d, stream Get(%d) len %d", i, dn, len(d.B), sn, len(s.B))
		}
		d.Release()
		s.Release()
	}
	if bud.Used() != 0 {
		t.Fatalf("budget %d after the interleaved cycles", bud.Used())
	}
	if s := sp.Get(1, nil); len(s.B) != 16<<10+ClassSlack {
		t.Fatalf("stream pool class 0: %d bytes, want 16 KiB+64 (unchanged)", len(s.B))
	} else {
		s.Release()
	}

	// Zero allocations in steady state (warm per-class pools).
	cycle := func() {
		r := p.Get(1153, bud)
		r.Ref()
		r.Release()
		r.Release()
		w := p.TryGet(wire.MaxDatagram+wire.FlowHeaderLen+1, bud)
		w.Release()
	}
	cycle()
	allocs := testing.AllocsPerRun(1000, cycle)
	if bud.Used() != 0 {
		t.Fatalf("budget %d after the allocation cycles", bud.Used())
	}
	if bufRaceEnabled {
		t.Logf("race detector on: %v allocs per cycle not asserted (non-race lane only)", allocs)
		return
	}
	if allocs != 0 {
		t.Fatalf("%v allocations per datagram-pool Get/Ref/Release cycle", allocs)
	}
}
