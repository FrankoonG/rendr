package session

import (
	"bytes"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// streamRound is one steady-state 64 KiB round trip between two sessions
// over one link, every step synchronous: Write, the sender's Fill, the
// receiver's reader delivering the DATA in a pooled Buf, Read, the
// receiver's Fill placing the ACK, and the sender processing it (which
// frees the chunk).
type streamRound struct {
	p      *pair
	src    []byte
	dst    []byte
	ba, bb *carrier.Batch
}

func newStreamRound() *streamRound {
	return &streamRound{
		p:   newPair(sopt{window: 1 << 20}, sopt{window: 1 << 20}, 1),
		src: pattern(0, 64<<10), dst: make([]byte, 64<<10),
		ba: carrier.NewBatch(0), bb: carrier.NewBatch(0),
	}
}

func (r *streamRound) run() {
	p := r.p
	if n, err := p.a.Write(r.src); n != len(r.src) || err != nil {
		panic("Write failed in the steady-state round")
	}
	r.ba.Reset(time.Now())
	p.al[0].Fill(nil, r.ba)
	if err := deliver(r.ba, p.bl[0]); err != nil {
		panic(err)
	}
	r.ba.ReleaseRefs()
	for k := 0; k < len(r.dst); {
		n, err := p.b.Read(r.dst[k:])
		if err != nil {
			panic(err)
		}
		k += n
	}
	r.bb.Reset(time.Now())
	p.bl[0].Fill(nil, r.bb)
	if err := deliver(r.bb, p.al[0]); err != nil {
		panic(err)
	}
	r.bb.ReleaseRefs()
}

// TestSteadyStateZeroAllocs_L41_L54 (session half, design §12.2): a
// warmed 64 KiB Write → DATA → Read → ACK round trip and a 256 KiB batch
// Fill allocate nothing — pooled chunks and receive buffers, reused
// batches, span and segment rings that never shrink, latest-wins ACK
// state. The allocation gate runs in the non-race lane (the race detector
// makes sync.Pool drop items on purpose); the round trip's integrity and
// buffer accounting are checked in both lanes.
func TestSteadyStateZeroAllocs_L41_L54(t *testing.T) {
	r := newStreamRound()
	for range 64 {
		r.run()
	}
	if !bytes.Equal(r.dst, r.src) {
		t.Fatal("round trip corrupted the bytes")
	}
	st := locked(r.p.a, func(st *stream) [3]uint64 { return [3]uint64{st.sBase, st.end, uint64(st.chunks.n)} })
	if st[0] != st[1] || st[2] != 0 {
		t.Fatalf("after a round: sBase %d end %d chunks %d, want everything acknowledged and freed", st[0], st[1], st[2])
	}
	if !streamRaceEnabled {
		if a := testing.AllocsPerRun(200, r.run); a != 0 {
			t.Fatalf("steady-state round trip: %v allocations per 64 KiB, want 0", a)
		}
	}

	// One batch of four 64 KiB segments.
	s := newTestSession(sopt{window: 8 << 20})
	l, _ := addLane(s, 1, true)
	s.mu.Lock()
	s.peerWindowLocked(1 << 30)
	s.mu.Unlock()
	b := carrier.NewBatch(0)
	batch := func() {
		if n, err := s.Write(r.src[:]); n != len(r.src) || err != nil {
			panic("Write")
		}
		if n, err := s.Write(r.src[:]); n != len(r.src) || err != nil {
			panic("Write")
		}
		if n, err := s.Write(r.src[:]); n != len(r.src) || err != nil {
			panic("Write")
		}
		if n, err := s.Write(r.src[:]); n != len(r.src) || err != nil {
			panic("Write")
		}
		b.Reset(time.Now())
		l.Fill(nil, b)
		data := 0
		for i := range b.Len() {
			if f := b.Frame(i); f.Header.Type == wire.TypeData {
				data++
			}
		}
		if data != 4 {
			panic("a 256 KiB batch must hold four segments")
		}
		b.ReleaseRefs()
		next := locked(s, func(st *stream) uint64 { return st.sNext })
		if err := sendAck(l, 0, next, 8<<20); err != nil {
			panic(err)
		}
	}
	for range 16 {
		batch()
	}
	if !streamRaceEnabled {
		if a := testing.AllocsPerRun(200, batch); a != 0 {
			t.Fatalf("256 KiB batch: %v allocations, want 0", a)
		}
	}
	endSession(s, errClosed)
	r.p.close(t)
	if u := s.env.Carrier.Budget.Used(); u != 0 {
		t.Fatalf("Budget.Used = %d after the end", u)
	}
}

// dispatchBench is a bond sender with n member lanes; op writes 64 KiB,
// lets the fastest member pull it and acknowledges it.
type dispatchBench struct {
	s     *Session
	ls    []*lane
	ps    []*fakePort
	b     *carrier.Batch
	src   []byte
	calls func() int
}

func newDispatchBench(n int) *dispatchBench {
	d := &dispatchBench{s: newTestSession(sopt{mode: ModeBond, window: 8 << 20}), b: carrier.NewBatch(0), src: pattern(0, 64<<10)}
	for i := range n {
		l, p := addLane(d.s, uint32(i+1), true)
		p.set(func(f *fakePort) { f.srtt = time.Duration(i+1) * time.Millisecond })
		d.ls, d.ps = append(d.ls, l), append(d.ps, p)
	}
	d.s.mu.Lock()
	d.s.peerWindowLocked(1 << 30)
	d.s.refreshOrderLocked(time.Now(), true)
	d.s.mu.Unlock()
	d.calls = func() int {
		c := 0
		for _, p := range d.ps {
			c += p.callCount()
		}
		return c
	}
	return d
}

func (d *dispatchBench) op() {
	if n, err := d.s.Write(d.src); n != len(d.src) || err != nil {
		panic("Write")
	}
	d.b.Reset(time.Now())
	d.ls[0].Fill(nil, d.b)
	d.b.ReleaseRefs()
	next := locked(d.s, func(st *stream) uint64 { return st.sNext })
	if err := sendAck(d.ls[0], 0, next, 8<<20); err != nil {
		panic(err)
	}
}

// TestDispatchCostIndependentOfCarrierCount_L54 (M1-should): dispatching a
// 64 KiB write in a bond (commit wake, the fastest member's Fill, the ACK)
// touches the same number of carrier ports with 2, 6 and 16 members and
// allocates nothing; its time does not grow with the member count (timing
// and allocation gates in the non-race lane only).
func TestDispatchCostIndependentOfCarrierCount_L54(t *testing.T) {
	var calls [3]float64
	var ns [3]float64
	for i, n := range []int{2, 6, 16} {
		d := newDispatchBench(n)
		for range 32 {
			d.op()
		}
		c0 := d.calls()
		const ops = 256
		for range ops {
			d.op()
		}
		calls[i] = float64(d.calls()-c0) / ops
		if !streamRaceEnabled {
			if a := testing.AllocsPerRun(100, d.op); a != 0 {
				t.Fatalf("%d lanes: %v allocations per dispatch, want 0", n, a)
			}
			best := time.Duration(1<<63 - 1)
			for range 5 {
				start := time.Now()
				for range ops {
					d.op()
				}
				best = min(best, time.Since(start))
			}
			ns[i] = float64(best) / ops
		}
		if pulled := locked(d.s, func(st *stream) uint64 { return st.sNext }); pulled == 0 {
			t.Fatal("no dispatch happened (stimulus)")
		}
		endSession(d.s, errClosed)
	}
	t.Logf("port calls per dispatch %v; ns per dispatch %v (2/6/16 lanes)", calls, ns)
	if calls[0] != calls[1] || calls[1] != calls[2] {
		t.Fatalf("port calls per dispatch %v grow with the carrier count", calls)
	}
	if !streamRaceEnabled && ns[2] > 2*ns[0]+2000 {
		t.Fatalf("dispatch with 16 lanes costs %.0f ns vs %.0f ns with 2: grows with the carrier count", ns[2], ns[0])
	}
}

// BenchmarkDispatch measures one bond dispatch with 2, 6 and 16 members
// (perf lane, design §12.4).
func BenchmarkDispatch(b *testing.B) {
	for _, n := range []int{2, 6, 16} {
		b.Run(map[int]string{2: "2", 6: "6", 16: "16"}[n], func(b *testing.B) {
			d := newDispatchBench(n)
			b.SetBytes(64 << 10)
			b.ReportAllocs()
			for b.Loop() {
				d.op()
			}
			endSession(d.s, errClosed)
		})
	}
}

// BenchmarkStreamLoopback measures the synchronous 64 KiB round trip
// between two sessions (perf lane, design §12.4).
func BenchmarkStreamLoopback(b *testing.B) {
	r := newStreamRound()
	b.SetBytes(64 << 10)
	b.ReportAllocs()
	for b.Loop() {
		r.run()
	}
	r.p.close(b)
}
