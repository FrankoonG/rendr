package session

import (
	"bytes"
	"io"
	"math"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// dpRound is one steady-state datagram round trip between two packet
// sessions over one datagram lane, every step synchronous: WriteTo, the
// sender's Fill (datagram batch), the receiver's reader handing the DGRAM
// over, ReadFrom, the receiver's Fill (PACK when due) and the sender
// processing it.
type dpRound struct {
	p        *dpPair
	src, dst []byte
}

func dpNewRound(budget *carrier.Budget) *dpRound {
	r := &dpRound{
		p:   dpNewPair(dpOpt{budget: budget}, dpOpt{budget: budget}, true),
		src: dpPayload(1, 1000), dst: make([]byte, 2048),
	}
	// Seq 0 is lost for good: the dedup window must not care (L39).
	if _, err := r.p.a.s.WriteTo(r.src); err != nil {
		panic(err)
	}
	dpFill(r.p.a.ls[0], time.Now()).ReleaseRefs()
	return r
}

func (r *dpRound) run() {
	p := r.p
	if n, err := p.a.s.WriteTo(r.src); n != len(r.src) || err != nil {
		panic("WriteTo failed in the steady-state round")
	}
	b := dpFill(p.a.ls[0], time.Now())
	if err := dpDeliver(b, p.b.ls[0], 0, nil); err != nil {
		panic(err)
	}
	b.ReleaseRefs()
	if n, err := p.b.s.ReadFrom(r.dst); n != len(r.src) || err != nil {
		panic("ReadFrom failed in the steady-state round")
	}
	b = dpFill(p.b.ls[0], time.Now())
	if err := dpDeliver(b, p.a.ls[0], 0, nil); err != nil {
		panic(err)
	}
	b.ReleaseRefs()
}

// TestPacketRoundZeroAllocs_L41_L54: a warmed WriteTo → Fill → Datagram →
// ReadFrom round (PACKs included, seq 0 missing from the dedup window)
// allocates nothing (M2 design §A8.5) and leaves no buffer charged once
// the sessions end. The allocation gate runs in the non-race lane.
func TestPacketRoundZeroAllocs_L41_L54(t *testing.T) {
	budget := carrier.NewBudget(1 << 30)
	r := dpNewRound(budget)
	for range 600 { // past PackEvery: both PACK paths are warm
		r.run()
	}
	if !bytes.Equal(r.dst[:len(r.src)], r.src) {
		t.Fatal("the round trip corrupted the datagram")
	}
	if c := dpCtr(r.p.b.s); c.Received != 600 || c.DropLate != 0 || c.Duplicates != 0 {
		t.Fatalf("receiver counters %+v", c)
	}
	if c := dpCtr(r.p.a.s); c.PeerReceived < 512 {
		t.Fatalf("the sender's PeerReceived %d: PACKs did not flow", c.PeerReceived)
	}
	if !dpRaceEnabled {
		if a := testing.AllocsPerRun(500, r.run); a != 0 {
			t.Fatalf("steady-state datagram round: %v allocations, want 0", a)
		}
	}
	dpEnd(r.p.a.s, io.EOF)
	dpEnd(r.p.b.s, io.EOF)
	if u := budget.Used(); u != 0 {
		t.Fatalf("Budget.Used %d after the end", u)
	}
}

// dpDispatch is a bond sender with n datagram members and a receiver with
// n lanes; op queues one 1000-byte datagram, lets the fastest member place
// it (and go idle), and hands it to the receiver, which reads it.
type dpDispatch struct {
	s, r   *Session
	ls     []*lane
	ps     []*dpPort
	rl     *lane
	rps    []*dpPort
	src    []byte
	dst    []byte
	seq    uint64
	frames int
}

func dpNewDispatch(n int) *dpDispatch {
	d := &dpDispatch{
		s:   dpSession(dpOpt{mode: ModeBond}),
		r:   dpSession(dpOpt{role: RolePassive, mode: ModeBond}),
		src: dpPayload(1, 1000), dst: make([]byte, 2048),
	}
	for i := range n {
		l, p := dpAddLane(d.s, uint32(i+1), true, true)
		p.set(func(f *dpPort) { f.srtt = time.Duration(i+1) * time.Millisecond })
		d.ls, d.ps = append(d.ls, l), append(d.ps, p)
		rl, rp := dpAddLane(d.r, uint32(i+1), true, true)
		rp.set(func(f *dpPort) { f.srtt = time.Duration(i+1) * time.Millisecond })
		if i == 0 {
			d.rl = rl
		}
		d.rps = append(d.rps, rp)
	}
	for _, s := range []*Session{d.s, d.r} {
		s.mu.Lock()
		s.refreshOrderLocked(time.Now(), true)
		s.mu.Unlock()
	}
	for _, l := range d.ls {
		dpIdle(l)
	}
	return d
}

func (d *dpDispatch) op() {
	if n, err := d.s.WriteTo(d.src); n != len(d.src) || err != nil {
		panic("WriteTo")
	}
	for range 2 { // the writer's self-continuation: the second Fill finds nothing
		b := dpFill(d.ls[0], time.Now())
		for i := range b.Len() {
			if f := b.Frame(i); f.Header.Type == wire.TypeDgram {
				d.frames++
				if err := (*plane)(d.rl).Datagram(nil, d.seq, f.Body, nil); err != nil {
					panic(err)
				}
				d.seq++
			}
		}
		b.ReleaseRefs()
	}
	if _, err := d.r.ReadFrom(d.dst); err != nil {
		panic(err)
	}
}

func (d *dpDispatch) calls() int {
	c := 0
	for _, p := range append(d.ps[:len(d.ps):len(d.ps)], d.rps...) {
		c += p.callCount()
	}
	return c
}

// TestPacketDispatchCostFlat_L54: dispatching a datagram in a bond — the
// WriteTo wake, the member's Fill, the receiver's hand-over and ReadFrom —
// touches the same number of carrier ports with 2, 6 and 16 members (16 =
// MaxCarriersPerSession's maximum), allocates nothing, and its time does
// not grow with the member count (timing and allocation gates in the
// non-race lane).
func TestPacketDispatchCostFlat_L54(t *testing.T) {
	var calls [3]float64
	sizes := []int{2, 6, 16}
	synctest.Test(t, func(t *testing.T) {
		for i, n := range sizes {
			d := dpNewDispatch(n)
			for range 32 {
				d.op()
			}
			c0 := d.calls()
			const ops = 256
			for range ops {
				d.op()
			}
			calls[i] = float64(d.calls()-c0) / ops
			if d.frames != 32+ops {
				t.Fatalf("%d lanes: %d datagrams placed, want %d (stimulus)", n, d.frames, 32+ops)
			}
			if !dpRaceEnabled {
				if a := testing.AllocsPerRun(100, d.op); a != 0 {
					t.Fatalf("%d lanes: %v allocations per dispatch, want 0", n, a)
				}
			}
			dpEnd(d.s, io.EOF)
			dpEnd(d.r, io.EOF)
		}
	})
	t.Logf("port calls per dispatch %v (2/6/16 lanes)", calls)
	if calls[0] != calls[1] || calls[1] != calls[2] {
		t.Fatalf("port calls per dispatch %v grow with the carrier count", calls)
	}
	if dpRaceEnabled {
		return
	}
	var ns [3]float64
	for i, n := range sizes {
		d := dpNewDispatch(n)
		for range 64 {
			d.op()
		}
		// The host clock may tick coarsely (Windows): time at least 50 ms
		// per sample, best of three.
		ns[i] = math.Inf(1)
		for range 3 {
			ops, start := 0, time.Now()
			for time.Since(start) < 50*time.Millisecond {
				for range 256 {
					d.op()
				}
				ops += 256
			}
			ns[i] = min(ns[i], float64(time.Since(start))/float64(ops))
		}
		dpEnd(d.s, io.EOF)
		dpEnd(d.r, io.EOF)
	}
	t.Logf("ns per dispatch %v (2/6/16 lanes)", ns)
	if ns[2] > 1.5*ns[0]+2000 {
		t.Fatalf("dispatch with 16 lanes costs %.0f ns vs %.0f ns with 2: grows with the carrier count", ns[2], ns[0])
	}
}
