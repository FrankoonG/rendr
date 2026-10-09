package session

import (
	"bytes"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestPacketBoundaries_L36: datagram boundaries survive the plane exactly
// (5, 11, 257, an empty and a MaxPayload-sized datagram), on a datagram
// lane and on a stream lane; a 37-byte datagram read into 7 bytes returns
// (7, io.ErrShortBuffer) with the prefix, the rest is discarded and the
// next datagram is intact.
func TestPacketBoundaries_L36(t *testing.T) {
	for _, dg := range []bool{true, false} {
		t.Run(map[bool]string{true: "datagram", false: "stream"}[dg], func(t *testing.T) {
			p := dpNewPair(dpOpt{}, dpOpt{}, dg)
			sizes := []int{5, 11, 257, 0, 1375}
			var want [][]byte
			for i, n := range sizes {
				d := dpPayload(uint64(i), n)
				want = append(want, d)
				if k, err := p.a.s.WriteTo(d); k != n || err != nil {
					t.Fatalf("WriteTo(%d) = %d, %v", n, k, err)
				}
			}
			dpSettle(t, p, nil)
			got, err := dpReadAll(t, p.b.s)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(want) {
				t.Fatalf("read %d datagrams, want %d", len(got), len(want))
			}
			for i := range want {
				if !bytes.Equal(got[i], want[i]) {
					t.Fatalf("datagram %d: %d bytes %x…, want %d bytes", i, len(got[i]), got[i][:min(8, len(got[i]))], len(want[i]))
				}
			}

			long, next := dpPayload(99, 37), dpPayload(100, 3)
			for _, d := range [][]byte{long, next} {
				if k, err := p.a.s.WriteTo(d); k != len(d) || err != nil {
					t.Fatalf("WriteTo = %d, %v", k, err)
				}
			}
			dpSettle(t, p, nil)
			small := make([]byte, 7)
			if n, err := p.b.s.ReadFrom(small); n != 7 || err != io.ErrShortBuffer {
				t.Fatalf("ReadFrom(7 of 37) = %d, %v; want 7, io.ErrShortBuffer", n, err)
			}
			if !bytes.Equal(small, long[:7]) {
				t.Fatalf("short read %x, want the prefix %x", small, long[:7])
			}
			buf := make([]byte, 64)
			if n, err := p.b.s.ReadFrom(buf); n != 3 || err != nil || !bytes.Equal(buf[:3], next) {
				t.Fatalf("next ReadFrom = %d, %v (%x); want the 3-byte datagram intact", n, err, buf[:n])
			}
			c := dpCtr(p.b.s)
			if c.Received != 7 || c.Duplicates != 0 || c.DropLate != 0 || c.DropRecvQueue != 0 {
				t.Fatalf("receiver counters %+v", c)
			}
			if c := dpCtr(p.a.s); c.Sent != 7 {
				t.Fatalf("sender Sent %d, want 7", c.Sent)
			}
		})
	}
}

// TestPacketTooLarge_L37: WriteTo above MaxPayload fails with
// ErrPacketTooLarge (a net.Error, not a timeout) and changes nothing;
// exactly MaxPayload is carried. A received DGRAM above MaxPayload is a
// violation of its carrier. Datagrams of BigData and more travel by
// reference on both sides. After a budget shrink (M2-D45) a head above the
// lane's DgramRoom goes to another live data lane that can carry it, or is
// dropped (DropTooLarge) when none can.
func TestPacketTooLarge_L37(t *testing.T) {
	p := dpNewPair(dpOpt{maxPayload: 1200}, dpOpt{maxPayload: 1200}, true)
	type snap struct {
		ctr     PacketCounters
		queued  int
		txBytes uint64
	}
	take := func() snap {
		return dpLocked(p.a.s, func(st *stream, pk *packet) snap { return snap{pk.ctr, pk.tx.n, st.txBytes} })
	}
	before := take()
	n, err := p.a.s.WriteTo(make([]byte, 1201))
	if n != 0 || err != ErrPacketTooLarge {
		t.Fatalf("WriteTo(1201) = %d, %v; want 0, ErrPacketTooLarge", n, err)
	}
	var ne net.Error
	if !errors.As(err, &ne) || ne.Timeout() {
		t.Fatalf("ErrPacketTooLarge must be a net.Error without Timeout: %T", err)
	}
	if after := take(); after != before {
		t.Fatalf("a refused WriteTo changed state: %+v → %+v", before, after)
	}
	dpWrite(t, p.a.s, 1, 1200)
	dpSettle(t, p, nil)
	if got, _ := dpReadAll(t, p.b.s); len(got) != 1 || len(got[0]) != 1200 {
		t.Fatalf("MaxPayload datagram not carried: %d datagrams", len(got))
	}
	rc := dpCtr(p.b.s)
	if err := (*plane)(p.b.ls[0]).Datagram(nil, 50, make([]byte, 1201), nil); err != errDgramTooLarge {
		t.Fatalf("received DGRAM above MaxPayload: %v, want errDgramTooLarge", err)
	}
	if dpCtr(p.b.s) != rc {
		t.Fatal("a violating DGRAM changed the receiver's counters")
	}

	t.Run("big", func(t *testing.T) {
		budget := carrier.NewBudget(1 << 30)
		q := dpNewPair(dpOpt{maxPayload: wire.MaxPacketPayload, budget: budget}, dpOpt{maxPayload: wire.MaxPacketPayload, budget: budget}, false)
		sizes := []int{40000, carrier.BigData, carrier.BigData - 1, wire.MaxPacketPayload}
		for i, n := range sizes {
			dpWrite(t, q.a.s, uint64(i), n)
		}
		dpSettle(t, q, nil)
		got, err := dpReadAll(t, q.b.s)
		if err != nil || len(got) != len(sizes) {
			t.Fatalf("read %d, %v", len(got), err)
		}
		for i, n := range sizes {
			if !bytes.Equal(got[i], dpPayload(uint64(i), n)) {
				t.Fatalf("datagram %d (%d bytes) corrupted", i, n)
			}
		}
		dpEnd(q.a.s, io.EOF)
		dpEnd(q.b.s, io.EOF)
		if u := budget.Used(); u != 0 {
			t.Fatalf("Budget.Used %d after the end, want 0", u)
		}
	})

	t.Run("shrink", func(t *testing.T) {
		// Selector: the only data lane's budget shrank below the head.
		s := dpSession(dpOpt{})
		l, fp := dpAddLane(s, 1, true, true)
		dpWrite(t, s, 1, 1000)
		dpWrite(t, s, 2, 500)
		fp.set(func(f *dpPort) { f.budget = 600 })
		fs := dpFrames(dpFill(l, time.Now()))
		var seqs []uint64
		for _, f := range fs {
			if f.typ == wire.TypeDgram {
				seqs = append(seqs, f.seq)
				if len(f.body) != 500 {
					t.Fatalf("placed a %d-byte datagram on a 575-byte lane", len(f.body))
				}
			}
		}
		if len(seqs) != 1 || seqs[0] != 0 {
			t.Fatalf("placed seqs %v, want [0] (a dropped datagram consumes no seq)", seqs)
		}
		if c := dpCtr(s); c.DropTooLarge != 1 || c.Sent != 1 {
			t.Fatalf("counters %+v, want DropTooLarge 1, Sent 1", c)
		}

		// Bond: the head goes to the member that can carry it.
		b := dpSession(dpOpt{mode: ModeBond})
		l1, p1 := dpAddLane(b, 1, true, true)
		l2, p2 := dpAddLane(b, 2, true, true)
		p1.set(func(f *dpPort) { f.srtt = time.Millisecond; f.budget = 600 })
		p2.set(func(f *dpPort) { f.srtt = 2 * time.Millisecond })
		dpIdle(l1)
		dpIdle(l2)
		w := p2.wakeCount()
		dpWrite(t, b, 1, 1000) // the walk wakes the member that can carry it (integration 2)
		if fs := dpFrames(dpFill(l1, time.Now())); dpCount(fs, wire.TypeDgram) != 0 {
			t.Fatalf("the shrunk lane placed %v", fs)
		}
		if p2.wakeCount() == w {
			t.Fatal("the lane that can carry the head was not woken")
		}
		fs = dpFrames(dpFill(l2, time.Now()))
		if dpCount(fs, wire.TypeDgram) != 1 {
			t.Fatalf("the other member placed %v", fs)
		}
		if c := dpCtr(b); c.DropTooLarge != 0 || c.Sent != 1 {
			t.Fatalf("counters %+v, want the datagram sent once", c)
		}

		// Mixed bond (integration 2): a small datagram member that meets a
		// head it cannot carry defers it to a datagram member that can, never
		// to the stream member listed before it.
		m := dpSession(dpOpt{mode: ModeBond})
		ls, ps := dpAddLane(m, 1, true, true)
		lt, pt := dpAddLane(m, 2, true, false)
		lb, pb := dpAddLane(m, 3, true, true)
		ps.set(func(f *dpPort) { f.srtt = time.Millisecond; f.budget = 600 })
		pt.set(func(f *dpPort) { f.srtt = 2 * time.Millisecond })
		pb.set(func(f *dpPort) { f.srtt = 3 * time.Millisecond })
		for _, l := range []*lane{ls, lt, lb} {
			dpIdle(l)
		}
		dpWrite(t, m, 1, 500)
		dpWrite(t, m, 2, 1000)
		m.mu.Lock()
		lt.idle, lb.idle = true, true // as if both writers had gone idle since
		m.mu.Unlock()
		wt, wb := pt.wakeCount(), pb.wakeCount()
		if fs := dpFrames(dpFill(ls, time.Now())); dpCount(fs, wire.TypeDgram) != 1 {
			t.Fatalf("the small member placed %v, want the 500-byte datagram", fs)
		}
		if pb.wakeCount() == wb || pt.wakeCount() != wt {
			t.Fatalf("the deferred head woke the stream member (%d → %d) or not the big member (%d → %d)",
				wt, pt.wakeCount(), wb, pb.wakeCount())
		}
	})
}

// dpCount counts the frames of type typ.
func dpCount(fs []dpFrame, typ wire.Type) int {
	n := 0
	for _, f := range fs {
		if f.typ == typ {
			n++
		}
	}
	return n
}

// TestPacketNeverBlocks_L40: WriteTo never waits. A full send queue drops
// its oldest datagrams (exact DropQueue), a full receive queue too (exact
// DropRecvQueue), and what survives is the newest datagrams; a datagram
// whose buffer MaxBufferedBytes refuses is dropped and counted, never
// waited for (M2-D33, M2-D37; PA-25).
func TestPacketNeverBlocks_L40(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const q, total, size = 64 << 10, 200, 1000
		const fit = q / size // 65 datagrams of 1000 bytes fit 64 KiB
		p := dpNewPair(dpOpt{queue: q}, dpOpt{queue: q}, true)
		var werr error
		done := false
		go func() {
			for i := range total {
				if k, err := p.a.s.WriteTo(dpPayload(uint64(i), size)); k != size || err != nil {
					werr = err
					return
				}
			}
			done = true
		}()
		synctest.Wait()
		if !done || werr != nil {
			t.Fatalf("WriteTo blocked or failed (done %v, %v)", done, werr)
		}
		c := dpCtr(p.a.s)
		if c.DropQueue != total-fit {
			t.Fatalf("DropQueue %d, want %d", c.DropQueue, total-fit)
		}
		dpSettle(t, p, nil)
		got, err := dpReadAll(t, p.b.s)
		if err != nil || len(got) != fit {
			t.Fatalf("received %d, %v; want %d", len(got), err, fit)
		}
		for i, d := range got {
			if id := dpID(d); id != uint64(total-fit+i) {
				t.Fatalf("datagram %d has id %d, want %d: the queue must keep the newest", i, id, total-fit+i)
			}
		}

		// The receive side: nobody reads.
		r := dpSession(dpOpt{role: RolePassive, queue: q})
		rl, _ := dpAddLane(r, 1, true, true)
		for i := range total {
			if err := dpDatagram(rl, uint64(i), dpPayload(uint64(i), size)); err != nil {
				t.Fatal(err)
			}
		}
		if c := dpCtr(r); c.DropRecvQueue != total-fit || c.Received != total {
			t.Fatalf("receiver counters %+v, want DropRecvQueue %d of %d received", c, total-fit, total)
		}
		got, _ = dpReadAll(t, r)
		if len(got) != fit || dpID(got[0]) != total-fit || dpID(got[fit-1]) != total-1 {
			t.Fatalf("receive queue kept %d datagrams, want the newest %d", len(got), fit)
		}

		// MaxBufferedBytes: room for one 64 KiB chunk only.
		m := dpSession(dpOpt{budget: carrier.NewBudget(70000), maxPayload: wire.MaxPacketPayload})
		for i := range 70 {
			dpWrite(t, m, uint64(i), size)
		}
		dpWrite(t, m, 70, 20000) // its own Buf is refused
		c = dpCtr(m)
		queued := dpLocked(m, func(_ *stream, pk *packet) int { return pk.tx.n })
		// 65 fit the chunk; each later one evicts the head once, then is
		// dropped itself: 5 × 2, plus the refused big one.
		if c.DropQueue != 11 || queued != 60 {
			t.Fatalf("DropQueue %d, queued %d; want 11 and 60", c.DropQueue, queued)
		}
	})
}

// TestPacketRingCharge_Q5: tiny datagrams cannot exceed Queue through
// their descriptors — each is charged max(len, 64) and at most Queue/64
// are queued — and the chunks they hold stay within the bound of the
// chunk ring.
func TestPacketRingCharge_Q5(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const q = 64 << 10
		budget := carrier.NewBudget(1 << 30)
		s := dpSession(dpOpt{queue: q, budget: budget, maxPayload: wire.MaxPacketPayload})
		for i := range 10000 {
			if k, err := s.WriteTo(make([]byte, i%2)); k != i%2 || err != nil {
				t.Fatalf("WriteTo = %d, %v", k, err)
			}
		}
		v := dpLocked(s, func(_ *stream, pk *packet) [3]int64 {
			return [3]int64{int64(pk.tx.n), pk.tx.charge, int64(pk.tx.cn)}
		})
		n, charge, cn := v[0], v[1], v[2]
		if n != q/64 || charge != q || cn != 1 {
			t.Fatalf("queued %d (charge %d, %d chunks), want %d datagrams charged %d in one chunk", n, charge, cn, q/64, q)
		}
		if c := dpCtr(s); c.DropQueue != 10000-q/64 {
			t.Fatalf("DropQueue %d, want %d", c.DropQueue, 10000-q/64)
		}
		if u := budget.Used(); u != carrier.ChunkSize+carrier.ClassSlack {
			t.Fatalf("Budget.Used %d, want one chunk", u)
		}

		// Mixed sizes: the bounds hold after every WriteTo.
		rng := rand.New(rand.NewPCG(1, 2))
		for i := range 20000 {
			n := rng.IntN(carrier.BigData)
			if rng.IntN(4) == 0 {
				n = rng.IntN(100)
			}
			dpWrite(t, s, uint64(i), n)
			bad := dpLocked(s, func(_ *stream, pk *packet) string {
				q := &pk.tx
				switch {
				case q.charge > q.max:
					return "charge above Queue"
				case q.n > q.maxN:
					return "more descriptors than Queue/64"
				case q.cn >= len(q.chunks):
					return "chunk ring full"
				case budget.Used() > int64(q.cn)*(carrier.ChunkSize+carrier.ClassSlack):
					return "Budget charge beyond the held chunks"
				}
				return ""
			})
			if bad != "" {
				t.Fatalf("write %d: %s", i, bad)
			}
		}
		dpEnd(s, io.EOF)
		if u := budget.Used(); u != 0 {
			t.Fatalf("Budget.Used %d after the end", u)
		}
	})
}

// TestPacketDeadlines_L06: the L06 table for packet sessions: a 200 ms read
// deadline fires at 200 ms; a deadline shortened while ReadFrom waits
// takes effect; five waiting readers are woken by a past deadline; a
// passed deadline fails ReadFrom even with a datagram queued (net.Conn),
// which stays readable once the deadline moves; a past write deadline
// fails WriteTo with (0, timeout) and no side effect; the session survives
// all of it.
func TestPacketDeadlines_L06(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := dpSession(dpOpt{role: RolePassive})
		l, _ := dpAddLane(s, 1, true, true)
		buf := make([]byte, 2048)
		isTimeout := func(err error) bool {
			var ne net.Error
			return errors.Is(err, os.ErrDeadlineExceeded) && errors.As(err, &ne) && ne.Timeout()
		}

		start := time.Now()
		_ = s.SetReadDeadline(start.Add(200 * time.Millisecond))
		if _, err := s.ReadFrom(buf); !isTimeout(err) {
			t.Fatalf("ReadFrom: %v, want a timeout", err)
		}
		if d := time.Since(start); d != 200*time.Millisecond {
			t.Fatalf("200 ms deadline fired after %v", d)
		}

		start = time.Now()
		_ = s.SetReadDeadline(start.Add(time.Second))
		go func() {
			time.Sleep(100 * time.Millisecond)
			_ = s.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		}()
		if _, err := s.ReadFrom(buf); !isTimeout(err) {
			t.Fatalf("ReadFrom: %v, want a timeout", err)
		}
		if d := time.Since(start); d != 200*time.Millisecond {
			t.Fatalf("shortened deadline fired after %v, want 200ms", d)
		}

		_ = s.SetReadDeadline(time.Time{})
		var wg sync.WaitGroup
		errs := make([]error, 5)
		for i := range errs {
			wg.Go(func() { _, errs[i] = s.ReadFrom(make([]byte, 16)) })
		}
		synctest.Wait()
		_ = s.SetReadDeadline(time.Now().Add(-time.Second))
		wg.Wait()
		for i, err := range errs {
			if !isTimeout(err) {
				t.Fatalf("reader %d: %v, want a timeout", i, err)
			}
		}

		if err := dpDatagram(l, 0, []byte("queued")); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ReadFrom(buf); !isTimeout(err) {
			t.Fatalf("ReadFrom past the deadline with a datagram queued: %v, want a timeout", err)
		}
		_ = s.SetReadDeadline(time.Time{})
		if n, err := s.ReadFrom(buf); err != nil || string(buf[:n]) != "queued" {
			t.Fatalf("after the deadline moved: %q, %v", buf[:n], err)
		}

		_ = s.SetWriteDeadline(time.Now().Add(-time.Millisecond))
		before := dpLocked(s, func(st *stream, pk *packet) [3]uint64 {
			return [3]uint64{uint64(pk.tx.n), st.txBytes, pk.ctr.DropQueue}
		})
		if n, err := s.WriteTo([]byte("x")); n != 0 || !isTimeout(err) {
			t.Fatalf("WriteTo past the write deadline = %d, %v", n, err)
		}
		if after := dpLocked(s, func(st *stream, pk *packet) [3]uint64 {
			return [3]uint64{uint64(pk.tx.n), st.txBytes, pk.ctr.DropQueue}
		}); after != before {
			t.Fatalf("a timed-out WriteTo changed state: %v → %v", before, after)
		}
		_ = s.SetWriteDeadline(time.Time{})
		dpWrite(t, s, 1, 100)
		if fs := dpFrames(dpFill(l, time.Now())); dpCount(fs, wire.TypeDgram) != 1 {
			t.Fatalf("the session did not survive: %v", fs)
		}
		dpEnd(s, io.EOF)
	})
}

// TestPacketReadCloseRace_L07: ReadFrom's commit re-checks Close (M2-D38):
// a Close during the copy wins ((0, net.ErrClosed), the datagram
// released); a Close after the copy's commit leaves the datagram returned.
// 1000 random races end in one of the two outcomes and leak no buffer.
func TestPacketReadCloseRace_L07(t *testing.T) {
	hooks := &testhooks.Hooks{}
	budget := carrier.NewBudget(1 << 30)
	s := dpSession(dpOpt{role: RolePassive, hooks: hooks, budget: budget})
	l, _ := dpAddLane(s, 1, true, true)
	if err := dpDatagram(l, 0, []byte("first")); err != nil {
		t.Fatal(err)
	}
	hooks.ReadDequeued = func() { dpClose(s) }
	buf := make([]byte, 64)
	if n, err := s.ReadFrom(buf); n != 0 || err != net.ErrClosed {
		t.Fatalf("Close during the copy: ReadFrom = %d, %v; want 0, net.ErrClosed", n, err)
	}
	hooks.ReadDequeued = nil
	dpEnd(s, net.ErrClosed)
	if u := budget.Used(); u != 0 {
		t.Fatalf("Close won but Budget.Used is %d", u)
	}

	s = dpSession(dpOpt{role: RolePassive, hooks: hooks, budget: budget})
	l, _ = dpAddLane(s, 1, true, true)
	_ = dpDatagram(l, 0, []byte("first"))
	if n, err := s.ReadFrom(buf); err != nil || string(buf[:n]) != "first" {
		t.Fatalf("ReadFrom = %q, %v", buf[:n], err)
	}
	dpClose(s)
	if _, err := s.ReadFrom(buf); err != net.ErrClosed {
		t.Fatalf("ReadFrom after Close: %v", err)
	}
	dpEnd(s, net.ErrClosed)

	won := [2]int{}
	for i := range 1000 {
		s := dpSession(dpOpt{role: RolePassive, budget: budget})
		l, _ := dpAddLane(s, 1, true, true)
		want := dpPayload(uint64(i), 100)
		_ = dpDatagram(l, 0, want)
		var n int
		var err error
		got := make([]byte, 200)
		var wg sync.WaitGroup
		wg.Go(func() { n, err = s.ReadFrom(got) })
		wg.Go(func() { dpClose(s) })
		wg.Wait()
		switch {
		case err == nil && bytes.Equal(got[:n], want):
			won[0]++
		case err == net.ErrClosed && n == 0:
			won[1]++
		default:
			t.Fatalf("race %d: ReadFrom = %d, %v", i, n, err)
		}
		if _, err := s.ReadFrom(got); err != net.ErrClosed {
			t.Fatalf("race %d: ReadFrom after Close: %v", i, err)
		}
		dpEnd(s, net.ErrClosed)
	}
	if u := budget.Used(); u != 0 {
		t.Fatalf("Budget.Used %d after 1000 races: a buffer leaked", u)
	}
	t.Logf("ReadFrom won %d, Close won %d", won[0], won[1])
}
