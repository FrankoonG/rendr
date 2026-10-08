package session

import (
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestPacketMaxAge_L40: a datagram not placed within MaxAge is dropped, at
// dequeue (Fill) and at enqueue (the next WriteTo), and counts DropAge
// while a data lane exists; DropNoPath when no data lane exists (the
// actor's ageing step, pktAgeLocked, which returns the next age-out) or
// when it was queued before the latest no-path episode ended (M2-D35). A
// dropped datagram consumes no seq; a fresh one is placed.
func TestPacketMaxAge_L40(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const maxAge = 100 * time.Millisecond
		s := dpSession(dpOpt{maxAge: maxAge})
		l, _ := dpAddLane(s, 1, true, true)
		dpIdle(l)
		dpWrite(t, s, 1, 100)
		time.Sleep(150 * time.Millisecond)
		if fs := dpFrames(dpFill(l, time.Now())); dpCount(fs, wire.TypeDgram) != 0 {
			t.Fatalf("an aged datagram was placed: %v", fs)
		}
		if c := dpCtr(s); c.DropAge != 1 || c.Sent != 0 || c.DropNoPath != 0 {
			t.Fatalf("at dequeue: %+v, want DropAge 1", c)
		}
		dpWrite(t, s, 2, 100)
		time.Sleep(maxAge)
		fs := dpFrames(dpFill(l, time.Now()))
		if dpCount(fs, wire.TypeDgram) != 1 || fs[len(fs)-1].seq != 0 || dpID(fs[len(fs)-1].body) != 2 {
			t.Fatalf("a datagram exactly MaxAge old must be placed as seq 0: %v", fs)
		}
		dpIdle(l)
		dpWrite(t, s, 3, 100)
		time.Sleep(150 * time.Millisecond)
		dpWrite(t, s, 4, 100)
		if n := dpLocked(s, func(_ *stream, pk *packet) int { return pk.tx.n }); n != 1 {
			t.Fatalf("at enqueue: %d queued, want the aged head evicted", n)
		}
		if c := dpCtr(s); c.DropAge != 2 {
			t.Fatalf("at enqueue: %+v, want DropAge 2", c)
		}
		dpEnd(s, io.EOF)

		// No data lane: the actor's ageing step counts DropNoPath.
		n := dpSession(dpOpt{maxAge: maxAge})
		dpAddLane(n, 1, false, true)
		t0 := time.Now()
		dpWrite(t, n, 1, 100)
		time.Sleep(60 * time.Millisecond)
		dpWrite(t, n, 2, 100)
		time.Sleep(60 * time.Millisecond)
		age := func() time.Time {
			n.mu.Lock()
			defer n.mu.Unlock()
			return n.pktAgeLocked(time.Now())
		}
		if next, want := age(), t0.Add(60*time.Millisecond+maxAge+1); !next.Equal(want) {
			t.Fatalf("pktAgeLocked returned %v, want %v (the next age-out)", next.Sub(t0), want.Sub(t0))
		}
		if c := dpCtr(n); c.DropNoPath != 1 || c.DropAge != 0 {
			t.Fatalf("no data lane: %+v, want DropNoPath 1", c)
		}
		time.Sleep(time.Until(t0.Add(60*time.Millisecond + maxAge + 1)))
		if next := age(); !next.IsZero() {
			t.Fatalf("pktAgeLocked returned %v with nothing queued, want zero", next)
		}
		dpWrite(t, n, 3, 100) // enqueue-time ageing while no data lane exists
		time.Sleep(150 * time.Millisecond)
		dpWrite(t, n, 4, 100)
		if c := dpCtr(n); c.DropNoPath != 3 || c.DropAge != 0 {
			t.Fatalf("no data lane at enqueue: %+v, want DropNoPath 3", c)
		}
		dpEnd(n, io.EOF)

		// Queued during a no-path episode, aged after it ended.
		e := dpSession(dpOpt{maxAge: maxAge})
		el, _ := dpAddLane(e, 1, false, true)
		dpIdle(el)
		dpWrite(t, e, 1, 100)
		time.Sleep(50 * time.Millisecond)
		e.mu.Lock()
		e.pk.noPathEnd = time.Now() // episodeEndLocked (WP6b)
		e.mu.Unlock()
		dpRoute(e, el, true)
		time.Sleep(100 * time.Millisecond)
		if fs := dpFrames(dpFill(el, time.Now())); dpCount(fs, wire.TypeDgram) != 0 {
			t.Fatalf("placed %v", fs)
		}
		if c := dpCtr(e); c.DropNoPath != 1 || c.DropAge != 0 {
			t.Fatalf("queued before the episode ended: %+v, want DropNoPath 1", c)
		}
		dpEnd(e, io.EOF)
	})
}

// TestPacketSeqExhaustion_L14: the seq is assigned at placement; at the
// offset limit Fill stops and reports exhaustion, WriteTo fails with the
// exhaustion error, and the termination rules end the session with
// exactly one RST(Exhausted); the datagrams never placed count DropQueue.
func TestPacketSeqExhaustion_L14(t *testing.T) {
	const limit = 1 << 62
	s := dpSession(dpOpt{firstSeq: limit - 3, limit: limit})
	l, _ := dpAddLane(s, 1, true, true)
	for i := range 5 {
		dpWrite(t, s, uint64(i), 50)
	}
	fs := dpFrames(dpFill(l, time.Now()))
	var seqs []uint64
	for _, f := range fs {
		if f.typ == wire.TypeDgram {
			seqs = append(seqs, f.seq)
		}
	}
	if len(seqs) != 3 || seqs[0] != limit-3 || seqs[2] != limit-1 {
		t.Fatalf("placed seqs %v, want the last three below the limit", seqs)
	}
	ex, facts := dpLocked(s, func(st *stream, _ *packet) bool { return st.exhausted }), dpLocked(s, func(st *stream, _ *packet) uint32 { return st.facts })
	if !ex || facts&factExhausted == 0 {
		t.Fatal("exhaustion not reported to the actor")
	}
	_, err := s.WriteTo([]byte("x"))
	var ae *AbortError
	if !errors.As(err, &ae) || ae.Code != AbortExhausted || !errors.Is(err, ErrAborted) {
		t.Fatalf("WriteTo after exhaustion: %v", err)
	}
	end, rst := dpTerm(s, time.Now())
	if !errors.As(end, &ae) || ae.Code != AbortExhausted || ae.Remote || rst == nil || rst.Code != wire.RstExhausted {
		t.Fatalf("end %v, RST %+v; want AbortExhausted and RST(Exhausted)", end, rst)
	}
	rsts := 0
	for range 3 {
		b := dpFill(l, time.Now())
		rsts += dpCount(dpFrames(b), wire.TypeRst)
		if dpCount(dpFrames(b), wire.TypeDgram) != 0 {
			t.Fatal("a DGRAM after the end")
		}
	}
	if rsts != 1 {
		t.Fatalf("%d RSTs placed, want exactly one", rsts)
	}
	if c := dpCtr(s); c.Sent != 3 || c.DropQueue != 2 {
		t.Fatalf("counters %+v; want Sent 3 and the 2 unplaced counted DropQueue", c)
	}

	// The receiving side accepts seqs up to the limit only.
	r := dpSession(dpOpt{role: RolePassive, firstSeq: limit - 3, limit: limit})
	rl, _ := dpAddLane(r, 1, true, true)
	if err := dpDatagram(rl, limit-1, nil); err != nil {
		t.Fatal(err)
	}
	if err := dpDatagram(rl, limit, nil); err != errDgramBeyondLimit {
		t.Fatalf("seq at the limit: %v", err)
	}
	dpEnd(r, io.EOF)
}

// dpWakes sums the wakes of ports.
func dpWakes(ps []*dpPort) int {
	n := 0
	for _, p := range ps {
		n += p.wakeCount()
	}
	return n
}

// TestPacketWakePolicy_L08: WriteTo wakes at most the lanes the queue needs
// (M2-D43, R1-19): the selector's active lane once while idle; in a bond
// the minimum share first, then datagram lanes before stream lanes in srtt
// order, one batch per woken writer, never a write-blocked lane; a
// datagram above every datagram lane's DgramMax rides txBig and wakes
// stream lanes only. Over long runs every bond member places a DGRAM at
// least every PacketPing/2, at most one writer is woken per WriteTo, and a
// rejoined member carries datagrams within PacketPing/4.
func TestPacketWakePolicy_L08(t *testing.T) {
	t.Run("selector", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s := dpSession(dpOpt{})
			l1, p1 := dpAddLane(s, 1, true, true)
			l2, p2 := dpAddLane(s, 2, false, true)
			dpIdle(l1)
			dpIdle(l2)
			w1, w2 := p1.wakeCount(), p2.wakeCount()
			dpWrite(t, s, 1, 10)
			dpWrite(t, s, 2, 10)
			if p1.wakeCount() != w1+1 || p2.wakeCount() != w2 {
				t.Fatalf("wakes active %d non-active %d; want 1 and 0", p1.wakeCount()-w1, p2.wakeCount()-w2)
			}
			dpIdle(l1)
			dpWrite(t, s, 3, 10)
			if p1.wakeCount() != w1+2 {
				t.Fatal("an idle active lane was not woken")
			}
			dpEnd(s, io.EOF)
		})
	})

	t.Run("bond", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s := dpSession(dpOpt{mode: ModeBond})
			var ls []*lane
			var ps []*dpPort
			for i, srtt := range []time.Duration{3, 1, 2, 0} { // the last: a stream lane, faster than all
				l, p := dpAddLane(s, uint32(i+1), true, i < 3)
				p.set(func(f *dpPort) { f.srtt = srtt*time.Millisecond + 500*time.Microsecond })
				ls, ps = append(ls, l), append(ps, p)
			}
			for _, l := range ls {
				dpIdle(l)
			}
			now := time.Now()
			s.mu.Lock()
			for _, l := range ls {
				l.lastDgramAt = now // every member is served: the minimum share stays out of this part
			}
			s.refreshOrderLocked(now, true)
			s.mu.Unlock()
			w := [4]int{}
			for i, p := range ps {
				w[i] = p.wakeCount()
			}
			var at [4]int // the queue length at each lane's wake
			for i := 1; i <= 200; i++ {
				dpWrite(t, s, uint64(i), 10)
				for k, p := range ps {
					if at[k] == 0 && p.wakeCount() > w[k] {
						at[k] = i
					}
				}
			}
			// srtt order among datagram lanes: lane 2 (1 ms), lane 3, lane 1; the
			// stream lane last although it is the fastest.
			if at != [4]int{129, 1, 65, 193} {
				t.Fatalf("lanes woken at queue lengths %v, want [129 1 65 193]", at)
			}
			for k, p := range ps {
				if p.wakeCount()-w[k] != 1 {
					t.Fatalf("lane %d woken %d times, want once", k+1, p.wakeCount()-w[k])
				}
			}
			dpEnd(s, io.EOF)
		})
	})

	t.Run("blocked", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s := dpSession(dpOpt{mode: ModeBond})
			l1, p1 := dpAddLane(s, 1, true, true)
			l2, p2 := dpAddLane(s, 2, true, true)
			p1.set(func(f *dpPort) { f.srtt = time.Millisecond; f.blocked = true })
			p2.set(func(f *dpPort) { f.srtt = 2 * time.Millisecond })
			dpIdle(l1)
			dpIdle(l2)
			w1, w2 := p1.wakeCount(), p2.wakeCount()
			dpWrite(t, s, 1, 10)
			if p1.wakeCount() != w1 || p2.wakeCount() != w2+1 {
				t.Fatal("a write-blocked lane was woken, or the other one was not")
			}
			// The walk itself skips it: with every member served, the
			// minimum share stays out and the walk alone chooses.
			dpIdle(l2)
			now := time.Now()
			s.mu.Lock()
			l1.lastDgramAt, l2.lastDgramAt = now, now
			s.refreshOrderLocked(now, true)
			s.mu.Unlock()
			w1, w2 = p1.wakeCount(), p2.wakeCount()
			dpWrite(t, s, 2, 10)
			if p1.wakeCount() != w1 || p2.wakeCount() != w2+1 {
				t.Fatalf("walk: blocked lane woken %d times, other %d; want 0 and 1", p1.wakeCount()-w1, p2.wakeCount()-w2)
			}
			dpEnd(s, io.EOF)
		})
	})

	// A stream member without spare capacity covers nothing and never
	// holds the minimum share (L32: a stalled member absorbs at most its
	// capacity): at a low rate the healthy member carries every datagram.
	for _, mixed := range []bool{true, false} {
		t.Run(map[bool]string{true: "capblocked/mixed", false: "capblocked/stream"}[mixed], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { dpCapBlockedRun(t, mixed) })
		})
	}
	// A member the minimum share chose while it had capacity, out of
	// capacity before it placed anything, is forgotten: the next WriteTo
	// wakes the healthy member.
	t.Run("capblocked/remembered", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s := dpSession(dpOpt{mode: ModeBond})
			la, pa := dpAddLane(s, 1, true, false)
			lb, pb := dpAddLane(s, 2, true, true)
			pa.set(func(f *dpPort) { f.srtt = time.Millisecond; f.capacity = 4000 })
			pb.set(func(f *dpPort) { f.srtt = 2 * time.Millisecond })
			dpIdle(la)
			dpIdle(lb)
			now := time.Now()
			s.mu.Lock()
			lb.lastDgramAt = now // served; la never placed: the share's choice
			s.refreshOrderLocked(now, true)
			s.mu.Unlock()
			wa, wb := pa.wakeCount(), pb.wakeCount()
			dpWrite(t, s, 1, 100)
			if pa.wakeCount() != wa+1 || pb.wakeCount() != wb {
				t.Fatalf("first WriteTo woke the stale member %d and the other %d times; want 1 and 0 (stimulus)", pa.wakeCount()-wa, pb.wakeCount()-wb)
			}
			pa.set(func(f *dpPort) { f.inflight = f.capacity })
			if fs := dpFrames(dpFill(la, time.Now())); dpCount(fs, wire.TypeDgram) != 0 {
				t.Fatalf("a member without capacity placed %v", fs)
			}
			wa = pa.wakeCount()
			dpWrite(t, s, 2, 100)
			if pa.wakeCount() != wa || pb.wakeCount() != wb+1 {
				t.Fatalf("second WriteTo woke the member without capacity %d and the healthy one %d times; want 0 and 1", pa.wakeCount()-wa, pb.wakeCount()-wb)
			}
			dpEnd(s, io.EOF)
		})
	})

	// The minimum share's member was woken and has not run yet when more
	// datagrams arrive (one burst): it still covers the queue up to a
	// batch, so no other member is woken and its Fill takes the whole
	// burst (R1-19). Counting it only on the WriteTo that woke it let the
	// fastest member's writer, run first at GOMAXPROCS=1, drain the burst
	// every time: a rejoined member then placed nothing for seconds.
	t.Run("share/pending", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s := dpSession(dpOpt{mode: ModeBond})
			lf, pf := dpAddLane(s, 1, true, true)
			ls, ps := dpAddLane(s, 2, true, true)
			pf.set(func(f *dpPort) { f.srtt = time.Millisecond })
			ps.set(func(f *dpPort) { f.srtt = 2 * time.Millisecond })
			dpIdle(lf)
			dpIdle(ls)
			now := time.Now()
			s.mu.Lock()
			lf.lastDgramAt = now // served; ls never placed: the share's choice
			s.refreshOrderLocked(now, true)
			s.mu.Unlock()
			wf, ws := pf.wakeCount(), ps.wakeCount()
			const burst = 20
			for i := 1; i <= burst; i++ {
				dpWrite(t, s, uint64(i), 100)
				if pf.wakeCount() != wf || ps.wakeCount() != ws+1 {
					t.Fatalf("after WriteTo %d: fastest member woken %d times, stale member %d; want 0 and 1", i, pf.wakeCount()-wf, ps.wakeCount()-ws)
				}
			}
			if fs := dpFrames(dpFill(ls, time.Now())); dpCount(fs, wire.TypeDgram) != burst {
				t.Fatalf("the stale member placed %d DGRAMs, want the whole burst of %d", dpCount(fs, wire.TypeDgram), burst)
			}
			dpEnd(s, io.EOF)
		})
	})

	t.Run("txBig", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s := dpSession(dpOpt{mode: ModeBond, maxPayload: 4000})
			ld, pd := dpAddLane(s, 1, true, true)
			lst, pst := dpAddLane(s, 2, true, false)
			dpIdle(ld)
			dpIdle(lst)
			wd, ws := pd.wakeCount(), pst.wakeCount()
			dpWrite(t, s, 1, 3000) // above the datagram lane's 1375
			if pd.wakeCount() != wd || pst.wakeCount() != ws+1 {
				t.Fatalf("txBig woke the datagram lane (%d) or not the stream lane (%d)", pd.wakeCount()-wd, pst.wakeCount()-ws)
			}
			dpWrite(t, s, 2, 500)
			fs := dpFrames(dpFill(ld, time.Now()))
			if dpCount(fs, wire.TypeDgram) != 1 || len(fs[len(fs)-1].body) != 500 {
				t.Fatalf("the datagram lane placed %v; want the small datagram (no head-of-line block)", fs)
			}
			fs = dpFrames(dpFill(lst, time.Now()))
			if dpCount(fs, wire.TypeDgram) != 1 || len(fs[len(fs)-1].body) != 3000 {
				t.Fatalf("the stream lane placed %v; want the big datagram", fs)
			}
			dpWrite(t, s, 3, 3000)
			dpKill(s, lst)
			if c := dpCtr(s); c.DropTooLarge != 1 || c.Sent != 2 {
				t.Fatalf("counters %+v; want the big datagram dropped with the last stream lane", c)
			}
			if mixed := dpLocked(s, func(_ *stream, pk *packet) bool { return pk.mixed }); mixed {
				t.Fatal("still mixed without a stream lane")
			}
			dpEnd(s, io.EOF)
		})
	})

	// The minimum share (R1-19), emulated writers in a bubble.
	for _, tc := range []struct {
		members int
		every   time.Duration
		run     time.Duration
	}{
		{2, time.Millisecond, 60 * time.Second},
		{4, time.Millisecond, 60 * time.Second},
		{2, 100 * time.Microsecond, 6 * time.Second},
		{4, 100 * time.Microsecond, 6 * time.Second},
		{8, time.Millisecond, 10 * time.Second},
		{16, time.Millisecond, 10 * time.Second}, // MaxCarriersPerSession's maximum
	} {
		t.Run(fmt.Sprintf("share/%d@%v", tc.members, tc.every), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { dpShareRun(t, tc.members, tc.every, tc.run) })
		})
	}
}

// dpCapBlockedRun: a bond whose fastest member is a stream lane with no
// spare capacity (Capacity == Inflight) and a healthy member (a datagram
// lane when mixed, else a stream lane); 100-byte datagrams every 10 ms for
// 3 virtual seconds with MaxAge 100 ms. The member without capacity is
// never woken (neither the walk nor the minimum share picks it).
func dpCapBlockedRun(t *testing.T, mixed bool) {
	s := dpSession(dpOpt{mode: ModeBond, maxAge: 100 * time.Millisecond, packetPing: time.Second})
	stop := make(chan struct{})
	var wg sync.WaitGroup
	lb, pb := dpAddLane(s, 1, true, false)
	pb.set(func(f *dpPort) { f.srtt = time.Millisecond; f.capacity, f.inflight = 4000, 4000 })
	lh, ph := dpAddLane(s, 2, true, mixed)
	ph.set(func(f *dpPort) { f.srtt = 2 * time.Millisecond })
	blocked := &dpShareLane{l: lb, p: pb, start: time.Now(), first: -1}
	healthy := &dpShareLane{l: lh, p: ph, start: time.Now(), first: -1}
	for _, w := range []*dpShareLane{blocked, healthy} {
		dpIdle(w.l)
		wg.Go(func() { w.run(stop) })
	}
	wb := pb.wakeCount()
	const n = 300
	for range n {
		synctest.Wait()
		if _, err := s.WriteTo(make([]byte, 100)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	synctest.Wait()
	close(stop)
	wg.Wait()
	c := dpCtr(s)
	t.Logf("counters %+v; healthy %d DGRAMs, blocked %d", c, healthy.dgrams, blocked.dgrams)
	if blocked.dgrams != 0 || pb.wakeCount() != wb {
		t.Fatalf("the member without capacity placed %d DGRAMs and was woken %d times; want neither", blocked.dgrams, pb.wakeCount()-wb)
	}
	if c.Sent < n*9/10 || healthy.dgrams != int(c.Sent) {
		t.Fatalf("Sent %d (healthy member %d) of %d; want ≥ 90 %% by the healthy member", c.Sent, healthy.dgrams, n)
	}
	dpEnd(s, io.EOF)
}

// dpShareLane is an emulated carrier writer: woken by its port, it runs
// Fill until it appends nothing (each "write" takes no virtual time) and
// records when it placed DGRAMs.
type dpShareLane struct {
	l      *lane
	p      *dpPort
	start  time.Time
	first  time.Duration // first DGRAM after start (−1: none yet)
	gone   bool          // killed: out of the share checks from then on
	last   time.Time
	maxGap time.Duration
	dgrams int
}

func (w *dpShareLane) run(stop <-chan struct{}) {
	for {
		select {
		case <-w.p.wake:
		case <-stop:
			return
		}
		for {
			b := dpFill(w.l, time.Now())
			n, dg := b.Len(), 0
			for i := range n {
				if b.Frame(i).Header.Type == wire.TypeDgram {
					dg++
				}
			}
			b.ReleaseRefs()
			if dg > 0 {
				now := time.Now()
				if w.first < 0 {
					w.first = now.Sub(w.start)
				} else {
					w.maxGap = max(w.maxGap, now.Sub(w.last))
				}
				w.last = now
				w.dgrams += dg
			}
			if n == 0 {
				break
			}
		}
	}
}

func dpShareRun(t *testing.T, members int, every, run time.Duration) {
	const pp = time.Second // PacketPing
	s := dpSession(dpOpt{mode: ModeBond, packetPing: pp})
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var ws []*dpShareLane
	var ports []*dpPort
	add := func(id int) *dpShareLane {
		l, p := dpAddLane(s, uint32(id), true, true)
		p.set(func(f *dpPort) { f.srtt = time.Duration(id) * time.Millisecond })
		w := &dpShareLane{l: l, p: p, start: time.Now(), first: -1}
		ws, ports = append(ws, w), append(ports, p)
		dpIdle(l)
		wg.Go(func() { w.run(stop) })
		return w
	}
	for i := range members {
		add(i + 1)
	}
	var rejoined *dpShareLane
	start := time.Now()
	multi := 0
	for i := 0; time.Since(start) < run; i++ {
		synctest.Wait()
		before := dpWakes(ports)
		if _, err := s.WriteTo(make([]byte, 100)); err != nil {
			t.Fatal(err)
		}
		if queued := dpLocked(s, func(_ *stream, pk *packet) int { return pk.tx.n }); queued <= carrier.MaxBatchFrames && dpWakes(ports)-before > 1 {
			multi++
		}
		if members == 2 && rejoined == nil && time.Since(start) >= run/2 {
			// A member dies and another attaches.
			dpKill(s, ws[members-1].l)
			ws[members-1].gone = true // out of the share checks from here on
			rejoined = add(10)
		}
		time.Sleep(every)
	}
	close(stop)
	wg.Wait()
	if multi > 0 {
		t.Fatalf("%d WriteTos woke more than one writer with at most a batch queued", multi)
	}
	for k, w := range ws {
		t.Logf("member %d (gone %v): %d DGRAMs, first after %v (−1: never), longest gap %v", k+1, w.gone, w.dgrams, w.first, w.maxGap)
	}
	for k, w := range ws {
		if w == rejoined || w.gone {
			continue
		}
		if w.first < 0 || w.first > pp/2 {
			t.Fatalf("member %d: first DGRAM after %v (want ≤ %v); %d placed", k+1, w.first, pp/2, w.dgrams)
		}
		if w.maxGap > pp/2 {
			t.Fatalf("member %d went %v without a DGRAM (want ≤ %v)", k+1, w.maxGap, pp/2)
		}
	}
	if rejoined != nil && (rejoined.first < 0 || rejoined.first > pp/4) {
		t.Fatalf("the rejoined member placed its first DGRAM after %v, want ≤ %v", rejoined.first, pp/4)
	}
	dpEnd(s, io.EOF)
}

// TestPacketAccountingIdentity: whatever happens on the send side —
// queue overflow, MaxBufferedBytes refusals, ageing with and without a
// data lane, budget shrinks, routing changes, txBig drops, the peer's FIN
// and the end — every datagram WriteTo accepted is Sent, dropped in
// exactly one counter or still queued: accepted = Sent + DropQueue +
// DropAge + DropNoPath + DropTooLarge + queued (§A7.2; the carrier's
// Refused share is folded in by publishLocked, WP6b).
func TestPacketAccountingIdentity(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rng := rand.New(rand.NewPCG(7, 8))
		budget := carrier.NewBudget(400 << 10)
		s := dpSession(dpOpt{mode: ModeBond, queue: 64 << 10, maxPayload: 20000, budget: budget, maxAge: 100 * time.Millisecond})
		l1, p1 := dpAddLane(s, 1, true, true)
		l2, p2 := dpAddLane(s, 2, true, false)
		l3, p3 := dpAddLane(s, 3, true, true)
		p2.set(func(f *dpPort) { f.capacity = 50000 })
		p3.set(func(f *dpPort) { f.budget = 3000 })
		ls, ps := []*lane{l1, l2, l3}, []*dpPort{p1, p2, p3}
		accepted := uint64(0)
		check := func(step int) {
			t.Helper()
			c, queued := dpCtr(s), dpLocked(s, func(_ *stream, pk *packet) uint64 { return uint64(pk.tx.n + pk.txBig.n) })
			if got := c.Sent + c.DropQueue + c.DropAge + c.DropNoPath + c.DropTooLarge + queued; got != accepted {
				t.Fatalf("step %d: accepted %d but Sent+drops+queued = %d (%+v, queued %d)", step, accepted, got, c, queued)
			}
		}
		for step := range 6000 {
			switch k := rng.IntN(12); {
			case k < 6:
				n := rng.IntN(3000)
				if rng.IntN(20) == 0 {
					n = carrier.BigData + rng.IntN(5000) // its own Buf (the Budget may refuse it)
				}
				if rng.IntN(50) == 0 {
					n = 20001 // too large: not accepted
				}
				burst := 1
				if rng.IntN(30) == 0 {
					burst = 50 // overflows the 64 KiB queue
				}
				for range burst {
					if k, err := s.WriteTo(make([]byte, n)); err == nil {
						accepted++
						if k != n {
							t.Fatalf("WriteTo = %d", k)
						}
					} else if err != ErrPacketTooLarge {
						t.Fatal(err)
					}
				}
			case k == 6:
				i := rng.IntN(3)
				if ls[i].state != LaneDead {
					dpFill(ls[i], time.Now()).ReleaseRefs()
				}
			case k == 7:
				time.Sleep(time.Duration(rng.IntN(150)) * time.Millisecond)
			case k == 8:
				i := []int{0, 2}[rng.IntN(2)]
				ps[i].set(func(f *dpPort) { f.budget = 600 + rng.IntN(2500) })
				s.mu.Lock()
				s.pktRecomputeLocked()
				s.mu.Unlock()
			case k == 9:
				i := rng.IntN(3)
				dpRoute(s, ls[i], !ls[i].data)
				s.mu.Lock()
				if !s.pktHasDataLaneLocked() {
					s.pktAgeLocked(time.Now())
				}
				s.mu.Unlock()
			case k == 10:
				s.mu.Lock()
				s.pk.noPathEnd = time.Now()
				s.mu.Unlock()
			default:
				for _, l := range ls {
					if !l.data {
						dpRoute(s, l, true)
					}
				}
			}
			check(step)
		}
		c := dpCtr(s)
		if c.Sent == 0 || c.DropQueue == 0 || c.DropAge == 0 || c.DropNoPath == 0 || c.DropTooLarge == 0 {
			t.Fatalf("stimulus not proven: %+v", c)
		}
		// The peer's FIN drops what is queued; WriteTo then fails.
		for range 3 {
			dpWrite(t, s, 0, 10)
			accepted++
		}
		if err := dpSendFin(l1, 0); err != nil {
			t.Fatal(err)
		}
		check(-1)
		if _, err := s.WriteTo([]byte("x")); err == nil {
			t.Fatal("WriteTo after the peer's FIN")
		}
		dpEnd(s, io.EOF)
		check(-2)
		if u := budget.Used(); u != 0 {
			t.Fatalf("Budget.Used %d after the end", u)
		}
	})
}
