package session

import (
	"errors"
	"io"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestPacketFinAfterQueue: our FIN is placed only once tx and txBig are
// empty, and its final seq is fixed at that placement (M2-D34). A round
// that stops with datagrams still queued after Close — a stream lane out
// of capacity, a head deferred to another lane — places no FIN; the FIN
// that follows carries the last seq + 1, the peer sees no violation and
// reads every datagram, then io.EOF.
func TestPacketFinAfterQueue(t *testing.T) {
	t.Run("capacity", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			p := dpNewPair(dpOpt{}, dpOpt{}, false)
			p.a.ps[0].set(func(f *dpPort) { f.capacity = 2500 })
			for i := range 5 {
				dpWrite(t, p.a.s, uint64(i), 1000)
			}
			dpClose(p.a.s)
			b := dpFill(p.a.ls[0], time.Now())
			fs := dpFrames(b)
			if dpCount(fs, wire.TypeDgram) != 2 || dpCount(fs, wire.TypeFin) != 0 {
				t.Fatalf("first round %v; want 2 DGRAMs (the capacity) and no FIN", fs)
			}
			if err := dpDeliver(b, p.b.ls[0], 0, nil); err != nil {
				t.Fatalf("first round: %v", err)
			}
			b.ReleaseRefs()
			dpFinAfterQueueCheck(t, p, 5)
		})
	})
	t.Run("deferred", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			p := dpNewPair(dpOpt{mode: ModeBond}, dpOpt{}, true, true)
			dpWrite(t, p.a.s, 0, 1000)
			p.a.ps[0].set(func(f *dpPort) { f.budget = 600 }) // the head is above this lane's budget now
			dpClose(p.a.s)
			b := dpFill(p.a.ls[0], time.Now())
			fs := dpFrames(b)
			if dpCount(fs, wire.TypeDgram) != 0 || dpCount(fs, wire.TypeFin) != 0 {
				t.Fatalf("the deferring lane placed %v; want neither a DGRAM nor the FIN", fs)
			}
			if err := dpDeliver(b, p.b.ls[0], 0, nil); err != nil {
				t.Fatalf("first round: %v", err)
			}
			b.ReleaseRefs()
			dpFinAfterQueueCheck(t, p, 1)
		})
	})
}

// dpFinAfterQueueCheck settles p and checks the end of
// TestPacketFinAfterQueue: n datagrams, FIN(n), all read, then io.EOF.
func dpFinAfterQueueCheck(t *testing.T, p *dpPair, n int) {
	t.Helper()
	dpSettle(t, p, nil)
	fin := dpLocked(p.a.s, func(st *stream, pk *packet) [2]uint64 {
		return [2]uint64{st.fin.off, map[bool]uint64{true: 1}[pk.finPlaced]}
	})
	if fin != [2]uint64{uint64(n), 1} {
		t.Fatalf("our FIN (final seq, placed) = %v; want [%d 1]", fin, n)
	}
	got := dpReadEOF(t, p.b.s)
	if len(got) != n {
		t.Fatalf("the peer read %d datagrams before io.EOF, want %d", len(got), n)
	}
	for i, d := range got {
		if dpID(d) != uint64(i) {
			t.Fatalf("datagram %d has id %d", i, dpID(d))
		}
	}
}

// TestPacketCloseRules: Close (§A5.6, M2-D37) discards the receive queue
// and its memory, wakes a lane for our FIN, and discards (but counts) every
// later DGRAM; a peer FIN still waiting for stragglers is delivered at once
// (FIN_DELIVERED without the finWait deadline). The peer's FIN wakes a lane
// for our FIN although it is not delivered yet (it overtook a DGRAM).
func TestPacketCloseRules(t *testing.T) {
	t.Run("discard", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			bud := carrier.NewBudget(1 << 30)
			s := dpSession(dpOpt{budget: bud})
			l, fp := dpAddLane(s, 1, true, true)
			for i := range 10 {
				if err := dpDatagram(l, uint64(i), dpPayload(uint64(i), 100)); err != nil {
					t.Fatal(err)
				}
			}
			dpIdle(l)
			if rx := dpLocked(s, func(_ *stream, pk *packet) int { return pk.rx.n }); rx != 10 || bud.Used() == 0 {
				t.Fatalf("before Close: rx %d, Budget.Used %d (stimulus)", rx, bud.Used())
			}
			w := fp.wakeCount()
			dpClose(s)
			if rx := dpLocked(s, func(_ *stream, pk *packet) int { return pk.rx.n }); rx != 0 || bud.Used() != 0 {
				t.Fatalf("after Close: rx %d, Budget.Used %d; want both 0", rx, bud.Used())
			}
			if fp.wakeCount() != w+1 {
				t.Fatalf("Close woke the data lane %d times, want once (our FIN)", fp.wakeCount()-w)
			}
			for i := 10; i < 20; i++ {
				if err := dpDatagram(l, uint64(i), dpPayload(uint64(i), 100)); err != nil {
					t.Fatal(err)
				}
			}
			if rx := dpLocked(s, func(_ *stream, pk *packet) int { return pk.rx.n }); rx != 0 || bud.Used() != 0 {
				t.Fatalf("DGRAMs after Close: rx %d, Budget.Used %d; want both 0", rx, bud.Used())
			}
			if c := dpCtr(s); c.Received != 20 || c.DropRecvQueue != 0 {
				t.Fatalf("counters %+v; want Received 20 and nothing counted dropped", c)
			}
			fs := dpFrames(dpFill(l, time.Now()))
			if dpCount(fs, wire.TypeFin) != 1 {
				t.Fatalf("after Close the lane placed %v; want our FIN", fs)
			}
			dpEnd(s, io.EOF)
		})
	})
	t.Run("pending-fin", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s := dpSession(dpOpt{finWaitMax: 5 * time.Second})
			l, _ := dpAddLane(s, 1, true, true)
			for _, seq := range []uint64{0, 2} { // seq 1 is still on its way
				if err := dpDatagram(l, seq, dpPayload(seq, 100)); err != nil {
					t.Fatal(err)
				}
			}
			if err := dpSendFin(l, 3); err != nil {
				t.Fatal(err)
			}
			if dpLocked(s, func(st *stream, _ *packet) bool { return st.peerFinDelivered }) {
				t.Fatal("the FIN was delivered with a seq missing (stimulus)")
			}
			dpClose(s)
			now := time.Now()
			ok := dpLocked(s, func(st *stream, pk *packet) bool {
				return st.peerFinDelivered && st.ackFlags&wire.FlagAckFinDelivered != 0 && now.Before(pk.finWaitAt)
			})
			if !ok {
				t.Fatal("Close did not deliver the pending peer FIN at once")
			}
			dpEnd(s, io.EOF)
		})
	})
	t.Run("peer-fin-wakes", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s := dpSession(dpOpt{})
			l, fp := dpAddLane(s, 1, true, true)
			if err := dpDatagram(l, 1, dpPayload(1, 100)); err != nil { // seq 0 is overtaken
				t.Fatal(err)
			}
			dpIdle(l)
			w := fp.wakeCount()
			if err := dpSendFin(l, 2); err != nil {
				t.Fatal(err)
			}
			delivered := dpLocked(s, func(st *stream, _ *packet) bool { return st.peerFinDelivered })
			if delivered || fp.wakeCount() != w+1 {
				t.Fatalf("peer FIN: delivered %v, data lane woken %d times; want false and once (our FIN)", delivered, fp.wakeCount()-w)
			}
			fs := dpFrames(dpFill(l, time.Now()))
			if dpCount(fs, wire.TypeFin) != 1 {
				t.Fatalf("the woken lane placed %v; want our FIN", fs)
			}
			dpEnd(s, io.EOF)
		})
	})
}

// TestPacketShrinkDropsAtOnce_L37: a head above the lane's budget after a
// shrink is deferred only to a lane that can carry it now (M2-D45): with
// every other member also shrunk, write-blocked or (a stream lane) out of
// capacity, it is DropTooLarge at once and the next datagram is placed —
// two lanes never defer to each other and the queue is not held behind
// the head until MaxAge.
func TestPacketShrinkDropsAtOnce_L37(t *testing.T) {
	for _, tc := range []struct {
		name  string
		dgram bool
		other func(f *dpPort)
	}{
		{"both-shrunk", true, func(f *dpPort) { f.budget = 500 }},
		{"other-blocked", true, func(f *dpPort) { f.blocked = true }},
		{"other-capblocked", false, func(f *dpPort) { f.capacity, f.inflight = 4000, 4000 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := dpSession(dpOpt{mode: ModeBond})
				l1, p1 := dpAddLane(s, 1, true, true)
				_, p2 := dpAddLane(s, 2, true, tc.dgram)
				dpWrite(t, s, 0, 1000)
				dpWrite(t, s, 1, 100)
				p1.set(func(f *dpPort) { f.budget = 500 })
				p2.set(tc.other)
				fs := dpFrames(dpFill(l1, time.Now()))
				if dpCount(fs, wire.TypeDgram) != 1 || len(fs[len(fs)-1].body) != 100 {
					t.Fatalf("the shrunk lane placed %v; want the 100-byte datagram", fs)
				}
				if c := dpCtr(s); c.DropTooLarge != 1 || c.Sent != 1 {
					t.Fatalf("counters %+v; want DropTooLarge 1, Sent 1", c)
				}
				dpEnd(s, io.EOF)
			})
		})
	}
}

// TestPacketRingChunks: the packed queue's chunk bookkeeping (M2-D32):
// chunk numbers never decrease along the queue (an ext datagram carries
// the newest chunk's number), the head's chunk is the ring's oldest (every
// chunk below it was released when the head moved past it), and nothing
// stays charged once the queue is empty.
func TestPacketRingChunks(t *testing.T) {
	pool, bud := carrier.NewBufPool(), carrier.NewBudget(1<<30)
	var q pring
	q.init(1<<20, (1<<20)/pktChargeMin)
	check := func(step string) {
		t.Helper()
		if q.n == 0 {
			if q.cn != 0 {
				t.Fatalf("%s: empty queue holds %d chunks", step, q.cn)
			}
			return
		}
		prev := q.front().chunk
		if q.cn > 0 && prev != q.cbase {
			t.Fatalf("%s: head's chunk %d, oldest held %d: a chunk below the head is kept", step, prev, q.cbase)
		}
		for i := range q.n {
			c := q.desc[(q.head+i)&(len(q.desc)-1)].chunk
			if c < prev || (q.cn > 0 && c > q.cbase+uint32(q.cn)-1) {
				t.Fatalf("%s: descriptor %d has chunk %d after %d (held %d..%d)", step, i, c, prev, q.cbase, q.cbase+uint32(q.cn)-1)
			}
			prev = c
		}
	}
	push := func(n int, big bool) {
		var ext *carrier.Buf
		if big {
			ext = pool.TryGet(n, bud)
			ext.B = ext.B[:n]
		}
		if _, ev, ok := q.push(n, 0, ext, pool, bud); !ok || ev != 0 {
			t.Fatalf("push(%d): ok %v, evicted %d", n, ok, ev)
		}
	}
	for range 70 { // more than one chunk of 1000-byte datagrams
		push(1000, false)
	}
	if q.cn != 2 {
		t.Fatalf("%d chunks after 70 KB (stimulus)", q.cn)
	}
	push(carrier.BigData, true)
	check("ext after two chunks")
	for range 70 {
		push(1000, false)
		check("push")
	}
	push(carrier.BigData, true)
	for q.n > 0 {
		q.evict()
		check("pop")
	}
	if u := bud.Used(); u != 0 {
		t.Fatalf("Budget.Used %d with the queue empty", u)
	}
}

// TestPacketAccountingRecvEnd: on the receive side every accepted
// datagram is returned or counted (§A7.2): at an error end the datagrams
// the application never read are DropRecvQueue.
func TestPacketAccountingRecvEnd(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := dpSession(dpOpt{})
		l, _ := dpAddLane(s, 1, true, true)
		for i := range 5 {
			if err := dpDatagram(l, uint64(i), dpPayload(uint64(i), 100)); err != nil {
				t.Fatal(err)
			}
		}
		buf := make([]byte, 200)
		for range 2 {
			if _, err := s.ReadFrom(buf); err != nil {
				t.Fatal(err)
			}
		}
		dpEnd(s, errors.New("test end"))
		if c := dpCtr(s); c.Received != 5 || c.DropRecvQueue != 3 {
			t.Fatalf("counters %+v; want Received 5 = 2 returned + DropRecvQueue 3", c)
		}
	})
}

// TestPacketIdleClockBusyReceiver_L19: accepted datagrams move the idle
// clock (M2-D41) even while the PACK that reports them cannot be placed:
// every PackEvery-th unreported datagram reads the clock.
func TestPacketIdleClockBusyReceiver_L19(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := dpSession(dpOpt{packEvery: 16, packetPing: time.Second})
		l, _ := dpAddLane(s, 1, true, true) // its Fill never runs: no PACK is placed
		seq := uint64(0)
		deliver := func(n int) {
			for range n {
				if err := dpDatagram(l, seq, dpPayload(seq, 50)); err != nil {
					t.Fatal(err)
				}
				seq++
			}
		}
		deliver(1)
		for round := range 2 {
			time.Sleep(10 * time.Second)
			deliver(15 + round)
			now := time.Now()
			if last := dpLocked(s, func(st *stream, _ *packet) time.Time { return st.lastData }); !last.Equal(now) {
				t.Fatalf("round %d: the idle clock is %v behind after %d datagrams", round, now.Sub(last), seq)
			}
		}
		dpEnd(s, io.EOF)
	})
}
