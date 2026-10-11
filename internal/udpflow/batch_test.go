package udpflow

// The batched Source rows of M5 design §A10.1 (WP3; M5-D13, M5-D14,
// Revision 1 R1-4, R1-6, R1-7): the reads of rendr's own socket through
// the fakeSock seam inside synctest bubbles (every OS), and the shared
// socket's writes and counters on a real loopback socket.

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/udpsocket"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

const seamDgram = 1232 // the MaxDatagram of the seam sources

// slotBytes is the class capacity of one read slot of a Source of
// MaxDatagram n: what a charged slot costs the Budget.
func slotBytes(env *carrier.Env, n int) int64 {
	b := env.DBufs.Get(n+1, nil)
	defer b.Release()
	return int64(len(b.B))
}

// pingSeq returns the fseq a pingFrame datagram carries (rendr bytes).
func pingSeq(b []byte) uint32 { return u32(b[5:9]) }

// recordWakes records, for the rest of the test, every wake of a flow
// with the number of datagrams its inbox held at that wake (testWake runs
// under f.mu): the result returns a flow's list.
func recordWakes(t *testing.T) func(f *Flow) []int {
	var mu sync.Mutex
	held := map[*Flow][]int{}
	fn := func(f *Flow) {
		mu.Lock()
		held[f] = append(held[f], f.n)
		mu.Unlock()
	}
	testWake.Store(&fn)
	t.Cleanup(func() { testWake.Store(nil) })
	return func(f *Flow) []int {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(held[f])
	}
}

// TestSourceBatchOneWakePerFlow_L54 (M5-D14, §A4.5): one read of 32
// datagrams for three flows wakes each flow's waiting reader exactly once,
// after every datagram of the read was routed (at its wake each inbox
// already holds all the read gave it, so a reader that drained early
// cannot stall); each reader then drains its inbox in arrival order; the
// flow whose inbox fills within the read drops the rest and counts them
// (M2's inbox rule, L58), and the slots of those drops keep their charge
// (R1-4: afterwards the Budget holds exactly the 31 waiting extras).
func TestSourceBatchOneWakePerFlow_L54(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		c := newFakeSock(32)
		h := newFHarness(t, env, Limits{Inbox: 8}, c, seamDgram)
		defer h.shutdown()
		from := apOf(2, 1000)
		c.queue(from, h1(1, wire.TypeOpen, 1), h1(2, wire.TypeOpen, 2), h1(3, wire.TypeOpen, 3))
		synctest.Wait()
		fs := h.flows()
		if len(fs) != 3 {
			t.Fatalf("%d flows admitted, want 3", len(fs))
		}
		for _, f := range fs {
			readOne(t, f, time.Second)
			f.Admitted()
			if err := f.SetReadDeadline(time.Time{}); err != nil {
				t.Fatal(err)
			}
		}

		// Every flow's reader waits.
		var mu sync.Mutex
		got := make([][]uint32, 3)
		var wg sync.WaitGroup
		for i, f := range fs {
			wg.Go(func() {
				for {
					b, _, ev, err := f.ReadDatagram(nil)
					if err != nil {
						return
					}
					mu.Lock()
					if ev == carrier.ReadOK {
						got[i] = append(got[i], pingSeq(b))
					}
					mu.Unlock()
					f.Release()
				}
			})
		}
		synctest.Wait()
		wakes := recordWakes(t)

		// One read: flows 1 and 2 get 8 each, flow 3 gets 16 (its inbox
		// holds 8): the pattern 1, 2, 3, 3 eight times.
		var batch [][]byte
		want := make([][]uint32, 3)
		for range 8 {
			for _, id := range []uint64{1, 2, 3, 3} {
				seq := uint32(100*id) + uint32(len(batch))
				batch = append(batch, dg(id, pingFrame(seq)))
				if len(want[id-1]) < 8 {
					want[id-1] = append(want[id-1], seq)
				}
			}
		}
		before := h.s.Stats().InboxDrops
		c.queue(from, batch...)
		synctest.Wait()

		if _, g := c.reads(); g[len(g)-1] != 32 {
			t.Fatalf("stimulus: the last read moved %d datagrams, want 32 (reads %v)", g[len(g)-1], g)
		}
		for i, f := range fs {
			if w := wakes(f); !slices.Equal(w, []int{8}) {
				t.Errorf("flow %d: wakes with %v queued, want one wake with all 8 of the read queued", i+1, w)
			}
		}
		mu.Lock()
		for i := range fs {
			if !slices.Equal(got[i], want[i]) {
				t.Errorf("flow %d read %v, want %v (arrival order, the full inbox's rest dropped)", i+1, got[i], want[i])
			}
		}
		mu.Unlock()
		if d := h.s.Stats().InboxDrops - before; d != 8 {
			t.Errorf("%d inbox drops, want 8 (flow 3's overflow)", d)
		}
		if d := env.Dgram.InboxDrops.Load(); d != 8 {
			t.Errorf("Runtime InboxDrops %d, want 8", d)
		}
		if b, want := env.Budget.Used(), 31*slotBytes(env, seamDgram); b != want {
			t.Errorf("Budget %d after the drain, want %d (the 31 extras of the waiting read, each charged once)", b, want)
		}
		h.s.Abort()
		wg.Wait()
	})
}

// TestSourceBatchBudgetRefusal_L16 (R1-4): while Env.Budget is full the
// Source reads into slot 0 only — every extra slot's TryGet is refused and
// counted in ChargeRefused — the hand-over of slot 0 is refused as in M2
// (a DGRAM is an inbox drop, control goes through the reserve), and the
// accounts are exact; once the Budget has room the next read takes its
// extras (charged while they wait) and moves 32 datagrams in one call.
func TestSourceBatchBudgetRefusal_L16(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const budget = 1 << 20
		env := testEnv(budget)
		slot := slotBytes(env, seamDgram)
		header := int64(32) * batchMsgBytes
		env.Budget.Acquire(budget) // a test charge fills the Budget
		c := newFakeSock(32)
		h := newFHarness(t, env, Limits{}, c, seamDgram)
		defer h.shutdown()
		from := apOf(2, 1000)
		c.queue(from, h1(1, wire.TypeOpen, 1))
		synctest.Wait()
		f := h.flows()[0]
		readOne(t, f, time.Second) // through the control reserve
		f.Admitted()

		c.queue(from, dg(1, dgramFrame(2, 100)), dg(1, pingFrame(3)), dg(1, dgramFrame(4, 100)))
		synctest.Wait()
		offered, _ := c.reads()
		for i, n := range offered {
			if n != 1 {
				t.Fatalf("read %d offered %d slots under a full Budget, want 1 (reads %v)", i, n, offered)
			}
		}
		if r, want := env.Dgram.ChargeRefused.Load(), uint64(31*len(offered)); r != want {
			t.Fatalf("ChargeRefused %d, want %d (31 per read)", r, want)
		}
		if d := h.s.Stats().InboxDrops; d != 2 {
			t.Fatalf("%d inbox drops, want 2 (the DGRAMs)", d)
		}
		if b, s := env.Budget.Used(), env.Stages.Used(); b != budget || s != header+slot {
			t.Fatalf("Budget %d, Stages %d; want %d (the test charge) and %d (the Batch and the PING's reserve)", b, s, budget, header+slot)
		}
		if b, _, ev := readOne(t, f, time.Second); ev != carrier.ReadOK || pingSeq(b) != 3 {
			t.Fatalf("event %d, want the PING", ev)
		}
		if s := env.Stages.Used(); s != header {
			t.Fatalf("Stages %d after the read, want %d", s, header)
		}

		// Room again: the read already waiting holds slot 0 only; the next
		// one takes its 31 extras.
		refused := env.Dgram.ChargeRefused.Load()
		env.Budget.Release(budget)
		c.queue(from, dg(1, pingFrame(5)))
		synctest.Wait()
		offered, _ = c.reads()
		if n := offered[len(offered)-1]; n != 32 {
			t.Fatalf("the read after the Budget freed offered %d slots, want 32", n)
		}
		if r := env.Dgram.ChargeRefused.Load(); r != refused {
			t.Fatalf("ChargeRefused %d → %d with room in the Budget", refused, r)
		}
		if b := env.Budget.Used(); b != 32*slot {
			t.Fatalf("Budget %d, want %d (31 waiting extras and the queued PING's slot)", b, 32*slot)
		}
		readOne(t, f, time.Second)
		if b := env.Budget.Used(); b != 31*slot {
			t.Fatalf("Budget %d, want %d (the waiting extras)", b, 31*slot)
		}
		var batch [][]byte
		for i := range 32 {
			batch = append(batch, dg(1, pingFrame(uint32(6+i))))
		}
		c.queue(from, batch...)
		synctest.Wait()
		if _, g := c.reads(); g[len(g)-1] != 32 {
			t.Fatalf("the last read moved %d datagrams, want 32", g[len(g)-1])
		}
		for i := range 32 {
			if b, _, _ := readOne(t, f, time.Second); pingSeq(b) != uint32(6+i) {
				t.Fatalf("datagram %d: seq %d", i, pingSeq(b))
			}
		}
		if b, s := env.Budget.Used(), env.Stages.Used(); b != 31*slot || s != header {
			t.Fatalf("Budget %d, Stages %d after the drain; want %d and %d", b, s, 31*slot, header)
		}
		h.shutdown()
		if u := buffered(env); u != 0 {
			t.Fatalf("%d bytes buffered after Done", u)
		}
	})
}

// TestSourceFallbackReleasesSlots_L16 (M5-D15, L16): a socket that leaves
// ModeBatch reads one datagram per call from its next read on and returns
// the extra slots and the Batch: only slot 0, uncharged, remains.
func TestSourceFallbackReleasesSlots_L16(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		c := newFakeSock(32)
		h := newFHarness(t, env, Limits{}, c, seamDgram)
		defer h.shutdown()
		from := apOf(2, 1000)
		c.queue(from, h1(1, wire.TypeOpen, 1))
		synctest.Wait()
		f := h.flows()[0]
		readOne(t, f, time.Second)
		if u := buffered(env); u != 31*slotBytes(env, seamDgram)+32*batchMsgBytes {
			t.Fatalf("stimulus: %d bytes buffered by a batching source", u)
		}
		c.mode.Store(uint32(udpsocket.ModePlain))
		c.queue(from, dg(1, pingFrame(2)), dg(1, pingFrame(3)))
		synctest.Wait()
		offered, _ := c.reads()
		if n := offered[len(offered)-1]; n != 1 {
			t.Fatalf("a read after the fallback offered %d slots, want 1", n)
		}
		readOne(t, f, time.Second)
		readOne(t, f, time.Second)
		if u := buffered(env); u != 0 {
			t.Fatalf("%d bytes buffered after the fallback, want 0", u)
		}
	})
}

// TestSourceMaxBatchOne (R1-6, M5-D16): a Source whose socket has
// MaxBatch 1 reads one datagram per call — through the seam (a socket in
// ModeBatch) and on a real socket, where 1,000 datagrams cost exactly
// 1,000 counted receive calls.
func TestSourceMaxBatchOne(t *testing.T) {
	t.Run("seam", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			env := testEnv(1 << 30)
			c := newFakeSock(1)
			h := newFHarness(t, env, Limits{}, c, seamDgram)
			defer h.shutdown()
			from := apOf(2, 1000)
			batch := [][]byte{h1(1, wire.TypeOpen, 1)}
			for i := range 40 {
				batch = append(batch, dg(1, pingFrame(uint32(2+i))))
			}
			c.queue(from, batch...)
			synctest.Wait()
			offered, got := c.reads()
			if len(got) != 41 || slices.ContainsFunc(offered, func(n int) bool { return n != 1 }) {
				t.Fatalf("41 queued datagrams: reads offered %v, moved %v; want one per call", offered, got)
			}
			if u := buffered(env); u != 41*slotBytes(env, seamDgram) {
				t.Fatalf("%d bytes buffered: depth 1 holds no extras", u)
			}
		})
	})
	t.Run("real", func(t *testing.T) {
		env := testEnv(1 << 30)
		rs := newRealSourceIO(t, 1232, env, Limits{}, 1)
		rs.start()
		const id, total, burst = 0x51, 1000, 25
		rs.send(h1(id, wire.TypeOpen, 1))
		f := rs.flow()
		readOne(t, f, realWait)
		f.Admitted()
		for sent := 1; sent < total; {
			n := min(burst, total-sent)
			for i := range n {
				rs.send(dg(id, pingFrame(uint32(sent+i+1))))
			}
			for i := range n {
				if b, _, ev := readOne(t, f, realWait); ev != carrier.ReadOK || pingSeq(b) != uint32(sent+i+1) {
					t.Fatalf("datagram %d: event %d", sent+i, ev)
				}
			}
			sent += n
		}
		_, _, calls, dgrams, _ := env.Dgram.IO.Load()
		if calls != total || dgrams != total {
			t.Fatalf("RecvCalls %d, RecvDatagrams %d; want %d and %d", calls, dgrams, total, total)
		}
	})
}

// TestSourceDrainsQueuedSeam_L54 (R1-7, B0.2 item 5): 32 datagrams queued
// before the Source reads move in one call of depth 32; the seam half of
// TestSourceDrainsQueued_L54 (Linux real socket), run on every OS.
func TestSourceDrainsQueuedSeam_L54(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		c := newFakeSock(32)
		from := apOf(2, 1000)
		batch := [][]byte{h1(1, wire.TypeOpen, 1)}
		for i := range 31 {
			batch = append(batch, dg(1, pingFrame(uint32(2+i))))
		}
		c.queue(from, batch...)
		h := newFHarness(t, env, Limits{}, c, seamDgram)
		defer h.shutdown()
		synctest.Wait()
		offered, got := c.reads()
		if len(got) != 1 || got[0] != 32 || offered[0] != 32 {
			t.Fatalf("32 queued datagrams: reads offered %v, moved %v; want one call of 32", offered, got)
		}
		f := h.flows()[0]
		for i := range 32 {
			b, _, _ := readOne(t, f, time.Second)
			if i > 0 && pingSeq(b) != uint32(1+i) {
				t.Fatalf("datagram %d: seq %d", i, pingSeq(b))
			}
		}
	})
}

// TestFlowReadDatagramsOrder (§A4.5): ReadDatagrams drains up to
// min(len(rs), MaxBatch) inbox datagrams per call in arrival order, each
// as ReadDatagram would return it (a candidate from another source — the
// call's last result, R3-14 — a datagram over the receive limit
// truncated); the buffers stay charged until the next read or Release,
// and the held-entry slice of the largest call until Close (R3-28).
func TestFlowReadDatagramsOrder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		c := newFakeSock(32)
		h := newFHarness(t, env, Limits{}, c, seamDgram)
		defer h.shutdown()
		peer, other := apOf(2, 1000), apOf(3, 1000)
		c.queue(peer, h1(1, wire.TypeOpen, 1))
		synctest.Wait()
		f := h.flows()[0]
		if f.MaxBatch() != 32 {
			t.Fatalf("MaxBatch %d, want the socket's 32", f.MaxBatch())
		}
		readOne(t, f, time.Second)
		f.SetLimit(600)
		base, sbase := env.Budget.Used(), env.Stages.Used()

		c.queue(peer, dg(1, pingFrame(2)))
		c.queue(other, dg(1, pingFrame(3)))
		c.queue(peer, dg(1, make([]byte, 601)), dg(1, pingFrame(5)))
		var tail [][]byte
		for i := range 40 {
			tail = append(tail, dg(1, pingFrame(uint32(6+i))))
		}
		c.queue(peer, tail...)
		synctest.Wait()

		rs := make([]carrier.ReadResult, 3)
		n, err := f.ReadDatagrams(rs)
		if err != nil || n != 2 {
			t.Fatalf("ReadDatagrams: %d, %v; want 2 (the call ends at its candidate)", n, err)
		}
		if rs[0].Ev != carrier.ReadOK || pingSeq(rs[0].Data) != 2 || rs[0].Src.AP != peer {
			t.Fatalf("result 0: %+v", rs[0])
		}
		if rs[1].Ev != carrier.ReadCandidate || pingSeq(rs[1].Data) != 3 || rs[1].Src.AP != other {
			t.Fatalf("result 1: event %d, source %v", rs[1].Ev, rs[1].Src)
		}
		if err := f.WriteDatagramTo(make([]byte, wire.FlowHeaderLen+8), carrier.PeerKey{AP: other}); err != nil {
			t.Fatalf("a challenge to the batch's candidate: %v", err)
		}
		held := env.Budget.Used()
		big := make([]carrier.ReadResult, 64)
		n, err = f.ReadDatagrams(big)
		if err != nil || n != 32 {
			t.Fatalf("ReadDatagrams of 64: %d, %v; want 32 (MaxBatch)", n, err)
		}
		if env.Budget.Used() >= held {
			t.Fatal("the previous batch's buffers were not returned by the next read")
		}
		if big[0].Ev != carrier.ReadTruncated || big[0].Data != nil {
			t.Fatalf("result 0: event %d, %d bytes; want truncated", big[0].Ev, len(big[0].Data))
		}
		for i := 1; i < n; i++ {
			if want := uint32(4 + i); big[i].Ev != carrier.ReadOK || pingSeq(big[i].Data) != want {
				t.Fatalf("result %d: event %d, seq %d, want %d", i, big[i].Ev, pingSeq(big[i].Data), want)
			}
		}
		n, err = f.ReadDatagrams(big)
		if err != nil || n != 10 || pingSeq(big[9].Data) != 45 {
			t.Fatalf("the rest: %d, %v", n, err)
		}
		f.Release()
		if u, s, want := env.Budget.Used(), env.Stages.Used(), sbase+32*entrySize; u != base || s != want {
			t.Fatalf("after Release: Budget %d, Stages %d; want %d and %d (the held slice of 32 entries, in Stages)", u, s, base, want)
		}
		if _, err := f.ReadDatagrams(nil); err == nil {
			t.Fatal("ReadDatagrams without a result slot succeeded")
		}
		if err := f.SetReadDeadline(time.Now().Add(time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if _, err := f.ReadDatagrams(big); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("an empty inbox: %v, want the deadline", err)
		}
		f.Close()
		if u, s := env.Budget.Used(), env.Stages.Used(); u != base || s != sbase {
			t.Fatalf("after Close: Budget %d, Stages %d; want %d and %d: Close returns the slice's charge", u, s, base, sbase)
		}
		if _, err := f.ReadDatagrams(big); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("a closed flow: %v", err)
		}
		if f.held != nil || env.Budget.Used() != base || env.Stages.Used() != sbase {
			t.Fatalf("a closed flow's read kept its slice (cap %d) or charged one (Budget %d, Stages %d; want %d and %d)", cap(f.held), env.Budget.Used(), env.Stages.Used(), base, sbase)
		}
	})
}

// TestFlowWriteDatagramsSeam (§A4.5, R1-5 rule 2): WriteDatagrams writes
// the flow header in front of each datagram and hands the call's
// datagrams to the socket in calls of at most MaxBatch with the writer's
// pooled Batch (a single datagram without one); a Batch is charged to
// Stages only while a call holds it; the error of datagram n is returned
// with n (L42's invalid count here; the errno classes in
// TestFlowWriteDatagramsNoise, batch_errno_test.go).
func TestFlowWriteDatagramsSeam(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		c := newFakeSock(4)
		h := newFHarness(t, env, Limits{}, c, seamDgram)
		defer h.shutdown()
		peer := apOf(2, 1000)
		c.queue(peer, h1(7, wire.TypeOpen, 1))
		synctest.Wait()
		f := h.flows()[0]
		readOne(t, f, time.Second)
		stages := env.Stages.Used()

		ds := make([][]byte, 10)
		for i := range ds {
			ds[i] = make([]byte, wire.FlowHeaderLen+3)
			ds[i][wire.FlowHeaderLen] = byte(i)
		}
		if n, err := f.WriteDatagrams(ds); n != 10 || err != nil {
			t.Fatalf("WriteDatagrams: %d, %v", n, err)
		}
		if !slices.Equal(c.wsizes, []int{4, 4, 2}) || slices.Contains(c.wbatched, false) {
			t.Fatalf("calls %v (batched %v), want 4, 4, 2 with a Batch", c.wsizes, c.wbatched)
		}
		for i, m := range c.written() {
			id, rest, err := wire.ParseFlowHeader(m.b)
			if err != nil || id != 7 || rest[0] != byte(i) || m.addr != peer {
				t.Fatalf("datagram %d: flow %x (%v), first byte %d, to %v", i, id, err, rest[0], m.addr)
			}
		}
		if err := f.WriteDatagram(ds[0]); err != nil || c.wbatched[len(c.wbatched)-1] {
			t.Fatalf("a single datagram: %v, batched %v", err, c.wbatched[len(c.wbatched)-1])
		}
		// A socket that does not batch writes one call per datagram: the
		// writer takes no Batch (and no Stages charge) for it.
		c.mode.Store(uint32(udpsocket.ModePlain))
		if n, err := f.WriteDatagrams(ds[:4]); n != 4 || err != nil || c.wbatched[len(c.wbatched)-1] {
			t.Fatalf("plain mode: %d, %v, batched %v", n, err, c.wbatched[len(c.wbatched)-1])
		}
		c.mode.Store(uint32(udpsocket.ModeBatch))
		if s := env.Stages.Used(); s != stages {
			t.Fatalf("Stages %d after the calls, want %d: an idle writer holds no Batch", s, stages)
		}

		c.mu.Lock()
		c.wErrs = []fakeWErr{{n: 1, err: udpsocket.ErrInvalidCount}}
		c.mu.Unlock()
		if n, err := f.WriteDatagrams(ds[:4]); n != 1 || err != udpsocket.ErrInvalidCount {
			t.Fatalf("an invalid count: %d, %v (L42: death)", n, err)
		}
		f.Close()
		if _, err := f.WriteDatagrams(ds[:2]); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("a closed flow: %v", err)
		}
	})
}

// TestSourceTokenIO: tokenIO — the path of a token without the batched
// accessor, or whose socket refuses it — reads and writes one datagram
// per call through the token's own AddrPort methods and classes (M2).
func TestSourceTokenIO(t *testing.T) {
	env := testEnv(1 << 30)
	rs := newRealSourceIO(t, 1232, env, Limits{}, -1)
	rs.start()
	const id = 0x61
	rs.send(h1(id, wire.TypeOpen, 1))
	f := rs.flow()
	readOne(t, f, realWait)
	if f.MaxBatch() != 1 {
		t.Fatalf("MaxBatch %d, want 1", f.MaxBatch())
	}
	rs.send(make([]byte, 1233)) // truncated
	rs.send(nil)                // empty
	rs.send(dg(id, pingFrame(2)))
	if b, _, ev := readOne(t, f, realWait); ev != carrier.ReadOK || pingSeq(b) != 2 {
		t.Fatalf("event %d", ev)
	}
	if st := rs.s.Stats(); st.Truncated != 1 || st.Dropped != 2 {
		t.Fatalf("Stats %+v", st)
	}
	wb := make([]byte, wire.FlowHeaderLen+5)
	if n, err := f.WriteDatagrams([][]byte{wb, wb}); n != 2 || err != nil {
		t.Fatalf("WriteDatagrams: %d, %v", n, err)
	}
	for range 2 {
		if got, _ := rs.recv(); len(got) != len(wb) {
			t.Fatalf("client got %d bytes", len(got))
		}
	}
}

// TestSourceAdoptsTokenSocket (A2.1, A4.4, R1-2, R1-6): NewSource alone —
// no test seam — reads and writes rendr's own socket through the token's
// counted udpsocket.Conn (M5 WP2's NewBatchConn) at depth min(MaxBatch,
// 32), and every read and write of the traffic is counted in
// Env.Dgram.IO. It skips only while carrier.OwnedUDPSocket has no
// NewBatchConn at all (before WP2 merges); a NewBatchConn that does not
// match batchToken fails, so the Source can never silently stay at one
// uncounted datagram per call.
func TestSourceAdoptsTokenSocket(t *testing.T) {
	env := testEnv(1 << 30)
	rs := newRealSourceIO(t, 1232, env, Limits{}, 0)
	rs.start()
	c, ok := rs.s.bio.(*udpsocket.Conn)
	if !ok {
		if _, has := reflect.TypeFor[*carrier.OwnedUDPSocket]().MethodByName("NewBatchConn"); has {
			t.Fatalf("carrier.OwnedUDPSocket has NewBatchConn, yet NewSource uses %T: the method set does not match batchToken, or the socket refused it", rs.s.bio)
		}
		t.Skip("contract pending: carrier.OwnedUDPSocket has no NewBatchConn yet (M5 WP2; WP3 contract note 1)")
	}
	if c.MaxBatch() != defaultMaxBatch {
		t.Fatalf("the Conn's MaxBatch is %d, want the token's default %d", c.MaxBatch(), defaultMaxBatch)
	}
	want := 1
	if c.Mode() == udpsocket.ModeBatch {
		want = min(defaultMaxBatch, srcMaxDepth)
	}
	if d := rs.s.readDepth(); d != want {
		t.Fatalf("read depth %d, want %d (mode %v)", d, want, c.Mode())
	}
	const id = 0x77
	rs.send(h1(id, wire.TypeOpen, 1))
	f := rs.flow()
	readOne(t, f, realWait)
	if f.MaxBatch() != defaultMaxBatch {
		t.Fatalf("Flow MaxBatch %d, want %d", f.MaxBatch(), defaultMaxBatch)
	}
	for i := range 3 {
		rs.send(dg(id, pingFrame(uint32(2+i))))
	}
	for range 3 {
		readOne(t, f, realWait)
	}
	wb := make([]byte, wire.FlowHeaderLen+5)
	if n, err := f.WriteDatagrams([][]byte{wb, wb}); n != 2 || err != nil {
		t.Fatalf("WriteDatagrams: %d, %v", n, err)
	}
	for range 2 {
		rs.recv()
	}
	sc, sent, rc, rd, _ := env.Dgram.IO.Load()
	if sc == 0 || sent != 2 || rc == 0 || rd != 4 {
		t.Fatalf("IO counters: SendCalls %d, SentDatagrams %d, RecvCalls %d, RecvDatagrams %d; want sends and 4 datagrams read, all counted", sc, sent, rc, rd)
	}
}

// noiseToken is an ownership token whose next reads report ReadNoise
// (an ICMP-class error of the socket) before it reads its fakeSock.
type noiseToken struct {
	c     *fakeSock
	noise atomic.Int32
}

func (t *noiseToken) ReadAddrPort(p []byte) (int, netip.AddrPort, carrier.ReadEvent, error) {
	if t.noise.Add(-1) >= 0 {
		return 0, netip.AddrPort{}, carrier.ReadNoise, nil
	}
	ms := []udpsocket.Msg{{Buf: p}}
	if _, err := t.c.ReadBatch(nil, ms); err != nil {
		return 0, netip.AddrPort{}, carrier.ReadOK, err
	}
	return ms[0].N, ms[0].Addr, carrier.ReadOK, nil
}

func (t *noiseToken) WriteAddrPort(p []byte, dst netip.AddrPort) error {
	_, err := t.c.WriteBatch(nil, []udpsocket.Msg{{Buf: p, Addr: dst}})
	return err
}

// TestSourceTokenIONoise_L58: through tokenIO, a token's ReadNoise is a
// transient error — the Source counts it, backs off and keeps reading —
// not the end of every flow of the socket.
func TestSourceTokenIONoise_L58(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		c := newFakeSock(32)
		tok := &noiseToken{c: c}
		tok.noise.Store(2)
		s := newSeamSource(env, c, tokenIO{tok}, seamDgram, Limits{})
		admitted := make(chan *Flow, 1)
		go s.Run(func(f *Flow) { admitted <- f })
		c.queue(apOf(2, 1000), h1(1, wire.TypeOpen, 1))
		time.Sleep(time.Second) // past the backoffs
		synctest.Wait()
		var f *Flow
		select {
		case f = <-admitted:
		default:
			t.Fatal("no flow admitted after two noise reads: the Source stopped")
		}
		readOne(t, f, time.Second)
		if st := s.Stats(); st.ReadErrors != 2 {
			t.Fatalf("ReadErrors %d, want 2", st.ReadErrors)
		}
		s.Abort()
		f.Close()
		<-s.Done()
	})
}

// TestSourceChargedSlotMoves_L16 (R1-4): a datagram read into a charged
// slot (1 … D−1) moves to its flow's inbox with the charge it already
// carries — nothing is charged twice — so with Budget room for exactly one
// more buffer a read of three DGRAMs delivers all three (slot 0 takes the
// last room at its hand-over).
func TestSourceChargedSlotMoves_L16(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		probe := testEnv(1 << 30)
		slot := slotBytes(probe, seamDgram)
		env := testEnv(32 * slot) // the 31 waiting extras and one more buffer
		c := newFakeSock(32)
		h := newFHarness(t, env, Limits{}, c, seamDgram)
		defer h.shutdown()
		from := apOf(2, 1000)
		c.queue(from, h1(1, wire.TypeOpen, 1))
		synctest.Wait()
		f := h.flows()[0]
		readOne(t, f, time.Second)
		f.Admitted()
		if b := env.Budget.Used(); b != 31*slot {
			t.Fatalf("stimulus: Budget %d, want the 31 extras (%d)", b, 31*slot)
		}
		c.queue(from, dg(1, dgramFrame(2, 100)), dg(1, dgramFrame(3, 100)), dg(1, dgramFrame(4, 100)))
		synctest.Wait()
		if _, g := c.reads(); g[len(g)-1] != 3 {
			t.Fatalf("stimulus: the read moved %d datagrams, want 3", g[len(g)-1])
		}
		if d := h.s.Stats().InboxDrops; d != 0 {
			t.Fatalf("%d inbox drops: a charged slot was charged again at its hand-over", d)
		}
		for i := range 3 {
			if b, _, ev := readOne(t, f, time.Second); ev != carrier.ReadOK || wire.Type(b[0]) != wire.TypeDgram {
				t.Fatalf("datagram %d: event %d", i, ev)
			}
		}
	})
}

// TestSourceAnswerCounted (R1-2, A2.1): the stateless answers of rendr's
// own socket go through its counted calls like every other write. The
// count lands when the Source's write returns, which may be after the
// client already read the answer: the row waits for it (bounded), then
// requires exactly one call of one datagram.
func TestSourceAnswerCounted(t *testing.T) {
	env := testEnv(1 << 30)
	rs := newRealSourceIO(t, 1232, env, Limits{}, defaultMaxBatch)
	rs.start()
	rs.send(h1(0x76, wire.TypeOpen, 8))
	rs.flow() // keeps the stopped source's socket open
	rs.s.Stop()
	rs.send(h1(0x77, wire.TypeOpen, 9))
	ans, _ := rs.recv()
	if id, ack := parseAnswer(t, ans); id != 0x77 || ack.Status != wire.PrefaceCapacity {
		t.Fatalf("answer: flow %x, %+v", id, ack)
	}
	for deadline := time.Now().Add(realWait); ; time.Sleep(time.Millisecond) {
		calls, sent, _, _, _ := env.Dgram.IO.Load()
		if calls != 0 || time.Now().After(deadline) {
			if calls != 1 || sent != 1 {
				t.Fatalf("SendCalls %d, SentDatagrams %d; want the answer counted once", calls, sent)
			}
			break
		}
	}
}

// TestSourceSlotTruncation_L58 (L58, M2's truncation rule per slot): every
// read slot is MaxDatagram + 1 bytes, so within one read a datagram of
// exactly MaxDatagram is delivered whole and a longer one is a truncation
// drop, whichever slot it lands in.
func TestSourceSlotTruncation_L58(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		c := newFakeSock(32)
		h := newFHarness(t, env, Limits{}, c, seamDgram)
		defer h.shutdown()
		from := apOf(2, 1000)
		c.queue(from, h1(1, wire.TypeOpen, 1))
		synctest.Wait()
		f := h.flows()[0]
		readOne(t, f, time.Second)
		full := dg(1, make([]byte, seamDgram-wire.FlowHeaderLen))
		over := dg(1, make([]byte, seamDgram-wire.FlowHeaderLen+1))
		c.queue(from, full, over, full, over)
		synctest.Wait()
		if _, g := c.reads(); g[len(g)-1] != 4 {
			t.Fatalf("stimulus: the read moved %d datagrams, want 4", g[len(g)-1])
		}
		for i := range 2 {
			if b, _, ev := readOne(t, f, time.Second); ev != carrier.ReadOK || len(b) != seamDgram-wire.FlowHeaderLen {
				t.Fatalf("datagram %d: event %d, %d bytes", i, ev, len(b))
			}
		}
		if st := h.s.Stats(); st.Truncated != 2 || st.Dropped != 2 {
			t.Fatalf("Stats %+v, want 2 truncated", st)
		}
	})
}
