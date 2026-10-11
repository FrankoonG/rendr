package udpflow

// The integrator's rows of M5 design Revision 3 (FIXA): a flow's batched
// read ends at its first rebind candidate (R3-14), and its held-entry
// slice is charged to Env.Budget (R3-28, R3-23). Seam sources inside
// synctest bubbles (every OS).

import (
	"testing"
	"testing/synctest"
	"time"
	"unsafe"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/udpsocket"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// entrySize is what one held entry costs the Budget: the size of the
// inbox entry (R3-28).
const entrySize = int64(unsafe.Sizeof(entry{}))

// queueFrom queues datagrams of several sources at once (one socket read
// returns them together).
func queueFrom(c *fakeSock, ms ...fakeMsg) {
	c.mu.Lock()
	c.q = append(c.q, ms...)
	c.mu.Unlock()
	c.wake()
}

// TestFlowReadDatagramsEndsAtCandidate_L55 (R3-14, L55): one batch of the
// inbox holds the challenge answer from B (the flow's peer is A) and then
// a datagram from C. ReadDatagrams returns B's answer alone, as the call's
// last result; the carrier commits the rebind — SetPeer(B) succeeds —
// before C's datagram is classified: the next call returns it as the new
// candidate, and B's next datagram is the peer's (ReadOK).
// Mutant: the drain loop reads past a candidate (SetPeer(B) then fails,
// "not the flow's latest rebind candidate").
func TestFlowReadDatagramsEndsAtCandidate_L55(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		c := newFakeSock(32)
		h := newFHarness(t, env, Limits{}, c, seamDgram)
		defer h.shutdown()
		a, b, cc := apOf(2, 1000), apOf(3, 1000), apOf(4, 1000)
		c.queue(a, h1(1, wire.TypeOpen, 1))
		synctest.Wait()
		f := h.flows()[0]
		readOne(t, f, time.Second)

		queueFrom(c, fakeMsg{dg(1, pingFrame(2)), b}, fakeMsg{dg(1, pingFrame(3)), cc})
		synctest.Wait()
		if _, g := c.reads(); g[len(g)-1] != 2 {
			t.Fatalf("stimulus: the last socket read moved %d datagrams, want both in one batch", g[len(g)-1])
		}

		rs := make([]carrier.ReadResult, 8)
		n, err := f.ReadDatagrams(rs)
		if err != nil || n < 1 || rs[0].Ev != carrier.ReadCandidate || rs[0].Src.AP != b || pingSeq(rs[0].Data) != 2 {
			t.Fatalf("ReadDatagrams: %d results, %v; result 0 event %d from %v; want B's candidate 2", n, err, rs[0].Ev, rs[0].Src)
		}
		if err := f.SetPeer(carrier.PeerKey{AP: b}); err != nil {
			t.Fatalf("SetPeer(B) after B's answer: %v (a later datagram of the call replaced the candidate; the call returned %d results)", err, n)
		}
		if n != 1 {
			t.Fatalf("ReadDatagrams: %d results, want B's answer alone (the call ends at its candidate)", n)
		}

		n, err = f.ReadDatagrams(rs)
		if err != nil || n != 1 || rs[0].Ev != carrier.ReadCandidate || rs[0].Src.AP != cc || pingSeq(rs[0].Data) != 3 {
			t.Fatalf("second call: %d results (%v), result 0 event %d from %v; want C's datagram alone as the new candidate", n, err, rs[0].Ev, rs[0].Src)
		}
		c.queue(b, dg(1, pingFrame(4)))
		synctest.Wait()
		n, err = f.ReadDatagrams(rs)
		if err != nil || n != 1 || rs[0].Ev != carrier.ReadOK || rs[0].Src.AP != b || pingSeq(rs[0].Data) != 4 {
			t.Fatalf("third call: %d results (%v), result 0 event %d from %v; want B's datagram as the peer's", n, err, rs[0].Ev, rs[0].Src)
		}
		f.Release()
	})
}

// TestFlowHeldSliceCharged_L16 (R3-28, R1-4, L16): 1,000 flows each read
// once through ReadDatagrams (8 result slots, MaxBatch 32) hold exactly
// 1,000 held-entry slices of 8 entries, charged to Env.Budget —
// BufferedBytes is the source's baseline plus that, to the byte — and
// once every flow closed BufferedBytes is back at the baseline. A flow
// whose socket moves one datagram per call (MaxBatch 1) takes no slice.
// Mutants: the slice not charged; Close not returning its charge.
func TestFlowHeldSliceCharged_L16(t *testing.T) {
	t.Run("1000 flows", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			const flows = 1000
			env := testEnv(1 << 30)
			c := newFakeSock(32)
			h := newFHarness(t, env, Limits{PerSource: flows}, c, seamDgram)
			defer h.shutdown()
			from := apOf(2, 1000)
			synctest.Wait()
			base := buffered(env) // the Source's waiting extras and Batch

			for i := range flows {
				c.queue(from, h1(uint64(1+i), wire.TypeOpen, 1))
			}
			synctest.Wait()
			fs := h.flows()
			if len(fs) != flows {
				t.Fatalf("%d flows admitted, want %d", len(fs), flows)
			}
			rs := make([]carrier.ReadResult, 8)
			for i, f := range fs {
				if n, err := f.ReadDatagrams(rs); err != nil || n != 1 || rs[0].Ev != carrier.ReadOK {
					t.Fatalf("flow %d: ReadDatagrams %d, %v, event %d", i, n, err, rs[0].Ev)
				}
				f.Release()
				f.Admitted()
			}
			if got, want := buffered(env), base+flows*8*entrySize; got != want {
				t.Fatalf("BufferedBytes %d after %d flows read once, want %d (baseline %d + %d slices of 8 × %d B)", got, flows, want, base, flows, entrySize)
			}
			if r := env.Dgram.ChargeRefused.Load(); r != 0 {
				t.Fatalf("ChargeRefused %d with room in the Budget", r)
			}
			for _, f := range fs {
				f.Close()
			}
			if got := buffered(env); got != base {
				t.Fatalf("BufferedBytes %d after every flow closed, want the baseline %d", got, base)
			}
		})
	})
	t.Run("MaxBatch 1", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			env := testEnv(1 << 30)
			c := newFakeSock(1)
			h := newFHarness(t, env, Limits{}, c, seamDgram)
			defer h.shutdown()
			from := apOf(2, 1000)
			synctest.Wait()
			base := buffered(env)
			c.queue(from, h1(1, wire.TypeOpen, 1), dg(1, pingFrame(2)))
			synctest.Wait()
			f := h.flows()[0]
			rs := make([]carrier.ReadResult, 8)
			for want := range uint32(2) {
				if n, err := f.ReadDatagrams(rs); err != nil || n != 1 {
					t.Fatalf("read %d: %d, %v", want, n, err)
				}
			}
			f.Release()
			if got := buffered(env); got != base {
				t.Fatalf("BufferedBytes %d, want the baseline %d: one datagram per call holds no slice", got, base)
			}
		})
	})
}

// TestFlowHeldSliceRefused_L16 (R3-28, R3-23): with Env.Budget full a
// flow's first ReadDatagrams cannot charge its held slice; the read never
// fails — it moves one datagram — and ChargeRefused counts the 7 slots
// beyond the first; each later call while the Budget stays full asks
// again (+7 each). Once the Budget has room the next call charges the
// slice and moves the rest of the inbox in one call. Mutant: a refused
// charge still reads at full depth (or uncharged).
func TestFlowHeldSliceRefused_L16(t *testing.T) {
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
		f.Admitted()
		for i := range 5 {
			c.queue(from, dg(1, pingFrame(uint32(2+i))))
		}
		synctest.Wait()

		bud := env.Budget
		charge := bud.Max()
		bud.Acquire(charge) // a test charge keeps the Budget full while buffers go back
		before := bud.Used()
		rs := make([]carrier.ReadResult, 8)
		for i := range 2 {
			n, err := f.ReadDatagrams(rs)
			if err != nil || n != 1 || rs[0].Ev != carrier.ReadOK || pingSeq(rs[0].Data) != uint32(2+i) {
				t.Fatalf("call %d with the Budget full: %d results, %v; want datagram %d alone", i, n, err, 2+i)
			}
			if r := env.Dgram.ChargeRefused.Load(); r != uint64(7*(i+1)) {
				t.Fatalf("call %d: ChargeRefused %d, want %d (7 refused slots per call)", i, r, 7*(i+1))
			}
		}
		f.Release()
		if got := bud.Used(); got >= before {
			t.Fatalf("Budget %d after the refused calls' Release, want below %d: no slice was charged and the datagrams' buffers went back", got, before)
		}
		bud.Release(charge)
		used := bud.Used()
		n, err := f.ReadDatagrams(rs)
		if err != nil || n != 3 || pingSeq(rs[0].Data) != 4 || pingSeq(rs[2].Data) != 6 {
			t.Fatalf("with room: %d results, %v; want the other 3 in one call", n, err)
		}
		if got := bud.Used() - used; got != 8*entrySize {
			t.Fatalf("the slice charged %d, want %d", got, 8*entrySize)
		}
		if r := env.Dgram.ChargeRefused.Load(); r != 14 {
			t.Fatalf("ChargeRefused %d after the charge succeeded, want 14", r)
		}
		f.Release()
	})
}

// TestSourceAdoptsTokenSocketMaxBatchOne (R3-25, R1-6, M5-D16): a token
// built with Options.MaxBatch 1 (NewOwnedUDPSocketBatch(u, 1232, 1)) gives
// NewSource — no test seam — a counted udpsocket.Conn of MaxBatch 1: the
// Source reads at depth 1, its flows report MaxBatch 1, and every read and
// write of the traffic moves one counted datagram per call. Mutant: the
// token's NewBatchConn ignores its MaxBatch.
func TestSourceAdoptsTokenSocketMaxBatchOne(t *testing.T) {
	env := testEnv(1 << 30)
	rs := newRealSourceTok(t, 1232, env, Limits{}, 0, 1)
	rs.start()
	c, ok := rs.s.bio.(*udpsocket.Conn)
	if !ok {
		t.Fatalf("NewSource uses %T, want the token's *udpsocket.Conn", rs.s.bio)
	}
	if c.MaxBatch() != 1 || rs.s.readDepth() != 1 {
		t.Fatalf("the Conn's MaxBatch %d, read depth %d; want 1 and 1", c.MaxBatch(), rs.s.readDepth())
	}
	const id, total = 0x78, 40
	rs.send(h1(id, wire.TypeOpen, 1))
	f := rs.flow()
	readOne(t, f, realWait)
	if f.MaxBatch() != 1 {
		t.Fatalf("Flow MaxBatch %d, want 1", f.MaxBatch())
	}
	for i := range total {
		rs.send(dg(id, pingFrame(uint32(2+i))))
	}
	for i := range total {
		if b, _, ev := readOne(t, f, realWait); ev != carrier.ReadOK || pingSeq(b) != uint32(2+i) {
			t.Fatalf("datagram %d: event %d", i, ev)
		}
	}
	ds := make([][]byte, 4)
	for i := range ds {
		ds[i] = make([]byte, wire.FlowHeaderLen+5)
	}
	if n, err := f.WriteDatagrams(ds); n != 4 || err != nil {
		t.Fatalf("WriteDatagrams: %d, %v", n, err)
	}
	for range 4 {
		rs.recv()
	}
	sc, sent, rc, rd, fb := env.Dgram.IO.Load()
	if sc != 4 || sent != 4 || rc != total+1 || rd != total+1 || fb != 0 {
		t.Fatalf("IO counters: send %d calls / %d datagrams, recv %d / %d, fallbacks %d; want 4 / 4 and %d / %d, 0", sc, sent, rc, rd, fb, total+1, total+1)
	}
}
