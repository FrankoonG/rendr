package udpflow

// The per-flow inbox bounded by the socket's read buffer (M5 work item
// inboxtime; the delegate's F-6 decision on C-P's G3-bond-100k rows, whose
// passive dropped 17,145 and 20,484 datagrams in flow inboxes of 512
// datagrams — 5 ms at 100 kpps — with a clean kernel path and a 16-MiB
// read buffer). On rendr's own listening socket a flow queues datagram
// buffers while their bytes are below the socket's read buffer (never
// fewer than one read's 32 datagrams), and always while it holds fewer
// than Limits.Inbox (M2's 512, so a large MaxDatagram's slot class never
// holds fewer than M2 did); both bounds are the flow's own. Its entry
// storage grows by pooled blocks charged to Stages and shrinks as its
// reader drains them, so an idle flow holds its first block only, and a
// drained block references nothing; every queued datagram stays charged
// to the Budget, so MaxBufferedBytes bounds them all. Seam sources inside
// synctest bubbles and real tokens, on every OS; the real-socket rows
// through carrier/udp's Listen are carrier/udp's
// TestFlowInboxHoldsTwentyMillisAt100kpps_L40 and
// TestListenJumboInboxKeepsM2Bound_L40.

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// inboxStorageLocked returns the entries of f's linked inbox blocks, how
// many of those blocks are pooled ones (charged), and the datagrams queued.
// f.mu is held.
func inboxStorageLocked(f *Flow) (entries, pooled, queued int) {
	for b := f.head; b != nil; b = b.next {
		entries += len(b.e)
		if b != f.base {
			pooled++
		}
	}
	return entries, pooled, f.n
}

// pooledFor is the pooled blocks an inbox links for n datagrams pushed
// into it with no read in between: one per blockLen beyond its first block.
func pooledFor(n int) int {
	if n <= minRing {
		return 0
	}
	return (n - minRing + blockLen - 1) / blockLen
}

// newFHarnessRB is newFHarness with every flow's inbox bounded by rb bytes
// of queued buffers (setReadBuffer, before Run).
func newFHarnessRB(t *testing.T, env *carrier.Env, lim Limits, c *fakeSock, maxDatagram, rb int) *fharness {
	h := &fharness{t: t, env: env, c: c}
	h.s = newSeamSource(env, c, c, maxDatagram, lim)
	h.s.setReadBuffer(rb)
	go h.s.Run(func(f *Flow) {
		h.mu.Lock()
		h.fs = append(h.fs, f)
		h.mu.Unlock()
	})
	return h
}

// queueSeq queues n PING datagrams of flow id from from, at fseq first,
// first+1, … (one read of the seam moves up to its depth).
func queueSeq(c *fakeSock, from netip.AddrPort, id uint64, first, n int) {
	ds := make([][]byte, n)
	for i := range ds {
		ds[i] = dg(id, pingFrame(uint32(first+i)))
	}
	c.queue(from, ds...)
}

// drainSeq reads n datagrams of f with ReadDatagrams (at most 32 result
// slots a call, never more than are left to read), which must be the PINGs
// at fseq first, first+1, … in order, and releases them.
func drainSeq(t *testing.T, f *Flow, first, n int) {
	t.Helper()
	rs := make([]carrier.ReadResult, 32)
	for got := 0; got < n; {
		if err := f.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		k, err := f.ReadDatagrams(rs[:min(len(rs), n-got)])
		if err != nil {
			t.Fatalf("after %d of %d datagrams: %v", got, n, err)
		}
		for _, r := range rs[:k] {
			if r.Ev != carrier.ReadOK || pingSeq(r.Data) != uint32(first+got) {
				t.Fatalf("datagram %d: event %d, fseq %d; want ReadOK at fseq %d", got, r.Ev, pingSeq(r.Data), first+got)
			}
			got++
		}
	}
	f.Release()
}

// readFirst reads f's H1 with one ReadDatagrams call of 32 result slots,
// which gives the flow its held-entry slice of 32 entries — charged to
// Stages for the flow's life (R3-28) — so that the later calls (drainSeq)
// move no stage charge but the inbox's own.
func readFirst(t *testing.T, f *Flow) {
	t.Helper()
	rs := make([]carrier.ReadResult, 32)
	if n, err := f.ReadDatagrams(rs); err != nil || n != 1 || rs[0].Ev != carrier.ReadOK {
		t.Fatalf("the H1: %d results, %v", n, err)
	}
	f.Release()
}

// heldSlice is the stage charge of a held-entry slice of 32 entries.
const heldSlice = 32 * entrySize

// idleInbox fails unless f's inbox is empty and back on its first block,
// with nothing counted against its bound and every entry of the first block
// cleared (cleanBlock).
func idleInbox(t *testing.T, f *Flow, what string) {
	t.Helper()
	f.mu.Lock()
	entries, pooled, queued := inboxStorageLocked(f)
	onBase, qb := f.head == f.base && f.tail == f.base && f.hi == 0 && f.ti == 0, f.qBytes
	dirty := -1
	if f.base != nil {
		dirty = cleanBlock(f.base)
	}
	f.mu.Unlock()
	if !onBase || entries != minRing || pooled != 0 || queued != 0 || qb != 0 {
		t.Fatalf("%s: inbox on its first block %v, %d entries in %d pooled blocks, %d queued, %d bytes counted; want the first block alone, empty",
			what, onBase, entries, pooled, queued, qb)
	}
	if dirty >= 0 {
		t.Fatalf("%s: the drained first block is not clear at %d of its %d entries (an entry still set, or at %d a stale link); want every dequeued entry cleared",
			what, dirty, minRing, minRing)
	}
}

// pooledBlocksLocked returns the pooled blocks linked into f's inbox, in
// order (f.mu held).
func pooledBlocksLocked(f *Flow) []*block {
	var bs []*block
	for b := f.head; b != nil; b = b.next {
		if b != f.base {
			bs = append(bs, b)
		}
	}
	return bs
}

// cleanBlock returns the index of b's first entry that still references a
// buffer, data, a source or a foreign address — or is marked reserve — and
// -1 when every entry is cleared and b links no further block (len(b.e):
// only a stale link).
func cleanBlock(b *block) int {
	for i := range b.e {
		if e := &b.e[i]; e.buf != nil || e.data != nil || e.src != (netip.AddrPort{}) || e.addr != nil || e.reserve {
			return i
		}
	}
	if b.next != nil {
		return len(b.e)
	}
	return -1
}

// pooledClean fails unless every block of bs — pooled blocks a flow linked
// and has drained, back in its Source's pool — is cleared (cleanBlock):
// the pool hands them to any flow of the Source, so a stale entry would pin
// a released buffer, which another flow may already reuse, and its address.
func pooledClean(t *testing.T, bs []*block, what string) {
	t.Helper()
	for i, b := range bs {
		if j := cleanBlock(b); j >= 0 {
			t.Fatalf("%s: drained pooled block %d of %d: entry %d (of %d) not cleared, or a stale link", what, i, len(bs), j, len(b.e))
		}
	}
}

// TestFlowInboxReadBufferBound_L58 (F-6; L58's drop rule at the new bound;
// L16): a flow of a socket whose read buffer is rb holds datagrams while
// the buffers it holds are below rb — here 601 datagrams of the read
// slots' class, rb = 600 slots + 1 byte, above M2's 512 (production
// Limits) — and tail-drops the rest of a burst of 700, counted in Stats
// and Env.Dgram (InboxDrops); the demux goes on. While they are queued,
// every held datagram is charged to the Budget (exactly 601 slots beyond
// the reader's extras) and the inbox's pooled blocks to Stages, once each
// (exactly pooledFor(601) blocks); its reader then gets all 601 in order,
// and the drained inbox is back on its first block with both accounts at
// their baselines (the storage shrinks) and every drained block cleared. A
// second burst meets the same bound (the count of held bytes is exact),
// and Close with a full inbox returns every charge once. Mutants: the bound
// back at 512 datagrams (512 queued); a held datagram uncharged (the
// Budget short by a slot per uncharged one); a block charged twice; blocks
// never returned (Stages above its baseline after the drain); the held
// bytes not counted down (bytes still counted after the drain); a dequeued
// entry not cleared (a drained block still references its datagram).
func TestFlowInboxReadBufferBound_L58(t *testing.T) {
	idlePeriod(t, time.Hour) // the reader keeps its extras: the charges below are exact
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		slot := slotBytes(env, seamDgram)
		const keep, sent = 601, 700
		rb := (keep-1)*slot + 1 // the 601st datagram still finds the held bytes below the bound
		c := newFakeSock(32)
		h := newFHarnessRB(t, env, Limits{}, c, seamDgram, int(rb))
		defer h.shutdown()
		if h.s.inboxBytes != rb || h.s.lim.Inbox >= keep {
			t.Fatalf("premise: the Source's byte bound %d, want the read buffer %d (above one read's %d), with Limits.Inbox %d below the %d it holds",
				h.s.inboxBytes, rb, srcMaxDepth*slot, h.s.lim.Inbox, keep)
		}
		from := apOf(2, 1000)
		c.queue(from, h1(1, wire.TypeOpen, 1))
		synctest.Wait()
		f := h.flows()[0]
		readFirst(t, f)
		f.Admitted()
		synctest.Wait()
		// The baseline: the reader's extras, parked (srcHold), and the flow's
		// held-entry slice.
		hb, hs := srcHold(env)
		b0, s0 := hb, hs+heldSlice
		if b, s := env.Budget.Used(), env.Stages.Used(); b != b0 || s != s0 {
			t.Fatalf("baseline: %s, want Budget %d and Stages %d (the reader's extras and the held slice)", heldBytes(env), b0, s0)
		}
		idleInbox(t, f, "after the H1")

		for round := range 2 {
			queueSeq(c, from, 1, 2, sent)
			synctest.Wait()
			st := h.s.Stats()
			f.mu.Lock()
			entries, pooled, queued := inboxStorageLocked(f)
			qb := f.qBytes
			linked := pooledBlocksLocked(f)
			f.mu.Unlock()
			drops := uint64((round + 1) * (sent - keep))
			if queued != keep || qb != keep*slot || st.InboxDrops != drops || env.Dgram.InboxDrops.Load() != drops {
				t.Fatalf("burst %d: %d queued (%d bytes counted), InboxDrops %d (Env %d); want %d queued (%d bytes) and %d drops",
					round, queued, qb, st.InboxDrops, env.Dgram.InboxDrops.Load(), keep, keep*slot, drops)
			}
			if b := env.Budget.Used(); b != b0+keep*slot {
				t.Fatalf("burst %d: Budget %d, want the extras %d + %d held datagrams × %d B = %d (every held datagram charged once)",
					round, b, b0, keep, slot, b0+keep*slot)
			}
			if s := env.Stages.Used(); pooled != pooledFor(keep) || entries < keep || s != s0+int64(pooled)*blockBytes {
				t.Fatalf("burst %d: %d entries in %d pooled blocks, Stages %d; want %d pooled blocks of %d B charged once beyond the baseline %d",
					round, entries, pooled, s, pooledFor(keep), blockBytes, s0)
			}
			drainSeq(t, f, 2, keep)
			idleInbox(t, f, "after the drain")
			pooledClean(t, linked, "after the drain")
			if b, s := env.Budget.Used(), env.Stages.Used(); b != b0 || s != s0 {
				t.Fatalf("burst %d drained: Budget %d, Stages %d; want the baselines %d and %d", round, b, s, b0, s0)
			}
		}

		queueSeq(c, from, 1, 2, sent)
		synctest.Wait()
		f.mu.Lock()
		linked := pooledBlocksLocked(f)
		f.mu.Unlock()
		if len(linked) != pooledFor(keep) {
			t.Fatalf("before Close: %d pooled blocks linked, want %d", len(linked), pooledFor(keep))
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		if b, s := env.Budget.Used(), env.Stages.Used(); b != hb || s != hs {
			t.Fatalf("Close with a full inbox: Budget %d, Stages %d; want the reader's extras %d and %d (every charge of the flow returned once)", b, s, hb, hs)
		}
		pooledClean(t, linked, "after Close")
	})
}

// TestFlowInboxFloorOneRead_L54 (M5-D14, §A4.5): whatever the read buffer
// (here 1 byte), a flow's inbox holds one read of the socket — 32
// datagrams of the read slots' class — so the datagrams one read routes to
// a flow whose reader has drained it always reach it before its one wake.
// M2's datagram floor (Limits.Inbox, 512) already holds one read; the byte
// floor keeps the rule under a Limits.Inbox below one read, as a test hook
// can set (here 8). A second read of 32 finds the inbox full and drops all
// of them. Mutant: the byte bound not raised to one read (8 datagrams
// queued, 24 dropped).
func TestFlowInboxFloorOneRead_L54(t *testing.T) {
	idlePeriod(t, time.Hour)
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		slot := slotBytes(env, seamDgram)
		c := newFakeSock(32)
		h := newFHarnessRB(t, env, Limits{Inbox: 8}, c, seamDgram, 1)
		defer h.shutdown()
		if want := int64(srcMaxDepth) * slot; h.s.inboxBytes != want {
			t.Fatalf("the byte bound for a 1-byte read buffer: %d, want one read, %d", h.s.inboxBytes, want)
		}
		from := apOf(2, 1000)
		c.queue(from, h1(1, wire.TypeOpen, 1))
		synctest.Wait()
		f := h.flows()[0]
		readOne(t, f, time.Second)
		f.Admitted()

		queueSeq(c, from, 1, 2, srcMaxDepth)
		synctest.Wait()
		if _, g := c.reads(); g[len(g)-1] != srcMaxDepth {
			t.Fatalf("stimulus: the read moved %d datagrams, want %d in one", g[len(g)-1], srcMaxDepth)
		}
		if st := h.s.Stats(); st.InboxDrops != 0 {
			t.Fatalf("one read of %d datagrams to a drained flow: InboxDrops %d, want 0", srcMaxDepth, st.InboxDrops)
		}
		queueSeq(c, from, 1, 2+srcMaxDepth, srcMaxDepth)
		synctest.Wait()
		if st := h.s.Stats(); st.InboxDrops != srcMaxDepth {
			t.Fatalf("a second read into the full inbox: InboxDrops %d, want %d", st.InboxDrops, srcMaxDepth)
		}
		drainSeq(t, f, 2, srcMaxDepth)
		idleInbox(t, f, "after the drain")
	})
}

// TestFlowInboxNeverBelowM2Bound_L58 (F-6: the read buffer only ever
// raises the bound; M2-D59; L58): every queued datagram counts its read
// slot's class whatever its length, so where the class is large the byte
// bound alone would hold fewer than M2's 512 datagrams — at the 4-MiB
// default 509 at a MaxDatagram of 4,200 (class 8,256 B), 256 at 9,000
// (16,448 B) and 64 at 65,507 (65,600 B), and at A6.3's 16 MiB still 256
// at 65,507 — where every flow of a udp.Listen socket held 512 before
// inboxtime. A lagging flow there still takes 512 of a burst of 600, each
// charged at its slot's class, and drops the other 88 (L58); its reader
// gets all 512 in order and the drained inbox holds nothing. Mutant: the
// datagram floor dropped on rendr's own socket (509, 256, 64 and 256
// queued).
func TestFlowInboxNeverBelowM2Bound_L58(t *testing.T) {
	idlePeriod(t, time.Hour)
	for _, r := range []struct{ maxDatagram, rb int }{
		{4200, 4 << 20}, {9000, 4 << 20}, {65507, 4 << 20}, {65507, 16 << 20},
	} {
		t.Run(fmt.Sprintf("MaxDatagram%d-rb%dMiB", r.maxDatagram, r.rb>>20), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				const sent = 600
				env := testEnv(1 << 30)
				slot := slotBytes(env, r.maxDatagram)
				if byBytes := (int64(r.rb) + slot - 1) / slot; byBytes >= DefaultInbox {
					t.Fatalf("premise: the byte bound holds %d datagrams of class %d, want fewer than %d", byBytes, slot, DefaultInbox)
				}
				c := newFakeSock(32)
				h := newFHarnessRB(t, env, Limits{}, c, r.maxDatagram, r.rb)
				defer h.shutdown()
				from := apOf(2, 1000)
				c.queue(from, h1(1, wire.TypeOpen, 1))
				synctest.Wait()
				f := h.flows()[0]
				readOne(t, f, time.Second)
				f.Admitted()
				synctest.Wait()
				b0 := env.Budget.Used() // the reader's extras
				queueSeq(c, from, 1, 2, sent)
				synctest.Wait()
				f.mu.Lock()
				queued := f.n
				f.mu.Unlock()
				drops := uint64(sent - DefaultInbox)
				if st := h.s.Stats(); queued != DefaultInbox || st.InboxDrops != drops || env.Dgram.InboxDrops.Load() != drops {
					t.Fatalf("a lagging flow, slot class %d B, read buffer %d: %d of %d queued, InboxDrops %d (Env %d); want %d queued (M2's bound) and %d drops",
						slot, r.rb, queued, sent, st.InboxDrops, env.Dgram.InboxDrops.Load(), DefaultInbox, drops)
				}
				if b := env.Budget.Used(); b != b0+DefaultInbox*slot {
					t.Fatalf("Budget %d, want the extras %d + %d queued × %d B", b, b0, DefaultInbox, slot)
				}
				drainSeq(t, f, 2, DefaultInbox)
				idleInbox(t, f, "after the drain")
				if b := env.Budget.Used(); b != b0 {
					t.Fatalf("drained: Budget %d, want the extras %d", b, b0)
				}
			})
		})
	}
}

// TestFlowInboxBoundPerFlow_L58 (F-6: "a flow never drops while the bytes
// it holds are below" the read buffer — each flow's own bytes): two
// lagging flows of one Source whose read buffer holds 601 datagrams (600
// slots + 1 byte, above M2's 512) each take 601 of a burst of 700 and drop
// 99, wherever the other flow's inbox stands; their readers then get every
// queued datagram in order. Mutant: the byte bound applied to the Source's
// total (the second flow gets only its 512-datagram floor).
func TestFlowInboxBoundPerFlow_L58(t *testing.T) {
	idlePeriod(t, time.Hour)
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		slot := slotBytes(env, seamDgram)
		const keep, sent = 601, 700
		c := newFakeSock(32)
		h := newFHarnessRB(t, env, Limits{}, c, seamDgram, int((keep-1)*slot+1))
		defer h.shutdown()
		a, b := apOf(2, 1000), apOf(3, 1000)
		c.queue(a, h1(1, wire.TypeOpen, 1))
		c.queue(b, h1(2, wire.TypeOpen, 1))
		synctest.Wait()
		fs := h.flows()
		if len(fs) != 2 {
			t.Fatalf("%d flows admitted, want 2", len(fs))
		}
		for _, f := range fs {
			readOne(t, f, time.Second)
			f.Admitted()
		}
		synctest.Wait()
		b0 := env.Budget.Used()
		queueSeq(c, a, 1, 2, sent) // the first flow fills first: one read moves 32 of one source
		queueSeq(c, b, 2, 2, sent)
		synctest.Wait()
		for _, f := range fs {
			f.mu.Lock()
			queued, qb := f.n, f.qBytes
			f.mu.Unlock()
			if queued != keep || qb != keep*slot {
				t.Errorf("flow %d: %d queued (%d bytes counted), want %d (%d bytes): the bound is each flow's own", f.ID(), queued, qb, keep, keep*slot)
			}
		}
		if st := h.s.Stats(); st.InboxDrops != 2*(sent-keep) {
			t.Fatalf("InboxDrops %d, want %d (%d of each flow's burst)", st.InboxDrops, 2*(sent-keep), sent-keep)
		}
		if u := env.Budget.Used(); u != b0+2*keep*slot {
			t.Fatalf("Budget %d, want the extras %d + 2 × %d queued × %d B", u, b0, keep, slot)
		}
		for _, f := range fs {
			drainSeq(t, f, 2, keep)
			idleInbox(t, f, fmt.Sprintf("flow %d after the drain", f.ID()))
		}
	})
}

// TestFlowInboxBudgetBoundsTotal_L16 (F-6: every queued datagram stays
// charged as before, so MaxBufferedBytes bounds the inboxes together):
// with a read buffer far above it (16 MiB), a flow's inbox stops at the
// Budget — 40 datagram slots — and the DGRAMs beyond it are inbox drops
// (no control reserve for a DGRAM, L16); the Budget is then exactly full,
// never above. Drained, the inbox takes 40 again. One datagram per read
// (MaxBatch 1): no extra slots share the Budget. Mutant: a datagram queued
// without its charge (all 100 queued, the Budget empty).
func TestFlowInboxBudgetBoundsTotal_L16(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const room, sent = 40, 100
		probe := testEnv(1)
		slot := slotBytes(probe, seamDgram)
		env := testEnv(room * slot)
		c := newFakeSock(1)
		h := newFHarnessRB(t, env, Limits{}, c, seamDgram, 16<<20)
		defer h.shutdown()
		from := apOf(2, 1000)
		c.queue(from, h1(1, wire.TypeOpen, 1))
		synctest.Wait()
		f := h.flows()[0]
		readOne(t, f, time.Second)
		f.Admitted()
		if b := env.Budget.Used(); b != 0 {
			t.Fatalf("baseline: Budget %d, want 0 (one datagram per read: no extra slots)", b)
		}
		for round := range 2 {
			for i := range sent {
				c.queue(from, dg(1, dgramFrame(uint32(2+i), 900)))
			}
			synctest.Wait()
			f.mu.Lock()
			queued := f.n
			f.mu.Unlock()
			drops := uint64((round + 1) * (sent - room))
			if st := h.s.Stats(); queued != room || st.InboxDrops != drops {
				t.Fatalf("round %d: %d queued, InboxDrops %d; want %d queued (the Budget's room) and %d drops", round, queued, st.InboxDrops, room, drops)
			}
			if b := env.Budget.Used(); b != env.Budget.Max() {
				t.Fatalf("round %d: Budget %d of %d; want it exactly full (every queued datagram charged)", round, b, env.Budget.Max())
			}
			rs := make([]carrier.ReadResult, 8)
			for got := 0; got < room; {
				n, err := f.ReadDatagrams(rs)
				if err != nil {
					t.Fatalf("round %d: after %d datagrams: %v", round, got, err)
				}
				got += n
			}
			f.Release()
			if b := env.Budget.Used(); b != 0 {
				t.Fatalf("round %d drained: Budget %d, want 0", round, b)
			}
		}
	})
}

// TestFlowInboxOrderAcrossBlocks (L39, L58): pushes and pops that
// interleave across the inbox's blocks keep arrival order — 100 queued
// (the first block and two pooled ones), 50 read (the first block drained
// and dropped from the list, the next one half read), 100 more queued (the
// last block filled, a third pooled one), then all 150 read — and the
// drained inbox is back on its first block with Stages at its baseline.
func TestFlowInboxOrderAcrossBlocks(t *testing.T) {
	idlePeriod(t, time.Hour)
	synctest.Test(t, func(t *testing.T) {
		env := testEnv(1 << 30)
		c := newFakeSock(32)
		h := newFHarnessRB(t, env, Limits{}, c, seamDgram, 16<<20)
		defer h.shutdown()
		from := apOf(2, 1000)
		c.queue(from, h1(1, wire.TypeOpen, 1))
		synctest.Wait()
		f := h.flows()[0]
		readFirst(t, f) // the held slice now, so that Stages moves with the blocks alone
		f.Admitted()
		synctest.Wait()
		s0 := env.Stages.Used()

		queueSeq(c, from, 1, 2, 100)
		synctest.Wait()
		drainSeq(t, f, 2, 50)
		f.mu.Lock()
		_, pooled, queued := inboxStorageLocked(f)
		baseOut := f.head != f.base
		f.mu.Unlock()
		if queued != 50 || pooled != 2 || !baseOut {
			t.Fatalf("after 100 queued and 50 read: %d queued in %d pooled blocks, first block dropped from the list %v; want 50 in 2, true", queued, pooled, baseOut)
		}
		queueSeq(c, from, 1, 102, 100)
		synctest.Wait()
		f.mu.Lock()
		_, pooled, queued = inboxStorageLocked(f)
		f.mu.Unlock()
		if queued != 150 || pooled != 3 || env.Stages.Used() != s0+3*blockBytes {
			t.Fatalf("after 100 more: %d queued in %d pooled blocks, Stages %d; want 150 in 3, %d", queued, pooled, env.Stages.Used(), s0+3*blockBytes)
		}
		drainSeq(t, f, 52, 150)
		idleInbox(t, f, "after the last read")
		if s := env.Stages.Used(); s != s0 {
			t.Fatalf("drained: Stages %d, want the baseline %d", s, s0)
		}
		if st := h.s.Stats(); st.InboxDrops != 0 {
			t.Fatalf("Stats %+v, want no inbox drop", st)
		}
	})
}

// TestSourceAdoptsTokenReadBuffer (F-6; the options plumbing): NewSource
// over rendr's own listening socket bounds its flows' inboxes by the read
// buffer the token records (carrier/udp's Listen: NewOwnedUDPListenSocket),
// raised to one read (32 slots of the socket's MaxDatagram class); a token
// that records none, or a negative size, keeps the datagram bound
// (Limits.Inbox), as an embedder's conn does (M2-D59). Mutant: NewSource
// ignoring the token's read buffer.
func TestSourceAdoptsTokenReadBuffer(t *testing.T) {
	env := testEnv(1 << 30)
	slot := slotBytes(env, 1232)
	rows := []struct {
		name string
		rb   int
		tok  bool // NewOwnedUDPListenSocket; else NewOwnedUDPSocketBatch (none recorded)
		want int64
	}{
		{"16 MiB", 16 << 20, true, 16 << 20},
		{"below one read", 1000, true, srcMaxDepth * slot},
		{"negative", -1, true, 0},
		{"none recorded", 0, false, 0},
	}
	for _, r := range rows {
		u, err := net.ListenUDP("udp4", loopback4())
		if err != nil {
			t.Fatal(err)
		}
		own := carrier.NewOwnedUDPSocketBatch(u, 1232, 0)
		if r.tok {
			own = carrier.NewOwnedUDPListenSocket(u, 1232, 0, r.rb)
		}
		s := NewSource(env, own, Limits{})
		if s.inboxBytes != r.want || s.lim.Inbox != DefaultInbox {
			t.Errorf("%s: byte bound %d, Inbox %d; want %d and %d", r.name, s.inboxBytes, s.lim.Inbox, r.want, DefaultInbox)
		}
		own.Close() // the Source never ran: the socket is the test's to close
	}
	if s := NewSource(env, newFakeConn(), Limits{}); s.inboxBytes != 0 || s.lim.Inbox != DefaultInbox {
		t.Errorf("an embedder's conn: byte bound %d, Inbox %d; want 0 and %d (M2-D59)", s.inboxBytes, s.lim.Inbox, DefaultInbox)
	}
}
