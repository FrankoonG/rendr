package carrier

import (
	"bytes"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// WP8 tests of the MUX writer: payload quotas, the control pass, deficit
// round robin, the ready handshake, capacity and REL wakes, allocation and
// cost (M3 design §A5.3; M3-D10, M3-D11; R1-1).

// openLive opens views on a dialer side against a raw passive peer that
// answers OK, attaches them and waits until their go frames are out.
func openLive(t *testing.T, s *muxSide, p *wirePeer, hs ...uint32) {
	t.Helper()
	for _, h := range hs {
		v, wait := s.openRaw(t, wire.TypeOpen, byte(h))
		synctest.Wait()
		_ = p.send(wire.TypeOpenAck, 0, h, okAck(wire.TypeOpenAck))
		if _, err := wait(); err != nil {
			t.Fatalf("view %d: %v", h, err)
		}
		s.attach(v)
		synctest.Wait()
	}
}

// writeShares returns, per Write of a tapped side, the DATA payload bytes
// of each handle.
func writeShares(log []tapRec) []map[uint32]int {
	var out []map[uint32]int
	for _, r := range log {
		for len(out) < r.write {
			out = append(out, map[uint32]int{})
		}
		if r.h.Type == wire.TypeData {
			out[r.write-1][r.h.Handle] += int(r.h.Len) - wire.DataPrefixLen
		}
	}
	return out
}

// checkShares checks the byte shares of handles hs over every window of 16
// consecutive writes among the first n in which all of them were
// backlogged: each pair within [0.8, 1.25].
func checkShares(t *testing.T, shares []map[uint32]int, from, n int, hs ...uint32) {
	t.Helper()
	if len(shares) < from+n {
		t.Fatalf("%d writes, want at least %d", len(shares), from+n)
	}
	for w := from; w+16 <= from+n; w++ {
		sum := map[uint32]int{}
		for _, m := range shares[w : w+16] {
			for _, h := range hs {
				sum[h] += m[h]
			}
		}
		for _, a := range hs {
			for _, b := range hs {
				if a == b {
					continue
				}
				r := float64(sum[a]) / float64(max(sum[b], 1))
				if r < 0.8 || r > 1.25 {
					t.Fatalf("writes %d…%d: handle %d sent %d bytes, handle %d %d (ratio %.2f, want within [0.8, 1.25])", w, w+15, a, sum[a], b, sum[b], r)
				}
			}
		}
	}
}

// TestMuxDRRFairness (M3-D10): backlogged views of one trunk get byte
// shares within [0.8, 1.25] over any 16 writer rounds: two views; three
// views on a batch of two quanta (each round leads with the least recently
// served view, so the third is served next); and a view whose deficit
// grows while it trickles (the deficit cap bounds its quota).
func TestMuxDRRFairness(t *testing.T) {
	t.Run("two views", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, p := muxRawDialer(t, nil)
			openLive(t, s, p, 2, 3)
			n0 := s.tap.nwrites()
			for _, h := range []uint32{2, 3} {
				s.view(h).src.offer(16 << 20)
			}
			s.view(2).c.Wake()
			s.view(3).c.Wake()
			synctest.Wait()
			shares := writeShares(s.tap.log())
			checkShares(t, shares, n0+1, 48, 2, 3)
			// Each round serves both: a payload quota per call, not a
			// whole batch per view.
			for w := n0 + 1; w < n0+48; w++ {
				if shares[w][2] == 0 || shares[w][3] == 0 {
					t.Fatalf("write %d carried %d bytes of view 2 and %d of view 3: a round served one view only", w, shares[w][2], shares[w][3])
				}
			}
		})
	})
	t.Run("three views, rotation", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, p := muxRawDialer(t, func(env *Env) { env.Timing.BatchBudget = 2 * defMuxQuantum })
			openLive(t, s, p, 2, 3, 4)
			n0 := s.tap.nwrites()
			for _, h := range []uint32{2, 3, 4} {
				s.view(h).src.offer(16 << 20)
				s.view(h).c.Wake()
			}
			synctest.Wait()
			checkShares(t, writeShares(s.tap.log()), n0+1, 48, 2, 3, 4)
		})
	})
	t.Run("deficit cap", func(t *testing.T) {
		// A view whose producer writes 1 KiB and wakes it during each of
		// its calls ends every turn with most of its quantum unused, and the
		// wake takes it out of the round (the ring carries it to the next),
		// so it carries a deficit from round to round on a batch with room
		// to spare; the deficit never grows beyond two quanta, so no call of
		// the view gets a quota above 2·Quantum (M3-D10).
		const q = defMuxQuantum
		env := hEnv()
		chunk := env.Bufs.Get(ChunkSize, nil)
		a := &drrEP{chunk: chunk, avail: 1 << 10, wake: true}
		b := &drrEP{chunk: chunk, avail: 1 << 40}
		c, views := bareMuxTrunk(env, &nopConn{}, 3, nil)
		views[0].ep = &drrEP{chunk: chunk}
		views[1].ep, views[2].ep = a, b
		built := 0
		for i := 0; i < 24; i++ {
			bt := NewBatch(8 * q)
			bt.Reset(time.Now())
			a.avail = 1 << 10
			views[1].Wake()
			views[2].Wake()
			c.fillRound(bt)
			bt.Reset(time.Time{})
			built = max(built, views[1].deficit)
		}
		if built <= q/2 {
			t.Fatalf("view 2 carried a deficit of at most %d, want one built up (> Quantum/2)", built)
		}
		if a.maxRoom > 2*q || built > 2*q {
			t.Fatalf("a call got a quota of %d bytes (deficit up to %d), want at most 2·Quantum = %d", a.maxRoom, built, 2*q)
		}
	})
}

// drrEP places min(avail, Room) DATA bytes per payload call in 16 KiB
// frames and records the largest Room a payload call saw (its quota).
type drrEP struct {
	hEP
	chunk   *Buf
	avail   int
	maxRoom int
	wake    bool // a producer wakes the view during each payload call
}

func (e *drrEP) Fill(c *Conn, b *Batch) {
	if b.ControlOnly() {
		return
	}
	if e.wake {
		c.Wake()
	}
	e.maxRoom = max(e.maxRoom, b.Room())
	for e.avail > 0 {
		n := min(16<<10, e.avail, b.Room())
		if n <= 0 || !b.AddData(c.Handle(), 0, e.chunk.B[:n], e.chunk, false) {
			return
		}
		e.avail -= n
	}
}

// TestMuxControlPassFirst_L16 (M3-D10, L16): a view's control frames are
// placed before any view's DATA in the round: while view 2 is backlogged,
// view 3 gets an ACK queued every round; in every write that carries it,
// the ACK comes before the first DATA frame.
func TestMuxControlPassFirst_L16(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p := muxRawDialer(t, nil)
		openLive(t, s, p, 2, 3)
		a, b := s.view(2), s.view(3)
		var rounds atomic.Int32
		a.src.hook = func(c *Conn, bt *Batch) {
			if bt.ControlOnly() || rounds.Load() >= 24 {
				return
			}
			b.src.mu.Lock()
			if len(b.src.ctl) == 0 {
				b.src.ctl = append(b.src.ctl, hFrame{t: wire.TypeAck, payload: ackPayload()})
				rounds.Add(1)
			}
			b.src.mu.Unlock()
			b.c.Wake() // a producer of view 3 (the writer holds no carrier lock during a Fill)
		}
		n0 := s.tap.nwrites()
		a.src.offer(32 << 20)
		a.c.Wake()
		synctest.Wait()
		checked := 0
		var cur []tapRec
		flush := func() {
			ack, data := -1, -1
			for i, r := range cur {
				if r.h.Type == wire.TypeAck && r.h.Handle == 3 && ack < 0 {
					ack = i
				}
				if r.h.Type == wire.TypeData && data < 0 {
					data = i
				}
			}
			if ack >= 0 && data >= 0 {
				checked++
				if ack > data {
					t.Fatalf("a write carries view 2's DATA (frame %d) before view 3's ACK (frame %d)", data, ack)
				}
			}
			cur = cur[:0]
		}
		w := 0
		for _, r := range s.tap.log() {
			if r.write <= n0 {
				continue
			}
			if r.write != w {
				flush()
				w = r.write
			}
			cur = append(cur, r)
		}
		flush()
		if checked < 16 {
			t.Fatalf("only %d writes carried both an ACK of view 3 and DATA", checked)
		}
	})
}

// TestMuxQuotaRoom (M3-D10, M3-D11, R1-1 rule 5): Room, DgramRoom and
// Taken under a payload quota; quota 0 places control frames only and
// marks nothing cap-blocked; on a datagram batch DgramRoom keeps the
// budget while AddDgram enforces the quota.
func TestMuxQuotaRoom(t *testing.T) {
	chunk := make([]byte, ChunkSize)
	b := NewBatch(256 << 10)
	b.Reset(time.Now())
	b.limit(10 << 10)
	if b.Room() != 10<<10 || b.Taken() != 0 || b.ControlOnly() {
		t.Fatalf("quota 10 KiB: Room %d Taken %d ControlOnly %v", b.Room(), b.Taken(), b.ControlOnly())
	}
	if !b.AddData(2, 0, chunk[:6<<10], nil, false) || b.AddData(2, 6<<10, chunk[:5<<10], nil, false) {
		t.Fatal("AddData ignored the quota")
	}
	if b.Room() != 4<<10 {
		t.Fatalf("Room %d after 6 KiB of a 10 KiB quota, want 4 KiB", b.Room())
	}
	b.limit(64 << 10) // the next endpoint call
	if b.Taken() != 6<<10 || b.Room() != 64<<10 {
		t.Fatalf("next call: Taken %d Room %d, want 6 KiB and 64 KiB", b.Taken(), b.Room())
	}
	b.limit(0)
	if !b.ControlOnly() || b.Room() != 0 || b.DgramRoom() != 0 {
		t.Fatalf("quota 0: ControlOnly %v Room %d DgramRoom %d", b.ControlOnly(), b.Room(), b.DgramRoom())
	}
	if b.AddData(3, 0, chunk[:1], nil, false) || b.AddDgram(3, 0, nil, nil) || b.AddDgram(3, 0, chunk[:1], nil) {
		t.Fatal("quota 0 placed payload")
	}
	b.MarkCapBlocked()
	if b.CapBlocked() {
		t.Fatal("a quota-0 call marked the batch cap-blocked")
	}
	if !b.AddAck(3, 0, &wire.Ack{}) || !b.AddFin(3, 9) {
		t.Fatal("quota 0 refused a control frame")
	}
	b.limit(-1)
	if b.ControlOnly() || b.Room() != 256<<10-6<<10 {
		t.Fatalf("no quota: ControlOnly %v Room %d", b.ControlOnly(), b.Room())
	}
	b.MarkCapBlocked()
	if !b.CapBlocked() {
		t.Fatal("MarkCapBlocked without a quota did nothing")
	}

	d := NewBatch(256 << 10)
	d.Reset(time.Now())
	d.SetDatagram(1200, wire.RelWindow)
	d.limit(2000)
	if d.DgramRoom() != 1200-wire.DgramOverhead {
		t.Fatalf("datagram DgramRoom %d under a quota, want the budget's %d", d.DgramRoom(), 1200-wire.DgramOverhead)
	}
	if !d.AddDgram(2, 1, chunk[:1000], nil) || d.AddDgram(2, 2, chunk[:1001], nil) || !d.AddDgram(2, 2, chunk[:1000], nil) {
		t.Fatal("datagram quota: want 1000 accepted, 1001 refused, 1000 accepted (2000 in all)")
	}
	if d.AddDgram(2, 3, chunk[:1], nil) {
		t.Fatal("datagram quota exceeded")
	}
	d.limit(-1)
	if d.Taken() != 2000 {
		t.Fatalf("datagram Taken %d, want 2000", d.Taken())
	}
}

// TestMuxCapWake (§A4.3): a PONG that frees capacity re-readies the views
// that were cap-blocked in their last Fill, and only those.
func TestMuxCapWake(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p := muxRawDialer(t, nil)
		openLive(t, s, p, 2, 3)
		a, b := s.view(2), s.view(3)
		a.src.capAware = true
		a.src.offer(8 << 20)
		a.c.Wake()
		synctest.Wait()
		if !a.c.capMarked {
			t.Fatal("view 2 not cap-marked at its capacity")
		}
		fa, fb := a.src.fills.Load(), b.src.fills.Load()
		sent := a.src.placed.Load()
		var pg wire.Ping
		found := false
		for _, f := range p.received() {
			if f.Type == wire.TypePing {
				pg, _ = wire.ParsePing(f.Payload)
				found = true
			}
		}
		if !found {
			t.Fatal("no PING to answer")
		}
		time.Sleep(time.Millisecond)
		_ = p.pong(pg)
		synctest.Wait()
		if a.src.fills.Load() == fa || a.src.placed.Load() == sent {
			t.Fatalf("the PONG did not re-ready the cap-blocked view (fills %d → %d, placed %d → %d)", fa, a.src.fills.Load(), sent, a.src.placed.Load())
		}
		if b.src.fills.Load() != fb {
			t.Fatalf("the PONG re-readied view 3, which was not cap-blocked (fills %d → %d)", fb, b.src.fills.Load())
		}
	})
}

// TestMuxWakeDuringFillNotLost (R1-1): a producer that writes and wakes a
// view between its DRR call's return and the writer's ready-set decision
// (the AfterViewFill hook) is served in the next round, 1000 times — no
// write waits for an ACK, a PONG or a timer. The second row wakes the view
// from inside its own Fill, which places nothing (a producer racing the
// call): the ready flag is cleared before the call, so the Wake re-readies
// it and the bytes leave in the next round, 1000 times.
func TestMuxWakeDuringFillNotLost(t *testing.T) {
	t.Run("after the call", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var arm atomic.Bool
			var v2 atomic.Pointer[mView]
			s, p := muxRawDialer(t, func(env *Env) {
				env.Hooks = &testhooks.Hooks{AfterViewFill: func(_, h uint32) {
					if mv := v2.Load(); h == 2 && mv != nil && arm.CompareAndSwap(true, false) {
						mv.src.offer(100)
						mv.c.Wake()
					}
				}}
			})
			openLive(t, s, p, 2, 3)
			mv := s.view(2)
			v2.Store(mv)
			start := time.Now()
			for i := 0; i < 1000; i++ {
				arm.Store(true)
				mv.c.Wake() // a DRR call with nothing to place; the hook writes then
				synctest.Wait()
				if arm.Load() {
					t.Fatalf("iteration %d: view 2 got no DRR call", i)
				}
				if n := mv.src.pending(); n != 0 {
					t.Fatalf("iteration %d: %d bytes left waiting (a lost wakeup)", i, n)
				}
			}
			if el := time.Since(start); el != 0 {
				t.Fatalf("the writes waited %v of virtual time", el)
			}
			if got := mv.src.placed.Load(); got != 100*1000 {
				t.Fatalf("placed %d bytes, want %d", got, 100*1000)
			}
		})
	})
	t.Run("during the call", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, p := muxRawDialer(t, nil)
			v, wait := s.openRaw(t, wire.TypeOpen, 2)
			synctest.Wait()
			_ = p.send(wire.TypeOpenAck, 0, 2, okAck(wire.TypeOpenAck))
			if _, err := wait(); err != nil {
				t.Fatal(err)
			}
			src := newVSource(s.env)
			var arm atomic.Bool
			ep := &dEP{}
			ep.fill = func(c *Conn, b *Batch) {
				if !b.ControlOnly() && arm.CompareAndSwap(true, false) {
					src.offer(100) // the producer writes and wakes during the call,
					c.Wake()       // after the call's own look found nothing
					return
				}
				src.fill(c, b)
			}
			v.Start(ep, &hBell{}, StartOptions{})
			synctest.Wait()
			openLive(t, s, p, 3)
			start := time.Now()
			for i := 0; i < 1000; i++ {
				arm.Store(true)
				v.Wake()
				synctest.Wait()
				if arm.Load() {
					t.Fatalf("iteration %d: view 2 got no DRR call", i)
				}
				if n := src.pending(); n != 0 {
					t.Fatalf("iteration %d: %d bytes left waiting (a lost wakeup)", i, n)
				}
			}
			if el := time.Since(start); el != 0 {
				t.Fatalf("the writes waited %v of virtual time", el)
			}
			if got := src.placed.Load(); got != 100*1000 {
				t.Fatalf("placed %d bytes, want %d", got, 100*1000)
			}
		})
	})
}

// TestMuxViewWakeAt (§A4.3 row "Batch.WakeAt(t) from a view → that view at
// t"): a view's Fill asks for a call 5 ms later (a delayed ACK) and places
// nothing; with no other wake, the writer calls it again exactly at the due
// time, where it places its ACK; no call of it comes in between, and the
// other view is not called.
func TestMuxViewWakeAt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const delay = 5 * time.Millisecond
		s, p := muxRawDialer(t, nil)
		v, wait := s.openRaw(t, wire.TypeOpen, 2)
		synctest.Wait()
		_ = p.send(wire.TypeOpenAck, 0, 2, okAck(wire.TypeOpenAck))
		if _, err := wait(); err != nil {
			t.Fatal(err)
		}
		var phase atomic.Int32 // 0 idle, 1 armed, 2 waiting for the due call, 3 ACK placed
		var dueNs, ackNs atomic.Int64
		var early atomic.Int32
		ep := &dEP{}
		ep.fill = func(c *Conn, b *Batch) {
			if c.NeedGo() {
				b.AddAck(c.Handle(), 0, &wire.Ack{Window: 1 << 20}) // the go frame
				return
			}
			switch phase.Load() {
			case 1:
				due := b.Now().Add(delay)
				dueNs.Store(due.UnixNano())
				b.WakeAt(due) // once, as the session's delayed ACK does
				phase.Store(2)
			case 2:
				if now := b.Now().UnixNano(); now < dueNs.Load() {
					if now > dueNs.Load()-int64(delay) {
						early.Add(1) // a later round's call before the due time
					}
					return
				}
				if b.AddAck(c.Handle(), 0, &wire.Ack{Window: 1 << 20}) {
					ackNs.Store(b.Now().UnixNano())
					phase.Store(3)
				}
			}
		}
		v.Start(ep, &hBell{}, StartOptions{})
		synctest.Wait()
		openLive(t, s, p, 3)
		v3 := s.view(3)
		f3 := v3.src.fills.Load()
		acks := p.count(wire.TypeAck)
		phase.Store(1)
		v.Wake()
		synctest.Wait()
		if phase.Load() != 2 {
			t.Fatalf("phase %d after the wake, want 2 (WakeAt requested)", phase.Load())
		}
		time.Sleep(2 * delay)
		synctest.Wait()
		if phase.Load() != 3 {
			t.Fatal("the view was not called at its WakeAt: its delayed ACK waits for an unrelated wake")
		}
		if got := ackNs.Load(); got != dueNs.Load() {
			t.Fatalf("the ACK was placed %v after the due time, want exactly at it", time.Duration(got-dueNs.Load()))
		}
		if n := early.Load(); n != 0 {
			t.Fatalf("%d calls of the view between its request and its due time", n)
		}
		if n := v3.src.fills.Load(); n != f3 {
			t.Fatalf("view 3 was called %d times by view 2's WakeAt", n-f3)
		}
		if p.count(wire.TypeAck) != acks+1 {
			t.Fatalf("%d ACKs reached the peer, want 1", p.count(wire.TypeAck)-acks)
		}
	})
}

// TestMuxRelFairness_L12 (§A5.10, L12): on a datagram trunk 16 views share
// one REL window of 8; each places one reliable frame (FIN) at once and
// all of them are dispatched within ⌈16/8⌉ RTTs + RTO.
func TestMuxRelFairness_L12(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d, p, ia, ib := dgMuxPair(t, 1200, nil)
		const delay = 10 * time.Millisecond
		ia.setDelay(delay)
		ib.setDelay(delay)
		var hs []uint32
		for i := 0; i < 16; i++ {
			h := uint32(2 + i)
			d.open(t, wire.TypeOpen, byte(h))
			hs = append(hs, h)
		}
		time.Sleep(time.Second) // RTT samples
		synctest.Wait()
		d.c.mu.Lock()
		rto := d.c.relRTOLocked()
		d.c.mu.Unlock()
		start := time.Now()
		for _, h := range hs {
			mv := d.view(h)
			mv.src.addCtl(hFrame{t: wire.TypeFin, payload: finInner(0)})
			mv.c.Wake()
		}
		for {
			all := true
			for _, h := range hs {
				got := false
				for _, c := range p.view(h).ep.controls() {
					got = got || c.Type == wire.TypeFin
				}
				all = all && got
			}
			if all {
				break
			}
			if time.Since(start) > 10*time.Second {
				t.Fatal("not every FIN arrived")
			}
			time.Sleep(time.Millisecond)
		}
		bound := 2*(2*delay) + rto + 2*time.Millisecond
		if el := time.Since(start); el > bound {
			t.Fatalf("16 views' FINs took %v, want ≤ ⌈16/8⌉·RTT + RTO = %v", el, bound)
		}
	})
}

// bareMuxTrunk returns a started-ready dialer MUX trunk without goroutines
// and n views (handle 1 … n) attached with endpoint ep, for the writer and
// reader allocation and cost tests.
func bareMuxTrunk(env *Env, nc net.Conn, n int, ep Endpoint) (*Conn, []*Conn) {
	c := newConn(env, nc, 7, mPassiveInst, 0, "f0", true)
	c.mux = true
	c.ep = ep
	c.startMux()
	views := []*Conn{c}
	c.mx.Lock()
	for h := uint32(2); h <= uint32(n); h++ {
		v := c.newViewLocked(h, viewLive)
		v.ep, v.vx.attached, v.vx.dialer = ep, true, true
		v.vx.fillOK.Store(true)
		views = append(views, v)
	}
	c.mx.Unlock()
	return c, views
}

// ackDataEP places one ACK and up to one 1 KiB DATA frame per Fill.
type ackDataEP struct {
	hEP
	chunk *Buf
}

func (e *ackDataEP) Fill(c *Conn, b *Batch) {
	b.AddAck(c.Handle(), 0, &wire.Ack{})
	if b.Room() >= 1024 {
		b.AddData(c.Handle(), 0, e.chunk.B[:1024], e.chunk, false)
	}
}

func (e *ackDataEP) Data(c *Conn, off uint64, p []byte, buf *Buf) error {
	buf.Release()
	return nil
}

func (e *ackDataEP) Control(c *Conn, h wire.Header, p []byte) error { return nil }

// TestMuxWriterZeroAllocs (§A5.3, §A11.4): a steady MUX writer round over 8
// ready views — the ready ring, the control pass, DRR, per-view
// accounting — allocates nothing.
func TestMuxWriterZeroAllocs(t *testing.T) {
	env := hEnv()
	ep := &ackDataEP{chunk: env.Bufs.Get(ChunkSize, nil)}
	c, views := bareMuxTrunk(env, &nopConn{}, 8, ep)
	b := NewBatch(256 << 10)
	round := func() {
		b.Reset(time.Now())
		for _, v := range views {
			v.Wake()
		}
		c.fillRound(b)
		if b.Len() < 16 {
			t.Fatalf("round placed %d frames", b.Len())
		}
	}
	round()
	if n := testing.AllocsPerRun(200, round); n != 0 && !carrierRace {
		t.Fatalf("%.1f allocations per MUX writer round, want 0", n)
	}
}

// TestMuxWriterCostFlat_L54 (§A5.3, L54): idle views cost nothing. A round
// over the same 2 ready views — one of them asking for a WakeAt and marking
// itself cap-blocked every round, with every round's PONG watermark moved,
// so the writer's wake and capacity passes run every round — visits the
// same number of views and makes the same endpoint calls with 2, 64 and
// 256 attached views. The count is deterministic; the wall-clock cost per
// round is logged only (no timing assertion in the unit lane, A11.5).
func TestMuxWriterCostFlat_L54(t *testing.T) {
	type cost struct {
		touched, fills uint64
		wall           time.Duration
	}
	const rounds = 2000
	run := func(n int) cost {
		env := hEnv()
		ep := &wakeCapEP{ackDataEP: ackDataEP{chunk: env.Bufs.Get(ChunkSize, nil)}}
		c, views := bareMuxTrunk(env, &nopConn{}, n, ep)
		b := NewBatch(256 << 10)
		base := time.Now()
		t0, start := c.ms.touched, time.Now()
		for i := 0; i < rounds; i++ {
			b.Reset(base.Add(time.Duration(i+1) * 10 * time.Microsecond))
			c.mu.Lock()
			c.st.pongMark++ // a PONG arrived: the capacity pass runs
			c.mu.Unlock()
			views[0].Wake() // the same two views are ready in every configuration
			views[1].Wake()
			c.fillRound(b)
		}
		return cost{touched: c.ms.touched - t0, fills: ep.fills, wall: time.Since(start) / rounds}
	}
	c2, c64, c256 := run(2), run(64), run(256)
	t.Logf("round cost: 2 views %v, 64 views %v, 256 views %v (views visited %d, %d, %d)", c2.wall, c64.wall, c256.wall, c2.touched, c64.touched, c256.touched)
	if c2.fills < 4*rounds || c2.touched < 4*rounds-2 { // 2 ready views, then the wake and the capacity pass, every round but the first
		t.Fatalf("2 views: %d endpoint calls and %d views visited in %d rounds; the wake and capacity passes did not run", c2.fills, c2.touched, rounds)
	}
	for _, c := range []cost{c64, c256} {
		if c.touched != c2.touched || c.fills != c2.fills {
			t.Fatalf("a round's work grows with idle views: views visited %d / %d / %d, endpoint calls %d / %d / %d (2 / 64 / 256 views)",
				c2.touched, c64.touched, c256.touched, c2.fills, c64.fills, c256.fills)
		}
	}
}

// wakeCapEP is ackDataEP whose view 2, in its payload call, asks for a
// call 5 µs later and marks the batch cap-blocked; it counts Fill calls.
type wakeCapEP struct {
	ackDataEP
	fills uint64
}

func (e *wakeCapEP) Fill(c *Conn, b *Batch) {
	e.fills++
	e.ackDataEP.Fill(c, b)
	if c.Handle() == 2 && !b.ControlOnly() {
		b.WakeAt(b.Now().Add(5 * time.Microsecond))
		b.MarkCapBlocked()
	}
}

// nopConn is a net.Conn that discards writes and reads EOF.
type nopConn struct{ net.Conn }

func (nopConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (nopConn) Write(p []byte) (int, error)      { return len(p), nil }
func (nopConn) Close() error                     { return nil }
func (nopConn) SetDeadline(time.Time) error      { return nil }
func (nopConn) SetReadDeadline(time.Time) error  { return nil }
func (nopConn) SetWriteDeadline(time.Time) error { return nil }

// loopReader serves an encoded frame stream from the start again once it
// was read (with the fseq restarting: the test resets the reader's).
type loopReader struct {
	nopConn
	b   []byte
	pos int
}

func (l *loopReader) Read(p []byte) (int, error) {
	if l.pos == len(l.b) {
		return 0, io.EOF
	}
	n := copy(p, l.b[l.pos:])
	l.pos += n
	return n, nil
}

// TestTrunkDispatchZeroAllocs (M3-D9, §A11.4): the reader's dispatch of a
// session frame on a MUX trunk — a last-hit cache hit and a table miss —
// allocates nothing.
func TestTrunkDispatchZeroAllocs(t *testing.T) {
	env := hEnv()
	ep := &ackDataEP{chunk: env.Bufs.Get(ChunkSize, nil)}
	const frames = 4096
	var stream bytes.Buffer
	payload := dataPayload(0, 200)
	fseq := env.Presets.firstFseq()
	for i := 0; i < frames; i++ {
		h := uint32(2)
		if i%4 >= 2 {
			h = uint32(3 + i%2) // misses: 3, 4 alternate
		}
		stream.Write(wire.AppendFrame(nil, wire.Header{Type: wire.TypeData, Fseq: fseq, Handle: h}, payload))
		fseq++
	}
	lr := &loopReader{b: stream.Bytes()}
	c, _ := bareMuxTrunk(env, lr, 4, ep)
	rd := &c.rd
	rd.stage = env.Bufs.Get(BigData, nil)
	read := func() {
		if !c.readFrame(rd) {
			t.Fatal("readFrame ended")
		}
	}
	read()
	if n := testing.AllocsPerRun(frames-200, read); n != 0 && !carrierRace {
		t.Fatalf("%.2f allocations per dispatched frame, want 0", n)
	}
}
