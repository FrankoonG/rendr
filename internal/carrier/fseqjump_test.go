package carrier

import (
	"slices"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// The forward-jump rule of the datagram fseq window (m3 FSEQJUMP; m3
// design §A9.1, R1-35; L43, L59): a frame a window or more ahead moves the
// window only when its datagram proves it comes from this direction's
// sender (dgJumpProof); otherwise it is dropped and counted, and its claim
// is kept moving (dgJumpClaim).

// fjDelivered returns the session seqs of the DGRAMs an endpoint received.
func fjDelivered(e *dEP) (seqs []uint64) {
	for _, d := range e.datagrams() {
		seqs = append(seqs, d.seq)
	}
	return seqs
}

// fjPings returns the ids of the PINGs (pong false) or PONGs the peer read.
func fjPings(ds [][]byte, pong bool) (ids []uint32, all []wire.Ping) {
	for _, d := range ds {
		for _, pg := range pingsOf(d, pong) {
			ids = append(ids, pg.ID)
			all = append(all, pg)
		}
	}
	return ids, all
}

// fjSettle answers every PING the carrier wrote so far, so that no PING
// of the carrier is outstanding, and drains the peer.
func fjSettle(p *rawPeer) {
	for {
		ds := p.read()
		if len(ds) == 0 {
			return
		}
		for _, d := range ds {
			for _, pg := range pingsOf(d, false) {
				p.send(pingFrame(wire.TypePong, pg))
			}
		}
		synctest.Wait()
	}
}

// TestDatagramForeignJumpDropped_L43: the datagrams of another carrier
// direction or session, whose fseqs start elsewhere (§0.13 A6), arrive a
// window or more ahead of the receiver's window: every frame is dropped and
// counted — a DGRAM, a PING and a PONG answering another incarnation's
// PING — no DGRAM reaches the endpoint, nothing dies, and the genuine
// direction goes on without a loss (before m3 FSEQJUMP the first one moved
// the window 2^20 ahead: the foreign DGRAMs were delivered and every
// genuine frame after them was late until ping_timeout).
func TestDatagramForeignJumpDropped_L43(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p := rawPair(t, 1200, true)
		s.start(StartOptions{})
		synctest.Wait()
		fjSettle(p)
		p.send(dgramFrame(1, 100))
		synctest.Wait()
		d0 := s.c.Stats().Dropped
		foreign := &rawPeer{io: p.io, fseq: p.fseq + 1<<20}
		for i := range uint32(16) {
			foreign.send(
				dgramFrame(uint64(100+i), 100),
				pingFrame(wire.TypePong, wire.Ping{ID: 1 + i, Nonce: 99}), // answers another salt
				pingFrame(wire.TypePing, wire.Ping{ID: 50 + i, Nonce: 7}),
			)
		}
		synctest.Wait()
		if d := s.c.Stats().Dropped - d0; d != 48 {
			t.Fatalf("dropped %d frames of the 16 foreign datagrams, want all 48", d)
		}
		if got := fjDelivered(s.ep); !slices.Equal(got, []uint64{1}) {
			t.Fatalf("delivered seqs %v, want [1]: a foreign DGRAM reached the endpoint", got)
		}
		p.read()
		p.send(dgramFrame(2, 100), pingFrame(wire.TypePing, wire.Ping{ID: 9, Nonce: 5}))
		synctest.Wait()
		if got := fjDelivered(s.ep); !slices.Equal(got, []uint64{1, 2}) {
			t.Fatalf("delivered seqs %v, want [1 2]: the genuine direction lost a DGRAM", got)
		}
		if pongs, _ := fjPings(p.read(), true); !slices.Contains(pongs, 9) {
			t.Fatalf("PONGs %v: the genuine PING 9 after the foreign datagrams was not answered", pongs)
		}
		if d := s.c.Stats().Dropped - d0; d != 48 {
			t.Fatalf("dropped %d, want the 48 foreign frames only", d)
		}
		if dead, cause, detail, _ := s.c.Death(); dead {
			t.Fatalf("carrier died: %v %q", cause, detail)
		}
	})
}

// TestDatagramJumpProvedByPong_L43: the peer's own direction jumps after
// an outage cost it 5000 frames. The first jumped datagram is dropped and
// counted (a DGRAM and a PING), but its PING is answered — the peer may
// wait for the same proof — and the carrier asks for a PING of its own,
// once per RTO however many jumped datagrams follow. The PONG to it proves
// the jump: the frames of its datagram (a DGRAM before it included) and
// everything after are accepted; jumped frames reordered behind the PONG
// are new once. While a genuine answer is due, a jumped PING never
// displaces it.
func TestDatagramJumpProvedByPong_L43(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p := rawPair(t, 1200, true)
		s.start(StartOptions{})
		synctest.Wait()
		fjSettle(p)
		d0 := s.c.Stats().Dropped
		p.fseq += 5000 // lost in the outage
		p.send(pingFrame(wire.TypePing, wire.Ping{ID: 20, Nonce: 3}), dgramFrame(10, 100))
		synctest.Wait()
		if d := s.c.Stats().Dropped - d0; d != 2 || len(fjDelivered(s.ep)) != 0 {
			t.Fatalf("dropped %d, delivered %v: the unproven jump was taken", d, fjDelivered(s.ep))
		}
		ds := p.read()
		pongs, _ := fjPings(ds, true)
		pingIDs, pings := fjPings(ds, false)
		if !slices.Contains(pongs, 20) || len(pings) != 1 || pingIDs[0] == 0 {
			t.Fatalf("PONGs %v, PINGs %v: want the jumped PING 20 answered and one PING of the carrier", pongs, pingIDs)
		}
		ours := pings[0]
		// More jumped datagrams within the RTO ask for no second PING.
		p.send(dgramFrame(11, 100))
		p.send(dgramFrame(12, 100))
		synctest.Wait()
		if ids, _ := fjPings(p.read(), false); len(ids) != 0 {
			t.Fatalf("PINGs %v within the RTO of the first request", ids)
		}
		// The proof: a DGRAM, the PONG to our PING and a DGRAM in one
		// datagram, then a reordered jumped frame and the next in order.
		late := p.datagram(dgramFrame(13, 100))
		p.send(dgramFrame(14, 100), pingFrame(wire.TypePong, ours), dgramFrame(15, 100))
		_ = p.io.WriteDatagram(late)
		p.send(dgramFrame(16, 100), pingFrame(wire.TypePing, wire.Ping{ID: 21, Nonce: 3}))
		synctest.Wait()
		if got := fjDelivered(s.ep); !slices.Equal(got, []uint64{14, 15, 13, 16}) {
			t.Fatalf("delivered seqs %v, want [14 15 13 16]", got)
		}
		if pongs, _ := fjPings(p.read(), true); !slices.Contains(pongs, 21) {
			t.Fatalf("PONGs %v: PING 21 after the proved jump was not answered", pongs)
		}
		if d := s.c.Stats().Dropped - d0; d != 4 {
			t.Fatalf("dropped %d, want the 4 unproven jumped frames", d)
		}
		// A jumped PING while a genuine answer is due: the writer is held in
		// a write, a genuine PING fills the PONG slot, and a PING a window
		// ahead in the same datagram leaves it.
		gate := make(chan struct{})
		s.io.setOut(func([]byte) error { <-gate; return nil })
		p.send(pingFrame(wire.TypePing, wire.Ping{ID: 29, Nonce: 3})) // the write the writer blocks in
		synctest.Wait()
		d := p.datagram(pingFrame(wire.TypePing, wire.Ping{ID: 30, Nonce: 3}))
		p.fseq += 1 << 20
		d = append(d, p.datagram(pingFrame(wire.TypePing, wire.Ping{ID: 31, Nonce: 3}))...)
		_ = p.io.WriteDatagram(d)
		synctest.Wait()
		s.io.setOut(nil)
		close(gate)
		synctest.Wait()
		if pongs, _ := fjPings(p.read(), true); !slices.Contains(pongs, 30) || slices.Contains(pongs, 31) {
			t.Fatalf("PONGs %v: want the genuine PING 30 answered, never the jumped 31 in its place", pongs)
		}
		if dead, cause, detail, _ := s.c.Death(); dead {
			t.Fatalf("carrier died: %v %q", cause, detail)
		}
	})
}

// TestDatagramJumpWithRebind_L59: an outage that also moved the dialer's
// NAT mapping: the passive raw-UDP flow's peer sends from a new source with
// its fseqs 5000 ahead. Its datagram is dropped (no proof: the passive's
// replies go to the old address and are lost) but starts a rebind
// challenge; a jumped datagram from a third source does not retarget it;
// the challenge's answer from the candidate proves the jump and commits
// the rebind, and replies follow the new address (M2-D27).
func TestDatagramJumpWithRebind_L59(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p := rawPair(t, 1200, false)
		s.io.rebind = true
		s.start(StartOptions{})
		synctest.Wait()
		fjSettle(p)
		p.io.moveTo(fakeAddr(9))
		p.fseq += 5000
		p.send(pingFrame(wire.TypePing, wire.Ping{ID: 5, Nonce: 1}))
		synctest.Wait()
		third := &rawPeer{io: p.io, fseq: p.fseq + 1<<24}
		s.io.inject(fakeAddr(30), third.datagram(pingFrame(wire.TypePing, wire.Ping{ID: 6, Nonce: 1})))
		synctest.Wait()
		if n := rebindAnswer(p); n != 1 {
			t.Fatalf("%d challenges reached the candidate", n)
		}
		synctest.Wait()
		if st := s.c.Stats(); st.Rebinds != 1 || s.io.cur != fakeAddr(9) {
			t.Fatalf("rebinds %d, peer %v: the challenge's answer did not prove the jump", st.Rebinds, s.io.cur)
		}
		p.read()
		p.send(pingFrame(wire.TypePing, wire.Ping{ID: 7, Nonce: 1}))
		synctest.Wait()
		if pongs, _ := fjPings(p.read(), true); !slices.Contains(pongs, 7) {
			t.Fatalf("PONGs %v: replies do not follow the committed rebind", pongs)
		}
		if dead, cause, detail, _ := s.c.Death(); dead {
			t.Fatalf("carrier died: %v %q", cause, detail)
		}
	})
}

// fjChal returns the nonces of the challenge PINGs (pong false) or
// challenge PONGs (pong true), the ones with id 0, in ds.
func fjChal(ds [][]byte, pong bool) (nonces []uint64) {
	_, all := fjPings(ds, pong)
	for _, pg := range all {
		if pg.ID == 0 {
			nonces = append(nonces, pg.Nonce)
		}
	}
	return nonces
}

// TestDatagramJumpChallengePing_L59: the challenge-PONG slot under the
// forward-jump rule (dgJumpClaim). While the writer is held and the
// answer to a genuine challenge PING is due, a challenge PING a window
// ahead in the same datagram leaves it. Once the slot is free, a challenge
// PING a window ahead — the passive's challenge after an outage that cost
// both directions a window of frames — is answered with its nonce, and
// the PONG to the PING the carrier asked for proves the jump.
func TestDatagramJumpChallengePing_L59(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p := rawPair(t, 1200, true)
		s.start(StartOptions{})
		synctest.Wait()
		fjSettle(p)
		gate := make(chan struct{})
		s.io.setOut(func([]byte) error { <-gate; return nil })
		p.send(pingFrame(wire.TypePing, wire.Ping{ID: 29, Nonce: 3})) // the write the writer blocks in
		synctest.Wait()
		d := p.datagram(pingFrame(wire.TypePing, wire.Ping{ID: 0, Nonce: 0x6e6e}))
		p.fseq += 1 << 20
		d = append(d, p.datagram(pingFrame(wire.TypePing, wire.Ping{ID: 0, Nonce: 0x7a7a}))...)
		_ = p.io.WriteDatagram(d)
		synctest.Wait()
		s.io.setOut(nil)
		close(gate)
		synctest.Wait()
		ds := p.read()
		if got := fjChal(ds, true); !slices.Equal(got, []uint64{0x6e6e}) {
			t.Fatalf("challenge PONGs %#x, want the genuine 0x6e6e only, never the jumped 0x7a7a in its place", got)
		}
		_, ours := fjPings(ds, false)
		if len(ours) == 0 {
			t.Fatal("the carrier asked for no PING of its own after the jumped frame")
		}
		// The slot is free: a jumped challenge PING is answered.
		p.send(pingFrame(wire.TypePing, wire.Ping{ID: 0, Nonce: 0x5151}), dgramFrame(40, 100))
		synctest.Wait()
		if got := fjChal(p.read(), true); !slices.Equal(got, []uint64{0x5151}) {
			t.Fatalf("challenge PONGs %#x, want 0x5151: a jumped challenge PING was not answered", got)
		}
		if got := fjDelivered(s.ep); len(got) != 0 {
			t.Fatalf("delivered %v before the jump was proved", got)
		}
		p.send(pingFrame(wire.TypePong, ours[len(ours)-1]), dgramFrame(41, 100))
		synctest.Wait()
		if got := fjDelivered(s.ep); !slices.Equal(got, []uint64{41}) {
			t.Fatalf("delivered %v, want [41]: the PONG to the carrier's PING did not prove the jump", got)
		}
		if dead, cause, detail, _ := s.c.Death(); dead {
			t.Fatalf("carrier died: %v %q", cause, detail)
		}
	})
}

// TestDatagramJumpBothWaysWithRebind_L59: an outage costs both directions
// of a raw-UDP flow 1500 frames and moves the dialer's NAT mapping. The
// dialer's next DGRAM reaches the passive a window ahead from a new
// source: it is dropped and starts a rebind challenge, whose PING reaches
// the dialer a window ahead too. The dialer answers it (dgJumpClaim), the
// answer proves the jump to the passive and commits the rebind, and the
// passive's PONG to the dialer's PING, now sent to the new address, proves
// the jump to the dialer: DGRAMs flow both ways again, nothing dies.
func TestDatagramJumpBothWaysWithRebind_L59(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := dgPair(t, 1200)
		b.io.rebind = true
		var wantA, wantB, size atomic.Int32
		size.Store(10)
		a.ep.setFill(dgramFill(&wantA, &size))
		b.ep.setFill(dgramFill(&wantB, &size))
		a.start(StartOptions{})
		b.start(StartOptions{})
		synctest.Wait()
		wantA.Store(1)
		wantB.Store(1)
		a.c.Wake()
		b.c.Wake()
		synctest.Wait()
		if na, nb := len(b.ep.datagrams()), len(a.ep.datagrams()); na != 1 || nb != 1 {
			t.Fatalf("before the outage: %d and %d DGRAMs delivered, want 1 each", na, nb)
		}
		// The outage: 1500 DGRAMs each way are lost, then the dialer moves.
		drop := func([]byte) bool { return false }
		a.io.setFilter(drop)
		b.io.setFilter(drop)
		const lost = 1500
		wantA.Store(lost)
		wantB.Store(lost)
		for wantA.Load() > 0 || wantB.Load() > 0 {
			a.c.Wake()
			b.c.Wake()
			synctest.Wait()
		}
		if la, lb := a.io.lost.Load(), b.io.lost.Load(); la < lost || lb < lost {
			t.Fatalf("stimulus: the outage lost %d and %d datagrams, want ≥ %d each", la, lb, lost)
		}
		a.io.setFilter(nil)
		b.io.setFilter(nil)
		a.io.moveTo(fakeAddr(9))
		da, db := a.c.Stats().Dropped, b.c.Stats().Dropped
		wantA.Store(1)
		a.c.Wake()
		time.Sleep(time.Second)
		if st := b.c.Stats(); st.Rebinds != 1 || b.io.cur != fakeAddr(9) {
			t.Fatalf("rebinds %d, peer %v: the passive's challenge, a window ahead, was not answered", st.Rebinds, b.io.cur)
		}
		if a.c.Stats().Dropped == da || b.c.Stats().Dropped == db {
			t.Fatalf("stimulus: no frame was dropped as ahead (dropped %d → %d, %d → %d)",
				da, a.c.Stats().Dropped, db, b.c.Stats().Dropped)
		}
		na, nb := len(b.ep.datagrams()), len(a.ep.datagrams())
		wantA.Store(1)
		wantB.Store(1)
		a.c.Wake()
		b.c.Wake()
		synctest.Wait()
		if ga, gb := len(b.ep.datagrams())-na, len(a.ep.datagrams())-nb; ga != 1 || gb != 1 {
			t.Fatalf("after the recovery %d and %d DGRAMs delivered, want 1 each way", ga, gb)
		}
		for _, s := range []*dgSide{a, b} {
			if dead, cause, detail, _ := s.c.Death(); dead {
				t.Fatalf("carrier died: %v %q", cause, detail)
			}
		}
	})
}

// TestDatagramJumpChallengeProof_L59: a challenge answer proves a jump
// only as the challenge itself accepts it (onChallengePong): its nonce,
// from its candidate, before its expiry. The right nonce from a third
// source proves nothing, nor does it from the candidate once the challenge
// expired while the writer was held (an expired challenge stays recorded
// until the writer runs); the frames are dropped. A PONG to a PING of the
// carrier still proves the jump afterwards.
func TestDatagramJumpChallengeProof_L59(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p := rawPairWith(t, 1200, false, func(env *Env) { env.Timing.WriteStall = 3 * time.Second })
		s.io.rebind = true
		s.start(StartOptions{})
		synctest.Wait()
		fjSettle(p)
		gate := make(chan struct{})
		s.io.setOut(func([]byte) error { <-gate; return nil })
		defer func() {
			s.io.setOut(nil)
			close(gate)
		}()
		p.io.moveTo(fakeAddr(9))
		p.fseq += 5000
		p.send(pingFrame(wire.TypePing, wire.Ping{ID: 5, Nonce: 1}))
		synctest.Wait()
		s.c.mu.Lock()
		ch := s.c.dg.chal
		s.c.mu.Unlock()
		if !ch.active || ch.cand != fakeAddr(9) {
			t.Fatalf("stimulus: no challenge to the new source (%+v)", ch)
		}
		answer := pingFrame(wire.TypePong, wire.Ping{ID: 0, Nonce: ch.nonce})
		s.io.inject(fakeAddr(30), p.datagram(dgramFrame(50, 100), answer))
		synctest.Wait()
		if got := fjDelivered(s.ep); len(got) != 0 {
			t.Fatalf("delivered %v: the challenge's nonce from a third source proved the jump", got)
		}
		time.Sleep(time.Until(ch.at.Add(chalExpiry)))
		p.send(dgramFrame(51, 100), answer)
		synctest.Wait()
		if got := fjDelivered(s.ep); len(got) != 0 {
			t.Fatalf("delivered %v: the expired challenge's answer proved the jump", got)
		}
		if st := s.c.Stats(); st.Rebinds != 0 {
			t.Fatalf("rebinds %d after a misdirected and an expired answer", st.Rebinds)
		}
		p.send(dgramFrame(52, 100), pingFrame(wire.TypePong, wire.Ping{ID: 77, Nonce: s.c.salt ^ 77}))
		synctest.Wait()
		if got := fjDelivered(s.ep); !slices.Equal(got, []uint64{52}) {
			t.Fatalf("delivered %v, want [52]: a PONG with the carrier's salt did not prove the jump", got)
		}
		if dead, cause, detail, _ := s.c.Death(); dead {
			t.Fatalf("carrier died: %v %q", cause, detail)
		}
	})
}
