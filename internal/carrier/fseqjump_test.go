package carrier

import (
	"slices"
	"testing"
	"testing/synctest"

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
