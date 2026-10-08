package carrier

import (
	"bytes"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Wave-4 group G1 tests: a second NAT move while a challenge is in flight,
// a move after a held passive flow was released but before its first REL
// reached the dialer (M2-D27, R1-14), and the resend of a REL burst's tail
// (M2-D16, R1-18).

// chalTo returns the recorded rebind challenges written to dst.
func chalTo(ws []dgWrite, dst PeerKey) (n int) {
	for _, d := range challenges(ws) {
		if d == dst {
			n++
		}
	}
	return n
}

// TestRebindDoubleMove_L59: the peer of a passive raw-UDP flow moves to
// address 9 and PINGs without answering the challenge; 10 ms later it moves
// again, to 10, and from then on PINGs and answers every challenge every
// 20 ms. The challenge in flight is retargeted to the newer source (M2-D27):
// the rebind commits to 10 within 2·RTO + RTT of the second move, exactly
// once, and the carrier lives; replies follow the commit.
func TestRebindDoubleMove_L59(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p := rawPair(t, 1200, false)
		s.io.rebind = true
		s.io.setRec(true)
		s.io.setDelay(10 * time.Millisecond)
		p.io.setDelay(10 * time.Millisecond)
		t.Cleanup(func() { p.io.Close() }) // ends the delay goroutine towards the raw peer
		s.start(StartOptions{})
		for range 5 { // the first PING answered: an RTT sample (20 ms)
			time.Sleep(20 * time.Millisecond)
			rebindAnswer(p)
		}
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		p.read()
		s.c.mu.Lock()
		rto, rtt, seen := s.c.relRTOLocked(), s.c.st.srtt, s.c.st.rttSeen
		s.c.mu.Unlock()
		if !seen || rtt <= 0 {
			t.Fatalf("no RTT sample before the moves (srtt %v)", rtt)
		}

		p.io.moveTo(fakeAddr(9))
		p.send(pingFrame(wire.TypePing, wire.Ping{ID: 100, Nonce: 1}))
		time.Sleep(10 * time.Millisecond)
		p.io.moveTo(fakeAddr(10))
		t1 := time.Now()
		id := uint32(101)
		for s.c.Stats().Rebinds == 0 && time.Since(t1) < 3*time.Second {
			p.send(pingFrame(wire.TypePing, wire.Ping{ID: id, Nonce: 1}))
			id++
			time.Sleep(20 * time.Millisecond)
			rebindAnswer(p)
		}
		took := time.Since(t1)
		ws := s.io.recorded()
		if n9 := chalTo(ws, fakeAddr(9)); n9 == 0 {
			t.Fatal("no challenge went to the first candidate (stimulus)")
		}
		if n10 := chalTo(ws, fakeAddr(10)); n10 == 0 {
			t.Fatal("no challenge went to the second candidate")
		}
		if st := s.c.Stats(); st.Rebinds != 1 || s.io.cur != fakeAddr(10) || took > 2*rto+rtt {
			t.Fatalf("rebinds %d, peer %v, %v after the second move; want 1, the second address, within 2·RTO + RTT = %v",
				st.Rebinds, s.io.cur, took, 2*rto+rtt)
		}
		t.Logf("second move committed %v after it (RTO %v, RTT %v)", took, rto, rtt)
		// Integrity: the carrier lives and its replies reach the new address.
		for range 100 {
			p.send(pingFrame(wire.TypePing, wire.Ping{ID: id, Nonce: 1}))
			id++
			time.Sleep(20 * time.Millisecond)
			rebindAnswer(p)
		}
		p.send(pingFrame(wire.TypePing, wire.Ping{ID: id, Nonce: 7}))
		time.Sleep(50 * time.Millisecond)
		var pong bool
		for _, d := range p.read() {
			for _, pg := range pingsOf(d, true) {
				pong = pong || pg.ID == id
			}
		}
		if dead, cause, detail, _ := s.c.Death(); dead || !pong {
			t.Fatalf("after the commit: dead %v (%v %q), PONG at the new address %v", dead, cause, detail, pong)
		}
		if r := s.c.Stats().Rebinds; r != 1 {
			t.Fatalf("rebinds %d after the commit, want 1", r)
		}
	})
}

// TestRebindReleasedBeforeH3_L59: a held passive flow (stored PREFACE and
// H2) is released by a Fill that places its first REL (H3, OPEN_ACK); the
// dialer moved before H3 arrived, so H3 went to the dead mapping, and the
// dialer — which sends nothing but copies of H1 until H3 arrives — sends an
// H1 copy from its new address. The copy starts a challenge to the new
// source while the first REL is unacknowledged (R1-14 as amended by
// wave 4): one challenge, the commit, and H3's next resend reaches the new
// address.
func TestRebindReleasedBeforeH3_L59(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p := rawPair(t, 1200, false)
		s.io.rebind = true
		s.io.setRec(true)
		var pre, ack [wire.PrefaceLen]byte
		wire.PutPreface(pre[:], &wire.Preface{Minor: wire.Minor, Instance: hPeerInst, CarrierID: 7})
		wire.PutPrefaceAck(ack[:], &wire.PrefaceAck{Minor: wire.Minor, Status: wire.PrefaceOK, Instance: s.env.Local, CarrierID: 7})
		s.c.dg.hs.pre = bytes.Clone(pre[:])
		s.c.dg.hs.h2b = bytes.Clone(ack[:])
		var verdict, placed atomic.Bool
		s.ep.setFill(func(c *Conn, b *Batch) {
			if verdict.Load() && !placed.Load() && b.AddOpenAck(wire.SessionHandle, &wire.OpenAck{Status: wire.StatusOK}) {
				placed.Store(true)
			}
		})
		s.start(StartOptions{Hold: true})
		synctest.Wait()
		p.read()
		first := s.env.Presets.firstCseq()

		p.io.moveTo(fakeAddr(9)) // the NAT moved: H3 goes to the dead mapping
		verdict.Store(true)
		s.c.Wake()
		synctest.Wait()
		if !placed.Load() || s.c.dg.held.Load() {
			t.Fatalf("H3 placed %v, held %v: the Fill did not release the hold", placed.Load(), s.c.dg.held.Load())
		}
		lostH3 := 0
		for _, w := range s.io.recorded() {
			for _, h := range relsOf(w.b) {
				if h.Cseq == first && w.dst == fakeAddr(2) {
					lostH3++
				}
			}
		}
		if lostH3 != 1 || len(p.read()) != 0 {
			t.Fatalf("H3 writes to the old address %d, want 1 lost (stimulus)", lostH3)
		}

		t0 := time.Now()
		_ = p.io.WriteDatagram(pre[:]) // an H1 copy (the dialer's keepalive) from the new address
		synctest.Wait()
		if n := chalTo(s.io.recorded(), fakeAddr(9)); n != 1 {
			t.Fatalf("%d challenges to the new address after the H1 copy, want 1", n)
		}
		if n := rebindAnswer(p); n != 1 {
			t.Fatalf("%d challenges reached the dialer, want 1", n)
		}
		synctest.Wait()
		if st := s.c.Stats(); st.Rebinds != 1 || s.io.cur != fakeAddr(9) {
			t.Fatalf("rebinds %d, peer %v; want 1 and the new address", st.Rebinds, s.io.cur)
		}
		var h3 time.Time
		for h3.IsZero() && time.Since(t0) < 3*time.Second {
			time.Sleep(10 * time.Millisecond)
			for _, d := range p.read() {
				for _, h := range relsOf(d) {
					if h.Cseq == first && h.Type == wire.TypeOpenAck {
						h3 = time.Now()
					}
				}
			}
		}
		s.c.mu.Lock()
		rto := s.c.relRTOLocked()
		s.c.mu.Unlock()
		if h3.IsZero() || h3.Sub(t0) > 2*rto {
			t.Fatalf("H3's resend reached the new address %v after the H1 copy (zero: never), want within 2·RTO = %v", h3.Sub(t0), 2*rto)
		}
		t.Logf("H3 resent to the new address %v after the H1 copy (RTO %v)", h3.Sub(t0), rto)
		if dead, cause, detail, _ := s.c.Death(); dead {
			t.Fatalf("the carrier died: %v %q", cause, detail)
		}
	})
}

// TestRelBurstTailResend_L12: three RELs lost together in one datagram, at
// 10 ms each way with the RTT settled. The RACK that the first REL's
// retransmission draws still leaves the second unacknowledged although it
// left with the first: it is known lost and resent at once (one
// implied-loss resend per RACK; no SACK logic, R1-18), within RTT + 5 ms
// of the first one's resend instead of RTT + RTO, and the third follows
// the second the same way. The FINs arrive in order, once each.
func TestRelBurstTailResend_L12(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := dgPair(t, 1200)
		a.io.setDelay(10 * time.Millisecond)
		b.io.setDelay(10 * time.Millisecond)
		a.io.setRec(true)
		var go2, placed atomic.Bool
		a.ep.setFill(func(c *Conn, bt *Batch) {
			if go2.Load() && !placed.Load() {
				placed.Store(true)
				if !bt.AddFin(wire.SessionHandle, 0) || !bt.AddFin(wire.SessionHandle, 1) || !bt.AddFin(wire.SessionHandle, 2) {
					t.Error("three FINs did not fit one round")
				}
			}
		})
		a.start(StartOptions{})
		b.start(StartOptions{})
		time.Sleep(2 * time.Second) // the first PINGs answered: the RTT settles at 20 ms
		a.c.mu.Lock()
		rtt, rto, seen := a.c.st.srtt, a.c.relRTOLocked(), a.c.st.rttSeen
		a.c.mu.Unlock()
		if !seen || rtt < 15*time.Millisecond || rtt > 25*time.Millisecond {
			t.Fatalf("srtt %v (seen %v), want about 20 ms", rtt, seen)
		}
		first := a.env.Presets.firstCseq()
		var lost atomic.Int32
		a.io.setFilter(dropFirst(func(d []byte) bool { return len(relsOf(d)) == 3 }, 1, &lost))
		go2.Store(true)
		a.c.Wake()
		time.Sleep(3 * time.Second)
		if lost.Load() != 1 {
			t.Fatalf("%d three-REL datagrams lost, want 1 (stimulus)", lost.Load())
		}
		var sent [3][]time.Time
		for _, w := range a.io.recorded() {
			for _, h := range relsOf(w.b) {
				if d := h.Cseq - first; d < 3 {
					sent[d] = append(sent[d], w.at)
				}
			}
		}
		for i := range sent {
			if len(sent[i]) != 2 {
				t.Fatalf("REL %d sent %d times, want twice (the lost copy and one resend)", i, len(sent[i]))
			}
		}
		for i := 1; i < 3; i++ {
			gap := sent[i][1].Sub(sent[i-1][1])
			if gap < 0 || gap > rtt+5*time.Millisecond {
				t.Fatalf("REL %d was resent %v after REL %d (RTO %v), want within RTT + 5 ms = %v", i, gap, i-1, rto, rtt+5*time.Millisecond)
			}
			t.Logf("REL %d resent %v after REL %d (RTT %v, RTO %v)", i, gap, i-1, rtt, rto)
		}
		if got := finOffsets(b.ep); len(got) != 3 || got[0] != 0 || got[1] != 1 || got[2] != 2 {
			t.Fatalf("passive FINs %v, want 0, 1, 2 once each (integrity)", got)
		}
		if dead, cause, detail, _ := a.c.Death(); dead {
			t.Fatalf("the carrier died: %v %q", cause, detail)
		}
	})
}

// TestRebindForgedAnswerKeepsTarget_L59: a datagram from a third source
// whose only frame is a PONG with id 0 carrying the challenge's nonce — a
// forged answer — is dropped and counted and does not retarget the
// challenge in flight (an answer is no claim of a new source): the
// challenge's resends keep going to the candidate, whose own answer then
// commits the rebind to it.
func TestRebindForgedAnswerKeepsTarget_L59(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p := rawPair(t, 1200, false)
		s.io.rebind = true
		s.io.setRec(true)
		s.start(StartOptions{})
		synctest.Wait()
		rebindAnswer(p)
		synctest.Wait()

		p.io.moveTo(fakeAddr(9))
		p.send(pingFrame(wire.TypePing, wire.Ping{ID: 100, Nonce: 1}))
		synctest.Wait()
		var nonce uint64
		for _, d := range p.read() { // the candidate does not answer yet
			for _, pg := range pingsOf(d, false) {
				if pg.ID == 0 {
					nonce = pg.Nonce
				}
			}
		}
		if nonce == 0 {
			t.Fatal("no challenge to the candidate (stimulus)")
		}
		d0 := s.c.Stats().Dropped
		s.io.inject(fakeAddr(22), p.datagram(pingFrame(wire.TypePong, wire.Ping{ID: 0, Nonce: nonce})))
		synctest.Wait()
		if d := s.c.Stats().Dropped - d0; d != 1 {
			t.Fatalf("the forged answer: %d dropped, want 1", d)
		}
		time.Sleep(time.Second) // the challenge's resends
		if n := chalTo(s.io.recorded(), fakeAddr(22)); n != 0 {
			t.Fatalf("%d challenges to the forged answer's source, want 0", n)
		}
		if n := rebindAnswer(p); n == 0 {
			t.Fatal("no challenge resend reached the candidate")
		}
		synctest.Wait()
		if st := s.c.Stats(); st.Rebinds != 1 || s.io.cur != fakeAddr(9) {
			t.Fatalf("rebinds %d, peer %v; want 1 and the candidate", st.Rebinds, s.io.cur)
		}
		if dead, cause, detail, _ := s.c.Death(); dead {
			t.Fatalf("the carrier died: %v %q", cause, detail)
		}
	})
}
