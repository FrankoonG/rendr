package carrier

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Datagram carrier tests of GOAWAY, closing rounds, the written RACK of the
// retirement, big DGRAMs, write deadlines and the PING commit (M2 design
// §A4.6, §A5.3, §A5.8, §A5.10; Revision 1, R1-4; integration 1, D17).

// relTypes returns the inner types of the RELs among recorded writes, one
// per cseq in order of first appearance, and their cseqs.
func relTypes(ws []dgWrite) (types []wire.Type, cseqs []uint32) {
	seen := map[uint32]bool{}
	for _, w := range ws {
		for _, h := range relsOf(w.b) {
			if !seen[h.Cseq] {
				seen[h.Cseq] = true
				types = append(types, h.Type)
				cseqs = append(cseqs, h.Cseq)
			}
		}
	}
	return types, cseqs
}

// firstWrite returns when the first recorded write matching pred was made.
func firstWrite(ws []dgWrite, pred func([]byte) bool) time.Time {
	for _, w := range ws {
		if pred(w.b) {
			return w.at
		}
	}
	return time.Time{}
}

// closeCseq returns the cseq of our REL{CLOSE} among datagrams ds.
func closeCseq(ds [][]byte) (uint32, bool) {
	for _, d := range ds {
		for _, h := range relsOf(d) {
			if h.Type == wire.TypeClose {
				return h.Cseq, true
			}
		}
	}
	return 0, false
}

// TestDatagramGoAway: Conn.GoAway on a datagram carrier places REL{GOAWAY}
// ahead of REL{CLOSE} (Runtime.Close, §A4.6, §A5.10); the peer reports
// PeerGoAway and PeerClosed, and both ends retire. With one REL of room
// left the CLOSE waits for the RACK of the GOAWAY.
func TestDatagramGoAway(t *testing.T) {
	isClose := func(d []byte) bool {
		_, ok := closeCseq([][]byte{d})
		return ok
	}
	t.Run("GOAWAY then CLOSE", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			a, b := dgPair(t, 1200)
			a.ep, b.ep = nil, nil // b answers the CLOSE with its own at once
			a.io.setRec(true)
			a.start(StartOptions{})
			b.start(StartOptions{})
			synctest.Wait()
			a.c.GoAway()
			hWait(t, a.c)
			hWait(t, b.c)
			types, cseqs := relTypes(a.io.recorded())
			if len(types) != 2 || types[0] != wire.TypeGoAway || types[1] != wire.TypeClose || cseqs[1] != cseqs[0]+1 {
				t.Fatalf("RELs %v (cseqs %v), want GOAWAY then CLOSE", types, cseqs)
			}
			if !b.c.PeerGoAway() || !b.c.PeerClosed() {
				t.Fatalf("peer: GOAWAY %v, CLOSE %v", b.c.PeerGoAway(), b.c.PeerClosed())
			}
			for _, s := range []*dgSide{a, b} {
				if _, cause, detail, _ := s.c.Death(); cause != CauseRetired {
					t.Fatalf("cause %v %q, want retired", cause, detail)
				}
			}
		})
	})
	t.Run("CLOSE waits for the RACK of the GOAWAY", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			a, b := dgPair(t, 1200)
			var want atomic.Int32
			var next atomic.Uint64
			a.ep.setFill(finFill(&want, &next))
			a.io.setRec(true)
			b.io.setRec(true)
			a.start(StartOptions{})
			b.start(StartOptions{})
			synctest.Wait()
			b.io.setFilter(func([]byte) bool { return false }) // no RACK reaches a
			want.Store(wire.RelWindow - 1)
			a.c.Wake()
			synctest.Wait()
			if r := a.c.RelRoom(); r != 1 {
				t.Fatalf("RelRoom %d, want 1", r)
			}
			a.c.GoAway()
			synctest.Wait()
			types, cseqs := relTypes(a.io.recorded())
			if n := len(types); n != wire.RelWindow || types[n-1] != wire.TypeGoAway {
				t.Fatalf("RELs %v, want seven FINs then GOAWAY and no CLOSE", types)
			}
			goAway := cseqs[len(cseqs)-1]
			if !b.c.PeerGoAway() {
				t.Fatal("the peer did not report GOAWAY")
			}
			b.io.setFilter(nil) // the retransmission of una draws a RACK covering the GOAWAY
			for start := time.Now(); !b.c.PeerClosed(); {
				if time.Since(start) > 3*time.Second {
					t.Fatal("our CLOSE never reached the peer")
				}
				time.Sleep(10 * time.Millisecond)
			}
			b.c.Retire(wire.CloseRetire) // the owner's answer to the bell
			hWait(t, a.c)
			hWait(t, b.c)
			rackAt := firstWrite(b.io.recorded(), func(d []byte) bool {
				for _, r := range racksOf(d) {
					if !wire.SeqLess(r.CumAck, goAway) {
						return true
					}
				}
				return false
			})
			closeAt := firstWrite(a.io.recorded(), isClose)
			if rackAt.IsZero() || closeAt.IsZero() || closeAt.Before(rackAt) {
				t.Fatalf("the RACK of the GOAWAY written at %v, our CLOSE at %v: the CLOSE went first", rackAt, closeAt)
			}
			for _, s := range []*dgSide{a, b} {
				if _, cause, detail, _ := s.c.Death(); cause != CauseRetired {
					t.Fatalf("cause %v %q, want retired", cause, detail)
				}
			}
		})
	})
}

// TestDatagramClosingRounds: after our CLOSE the rounds place only RACKs and
// REL retransmissions (M2-D31): a PING is not answered, RelRoom is 0 (no
// frame follows a CLOSE), a REL from the peer is still RACKed; the RACK of
// our CLOSE and the peer's CLOSE then end the retirement.
func TestDatagramClosingRounds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p := rawPair(t, 1200, true)
		s.start(StartOptions{})
		synctest.Wait()
		p.read()
		s.c.Retire(wire.CloseRetire)
		synctest.Wait()
		ourClose, ok := closeCseq(p.read())
		if !ok {
			t.Fatal("our CLOSE was not written")
		}
		if r := s.c.RelRoom(); r != 0 {
			t.Fatalf("RelRoom %d after our CLOSE, want 0", r)
		}
		first := s.env.Presets.firstCseq()
		p.send(pingFrame(wire.TypePing, wire.Ping{ID: 41, Nonce: 1}), relFrame(first, wire.TypeFin, 0, wire.SessionHandle, finInner(0)))
		synctest.Wait()
		var pong, rack bool
		for _, d := range p.read() {
			pong = pong || len(pingsOf(d, true)) > 0
			for _, r := range racksOf(d) {
				rack = rack || r.CumAck == first
			}
		}
		if pong || !rack {
			t.Fatalf("closing rounds: PONG %v, RACK of the peer's REL %v; want only the RACK", pong, rack)
		}
		p.send(relFrame(first+1, wire.TypeClose, 0, 0, []byte{byte(wire.CloseRetire)}), rackFrame(ourClose, 0))
		hWait(t, s.c)
		if _, cause, detail, _ := s.c.Death(); cause != CauseRetired || !strings.Contains(detail, "CLOSE exchange complete") {
			t.Fatalf("cause %v %q, want retired by the CLOSE exchange", cause, detail)
		}
	})
}

// TestDatagramRetireNeedsWrittenRack: the retirement completes only after a
// datagram carrying the RACK of the peer's CLOSE was written; one lost to
// noise does not count, the RACK answering the peer's retransmitted CLOSE
// does (R1-4).
func TestDatagramRetireNeedsWrittenRack(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p := rawPair(t, 1200, false)
		var noised atomic.Bool
		s.io.setOut(func(d []byte) error {
			if anyRack(d) && noised.CompareAndSwap(false, true) {
				return ErrNoise
			}
			return nil
		})
		s.start(StartOptions{})
		synctest.Wait()
		p.read()
		first := s.env.Presets.firstCseq()
		closeF := relFrame(first, wire.TypeClose, 0, 0, []byte{byte(wire.CloseRetire)})
		p.send(closeF)
		synctest.Wait()
		if !noised.Load() || !s.c.PeerClosed() {
			t.Fatalf("RACK lost to noise %v, peer closed %v", noised.Load(), s.c.PeerClosed())
		}
		s.c.Retire(wire.CloseRetire)
		synctest.Wait()
		ourClose, ok := closeCseq(p.read())
		if !ok {
			t.Fatal("our CLOSE was not written")
		}
		p.send(rackFrame(ourClose, 0))
		synctest.Wait()
		if dead, cause, detail, _ := s.c.Death(); dead {
			t.Fatalf("retired (%v %q) while the RACK of the peer's CLOSE was only lost to noise", cause, detail)
		}
		p.send(closeF) // the peer retransmits its CLOSE: re-RACKed, and this RACK is written
		hWait(t, s.c)
		if _, cause, detail, _ := s.c.Death(); cause != CauseRetired || !strings.Contains(detail, "CLOSE exchange complete") {
			t.Fatalf("cause %v %q, want retired by the CLOSE exchange", cause, detail)
		}
	})
}

// TestDatagramBigDgramByRef: on a datagram carrier a DGRAM of BigData or
// more is copied into a Buf of its own whose ownership moves to the
// endpoint, a smaller one is valid during the call; a big DGRAM whose Buf
// the Budget refuses is dropped and counted, and the carrier lives (§A5.3).
func TestDatagramBigDgramByRef(t *testing.T) {
	const cmtu = 24000
	t.Run("by reference", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, p := rawPair(t, cmtu, true)
			s.start(StartOptions{})
			synctest.Wait()
			p.send(dgramFrame(1, 100))
			p.send(dgramFrame(2, 20000))
			synctest.Wait()
			got := s.ep.datagrams()
			if len(got) != 2 || got[0] != (dgRec{seq: 1, n: 100}) || got[1] != (dgRec{seq: 2, n: 20000, byRef: true}) {
				t.Fatalf("datagrams %+v", got)
			}
		})
	})
	t.Run("refused by the Budget", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, p := rawPairWith(t, cmtu, true, func(env *Env) { env.Budget = NewBudget(4096) })
			s.start(StartOptions{})
			synctest.Wait()
			p.send(dgramFrame(1, 20000))
			p.send(dgramFrame(2, 100))
			synctest.Wait()
			if dead, cause, detail, _ := s.c.Death(); dead {
				t.Fatalf("carrier died: %v %q", cause, detail)
			}
			got := s.ep.datagrams()
			if len(got) != 1 || got[0] != (dgRec{seq: 2, n: 100}) || s.c.Stats().Dropped != 1 {
				t.Fatalf("datagrams %+v, dropped %d; want the small one and 1 dropped", got, s.c.Stats().Dropped)
			}
		})
	})
}

// TestDatagramWriteDeadlineIsStall_D17: a datagram write that ends at its
// deadline — os.ErrDeadlineExceeded, wrapped as transports do — ends the
// carrier as write_stall, not transport_error (integration 1, D17).
func TestDatagramWriteDeadlineIsStall_D17(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := dgPair(t, 1200)
		a.io.setOut(func([]byte) error { return fmt.Errorf("writeto: %w", os.ErrDeadlineExceeded) })
		a.start(StartOptions{})
		b.start(StartOptions{})
		hWait(t, a.c)
		if _, cause, detail, _ := a.c.Death(); cause != CauseWriteStall {
			t.Fatalf("cause %v %q, want write_stall", cause, detail)
		}
	})
}

// TestRefusedPingRecordRemoved: a PING whose datagram the transport refused
// as too large never left: its record goes (§A5.8), so it holds no ring
// slot, draws no retry and counts toward no death.
func TestRefusedPingRecordRemoved(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := dgPair(t, 1200)
		var refused atomic.Uint32
		a.io.setOut(func(d []byte) error {
			for _, pg := range pingsOf(d, false) {
				if pg.ID != 0 && refused.CompareAndSwap(0, pg.ID) {
					return &wire.DatagramTooLargeError{Max: 0}
				}
			}
			return nil
		})
		a.start(StartOptions{})
		b.start(StartOptions{})
		synctest.Wait()
		id := refused.Load()
		a.c.mu.Lock()
		i := a.c.st.find(id)
		a.c.mu.Unlock()
		if id == 0 || i >= 0 {
			t.Fatalf("refused PING %d, its record at %d; want it removed", id, i)
		}
	})
}

// TestDatagramPingCommittedWithItsWrite_L23: a PING is committed when the
// write of its datagram returns, not at the end of the round: later
// datagrams of the same round that take long to write neither stretch the
// RTT sample nor make its PONG arrive before the commit (no sample at all).
func TestDatagramPingCommittedWithItsWrite_L23(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := dgPair(t, 1200)
		const oneWay = 5 * time.Millisecond
		a.io.setDelay(oneWay)
		b.io.setDelay(oneWay)
		a.io.setOut(func(d []byte) error {
			if !isPingDatagram(d) && hasType(d, wire.TypeDgram) {
				time.Sleep(20 * time.Millisecond) // a slow write behind the PING's
			}
			return nil
		})
		var done atomic.Bool
		body := make([]byte, 1000)
		a.ep.setFill(func(c *Conn, bt *Batch) {
			if done.Swap(true) {
				return
			}
			for k := range 10 {
				bt.AddDgram(wire.SessionHandle, uint64(k), body, nil)
			}
		})
		a.io.setRec(true)
		a.start(StartOptions{})
		b.start(StartOptions{})
		time.Sleep(300 * time.Millisecond) // the round takes about 200 ms
		synctest.Wait()
		ws := a.io.recorded()
		if len(ws) < 10 || !isPingDatagram(ws[0].b) || ws[len(ws)-1].at.Sub(ws[0].at) < 150*time.Millisecond {
			t.Fatalf("%d writes; want the PING first in a round of slow writes", len(ws))
		}
		a.c.mu.Lock()
		seen, srtt := a.c.st.rttSeen, a.c.st.srtt
		a.c.mu.Unlock()
		if !seen || srtt != 2*oneWay {
			t.Fatalf("RTT sampled %v, srtt %v; want the path's %v", seen, srtt, 2*oneWay)
		}
	})
}
