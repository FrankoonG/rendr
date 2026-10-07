package session

import (
	"io"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestPacketDedupWindow_L39: the receive dedup is the fixed SeqWindow
// (M2-D36): a seq seen within the window counts Duplicates, a seq older
// than the window DropLate — also one never seen (seq 0, lost for good,
// pins nothing) — reordering within the window loses nothing, and
// accepting a datagram allocates nothing.
func TestPacketDedupWindow_L39(t *testing.T) {
	s := dpSession(dpOpt{role: RolePassive, dedupBits: 1024})
	l, _ := dpAddLane(s, 1, true, true)
	buf := make([]byte, 64)
	deliver := func(seq uint64) {
		t.Helper()
		if err := dpDatagram(l, seq, dpPayload(seq, 16)); err != nil {
			t.Fatalf("seq %d: %v", seq, err)
		}
	}
	read := func() {
		if _, err := s.ReadFrom(buf); err != nil {
			panic(err)
		}
	}
	for seq := uint64(1); seq <= 3000; seq++ { // seq 0 is lost for good
		deliver(seq)
		read()
	}
	deliver(2990)            // inside the window, seen
	deliver(3000 - 1024 + 1) // the oldest seq the window still holds
	deliver(3000 - 1024)     // seen, but beyond the window
	deliver(0)               // never seen, beyond the window: late, not new
	deliver(3010)            // a jump ahead
	deliver(3005)            // reordered inside the window: new
	deliver(3005)            // and now a duplicate
	c := dpCtr(s)
	if c.Received != 3002 || c.Duplicates != 3 || c.DropLate != 2 {
		t.Fatalf("counters %+v; want Received 3002, Duplicates 3, DropLate 2", c)
	}
	hn := dpLocked(s, func(_ *stream, pk *packet) [2]uint64 { return [2]uint64{pk.rxHigh, pk.rxCount} })
	hi, n := hn[0], hn[1]
	if hi != 3010 || n != 3002 {
		t.Fatalf("PACK state highest %d received %d, want 3010 and 3002", hi, n)
	}
	read()
	read()
	if !dpRaceEnabled {
		seq := uint64(4000)
		if a := testing.AllocsPerRun(1000, func() {
			seq++
			if err := (*plane)(l).Datagram(nil, seq, buf[:16], nil); err != nil {
				panic(err)
			}
			read()
		}); a != 0 {
			t.Fatalf("%v allocations per accepted datagram, want 0", a)
		}
	}
	dpEnd(s, io.EOF)
}

// TestPacketEOFAfterQueued_L40: io.EOF comes only after every datagram the
// peer sent before its FIN — also when the FIN overtakes the last datagram
// (reordering) — with the reader running concurrently (1000 rounds; each
// round a fresh pair in a bubble, so the straggler bound never fires).
func TestPacketEOFAfterQueued_L40(t *testing.T) {
	for i := range 1000 {
		synctest.Test(t, func(t *testing.T) {
			p := dpNewPair(dpOpt{}, dpOpt{}, true)
			for k := range 3 {
				dpWrite(t, p.a.s, uint64(k), 100)
			}
			dpClose(p.a.s)
			b := dpFill(p.a.ls[0], time.Now())
			var order []int
			fin := -1
			for k := range b.Len() {
				if b.Frame(k).Header.Type == wire.TypeFin {
					fin = k
					continue
				}
				order = append(order, k)
			}
			if fin < 0 || dpCount(dpFrames(b), wire.TypeDgram) != 3 {
				t.Fatalf("the closer's batch %v lacks the 3 datagrams and the FIN", dpFrames(b))
			}
			if i%2 == 1 {
				order = append(order[:len(order)-1], fin, order[len(order)-1]) // the FIN overtakes the last DGRAM
			} else {
				order = append(order, fin)
			}
			var got []uint64
			var rerr error
			var wg sync.WaitGroup
			wg.Go(func() {
				buf := make([]byte, 256)
				for {
					n, err := p.b.s.ReadFrom(buf)
					if err != nil {
						rerr = err
						return
					}
					got = append(got, dpID(buf[:n]))
				}
			})
			for _, k := range order {
				if err := dpDeliverFrame(p.b.ls[0], b.Frame(k)); err != nil {
					t.Fatal(err)
				}
			}
			b.ReleaseRefs()
			wg.Wait()
			if rerr != io.EOF || len(got) != 3 || got[0] != 0 || got[1] != 1 || got[2] != 2 {
				t.Fatalf("round %d: read %v then %v; want [0 1 2] then io.EOF", i, got, rerr)
			}
		})
	}
}

// TestPacketFinWaitBound_L40: with a datagram lost for good the peer's FIN
// is delivered after clamp(2·max srtt, 50 ms, FinWaitMax) (M2-D40): a
// waiting ReadFrom returns io.EOF exactly then, never waits forever.
func TestPacketFinWaitBound_L40(t *testing.T) {
	for _, tc := range []struct {
		srtt, want time.Duration
	}{{0, 50 * time.Millisecond}, {200 * time.Millisecond, 400 * time.Millisecond}, {2 * time.Second, time.Second}} {
		synctest.Test(t, func(t *testing.T) {
			s := dpSession(dpOpt{role: RolePassive, finWaitMax: time.Second})
			l, fp := dpAddLane(s, 1, true, true)
			fp.set(func(f *dpPort) { f.srtt = tc.srtt })
			for _, seq := range []uint64{0, 2} { // seq 1 is lost for good
				if err := dpDatagram(l, seq, dpPayload(seq, 32)); err != nil {
					t.Fatal(err)
				}
			}
			if got, err := dpReadAll(t, s); err != nil || len(got) != 2 {
				t.Fatalf("read %d, %v", len(got), err)
			}
			start := time.Now()
			if err := dpSendFin(l, 3); err != nil {
				t.Fatal(err)
			}
			var rerr error
			var took time.Duration
			done := false
			go func() {
				_, rerr = s.ReadFrom(make([]byte, 64))
				took, done = time.Since(start), true
			}()
			// The actor's pk.finWaitAt deadline (WP6b) runs the check.
			at := dpLocked(s, func(_ *stream, pk *packet) time.Time { return pk.finWaitAt })
			go func() {
				time.Sleep(time.Until(at))
				s.mu.Lock()
				s.pktPeerFinCheckLocked(time.Now())
				s.mu.Unlock()
			}()
			time.Sleep(5 * time.Second)
			synctest.Wait()
			if !done {
				dpEnd(s, io.EOF)
				t.Fatalf("srtt %v: ReadFrom still waits for the lost datagram after 5 s", tc.srtt)
			}
			if rerr != io.EOF || took != tc.want {
				t.Fatalf("srtt %v: ReadFrom = %v after %v; want io.EOF after %v", tc.srtt, rerr, took, tc.want)
			}
			dpEnd(s, io.EOF)
		})
	}
}

// TestPacketEOFFinal_L40: nothing is returned after io.EOF (R1-12): a
// straggler below the final seq that arrives after the FIN was delivered
// counts DropLate, is not received, and ReadFrom keeps returning io.EOF.
func TestPacketEOFFinal_L40(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := dpSession(dpOpt{role: RolePassive})
		l, _ := dpAddLane(s, 1, true, true)
		for _, seq := range []uint64{0, 2} {
			_ = dpDatagram(l, seq, dpPayload(seq, 32))
		}
		if err := dpSendFin(l, 3); err != nil {
			t.Fatal(err)
		}
		time.Sleep(60 * time.Millisecond) // past the 50-ms straggler bound
		s.mu.Lock()
		s.pktPeerFinCheckLocked(time.Now()) // the actor's deadline; the queue is not empty yet
		s.mu.Unlock()
		if got := dpReadEOF(t, s); len(got) != 2 {
			t.Fatalf("read %d datagrams before io.EOF, want 2", len(got))
		}
		if err := dpDatagram(l, 1, dpPayload(1, 32)); err != nil {
			t.Fatalf("a straggler after io.EOF: %v, want a silent drop", err)
		}
		if c := dpCtr(s); c.DropLate != 1 || c.Received != 2 {
			t.Fatalf("counters %+v; want DropLate 1, Received 2", c)
		}
		for range 2 {
			if n, err := s.ReadFrom(make([]byte, 64)); n != 0 || err != io.EOF {
				t.Fatalf("ReadFrom after io.EOF = %d, %v", n, err)
			}
		}
		dpEnd(s, io.EOF)
	})
}

// TestPacketFinConflict_L13: the peer's FIN is checked against what was
// received (violations of the delivering carrier): another final seq than
// an earlier FIN's, a final seq at or below an accepted datagram or below
// FirstSeq, one beyond the offset limit; a DGRAM at or beyond the final
// seq or the offset limit. A repeated FIN after delivery is answered again.
func TestPacketFinConflict_L13(t *testing.T) {
	s := dpSession(dpOpt{role: RolePassive})
	l, _ := dpAddLane(s, 1, true, true)
	for seq := range uint64(5) {
		_ = dpDatagram(l, seq, nil)
	}
	if err := dpSendFin(l, 4); err != errFinBelowData {
		t.Fatalf("FIN at an accepted seq: %v", err)
	}
	if err := dpSendFin(l, 5); err != nil {
		t.Fatal(err)
	}
	if err := dpSendFin(l, 6); err != errFinConflict {
		t.Fatalf("a second FIN with another final seq: %v", err)
	}
	if err := dpSendFin(l, 5); err != nil {
		t.Fatalf("a repeated FIN: %v", err)
	}
	for _, seq := range []uint64{5, 7} {
		if err := dpDatagram(l, seq, nil); err != errDgramBeyondFin {
			t.Fatalf("DGRAM seq %d beyond the FIN: %v", seq, err)
		}
	}
	if got := dpReadEOF(t, s); len(got) != 5 {
		t.Fatalf("read %d before io.EOF", len(got))
	}
	gen := dpLocked(s, func(st *stream, _ *packet) uint64 { return st.ackGen })
	if err := dpSendFin(l, 5); err != nil {
		t.Fatal(err)
	}
	if dpLocked(s, func(st *stream, _ *packet) uint64 { return st.ackGen }) == gen {
		t.Fatal("a FIN repeated after delivery was not answered (no PACK bump)")
	}
	if c := dpCtr(s); c.Received != 5 {
		t.Fatalf("counters %+v", c)
	}

	const limit = 1 << 40
	u := dpSession(dpOpt{role: RolePassive, firstSeq: 100, limit: limit})
	ul, _ := dpAddLane(u, 1, true, true)
	if err := dpDatagram(ul, limit, nil); err != errDgramBeyondLimit {
		t.Fatalf("DGRAM at the offset limit: %v", err)
	}
	if err := dpDatagram(ul, limit-1, nil); err != nil {
		t.Fatalf("DGRAM below the offset limit: %v", err)
	}
	if got, _ := dpReadAll(t, u); len(got) != 1 {
		t.Fatal("the last legal seq was not received")
	}
	v := dpSession(dpOpt{role: RolePassive, firstSeq: 100, limit: limit})
	vl, _ := dpAddLane(v, 1, true, true)
	if err := dpSendFin(vl, 99); err != errFinBelowData {
		t.Fatalf("FIN below FirstSeq: %v", err)
	}
	if err := dpSendFin(vl, limit+1); err != errFinBeyondWindow {
		t.Fatalf("FIN beyond the offset limit: %v", err)
	}
	if err := dpSendFin(vl, 100); err != nil {
		t.Fatal(err)
	}
	if got := dpReadEOF(t, v); len(got) != 0 {
		t.Fatal("a FIN at FirstSeq: nothing was sent, io.EOF at once")
	}
	for _, x := range []*Session{s, u, v} {
		dpEnd(x, io.EOF)
	}
}
