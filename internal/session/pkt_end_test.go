package session

import (
	"io"
	"net"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// dpDone reports doneSent and peerDone of s.
func dpDone(s *Session) [2]bool {
	return dpLocked(s, func(st *stream, _ *packet) [2]bool { return [2]bool{st.doneSent, st.peerDone} })
}

// TestPacketAutoFin: the peer's FIN closes both directions (PA-6): the
// receiver's queued datagrams are dropped (DropQueue), WriteTo fails with
// net.ErrClosed, its own FIN follows at once, it reads what arrived and
// then io.EOF, and the DONE exchange ends both sides with io.EOF without
// waiting for Linger.
func TestPacketAutoFin(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := dpNewPair(dpOpt{}, dpOpt{}, true)
		dpWrite(t, p.a.s, 0, 100)
		dpWrite(t, p.a.s, 1, 100)
		for i := range 3 {
			dpWrite(t, p.b.s, uint64(10+i), 100) // never placed: the peer closes first
		}
		dpClose(p.a.s)
		if _, err := dpPump(&p.a, &p.b, nil); err != nil {
			t.Fatal(err)
		}
		req := dpLocked(p.b.s, func(st *stream, _ *packet) bool { return st.fin.requested && st.peerFinSet })
		if !req {
			t.Fatal("the peer's FIN did not request our FIN")
		}
		if _, err := p.b.s.WriteTo([]byte("x")); err != net.ErrClosed {
			t.Fatalf("WriteTo after the peer's FIN: %v, want net.ErrClosed", err)
		}
		if c := dpCtr(p.b.s); c.DropQueue != 3 || c.Sent != 0 {
			t.Fatalf("receiver counters %+v; want its 3 queued datagrams dropped", c)
		}
		if got := dpReadEOF(t, p.b.s); len(got) != 2 {
			t.Fatalf("read %d datagrams before io.EOF, want 2", len(got))
		}
		dpSettle(t, p, nil)
		if d := dpDone(p.a.s); d != [2]bool{true, true} {
			t.Fatalf("closer doneSent/peerDone %v", d)
		}
		if d := dpDone(p.b.s); d != [2]bool{true, true} {
			t.Fatalf("receiver doneSent/peerDone %v", d)
		}
		for _, s := range []*Session{p.a.s, p.b.s} {
			if err, rst := dpTerm(s, time.Now()); err != io.EOF || rst != nil {
				t.Fatalf("end %v, RST %+v; want io.EOF without RST", err, rst)
			}
		}
		if _, err := p.a.s.ReadFrom(make([]byte, 8)); err != net.ErrClosed {
			t.Fatalf("the closer's ReadFrom: %v", err)
		}
	})
}

// TestPacketEndLastAckLoss_L12: the packet end is M1's DONE exchange
// (M2-D40, §0.2 flaw 2). The closer may learn that its FIN was delivered
// before it receives the peer's FIN, or after; when the final PACK (the
// second DONE) is lost, the side that misses it still ends with io.EOF
// after Linger and the other at once. A FIN lost with its lane is placed
// again on the surviving lane, and the end still completes.
func TestPacketEndLastAckLoss_L12(t *testing.T) {
	const linger = 2 * time.Second
	for _, tc := range []struct {
		name     string
		packLast bool // the receiver's PACK(FIN_DELIVERED) reaches the closer after its FIN
		lose     int  // whose DONE is lost: 0 the closer's, 1 the receiver's
	}{
		{"pack-before-fin/closer-done-lost", false, 0},
		{"pack-before-fin/receiver-done-lost", false, 1},
		{"fin-before-pack/closer-done-lost", true, 0},
		{"fin-before-pack/receiver-done-lost", true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p := dpNewPair(dpOpt{linger: linger}, dpOpt{linger: linger}, true)
				dpWrite(t, p.a.s, 0, 100)
				dpClose(p.a.s)
				if _, err := dpPump(&p.a, &p.b, nil); err != nil {
					t.Fatal(err)
				}
				if got := dpReadEOF(t, p.b.s); len(got) != 1 {
					t.Fatalf("the receiver read %d before io.EOF", len(got))
				}
				// The receiver's batch: PACK(FIN_DELIVERED) and its FIN.
				b := dpFill(p.b.ls[0], time.Now())
				var pack, fin = -1, -1
				for i := range b.Len() {
					switch f := b.Frame(i); f.Header.Type {
					case wire.TypePack:
						if f.Header.Flags&wire.FlagPackFinDelivered != 0 {
							pack = i
						}
					case wire.TypeFin:
						fin = i
					}
				}
				if pack < 0 || fin < 0 {
					t.Fatalf("the receiver's batch %v lacks PACK(FIN_DELIVERED) or FIN", dpFrames(b))
				}
				order := []int{pack, fin}
				if tc.packLast {
					order = []int{fin, pack}
				}
				for _, i := range order {
					if err := dpDeliverFrame(p.a.ls[0], b.Frame(i)); err != nil {
						t.Fatal(err)
					}
				}
				b.ReleaseRefs()
				lost := []*Session{p.a.s, p.b.s}[tc.lose]
				// Every PACK carrying the DONE of the side named lost is
				// dropped: its peer never learns it.
				drop := func(_ int, f carrier.BatchFrame) bool {
					return f.Header.Type == wire.TypePack && f.Header.Flags&wire.FlagPackDone != 0
				}
				dropFrom := func(side *dpSide) dpDrop {
					if side.s != lost {
						return nil
					}
					return drop
				}
				for range 20 {
					if _, err := dpPump(&p.a, &p.b, dropFrom(&p.a)); err != nil {
						t.Fatal(err)
					}
					if _, err := dpPump(&p.b, &p.a, dropFrom(&p.b)); err != nil {
						t.Fatal(err)
					}
				}
				other := []*Session{p.b.s, p.a.s}[tc.lose]
				if d := dpDone(lost); d != [2]bool{true, true} {
					t.Fatalf("the side whose DONE was lost: doneSent/peerDone %v", d)
				}
				if d := dpDone(other); d != [2]bool{true, false} {
					t.Fatalf("the side that missed the final PACK: doneSent/peerDone %v", d)
				}
				if err, _ := dpTerm(lost, time.Now()); err != io.EOF {
					t.Fatalf("DONE both ways: %v, want io.EOF", err)
				}
				if err, _ := dpTerm(other, time.Now()); err != nil {
					t.Fatalf("ended before Linger: %v", err)
				}
				time.Sleep(linger)
				if err, rst := dpTerm(other, time.Now()); err != io.EOF || rst != nil {
					t.Fatalf("after Linger: %v, RST %+v; want io.EOF without RST", err, rst)
				}
			})
		})
	}

	t.Run("fin-lost-with-its-lane", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			p := dpNewPair(dpOpt{linger: linger}, dpOpt{linger: linger}, true, true)
			dpWrite(t, p.a.s, 0, 100)
			dpClose(p.a.s)
			b := dpFill(p.a.ls[0], time.Now())
			if dpCount(dpFrames(b), wire.TypeFin) != 1 {
				t.Fatalf("the closer's first batch %v lacks its FIN", dpFrames(b))
			}
			b.ReleaseRefs() // lost with the lane
			for _, sd := range []*dpSide{&p.a, &p.b} {
				dpKill(sd.s, sd.ls[0])
				dpRoute(sd.s, sd.ls[1], true)
			}
			dpSettle(t, p, nil)
			// The datagram was lost with the lane: the receiver's FIN
			// waits for the straggler bound (the actor's deadline).
			time.Sleep(time.Until(dpLocked(p.b.s, func(_ *stream, pk *packet) time.Time { return pk.finWaitAt })))
			p.b.s.mu.Lock()
			p.b.s.pktPeerFinCheckLocked(time.Now())
			p.b.s.mu.Unlock()
			dpSettle(t, p, nil)
			if got, err := dpReadAll(t, p.b.s); err != io.EOF || len(got) != 0 {
				t.Fatalf("receiver: %d datagrams, %v; want io.EOF (the datagram was lost with the lane)", len(got), err)
			}
			for _, s := range []*Session{p.a.s, p.b.s} {
				if err, rst := dpTerm(s, time.Now()); err != io.EOF || rst != nil {
					t.Fatalf("end %v, RST %+v; want io.EOF", err, rst)
				}
			}
		})
	})
}

// TestPacketIdleTimeout_L19: a packet session's idle clock (M2-D41) moves
// on an accepted WriteTo, an accepted DGRAM and a datagram returned by
// ReadFrom — and on nothing else: not a received PACK, a duplicate or a
// refused WriteTo. IdleTimeout then ends the session with RST(Idle).
func TestPacketIdleTimeout_L19(t *testing.T) {
	const idle = 10 * time.Second
	expect := func(t *testing.T, s *Session, t0 time.Time, at time.Duration) {
		t.Helper()
		time.Sleep(time.Until(t0.Add(at - time.Millisecond)))
		if err, _ := dpTerm(s, time.Now()); err != nil {
			t.Fatalf("ended at %v: %v", time.Since(t0), err)
		}
		time.Sleep(time.Millisecond)
		err, rst := dpTerm(s, time.Now())
		if err != ErrIdleTimeout || rst == nil || rst.Code != wire.RstIdle {
			t.Fatalf("at %v: %v, RST %+v; want ErrIdleTimeout and RST(Idle)", time.Since(t0), err, rst)
		}
	}
	t.Run("writeto", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			t0 := time.Now()
			s := dpSession(dpOpt{idle: idle})
			time.Sleep(9 * time.Second)
			dpWrite(t, s, 0, 10)
			expect(t, s, t0, 19*time.Second)
		})
	})
	t.Run("datagram", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			t0 := time.Now()
			s := dpSession(dpOpt{role: RolePassive, idle: idle})
			l, _ := dpAddLane(s, 1, true, true)
			time.Sleep(9 * time.Second)
			_ = dpDatagram(l, 0, []byte("x"))
			expect(t, s, t0, 19*time.Second)
		})
	})
	t.Run("readfrom", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			t0 := time.Now()
			s := dpSession(dpOpt{role: RolePassive, idle: idle})
			l, _ := dpAddLane(s, 1, true, true)
			_ = dpDatagram(l, 0, []byte("x"))
			time.Sleep(9 * time.Second)
			if _, err := s.ReadFrom(make([]byte, 8)); err != nil {
				t.Fatal(err)
			}
			expect(t, s, t0, 19*time.Second)
		})
	})
	t.Run("nothing-else", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			t0 := time.Now()
			s := dpSession(dpOpt{role: RolePassive, idle: idle, maxPayload: 100})
			l, _ := dpAddLane(s, 1, true, true)
			_ = dpDatagram(l, 0, []byte("x"))
			time.Sleep(5 * time.Second)
			_ = dpDatagram(l, 0, []byte("x")) // a duplicate
			_ = dpSendPack(l, 0, wire.Pack{})
			if _, err := s.WriteTo(make([]byte, 101)); err != ErrPacketTooLarge {
				t.Fatal(err)
			}
			_ = s.SetWriteDeadline(time.Now().Add(-time.Second))
			if _, err := s.WriteTo([]byte("x")); err != os.ErrDeadlineExceeded {
				t.Fatal(err)
			}
			if c := dpCtr(s); c.Duplicates != 1 {
				t.Fatalf("stimulus: %+v", c)
			}
			expect(t, s, t0, idle)
		})
	})
}
