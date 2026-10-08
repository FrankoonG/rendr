package carrier

import (
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Datagram carrier I/O tests: counts, sizes, corruption, violations, the
// peer's CLOSE, the REL timer, retirement, joins (M2 design §A5.7, §A5.8,
// §A5.10 retirement, §A5.11 budget shrink; §A8.2 WP3a rows).

// dgramFrame is a DGRAM rawFrame of n bytes for session seq seq.
func dgramFrame(seq uint64, n int) rawFrame {
	p := make([]byte, wire.DgramPrefixLen+n)
	wire.PutDgramSeq(p, seq)
	for i := range n {
		p[wire.DgramPrefixLen+i] = byte(i)
	}
	return rawFrame{t: wire.TypeDgram, handle: wire.SessionHandle, payload: p}
}

// dgramFill returns a Fill that places one DGRAM of *size bytes per call
// while *want > 0.
func dgramFill(want *atomic.Int32, size *atomic.Int32) func(c *Conn, b *Batch) {
	var seq uint64
	body := make([]byte, wire.MaxPacketPayload)
	return func(c *Conn, b *Batch) {
		if want.Load() <= 0 {
			return
		}
		if b.AddDgram(wire.SessionHandle, seq, body[:size.Load()], nil) {
			seq++
			want.Add(-1)
		}
	}
}

// TestDatagramWriteCount_L42: a datagram write that fails other than by
// noise or a size refusal — the embedder adapter reports an invalid count
// as such an error — ends the carrier (transport_error) and is never
// retried on it (L42, PA-19); another carrier is unaffected.
func TestDatagramWriteCount_L42(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  func(n int) error
	}{
		{"len-3", func(n int) error { return &countError{"WriteTo", n - 3, n} }},
		{"zero", func(n int) error { return &countError{"WriteTo", 0, n} }},
		{"-1", func(n int) error { return &countError{"WriteTo", -1, n} }},
		{"len+1", func(n int) error { return &countError{"WriteTo", n + 1, n} }},
		{"error", func(int) error { return errNotNoise }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a, b := dgPair(t, 1200)
				a.io.setOut(func(d []byte) error { return tc.err(len(d)) })
				a.start(StartOptions{})
				b.start(StartOptions{})
				hWait(t, a.c)
				if _, cause, detail, _ := a.c.Death(); cause != CauseTransportError || !strings.Contains(detail, "write:") {
					t.Fatalf("cause %v %q, want transport_error on the write", cause, detail)
				}
				if n := a.io.nwrites.Load(); n != 1 {
					t.Fatalf("%d writes, want the failed one only (never retried)", n)
				}
				// A second carrier over a sound transport completes its exchange.
				c, d := dgPair(t, 1200)
				var want atomic.Int32
				var next atomic.Uint64
				want.Store(1)
				c.ep.setFill(finFill(&want, &next))
				c.start(StartOptions{})
				d.start(StartOptions{})
				synctest.Wait()
				if len(finOffsets(d.ep)) != 1 || c.c.RelRoom() != wire.RelWindow {
					t.Fatal("the second carrier did not complete")
				}
			})
		})
	}
}

// TestDatagramReadCount_L42: a read error — an invalid count the adapter
// reports, a closed conn — ends the carrier; a truncated or empty datagram
// is dropped and counted, never a death (PA-18); and a transport that hands
// over nothing forever never makes the reader spin: every 64 such reads
// pause 1 ms — fixed, not doubling, so a real burst is still read fast
// (R1-27 and M2-D86 as amended by WP12).
func TestDatagramReadCount_L42(t *testing.T) {
	t.Run("invalid count", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, _ := rawPair(t, 1200, true)
			s.start(StartOptions{})
			s.io.injectEvent(ReadOK, &countError{"ReadFrom", -1, 1201})
			hWait(t, s.c)
			if _, cause, detail, _ := s.c.Death(); cause != CauseTransportError || !strings.Contains(detail, "invalid count") {
				t.Fatalf("cause %v %q, want transport_error", cause, detail)
			}
		})
	})
	t.Run("truncated and empty", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, p := rawPair(t, 1200, true)
			s.start(StartOptions{})
			synctest.Wait()
			p.read()
			p.io.WriteDatagram(make([]byte, 1201)) // one byte over the receive limit
			s.io.injectEvent(ReadEmpty, nil)
			p.send(pingFrame(wire.TypePing, wire.Ping{ID: 77, Nonce: 5}))
			synctest.Wait()
			st := s.c.Stats()
			if dead, cause, detail, _ := s.c.Death(); dead {
				t.Fatalf("carrier died: %v %q", cause, detail)
			}
			if st.Truncated != 1 || st.Dropped != 2 || s.env.Dgram.Truncated.Load() != 1 || s.env.Dgram.Dropped.Load() != 2 {
				t.Fatalf("truncated %d dropped %d (Runtime %d/%d), want 1 and 2", st.Truncated, st.Dropped, s.env.Dgram.Truncated.Load(), s.env.Dgram.Dropped.Load())
			}
			var pong bool
			for _, d := range p.read() {
				for _, pg := range pingsOf(d, true) {
					pong = pong || pg.ID == 77
				}
			}
			if !pong {
				t.Fatal("the PING after the drops was not answered")
			}
		})
	})
	t.Run("endless empties", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, _ := rawPair(t, 1200, true)
			s.io.mu.Lock()
			s.io.endless = ReadEmpty
			s.io.mu.Unlock()
			s.start(StartOptions{})
			time.Sleep(500 * time.Millisecond)
			n1 := s.io.nreads.Load()
			time.Sleep(time.Second)
			n2 := s.io.nreads.Load()
			if dead, cause, detail, _ := s.c.Death(); dead {
				t.Fatalf("carrier died: %v %q", cause, detail)
			}
			const perSecond = spinIdle * int64(time.Second/spinPause)
			if r := n2 - n1; r < perSecond-spinIdle || r > perSecond+2*spinIdle {
				t.Fatalf("%d reads in 1 s, want about %d (%d per %v: neither a spin nor a doubling back-off)", r, perSecond, spinIdle, spinPause)
			}
		})
	})
	t.Run("a handed-over datagram resets the guard", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, p := rawPair(t, 1200, true)
			s.start(StartOptions{})
			synctest.Wait()
			p.read()
			for k := range uint32(3) {
				for range spinIdle - 1 {
					s.io.injectEvent(ReadForeign, nil)
				}
				p.send(pingFrame(wire.TypePing, wire.Ping{ID: 100 + k, Nonce: 1}))
			}
			synctest.Wait() // no virtual time passes: a back-off would leave reads pending
			s.io.mu.Lock()
			left := s.io.n
			s.io.mu.Unlock()
			last := false // the PONG slot is latest-wins: the last PING is answered
			for _, d := range p.read() {
				for _, pg := range pingsOf(d, true) {
					last = last || pg.ID == 102
				}
			}
			if dropped := s.c.Stats().Dropped; left != 0 || !last || dropped != 3*(spinIdle-1) {
				t.Fatalf("%d reads pending, PONG of the last PING %v, dropped %d; want none pending (no back-off)", left, last, dropped)
			}
		})
	})
	t.Run("a transport answering after Close", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, _ := rawPair(t, 1200, true)
			s.io.mu.Lock()
			s.io.endless, s.io.zombie = ReadEmpty, true
			s.io.mu.Unlock()
			s.start(StartOptions{})
			time.Sleep(time.Second)
			n1 := s.io.nreads.Load()
			s.c.Kill(CauseLocalClose, "test")
			hWait(t, s.c)
			time.Sleep(time.Second)
			if n := s.io.nreads.Load() - n1; n > spinIdle {
				t.Fatalf("%d reads after the death, want the reader gone at its next back-off", n)
			}
			if s.env.Abandon.Len() != 0 {
				t.Fatal("the reader was abandoned")
			}
		})
	})
}

// TestDatagramTooLargeShrinks_L37_L01: a size refusal loses that datagram
// only (its DGRAM counted Refused); DatagramTooLargeError{Max} with 0 < Max
// < budget lowers the budget, which is never raised again; Max 0 lowers
// nothing; a budget below wire.ControlFloor kills (transport_error)
// (M2-D25; lessons:629 "容量下降不算承载死亡").
func TestDatagramTooLargeShrinks_L37_L01(t *testing.T) {
	for _, tc := range []struct {
		name    string
		max     int
		wantMTU int
		dies    bool
	}{
		{"shrink", 800, 800, false},
		{"max 0", 0, 1200, false},
		{"below the floor", 250, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a, b := dgPair(t, 1200)
				a.io.setOut(func(d []byte) error {
					if len(d) > 800 {
						return &wire.DatagramTooLargeError{Max: tc.max}
					}
					return nil
				})
				var want, size atomic.Int32
				want.Store(1)
				size.Store(1000)
				a.ep.setFill(dgramFill(&want, &size))
				a.start(StartOptions{})
				b.start(StartOptions{})
				synctest.Wait()
				if tc.dies {
					hWait(t, a.c)
					if _, cause, detail, _ := a.c.Death(); cause != CauseTransportError || !strings.Contains(detail, "control floor") {
						t.Fatalf("cause %v %q, want transport_error below the control floor", cause, detail)
					}
					return
				}
				if dead, cause, detail, _ := a.c.Death(); dead {
					t.Fatalf("carrier died: %v %q", cause, detail)
				}
				st := a.c.Stats()
				if st.MTU != tc.wantMTU || a.c.MTU() != tc.wantMTU || st.Refused != 1 || a.c.DgramMax() != tc.wantMTU-wire.DgramOverhead {
					t.Fatalf("MTU %d (%d), refused %d, DgramMax %d; want MTU %d, refused 1", st.MTU, a.c.MTU(), st.Refused, a.c.DgramMax(), tc.wantMTU)
				}
				size.Store(500)
				want.Store(5)
				a.c.Wake()
				time.Sleep(time.Second)
				synctest.Wait()
				if got := len(b.ep.datagrams()); got != 5 || a.c.MTU() != tc.wantMTU {
					t.Fatalf("%d datagrams delivered after the refusal, MTU %d; want 5 and %d (never raised)", got, a.c.MTU(), tc.wantMTU)
				}
			})
		})
	}
}

// TestDatagramCorruptDropped_L43: on a datagram carrier a frame that fails
// to decode (a CRC error, garbage) drops the rest of its datagram and is
// counted; the frames before it stay processed and the carrier lives
// (PA-1, M2-D14).
func TestDatagramCorruptDropped_L43(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p := rawPair(t, 1200, true)
		s.start(StartOptions{})
		synctest.Wait()
		p.read()
		d := p.datagram(
			pingFrame(wire.TypePing, wire.Ping{ID: 10, Nonce: 1}),
			pingFrame(wire.TypePing, wire.Ping{ID: 11, Nonce: 1}),
			pingFrame(wire.TypePing, wire.Ping{ID: 12, Nonce: 1}),
		)
		one := wire.FrameOverhead + wire.PingFixedLen
		d[one+wire.HeaderLen+5] ^= 0xff // the second PING's payload: a CRC error
		_ = p.io.WriteDatagram(d)
		synctest.Wait()
		_ = p.io.WriteDatagram([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e})
		synctest.Wait()
		p.send(pingFrame(wire.TypePing, wire.Ping{ID: 13, Nonce: 1}))
		synctest.Wait()
		if dead, cause, detail, _ := s.c.Death(); dead {
			t.Fatalf("carrier died: %v %q", cause, detail)
		}
		pongs := map[uint32]bool{}
		for _, d := range p.read() {
			for _, pg := range pingsOf(d, true) {
				pongs[pg.ID] = true
			}
		}
		if !pongs[10] || !pongs[13] || pongs[11] || pongs[12] {
			t.Fatalf("PONGs %v, want 10 and 13 only", pongs)
		}
		if st := s.c.Stats(); st.Dropped != 2 {
			t.Fatalf("dropped %d, want 2", st.Dropped)
		}
	})
}

// TestDatagramSemanticViolationKills_L43: a CRC-valid, in-window frame that
// breaks the protocol kills the carrier (protocol_violation; PA-1 drops
// only damage): a bare reliable frame, DATA, a PING with non-zero padding,
// a wrapped handshake frame, a malformed REL, a DGRAM to a stream session.
func TestDatagramSemanticViolationKills_L43(t *testing.T) {
	joinAck := make([]byte, wire.JoinAckLen)
	data := make([]byte, wire.DataPrefixLen+4)
	pad := make([]byte, wire.PingFixedLen+4)
	pad[len(pad)-1] = 1
	shortFin := relPayloadOf(1, wire.TypeFin, 0, wire.SessionHandle, make([]byte, wire.FinLen-1))
	for _, tc := range []struct {
		name   string
		f      rawFrame
		stream bool
		detail string
	}{
		{"bare FIN", rawFrame{t: wire.TypeFin, handle: wire.SessionHandle, payload: finInner(0)}, false, "bare FIN"},
		{"bare CLOSE", rawFrame{t: wire.TypeClose, payload: []byte{byte(wire.CloseRetire)}}, false, "bare CLOSE"},
		{"DATA", rawFrame{t: wire.TypeData, handle: wire.SessionHandle, payload: data}, false, "bare DATA"},
		{"PING pad", rawFrame{t: wire.TypePing, payload: pad}, false, "PING"},
		{"REL JOIN_ACK", relFrame(1, wire.TypeJoinAck, 0, wire.SessionHandle, joinAck), false, "after the handshake"},
		{"REL short FIN", rawFrame{t: wire.TypeRel, payload: shortFin}, false, "REL"},
		{"DGRAM to a stream session", dgramFrame(1, 10), true, "DGRAM on a stream session"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s, p := rawPair(t, 1200, true)
				if tc.stream {
					s.c.Start(&hEP{}, s.bell, StartOptions{})
				} else {
					s.start(StartOptions{})
				}
				synctest.Wait()
				p.send(tc.f)
				hWait(t, s.c)
				if _, cause, detail, _ := s.c.Death(); cause != CauseProtocolViolation || !strings.Contains(detail, tc.detail) {
					t.Fatalf("cause %v %q, want protocol_violation %q", cause, detail, tc.detail)
				}
			})
		})
	}
}

// TestDatagramAfterPeerClose: once the peer's CLOSE was dispatched, frames
// with a later fseq are dropped and counted unless they are a RACK or a REL
// duplicate (re-RACKed); a new REL behind the CLOSE is dropped and counted,
// never dispatched; earlier fseqs (reordered) are still processed (M2-D30),
// and the retirement completes after the CLOSE exchange (R1-4).
func TestDatagramAfterPeerClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p := rawPair(t, 1200, false)
		s.start(StartOptions{})
		synctest.Wait()
		p.read()
		first := s.env.Presets.firstCseq()
		reserved := p.fseq // an fseq before the CLOSE's, sent after it
		p.fseq++
		closeF := relFrame(first, wire.TypeClose, 0, 0, []byte{byte(wire.CloseRetire)})
		p.send(closeF)
		synctest.Wait()
		if !s.c.PeerClosed() {
			t.Fatal("the peer's CLOSE was not dispatched")
		}
		if r, ok := s.c.PeerCloseReason(); !ok || r != wire.CloseRetire {
			t.Fatalf("PeerCloseReason %v %v", r, ok)
		}
		dropped := s.c.Stats().Dropped
		p.send(pingFrame(wire.TypePing, wire.Ping{ID: 50, Nonce: 1}))
		p.send(dgramFrame(1, 10))
		synctest.Wait()
		if got := s.c.Stats().Dropped - dropped; got != 2 {
			t.Fatalf("%d frames dropped after the CLOSE, want 2", got)
		}
		dropped = s.c.Stats().Dropped
		rst := make([]byte, wire.RstFixedLen)
		wire.PutRst(rst, &wire.Rst{Code: 1})
		p.send(relFrame(first+1, wire.TypeRst, 0, wire.SessionHandle, rst))
		synctest.Wait()
		if got := s.c.Stats().Dropped - dropped; got != 1 {
			t.Fatalf("a new REL after the CLOSE: %d dropped, want 1", got)
		}
		for _, h := range s.ep.controls() {
			if h.Type == wire.TypeRst {
				t.Fatal("a new REL{RST} after the peer's CLOSE was dispatched")
			}
		}
		late := p.fseq
		p.fseq = reserved
		p.send(pingFrame(wire.TypePing, wire.Ping{ID: 60, Nonce: 1})) // reordered: before the CLOSE
		p.fseq = late
		p.send(closeF) // a duplicate REL: RACKed again
		synctest.Wait()
		s.c.Retire(wire.CloseRetire) // the owner's answer to the bell
		synctest.Wait()
		var ourClose bool
		pongs := map[uint32]bool{}
		racks := 0
		for _, d := range p.read() {
			for _, pg := range pingsOf(d, true) {
				pongs[pg.ID] = true
			}
			for _, r := range racksOf(d) {
				if r.CumAck == first {
					racks++
				}
			}
			for _, h := range relsOf(d) {
				ourClose = ourClose || h.Type == wire.TypeClose
			}
		}
		if pongs[50] || !pongs[60] || racks < 2 || !ourClose || len(s.ep.datagrams()) != 0 {
			t.Fatalf("PONGs %v, RACKs of the CLOSE %d, our CLOSE %v, datagrams %d", pongs, racks, ourClose, len(s.ep.datagrams()))
		}
		if dead, _, _, _ := s.c.Death(); dead {
			t.Fatal("retired before our CLOSE was RACKed")
		}
		p.send(rackFrame(first, 0)) // a RACK after the CLOSE: processed
		hWait(t, s.c)
		if _, cause, detail, _ := s.c.Death(); cause != CauseRetired {
			t.Fatalf("cause %v %q, want retired", cause, detail)
		}
	})
}

// TestRelArmedOnAttempt_L12: the REL timer is armed when the datagram
// carrying a new REL was attempted — refused as too large or lost to noise
// as well as written — so the REL is resent one RTO later; and a RACK that
// arrived before the writer's commit leaves nothing armed: no write and no
// wake for 5 s of idle (R1-2).
func TestRelArmedOnAttempt_L12(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"refused", &wire.DatagramTooLargeError{Max: 0}},
		{"noise", ErrNoise},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a, b := dgPair(t, 1200)
				var log retxLog
				a.env.Hooks = log.hooks()
				var failed atomic.Bool
				a.io.setOut(func(d []byte) error {
					if anyRel(d) && failed.CompareAndSwap(false, true) {
						return tc.err
					}
					return nil
				})
				var want atomic.Int32
				var next atomic.Uint64
				want.Store(1)
				a.ep.setFill(finFill(&want, &next))
				t0 := time.Now()
				// The peer stays silent at first, so no other write of a (a PONG)
				// can arm the timer: only the attempt of the REL's datagram does.
				b.io.setFilter(func([]byte) bool { return time.Since(t0) >= 200*time.Millisecond })
				a.start(StartOptions{})
				b.start(StartOptions{})
				time.Sleep(time.Second)
				synctest.Wait()
				at, _ := log.get()
				if !failed.Load() || len(at) != 1 || at[0].Sub(t0) != 300*time.Millisecond {
					t.Fatalf("failed %v, retransmissions at %v, want one at 300ms", failed.Load(), at)
				}
				if len(finOffsets(b.ep)) != 1 || a.c.RelRoom() != wire.RelWindow {
					t.Fatal("the REL was not delivered and RACKed")
				}
			})
		})
	}
	t.Run("RACK before the commit", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			a, b := dgPair(t, 1200)
			for _, s := range []*dgSide{a, b} {
				s.env.Timing.PingIdle = time.Minute
				s.c.tm = s.env.Timing.withDefaults()
			}
			var want atomic.Int32
			var next atomic.Uint64
			a.ep.setFill(finFill(&want, &next))
			a.start(StartOptions{})
			b.start(StartOptions{})
			time.Sleep(6 * time.Second)
			var raced atomic.Bool
			a.io.setPost(func(d []byte) {
				if !anyRel(d) {
					return
				}
				for range 100 { // hold the write until the RACK was processed
					a.c.mu.Lock()
					done := !a.c.dg.rel.outstanding()
					a.c.mu.Unlock()
					if done {
						raced.Store(true)
						return
					}
					time.Sleep(time.Millisecond)
				}
			})
			want.Store(1)
			a.c.Wake()
			time.Sleep(200 * time.Millisecond) // the hook polls in virtual time
			synctest.Wait()
			a.io.setPost(nil)
			if !raced.Load() {
				t.Fatal("the RACK did not arrive before the commit")
			}
			a.c.mu.Lock()
			due := a.c.dg.rel.due
			a.c.mu.Unlock()
			if !due.IsZero() {
				t.Fatalf("REL timer armed at %v with nothing outstanding", due)
			}
			wa, fa := a.io.nwrites.Load(), a.ep.fills.Load()
			time.Sleep(5 * time.Second)
			synctest.Wait()
			if a.io.nwrites.Load() != wa || a.ep.fills.Load() != fa {
				t.Fatalf("idle: %d writes, %d wakes", a.io.nwrites.Load()-wa, a.ep.fills.Load()-fa)
			}
		})
	})
}

// TestDatagramRetireBothRetired: on a lossless link both ends of a CLOSE
// exchange end with cause retired within 2·RTT plus one writer round: the
// retirement completes once our CLOSE was RACKed, the peer's CLOSE
// dispatched and the RACK covering it written (R1-4), never on the peer's
// CLOSE alone, which would leave the peer waiting for its bound.
func TestDatagramRetireBothRetired(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := dgPair(t, 1200)
		a.ep, b.ep = nil, nil // carriers without a session: a peer CLOSE is answered at once
		const oneWay = 10 * time.Millisecond
		a.io.setDelay(oneWay)
		b.io.setDelay(oneWay)
		a.start(StartOptions{})
		b.start(StartOptions{})
		time.Sleep(3 * time.Second) // RTT samples
		t1 := time.Now()
		a.c.Retire(wire.CloseRetire)
		hWait(t, a.c)
		hWait(t, b.c)
		for _, s := range []*dgSide{a, b} {
			_, cause, detail, at := s.c.Death()
			if cause != CauseRetired {
				t.Fatalf("cause %v %q, want retired", cause, detail)
			}
			if d := at.Sub(t1); d > 4*oneWay+time.Millisecond {
				t.Fatalf("%s retired %v after the CLOSE (%s), want ≤ 2·RTT (%v)", map[bool]string{true: "dialer", false: "passive"}[s == a], d, detail, 4*oneWay)
			}
			if n := s.io.closes.Load(); n != 1 {
				t.Fatalf("transport closed %d times, want 1", n)
			}
		}
	})
}

// TestDatagramPartsJoined_L52: a datagram carrier's reader, writer and
// closer are joined by Done and its PacketIO is closed exactly once; a
// reader stuck in a transport that ignores Close and deadlines is abandoned
// after AbandonWait and counted until its call returns.
func TestDatagramPartsJoined_L52(t *testing.T) {
	t.Run("joined", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			a, b := dgPair(t, 1200)
			a.start(StartOptions{})
			b.start(StartOptions{})
			synctest.Wait()
			a.c.Kill(CauseLocalClose, "test")
			hWait(t, a.c)
			if n := a.io.closes.Load(); n != 1 {
				t.Fatalf("closed %d times", n)
			}
			if a.env.Abandon.Len() != 0 {
				t.Fatal("a part was abandoned")
			}
		})
	})
	t.Run("stuck reader", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			a, b := dgPair(t, 1200)
			hang := make(chan struct{})
			a.io.hang = hang
			a.start(StartOptions{})
			b.start(StartOptions{})
			synctest.Wait()
			t0 := time.Now()
			a.c.Kill(CauseLocalClose, "test")
			hWait(t, a.c)
			if d := time.Since(t0); d != a.env.Timing.AbandonWait {
				t.Fatalf("Done after %v, want AbandonWait %v", d, a.env.Timing.AbandonWait)
			}
			if n := a.env.Abandon.Len(); n != 1 {
				t.Fatalf("%d abandoned, want the reader", n)
			}
			close(hang)
			synctest.Wait()
			if n := a.env.Abandon.Len(); n != 0 || a.io.closes.Load() != 1 {
				t.Fatalf("%d abandoned after the read returned, closes %d", n, a.io.closes.Load())
			}
		})
	})
}

// TestEmbedderClosedConnIsDeath_L01: an embedder that closes the conn its
// factory returned ends the carrier at once with transport_error (never
// noise, never an application error); rendr's own close afterwards is
// harmless.
func TestEmbedderClosedConnIsDeath_L01(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := dgPair(t, 1200)
		a.start(StartOptions{})
		b.start(StartOptions{})
		synctest.Wait()
		t0 := time.Now()
		_ = a.io.Close() // the embedder's close
		hWait(t, a.c)
		_, cause, detail, at := a.c.Death()
		if cause != CauseTransportError || !strings.Contains(detail, "read:") || !at.Equal(t0) {
			t.Fatalf("cause %v %q at %v, want transport_error at once", cause, detail, at.Sub(t0))
		}
		a.c.Kill(CauseLocalClose, "later")
		if n := a.io.closes.Load(); n != 2 {
			t.Fatalf("closes %d, want the embedder's and rendr's one", n)
		}
	})
}

// TestDgramOnStreamCarrier: on a stream carrier of a packet session a DGRAM
// is an ordinary frame counted as DATA (M2-D26): a small one is handed over
// during the call, one of 16 KiB or more by reference (read straight into
// its own Buf, §A5.3); a DGRAM the session places is submitted like DATA.
func TestDgramOnStreamCarrier(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		env := hEnv()
		c, p := hPair(t, env, nil)
		ep := &dEP{}
		var want, size atomic.Int32
		size.Store(1000)
		ep.setFill(dgramFill(&want, &size))
		c.Start(ep, &hBell{}, StartOptions{})
		synctest.Wait()
		small := dgramFrame(4, 100)
		big := dgramFrame(5, 20000)
		if err := p.sendFrames(hFrame{t: small.t, handle: small.handle, payload: small.payload}, hFrame{t: big.t, handle: big.handle, payload: big.payload}); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		got := ep.datagrams()
		if len(got) != 2 || got[0] != (dgRec{seq: 4, n: 100}) || got[1] != (dgRec{seq: 5, n: 20000, byRef: true}) {
			t.Fatalf("datagrams %+v", got)
		}
		if st := c.Stats(); st.RxBytes != 20100 || st.MTU != 0 || st.DatagramsRx != 0 {
			t.Fatalf("RxBytes %d MTU %d DatagramsRx %d", st.RxBytes, st.MTU, st.DatagramsRx)
		}
		want.Store(1)
		c.Wake()
		synctest.Wait()
		if st := c.Stats(); st.TxBytes != 1000 || c.Inflight() != 1000 {
			t.Fatalf("TxBytes %d inflight %d, want the DGRAM counted as DATA", st.TxBytes, c.Inflight())
		}
		var dg int
		for _, f := range p.received() {
			if f.Type == wire.TypeDgram {
				dg++
			}
		}
		if dg != 1 {
			t.Fatalf("%d DGRAM frames on the wire", dg)
		}
	})
}

// TestDatagramTailWalked: the rendr bytes that followed the response frame
// in the response datagram (dg.tail, kept by Establish) are walked by the
// reader before its first read, exactly as the rest of that datagram — a
// PING in it is answered at once, a DGRAM in it delivered — and nothing
// is lost (R1-1; Establish's half is WP3b's TestEstablishResponseTail).
func TestDatagramTailWalked(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, p := rawPair(t, 1200, true)
		s.c.dg.tail = p.datagram(pingFrame(wire.TypePing, wire.Ping{ID: 9, Nonce: 90}), dgramFrame(3, 50))
		s.start(StartOptions{})
		synctest.Wait()
		var pong bool
		for _, d := range p.read() {
			for _, pg := range pingsOf(d, true) {
				pong = pong || pg.ID == 9
			}
		}
		got := s.ep.datagrams()
		if !pong || len(got) != 1 || got[0].seq != 3 || got[0].n != 50 {
			t.Fatalf("PONG for the tail's PING %v, datagrams %+v", pong, got)
		}
		if s.c.dg.tail != nil || s.c.Stats().Dropped != 0 {
			t.Fatalf("tail kept or frames dropped (%d)", s.c.Stats().Dropped)
		}
	})
}
