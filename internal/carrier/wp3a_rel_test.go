package carrier

import (
	"bytes"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// REL sublayer tests (M2-D16…M2-D18; M2 design §A5.9, §A8.2 WP3a rows).

// withRel reports datagrams that carry a REL with cseq cs.
func withRel(cs uint32) func([]byte) bool {
	return func(d []byte) bool {
		for _, h := range relsOf(d) {
			if h.Cseq == cs {
				return true
			}
		}
		return false
	}
}

// anyRel reports datagrams that carry a REL.
func anyRel(d []byte) bool { return len(relsOf(d)) > 0 }

// anyRack reports datagrams that carry a RACK.
func anyRack(d []byte) bool { return len(racksOf(d)) > 0 }

// dropFirst returns a filter that loses the first n datagrams matching
// pred, and counts them in lost.
func dropFirst(pred func([]byte) bool, n int, lost *atomic.Int32) func([]byte) bool {
	return func(d []byte) bool {
		if pred(d) && int(lost.Load()) < n {
			lost.Add(1)
			return false
		}
		return true
	}
}

// dropAll loses every datagram matching pred.
func dropAll(pred func([]byte) bool) func([]byte) bool {
	return func(d []byte) bool { return !pred(d) }
}

// retxLog records Hooks.RelRetransmit calls.
type retxLog struct {
	mu sync.Mutex
	at []time.Time
	cs []uint32
}

func (l *retxLog) hooks() *testhooks.Hooks {
	return &testhooks.Hooks{RelRetransmit: func(_ uint32, cseq uint32) {
		l.mu.Lock()
		l.at = append(l.at, time.Now())
		l.cs = append(l.cs, cseq)
		l.mu.Unlock()
	}}
}

func (l *retxLog) get() ([]time.Time, []uint32) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]time.Time(nil), l.at...), append([]uint32(nil), l.cs...)
}

// TestRelWindow_L12: at most wire.RelWindow RELs are outstanding; a ninth
// reliable frame is refused by the batch and stays due in the session
// (RelRoom 0); the RACK that frees room wakes the blocked writer, which
// then places it.
func TestRelWindow_L12(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := dgPair(t, 1200)
		var want atomic.Int32
		var next atomic.Uint64
		want.Store(9)
		a.ep.setFill(finFill(&want, &next))
		b.io.setFilter(func([]byte) bool { return false }) // no RACK reaches a
		a.io.setRec(true)
		a.start(StartOptions{})
		b.start(StartOptions{})
		synctest.Wait()
		if r := a.c.RelRoom(); r != 0 {
			t.Fatalf("RelRoom %d with 8 outstanding, want 0", r)
		}
		if w := want.Load(); w != 1 {
			t.Fatalf("%d FINs still due, want the ninth (1)", w)
		}
		seen := map[uint32]bool{}
		for _, w := range a.io.recorded() {
			for _, h := range relsOf(w.b) {
				seen[h.Cseq] = true
			}
		}
		if len(seen) != wire.RelWindow {
			t.Fatalf("%d distinct cseqs written, want %d", len(seen), wire.RelWindow)
		}
		if got := finOffsets(b.ep); len(got) != 8 || got[7] != 7 {
			t.Fatalf("passive FINs %v, want 0…7", got)
		}
		b.io.setFilter(nil)
		time.Sleep(time.Second) // the retransmission of una draws a RACK covering all eight
		synctest.Wait()
		if w := want.Load(); w != 0 {
			t.Fatalf("the ninth FIN still due after the RACK")
		}
		if got := finOffsets(b.ep); len(got) != 9 || got[8] != 8 {
			t.Fatalf("passive FINs %v, want 0…8", got)
		}
		if a.c.Stats().Retransmits == 0 {
			t.Fatal("no retransmission drew the RACK")
		}
	})
}

// TestRelResendIdentical_L12: a retransmission is a new outer frame — a new
// fseq and CRC — around the byte-identical REL payload (PA-21), so the
// receiver's fseq window accepts it and the REL is dispatched once.
func TestRelResendIdentical_L12(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := dgPair(t, 1200)
		var want atomic.Int32
		var next atomic.Uint64
		want.Store(1)
		a.ep.setFill(finFill(&want, &next))
		var lost atomic.Int32
		first := a.env.Presets.firstCseq()
		a.io.setFilter(dropFirst(withRel(first), 1, &lost))
		a.io.setRec(true)
		a.start(StartOptions{})
		b.start(StartOptions{})
		time.Sleep(time.Second)
		synctest.Wait()
		var copies []wire.Frame
		for _, w := range a.io.recorded() {
			fs, _ := dgDecode(w.b)
			for _, f := range fs {
				if f.Type == wire.TypeRel {
					copies = append(copies, f)
				}
			}
		}
		if lost.Load() != 1 || len(copies) != 2 {
			t.Fatalf("lost %d, REL copies %d, want 1 and 2", lost.Load(), len(copies))
		}
		if !bytes.Equal(copies[0].Payload, copies[1].Payload) {
			t.Fatalf("REL payload changed:\n%x\n%x", copies[0].Payload, copies[1].Payload)
		}
		if copies[0].Fseq == copies[1].Fseq {
			t.Fatalf("the retransmission reused fseq %d", copies[0].Fseq)
		}
		if got := finOffsets(b.ep); len(got) != 1 {
			t.Fatalf("passive FINs %v, want one", got)
		}
		if r := a.c.RelRoom(); r != wire.RelWindow {
			t.Fatalf("RelRoom %d after the RACK, want %d", r, wire.RelWindow)
		}
	})
}

// TestRelSingleFlight_L12: on a path that loses every REL only una is
// retransmitted, once per backed-off RTO — 0.3, 0.9, 2.1 s after the first
// attempt (300 ms before an RTT sample, doubling, PA-8) — and the
// retransmissions stop when the carrier dies (L12 "受宽限约束").
func TestRelSingleFlight_L12(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := dgPair(t, 1200)
		var log retxLog
		a.env.Hooks = log.hooks()
		var want atomic.Int32
		var next atomic.Uint64
		want.Store(3)
		a.ep.setFill(finFill(&want, &next))
		a.io.setFilter(dropAll(anyRel))
		b.io.setFilter(func([]byte) bool { return false }) // nothing returns: the carrier dies by its PING deadline
		t0 := time.Now()
		a.start(StartOptions{})
		b.start(StartOptions{})
		hWait(t, a.c)
		_, cause, _, deathAt := a.c.Death()
		if cause != CausePingTimeout {
			t.Fatalf("cause %v, want ping_timeout", cause)
		}
		time.Sleep(10 * time.Second)
		at, cs := log.get()
		wantAt := []time.Duration{300 * time.Millisecond, 900 * time.Millisecond, 2100 * time.Millisecond}
		if len(at) != len(wantAt) {
			t.Fatalf("%d retransmissions %v, want %d", len(at), at, len(wantAt))
		}
		first := a.env.Presets.firstCseq()
		for i := range at {
			if cs[i] != first {
				t.Fatalf("retransmission %d of cseq %d, want only una %d", i, cs[i], first)
			}
			if d := at[i].Sub(t0); d != wantAt[i] {
				t.Fatalf("retransmission %d at %v, want %v", i, d, wantAt[i])
			}
			if at[i].After(deathAt) {
				t.Fatalf("retransmission after the death")
			}
		}
	})
}

// TestRelIdleZeroWrites_L12: once every REL is RACKed nothing is armed: an
// idle carrier pair neither writes nor wakes its writer for 5 s (M2-D65).
func TestRelIdleZeroWrites_L12(t *testing.T) {
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
		time.Sleep(6 * time.Second) // past the carriers' youth: PINGs at PingIdle only
		want.Store(1)
		a.c.Wake()
		synctest.Wait()
		if got := finOffsets(b.ep); len(got) != 1 || a.c.RelRoom() != wire.RelWindow {
			t.Fatalf("FIN not delivered and RACKed: %v, room %d", got, a.c.RelRoom())
		}
		wa, wb := a.io.nwrites.Load(), b.io.nwrites.Load()
		fa, fb := a.ep.fills.Load(), b.ep.fills.Load()
		time.Sleep(5 * time.Second)
		synctest.Wait()
		if a.io.nwrites.Load() != wa || b.io.nwrites.Load() != wb {
			t.Fatalf("writes while idle: a %d, b %d", a.io.nwrites.Load()-wa, b.io.nwrites.Load()-wb)
		}
		if a.ep.fills.Load() != fa || b.ep.fills.Load() != fb {
			t.Fatalf("writer wakes while idle: a %d, b %d", a.ep.fills.Load()-fa, b.ep.fills.Load()-fb)
		}
	})
}

// TestRelFirstResendAt600ms_L12: with srtt 400 ms and rttvar 50 ms the REL
// timeout is 600 ms (L12 arithmetic: clamp(srtt + 4·rttvar, 200 ms, 2 s)).
func TestRelFirstResendAt600ms_L12(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := dgPair(t, 1200)
		var log retxLog
		a.env.Hooks = log.hooks()
		a.c.st.srtt, a.c.st.rttvar, a.c.st.rttSeen = 400*time.Millisecond, 50*time.Millisecond, true
		var want atomic.Int32
		var next atomic.Uint64
		want.Store(1)
		a.ep.setFill(finFill(&want, &next))
		a.io.setFilter(func([]byte) bool { return false })
		b.io.setFilter(func([]byte) bool { return false })
		t0 := time.Now()
		a.start(StartOptions{})
		b.start(StartOptions{})
		time.Sleep(time.Second)
		at, _ := log.get()
		if len(at) != 1 || at[0].Sub(t0) != 600*time.Millisecond {
			t.Fatalf("retransmissions at %v, want one at 600ms", at)
		}
	})
}

// TestRelInOrderDispatch_L12_L45: RELs are dispatched in cseq order — an
// RST overtaken by the CLOSE behind it is dispatched first, the CLOSE held
// until then (M1's per-carrier FIFO) — and cum advances only after the
// endpoint call returned, so no RACK ever covers a frame still being
// dispatched (M2-D17).
func TestRelInOrderDispatch_L12_L45(t *testing.T) {
	t.Run("RST before CLOSE", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			a, b := dgPair(t, 1200)
			var placed atomic.Bool
			a.ep.setFill(func(c *Conn, bt *Batch) {
				if !placed.Load() && bt.AddRst(wire.SessionHandle, &wire.Rst{Code: 1}) {
					placed.Store(true)
				}
			})
			var lost atomic.Int32
			a.io.setFilter(dropFirst(withRel(a.env.Presets.firstCseq()), 1, &lost))
			var closedAtRst atomic.Int32
			b.ep.setHook(func(h wire.Header, _ []byte) {
				if h.Type == wire.TypeRst && b.c.PeerClosed() {
					closedAtRst.Add(1)
				}
			})
			a.start(StartOptions{})
			b.start(StartOptions{})
			synctest.Wait()
			a.c.Retire(wire.CloseRetire)
			time.Sleep(time.Second)
			synctest.Wait()
			var rst int
			for _, h := range b.ep.controls() {
				if h.Type == wire.TypeRst {
					rst++
				}
			}
			if lost.Load() != 1 || rst != 1 || closedAtRst.Load() != 0 || !b.c.PeerClosed() {
				t.Fatalf("lost %d, RST dispatched %d (after the CLOSE: %d), peer closed %v", lost.Load(), rst, closedAtRst.Load(), b.c.PeerClosed())
			}
		})
	})
	t.Run("RACK covers dispatched only", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			a, b := dgPair(t, 1200)
			var want atomic.Int32
			var next atomic.Uint64
			want.Store(2)
			a.ep.setFill(finFill(&want, &next))
			first := a.env.Presets.firstCseq()
			var lost atomic.Int32
			a.io.setFilter(dropFirst(withRel(first), 1, &lost))
			release := make(chan struct{})
			var blocking atomic.Bool
			b.ep.setHook(func(h wire.Header, p []byte) {
				if off, _ := wire.ParseFin(p); h.Type == wire.TypeFin && off == 1 {
					blocking.Store(true)
					<-release
					blocking.Store(false)
				}
			})
			b.io.setRec(true)
			a.start(StartOptions{})
			b.start(StartOptions{})
			time.Sleep(400 * time.Millisecond) // the retransmission of una (300 ms) arrives
			synctest.Wait()
			if !blocking.Load() {
				t.Fatal("the held FIN is not being dispatched")
			}
			sawFirst := false
			for _, w := range b.io.recorded() {
				for _, r := range racksOf(w.b) {
					if !wire.SeqLess(r.CumAck, first+1) {
						t.Fatalf("RACK cum %d covers cseq %d while its endpoint call runs", r.CumAck, first+1)
					}
					sawFirst = sawFirst || r.CumAck == first
				}
			}
			if !sawFirst {
				t.Fatal("no RACK covered the dispatched first FIN")
			}
			close(release)
			synctest.Wait()
			if r := a.c.RelRoom(); r != wire.RelWindow {
				t.Fatalf("RelRoom %d after the release, want %d", r, wire.RelWindow)
			}
		})
	})
}

// TestRelDuplicateReRacked_L12: a RACK is due after every REL, duplicates
// included: a lost RACK is repaired by the retransmission it causes, and the
// duplicate is never dispatched again (M2-D17).
func TestRelDuplicateReRacked_L12(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := dgPair(t, 1200)
		var want atomic.Int32
		var next atomic.Uint64
		want.Store(1)
		a.ep.setFill(finFill(&want, &next))
		var lost atomic.Int32
		b.io.setFilter(dropFirst(anyRack, 1, &lost))
		b.io.setRec(true)
		a.start(StartOptions{})
		b.start(StartOptions{})
		time.Sleep(time.Second)
		synctest.Wait()
		first := a.env.Presets.firstCseq()
		var racks int
		for _, w := range b.io.recorded() {
			for _, r := range racksOf(w.b) {
				if r.CumAck == first {
					racks++
				}
			}
		}
		if lost.Load() != 1 || racks < 2 {
			t.Fatalf("lost %d RACKs, RACKs covering the FIN %d, want 1 and ≥ 2", lost.Load(), racks)
		}
		if got := finOffsets(b.ep); len(got) != 1 {
			t.Fatalf("FIN dispatched %d times", len(got))
		}
		if r := a.c.RelRoom(); r != wire.RelWindow || a.c.Stats().Retransmits != 1 {
			t.Fatalf("RelRoom %d, retransmits %d, want %d and 1", r, a.c.Stats().Retransmits, wire.RelWindow)
		}
	})
}

// TestRelBeyondWindowKills_L43: a correct sender never runs more than
// wire.RelWindow ahead: a REL at cum + 9 kills the carrier; one at cum + 8
// is held and reported in the RACK's last sack bit.
func TestRelBeyondWindowKills_L43(t *testing.T) {
	for _, tc := range []struct {
		name string
		d    uint32
		kill bool
	}{{"cum+8 held", 8, false}, {"cum+9 kills", 9, true}} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s, p := rawPair(t, 1200, false)
				s.start(StartOptions{})
				synctest.Wait()
				cum := s.env.Presets.firstCseq() - 1
				p.send(relFrame(cum+tc.d, wire.TypeFin, 0, wire.SessionHandle, finInner(0)))
				synctest.Wait()
				dead, cause, detail, _ := s.c.Death()
				if tc.kill {
					if !dead || cause != CauseProtocolViolation || !strings.Contains(detail, "beyond the window") {
						t.Fatalf("death %v %v %q, want protocol_violation beyond the window", dead, cause, detail)
					}
					return
				}
				if dead {
					t.Fatalf("held REL killed the carrier: %v %q", cause, detail)
				}
				var sack uint32
				for _, d := range p.read() {
					for _, r := range racksOf(d) {
						sack = r.Sack
					}
				}
				if sack != 1<<6 {
					t.Fatalf("sack %#x, want bit 6 (cum + 8)", sack)
				}
				if len(finOffsets(s.ep)) != 0 {
					t.Fatal("a held REL was dispatched")
				}
			})
		})
	}
}

// TestRackValidation_L13: a RACK naming a cseq never sent — by its cumAck
// or by a sack bit — or with reserved sack bits kills the carrier; a stale
// cumAck is ignored; a cumAck at una frees its slot (§A3.3).
func TestRackValidation_L13(t *testing.T) {
	for _, tc := range []struct {
		name string
		cum  int32 // relative to the first cseq; two RELs are outstanding
		sack uint32
		kill string
		room int
	}{
		{"cumAck beyond sent", 2, 0, "beyond the last cseq sent", 0},
		{"sack bit beyond sent", -1, 1 << 1, "never sent", 0},
		{"reserved sack bit", 0, 1 << 7, "RACK", 0},
		{"stale cumAck", -1, 1 << 0, "", wire.RelWindow - 2},
		{"cumAck at una", 0, 0, "", wire.RelWindow - 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s, p := rawPair(t, 1200, true)
				var want atomic.Int32
				var next atomic.Uint64
				want.Store(2)
				s.ep.setFill(finFill(&want, &next))
				s.start(StartOptions{})
				synctest.Wait()
				first := s.env.Presets.firstCseq()
				p.send(rackFrame(first+uint32(tc.cum), tc.sack))
				synctest.Wait()
				dead, cause, detail, _ := s.c.Death()
				if tc.kill != "" {
					if !dead || cause != CauseProtocolViolation || !strings.Contains(detail, tc.kill) {
						t.Fatalf("death %v %v %q, want protocol_violation %q", dead, cause, detail, tc.kill)
					}
					return
				}
				if dead {
					t.Fatalf("carrier died: %v %q", cause, detail)
				}
				if r := s.c.RelRoom(); r != tc.room {
					t.Fatalf("RelRoom %d, want %d", r, tc.room)
				}
			})
		})
	}
}
