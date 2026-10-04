package session

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestStreamBlockedCallsWoken (§3.5): every event a blocked application
// call waits for wakes it — the session's end wakes a blocked Read and a
// blocked Write with the end error, a FIN at the contiguous point wakes a
// blocked Read with io.EOF, and CloseWrite wakes a Write blocked on a full
// send buffer with net.ErrClosed. A lost wakeup deadlocks the bubble.
func TestStreamBlockedCallsWoken(t *testing.T) {
	const w = 256 << 10
	block := func(t *testing.T, s *Session, read bool) <-chan stIO {
		ch := make(chan stIO, 1)
		go func() {
			var r stIO
			if read {
				r.n, r.err = s.Read(make([]byte, 10))
			} else {
				r.n, r.err = s.Write(make([]byte, 1000))
			}
			ch <- r
		}()
		synctest.Wait()
		if len(ch) != 0 {
			t.Fatalf("the call (read %v) returned instead of blocking (stimulus)", read)
		}
		return ch
	}
	fullSender := func(t *testing.T) *Session {
		s := stSession(stOpt{window: w})
		if n, err := s.Write(make([]byte, w)); n != w || err != nil {
			t.Fatalf("Write of one window = (%d, %v)", n, err)
		}
		return s
	}
	t.Run("end", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s := fullSender(t)
			calls := [2]<-chan stIO{block(t, s, true), block(t, s, false)}
			stEnd(s, ErrNoPath)
			for _, ch := range calls {
				if r := <-ch; r.n != 0 || !errors.Is(r.err, ErrNoPath) {
					t.Fatalf("blocked call after the end = (%d, %v), want (0, ErrNoPath)", r.n, r.err)
				}
			}
			if u := s.env.Carrier.Budget.Used(); u != 0 {
				t.Fatalf("Budget.Used = %d after the end", u)
			}
		})
	})
	t.Run("FIN", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s := stSession(stOpt{role: RolePassive})
			l, _ := stAddLane(s, 1, false)
			if err := l.Data(nil, 0, stPattern(0, 100), nil); err != nil {
				t.Fatal(err)
			}
			stReadN(t, s, 100)
			ch := block(t, s, true)
			if err := stSendFin(l, 100); err != nil {
				t.Fatal(err)
			}
			if r := <-ch; r.n != 0 || r.err != io.EOF {
				t.Fatalf("Read blocked at the FIN's offset = (%d, %v), want (0, io.EOF)", r.n, r.err)
			}
			stEnd(s, io.EOF)
		})
	})
	t.Run("CloseWrite", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s := fullSender(t)
			ch := block(t, s, false)
			_ = s.CloseWrite()
			if r := <-ch; r.n != 0 || !errors.Is(r.err, net.ErrClosed) {
				t.Fatalf("Write blocked on a full buffer after CloseWrite = (%d, %v), want (0, net.ErrClosed)", r.n, r.err)
			}
			stEnd(s, errClosed)
		})
	})
}

// TestStreamLaneWakes (§3.5, R1): every producer that makes DATA or the FIN
// sendable wakes an idle data lane — peer-window growth with committed
// bytes waiting, CloseWrite once the FIN is due, a routing change that
// makes a lane the data lane, a requeue when a bond member loses data
// eligibility, and the FIN re-armed by the death of the lane it went out
// on (here no ACK duty lane exists, so the re-ACK bump cannot mask it) —
// and a Fill stopped by the carrier's capacity cap with bytes still
// pullable marks its batch cap-blocked, so the PONG that frees capacity
// wakes the writer (C5).
func TestStreamLaneWakes(t *testing.T) {
	drain := func(l *lane) { // Fill until nothing is appended: l is idle
		for {
			fs, b := stFill(l, time.Now())
			b.ReleaseRefs()
			if len(fs) == 0 {
				return
			}
		}
	}
	woken := func(fp *stPort, fn func()) bool {
		w := fp.wakeCount()
		fn()
		return fp.wakeCount() > w
	}
	withLock := func(s *Session, fn func()) func() {
		return func() {
			s.mu.Lock()
			fn()
			s.mu.Unlock()
		}
	}

	s := stSession(stOpt{})
	l, fp := stAddLane(s, 1, true)
	withLock(s, func() { s.peerWindowLocked(64 << 10) })()
	if n, err := s.Write(stPattern(0, 200<<10)); n != 200<<10 || err != nil {
		t.Fatal(err)
	}
	drain(l) // the peer's 64 KiB window is used up; 136 KiB wait
	if !woken(fp, func() { _ = stSendAck(l, 0, 0, 1<<20) }) {
		t.Fatal("peer-window growth with committed bytes waiting did not wake the idle data lane")
	}
	drain(l) // everything sent; the FIN becomes due at CloseWrite
	if !woken(fp, func() { _ = s.CloseWrite() }) {
		t.Fatal("CloseWrite with the FIN due did not wake the idle data lane")
	}
	// A standby lane made the data lane (the actor's routing change).
	l2, fp2 := stAddLane(s, 2, false)
	drain(l2)
	stRoute(s, l, false)
	if !woken(fp2, func() { stRoute(s, l2, true) }) {
		t.Fatal("a routing change left the new data lane asleep with the FIN due")
	}
	stEnd(s, errClosed)

	// Capacity cap.
	s = stSession(stOpt{})
	l, fp = stAddLane(s, 1, true)
	fp.set(func(f *stPort) { f.capacity = 64 << 10 })
	withLock(s, func() { s.peerWindowLocked(1 << 20) })()
	if n, err := s.Write(stPattern(0, 200<<10)); n != 200<<10 || err != nil {
		t.Fatal(err)
	}
	fs, b := stFill(l, time.Now())
	if capped := b.CapBlocked(); !capped || stCount(fs, wire.TypeData) != 1 {
		t.Fatalf("Fill at the 64 KiB capacity cap: %v, cap-blocked %v; want one segment and the cap-blocked mark", fs, capped)
	}
	b.ReleaseRefs()
	fp.set(func(f *stPort) { f.capacity = 1 << 40 })
	if _, b = stFill(l, time.Now()); b.CapBlocked() {
		t.Fatal("a Fill that pulled everything is marked cap-blocked")
	}
	b.ReleaseRefs()
	stEnd(s, errClosed)

	// Bond: member 1 loses data eligibility (the actor's retirement step).
	s = stSession(stOpt{mode: ModeBond})
	l1, _ := stAddLane(s, 1, true)
	l2, fp2 = stAddLane(s, 2, true)
	withLock(s, func() { s.peerWindowLocked(1 << 20) })()
	if n, err := s.Write(stPattern(0, 100<<10)); n != 100<<10 || err != nil {
		t.Fatal(err)
	}
	drain(l1)
	drain(l2)
	withLock(s, func() { l1.data, l1.retireCalled = false, true })()
	if !woken(fp2, withLock(s, func() { s.requeueLocked(l1) })) {
		t.Fatal("a requeue left the other bond member asleep")
	}
	stEnd(s, errClosed)

	// Passive bond: our FIN went out on member 1, which dies; member 2 is
	// data-eligible but has not placed its JOIN_ACK yet (no ACK duty).
	s = stSession(stOpt{role: RolePassive, mode: ModeBond})
	l1, _ = stAddLane(s, 1, true)
	l2, fp2 = stAddLane(s, 2, true)
	withLock(s, func() {
		l2.firstSent = false
		l2.first = firstFrame{t: wire.TypeJoinAck, joinAck: wire.JoinAck{Status: wire.StatusOK}}
		l2.idle = true
		s.peerWindowLocked(1 << 20)
	})()
	_ = s.CloseWrite()
	if fs, b := stFill(l1, time.Now()); stCount(fs, wire.TypeFin) != 1 {
		t.Fatalf("member 1 sent %v, want the FIN", fs)
	} else {
		b.ReleaseRefs()
	}
	if !woken(fp2, func() { stKillLane(s, l1) }) {
		t.Fatal("the FIN re-armed by its lane's death woke no data lane")
	}
	stEnd(s, errClosed)
}

// TestStreamReplayAndWindowWakes (R1, L10, L15) over writer emulations
// that sleep until woken and links with 1 ms of virtual latency, so every
// answer arrives after the sending writer went idle: the sender's buffer
// (1 MiB) exceeds the receiver's window (256 KiB). A Write commits 600 KiB
// to idle writers; member 1 carries the whole peer window into a black
// hole and dies; its bytes are requeued and replayed by member 2, then the
// rest follows as the peer's ACKs grow the window; CloseWrite after
// everything was acknowledged sends the FIN. Every byte arrives once and
// in order, the replay before new data and the FIN; a lost wakeup
// deadlocks the bubble. Selector (the death routes member 2) and bond
// (member 2 is already a data member).
func TestStreamReplayAndWindowWakes(t *testing.T) {
	for _, mode := range []Mode{ModeSelector, ModeBond} {
		t.Run(map[Mode]string{ModeSelector: "selector", ModeBond: "bond"}[mode], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				const pw = 256 << 10
				p := stNewPair(stOpt{mode: mode, window: 1 << 20}, stOpt{window: pw}, 2)
				stop := make(chan struct{})
				var wg sync.WaitGroup
				var lost atomic.Int64 // DATA bytes link 1 carried into the black hole
				p.runLinks(&wg, stop, time.Millisecond, func(i int, aToB bool, b *carrier.Batch) bool {
					if i != 0 || !aToB {
						return false
					}
					for _, f := range stFrames(b) {
						lost.Add(int64(f.n))
					}
					return true
				})
				defer func() {
					select {
					case <-stop:
					default:
						close(stop)
					}
					wg.Wait()
				}()
				synctest.Wait() // every writer is idle: the commit must wake one
				msg := stPattern(0, 600<<10)
				if n, err := p.a.Write(msg); n != len(msg) || err != nil {
					t.Fatalf("Write = (%d, %v)", n, err)
				}
				got := stReadAsync(p.b, len(msg))
				synctest.Wait()
				if n := lost.Load(); n != pw || len(got) != 0 {
					t.Fatalf("link 1 lost %d DATA bytes (want the peer's window, %d) and the reader got %d results", n, pw, len(got))
				}
				stKillLane(p.a, p.al[0])
				stKillLane(p.b, p.bl[0])
				if mode == ModeSelector {
					stRoute(p.a, p.al[1], true)
					stRoute(p.b, p.bl[1], true)
				}
				if r := <-got; r.err != nil || !bytes.Equal(r.b, msg) {
					t.Fatalf("transfer after the death: %v (corrupted: %v)", r.err, !bytes.Equal(r.b, msg))
				}
				synctest.Wait() // everything sent and acknowledged: every writer is idle
				_ = p.a.CloseWrite()
				if _, err := p.b.Read(make([]byte, 1)); err != io.EOF {
					t.Fatalf("after the transfer: %v, want io.EOF", err)
				}
				close(stop)
				wg.Wait()
				var last uint64 // ascending offsets with retx ⇔ below pw: the replay first
				fin := false
				for _, f := range p.traceAB {
					switch {
					case f.typ == wire.TypeData && (fin || f.off < last || f.retx != (f.off < pw)):
						t.Fatalf("%v after DATA up to %d (FIN sent %v): the replay must come first, then new data, then the FIN", f, last, fin)
					case f.typ == wire.TypeData:
						last = f.off + uint64(f.n)
					case f.typ == wire.TypeFin:
						if fin || f.off != uint64(len(msg)) || last != f.off {
							t.Fatalf("FIN %v after DATA up to %d (repeated %v)", f, last, fin)
						}
						fin = true
					}
				}
				if !fin {
					t.Fatal("no FIN on member 2")
				}
				if errs := p.errors(); len(errs) != 0 {
					t.Fatalf("violations: %v", errs)
				}
				p.close(t)
			})
		})
	}
}
