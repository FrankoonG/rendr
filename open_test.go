package rendr

import (
	"context"
	"errors"
	"math/rand/v2"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// acceptLog accepts every session of ln on its own goroutine and hands each
// PendingConn to decide, recording how often every session ID was
// accepted. stop ends the loop and joins it.
type acceptLog struct {
	mu    sync.Mutex
	count map[SessionID]int
	conns []*Conn // confirmed passive ends
	stop  func()
}

func newAcceptLog(ln *Listener, decide func(pc *PendingConn) (*Conn, error)) *acceptLog {
	a := &acceptLog{count: make(map[SessionID]int)}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			pc, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			a.mu.Lock()
			a.count[pc.ID()]++
			a.mu.Unlock()
			if c, err := decide(pc); err == nil && c != nil {
				a.mu.Lock()
				a.conns = append(a.conns, c)
				a.mu.Unlock()
			}
		}
	})
	a.stop = func() {
		cancel()
		wg.Wait()
	}
	return a
}

// accepted returns how often sid was accepted and the number of distinct
// sessions accepted.
func (a *acceptLog) accepted(sid SessionID) (n, sessions int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.count[sid], len(a.count)
}

// TestOpenIdempotent_L47: an OPEN is idempotent (L47, design §6.2, §6.5).
// When the first OPEN_ACK(OK) is lost, the dialer's retried OPEN (same
// session ID) reaches the session the passive already confirmed: the
// application accepted exactly one session, the dialer's Conn is that
// session and carries data. When an OPEN_ACK(REJECTED) is lost, the
// retried OPEN gets REJECTED with the same code and message again from the
// tombstone — still one Accept. Stimulus proof: exactly one OPEN_ACK frame
// dropped per case on a session carrier; a replay after the end gets
// UNKNOWN_SESSION.
func TestOpenIdempotent_L47(t *testing.T) {
	t.Run("lost OPEN_ACK OK", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
			link := e.links[0]
			acc := newAcceptLog(e.ln, func(pc *PendingConn) (*Conn, error) {
				link.DropNextFrame(rendrtest.Down, rendrtest.FrameOpenAck) // the carrier exists: it carried this OPEN
				return pc.Confirm()
			})
			start := time.Now()
			dc, err := e.peer().Dial(context.Background(), DialOptions{})
			if err != nil {
				t.Fatalf("Dial after a lost OPEN_ACK: %v", err)
			}
			synctest.Wait()
			if st := link.Stats(); st.Session.FramesDropped != 1 || st.Dials < 2 {
				t.Fatalf("stimulus: %d OPEN_ACKs dropped, %d dials", st.Session.FramesDropped, st.Dials)
			}
			if n, sessions := acc.accepted(dc.ID()); n != 1 || sessions != 1 {
				t.Fatalf("accepted %d times (%d sessions), want exactly one", n, sessions)
			}
			if ps := e.p.Status(); ps.Sessions.Open+ps.Sessions.Orphaned != 1 || e.p.table.inUse() != 1 {
				t.Fatalf("passive sessions %+v (%d units)", ps.Sessions, e.p.table.inUse())
			}
			t.Logf("Dial took %v over two carriers", time.Since(start))
			acc.mu.Lock()
			sc := acc.conns[0]
			acc.mu.Unlock()
			if sc.ID() != dc.ID() {
				t.Fatalf("confirmed %v, dialled %v", sc.ID(), dc.ID())
			}
			e2eExchange(t, dc, sc, 1<<20, 7)
			e2eFinish(t, dc, sc)
			d := wpConnect(t, e.ln, e.d.InstanceID(), 99)
			d.hello(e.p)
			d.send(wire.TypeOpen, 0, wpOpen(dc.ID(), wire.KindStream, 1, nil))
			d.expectOpenAck(wire.StatusUnknownSession, 0)
			d.expectEOF()
			d.close()
			acc.stop()
			e.close()
		})
	})
	t.Run("lost OPEN_ACK REJECTED", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a")
			link := e.links[0]
			acc := newAcceptLog(e.ln, func(pc *PendingConn) (*Conn, error) {
				link.DropNextFrame(rendrtest.Down, rendrtest.FrameOpenAck)
				return nil, pc.Reject(42, "no route to host")
			})
			_, err := e.peer().Dial(context.Background(), DialOptions{})
			var re *RejectError
			if !errors.As(err, &re) || !errors.Is(err, ErrRejected) || re.Code != 42 || re.Msg != "no route to host" {
				t.Fatalf("Dial after a lost REJECTED: %v", err)
			}
			synctest.Wait()
			if st := link.Stats(); st.Session.FramesDropped != 1 || st.Dials < 2 {
				t.Fatalf("stimulus: %d OPEN_ACKs dropped, %d dials", st.Session.FramesDropped, st.Dials)
			}
			acc.mu.Lock()
			total := 0
			for _, n := range acc.count {
				total += n
			}
			acc.mu.Unlock()
			if total != 1 {
				t.Fatalf("%d Accepts, want 1", total)
			}
			if ps := e.p.Status(); ps.Sessions != (SessionCounts{Tombstones: 1}) {
				t.Fatalf("passive sessions %+v", ps.Sessions)
			}
			acc.stop()
			e.close()
		})
	})
}

// TestOpenRaceSingleSession_L47: 64 carriers of one dialer instance OPEN
// the same session ID at the same instant (L47, design §6.2 D28, C8).
// Exactly one session is created and started: one Accept, one MaxSessions
// unit, one backlog slot, no reservation left by the losers (their
// sessions were never started); every loser's carrier is attached to the
// winner (MaxCarriersPerSession raised to 64), so Confirm answers
// OPEN_ACK(OK) on all 64 carriers of the one session.
func TestOpenRaceSingleSession_L47(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const n = 64
		rt := wpTestRuntime(t, Config{}, &testhooks.Overrides{MaxCarriersPerSession: n})
		ln := wpListen(t, rt, ListenConfig{})
		inst, sid := wpInst(0x47), wpSID(47)
		ds := make([]*wpDialer, n)
		for i := range ds {
			ds[i] = wpConnect(t, ln, inst, uint32(i+1))
			ds[i].hello(rt)
		}
		go1 := make(chan struct{})
		var wg sync.WaitGroup
		for _, d := range ds {
			wg.Go(func() {
				<-go1
				d.send(wire.TypeOpen, 0, wpOpen(sid, wire.KindStream, 1, []byte("race")))
			})
		}
		close(go1)
		wg.Wait()
		synctest.Wait()
		if units, bl := rt.table.inUse(), rt.backlog.Load(); units != 1 || bl != 1 {
			t.Fatalf("after %d racing OPENs: %d MaxSessions units, %d backlog slots", n, units, bl)
		}
		ln.mu.Lock()
		reserved, pending := ln.reserved, len(ln.pending)
		ln.mu.Unlock()
		if reserved != 0 || pending != 1 {
			t.Fatalf("listener: %d reservations, %d pending sessions", reserved, pending)
		}
		pc, err := ln.Accept(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		if extra, err := ln.Accept(ctx); extra != nil || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("a second Accept: %v, %v", extra, err)
		}
		cancel()
		if pc.ID() != SessionID(sid) {
			t.Fatalf("accepted %v", pc.ID())
		}
		sc, err := pc.Confirm()
		if err != nil {
			t.Fatal(err)
		}
		for i, d := range ds {
			wg.Go(func() {
				a := d.expectOpenAck(wire.StatusOK, 0)
				if a.Window == 0 {
					t.Errorf("carrier %d: OPEN_ACK(OK) without a window", i+1)
				}
			})
		}
		wg.Wait()
		synctest.Wait()
		if st := sc.Status(); len(st.Carriers) != n {
			t.Fatalf("the session holds %d carriers, want %d", len(st.Carriers), n)
		}
		for _, d := range ds {
			d.close()
		}
		rt.Close()
		wpNoState(t, rt)
	})
}

// TestRandomOpenAckLoss_L47: random OPEN_ACK loss never forks a session
// (L47 fuzz): 40 Dials over two links in selector and bond mode, a seeded
// dropper loses the next OPEN_ACK of every current carrier at random
// instants and at half of the Confirms. Each Dial produced at most one
// passive session: no session ID was accepted twice; every successful Dial
// is exactly the one session the passive application accepted for its ID,
// and carries data; Dials that failed left no session behind. Stimulus
// proof: OPEN_ACK frames were dropped on session carriers and the Dials
// retried.
func TestRandomOpenAckLoss_L47(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rng := rand.New(rand.NewPCG(47, 4747))
		var rmu sync.Mutex
		coin := func(p float64) bool {
			rmu.Lock()
			defer rmu.Unlock()
			return rng.Float64() < p
		}
		e := e2eNew(t, Config{}, Config{}, nil, ListenConfig{}, "a", "b")
		for _, l := range e.links {
			l.SetDelay(time.Millisecond, 0) // probes need an RTT above zero (WaitFirst)
		}
		drop := func() {
			for _, l := range e.links {
				l.DropNextFrame(rendrtest.Down, rendrtest.FrameOpenAck)
			}
		}
		acc := newAcceptLog(e.ln, func(pc *PendingConn) (*Conn, error) {
			if coin(0.5) {
				drop()
			}
			return pc.Confirm()
		})
		stop := make(chan struct{})
		var stopOnce sync.Once
		var wg sync.WaitGroup
		t.Cleanup(func() { // a failing test still ends the dropper before the bubble ends
			stopOnce.Do(func() { close(stop) })
			wg.Wait()
		})
		wg.Go(func() { // the dropper
			for {
				select {
				case <-stop:
					return
				case <-time.After(73 * time.Millisecond):
				}
				if coin(0.3) {
					drop()
				}
			}
		})
		peer := e.peer()
		const dials = 40
		ok := 0
		for i := range dials {
			mode := ModeSelector
			if i%2 == 1 {
				mode = ModeBond
			}
			dc, err := peer.Dial(context.Background(), DialOptions{Mode: mode})
			if err != nil {
				if !errors.Is(err, ErrNoPath) {
					t.Fatalf("Dial %d: %v", i, err)
				}
				continue
			}
			ok++
			if n, _ := acc.accepted(dc.ID()); n != 1 {
				t.Fatalf("Dial %d: its session was accepted %d times", i, n)
			}
			var sc *Conn
			acc.mu.Lock()
			for _, c := range acc.conns {
				if c.ID() == dc.ID() {
					sc = c
				}
			}
			acc.mu.Unlock()
			if sc == nil {
				t.Fatalf("Dial %d: the passive end was never confirmed", i)
			}
			e2eExchange(t, dc, sc, 64<<10, uint64(i))
			dc.Close()
			sc.Close()
		}
		stopOnce.Do(func() { close(stop) })
		wg.Wait()
		synctest.Wait()
		acc.mu.Lock()
		for sid, n := range acc.count {
			if n != 1 {
				t.Fatalf("session %v accepted %d times", sid, n)
			}
		}
		accepted := len(acc.count)
		acc.mu.Unlock()
		dropped := e.links[0].Stats().Session.FramesDropped + e.links[1].Stats().Session.FramesDropped
		dialled := e.links[0].Stats().Dials + e.links[1].Stats().Dials
		t.Logf("%d of %d Dials succeeded, %d sessions accepted, %d OPEN_ACKs dropped, %d carrier dials", ok, dials, accepted, dropped, dialled)
		if ok < dials/2 || accepted < ok || dropped < 10 {
			t.Fatalf("stimulus or load not reached: %d Dials succeeded, %d accepted, %d OPEN_ACKs dropped", ok, accepted, dropped)
		}
		if ps := e.p.Status(); ps.Sessions.Pending != 0 || ps.AcceptBacklog[0] != 0 {
			t.Fatalf("passive left %+v", ps)
		}
		acc.stop()
		e.close()
	})
}
