package lessons4

import (
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// closeCounter wraps the dialer's carrier conns and counts their Close
// calls (L52: every carrier is closed exactly once).
type closeCounter struct {
	mu    sync.Mutex
	conns []*countedConn
}

type countedConn struct {
	net.Conn
	closes atomic.Int32
}

func (c *countedConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

func (cc *closeCounter) wrap(_ string, c net.Conn) net.Conn {
	k := &countedConn{Conn: c}
	cc.mu.Lock()
	cc.conns = append(cc.conns, k)
	cc.mu.Unlock()
	return k
}

// closes returns every wrapped conn's Close count.
func (cc *closeCounter) closes() []int32 {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	out := make([]int32, len(cc.conns))
	for i, c := range cc.conns {
		out[i] = c.closes.Load()
	}
	return out
}

// TestAttachKillChurnNoLeak_L52: 10,000 times (2,000 under -race) the live
// carrier of a session is cut and the session redials and attaches a new
// one. Afterwards the goroutines are exactly those of the start (one
// session with one carrier), every carrier conn of both ends was closed
// exactly once, every cut was one death migration and one no-path episode
// on both ends and one rejoin of the dialer, the session still moves data
// intact, and both Runtimes end with nothing left (no session, buffered
// byte or abandoned call).
func TestAttachKillChurnNoLeak_L52(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cycles := 10000
		if raceEnabled {
			cycles = 2000
		}
		var dconns closeCounter
		w := newWorld(t, worldOpts{tap: true}, "a")
		l := w.link("a")
		// A 1 ms path: both ends see a cut at once, so the passive's death
		// step for the old carrier runs before the redialled JOIN can reach
		// it, and every cut is a no-path episode on both ends (a JOIN that
		// overtook the death step would legitimately start none).
		l.SetDelay(time.Millisecond, 0)
		dc, pc := w.open(w.peer(dconns.wrap, l), rendr.DialOptions{})
		e2 := startFlow(dc, pc, 1<<20, 520, flowOpts{})
		e2.wait(t, time.Minute, "warm-up")

		// live: both ends route on the same carrier, and the passive applied
		// and echoed the dialer's SCHED for it, so the next cut cannot lose
		// that SCHED in the link (the passive counts its death migrations
		// from the SCHEDs it applies).
		live := func() (rendr.CarrierID, bool) {
			ds, ps := dc.Status(), pc.Status()
			da, ok := activeOf(ds)
			pa, ok2 := activeOf(ps)
			synced := ds.SchedEchoed == ds.SchedEpoch && ps.SchedEpoch == ds.SchedEpoch
			return da.ID, ok && ok2 && da.ID == pa.ID && synced
		}
		settle := func(what string, prev rendr.CarrierID) rendr.CarrierID {
			var id rendr.CarrierID
			waitFor(t, 10*time.Second, what, func() bool {
				var ok bool
				id, ok = live()
				return ok && id != prev
			})
			synctest.Wait()
			return id
		}
		id := settle("the first carrier on both ends", 0)
		// Goroutines are counted with both session actors parked (twice
		// the default ActorLinger idle, M3-D42): a running actor is one
		// goroutine more, so a count taken while one of them happens to run
		// differs by one without a leak (a premise flake of the Linux race
		// lane: 20 against a baseline of 21).
		quietG := func() int {
			time.Sleep(2 * time.Second)
			synctest.Wait()
			return runtime.NumGoroutine()
		}
		baseG := quietG()
		for i := range cycles {
			if l.Kill() != 1 {
				t.Fatalf("cycle %d: the link had no live carrier to cut", i)
			}
			id = settle(fmt.Sprintf("the carrier of cycle %d", i+1), id)
		}
		if g := quietG(); g != baseG {
			buf := make([]byte, 1<<20)
			t.Fatalf("goroutines %d after %d attach/kill cycles, want the baseline %d\n%s", g, cycles, baseG, buf[:runtime.Stack(buf, true)])
		}
		for _, s := range []rendr.SessionStatus{dc.Status(), pc.Status()} {
			if s.Migrations != (rendr.MigrationCounts{Death: uint64(cycles)}) || s.NoPathEpisodes != uint64(cycles) || s.State != rendr.StateOpen {
				t.Fatalf("%v after %d cycles: %+v", s.Role, cycles, s)
			}
			if len(s.Carriers) > 9 {
				t.Fatalf("%v keeps %d carriers in Status, want the live one and at most 8 dead", s.Role, len(s.Carriers))
			}
		}
		if ds := dc.Status(); ds.Rejoins != uint64(cycles) {
			t.Fatalf("dialer rejoins %d, want %d", ds.Rejoins, cycles)
		}
		if st := l.Stats(); st.Session.Killed != int64(cycles) || st.Dials != int64(cycles+1) {
			t.Fatalf("link: %d killed, %d dials; want %d and %d (stimulus)", st.Session.Killed, st.Dials, cycles, cycles+1)
		}
		e3 := startFlow(dc, pc, 1<<20, 521, flowOpts{})
		f3 := startFlow(pc, dc, 1<<20, 522, flowOpts{})
		e3.wait(t, time.Minute, "after the churn")
		f3.wait(t, time.Minute, "after the churn, reverse")
		endClean(t, dc, pc)
		w.close()

		// Every carrier conn, of both ends, was closed exactly once.
		dcl := dconns.closes()
		if len(dcl) != cycles+1 {
			t.Fatalf("dialer conns %d, want %d", len(dcl), cycles+1)
		}
		for i, n := range dcl {
			if n != 1 {
				t.Fatalf("dialer conn %d closed %d times", i, n)
			}
		}
		taps := w.taps.all("a")
		if len(taps) != cycles+1 {
			t.Fatalf("passive conns %d, want %d", len(taps), cycles+1)
		}
		for i, c := range taps {
			if n := c.closes.Load(); n != 1 {
				t.Fatalf("passive conn %d closed %d times", i, n)
			}
		}
	})
}

// TestStatusSnapshotsConsistent_L53 (should): 10,000 snapshots of both ends
// taken while carriers are cut every 100 ms under traffic in both
// directions, and while the session finishes, are each self-consistent and
// never go backwards: at most one active carrier, unique IDs, dead
// carriers (and only they) carry a death cause, no data carrier inside a
// no-path episode, acknowledged ≤ sent and delivered ≤ received, the echo
// never ahead of the epoch, and every counter monotonic; Status never
// blocks, also not during the end.
func TestStatusSnapshotsConsistent_L53(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const snapshots = 10000
		w := newWorld(t, worldOpts{}, "a")
		l := w.link("a")
		l.SetDelay(time.Millisecond, 0)
		dc, pc := w.open(w.peer(nil, l), rendr.DialOptions{})
		const n = 32 << 20
		f := startFlow(dc, pc, n, 530, flowOpts{chunk: 16 << 10, pace: time.Millisecond, closeWrite: true, eof: true})
		g := startFlow(pc, dc, n, 531, flowOpts{chunk: 16 << 10, pace: time.Millisecond, closeWrite: true, eof: true})
		stop := make(chan struct{})
		killed := make(chan int)
		go func() {
			k := 0
			defer func() { killed <- k }()
			for {
				select {
				case <-stop:
					return
				case <-time.After(100 * time.Millisecond):
					k += l.Kill()
				}
			}
		}()
		var prev [2]rendr.SessionStatus
		for i := range snapshots {
			for j, c := range []*rendr.Conn{dc, pc} {
				s := c.Status()
				if err := snapshotConsistent(s); err != nil {
					t.Fatalf("snapshot %d of the %v: %v\n%+v", i, s.Role, err, s)
				}
				if i > 0 {
					if err := snapshotMonotonic(prev[j], s); err != nil {
						t.Fatalf("snapshot %d of the %v: %v\nbefore: %+v\nafter:  %+v", i, s.Role, err, prev[j], s)
					}
				}
				prev[j] = s
			}
			time.Sleep(200 * time.Microsecond)
		}
		close(stop)
		kills := <-killed
		if kills < 10 || prev[0].Migrations.Death < 10 {
			t.Fatalf("%d cuts, %d death migrations during the snapshots (stimulus)", kills, prev[0].Migrations.Death)
		}
		f.wait(t, time.Minute, "forward")
		g.wait(t, time.Minute, "reverse")

		// Snapshots keep coming, consistent, while both ends finish.
		done := make(chan error, 1)
		go func() {
			last := [2]rendr.SessionStatus{dc.Status(), pc.Status()}
			for {
				ended := true
				for j, c := range []*rendr.Conn{dc, pc} {
					s := c.Status()
					if err := snapshotConsistent(s); err != nil {
						done <- fmt.Errorf("%v: %w", s.Role, err)
						return
					}
					if err := snapshotMonotonic(last[j], s); err != nil {
						done <- fmt.Errorf("%v: %w", s.Role, err)
						return
					}
					last[j] = s
					ended = ended && s.State == rendr.StateEnded
				}
				if ended {
					if last[0].Err != io.EOF || last[1].Err != io.EOF {
						done <- fmt.Errorf("ended with %v / %v", last[0].Err, last[1].Err)
					} else {
						done <- nil
					}
					return
				}
				time.Sleep(200 * time.Microsecond)
			}
		}()
		endClean(t, dc, pc)
		if err := <-done; err != nil {
			t.Fatalf("snapshots during the end: %v", err)
		}
		w.close()
	})
}

// snapshotConsistent checks the invariants of one session snapshot.
func snapshotConsistent(s rendr.SessionStatus) error {
	active := 0
	seen := map[rendr.CarrierID]bool{}
	for _, c := range s.Carriers {
		if seen[c.ID] {
			return fmt.Errorf("carrier %d listed twice", c.ID)
		}
		seen[c.ID] = true
		switch c.State {
		case rendr.CarrierActive:
			active++
		case rendr.CarrierDead:
			if c.DeathCause == rendr.CauseNone {
				return fmt.Errorf("dead carrier %d without a cause", c.ID)
			}
			continue
		}
		if c.DeathCause != rendr.CauseNone {
			return fmt.Errorf("%v carrier %d with death cause %v", c.State, c.ID, c.DeathCause)
		}
		if s.InNoPath && (c.State == rendr.CarrierActive || c.State == rendr.CarrierMember) {
			return fmt.Errorf("data carrier %d inside a no-path episode", c.ID)
		}
	}
	switch {
	case active > 1:
		return fmt.Errorf("%d active carriers", active)
	case s.AckedBytes > s.TxBytes:
		return fmt.Errorf("acknowledged %d of %d sent", s.AckedBytes, s.TxBytes)
	case s.DeliveredBytes > s.RxBytes:
		return fmt.Errorf("delivered %d of %d received", s.DeliveredBytes, s.RxBytes)
	case wire.SeqLess(s.SchedEpoch, s.SchedEchoed):
		return fmt.Errorf("echo %d ahead of epoch %d", s.SchedEchoed, s.SchedEpoch)
	case s.State == rendr.StateEnded && s.Err == nil, s.State != rendr.StateEnded && s.Err != nil:
		return fmt.Errorf("state %v with error %v", s.State, s.Err)
	}
	return nil
}

// snapshotMonotonic checks that no counter of a went backwards in b.
func snapshotMonotonic(a, b rendr.SessionStatus) error {
	type pair struct {
		name string
		x, y uint64
	}
	for _, p := range []pair{
		{"death migrations", a.Migrations.Death, b.Migrations.Death},
		{"quality migrations", a.Migrations.Quality, b.Migrations.Quality},
		{"explicit migrations", a.Migrations.Explicit, b.Migrations.Explicit},
		{"rejoins", a.Rejoins, b.Rejoins},
		{"no-path episodes", a.NoPathEpisodes, b.NoPathEpisodes},
		{"sent", a.TxBytes, b.TxBytes},
		{"acknowledged", a.AckedBytes, b.AckedBytes},
		{"received", a.RxBytes, b.RxBytes},
		{"delivered", a.DeliveredBytes, b.DeliveredBytes},
		{"retransmitted", a.RetransmittedBytes, b.RetransmittedBytes},
	} {
		if p.y < p.x {
			return fmt.Errorf("%s went back from %d to %d", p.name, p.x, p.y)
		}
	}
	switch {
	case wire.SeqLess(b.SchedEpoch, a.SchedEpoch):
		return fmt.Errorf("epoch went back from %d to %d", a.SchedEpoch, b.SchedEpoch)
	case wire.SeqLess(b.SchedEchoed, a.SchedEchoed):
		return fmt.Errorf("echo went back from %d to %d", a.SchedEchoed, b.SchedEchoed)
	case b.State < a.State:
		return fmt.Errorf("state went back from %v to %v", a.State, b.State)
	}
	return nil
}
