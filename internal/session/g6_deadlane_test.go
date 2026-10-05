package session

import (
	"context"
	"errors"
	"net"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
	"weak"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Dead-lane retention (design §0.14 B7). The Status history of the last
// dead lanes keeps a carrier only until the step that prunes it from the
// join list after its join, and then its final Stats; the actor prunes
// joined carriers in every step and wakes when the oldest carrier still in
// the join list is joined; a passive lane that dies unconfirmed leaves the
// unconfirmed list at once. So no list of a session keeps a dead
// *carrier.Conn — its writer Batch, timers and embedder conn — reachable
// once it was joined and its session took the step that join wakes, while
// Status keeps reporting the dead carriers as before and the exit still
// waits for every one of them (L52). Package-level helpers of these tests
// start with "g6".

// g6Watch follows one carrier through its death and join: the test holds
// it strongly until release, then only weakly.
type g6Watch struct {
	id    uint32
	conn  *carrier.Conn // strong until release
	done  <-chan struct{}
	wc    weak.Pointer[carrier.Conn]
	wb    weak.Pointer[carrier.Batch]
	final carrier.Stats // its Stats once joined (release)
	// Its death record (release): set once by the carrier, the record the
	// session's death step copies into Status.
	cause  carrier.Cause
	detail string
	at     time.Time
}

// g6Watch1 watches the carrier with CarrierID id among s's lanes.
func g6Watch1(t testing.TB, s *Session, id uint32) *g6Watch {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.lanes {
		if c := l.c; c.ID() == id {
			return &g6Watch{id: id, conn: c, done: c.Done(), wc: weak.Make(c)}
		}
	}
	t.Fatalf("%v session has no lane with carrier %d", s.Role(), id)
	return nil
}

// g6WatchActive watches the active carrier of both ends of a selector pair.
func g6WatchActive(t testing.TB, a, b *Session) (wa, wb *g6Watch) {
	t.Helper()
	id := acActive(a)
	if id == 0 || acActive(b) != id {
		t.Fatalf("active carriers %d and %d, want one shared carrier", id, acActive(b))
	}
	return g6Watch1(t, a, id), g6Watch1(t, b, id)
}

// release waits (virtual time) for the carrier's join, takes its final
// Stats, its death record and a weak pointer to its writer Batch, and
// drops the strong reference. Done orders the writer's exit (and its
// Batch) before these reads.
func (w *g6Watch) release(t testing.TB, within time.Duration) {
	t.Helper()
	select {
	case <-w.done:
	case <-time.After(within):
		t.Fatalf("carrier %d not joined within %v", w.id, within)
	}
	w.final = w.conn.Stats()
	var dead bool
	dead, w.cause, w.detail, w.at = w.conn.Death()
	if !dead {
		t.Fatalf("carrier %d joined without a death record", w.id)
	}
	w.wb = weak.Make(g6BatchOf(t, w.conn))
	w.conn = nil
}

// g6BatchOf returns c's writer Batch (the unexported field wr.b): about
// 14.5 KiB, the largest part of what a retained dead carrier pins.
func g6BatchOf(t testing.TB, c *carrier.Conn) *carrier.Batch {
	t.Helper()
	f := reflect.ValueOf(c).Elem().FieldByName("wr")
	if f.IsValid() {
		f = f.FieldByName("b")
	}
	if !f.IsValid() || f.Kind() != reflect.Pointer || f.IsNil() {
		t.Fatal("carrier.Conn keeps no writer Batch at wr.b: update g6BatchOf")
	}
	return (*carrier.Batch)(f.UnsafePointer())
}

// g6Settle lets every stopped timer of the joined carriers leave the
// bubble's timer heap (a stopped runtime timer stays queued until its old
// due time passes, and it references its callback's carrier until then:
// the write-stall watchdog, the abandonment and drain timers), then waits
// for the bubble to block.
func g6Settle() {
	time.Sleep(3 * time.Second)
	synctest.Wait()
}

// g6Unreachable fails the test if a full collection did not reclaim every
// watched carrier and its writer Batch.
func g6Unreachable(t testing.TB, what string, ws ...*g6Watch) {
	t.Helper()
	runtime.GC()
	runtime.GC()
	var conns, batches []uint32
	for _, w := range ws {
		if w.conn != nil {
			t.Fatalf("%s: carrier %d was never released by the test", what, w.id)
		}
		if w.wc.Value() != nil {
			conns = append(conns, w.id)
		}
		if w.wb.Value() != nil {
			batches = append(batches, w.id)
		}
	}
	if len(conns) > 0 || len(batches) > 0 {
		t.Fatalf("%s: after their join, %d of %d dead carriers %v and %d writer Batches %v are still reachable",
			what, len(conns), len(ws), g6First(conns), len(batches), g6First(batches))
	}
}

// g6First returns at most the first 8 of ids (for messages).
func g6First(ids []uint32) []uint32 {
	return ids[:min(len(ids), 8)]
}

// g6CheckDead checks that st lists exactly the watched (released) carriers
// ws as its dead ones, after every live one and oldest first, each with
// the death record its carrier holds (cause, detail and time) and its
// final Stats; unless cause is CauseNone, each also died of cause, with a
// death time and a detail.
func g6CheckDead(t testing.TB, side string, st Status, cause carrier.Cause, ws ...*g6Watch) {
	t.Helper()
	var dead []CarrierStatus
	for _, cs := range st.Carriers {
		if cs.State == LaneDead {
			dead = append(dead, cs)
		} else if len(dead) > 0 {
			t.Fatalf("%s: live carrier %d listed after a dead one: %+v", side, cs.ID, st.Carriers)
		}
	}
	if len(dead) != len(ws) {
		t.Fatalf("%s: %d dead carriers in Status, want %d: %+v", side, len(dead), len(ws), st.Carriers)
	}
	for i, d := range dead {
		w := ws[i]
		switch {
		case d.ID != w.id:
			t.Fatalf("%s: dead carrier #%d is %d, want %d (oldest first): %+v", side, i, d.ID, w.id, st.Carriers)
		case cause != carrier.CauseNone && (d.DeathCause != cause || d.DeathAt.IsZero() || d.DeathDetail == ""):
			t.Fatalf("%s: dead carrier %d: cause %v at %v (%q), want %v", side, d.ID, d.DeathCause, d.DeathAt, d.DeathDetail, cause)
		case d.DeathCause != w.cause || d.DeathDetail != w.detail || !d.DeathAt.Equal(w.at) || d.DeathAt.IsZero():
			t.Fatalf("%s: dead carrier %d: cause %v at %v (%q), want its own death record %v at %v (%q)",
				side, d.ID, d.DeathCause, d.DeathAt, d.DeathDetail, w.cause, w.at, w.detail)
		case d.Stats != w.final:
			t.Fatalf("%s: dead carrier %d reports %+v, want its final Stats %+v", side, d.ID, d.Stats, w.final)
		}
	}
}

// g6StuckClose is an embedder conn whose Close blocks until release is
// closed: the carrier's closer is abandoned AbandonWait after the death and
// the carrier is joined then, long after its session moved on and went
// idle.
type g6StuckClose struct {
	net.Conn
	release <-chan struct{}
}

func (c *g6StuckClose) Close() error {
	<-c.release
	return c.Conn.Close()
}

// g6OpenStuckFirst opens a selector pair over l1 whose first carrier's
// embedder conn on the dialer blocks in Close (g6StuckClose) until unblock
// is called. unblock is idempotent; the caller defers it after
// w.teardown, so the stuck Close returns before the bubble ends also when
// the test fails.
func g6OpenStuckFirst(w *acWorld, l1 *rendrtest.Link) (a, b *Session, unblock func()) {
	release := make(chan struct{})
	var once sync.Once
	unblock = func() { once.Do(func() { close(release) }) }
	var wrapped atomic.Bool
	f := carrier.Factory{Name: l1.Name(), Dial: func(ctx context.Context) (net.Conn, error) {
		c, err := l1.Dial(ctx)
		if err == nil && wrapped.CompareAndSwap(false, true) {
			return &g6StuckClose{Conn: c, release: release}, nil
		}
		return c, err
	}}
	w.sid++
	p := w.a.p
	p.Mode = ModeSelector
	a, b = w.openSpec(DialSpec{SID: [16]byte{0xD6, w.sid}, Params: p, Factories: []carrier.Factory{f}}, nil)
	return a, b, unblock
}

// g6PipePath is a factory over net.Pipe straight into the passive shim. It
// keeps no history of its carriers (a rendrtest.Link keeps every carrier
// it made, which a heap measurement would count): only the dialer's end of
// the latest pipe, which cut closes.
type g6PipePath struct {
	p   *acPassive
	mu  sync.Mutex
	cur net.Conn
}

func (pp *g6PipePath) dial(ctx context.Context) (net.Conn, error) {
	c1, c2 := net.Pipe()
	_ = pp.p.accept(c2) // never fails: its handshake goroutine owns c2
	pp.mu.Lock()
	pp.cur = c1
	pp.mu.Unlock()
	return c1, nil
}

// cut closes the latest pipe: both ends' carriers read EOF and die.
func (pp *g6PipePath) cut() {
	pp.mu.Lock()
	c := pp.cur
	pp.cur = nil
	pp.mu.Unlock()
	if c != nil {
		_ = c.Close()
	}
}

// g6OpenPipePairs opens n single-carrier selector pairs, each over its own
// pipe path.
func g6OpenPipePairs(w *acWorld, n int) (paths []*g6PipePath, dialers, passives []*Session) {
	paths = make([]*g6PipePath, n)
	dialers = make([]*Session, n)
	passives = make([]*Session, n)
	for i := range paths {
		paths[i] = &g6PipePath{p: w.b}
		w.sid++
		p := w.a.p
		p.Mode = ModeSelector
		spec := DialSpec{SID: [16]byte{0xD6, w.sid, byte(i)}, Params: p, Factories: []carrier.Factory{{Name: "pipe", Dial: paths[i].dial}}}
		dialers[i], passives[i] = w.openSpec(spec, nil)
	}
	return paths, dialers, passives
}

// g6CutRound cuts every pair's carrier and waits until each pair runs on a
// new one on both ends.
func g6CutRound(t testing.TB, paths []*g6PipePath, dialers, passives []*Session) {
	t.Helper()
	old := make([]uint32, len(dialers))
	for i, a := range dialers {
		old[i] = acActive(a)
		if old[i] == 0 {
			t.Fatalf("pair %d has no active carrier before the cut", i)
		}
		paths[i].cut()
	}
	acWaitFor(t, 10*time.Second, "every pair recovered on a new carrier", func() bool {
		for i, a := range dialers {
			id := acActive(a)
			if id == 0 || id == old[i] || acActive(passives[i]) != id {
				return false
			}
		}
		return true
	})
}

// TestG6DeadCarrierReleasedAtJoin_L52_L53: once a dead carrier is joined
// and its session took the step that join wakes, no list of the session
// keeps it — nor its writer Batch — reachable, and Status still lists it
// among the dead ones with its final Stats (design §0.14 B7; was: the
// dead-lane history pinned the last 8 carriers and the join list up to
// 16). No carrier leaves the join list before it is joined: the exit
// still waits for each (L52).
func TestG6DeadCarrierReleasedAtJoin_L52_L53(t *testing.T) {
	// late-join: the dialer's carrier dies with a transfer behind it, and
	// its embedder Close blocks, so it is joined only at AbandonWait, after
	// its session moved to a new carrier and went idle. The actor wakes at
	// that join by itself and lets the carrier go.
	t.Run("late-join", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := acNewWorld(t, nil)
			defer w.teardown()
			l1 := w.link("p1")
			a, b, unblock := g6OpenStuckFirst(w, l1)
			defer unblock() // before the teardown
			if we, re := acTransfer(a, b, 256<<10, 61, false); we != nil || re != nil {
				t.Fatalf("transfer a→b: %v %v", we, re)
			}
			if we, re := acTransfer(b, a, 256<<10, 62, false); we != nil || re != nil {
				t.Fatalf("transfer b→a: %v %v", we, re)
			}
			wa, wb := g6WatchActive(t, a, b)
			cut := time.Now()
			if n := l1.Kill(); n != 1 {
				t.Fatalf("Kill closed %d carriers, want 1 (stimulus)", n)
			}
			acWaitFor(t, 5*time.Second, "the pair runs on a new carrier", func() bool {
				id := acActive(a)
				return id != 0 && id != wa.id && acActive(b) == id
			})
			select {
			case <-wa.done:
				t.Fatal("the dialer's dead carrier was joined while its Close blocked (stimulus)")
			default:
			}
			if d := g6DeadIDs(a.Status()); len(d) != 1 || d[0] != wa.id {
				t.Fatalf("dialer Status lists dead carriers %v before the join, want [%d]", d, wa.id)
			}
			wa.release(t, 5*time.Second)
			if d, aw := time.Since(cut), w.a.cenv.Timing.AbandonWait; d < aw {
				t.Fatalf("the dialer's dead carrier was joined %v after the cut, want its abandoned Close at AbandonWait %v (stimulus)", d, aw)
			}
			unblock() // the abandoned Close returns and its closer exits
			wb.release(t, 5*time.Second)
			g6Settle()
			if wa.final.TxBytes == 0 || wa.final.RxBytes == 0 || wb.final.TxBytes == 0 || wb.final.RxBytes == 0 {
				t.Fatalf("the dead carriers moved no data (load): dialer %+v, passive %+v", wa.final, wb.final)
			}
			g6CheckDead(t, "dialer", a.Status(), carrier.CauseTransportError, wa)
			g6CheckDead(t, "passive", b.Status(), carrier.CauseTransportError, wb)
			g6Unreachable(t, "late-join", wa, wb)
			if n := w.a.cenv.Abandon.Len(); n != 0 {
				t.Fatalf("abandoned pool %d after the Close returned, want 0", n)
			}
		})
	})

	// dead-before-end: every step prunes the join list, yet a carrier that
	// died while its session was open stays in it until it is joined, so
	// the session's exit still waits for it (L52). The dialer's dead
	// carrier is stuck in its embedder Close when the session is shut
	// down: Session.Done closes at that carrier's join, AbandonWait after
	// its death, and not before. Once both sessions ended, their final
	// Status lists every carrier with its final Stats, and none of them
	// stays reachable while the application still holds the sessions.
	t.Run("dead-before-end", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := acNewWorld(t, nil)
			defer w.teardown()
			l1 := w.link("p1")
			a, b, unblock := g6OpenStuckFirst(w, l1)
			defer unblock() // before the teardown
			wa1, wb1 := g6WatchActive(t, a, b)
			cut := time.Now()
			if n := l1.Kill(); n != 1 {
				t.Fatalf("Kill closed %d carriers, want 1 (stimulus)", n)
			}
			acWaitFor(t, 5*time.Second, "the pair runs on a new carrier", func() bool {
				id := acActive(a)
				return id != 0 && id != wa1.id && acActive(b) == id
			})
			wa2, wb2 := g6WatchActive(t, a, b)
			joinedAt := make(chan time.Time, 1)
			go func() {
				<-wa1.done
				joinedAt <- time.Now()
			}()
			select {
			case <-wa1.done:
				t.Fatal("the dialer's dead carrier was joined while its Close blocked (stimulus)")
			default:
			}
			if d := g6DeadIDs(a.Status()); len(d) != 1 || d[0] != wa1.id {
				t.Fatalf("dialer Status lists dead carriers %v before Shutdown, want [%d] (stimulus)", d, wa1.id)
			}
			a.Shutdown()
			acDone(t, a, 5*time.Second)
			select {
			case <-wa1.done:
			default:
				t.Fatalf("Session.Done closed %v after the cut while its dead carrier %d was not joined (L52)", time.Since(cut), wa1.id)
			}
			synctest.Wait() // the join's watcher ran
			var at time.Time
			select {
			case at = <-joinedAt:
			default:
				t.Fatal("the join's watcher did not run")
			}
			if d, aw := at.Sub(cut), w.a.cenv.Timing.AbandonWait; d < aw {
				t.Fatalf("the dialer's dead carrier was joined %v after the cut, want its abandoned Close at AbandonWait %v (stimulus)", d, aw)
			}
			if d := time.Since(at); d > 10*time.Millisecond {
				t.Fatalf("Session.Done %v after its dead carrier's join, want at once", d)
			}
			acDone(t, b, 5*time.Second) // the passive ends on the dialer's going-away abort
			var ae *AbortError
			if err := b.Status().Err; !errors.As(err, &ae) || ae.Code != AbortGoingAway || !ae.Remote {
				t.Fatalf("passive ended with %v, want the dialer's going-away abort (stimulus)", err)
			}
			for _, wt := range []*g6Watch{wa1, wa2, wb1, wb2} {
				wt.release(t, 5*time.Second)
			}
			unblock() // the abandoned Close returns and its closer exits
			g6Settle()
			if wa1.cause != carrier.CauseTransportError || wb1.cause != carrier.CauseTransportError {
				t.Fatalf("the cut carriers died of %v and %v, want transport_error (stimulus)", wa1.cause, wb1.cause)
			}
			g6CheckDead(t, "dialer", a.Status(), carrier.CauseNone, wa1, wa2)
			g6CheckDead(t, "passive", b.Status(), carrier.CauseNone, wb1, wb2)
			g6Unreachable(t, "dead-before-end", wa1, wa2, wb1, wb2)
			if n := w.a.cenv.Abandon.Len(); n != 0 {
				t.Fatalf("abandoned pool %d after the Close returned, want 0", n)
			}
		})
	})

	// pending-parked: a pending passive session parks a duplicate OPEN's
	// carrier until its verdict; when that carrier dies, the lane is not
	// confirmed and never will be, yet nothing keeps it reachable after its
	// join (the session stays pending all along).
	t.Run("pending-parked", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := acNewWorld(t, nil)
			defer w.teardown()
			w.a.cenv.Timing.DialTimeout = 30 * time.Second // the first OPEN waits for the verdict
			l1, l2 := w.link("p1"), w.link("p2")
			spec := w.spec(ModeSelector, l1, l2)
			type res struct {
				s   *Session
				err error
			}
			ch := make(chan res, 1)
			go func() {
				s, err := w.dial(context.Background(), spec, nil)
				ch <- res{s, err}
			}()
			b := <-w.b.pending
			w.sess = append(w.sess, b)
			acWaitFor(t, 5*time.Second, "a duplicate OPEN parked on the pending session", func() bool {
				b.mu.Lock()
				defer b.mu.Unlock()
				return len(b.lanes) == 2
			})
			b.mu.Lock()
			first, second := b.lanes[0].id, b.lanes[1].id // attach order
			b.mu.Unlock()
			parked := g6Watch1(t, b, second)
			l2.SetRefuse(true)
			if n := l2.Kill(); n != 1 {
				t.Fatalf("Kill closed %d carriers on the second path, want 1 (stimulus)", n)
			}
			parked.release(t, 5*time.Second)
			g6Settle()
			st := b.Status()
			if st.State != StatePending {
				t.Fatalf("passive state %v, want pending (stimulus)", st.State)
			}
			if live := len(st.Carriers) - len(g6DeadIDs(st)); live != 1 || st.Carriers[0].ID != first {
				t.Fatalf("passive carriers %+v, want the first OPEN's %d alive and the parked one dead", st.Carriers, first)
			}
			g6CheckDead(t, "passive", st, carrier.CauseTransportError, parked)
			g6Unreachable(t, "pending-parked", parked)
			if err := b.Confirm(); err != nil {
				t.Fatalf("Confirm: %v", err)
			}
			if r := <-ch; r.err != nil {
				t.Fatalf("Dial: %v", r.err)
			}
		})
	})

	// churn: every carrier of 8 pairs is cut 16 times. Not one of the 128
	// dead carriers of either side stays reachable, and Status keeps
	// exactly the last 8 of each session, oldest first, each with its final
	// Stats.
	t.Run("churn", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			const pairs, cuts = 8, 16
			w := acNewWorld(t, nil)
			defer w.teardown()
			paths, dialers, passives := g6OpenPipePairs(w, pairs)
			hist := make([][2][]*g6Watch, pairs)
			for range cuts {
				round := make([][2]*g6Watch, pairs)
				for i := range pairs {
					wa, wb := g6WatchActive(t, dialers[i], passives[i])
					round[i] = [2]*g6Watch{wa, wb}
				}
				g6CutRound(t, paths, dialers, passives)
				for i := range pairs {
					for k, wt := range round[i] {
						wt.release(t, 5*time.Second)
						hist[i][k] = append(hist[i][k], wt)
					}
				}
			}
			g6Settle()
			var all []*g6Watch
			for i := range pairs {
				g6CheckDead(t, "dialer", dialers[i].Status(), carrier.CauseTransportError, hist[i][0][cuts-maxDeadLanes:]...)
				g6CheckDead(t, "passive", passives[i].Status(), carrier.CauseTransportError, hist[i][1][cuts-maxDeadLanes:]...)
				all = append(append(all, hist[i][0]...), hist[i][1]...)
			}
			g6Unreachable(t, "churn", all...)
		})
	})
}

// g6DeadIDs returns the IDs of the dead carriers of st, in order.
func g6DeadIDs(st Status) []uint32 {
	var out []uint32
	for _, cs := range st.Carriers {
		if cs.State == LaneDead {
			out = append(out, cs.ID)
		}
	}
	return out
}

// g6Heap returns the live heap after full collections (the buffer pools are
// sync.Pools: two collections empty them).
func g6Heap() uint64 {
	for range 3 {
		runtime.GC()
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// TestG6ChurnRetainedHeapBounded_L52: 32 single-carrier pairs, each
// carrier cut 16 times (pipes: no link history). After 8 and after 16 cuts
// the heap one pair retains stays within g6RetainBound — measured: about
// 8 to 9 KiB, the two full 8-entry dead-lane histories and the snapshots
// that list them; before the fix (089ba88) about 607 KiB after 16 cuts,
// the last 8 dead carriers and up to 16 unpruned joined ones per side,
// each with its writer Batch — and the last 8 cuts, made once every
// history is full, add at most g6GrowBound per pair (measured: 0.0 KiB;
// before the fix about 301 KiB).
func TestG6ChurnRetainedHeapBounded_L52(t *testing.T) {
	// One P: per-P runtime caches (free goroutine descriptors, the timer
	// heap's capacity) would otherwise add up to tens of KiB per pair of
	// noise that grows with GOMAXPROCS.
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	synctest.Test(t, func(t *testing.T) {
		const pairs, cuts = 32, 16
		w := acNewWorld(t, nil)
		defer w.teardown()
		w.a.env.Events, w.b.env.Events = nil, nil // the test recorder keeps every event
		paths, dialers, passives := g6OpenPipePairs(w, pairs)
		g6Settle()
		h0 := g6Heap()
		var h8 uint64
		for r := range cuts {
			g6CutRound(t, paths, dialers, passives)
			g6Settle()
			if r == cuts/2-1 {
				h8 = g6Heap()
			}
		}
		h16 := g6Heap()
		for i := range pairs {
			if a, b := dialers[i].Status(), passives[i].Status(); a.MigDeath != cuts || len(g6DeadIDs(a)) != maxDeadLanes || len(g6DeadIDs(b)) != maxDeadLanes {
				t.Fatalf("pair %d: %d death migrations, %d and %d dead carriers listed; want %d cuts and full histories (stimulus)", i, a.MigDeath, len(g6DeadIDs(a)), len(g6DeadIDs(b)), cuts)
			}
		}
		per := func(from, to uint64) float64 { return (float64(to) - float64(from)) / pairs / 1024 }
		t.Logf("retained per pair after %d cuts: %+.1f KiB, after %d: %+.1f KiB", cuts/2, per(h0, h8), cuts, per(h0, h16))
		for _, m := range []struct {
			n int
			h uint64
		}{{cuts / 2, h8}, {cuts, h16}} {
			if r := per(h0, m.h); r > g6RetainBound {
				t.Errorf("a pair retains %.1f KiB after %d cuts of its carrier, want at most %d KiB", r, m.n, g6RetainBound)
			}
		}
		if g := per(h8, h16); g > g6GrowBound {
			t.Errorf("the last %d cuts grew a pair's heap by %.1f KiB, want at most %d KiB", cuts/2, g, g6GrowBound)
		}
	})
}

// Bounds of TestG6ChurnRetainedHeapBounded_L52 (KiB per pair).
const (
	g6RetainBound = 16
	g6GrowBound   = 2
)
