package session

import (
	"runtime"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Stale incarnations and routing consistency (design §7.3; L21, L27, C1).

// acGate holds a hook until released: armed for one carrier ID (or the
// first call when id is 0 and any is set).
type acGate struct {
	armed   atomic.Bool
	any     bool
	id      atomic.Uint32
	held    chan uint32   // receives the ID once the hook is held
	release chan struct{} // closed by the test
}

func acNewGate() *acGate {
	return &acGate{held: make(chan uint32, 1), release: make(chan struct{})}
}

// arm holds the next call for id (any call when any).
func (g *acGate) arm(id uint32, any bool) {
	g.id.Store(id)
	g.any = any
	g.armed.Store(true)
}

func (g *acGate) hook(id uint32) {
	if !g.armed.Load() || (!g.any && id != g.id.Load()) {
		return
	}
	if !g.armed.CompareAndSwap(true, false) {
		return
	}
	g.held <- id
	<-g.release
}

// TestStaleDeathCannotTouchSuccessor_L21: the active carrier A dies; the
// race's first attempt (factory p2) is established but its result is held
// (Hooks.DialResult) while the race's next attempt — a redial of A's own
// factory, A' — attaches and becomes active (one death migration). Then p2's
// link is killed and the stale result released: it attaches as a race loser
// and dies at once; that death is held too (Hooks.DeathObserved) while the
// successor is checked, then released. A' stays active and the death of A
// stays the only migration.
func TestStaleDeathCannotTouchSuccessor_L21(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		results, deaths := acNewGate(), acNewGate()
		w := acNewWorld(t, &testhooks.Hooks{DialResult: results.hook, DeathObserved: deaths.hook})
		defer w.teardown()
		l1, l2 := w.link("p1"), w.link("p2")
		a, b := w.open(ModeSelector, nil, l1, l2)
		first := acActive(a)

		results.arm(0, true) // hold the first result after the death: the race starts with p2 (p1 is failed)
		l1.Kill()
		held := <-results.held
		synctest.Wait()
		joining := false
		for _, c := range a.Status().Carriers {
			joining = joining || (c.ID == held && c.State == LaneJoining && c.Name == "p2")
		}
		if !joining {
			t.Fatalf("the held attempt %d is not reported as joining: %+v", held, a.Status().Carriers)
		}
		acWaitFor(t, 2*time.Second, "A' attached", func() bool {
			id := acActive(a)
			return id != 0 && id != first && id != held
		})
		succ := acActive(a)
		if st := a.Status(); st.MigDeath != 1 || st.Carriers[0].Name != "p1" {
			t.Fatalf("successor: %+v, want A' on p1 after one death migration", st)
		}

		l2.Kill() // the held result's carrier is dead before the actor sees the result
		deaths.arm(held, false)
		close(results.release)
		if id := <-deaths.held; id != held {
			t.Fatalf("held death of %d, want the stale incarnation %d", id, held)
		}
		// The actor waits in the hook: the published routing is A'.
		if got := acActive(a); got != succ {
			t.Fatalf("while the stale death is held: active %d, want %d", got, succ)
		}
		close(deaths.release)
		synctest.Wait()
		if got := acActive(a); got != succ {
			t.Fatalf("after the stale death: active %d, want %d", got, succ)
		}
		st := a.Status()
		if st.MigDeath != 1 || st.MigExplicit+st.MigQuality != 0 {
			t.Fatalf("migrations %d/%d/%d, want the one death migration", st.MigDeath, st.MigQuality, st.MigExplicit)
		}
		for _, c := range st.Carriers {
			if c.ID == held && (c.State != LaneDead || !c.DeathCause.Death()) {
				t.Fatalf("stale incarnation %+v, want dead with a death cause", c)
			}
		}
		if we, re := acTransfer(a, b, 1<<20, 6, false); we != nil || re != nil {
			t.Fatalf("transfer on the successor: %v %v", we, re)
		}
	})
}

// TestReportedActiveEqualsRouting_L27: across 200 deaths of the active
// carrier, the test goroutine takes each session's lock as often as it can
// while the actors reroute (in parallel with them: the failovers need no
// virtual time) and never finds the reported active carrier (the published
// snapshot) different from the routed one (lane.data, ctl.active), on
// either end.
func TestReportedActiveEqualsRouting_L27(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := acNewWorld(t, nil)
		defer w.teardown()
		var links []*rendrtest.Link
		for _, n := range []string{"p1", "p2", "p3"} {
			links = append(links, w.link(n))
		}
		a, b := w.open(ModeSelector, nil, links...)
		checks := 0
		check := func(i int, s *Session) {
			rep, routed, n := acRouted(s)
			checks++
			if rep != routed || n > 1 || (routed == 0) != (n == 0) {
				t.Fatalf("death %d, %v: reported active %d, routed %d, %d data lanes", i, s.Role(), rep, routed, n)
			}
		}
		for i := range 200 {
			synctest.Wait()
			id := acActive(a)
			for _, c := range a.Status().Carriers {
				if c.ID == id {
					links[c.Name[1]-'1'].Kill()
				}
			}
			for spin := 0; ; spin++ {
				check(i, a)
				check(i, b)
				if n := acActive(a); n != 0 && n != id {
					break
				}
				if spin == 1e6 {
					t.Fatalf("death %d: no new active carrier", i)
				}
				runtime.Gosched()
			}
		}
		synctest.Wait()
		check(200, a)
		check(200, b)
		if st, bs := a.Status(), b.Status(); st.MigDeath != 200 || bs.MigDeath != 200 {
			t.Fatalf("death migrations: dialer %d, passive %d, want 200 each", st.MigDeath, bs.MigDeath)
		}
		if checks < 1000 {
			t.Fatalf("only %d consistency checks", checks)
		}
		if we, re := acTransfer(a, b, 256<<10, 7, false); we != nil || re != nil {
			t.Fatalf("transfer: %v %v", we, re)
		}
	})
}

// TestDeathStepVsDyingWriterFill_L27: the active carrier dies while the
// session holds unsent data and a requested FIN. While the death step is
// held (Hooks.DeathObserved) the dying lane's Fill — a writer round already
// running when the carrier was killed — pulls the DATA and the FIN into a
// batch that is never written; the death step then requeues both (C1), a
// Fill after it appends nothing, and every byte and the FIN arrive through
// the successor.
func TestDeathStepVsDyingWriterFill_L27(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		deaths := acNewGate()
		w := acNewWorld(t, &testhooks.Hooks{DeathObserved: deaths.hook})
		defer w.teardown()
		l1, l2 := w.link("p1"), w.link("p2")
		a, b := w.open(ModeSelector, nil, l1, l2)
		a.mu.Lock()
		dying := a.ctl.active
		a.mu.Unlock()

		deaths.arm(dying.id, false)
		l1.Kill()
		<-deaths.held
		const n = 100 << 10
		if err := acWritePRNG(a, n, 8); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := a.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite: %v", err)
		}
		before := carrier.NewBatch(256 << 10)
		before.Reset(time.Now())
		dying.Fill(dying.c, before)
		var data, fins int
		for i := range before.Len() {
			switch f := before.Frame(i); f.Header.Type {
			case wire.TypeData:
				data += len(f.Body)
			case wire.TypeFin:
				fins++
			}
		}
		before.ReleaseRefs()
		if data != n || fins != 1 {
			t.Fatalf("the dying lane's Fill pulled %d DATA bytes and %d FINs, want %d and 1 (stimulus)", data, fins, n)
		}

		close(deaths.release)
		synctest.Wait()
		after := carrier.NewBatch(256 << 10)
		after.Reset(time.Now())
		dying.Fill(dying.c, after)
		if after.Len() != 0 {
			t.Fatalf("Fill after the death step appended %d frames", after.Len())
		}
		v := rendrtest.NewVerifier(8, n)
		if err := v.ReadAll(b); err != nil {
			t.Fatalf("passive read: %v", err)
		}
		if l2.Stats().Session.Bytes < n {
			t.Fatal("the successor did not carry the replay")
		}
		if st := a.Status(); st.MigDeath != 1 || st.RetransmittedBytes < n {
			t.Fatalf("dialer: %d death migrations, %d retransmitted bytes", st.MigDeath, st.RetransmittedBytes)
		}
	})
}
