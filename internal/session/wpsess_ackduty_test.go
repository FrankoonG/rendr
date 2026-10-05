package session

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The passive's ACK duty follows the applied SCHED (design §0.13 A7 (c),
// M1c). After a death that only the dialer detects — one-way loss on the
// duty lane: the dialer's PINGs go unanswered while the passive's own death
// deadline (up to DeadMax) has not expired and the dialer's close never
// reaches it — the dialer fails over and publishes a SCHED without that
// lane. The passive applies it and moves its sending at once (L45); its
// ACKs must move with it: an ACK left on the abandoned lane is lost, so
// the dialer's acknowledged front and send window stall until the passive
// detects the death itself. Package-level helpers of this file start with
// "wpsess".

// wpsessApplySched applies SCHED{epoch, ids} to the passive stream s as the
// actor's applySchedLocked does for the ACK path (routing is the actor's
// and not exercised here): the applied set and epoch, then the urgent bump
// that echoes the epoch.
func wpsessApplySched(s *Session, epoch uint32, ids ...uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	set := wire.Sched{Epoch: epoch, N: len(ids)}
	copy(set.IDs[:], ids)
	s.ctl.epoch, s.ctl.set = epoch, set
	s.bumpAckLocked(true)
}

// wpsessAckOf returns the ACK a Fill of l places now (ok false: none).
func wpsessAckOf(l *lane) (a wire.Ack, ok bool) {
	fs, b := stFill(l, time.Now())
	b.ReleaseRefs()
	for _, f := range fs {
		if f.typ == wire.TypeAck {
			return f.ack, true
		}
	}
	return wire.Ack{}, false
}

// TestWpsessAckDutyFollowsSched_L45: on the passive, applying a SCHED that
// no longer lists the duty lane hands the duty to a listed lane at the
// SCHED's own urgent bump — the listed lane is woken and its next Fill
// places the ACK echoing that epoch, the dropped lane's places none —
// although the dropped lane still qualifies and has the lower srtt. A
// dropped lane ranks like a retiring one: it carries the duty only while
// no listed lane is writable (an ACK never waits behind a blocked carrier
// while a writable lane qualifies), and gives it back at the next bump. A
// bond passive follows its SCHED's member list the same way. The dialer's
// duty does not follow its own published set.
func TestWpsessAckDutyFollowsSched_L45(t *testing.T) {
	duty := func(s *Session) *lane { return stLocked(s, func(st *stream) *lane { return st.ackLane }) }
	setup := func(role Role, mode Mode) (s *Session, la, lb *lane, pa, pb *stPort) {
		s = stSession(stOpt{role: role, mode: mode})
		la, pa = stAddLane(s, 1, true)
		lb, pb = stAddLane(s, 2, mode == ModeBond) // a bond member; the selector's standby
		pa.set(func(f *stPort) { f.srtt = time.Millisecond })
		pb.set(func(f *stPort) { f.srtt = 5 * time.Millisecond })
		s.mu.Lock()
		s.refreshOrderLocked(time.Now(), true)
		s.st.ackLane = nil
		s.ensureAckLaneLocked()
		s.mu.Unlock()
		if duty(s) != la {
			t.Fatal("A, the lowest-srtt lane, does not hold the duty")
		}
		return s, la, lb, pa, pb
	}

	t.Run("passive", func(t *testing.T) {
		s, la, lb, _, pb := setup(RolePassive, ModeSelector)
		defer stEnd(s, errClosed)
		wpsessApplySched(s, 1, la.id) // the initial SCHED lists A: nothing moves
		if duty(s) != la {
			t.Fatal("the duty left A, which the applied SCHED lists")
		}
		if a, ok := wpsessAckOf(la); !ok || a.EpochEcho != 1 {
			t.Fatalf("A's Fill placed ACK %+v (%v), want the echo of epoch 1", a, ok)
		}
		if _, ok := wpsessAckOf(lb); ok { // B's writer finds nothing: it sleeps until woken
			t.Fatal("B placed an ACK without the duty")
		}
		wakes := pb.wakeCount()
		wpsessApplySched(s, 2, lb.id) // the dialer abandoned A
		if duty(s) != lb {
			t.Fatal("the duty stayed on A after a SCHED that no longer lists it")
		}
		if pb.wakeCount() == wakes {
			t.Fatal("B, the new duty lane, was not woken for the echo")
		}
		if a, ok := wpsessAckOf(lb); !ok || a.EpochEcho != 2 {
			t.Fatalf("B's Fill placed ACK %+v (%v), want the echo of epoch 2", a, ok)
		}
		if a, ok := wpsessAckOf(la); ok {
			t.Fatalf("A's Fill placed ACK %+v: A was dropped by the applied SCHED", a)
		}
		pb.set(func(f *stPort) { f.blocked = true })
		lb.WriteBlocked(nil)
		if duty(s) != la {
			t.Fatal("B's writer blocked but the duty did not move to A, the writable dropped lane")
		}
		pb.set(func(f *stPort) { f.blocked = false })
		s.mu.Lock()
		s.bumpNowLocked()
		s.mu.Unlock()
		if duty(s) != lb {
			t.Fatal("B is writable again but the duty stayed on the dropped lane A")
		}
		wpsessApplySched(s, 3, la.id) // the dialer is back on A
		if duty(s) != la {
			t.Fatal("the duty stayed on B after a SCHED that no longer lists it")
		}
	})

	t.Run("passive-bond", func(t *testing.T) {
		s, la, lb, _, pb := setup(RolePassive, ModeBond)
		defer stEnd(s, errClosed)
		wpsessApplySched(s, 1, la.id, lb.id) // both members listed: nothing moves
		if duty(s) != la {
			t.Fatal("the duty left member A, which the applied SCHED lists")
		}
		if a, ok := wpsessAckOf(la); !ok || a.EpochEcho != 1 {
			t.Fatalf("A's Fill placed ACK %+v (%v), want the echo of epoch 1", a, ok)
		}
		if _, ok := wpsessAckOf(lb); ok { // B's writer finds nothing: it sleeps until woken
			t.Fatal("B placed an ACK without the duty")
		}
		wakes := pb.wakeCount()
		wpsessApplySched(s, 2, lb.id) // the dialer dropped member A
		if duty(s) != lb {
			t.Fatal("the duty stayed on member A after a SCHED that no longer lists it")
		}
		if pb.wakeCount() == wakes {
			t.Fatal("B, the new duty lane, was not woken for the echo")
		}
		if a, ok := wpsessAckOf(lb); !ok || a.EpochEcho != 2 {
			t.Fatalf("B's Fill placed ACK %+v (%v), want the echo of epoch 2", a, ok)
		}
		if a, ok := wpsessAckOf(la); ok {
			t.Fatalf("A's Fill placed ACK %+v: A was dropped by the applied SCHED", a)
		}
		wpsessApplySched(s, 3, la.id, lb.id) // A is a member again: B, listed, keeps the duty
		if duty(s) != lb {
			t.Fatal("the duty left B, which the applied SCHED still lists")
		}
	})

	t.Run("dialer", func(t *testing.T) {
		s, la, lb, _, _ := setup(RoleDialer, ModeSelector)
		defer stEnd(s, errClosed)
		wpsessApplySched(s, 1, lb.id) // the dialer's own published set
		if duty(s) != la {
			t.Fatal("the dialer's duty followed its published set")
		}
	})
}

// wpsessLossyConn is the passive's end of a carrier whose passive-to-dialer
// direction fails silently: once lossy is set, every Write reports success
// and forwards nothing (whole writes, so no partial frame is ever seen).
type wpsessLossyConn struct {
	net.Conn
	lossy     *atomic.Bool
	swallowed *atomic.Int64
}

func (c *wpsessLossyConn) Write(p []byte) (int, error) {
	if c.lossy.Load() {
		c.swallowed.Add(int64(len(p)))
		return len(p), nil
	}
	return c.Conn.Write(p)
}

// wpsessMuteCloseConn is the dialer's end of a carrier whose close never
// reaches the passive (an L7 relay that keeps its far side open, or a path
// that also loses the FIN): once mute is set, Close only cuts this end off
// with a past deadline. The Link closes the conn's far ends when the test
// ends.
type wpsessMuteCloseConn struct {
	net.Conn
	mute *atomic.Bool
}

func (c *wpsessMuteCloseConn) Close() error {
	if c.mute.Load() {
		return c.Conn.SetDeadline(time.Unix(1, 0))
	}
	return c.Conn.Close()
}

// wpsessFlow streams PRNG(seed) from w to r until stopped, then
// half-closes; the reader verifies every byte up to io.EOF.
type wpsessFlow struct {
	stop       chan struct{}
	once       sync.Once
	done       chan struct{}
	werr, rerr error
}

func wpsessStartFlow(w, r *Session, seed uint64) *wpsessFlow {
	f := &wpsessFlow{stop: make(chan struct{}), done: make(chan struct{})}
	var wg sync.WaitGroup
	var sent atomic.Int64
	wg.Add(2)
	go func() {
		defer wg.Done()
		g := rendrtest.PRNG(seed)
		buf := make([]byte, 32<<10)
		for {
			select {
			case <-f.stop:
				f.werr = w.CloseWrite()
				return
			default:
			}
			g.Read(buf)
			n, err := w.Write(buf)
			sent.Add(int64(n))
			if err != nil {
				f.werr = fmt.Errorf("write after %d bytes: %w", sent.Load(), err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		want := rendrtest.PRNG(seed)
		buf, exp := make([]byte, 64<<10), make([]byte, 64<<10)
		var got int64
		for {
			k, err := r.Read(buf)
			if k > 0 {
				want.Read(exp[:k])
				if !bytes.Equal(buf[:k], exp[:k]) {
					f.rerr = fmt.Errorf("byte mismatch in the %d bytes after offset %d", k, got)
					return
				}
				got += int64(k)
			}
			if err == io.EOF {
				if s := sent.Load(); got != s {
					f.rerr = fmt.Errorf("io.EOF after %d bytes, %d written", got, s)
				}
				return
			}
			if err != nil {
				f.rerr = fmt.Errorf("read after %d bytes: %w", got, err)
				return
			}
		}
	}()
	go func() {
		wg.Wait()
		close(f.done)
	}()
	return f
}

// finish stops the writer and waits for both ends (bounded).
func (f *wpsessFlow) finish(t *testing.T, within time.Duration) {
	t.Helper()
	f.once.Do(func() { close(f.stop) })
	select {
	case <-f.done:
	case <-time.After(within):
		t.Fatalf("flow not finished within %v", within)
	}
	if err := errors.Join(f.werr, f.rerr); err != nil {
		t.Fatal(err)
	}
}

// wpsessLaneOf returns s's live lane of factory i (nil: none).
func wpsessLaneOf(s *Session, i int) *lane {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.lanes {
		if l.factory == i && l.state != LaneDead {
			return l
		}
	}
	return nil
}

// wpsessLaneByID returns s's lane of carrier id (nil: none).
func wpsessLaneByID(s *Session, id uint32) *lane {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.lanes {
		if l.id == id {
			return l
		}
	}
	return nil
}

// wpsessSchedOf returns s's SCHED set: the dialer's published one, the
// passive's applied one.
func wpsessSchedOf(s *Session) wire.Sched {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ctl.set
}

// TestWpsessOneWayLossMovesAckDuty_L45: a session sends bulk dialer →
// passive over path a (1 ms one-way) — the selector with path b (5 ms)
// unused, the bond striped over members a and b; both paths run at 4 MiB/s
// with a 1 MiB window. Then a's passive-to-dialer direction drops
// everything and the dialer's close of a never reaches the passive, whose
// death deadline is 10 s: only the dialer detects the death (ping_timeout,
// within its DeadMax of 2 s) and publishes a SCHED without a — the
// selector fails over to b, the bond drops member a. Once the passive
// applies it, its ACKs must travel on b: the first one, the SCHED's echo,
// reaches the dialer on b within about one RTT of b, and the transfer goes
// on at the path rate — instead of stalling, its window exhausted, until
// the passive's own detection about 10 s after the fault. Integrity: every
// byte arrives verified, then io.EOF.
func TestWpsessOneWayLossMovesAckDuty_L45(t *testing.T) {
	t.Run("selector", func(t *testing.T) { wpsessOneWayLoss(t, ModeSelector, 121) })
	t.Run("bond", func(t *testing.T) { wpsessOneWayLoss(t, ModeBond, 131) })
}

// wpsessOneWayLoss runs TestWpsessOneWayLossMovesAckDuty_L45 in mode.
func wpsessOneWayLoss(t *testing.T, mode Mode, seed uint64) {
	synctest.Test(t, func(t *testing.T) {
		const (
			rate     = 4 << 20
			bDelay   = 5 * time.Millisecond
			passDead = 10 * time.Second
		)
		bond := mode == ModeBond
		w := acNewWorld(t, nil)
		defer w.teardown()
		w.b.cenv.Timing.DeadMin, w.b.cenv.Timing.DeadMax = passDead, passDead
		var lossy, mute atomic.Bool
		var swallowed atomic.Int64
		la := rendrtest.NewLink(rendrtest.LinkConfig{Name: "a", Accept: func(nc net.Conn) error {
			return w.b.accept(&wpsessLossyConn{Conn: nc, lossy: &lossy, swallowed: &swallowed})
		}})
		la.SetDelay(acLinkDelay, 0)
		la.SetRate(rate)
		w.links = append(w.links, la)
		lb := w.link("b")
		lb.SetDelay(bDelay, 0)
		lb.SetRate(rate)
		spec := w.spec(mode, la, lb)
		spec.Factories[0].Dial = func(ctx context.Context) (net.Conn, error) {
			c, err := la.Dial(ctx)
			if err != nil {
				return nil, err
			}
			return &wpsessMuteCloseConn{Conn: c, mute: &mute}, nil
		}
		a, b := w.openSpec(spec, nil)
		da := wpsessLaneOf(a, 0)
		if da == nil {
			t.Fatal("setup: the dialer has no carrier of a")
		}
		if bond {
			acWaitFor(t, 5*time.Second, "the passive applying SCHED{a, b}", func() bool {
				set, db := wpsessSchedOf(b), wpsessLaneOf(a, 1)
				return db != nil && set.N == 2 && schedLists(&set, da.id) && schedLists(&set, db.id)
			})
		}
		flow := wpsessStartFlow(a, b, seed)
		defer flow.once.Do(func() { close(flow.stop) })
		acWaitFor(t, 5*time.Second, "2 MiB delivered", func() bool { return b.Status().DeliveredBytes >= 2<<20 })
		pa := wpsessLaneByID(b, da.id)
		if pa == nil || wpsessLaneOf(a, 0) != da || (wpsessLaneOf(a, 1) != nil) != bond {
			t.Fatal("setup: the selector does not run on a alone, or the bond not on members a and b")
		}
		if d := stLocked(b, func(st *stream) *lane { return st.ackLane }); d != pa {
			t.Fatal("setup: the passive's ACK duty is not on a")
		}

		faultAt := time.Now()
		lossy.Store(true)
		mute.Store(true)
		// applied: when the passive applied the dialer's SCHED without a;
		// ackBase: the front the dialer had seen acknowledged on b by then
		// (the selector's carrier of b is new: every ACK on it comes later).
		var applied time.Time
		var ackBase uint64
		var db *lane
		var dmig []Event
		if bond {
			// A bond passive emits no Migration event: watch its applied set.
			db = wpsessLaneOf(a, 1)
			for deadline := faultAt.Add(5 * time.Second); applied.IsZero(); time.Sleep(time.Millisecond) {
				if set := wpsessSchedOf(b); set.N > 0 && !schedLists(&set, da.id) {
					applied = time.Now()
					ackBase = stLocked(a, func(*stream) uint64 { return db.lastAck })
				} else if !time.Now().Before(deadline) {
					t.Fatal("the passive did not apply a SCHED without a within 5s of the fault")
				}
			}
		} else {
			acWaitFor(t, 5*time.Second, "the dialer's failover to b", func() bool {
				dmig = w.a.ev.of(a.ID(), EventMigration)
				return len(dmig) == 1
			})
			var pmig []Event
			acWaitFor(t, time.Second, "the passive applying SCHED{b}", func() bool {
				pmig = w.b.ev.of(b.ID(), EventMigration)
				return len(pmig) == 1
			})
			applied = pmig[0].Time
			db = wpsessLaneOf(a, 1)
		}

		// Stimulus: the death was the dialer's alone. The passive applied
		// the dialer's SCHED without a while it still held a, with nothing
		// of its own direction arriving any more.
		dst := a.Status()
		var dead *CarrierStatus
		for i := range dst.Carriers {
			if dst.Carriers[i].ID == da.id {
				dead = &dst.Carriers[i]
			}
		}
		if dead == nil || dead.State != LaneDead || dead.DeathCause != carrier.CausePingTimeout || (!bond && dmig[0].From != da.id) {
			t.Fatalf("dialer carriers %+v, migrations %+v: want a (carrier %d) dead of ping_timeout", dst.Carriers, dmig, da.id)
		}
		pset := wpsessSchedOf(b)
		if st := b.Status(); st.SchedEpoch != dst.SchedEpoch || db == nil || !schedLists(&pset, db.id) || laneEnded(pa) || swallowed.Load() == 0 {
			t.Fatalf("passive epoch %d (dialer %d), applied set %v, its a ended %v, %d bytes swallowed: want SCHED{b} applied while the passive still holds a (stimulus)",
				st.SchedEpoch, dst.SchedEpoch, pset.IDs[:pset.N], laneEnded(pa), swallowed.Load())
		}

		// The passive's ACKs travel on b within about one RTT of b, and the
		// echo with them.
		var ackAt, echoAt time.Time
		for deadline := applied.Add(passDead); ackAt.IsZero() || echoAt.IsZero(); time.Sleep(time.Millisecond) {
			if ackAt.IsZero() && stLocked(a, func(*stream) uint64 { return db.lastAck }) > ackBase {
				ackAt = time.Now()
			}
			if st := a.Status(); echoAt.IsZero() && st.SchedEchoed == st.SchedEpoch {
				echoAt = time.Now()
			}
			if !time.Now().Before(deadline) {
				t.Fatalf("within %v of the passive's SCHED{b}: first ACK on b at %v, echo at %v (zero: none)", passDead, ackAt, echoAt)
			}
		}
		took, echoed := ackAt.Sub(applied), echoAt.Sub(applied)
		t.Logf("fault +%v: the passive applied the dialer's SCHED without a; first ACK on b %v and the echo %v later",
			applied.Sub(faultAt), took, echoed)
		if rtt := 2 * bDelay; took > 2*rtt || echoed > 2*rtt {
			t.Fatalf("first ACK on b %v and the echo %v after the passive applied SCHED{b}, want both within about one RTT (%v)", took, echoed, rtt)
		}
		if pd := stLocked(b, func(st *stream) *lane { return st.ackLane }); pd == pa || pd == nil {
			t.Fatal("the passive's ACK duty is still on a after SCHED{b}")
		}

		// Load: the transfer goes on at about the path rate, its window
		// never exhausted until the passive's own detection.
		before := b.Status().DeliveredBytes
		time.Sleep(time.Second)
		if got := b.Status().DeliveredBytes - before; got < rate/2 {
			t.Fatalf("%d bytes delivered in the second after the SCHED, want at least %d (the window stalled)", got, rate/2)
		}
		if laneEnded(pa) {
			t.Fatal("the passive detected a's death meanwhile: the test window is not the A7c one (stimulus)")
		}
		if m := a.Status(); !bond && (m.MigDeath != 1 || m.MigQuality+m.MigExplicit != 0) {
			t.Fatalf("dialer migrations {%d %d %d}, want one death", m.MigDeath, m.MigQuality, m.MigExplicit)
		}
		flow.finish(t, 10*time.Second)
	})
}
