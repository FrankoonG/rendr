package lessons2

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// TestStaleCarrierRefusalsRecover_L18 (L18, L20; design D27 and §0.14 B6):
// the passive's MaxCarriersPerSession equals the number of carriers the
// session holds — one for a selector session over one factory, two for a
// bond over two. Right after the passive's idle PING the dialer loses its
// path locally: its carriers fail at once, but nothing reaches the passive
// (no FIN, no RST), so the passive keeps its lanes until their PINGs time
// out, PingIdle + DeadMin ≈ 13 s later, and answers every replacement JOIN
// with JOIN_ACK CAPACITY until then (D27). The dialer's NoPathGrace is 15 s.
//
// The refusals must keep the redial cadence of a slot whose carrier died
// (the recovery window of sched.Cadence): every interval within one
// Backoff(0), so the first JOIN after the passive dropped its stale lane
// attaches within one such interval, inside the grace, and the session goes
// on delivering. With B6 as first decided the refusals grew the interval to
// the 4 s cap and the session ended with ErrNoPath for jitter 0 and 0.5
// (with jitter 0.5: JOINs at 0, 0.5, 1.5, 3.5, 7.5 and 11.5 s, none in
// [13 s, 15 s)).
func TestStaleCarrierRefusalsRecover_L18(t *testing.T) {
	for _, tc := range []struct {
		name string
		bond bool
	}{
		{"selector, one factory", false},
		{"bond, both members", true},
	} {
		for _, j := range []struct {
			name string
			u    float64 // fixed jitter; negative: the real jitter source
		}{
			{"jitter 0", 0},
			{"jitter 0.5", 0.5},
			{"jitter 1", 1},
			{"real jitter", -1},
		} {
			t.Run(tc.name+"/"+j.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) { g3StaleRecovery(t, tc.bond, j.u) })
			})
		}
	}
}

func g3StaleRecovery(t *testing.T, bond bool, u float64) {
	const (
		grace      = 15 * time.Second // NoPathGrace (the default, set explicitly)
		backoffMax = 4 * time.Second  // RejoinBackoffMax (the default, set explicitly)
		pingIdle   = 10 * time.Second // the passive's PingIdle (the default)
		timerSlack = time.Millisecond // the actor arms no timer shorter than 1 ms
		lossDelay  = 30 * time.Millisecond
		chunk      = 64 << 10
	)
	cap := min(backoffMax, grace/2)
	// The longest interval while refused: one Backoff(0) (the immediate
	// redials after the death and after the episode start are shorter).
	maxGap := sched.Backoff(0, cap, 1) + timerSlack
	ov := &testhooks.Overrides{}
	if u >= 0 {
		ov.Rand = func() float64 { return u }
	}
	members := 1
	pcfg := rendr.Config{MaxCarriersPerSession: 1}
	if bond {
		members = 2
		pcfg.MaxCarriersPerSession = 2
	}
	e := newEnv(t, rendr.Config{NoPathGrace: grace, RejoinBackoffMax: backoffMax}, pcfg, ov)
	for _, rt := range []*rendr.Runtime{e.d, e.p} {
		if adj := rt.Status().ConfigAdjustments; len(adj) != 0 {
			t.Fatalf("configuration adjusted: %v", adj)
		}
	}
	paths := []*path{e.path("a", 5*time.Millisecond)}
	if bond {
		paths = append(paths, e.path("b", 10*time.Millisecond))
	}
	lossy := make([]*g3Lossy, len(paths))
	carriers := make([]rendr.Carrier, len(paths))
	for i, p := range paths {
		lossy[i] = &g3Lossy{p: p}
		carriers[i] = lossy[i].carrier()
	}
	peer, err := e.d.NewPeer(rendr.PeerConfig{Carriers: carriers})
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	o := rendr.DialOptions{}
	if bond {
		o.Mode = rendr.ModeBond
	}
	dc, pc := e.open(peer, o)
	waitFor(t, 10*time.Second, time.Millisecond, "every member attached", func() bool {
		return len(liveOf(dc.Status(), "")) == members && len(liveOf(pc.Status(), "")) == members
	})
	exchange(t, dc, pc, chunk, 2700)

	// The session idles; the loss follows the passive's next idle PING on
	// every lane by 30 ms (the worst phase: its next PING is PingIdle later).
	time.Sleep(time.Second)
	before := make([]int, len(paths))
	for i, p := range paths {
		before[i] = len(p.sentBack(wire.TypePing))
	}
	waitFor(t, pingIdle+time.Second, time.Millisecond, "the passive's idle PINGs", func() bool {
		for i, p := range paths {
			if len(p.sentBack(wire.TypePing)) == before[i] {
				return false
			}
		}
		return true
	})
	var lastPing time.Time
	for _, p := range paths {
		pings := p.sentBack(wire.TypePing)
		if at := pings[len(pings)-1].at; at.After(lastPing) {
			lastPing = at
		}
	}
	time.Sleep(time.Until(lastPing.Add(lossDelay)))
	ids := make(map[rendr.CarrierID]*path)
	for _, p := range paths {
		l := liveOf(dc.Status(), p.name)
		if len(l) != 1 {
			t.Fatalf("before the loss: %d live carriers on %s", len(l), p.name)
		}
		ids[l[0].ID] = p
	}
	cut := time.Now()
	lost := 0
	for _, l := range lossy {
		lost += l.lose()
	}
	if lost != members {
		t.Fatalf("stimulus: the loss hit %d session carriers, want %d", lost, members)
	}
	waitFor(t, time.Second, time.Millisecond, "the dialer saw its carriers die", func() bool {
		return len(liveOf(dc.Status(), "")) == 0
	})
	waitFor(t, grace+time.Second, time.Millisecond, "reattach (or the session's end)", func() bool {
		st := dc.Status()
		return st.State == rendr.StateEnded || (len(liveOf(st, "")) == members && st.Rejoins == uint64(members))
	})
	ds := dc.Status()
	if ds.State != rendr.StateOpen || ds.NoPathEpisodes != 1 || ds.Rejoins != uint64(members) {
		t.Fatalf("after the loss: dialer %v (err %v), %d episodes, %d rejoins; want open, 1, %d",
			ds.State, ds.Err, ds.NoPathEpisodes, ds.Rejoins, members)
	}

	// Stimulus: the dialer saw the deaths at the loss; the passive kept every
	// stale lane until its PING timed out, at least PingIdle − 1 s later.
	for _, ev := range e.dev.of(rendr.EventCarrierDown) {
		if ids[ev.Carrier] != nil && ev.Time.Sub(cut) > 10*time.Millisecond {
			t.Fatalf("stimulus: the dialer saw carrier %d die %v after the loss", ev.Carrier, ev.Time.Sub(cut))
		}
	}
	var firstStale, lastStale time.Time
	stale := 0
	for _, ev := range e.pev.of(rendr.EventCarrierDown) {
		if ids[ev.Carrier] == nil {
			continue
		}
		stale++
		if firstStale.IsZero() || ev.Time.Before(firstStale) {
			firstStale = ev.Time
		}
		if ev.Time.After(lastStale) {
			lastStale = ev.Time
		}
	}
	if stale != members || firstStale.Sub(cut) < pingIdle-time.Second || !lastStale.Before(cut.Add(grace)) {
		t.Fatalf("stimulus: the passive dropped %d stale lanes at +%v … +%v after the loss; want %d within [+%v, +%v)",
			stale, firstStale.Sub(cut), lastStale.Sub(cut), members, pingIdle-time.Second, grace)
	}

	// The cadence and the refusals, per path: every JOIN that reached the
	// passive well before its first stale lane died was refused with
	// CAPACITY, enough of them to prove the cadence; no interval longer than
	// one Backoff(0); the path's last JOIN (the one that attached) followed
	// the last stale lane's death within one more interval.
	for _, p := range paths {
		var joins []*tconn
		for _, c := range p.sessionConns(true) {
			if f, ok := c.out.first(); ok && f.typ == wire.TypeJoin && !f.at.Before(cut) {
				joins = append(joins, c)
			}
		}
		if len(joins) == 0 {
			t.Fatalf("stimulus: no JOIN on %s after the loss", p.name)
		}
		var prev time.Time
		refused := 0
		for k, c := range joins {
			j, _ := c.out.first()
			if k == 0 && j.at.Sub(cut) > 10*time.Millisecond {
				t.Fatalf("%s: the first redial started %v after the death, want at once", p.name, j.at.Sub(cut))
			}
			if k > 0 && j.at.Sub(prev) > maxGap {
				t.Fatalf("%s: JOIN %d started %v after the previous one, want at most %v (a recovering slot's refusals keep Backoff(0))",
					p.name, k+1, j.at.Sub(prev), maxGap)
			}
			prev = j.at
			ack, ok := c.in.first()
			if !ok || ack.typ != wire.TypeJoinAck {
				t.Fatalf("%s: JOIN %d got %+v (ok %v), want a JOIN_ACK", p.name, k+1, ack, ok)
			}
			status := wire.AckStatus(ack.b0)
			if k == len(joins)-1 {
				if status != wire.StatusOK || !j.at.After(lastStale.Add(-maxGap)) || j.at.Sub(lastStale) > maxGap {
					t.Fatalf("%s: the last JOIN (status %d) started %v after the last stale lane died, want OK within (−%v, %v]",
						p.name, status, j.at.Sub(lastStale), maxGap, maxGap)
				}
				continue
			}
			if j.at.Before(firstStale.Add(-time.Second)) {
				if status != wire.StatusCapacity {
					t.Fatalf("%s: JOIN %d at +%v (passive still full) got status %d, want CAPACITY", p.name, k+1, j.at.Sub(cut), status)
				}
				refused++
			}
		}
		if lo := int((firstStale.Sub(cut) - time.Second) / maxGap); refused < lo {
			t.Fatalf("stimulus: %d JOINs of %s refused with CAPACITY before the passive dropped a stale lane, want at least %d", refused, p.name, lo)
		}
		t.Logf("%s: %d JOINs after the loss, %d refused; the last one %v after the last stale lane died (+%v)",
			p.name, len(joins), refused, prev.Sub(lastStale), lastStale.Sub(cut))
	}

	// Load and integrity: the session delivers again, exactly.
	exchange(t, dc, pc, chunk, 2702)
	ds, ps := dc.Status(), pc.Status()
	want := uint64(2 * chunk)
	if ds.DeliveredBytes != want || ps.DeliveredBytes != want || ds.TxBytes != want || ps.TxBytes != want {
		t.Fatalf("load: dialer delivered %d sent %d, passive delivered %d sent %d; want %d each",
			ds.DeliveredBytes, ds.TxBytes, ps.DeliveredBytes, ps.TxBytes, want)
	}
	if len(liveOf(ds, "")) != members || len(liveOf(ps, "")) != members {
		t.Fatalf("after the recovery: dialer %+v, passive %+v", ds, ps)
	}
	endClean(t, dc, pc)
	e.close()
}

// TestRefusedMemberAfterLossBacksOff_L20 (L20, L18; design §0.14 B6 and
// D27): a bond Peer with two factories dials a passive whose
// MaxCarriersPerSession is 1, so b is refused with JOIN_ACK CAPACITY for as
// long as a lives and backs off to the cap (B6). Then the dialer loses a's
// path locally right after the passive's idle PING, and the passive keeps
// the stale lane until its PING times out (≈ 13 s). Both member slots
// recover — a's carrier died, b was kicked when the no-path episode started
// —, so every JOIN of either keeps the Backoff(0) cadence until the passive
// drops the stale lane, and one of them attaches inside the grace. The
// member left over is refused for the rest of the session: within 60 s of
// the loss its JOIN dials stay within what one recovery window (4 × cap) at
// Backoff(0) and the growing cadence after it allow, and its last intervals
// are at the cap, so a death does not bring back B6's endless 0.5 s loop.
// In the second case a's path stays down after the loss (its factory
// fails): only b, which was refused before the episode, can recover the
// session, and it does.
func TestRefusedMemberAfterLossBacksOff_L20(t *testing.T) {
	for _, tc := range []struct {
		name string
		down bool
	}{
		{"a redials", false},
		{"path a down", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { g3RefusedAfterLoss(t, tc.down) })
		})
	}
}

// g3Joins returns the dialer ends of p's carriers that wrote a JOIN at or
// after since, in creation order.
func g3Joins(p *path, since time.Time) []*tconn {
	var out []*tconn
	for _, c := range p.sessionConns(true) {
		if f, ok := c.out.first(); ok && f.typ == wire.TypeJoin && !f.at.Before(since) {
			out = append(out, c)
		}
	}
	return out
}

// g3AckStatus is the status of the JOIN_ACK that answered c (ok false: none).
func g3AckStatus(c *tconn) (wire.AckStatus, bool) {
	f, ok := c.in.first()
	if !ok || f.typ != wire.TypeJoinAck {
		return 0, false
	}
	return wire.AckStatus(f.b0), true
}

func g3RefusedAfterLoss(t *testing.T, down bool) {
	const (
		grace      = 15 * time.Second // NoPathGrace (the default, set explicitly)
		backoffMax = 4 * time.Second  // RejoinBackoffMax (the default, set explicitly)
		pingIdle   = 10 * time.Second // the passive's PingIdle (the default)
		timerSlack = time.Millisecond // the actor arms no timer shorter than 1 ms
		lossDelay  = 30 * time.Millisecond
		observe    = time.Minute // from the loss
		chunk      = 64 << 10
		window     = 4 // a recovery window lasts 4 × cap (sched.Cadence)
	)
	cap := min(backoffMax, grace/2)
	maxGap := sched.Backoff(0, cap, 1) + timerSlack
	// The most JOIN dials one slot can make within observe of the loss: the
	// immediate redials at the death and at the episode start, one recovery
	// window at intervals of at least Backoff(0, cap, 0), then the growing
	// cadence from failure 1 at its shortest intervals.
	maxN := 2 + int(window*cap/sched.Backoff(0, cap, 0)) +
		g3Starts(observe-window*cap, func(k int) time.Duration { return sched.Backoff(k+1, cap, 0) })
	atCap := [2]time.Duration{sched.Backoff(9, cap, 0), sched.Backoff(9, cap, 1) + timerSlack}
	e := newEnv(t, rendr.Config{NoPathGrace: grace, RejoinBackoffMax: backoffMax}, rendr.Config{MaxCarriersPerSession: 1}, nil)
	for _, rt := range []*rendr.Runtime{e.d, e.p} {
		if adj := rt.Status().ConfigAdjustments; len(adj) != 0 {
			t.Fatalf("configuration adjusted: %v", adj)
		}
	}
	a := e.path("a", 5*time.Millisecond) // the faster path: the session opens on it
	b := e.path("b", 10*time.Millisecond)
	la, lb := &g3Lossy{p: a}, &g3Lossy{p: b}
	peer, err := e.d.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{la.carrier(), lb.carrier()}})
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	dc, pc := e.open(peer, rendr.DialOptions{Mode: rendr.ModeBond})
	exchange(t, dc, pc, chunk, 2800)
	waitFor(t, 5*time.Second, time.Millisecond, "b refused", func() bool {
		js := g3Joins(b, time.Time{})
		if len(js) == 0 {
			return false
		}
		st, ok := g3AckStatus(js[0])
		return ok && st == wire.StatusCapacity
	})

	// The loss follows the passive's next idle PING on a by 30 ms.
	time.Sleep(time.Second)
	n0 := len(a.sentBack(wire.TypePing))
	waitFor(t, pingIdle+time.Second, time.Millisecond, "the passive's idle PING on a", func() bool {
		return len(a.sentBack(wire.TypePing)) > n0
	})
	pings := a.sentBack(wire.TypePing)
	time.Sleep(time.Until(pings[len(pings)-1].at.Add(lossDelay)))
	ds := dc.Status()
	if l := liveOf(ds, ""); len(l) != 1 || l[0].Name != "a" {
		t.Fatalf("before the loss: live carriers %+v, want a alone", l)
	}
	aID := liveOf(ds, "a")[0].ID
	cut := time.Now()
	if down {
		a.link.SetRefuse(true)
	}
	if n := la.lose() + lb.lose(); n != 1 {
		t.Fatalf("stimulus: the loss hit %d session carriers, want 1", n)
	}
	waitFor(t, time.Second, time.Millisecond, "the dialer saw a die", func() bool { return len(liveOf(dc.Status(), "")) == 0 })
	waitFor(t, grace+time.Second, time.Millisecond, "reattach (or the session's end)", func() bool {
		st := dc.Status()
		return st.State == rendr.StateEnded || len(liveOf(st, "")) == 1
	})
	ds = dc.Status()
	if ds.State != rendr.StateOpen || ds.NoPathEpisodes != 1 {
		t.Fatalf("after the loss: dialer %v (err %v), %d episodes; want open, 1", ds.State, ds.Err, ds.NoPathEpisodes)
	}
	winner := liveOf(ds, "")[0].Name
	if down && winner != "b" {
		t.Fatalf("path a is down, yet %s attached", winner)
	}
	var stale time.Time
	for _, ev := range e.pev.of(rendr.EventCarrierDown) {
		if ev.Carrier == aID {
			stale = ev.Time
		}
	}
	if stale.IsZero() || stale.Sub(cut) < pingIdle-time.Second || !stale.Before(cut.Add(grace)) {
		t.Fatalf("stimulus: the passive dropped a's stale lane at +%v after the loss, want within [+%v, +%v)",
			stale.Sub(cut), pingIdle-time.Second, grace)
	}

	// The load goes on over the winner; then the observation runs out, and a
	// JOIN made at its very end has been answered (five round trips of b).
	exchange(t, dc, pc, chunk, 2802)
	time.Sleep(time.Until(cut.Add(observe + 100*time.Millisecond)))
	synctest.Wait()

	// During the episode every JOIN of a recovering slot kept the Backoff(0)
	// cadence, and those that reached the passive well before it dropped the
	// stale lane were refused with CAPACITY; the winner's attaching JOIN
	// reached the passive after that and was written within one Backoff(0)
	// of it.
	paths := map[string]*path{"a": a, "b": b}
	for name, p := range paths {
		js := g3Joins(p, cut)
		if name == "a" && down {
			if len(js) != 0 {
				t.Fatalf("path a is down, yet %d JOINs crossed it", len(js))
			}
			continue
		}
		if len(js) == 0 {
			t.Fatalf("stimulus: no JOIN on %s after the loss", name)
		}
		var prev time.Time
		attached := false
		for k, c := range js {
			j, _ := c.out.first()
			st, ok := g3AckStatus(c)
			// At once (the death's or the episode's kick), or right after a
			// refused JOIN of b that was in flight at the loss (one round trip).
			if k == 0 && j.at.Sub(cut) > 100*time.Millisecond {
				t.Fatalf("%s: the first JOIN after the loss started %v later, want at once (death or episode kick)", name, j.at.Sub(cut))
			}
			// A JOIN scheduled during the episode — its predecessor started
			// while the passive still held the stale lane — follows within
			// one Backoff(0).
			if k > 0 && prev.Before(stale) && j.at.Sub(prev) > maxGap {
				t.Fatalf("%s: JOIN %d started %v after the previous one (at +%v), want at most %v during the episode",
					name, k+1, j.at.Sub(prev), j.at.Sub(cut), maxGap)
			}
			prev = j.at
			if j.at.Before(stale.Add(-time.Second)) {
				if !ok || st != wire.StatusCapacity {
					t.Fatalf("stimulus: %s: JOIN %d at +%v (stale lane held) got status %d (ok %v), want CAPACITY", name, k+1, j.at.Sub(cut), st, ok)
				}
				continue
			}
			if ok && st == wire.StatusOK {
				// One one-way delay (≤ 10 ms here) before the death at most:
				// it reached the passive after the stale lane died.
				if name != winner || j.at.Before(stale.Add(-50*time.Millisecond)) || j.at.Sub(stale) > maxGap {
					t.Fatalf("%s: JOIN %d attached, written %v after the stale lane died (winner %s), want within (−50ms, %v]",
						name, k+1, j.at.Sub(stale), winner, maxGap)
				}
				attached = true
				break
			}
			if j.at.After(stale) {
				break // the member left over, after the episode: below
			}
		}
		if name == winner && !attached {
			t.Fatalf("%s attached, but none of its JOINs after the loss was answered OK", name)
		}
	}

	// The member left over is redialled at a bounded cadence that settles
	// at the cap; every JOIN of it after the attach was refused.
	if !down {
		loser := "a"
		if winner == "a" {
			loser = "b"
		}
		var at []time.Time
		for _, c := range g3Joins(paths[loser], cut) {
			j, _ := c.out.first()
			if j.at.After(cut.Add(observe)) {
				continue
			}
			at = append(at, j.at)
			if st, ok := g3AckStatus(c); j.at.After(stale.Add(maxGap)) && (!ok || st != wire.StatusCapacity) {
				t.Fatalf("stimulus: %s's JOIN at +%v (after the attach) got status %d (ok %v), want CAPACITY", loser, j.at.Sub(cut), st, ok)
			}
		}
		if len(at) > maxN || len(at) < 4 {
			t.Fatalf("%s: %d JOIN dials within %v of the loss, want 4–%d", loser, len(at), observe, maxN)
		}
		for k := len(at) - 3; k < len(at); k++ {
			if gap := at[k].Sub(at[k-1]); gap < atCap[0] || gap > atCap[1] {
				t.Fatalf("%s: interval %v at +%v, want at the cap: within [%v, %v]", loser, gap, at[k].Sub(cut), atCap[0], atCap[1])
			}
		}
		t.Logf("%s attached; %s made %d JOIN dials within %v of the loss (at most %d)", winner, loser, len(at), observe, maxN)
	}

	// Load and integrity: both exchanges arrived intact.
	ds, ps := dc.Status(), pc.Status()
	want := uint64(2 * chunk)
	if ds.DeliveredBytes != want || ps.DeliveredBytes != want || ds.TxBytes != want || ps.TxBytes != want {
		t.Fatalf("load: dialer delivered %d sent %d, passive delivered %d sent %d; want %d each",
			ds.DeliveredBytes, ds.TxBytes, ps.DeliveredBytes, ps.TxBytes, want)
	}
	if ds.State != rendr.StateOpen || len(liveOf(ds, "")) != 1 || len(liveOf(ps, "")) != 1 || ds.NoPathEpisodes != 1 {
		t.Fatalf("after %v: dialer %+v, passive %+v", observe, ds, ps)
	}
	endClean(t, dc, pc)
	e.close()
}

// errG3Lost is the error of a dialer carrier whose path was lost locally.
var errG3Lost = errors.New("lessons2: path lost at the dialer")

// g3Conn is a dialer carrier end whose path can be lost locally (lose):
// from then on Read and Write fail at once and Close no longer reaches the
// passive — no FIN, no RST —, so the passive keeps its lane until its own
// PING times out, as when the dialer's network fails.
type g3Conn struct {
	*tconn
	lost     chan struct{}
	loseOnce sync.Once
}

func (c *g3Conn) lose() {
	c.loseOnce.Do(func() {
		close(c.lost)
		c.tconn.SetDeadline(time.Now()) // a Read or Write in progress returns now
	})
}

func (c *g3Conn) isLost() bool {
	select {
	case <-c.lost:
		return true
	default:
		return false
	}
}

func (c *g3Conn) Read(b []byte) (int, error) {
	if c.isLost() {
		return 0, errG3Lost
	}
	n, err := c.tconn.Read(b)
	if c.isLost() {
		return 0, errG3Lost
	}
	return n, err
}

func (c *g3Conn) Write(b []byte) (int, error) {
	if c.isLost() {
		return 0, errG3Lost
	}
	n, err := c.tconn.Write(b)
	if c.isLost() {
		return 0, errG3Lost
	}
	return n, err
}

func (c *g3Conn) Close() error {
	if c.isLost() {
		return nil
	}
	return c.tconn.Close()
}

func (c *g3Conn) SetDeadline(t time.Time) error {
	if c.isLost() {
		return nil
	}
	return c.tconn.SetDeadline(t)
}

func (c *g3Conn) SetReadDeadline(t time.Time) error {
	if c.isLost() {
		return nil
	}
	return c.tconn.SetReadDeadline(t)
}

func (c *g3Conn) SetWriteDeadline(t time.Time) error {
	if c.isLost() {
		return nil
	}
	return c.tconn.SetWriteDeadline(t)
}

// g3Lossy is a factory over path p whose session carriers can lose their
// path locally.
type g3Lossy struct {
	p     *path
	mu    sync.Mutex
	conns []*g3Conn
}

func (l *g3Lossy) carrier() rendr.StreamCarrier {
	return rendr.StreamCarrier{Name: l.p.name, Dial: func(ctx context.Context) (net.Conn, error) {
		c, err := l.p.dial(ctx, nil)
		if err != nil || c == nil {
			return c, err
		}
		gc := &g3Conn{tconn: c.(*tconn), lost: make(chan struct{})}
		l.mu.Lock()
		l.conns = append(l.conns, gc)
		l.mu.Unlock()
		return gc, nil
	}}
}

// lose loses the path of every attached session carrier of the factory —
// open, its OPEN or JOIN answered OK — and returns how many it hit. Probe
// carriers and a JOIN still waiting for its answer keep theirs.
func (l *g3Lossy) lose() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, c := range l.conns {
		t := c.firstFrame()
		ack, ok := c.in.first()
		attached := ok && (ack.typ == wire.TypeOpenAck || ack.typ == wire.TypeJoinAck) && wire.AckStatus(ack.b0) == wire.StatusOK
		if (t == wire.TypeOpen || t == wire.TypeJoin) && attached && c.closes.Load() == 0 && !c.isLost() {
			c.lose()
			n++
		}
	}
	return n
}
