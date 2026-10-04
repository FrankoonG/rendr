package lessons4

import (
	"fmt"
	"math/rand/v2"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestFailoverProvenBySurvivorCounters_L60: a failover proves itself by the
// survivor's counters, never by the absence of an error (L60). A's factory
// is blocked before A is killed, so nothing can redial A and pose as the
// survivor; the successor's path existed before the kill (bond: B was a
// member carrying data; selector: B's probe carrier held Fresh evidence).
// Status' death migrations go from 0 to 1, the Migration event names A
// with a death cause, B carries DATA afterwards (its own byte counters and
// the link's grow), and every byte arrives intact.
func TestFailoverProvenBySurvivorCounters_L60(t *testing.T) {
	for _, mode := range []rendr.Mode{rendr.ModeBond, rendr.ModeSelector} {
		t.Run(mode.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { failoverProven(t, mode) })
		})
	}
}

func failoverProven(t *testing.T, mode rendr.Mode) {
	n := int64(24 << 20)
	if raceEnabled {
		n = 8 << 20
	}
	w := newWorld(t, worldOpts{}, "a", "b")
	la, lb := w.link("a"), w.link("b")
	la.SetDelay(2*time.Millisecond, 0)
	lb.SetDelay(4*time.Millisecond, 0)
	la.SetRate(16 << 20)
	lb.SetRate(16 << 20)
	dc, pc := w.open(w.peer(nil, la, lb), rendr.DialOptions{Mode: mode})
	f := startFlow(dc, pc, n, 60, flowOpts{closeWrite: true, eof: true})
	waitFor(t, 30*time.Second, "30% delivered", func() bool { return f.got.Load() >= n*3/10 })

	st := dc.Status()
	if st.Migrations != (rendr.MigrationCounts{}) {
		t.Fatalf("migrations before the kill: %+v", st.Migrations)
	}
	ca, ok := memberOn(st, "a")
	if !ok {
		t.Fatalf("no data carrier on a before the kill: %+v", st.Carriers)
	}
	var cbID rendr.CarrierID
	switch mode {
	case rendr.ModeBond:
		cb, ok := memberOn(st, "b")
		if !ok || cb.TxBytes == 0 || ca.TxBytes == 0 {
			t.Fatalf("the successor did not carry data before the kill: %+v", st.Carriers)
		}
		cbID = cb.ID
	case rendr.ModeSelector:
		if ca.State != rendr.CarrierActive {
			t.Fatalf("a is not the active carrier: %+v", st.Carriers)
		}
		ps := w.peers0(t)
		if fs := ps.Factories[1]; fs.Name != "b" || fs.Evidence != rendr.EvidenceFresh || fs.ProbeCarrier == 0 {
			t.Fatalf("the successor's path was not up before the kill: %+v", ps)
		}
	}
	bBefore := lb.Stats().Session.Bytes
	la.SetRefuse(true) // nothing can redial a and pose as the survivor
	killedAt := time.Now()
	la.Kill()
	if k := la.Stats().Session.Killed; k != 1 {
		t.Fatalf("session carriers killed on a: %d, want 1", k)
	}

	waitFor(t, 10*time.Second, "one death migration", func() bool { return dc.Status().Migrations.Death == 1 })
	var mig rendr.Event
	waitFor(t, 5*time.Second, "the migration event", func() bool {
		evs := w.dev.of(rendr.EventMigration)
		if len(evs) == 0 {
			return false
		}
		mig = evs[0]
		return true
	})
	if mig.From != ca.ID || mig.Session != dc.ID() || !deathCause(mig.Cause) || mig.Time.Before(killedAt) {
		t.Fatalf("migration event %+v, want from %d with a death cause after the kill", mig, ca.ID)
	}
	if mode == rendr.ModeSelector {
		nb, ok := carrierOf(dc.Status(), mig.To)
		if !ok || nb.Name != "b" || nb.State != rendr.CarrierActive {
			t.Fatalf("the migration went to %d (%+v), want the active carrier on b", mig.To, dc.Status().Carriers)
		}
		cbID = mig.To
	} else if mig.To != 0 {
		t.Fatalf("bond migration event %+v, want To 0 (no single successor)", mig)
	}
	f.wait(t, time.Minute, "transfer")

	st = dc.Status()
	cb, ok := carrierOf(st, cbID)
	if !ok || cb.Name != "b" || cb.TxBytes == 0 {
		t.Fatalf("the survivor %d carried nothing: %+v", cbID, st.Carriers)
	}
	if got := lb.Stats().Session.Bytes; got-bBefore < n/4 {
		t.Fatalf("the survivor's link moved %s after the kill, want ≥ %s", mib(got-bBefore), mib(n/4))
	}
	for _, c := range st.Carriers {
		if c.Name == "a" && c.State != rendr.CarrierDead {
			t.Fatalf("a carrier of the blocked factory is alive: %+v", st.Carriers)
		}
	}
	if st.Migrations.Death != 1 || st.Migrations.Quality+st.Migrations.Explicit != 0 || st.Rejoins != 0 {
		t.Fatalf("dialer counts %+v rejoins %d, want one death and no rejoin", st.Migrations, st.Rejoins)
	}
	if la.Stats().DialFailures == 0 && mode == rendr.ModeBond {
		t.Fatal("the bond never tried to redial the blocked factory")
	}
	if mode == rendr.ModeSelector {
		if ps := pc.Status(); ps.Migrations.Death != 1 {
			t.Fatalf("passive counts %+v, want the same single death", ps.Migrations)
		}
	}
	endClean(t, dc, pc)
	w.close()
}

// peers0 returns the PeerStatus of the dialer's only Peer (the world's
// first Peer is the session's).
func (w *world) peers0(t testing.TB) rendr.PeerStatus {
	t.Helper()
	if w.lastPeer == nil {
		t.Fatal("no Peer")
	}
	return w.lastPeer.Status()
}

// deathCause reports a carrier death cause (plan §3.6), as opposed to a
// retirement or a quality switch.
func deathCause(c rendr.Cause) bool {
	switch c {
	case rendr.CausePingTimeout, rendr.CauseWriteStall, rendr.CauseTransportError,
		rendr.CauseProtocolViolation, rendr.CauseInstanceMismatch, rendr.CauseGoAway:
		return true
	}
	return false
}

// TestRandomOffsetBlackholeSeeds_L61: the unit mirror of G4-sel-seeds (plan
// §10.3, L10, L61) on the buffer-loss model: a selector session moves a
// G1-style transfer (passive → dialer) over two 50 Mbit/s paths with 20 ms
// RTT; at a seeded random offset the active path is blackholed (every byte
// in its 2 MiB link buffers, in flight and later vanishes; nothing closes).
// The DROP lands while DATA is in flight on the active carrier. For each of
// 20 seeds: no write or read error, every byte verified, no pause in
// delivery longer than the G4 budget of 5 s, the end that detects the
// silent death records ping_timeout or write_stall, one death migration on
// both ends, the bytes lost in the path are replayed, and the stimulus is
// proven by the blackhole's drop counter.
func TestRandomOffsetBlackholeSeeds_L61(t *testing.T) {
	for seed := uint64(1); seed <= 20; seed++ {
		t.Run(fmt.Sprintf("seed%02d", seed), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { blackholeSeed(t, seed) })
		})
	}
}

func blackholeSeed(t *testing.T, seed uint64) {
	const rate = 50e6 / 8 // 50 Mbit/s
	n := int64(12 << 20)
	if raceEnabled {
		n = 6 << 20
	}
	rng := rand.New(rand.NewPCG(seed, 61))
	at := n/10 + rng.Int64N(n*8/10) // the DROP offset: 10%–90% of the transfer

	w := newWorld(t, worldOpts{}, "a", "b")
	la, lb := w.link("a"), w.link("b")
	for _, l := range []*rendrtest.Link{la, lb} {
		l.SetDelay(10*time.Millisecond, 0)
		l.SetRate(rate)
	}
	dc, pc := w.open(w.peer(nil, la, lb), rendr.DialOptions{})
	f := startFlow(pc, dc, n, 6100+seed, flowOpts{closeWrite: true, eof: true})
	// The DROP lands at the offset once DATA is in flight on the active
	// carrier (G4 is INVALID without in-flight data): sent by the passive
	// on it and not yet received by the dialer.
	var act rendr.CarrierStatus
	waitFor(t, time.Minute, "the DROP offset with DATA in flight", func() bool {
		if f.got.Load() < at {
			return false
		}
		var ok bool
		if act, ok = activeOf(dc.Status()); !ok {
			return false
		}
		sent, ok := carrierOf(pc.Status(), act.ID)
		return ok && sent.TxBytes >= act.RxBytes+64<<10
	})
	victim, other := la, lb
	if act.Name == "b" {
		victim, other = lb, la
	}
	dropAt := time.Now()
	victim.SetBlackhole(true) // DROP both ways: no RST, no close
	f.wait(t, 2*time.Minute, "transfer across the DROP")

	if d := victim.Stats().Session.Dropped; d == 0 {
		t.Fatal("the blackhole dropped no session byte (stimulus)")
	}
	if gap, end := f.gap(); gap > 5*time.Second {
		t.Fatalf("delivery paused %v (until %v after the DROP), want ≤ 5 s (G4 budget)", gap, end.Sub(dropAt))
	}
	resumed, ok := f.firstReadAfter(dropAt.Add(20 * time.Millisecond)) // bytes already in flight arrive for one one-way delay
	if !ok || resumed.at.Sub(dropAt) > 5*time.Second {
		t.Fatalf("no new byte within 5 s of the DROP (first after: %v)", resumed.at.Sub(dropAt))
	}
	gap, _ := f.gap()
	t.Logf("DROP at %s of %s: delivery resumed %v later, longest pause %v", mib(at), mib(n), resumed.at.Sub(dropAt), gap)
	// The side whose PING went unanswered first declares the death
	// (ping_timeout, or write_stall); its close reaches the other side as
	// the carrier's end (the link model propagates a close even while
	// blackholed), so that side may record transport_error.
	st, ps := dc.Status(), pc.Status()
	detected := false
	for _, s := range []rendr.SessionStatus{st, ps} {
		dead := deadOf(s)
		if len(dead) != 1 || dead[0].ID != act.ID {
			t.Fatalf("%v dead carriers %+v, want exactly %d", s.Role, dead, act.ID)
		}
		switch dead[0].DeathCause {
		case rendr.CausePingTimeout, rendr.CauseWriteStall:
			detected = true
		case rendr.CauseTransportError:
		default:
			t.Fatalf("%v: %d died of %v", s.Role, act.ID, dead[0].DeathCause)
		}
	}
	if !detected {
		t.Fatalf("neither end detected the silent death: %+v / %+v", deadOf(st), deadOf(ps))
	}
	na, ok := activeOf(st)
	if !ok || na.Name != other.Name() || st.Migrations.Death != 1 {
		t.Fatalf("after the DROP: active %+v, migrations %+v; want one death onto %s", na, st.Migrations, other.Name())
	}
	// The buffer-loss model: DATA the passive wrote on the dead carrier and
	// the dialer never received vanished in the link; the passive replayed
	// at least that much from its send buffer.
	sentOn, _ := carrierOf(ps, act.ID)
	recvOn, _ := carrierOf(st, act.ID)
	lost := int64(sentOn.TxBytes) - int64(recvOn.RxBytes)
	if lost <= 0 || int64(ps.RetransmittedBytes) < lost || ps.Migrations.Death != 1 {
		t.Fatalf("passive (the sender): %d bytes lost in the link, %d retransmitted, migrations %+v; want a replay of the loss and one death",
			lost, ps.RetransmittedBytes, ps.Migrations)
	}
	victim.SetBlackhole(false)
	endClean(t, dc, pc)
	w.close()
}
