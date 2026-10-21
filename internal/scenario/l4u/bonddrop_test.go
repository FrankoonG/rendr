package l4u

import (
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/l4"
)

// TestL4UBondSilentMemberKeepsStream_L39 (G10-bond's DROP row as the M6
// delegate decision of 2026-10-21 amends it — judged against the
// death-detection bound, as G4-pkt-bond is (plan:757, F14) — and §A14's
// bond row; L39): the ML-100 miniature's three flows
// (TestL4UStreamMiniature_L39_L40_L70's profile) in bond mode over two
// DatagramLinks v1 and v2. After 3 s of streaming the path of the member
// that carried most of the video in the last second is blackholed both
// ways for 6 s, then restored; the row judges until 6 s after the removal,
// and at least a second after the member's rejoin, and the profile runs a
// second longer (lane.silentWarm, lane.silentDrop and lane.silentTail:
// under the race detector 1 s of streaming, a blackhole of 5 s — the
// death-detection bound — and 1 s after the removal; the windows and the
// bounds are the same).
//
// A packet bond places by member srtt, and a silent member's srtt does
// not rise before a PONG proves it, so the member keeps receiving most of
// the stream until its death is detected and the datagrams placed on it
// are lost (the decision's documented behaviour, measured at about 7 % of
// the video delivered over the ≈ 4 s to the death). The row asserts the
// bound that behaviour must keep, not the share it loses (recorded only).
//
// Stimulus: the blackholed member carried most of the video before the
// blackhole, its path lost session datagrams, and it died silently on the
// dialer (ping_timeout, write_stall, or PA-86's peer_down).
//
// PASS (the death-detection bound; W = [t_d − 200 ms, t_d +
// recoveryBound], G10's bond DROP window, the video's end extended through
// the recovery IDR as G10 does):
//
//   - the member's death on the dialer within recoveryBound (DeadMax 4 s +
//     1 s) of the blackhole (G10-bond: the member's death ≤ 5 s);
//   - recovery within the bound (bondDropRecovery): every video arrival
//     gap above 200 ms from 1 s before the blackhole to the judged span's
//     end (6 s after the removal, lane.silentTail, and at least 1 s after
//     the rejoin) lies inside [t_d − 200 ms, t_d + recoveryBound] — the
//     stream arrives again by the bound and stops for no longer than
//     200 ms before the blackhole, after the recovery, at the removal and
//     at the member's rejoin;
//   - losses only inside W, per flow and direction (every flow's sessions
//     share the two paths), and none at the removal or the rejoin (G5-pkt);
//   - the member rejoins within G5Bound of the removal (G10-bond's removal
//     row; mlRejoin, 4.06 s), every datagram that arrived is intact and
//     arrived once, and each flow keeps its one session (three flows
//     opened once, one egress source each: the stream is kept, never
//     re-opened).
func TestL4UBondSilentMemberKeepsStream_L39(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		warm, drop, tail := lane.silentWarm, lane.silentDrop, lane.silentTail
		w := newWorld(t, worldOpts{}, linkSpec{name: "v1"}, linkSpec{name: "v2"})
		m := newMLRun(w.quit)
		w.target(mlVideoPort, m.hostVideo)
		w.target(mlAudioPort, m.hostAudio)
		w.target(mlCtlPort, m.hostControl)
		pf := &l4.PortForward{Peer: w.peer("v1", "v2"), Options: rendr.DialOptions{Mode: rendr.ModeBond}}
		inV := w.forward(pf, targetAddr(mlVideoPort), hubCfg(1))
		inA := w.forward(pf, targetAddr(mlAudioPort), hubCfg(2))
		inC := w.forward(pf, targetAddr(mlCtlPort), hubCfg(3))
		client := netip.AddrFrom4([4]byte{192, 0, 2, 50})
		srcV, srcA, srcC := netip.AddrPortFrom(client, 50000), netip.AddrPortFrom(client, 50001), netip.AddrPortFrom(client, 50002)
		cv, ca, cc := inV.client(srcV), inA.client(srcA), inC.client(srcC)
		m.clientControl(cc)
		m.clientVideo(cv, cc)
		m.clientAudio(ca)
		waitFor(t, 15*time.Second, "three flows open with two members and streaming", func() bool {
			for _, src := range []netip.AddrPort{srcV, srcA, srcC} {
				fi, ok := flowOf(pf, src)
				if !ok || fi.State != l4.FlowOpen || len(liveOf(fi.Session)) < 2 {
					return false
				}
			}
			return m.vDown.arrived() > 0 && m.aDown.arrived() > 0 && m.cDown.arrived() > 0
		})
		s0 := time.Now()
		sleepUntil(s0.Add(warm - time.Second))
		before, _ := flowOf(pf, srcV)
		time.Sleep(time.Second)
		fi, _ := flowOf(pf, srcV)
		live := liveOf(fi.Session)
		if len(live) != 2 {
			t.Fatalf("stimulus: the video flow has %d live members, want 2", len(live))
		}
		var victim rendr.CarrierStatus
		var most, total uint64
		for _, c := range live {
			old, _ := carrierOf(before.Session, c.ID)
			d := c.RxBytes - old.RxBytes
			total += d
			if d >= most {
				most, victim = d, c
			}
		}
		if most*2 <= total {
			t.Fatalf("stimulus: no member carried most of the video in the last second (%d of %d bytes)", most, total)
		}
		l := w.dlink(victim.Name)
		lost0 := l.Stats().Session.Lost
		td := time.Now()
		for _, d := range bothDirs {
			l.Blackhole(d, true)
		}
		sleepUntil(td.Add(drop))
		if l.Stats().Session.Lost == lost0 {
			t.Fatalf("stimulus: the blackhole of %s lost no session datagram", victim.Name)
		}
		downs := w.dev.downOf(victim.ID)
		if len(downs) == 0 {
			t.Fatalf("G10-bond: the silent member %d was still live %v after the blackhole of its path, want its death within the death-detection bound %v", victim.ID, drop, recoveryBound)
		}
		if c := downs[0].Cause; c != rendr.CausePingTimeout && c != rendr.CauseWriteStall && c != rendr.CausePeerDown {
			t.Fatalf("stimulus: the blackholed member %d did not die silently on the dialer: %+v", victim.ID, downs)
		}
		dead := downs[0].Time
		if d := dead.Sub(td); d > recoveryBound {
			t.Fatalf("G10-bond: the silent member %d died %v after the blackhole of its path, want within the death-detection bound %v", victim.ID, d, recoveryBound)
		}
		for _, d := range bothDirs {
			l.Blackhole(d, false)
		}
		rm := time.Now()
		waitFor(t, mlRejoin, "a member on the restored path again within G5Bound", func() bool {
			fi, _ := flowOf(pf, srcV)
			for _, c := range liveOf(fi.Session) {
				if c.Name == victim.Name {
					return true
				}
			}
			return false
		})
		rejoin := time.Since(rm)
		// The judged span ends tail after the removal, and never less than
		// a second after the rejoin: a gap or a loss at the rejoin is judged
		// in every lane.
		to := rm.Add(max(tail, rejoin+time.Second))
		sleepUntil(to.Add(time.Second))
		pEnd := time.Now()
		m.end()
		time.Sleep(time.Second) // the last datagrams arrive

		sent, lost := sentIn(m.vDown.ledger, td, dead), len(m.vDown.lossesIn(td, dead))
		t.Logf("blackhole of %s (member %d, %d of %d video bytes in the last second): dead (%v) after %v; video sent until then %d, arrived %d (recorded); a member on the path again %v after the removal (G5Bound %v)",
			victim.Name, victim.ID, most, total, downs[0].Cause, dead.Sub(td), sent, sent-lost, rejoin, mlRejoin)
		rec := bondDropRecovery(t, m.vDown.ledger, td, to, td)
		t.Logf("the video recovered %v after the blackhole (the end of its last arrival gap above %v; bound %v)", rec, mlStopMax, recoveryBound)

		wins := map[*mlFlow][]window{}
		for _, f := range m.flows() {
			wins[f] = []window{{td.Add(-mlW), td.Add(recoveryBound)}}
		}
		m.idrExtend(wins)
		for _, f := range m.flows() {
			f.integrity(t)
			if n := f.bad.Load(); n != 0 {
				t.Fatalf("%s: %d datagrams failed their CRC or carried another flow's tag", f.name, n)
			}
			n := f.lossesOutsideIn(t, s0, pEnd, wins[f], td)
			t.Logf("%s: %d sent, %d arrived, %d lost inside W %s", f.name, f.sentCount(), f.arrived(), n, fmtWindows(wins[f], td))
		}
		oneFlow(t, w, pf, 0, 3)
		w.noViolation()
		w.close()
	})
}

// bondDropRecovery judges G10-bond's DROP rule as the M6 delegate decision
// of 2026-10-21 amends it (the death-detection bound, judged as
// G4-pkt-bond's recovery is, F14): every arrival gap of ledger l above
// mlStopMax in [td − mlSpanBefore, to] lies inside [td − mlW, td +
// recoveryBound] — a silent member's share may stop the stream until its
// death is detected, nothing else may stop it for longer than mlStopMax.
// It returns the recovery: the end of the last such gap less td (0 when
// the stream never stopped for longer than mlStopMax). Instants are
// printed relative to origin.
func bondDropRecovery(t *testing.T, l *ledger, td, to, origin time.Time) time.Duration {
	t.Helper()
	var rec time.Duration
	for _, g := range gapsAbove(l, td.Add(-mlSpanBefore), to, mlStopMax) {
		if g.from.Before(td.Add(-mlW)) || g.to.After(td.Add(recoveryBound)) {
			t.Fatalf("G10-bond: %s stopped for %v in [+%v, +%v] around the blackhole at +%v, want no gap above %v outside [t_d − %v, t_d + %v] (the death-detection bound)",
				l.name, g.to.Sub(g.from), g.from.Sub(origin), g.to.Sub(origin), td.Sub(origin), mlStopMax, mlW, recoveryBound)
		}
		rec = g.to.Sub(td)
	}
	return rec
}

// sentIn counts the ledger's datagrams sent in [from, until).
func sentIn(l *ledger, from, until time.Time) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, at := range l.sent {
		if !at.IsZero() && !at.Before(from) && at.Before(until) {
			n++
		}
	}
	return n
}
