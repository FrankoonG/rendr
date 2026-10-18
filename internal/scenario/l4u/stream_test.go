package l4u

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/l4"
)

// The Moonlight-like stream miniature (M6 design §A16.2; G10 at reduced
// scale, §B5.1).
const (
	mlW       = 200 * time.Millisecond
	mlRejoin  = 10 * time.Second // a bond or race member rejoins within this of the removal
	mlIDRWait = 500 * time.Millisecond
	// G10's per-event bounds: the interruption of an event at t is the
	// largest video arrival gap in [t − 1 s, t + 6 s] less Q's largest gap.
	mlSpanBefore = time.Second
	mlSpanAfter  = 6 * time.Second
	mlStopMax    = 200 * time.Millisecond // CLOSE (selector, bond): interruption below this; bond DROP: no arrival gap above it
	mlRaceStop   = 50 * time.Millisecond  // race: CLOSE and DROP interruption below this
	// mlMaxAge is Packet.MaxAge's default: a datagram queued in a window
	// ages out (DropAge) at most this long after its WriteTo.
	mlMaxAge = 100 * time.Millisecond
	// mlSample is criterion 8's sampling period of the dialer sessions'
	// drop counters.
	mlSample = 25 * time.Millisecond
)

// mlEvent is one event of T: a kill (a local close of the carrier carrying
// video) or the blackhole of a path.
type mlEvent struct {
	at     time.Time
	drop   bool
	link   string
	id     rendr.CarrierID
	remove time.Time // drop: the blackhole's end
}

// TestL4UStreamMiniature_L39_L40_L70 (§A16.2; G10, §B3.1 and §B5.1 at
// 1/20 of the video rate; L39, L40, L70): the ML-100 profile's three UDP
// flows — video (60 fps, frames of 10.4 KB mean, lognormal σ 0.25 clipped
// to [0.25, 3]× the mean, an IDR of 4× every 600 frames and on request,
// coalesced; 1,408-byte shards with 20 % parity per block), audio (4 data
// and 2 parity shards of 220 bytes every 20 ms) and the ENet-shaped
// control (250 reliable 48-byte messages per second acked by the host,
// RTO max(srtt + 4·rttvar, 100 ms), 500 ms at first, doubling; feedback
// 10 per second; keepalives each way every 500 ms; IDR requests when a
// frame is incomplete at its deadline) — through one PortForward (three
// ServeUDP sockets) over a Peer of two DatagramLinks v1 and v2 with 1,500-
// byte links and a raised budget (frame budget 1,463: MaxPayload 1,438, the
// L4U-1472 configuration), per mode (selector, bond, race). The host sends
// on the video and audio ports only after a ping arrived, and only to that
// port's first source (learn-and-stream).
//
// Phases. R, the direct baseline, is exact in process (profile_test.go:
// every one-way delay and frame completion is oneWay, a control round trip
// 2·oneWay), so the frame deadline is G10's — first shard's send + R's
// p99.9 frame completion + 20 ms — from the start. Q: 10 s through rendr
// without events. T: four kills — a local close of the carrier carrying
// video (selector: the video flow's active carrier in Flows(); bond and
// race: the member whose received bytes grew most in the last second,
// alternating on a tie) at T + 5, 12, 19 and 26 s — and the blackhole of a
// path (selector: the active one; bond and race: one member's) both ways at
// T + 33 s for 20 s, then its removal; T ends 10 s later (lane: under the
// race detector the selector only, Q 3 s, one kill at T + 2 s, the
// blackhole at T + 7 s for 6 s, T's end 2 s after the removal; the same
// windows and bounds).
//
// Windows W per flow and direction (G10, R1-31): a kill [t − 200 ms,
// t + 200 ms] (G3's, plan:750; race none); the blackhole, selector [t_d −
// 200 ms, r_f + 200 ms] with r_f that flow's first arrival in that
// direction of a datagram sent after t_d, and r_f within recoveryBound of
// t_d (DeadMax + dial + JOIN, plan:757); bond [t_d − 200 ms, t_d + 5 s]
// (the member's share until its death is known); race none; the removal
// none. Every video W's end extends through the recovery IDR: to the
// completion of the first IDR frame started within [t, W's end + 0.5 s].
// The per-event judges below bound what that extension may hide.
//
// Stimulus: every kill's carrier is dead on the dialer's video session
// within a second and (selector) another is active, with a death migration
// of that carrier counted; the blackholed link lost session datagrams and
// its carrier died within recoveryBound (ping_timeout or write_stall,
// PA-86's peer_down reading); bond and race: both members live before each
// event and again within 10 s of the removal.
//
// PASS (G10's criteria, numbered as there):
//
//  1. integrity — every datagram of every flow intact (CRC) and once;
//  2. loss — none in Q (R1-42), none outside W in T per flow and direction
//     (race: none at all);
//  3. frames — every video frame of Q, and outside W every one of T,
//     complete by its deadline, every audio block complete (race: every
//     frame and block); an IDR request only for a frame incomplete at its
//     deadline, none for a frame of Q, none for a frame of Q or T in race
//     (a request is attributed to the frame it asks for: the setup's
//     frames, before Q, are in no judged phase, R1-42);
//  4. Q against R — no migration in Q (R1-42); video one-way p50 ≤ R +
//     1 ms, p99 ≤ R + 3 ms, p99.9 ≤ R + 10 ms; frame completion p99 ≤ R +
//     5 ms; audio and control one-way p99 ≤ R + 3 ms (both control
//     directions); control round trip p99 ≤ R + 6 ms;
//  5. T outside W against Q — video one-way p99 ≤ Q + 5 ms and p99.9 ≤ Q
//     + 20 ms, frame completion p99 ≤ Q + 5 ms, control round trip p99 ≤ Q
//     + 5 ms (bond's single-path interval is judged against Q too: Q is R
//     in process);
//  6. NAT behaviour (F79) — three flows, each opened once (Opened 3,
//     Confirmed 3, three target dials: one egress source per flow) and
//     TooLarge 0 at both ends;
//  7. control — never "disconnected" (no 10-s silence at either end), every
//     message acked by the end, at most 5 retransmissions of messages first
//     sent in T outside W (R's rate, 0, as the baseline);
//  8. counters — the dialer sessions' DropQueue, DropRecvQueue and DropAge
//     rise only inside a W of their flow (either direction, an increment
//     trailing a W's end by at most mlMaxAge + mlSample), never in Q (the
//     passive's sessions are not reachable from the public API per flow:
//     their drops show as the losses criterion 2 judges);
//
// and per event (interruption = the largest video arrival gap in [t − 1 s,
// t + 6 s], cut at the next event, less Q's largest gap): a kill's
// interruption < 200 ms (race: < 50 ms) — "frames complete again within
// 200 ms of a kill" (§A16.2), whatever the IDR extension of its W; the
// blackhole: selector the first arrival of every flow within recoveryBound
// (the W rule), race an interruption < 50 ms, bond the member's death
// within recoveryBound (G10-bond's other rule, no video arrival gap above
// 200 ms, is recorded here and judged by
// TestL4UBondSilentMemberKeepsStream_L39, merged with its decision); the
// removal: no loss.
func TestL4UStreamMiniature_L39_L40_L70(t *testing.T) {
	for _, mode := range lane.mlModes {
		t.Run(mode.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { mlMiniature(t, mode) })
		})
	}
}

func mlMiniature(t *testing.T, mode rendr.Mode) {
	w := newWorld(t, worldOpts{}, linkSpec{name: "v1"}, linkSpec{name: "v2"})
	m := newMLRun(w.quit)
	w.target(mlVideoPort, m.hostVideo)
	w.target(mlAudioPort, m.hostAudio)
	w.target(mlCtlPort, m.hostControl)
	pf := &l4.PortForward{Peer: w.peer("v1", "v2"), Options: rendr.DialOptions{Mode: mode}}
	inV := w.forward(pf, targetAddr(mlVideoPort), hubCfg(1))
	inA := w.forward(pf, targetAddr(mlAudioPort), hubCfg(2))
	inC := w.forward(pf, targetAddr(mlCtlPort), hubCfg(3))
	client := netip.AddrFrom4([4]byte{192, 0, 2, 50})
	srcV, srcA, srcC := netip.AddrPortFrom(client, 50000), netip.AddrPortFrom(client, 50001), netip.AddrPortFrom(client, 50002)
	cv, ca, cc := inV.client(srcV), inA.client(srcA), inC.client(srcC)
	m.clientControl(cc)
	m.clientVideo(cv, cc)
	m.clientAudio(ca)

	members := 1
	if mode != rendr.ModeSelector {
		members = 2
	}
	waitFor(t, 15*time.Second, "three flows open and streaming", func() bool {
		for _, src := range []netip.AddrPort{srcV, srcA, srcC} {
			fi, ok := flowOf(pf, src)
			if !ok || fi.State != l4.FlowOpen || len(liveOf(fi.Session)) < members {
				return false
			}
		}
		return m.vDown.arrived() > 0 && m.aDown.arrived() > 0 && m.cDown.arrived() > 0
	})

	// Q.
	q0 := time.Now()
	drops := sampleDrops(pf, []netip.AddrPort{srcV, srcA, srcC}, w.quit)
	sleepUntil(q0.Add(lane.mlQuiet))
	q1 := time.Now()

	// T.
	t0 := time.Now()
	var evs []mlEvent
	for k := range lane.mlKills {
		at := t0.Add(lane.mlFirst + time.Duration(k)*lane.mlKill)
		evs = append(evs, m.kill(t, w, pf, srcV, mode, k, at, members))
	}
	evs = append(evs, m.blackhole(t, w, pf, srcV, mode, t0.Add(lane.mlFirst+time.Duration(lane.mlKills)*lane.mlKill), members))
	tEnd := evs[len(evs)-1].remove.Add(lane.mlTail)
	sleepUntil(tEnd)
	m.end()
	time.Sleep(time.Second) // the last datagrams arrive
	drops.end()
	if mode != rendr.ModeSelector {
		for _, src := range []netip.AddrPort{srcV, srcA, srcC} {
			if fi, _ := flowOf(pf, src); len(liveOf(fi.Session)) != 2 {
				t.Fatalf("bond/race: the flow of %v has %d live members after the removal, want 2: %+v", src, len(liveOf(fi.Session)), fi.Session.Carriers)
			}
		}
	}

	// Q against R (criteria 2, 3 and 4 in Q; R1-42).
	qb := m.judgeQ(t, w, q0, q1)

	// Windows per flow and direction.
	flows := m.flows()
	wins := map[*mlFlow][]window{}
	for _, f := range flows {
		wins[f] = m.windows(t, f, evs, mode)
	}
	m.idrExtend(wins)
	for _, f := range flows {
		f.integrity(t)
		if n := f.bad.Load(); n != 0 {
			t.Fatalf("%s: %d datagrams failed their CRC or carried another flow's tag", f.name, n)
		}
		lost := f.lossesOutsideIn(t, t0, tEnd, wins[f], t0)
		if mode == rendr.ModeRace {
			if ls := f.lossesIn(t0, tEnd); len(ls) != 0 {
				t.Fatalf("race: %s lost %d datagrams (first: seq %d at +%v), want none", f.name, len(ls), ls[0].seq, ls[0].sent.Sub(t0))
			}
		}
		t.Logf("%s: %d sent, %d arrived, %d lost inside W %s", f.name, f.sentCount(), f.arrived(), lost, fmtWindows(wins[f], t0))
	}
	m.judgeFrames(t, q0, t0, tEnd, wins[m.vDown], wins[m.aDown], mode)
	m.judgeControl(t, t0, tEnd, wins[m.cUp])
	m.judgeEvents(t, evs, mode, qb.gap, t0, tEnd)

	// Criterion 5: T outside W against Q.
	tDelay := m.vDown.delays(t0, tEnd, wins[m.vDown])
	tFrames := m.completions(t0, tEnd, wins[m.vDown])
	tRTT := m.rtts(t0, tEnd, wins[m.cUp], wins[m.cDown])
	p99, p999, fc99, rtt99 := pctl(tDelay, 0.99), pctl(tDelay, 0.999), pctl(tFrames, 0.99), pctl(tRTT, 0.99)
	t.Logf("T outside W: video one-way p99 %v p99.9 %v, frame completion p99 %v, control round trip p99 %v (%d frames, %d messages)",
		p99, p999, fc99, rtt99, len(tFrames), len(tRTT))
	if p99 > qb.vP99+5*time.Millisecond || p999 > qb.vP999+20*time.Millisecond {
		t.Fatalf("latency after events: video one-way p99 %v (Q %v + 5 ms), p99.9 %v (Q %v + 20 ms)", p99, qb.vP99, p999, qb.vP999)
	}
	if fc99 > qb.fcP99+5*time.Millisecond || rtt99 > qb.rttP99+5*time.Millisecond {
		t.Fatalf("latency after events: frame completion p99 %v (Q %v + 5 ms), control round trip p99 %v (Q %v + 5 ms)", fc99, qb.fcP99, rtt99, qb.rttP99)
	}

	// Criterion 8: the dialer sessions' drop counters only inside W.
	for _, fw := range []struct {
		name string
		src  netip.AddrPort
		up   *mlFlow
		down *mlFlow
	}{{"video", srcV, m.vUp, m.vDown}, {"audio", srcA, m.aUp, m.aDown}, {"control", srcC, m.cUp, m.cDown}} {
		drops.judge(t, fw.name, fw.src, append(slices.Clone(wins[fw.up]), wins[fw.down]...), q0, q1, t0)
	}

	for _, port := range []uint16{mlVideoPort, mlAudioPort, mlCtlPort} {
		if es := w.egressesOf(port); len(es) != 1 {
			t.Fatalf("F79: %d target dials toward port %d, want one egress source for the flow's whole life", len(es), port)
		}
	}
	oneFlow(t, w, pf, 0, 3)
	if ps, ss := pf.Status().UDP, w.srv.Status().UDP; ps.TooLarge != 0 || ss.TooLarge != 0 || ps.MaxPayload != kitPayload || ss.MaxPayload != kitPayload {
		t.Fatalf("sizes: TooLarge %d at the ingress and %d at the passive, MaxPayload %d and %d; want 0 and %d", ps.TooLarge, ss.TooLarge, ps.MaxPayload, ss.MaxPayload, kitPayload)
	}
	w.noViolation()
	w.close()
}

// flows returns the six flow directions.
func (m *mlRun) flows() []*mlFlow {
	return []*mlFlow{m.vDown, m.aDown, m.cDown, m.vUp, m.aUp, m.cUp}
}

// kill closes, at at, the dialer's conn of the carrier carrying the video
// flow (selector: its active carrier; bond and race: the member whose
// received bytes grew most over the last second, alternating with k on a
// tie) and checks that it died (selector: with a death migration of the
// video session away from it).
func (m *mlRun) kill(t *testing.T, w *world, pf *l4.PortForward, srcV netip.AddrPort, mode rendr.Mode, k int, at time.Time, members int) mlEvent {
	t.Helper()
	sleepUntil(at.Add(-time.Second))
	before, _ := flowOf(pf, srcV)
	sleepUntil(at)
	fi, _ := flowOf(pf, srcV)
	live := liveOf(fi.Session)
	if len(live) < members {
		t.Fatalf("stimulus: kill %d: the video flow has %d live carriers, want %d: %+v", k, len(live), members, fi.Session.Carriers)
	}
	var victim rendr.CarrierStatus
	if mode == rendr.ModeSelector {
		victim, _ = activeOf(fi.Session)
	} else {
		deltas := make([]uint64, len(live))
		best := 0
		for i, c := range live {
			old, _ := carrierOf(before.Session, c.ID)
			deltas[i] = c.RxBytes - old.RxBytes
			if deltas[i] > deltas[best] {
				best = i
			}
		}
		victim = live[best]
		tie := true
		for _, d := range deltas {
			if d+deltas[best]/10 < deltas[best] {
				tie = false
			}
		}
		if tie {
			victim = live[k%len(live)] // alternating
		}
	}
	deaths := fi.Session.Migrations
	w.localClose(victim.ID)
	waitFor(t, time.Second, fmt.Sprintf("kill %d: carrier %d dead (selector: another active, and a death migration away from it in the dialer's Status and events)", k, victim.ID), func() bool {
		fi, _ = flowOf(pf, srcV)
		c, _ := carrierOf(fi.Session, victim.ID)
		if c.State != rendr.CarrierDead {
			return false
		}
		a, ok := activeOf(fi.Session)
		return mode != rendr.ModeSelector || ok && a.ID != victim.ID && fi.Session.Migrations.Death > deaths.Death && m.migratedFrom(w, fi.Session.ID, victim.ID, at)
	})
	if mode != rendr.ModeSelector {
		t.Logf("kill %d (%v): the video session's migrations %+v before, %+v after", k, mode, deaths, fi.Session.Migrations)
	}
	return mlEvent{at: at, link: victim.Name, id: victim.ID}
}

// migratedFrom reports whether the dialer emitted a migration of session
// id away from carrier from at or after at.
func (m *mlRun) migratedFrom(w *world, id rendr.SessionID, from rendr.CarrierID, at time.Time) bool {
	for _, ev := range w.dev.of(rendr.EventMigration) {
		if ev.Session == id && ev.From == from && !ev.Time.Before(at) {
			return true
		}
	}
	return false
}

// blackhole drops every datagram of the link carrying the video (selector:
// the active carrier's; bond and race: one member's) both ways from at for
// lane.mlDrop, then lifts it.
func (m *mlRun) blackhole(t *testing.T, w *world, pf *l4.PortForward, srcV netip.AddrPort, mode rendr.Mode, at time.Time, members int) mlEvent {
	t.Helper()
	sleepUntil(at)
	fi, _ := flowOf(pf, srcV)
	live := liveOf(fi.Session)
	if len(live) < members {
		t.Fatalf("stimulus: the blackhole: the video flow has %d live carriers, want %d", len(live), members)
	}
	victim := live[0]
	if a, ok := activeOf(fi.Session); ok {
		victim = a
	}
	l := w.dlink(victim.Name)
	lost0 := l.Stats().Session.Lost
	for _, d := range bothDirs {
		l.Blackhole(d, true)
	}
	sleepUntil(at.Add(lane.mlDrop))
	if l.Stats().Session.Lost == lost0 {
		t.Fatalf("stimulus: the blackhole of %s lost no session datagram", victim.Name)
	}
	down := w.dev.downOf(victim.ID)
	if len(down) == 0 || (down[0].Cause != rendr.CausePingTimeout && down[0].Cause != rendr.CauseWriteStall && down[0].Cause != rendr.CausePeerDown) {
		t.Fatalf("stimulus: the blackholed carrier %d did not die silently on the dialer: %+v", victim.ID, down)
	}
	if d := down[0].Time.Sub(at); d > recoveryBound {
		t.Fatalf("the blackholed carrier %d died %v after the blackhole, want within %v (G10: the member's death ≤ 5 s)", victim.ID, d, recoveryBound)
	}
	for _, d := range bothDirs {
		l.Blackhole(d, false)
	}
	rm := time.Now()
	if mode != rendr.ModeSelector {
		waitFor(t, mlRejoin, "a member on the restored path again", func() bool {
			fi, _ := flowOf(pf, srcV)
			for _, c := range liveOf(fi.Session) {
				if c.Name == victim.Name {
					return true
				}
			}
			return false
		})
		t.Logf("blackhole of %s: a member on it again %v after the removal", victim.Name, time.Since(rm))
	}
	t.Logf("blackhole of %s (carrier %d): dead (%v) after %v", victim.Name, victim.ID, down[0].Cause, down[0].Time.Sub(at))
	return mlEvent{at: at, drop: true, link: victim.Name, id: victim.ID, remove: rm}
}

// windows returns flow f's loss windows for the events (G10's W, per flow
// and direction).
func (m *mlRun) windows(t *testing.T, f *mlFlow, evs []mlEvent, mode rendr.Mode) []window {
	t.Helper()
	var ws []window
	for _, ev := range evs {
		switch {
		case mode == rendr.ModeRace:
		case !ev.drop:
			ws = append(ws, window{ev.at.Add(-mlW), ev.at.Add(mlW)})
		case mode == rendr.ModeBond:
			ws = append(ws, window{ev.at.Add(-mlW), ev.at.Add(5 * time.Second)})
		default:
			rf := f.firstArrivalFrom(ev.at)
			if rf.IsZero() || rf.Sub(ev.at) > recoveryBound {
				t.Fatalf("%s: the first datagram sent after the blackhole arrived at %+v of it, want within %v", f.name, rf.Sub(ev.at), recoveryBound)
			}
			ws = append(ws, window{ev.at.Add(-mlW), rf.Add(mlW)})
		}
	}
	return ws
}

// idrExtend extends every video window's end through the recovery IDR: to
// the completion of the first IDR frame started within [t, end + 0.5 s].
func (m *mlRun) idrExtend(wins map[*mlFlow][]window) {
	m.mu.Lock()
	frames := slices.Clone(m.frames)
	m.mu.Unlock()
	vw := wins[m.vDown]
	for i := range vw {
		for _, fr := range frames {
			if fr.idr && !fr.start.Before(vw[i].from.Add(mlW)) && !fr.start.After(vw[i].to.Add(mlIDRWait)) {
				if ok, done := m.frameDone(fr, fr.start.Add(time.Hour)); ok && done.After(vw[i].to) {
					vw[i].to = done
				}
				break
			}
		}
	}
}

// completions returns the completion latency of every frame started in
// [from, to) that completed (first shard's send → the last block's
// completing shard), skipping frames started inside a window.
func (m *mlRun) completions(from, to time.Time, skip []window) []time.Duration {
	m.mu.Lock()
	frames := slices.Clone(m.frames)
	m.mu.Unlock()
	var out []time.Duration
	for _, fr := range frames {
		if fr.start.Before(from) || !fr.start.Before(to) || inAny(skip, fr.start) {
			continue
		}
		if ok, done := m.frameDone(fr, fr.start.Add(time.Hour)); ok {
			out = append(out, done.Sub(fr.start))
		}
	}
	return out
}

// rtts returns the round trip (first send → ack) of every reliable control
// message first sent in [from, to) and acked, skipping those first sent
// inside a window of either control direction.
func (m *mlRun) rtts(from, to time.Time, skipUp, skipDown []window) []time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []time.Duration
	for _, g := range m.msgs {
		if g.first.Before(from) || !g.first.Before(to) || g.acked.IsZero() || inAny(skipUp, g.first) || inAny(skipDown, g.first) {
			continue
		}
		out = append(out, g.acked.Sub(g.first))
	}
	return out
}

// qBase is Q's baseline for criterion 5 and the per-event judges.
type qBase struct {
	vP99, vP999, fcP99, rttP99 time.Duration
	gap                        time.Duration // the largest video arrival gap in Q
}

// judgeQ applies G10's rules to Q [q0, q1): no lost datagram and no
// migration (R1-42), every frame complete by its deadline and no IDR
// request for one or sent in Q (criterion 3), and criterion 4 against the
// in-process R; it returns Q's baseline.
func (m *mlRun) judgeQ(t *testing.T, w *world, q0, q1 time.Time) qBase {
	t.Helper()
	for _, f := range m.flows() {
		if ls := f.lossesIn(q0, q1); len(ls) != 0 {
			t.Fatalf("Q: %s lost %d datagrams (first: seq %d at +%v of Q), want none (R1-42)", f.name, len(ls), ls[0].seq, ls[0].sent.Sub(q0))
		}
	}
	for i, l := range []*eventLog{w.dev, w.pev} {
		for _, ev := range l.of(rendr.EventMigration) {
			if !ev.Time.Before(q0) && ev.Time.Before(q1) {
				t.Fatalf("Q: the %s's session %v migrated at +%v of Q (%+v), want no migration (R1-42)", side(i), ev.Session, ev.Time.Sub(q0), ev)
			}
		}
	}
	m.mu.Lock()
	frames := slices.Clone(m.frames)
	reqFor, reqAt := slices.Clone(m.reqFor), slices.Clone(m.reqAt)
	m.mu.Unlock()
	off := time.Duration(m.deadline.Load())
	inQ := map[uint32]bool{}
	var fc []time.Duration
	for _, fr := range frames {
		if fr.start.Before(q0) || !fr.start.Before(q1) {
			continue
		}
		inQ[fr.id] = true
		ok, done := m.frameDone(fr, fr.start.Add(off))
		if !ok {
			t.Fatalf("Q: frame %d (IDR %v) started at +%v of Q is incomplete at its deadline (+%v)", fr.id, fr.idr, fr.start.Sub(q0), off)
		}
		fc = append(fc, done.Sub(fr.start))
	}
	if want := int(q1.Sub(q0) / mlInterval); len(fc) < want*9/10 {
		t.Fatalf("load: Q has %d frames, want about %d", len(fc), want)
	}
	for i, id := range reqFor {
		if inQ[id] {
			t.Fatalf("Q: the client asked for an IDR for frame %d of Q (sent at +%v of Q), want none in Q", id, reqAt[i].Sub(q0))
		}
	}
	vd := m.vDown.delays(q0, q1, nil)
	rtt := m.rtts(q0, q1, nil, nil)
	b := qBase{vP99: pctl(vd, 0.99), vP999: pctl(vd, 0.999), fcP99: pctl(fc, 0.99), rttP99: pctl(rtt, 0.99), gap: maxGap(m.vDown.ledger, q0, q1)}
	v50 := pctl(vd, 0.5)
	t.Logf("Q (R: one-way %v, frame %v, round trip %v; deadline %v): %d frames, completion p99 %v; video one-way p50 %v p99 %v p99.9 %v; control round trip p99 %v; largest video gap %v",
		rOneWay, rFrame, rRTT, off, len(fc), b.fcP99, v50, b.vP99, b.vP999, b.rttP99, b.gap)
	if v50 > rOneWay+time.Millisecond || b.vP99 > rOneWay+3*time.Millisecond || b.vP999 > rOneWay+10*time.Millisecond {
		t.Fatalf("criterion 4: video one-way in Q p50 %v p99 %v p99.9 %v, want ≤ R (%v) + 1, 3 and 10 ms", v50, b.vP99, b.vP999, rOneWay)
	}
	if b.fcP99 > rFrame+5*time.Millisecond {
		t.Fatalf("criterion 4: frame completion in Q p99 %v, want ≤ R (%v) + 5 ms", b.fcP99, rFrame)
	}
	for _, f := range []*mlFlow{m.aDown, m.cUp, m.cDown} {
		if p := pctl(f.delays(q0, q1, nil), 0.99); p > rOneWay+3*time.Millisecond {
			t.Fatalf("criterion 4: %s one-way in Q p99 %v, want ≤ R (%v) + 3 ms", f.name, p, rOneWay)
		}
	}
	if len(rtt) == 0 || b.rttP99 > rRTT+6*time.Millisecond {
		t.Fatalf("criterion 4: control round trip in Q p99 %v over %d messages, want ≤ R (%v) + 6 ms", b.rttP99, len(rtt), rRTT)
	}
	return b
}

// judgeFrames applies criterion 3 to T: outside W every video frame of T
// is complete by its deadline and every audio block complete (race: every
// one); every IDR request asked for a frame incomplete at its deadline
// (none in race).
func (m *mlRun) judgeFrames(t *testing.T, q0, t0, tEnd time.Time, vw, aw []window, mode rendr.Mode) {
	t.Helper()
	off := time.Duration(m.deadline.Load())
	m.mu.Lock()
	frames, audio := slices.Clone(m.frames), slices.Clone(m.audio)
	reqFor, reqs := slices.Clone(m.reqFor), m.idrReqs
	m.mu.Unlock()
	var nT, inc int
	byID := map[uint32]mlFrame{}
	for _, fr := range frames {
		byID[fr.id] = fr
		if fr.start.Before(t0) || !fr.start.Before(tEnd) {
			continue
		}
		nT++
		if ok, _ := m.frameDone(fr, fr.start.Add(off)); ok {
			continue
		}
		inc++
		if mode == rendr.ModeRace || !inAny(vw, fr.start) {
			t.Fatalf("frame %d (IDR %v) started at +%v is incomplete at its deadline (+%v) outside W %s", fr.id, fr.idr, fr.start.Sub(t0), off, fmtWindows(vw, t0))
		}
	}
	var aInc int
	for _, b := range audio {
		if b.start.Before(t0) || !b.start.Before(tEnd) {
			continue
		}
		if ok, _ := blocksDone(m.aDown.ledger, b, b.start.Add(time.Hour)); !ok {
			aInc++
			if mode == rendr.ModeRace || !inAny(aw, b.start) {
				t.Fatalf("audio block %d started at +%v is incomplete outside W", b.id, b.start.Sub(t0))
			}
		}
	}
	if nT < int((tEnd.Sub(t0))/mlInterval)*9/10 {
		t.Fatalf("load: %d frames in T, want about %d", nT, int(tEnd.Sub(t0)/mlInterval))
	}
	judged := 0 // requests for frames of Q or T
	for _, id := range reqFor {
		fr, ok := byID[id]
		if !ok {
			t.Fatalf("IDR requests: the client asked for frame %d, which the host never sent", id)
		}
		if !fr.start.Before(q0) && fr.start.Before(tEnd) {
			judged++
		}
		// Complete strictly before its deadline: the client's judge, which
		// runs at or after the deadline, saw it complete (a shard arriving
		// in the deadline's own instant may be seen either way).
		if done, _ := m.frameDone(fr, fr.start.Add(off-1)); done {
			t.Fatalf("IDR requests: the client asked for frame %d (started at +%v), complete before its deadline", id, fr.start.Sub(t0))
		}
	}
	if mode == rendr.ModeRace && judged != 0 {
		t.Fatalf("IDR requests: race: the client sent %d for frames of Q and T, want none", judged)
	}
	t.Logf("frames: %d in T, %d incomplete (all inside W); audio blocks incomplete inside W %d; IDR requests sent %d (%d for frames of Q and T), received %d",
		nT, inc, aInc, len(reqFor), judged, reqs)
}

// judgeEvents applies G10's per-event bounds. The interruption of an
// event at t is the largest video arrival gap (host → client) in [t − 1 s,
// t + 6 s], cut at the next event (or T's end), less Q's largest gap.
func (m *mlRun) judgeEvents(t *testing.T, evs []mlEvent, mode rendr.Mode, qGap time.Duration, t0, tEnd time.Time) {
	t.Helper()
	for i, ev := range evs {
		next := tEnd
		if i+1 < len(evs) {
			next = evs[i+1].at
		}
		var gapAt time.Time
		span := func(to time.Time) time.Duration {
			if to.After(next) {
				to = next
			}
			var g time.Duration
			g, gapAt = maxGapAt(m.vDown.ledger, ev.at.Add(-mlSpanBefore), to)
			return g
		}
		switch {
		case !ev.drop:
			bound := mlStopMax
			if mode == rendr.ModeRace {
				bound = mlRaceStop
			}
			g := span(ev.at.Add(mlSpanAfter))
			t.Logf("kill at +%v (%s, carrier %d): largest video gap %v from +%v, interruption %v (bound %v)", ev.at.Sub(t0), ev.link, ev.id, g, gapAt.Sub(t0), g-qGap, bound)
			if g-qGap >= bound {
				t.Fatalf("kill at +%v: the video interruption is %v (largest gap %v less Q's %v), want below %v", ev.at.Sub(t0), g-qGap, g, qGap, bound)
			}
		case mode == rendr.ModeBond:
			// Recorded here; G10-bond's rule (no video arrival gap above
			// 200 ms) is TestL4UBondSilentMemberKeepsStream_L39's, which
			// fails on the core of 2026-10-18: the bond keeps placing the
			// video on the silent member until its death (the WP9 report's
			// open item).
			g := span(ev.remove.Add(mlSpanAfter))
			t.Logf("blackhole at +%v (%s): largest video gap until the removal + %v: %v from +%v (G10-bond's bound %v: TestL4UBondSilentMemberKeepsStream_L39)",
				ev.at.Sub(t0), ev.link, mlSpanAfter, g, gapAt.Sub(t0), mlStopMax)
		case mode == rendr.ModeRace:
			g := span(ev.at.Add(mlSpanAfter))
			t.Logf("blackhole at +%v (%s): largest video gap %v, interruption %v (bound %v)", ev.at.Sub(t0), ev.link, g, g-qGap, mlRaceStop)
			if g-qGap >= mlRaceStop {
				t.Fatalf("race: the video interruption at the blackhole (+%v) is %v, want below %v", ev.at.Sub(t0), g-qGap, mlRaceStop)
			}
		}
	}
}

// judgeControl applies criterion 7: never disconnected, every message
// acked, at most 5 retransmissions of messages first sent outside W.
func (m *mlRun) judgeControl(t *testing.T, t0, tEnd time.Time, cw []window) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cliGap >= mlDisconnect || m.hostGap >= mlDisconnect {
		t.Fatalf("control: disconnected: the longest silence at the client %v, at the host %v (limit %v)", m.cliGap, m.hostGap, mlDisconnect)
	}
	unacked := 0
	for _, g := range m.msgs {
		if g.acked.IsZero() {
			unacked++
		}
	}
	if unacked != 0 {
		t.Fatalf("control: %d of %d reliable messages never acked", unacked, len(m.msgs))
	}
	outside := 0
	for _, first := range m.retx {
		if !first.Before(t0) && first.Before(tEnd) && !inAny(cw, first) {
			outside++
		}
	}
	if outside > 5 {
		t.Fatalf("control: %d retransmissions of messages first sent in T outside W (want at most 5; %d in all)", outside, len(m.retx))
	}
	t.Logf("control: %d messages, all acked; %d retransmissions (%d of messages first sent in T outside W); longest silence client %v host %v; srtt %v",
		len(m.msgs), len(m.retx), outside, m.cliGap, m.hostGap, m.srtt)
}

// dropSampler samples, every mlSample, the drop counters of the dialer
// sessions of some flows (criterion 8): DropQueue, DropRecvQueue, DropAge.
type dropSampler struct {
	stop, done chan struct{}
	s          map[netip.AddrPort][]dropSample
}

type dropSample struct {
	at time.Time
	n  [3]uint64 // DropQueue, DropRecvQueue, DropAge
}

// sampleDrops starts sampling the flows of srcs on pf.
func sampleDrops(pf *l4.PortForward, srcs []netip.AddrPort, quit <-chan struct{}) *dropSampler {
	d := &dropSampler{stop: make(chan struct{}), done: make(chan struct{}), s: map[netip.AddrPort][]dropSample{}}
	go func() {
		defer close(d.done)
		for {
			now := time.Now()
			for _, fi := range pf.Flows() {
				if p := fi.Session.Packet; p != nil && slices.Contains(srcs, fi.Client) {
					d.s[fi.Client] = append(d.s[fi.Client], dropSample{now, [3]uint64{p.DropQueue, p.DropRecvQueue, p.DropAge}})
				}
			}
			select {
			case <-d.stop:
				return
			case <-quit:
				return
			case <-time.After(mlSample):
			}
		}
	}()
	return d
}

// end stops the sampler.
func (d *dropSampler) end() {
	close(d.stop)
	<-d.done
}

// judge fails when flow src's counters rose between two samples where no
// window of ws was open (an increment may trail a window's end by
// mlMaxAge: a datagram written inside it ages out that much later), or
// rose in Q [q0, q1).
func (d *dropSampler) judge(t *testing.T, name string, src netip.AddrPort, ws []window, q0, q1, t0 time.Time) {
	t.Helper()
	ss := d.s[src]
	if len(ss) < 2 {
		t.Fatalf("criterion 8: %d samples of the %s flow's counters", len(ss), name)
	}
	if d := ss[0].at.Sub(q0); d < 0 || d >= mlSample {
		t.Fatalf("criterion 8: the %s flow's first sample at +%v of Q, want at Q's start", name, d)
	}
	rose := 0
	for i := 1; i < len(ss); i++ {
		a, b := ss[i-1], ss[i]
		if a.n == b.n {
			continue
		}
		rose++
		if a.at.Before(q1) && !b.at.After(q1) {
			t.Fatalf("criterion 8: the %s flow's dialer session dropped datagrams in Q (+%v … +%v of Q): DropQueue, DropRecvQueue, DropAge %v → %v",
				name, a.at.Sub(q0), b.at.Sub(q0), a.n, b.n)
		}
		open := false
		for _, w := range ws {
			if !w.from.After(b.at) && !w.to.Add(mlMaxAge).Before(a.at) {
				open = true
				break
			}
		}
		if !open {
			t.Fatalf("criterion 8: the %s flow's dialer session dropped datagrams outside W (+%v … +%v of T; W %s): DropQueue, DropRecvQueue, DropAge %v → %v",
				name, a.at.Sub(t0), b.at.Sub(t0), fmtWindows(ws, t0), a.n, b.n)
		}
	}
	last := ss[len(ss)-1].n
	t.Logf("criterion 8: %s: %d samples, %d with drops (all inside W); DropQueue, DropRecvQueue, DropAge at the end %v", name, len(ss), rose, last)
}

// pctl returns the q-quantile of ds (0 for none).
func pctl(ds []time.Duration, q float64) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	s := slices.Clone(ds)
	slices.Sort(s)
	i := int(float64(len(s)-1) * q)
	return s[i]
}
