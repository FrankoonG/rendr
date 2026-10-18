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
// port's first source (learn-and-stream). Q: 10 s through rendr without
// events, whose frame-completion p99.9 + 20 ms is the frame deadline of T
// (G10 criterion 3 with Q in place of the direct baseline, which an
// in-process world does not have). T: four kills — a local close of the
// carrier carrying video (selector: the video flow's active carrier in
// Flows(); bond and race: the member whose received bytes grew most in the
// last second, alternating on a tie) at T + 5, 12, 19 and 26 s — and the
// blackhole of a path (selector: the active one; bond and race: one
// member's) both ways at T + 33 s for 20 s, then its removal; T ends 10 s
// later (lane: under the race detector the selector only, Q 3 s, one kill
// at T + 2 s, the blackhole at T + 7 s for 6 s, T's end 2 s after the
// removal; the same windows and bounds).
//
// Windows W per flow and direction (G10, R1-31): a kill [t − 200 ms,
// t + 200 ms] (G3's, plan:750; race none); the blackhole, selector [t_d −
// 200 ms, r_f + 200 ms] with r_f that flow's first arrival in that
// direction of a datagram sent after t_d, and r_f within recoveryBound of
// t_d (DeadMax + dial + JOIN, plan:757); bond [t_d − 200 ms, t_d + 5 s]
// (the member's share until its death is known); race none; the removal
// none. Every video W's end extends through the recovery IDR: to the
// completion of the first IDR frame started within [t, W's end + 0.5 s].
//
// Stimulus: every kill's carrier is dead on the dialer's video session
// within a second and (selector) another is active; the blackholed link
// lost session datagrams and its carrier died (ping_timeout or
// write_stall, PA-86's peer_down reading); bond and race: both members
// live before each event and again within 10 s of the removal.
//
// PASS: integrity — every datagram of every flow intact (CRC) and once;
// loss — none outside W per flow and direction (race: none at all); frames
// — outside W every video frame complete by its deadline and every audio
// block complete (race: every frame and block in T); selector: frames
// complete again within 200 ms of each kill and within recoveryBound of the
// blackhole (the W rule); IDR requests only for incomplete frames (none in
// race); added latency after events — video one-way p99 outside W ≤ Q's +
// 5 ms and p99.9 ≤ Q's + 20 ms (G10 criterion 5); control — never
// "disconnected" (no 10-s silence at either end), every message acked by
// the end, at most 5 retransmissions of messages first sent in T outside W
// (criterion 7 with Q's rate, 0, as the baseline); NAT behaviour (F79) —
// three flows, each opened once (Opened 3, Confirmed 3, three target
// dials: one egress source per flow) and TooLarge 0 at both ends.
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
	sleepUntil(q0.Add(lane.mlQuiet))
	q1 := time.Now()
	qFrames := m.completions(q0, q1.Add(-200*time.Millisecond), nil)
	if len(qFrames) < int(lane.mlQuiet/mlInterval)*6/10 {
		t.Fatalf("load: Q has %d complete frames, want about %d", len(qFrames), int(lane.mlQuiet/mlInterval))
	}
	p999 := pctl(qFrames, 0.999)
	m.deadline.Store(int64(p999 + 20*time.Millisecond))
	qDelay := m.vDown.delays(q0, q1.Add(-200*time.Millisecond), nil)
	qp99, qp999 := pctl(qDelay, 0.99), pctl(qDelay, 0.999)
	t.Logf("Q: %d frames, completion p99.9 %v (deadline %v); video one-way p99 %v p99.9 %v", len(qFrames), p999, p999+20*time.Millisecond, qp99, qp999)

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
	if mode != rendr.ModeSelector {
		for _, src := range []netip.AddrPort{srcV, srcA, srcC} {
			if fi, _ := flowOf(pf, src); len(liveOf(fi.Session)) != 2 {
				t.Fatalf("bond/race: the flow of %v has %d live members after the removal, want 2: %+v", src, len(liveOf(fi.Session)), fi.Session.Carriers)
			}
		}
	}

	// Windows per flow and direction.
	flows := []*mlFlow{m.vDown, m.aDown, m.cDown, m.vUp, m.aUp, m.cUp}
	wins := map[*mlFlow][]window{}
	for _, f := range flows {
		wins[f] = m.windows(t, f, evs, mode)
	}
	m.idrExtend(wins, evs)
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
	m.judgeFrames(t, t0, tEnd, wins[m.vDown], wins[m.aDown], mode)
	m.judgeControl(t, t0, tEnd, wins[m.cUp])
	tDelay := m.vDown.delays(t0, tEnd, wins[m.vDown])
	if p99, p999 := pctl(tDelay, 0.99), pctl(tDelay, 0.999); p99 > qp99+5*time.Millisecond || p999 > qp999+20*time.Millisecond {
		t.Fatalf("latency after events: video one-way p99 %v (Q %v + 5 ms), p99.9 %v (Q %v + 20 ms)", p99, qp99, p999, qp999)
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

// kill closes, at at, the dialer's conn of the carrier carrying the video
// flow (selector: its active carrier; bond and race: the member whose
// received bytes grew most over the last second, alternating with k on a
// tie) and checks that it died.
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
	w.localClose(victim.ID)
	waitFor(t, time.Second, fmt.Sprintf("kill %d: carrier %d dead", k, victim.ID), func() bool {
		fi, _ := flowOf(pf, srcV)
		c, _ := carrierOf(fi.Session, victim.ID)
		if c.State != rendr.CarrierDead {
			return false
		}
		a, ok := activeOf(fi.Session)
		return mode != rendr.ModeSelector || ok && a.ID != victim.ID
	})
	return mlEvent{at: at, link: victim.Name, id: victim.ID}
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
func (m *mlRun) idrExtend(wins map[*mlFlow][]window, evs []mlEvent) {
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
	_ = evs
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

// judgeFrames applies criterion 3: outside W every video frame of T is
// complete by its deadline and every audio block complete (race: every
// one); IDR requests only for incomplete frames.
func (m *mlRun) judgeFrames(t *testing.T, t0, tEnd time.Time, vw, aw []window, mode rendr.Mode) {
	t.Helper()
	off := time.Duration(m.deadline.Load())
	m.mu.Lock()
	frames, audio := slices.Clone(m.frames), slices.Clone(m.audio)
	requested, reqs := m.requested, m.idrReqs
	m.mu.Unlock()
	var nT, inc, incW int
	for _, fr := range frames {
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
		incW++
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
	if requested > inc+m.qIncomplete(t0) || (mode == rendr.ModeRace && requested != 0) {
		t.Fatalf("IDR requests: the client sent %d for %d incomplete frames in T (race: want none)", requested, inc)
	}
	t.Logf("frames: %d in T, %d incomplete (all inside W); audio blocks incomplete inside W %d; IDR requests sent %d, received %d", nT, inc, aInc, requested, reqs)
}

// qIncomplete counts the frames before t0 that were incomplete at their
// deadline then (the setup and Q; none expected).
func (m *mlRun) qIncomplete(t0 time.Time) int {
	m.mu.Lock()
	frames := slices.Clone(m.frames)
	m.mu.Unlock()
	n := 0
	for _, fr := range frames {
		if fr.start.Before(t0) {
			if ok, _ := m.frameDone(fr, fr.start.Add(mlPreDeadline)); !ok {
				n++
			}
		}
	}
	return n
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
