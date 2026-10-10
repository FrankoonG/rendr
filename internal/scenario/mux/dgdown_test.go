package mux

import (
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
)

// TestMuxDatagramTrunkKillDownPerSession_R13 (M3 design §A5 death fan-out,
// §A10 events; B0.2 / R-13, plan:184; DGDOWN, the first full-scale G6
// run's packet kill k18): one Peer with two raw-UDP-like datagram
// factories u1 and u2 (DatagramLinks, 10 ms RTT) carries 16 long packet
// sessions — selector, bond and race in turn; half of them echo one
// datagram every 200 ms, the other half stay idle, so that their actors
// park (G6's idle long sessions) — and 14 churn workers that open, echo
// once and close packet sessions back to back on the same trunks, so a
// trunk carries about 30 views at once while views open, retire and end
// beside the long ones. At a random instant (1.5 to 2.5 s after the long
// sessions opened) the dialer's conn of the trunk that carries the most
// views is closed under rendr (F10's local close: the harness's
// carrier.close) while the churn runs on.
//
// Premise and stimulus proof: the killed trunk carried at least 8 long
// sessions and at least one churn session at the kill (both read from
// every dialer session's Status at the kill's virtual instant), some
// session actor was parked at the kill, the close returned nil, and the
// churn completed cycles after the kill.
// PASS (dialer, where the kill is local): every session whose Status
// listed a live or retiring view on the trunk at the kill records its own
// CarrierDown of the trunk's ID at or after the kill and within 2 s of it
// (B1.5's dialer bound; the gold cases select a kill's records by these
// times; a long session's within 1 ms: its death step runs at the kill's
// virtual instant, woken by the trunk's death fan-out) — a long session
// exactly one per view it held there, with transport_error (retired only
// for a view listed retiring, whose retirement completed at the kill's
// instant; a view listed active or member records transport_error, the
// gold packet kill's dialer cause, B1.5); a churn
// session too unless it was already ending at the kill (its SessionEnd at
// the kill's instant: an ending session records no CarrierDown, §A10) —;
// for every session the CarrierDowns of the trunk's ID equal its dead
// rows of that ID one to one (a long session; an ending churn session may
// record fewer), with the row's cause; no session's Status lists the
// trunk live after the kill. Passive: every long session listed at the
// kill records its CarrierDown of the trunk within 15 s. No carrier ended
// with protocol_violation; every session ends cleanly and both Runtimes
// close without leftovers.
//
// This row held before DGDOWN's fix (600 runs at -cpu 1,2,4): the per-view
// fan-out and Status's listing are complete under churn. G6's missing
// record was a CarrierDown dated at the start of a step that began before
// the close (a virtual-time bubble runs a step at one instant, so this row
// cannot show it); TestCarrierDownDatedAtItsDeathStep in package session
// is that defect's failing-first row.
func TestMuxDatagramTrunkKillDownPerSession_R13(t *testing.T) {
	synctest.Test(t, func(t *testing.T) { dgKillChurn(t) })
}

// dgSess is one dialer packet session of the scenario.
type dgSess struct {
	key  string
	long bool
	d    *rendr.PacketConn
}

// dgKill is the scenario's world and populations.
type dgKill struct {
	w  *world
	pu *rendr.Peer

	stop   chan struct{}
	wg     sync.WaitGroup
	cycles atomic.Int64 // churn cycles completed
	failed atomic.Int64 // churn cycles that ended early (a dial or an exchange crossing the kill)

	mu   sync.Mutex
	sess []*dgSess
}

var dgModes = [3]rendr.Mode{rendr.ModeSelector, rendr.ModeBond, rendr.ModeRace}

const (
	dgLong    = 16
	dgWorkers = 14
	// dgDownBound is the dialer's bound for its record of a local close
	// (the gold cases' packet kills, B1.5: transport_error within 2 s).
	dgDownBound = 2 * time.Second
	// dgLongBound is a long session's bound: its actor learns the local
	// close through the trunk's death fan-out (its view's doorbell) and
	// runs the death step at once — at the kill's virtual instant here (a
	// churn session in its closing phase may wait for its reader first).
	dgLongBound = time.Millisecond
)

func dgKillChurn(t *testing.T) {
	const oneWay = 5 * time.Millisecond
	w := newWorld(t, worldOpts{}, linkSpec{name: "u1", oneWay: oneWay, dgram: true}, linkSpec{name: "u2", oneWay: oneWay, dgram: true})
	k := &dgKill{w: w, pu: w.peer("u1", "u2"), stop: make(chan struct{})}
	w.addStop(k.stop)

	// The long sessions and their echo loops.
	type longEnd struct {
		s    ppair
		done chan struct{}
	}
	var longs []longEnd
	for i := range dgLong {
		s := w.openPacket(k.pu, fmt.Sprintf("L%02d", i), dgModes[i%3])
		k.add(&dgSess{key: s.key, long: true, d: s.d})
		le := longEnd{s: s, done: make(chan struct{})}
		go echoUntilEOF(s.p, nil)
		if i%2 == 0 {
			go k.longPing(s, le.done)
		} else {
			close(le.done) // idle: its actor parks
		}
		longs = append(longs, le)
	}
	for i := range dgWorkers {
		k.wg.Go(func() { k.churn(i) })
	}

	// The kill: at a random instant 1.5 to 2.5 s from here (the idle
	// sessions' actors parked after ActorLinger, 1 s), once a trunk
	// carries at least 8 long sessions and one churn session.
	sleepUntil(time.Now().Add(1500*time.Millisecond + time.Duration(rand.N(1000))*time.Millisecond))
	var target rendr.CarrierID
	var listed map[*dgSess][]rendr.CarrierState
	deadline := time.Now().Add(2 * time.Second)
	for {
		target, listed = k.pick()
		nl, nc := 0, 0
		for s := range listed {
			if s.long {
				nl++
			} else {
				nc++
			}
		}
		if nl >= 8 && nc >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("premise: no trunk carried ≥ 8 long and ≥ 1 churn session within 2 s (best %d: %d long, %d churn)", target, nl, nc)
		}
		time.Sleep(time.Millisecond)
	}
	if parked := testhooks.ParkedSessions.Load() - w.parked0; parked <= 0 {
		t.Fatalf("premise: no session actor parked at the kill (%d)", parked)
	}
	killAt := time.Now()
	w.localClose(target)
	before := k.cycles.Load()
	sleepUntil(killAt.Add(2 * time.Second))
	close(k.stop)
	k.wg.Wait()
	if after := k.cycles.Load(); after <= before {
		t.Fatalf("stimulus: no churn cycle completed after the kill (%d before)", before)
	}
	for _, le := range longs {
		<-le.done
	}
	sleepUntil(killAt.Add(16 * time.Second)) // the passive's death records (≤ 15 s)

	k.judge(t, target, killAt, listed)

	for _, le := range longs {
		closePacket(t, le.s)
	}
	w.noViolation()
	t.Logf("trunk %d: %d sessions listed at the kill; churn cycles %d (%d ended early)", target, len(listed), k.cycles.Load(), k.failed.Load())
	w.close()
}

func (k *dgKill) add(s *dgSess) {
	k.mu.Lock()
	k.sess = append(k.sess, s)
	k.mu.Unlock()
}

func (k *dgKill) all() []*dgSess {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]*dgSess(nil), k.sess...)
}

// pick reads every dialer session's Status and returns the carrier with
// the most live or retiring views and, per session on it, the states of
// its rows of that carrier.
func (k *dgKill) pick() (rendr.CarrierID, map[*dgSess][]rendr.CarrierState) {
	rows := map[rendr.CarrierID]map[*dgSess][]rendr.CarrierState{}
	for _, s := range k.all() {
		for _, cs := range s.d.Status().Carriers {
			switch cs.State {
			case rendr.CarrierActive, rendr.CarrierMember, rendr.CarrierRetiring:
				if rows[cs.ID] == nil {
					rows[cs.ID] = map[*dgSess][]rendr.CarrierState{}
				}
				rows[cs.ID][s] = append(rows[cs.ID][s], cs.State)
			}
		}
	}
	var best rendr.CarrierID
	for id, m := range rows {
		if best == 0 || len(m) > len(rows[best]) {
			best = id
		}
	}
	return best, rows[best]
}

// longPing writes one datagram every 200 ms on a long session's dialer
// end and reads the echoes, until the churn stops.
func (k *dgKill) longPing(s ppair, done chan struct{}) {
	defer close(done)
	go func() {
		buf := make([]byte, s.d.MaxPayload()+1)
		for {
			if _, _, err := s.d.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	msg := []byte("long " + s.key)
	for {
		select {
		case <-k.stop:
			return
		case <-time.After(200 * time.Millisecond):
		}
		if _, err := s.d.WriteTo(msg, nil); err != nil {
			return
		}
	}
}

// echoUntilEOF echoes every datagram on c until ReadFrom fails (io.EOF:
// the dialer's clean end), then closes c. got, when not nil, receives the
// first datagram's arrival.
func echoUntilEOF(c *rendr.PacketConn, got chan<- struct{}) {
	defer c.Close()
	buf := make([]byte, c.MaxPayload()+1)
	for {
		n, _, err := c.ReadFrom(buf)
		if err != nil {
			return
		}
		if got != nil {
			got <- struct{}{}
			got = nil
		}
		if _, err := c.WriteTo(buf[:n], nil); err != nil {
			return
		}
	}
}

// churn runs worker i's cycles until the stop: open a packet session
// (modes in turn), echo one datagram, close it and wait until both ends
// are done.
func (k *dgKill) churn(i int) {
	for n := 0; ; n++ {
		select {
		case <-k.stop:
			return
		default:
		}
		key := fmt.Sprintf("c%02d-%04d", i, n)
		if !k.cycle(key, dgModes[(i+n)%3]) {
			k.failed.Add(1)
		} else {
			k.cycles.Add(1)
		}
		time.Sleep(time.Duration(rand.N(20)) * time.Millisecond)
	}
}

// cycle is one churn cycle; false when it ended early (a Dial or the echo
// crossed the kill). Both ends are done when it returns.
func (k *dgKill) cycle(key string, mode rendr.Mode) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	d, err := k.pu.DialPacket(ctx, rendr.DialOptions{Mode: mode, Metadata: []byte(key)})
	cancel()
	if err != nil {
		return false
	}
	k.add(&dgSess{key: key, d: d})
	var p *rendr.PacketConn
	select {
	case p = <-k.w.packetCh(key):
	case <-time.After(5 * time.Second):
		d.Close()
		<-d.Done()
		return false
	}
	go echoUntilEOF(p, nil)
	ok := true
	if _, err := d.WriteTo([]byte(key), nil); err != nil {
		ok = false
	} else {
		_ = d.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, d.MaxPayload()+1)
		if n, _, err := d.ReadFrom(buf); err != nil || string(buf[:n]) != key {
			ok = false
		}
	}
	d.Close()
	for _, c := range []*rendr.PacketConn{d, p} {
		select {
		case <-c.Done():
		case <-time.After(40 * time.Second):
			panic(fmt.Sprintf("churn %s: a session end did not finish within 40 s: %+v", key, c.Status()))
		}
	}
	return ok
}

// closePacket ends a long session: the dialer closes, the passive's echo
// loop reads io.EOF and closes; both end with io.EOF.
func closePacket(t testing.TB, s ppair) {
	t.Helper()
	s.d.Close()
	for _, c := range []*rendr.PacketConn{s.d, s.p} {
		select {
		case <-c.Done():
		case <-time.After(40 * time.Second):
			t.Fatalf("%s: a session did not end within 40 s: %+v", s.key, c.Status())
		}
		if st := c.Status(); st.Err != io.EOF {
			t.Fatalf("%s: the %v session ended with %v, want io.EOF", s.key, st.Role, st.Err)
		}
	}
}

// judge checks the death records of the kill (see the test's comment).
func (k *dgKill) judge(t *testing.T, target rendr.CarrierID, killAt time.Time, listed map[*dgSess][]rendr.CarrierState) {
	t.Helper()
	w := k.w
	ends := map[rendr.SessionID]rendr.Event{}
	for _, ev := range w.dev.of(rendr.EventSessionEnd) {
		ends[ev.Session] = ev
	}
	var bad []string
	for _, s := range k.all() {
		sid := s.d.ID()
		var downs, after []rendr.Event
		for _, ev := range w.dev.downOf(target) {
			if ev.Session == sid {
				downs = append(downs, ev)
				if !ev.Time.Before(killAt) {
					after = append(after, ev)
				}
			}
		}
		var dead []rendr.CarrierStatus
		for _, cs := range s.d.Status().Carriers {
			if cs.ID != target {
				continue
			}
			if cs.State != rendr.CarrierDead {
				bad = append(bad, fmt.Sprintf("%s: Status lists the killed carrier %d %v after the kill", s.key, target, cs.State))
				continue
			}
			dead = append(dead, cs)
		}
		end, ended := ends[sid]
		ending := ended && !end.Time.After(killAt) // ending at the kill's instant
		if st, on := listed[s]; on && (s.long || !ending) {
			if len(after) != len(st) {
				bad = append(bad, fmt.Sprintf("%s (long %v): listed %v on carrier %d at the kill, %d CarrierDown of it at or after the kill (%v), want %d",
					s.key, s.long, st, target, len(after), causes(after), len(st)))
			}
			// retired only for a view listed retiring at the kill (its
			// retirement completed at the kill's instant); a view listed
			// active or member records the kill's transport_error (B1.5's
			// dialer cause).
			retiring, retired := 0, 0
			for _, cs := range st {
				if cs == rendr.CarrierRetiring {
					retiring++
				}
			}
			for _, ev := range after {
				switch ev.Cause {
				case rendr.CauseTransportError:
				case rendr.CauseRetired:
					retired++
				default:
					bad = append(bad, fmt.Sprintf("%s: CarrierDown of the killed carrier with %v, want transport_error", s.key, ev.Cause))
				}
				if bound := dgDownBound; ev.Time.After(killAt.Add(bound)) || s.long && ev.Time.After(killAt.Add(dgLongBound)) {
					if s.long {
						bound = dgLongBound
					}
					bad = append(bad, fmt.Sprintf("%s: CarrierDown of the killed carrier %v after the kill, want ≤ %v", s.key, ev.Time.Sub(killAt), bound))
				}
			}
			if retired > retiring {
				bad = append(bad, fmt.Sprintf("%s: listed %v on carrier %d at the kill, %d CarrierDown with retired at or after the kill (%v): retired only for a view listed retiring",
					s.key, st, target, retired, causes(after)))
			}
		}
		if s.long || !ended {
			if len(downs) != len(dead) {
				bad = append(bad, fmt.Sprintf("%s: %d CarrierDown of carrier %d (%v), %d dead rows of it", s.key, len(downs), target, causes(downs), len(dead)))
			} else {
				for i := range downs {
					if downs[i].Cause != dead[i].DeathCause {
						bad = append(bad, fmt.Sprintf("%s: CarrierDown %d with %v, its row's cause %v", s.key, i, downs[i].Cause, dead[i].DeathCause))
					}
				}
			}
		} else if len(downs) > len(dead) {
			bad = append(bad, fmt.Sprintf("%s: %d CarrierDown of carrier %d (%v), only %d dead rows of it", s.key, len(downs), target, causes(downs), len(dead)))
		}
	}
	// The passive's records of the long sessions on the trunk.
	pdowns := map[rendr.SessionID]bool{}
	for _, ev := range w.pev.downOf(target) {
		if !ev.Time.Before(killAt) && ev.Time.Before(killAt.Add(15*time.Second)) {
			pdowns[ev.Session] = true
		}
	}
	for s, st := range listed {
		if s.long && !pdowns[s.d.ID()] {
			bad = append(bad, fmt.Sprintf("%s: listed %v on carrier %d at the kill, no passive CarrierDown of it within 15 s", s.key, st, target))
		}
	}
	if len(bad) > 0 {
		t.Fatalf("trunk %d killed at %v with %d sessions listed:\n%s", target, killAt, len(listed), strings.Join(bad, "\n"))
	}
}

// causes lists the events' causes.
func causes(evs []rendr.Event) []string {
	out := make([]string, len(evs))
	for i, ev := range evs {
		out[i] = ev.Cause.String()
	}
	return out
}
