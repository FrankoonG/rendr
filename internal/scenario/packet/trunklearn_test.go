package packet

import (
	"fmt"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestPacketTrunkCloseEverySessionLearns_L45_L39 (RI part 2, proposed
// failing-first row for G6-nat-multivm run 20261014-080240-a87e,
// inflight_probe_close): the in-flight row closes the dialer's conn of a
// carrier that one session uses. In G6 the probe session's members were
// shared MUX trunks of the natu Peer (its first member, carrier 24, served
// 417 sessions over the run and 31 of them lost it at the close), so the
// dialer's local close of one trunk makes every session on it publish a
// death SCHED at once, each on its surviving trunk. A SCHED on a datagram
// carrier is REL-wrapped, and a carrier's REL window holds wire.RelWindow
// (8) unacknowledged control frames for all the sessions it carries; the
// probe's passive wrote its replies on the dead trunk for at least 9.4 ms
// after the dialer's CarrierDown (until its ping_timeout 3.1 s later), the
// last ones 4.4 ms past the earliest instant the death SCHED could have
// reached it, with every drop counter 0 and no stall.
//
// The row replays it in virtual time: N bond packet sessions of one Peer
// over two shared trunks (G6's natu path: 5 ms one way, the 1-ms echo),
// the dialer's conn of trunk u1 closed between two requests, and it checks
// for every session the L45 contract the G6 judge relies on (the 13:45
// physical bound): its passive moves off the closed trunk within one
// one-way delay (plus the observation's two polls), and every reply its
// passive writes after that instant arrives.
//
// A passive moves off the trunk at the first of two events: it applies a
// SCHED the dialer published after the close (RI's observable, the only
// one before PA-86), or its own end of the trunk ends and its session's
// death rules move its replies (a bond member dies). PA-86's DOWN causes
// the second: the dialer's DOWN for the closed trunk, one REL ahead of the
// death SCHEDs on the surviving trunk, kills the passive's end of it
// (cause peer_down) one one-way delay after the close, whatever N is,
// while the death SCHEDs themselves still pass the REL window eight at a
// time (they change the epoch only; the replies have moved). A move of the
// second kind counts only by that mechanism: the session's passive
// recorded the trunk's CarrierDown with cause peer_down, no earlier than
// one one-way delay after the close (the DOWN's flight) and no later than
// the poll that saw the move. Without PA-86 the passive's end lives until
// its ping timeout, so the row fails at 32 sessions and more on the
// merge-base. The 256-session subtest raises the datagram trunk's view cap
// (64 by default, MuxMaxViewsDatagram) on both Runtimes so that one trunk
// still carries every session, as the premise requires: M4 puts each
// forwarded TCP connection on shared trunks, far beyond 32. The event
// queues hold every session's events of the close (premise: none dropped).
func TestPacketTrunkCloseEverySessionLearns_L45_L39(t *testing.T) {
	for _, n := range []int{8, 32, 256} {
		t.Run(fmt.Sprintf("sessions=%d", n), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { trunkCloseLearns(t, n) })
		})
	}
}

// sessionDownOf returns the EventCarrierDown of carrier id in session sid.
func sessionDownOf(l *eventLog, sid rendr.SessionID, id rendr.CarrierID) (rendr.Event, bool) {
	for _, ev := range l.of(rendr.EventCarrierDown) {
		if ev.Session == sid && ev.Carrier == id {
			return ev, true
		}
	}
	return rendr.Event{}, false
}

// trunkSess is one session of the trunk row.
type trunkSess struct {
	dc, pc *rendr.PacketConn
	echo   *echoer
	ver    *rendrtest.PacketVerifier
	mu     sync.Mutex
	got    map[uint64]bool
	rdone  chan error
}

func trunkCloseLearns(t *testing.T, n int) {
	o := worldOpts{oneWay: clOneWay}
	if n >= 64 {
		o.ov.MuxMaxViewsDatagram = 2 * n // one trunk per link carries every session (the premise below)
	}
	o.ov.EventQueue = 16*n + 256 // every session's CarrierDown and migration events of the close, with room (Config.OnEvent's default queue is 256)
	w := newWorld(t, o, "u1", "u2")
	p := w.peer("u1", "u2")
	ss := make([]*trunkSess, n)
	for i := range ss {
		dc, pc := w.open(p, rendr.DialOptions{Mode: rendr.ModeBond})
		ss[i] = &trunkSess{dc: dc, pc: pc, got: map[uint64]bool{}, rdone: make(chan error, 1)}
	}
	for i, s := range ss {
		waitFor(t, 5*time.Second, fmt.Sprintf("two members on both ends of session %d", i), func() bool {
			return len(liveOf(s.dc.Status())) == 2 && len(liveOf(s.pc.Status())) == 2
		})
	}
	// Premise: the sessions share the two trunks (the dialer's MUX on
	// datagram carriers, M3).
	vic, ok := liveNamed(ss[0].dc.Status(), "u1")
	if !ok {
		t.Fatalf("session 0 has no live carrier on u1: %+v", ss[0].dc.Status().Carriers)
	}
	for i, s := range ss {
		if c, ok := liveNamed(s.dc.Status(), "u1"); !ok || c.ID != vic.ID {
			t.Fatalf("premise: session %d's u1 member is %+v (found %v), not the shared trunk %d", i, c, ok, vic.ID)
		}
	}
	for i, s := range ss {
		seed := uint64(0x7000 + i)
		s.echo = startEcho(s.pc, seed)
		s.ver = rendrtest.NewPacketVerifier(seed)
		go func() {
			buf := make([]byte, s.dc.MaxPayload()+1)
			for {
				m, _, err := s.dc.ReadFrom(buf)
				if err != nil {
					s.rdone <- err
					return
				}
				if verr := s.ver.Add(buf[:m], time.Now()); verr != nil {
					s.rdone <- verr
					return
				}
				s.mu.Lock()
				s.got[seqOf(buf)] = true
				s.mu.Unlock()
			}
		}()
	}

	// The observer: from the close on, every clPoll, the first poll at
	// which each session's passive has moved off the closed trunk: it
	// applied an epoch the dialer published after the close, or it no
	// longer lists the closed trunk as a live carrier. A session that moved
	// is not polled again, and nothing is polled before the close (256
	// sessions' Status every 100 µs is most of the row's cost under -race);
	// virtual time does not move while the observer reads.
	var tClose time.Time
	ePre := make([]uint32, n)
	learn := make([]time.Duration, n) // -1 until the session's passive moved off
	bySchedOf := make([]bool, n)      // it moved by a post-close SCHED (else: its end of the trunk ended)
	for i := range learn {
		learn[i] = -1
	}
	closing, stop, odone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(odone)
		select {
		case <-closing:
		case <-stop:
			return
		}
		for {
			if now := time.Now(); now.After(tClose) {
				for i, s := range ss {
					if learn[i] >= 0 {
						continue
					}
					ps := s.pc.Status()
					dEpoch := s.dc.Status().SchedEpoch
					c, ok := carrierOf(ps, vic.ID)
					live := ok && (c.State == rendr.CarrierActive || c.State == rendr.CarrierMember)
					sched := ps.SchedEpoch > ePre[i] && ps.SchedEpoch <= dEpoch
					if sched || !live {
						learn[i], bySchedOf[i] = now.Sub(tClose), sched
					}
				}
			}
			select {
			case <-stop:
				return
			case <-time.After(clPoll):
			}
		}
	}()

	start := time.Now()
	var wg sync.WaitGroup
	for i, s := range ss {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, clSize)
			for seq := range uint64(clRequests) {
				sleepUntil(start.Add(time.Duration(seq) * clGap))
				if _, err := s.dc.WriteTo(rendrtest.PacketPayload(buf, uint64(0x7000+i), seq, clSize, time.Now()), nil); err != nil {
					t.Errorf("session %d: WriteTo of request %d: %v", i, seq, err)
					return
				}
			}
		}()
	}
	sleepUntil(start.Add(10*clGap + clGap/2))
	for i, s := range ss {
		ePre[i] = s.dc.Status().SchedEpoch
	}
	tClose = time.Now()
	close(closing)
	w.localClose(vic.ID)
	wg.Wait()
	sleepUntil(start.Add(clRequests*clGap + 300*time.Millisecond))
	close(stop)
	<-odone

	down, ok := w.dev.downOf(vic.ID)
	if !ok || down.Cause != rendr.CauseTransportError {
		t.Fatalf("stimulus: the dialer's CarrierDown of trunk %d is %+v (found %v), want transport_error", vic.ID, down, ok)
	}
	bound := clOneWay + 2*clPoll
	bySched := 0 // sessions whose passive moved by a post-close SCHED (else: its end of the trunk ended)
	for _, b := range bySchedOf {
		if b {
			bySched++
		}
	}
	sorted := slices.Clone(learn)
	slices.Sort(sorted)
	t.Logf("%d sessions on trunks %d (closed) and its mate: moved off after the close: min %v, median %v, max %v (bound %v); %d by a SCHED, %d by their end of the trunk ending",
		n, vic.ID, sorted[0], sorted[n/2], sorted[n-1], bound, bySched, n-bySched)
	if st := w.p.Status(); st.EventsDropped != 0 {
		t.Fatalf("premise: the passive Runtime dropped %d events", st.EventsDropped)
	}
	var late []string
	for i, d := range learn {
		switch {
		case d < 0:
			late = append(late, fmt.Sprintf("session %d never applied a post-close SCHED and kept the closed trunk", i))
		case d > bound:
			late = append(late, fmt.Sprintf("session %d after %v", i, d))
		}
		if d < 0 || bySchedOf[i] {
			continue
		}
		// Moved because its end of the trunk ended: only by the dialer's
		// DOWN (rendr.CausePeerDown, compared by its name so that the row
		// builds on the merge-base too).
		ev, ok := sessionDownOf(w.pev, ss[i].pc.ID(), vic.ID)
		if !ok || ev.Cause.String() != "peer_down" || ev.Time.Before(tClose.Add(clOneWay)) || ev.Time.After(tClose.Add(d)) {
			late = append(late, fmt.Sprintf("session %d: its end of the trunk ended (found %v) %v after the close with %v, want peer_down within [one-way, %v]",
				i, ok, ev.Time.Sub(tClose), ev.Cause, d))
		}
	}
	// Every reply written after its passive learned arrives.
	for i, s := range ss {
		if learn[i] < 0 {
			continue
		}
		tl := tClose.Add(learn[i])
		s.mu.Lock()
		for seq := range uint64(clRequests) {
			if at, echoed := s.echo.echoedAt(seq); echoed && at.After(tl.Add(clPoll)) && !s.got[seq] {
				late = append(late, fmt.Sprintf("session %d: reply %d written %v after the close (learned %v) never arrived", i, seq, at.Sub(tClose), learn[i]))
				break
			}
		}
		s.mu.Unlock()
	}
	if len(late) > 0 {
		t.Fatalf("the passives did not move off the closed trunk within one one-way delay (%v; L45, the G6 judge's physical bound): %d of %d: %v",
			bound, len(late), n, late[:min(len(late), 8)])
	}
	for _, s := range ss {
		s.dc.Close()
	}
	for i, s := range ss {
		select {
		case <-s.echo.done:
		case <-time.After(30 * time.Second):
			t.Fatalf("session %d's echo did not end", i)
		}
	}
	w.close()
}
