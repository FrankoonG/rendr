package mux

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestMuxPacketCarrierCloseLossInFlight_L39 is internal/scenario/packet's
// TestPacketCarrierCloseLossInFlight_L39 (G6's packet-loss gap, m4 design
// R3-17) on G6's own carrier shape: the packet churn session runs as views
// of datagram trunks that a long packet session already holds (the Peers'
// default Props; G6's carrier 12082 carried the long sessions lu000 …
// and the churn session ps2298), and the stimulus — F10's local close of
// the dialer's conn — ends the whole trunk. Schedule, stimulus and
// criteria are the packet row's: replies lost with every drop counter 0,
// each counted in the passive's Sent − PeerReceived; every lost reply
// written by the passive between one one-way delay before the close and
// the instant it applied the first SCHED the dialer published after the
// close; no DGRAM byte of the churn session on the closed trunk from the
// next instant on, although that trunk lives on at the passive; the
// passive learned within one one-way delay (race, bond) or within the
// failover view's JOIN round trip plus one one-way delay (selector).
func TestMuxPacketCarrierCloseLossInFlight_L39(t *testing.T) {
	for _, mode := range []rendr.Mode{rendr.ModeRace, rendr.ModeBond, rendr.ModeSelector} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { muxCloseLossInFlight(t, mode) })
		})
	}
}

// muxCloseObs is one poll of the churn session's Status on both ends.
type muxCloseObs struct {
	at          time.Time
	dEpoch      uint32 // the dialer's last published SCHED epoch
	pEpoch      uint32 // the passive's last applied SCHED epoch
	pTx         uint64 // the passive's DGRAM bytes of this session on the victim trunk
	pVictimLive bool   // the victim is a live carrier of the passive's session
}

// Schedule (G6's natu path and pkt-echo churn session; see the packet row).
const (
	mclOneWay   = 5 * time.Millisecond
	mclGap      = time.Millisecond
	mclRequests = 64
	mclSize     = 200
	mclPoll     = 100 * time.Microsecond
	mclSelClose = 8 * time.Millisecond
)

func muxCloseLossInFlight(t *testing.T, mode rendr.Mode) {
	w := newWorld(t, worldOpts{}, linkSpec{name: "u1", oneWay: mclOneWay, dgram: true}, linkSpec{name: "u2", oneWay: mclOneWay, dgram: true})
	peer := w.peer("u1", "u2")
	// The long session holds a trunk on each link (G6's lu sessions).
	long := w.openPacket(peer, "L", rendr.ModeBond)
	go echoUntilEOF(long.p, nil)
	waitFor(t, 10*time.Second, "the long session on both trunks", func() bool {
		return len(liveOf(long.d.Status())) == 2 && len(liveOf(long.p.Status())) == 2
	})
	trunk, ok := liveNamed(long.d.Status(), "u1")
	if !ok {
		t.Fatalf("no trunk on u1: %+v", long.d.Status().Carriers)
	}

	s := w.openPacket(peer, "C", mode)
	opened := time.Now()
	dc, pc := s.d, s.p
	if vic, ok := liveNamed(dc.Status(), "u1"); !ok || vic.ID != trunk.ID || vic.Shared < 2 {
		t.Fatalf("premise: the churn session did not open as a view of the long session's u1 trunk %d: %+v", trunk.ID, dc.Status().Carriers)
	}
	const seed = 0xc001
	var mu sync.Mutex
	echoed := map[uint64]time.Time{}
	var reads, writes int
	edone := make(chan error, 1)
	go func() {
		defer pc.Close()
		buf := make([]byte, pc.MaxPayload()+1)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				edone <- err
				return
			}
			mu.Lock()
			reads++
			mu.Unlock()
			if _, err := pc.WriteTo(buf[:n], nil); err != nil {
				edone <- err
				return
			}
			mu.Lock()
			writes++
			echoed[seqOf(buf)] = time.Now()
			mu.Unlock()
		}
	}()
	got := map[uint64]bool{}
	ver := rendrtest.NewPacketVerifier(seed)
	rdone := make(chan error, 1)
	go func() {
		buf := make([]byte, dc.MaxPayload()+1)
		for {
			n, _, err := dc.ReadFrom(buf)
			if err != nil {
				rdone <- err
				return
			}
			if verr := ver.Add(buf[:n], time.Now()); verr != nil {
				rdone <- verr
				return
			}
			mu.Lock()
			got[seqOf(buf)] = true
			mu.Unlock()
		}
	}()
	wdone := make(chan error, 1)
	go func() {
		buf := make([]byte, mclSize)
		for seq := range uint64(mclRequests) {
			sleepUntil(opened.Add(time.Duration(seq) * mclGap))
			if _, err := dc.WriteTo(rendrtest.PacketPayload(buf, seed, seq, mclSize, time.Now()), nil); err != nil {
				wdone <- fmt.Errorf("WriteTo of request %d: %w", seq, err)
				return
			}
		}
		wdone <- nil
	}()
	var obs []muxCloseObs
	stop, odone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(odone)
		for {
			ds, ps := dc.Status(), pc.Status()
			o := muxCloseObs{at: time.Now(), dEpoch: ds.SchedEpoch, pEpoch: ps.SchedEpoch}
			if c, ok := carrierOf(ps, trunk.ID); ok {
				o.pTx = c.TxBytes
				o.pVictimLive = c.State == rendr.CarrierActive || c.State == rendr.CarrierMember
			}
			obs = append(obs, o)
			select {
			case <-stop:
				return
			case <-time.After(mclPoll):
			}
		}
	}()

	if mode == rendr.ModeSelector {
		sleepUntil(opened.Add(mclSelClose))
	} else {
		for {
			if _, ok := liveNamed(dc.Status(), "u2"); ok {
				break
			}
			if time.Since(opened) > time.Second {
				t.Fatalf("no second member within 1 s: %+v", dc.Status().Carriers)
			}
			time.Sleep(mclPoll)
		}
	}
	ePre := dc.Status().SchedEpoch
	tClose := time.Now()
	w.localClose(trunk.ID)

	if err := <-wdone; err != nil {
		t.Fatal(err)
	}
	sleepUntil(opened.Add(mclRequests*mclGap + 200*time.Millisecond))
	close(stop)
	<-odone
	waitFor(t, 10*time.Second, "the packet accounting to settle", func() bool {
		ds, ps := dc.Status().Packet, pc.Status().Packet
		return ds.PeerReceived == ps.Received && ps.PeerReceived == ds.Received
	})
	ds, ps := *dc.Status().Packet, *pc.Status().Packet

	// Stimulus.
	if ev, ok := w.dev.sessionDown(dc.ID(), trunk.ID); !ok || ev.Cause != rendr.CauseTransportError || ev.Time.Sub(tClose) > mclPoll {
		t.Fatalf("stimulus: the churn session's CarrierDown of trunk %d is %+v (found %v), want transport_error at the close %v", trunk.ID, ev, ok, tClose)
	}
	lostOnVictim := w.dlink("u1").Stats().Session.Lost
	if lostOnVictim == 0 {
		t.Fatalf("stimulus: the link of the closed trunk lost no datagram")
	}

	// When the passive learned.
	learnIdx := -1
	for i, o := range obs {
		if o.at.After(tClose) && o.pEpoch > ePre && o.pEpoch <= o.dEpoch {
			learnIdx = i
			break
		}
	}
	if learnIdx < 0 || learnIdx+1 >= len(obs) {
		t.Fatalf("the passive applied no SCHED published after the close (dialer epoch at the close %d; last poll %+v)", ePre, obs[len(obs)-1])
	}
	tLearn := obs[learnIdx].at
	learn := tLearn.Sub(tClose)
	// Race, bond: the death verdict's SCHED crosses the u2 trunk once.
	// Selector: the failover view's JOIN round trip on the u2 trunk, then
	// that SCHED. Two polls: the observation's granularity.
	bound := mclOneWay + 2*mclPoll
	if mode == rendr.ModeSelector {
		bound = 3*mclOneWay + 2*mclPoll
	}
	if learn > bound {
		t.Fatalf("the passive applied the dialer's post-close SCHED %v after the close, want ≤ %v", learn, bound)
	}

	// Classification.
	after, last := obs[learnIdx+1], obs[len(obs)-1]
	if !last.pVictimLive {
		t.Fatalf("premise: the closed trunk died on the passive within %v of the close", last.at.Sub(tClose))
	}
	if last.pTx != after.pTx {
		t.Fatalf("(a): the passive placed %d DGRAM bytes of the churn session on trunk %d after it applied the SCHED that dropped it (%v after the close)",
			last.pTx-after.pTx, trunk.ID, learn)
	}
	mu.Lock()
	var lost []uint64
	late := 0
	for seq := range uint64(mclRequests) {
		at, ok := echoed[seq]
		if ok && at.After(after.at) {
			late++
		}
		if !ok || got[seq] {
			continue
		}
		lost = append(lost, seq)
		if at.Before(tClose.Add(-mclOneWay)) || at.After(tLearn) {
			mu.Unlock()
			t.Fatalf("reply %d was lost but written %v after the close, outside [close − one-way, learned = %v]", seq, at.Sub(tClose), learn)
		}
	}
	nr, nw := reads, writes
	mu.Unlock()
	if late == 0 {
		t.Fatalf("load: the passive echoed nothing after it learned (%d echoed)", nw)
	}
	if len(lost) == 0 {
		t.Fatalf("reproduction: no reply lost (the schedule missed G6's window)")
	}
	for i, c := range []rendr.PacketCounters{ds, ps} {
		if drops(&c)+c.DropRecvQueue+c.DropLate != 0 {
			t.Fatalf("%s: a drop counter moved: %+v", side(i), c)
		}
	}
	if n := ps.Sent - ps.PeerReceived; n != uint64(len(lost)) || ps.Sent != uint64(nw) {
		t.Fatalf("accounting: the passive's Sent %d − PeerReceived %d = %d, want the %d replies lost (%d echoed)", ps.Sent, ps.PeerReceived, n, len(lost), nw)
	}
	if n := ds.Sent - ds.PeerReceived; n != uint64(mclRequests-nr) || ds.Sent != mclRequests {
		t.Fatalf("accounting: the dialer's Sent %d − PeerReceived %d, but the passive read %d of %d requests", ds.Sent, ds.PeerReceived, nr, mclRequests)
	}
	if res := ver.Result(); res.Duplicates+res.Corrupt+res.BadSize != 0 {
		t.Fatalf("integrity: %+v", res)
	}
	t.Logf("%v: closed trunk %d (shared) %v after the open; passive learned %v later (epoch %d → %d); %d of %d replies lost, the link lost %d datagrams",
		mode, trunk.ID, tClose.Sub(opened), learn, ePre, obs[learnIdx].pEpoch, len(lost), nw, lostOnVictim)

	// Clean end of both sessions.
	dc.Close()
	select {
	case err := <-rdone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("the dialer's reader ended with %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the dialer's reader did not end")
	}
	select {
	case err := <-edone:
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("the echo ended with %v, want io.EOF", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("the echo did not end: %+v", pc.Status())
	}
	closePacket(t, s)
	closePacket(t, long)
	w.noViolation()
	w.close()
}
