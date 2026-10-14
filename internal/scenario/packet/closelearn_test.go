package packet

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestPacketCloseInWriteRoundPassiveLearns_L45_L39 (RI part 2, proposed
// failing-first row for G6-nat-multivm run 20261014-080240-a87e,
// inflight_probe_close): the in-flight row (TestPacketCarrierCloseLossInFlight_L39)
// closes the dialer's conn between two requests, so the dialer's death
// step never has a request to hand back; the unsent row
// (TestPacketCarrierCloseUnsentReplaced_L39) closes it inside a write
// round, so a request is handed back and re-placed, but it never checks
// the passive. In the pool run both happened at once: the dialer's local
// close of the bond member 24 landed while a request was placed and
// unwritten (A's death step counted a bond death migration from 24: its
// requeue was not empty), and the passive then wrote every reply of the
// probe on 24 — five of them 0.2 to 4.4 ms after the earliest instant the
// dialer's death SCHED could have reached it — until its ping_timeout
// 3.1 s later, with every drop counter 0 and no stall.
//
// The row replays that schedule in virtual time (G6's natu path: 5 ms one
// way, the 1-ms echo, the close inside the dialer's BeforeWrite of a
// request datagram on the victim) for the member modes and checks the L45
// contract the G6 judge relies on (the 13:45 physical bound): the passive
// applies a SCHED the dialer published after the close within one one-way
// delay (plus the observation's two polls) of the close, it writes no reply
// on the victim after that instant, and every reply it writes later is
// delivered.
func TestPacketCloseInWriteRoundPassiveLearns_L45_L39(t *testing.T) {
	for _, mode := range []rendr.Mode{rendr.ModeBond, rendr.ModeRace} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { closeInRoundLearns(t, mode) })
		})
	}
}

func closeInRoundLearns(t *testing.T, mode rendr.Mode) {
	stim := &unsentStim{}
	// The dialer's last published SCHED epoch in the instant before the
	// stimulus closes the conn, read in the write hook that closes it: an
	// epoch above it was published after the close. The observer cannot
	// tell it: its poll in the close's own virtual instant may run after
	// the dialer's death verdict and already see the death's epoch.
	var dcRef atomic.Pointer[rendr.PacketConn]
	var preEpoch atomic.Int64
	preEpoch.Store(-1)
	before := func(id uint32, frames, bytes int) {
		e := int64(-1)
		if dc := dcRef.Load(); dc != nil && id != 0 && id == stim.vic.Load() && !stim.fired.Load() {
			e = int64(dc.Status().SchedEpoch) // only the victim's writer calls with its ID: nothing fires in between
		}
		stim.before(id, frames, bytes)
		if e >= 0 && stim.fired.Load() {
			preEpoch.CompareAndSwap(-1, e)
		}
	}
	rec := &replyWrites{lo: urSize, hi: urSize + urSpan}
	w := newWorldHooked(t, worldOpts{oneWay: clOneWay}, &testhooks.Hooks{BeforeWrite: before}, &testhooks.Hooks{BeforeWrite: rec.before}, "u1", "u2")
	stim.conn = w.conn
	dc, pc := w.open(w.peer("u1", "u2"), rendr.DialOptions{Mode: mode})
	dcRef.Store(dc)
	vic, ok := liveNamed(dc.Status(), "u1")
	if !ok {
		t.Fatalf("the session did not open on u1: %+v", dc.Status().Carriers)
	}
	rec.vic.Store(uint32(vic.ID))
	waitFor(t, 2*time.Second, "two members on both ends", func() bool {
		return len(liveOf(dc.Status())) == 2 && len(liveOf(pc.Status())) == 2
	})
	const seed = 0x1ea
	echo := startEcho(pc, seed)
	ver := rendrtest.NewPacketVerifier(seed)
	var mu sync.Mutex
	got := map[uint64]bool{}
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

	// The observer: both ends' Status every clPoll.
	var obs []closeLossObs
	stop, odone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(odone)
		for {
			ds, ps := dc.Status(), pc.Status()
			o := closeLossObs{at: time.Now(), dEpoch: ds.SchedEpoch, pEpoch: ps.SchedEpoch}
			if c, ok := carrierOf(ps, vic.ID); ok {
				o.pTx = c.TxBytes
				o.pVictimLive = c.State == rendr.CarrierActive || c.State == rendr.CarrierMember
			}
			obs = append(obs, o)
			select {
			case <-stop:
				return
			case <-time.After(clPoll):
			}
		}
	}()

	start := time.Now()
	buf := make([]byte, urSize)
	for seq := range uint64(clRequests) {
		sleepUntil(start.Add(time.Duration(seq) * clGap))
		if seq == urArm {
			stim.vic.Store(uint32(vic.ID))
		}
		if _, err := dc.WriteTo(rendrtest.PacketPayload(buf, seed, seq, urSize, time.Now()), nil); err != nil {
			t.Fatalf("WriteTo of request %d: %v", seq, err)
		}
	}
	sleepUntil(start.Add(clRequests*clGap + 200*time.Millisecond))
	close(stop)
	<-odone
	waitFor(t, 10*time.Second, "the packet accounting to settle", func() bool {
		ds, ps := dc.Status().Packet, pc.Status().Packet
		return ds.PeerReceived == ps.Received && ps.PeerReceived == ds.Received
	})

	// Stimulus: the close inside a request round, and the dialer's death.
	stim.mu.Lock()
	tClose, cerr := stim.at, stim.err
	stim.mu.Unlock()
	if !stim.fired.Load() || cerr != nil {
		t.Fatalf("stimulus: the close in BeforeWrite of a request datagram on carrier %d did not happen (fired %v, close %v)", vic.ID, stim.fired.Load(), cerr)
	}
	down, ok := w.dev.downOf(vic.ID)
	if !ok || down.Cause != rendr.CauseTransportError {
		t.Fatalf("stimulus: the dialer's CarrierDown of %d is %+v (found %v), want transport_error", vic.ID, down, ok)
	}
	e := preEpoch.Load()
	if e < 0 {
		t.Fatalf("stimulus: the dialer's SCHED epoch before the close was not recorded")
	}
	ePre := uint32(e)

	// L45: the passive applies a post-close SCHED within one one-way delay.
	var tLearn time.Time
	learnIdx := -1
	for i, o := range obs {
		if o.at.After(tClose) && o.pEpoch > ePre && o.pEpoch <= o.dEpoch {
			tLearn, learnIdx = o.at, i
			break
		}
	}
	if learnIdx < 0 {
		t.Fatalf("the passive applied no SCHED published after the close (dialer epoch at the close %d; last poll %+v)", ePre, obs[len(obs)-1])
	}
	learn := tLearn.Sub(tClose)
	if bound := clOneWay + 2*clPoll; learn > bound {
		t.Fatalf("the passive applied the dialer's post-close SCHED %v after the close, want ≤ %v (one one-way delay: L45, the G6 judge's physical bound)", learn, bound)
	}
	if late := rec.after(tLearn); late > 0 {
		t.Fatalf("the passive wrote %d reply datagrams on the closed carrier %d after it applied the SCHED that dropped it (%v after the close)", late, vic.ID, learn)
	}
	// Every reply written after the passive learned arrives.
	mu.Lock()
	for seq := range uint64(clRequests) {
		at, echoed := echo.echoedAt(seq)
		if echoed && at.After(tLearn.Add(clPoll)) && !got[seq] {
			mu.Unlock()
			t.Fatalf("reply %d, written %v after the close (the passive learned %v after it), never arrived", seq, at.Sub(tClose), learn)
		}
	}
	mu.Unlock()
	t.Logf("%v: closed carrier %d inside a request round %v after the start; dialer CarrierDown %v after the close; the passive learned %v after it (epoch %d → %d)",
		mode, vic.ID, tClose.Sub(start), down.Time.Sub(tClose), learn, ePre, obs[learnIdx].pEpoch)
	unsentEnd(t, w, dc, pc, echo, rdone, ver)
}
