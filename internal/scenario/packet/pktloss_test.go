package packet

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// G6's packet-loss gap (m4 design R3-17, escalated; runs 20261010-231349
// and 20261010-232953): normal packet churn sessions on the raw-UDP NAT
// route got 8, 9 and 15 of their 16 echo replies while every send- and
// receive-side drop counter of both ends stayed 0; the passive wrote the
// replies on a carrier the stimulus (F10's local close of the dialer's
// conn) had just ended. The rows below replay that schedule in virtual
// time — the 16-datagram echo at a 1-ms gap starting at the open, a 5-ms
// one-way path (G6's natu RTT is 10 ms), the dialer's conn of the
// session's first carrier closed under rendr in the instant its second
// member came up (2 ms after it in the pool run of race session ps2298) —
// and decide which of two cases the gap is:
//
//   - (a) rendr writes datagrams on a carrier it already knows is dead,
//     dying or retired: the passive would place a DGRAM on the closed
//     carrier after it applied the SCHED in which the dialer dropped it;
//   - (b) the datagrams leave on a carrier the writing end still believes
//     healthy and are lost in the network: UDP has no RST, the passive
//     learns of a local close on the dialer only from the dialer's next
//     SCHED (L45: the dialer is the sole routing authority), which it
//     sends on the surviving carrier in the instant of its death verdict;
//     every reply written on the closed carrier before that SCHED arrives
//     — and those written up to one one-way delay before the close — goes
//     to a closed port.
//
// The rows prove (b) and pin the behaviour that makes it (b):
//
//   - Stimulus: the dialer records the closed carrier's death
//     (transport_error) at the close, and the link lost datagrams on it
//     (UDP to a closed port: only the passive writes to the dialer's
//     closed end).
//   - Reproduction: replies are lost while every drop counter of both
//     ends is 0 (G6's signature) — and the loss is counted where the
//     packet contract counts in-flight data on a dead carrier (L39: "only
//     data in flight on a dead carrier may be lost, and is counted"; ACK
//     is for accounting only, L40): the passive's Sent − PeerReceived
//     equals the replies lost, exactly, once the accounting settled.
//   - Classification (the decisive part): every lost reply was written by
//     the passive no earlier than one one-way delay before the close and
//     no later than the instant the passive applied the first SCHED the
//     dialer published after the close; after that instant the passive
//     wrote no datagram holding a reply on the closed carrier (its
//     Hooks.BeforeWrite on that carrier, and its TxBytes there frozen),
//     although the carrier stays alive on the passive for seconds (until
//     its ping_timeout) and the echo goes on. The close falls half a
//     millisecond between two requests' arrivals, so the SCHED's arrival
//     (one one-way delay, or the selector's failover, later) never shares
//     an instant with a reply's write, and a passive that wrote even one
//     more reply on the closed carrier after applying that SCHED is seen.
//   - Timeliness: the dialer published that SCHED in the instant of its
//     death verdict, so the passive learned within one one-way delay of
//     the close (race, bond); a selector dialer has no other session
//     carrier and publishes once its failover carrier is up, within its
//     JOIN round trip plus one one-way delay.
//   - Integrity and end: no duplicate, corrupt or resized reply reaches
//     the application; both ends finish cleanly and Runtime.Close leaves
//     nothing.
//
// PA-86 (F-7) lets the passive know at the same instant on a shared trunk
// with another trunk of the pair (race, bond): the dialer's DOWN for the
// closed trunk, one REL ahead of the SCHED, ends the passive's end
// (peer_down), so the carrier no longer outlives the observation there;
// the premise accepts that end in the instant the passive learns, and
// every other criterion is unchanged — (a) then holds by the trunk's
// death, and only the selector row, which has no other trunk of the pair
// at the close and keeps the strict premise, still proves (a) on a carrier
// that lives on at the passive. Because the passive cannot know
// earlier than one one-way delay after the close, rendr has nothing more
// to count than PeerReceived already shows: the gap is the G6 judge's
// attribution of a loss on a carrier its own stimulus ended (its
// no_other_error_class counts every incomplete packet churn echo, "k of
// n replies", as error class other, and it has no row for the in-flight
// loss of plan:742 and plan:749). A mutant that keeps the passive writing
// on a carrier the applied SCHED dropped, even for one more reply, fails
// the classification here.
//
// The dialer's direction loses nothing: a request written before the
// close is in flight on a path that still delivers it, and a request the
// dialer placed in a round whose write failed on the closed conn goes back
// to the session and is placed again on the surviving carrier
// (TestPacketCarrierCloseUnsentReplaced_L39), so the passive reads every
// request and the dialer's Sent equals its PeerReceived.
func TestPacketCarrierCloseLossInFlight_L39(t *testing.T) {
	for _, mode := range []rendr.Mode{rendr.ModeRace, rendr.ModeBond, rendr.ModeSelector} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { closeLossInFlight(t, mode) })
		})
	}
}

// closeLossObs is one poll of both ends' Status by the observer.
type closeLossObs struct {
	at          time.Time
	dEpoch      uint32 // the dialer's last published SCHED epoch
	pEpoch      uint32 // the passive's last applied SCHED epoch
	pTx         uint64 // the passive's DGRAM bytes on the victim carrier
	pVictimLive bool   // the victim is a live carrier of the passive's session
}

// Schedule of the rows (G6's natu path and pkt-echo churn session).
const (
	clOneWay   = 5 * time.Millisecond   // natu: RTT 10 ms
	clGap      = time.Millisecond       // PktChurn.EchoGap
	clRequests = 64                     // G6's 16 plus enough to echo well past the close
	clSize     = 200                    // bytes per request (PktChurn.EchoSize order)
	clPoll     = 100 * time.Microsecond // observer period: below every link delay
	clSelClose = 8 * time.Millisecond   // selector: the close 8.5 ms after the open (9 requests out)
	// A datagram holding a reply DGRAM has [clSize + clDgramOverhead,
	// clSize + clSpan) bytes; control datagrams are smaller, padded probes
	// and their PONGs larger.
	clDgramOverhead = 25 // wire.DgramOverhead: the DGRAM frame's header, seq and trailer
	clSpan          = 400
)

func closeLossInFlight(t *testing.T, mode rendr.Mode) {
	rec := &replyWrites{lo: clSize + clDgramOverhead, hi: clSize + clSpan}
	w := newWorldHooked(t, worldOpts{oneWay: clOneWay}, nil, &testhooks.Hooks{BeforeWrite: rec.before}, "u1", "u2")
	dc, pc := w.open(w.peer("u1", "u2"), rendr.DialOptions{Mode: mode})
	opened := time.Now()
	vic, ok := liveNamed(dc.Status(), "u1")
	if !ok {
		t.Fatalf("the session did not open on u1: %+v", dc.Status().Carriers)
	}
	rec.vic.Store(uint32(vic.ID))
	const seed = 0x6abe
	echo := startEcho(pc, seed)

	// The dialer's echo client: requests at a fixed gap from the open,
	// replies verified and recorded by seq.
	var mu sync.Mutex
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
		buf := make([]byte, clSize)
		for seq := range uint64(clRequests) {
			sleepUntil(opened.Add(time.Duration(seq) * clGap))
			if _, err := dc.WriteTo(rendrtest.PacketPayload(buf, seed, seq, clSize, time.Now()), nil); err != nil {
				wdone <- fmt.Errorf("WriteTo of request %d: %w", seq, err)
				return
			}
		}
		wdone <- nil
	}()

	// The observer: both ends' Status every clPoll until stopped.
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

	// The stimulus: race and bond close the victim as the dialer's second
	// member comes up (G6 ps2298: 2 ms after it), at the next half
	// millisecond between two requests; selector closes its active carrier
	// half a millisecond after a request.
	if mode == rendr.ModeSelector {
		sleepUntil(opened.Add(clSelClose + clGap/2))
	} else {
		for {
			if _, ok := liveNamed(dc.Status(), "u2"); ok {
				break
			}
			if time.Since(opened) > time.Second {
				t.Fatalf("no second member within 1 s: %+v", dc.Status().Carriers)
			}
			time.Sleep(clPoll)
		}
		sleepUntil(opened.Add(time.Since(opened).Truncate(clGap) + clGap/2))
	}
	ePre := dc.Status().SchedEpoch
	tClose := time.Now()
	w.localClose(vic.ID)

	if err := <-wdone; err != nil {
		t.Fatal(err)
	}
	sleepUntil(opened.Add(clRequests*clGap + 200*time.Millisecond))
	close(stop)
	<-odone

	// The accounting settles: each end's PeerReceived reaches the other's
	// Received (ACK is for accounting, L40).
	waitFor(t, 10*time.Second, "the packet accounting to settle", func() bool {
		ds, ps := dc.Status().Packet, pc.Status().Packet
		return ds.PeerReceived == ps.Received && ps.PeerReceived == ds.Received
	})
	ds, ps := *dc.Status().Packet, *pc.Status().Packet

	// Stimulus: the dialer's death verdict at the close, and datagrams the
	// passive wrote to the closed end.
	down, ok := w.dev.downOf(vic.ID)
	if !ok || down.Cause != rendr.CauseTransportError || down.Time.Sub(tClose) > clPoll {
		t.Fatalf("stimulus: the dialer's CarrierDown of %d is %+v (found %v), want transport_error at the close %v", vic.ID, down, ok, tClose)
	}
	lostOnVictim := w.link("u1").Stats().Session.Lost
	if lostOnVictim == 0 {
		t.Fatalf("stimulus: the link of the closed carrier lost no datagram (the close caught no reply)")
	}

	// When the passive learned: the first poll at which it had applied an
	// epoch the dialer published after the close.
	var tLearn time.Time
	var learnIdx int
	for i, o := range obs {
		if o.at.After(tClose) && o.pEpoch > ePre && o.pEpoch <= o.dEpoch {
			tLearn, learnIdx = o.at, i
			break
		}
	}
	if tLearn.IsZero() {
		t.Fatalf("the passive applied no SCHED published after the close (dialer epoch at the close %d; last poll %+v)", ePre, obs[len(obs)-1])
	}
	learn := tLearn.Sub(tClose)
	// Race, bond: the SCHED of the death verdict crosses u2 once. Selector:
	// the failover carrier's JOIN round trip, then that SCHED. Two polls:
	// the observation's granularity.
	bound := clOneWay + 2*clPoll
	if mode == rendr.ModeSelector {
		bound = 3*clOneWay + 2*clPoll
	}
	if learn > bound {
		t.Fatalf("the passive applied the dialer's post-close SCHED %v after the close, want ≤ %v", learn, bound)
	}

	// Classification: nothing placed on the victim after the passive
	// learned, although it lived on there and the echo continued.
	if learnIdx+1 >= len(obs) {
		t.Fatalf("no poll after the passive learned")
	}
	after := obs[learnIdx+1] // the next instant: everything of tLearn's instant is in it
	last := obs[len(obs)-1]
	if !last.pVictimLive {
		// PA-86: race and bond hold a second trunk of the pair, on which the
		// dialer's DOWN for the closed one arrives one REL ahead of the
		// SCHED; it ends the passive's end (peer_down) in the instant the
		// passive learns, so the passive also stops writing there by the
		// trunk's death, and (a) below holds by that death. Any other end
		// before the observation's is the premise's failure. Selector holds
		// no second trunk at the close, so no DOWN: its closed carrier must
		// outlive the observation (until its ping_timeout), and the selector
		// row keeps (a) exercised on a live carrier.
		if mode == rendr.ModeSelector {
			t.Fatalf("premise: the closed carrier died on the passive %v after the close (selector: no DOWN, it must outlive the observation)", last.at.Sub(tClose))
		}
		if pd, ok := w.pev.downOf(vic.ID); !ok || pd.Cause != rendr.CausePeerDown || pd.Time.Before(tClose.Add(clOneWay)) || pd.Time.After(tLearn) {
			t.Fatalf("premise: the closed carrier died on the passive %v after the close (it must outlive the observation, or end by the dialer's DOWN when the passive learns: %+v, found %v)",
				last.at.Sub(tClose), pd, ok)
		}
	}
	if last.pTx != after.pTx {
		t.Fatalf("(a): the passive placed %d DGRAM bytes on carrier %d after it applied the SCHED that dropped it (%v after the close)",
			last.pTx-after.pTx, vic.ID, learn)
	}
	if late := rec.after(tLearn); late > 0 {
		t.Fatalf("(a): the passive wrote %d reply datagrams on carrier %d after it applied the SCHED that dropped it (%v after the close)",
			late, vic.ID, learn)
	}
	if rec.after(tClose) == 0 {
		t.Fatalf("stimulus: the passive wrote no reply on carrier %d after the close", vic.ID)
	}
	if echo.writes.Load() <= int64(clRequests/2) || echoedAfter(echo, after.at) == 0 {
		t.Fatalf("load: the passive echoed %d requests, none after it learned", echo.writes.Load())
	}

	// Reproduction and attribution of every lost reply.
	mu.Lock()
	var lost []uint64
	for seq := range uint64(clRequests) {
		at, echoed := echo.echoedAt(seq)
		if !echoed || got[seq] {
			continue
		}
		lost = append(lost, seq)
		if at.Before(tClose.Add(-clOneWay)) || at.After(tLearn) {
			mu.Unlock()
			t.Fatalf("reply %d was lost but written %v after the close, outside [close − one-way, learned = %v]: not in flight on the closed carrier",
				seq, at.Sub(tClose), learn)
		}
	}
	mu.Unlock()
	if len(lost) == 0 {
		t.Fatalf("reproduction: no reply lost (the schedule missed G6's window)")
	}
	for i, c := range []rendr.PacketCounters{ds, ps} {
		if drops(&c)+c.DropRecvQueue+c.DropLate != 0 {
			t.Fatalf("%s: a drop counter moved: %+v (G6's signature has all of them 0)", side(i), c)
		}
	}
	if n := ps.Sent - ps.PeerReceived; n != uint64(len(lost)) || ps.Sent != uint64(echo.writes.Load()) {
		t.Fatalf("accounting: the passive's Sent %d − PeerReceived %d = %d, want the %d replies lost (%d echoed)",
			ps.Sent, ps.PeerReceived, n, len(lost), echo.writes.Load())
	}
	if ds.Sent != clRequests || ds.PeerReceived != clRequests || echo.reads.Load() != clRequests {
		t.Fatalf("the dialer's direction lost a request: Sent %d, PeerReceived %d, the passive read %d of %d",
			ds.Sent, ds.PeerReceived, echo.reads.Load(), clRequests)
	}
	res := ver.Result()
	if res.Duplicates+res.Corrupt+res.BadSize != 0 {
		t.Fatalf("integrity: %+v", res)
	}
	t.Logf("%v: closed carrier %d %v after the open; passive learned %v later (epoch %d → %d); %d of %d replies lost "+
		"(written %v … %v after the close), the link lost %d datagrams on it; passive Sent %d, PeerReceived %d",
		mode, vic.ID, tClose.Sub(opened), learn, ePre, obs[learnIdx].pEpoch, len(lost), echo.writes.Load(),
		lostSpan(echo, lost, tClose, true), lostSpan(echo, lost, tClose, false), lostOnVictim, ps.Sent, ps.PeerReceived)

	// Clean end: the dialer closes, the echo reads io.EOF and closes.
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
	case <-echo.done:
	case <-time.After(30 * time.Second):
		t.Fatalf("the echo did not end: %+v", pc.Status())
	}
	if echo.err != nil {
		t.Fatalf("echo: %v", echo.err)
	}
	for _, c := range []*rendr.PacketConn{dc, pc} {
		select {
		case <-c.Done():
		case <-time.After(30 * time.Second):
			t.Fatalf("a session did not end within Linger: %+v", c.Status())
		}
	}
	w.noViolation()
	w.close()
}

// replyWrites records when the passive's writer wrote a datagram holding a
// reply DGRAM ([lo, hi) bytes) on the victim carrier (its Hooks.BeforeWrite:
// the instant of the write, not of the commit that moves TxBytes).
type replyWrites struct {
	vic    atomic.Uint32
	lo, hi int
	mu     sync.Mutex
	at     []time.Time
}

func (r *replyWrites) before(id uint32, frames, bytes int) {
	if v := r.vic.Load(); v == 0 || id != v || bytes < r.lo || bytes >= r.hi {
		return
	}
	r.mu.Lock()
	r.at = append(r.at, time.Now())
	r.mu.Unlock()
}

// after returns the recorded writes later than t.
func (r *replyWrites) after(t time.Time) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, at := range r.at {
		if at.After(t) {
			n++
		}
	}
	return n
}

// echoedAfter is the number of requests the echo answered after at.
func echoedAfter(e *echoer, at time.Time) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	for _, w := range e.echoed {
		if w.After(at) {
			n++
		}
	}
	return n
}

// lostSpan is the earliest (first) or latest echo time of the lost
// replies, relative to the close.
func lostSpan(e *echoer, lost []uint64, close time.Time, first bool) time.Duration {
	var d time.Duration
	for i, seq := range lost {
		at, _ := e.echoedAt(seq)
		r := at.Sub(close)
		if i == 0 || (first && r < d) || (!first && r > d) {
			d = r
		}
	}
	return d
}
