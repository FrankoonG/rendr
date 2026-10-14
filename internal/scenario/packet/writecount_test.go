package packet

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestPacketMisreportedWriteSentOnce_L42 is A3 of M5's second review wave
// end to end (L42; the packet contract's at-most-once): an
// embedder conn that sent a datagram and reported another count — here
// (len+1, nil), DatagramLink.ScriptWrites with Transmit — ends its
// carrier, and the datagram, which left, is not handed back to the
// session (the writer's DgramReturner withholds the datagrams of a call
// whose count lied). Before A3 the adapter's count error took the default
// branch of the writer's outcome: the datagram went back, the session
// placed it again on the surviving carrier (or on the redialled one) and
// it left twice — the passive's session dropped the second copy as a
// Duplicate. bond, selector and race-alone (a race session over u1 alone,
// whose hand-back waits for u1's redial) run over the natu path of the
// unsent rows with the same request schedule. Criteria:
//
//   - Stimulus: the script was consumed by a session carrier's write of a
//     request datagram on u1, whose carrier then died of the invalid count
//     (transport_error, its detail naming the count).
//   - Once: every request reached the passive's application once (the
//     echo read each, none twice), the dialer's Sent and PeerReceived,
//     settled, equal the requests, no dialer drop counter moved, and the
//     passive counted no duplicate.
//   - On the wire: the dialer's writers tried every request datagram
//     exactly once — the misreported one left on u1 and was never written
//     again (before A3: once more).
//   - Integrity: no damaged datagram on either side, no protocol
//     violation, a clean end.
//
// That the round's datagrams after the misreported call do go back — no
// call was given them — is proven on the carrier's writer
// (internal/carrier's TestDgramUnsentNotReturnedOnAdapterCount_L42); here
// any such datagram is one of the requests the criteria count once.
func TestPacketMisreportedWriteSentOnce_L42(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mode  rendr.Mode
		alone bool
	}{{"bond", rendr.ModeBond, false}, {"selector", rendr.ModeSelector, false}, {"race-alone", rendr.ModeRace, true}} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { misreportedOnce(t, tc.mode, tc.alone) })
		})
	}
}

// countStim is the stimulus of the misreported-count row: armed with the
// victim carrier, it scripts the next WriteTo of the dialer's side of the
// victim's link once — in the dialer writer's BeforeWrite of a datagram
// holding a request DGRAM, so that write is the scripted one: sent whole,
// reported as len+1. It also counts the dialer's request datagrams per
// carrier (every write attempt).
type countStim struct {
	vic   atomic.Uint32 // 0: not armed
	fired atomic.Bool
	link  *rendrtest.DatagramLink
	mu    sync.Mutex
	at    time.Time
	reqs  map[uint32]int // request datagrams the dialer's writers tried, by carrier
}

// before is the dialer's Hooks.BeforeWrite.
func (s *countStim) before(id uint32, frames, bytes int) {
	if bytes < urSize || bytes >= urSize+urSpan {
		return
	}
	s.mu.Lock()
	if s.reqs == nil {
		s.reqs = map[uint32]int{}
	}
	s.reqs[id]++
	s.mu.Unlock()
	if v := s.vic.Load(); v == 0 || id != v || !s.fired.CompareAndSwap(false, true) {
		return
	}
	s.link.ScriptWrites(rendrtest.Up, rendrtest.WriteResult{N: 1, Relative: true, Transmit: true})
	s.mu.Lock()
	s.at = time.Now()
	s.mu.Unlock()
}

func misreportedOnce(t *testing.T, mode rendr.Mode, alone bool) {
	stim := &countStim{}
	links := []string{"u1", "u2"}
	if alone {
		links = links[:1]
	}
	w := newWorldHooked(t, worldOpts{oneWay: clOneWay}, &testhooks.Hooks{BeforeWrite: stim.before}, nil, links...)
	stim.link = w.link("u1")
	dc, pc := w.open(w.peer(links...), rendr.DialOptions{Mode: mode})
	vic, ok := liveNamed(dc.Status(), "u1")
	if !ok {
		t.Fatalf("the session did not open on u1: %+v", dc.Status().Carriers)
	}
	if mode == rendr.ModeBond {
		// Both members up on both ends: the bond's requests after the death go to u2.
		waitFor(t, 2*time.Second, "two members on both ends", func() bool {
			return len(liveOf(dc.Status())) == 2 && len(liveOf(pc.Status())) == 2
		})
	}
	const seed = 0x77a
	echo := startEcho(pc, seed)
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
		}
	}()
	start := time.Now()
	buf := make([]byte, urSize)
	var pause time.Duration
	for seq := range uint64(clRequests) {
		sleepUntil(start.Add(time.Duration(seq)*clGap + pause))
		if seq == urArm {
			stim.vic.Store(uint32(vic.ID))
		}
		if _, err := dc.WriteTo(rendrtest.PacketPayload(buf, seed, seq, urSize, time.Now()), nil); err != nil {
			t.Fatalf("WriteTo of request %d: %v", seq, err)
		}
		synctest.Wait() // the dialer's writer has written it (or the carrier died)
		if pause == 0 && stim.fired.Load() {
			// The victim died: race-alone redials its only carrier meanwhile,
			// so no later request waits for a lane past MaxAge.
			pause = 2 * clMaxAge
		}
	}
	waitFor(t, 10*time.Second, "the packet accounting to settle", func() bool {
		ds, ps := dc.Status().Packet, pc.Status().Packet
		return ds.PeerReceived == ps.Received && ps.PeerReceived == ds.Received && echo.reads.Load() == int64(ps.Received)
	})
	ds, ps := *dc.Status().Packet, *pc.Status().Packet

	// Stimulus.
	stim.mu.Lock()
	at := stim.at
	stim.mu.Unlock()
	if st := stim.link.Stats(); !stim.fired.Load() || st.Session.ScriptedWrites != 1 || st.Probe.ScriptedWrites != 0 {
		t.Fatalf("stimulus: the scripted write of a request datagram on carrier %d did not happen (fired %v, scripted writes %d session, %d probe)",
			vic.ID, stim.fired.Load(), st.Session.ScriptedWrites, st.Probe.ScriptedWrites)
	}
	if down, ok := w.dev.downOf(vic.ID); !ok || down.Cause != rendr.CauseTransportError {
		t.Fatalf("stimulus: the dialer's CarrierDown of %d is %+v (found %v), want transport_error", vic.ID, down, ok)
	}
	if c, ok := carrierOf(dc.Status(), vic.ID); !ok || c.State != rendr.CarrierDead || !strings.Contains(c.DeathDetail, "invalid count") {
		t.Fatalf("stimulus: the dialer's carrier %d is %+v (found %v), want it dead of the invalid count", vic.ID, c, ok)
	}

	// Once: every request reached the passive once, none was sent twice.
	if r := echo.reads.Load(); r != clRequests || ds.Sent != clRequests || ds.PeerReceived != clRequests || drops(&ds) != 0 {
		t.Fatalf("a request was lost: the passive read %d of %d; dialer %+v", r, clRequests, ds)
	}
	if res := echo.v.Result(); ps.Duplicates != 0 || res.Duplicates+res.Corrupt+res.BadSize != 0 {
		t.Fatalf("the passive counted %d duplicates (integrity %+v): the misreported datagram, which left, was sent again", ps.Duplicates, res)
	}
	if ps.DropLate != 0 || ps.DropRecvQueue != 0 {
		t.Fatalf("the passive dropped a request: %+v", ps)
	}
	// On the wire: each request datagram tried once, the misreported one
	// included.
	stim.mu.Lock()
	total := 0
	for _, n := range stim.reqs {
		total += n
	}
	stim.mu.Unlock()
	if total != clRequests {
		t.Fatalf("the dialer tried %d request datagrams, want %d (each once: the misreported one left and is never written again)", total, clRequests)
	}
	t.Logf("%v: carrier %d misreported the write of a request %v after the start; passive read %d of %d; dialer %+v; passive %+v",
		mode, vic.ID, at.Sub(start), echo.reads.Load(), clRequests, ds, ps)

	unsentEnd(t, w, dc, pc, echo, rdone, ver)
}
