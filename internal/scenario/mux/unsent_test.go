package mux

import (
	"errors"
	"fmt"
	"io"
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

// TestMuxPacketCarrierCloseUnsentReplaced_L39 is internal/scenario/packet's
// TestPacketCarrierCloseUnsentReplaced_L39 on G6's carrier shape: the
// packet churn session is a view of datagram trunks a long packet session
// already holds, and F10's local close of the dialer's conn — here from
// the dialer's Hooks.BeforeWrite of a datagram holding a churn request —
// ends the whole trunk in the middle of a round. The DGRAMs the round
// placed and never wrote go back to the session of their own handle (the
// trunk's frames belong to several views) and are placed again on its
// live view: every churn request reaches the passive's application once,
// the dialer's Sent and PeerReceived equal the requests, every dialer drop
// counter is 0, and the request datagrams on the wire are the requests
// once each plus the failed write (race: the surviving member's copies,
// once each). Mutant: the hand-back goes to the trunk's first view (the
// long session) instead of the frame's handle.
func TestMuxPacketCarrierCloseUnsentReplaced_L39(t *testing.T) {
	for _, mode := range []rendr.Mode{rendr.ModeRace, rendr.ModeBond, rendr.ModeSelector} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { muxUnsentReplaced(t, mode) })
		})
	}
}

// Schedule: the churn echo of the in-flight row with a request size no
// control datagram has.
const (
	muSize = 777 // bytes per request: a DGRAM datagram of [muSize, muSize+muSpan) bytes
	muSpan = 400 // the frames a datagram may carry in front of its DGRAM; a padded PONG is larger
	muArm  = 10  // the stimulus is armed after this many requests
)

// muxUnsentStim closes the dialer's conn of the victim trunk once, in the
// dialer writer's BeforeWrite of a datagram holding a request, and counts
// the dialer's request datagrams per carrier.
type muxUnsentStim struct {
	vic   atomic.Uint32
	fired atomic.Bool
	mu    sync.Mutex
	err   error
	reqs  map[uint32]int
	conn  func(id rendr.CarrierID) net.PacketConn
}

func (s *muxUnsentStim) before(id uint32, frames, bytes int) {
	if bytes < muSize || bytes >= muSize+muSpan {
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
	err := errors.New("no registered conn")
	if pc := s.conn(rendr.CarrierID(id)); pc != nil {
		err = pc.Close()
	}
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
}

func muxUnsentReplaced(t *testing.T, mode rendr.Mode) {
	stim := &muxUnsentStim{}
	w := newWorld(t, worldOpts{dov: testhooks.Overrides{Hooks: &testhooks.Hooks{BeforeWrite: stim.before}}},
		linkSpec{name: "u1", oneWay: mclOneWay, dgram: true}, linkSpec{name: "u2", oneWay: mclOneWay, dgram: true})
	stim.conn = w.dconn
	peer := w.peer("u1", "u2")
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
	dc, pc := s.d, s.p
	if vic, ok := liveNamed(dc.Status(), "u1"); !ok || vic.ID != trunk.ID || vic.Shared < 2 || vic.Handle == 1 {
		t.Fatalf("premise: the churn session did not open as a second view of the long session's u1 trunk %d: %+v", trunk.ID, dc.Status().Carriers)
	}
	var mate rendr.CarrierStatus
	if mode != rendr.ModeSelector {
		waitFor(t, 2*time.Second, "two members on both ends", func() bool {
			return len(liveOf(dc.Status())) == 2 && len(liveOf(pc.Status())) == 2
		})
		mate, _ = liveNamed(dc.Status(), "u2")
	}
	const seed = 0x777c
	var reads atomic.Int64
	ever := rendrtest.NewPacketVerifier(seed)
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
			reads.Add(1)
			if verr := ever.Add(buf[:n], time.Now()); verr != nil {
				edone <- verr
				return
			}
			if _, err := pc.WriteTo(buf[:n], nil); err != nil {
				edone <- err
				return
			}
		}
	}()
	rdone := make(chan error, 1)
	go func() {
		buf := make([]byte, dc.MaxPayload()+1)
		for {
			if _, _, err := dc.ReadFrom(buf); err != nil {
				rdone <- err
				return
			}
		}
	}()
	start := time.Now()
	buf := make([]byte, muSize)
	for seq := range uint64(mclRequests) {
		sleepUntil(start.Add(time.Duration(seq) * mclGap))
		if seq == muArm {
			stim.vic.Store(uint32(trunk.ID))
		}
		if _, err := dc.WriteTo(rendrtest.PacketPayload(buf, seed, seq, muSize, time.Now()), nil); err != nil {
			t.Fatalf("WriteTo of request %d: %v", seq, err)
		}
	}
	waitFor(t, 10*time.Second, "the packet accounting to settle", func() bool {
		ds, ps := dc.Status().Packet, pc.Status().Packet
		return ds.PeerReceived == ps.Received && ps.PeerReceived == ds.Received && reads.Load() == int64(ps.Received)
	})
	ds, ps := *dc.Status().Packet, *pc.Status().Packet

	stim.mu.Lock()
	cerr, reqs := stim.err, stim.reqs
	stim.mu.Unlock()
	if !stim.fired.Load() || cerr != nil {
		t.Fatalf("stimulus: the close in BeforeWrite of a request datagram on trunk %d did not happen (fired %v, close %v)", trunk.ID, stim.fired.Load(), cerr)
	}
	if ev, ok := w.dev.sessionDown(dc.ID(), trunk.ID); !ok || ev.Cause != rendr.CauseTransportError {
		t.Fatalf("stimulus: the churn session's CarrierDown of trunk %d is %+v (found %v), want transport_error", trunk.ID, ev, ok)
	}
	if r := reads.Load(); r != mclRequests || ds.Sent != mclRequests || ds.PeerReceived != mclRequests || drops(&ds) != 0 {
		t.Fatalf("a request the dialer never wrote was lost: the passive read %d of %d; dialer %+v", r, mclRequests, ds)
	}
	if res := ever.Result(); res.Duplicates+res.Corrupt+res.BadSize != 0 {
		t.Fatalf("integrity at the passive: %+v", res)
	}
	total := 0
	for _, n := range reqs {
		total += n
	}
	if mode == rendr.ModeRace {
		if n := reqs[uint32(mate.ID)]; n != mclRequests || dc.Status().Race.Copies != ps.Duplicates+ps.DropLate {
			t.Fatalf("race: the surviving member %d wrote %d request datagrams (want %d); copies %d, passive duplicates %d",
				mate.ID, n, mclRequests, dc.Status().Race.Copies, ps.Duplicates)
		}
	} else if total != mclRequests+1 || ps.Duplicates != 0 {
		t.Fatalf("the dialer tried %d request datagrams (want %d) and the passive counted %d duplicates", total, mclRequests+1, ps.Duplicates)
	}
	if lp := long.p.Status().Packet; lp.Received != 0 {
		t.Fatalf("the long session received %d datagrams: a churn request went to the wrong session", lp.Received)
	}
	t.Logf("%v: closed trunk %d (shared) in the write of a request; passive read %d of %d; dialer %+v", mode, trunk.ID, reads.Load(), mclRequests, ds)

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

// dconn returns the dialer's registered conn of datagram carrier id (nil:
// none).
func (w *world) dconn(id rendr.CarrierID) net.PacketConn {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.conns[id]
}
