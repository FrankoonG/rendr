package packet

import (
	"context"
	"errors"
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

// TestPacketCarrierCloseUnsentReplaced_L39 is the dialer half of G6's
// packet-loss gap (m4 design R3-17; M5 pktloss review): F10's local close
// of the dialer's conn can land while the dialer's writer holds a round
// whose DGRAMs it has placed but not yet written. The write then fails on
// the closed conn: rendr knows those datagrams never left. Before pktloss
// they were lost with every drop counter at 0 and counted in Sent alone,
// indistinguishable from a datagram lost in the network (G6's signature,
// in the A → B direction). L39 allows only data in flight on a dead
// carrier to be lost; a datagram that never left is not in flight, and a
// live carrier exists, so rendr re-places it there (the packet contract's
// re-route; at-most-once holds because it never left) and counts it
// DropAge or DropNoPath only when it ages out first.
//
// The stimulus closes the dialer's conn of the victim carrier from
// Hooks.BeforeWrite, right before the dialer writes a datagram that holds
// a request DGRAM on it (a request size no control datagram has), so the
// round's DGRAM is placed and unwritten. The client then writes nothing
// for twice MaxAge: no WriteTo wakes a lane, so the returned request is
// placed again only because its return woke one (or the routing change
// did). race, bond and selector run over two links (u1 the victim);
// race-alone is a race session over u1 alone, whose returned request
// waits for u1's redial (no other member carries a copy). Criteria:
//
//   - Stimulus: the hook fired on such a datagram and the dialer recorded
//     the victim's death (transport_error).
//   - No loss on the dialer: every request reached the passive's
//     application once (the echo read all of them, none twice); the
//     dialer's Sent and PeerReceived, settled, equal the requests; every
//     dialer drop counter is 0. Without the re-placement a bond,
//     selector or lone race session loses the request of the failed
//     write (race with two members carries a copy on the other).
//   - On the wire: every request datagram once plus the failed write
//     (bond, selector, race-alone; no duplicate at the passive); race: the
//     surviving member writes every request once — the failed copy is not
//     placed again — and the dialer's Race.Copies equals the passive's
//     duplicates (the failed copy left the count).
//   - Integrity: no duplicate or damaged datagram on either side's
//     application, no protocol violation, a clean end.
func TestPacketCarrierCloseUnsentReplaced_L39(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mode  rendr.Mode
		alone bool
	}{{"race", rendr.ModeRace, false}, {"bond", rendr.ModeBond, false}, {"selector", rendr.ModeSelector, false}, {"race-alone", rendr.ModeRace, true}} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { unsentReplaced(t, tc.mode, tc.alone) })
		})
	}
}

// Schedule of the unsent rows: G6's natu path and echo (as the in-flight
// rows), with a request size that no control datagram has.
const (
	urSize = 777 // bytes per request: a DGRAM datagram of [urSize, urSize+urSpan) bytes
	urSpan = 400 // the frames a datagram may carry in front of its DGRAM (REL SCHED, PACK, PING, RACK); a padded PONG is larger
	urArm  = 10  // the stimulus is armed after this many requests
	// clMaxAge is Packet.MaxAge's default: a returned datagram not placed
	// again within it is dropped.
	clMaxAge = 100 * time.Millisecond
)

// unsentStim is the stimulus of the unsent rows: armed with the victim
// carrier, it closes the dialer's conn of that carrier once, in the
// dialer writer's BeforeWrite of a datagram holding a request DGRAM —
// after holding that write for hold first (0: none), as a write that
// blocks until its stall window would. It also counts the dialer's request
// datagrams per carrier (every write attempt, the failed one included).
type unsentStim struct {
	vic   atomic.Uint32 // 0: not armed
	fired atomic.Bool
	hold  time.Duration
	mu    sync.Mutex
	at    time.Time
	err   error
	reqs  map[uint32]int // request datagrams the dialer's writers tried, by carrier
	conn  func(id rendr.CarrierID) net.PacketConn
}

// before is the dialer's Hooks.BeforeWrite.
func (s *unsentStim) before(id uint32, frames, bytes int) {
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
	if s.hold > 0 {
		time.Sleep(s.hold)
	}
	pc := s.conn(rendr.CarrierID(id))
	err := errors.New("no registered conn")
	if pc != nil {
		err = pc.Close()
	}
	s.mu.Lock()
	s.at, s.err = time.Now(), err
	s.mu.Unlock()
}

func unsentReplaced(t *testing.T, mode rendr.Mode, alone bool) {
	stim := &unsentStim{}
	links := []string{"u1", "u2"}
	if alone {
		links = links[:1]
	}
	w := newWorldHooked(t, worldOpts{oneWay: clOneWay}, &testhooks.Hooks{BeforeWrite: stim.before}, nil, links...)
	stim.conn = w.conn
	dc, pc := w.open(w.peer(links...), rendr.DialOptions{Mode: mode})
	vic, ok := liveNamed(dc.Status(), "u1")
	if !ok {
		t.Fatalf("the session did not open on u1: %+v", dc.Status().Carriers)
	}
	var mate rendr.CarrierStatus // race, bond: the dialer's u2 member
	if mode != rendr.ModeSelector && !alone {
		// Both members up on both ends: the bond's re-placement goes to u2.
		waitFor(t, 2*time.Second, "two members on both ends", func() bool {
			return len(liveOf(dc.Status())) == 2 && len(liveOf(pc.Status())) == 2
		})
		mate, _ = liveNamed(dc.Status(), "u2")
	}
	const seed = 0x777
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
		synctest.Wait() // the dialer's writer has written (or failed to write) it
		if pause == 0 && stim.fired.Load() {
			pause = 2 * clMaxAge // no WriteTo wakes a lane meanwhile
		}
	}
	waitFor(t, 10*time.Second, "the packet accounting to settle", func() bool {
		ds, ps := dc.Status().Packet, pc.Status().Packet
		return ds.PeerReceived == ps.Received && ps.PeerReceived == ds.Received && echo.reads.Load() == int64(ps.Received)
	})
	ds, ps := *dc.Status().Packet, *pc.Status().Packet

	// Stimulus.
	stim.mu.Lock()
	at, cerr := stim.at, stim.err
	stim.mu.Unlock()
	if !stim.fired.Load() || cerr != nil {
		t.Fatalf("stimulus: the close in BeforeWrite of a request datagram on carrier %d did not happen (fired %v, close %v)", vic.ID, stim.fired.Load(), cerr)
	}
	down, ok := w.dev.downOf(vic.ID)
	if !ok || down.Cause != rendr.CauseTransportError {
		t.Fatalf("stimulus: the dialer's CarrierDown of %d is %+v (found %v), want transport_error", vic.ID, down, ok)
	}

	// No loss on the dialer: every request reached the passive once.
	if r := echo.reads.Load(); r != clRequests || ds.Sent != clRequests || ds.PeerReceived != clRequests || drops(&ds) != 0 {
		t.Fatalf("a request the dialer never wrote was lost: the passive read %d of %d; dialer %+v (closed %v after the start)",
			r, clRequests, ds, at.Sub(start))
	}
	if res := echo.v.Result(); res.Duplicates+res.Corrupt+res.BadSize != 0 {
		t.Fatalf("integrity at the passive: %+v", res)
	}
	if ps.DropLate != 0 || ps.DropRecvQueue != 0 {
		t.Fatalf("the passive dropped a request: %+v", ps)
	}
	// On the wire: the failed write is the one extra attempt. Bond and
	// selector write every request once (the re-placement included) and
	// the passive counts no duplicate; race writes every request once per
	// member — its surviving member's copy covers the failed one, which is
	// not placed again — and the dialer's copies are exactly the passive's
	// duplicates (the failed copy left the count).
	stim.mu.Lock()
	reqs := stim.reqs
	stim.mu.Unlock()
	total := 0
	for _, n := range reqs {
		total += n
	}
	if mode == rendr.ModeRace && !alone {
		dsAll := dc.Status()
		if n := reqs[uint32(mate.ID)]; n != clRequests || dsAll.Race.Copies != ps.Duplicates+ps.DropLate {
			t.Fatalf("race: the surviving member %d wrote %d request datagrams (want %d: each once, none placed again); copies %d, passive duplicates %d",
				mate.ID, n, clRequests, dsAll.Race.Copies, ps.Duplicates)
		}
	} else if total != clRequests+1 || ps.Duplicates != 0 {
		t.Fatalf("the dialer tried %d request datagrams (want %d: each once, plus the failed write) and the passive counted %d duplicates: a request left twice",
			total, clRequests+1, ps.Duplicates)
	}
	t.Logf("%v: closed carrier %d in the write of a request %v after the start; passive read %d of %d; dialer %+v; passive %+v",
		mode, vic.ID, at.Sub(start), echo.reads.Load(), clRequests, ds, ps)

	unsentEnd(t, w, dc, pc, echo, rdone, ver)
}

// TestPacketCarrierCloseUnsentNoPath_L39 is the unsent row without a
// carrier to re-place on: a selector session over one link whose redials
// the link refuses. The request of the failed write goes back to the
// session, waits through MaxAge with no data lane and is counted
// DropNoPath (M2-D35), like the requests queued after it; none of them
// counts in Sent. So the dialer's Sent equals the requests the passive
// received, and Sent plus DropNoPath equals the requests written, before
// the session ends. Mutants: no hand-back (Sent exceeds what the passive
// received by the failed request); no no-path ageing of the returned
// requests (they stay uncounted until the end).
func TestPacketCarrierCloseUnsentNoPath_L39(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		stim := &unsentStim{}
		w := newWorldHooked(t, worldOpts{oneWay: clOneWay}, &testhooks.Hooks{BeforeWrite: stim.before}, nil, "u1")
		stim.conn = w.conn
		dc, pc := w.open(w.peer("u1"), rendr.DialOptions{Mode: rendr.ModeSelector})
		vic, ok := liveNamed(dc.Status(), "u1")
		if !ok {
			t.Fatalf("the session did not open on u1: %+v", dc.Status().Carriers)
		}
		const seed = 0x778
		echo := startEcho(pc, seed)
		w.link("u1").Refuse(true) // no carrier comes back
		start := time.Now()
		buf := make([]byte, urSize)
		const requests = 20
		for seq := range uint64(requests) {
			sleepUntil(start.Add(time.Duration(seq) * clGap))
			if seq == urArm {
				stim.vic.Store(uint32(vic.ID))
			}
			if _, err := dc.WriteTo(rendrtest.PacketPayload(buf, seed, seq, urSize, time.Now()), nil); err != nil {
				t.Fatalf("WriteTo of request %d: %v", seq, err)
			}
		}
		// Every request is placed or aged out after MaxAge (100 ms).
		time.Sleep(time.Second)
		ds, ps := *dc.Status().Packet, *pc.Status().Packet
		if !stim.fired.Load() {
			t.Fatalf("stimulus: the close in BeforeWrite of a request datagram on carrier %d did not happen", vic.ID)
		}
		if down, ok := w.dev.downOf(vic.ID); !ok || down.Cause != rendr.CauseTransportError {
			t.Fatalf("stimulus: the dialer's CarrierDown of %d is %+v (found %v), want transport_error", vic.ID, down, ok)
		}
		if live := liveOf(dc.Status()); len(live) != 0 {
			t.Fatalf("premise: a carrier came back: %+v", live)
		}
		if ds.Sent != ps.Received || ds.Sent+ds.DropNoPath != requests || drops(&ds) != ds.DropNoPath || ds.DropNoPath == 0 {
			t.Fatalf("the dialer counts %+v and the passive received %d of %d: want Sent = received and the rest DropNoPath",
				ds, ps.Received, requests)
		}
		if r := echo.reads.Load(); r != int64(ps.Received) {
			t.Fatalf("the echo read %d, the passive received %d", r, ps.Received)
		}
		t.Logf("dialer %+v; passive received %d of %d", ds, ps.Received, requests)
		dc.Close()
		for _, c := range []*rendr.PacketConn{dc, pc} {
			select {
			case <-c.Done():
			case <-time.After(60 * time.Second):
				t.Fatalf("a session did not end: %+v", c.Status())
			}
		}
		<-echo.done
		w.noViolation()
		w.close()
	})
}

// TestPacketCarrierCloseUnsentAged_L40 (M5 review D2-1; plan:286, M2-D35,
// L40) is the unsent row with a write that blocks first: the victim's
// writer is held in Hooks.BeforeWrite of a request datagram for twice
// MaxAge, as a write blocked until its stall window, then its conn is
// closed. The round's request comes back older than MaxAge since its
// WriteTo, and a returned datagram keeps that age: bond and selector count
// it and never deliver it stale on the surviving carrier (with its age
// restarted at the hand-back the passive read it 200 ms late). The client
// writes nothing while the write is held, so nothing else ages. Criteria:
//
//   - Stimulus: the hook fired and held a request; the dialer recorded the
//     victim's death (transport_error).
//   - Age: the held request never reached the passive's application; the
//     dialer counts it in one drop counter, as its queue would (M2-D35):
//     DropAge while a data lane exists (bond's other member; a selector's
//     standby carrier, up before the victim died, is activated at once),
//     DropNoPath when the selector has no carrier to fall back to and ages
//     it while the failover dials one.
//   - Accounting: settled, the dialer's Sent equals its PeerReceived and the
//     echo's reads, and Sent plus that drop equals the requests written.
//   - Integrity: no duplicate or damaged datagram, no violation, a clean
//     end.
func TestPacketCarrierCloseUnsentAged_L40(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode rendr.Mode
	}{{"bond", rendr.ModeBond}, {"selector", rendr.ModeSelector}} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { unsentAged(t, tc.mode) })
		})
	}
}

func unsentAged(t *testing.T, mode rendr.Mode) {
	stim := &unsentStim{hold: 2 * clMaxAge}
	w := newWorldHooked(t, worldOpts{oneWay: clOneWay}, &testhooks.Hooks{BeforeWrite: stim.before}, nil, "u1", "u2")
	stim.conn = w.conn
	dc, pc := w.open(w.peer("u1", "u2"), rendr.DialOptions{Mode: mode})
	vic, ok := liveNamed(dc.Status(), "u1")
	if !ok {
		t.Fatalf("the session did not open on u1: %+v", dc.Status().Carriers)
	}
	if mode == rendr.ModeBond {
		waitFor(t, 2*time.Second, "two members on both ends", func() bool {
			return len(liveOf(dc.Status())) == 2 && len(liveOf(pc.Status())) == 2
		})
	}
	const seed = 0x779
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
	held := int64(-1)
	for seq := range uint64(clRequests) {
		sleepUntil(start.Add(time.Duration(seq)*clGap + pause))
		if seq == urArm {
			stim.vic.Store(uint32(vic.ID))
		}
		if _, err := dc.WriteTo(rendrtest.PacketPayload(buf, seed, seq, urSize, time.Now()), nil); err != nil {
			t.Fatalf("WriteTo of request %d: %v", seq, err)
		}
		synctest.Wait() // the dialer's writer has written it, failed to, or is held in the hook
		if held < 0 && stim.fired.Load() {
			held = int64(seq)    // the only request not yet written
			pause = 3 * clMaxAge // past the hold: no WriteTo while the write is held
		}
	}
	waitFor(t, 10*time.Second, "the packet accounting to settle", func() bool {
		ds, ps := dc.Status().Packet, pc.Status().Packet
		return ds.PeerReceived == ps.Received && ps.PeerReceived == ds.Received && echo.reads.Load() == int64(ps.Received)
	})
	ds, ps := *dc.Status().Packet, *pc.Status().Packet

	// Stimulus.
	stim.mu.Lock()
	at, cerr := stim.at, stim.err
	stim.mu.Unlock()
	if held < 0 || cerr != nil {
		t.Fatalf("stimulus: the held close in BeforeWrite of a request datagram on carrier %d did not happen (fired %v, close %v)", vic.ID, stim.fired.Load(), cerr)
	}
	down, ok := w.dev.downOf(vic.ID)
	if !ok || down.Cause != rendr.CauseTransportError {
		t.Fatalf("stimulus: the dialer's CarrierDown of %d is %+v (found %v), want transport_error", vic.ID, down, ok)
	}
	fallback := mode == rendr.ModeBond // bond: the other member is a data lane throughout
	for _, ev := range w.dev.of(rendr.EventCarrierUp) {
		if ev.Carrier != vic.ID && ev.Time.Before(down.Time) {
			fallback = true // a carrier the selector activates at the victim's death
		}
	}

	// Age: the held request is counted, never delivered stale.
	if when, ok := echo.echoedAt(uint64(held)); ok {
		t.Fatalf("request %d, held %v in its write, reached the passive at %v after the start: older than MaxAge %v since its WriteTo",
			held, stim.hold, when.Sub(start), clMaxAge)
	}
	aged := ds.DropAge
	if !fallback {
		aged = ds.DropNoPath
	}
	if aged != 1 || drops(&ds) != 1 {
		t.Fatalf("the dialer counts %+v (a carrier to fall back to: %v): want the held request DropAge with one, DropNoPath without, and no other drop",
			ds, fallback)
	}

	// Accounting.
	if r := echo.reads.Load(); ds.Sent != ds.PeerReceived || int64(ds.Sent) != r || ds.Sent+aged != clRequests {
		t.Fatalf("the dialer counts %+v and the passive read %d of %d: want Sent = PeerReceived = reads and Sent + the drop = requests",
			ds, r, clRequests)
	}
	if res := echo.v.Result(); res.Duplicates+res.Corrupt+res.BadSize != 0 {
		t.Fatalf("integrity at the passive: %+v", res)
	}
	t.Logf("%v: held request %d for %v on carrier %d, closed %v after the start (a carrier to fall back to: %v); dialer %+v; passive %+v",
		mode, held, stim.hold, vic.ID, at.Sub(start), fallback, ds, ps)

	unsentEnd(t, w, dc, pc, echo, rdone, ver)
}

// unsentEnd is the clean end of the unsent rows: the dialer closes, its
// reader ends with net.ErrClosed, the echo reads io.EOF and closes, both
// sessions end, no violation, Runtime.Close leaves nothing.
func unsentEnd(t *testing.T, w *world, dc, pc *rendr.PacketConn, echo *echoer, rdone chan error, ver *rendrtest.PacketVerifier) {
	t.Helper()
	dc.Close()
	select {
	case err := <-rdone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("the dialer's reader ended with %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the dialer's reader did not end")
	}
	if res := ver.Result(); res.Duplicates+res.Corrupt+res.BadSize != 0 {
		t.Fatalf("integrity at the dialer: %+v", res)
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

// conn returns the dialer's registered conn of carrier id (nil: none).
func (w *world) conn(id rendr.CarrierID) net.PacketConn {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.conns[id]
}

// newWorldHooked is newWorld with the dialer's own hooks dh and the
// passive's own hooks ph (nil: none): a hook keyed by a CarrierID would
// otherwise run on both ends, which share the ID.
func newWorldHooked(t testing.TB, o worldOpts, dh, ph *testhooks.Hooks, names ...string) *world {
	t.Helper()
	w := &world{t: t, dev: &eventLog{}, pev: &eventLog{}, mtu: o.mtu, conns: map[rendr.CarrierID]net.PacketConn{},
		acceptCh: make(chan *rendr.PendingPacket, 1), acceptDone: make(chan struct{})}
	if w.mtu == 0 {
		w.mtu = 1223
	}
	dov, pov := o.ov, o.ov
	dov.Hooks, pov.Hooks = dh, ph
	w.d = newRuntime(t, rendr.Config{OnEvent: w.dev.add}, &dov)
	w.p = newRuntime(t, rendr.Config{OnEvent: w.pev.add}, &pov)
	t.Cleanup(w.shutdown)
	ln, err := w.p.Listen(rendr.ListenConfig{})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	w.ln = ln
	ctx, cancel := context.WithCancel(context.Background())
	w.stopAccept = cancel
	go w.acceptor(ctx)
	for _, n := range names {
		l := rendrtest.NewDatagramLink(rendrtest.DatagramLinkConfig{Name: n, Accept: w.ln.HandlePacket, Queue: 16384})
		for _, d := range bothDirs {
			l.SetDelay(d, o.oneWay, 0)
		}
		w.links = append(w.links, l)
	}
	return w
}
