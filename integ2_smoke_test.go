package rendr_test

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/carrier/udp"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The checkpoint C-A smoke (M2 design §A11.4 step 4): two Runtimes, one
// packet session per run, over two datagram paths of one transport — the
// in-memory DatagramLink (passive: Listener.HandlePacket), the in-memory
// shared socket DatagramHub (passive: FromPacketConn) and carrier/udp on
// loopback (FromPacketConn of a real socket) — in selector and in bond
// mode. The dialer sends 10,000 datagrams per second (1,000 under -race)
// and the passive 1,000 per second back, while every 10 s a path that
// carries the session is killed — selector: the active carrier's, bond:
// the members' in turn (DatagramLink.Kill: both ends fail; the
// shared-socket transports: the dialer's session conn is closed under
// rendr, an embedder-closed conn).
//
// Stimulus: every kill ended a carrier (CarrierDown events of the dialer)
// and the session survived each. Load: the rate was reached (the received
// count). Integrity: every datagram is verified (seq, size, CRC and body);
// none is corrupt, resized or duplicated; every loss falls within a short
// window after a kill or is a counted queue drop; the PacketCounters of both ends add up (§A7.2:
// accepted = Sent + the send-side drops, nothing queued after the end;
// Received = returned by ReadFrom + DropRecvQueue). After Runtime.Close
// nothing is left: no session, handshake, flow, source or buffered byte,
// and no goroutine (the bubble ends only when every goroutine of it
// exited; the real-socket run counts goroutines).

// smokeRun describes one smoke run.
type smokeRun struct {
	mode     rendr.Mode
	duration time.Duration // traffic time
	every    time.Duration // a kill every this long
	rate     int           // dialer → passive datagrams per second
	back     int           // passive → dialer datagrams per second
	lossWin  time.Duration // losses must start within this after a kill
}

// smokeNet is one transport's two paths between the Runtimes.
type smokeNet struct {
	carriers []rendr.Carrier
	kill     func(i int) bool // fails path i's current session carrier; false: none
	listen   rendr.ListenConfig
	attach   func(ln *rendr.Listener) // HandlePacket wiring, if any
	close    func()
}

// lastConn wraps a datagram factory so that the session conn it returned
// last can be closed under rendr (an embedder-closed conn: transport_error
// at once); probe carriers' conns are not recorded.
type lastConn struct {
	mu sync.Mutex
	pc net.PacketConn
}

func (l *lastConn) wrap(dial func(context.Context) (net.PacketConn, net.Addr, error)) func(context.Context) (net.PacketConn, net.Addr, error) {
	return func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		pc, a, err := dial(ctx)
		if di, ok := rendr.CarrierDialInfo(ctx); err == nil && ok && !di.Probe {
			l.mu.Lock()
			l.pc = pc
			l.mu.Unlock()
		}
		return pc, a, err
	}
}

func (l *lastConn) kill() bool {
	l.mu.Lock()
	pc := l.pc
	l.pc = nil
	l.mu.Unlock()
	if pc == nil {
		return false
	}
	pc.Close()
	return true
}

// smokeLinkNet: two DatagramLinks with a 2 ms one-way delay.
func smokeLinkNet() *smokeNet {
	n := &smokeNet{}
	var links []*rendrtest.DatagramLink
	var ln atomic.Pointer[rendr.Listener]
	for _, name := range []string{"a", "b"} {
		l := rendrtest.NewDatagramLink(rendrtest.DatagramLinkConfig{Name: name, Queue: 16384,
			Accept: func(pc net.PacketConn, peer net.Addr) error { return ln.Load().HandlePacket(pc, peer) }})
		l.SetDelay(rendrtest.Up, 2*time.Millisecond, 0)
		l.SetDelay(rendrtest.Down, 2*time.Millisecond, 0)
		links = append(links, l)
		n.carriers = append(n.carriers, rendr.DatagramCarrier{Name: name, Dial: l.Dial, MTU: 1400})
	}
	n.attach = func(l *rendr.Listener) { ln.Store(l) }
	n.kill = func(i int) bool { return links[i].Stats().Carriers > 0 && killLink(links[i]) }
	n.close = func() {
		for _, l := range links {
			l.Close()
		}
	}
	return n
}

// killLink kills the link's carriers and reports whether one was live.
func killLink(l *rendrtest.DatagramLink) bool {
	before := l.Stats().All.Killed
	l.Kill()
	return l.Stats().All.Killed > before
}

// smokeHubNet: one DatagramHub; the two paths are clients of two hosts.
func smokeHubNet() *smokeNet {
	hub := rendrtest.NewDatagramHub(rendrtest.DatagramHubConfig{Name: "hub", Queue: 16384})
	n := &smokeNet{listen: rendr.ListenConfig{Sources: []rendr.Source{rendr.FromPacketConn(hub.PacketConn())}}}
	lc := make([]*lastConn, 2)
	for i, name := range []string{"h0", "h1"} {
		lc[i] = &lastConn{}
		n.carriers = append(n.carriers, rendr.DatagramCarrier{Name: name, Dial: lc[i].wrap(hub.DialFrom(i)), MTU: 1400})
	}
	n.kill = func(i int) bool { return lc[i].kill() }
	n.close = func() { hub.Close() }
	return n
}

// smokeUDPNet: carrier/udp on loopback, one listening socket.
func smokeUDPNet(t *testing.T) *smokeNet {
	pc, err := udp.Listen("udp4", "127.0.0.1:0", udp.Options{})
	if err != nil {
		t.Fatalf("udp.Listen: %v", err)
	}
	addr := pc.LocalAddr().String()
	n := &smokeNet{listen: rendr.ListenConfig{Sources: []rendr.Source{rendr.FromPacketConn(pc)}}}
	lc := make([]*lastConn, 2)
	for i, name := range []string{"u0", "u1"} {
		lc[i] = &lastConn{}
		c := udp.Carrier(name, "udp4", addr, udp.Options{})
		c.Dial = lc[i].wrap(c.Dial)
		n.carriers = append(n.carriers, c)
	}
	n.kill = func(i int) bool { return lc[i].kill() }
	n.close = func() {}
	return n
}

// smokeSide is one direction's generator and receiver.
type smokeSide struct {
	v        *rendrtest.PacketVerifier
	accepted atomic.Uint64 // WriteTo returned (n, nil)
	read     atomic.Uint64 // ReadFrom returned a datagram
	readErr  error         // the error that ended the reader
	verr     atomic.Value  // the first verifier error
}

// smokeSize is the size of datagram seq: 24 … 1000 bytes.
func smokeSize(seq uint64) int { return rendrtest.PacketHeaderLen + int(seq*37%977) }

// generate writes rate datagrams per second (bursts every millisecond)
// until stop closes; datagram seq is sent at start + seq/rate.
func (s *smokeSide) generate(c *rendr.PacketConn, seed uint64, rate int, stop <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	buf := make([]byte, 1024)
	start := time.Now()
	var seq uint64
	tk := time.NewTicker(time.Millisecond)
	defer tk.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-tk.C:
			due := uint64(now.Sub(start).Seconds() * float64(rate))
			for ; seq < due; seq++ {
				b := rendrtest.PacketPayload(buf, seed, seq, smokeSize(seq), now)
				if _, err := c.WriteTo(b, nil); err != nil {
					s.verr.CompareAndSwap(nil, err)
					return
				}
				s.accepted.Add(1)
			}
		}
	}
}

// receive reads and verifies datagrams until ReadFrom fails.
func (s *smokeSide) receive(c *rendr.PacketConn, wg *sync.WaitGroup) {
	defer wg.Done()
	buf := make([]byte, 2048)
	for {
		n, _, err := c.ReadFrom(buf)
		if err != nil {
			s.readErr = err
			return
		}
		s.read.Add(1)
		if err := s.v.Add(buf[:n], time.Now()); err != nil {
			s.verr.CompareAndSwap(nil, err)
		}
	}
}

// runSmoke runs one smoke over n.
func runSmoke(t *testing.T, n *smokeNet, r smokeRun, cfg rendr.Config) {
	t.Helper()
	var downs atomic.Int64
	dcfg := cfg
	dcfg.OnEvent = func(ev rendr.Event) {
		if ev.Kind == rendr.EventCarrierDown {
			downs.Add(1)
		}
	}
	d, err := rendr.NewRuntime(dcfg)
	if err != nil {
		t.Fatal(err)
	}
	p, err := rendr.NewRuntime(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := p.Listen(n.listen)
	if err != nil {
		t.Fatal(err)
	}
	if n.attach != nil {
		n.attach(ln)
	}
	peer, err := d.NewPeer(rendr.PeerConfig{Carriers: n.carriers})
	if err != nil {
		t.Fatal(err)
	}
	dres := make(chan *rendr.PacketConn, 1)
	go func() {
		c, err := peer.DialPacket(context.Background(), rendr.DialOptions{Mode: r.mode})
		if err != nil {
			t.Errorf("DialPacket: %v", err)
		}
		dres <- c
	}()
	pp, err := ln.AcceptPacket(context.Background())
	if err != nil {
		t.Fatalf("AcceptPacket: %v", err)
	}
	pc, err := pp.Confirm()
	if err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	dc := <-dres
	if dc == nil {
		t.FailNow()
	}
	if r.mode == rendr.ModeBond {
		deadline := time.Now().Add(5 * time.Second)
		for len(liveCarriers(dc)) < 2 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
	}

	up := &smokeSide{v: rendrtest.NewPacketVerifier(1)}   // dialer → passive
	down := &smokeSide{v: rendrtest.NewPacketVerifier(2)} // passive → dialer
	var gens, readers sync.WaitGroup
	stop := make(chan struct{})
	start := time.Now()
	gens.Add(2)
	readers.Add(2)
	go up.generate(dc, 1, r.rate, stop, &gens)
	go down.generate(pc, 2, r.back, stop, &gens)
	go up.receive(pc, &readers)
	go down.receive(dc, &readers)

	var kills []time.Duration
	for k := 1; time.Duration(k)*r.every < r.duration; k++ {
		time.Sleep(time.Until(start.Add(time.Duration(k) * r.every)))
		victim := (k - 1) % 2
		if r.mode == rendr.ModeSelector {
			victim = -1
			for _, cs := range dc.Status().Carriers {
				if cs.State == rendr.CarrierActive {
					for i, c := range n.carriers {
						if c.(rendr.DatagramCarrier).Name == cs.Name {
							victim = i
						}
					}
				}
			}
		}
		if victim >= 0 && n.kill(victim) {
			kills = append(kills, time.Since(start))
		}
	}
	time.Sleep(time.Until(start.Add(r.duration)))
	close(stop)
	gens.Wait()
	time.Sleep(2 * time.Second) // drain both directions
	// The passive reads up to its io.EOF; the dialer's reader ends with
	// net.ErrClosed at its own Close (the reverse direction is drained).
	ds0, ps0 := dc.Status(), pc.Status()
	dc.Close()
	waitDone(t, dc.Done(), "the dialer session")
	readers.Wait()
	pc.Close()
	waitDone(t, pc.Done(), "the passive session")
	ds, ps := dc.Status(), pc.Status()

	// Stimulus: every kill ended a carrier, the session lived through all.
	if want := int(r.duration/r.every) - 1; len(kills) < want {
		t.Errorf("stimulus: %d kills hit a live carrier, want %d", len(kills), want)
	}
	if got := downs.Load(); got < int64(len(kills)) {
		t.Errorf("stimulus: %d CarrierDown events for %d kills", got, len(kills))
	}
	if ds0.Err != nil || ps0.Err != nil {
		t.Errorf("a session failed before its Close: dialer %v, passive %v", ds0.Err, ps0.Err)
	}
	// Integrity and load per direction.
	for _, x := range []struct {
		name     string
		s        *smokeSide
		rate     int
		eof      error
		tx, rx   rendr.SessionStatus
		sentSeqs uint64
	}{
		{"dialer → passive", up, r.rate, io.EOF, ds, ps, up.accepted.Load()},
		{"passive → dialer", down, r.back, net.ErrClosed, ps, ds, down.accepted.Load()},
	} {
		if e := x.s.verr.Load(); e != nil {
			t.Errorf("%s: %v", x.name, e)
		}
		if !errors.Is(x.s.readErr, x.eof) {
			t.Errorf("%s: the reader ended with %v, want %v", x.name, x.s.readErr, x.eof)
		}
		res := x.s.v.Result()
		if res.Corrupt != 0 || res.BadSize != 0 || res.Duplicates != 0 {
			t.Errorf("%s: corrupt %d, resized %d, duplicates %d", x.name, res.Corrupt, res.BadSize, res.Duplicates)
		}
		if min := uint64(float64(r.duration/time.Second)*float64(x.rate)) * 9 / 10; res.Unique < min {
			t.Errorf("load: %s received %d unique datagrams, want ≥ %d", x.name, res.Unique, min)
		}
		lost := x.sentSeqs - res.Unique
		tp, rp := x.tx.Packet, x.rx.Packet
		if tp == nil || rp == nil {
			t.Fatalf("%s: no PacketCounters", x.name)
		}
		// Losses away from every kill must be counted drops of the
		// session's own queues (none in virtual time; in real time under
		// -race a host stall can age one out: DropAge), never silent.
		var away uint64
		for _, m := range res.Missing {
			at := time.Duration(float64(m.From) / float64(x.rate) * float64(time.Second))
			if !nearKill(at, kills, r.lossWin) {
				away += m.To - m.From + 1
			}
		}
		if counted := tp.DropQueue + tp.DropAge + tp.DropNoPath + tp.DropTooLarge + rp.DropRecvQueue; away > counted {
			t.Errorf("%s: %d datagrams lost away from every kill %v, only %d counted as queue drops (missing %v)",
				x.name, away, kills, counted, res.Missing)
		}
		// §A7.2: the send side adds up over public fields; the receive side
		// read up to its end (nothing discarded after Close).
		if sum := tp.Sent + tp.DropQueue + tp.DropAge + tp.DropNoPath + tp.DropTooLarge; sum != x.sentSeqs {
			t.Errorf("%s: accepted %d ≠ Sent %d + DropQueue %d + DropAge %d + DropNoPath %d + DropTooLarge %d = %d",
				x.name, x.sentSeqs, tp.Sent, tp.DropQueue, tp.DropAge, tp.DropNoPath, tp.DropTooLarge, sum)
		}
		if got := x.s.read.Load() + rp.DropRecvQueue; rp.Received != got {
			t.Errorf("%s: Received %d ≠ read %d + DropRecvQueue %d", x.name, rp.Received, x.s.read.Load(), rp.DropRecvQueue)
		}
		if rp.Received > tp.Sent || rp.Duplicates != 0 {
			t.Errorf("%s: Received %d of Sent %d, Duplicates %d", x.name, rp.Received, tp.Sent, rp.Duplicates)
		}
		t.Logf("%s: accepted %d, unique %d, lost %d (%.3f%%), missing ranges %d, max gap %v; tx %+v; rx %+v",
			x.name, x.sentSeqs, res.Unique, lost, 100*float64(lost)/float64(max(x.sentSeqs, 1)), len(res.Missing), res.MaxGap, *tp, *rp)
	}
	t.Logf("kills at %v; dialer CarrierDown events %d; migrations dialer %+v passive %+v", kills, downs.Load(), ds.Migrations, ps.Migrations)

	d.Close()
	p.Close()
	for _, rt := range []*rendr.Runtime{d, p} {
		st := rt.Status()
		sc := st.Sessions
		if sc.Open+sc.Pending+sc.Lingering+sc.Orphaned != 0 || st.Handshakes != 0 || st.Sessionless != 0 ||
			st.BufferedBytes != 0 || st.Abandoned != 0 || st.Datagram.Flows != 0 || st.Datagram.Sources != 0 || st.Datagram.Admitting != 0 {
			t.Errorf("state left after Runtime.Close: %+v", st)
		}
	}
}

// liveCarriers returns the live carriers of c.
func liveCarriers(c *rendr.PacketConn) []rendr.CarrierStatus {
	var out []rendr.CarrierStatus
	for _, cs := range c.Status().Carriers {
		if cs.DeathCause == rendr.CauseNone {
			out = append(out, cs)
		}
	}
	return out
}

// nearKill reports whether at lies in [k − 50 ms, k + win] of a kill k
// (a datagram queued just before the kill may be lost with its carrier).
func nearKill(at time.Duration, kills []time.Duration, win time.Duration) bool {
	for _, k := range kills {
		if at >= k-50*time.Millisecond && at <= k+win {
			return true
		}
	}
	return false
}

func waitDone(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(40 * time.Second):
		t.Fatalf("%s did not end within 40 s of its Close", what)
	}
}

// TestPacketSmoke_CA is the in-memory half: DatagramLink and DatagramHub,
// selector and bond, 60 virtual seconds each.
func TestPacketSmoke_CA(t *testing.T) {
	rate := 10000
	if loopbackRace {
		rate = 1000
	}
	for _, tr := range []struct {
		name string
		net  func() *smokeNet
	}{{"DatagramLink", smokeLinkNet}, {"DatagramHub", smokeHubNet}} {
		for _, mode := range []rendr.Mode{rendr.ModeSelector, rendr.ModeBond} {
			t.Run(tr.name+"/"+mode.String(), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					n := tr.net()
					defer n.close()
					runSmoke(t, n, smokeRun{mode: mode, duration: 60 * time.Second, every: 10 * time.Second,
						rate: rate, back: 1000, lossWin: 5 * time.Second}, rendr.Config{})
				})
			})
		}
	}
}

// TestPacketSmokeUDP_CA is the real-socket half over carrier/udp on
// loopback: 10 real seconds with a kill every 2 s per mode (a shortened
// timeline: the host runs no long real-time loads).
func TestPacketSmokeUDP_CA(t *testing.T) {
	if testing.Short() {
		t.Skip("real-time smoke")
	}
	rate := 10000
	if loopbackRace {
		rate = 2000
	}
	for _, mode := range []rendr.Mode{rendr.ModeSelector, rendr.ModeBond} {
		t.Run(mode.String(), func(t *testing.T) {
			g0 := runtime.NumGoroutine()
			n := smokeUDPNet(t)
			runSmoke(t, n, smokeRun{mode: mode, duration: 10 * time.Second, every: 2 * time.Second,
				rate: rate, back: 1000, lossWin: 5 * time.Second}, rendr.Config{})
			deadline := time.Now().Add(5 * time.Second)
			for runtime.NumGoroutine() > g0 && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if g := runtime.NumGoroutine(); g > g0 {
				buf := make([]byte, 1<<20)
				t.Fatalf("%d goroutines after Runtime.Close, %d before:\n%s", g, g0, buf[:runtime.Stack(buf, true)])
			}
		})
	}
}
