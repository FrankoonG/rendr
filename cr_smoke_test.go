package rendr_test

import (
	"context"
	"io"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The checkpoint C-R smoke (M3 design §A14.3 row I1): race, the parked
// actors and the M3 root surface between two Runtimes over rendrtest
// links, in synctest bubbles.
//
//   - TestStreamSmoke_CR: one stream session per mode (selector, bond and
//     race) moves 64 MiB (16 MiB under -race, the same timeline) over two
//     shaped Links while a carrier of the session is killed every 10 s.
//   - TestPacketRaceSmoke_CR: a packet race session at 10,000 datagrams
//     per second (1,000 under -race) for 60 virtual seconds over the
//     DatagramLink and the DatagramHub, a member closed every 10 s (the
//     C-A smoke's runSmoke, which already runs selector and bond).
//   - TestIdleSessionsPark_CR: 1,000 sessions (250 under -race) of the
//     three modes park after their single exchange and still carry data
//     while parked.
//
// Each run checks the stimulus (every kill ended a session carrier, the
// session survived), the load (every byte or the datagram rate arrived)
// and integrity (PRNG-verified bytes, verified datagrams), that the
// counters add up, and that after Runtime.Close nothing is left: no
// session, handshake, flow or buffered byte, no live or parked session in
// the registry (R1-24), and no goroutine (the bubble ends only when every
// goroutine of it exited).

// crRuntimeEmpty fails if rt holds any state after its Close.
func crRuntimeEmpty(t testing.TB, rt *rendr.Runtime) {
	t.Helper()
	st := rt.Status()
	sc := st.Sessions
	if sc.Open+sc.Pending+sc.Lingering+sc.Orphaned != 0 || st.Handshakes != 0 || st.Sessionless != 0 || st.Actors != 0 ||
		st.BufferedBytes != 0 || st.Abandoned != 0 || st.Datagram.Flows != 0 || st.Datagram.Sources != 0 || st.Datagram.Admitting != 0 {
		t.Errorf("state left after Runtime.Close: %+v", st)
	}
}

// crRegistryBack fails unless the session registry is back at its values
// before the run (R1-24).
func crRegistryBack(t testing.TB, live0, parked0 int64) {
	t.Helper()
	if l, p := testhooks.LiveSessions.Load()-live0, testhooks.ParkedSessions.Load()-parked0; l != 0 || p != 0 {
		t.Errorf("session registry after Runtime.Close: %+d live, %+d parked", l, p)
	}
}

// crMembers counts the carriers of st in state s.
func crMembers(st rendr.SessionStatus, s rendr.CarrierState) int {
	n := 0
	for _, c := range st.Carriers {
		if c.State == s {
			n++
		}
	}
	return n
}

// crUntil polls cond every 10 ms of virtual time, failing after within.
func crUntil(t testing.TB, within time.Duration, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(within); !cond(); {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within %v", what, within)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// crPump writes n bytes of PRNG(seed) on w, then half-closes it.
func crPump(c *rendr.Conn, n int64, seed uint64) error {
	if _, err := io.Copy(struct{ io.Writer }{c}, io.LimitReader(rendrtest.PRNG(seed), n)); err != nil {
		return err
	}
	return c.CloseWrite()
}

// TestStreamSmoke_CR: per mode, a dialer and a passive Runtime joined by two
// Links (10 ms one way, each shaped to size/50 s, so a selector or race
// session needs ≈ 50 virtual seconds and a bond session ≈ 25); the dialer
// sends size bytes and the passive 1 MiB back at once; every 10 s while the
// transfer runs a Link carrying the session is killed (Link.Kill closes
// both ends of its carriers): selector the active carrier's, bond and race
// the members' in turn. Stimulus: every kill ended a session carrier
// (Link Session.Killed) and the dialer saw a CarrierDown for each; at
// least 4 kills (bond 2). Load and integrity: both directions verified
// byte for byte up to io.EOF; the sessions end with io.EOF. Counters: the
// dialer's TxBytes and AckedBytes and the passive's DeliveredBytes are
// size, the reverse likewise 1 MiB (unique accounting: a race copy counts
// once, M3-D35); race: the dialer placed copies (Race.CopyBytes) and the
// passive discarded copies it already held (DupBytes); selector and bond
// place none.
func TestStreamSmoke_CR(t *testing.T) {
	size := int64(64 << 20)
	if loopbackRace {
		size = 16 << 20 // the same timeline (R2-37)
	}
	for _, mode := range []rendr.Mode{rendr.ModeSelector, rendr.ModeBond, rendr.ModeRace} {
		t.Run(mode.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { runStreamSmoke(t, mode, size) })
		})
	}
}

func runStreamSmoke(t *testing.T, mode rendr.Mode, size int64) {
	const back = 1 << 20
	live0, parked0 := testhooks.LiveSessions.Load(), testhooks.ParkedSessions.Load()
	var downs atomic.Int64
	d, err := rendr.NewRuntime(rendr.Config{OnEvent: func(ev rendr.Event) {
		if ev.Kind == rendr.EventCarrierDown {
			downs.Add(1)
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := rendr.NewRuntime(rendr.Config{})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := p.Listen(rendr.ListenConfig{})
	if err != nil {
		t.Fatal(err)
	}
	var links []*rendrtest.Link
	var carriers []rendr.Carrier
	for _, name := range []string{"a", "b"} {
		l := rendrtest.NewLink(rendrtest.LinkConfig{Name: name, Accept: ln.Handle})
		l.SetDelay(10*time.Millisecond, 0)
		l.SetRate(float64(size) / 50)
		links = append(links, l)
		carriers = append(carriers, rendr.StreamCarrier{Name: name, Dial: l.Dial})
	}
	peer, err := d.NewPeer(rendr.PeerConfig{Carriers: carriers})
	if err != nil {
		t.Fatal(err)
	}
	dres := make(chan *rendr.Conn, 1)
	go func() {
		c, err := peer.Dial(context.Background(), rendr.DialOptions{Mode: mode})
		if err != nil {
			t.Errorf("Dial(%v): %v", mode, err)
		}
		dres <- c
	}()
	pend, err := ln.Accept(context.Background())
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if pend.Mode() != mode {
		t.Fatalf("pending mode %v, want %v", pend.Mode(), mode)
	}
	pc, err := pend.Confirm()
	if err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	dc := <-dres
	if dc == nil {
		t.FailNow()
	}
	if mode != rendr.ModeSelector {
		crUntil(t, 10*time.Second, "two members on both ends", func() bool {
			return crMembers(dc.Status(), rendr.CarrierMember) == 2 && crMembers(pc.Status(), rendr.CarrierMember) == 2
		})
	}

	// Traffic: both directions at once, each verified up to io.EOF.
	errs := make(chan error, 4)
	var wg sync.WaitGroup
	done := make(chan struct{})
	start := time.Now()
	wg.Go(func() { errs <- crPump(dc, size, 1) })
	wg.Go(func() { errs <- crPump(pc, back, 2) })
	var readers sync.WaitGroup
	readers.Go(func() { errs <- rendrtest.NewVerifier(1, size).ReadAll(pc) })
	readers.Go(func() { errs <- rendrtest.NewVerifier(2, back).ReadAll(dc) })
	go func() { readers.Wait(); close(done) }()

	// A kill every 10 s while the transfer runs.
	var kills []time.Duration
	for k := 1; ; k++ {
		select {
		case <-done:
		case <-time.After(time.Until(start.Add(time.Duration(k) * 10 * time.Second))):
			victim := (k - 1) % 2
			if mode == rendr.ModeSelector {
				victim = -1
				for _, cs := range dc.Status().Carriers {
					if cs.State == rendr.CarrierActive {
						victim = int(cs.Name[0] - 'a')
					}
				}
			}
			if victim >= 0 {
				before := links[victim].Stats().Session.Killed
				at := time.Since(start)
				links[victim].Kill()
				if links[victim].Stats().Session.Killed > before {
					kills = append(kills, at)
				}
			}
			continue
		}
		break
	}
	took := time.Since(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("%v traffic: %v", mode, err)
		}
	}
	if t.Failed() {
		t.FailNow()
	}
	// The last ACK may still be on its way when the reader has every byte.
	crUntil(t, 10*time.Second, "the last ACKs", func() bool {
		return dc.Status().AckedBytes == uint64(size) && pc.Status().AckedBytes == back
	})
	ds, ps := dc.Status(), pc.Status()

	// Stimulus.
	want := 4
	if mode == rendr.ModeBond {
		want = 2
	}
	if len(kills) < want {
		t.Errorf("stimulus: %d kills ended a session carrier within %v, want ≥ %d", len(kills), took, want)
	}
	if got := downs.Load(); got < int64(len(kills)) {
		t.Errorf("stimulus: %d CarrierDown events for %d kills", got, len(kills))
	}
	// Counters (unique accounting).
	if ds.TxBytes != uint64(size) || ds.AckedBytes != uint64(size) || ps.DeliveredBytes != uint64(size) {
		t.Errorf("dialer → passive: TxBytes %d, AckedBytes %d, DeliveredBytes %d, want %d each", ds.TxBytes, ds.AckedBytes, ps.DeliveredBytes, size)
	}
	if ps.TxBytes != back || ps.AckedBytes != back || ds.DeliveredBytes != back {
		t.Errorf("passive → dialer: TxBytes %d, AckedBytes %d, DeliveredBytes %d, want %d each", ps.TxBytes, ps.AckedBytes, ds.DeliveredBytes, back)
	}
	switch {
	case mode == rendr.ModeRace && (ds.Race.CopyBytes == 0 || ps.DupBytes == 0):
		t.Errorf("race: the dialer placed %d copy bytes and the passive discarded %d duplicate bytes, want both > 0", ds.Race.CopyBytes, ps.DupBytes)
	case mode != rendr.ModeRace && (ds.Race != rendr.RaceCounters{} || ps.Race != rendr.RaceCounters{}):
		t.Errorf("%v: race counters %+v and %+v, want zero", mode, ds.Race, ps.Race)
	}
	if ds.Mode != mode || ps.Mode != mode {
		t.Errorf("modes %v and %v, want %v", ds.Mode, ps.Mode, mode)
	}
	t.Logf("%v: %d MiB in %v (%.2f MiB/s), kills at %v, CarrierDown %d; dialer migrations %+v rejoins %d retx %d copies %d; passive DupBytes %d",
		mode, size>>20, took.Round(time.Millisecond), float64(size)/(1<<20)/took.Seconds(), kills, downs.Load(),
		ds.Migrations, ds.Rejoins, ds.RetransmittedBytes, ds.Race.CopyBytes, ps.DupBytes)

	dc.Close()
	pc.Close()
	for _, c := range []*rendr.Conn{dc, pc} {
		select {
		case <-c.Done():
		case <-time.After(30 * time.Second):
			t.Fatalf("session not done 30 s after Close: %+v", c.Status())
		}
		if st := c.Status(); st.State != rendr.StateEnded || st.Err != io.EOF {
			t.Errorf("session end: state %v, err %v, want io.EOF", st.State, st.Err)
		}
	}
	peer.Close()
	d.Close()
	p.Close()
	for _, l := range links {
		l.Close()
	}
	crRuntimeEmpty(t, d)
	crRuntimeEmpty(t, p)
	crRegistryBack(t, live0, parked0)
}

// TestPacketRaceSmoke_CR: the C-A packet smoke (runSmoke) for a race
// session over the DatagramLink and the DatagramHub: 60 virtual seconds
// at 10,000 datagrams per second (1,000 under -race) and 1,000 back, a
// member's carrier closed every 10 s in turn. On top of runSmoke's
// checks (no corrupt, resized or application-duplicated datagram, losses
// only near kills or counted, the counters adding up, nothing left after
// Close), race delivers at least 99 % of what was accepted in each
// direction, the receiver counts the members' copies as Duplicates, and
// the sender's copies as Race.Copies.
func TestPacketRaceSmoke_CR(t *testing.T) {
	rate := 10000
	if loopbackRace {
		rate = 1000
	}
	for _, tr := range []struct {
		name string
		net  func() *smokeNet
	}{{"DatagramLink", smokeLinkNet}, {"DatagramHub", smokeHubNet}} {
		t.Run(tr.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				live0, parked0 := testhooks.LiveSessions.Load(), testhooks.ParkedSessions.Load()
				n := tr.net()
				defer n.close()
				runSmoke(t, n, smokeRun{mode: rendr.ModeRace, duration: 60 * time.Second, every: 10 * time.Second,
					rate: rate, back: 1000, lossWin: 200 * time.Millisecond}, rendr.Config{})
				crRegistryBack(t, live0, parked0)
			})
		})
	}
}

// TestIdleSessionsPark_CR: n sessions (1,000; 250 under -race) between two
// Runtimes over two Links, every tenth a bond and every tenth a race
// session, the rest selector; each carries one byte each way. After the
// default ActorLinger (1 s) every actor on both ends is parked: Status.Actors
// is 0 on both Runtimes, the registry counts 2n live and 2n parked
// sessions, no actor goroutine runs, and the goroutines rendr runs are the
// carriers' readers and writers only (2 per carrier per side, plus a
// constant). Parked sessions still carry data: a second byte each way on
// every session arrives. Closing every session and both Runtimes leaves
// nothing.
func TestIdleSessionsPark_CR(t *testing.T) {
	n := 1000
	if loopbackRace {
		n = 250
	}
	synctest.Test(t, func(t *testing.T) {
		live0, parked0 := testhooks.LiveSessions.Load(), testhooks.ParkedSessions.Load()
		cfg := rendr.Config{Handshake: rendr.HandshakeLimits{MaxConcurrent: 2 * n}}
		d, err := rendr.NewRuntime(cfg)
		if err != nil {
			t.Fatal(err)
		}
		p, err := rendr.NewRuntime(cfg)
		if err != nil {
			t.Fatal(err)
		}
		ln, err := p.Listen(rendr.ListenConfig{AcceptBacklog: 2 * n})
		if err != nil {
			t.Fatal(err)
		}
		var links []*rendrtest.Link
		var carriers []rendr.Carrier
		for _, name := range []string{"a", "b"} {
			l := rendrtest.NewLink(rendrtest.LinkConfig{Name: name, Accept: ln.Handle})
			l.SetDelay(5*time.Millisecond, 0)
			links = append(links, l)
			carriers = append(carriers, rendr.StreamCarrier{Name: name, Dial: l.Dial})
		}
		peer, err := d.NewPeer(rendr.PeerConfig{Carriers: carriers})
		if err != nil {
			t.Fatal(err)
		}
		modeOf := func(i int) rendr.Mode {
			switch i % 10 {
			case 0:
				return rendr.ModeBond
			case 1:
				return rendr.ModeRace
			}
			return rendr.ModeSelector
		}
		// The passive confirms everything; sessions are matched by their
		// metadata (the index).
		passive := make([]*rendr.Conn, n)
		var accepted sync.WaitGroup
		accepted.Go(func() {
			for range n {
				pend, err := ln.Accept(context.Background())
				if err != nil {
					t.Errorf("Accept: %v", err)
					return
				}
				c, err := pend.Confirm()
				if err != nil {
					t.Errorf("Confirm: %v", err)
					return
				}
				i, err := strconv.Atoi(string(pend.Metadata()))
				if err != nil || i < 0 || i >= n || passive[i] != nil {
					t.Errorf("metadata %q", pend.Metadata())
					return
				}
				passive[i] = c
			}
		})
		dialer := make([]*rendr.Conn, n)
		var dials sync.WaitGroup
		for i := range n {
			dials.Go(func() {
				meta := []byte(strconv.Itoa(i))
				c, err := peer.Dial(context.Background(), rendr.DialOptions{Mode: modeOf(i), Metadata: meta})
				if err != nil {
					t.Errorf("Dial %d (%v): %v", i, modeOf(i), err)
					return
				}
				dialer[i] = c
			})
		}
		dials.Wait()
		accepted.Wait()
		if t.Failed() {
			t.FailNow()
		}
		exchange := func(round byte) {
			t.Helper()
			var wg sync.WaitGroup
			for i := range n {
				wg.Go(func() {
					for _, pair := range [][2]*rendr.Conn{{dialer[i], passive[i]}, {passive[i], dialer[i]}} {
						if _, err := pair[0].Write([]byte{round}); err != nil {
							t.Errorf("session %d: Write: %v", i, err)
							return
						}
						var b [1]byte
						if _, err := io.ReadFull(pair[1], b[:]); err != nil || b[0] != round {
							t.Errorf("session %d: Read %v, %v; want %d", i, b[0], err, round)
							return
						}
					}
				})
			}
			wg.Wait()
		}
		exchange(1)
		if t.Failed() {
			t.FailNow()
		}
		carrierCount := 0
		for _, c := range dialer {
			carrierCount += crMembers(c.Status(), rendr.CarrierActive) + crMembers(c.Status(), rendr.CarrierMember)
		}

		time.Sleep(2 * time.Second) // twice the default ActorLinger
		synctest.Wait()
		if a, b := d.Status().Actors, p.Status().Actors; a != 0 || b != 0 {
			t.Fatalf("Status.Actors %d and %d after the linger, want every actor parked", a, b)
		}
		if l, pk := testhooks.LiveSessions.Load()-live0, testhooks.ParkedSessions.Load()-parked0; l != int64(2*n) || pk != int64(2*n) {
			t.Fatalf("registry: %d live and %d parked sessions, want %d each", l, pk, 2*n)
		}
		ours, actors := crGoroutines()
		t.Logf("%d sessions (%d dialer carriers): %d rendr goroutines, %d actors", n, carrierCount, ours, actors)
		if actors != 0 || ours > 4*carrierCount+64 {
			t.Fatalf("%d rendr goroutines (%d actors) for %d parked sessions on %d carriers per side, want 0 actors and ≤ %d",
				ours, actors, n, carrierCount, 4*carrierCount+64)
		}

		exchange(2) // parked sessions still carry data
		if t.Failed() {
			t.FailNow()
		}

		var wg sync.WaitGroup
		for i := range n {
			wg.Go(func() {
				dialer[i].Close()
				passive[i].Close()
				for _, c := range []*rendr.Conn{dialer[i], passive[i]} {
					select {
					case <-c.Done():
					case <-time.After(time.Minute):
						t.Errorf("session %d not done a minute after Close", i)
					}
				}
			})
		}
		wg.Wait()
		peer.Close()
		d.Close()
		p.Close()
		for _, l := range links {
			l.Close()
		}
		crRuntimeEmpty(t, d)
		crRuntimeEmpty(t, p)
		crRegistryBack(t, live0, parked0)
	})
}

// crGoroutines counts the goroutines running rendr code and, of them, the
// session actors.
func crGoroutines() (ours, actors int) {
	buf := make([]byte, 64<<20)
	buf = buf[:runtime.Stack(buf, true)]
	for _, g := range strings.Split(string(buf), "\n\n") {
		if !strings.Contains(g, "github.com/FrankoonG/rendr/v2.") && !strings.Contains(g, "github.com/FrankoonG/rendr/v2/internal/") {
			continue
		}
		if strings.Contains(g, "rendr/v2/rendrtest.") || strings.Contains(g, "rendr/v2_test.") {
			continue // the links' pumps and this test's goroutines
		}
		ours++
		if strings.Contains(g, "internal/session.(*actor).run") {
			actors++
		}
	}
	return ours, actors
}
