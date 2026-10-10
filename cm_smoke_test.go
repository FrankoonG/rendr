package rendr_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The checkpoint C-M smoke (M3 design §A14.3 row I2): rendr mux between
// two Runtimes over two rendrtest Links, in a synctest bubble.
//
// TestMuxSmoke_CM: one Peer with two stream factories (default Props: both
// share their carriers) carries 8 selector, 4 bond and 4 race stream
// sessions and 4 packet sessions (selector, bond, race, selector) for 60
// virtual seconds, while every 10 s the Link of a or b is killed in turn
// (Link.Kill closes both ends of every carrier on it: the shared trunks of
// that factory with all their views, and the probe carrier). A stream
// trunk carries sessions of one kind (KINDSPLIT), so each Link carries two
// shared trunks: one for the stream sessions, one for the packet sessions.
// Beside them a
// churn of 200 short stream sessions (selector, bond, race in turn), one
// started every 300 ms, each moving 16 KiB each way, opens and closes on
// the shared trunks.
//
// Stimulus: every kill ended a session carrier of its Link (Session.Killed)
// and the dialer saw CarrierDown events. Load and integrity: every stream
// session's bytes, paced over the 60 s in both directions, arrive up to
// io.EOF with matching SHA-256 sums and PRNG content; every packet
// session's datagrams are verified (no corrupt, resized or application-
// duplicated datagram; losses only near a kill or counted; race ≤ 1 %);
// every churn session's exchange verifies. Counters: TxBytes, AckedBytes
// and DeliveredBytes exact in both directions (race copies counted once,
// M3-D35); PacketCounters add up. rendr mux: ≤ 1 dial per factory and
// session kind per kill — the session carriers a Link ever carried are at
// most 2 × (1 + the kills of that Link) (the pool's coalescing, M3-D18,
// per session kind) —; Status.Mux on both Runtimes counts the live trunks
// (two per Link, one per session kind) and as many views as the
// sessions hold live carriers, and every live carrier reports Shared equal
// to the views of its trunk (M3-D49); fast paths were taken. After every
// session closed, the trunks close at their last view (M3-D20: Status.Mux
// zero on both Runtimes and every session carrier of both Links closed
// before Runtime.Close). Runtime.Close then leaves nothing (crRuntimeEmpty,
// the session registry back at its baseline, and the bubble ends with no
// goroutine).
func TestMuxSmoke_CM(t *testing.T) {
	cfg := cmConfig{up: 4 << 20, back: 1 << 20, rate: 1000, rateBack: 200, churnBytes: 16 << 10}
	if loopbackRace {
		// The same timeline at a smaller size (R2-37).
		cfg = cmConfig{up: 1 << 20, back: 256 << 10, rate: 250, rateBack: 50, churnBytes: 4 << 10}
	}
	synctest.Test(t, func(t *testing.T) { runMuxSmoke(t, cfg) })
}

// cmConfig sizes the C-M smoke.
type cmConfig struct {
	up, back       int64 // stream bytes per session, dialer → passive and back
	rate, rateBack int   // packet datagrams per second per session, each way
	churnBytes     int64 // bytes each way per churn session
}

const (
	cmDuration = 60 * time.Second
	cmEvery    = 10 * time.Second
	cmChurn    = 200
	cmChurnGap = 300 * time.Millisecond
)

// cmStreamModes and cmPacketModes are the long sessions' modes.
var (
	cmStreamModes = []rendr.Mode{
		rendr.ModeSelector, rendr.ModeSelector, rendr.ModeSelector, rendr.ModeSelector,
		rendr.ModeSelector, rendr.ModeSelector, rendr.ModeSelector, rendr.ModeSelector,
		rendr.ModeBond, rendr.ModeBond, rendr.ModeBond, rendr.ModeBond,
		rendr.ModeRace, rendr.ModeRace, rendr.ModeRace, rendr.ModeRace,
	}
	cmPacketModes = []rendr.Mode{rendr.ModeSelector, rendr.ModeBond, rendr.ModeRace, rendr.ModeSelector}
)

// cmPassive routes the passive's accepted sessions by their metadata.
type cmPassive struct {
	mu      sync.Mutex
	streams map[string]chan *rendr.Conn
	packets map[string]chan *rendr.PacketConn
}

func (cp *cmPassive) stream(key string) chan *rendr.Conn {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	ch, ok := cp.streams[key]
	if !ok {
		ch = make(chan *rendr.Conn, 1)
		cp.streams[key] = ch
	}
	return ch
}

func (cp *cmPassive) packet(key string) chan *rendr.PacketConn {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	ch, ok := cp.packets[key]
	if !ok {
		ch = make(chan *rendr.PacketConn, 1)
		cp.packets[key] = ch
	}
	return ch
}

// cmPace writes n bytes of PRNG(seed) on c in equal chunks every 100 ms
// over d (the last chunk takes the rest), hashing them into h, then
// half-closes c.
func cmPace(c *rendr.Conn, n int64, seed uint64, d time.Duration, h hash.Hash) error {
	ticks := int64(d / (100 * time.Millisecond))
	chunk := n / ticks
	src := io.TeeReader(io.LimitReader(rendrtest.PRNG(seed), n), h)
	start := time.Now()
	sent := int64(0)
	for k := int64(1); sent < n; k++ {
		m := chunk
		if k >= ticks {
			m = n - sent
		}
		w, err := io.CopyN(struct{ io.Writer }{c}, src, m)
		sent += w
		if err != nil {
			return fmt.Errorf("after %d of %d bytes: %w", sent, n, err)
		}
		time.Sleep(time.Until(start.Add(time.Duration(k) * 100 * time.Millisecond)))
	}
	return c.CloseWrite()
}

// cmRead verifies n bytes of PRNG(seed) on c up to io.EOF, hashing what it
// read into h.
func cmRead(c *rendr.Conn, n int64, seed uint64, h hash.Hash) error {
	return rendrtest.NewVerifier(seed, n).ReadAll(io.TeeReader(c, h))
}

// cmLiveViews counts, per carrier ID, the live carriers (not dead) the
// given session statuses hold, and checks that each reports Shared equal
// to that count. It returns the per-ID counts and a mismatch, if any.
func cmLiveViews(sts []rendr.SessionStatus) (map[rendr.CarrierID]int, string) {
	views := map[rendr.CarrierID]int{}
	shared := map[rendr.CarrierID][]int{}
	for _, st := range sts {
		for _, cs := range st.Carriers {
			if cs.State == rendr.CarrierDead {
				continue
			}
			views[cs.ID]++
			shared[cs.ID] = append(shared[cs.ID], cs.Shared)
		}
	}
	for id, n := range views {
		for _, s := range shared[id] {
			if s != n {
				return views, fmt.Sprintf("carrier %v: %d session views, a view reports Shared %d", id, n, s)
			}
		}
	}
	return views, ""
}

// cmMuxIdentity checks Status.Mux of rt against the live carriers of its
// sessions: Carriers = the distinct live carrier IDs, Views = their sum,
// Shared = the views of each carrier; "" when every identity holds.
func cmMuxIdentity(rt *rendr.Runtime, sts []rendr.SessionStatus) string {
	views, bad := cmLiveViews(sts)
	if bad != "" {
		return bad
	}
	sum := 0
	for _, n := range views {
		sum += n
	}
	if m := rt.Status().Mux; m.Carriers != len(views) || m.Views != sum {
		return fmt.Sprintf("Status.Mux %+v; the sessions hold %d views on %d carriers %v", m, sum, len(views), views)
	}
	return ""
}

// cmSessionCarriers counts a Link's carriers that carried a session (their
// first frame was an OPEN or a JOIN) and those of them still open.
func cmSessionCarriers(l *rendrtest.Link) (all, open int) {
	for _, c := range l.Carriers() {
		if c.Session {
			all++
			if !c.Closed {
				open++
			}
		}
	}
	return all, open
}

func runMuxSmoke(t *testing.T, cfg cmConfig) {
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
	for i, name := range []string{"a", "b"} {
		l := rendrtest.NewLink(rendrtest.LinkConfig{Name: name, Accept: ln.Handle})
		l.SetDelay(time.Duration(10+2*i)*time.Millisecond, 0)
		links = append(links, l)
		carriers = append(carriers, rendr.StreamCarrier{Name: name, Dial: l.Dial})
	}
	peer, err := d.NewPeer(rendr.PeerConfig{Carriers: carriers})
	if err != nil {
		t.Fatal(err)
	}

	// The passive confirms everything and hands each session to the
	// goroutine that waits for its metadata.
	cp := &cmPassive{streams: map[string]chan *rendr.Conn{}, packets: map[string]chan *rendr.PacketConn{}}
	var acceptors sync.WaitGroup
	acceptors.Go(func() {
		for {
			pend, err := ln.Accept(context.Background())
			if err != nil {
				return // the Listener closed
			}
			c, err := pend.Confirm()
			if err != nil {
				t.Errorf("Confirm %q: %v", pend.Metadata(), err)
				continue
			}
			cp.stream(string(pend.Metadata())) <- c
		}
	})
	acceptors.Go(func() {
		for {
			pend, err := ln.AcceptPacket(context.Background())
			if err != nil {
				return
			}
			c, err := pend.Confirm()
			if err != nil {
				t.Errorf("Confirm %q: %v", pend.Metadata(), err)
				continue
			}
			cp.packet(string(pend.Metadata())) <- c
		}
	})

	// The long sessions.
	ns, np := len(cmStreamModes), len(cmPacketModes)
	sd, sp := make([]*rendr.Conn, ns), make([]*rendr.Conn, ns)
	pd, pp := make([]*rendr.PacketConn, np), make([]*rendr.PacketConn, np)
	var opens sync.WaitGroup
	for i, mode := range cmStreamModes {
		opens.Go(func() {
			key := "S" + strconv.Itoa(i)
			c, err := peer.Dial(context.Background(), rendr.DialOptions{Mode: mode, Metadata: []byte(key)})
			if err != nil {
				t.Errorf("Dial %s (%v): %v", key, mode, err)
				return
			}
			sd[i], sp[i] = c, <-cp.stream(key)
		})
	}
	for i, mode := range cmPacketModes {
		opens.Go(func() {
			key := "P" + strconv.Itoa(i)
			c, err := peer.DialPacket(context.Background(), rendr.DialOptions{Mode: mode, Metadata: []byte(key)})
			if err != nil {
				t.Errorf("DialPacket %s (%v): %v", key, mode, err)
				return
			}
			pd[i], pp[i] = c, <-cp.packet(key)
		})
	}
	opens.Wait()
	if t.Failed() {
		t.FailNow()
	}
	// Bond and race sessions hold a member on each trunk before the run.
	crUntil(t, 10*time.Second, "two members of every bond and race session", func() bool {
		for i, mode := range cmStreamModes {
			if mode != rendr.ModeSelector && crMembers(sd[i].Status(), rendr.CarrierMember) < 2 {
				return false
			}
		}
		for i, mode := range cmPacketModes {
			if mode != rendr.ModeSelector && len(liveCarriers(pd[i])) < 2 {
				return false
			}
		}
		return true
	})
	statuses := func(dialer bool) []rendr.SessionStatus {
		var out []rendr.SessionStatus
		for i := range ns {
			if dialer {
				out = append(out, sd[i].Status())
			} else {
				out = append(out, sp[i].Status())
			}
		}
		for i := range np {
			if dialer {
				out = append(out, pd[i].Status())
			} else {
				out = append(out, pp[i].Status())
			}
		}
		return out
	}
	// identities checks Status.Mux on both Runtimes against the sessions'
	// live carriers, and one shared trunk per Link and session kind
	// (KINDSPLIT): the live trunks are exactly the (Link, kind) pairs the
	// dialer's sessions hold live carriers on — streamLinks of them for the
	// stream sessions, both Links for the packet sessions.
	identities := func(when string, streamLinks int) {
		t.Helper()
		type linkKind struct {
			link   string
			packet bool
		}
		trunks := func() string {
			pairs := map[linkKind]bool{}
			for i, st := range statuses(true) {
				for _, cs := range st.Carriers {
					if cs.State != rendr.CarrierDead {
						pairs[linkKind{cs.Name, i >= ns}] = true
					}
				}
			}
			nStream, nPacket := 0, 0
			for k := range pairs {
				if k.packet {
					nPacket++
				} else {
					nStream++
				}
			}
			if dm, pm := d.Status().Mux, p.Status().Mux; nStream != streamLinks || nPacket != 2 || dm.Carriers != len(pairs) || pm.Carriers != len(pairs) {
				return fmt.Sprintf("dialer %+v, passive %+v; the sessions hold live carriers on %d Links (stream sessions) and %d (packet sessions), want %d and 2, with one shared trunk per Link and session kind", dm, pm, nStream, nPacket, streamLinks)
			}
			return ""
		}
		var why string
		for deadline := time.Now().Add(10 * time.Second); ; {
			why = cmMuxIdentity(d, statuses(true))
			if why == "" {
				why = cmMuxIdentity(p, statuses(false))
			}
			if why == "" {
				why = trunks()
			}
			if why == "" || time.Now().After(deadline) {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if why != "" {
			t.Fatalf("Status.Mux identities %s: %s", when, why)
		}
	}
	identities("before the run", 2)
	for i, l := range links {
		if all, _ := cmSessionCarriers(l); all != 2 {
			t.Fatalf("Link %d carried %d session carriers for %d sessions, want 2 shared trunks (one per session kind)", i, all, ns+np)
		}
	}

	// Traffic: the stream sessions both ways, paced over the run.
	start := time.Now()
	errs := make(chan error, 4*ns+2*cmChurn)
	var streams sync.WaitGroup
	sums := make([][4][]byte, ns) // up sent, up read, back sent, back read
	for i := range ns {
		streams.Go(func() {
			var hs [4]hash.Hash
			for k := range hs {
				hs[k] = sha256.New()
			}
			var wg sync.WaitGroup
			wg.Go(func() {
				errs <- wrapErr(fmt.Sprintf("S%d up write", i), cmPace(sd[i], cfg.up, uint64(100+i), cmDuration, hs[0]))
			})
			wg.Go(func() { errs <- wrapErr(fmt.Sprintf("S%d up read", i), cmRead(sp[i], cfg.up, uint64(100+i), hs[1])) })
			wg.Go(func() {
				errs <- wrapErr(fmt.Sprintf("S%d back write", i), cmPace(sp[i], cfg.back, uint64(200+i), cmDuration, hs[2]))
			})
			wg.Go(func() {
				errs <- wrapErr(fmt.Sprintf("S%d back read", i), cmRead(sd[i], cfg.back, uint64(200+i), hs[3]))
			})
			wg.Wait()
			for k := range hs {
				sums[i][k] = hs[k].Sum(nil)
			}
		})
	}
	// The packet sessions.
	ups, downsP := make([]*smokeSide, np), make([]*smokeSide, np)
	var gens, preaders sync.WaitGroup
	stop := make(chan struct{})
	for i := range np {
		ups[i] = &smokeSide{v: rendrtest.NewPacketVerifier(uint64(300 + i))}
		downsP[i] = &smokeSide{v: rendrtest.NewPacketVerifier(uint64(400 + i))}
		gens.Add(2)
		preaders.Add(2)
		go ups[i].generate(pd[i], uint64(300+i), cfg.rate, stop, &gens)
		go downsP[i].generate(pp[i], uint64(400+i), cfg.rateBack, stop, &gens)
		go ups[i].receive(pp[i], &preaders)
		go downsP[i].receive(pd[i], &preaders)
	}
	// The churn.
	var churned, churnFast atomic.Int64
	var churn sync.WaitGroup
	churn.Go(func() {
		var each sync.WaitGroup
		for j := range cmChurn {
			time.Sleep(time.Until(start.Add(time.Duration(j) * cmChurnGap)))
			each.Go(func() {
				if err := cmChurnOne(peer, cp, j, cfg.churnBytes); err != nil {
					errs <- fmt.Errorf("churn %d: %w", j, err)
					return
				}
				churned.Add(1)
			})
		}
		each.Wait()
		churnFast.Store(int64(d.Status().Mux.FastPaths))
	})

	// A kill every 10 s, Links a and b in turn.
	var kills []time.Duration
	killsOf := make([]int, len(links))
	for k := 1; time.Duration(k)*cmEvery < cmDuration; k++ {
		time.Sleep(time.Until(start.Add(time.Duration(k) * cmEvery)))
		v := (k - 1) % 2
		before := links[v].Stats().Session.Killed
		at := time.Since(start)
		links[v].Kill()
		if links[v].Stats().Session.Killed > before {
			kills = append(kills, at)
			killsOf[v]++
		}
	}
	time.Sleep(time.Until(start.Add(cmDuration)))
	close(stop)
	gens.Wait()
	streams.Wait()
	churn.Wait()
	took := time.Since(start)
	time.Sleep(2 * time.Second) // drain the packet sessions both ways
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	if t.Failed() {
		t.FailNow()
	}

	// Stimulus.
	if len(kills) != int(cmDuration/cmEvery)-1 {
		t.Errorf("stimulus: %d kills ended a session carrier, want %d", len(kills), int(cmDuration/cmEvery)-1)
	}
	if got := downs.Load(); got < int64(len(kills)) {
		t.Errorf("stimulus: %d CarrierDown events for %d kills", got, len(kills))
	}
	// ≤ 1 dial per factory and session kind per kill. The bound counts per
	// Link, not per kind: a Link's log cannot tell a JOIN's kind (its
	// payload does not carry it). It is still tight per kind here: the
	// identities before the run require both kinds' trunks on every Link,
	// the stream sessions pace until cmDuration and the packet sessions run
	// until stop, and every kill comes before cmDuration, so each kill ends
	// one trunk of each kind and each kind is owed at most one redial. The
	// bound has slack for a double dial of one kind only after a kill at
	// which the other kind did not redial on that Link; the root-level
	// per-kind rows (internal/carrier TestPoolKindSplitCoalescing,
	// internal/scenario/mux TestMuxMixedKinds) pin one dial per kind.
	for i, l := range links {
		all, _ := cmSessionCarriers(l)
		if all > 2*(1+killsOf[i]) {
			t.Errorf("Link %d carried %d session carriers with %d kills, want ≤ 2 × (1 + %d) (one dial per factory and session kind per kill)", i, all, killsOf[i], killsOf[i])
		}
	}
	if churned.Load() != cmChurn {
		t.Errorf("%d of %d churn sessions completed", churned.Load(), cmChurn)
	}
	// The ACKs of the last bytes may still be on their way.
	crUntil(t, 10*time.Second, "the last ACKs", func() bool {
		for i := range ns {
			if sd[i].Status().AckedBytes != uint64(cfg.up) || sp[i].Status().AckedBytes != uint64(cfg.back) {
				return false
			}
		}
		return true
	})
	// The stream sessions ended (both directions reached io.EOF): their
	// trunks closed at their last view, the packet sessions' remain.
	identities("after the run", 0)

	// Stream counters and SHA sums.
	for i, mode := range cmStreamModes {
		ds, ps := sd[i].Status(), sp[i].Status()
		if ds.TxBytes != uint64(cfg.up) || ds.AckedBytes != uint64(cfg.up) || ps.DeliveredBytes != uint64(cfg.up) {
			t.Errorf("S%d (%v) dialer → passive: TxBytes %d, AckedBytes %d, DeliveredBytes %d, want %d each", i, mode, ds.TxBytes, ds.AckedBytes, ps.DeliveredBytes, cfg.up)
		}
		if ps.TxBytes != uint64(cfg.back) || ps.AckedBytes != uint64(cfg.back) || ds.DeliveredBytes != uint64(cfg.back) {
			t.Errorf("S%d (%v) passive → dialer: TxBytes %d, AckedBytes %d, DeliveredBytes %d, want %d each", i, mode, ps.TxBytes, ps.AckedBytes, ds.DeliveredBytes, cfg.back)
		}
		if !bytes.Equal(sums[i][0], sums[i][1]) || !bytes.Equal(sums[i][2], sums[i][3]) {
			t.Errorf("S%d (%v): SHA-256 up %x / %x, back %x / %x", i, mode, sums[i][0], sums[i][1], sums[i][2], sums[i][3])
		}
		switch {
		case mode == rendr.ModeRace && ds.Race.CopyBytes == 0:
			t.Errorf("S%d race: the dialer placed no copy bytes", i)
		case mode != rendr.ModeRace && (ds.Race != rendr.RaceCounters{} || ps.Race != rendr.RaceCounters{}):
			t.Errorf("S%d (%v): race counters %+v and %+v, want zero", i, mode, ds.Race, ps.Race)
		}
		if ds.Mode != mode || ps.Mode != mode {
			t.Errorf("S%d: modes %v and %v, want %v", i, ds.Mode, ps.Mode, mode)
		}
	}
	// Packet sessions: close the dialer ends (the passive readers end at
	// io.EOF, the dialer's at its own Close), then judge each direction.
	pstat := make([][2]rendr.SessionStatus, np)
	for i := range np {
		if a, b := pd[i].Status(), pp[i].Status(); a.Err != nil || b.Err != nil {
			t.Errorf("P%d failed before its Close: dialer %v, passive %v", i, a.Err, b.Err)
		}
		pd[i].Close()
		waitDone(t, pd[i].Done(), "a packet dialer session")
	}
	preaders.Wait()
	for i := range np {
		pp[i].Close()
		waitDone(t, pp[i].Done(), "a packet passive session")
		pstat[i] = [2]rendr.SessionStatus{pd[i].Status(), pp[i].Status()}
	}
	for i, mode := range cmPacketModes {
		ds, ps := pstat[i][0], pstat[i][1]
		for _, x := range []struct {
			name   string
			s      *smokeSide
			rate   int
			eof    error
			tx, rx rendr.SessionStatus
		}{
			{fmt.Sprintf("P%d (%v) dialer → passive", i, mode), ups[i], cfg.rate, io.EOF, ds, ps},
			{fmt.Sprintf("P%d (%v) passive → dialer", i, mode), downsP[i], cfg.rateBack, net.ErrClosed, ps, ds},
		} {
			cmJudgePackets(t, x.name, mode, x.s, x.rate, x.eof, x.tx, x.rx, kills)
		}
	}
	t.Logf("%v: kills at %v (a %d, b %d), CarrierDown %d; churn %d sessions; dialer Mux %+v; session carriers a %v b %v",
		took.Round(time.Millisecond), kills, killsOf[0], killsOf[1], downs.Load(), churned.Load(), d.Status().Mux,
		fmt.Sprint(cmSessionCarriers(links[0])), fmt.Sprint(cmSessionCarriers(links[1])))
	if fp := churnFast.Load(); fp == 0 {
		t.Errorf("no attempt took a fast path (Status.Mux.FastPaths 0 after the churn)")
	}

	// Close every stream session; the trunks then close at their last view
	// (before Peer.Close and Runtime.Close).
	var closing sync.WaitGroup
	for i := range ns {
		closing.Go(func() {
			sd[i].Close()
			sp[i].Close()
			for _, c := range []*rendr.Conn{sd[i], sp[i]} {
				select {
				case <-c.Done():
				case <-time.After(30 * time.Second):
					t.Errorf("S%d not done 30 s after Close: %+v", i, c.Status())
				}
				if st := c.Status(); st.State != rendr.StateEnded || st.Err != io.EOF {
					t.Errorf("S%d end: state %v, err %v, want io.EOF", i, st.State, st.Err)
				}
			}
		})
	}
	closing.Wait()
	crUntil(t, 10*time.Second, "the trunks closed at their last view", func() bool {
		for _, rt := range []*rendr.Runtime{d, p} {
			if m := rt.Status().Mux; m.Carriers != 0 || m.Views != 0 {
				return false
			}
		}
		for _, l := range links {
			if _, open := cmSessionCarriers(l); open != 0 {
				return false
			}
		}
		return true
	})

	peer.Close()
	d.Close()
	p.Close()
	acceptors.Wait()
	for _, l := range links {
		l.Close()
	}
	crRuntimeEmpty(t, d)
	crRuntimeEmpty(t, p)
	for _, rt := range []*rendr.Runtime{d, p} {
		if m := rt.Status().Mux; m.Carriers != 0 || m.Views != 0 {
			t.Errorf("Status.Mux after Runtime.Close: %+v", m)
		}
	}
	crRegistryBack(t, live0, parked0)
}

// wrapErr names err (nil stays nil).
func wrapErr(what string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", what, err)
}

// cmChurnOne opens churn session j (selector, bond, race in turn), moves n
// bytes each way, verified, and closes both ends.
func cmChurnOne(peer *rendr.Peer, cp *cmPassive, j int, n int64) error {
	mode := []rendr.Mode{rendr.ModeSelector, rendr.ModeBond, rendr.ModeRace}[j%3]
	key := "C" + strconv.Itoa(j)
	dc, err := peer.Dial(context.Background(), rendr.DialOptions{Mode: mode, Metadata: []byte(key)})
	if err != nil {
		return fmt.Errorf("Dial (%v): %w", mode, err)
	}
	pc := <-cp.stream(key)
	errs := make(chan error, 4)
	var wg sync.WaitGroup
	wg.Go(func() { errs <- crPump(dc, n, uint64(1000+j)) })
	wg.Go(func() { errs <- rendrtest.NewVerifier(uint64(1000+j), n).ReadAll(pc) })
	wg.Go(func() { errs <- crPump(pc, n, uint64(2000+j)) })
	wg.Go(func() { errs <- rendrtest.NewVerifier(uint64(2000+j), n).ReadAll(dc) })
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			return fmt.Errorf("%v: %w", mode, err)
		}
	}
	dc.Close()
	pc.Close()
	for _, c := range []*rendr.Conn{dc, pc} {
		select {
		case <-c.Done():
		case <-time.After(30 * time.Second):
			return fmt.Errorf("%v: not done 30 s after Close: %+v", mode, c.Status())
		}
		if st := c.Status(); st.Err != io.EOF {
			return fmt.Errorf("%v: ended with %v, want io.EOF", mode, st.Err)
		}
	}
	return nil
}

// cmJudgePackets applies the C-A smoke's checks (runSmoke) to one
// direction of a packet session: no corrupt, resized or application-
// duplicated datagram; the reader ended with eof; at least 90 % of the
// rate arrived; losses away from every kill are counted queue drops; the
// sender's PacketCounters add up and the receiver's Received is what it
// read plus its queue drops; race loses ≤ 1 % and its receiver counts the
// members' copies as Duplicates.
func cmJudgePackets(t *testing.T, name string, mode rendr.Mode, s *smokeSide, rate int, eof error, tx, rx rendr.SessionStatus, kills []time.Duration) {
	t.Helper()
	const lossWin = 200 * time.Millisecond
	if e := s.verr.Load(); e != nil {
		t.Errorf("%s: %v", name, e)
	}
	if !errors.Is(s.readErr, eof) {
		t.Errorf("%s: the reader ended with %v, want %v", name, s.readErr, eof)
	}
	res := s.v.Result()
	sent := s.accepted.Load()
	if res.Corrupt != 0 || res.BadSize != 0 || res.Duplicates != 0 {
		t.Errorf("%s: corrupt %d, resized %d, duplicates %d", name, res.Corrupt, res.BadSize, res.Duplicates)
	}
	tp, rp := tx.Packet, rx.Packet
	if tp == nil || rp == nil {
		t.Fatalf("%s: no PacketCounters", name)
	}
	if res.Unique*10 < sent*9 {
		t.Errorf("load: %s received %d unique of %d datagrams", name, res.Unique, sent)
	}
	var away uint64
	for _, m := range res.Missing {
		for seq := m.From; seq <= m.To; seq++ {
			at := time.Duration(float64(seq) / float64(rate) * float64(time.Second))
			if !nearKill(at, kills, 0, lossWin) {
				away++
			}
		}
	}
	if counted := tp.DropQueue + tp.DropAge + tp.DropNoPath + tp.DropTooLarge + rp.DropRecvQueue; away > counted {
		t.Errorf("%s: %d datagrams lost away from every kill %v, only %d counted (missing %v)", name, away, kills, counted, res.Missing)
	}
	if sum := tp.Sent + tp.DropQueue + tp.DropAge + tp.DropNoPath + tp.DropTooLarge; sum != sent {
		t.Errorf("%s: accepted %d ≠ Sent + send-side drops %d (%+v)", name, sent, sum, *tp)
	}
	if got := s.read.Load() + rp.DropRecvQueue; rp.Received != got {
		t.Errorf("%s: Received %d ≠ read %d + DropRecvQueue %d", name, rp.Received, s.read.Load(), rp.DropRecvQueue)
	}
	lost := sent - res.Unique
	if mode == rendr.ModeRace {
		if lost*100 > sent {
			t.Errorf("%s: race lost %d of %d datagrams, want ≤ 1 %%", name, lost, sent)
		}
		if tx.Race.Copies == 0 || rp.Duplicates*10 < rp.Received*9 {
			t.Errorf("%s: race copies %d, receiver Duplicates %d of Received %d", name, tx.Race.Copies, rp.Duplicates, rp.Received)
		}
	} else if rp.Duplicates != 0 {
		t.Errorf("%s: receiver Duplicates %d outside race", name, rp.Duplicates)
	}
	t.Logf("%s: accepted %d, unique %d, lost %d (%.3f%%), missing ranges %d", name, sent, res.Unique, lost,
		100*float64(lost)/float64(max(sent, 1)), len(res.Missing))
}
