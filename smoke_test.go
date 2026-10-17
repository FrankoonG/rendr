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
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/carrier/udp"
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

// The checkpoint C-R smoke (M3 design §A14.3 row I1): race, the parked
// actors and the M3 root surface between two Runtimes over rendrtest
// links, in synctest bubbles.
//
//   - TestStreamSmoke_CR: one stream session per mode (selector, bond and
//     race) moves 64 MiB (16 MiB under -race, the same timeline) over two
//     shaped Links while a carrier of the session is killed every 10 s.
//   - TestPacketRaceSmoke_CR: a packet race session at 10,000 datagrams
//     per second for 60 virtual seconds (1,000 for 30 s under -race) over the
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
// at 10,000 datagrams per second and 1,000 back (30 s at 400 each way
// under -race, there over the DatagramHub only: raceSmokeNets), a
// member's carrier closed every 10 s in turn. On top of runSmoke's
// checks (no corrupt, resized or application-duplicated datagram, losses
// only near kills or counted, the counters adding up, nothing left after
// Close), race delivers at least 99 % of what was accepted in each
// direction, the receiver counts the members' copies as Duplicates, and
// the sender's copies as Race.Copies.
func TestPacketRaceSmoke_CR(t *testing.T) {
	rate, back, duration := 10000, 1000, 60*time.Second
	if loopbackRace {
		// R1-23's first lever (R2-37): the race lane runs 30 virtual
		// seconds (two kills) at 400 datagrams per second each way (1,000
		// and 1,000 back until I3 of M4, when the race-unit passes
		// exceeded 300 s), with the same criteria.
		rate, back, duration = 400, 400, 30*time.Second
	}
	for _, tr := range raceSmokeNets() {
		t.Run(tr.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				live0, parked0 := testhooks.LiveSessions.Load(), testhooks.ParkedSessions.Load()
				n := tr.net()
				defer n.close()
				runSmoke(t, n, smokeRun{mode: rendr.ModeRace, duration: duration, every: 10 * time.Second,
					rate: rate, back: back, lossWin: 200 * time.Millisecond}, rendr.Config{})
				crRegistryBack(t, live0, parked0)
			})
		})
	}
}

// raceSmokeNets are TestPacketRaceSmoke_CR's subtests: the DatagramLink and
// the DatagramHub (smokeTransports). Under -race (R1-23 lever 1; the
// race-unit target of 270 s per pass, m5's prerc decision) the DatagramHub
// only, with the same criteria: the row's own rules — race's delivery,
// Duplicates and Race.Copies — are the mode's, the same on either
// transport, and TestPacketSmoke_CA's race subset runs each transport. The
// non-race lanes run both; TestRaceLaneSubtests checks the lists.
func raceSmokeNets() []smokeTransport {
	all := smokeTransports()
	if loopbackRace {
		return all[1:]
	}
	return all
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
	lossWin  time.Duration // a lost datagram was sent within this after a kill
	preWin   time.Duration // ... or within this before it (0: 50 ms)
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
	if r.mode != rendr.ModeSelector { // bond and race: both members
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
		at := time.Since(start) // the pre-command time (B0 F8)
		if victim >= 0 && n.kill(victim) {
			kills = append(kills, at)
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
		// -race a host stall can age one out: DropAge), never silent. Each
		// lost datagram is judged by its own send time (seq / rate), so a
		// range that starts at a kill does not excuse its tail.
		var away uint64
		var late time.Duration // the latest send time of a loss after its kill
		for _, m := range res.Missing {
			for seq := m.From; seq <= m.To; seq++ {
				at := time.Duration(float64(seq) / float64(x.rate) * float64(time.Second))
				if !nearKill(at, kills, r.preWin, r.lossWin) {
					away++
				} else if d := sinceKill(at, kills, r.lossWin); d > late {
					late = d
				}
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
		if rp.Received > tp.Sent || (rp.Duplicates != 0) != (r.mode == rendr.ModeRace) {
			t.Errorf("%s: Received %d of Sent %d, Duplicates %d", x.name, rp.Received, tp.Sent, rp.Duplicates)
		}
		if r.mode == rendr.ModeRace {
			// Race (M3-D32, M3-D35): every member carries every datagram,
			// so a member's death loses (almost) nothing; the receiver
			// counts the other members' copies as Duplicates (G3-race's
			// ≥ 0.9 × Received), the sender its extra placements as
			// Race.Copies.
			if lost*100 > x.sentSeqs {
				t.Errorf("%s: race lost %d of %d datagrams, want ≤ 1 %%", x.name, lost, x.sentSeqs)
			}
			if x.tx.Race.Copies == 0 || rp.Duplicates*10 < rp.Received*9 {
				t.Errorf("%s: race copies %d, receiver Duplicates %d of Received %d, want copies and Duplicates ≥ 0.9 × Received",
					x.name, x.tx.Race.Copies, rp.Duplicates, rp.Received)
			}
			t.Logf("%s: race copies %d, receiver duplicates %d (%.3f of Received)", x.name, x.tx.Race.Copies, rp.Duplicates,
				float64(rp.Duplicates)/float64(max(rp.Received, 1)))
		}
		t.Logf("%s: accepted %d, unique %d, lost %d (%.3f%%), missing ranges %d, latest loss %v after its kill, max gap %v; tx %+v; rx %+v",
			x.name, x.sentSeqs, res.Unique, lost, 100*float64(lost)/float64(max(x.sentSeqs, 1)), len(res.Missing), late, res.MaxGap, *tp, *rp)
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

// nearKill reports whether at lies in [k − pre, k + win] of a kill k
// (pre 0: 50 ms; a datagram sent just before the kill may be lost with
// its carrier).
func nearKill(at time.Duration, kills []time.Duration, pre, win time.Duration) bool {
	if pre == 0 {
		pre = 50 * time.Millisecond
	}
	for _, k := range kills {
		if at >= k-pre && at <= k+win {
			return true
		}
	}
	return false
}

// sinceKill returns at − k for a kill k with k ≤ at ≤ k + win (0: none).
func sinceKill(at time.Duration, kills []time.Duration, win time.Duration) time.Duration {
	for _, k := range kills {
		if k <= at && at <= k+win {
			return at - k
		}
	}
	return 0
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
// selector and bond, 60 virtual seconds each (30 under -race, and there two
// of the four subtests: smokeCACases).
func TestPacketSmoke_CA(t *testing.T) {
	rate, back, duration := 10000, 1000, 60*time.Second
	if loopbackRace {
		// R1-23's first lever (R2-37), as TestPacketRaceSmoke_CR: the race
		// lane runs 30 virtual seconds (two kills) at 400 datagrams per
		// second each way, with the same criteria (the root package's
		// Linux race time reached the 270-s lever line at M3's I2; 1,000
		// and 1,000 back until I3 of M4, when the race-unit passes
		// exceeded 300 s).
		rate, back, duration = 400, 400, 30*time.Second
	}
	for _, c := range smokeCACases() {
		t.Run(c.name(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				n := c.net()
				defer n.close()
				runSmoke(t, n, smokeRun{mode: c.mode, duration: duration, every: 10 * time.Second,
					rate: rate, back: back, lossWin: 200 * time.Millisecond}, rendr.Config{})
			})
		})
	}
}

// smokeCACase is one subtest of TestPacketSmoke_CA: a transport and a mode.
type smokeCACase struct {
	tr   smokeTransport
	mode rendr.Mode
}

func (c smokeCACase) name() string { return c.tr.name + "/" + c.mode.String() }

func (c smokeCACase) net() *smokeNet { return c.tr.net() }

// smokeCACases are TestPacketSmoke_CA's subtests: each transport in each
// mode. Under -race (R1-23 lever 1; the race-unit target of 270 s per
// pass, m5's prerc decision) DatagramLink/selector and DatagramHub/bond
// run, with the same criteria: each transport and each mode once (the
// row's rules are runSmoke's, the same for every pair). The non-race unit
// and sweep lanes run all four; TestRaceLaneSubtests checks the lists.
func smokeCACases() []smokeCACase {
	var all []smokeCACase
	for _, tr := range smokeTransports() {
		for _, mode := range []rendr.Mode{rendr.ModeSelector, rendr.ModeBond} {
			all = append(all, smokeCACase{tr, mode})
		}
	}
	if !loopbackRace {
		return all
	}
	return []smokeCACase{all[0], all[3]}
}

// smokeTransport is one in-memory transport of the packet smokes.
type smokeTransport struct {
	name string
	net  func() *smokeNet
}

// smokeTransports are the in-memory transports of the packet smokes: the
// DatagramLink (one datagram carrier per conn) and the DatagramHub (raw-UDP
// flows into the passive's FromPacketConn source).
func smokeTransports() []smokeTransport {
	return []smokeTransport{{"DatagramLink", smokeLinkNet}, {"DatagramHub", smokeHubNet}}
}

// TestPacketSmokeUDP_CA is the real-socket half over carrier/udp on
// loopback: 10 real seconds with a kill every 2 s per mode (a shortened
// timeline: the host runs no long real-time loads); 6 s (two kills) under
// the race detector (m3 R1-23's first lever, I3 of M4), with the same
// criteria.
func TestPacketSmokeUDP_CA(t *testing.T) {
	if testing.Short() {
		t.Skip("real-time smoke")
	}
	rate, duration := 10000, 10*time.Second
	if loopbackRace {
		rate, duration = 2000, 6*time.Second
	}
	pre, post := realLossWindows()
	for _, mode := range []rendr.Mode{rendr.ModeSelector, rendr.ModeBond} {
		t.Run(mode.String(), func(t *testing.T) {
			g0 := runtime.NumGoroutine()
			n := smokeUDPNet(t)
			runSmoke(t, n, smokeRun{mode: mode, duration: duration, every: 2 * time.Second,
				rate: rate, back: 1000, lossWin: post, preWin: pre}, rendr.Config{})
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

// The real-socket group of the root package (M2 design §A8.6; WP12): two
// Runtimes over carrier/udp on loopback, the passive on one listening
// socket through FromPacketConn, outside synctest bubbles. Each row is a
// leak oracle (rendrtest.AssertNoLeak, registered first so that it runs
// after every other cleanup) and uses runSmoke (above):
// stimulus (every kill ended a live carrier and raised a CarrierDown),
// load (≥ 90 % of the rate arrived) and integrity (every datagram's seq,
// size, CRC and body; no duplicate; losses only right after a kill or
// counted as queue drops; the §A7.2 identities on both ends), and nothing
// left after Runtime.Close.

// realLossWindows are the loss windows of a real-time smoke over
// carrier/udp: a lost datagram must have been sent in [T_k − pre,
// T_k + post] of a kill at T_k (M2 design B1.4, F8: ± 200 ms; the 50-ms
// pre-window of runSmoke's default is tighter). Under -race in real time
// the receiving reader can lag 100 ms and more, so datagrams that still
// sat unread in the killed socket were in flight on the dead carrier, and
// the passive's switch to the new carrier lags as much: both windows
// widen.
func realLossWindows() (pre, post time.Duration) {
	if loopbackRace {
		return 250 * time.Millisecond, 500 * time.Millisecond
	}
	return 0, 200 * time.Millisecond
}

// TestUDPEndToEnd: selector and bond, 10 s at 2,000 datagrams per second
// (1,000 back), one carrier closed under rendr at 5 s (an embedder-closed
// socket: transport_error at once); the session moves to a new carrier and
// keeps every datagram that was not in flight on the dead one. Under the
// race detector the timeline is 4 s with the kill at 2 s (m3 R1-23's
// first lever: 6 s with the kill at 3 s from I3 of M4 until I1 of M5,
// whose race-unit passes reached 306 s), in selector mode only
// (udpEndToEndModes), with the same criteria; the non-race lanes keep
// 10 s in both modes.
func TestUDPEndToEnd(t *testing.T) {
	pre, post := realLossWindows()
	duration, every := 10*time.Second, 5*time.Second
	if loopbackRace {
		duration, every = 4*time.Second, 2*time.Second
	}
	for _, mode := range udpEndToEndModes() {
		t.Run(mode.String(), func(t *testing.T) {
			t.Cleanup(rendrtest.AssertNoLeak(t))
			runSmoke(t, smokeUDPNet(t), smokeRun{mode: mode, duration: duration, every: every,
				rate: 2000, back: 1000, lossWin: post, preWin: pre}, rendr.Config{})
		})
	}
}

// TestPacketSmokeUDP60_CA is the 60-second real-UDP smoke of checkpoint
// C-A (integration 2, §2.4: TestPacketSmokeUDP_CA runs a shortened 10-s
// timeline): carrier/udp on loopback, selector and bond, 10,000 datagrams
// per second (2,000 under -race) and 1,000 back for 60 real seconds, a
// kill every 10 s (selector: the active carrier; bond: the members in
// turn). It is a long real-time load, so -short skips it; the pool lanes
// run it without -short.
//
// Under the race detector it runs 8 s (two kills, 3 s apart: in bond mode
// each member once; 30 s with kills 10 s apart until I3 of M4, 12 s with
// kills 4 s apart until I1 of M5), in bond mode only (smokeUDP60Modes),
// with the same criteria: the unit suite's -race lane has a 5-minute
// wall-clock budget (plan §9.0; m3 R1-23's first lever) and a required
// test must not skip there, while the 60-s timeline at full rate stays in
// the non-race lanes.
func TestPacketSmokeUDP60_CA(t *testing.T) {
	if testing.Short() {
		t.Skip("60-s real-time smoke")
	}
	rate, duration, every := 10000, 60*time.Second, 10*time.Second
	if loopbackRace {
		rate, duration, every = 2000, 8*time.Second, 3*time.Second
	}
	pre, post := realLossWindows()
	for _, mode := range smokeUDP60Modes() {
		t.Run(mode.String(), func(t *testing.T) {
			t.Cleanup(rendrtest.AssertNoLeak(t))
			runSmoke(t, smokeUDPNet(t), smokeRun{mode: mode, duration: duration, every: every,
				rate: rate, back: 1000, lossWin: post, preWin: pre}, rendr.Config{})
		})
	}
}

// udpEndToEndModes are TestUDPEndToEnd's subtests: selector and bond.
// Under -race (R1-23 lever 1; the race-unit target of 270 s per pass,
// m5's prerc decision) its timeline — 2,000 datagrams per second and
// 1,000 back over carrier/udp, a carrier closed under rendr — repeats
// TestPacketSmokeUDP_CA's race timeline (the same rates, a carrier closed
// every 2 s), which runs both modes, so it runs selector only, the mode
// whose kill is a migration of the session's one active carrier, with
// unchanged criteria. The non-race lanes run both; TestRaceLaneSubtests
// checks the lists.
func udpEndToEndModes() []rendr.Mode {
	if loopbackRace {
		return []rendr.Mode{rendr.ModeSelector}
	}
	return []rendr.Mode{rendr.ModeSelector, rendr.ModeBond}
}

// smokeUDP60Modes are TestPacketSmokeUDP60_CA's subtests: selector and
// bond. Under -race (R1-23 lever 1; the race-unit target of 270 s per
// pass, m5's prerc decision) its timeline — 2,000 datagrams per second
// over carrier/udp with two kills — repeats TestPacketSmokeUDP_CA's race
// timeline, which runs both modes, so it runs bond only, the mode whose
// two kills reach each member once, with unchanged criteria. The non-race
// lanes run both at 10,000 datagrams per second for 60 s;
// TestRaceLaneSubtests checks the lists.
func smokeUDP60Modes() []rendr.Mode {
	if loopbackRace {
		return []rendr.Mode{rendr.ModeBond}
	}
	return []rendr.Mode{rendr.ModeSelector, rendr.ModeBond}
}
