package mux

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"sort"
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

// The end paths of one cycle of TestMuxDetachAfterLocalViewEnd_R1_9: the
// ways a view of a shared trunk ends on either side (M3 design §A5.4,
// R1-9). The metadata's first byte names the path, which also tells the
// passive's acceptor what to do.
const (
	dcDialerClose  = iota // confirmed; the dialer closes first, the passive reads EOF
	dcPassiveClose        // confirmed; the passive closes first, the dialer reads EOF
	dcBothClose           // confirmed; both ends close at once
	dcReject              // the passive's Reject: a refusal as the view's first frame
	dcTimeout             // the passive never decides: its AcceptTimeout and the dialer's attempt deadline cross
	dcWithdraw            // the passive never decides; the Dial's context ends early (RST(AbortWithdrawn), or a handle gap)
	dcLateConfirm         // the passive confirms late, racing the Dial's context end
	dcPacket              // a packet session: confirmed, one datagram, closed by both
	dcPaths
)

var dcNames = [dcPaths]string{"dialer-close", "passive-close", "both-close", "reject", "accept-timeout",
	"withdraw", "late-confirm", "packet"}

// dcWeight is each path's share of the cycles: the crossing that killed
// G6's trunks takes three shares.
var dcWeight = [dcPaths]int{1, 1, 1, 1, 3, 1, 1, 1}

// dcAccept is the passive's AcceptTimeout and the dialer's DialTimeout (the
// bound of one dial attempt): as in G6, where both are 10 s, a dialer
// attempt that waits for an undecided session ends exactly when the
// passive's AcceptTimeout fires, so its DETACH reaches the passive at the
// virtual instant the passive's session places its CAPACITY refusal.
const dcAccept = 100 * time.Millisecond

// dcLong is the population of long sessions that stay open through the
// churn (G6's idle sessions): the trunks carry their views, in every
// mode, while the short sessions' views come and go beside them.
const dcLong = 32

// TestMuxDetachAfterLocalViewEnd_R1_9 (M3 design §A5.4, §A5.5, M3-D7,
// R1-9; DEFECT A of the regress case gold/G6-mixed-nat at pin 20cf3f5):
// 10,000 short sessions (2,000 under -race, R1-11) open and close on the
// shared trunks of two stream factories, at most 64 at once and one
// started every millisecond, beside 32 long sessions that stay open, so
// that the trunks carry views in every state while others end. Each cycle
// takes one end path (dcNames): the dialer, the passive or both close a
// confirmed session after a verified 64-byte exchange; the passive
// rejects; the passive never decides, so its AcceptTimeout refuses the
// view at the instant the dialer's attempt deadline abandons it (the
// dialer's DialTimeout equals the AcceptTimeout, 100 ms, as G6 runs both
// at 10 s: the dialer's DETACH reaches the passive as the passive's
// session places its CAPACITY refusal — the defect's crossing; three
// shares of the cycles); the Dial's context ends early (a withdrawn OPEN,
// also before its first frame was placed); the passive confirms late,
// racing the withdrawal; a packet session. Modes rotate over selector,
// race and bond, so race and bond members open and retire views on both
// trunks; after every quarter of the cycles one link kills its carriers
// (failover: the long sessions' views requeue, and the next views open on
// new trunks).
//
// PASS: no carrier of either Runtime ended with protocol_violation (the
// defect: the passive followed its refusal with a DETACH, and the dialer,
// which ends the handle at the refusal, killed the healthy trunk with
// "DETACH for an unknown handle", migrating every session on it); every
// cycle ended as its path allows (a confirmed session's exchange verified
// and both ends done; RejectError; ErrCapacity); the stimulus is proven:
// every path ran at least cycles/16 times; at least half of the
// accept-timeout cycles crossed — the passive session ended by its
// AcceptTimeout at the virtual instant the passive dispatched a dialer's
// DETACH; DETACH was placed and dispatched on both sides (AfterDetach);
// most views opened on a live trunk (FastPaths). Then both Runtimes close
// without leftovers. The crossing needs two Ps to interleave inside the
// passive's Fill: at -cpu 1 the scenario cannot fail without the fix
// (TestPassiveResponseCrossesPeerDetach_R1_9 is the deterministic row).
func TestMuxDetachAfterLocalViewEnd_R1_9(t *testing.T) {
	cycles := 10000
	if raceEnabled {
		cycles = 2000 // R1-11
	}
	synctest.Test(t, func(t *testing.T) { detachChurn(t, cycles) })
}

// dcWorld is the churn's two Runtimes, Listener, links and Peer (the
// shared kit's world confirms every session; this one decides per path).
type dcWorld struct {
	t        *testing.T
	d, p     *rendr.Runtime
	ln       *rendr.Listener
	links    []*rendrtest.Link
	dev, pev *eventLog
	peer     *rendr.Peer

	detach [2][2]atomic.Int64 // [side][sent]: AfterDetach calls
	dmu    sync.Mutex
	pdisp  map[int64]int  // virtual instants (ns) at which the passive dispatched a dialer's DETACH
	held   sync.WaitGroup // the acceptors and the passive halves
	mu     sync.Mutex
	viol   map[string]int // protocol_violation details of the sessions' rows
	pend   []any          // undecided pending sessions (until the Listener closes)
}

func detachChurn(t *testing.T, cycles int) {
	const inflight, gap = 64, time.Millisecond
	failoverEvery := cycles / 4 // three failovers, also at the race size
	w := &dcWorld{t: t, dev: &eventLog{}, pev: &eventLog{}, viol: map[string]int{}, pdisp: map[int64]int{}}
	live0, parked0 := testhooks.LiveSessions.Load(), testhooks.ParkedSessions.Load()
	var dov, pov testhooks.Overrides
	dov.Hooks = &testhooks.Hooks{AfterDetach: func(_, _ uint32, sent bool) { w.detach[0][b2i(sent)].Add(1) }}
	pov.Hooks = &testhooks.Hooks{AfterDetach: func(_, _ uint32, sent bool) {
		w.detach[1][b2i(sent)].Add(1)
		if !sent {
			w.dmu.Lock()
			w.pdisp[time.Now().UnixNano()]++
			w.dmu.Unlock()
		}
	}}
	dov.DialTimeout = dcAccept // G6: an attempt's bound equals the passive's AcceptTimeout
	w.d = newRuntime(t, rendr.Config{OnEvent: w.dev.add}, &dov)
	w.p = newRuntime(t, rendr.Config{OnEvent: w.pev.add}, &pov)
	ln, err := w.p.Listen(rendr.ListenConfig{AcceptTimeout: dcAccept, AcceptBacklog: 1024})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	w.ln = ln
	var cs []rendr.Carrier
	for i, oneWay := range []time.Duration{2 * time.Millisecond, 3 * time.Millisecond} {
		name := fmt.Sprintf("n%d", i+1)
		l := rendrtest.NewLink(rendrtest.LinkConfig{Name: name, Accept: ln.Handle})
		l.SetDelay(oneWay, 0)
		w.links = append(w.links, l)
		cs = append(cs, rendr.StreamCarrier{Name: name, Dial: l.Dial})
	}
	w.peer, err = w.d.NewPeer(rendr.PeerConfig{Carriers: cs})
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	w.held.Go(w.acceptStreams)
	w.held.Go(w.acceptPackets)
	shut := sync.OnceFunc(func() {
		w.peer.Close()
		w.d.Close()
		w.p.Close()
		w.held.Wait()
		for _, l := range w.links {
			l.Close()
		}
	})
	t.Cleanup(shut)

	rng := rand.New(rand.NewPCG(0x52, 0x19))
	modes := []rendr.Mode{rendr.ModeSelector, rendr.ModeSelector, rendr.ModeRace, rendr.ModeBond}
	var longs []*rendr.Conn
	for i := range dcLong {
		c, err := w.peer.Dial(context.Background(), rendr.DialOptions{Mode: modes[i%len(modes)], Metadata: []byte(fmt.Sprintf("z%d", i))})
		if err != nil {
			t.Fatalf("long session %d: %v", i, err)
		}
		longs = append(longs, c)
	}
	total := 0
	for _, n := range dcWeight {
		total += n
	}
	var ran [dcPaths]atomic.Int64
	sem := make(chan struct{}, inflight)
	var wg sync.WaitGroup
	errs := make(chan error, cycles)
	for i := range cycles {
		if i > 0 && i%failoverEvery == 0 {
			// Failover: one link kills its carriers; the long sessions'
			// views on its trunks requeue, and the race and bond ones rejoin
			// it on a new trunk. The churn resumes once they did, so that a
			// new trunk's first view is a long session's JOIN, answered at
			// once (an undecided session opening a trunk holds the sessions
			// coalesced on that dial until its AcceptTimeout, which equals
			// their attempt bound here).
			wg.Wait()
			l := w.links[(i/failoverEvery)%2]
			if n := l.Kill(); n == 0 {
				t.Fatalf("failover at cycle %d: link %s had no carrier to kill", i, l.Name())
			}
			waitFor(t, 10*time.Second, "the long sessions rejoined link "+l.Name(), func() bool {
				_, open := sessionCarriers(l)
				return open > 0
			})
		}
		sem <- struct{}{}
		path, r := 0, rng.IntN(total)
		for r >= dcWeight[path] {
			r -= dcWeight[path]
			path++
		}
		mode := modes[rng.IntN(len(modes))]
		within := time.Duration(rng.IntN(4000)+500) * time.Microsecond // a withdrawal's Dial context
		if path == dcLateConfirm {
			within = time.Duration(rng.IntN(8000)+2000) * time.Microsecond
		}
		key := fmt.Sprintf("%c%d", dcCode(path), i)
		wg.Go(func() {
			defer func() { <-sem }()
			if err := w.cycle(key, path, mode, within); err != nil {
				errs <- fmt.Errorf("cycle %s (%s, %v): %w", key, dcNames[path], mode, err)
				return
			}
			ran[path].Add(1)
		})
		time.Sleep(gap)
	}
	wg.Wait()
	for _, c := range longs {
		w.record(0, c)
		c.Close()
		if err := waitDone(c.Done(), "long session"); err != nil {
			t.Error(err)
		}
	}
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	w.noViolation()
	if t.Failed() {
		t.FailNow()
	}
	var load strings.Builder
	for p := range dcPaths {
		fmt.Fprintf(&load, " %s=%d", dcNames[p], ran[p].Load())
		if n := ran[p].Load(); n < int64(cycles/16) {
			t.Errorf("path %s ran %d times, want ≥ %d", dcNames[p], n, cycles/16)
		}
	}
	// The crossing: a passive session that ended by its AcceptTimeout at
	// the virtual instant the passive dispatched a dialer's DETACH.
	capEnds, crossed := 0, 0
	w.dmu.Lock()
	for _, ev := range w.pev.of(rendr.EventSessionEnd) {
		if errors.Is(ev.Err, rendr.ErrCapacity) {
			capEnds++
			if w.pdisp[ev.Time.UnixNano()] > 0 {
				crossed++
			}
		}
	}
	w.dmu.Unlock()
	if n := ran[dcTimeout].Load(); int64(crossed) < n/2 {
		t.Errorf("%d of %d accept-timeout cycles crossed a dialer's DETACH (%d sessions ended by AcceptTimeout), want ≥ half",
			crossed, n, capEnds)
	}
	for i := range 2 {
		if w.detach[i][1].Load() == 0 || w.detach[i][0].Load() == 0 {
			t.Errorf("%s: DETACH placed %d, dispatched %d: want both > 0", side(i), w.detach[i][1].Load(), w.detach[i][0].Load())
		}
	}
	m := w.d.Status().Mux
	if m.FastPaths < uint64(cycles/2) {
		t.Errorf("FastPaths %d of %d cycles: the views did not share trunks", m.FastPaths, cycles)
	}
	t.Logf("%d cycles:%s; AcceptTimeouts crossing a DETACH %d of %d; DETACH dialer placed %d dispatched %d, passive placed %d dispatched %d; Mux %+v",
		cycles, load.String(), crossed, capEnds, w.detach[0][1].Load(), w.detach[0][0].Load(), w.detach[1][1].Load(), w.detach[1][0].Load(), m)
	if t.Failed() {
		t.FailNow()
	}
	shut()
	for _, rt := range []*rendr.Runtime{w.d, w.p} {
		st := rt.Status()
		sc := st.Sessions
		if sc.Open+sc.Pending+sc.Lingering+sc.Orphaned != 0 || st.Handshakes != 0 || st.Sessionless != 0 || st.Actors != 0 ||
			st.BufferedBytes != 0 || st.Abandoned != 0 || st.Mux.Carriers != 0 || st.Mux.Views != 0 {
			t.Fatalf("Runtime %v left state after Close: %+v", rt.InstanceID(), st)
		}
	}
	if l, p := testhooks.LiveSessions.Load()-live0, testhooks.ParkedSessions.Load()-parked0; l != 0 || p != 0 {
		t.Fatalf("session registry after Runtime.Close: %+d live, %+d parked", l, p)
	}
}

// dcCode is the metadata prefix of path p.
func dcCode(p int) byte { return 'a' + byte(p) }

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// cycle runs the dialer's half of one cycle on path; the passive's half
// runs in its acceptor.
func (w *dcWorld) cycle(key string, path int, mode rendr.Mode, within time.Duration) error {
	ctx := context.Background()
	if path == dcWithdraw || path == dcLateConfirm {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, within)
		defer cancel()
	}
	o := rendr.DialOptions{Mode: mode, Metadata: []byte(key)}
	if path == dcPacket {
		c, err := w.peer.DialPacket(ctx, o)
		if err != nil {
			return fmt.Errorf("DialPacket: %w", err)
		}
		defer w.record(0, c)
		if _, err := c.WriteTo(make([]byte, 32), c.RemoteAddr()); err != nil {
			return fmt.Errorf("WriteTo: %w", err)
		}
		c.Close()
		return waitDone(c.Done(), "dialer packet session")
	}
	c, err := w.peer.Dial(ctx, o)
	switch path {
	case dcReject:
		if re := (*rendr.RejectError)(nil); !errors.As(err, &re) {
			return fmt.Errorf("Dial: %v, want a RejectError", err)
		}
		return nil
	case dcTimeout:
		if !errors.Is(err, rendr.ErrCapacity) {
			return fmt.Errorf("Dial: %v, want ErrCapacity (AcceptTimeout)", err)
		}
		return nil
	case dcWithdraw:
		if err == nil {
			c.Close()
			return fmt.Errorf("Dial succeeded on a passive that never decides")
		}
		return nil
	case dcLateConfirm:
		if err != nil {
			return nil // withdrawn: the passive's late Confirm fails
		}
	default:
		if err != nil {
			return fmt.Errorf("Dial: %w", err)
		}
	}
	defer w.record(0, c)
	c.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := c.Write(dcPayload(key)); err != nil {
		c.Close()
		return fmt.Errorf("Write: %w", err)
	}
	switch path {
	case dcDialerClose, dcBothClose, dcLateConfirm:
		c.Close()
	case dcPassiveClose:
		if _, err := io.Copy(io.Discard, c); err != nil {
			c.Close()
			return fmt.Errorf("reading the passive's EOF: %w", err)
		}
		c.Close()
	}
	return waitDone(c.Done(), "dialer session")
}

// lateDelay is the passive's delay before a late Confirm: 0–5 ms by the
// cycle number in key.
func lateDelay(key string) time.Duration {
	n := 0
	for _, r := range key[1:] {
		n = n*7 + int(r-'0')
	}
	return time.Duration(n%6) * time.Millisecond
}

// dcPayload is the 64-byte exchange of a confirmed stream cycle.
func dcPayload(key string) []byte {
	b := make([]byte, 64)
	copy(b, key)
	return b
}

// waitDone waits (at most 30 s) for a session's Done.
func waitDone(done <-chan struct{}, what string) error {
	select {
	case <-done:
		return nil
	case <-time.After(30 * time.Second):
		return fmt.Errorf("%s not done 30 s after Close", what)
	}
}

// record notes the protocol_violation rows of an ended session end (side
// 0 dialer, 1 passive) for the failure report.
func (w *dcWorld) record(i int, c statuser) {
	for _, cs := range c.Status().Carriers {
		if cs.DeathCause == rendr.CauseProtocolViolation {
			w.mu.Lock()
			w.viol[side(i)+": "+cs.DeathDetail]++
			w.mu.Unlock()
		}
	}
}

// acceptStreams decides every stream session by its path until the
// Listener closes; the passive half of a confirmed session runs on its
// own.
func (w *dcWorld) acceptStreams() {
	for {
		pend, err := w.ln.Accept(context.Background())
		if err != nil {
			return
		}
		key := string(pend.Metadata())
		switch path := int(key[0] - 'a'); path {
		case dcReject:
			_ = pend.Reject(7, "churn")
		case dcTimeout, dcWithdraw:
			w.mu.Lock()
			w.pend = append(w.pend, pend) // never decided
			w.mu.Unlock()
		case dcLateConfirm:
			w.held.Go(func() {
				time.Sleep(lateDelay(key))
				if c, err := pend.Confirm(); err == nil {
					w.passive(c, key, path)
				}
			})
		case 'z' - 'a': // a long session: open until the dialer closes it
			c, err := pend.Confirm()
			if err != nil {
				w.t.Errorf("Confirm %s: %v", key, err)
				continue
			}
			w.held.Go(func() {
				defer w.record(1, c)
				_, _ = io.Copy(io.Discard, c)
				c.Close()
			})
		default:
			c, err := pend.Confirm()
			if err != nil {
				w.t.Errorf("Confirm %s: %v", key, err)
				continue
			}
			w.held.Go(func() { w.passive(c, key, path) })
		}
	}
}

// passive is the passive's half of a confirmed short stream session.
func (w *dcWorld) passive(c *rendr.Conn, key string, path int) {
	defer w.record(1, c)
	c.SetDeadline(time.Now().Add(30 * time.Second))
	b := make([]byte, 64)
	if _, err := io.ReadFull(c, b); err != nil {
		c.Close()
		if path != dcLateConfirm {
			w.t.Errorf("passive %s: reading the exchange: %v", key, err)
		}
		return
	}
	if string(b) != string(dcPayload(key)) {
		w.t.Errorf("passive %s: the exchange arrived corrupted", key)
	}
	switch path {
	case dcPassiveClose, dcBothClose:
		c.Close()
	default:
		if _, err := io.Copy(io.Discard, c); err != nil {
			w.t.Errorf("passive %s: reading the dialer's EOF: %v", key, err)
		}
		c.Close()
	}
	if err := waitDone(c.Done(), "passive session "+key); err != nil {
		w.t.Error(err)
	}
}

// acceptPackets confirms every packet session, reads its datagram (at
// most 1 s: the dialer may close before it is delivered) and closes it.
func (w *dcWorld) acceptPackets() {
	for {
		pend, err := w.ln.AcceptPacket(context.Background())
		if err != nil {
			return
		}
		key := string(pend.Metadata())
		c, err := pend.Confirm()
		if err != nil {
			w.t.Errorf("Confirm %s: %v", key, err)
			continue
		}
		w.held.Go(func() {
			defer w.record(1, c)
			c.SetReadDeadline(time.Now().Add(time.Second))
			var b [64]byte
			_, _, _ = c.ReadFrom(b[:])
			c.Close()
			if err := waitDone(c.Done(), "passive packet session "+key); err != nil {
				w.t.Error(err)
			}
		})
	}
}

// noViolation fails when a carrier of either Runtime ended with
// protocol_violation, with the details the sessions' rows recorded.
func (w *dcWorld) noViolation() {
	w.t.Helper()
	n := [2]int{}
	ids := [2]map[rendr.CarrierID]bool{{}, {}}
	for i, l := range []*eventLog{w.dev, w.pev} {
		for _, ev := range l.of(rendr.EventCarrierDown) {
			if ev.Cause == rendr.CauseProtocolViolation {
				n[i]++
				ids[i][ev.Carrier] = true
			}
		}
	}
	if n[0]+n[1] == 0 {
		return
	}
	w.mu.Lock()
	var ds []string
	for d, k := range w.viol {
		ds = append(ds, fmt.Sprintf("%d× %s", k, d))
	}
	w.mu.Unlock()
	sort.Strings(ds)
	w.t.Errorf("protocol_violation: dialer %d CarrierDown events on %d carriers, passive %d on %d; details: %s",
		n[0], len(ids[0]), n[1], len(ids[1]), strings.Join(ds, "; "))
}
