package timers

import (
	"context"
	"fmt"
	"io"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Scenario kit of package timers. A world is two Runtimes — the dialer d
// and the passive p with one push-only Listener — built with
// testhooks.NewRuntime and joined by rendrtest.Links whose Accept is the
// Listener's Handle; a population of sessions is dialled concurrently and
// matched on the passive by its metadata. Everything is created inside the
// synctest bubble that uses it and closed before the bubble ends; close
// checks that neither Runtime holds state and that the session registry is
// back where it was (R1-24).

// linkSpec is one path of a world.
type linkSpec struct {
	name   string
	oneWay time.Duration
	props  rendr.Props
}

// worldOpts configures a world.
type worldOpts struct {
	dcfg     rendr.Config        // the dialer's (Handshake is sized for the population)
	pcfg     rendr.Config        // the passive's (Handshake and the backlog are sized for the population)
	dov, pov testhooks.Overrides // the dialer's and the passive's
	n        int                 // the session population
}

// world is one scenario's two Runtimes, links and Peer.
type world struct {
	t     testing.TB
	d, p  *rendr.Runtime
	ln    *rendr.Listener
	specs []linkSpec
	links []*rendrtest.Link
	peer  *rendr.Peer
	ends  [2]*endLog // the dialer's and the passive's EventSessionEnd

	live0, parked0 int64
	shutOnce       sync.Once
}

// newWorld builds the Runtimes, the Listener, one Link per spec and a Peer
// over them in that order.
func newWorld(t testing.TB, o worldOpts, specs ...linkSpec) *world {
	t.Helper()
	w := &world{t: t, specs: specs, ends: [2]*endLog{{at: map[rendr.SessionID]rendr.Event{}}, {at: map[rendr.SessionID]rendr.Event{}}},
		live0: testhooks.LiveSessions.Load(), parked0: testhooks.ParkedSessions.Load()}
	for i, c := range []*rendr.Config{&o.dcfg, &o.pcfg} {
		c.Handshake.MaxConcurrent = max(c.Handshake.MaxConcurrent, 2*o.n)
		c.OnEvent = w.ends[i].add
	}
	w.d = newRuntime(t, o.dcfg, &o.dov)
	w.p = newRuntime(t, o.pcfg, &o.pov)
	t.Cleanup(w.shutdown)
	ln, err := w.p.Listen(rendr.ListenConfig{AcceptBacklog: max(2*o.n, 1)})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	w.ln = ln
	var cs []rendr.Carrier
	for _, s := range specs {
		l := rendrtest.NewLink(rendrtest.LinkConfig{Name: s.name, Accept: ln.Handle})
		l.SetDelay(s.oneWay, 0)
		w.links = append(w.links, l)
		cs = append(cs, rendr.StreamCarrier{Name: s.name, Dial: l.Dial, Props: s.props})
	}
	if w.peer, err = w.d.NewPeer(rendr.PeerConfig{Carriers: cs}); err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	return w
}

// endLog records the EventSessionEnd of every session of a Runtime.
type endLog struct {
	mu sync.Mutex
	at map[rendr.SessionID]rendr.Event
}

func (l *endLog) add(ev rendr.Event) {
	if ev.Kind != rendr.EventSessionEnd {
		return
	}
	l.mu.Lock()
	l.at[ev.Session] = ev
	l.mu.Unlock()
}

// of returns the EventSessionEnd of session id, if any.
func (l *endLog) of(id rendr.SessionID) (rendr.Event, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ev, ok := l.at[id]
	return ev, ok
}

// newRuntime builds a Runtime through testhooks (unclamped overrides).
func newRuntime(t testing.TB, cfg rendr.Config, ov *testhooks.Overrides) *rendr.Runtime {
	t.Helper()
	v, err := testhooks.NewRuntime(cfg, ov)
	if err != nil {
		t.Fatalf("testhooks.NewRuntime: %v", err)
	}
	return v.(*rendr.Runtime)
}

// pair is one session's dialer and passive ends.
type pair struct{ d, p *rendr.Conn }

// openMany dials n sessions concurrently (mode by index) and confirms each
// on the passive, matched by its metadata (the index).
func (w *world) openMany(n int, modeOf func(i int) rendr.Mode) []pair {
	w.t.Helper()
	ps := make([]pair, n)
	var accepted sync.WaitGroup
	accepted.Go(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		for range n {
			pend, err := w.ln.Accept(ctx)
			if err != nil {
				w.t.Errorf("Accept: %v", err)
				return
			}
			c, err := pend.Confirm()
			if err != nil {
				w.t.Errorf("Confirm: %v", err)
				return
			}
			i, err := strconv.Atoi(string(pend.Metadata()))
			if err != nil || i < 0 || i >= n || ps[i].p != nil || pend.Mode() != modeOf(i) {
				w.t.Errorf("metadata %q, mode %v", pend.Metadata(), pend.Mode())
				return
			}
			ps[i].p = c
		}
	})
	var dials sync.WaitGroup
	for i := range n {
		dials.Go(func() {
			c, err := w.peer.Dial(context.Background(), rendr.DialOptions{Mode: modeOf(i), Metadata: []byte(strconv.Itoa(i))})
			if err != nil {
				w.t.Errorf("Dial %d (%v): %v", i, modeOf(i), err)
				return
			}
			ps[i].d = c
		})
	}
	dials.Wait()
	accepted.Wait()
	if w.t.Failed() {
		w.t.FailNow()
	}
	return ps
}

// exchange moves one byte (round) each way on every session, verified.
func exchange(t testing.TB, ps []pair, round byte) {
	t.Helper()
	var wg sync.WaitGroup
	for i, s := range ps {
		wg.Go(func() {
			for _, dir := range [][2]*rendr.Conn{{s.d, s.p}, {s.p, s.d}} {
				if _, err := dir[0].Write([]byte{round}); err != nil {
					t.Errorf("session %d: Write: %v", i, err)
					return
				}
				var b [1]byte
				if _, err := io.ReadFull(dir[1], b[:]); err != nil || b[0] != round {
					t.Errorf("session %d: Read %d, %v; want %d", i, b[0], err, round)
					return
				}
			}
		})
	}
	wg.Wait()
	if t.Failed() {
		t.FailNow()
	}
}

// closeAll closes every session on both ends and waits for their ends.
func closeAll(t testing.TB, ps []pair) {
	t.Helper()
	var wg sync.WaitGroup
	for i, s := range ps {
		wg.Go(func() {
			s.d.Close()
			s.p.Close()
			for _, c := range []*rendr.Conn{s.d, s.p} {
				select {
				case <-c.Done():
				case <-time.After(time.Minute):
					t.Errorf("session %d not done a minute after Close: %+v", i, c.Status())
				}
			}
		})
	}
	wg.Wait()
}

// registry returns the session registry gauges relative to the world's
// start (R1-24): live and parked sessions.
func (w *world) registry() (live, parked int64) {
	return testhooks.LiveSessions.Load() - w.live0, testhooks.ParkedSessions.Load() - w.parked0
}

// actors returns Status.Actors of both Runtimes.
func (w *world) actors() (d, p int) { return w.d.Status().Actors, w.p.Status().Actors }

// carriers returns the live carriers of the dialer's sessions (each is one
// carrier per side).
func carriers(ps []pair) int {
	n := 0
	for _, s := range ps {
		for _, c := range s.d.Status().Carriers {
			if c.State == rendr.CarrierActive || c.State == rendr.CarrierMember {
				n++
			}
		}
	}
	return n
}

// shutdown closes the Peer, both Runtimes (the dialer first) and every
// link (once; also the cleanup of a failed test).
func (w *world) shutdown() {
	w.shutOnce.Do(func() {
		w.peer.Close()
		w.d.Close()
		w.p.Close()
		for _, l := range w.links {
			l.Close()
		}
	})
}

// close shuts the world down and requires that neither Runtime holds a
// session, a handshake, a sessionless carrier, an actor or a buffered byte
// any more, that nothing was abandoned, and that the session registry is
// back at its value before the world (R1-24).
func (w *world) close() {
	w.t.Helper()
	w.shutdown()
	for _, rt := range []*rendr.Runtime{w.d, w.p} {
		st := rt.Status()
		sc := st.Sessions
		if sc.Open+sc.Pending+sc.Lingering+sc.Orphaned != 0 || st.Handshakes != 0 || st.Sessionless != 0 || st.Actors != 0 ||
			st.BufferedBytes != 0 || st.Abandoned != 0 || st.AcceptBacklog != [2]int{} {
			w.t.Fatalf("Runtime %v left state after Close: %+v", rt.InstanceID(), st)
		}
	}
	if l, p := w.registry(); l != 0 || p != 0 {
		w.t.Fatalf("session registry after Runtime.Close: %+d live, %+d parked", l, p)
	}
}

// goroutines counts the goroutines rendr started — those created by a
// function of package rendr or of its internal packages, wherever they
// are blocked now (a carrier reader waits inside a Link's conn) — and, of
// them, the session actors; byTop counts them by the function that
// created them. The links' pumps and the test's own goroutines are not
// rendr's.
func goroutines() (ours, actors int, byTop map[string]int) {
	buf := make([]byte, 64<<20)
	buf = buf[:runtime.Stack(buf, true)]
	byTop = map[string]int{}
	for _, g := range strings.Split(string(buf), "\n\n") {
		by := creator(g)
		if !strings.HasPrefix(by, "github.com/FrankoonG/rendr/v2.") && !strings.HasPrefix(by, "github.com/FrankoonG/rendr/v2/internal/") ||
			strings.HasPrefix(by, "github.com/FrankoonG/rendr/v2/internal/scenario/") {
			continue
		}
		ours++
		if strings.Contains(g, "internal/session.(*actor).run") {
			actors++
		}
		byTop[strings.TrimPrefix(by, "github.com/FrankoonG/rendr/v2")]++
	}
	return ours, actors, byTop
}

// creator returns the function named by a goroutine's "created by" line
// ("" for none).
func creator(g string) string {
	i := strings.LastIndex(g, "\ncreated by ")
	if i < 0 {
		return ""
	}
	by := g[i+len("\ncreated by "):]
	if j := strings.IndexAny(by, " \n"); j >= 0 {
		by = by[:j]
	}
	return by
}

// histogram formats byTop, largest first.
func histogram(byTop map[string]int) string {
	type kv struct {
		k string
		v int
	}
	var s []kv
	for k, v := range byTop {
		s = append(s, kv{k, v})
	}
	sort.Slice(s, func(i, j int) bool { return s[i].v > s[j].v || (s[i].v == s[j].v && s[i].k < s[j].k) })
	var b strings.Builder
	for _, e := range s {
		fmt.Fprintf(&b, "\n\t%6d %s", e.v, e.k)
	}
	return b.String()
}
