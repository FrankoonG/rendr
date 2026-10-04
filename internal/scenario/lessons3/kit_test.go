package lessons3

import (
	"context"
	"sync"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Scenario kit (design §11.1 scenario layer, §10.5, V12): a dialer and a
// passive Runtime built with testhooks.NewRuntime and joined by rendrtest
// Links. A world is created inside the synctest bubble that uses it and is
// closed before the bubble ends: on success by finish (which also checks
// that nothing was left behind), on failure by its t.Cleanup. Every link's
// Accept is the passive Listener's Handle, so carriers go through the whole
// passive handshake and admission; the dialer's factories are the links'
// Dial unless a test supplies its own.

const (
	kib = 1 << 10
	mib = 1 << 20
)

// linkSpec describes one link of a world.
type linkSpec struct {
	name  string
	delay time.Duration // one-way delay of both directions
	rate  float64       // bytes/s of each direction's shared bottleneck; 0 = unlimited
}

// worldConfig configures a world: its links and the dialer's and the
// passive's overrides (both Runtimes otherwise use the default Config).
// pov nil uses dov (counter presets must be identical on both Runtimes,
// L14); a test that installs hooks or timings on one side only gives the
// sides separate values with the same presets.
type worldConfig struct {
	links    []linkSpec
	dov, pov *testhooks.Overrides
}

// world is two Runtimes, the passive's push-only Listener and the links
// between them.
type world struct {
	t        *testing.T
	d, p     *rendr.Runtime // dialer, passive
	ln       *rendr.Listener
	links    []*rendrtest.Link
	dev, pev *evlog // events of the dialer and of the passive Runtime

	accepted chan *rendr.Conn // passive Conns confirmed by the accept loop
	done     chan struct{}    // closed by close: the accept loop stops handing out Conns
	bg       sync.WaitGroup   // the accept loop and every flow goroutine
	gates    []*holdGate      // opened by close: no rendr goroutine stays held
	closed   bool
}

// newRuntime builds a Runtime with ov applied after normalization.
func newRuntime(t *testing.T, cfg rendr.Config, ov *testhooks.Overrides) *rendr.Runtime {
	t.Helper()
	v, err := testhooks.NewRuntime(cfg, ov)
	if err != nil {
		t.Fatalf("testhooks.NewRuntime: %v", err)
	}
	rt, ok := v.(*rendr.Runtime)
	if !ok {
		t.Fatalf("testhooks.NewRuntime returned %T", v)
	}
	return rt
}

// newWorld builds a world inside the caller's bubble. Gates passed in are
// opened when the world closes, before its Runtimes close.
func newWorld(t *testing.T, wc worldConfig, gates ...*holdGate) *world {
	t.Helper()
	w := &world{
		t: t, dev: newEvlog(), pev: newEvlog(),
		accepted: make(chan *rendr.Conn, 16), done: make(chan struct{}),
		gates: gates,
	}
	pov := wc.pov
	if pov == nil {
		pov = wc.dov
	}
	w.d = newRuntime(t, rendr.Config{OnEvent: w.dev.add}, wc.dov)
	w.p = newRuntime(t, rendr.Config{OnEvent: w.pev.add}, pov)
	t.Cleanup(w.close) // also when the test failed
	ln, err := w.p.Listen(rendr.ListenConfig{})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	w.ln = ln
	for _, ls := range wc.links {
		l := rendrtest.NewLink(rendrtest.LinkConfig{Name: ls.name, Accept: ln.Handle})
		l.SetDelay(ls.delay, 0)
		l.SetRate(ls.rate)
		w.links = append(w.links, l)
	}
	w.bg.Add(1)
	go w.acceptLoop()
	return w
}

// acceptLoop confirms every session the passive admits and hands its Conn
// to the test.
func (w *world) acceptLoop() {
	defer w.bg.Done()
	for {
		pc, err := w.ln.Accept(context.Background())
		if err != nil {
			return
		}
		c, err := pc.Confirm()
		if err != nil {
			continue // withdrawn meanwhile: the dialer's Dial reports it
		}
		select {
		case w.accepted <- c:
		case <-w.done:
			return
		}
	}
}

// link returns the world's link called name.
func (w *world) link(name string) *rendrtest.Link {
	w.t.Helper()
	for _, l := range w.links {
		if l.Name() == name {
			return l
		}
	}
	w.t.Fatalf("no link %q", name)
	return nil
}

// carrierOf is the plain StreamCarrier of a link.
func carrierOf(l *rendrtest.Link) rendr.StreamCarrier {
	return rendr.StreamCarrier{Name: l.Name(), Dial: l.Dial}
}

// peer returns a dialer Peer over the named links in that order (every
// link when none is named).
func (w *world) peer(names ...string) *rendr.Peer {
	w.t.Helper()
	var cs []rendr.Carrier
	if len(names) == 0 {
		for _, l := range w.links {
			cs = append(cs, carrierOf(l))
		}
	}
	for _, n := range names {
		cs = append(cs, carrierOf(w.link(n)))
	}
	return w.peerOf(cs...)
}

// peerOf returns a dialer Peer over the given carriers.
func (w *world) peerOf(cs ...rendr.Carrier) *rendr.Peer {
	w.t.Helper()
	p, err := w.d.NewPeer(rendr.PeerConfig{Carriers: cs})
	if err != nil {
		w.t.Fatalf("NewPeer: %v", err)
	}
	return p
}

// open dials one session and returns both of its ends.
func (w *world) open(p *rendr.Peer, mode rendr.Mode) (dc, pc *rendr.Conn) {
	w.t.Helper()
	dc, err := p.Dial(context.Background(), rendr.DialOptions{Mode: mode})
	if err != nil {
		w.t.Fatalf("Dial: %v", err)
	}
	select {
	case pc = <-w.accepted:
	case <-time.After(10 * time.Second):
		w.t.Fatal("the passive end was not confirmed within 10 s")
	}
	if pc.ID() != dc.ID() {
		w.t.Fatalf("passive session %v, dialer session %v", pc.ID(), dc.ID())
	}
	return dc, pc
}

// close releases every held hook and every blocked link write (abandoned
// calls return, L52), closes both Runtimes and every link, and joins the
// world's own goroutines. Idempotent; registered as the world's cleanup.
func (w *world) close() {
	if w.closed {
		return
	}
	w.closed = true
	for _, g := range w.gates {
		g.open()
	}
	for _, l := range w.links {
		l.Release()
	}
	w.d.Close()
	w.p.Close()
	for _, l := range w.links {
		l.Close()
	}
	close(w.done)
	w.bg.Wait()
}

// finish closes the world (sessions should have ended by now) and requires
// that both Runtimes are left with no session, buffered byte or abandoned
// goroutine (design §3.1, §6.8).
func (w *world) finish() {
	w.t.Helper()
	w.close()
	for _, x := range []struct {
		name string
		rt   *rendr.Runtime
	}{{"dialer", w.d}, {"passive", w.p}} {
		st := x.rt.Status()
		sc := st.Sessions
		if sc.Open+sc.Pending+sc.Lingering+sc.Orphaned != 0 || st.BufferedBytes != 0 || st.Abandoned != 0 || st.Handshakes != 0 {
			w.t.Errorf("%s Runtime left state after Close: sessions %+v, buffered %d, abandoned %d, handshakes %d",
				x.name, sc, st.BufferedBytes, st.Abandoned, st.Handshakes)
		}
	}
}

// goBG runs f on a goroutine the world joins when it closes.
func (w *world) goBG(f func()) {
	w.bg.Add(1)
	go func() {
		defer w.bg.Done()
		f()
	}()
}

// evlog records the events of one Runtime (Config.OnEvent). wait blocks
// until a matching event was recorded.
type evlog struct {
	mu  sync.Mutex
	evs []rendr.Event
	sig chan struct{} // closed and renewed on every event
}

func newEvlog() *evlog { return &evlog{sig: make(chan struct{})} }

// add is the Runtime's OnEvent: it never blocks.
func (l *evlog) add(ev rendr.Event) {
	l.mu.Lock()
	l.evs = append(l.evs, ev)
	close(l.sig)
	l.sig = make(chan struct{})
	l.mu.Unlock()
}

// mark returns the number of events recorded so far (a start index for
// find and wait).
func (l *evlog) mark() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.evs)
}

// find returns the events from index from on that match.
func (l *evlog) find(from int, match func(rendr.Event) bool) []rendr.Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []rendr.Event
	for _, ev := range l.evs[min(from, len(l.evs)):] {
		if match(ev) {
			out = append(out, ev)
		}
	}
	return out
}

// wait returns the first event from index from on that matches, failing t
// when none was recorded within (virtual time).
func (l *evlog) wait(t testing.TB, from int, within time.Duration, what string, match func(rendr.Event) bool) rendr.Event {
	t.Helper()
	timer := time.NewTimer(within)
	defer timer.Stop()
	for {
		l.mu.Lock()
		for _, ev := range l.evs[min(from, len(l.evs)):] {
			if match(ev) {
				l.mu.Unlock()
				return ev
			}
		}
		sig := l.sig
		l.mu.Unlock()
		select {
		case <-sig:
		case <-timer.C:
			t.Fatalf("no %s event within %v", what, within)
			return rendr.Event{}
		}
	}
}

// isKind matches events of kind k of session sid.
func isKind(k rendr.EventKind, sid rendr.SessionID) func(rendr.Event) bool {
	return func(ev rendr.Event) bool { return ev.Kind == k && ev.Session == sid }
}

// holdGate holds a rendr goroutine at a testhooks hook point (DialResult,
// DeathObserved): once armed, the first call whose carrier ID matches is
// held until open; every other call passes. A world opens its gates before
// it closes its Runtimes, so a failed test never leaves a goroutine held.
type holdGate struct {
	mu      sync.Mutex
	match   func(id uint32) bool // nil: disarmed
	held    chan uint32          // receives the ID of the held call
	release chan struct{}
	once    sync.Once
}

func newHoldGate() *holdGate {
	return &holdGate{held: make(chan uint32, 1), release: make(chan struct{})}
}

// arm holds the next call whose ID matches.
func (g *holdGate) arm(match func(id uint32) bool) {
	g.mu.Lock()
	g.match = match
	g.mu.Unlock()
}

// hook is the testhooks function.
func (g *holdGate) hook(id uint32) {
	g.mu.Lock()
	hold := g.match != nil && g.match(id)
	if hold {
		g.match = nil
	}
	g.mu.Unlock()
	if !hold {
		return
	}
	g.held <- id
	<-g.release
}

// open releases the held call (and every later one: the gate is spent).
func (g *holdGate) open() { g.once.Do(func() { close(g.release) }) }

// anyID matches every carrier.
func anyID(uint32) bool { return true }

// waitFor polls cond in virtual time until it holds, failing t after
// within.
func waitFor(t testing.TB, within time.Duration, what string, cond func() bool) {
	t.Helper()
	waitState(t, within, what, func() (bool, string) { return cond(), "" })
}

// waitState is waitFor whose condition also describes the state it saw;
// the last description is reported on failure.
func waitState(t testing.TB, within time.Duration, what string, cond func() (bool, string)) {
	t.Helper()
	step := max(time.Millisecond, min(within/2000, 10*time.Millisecond))
	deadline := time.Now().Add(within)
	for {
		ok, state := cond()
		if ok {
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("%s: not within %v (last seen: %s)", what, within, state)
		}
		time.Sleep(step)
	}
}

// activeCarrier returns the carrier a selector session reports active.
func activeCarrier(c *rendr.Conn) (rendr.CarrierStatus, bool) {
	for _, cs := range c.Status().Carriers {
		if cs.State == rendr.CarrierActive {
			return cs, true
		}
	}
	return rendr.CarrierStatus{}, false
}

// mustActive is activeCarrier failing t without one.
func mustActive(t testing.TB, c *rendr.Conn, side string) rendr.CarrierStatus {
	t.Helper()
	cs, ok := activeCarrier(c)
	if !ok {
		t.Fatalf("%s: no active carrier: %+v", side, c.Status().Carriers)
	}
	return cs
}

// carrierByID returns carrier id of c's session (live or among the last
// dead ones).
func carrierByID(c *rendr.Conn, id rendr.CarrierID) (rendr.CarrierStatus, bool) {
	for _, cs := range c.Status().Carriers {
		if cs.ID == id {
			return cs, true
		}
	}
	return rendr.CarrierStatus{}, false
}

// sessionCarriers lists the session carriers a link created (probe
// carriers excluded).
func sessionCarriers(l *rendrtest.Link) []rendrtest.CarrierInfo {
	var out []rendrtest.CarrierInfo
	for _, ci := range l.Carriers() {
		if ci.Session {
			out = append(out, ci)
		}
	}
	return out
}

// wantMigrations fails t unless c's session counted exactly want
// migrations.
func wantMigrations(t testing.TB, side string, c *rendr.Conn, want rendr.MigrationCounts) {
	t.Helper()
	if got := c.Status().Migrations; got != want {
		t.Fatalf("%s migrations %+v, want %+v", side, got, want)
	}
}
