package lessons1

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Scenario fixture (design §10.5, §11.1, V12): a dialer and a passive
// Runtime built with testhooks.NewRuntime from one shared Overrides value
// (counter presets must be identical on both ends, L14), the passive's
// push-only Listener, and one rendrtest.Link per name whose Accept hands a
// tapped conn to Listener.Handle. Peers dial the Links through taps as
// well. Create a fixture inside the bubble that uses it; close it before
// the bubble ends (close is idempotent and also registered as a cleanup, so
// a failing test still ends its bubble without leaks).

// opts configure a fixture.
type opts struct {
	ov         testhooks.Overrides // applied to both Runtimes
	dcfg, pcfg rendr.Config        // OnEvent is replaced by the fixture's event log
	lc         rendr.ListenConfig
	buffer     int // Link buffer per direction (0: rendrtest's 2 MiB)
}

// fixture is two Runtimes, the passive's Listener and the Links between them.
type fixture struct {
	t        testing.TB
	d, p     *rendr.Runtime // dialer, passive
	ln       *rendr.Listener
	links    []*rendrtest.Link
	byName   map[string]*rendrtest.Link
	dev, pev *evLog
	wire     *wireLog
	once     sync.Once
}

// newFixture builds a fixture with one Link per name.
func newFixture(t testing.TB, o opts, names ...string) *fixture {
	t.Helper()
	f := &fixture{t: t, byName: map[string]*rendrtest.Link{}, dev: &evLog{}, pev: &evLog{}, wire: newWireLog()}
	dcfg, pcfg := o.dcfg, o.pcfg
	dcfg.OnEvent, pcfg.OnEvent = f.dev.add, f.pev.add
	f.d = newRuntime(t, dcfg, &o.ov)
	f.p = newRuntime(t, pcfg, &o.ov)
	ln, err := f.p.Listen(o.lc)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	f.ln = ln
	for _, name := range names {
		l := rendrtest.NewLink(rendrtest.LinkConfig{Name: name, Buffer: o.buffer, Accept: f.accept(name)})
		f.links = append(f.links, l)
		f.byName[name] = l
	}
	t.Cleanup(f.close)
	return f
}

// newRuntime builds a Runtime with ov applied after normalization.
func newRuntime(t testing.TB, cfg rendr.Config, ov *testhooks.Overrides) *rendr.Runtime {
	t.Helper()
	v, err := testhooks.NewRuntime(cfg, ov)
	if err != nil {
		t.Fatalf("testhooks.NewRuntime: %v", err)
	}
	return v.(*rendr.Runtime)
}

// accept is the Accept of link name: the passive end, tapped, goes to the
// Listener's handshake.
func (f *fixture) accept(name string) func(net.Conn) error {
	return func(c net.Conn) error { return f.ln.Handle(f.wire.newTap(name, passiveSide, c)) }
}

// link returns the Link called name.
func (f *fixture) link(name string) *rendrtest.Link {
	l := f.byName[name]
	if l == nil {
		f.t.Fatalf("no link %q", name)
	}
	return l
}

// carrier is the StreamCarrier of link name: every conn it dials is tapped.
func (f *fixture) carrier(name string) rendr.StreamCarrier {
	l := f.link(name)
	return rendr.StreamCarrier{Name: name, Dial: func(ctx context.Context) (net.Conn, error) {
		c, err := l.Dial(ctx)
		if err != nil {
			return nil, err
		}
		return f.wire.newTap(name, dialerSide, c), nil
	}}
}

// peer returns a dialer Peer over the named links (every link when none),
// in that preference order. A single-factory Peer has no probe carriers, so
// one-shot conn controls can only hit session carriers (V12).
func (f *fixture) peer(names ...string) *rendr.Peer {
	f.t.Helper()
	if len(names) == 0 {
		for _, l := range f.links {
			names = append(names, l.Name())
		}
	}
	cs := make([]rendr.Carrier, len(names))
	for i, n := range names {
		cs[i] = f.carrier(n)
	}
	p, err := f.d.NewPeer(rendr.PeerConfig{Carriers: cs})
	if err != nil {
		f.t.Fatalf("NewPeer: %v", err)
	}
	return p
}

// dialRes is the outcome of an asynchronous Dial.
type dialRes struct {
	c   *rendr.Conn
	err error
}

// dialAsync dials on its own goroutine.
func dialAsync(peer *rendr.Peer, o rendr.DialOptions) <-chan dialRes {
	ch := make(chan dialRes, 1)
	go func() {
		c, err := peer.Dial(context.Background(), o)
		ch <- dialRes{c, err}
	}()
	return ch
}

// openWithin bounds each step of opening a session (virtual time).
const openWithin = 30 * time.Second

// open dials one session on peer and confirms it on the fixture's Listener.
func (f *fixture) open(peer *rendr.Peer, o rendr.DialOptions) (dc, pc *rendr.Conn) {
	f.t.Helper()
	res := dialAsync(peer, o)
	ctx, cancel := context.WithTimeout(context.Background(), openWithin)
	defer cancel()
	pend, err := f.ln.Accept(ctx)
	if err != nil {
		f.t.Fatalf("Accept: %v", err)
	}
	pc, err = pend.Confirm()
	if err != nil {
		f.t.Fatalf("Confirm: %v", err)
	}
	r := recv(f.t, res, openWithin, "Dial")
	if r.err != nil {
		f.t.Fatalf("Dial: %v", r.err)
	}
	return r.c, pc
}

// recv receives one value from ch and fails t, naming what (and the
// details, evaluated at the failure), when none arrives within d. Inside a
// bubble d is virtual time: rendr's PING timers keep the clock moving, so a
// stuck scenario never deadlocks the bubble — without a bound it would only
// end at the package -timeout, with every later test lost. (A loop that
// never lets virtual time pass, such as carriers killed and redialled over
// a zero-delay Link, escapes every such bound: tests that could run into
// one give their Links a delay.)
func recv[T any](t testing.TB, ch <-chan T, d time.Duration, what string, details ...func() string) T {
	t.Helper()
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case v := <-ch:
		return v
	case <-timer.C:
		for _, f := range details {
			what += "; " + f()
		}
		t.Fatalf("%s: not within %v", what, d)
		var zero T
		return zero
	}
}

// runWithin runs fn on its own goroutine and fails t when fn returns an
// error or does not return within d (see recv). After a failure the
// fixture's cleanup closes the Runtimes, which unblocks fn.
func runWithin(t testing.TB, d time.Duration, what string, fn func() error) {
	t.Helper()
	ch := make(chan error, 1)
	go func() { ch <- fn() }()
	if err := recv(t, ch, d, what); err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

// reached waits until gauge g counted k bytes and fails t when it does not
// within d (see recv).
func reached(t testing.TB, g *gauge, k int64, d time.Duration) {
	t.Helper()
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-g.at(k):
	case <-timer.C:
		t.Fatalf("%d bytes received: not within %v (have %d)", k, d, g.get())
	}
}

// close releases every blocked write, closes both Runtimes (the dialer
// first) and every Link, and requires that both Runtimes hold no live
// session, handshake, buffered byte or abandoned goroutine. Idempotent.
func (f *fixture) close() {
	f.once.Do(func() {
		for _, l := range f.links {
			l.Release()
		}
		f.d.Close()
		f.p.Close()
		for _, l := range f.links {
			l.Close()
		}
		for _, rt := range []*rendr.Runtime{f.d, f.p} {
			st := rt.Status()
			s := st.Sessions
			if s.Open+s.Pending+s.Lingering+s.Orphaned != 0 || st.Handshakes != 0 || st.Sessionless != 0 ||
				st.BufferedBytes != 0 || st.Abandoned != 0 || st.AcceptBacklog != [2]int{} {
				f.t.Errorf("Runtime %v not empty after Close: %+v", rt.InstanceID(), st)
			}
		}
	})
}

// evLog records Config.OnEvent calls.
type evLog struct {
	mu  sync.Mutex
	evs []rendr.Event
}

func (l *evLog) add(ev rendr.Event) {
	l.mu.Lock()
	l.evs = append(l.evs, ev)
	l.mu.Unlock()
}

// of returns the recorded events of session sid and kind k.
func (l *evLog) of(sid rendr.SessionID, k rendr.EventKind) []rendr.Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []rendr.Event
	for _, ev := range l.evs {
		if ev.Session == sid && ev.Kind == k {
			out = append(out, ev)
		}
	}
	return out
}

// eventually polls cond every millisecond of (virtual) time and fails t
// when it does not hold within. Inside a bubble each poll waits until every
// goroutine is blocked, so cond is evaluated at quiescent points.
func eventually(t testing.TB, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if !time.Now().Before(deadline) {
			t.Fatalf("%s: not within %v", what, within)
		}
		time.Sleep(time.Millisecond)
	}
}

// endedAt returns the publication time of the SessionEnd event of c's
// session (exact, unlike a poll), waiting for its asynchronous delivery.
func endedAt(t testing.TB, l *evLog, c *rendr.Conn) time.Time {
	t.Helper()
	var evs []rendr.Event
	eventually(t, time.Second, "SessionEnd event of "+c.ID().String(), func() bool {
		evs = l.of(c.ID(), rendr.EventSessionEnd)
		return len(evs) > 0
	})
	if len(evs) != 1 {
		t.Fatalf("session %v: %d SessionEnd events", c.ID(), len(evs))
	}
	return evs[0].Time
}

// waitEnded waits until the session of c ended and returns its status.
func waitEnded(t testing.TB, c *rendr.Conn, within time.Duration) rendr.SessionStatus {
	t.Helper()
	var st rendr.SessionStatus
	eventually(t, within, "session "+c.ID().String()+" ended", func() bool {
		st = c.Status()
		return st.State == rendr.StateEnded
	})
	return st
}

// sessionCarriers returns the carriers of the link's history that carried
// a session (OPEN or JOIN first), in creation order.
func sessionCarriers(l *rendrtest.Link) []rendrtest.CarrierInfo {
	var out []rendrtest.CarrierInfo
	for _, c := range l.Carriers() {
		if c.Session {
			out = append(out, c)
		}
	}
	return out
}

// deadCarriers returns the dead carriers of a session status.
func deadCarriers(st rendr.SessionStatus) []rendr.CarrierStatus {
	var out []rendr.CarrierStatus
	for _, c := range st.Carriers {
		if c.State == rendr.CarrierDead {
			out = append(out, c)
		}
	}
	return out
}

// carrierIn returns the carrier of st in state s (the first one), or false.
func carrierIn(st rendr.SessionStatus, s rendr.CarrierState) (rendr.CarrierStatus, bool) {
	for _, c := range st.Carriers {
		if c.State == s {
			return c, true
		}
	}
	return rendr.CarrierStatus{}, false
}

// noMigrations is the zero migration count.
var noMigrations rendr.MigrationCounts
