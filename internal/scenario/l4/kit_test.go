package l4

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/l4"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Scenario kit of package l4 (M4 design §A12.2). A world is two Runtimes —
// the dialer d (the ingress side) and the passive p with one push-only
// Listener served by an l4.Server — joined by rendrtest.Links of 20 ms RTT
// whose Accept is the Listener's Handle (or a test's wrapper of it). The
// Server's Dial hook routes each target address by its class, the
// address's first label up to its '-' ("echo-3.test:80" → "echo"), to a
// rendrtest.Target or a ScriptedDial the test registered. Every factory
// call goes through a wrapper that counts the session carriers' calls per
// factory apart from the probe carriers' (rendr.CarrierDialInfo). Both
// Runtimes' events are recorded. An ingress is the dialer side of one
// forwarded connection: l4.Dial, then l4.Forward between the Conn and the
// server end of a TargetPipe whose client end the test drives.
// Everything is created inside the synctest bubble that uses it and
// closed before the bubble ends; the bubble itself fails if a goroutine
// outlives it, and close checks that neither Runtime holds state, that
// the Server holds nothing and that the session registry is back where it
// was (M3 design R1-24).

// oneWay is the links' one-way delay: the fixture's 20 ms RTT.
const oneWay = 10 * time.Millisecond

// dialFunc is a target dial (rendrtest.Target.Dial, a ScriptedDial).
type dialFunc = func(ctx context.Context, addr string) (net.Conn, error)

// linkSpec is one path of a world; its name is also the factory's name.
type linkSpec struct {
	name   string
	rate   float64     // bytes/s per direction; 0 = unlimited
	props  rendr.Props // the factory's Props (zero: rendr mux)
	buffer int         // the Link's buffer per direction (0: 2 MiB)
}

// worldOpts configures a world.
type worldOpts struct {
	dcfg, pcfg rendr.Config        // OnEvent is set by the world
	dov, pov   testhooks.Overrides // the dialer's and the passive's
	listen     rendr.ListenConfig
	srv        *l4.Server // nil: the zero Server; its Dial is the world's router
	// accept, when set, receives the passive end of every new carrier of
	// link name and must hand it (or a wrapper) to handle, the Listener's
	// Handle.
	accept func(name string, c net.Conn, handle func(net.Conn) error) error
}

// world is one scenario's two Runtimes, Listener, Server and links.
type world struct {
	t        testing.TB
	d, p     *rendr.Runtime
	ln       *rendr.Listener
	srv      *l4.Server
	specs    []linkSpec
	links    map[string]*rendrtest.Link
	dev, pev *eventLog
	peers    []*rendr.Peer

	serveCancel context.CancelFunc
	serveDone   chan error
	served      error // Serve's result once it returned

	live0, parked0 int64
	shutOnce       sync.Once
	// quit is closed first by shutdown: paced traffic goroutines (pace)
	// stop at once, so that a row that failed mid-traffic ends cleanly
	// (a synctest bubble cannot advance its clock for sleepers once its
	// main goroutine has exited).
	quit    chan struct{}
	closers []func()                // targets and tampers, closed after the Runtimes
	clients []*rendrtest.TargetConn // the ingresses' client ends, closed first

	mu     sync.Mutex
	routes map[string]dialFunc    // target dials by class
	calls  map[string][]time.Time // session factory calls per factory
	probes map[string]int         // probe factory calls per factory
}

// newWorld builds the Runtimes, the Listener, the links and the Server
// (running Serve). A cleanup shuts everything down if the test fails
// before close.
func newWorld(t testing.TB, o worldOpts, specs ...linkSpec) *world {
	t.Helper()
	w := &world{t: t, specs: specs, links: map[string]*rendrtest.Link{}, dev: &eventLog{}, pev: &eventLog{},
		routes: map[string]dialFunc{}, calls: map[string][]time.Time{}, probes: map[string]int{},
		live0: testhooks.LiveSessions.Load(), parked0: testhooks.ParkedSessions.Load(), quit: make(chan struct{})}
	o.dcfg.OnEvent, o.pcfg.OnEvent = w.dev.add, w.pev.add
	w.d = newRuntime(t, o.dcfg, &o.dov)
	w.p = newRuntime(t, o.pcfg, &o.pov)
	t.Cleanup(w.shutdown)
	ln, err := w.p.Listen(o.listen)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	w.ln = ln
	for _, s := range specs {
		name := s.name
		accept := ln.Handle
		if o.accept != nil {
			accept = func(c net.Conn) error { return o.accept(name, c, ln.Handle) }
		}
		l := rendrtest.NewLink(rendrtest.LinkConfig{Name: name, Buffer: s.buffer, Accept: accept})
		l.SetDelay(oneWay, 0)
		l.SetRate(s.rate)
		w.links[name] = l
	}
	w.srv = o.srv
	if w.srv == nil {
		w.srv = &l4.Server{}
	}
	if w.srv.Dial == nil {
		w.srv.Dial = w.route
	}
	ctx, cancel := context.WithCancel(context.Background())
	w.serveCancel, w.serveDone = cancel, make(chan error, 1)
	go func() { w.serveDone <- w.srv.Serve(ctx, ln) }()
	return w
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

// classOf is the class of a target address: its first label up to '-'.
func classOf(addr string) string {
	host, _, _ := strings.Cut(addr, ".")
	class, _, _ := strings.Cut(host, "-")
	return class
}

// route is the Server's Dial hook: the dial registered for the address's
// class.
func (w *world) route(ctx context.Context, r l4.Request) (net.Conn, error) {
	w.mu.Lock()
	dial := w.routes[classOf(r.Addr)]
	w.mu.Unlock()
	if dial == nil {
		return nil, fmt.Errorf("scenario: no target for %q", r.Addr)
	}
	return dial(ctx, r.Addr)
}

// handle registers dial for class.
func (w *world) handle(class string, dial dialFunc) {
	w.mu.Lock()
	w.routes[class] = dial
	w.mu.Unlock()
}

// target creates a Target running b (TargetPipe buffers of 64 KiB),
// routes class to it and closes it after the Runtimes.
func (w *world) target(class string, b rendrtest.TargetBehaviour) *rendrtest.Target {
	tg := rendrtest.NewTarget(b, 0)
	w.handle(class, tg.Dial)
	w.onClose(tg.Close)
	return tg
}

// scripted routes class to a ScriptedDial of the outcomes.
func (w *world) scripted(class string, outcomes ...rendrtest.DialOutcome) *rendrtest.DialCounts {
	dial, counts := rendrtest.ScriptedDial(outcomes...)
	w.handle(class, dial)
	return counts
}

// onClose registers f to run after the Runtimes are closed.
func (w *world) onClose(f func()) {
	w.mu.Lock()
	w.closers = append(w.closers, f)
	w.mu.Unlock()
}

// link returns the link named name.
func (w *world) link(name string) *rendrtest.Link {
	if l := w.links[name]; l != nil {
		return l
	}
	w.t.Fatalf("no link %q", name)
	return nil
}

// spec returns the spec of the link named name.
func (w *world) spec(name string) linkSpec {
	for _, s := range w.specs {
		if s.name == name {
			return s
		}
	}
	w.t.Fatalf("no link %q", name)
	return linkSpec{}
}

// count records one factory call of factory name.
func (w *world) count(ctx context.Context, name string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if di, ok := rendr.CarrierDialInfo(ctx); ok && di.Probe {
		w.probes[name]++
		return
	}
	w.calls[name] = append(w.calls[name], time.Now())
}

// dials returns the session factory calls of factory name so far.
func (w *world) dials(name string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.calls[name])
}

// dialsIn returns the session factory calls of factory name made in
// [from, to).
func (w *world) dialsIn(name string, from, to time.Time) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, at := range w.calls[name] {
		if !at.Before(from) && at.Before(to) {
			n++
		}
	}
	return n
}

// peer returns a dialer Peer over the links named, in that order.
func (w *world) peer(names ...string) *rendr.Peer {
	w.t.Helper()
	var cs []rendr.Carrier
	for _, n := range names {
		s, l := w.spec(n), w.link(n)
		cs = append(cs, rendr.StreamCarrier{Name: n, Props: s.props, Dial: func(ctx context.Context) (net.Conn, error) {
			w.count(ctx, n)
			return l.Dial(ctx)
		}})
	}
	p, err := w.d.NewPeer(rendr.PeerConfig{Carriers: cs})
	if err != nil {
		w.t.Fatalf("NewPeer: %v", err)
	}
	w.mu.Lock()
	w.peers = append(w.peers, p)
	w.mu.Unlock()
	return p
}

// ingress is the dialer side of one forwarded L4 connection: the client
// end of a TargetPipe that the test drives, the l4.Dial Conn, its State
// when l4.Dial returned (StatePending: an EarlyReturn opening deferred to
// the first Write, Read or CloseWrite) and the ingress Forward's result.
type ingress struct {
	addr   string
	cli    *rendrtest.TargetConn
	c      *rendr.Conn
	dialed rendr.State
	res    <-chan l4.ForwardResult
	quit   <-chan struct{} // the world's quit
}

// ingress dials addr through p with o and starts the ingress Forward
// between the Conn and the server end of a TargetPipe; idle > 0 sets the
// session's idle limit before Forward starts.
func (w *world) ingress(p *rendr.Peer, addr string, o rendr.DialOptions, idle time.Duration) (*ingress, error) {
	c, err := l4.Dial(context.Background(), p, addr, o)
	if err != nil {
		return nil, err
	}
	dialed := c.Status().State
	if idle > 0 {
		if err := c.SetIdleTimeout(idle); err != nil {
			c.Close()
			return nil, fmt.Errorf("SetIdleTimeout: %w", err)
		}
	}
	cli, srv := rendrtest.TargetPipe(0)
	w.mu.Lock()
	w.clients = append(w.clients, cli)
	w.mu.Unlock()
	res := make(chan l4.ForwardResult, 1)
	go func() { res <- l4.Forward(context.Background(), c, srv) }()
	return &ingress{addr: addr, cli: cli, c: c, dialed: dialed, res: res, quit: w.quit}, nil
}

// mustIngress is ingress failing the test on an error.
func (w *world) mustIngress(p *rendr.Peer, addr string, o rendr.DialOptions, idle time.Duration) *ingress {
	w.t.Helper()
	in, err := w.ingress(p, addr, o, idle)
	if err != nil {
		w.t.Fatalf("ingress %s: %v", addr, err)
	}
	return in
}

// result waits up to within (virtual) for the ingress Forward's result.
func (in *ingress) result(within time.Duration) (l4.ForwardResult, error) {
	select {
	case r := <-in.res:
		return r, nil
	case <-time.After(within):
		return l4.ForwardResult{}, fmt.Errorf("%s: the ingress Forward did not end within %v: %+v", in.addr, within, in.c.Status())
	}
}

// shutdown closes quit and the ingresses' client ends (so that a row that
// failed with traffic goroutines still pacing or blocked on them ends
// cleanly instead of leaving the bubble deadlocked), the Peers, both
// Runtimes (the dialer first), waits for Serve, then closes the targets,
// tampers and links (once; also the cleanup of a failed test).
func (w *world) shutdown() {
	w.shutOnce.Do(func() {
		close(w.quit)
		w.mu.Lock()
		peers, clients := slices.Clone(w.peers), slices.Clone(w.clients)
		w.mu.Unlock()
		for _, cli := range clients {
			cli.Close()
		}
		for _, p := range peers {
			p.Close()
		}
		w.d.Close()
		w.p.Close()
		select {
		case w.served = <-w.serveDone:
		case <-time.After(time.Minute):
			w.t.Errorf("Serve did not return within a minute of Runtime.Close: %+v", w.srv.Status())
		}
		w.serveCancel()
		w.mu.Lock()
		closers := slices.Clone(w.closers)
		w.mu.Unlock()
		for _, f := range closers {
			f()
		}
		for _, l := range w.links {
			l.Close()
		}
	})
}

// close shuts the world down and requires that Serve returned
// net.ErrClosed with no handler, hook call or connection left, that
// neither Runtime holds a session, a handshake, a sessionless or shared
// carrier, an actor or a buffered byte any more, that nothing was
// abandoned, and that the session registry is back at its value before
// the world (R1-24).
func (w *world) close() {
	w.t.Helper()
	w.shutdown()
	if !errors.Is(w.served, net.ErrClosed) {
		w.t.Fatalf("Serve returned %v, want net.ErrClosed after Runtime.Close", w.served)
	}
	if st := w.srv.Status(); st.Dialing != 0 || st.Live != 0 || st.Hooks != 0 || st.Abandoned != 0 {
		w.t.Fatalf("Server state left after Runtime.Close: %+v", plain(st))
	}
	for _, rt := range []*rendr.Runtime{w.d, w.p} {
		st := rt.Status()
		sc := st.Sessions
		if sc.Open+sc.Pending+sc.Lingering+sc.Orphaned != 0 || st.Handshakes != 0 || st.Sessionless != 0 || st.Actors != 0 ||
			st.BufferedBytes != 0 || st.Abandoned != 0 || st.AcceptBacklog != [2]int{} || st.Mux.Carriers != 0 || st.Mux.Views != 0 {
			w.t.Fatalf("Runtime %v left state after Close: %+v", rt.InstanceID(), st)
		}
	}
	if l, p := testhooks.LiveSessions.Load()-w.live0, testhooks.ParkedSessions.Load()-w.parked0; l != 0 || p != 0 {
		w.t.Fatalf("session registry after Runtime.Close: %+d live, %+d parked", l, p)
	}
}

// noViolation fails when a carrier of either Runtime ended with
// protocol_violation.
func (w *world) noViolation() {
	w.t.Helper()
	for i, l := range []*eventLog{w.dev, w.pev} {
		for _, ev := range l.of(rendr.EventCarrierDown) {
			if ev.Cause == rendr.CauseProtocolViolation {
				w.t.Fatalf("%s carrier %d ended with protocol_violation: %+v", side(i), ev.Carrier, ev)
			}
		}
	}
}

// activeLink returns the link carrying c's data (its active carrier),
// waiting up to within for one.
func (w *world) activeLink(c *rendr.Conn, within time.Duration) (*rendrtest.Link, rendr.CarrierStatus) {
	w.t.Helper()
	var cs rendr.CarrierStatus
	waitFor(w.t, within, "an active carrier", func() bool {
		var ok bool
		cs, ok = active(c.Status())
		return ok
	})
	return w.link(cs.Name), cs
}

// plain is st without LastErr (for messages).
func plain(st l4.ServerStatus) l4.ServerStatus {
	st.LastErr = nil
	return st
}

// side names end i: 0 the dialer, 1 the passive.
func side(i int) string { return [2]string{"dialer", "passive"}[i] }

// eventLog records Config.OnEvent calls.
type eventLog struct {
	mu  sync.Mutex
	evs []rendr.Event
}

func (l *eventLog) add(ev rendr.Event) {
	l.mu.Lock()
	l.evs = append(l.evs, ev)
	l.mu.Unlock()
}

// of returns the recorded events of kind k.
func (l *eventLog) of(k rendr.EventKind) []rendr.Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []rendr.Event
	for _, ev := range l.evs {
		if ev.Kind == k {
			out = append(out, ev)
		}
	}
	return out
}

// downOf returns the EventCarrierDown events of carrier id (one per
// session that held a lane on it).
func (l *eventLog) downOf(id rendr.CarrierID) []rendr.Event {
	var out []rendr.Event
	for _, ev := range l.of(rendr.EventCarrierDown) {
		if ev.Carrier == id {
			out = append(out, ev)
		}
	}
	return out
}

// ends returns the EventSessionEnd events.
func (l *eventLog) ends() []rendr.Event { return l.of(rendr.EventSessionEnd) }

// waitFor polls cond every millisecond of virtual time until it holds,
// failing after within.
func waitFor(t testing.TB, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if !time.Now().Before(deadline) {
			t.Fatalf("timed out after %v waiting for %s", within, what)
		}
		time.Sleep(time.Millisecond)
	}
}

// eventually polls cond every millisecond (virtual) for up to within and
// reports whether it held (for goroutines other than the test's).
func eventually(within time.Duration, cond func() bool) bool {
	for end := time.Now().Add(within); !cond(); {
		if !time.Now().Before(end) {
			return false
		}
		time.Sleep(time.Millisecond)
	}
	return true
}

// sleepUntil sleeps until at (no-op when it passed).
func sleepUntil(at time.Time) {
	if d := time.Until(at); d > 0 {
		time.Sleep(d)
	}
}

// pace sleeps until at, or until quit is closed; it reports whether at
// was reached (false: the world is shutting down).
func pace(quit <-chan struct{}, at time.Time) bool {
	d := time.Until(at)
	if d <= 0 {
		select {
		case <-quit:
			return false
		default:
			return true
		}
	}
	tm := time.NewTimer(d)
	defer tm.Stop()
	select {
	case <-tm.C:
		return true
	case <-quit:
		return false
	}
}

// Status helpers.

// liveOf returns the attached live carriers (active or member).
func liveOf(st rendr.SessionStatus) []rendr.CarrierStatus {
	var out []rendr.CarrierStatus
	for _, c := range st.Carriers {
		if c.State == rendr.CarrierActive || c.State == rendr.CarrierMember {
			out = append(out, c)
		}
	}
	return out
}

// active returns the active carrier of a selector session.
func active(st rendr.SessionStatus) (rendr.CarrierStatus, bool) {
	for _, c := range st.Carriers {
		if c.State == rendr.CarrierActive {
			return c, true
		}
	}
	return rendr.CarrierStatus{}, false
}

// liveNamed returns the live carrier of factory name (dialer side).
func liveNamed(st rendr.SessionStatus, name string) (rendr.CarrierStatus, bool) {
	for _, c := range liveOf(st) {
		if c.Name == name {
			return c, true
		}
	}
	return rendr.CarrierStatus{}, false
}

// carrierOf returns the latest row of carrier id (live or among the recent
// dead).
func carrierOf(st rendr.SessionStatus, id rendr.CarrierID) (rendr.CarrierStatus, bool) {
	for i := len(st.Carriers) - 1; i >= 0; i-- {
		if c := st.Carriers[i]; c.ID == id {
			return c, true
		}
	}
	return rendr.CarrierStatus{}, false
}

// Traffic.

// sender is one direction's writer.
type sender struct {
	start time.Time
	done  chan struct{}
	err   error
	sent  atomic.Int64
}

// startSender writes size bytes of PRNG(seed) to wr in chunk-sized Writes,
// one every interval (an absolute schedule; 0: back to back), then calls
// fin (CloseWrite; nil: none). It stops when quit is closed.
func startSender(wr io.Writer, quit <-chan struct{}, seed uint64, size int64, chunk int, interval time.Duration, fin func() error) *sender {
	s := &sender{start: time.Now(), done: make(chan struct{})}
	go func() {
		defer close(s.done)
		src := rendrtest.PRNG(seed)
		buf := make([]byte, chunk)
		for k := 1; s.sent.Load() < size; k++ {
			n := min(int64(chunk), size-s.sent.Load())
			src.Read(buf[:n])
			if _, err := wr.Write(buf[:n]); err != nil {
				s.err = fmt.Errorf("Write after %d bytes: %w", s.sent.Load(), err)
				return
			}
			s.sent.Add(n)
			if interval > 0 && !pace(quit, s.start.Add(time.Duration(k)*interval)) {
				s.err = fmt.Errorf("stopped by the world's shutdown after %d bytes", s.sent.Load())
				return
			}
		}
		if fin != nil {
			if err := fin(); err != nil {
				s.err = fmt.Errorf("CloseWrite: %w", err)
			}
		}
	}()
	return s
}

// wait waits for the sender to finish; an error fails the test.
func (s *sender) wait(t testing.TB, within time.Duration) {
	t.Helper()
	if err := s.check(within); err != nil {
		t.Fatal(err)
	}
}

// check is wait returning its verdict.
func (s *sender) check(within time.Duration) error {
	select {
	case <-s.done:
	case <-time.After(within):
		return fmt.Errorf("the sender did not finish within %v (%d bytes sent)", within, s.sent.Load())
	}
	return s.err
}

// receiver is one direction's verified reader.
type receiver struct {
	v     *rendrtest.Verifier
	size  int64
	start time.Time
	done  chan struct{}
	err   error // the verifier's verdict (nil: exactly size bytes, then io.EOF)
	// readErr is the Read error that ended the stream (nil when the
	// verifier stopped it: bad is then set, a byte that was not the next
	// of PRNG(seed) or one past size).
	readErr error
	bad     bool
	got     atomic.Int64

	mu sync.Mutex
	at []time.Time // when each Read that returned bytes returned
}

// startReceiver reads r to its end through a verifier of size bytes of
// PRNG(seed).
func startReceiver(r io.Reader, seed uint64, size int64) *receiver {
	rc := &receiver{v: rendrtest.NewVerifier(seed, size), size: size, start: time.Now(), done: make(chan struct{})}
	go func() {
		defer close(rc.done)
		buf := make([]byte, 64<<10)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				now := time.Now()
				if _, werr := rc.v.Write(buf[:n]); werr != nil {
					rc.err, rc.bad = rc.v.Done(werr), true
					return
				}
				rc.got.Add(int64(n))
				rc.mu.Lock()
				rc.at = append(rc.at, now)
				rc.mu.Unlock()
			}
			if err != nil {
				rc.err, rc.readErr = rc.v.Done(err), err
				return
			}
		}
	}()
	return rc
}

// wait waits for the receiver's end; anything but exactly size verified
// bytes followed by io.EOF fails the test.
func (r *receiver) wait(t testing.TB, within time.Duration) {
	t.Helper()
	if err := r.check(within); err != nil {
		t.Fatal(err)
	}
}

// check is wait returning its verdict.
func (r *receiver) check(within time.Duration) error {
	select {
	case <-r.done:
	case <-time.After(within):
		return fmt.Errorf("the receiver did not finish within %v (%d of %d bytes)", within, r.got.Load(), r.size)
	}
	if r.err != nil {
		return fmt.Errorf("integrity: %w", r.err)
	}
	return nil
}

// end returns the time of the last Read that returned bytes.
func (r *receiver) end() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.at) == 0 {
		return r.start
	}
	return r.at[len(r.at)-1]
}

// maxGap returns the longest interval in [from, to] without a Read that
// returned bytes (the ends count as Reads), and where it starts.
func (r *receiver) maxGap(from, to time.Time) (gap time.Duration, at time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	last := from
	for _, a := range r.at {
		if a.Before(from) || a.After(to) {
			continue
		}
		if g := a.Sub(last); g > gap {
			gap, at = g, last
		}
		last = a
	}
	if g := to.Sub(last); g > gap {
		gap, at = g, last
	}
	return gap, at
}

// firstAfter returns the first Read that returned bytes after at (zero:
// none).
func (r *receiver) firstAfter(at time.Time) time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	i, _ := slices.BinarySearchFunc(r.at, at, func(a, b time.Time) int { return a.Compare(b) })
	for ; i < len(r.at); i++ {
		if r.at[i].After(at) {
			return r.at[i]
		}
	}
	return time.Time{}
}

// Error classes.

// isReset reports whether err is a TargetPipe's connection reset.
func isReset(err error) bool { return errors.Is(err, rendrtest.ErrReset) }

// abortOf returns the code of an *rendr.AbortError and whether it came
// from the peer.
func abortOf(err error) (code rendr.AbortCode, remote, ok bool) {
	var ae *rendr.AbortError
	if !errors.As(err, &ae) {
		return 0, false, false
	}
	return ae.Code, ae.Remote, true
}

// checkReject is nil when err is an l4 refusal with code and the code's
// fixed text as its message (a row without carrier kills).
func checkReject(err error, code l4.RejectCode) error { return checkRefusal(err, code, false) }

// checkRejectKilled is checkReject for a row with carrier kills: the
// message may also be empty. An OPEN retried after a kill took its
// OPEN_ACK down is answered by the passive's tombstone, and on a view of a
// shared trunk that answer is a fixed-size refusal record without the
// message (M3-D12); the code is the contract (l4's package doc).
func checkRejectKilled(err error, code l4.RejectCode) error { return checkRefusal(err, code, true) }

func checkRefusal(err error, code l4.RejectCode, emptyMsg bool) error {
	var re *rendr.RejectError
	if !errors.As(err, &re) || !errors.Is(err, rendr.ErrRejected) {
		return fmt.Errorf("got %v, want a refusal %#x (%v)", err, uint32(code), code)
	}
	if got, ok := l4.CodeOf(err); !ok || got != code || (re.Msg != code.String() && (!emptyMsg || re.Msg != "")) {
		return fmt.Errorf("got refusal %#x %q, want %#x %q", re.Code, re.Msg, uint32(code), code.String())
	}
	return nil
}

// totals is c without its per-connection records (for messages).
func totals(c rendrtest.TargetCounts) rendrtest.TargetCounts {
	c.Conns = nil
	return c
}

// prngSum is the SHA-256 of the first n bytes of PRNG(seed).
func prngSum(seed uint64, n int64) [32]byte {
	h := sha256.New()
	io.CopyN(h, rendrtest.PRNG(seed), n)
	var sum [32]byte
	h.Sum(sum[:0])
	return sum
}
