package race

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Scenario kit of package race. A world is two Runtimes — the dialer d
// (role A) and the passive p (role B) with one push-only Listener — built
// with testhooks.NewRuntime and joined by rendrtest.Links (stream) and
// rendrtest.DatagramLinks (packet) whose Accept is the Listener's Handle or
// HandlePacket, so every carrier goes through the whole handshake and
// admission. The dialer's datagram factories record the conn of every
// session carrier by its CarrierID (rendr.CarrierDialInfo), so that a test
// can close one under rendr (the gold cases' local close, F10). Everything
// is created inside the synctest bubble that uses it and closed before the
// bubble ends; the bubble itself fails if a goroutine outlives it, and
// close checks that neither Runtime holds state and that the session
// registry is back where it was (R1-24).

// linkSpec is one path of a world.
type linkSpec struct {
	name   string
	oneWay time.Duration // both directions
	rate   float64       // bytes/s per direction; 0 = unlimited (stream links only)
	props  rendr.Props   // the factory's Props
	dgram  bool          // a DatagramLink (packet sessions) instead of a Link
}

// worldOpts configures a world.
type worldOpts struct {
	dcfg, pcfg rendr.Config        // OnEvent is set by the world
	ov         testhooks.Overrides // both Runtimes
	mtu        int                 // datagram factories' frame budget (0: 1223, carrier/udp's default less its flow header)
}

// world is one scenario's two Runtimes and links.
type world struct {
	t        testing.TB
	d, p     *rendr.Runtime
	ln       *rendr.Listener
	specs    []linkSpec
	links    map[string]*rendrtest.Link
	dlinks   map[string]*rendrtest.DatagramLink
	dev, pev *eventLog
	mtu      int
	peers    []*rendr.Peer

	live0, parked0 int64
	shutOnce       sync.Once
	stops          []chan struct{} // the traffic generators' stops, closed by shutdown

	mu    sync.Mutex
	conns map[rendr.CarrierID]net.PacketConn // the dialer's datagram session carrier conns
}

// newWorld builds the Runtimes, the Listener and one link per spec. A
// cleanup shuts everything down if the test fails before close.
func newWorld(t testing.TB, o worldOpts, specs ...linkSpec) *world {
	t.Helper()
	w := &world{t: t, specs: specs, links: map[string]*rendrtest.Link{}, dlinks: map[string]*rendrtest.DatagramLink{},
		dev: &eventLog{}, pev: &eventLog{}, mtu: o.mtu, conns: map[rendr.CarrierID]net.PacketConn{},
		live0: testhooks.LiveSessions.Load(), parked0: testhooks.ParkedSessions.Load()}
	if w.mtu == 0 {
		w.mtu = 1223
	}
	o.dcfg.OnEvent, o.pcfg.OnEvent = w.dev.add, w.pev.add
	dov, pov := o.ov, o.ov
	w.d = newRuntime(t, o.dcfg, &dov)
	w.p = newRuntime(t, o.pcfg, &pov)
	t.Cleanup(w.shutdown)
	ln, err := w.p.Listen(rendr.ListenConfig{})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	w.ln = ln
	for _, s := range specs {
		if s.dgram {
			l := rendrtest.NewDatagramLink(rendrtest.DatagramLinkConfig{Name: s.name, Accept: ln.HandlePacket, Queue: 16384})
			for _, d := range bothDirs {
				l.SetDelay(d, s.oneWay, 0)
			}
			w.dlinks[s.name] = l
			continue
		}
		l := rendrtest.NewLink(rendrtest.LinkConfig{Name: s.name, Accept: ln.Handle})
		l.SetDelay(s.oneWay, 0)
		l.SetRate(s.rate)
		w.links[s.name] = l
	}
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

// bothDirs are the two directions of a link (Up: dialer → passive, A → B;
// Down: passive → dialer, B → A).
var bothDirs = []rendrtest.Dir{rendrtest.Up, rendrtest.Down}

// link returns the stream link named name.
func (w *world) link(name string) *rendrtest.Link {
	if l := w.links[name]; l != nil {
		return l
	}
	w.t.Fatalf("no stream link %q", name)
	return nil
}

// dlink returns the datagram link named name.
func (w *world) dlink(name string) *rendrtest.DatagramLink {
	if l := w.dlinks[name]; l != nil {
		return l
	}
	w.t.Fatalf("no datagram link %q", name)
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

// peer returns a dialer Peer over the links named, in that order.
func (w *world) peer(names ...string) *rendr.Peer {
	w.t.Helper()
	var cs []rendr.Carrier
	for _, n := range names {
		s := w.spec(n)
		if !s.dgram {
			cs = append(cs, rendr.StreamCarrier{Name: n, Dial: w.link(n).Dial, Props: s.props})
			continue
		}
		l := w.dlink(n)
		cs = append(cs, rendr.DatagramCarrier{Name: n, MTU: w.mtu, Props: s.props, Dial: func(ctx context.Context) (net.PacketConn, net.Addr, error) {
			pc, a, err := l.Dial(ctx)
			if di, ok := rendr.CarrierDialInfo(ctx); err == nil && ok && !di.Probe {
				w.mu.Lock()
				w.conns[di.Carrier] = pc
				w.mu.Unlock()
			}
			return pc, a, err
		}})
	}
	p, err := w.d.NewPeer(rendr.PeerConfig{Carriers: cs})
	if err != nil {
		w.t.Fatalf("NewPeer: %v", err)
	}
	w.peers = append(w.peers, p)
	return p
}

// open dials one stream session over p and confirms it on the passive: its
// dialer and passive ends.
func (w *world) open(p *rendr.Peer, o rendr.DialOptions) (dc, pc *rendr.Conn) {
	w.t.Helper()
	type dialed struct {
		c   *rendr.Conn
		err error
	}
	ch := make(chan dialed, 1)
	go func() {
		c, err := p.Dial(context.Background(), o)
		ch <- dialed{c, err}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pend, err := w.ln.Accept(ctx)
	if err != nil {
		w.t.Fatalf("Accept: %v", err)
	}
	pc, err = pend.Confirm()
	if err != nil {
		w.t.Fatalf("Confirm: %v", err)
	}
	r := <-ch
	if r.err != nil {
		w.t.Fatalf("Dial: %v", r.err)
	}
	return r.c, pc
}

// openPacket dials one packet session over p and confirms it on the
// passive.
func (w *world) openPacket(p *rendr.Peer, o rendr.DialOptions) (dc, pc *rendr.PacketConn) {
	w.t.Helper()
	type dialed struct {
		c   *rendr.PacketConn
		err error
	}
	ch := make(chan dialed, 1)
	go func() {
		c, err := p.DialPacket(context.Background(), o)
		ch <- dialed{c, err}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pp, err := w.ln.AcceptPacket(ctx)
	if err != nil {
		w.t.Fatalf("AcceptPacket: %v", err)
	}
	pc, err = pp.Confirm()
	if err != nil {
		w.t.Fatalf("Confirm: %v", err)
	}
	r := <-ch
	if r.err != nil {
		w.t.Fatalf("DialPacket: %v", r.err)
	}
	return r.c, pc
}

// localClose closes the dialer's conn of datagram carrier id under rendr
// (the gold cases' carrier.close, F10). It fails the test unless the
// carrier was registered and its Close returned nil.
func (w *world) localClose(id rendr.CarrierID) {
	w.t.Helper()
	w.mu.Lock()
	pc := w.conns[id]
	w.mu.Unlock()
	if pc == nil {
		w.t.Fatalf("stimulus: carrier %d has no registered conn", id)
	}
	if err := pc.Close(); err != nil {
		w.t.Fatalf("stimulus: closing carrier %d's conn: %v", id, err)
	}
}

// shutdown closes the Peers, both Runtimes (the dialer first) and every
// link (once; also the cleanup of a failed test).
func (w *world) shutdown() {
	w.shutOnce.Do(func() {
		for _, c := range w.stops {
			select {
			case <-c:
			default:
				close(c)
			}
		}
		for _, p := range w.peers {
			p.Close()
		}
		w.d.Close()
		w.p.Close()
		for _, l := range w.links {
			l.Close()
		}
		for _, l := range w.dlinks {
			l.Close()
		}
	})
}

// close shuts the world down and requires that neither Runtime holds a
// session, a handshake, a sessionless carrier, a flow, an actor or a
// buffered byte any more, that nothing was abandoned, and that the session
// registry is back at its value before the world (R1-24).
func (w *world) close() {
	w.t.Helper()
	w.shutdown()
	for _, rt := range []*rendr.Runtime{w.d, w.p} {
		st := rt.Status()
		sc := st.Sessions
		if sc.Open+sc.Pending+sc.Lingering+sc.Orphaned != 0 || st.Handshakes != 0 || st.Sessionless != 0 || st.Actors != 0 ||
			st.BufferedBytes != 0 || st.Abandoned != 0 || st.AcceptBacklog != [2]int{} ||
			st.Datagram.Flows != 0 || st.Datagram.Sources != 0 || st.Datagram.Admitting != 0 {
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

// side names end i: 0 the dialer (A), 1 the passive (B).
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

// downOf returns the EventCarrierDown of carrier id, if any.
func (l *eventLog) downOf(id rendr.CarrierID) (rendr.Event, bool) {
	for _, ev := range l.of(rendr.EventCarrierDown) {
		if ev.Carrier == id {
			return ev, true
		}
	}
	return rendr.Event{}, false
}

// waitFor polls cond every millisecond of virtual time until it holds,
// failing after within. Polling only waits for the sessions' own timers;
// the bubble makes it deterministic.
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

// sleepUntil sleeps until at (no-op when it passed).
func sleepUntil(at time.Time) {
	if d := time.Until(at); d > 0 {
		time.Sleep(d)
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

// liveNamed returns the live carrier of factory name (dialer side).
func liveNamed(st rendr.SessionStatus, name string) (rendr.CarrierStatus, bool) {
	for _, c := range liveOf(st) {
		if c.Name == name {
			return c, true
		}
	}
	return rendr.CarrierStatus{}, false
}

// carrierOf returns the carrier with ID id (live or among the recent dead).
func carrierOf(st rendr.SessionStatus, id rendr.CarrierID) (rendr.CarrierStatus, bool) {
	for _, c := range st.Carriers {
		if c.ID == id {
			return c, true
		}
	}
	return rendr.CarrierStatus{}, false
}

// twoMembers reports that both ends list two live race members.
func twoMembers(dc, pc interface{ Status() rendr.SessionStatus }) bool {
	return len(liveOf(dc.Status())) == 2 && len(liveOf(pc.Status())) == 2
}

// Stream traffic. A sender writes PRNG(seed) bytes on one Conn, as fast as
// the session takes them (bulk) or paced in 10-ms slots, then half-closes;
// a receiver reads them on the other Conn through a rendrtest.Verifier
// (byte for byte, exactly size bytes, then io.EOF) and records when each
// Read returned and how many bytes it had then, so that delivery gaps can
// be placed in time.

// slot is the paced sender's send slot.
const slot = 10 * time.Millisecond

// sender is one direction's writer.
type sender struct {
	start time.Time
	stop  chan struct{} // closed by the world's shutdown
	done  chan struct{}
	err   error
	sent  atomic.Int64
}

// startSender writes size bytes of PRNG(seed) on c and then calls
// CloseWrite; rate > 0 paces it at rate bytes/s in slot-sized steps.
func (w *world) startSender(c *rendr.Conn, seed uint64, size int64, rate float64) *sender {
	s := &sender{start: time.Now(), stop: make(chan struct{}), done: make(chan struct{})}
	w.stops = append(w.stops, s.stop)
	go func() {
		defer close(s.done)
		src := rendrtest.PRNG(seed)
		buf := make([]byte, 64<<10)
		for k := 1; s.sent.Load() < size; k++ {
			n := min(int64(len(buf)), size-s.sent.Load())
			if rate > 0 {
				n = min(size, int64(rate*float64(k)*slot.Seconds())) - s.sent.Load()
			}
			for n > 0 {
				m := min(n, int64(len(buf)))
				src.Read(buf[:m])
				if _, err := c.Write(buf[:m]); err != nil {
					s.err = fmt.Errorf("Write after %d bytes: %w", s.sent.Load(), err)
					return
				}
				s.sent.Add(m)
				n -= m
			}
			if rate > 0 {
				select {
				case <-s.stop:
					s.err = fmt.Errorf("stopped after %d bytes", s.sent.Load())
					return
				case <-time.After(time.Until(s.start.Add(time.Duration(k) * slot))):
				}
			}
		}
		if err := c.CloseWrite(); err != nil {
			s.err = fmt.Errorf("CloseWrite: %w", err)
		}
	}()
	return s
}

// wait waits for the sender to finish; an error fails the test.
func (s *sender) wait(t testing.TB, within time.Duration) {
	t.Helper()
	select {
	case <-s.done:
	case <-time.After(within):
		t.Fatalf("the sender did not finish within %v (%d bytes sent)", within, s.sent.Load())
	}
	if s.err != nil {
		t.Fatal(s.err)
	}
}

// receiver is one direction's verified reader.
type receiver struct {
	v     *rendrtest.Verifier
	size  int64
	start time.Time
	done  chan struct{}
	err   error // the verifier's verdict (nil: exactly size bytes, then io.EOF)
	got   atomic.Int64

	mu  sync.Mutex
	at  []time.Time // when each Read that returned bytes returned
	cum []int64     // bytes received after that Read
}

// startReceiver reads c to its end through a verifier of size bytes of
// PRNG(seed).
func startReceiver(c *rendr.Conn, seed uint64, size int64) *receiver {
	r := &receiver{v: rendrtest.NewVerifier(seed, size), size: size, start: time.Now(), done: make(chan struct{})}
	go func() {
		defer close(r.done)
		buf := make([]byte, 64<<10)
		for {
			n, err := c.Read(buf)
			if n > 0 {
				now := time.Now()
				if _, werr := r.v.Write(buf[:n]); werr != nil {
					r.err = r.v.Done(err)
					return
				}
				got := r.got.Add(int64(n))
				r.mu.Lock()
				r.at = append(r.at, now)
				r.cum = append(r.cum, got)
				r.mu.Unlock()
			}
			if err != nil {
				r.err = r.v.Done(err)
				return
			}
		}
	}()
	return r
}

// wait waits for the receiver's end; anything but exactly size verified
// bytes followed by io.EOF fails the test.
func (r *receiver) wait(t testing.TB, within time.Duration) {
	t.Helper()
	select {
	case <-r.done:
	case <-time.After(within):
		t.Fatalf("the receiver did not finish within %v (%d of %d bytes)", within, r.got.Load(), r.size)
	}
	if r.err != nil {
		t.Fatalf("integrity: %v", r.err)
	}
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

// firstAfter returns the first Read that returned bytes at or after at
// (zero: none).
func (r *receiver) firstAfter(at time.Time) time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	i, _ := slices.BinarySearchFunc(r.at, at, func(a, b time.Time) int { return a.Compare(b) })
	if i == len(r.at) {
		return time.Time{}
	}
	return r.at[i]
}

// finish closes both ends of a session whose traffic ended and requires a
// clean end: both sessions end within Linger with io.EOF.
func finish(t testing.TB, dc, pc *rendr.Conn) {
	t.Helper()
	dc.Close()
	pc.Close()
	timeout := time.After(30 * time.Second) // Linger
	for _, c := range []*rendr.Conn{dc, pc} {
		select {
		case <-c.Done():
		case <-timeout:
			t.Fatalf("a session did not end within Linger: %+v", c.Status())
		}
		if st := c.Status(); st.State != rendr.StateEnded || !errors.Is(st.Err, io.EOF) {
			t.Fatalf("%v session ended %v with %v, want io.EOF", st.Role, st.State, st.Err)
		}
	}
}

// droppedCause requires the death records of carrier id, blackholed at
// drop, on both ends (it waits up to 10 s, the session living on its other
// member), each with ping_timeout or write_stall: the gold's "the dropped
// member's cause ∈ {ping_timeout, write_stall} on both ends" (B1.6, B1.8).
// The test blackholes the link in BlackholeCloses mode, as an nft DROP:
// the close of the end whose verdict comes first does not cross, so the
// other end must reach a verdict of its own too — a transport_error there
// would be the Link's close, not the end's detection.
func droppedCause(t testing.TB, w *world, dc, pc *rendr.Conn, id rendr.CarrierID, drop time.Time) {
	t.Helper()
	var evs [2]rendr.Event
	for i, l := range []*eventLog{w.dev, w.pev} {
		waitFor(t, 10*time.Second, side(i)+"'s death record of the dropped carrier", func() bool {
			var ok bool
			evs[i], ok = l.downOf(id)
			return ok
		})
	}
	for i, c := range []*rendr.Conn{dc, pc} {
		ev := evs[i]
		if ev.Cause != rendr.CausePingTimeout && ev.Cause != rendr.CauseWriteStall || ev.Time.Before(drop) {
			t.Errorf("the %s's death record of the dropped carrier %d at DROP %+v: %+v, want ping_timeout or write_stall after the DROP",
				side(i), id, ev.Time.Sub(drop), ev)
		}
		if cs, ok := carrierOf(c.Status(), id); !ok || cs.State != rendr.CarrierDead || cs.DeathCause != ev.Cause {
			t.Errorf("the %s's status of the dropped carrier %d: %+v (found %v), want dead with %v", side(i), id, cs, ok, ev.Cause)
		}
		t.Logf("%s: the dropped carrier %d dead with %v at DROP +%v", side(i), id, ev.Cause, ev.Time.Sub(drop))
	}
	if t.Failed() {
		t.FailNow()
	}
}
