package mux

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Scenario kit of package mux. A world is two Runtimes — the dialer d
// (role A) and the passive p (role B) with one Listener — built with
// testhooks.NewRuntime and joined by rendrtest.Links (stream) and
// rendrtest.DatagramLinks (packet) whose Accept is the Listener's Handle or
// HandlePacket behind a counter, so every carrier goes through the whole
// handshake and admission and the test knows how many carriers the
// passive accepted per link. Every factory call goes through a wrapper
// that counts the session carriers' calls per factory (with their times)
// apart from the probe carriers' (rendr.CarrierDialInfo), so that a test
// can count the dials the pool made. The passive confirms every session
// and hands it to the test by its metadata, so sessions can be opened
// concurrently. Everything is created inside the synctest bubble that
// uses it and closed before the bubble ends; the bubble itself fails if a
// goroutine outlives it, and close checks that neither Runtime holds state
// and that the session registry is back where it was (R1-24).

// linkSpec is one path of a world; its name is also the factory's name.
type linkSpec struct {
	name   string
	oneWay time.Duration // both directions
	rate   float64       // bytes/s per direction; 0 = unlimited
	props  rendr.Props   // the factory's Props
	dgram  bool          // a DatagramLink (packet sessions only) instead of a Link
	buffer int           // a Link's buffer per direction (0: rendrtest's default, 2 MiB)
}

// worldOpts configures a world.
type worldOpts struct {
	dcfg, pcfg rendr.Config        // OnEvent is set by the world
	dov, pov   testhooks.Overrides // the dialer's and the passive's
	mtu        int                 // datagram factories' frame budget (0: 1223)
}

// world is one scenario's two Runtimes, Listener and links.
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

	accepts map[string]*atomic.Int64 // carriers the Listener received per link (sessions' and probes')

	live0, parked0 int64
	shutOnce       sync.Once
	acceptors      sync.WaitGroup
	stopMu         sync.Mutex
	stops          []chan struct{} // the traffic generators' stops, closed by shutdown

	mu      sync.Mutex
	calls   map[string][]time.Time             // session factory calls per factory, in call order
	probes  map[string]int                     // probe factory calls per factory
	conns   map[rendr.CarrierID]net.PacketConn // the dialer's datagram session carrier conns
	streams map[string]chan *rendr.Conn        // confirmed passive stream sessions by metadata
	packets map[string]chan *rendr.PacketConn  // confirmed passive packet sessions by metadata
}

// newWorld builds the Runtimes, the Listener, the passive's acceptors and
// one link per spec. A cleanup shuts everything down if the test fails
// before close.
func newWorld(t testing.TB, o worldOpts, specs ...linkSpec) *world {
	t.Helper()
	w := &world{t: t, specs: specs, links: map[string]*rendrtest.Link{}, dlinks: map[string]*rendrtest.DatagramLink{},
		dev: &eventLog{}, pev: &eventLog{}, mtu: o.mtu, accepts: map[string]*atomic.Int64{},
		calls: map[string][]time.Time{}, probes: map[string]int{}, conns: map[rendr.CarrierID]net.PacketConn{},
		streams: map[string]chan *rendr.Conn{}, packets: map[string]chan *rendr.PacketConn{},
		live0: testhooks.LiveSessions.Load(), parked0: testhooks.ParkedSessions.Load()}
	if w.mtu == 0 {
		w.mtu = 1223
	}
	o.dcfg.OnEvent, o.pcfg.OnEvent = w.dev.add, w.pev.add
	w.d = newRuntime(t, o.dcfg, &o.dov)
	w.p = newRuntime(t, o.pcfg, &o.pov)
	t.Cleanup(w.shutdown)
	ln, err := w.p.Listen(rendr.ListenConfig{})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	w.ln = ln
	for _, s := range specs {
		n := &atomic.Int64{}
		w.accepts[s.name] = n
		if s.dgram {
			l := rendrtest.NewDatagramLink(rendrtest.DatagramLinkConfig{Name: s.name, Queue: 16384,
				Accept: func(pc net.PacketConn, a net.Addr) error { n.Add(1); return ln.HandlePacket(pc, a) }})
			for _, d := range []rendrtest.Dir{rendrtest.Up, rendrtest.Down} {
				l.SetDelay(d, s.oneWay, 0)
				l.SetRate(d, s.rate)
			}
			w.dlinks[s.name] = l
			continue
		}
		l := rendrtest.NewLink(rendrtest.LinkConfig{Name: s.name, Buffer: s.buffer, Accept: func(c net.Conn) error { n.Add(1); return ln.Handle(c) }})
		l.SetDelay(s.oneWay, 0)
		l.SetRate(s.rate)
		w.links[s.name] = l
	}
	w.acceptors.Go(w.acceptStreams)
	w.acceptors.Go(w.acceptPackets)
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

// acceptStreams confirms every stream session and hands it over by its
// metadata, until the Listener closes.
func (w *world) acceptStreams() {
	for {
		pend, err := w.ln.Accept(context.Background())
		if err != nil {
			return
		}
		c, err := pend.Confirm()
		if err != nil {
			w.t.Errorf("Confirm %q: %v", pend.Metadata(), err)
			continue
		}
		w.streamCh(string(pend.Metadata())) <- c
	}
}

// acceptPackets confirms every packet session and hands it over by its
// metadata, until the Listener closes.
func (w *world) acceptPackets() {
	for {
		pend, err := w.ln.AcceptPacket(context.Background())
		if err != nil {
			return
		}
		c, err := pend.Confirm()
		if err != nil {
			w.t.Errorf("Confirm %q: %v", pend.Metadata(), err)
			continue
		}
		w.packetCh(string(pend.Metadata())) <- c
	}
}

func (w *world) streamCh(key string) chan *rendr.Conn {
	w.mu.Lock()
	defer w.mu.Unlock()
	ch, ok := w.streams[key]
	if !ok {
		ch = make(chan *rendr.Conn, 1)
		w.streams[key] = ch
	}
	return ch
}

func (w *world) packetCh(key string) chan *rendr.PacketConn {
	w.mu.Lock()
	defer w.mu.Unlock()
	ch, ok := w.packets[key]
	if !ok {
		ch = make(chan *rendr.PacketConn, 1)
		w.packets[key] = ch
	}
	return ch
}

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

// accepted returns the carriers the Listener received over link name.
func (w *world) accepted(name string) int64 { return w.accepts[name].Load() }

// peer returns a dialer Peer over the links named, in that order.
func (w *world) peer(names ...string) *rendr.Peer {
	w.t.Helper()
	var cs []rendr.Carrier
	for _, n := range names {
		s := w.spec(n)
		if !s.dgram {
			l := w.link(n)
			cs = append(cs, rendr.StreamCarrier{Name: n, Props: s.props, Dial: func(ctx context.Context) (net.Conn, error) {
				w.count(ctx, n)
				return l.Dial(ctx)
			}})
			continue
		}
		l := w.dlink(n)
		cs = append(cs, rendr.DatagramCarrier{Name: n, MTU: w.mtu, Props: s.props, Dial: func(ctx context.Context) (net.PacketConn, net.Addr, error) {
			w.count(ctx, n)
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

// pair is one stream session's dialer and passive ends.
type pair struct {
	key  string
	mode rendr.Mode
	d, p *rendr.Conn
}

// ppair is one packet session's dialer and passive ends.
type ppair struct {
	key  string
	mode rendr.Mode
	d, p *rendr.PacketConn
}

// open dials one stream session with metadata key over p and returns it
// once the passive confirmed it.
func (w *world) open(p *rendr.Peer, key string, mode rendr.Mode) pair {
	w.t.Helper()
	s, err := w.tryOpen(p, key, mode)
	if err != nil {
		w.t.Fatal(err)
	}
	return s
}

// tryOpen is open returning its error.
func (w *world) tryOpen(p *rendr.Peer, key string, mode rendr.Mode) (pair, error) {
	c, err := p.Dial(context.Background(), rendr.DialOptions{Mode: mode, Metadata: []byte(key)})
	if err != nil {
		return pair{}, fmt.Errorf("Dial %s (%v): %w", key, mode, err)
	}
	select {
	case pc := <-w.streamCh(key):
		return pair{key: key, mode: mode, d: c, p: pc}, nil
	case <-time.After(30 * time.Second):
		return pair{}, fmt.Errorf("session %s dialled but never confirmed on the passive", key)
	}
}

// openMany opens n stream sessions concurrently, keys prefix0 …, mode by
// index.
func (w *world) openMany(p *rendr.Peer, prefix string, n int, modeOf func(i int) rendr.Mode) []pair {
	w.t.Helper()
	ps := make([]pair, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			s, err := w.tryOpen(p, prefix+strconv.Itoa(i), modeOf(i))
			if err != nil {
				w.t.Error(err)
				return
			}
			ps[i] = s
		})
	}
	wg.Wait()
	if w.t.Failed() {
		w.t.FailNow()
	}
	return ps
}

// openPacket dials one packet session with metadata key over p and
// returns it once the passive confirmed it.
func (w *world) openPacket(p *rendr.Peer, key string, mode rendr.Mode) ppair {
	w.t.Helper()
	c, err := p.DialPacket(context.Background(), rendr.DialOptions{Mode: mode, Metadata: []byte(key)})
	if err != nil {
		w.t.Fatalf("DialPacket %s (%v): %v", key, mode, err)
	}
	select {
	case pc := <-w.packetCh(key):
		return ppair{key: key, mode: mode, d: c, p: pc}
	case <-time.After(30 * time.Second):
		w.t.Fatalf("packet session %s dialled but never confirmed on the passive", key)
	}
	return ppair{}
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

// addStop registers a traffic generator's stop channel with shutdown.
func (w *world) addStop(c chan struct{}) {
	w.stopMu.Lock()
	w.stops = append(w.stops, c)
	w.stopMu.Unlock()
}

// shutdown stops the generators, closes the Peers, both Runtimes (the
// dialer first; the passive's Close ends the acceptors) and every link
// (once; also the cleanup of a failed test).
func (w *world) shutdown() {
	w.shutOnce.Do(func() {
		w.stopMu.Lock()
		for _, c := range w.stops {
			select {
			case <-c:
			default:
				close(c)
			}
		}
		w.stopMu.Unlock()
		for _, p := range w.peers {
			p.Close()
		}
		w.d.Close()
		w.p.Close()
		w.acceptors.Wait()
		for _, l := range w.links {
			l.Close()
		}
		for _, l := range w.dlinks {
			l.Close()
		}
	})
}

// close shuts the world down and requires that neither Runtime holds a
// session, a handshake, a sessionless or shared carrier, a flow, an actor
// or a buffered byte any more, that nothing was abandoned, and that the
// session registry is back at its value before the world (R1-24).
func (w *world) close() {
	w.t.Helper()
	w.shutdown()
	for _, rt := range []*rendr.Runtime{w.d, w.p} {
		st := rt.Status()
		sc := st.Sessions
		if sc.Open+sc.Pending+sc.Lingering+sc.Orphaned != 0 || st.Handshakes != 0 || st.Sessionless != 0 || st.Actors != 0 ||
			st.BufferedBytes != 0 || st.Abandoned != 0 || st.AcceptBacklog != [2]int{} || st.Mux.Carriers != 0 || st.Mux.Views != 0 ||
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

// muxIdle waits until both Runtimes report no shared carrier and no view
// and every session carrier of every link is closed: every trunk closed
// at its last view (M3-D20), before Runtime.Close.
func (w *world) muxIdle(within time.Duration) {
	w.t.Helper()
	waitFor(w.t, within, "every shared carrier closed at its last session", func() bool {
		for _, rt := range []*rendr.Runtime{w.d, w.p} {
			if m := rt.Status().Mux; m.Carriers != 0 || m.Views != 0 {
				return false
			}
		}
		for _, l := range w.links {
			if _, open := sessionCarriers(l); open != 0 {
				return false
			}
		}
		return true
	})
}

// sessionCarriers counts a Link's carriers that carried a session (their
// first frame after the PREFACE was an OPEN or a JOIN) and those of them
// still open.
func sessionCarriers(l *rendrtest.Link) (all, open int) {
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

// sessionDown returns session sid's EventCarrierDown of carrier id.
func (l *eventLog) sessionDown(sid rendr.SessionID, id rendr.CarrierID) (rendr.Event, bool) {
	for _, ev := range l.downOf(id) {
		if ev.Session == sid {
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

// active returns the active carrier of a selector session.
func active(st rendr.SessionStatus) (rendr.CarrierStatus, bool) {
	for _, c := range st.Carriers {
		if c.State == rendr.CarrierActive {
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

// liveIDs returns the IDs of a session's live carriers.
func liveIDs(st rendr.SessionStatus) []rendr.CarrierID {
	var out []rendr.CarrierID
	for _, c := range liveOf(st) {
		out = append(out, c.ID)
	}
	slices.Sort(out)
	return out
}

// statuser is a session end (*rendr.Conn or *rendr.PacketConn).
type statuser interface{ Status() rendr.SessionStatus }

// muxIdentity checks Status.Mux of rt against the live carriers of the
// given session ends (all of that Runtime's sessions): Carriers = the
// distinct live carrier IDs, Views = their sum, and every live row reports
// Shared equal to its carrier's views; "" when every identity holds.
func muxIdentity(rt *rendr.Runtime, ends []statuser) string {
	views := map[rendr.CarrierID]int{}
	shared := map[rendr.CarrierID][]int{}
	for _, e := range ends {
		for _, cs := range e.Status().Carriers {
			if cs.State == rendr.CarrierDead {
				continue
			}
			views[cs.ID]++
			shared[cs.ID] = append(shared[cs.ID], cs.Shared)
		}
	}
	sum := 0
	for id, n := range views {
		sum += n
		for _, s := range shared[id] {
			if s != n {
				return fmt.Sprintf("carrier %v: %d session views, a view reports Shared %d", id, n, s)
			}
		}
	}
	if m := rt.Status().Mux; m.Carriers != len(views) || m.Views != sum {
		return fmt.Sprintf("Status.Mux %+v; the sessions hold %d views on %d carriers %v", m, sum, len(views), views)
	}
	return ""
}

// identities waits (at most 10 s) until muxIdentity holds on both
// Runtimes for the given sessions.
func (w *world) identities(when string, ps []pair, pps ...ppair) {
	w.t.Helper()
	var ds, pss []statuser
	for _, s := range ps {
		ds, pss = append(ds, s.d), append(pss, s.p)
	}
	for _, s := range pps {
		ds, pss = append(ds, s.d), append(pss, s.p)
	}
	var why string
	for deadline := time.Now().Add(10 * time.Second); ; {
		if why = muxIdentity(w.d, ds); why == "" {
			why = muxIdentity(w.p, pss)
		}
		if why == "" || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if why != "" {
		w.t.Fatalf("Status.Mux identities %s: %s", when, why)
	}
}
