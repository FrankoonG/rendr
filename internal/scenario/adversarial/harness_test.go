package adversarial

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The suite's kit. A world is two Runtimes — the dialer d and the passive
// p with one push-only Listener — built with testhooks.NewRuntime and
// joined by rendrtest links named "a" and "b" (stream Links and
// DatagramLinks): every session carrier goes through the whole handshake
// and admission. The dialer's factories send probe carriers (Probe in
// rendr.CarrierDialInfo) over separate links of their own, so that the
// session links, their counters and their one-shot controls see session
// carriers only. Every stream session carrier passes through a
// rendrtest.Tamper (dialer conn ↔ tamper ↔ Link), registered by its
// CarrierID; every datagram session carrier of the dialer passes through a
// dflipConn, and every passive datagram conn through one as well. Link "a"
// is 2 ms one way and "b" 3 ms, both linkRate: "a" ranks first, so the
// selector's carrier, race's ACK lane and the attacked member are on "a".
// Everything is created inside the synctest bubble that uses it and closed
// before the bubble ends.

// setup is one carrier setup a row runs against (§A9.3: "each row runs
// against a dedicated carrier (selector, bond and race sessions) and a
// 4-session MUX trunk"). Every row opens s.sessions sessions on each Peer
// it uses (openN, openPacketN), moves data on all of them and attacks a
// carrier of the first; with dedicated carriers every session has carriers
// of its own (Props.CheapSubflow), on a MUX trunk the sessions share the
// attacked carrier. The expectations that differ — the neighbours' Death
// migrations — branch on mux in neighbours and neighboursPacket; the rows
// whose stimulus hits every carrier of a link (a Kill) expect the same of
// every session either way.
type setup struct {
	name     string
	mode     rendr.Mode
	mux      bool        // the sessions share the attacked carrier (a MUX trunk)
	sessions int         // sessions on the Peer (dedicated: 1)
	props    rendr.Props // every factory's Props
}

// dedicatedSetups are the dedicated-carrier setups: CheapSubflow keeps
// every carrier of a session its own (M3-D2), whatever the Runtime would
// share.
func dedicatedSetups() []setup {
	own := rendr.Props{CheapSubflow: true}
	return []setup{
		{name: "selector", mode: rendr.ModeSelector, sessions: 1, props: own},
		{name: "bond", mode: rendr.ModeBond, sessions: 1, props: own},
		{name: "race", mode: rendr.ModeRace, sessions: 1, props: own},
	}
}

// muxSetups are the 4-session MUX trunk setups: zero Props let the Runtime
// share every carrier (the rendr mux is the default), so the four sessions
// of a Peer ride one trunk per link and the attacked carrier is theirs.
func muxSetups() []setup {
	return []setup{
		{name: "mux-selector", mode: rendr.ModeSelector, mux: true, sessions: 4, props: rendr.Props{}},
		{name: "mux-bond", mode: rendr.ModeBond, mux: true, sessions: 4, props: rendr.Props{}},
		{name: "mux-race", mode: rendr.ModeRace, mux: true, sessions: 4, props: rendr.Props{}},
	}
}

// setups are the setups every row runs against: the dedicated carriers,
// then the 4-session MUX trunks.
func setups() []setup { return slices.Concat(dedicatedSetups(), muxSetups()) }

// eachSetup runs body once per setup, each in a bubble of its own.
func eachSetup(t *testing.T, body func(t *testing.T, s setup)) {
	t.Helper()
	eachSetupOf(t, setups(), body)
}

// eachSetupOf runs body once per setup of ss, each in a bubble of its own.
func eachSetupOf(t *testing.T, ss []setup, body func(t *testing.T, s setup)) {
	t.Helper()
	for _, s := range ss {
		t.Run(s.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { body(t, s) })
		})
	}
}

// members reports whether s keeps several data members (bond, race).
func (s setup) members() bool { return s.mode == rendr.ModeBond || s.mode == rendr.ModeRace }

// worldOpts configures a world.
type worldOpts struct {
	ov testhooks.Overrides // to both Runtimes (counter presets must be equal, L14)
	// wrap, if set, wraps the conn rendr gets for every stream session
	// carrier (an embedder conn between rendr and the tamper).
	wrap func(link string, c net.Conn) net.Conn
	// record keeps a copy of every datagram each dialer session conn
	// wrote (dflipConn.sent), for the replay rows' choice of datagrams.
	record bool
	// links is the number of links ("a", "b", "c", ...; default 2).
	links int
	// hub adds a rendrtest.DatagramHub whose passive socket the Listener
	// reads through rendr.FromPacketConn (raw-UDP flows; hubPeer).
	hub bool
}

// world is one scenario's two Runtimes and links.
type world struct {
	t        testing.TB
	s        setup
	o        worldOpts
	d, p     *rendr.Runtime
	ln       *rendr.Listener
	dev, pev *eventLog
	live0    int64

	links   []*rendrtest.Link // session stream links, in name order
	probes  []*rendrtest.Link
	dlinks  []*rendrtest.DatagramLink
	dprobes []*rendrtest.DatagramLink
	hub     *rendrtest.DatagramHub // worldOpts.hub
	flip    *dflip

	mu      sync.Mutex
	tampers []*tamperRec
	onNew   func(tm *rendrtest.Tamper) // arms every new session tamper (armNew)
	onSess  rendr.SessionID            // of this session only (zero: any)
	dconns  []*dflipConn               // in dial order
	hubs    int                        // hub clients dialled (the next one's index)
	shut    sync.Once
}

// tamperRec is the tamper of one stream session carrier.
type tamperRec struct {
	id   rendr.CarrierID
	sess rendr.SessionID
	link string
	tm   *rendrtest.Tamper
}

// linkNames returns the names of n links.
func linkNames(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = string(rune('a' + i))
	}
	return out
}

// newWorld builds the Runtimes, the Listener and the stream and datagram
// links. A cleanup shuts everything down if the test fails before close.
func newWorld(t testing.TB, s setup, o worldOpts) *world {
	t.Helper()
	if o.links == 0 {
		o.links = 2
	}
	if o.ov.SelectorDwell == 0 {
		// No quality switch during a row: a selector's attacked carrier is
		// the one the row picked, and a bufferbloated "a" (its link queue
		// adds up to 16 ms) never loses to an idle "b".
		o.ov.SelectorDwell = time.Hour
	}
	w := &world{t: t, s: s, o: o, dev: &eventLog{}, pev: &eventLog{}, flip: newDflip(), live0: testhooks.LiveSessions.Load()}
	dov, pov := o.ov, o.ov
	w.d = newRuntime(t, rendr.Config{OnEvent: w.dev.add}, &dov)
	w.p = newRuntime(t, rendr.Config{OnEvent: w.pev.add}, &pov)
	t.Cleanup(w.shutdown)
	var lc rendr.ListenConfig
	if o.hub {
		w.hub = rendrtest.NewDatagramHub(rendrtest.DatagramHubConfig{Name: "hub", Queue: 16384})
		for _, d := range bothDirs {
			w.hub.SetDelay(d, 2*time.Millisecond, 0)
		}
		lc.Sources = []rendr.Source{rendr.FromPacketConn(w.hub.PacketConn())}
	}
	ln, err := w.p.Listen(lc)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	w.ln = ln
	for i, name := range linkNames(o.links) {
		delay := time.Duration(2+i) * time.Millisecond
		for _, probe := range []bool{false, true} {
			n := name
			if probe {
				n += "-probe"
			}
			l := rendrtest.NewLink(rendrtest.LinkConfig{Name: n, Accept: ln.Handle, Buffer: linkBuffer})
			l.SetDelay(delay, 0)
			l.SetRate(linkRate)
			accept := w.acceptPacket // the passive end of a session carrier passes through a dflipConn
			if probe {
				accept = ln.HandlePacket
			}
			dl := rendrtest.NewDatagramLink(rendrtest.DatagramLinkConfig{Name: n, Queue: 16384, Accept: accept})
			for _, d := range bothDirs {
				dl.SetDelay(d, delay, 0)
			}
			if probe {
				w.probes, w.dprobes = append(w.probes, l), append(w.dprobes, dl)
			} else {
				w.links, w.dlinks = append(w.links, l), append(w.dlinks, dl)
			}
		}
	}
	return w
}

// linkBuffer bounds the bytes a stream link holds per direction: a
// bandwidth-delay product, so that the bytes in flight between the
// tamper and the far end stay small and an operation armed mid-transfer
// meets the transfer's later frames.
const linkBuffer = 64 << 10

// linkRate is every stream link's rate: a row's transfer lasts long
// enough (half a virtual second) for its operation to land mid-transfer.
const linkRate = 4 << 20

// newRuntime builds a Runtime through testhooks (unclamped overrides).
func newRuntime(t testing.TB, cfg rendr.Config, ov *testhooks.Overrides) *rendr.Runtime {
	t.Helper()
	v, err := testhooks.NewRuntime(cfg, ov)
	if err != nil {
		t.Fatalf("testhooks.NewRuntime: %v", err)
	}
	return v.(*rendr.Runtime)
}

// bothDirs are the two directions of a link (Up: dialer → passive).
var bothDirs = []rendrtest.Dir{rendrtest.Up, rendrtest.Down}

// acceptPacket hands the passive end of a datagram carrier to the
// Listener through the passive side's flipping conn.
func (w *world) acceptPacket(pc net.PacketConn, peer net.Addr) error {
	return w.ln.HandlePacket(&dflipConn{PacketConn: pc, f: w.flip, dir: rendrtest.Down, hub: -1}, peer)
}

// link returns the session stream link called name.
func (w *world) link(name string) *rendrtest.Link {
	for _, l := range w.links {
		if l.Name() == name {
			return l
		}
	}
	w.t.Fatalf("no link %q", name)
	return nil
}

// dlink returns the session datagram link called name.
func (w *world) dlink(name string) *rendrtest.DatagramLink {
	for _, l := range w.dlinks {
		if l.Name() == name {
			return l
		}
	}
	w.t.Fatalf("no datagram link %q", name)
	return nil
}

// streamPeer returns a dialer Peer of stream factories over the session
// links (probes over the probe links); every session carrier passes
// through a registered Tamper.
func (w *world) streamPeer() *rendr.Peer {
	w.t.Helper()
	var cs []rendr.Carrier
	for i, l := range w.links {
		name, pl := l.Name(), w.probes[i]
		cs = append(cs, rendr.StreamCarrier{Name: name, Props: w.s.props, Dial: func(ctx context.Context) (net.Conn, error) {
			di, ok := rendr.CarrierDialInfo(ctx)
			if ok && di.Probe {
				return pl.Dial(ctx)
			}
			up, err := l.Dial(ctx)
			if err != nil {
				return nil, err
			}
			a, b := net.Pipe()
			w.addTamper(&tamperRec{id: di.Carrier, sess: di.Session, link: name, tm: rendrtest.NewTamper(b, up)})
			var c net.Conn = a
			if w.o.wrap != nil {
				c = w.o.wrap(name, c)
			}
			return c, nil
		}})
	}
	return w.newPeer(cs)
}

// datagramPeer returns a dialer Peer of datagram factories over the
// session datagram links named (all when none; probes over the probe
// links); every session carrier's conn is a registered dflipConn.
func (w *world) datagramPeer(names ...string) *rendr.Peer {
	w.t.Helper()
	var cs []rendr.Carrier
	for i, l := range w.dlinks {
		if len(names) > 0 && !slices.Contains(names, l.Name()) {
			continue
		}
		name, pl := l.Name(), w.dprobes[i]
		cs = append(cs, rendr.DatagramCarrier{Name: name, MTU: dgMTU, Props: w.s.props, Dial: func(ctx context.Context) (net.PacketConn, net.Addr, error) {
			di, ok := rendr.CarrierDialInfo(ctx)
			if ok && di.Probe {
				return pl.Dial(ctx)
			}
			// latestOn's dial order is the link's carrier order: dial
			// under w.mu.
			w.mu.Lock()
			defer w.mu.Unlock()
			pc, a, err := l.Dial(ctx)
			if err != nil {
				return nil, nil, err
			}
			c := &dflipConn{PacketConn: pc, f: w.flip, dir: rendrtest.Up, id: di.Carrier, link: name, hub: -1, record: w.o.record}
			w.dconns = append(w.dconns, c)
			return c, a, nil
		}})
	}
	return w.newPeer(cs)
}

// hubPeer returns a dialer Peer of datagram factories called names whose
// session carriers are clients of the hub (worldOpts.hub: raw-UDP flows
// into the passive's FromPacketConn source; probes over the probe link of
// the same name). Every session carrier's conn is a registered dflipConn
// that knows its hub client index (DatagramHub.ReplayFlow).
func (w *world) hubPeer(names ...string) *rendr.Peer {
	w.t.Helper()
	var cs []rendr.Carrier
	for _, name := range names {
		var pl *rendrtest.DatagramLink
		for _, l := range w.dprobes {
			if l.Name() == name+"-probe" {
				pl = l
			}
		}
		if pl == nil {
			w.t.Fatalf("no probe link for %q", name)
		}
		cs = append(cs, rendr.DatagramCarrier{Name: name, MTU: dgMTU, Props: w.s.props, Dial: func(ctx context.Context) (net.PacketConn, net.Addr, error) {
			di, ok := rendr.CarrierDialInfo(ctx)
			if ok && di.Probe {
				return pl.Dial(ctx)
			}
			// The hub numbers its clients in dial order: dial under w.mu.
			w.mu.Lock()
			defer w.mu.Unlock()
			pc, a, err := w.hub.Dial(ctx)
			if err != nil {
				return nil, nil, err
			}
			c := &dflipConn{PacketConn: pc, f: w.flip, dir: rendrtest.Up, id: di.Carrier, link: name, hub: w.hubs, record: w.o.record}
			w.hubs++
			w.dconns = append(w.dconns, c)
			return c, a, nil
		}})
	}
	return w.newPeer(cs)
}

// dgMTU is every datagram factory's frame budget (carrier/udp's default
// MaxDatagram 1232 less its 9-byte flow header).
const dgMTU = 1223

func (w *world) newPeer(cs []rendr.Carrier) *rendr.Peer {
	w.t.Helper()
	p, err := w.d.NewPeer(rendr.PeerConfig{Carriers: cs})
	if err != nil {
		w.t.Fatalf("NewPeer: %v", err)
	}
	return p
}

// addTamper registers a new session carrier's tamper and arms it when an
// armNew is active.
func (w *world) addTamper(r *tamperRec) {
	w.mu.Lock()
	w.tampers = append(w.tampers, r)
	f := w.onNew
	if w.onSess != (rendr.SessionID{}) && r.sess != w.onSess {
		f = nil
	}
	w.mu.Unlock()
	if f != nil {
		f(r.tm)
	}
}

// armNew makes f arm the tamper of every carrier dialled from now on for
// session sess (zero: any session), until disarm.
func (w *world) armNew(sess rendr.SessionID, f func(tm *rendrtest.Tamper)) {
	w.mu.Lock()
	w.onNew, w.onSess = f, sess
	w.mu.Unlock()
}

func (w *world) disarm() { w.armNew(rendr.SessionID{}, nil) }

// tamperOf returns the tamper of session carrier id.
func (w *world) tamperOf(id rendr.CarrierID) *rendrtest.Tamper {
	w.t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, r := range w.tampers {
		if r.id == id {
			return r.tm
		}
	}
	w.t.Fatalf("no tamper for carrier %d", id)
	return nil
}

// latestOn returns the dialer's conn of the latest datagram session
// carrier dialled on link name: the carrier DatagramLink.ReplayInto takes
// its datagrams from and replays into (with several sessions on dedicated
// carriers, not necessarily the first session's).
func (w *world) latestOn(name string) *dflipConn {
	w.t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	for i := len(w.dconns) - 1; i >= 0; i-- {
		if c := w.dconns[i]; c.link == name && c.hub < 0 {
			return c
		}
	}
	w.t.Fatalf("no datagram carrier on link %q", name)
	return nil
}

// latestHub returns the dialer's conn of the latest hub client dialled by
// factory name.
func (w *world) latestHub(name string) *dflipConn {
	w.t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	for i := len(w.dconns) - 1; i >= 0; i-- {
		if c := w.dconns[i]; c.link == name && c.hub >= 0 {
			return c
		}
	}
	w.t.Fatalf("no hub client of factory %q", name)
	return nil
}

// ownerOf returns the session of xs that has carrier id (any of them on a
// shared carrier).
func ownerOf(t testing.TB, xs []*ppair, id rendr.CarrierID) *ppair {
	t.Helper()
	for _, x := range xs {
		if _, ok := carrierOf(x.p.Status(), id); ok {
			return x
		}
	}
	t.Fatalf("no session has carrier %d", id)
	return nil
}

// dconnOf returns the dialer's conn of datagram session carrier id.
func (w *world) dconnOf(id rendr.CarrierID) *dflipConn {
	w.t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, c := range w.dconns {
		if c.id == id {
			return c
		}
	}
	w.t.Fatalf("no datagram conn for carrier %d", id)
	return nil
}

// open dials a stream session over p and confirms it: its two ends.
func (w *world) open(p *rendr.Peer) *pair {
	w.t.Helper()
	type dialed struct {
		c   *rendr.Conn
		err error
	}
	ch := make(chan dialed, 1)
	go func() {
		c, err := p.Dial(context.Background(), rendr.DialOptions{Mode: w.s.mode})
		ch <- dialed{c, err}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pend, err := w.ln.Accept(ctx)
	if err != nil {
		w.t.Fatalf("Accept: %v", err)
	}
	pc, err := pend.Confirm()
	if err != nil {
		w.t.Fatalf("Confirm: %v", err)
	}
	r := <-ch
	if r.err != nil {
		w.t.Fatalf("Dial(%v): %v", w.s.mode, r.err)
	}
	x := &pair{d: r.c, p: pc}
	x.waitMembers(w.t, w.s)
	return x
}

// openPacket dials a packet session over p and confirms it: its two ends.
func (w *world) openPacket(p *rendr.Peer) *ppair {
	w.t.Helper()
	type dialed struct {
		c   *rendr.PacketConn
		err error
	}
	ch := make(chan dialed, 1)
	go func() {
		c, err := p.DialPacket(context.Background(), rendr.DialOptions{Mode: w.s.mode})
		ch <- dialed{c, err}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pend, err := w.ln.AcceptPacket(ctx)
	if err != nil {
		w.t.Fatalf("AcceptPacket: %v", err)
	}
	pc, err := pend.Confirm()
	if err != nil {
		w.t.Fatalf("Confirm: %v", err)
	}
	r := <-ch
	if r.err != nil {
		w.t.Fatalf("DialPacket(%v): %v", w.s.mode, r.err)
	}
	x := &ppair{d: r.c, p: pc}
	if w.s.members() {
		waitFor(w.t, 10*time.Second, "two members on both ends", func() bool {
			return len(liveOf(x.d.Status())) == 2 && len(liveOf(x.p.Status())) == 2
		})
	}
	return x
}

// openN opens the setup's s.sessions stream sessions over p; the rows
// attack the first.
func (w *world) openN(p *rendr.Peer) []*pair {
	w.t.Helper()
	xs := make([]*pair, w.s.sessions)
	for i := range xs {
		xs[i] = w.open(p)
	}
	return xs
}

// openPacketN opens the setup's s.sessions packet sessions over p; the
// rows attack the first.
func (w *world) openPacketN(p *rendr.Peer) []*ppair {
	w.t.Helper()
	xs := make([]*ppair, w.s.sessions)
	for i := range xs {
		xs[i] = w.openPacket(p)
	}
	return xs
}

// neighbours requires what an attack on a carrier of xs[0] did to the
// other sessions of its Peer: own Death migrations each on dedicated
// carriers (0, untouched, unless the stimulus killed a whole link), and
// shared on a MUX trunk (the attacked session's own count when they shared
// the carrier that died; 0 on a datagram trunk, which drops and lives).
func neighbours(t testing.TB, s setup, xs []*pair, own, shared uint64) {
	t.Helper()
	d := own
	if s.mux {
		d = shared
	}
	for i, x := range xs[1:] {
		if d > 0 {
			x.deathsAre(t, s, d)
			continue
		}
		untouched(t, fmt.Sprintf("neighbour session %d", i+1), x)
	}
}

// kill names the carrier an attack killed: its ID, the cause and which end
// detected it (dialer: a Down attack; else the passive). A zero id names
// no one carrier (a stimulus that cut whole links).
type kill struct {
	id     rendr.CarrierID
	cause  rendr.Cause
	dialer bool
	// some: on a MUX trunk only some sessions of xs had the carrier (a
	// selector's failover spreads them over the trunks of both links);
	// the others count own.
	some bool
}

// migrated requires what an attack that killed carrier k of xs[0] did to
// the stream sessions xs: d Death migrations of the attacked session (the
// row's deaths, k among them) and own of each neighbour on dedicated
// carriers (neighbours).
//
// On a MUX trunk every session of xs had k (k.some: at least one): the
// detecting end of each lists k dead with k's cause — the one trunk death
// reached every view — and each counts its own migrations, d (own for a
// session k.some left off the trunk). Selector sessions count exactly that
// (a lost active carrier always counts). A bond or race member's death
// counts only when it took unacknowledged spans with it (§7.6, M3-D34;
// A6.6): with four sessions on one trunk whether a session's view held any
// at the death instant is the other views' timing on the trunk, and a race
// view's spans below the ACK edge its other member's copies moved are
// trimmed (requeueLocked) — so each dialer counts at most that and its
// passive none (it sent nothing of its own). Bond's data on the dead trunk
// was its only copy: at least one session counts a death. Every bond or
// race session gets two live members back on both ends.
func migrated(t testing.TB, s setup, xs []*pair, k kill, d, own uint64) {
	t.Helper()
	if !s.mux {
		xs[0].deathsAre(t, s, d)
		neighbours(t, s, xs, own, d)
		return
	}
	want := make([]uint64, len(xs))
	on := 0
	for i, x := range xs {
		want[i] = d
		if k.id == 0 {
			continue
		}
		end := x.p
		if k.dialer {
			end = x.d
		}
		if _, ok := carrierOf(end.Status(), k.id); !ok {
			if !k.some {
				t.Fatalf("session %d never had the shared carrier %d", i, k.id)
			}
			want[i] = own
			continue
		}
		on++
		c := endDead(t, fmt.Sprintf("session %d's detecting end", i), end.Status, k.id)
		if c.DeathCause != k.cause {
			t.Fatalf("session %d: trunk %d died of %v %q at the detecting end, want %v", i, k.id, c.DeathCause, c.DeathDetail, k.cause)
		}
	}
	if k.id != 0 && on == 0 {
		t.Fatalf("no session had carrier %d", k.id)
	}
	if !s.members() && !k.some {
		for i, x := range xs {
			x.deathsAre(t, s, want[i])
		}
		return
	}
	if !s.members() {
		// A selector's failover race may leave a session with a view on
		// the new trunk that is not its active carrier: losing it is no
		// Death migration. A session on k counts own or d — d when k was
		// its active carrier, as it was for the session whose SCHED the
		// attack hit — and the passive follows the dialer's counts.
		top := false
		for i, x := range xs {
			waitFor(t, 10*time.Second, fmt.Sprintf("session %d's Death migrations settled", i), func() bool {
				dm, pm := x.d.Status().Migrations.Death, x.p.Status().Migrations.Death
				return dm >= own && dm == pm
			})
			if dm := x.d.Status().Migrations.Death; dm > want[i] {
				t.Fatalf("session %d: %d Death migrations, want %d to %d", i, dm, own, want[i])
			} else if dm == d {
				top = true
			}
		}
		if !top {
			t.Fatalf("no session counted the death of its active carrier %d", k.id)
		}
		return
	}
	var sum uint64
	for i, x := range xs {
		// Whatever the counts, each session replaced the member it lost
		// on k: two live members again on both ends (liveOf excludes the
		// dead trunk) — the load moved, not only finished on the survivor.
		waitFor(t, 10*time.Second, fmt.Sprintf("session %d: two live members on both ends after the death of %d", i, k.id), func() bool {
			return len(liveOf(x.d.Status())) == 2 && len(liveOf(x.p.Status())) == 2
		})
		dm, pm := x.d.Status().Migrations, x.p.Status().Migrations
		if dm.Death > want[i] || pm.Death != 0 {
			t.Fatalf("session %d: Death migrations: dialer %+v, passive %+v; want at most %d and 0", i, dm, pm, want[i])
		}
		sum += dm.Death
	}
	if s.mode == rendr.ModeBond && sum == 0 {
		t.Fatal("no bond session counted the death of the trunk that carried their unacknowledged data")
	}
}

// carrying returns the first session of xs whose end (the dialer's, else
// the passive's) has or had carrier id.
func carrying(t testing.TB, xs []*pair, id rendr.CarrierID, dialer bool) *pair {
	t.Helper()
	for _, x := range xs {
		end := x.p
		if dialer {
			end = x.d
		}
		if _, ok := carrierOf(end.Status(), id); ok {
			return x
		}
	}
	t.Fatalf("no session has carrier %d", id)
	return nil
}

// neighboursPacket is neighbours for packet sessions.
func neighboursPacket(t testing.TB, s setup, xs []*ppair, own, shared uint64) {
	t.Helper()
	d := own
	if s.mux {
		d = shared
	}
	for i, x := range xs[1:] {
		if d > 0 {
			deathsAre(t, s, x.d.Status, x.p.Status, d)
			continue
		}
		untouchedPacket(t, fmt.Sprintf("neighbour session %d", i+1), x)
	}
}

// shutdown closes both Runtimes (the dialer first), every tamper and every
// link (once; also the cleanup of a failed test).
func (w *world) shutdown() {
	w.shut.Do(func() {
		w.d.Close()
		w.p.Close()
		w.mu.Lock()
		rs := slices.Clone(w.tampers)
		w.mu.Unlock()
		for _, r := range rs {
			r.tm.Close()
		}
		for _, l := range slices.Concat(w.links, w.probes) {
			l.Close()
		}
		for _, l := range slices.Concat(w.dlinks, w.dprobes) {
			l.Close()
		}
		if w.hub != nil {
			w.hub.Close()
		}
	})
}

// close shuts the world down and requires that neither Runtime holds a
// session, a handshake, a sessionless carrier, a flow or a buffered byte
// any more, that nothing was abandoned, and that the session registry is
// back where it was (L52; R1-24).
func (w *world) close() {
	w.t.Helper()
	w.shutdown()
	for _, rt := range []*rendr.Runtime{w.d, w.p} {
		st := rt.Status()
		sc := st.Sessions
		if sc.Open+sc.Pending+sc.Lingering+sc.Orphaned != 0 || st.Handshakes != 0 || st.Sessionless != 0 || st.Actors != 0 ||
			st.BufferedBytes != 0 || st.Abandoned != 0 || st.AcceptBacklog != [2]int{} || st.Datagram.Flows != 0 {
			w.t.Fatalf("Runtime %v left state after Close: %+v", rt.InstanceID(), st)
		}
	}
	if n := testhooks.LiveSessions.Load() - w.live0; n != 0 {
		w.t.Fatalf("session registry after Close: %+d live sessions", n)
	}
}

// noViolation fails when a carrier of either Runtime ended with
// protocol_violation.
func (w *world) noViolation() {
	w.t.Helper()
	for i, l := range []*eventLog{w.dev, w.pev} {
		for _, ev := range l.of(rendr.EventCarrierDown) {
			if ev.Cause == rendr.CauseProtocolViolation {
				w.t.Fatalf("%s carrier %d ended with protocol_violation", side(i), ev.Carrier)
			}
		}
	}
}

// deaths returns the carriers of either side that died (EventCarrierDown
// with a cause other than a planned end), by side.
func (w *world) deaths() [2][]rendr.Event {
	var out [2][]rendr.Event
	for i, l := range []*eventLog{w.dev, w.pev} {
		for _, ev := range l.of(rendr.EventCarrierDown) {
			switch ev.Cause {
			case rendr.CauseRetired, rendr.CauseLocalClose, rendr.CauseNone:
			default:
				out[i] = append(out[i], ev)
			}
		}
	}
	return out
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

// Status helpers.

// liveOf returns the attached data carriers (active or member).
func liveOf(st rendr.SessionStatus) []rendr.CarrierStatus {
	var out []rendr.CarrierStatus
	for _, c := range st.Carriers {
		if c.State == rendr.CarrierActive || c.State == rendr.CarrierMember {
			out = append(out, c)
		}
	}
	return out
}

// carrierOf returns the carrier with ID id.
func carrierOf(st rendr.SessionStatus, id rendr.CarrierID) (rendr.CarrierStatus, bool) {
	for _, c := range st.Carriers {
		if c.ID == id {
			return c, true
		}
	}
	return rendr.CarrierStatus{}, false
}

// deadOf returns the dead carriers the session reports.
func deadOf(st rendr.SessionStatus) []rendr.CarrierStatus {
	var out []rendr.CarrierStatus
	for _, c := range st.Carriers {
		if c.State == rendr.CarrierDead {
			out = append(out, c)
		}
	}
	return out
}

// target returns the dialer carrier a row attacks in setup s: the
// selector's active carrier, else the data member on the session's first
// link ("a", or "c" for a Peer over "c" and "d").
func target(t testing.TB, s setup, st rendr.SessionStatus) rendr.CarrierID {
	t.Helper()
	var best rendr.CarrierStatus
	for _, c := range liveOf(st) {
		switch {
		case s.mode == rendr.ModeSelector && c.State == rendr.CarrierActive:
			return c.ID
		case s.mode != rendr.ModeSelector && (best.ID == 0 || c.Name < best.Name):
			best = c
		}
	}
	if best.ID == 0 {
		t.Fatalf("no carrier to attack in %+v", st.Carriers)
	}
	return best.ID
}

// endDead waits until carrier id is dead in the status get returns and
// returns that row.
func endDead(t testing.TB, what string, get func() rendr.SessionStatus, id rendr.CarrierID) rendr.CarrierStatus {
	t.Helper()
	var c rendr.CarrierStatus
	waitFor(t, 10*time.Second, what+": carrier "+fmt.Sprint(id)+" dead", func() bool {
		var ok bool
		c, ok = carrierOf(get(), id)
		return ok && c.State == rendr.CarrierDead
	})
	return c
}

// violated requires a protocol_violation whose detail names one of the
// checks in any (none: any detail).
func violated(t testing.TB, what string, c rendr.CarrierStatus, any ...string) {
	t.Helper()
	if c.DeathCause != rendr.CauseProtocolViolation {
		t.Fatalf("%s: carrier %d died of %v %q, want protocol_violation", what, c.ID, c.DeathCause, c.DeathDetail)
	}
	t.Logf("%s: carrier %d: protocol_violation %q", what, c.ID, c.DeathDetail)
	if len(any) == 0 {
		return
	}
	for _, s := range any {
		if strings.Contains(c.DeathDetail, s) {
			return
		}
	}
	t.Fatalf("%s: carrier %d died of protocol_violation %q, want a detail naming one of %q", what, c.ID, c.DeathDetail, any)
}

// pair is the two ends of a stream session.
type pair struct{ d, p *rendr.Conn }

// waitMembers waits until a bond or race session has two data members on
// both ends.
func (x *pair) waitMembers(t testing.TB, s setup) {
	t.Helper()
	if !s.members() {
		return
	}
	waitFor(t, 10*time.Second, "two members on both ends", func() bool {
		return len(liveOf(x.d.Status())) == 2 && len(liveOf(x.p.Status())) == 2
	})
}

// endClean half-closes both ends, requires io.EOF on both, closes both and
// waits until both sessions ended cleanly (Err io.EOF).
func (x *pair) endClean(t testing.TB) {
	t.Helper()
	for _, c := range []*rendr.Conn{x.d, x.p} {
		if err := c.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite: %v", err)
		}
	}
	for _, c := range []*rendr.Conn{x.d, x.p} {
		var b [1]byte
		if n, err := c.Read(b[:]); n != 0 || err != io.EOF {
			t.Fatalf("Read after the peer's FIN: (%d, %v), want EOF", n, err)
		}
	}
	for _, c := range []*rendr.Conn{x.d, x.p} {
		if err := c.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}
	for _, c := range []*rendr.Conn{x.d, x.p} {
		select {
		case <-c.Done():
		case <-time.After(time.Minute):
			t.Fatalf("session %v did not end", c.ID())
		}
		if st := c.Status(); st.Err != io.EOF {
			t.Fatalf("%v session %v ended with %v, want io.EOF", st.Role, c.ID(), st.Err)
		}
	}
}

// deathsAre requires the session's Death migrations (see deathsAre).
func (x *pair) deathsAre(t testing.TB, s setup, d uint64) {
	t.Helper()
	deathsAre(t, s, x.d.Status, x.p.Status, d)
}

// Stream application data.

// sflow is n bytes of PRNG(seed) written on one Conn (then CloseWrite) and
// verified on another up to io.EOF, each side on its own goroutine.
type sflow struct {
	n          int64
	sent, got  atomic.Int64
	wdone      chan struct{}
	rdone      chan struct{}
	werr, rerr error
}

// startFlow writes n bytes of PRNG(seed) on wc and verifies them on rc.
func startFlow(wc, rc *rendr.Conn, n int64, seed uint64) *sflow {
	f := &sflow{n: n, wdone: make(chan struct{}), rdone: make(chan struct{})}
	go func() {
		defer close(f.wdone)
		f.werr = f.write(wc, seed)
	}()
	go func() {
		defer close(f.rdone)
		f.rerr = f.read(rc, seed)
	}()
	return f
}

func (f *sflow) write(c *rendr.Conn, seed uint64) error {
	src := rendrtest.PRNG(seed)
	buf := make([]byte, 64<<10)
	for done := int64(0); done < f.n; {
		k := int(min(int64(len(buf)), f.n-done))
		src.Read(buf[:k])
		m, err := c.Write(buf[:k])
		done += int64(m)
		f.sent.Store(done)
		if err != nil {
			return fmt.Errorf("write after %d of %d bytes: %w", done, f.n, err)
		}
	}
	if err := c.CloseWrite(); err != nil {
		return fmt.Errorf("CloseWrite: %w", err)
	}
	return nil
}

func (f *sflow) read(c *rendr.Conn, seed uint64) error {
	v := rendrtest.NewVerifier(seed, f.n)
	buf := make([]byte, 64<<10)
	for {
		k, err := c.Read(buf)
		if k > 0 {
			f.got.Add(int64(k))
			if _, werr := v.Write(buf[:k]); werr != nil {
				return v.Done(err)
			}
		}
		if err != nil {
			return v.Done(err)
		}
	}
}

// wait waits for both sides and fails on any error: a write error, a
// short, corrupted or duplicated stream, an early or missing EOF.
func (f *sflow) wait(t testing.TB, within time.Duration, what string) {
	t.Helper()
	timeout := time.After(within)
	for _, ch := range []chan struct{}{f.wdone, f.rdone} {
		select {
		case <-ch:
		case <-timeout:
			t.Fatalf("%s: not done after %v (sent %d, received %d of %d)", what, within, f.sent.Load(), f.got.Load(), f.n)
		}
	}
	if f.werr != nil {
		t.Fatalf("%s: writer: %v", what, f.werr)
	}
	if f.rerr != nil {
		t.Fatalf("%s: reader: %v", what, f.rerr)
	}
}

// reached waits until the reader has k bytes.
func (f *sflow) reached(t testing.TB, k int64, what string) {
	t.Helper()
	waitFor(t, time.Minute, what, func() bool { return f.got.Load() >= k })
}

// Packet application data.

// ppair is the two ends of a packet session.
type ppair struct{ d, p *rendr.PacketConn }

// pflow writes test datagrams (rendrtest.PacketPayload) on one PacketConn
// at rate datagrams per second in 10-ms slots and verifies them on another.
type pflow struct {
	name       string
	w, r       *rendr.PacketConn
	v          *rendrtest.PacketVerifier
	rate, size int
	seed       uint64
	start      time.Time

	stop         chan struct{}
	once         sync.Once
	wdone, rdone chan struct{}
	accepted     atomic.Int64 // WriteTo calls that returned (size, nil)
	read         atomic.Int64 // datagrams ReadFrom returned
	werr, rerr   error

	mu  sync.Mutex
	bad error // the first integrity failure
}

// startPacketFlow writes on wc and reads on rc (size 0: 1000 bytes). A
// cleanup stops the writer, whose timer would otherwise outlive a failed
// test's bubble.
func startPacketFlow(t testing.TB, name string, wc, rc *rendr.PacketConn, seed uint64, rate, size int) *pflow {
	if size == 0 {
		size = 1000
	}
	f := &pflow{name: name, w: wc, r: rc, v: rendrtest.NewPacketVerifier(seed), rate: rate, size: size, seed: seed,
		start: time.Now(), stop: make(chan struct{}), wdone: make(chan struct{}), rdone: make(chan struct{})}
	t.Cleanup(f.stopOnce)
	go f.writer()
	go f.reader()
	return f
}

// startPacketFlows starts a flow dialer → passive on each session of xs
// (seed, seed+1, ...; 1000-byte datagrams at rate).
func startPacketFlows(t testing.TB, xs []*ppair, seed uint64, rate int) []*pflow {
	fs := make([]*pflow, len(xs))
	for i, x := range xs {
		fs[i] = startPacketFlow(t, fmt.Sprintf("session %d", i), x.d, x.p, seed+uint64(i), rate, 0)
	}
	return fs
}

// endPackets ends every session of xs cleanly (endPacket with its flow).
func endPackets(t testing.TB, xs []*ppair, fs []*pflow) {
	t.Helper()
	for i, x := range xs {
		x.endPacket(t, fs[i])
	}
}

// stopOnce tells the writer to stop (idempotent).
func (f *pflow) stopOnce() {
	f.once.Do(func() { close(f.stop) })
}

func (f *pflow) writer() {
	defer close(f.wdone)
	buf := make([]byte, f.size)
	seq := 0
	for k := 1; ; k++ {
		due := int(time.Since(f.start) * time.Duration(f.rate) / time.Second)
		for ; seq < due; seq++ {
			m, err := f.w.WriteTo(rendrtest.PacketPayload(buf, f.seed, uint64(seq), f.size, time.Now()), nil)
			if err != nil {
				f.werr = fmt.Errorf("%s: WriteTo of seq %d: %w", f.name, seq, err)
				return
			}
			if m != f.size {
				f.werr = fmt.Errorf("%s: WriteTo returned %d for a %d-byte datagram", f.name, m, f.size)
				return
			}
			f.accepted.Add(1)
		}
		select {
		case <-f.stop:
			return
		case <-time.After(time.Until(f.start.Add(time.Duration(k) * 10 * time.Millisecond))):
		}
	}
}

func (f *pflow) reader() {
	defer close(f.rdone)
	buf := make([]byte, f.r.MaxPayload()+1)
	for {
		n, _, err := f.r.ReadFrom(buf)
		if err != nil {
			f.rerr = err
			return
		}
		if verr := f.v.Add(buf[:n], time.Now()); verr != nil {
			f.mu.Lock()
			if f.bad == nil {
				f.bad = fmt.Errorf("%s: %w", f.name, verr)
			}
			f.mu.Unlock()
		}
		f.read.Add(1)
	}
}

// halt stops the writer and waits for it; a WriteTo error fails the test.
func (f *pflow) halt(t testing.TB) {
	t.Helper()
	f.stopOnce()
	select {
	case <-f.wdone:
	case <-time.After(time.Minute):
		t.Fatalf("%s: the writer did not stop", f.name)
	}
	if f.werr != nil {
		t.Fatal(f.werr)
	}
}

// integrity requires that every datagram returned was intact and the
// generator's (0 foreign or corrupt ones), at most once, and returns the
// verdict.
func (f *pflow) integrity(t testing.TB) rendrtest.PacketResult {
	t.Helper()
	res := f.v.Result()
	f.mu.Lock()
	bad := f.bad
	f.mu.Unlock()
	if bad != nil || res.Corrupt+res.BadSize+res.Duplicates != 0 {
		t.Fatalf("%s: integrity (%v): unique %d, duplicates %d, corrupt %d, bad size %d", f.name, bad, res.Unique, res.Duplicates, res.Corrupt, res.BadSize)
	}
	return res
}

// lost is the number of accepted datagrams that have not arrived.
func (f *pflow) lost() int64 { return f.accepted.Load() - int64(f.v.Result().Unique) }

// endPacket ends a packet session cleanly once the flows were halted: the
// dialer closes, the passive reads until io.EOF and closes; both sessions
// end with io.EOF.
func (x *ppair) endPacket(t testing.TB, up *pflow) {
	t.Helper()
	time.Sleep(time.Second) // the last datagrams and their accounting
	x.d.Close()
	select {
	case <-up.rdone:
	case <-time.After(30 * time.Second):
		t.Fatalf("%s: the reader did not end", up.name)
	}
	if !errors.Is(up.rerr, io.EOF) {
		t.Fatalf("%s: the reader ended with %v, want io.EOF", up.name, up.rerr)
	}
	x.p.Close()
	for _, c := range []*rendr.PacketConn{x.d, x.p} {
		select {
		case <-c.Done():
		case <-time.After(time.Minute):
			t.Fatalf("a session did not end: %+v", c.Status())
		}
		if st := c.Status(); st.Err != io.EOF {
			t.Fatalf("%v session ended with %v, want io.EOF", st.Role, st.Err)
		}
	}
}

// Datagram damage.

// dflip damages datagrams rendr writes (a corrupting path): one targeted
// flip — a bit of the first frame of a type in the next datagram of a
// dialer session conn that carries one — and random flips of one bit in a
// share of every datagram of a direction. Datagrams that start with a
// PREFACE (handshake datagrams) are never damaged: the rows are about
// carrier frames.
type dflip struct {
	mu    sync.Mutex
	armed bool
	typ   wire.Type
	bit   int
	only  rendr.CarrierID // 0: any dialer session conn
	fired rendr.CarrierID // the conn the targeted flip hit
	nfire int

	// rw: a targeted handle rewrite with a recomputed CRC (a broken peer;
	// rewrite).
	rw      bool
	rwTyp   wire.Type
	rwH     uint32
	rwOnly  rendr.CarrierID
	rwFired rendr.CarrierID
	rwN     int

	rate [2]float64 // random flips per datagram, per direction (Up, Down)
	// rng draws per direction: a direction's flips are a function of the
	// number of datagrams it wrote, not of how the goroutines of the two
	// directions interleave.
	rng   [2]*rand.Rand
	flips [2]int // random flips done per direction
	draws [2]int // datagrams drawn for a random flip per direction
}

func newDflip() *dflip {
	return &dflip{rng: [2]*rand.Rand{rand.New(rand.NewPCG(43, 41)), rand.New(rand.NewPCG(41, 43))}}
}

// arm arms the targeted flip: bit of the first frame of type typ (counted
// as in rendrtest.Tamper.FlipBit: 0 is the header's first bit, a negative
// bit counts from the frame's end) in the next datagram of carrier only's
// conn (0: any dialer session conn) that carries such a frame.
func (f *dflip) arm(typ wire.Type, bit int, only rendr.CarrierID) {
	f.mu.Lock()
	f.armed, f.typ, f.bit, f.only = true, typ, bit, only
	f.mu.Unlock()
}

// rewrite arms a targeted handle rewrite with a recomputed CRC (a broken
// peer, §A9.3's RewriteHandle on a datagram trunk) in the next datagram of
// carrier only's conn (0: any dialer session conn) that carries a frame
// of type typ: a DGRAM's header handle; the inner handle of the REL that
// wraps an OPEN or JOIN (wire.TypeOpen: either); the handle a REL-wrapped
// DETACH ends.
func (f *dflip) rewrite(typ wire.Type, h uint32, only rendr.CarrierID) {
	f.mu.Lock()
	f.rw, f.rwTyp, f.rwH, f.rwOnly = true, typ, h, only
	f.mu.Unlock()
}

// rewritten returns the conn the rewrite hit and how often it fired.
func (f *dflip) rewritten() (rendr.CarrierID, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rwFired, f.rwN
}

// targeted returns the conn the targeted flip hit and how often it fired.
func (f *dflip) targeted() (rendr.CarrierID, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fired, f.nfire
}

// random sets the share of datagrams of direction d that get a random flip.
func (f *dflip) random(d rendrtest.Dir, share float64) {
	f.mu.Lock()
	f.rate[dirIndex(d)] = share
	f.mu.Unlock()
}

// randomFlips returns the random flips done in direction d and the
// datagrams drawn for them (written while its share was set).
func (f *dflip) randomFlips(d rendrtest.Dir) (flips, draws int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.flips[dirIndex(d)], f.draws[dirIndex(d)]
}

func dirIndex(d rendrtest.Dir) int {
	if d == rendrtest.Down {
		return 1
	}
	return 0
}

// apply returns the damaged copy of datagram p written by conn c, or nil
// when it passes untouched.
func (f *dflip) apply(c *dflipConn, p []byte) []byte {
	if wire.IsPreface(p) {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rw && c.dir == rendrtest.Up && (f.rwOnly == 0 || f.rwOnly == c.id) {
		if q, ok := rewriteHandle(p, f.rwTyp, f.rwH); ok {
			f.rw, f.rwFired = false, c.id
			f.rwN++
			return q
		}
	}
	if f.armed && c.dir == rendrtest.Up && (f.only == 0 || f.only == c.id) {
		if off, size, ok := frameOf(p, f.typ); ok {
			b := f.bit
			if b < 0 {
				b += 8 * size
			}
			q := slices.Clone(p)
			q[off+b/8] ^= 0x80 >> (b % 8)
			f.armed, f.fired = false, c.id
			f.nfire++
			return q
		}
	}
	i := dirIndex(c.dir)
	if f.rate[i] > 0 {
		f.draws[i]++
	}
	if f.rate[i] > 0 && f.rng[i].Float64() < f.rate[i] {
		q := slices.Clone(p)
		b := f.rng[i].IntN(8 * len(q))
		q[b/8] ^= 0x80 >> (b % 8)
		f.flips[i]++
		return q
	}
	return nil
}

// frameOf returns the offset and size of the first top-level frame of type
// typ in datagram p; for wire.TypeDetach, of the first REL that carries a
// DETACH (a datagram trunk REL-wraps it, §A3.4).
func frameOf(p []byte, typ wire.Type) (off, size int, ok bool) {
	for off < len(p) {
		h, err := wire.ParseHeader(p[off:])
		if err != nil {
			return 0, 0, false
		}
		size = wire.FrameOverhead + int(h.Len)
		if off+size > len(p) {
			return 0, 0, false
		}
		if h.Type == typ || typ == wire.TypeDetach && h.Type == wire.TypeRel && size > wire.HeaderLen+4 &&
			wire.Type(p[off+wire.HeaderLen+4]) == wire.TypeDetach { // the REL head's inner type
			return off, size, true
		}
		off += size
	}
	return 0, 0, false
}

// rewriteHandle returns a copy of datagram p whose first frame of type typ
// (see dflip.rewrite) names handle h, the frame's CRC recomputed; false
// when p has none.
func rewriteHandle(p []byte, typ wire.Type, h uint32) ([]byte, bool) {
	for off := 0; off < len(p); {
		hd, err := wire.ParseHeader(p[off:])
		if err != nil {
			return nil, false
		}
		size := wire.FrameOverhead + int(hd.Len)
		if off+size > len(p) {
			return nil, false
		}
		at := -1
		switch {
		case hd.Type == typ && typ == wire.TypeDgram:
			at = off + 9 // the header's handle
		case hd.Type == wire.TypeRel && size >= wire.FrameOverhead+wire.RelHeadLen && innerIs(wire.Type(p[off+wire.HeaderLen+4]), typ):
			at = off + wire.HeaderLen + 6 // the REL head's inner handle
			if typ == wire.TypeDetach && size >= wire.FrameOverhead+wire.RelHeadLen+4 {
				at = off + wire.HeaderLen + wire.RelHeadLen // the handle the DETACH ends
			}
		}
		if at >= 0 {
			q := slices.Clone(p)
			binary.BigEndian.PutUint32(q[at:at+4], h)
			end := off + size - wire.TrailerLen
			wire.PutTrailer(q[end:], wire.CRC(q[off:end]))
			return q, true
		}
		off += size
	}
	return nil, false
}

// innerIs reports whether a REL's inner type is typ (wire.TypeOpen: an
// OPEN or a JOIN).
func innerIs(inner, typ wire.Type) bool {
	return inner == typ || typ == wire.TypeOpen && inner == wire.TypeJoin
}

// dflipConn is a datagram carrier conn whose writes pass through a dflip;
// the dialer's conns also keep a copy of every datagram written (record).
type dflipConn struct {
	net.PacketConn
	f      *dflip
	dir    rendrtest.Dir // the direction this conn writes
	id     rendr.CarrierID
	link   string // the factory's link name
	hub    int    // its hub client index (-1: a DatagramLink conn)
	record bool

	mu   sync.Mutex
	sent [][]byte
}

func (c *dflipConn) WriteTo(p []byte, a net.Addr) (int, error) {
	if c.record {
		c.mu.Lock()
		c.sent = append(c.sent, slices.Clone(p))
		c.mu.Unlock()
	}
	if q := c.f.apply(c, p); q != nil {
		if _, err := c.PacketConn.WriteTo(q, a); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	return c.PacketConn.WriteTo(p, a)
}

// written returns the datagrams the conn wrote so far (record).
func (c *dflipConn) written() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.sent)
}
