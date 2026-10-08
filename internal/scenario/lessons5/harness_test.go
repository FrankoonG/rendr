package lessons5

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// Scenario kit of lessons5 (its own fixture, R1-23). A world is two
// Runtimes — the dialer d and the passive p with one push-only Listener —
// built with testhooks.NewRuntime and joined by rendrtest.DatagramLinks
// whose Accept is the Listener's HandlePacket (and rendrtest.Links whose
// Accept is its Handle), so every carrier goes through the whole datagram
// handshake and admission. Everything is created inside the synctest
// bubble that uses it and closed before the bubble ends. Only the public
// API is used; internal packages appear only as testhooks (Overrides) and
// wire (parsing captured datagrams in the taps).

// worldOpts configures a world.
type worldOpts struct {
	// ov goes to both Runtimes (counter presets must be equal, L14); only
	// the dialer's copy gets dHooks.
	ov     testhooks.Overrides
	dHooks *testhooks.Hooks
	// dcfg and pcfg are the dialer's and the passive's Config (OnEvent is
	// the world's event log).
	dcfg, pcfg rendr.Config
	// tap wraps every datagram conn of both ends in a tapPC (world.taps).
	tap bool
}

// world is one scenario's two Runtimes and links.
type world struct {
	t        testing.TB
	d, p     *rendr.Runtime
	ln       *rendr.Listener
	links    []*rendrtest.DatagramLink
	slinks   []*rendrtest.Link
	dev, pev *eventLog
	taps     *tapSet
	tap      bool
	lastPeer *rendr.Peer
}

// newWorld builds the Runtimes, the Listener and one DatagramLink per name.
// A cleanup shuts everything down if the test fails before close.
func newWorld(t testing.TB, o worldOpts, names ...string) *world {
	t.Helper()
	w := &world{t: t, dev: &eventLog{}, pev: &eventLog{}, taps: &tapSet{}, tap: o.tap}
	dov, pov := o.ov, o.ov
	dov.Hooks, pov.Hooks = o.dHooks, nil
	dcfg, pcfg := o.dcfg, o.pcfg
	dcfg.OnEvent, pcfg.OnEvent = w.dev.add, w.pev.add
	w.d = newRuntime(t, dcfg, &dov)
	w.p = newRuntime(t, pcfg, &pov)
	t.Cleanup(w.shutdown)
	ln, err := w.p.Listen(rendr.ListenConfig{})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	w.ln = ln
	for _, n := range names {
		w.addLink(n)
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

// addLink adds a DatagramLink whose carriers are handed to the passive
// Listener (through a tap when the world taps). Its queue holds 8,192
// datagrams per direction: no scenario here comes near it.
func (w *world) addLink(name string) *rendrtest.DatagramLink {
	accept := func(pc net.PacketConn, peer net.Addr) error {
		if w.tap {
			pc = w.taps.wrap(pc, false, name, 0, false)
		}
		return w.ln.HandlePacket(pc, peer)
	}
	l := rendrtest.NewDatagramLink(rendrtest.DatagramLinkConfig{Name: name, Accept: accept, Queue: 8192})
	w.links = append(w.links, l)
	return l
}

// addStreamLink adds a stream Link whose carriers are handed to the passive
// Listener's Handle.
func (w *world) addStreamLink(name string) *rendrtest.Link {
	l := rendrtest.NewLink(rendrtest.LinkConfig{Name: name, Accept: w.ln.Handle})
	w.slinks = append(w.slinks, l)
	return l
}

// link returns the DatagramLink called name.
func (w *world) link(name string) *rendrtest.DatagramLink {
	for _, l := range w.links {
		if l.Name() == name {
			return l
		}
	}
	w.t.Fatalf("no datagram link %q", name)
	return nil
}

// dgCarrier is the DatagramCarrier of l with frame budget mtu; in a tapping
// world every conn it dials is wrapped in a tapPC that knows its DialInfo.
func (w *world) dgCarrier(l *rendrtest.DatagramLink, mtu int) rendr.DatagramCarrier {
	name := l.Name()
	return rendr.DatagramCarrier{Name: name, MTU: mtu, Dial: func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		pc, addr, err := l.Dial(ctx)
		if err != nil || pc == nil || !w.tap {
			return pc, addr, err
		}
		di, _ := rendr.CarrierDialInfo(ctx)
		return w.taps.wrap(pc, true, name, di.Carrier, di.Probe), addr, nil
	}}
}

// peer returns a dialer Peer over cs (configuration order breaks ranking
// ties).
func (w *world) peer(cs ...rendr.Carrier) *rendr.Peer {
	w.t.Helper()
	p, err := w.d.NewPeer(rendr.PeerConfig{Carriers: cs})
	if err != nil {
		w.t.Fatalf("NewPeer: %v", err)
	}
	w.lastPeer = p
	return p
}

// dialed is the outcome of an asynchronous DialPacket.
type dialed struct {
	c   *rendr.PacketConn
	err error
	at  time.Time
}

// dialAsync dials a packet session on its own goroutine.
func dialAsync(p *rendr.Peer, o rendr.DialOptions) <-chan dialed {
	ch := make(chan dialed, 1)
	go func() {
		c, err := p.DialPacket(context.Background(), o)
		ch <- dialed{c, err, time.Now()}
	}()
	return ch
}

// pending waits for the next pending packet session on the Listener.
func (w *world) pending() *rendr.PendingPacket {
	w.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pp, err := w.ln.AcceptPacket(ctx)
	if err != nil {
		w.t.Fatalf("AcceptPacket: %v", err)
	}
	return pp
}

// open dials one packet session over p and confirms it on the passive: its
// dialer and passive ends.
func (w *world) open(p *rendr.Peer, o rendr.DialOptions) (dc, pc *rendr.PacketConn) {
	w.t.Helper()
	res := dialAsync(p, o)
	pc, err := w.pending().Confirm()
	if err != nil {
		w.t.Fatalf("Confirm: %v", err)
	}
	r := <-res
	if r.err != nil {
		w.t.Fatalf("DialPacket: %v", r.err)
	}
	return r.c, pc
}

// openStream dials one stream session over p and confirms it.
func (w *world) openStream(p *rendr.Peer) (dc, sc *rendr.Conn) {
	w.t.Helper()
	type res struct {
		c   *rendr.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := p.Dial(context.Background(), rendr.DialOptions{})
		ch <- res{c, err}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pend, err := w.ln.Accept(ctx)
	if err != nil {
		w.t.Fatalf("Accept: %v", err)
	}
	sc, err = pend.Confirm()
	if err != nil {
		w.t.Fatalf("Confirm: %v", err)
	}
	r := <-ch
	if r.err != nil {
		w.t.Fatalf("Dial: %v", r.err)
	}
	return r.c, sc
}

// shutdown closes both Runtimes (the dialer first) and every link
// (idempotent; also the cleanup of a failed test).
func (w *world) shutdown() {
	w.d.Close()
	w.p.Close()
	for _, l := range w.links {
		l.Close()
	}
	for _, l := range w.slinks {
		l.Close()
	}
}

// close shuts the world down and requires that neither Runtime holds a
// session, a handshake, a sessionless carrier, a datagram flow or source,
// an admitting flow or a buffered byte any more and that nothing was
// abandoned (L52).
func (w *world) close() {
	w.t.Helper()
	w.shutdown()
	for _, rt := range []*rendr.Runtime{w.d, w.p} {
		st := rt.Status()
		sc := st.Sessions
		if sc.Open+sc.Pending+sc.Lingering+sc.Orphaned != 0 || st.Handshakes != 0 || st.Sessionless != 0 ||
			st.BufferedBytes != 0 || st.Abandoned != 0 || st.AcceptBacklog != [2]int{} ||
			st.Datagram.Flows != 0 || st.Datagram.Sources != 0 || st.Datagram.Admitting != 0 {
			w.t.Fatalf("Runtime %v left state after Close: %+v", rt.InstanceID(), st)
		}
	}
}

// noViolation fails when a carrier of either Runtime ended with
// protocol_violation (a duplicate, a reordered or a resent frame is never
// one, L43).
func (w *world) noViolation() {
	w.t.Helper()
	for i, l := range []*eventLog{w.dev, w.pev} {
		for _, ev := range l.of(rendr.EventCarrierDown) {
			if ev.Cause == rendr.CauseProtocolViolation {
				w.t.Fatalf("%s carrier %d ended with protocol_violation: %+v", [2]string{"dialer", "passive"}[i], ev.Carrier, ev)
			}
		}
	}
}

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

// waitDone waits until both sessions ended and requires the clean end of a
// packet session (Err io.EOF, M2-D40) on both.
func waitDone(t testing.TB, within time.Duration, cs ...*rendr.PacketConn) {
	t.Helper()
	timeout := time.After(within)
	for _, c := range cs {
		select {
		case <-c.Done():
		case <-timeout:
			t.Fatalf("a session did not end within %v: %+v", within, c.Status())
		}
		if st := c.Status(); st.State != rendr.StateEnded || st.Err != io.EOF {
			t.Fatalf("%v session ended %v with %v, want io.EOF", st.Role, st.State, st.Err)
		}
	}
}

// Status helpers.

// activeOf returns the carrier the session reports active.
func activeOf(st rendr.SessionStatus) (rendr.CarrierStatus, bool) {
	for _, c := range st.Carriers {
		if c.State == rendr.CarrierActive {
			return c, true
		}
	}
	return rendr.CarrierStatus{}, false
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

// dropped sums the Dropped counters of every carrier the session reports
// (live ones and the last eight dead ones).
func dropped(st rendr.SessionStatus) uint64 {
	var n uint64
	for _, c := range st.Carriers {
		n += c.Dropped
	}
	return n
}

// retransmits sums the REL retransmissions of every carrier the session
// reports.
func retransmits(st rendr.SessionStatus) uint64 {
	var n uint64
	for _, c := range st.Carriers {
		n += c.Retransmits
	}
	return n
}

// Packet traffic.

// sizeOf is the size of test datagram k: 24 … 1000 bytes, every size class
// of a datagram carrier's batch exercised (L36: boundaries kept).
func sizeOf(k int) int { return rendrtest.PacketHeaderLen + k*37%977 }

// pktWriter writes n test datagrams of one seed on a PacketConn.
type pktWriter struct {
	done     chan struct{}
	accepted atomic.Int64  // WriteTo calls that returned (len, nil)
	maxCall  time.Duration // the longest WriteTo call (L40: never blocks)
	err      error         // the first WriteTo error (net.ErrClosed after the peer's FIN)
}

// writePackets writes datagrams first … first+n−1 of seed on c, one every
// pace (0: back to back), sized by size (nil: sizeOf).
func writePackets(c *rendr.PacketConn, seed uint64, first, n int, pace time.Duration, size func(int) int) *pktWriter {
	if size == nil {
		size = sizeOf
	}
	w := &pktWriter{done: make(chan struct{})}
	go func() {
		defer close(w.done)
		buf := make([]byte, wire.MaxDatagram)
		for k := first; k < first+n; k++ {
			at := time.Now()
			m, err := c.WriteTo(rendrtest.PacketPayload(buf, seed, uint64(k), size(k), at), nil)
			w.maxCall = max(w.maxCall, time.Since(at))
			if err != nil {
				w.err = err
				return
			}
			if m != size(k) {
				w.err = fmt.Errorf("WriteTo returned %d for a %d-byte datagram", m, size(k))
				return
			}
			w.accepted.Add(1)
			if pace > 0 {
				time.Sleep(pace)
			}
		}
	}()
	return w
}

// wait waits for the writer and fails on an error.
func (w *pktWriter) wait(t testing.TB, within time.Duration, what string) {
	t.Helper()
	select {
	case <-w.done:
	case <-time.After(within):
		t.Fatalf("%s: the writer did not finish within %v (%d accepted)", what, within, w.accepted.Load())
	}
	if w.err != nil {
		t.Fatalf("%s: WriteTo: %v", what, w.err)
	}
}

// pktReader reads a PacketConn until an error, verifying every datagram.
type pktReader struct {
	v     *rendrtest.PacketVerifier
	done  chan struct{}
	n     atomic.Int64 // datagrams returned
	err   error        // what ended it (io.EOF: the clean end)
	endAt time.Time
	bad   error // the first verification failure
}

// readPackets reads c on its own goroutine until ReadFrom fails, verifying
// every datagram against seed (seq, size, CRC-32C, body; duplicates counted).
func readPackets(c *rendr.PacketConn, seed uint64) *pktReader {
	r := &pktReader{v: rendrtest.NewPacketVerifier(seed), done: make(chan struct{})}
	go func() {
		defer close(r.done)
		buf := make([]byte, wire.MaxDatagram)
		for {
			n, _, err := c.ReadFrom(buf)
			if err != nil {
				r.err, r.endAt = err, time.Now()
				return
			}
			if verr := r.v.Add(buf[:n], time.Now()); verr != nil && r.bad == nil {
				r.bad = verr
			}
			r.n.Add(1)
		}
	}()
	return r
}

// wait waits until the reader ended with io.EOF and requires that every
// datagram it returned was intact and returned once.
func (r *pktReader) wait(t testing.TB, within time.Duration, what string) rendrtest.PacketResult {
	t.Helper()
	select {
	case <-r.done:
	case <-time.After(within):
		t.Fatalf("%s: no io.EOF within %v (%d datagrams read)", what, within, r.n.Load())
	}
	if r.err != io.EOF {
		t.Fatalf("%s: the reader ended with %v, want io.EOF", what, r.err)
	}
	return r.check(t, what)
}

// waitClosed waits until the reader of the side that closed its session
// ended with net.ErrClosed and checks what it returned before.
func (r *pktReader) waitClosed(t testing.TB, within time.Duration, what string) rendrtest.PacketResult {
	t.Helper()
	select {
	case <-r.done:
	case <-time.After(within):
		t.Fatalf("%s: the reader did not end within %v of its Close", what, within)
	}
	if !errors.Is(r.err, net.ErrClosed) {
		t.Fatalf("%s: the closer's reader ended with %v, want net.ErrClosed", what, r.err)
	}
	return r.check(t, what)
}

// check requires that every datagram returned so far was intact and was
// returned at most once (L39).
func (r *pktReader) check(t testing.TB, what string) rendrtest.PacketResult {
	t.Helper()
	res := r.v.Result()
	if r.bad != nil || res.Corrupt+res.BadSize != 0 {
		t.Fatalf("%s: a damaged datagram (%v): %+v", what, r.bad, res)
	}
	if res.Duplicates != 0 {
		t.Fatalf("%s: %d datagrams returned twice (L39: at most once): %+v", what, res.Duplicates, res)
	}
	return res
}

// Stream traffic (SHA-256 on both ends).

// streamFlow is n bytes of PRNG(seed) written on one Conn and hashed on
// another.
type streamFlow struct {
	n                  int64
	wdone, rdone       chan struct{}
	werr, rerr         error
	sent, got          [32]byte
	start, rend, wdEnd time.Time
}

// startStream writes n bytes of PRNG(seed) on wc and reads them on rc, each
// side on its own goroutine, both hashing what they handled.
func startStream(wc, rc net.Conn, n int64, seed uint64) *streamFlow {
	f := &streamFlow{n: n, wdone: make(chan struct{}), rdone: make(chan struct{}), start: time.Now()}
	go func() {
		defer close(f.wdone)
		h := sha256.New()
		src := rendrtest.PRNG(seed)
		buf := make([]byte, 32<<10)
		for done := int64(0); done < n; {
			k := int(min(int64(len(buf)), n-done))
			src.Read(buf[:k])
			h.Write(buf[:k])
			m, err := wc.Write(buf[:k])
			done += int64(m)
			if err != nil {
				f.werr = err
				return
			}
		}
		h.Sum(f.sent[:0])
		f.wdEnd = time.Now()
	}()
	go func() {
		defer close(f.rdone)
		h := sha256.New()
		v := rendrtest.NewVerifier(seed, n)
		buf := make([]byte, 64<<10)
		var got int64
		for got < n {
			k, err := rc.Read(buf[:min(int64(len(buf)), n-got)])
			if k > 0 {
				got += int64(k)
				h.Write(buf[:k])
				if _, verr := v.Write(buf[:k]); verr != nil {
					f.rerr = v.Done(verr)
					return
				}
			}
			if err != nil {
				f.rerr = v.Done(err)
				return
			}
		}
		h.Sum(f.got[:0])
		f.rend = time.Now()
	}()
	return f
}

// wait waits for both sides and requires equal digests of n bytes.
func (f *streamFlow) wait(t testing.TB, within time.Duration, what string) {
	t.Helper()
	timeout := time.After(within)
	for _, ch := range []chan struct{}{f.wdone, f.rdone} {
		select {
		case <-ch:
		case <-timeout:
			t.Fatalf("%s: not done within %v", what, within)
		}
	}
	if f.werr != nil || f.rerr != nil {
		t.Fatalf("%s: writer %v, reader %v", what, f.werr, f.rerr)
	}
	if f.sent != f.got {
		t.Fatalf("%s: SHA-256 %x sent, %x received", what, f.sent, f.got)
	}
}

// Captures: a rendrtest capture channel stamped with the virtual time of
// the capture.

// capture is one datagram a link copied and when.
type capture struct {
	b  []byte
	at time.Time
}

// stamp forwards the datagram ch delivers with the time it arrived; the
// forwarder leaves when stop closes.
func stamp(ch <-chan []byte, stop <-chan struct{}) <-chan capture {
	out := make(chan capture, 1)
	go func() {
		select {
		case b := <-ch:
			out <- capture{b, time.Now()}
		case <-stop:
		}
	}()
	return out
}

// relOf returns the REL payload (cseq · itype · iflags · ihandle · inner)
// of the first REL frame of datagram d that wraps type t, and its outer
// fseq; ok is false when d holds none.
func relOf(d []byte, t wire.Type) (payload []byte, fseq uint32, ok bool) {
	walkFrames(d, func(f wire.Frame) bool {
		if f.Type != wire.TypeRel {
			return true
		}
		if h, _, err := wire.ParseRel(f.Payload); err == nil && h.Type == t {
			payload, fseq, ok = slices.Clone(f.Payload), f.Fseq, true
			return false
		}
		return true
	})
	return payload, fseq, ok
}

// walkFrames calls f for every frame of the rendr bytes d (after a PREFACE
// or PREFACE_ACK) until f returns false or a frame fails to decode.
func walkFrames(d []byte, f func(wire.Frame) bool) {
	if wire.IsPreface(d) {
		d = d[wire.PrefaceLen:]
	}
	for len(d) > 0 {
		fr, n, err := wire.DecodeFrame(d)
		if err != nil || !f(fr) {
			return
		}
		d = d[n:]
	}
}

// Taps: a datagram conn wrapper on either end that follows the fseqs of
// what it reads (to count the window duplicates the carrier must drop) and
// can inject, on the dialer's side, a session-level duplicate: a DGRAM
// frame it wrote, re-sent in a datagram of its own with a fresh fseq and a
// valid CRC (R1-10). To keep every fseq unique it renumbers: after k
// injections every later frame of the conn carries fseq + k (a monotone
// map, so window order, duplicates and the M2-D30 CLOSE order are kept).

// tapPC wraps one carrier conn.
type tapPC struct {
	net.PacketConn
	dialer bool
	link   string
	id     rendr.CarrierID // dialer: the DialInfo's carrier

	mu    sync.Mutex
	typed bool // classified: probe or session carrier
	probe bool
	// Read side: fseqs of the frames read (handshake datagrams are not
	// walked; they are kept to recognise their copies), the frames read
	// again and the datagrams read again whole.
	seen        map[uint32]struct{}
	early       [][]byte
	established bool // dialer: it wrote a datagram after its handshake (H4); passive: always
	n           tapCounts
	// Write side.
	off     uint32 // added to every frame's fseq (the injections so far)
	armed   int    // injections still to make
	scratch []byte
}

// tapCounts are a tap's counters.
type tapCounts struct {
	DupFrames   int // frames read whose fseq was read before (window duplicates)
	DupDgrams   int // datagrams read whose every frame was read before
	EarlyCopies int // byte-equal copies of handshake-time datagrams
	Injected    int // session-level duplicates written
}

func (a tapCounts) add(b tapCounts) tapCounts {
	return tapCounts{a.DupFrames + b.DupFrames, a.DupDgrams + b.DupDgrams, a.EarlyCopies + b.EarlyCopies, a.Injected + b.Injected}
}

// ReadFrom implements net.PacketConn.
func (c *tapPC) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if err == nil && n > 0 && n <= len(p) {
		c.observe(p[:n])
	}
	return n, addr, err
}

// observe classifies a passive conn by its first datagram and counts the
// frames whose fseq it saw before.
func (c *tapPC) observe(d []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.typed {
		c.typed = true
		c.probe = true
		walkFrames(d, func(f wire.Frame) bool {
			if f.Type == wire.TypeRel {
				if h, _, err := wire.ParseRel(f.Payload); err == nil && (h.Type == wire.TypeOpen || h.Type == wire.TypeJoin) {
					c.probe = false
				}
			}
			return false
		})
	}
	if wire.IsPreface(d) || !c.established {
		// A handshake datagram, or any datagram the dialer's handshake reads
		// before its fseq window exists: rendr answers or drops it whole
		// (M2-D20), so its frames are not followed. A byte-equal copy of an
		// earlier one is a network duplicate or a verbatim repeat (an H1
		// resend, an H2 repeated for a duplicate H1): counted apart.
		for _, p := range c.early {
			if bytes.Equal(p, d) {
				c.n.EarlyCopies++
				return
			}
		}
		c.early = append(c.early, slices.Clone(d))
		return
	}
	frames, dups := 0, 0
	walkFrames(d, func(f wire.Frame) bool {
		frames++
		if _, ok := c.seen[f.Fseq]; ok {
			dups++
			return true
		}
		if c.seen == nil {
			c.seen = make(map[uint32]struct{})
		}
		c.seen[f.Fseq] = struct{}{}
		return true
	})
	c.n.DupFrames += dups
	if frames > 0 && dups == frames {
		c.n.DupDgrams++
	}
}

// WriteTo implements net.PacketConn: it renumbers the frames by the
// injections so far and, when an injection is armed and d holds a DGRAM,
// writes that DGRAM again right after d, alone, at the next fseq.
func (c *tapPC) WriteTo(d []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !wire.IsPreface(d) {
		c.established = true
	}
	if c.off == 0 && c.armed == 0 {
		return c.PacketConn.WriteTo(d, addr)
	}
	c.scratch = append(c.scratch[:0], d...)
	b := c.scratch
	var last uint32
	var dgram []byte
	forFrames(b, func(fr []byte) {
		fs := getFseq(fr) + c.off
		putFseq(fr, fs)
		last = fs
		if dgram == nil && wire.Type(fr[0]) == wire.TypeDgram {
			dgram = fr
		}
	})
	n, err := c.PacketConn.WriteTo(b, addr)
	if err != nil || c.armed == 0 || dgram == nil {
		if n == len(b) {
			n = len(d)
		}
		return n, err
	}
	dup := slices.Clone(dgram)
	putFseq(dup, last+1)
	if _, ierr := c.PacketConn.WriteTo(dup, addr); ierr == nil {
		c.off++
		c.armed--
		c.n.Injected++
	}
	return len(d), nil
}

// arm makes the conn inject one session-level duplicate with its next
// datagram that carries a DGRAM.
func (c *tapPC) arm() {
	c.mu.Lock()
	c.armed++
	c.mu.Unlock()
}

// counts returns the conn's counters and whether it is a probe carrier's.
func (c *tapPC) counts() (tapCounts, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n, c.probe
}

// forFrames calls f with the bytes of every whole frame of the rendr bytes
// b (after a PREFACE or PREFACE_ACK); the walk stops at a frame that runs
// past b.
func forFrames(b []byte, f func(frame []byte)) {
	if wire.IsPreface(b) {
		b = b[wire.PrefaceLen:]
	}
	for len(b) >= wire.HeaderLen {
		end := wire.HeaderLen + (int(b[2])<<16 | int(b[3])<<8 | int(b[4])) + wire.TrailerLen
		if end > len(b) {
			return
		}
		f(b[:end])
		b = b[end:]
	}
}

// getFseq reads a frame's fseq.
func getFseq(fr []byte) uint32 {
	return uint32(fr[5])<<24 | uint32(fr[6])<<16 | uint32(fr[7])<<8 | uint32(fr[8])
}

// putFseq writes a frame's fseq and recomputes its CRC-32C trailer.
func putFseq(fr []byte, fs uint32) {
	fr[5], fr[6], fr[7], fr[8] = byte(fs>>24), byte(fs>>16), byte(fs>>8), byte(fs)
	end := len(fr) - wire.TrailerLen
	wire.PutTrailer(fr[end:], wire.CRC(fr[:end]))
}

// tapSet holds every tap of a world, in creation order.
type tapSet struct {
	mu   sync.Mutex
	taps []*tapPC
}

// wrap wraps pc; a dialer's conn is classified by its DialInfo, a
// passive's by the first datagram it reads.
func (s *tapSet) wrap(pc net.PacketConn, dialer bool, link string, id rendr.CarrierID, probe bool) *tapPC {
	c := &tapPC{PacketConn: pc, dialer: dialer, link: link, id: id, typed: dialer, probe: probe, established: !dialer}
	s.mu.Lock()
	s.taps = append(s.taps, c)
	s.mu.Unlock()
	return c
}

// sessionTaps returns the session carriers' taps of one end.
func (s *tapSet) sessionTaps(dialer bool) []*tapPC {
	s.mu.Lock()
	all := slices.Clone(s.taps)
	s.mu.Unlock()
	var out []*tapPC
	for _, c := range all {
		if _, probe := c.counts(); c.dialer == dialer && !probe {
			out = append(out, c)
		}
	}
	return out
}

// dialerTap returns the dialer's tap of carrier id.
func (s *tapSet) dialerTap(id rendr.CarrierID) *tapPC {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.taps {
		if c.dialer && c.id == id {
			return c
		}
	}
	return nil
}

// tapTotals sums the counters of one end's session carriers.
func (s *tapSet) tapTotals(dialer bool) tapCounts {
	var sum tapCounts
	for _, c := range s.sessionTaps(dialer) {
		n, _ := c.counts()
		sum = sum.add(n)
	}
	return sum
}
