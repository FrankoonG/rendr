package rendr

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/carrier"
	"github.com/FrankoonG/rendr/v2/internal/session"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/internal/wire"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// End-to-end test kit (design §11.1, integration layer): a dialer and a
// passive Runtime joined by rendrtest.Links inside synctest bubbles. Every
// Link's Accept is the passive Listener's Handle (or a test's own routing),
// so carriers go through the whole passive handshake and admission; the
// dialer's factories are the Links' Dial. Helpers of these tests start
// with "e2e" (the raw-wire admission helpers with "wp").

// e2eCarrier is the StreamCarrier of a Link.
func e2eCarrier(l *rendrtest.Link) StreamCarrier {
	return StreamCarrier{Name: l.Name(), Dial: l.Dial}
}

// e2ePair is two Runtimes, the passive's Listener and the Links between
// them. Create it inside the bubble that uses it; close it (close) before
// the bubble ends.
type e2ePair struct {
	t     testing.TB
	d, p  *Runtime // dialer, passive
	ln    *Listener
	links []*rendrtest.Link
}

// e2eNew builds both Runtimes with the same overrides (counter presets
// must be identical on both ends, L14) and one push-only Listener with lc
// on the passive, plus one Link per name whose Accept is that Listener's
// Handle.
func e2eNew(t testing.TB, dcfg, pcfg Config, ov *testhooks.Overrides, lc ListenConfig, names ...string) *e2ePair {
	t.Helper()
	e := &e2ePair{t: t, d: wpTestRuntime(t, dcfg, ov), p: wpTestRuntime(t, pcfg, ov)}
	e.ln = wpListen(t, e.p, lc)
	for _, n := range names {
		l := rendrtest.NewLink(rendrtest.LinkConfig{Name: n, Accept: e.ln.Handle})
		e.links = append(e.links, l)
		t.Cleanup(l.Close) // also when the test failed (before the Runtimes' cleanups: LIFO)
	}
	return e
}

// peer returns a Peer of the dialer over the given links (all when none).
func (e *e2ePair) peer(links ...*rendrtest.Link) *Peer {
	e.t.Helper()
	if len(links) == 0 {
		links = e.links
	}
	cs := make([]Carrier, len(links))
	for i, l := range links {
		cs[i] = e2eCarrier(l)
	}
	p, err := e.d.NewPeer(PeerConfig{Carriers: cs})
	if err != nil {
		e.t.Fatalf("NewPeer: %v", err)
	}
	return p
}

// close closes both Runtimes (the dialer first), then every Link, and
// requires that both Runtimes hold no session, reservation or buffered
// byte any more (R7: BufferedBytes == 0 after Close) and abandoned nothing.
func (e *e2ePair) close() {
	e.t.Helper()
	e.d.Close()
	e.p.Close()
	for _, l := range e.links {
		l.Close()
	}
	for _, rt := range []*Runtime{e.d, e.p} {
		wpNoState(e.t, rt)
		if st := rt.Status(); st.Abandoned != 0 {
			e.t.Fatalf("Runtime %v abandoned %d goroutines", rt.InstanceID(), st.Abandoned)
		}
	}
}

// e2eConfirm accepts one session on ln and confirms it.
func e2eConfirm(t testing.TB, ln *Listener) *Conn {
	t.Helper()
	pc, err := ln.Accept(context.Background())
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	c, err := pc.Confirm()
	if err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	return c
}

// dialResult is the outcome of an asynchronous Dial.
type dialResult struct {
	c   *Conn
	err error
	at  time.Duration // since the Dial started
}

// e2eDialAsync dials on its own goroutine.
func e2eDialAsync(ctx context.Context, p *Peer, o DialOptions) <-chan dialResult {
	ch := make(chan dialResult, 1)
	start := time.Now()
	go func() {
		c, err := p.Dial(ctx, o)
		ch <- dialResult{c, err, time.Since(start)}
	}()
	return ch
}

// e2eOpen dials p and confirms the session on ln: the two ends of one
// session.
func e2eOpen(t testing.TB, p *Peer, ln *Listener, o DialOptions) (dc, pc *Conn) {
	t.Helper()
	res := e2eDialAsync(context.Background(), p, o)
	pc = e2eConfirm(t, ln)
	r := <-res
	if r.err != nil {
		t.Fatalf("Dial: %v", r.err)
	}
	return r.c, pc
}

// e2eExchange writes n bytes of PRNG(seed) on a and verifies them on b,
// concurrently with the reverse direction (n bytes of PRNG(seed+1) from b
// to a): both directions are in flight at once.
func e2eExchange(t testing.TB, a, b net.Conn, n int64, seed uint64) {
	t.Helper()
	if err := e2eExchangeErr(a, b, n, seed); err != nil {
		t.Fatalf("exchange: %v", err)
	}
}

// e2eExchangeErr is e2eExchange returning the first error (for use on a
// goroutine other than the test's).
func e2eExchangeErr(a, b net.Conn, n int64, seed uint64) error {
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	pump := func(w, r net.Conn, seed uint64) {
		wg.Go(func() {
			_, err := io.Copy(onlyWriter{w}, io.LimitReader(rendrtest.PRNG(seed), n))
			errs <- err
		})
		wg.Go(func() {
			v := rendrtest.NewVerifier(seed, n)
			buf := make([]byte, 32<<10)
			var got int64
			for got < n {
				k, err := r.Read(buf[:min(int64(len(buf)), n-got)])
				if k > 0 {
					v.Write(buf[:k])
					got += int64(k)
				}
				if err != nil {
					errs <- err
					return
				}
			}
			errs <- v.Done(io.EOF)
		})
	}
	pump(a, b, seed)
	pump(b, a, seed+1)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// onlyWriter hides io.ReaderFrom so that io.Copy uses plain Writes.
type onlyWriter struct{ io.Writer }

// e2eFinish half-closes both ends, requires io.EOF on both, closes both and
// waits until both sessions ended cleanly (io.EOF).
func e2eFinish(t testing.TB, a, b *Conn) {
	t.Helper()
	for _, c := range []*Conn{a, b} {
		if err := c.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite: %v", err)
		}
	}
	for _, c := range []*Conn{a, b} {
		var x [1]byte
		if n, err := c.Read(x[:]); n != 0 || err != io.EOF {
			t.Fatalf("Read after the peer's FIN: (%d, %v), want EOF", n, err)
		}
	}
	for _, c := range []*Conn{a, b} {
		if err := c.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}
	for _, c := range []*Conn{a, b} {
		e2eDone(t, c, 30*time.Second)
		if st := c.Status(); st.State != StateEnded || st.Err != io.EOF {
			t.Fatalf("session %v after a clean finish: state %v, err %v", c.ID(), st.State, st.Err)
		}
	}
}

// e2eDone waits until the session of c is done (ended and every goroutine
// it owns joined), failing after within (virtual time).
func e2eDone(t testing.TB, c *Conn, within time.Duration) {
	t.Helper()
	select {
	case <-c.s.Done():
	case <-time.After(within):
		t.Fatalf("session %v not done after %v: %+v", c.ID(), within, c.Status())
	}
}

// eventLog records Config.OnEvent calls.
type eventLog struct {
	mu  sync.Mutex
	evs []Event
}

func (l *eventLog) add(ev Event) {
	l.mu.Lock()
	l.evs = append(l.evs, ev)
	l.mu.Unlock()
}

// of returns the recorded events of kind k (all sessions).
func (l *eventLog) of(k EventKind) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []Event
	for _, ev := range l.evs {
		if ev.Kind == k {
			out = append(out, ev)
		}
	}
	return out
}

// all returns every recorded event.
func (l *eventLog) all() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Event(nil), l.evs...)
}

// TestDialConfirmRoundTrip: the whole public path of one session between
// two Runtimes. Dial waits until the passive application confirms; the
// PendingConn names the session, mode, metadata and dialer instance; both
// Conns report the same session with logical addresses and each other's
// instance; data crosses both ways at once intact; Status shows one
// active carrier per end, the admission counters move pending → open,
// CloseWrite/EOF/Close end both sessions cleanly (io.EOF), events report
// CarrierUp and SessionEnd in Seq order, the passive remembers a tombstone
// that answers UNKNOWN_SESSION, and nothing is left after Close.
func TestDialConfirmRoundTrip(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var dev, pev eventLog
		e := e2eNew(t, Config{OnEvent: dev.add}, Config{OnEvent: pev.add}, nil, ListenConfig{}, "a")
		peer := e.peer()
		meta := []byte("route: echo")
		res := e2eDialAsync(context.Background(), peer, DialOptions{Metadata: meta})
		pc, err := e.ln.Accept(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		select {
		case r := <-res:
			t.Fatalf("Dial returned before Confirm: %v", r.err)
		default:
		}
		if pc.Mode() != ModeSelector || !bytes.Equal(pc.Metadata(), meta) || pc.PeerInstance() != e.d.InstanceID() || pc.ID() == (SessionID{}) {
			t.Fatalf("PendingConn: mode %v metadata %q instance %v id %v", pc.Mode(), pc.Metadata(), pc.PeerInstance(), pc.ID())
		}
		if st := e.p.Status(); st.Sessions.Pending != 1 || st.AcceptBacklog[0] != 1 || e.d.table.inUse() != 1 {
			t.Fatalf("while pending: passive %+v, dialer units %d", st, e.d.table.inUse())
		}
		sc, err := pc.Confirm()
		if err != nil {
			t.Fatal(err)
		}
		r := <-res
		if r.err != nil {
			t.Fatal(r.err)
		}
		dc := r.c
		if _, err := pc.Confirm(); err == nil {
			t.Fatal("a second Confirm succeeded")
		}
		synctest.Wait()

		if dc.ID() != pc.ID() || sc.ID() != pc.ID() || dc.PeerInstance() != e.p.InstanceID() || sc.PeerInstance() != e.d.InstanceID() {
			t.Fatalf("ids %v/%v, instances %v/%v", dc.ID(), sc.ID(), dc.PeerInstance(), sc.PeerInstance())
		}
		wantLocal := Addr{Instance: e.d.InstanceID(), Session: dc.ID()}
		wantRemote := Addr{Instance: e.p.InstanceID(), Session: dc.ID()}
		if dc.LocalAddr() != wantLocal || dc.RemoteAddr() != wantRemote || sc.LocalAddr() != wantRemote || sc.RemoteAddr() != wantLocal {
			t.Fatalf("addresses %v→%v and %v→%v", dc.LocalAddr(), dc.RemoteAddr(), sc.LocalAddr(), sc.RemoteAddr())
		}
		if dc.LocalAddr().Network() != "rendr" || !bytes.Equal(dc.Metadata(), meta) || !bytes.Equal(sc.Metadata(), meta) {
			t.Fatalf("network %q, metadata %q / %q", dc.LocalAddr().Network(), dc.Metadata(), sc.Metadata())
		}
		for _, x := range []struct {
			c    *Conn
			role Role
		}{{dc, RoleDialer}, {sc, RolePassive}} {
			st := x.c.Status()
			if st.Role != x.role || st.Mode != ModeSelector || st.State != StateOpen || st.Kind != KindStream || st.Err != nil ||
				len(st.Carriers) != 1 || st.Carriers[0].State != CarrierActive || st.Carriers[0].Kind != KindStream {
				t.Fatalf("%v status %+v", x.role, st)
			}
		}
		if st := dc.Status(); st.Carriers[0].Name != "a" || st.Carriers[0].ID == 0 || st.Carriers[0].ID != sc.Status().Carriers[0].ID {
			t.Fatalf("carriers %+v / %+v", st.Carriers, sc.Status().Carriers)
		}
		if ds, ps := e.d.Status(), e.p.Status(); ds.Sessions.Open != 1 || ps.Sessions.Open != 1 || ps.Sessions.Pending != 0 || ps.AcceptBacklog[0] != 0 {
			t.Fatalf("open counts: dialer %+v, passive %+v", ds.Sessions, ps.Sessions)
		}

		// Deadlines (net.Conn semantics, L06): a past read deadline fails Read
		// at once with a timeout and leaves the session usable; SetDeadline
		// covers both directions — after SetDeadline(past) a Write fails at
		// once with a timeout and accepts nothing (TxBytes stays 0), and a
		// Read times out after exactly its 100 ms deadline; zero clears.
		if err := sc.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
		var ne net.Error
		if n, err := sc.Read(make([]byte, 1)); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) || !errors.As(err, &ne) || !ne.Timeout() {
			t.Fatalf("Read past its deadline: (%d, %v)", n, err)
		}
		for _, c := range []*Conn{dc, sc} {
			if err := c.SetDeadline(time.Now().Add(-time.Second)); err != nil {
				t.Fatal(err)
			}
			ne = nil
			if n, err := c.Write([]byte("late")); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) || !errors.As(err, &ne) || !ne.Timeout() {
				t.Fatalf("%v Write after SetDeadline(past): (%d, %v), want (0, a timeout)", c.Status().Role, n, err)
			}
			if st := c.Status(); st.TxBytes != 0 || st.State != StateOpen {
				t.Fatalf("%v after a Write past its deadline: %d bytes accepted, state %v", st.Role, st.TxBytes, st.State)
			}
		}
		if err := dc.SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		if _, err := dc.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) || time.Since(start) != 100*time.Millisecond {
			t.Fatalf("Read with a 100 ms deadline: %v after %v", err, time.Since(start))
		}
		for _, c := range []*Conn{dc, sc} {
			if err := c.SetDeadline(time.Time{}); err != nil {
				t.Fatal(err)
			}
		}
		if err := dc.SetWriteDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
		e2eExchange(t, dc, sc, 3<<20+17, 1)
		if st := dc.Status(); st.TxBytes != 3<<20+17 || st.DeliveredBytes != 3<<20+17 || st.State != StateOpen {
			t.Fatalf("dialer byte counters %+v", st)
		}
		// SCHED (§7.5, §10.1): the dialer's initial epoch was applied and
		// echoed; the passive reports the epoch it applied as echoed.
		synctest.Wait()
		if ds, ps := dc.Status(), sc.Status(); ds.SchedEpoch == 0 || ds.SchedEchoed != ds.SchedEpoch ||
			ps.SchedEpoch != ds.SchedEpoch || ps.SchedEchoed != ps.SchedEpoch {
			t.Fatalf("SCHED epochs: dialer %d echoed %d, passive %d echoed %d", ds.SchedEpoch, ds.SchedEchoed, ps.SchedEpoch, ps.SchedEchoed)
		}
		e2eFinish(t, dc, sc)
		// An ended session is remembered for Runtime.Close only by its Done
		// channel, and only until it closed: reading Status drops it.
		for _, rt := range []*Runtime{e.d, e.p} {
			rt.Status()
			rt.mu.Lock()
			n := len(rt.draining)
			rt.mu.Unlock()
			if n != 0 {
				t.Fatalf("Runtime %v still remembers %d ended sessions whose Done closed", rt.InstanceID(), n)
			}
		}
		ds, ps := e.d.Status(), e.p.Status()
		if ds.Sessions != (SessionCounts{}) || ps.Sessions != (SessionCounts{Tombstones: 1}) || e.d.table.inUse() != 0 || e.p.table.inUse() != 0 {
			t.Fatalf("after the end: dialer %+v, passive %+v", ds.Sessions, ps.Sessions)
		}
		if _, err := dc.Write([]byte{1}); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Write after the end: %v", err)
		}

		// A replayed OPEN of the ended session gets UNKNOWN_SESSION.
		d := wpConnect(t, e.ln, e.d.InstanceID(), 77)
		d.hello(e.p)
		d.send(wire.TypeOpen, 0, wpOpen(dc.ID(), wire.KindStream, 1, nil))
		d.expectOpenAck(wire.StatusUnknownSession, 0)
		d.expectEOF()
		d.close()

		e.close()
		for _, l := range []*eventLog{&dev, &pev} {
			evs := l.all()
			if len(l.of(EventCarrierUp)) != 1 || len(l.of(EventSessionEnd)) != 1 || len(l.of(EventMigration)) != 0 {
				t.Fatalf("events %+v", evs)
			}
			for i, ev := range evs {
				if ev.Seq != uint64(i+1) || ev.Session != dc.ID() {
					t.Fatalf("event %d: %+v", i, ev)
				}
			}
			if end := l.of(EventSessionEnd)[0]; end.Err != io.EOF {
				t.Fatalf("SessionEnd %+v", end)
			}
		}
	})
}

// rendrGoroutines counts the live goroutines running rendr's own code — the
// entry function (the bottom frame of the stack) belongs to this module,
// not to rendrtest and not to a test file — in total and by entry function.
// Inside a bubble, after synctest.Wait, it lists every goroutine a closed
// object failed to join (none may be left, L52).
func rendrGoroutines() (int, map[string]int) {
	buf := make([]byte, 64<<20)
	n := runtime.Stack(buf, true)
	by := make(map[string]int)
	total := 0
	for _, g := range strings.Split(string(buf[:n]), "\n\n") {
		lines := strings.Split(strings.TrimRight(g, "\n"), "\n")
		var fn, file string
		for i := 1; i+1 < len(lines); i += 2 {
			if strings.HasPrefix(lines[i], "created by ") {
				break
			}
			fn, file = lines[i], lines[i+1]
		}
		if k := strings.LastIndex(fn, "("); k > 0 {
			fn = fn[:k]
		}
		if strings.HasPrefix(fn, "github.com/FrankoonG/rendr/v2") && !strings.Contains(fn, "/rendrtest.") && !strings.Contains(file, "_test.go:") {
			by[fn]++
			total++
		}
	}
	return total, by
}

// The rendr mux integration kit (M3 WP10): dialer factories whose carriers
// run through a rendrtest.Tamper — its frame tap (Log) shows what each side
// placed for each handle, its Hold and Release stop and resume one
// direction —, factory call counts, and Runtime-level views of the shared
// trunks. Helpers of these tests start with "mx".

// mxTaps records the tampers of one factory's carriers, oldest first.
type mxTaps struct {
	mu    sync.Mutex
	tps   []*rendrtest.Tamper
	dials atomic.Int32 // factory calls
	fail  atomic.Bool  // factory calls fail at once (a dead path)
}

// mxErrDial is the error of a failing factory call.
var mxErrDial = &net.OpError{Op: "dial", Net: "test", Err: net.ErrClosed}

// mxTapCarrier returns a StreamCarrier over l whose every carrier passes
// through a new Tamper recorded in taps.
func mxTapCarrier(l *rendrtest.Link, taps *mxTaps) StreamCarrier {
	return StreamCarrier{Name: l.Name(), Dial: func(ctx context.Context) (net.Conn, error) {
		taps.dials.Add(1)
		if taps.fail.Load() {
			return nil, mxErrDial
		}
		c, err := l.Dial(ctx)
		if err != nil {
			return nil, err
		}
		a, a2 := net.Pipe()
		tp := rendrtest.NewTamper(a2, c)
		taps.mu.Lock()
		taps.tps = append(taps.tps, tp)
		taps.mu.Unlock()
		return a, nil
	}}
}

// tap returns the i-th tamper (its carrier the i-th factory call's).
func (m *mxTaps) tap(t testing.TB, i int) *rendrtest.Tamper {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if i >= len(m.tps) {
		t.Fatalf("tamper %d of %d", i, len(m.tps))
	}
	return m.tps[i]
}

// count returns the tampers made so far.
func (m *mxTaps) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.tps)
}

// close closes every tamper (each ends its two pumps).
func (m *mxTaps) close() {
	m.mu.Lock()
	tps := m.tps
	m.mu.Unlock()
	for _, tp := range tps {
		tp.Close()
	}
}

// mxFrames returns the logged frames of direction d of tp of type typ for
// handle h (any handle when h is 0 and typ a session type; handle 0 for a
// carrier-level type).
func mxFrames(tp *rendrtest.Tamper, d rendrtest.Dir, typ rendrtest.FrameType, h uint32) []rendrtest.FrameRec {
	var out []rendrtest.FrameRec
	for _, r := range tp.Log(d) {
		if r.Type == typ && (h == 0 || r.Handle == h) {
			out = append(out, r)
		}
	}
	return out
}

// mxHandles returns the set of handles of frames of type typ in direction d.
func mxHandles(tp *rendrtest.Tamper, d rendrtest.Dir, typ rendrtest.FrameType) map[uint32]int {
	out := map[uint32]int{}
	for _, r := range tp.Log(d) {
		if r.Type == typ {
			out[r.Handle]++
		}
	}
	return out
}

// mxPeer returns a dialer Peer of e over the given factories.
func (e *e2ePair) mxPeer(cs ...Carrier) *Peer {
	e.t.Helper()
	p, err := e.d.NewPeer(PeerConfig{Carriers: cs})
	if err != nil {
		e.t.Fatalf("NewPeer: %v", err)
	}
	return p
}

// mxOpen dials p and confirms the session on ln (e2eOpen), returning both
// ends and the dialer's carrier of factory name.
func mxOpen(t testing.TB, p *Peer, ln *Listener, o DialOptions) (dc, pc *Conn) {
	t.Helper()
	return e2eOpen(t, p, ln, o)
}

// mxCarrier returns c's live carrier named name ("" on the passive: any).
func mxCarrier(t testing.TB, c *Conn, name string) CarrierStatus {
	t.Helper()
	for _, cs := range c.Status().Carriers {
		if cs.State != CarrierDead && (name == "" || cs.Name == name) {
			return cs
		}
	}
	t.Fatalf("no live carrier %q: %+v", name, c.Status().Carriers)
	return CarrierStatus{}
}

// mxHandleOf returns the handle of c's live carrier named name ("": any):
// its view's on the shared trunk, read from the session's own status (the
// carrier's Stats.Handle).
func mxHandleOf(t testing.TB, c *Conn, name string) uint32 {
	t.Helper()
	for _, cs := range c.s.Status().Carriers {
		if cs.State != session.LaneDead && (name == "" || cs.Name == name) {
			return cs.Stats.Handle
		}
	}
	t.Fatalf("no live carrier %q: %+v", name, c.Status().Carriers)
	return 0
}

// mxSessionCarriers returns the session-level carrier rows of c (dead ones
// included), with their handles.
func mxSessionCarriers(c *Conn) []session.CarrierStatus { return c.s.Status().Carriers }

// mxWait waits, at most within (virtual time), until cond holds.
func mxWait(t testing.TB, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within %v", what, within)
		}
		time.Sleep(time.Millisecond)
	}
}

// mxTrunkSet returns the passive trunk set's view-1 conns.
func mxTrunkSet(rt *Runtime) []*carrier.Conn {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return mapKeys(rt.trunks)
}

// mxPeOpen is peOpen bounded by within (virtual time): a Dial or an Accept
// that does not complete fails the test by its assertion instead of the
// binary's timeout.
func mxPeOpen(t testing.TB, p *Peer, ln *Listener, o DialOptions, within time.Duration) (dc, pc *PacketConn) {
	t.Helper()
	ch := peDial(p, o)
	ctx, cancel := context.WithTimeout(context.Background(), within)
	defer cancel()
	pp, err := ln.AcceptPacket(ctx)
	if err != nil {
		t.Fatalf("AcceptPacket: %v (no packet session offered within %v)", err, within)
	}
	if pc, err = pp.Confirm(); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("DialPacket: %v", r.err)
		}
		return r.c, pc
	case <-time.After(within):
		t.Fatalf("DialPacket did not return within %v of its confirmation", within)
	}
	return nil, nil
}

// mxOpenWithin is e2eOpen bounded by within (virtual time): a Dial or an
// Accept that does not complete fails the test by its assertion instead of
// the binary's timeout.
func mxOpenWithin(t testing.TB, p *Peer, ln *Listener, o DialOptions, within time.Duration) (dc, pc *Conn) {
	t.Helper()
	res := e2eDialAsync(context.Background(), p, o)
	ctx, cancel := context.WithTimeout(context.Background(), within)
	defer cancel()
	pend, err := ln.Accept(ctx)
	if err != nil {
		t.Fatalf("Accept: %v (no session offered within %v)", err, within)
	}
	if pc, err = pend.Confirm(); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	select {
	case r := <-res:
		if r.err != nil {
			t.Fatalf("Dial: %v", r.err)
		}
		return r.c, pc
	case <-time.After(within):
		t.Fatalf("Dial did not return within %v of its confirmation", within)
	}
	return nil, nil
}

// Dedicated carriers for the M1/M2 tests whose premise is one carrier per
// session (M3-D2: rendr mux is the default for every factory that is not a
// CheapSubflow). Those tests measure per-session carriers — their count,
// reader stages and goroutines, a session's Done joining its carriers, a
// carrier's own CLOSE drain — so they run on CheapSubflow factories, which
// keep M2's path exactly; their mux counterparts are the WP10 tests
// (TestViewGoneJoin_L52, TestStatusMuxIdentities, TestRuntimeCloseJoinsTrunks_L52,
// TestMuxOpenAfterListenerClose_L50, ...).

// dedicated returns c as a CheapSubflow factory (M2's dedicated carriers).
func dedicated(c StreamCarrier) StreamCarrier {
	c.Props.CheapSubflow = true
	return c
}

// dedicatedPeer is e.peer with every factory a CheapSubflow one.
func (e *e2ePair) dedicatedPeer(links ...*rendrtest.Link) *Peer {
	e.t.Helper()
	if len(links) == 0 {
		links = e.links
	}
	cs := make([]Carrier, len(links))
	for i, l := range links {
		cs[i] = dedicated(e2eCarrier(l))
	}
	p, err := e.d.NewPeer(PeerConfig{Carriers: cs})
	if err != nil {
		e.t.Fatalf("NewPeer: %v", err)
	}
	return p
}

// Scripted raw-wire dialers for the passive admission tests (design §11.1:
// "scripted raw-wire peers for admission"). A wpDialer speaks the v2 wire
// format byte by byte against a rendr passive over the dialer end of a
// net.Pipe whose other end is handed to Listener.Handle. It reads
// everything the passive writes before it writes again (design §0.8 V1),
// so the unbuffered pipe never blocks both ends.

// wpTestRuntime builds a Runtime for a test from cfg and ov (nil: none),
// failing the test on error. The test closes it; a cleanup closes it again
// (Close is idempotent), so that a failed test still ends its bubble
// without goroutines left behind.
func wpTestRuntime(t testing.TB, cfg Config, ov *testhooks.Overrides) *Runtime {
	t.Helper()
	rt, err := newRuntime(cfg, ov)
	if err != nil {
		t.Fatalf("newRuntime: %v", err)
	}
	t.Cleanup(func() { rt.Close() })
	return rt
}

// wpListen creates a push-only Listener (fed by Handle) with cfg.
func wpListen(t testing.TB, rt *Runtime, cfg ListenConfig) *Listener {
	t.Helper()
	ln, err := rt.Listen(cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	return ln
}

// wpInst returns a dialer InstanceID whose bytes are all b (never zero for
// b ≠ 0).
func wpInst(b byte) [16]byte {
	var id [16]byte
	for i := range id {
		id[i] = b
	}
	return id
}

// wpSID returns a session ID derived from i (never zero).
func wpSID(i int) [16]byte {
	var sid [16]byte
	sid[0] = 0x5e
	binary.BigEndian.PutUint64(sid[8:], uint64(i))
	return sid
}

// wpDialer is one scripted dialer carrier.
type wpDialer struct {
	t      testing.TB
	nc     net.Conn // the dialer end
	inst   [16]byte
	id     uint32 // carrier ID
	txFseq uint32 // fseq of the next frame this dialer sends
	rxFseq uint32 // fseq expected on the next frame from the passive
}

// wpConnect creates a pipe, hands the passive end to ln.Handle (which must
// accept it) and returns the dialer end. A cleanup closes the dialer end
// (again), so that a failed test leaves no passive write blocked on it.
func wpConnect(t testing.TB, ln *Listener, inst [16]byte, id uint32) *wpDialer {
	t.Helper()
	a, b := net.Pipe()
	if err := ln.Handle(a); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	t.Cleanup(func() { b.Close() })
	return &wpDialer{t: t, nc: b, inst: inst, id: id, txFseq: wire.FirstFseq, rxFseq: wire.FirstFseq}
}

// wpPreface encodes a valid dialer PREFACE.
func wpPreface(inst [16]byte, id uint32) []byte {
	b := make([]byte, wire.PrefaceLen)
	wire.PutPreface(b, &wire.Preface{Minor: wire.Minor, Kind: wire.KindStream, Instance: inst, CarrierID: id})
	return b
}

// wpRecrc recomputes the CRC of a 40-byte preface after its bytes 0–35
// were edited (a well-formed preface with another value).
func wpRecrc(b []byte) []byte {
	binary.BigEndian.PutUint32(b[36:40], wire.CRC(b[:36]))
	return b
}

// sendPreface writes p (40 bytes or a malformed variant) and reads the
// answer: a 40-byte PREFACE_ACK, or ok == false when the passive closed the
// carrier without one (n bytes received before EOF). Each direction then
// numbers its frames from its own preface's CRC field (design §0.13 A6).
func (d *wpDialer) sendPreface(p []byte) (ack wire.PrefaceAck, ok bool, n int) {
	d.t.Helper()
	if len(p) >= wire.PrefaceLen {
		d.txFseq = wire.PrefaceFseq(p)
	}
	if _, err := d.nc.Write(p); err != nil {
		return ack, false, 0 // closed before it read the whole preface
	}
	var b [wire.PrefaceLen]byte
	n, err := io.ReadFull(d.nc, b[:])
	if err != nil {
		return ack, false, n
	}
	ack, err = wire.ParsePrefaceAck(b[:])
	if err != nil {
		d.t.Fatalf("PREFACE_ACK does not parse: %v", err)
	}
	d.rxFseq = wire.PrefaceFseq(b[:])
	return ack, true, n
}

// hello runs the PREFACE exchange and requires PREFACE_ACK(OK) from rt.
func (d *wpDialer) hello(rt *Runtime) {
	d.t.Helper()
	ack, ok, _ := d.sendPreface(wpPreface(d.inst, d.id))
	if !ok {
		d.t.Fatal("PREFACE not answered")
	}
	if ack.Status != wire.PrefaceOK || ack.Instance != rt.InstanceID() || ack.CarrierID != d.id {
		d.t.Fatalf("PREFACE_ACK %+v, want OK from %v for carrier %d", ack, rt.InstanceID(), d.id)
	}
}

// frame encodes the next frame of type ty with this dialer's fseq and the
// handle its type requires.
func (d *wpDialer) frame(ty wire.Type, flags uint8, payload []byte) []byte {
	var handle uint32
	if !ty.CarrierLevel() {
		handle = wire.SessionHandle
	}
	f := wire.AppendFrame(nil, wire.Header{Type: ty, Flags: flags, Fseq: d.txFseq, Handle: handle}, payload)
	d.txFseq++
	return f
}

// send writes one frame; the passive reads frames completely, so the write
// returns once it was read.
func (d *wpDialer) send(ty wire.Type, flags uint8, payload []byte) {
	d.t.Helper()
	if _, err := d.nc.Write(d.frame(ty, flags, payload)); err != nil {
		d.t.Fatalf("writing %v: %v", ty, err)
	}
}

// sendAsync writes one frame on its own goroutine: for a frame the passive
// answers before reading it completely (an OPEN whose metadata it refuses
// unread). The returned channel reports the write's result.
func (d *wpDialer) sendAsync(ty wire.Type, flags uint8, payload []byte) <-chan error {
	f := d.frame(ty, flags, payload)
	done := make(chan error, 1)
	go func() {
		_, err := d.nc.Write(f)
		done <- err
	}()
	return done
}

// recv reads one complete frame and checks its CRC and fseq.
func (d *wpDialer) recv() (wire.Frame, error) {
	var hb [wire.HeaderLen]byte
	if _, err := io.ReadFull(d.nc, hb[:]); err != nil {
		return wire.Frame{}, err
	}
	h, err := wire.ParseHeader(hb[:])
	if err != nil {
		return wire.Frame{}, fmt.Errorf("header: %w", err)
	}
	rest := make([]byte, int(h.Len)+wire.TrailerLen)
	if _, err := io.ReadFull(d.nc, rest); err != nil {
		return wire.Frame{}, err
	}
	payload := rest[:h.Len]
	if wire.CRCUpdate(wire.CRC(hb[:]), payload) != wire.Trailer(rest[h.Len:]) {
		return wire.Frame{}, fmt.Errorf("%v: %w", h.Type, wire.ErrCRC)
	}
	if h.Fseq != d.rxFseq {
		return wire.Frame{}, fmt.Errorf("%v: fseq %d, want %d", h.Type, h.Fseq, d.rxFseq)
	}
	d.rxFseq++
	return wire.Frame{Header: h, Payload: payload}, nil
}

// expect reads one frame and requires its type.
func (d *wpDialer) expect(ty wire.Type) wire.Frame {
	d.t.Helper()
	f, err := d.recv()
	if err != nil {
		d.t.Fatalf("waiting for %v: %v", ty, err)
	}
	if f.Type != ty {
		d.t.Fatalf("got %v (%d bytes), want %v", f.Type, len(f.Payload), ty)
	}
	return f
}

// expectOpenAck reads one OPEN_ACK and requires status and code.
func (d *wpDialer) expectOpenAck(st wire.AckStatus, code uint32) wire.OpenAck {
	d.t.Helper()
	f := d.expect(wire.TypeOpenAck)
	if f.Handle != wire.SessionHandle {
		d.t.Fatalf("OPEN_ACK on handle %d", f.Handle)
	}
	a, err := wire.ParseOpenAck(f.Payload)
	if err != nil {
		d.t.Fatalf("OPEN_ACK: %v", err)
	}
	if a.Status != st || a.Code != code {
		d.t.Fatalf("OPEN_ACK status %d code %d (%q), want status %d code %d", a.Status, a.Code, a.Msg, st, code)
	}
	return a
}

// expectJoinAck reads one JOIN_ACK and requires its status.
func (d *wpDialer) expectJoinAck(st wire.AckStatus) {
	d.t.Helper()
	f := d.expect(wire.TypeJoinAck)
	a, err := wire.ParseJoinAck(f.Payload)
	if err != nil {
		d.t.Fatalf("JOIN_ACK: %v", err)
	}
	if a.Status != st {
		d.t.Fatalf("JOIN_ACK status %d, want %d", a.Status, st)
	}
}

// expectEOF requires that the passive closes the carrier with nothing more
// written. The passive drains after its last frame until our EOF or 1 s
// (L05), so expectEOF closes our end first only when told to.
func (d *wpDialer) expectEOF() {
	d.t.Helper()
	var b [64]byte
	n, err := d.nc.Read(b[:])
	if n != 0 || !errors.Is(err, io.EOF) {
		d.t.Fatalf("read (%d bytes %x, %v), want EOF", n, b[:n], err)
	}
}

// close closes the dialer end.
func (d *wpDialer) close() { d.nc.Close() }

// wpOpen encodes an OPEN payload.
func wpOpen(sid [16]byte, kind wire.CarrierKind, mode uint8, meta []byte) []byte {
	b := make([]byte, wire.OpenFixedLen+len(meta))
	wire.PutOpen(b, &wire.Open{SID: sid, Kind: kind, Mode: mode, RetainMs: 30000, Window: 8 << 20, Metadata: meta})
	return b
}

// wpJoin encodes a JOIN payload.
func wpJoin(sid [16]byte, mode uint8, rxNext uint64) []byte {
	b := make([]byte, wire.JoinLen)
	wire.PutJoin(b, &wire.Join{SID: sid, Mode: mode, RxNext: rxNext})
	return b
}

// wpRst encodes an RST payload.
func wpRst(code uint32, msg string) []byte {
	b := make([]byte, wire.RstFixedLen+len(msg))
	wire.PutRst(b, &wire.Rst{Code: code, Msg: []byte(msg)})
	return b
}

// drain reads frames until the passive ends the carrier and returns their
// types. The passive closes in the L05 order — its CLOSE, then it reads
// until our EOF — so drain closes our end once it read that CLOSE.
func (d *wpDialer) drain() []wire.Type {
	var seen []wire.Type
	for {
		f, err := d.recv()
		if err != nil {
			return seen
		}
		seen = append(seen, f.Type)
		if f.Type == wire.TypeClose {
			d.close()
		}
	}
}

// wpPing encodes a PING (or PONG) payload.
func wpPing(p wire.Ping) []byte {
	b := make([]byte, wire.PingFixedLen+p.Pad)
	wire.PutPing(b, &p)
	return b
}

// wpProbe connects a scripted probe carrier (first frame PING) and returns
// it with the passive's first answer: the PONG of that PING, or the
// refusal (CLOSE or GOAWAY) in f.
func wpProbe(t testing.TB, rt *Runtime, ln *Listener, inst [16]byte, id uint32) (*wpDialer, wire.Frame) {
	t.Helper()
	d := wpConnect(t, ln, inst, id)
	d.hello(rt)
	ping := wire.Ping{ID: id, TS: uint64(id) << 8, Nonce: 0xfeed0000 + uint64(id)}
	d.send(wire.TypePing, 0, wpPing(ping))
	f, err := d.recv()
	if err != nil {
		t.Fatalf("probe %d: no answer to its PING: %v", id, err)
	}
	if f.Type == wire.TypePong && !bytes.Equal(f.Payload, wpPing(ping)) {
		t.Fatalf("probe %d: PONG %x does not echo PING %x", id, f.Payload, wpPing(ping))
	}
	return d, f
}

// wpPingPong sends one more PING with pad bytes and requires the echoing
// PONG.
func (d *wpDialer) pingPong(id uint32, pad int) {
	d.t.Helper()
	ping := wire.Ping{ID: id, TS: 77, Nonce: 0xabc0000 + uint64(id), Pad: pad}
	d.send(wire.TypePing, 0, wpPing(ping))
	f := d.expect(wire.TypePong)
	if f.Flags != 0 || f.Handle != 0 || !bytes.Equal(f.Payload, wpPing(ping)) {
		d.t.Fatalf("PONG flags %d handle %d payload %x, want an echo of %+v", f.Flags, f.Handle, f.Payload, ping)
	}
}

// wpTomb inserts a tombstone answering v for (dialer, sid) into rt's table
// with ttl (a passive session that ended; the session pointer is a dummy
// that the table never dereferences).
func wpTomb(t testing.TB, rt *Runtime, dialer [16]byte, sid [16]byte, v session.Verdict, ttl time.Duration) {
	t.Helper()
	k := passiveKey(InstanceID(dialer), SessionID(sid))
	s := new(session.Session)
	if !rt.table.reserve() {
		t.Fatal("no MaxSessions unit for a tombstone")
	}
	if _, ok := rt.table.insertOrGet(k, s, ttl, time.Now()); !ok {
		t.Fatalf("key %v already present", k)
	}
	if !rt.table.ended(k, s, v, time.Now()) {
		t.Fatalf("ending %v failed", k)
	}
}

// countConn counts the embedder Close calls of a conn (L51: exactly once).
type countConn struct {
	net.Conn
	closes atomic.Int32
}

func (c *countConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

// wpNoState requires that rt holds no session, reservation, handshake or
// sessionless carrier and that the memory budget is back to zero.
func wpNoState(t testing.TB, rt *Runtime) {
	t.Helper()
	st := rt.Status()
	sc := st.Sessions
	if sc.Open+sc.Pending+sc.Lingering+sc.Orphaned != 0 || rt.table.inUse() != 0 || st.AcceptBacklog != [2]int{} ||
		st.Handshakes != 0 || st.Sessionless != 0 || st.BufferedBytes != 0 {
		t.Fatalf("state left: %+v (MaxSessions units %d)", st, rt.table.inUse())
	}
}

// Scripted raw-wire datagram dialers for the passive admission tests of
// packet sessions (M2 design §A5.10, §A5.14): a wdDialer writes the first
// datagram H1 of a carrier byte by byte over the dialer end of a
// rendrtest.DatagramLink carrier whose passive end the link handed to the
// Listener — through HandlePacket, or through wdLink's hook, which wraps it
// in a transport of a chosen receive limit (a QUIC-like 1152) that records
// the limits the admission sets (wdIO).

// wdLink is a DatagramLink whose passive ends enter ln's datagram
// handshake through a PacketIO with receive limit limit (0: HandlePacket),
// each recorded in order.
type wdLink struct {
	t    testing.TB
	link *rendrtest.DatagramLink

	mu  sync.Mutex
	ios []*wdIO
	got chan struct{} // cap 64: one token per passive end
}

func newWDLink(t testing.TB, rt *Runtime, ln *Listener, limit int) *wdLink {
	t.Helper()
	w := &wdLink{t: t, got: make(chan struct{}, 64)}
	w.link = rendrtest.NewDatagramLink(rendrtest.DatagramLinkConfig{
		Name: "wd",
		Accept: func(pc net.PacketConn, peer net.Addr) error {
			if limit == 0 {
				return ln.HandlePacket(pc, peer)
			}
			pio, err := carrier.NewPacketIO(&rt.cenv, pc, peer, limit)
			if err != nil {
				return err
			}
			io := &wdIO{PacketIO: pio}
			if !ln.beginHandshake() {
				return net.ErrClosed
			}
			w.mu.Lock()
			w.ios = append(w.ios, io)
			w.mu.Unlock()
			rt.startHandshakeDatagram(ln, io, time.Now())
			w.got <- struct{}{}
			return nil
		},
	})
	t.Cleanup(func() { w.link.Close() })
	return w
}

// io returns the transport of the i-th passive end (wdLink with a limit).
func (w *wdLink) io(i int) *wdIO {
	w.t.Helper()
	for {
		w.mu.Lock()
		if i < len(w.ios) {
			io := w.ios[i]
			w.mu.Unlock()
			return io
		}
		w.mu.Unlock()
		<-w.got
	}
}

// wdIO is a passive datagram transport that records every receive limit
// set on it (Conn.SetBudget lowers it to the negotiated cmtu, R1-6).
type wdIO struct {
	carrier.PacketIO
	mu     sync.Mutex
	limits []int
}

func (w *wdIO) SetLimit(n int) {
	w.mu.Lock()
	w.limits = append(w.limits, n)
	w.mu.Unlock()
	w.PacketIO.SetLimit(n)
}

// lastLimit returns the latest SetLimit (0: none).
func (w *wdIO) lastLimit() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.limits) == 0 {
		return 0
	}
	return w.limits[len(w.limits)-1]
}

// wdDialer is one scripted dialer datagram carrier.
type wdDialer struct {
	t    testing.TB
	pc   net.PacketConn
	peer net.Addr
	inst [16]byte
	id   uint32
	h1   []byte // the last H1 written (resent verbatim)
	tx   uint32 // fseq of this dialer's next frame after H1
	rx   uint32 // fseq expected next from the passive (set by the PREFACE_ACK)

	flow  bool      // a FromPacketConn flow (wdHubDial): the H2 of an OPEN carries the address check
	first wire.Type // the first frame of the last H1 written
	check uint64    // the address check's nonce from H2 (0: none)
}

// dial opens a carrier of w as dialer inst with carrier ID id.
func (w *wdLink) dial(inst [16]byte, id uint32) *wdDialer {
	w.t.Helper()
	pc, peer, err := w.link.Dial(context.Background())
	if err != nil {
		w.t.Fatalf("DatagramLink.Dial: %v", err)
	}
	return &wdDialer{t: w.t, pc: pc, peer: peer, inst: inst, id: id}
}

// wdH1 builds a carrier's first datagram (M2-D19): PREFACE of kind
// datagram ‖ REL{FirstCseq, t, payload} at the PREFACE's first fseq.
func wdH1(inst [16]byte, id uint32, t wire.Type, payload []byte) []byte {
	pre := make([]byte, wire.PrefaceLen)
	wire.PutPreface(pre, &wire.Preface{Minor: wire.Minor, Kind: wire.KindDatagram, Instance: inst, CarrierID: id})
	rel := make([]byte, wire.RelHeadLen+len(payload))
	wire.PutRelHead(rel, &wire.RelHead{Cseq: wire.FirstCseq, Type: t, Handle: wire.SessionHandle})
	copy(rel[wire.RelHeadLen:], payload)
	return wire.AppendFrame(pre, wire.Header{Type: wire.TypeRel, Fseq: wire.PrefaceFseq(pre)}, rel)
}

// sendH1 writes the H1 carrying (t, payload).
func (d *wdDialer) sendH1(t wire.Type, payload []byte) {
	d.t.Helper()
	d.h1 = wdH1(d.inst, d.id, t, payload)
	d.first, d.tx = t, wire.PrefaceFseq(d.h1[:wire.PrefaceLen])+1
	if _, err := d.pc.WriteTo(d.h1, d.peer); err != nil {
		d.t.Fatalf("writing H1: %v", err)
	}
}

// read returns the next datagram from the passive within d (virtual time),
// or nil when none came.
func (d *wdDialer) read(within time.Duration) []byte {
	d.t.Helper()
	if err := d.pc.SetReadDeadline(time.Now().Add(within)); err != nil {
		d.t.Fatalf("SetReadDeadline: %v", err)
	}
	b := make([]byte, wire.MaxDatagram+1)
	n, _, err := d.pc.ReadFrom(b)
	switch {
	case errors.Is(err, os.ErrDeadlineExceeded):
		return nil
	case err != nil:
		d.t.Fatalf("ReadFrom: %v", err)
	}
	return b[:n]
}

// frames decodes the frames of datagram b (after a PREFACE_ACK, if any).
func (d *wdDialer) frames(b []byte) []wire.Frame {
	d.t.Helper()
	var out []wire.Frame
	for len(b) > 0 {
		f, n, err := wire.DecodeFrame(b)
		if err != nil {
			d.t.Fatalf("a frame of the passive's datagram: %v", err)
		}
		out = append(out, f)
		b = b[n:]
	}
	return out
}

// expectH2 requires H2 = PREFACE_ACK(OK, our carrier ID, from rt) ‖
// RACK{FirstCseq} (M2-D19) ‖, for an OPEN on a FromPacketConn flow and
// only there, the address check PING{id 0, nonce ≠ 0, pad 0} at the next
// fseq (carrier.SourceChecker), whose nonce it records (answerCheck).
func (d *wdDialer) expectH2(rt *Runtime) {
	d.t.Helper()
	b := d.read(time.Second)
	if len(b) < wire.PrefaceLen || !wire.IsPreface(b) {
		d.t.Fatalf("no H2: %x", b)
	}
	ack, err := wire.ParsePrefaceAck(b[:wire.PrefaceLen])
	if err != nil || ack.Status != wire.PrefaceOK || ack.CarrierID != d.id || ack.Instance != rt.InstanceID() {
		d.t.Fatalf("PREFACE_ACK %+v (%v), want OK for carrier %d from %v", ack, err, d.id, rt.InstanceID())
	}
	d.rx = wire.PrefaceFseq(b[:wire.PrefaceLen])
	fs := d.frames(b[wire.PrefaceLen:])
	want := 1
	if d.flow && d.first == wire.TypeOpen {
		want = 2
	}
	if len(fs) != want || fs[0].Type != wire.TypeRack || fs[0].Fseq != d.rx {
		d.t.Fatalf("H2 frames %+v, want a RACK at fseq %d and %d frames", fs, d.rx, want)
	}
	if r, err := wire.ParseRack(fs[0].Payload); err != nil || r.CumAck != wire.FirstCseq {
		d.t.Fatalf("H2 RACK %+v (%v), want cumAck %d", r, err, wire.FirstCseq)
	}
	d.rx++
	if want == 2 {
		p, err := wire.ParsePing(fs[1].Payload)
		if fs[1].Type != wire.TypePing || fs[1].Fseq != d.rx || err != nil || p.ID != 0 || p.Nonce == 0 || p.Pad != 0 {
			d.t.Fatalf("H2's address check %+v (%+v, %v), want PING{id 0, nonce ≠ 0} at fseq %d", fs[1], p, err, d.rx)
		}
		d.check = p.Nonce
		d.rx++
	}
}

// answerCheck answers H2's address check with PONG{id 0, nonce}, as
// Establish does (R1-14 (4)), with nonce xor (0: the check's own nonce).
func (d *wdDialer) answerCheck(xor uint64) {
	d.t.Helper()
	if d.check == 0 {
		d.t.Fatal("answerCheck: H2 carried no address check")
	}
	b := wire.AppendFrame(nil, wire.Header{Type: wire.TypePong, Fseq: d.tx}, wpPing(wire.Ping{Nonce: d.check ^ xor}))
	d.tx++
	if _, err := d.pc.WriteTo(b, d.peer); err != nil {
		d.t.Fatalf("writing the check's PONG: %v", err)
	}
}

// expectVerdict reads datagrams until the passive's REL{FirstCseq} and
// returns its inner frame type and payload (H3 or a reliable verdict,
// M2-D21); H2 repeats and RACKs before it are skipped.
func (d *wdDialer) expectVerdict() (wire.Type, []byte) {
	d.t.Helper()
	for range 16 {
		b := d.read(3 * time.Second)
		if b == nil {
			d.t.Fatal("no verdict within 3 s")
		}
		if wire.IsPreface(b) {
			continue // an H2 repeat
		}
		for _, f := range d.frames(b) {
			if f.Type != wire.TypeRel {
				continue
			}
			h, inner, err := wire.ParseRel(f.Payload)
			if err != nil || h.Cseq != wire.FirstCseq {
				d.t.Fatalf("REL %+v (%v), want cseq %d", h, err, wire.FirstCseq)
			}
			return h.Type, inner
		}
	}
	d.t.Fatal("no REL among 16 datagrams")
	return 0, nil
}

// expectOpenAck requires the verdict OPEN_ACK(st, code).
func (d *wdDialer) expectOpenAck(st wire.AckStatus, code uint32) wire.OpenAck {
	d.t.Helper()
	ty, inner := d.expectVerdict()
	if ty != wire.TypeOpenAck {
		d.t.Fatalf("verdict %v, want OPEN_ACK", ty)
	}
	a, err := wire.ParseOpenAck(inner)
	if err != nil || a.Status != st || a.Code != code {
		d.t.Fatalf("OPEN_ACK %+v (%v), want status %d code %d", a, err, st, code)
	}
	return a
}

// close closes the dialer end.
func (d *wdDialer) close() { d.pc.Close() }

// wdPacketOpen encodes a packet OPEN (M2 design §A3.5): window = the
// carrier's cmtu offer (0 on a stream carrier), pmtu = the MaxPayload
// offer.
func wdPacketOpen(sid [16]byte, mode uint8, window uint32, pmtu uint16) []byte {
	b := make([]byte, wire.OpenFixedLen)
	wire.PutOpen(b, &wire.Open{SID: sid, Kind: wire.KindDatagram, Mode: mode, RetainMs: 30000, Window: window, PMTU: pmtu})
	return b
}

// countPC counts the Close calls of an embedder net.PacketConn (L57: a
// conn rendr owns is closed exactly once; one it does not own never).
type countPC struct {
	net.PacketConn
	closes atomic.Int32
}

func (c *countPC) Close() error {
	c.closes.Add(1)
	return c.PacketConn.Close()
}

// panicAddr is a foreign net.Addr whose String panics (L38, L57).
type panicAddr struct{}

func (panicAddr) Network() string { return "panic" }
func (panicAddr) String() string  { panic("panicAddr.String called") }

// wdProbe writes a probe carrier's first datagram H1p = PREFACE ‖ PING
// (pad 0) and requires H2p = PREFACE_ACK(OK) ‖ PONG echoing it (M2-D71).
func (d *wdDialer) wdProbe(rt *Runtime) {
	d.t.Helper()
	pre := make([]byte, wire.PrefaceLen)
	wire.PutPreface(pre, &wire.Preface{Minor: wire.Minor, Kind: wire.KindDatagram, Instance: d.inst, CarrierID: d.id})
	ping := wpPing(wire.Ping{ID: 1, TS: 2, Nonce: 3})
	d.h1 = wire.AppendFrame(pre, wire.Header{Type: wire.TypePing, Fseq: wire.PrefaceFseq(pre)}, ping)
	d.tx = wire.PrefaceFseq(pre) + 1
	if _, err := d.pc.WriteTo(d.h1, d.peer); err != nil {
		d.t.Fatalf("writing H1p: %v", err)
	}
	b := d.read(time.Second)
	if len(b) < wire.PrefaceLen {
		d.t.Fatalf("no H2p: %x", b)
	}
	ack, err := wire.ParsePrefaceAck(b[:wire.PrefaceLen])
	if err != nil || ack.Status != wire.PrefaceOK || ack.CarrierID != d.id || ack.Instance != rt.InstanceID() {
		d.t.Fatalf("PREFACE_ACK %+v (%v)", ack, err)
	}
	fs := d.frames(b[wire.PrefaceLen:])
	if len(fs) != 1 || fs[0].Type != wire.TypePong || string(fs[0].Payload) != string(ping) {
		d.t.Fatalf("H2p frames %+v, want the PONG of %x", fs, ping)
	}
}

// expectRefusal requires a stateless PREFACE_ACK(st) alone.
func (d *wdDialer) expectRefusal(st wire.PrefaceStatus) {
	d.t.Helper()
	b := d.read(time.Second)
	if len(b) != wire.PrefaceLen {
		d.t.Fatalf("refusal %x, want a PREFACE_ACK alone", b)
	}
	if ack, err := wire.ParsePrefaceAck(b); err != nil || ack.Status != st {
		d.t.Fatalf("PREFACE_ACK %+v (%v), want status %d", ack, err, st)
	}
}

// wdHubDial opens a client of hub as dialer inst with carrier ID id.
func wdHubDial(t testing.TB, hub *rendrtest.DatagramHub, inst [16]byte, id uint32) *wdDialer {
	t.Helper()
	pc, peer, err := hub.Dial(context.Background())
	if err != nil {
		t.Fatalf("DatagramHub.Dial: %v", err)
	}
	return &wdDialer{t: t, pc: pc, peer: peer, inst: inst, id: id, flow: true}
}

// wdProbePing sends one more PING on a started probe carrier and requires
// its PONG (a sessionless carrier answers every PING).
func (d *wdDialer) wdProbePing(rt *Runtime) {
	d.t.Helper()
	ping := wpPing(wire.Ping{ID: 2, TS: 5, Nonce: 6})
	b := wire.AppendFrame(nil, wire.Header{Type: wire.TypePing, Fseq: d.tx}, ping)
	d.tx++
	if _, err := d.pc.WriteTo(b, d.peer); err != nil {
		d.t.Fatalf("writing a PING: %v", err)
	}
	for range 4 {
		r := d.read(time.Second)
		if r == nil {
			break
		}
		for _, f := range d.frames(r) {
			if f.Type == wire.TypePong && string(f.Payload) == string(ping) {
				return
			}
		}
	}
	d.t.Fatal("no PONG for the PING")
}

// wdNoFlowRecords requires that rt holds no passive packet session's flow
// record (rt.pflows): each one leaves with its session (Registry.Ended)
// or a lost insert, so none keeps an ended session reachable (invariant 4).
func wdNoFlowRecords(t testing.TB, rt *Runtime) {
	t.Helper()
	rt.fmu.Lock()
	n := len(rt.pflows)
	rt.fmu.Unlock()
	if n != 0 {
		t.Fatalf("%d flow records left after their sessions ended", n)
	}
}

// wdFindOpenAck reads the passive's datagrams until one carries a reliable
// OPEN_ACK (GOAWAY, CLOSE and RACKs around it skipped) and returns it;
// false when none came within 3 s of the previous datagram.
func (d *wdDialer) wdFindOpenAck() (wire.OpenAck, bool) {
	d.t.Helper()
	for range 32 {
		b := d.read(3 * time.Second)
		if b == nil {
			break
		}
		if wire.IsPreface(b) {
			continue
		}
		for _, f := range d.frames(b) {
			if f.Type != wire.TypeRel {
				continue
			}
			if h, inner, err := wire.ParseRel(f.Payload); err == nil && h.Type == wire.TypeOpenAck {
				a, err := wire.ParseOpenAck(inner)
				return a, err == nil
			}
		}
	}
	return wire.OpenAck{}, false
}
