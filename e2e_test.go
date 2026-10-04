package rendr

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

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
		// covers both directions; zero clears.
		if err := sc.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
		var ne net.Error
		if n, err := sc.Read(make([]byte, 1)); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) || !errors.As(err, &ne) || !ne.Timeout() {
			t.Fatalf("Read past its deadline: (%d, %v)", n, err)
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
