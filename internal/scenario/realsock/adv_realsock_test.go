package realsock

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The adversarial set's real-socket row (M3 design §A9.3, R1-23): a
// rendrtest.Tamper between real loopback TCP sockets, outside synctest
// bubbles. Its helpers carry the adv prefix: the package's other files
// belong to other work packages.

// advRace reports a race-detector build (the build setting "-race"; the
// file cannot carry a build tag of its own beside the package's others).
var advRace = func() bool {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return false
	}
	for _, s := range bi.Settings {
		if s.Key == "-race" {
			return s.Value == "true"
		}
	}
	return false
}()

// advNet is two Runtimes joined through a relay on loopback TCP: the
// dialer's factory connects to the relay; the relay accepts, connects to
// the passive's listener and puts a Tamper between the two sockets, which
// it registers by the dialer socket's address; the passive's listener
// hands every connection to its rendr Listener.
type advNet struct {
	t        testing.TB
	d, p     *rendr.Runtime
	ln       *rendr.Listener
	pl, rl   net.Listener // the passive's listener, the relay's
	wg       sync.WaitGroup
	mu       sync.Mutex
	tampers  map[string]*rendrtest.Tamper // by the dialer socket's address
	carriers map[rendr.CarrierID]string   // the dialer socket's address by CarrierID
	all      []*rendrtest.Tamper
}

func newAdvNet(t *testing.T) *advNet {
	t.Helper()
	n := &advNet{t: t, tampers: map[string]*rendrtest.Tamper{}, carriers: map[rendr.CarrierID]string{}}
	var err error
	if n.d, err = rendr.NewRuntime(rendr.Config{}); err != nil {
		t.Fatal(err)
	}
	if n.p, err = rendr.NewRuntime(rendr.Config{}); err != nil {
		t.Fatal(err)
	}
	if n.ln, err = n.p.Listen(rendr.ListenConfig{}); err != nil {
		t.Fatal(err)
	}
	if n.pl, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	if n.rl, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	n.wg.Add(2)
	go n.serve(n.pl, func(c net.Conn) { n.ln.Handle(c) })
	go n.serve(n.rl, func(c net.Conn) {
		up, err := net.Dial("tcp", n.pl.Addr().String())
		if err != nil {
			c.Close()
			return
		}
		tm := rendrtest.NewTamper(c, up)
		n.mu.Lock()
		n.tampers[c.RemoteAddr().String()] = tm
		n.all = append(n.all, tm)
		n.mu.Unlock()
	})
	return n
}

// serve accepts until the listener closes.
func (n *advNet) serve(l net.Listener, h func(net.Conn)) {
	defer n.wg.Done()
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		h(c)
	}
}

// peer returns a dialer Peer with one factory through the relay: a
// dedicated one (Props.CheapSubflow), or with mux one whose carriers the
// Peer's sessions share (rendr mux).
func (n *advNet) peer(mux bool) *rendr.Peer {
	n.t.Helper()
	p, err := n.d.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{rendr.StreamCarrier{Name: "relay", Props: rendr.Props{CheapSubflow: !mux},
		Dial: func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			c, err := d.DialContext(ctx, "tcp", n.rl.Addr().String())
			if err != nil {
				return nil, err
			}
			if di, ok := rendr.CarrierDialInfo(ctx); ok {
				n.mu.Lock()
				n.carriers[di.Carrier] = c.LocalAddr().String()
				n.mu.Unlock()
			}
			return c, nil
		}}}})
	if err != nil {
		n.t.Fatal(err)
	}
	return p
}

// open dials a session and confirms it.
func (n *advNet) open(p *rendr.Peer) (dc, pc *rendr.Conn) {
	n.t.Helper()
	type dialed struct {
		c   *rendr.Conn
		err error
	}
	ch := make(chan dialed, 1)
	go func() {
		c, err := p.Dial(context.Background(), rendr.DialOptions{})
		ch <- dialed{c, err}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pend, err := n.ln.Accept(ctx)
	if err != nil {
		n.t.Fatalf("Accept: %v", err)
	}
	if pc, err = pend.Confirm(); err != nil {
		n.t.Fatalf("Confirm: %v", err)
	}
	r := <-ch
	if r.err != nil {
		n.t.Fatalf("Dial: %v", r.err)
	}
	return r.c, pc
}

// tamperOf returns the tamper of the session's active carrier.
func (n *advNet) tamperOf(dc *rendr.Conn) (rendr.CarrierID, *rendrtest.Tamper) {
	n.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, c := range dc.Status().Carriers {
			if c.State != rendr.CarrierActive {
				continue
			}
			n.mu.Lock()
			tm := n.tampers[n.carriers[c.ID]]
			n.mu.Unlock()
			if tm != nil {
				return c.ID, tm
			}
		}
		if time.Now().After(deadline) {
			n.t.Fatal("no tamper for the session's active carrier")
		}
		time.Sleep(time.Millisecond)
	}
}

// close closes both Runtimes, the listeners and every tamper and joins
// the accept loops.
func (n *advNet) close() {
	n.d.Close()
	n.p.Close()
	n.pl.Close()
	n.rl.Close()
	n.wg.Wait()
	n.mu.Lock()
	all := n.all
	n.mu.Unlock()
	for _, tm := range all {
		tm.Close()
	}
}

// advFlow is size bytes of PRNG(seed) dialer → passive, verified up to EOF.
type advFlow struct {
	got  atomic.Int64
	done chan error
}

func advStart(dc, pc *rendr.Conn, size int64, seed uint64) *advFlow {
	f := &advFlow{done: make(chan error, 2)}
	go func() {
		_, err := io.Copy(struct{ io.Writer }{dc}, io.LimitReader(rendrtest.PRNG(seed), size))
		if err == nil {
			err = dc.CloseWrite()
		}
		f.done <- err
	}()
	go func() {
		v := rendrtest.NewVerifier(seed, size)
		buf := make([]byte, 64<<10)
		for {
			k, err := pc.Read(buf)
			if k > 0 {
				f.got.Add(int64(k))
				if _, werr := v.Write(buf[:k]); werr != nil {
					f.done <- v.Done(err)
					return
				}
			}
			if err != nil {
				f.done <- v.Done(err)
				return
			}
		}
	}()
	return f
}

// wait fails on any error of either side.
func (f *advFlow) wait(t testing.TB, what string) {
	t.Helper()
	for range 2 {
		select {
		case err := <-f.done:
			if err != nil {
				t.Fatalf("%s: %v", what, err)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: not done (%d bytes received)", what, f.got.Load())
		}
	}
}

// advUntil polls cond every millisecond for at most 5 s.
func advUntil(t testing.TB, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("not within 5 s: %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// advReadRec is a relay's upstream conn that counts what it reads and
// keeps the error that ended its reads.
type advReadRec struct {
	net.Conn
	n   atomic.Int64
	mu  sync.Mutex
	err error
}

func (c *advReadRec) Read(p []byte) (int, error) {
	k, err := c.Conn.Read(p)
	c.n.Add(int64(k))
	if err != nil {
		c.mu.Lock()
		if c.err == nil {
			c.err = err
		}
		c.mu.Unlock()
	}
	return k, err
}

// result returns the bytes read and the error that ended the reads (nil
// while they go on).
func (c *advReadRec) result() (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n.Load(), c.err
}

// advDead waits until carrier id is dead in get's status and returns it.
func advDead(t testing.TB, get func() rendr.SessionStatus, id rendr.CarrierID) rendr.CarrierStatus {
	t.Helper()
	var out rendr.CarrierStatus
	advUntil(t, "the carrier's death", func() bool {
		for _, c := range get().Carriers {
			if c.ID == id && c.State == rendr.CarrierDead {
				out = c
				return true
			}
		}
		return false
	})
	return out
}

// advEnd ends a session cleanly: both ends close and end with io.EOF
// (the dialer's flow already half-closed its direction).
func advEnd(t testing.TB, dc, pc *rendr.Conn) {
	t.Helper()
	if err := pc.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if k, err := dc.Read(b[:]); k != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("dialer Read after the passive's FIN: (%d, %v)", k, err)
	}
	dc.Close()
	pc.Close()
	for _, c := range []*rendr.Conn{dc, pc} {
		select {
		case <-c.Done():
		case <-time.After(5 * time.Second):
			t.Fatalf("session %v did not end", c.ID())
		}
		if st := c.Status(); st.Err != io.EOF {
			t.Fatalf("%v ended with %v, want io.EOF", st.Role, st.Err)
		}
	}
}

// TestRelaySpliceRealTCP_L43: a Tamper relays a carrier between real
// loopback TCP sockets — a dedicated carrier of one session, and ("mux/")
// a MUX trunk four sessions share — and damages it three ways while 16 MiB
// move dialer → passive (4 MiB under -race; on the trunk a quarter per
// session): "flip" — one bit of a DATA payload: the passive kills the
// carrier (crc mismatch) for every session on it; "splice" — the frames of
// session X's carrier (a trunk of four sessions X) spliced into session
// Y's (a trunk of four sessions Y, another Peer's): Y's passive kills it
// (fseq) for every Y, every X is untouched; "switch" — the relay
// reconnects its upstream mid-stream: the fresh connection is closed by
// the passive's handshake (not "RND2"), the carrier dies on both ends of
// every session on it. Each time the sessions redial through the relay and
// every stream arrives intact; nothing leaks.
func TestRelaySpliceRealTCP_L43(t *testing.T) {
	size := int64(16 << 20)
	if advRace {
		size = 4 << 20
	}
	advRows(t, size, false)
	t.Run("mux", func(t *testing.T) { advRows(t, size, true) })
}

// advRows runs the three rows on a dedicated carrier (one session) or on
// a MUX trunk (four sessions moving size/4 each).
func advRows(t *testing.T, size int64, mux bool) {
	k := 1
	if mux {
		k, size = 4, size/4
	}
	t.Run("flip", func(t *testing.T) {
		t.Cleanup(rendrtest.AssertNoLeak(t))
		n := newAdvNet(t)
		defer n.close()
		ds, ps := n.openK(n.peer(mux), k)
		fs := advStartAll(ds, ps, size, 1)
		advUntil(t, "a quarter of the transfer", func() bool { return fs[0].got.Load() >= size/4 })
		id, tm := n.shared(ds)
		tm.FlipBit(rendrtest.Up, rendrtest.NextOfType(rendrtest.FrameData), 13*8+20)
		advUntil(t, "the flip (stimulus)", func() bool { return tm.Stats().Flipped == 1 })
		for i, pc := range ps {
			if c := advDead(t, pc.Status, id); c.DeathCause != rendr.CauseProtocolViolation || !strings.Contains(c.DeathDetail, "crc mismatch") {
				t.Fatalf("session %d: the flipped carrier died of %v %q, want protocol_violation crc mismatch", i, c.DeathCause, c.DeathDetail)
			}
		}
		advWaitAll(t, fs, "the transfer across the flip")
		advEndAll(t, ds, ps)
	})
	t.Run("splice", func(t *testing.T) {
		t.Cleanup(rendrtest.AssertNoLeak(t))
		n := newAdvNet(t)
		defer n.close()
		// Dedicated: X and Y on carriers of their own of one Peer; MUX: a
		// Peer each, so each has a trunk of its own.
		px, py := n.peer(mux), n.peer(mux)
		if !mux {
			py = px
		}
		xd, xp := n.openK(px, k)
		yd, yp := n.openK(py, k)
		fx, fy := advStartAll(xd, xp, size, 2), advStartAll(yd, yp, size, 20)
		advUntil(t, "a quarter of both", func() bool { return fx[0].got.Load() >= size/4 && fy[0].got.Load() >= size/4 })
		_, tx := n.shared(xd)
		id, ty := n.shared(yd)
		ty.Splice(rendrtest.Up, tx, 0)
		advUntil(t, "X's frames in Y's carrier (stimulus)", func() bool { return ty.Stats().SplicedBytes > 0 })
		for i, pc := range yp {
			if c := advDead(t, pc.Status, id); c.DeathCause != rendr.CauseProtocolViolation || !strings.Contains(c.DeathDetail, "fseq") {
				t.Fatalf("Y %d: the spliced carrier died of %v %q, want protocol_violation fseq", i, c.DeathCause, c.DeathDetail)
			}
		}
		advWaitAll(t, fx, "X")
		advWaitAll(t, fy, "Y")
		for _, st := range advStatuses(xd, xp) {
			for _, c := range st.Carriers {
				if c.State == rendr.CarrierDead {
					t.Fatalf("X (%v) lost carrier %+v to Y's splice", st.Role, c)
				}
			}
		}
		advEndAll(t, xd, xp)
		advEndAll(t, yd, yp)
	})
	t.Run("switch", func(t *testing.T) {
		t.Cleanup(rendrtest.AssertNoLeak(t))
		n := newAdvNet(t)
		defer n.close()
		ds, ps := n.openK(n.peer(mux), k)
		fs := advStartAll(ds, ps, size, 4)
		advUntil(t, "a quarter of the transfer", func() bool { return fs[0].got.Load() >= size/4 })
		id, tm := n.shared(ds)
		var fresh *advReadRec
		tm.SwitchUpstream(func() (net.Conn, error) {
			c, err := net.Dial("tcp", n.pl.Addr().String())
			if err != nil {
				return nil, err
			}
			fresh = &advReadRec{Conn: c}
			return fresh, nil
		})
		if tm.Stats().Switched != 1 || fresh == nil {
			t.Fatalf("stimulus: %+v", tm.Stats())
		}
		// The passive closed the fresh connection without a byte back (no
		// PREFACE_ACK: its first bytes are not "RND2", L48): the relay's
		// read of it ended in EOF or a reset, not in its own close.
		advUntil(t, "the passive closing the fresh connection", func() bool { _, err := fresh.result(); return err != nil })
		if k, err := fresh.result(); k != 0 || errors.Is(err, net.ErrClosed) {
			t.Fatalf("the fresh connection: %d bytes back, then %v; want none, then the passive's close", k, err)
		}
		for _, st := range [][]*rendr.Conn{ds, ps} {
			for _, c := range st {
				if d := advDead(t, c.Status, id); d.DeathCause != rendr.CauseTransportError {
					t.Fatalf("the switched carrier died of %v %q, want transport_error", d.DeathCause, d.DeathDetail)
				}
			}
		}
		advUntil(t, "no handshake left on the passive", func() bool { return n.p.Status().Handshakes == 0 })
		// One snapshot: the sessions rejoin meanwhile (orphaned → open),
		// and Status counts each of them exactly once (SessionCounts).
		if st := n.p.Status(); st.Sessions.Open+st.Sessions.Orphaned+st.Sessions.Lingering != k || st.Sessions.Pending != 0 || st.AcceptBacklog != [2]int{} {
			t.Fatalf("the passive kept state from the fresh connection: %+v", st)
		}
		advWaitAll(t, fs, "the transfer across the switch")
		advEndAll(t, ds, ps)
	})
}

// openK opens k sessions over p.
func (n *advNet) openK(p *rendr.Peer, k int) (ds, ps []*rendr.Conn) {
	n.t.Helper()
	for range k {
		dc, pc := n.open(p)
		ds, ps = append(ds, dc), append(ps, pc)
	}
	return ds, ps
}

// shared returns the active carrier and its tamper of the sessions ds,
// which must all have it (one dedicated session; a MUX trunk's four).
func (n *advNet) shared(ds []*rendr.Conn) (rendr.CarrierID, *rendrtest.Tamper) {
	n.t.Helper()
	id, tm := n.tamperOf(ds[0])
	for i, dc := range ds[1:] {
		if j, _ := n.tamperOf(dc); j != id {
			n.t.Fatalf("premise: session %d is active on carrier %d, session 0 on %d (one trunk)", i+1, j, id)
		}
	}
	return id, tm
}

// advStartAll starts a flow on every session (seeds seed, seed+1, ...).
func advStartAll(ds, ps []*rendr.Conn, size int64, seed uint64) []*advFlow {
	fs := make([]*advFlow, len(ds))
	for i := range ds {
		fs[i] = advStart(ds[i], ps[i], size, seed+uint64(i))
	}
	return fs
}

// advWaitAll waits for every flow.
func advWaitAll(t testing.TB, fs []*advFlow, what string) {
	t.Helper()
	for i, f := range fs {
		f.wait(t, fmt.Sprintf("%s, session %d", what, i))
	}
}

// advEndAll ends every session cleanly.
func advEndAll(t testing.TB, ds, ps []*rendr.Conn) {
	t.Helper()
	for i := range ds {
		advEnd(t, ds[i], ps[i])
	}
}

// advStatuses returns the status of every end of the sessions.
func advStatuses(ds, ps []*rendr.Conn) []rendr.SessionStatus {
	var out []rendr.SessionStatus
	for _, c := range slices.Concat(ds, ps) {
		out = append(out, c.Status())
	}
	return out
}
