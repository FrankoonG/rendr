package l4

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/l4"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The first-byte latency of EarlyReturn through package l4 (plan:663; M4
// design §A12.2, §A13.3, R1-15, R1-18; the I2 integrator's file). One
// Link of 100 ms RTT and a single factory — so no probe carrier shares the
// path — joins a dialer Runtime and a passive one whose Listener's pending
// sessions go to the passive application: the l4.Server ("server") or the
// row's own handler that does what Handle does — dial the target, Confirm,
// Forward — and keeps the passive Conn so its Status can be read ("conn").
// The client either uses the l4.Dial Conn itself ("direct") or sits on a
// rendrtest.TargetPipe behind the ingress l4.Forward ("forward"). The target
// is a rendrtest.Target; a client-first exchange is a 1-KiB request and its
// 1-KiB echo. Every time is virtual (testing/synctest), so the criteria are
// exact.
//
// The rows:
//
//   - TestL4EarlyTTFB: on a fresh carrier the time from Dial to the first
//     answer byte is one RTT shorter with EarlyReturn than without (± 1 ms),
//     and the 1,024 request bytes are early on both ends; on a live trunk
//     (another session holds it) the two times are equal within 1 ms
//     (M4-D17).
//   - TestL4EarlyTTFBWithTargetDialDelay: the same with a 30-ms target dial;
//     the early bytes reach the target at most 1 ms after the target
//     connected (the Confirm follows at once).
//   - TestForwardEarlyFirstWriteRidesFirstFlight (R1-15): through the ingress
//     Forward a client that writes at once has its whole first write
//     travel early, in 200 of 200 runs.
//   - TestForwardEarlyServerFirstBounded (R1-15): a client that waits for the
//     server's banner costs the opening at most 20 ms: the session's carrier
//     is dialled 20 ms after Forward started, and the banner arrives.

// The fixture's figures.
const (
	ttfbOneWay = 50 * time.Millisecond // the Link's one-way delay: RTT 100 ms
	ttfbRTT    = 2 * ttfbOneWay
	ttfbReq    = 1 << 10 // the client-first request and its echo
	ttfbRuns   = 20      // runs each way (with and without EarlyReturn)
	ttfbSlack  = time.Millisecond
	// ttfbTargetDial is the target dial's default duration. A real
	// target's connect takes time; one that took none would let the
	// passive confirm in the same instant in which its early DATA frame
	// arrives, before the carrier reader handed it over, and the bytes
	// would then count as received after the verdict (EarlyBytes 0, with
	// the same latency).
	ttfbTargetDial = time.Millisecond
	// ttfbHold is l4's earlyFirstWriteWait (R1-15, M4-D57).
	ttfbHold = 20 * time.Millisecond
)

// ttfbOpts configures a TTFB world.
type ttfbOpts struct {
	shared    bool          // the factory's carriers are shared (rendr mux); else one fresh carrier per session
	app       string        // the passive application: "server" or "conn"
	dialDelay time.Duration // the target dial's duration (0: ttfbTargetDial)
	banner    int64         // > 0: the target sends this many bytes of PRNG(11), then its FIN; 0: echo
}

// ttfbWorld is one row's Runtimes, Link, Peer, passive application and
// target, with the instants the row measures.
type ttfbWorld struct {
	t      testing.TB
	o      ttfbOpts
	d, p   *rendr.Runtime
	ln     *rendr.Listener
	link   *rendrtest.Link
	peer   *rendr.Peer
	target *rendrtest.Target
	srv    *l4.Server
	cancel context.CancelFunc
	apps   sync.WaitGroup // the accept loop and its handlers

	mu        sync.Mutex
	dials     []time.Time            // the session carriers' factory calls
	connected map[string]time.Time   // address → the target connected (the Confirm follows)
	firstIn   map[string]time.Time   // address → the target's first byte from the session
	passive   map[string]*rendr.Conn // address → the passive Conn ("conn" only)
	appErrs   []error                // the "conn" handler's failures
	live0     [2]int64               // the session registry at the start
}

// newTTFBWorld builds the world inside the calling synctest bubble.
func newTTFBWorld(t testing.TB, o ttfbOpts) *ttfbWorld {
	t.Helper()
	w := &ttfbWorld{t: t, o: o, connected: map[string]time.Time{}, firstIn: map[string]time.Time{}, passive: map[string]*rendr.Conn{},
		live0: [2]int64{testhooks.LiveSessions.Load(), testhooks.ParkedSessions.Load()}}
	w.d = ttfbRuntime(t)
	w.p = ttfbRuntime(t)
	ln, err := w.p.Listen(rendr.ListenConfig{})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	w.ln = ln
	w.link = rendrtest.NewLink(rendrtest.LinkConfig{Name: "a", Accept: ln.Handle})
	w.link.SetDelay(ttfbOneWay, 0)
	w.peer, err = w.d.NewPeer(rendr.PeerConfig{Carriers: []rendr.Carrier{rendr.StreamCarrier{
		Name: "a", Dial: w.dial, Props: rendr.Props{CheapSubflow: !o.shared},
	}}})
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	b := rendrtest.TargetEcho()
	if o.banner > 0 {
		b = rendrtest.TargetGen(o.banner, 11)
	}
	w.target = rendrtest.NewTarget(b, 0)
	w.srv = &l4.Server{Dial: func(ctx context.Context, r l4.Request) (net.Conn, error) { return w.dialTarget(ctx, r.Addr) }}
	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel
	w.apps.Go(func() { w.acceptLoop(ctx) })
	return w
}

// ttfbRuntime is a Runtime with the production timings.
func ttfbRuntime(t testing.TB) *rendr.Runtime {
	t.Helper()
	v, err := testhooks.NewRuntime(rendr.Config{}, &testhooks.Overrides{})
	if err != nil {
		t.Fatalf("testhooks.NewRuntime: %v", err)
	}
	return v.(*rendr.Runtime)
}

// dial is the factory: it records the session carriers' calls.
func (w *ttfbWorld) dial(ctx context.Context) (net.Conn, error) {
	if info, ok := rendr.CarrierDialInfo(ctx); !ok || !info.Probe {
		w.mu.Lock()
		w.dials = append(w.dials, time.Now())
		w.mu.Unlock()
	}
	return w.link.Dial(ctx)
}

// dialCount returns the number of session carriers dialled so far and the
// instant of the last one.
func (w *ttfbWorld) dialCount() (int, time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.dials) == 0 {
		return 0, time.Time{}
	}
	return len(w.dials), w.dials[len(w.dials)-1]
}

// dialTarget is the target dial of both applications: it takes the
// configured time, connects to the target and taps its conn.
func (w *ttfbWorld) dialTarget(ctx context.Context, addr string) (net.Conn, error) {
	if w.o.dialDelay > 0 {
		time.Sleep(w.o.dialDelay)
	} else {
		time.Sleep(ttfbTargetDial)
	}
	c, err := w.target.Dial(ctx, addr)
	if err != nil {
		return nil, err
	}
	w.mu.Lock()
	w.connected[addr] = time.Now()
	w.mu.Unlock()
	return &ttfbTap{Conn: c, w: w, addr: addr}, nil
}

// acceptLoop is the passive application.
func (w *ttfbWorld) acceptLoop(ctx context.Context) {
	for {
		pc, err := w.ln.Accept(ctx)
		if err != nil {
			return
		}
		if w.o.app == "server" {
			w.apps.Go(func() { w.srv.Handle(ctx, pc) })
			continue
		}
		w.apps.Go(func() { w.handleConn(ctx, pc) })
	}
}

// handleConn is the "conn" application: Handle's sequence (the target is
// dialled while the session is pending, the session confirmed once it
// connected, then forwarded), keeping the passive Conn.
func (w *ttfbWorld) handleConn(ctx context.Context, pc *rendr.PendingConn) {
	fail := func(err error) {
		w.mu.Lock()
		w.appErrs = append(w.appErrs, err)
		w.mu.Unlock()
	}
	r, err := l4.ParseMetadata(pc.Metadata())
	if err != nil {
		pc.Reject(uint32(l4.CodeBadRequest), l4.CodeBadRequest.String())
		fail(err)
		return
	}
	tc, err := w.dialTarget(ctx, r.Addr)
	if err != nil {
		pc.Reject(uint32(l4.CodeDialFailed), l4.CodeDialFailed.String())
		fail(err)
		return
	}
	sc, err := pc.Confirm()
	if err != nil {
		tc.Close()
		fail(fmt.Errorf("%s: Confirm: %w", r.Addr, err))
		return
	}
	w.mu.Lock()
	w.passive[r.Addr] = sc
	w.mu.Unlock()
	l4.Forward(ctx, sc, tc)
}

// ttfbTap records the instant the session's first bytes reach the target
// (Forward's first Write on it); it offers the target conn's CloseWrite
// and SetLinger, which Forward uses.
type ttfbTap struct {
	net.Conn
	w    *ttfbWorld
	addr string
	once sync.Once
}

func (c *ttfbTap) Write(b []byte) (int, error) {
	c.once.Do(func() {
		c.w.mu.Lock()
		c.w.firstIn[c.addr] = time.Now()
		c.w.mu.Unlock()
	})
	return c.Conn.Write(b)
}

func (c *ttfbTap) CloseWrite() error {
	return c.Conn.(interface{ CloseWrite() error }).CloseWrite()
}

func (c *ttfbTap) SetLinger(sec int) error {
	return c.Conn.(interface{ SetLinger(int) error }).SetLinger(sec)
}

// at returns what the world recorded for addr: the target's connect
// instant, its first byte's instant and the passive Conn ("conn").
func (w *ttfbWorld) at(addr string) (connected, firstIn time.Time, passive *rendr.Conn) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.connected[addr], w.firstIn[addr], w.passive[addr]
}

// close stops the application, closes everything and checks that nothing
// is left: no session, buffered byte or actor in either Runtime, no
// target connection, the session registry back at its start.
func (w *ttfbWorld) close() {
	t := w.t
	t.Helper()
	w.cancel()
	w.peer.Close()
	w.d.Close()
	w.p.Close()
	w.apps.Wait()
	w.link.Close()
	w.target.Close()
	for _, rt := range []*rendr.Runtime{w.d, w.p} {
		st := rt.Status()
		sc := st.Sessions
		if sc.Open+sc.Pending+sc.Lingering+sc.Orphaned != 0 || st.Handshakes != 0 || st.Actors != 0 || st.BufferedBytes != 0 {
			t.Errorf("state left after Runtime.Close: %+v", st)
		}
	}
	if c := w.target.Counts(); c.Open != 0 {
		t.Errorf("%d target connections left open", c.Open)
	}
	if l, p := testhooks.LiveSessions.Load()-w.live0[0], testhooks.ParkedSessions.Load()-w.live0[1]; l != 0 || p != 0 {
		t.Errorf("session registry after Runtime.Close: %+d live, %+d parked", l, p)
	}
	w.mu.Lock()
	errs := w.appErrs
	w.mu.Unlock()
	for _, err := range errs {
		t.Errorf("passive application: %v", err)
	}
}

// ttfbRun is one client-first exchange's record.
type ttfbRun struct {
	addr   string
	ttfb   time.Duration // Dial's start to the first answer byte
	early  uint64        // the dialer's EarlyBytes
	dialer *rendr.Conn
}

// exchange runs one client-first exchange of ttfbReq bytes to addr: Dial
// (with EarlyReturn when early), the request written at once — on the Conn
// ("direct") or into the TargetPipe of an ingress Forward ("forward") — the
// echo read and checked, a half-close each way, and the session's end.
func (w *ttfbWorld) exchange(addr, path string, early bool, seed byte) (ttfbRun, error) {
	req := ttfbPattern(seed, ttfbReq)
	start := time.Now()
	c, err := l4.Dial(context.Background(), w.peer, addr, rendr.DialOptions{EarlyReturn: early})
	if err != nil {
		return ttfbRun{}, fmt.Errorf("Dial: %w", err)
	}
	run := ttfbRun{addr: addr, dialer: c}
	var rw io.ReadWriter = c
	var cw func() error = c.CloseWrite
	var res <-chan l4.ForwardResult
	if path == "forward" {
		cli, srv := rendrtest.TargetPipe(0)
		defer cli.Close()
		ch := make(chan l4.ForwardResult, 1)
		go func() { ch <- l4.Forward(context.Background(), c, srv) }()
		res, rw, cw = ch, cli, cli.CloseWrite
	}
	if _, err := rw.Write(req); err != nil {
		c.Close()
		return run, fmt.Errorf("request: %w", err)
	}
	got := make([]byte, ttfbReq)
	if _, err := io.ReadFull(rw, got[:1]); err != nil {
		c.Close()
		return run, fmt.Errorf("first answer byte: %w", err)
	}
	run.ttfb = time.Since(start)
	if _, err := io.ReadFull(rw, got[1:]); err != nil || !bytes.Equal(got, req) {
		c.Close()
		return run, fmt.Errorf("echo: %v (intact %v)", err, bytes.Equal(got, req))
	}
	if err := cw(); err != nil {
		c.Close()
		return run, fmt.Errorf("CloseWrite: %w", err)
	}
	if n, err := rw.Read(got); n != 0 || err != io.EOF {
		c.Close()
		return run, fmt.Errorf("after the echo: %d bytes, %v; want io.EOF", n, err)
	}
	if res != nil {
		if r := <-res; !r.Clean || r.ToSession != ttfbReq || r.ToLocal != ttfbReq {
			return run, fmt.Errorf("ingress Forward %+v, want a clean end with %d bytes each way", r, ttfbReq)
		}
	} else {
		c.Close()
	}
	select {
	case <-c.Done():
	case <-time.After(time.Minute):
		return run, fmt.Errorf("the dialer session not done a minute after the exchange: %+v", c.Status())
	}
	run.early = c.Status().EarlyBytes
	return run, nil
}

// ttfbPattern is n bytes of a pattern that depends on seed.
func ttfbPattern(seed byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*31) ^ seed
	}
	return b
}

// ttfbVariants runs f in a synctest bubble for every pair of client path
// and passive application.
func ttfbVariants(t *testing.T, f func(t *testing.T, path, app string)) {
	for _, path := range []string{"direct", "forward"} {
		for _, app := range []string{"server", "conn"} {
			t.Run(path+"/"+app, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) { f(t, path, app) })
			})
		}
	}
}

// ttfbPairs runs ttfbRuns exchanges each way, alternating, and returns
// the EarlyReturn runs and the classic ones (fatal on an exchange error).
func ttfbPairs(t *testing.T, w *ttfbWorld, path string) (early, classic []ttfbRun) {
	t.Helper()
	for i := range ttfbRuns {
		for _, e := range []bool{true, false} {
			addr := fmt.Sprintf("ttfb-%d-%v.test:80", i, e)
			r, err := w.exchange(addr, path, e, byte(i))
			if err != nil {
				t.Fatalf("%s: %v", addr, err)
			}
			if e {
				early = append(early, r)
			} else {
				classic = append(classic, r)
			}
		}
	}
	return early, classic
}

// checkEarlyRuns checks the early-data proofs of fresh-carrier EarlyReturn
// runs: the dialer's EarlyBytes, the passive's ("conn"), and the request
// at the target at most 1 ms after it connected — the passive held the
// bytes at its verdict, so they did not wait a round trip.
func checkEarlyRuns(t *testing.T, w *ttfbWorld, runs []ttfbRun) {
	t.Helper()
	for _, r := range runs {
		connected, firstIn, sc := w.at(r.addr)
		if r.early != ttfbReq {
			t.Errorf("%s: dialer EarlyBytes %d, want %d", r.addr, r.early, ttfbReq)
		}
		if w.o.app == "conn" {
			if sc == nil {
				t.Errorf("%s: no passive Conn", r.addr)
			} else if n := sc.Status().EarlyBytes; n != ttfbReq {
				t.Errorf("%s: passive EarlyBytes %d, want %d", r.addr, n, ttfbReq)
			}
		}
		if connected.IsZero() || firstIn.IsZero() || firstIn.Sub(connected) > ttfbSlack {
			t.Errorf("%s: the request reached the target %v after it connected, want at most %v", r.addr, firstIn.Sub(connected), ttfbSlack)
		}
	}
}

// TestL4EarlyTTFB (plan:663, PA-56, M4-D17; §A12.2, R1-18): a client-first
// exchange of 1 KiB each way over one Link of 100 ms RTT. On a fresh
// carrier — one per session, so every session dials — EarlyReturn's first
// answer byte comes exactly one RTT sooner than a classic Dial's (± 1 ms;
// the classic one is 2 RTT: OPEN/OPEN_ACK, then request/answer), and the
// request travelled early on both ends in every run. On a live trunk
// (rendr mux; another session holds it) the session opens on the trunk
// without early data, and the two times are equal within 1 ms. Stimulus:
// one carrier dial per fresh session, one trunk for every shared one.
func TestL4EarlyTTFB(t *testing.T) {
	t.Run("fresh carrier", func(t *testing.T) { ttfbVariants(t, ttfbFresh) })
	t.Run("live trunk", func(t *testing.T) { ttfbVariants(t, ttfbTrunk) })
}

// ttfbFresh is TestL4EarlyTTFB's fresh-carrier row.
func ttfbFresh(t *testing.T, path, app string) {
	w := newTTFBWorld(t, ttfbOpts{app: app})
	early, classic := ttfbPairs(t, w, path)
	if n, _ := w.dialCount(); n != 2*ttfbRuns {
		t.Errorf("stimulus: %d carrier dials, want one per session (%d)", n, 2*ttfbRuns)
	}
	for i := range early {
		if want := classic[i].ttfb - ttfbRTT; early[i].ttfb < want-ttfbSlack || early[i].ttfb > want+ttfbSlack {
			t.Errorf("run %d: first answer byte after %v with EarlyReturn, %v without; want one RTT (%v) less, ± %v",
				i, early[i].ttfb, classic[i].ttfb, ttfbRTT, ttfbSlack)
		}
		if classic[i].early != 0 {
			t.Errorf("run %d: a classic Dial reports EarlyBytes %d", i, classic[i].early)
		}
	}
	checkEarlyRuns(t, w, early)
	t.Logf("first answer byte: EarlyReturn %v, classic %v (RTT %v)", early[0].ttfb, classic[0].ttfb, ttfbRTT)
	w.close()
}

// ttfbTrunk is TestL4EarlyTTFB's live-trunk row.
func ttfbTrunk(t *testing.T, path, app string) {
	w := newTTFBWorld(t, ttfbOpts{app: app, shared: true})
	// The holder keeps the trunk live through every run.
	holder, err := l4.Dial(context.Background(), w.peer, "holder.test:80", rendr.DialOptions{})
	if err != nil {
		t.Fatalf("holder Dial: %v", err)
	}
	early, classic := ttfbPairs(t, w, path)
	if n, _ := w.dialCount(); n != 1 {
		t.Errorf("stimulus: %d carrier dials, want the one trunk", n)
	}
	for i := range early {
		if d := early[i].ttfb - classic[i].ttfb; d < -ttfbSlack || d > ttfbSlack {
			t.Errorf("run %d: first answer byte after %v with EarlyReturn, %v without; want equal within %v",
				i, early[i].ttfb, classic[i].ttfb, ttfbSlack)
		}
		if early[i].early != 0 {
			t.Errorf("run %d: EarlyReturn on the live trunk reports EarlyBytes %d, want 0 (M4-D17)", i, early[i].early)
		}
		if _, _, sc := w.at(early[i].addr); sc != nil && sc.Status().EarlyBytes != 0 {
			t.Errorf("run %d: passive EarlyBytes %d on the live trunk, want 0", i, sc.Status().EarlyBytes)
		}
	}
	t.Logf("first answer byte on the live trunk: EarlyReturn %v, classic %v", early[0].ttfb, classic[0].ttfb)
	holder.Close()
	w.close()
}

// TestL4EarlyTTFBWithTargetDialDelay (plan:663; §A12.2): as
// TestL4EarlyTTFB's fresh-carrier row with a target that takes 30 ms to
// connect: the saving is still exactly one RTT, and the early request
// reaches the target at most 1 ms after it connected (the passive confirms
// at once and forwards the bytes it held).
func TestL4EarlyTTFBWithTargetDialDelay(t *testing.T) {
	ttfbVariants(t, func(t *testing.T, path, app string) {
		const delay = 30 * time.Millisecond
		w := newTTFBWorld(t, ttfbOpts{app: app, dialDelay: delay})
		early, classic := ttfbPairs(t, w, path)
		for i := range early {
			if want := classic[i].ttfb - ttfbRTT; early[i].ttfb < want-ttfbSlack || early[i].ttfb > want+ttfbSlack {
				t.Errorf("run %d: first answer byte after %v with EarlyReturn, %v without; want one RTT (%v) less, ± %v",
					i, early[i].ttfb, classic[i].ttfb, ttfbRTT, ttfbSlack)
			}
			if classic[i].ttfb < 2*ttfbRTT+delay {
				t.Errorf("premise: run %d: a classic exchange took %v, less than 2 RTT + the target dial (%v)", i, classic[i].ttfb, 2*ttfbRTT+delay)
			}
		}
		checkEarlyRuns(t, w, early)
		t.Logf("first answer byte with a %v target dial: EarlyReturn %v, classic %v", delay, early[0].ttfb, classic[0].ttfb)
		w.close()
	})
}

// TestForwardEarlyFirstWriteRidesFirstFlight (R1-15, M4-D57): an
// EarlyReturn Conn handed to the ingress Forward while still pending, with
// a client that writes its first 1 KiB at once: Forward's session-reading
// pump holds its first Read until the client's bytes were written to the
// Conn, so the first OPEN carries them — EarlyBytes is the request's
// length on both ends in 200 of 200 runs, each on a fresh carrier. Without
// the hold the Read opens the session first, without early bytes.
func TestForwardEarlyFirstWriteRidesFirstFlight(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const runs = 200
		w := newTTFBWorld(t, ttfbOpts{app: "conn"})
		var early []ttfbRun
		for i := range runs {
			addr := fmt.Sprintf("first-%d.test:80", i)
			r, err := w.exchange(addr, "forward", true, byte(i))
			if err != nil {
				t.Fatalf("%s: %v", addr, err)
			}
			early = append(early, r)
		}
		dialer, passive := 0, 0
		for _, r := range early {
			if r.early != ttfbReq {
				dialer++
			}
			if _, _, sc := w.at(r.addr); sc == nil || sc.Status().EarlyBytes != ttfbReq {
				passive++
			}
		}
		if dialer+passive != 0 {
			t.Errorf("of %d runs, %d did not send the client's first write as early data and %d did not receive it so", runs, dialer, passive)
			checkEarlyRuns(t, w, early)
		}
		if n, _ := w.dialCount(); n != runs {
			t.Errorf("stimulus: %d carrier dials, want one per session (%d)", n, runs)
		}
		w.close()
	})
}

// TestForwardEarlyServerFirstBounded (R1-15): the target speaks first (a
// 512-byte banner, then its FIN) and the client waits for it without
// writing. Forward's hold of its first session Read ends 20 ms after the
// call, and that Read opens the session: the session's carrier is dialled
// at most 20 ms after Forward started (exactly 20 ms: the hold ran), no
// early byte travels, and the banner arrives intact.
func TestForwardEarlyServerFirstBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const banner = 512
		w := newTTFBWorld(t, ttfbOpts{app: "conn", banner: banner})
		for i := range 5 {
			addr := fmt.Sprintf("banner-%d.test:80", i)
			c, err := l4.Dial(context.Background(), w.peer, addr, rendr.DialOptions{EarlyReturn: true})
			if err != nil {
				t.Fatalf("%s: Dial: %v", addr, err)
			}
			n0, _ := w.dialCount()
			cli, srv := rendrtest.TargetPipe(0)
			started := time.Now()
			res := make(chan l4.ForwardResult, 1)
			go func() { res <- l4.Forward(context.Background(), c, srv) }()
			got, err := io.ReadAll(cli)
			if err != nil || !bytes.Equal(got, ttfbGen(11, banner)) {
				t.Fatalf("%s: banner: %d bytes (intact %v), %v", addr, len(got), bytes.Equal(got, ttfbGen(11, banner)), err)
			}
			n1, dialled := w.dialCount()
			if n1 != n0+1 {
				t.Fatalf("stimulus: %s: %d carrier dials for the session, want 1", addr, n1-n0)
			}
			if el := dialled.Sub(started); el > ttfbHold || el < ttfbHold-ttfbSlack {
				t.Errorf("%s: the session's carrier dialled %v after Forward started, want the hold's %v (at most)", addr, el, ttfbHold)
			}
			if err := cli.CloseWrite(); err != nil {
				t.Fatalf("%s: CloseWrite: %v", addr, err)
			}
			if r := <-res; !r.Clean || r.ToLocal != banner || r.ToSession != 0 {
				t.Errorf("%s: ingress Forward %+v, want a clean end with the banner only", addr, r)
			}
			cli.Close()
			_, _, sc := w.at(addr)
			if e := c.Status().EarlyBytes; e != 0 || sc == nil || sc.Status().EarlyBytes != 0 {
				t.Errorf("%s: EarlyBytes dialer %d, passive %v; want 0 (nothing was written before the opening)", addr, e, sc)
			}
		}
		w.close()
	})
}

// ttfbGen is the first n bytes of rendrtest.PRNG(seed): TargetGen's bytes.
func ttfbGen(seed uint64, n int) []byte {
	b := make([]byte, n)
	io.ReadFull(rendrtest.PRNG(seed), b)
	return b
}

// Interface checks of the tap (Forward uses CloseWrite and SetLinger of
// the target conn when offered).
var (
	_ interface{ CloseWrite() error }   = (*ttfbTap)(nil)
	_ interface{ SetLinger(int) error } = (*ttfbTap)(nil)
)
