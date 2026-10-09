package realsock

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/carrier/tcp"
	"github.com/FrankoonG/rendr/v2/carrier/udp"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The rendr mux and race rows of the real-socket group (M3 design §A11.4,
// R1-23): two Runtimes joined by the built-in carriers (carrier/tcp,
// carrier/udp) on loopback, outside synctest bubbles, on Linux and Windows
// alike, driven only through the public API. Every test registers
// rendrtest.AssertNoLeak first (its check runs after every other cleanup,
// once both Runtimes are closed) and never runs in parallel. Each takes at
// most about 10 s; under the race detector the same timeline runs at a
// lower size or rate with the same criteria (R2-37). Helpers carry the ms
// prefix: the package's other files belong to other work packages.

// msRace reports a race-detector build (the build setting "-race"; the
// package keeps no build-tagged files of its own).
var msRace = func() bool {
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

// msUntil polls cond every millisecond for at most within.
func msUntil(t testing.TB, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("not within %v: %s", within, what)
		}
		time.Sleep(time.Millisecond)
	}
}

// msDials counts one factory's session dials (probe carriers excluded) and
// remembers their conns, so that a test can find and close the carrier a
// session uses.
type msDials struct {
	n     atomic.Int64
	mu    sync.Mutex
	local []string         // stream: the local address of every session conn, in dial order
	pcs   []net.PacketConn // datagram: every session socket, in dial order
}

// wrapStream counts the session dials of c in dl. The conn rendr gets is
// the factory's own (a carrier/tcp conn keeps its vectored writes).
func (dl *msDials) wrapStream(c rendr.StreamCarrier) rendr.StreamCarrier {
	dial := c.Dial
	c.Dial = func(ctx context.Context) (net.Conn, error) {
		nc, err := dial(ctx)
		if di, ok := rendr.CarrierDialInfo(ctx); err == nil && ok && !di.Probe {
			dl.n.Add(1)
			dl.mu.Lock()
			dl.local = append(dl.local, nc.LocalAddr().String())
			dl.mu.Unlock()
		}
		return nc, err
	}
	return c
}

// wrapDgram counts the session dials of c in dl.
func (dl *msDials) wrapDgram(c rendr.DatagramCarrier) rendr.DatagramCarrier {
	dial := c.Dial
	c.Dial = func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		pc, a, err := dial(ctx)
		if di, ok := rendr.CarrierDialInfo(ctx); err == nil && ok && !di.Probe {
			dl.n.Add(1)
			dl.mu.Lock()
			dl.pcs = append(dl.pcs, pc)
			dl.mu.Unlock()
		}
		return pc, a, err
	}
	return c
}

// lastLocal returns the local address of the latest session conn.
func (dl *msDials) lastLocal() string {
	dl.mu.Lock()
	defer dl.mu.Unlock()
	if len(dl.local) == 0 {
		return ""
	}
	return dl.local[len(dl.local)-1]
}

// closeLast closes the latest session socket under rendr (an embedder-
// closed socket: transport_error at once) and reports whether there was one.
func (dl *msDials) closeLast() bool {
	dl.mu.Lock()
	defer dl.mu.Unlock()
	if len(dl.pcs) == 0 {
		return false
	}
	return dl.pcs[len(dl.pcs)-1].Close() == nil
}

// msPair is two Runtimes (dialer d, passive p), the passive's Listener and
// the dialer's Peer.
type msPair struct {
	t     testing.TB
	d, p  *rendr.Runtime
	ln    *rendr.Listener
	peer  *rendr.Peer
	downs atomic.Int64 // the dialer's CarrierDown events of session carriers
	live0 int64        // the session registry at the start (R1-24)
}

// newMsPair builds the Runtimes (ov, when non-nil, goes to both through
// testhooks), the passive's Listener on lc and the dialer's Peer on
// carriers. The Runtimes are closed by a cleanup as well, so that a failed
// test leaves nothing behind for the next one.
func newMsPair(t testing.TB, cfg rendr.Config, ov *testhooks.Overrides, lc rendr.ListenConfig, carriers []rendr.Carrier) *msPair {
	t.Helper()
	m := &msPair{t: t, live0: testhooks.LiveSessions.Load()}
	build := func(cfg rendr.Config) *rendr.Runtime {
		t.Helper()
		if ov == nil {
			rt, err := rendr.NewRuntime(cfg)
			if err != nil {
				t.Fatal(err)
			}
			return rt
		}
		o := *ov
		rt, err := testhooks.NewRuntime(cfg, &o)
		if err != nil {
			t.Fatal(err)
		}
		return rt.(*rendr.Runtime)
	}
	dcfg := cfg
	dcfg.OnEvent = func(ev rendr.Event) {
		if ev.Kind == rendr.EventCarrierDown && ev.Session != (rendr.SessionID{}) {
			m.downs.Add(1)
		}
	}
	m.d = build(dcfg)
	m.p = build(cfg)
	t.Cleanup(func() { m.d.Close(); m.p.Close() })
	var err error
	if m.ln, err = m.p.Listen(lc); err != nil {
		t.Fatal(err)
	}
	if m.peer, err = m.d.NewPeer(rendr.PeerConfig{Carriers: carriers}); err != nil {
		t.Fatal(err)
	}
	return m
}

// open dials one stream session of mode and confirms it on the passive.
// Sessions are opened one at a time.
func (m *msPair) open(mode rendr.Mode) (dc, pc *rendr.Conn) {
	m.t.Helper()
	type dialed struct {
		c   *rendr.Conn
		err error
	}
	ch := make(chan dialed, 1)
	go func() {
		c, err := m.peer.Dial(context.Background(), rendr.DialOptions{Mode: mode})
		ch <- dialed{c, err}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pend, err := m.ln.Accept(ctx)
	if err == nil {
		pc, err = pend.Confirm()
	}
	if err != nil {
		m.t.Fatalf("Accept: %v", err)
	}
	r := <-ch
	if r.err != nil {
		m.t.Fatalf("Dial: %v", r.err)
	}
	return r.c, pc
}

// openPacket dials one packet session of mode and confirms it.
func (m *msPair) openPacket(mode rendr.Mode) (dc, pc *rendr.PacketConn) {
	m.t.Helper()
	type dialed struct {
		c   *rendr.PacketConn
		err error
	}
	ch := make(chan dialed, 1)
	go func() {
		c, err := m.peer.DialPacket(context.Background(), rendr.DialOptions{Mode: mode})
		ch <- dialed{c, err}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pend, err := m.ln.AcceptPacket(ctx)
	if err == nil {
		pc, err = pend.Confirm()
	}
	if err != nil {
		m.t.Fatalf("AcceptPacket: %v", err)
	}
	r := <-ch
	if r.err != nil {
		m.t.Fatalf("DialPacket: %v", r.err)
	}
	return r.c, pc
}

// muxZero waits until both Runtimes hold no shared carrier: the trunks
// close at their last view (M3-D20).
func (m *msPair) muxZero() {
	m.t.Helper()
	msUntil(m.t, 10*time.Second, "the MUX trunks closed at their last view", func() bool {
		return m.d.Status().Mux.Carriers == 0 && m.p.Status().Mux.Carriers == 0 &&
			m.d.Status().Mux.Views == 0 && m.p.Status().Mux.Views == 0
	})
}

// close closes both Runtimes and requires that nothing is left: no
// session, handshake, flow, actor, buffered byte or shared carrier, and the
// session registry back at its start.
func (m *msPair) close() {
	m.t.Helper()
	m.peer.Close()
	m.d.Close()
	m.p.Close()
	for _, rt := range []*rendr.Runtime{m.d, m.p} {
		st := rt.Status()
		sc := st.Sessions
		if sc.Open+sc.Pending+sc.Lingering+sc.Orphaned != 0 || st.Handshakes != 0 || st.Sessionless != 0 || st.Actors != 0 ||
			st.BufferedBytes != 0 || st.Abandoned != 0 || st.Datagram.Flows != 0 || st.Datagram.Sources != 0 ||
			st.Mux.Carriers != 0 || st.Mux.Views != 0 {
			m.t.Errorf("state left after Runtime.Close: %+v", st)
		}
	}
	msUntil(m.t, 10*time.Second, "the session registry back at its start", func() bool {
		return testhooks.LiveSessions.Load() == m.live0
	})
}

// msEnd closes both ends of a stream session and requires a clean end.
func msEnd(t testing.TB, dc, pc *rendr.Conn) {
	t.Helper()
	dc.Close()
	pc.Close()
	for _, c := range []*rendr.Conn{dc, pc} {
		select {
		case <-c.Done():
		case <-time.After(30 * time.Second):
			t.Fatalf("session %v (%v) not done 30 s after Close", c.ID(), c.Status().Role)
		}
		if st := c.Status(); st.Err != io.EOF {
			t.Errorf("session %v (%v) ended with %v, want io.EOF", c.ID(), st.Role, st.Err)
		}
	}
}

// msStream is one stream session's two flows, dialer → passive (up) and
// back, each paced and digested with SHA-256 on both ends.
type msStream struct {
	up, back int64
	got      atomic.Int64 // up bytes the passive read
	sums     [4][32]byte  // up sent, up read, back sent, back read
	errs     [4]error
	wg       sync.WaitGroup
}

// msStart starts both flows of a session: up bytes of PRNG(seed) from the
// dialer and back bytes of PRNG(seed+1) from the passive, each written in
// equal chunks every 100 ms over d and then half-closed; each reader
// verifies its bytes up to io.EOF.
func msStart(dc, pc *rendr.Conn, up, back int64, seed uint64, d time.Duration) *msStream {
	s := &msStream{up: up, back: back}
	s.wg.Add(4)
	go func() { defer s.wg.Done(); s.sums[0], s.errs[0] = msPace(dc, up, seed, d) }()
	go func() { defer s.wg.Done(); s.sums[1], s.errs[1] = msRead(pc, up, seed, &s.got) }()
	go func() { defer s.wg.Done(); s.sums[2], s.errs[2] = msPace(pc, back, seed+1, d) }()
	go func() { defer s.wg.Done(); s.sums[3], s.errs[3] = msRead(dc, back, seed+1, nil) }()
	return s
}

// wait waits (at most within) for both flows and checks them: no error,
// matching digests both ways.
func (s *msStream) wait(t testing.TB, name string, within time.Duration) {
	t.Helper()
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(within):
		t.Fatalf("%s: flows not done within %v (%d of %d up bytes read)", name, within, s.got.Load(), s.up)
	}
	for i, what := range []string{"up write", "up read", "back write", "back read"} {
		if s.errs[i] != nil {
			t.Errorf("%s %s: %v", name, what, s.errs[i])
		}
	}
	if s.sums[0] != s.sums[1] || s.sums[2] != s.sums[3] {
		t.Errorf("%s: SHA-256 up %x / %x, back %x / %x", name, s.sums[0][:8], s.sums[1][:8], s.sums[2][:8], s.sums[3][:8])
	}
}

// msPace writes n bytes of PRNG(seed) on c in equal chunks every 100 ms
// over d (an absolute schedule; the last chunk takes the rest), then
// half-closes c. It returns the digest of what it wrote.
func msPace(c *rendr.Conn, n int64, seed uint64, d time.Duration) (sum [32]byte, err error) {
	h := sha256.New()
	ticks := max(int64(d/(100*time.Millisecond)), 1)
	chunk := n / ticks
	src := io.TeeReader(io.LimitReader(rendrtest.PRNG(seed), n), h)
	start := time.Now()
	for k, sent := int64(1), int64(0); sent < n; k++ {
		m := chunk
		if k >= ticks {
			m = n - sent
		}
		w, err := io.CopyN(struct{ io.Writer }{c}, src, m)
		sent += w
		if err != nil {
			return sum, err
		}
		time.Sleep(time.Until(start.Add(time.Duration(k) * 100 * time.Millisecond)))
	}
	h.Sum(sum[:0])
	return sum, c.CloseWrite()
}

// msRead reads c to io.EOF, verifying n bytes of PRNG(seed), and returns
// the digest of what it read; got, when non-nil, counts the bytes read.
func msRead(c *rendr.Conn, n int64, seed uint64, got *atomic.Int64) (sum [32]byte, err error) {
	h := sha256.New()
	v := rendrtest.NewVerifier(seed, n)
	buf := make([]byte, 64<<10)
	for {
		k, rerr := c.Read(buf)
		if k > 0 {
			h.Write(buf[:k])
			if got != nil {
				got.Add(int64(k))
			}
			if _, werr := v.Write(buf[:k]); werr != nil {
				return sum, v.Done(rerr)
			}
		}
		if rerr != nil {
			h.Sum(sum[:0])
			return sum, v.Done(rerr)
		}
	}
}

// msRelay forwards TCP connections byte for byte from its listener to
// target and can reset one of them (SO_LINGER 0 and Close on both sockets:
// both rendr ends get a TCP RST), found by the dialer socket's address.
type msRelay struct {
	ln     net.Listener
	target string
	mu     sync.Mutex
	pairs  map[string]*msRelayPair // by the dialer socket's address
	wg     sync.WaitGroup
	resets atomic.Int64
}

type msRelayPair struct{ a, b *net.TCPConn } // dialer side, passive side

func newMsRelay(t testing.TB, target string) *msRelay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &msRelay{ln: ln, target: target, pairs: map[string]*msRelayPair{}}
	r.wg.Go(r.accept)
	return r
}

func (r *msRelay) addr() string { return r.ln.Addr().String() }

func (r *msRelay) accept() {
	for {
		c, err := r.ln.Accept()
		if err != nil {
			return
		}
		up, err := net.Dial("tcp", r.target)
		if err != nil {
			c.Close()
			continue
		}
		p := &msRelayPair{a: c.(*net.TCPConn), b: up.(*net.TCPConn)}
		key := c.RemoteAddr().String()
		r.mu.Lock()
		r.pairs[key] = p
		r.mu.Unlock()
		r.wg.Go(func() { r.serve(key, p) })
	}
}

// serve pumps both directions: an EOF is passed on as a half-close, an
// error (a reset) closes both sockets.
func (r *msRelay) serve(key string, p *msRelayPair) {
	var wg sync.WaitGroup
	pump := func(dst, src *net.TCPConn) {
		if _, err := io.Copy(dst, src); err != nil {
			dst.Close()
			src.Close()
			return
		}
		dst.CloseWrite()
	}
	wg.Go(func() { pump(p.b, p.a) })
	wg.Go(func() { pump(p.a, p.b) })
	wg.Wait()
	p.a.Close()
	p.b.Close()
	r.mu.Lock()
	if r.pairs[key] == p {
		delete(r.pairs, key)
	}
	r.mu.Unlock()
}

// reset resets the relayed connection of the dialer socket at addr and
// reports whether it was live.
func (r *msRelay) reset(addr string) bool {
	r.mu.Lock()
	p := r.pairs[addr]
	delete(r.pairs, addr)
	r.mu.Unlock()
	if p == nil {
		return false
	}
	for _, c := range []*net.TCPConn{p.a, p.b} {
		c.SetLinger(0)
		c.Close()
	}
	r.resets.Add(1)
	return true
}

// close stops accepting, resets what is left and joins every goroutine.
func (r *msRelay) close() {
	r.ln.Close()
	r.mu.Lock()
	keys := make([]string, 0, len(r.pairs))
	for k := range r.pairs {
		keys = append(keys, k)
	}
	r.mu.Unlock()
	for _, k := range keys {
		r.reset(k)
	}
	r.wg.Wait()
}

// msTCPListen opens a carrier/tcp listening socket on loopback.
func msTCPListen(t testing.TB) net.Listener {
	t.Helper()
	l, err := tcp.Listen("tcp", "127.0.0.1:0", tcp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// msUDPListen opens a carrier/udp listening socket on loopback.
func msUDPListen(t testing.TB) net.PacketConn {
	t.Helper()
	pc, err := udp.Listen("udp4", "127.0.0.1:0", udp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return pc
}

// msSide is one direction of a packet session: its generator and its
// verifying reader.
type msSide struct {
	v        *rendrtest.PacketVerifier
	accepted atomic.Uint64 // WriteTo returned (n, nil)
	read     atomic.Uint64 // ReadFrom returned a datagram
	readErr  error         // the error that ended the reader
	verr     atomic.Value  // the first generator or verifier error
}

// msSize is the size of test datagram seq: 24 … 1000 bytes.
func msSize(seq uint64) int { return rendrtest.PacketHeaderLen + int(seq*37%977) }

// generate writes rate datagrams per second (a burst every millisecond)
// until stop closes: datagram seq is due at start + seq/rate.
func (s *msSide) generate(c *rendr.PacketConn, seed uint64, rate int, start time.Time, stop <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	buf := make([]byte, 1024)
	tk := time.NewTicker(time.Millisecond)
	defer tk.Stop()
	var seq uint64
	for {
		select {
		case <-stop:
			return
		case now := <-tk.C:
			for due := uint64(now.Sub(start).Seconds() * float64(rate)); seq < due; seq++ {
				if _, err := c.WriteTo(rendrtest.PacketPayload(buf, seed, seq, msSize(seq), now), nil); err != nil {
					s.verr.CompareAndSwap(nil, err)
					return
				}
				s.accepted.Add(1)
			}
		}
	}
}

// receive reads and verifies datagrams until ReadFrom fails.
func (s *msSide) receive(c *rendr.PacketConn, wg *sync.WaitGroup) {
	defer wg.Done()
	buf := make([]byte, 2048)
	for {
		n, _, err := c.ReadFrom(buf)
		if err != nil {
			s.readErr = err
			return
		}
		s.read.Add(1)
		if err := s.v.Add(buf[:n], time.Now()); err != nil {
			s.verr.CompareAndSwap(nil, err)
		}
	}
}

// msLossWindows are the loss windows of a real-time packet run: a lost
// datagram must have been sent within [k − pre, k + post] of a kill at k
// (the M2 real-UDP smoke's windows, F8). Under -race the receiving reader
// can lag 100 ms and more in real time, so both windows widen.
func msLossWindows() (pre, post time.Duration) {
	if msRace {
		return 250 * time.Millisecond, 500 * time.Millisecond
	}
	return 50 * time.Millisecond, 200 * time.Millisecond
}

// msJudge checks one direction of a packet session after both ends ended:
// no generator or verifier error, the reader ended with eof, no corrupt,
// resized or application-visible duplicate datagram, at least 90 % of
// rate × run received, no datagram lost outside the windows of the kills
// (each judged by its own send time, seq / rate), the send side's
// counters adding up to what WriteTo accepted and the receive side's to
// what the reader read (§A7.2). Race (M3-D32, M3-D35): at most 1 % lost in
// all, the sender placed extra copies and the receiver counted the other
// member's copies as Duplicates (≥ 0.9 × Received, G3-race).
func msJudge(t testing.TB, name string, s *msSide, rate int, run time.Duration, eof error, tx, rx rendr.SessionStatus, kills []time.Duration) {
	t.Helper()
	if e := s.verr.Load(); e != nil {
		t.Errorf("%s: %v", name, e)
	}
	if !errors.Is(s.readErr, eof) {
		t.Errorf("%s: the reader ended with %v, want %v", name, s.readErr, eof)
	}
	res := s.v.Result()
	if res.Corrupt != 0 || res.BadSize != 0 || res.Duplicates != 0 {
		t.Errorf("%s: corrupt %d, resized %d, duplicates %d", name, res.Corrupt, res.BadSize, res.Duplicates)
	}
	sent := s.accepted.Load()
	if want := uint64(run.Seconds()*float64(rate)) * 9 / 10; res.Unique < want {
		t.Errorf("load: %s received %d unique datagrams, want ≥ %d", name, res.Unique, want)
	}
	pre, post := msLossWindows()
	var away, near uint64
	for _, m := range res.Missing {
		for seq := m.From; seq <= m.To; seq++ {
			at := time.Duration(float64(seq) / float64(rate) * float64(time.Second))
			in := false
			for _, k := range kills {
				in = in || (at >= k-pre && at <= k+post)
			}
			if in {
				near++
			} else {
				away++
			}
		}
	}
	// Datagrams above the highest one received were sent at the end.
	tail := sent - min(sent, res.Highest+1)
	if away != 0 || tail != 0 {
		t.Errorf("%s: %d datagrams lost outside the kill windows %v (and %d at the end); missing %v", name, away, kills, tail, res.Missing)
	}
	tp, rp := tx.Packet, rx.Packet
	if tp == nil || rp == nil {
		t.Fatalf("%s: no PacketCounters", name)
	}
	if sum := tp.Sent + tp.DropQueue + tp.DropAge + tp.DropNoPath + tp.DropTooLarge; sum != sent {
		t.Errorf("%s: accepted %d ≠ Sent %d + DropQueue %d + DropAge %d + DropNoPath %d + DropTooLarge %d", name, sent, tp.Sent, tp.DropQueue, tp.DropAge, tp.DropNoPath, tp.DropTooLarge)
	}
	if got := s.read.Load() + rp.DropRecvQueue; rp.Received != got {
		t.Errorf("%s: Received %d ≠ read %d + DropRecvQueue %d", name, rp.Received, s.read.Load(), rp.DropRecvQueue)
	}
	race := tx.Mode == rendr.ModeRace
	if rp.Received > tp.Sent || (rp.Duplicates != 0 && !race) {
		t.Errorf("%s: Received %d of Sent %d, Duplicates %d", name, rp.Received, tp.Sent, rp.Duplicates)
	}
	lost := sent - res.Unique
	if race {
		if lost*100 > sent {
			t.Errorf("%s: race lost %d of %d datagrams, want ≤ 1 %%", name, lost, sent)
		}
		if tx.Race.Copies == 0 || rp.Duplicates*10 < rp.Received*9 {
			t.Errorf("%s: race copies %d, receiver Duplicates %d of Received %d; want copies and Duplicates ≥ 0.9 × Received", name, tx.Race.Copies, rp.Duplicates, rp.Received)
		}
	}
	t.Logf("%s: accepted %d, unique %d, lost %d (%d in the kill windows), max gap %v; tx %+v race %+v; rx %+v",
		name, sent, res.Unique, lost, near, res.MaxGap, *tp, tx.Race, *rp)
}

// msPackets runs the packet sessions of a test: rate datagrams per second
// dialer → passive and back per second back, for run, calling kill once at
// killAt; then it drains both directions, closes the dialer ends (the
// passive readers end at io.EOF, the dialer readers at net.ErrClosed),
// closes the passive ends and judges every direction. kill returns
// whether it ended a live carrier.
func msPackets(t testing.TB, dcs, pcs []*rendr.PacketConn, rate, back int, run, killAt time.Duration, kill func() bool) {
	t.Helper()
	n := len(dcs)
	ups, downs := make([]*msSide, n), make([]*msSide, n)
	var gens, readers sync.WaitGroup
	stop := make(chan struct{})
	start := time.Now()
	for i := range n {
		ups[i] = &msSide{v: rendrtest.NewPacketVerifier(uint64(100 + i))}
		downs[i] = &msSide{v: rendrtest.NewPacketVerifier(uint64(200 + i))}
		gens.Add(2)
		readers.Add(2)
		go ups[i].generate(dcs[i], uint64(100+i), rate, start, stop, &gens)
		go downs[i].generate(pcs[i], uint64(200+i), back, start, stop, &gens)
		go ups[i].receive(pcs[i], &readers)
		go downs[i].receive(dcs[i], &readers)
	}
	time.Sleep(time.Until(start.Add(killAt)))
	var kills []time.Duration
	if at := time.Since(start); kill() {
		kills = append(kills, at)
	}
	time.Sleep(time.Until(start.Add(run)))
	close(stop)
	gens.Wait()
	// Drain: every datagram sent was received or lost, both ways.
	drain := time.Second
	if msRace {
		drain = 2 * time.Second
	}
	time.Sleep(drain)
	for i := range n {
		if a, b := dcs[i].Status(), pcs[i].Status(); a.Err != nil || b.Err != nil {
			t.Errorf("packet session %d failed before its Close: dialer %v, passive %v", i, a.Err, b.Err)
		}
		dcs[i].Close()
	}
	for i := range n {
		msDone(t, dcs[i].Done(), "a packet dialer session")
	}
	readers.Wait()
	for i := range n {
		pcs[i].Close()
		msDone(t, pcs[i].Done(), "a packet passive session")
	}
	if len(kills) != 1 {
		t.Fatalf("stimulus: the kill at %v ended no live carrier", killAt)
	}
	for i := range n {
		ds, ps := dcs[i].Status(), pcs[i].Status()
		msJudge(t, fmt.Sprintf("P%d (%v) dialer → passive", i, ds.Mode), ups[i], rate, run, io.EOF, ds, ps, kills)
		msJudge(t, fmt.Sprintf("P%d (%v) passive → dialer", i, ds.Mode), downs[i], back, run, net.ErrClosed, ps, ds, kills)
	}
}

// msDone waits for ch at most 30 s.
func msDone(t testing.TB, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(30 * time.Second):
		t.Fatalf("%s did not end within 30 s of its Close", what)
	}
}

// msDeadRow returns the row of carrier id in st if it is dead.
func msDeadRow(st rendr.SessionStatus, id rendr.CarrierID) (rendr.CarrierStatus, bool) {
	for _, c := range st.Carriers {
		if c.ID == id && c.State == rendr.CarrierDead {
			return c, true
		}
	}
	return rendr.CarrierStatus{}, false
}

// msLive counts the live carriers of st.
func msLive(st rendr.SessionStatus) int {
	n := 0
	for _, c := range st.Carriers {
		if c.State != rendr.CarrierDead {
			n++
		}
	}
	return n
}

// TestMuxTCPE2E (§A11.4, M3-D2, M3-D18; L10, L52): rendr mux over
// carrier/tcp with default Props. One Peer with two factories a and b, each
// connecting through its own relay to the passive's carrier/tcp listener,
// carries 8 selector sessions; they share one MUX trunk (one session dial
// in all). While each session moves 8 MiB up and 2 MiB back (2 MiB and
// 512 KiB under -race; the same 3-s pacing), the trunk is killed 1 s in:
// the relay resets both of its sockets (SO_LINGER 0, a TCP RST on both
// rendr ends). Stimulus: every session was mid-transfer at the kill, and on
// both ends every session lists the trunk dead of transport_error. The
// pool coalesces the 8 sessions' redials: at most 1 new session dial per
// factory, and at least one in all. Integrity: every session's bytes
// arrive in both directions with matching SHA-256 sums and PRNG content,
// and TxBytes, AckedBytes and DeliveredBytes are exact. While the
// transfers go on, the 8 sessions share one new trunk on both Runtimes.
// The trunks close at the last view, and Runtime.Close leaves nothing.
func TestMuxTCPE2E(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	const (
		n      = 8
		run    = 3 * time.Second
		killAt = time.Second
	)
	up, back := int64(8<<20), int64(2<<20)
	if msRace {
		up, back = 2<<20, 512<<10 // the same timeline (R2-37)
	}
	l := msTCPListen(t)
	var relays []*msRelay
	var dials []*msDials
	var carriers []rendr.Carrier
	for _, name := range []string{"a", "b"} {
		r := newMsRelay(t, l.Addr().String())
		t.Cleanup(r.close)
		dl := &msDials{}
		relays, dials = append(relays, r), append(dials, dl)
		carriers = append(carriers, dl.wrapStream(tcp.Carrier(name, "tcp", r.addr(), tcp.Options{})))
	}
	m := newMsPair(t, rendr.Config{}, nil, rendr.ListenConfig{Sources: []rendr.Source{rendr.FromListener(l)}}, carriers)
	dcs, pcs := make([]*rendr.Conn, n), make([]*rendr.Conn, n)
	for i := range n {
		dcs[i], pcs[i] = m.open(rendr.ModeSelector)
	}
	msUntil(t, 5*time.Second, "8 views on one trunk on both Runtimes", func() bool {
		dm, pm := m.d.Status().Mux, m.p.Status().Mux
		return dm.Carriers == 1 && dm.Views == n && pm.Carriers == 1 && pm.Views == n
	})
	victim := -1
	for i, dl := range dials {
		if dl.n.Load() == 1 {
			victim = i
		}
	}
	if total := dials[0].n.Load() + dials[1].n.Load(); total != 1 || victim < 0 {
		t.Fatalf("%d session dials for %d sessions, want 1 shared trunk", total, n)
	}
	var trunk rendr.CarrierID
	for _, c := range dcs[0].Status().Carriers {
		if c.State == rendr.CarrierActive {
			trunk = c.ID
		}
	}
	for i := range n {
		cs := dcs[i].Status().Carriers
		if len(cs) != 1 || cs[0].ID != trunk || cs[0].Shared != n {
			t.Fatalf("session %d carriers %+v, want one view of trunk %v shared by %d", i, cs, trunk, n)
		}
	}

	start := time.Now()
	streams := make([]*msStream, n)
	for i := range n {
		streams[i] = msStart(dcs[i], pcs[i], up, back, uint64(10+2*i), run)
	}
	time.Sleep(time.Until(start.Add(killAt)))
	before := [2]int64{dials[0].n.Load(), dials[1].n.Load()}
	gotAtKill := make([]int64, n)
	for i := range n {
		gotAtKill[i] = streams[i].got.Load()
	}
	if !relays[victim].reset(dials[victim].lastLocal()) {
		t.Fatal("stimulus: the trunk's relayed connection was not live at the kill")
	}
	// The 8 sessions share one new trunk while their transfers go on.
	newTrunk := func() bool {
		var id rendr.CarrierID
		for i := range n {
			var live []rendr.CarrierStatus
			for _, c := range dcs[i].Status().Carriers {
				if c.State != rendr.CarrierDead {
					live = append(live, c)
				}
			}
			if len(live) != 1 || live[0].ID == trunk || (id != 0 && live[0].ID != id) || live[0].Shared != n {
				return false
			}
			id = live[0].ID
		}
		dm, pm := m.d.Status().Mux, m.p.Status().Mux
		return dm.Carriers == 1 && dm.Views == n && pm.Carriers == 1 && pm.Views == n
	}
	for deadline := time.Now().Add(run - killAt - 500*time.Millisecond); !newTrunk(); time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the sessions did not share one new trunk after the kill: dialer Mux %+v, passive Mux %+v", m.d.Status().Mux, m.p.Status().Mux)
		}
	}
	rejoined := time.Since(start) - killAt
	for i := range n {
		streams[i].wait(t, fmt.Sprintf("session %d", i), 20*time.Second)
	}
	took := time.Since(start)
	if t.Failed() {
		t.FailNow()
	}

	// Stimulus: mid-transfer, and the trunk died on both ends of every
	// session.
	for i := range n {
		if gotAtKill[i] == 0 || gotAtKill[i] >= up {
			t.Errorf("stimulus: session %d had read %d of %d bytes at the kill, want mid-transfer", i, gotAtKill[i], up)
		}
		for _, st := range []rendr.SessionStatus{dcs[i].Status(), pcs[i].Status()} {
			if row, ok := msDeadRow(st, trunk); !ok || row.DeathCause != rendr.CauseTransportError {
				t.Errorf("stimulus: session %d (%v) trunk %v row %+v (dead %v), want dead of transport_error", i, st.Role, trunk, row, ok)
			}
		}
	}
	if got := m.downs.Load(); got < n {
		t.Errorf("stimulus: %d CarrierDown events of session carriers for %d views on the killed trunk", got, n)
	}
	// Coalescing (M3-D18): at most one new dial per factory.
	newDials := int64(0)
	for i, dl := range dials {
		d := dl.n.Load() - before[i]
		newDials += d
		if d > 1 {
			t.Errorf("factory %d: %d new session dials after the kill, want ≤ 1", i, d)
		}
	}
	if newDials == 0 {
		t.Errorf("no new session dial after the trunk's death")
	}
	// Counters (the last ACKs may still be on their way) and the views.
	msUntil(t, 10*time.Second, "the last ACKs", func() bool {
		for i := range n {
			if dcs[i].Status().AckedBytes != uint64(up) || pcs[i].Status().AckedBytes != uint64(back) {
				return false
			}
		}
		return true
	})
	for i := range n {
		ds, ps := dcs[i].Status(), pcs[i].Status()
		if ds.TxBytes != uint64(up) || ps.DeliveredBytes != uint64(up) || ps.TxBytes != uint64(back) || ds.DeliveredBytes != uint64(back) {
			t.Errorf("session %d: up TxBytes %d DeliveredBytes %d, back TxBytes %d DeliveredBytes %d; want %d and %d", i, ds.TxBytes, ps.DeliveredBytes, ps.TxBytes, ds.DeliveredBytes, up, back)
		}
	}
	t.Logf("%v: one shared trunk again %v after the kill; session dials a %d, b %d (victim %d); dialer CarrierDown %d; dialer Mux %+v",
		took.Round(time.Millisecond), rejoined.Round(time.Millisecond), dials[0].n.Load(), dials[1].n.Load(), victim, m.downs.Load(), m.d.Status().Mux)

	var ends sync.WaitGroup
	for i := range n {
		ends.Go(func() { msEnd(t, dcs[i], pcs[i]) })
	}
	ends.Wait()
	m.muxZero()
	m.close()
	for _, r := range relays {
		r.close()
	}
}

// TestMuxUDPE2E (§A11.4, M3-D2; L39, L40): rendr mux over carrier/udp
// with default Props. Four selector packet sessions share one datagram
// MUX trunk (one session dial); each sends 2,000 datagrams per second up
// and 500 back (1,000 and 250 under -race) for 10 s, and the trunk's
// dialer socket is closed under rendr at 5 s (an embedder-closed socket:
// transport_error at once). Stimulus: the trunk died for every session
// (≥ 4 CarrierDown events) and the pool coalesced the four rejoins into
// one new dial. Integrity per session and direction (msJudge): every
// datagram verified, losses only in the kill's window, the counters
// adding up. The trunk closes at its last view; Runtime.Close leaves
// nothing.
func TestMuxUDPE2E(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	const (
		n      = 4
		run    = 10 * time.Second
		killAt = 5 * time.Second
	)
	rate, back := 2000, 500
	if msRace {
		rate, back = 1000, 250 // the same timeline (R2-37)
	}
	sock := msUDPListen(t)
	dl := &msDials{}
	m := newMsPair(t, rendr.Config{}, nil, rendr.ListenConfig{Sources: []rendr.Source{rendr.FromPacketConn(sock)}},
		[]rendr.Carrier{dl.wrapDgram(udp.Carrier("u", "udp4", sock.LocalAddr().String(), udp.Options{}))})
	dcs, pcs := make([]*rendr.PacketConn, n), make([]*rendr.PacketConn, n)
	for i := range n {
		dcs[i], pcs[i] = m.openPacket(rendr.ModeSelector)
	}
	msUntil(t, 5*time.Second, "4 views on one datagram trunk on both Runtimes", func() bool {
		dm, pm := m.d.Status().Mux, m.p.Status().Mux
		return dm.Carriers == 1 && dm.Views == n && pm.Carriers == 1 && pm.Views == n
	})
	if got := dl.n.Load(); got != 1 {
		t.Fatalf("%d session dials for %d packet sessions, want 1 shared trunk", got, n)
	}
	trunk := dcs[0].Status().Carriers[0].ID
	for i := range n {
		if cs := dcs[i].Status().Carriers; len(cs) != 1 || cs[0].ID != trunk || cs[0].Shared != n || cs[0].Kind != rendr.KindDatagram {
			t.Fatalf("packet session %d carriers %+v, want one view of datagram trunk %v shared by %d", i, cs, trunk, n)
		}
	}

	msPackets(t, dcs, pcs, rate, back, run, killAt, dl.closeLast)

	for i := range n {
		if row, ok := msDeadRow(dcs[i].Status(), trunk); !ok || row.DeathCause != rendr.CauseTransportError {
			t.Errorf("stimulus: packet session %d trunk %v row %+v (dead %v), want dead of transport_error", i, trunk, row, ok)
		}
	}
	if got := m.downs.Load(); got < n {
		t.Errorf("stimulus: %d CarrierDown events of session carriers for %d views on the closed trunk", got, n)
	}
	if got := dl.n.Load(); got != 2 {
		t.Errorf("%d session dials (one before the close), want 2: the pool coalesces the rejoins into one dial", got)
	}
	t.Logf("dialer CarrierDown %d; dialer Mux %+v", m.downs.Load(), m.d.Status().Mux)
	m.muxZero()
	m.close()
}

// TestRaceUDPE2E (§A11.4, M3-D32; L39): a race packet session over two
// carrier/udp factories (default Props: a MUX trunk of one view each)
// sends 2,000 datagrams per second up and 500 back (1,000 and 250 under
// -race) for 10 s; at 5 s one member's dialer socket is closed under rendr.
// Every member carries every datagram, so no datagram is lost outside the
// close's window and at most 1 % in all; the sender placed copies
// (Race.Copies) and the receiver discarded the other member's copies as
// Duplicates (≥ 0.9 × Received). The member rejoins on its own factory.
func TestRaceUDPE2E(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	const (
		run    = 10 * time.Second
		killAt = 5 * time.Second
	)
	rate, back := 2000, 500
	if msRace {
		rate, back = 1000, 250 // the same timeline (R2-37)
	}
	sock := msUDPListen(t)
	dials := []*msDials{{}, {}}
	var carriers []rendr.Carrier
	for i, name := range []string{"u0", "u1"} {
		carriers = append(carriers, dials[i].wrapDgram(udp.Carrier(name, "udp4", sock.LocalAddr().String(), udp.Options{})))
	}
	m := newMsPair(t, rendr.Config{}, nil, rendr.ListenConfig{Sources: []rendr.Source{rendr.FromPacketConn(sock)}}, carriers)
	dc, pc := m.openPacket(rendr.ModeRace)
	msUntil(t, 5*time.Second, "both race members live", func() bool { return msLive(dc.Status()) == 2 && msLive(pc.Status()) == 2 })
	var victim rendr.CarrierID
	for _, c := range dc.Status().Carriers {
		if c.Name == "u0" && c.State != rendr.CarrierDead {
			victim = c.ID
		}
	}

	msPackets(t, []*rendr.PacketConn{dc}, []*rendr.PacketConn{pc}, rate, back, run, killAt, dials[0].closeLast)

	if row, ok := msDeadRow(dc.Status(), victim); !ok || row.DeathCause != rendr.CauseTransportError {
		t.Errorf("stimulus: member %v row %+v (dead %v), want dead of transport_error", victim, row, ok)
	}
	if got := dials[0].n.Load(); got != 2 {
		t.Errorf("factory u0: %d session dials, want 2 (the member rejoined on its own factory once)", got)
	}
	t.Logf("session dials u0 %d, u1 %d; dialer CarrierDown %d", dials[0].n.Load(), dials[1].n.Load(), m.downs.Load())
	m.muxZero()
	m.close()
}

// TestIdleSessionsRealSockets_L52 (§A11.4, M3-D42; L52): 200 selector
// sessions over real carrier/tcp (default Props: shared trunks) each
// exchange one byte each way and then stay idle. 2 s later — twice the
// default ActorLinger — Status.Actors is 0 on both Runtimes and the
// session registry counts 400 live and 400 parked sessions: an idle
// session holds no goroutine of its own. Parked sessions still carry data
// (a second byte each way arrives on every session); closing them all
// closes the trunks, and Runtime.Close leaves nothing.
func TestIdleSessionsRealSockets_L52(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	const n = 200
	parked0 := testhooks.ParkedSessions.Load()
	l := msTCPListen(t)
	cfg := rendr.Config{Handshake: rendr.HandshakeLimits{MaxConcurrent: 2 * n}}
	m := newMsPair(t, cfg, nil, rendr.ListenConfig{Sources: []rendr.Source{rendr.FromListener(l)}, AcceptBacklog: 2 * n},
		[]rendr.Carrier{tcp.Carrier("direct", "tcp", l.Addr().String(), tcp.Options{})})

	// The passive confirms every session and files it by its metadata.
	passive := make([]*rendr.Conn, n)
	var accepted sync.WaitGroup
	accepted.Go(func() {
		for range n {
			pend, err := m.ln.Accept(context.Background())
			if err != nil {
				t.Errorf("Accept: %v", err)
				return
			}
			c, err := pend.Confirm()
			if err != nil {
				t.Errorf("Confirm: %v", err)
				return
			}
			i, err := strconv.Atoi(string(pend.Metadata()))
			if err != nil || i < 0 || i >= n || passive[i] != nil {
				t.Errorf("metadata %q", pend.Metadata())
				return
			}
			passive[i] = c
		}
	})
	dialer := make([]*rendr.Conn, n)
	var dials sync.WaitGroup
	for i := range n {
		dials.Go(func() {
			c, err := m.peer.Dial(context.Background(), rendr.DialOptions{Metadata: []byte(strconv.Itoa(i))})
			if err != nil {
				t.Errorf("Dial %d: %v", i, err)
				return
			}
			dialer[i] = c
		})
	}
	dials.Wait()
	accepted.Wait()
	if t.Failed() {
		t.FailNow()
	}
	exchange := func(round byte) {
		t.Helper()
		var wg sync.WaitGroup
		for i := range n {
			wg.Go(func() {
				for _, pair := range [][2]*rendr.Conn{{dialer[i], passive[i]}, {passive[i], dialer[i]}} {
					if _, err := pair[0].Write([]byte{round}); err != nil {
						t.Errorf("session %d: Write: %v", i, err)
						return
					}
					var b [1]byte
					if _, err := io.ReadFull(pair[1], b[:]); err != nil || b[0] != round {
						t.Errorf("session %d: Read %d, %v; want %d", i, b[0], err, round)
						return
					}
				}
			})
		}
		wg.Wait()
		if t.Failed() {
			t.FailNow()
		}
	}
	exchange(1)

	time.Sleep(2 * time.Second) // twice the default ActorLinger (1 s)
	da, pa := m.d.Status().Actors, m.p.Status().Actors
	live, parked := testhooks.LiveSessions.Load()-m.live0, testhooks.ParkedSessions.Load()-parked0
	t.Logf("%d idle sessions: Actors %d and %d; registry %d live, %d parked; dialer Mux %+v", n, da, pa, live, parked, m.d.Status().Mux)
	if da != 0 || pa != 0 {
		t.Fatalf("Status.Actors %d (dialer) and %d (passive) 2 s after the last exchange, want 0", da, pa)
	}
	if live != 2*n || parked != 2*n {
		t.Fatalf("registry: %d live and %d parked sessions, want %d each", live, parked, 2*n)
	}

	exchange(2) // parked sessions still carry data

	var ends sync.WaitGroup
	for i := range n {
		ends.Go(func() { msEnd(t, dialer[i], passive[i]) })
	}
	ends.Wait()
	m.muxZero()
	m.close()
}

// msCPU returns the CPU time the process's Go code has used so far, as
// the runtime estimates it (runtime/metrics: total minus idle CPU
// seconds; a portable figure for the perf lane, comparable only with
// itself). The runtime updates the estimate at each garbage collection,
// so msCPU runs one first: call it outside the benchmark's clock.
func msCPU() float64 {
	runtime.GC()
	s := []metrics.Sample{{Name: "/cpu/classes/total:cpu-seconds"}, {Name: "/cpu/classes/idle:cpu-seconds"}}
	metrics.Read(s)
	if s[0].Value.Kind() != metrics.KindFloat64 || s[1].Value.Kind() != metrics.KindFloat64 {
		return 0
	}
	return s[0].Value.Float64() - s[1].Value.Float64()
}

// msBulk moves count chunks of size bytes on every session dialer →
// passive, each session with its own writer and reader, and returns when
// every byte was read.
func msBulk(tb testing.TB, dcs, pcs []*rendr.Conn, count, size int) {
	var wg sync.WaitGroup
	for i := range dcs {
		wg.Go(func() {
			buf := make([]byte, size)
			for range count {
				if _, err := dcs[i].Write(buf); err != nil {
					tb.Errorf("session %d: Write: %v", i, err)
					return
				}
			}
		})
		wg.Go(func() {
			buf := make([]byte, size)
			for range count {
				if _, err := io.ReadFull(pcs[i], buf); err != nil {
					tb.Errorf("session %d: Read: %v", i, err)
					return
				}
			}
		})
	}
	wg.Wait()
}

// BenchmarkMuxLoopback (§A11.4; perf lane, recorded, never gating): the
// aggregate throughput of 1, 4, 16 and 64 stream sessions on one MUX
// trunk over carrier/tcp on loopback (default Props), every session
// writing 64 KiB per operation dialer → passive with its own writer and
// reader. It reports MB/s (SetBytes) and the CPU seconds the process used
// per GiB moved (cpu-s/GiB, the runtime's estimate). On the Windows host
// only a smoke run (-benchtime=1x) is allowed.
func BenchmarkMuxLoopback(b *testing.B) {
	const chunk = 64 << 10
	for _, n := range []int{1, 4, 16, 64} {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			l := msTCPListen(b)
			m := newMsPair(b, rendr.Config{}, nil, rendr.ListenConfig{Sources: []rendr.Source{rendr.FromListener(l)}},
				[]rendr.Carrier{tcp.Carrier("direct", "tcp", l.Addr().String(), tcp.Options{})})
			dcs, pcs := make([]*rendr.Conn, n), make([]*rendr.Conn, n)
			for i := range n {
				dcs[i], pcs[i] = m.open(rendr.ModeSelector)
			}
			if mx := m.d.Status().Mux; mx.Carriers != 1 || mx.Views != n {
				b.Fatalf("dialer Mux %+v, want %d views on one trunk", mx, n)
			}
			msBulk(b, dcs, pcs, 16, chunk) // warm-up: windows, pools, rings
			b.SetBytes(int64(n) * chunk)
			b.ReportAllocs()
			cpu0 := msCPU()
			b.ResetTimer()
			msBulk(b, dcs, pcs, b.N, chunk)
			b.StopTimer()
			b.ReportMetric((msCPU()-cpu0)/(float64(n)*float64(chunk)*float64(b.N)/(1<<30)), "cpu-s/GiB")
			for i := range n {
				msEnd(b, dcs[i], pcs[i])
			}
			m.muxZero()
			m.close()
		})
	}
}

// BenchmarkRaceLoopback (§A11.4, §A12; perf lane, recorded, never
// gating): one race stream session over two carrier/tcp factories on
// loopback (default Props: a MUX trunk of one view each), 64 KiB per
// operation dialer → passive. Every member carries every byte, so wire
// bytes are about twice the goodput: it reports MB/s of goodput and the
// CPU seconds per delivered GiB (≈ 2 × a selector session's, §A12).
func BenchmarkRaceLoopback(b *testing.B) {
	const chunk = 64 << 10
	l := msTCPListen(b)
	m := newMsPair(b, rendr.Config{}, nil, rendr.ListenConfig{Sources: []rendr.Source{rendr.FromListener(l)}},
		[]rendr.Carrier{tcp.Carrier("r0", "tcp", l.Addr().String(), tcp.Options{}), tcp.Carrier("r1", "tcp", l.Addr().String(), tcp.Options{})})
	dc, pc := m.open(rendr.ModeRace)
	msUntil(b, 5*time.Second, "both race members live", func() bool { return msLive(dc.Status()) == 2 })
	dcs, pcs := []*rendr.Conn{dc}, []*rendr.Conn{pc}
	msBulk(b, dcs, pcs, 16, chunk)
	b.SetBytes(chunk)
	b.ReportAllocs()
	cpu0 := msCPU()
	b.ResetTimer()
	msBulk(b, dcs, pcs, b.N, chunk)
	b.StopTimer()
	b.ReportMetric((msCPU()-cpu0)/(float64(chunk)*float64(b.N)/(1<<30)), "cpu-s/GiB")
	b.ReportMetric(float64(dc.Status().Race.CopyBytes)/float64(max(dc.Status().TxBytes, 1)), "copies/byte")
	msEnd(b, dc, pc)
	m.muxZero()
	m.close()
}
