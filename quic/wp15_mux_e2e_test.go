package quic

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime/debug"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The rendr mux rows of the quic module (M3 design §A11.4, §A7.4; M3-D2,
// M3-D40, PA-29): the quic module keeps one QUIC connection per carrier,
// and its factories are mux-eligible by default, so the sessions of one
// Peer share one QUIC connection's carrier unless the role sets
// Props.CheapSubflow on the returned factory. Real loopback sockets,
// outside synctest bubbles; every test registers rendrtest.AssertNoLeak
// first.

// mxEnv is two Runtimes and a quic Listener serving the passive's rendr
// Listener; dials counts the dialer's session dials (probe carriers
// excluded) per factory name.
type mxEnv struct {
	t      *testing.T
	d, p   *rendr.Runtime
	rl     *rendr.Listener
	ql     *Listener
	served chan error
	cli    Options // the factories' options (the client TLS configuration)
	mu     sync.Mutex
	dials  map[string]int
}

func newMxEnv(t *testing.T) *mxEnv {
	t.Helper()
	srv, cli := testTLS(t)
	e := &mxEnv{t: t, served: make(chan error, 1), cli: Options{TLS: cli}, dials: map[string]int{}}
	var err error
	if e.d, err = rendr.NewRuntime(rendr.Config{}); err != nil {
		t.Fatal(err)
	}
	if e.p, err = rendr.NewRuntime(rendr.Config{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.d.Close(); e.p.Close() })
	if e.rl, err = e.p.Listen(rendr.ListenConfig{}); err != nil {
		t.Fatal(err)
	}
	if e.ql, err = Listen("udp4", "127.0.0.1:0", Options{TLS: srv}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.ql.Close() }) // after a failure too (close is idempotent)
	go func() { e.served <- e.ql.Serve(e.rl) }()
	return e
}

// countStream and countDgram wrap a factory's Dial to count its session
// dials; the conn rendr gets is the factory's own.
func (e *mxEnv) countStream(c rendr.StreamCarrier) rendr.StreamCarrier {
	dial := c.Dial
	c.Dial = func(ctx context.Context) (net.Conn, error) {
		nc, err := dial(ctx)
		if di, ok := rendr.CarrierDialInfo(ctx); err == nil && ok && !di.Probe {
			e.mu.Lock()
			e.dials[c.Name]++
			e.mu.Unlock()
		}
		return nc, err
	}
	return c
}

func (e *mxEnv) countDgram(c rendr.DatagramCarrier) rendr.DatagramCarrier {
	dial := c.Dial
	c.Dial = func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		pc, a, err := dial(ctx)
		if di, ok := rendr.CarrierDialInfo(ctx); err == nil && ok && !di.Probe {
			e.mu.Lock()
			e.dials[c.Name]++
			e.mu.Unlock()
		}
		return pc, a, err
	}
	return c
}

func (e *mxEnv) dialsOf(name string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.dials[name]
}

// stream returns a QUIC stream factory with props, counted.
func (e *mxEnv) stream(name string, props rendr.Props) rendr.StreamCarrier {
	e.t.Helper()
	c, err := StreamCarrier(name, e.ql.Addr().String(), e.cli)
	if err != nil {
		e.t.Fatal(err)
	}
	if c.Props != (rendr.Props{}) {
		e.t.Fatalf("StreamCarrier returned Props %+v, want the zero value (mux-eligible, a fate group of its own)", c.Props)
	}
	c.Props = props
	return e.countStream(c)
}

// datagram returns a QUIC DATAGRAM factory with props, counted.
func (e *mxEnv) datagram(name string, props rendr.Props) rendr.DatagramCarrier {
	e.t.Helper()
	c, err := DatagramCarrier(name, e.ql.Addr().String(), e.cli)
	if err != nil {
		e.t.Fatal(err)
	}
	if c.Props != (rendr.Props{}) {
		e.t.Fatalf("DatagramCarrier returned Props %+v, want the zero value (mux-eligible, a fate group of its own)", c.Props)
	}
	c.Props = props
	return e.countDgram(c)
}

// peer builds a dialer Peer on carriers.
func (e *mxEnv) peer(carriers ...rendr.Carrier) *rendr.Peer {
	e.t.Helper()
	p, err := e.d.NewPeer(rendr.PeerConfig{Carriers: carriers})
	if err != nil {
		e.t.Fatal(err)
	}
	return p
}

// openStreams opens n stream sessions on peer one at a time; the passive
// confirms each.
func (e *mxEnv) openStreams(peer *rendr.Peer, n int) (dcs, pcs []*rendr.Conn) {
	e.t.Helper()
	for range n {
		ch := make(chan *rendr.Conn, 1)
		go func() {
			c, err := peer.Dial(context.Background(), rendr.DialOptions{})
			if err != nil {
				e.t.Errorf("Dial: %v", err)
			}
			ch <- c
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		pend, err := e.rl.Accept(ctx)
		cancel()
		var pc *rendr.Conn
		if err == nil {
			pc, err = pend.Confirm()
		}
		if err != nil {
			e.t.Fatalf("Accept: %v", err)
		}
		dc := <-ch
		if dc == nil {
			e.t.FailNow()
		}
		dcs, pcs = append(dcs, dc), append(pcs, pc)
	}
	return dcs, pcs
}

// openPackets opens n packet sessions on peer one at a time.
func (e *mxEnv) openPackets(peer *rendr.Peer, n int) (dcs, pcs []*rendr.PacketConn) {
	e.t.Helper()
	for range n {
		ch := make(chan *rendr.PacketConn, 1)
		go func() {
			c, err := peer.DialPacket(context.Background(), rendr.DialOptions{})
			if err != nil {
				e.t.Errorf("DialPacket: %v", err)
			}
			ch <- c
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		pend, err := e.rl.AcceptPacket(ctx)
		cancel()
		var pc *rendr.PacketConn
		if err == nil {
			pc, err = pend.Confirm()
		}
		if err != nil {
			e.t.Fatalf("AcceptPacket: %v", err)
		}
		dc := <-ch
		if dc == nil {
			e.t.FailNow()
		}
		dcs, pcs = append(dcs, dc), append(pcs, pc)
	}
	return dcs, pcs
}

// close closes both Runtimes and the quic Listener and requires that
// nothing is left.
func (e *mxEnv) close() {
	e.t.Helper()
	e.d.Close()
	e.p.Close()
	_ = e.ql.Close()
	if err := <-e.served; !errors.Is(err, net.ErrClosed) {
		e.t.Errorf("Serve returned %v, want net.ErrClosed", err)
	}
	select {
	case <-e.ql.Done():
	case <-time.After(10 * time.Second):
		e.t.Errorf("quic Listener: Done not closed after Runtime.Close")
	}
	for _, rt := range []*rendr.Runtime{e.d, e.p} {
		st := rt.Status()
		sc := st.Sessions
		if sc.Open+sc.Pending+sc.Lingering+sc.Orphaned != 0 || st.Handshakes != 0 || st.BufferedBytes != 0 || st.Abandoned != 0 ||
			st.Actors != 0 || st.Mux.Carriers != 0 || st.Mux.Views != 0 {
			e.t.Errorf("state left after Runtime.Close: %+v", st)
		}
	}
}

// mxWait polls cond every millisecond for at most within.
func mxWait(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("not within %v: %s", within, what)
		}
		time.Sleep(time.Millisecond)
	}
}

// mxExchange moves size bytes of PRNG each way on every stream session at
// once (the passive's bytes from seed+1) and checks both directions with
// the PRNG verifier and SHA-256 digests; then it closes every session and
// requires a clean end (io.EOF).
func mxExchange(t *testing.T, dcs, pcs []*rendr.Conn, size int64) {
	t.Helper()
	var wg sync.WaitGroup
	errs := make(chan error, 4*len(dcs))
	for i := range dcs {
		seed := uint64(10 + 2*i)
		for _, dir := range []struct {
			w, r *rendr.Conn
			seed uint64
			name string
		}{{dcs[i], pcs[i], seed, "up"}, {pcs[i], dcs[i], seed + 1, "back"}} {
			var sent, read [32]byte
			wg.Go(func() {
				h := sha256.New()
				_, err := io.Copy(struct{ io.Writer }{dir.w}, io.TeeReader(io.LimitReader(rendrtest.PRNG(dir.seed), size), h))
				if err == nil {
					err = dir.w.CloseWrite()
				}
				h.Sum(sent[:0])
				if err != nil {
					errs <- fmt.Errorf("session %d %s write: %w", i, dir.name, err)
				}
			})
			wg.Go(func() {
				h := sha256.New()
				err := rendrtest.NewVerifier(dir.seed, size).ReadAll(io.TeeReader(dir.r, h))
				h.Sum(read[:0])
				if err != nil {
					errs <- fmt.Errorf("session %d %s read: %w", i, dir.name, err)
				}
			})
			defer func() {
				if sent != read {
					t.Errorf("session %d %s: SHA-256 %x sent, %x read", i, dir.name, sent[:8], read[:8])
				}
			}()
		}
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the exchanges did not finish within 30 s")
	}
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	for i := range dcs {
		for _, c := range []*rendr.Conn{dcs[i], pcs[i]} {
			c.Close()
			select {
			case <-c.Done():
			case <-time.After(30 * time.Second):
				t.Fatalf("session %d (%v) not done 30 s after Close", i, c.Status().Role)
			}
			if st := c.Status(); st.Err != io.EOF {
				t.Errorf("session %d (%v) ended with %v, want io.EOF", i, st.Role, st.Err)
			}
		}
	}
}

// TestQUICMuxE2E (§A11.4, §A7.4; M3-D2, M3-D40): four stream sessions of
// one Peer over a QUIC stream factory. By default (the zero Props the
// factory returns) they share one QUIC connection's carrier: one session
// dial, one connection handed to the passive, Status.Mux one carrier with
// four views on both Runtimes and every session's carrier Shared by 4.
// With Props.CheapSubflow set on the returned factory every session dials
// its own carrier: four session dials, four QUIC connections handed to the
// passive, no MUX trunk, each carrier Shared by 1. In both, 1 MiB moves
// each way on every session at once (256 KiB under -race) with verified
// content and SHA-256 sums, every session ends with io.EOF, the shared
// connection closes after its last session (the default's trunk closes at
// its last view, M3-D20), and Runtime.Close leaves nothing.
func TestQUICMuxE2E(t *testing.T) {
	const n = 4
	size := int64(1 << 20)
	if quicRace {
		size = 256 << 10
	}
	for _, cheap := range []bool{false, true} {
		t.Run("CheapSubflow="+strconv.FormatBool(cheap), func(t *testing.T) {
			t.Cleanup(rendrtest.AssertNoLeak(t))
			e := newMxEnv(t)
			peer := e.peer(e.stream("qs", rendr.Props{CheapSubflow: cheap}))
			dcs, pcs := e.openStreams(peer, n)
			wantConns, wantShared := 1, n
			if cheap {
				wantConns, wantShared = n, 1
			}
			mxWait(t, 5*time.Second, "the passive's carriers", func() bool {
				return int(e.ql.Stats().Streams) == wantConns
			})
			if got := e.dialsOf("qs"); got != wantConns {
				t.Fatalf("%d session dials for %d sessions, want %d", got, n, wantConns)
			}
			ids := map[rendr.CarrierID]bool{}
			for i := range n {
				for _, st := range []rendr.SessionStatus{dcs[i].Status(), pcs[i].Status()} {
					cs := st.Carriers
					if len(cs) != 1 || cs[0].Shared != wantShared || cs[0].State == rendr.CarrierDead {
						t.Fatalf("session %d (%v) carriers %+v, want one live carrier Shared by %d", i, st.Role, cs, wantShared)
					}
					if st.Role == rendr.RoleDialer {
						ids[cs[0].ID] = true
					}
				}
			}
			if len(ids) != wantConns {
				t.Fatalf("the dialer's sessions use %d carriers, want %d", len(ids), wantConns)
			}
			wantMux := rendr.MuxStatus{Carriers: 1, Views: n}
			if cheap {
				wantMux = rendr.MuxStatus{}
			}
			for _, rt := range []*rendr.Runtime{e.d, e.p} {
				if m := rt.Status().Mux; m.Carriers != wantMux.Carriers || m.Views != wantMux.Views {
					t.Fatalf("Status.Mux %+v, want %d carriers and %d views", m, wantMux.Carriers, wantMux.Views)
				}
			}

			mxExchange(t, dcs, pcs, size)

			if got := e.dialsOf("qs"); got != wantConns {
				t.Errorf("%d session dials after the exchange, want %d (no carrier died)", got, wantConns)
			}
			mxWait(t, 10*time.Second, "the MUX trunks closed at their last view", func() bool {
				return e.d.Status().Mux.Carriers == 0 && e.p.Status().Mux.Carriers == 0
			})
			t.Logf("CheapSubflow %v: %d session dials, %d QUIC connections handed to the passive; dialer Mux %+v",
				cheap, e.dialsOf("qs"), e.ql.Stats().Streams, e.d.Status().Mux)
			e.close()
		})
	}
}

// quicRace reports a race-detector build (the build setting "-race").
var quicRace = func() bool {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return false
	}
	for _, st := range bi.Settings {
		if st.Key == "-race" {
			return st.Value == "true"
		}
	}
	return false
}()
