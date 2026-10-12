package l4

import (
	"context"
	"errors"
	"net"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// M4 WP5: the Server's sessions end to end (M4 design §A6, §A12.1).

// fakeDNS is a loopback UDP DNS server (real sockets, outside bubbles):
// it answers every query NXDOMAIN, or never answers when silent.
type fakeDNS struct {
	pc      net.PacketConn
	queries atomic.Int64
	done    chan struct{}
}

func newFakeDNS(t *testing.T, silent bool) *fakeDNS {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeDNS{pc: pc, done: make(chan struct{})}
	go func() {
		defer close(f.done)
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			f.queries.Add(1)
			if resp := nxdomain(buf[:n]); !silent && resp != nil {
				pc.WriteTo(resp, from)
			}
		}
	}()
	t.Cleanup(func() { pc.Close(); <-f.done })
	return f
}

// nxdomain is the NXDOMAIN answer to query q: its header and question
// with QR, RA and RCODE 3 set and no records.
func nxdomain(q []byte) []byte {
	i := 12
	for i < len(q) && q[i] != 0 {
		i += int(q[i]) + 1
	}
	i += 1 + 4 // the root label, QTYPE, QCLASS
	if len(q) < 12 || i > len(q) {
		return nil
	}
	r := append([]byte(nil), q[:i]...)
	r[2] = 0x80 | q[2]&0x01 // QR, RD as asked
	r[3] = 0x83             // RA, RCODE NXDOMAIN
	clear(r[6:12])          // no answer, authority or additional records
	return r
}

// resolverHook is a Dial hook whose pure-Go resolver asks only f.
func resolverHook(f *fakeDNS) func(context.Context, Request) (net.Conn, error) {
	res := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", f.pc.LocalAddr().String())
	}}
	return func(ctx context.Context, r Request) (net.Conn, error) {
		return (&net.Dialer{Resolver: res}).DialContext(ctx, "tcp", r.Addr)
	}
}

// TestServerDNSNotFound (§A8.1 row 2): a name that does not exist is
// answered CodeDNSNotFound, from a scripted resolver error and from a
// pure-Go resolver whose server answers NXDOMAIN (real loopback UDP).
func TestServerDNSNotFound(t *testing.T) {
	t.Run("scripted", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w := newSrvWorld(t, srvOpts{})
			dial, _ := rendrtest.ScriptedDial(rendrtest.OutcomeDNSNotFound())
			s := &Server{Dial: hookOf(dial)}
			sv := serve(w, s)
			_, err := Dial(context.Background(), w.peer, "nx.test:80", rendr.DialOptions{})
			wantReject(t, err, CodeDNSNotFound)
			sv.stop(t)
			w.shutdown()
		})
	})
	t.Run("resolver", func(t *testing.T) {
		f := newFakeDNS(t, false)
		w := newSrvWorld(t, srvOpts{})
		s := &Server{Dial: resolverHook(f), DialTimeout: 2 * time.Second}
		sv := serve(w, s)
		_, err := Dial(context.Background(), w.peer, "nx.l4-test.example.:80", rendr.DialOptions{})
		wantReject(t, err, CodeDNSNotFound)
		if f.queries.Load() == 0 {
			t.Fatalf("stimulus: the fake DNS server saw no query (last error %v)", s.Status().LastErr)
		}
		sv.stop(t)
		w.shutdown()
	})
}

// TestServerDNSFailureSilent (M4-D33 order): a resolver whose server
// never answers runs into the dial budget; the answer is CodeDNSFailure
// (the DNS row precedes the timeout row), within the budget. Real
// loopback UDP, outside bubbles.
func TestServerDNSFailureSilent(t *testing.T) {
	f := newFakeDNS(t, true)
	w := newSrvWorld(t, srvOpts{})
	s := &Server{Dial: resolverHook(f), DialTimeout: time.Second}
	sv := serve(w, s)
	start := time.Now()
	_, err := Dial(context.Background(), w.peer, "silent.l4-test.example.:80", rendr.DialOptions{})
	el := time.Since(start)
	wantReject(t, err, CodeDNSFailure)
	if el < time.Second || el > 3*time.Second {
		t.Fatalf("refused after %v, want the 1 s budget", el)
	}
	if f.queries.Load() == 0 {
		t.Fatalf("stimulus: the fake DNS server saw no query (last error %v)", s.Status().LastErr)
	}
	t.Logf("refused after %v; %d queries; raw %v", el, f.queries.Load(), s.Status().LastErr)
	sv.stop(t)
	w.shutdown()
}

// TestServerDuplicateOpenDialsOnce_L47: the dialer retries its OPEN after
// the first OPEN_ACK(OK) was lost; the retried OPEN reaches the session
// already confirmed, so the target is dialled once and the connection
// carries data intact.
func TestServerDuplicateOpenDialsOnce_L47(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newSrvWorld(t, srvOpts{})
		target := rendrtest.NewTarget(rendrtest.TargetEcho(), 0)
		hl := newHookLog(func(ctx context.Context, r Request) (net.Conn, error) {
			w.links[0].DropNextFrame(rendrtest.Down, rendrtest.FrameOpenAck)
			return target.Dial(ctx, r.Addr)
		})
		s := &Server{Dial: hl.dial}
		sv := serve(w, s)
		c, err := Dial(context.Background(), w.peer, kitTarget, rendr.DialOptions{})
		if err != nil {
			t.Fatalf("Dial after a lost OPEN_ACK: %v", err)
		}
		synctest.Wait()
		if st := w.links[0].Stats(); st.Session.FramesDropped != 1 || st.Dials < 2 {
			t.Fatalf("stimulus: %d OPEN_ACKs dropped, %d carrier dials", st.Session.FramesDropped, st.Dials)
		}
		echoRoundTrip(t, c, 128<<10, 4)
		c.Close()
		waitFor(t, time.Minute, "the forward ends", func() bool { return s.Status().Live == 0 })
		calls, _, _, _ := hl.snapshot()
		if tc, st := target.Counts(), s.Status(); calls != 1 || tc.Accepted != 1 || st.Confirmed != 1 || st.Rejected != 0 {
			t.Fatalf("%d hook calls, %d target conns; status %+v", calls, tc.Accepted, st)
		}
		sv.stop(t)
		w.shutdown()
	})
}

// TestServerListenerCloseKeepsForwards_L50 (M4-D34): Listener.Close stops
// Accept, but confirmed forwards continue; Serve returns net.ErrClosed once
// they ended.
func TestServerListenerCloseKeepsForwards_L50(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newSrvWorld(t, srvOpts{})
		target := rendrtest.NewTarget(rendrtest.TargetEcho(), 0)
		s := &Server{Dial: hookOf(target.Dial)}
		sv := serve(w, s)
		c, err := Dial(context.Background(), w.peer, kitTarget, rendr.DialOptions{})
		if err != nil {
			t.Fatal(err)
		}
		ping(t, c, 1000)
		w.ln.Close()
		time.Sleep(5 * time.Second)
		select {
		case err := <-sv.done:
			t.Fatalf("Serve returned %v while a forward runs", err)
		default:
		}
		ping(t, c, 1000)
		echoRoundTrip(t, c, 64<<10, 5)
		c.Close()
		if err := sv.wait(t, time.Minute); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Serve: %v", err)
		}
		if tc, st := target.Counts(), s.Status(); tc.RSTIn != 0 || tc.FINIn != 1 || tc.Open != 0 || st.Live != 0 || st.Confirmed != 1 {
			t.Fatalf("target %+v; status %+v", tc, st)
		}
		w.shutdown()
	})
}

// TestServerIgnoresPacketOpens (M4-D35): Serve never accepts packet
// sessions: a packet OPEN with L4 metadata waits in the packet backlog
// until AcceptTimeout answers CAPACITY, without a hook call, while a
// stream session is served beside it.
func TestServerIgnoresPacketOpens(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newSrvWorld(t, srvOpts{acceptTimeout: time.Second})
		target := rendrtest.NewTarget(rendrtest.TargetEcho(), 0)
		hl := newHookLog(hookOf(target.Dial))
		s := &Server{Dial: hl.dial}
		sv := serve(w, s)
		md, err := AppendMetadata(nil, Request{Cmd: CmdConnect, Addr: kitTarget})
		if err != nil {
			t.Fatal(err)
		}
		pres := make(chan error, 1)
		start := time.Now()
		go func() {
			_, err := w.peer.DialPacket(context.Background(), rendr.DialOptions{Metadata: md})
			pres <- err
		}()
		c, err := Dial(context.Background(), w.peer, kitTarget, rendr.DialOptions{})
		if err != nil {
			t.Fatalf("stream Dial: %v", err)
		}
		ping(t, c, 100)
		err = <-pres
		if el := time.Since(start); !errors.Is(err, rendr.ErrCapacity) || el < time.Second {
			t.Fatalf("DialPacket: %v after %v, want ErrCapacity at the AcceptTimeout", err, el)
		}
		if calls, _, _, _ := hl.snapshot(); calls != 1 {
			t.Fatalf("%d hook calls, want the stream session's only", calls)
		}
		if st := s.Status(); st.Rejected != 0 || st.Confirmed != 1 {
			t.Fatalf("status %+v", st)
		}
		c.Close()
		sv.stop(t)
		w.shutdown()
	})
}

// TestServerIdleDefault (M4-D41): every served session gets the Server's
// IdleTimeout: DefaultIdleTimeout (10 min) by default, the value set, or
// none when negative. The dialer sets no idle limit of its own here, so
// the passive's ends the session (RST(Idle) to the dialer) and Forward
// resets the target.
func TestServerIdleDefault(t *testing.T) {
	rows := []struct {
		name string
		idle time.Duration
		want time.Duration // 0: no expiry
	}{
		{"default", 0, DefaultIdleTimeout},
		{"2 min", 2 * time.Minute, 2 * time.Minute},
		{"none", -1, 0},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newSrvWorld(t, srvOpts{})
				target := rendrtest.NewTarget(rendrtest.TargetEcho(), 0)
				s := &Server{Dial: hookOf(target.Dial), IdleTimeout: row.idle}
				sv := serve(w, s)
				md, err := AppendMetadata(nil, Request{Cmd: CmdConnect, Addr: kitTarget})
				if err != nil {
					t.Fatal(err)
				}
				c, err := w.peer.Dial(context.Background(), rendr.DialOptions{Metadata: md})
				if err != nil {
					t.Fatal(err)
				}
				ping(t, c, 100)
				time.Sleep(time.Second)
				synctest.Wait()
				quiet := time.Now()
				if row.want == 0 {
					time.Sleep(30 * time.Minute)
					select {
					case <-c.Done():
						t.Fatalf("the session ended %v after its last byte: %v", time.Since(quiet), c.Status().Err)
					default:
					}
					c.Close()
				} else {
					time.Sleep(row.want - 2*time.Second)
					select {
					case <-c.Done():
						t.Fatalf("the session ended %v after its last byte, before %v", time.Since(quiet), row.want)
					default:
					}
					waitDone(t, c, time.Minute)
					if el := time.Since(quiet); el > row.want+3*time.Second {
						t.Fatalf("the session ended %v after its last byte, want %v", el, row.want)
					}
					if code, remote, ok := abortCode(c.Status().Err); !ok || code != rendr.AbortIdle || !remote {
						t.Fatalf("dialer end %v, want *AbortError{AbortIdle, Remote}", c.Status().Err)
					}
				}
				waitFor(t, time.Minute, "the target is released", func() bool { return target.Counts().Open == 0 })
				if tc := target.Counts(); row.want > 0 && tc.RSTIn != 1 {
					t.Fatalf("target %+v, want a reset", tc)
				}
				sv.stop(t)
				w.shutdown()
			})
		})
	}
}

// TestServerAllocsPerConn (§A12.6, recorded ceiling): the Server's own
// allocations per accepted, dialled, confirmed and forwarded connection —
// Serve and Handle against a hand-written Accept, Confirm and Forward loop
// over the same Runtimes, links and target — stay at most 64. The ceiling
// applies to that difference, not to the end-to-end total (about 470 per
// connection, mostly the core's session setup; recorded in the log). The
// two loops are measured in three alternating pairs and the median
// difference is checked: one pair's baseline once came out 50 allocations
// per connection low (the pool's l4 sweep, 1 run in 600; the sync.Pools
// both loops draw on depend on when the collector ran).
func TestServerAllocsPerConn(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const k = 400 // enough connections that the difference of two totals is stable
		w := newSrvWorld(t, srvOpts{})
		target := rendrtest.NewTarget(rendrtest.TargetEcho(), 0)
		one := func() {
			c, err := Dial(context.Background(), w.peer, kitTarget, rendr.DialOptions{})
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			ping(t, c, 100)
			c.Close()
			waitDone(t, c, time.Minute)
		}
		measure := func(settle func()) float64 {
			for range 10 { // warm up
				one()
			}
			settle()
			var m0, m1 runtime.MemStats
			runtime.ReadMemStats(&m0)
			for range k {
				one()
			}
			settle()
			runtime.ReadMemStats(&m1)
			return float64(m1.Mallocs-m0.Mallocs) / k
		}

		// The baseline: Accept, the target dial, Confirm, SetIdleTimeout and
		// Forward written out.
		baseline := func() float64 {
			ctx, cancel := context.WithCancel(context.Background())
			var handlers sync.WaitGroup
			var live atomic.Int64
			loop := make(chan struct{})
			go func() {
				defer close(loop)
				for {
					p, err := w.ln.Accept(ctx)
					if err != nil {
						return
					}
					live.Add(1)
					handlers.Go(func() {
						defer live.Add(-1)
						tc, _ := target.Dial(ctx, kitTarget)
						c, err := p.Confirm()
						if err != nil {
							tc.Close()
							return
						}
						c.SetIdleTimeout(DefaultIdleTimeout)
						Forward(ctx, c, tc)
					})
				}
			}()
			n := measure(func() {
				waitFor(t, time.Minute, "the baseline forwards end", func() bool { return live.Load() == 0 })
				synctest.Wait()
			})
			cancel()
			<-loop
			handlers.Wait()
			return n
		}
		served := func() float64 {
			s := &Server{Dial: hookOf(target.Dial)}
			sv := serve(w, s)
			n := measure(func() {
				waitFor(t, time.Minute, "the forwards end", func() bool { st := s.Status(); return st.Live == 0 && st.Hooks == 0 })
				synctest.Wait()
			})
			sv.stop(t)
			return n
		}
		var own [3]float64
		for i := range own {
			base, server := baseline(), served()
			own[i] = server - base
			t.Logf("allocations per connection: baseline %.1f, Serve %.1f, the Server's own %.1f", base, server, own[i])
		}
		slices.Sort(own[:])
		if !raceEnabled && own[1] > 64 {
			t.Fatalf("the Server allocates %.1f times per connection (median of %v), want ≤ 64", own[1], own)
		}
		w.shutdown()
	})
}
