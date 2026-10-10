package l4

import (
	"context"
	"errors"
	"io"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// M4 WP4: Forward's FIN/RST mapping (§A7.3), the release rows (§A7.4,
// R1-1, R1-3) and ctx (§A7.6).

// testAbort is an application abort code (≥ 256) the tests send.
const testAbort rendr.AbortCode = 0x5000

// TestForwardTargetResetIsReset_L02 (§A7.3, M4-D37, L02): a target that
// resets in the middle of its answer reaches the client as a reset, never
// as EOF: the egress Forward aborts the session (AbortReset), the ingress
// Forward resets the client.
func TestForwardTargetResetIsReset_L02(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newWorld(t, worldOpts{})
		const sent = 100 << 10
		ch := w.chain(rendrtest.TargetRSTAfter(sent), 0)
		n, _, err := readAll(ch.client)
		if !isReset(err) || n > sent {
			t.Fatalf("client read %d bytes, then %v; want at most %d, then a reset (never io.EOF)", n, err, sent)
		}
		in, out := ch.results()
		if !isReset(out.LocalErr) || out.Clean {
			t.Fatalf("egress Forward: %+v, want the target's reset as LocalErr", out)
		}
		if code, remote, ok := abortCode(in.SessionErr); !ok || code != AbortReset || !remote || in.Clean {
			t.Fatalf("ingress Forward: %+v, want *AbortError{AbortReset, Remote}", in)
		}
		synctest.Wait() // the target notices the reset and closes
		if c := ch.target.Counts().Conns[0]; !c.RSTOut || c.FINOut {
			t.Fatalf("stimulus: target connection %+v, want its reset", c)
		}
		ch.end(t)
		w.shutdown()
	})
}

// TestForwardSessionErrorResetsLocal_L02 (§A7.3, M4-D37): every unclean
// end of the session resets the local conn (SetLinger(0), Close): the
// target sees a reset, never a FIN.
func TestForwardSessionErrorResetsLocal_L02(t *testing.T) {
	cases := []struct {
		name  string
		opts  worldOpts
		end   func(w *world, d, p *rendr.Conn)
		check func(err error) bool
	}{
		{"peer abort", worldOpts{}, func(_ *world, d, _ *rendr.Conn) { d.Abort(testAbort, "test") },
			func(err error) bool { c, r, ok := abortCode(err); return ok && c == testAbort && r }},
		{"peer runtime close", worldOpts{}, func(w *world, _, _ *rendr.Conn) { w.d.Close() },
			func(err error) bool { c, r, ok := abortCode(err); return ok && c == rendr.AbortGoingAway && r }},
		{"idle", worldOpts{}, func(_ *world, _, p *rendr.Conn) { p.SetIdleTimeout(10 * time.Second) },
			func(err error) bool { return errors.Is(err, rendr.ErrIdleTimeout) }},
		{"no path", worldOpts{}, func(w *world, _, _ *rendr.Conn) { w.links[0].SetRefuse(true); w.links[0].Kill() },
			func(err error) bool { return errors.Is(err, rendr.ErrNoPath) || errors.Is(err, rendr.ErrSessionLost) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newWorld(t, tc.opts)
				tg := rendrtest.NewTarget(rendrtest.TargetEcho(), 0)
				d, p := w.open(rendr.DialOptions{})
				tconn, err := tg.Dial(context.Background(), kitTarget)
				if err != nil {
					t.Fatal(err)
				}
				out := forwardAsync(context.Background(), p, tconn)
				if err := writePRNG(d, 1, 4<<10); err != nil {
					t.Fatalf("Write: %v", err)
				}
				buf := make([]byte, 4<<10)
				if _, err := io.ReadFull(d, buf); err != nil {
					t.Fatalf("echo: %v", err)
				}
				tc.end(w, d, p)
				r := <-out
				if r.Clean || !tc.check(r.SessionErr) {
					t.Fatalf("egress Forward: %+v (session end %v)", r, p.Status().Err)
				}
				synctest.Wait() // the target notices the reset and closes
				if c := tg.Counts().Conns[0]; !c.RSTIn || c.FINIn || c.Open {
					t.Fatalf("target connection %+v: want a reset, no FIN", c)
				}
				tg.Close()
				w.shutdown()
			})
		})
	}
}

// TestForwardEOFOnlyAfterTargetFIN_L02 (§A7.3, L02): a target's 4 MiB and
// its FIN cross three kills of the active carrier; the client reads every
// byte and then EOF, never an early EOF.
func TestForwardEOFOnlyAfterTargetFIN_L02(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newWorld(t, worldOpts{links: 2, rate: 8 << 20})
		const gen = 4 << 20
		ch := w.chain(rendrtest.TargetGen(gen, 9), 0)
		if err := ch.client.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 32<<10)
		var n int64
		kills, next := 0, int64(gen/4)
		h := newSum()
		var err error
		for {
			var k int
			k, err = ch.client.Read(buf)
			h.Write(buf[:k])
			n += int64(k)
			if err != nil {
				break
			}
			if n >= next && kills < 3 {
				if l := w.activeLink(ch.d); l != nil && l.Kill() > 0 {
					kills++
				}
				next += gen / 4
			}
		}
		if err != io.EOF || n != gen || h.sum() != prngSum(9, gen) {
			t.Fatalf("client read %d bytes (SHA ok: %v), then %v; want %d, then io.EOF", n, h.sum() == prngSum(9, gen), err, gen)
		}
		if kills != 3 || ch.d.Status().Migrations.Death < 3 {
			t.Fatalf("stimulus: %d kills, %d death migrations; want 3", kills, ch.d.Status().Migrations.Death)
		}
		in, out := ch.results()
		checkClean(t, "ingress", in, 0, gen)
		checkClean(t, "egress", out, gen, 0)
		endClean(t, w, ch)
	})
}

// TestForwardReleaseOnSessionEnd (§A7.4, M4-D38): a session that ends
// uncleanly while local still has a direction open releases local at once
// (≤ 1 virtual ms after Done): a target that never reads (pump B blocked in
// its Write, pump A in its Read) and one that ignores the FIN (pump A
// blocked in its Read).
func TestForwardReleaseOnSessionEnd(t *testing.T) {
	cases := []struct {
		name string
		b    rendrtest.TargetBehaviour
		feed func(t *testing.T, d *rendr.Conn)
	}{
		{"never reads", rendrtest.TargetNoRead(), func(t *testing.T, d *rendr.Conn) {
			if err := writePRNG(d, 1, 256<<10); err != nil { // beyond the pipe and the pump buffer
				t.Fatalf("Write: %v", err)
			}
		}},
		{"ignores FIN", rendrtest.TargetStall(), func(t *testing.T, d *rendr.Conn) {
			if err := writePRNG(d, 1, 4<<10); err != nil {
				t.Fatalf("Write: %v", err)
			}
			d.CloseWrite()
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				w := newWorld(t, worldOpts{})
				tg := rendrtest.NewTarget(tc.b, 16<<10)
				d, p := w.open(rendr.DialOptions{})
				tconn, err := tg.Dial(context.Background(), kitTarget)
				if err != nil {
					t.Fatal(err)
				}
				spy := &spyConn{Conn: tconn}
				out := forwardAsync(context.Background(), p, fullSpy{spy})
				tc.feed(t, d)
				time.Sleep(time.Second)
				synctest.Wait()
				if _, _, closes, _ := spy.snapshot(); closes != 0 || tg.Counts().Open != 1 {
					t.Fatal("local released before the session ended")
				}
				d.Abort(testAbort, "test")
				<-p.Done()
				doneAt := time.Now()
				var r ForwardResult
				select {
				case r = <-out:
				case <-time.After(time.Minute):
					t.Fatal("Forward still running a minute after the session ended")
				}
				synctest.Wait() // the target's behaviour notices the reset and closes
				_, l0, closes, _ := spy.snapshot()
				if el := spy.closedAt.Sub(doneAt); closes != 1 || l0 != 1 || el > time.Millisecond {
					t.Fatalf("local: %d Closes, %d SetLinger(0), closed %v after Done; want one reset within 1 ms", closes, l0, el)
				}
				if c := tg.Counts().Conns[0]; !c.RSTIn || c.Open {
					t.Fatalf("target connection %+v: want it reset and gone", c)
				}
				if r.Clean || r.Err() == nil {
					t.Fatalf("Forward: %+v, want an unclean end", r)
				}
				tg.Close()
				w.shutdown()
			})
		})
	}
}

// TestForwardNoReadLocalReleasedAtIdle (§A7.4, M4-D38): a target that never
// reads stops both directions; nothing moves, the idle limit (10 min, set by
// Dial and on the passive as the Server does) ends the session, and both
// Forwards reset their sockets: the target is reset, the client too.
func TestForwardNoReadLocalReleasedAtIdle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newWorld(t, worldOpts{})
		ch := w.chain(rendrtest.TargetNoRead(), 16<<10)
		if err := ch.p.SetIdleTimeout(DefaultIdleTimeout); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		wrote := make(chan error, 1)
		go func() { wrote <- writePRNG(ch.client, 1, 32<<20) }()
		time.Sleep(time.Second) // the windows fill; nothing moves from here
		synctest.Wait()
		moved := ch.d.Status().TxBytes
		if moved == 0 || moved >= 32<<20 {
			t.Fatalf("load: the dialer accepted %d bytes", moved)
		}
		time.Sleep(DefaultIdleTimeout - 2*time.Second)
		synctest.Wait()
		if tg := ch.target.Counts(); tg.Open != 1 || tg.RSTIn != 0 {
			t.Fatalf("target released before the idle limit: %+v", tg)
		}
		in, out := ch.results()
		released := time.Since(start)
		if released < DefaultIdleTimeout || released > DefaultIdleTimeout+time.Second+5*time.Second {
			t.Fatalf("released %v after the start, want the idle limit %v (+ DeadMax + 1 s)", released, DefaultIdleTimeout)
		}
		synctest.Wait() // the target notices the reset and closes
		if c := ch.target.Counts().Conns[0]; !c.RSTIn || c.Open {
			t.Fatalf("target connection %+v: want it reset", c)
		}
		if err := <-wrote; !isReset(err) {
			t.Fatalf("client Write ended with %v, want a reset", err)
		}
		for _, r := range []ForwardResult{in, out} {
			idle := errors.Is(r.SessionErr, rendr.ErrIdleTimeout)
			if code, _, ok := abortCode(r.SessionErr); ok && code == rendr.AbortIdle {
				idle = true
			}
			if r.Clean || !idle {
				t.Fatalf("Forward: %+v, want the idle end", r)
			}
		}
		ch.end(t)
		w.shutdown()
	})
}

// TestForwardCtxCancel (§A7.3, M4-D34): ctx ending aborts the session with
// AbortShutdown and resets local; the far Forward resets its socket.
func TestForwardCtxCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newWorld(t, worldOpts{})
		ch := w.chain(rendrtest.TargetEcho(), 0)
		if err := writePRNG(ch.client, 1, 64<<10); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64<<10)
		if _, err := io.ReadFull(ch.client, buf); err != nil {
			t.Fatalf("echo: %v", err)
		}
		ch.cancelOut()
		in, out := ch.results()
		if out.Clean || !errors.Is(out.SessionErr, context.Canceled) {
			t.Fatalf("egress Forward: %+v, want context.Canceled", out)
		}
		if code, remote, ok := abortCode(in.SessionErr); !ok || code != AbortShutdown || !remote {
			t.Fatalf("ingress Forward: %+v, want *AbortError{AbortShutdown, Remote}", in)
		}
		if _, err := ch.client.Read(buf); !isReset(err) {
			t.Fatalf("client Read: %v, want a reset", err)
		}
		synctest.Wait() // the target notices the reset and closes
		if c := ch.target.Counts().Conns[0]; !c.RSTIn || c.FINIn || c.Open {
			t.Fatalf("target connection %+v: want it reset", c)
		}
		ch.end(t)
		w.shutdown()
	})
}

// TestForwardCleanEndWhileLastChunkInFlight (R1-1): the session ends
// cleanly (DONE both ways) while pump B still writes the last chunk to a
// local that reads 16 bytes per virtual ms; the local receives every byte
// and then EOF, never a reset, and Forward ends clean. 1,000 iterations
// (100 under -race).
func TestForwardCleanEndWhileLastChunkInFlight(t *testing.T) {
	iters := 1000
	if raceEnabled {
		iters = 100
	}
	synctest.Test(t, func(t *testing.T) {
		w := newWorld(t, worldOpts{})
		const size = 4 << 10
		for i := range iters {
			d, p := w.open(rendr.DialOptions{})
			tcli, tsrv := rendrtest.TargetPipe(1 << 10)
			tsrv.CloseWrite() // the target FINs at once and then drains slowly
			type got struct {
				n   int64
				sum [32]byte
				err error
			}
			slow := make(chan got, 1)
			go func() {
				h, b := newSum(), make([]byte, 16)
				var n int64
				for {
					k, err := tsrv.Read(b)
					h.Write(b[:k])
					n += int64(k)
					if err != nil {
						slow <- got{n, h.sum(), err}
						return
					}
					time.Sleep(time.Millisecond)
				}
			}()
			out := forwardAsync(context.Background(), p, tcli)
			if err := writePRNG(d, uint64(i), size); err != nil {
				t.Fatalf("iteration %d: Write: %v", i, err)
			}
			d.CloseWrite()
			if n, _, err := readAll(d); n != 0 || err != io.EOF {
				t.Fatalf("iteration %d: dialer read %d, %v; want io.EOF", i, n, err)
			}
			<-p.Done()
			if p.Status().Err != io.EOF {
				t.Fatalf("iteration %d: passive end %v, want io.EOF", i, p.Status().Err)
			}
			select {
			case g := <-slow:
				t.Fatalf("iteration %d: stimulus: the local had every byte (%d, %v) when the session ended", i, g.n, g.err)
			default:
			}
			r := <-out
			g := <-slow
			if g.err != io.EOF || g.n != size || g.sum != prngSum(uint64(i), size) {
				t.Fatalf("iteration %d: local read %d bytes (SHA ok: %v), then %v; want %d, then io.EOF", i, g.n, g.sum == prngSum(uint64(i), size), g.err, size)
			}
			checkClean(t, "egress", r, 0, size)
			tsrv.Close()
			d.Close()
			waitDone(t, d, time.Minute)
		}
		w.shutdown()
	})
}

// TestForwardCleanEndLocalNeverDrains (R1-1, §A9): after a clean session
// end a local that stops reading is reset cleanJoinMax after Done, and the
// result is not clean.
func TestForwardCleanEndLocalNeverDrains(t *testing.T) {
	defer func(v time.Duration) { cleanJoinMax = v }(cleanJoinMax)
	cleanJoinMax = 5 * time.Second
	synctest.Test(t, func(t *testing.T) {
		w := newWorld(t, worldOpts{})
		d, p := w.open(rendr.DialOptions{})
		tcli, tsrv := rendrtest.TargetPipe(1 << 10)
		tsrv.CloseWrite() // FIN at once; never reads
		out := forwardAsync(context.Background(), p, tcli)
		// One chunk: pump B reads it all (the FIN is then delivered and the
		// session ends cleanly) and blocks writing it to local.
		if err := writePRNG(d, 1, 4<<10); err != nil {
			t.Fatalf("Write: %v", err)
		}
		d.CloseWrite()
		if _, _, err := readAll(d); err != io.EOF {
			t.Fatalf("dialer Read: %v, want io.EOF", err)
		}
		<-p.Done()
		doneAt := time.Now()
		if p.Status().Err != io.EOF {
			t.Fatalf("passive end %v, want io.EOF", p.Status().Err)
		}
		r := <-out
		if el := time.Since(doneAt); el != cleanJoinMax {
			t.Fatalf("Forward returned %v after Done, want cleanJoinMax %v", el, cleanJoinMax)
		}
		if r.Clean || !errors.Is(r.LocalErr, errNoDrain) {
			t.Fatalf("Forward: %+v, want not clean with %v", r, errNoDrain)
		}
		if _, err := tsrv.Read(make([]byte, 8)); !isReset(err) {
			t.Fatalf("local's peer Read: %v, want a reset", err)
		}
		tsrv.Close()
		d.Close()
		waitDone(t, d, time.Minute)
		w.shutdown()
	})
}

// TestForwardHalfClosedLocalCloseUnobservable (R1-3): the client
// half-closes and then closes its socket, which TCP does not signal; the
// target stalls. The session ends at the dialer's idle limit (30 s), not
// earlier, and then both sockets are reset.
func TestForwardHalfClosedLocalCloseUnobservable(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newWorld(t, worldOpts{})
		tg := rendrtest.NewTarget(rendrtest.TargetStall(), 0)
		d, p := w.open(rendr.DialOptions{})
		const idle = 30 * time.Second
		if err := d.SetIdleTimeout(idle); err != nil {
			t.Fatal(err)
		}
		p.SetIdleTimeout(DefaultIdleTimeout)
		tconn, err := tg.Dial(context.Background(), kitTarget)
		if err != nil {
			t.Fatal(err)
		}
		cli, srv := rendrtest.TargetPipe(0)
		spy := &spyConn{Conn: srv}
		in := forwardAsync(context.Background(), d, fullSpy{spy})
		out := forwardAsync(context.Background(), p, tconn)
		if err := writePRNG(cli, 1, 1<<10); err != nil {
			t.Fatal(err)
		}
		cli.CloseWrite()
		time.Sleep(time.Second) // the request, its FIN and their ACKs cross
		synctest.Wait()
		quiet := time.Now()
		if c := tg.Counts().Conns[0]; !c.FINIn || c.BytesIn != 1<<10 {
			t.Fatalf("stimulus: target connection %+v, want the request and the FIN", c)
		}
		cli.Close() // unobservable: nothing unread, FIN already sent
		time.Sleep(idle - 2*time.Second)
		synctest.Wait()
		if _, _, closes, _ := spy.snapshot(); closes != 0 || tg.Counts().Open != 1 {
			t.Fatal("released before the idle limit")
		}
		rin, rout := <-in, <-out
		released := time.Since(quiet)
		if released < idle-time.Second || released > idle+2*time.Second+time.Second {
			t.Fatalf("released %v after the last byte, want the idle limit %v (+ DeadMax + 1 s)", released, idle)
		}
		if !errors.Is(rin.SessionErr, rendr.ErrIdleTimeout) {
			t.Fatalf("ingress Forward: %+v, want ErrIdleTimeout", rin)
		}
		if code, remote, ok := abortCode(rout.SessionErr); !ok || code != rendr.AbortIdle || !remote {
			t.Fatalf("egress Forward: %+v, want *AbortError{AbortIdle, Remote}", rout)
		}
		if _, l0, closes, _ := spy.snapshot(); closes != 1 || l0 != 1 {
			t.Fatalf("ingress local: %d Closes, %d SetLinger(0); want one reset", closes, l0)
		}
		synctest.Wait() // the target's behaviour notices the reset and closes
		if c := tg.Counts().Conns[0]; !c.RSTIn || c.Open {
			t.Fatalf("target connection %+v: want it reset", c)
		}
		tg.Close()
		w.shutdown()
	})
}
