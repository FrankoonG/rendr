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

// M4 WP4 (m4-design §A7, §A12.1): Forward's half-close rows (§A7.2), its
// FIN/RST mapping (§A7.3), the release of a socket that ignores FIN or never
// reads (§A7.4, R1-1, R1-3) and its deadlines (§A7.5, R1-23).

// checkClean requires a clean result with the given byte counts.
func checkClean(t *testing.T, side string, r ForwardResult, toSession, toLocal int64) {
	t.Helper()
	if !r.Clean || r.Err() != nil || r.ToSession != toSession || r.ToLocal != toLocal {
		t.Fatalf("%s Forward: %+v, want clean with %d bytes to the session and %d to local", side, r, toSession, toLocal)
	}
}

// checkTargetConn requires the target's one connection to have read in
// bytes (SHA-256 sumIn), with the given FIN and RST records.
func checkTargetConn(t *testing.T, tg *rendrtest.Target, in int64, sumIn [32]byte, finIn, rstIn, rstOut bool) rendrtest.TargetConnCounts {
	t.Helper()
	cs := tg.Counts()
	if cs.Accepted != 1 {
		t.Fatalf("target accepted %d connections, want 1", cs.Accepted)
	}
	c := cs.Conns[0]
	if c.BytesIn != in || c.SHAIn != sumIn || c.FINIn != finIn || c.RSTIn != rstIn || c.RSTOut != rstOut {
		t.Fatalf("target connection %+v: want %d bytes in (SHA ok: %v), FINIn %v, RSTIn %v, RSTOut %v",
			c, in, c.SHAIn == sumIn, finIn, rstIn, rstOut)
	}
	return c
}

// endClean closes the client, requires both sessions to end cleanly and
// shuts the world down.
func endClean(t *testing.T, w *world, ch *chain) {
	t.Helper()
	ch.client.Close()
	waitDone(t, ch.d, time.Minute)
	waitDone(t, ch.p, time.Minute)
	if de, pe := ch.d.Status().Err, ch.p.Status().Err; de != io.EOF || pe != io.EOF {
		t.Fatalf("session ends: dialer %v, passive %v; want io.EOF on both", de, pe)
	}
	ch.end(t)
	w.shutdown()
}

// TestForwardHalfCloseClientFirst_L04 (§A7.2, plan:660): the client sends
// its request and FINs; the FIN crosses both Forwards to the target, which
// answers and FINs; the client reads every byte, then EOF; both Forwards
// end clean; nothing is reset anywhere.
func TestForwardHalfCloseClientFirst_L04(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newWorld(t, worldOpts{})
		const req, resp = 64 << 10, 256 << 10
		ch := w.chain(rendrtest.TargetHalf(resp), 0)
		if err := writePRNG(ch.client, 1, req); err != nil {
			t.Fatalf("client Write: %v", err)
		}
		if err := ch.client.CloseWrite(); err != nil {
			t.Fatalf("client CloseWrite: %v", err)
		}
		n, sum, err := readAll(ch.client)
		if err != io.EOF || n != resp || sum != prngSum(0, resp) {
			t.Fatalf("client read %d bytes (SHA ok: %v), then %v; want %d, then io.EOF", n, sum == prngSum(0, resp), err, resp)
		}
		in, out := ch.results()
		checkClean(t, "ingress", in, req, resp)
		checkClean(t, "egress", out, resp, req)
		c := checkTargetConn(t, ch.target, req, prngSum(1, req), true, false, false)
		if !c.FINOut || c.BytesOut != resp {
			t.Fatalf("target connection %+v: want its %d-byte answer and FIN out", c, resp)
		}
		endClean(t, w, ch)
	})
}

// TestForwardHalfCloseTargetFirst_L04 (§A7.2): the target sends its data
// and FINs while the client is still sending (HTTP/1.0 style); the client
// reads every byte and EOF, sends on, and FINs later; both ends clean.
func TestForwardHalfCloseTargetFirst_L04(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newWorld(t, worldOpts{})
		const gen, up1, up2 = 512 << 10, 128 << 10, 192 << 10
		ch := w.chain(rendrtest.TargetGen(gen, 3), 0)
		src := rendrtest.PRNG(1)
		if err := writeFrom(ch.client, src, up1); err != nil {
			t.Fatalf("client Write: %v", err)
		}
		n, sum, err := readAll(ch.client)
		if err != io.EOF || n != gen || sum != prngSum(3, gen) {
			t.Fatalf("client read %d bytes (SHA ok: %v), then %v; want %d, then io.EOF", n, sum == prngSum(3, gen), err, gen)
		}
		// The target's FIN arrived; the client still sends.
		if err := writeFrom(ch.client, src, up2); err != nil {
			t.Fatalf("client Write after the target's FIN: %v", err)
		}
		if err := ch.client.CloseWrite(); err != nil {
			t.Fatalf("client CloseWrite: %v", err)
		}
		in, out := ch.results()
		checkClean(t, "ingress", in, up1+up2, gen)
		checkClean(t, "egress", out, gen, up1+up2)
		checkTargetConn(t, ch.target, up1+up2, prngSum(1, up1+up2), true, false, false)
		endClean(t, w, ch)
	})
}

// TestForwardSimultaneousFIN_L05 (§A7.2): the client and the target FIN at
// the same instant; both Forwards end clean and nothing is reset.
func TestForwardSimultaneousFIN_L05(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newWorld(t, worldOpts{})
		const gen, req = 64 << 10, 16 << 10
		ch := w.chain(rendrtest.TargetGen(gen, 5), 0) // sends and FINs at once
		start := time.Now()
		if err := writePRNG(ch.client, 1, req); err != nil {
			t.Fatalf("client Write: %v", err)
		}
		if err := ch.client.CloseWrite(); err != nil {
			t.Fatalf("client CloseWrite: %v", err)
		}
		if el := time.Since(start); el != 0 {
			t.Fatalf("the client's FIN left %v after the target's; want the same instant", el)
		}
		n, sum, err := readAll(ch.client)
		if err != io.EOF || n != gen || sum != prngSum(5, gen) {
			t.Fatalf("client read %d bytes (SHA ok: %v), then %v; want %d, then io.EOF", n, sum == prngSum(5, gen), err, gen)
		}
		in, out := ch.results()
		checkClean(t, "ingress", in, req, gen)
		checkClean(t, "egress", out, gen, req)
		c := checkTargetConn(t, ch.target, req, prngSum(1, req), true, false, false)
		if !c.FINOut {
			t.Fatalf("target connection %+v: want its FIN out", c)
		}
		endClean(t, w, ch)
	})
}

// TestForwardHalfCloseAcrossMigration_L04 (§A7.2, L04): the client FINs
// while the active carrier dies with the request's tail and the FIN in
// flight; the FIN rides the replacement carrier, the target reads every
// byte and the FIN, answers, and the client reads the answer and EOF.
func TestForwardHalfCloseAcrossMigration_L04(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newWorld(t, worldOpts{links: 2, rate: 1 << 20})
		const req, resp = 256 << 10, 128 << 10
		ch := w.chain(rendrtest.TargetHalf(resp), 0)
		if err := writePRNG(ch.client, 1, req); err != nil {
			t.Fatalf("client Write: %v", err)
		}
		if err := ch.client.CloseWrite(); err != nil {
			t.Fatalf("client CloseWrite: %v", err)
		}
		synctest.Wait() // the ingress Forward took the FIN: d.CloseWrite
		l := w.activeLink(ch.d)
		if l == nil {
			t.Fatalf("no active carrier: %+v", ch.d.Status())
		}
		if got := ch.target.Counts().Conns[0]; got.FINIn || got.BytesIn == req {
			t.Fatalf("stimulus: the target already has %d bytes and FIN %v before the kill", got.BytesIn, got.FINIn)
		}
		if k := l.Kill(); k == 0 {
			t.Fatal("stimulus: the kill found no carrier")
		}
		n, sum, err := readAll(ch.client)
		if err != io.EOF || n != resp || sum != prngSum(0, resp) {
			t.Fatalf("client read %d bytes (SHA ok: %v), then %v; want %d, then io.EOF", n, sum == prngSum(0, resp), err, resp)
		}
		if m := ch.d.Status().Migrations.Death; m == 0 {
			t.Fatal("stimulus: no death migration on the dialer")
		}
		in, out := ch.results()
		checkClean(t, "ingress", in, req, resp)
		checkClean(t, "egress", out, resp, req)
		checkTargetConn(t, ch.target, req, prngSum(1, req), true, false, false)
		endClean(t, w, ch)
	})
}

// TestForwardLongHalfOpen_L30 (§A7.2): the client FINs its request; the
// target then streams 64 MiB over 5 virtual minutes in chunks 4.7 s apart
// while both ends have a 10-s idle limit: the half-open session never
// expires (bytes move), every byte arrives, both ends are clean.
func TestForwardLongHalfOpen_L30(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newWorld(t, worldOpts{})
		const req, chunks = 1 << 10, 64
		chunk := int64(1 << 20)
		if raceEnabled {
			chunk = 256 << 10
		}
		every := 5 * time.Minute / chunks
		d, p := w.open(rendr.DialOptions{})
		for _, c := range []*rendr.Conn{d, p} {
			if err := c.SetIdleTimeout(10 * time.Second); err != nil {
				t.Fatalf("SetIdleTimeout: %v", err)
			}
		}
		cli, srv := rendrtest.TargetPipe(0)
		tcli, tsrv := rendrtest.TargetPipe(0)
		in := forwardAsync(context.Background(), d, srv)
		out := forwardAsync(context.Background(), p, tcli)
		var targetErr error
		served := make(chan struct{})
		go func() { // the target: the request and FIN, then the paced stream
			defer close(served)
			n, _, err := readAll(tsrv)
			if err != io.EOF || n != req {
				targetErr = errors.New("the target did not read the request and its FIN")
				return
			}
			src := rendrtest.PRNG(9)
			for range chunks {
				time.Sleep(every)
				if err := writeFrom(tsrv, src, chunk); err != nil {
					targetErr = err
					return
				}
			}
			targetErr = tsrv.CloseWrite()
		}()
		start := time.Now()
		if err := writePRNG(cli, 1, req); err != nil {
			t.Fatalf("client Write: %v", err)
		}
		cli.CloseWrite()
		n, sum, err := readAll(cli)
		if want := chunk * chunks; err != io.EOF || n != want || sum != prngSum(9, want) {
			t.Fatalf("client read %d bytes (SHA ok: %v), then %v; want %d, then io.EOF", n, sum == prngSum(9, want), err, want)
		}
		if el := time.Since(start); el < 5*time.Minute {
			t.Fatalf("load: the stream lasted %v, want at least 5 minutes", el)
		}
		<-served
		if targetErr != nil {
			t.Fatalf("target: %v", targetErr)
		}
		checkClean(t, "ingress", <-in, req, chunk*chunks)
		checkClean(t, "egress", <-out, chunk*chunks, req)
		cli.Close()
		tsrv.Close()
		waitDone(t, d, time.Minute)
		waitDone(t, p, time.Minute)
		if de, pe := d.Status().Err, p.Status().Err; de != io.EOF || pe != io.EOF {
			t.Fatalf("session ends: dialer %v, passive %v; want io.EOF on both (no idle expiry)", de, pe)
		}
		w.shutdown()
	})
}

// TestForwardNoCloseWriteLocal (§A7.2, M4-D39): a local conn without
// CloseWrite stays open after the session's EOF, so the target still
// answers through it; it is closed (plainly) once both directions ended.
func TestForwardNoCloseWriteLocal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		w := newWorld(t, worldOpts{})
		const req, resp = 8 << 10, 64 << 10
		tg := rendrtest.NewTarget(rendrtest.TargetReqResp(req, resp), 0)
		d, p := w.open(rendr.DialOptions{})
		tc, err := tg.Dial(context.Background(), kitTarget)
		if err != nil {
			t.Fatal(err)
		}
		spy := &spyConn{Conn: tc} // no CloseWrite, no SetLinger
		out := forwardAsync(context.Background(), p, spy)
		if err := writePRNG(d, 1, req); err != nil {
			t.Fatalf("Write: %v", err)
		}
		d.CloseWrite()
		n, sum, err := readAll(d)
		if err != io.EOF || n != resp || sum != prngSum(0, resp) {
			t.Fatalf("dialer read %d bytes (SHA ok: %v), then %v; want %d, then io.EOF", n, sum == prngSum(0, resp), err, resp)
		}
		checkClean(t, "egress", <-out, resp, req)
		if dl, l0, closes, _ := spy.snapshot(); closes != 1 || l0 != 0 || len(dl) != 0 {
			t.Fatalf("local: %d Closes, %d SetLinger(0), %d deadline calls; want one plain Close", closes, l0, len(dl))
		}
		d.Close()
		waitDone(t, d, time.Minute)
		waitDone(t, p, time.Minute)
		tg.Close()
		if c := tg.Counts().Conns[0]; c.BytesIn != req || c.BytesOut != resp || c.RSTIn || c.RSTOut || c.Open {
			t.Fatalf("target connection %+v", c)
		}
		w.shutdown()
	})
}
