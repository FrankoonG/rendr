package main

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/internal/testhooks"
	"github.com/FrankoonG/rendr/v2/l4"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestSocks5Smoke_CL is the SOCKS5 row of the checkpoint C-L smoke (M4
// design §A15.3 row I1; l4's TestL4Smoke_CL is the rest): one SOCKS5
// CONNECT through the example's front end, a 1-MiB request half-closed by
// the client and a 4-MiB answer from a target that reads to EOF first,
// over two Links while the Link carrying the session is killed during the
// request and again during the answer. Stimulus: both kills ended a
// carrier while bytes were moving (the client had written 512 KiB of the
// request; it had read 2 MiB of the answer) and the session counts two
// death migrations. Load and integrity: the target read every request
// byte (SHA-256) and then the client's FIN; the client read every answer
// byte (SHA-256), then io.EOF. Afterwards the front end, the Server, the
// Peer and both Runtimes are shut down and nothing is left: no Server
// handler, no target connection, no session or buffered byte in either
// Runtime, the session registry back at its start, and no goroutine (the
// bubble ends only when every goroutine of it exited).
func TestSocks5Smoke_CL(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const req, resp = 1 << 20, 4 << 20
		live0, parked0 := testhooks.LiveSessions.Load(), testhooks.ParkedSessions.Load()
		target := rendrtest.NewTarget(rendrtest.TargetHalf(resp), 0)
		s := newStack(t, stackOpts{links: 2, rate: 8 << 20, dial: func(ctx context.Context, q l4.Request) (net.Conn, error) {
			return target.Dial(ctx, q.Addr)
		}})
		c := s.connect().(*rendrtest.TargetConn)
		if rep, err := socksConnect(c, connectReq("smoke.test", 443), nil); err != nil || rep != repSuccess {
			t.Fatalf("CONNECT: REP %d, %v", rep, err)
		}
		kill := func(what string) {
			t.Helper()
			l := s.activeLink(s.conn(0))
			if l == nil {
				t.Fatalf("%s: no active carrier: %+v", what, s.conn(0).Status())
			}
			if l.Kill() == 0 {
				t.Fatalf("stimulus: the kill %s ended no carrier", what)
			}
		}
		var wrote atomic.Int64
		werr := make(chan error, 1)
		go func() {
			err := writePRNG(clCountingWriter{c, &wrote}, 1, req)
			if err == nil {
				err = c.CloseWrite()
			}
			werr <- err
		}()
		for wrote.Load() < 512<<10 {
			time.Sleep(time.Millisecond)
		}
		kill("during the request")
		pr := &progressReader{r: c}
		type result struct {
			n   int64
			sum [32]byte
			err error
		}
		done := make(chan result, 1)
		go func() {
			k, sum, err := readAll(pr)
			done <- result{k, sum, err}
		}()
		for pr.n.Load() < 2<<20 {
			time.Sleep(time.Millisecond)
		}
		kill("during the answer")
		res := <-done
		if err := <-werr; err != nil {
			t.Fatalf("client write: %v", err)
		}
		if res.err != io.EOF || res.n != resp || res.sum != prngSum(0, resp) {
			t.Fatalf("client read %d bytes (SHA ok %v), then %v; want %d, then io.EOF", res.n, res.sum == prngSum(0, resp), res.err, resp)
		}
		tc := target.Counts().Conns[0]
		if tc.BytesIn != req || tc.SHAIn != prngSum(1, req) || !tc.FINIn || tc.RSTIn || tc.RSTOut {
			t.Fatalf("target connection %+v; want %d intact bytes, the FIN, no reset", tc, req)
		}
		if m := s.conn(0).Status().Migrations.Death; m < 2 {
			t.Fatalf("stimulus: %d death migrations after 2 kills: %+v", m, s.conn(0).Status())
		}
		c.Close()
		// The session ends cleanly (DONE both ways); then everything is
		// shut down.
		select {
		case <-s.conn(0).Done():
		case <-time.After(time.Minute):
			t.Fatalf("the session did not end: %+v", s.conn(0).Status())
		}
		s.shutdown()
		synctest.Wait()
		if st := s.srv.Status(); st.Dialing != 0 || st.Live != 0 || st.Hooks != 0 || st.Abandoned != 0 || st.Confirmed != 1 || st.Rejected != 0 {
			t.Errorf("Server after the shutdown: %+v", st)
		}
		if tg := target.Counts(); tg.Accepted != 1 || tg.Open != 0 {
			t.Errorf("target after the shutdown: accepted %d, open %d", tg.Accepted, tg.Open)
		}
		target.Close()
		for _, rt := range []*rendr.Runtime{s.d, s.p} {
			st := rt.Status()
			sc := st.Sessions
			if sc.Open+sc.Pending+sc.Lingering+sc.Orphaned != 0 || st.Handshakes != 0 || st.Sessionless != 0 || st.Actors != 0 ||
				st.BufferedBytes != 0 || st.Abandoned != 0 {
				t.Errorf("state left after Runtime.Close: %+v", st)
			}
		}
		if l, p := testhooks.LiveSessions.Load()-live0, testhooks.ParkedSessions.Load()-parked0; l != 0 || p != 0 {
			t.Errorf("session registry after Runtime.Close: %+d live, %+d parked", l, p)
		}
	})
}

// clCountingWriter counts the bytes written through it.
type clCountingWriter struct {
	w io.Writer
	n *atomic.Int64
}

func (c clCountingWriter) Write(b []byte) (int, error) {
	k, err := c.w.Write(b)
	c.n.Add(int64(k))
	return k, err
}
