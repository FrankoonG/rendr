package main

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2/l4"
)

// TestPortForwardExampleSupervise (§A9: status every 10 s; the stop waits
// at most 5 s): in a synctest bubble, the report runs every statusEvery
// while the serves run and once after they end; a stop returns as soon as
// the serves returned, and at stopWait after it when one of them does not
// return; a serve that fails before the stop ends the others and is the
// result.
func TestPortForwardExampleSupervise(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var reports atomic.Int64
		report := func() { reports.Add(1) }
		waitCtx := func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }

		ctx, cancel := context.WithCancel(context.Background())
		res := make(chan error, 1)
		t0 := time.Now()
		go func() { res <- supervise(ctx, report, []func(context.Context) error{waitCtx, waitCtx}) }()
		time.Sleep(35 * time.Second)
		synctest.Wait()
		if n := reports.Load(); n != 3 {
			t.Fatalf("%d reports in 35 s, want 3 (every %v)", n, statusEvery)
		}
		cancel()
		if err := <-res; err != nil || time.Since(t0) != 35*time.Second || reports.Load() != 4 {
			t.Fatalf("stop: %v after %v with %d reports, want nil at once and a final report", err, time.Since(t0), reports.Load())
		}

		release := make(chan struct{})
		stuck := func(context.Context) error { <-release; return nil }
		ctx, cancel = context.WithCancel(context.Background())
		go func() { res <- supervise(ctx, report, []func(context.Context) error{waitCtx, stuck}) }()
		synctest.Wait()
		t0 = time.Now()
		cancel()
		if err := <-res; err != nil || time.Since(t0) != stopWait {
			t.Fatalf("stop with a stuck serve: %v after %v, want nil after %v", err, time.Since(t0), stopWait)
		}
		close(release)

		errX := errors.New("serve failed")
		var ended atomic.Bool
		fail := func(context.Context) error { time.Sleep(time.Second); return errX }
		other := func(ctx context.Context) error { <-ctx.Done(); ended.Store(true); return ctx.Err() }
		if err := supervise(context.Background(), report, []func(context.Context) error{fail, other}); !errors.Is(err, errX) || !ended.Load() {
			t.Fatalf("a failing serve: %v (the other ended %v), want %v and the other ended", err, ended.Load(), errX)
		}
	})
}

// TestPortForwardExampleAllowHook (§A9, §A10): the server's hook refuses
// every target that is no -allow entry with ErrDenied (CodeNotAllowed),
// refuses an allowed name's resolved multicast, limited broadcast or
// unspecified address with ErrDenied, and dials an allowed target as a
// connected datagram conn (UDP) or a TCP connection.
func TestPortForwardExampleAllowHook(t *testing.T) {
	u, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ua, ta := u.LocalAddr().String(), ln.Addr().String()
	// The literals stand for names that resolve to them: the metadata rules
	// refuse such literals before any hook runs. (An unspecified address is
	// not a row: Windows dials the loopback for it, which Control sees.)
	dial := allowDial(map[string]bool{ua: true, ta: true, "224.0.0.1:5353": true, "255.255.255.255:9": true, "[ff02::1]:9": true})
	ctx := context.Background()
	for _, r := range []l4.Request{{Cmd: l4.CmdUDP, Addr: "127.0.0.1:1"}, {Cmd: l4.CmdConnect, Addr: "127.0.0.1:1"}} {
		if c, err := dial(ctx, r); !errors.Is(err, l4.ErrDenied) {
			if c != nil {
				c.Close()
			}
			t.Errorf("%+v: %v, want ErrDenied (not an -allow entry)", r, err)
		}
	}
	for _, a := range []string{"224.0.0.1:5353", "255.255.255.255:9", "[ff02::1]:9"} {
		if c, err := dial(ctx, l4.Request{Cmd: l4.CmdUDP, Addr: a}); !errors.Is(err, l4.ErrDenied) {
			if c != nil {
				c.Close()
			}
			t.Errorf("allowed %s resolved: %v, want ErrDenied", a, err)
		}
	}
	c, err := dial(ctx, l4.Request{Cmd: l4.CmdUDP, Addr: ua})
	if err != nil {
		t.Fatalf("allowed UDP target: %v", err)
	}
	if uc, ok := c.(*net.UDPConn); !ok || uc.RemoteAddr().String() != ua {
		t.Fatalf("allowed UDP target: %T to %v, want a *net.UDPConn connected to %s", c, c.RemoteAddr(), ua)
	}
	c.Close()
	c, err = dial(ctx, l4.Request{Cmd: l4.CmdConnect, Addr: ta})
	if err != nil {
		t.Fatalf("allowed TCP target: %v", err)
	}
	if _, ok := c.(*net.TCPConn); !ok {
		t.Fatalf("allowed TCP target: %T, want a *net.TCPConn", c)
	}
	c.Close()
}
