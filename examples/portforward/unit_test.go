package main

import (
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/FrankoonG/rendr/v2"
	"github.com/FrankoonG/rendr/v2/carrier/tcp"
	"github.com/FrankoonG/rendr/v2/carrier/udp"
	"github.com/FrankoonG/rendr/v2/l4"
)

// TestPortForwardExampleSupervise (§A9: status every 10 s; the stop within
// 5 s): in a synctest bubble, the report runs every statusEvery while the
// serves run and once after they end; a stop returns as soon as the serves
// returned, and stopWait minus closeBound after it when one of them does
// not return (the Runtimes' Close has the rest of the 5 s, and the
// client's two Runtimes close at once); a serve that fails before the stop
// ends the others and is the result, also when the stop comes while they
// end.
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
		if err := <-res; err != nil || time.Since(t0) != stopWait-closeBound {
			t.Fatalf("stop with a stuck serve: %v after %v, want nil after %v", err, time.Since(t0), stopWait-closeBound)
		}
		close(release)
		if stopWait != 5*time.Second || closeBound < 2250*time.Millisecond {
			t.Fatalf("stopWait %v, closeBound %v: want 5 s and at least Runtime.Close's 2.25 s", stopWait, closeBound)
		}

		errX := errors.New("serve failed")
		var ended atomic.Bool
		fail := func(context.Context) error { time.Sleep(time.Second); return errX }
		other := func(ctx context.Context) error { <-ctx.Done(); ended.Store(true); return ctx.Err() }
		if err := supervise(context.Background(), report, []func(context.Context) error{fail, other}); !errors.Is(err, errX) || !ended.Load() {
			t.Fatalf("a failing serve: %v (the other ended %v), want %v and the other ended", err, ended.Load(), errX)
		}
		// The stop arrives while the other serve still ends: the failure stays
		// the result.
		ctx, cancel = context.WithCancel(context.Background())
		slow := func(ctx context.Context) error { <-ctx.Done(); time.Sleep(time.Second); return ctx.Err() }
		go func() { res <- supervise(ctx, report, []func(context.Context) error{fail, slow}) }()
		time.Sleep(1500 * time.Millisecond)
		cancel()
		if err := <-res; !errors.Is(err, errX) {
			t.Fatalf("a failing serve, then a stop: %v, want %v", err, errX)
		}

		// The client's two Runtimes close at once: two Closes that each take
		// their whole bound hold the stop for one bound.
		var closed atomic.Int64
		slowClose := closerFunc(func() error { time.Sleep(closeBound); closed.Add(1); return nil })
		t0 = time.Now()
		if closeAll([]io.Closer{slowClose, slowClose}); time.Since(t0) != closeBound || closed.Load() != 2 {
			t.Fatalf("closeAll of two slow Runtimes: %v, %d closed; want %v and both", time.Since(t0), closed.Load(), closeBound)
		}
	})
}

// closerFunc is an io.Closer.
type closerFunc func() error

func (f closerFunc) Close() error { return f() }

// TestPortForwardExampleAllowHook (§A9, §A10): the server's hook refuses
// every target that is no -allow entry with ErrDenied (CodeNotAllowed),
// matching an entry in any case, refuses an allowed name's resolved
// multicast, limited broadcast or unspecified address with ErrDenied, and
// dials an allowed target as a connected datagram conn (UDP) or a TCP
// connection; with -allow-any it dials every target the same way.
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
	_, tport, _ := net.SplitHostPort(ta)
	// The literals stand for names that resolve to them: the metadata rules
	// refuse such literals before any hook runs. (An unspecified address is
	// not a row: Windows dials the loopback for it, which Control sees.)
	// The entries are in runServer's form (lower case); a request in another
	// case matches.
	dial := allowDial(map[string]bool{ua: true, ta: true, "localhost:" + tport: true, "224.0.0.1:5353": true, "255.255.255.255:9": true, "[ff02::1]:9": true}, false)
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
	for _, a := range []string{ta, "LocalHost:" + tport} {
		c, err = dial(ctx, l4.Request{Cmd: l4.CmdConnect, Addr: a})
		if err != nil {
			t.Fatalf("allowed TCP target %s: %v", a, err)
		}
		if _, ok := c.(*net.TCPConn); !ok {
			t.Fatalf("allowed TCP target %s: %T, want a *net.TCPConn", a, c)
		}
		c.Close()
	}

	// -allow-any: no entry is needed; the resolved-address rule still holds.
	dial = allowDial(nil, true)
	for _, r := range []l4.Request{{Cmd: l4.CmdUDP, Addr: ua}, {Cmd: l4.CmdConnect, Addr: ta}} {
		c, err := dial(ctx, r)
		if err != nil {
			t.Fatalf("-allow-any %+v: %v", r, err)
		}
		c.Close()
	}
	if c, err := dial(ctx, l4.Request{Cmd: l4.CmdUDP, Addr: "224.0.0.1:5353"}); !errors.Is(err, l4.ErrDenied) {
		if c != nil {
			c.Close()
		}
		t.Errorf("-allow-any to a multicast address: %v, want ErrDenied", err)
	}
}

// TestPortForwardExampleWiring (§A9, §A4.4 item 6, M6-D31): the carriers
// of both ends are loopback-only unless -carrier-insecure and carry the
// -max-datagram budget with burst-sized carrier/udp buffers; every Runtime
// has burst-sized packet queues and counts its carrier deaths; each side's
// PortForward takes -allow-nonloopback and -mode.
func TestPortForwardExampleWiring(t *testing.T) {
	for _, c := range []struct{ args, want []string }{
		{[]string{"server"}, []string{defaultRendr}},
		{[]string{"client", "-L", "udp:127.0.0.1:0=192.0.2.10:53"}, []string{defaultRendr}},
		{[]string{"server", "-rendr", "127.0.0.1:9", "-rendr", "127.0.0.1:8"}, []string{"127.0.0.1:9", "127.0.0.1:8"}},
	} {
		if o, err := parseFlags(c.args[0], c.args[1:], io.Discard); err != nil || !slices.Equal(o.rendr, c.want) {
			t.Errorf("parseFlags(%q): -rendr %q, %v; want %q", c.args, o.rendr, err, c.want)
		}
	}
	for _, o := range []options{{}, {insecure: true, maxDatagram: 1472}} {
		to, uo := carrierOptions(o)
		want := udp.Options{AllowNonLoopback: o.insecure, MaxDatagram: o.maxDatagram, ReadBuffer: 16 << 20, WriteBuffer: 4 << 20}
		if to != (tcp.Options{AllowNonLoopback: o.insecure}) || uo != want {
			t.Errorf("carrierOptions(%+v) = %+v, %+v; want AllowNonLoopback %v and %+v", o, to, uo, o.insecure, want)
		}
	}
	var d carrierDeaths
	cfg := runtimeConfig(&d)
	if cfg.Packet.Queue != 4<<20 || cfg.OnEvent == nil {
		t.Fatalf("runtimeConfig: Packet.Queue %d, OnEvent set %v; want 4 MiB and the death counter", cfg.Packet.Queue, cfg.OnEvent != nil)
	}
	cfg.OnEvent(rendr.Event{Kind: rendr.EventCarrierDown, Cause: rendr.CausePingTimeout})
	if n := d[rendr.CausePingTimeout].Load(); n != 1 {
		t.Fatalf("runtimeConfig's OnEvent counted %d deaths, want 1", n)
	}
	for _, kind := range []string{"udp", "tcp"} {
		for _, o := range []options{{rendr: []string{"127.0.0.1:1"}}, {rendr: []string{"127.0.0.1:1"}, allowNonLoopback: true, mode: rendr.ModeRace}} {
			s, err := newSide(kind, o)
			if err != nil {
				t.Fatalf("newSide(%s, %+v): %v", kind, o, err)
			}
			if s.pf.AllowNonLoopback != o.allowNonLoopback || s.pf.Options.Mode != o.mode || s.pf.Peer == nil {
				t.Errorf("newSide(%s, %+v): AllowNonLoopback %v, Mode %v; want %v, %v and a Peer", kind, o, s.pf.AllowNonLoopback, s.pf.Options.Mode, o.allowNonLoopback, o.mode)
			}
			s.rt.Close()
		}
	}
}
