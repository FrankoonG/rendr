package tcp_test

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/carrier/tcp"
	"github.com/FrankoonG/rendr/v2/internal/carrier"
)

// syscaller is a conn exposing its socket (both *carrier.OwnedTCP and
// *net.TCPConn).
type syscaller interface {
	SyscallConn() (syscall.RawConn, error)
}

// sockopt reads an integer socket option through SyscallConn.
func sockopt(t *testing.T, c syscaller, level, opt int) int {
	t.Helper()
	rc, err := c.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var v int
	var serr error
	if err := rc.Control(func(fd uintptr) { v, serr = getsockopt(fd, level, opt) }); err != nil || serr != nil {
		t.Fatalf("getsockopt(%d, %d): %v, %v", level, opt, err, serr)
	}
	return v
}

// TestTCPKeepAliveOff_L26: TCP keepalive is off on both the dialed and the
// accepted connection (a carrier's own liveness timer must never declare
// death before rendr does), TCP_NODELAY is on, and both are rendr-owned.
// A conn from Go's default dialer, which enables keepalive, reads 1 through
// the same probe: the zeros are real readings, not a broken probe.
func TestTCPKeepAliveOff_L26(t *testing.T) {
	ln, err := tcp.Listen("tcp", "127.0.0.1:0", tcp.Options{})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	var wg sync.WaitGroup
	defer wg.Wait()
	defer ln.Close()
	accepted := make(chan net.Conn, 2)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dialed, err := tcp.Carrier("loop", "tcp", ln.Addr().String(), tcp.Options{}).Dial(ctx)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer dialed.Close()
	server := <-accepted
	defer server.Close()
	for name, c := range map[string]net.Conn{"dialed": dialed, "accepted": server} {
		o, ok := c.(*carrier.OwnedTCP)
		if !ok {
			t.Fatalf("%s conn is %T, not rendr-owned", name, c)
		}
		if ka := sockopt(t, o, solSocket, soKeepAlive); ka != 0 {
			t.Errorf("%s conn: SO_KEEPALIVE = %d, want 0", name, ka)
		}
		if nd := sockopt(t, o, ipprotoTCP, tcpNoDelay); nd == 0 {
			t.Errorf("%s conn: TCP_NODELAY = 0, want on", name)
		}
	}

	ctl, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("control dial: %v", err)
	}
	defer ctl.Close()
	(<-accepted).Close()
	if ka := sockopt(t, ctl.(*net.TCPConn), solSocket, soKeepAlive); ka == 0 {
		t.Fatal("control conn with Go's default keepalive reads SO_KEEPALIVE = 0: the probe is broken")
	}

	if _, err := dialed.Write([]byte("ping")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(server, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("Read = %q, %v", buf, err)
	}
}

// TestLoopbackOnlyByDefault: without AllowNonLoopback, Listen and the
// factory refuse every non-loopback address — the unspecified addresses
// (all interfaces), broadcast, an empty host — with ErrNonLoopback before
// any socket is opened; loopback literals pass the check; AllowNonLoopback
// lifts it; other networks are not TCP.
func TestLoopbackOnlyByDefault(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	refused := []struct{ network, address string }{
		{"tcp", ":0"},
		{"tcp", net.JoinHostPort(net.IPv4zero.String(), "0")},
		{"tcp4", net.JoinHostPort(net.IPv4bcast.String(), "0")},
		{"tcp6", net.JoinHostPort(net.IPv6unspecified.String(), "0")},
	}
	for _, r := range refused {
		if ln, err := tcp.Listen(r.network, r.address, tcp.Options{}); !errors.Is(err, tcp.ErrNonLoopback) {
			if ln != nil {
				ln.Close()
			}
			t.Errorf("Listen(%s, %s) = %v, want ErrNonLoopback", r.network, r.address, err)
		}
		if c, err := tcp.Carrier("x", r.network, r.address, tcp.Options{}).Dial(ctx); !errors.Is(err, tcp.ErrNonLoopback) {
			if c != nil {
				c.Close()
			}
			t.Errorf("Dial(%s, %s) = %v, want ErrNonLoopback", r.network, r.address, err)
		}
	}
	if ln, err := tcp.Listen("udp", "127.0.0.1:0", tcp.Options{}); err == nil || errors.Is(err, tcp.ErrNonLoopback) {
		if ln != nil {
			ln.Close()
		}
		t.Errorf("Listen(udp) = %v, want an unknown-network error", err)
	}

	ln, err := tcp.Listen("tcp4", "127.0.0.1:0", tcp.Options{})
	if err != nil {
		t.Fatalf("Listen(loopback): %v", err)
	}
	defer ln.Close()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	for _, a := range []struct{ network, address string }{
		{"tcp", net.JoinHostPort("127.0.0.1", port)},
		{"tcp6", net.JoinHostPort("::1", port)},
	} {
		c, err := tcp.Carrier("x", a.network, a.address, tcp.Options{}).Dial(ctx)
		if errors.Is(err, tcp.ErrNonLoopback) {
			t.Errorf("Dial(%s, %s) refused a loopback address", a.network, a.address)
		}
		if c != nil {
			c.Close()
		}
	}
	allowed := net.JoinHostPort(net.IPv4zero.String(), port)
	c, err := tcp.Carrier("x", "tcp4", allowed, tcp.Options{AllowNonLoopback: true}).Dial(ctx)
	if errors.Is(err, tcp.ErrNonLoopback) {
		t.Errorf("AllowNonLoopback still refused %s", allowed)
	}
	if c != nil {
		c.Close()
	}
}
