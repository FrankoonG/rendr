//go:build unix || windows

package main

import (
	"context"
	"errors"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/l4"
)

// sockoptInt reads the SOL_SOCKET option opt of c.
func sockoptInt(t *testing.T, c syscall.Conn, opt int) int {
	t.Helper()
	rc, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v int
	var gerr error
	if err := rc.Control(func(fd uintptr) { v, gerr = getInt(syscall.GetsockoptInt, fd, opt) }); err != nil || gerr != nil {
		t.Fatalf("getsockopt %d: %v, %v", opt, err, gerr)
	}
	return v
}

// granted returns the SO_RCVBUF and SO_SNDBUF the OS reports for a fresh
// UDP socket that asked for n bytes of each (n 0: asked for nothing). The
// OS caps and may double a request (Linux), so a socket's buffers are
// compared with what the same request gets.
func granted(t *testing.T, n int) (int, int) {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if n > 0 {
		c.SetReadBuffer(n)
		c.SetWriteBuffer(n)
	}
	return sockoptInt(t, c, syscall.SO_RCVBUF), sockoptInt(t, c, syscall.SO_SNDBUF)
}

// TestPortForwardExampleSockets (§A4.4 item 6, F86, M6-D34): the client's
// UDP ingress sockets get the 8-MiB buffers the -L forward asks for; the
// server's hook, with -allow and with -allow-any, gives a UDP target's
// socket 4-MiB buffers and turns its SO_BROADCAST off (Go turns it on for
// every IPv4 UDP socket), as l4's default dialer does.
func TestPortForwardExampleSockets(t *testing.T) {
	r0, s0 := granted(t, 0)
	ri, si := granted(t, ingressBuffer)
	rb, sb := granted(t, burstBuffer)
	if ri == r0 || si == s0 || rb == r0 || sb == s0 {
		t.Fatalf("the OS grants the default buffers (%d, %d) for 8 MiB (%d, %d) or 4 MiB (%d, %d): this test cannot tell them apart", r0, s0, ri, si, rb, sb)
	}

	var mu sync.Mutex
	var ingress []*net.UDPConn
	old := listenUDP
	listenUDP = func(network string, laddr *net.UDPAddr) (*net.UDPConn, error) {
		c, err := old(network, laddr)
		if err == nil {
			mu.Lock()
			ingress = append(ingress, c)
			mu.Unlock()
		}
		return c, err
	}
	t.Cleanup(func() { listenUDP = old })
	p := start(t, "client", "-rendr", "127.0.0.1:1", "-L", "udp:127.0.0.1:0=192.0.2.10:53")
	p.out.wait(t, forwardLine, 10*time.Second) // logged after the buffers were set
	mu.Lock()
	if len(ingress) != 1 {
		t.Fatalf("%d ingress sockets, want 1", len(ingress))
	}
	if r, s := sockoptInt(t, ingress[0], syscall.SO_RCVBUF), sockoptInt(t, ingress[0], syscall.SO_SNDBUF); r != ri || s != si {
		t.Errorf("ingress buffers %d, %d; want %d, %d (8 MiB asked)", r, s, ri, si)
	}
	mu.Unlock()
	p.stop(t, "client")

	u, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	fresh, err := net.DialUDP("udp", nil, u.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if v := sockoptInt(t, fresh, syscall.SO_BROADCAST); v == 0 {
		t.Fatalf("a fresh IPv4 UDP socket has SO_BROADCAST %d: this test cannot see the hook turn it off", v)
	}
	ua := u.LocalAddr().String()
	for _, all := range []bool{false, true} {
		c, err := allowDial(map[string]bool{ua: !all}, all)(context.Background(), l4.Request{Cmd: l4.CmdUDP, Addr: ua})
		if err != nil {
			t.Fatalf("allowed UDP target (-allow-any %v): %v", all, err)
		}
		uc := c.(*net.UDPConn)
		if v := sockoptInt(t, uc, syscall.SO_BROADCAST); v != 0 {
			t.Errorf("-allow-any %v: the hook's target socket has SO_BROADCAST %d, want 0", all, v)
		}
		if r, s := sockoptInt(t, uc, syscall.SO_RCVBUF), sockoptInt(t, uc, syscall.SO_SNDBUF); r != rb || s != sb {
			t.Errorf("-allow-any %v: the hook's target buffers %d, %d; want %d, %d (4 MiB asked)", all, r, s, rb, sb)
		}
		c.Close()
	}

	// Fail closed: a socket whose SO_BROADCAST cannot be turned off is not
	// dialled; the option is an IPv4 UDP one only.
	var bad badSocket
	if err := targetControl("udp4", "127.0.0.1:9", &bad); err == nil || bad.calls != 1 {
		t.Errorf("targetControl on a socket the option cannot be set on: %v after %d calls, want an error", err, bad.calls)
	}
	bad.calls = 0
	for _, network := range []string{"udp6", "tcp4", "tcp6"} {
		if err := targetControl(network, "127.0.0.1:9", &bad); err != nil || bad.calls != 0 {
			t.Errorf("targetControl(%s): %v after %d calls, want nil without touching the socket", network, err, bad.calls)
		}
	}
}

// badSocket is a syscall.RawConn whose descriptor is no socket.
type badSocket struct{ calls int }

func (b *badSocket) Control(f func(fd uintptr)) error {
	b.calls++
	f(^uintptr(0))
	return nil
}

func (b *badSocket) Read(func(fd uintptr) bool) error  { return errors.ErrUnsupported }
func (b *badSocket) Write(func(fd uintptr) bool) error { return errors.ErrUnsupported }
