package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// childEnv makes the test binary run main (TestSocks5SignalExit's
// children).
const childEnv = "RENDR_SOCKS5_TEST_MAIN"

func TestMain(m *testing.M) {
	if os.Getenv(childEnv) == "1" {
		main()
		return
	}
	os.Exit(m.Run())
}

// stopSignal is one way to stop a child.
type stopSignal struct {
	name string
	sig  os.Signal
}

// lockedBuffer is a bytes.Buffer safe for concurrent use.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// listenLine matches the address the subcommands log once they listen.
var listenLine = regexp.MustCompile(`(?:SOCKS5|rendr carriers) on (\S+)`)

// waitAddr waits up to 10 s for the listen line in out.
func waitAddr(t *testing.T, out interface{ String() string }) string {
	t.Helper()
	var addr string
	if !waitFor(10*time.Second, func() bool {
		m := listenLine.FindStringSubmatch(out.String())
		if m != nil {
			addr = m[1]
		}
		return m != nil
	}) {
		t.Fatalf("no listen line in %q", out.String())
	}
	return addr
}

// TestSocks5LoopbackOnly (M4-D44): a -listen that does not resolve to a
// loopback address exits with status 2 and names the rule; loopback
// addresses serve until ctx ends (status 0).
func TestSocks5LoopbackOnly(t *testing.T) {
	for _, l := range []string{"0.0.0.0:0", "[::]:0", ":0", "192.0.2.1:1080", "198.51.100.7:0", "[2001:db8::1]:1080"} {
		var out lockedBuffer
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		code := run(ctx, []string{"client", "-listen", l}, &out)
		cancel()
		if code != 2 || !strings.Contains(out.String(), "not a loopback address") {
			t.Errorf("-listen %s: status %d, output %q; want 2 and the loopback rule", l, code, out.String())
		}
	}
	for _, l := range []string{"127.0.0.1:0", "localhost:0"} {
		var out lockedBuffer
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan int, 1)
		go func() { done <- run(ctx, []string{"client", "-listen", l}, &out) }()
		addr := waitAddr(t, &out)
		if ap, err := net.ResolveTCPAddr("tcp", addr); err != nil || !ap.IP.IsLoopback() {
			t.Errorf("-listen %s listens on %s", l, addr)
		}
		cancel()
		if code := <-done; code != 0 {
			t.Errorf("-listen %s: status %d after ctx ended, want 0; output %q", l, code, out.String())
		}
	}
	for _, args := range [][]string{nil, {"proxy"}, {"server", "-listen", "127.0.0.1:0"}, {"server", "-rendr", "127.0.0.1:0", "-rendr", "127.0.0.1:0"}, {"client", "extra"}} {
		if code := run(context.Background(), args, io.Discard); code != 2 {
			t.Errorf("args %q: status %d, want 2", args, code)
		}
	}
}

// child is one running subcommand of the test binary.
type child struct {
	cmd  *exec.Cmd
	out  *lockedBuffer
	addr string
	done chan error
}

func startChild(t *testing.T, args ...string) *child {
	t.Helper()
	c := &child{cmd: exec.Command(os.Args[0], args...), out: &lockedBuffer{}, done: make(chan error, 1)}
	c.cmd.Env = append(os.Environ(), childEnv+"=1")
	c.cmd.Stdout, c.cmd.Stderr = c.out, c.out
	c.cmd.SysProcAttr = childAttr()
	if err := c.cmd.Start(); err != nil {
		t.Fatalf("start %q: %v", args, err)
	}
	go func() { c.done <- c.cmd.Wait() }()
	t.Cleanup(func() {
		c.cmd.Process.Kill()
		<-c.done
	})
	c.addr = waitAddr(t, c.out)
	return c
}

// TestSocks5SignalExit (R1-21): both subcommands stop on SIGTERM and
// SIGINT (Windows: CTRL_BREAK) through the shutdown path: each logs that it
// stopped after its Runtime closed, a forwarded connection is reset (on
// unix, where an exit without the reset would send a FIN; Windows resets
// the sockets of any exiting process, so there it is only closed), a
// connection still in its handshake is closed at once, both exit with
// status 0 well before the 10-s handshake deadline, and neither leaves a
// listener behind.
func TestSocks5SignalExit(t *testing.T) {
	if len(stopSignals) == 0 {
		t.Skip("this platform cannot signal a child process")
	}
	for _, sig := range stopSignals {
		t.Run(sig.name, func(t *testing.T) {
			echo, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("echo listen: %v", err)
			}
			defer echo.Close()
			go func() {
				for c, err := echo.Accept(); err == nil; c, err = echo.Accept() {
					go func() { io.Copy(c, c); c.Close() }()
				}
			}()
			srv := startChild(t, "server", "-rendr", "127.0.0.1:0")
			cli := startChild(t, "client", "-listen", "127.0.0.1:0", "-rendr", srv.addr)

			fwd, err := net.Dial("tcp", cli.addr)
			if err != nil {
				t.Fatalf("dial the SOCKS listener: %v", err)
			}
			defer fwd.Close()
			ta := echo.Addr().(*net.TCPAddr)
			q := request{cmd: cmdConnect, atyp: atypIPv4, addr: ta.IP.To4(), port: uint16(ta.Port)}
			if rep, err := socksConnect(fwd, q, []byte("ping")); err != nil || rep != repSuccess {
				t.Fatalf("CONNECT through the children: REP %d, %v (client %q, server %q)", rep, err, cli.out, srv.out)
			}
			var b [4]byte
			if _, err := io.ReadFull(fwd, b[:]); err != nil || string(b[:]) != "ping" {
				t.Fatalf("echo through the children: %q, %v", b, err)
			}
			hs, err := net.Dial("tcp", cli.addr) // holds a handshake slot
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer hs.Close()
			// The method reply proves hs is in its handshake (it holds a
			// slot and waits for the request).
			var m [2]byte
			if _, err := hs.Write(greeting); err != nil {
				t.Fatalf("greeting: %v", err)
			}
			if _, err := io.ReadFull(hs, m[:]); err != nil || !bytes.Equal(m[:], methodOK) {
				t.Fatalf("method reply % x, %v; want % x", m, err, methodOK)
			}

			start := time.Now()
			for _, c := range []*child{cli, srv} {
				if err := sendStop(c.cmd.Process, sig.sig); err != nil {
					t.Skipf("cannot deliver %s here (the test process shares no console with its child): %v", sig.name, err)
				}
			}
			for _, c := range []*child{cli, srv} {
				select {
				case err := <-c.done:
					c.done <- err
					if err != nil {
						t.Fatalf("%q exited with %v after %s; output %q", c.cmd.Args[1:], err, sig.name, c.out)
					}
				case <-time.After(5 * time.Second):
					t.Fatalf("%q still running 5 s after %s; output %q", c.cmd.Args[1:], sig.name, c.out)
				}
			}
			t.Logf("both exited %v after %s", time.Since(start), sig.name)
			for _, c := range []*child{cli, srv} {
				if line := c.cmd.Args[1] + ": stopped"; !strings.Contains(c.out.String(), line) {
					t.Fatalf("%q exited without %q (not through the shutdown path); output %q", c.cmd.Args[1:], line, c.out)
				}
			}
			for _, c := range []net.Conn{fwd, hs} {
				c.SetReadDeadline(time.Now().Add(5 * time.Second))
				_, err := bufio.NewReader(c).ReadByte()
				switch {
				case err == nil || isTimeout(err):
					t.Fatalf("a client connection after the exit: %v, want it closed", err)
				case c == fwd && stopResetsVisible && !isReset(err):
					t.Fatalf("the forwarded connection ended with %v, want a reset (Forward's AbortShutdown)", err)
				}
			}
			for _, a := range []string{cli.addr, srv.addr} {
				if c, err := net.DialTimeout("tcp", a, 5*time.Second); err == nil {
					c.Close()
					t.Fatalf("%s still accepts connections after the exit", a)
				}
			}
		})
	}
}
