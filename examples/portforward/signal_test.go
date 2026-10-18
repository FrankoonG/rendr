package main

import (
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// stopSignal is one way to stop a child.
type stopSignal struct {
	name string
	sig  os.Signal
}

// child is one subcommand run as a process of the test binary.
type child struct {
	cmd  *exec.Cmd
	out  *output
	done chan error
}

func startChild(t *testing.T, args ...string) *child {
	t.Helper()
	c := &child{cmd: exec.Command(os.Args[0], args...), out: newOutput(), done: make(chan error, 1)}
	c.cmd.Env = append(os.Environ(), childEnv+"=1")
	c.cmd.Stdout, c.cmd.Stderr = c.out, c.out
	c.cmd.SysProcAttr = childAttr()
	if err := c.cmd.Start(); err != nil {
		t.Fatalf("start %q: %v", args, err)
	}
	go func() { c.done <- c.cmd.Wait() }()
	t.Cleanup(func() {
		c.cmd.Process.Kill()
		c.done <- <-c.done
	})
	return c
}

// TestPortForwardExampleSignalExit (M6-D31, §A9): both subcommands stop on
// SIGTERM and SIGINT (Windows: CTRL_BREAK) through the shutdown path with
// a UDP flow and a TCP connection live: each logs that it stopped after
// its Runtime closed and exits with status 0 within the 5-s stop bound
// (when both ends stop at once, the server's Runtime.Close may wait its
// 1-s close bound for a client already gone), the forwarded TCP
// connection is reset (where an exit without the reset would send a FIN),
// and no socket is left: the ingress and carrier addresses bind again
// (UDP) and refuse connections (TCP).
func TestPortForwardExampleSignalExit(t *testing.T) {
	if len(stopSignals) == 0 {
		t.Skip("this platform cannot signal a child process")
	}
	for _, sig := range stopSignals {
		t.Run(sig.name, func(t *testing.T) {
			ut, tt := newUDPTarget(t), newTCPTarget(t)
			srv := startChild(t, "server", "-rendr", "127.0.0.1:0", "-udp", "-allow", ut.addr(), "-allow", tt.addr())
			rendrAddr := srv.out.wait(t, serverLine, 10*time.Second)[1]
			cli := startChild(t, "client", "-rendr", rendrAddr, "-L", "udp:127.0.0.1:0="+ut.addr(), "-L", "tcp:127.0.0.1:0="+tt.addr())
			local := map[string]string{}
			for _, m := range cli.out.waitN(t, forwardLine, 2, 10*time.Second) {
				local[m[1]] = m[2]
			}
			c := dialClient(t, local["udp"])
			for range 20 {
				c.roundTrip(t, 512)
			}
			fwd, err := net.Dial("tcp", local["tcp"])
			if err != nil {
				t.Fatalf("dial the TCP ingress: %v", err)
			}
			defer fwd.Close()
			fwd.SetDeadline(time.Now().Add(10 * time.Second))
			var b [4]byte
			if _, err := fwd.Write([]byte("ping")); err != nil {
				t.Fatalf("TCP write: %v", err)
			}
			if _, err := io.ReadFull(fwd, b[:]); err != nil || string(b[:]) != "ping" {
				t.Fatalf("TCP echo through the children: %q, %v", b, err)
			}

			start := time.Now()
			for _, ch := range []*child{cli, srv} {
				if err := sendStop(ch.cmd.Process, sig.sig); err != nil {
					t.Skipf("cannot deliver %s here (the test process shares no console with its child): %v", sig.name, err)
				}
			}
			for _, ch := range []*child{cli, srv} {
				select {
				case err := <-ch.done:
					ch.done <- err
					if err != nil {
						t.Fatalf("%q exited with %v after %s; output %q", ch.cmd.Args[1:], err, sig.name, ch.out)
					}
				case <-time.After(stopWait - time.Since(start)):
					t.Fatalf("%q still running %v after %s; output %q", ch.cmd.Args[1:], stopWait, sig.name, ch.out)
				}
				if line := ch.cmd.Args[1] + ": stopped"; !strings.Contains(ch.out.String(), line) {
					t.Fatalf("%q exited without %q (not through the shutdown path); output %q", ch.cmd.Args[1:], line, ch.out)
				}
			}
			t.Logf("both exited %v after %s", time.Since(start), sig.name)
			_, err = fwd.Read(b[:])
			var ne net.Error
			switch {
			case err == nil || (errors.As(err, &ne) && ne.Timeout()):
				t.Fatalf("the forwarded connection after the exit: %v, want its end", err)
			case stopResetsVisible && !errors.Is(err, errConnReset):
				t.Fatalf("the forwarded connection ended with %v, want a reset (ServeTCP's shutdown)", err)
			}
			for _, a := range []string{local["udp"], rendrAddr} {
				u, err := net.ListenPacket("udp", a)
				if err != nil {
					t.Fatalf("UDP %s still bound after the exit: %v", a, err)
				}
				u.Close()
			}
			for _, a := range []string{local["tcp"], rendrAddr} {
				if c, err := net.DialTimeout("tcp", a, 5*time.Second); err == nil {
					c.Close()
					t.Fatalf("TCP %s still accepts connections after the exit", a)
				}
			}
		})
	}
}
