//go:build unix || windows

package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"runtime"
	"strings"
	"testing"
	"time"
)

// reportScale is how much more than it grants the OS reports for a socket
// buffer (Linux doubles it).
func reportScale() int {
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		return 2
	}
	return 1
}

// stubGrant makes the OS grant every UDP socket at most limit bytes of
// each buffer (as it reports them) for the rest of the test.
func stubGrant(t *testing.T, limit int) {
	old := grantedBuffers
	grantedBuffers = func(n int) (int, int, error) {
		g := min(n, limit) * reportScale()
		return g, g, nil
	}
	t.Cleanup(func() { grantedBuffers = old })
}

// TestPortForwardExampleBufferWarning (§A4.4 item 6, F86): when the OS
// grants the UDP sockets less buffer than a subcommand asks for (a default
// Linux host: net.core.rmem_max and wmem_max are 212,992 bytes), the
// subcommand logs one warning at its start naming the granted and the
// requested sizes and the sysctls to raise: the server for its target
// sockets (with -udp only), the client for its ingress sockets (with a UDP
// forward only). A full grant, or a probe that fails, logs nothing. With
// the real OS, Windows grants every request (nothing logged); elsewhere
// the warning appears exactly when the OS reports less than it was asked
// for.
func TestPortForwardExampleBufferWarning(t *testing.T) {
	const linuxDefault = 212992
	t.Run("check", func(t *testing.T) {
		for _, r := range []struct {
			name     string
			rcv, snd int // the grant limits
			err      error
			want     bool
		}{
			{"capped", linuxDefault, linuxDefault, nil, true},
			{"send capped", burstBuffer, linuxDefault, nil, true},
			{"receive capped", linuxDefault, burstBuffer, nil, true},
			{"granted", burstBuffer, burstBuffer, nil, false},
			{"probe failed", 0, 0, errors.New("no loopback"), false},
		} {
			old := grantedBuffers
			grantedBuffers = func(n int) (int, int, error) {
				return min(n, r.rcv) * reportScale(), min(n, r.snd) * reportScale(), r.err
			}
			var out bytes.Buffer
			checkBuffers(log.New(&out, "", 0), "server", "target", burstBuffer)
			grantedBuffers = old
			want := fmt.Sprintf("server: warning: UDP target sockets get %d bytes of receive and %d of send buffer, not the %d asked for; bursts beyond them are lost (on Linux raise net.core.rmem_max and net.core.wmem_max)\n",
				r.rcv, r.snd, burstBuffer)
			if got := out.String(); (r.want && got != want) || (!r.want && got != "") {
				t.Errorf("%s: logged %q, want %v", r.name, got, r.want)
			}
		}
	})
	t.Run("subcommands", func(t *testing.T) {
		stubGrant(t, linuxDefault)
		warning := func(sub, kind string) string { return sub + ": warning: UDP " + kind + " sockets get 212992 bytes" }
		srv := start(t, "server", "-rendr", "127.0.0.1:0", "-udp")
		srv.out.wait(t, serverLine, 10*time.Second) // logged after the check
		srv.stop(t, "server")
		quiet := start(t, "server", "-rendr", "127.0.0.1:0")
		quiet.out.wait(t, serverLine, 10*time.Second)
		quiet.stop(t, "server")
		cli := start(t, "client", "-rendr", "127.0.0.1:1", "-L", "udp:127.0.0.1:0=192.0.2.10:53")
		cli.out.wait(t, forwardLine, 10*time.Second) // logged after the check
		cli.stop(t, "client")
		tcpOnly := start(t, "client", "-rendr", "127.0.0.1:1", "-L", "tcp:127.0.0.1:0=192.0.2.10:80")
		tcpOnly.out.wait(t, forwardLine, 10*time.Second)
		tcpOnly.stop(t, "client")
		for _, r := range []struct {
			name, out, line string
			n               int
		}{
			{"server -udp", srv.out.String(), warning("server", "target"), 1},
			{"server without -udp", quiet.out.String(), "warning", 0},
			{"client with a UDP forward", cli.out.String(), warning("client", "ingress"), 1},
			{"client with TCP forwards only", tcpOnly.out.String(), "warning", 0},
		} {
			if n := strings.Count(r.out, r.line); n != r.n {
				t.Errorf("%s: %d lines with %q, want %d; output %q", r.name, n, r.line, r.n, r.out)
			}
		}
	})
	t.Run("real", func(t *testing.T) {
		var out bytes.Buffer
		checkBuffers(log.New(&out, "", 0), "server", "target", burstBuffer)
		r, s := granted(t, burstBuffer)
		capped := r < reportScale()*burstBuffer || s < reportScale()*burstBuffer
		if runtime.GOOS == "windows" && capped {
			t.Fatalf("premise: Windows granted %d, %d for %d", r, s, burstBuffer)
		}
		if got := out.String() != ""; got != capped {
			t.Fatalf("the OS reports %d, %d for %d bytes asked (capped %v); logged %q", r, s, burstBuffer, capped, out.String())
		}
		t.Logf("the OS reports %d, %d for %d bytes asked; logged %q", r, s, burstBuffer, out.String())
	})
}
