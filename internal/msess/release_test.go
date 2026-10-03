package msess_test

import (
	"net"
	"testing"
	"time"
)

// waitReleased waits until the server holds no session and no target
// connection; it fails the test after within.
func waitReleased(t *testing.T, f *fixture, within time.Duration) time.Duration {
	t.Helper()
	took, ok := waitFor(within, func() bool { return f.serverSessions() == 0 && f.far.open.Load() == 0 })
	if !ok {
		t.Fatalf("after %s: server sessions %d, target connections still open %d", within,
			f.serverSessions(), f.far.open.Load())
	}
	return took
}

// The user half-closes (FIN), the dialer stops waiting for the reply a
// moment later and closes. The server must drop the session and the target
// connection even though the target (stall: reads until FIN, then holds the
// socket) never answers the FIN.
func TestStalledTargetReleasedAfterClose(t *testing.T) {
	f := newFixture(t, "a")
	const n = 5
	var conns []net.Conn
	for i := 0; i < n; i++ {
		c := f.mustDial(selector, dialOpts{target: stall()})
		if _, err := c.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
			t.Fatal(err)
		}
		c.(interface{ CloseWrite() error }).CloseWrite()
		conns = append(conns, c)
	}
	time.Sleep(time.Second)
	if got := f.serverSessions(); got != n || f.far.open.Load() != n {
		t.Fatalf("sanity: %d server sessions, %d target connections, want %d", got, f.far.open.Load(), n)
	}
	for _, c := range conns {
		c.Close()
	}
	took := waitReleased(t, f, 3*tun.Linger)
	t.Logf("released %s after Close (linger budget %s)", took.Round(time.Millisecond), tun.Linger)
	if took > tun.Linger/2 {
		t.Errorf("release took %s: waited for the linger budget instead of resetting", took)
	}
}

// A connection where neither side sends anything (and nobody closes) must
// not live forever: the session's carriers answer PINGs, so only the idle
// limit ends it.
func TestIdleSessionExpires(t *testing.T) {
	f := newFixture(t, "a")
	c := f.mustDial(selector, dialOpts{target: stall()})
	c.Write([]byte("hello"))
	start := time.Now()
	stimulus(t, f.far.open.Load() == 1, "target connection not open")
	took := waitReleased(t, f, tun.StreamIdle+10*time.Second)
	t.Logf("idle session released after %s (idle limit %s)", took.Round(time.Millisecond), tun.StreamIdle)
	if took < tun.StreamIdle-time.Second {
		t.Errorf("released after %s, before the idle limit %s", took, tun.StreamIdle)
	}
	buf := make([]byte, 1)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(buf); err == nil || time.Since(start) < tun.StreamIdle {
		t.Errorf("dialer side: read err=%v after %s", err, time.Since(start))
	}
}
