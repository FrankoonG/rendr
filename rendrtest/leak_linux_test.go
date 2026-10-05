package rendrtest

import (
	"io"
	"net"
	"strings"
	"testing"
)

// TestAssertNoLeakSplicePipes_L66: io.Copy between two TCP connections
// splices through a pipe pair from Go's pool on Linux, and that pair stays
// open after the copy until garbage collection drops it from the pool. The
// check must not report it: it collects garbage before every sample. The
// test first proves that the copy left a pipe pair the baseline did not
// have (the stimulus), then that the check passes.
func TestAssertNoLeakSplicePipes_L66(t *testing.T) {
	check := AssertNoLeak(t)
	base := openFDs()

	pair := func() (net.Conn, *net.TCPConn) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		s, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		return c, s.(*net.TCPConn)
	}
	srcW, src := pair() // srcW writes into src
	dst, dstR := pair() // dst's bytes arrive at dstR
	defer srcW.Close()
	defer src.Close()
	defer dst.Close()
	defer dstR.Close()

	const n = 1 << 20
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(dst.(*net.TCPConn), src) // TCP to TCP: splice(2)
		done <- err
	}()
	go func() {
		srcW.Write(make([]byte, n))
		srcW.Close()
	}()
	if got, err := io.Copy(io.Discard, io.LimitReader(dstR, n)); err != nil || got != n {
		t.Fatalf("relayed %d bytes (%v), want %d", got, err, n)
	}
	if err := <-done; err != nil {
		t.Fatalf("io.Copy: %v", err)
	}

	pipes := 0
	for fd := range openFDs() {
		if !base[fd] && strings.Contains(fd, "pipe:") {
			pipes++
		}
	}
	if pipes == 0 {
		t.Fatal("stimulus missing: io.Copy between TCP connections left no pooled splice pipe")
	}
	t.Logf("io.Copy left %d pooled pipe fd(s)", pipes)

	srcW.Close()
	src.Close()
	dst.Close()
	dstR.Close()
	check()
}
