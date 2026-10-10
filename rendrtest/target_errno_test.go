//go:build !plan9

package rendrtest

import (
	"context"
	"errors"
	"net"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// TestScriptedDialErrnos: the errno outcomes carry the errno this OS's net
// package returns (the WSA numbers on Windows, the syscall symbols
// elsewhere), which l4's classification reads; a real dial to a closed
// loopback port fails with the same errno as OutcomeRefuse.
func TestScriptedDialErrnos(t *testing.T) {
	want := []syscall.Errno{syscall.ECONNREFUSED, syscall.ENETUNREACH, syscall.EHOSTUNREACH}
	if runtime.GOOS == "windows" {
		want = []syscall.Errno{10061, 10051, 10065} // WSAECONNREFUSED, WSAENETUNREACH, WSAEHOSTUNREACH
	}
	dial, _ := ScriptedDial(OutcomeRefuse(), OutcomeNetUnreachable(), OutcomeHostUnreachable())
	for k, w := range want {
		_, err := dial(t.Context(), "target.test:80")
		var errno syscall.Errno
		if !errors.As(err, &errno) || errno != w {
			t.Fatalf("outcome %d: %v (errno %d); want errno %d", k, err, errno, w)
		}
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	c, err := new(net.Dialer).DialContext(ctx, "tcp", addr)
	if err == nil {
		c.Close()
		t.Fatal("a dial to a closed loopback port connected")
	}
	var real syscall.Errno
	if !errors.As(err, &real) || real != want[0] {
		t.Fatalf("real refused dial: %v (errno %d); want errno %d, as OutcomeRefuse", err, real, want[0])
	}
}
