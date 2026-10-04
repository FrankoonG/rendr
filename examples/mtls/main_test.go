package main

import (
	"bytes"
	"testing"

	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// TestRunEchoesOverMutualTLS (design §0.8 V17): the example end to end on
// real loopback sockets — two Runtimes, carrier/tcp wrapped in mutually
// authenticated TLS 1.3, one selector session through the passive's
// Listener.Handle — echoes a 1 MiB message intact, ends both sessions
// through the example's own CloseWrite/EOF/Close sequence and leaves no
// goroutine behind once run returned (both Runtimes and the TLS server
// were closed and joined).
func TestRunEchoesOverMutualTLS(t *testing.T) {
	check := rendrtest.AssertNoLeak(t)
	p, err := newPKI()
	if err != nil {
		t.Fatalf("newPKI: %v", err)
	}
	line := []byte("rendr over mutually authenticated TLS carriers\n")
	msg := bytes.Repeat(line, (1<<20)/len(line)+1)[:1<<20]
	got, err := run(p, msg)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echoed %d bytes, sent %d (equal prefix %d)", len(got), len(msg), commonPrefix(got, msg))
	}
	check()
}

// commonPrefix returns the length of the longest common prefix of a and b.
func commonPrefix(a, b []byte) int {
	n := 0
	for n < len(a) && n < len(b) && a[n] == b[n] {
		n++
	}
	return n
}
