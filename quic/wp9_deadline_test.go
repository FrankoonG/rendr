package quic

import (
	"bytes"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// isDeadline reports whether err is a deadline expiry as net.Conn defines
// it: os.ErrDeadlineExceeded with Timeout() true (L06).
func isDeadline(err error) bool {
	var ne net.Error
	return errors.Is(err, os.ErrDeadlineExceeded) && errors.As(err, &ne) && ne.Timeout()
}

// TestQUICDatagramDeadlines_L06_L52: the DATAGRAM adapter's deadlines
// behave as a socket's, which the core's datagram handshakes and closer
// rely on. A read deadline fires on time; a changed deadline ends every
// blocked ReadFrom at the new time (L06), and SetReadDeadline(now) wakes
// a blocked reader (L52: SetDeadline(now) before Close); a passed
// deadline fails ReadFrom even with datagrams queued, which stay queued;
// WriteTo after its deadline fails at once and queues nothing; the zero
// value clears a deadline. A read that blocks too long closes the conn,
// so a regression cannot hang the test.
func TestQUICDatagramDeadlines_L06_L52(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	cli, srv, _ := dgramPair(t, Options{}, Options{})
	buf := make([]byte, DatagramBudget+1)
	readWithin := func(limit time.Duration) (int, error) {
		t.Helper()
		type result struct {
			n   int
			err error
		}
		ch := make(chan result, 1)
		go func() { n, _, err := srv.ReadFrom(buf); ch <- result{n, err} }()
		select {
		case r := <-ch:
			return r.n, r.err
		case <-time.After(limit):
			_ = srv.Close()
			<-ch
			t.Fatalf("ReadFrom still blocked after %v", limit)
			return 0, nil
		}
	}

	_ = srv.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	start := time.Now()
	if _, err := readWithin(5 * time.Second); !isDeadline(err) {
		t.Fatalf("ReadFrom with a 100 ms deadline: %v", err)
	}
	if d := time.Since(start); d < 80*time.Millisecond || d > 2*time.Second {
		t.Errorf("a 100 ms deadline fired after %v", d)
	}

	errs := make(chan error, 4)
	read := func() { _, _, err := srv.ReadFrom(make([]byte, 64)); errs <- err }
	collect := func(what string, k int) {
		t.Helper()
		for range k {
			select {
			case err := <-errs:
				if !isDeadline(err) {
					t.Errorf("%s: a blocked ReadFrom returned %v", what, err)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("%s: a blocked ReadFrom did not return", what)
			}
		}
	}
	_ = srv.SetReadDeadline(time.Now().Add(time.Minute))
	for range 3 {
		go read()
	}
	time.Sleep(50 * time.Millisecond) // the readers block; one that has not yet reads the new deadline itself
	start = time.Now()
	_ = srv.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	collect("a deadline shortened to 100 ms", 3)
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("the blocked readers returned %v after their deadline was shortened to 100 ms", d)
	}
	_ = srv.SetReadDeadline(time.Time{})
	go read()
	time.Sleep(50 * time.Millisecond) // the reader blocks; if it has not yet, it reads the passed deadline itself
	_ = srv.SetReadDeadline(time.Now())
	collect("SetReadDeadline(now)", 1)

	_ = srv.SetReadDeadline(time.Time{})
	for i := range 3 {
		if _, err := cli.WriteTo(seqDatagram(i, 100), nil); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "three datagrams queued", func() bool { return queued(srv) == 3 })
	_ = srv.SetReadDeadline(time.Now().Add(-time.Second))
	if n, err := readWithin(5 * time.Second); !isDeadline(err) {
		t.Errorf("ReadFrom after its deadline with datagrams queued: %d bytes, %v", n, err)
	}
	_ = srv.SetReadDeadline(time.Time{})
	for i := range 3 {
		if n, err := readWithin(5 * time.Second); err != nil || !bytes.Equal(buf[:n], seqDatagram(i, 100)) {
			t.Fatalf("queued datagram %d after the deadline was cleared: %d bytes, %v", i, n, err)
		}
	}

	_ = cli.SetWriteDeadline(time.Now().Add(-time.Second))
	if n, err := cli.WriteTo([]byte("late"), nil); n != 0 || !isDeadline(err) {
		t.Errorf("WriteTo after its deadline: %d, %v", n, err)
	}
	_ = cli.SetWriteDeadline(time.Time{})
	if _, err := cli.WriteTo([]byte("in time"), nil); err != nil {
		t.Fatal(err)
	}
	if n, err := readWithin(5 * time.Second); err != nil || string(buf[:n]) != "in time" {
		t.Errorf("the datagram after a refused WriteTo: %q, %v", buf[:n], err)
	}
}

// TestQUICDatagramClose_L52: Close unblocks a blocked ReadFrom with
// net.ErrClosed, later calls fail with net.ErrClosed, and Close returns
// only after the pump and the egress sender exited (L52; R1-9: the sender
// is joined by the conn's Close).
func TestQUICDatagramClose_L52(t *testing.T) {
	t.Cleanup(rendrtest.AssertNoLeak(t))
	cli, _, _ := dgramPair(t, Options{}, Options{})
	read := make(chan error, 1)
	go func() { _, _, err := cli.ReadFrom(make([]byte, 64)); read <- err }()
	gate, exits := make(chan struct{}), make(chan struct{}, 2)
	open := sync.OnceFunc(func() { close(gate) })
	defer open()
	cli.exitHook = func() { exits <- struct{}{}; <-gate } // holds the pump and the sender at their exit
	closed := make(chan struct{})
	go func() { _ = cli.Close(); close(closed) }()
	select {
	case err := <-read:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("a blocked ReadFrom returned %v at Close, want net.ErrClosed", err)
		}
	case <-time.After(handTimeout):
		t.Fatal("Close did not unblock a blocked ReadFrom")
	}
	for range 2 {
		select {
		case <-exits:
		case <-time.After(handTimeout):
			t.Fatal("the pump and the sender did not exit at Close")
		}
	}
	select {
	case <-closed:
		t.Fatal("Close returned before the pump and the sender exited")
	case <-time.After(50 * time.Millisecond): // Close waits in its join
	}
	open()
	select {
	case <-closed:
	case <-time.After(handTimeout):
		t.Fatal("Close did not return once the pump and the sender exited")
	}
	if _, _, err := cli.ReadFrom(make([]byte, 64)); !errors.Is(err, net.ErrClosed) {
		t.Errorf("ReadFrom after Close: %v", err)
	}
	if _, err := cli.WriteTo([]byte("x"), nil); !errors.Is(err, net.ErrClosed) {
		t.Errorf("WriteTo after Close: %v", err)
	}
}
