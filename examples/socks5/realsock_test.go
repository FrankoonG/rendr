package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/v2/l4"
	"github.com/FrankoonG/rendr/v2/rendrtest"
)

// The real-socket rows of M4 design §A10.3: the front end on loopback TCP
// (Windows and Linux), outside synctest bubbles.

// waitFor polls cond every 5 ms for at most d.
func waitFor(d time.Duration, cond func() bool) bool {
	for end := time.Now().Add(d); ; time.Sleep(5 * time.Millisecond) {
		if cond() {
			return true
		}
		if time.Now().After(end) {
			return false
		}
	}
}

// fdCount returns this process's open file descriptors (Linux); ok is
// false elsewhere: Windows has no portable fd count (R1-27).
func fdCount() (n int, ok bool) {
	if runtime.GOOS != "linux" {
		return 0, false
	}
	names, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0, false
	}
	return len(names), true
}

// TestSocks5HandshakeBounds_L48 (M4-D46, R1-27): silent connections hold
// at most 256 handshake slots; every one beyond, and a legitimate client
// arriving while all slots are held, is closed at once; the silent ones
// are closed at the handshake deadline; then a legitimate CONNECT succeeds
// within 100 ms, and goroutines, running handshakes and (Linux) fds return
// to their baseline. 1,000 silent connections on Linux, 300 elsewhere. The
// deadline is shortened to 2 s (the production 10 s is the parser rows').
func TestSocks5HandshakeBounds_L48(t *testing.T) {
	silent := 300
	if runtime.GOOS == "linux" {
		silent = 1000
	}
	const deadline = 2 * time.Second
	s := newStack(t, stackOpts{real: true, delay: -1, hsTimeout: deadline})
	legit := func() (time.Duration, byte, error) {
		start := time.Now()
		c := s.connect()
		defer c.Close()
		rep, err := socksConnect(c, connectReq("legit.test", 80), nil)
		if err == nil && rep == repSuccess {
			if _, err = c.Write([]byte("ping")); err == nil {
				var b [4]byte
				_, err = io.ReadFull(c, b[:])
			}
		}
		return time.Since(start), rep, err
	}
	if _, rep, err := legit(); err != nil || rep != repSuccess { // warms the carrier
		t.Fatalf("warm-up CONNECT: REP %d, %v", rep, err)
	}
	waitFor(5*time.Second, func() bool { return s.target.Counts().Open == 0 })
	baseG := runtime.NumGoroutine()
	baseFD, haveFD := fdCount()

	conns := make([]net.Conn, silent)
	ended := make([]atomic.Int64, silent) // ns after start; 0 while open
	start := time.Now()
	var readers sync.WaitGroup
	for i := range conns {
		conns[i] = s.connect()
		readers.Go(func() {
			var b [1]byte
			conns[i].Read(b[:]) // returns at the close (EOF or reset): the front end sends nothing
			ended[i].Store(int64(time.Since(start)) + 1)
		})
	}
	closed := func() (n int) {
		for i := range ended {
			if ended[i].Load() != 0 {
				n++
			}
		}
		return n
	}
	if !waitFor(deadline/2, func() bool { return closed() == silent-maxHandshakes }) {
		t.Fatalf("%d of %d silent connections closed before the deadline, want %d (the cap)", closed(), silent, silent-maxHandshakes)
	}
	if h := s.front.handshakes(); h != maxHandshakes {
		t.Fatalf("%d handshakes running, want %d", h, maxHandshakes)
	}
	// A newcomer while every slot is held is closed at once.
	nc := s.connect()
	nc.SetReadDeadline(time.Now().Add(deadline / 4))
	if _, err := nc.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("a newcomer at the cap: %v, want closed at once", err)
	}
	nc.Close()
	// The silent ones end at the handshake deadline.
	if !waitFor(deadline+2*time.Second, func() bool { return closed() == silent }) {
		t.Fatalf("%d of %d silent connections closed %v after the deadline", closed(), silent, time.Since(start)-deadline)
	}
	early := 0
	for i := range ended {
		if time.Duration(ended[i].Load()) < deadline-100*time.Millisecond {
			early++
		}
	}
	if early != silent-maxHandshakes {
		t.Fatalf("%d connections closed before the deadline, want %d", early, silent-maxHandshakes)
	}
	readers.Wait()
	for _, c := range conns {
		c.Close()
	}
	if !waitFor(time.Second, func() bool { return s.front.handshakes() == 0 }) {
		t.Fatalf("%d handshakes still running after the deadline", s.front.handshakes())
	}
	if el, rep, err := legit(); err != nil || rep != repSuccess || el > 100*time.Millisecond {
		t.Fatalf("legitimate CONNECT after the flood: REP %d, %v, in %v (want success within 100 ms)", rep, err, el)
	}
	if !waitFor(10*time.Second, func() bool { return runtime.NumGoroutine() <= baseG+2 }) {
		t.Fatalf("goroutines: %d, baseline %d", runtime.NumGoroutine(), baseG)
	}
	if haveFD && !waitFor(10*time.Second, func() bool { n, _ := fdCount(); return n <= baseFD }) {
		n, _ := fdCount()
		t.Fatalf("fds: %d, baseline %d", n, baseFD)
	}
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

// TestSocks5FailureReplySurvivesOptimisticData_L05 (L05, R1-13): a client
// sends its request and 32 KiB more in one write; the failure reply — a
// refused target (REP 05), BIND (REP 07), a bad ATYP (REP 08), no
// acceptable method (05 FF) — always reaches it, followed by a clean end,
// never a reset. 200 runs of each row on loopback TCP.
func TestSocks5FailureReplySurvivesOptimisticData_L05(t *testing.T) {
	s := newStack(t, stackOpts{real: true, delay: -1, n: 16, dial: func(ctx context.Context, r l4.Request) (net.Conn, error) {
		d, _ := rendrtest.ScriptedDial(rendrtest.OutcomeRefuse())
		return d(ctx, r.Addr)
	}})
	extra := bytes.Repeat([]byte{0x5a}, 32<<10)
	withGreeting := func(b []byte) []byte { return append(append(append([]byte(nil), greeting...), b...), extra...) }
	rows := []struct {
		name      string
		msg, want []byte
	}{
		{"refused", withGreeting(appendRequest(nil, connectReq("refused.test", 80))), append(append([]byte(nil), methodOK...), reply(repRefused)...)},
		{"bind", withGreeting(appendRequest(nil, request{cmd: 2, atyp: atypIPv4, addr: []byte{192, 0, 2, 1}, port: 80})), append(append([]byte(nil), methodOK...), reply(repBadCommand)...)},
		{"bad atyp", withGreeting([]byte{socksVersion, cmdConnect, 0, 5}), append(append([]byte(nil), methodOK...), reply(repBadAddress)...)},
		{"no method", append([]byte{socksVersion, 1, 0x02}, extra...), []byte{socksVersion, methodNone}},
	}
	const runs, par = 200, 8
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			var wg sync.WaitGroup
			var failed atomic.Int64
			sem := make(chan struct{}, par)
			for i := range runs {
				sem <- struct{}{}
				wg.Go(func() {
					defer func() { <-sem }()
					c := s.connect()
					defer c.Close()
					c.SetDeadline(time.Now().Add(10 * time.Second))
					if _, err := c.Write(r.msg); err != nil {
						failed.Add(1)
						t.Errorf("run %d: write: %v", i, err)
						return
					}
					got, err := io.ReadAll(c)
					if !bytes.Equal(got, r.want) || err != nil {
						failed.Add(1)
						t.Errorf("run %d: read % x then %v; want % x then the clean end", i, got, err, r.want)
					}
				})
			}
			wg.Wait()
			if n := failed.Load(); n > 0 {
				t.Fatalf("%d of %d runs lost the reply or ended with a reset", n, runs)
			}
		})
	}
}
