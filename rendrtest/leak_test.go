package rendrtest

import (
	"fmt"
	"io"
	"net"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// fakeTB records failures instead of failing the test; Fatalf ends the
// calling goroutine like testing does.
type fakeTB struct {
	testing.TB
	mu   sync.Mutex
	msgs []string
}

func (f *fakeTB) Helper() {}

func (f *fakeTB) Errorf(format string, args ...any) {
	f.mu.Lock()
	f.msgs = append(f.msgs, fmt.Sprintf(format, args...))
	f.mu.Unlock()
}

func (f *fakeTB) Fatalf(format string, args ...any) {
	f.Errorf(format, args...)
	runtime.Goexit()
}

func (f *fakeTB) failures() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.msgs, "\n")
}

var leakReport = regexp.MustCompile(`leak after (\S+): (\d+) goroutine\(s\) and (\d+) fd\(s\) not in the baseline`)

// expectLeak checks a report of exactly goroutines new goroutines whose
// stacks name the test, without the stacks of baseline goroutines.
func expectLeak(t *testing.T, msg string, goroutines int) {
	t.Helper()
	m := leakReport.FindStringSubmatch(msg)
	if m == nil {
		t.Fatalf("AssertNoLeak missed the leak: %.300s", msg)
	}
	if n, _ := strconv.Atoi(m[2]); n != goroutines {
		t.Fatalf("reported %s new goroutines, want %d: %.600s", m[2], goroutines, msg)
	}
	if !strings.Contains(msg, t.Name()[:strings.IndexByte(t.Name(), '/')]) || strings.Contains(msg, "testing.tRunner") {
		t.Fatalf("the report does not carry exactly the leaked goroutine's stack: %.600s", msg)
	}
}

// TestAssertNoLeakDetectsLeak_L66: AssertNoLeak compares goroutines by
// identity. It stays quiet when the test joined what it started — also when
// a goroutine of the baseline ended meanwhile (a count would fail) — and
// reports exactly the leaked goroutine after its full 10 s settling window
// — also when a baseline goroutine ended and the count is unchanged (a
// count would pass). The procedure runs inside bubbles without its real
// sockets and fds (design §3.8); TestAssertNoLeakRealSockets_L66 covers
// those.
func TestAssertNoLeakDetectsLeak_L66(t *testing.T) {
	inBubble := leakCheck{wait: leakWait}
	// older starts a goroutine before the baseline and returns a func that
	// ends it and waits for it.
	older := func() (end func()) {
		stop, done := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(done)
			<-stop
		}()
		return func() {
			close(stop)
			<-done
		}
	}
	t.Run("joined", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := &fakeTB{TB: t}
			check := inBubble.assert(f)
			joined := make(chan struct{})
			go func() { close(joined) }()
			<-joined
			start := time.Now()
			check()
			if msg := f.failures(); msg != "" || time.Since(start) >= leakWait {
				t.Fatalf("failed without a leak after %v: %.300s", time.Since(start), msg)
			}
		})
	})
	t.Run("baseline-goroutine-ended", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := &fakeTB{TB: t}
			end := older()
			check := inBubble.assert(f)
			end()
			start := time.Now()
			check()
			if msg := f.failures(); msg != "" || time.Since(start) >= leakWait {
				t.Fatalf("failed after a baseline goroutine ended (%v): %.300s", time.Since(start), msg)
			}
		})
	})
	t.Run("leaked", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := &fakeTB{TB: t}
			check := inBubble.assert(f)
			stop := make(chan struct{})
			go func() { <-stop }()
			start := time.Now()
			check()
			waited := time.Since(start)
			close(stop)
			expectLeak(t, f.failures(), 1)
			if waited != leakWait {
				t.Fatalf("reported after %v, want the full %v", waited, leakWait)
			}
		})
	})
	t.Run("leak-behind-an-ended-goroutine", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := &fakeTB{TB: t}
			end := older()
			check := inBubble.assert(f)
			end()
			stop := make(chan struct{})
			go func() { <-stop }() // as many goroutines as at the baseline
			check()
			close(stop)
			expectLeak(t, f.failures(), 1)
		})
	})
}

// TestAssertNoLeakRealSockets_L66: the exported AssertNoLeak on the real
// clock with its netpoll round trip and, on Linux, fd identities: a test
// that closed its loopback connections and joined its goroutines passes;
// one that leaves a goroutine and a connection behind is reported (the
// goroutine's stack, and on Linux both sockets) by the same procedure with
// a 1 s window.
func TestAssertNoLeakRealSockets_L66(t *testing.T) {
	pair := func() (net.Conn, net.Conn, net.Listener) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Listen: %v", err)
		}
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		s, err := ln.Accept()
		if err != nil {
			t.Fatalf("Accept: %v", err)
		}
		return c, s, ln
	}

	quiet := &fakeTB{TB: t}
	check := AssertNoLeak(quiet)
	c, s, ln := pair()
	var wg sync.WaitGroup
	wg.Go(func() { io.Copy(io.Discard, s) })
	c.Write([]byte("bye"))
	c.Close()
	wg.Wait()
	s.Close()
	ln.Close()
	start := time.Now()
	check()
	if msg := quiet.failures(); msg != "" || time.Since(start) >= leakWait {
		t.Fatalf("failed after everything was closed and joined (%v): %.300s", time.Since(start), msg)
	}

	leaky := &fakeTB{TB: t}
	check = leakCheck{wait: time.Second, real: true}.assert(leaky)
	stop := make(chan struct{})
	go func() { <-stop }()
	c, s, ln = pair()
	ln.Close()
	check()
	close(stop)
	c.Close()
	s.Close()
	msg := leaky.failures()
	m := leakReport.FindStringSubmatch(msg)
	if m == nil || !strings.Contains(msg, "TestAssertNoLeakRealSockets_L66.func") {
		t.Fatalf("the leaked goroutine was not reported: %.600s", msg)
	}
	if fds, _ := strconv.Atoi(m[3]); openFDs() != nil && (fds < 2 || !strings.Contains(msg, "socket:[")) {
		t.Fatalf("the two leaked sockets were not reported: %.600s", msg)
	}
}

// TestReadyBothHelper_L66: ReadyBoth waits for both ends, not the first one
// to be ready, and fails after its bound when one end never gets ready.
func TestReadyBothHelper_L66(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var a, b atomic.Bool
		go func() {
			time.Sleep(30 * time.Millisecond)
			a.Store(true)
		}()
		go func() {
			time.Sleep(120 * time.Millisecond)
			b.Store(true)
		}()
		start := time.Now()
		ReadyBoth(t, a.Load, b.Load, time.Second)
		if d := time.Since(start); d < 120*time.Millisecond || d > 120*time.Millisecond+readyPoll {
			t.Fatalf("ReadyBoth returned after %v; the later end was ready at 120ms", d)
		}

		f := &fakeTB{TB: t}
		var never atomic.Bool
		done := make(chan struct{})
		start = time.Now()
		go func() {
			defer close(done)
			ReadyBoth(f, a.Load, never.Load, 500*time.Millisecond)
		}()
		<-done
		if d, msg := time.Since(start), f.failures(); d != 500*time.Millisecond || !strings.Contains(msg, "a ready: true, b ready: false") {
			t.Fatalf("one end never ready: failed after %v with %q", d, msg)
		}

		start = time.Now()
		ReadyBoth(t, a.Load, b.Load, time.Second)
		if d := time.Since(start); d != 0 {
			t.Fatalf("both ends ready: waited %v", d)
		}
	})
}
