package rendrtest

import (
	"fmt"
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

// TestAssertNoLeakDetectsLeak_L66: AssertNoLeak stays quiet when the test
// joined what it started, and reports exactly one leaked goroutine (after
// its full 10 s settling window) when one is still running at the check.
func TestAssertNoLeakDetectsLeak_L66(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		quiet := &fakeTB{TB: t}
		check := AssertNoLeak(quiet)
		joined := make(chan struct{})
		go func() { close(joined) }()
		<-joined
		check()
		if msg := quiet.failures(); msg != "" {
			t.Fatalf("AssertNoLeak failed without a leak: %.300s", msg)
		}

		leaky := &fakeTB{TB: t}
		check = AssertNoLeak(leaky)
		stop := make(chan struct{})
		go func() { <-stop }()
		start := time.Now()
		check()
		waited := time.Since(start)
		close(stop)
		msg := leaky.failures()
		m := regexp.MustCompile(`leak after 10s: (\d+) goroutines \(baseline (\d+)\), (-?\d+) fds \(baseline (-?\d+)\)`).FindStringSubmatch(msg)
		if m == nil {
			t.Fatalf("AssertNoLeak missed the leaked goroutine: %.300s", msg)
		}
		got, _ := strconv.Atoi(m[1])
		base, _ := strconv.Atoi(m[2])
		fds, _ := strconv.Atoi(m[3])
		fdBase, _ := strconv.Atoi(m[4])
		if got != base+1 || fds != fdBase || waited < 10*time.Second {
			t.Fatalf("reported %d goroutines over baseline %d (fds %d/%d) after %v; want exactly one more after 10s", got, base, fds, fdBase, waited)
		}
		if !strings.Contains(msg, "TestAssertNoLeakDetectsLeak_L66") {
			t.Fatal("the report carries no goroutine dump")
		}
	})
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
