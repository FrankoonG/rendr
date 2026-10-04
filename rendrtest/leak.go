package rendrtest

import (
	"net"
	"runtime"
	"testing"
	"time"
)

const (
	leakWait     = 10 * time.Second
	leakInterval = 100 * time.Millisecond
	leakSamples  = 3
	readyPoll    = 5 * time.Millisecond
)

// leakSample is one observation: goroutines and open fds (-1 where fds are
// not counted).
type leakSample struct{ g, fd int }

func sampleLeak() leakSample { return leakSample{runtime.NumGoroutine(), openFDs()} }

// AssertNoLeak records a settled goroutine baseline (and the open-fd count
// on Linux) and returns a check to defer (L66). The caller must have joined
// everything it started before the check runs; the check then forces a
// netpoll round trip and waits (at most 10 s) until three consecutive
// samples 100 ms apart equal the baseline (unit layer: zero growth), else
// it fails t with a full goroutine dump. Inside a synctest bubble the
// bubble's own leak check makes it unnecessary.
func AssertNoLeak(t testing.TB) (check func()) {
	t.Helper()
	netpollRoundTrip()
	base := settle()
	return func() {
		t.Helper()
		netpollRoundTrip()
		deadline := time.Now().Add(leakWait)
		var cur leakSample
		for same := 0; ; {
			if cur = sampleLeak(); cur == base {
				if same++; same == leakSamples {
					return
				}
			} else {
				same = 0
			}
			if !time.Now().Before(deadline) {
				break
			}
			time.Sleep(leakInterval)
		}
		buf := make([]byte, 1<<20)
		buf = buf[:runtime.Stack(buf, true)]
		t.Errorf("rendrtest: leak after %v: %d goroutines (baseline %d), %d fds (baseline %d)\n%s",
			leakWait, cur.g, base.g, cur.fd, base.fd, buf)
	}
}

// settle returns the first value seen in three consecutive samples 100 ms
// apart (or the last sample after leakWait).
func settle() leakSample {
	deadline := time.Now().Add(leakWait)
	last, same := sampleLeak(), 1
	for same < leakSamples && time.Now().Before(deadline) {
		time.Sleep(leakInterval)
		if cur := sampleLeak(); cur == last {
			same++
		} else {
			last, same = cur, 1
		}
	}
	return last
}

// netpollRoundTrip moves one byte through a loopback TCP pair, so that the
// runtime's poller has run since the caller closed its connections (their
// parked readers are woken and gone before sampling).
func netpollRoundTrip() {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return
	}
	defer ln.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		return
	}
	defer c.Close()
	s, err := ln.Accept()
	if err != nil {
		return
	}
	defer s.Close()
	if _, err := c.Write([]byte{1}); err == nil {
		s.Read(make([]byte, 1))
	}
}

// ReadyBoth waits until both a() and b() hold (L66: readiness waits for both
// ends), failing t after within.
func ReadyBoth(t testing.TB, a, b func() bool, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		ra, rb := a(), b()
		if ra && rb {
			return
		}
		left := time.Until(deadline)
		if left <= 0 {
			t.Fatalf("rendrtest: ReadyBoth: not ready after %v (a ready: %v, b ready: %v)", within, ra, rb)
			return
		}
		time.Sleep(min(readyPoll, left))
	}
}
