package rendrtest

import (
	"net"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	leakWait     = 10 * time.Second
	leakInterval = 100 * time.Millisecond
	leakSamples  = 3
	readyPoll    = 5 * time.Millisecond
)

// AssertNoLeak records a settled baseline of the live goroutines — by
// identity — and, on Linux, of the open file descriptors, and returns a
// check to defer (L66). The caller must have joined everything it started
// before the check runs; the check then forces a netpoll round trip and
// waits (at most 10 s) until three consecutive samples 100 ms apart show no
// goroutine and no fd that was not in the baseline (unit layer: zero
// growth). Baseline goroutines and fds may end meanwhile without hiding a
// new one. On failure t gets the stacks of the new goroutines and the new
// fds only.
//
// It is meant for real-time tests outside synctest bubbles (a bubble checks
// its own goroutines). It cannot be used with t.Parallel: goroutines of
// tests running in parallel would count as leaks.
func AssertNoLeak(t testing.TB) (check func()) {
	t.Helper()
	return leakCheck{wait: leakWait, real: true}.assert(t)
}

// leakCheck is AssertNoLeak's procedure. Its self-tests run it inside
// synctest bubbles with real false: no sockets (the netpoll round trip) and
// no fds there (design §3.8).
type leakCheck struct {
	wait time.Duration
	real bool
}

func (lc leakCheck) assert(t testing.TB) (check func()) {
	t.Helper()
	if lc.real {
		netpollRoundTrip()
	}
	base := lc.settle()
	return func() {
		t.Helper()
		if lc.real {
			netpollRoundTrip()
		}
		deadline := time.Now().Add(lc.wait)
		var gs, fds []string
		for clean := 0; ; {
			if gs, fds = leaked(base, lc.sample()); len(gs)+len(fds) == 0 {
				if clean++; clean == leakSamples {
					return
				}
			} else {
				clean = 0
			}
			if !time.Now().Before(deadline) {
				break
			}
			time.Sleep(leakInterval)
		}
		t.Errorf("rendrtest: leak after %v: %d goroutine(s) and %d fd(s) not in the baseline %q\n%s",
			lc.wait, len(gs), len(fds), fds, strings.Join(gs, "\n\n"))
	}
}

// leakSample is one observation: the live goroutines by ID with their
// stacks, the sampling goroutine's ID, and the open fds ("fd -> target"; nil
// where they are not observed).
type leakSample struct {
	gs   map[uint64]string
	self uint64
	fds  map[string]bool
}

func (lc leakCheck) sample() leakSample {
	buf := make([]byte, 64<<10)
	for {
		if n := runtime.Stack(buf, true); n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	s := leakSample{gs: map[uint64]string{}}
	for i, block := range strings.Split(string(buf), "\n\n") {
		head, _, _ := strings.Cut(strings.TrimPrefix(block, "goroutine "), " ")
		if id, err := strconv.ParseUint(head, 10, 64); err == nil {
			s.gs[id] = block
			if i == 0 { // runtime.Stack lists the calling goroutine first
				s.self = id
			}
		}
	}
	if lc.real {
		s.fds = openFDs()
	}
	return s
}

// settle samples until three consecutive samples 100 ms apart see the same
// goroutines and fds (or lc.wait passed) and returns the last one.
func (lc leakCheck) settle() leakSample {
	deadline := time.Now().Add(lc.wait)
	last, same := lc.sample(), 1
	for same < leakSamples && time.Now().Before(deadline) {
		time.Sleep(leakInterval)
		cur := lc.sample()
		if g, f := leaked(last, cur); len(g)+len(f) == 0 && len(cur.gs) == len(last.gs) && len(cur.fds) == len(last.fds) {
			same++
		} else {
			same = 1
		}
		last = cur
	}
	return last
}

// leaked returns the stacks of the goroutines of cur that are not in base
// (except the sampling goroutine), in ID order, and its fds not in base.
func leaked(base, cur leakSample) (gs, fds []string) {
	var ids []uint64
	for id := range cur.gs {
		if _, ok := base.gs[id]; !ok && id != cur.self {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	for _, id := range ids {
		gs = append(gs, cur.gs[id])
	}
	for fd := range cur.fds {
		if !base.fds[fd] {
			fds = append(fds, fd)
		}
	}
	slices.Sort(fds)
	return gs, fds
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
