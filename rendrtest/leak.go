package rendrtest

import (
	"testing"
	"time"
)

// AssertNoLeak records a settled goroutine baseline (and the open-fd count
// on Linux) and returns a check to defer (L66). The caller must have joined
// everything it started before the check runs; the check then forces a
// netpoll round trip and waits (at most 10 s) until three consecutive
// samples 100 ms apart equal the baseline (unit layer: zero growth), else
// it fails t with a full goroutine dump. Inside a synctest bubble the
// bubble's own leak check makes it unnecessary.
func AssertNoLeak(t testing.TB) (check func()) {
	panic("unimplemented: M1b")
}

// ReadyBoth waits until both a() and b() hold (L66: readiness waits for both
// ends), failing t after within.
func ReadyBoth(t testing.TB, a, b func() bool, within time.Duration) {
	panic("unimplemented: M1b")
}
