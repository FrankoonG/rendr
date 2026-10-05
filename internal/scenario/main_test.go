package scenario

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestMain runs the package's tests and then checks that none of them left
// a goroutine behind (L52, L66; design §0.14 B11). The tests run their
// fixtures in parallel on real time, so no single test can compare against
// a goroutine baseline (TestHalfCloseAndCleanFinish runs alone for that
// reason); but every fixture closes and joins both Runtimes, its links and
// its far end, so once m.Run returned only the runtime's and the test
// framework's own goroutines may remain. The check runs only after the
// tests passed (a failed test may leave its goroutines; its failure is the
// report), waits up to g10LeakWait for goroutines that are still
// unwinding, requires g10LeakSamples clean samples in a row, and otherwise
// prints the stacks of the goroutines left and fails the binary.
func TestMain(m *testing.M) {
	code := m.Run()
	if code == 0 {
		if left := g10Leftover(g10LeakWait); len(left) > 0 {
			fmt.Fprintf(os.Stderr, "FAIL: %d goroutine(s) still running after every test of the package ended (a leak, L52/L66):\n\n%s\n",
				len(left), strings.Join(left, "\n\n"))
			code = 1
		}
	}
	os.Exit(code)
}

// The end-of-package leak check: at most g10LeakWait, samples
// g10LeakInterval apart, g10LeakSamples clean ones in a row.
const (
	g10LeakWait     = 10 * time.Second
	g10LeakInterval = 100 * time.Millisecond
	g10LeakSamples  = 3
)

// g10Leftover returns nil once g10LeakSamples samples in a row show no
// goroutine but the caller's and those of the runtime and the test
// framework, or the stacks of the last sample's goroutines when within
// passed first.
func g10Leftover(within time.Duration) []string {
	deadline := time.Now().Add(within)
	for clean := 0; ; {
		left := g10Goroutines()
		if len(left) > 0 {
			clean = 0
		} else if clean++; clean == g10LeakSamples {
			return nil
		}
		if !time.Now().Before(deadline) {
			return left
		}
		time.Sleep(g10LeakInterval)
	}
}

// g10Goroutines returns the stacks of the live goroutines other than the
// caller (runtime.Stack lists it first) and those of the runtime and the
// test framework (g10Framework).
func g10Goroutines() []string {
	buf := make([]byte, 1<<20)
	for {
		if n := runtime.Stack(buf, true); n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	var left []string
	for i, g := range strings.Split(string(buf), "\n\n") {
		if i > 0 && !g10Framework(g) {
			left = append(left, g)
		}
	}
	return left
}

// g10Framework reports a goroutine that the test framework or the runtime
// owns, found by a frame of its stack (a frame line starts with the
// function name, a "created by" line does not): the test runner and its
// parallel and fuzz waiters, the signal handler, a trace reader.
func g10Framework(stack string) bool {
	for _, fn := range []string{
		"testing.RunTests(", "testing.(*T).Run(", "testing.(*T).Parallel(", "testing.runFuzzing(", "testing.runFuzzTests(",
		"os/signal.signal_recv(", "os/signal.loop(", "runtime.ensureSigM(", "runtime.ReadTrace(",
	} {
		if strings.Contains(stack, "\n"+fn) {
			return true
		}
	}
	return false
}
