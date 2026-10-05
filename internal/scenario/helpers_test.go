package scenario

// API-independent traffic helpers: they only use net.Conn / io interfaces.

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"
)

// echoRun streams PRNG bytes at rateKiB for dur through c (echo target),
// verifying every returned byte; midway() runs once at half time on the
// writer goroutine (a fault that must not pause the load runs its own
// goroutine). Reads carry a deadline of dur+echoSlack, so a silent stall
// fails instead of hanging the test binary.
type echoResult struct {
	sent, recvd int64
	maxStall    time.Duration
	err         error
	tx, rx      []sample // cumulative bytes written / verified over time
}

type sample struct {
	at    time.Time
	total int64
}

const echoSlack = 15 * time.Second

func echoRun(c io.ReadWriteCloser, dur time.Duration, rateKiB int, midway func()) echoResult {
	var res echoResult
	var mu sync.Mutex
	done := make(chan struct{})
	if d, ok := c.(interface{ SetReadDeadline(time.Time) error }); ok {
		d.SetReadDeadline(time.Now().Add(dur + echoSlack))
	}
	go func() {
		defer close(done)
		src := prng(11)
		buf := make([]byte, 4096)
		iv := time.Duration(float64(time.Second) * 4096 / float64(rateKiB*1024))
		start := time.Now()
		next := start
		half := false
		for time.Since(start) < dur {
			src.Read(buf)
			if _, err := c.Write(buf); err != nil {
				mu.Lock()
				res.err = fmt.Errorf("write: %w", err)
				mu.Unlock()
				return
			}
			mu.Lock()
			res.sent += 4096
			res.tx = append(res.tx, sample{time.Now(), res.sent})
			mu.Unlock()
			if !half && time.Since(start) > dur/2 && midway != nil {
				half = true
				midway()
			}
			next = next.Add(iv)
			if d := time.Until(next); d > 0 {
				time.Sleep(d)
			}
		}
		if cw, ok := c.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}()
	want := prng(11)
	got := make([]byte, 32<<10)
	exp := make([]byte, 32<<10)
	last := time.Now()
	for {
		n, err := c.Read(got)
		if n > 0 {
			if g := time.Since(last); g > res.maxStall {
				res.maxStall = g
			}
			last = time.Now()
			want.Read(exp[:n])
			if !bytes.Equal(got[:n], exp[:n]) {
				c.Close()
				<-done
				res.err = fmt.Errorf("mismatch near offset %d", res.recvd)
				return res
			}
			res.recvd += int64(n)
			res.rx = append(res.rx, sample{last, res.recvd})
		}
		if err != nil {
			if err != io.EOF {
				res.err = fmt.Errorf("read: %w", err)
			}
			break
		}
	}
	<-done
	mu.Lock()
	defer mu.Unlock()
	if res.err == nil && res.recvd != res.sent {
		res.err = fmt.Errorf("short: sent %d recvd %d", res.sent, res.recvd)
	}
	if res.err == nil && res.sent == 0 {
		res.err = fmt.Errorf("no load: nothing was sent")
	}
	c.Close()
	return res
}

// resumedAfter is the recovery time after t: how long until the echo
// returned a byte that was written after t. ok is false if that never
// happened.
func (r echoResult) resumedAfter(t time.Time) (time.Duration, bool) {
	var before int64
	for _, s := range r.tx {
		if s.at.After(t) {
			break
		}
		before = s.total
	}
	for _, s := range r.rx {
		if s.total > before && !s.at.Before(t) {
			return s.at.Sub(t), true
		}
	}
	return 0, false
}

// offeredLoad fails the test unless the writer kept its schedule: at least
// 90% of rateKiB*dur was written.
func offeredLoad(t *testing.T, r echoResult, rateKiB int, dur time.Duration) {
	t.Helper()
	want := int64(0.9 * float64(rateKiB*1024) * dur.Seconds())
	if r.sent < want {
		t.Fatalf("offered load %d bytes, want >= %d (%d KiB/s for %s)", r.sent, want, rateKiB, dur)
	}
}

type prngReader struct{ x uint64 }

func prng(seed uint64) *prngReader { return &prngReader{x: seed*2654435761 + 1} }

func (p *prngReader) Read(b []byte) (int, error) {
	for i := range b {
		p.x ^= p.x << 13
		p.x ^= p.x >> 7
		p.x ^= p.x << 17
		b[i] = byte(p.x)
	}
	return len(b), nil
}

// digest hashes exactly n bytes from r; a short read yields a zero digest.
// within > 0 sets a read deadline on r (a net.Conn), so a stalled transfer
// fails instead of hanging.
func digest(r io.Reader, n int64, within time.Duration) [32]byte {
	if d, ok := r.(interface{ SetReadDeadline(time.Time) error }); ok && within > 0 {
		d.SetReadDeadline(time.Now().Add(within))
	}
	h := sha256.New()
	if k, _ := io.CopyN(h, r, n); k != n {
		return [32]byte{}
	}
	var d [32]byte
	copy(d[:], h.Sum(nil))
	return d
}

// stimulus fails the test when a fault the test injected did not happen.
func stimulus(t *testing.T, ok bool, format string, args ...any) {
	t.Helper()
	if !ok {
		t.Fatalf("INVALID: stimulus did not happen: "+format, args...)
	}
}

// settledGoroutines waits until the goroutine count has not changed for
// one second (at most 15 s) and returns it: a baseline that does not
// depend on what earlier tests left behind.
func settledGoroutines() int {
	n, since := runtime.NumGoroutine(), time.Now()
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
		time.Sleep(50 * time.Millisecond)
		if m := runtime.NumGoroutine(); m != n {
			n, since = m, time.Now()
		} else if time.Since(since) >= time.Second {
			break
		}
	}
	return n
}

// notTimeout fails the test if err is a read-deadline expiry: the test's
// watchdog fired, which is a hang, not the error under test.
func notTimeout(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("watchdog deadline expired: %v", err)
	}
}
