// Package harness implements the frozen BENCH-E2E-1 workload. Adapters only
// supply how to establish one connection pair over exactly one loopback TCP
// carrier; everything measured is here, so every implementation runs the
// identical workload. Do not change this file: a change breaks comparability
// with every recorded baseline.
//
// BENCH-E2E-1: one process hosts both ends with GOMAXPROCS(8). The sender
// writes a ChaCha8 stream (seed "rendr" zero-padded to 32 bytes) in 64 KiB
// calls, N bytes in total. The receiver reads with a 64 KiB buffer and
// computes CRC-32C, which must match the sender's CRC over what it wrote.
// The timer starts immediately before the first Write and stops when the
// receiver has read all N bytes and the CRC matched; connection setup is
// excluded. The CRC is compared with one computed independently from the
// seed before the timer starts, so a Write that mutates its input or a
// sender-side CRC bug cannot hide corruption; the sender's own CRC must
// match it as well. One warm-up transfer, then the measured transfers, each on a
// fresh connection. Output: exactly one JSON line. 1 MB = 1e6 bytes.
package harness

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"runtime"
	"slices"
	"sync/atomic"
	"time"
)

// GOMAXPROCS(8) is fixed before any adapter code (package main's init and
// setup run after this package's init).
func init() { runtime.GOMAXPROCS(8) }

// stallTimeout aborts a transfer whose receiver made no progress for this
// long (a dead sender or a wedged implementation), so the process reports
// an error instead of hanging until an outer kill.
const stallTimeout = 2 * time.Minute

// Pair establishes one fresh connection pair. The client end writes, the
// server end reads. cleanup releases everything Pair created.
type Pair func() (client, server net.Conn, cleanup func(), err error)

const chunk = 64 * 1024

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// Seed returns the frozen BENCH-E2E-1 seed.
func Seed() [32]byte {
	var s [32]byte
	copy(s[:], "rendr")
	return s
}

// Line is the JSON result line.
type Line struct {
	Bench      string    `json:"bench"`
	Impl       string    `json:"impl"`
	Bytes      int64     `json:"bytes"`
	RunsMbps   []float64 `json:"runs_mbps"`
	MedianMbps float64   `json:"median_mbps"`
	GOMAXPROCS int       `json:"gomaxprocs"`
	Go         string    `json:"go"`
	GOOS       string    `json:"goos"`
	GOARCH     string    `json:"goarch"`
}

// Main parses -bytes, -runs and -warmup-bytes, runs the benchmark and prints
// one JSON line. Any I/O error or CRC mismatch exits 1.
func Main(impl string, pair Pair) {
	n := flag.Int64("bytes", 1<<30, "bytes per measured transfer")
	runs := flag.Int("runs", 5, "measured transfers")
	warm := flag.Int64("warmup-bytes", 64<<20, "bytes of the warm-up transfer (0 = none)")
	flag.Parse()
	line, err := Run(impl, pair, *n, *runs, *warm)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bench e2e-1:", err)
		os.Exit(1)
	}
	out, _ := json.Marshal(line)
	fmt.Println(string(out))
}

// Run executes the warm-up and measured transfers.
func Run(impl string, pair Pair, n int64, runs int, warm int64) (Line, error) {
	runtime.GOMAXPROCS(8)
	if n <= 0 || runs <= 0 || warm < 0 {
		return Line{}, errors.New("bytes and runs must be positive, warmup-bytes non-negative")
	}
	if warm > 0 {
		if _, err := transfer(pair, warm); err != nil {
			return Line{}, fmt.Errorf("warm-up: %w", err)
		}
	}
	l := Line{Bench: "e2e-1", Impl: impl, Bytes: n, GOMAXPROCS: runtime.GOMAXPROCS(0),
		Go: runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
	for i := 0; i < runs; i++ {
		d, err := transfer(pair, n)
		if err != nil {
			return Line{}, fmt.Errorf("run %d: %w", i+1, err)
		}
		l.RunsMbps = append(l.RunsMbps, float64(n)/1e6/d.Seconds())
	}
	l.MedianMbps = median(l.RunsMbps)
	return l, nil
}

func median(v []float64) float64 {
	s := slices.Clone(v)
	slices.Sort(s)
	if len(s)%2 == 1 {
		return s[len(s)/2]
	}
	return (s[len(s)/2-1] + s[len(s)/2]) / 2
}

type sent struct {
	crc uint32
	err error
}

// expectedCRC is the CRC-32C of the first n bytes of the frozen stream.
func expectedCRC(n int64) uint32 {
	rng := rand.NewChaCha8(Seed())
	buf := make([]byte, chunk)
	var crc uint32
	for left := n; left > 0; {
		size := int(min(int64(chunk), left))
		rng.Read(buf[:size])
		crc = crc32.Update(crc, castagnoli, buf[:size])
		left -= int64(size)
	}
	return crc
}

// transfer moves n bytes over a fresh pair and returns the timed duration.
func transfer(pair Pair, n int64) (time.Duration, error) {
	want := expectedCRC(n)
	client, server, cleanup, err := pair()
	if err != nil {
		return 0, fmt.Errorf("connect: %w", err)
	}
	defer cleanup()
	defer client.Close()
	defer server.Close()
	abort := func() { client.Close(); server.Close() }

	rng := rand.NewChaCha8(Seed())
	buf := make([]byte, chunk)
	first := int(min(int64(chunk), n))
	rng.Read(buf[:first])
	start := make(chan time.Time, 1)
	sentc := make(chan sent, 1)
	go func() {
		var crc uint32
		left := n
		size := first
		t0 := time.Now()
		start <- t0
		for left > 0 {
			if left != n {
				size = int(min(int64(chunk), left))
				rng.Read(buf[:size])
			}
			if _, err := client.Write(buf[:size]); err != nil {
				sentc <- sent{err: fmt.Errorf("write: %w", err)}
				abort() // unblock the receiver
				return
			}
			crc = crc32.Update(crc, castagnoli, buf[:size])
			left -= int64(size)
		}
		sentc <- sent{crc: crc}
	}()

	var got atomic.Int64
	stalled := make(chan struct{})
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		last := int64(-1)
		t := time.NewTicker(stallTimeout)
		defer t.Stop()
		for {
			select {
			case <-watchDone:
				return
			case <-t.C:
				g := got.Load()
				if g == last {
					close(stalled)
					abort()
					return
				}
				last = g
			}
		}
	}()

	rbuf := make([]byte, chunk)
	var crc uint32
	var rerr error
	var end time.Time
	for got.Load() < n {
		k, err := server.Read(rbuf)
		if k > 0 {
			crc = crc32.Update(crc, castagnoli, rbuf[:k])
			if got.Add(int64(k)) >= n {
				end = time.Now()
			}
		}
		if err != nil {
			if g := got.Load(); g < n {
				if err == io.EOF {
					err = io.ErrUnexpectedEOF
				}
				rerr = fmt.Errorf("read after %d bytes: %w", g, err)
			}
			break
		}
	}
	if g := got.Load(); rerr == nil && g > n {
		rerr = fmt.Errorf("received %d bytes, sent %d", g, n)
	}
	if rerr == nil && crc != want {
		rerr = fmt.Errorf("crc32c mismatch: expected %08x, received %08x", want, crc)
	}
	select {
	case <-stalled:
		rerr = fmt.Errorf("no progress for %v after %d bytes: %v", stallTimeout, got.Load(), rerr)
	default:
	}
	if rerr != nil {
		abort()
		if s := <-sentc; s.err != nil {
			return 0, fmt.Errorf("%w (sender: %v)", rerr, s.err)
		}
		return 0, rerr
	}
	s := <-sentc
	if s.err != nil {
		return 0, s.err
	}
	if s.crc != want {
		return 0, fmt.Errorf("crc32c mismatch: expected %08x, sender wrote %08x", want, s.crc)
	}
	return end.Sub(<-start), nil
}
