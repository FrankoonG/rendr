// Command e2ebench runs the frozen end-to-end throughput workload
// BENCH-E2E-1 over the msess session layer.
//
// The workload itself lives in package harness, a verbatim copy of the
// frozen rendr-regress bench/harness/harness.go (rendr-regress cannot import
// this module's internal packages, so the copy has to live here). The
// canonical file is the rendr-regress one; harness/harness.go must stay
// byte-identical to it, which TestHarnessIsFrozenCopy and the rendr-regress
// controller both check against FrozenHarnessSHA256. This file is only the
// Pair adapter, like bench/v030 and bench/v1 in rendr-regress.
//
// Topology: one loopback TCP listener on 127.0.0.1:0 served by an msess
// Server. Each pair dials one selector-mode session over exactly one carrier
// connection to it. The client end is the msess Conn. The server end is the
// accepted session itself: the Server's target is an in-process conn whose
// ReadFrom hands the session reader to the harness, so the harness reads the
// session directly with its 64 KiB buffer and no relay hop is in the path.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/e2ebench/harness"
	"github.com/FrankoonG/rendr/v2/internal/msess"
)

const implName = "rendr-v2-m1a-msess"

// FrozenHarnessSHA256 is the SHA-256 of rendr-regress bench/harness/harness.go
// (CR bytes stripped), which harness/harness.go copies verbatim.
const FrozenHarnessSHA256 = "9c0c17507753e86344cdd47ab0a0ecb5c2c0defac4e478b8bf9e362106e81c3a"

// teardownTimeout bounds how long one pair may take to release its session
// on both ends after the harness closed it.
const teardownTimeout = 10 * time.Second

type bench struct {
	ln       net.Listener
	srv      *msess.Server
	prober   *msess.Prober
	accepted atomic.Int64

	mu      sync.Mutex
	targets map[string]*target
	seq     int
	failed  error // first teardown failure; fails the next pair and the run
}

func newBench() (*bench, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	b := &bench{ln: ln, targets: map[string]*target{}}
	b.srv = msess.NewServer(msess.ServerConfig{DialTarget: b.dialTarget})
	// A closed prober never opens probe connections, so the session's single
	// carrier is the only connection to the listener.
	b.prober = msess.NewProber(nil)
	b.prober.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			b.accepted.Add(1)
			go b.srv.Handle(c)
		}
	}()
	return b, nil
}

// dialTarget is the Server's target dialer: "bench:<id>" resolves to the
// target registered by pair.
func (b *bench) dialTarget(ctx context.Context, addr string) (net.Conn, error) {
	id, ok := strings.CutPrefix(addr, "bench:")
	b.mu.Lock()
	t := b.targets[id]
	delete(b.targets, id)
	b.mu.Unlock()
	if !ok || t == nil {
		return nil, fmt.Errorf("unknown target %q", addr)
	}
	return t, nil
}

// pair is the harness.Pair: one fresh session over one fresh carrier.
func (b *bench) pair() (net.Conn, net.Conn, func(), error) {
	b.mu.Lock()
	if b.failed != nil {
		err := b.failed
		b.mu.Unlock()
		return nil, nil, nil, err
	}
	b.seq++
	id := strconv.Itoa(b.seq)
	t := newTarget()
	b.targets[id] = t
	b.mu.Unlock()
	unregister := func() {
		b.mu.Lock()
		delete(b.targets, id)
		b.mu.Unlock()
	}

	accepted := b.accepted.Load()
	addr := b.ln.Addr().String()
	path := msess.Path{Name: "loopback", Exit: "bench", Dial: func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}}
	c, err := msess.Dial(context.Background(), msess.DialConfig{Mode: msess.ModeSelector,
		Target: "bench:" + id, Paths: []msess.Path{path}, Prober: b.prober, NoProbeWait: true})
	if err != nil {
		unregister()
		return nil, nil, nil, fmt.Errorf("dial: %w", err)
	}
	cleanup := func() {
		unregister()
		if err := b.teardown(c, t, accepted); err != nil {
			fmt.Fprintln(os.Stderr, "e2ebench: teardown:", err)
			b.mu.Lock()
			if b.failed == nil {
				b.failed = err
			}
			b.mu.Unlock()
		}
	}
	// The session's server end has no Close of its own; aborting a blocked
	// read (the harness's stall watchdog) closes the whole Server, which fails
	// the benchmark anyway.
	return c, t.harnessEnd(func() { b.srv.Close() }), cleanup, nil
}

// teardown waits until the transfer's session has ended on both ends and its
// server pumps have exited, so no teardown overlaps the next measured run.
func (b *bench) teardown(c *msess.Conn, t *target, accepted int64) error {
	deadline := time.After(teardownTimeout)
	select {
	case <-c.Done():
	case <-deadline:
		return errors.New("client session did not end")
	}
	select {
	case <-t.released:
	case <-deadline:
		return errors.New("server target was not released")
	}
	// The server forgets a session only after both pump goroutines exited.
	for b.srv.Stats().Sessions != 0 {
		select {
		case <-deadline:
			return fmt.Errorf("server still holds %d sessions", b.srv.Stats().Sessions)
		case <-time.After(time.Millisecond):
		}
	}
	if got := b.accepted.Load() - accepted; got != 1 {
		return fmt.Errorf("transfer used %d carrier connections, want exactly 1", got)
	}
	return nil
}

// target is the Server's target conn. The Server pumps session -> target
// with io.Copy, which calls ReadFrom with the session reader; ReadFrom hands
// that reader to the harness end and, once the harness closed its end,
// drains the rest of the session so it ends with the client's FIN. Its own
// Read (target -> session) has nothing to send and reports EOF on Close.
type target struct {
	reader   chan io.Reader // the session reader, handed over once
	done     chan struct{}  // harness end closed
	closed   chan struct{}  // target closed by the Server
	released chan struct{}  // closed, and ReadFrom (if it ran) returned
	doneOnce sync.Once
	closeOne sync.Once

	mu      sync.Mutex
	running bool // ReadFrom in progress
	ended   bool // closed and no ReadFrom running; ReadFrom refuses to start
}

func newTarget() *target {
	return &target{reader: make(chan io.Reader, 1), done: make(chan struct{}),
		closed: make(chan struct{}), released: make(chan struct{})}
}

func (t *target) ReadFrom(r io.Reader) (int64, error) {
	t.mu.Lock()
	if t.ended {
		t.mu.Unlock()
		return 0, net.ErrClosed
	}
	t.running = true
	t.mu.Unlock()
	defer func() {
		t.mu.Lock()
		t.running = false
		t.releaseLocked()
		t.mu.Unlock()
	}()
	t.reader <- r
	select {
	case <-t.done:
	case <-t.closed:
		return 0, net.ErrClosed
	}
	return io.Copy(io.Discard, r)
}

// releaseLocked closes released once the target is closed and no ReadFrom
// is running.
func (t *target) releaseLocked() {
	select {
	case <-t.closed:
	default:
		return
	}
	if !t.running && !t.ended {
		t.ended = true
		close(t.released)
	}
}

func (t *target) Read([]byte) (int, error) {
	<-t.closed
	return 0, io.EOF
}

func (t *target) Write([]byte) (int, error) {
	return 0, errors.New("e2ebench target: unexpected Write")
}

func (t *target) Close() error {
	t.closeOne.Do(func() {
		close(t.closed)
		t.mu.Lock()
		t.releaseLocked()
		t.mu.Unlock()
	})
	return nil
}

func (t *target) LocalAddr() net.Addr              { return benchAddr("target") }
func (t *target) RemoteAddr() net.Addr             { return benchAddr("session") }
func (t *target) SetDeadline(time.Time) error      { return nil }
func (t *target) SetReadDeadline(time.Time) error  { return nil }
func (t *target) SetWriteDeadline(time.Time) error { return nil }
func (t *target) harnessEnd(abort func()) net.Conn { return &harnessEnd{t: t, abort: abort} }

type benchAddr string

func (a benchAddr) Network() string { return "e2ebench" }
func (a benchAddr) String() string  { return string(a) }

// harnessEnd is the server end given to the harness: it reads the session
// directly through the reader the Server passed to target.ReadFrom.
type harnessEnd struct {
	t       *target
	r       io.Reader
	abort   func()
	reading atomic.Bool
}

func (h *harnessEnd) Read(p []byte) (int, error) {
	h.reading.Store(true)
	defer h.reading.Store(false)
	if h.r == nil {
		select {
		case h.r = <-h.t.reader:
		case <-h.t.closed:
			return 0, net.ErrClosed
		case <-h.t.done:
			return 0, net.ErrClosed
		}
	}
	return h.r.Read(p)
}

// Close ends the harness's use of the session. A Close that races a
// blocked Read is an abort: it closes the Server so the Read returns.
func (h *harnessEnd) Close() error {
	h.t.doneOnce.Do(func() { close(h.t.done) })
	if h.reading.Load() {
		h.abort()
	}
	return nil
}

func (h *harnessEnd) Write([]byte) (int, error) {
	return 0, errors.New("e2ebench: server end is read-only")
}
func (h *harnessEnd) LocalAddr() net.Addr              { return benchAddr("session") }
func (h *harnessEnd) RemoteAddr() net.Addr             { return benchAddr("client") }
func (h *harnessEnd) SetDeadline(time.Time) error      { return nil }
func (h *harnessEnd) SetReadDeadline(time.Time) error  { return nil }
func (h *harnessEnd) SetWriteDeadline(time.Time) error { return nil }

// main mirrors harness.Main (same flags, one JSON line on stdout), but also
// fails when the teardown after the last transfer failed, before printing.
func main() {
	n := flag.Int64("bytes", 1<<30, "bytes per measured transfer")
	runs := flag.Int("runs", 5, "measured transfers")
	warm := flag.Int64("warmup-bytes", 64<<20, "bytes of the warm-up transfer (0 = none)")
	flag.Parse()
	b, err := newBench()
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2ebench:", err)
		os.Exit(1)
	}
	line, err := harness.Run(implName, b.pair, *n, *runs, *warm)
	if err == nil {
		b.mu.Lock()
		err = b.failed
		b.mu.Unlock()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "bench e2e-1:", err)
		os.Exit(1)
	}
	out, _ := json.Marshal(line)
	fmt.Println(string(out))
}
