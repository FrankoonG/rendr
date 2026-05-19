package smoke

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/FrankoonG/rendr"
)

// G2Opts configures one G2-smoke run. Defaults (30s / 5 migrations /
// 2 paths / tcp / 100 ms cadence) match docs/regression-suite.md §6.
type G2Opts struct {
	Duration   time.Duration // default 30s
	Migrations int           // approx migrations to trigger; default 5
	Paths      int           // default 2
	Transport  string        // default "tcp"
	Interval   time.Duration // echo cadence; default 100ms
	// P99CeilingMs caps P99 RTT. Default 200ms — generous for
	// loopback + Windows scheduler noise; CI Linux usually < 5ms.
	P99CeilingMs int
}

func (o *G2Opts) withDefaults() {
	if o.Duration <= 0 {
		o.Duration = 30 * time.Second
	}
	if o.Migrations < 0 {
		o.Migrations = 0
	}
	if o.Paths < 1 {
		o.Paths = 2
	}
	if o.Transport == "" {
		o.Transport = "tcp"
	}
	if o.Interval <= 0 {
		o.Interval = 100 * time.Millisecond
	}
	if o.P99CeilingMs <= 0 {
		o.P99CeilingMs = 200
	}
}

// RunG2 drives a long-lived echo loop with periodic migrations,
// asserts 0 loss and P99 RTT under the configured ceiling, and
// proves MigrationCount() advances. Detail keys:
//
//	echoes       int
//	lost         int
//	migrations   uint64
//	p50_ms       float64
//	p99_ms       float64
//	p999_ms      float64
//	max_ms       float64
func RunG2(ctx context.Context, opts G2Opts) Result {
	opts.withDefaults()
	t0 := time.Now()
	name := fmt.Sprintf("G2-smoke (%s, %s, %d paths, ~%d migrations)",
		opts.Transport, opts.Duration, opts.Paths, opts.Migrations)

	ln, err := listenForTransport(opts.Transport)
	if err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("listen: %w", err))
	}
	defer ln.Close()

	accepted := make(chan rendr.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		actx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		c, err := ln.Accept(actx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- c
	}()

	specs := make([]rendr.PathSpec, opts.Paths)
	for i := range specs {
		specs[i] = rendr.PathSpec{Transport: opts.Transport, Address: ln.Addr().String()}
	}
	client, err := (&rendr.Dialer{Mode: rendr.ModePrime, Paths: specs}).Dial(ctx)
	if err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("dial: %w", err))
	}
	defer client.Close()

	var server rendr.Conn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		return FromError(name, time.Since(t0), fmt.Errorf("accept: %w", err))
	case <-time.After(15 * time.Second):
		return FromError(name, time.Since(t0), fmt.Errorf("accept timeout"))
	}
	defer server.Close()

	// Server echoes everything back; protocol is one 12-byte record
	// per ping: 4B seq + 8B unix-nanos send-time. Server returns the
	// same record verbatim.
	echoErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 12)
		for {
			if _, err := io.ReadFull(server, buf); err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
					echoErr <- nil
					return
				}
				echoErr <- err
				return
			}
			if _, err := server.Write(buf); err != nil {
				echoErr <- err
				return
			}
		}
	}()

	admin, ok := client.(rendr.AdminConn)
	if !ok {
		return FromError(name, time.Since(t0), fmt.Errorf("client conn is not rendr.AdminConn"))
	}

	// Migration ticker: spread `Migrations` migrations evenly across
	// the run.
	var migTicker *time.Ticker
	migInterval := time.Duration(0)
	if opts.Migrations > 0 {
		migInterval = opts.Duration / time.Duration(opts.Migrations+1)
		migTicker = time.NewTicker(migInterval)
		defer migTicker.Stop()
	}

	startMigCount := admin.MigrationCount()
	rtts := make([]time.Duration, 0, int(opts.Duration/opts.Interval)+2)
	deadline := time.Now().Add(opts.Duration)
	tick := time.NewTicker(opts.Interval)
	defer tick.Stop()

	// Receiver: collect echoes into a slice owned by the goroutine.
	// The previous implementation used `make(chan echo, 1024)` which
	// deadlocked any run that emitted >1024 echoes: recv blocks on
	// chan-send, main blocks on <-doneRecv, no one drains the chan.
	// Smoke (300 echoes) stayed under the buffer; T4 (18000 echoes
	// at 30min) hit it at echo 1024 and the run hung indefinitely.
	// Single-writer slice + close(recvDone) is the happens-before fence.
	type echo struct {
		seq int32
		rtt time.Duration
	}
	echoBuf := make([]echo, 0, int(opts.Duration/opts.Interval)+128)
	doneRecv := make(chan struct{})
	go func() {
		defer close(doneRecv)
		buf := make([]byte, 12)
		for {
			if err := client.SetReadDeadline(time.Now().Add(opts.Duration + 5*time.Second)); err != nil {
				return
			}
			if _, err := io.ReadFull(client, buf); err != nil {
				return
			}
			seq := int32(binary.BigEndian.Uint32(buf[:4]))
			sentNs := int64(binary.BigEndian.Uint64(buf[4:]))
			rtt := time.Duration(time.Now().UnixNano() - sentNs)
			echoBuf = append(echoBuf, echo{seq: seq, rtt: rtt})
		}
	}()

	// Per-write deadline so a wedged engine surfaces as a concrete
	// "write seq N timed out" failure rather than hanging the whole
	// goroutine. 30 s is generous on loopback (writes normally < 1ms);
	// long enough that a slow migration doesn't trip the deadline.
	const writeDeadline = 30 * time.Second
	var seq int32
	sent := map[int32]struct{}{}
	lastProgress := time.Now()
	for time.Now().Before(deadline) {
		select {
		case <-tick.C:
			seq++
			buf := make([]byte, 12)
			binary.BigEndian.PutUint32(buf[:4], uint32(seq))
			binary.BigEndian.PutUint64(buf[4:], uint64(time.Now().UnixNano()))
			_ = client.SetWriteDeadline(time.Now().Add(writeDeadline))
			if _, err := client.Write(buf); err != nil {
				return FromError(name, time.Since(t0), fmt.Errorf("write seq %d: %w", seq, err))
			}
			_ = client.SetWriteDeadline(time.Time{})
			sent[seq] = struct{}{}
			// Coarse progress beacon for T4-scale long runs.
			if opts.Duration > 60*time.Second && time.Since(lastProgress) >= 30*time.Second {
				lastProgress = time.Now()
				fmt.Printf("    G2 progress: t=%s seq=%d sent=%d migrations=%d\n",
					time.Since(t0).Truncate(time.Second), seq, len(sent),
					admin.MigrationCount()-startMigCount)
			}
		case <-migTickerChan(migTicker):
			cur := admin.ActivePath()
			for _, p := range client.Paths() {
				if p.ID != cur {
					_ = admin.Migrate(p.ID)
					break
				}
			}
		case <-ctx.Done():
			break
		}
	}

	// Give the receiver a moment to drain in-flight echoes, then
	// force its ReadFull to return via the read deadline.
	time.Sleep(500 * time.Millisecond)
	_ = client.SetReadDeadline(time.Now())
	<-doneRecv

	received := map[int32]time.Duration{}
	for _, e := range echoBuf {
		received[e.seq] = e.rtt
		rtts = append(rtts, e.rtt)
	}

	lost := 0
	for s := range sent {
		if _, ok := received[s]; !ok {
			lost++
		}
	}

	if len(rtts) == 0 {
		return FromError(name, time.Since(t0), fmt.Errorf("no echoes received"))
	}
	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
	p50 := rtts[len(rtts)*50/100]
	p99 := rtts[len(rtts)*99/100]
	p999 := rtts[len(rtts)*999/1000]
	if p999 == 0 && len(rtts) > 0 {
		p999 = rtts[len(rtts)-1]
	}
	maxRTT := rtts[len(rtts)-1]

	migrated := admin.MigrationCount() - startMigCount
	r := Result{
		Name:     name,
		Duration: time.Since(t0),
		Detail: map[string]any{
			"echoes":     len(sent),
			"lost":       lost,
			"migrations": migrated,
			"p50_ms":     float64(p50) / float64(time.Millisecond),
			"p99_ms":     float64(p99) / float64(time.Millisecond),
			"p999_ms":    float64(p999) / float64(time.Millisecond),
			"max_ms":     float64(maxRTT) / float64(time.Millisecond),
		},
	}
	if lost > 0 {
		r.Failure = fmt.Sprintf("echo loss: %d / %d", lost, len(sent))
		return r
	}
	if int(p99/time.Millisecond) > opts.P99CeilingMs {
		r.Failure = fmt.Sprintf("P99 RTT %.1fms exceeds ceiling %dms", float64(p99)/float64(time.Millisecond), opts.P99CeilingMs)
		return r
	}
	if opts.Migrations > 0 && migrated == 0 {
		r.Failure = "no migrations actually fired"
		return r
	}
	return r
}

// migTickerChan returns t.C, or a nil channel if t is nil. This lets
// the select arm be a no-op when migrations are disabled.
func migTickerChan(t *time.Ticker) <-chan time.Time {
	if t == nil {
		return nil
	}
	return t.C
}
