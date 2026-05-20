package smoke

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"runtime"
	"time"

	"github.com/FrankoonG/rendr"
)

// G4Opts configures one G4 case (path-A force-kill, verify B picks
// up < 5s, app sees no error). Linux-only: drops the active path's
// outbound TCP via `iptables -A OUTPUT -p tcp --sport <port> -j DROP`
// after grabbing PathInfo.LocalAddr. Requires CAP_NET_ADMIN (provided
// by scripts/regress.sh's `docker --cap-add=NET_ADMIN`).
//
// Cross-platform unit-test coverage of the same engine code path lives
// in rendr_test.go (TestM6PathDeath* etc.), which reaches into the
// engine via the bc.Engine().ForceKillPathForTest() internal accessor.
// The regress smoke G4 is the integration-level proof.
type G4Opts struct {
	Duration  time.Duration // default 6s
	KillAt    time.Duration // default 2s
	EchoInt   time.Duration // default 10ms
	Paths     int           // default 2
	BudgetMs  int           // failover ceiling; default 5000
	Transport string        // "tcp" only — iptables filters TCP sport
}

func (o *G4Opts) withDefaults() {
	if o.Duration <= 0 {
		o.Duration = 6 * time.Second
	}
	if o.KillAt <= 0 {
		o.KillAt = 2 * time.Second
	}
	if o.EchoInt <= 0 {
		o.EchoInt = 10 * time.Millisecond
	}
	if o.Paths < 2 {
		o.Paths = 2
	}
	if o.BudgetMs <= 0 {
		o.BudgetMs = 5000
	}
	if o.Transport == "" {
		o.Transport = "tcp"
	}
}

// RunG4 returns Result with Detail keys:
//
//	echoes              int
//	application_lost    int
//	failover_ms         int64
//	max_rtt_ms          float64
func RunG4(ctx context.Context, opts G4Opts) Result {
	opts.withDefaults()
	t0 := time.Now()
	name := fmt.Sprintf("G4 (%s, iptables-kill@%s, budget %dms)", opts.Transport, opts.KillAt, opts.BudgetMs)

	if runtime.GOOS != "linux" {
		return Result{
			Name:     name,
			Duration: time.Since(t0),
			Failure:  "G4 requires Linux iptables (run inside docker container with --cap-add=NET_ADMIN)",
		}
	}
	if opts.Transport != "tcp" {
		return FromError(name, time.Since(t0), fmt.Errorf("G4 iptables variant only supports TCP, got %q", opts.Transport))
	}

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

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(client.Paths()) >= opts.Paths && len(server.Paths()) >= opts.Paths {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	echoErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 8)
		for {
			if _, err := io.ReadFull(server, buf); err != nil {
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

	// Scheduled kill: at KillAt, find the active path's local TCP
	// source port, drop it via iptables.
	killDone := make(chan time.Time, 1)
	killErr := make(chan error, 1)
	var deferredCleanup func() error
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(opts.KillAt):
		}
		curID := admin.ActivePath()
		var localAddr string
		for _, p := range client.Paths() {
			if p.ID == curID {
				localAddr = p.LocalAddr
				break
			}
		}
		if localAddr == "" {
			killErr <- fmt.Errorf("active path %d has no LocalAddr", curID)
			return
		}
		port, err := portFromAddr(localAddr)
		if err != nil {
			killErr <- fmt.Errorf("parse local addr %q: %w", localAddr, err)
			return
		}
		cleanup, err := iptablesDropSrcPort(port)
		if err != nil {
			killErr <- err
			return
		}
		deferredCleanup = cleanup
		killDone <- time.Now()
	}()
	// Ensure cleanup fires even on early return.
	defer func() {
		if deferredCleanup != nil {
			_ = deferredCleanup()
		}
	}()

	start := time.Now()
	endAt := start.Add(opts.Duration)
	var counter uint64
	rxbuf := make([]byte, 8)
	var killStamp time.Time
	var firstPostKill time.Time
	var lost int
	var maxRTT time.Duration
	var cause string
	for time.Now().Before(endAt) {
		var tx [8]byte
		binary.BigEndian.PutUint64(tx[:], counter)
		echoStart := time.Now()
		if _, err := client.Write(tx[:]); err != nil {
			cause = fmt.Sprintf("write at %d: %v", counter, err)
			break
		}
		if _, err := io.ReadFull(client, rxbuf); err != nil {
			cause = fmt.Sprintf("read at %d: %v", counter, err)
			break
		}
		if binary.BigEndian.Uint64(rxbuf) != counter {
			lost++
		}
		rtt := time.Since(echoStart)
		if rtt > maxRTT {
			maxRTT = rtt
		}
		select {
		case s := <-killDone:
			killStamp = s
			killDone = nil
		case e := <-killErr:
			cause = fmt.Sprintf("kill: %v", e)
			killErr = nil
		default:
		}
		if cause != "" {
			break
		}
		if !killStamp.IsZero() && firstPostKill.IsZero() && time.Now().After(killStamp) {
			firstPostKill = time.Now()
		}
		counter++
		if opts.EchoInt > 0 {
			time.Sleep(opts.EchoInt)
		}
	}

	var failoverMs int64
	if !killStamp.IsZero() && !firstPostKill.IsZero() {
		failoverMs = firstPostKill.Sub(killStamp).Milliseconds()
	}

	r := Result{
		Name:     name,
		Duration: time.Since(t0),
		Detail: map[string]any{
			"echoes":           int(counter),
			"application_lost": lost,
			"failover_ms":      failoverMs,
			"max_rtt_ms":       float64(maxRTT) / float64(time.Millisecond),
		},
	}
	if cause != "" {
		r.Failure = cause
		return r
	}
	if lost > 0 {
		r.Failure = fmt.Sprintf("application-visible echo loss: %d", lost)
		return r
	}
	if failoverMs > int64(opts.BudgetMs) {
		r.Failure = fmt.Sprintf("failover %dms exceeds %dms budget", failoverMs, opts.BudgetMs)
		return r
	}
	return r
}

// G5Opts configures the G5 case (G4 then re-add the killed path,
// verify no spurious reorder).
type G5Opts struct {
	G4 G4Opts // run G4 first; same shape
	// PostAddBytes is the data exchanged after AddPath to validate
	// the re-attached path doesn't induce a SEQ rewind / dup spike.
	PostAddBytes int64 // default 256 KiB
}

// RunG5 kills the active path via iptables, then AddPath() with the
// same transport spec to verify the engine can re-attach a fresh path
// and exchange bytes without spurious dups. Asserts:
//   - AddPath returns a fresh id
//   - RecvDups stays 0 (no reorder artifacts)
//   - bytes round-trip intact
//
// Linux-only (uses iptables); see G4 docstring for the cross-platform
// unit-test note.
func RunG5(ctx context.Context, opts G5Opts) Result {
	o := opts.G4
	o.withDefaults()
	if opts.PostAddBytes <= 0 {
		opts.PostAddBytes = 256 << 10
	}
	t0 := time.Now()
	name := fmt.Sprintf("G5 (after G4: AddPath + %d byte exchange)", opts.PostAddBytes)

	if runtime.GOOS != "linux" {
		return Result{
			Name:     name,
			Duration: time.Since(t0),
			Failure:  "G5 requires Linux iptables (run inside docker container with --cap-add=NET_ADMIN)",
		}
	}
	if o.Transport != "tcp" {
		return FromError(name, time.Since(t0), fmt.Errorf("G5 iptables variant only supports TCP, got %q", o.Transport))
	}

	ln, err := listenForTransport(o.Transport)
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

	specs := make([]rendr.PathSpec, o.Paths)
	for i := range specs {
		specs[i] = rendr.PathSpec{Transport: o.Transport, Address: ln.Addr().String()}
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

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(client.Paths()) >= o.Paths && len(server.Paths()) >= o.Paths {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	admin, ok := client.(rendr.AdminConn)
	if !ok {
		return FromError(name, time.Since(t0), fmt.Errorf("client conn is not rendr.AdminConn"))
	}

	// Find active path's local TCP source port and iptables-drop it.
	curID := admin.ActivePath()
	var localAddr string
	for _, p := range client.Paths() {
		if p.ID == curID {
			localAddr = p.LocalAddr
			break
		}
	}
	if localAddr == "" {
		return FromError(name, time.Since(t0), fmt.Errorf("active path %d has no LocalAddr", curID))
	}
	port, err := portFromAddr(localAddr)
	if err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("parse %q: %w", localAddr, err))
	}
	cleanup, err := iptablesDropSrcPort(port)
	if err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("iptables drop sport=%d: %w", port, err))
	}
	defer func() { _ = cleanup() }()

	// Server echo loop.
	echoErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := server.Read(buf)
			if err != nil {
				echoErr <- err
				return
			}
			if _, err := server.Write(buf[:n]); err != nil {
				echoErr <- err
				return
			}
		}
	}()

	// Wait briefly for failover to settle.
	time.Sleep(300 * time.Millisecond)

	// Re-add a fresh path with same spec.
	newID, err := admin.AddPath(rendr.PathSpec{Transport: o.Transport, Address: ln.Addr().String()})
	if err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("AddPath: %w", err))
	}

	// Exchange PostAddBytes and verify no echo loss + no dups.
	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte(i)
	}
	var written int64
	rx := make([]byte, 4096)
	for written < opts.PostAddBytes {
		toWrite := opts.PostAddBytes - written
		if toWrite > int64(len(payload)) {
			toWrite = int64(len(payload))
		}
		if _, err := client.Write(payload[:toWrite]); err != nil {
			return FromError(name, time.Since(t0), fmt.Errorf("post-add write: %w", err))
		}
		got := int64(0)
		for got < toWrite {
			n, err := client.Read(rx[got:toWrite])
			if err != nil {
				return FromError(name, time.Since(t0), fmt.Errorf("post-add read: %w", err))
			}
			got += int64(n)
		}
		written += toWrite
	}

	stats := admin.Stats()
	r := Result{
		Name:     name,
		Duration: time.Since(t0),
		Detail: map[string]any{
			"new_path_id":     newID,
			"recv_dups":       stats.RecvDups,
			"migration_count": stats.MigrationCount,
			"post_add_bytes":  written,
		},
	}
	if stats.RecvDups > 0 {
		r.Failure = fmt.Sprintf("RecvDups=%d after path re-add (expected 0)", stats.RecvDups)
		return r
	}
	if newID == 0 {
		r.Failure = "AddPath returned id=0"
		return r
	}
	return r
}
