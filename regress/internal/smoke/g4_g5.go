package smoke

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/FrankoonG/rendr"
)

// G4Opts configures one G4 case (path-A force-kill, verify B picks
// up < 5s, app sees no error). Cross-platform: uses rendr's
// ForceKillPathForTest engine backdoor, not iptables.
type G4Opts struct {
	Duration  time.Duration // default 6s
	KillAt    time.Duration // default 2s
	EchoInt   time.Duration // default 10ms
	Paths     int           // default 2
	BudgetMs  int           // failover ceiling; default 5000
	Transport string        // "tcp" | "quic"; default "tcp"
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

type g4KillOutcome struct {
	at  time.Time
	err error
}

func validateG4Evidence(killErr error, killAt, firstPostKill time.Time, postKillSamples int, budget time.Duration) (time.Duration, error) {
	if killErr != nil {
		return 0, fmt.Errorf("kill stimulus failed: %w", killErr)
	}
	if killAt.IsZero() {
		return 0, fmt.Errorf("kill stimulus timestamp was not observed")
	}
	if firstPostKill.IsZero() {
		return 0, fmt.Errorf("post-kill delivery timestamp was not observed")
	}
	if postKillSamples <= 0 {
		return 0, fmt.Errorf("post-kill delivery samples=%d, want > 0", postKillSamples)
	}
	if firstPostKill.Before(killAt) {
		return 0, fmt.Errorf("post-kill delivery timestamp precedes kill stimulus")
	}
	failover := firstPostKill.Sub(killAt)
	if failover > budget {
		return failover, fmt.Errorf("failover %dms exceeds %dms budget", failover.Milliseconds(), budget.Milliseconds())
	}
	return failover, nil
}

// RunG4 returns Result with Detail keys:
//
//	echoes              int
//	application_lost    int
//	kill_observed       bool
//	post_kill_samples   int
//	failover_ms         int64
//	max_rtt_ms          float64
func RunG4(ctx context.Context, opts G4Opts) Result {
	opts.withDefaults()
	t0 := time.Now()
	name := fmt.Sprintf("G4 (%s, kill@%s, budget %dms)", opts.Transport, opts.KillAt, opts.BudgetMs)

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

	killer, ok := client.(interface {
		ForceKillPathForTest(id uint32) error
	})
	if !ok {
		return FromError(name, time.Since(t0), fmt.Errorf("rendr.Conn lacks ForceKillPathForTest test hook"))
	}

	killDone := make(chan g4KillOutcome, 1)
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(opts.KillAt):
		}
		cur := admin.ActivePath()
		if cur == 0 {
			killDone <- g4KillOutcome{err: fmt.Errorf("no active path to kill")}
			return
		}
		if err := killer.ForceKillPathForTest(cur); err != nil {
			killDone <- g4KillOutcome{err: err}
			return
		}
		killDone <- g4KillOutcome{at: time.Now()}
	}()

	start := time.Now()
	endAt := start.Add(opts.Duration)
	var counter uint64
	rxbuf := make([]byte, 8)
	var killErr error
	var killStamp time.Time
	var firstPostKill time.Time
	var postKillSamples int
	var lost int
	var maxRTT time.Duration
	var cause string
	recordKill := func(out g4KillOutcome) {
		killStamp = out.at
		killErr = out.err
		killDone = nil
	}
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
		echoEnd := time.Now()
		rtt := echoEnd.Sub(echoStart)
		if rtt > maxRTT {
			maxRTT = rtt
		}
		select {
		case out := <-killDone:
			recordKill(out)
		default:
		}
		if !killStamp.IsZero() && !echoEnd.Before(killStamp) {
			postKillSamples++
			if firstPostKill.IsZero() {
				firstPostKill = echoEnd
			}
		}
		counter++
		if opts.EchoInt > 0 {
			time.Sleep(opts.EchoInt)
		}
	}

	if killDone != nil {
		select {
		case out := <-killDone:
			recordKill(out)
		default:
		}
	}
	failover, evidenceErr := validateG4Evidence(
		killErr,
		killStamp,
		firstPostKill,
		postKillSamples,
		time.Duration(opts.BudgetMs)*time.Millisecond,
	)
	failoverMs := failover.Milliseconds()

	r := Result{
		Name:     name,
		Duration: time.Since(t0),
		Detail: map[string]any{
			"echoes":            int(counter),
			"application_lost":  lost,
			"kill_observed":     !killStamp.IsZero() && killErr == nil,
			"post_kill_samples": postKillSamples,
			"failover_ms":       failoverMs,
			"max_rtt_ms":        float64(maxRTT) / float64(time.Millisecond),
		},
	}
	if evidenceErr != nil {
		r.Failure = evidenceErr.Error()
		return r
	}
	if cause != "" {
		r.Failure = cause
		return r
	}
	if lost > 0 {
		r.Failure = fmt.Sprintf("application-visible echo loss: %d", lost)
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

func validateG5Payload(offset int64, sent, received []byte) error {
	if len(sent) != len(received) {
		return fmt.Errorf("post-recovery payload length at offset %d: sent=%d received=%d", offset, len(sent), len(received))
	}
	if bytes.Equal(sent, received) {
		return nil
	}
	for i := range sent {
		if sent[i] != received[i] {
			return fmt.Errorf("post-recovery payload mismatch at offset %d: sent=%02x received=%02x", offset+int64(i), sent[i], received[i])
		}
	}
	return fmt.Errorf("post-recovery payload mismatch at offset %d", offset)
}

func pathInfoByID(paths []rendr.PathInfo, id uint32) (rendr.PathInfo, bool) {
	for _, path := range paths {
		if path.ID == id {
			return path, true
		}
	}
	return rendr.PathInfo{}, false
}

func validateRecoveredPathProgress(newID, activeID uint32, before, after rendr.PathInfo) error {
	if newID == 0 {
		return fmt.Errorf("AddPath returned id=0")
	}
	if before.ID != newID || after.ID != newID {
		return fmt.Errorf("recovered path %d was not present in both traffic snapshots", newID)
	}
	if activeID != newID {
		return fmt.Errorf("active path after recovery traffic=%d, want recovered path %d", activeID, newID)
	}
	if after.Writes <= before.Writes {
		return fmt.Errorf("recovered path %d writes did not advance: before=%d after=%d", newID, before.Writes, after.Writes)
	}
	if after.LastSendAt.IsZero() || !after.LastSendAt.After(before.LastSendAt) {
		return fmt.Errorf("recovered path %d last-send timestamp did not advance", newID)
	}
	return nil
}

// RunG5 runs G4-style failover, then AddPath the killed transport
// back and writes PostAddBytes more bytes. Asserts:
//   - AddPath returns a fresh id
//   - RecvDups stays 0 (no reorder artifacts)
//   - bytes round-trip intact by direct comparison
//   - the recovered path's write counter advances during the payload
func RunG5(ctx context.Context, opts G5Opts) Result {
	o := opts.G4
	o.withDefaults()
	if opts.PostAddBytes <= 0 {
		opts.PostAddBytes = 256 << 10
	}
	t0 := time.Now()
	name := fmt.Sprintf("G5 (after G4: AddPath + %d byte exchange)", opts.PostAddBytes)

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
	killer, ok := client.(interface {
		ForceKillPathForTest(id uint32) error
	})
	if !ok {
		return FromError(name, time.Since(t0), fmt.Errorf("rendr.Conn lacks ForceKillPathForTest test hook"))
	}
	originalPathIDs := make(map[uint32]struct{}, len(client.Paths()))
	for _, path := range client.Paths() {
		originalPathIDs[path.ID] = struct{}{}
	}

	// Kill the active path immediately.
	cur := admin.ActivePath()
	if cur == 0 {
		return FromError(name, time.Since(t0), fmt.Errorf("no active path to kill"))
	}
	if err := killer.ForceKillPathForTest(cur); err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("kill active: %w", err))
	}

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
	if newID == 0 {
		return FromError(name, time.Since(t0), fmt.Errorf("AddPath returned id=0"))
	}
	if _, existed := originalPathIDs[newID]; existed {
		return FromError(name, time.Since(t0), fmt.Errorf("AddPath reused existing path id %d", newID))
	}
	if err := admin.Migrate(newID); err != nil {
		return FromError(name, time.Since(t0), fmt.Errorf("migrate to recovered path %d: %w", newID, err))
	}
	if active := admin.ActivePath(); active != newID {
		return FromError(name, time.Since(t0), fmt.Errorf("active path after recovered-path migration=%d, want %d", active, newID))
	}

	// Migrate emits its control frame asynchronously. Let that frame
	// settle before taking the baseline so only the payload window is
	// credited as recovered-path traffic.
	time.Sleep(50 * time.Millisecond)
	pathBefore, ok := pathInfoByID(client.Paths(), newID)
	if !ok {
		return FromError(name, time.Since(t0), fmt.Errorf("recovered path %d missing before payload", newID))
	}

	// Exchange PostAddBytes and verify no echo loss + no dups.
	payload := make([]byte, 4096)
	var written int64
	rx := make([]byte, 4096)
	for written < opts.PostAddBytes {
		toWrite := opts.PostAddBytes - written
		if toWrite > int64(len(payload)) {
			toWrite = int64(len(payload))
		}
		fillG1Pattern(payload[:toWrite], written)
		n, err := client.Write(payload[:toWrite])
		if err != nil {
			return FromError(name, time.Since(t0), fmt.Errorf("post-add write: %w", err))
		}
		if int64(n) != toWrite {
			return FromError(name, time.Since(t0), fmt.Errorf("post-add short write: got=%d want=%d", n, toWrite))
		}
		got := int64(0)
		for got < toWrite {
			n, err := client.Read(rx[got:toWrite])
			if err != nil {
				return FromError(name, time.Since(t0), fmt.Errorf("post-add read: %w", err))
			}
			got += int64(n)
		}
		if err := validateG5Payload(written, payload[:toWrite], rx[:toWrite]); err != nil {
			return FromError(name, time.Since(t0), err)
		}
		written += toWrite
	}

	stats := admin.Stats()
	pathAfter, ok := pathInfoByID(stats.Paths, newID)
	if !ok {
		return FromError(name, time.Since(t0), fmt.Errorf("recovered path %d missing after payload", newID))
	}
	progressErr := validateRecoveredPathProgress(newID, stats.ActivePath, pathBefore, pathAfter)
	r := Result{
		Name:     name,
		Duration: time.Since(t0),
		Detail: map[string]any{
			"new_path_id":            newID,
			"new_path_writes_before": pathBefore.Writes,
			"new_path_writes_after":  pathAfter.Writes,
			"new_path_write_delta":   pathAfter.Writes - pathBefore.Writes,
			"recv_dups":              stats.RecvDups,
			"migration_count":        stats.MigrationCount,
			"post_add_bytes":         written,
			"payload_match":          true,
		},
	}
	if stats.RecvDups > 0 {
		r.Failure = fmt.Sprintf("RecvDups=%d after path re-add (expected 0)", stats.RecvDups)
		return r
	}
	if progressErr != nil {
		r.Failure = progressErr.Error()
		return r
	}
	return r
}
