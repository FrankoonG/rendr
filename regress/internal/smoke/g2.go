package smoke

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"time"

	"github.com/FrankoonG/rendr"
)

// G2Opts configures one G2-smoke run. Defaults (30s / 5 migrations /
// 2 paths / tcp / prime / 100 ms cadence) match docs/regression-suite.md §6.
type G2Opts struct {
	Duration   time.Duration // default 30s
	Migrations int           // migrations; 0 defaults to 5, negative disables
	Paths      int           // default 2
	Transport  string        // default "tcp"
	Mode       rendr.Mode    // default ModePrime; ModeRace / ModeBond for matrix coverage
	Interval   time.Duration // echo cadence; default 100ms
	// P99CeilingMs caps P99 RTT. Default 200ms — generous for
	// loopback + Windows scheduler noise; CI Linux usually < 5ms.
	P99CeilingMs int
}

type g2Evidence struct {
	mode                  rendr.Mode
	migrationsRequested   int
	migrationCallsFired   int
	migrationCountBefore  uint64
	migrationCountAfter   uint64
	applicationDuplicates int
	recvDupsBefore        uint64
	recvDupsAfter         uint64
}

const g2MinimumCompletionPercent = 95

type g2RunEvidence struct {
	requestedDuration time.Duration
	observedDuration  time.Duration
	interval          time.Duration
	sent              int
	received          int
	contextErr        error
	operationErr      error
	receiverErr       error
	serverErr         error
}

func (e g2RunEvidence) expectedSamples() int {
	if e.requestedDuration <= 0 || e.interval <= 0 {
		return 0
	}
	return int(e.requestedDuration / e.interval)
}

func minimumG2Evidence(value int) int {
	if value <= 0 {
		return 0
	}
	return (value*g2MinimumCompletionPercent + 99) / 100
}

// validateG2RunEvidence separates invalid stimulus from product failures.
// Matching sender/receiver counts are insufficient: the run must also sustain
// at least 95% of its requested duration and offered echo schedule.
func validateG2RunEvidence(e g2RunEvidence) (invalidReason, failure string) {
	if e.operationErr != nil {
		return "", e.operationErr.Error()
	}
	if e.receiverErr != nil {
		return "", fmt.Sprintf("receiver exited before clean teardown: %v", e.receiverErr)
	}
	if e.serverErr != nil {
		return "", fmt.Sprintf("server echo exited before clean teardown: %v", e.serverErr)
	}
	if e.contextErr != nil {
		return fmt.Sprintf("run context ended before completion: %v", e.contextErr), ""
	}

	minimumDuration := e.requestedDuration * g2MinimumCompletionPercent / 100
	if e.observedDuration < minimumDuration {
		return fmt.Sprintf(
			"run duration %s below %d%% minimum %s (requested %s)",
			e.observedDuration, g2MinimumCompletionPercent, minimumDuration, e.requestedDuration,
		), ""
	}

	expectedSamples := e.expectedSamples()
	minimumSamples := minimumG2Evidence(expectedSamples)
	if e.sent < minimumSamples {
		return fmt.Sprintf(
			"offered echo samples=%d below %d%% minimum %d (expected %d for %s at %s cadence)",
			e.sent, g2MinimumCompletionPercent, minimumSamples, expectedSamples,
			e.requestedDuration, e.interval,
		), ""
	}
	if e.received < minimumSamples {
		return "", fmt.Sprintf(
			"received echo samples=%d below %d%% minimum %d (expected %d)",
			e.received, g2MinimumCompletionPercent, minimumSamples, expectedSamples,
		)
	}
	return "", ""
}

func isG2IntentionalTeardownError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func validateG2Evidence(e g2Evidence) (uint64, uint64, error) {
	migrations, err := validateRequestedMigrations(
		e.migrationsRequested,
		e.migrationCallsFired,
		e.migrationCountBefore,
		e.migrationCountAfter,
	)
	if err != nil {
		return migrations, 0, err
	}
	if e.applicationDuplicates != 0 {
		return migrations, 0, fmt.Errorf("application-visible duplicate echoes=%d, want 0", e.applicationDuplicates)
	}
	if e.recvDupsAfter < e.recvDupsBefore {
		return migrations, 0, fmt.Errorf("receive duplicate counter regressed from %d to %d", e.recvDupsBefore, e.recvDupsAfter)
	}
	recvDups := e.recvDupsAfter - e.recvDupsBefore
	if e.mode == rendr.ModeRace && recvDups == 0 {
		return migrations, recvDups, fmt.Errorf("race duplicate stimulus was not observed")
	}
	return migrations, recvDups, nil
}

func (o *G2Opts) withDefaults() {
	if o.Duration <= 0 {
		o.Duration = 30 * time.Second
	}
	if o.Migrations == 0 {
		o.Migrations = 5
	} else if o.Migrations < 0 {
		o.Migrations = 0
	}
	if o.Paths < 1 {
		o.Paths = 2
	}
	if o.Transport == "" {
		o.Transport = "tcp"
	}
	if o.Mode == 0 {
		o.Mode = rendr.ModePrime
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
// proves every requested migration fires. Race intentionally permits
// zero migrations, but must observe engine-level duplicate suppression
// without exposing duplicate echoes to the application. Detail keys:
//
//	echoes                  int
//	received_echoes         int
//	expected_echoes         int
//	minimum_echoes          int
//	requested_duration_ms   int64
//	observed_run_duration_ms int64
//	lost                    int
//	requested_migrations    int
//	migration_calls_fired   int
//	migrations              uint64
//	application_duplicates  int
//	recv_dups               uint64
//	recv_dups_observer      string
//	p50_ms                  float64
//	p99_ms                  float64
//	p999_ms                 float64
//	max_ms                  float64
func RunG2(ctx context.Context, opts G2Opts) Result {
	opts.withDefaults()
	t0 := time.Now()
	name := fmt.Sprintf("G2-smoke (%s/%s, %s, %d paths, ~%d migrations)",
		opts.Transport, modeName(opts.Mode), opts.Duration, opts.Paths, opts.Migrations)

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
	client, err := (&rendr.Dialer{Mode: opts.Mode, Paths: specs}).Dial(ctx)
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

	admin, ok := client.(rendr.AdminConn)
	if !ok {
		return FromError(name, time.Since(t0), fmt.Errorf("client conn is not rendr.AdminConn"))
	}
	serverAdmin, ok := server.(rendr.AdminConn)
	if !ok {
		return FromError(name, time.Since(t0), fmt.Errorf("server conn is not rendr.AdminConn"))
	}

	type goroutineResult struct {
		err     error
		endedAt time.Time
	}

	// Server echoes everything back; protocol is one 12-byte record
	// per ping: 4B seq + 8B unix-nanos send-time. Server returns the
	// same record verbatim. Every exit is reported and consumed below.
	echoResultCh := make(chan goroutineResult, 1)
	go func() {
		buf := make([]byte, 12)
		for {
			if _, err := io.ReadFull(server, buf); err != nil {
				echoResultCh <- goroutineResult{err: fmt.Errorf("read: %w", err), endedAt: time.Now()}
				return
			}
			n, err := server.Write(buf)
			if err != nil {
				echoResultCh <- goroutineResult{err: fmt.Errorf("write: %w", err), endedAt: time.Now()}
				return
			}
			if n != len(buf) {
				echoResultCh <- goroutineResult{
					err:     fmt.Errorf("write: %w (%d/%d bytes)", io.ErrShortWrite, n, len(buf)),
					endedAt: time.Now(),
				}
				return
			}
		}
	}()

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
	// Mode is sender-local. A client race duplicates client TX frames, so the
	// independent proof lives on the peer/server RX engine, not client RX.
	startRecvDups := serverAdmin.RecvDups()
	var migrationCallsFired int
	rtts := make([]time.Duration, 0, int(opts.Duration/opts.Interval)+2)
	runStarted := time.Now()
	deadline := runStarted.Add(opts.Duration)
	runTimer := time.NewTimer(opts.Duration)
	defer runTimer.Stop()
	tick := time.NewTicker(opts.Interval)
	defer tick.Stop()

	// Receiver: collect echoes into a slice owned by the goroutine.
	// The previous implementation used `make(chan echo, 1024)` which
	// deadlocked any run that emitted >1024 echoes: recv blocks on
	// chan-send, main blocks on <-doneRecv, no one drains the chan.
	// Smoke (300 echoes) stayed under the buffer; T4 (18000 echoes
	// at 30min) hit it at echo 1024 and the run hung indefinitely.
	// The single result-channel send is the ownership handoff and
	// happens-before fence for the receiver-owned slice.
	type echo struct {
		seq int32
		rtt time.Duration
	}
	type receiverResult struct {
		goroutineResult
		echoes []echo
	}
	receiverResultCh := make(chan receiverResult, 1)
	go func() {
		echoes := make([]echo, 0, int(opts.Duration/opts.Interval)+128)
		finish := func(err error) {
			receiverResultCh <- receiverResult{
				goroutineResult: goroutineResult{err: err, endedAt: time.Now()},
				echoes:          echoes,
			}
		}
		if err := client.SetReadDeadline(deadline.Add(5 * time.Second)); err != nil {
			finish(fmt.Errorf("set read deadline: %w", err))
			return
		}
		buf := make([]byte, 12)
		for {
			if _, err := io.ReadFull(client, buf); err != nil {
				finish(fmt.Errorf("read: %w", err))
				return
			}
			seq := int32(binary.BigEndian.Uint32(buf[:4]))
			sentNs := int64(binary.BigEndian.Uint64(buf[4:]))
			rtt := time.Duration(time.Now().UnixNano() - sentNs)
			echoes = append(echoes, echo{seq: seq, rtt: rtt})
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
	var contextErr error
	var operationErr error
	var receiverResultValue receiverResult
	var receiverDone bool
	var echoResult goroutineResult
	var echoDone bool
runLoop:
	for {
		select {
		case <-tick.C:
			seq++
			buf := make([]byte, 12)
			binary.BigEndian.PutUint32(buf[:4], uint32(seq))
			binary.BigEndian.PutUint64(buf[4:], uint64(time.Now().UnixNano()))
			if err := client.SetWriteDeadline(time.Now().Add(writeDeadline)); err != nil {
				operationErr = fmt.Errorf("set write deadline for seq %d: %w", seq, err)
				break runLoop
			}
			n, err := client.Write(buf)
			if err != nil {
				operationErr = fmt.Errorf("write seq %d: %w", seq, err)
				break runLoop
			}
			if n != len(buf) {
				operationErr = fmt.Errorf("write seq %d: %w (%d/%d bytes)", seq, io.ErrShortWrite, n, len(buf))
				break runLoop
			}
			if err := client.SetWriteDeadline(time.Time{}); err != nil {
				operationErr = fmt.Errorf("clear write deadline for seq %d: %w", seq, err)
				break runLoop
			}
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
			var target uint32
			for _, p := range client.Paths() {
				if p.ID != cur {
					target = p.ID
					break
				}
			}
			if target == 0 {
				operationErr = fmt.Errorf("migration %d: no alternate path", migrationCallsFired+1)
				break runLoop
			}
			if err := admin.Migrate(target); err != nil {
				operationErr = fmt.Errorf("migration %d: %w", migrationCallsFired+1, err)
				break runLoop
			}
			migrationCallsFired++
			if migrationCallsFired == opts.Migrations {
				migTicker.Stop()
				migTicker = nil
			}
		case receiverResultValue = <-receiverResultCh:
			receiverDone = true
			break runLoop
		case echoResult = <-echoResultCh:
			echoDone = true
			break runLoop
		case <-ctx.Done():
			contextErr = ctx.Err()
			break runLoop
		case <-runTimer.C:
			break runLoop
		}
	}
	runElapsed := time.Since(runStarted)

	// Give the receiver a moment to drain in-flight echoes, then
	// force its ReadFull to return via the read deadline. Any goroutine
	// exit timestamped before teardown is evidence of an early failure.
	if contextErr == nil && operationErr == nil && !receiverDone && !echoDone {
		drainTimer := time.NewTimer(500 * time.Millisecond)
		select {
		case receiverResultValue = <-receiverResultCh:
			receiverDone = true
		case echoResult = <-echoResultCh:
			echoDone = true
		case <-drainTimer.C:
		}
		if !drainTimer.Stop() {
			select {
			case <-drainTimer.C:
			default:
			}
		}
	}

	teardownStarted := time.Now()
	if !receiverDone {
		if err := client.SetReadDeadline(teardownStarted); err != nil {
			operationErr = errors.Join(operationErr, fmt.Errorf("set receiver teardown deadline: %w", err))
		}
		select {
		case receiverResultValue = <-receiverResultCh:
			receiverDone = true
		case <-time.After(5 * time.Second):
			operationErr = errors.Join(operationErr, fmt.Errorf("receiver did not stop within teardown timeout"))
		}
	}

	endMigCount := admin.MigrationCount()
	endRecvDups := serverAdmin.RecvDups()
	_ = client.Close()
	_ = server.Close()
	if !echoDone {
		select {
		case echoResult = <-echoResultCh:
			echoDone = true
		case <-time.After(5 * time.Second):
			operationErr = errors.Join(operationErr, fmt.Errorf("server echo goroutine did not stop within teardown timeout"))
		}
	}

	var receiverErr error
	echoBuf := receiverResultValue.echoes
	if receiverDone {
		if receiverResultValue.endedAt.Before(teardownStarted) {
			receiverErr = receiverResultValue.err
		} else if !isG2IntentionalTeardownError(receiverResultValue.err) {
			receiverErr = receiverResultValue.err
		}
	}
	var serverErr error
	if echoDone {
		if echoResult.endedAt.Before(teardownStarted) {
			serverErr = echoResult.err
		} else if !isG2IntentionalTeardownError(echoResult.err) {
			serverErr = echoResult.err
		}
	}

	received := map[int32]time.Duration{}
	applicationDuplicates := 0
	unexpected := 0
	for _, e := range echoBuf {
		if _, ok := sent[e.seq]; !ok {
			unexpected++
		}
		if _, ok := received[e.seq]; ok {
			applicationDuplicates++
		} else {
			received[e.seq] = e.rtt
		}
		rtts = append(rtts, e.rtt)
	}

	lost := 0
	for s := range sent {
		if _, ok := received[s]; !ok {
			lost++
		}
	}

	var p50, p99, p999, maxRTT time.Duration
	if len(rtts) > 0 {
		sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
		p50 = rtts[len(rtts)*50/100]
		p99 = rtts[len(rtts)*99/100]
		p999 = rtts[len(rtts)*999/1000]
		if p999 == 0 {
			p999 = rtts[len(rtts)-1]
		}
		maxRTT = rtts[len(rtts)-1]
	}

	migrated, recvDups, evidenceErr := validateG2Evidence(g2Evidence{
		mode:                  opts.Mode,
		migrationsRequested:   opts.Migrations,
		migrationCallsFired:   migrationCallsFired,
		migrationCountBefore:  startMigCount,
		migrationCountAfter:   endMigCount,
		applicationDuplicates: applicationDuplicates,
		recvDupsBefore:        startRecvDups,
		recvDupsAfter:         endRecvDups,
	})
	expectedEchoes := int(opts.Duration / opts.Interval)
	minimumEchoes := minimumG2Evidence(expectedEchoes)
	r := Result{
		Name:     name,
		Duration: time.Since(t0),
		Detail: map[string]any{
			"echoes":                   len(sent),
			"received_echoes":          len(received),
			"expected_echoes":          expectedEchoes,
			"minimum_echoes":           minimumEchoes,
			"requested_duration_ms":    opts.Duration.Milliseconds(),
			"observed_run_duration_ms": runElapsed.Milliseconds(),
			"lost":                     lost,
			"requested_migrations":     opts.Migrations,
			"migration_calls_fired":    migrationCallsFired,
			"migrations":               migrated,
			"application_duplicates":   applicationDuplicates,
			"recv_dups":                recvDups,
			"recv_dups_observer":       "peer_server_rx",
			"p50_ms":                   float64(p50) / float64(time.Millisecond),
			"p99_ms":                   float64(p99) / float64(time.Millisecond),
			"p999_ms":                  float64(p999) / float64(time.Millisecond),
			"max_ms":                   float64(maxRTT) / float64(time.Millisecond),
		},
	}
	invalidReason, runFailure := validateG2RunEvidence(g2RunEvidence{
		requestedDuration: opts.Duration,
		observedDuration:  runElapsed,
		interval:          opts.Interval,
		sent:              len(sent),
		received:          len(received),
		contextErr:        contextErr,
		operationErr:      operationErr,
		receiverErr:       receiverErr,
		serverErr:         serverErr,
	})
	if invalidReason != "" {
		r.InvalidReason = invalidReason
		return r
	}
	if runFailure != "" {
		r.Failure = runFailure
		return r
	}
	if len(rtts) == 0 {
		r.Failure = "no echoes received"
		return r
	}
	if unexpected > 0 {
		r.Failure = fmt.Sprintf("unexpected echo sequences: %d", unexpected)
		return r
	}
	if lost > 0 {
		r.Failure = fmt.Sprintf("echo loss: %d / %d", lost, len(sent))
		return r
	}
	if int(p99/time.Millisecond) > opts.P99CeilingMs {
		r.Failure = fmt.Sprintf("P99 RTT %.1fms exceeds ceiling %dms", float64(p99)/float64(time.Millisecond), opts.P99CeilingMs)
		return r
	}
	if evidenceErr != nil {
		r.Failure = evidenceErr.Error()
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

// modeName returns a short string suitable for the case-name suffix.
func modeName(m rendr.Mode) string {
	switch m {
	case rendr.ModePrime:
		return "prime"
	case rendr.ModeBond:
		return "bond"
	case rendr.ModeRace:
		return "race"
	default:
		return fmt.Sprintf("mode%d", m)
	}
}
