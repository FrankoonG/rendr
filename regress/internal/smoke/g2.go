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

const (
	g2P99MinimumSamples  = 1_000
	g2P999MinimumSamples = 10_000
	g2P999Ceiling        = time.Second
)

type g2RunEvidence struct {
	requestedDuration time.Duration
	observedDuration  time.Duration
	interval          time.Duration
	planned           int
	scheduled         int
	writeCompleted    int
	received          int
	unoffered         int
	transportLost     int
	contextErr        error
	operationErr      error
	receiverErr       error
	serverErr         error
}

func (e g2RunEvidence) expectedSamples() int {
	return plannedG2Samples(e.requestedDuration, e.interval)
}

func plannedG2Samples(duration, interval time.Duration) int {
	if duration <= 0 || interval <= 0 {
		return 0
	}
	// Slots are [0, duration), so an exact multiple ends one interval before
	// the endpoint and a partial final interval still has one planned slot.
	return int((duration-1)/interval) + 1
}

type g2WriteRequest struct {
	seq       int32
	plannedAt time.Time
}

type g2WriteResult struct {
	request      g2WriteRequest
	writeStarted time.Time
	completed    bool
	err          error
}

type g2SlotScheduler struct {
	start      time.Time
	interval   time.Duration
	planned    int
	next       int
	scheduled  int
	latenesses []time.Duration
}

func newG2SlotScheduler(start time.Time, duration, interval time.Duration) *g2SlotScheduler {
	planned := plannedG2Samples(duration, interval)
	return &g2SlotScheduler{
		start:      start,
		interval:   interval,
		planned:    planned,
		latenesses: make([]time.Duration, 0, planned),
	}
}

// offerDue evaluates every absolute slot up to now. It never waits for the
// sender: a busy sender leaves the slot explicitly unoffered instead of letting
// a time.Ticker coalesce and hide it.
func (s *g2SlotScheduler) offerDue(now time.Time, requests chan<- g2WriteRequest) {
	for s.next < s.planned {
		plannedAt := s.start.Add(time.Duration(s.next) * s.interval)
		if plannedAt.After(now) {
			return
		}
		lateness := now.Sub(plannedAt)
		if lateness < 0 {
			lateness = 0
		}
		s.latenesses = append(s.latenesses, lateness)
		request := g2WriteRequest{
			seq:       int32(s.next + 1),
			plannedAt: plannedAt,
		}
		select {
		case requests <- request:
			s.scheduled++
		default:
		}
		s.next++
	}
}

func (s *g2SlotScheduler) nextDelay(now time.Time) (time.Duration, bool) {
	if s.next >= s.planned {
		return 0, false
	}
	delay := s.start.Add(time.Duration(s.next) * s.interval).Sub(now)
	if delay < 0 {
		delay = 0
	}
	return delay, true
}

func (s *g2SlotScheduler) unoffered() int {
	return s.planned - s.scheduled
}

// validateG2RunEvidence separates invalid stimulus from product failures.
// Every planned slot must be scheduled, written, and echoed exactly once.
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

	if e.observedDuration < e.requestedDuration {
		return fmt.Sprintf(
			"run duration %s ended before requested endpoint %s",
			e.observedDuration, e.requestedDuration,
		), ""
	}

	expectedSamples := e.expectedSamples()
	if expectedSamples <= 0 {
		return fmt.Sprintf("invalid G2 schedule duration=%s interval=%s", e.requestedDuration, e.interval), ""
	}
	if e.planned != expectedSamples {
		return fmt.Sprintf(
			"planned echo slots=%d, want exact schedule %d for %s at %s cadence",
			e.planned, expectedSamples, e.requestedDuration, e.interval,
		), ""
	}
	if e.scheduled < 0 || e.scheduled > e.planned {
		return fmt.Sprintf("scheduled echo slots=%d outside planned range [0,%d]", e.scheduled, e.planned), ""
	}
	wantUnoffered := e.planned - e.scheduled
	if e.unoffered != wantUnoffered {
		return fmt.Sprintf("unoffered echo slots=%d, counter arithmetic wants %d", e.unoffered, wantUnoffered), ""
	}
	if e.unoffered != 0 {
		return fmt.Sprintf(
			"unoffered echo slots=%d (planned=%d scheduled=%d); sender/evaluator did not establish exact load",
			e.unoffered, e.planned, e.scheduled,
		), ""
	}
	if e.writeCompleted < 0 || e.writeCompleted > e.scheduled {
		return fmt.Sprintf("write-completed echoes=%d outside scheduled range [0,%d]", e.writeCompleted, e.scheduled), ""
	}
	if e.writeCompleted != e.scheduled {
		return "", fmt.Sprintf(
			"write-completed echoes=%d, want scheduled=%d",
			e.writeCompleted, e.scheduled,
		)
	}
	if e.received < 0 || e.received > e.writeCompleted {
		return fmt.Sprintf("received echoes=%d outside write-completed range [0,%d]", e.received, e.writeCompleted), ""
	}
	wantTransportLost := e.writeCompleted - e.received
	if e.transportLost != wantTransportLost {
		return fmt.Sprintf("transport-lost echoes=%d, counter arithmetic wants %d", e.transportLost, wantTransportLost), ""
	}
	if e.transportLost != 0 {
		return "", fmt.Sprintf(
			"transport-lost echoes=%d (write-completed=%d received=%d), want 0",
			e.transportLost, e.writeCompleted, e.received,
		)
	}
	return "", ""
}

func validateG2Latency(sampleCount int, p99, p999, p99Ceiling time.Duration) (p99Qualified, p999Qualified bool, failure string) {
	p99Qualified = sampleCount >= g2P99MinimumSamples
	p999Qualified = sampleCount >= g2P999MinimumSamples
	if p99Qualified && p99 >= p99Ceiling {
		return p99Qualified, p999Qualified, fmt.Sprintf(
			"P99 RTT %.3fms does not satisfy strict ceiling < %.3fms",
			float64(p99)/float64(time.Millisecond), float64(p99Ceiling)/float64(time.Millisecond),
		)
	}
	if p999Qualified && p999 >= g2P999Ceiling {
		return p99Qualified, p999Qualified, fmt.Sprintf(
			"P99.9 RTT %.3fms does not satisfy strict ceiling < %.3fms",
			float64(p999)/float64(time.Millisecond), float64(g2P999Ceiling)/float64(time.Millisecond),
		)
	}
	return p99Qualified, p999Qualified, ""
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

// RunG2 drives a long-lived echo loop with periodic migrations and exact
// application-load accounting. P99 remains diagnostic below 1,000 samples;
// qualified runs enforce the configured ceiling. Race intentionally permits
// zero migrations, but must observe engine-level duplicate suppression without
// exposing duplicate echoes to the application. Detail keys include:
//
//	planned_echoes/scheduled_echoes/write_completed_echoes int
//	unoffered_echoes/transport_lost_echoes                 int
//	requested_duration_ms/observed_run_duration_ms         int64
//	schedule_lateness_p99_ms/schedule_lateness_max_ms      float64
//	blackout_ms/migration_blackout_ms                      float64
//	latency_samples/p99_qualified/p999_qualified           mixed
//	p50_ms/p99_ms/p999_ms/max_ms                           float64
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

	// Server echoes everything back; protocol is one 12-byte record per ping.
	// Every exit is reported and consumed below.
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

	startMigCount := admin.MigrationCount()
	// Mode is sender-local. A client race duplicates client TX frames, so the
	// independent proof lives on the peer/server RX engine, not client RX.
	startRecvDups := serverAdmin.RecvDups()
	var migrationCallsFired int
	migrationTimes := make([]time.Time, 0, opts.Migrations)
	runStarted := time.Now()
	deadline := runStarted.Add(opts.Duration)
	runTimer := time.NewTimer(time.Until(deadline))
	defer stopG2Timer(runTimer)

	scheduler := newG2SlotScheduler(runStarted, opts.Duration, opts.Interval)
	writeRequests := make(chan g2WriteRequest, 1)
	writeResults := make(chan g2WriteResult, 4)
	senderDone := make(chan struct{})
	go runG2Sender(client, deadline, writeRequests, writeResults, senderDone)

	slotTimer := time.NewTimer(0)
	defer stopG2Timer(slotTimer)
	var migrationTimer *time.Timer
	if opts.Migrations > 0 {
		migrationTimer = time.NewTimer(g2MigrationTime(runStarted, opts.Duration, 0, opts.Migrations).Sub(time.Now()))
		defer stopG2Timer(migrationTimer)
	}

	// Receiver: collect echoes into a slice owned by the goroutine.
	// The previous implementation used `make(chan echo, 1024)` which
	// deadlocked any run that emitted >1024 echoes: recv blocks on
	// chan-send, main blocks on <-doneRecv, no one drains the chan.
	// Smoke (300 echoes) stayed under the buffer; T4 (18000 echoes
	// at 30min) hit it at echo 1024 and the run hung indefinitely.
	// The single result-channel send is the ownership handoff and
	// happens-before fence for the receiver-owned slice.
	type echo struct {
		seq        int32
		receivedAt time.Time
	}
	type receiverResult struct {
		goroutineResult
		echoes []echo
	}
	receiverResultCh := make(chan receiverResult, 1)
	go func() {
		echoes := make([]echo, 0, scheduler.planned+128)
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
			echoes = append(echoes, echo{seq: seq, receivedAt: time.Now()})
		}
	}()

	writes := make(map[int32]g2WriteResult, scheduler.planned)
	writeStartLateness := make([]time.Duration, 0, scheduler.planned)
	lastProgress := time.Now()
	var contextErr error
	var operationErr error
	var receiverResultValue receiverResult
	var receiverDone bool
	var echoResult goroutineResult
	var echoDone bool
	var senderFinished bool

	recordWriteResult := func(result g2WriteResult) {
		if !result.writeStarted.IsZero() {
			lateness := result.writeStarted.Sub(result.request.plannedAt)
			if lateness < 0 {
				lateness = 0
			}
			writeStartLateness = append(writeStartLateness, lateness)
		}
		if result.completed {
			if _, exists := writes[result.request.seq]; exists {
				operationErr = errors.Join(operationErr, fmt.Errorf("duplicate write completion for seq %d", result.request.seq))
			} else {
				writes[result.request.seq] = result
			}
		}
		if result.err != nil {
			operationErr = errors.Join(operationErr, result.err)
		}
	}

	resetSlotTimer := func() {
		if delay, ok := scheduler.nextDelay(time.Now()); ok {
			resetG2Timer(slotTimer, delay)
			return
		}
		stopG2Timer(slotTimer)
		slotTimer = nil
	}
	resetMigrationTimer := func() {
		if migrationCallsFired >= opts.Migrations {
			stopG2Timer(migrationTimer)
			migrationTimer = nil
			return
		}
		next := g2MigrationTime(runStarted, opts.Duration, migrationCallsFired, opts.Migrations)
		resetG2Timer(migrationTimer, next.Sub(time.Now()))
	}
	fireMigration := func() error {
		cur := admin.ActivePath()
		var target uint32
		for _, p := range client.Paths() {
			if p.ID != cur {
				target = p.ID
				break
			}
		}
		if target == 0 {
			return fmt.Errorf("migration %d: no alternate path", migrationCallsFired+1)
		}
		if err := admin.Migrate(target); err != nil {
			return fmt.Errorf("migration %d: %w", migrationCallsFired+1, err)
		}
		migrationCallsFired++
		migrationTimes = append(migrationTimes, time.Now())
		return nil
	}

runLoop:
	for {
		select {
		case <-g2TimerChan(slotTimer):
			scheduler.offerDue(time.Now(), writeRequests)
			resetSlotTimer()
			// Coarse progress beacon for T4-scale long runs.
			if opts.Duration > 60*time.Second && time.Since(lastProgress) >= 30*time.Second {
				lastProgress = time.Now()
				fmt.Printf("    G2 progress: t=%s planned=%d scheduled=%d written=%d migrations=%d\n",
					time.Since(t0).Truncate(time.Second), scheduler.next, scheduler.scheduled, len(writes),
					admin.MigrationCount()-startMigCount)
			}
		case result := <-writeResults:
			recordWriteResult(result)
			if operationErr != nil {
				break runLoop
			}
		case <-g2TimerChan(migrationTimer):
			now := time.Now()
			for migrationCallsFired < opts.Migrations &&
				!g2MigrationTime(runStarted, opts.Duration, migrationCallsFired, opts.Migrations).After(now) {
				if err := fireMigration(); err != nil {
					operationErr = err
					break runLoop
				}
			}
			resetMigrationTimer()
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
			// If the endpoint wins a select against an already-due slot timer,
			// account every remaining slot explicitly before evaluation.
			scheduler.offerDue(time.Now(), writeRequests)
			break runLoop
		}
	}
	runElapsed := time.Since(runStarted)

	close(writeRequests)
	if err := client.SetWriteDeadline(time.Now()); err != nil {
		operationErr = errors.Join(operationErr, fmt.Errorf("set sender teardown deadline: %w", err))
	}
	senderTimer := time.NewTimer(5 * time.Second)
	senderForcedClosed := false
	for !senderFinished {
		select {
		case result := <-writeResults:
			recordWriteResult(result)
		case <-senderDone:
			senderFinished = true
		case <-senderTimer.C:
			if !senderForcedClosed {
				operationErr = errors.Join(operationErr, fmt.Errorf("sender did not stop within teardown timeout; forcing connection close"))
				_ = client.Close()
				senderForcedClosed = true
				resetG2Timer(senderTimer, 5*time.Second)
				continue
			}
			operationErr = errors.Join(operationErr, fmt.Errorf("sender did not stop after forced connection close"))
			senderFinished = true
		}
	}
	stopG2Timer(senderTimer)
	for {
		select {
		case result := <-writeResults:
			recordWriteResult(result)
		default:
			goto senderResultsDrained
		}
	}

senderResultsDrained:

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

	received := make(map[int32]time.Time, len(writes))
	rtts := make([]time.Duration, 0, len(writes))
	deliveryTimes := make([]time.Time, 0, len(writes))
	applicationDuplicates := 0
	unexpected := 0
	for _, e := range echoBuf {
		write, ok := writes[e.seq]
		if !ok {
			unexpected++
			continue
		}
		if _, ok := received[e.seq]; ok {
			applicationDuplicates++
		} else {
			received[e.seq] = e.receivedAt
			rtt := e.receivedAt.Sub(write.writeStarted)
			if rtt < 0 {
				unexpected++
				continue
			}
			rtts = append(rtts, rtt)
			deliveryTimes = append(deliveryTimes, e.receivedAt)
		}
	}

	transportLost := 0
	for s := range writes {
		if _, ok := received[s]; !ok {
			transportLost++
		}
	}

	p50, p99, p999, maxRTT := g2DurationStats(rtts)
	_, scheduleP99, _, scheduleMax := g2DurationStats(scheduler.latenesses)
	_, writeStartP99, _, writeStartMax := g2DurationStats(writeStartLateness)
	blackout := g2MaxBlackout(runStarted, deadline, deliveryTimes)
	migrationBlackout := g2MaxStimulusBlackout(migrationTimes, deadline, deliveryTimes)
	p99Ceiling := time.Duration(opts.P99CeilingMs) * time.Millisecond
	p99Qualified, p999Qualified, latencyFailure := validateG2Latency(
		len(rtts), p99, p999, p99Ceiling,
	)
	latencyEvidence := "diagnostic"
	if p99Qualified {
		latencyEvidence = "qualified"
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
	r := Result{
		Name:     name,
		Duration: time.Since(t0),
		Detail: map[string]any{
			"measurement_started_unix_ns":  runStarted.UnixNano(),
			"measurement_finished_unix_ns": runStarted.Add(runElapsed).UnixNano(),
			"interval_ns":                  opts.Interval.Nanoseconds(),
			"mode":                         modeName(opts.Mode),
			"transport":                    opts.Transport,
			"paths":                        opts.Paths,
			"echoes":                       len(writes),
			"received_echoes":              len(received),
			"expected_echoes":              scheduler.planned,
			"planned_echoes":               scheduler.planned,
			"scheduled_echoes":             scheduler.scheduled,
			"write_completed_echoes":       len(writes),
			"unoffered_echoes":             scheduler.unoffered(),
			"transport_lost_echoes":        transportLost,
			"requested_duration_ms":        opts.Duration.Milliseconds(),
			"observed_run_duration_ms":     runElapsed.Milliseconds(),
			"lost":                         transportLost,
			"requested_migrations":         opts.Migrations,
			"migration_calls_fired":        migrationCallsFired,
			"migrations":                   migrated,
			"application_duplicates":       applicationDuplicates,
			"recv_dups":                    recvDups,
			"recv_dups_observer":           "peer_server_rx",
			"schedule_lateness_p99_ms":     float64(scheduleP99) / float64(time.Millisecond),
			"schedule_lateness_max_ms":     float64(scheduleMax) / float64(time.Millisecond),
			"write_start_lateness_p99_ms":  float64(writeStartP99) / float64(time.Millisecond),
			"write_start_lateness_max_ms":  float64(writeStartMax) / float64(time.Millisecond),
			"blackout_ms":                  float64(blackout) / float64(time.Millisecond),
			"migration_blackout_ms":        float64(migrationBlackout) / float64(time.Millisecond),
			"latency_samples":              len(rtts),
			"latency_evidence":             latencyEvidence,
			"p99_qualified":                p99Qualified,
			"p99_minimum_samples":          g2P99MinimumSamples,
			"p999_qualified":               p999Qualified,
			"p999_minimum_samples":         g2P999MinimumSamples,
			"p99_ceiling_ms":               float64(p99Ceiling) / float64(time.Millisecond),
			"p50_ms":                       float64(p50) / float64(time.Millisecond),
			"p99_ms":                       float64(p99) / float64(time.Millisecond),
			"p999_ms":                      float64(p999) / float64(time.Millisecond),
			"max_ms":                       float64(maxRTT) / float64(time.Millisecond),
		},
	}
	invalidReason, runFailure := validateG2RunEvidence(g2RunEvidence{
		requestedDuration: opts.Duration,
		observedDuration:  runElapsed,
		interval:          opts.Interval,
		planned:           scheduler.planned,
		scheduled:         scheduler.scheduled,
		writeCompleted:    len(writes),
		received:          len(received),
		unoffered:         scheduler.unoffered(),
		transportLost:     transportLost,
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
	if transportLost > 0 {
		r.Failure = fmt.Sprintf("echo loss: %d / %d", transportLost, len(writes))
		return r
	}
	if latencyFailure != "" {
		r.Failure = latencyFailure
		return r
	}
	if evidenceErr != nil {
		r.Failure = evidenceErr.Error()
		return r
	}
	return r
}

const g2WriteDeadline = 30 * time.Second

type g2WriteConn interface {
	Write([]byte) (int, error)
	SetWriteDeadline(time.Time) error
}

func runG2Sender(conn g2WriteConn, endpoint time.Time, requests <-chan g2WriteRequest, results chan<- g2WriteResult, done chan<- struct{}) {
	defer close(done)
	for request := range requests {
		result := g2WriteResult{request: request, writeStarted: time.Now()}
		if !result.writeStarted.Before(endpoint) {
			result.err = fmt.Errorf("write seq %d did not start before run endpoint", request.seq)
			results <- result
			continue
		}

		deadline := result.writeStarted.Add(g2WriteDeadline)
		if endpoint.Before(deadline) {
			deadline = endpoint
		}
		if err := conn.SetWriteDeadline(deadline); err != nil {
			result.err = fmt.Errorf("set write deadline for seq %d: %w", request.seq, err)
			results <- result
			continue
		}

		buf := make([]byte, 12)
		binary.BigEndian.PutUint32(buf[:4], uint32(request.seq))
		binary.BigEndian.PutUint64(buf[4:], uint64(result.writeStarted.UnixNano()))
		n, err := conn.Write(buf)
		if err != nil {
			result.err = fmt.Errorf("write seq %d: %w", request.seq, err)
		} else if n != len(buf) {
			result.err = fmt.Errorf("write seq %d: %w (%d/%d bytes)", request.seq, io.ErrShortWrite, n, len(buf))
		} else {
			result.completed = true
		}
		if err := conn.SetWriteDeadline(time.Time{}); err != nil {
			result.err = errors.Join(result.err, fmt.Errorf("clear write deadline for seq %d: %w", request.seq, err))
		}
		results <- result
	}
}

func g2MigrationTime(start time.Time, duration time.Duration, index, total int) time.Time {
	if total <= 0 {
		return start.Add(duration)
	}
	offset := duration * time.Duration(index+1) / time.Duration(total+1)
	return start.Add(offset)
}

func g2DurationStats(samples []time.Duration) (p50, p99, p999, max time.Duration) {
	if len(samples) == 0 {
		return 0, 0, 0, 0
	}
	sorted := append([]time.Duration(nil), samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return g2NearestRank(sorted, 50, 100),
		g2NearestRank(sorted, 99, 100),
		g2NearestRank(sorted, 999, 1000),
		sorted[len(sorted)-1]
}

func g2NearestRank(sorted []time.Duration, numerator, denominator int) time.Duration {
	if len(sorted) == 0 || numerator <= 0 || denominator <= 0 {
		return 0
	}
	rank := (len(sorted)*numerator + denominator - 1) / denominator
	if rank < 1 {
		rank = 1
	}
	if rank > len(sorted) {
		rank = len(sorted)
	}
	return sorted[rank-1]
}

func g2MaxBlackout(start, endpoint time.Time, deliveries []time.Time) time.Duration {
	cursor := start
	var max time.Duration
	for _, deliveredAt := range deliveries {
		if deliveredAt.Before(cursor) {
			continue
		}
		if gap := deliveredAt.Sub(cursor); gap > max {
			max = gap
		}
		cursor = deliveredAt
	}
	if endpoint.After(cursor) {
		if gap := endpoint.Sub(cursor); gap > max {
			max = gap
		}
	}
	return max
}

func g2MaxStimulusBlackout(stimuli []time.Time, endpoint time.Time, deliveries []time.Time) time.Duration {
	var max time.Duration
	for _, stimulusAt := range stimuli {
		next := endpoint
		for _, deliveredAt := range deliveries {
			if !deliveredAt.Before(stimulusAt) {
				next = deliveredAt
				break
			}
		}
		if next.Before(stimulusAt) {
			continue
		}
		if gap := next.Sub(stimulusAt); gap > max {
			max = gap
		}
	}
	return max
}

func resetG2Timer(timer *time.Timer, delay time.Duration) {
	if timer == nil {
		return
	}
	stopG2Timer(timer)
	if delay < 0 {
		delay = 0
	}
	timer.Reset(delay)
}

func stopG2Timer(timer *time.Timer) {
	if timer == nil || timer.Stop() {
		return
	}
	select {
	case <-timer.C:
	default:
	}
}

func g2TimerChan(t *time.Timer) <-chan time.Time {
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
