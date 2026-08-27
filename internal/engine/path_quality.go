package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/FrankoonG/rendr/transport"
)

const (
	selectorQualityObservationBudget = 50 * time.Millisecond
	pathQualityCallbackCleanupGrace  = 50 * time.Millisecond
	pathQualityCallbackOperation     = "PathQualityReader.QualityContext"
)

type pathQualityTicket struct {
	sequence   uint64
	generation pathProbeGeneration
	supported  bool
}

type pathQualityCallbackPanicError struct {
	panicType string
}

func (err *pathQualityCallbackPanicError) Error() string {
	if err == nil || err.panicType == "" {
		return "engine: transport PathQualityReader.QualityContext callback panicked"
	}
	return fmt.Sprintf(
		"engine: transport PathQualityReader.QualityContext callback panicked with %s",
		err.panicType,
	)
}

type pathQualityCallbackGoexitError struct{}

func (*pathQualityCallbackGoexitError) Error() string {
	return "engine: transport PathQualityReader.QualityContext callback called runtime.Goexit"
}

type pathQualityCallbackResult struct {
	quality transport.PathQuality
	err     error
}

func pathQualityCallbackFailedAbnormally(err error) bool {
	var panicErr *pathQualityCallbackPanicError
	var goexitErr *pathQualityCallbackGoexitError
	return errors.As(err, &panicErr) || errors.As(err, &goexitErr) ||
		externalPathCallbackBoundaryError(err) || errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded)
}

func (s *pathSlot) retireLegacyQualityEvidence() {
	if s != nil {
		s.legacyQualityRetired.Store(true)
	}
}

func (s *pathSlot) qualityEvidenceCurrent(
	quality transport.PathQuality,
	generation pathProbeGeneration,
) bool {
	if s == nil || s.legacyQualityRetired.Load() ||
		generation != pathProbeGenerationForSlot(s) || quality == (transport.PathQuality{}) {
		return false
	}
	return true
}

func (s *pathSlot) requestQualityObservation() pathQualityTicket {
	if s == nil || s.conn == nil || s.legacyQualityRetired.Load() {
		return pathQualityTicket{}
	}
	if _, ok := s.conn.(transport.PathQualityReader); !ok {
		return pathQualityTicket{}
	}
	s.qualityObserverMu.Lock()
	if s.qualityObserverStopped {
		ticket := pathQualityTicket{
			sequence: s.qualityObserverSeq, generation: pathProbeGenerationForSlot(s), supported: true,
		}
		s.qualityObserverMu.Unlock()
		return ticket
	}
	if !s.qualityObserverStarted {
		s.qualityObserverStarted = true
		s.qualityObserverRequest = make(chan struct{}, 1)
		s.qualityObserverWake = make(chan struct{})
		s.qualityObserverStop = make(chan struct{})
		s.qualityObserverDone = make(chan struct{})
		ctx, cancel := context.WithCancel(context.Background())
		s.qualityObserverCancel = cancel
		go s.runQualityObserver(ctx)
	}
	ticket := pathQualityTicket{
		sequence: s.qualityObserverSeq, generation: pathProbeGenerationForSlot(s), supported: true,
	}
	requests := s.qualityObserverRequest
	s.qualityObserverMu.Unlock()
	select {
	case requests <- struct{}{}:
	default:
	}
	return ticket
}

func (s *pathSlot) runQualityObserver(ctx context.Context) {
	s.qualityObserverMu.Lock()
	requests := s.qualityObserverRequest
	stop := s.qualityObserverStop
	done := s.qualityObserverDone
	s.qualityObserverMu.Unlock()
	defer close(done)
	for {
		select {
		case <-stop:
			return
		case <-requests:
		}

		generation := pathProbeGenerationForSlot(s)
		observationCtx, cancel := context.WithTimeout(ctx, selectorQualityObservationBudget)
		quality, err := readPathQuality(observationCtx, s.conn)
		cancel()
		abnormal := pathQualityCallbackFailedAbnormally(err)
		ok := err == nil
		ok = ok && s.qualityEvidenceCurrent(quality, generation)
		if !s.publishQualityObservation(quality, generation, abnormal, ok) {
			return
		}
	}
}

// publishQualityObservation linearizes adapter telemetry with selector route
// publication. A changed sample advances the same health evidence frontier
// bound into selectorEvidenceCommit; an observer racing a commit is therefore
// ordered wholly before validation or wholly after route publication.
func (s *pathSlot) publishQualityObservation(
	quality transport.PathQuality,
	generation pathProbeGeneration,
	abnormal bool,
	ok bool,
) bool {
	unlock := s.lockHealthEvidenceMutation()
	defer unlock()

	s.qualityObserverMu.Lock()
	defer s.qualityObserverMu.Unlock()
	if s.qualityObserverStopped {
		return false
	}
	changed := false
	s.qualityObserverSeq++
	if abnormal {
		changed = s.qualityObserverSampled ||
			s.qualityObserverSample != (transport.PathQuality{}) ||
			s.qualityObserverGen != (pathProbeGeneration{})
		s.qualityObserverSample = transport.PathQuality{}
		s.qualityObserverGen = pathProbeGeneration{}
		s.qualityObserverSampled = false
	} else if ok {
		changed = !s.qualityObserverSampled ||
			s.qualityObserverSample != quality || s.qualityObserverGen != generation
		s.qualityObserverSample = quality
		s.qualityObserverGen = generation
		s.qualityObserverSampled = true
	}
	if changed {
		s.advanceHealthEvidenceRevisionLocked()
	}
	close(s.qualityObserverWake)
	s.qualityObserverWake = make(chan struct{})
	return true
}

func readPathQuality(ctx context.Context, conn transport.PathConn) (transport.PathQuality, error) {
	if conn == nil {
		return transport.PathQuality{}, errors.New("engine: nil path quality connection")
	}
	reader, ok := conn.(transport.PathQualityReader)
	if !ok {
		return transport.PathQuality{}, errors.New("engine: path does not implement PathQualityReader")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return transport.PathQuality{}, &pathDispatchCallbackDeadlineError{
			operation: pathQualityCallbackOperation,
			cause:     err,
		}
	}
	callbackCtx, cancelCallback := context.WithTimeout(ctx, selectorQualityObservationBudget)
	defer cancelCallback()
	containmentBudget := selectorQualityObservationBudget + pathQualityCallbackCleanupGrace
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining < 0 {
			remaining = 0
		} else if remaining > selectorQualityObservationBudget {
			remaining = selectorQualityObservationBudget
		}
		containmentBudget = remaining + pathQualityCallbackCleanupGrace
	}
	containmentCtx, cancelContainment := context.WithTimeout(context.Background(), containmentBudget)
	defer cancelContainment()
	callbackResult, err := invokeExternalPathValueCallbackContext(
		containmentCtx,
		pathQualityCallbackOperation,
		conn,
		func() pathQualityCallbackResult {
			quality, err := reader.QualityContext(callbackCtx)
			return pathQualityCallbackResult{quality: quality, err: err}
		},
	)
	if callbackErr := callbackCtx.Err(); callbackErr != nil {
		return transport.PathQuality{}, &pathDispatchCallbackDeadlineError{
			operation: pathQualityCallbackOperation,
			cause:     callbackErr,
		}
	}
	if err != nil {
		var panicErr *pathDispatchCallbackPanicError
		var goexitErr *pathDispatchCallbackGoexitError
		switch {
		case errors.As(err, &panicErr):
			return transport.PathQuality{}, &pathQualityCallbackPanicError{panicType: panicErr.recoveredType}
		case errors.As(err, &goexitErr):
			return transport.PathQuality{}, &pathQualityCallbackGoexitError{}
		default:
			return transport.PathQuality{}, err
		}
	}
	return callbackResult.quality, callbackResult.err
}

func (s *pathSlot) awaitQualityObservation(
	ctx context.Context,
	ticket pathQualityTicket,
) (transport.PathQuality, bool) {
	if s == nil || !ticket.supported {
		return transport.PathQuality{}, false
	}
	for {
		s.qualityObserverMu.Lock()
		quality := s.qualityObserverSample
		generation := s.qualityObserverGen
		sampled := s.qualityObserverSampled && generation == ticket.generation &&
			ticket.generation == pathProbeGenerationForSlot(s) &&
			s.qualityEvidenceCurrent(quality, generation)
		if s.qualityObserverSeq > ticket.sequence {
			s.qualityObserverMu.Unlock()
			return quality, sampled
		}
		if s.qualityObserverStopped || !s.qualityObserverStarted {
			s.qualityObserverMu.Unlock()
			return quality, sampled
		}
		wake := s.qualityObserverWake
		stop := s.qualityObserverStop
		s.qualityObserverMu.Unlock()
		select {
		case <-ctx.Done():
			s.invalidateTimedOutQualityObservation(ticket)
			return transport.PathQuality{}, false
		case <-stop:
			return s.qualityObservationForTicket(ticket)
		case <-wake:
		}
	}
}

// invalidateTimedOutQualityObservation clears only the evidence generation
// whose requested refresh missed this decision budget. A publication that won
// the sequence race remains authoritative for later decisions, while this
// timed-out decision still fails closed.
func (s *pathSlot) invalidateTimedOutQualityObservation(ticket pathQualityTicket) {
	if s == nil || !ticket.supported {
		return
	}
	unlock := s.lockHealthEvidenceMutation()
	defer unlock()

	s.qualityObserverMu.Lock()
	defer s.qualityObserverMu.Unlock()
	if s.qualityObserverStopped || s.qualityObserverSeq > ticket.sequence {
		return
	}
	changed := s.qualityObserverSampled ||
		s.qualityObserverSample != (transport.PathQuality{}) ||
		s.qualityObserverGen != (pathProbeGeneration{})
	s.qualityObserverSeq++
	s.qualityObserverSample = transport.PathQuality{}
	s.qualityObserverGen = pathProbeGeneration{}
	s.qualityObserverSampled = false
	if changed {
		s.advanceHealthEvidenceRevisionLocked()
	}
	close(s.qualityObserverWake)
	s.qualityObserverWake = make(chan struct{})
}

func (s *pathSlot) qualityObservationForTicket(ticket pathQualityTicket) (transport.PathQuality, bool) {
	if s == nil || !ticket.supported {
		return transport.PathQuality{}, false
	}
	s.qualityObserverMu.Lock()
	quality := s.qualityObserverSample
	generation := s.qualityObserverGen
	sampled := s.qualityObserverSampled
	s.qualityObserverMu.Unlock()
	if !sampled || generation != ticket.generation || ticket.generation != pathProbeGenerationForSlot(s) ||
		!s.qualityEvidenceCurrent(quality, generation) {
		return transport.PathQuality{}, false
	}
	return quality, true
}

func (s *pathSlot) latestObservedQuality() transport.PathQuality {
	if s == nil {
		return transport.PathQuality{}
	}
	ticket := s.requestQualityObservation()
	if !ticket.supported {
		return transport.PathQuality{}
	}
	s.qualityObserverMu.Lock()
	quality := s.qualityObserverSample
	generation := s.qualityObserverGen
	sampled := s.qualityObserverSampled
	s.qualityObserverMu.Unlock()
	if !sampled || !s.qualityEvidenceCurrent(quality, generation) {
		return transport.PathQuality{}
	}
	return quality
}

// latestSchedulingQuality returns only generation-bound, fresh RTT evidence.
// Untimestamped legacy quality remains available to the first probe as a
// bounded timeout hint, but it never becomes selector/bond scheduling input.
func (s *pathSlot) latestSchedulingQuality(now time.Time, probeInterval time.Duration) transport.PathQuality {
	quality, _ := s.schedulingQualityProjection(now, probeInterval)
	return quality
}

// schedulingQualityProjection returns both the current result and the first
// wall-clock instant at which that result can change without a new evidence
// publication. The dispatch projection cache uses the boundary to avoid
// retaining a quality or loss sample for even one write beyond its factual
// lifetime.
func (s *pathSlot) schedulingQualityProjection(
	now time.Time,
	probeInterval time.Duration,
) (transport.PathQuality, time.Time) {
	if s == nil || now.IsZero() {
		return transport.PathQuality{}, time.Time{}
	}
	adapter := s.latestObservedQuality()
	probe := transport.PathQuality{}
	if evidence := s.probeEvidence.Load(); s.probeEvidenceCurrent(evidence) && !evidence.lastSuccess.IsZero() {
		probe = evidence.quality
	}
	quality := mergeSchedulingQuality(adapter, probe, now, probeInterval)
	var transition time.Time
	consider := func(candidate time.Time) {
		if candidate.IsZero() || candidate.Before(now) {
			return
		}
		if transition.IsZero() || candidate.Before(transition) {
			transition = candidate
		}
	}
	for _, source := range []transport.PathQuality{adapter, probe} {
		if source.RTT <= 0 || source.At.IsZero() {
			continue
		}
		if source.At.After(now) {
			consider(source.At)
			continue
		}
		freshUntil := source.At.Add(selectorProbeFreshFor(probeInterval, source))
		if now.Before(freshUntil) {
			consider(freshUntil)
		}
	}
	if !adapter.At.IsZero() {
		if adapter.At.After(now) {
			consider(adapter.At)
		} else {
			lossUntil := adapter.At.Add(selectorEvidenceFreshFor + time.Nanosecond)
			if now.Before(lossUntil) {
				consider(lossUntil)
			}
		}
	}
	return quality, transition
}

// probeTimingQuality chooses only bounded, generation-current timing evidence
// for local probe write/wire deadlines. A current successful probe has
// priority over adapter telemetry. Untimestamped adapter telemetry is accepted
// only before this path generation has any probe evidence and never enters
// scheduling or public quality state.
func (s *pathSlot) probeTimingQuality(
	adapter transport.PathQuality,
	now time.Time,
	probeInterval time.Duration,
) transport.PathQuality {
	if s == nil || now.IsZero() {
		return transport.PathQuality{}
	}
	evidence := s.probeEvidence.Load()
	currentEvidence := s.probeEvidenceCurrent(evidence)
	if currentEvidence && !evidence.lastSuccess.IsZero() &&
		schedulingQualityFresh(evidence.quality, now, probeInterval) {
		return evidence.quality
	}
	if schedulingQualityFresh(adapter, now, probeInterval) {
		return adapter
	}
	if !currentEvidence && adapter.RTT > 0 && adapter.At.IsZero() {
		return adapter
	}
	return transport.PathQuality{}
}

func mergeSchedulingQuality(
	adapter transport.PathQuality,
	probe transport.PathQuality,
	now time.Time,
	probeInterval time.Duration,
) transport.PathQuality {
	adapterOK := schedulingQualityFresh(adapter, now, probeInterval)
	probeOK := schedulingQualityFresh(probe, now, probeInterval)
	switch {
	case adapterOK && probeOK:
		if adapter.At.After(probe.At) {
			return adapter
		}
		if schedulingLossFresh(adapter, now) {
			probe.LossPP = adapter.LossPP
		}
		return probe
	case adapterOK:
		return adapter
	case probeOK:
		if schedulingLossFresh(adapter, now) {
			probe.LossPP = adapter.LossPP
		}
		return probe
	default:
		return transport.PathQuality{}
	}
}

func schedulingLossFresh(quality transport.PathQuality, now time.Time) bool {
	if quality.At.IsZero() || quality.At.After(now) {
		return false
	}
	return now.Sub(quality.At) <= selectorEvidenceFreshFor
}

func schedulingQualityFresh(quality transport.PathQuality, now time.Time, probeInterval time.Duration) bool {
	if quality.RTT <= 0 || quality.At.IsZero() || quality.At.After(now) {
		return false
	}
	return now.Sub(quality.At) < selectorProbeFreshFor(probeInterval, quality)
}

func (s *pathSlot) stopQualityObserver() {
	if s == nil {
		return
	}
	s.qualityObserverMu.Lock()
	if s.qualityObserverStopped {
		s.qualityObserverMu.Unlock()
		return
	}
	s.qualityObserverStopped = true
	cancel := s.qualityObserverCancel
	if s.qualityObserverStarted {
		close(s.qualityObserverStop)
		close(s.qualityObserverWake)
		s.qualityObserverWake = make(chan struct{})
	}
	s.qualityObserverMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *pathSlot) waitQualityObserver() {
	if s == nil {
		return
	}
	s.qualityObserverMu.Lock()
	started := s.qualityObserverStarted
	done := s.qualityObserverDone
	s.qualityObserverMu.Unlock()
	if started && done != nil {
		<-done
	}
}

func observePathQualities(
	slots []*pathSlot,
	budget time.Duration,
) map[*pathSlot]transport.PathQuality {
	qualities := make(map[*pathSlot]transport.PathQuality, len(slots))
	if len(slots) == 0 {
		return qualities
	}
	if budget <= 0 {
		budget = selectorQualityObservationBudget
	}
	tickets := make(map[*pathSlot]pathQualityTicket, len(slots))
	for _, slot := range slots {
		if slot != nil {
			tickets[slot] = slot.requestQualityObservation()
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	for _, slot := range slots {
		if slot == nil {
			continue
		}
		if quality, ok := slot.awaitQualityObservation(ctx, tickets[slot]); ok {
			qualities[slot] = quality
		}
	}
	return qualities
}
