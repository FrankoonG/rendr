package engine

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type pathProbeGeneration struct {
	path               PathRef
	routeGeneration    uint64
	endpointGeneration uint64
	peerMobilityEpoch  uint64
}

type pathProbeLifecycle uint8

const (
	pathProbeReserved pathProbeLifecycle = iota
	pathProbeQueued
	pathProbeWriteStarted
	pathProbeWriteCommitted
	pathProbeWireTimeout
	pathProbeDataBlocked
	pathProbeDataStarved
	pathProbeWriteStalled
)

type pathProbeFailure uint8

const (
	pathProbeFailureNone pathProbeFailure = iota
	pathProbeFailureWireTimeout
	pathProbeFailureDataStarved
	pathProbeFailureWriteStalled
)

type pathProbeStatus struct {
	lifecycle pathProbeLifecycle
	failure   pathProbeFailure
}

type sendACKProgressObservation struct {
	next uint64
	at   time.Time
}

type pathProbeObservation struct {
	queuedAt             time.Time
	writeStartedAt       time.Time
	writeCommittedAt     time.Time
	writeStallDeadline   time.Time
	deadline             time.Time
	generation           pathProbeGeneration
	slot                 *pathSlot
	quality              transport.PathQuality
	wireTS               uint64
	fenceEpoch           uint64
	lifecycle            pathProbeLifecycle
	dataStallGeneration  uint64
	dataBlockedAt        time.Time
	wireAckBaseline      uint64
	wireDataWitnessNext  uint64
	wireMigrationEpoch   uint64
	wireProgressTracked  bool
	wireProgressDeferred bool
	pendingReplyAt       time.Time
}

// pathProbeEvidence contains only engine-owned same-carrier observations.
// Issued timestamps and counters begin at successful full-write commit; queue
// and in-Write time never enter wire liveness or RTT evidence. Transport-owned
// fields, including loss, remain live through PathConn.Quality.
type pathProbeEvidence struct {
	generation        pathProbeGeneration
	fenceEpoch        uint64
	fenceTracked      bool
	migrationEpoch    uint64
	migrationTracked  bool
	tokenStatsTracked bool
	firstIssued       time.Time
	lastIssued        time.Time
	lastSuccess       time.Time
	lastWireTimeout   time.Time
	lastLifecycle     pathProbeLifecycle
	lastTransition    time.Time
	quality           transport.PathQuality
	issued            uint64
	succeeded         uint64
	timedOut          uint64
	tokenIssued       uint64
	tokenSucceeded    uint64
	tokenTimedOut     uint64
}

func (e pathProbeEvidence) currentTokenCounters() (issued, succeeded, timedOut uint64) {
	if e.tokenStatsTracked {
		return e.tokenIssued, e.tokenSucceeded, e.tokenTimedOut
	}
	return e.issued, e.succeeded, e.timedOut
}

func (e *pathProbeEvidence) trackCurrentTokenCounters() {
	if e == nil || e.tokenStatsTracked {
		return
	}
	e.tokenIssued = e.issued
	e.tokenSucceeded = e.succeeded
	e.tokenTimedOut = e.timedOut
	e.tokenStatsTracked = true
}

func (lifecycle pathProbeLifecycle) blocksNextProbeWrite() bool {
	switch lifecycle {
	case pathProbeReserved, pathProbeQueued, pathProbeWriteStarted, pathProbeDataBlocked, pathProbeDataStarved, pathProbeWriteStalled:
		return true
	default:
		return false
	}
}

func pathProbeLifecycleCarriesHealthFact(lifecycle pathProbeLifecycle) bool {
	switch lifecycle {
	case pathProbeDataBlocked, pathProbeDataStarved, pathProbeWriteStalled, pathProbeWireTimeout:
		return true
	default:
		return false
	}
}

// mutatePathProbeLifecycleLocked runs while probeMu owns the observation.
// The shared commit gate and per-slot lock remain held until mutate has
// published the complete lifecycle transition.
func (e *Engine) mutatePathProbeLifecycleLocked(
	slot *pathSlot,
	before, after pathProbeLifecycle,
	mutate func(),
) {
	if slot == nil || before == after ||
		(!pathProbeLifecycleCarriesHealthFact(before) && !pathProbeLifecycleCarriesHealthFact(after)) {
		if mutate != nil {
			mutate()
		}
		return
	}
	slot.mutateHealthEvidence(mutate)
}

func pathProbeGenerationForSlot(slot *pathSlot) pathProbeGeneration {
	if slot == nil {
		return pathProbeGeneration{}
	}
	return pathProbeGeneration{
		path:               pathRefForSlot(slot),
		routeGeneration:    slot.routeGeneration.Load(),
		endpointGeneration: slot.probeEndpointGen.Load(),
		peerMobilityEpoch:  slot.peerMobilityEpoch.Load(),
	}
}

func (slot *pathSlot) quality() transport.PathQuality {
	if slot == nil || slot.conn == nil {
		return transport.PathQuality{}
	}
	quality := observePathQualities(
		[]*pathSlot{slot}, selectorQualityObservationBudget,
	)[slot]
	evidence := slot.probeEvidence.Load()
	if !slot.probeEvidenceCurrent(evidence) || evidence.lastSuccess.IsZero() {
		return quality
	}
	// Engine probes and adapter telemetry are independent timing sources for
	// the same physical generation. A historical probe must not permanently
	// mask a newer adapter observation, especially when an intentionally sparse
	// probe cadence exceeds the selector freshness window. Probe timeout state
	// remains authoritative through probeLiveness/pathProbeStatuses.
	if !quality.At.IsZero() && quality.At.After(evidence.quality.At) {
		return quality
	}
	quality.RTT = evidence.quality.RTT
	quality.Jitter = evidence.quality.Jitter
	quality.At = evidence.quality.At
	return quality
}

func (slot *pathSlot) probeSnapshot() (pathProbeEvidence, bool) {
	if slot == nil {
		return pathProbeEvidence{}, false
	}
	evidence := slot.probeEvidence.Load()
	if !slot.probeEvidenceCurrent(evidence) {
		return pathProbeEvidence{}, false
	}
	return *evidence, true
}

func (slot *pathSlot) probeEvidenceCurrent(evidence *pathProbeEvidence) bool {
	if slot == nil || evidence == nil || evidence.generation != pathProbeGenerationForSlot(slot) ||
		evidence.fenceTracked && evidence.fenceEpoch != slot.txFenceEpoch.Load() {
		return false
	}
	if !evidence.migrationTracked {
		return true
	}
	return slot.migrationEpochSource != nil && slot.migrationEpochSource.Load() == evidence.migrationEpoch
}

func pathProbeEvidenceMatchesObservation(evidence *pathProbeEvidence, observation pathProbeObservation) bool {
	return evidence != nil && evidence.generation == observation.generation &&
		evidence.fenceTracked && evidence.fenceEpoch == observation.fenceEpoch &&
		evidence.migrationTracked == observation.wireProgressTracked &&
		(!evidence.migrationTracked || evidence.migrationEpoch == observation.wireMigrationEpoch)
}

func (slot *pathSlot) probeLiveness(now time.Time, interval time.Duration) qualityState {
	evidence, ok := slot.probeSnapshot()
	issued, succeeded, _ := evidence.currentTokenCounters()
	if !ok || issued == 0 || evidence.firstIssued.IsZero() {
		return qualityStateUnknown
	}
	base := evidence.firstIssued
	if succeeded > 0 && !evidence.lastSuccess.IsZero() {
		base = evidence.lastSuccess
	}
	// Age alone is not path-failure evidence. A queued probe may be waiting
	// behind a local physical writer for arbitrarily long without ever reaching
	// the carrier. Only a committed probe whose wire-reply deadline expired may
	// turn same-carrier liveness stale.
	if evidence.lastWireTimeout.After(evidence.lastSuccess) &&
		now.Sub(base) > selectorProbeFreshFor(interval, evidence.quality) {
		return qualityStateStale
	}
	if succeeded > 0 && now.Sub(base) <= selectorProbeFreshFor(interval, evidence.quality) {
		return qualityStateFresh
	}
	return qualityStateUnknown
}

func (e *Engine) issuePathProbe(slot *pathSlot) {
	if e == nil || slot == nil || e.closing.Load() || e.isClosed() {
		return
	}
	queuedAt := nowFn()
	generation := pathProbeGenerationForSlot(slot)
	fenceEpoch := slot.txFenceEpoch.Load()
	adapterQuality := observePathQualities([]*pathSlot{slot}, selectorQualityObservationBudget)[slot]
	quality := slot.probeTimingQuality(adapterQuality, queuedAt, e.limits.ProbeInterval)
	e.probeMu.Lock()
	e.expirePathProbesLocked(queuedAt)
	if e.closing.Load() || e.isClosed() {
		e.probeMu.Unlock()
		return
	}
	for _, observation := range e.probeOutstanding {
		if observation.slot == slot && observation.generation == generation && observation.lifecycle.blocksNextProbeWrite() {
			e.probeMu.Unlock()
			return
		}
	}
	id, ok := reservePathProbeID(e.probeOutstanding)
	if !ok {
		e.probeMu.Unlock()
		return
	}
	wireTS := uint64(queuedAt.UnixNano())
	e.probeOutstanding[id] = pathProbeObservation{
		queuedAt: queuedAt, generation: generation, slot: slot, quality: quality,
		wireTS: wireTS, fenceEpoch: fenceEpoch, lifecycle: pathProbeReserved,
	}
	e.probeMu.Unlock()

	payload := proto.ProbePayload{TS: wireTS, ID: id}.Encode()
	frame := make([]byte, proto.HeaderSize+len(payload))
	hdr := proto.Header{
		Version: proto.Version,
		Type:    proto.FrameCtrl,
		Flags:   proto.FlagsForCtrl(proto.CtrlPathProbe),
		Seq:     0,
	}
	if err := hdr.Encode(frame[:proto.HeaderSize]); err != nil {
		e.cancelPathProbeReservation(id, slot)
		return
	}
	copy(frame[proto.HeaderSize:], payload)
	ready := make(chan struct{})
	if !e.startPathProbeWrite(slot, id, frame, ready, generation, fenceEpoch) {
		e.cancelPathProbeReservation(id, slot)
		return
	}
	e.markPathProbeSubmitted(id, slot)
	close(ready)
}

func reservePathProbeID(outstanding map[uint64]pathProbeObservation) (uint64, bool) {
	var encoded [8]byte
	for attempt := 0; attempt < 8; attempt++ {
		if _, err := rand.Read(encoded[:]); err != nil {
			return 0, false
		}
		id := binary.BigEndian.Uint64(encoded[:])
		if id == 0 {
			continue
		}
		if _, exists := outstanding[id]; !exists {
			return id, true
		}
	}
	return 0, false
}

// startProbeWriterLocked registers a probe writer while probeControlMu still
// excludes close and admission of later writers. probeWriteWG owns final
// teardown; probeWritersIdle gives a TX fence a context-aware drain boundary.
func (slot *pathSlot) startProbeWriterLocked() <-chan struct{} {
	if slot.probePermitCancel == nil {
		slot.probePermitCancel = make(chan struct{})
	}
	if slot.probeWriterCount == 0 {
		slot.probeWritersIdle = make(chan struct{})
	}
	slot.probeWriterCount++
	slot.probeWriteWG.Add(1)
	return slot.probePermitCancel
}

func (slot *pathSlot) finishProbeWriter() {
	slot.probeControlMu.Lock()
	slot.probeWriterCount--
	if slot.probeWriterCount == 0 {
		close(slot.probeWritersIdle)
		slot.probeWritersIdle = nil
	}
	slot.probeControlMu.Unlock()
	slot.probeWriteWG.Done()
}

func (slot *pathSlot) waitProbeWriters(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	slot.probeControlMu.Lock()
	if slot.probeWriterCount == 0 {
		slot.probeControlMu.Unlock()
		return nil
	}
	idle := slot.probeWritersIdle
	slot.probeControlMu.Unlock()
	select {
	case <-idle:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (slot *pathSlot) probeWritersIdleSignal() (<-chan struct{}, bool) {
	if slot == nil {
		return nil, false
	}
	slot.probeControlMu.Lock()
	defer slot.probeControlMu.Unlock()
	if slot.probeWriterCount == 0 {
		return nil, false
	}
	return slot.probeWritersIdle, true
}

// cancelProbeWritePermitWaiters revokes only probe writers that have not yet
// acquired the shared physical write permit. A writer already inside
// PathConn.Write remains registered and is drained by waitProbeWriters.
func (slot *pathSlot) cancelProbeWritePermitWaiters() {
	if slot == nil {
		return
	}
	slot.probeControlMu.Lock()
	slot.cancelProbeWritePermitWaitersLocked()
	slot.probeControlMu.Unlock()
}

func (slot *pathSlot) cancelProbeWritePermitWaitersLocked() {
	if slot.probePermitCancel != nil {
		close(slot.probePermitCancel)
		slot.probePermitCancel = nil
	}
}

func (e *Engine) startPathProbeWrite(
	slot *pathSlot,
	id uint64,
	frame []byte,
	ready <-chan struct{},
	generation pathProbeGeneration,
	fenceEpoch uint64,
) bool {
	slot.probeControlMu.Lock()
	if slot.probeControlClosed || !slot.txEnabled.Load() || slot.txFenceEpoch.Load() != fenceEpoch ||
		pathProbeGenerationForSlot(slot) != generation || e.closing.Load() || e.isClosed() {
		slot.probeControlMu.Unlock()
		return false
	}
	permitCancel := slot.startProbeWriterLocked()
	slot.probeControlMu.Unlock()
	go func() {
		callbackGuard := pathDispatchCallbackGuard{}
		defer func() {
			if callbackErr := callbackGuard.goexitError(); callbackErr != nil {
				e.completePathProbeWrite(id, slot, callbackErr, nowFn())
				e.failPathProbeControlWrite(slot, callbackErr)
			}
		}()
		defer slot.finishProbeWriter()
		select {
		case <-ready:
		case <-slot.quit:
			e.cancelPathProbeReservation(id, slot)
			return
		case <-e.closed:
			e.cancelPathProbeReservation(id, slot)
			return
		}
		if hook := slot.probeBeforeWritePermit; hook != nil {
			hook()
		}
		n, err := slot.writeProbeFrame(frame, fenceEpoch, permitCancel, &callbackGuard, func() bool {
			return e.markPathProbeWriteStarted(id, slot, time.Time{})
		})
		if err == nil && n != len(frame) {
			err = io.ErrShortWrite
		}
		if err != nil && !errors.Is(err, ErrPathTXFenced) {
			e.failPathProbeControlWrite(slot, err)
		}
		e.completePathProbeWrite(id, slot, err, nowFn())
	}()
	return true
}

func (slot *pathSlot) writeProbeFrame(
	frame []byte,
	fenceEpoch uint64,
	permitCancel <-chan struct{},
	callbackGuard *pathDispatchCallbackGuard,
	onWriteStart func() bool,
) (int, error) {
	if !slot.txEnabled.Load() || slot.txFenceEpoch.Load() != fenceEpoch {
		return 0, ErrPathTXFenced
	}
	if err := slot.acquireProbeWrite(context.Background(), permitCancel); err != nil {
		return 0, err
	}
	defer slot.releaseWrite()
	if !slot.txEnabled.Load() || slot.txFenceEpoch.Load() != fenceEpoch {
		return 0, ErrPathTXFenced
	}
	if hook := slot.probeBeforeConnWrite; hook != nil {
		hook()
	}
	if !slot.txEnabled.Load() || slot.txFenceEpoch.Load() != fenceEpoch {
		return 0, ErrPathTXFenced
	}
	if hook := slot.probeAfterFinalValidation; hook != nil {
		hook()
	}
	// This is the last engine-controlled boundary before PathConn.Write.
	// Queue time, permit wait, test hooks, and fence validation are local
	// scheduling facts and must never enter wire RTT or timeout evidence.
	if onWriteStart != nil && !onWriteStart() {
		return 0, ErrPathTXFenced
	}
	return slot.writeFrameOwnedGuarded(frame, callbackGuard)
}

func (slot *pathSlot) acquireProbeWrite(ctx context.Context, permitCancel <-chan struct{}) error {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-slot.writePermit:
		return nil
	case <-permitCancel:
		return ErrPathTXFenced
	case <-slot.quit:
		return net.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (e *Engine) markPathProbeSubmitted(id uint64, slot *pathSlot) {
	e.probeMu.Lock()
	observation, ok := e.probeOutstanding[id]
	if !ok || observation.slot != slot || observation.generation != pathProbeGenerationForSlot(slot) ||
		observation.fenceEpoch != slot.txFenceEpoch.Load() || observation.lifecycle != pathProbeReserved {
		e.probeMu.Unlock()
		return
	}
	observation.lifecycle = pathProbeQueued
	e.probeOutstanding[id] = observation
	e.probeMu.Unlock()
}

func (e *Engine) markPathProbeWriteStarted(id uint64, slot *pathSlot, started time.Time) bool {
	baseline, progressRelevant := e.flatSelectorProgressBaseline(slot)
	e.probeMu.Lock()
	defer e.probeMu.Unlock()
	observation, ok := e.probeOutstanding[id]
	if !ok || observation.slot != slot ||
		observation.generation != pathProbeGenerationForSlot(slot) ||
		observation.fenceEpoch != slot.txFenceEpoch.Load() ||
		(observation.lifecycle != pathProbeQueued && observation.lifecycle != pathProbeDataBlocked &&
			observation.lifecycle != pathProbeDataStarved) ||
		progressRelevant && baseline.migrationEpoch != e.migrationEpoch.Load() {
		return false
	}
	if started.IsZero() {
		started = nowFn()
	}
	if started.Before(observation.queuedAt) {
		started = observation.queuedAt
	}
	previousLifecycle := observation.lifecycle
	observation.lifecycle = pathProbeWriteStarted
	observation.writeStartedAt = started
	observation.writeStallDeadline = started.Add(pathProbeWriteStallFor(started, observation.quality))
	// markPathProbeWriteStarted runs while this probe owns the path's physical
	// write permit, immediately before PathConn.Write. Capture the DATA
	// predecessor and ACK baseline here; after the permit is released a DATA
	// writer may legitimately advance the leaf before completion is recorded.
	if progressRelevant {
		observation.wireAckBaseline = baseline.ackNext
		observation.wireDataWitnessNext = baseline.dataNext
		observation.wireMigrationEpoch = baseline.migrationEpoch
		observation.wireProgressTracked = true
	}
	e.mutatePathProbeLifecycleLocked(slot, previousLifecycle, observation.lifecycle, func() {
		e.probeOutstanding[id] = observation
	})
	return true
}

func (e *Engine) completePathProbeWrite(id uint64, slot *pathSlot, writeErr error, completed time.Time) {
	e.probeMu.Lock()
	observation, ok := e.probeOutstanding[id]
	if !ok || observation.slot != slot {
		e.probeMu.Unlock()
		return
	}
	if writeErr != nil || !e.pathProbeObservationCurrent(observation) {
		e.mutatePathProbeLifecycleLocked(slot, observation.lifecycle, pathProbeReserved, func() {
			delete(e.probeOutstanding, id)
		})
		e.probeMu.Unlock()
		return
	}
	if observation.lifecycle != pathProbeWriteStarted && observation.lifecycle != pathProbeWriteStalled {
		e.mutatePathProbeLifecycleLocked(slot, observation.lifecycle, pathProbeReserved, func() {
			delete(e.probeOutstanding, id)
		})
		e.probeMu.Unlock()
		return
	}
	if completed.Before(observation.writeStartedAt) {
		completed = observation.writeStartedAt
	}
	observation.lifecycle = pathProbeWriteCommitted
	observation.writeCommittedAt = completed
	observation.deadline = completed.Add(selectorProbeFreshFor(e.limits.ProbeInterval, observation.quality))
	maximumDeadline := observation.writeStartedAt.Add(maximumCommittedProbeLifetime)
	if observation.deadline.After(maximumDeadline) {
		observation.deadline = maximumDeadline
	}
	slot.mutateHealthEvidence(func() {
		e.recordPathProbeIssuedLocked(observation)
		switch {
		case !observation.pendingReplyAt.IsZero() && !observation.pendingReplyAt.After(observation.deadline):
			delete(e.probeOutstanding, id)
			e.recordPathProbeSuccessLocked(observation, observation.pendingReplyAt)
		case !observation.pendingReplyAt.IsZero():
			delete(e.probeOutstanding, id)
			e.recordPathProbeTimeoutLocked(observation, observation.pendingReplyAt)
		case !completed.Before(observation.deadline):
			delete(e.probeOutstanding, id)
			e.recordPathProbeTimeoutLocked(observation, completed)
		default:
			e.probeOutstanding[id] = observation
		}
	})
	e.probeMu.Unlock()
}

func (e *Engine) cancelPathProbeReservation(id uint64, slot *pathSlot) {
	e.probeMu.Lock()
	if observation, ok := e.probeOutstanding[id]; ok && observation.slot == slot {
		e.mutatePathProbeLifecycleLocked(slot, observation.lifecycle, pathProbeReserved, func() {
			delete(e.probeOutstanding, id)
		})
	}
	e.probeMu.Unlock()
}

func (e *Engine) submitPathProbeControl(
	slot *pathSlot,
	frame []byte,
	generation pathProbeGeneration,
	fenceEpoch uint64,
) bool {
	if e == nil || slot == nil || !slot.txEnabled.Load() || slot.txFenceEpoch.Load() != fenceEpoch ||
		pathProbeGenerationForSlot(slot) != generation || e.closing.Load() || e.isClosed() {
		return false
	}
	slot.probeControlMu.Lock()
	if slot.probeControlClosed || !slot.txEnabled.Load() || slot.txFenceEpoch.Load() != fenceEpoch ||
		pathProbeGenerationForSlot(slot) != generation || e.closing.Load() || e.isClosed() {
		slot.probeControlMu.Unlock()
		return false
	}
	slot.probeReplyPending = append(slot.probeReplyPending[:0], frame...)
	slot.probeReplyGeneration = generation
	slot.probeReplyFenceEpoch = fenceEpoch
	if slot.probeReplyRunning {
		slot.probeControlMu.Unlock()
		return true
	}
	slot.probeReplyRunning = true
	permitCancel := slot.startProbeWriterLocked()
	slot.probeControlMu.Unlock()
	go e.pathProbeReplyWriter(slot, permitCancel)
	return true
}

func (e *Engine) pathProbeReplyWriter(slot *pathSlot, permitCancel <-chan struct{}) {
	callbackGuard := pathDispatchCallbackGuard{}
	writePermitHeld := false
	defer func() {
		if writePermitHeld {
			slot.releaseWrite()
		}
		slot.finishProbeWriter()
		if callbackErr := callbackGuard.goexitError(); callbackErr != nil {
			slot.probeControlMu.Lock()
			slot.probeReplyPending = nil
			slot.probeReplyGeneration = pathProbeGeneration{}
			slot.probeReplyFenceEpoch = 0
			slot.probeReplyRunning = false
			slot.probeControlMu.Unlock()
			e.failPathProbeControlWrite(slot, callbackErr)
		}
	}()
	for {
		if hook := slot.probeBeforeWritePermit; hook != nil {
			hook()
		}
		if err := slot.acquireProbeWrite(context.Background(), permitCancel); err != nil {
			slot.probeControlMu.Lock()
			slot.probeReplyPending = nil
			slot.probeReplyGeneration = pathProbeGeneration{}
			slot.probeReplyFenceEpoch = 0
			slot.probeReplyRunning = false
			slot.probeControlMu.Unlock()
			return
		}
		writePermitHeld = true
		if !slot.txEnabled.Load() {
			slot.releaseWrite()
			writePermitHeld = false
			slot.probeControlMu.Lock()
			slot.probeReplyPending = nil
			slot.probeReplyGeneration = pathProbeGeneration{}
			slot.probeReplyFenceEpoch = 0
			slot.probeReplyRunning = false
			slot.probeControlMu.Unlock()
			return
		}
		slot.probeControlMu.Lock()
		if slot.probeControlClosed || len(slot.probeReplyPending) == 0 ||
			slot.probeReplyGeneration != pathProbeGenerationForSlot(slot) ||
			slot.probeReplyFenceEpoch != slot.txFenceEpoch.Load() {
			slot.probeReplyPending = nil
			slot.probeReplyGeneration = pathProbeGeneration{}
			slot.probeReplyFenceEpoch = 0
			slot.probeReplyRunning = false
			slot.probeControlMu.Unlock()
			slot.releaseWrite()
			writePermitHeld = false
			return
		}
		frame := append([]byte(nil), slot.probeReplyPending...)
		generation := slot.probeReplyGeneration
		fenceEpoch := slot.probeReplyFenceEpoch
		slot.probeReplyPending = nil
		slot.probeReplyGeneration = pathProbeGeneration{}
		slot.probeReplyFenceEpoch = 0
		slot.probeControlMu.Unlock()

		if hook := slot.probeAfterFinalValidation; hook != nil {
			hook()
		}
		if !slot.txEnabled.Load() || slot.txFenceEpoch.Load() != fenceEpoch ||
			pathProbeGenerationForSlot(slot) != generation {
			slot.releaseWrite()
			writePermitHeld = false
			slot.probeControlMu.Lock()
			slot.probeReplyPending = nil
			slot.probeReplyGeneration = pathProbeGeneration{}
			slot.probeReplyFenceEpoch = 0
			slot.probeReplyRunning = false
			slot.probeControlMu.Unlock()
			return
		}
		n, err := slot.writeFrameOwnedGuarded(frame, &callbackGuard)
		slot.releaseWrite()
		writePermitHeld = false
		if err == nil && n != len(frame) {
			err = io.ErrShortWrite
		}
		if err == nil {
			continue
		}
		e.failPathProbeControlWrite(slot, err)
		slot.probeControlMu.Lock()
		slot.probeReplyPending = nil
		slot.probeReplyGeneration = pathProbeGeneration{}
		slot.probeReplyFenceEpoch = 0
		slot.probeReplyRunning = false
		slot.probeControlMu.Unlock()
		return
	}
}

func (e *Engine) failPathProbeControlWrite(slot *pathSlot, err error) {
	e.failPathControlWrite(slot, err)
}

func (slot *pathSlot) closeProbeControl() {
	if slot == nil {
		return
	}
	slot.probeControlMu.Lock()
	slot.probeControlClosed = true
	slot.cancelProbeWritePermitWaitersLocked()
	slot.probeReplyPending = nil
	slot.probeReplyGeneration = pathProbeGeneration{}
	slot.probeReplyFenceEpoch = 0
	slot.probeControlMu.Unlock()
}

func (e *Engine) recordPathProbeIssuedLocked(observation pathProbeObservation) {
	if observation.slot == nil || observation.lifecycle != pathProbeWriteCommitted ||
		observation.writeCommittedAt.IsZero() || observation.generation != pathProbeGenerationForSlot(observation.slot) {
		return
	}
	evidence := pathProbeEvidence{
		generation: observation.generation, fenceEpoch: observation.fenceEpoch, fenceTracked: true,
		migrationEpoch: observation.wireMigrationEpoch, migrationTracked: observation.wireProgressTracked,
	}
	if current := observation.slot.probeEvidence.Load(); current != nil && current.generation == observation.generation {
		if observation.slot.probeEvidenceCurrent(current) {
			evidence = *current
			evidence.trackCurrentTokenCounters()
		} else {
			// Counters are lifetime diagnostics for the physical generation. Token
			// rollover invalidates liveness timestamps, not those aggregate totals.
			evidence.issued = current.issued
			evidence.succeeded = current.succeeded
			evidence.timedOut = current.timedOut
		}
	}
	evidence.generation = observation.generation
	evidence.fenceEpoch = observation.fenceEpoch
	evidence.fenceTracked = true
	evidence.migrationEpoch = observation.wireMigrationEpoch
	evidence.migrationTracked = observation.wireProgressTracked
	evidence.tokenStatsTracked = true
	if evidence.firstIssued.IsZero() {
		evidence.firstIssued = observation.writeCommittedAt
	}
	if evidence.tokenSucceeded == 0 {
		evidence.quality = transport.PathQuality{
			RTT: observation.quality.RTT, Jitter: observation.quality.Jitter, At: observation.quality.At,
		}
	}
	evidence.lastIssued = observation.writeCommittedAt
	evidence.lastLifecycle = pathProbeWriteCommitted
	evidence.lastTransition = observation.writeCommittedAt
	evidence.issued++
	evidence.tokenIssued++
	observation.slot.probeEvidence.Store(&evidence)
}

func pathProbeWriteStallFor(at time.Time, quality transport.PathQuality) time.Duration {
	window := minimumDispatchStallWindow
	if !quality.At.IsZero() {
		age := at.Sub(quality.At)
		if age >= 0 && age <= selectorEvidenceFreshFor {
			candidate := 4*quality.RTT + 2*quality.Jitter
			if candidate > window {
				window = candidate
			}
		}
	}
	if window > maximumDispatchStallWindow {
		return maximumDispatchStallWindow
	}
	return window
}

const maximumPathProbeDataStarvationFor = 2 * time.Second

// pathProbeDataStarvationFor requires two full probe cadences after the
// dispatcher has independently identified one stalled DATA generation. The
// cap combines with maximumDispatchStallWindow to keep default selector
// detection inside G4's five-second failover budget.
func pathProbeDataStarvationFor(interval time.Duration) time.Duration {
	if interval <= 0 {
		interval = DefaultLimits().ProbeInterval
	}
	if interval >= maximumPathProbeDataStarvationFor/2 {
		return maximumPathProbeDataStarvationFor
	}
	return 2 * interval
}

// refreshPathProbeBlockStatesLocked classifies local physical-writer stalls
// without creating wire evidence. A queued probe is data-starved only after
// the DATA dispatcher has independently marked the permit owner stalled in the
// same path generation. A predecessor-generation stall remains routing
// custody, but it cannot become successor health evidence. A probe already inside
// PathConn.Write has its own write-stalled state.
func (e *Engine) refreshPathProbeBlockStatesLocked(now time.Time) {
	for id, observation := range e.probeOutstanding {
		switch observation.lifecycle {
		case pathProbeQueued, pathProbeDataBlocked, pathProbeDataStarved:
			_, stall, stalled := observation.slot.healthEvidenceSnapshot()
			if !stalled || stall.pathGeneration != observation.generation {
				if observation.lifecycle != pathProbeQueued || observation.dataStallGeneration != 0 || !observation.dataBlockedAt.IsZero() {
					previousLifecycle := observation.lifecycle
					observation.lifecycle = pathProbeQueued
					observation.dataStallGeneration = 0
					observation.dataBlockedAt = time.Time{}
					e.mutatePathProbeLifecycleLocked(observation.slot, previousLifecycle, observation.lifecycle, func() {
						e.probeOutstanding[id] = observation
					})
				}
				continue
			}
			if observation.dataStallGeneration != stall.generation {
				previousLifecycle := observation.lifecycle
				observation.lifecycle = pathProbeDataBlocked
				observation.dataStallGeneration = stall.generation
				observation.dataBlockedAt = now
				if previousLifecycle == observation.lifecycle {
					observation.slot.mutateHealthEvidence(func() {
						e.probeOutstanding[id] = observation
					})
				} else {
					e.mutatePathProbeLifecycleLocked(observation.slot, previousLifecycle, observation.lifecycle, func() {
						e.probeOutstanding[id] = observation
					})
				}
				continue
			}
			if observation.lifecycle == pathProbeDataStarved {
				continue
			}
			previousLifecycle := observation.lifecycle
			if now.Before(observation.dataBlockedAt.Add(pathProbeDataStarvationFor(e.limits.ProbeInterval))) {
				observation.lifecycle = pathProbeDataBlocked
			} else {
				observation.lifecycle = pathProbeDataStarved
			}
			e.mutatePathProbeLifecycleLocked(observation.slot, previousLifecycle, observation.lifecycle, func() {
				e.probeOutstanding[id] = observation
			})
		case pathProbeWriteStarted:
			if !observation.writeStallDeadline.IsZero() && !now.Before(observation.writeStallDeadline) {
				previousLifecycle := observation.lifecycle
				observation.lifecycle = pathProbeWriteStalled
				e.mutatePathProbeLifecycleLocked(observation.slot, previousLifecycle, observation.lifecycle, func() {
					e.probeOutstanding[id] = observation
				})
			}
		}
	}
}

type flatSelectorProgressBaseline struct {
	ackNext        uint64
	dataNext       uint64
	migrationEpoch uint64
}

func (e *Engine) flatSelectorProgressBaseline(slot *pathSlot) (flatSelectorProgressBaseline, bool) {
	if e == nil || slot == nil {
		return flatSelectorProgressBaseline{}, false
	}
	runtime := e.localExecutionRuntime()
	if runtime == nil || !runtime.flatLeafSelector {
		return flatSelectorProgressBaseline{}, false
	}
	for attempts := 0; attempts < 3; attempts++ {
		fenceEpoch := slot.txFenceEpoch.Load()
		token := e.pathDataWriteToken(slot, fenceEpoch)
		if !token.valid() {
			return flatSelectorProgressBaseline{}, false
		}
		baseline := flatSelectorProgressBaseline{
			ackNext:        e.sendAckNext.Load(),
			migrationEpoch: token.migrationEpoch,
		}
		dataNext, witnessed := slot.earliestDataWriteAfter(baseline.ackNext, token)
		if witnessed {
			baseline.dataNext = dataNext
		}
		if token == e.pathDataWriteToken(slot, fenceEpoch) {
			return baseline, witnessed
		}
	}
	return flatSelectorProgressBaseline{}, false
}

func (e *Engine) pathProbeObservationCurrent(observation pathProbeObservation) bool {
	if e == nil || observation.slot == nil ||
		observation.generation != pathProbeGenerationForSlot(observation.slot) ||
		observation.fenceEpoch != observation.slot.txFenceEpoch.Load() {
		return false
	}
	return !observation.wireProgressTracked || e.migrationEpoch.Load() == observation.wireMigrationEpoch
}

func (e *Engine) flatSelectorCausalACK(
	observation pathProbeObservation,
	now time.Time,
) (sendACKProgressObservation, bool) {
	if !observation.wireProgressTracked || observation.wireDataWitnessNext == 0 ||
		!e.pathProbeObservationCurrent(observation) {
		return sendACKProgressObservation{}, false
	}
	runtime := e.localExecutionRuntime()
	if runtime == nil || !runtime.flatLeafSelector {
		return sendACKProgressObservation{}, false
	}
	progress := e.sendACKProgress.Load()
	if progress == nil || progress.next <= observation.wireAckBaseline ||
		progress.next < observation.wireDataWitnessNext ||
		!progress.at.After(observation.writeCommittedAt) || progress.at.After(now) ||
		!e.pathProbeObservationCurrent(observation) {
		return sendACKProgressObservation{}, false
	}
	return *progress, true
}

const maximumCommittedProbeLifetime = 5 * time.Second

func (e *Engine) refreshCommittedProbeDeadlineForProgress(
	observation *pathProbeObservation,
	now time.Time,
) bool {
	if observation == nil || observation.lifecycle != pathProbeWriteCommitted ||
		observation.deadline.IsZero() || now.Before(observation.deadline) ||
		observation.wireProgressDeferred || !e.pathProbeObservationCurrent(*observation) {
		return false
	}
	progress, causal := e.flatSelectorCausalACK(*observation, now)
	if !causal {
		return false
	}
	deadline := progress.at.Add(selectorProbeFreshFor(e.limits.ProbeInterval, observation.quality))
	maximum := observation.writeStartedAt.Add(maximumCommittedProbeLifetime)
	if deadline.After(maximum) {
		deadline = maximum
	}
	if !deadline.After(now) || !deadline.After(observation.deadline) {
		return false
	}
	observation.wireAckBaseline = progress.next
	observation.wireProgressDeferred = true
	observation.deadline = deadline
	return true
}

func (e *Engine) pathProbeStatuses(now time.Time) map[*pathSlot]pathProbeStatus {
	statuses := make(map[*pathSlot]pathProbeStatus)
	if e == nil {
		return statuses
	}
	e.probeMu.Lock()
	e.expirePathProbesLocked(now)
	for _, observation := range e.probeOutstanding {
		if observation.slot == nil || observation.generation != pathProbeGenerationForSlot(observation.slot) {
			continue
		}
		candidate := pathProbeStatus{lifecycle: observation.lifecycle}
		switch observation.lifecycle {
		case pathProbeDataStarved:
			candidate.failure = pathProbeFailureDataStarved
		case pathProbeWriteStalled:
			candidate.failure = pathProbeFailureWriteStalled
		}
		current := statuses[observation.slot]
		if pathProbeStatusPriority(candidate) > pathProbeStatusPriority(current) {
			statuses[observation.slot] = candidate
		}
	}
	e.probeMu.Unlock()
	return statuses
}

func pathProbeStatusPriority(status pathProbeStatus) uint8 {
	switch status.failure {
	case pathProbeFailureDataStarved:
		return 7
	case pathProbeFailureWriteStalled:
		return 6
	}
	switch status.lifecycle {
	case pathProbeWriteStarted:
		return 5
	case pathProbeDataBlocked:
		return 5
	case pathProbeQueued:
		return 4
	case pathProbeWriteCommitted:
		return 3
	case pathProbeReserved:
		return 2
	default:
		return 0
	}
}

func (e *Engine) expirePathProbes(now time.Time) {
	if e == nil {
		return
	}
	e.probeMu.Lock()
	e.expirePathProbesLocked(now)
	e.probeMu.Unlock()
}

func (e *Engine) expirePathProbesLocked(now time.Time) {
	for id, observation := range e.probeOutstanding {
		if !e.pathProbeObservationCurrent(observation) {
			e.mutatePathProbeLifecycleLocked(observation.slot, observation.lifecycle, pathProbeReserved, func() {
				delete(e.probeOutstanding, id)
			})
		}
	}
	e.refreshPathProbeBlockStatesLocked(now)
	for id, observation := range e.probeOutstanding {
		if observation.lifecycle != pathProbeWriteCommitted || observation.deadline.IsZero() {
			continue
		}
		if now.Before(observation.deadline) {
			continue
		}
		if e.refreshCommittedProbeDeadlineForProgress(&observation, now) {
			observation.slot.mutateHealthEvidence(func() {
				e.probeOutstanding[id] = observation
			})
			continue
		}
		observation.slot.mutateHealthEvidence(func() {
			observation.lifecycle = pathProbeWireTimeout
			e.recordPathProbeTimeoutLocked(observation, now)
			delete(e.probeOutstanding, id)
		})
	}
}

func (e *Engine) recordPathProbeTimeoutLocked(observation pathProbeObservation, at time.Time) {
	if !e.pathProbeObservationCurrent(observation) {
		return
	}
	current := observation.slot.probeEvidence.Load()
	if !observation.slot.probeEvidenceCurrent(current) || !pathProbeEvidenceMatchesObservation(current, observation) {
		return
	}
	next := *current
	next.trackCurrentTokenCounters()
	next.timedOut++
	next.tokenTimedOut++
	next.lastWireTimeout = at
	next.lastLifecycle = pathProbeWireTimeout
	next.lastTransition = at
	observation.slot.probeEvidence.Store(&next)
}

func (e *Engine) acceptPathProbeReply(slot *pathSlot, probe proto.ProbePayload, now time.Time) bool {
	e.probeMu.Lock()
	defer e.probeMu.Unlock()
	e.expirePathProbesLocked(now)
	observation, ok := e.probeOutstanding[probe.ID]
	if !ok || observation.slot != slot {
		return false
	}
	if observation.wireTS != probe.TS || !e.pathProbeObservationCurrent(observation) {
		return false
	}
	switch observation.lifecycle {
	case pathProbeWriteStarted, pathProbeWriteStalled:
		if now.Before(observation.writeStartedAt) {
			return false
		}
		if observation.pendingReplyAt.IsZero() || now.Before(observation.pendingReplyAt) {
			observation.pendingReplyAt = now
			e.probeOutstanding[probe.ID] = observation
		}
		return true
	case pathProbeWriteCommitted:
		if now.Before(observation.writeCommittedAt) {
			return false
		}
	default:
		return false
	}
	accepted := false
	slot.mutateHealthEvidence(func() {
		delete(e.probeOutstanding, probe.ID)
		accepted = e.recordPathProbeSuccessLocked(observation, now)
	})
	return accepted
}

func (e *Engine) recordPathProbeSuccessLocked(observation pathProbeObservation, now time.Time) bool {
	slot := observation.slot
	if slot == nil || !e.pathProbeObservationCurrent(observation) {
		return false
	}
	current := slot.probeEvidence.Load()
	if !slot.probeEvidenceCurrent(current) || !pathProbeEvidenceMatchesObservation(current, observation) {
		return false
	}
	successAt := now
	if successAt.Before(observation.writeCommittedAt) {
		successAt = observation.writeCommittedAt
	}
	rttStart := observation.writeCommittedAt
	if !observation.pendingReplyAt.IsZero() {
		// A reply observed before Write returned proves that the wire round trip
		// happened inside the physical Write. In that ordering, commit is only
		// an upper bound and Write start is the measurable transmission edge.
		rttStart = observation.writeStartedAt
	}
	rtt := now.Sub(rttStart)
	if rtt <= 0 {
		rtt = time.Nanosecond
	}
	jitter := current.quality.Jitter
	if current.quality.RTT > 0 {
		delta := rtt - current.quality.RTT
		if delta < 0 {
			delta = -delta
		}
		jitter = (jitter*3 + delta) / 4
	}
	next := *current
	next.trackCurrentTokenCounters()
	next.lastSuccess = successAt
	next.lastLifecycle = pathProbeWriteCommitted
	next.lastTransition = successAt
	next.succeeded++
	next.tokenSucceeded++
	next.quality = transport.PathQuality{RTT: rtt, Jitter: jitter, At: successAt}
	slot.probeEvidence.Store(&next)
	return true
}

func (e *Engine) invalidatePathProbeEvidence(slot *pathSlot) {
	if e == nil || slot == nil {
		return
	}
	e.probeMu.Lock()
	changed := slot.probeEvidence.Load() != nil
	for _, observation := range e.probeOutstanding {
		if observation.slot == slot {
			changed = true
		}
	}
	if changed {
		slot.mutateHealthEvidence(func() {
			for id, observation := range e.probeOutstanding {
				if observation.slot == slot {
					delete(e.probeOutstanding, id)
				}
			}
			slot.probeEvidence.Store(nil)
		})
	} else {
		slot.probeEvidence.Store(nil)
	}
	e.probeMu.Unlock()
}

// invalidatePredecessorPathProbeEvidence removes only observations from before
// a committed in-place route generation. A valid successor probe may complete
// concurrently with terminal mobility processing and must remain available.
func (e *Engine) invalidatePredecessorPathProbeEvidence(slot *pathSlot) {
	if e == nil || slot == nil {
		return
	}
	e.probeMu.Lock()
	e.invalidatePredecessorPathProbeEvidenceLocked(slot)
	e.probeMu.Unlock()
}

func (e *Engine) invalidatePredecessorPathProbeEvidenceLocked(slot *pathSlot) {
	// Caller holds probeMu. Taking the generation snapshot here is what makes a
	// successor publication ordered before cleanup survive that cleanup.
	current := pathProbeGenerationForSlot(slot)
	changed := false
	for _, observation := range e.probeOutstanding {
		if observation.slot != slot {
			continue
		}
		if observation.generation != current {
			changed = true
		}
	}
	evidence := slot.probeEvidence.Load()
	if evidence != nil && evidence.generation != current {
		changed = true
	}
	// This cleanup is called after an in-place route/endpoint generation
	// publication. Advance even when no predecessor probe object survived.
	if changed || current != (pathProbeGeneration{}) {
		slot.mutateHealthEvidence(func() {
			for id, observation := range e.probeOutstanding {
				if observation.slot == slot && observation.generation != current {
					delete(e.probeOutstanding, id)
				}
			}
			if evidence != nil && evidence.generation != current {
				slot.probeEvidence.CompareAndSwap(evidence, nil)
			}
		})
	}
}

func (e *Engine) clearPathProbeState(slots []*pathSlot) {
	if e == nil {
		return
	}
	e.probeMu.Lock()
	e.healthEvidenceCommitMu.RLock()
	changed := make(map[*pathSlot]bool)
	for _, observation := range e.probeOutstanding {
		if observation.slot != nil {
			changed[observation.slot] = true
		}
	}
	for _, slot := range slots {
		if slot != nil {
			if slot.probeEvidence.Load() != nil {
				changed[slot] = true
			}
			if changed[slot] {
				slot.healthEvidenceMu.Lock()
				slot.advanceHealthEvidenceRevisionLocked()
				slot.probeEvidence.Store(nil)
				slot.healthEvidenceMu.Unlock()
			} else {
				slot.probeEvidence.Store(nil)
			}
		}
	}
	e.probeOutstanding = make(map[uint64]pathProbeObservation)
	e.healthEvidenceCommitMu.RUnlock()
	e.probeMu.Unlock()
}
