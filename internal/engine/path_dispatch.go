package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/internal/dispatchtrust"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

const pathDispatchQueueSize = 64
const maximumPathDispatchBatch = 32
const maximumPathDispatchBatchYields = 15

const minimumDispatchStallWindow = 100 * time.Millisecond
const maximumDispatchStallWindow = 2 * time.Second

var (
	errFrameRetiredBeforeWrite = errors.New("engine: DATA frame retired before physical write")
	errFrameDispatchAdmission  = errors.New("engine: DATA dispatch lacks replay-ledger admission")
)

type pathDispatchCallbackPanicError struct {
	operation     string
	recoveredType string
}

func (err *pathDispatchCallbackPanicError) Error() string {
	return fmt.Sprintf("engine: transport %s callback panicked with %s", err.operation, err.recoveredType)
}

func newPathDispatchCallbackPanicError(operation string, recovered any) *pathDispatchCallbackPanicError {
	return &pathDispatchCallbackPanicError{
		operation:     operation,
		recoveredType: fmt.Sprintf("%T", recovered),
	}
}

type pathDispatchCallbackGoexitError struct {
	operation string
}

func (err *pathDispatchCallbackGoexitError) Error() string {
	return fmt.Sprintf("engine: transport %s callback called runtime.Goexit", err.operation)
}

type pathDispatchCallbackDeadlineError struct {
	operation string
	cause     error
}

func (err *pathDispatchCallbackDeadlineError) Error() string {
	reason := "was canceled"
	if errors.Is(err.cause, context.DeadlineExceeded) {
		reason = "exceeded its deadline"
	}
	return fmt.Sprintf("engine: transport %s callback %s", err.operation, reason)
}

func (err *pathDispatchCallbackDeadlineError) Unwrap() error { return err.cause }

type pathDispatchCallbackBusyError struct {
	operation string
}

func (err *pathDispatchCallbackBusyError) Error() string {
	return fmt.Sprintf("engine: transport %s callback already has an in-flight invocation", err.operation)
}

type pathDispatchCallbackCapacityError struct {
	operation string
}

func (err *pathDispatchCallbackCapacityError) Error() string {
	return fmt.Sprintf("engine: transport %s callback capacity is exhausted", err.operation)
}

type pathDispatchCallbackReadCountError struct {
	operation  string
	count      int
	bufferSize int
	cause      error
}

func (err *pathDispatchCallbackReadCountError) Error() string {
	return fmt.Sprintf(
		"engine: transport %s callback returned invalid byte count %d for %d-byte buffer",
		err.operation, err.count, err.bufferSize,
	)
}

func (err *pathDispatchCallbackReadCountError) Unwrap() error { return err.cause }

type pathDispatchCallbackGuard struct {
	goexitOperation string
}

type pathCallbackWriteResult struct {
	n   int
	err error
}

func (guard *pathDispatchCallbackGuard) recordGoexit(operation string) {
	if guard != nil && guard.goexitOperation == "" {
		guard.goexitOperation = operation
	}
}

func (guard *pathDispatchCallbackGuard) goexitError() *pathDispatchCallbackGoexitError {
	if guard == nil || guard.goexitOperation == "" {
		return nil
	}
	return &pathDispatchCallbackGoexitError{operation: guard.goexitOperation}
}

func pathCallbackFailedAbnormally(err error) bool {
	var panicErr *pathDispatchCallbackPanicError
	var goexitErr *pathDispatchCallbackGoexitError
	var readCountErr *pathDispatchCallbackReadCountError
	return errors.As(err, &panicErr) || errors.As(err, &goexitErr) || errors.As(err, &readCountErr)
}

func (e *Engine) failPathControlWrite(slot *pathSlot, err error) {
	if e == nil || slot == nil || err == nil {
		return
	}
	select {
	case <-slot.quit:
		return
	case <-e.closed:
		return
	default:
	}
	e.onPathDeath(slot.id, slot.owner, transport.CauseTransportError, err)
}

type FrameDispatchKind = transport.FrameDispatchKind
type FrameDispatchAttemptState = transport.FrameDispatchAttemptState

const (
	FrameDispatchKindUnknown       = transport.FrameDispatchKindUnknown
	FrameDispatchKindInitialCohort = transport.FrameDispatchKindInitialCohort
	FrameDispatchKindReplay        = transport.FrameDispatchKindReplay
	FrameDispatchAttemptUnknown    = transport.FrameDispatchAttemptUnknown
	FrameDispatchAttempted         = transport.FrameDispatchAttempted
	FrameDispatchNotAttempted      = transport.FrameDispatchNotAttempted
)

type frameDispatchAdmission struct {
	owner            *Engine
	id               uint64
	sequence         uint64
	digest           proto.FrameDigest
	frameBytes       int
	ledgerGeneration uint64
	kind             FrameDispatchKind
}

type FrameDispatchAuthorization = transport.FrameDispatchAuthorization
type FrameDispatchCompletion = transport.FrameDispatchCompletion
type FrameDispatchSpan = transport.FrameDispatchSpan
type FrameDispatchTracer = transport.FrameDispatchTracer

type physicalFrameDispatch struct {
	authorization FrameDispatchAuthorization
	data          bool
}

// frameDispatchLease gives one coherent ledger snapshot permission to reach a
// physical callback after sendHistMu is released. A later ACK may reclaim the
// immutable history because each leased job already owns its frame bytes and
// digest; batch attribution receipts are created under the same authorization
// lock before that ACK can detach their records.
type frameDispatchLease uint64

func (e *Engine) releaseFrameDispatchLease(lease *frameDispatchLease) {
	if e == nil || lease == nil || *lease == 0 {
		return
	}
	id := uint64(*lease)
	e.sendHistMu.Lock()
	if _, ok := e.frameDispatchLeases[id]; !ok {
		e.sendHistMu.Unlock()
		panic("engine: frame dispatch lease released without ownership")
	}
	delete(e.frameDispatchLeases, id)
	e.sendHistMu.Unlock()
	*lease = 0
}

type pathDispatchJob struct {
	frame                         []byte
	bonded                        bool
	capacityQualification         bool
	capacityQualificationPressure bool
	capacityQualificationComplete bool
	routePlanned                  bool
	topologyEpoch                 uint64
	firstPublication              bool
	admission                     frameDispatchAdmission
	preparedDispatch              physicalFrameDispatch
	dispatchPrepared              bool
	acceptedPacket                bool
	custodyTicket                 uint64
	result                        chan<- pathDispatchResult
	applicationWait               *applicationDispatchWaiter
	generation                    uint64
	pathGeneration                pathProbeGeneration
	fenceEpoch                    uint64
	submittedAt                   time.Time
	// beforePublication is a deterministic package-test hook. Tests install it
	// before submission and never mutate it concurrently.
	beforePublication func()
}

// pathDispatchBatchScratch is single-goroutine state owned by one pathSlot's
// writer. The fixed protocol batch limit bounds its memory independently of
// traffic volume. reset must run after callback-abnormal handling so replay
// payloads, waiters, callbacks and tracer spans are never retained while idle.
type pathDispatchBatchScratch struct {
	jobs             [maximumPathDispatchBatch]pathDispatchJob
	prepared         [maximumPathDispatchBatch]physicalFrameDispatch
	retired          [maximumPathDispatchBatch]bool
	receiptValues    [maximumPathDispatchBatch]batchDispatchAttributionReceipt
	preparedReceipts [maximumPathDispatchBatch]*batchDispatchAttributionReceipt
	activeIndices    [maximumPathDispatchBatch]int
	frames           [maximumPathDispatchBatch][]byte
	receipts         [maximumPathDispatchBatch]*batchDispatchAttributionReceipt
	cohorts          [maximumPathDispatchBatch]rootDeliveryCohort
	spans            [maximumPathDispatchBatch]FrameDispatchSpan
}

func (scratch *pathDispatchBatchScratch) reset(jobCount, activeCount int) {
	if scratch == nil {
		return
	}
	if jobCount < 0 || jobCount > maximumPathDispatchBatch ||
		activeCount < 0 || activeCount > jobCount {
		panic("engine: invalid path dispatch batch scratch extent")
	}
	clear(scratch.jobs[:jobCount])
	clear(scratch.prepared[:jobCount])
	clear(scratch.retired[:jobCount])
	clear(scratch.receiptValues[:jobCount])
	clear(scratch.preparedReceipts[:jobCount])
	clear(scratch.activeIndices[:activeCount])
	clear(scratch.frames[:activeCount])
	clear(scratch.receipts[:activeCount])
	clear(scratch.cohorts[:activeCount])
	clear(scratch.spans[:activeCount])
}

type pathDispatchIdentity struct {
	generation     uint64
	pathGeneration pathProbeGeneration
}

type pathDispatchStallSnapshot struct {
	identity pathDispatchIdentity
	// cutoverHandoff excludes an in-flight writer after selector custody has
	// moved to bounded replay. It is a routing fence, not evidence that the
	// carrier became unhealthy.
	cutoverHandoff bool
}

// pathDispatchStallState publishes one immutable stall fact. Load remains a
// cheap predicate for routing call sites; generation-sensitive consumers use
// snapshot so the fact cannot tear across independent atomics.
type pathDispatchStallState struct {
	state atomic.Pointer[pathDispatchStallSnapshot]
}

func (s *pathDispatchStallState) Load() bool {
	return s != nil && s.state.Load() != nil
}

func (s *pathDispatchStallState) snapshot() *pathDispatchStallSnapshot {
	if s == nil {
		return nil
	}
	return s.state.Load()
}

func (s *pathSlot) currentDispatchStall() (pathDispatchIdentity, bool) {
	_, identity, ok := s.healthEvidenceSnapshot()
	return identity, ok
}

func (s *pathSlot) healthEvidenceSnapshot() (uint64, pathDispatchIdentity, bool) {
	if s == nil {
		return 0, pathDispatchIdentity{}, false
	}
	s.healthEvidenceMu.Lock()
	defer s.healthEvidenceMu.Unlock()
	revision := s.healthEvidenceRevisionLocked()
	stall := s.dispatchStalled.snapshot()
	if stall == nil || stall.cutoverHandoff {
		return revision, pathDispatchIdentity{}, false
	}
	return revision, stall.identity, true
}

func (s *pathSlot) cutoverDispatchStalled() bool {
	if s == nil {
		return false
	}
	stall := s.dispatchStalled.snapshot()
	return stall != nil && stall.cutoverHandoff
}

func (s *pathSlot) healthEvidenceRevisionLocked() uint64 {
	if s.healthEvidenceRevision == 0 {
		s.healthEvidenceRevision = 1
	}
	return s.healthEvidenceRevision
}

func (s *pathSlot) advanceHealthEvidenceRevisionLocked() uint64 {
	current := s.healthEvidenceRevisionLocked()
	if current == ^uint64(0) {
		panic("engine: health evidence revision exhausted")
	}
	advanceHealthEvidenceEpoch(s.healthEvidenceEpochSrc)
	s.healthEvidenceRevision = current + 1
	return s.healthEvidenceRevision
}

func (s *pathSlot) lockHealthEvidenceMutation() func() {
	if s == nil {
		panic("engine: health evidence mutation on nil path")
	}
	if hook := s.healthEvidenceBeforeGate; hook != nil {
		hook()
	}
	if s.healthEvidenceCommitMu != nil {
		s.healthEvidenceCommitMu.RLock()
	}
	s.healthEvidenceMu.Lock()
	return func() {
		s.healthEvidenceMu.Unlock()
		if s.healthEvidenceCommitMu != nil {
			s.healthEvidenceCommitMu.RUnlock()
		}
	}
}

func (s *pathSlot) mutateHealthEvidence(mutate func()) {
	unlock := s.lockHealthEvidenceMutation()
	defer unlock()
	s.advanceHealthEvidenceRevisionLocked()
	if mutate != nil {
		mutate()
	}
}

func advanceHealthEvidenceEpoch(epoch *atomic.Uint64) {
	if epoch == nil {
		return
	}
	for {
		current := epoch.Load()
		if current == 0 || current == ^uint64(0) {
			panic("engine: health evidence epoch is invalid or exhausted")
		}
		if epoch.CompareAndSwap(current, current+1) {
			return
		}
	}
}

func (s *pathSlot) advanceHealthEvidenceRevision() uint64 {
	var revision uint64
	s.mutateHealthEvidence(func() {
		revision = s.healthEvidenceRevision
	})
	return revision
}

const (
	applicationDispatchWaiting uint32 = iota
	applicationDispatchAbandoned
	applicationDispatchDelivered
)

type applicationDispatchWaiter struct {
	state atomic.Uint32
	done  chan pathDispatchResult
}

var applicationDispatchWaiterPool = sync.Pool{New: func() any {
	return &applicationDispatchWaiter{done: make(chan pathDispatchResult, 1)}
}}

func acquireApplicationDispatchWaiter() *applicationDispatchWaiter {
	waiter := applicationDispatchWaiterPool.Get().(*applicationDispatchWaiter)
	waiter.state.Store(applicationDispatchWaiting)
	select {
	case <-waiter.done:
		panic("engine: pooled application dispatch waiter retained a result")
	default:
	}
	return waiter
}

func releaseApplicationDispatchWaiter(waiter *applicationDispatchWaiter) {
	if waiter == nil {
		return
	}
	waiter.state.Store(applicationDispatchWaiting)
	applicationDispatchWaiterPool.Put(waiter)
}

func abandonApplicationDispatchWaiter(waiter *applicationDispatchWaiter) {
	if waiter == nil || waiter.state.CompareAndSwap(applicationDispatchWaiting, applicationDispatchAbandoned) {
		return
	}
	// The writer won the race and owns a buffered delivery. Consume it before
	// recycling so a later dispatch can never observe this generation.
	<-waiter.done
	releaseApplicationDispatchWaiter(waiter)
}

func completeApplicationDispatchWaiter(waiter *applicationDispatchWaiter, result pathDispatchResult) {
	if waiter.state.CompareAndSwap(applicationDispatchWaiting, applicationDispatchDelivered) {
		waiter.done <- result
		return
	}
	if !waiter.state.CompareAndSwap(applicationDispatchAbandoned, applicationDispatchDelivered) {
		panic("engine: application dispatch waiter completed more than once")
	}
	releaseApplicationDispatchWaiter(waiter)
}

func (s *pathSlot) nextDispatchGeneration() uint64 {
	if s == nil {
		panic("engine: dispatch generation on nil path")
	}
	for {
		current := s.dispatchNextGen.Load()
		if current == ^uint64(0) {
			panic("engine: dispatch generation exhausted")
		}
		generation := current + 1
		if s.dispatchNextGen.CompareAndSwap(current, generation) {
			return generation
		}
	}
}

func (s *pathSlot) markDispatchStalled(identity pathDispatchIdentity) {
	s.markDispatchStall(identity, false)
}

func (s *pathSlot) markDispatchCutoverHandoff(identity pathDispatchIdentity) {
	s.markDispatchStall(identity, true)
}

func (s *pathSlot) markDispatchStall(identity pathDispatchIdentity, cutoverHandoff bool) {
	if s == nil || identity.generation == 0 {
		return
	}
	unlock := s.lockHealthEvidenceMutation()
	defer unlock()
	if s.dispatchDoneGen.Load() >= identity.generation {
		return
	}
	for {
		current := s.dispatchStalled.state.Load()
		if s.dispatchDoneGen.Load() >= identity.generation {
			return
		}
		if current != nil {
			if current.identity.generation > identity.generation {
				return
			}
			if current.identity.generation == identity.generation {
				if !current.cutoverHandoff || cutoverHandoff {
					return
				}
				// A factual observation upgrades an earlier custody-only fence.
				candidate := &pathDispatchStallSnapshot{identity: identity}
				if !s.dispatchStalled.state.CompareAndSwap(current, candidate) {
					continue
				}
				if pathProbeGenerationForSlot(s) == identity.pathGeneration {
					s.advanceHealthEvidenceRevisionLocked()
				}
				return
			}
			// Never erase an unresolved factual stall merely because a newer
			// dispatch was handed to cutover replay.
			candidateCutoverHandoff := cutoverHandoff
			if !current.cutoverHandoff && candidateCutoverHandoff {
				candidateCutoverHandoff = false
			}
			candidate := &pathDispatchStallSnapshot{
				identity: identity, cutoverHandoff: candidateCutoverHandoff,
			}
			if !s.dispatchStalled.state.CompareAndSwap(current, candidate) {
				continue
			}
			if !candidate.cutoverHandoff && pathProbeGenerationForSlot(s) == identity.pathGeneration {
				s.advanceHealthEvidenceRevisionLocked()
			}
			return
		}
		candidate := &pathDispatchStallSnapshot{
			identity: identity, cutoverHandoff: cutoverHandoff,
		}
		if !s.dispatchStalled.state.CompareAndSwap(current, candidate) {
			continue
		}
		if !candidate.cutoverHandoff && pathProbeGenerationForSlot(s) == identity.pathGeneration {
			s.advanceHealthEvidenceRevisionLocked()
		}
		return
	}
}

func (s *pathSlot) completeDispatch(identity pathDispatchIdentity) {
	if s == nil || identity.generation == 0 {
		return
	}
	unlock := s.lockHealthEvidenceMutation()
	defer unlock()
	for {
		completed := s.dispatchDoneGen.Load()
		if identity.generation <= completed || s.dispatchDoneGen.CompareAndSwap(completed, identity.generation) {
			break
		}
	}
	for {
		current := s.dispatchStalled.state.Load()
		if current == nil || current.identity != identity {
			return
		}
		if s.dispatchStalled.state.CompareAndSwap(current, nil) {
			if !current.cutoverHandoff && pathProbeGenerationForSlot(s) == identity.pathGeneration {
				s.advanceHealthEvidenceRevisionLocked()
			}
			return
		}
	}
}

type pathDispatchResult struct {
	slot *pathSlot
	err  error
}

type pathDispatchBatchOutcome struct {
	pending    pathDispatchJob
	hasPending bool
	handled    bool
}

type detachedStreamDispatchLease struct {
	custodyTicket uint64
}

func (s *pathSlot) submitDispatch(job pathDispatchJob) bool {
	_, submitted := s.submitDispatchTracked(job)
	return submitted
}

func (s *pathSlot) submitDispatchTracked(job pathDispatchJob) (pathDispatchIdentity, bool) {
	s.dispatchMu.Lock()
	defer s.dispatchMu.Unlock()
	if s.dispatchDead || s.dispatchFenced {
		return pathDispatchIdentity{}, false
	}
	if job.generation == 0 {
		job.generation = s.nextDispatchGeneration()
	}
	job.pathGeneration = pathProbeGenerationForSlot(s)
	identity := pathDispatchIdentity{
		generation:     job.generation,
		pathGeneration: job.pathGeneration,
	}
	job.fenceEpoch = s.txFenceEpoch.Load()
	if job.beforePublication != nil {
		job.beforePublication()
	}
	job.submittedAt = nowFn()
	select {
	case s.dispatchQ <- job:
		return identity, true
	default:
		return pathDispatchIdentity{}, false
	}
}

func (e *Engine) pathWriterLoop(slot *pathSlot) {
	defer close(slot.doneW)
	var pending pathDispatchJob
	hasPending := false
	for {
		if hasPending {
			select {
			case <-slot.quit:
				e.completeRejectedDispatch(slot, pending)
				e.rejectQueuedDispatches(slot)
				return
			case <-e.closed:
				e.completeRejectedDispatch(slot, pending)
				e.rejectQueuedDispatches(slot)
				return
			default:
			}
			job := pending
			pending = pathDispatchJob{}
			hasPending = false
			if outcome := e.executePathDispatchBatch(slot, job); outcome.handled {
				pending, hasPending = outcome.pending, outcome.hasPending
			} else {
				e.executePathDispatch(slot, job)
			}
			continue
		}
		select {
		case job := <-slot.dispatchQ:
			if outcome := e.executePathDispatchBatch(slot, job); outcome.handled {
				pending, hasPending = outcome.pending, outcome.hasPending
			} else {
				e.executePathDispatch(slot, job)
			}
		case <-slot.quit:
			e.rejectQueuedDispatches(slot)
			return
		case <-e.closed:
			e.rejectQueuedDispatches(slot)
			return
		}
	}
}

func (e *Engine) executePathDispatchBatch(slot *pathSlot, first pathDispatchJob) pathDispatchBatchOutcome {
	var scratch *pathDispatchBatchScratch
	usedJobs, usedActive := 0, 0
	defer func() {
		if scratch != nil {
			scratch.reset(usedJobs, usedActive)
		}
	}()
	callbackGuard := pathDispatchCallbackGuard{}
	var (
		abnormalJobs     []pathDispatchJob
		abnormalRetired  []bool
		abnormalReceipts []*batchDispatchAttributionReceipt
		pending          pathDispatchJob
		hasPending       bool
	)
	defer func() {
		if callbackErr := callbackGuard.goexitError(); callbackErr != nil {
			e.failPathDispatchCallback(
				slot, callbackErr, abnormalJobs, abnormalRetired,
				pending, hasPending, abnormalReceipts,
			)
		}
	}()

	writer, ok := slot.conn.(transport.FrameBatchWriter)
	_, atomicDispatch := slot.conn.(transport.FrameDispatchWriter)
	if !ok || atomicDispatch || !e.Packetized() {
		return pathDispatchBatchOutcome{}
	}
	firstSeq, ok := packetApplicationDispatchSequence(first)
	if !ok {
		return pathDispatchBatchOutcome{}
	}
	if !slot.txEnabled.Load() || slot.txFenceEpoch.Load() != first.fenceEpoch {
		e.completePathDispatch(slot, first, ErrPathTXFenced)
		return pathDispatchBatchOutcome{handled: true}
	}
	if slot.dispatchBeforeWritePermit != nil {
		slot.dispatchBeforeWritePermit()
	}
	if err := slot.acquireWrite(context.Background()); err != nil {
		e.completePathDispatch(slot, first, err)
		return pathDispatchBatchOutcome{handled: true}
	}
	writePermitHeld := true
	defer func() {
		if writePermitHeld {
			slot.releaseWrite()
		}
	}()

	scratch = slot.dispatchBatchScratch
	if scratch == nil {
		scratch = &pathDispatchBatchScratch{}
		slot.dispatchBatchScratch = scratch
	}
	jobs := scratch.jobs[:1]
	jobs[0] = first
	usedJobs = 1
	lastSeq := firstSeq
	yields := 0
	for len(jobs) < maximumPathDispatchBatch {
		select {
		case candidate := <-slot.dispatchQ:
			seq, compatible := packetApplicationDispatchSequence(candidate)
			if !compatible || candidate.fenceEpoch != first.fenceEpoch ||
				candidate.topologyEpoch != first.topologyEpoch || seq != lastSeq+1 {
				pending = candidate
				hasPending = true
				goto drained
			}
			jobs = append(jobs, candidate)
			usedJobs = len(jobs)
			lastSeq = seq
		default:
			if yields < maximumPathDispatchBatchYields &&
				e.packetWritesInFlight.Load() > int64(len(jobs)) {
				yields++
				if e.pathDispatchBatchYield != nil {
					e.pathDispatchBatchYield()
				} else {
					runtime.Gosched()
				}
				continue
			}
			goto drained
		}
	}

drained:
	if !slot.txEnabled.Load() || slot.txFenceEpoch.Load() != first.fenceEpoch {
		slot.releaseWrite()
		writePermitHeld = false
		for _, job := range jobs {
			e.completePathDispatch(slot, job, ErrPathTXFenced)
		}
		return pathDispatchBatchOutcome{pending: pending, hasPending: hasPending, handled: true}
	}
	allJobs := jobs
	prepared := scratch.prepared[:len(allJobs)]
	retired := scratch.retired[:len(allJobs)]
	receiptValues := scratch.receiptValues[:len(allJobs)]
	preparedReceipts := scratch.preparedReceipts[:len(allJobs)]
	lease, err := e.preparePhysicalFrameDispatchBatch(
		allJobs, slot, prepared, retired, receiptValues, preparedReceipts,
	)
	if err != nil {
		slot.releaseWrite()
		writePermitHeld = false
		for _, queued := range allJobs {
			e.completePathDispatch(slot, queued, err)
		}
		return pathDispatchBatchOutcome{pending: pending, hasPending: hasPending, handled: true}
	}
	defer func() {
		if lease != 0 {
			e.releaseFrameDispatchLease(&lease)
		}
	}()
	abnormalJobs = allJobs
	abnormalRetired = retired
	abnormalReceipts = preparedReceipts
	if lease != 0 && e.frameDispatchBatchAfterLease != nil {
		e.frameDispatchBatchAfterLease()
	}
	activeIndices := scratch.activeIndices[:0]
	frames := scratch.frames[:0]
	receipts := scratch.receipts[:0]
	for i, job := range allJobs {
		if retired[i] {
			continue
		}
		activeIndices = append(activeIndices, i)
		frames = append(frames, job.frame)
		receipts = append(receipts, preparedReceipts[i])
		usedActive = len(activeIndices)
	}
	if len(activeIndices) == 0 {
		slot.releaseWrite()
		writePermitHeld = false
		for _, job := range allJobs {
			e.completePathDispatch(slot, job, nil)
		}
		return pathDispatchBatchOutcome{pending: pending, hasPending: hasPending, handled: true}
	}
	cohorts := scratch.cohorts[:len(frames)]
	for i, frame := range frames {
		cohorts[i] = e.applicationRootCohortFromFrame(frame)
	}
	spans := scratch.spans[:len(activeIndices)]
	for i, originalIndex := range activeIndices {
		spans[i] = beginPhysicalFrameDispatch(slot, prepared[originalIndex], &callbackGuard)
	}
	writeToken := e.pathDataWriteToken(slot, first.fenceEpoch)
	started := nowFn()
	completed, batchErr := writeExternalFrameBatchGuarded(writer, frames, &callbackGuard)
	finished := nowFn()
	completed, batchErr = classifyFrameBatchResult(len(activeIndices), completed, batchErr)
	var perFrameService, serviceRemainder time.Duration
	if service := finished.Sub(started); completed > 0 && service > 0 {
		perFrameService = service / time.Duration(completed)
		serviceRemainder = service % time.Duration(completed)
	}
	for index := 0; index < completed; index++ {
		service := perFrameService
		if index == 0 {
			service += serviceRemainder
		}
		receipts[index].noteCapacityPressure(applicationDispatchPressureObservation{
			startedAt: started, completedAt: finished, serviceDuration: service,
		})
		job := allJobs[activeIndices[index]]
		if job.capacityQualification {
			receipts[index].noteCapacityQualificationPressure(
				started, finished, job.capacityQualificationPressure,
				job.capacityQualificationComplete,
			)
		}
	}
	for i, span := range spans {
		if span == nil {
			continue
		}
		completion := FrameDispatchCompletion{
			StartedAt: started, CompletedAt: finished, FrameBytes: len(frames[i]),
			AttemptState: FrameDispatchAttemptUnknown,
			BatchIndex:   i, BatchSize: len(frames),
		}
		if i < completed {
			completion.BytesWritten = len(frames[i])
			completion.BytesWrittenKnown = true
			completion.AttemptState = FrameDispatchAttempted
			completion.WriteAttempted = true
			completion.WholeFrameAccepted = true
		} else {
			completion.Err = batchErr
		}
		if completed == len(frames) && batchErr != nil && i == len(frames)-1 {
			completion.Err = batchErr
		}
		finishPhysicalFrameDispatch(span, completion, &callbackGuard)
	}
	// The transport callback and every tracer completion are now outside the
	// ACK-retirement race. Release before publishing per-job results so tests and
	// callers cannot observe a completed dispatch with a leaked lease.
	if lease != 0 {
		e.releaseFrameDispatchLease(&lease)
	}
	// Publish each successful first DATA write before releasing the permit. A
	// following probe can then bind ACK progress to a path-unique predecessor.
	for i := 0; i < completed; i++ {
		job := allJobs[activeIndices[i]]
		if job.firstPublication && len(job.frame) >= proto.HeaderSize {
			if header, err := proto.DecodeHeader(job.frame[:proto.HeaderSize]); err == nil &&
				header.Type == proto.FrameData {
				slot.noteFirstDataWriteSequence(header.Seq, writeToken)
			}
		}
	}
	if e.pathDispatchBatchBeforePermitRelease != nil {
		e.pathDispatchBatchBeforePermitRelease(slot)
	}
	slot.releaseWrite()
	writePermitHeld = false
	e.resolveApplicationBatchDispatch(receipts, completed)
	if completed > 0 {
		slot.batchWriteCalls.Add(1)
		slot.batchWriteFrames.Add(uint64(completed))
		updateAtomicMaximum(&slot.batchWriteMax, uint64(completed))
		slot.dataWrites.Add(uint64(completed))
		slot.lastSendUnixNano.Store(nowFn().UnixNano())
		for i := 0; i < completed; i++ {
			job := allJobs[activeIndices[i]]
			e.noteApplicationDispatchDuration(
				cohorts[i], job.topologyEpoch, started, finished, true,
			)
			slot.recordDispatch(job.frame, job.firstPublication)
			e.noteTailReplayPublication(job.frame, slot)
		}
	}
	if batchErr != nil && !errors.Is(batchErr, ErrPathTXFenced) {
		// The completed prefix remains successful. The error retires the path
		// and applies only to the first incomplete frame and its suffix.
		e.onPathDeath(slot.id, slot.owner, transport.CauseTransportError, batchErr)
	}
	written := 0
	for i, job := range allJobs {
		var err error
		if !retired[i] {
			if written >= completed {
				err = batchErr
			}
			written++
		}
		e.completePathDispatch(slot, job, err)
	}
	return pathDispatchBatchOutcome{pending: pending, hasPending: hasPending, handled: true}
}

func updateAtomicMaximum(value *atomic.Uint64, candidate uint64) {
	for current := value.Load(); candidate > current; current = value.Load() {
		if value.CompareAndSwap(current, candidate) {
			return
		}
	}
}

func packetApplicationDispatchSequence(job pathDispatchJob) (uint64, bool) {
	if (job.applicationWait == nil && !job.acceptedPacket) || job.bonded || len(job.frame) < proto.HeaderSize {
		return 0, false
	}
	header, err := proto.DecodeHeader(job.frame[:proto.HeaderSize])
	if err != nil || header.Type != proto.FrameData {
		return 0, false
	}
	return header.Seq, true
}

func applicationDispatchAckTarget(frame []byte) (uint64, bool) {
	if len(frame) < proto.HeaderSize {
		return 0, false
	}
	header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	if err != nil || header.Type != proto.FrameData || header.Seq == proto.MaxSeq {
		return 0, false
	}
	return header.Seq + 1, true
}

func (e *Engine) admitFrameDispatch(frame []byte, firstPublication bool) (frameDispatchAdmission, error) {
	if len(frame) < proto.HeaderSize {
		return frameDispatchAdmission{}, proto.ErrBadHeader
	}
	header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	if err != nil {
		return frameDispatchAdmission{}, err
	}
	if header.Type != proto.FrameData {
		return frameDispatchAdmission{}, nil
	}
	if header.Seq == proto.MaxSeq {
		return frameDispatchAdmission{}, errFrameDispatchAdmission
	}
	e.sendHistMu.Lock()
	entry := e.sendHistoryEntryLocked(header.Seq)
	ackNext := e.sendAckNext.Load()
	publishedNext := e.sendPublishedNext.Load()
	if entry == nil {
		e.sendHistMu.Unlock()
		if ackNext > header.Seq {
			return frameDispatchAdmission{}, errFrameRetiredBeforeWrite
		}
		return frameDispatchAdmission{}, errFrameDispatchAdmission
	}
	digest := entry.frameDigest
	if !sameFrameBacking(frame, entry.frame) {
		digest = proto.DigestFrame(frame)
	}
	if entry.frameDigest != digest || publishedNext <= header.Seq {
		e.sendHistMu.Unlock()
		return frameDispatchAdmission{}, errFrameDispatchAdmission
	}
	ledgerGeneration := e.sendHist.generation
	e.sendHistMu.Unlock()
	kind := FrameDispatchKindReplay
	if firstPublication {
		kind = FrameDispatchKindInitialCohort
	}
	return frameDispatchAdmission{
		owner: e, id: nextFrameDispatchIdentity(&e.frameDispatchAdmissionNext), sequence: header.Seq,
		digest: digest, frameBytes: len(frame), ledgerGeneration: ledgerGeneration, kind: kind,
	}, nil
}

func (e *Engine) authorizeFrameDispatch(
	frame []byte,
	admission frameDispatchAdmission,
) (FrameDispatchAuthorization, bool, bool, error) {
	e.sendHistMu.Lock()
	digest, _ := e.frameDigestForDispatchLocked(frame, admission)
	authorization, data, retired, err := e.authorizeFrameDispatchLocked(frame, digest, admission)
	e.sendHistMu.Unlock()
	return authorization, data, retired, err
}

// frameDigestForDispatchLocked reuses the ledger digest only when admission
// still names the exact immutable backing array owned by that ledger entry.
// A copied or substituted slice takes the full digest path and remains subject
// to the same admission checks. The caller holds sendHistMu.
func (e *Engine) frameDigestForDispatchLocked(
	frame []byte,
	admission frameDispatchAdmission,
) (proto.FrameDigest, bool) {
	if admission.owner == e && admission.id != 0 && admission.frameBytes == len(frame) {
		entry := e.sendHistoryEntryLocked(admission.sequence)
		if entry != nil && entry.frameDigest == admission.digest && sameFrameBacking(frame, entry.frame) {
			return admission.digest, true
		}
	}
	return proto.DigestFrame(frame), false
}

func sameFrameBacking(left, right []byte) bool {
	return len(left) == len(right) && len(left) != 0 && &left[0] == &right[0]
}

// authorizeFrameDispatchLocked validates one immutable frame against the
// current replay ledger. The caller owns sendHistMu; keeping the complete batch
// under this lock prevents a cumulative ACK from retiring a suffix between
// per-item checks.
func (e *Engine) authorizeFrameDispatchLocked(
	frame []byte,
	digest proto.FrameDigest,
	admission frameDispatchAdmission,
) (FrameDispatchAuthorization, bool, bool, error) {
	if len(frame) < proto.HeaderSize {
		return FrameDispatchAuthorization{}, false, false, proto.ErrBadHeader
	}
	header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	if err != nil {
		return FrameDispatchAuthorization{}, false, false, err
	}
	if header.Type != proto.FrameData {
		return FrameDispatchAuthorization{}, false, false, nil
	}
	if admission.owner != e || admission.id == 0 || admission.sequence != header.Seq ||
		admission.digest != digest || admission.frameBytes != len(frame) || admission.ledgerGeneration == 0 ||
		(admission.kind != FrameDispatchKindInitialCohort && admission.kind != FrameDispatchKindReplay) {
		return FrameDispatchAuthorization{}, true, false, errFrameDispatchAdmission
	}
	publishedNext := e.sendPublishedNext.Load()
	ackNext := e.sendAckNext.Load()
	ledgerGeneration := e.sendHist.generation
	entry := e.sendHistoryEntryLocked(header.Seq)
	if publishedNext <= header.Seq || admission.ledgerGeneration > ledgerGeneration ||
		(entry == nil && ackNext <= header.Seq) ||
		(entry != nil && entry.frameDigest != digest) {
		return FrameDispatchAuthorization{}, true, false, errFrameDispatchAdmission
	}
	authorizedAt := nowFn()
	authorization := FrameDispatchAuthorization{
		Sequence: header.Seq, PublishedNext: publishedNext, AckNext: ackNext,
		AdmissionLedgerGeneration: admission.ledgerGeneration, LedgerGeneration: ledgerGeneration,
		AdmissionID: admission.id,
		AttemptID:   nextFrameDispatchIdentity(&e.frameDispatchAttemptNext), Kind: admission.kind,
		AuthorizedAt: authorizedAt, FrameBytes: len(frame), FrameDigest: digest,
	}
	retired := ackNext > header.Seq
	return authorization, true, retired, nil
}

func nextFrameDispatchIdentity(counter *atomic.Uint64) uint64 {
	for {
		if identity := counter.Add(1); identity != 0 {
			return identity
		}
	}
}

func (e *Engine) preparePhysicalFrameDispatch(
	job pathDispatchJob,
) (physicalFrameDispatch, frameDispatchLease, error) {
	e.sendHistMu.Lock()
	digest, _ := e.frameDigestForDispatchLocked(job.frame, job.admission)
	dispatch := job.preparedDispatch
	retired := false
	if job.dispatchPrepared {
		if err := e.validatePreparedFrameDispatch(job.frame, digest, job.admission, dispatch); err != nil {
			e.sendHistMu.Unlock()
			return physicalFrameDispatch{}, 0, err
		}
	} else {
		authorization, data, itemRetired, err := e.authorizeFrameDispatchLocked(job.frame, digest, job.admission)
		if err != nil {
			e.sendHistMu.Unlock()
			return physicalFrameDispatch{}, 0, err
		}
		dispatch = physicalFrameDispatch{authorization: authorization, data: data}
		retired = itemRetired
	}
	if dispatch.data {
		expectedKind := FrameDispatchKindReplay
		if job.firstPublication {
			expectedKind = FrameDispatchKindInitialCohort
		}
		if dispatch.authorization.Kind != expectedKind {
			e.sendHistMu.Unlock()
			return physicalFrameDispatch{}, 0, errFrameDispatchAdmission
		}
	}
	var lease frameDispatchLease
	if dispatch.data && !retired {
		lease = e.newFrameDispatchLeaseLocked()
	}
	e.sendHistMu.Unlock()
	if retired {
		return physicalFrameDispatch{}, 0, errFrameRetiredBeforeWrite
	}
	return dispatch, lease, nil
}

// newFrameDispatchLeaseLocked registers one callback lease. The caller holds
// sendHistMu.
func (e *Engine) newFrameDispatchLeaseLocked() frameDispatchLease {
	leaseID := nextFrameDispatchIdentity(&e.frameDispatchLeaseNext)
	if e.frameDispatchLeases == nil {
		e.frameDispatchLeases = make(map[uint64]struct{})
	}
	if _, duplicate := e.frameDispatchLeases[leaseID]; duplicate {
		panic("engine: duplicate frame dispatch lease identity")
	}
	e.frameDispatchLeases[leaseID] = struct{}{}
	return frameDispatchLease(leaseID)
}

func (e *Engine) preparePhysicalFrameDispatchBatch(
	jobs []pathDispatchJob,
	batchSlot *pathSlot,
	dispatches []physicalFrameDispatch,
	retired []bool,
	receiptValues []batchDispatchAttributionReceipt,
	receipts []*batchDispatchAttributionReceipt,
) (frameDispatchLease, error) {
	if len(dispatches) != len(jobs) || len(retired) != len(jobs) ||
		len(receiptValues) != len(jobs) || len(receipts) != len(jobs) {
		panic("engine: physical frame batch scratch has inconsistent lengths")
	}
	if len(jobs) == 0 {
		return 0, nil
	}
	var binding graphBinding
	var attributionStarted time.Time
	if batchSlot != nil {
		binding = e.localGraphBinding()
		attributionStarted = nowFn()
	}
	e.sendHistMu.Lock()
	leasedDATA := 0
	for index, job := range jobs {
		digest, _ := e.frameDigestForDispatchLocked(job.frame, job.admission)
		dispatch := job.preparedDispatch
		itemRetired := false
		if job.dispatchPrepared {
			if err := e.validatePreparedFrameDispatch(job.frame, digest, job.admission, dispatch); err != nil {
				e.sendHistMu.Unlock()
				return 0, err
			}
		} else {
			authorization, data, retired, err := e.authorizeFrameDispatchLocked(job.frame, digest, job.admission)
			if err != nil {
				e.sendHistMu.Unlock()
				return 0, err
			}
			dispatch = physicalFrameDispatch{authorization: authorization, data: data}
			itemRetired = retired
		}
		data := dispatch.data
		if data {
			expectedKind := FrameDispatchKindReplay
			if job.firstPublication {
				expectedKind = FrameDispatchKindInitialCohort
			}
			if dispatch.authorization.Kind != expectedKind {
				e.sendHistMu.Unlock()
				return 0, errFrameDispatchAdmission
			}
		}
		dispatches[index] = dispatch
		retired[index] = itemRetired
		if data && !itemRetired {
			leasedDATA++
		}
		if e.frameDispatchBatchAfterValidation != nil {
			e.frameDispatchBatchAfterValidation(index)
		}
	}

	var lease frameDispatchLease
	if leasedDATA != 0 {
		lease = e.newFrameDispatchLeaseLocked()
	}
	if batchSlot != nil {
		for index, job := range jobs {
			if retired[index] || job.routePlanned {
				continue
			}
			receipts[index] = e.beginApplicationBatchDispatchLockedInto(
				job.frame, batchSlot, job.topologyEpoch, binding, attributionStarted,
				&receiptValues[index],
			)
		}
	}
	e.sendHistMu.Unlock()
	return lease, nil
}

// prepareLogicalFrameDispatchFanout commits every child of one race ticket in
// a single replay-ledger snapshot. A fast child may ACK before a slower path
// writer runs, but that later write still belongs to the already-committed race
// cohort and therefore must not be mistaken for a new ACK-retired replay.
func (e *Engine) prepareLogicalFrameDispatchFanout(
	jobs []pathDispatchJob,
) ([]physicalFrameDispatch, error) {
	dispatches := make([]physicalFrameDispatch, len(jobs))
	if len(jobs) < 2 {
		return nil, errors.New("engine: frame dispatch fanout requires at least two paths")
	}
	e.sendHistMu.Lock()
	defer e.sendHistMu.Unlock()
	for index, job := range jobs {
		digest, _ := e.frameDigestForDispatchLocked(job.frame, job.admission)
		authorization, data, retired, err := e.authorizeFrameDispatchLocked(job.frame, digest, job.admission)
		if err != nil {
			return nil, err
		}
		if retired {
			return nil, errFrameRetiredBeforeWrite
		}
		dispatches[index] = physicalFrameDispatch{authorization: authorization, data: data}
	}
	return dispatches, nil
}

func (e *Engine) validatePreparedFrameDispatch(
	frame []byte,
	digest proto.FrameDigest,
	admission frameDispatchAdmission,
	dispatch physicalFrameDispatch,
) error {
	if len(frame) < proto.HeaderSize {
		return proto.ErrBadHeader
	}
	header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	if err != nil {
		return err
	}
	if header.Type != proto.FrameData {
		if dispatch.data {
			return errFrameDispatchAdmission
		}
		return nil
	}
	authorization := dispatch.authorization
	if !dispatch.data || admission.owner != e || admission.id == 0 ||
		admission.sequence != header.Seq || admission.digest != digest || admission.frameBytes != len(frame) ||
		authorization.Sequence != header.Seq || authorization.PublishedNext <= header.Seq ||
		authorization.AckNext > header.Seq ||
		authorization.AdmissionLedgerGeneration != admission.ledgerGeneration ||
		authorization.LedgerGeneration < authorization.AdmissionLedgerGeneration ||
		authorization.AdmissionID != admission.id || authorization.AttemptID == 0 ||
		authorization.PhysicalOccurrence != 0 || authorization.EndpointGeneration != 0 || authorization.FrameOffset != 0 ||
		authorization.Kind != admission.kind || authorization.AuthorizedAt.IsZero() ||
		authorization.FrameBytes != len(frame) || authorization.FrameDigest != digest {
		return errFrameDispatchAdmission
	}
	return nil
}

func beginPhysicalFrameDispatch(
	slot *pathSlot,
	dispatch physicalFrameDispatch,
	guard *pathDispatchCallbackGuard,
) FrameDispatchSpan {
	if dispatch.data {
		if tracer, ok := slot.conn.(FrameDispatchTracer); ok {
			authorization := dispatch.authorization
			authorization.PhysicalOccurrence = 1
			authorization.FrameOffset = 0
			return beginExternalFrameDispatch(tracer, authorization, guard)
		}
	}
	return nil
}

func beginExternalFrameDispatch(
	tracer FrameDispatchTracer,
	authorization FrameDispatchAuthorization,
	guard *pathDispatchCallbackGuard,
) (span FrameDispatchSpan) {
	returned := false
	defer func() {
		if recovered := recover(); recovered != nil {
			span = nil
		} else if !returned {
			guard.recordGoexit("FrameDispatchTracer.BeginFrameDispatch")
		}
	}()
	span = tracer.BeginFrameDispatch(authorization)
	returned = true
	return span
}

func finishPhysicalFrameDispatch(
	span FrameDispatchSpan,
	completion FrameDispatchCompletion,
	guard *pathDispatchCallbackGuard,
) {
	if span == nil {
		return
	}
	returned := false
	defer func() {
		if recover() == nil && !returned {
			guard.recordGoexit("FrameDispatchSpan.FinishFrameDispatch")
		}
	}()
	span.FinishFrameDispatch(completion)
	returned = true
}

func writeExternalFrameBatch(
	writer transport.FrameBatchWriter,
	frames [][]byte,
) (completed int, err error) {
	return writeExternalFrameBatchGuarded(writer, frames, nil)
}

func writeExternalFrameBatchGuarded(
	writer transport.FrameBatchWriter,
	frames [][]byte,
	guard *pathDispatchCallbackGuard,
) (completed int, err error) {
	callbackFrames := frames
	borrowed, borrowedOK := writer.(transport.BorrowedFrameBatchWriter)
	if !borrowedOK {
		// Legacy implementations received a fresh exact-length outer slice before
		// the writer-local scratch path existed. Preserve that lifetime contract;
		// only explicit BorrowedFrameBatchWriter implementations see scratch.
		callbackFrames = append([][]byte(nil), frames...)
	}
	returned := false
	defer func() {
		if recovered := recover(); recovered != nil {
			completed = 0
			err = newPathDispatchCallbackPanicError("FrameBatchWriter.WriteFrameBatch", recovered)
		} else if !returned {
			guard.recordGoexit("FrameBatchWriter.WriteFrameBatch")
		}
	}()
	if borrowedOK {
		completed, err = borrowed.WriteBorrowedFrameBatch(callbackFrames)
	} else {
		completed, err = writer.WriteFrameBatch(callbackFrames)
	}
	returned = true
	return completed, err
}

func writeExternalPathConn(conn transport.PathConn, frame []byte) (n int, err error) {
	return writeExternalPathConnGuarded(conn, frame, nil)
}

func writeExternalPathConnGuarded(
	conn transport.PathConn,
	frame []byte,
	guard *pathDispatchCallbackGuard,
) (n int, err error) {
	returned := false
	defer func() {
		if recovered := recover(); recovered != nil {
			n = 0
			err = newPathDispatchCallbackPanicError("PathConn.Write", recovered)
		} else if !returned {
			guard.recordGoexit("PathConn.Write")
		}
	}()
	n, err = conn.Write(frame)
	returned = true
	return n, err
}

func writeExternalFrameDispatch(
	writer transport.FrameDispatchWriter,
	frame []byte,
	authorization FrameDispatchAuthorization,
) (n int, err error) {
	return writeExternalFrameDispatchGuarded(writer, frame, authorization, nil)
}

func writeExternalFrameDispatchGuarded(
	writer transport.FrameDispatchWriter,
	frame []byte,
	authorization FrameDispatchAuthorization,
	guard *pathDispatchCallbackGuard,
) (n int, err error) {
	returned := false
	defer func() {
		if recovered := recover(); recovered != nil {
			n = 0
			err = newPathDispatchCallbackPanicError("FrameDispatchWriter.WriteFrameDispatch", recovered)
		} else if !returned {
			guard.recordGoexit("FrameDispatchWriter.WriteFrameDispatch")
		}
	}()
	n, err = writer.WriteFrameDispatch(frame, authorization)
	returned = true
	return n, err
}

func writeExternalOwnedFrameDispatch(
	writer dispatchtrust.OwnedFrameWriter,
	frame []byte,
	authorization FrameDispatchAuthorization,
) (n int, err error) {
	return writeExternalOwnedFrameDispatchGuarded(writer, frame, authorization, nil)
}

func writeExternalOwnedFrameDispatchGuarded(
	writer dispatchtrust.OwnedFrameWriter,
	frame []byte,
	authorization FrameDispatchAuthorization,
	guard *pathDispatchCallbackGuard,
) (n int, err error) {
	returned := false
	defer func() {
		if recovered := recover(); recovered != nil {
			n = 0
			err = newPathDispatchCallbackPanicError("OwnedFrameWriter.WriteOwnedFrameDispatch", recovered)
		} else if !returned {
			guard.recordGoexit("OwnedFrameWriter.WriteOwnedFrameDispatch")
		}
	}()
	n, err = dispatchtrust.Write(writer, frame, authorization)
	returned = true
	return n, err
}

func writeContainedDispatchFrame(
	slot *pathSlot,
	frame []byte,
	prepared dispatchedFrameWrite,
	guard *pathDispatchCallbackGuard,
) (int, error) {
	var n int
	var err error
	if prepared.atomic {
		if writer, ok := slot.conn.(dispatchtrust.OwnedFrameWriter); ok {
			n, err = writeExternalOwnedFrameDispatchGuarded(writer, frame, prepared.authorization, guard)
		} else if writer, ok := slot.conn.(transport.FrameDispatchWriter); ok {
			borrowed := append([]byte(nil), frame...)
			n, err = writeExternalFrameDispatchGuarded(writer, borrowed, prepared.authorization, guard)
		} else {
			n, err = writeExternalPathConnGuarded(slot.conn, frame, guard)
		}
	} else {
		n, err = writeExternalPathConnGuarded(slot.conn, frame, guard)
	}
	slot.recordFrameWrite(frame, n, err)
	return n, err
}

func (slot *pathSlot) writeContainedDispatchedFrameEpochObserved(
	frame []byte,
	fenceEpoch uint64,
	guard *pathDispatchCallbackGuard,
	beforeWrite func() (dispatchedFrameWrite, error),
	afterWrite func(int, error),
) (int, error) {
	if !slot.txEnabled.Load() || slot.txFenceEpoch.Load() != fenceEpoch {
		return 0, ErrPathTXFenced
	}
	if slot.dispatchBeforeWritePermit != nil {
		slot.dispatchBeforeWritePermit()
	}
	if err := slot.acquireWrite(context.Background()); err != nil {
		return 0, err
	}
	defer slot.releaseWrite()
	if !slot.txEnabled.Load() || slot.txFenceEpoch.Load() != fenceEpoch {
		return 0, ErrPathTXFenced
	}
	var prepared dispatchedFrameWrite
	if beforeWrite != nil {
		var err error
		prepared, err = beforeWrite()
		if err != nil {
			return 0, err
		}
	}
	n, err := writeContainedDispatchFrame(slot, frame, prepared, guard)
	n, err = normalizeFrameWriteResult(len(frame), n, err)
	if afterWrite != nil {
		afterWrite(n, err)
	}
	return n, err
}

func classifyFrameBatchResult(total, completed int, err error) (int, error) {
	if completed < 0 || completed > total {
		return 0, errors.New("engine: frame batch writer returned invalid completed count")
	}
	if completed < total && err == nil {
		err = io.ErrShortWrite
	}
	return completed, err
}

func (e *Engine) executePathDispatch(slot *pathSlot, job pathDispatchJob) {
	callbackGuard := pathDispatchCallbackGuard{}
	cohort := e.applicationRootCohortFromFrame(job.frame)
	var writeToken pathDataWriteToken
	var dispatchSpan FrameDispatchSpan
	var dispatchLease frameDispatchLease
	var attributionReceipt *batchDispatchAttributionReceipt
	defer func() {
		if dispatchLease != 0 {
			e.releaseFrameDispatchLease(&dispatchLease)
		}
		if attributionReceipt != nil && !attributionReceipt.resolved {
			e.resolveApplicationBatchDispatch([]*batchDispatchAttributionReceipt{attributionReceipt}, 0)
		}
		if callbackErr := callbackGuard.goexitError(); callbackErr != nil {
			e.failPathDispatchCallback(
				slot, callbackErr, []pathDispatchJob{job}, nil,
				pathDispatchJob{}, false, nil,
			)
		}
	}()
	var physicalStarted time.Time
	started := nowFn()
	n, err := slot.writeContainedDispatchedFrameEpochObserved(job.frame, job.fenceEpoch, &callbackGuard, func() (dispatchedFrameWrite, error) {
		dispatch, lease, err := e.preparePhysicalFrameDispatch(job)
		if err != nil {
			return dispatchedFrameWrite{}, err
		}
		dispatchLease = lease
		prepared := dispatchedFrameWrite{}
		if dispatch.data {
			if _, ok := slot.conn.(transport.FrameDispatchWriter); ok {
				prepared.atomic = true
				prepared.authorization = dispatch.authorization
			} else {
				dispatchSpan = beginPhysicalFrameDispatch(slot, dispatch, &callbackGuard)
			}
		}
		if !job.routePlanned {
			attributionReceipt = e.beginApplicationBatchDispatch(
				job.frame, slot, job.topologyEpoch,
			)
		}
		writeToken = e.pathDataWriteToken(slot, job.fenceEpoch)
		physicalStarted = nowFn()
		return prepared, nil
	}, func(n int, writeErr error) {
		completedAt := nowFn()
		if dispatchSpan != nil {
			finishPhysicalFrameDispatch(dispatchSpan, FrameDispatchCompletion{
				StartedAt: physicalStarted, CompletedAt: completedAt,
				FrameBytes: len(job.frame), BytesWritten: n, BytesWrittenKnown: true,
				WriteCalls:   1,
				AttemptState: FrameDispatchAttempted, WriteAttempted: true,
				WholeFrameAccepted: n == len(job.frame),
				BatchIndex:         0, BatchSize: 1, Err: writeErr,
			}, &callbackGuard)
		}
		if !job.firstPublication || writeErr != nil || n != len(job.frame) || len(job.frame) < proto.HeaderSize {
			return
		}
		header, decodeErr := proto.DecodeHeader(job.frame[:proto.HeaderSize])
		if decodeErr == nil && header.Type == proto.FrameData {
			slot.noteFirstDataWriteSequence(header.Seq, writeToken)
		}
	})
	if dispatchLease != 0 {
		e.releaseFrameDispatchLease(&dispatchLease)
	}
	finished := nowFn()
	if errors.Is(err, errFrameRetiredBeforeWrite) {
		e.completePathDispatch(slot, job, nil)
		return
	}
	if err == nil && n != len(job.frame) {
		err = io.ErrShortWrite
	}
	attributed := 0
	if attributionReceipt != nil && !physicalStarted.IsZero() {
		// Preserve the prior route-attempt semantics even when a physical write
		// fails. A later replay through another target must not turn an
		// ambiguous partial attempt into leaf-specific capacity evidence.
		attributed = 1
	}
	if err == nil {
		attributionReceipt.noteCapacityPressure(applicationDispatchPressureObservation{
			startedAt: physicalStarted, completedAt: finished,
			serviceDuration: finished.Sub(physicalStarted),
		})
		if job.capacityQualification {
			attributionReceipt.noteCapacityQualificationPressure(
				physicalStarted, finished, job.capacityQualificationPressure,
				job.capacityQualificationComplete,
			)
		}
	}
	e.resolveApplicationBatchDispatch(
		[]*batchDispatchAttributionReceipt{attributionReceipt}, attributed,
	)
	e.noteApplicationDispatchDuration(
		cohort, job.topologyEpoch, started, finished, err == nil,
	)
	if err == nil {
		slot.lastSendUnixNano.Store(nowFn().UnixNano())
		slot.recordDispatch(job.frame, job.firstPublication)
		e.noteTailReplayPublication(job.frame, slot)
	} else if !errors.Is(err, ErrPathTXFenced) && !errors.Is(err, errFrameDispatchAdmission) {
		// Some third-party PathConn implementations cannot reliably invoke
		// OnDeath after a failed Write. The generation check makes this
		// synthetic report idempotent with a concurrent transport callback.
		e.onPathDeath(slot.id, slot.owner, transport.CauseTransportError, err)
	}
	e.completePathDispatch(slot, job, err)
}

func (e *Engine) failPathDispatchCallback(
	slot *pathSlot,
	err error,
	jobs []pathDispatchJob,
	retired []bool,
	pending pathDispatchJob,
	hasPending bool,
	receipts []*batchDispatchAttributionReceipt,
) {
	e.resolveApplicationBatchDispatch(receipts, 0)
	e.onPathDeath(slot.id, slot.owner, transport.CauseTransportError, err)
	for index, job := range jobs {
		jobErr := err
		if index < len(retired) && retired[index] {
			jobErr = nil
		}
		e.completePathDispatch(slot, job, jobErr)
	}
	if hasPending {
		e.completePathDispatch(slot, pending, err)
	}
	for {
		select {
		case job := <-slot.dispatchQ:
			e.completePathDispatch(slot, job, err)
		default:
			return
		}
	}
}

func (e *Engine) completePathDispatch(slot *pathSlot, job pathDispatchJob, err error) {
	result := pathDispatchResult{slot: slot, err: err}
	if slot.dispatchBeforeCompletePublication != nil {
		slot.dispatchBeforeCompletePublication()
	}
	slot.completeDispatch(pathDispatchIdentity{
		generation:     job.generation,
		pathGeneration: job.pathGeneration,
	})
	if job.acceptedPacket {
		e.completeAcceptedPacketDispatch(job.custodyTicket)
	}
	if job.applicationWait != nil {
		completeApplicationDispatchWaiter(job.applicationWait, result)
	} else if job.result != nil {
		job.result <- result
	} else if job.acceptedPacket && err != nil {
		if header, decodeErr := proto.DecodeHeader(job.frame[:proto.HeaderSize]); decodeErr == nil {
			e.requestReplayRange(header.Seq, header.Seq+1)
		}
	}
}

func (e *Engine) completeRejectedDispatch(slot *pathSlot, job pathDispatchJob) {
	e.completePathDispatch(slot, job, net.ErrClosed)
}

func (e *Engine) rejectQueuedDispatches(slot *pathSlot) {
	for {
		select {
		case job := <-slot.dispatchQ:
			e.completeRejectedDispatch(slot, job)
		default:
			return
		}
	}
}

func (e *Engine) dispatchRecursive(frame []byte, runtime *executionRuntime, firstPublication bool) error {
	return e.dispatchRecursiveMode(frame, runtime, firstPublication, false, nil, false)
}

func (e *Engine) dispatchRecursiveApplication(frame []byte, runtime *executionRuntime, firstPublication bool) error {
	return e.dispatchRecursiveMode(frame, runtime, firstPublication, true, nil, false)
}

func (e *Engine) dispatchRecursiveReplayPreemptingControl(
	frame []byte,
	runtime *executionRuntime,
	firstPublication bool,
) error {
	return e.dispatchRecursiveMode(frame, runtime, firstPublication, false, nil, true)
}

func (e *Engine) dispatchDetachedStreamApplication(
	frame []byte,
	runtime *executionRuntime,
	firstPublication bool,
	custodyTicket uint64,
) error {
	return e.dispatchRecursiveMode(
		frame, runtime, firstPublication, true,
		&detachedStreamDispatchLease{
			custodyTicket: custodyTicket,
		},
		false,
	)
}

const (
	bondCapacityWeightScale       uint64             = (1 << 16) - 1
	bondCapacityMinimumConfidence evidenceConfidence = evidenceConfidenceFull / 4
)

type recursiveDispatchSnapshot struct {
	topologyEpoch uint64
	latest        map[proto.TargetID]*pathSlot
	capacities    map[proto.TargetID]uint64
	projection    *recursiveDispatchProjection
}

// recursiveDispatchProjection is an immutable, revision-bound view of the
// physical leaves and their scheduling evidence. Its maps are never exposed to
// mutation. A topology, health, ACK-evidence, or exact time-freshness boundary
// invalidates the whole projection before it can authorize another ticket.
type recursiveDispatchProjection struct {
	topologyEpoch    uint64
	healthEpoch      uint64
	evidenceRevision uint64
	capacityRevision uint64
	builtAt          time.Time
	validUntil       time.Time
	eligibleLeaves   map[proto.TargetID]bool
	presentLeaves    map[proto.TargetID]bool
	eligibleNodes    map[proto.TargetID]bool
	presentNodes     map[proto.TargetID]bool
	latest           map[proto.TargetID]*pathSlot
	qualities        map[proto.TargetID]transport.PathQuality
	scheduling       bondSchedulingContext
}

func (projection *recursiveDispatchProjection) currentAt(
	topologyEpoch, healthEpoch, evidenceRevision, capacityRevision uint64,
	now time.Time,
) bool {
	if projection == nil || projection.topologyEpoch != topologyEpoch ||
		projection.healthEpoch != healthEpoch || projection.evidenceRevision != evidenceRevision ||
		projection.capacityRevision != capacityRevision ||
		now.IsZero() || now.Before(projection.builtAt) {
		return false
	}
	return projection.validUntil.IsZero() || now.Before(projection.validUntil)
}

func (projection *recursiveDispatchProjection) reusableAt(
	topologyEpoch, healthEpoch, capacityRevision uint64,
	now time.Time,
) bool {
	if projection == nil || projection.topologyEpoch != topologyEpoch ||
		projection.healthEpoch != healthEpoch || projection.capacityRevision != capacityRevision ||
		now.IsZero() || now.Before(projection.builtAt) {
		return false
	}
	return projection.validUntil.IsZero() || now.Before(projection.validUntil)
}

// withEvidenceRevision advances an ACK-only authority frontier. Capacity has
// its own revision, so unchanged topology, health, eligibility and weight maps
// remain immutable and can be shared without an O(paths) rebuild.
func (projection *recursiveDispatchProjection) withEvidenceRevision(
	e *Engine,
	evidenceRevision uint64,
	now time.Time,
) *recursiveDispatchProjection {
	if projection == nil {
		return nil
	}
	next := *projection
	next.evidenceRevision = evidenceRevision
	next.builtAt = now
	next.scheduling = projection.scheduling
	next.scheduling.now = now
	next.scheduling.evidenceSource = e
	next.scheduling.evidenceRevision = evidenceRevision
	return &next
}

func bondPriorWeight(slot *pathSlot) uint64 {
	if slot == nil || slot.spec.Weight == 0 {
		return 1
	}
	return uint64(slot.spec.Weight)
}

// scaleBondCapacityWeight returns ceil(value*scale/maximum) without allowing
// a raw bytes-per-second sample to enter the scheduler's cursor domain.
func scaleBondCapacityWeight(value, maximum, scale uint64) uint64 {
	if value == 0 || maximum == 0 || scale == 0 {
		return 0
	}
	if value > maximum {
		value = maximum
	}
	hi, lo := bits.Mul64(value, scale)
	quotient, remainder := bits.Div64(hi, lo, maximum)
	if remainder != 0 {
		quotient++
	}
	if quotient > scale {
		return scale
	}
	return quotient
}

// bondDispatchScheduling retains raw topology-bound capacity evidence. Each
// recursive bond normalizes only its own immediate-child aggregates; doing it
// here would let a stalled leaf or an unselected selector sibling compress an
// unrelated bond domain before the graph semantics are known.
func bondDispatchScheduling(
	latest map[proto.TargetID]*pathSlot,
	delivered map[proto.TargetID]speedEstimate,
	acknowledged map[proto.TargetID]uint64,
	now time.Time,
	topologyEpoch uint64,
) bondSchedulingContext {
	staticWeights := make(map[proto.TargetID]uint64, len(latest))
	effectiveWeights := make(map[proto.TargetID]uint64, len(latest))
	observed := make(map[proto.TargetID]bool, len(latest))
	leafIdentity := make(map[proto.TargetID]bondLeafIdentity, len(latest))
	for targetID, slot := range latest {
		prior := bondPriorWeight(slot)
		staticWeights[targetID] = prior
		effectiveWeights[targetID] = prior
		leafIdentity[targetID] = bondLeafIdentity{
			targetID: targetID, pathID: slot.id, owner: slot.owner, generation: slot.gen,
			routeGeneration: slot.routeGeneration.Load(),
		}
		estimate, exists := delivered[targetID]
		if !exists {
			continue
		}
		if !bondCapacityEstimateFreshAt(estimate, now) {
			continue
		}
		effectiveWeights[targetID] = estimate.bytesPerSecond
		observed[targetID] = true
	}
	return bondSchedulingContext{
		now: now, topologyEpoch: topologyEpoch,
		staticWeights: staticWeights, effectiveWeights: effectiveWeights,
		observed: observed, acknowledged: acknowledged, leafIdentity: leafIdentity,
		evidenceAware: true,
	}
}

func bondDispatchCapacities(
	latest map[proto.TargetID]*pathSlot,
	delivered map[proto.TargetID]speedEstimate,
	now time.Time,
) map[proto.TargetID]uint64 {
	return bondDispatchScheduling(latest, delivered, nil, now, 0).effectiveWeights
}

func earlierProjectionBoundary(current, candidate time.Time) time.Time {
	if candidate.IsZero() || (!current.IsZero() && !candidate.Before(current)) {
		return current
	}
	return candidate
}

func bondEvidenceProjectionBoundary(
	delivered map[proto.TargetID]speedEstimate,
	now time.Time,
) time.Time {
	var boundary time.Time
	for _, estimate := range delivered {
		if estimate.sampleTime.IsZero() {
			continue
		}
		if estimate.sampleTime.After(now) {
			boundary = earlierProjectionBoundary(boundary, estimate.sampleTime)
			continue
		}
		expires := estimate.sampleTime.Add(selectorEvidenceFreshFor + time.Nanosecond)
		if now.Before(expires) {
			boundary = earlierProjectionBoundary(boundary, expires)
		}
	}
	return boundary
}

func executionNodeAvailability(
	plan *executionPlan,
	leaves map[proto.TargetID]bool,
) map[proto.TargetID]bool {
	result := make(map[proto.TargetID]bool, len(plan.nodes))
	known := make(map[proto.TargetID]bool, len(plan.nodes))
	var available func(proto.TargetID) bool
	available = func(targetID proto.TargetID) bool {
		if known[targetID] {
			return result[targetID]
		}
		known[targetID] = true
		node, ok := plan.nodeView(targetID)
		if !ok {
			return false
		}
		if node.kind == proto.GraphNodeKindPath {
			result[targetID] = leaves[targetID]
			return result[targetID]
		}
		for _, childID := range node.children {
			if available(childID) {
				result[targetID] = true
				break
			}
		}
		return result[targetID]
	}
	for _, targetID := range plan.nodeIDs {
		available(targetID)
	}
	return result
}

func (e *Engine) buildRecursiveDispatchProjection(
	runtime *executionRuntime,
	now time.Time,
	topologyEpoch, healthEpoch, evidenceRevision, capacityRevision uint64,
	delivered map[proto.TargetID]speedEstimate,
	acknowledged map[proto.TargetID]uint64,
) (*recursiveDispatchProjection, bool) {
	if runtime == nil || runtime.plan == nil || now.IsZero() {
		return nil, false
	}
	e.pathsMu.RLock()
	if topologyEpoch != 0 && e.currentPathTopologyEpoch() != topologyEpoch {
		e.pathsMu.RUnlock()
		return nil, false
	}
	projection := &recursiveDispatchProjection{
		topologyEpoch: topologyEpoch, healthEpoch: healthEpoch,
		evidenceRevision: evidenceRevision, capacityRevision: capacityRevision, builtAt: now,
		eligibleLeaves: make(map[proto.TargetID]bool, len(e.paths)),
		presentLeaves:  make(map[proto.TargetID]bool, len(e.paths)),
		latest:         make(map[proto.TargetID]*pathSlot, len(e.paths)),
		qualities:      make(map[proto.TargetID]transport.PathQuality, len(e.paths)),
	}
	for _, slot := range e.paths {
		targetID := slot.localTXTargetID
		if targetID == (proto.TargetID{}) {
			continue
		}
		projection.presentLeaves[targetID] = true
		if slot.dispatchStalled.Load() {
			continue
		}
		projection.eligibleLeaves[targetID] = true
		if previous := projection.latest[targetID]; previous == nil || slot.gen > previous.gen {
			quality, transition := slot.schedulingQualityProjection(now, e.limits.ProbeInterval)
			projection.latest[targetID] = slot
			projection.qualities[targetID] = quality
			projection.validUntil = earlierProjectionBoundary(projection.validUntil, transition)
		}
	}
	e.pathsMu.RUnlock()
	projection.eligibleNodes = executionNodeAvailability(runtime.plan, projection.eligibleLeaves)
	projection.presentNodes = executionNodeAvailability(runtime.plan, projection.presentLeaves)
	projection.scheduling = bondDispatchScheduling(
		projection.latest, delivered, acknowledged, now, topologyEpoch,
	)
	projection.scheduling.healthEpoch = healthEpoch
	projection.scheduling.capacityRevision = capacityRevision
	projection.scheduling.evidenceSource = e
	projection.scheduling.evidenceRevision = evidenceRevision
	projection.validUntil = earlierProjectionBoundary(
		projection.validUntil, bondEvidenceProjectionBoundary(delivered, now),
	)
	if topologyEpoch != 0 && (e.currentPathTopologyEpoch() != topologyEpoch ||
		e.healthEvidenceEpoch.Load() != healthEpoch ||
		e.bondEvidenceRevision.Load() != evidenceRevision ||
		e.bondCapacityRevision.Load() != capacityRevision) {
		return nil, false
	}
	return projection, true
}

func (e *Engine) recursiveDispatchTicket(
	runtime *executionRuntime,
	controlFallback bool,
	now time.Time,
) (dispatchTicket, recursiveDispatchSnapshot, error) {
	ticket, snapshot, err := e.reserveRecursiveDispatchTicket(runtime, controlFallback, now)
	if err != nil {
		return dispatchTicket{}, snapshot, err
	}
	routes := append([]dispatchRoute(nil), ticket.routes...)
	ticket.finalizeScheduling(true)
	ticket.routes = routes
	return ticket, snapshot, nil
}

func (e *Engine) reserveRecursiveDispatchTicket(
	runtime *executionRuntime,
	controlFallback bool,
	now time.Time,
) (dispatchTicket, recursiveDispatchSnapshot, error) {
	if runtime == nil {
		return dispatchTicket{}, recursiveDispatchSnapshot{}, errExecutionRuntimeNotConfigured
	}
	for attempt := 0; attempt < 3; attempt++ {
		topologyEpoch := e.currentPathTopologyEpoch()
		healthEpoch := e.healthEvidenceEpoch.Load()
		evidenceRevision := e.bondEvidenceRevision.Load()
		capacityRevision := e.bondCapacityRevision.Load()
		projection := runtime.cachedRecursiveDispatchProjection(
			topologyEpoch, healthEpoch, evidenceRevision, capacityRevision, now,
		)
		if projection == nil {
			base := runtime.cachedRecursiveDispatchProjectionBase(
				topologyEpoch, healthEpoch, capacityRevision, now,
			)
			if base != nil && base.evidenceRevision != evidenceRevision {
				projection = base.withEvidenceRevision(e, evidenceRevision, now)
				if !projection.currentAt(
					e.currentPathTopologyEpoch(), e.healthEvidenceEpoch.Load(),
					e.bondEvidenceRevision.Load(), e.bondCapacityRevision.Load(), now,
				) {
					projection = nil
				} else {
					runtime.cacheRecursiveDispatchProjection(projection)
				}
			}
		}
		if projection == nil {
			var delivered map[proto.TargetID]speedEstimate
			var acknowledged map[proto.TargetID]uint64
			if runtime.hasBond {
				var cached bool
				delivered, acknowledged, cached = runtime.cachedBondDeliveryEvidence(
					topologyEpoch, evidenceRevision, now,
				)
				if !cached {
					runtime.bondEvidenceRebuilds.Add(1)
					var valid bool
					delivered, acknowledged, valid = e.targetBondSchedulingEvidenceAtEpoch(now, topologyEpoch)
					if !valid || e.bondEvidenceRevision.Load() != evidenceRevision {
						continue
					}
					runtime.cacheBondDeliveryEvidence(
						topologyEpoch, evidenceRevision, now, delivered, acknowledged,
					)
				}
			}
			var built bool
			projection, built = e.buildRecursiveDispatchProjection(
				runtime, now, topologyEpoch, healthEpoch, evidenceRevision, capacityRevision,
				delivered, acknowledged,
			)
			if !built {
				continue
			}
			if runtime.hasBond {
				runtime.cacheRecursiveDispatchProjection(projection)
			}
		}
		ticket, err := runtime.reserveTicketFromProjection(
			projection, controlFallback, e.Packetized(),
			e.limits.BondPinSize, e.limits.BondStuckRTTMultiplier,
		)
		if err != nil {
			return dispatchTicket{}, recursiveDispatchSnapshot{}, err
		}
		if !projection.currentAt(
			e.currentPathTopologyEpoch(), e.healthEvidenceEpoch.Load(),
			e.bondEvidenceRevision.Load(), e.bondCapacityRevision.Load(), now,
		) {
			ticket.finalizeSchedulingStale()
			continue
		}
		return ticket, recursiveDispatchSnapshot{
			topologyEpoch: projection.topologyEpoch,
			latest:        projection.latest, capacities: projection.scheduling.effectiveWeights,
			projection: projection,
		}, nil
	}
	return dispatchTicket{}, recursiveDispatchSnapshot{}, errNoExecutionRoute
}

func (e *Engine) dispatchRecursiveMode(
	frame []byte,
	runtime *executionRuntime,
	firstPublication, application bool,
	detached *detachedStreamDispatchLease,
	replayPreemptingControl bool,
) error {
	deadline := nowFn().Add(e.limits.MigrationBudget)
	ackTarget, trackACK := applicationDispatchAckTarget(frame)
	acknowledged := func() bool {
		return trackACK && e.applicationDispatchAcknowledged(ackTarget)
	}
	handedOff := func() bool {
		return detached != nil &&
			e.detachedStreamDispatchHandedOff(detached.custodyTicket)
	}
	if handedOff() {
		return errSelectorCutoverHandoff
	}
	admission, err := e.admitFrameDispatch(frame, firstPublication)
	if errors.Is(err, errFrameRetiredBeforeWrite) {
		return nil
	}
	if err != nil {
		return err
	}
	if application {
		if handled, err := e.dispatchFlatSelectorApplication(
			frame, runtime, firstPublication, admission, deadline, detached,
		); handled {
			return err
		}
	}
	controlFallback := false
	if len(frame) >= proto.HeaderSize {
		if header, err := proto.DecodeHeader(frame[:proto.HeaderSize]); err == nil {
			controlFallback = header.Type == proto.FrameCtrl
		}
	}
	for {
		if handedOff() {
			return errSelectorCutoverHandoff
		}
		if acknowledged() {
			return nil
		}
		if e.isClosed() {
			if acknowledged() {
				return nil
			}
			if err := e.CloseErr(); err != nil {
				return err
			}
			return net.ErrClosed
		}
		if !replayPreemptingControl {
			cutoverGeneration, _ := e.selectorCutoverDispatchSnapshot()
			if cutoverGeneration != 0 {
				if acknowledged() {
					return nil
				}
				if e.handoffSelectorCutoverDispatch(cutoverGeneration, !firstPublication) {
					return errSelectorCutoverHandoff
				}
			}
		}
		if application {
			if _, _, expired := e.writeDeadlineSnapshot(); expired {
				if acknowledged() {
					return nil
				}
				return ErrWriteDeadlineExceeded
			}
		}
		ticket, snapshot, err := e.reserveRecursiveDispatchTicket(runtime, controlFallback, nowFn())
		if handedOff() {
			ticket.finalizeScheduling(false)
			return errSelectorCutoverHandoff
		}
		if err != nil {
			if err != errNoExecutionRoute {
				if acknowledged() {
					return nil
				}
				return err
			}
			if err := e.waitForExecutionProgressModeAcknowledged(deadline, application, ackTarget); err != nil {
				return err
			}
			continue
		}
		topologyEpoch := snapshot.topologyEpoch
		latest := snapshot.latest
		multiRoute := len(ticket.routes) > 1
		// routes aliases runtime scratch until the scheduling reservation is
		// finalized. Capture every value needed after finalization while the
		// reservation still owns runtime.mu.
		strictSelector := application && ticket.kind == proto.ExecutionKindSelector &&
			len(ticket.routes) == 1 && !ticket.routes[0].bonded
		if multiRoute {
			e.noteApplicationDispatchPlanAtEpoch(frame, ticket.routes, topologyEpoch)
		}

		type routeCandidate struct {
			routeIndex int
			slot       *pathSlot
			job        pathDispatchJob
		}
		candidates := make([]routeCandidate, 0, len(ticket.routes))
		for routeIndex, route := range ticket.routes {
			slot := latest[route.targetID]
			if slot == nil {
				continue
			}
			candidates = append(candidates, routeCandidate{routeIndex: routeIndex, slot: slot, job: pathDispatchJob{
				frame:                         frame,
				bonded:                        route.bonded,
				capacityQualification:         route.capacityQualification,
				capacityQualificationPressure: route.capacityQualificationPressure,
				capacityQualificationComplete: route.capacityQualificationComplete,
				routePlanned:                  multiRoute,
				topologyEpoch:                 topologyEpoch,
				firstPublication:              firstPublication,
				admission:                     admission,
			}})
		}
		if len(candidates) > 1 {
			jobs := make([]pathDispatchJob, len(candidates))
			for index := range candidates {
				jobs[index] = candidates[index].job
			}
			dispatches, err := e.prepareLogicalFrameDispatchFanout(jobs)
			if errors.Is(err, errFrameRetiredBeforeWrite) {
				ticket.finalizeScheduling(false)
				return nil
			}
			if err != nil {
				ticket.finalizeScheduling(false)
				return err
			}
			for index := range candidates {
				candidates[index].job.preparedDispatch = dispatches[index]
				candidates[index].job.dispatchPrepared = true
			}
		}

		results := make(chan pathDispatchResult, len(candidates))
		submitted := 0
		submittedSlots := make(map[*pathSlot]pathDispatchIdentity, len(candidates))
		submittedBonded := make(map[*pathSlot]bool, len(candidates))
		if hook := e.recursiveDispatchBeforeAdmission; hook != nil {
			hook(snapshot.projection)
		}
		e.selectorCutoverMu.Lock()
		if !replayPreemptingControl && e.selectorCutoverPending {
			e.selectorCutoverHandedOff = true
			if firstPublication {
				e.selectorCutoverReplayRequired = true
			}
			e.selectorCutoverMu.Unlock()
			ticket.finalizeScheduling(false)
			return errSelectorCutoverHandoff
		}
		if snapshot.projection != nil && !snapshot.projection.currentAt(
			e.currentPathTopologyEpoch(), e.healthEvidenceEpoch.Load(),
			e.bondEvidenceRevision.Load(), e.bondCapacityRevision.Load(), nowFn(),
		) {
			e.selectorCutoverMu.Unlock()
			ticket.finalizeSchedulingStale()
			continue
		}
		for index := range candidates {
			candidate := &candidates[index]
			candidate.job.result = results
			if identity, ok := candidate.slot.submitDispatchTracked(candidate.job); ok {
				submitted++
				ticket.markRouteAdmitted(candidate.routeIndex)
				submittedSlots[candidate.slot] = identity
				submittedBonded[candidate.slot] = candidate.job.bonded
			}
		}
		e.selectorCutoverMu.Unlock()
		ticket.finalizeSchedulingAdmitted()
		if submitted == 0 {
			if handedOff() {
				return errSelectorCutoverHandoff
			}
			if err := e.waitForExecutionProgressModeAcknowledged(deadline, application, ackTarget); err != nil {
				return err
			}
			continue
		}

		remainingBudget := deadline.Sub(nowFn())
		if remainingBudget <= 0 {
			if acknowledged() {
				return nil
			}
			return e.executionBudgetExceeded()
		}
		budgetTimer := time.NewTimer(remainingBudget)
		stallWindowSlots := make(map[*pathSlot]struct{}, len(submittedSlots))
		for slot := range submittedSlots {
			stallWindowSlots[slot] = struct{}{}
		}
		stallTimer := time.NewTimer(e.executionStallWindow(stallWindowSlots))
		stallTimerC := stallTimer.C
		appTimer, appTimerC, appWake, appExpired := e.applicationDispatchDeadline(application)
		pending := make(map[*pathSlot]pathDispatchIdentity, submitted)
		for slot, identity := range submittedSlots {
			pending[slot] = identity
		}
		var ackWake <-chan struct{}
		if trackACK {
			acknowledged, wake := e.sendAcknowledgementSnapshot(ackTarget)
			if acknowledged {
				stopDeadlineTimer(budgetTimer)
				stopDeadlineTimer(stallTimer)
				stopDeadlineTimer(appTimer)
				return nil
			}
			ackWake = wake
		}
		cutoverGeneration := uint64(0)
		var cutoverWake <-chan struct{}
		if !replayPreemptingControl {
			cutoverGeneration, cutoverWake = e.selectorCutoverDispatchSnapshot()
		}
		if cutoverGeneration != 0 {
			if acknowledged() {
				stopDeadlineTimer(budgetTimer)
				stopDeadlineTimer(stallTimer)
				stopDeadlineTimer(appTimer)
				return nil
			}
			e.markDispatchCutoverPending(pending)
			stopDeadlineTimer(budgetTimer)
			stopDeadlineTimer(stallTimer)
			stopDeadlineTimer(appTimer)
			e.handoffSelectorCutoverDispatch(cutoverGeneration, !firstPublication)
			return errSelectorCutoverHandoff
		}
		if handedOff() {
			e.markDispatchCutoverPending(pending)
			stopDeadlineTimer(budgetTimer)
			stopDeadlineTimer(stallTimer)
			stopDeadlineTimer(appTimer)
			return errSelectorCutoverHandoff
		}
		if appExpired {
			if acknowledged() {
				stopDeadlineTimer(budgetTimer)
				stopDeadlineTimer(stallTimer)
				stopDeadlineTimer(appTimer)
				return nil
			}
			e.markDispatchPending(pending)
			stopDeadlineTimer(budgetTimer)
			stopDeadlineTimer(stallTimer)
			return ErrWriteDeadlineExceeded
		}
		stalled := false
		remaining := submitted
		for remaining > 0 && !stalled {
			select {
			case <-ackWake:
				acknowledged, wake := e.sendAcknowledgementSnapshot(ackTarget)
				ackWake = wake
				if acknowledged {
					stopDeadlineTimer(budgetTimer)
					stopDeadlineTimer(stallTimer)
					stopDeadlineTimer(appTimer)
					return nil
				}
			case result := <-results:
				remaining--
				delete(pending, result.slot)
				if result.err == nil {
					if application {
						if trackACK {
							if acknowledged, _ := e.sendAcknowledgementSnapshot(ackTarget); acknowledged {
								stopDeadlineTimer(budgetTimer)
								stopDeadlineTimer(stallTimer)
								stopDeadlineTimer(appTimer)
								return nil
							}
						}
						if _, _, expired := e.writeDeadlineSnapshot(); expired {
							e.markDispatchPending(pending)
							stopDeadlineTimer(budgetTimer)
							stopDeadlineTimer(stallTimer)
							stopDeadlineTimer(appTimer)
							return ErrWriteDeadlineExceeded
						}
					}
					stopDeadlineTimer(budgetTimer)
					stopDeadlineTimer(stallTimer)
					stopDeadlineTimer(appTimer)
					return nil
				}
			case <-stallTimerC:
				if acknowledged() {
					stopDeadlineTimer(budgetTimer)
					stopDeadlineTimer(stallTimer)
					stopDeadlineTimer(appTimer)
					return nil
				}
				for slot, identity := range pending {
					if submittedBonded[slot] && !slot.dispatchStalled.Load() {
						runtime.stuckSkips.Add(1)
					}
					slot.markDispatchStalled(identity)
				}
				if strictSelector {
					// The selected target still owns this immutable frame. Its
					// physical Write may complete after the stall observation; an
					// outer-loop resubmission would then put the same SEQ on the
					// wire twice. Wait for that exact result or for the selector
					// cutover handoff to transfer ownership to bounded replay.
					stallTimerC = nil
					continue
				}
				stalled = true
			case <-cutoverWake:
				if handedOff() {
					e.markDispatchCutoverPending(pending)
					stopDeadlineTimer(budgetTimer)
					stopDeadlineTimer(stallTimer)
					stopDeadlineTimer(appTimer)
					return errSelectorCutoverHandoff
				}
				cutoverGeneration, cutoverWake = e.selectorCutoverDispatchSnapshot()
				if cutoverGeneration != 0 {
					if acknowledged() {
						stopDeadlineTimer(budgetTimer)
						stopDeadlineTimer(stallTimer)
						stopDeadlineTimer(appTimer)
						return nil
					}
					e.markDispatchCutoverPending(pending)
					stopDeadlineTimer(budgetTimer)
					stopDeadlineTimer(stallTimer)
					stopDeadlineTimer(appTimer)
					e.handoffSelectorCutoverDispatch(cutoverGeneration, !firstPublication)
					return errSelectorCutoverHandoff
				}
			case <-e.closed:
				if acknowledged() {
					stopDeadlineTimer(budgetTimer)
					stopDeadlineTimer(stallTimer)
					stopDeadlineTimer(appTimer)
					return nil
				}
				stopDeadlineTimer(budgetTimer)
				stopDeadlineTimer(stallTimer)
				stopDeadlineTimer(appTimer)
				if err := e.CloseErr(); err != nil {
					return err
				}
				return net.ErrClosed
			case <-budgetTimer.C:
				if handedOff() {
					stopDeadlineTimer(stallTimer)
					stopDeadlineTimer(appTimer)
					return errSelectorCutoverHandoff
				}
				if acknowledged() {
					stopDeadlineTimer(stallTimer)
					stopDeadlineTimer(appTimer)
					return nil
				}
				stopDeadlineTimer(stallTimer)
				stopDeadlineTimer(appTimer)
				return e.executionBudgetExceeded()
			case <-appWake:
				stopDeadlineTimer(appTimer)
				appTimer, appTimerC, appWake, appExpired = e.applicationDispatchDeadline(application)
				if appExpired {
					if acknowledged() {
						stopDeadlineTimer(budgetTimer)
						stopDeadlineTimer(stallTimer)
						return nil
					}
					e.markDispatchPending(pending)
					stopDeadlineTimer(budgetTimer)
					stopDeadlineTimer(stallTimer)
					return ErrWriteDeadlineExceeded
				}
			case <-appTimerC:
				appTimer, appTimerC, appWake, appExpired = e.applicationDispatchDeadline(application)
				if appExpired {
					if acknowledged() {
						stopDeadlineTimer(budgetTimer)
						stopDeadlineTimer(stallTimer)
						return nil
					}
					e.markDispatchPending(pending)
					stopDeadlineTimer(budgetTimer)
					stopDeadlineTimer(stallTimer)
					return ErrWriteDeadlineExceeded
				}
			}
		}
		stopDeadlineTimer(budgetTimer)
		stopDeadlineTimer(stallTimer)
		stopDeadlineTimer(appTimer)
		if stalled {
			continue
		}
		if err := e.waitForExecutionProgressModeAcknowledged(deadline, application, ackTarget); err != nil {
			return err
		}
	}
}

type flatSelectorWaitReason uint8

const (
	flatSelectorWaitStall flatSelectorWaitReason = iota + 1
	flatSelectorWaitMigrationBudget
	flatSelectorWaitApplicationDeadline
)

// dispatchFlatSelectorApplication avoids rebuilding an immutable recursive
// ticket for the common root-selector-with-path-children shape. The recursive
// selector remains the sole route authority. Blocking writes still run on the path
// writer and retain the same stall, cutover, migration-budget, and application
// deadline semantics as the general dispatcher.
//
// The caller holds sendMu and the application write permit, which makes the
// reusable timer below single-owner without another lock.
func (e *Engine) dispatchFlatSelectorApplication(
	frame []byte,
	runtime *executionRuntime,
	firstPublication bool,
	admission frameDispatchAdmission,
	migrationDeadline time.Time,
	detached *detachedStreamDispatchLease,
) (bool, error) {
	handedOff := func() bool {
		return detached != nil &&
			e.detachedStreamDispatchHandedOff(detached.custodyTicket)
	}
	if handedOff() {
		return true, errSelectorCutoverHandoff
	}
	if runtime == nil || !runtime.flatLeafSelector {
		return false, nil
	}
	if generation, _ := e.selectorCutoverDispatchSnapshot(); generation != 0 &&
		e.handoffSelectorCutoverDispatch(generation, !firstPublication) {
		return true, errSelectorCutoverHandoff
	}
	if e.isClosed() {
		return true, net.ErrClosed
	}

	slot, topologyEpoch := e.flatSelectorDispatchSlot(runtime, false)
	if slot == nil {
		return false, nil
	}
	if handedOff() {
		return true, errSelectorCutoverHandoff
	}

	waiter := acquireApplicationDispatchWaiter()
	ackTarget, trackACK := applicationDispatchAckTarget(frame)
	acknowledged := func() bool {
		return trackACK && e.applicationDispatchAcknowledged(ackTarget)
	}
	identity, submitted := slot.submitDispatchTracked(pathDispatchJob{
		frame:            frame,
		topologyEpoch:    topologyEpoch,
		firstPublication: firstPublication,
		admission:        admission,
		applicationWait:  waiter,
	})
	if !submitted {
		releaseApplicationDispatchWaiter(waiter)
		return false, nil
	}
	stallDeadline := nowFn().Add(e.executionStallWindowForSlot(slot))
	stalled := false
	for {
		if handedOff() {
			slot.markDispatchCutoverHandoff(identity)
			abandonApplicationDispatchWaiter(waiter)
			return true, errSelectorCutoverHandoff
		}
		if acknowledged() {
			abandonApplicationDispatchWaiter(waiter)
			return true, nil
		}
		applicationDeadline, applicationWake, expired := e.writeDeadlineSnapshot()
		if expired {
			if acknowledged() {
				abandonApplicationDispatchWaiter(waiter)
				return true, nil
			}
			slot.markDispatchStalled(identity)
			abandonApplicationDispatchWaiter(waiter)
			return true, ErrWriteDeadlineExceeded
		}

		waitDeadline := migrationDeadline
		waitReason := flatSelectorWaitMigrationBudget
		if !stalled && stallDeadline.Before(waitDeadline) {
			waitDeadline = stallDeadline
			waitReason = flatSelectorWaitStall
		}
		if !applicationDeadline.IsZero() && applicationDeadline.Before(waitDeadline) {
			waitDeadline = applicationDeadline
			waitReason = flatSelectorWaitApplicationDeadline
		}
		timerC := e.resetFlatSelectorDispatchTimer(waitDeadline)

		cutoverGeneration, cutoverWake := e.selectorCutoverDispatchSnapshot()
		if cutoverGeneration != 0 {
			e.stopFlatSelectorDispatchTimer()
			if acknowledged() {
				abandonApplicationDispatchWaiter(waiter)
				return true, nil
			}
			slot.markDispatchStalled(identity)
			if e.handoffSelectorCutoverDispatch(cutoverGeneration, !firstPublication) {
				abandonApplicationDispatchWaiter(waiter)
				return true, errSelectorCutoverHandoff
			}
			continue
		}
		var ackWake <-chan struct{}
		if trackACK {
			acknowledged, wake := e.sendAcknowledgementSnapshot(ackTarget)
			if acknowledged {
				e.stopFlatSelectorDispatchTimer()
				abandonApplicationDispatchWaiter(waiter)
				return true, nil
			}
			ackWake = wake
		}

		select {
		case <-ackWake:
			acknowledged, _ := e.sendAcknowledgementSnapshot(ackTarget)
			if acknowledged {
				e.stopFlatSelectorDispatchTimer()
				abandonApplicationDispatchWaiter(waiter)
				return true, nil
			}
		case dispatchResult := <-waiter.done:
			e.stopFlatSelectorDispatchTimer()
			releaseApplicationDispatchWaiter(waiter)
			if dispatchResult.err != nil {
				if trackACK {
					if acknowledged, _ := e.sendAcknowledgementSnapshot(ackTarget); acknowledged {
						return true, nil
					}
				}
				return false, nil
			}
			if trackACK {
				if acknowledged, _ := e.sendAcknowledgementSnapshot(ackTarget); acknowledged {
					return true, nil
				}
			}
			if _, _, expired := e.writeDeadlineSnapshot(); expired {
				return true, ErrWriteDeadlineExceeded
			}
			return true, nil
		case <-timerC:
			if handedOff() {
				slot.markDispatchCutoverHandoff(identity)
				abandonApplicationDispatchWaiter(waiter)
				return true, errSelectorCutoverHandoff
			}
			if acknowledged() {
				e.stopFlatSelectorDispatchTimer()
				abandonApplicationDispatchWaiter(waiter)
				return true, nil
			}
			switch waitReason {
			case flatSelectorWaitStall:
				slot.markDispatchStalled(identity)
				stalled = true
			case flatSelectorWaitApplicationDeadline:
				if _, _, expired := e.writeDeadlineSnapshot(); expired {
					slot.markDispatchStalled(identity)
					abandonApplicationDispatchWaiter(waiter)
					return true, ErrWriteDeadlineExceeded
				}
			case flatSelectorWaitMigrationBudget:
				slot.markDispatchStalled(identity)
				abandonApplicationDispatchWaiter(waiter)
				return true, e.executionBudgetExceeded()
			}
		case <-applicationWake:
			e.stopFlatSelectorDispatchTimer()
		case <-cutoverWake:
			e.stopFlatSelectorDispatchTimer()
			if handedOff() {
				slot.markDispatchCutoverHandoff(identity)
				abandonApplicationDispatchWaiter(waiter)
				return true, errSelectorCutoverHandoff
			}
			if cutoverGeneration, _ := e.selectorCutoverDispatchSnapshot(); cutoverGeneration != 0 {
				if acknowledged() {
					abandonApplicationDispatchWaiter(waiter)
					return true, nil
				}
				slot.markDispatchCutoverHandoff(identity)
				if e.handoffSelectorCutoverDispatch(cutoverGeneration, !firstPublication) {
					abandonApplicationDispatchWaiter(waiter)
					return true, errSelectorCutoverHandoff
				}
			}
		case <-e.closed:
			e.stopFlatSelectorDispatchTimer()
			if acknowledged() {
				abandonApplicationDispatchWaiter(waiter)
				return true, nil
			}
			abandonApplicationDispatchWaiter(waiter)
			return true, net.ErrClosed
		}
	}
}

var errFlatSelectorPacketRedispatch = errors.New("engine: flat selector packet dispatch requires redispatch")

// acceptFlatSelectorPacketDispatch transfers a packet publication to a
// bounded path queue without waiting for the physical transport call. It is
// used only by the public net.PacketConn surface when no write deadline is
// installed, and only when the path can atomically accept whole-frame batches.
// The replay ledger remains the durable owner until peer ACK, so a later path
// failure or selector cutover can replay the exact immutable frame.
func (e *Engine) acceptFlatSelectorPacketDispatch(
	frame []byte,
	runtime *executionRuntime,
	firstPublication bool,
) (handled bool, err error) {
	if runtime == nil || !runtime.flatLeafSelector || !e.Packetized() {
		return false, nil
	}
	admission, admissionErr := e.admitFrameDispatch(frame, firstPublication)
	if errors.Is(admissionErr, errFrameRetiredBeforeWrite) {
		return true, nil
	}
	if admissionErr != nil {
		return true, admissionErr
	}
	// Route lookup must not run below selectorCutoverMu. Every physical topology
	// commit publishes its epoch while holding pathsMu -> selectorCutoverMu, so
	// the lock-free gap below is closed by the epoch check after custody is
	// acquired. If this dispatch wins the mutex, queue admission linearizes
	// before the topology commit; if the commit wins, this frame is redispatched.
	slot, topologyEpoch := e.flatSelectorDispatchSlot(runtime, true)
	if slot == nil {
		return false, nil
	}
	if hook := e.acceptedPacketAfterRouteSnapshot; hook != nil {
		hook()
	}

	e.selectorCutoverMu.Lock()
	defer e.selectorCutoverMu.Unlock()
	if e.selectorCutoverPending {
		e.selectorCutoverHandedOff = true
		if firstPublication {
			e.selectorCutoverReplayRequired = true
		}
		return true, errSelectorCutoverHandoff
	}
	if e.currentPathTopologyEpoch() != topologyEpoch {
		return false, nil
	}
	if e.isClosed() {
		return true, net.ErrClosed
	}

	custodyTicket := e.nextDispatchCustodyTicketLocked()
	if !slot.submitDispatch(pathDispatchJob{
		frame: frame, topologyEpoch: topologyEpoch, firstPublication: firstPublication,
		admission:      admission,
		acceptedPacket: true, custodyTicket: custodyTicket,
	}) {
		return false, nil
	}
	if firstPublication {
		e.noteTailReplayPublication(frame, slot)
	}
	e.admitAcceptedPacketDispatchLocked(custodyTicket)
	return true, nil
}

type flatSelectorPacketDispatch struct {
	runtime           *executionRuntime
	slot              *pathSlot
	waiter            *applicationDispatchWaiter
	firstPublication  bool
	identity          pathDispatchIdentity
	migrationDeadline time.Time
	stallDeadline     time.Time
	ackTarget         uint64
}

var flatSelectorPacketTimerPool = sync.Pool{New: func() any {
	timer := time.NewTimer(time.Hour)
	stopDeadlineTimer(timer)
	return timer
}}

// startFlatSelectorPacketDispatch publishes one packet job while sendMu still
// orders the sequence ledger and path queue. Its caller may then release
// sendMu while waiting for the physical result, allowing concurrent
// net.PacketConn writers to keep the bounded path queue fed.
func (e *Engine) startFlatSelectorPacketDispatch(
	frame []byte,
	runtime *executionRuntime,
	firstPublication bool,
	migrationDeadline time.Time,
) (*flatSelectorPacketDispatch, bool, error) {
	if runtime == nil || !runtime.flatLeafSelector || !e.Packetized() {
		return nil, false, nil
	}
	admission, admissionErr := e.admitFrameDispatch(frame, firstPublication)
	if errors.Is(admissionErr, errFrameRetiredBeforeWrite) {
		return nil, true, nil
	}
	if admissionErr != nil {
		return nil, true, admissionErr
	}
	if generation, _ := e.selectorCutoverDispatchSnapshot(); generation != 0 &&
		e.handoffSelectorCutoverDispatch(generation, !firstPublication) {
		return nil, true, errSelectorCutoverHandoff
	}
	if e.isClosed() {
		return nil, true, net.ErrClosed
	}

	slot, topologyEpoch := e.flatSelectorDispatchSlot(runtime, false)
	if slot == nil {
		return nil, false, nil
	}

	waiter := acquireApplicationDispatchWaiter()
	identity, submitted := slot.submitDispatchTracked(pathDispatchJob{
		frame:            frame,
		topologyEpoch:    topologyEpoch,
		firstPublication: firstPublication,
		admission:        admission,
		applicationWait:  waiter,
	})
	if !submitted {
		releaseApplicationDispatchWaiter(waiter)
		return nil, false, nil
	}
	ackTarget, _ := applicationDispatchAckTarget(frame)
	return &flatSelectorPacketDispatch{
		runtime: runtime, slot: slot, waiter: waiter, identity: identity,
		firstPublication:  firstPublication,
		migrationDeadline: migrationDeadline,
		stallDeadline:     nowFn().Add(e.executionStallWindowForSlot(slot)),
		ackTarget:         ackTarget,
	}, true, nil
}

// flatSelectorDispatchSlot projects the recursive selector decision onto the
// newest usable physical incarnation of its chosen leaf. activeID is an
// observational compatibility field and must never participate in routing.
func (e *Engine) flatSelectorDispatchSlot(
	runtime *executionRuntime,
	requireBatch bool,
) (*pathSlot, uint64) {
	if runtime == nil || !runtime.flatLeafSelector {
		return nil, 0
	}
	topologyEpoch := e.currentPathTopologyEpoch()
	healthEpoch := e.healthEvidenceEpoch.Load()
	if slot, cached := runtime.cachedFlatSelectorDispatchSlot(
		topologyEpoch, healthEpoch, requireBatch,
	); cached && e.currentPathTopologyEpoch() == topologyEpoch &&
		e.healthEvidenceEpoch.Load() == healthEpoch && !slot.dispatchStalled.Load() {
		return slot, topologyEpoch
	}

	e.pathsMu.RLock()
	topologyEpoch = e.currentPathTopologyEpoch()
	healthEpoch = e.healthEvidenceEpoch.Load()
	eligible := make(map[proto.TargetID]bool, len(e.paths))
	present := make(map[proto.TargetID]bool, len(e.paths))
	latest := make(map[proto.TargetID]*pathSlot, len(e.paths))
	for _, slot := range e.paths {
		targetID := slot.localTXTargetID
		if targetID == (proto.TargetID{}) || !runtime.ownsFlatSelectorLeaf(targetID) {
			continue
		}
		present[targetID] = true
		if slot.dispatchStalled.Load() {
			continue
		}
		if requireBatch {
			if _, ok := slot.conn.(transport.FrameBatchWriter); !ok {
				continue
			}
		}
		eligible[targetID] = true
		if previous := latest[targetID]; previous == nil || slot.gen > previous.gen {
			latest[targetID] = slot
		}
	}
	e.pathsMu.RUnlock()

	if e.currentPathTopologyEpoch() != topologyEpoch ||
		e.healthEvidenceEpoch.Load() != healthEpoch {
		return nil, topologyEpoch
	}
	slot := runtime.resolveFlatSelectorDispatchSlot(
		eligible, present, latest, topologyEpoch, healthEpoch, requireBatch,
	)
	if e.currentPathTopologyEpoch() != topologyEpoch ||
		e.healthEvidenceEpoch.Load() != healthEpoch ||
		(slot != nil && slot.dispatchStalled.Load()) {
		return nil, topologyEpoch
	}
	return slot, topologyEpoch
}

func (e *Engine) waitFlatSelectorPacketDispatch(dispatch *flatSelectorPacketDispatch) error {
	if dispatch == nil || dispatch.runtime == nil || dispatch.slot == nil || dispatch.waiter == nil {
		return net.ErrClosed
	}
	timer := flatSelectorPacketTimerPool.Get().(*time.Timer)
	defer func() {
		stopDeadlineTimer(timer)
		flatSelectorPacketTimerPool.Put(timer)
	}()
	stalled := false
	acknowledged := func() bool {
		return dispatch.ackTarget != 0 && e.applicationDispatchAcknowledged(dispatch.ackTarget)
	}
	for {
		if acknowledged() {
			abandonApplicationDispatchWaiter(dispatch.waiter)
			return nil
		}
		applicationDeadline, applicationWake, expired := e.writeDeadlineSnapshot()
		if expired {
			if acknowledged() {
				abandonApplicationDispatchWaiter(dispatch.waiter)
				return nil
			}
			dispatch.slot.markDispatchStalled(dispatch.identity)
			abandonApplicationDispatchWaiter(dispatch.waiter)
			return ErrWriteDeadlineExceeded
		}

		waitDeadline := dispatch.migrationDeadline
		waitReason := flatSelectorWaitMigrationBudget
		if !stalled && dispatch.stallDeadline.Before(waitDeadline) {
			waitDeadline = dispatch.stallDeadline
			waitReason = flatSelectorWaitStall
		}
		if !applicationDeadline.IsZero() && applicationDeadline.Before(waitDeadline) {
			waitDeadline = applicationDeadline
			waitReason = flatSelectorWaitApplicationDeadline
		}
		resetPooledDispatchTimer(timer, waitDeadline)

		cutoverGeneration, cutoverWake := e.selectorCutoverDispatchSnapshot()
		if cutoverGeneration != 0 {
			stopDeadlineTimer(timer)
			if acknowledged() {
				abandonApplicationDispatchWaiter(dispatch.waiter)
				return nil
			}
			dispatch.slot.markDispatchCutoverHandoff(dispatch.identity)
			if e.handoffSelectorCutoverDispatch(cutoverGeneration, !dispatch.firstPublication) {
				abandonApplicationDispatchWaiter(dispatch.waiter)
				return errSelectorCutoverHandoff
			}
			continue
		}
		var ackWake <-chan struct{}
		if dispatch.ackTarget != 0 {
			acknowledged, wake := e.sendAcknowledgementSnapshot(dispatch.ackTarget)
			if acknowledged {
				stopDeadlineTimer(timer)
				abandonApplicationDispatchWaiter(dispatch.waiter)
				return nil
			}
			ackWake = wake
		}

		select {
		case <-ackWake:
			acknowledged, _ := e.sendAcknowledgementSnapshot(dispatch.ackTarget)
			if acknowledged {
				stopDeadlineTimer(timer)
				abandonApplicationDispatchWaiter(dispatch.waiter)
				return nil
			}
		case result := <-dispatch.waiter.done:
			stopDeadlineTimer(timer)
			releaseApplicationDispatchWaiter(dispatch.waiter)
			if result.err != nil {
				if dispatch.ackTarget != 0 {
					if acknowledged, _ := e.sendAcknowledgementSnapshot(dispatch.ackTarget); acknowledged {
						return nil
					}
				}
				return errFlatSelectorPacketRedispatch
			}
			if dispatch.ackTarget != 0 {
				if acknowledged, _ := e.sendAcknowledgementSnapshot(dispatch.ackTarget); acknowledged {
					return nil
				}
			}
			if _, _, expired := e.writeDeadlineSnapshot(); expired {
				return ErrWriteDeadlineExceeded
			}
			return nil
		case <-timer.C:
			if acknowledged() {
				abandonApplicationDispatchWaiter(dispatch.waiter)
				return nil
			}
			switch waitReason {
			case flatSelectorWaitStall:
				dispatch.slot.markDispatchStalled(dispatch.identity)
				stalled = true
			case flatSelectorWaitApplicationDeadline:
				if _, _, expired := e.writeDeadlineSnapshot(); expired {
					dispatch.slot.markDispatchStalled(dispatch.identity)
					abandonApplicationDispatchWaiter(dispatch.waiter)
					return ErrWriteDeadlineExceeded
				}
			case flatSelectorWaitMigrationBudget:
				dispatch.slot.markDispatchStalled(dispatch.identity)
				abandonApplicationDispatchWaiter(dispatch.waiter)
				return e.executionBudgetExceeded()
			}
		case <-applicationWake:
			stopDeadlineTimer(timer)
		case <-cutoverWake:
			stopDeadlineTimer(timer)
			if cutoverGeneration, _ := e.selectorCutoverDispatchSnapshot(); cutoverGeneration != 0 {
				if acknowledged() {
					abandonApplicationDispatchWaiter(dispatch.waiter)
					return nil
				}
				dispatch.slot.markDispatchCutoverHandoff(dispatch.identity)
				if e.handoffSelectorCutoverDispatch(cutoverGeneration, !dispatch.firstPublication) {
					abandonApplicationDispatchWaiter(dispatch.waiter)
					return errSelectorCutoverHandoff
				}
			}
		case <-e.closed:
			stopDeadlineTimer(timer)
			if acknowledged() {
				abandonApplicationDispatchWaiter(dispatch.waiter)
				return nil
			}
			abandonApplicationDispatchWaiter(dispatch.waiter)
			return net.ErrClosed
		}
	}
}

func resetPooledDispatchTimer(timer *time.Timer, deadline time.Time) {
	stopDeadlineTimer(timer)
	wait := deadline.Sub(nowFn())
	if wait < 0 {
		wait = 0
	}
	timer.Reset(wait)
}

func (e *Engine) resetFlatSelectorDispatchTimer(deadline time.Time) <-chan time.Time {
	wait := deadline.Sub(nowFn())
	if wait < 0 {
		wait = 0
	}
	if e.flatSelectorDispatchTimer == nil {
		e.flatSelectorDispatchTimer = time.NewTimer(wait)
	} else {
		stopDeadlineTimer(e.flatSelectorDispatchTimer)
		e.flatSelectorDispatchTimer.Reset(wait)
	}
	return e.flatSelectorDispatchTimer.C
}

func (e *Engine) stopFlatSelectorDispatchTimer() {
	stopDeadlineTimer(e.flatSelectorDispatchTimer)
}

func (e *Engine) executionStallWindow(slots map[*pathSlot]struct{}) time.Duration {
	window := minimumDispatchStallWindow
	for slot := range slots {
		candidate := e.executionStallWindowForSlot(slot)
		if candidate > window {
			window = candidate
		}
	}
	if window > maximumDispatchStallWindow {
		return maximumDispatchStallWindow
	}
	return window
}

func (e *Engine) executionStallWindowForSlot(slot *pathSlot) time.Duration {
	window := minimumDispatchStallWindow
	if slot == nil {
		return window
	}
	quality := slot.latestSchedulingQuality(nowFn(), e.limits.ProbeInterval)
	if quality == (transport.PathQuality{}) {
		return window
	}
	if candidate := 4*quality.RTT + 2*quality.Jitter; candidate > window {
		window = candidate
	}
	if window > maximumDispatchStallWindow {
		return maximumDispatchStallWindow
	}
	return window
}

func (e *Engine) waitForExecutionProgress(deadline time.Time) error {
	return e.waitForExecutionProgressMode(deadline, false)
}

func (e *Engine) waitForExecutionProgressMode(deadline time.Time, application bool) error {
	return e.waitForExecutionProgressModeAcknowledged(deadline, application, 0)
}

func (e *Engine) waitForExecutionProgressModeAcknowledged(
	deadline time.Time,
	application bool,
	ackTarget uint64,
) error {
	acknowledged := func() bool { return e.applicationDispatchAcknowledged(ackTarget) }
	if acknowledged() {
		return nil
	}
	if !nowFn().Before(deadline) {
		if acknowledged() {
			return nil
		}
		return e.executionBudgetExceeded()
	}
	appTimer, appTimerC, appWake, expired := e.applicationDispatchDeadline(application)
	if expired {
		if acknowledged() {
			return nil
		}
		return ErrWriteDeadlineExceeded
	}
	defer stopDeadlineTimer(appTimer)
	timer := time.NewTimer(time.Millisecond)
	defer timer.Stop()
	select {
	case <-e.closed:
		if acknowledged() {
			return nil
		}
		if err := e.CloseErr(); err != nil {
			return err
		}
		return net.ErrClosed
	case <-timer.C:
		return nil
	case <-appWake:
		return nil
	case <-appTimerC:
		if _, _, expired := e.writeDeadlineSnapshot(); expired {
			if acknowledged() {
				return nil
			}
			return ErrWriteDeadlineExceeded
		}
		return nil
	}
}

func (e *Engine) applicationDispatchDeadline(enabled bool) (*time.Timer, <-chan time.Time, <-chan struct{}, bool) {
	if !enabled {
		return nil, nil, nil, false
	}
	deadline, wake, expired := e.writeDeadlineSnapshot()
	if expired {
		return nil, nil, wake, true
	}
	timer, timerC := writeDeadlineTimer(deadline)
	return timer, timerC, wake, expired
}

func (e *Engine) markDispatchPending(pending map[*pathSlot]pathDispatchIdentity) {
	for slot, identity := range pending {
		slot.markDispatchStalled(identity)
	}
}

func (e *Engine) markDispatchCutoverPending(pending map[*pathSlot]pathDispatchIdentity) {
	for slot, identity := range pending {
		slot.markDispatchCutoverHandoff(identity)
	}
}

func (e *Engine) executionBudgetExceeded() error {
	e.setCloseErr(ErrMigrationBudgetExceeded)
	go e.Close()
	return ErrMigrationBudgetExceeded
}
