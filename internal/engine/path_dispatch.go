package engine

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

const pathDispatchQueueSize = 64
const maximumPathDispatchBatch = 16
const maximumPathDispatchBatchYields = maximumPathDispatchBatch - 1

const minimumDispatchStallWindow = 100 * time.Millisecond
const maximumDispatchStallWindow = 2 * time.Second

var (
	errFrameRetiredBeforeWrite = errors.New("engine: DATA frame retired before physical write")
	errFrameDispatchAdmission  = errors.New("engine: DATA dispatch lacks replay-ledger admission")
)

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
	frame            []byte
	bonded           bool
	routePlanned     bool
	topologyEpoch    uint64
	firstPublication bool
	admission        frameDispatchAdmission
	preparedDispatch physicalFrameDispatch
	dispatchPrepared bool
	acceptedPacket   bool
	custodyTicket    uint64
	result           chan<- pathDispatchResult
	applicationWait  *applicationDispatchWaiter
	generation       uint64
	fenceEpoch       uint64
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

func (s *pathSlot) markDispatchStalled(generation uint64) {
	if s == nil || generation == 0 {
		return
	}
	s.dispatchStalled.Store(true)
	s.dispatchStallGen.Store(generation)
	if s.dispatchDoneGen.Load() >= generation && s.dispatchStallGen.CompareAndSwap(generation, 0) {
		s.dispatchStalled.Store(false)
	}
}

func (s *pathSlot) completeDispatch(generation uint64) {
	if s == nil || generation == 0 {
		return
	}
	for {
		completed := s.dispatchDoneGen.Load()
		if generation <= completed || s.dispatchDoneGen.CompareAndSwap(completed, generation) {
			break
		}
	}
	if s.dispatchStallGen.CompareAndSwap(generation, 0) {
		s.dispatchStalled.Store(false)
	}
}

type pathDispatchResult struct {
	slot *pathSlot
	err  error
}

type detachedStreamDispatchLease struct {
	custodyTicket uint64
}

func (s *pathSlot) submitDispatch(job pathDispatchJob) bool {
	s.dispatchMu.Lock()
	defer s.dispatchMu.Unlock()
	if s.dispatchDead || s.dispatchFenced {
		return false
	}
	job.fenceEpoch = s.txFenceEpoch.Load()
	select {
	case s.dispatchQ <- job:
		return true
	default:
		return false
	}
}

func (e *Engine) pathWriterLoop(slot *pathSlot) {
	defer close(slot.doneW)
	var pending *pathDispatchJob
	for {
		if pending != nil {
			select {
			case <-slot.quit:
				e.completeRejectedDispatch(slot, *pending)
				e.rejectQueuedDispatches(slot)
				return
			case <-e.closed:
				e.completeRejectedDispatch(slot, *pending)
				e.rejectQueuedDispatches(slot)
				return
			default:
			}
			job := *pending
			pending = nil
			if next, ok := e.executePathDispatchBatch(slot, job); ok {
				pending = next
			} else {
				e.executePathDispatch(slot, job)
			}
			continue
		}
		select {
		case job := <-slot.dispatchQ:
			if next, ok := e.executePathDispatchBatch(slot, job); ok {
				pending = next
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

func (e *Engine) executePathDispatchBatch(slot *pathSlot, first pathDispatchJob) (*pathDispatchJob, bool) {
	writer, ok := slot.conn.(transport.FrameBatchWriter)
	_, atomicDispatch := slot.conn.(transport.FrameDispatchWriter)
	if !ok || atomicDispatch || !e.Packetized() {
		return nil, false
	}
	firstSeq, ok := packetApplicationDispatchSequence(first)
	if !ok {
		return nil, false
	}
	if !slot.txEnabled.Load() || slot.txFenceEpoch.Load() != first.fenceEpoch {
		e.completePathDispatch(slot, first, ErrPathTXFenced)
		return nil, true
	}
	if slot.dispatchBeforeWritePermit != nil {
		slot.dispatchBeforeWritePermit()
	}
	if err := slot.acquireWrite(context.Background()); err != nil {
		e.completePathDispatch(slot, first, err)
		return nil, true
	}

	jobs := make([]pathDispatchJob, 1, maximumPathDispatchBatch)
	jobs[0] = first
	frames := make([][]byte, 1, maximumPathDispatchBatch)
	frames[0] = first.frame
	lastSeq := firstSeq
	var pending *pathDispatchJob
	yields := 0
	for len(jobs) < maximumPathDispatchBatch {
		select {
		case candidate := <-slot.dispatchQ:
			seq, compatible := packetApplicationDispatchSequence(candidate)
			if !compatible || candidate.fenceEpoch != first.fenceEpoch ||
				candidate.topologyEpoch != first.topologyEpoch || seq != lastSeq+1 {
				pending = &candidate
				goto drained
			}
			jobs = append(jobs, candidate)
			frames = append(frames, candidate.frame)
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
		for _, job := range jobs {
			e.completePathDispatch(slot, job, ErrPathTXFenced)
		}
		return pending, true
	}
	allJobs := jobs
	prepared, retired, preparedReceipts, lease, err := e.preparePhysicalFrameDispatchBatch(allJobs, slot)
	if err != nil {
		slot.releaseWrite()
		for _, queued := range allJobs {
			e.completePathDispatch(slot, queued, err)
		}
		return pending, true
	}
	defer func() {
		if lease != 0 {
			e.releaseFrameDispatchLease(&lease)
		}
	}()
	if lease != 0 && e.frameDispatchBatchAfterLease != nil {
		e.frameDispatchBatchAfterLease()
	}
	jobs = make([]pathDispatchJob, 0, len(allJobs))
	frames = make([][]byte, 0, len(allJobs))
	dispatches := make([]physicalFrameDispatch, 0, len(allJobs))
	receipts := make([]*batchDispatchAttributionReceipt, 0, len(allJobs))
	for i, job := range allJobs {
		if retired[i] {
			continue
		}
		jobs = append(jobs, job)
		frames = append(frames, job.frame)
		dispatches = append(dispatches, prepared[i])
		receipts = append(receipts, preparedReceipts[i])
	}
	if len(jobs) == 0 {
		slot.releaseWrite()
		for _, job := range allJobs {
			e.completePathDispatch(slot, job, nil)
		}
		return pending, true
	}
	cohorts := make([]rootDeliveryCohort, len(frames))
	for i, frame := range frames {
		cohorts[i] = e.applicationRootCohortFromFrame(frame)
	}
	spans := make([]FrameDispatchSpan, len(dispatches))
	for i := range dispatches {
		spans[i] = beginPhysicalFrameDispatch(slot, dispatches[i])
	}
	writeToken := e.pathDataWriteToken(slot, first.fenceEpoch)
	started := nowFn()
	completed, batchErr := writer.WriteFrameBatch(frames)
	finished := nowFn()
	completed, batchErr = classifyFrameBatchResult(len(jobs), completed, batchErr)
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
		span.FinishFrameDispatch(completion)
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
		if jobs[i].firstPublication && len(jobs[i].frame) >= proto.HeaderSize {
			if header, err := proto.DecodeHeader(jobs[i].frame[:proto.HeaderSize]); err == nil &&
				header.Type == proto.FrameData {
				slot.noteFirstDataWriteSequence(header.Seq, writeToken)
			}
		}
	}
	if e.pathDispatchBatchBeforePermitRelease != nil {
		e.pathDispatchBatchBeforePermitRelease(slot)
	}
	slot.releaseWrite()
	e.resolveApplicationBatchDispatch(receipts, completed)
	if completed > 0 {
		slot.batchWriteCalls.Add(1)
		slot.batchWriteFrames.Add(uint64(completed))
		updateAtomicMaximum(&slot.batchWriteMax, uint64(completed))
		slot.dataWrites.Add(uint64(completed))
		slot.lastSendUnixNano.Store(nowFn().UnixNano())
		for i := 0; i < completed; i++ {
			e.noteApplicationDispatchDuration(
				cohorts[i], jobs[i].topologyEpoch, started, finished, true,
			)
			slot.recordDispatch(jobs[i].frame, jobs[i].firstPublication)
			e.noteTailReplayPublication(jobs[i].frame, slot)
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
	return pending, true
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
	digest := proto.DigestFrame(frame)
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
	digest := proto.DigestFrame(frame)
	e.sendHistMu.Lock()
	authorization, data, retired, err := e.authorizeFrameDispatchLocked(frame, digest, admission)
	e.sendHistMu.Unlock()
	return authorization, data, retired, err
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
	digest := proto.DigestFrame(job.frame)
	e.sendHistMu.Lock()
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
) ([]physicalFrameDispatch, []bool, []*batchDispatchAttributionReceipt, frameDispatchLease, error) {
	dispatches := make([]physicalFrameDispatch, len(jobs))
	retired := make([]bool, len(jobs))
	receipts := make([]*batchDispatchAttributionReceipt, len(jobs))
	if len(jobs) == 0 {
		return dispatches, retired, receipts, 0, nil
	}
	var binding graphBinding
	var attributionStarted time.Time
	if batchSlot != nil {
		binding = e.localGraphBinding()
		attributionStarted = nowFn()
	}
	var digestStorage [maximumPathDispatchBatch]proto.FrameDigest
	var digests []proto.FrameDigest
	if len(jobs) <= len(digestStorage) {
		digests = digestStorage[:len(jobs)]
	} else {
		digests = make([]proto.FrameDigest, len(jobs))
	}
	for index := range jobs {
		digests[index] = proto.DigestFrame(jobs[index].frame)
	}

	e.sendHistMu.Lock()
	leasedDATA := 0
	for index, job := range jobs {
		dispatch := job.preparedDispatch
		itemRetired := false
		if job.dispatchPrepared {
			if err := e.validatePreparedFrameDispatch(job.frame, digests[index], job.admission, dispatch); err != nil {
				e.sendHistMu.Unlock()
				return nil, nil, nil, 0, err
			}
		} else {
			authorization, data, retired, err := e.authorizeFrameDispatchLocked(job.frame, digests[index], job.admission)
			if err != nil {
				e.sendHistMu.Unlock()
				return nil, nil, nil, 0, err
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
				return nil, nil, nil, 0, errFrameDispatchAdmission
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
			receipts[index] = e.beginApplicationBatchDispatchLocked(
				job.frame, batchSlot, job.topologyEpoch, binding, attributionStarted,
			)
		}
	}
	e.sendHistMu.Unlock()
	return dispatches, retired, receipts, lease, nil
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
	var digestStorage [maximumPathDispatchBatch]proto.FrameDigest
	var digests []proto.FrameDigest
	if len(jobs) <= len(digestStorage) {
		digests = digestStorage[:len(jobs)]
	} else {
		digests = make([]proto.FrameDigest, len(jobs))
	}
	firstFrame := jobs[0].frame
	firstDigest := proto.DigestFrame(firstFrame)
	for index := range jobs {
		frame := jobs[index].frame
		if len(frame) == len(firstFrame) && (len(frame) == 0 || &frame[0] == &firstFrame[0]) {
			digests[index] = firstDigest
			continue
		}
		digests[index] = proto.DigestFrame(frame)
	}
	e.sendHistMu.Lock()
	defer e.sendHistMu.Unlock()
	for index, job := range jobs {
		authorization, data, retired, err := e.authorizeFrameDispatchLocked(job.frame, digests[index], job.admission)
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

func beginPhysicalFrameDispatch(slot *pathSlot, dispatch physicalFrameDispatch) FrameDispatchSpan {
	if dispatch.data {
		if tracer, ok := slot.conn.(FrameDispatchTracer); ok {
			authorization := dispatch.authorization
			authorization.PhysicalOccurrence = 1
			authorization.FrameOffset = 0
			return tracer.BeginFrameDispatch(authorization)
		}
	}
	return nil
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
	cohort := e.applicationRootCohortFromFrame(job.frame)
	var writeToken pathDataWriteToken
	var dispatchSpan FrameDispatchSpan
	var dispatchLease frameDispatchLease
	var physicalStarted time.Time
	started := nowFn()
	n, err := slot.writeDispatchedFrameEpochObserved(job.frame, job.fenceEpoch, func() (dispatchedFrameWrite, error) {
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
				dispatchSpan = beginPhysicalFrameDispatch(slot, dispatch)
			}
		}
		e.noteApplicationDispatchRouteAtEpoch(job.frame, slot, job.topologyEpoch)
		writeToken = e.pathDataWriteToken(slot, job.fenceEpoch)
		physicalStarted = nowFn()
		return prepared, nil
	}, func(n int, writeErr error) {
		completedAt := nowFn()
		if dispatchSpan != nil {
			dispatchSpan.FinishFrameDispatch(FrameDispatchCompletion{
				StartedAt: physicalStarted, CompletedAt: completedAt,
				FrameBytes: len(job.frame), BytesWritten: n, BytesWrittenKnown: true,
				WriteCalls:   1,
				AttemptState: FrameDispatchAttempted, WriteAttempted: true,
				WholeFrameAccepted: n == len(job.frame),
				BatchIndex:         0, BatchSize: 1, Err: writeErr,
			})
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

func (e *Engine) completePathDispatch(slot *pathSlot, job pathDispatchJob, err error) {
	result := pathDispatchResult{slot: slot, err: err}
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
	slot.completeDispatch(job.generation)
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
		e.pathsMu.RLock()
		topologyEpoch := e.currentPathTopologyEpoch()
		attached := make(map[proto.TargetID]bool, len(e.paths))
		present := make(map[proto.TargetID]bool, len(e.paths))
		latest := make(map[proto.TargetID]*pathSlot, len(e.paths))
		qualities := make(map[proto.TargetID]transport.PathQuality, len(e.paths))
		capacities := make(map[proto.TargetID]uint64, len(e.paths))
		for _, slot := range e.paths {
			if slot.localTXTargetID == (proto.TargetID{}) {
				continue
			}
			present[slot.localTXTargetID] = true
			if slot.dispatchStalled.Load() {
				continue
			}
			attached[slot.localTXTargetID] = true
			if previous := latest[slot.localTXTargetID]; previous == nil || slot.gen > previous.gen {
				latest[slot.localTXTargetID] = slot
				qualities[slot.localTXTargetID] = slot.latestObservedQuality()
				capacities[slot.localTXTargetID] = uint64(slot.spec.Weight)
			}
		}
		e.pathsMu.RUnlock()
		if handedOff() {
			return errSelectorCutoverHandoff
		}

		selectorPresence := present
		if controlFallback {
			// Sequenced recovery/control traffic may escape a blocked selected
			// carrier so FIN, policy, and retirement cannot deadlock behind
			// application DATA. DATA, including replay, always uses physical
			// presence and therefore requires an authorized selector cutover.
			selectorPresence = attached
		}
		ticket, err := runtime.buildTicketObservedPresence(
			attached, selectorPresence, qualities, capacities, e.Packetized(),
			e.limits.BondPinSize, e.limits.BondStuckRTTMultiplier,
		)
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
		multiRoute := len(ticket.routes) > 1
		if multiRoute {
			e.noteApplicationDispatchPlanAtEpoch(frame, ticket.routes, topologyEpoch)
		}

		type routeCandidate struct {
			slot *pathSlot
			job  pathDispatchJob
		}
		candidates := make([]routeCandidate, 0, len(ticket.routes))
		for _, route := range ticket.routes {
			slot := latest[route.targetID]
			if slot == nil {
				continue
			}
			generation := slot.dispatchNextGen.Add(1)
			candidates = append(candidates, routeCandidate{slot: slot, job: pathDispatchJob{
				frame:            frame,
				bonded:           route.bonded,
				routePlanned:     multiRoute,
				topologyEpoch:    topologyEpoch,
				firstPublication: firstPublication,
				admission:        admission,
				generation:       generation,
			}})
		}
		if len(candidates) > 1 {
			jobs := make([]pathDispatchJob, len(candidates))
			for index := range candidates {
				jobs[index] = candidates[index].job
			}
			dispatches, err := e.prepareLogicalFrameDispatchFanout(jobs)
			if errors.Is(err, errFrameRetiredBeforeWrite) {
				return nil
			}
			if err != nil {
				return err
			}
			for index := range candidates {
				candidates[index].job.preparedDispatch = dispatches[index]
				candidates[index].job.dispatchPrepared = true
			}
		}

		results := make(chan pathDispatchResult, len(candidates))
		submitted := 0
		submittedSlots := make(map[*pathSlot]uint64, len(candidates))
		submittedBonded := make(map[*pathSlot]bool, len(candidates))
		for index := range candidates {
			candidate := &candidates[index]
			candidate.job.result = results
			if candidate.slot.submitDispatch(candidate.job) {
				submitted++
				submittedSlots[candidate.slot] = candidate.job.generation
				submittedBonded[candidate.slot] = candidate.job.bonded
			}
		}
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
		pending := make(map[*pathSlot]uint64, submitted)
		for slot, generation := range submittedSlots {
			pending[slot] = generation
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
			e.markDispatchPending(pending)
			stopDeadlineTimer(budgetTimer)
			stopDeadlineTimer(stallTimer)
			stopDeadlineTimer(appTimer)
			e.handoffSelectorCutoverDispatch(cutoverGeneration, !firstPublication)
			return errSelectorCutoverHandoff
		}
		if handedOff() {
			e.markDispatchPending(pending)
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
		strictSelector := application && ticket.kind == proto.ExecutionKindSelector &&
			len(ticket.routes) == 1 && !ticket.routes[0].bonded
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
				for slot, generation := range pending {
					if submittedBonded[slot] && !slot.dispatchStalled.Load() {
						runtime.stuckSkips.Add(1)
					}
					slot.markDispatchStalled(generation)
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
					e.markDispatchPending(pending)
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
					e.markDispatchPending(pending)
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
	generation := slot.dispatchNextGen.Add(1)
	if !slot.submitDispatch(pathDispatchJob{
		frame:            frame,
		topologyEpoch:    topologyEpoch,
		firstPublication: firstPublication,
		admission:        admission,
		applicationWait:  waiter,
		generation:       generation,
	}) {
		releaseApplicationDispatchWaiter(waiter)
		return false, nil
	}
	stallDeadline := nowFn().Add(e.executionStallWindowForSlot(slot))
	stalled := false
	for {
		if handedOff() {
			slot.markDispatchStalled(generation)
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
			slot.markDispatchStalled(generation)
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
			slot.markDispatchStalled(generation)
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
				slot.markDispatchStalled(generation)
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
				slot.markDispatchStalled(generation)
				stalled = true
			case flatSelectorWaitApplicationDeadline:
				if _, _, expired := e.writeDeadlineSnapshot(); expired {
					slot.markDispatchStalled(generation)
					abandonApplicationDispatchWaiter(waiter)
					return true, ErrWriteDeadlineExceeded
				}
			case flatSelectorWaitMigrationBudget:
				slot.markDispatchStalled(generation)
				abandonApplicationDispatchWaiter(waiter)
				return true, e.executionBudgetExceeded()
			}
		case <-applicationWake:
			e.stopFlatSelectorDispatchTimer()
		case <-cutoverWake:
			e.stopFlatSelectorDispatchTimer()
			if handedOff() {
				slot.markDispatchStalled(generation)
				abandonApplicationDispatchWaiter(waiter)
				return true, errSelectorCutoverHandoff
			}
			if cutoverGeneration, _ := e.selectorCutoverDispatchSnapshot(); cutoverGeneration != 0 {
				if acknowledged() {
					abandonApplicationDispatchWaiter(waiter)
					return true, nil
				}
				slot.markDispatchStalled(generation)
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

	generation := slot.dispatchNextGen.Add(1)
	custodyTicket := e.nextDispatchCustodyTicketLocked()
	if !slot.submitDispatch(pathDispatchJob{
		frame: frame, topologyEpoch: topologyEpoch, firstPublication: firstPublication,
		admission:      admission,
		acceptedPacket: true, custodyTicket: custodyTicket, generation: generation,
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
	generation        uint64
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
	generation := slot.dispatchNextGen.Add(1)
	if !slot.submitDispatch(pathDispatchJob{
		frame:            frame,
		topologyEpoch:    topologyEpoch,
		firstPublication: firstPublication,
		admission:        admission,
		applicationWait:  waiter,
		generation:       generation,
	}) {
		releaseApplicationDispatchWaiter(waiter)
		return nil, false, nil
	}
	ackTarget, _ := applicationDispatchAckTarget(frame)
	return &flatSelectorPacketDispatch{
		runtime: runtime, slot: slot, waiter: waiter, generation: generation,
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
	e.pathsMu.RLock()
	topologyEpoch := e.currentPathTopologyEpoch()
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

	targetID, ok := runtime.flatSelectorDispatchLeaf(eligible, present)
	if !ok {
		return nil, topologyEpoch
	}
	return latest[targetID], topologyEpoch
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
			dispatch.slot.markDispatchStalled(dispatch.generation)
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
			dispatch.slot.markDispatchStalled(dispatch.generation)
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
				dispatch.slot.markDispatchStalled(dispatch.generation)
				stalled = true
			case flatSelectorWaitApplicationDeadline:
				if _, _, expired := e.writeDeadlineSnapshot(); expired {
					dispatch.slot.markDispatchStalled(dispatch.generation)
					abandonApplicationDispatchWaiter(dispatch.waiter)
					return ErrWriteDeadlineExceeded
				}
			case flatSelectorWaitMigrationBudget:
				dispatch.slot.markDispatchStalled(dispatch.generation)
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
				dispatch.slot.markDispatchStalled(dispatch.generation)
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
	quality := slot.latestObservedQuality()
	if quality.At.IsZero() || nowFn().Sub(quality.At) > selectorEvidenceFreshFor {
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

func (e *Engine) markDispatchPending(pending map[*pathSlot]uint64) {
	for slot, generation := range pending {
		slot.markDispatchStalled(generation)
	}
}

func (e *Engine) executionBudgetExceeded() error {
	e.setCloseErr(ErrMigrationBudgetExceeded)
	go e.Close()
	return ErrMigrationBudgetExceeded
}
