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

type pathDispatchJob struct {
	frame            []byte
	bonded           bool
	routePlanned     bool
	topologyEpoch    uint64
	firstPublication bool
	acceptedPacket   bool
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
	handoffBaseline  uint64
	handedOffAtStart bool
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
	if !ok || !e.Packetized() {
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
	receipts := make([]*batchDispatchAttributionReceipt, len(jobs))
	for i := range jobs {
		if !jobs[i].routePlanned {
			receipts[i] = e.beginApplicationBatchDispatch(
				jobs[i].frame, slot, jobs[i].topologyEpoch,
			)
		}
	}
	cohorts := make([]rootDeliveryCohort, len(frames))
	for i, frame := range frames {
		cohorts[i] = e.applicationRootCohortFromFrame(frame)
	}
	started := nowFn()
	completed, batchErr := writer.WriteFrameBatch(frames)
	finished := nowFn()
	slot.releaseWrite()
	completed, batchErr = classifyFrameBatchResult(len(jobs), completed, batchErr)
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
	for i, job := range jobs {
		var err error
		if i >= completed {
			err = batchErr
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
	started := nowFn()
	n, err := slot.writeDispatchedFrameEpochObserved(job.frame, job.fenceEpoch, func() {
		e.noteApplicationDispatchRouteAtEpoch(job.frame, slot, job.topologyEpoch)
	})
	finished := nowFn()
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
	} else if !errors.Is(err, ErrPathTXFenced) {
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
		e.completeAcceptedPacketDispatch()
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

func (e *Engine) dispatchRecursiveReplayPreemptingControl(frame []byte, runtime *executionRuntime) error {
	return e.dispatchRecursiveMode(frame, runtime, true, false, nil, true)
}

func (e *Engine) dispatchDetachedStreamApplication(
	frame []byte,
	runtime *executionRuntime,
	firstPublication bool,
	handoffBaseline uint64,
	handedOffAtStart bool,
) error {
	return e.dispatchRecursiveMode(
		frame, runtime, firstPublication, true,
		&detachedStreamDispatchLease{
			handoffBaseline:  handoffBaseline,
			handedOffAtStart: handedOffAtStart,
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
			e.detachedStreamDispatchHandedOff(
				detached.handoffBaseline, detached.handedOffAtStart,
			)
	}
	if handedOff() {
		return errSelectorCutoverHandoff
	}
	if application {
		if handled, err := e.dispatchFlatSelectorApplication(
			frame, runtime, firstPublication, deadline, detached,
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
			pending, _ := e.selectorCutoverSnapshot()
			if pending {
				if acknowledged() {
					return nil
				}
				if e.handoffSelectorCutoverDispatch() {
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

		results := make(chan pathDispatchResult, len(ticket.routes))
		submitted := 0
		submittedSlots := make(map[*pathSlot]uint64, len(ticket.routes))
		submittedBonded := make(map[*pathSlot]bool, len(ticket.routes))
		for _, route := range ticket.routes {
			slot := latest[route.targetID]
			if slot == nil {
				continue
			}
			generation := slot.dispatchNextGen.Add(1)
			if slot.submitDispatch(pathDispatchJob{
				frame:            frame,
				bonded:           route.bonded,
				routePlanned:     multiRoute,
				topologyEpoch:    topologyEpoch,
				firstPublication: firstPublication,
				result:           results,
				generation:       generation,
			}) {
				submitted++
				submittedSlots[slot] = generation
				submittedBonded[slot] = route.bonded
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
		cutoverPending := false
		var cutoverWake <-chan struct{}
		if !replayPreemptingControl {
			cutoverPending, cutoverWake = e.selectorCutoverSnapshot()
		}
		if cutoverPending {
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
			e.handoffSelectorCutoverDispatch()
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
				cutoverPending, cutoverWake = e.selectorCutoverSnapshot()
				if cutoverPending {
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
					e.handoffSelectorCutoverDispatch()
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
	migrationDeadline time.Time,
	detached *detachedStreamDispatchLease,
) (bool, error) {
	handedOff := func() bool {
		return detached != nil &&
			e.detachedStreamDispatchHandedOff(
				detached.handoffBaseline, detached.handedOffAtStart,
			)
	}
	if handedOff() {
		return true, errSelectorCutoverHandoff
	}
	if runtime == nil || !runtime.flatLeafSelector {
		return false, nil
	}
	if pending, _ := e.selectorCutoverSnapshot(); pending && e.handoffSelectorCutoverDispatch() {
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

		cutoverPending, cutoverWake := e.selectorCutoverSnapshot()
		if cutoverPending {
			e.stopFlatSelectorDispatchTimer()
			if acknowledged() {
				abandonApplicationDispatchWaiter(waiter)
				return true, nil
			}
			slot.markDispatchStalled(generation)
			if e.handoffSelectorCutoverDispatch() {
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
			if pending, _ := e.selectorCutoverSnapshot(); pending {
				if acknowledged() {
					abandonApplicationDispatchWaiter(waiter)
					return true, nil
				}
				slot.markDispatchStalled(generation)
				if e.handoffSelectorCutoverDispatch() {
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
		return true, errSelectorCutoverHandoff
	}
	if e.currentPathTopologyEpoch() != topologyEpoch {
		return false, nil
	}
	if e.isClosed() {
		return true, net.ErrClosed
	}

	generation := slot.dispatchNextGen.Add(1)
	if !slot.submitDispatch(pathDispatchJob{
		frame: frame, topologyEpoch: topologyEpoch, firstPublication: firstPublication,
		acceptedPacket: true, generation: generation,
	}) {
		return false, nil
	}
	if firstPublication {
		e.noteTailReplayPublication(frame, slot)
	}
	e.acceptedPacketDispatches++
	return true, nil
}

type flatSelectorPacketDispatch struct {
	runtime           *executionRuntime
	slot              *pathSlot
	waiter            *applicationDispatchWaiter
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
	if pending, _ := e.selectorCutoverSnapshot(); pending && e.handoffSelectorCutoverDispatch() {
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
		applicationWait:  waiter,
		generation:       generation,
	}) {
		releaseApplicationDispatchWaiter(waiter)
		return nil, false, nil
	}
	ackTarget, _ := applicationDispatchAckTarget(frame)
	return &flatSelectorPacketDispatch{
		runtime: runtime, slot: slot, waiter: waiter, generation: generation,
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

		cutoverPending, cutoverWake := e.selectorCutoverSnapshot()
		if cutoverPending {
			stopDeadlineTimer(timer)
			if acknowledged() {
				abandonApplicationDispatchWaiter(dispatch.waiter)
				return nil
			}
			dispatch.slot.markDispatchStalled(dispatch.generation)
			if e.handoffSelectorCutoverDispatch() {
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
			if pending, _ := e.selectorCutoverSnapshot(); pending {
				if acknowledged() {
					abandonApplicationDispatchWaiter(dispatch.waiter)
					return nil
				}
				dispatch.slot.markDispatchStalled(dispatch.generation)
				if e.handoffSelectorCutoverDispatch() {
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
