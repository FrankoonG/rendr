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
			if !compatible || candidate.fenceEpoch != first.fenceEpoch || seq != lastSeq+1 {
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
	completed, batchErr := writer.WriteFrameBatch(frames)
	slot.releaseWrite()
	completed, batchErr = classifyFrameBatchResult(len(jobs), completed, batchErr)
	if completed > 0 {
		slot.batchWriteCalls.Add(1)
		slot.batchWriteFrames.Add(uint64(completed))
		updateAtomicMaximum(&slot.batchWriteMax, uint64(completed))
		slot.dataWrites.Add(uint64(completed))
		slot.lastSendUnixNano.Store(nowFn().UnixNano())
		for i := 0; i < completed; i++ {
			slot.recordDispatch(jobs[i].frame, jobs[i].firstPublication)
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
	n, err := slot.writeDispatchedFrameEpoch(job.frame, job.fenceEpoch)
	if err == nil && n != len(job.frame) {
		err = io.ErrShortWrite
	}
	if err == nil {
		slot.lastSendUnixNano.Store(nowFn().UnixNano())
		slot.recordDispatch(job.frame, job.firstPublication)
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
	return e.dispatchRecursiveMode(frame, runtime, firstPublication, false)
}

func (e *Engine) dispatchRecursiveApplication(frame []byte, runtime *executionRuntime, firstPublication bool) error {
	return e.dispatchRecursiveMode(frame, runtime, firstPublication, true)
}

func (e *Engine) dispatchRecursiveMode(frame []byte, runtime *executionRuntime, firstPublication, application bool) error {
	deadline := nowFn().Add(e.limits.MigrationBudget)
	if application {
		if handled, err := e.dispatchFlatSelectorApplication(frame, runtime, firstPublication, deadline); handled {
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
		if e.isClosed() {
			return net.ErrClosed
		}
		if pending, _ := e.selectorCutoverSnapshot(); pending && e.handoffSelectorCutoverDispatch() {
			return errSelectorCutoverHandoff
		}
		if application {
			if _, _, expired := e.writeDeadlineSnapshot(); expired {
				return ErrWriteDeadlineExceeded
			}
		}
		e.pathsMu.RLock()
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
				qualities[slot.localTXTargetID] = slot.quality()
				capacities[slot.localTXTargetID] = uint64(slot.spec.Weight)
			}
		}
		e.pathsMu.RUnlock()

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
				return err
			}
			if err := e.waitForExecutionProgressMode(deadline, application); err != nil {
				return err
			}
			continue
		}

		results := make(chan pathDispatchResult, len(ticket.routes))
		submitted := 0
		submittedSlots := make(map[*pathSlot]uint64, len(ticket.routes))
		for _, route := range ticket.routes {
			slot := latest[route.targetID]
			if slot == nil {
				continue
			}
			generation := slot.dispatchNextGen.Add(1)
			if slot.submitDispatch(pathDispatchJob{
				frame:            frame,
				bonded:           route.bonded,
				firstPublication: firstPublication,
				result:           results,
				generation:       generation,
			}) {
				submitted++
				submittedSlots[slot] = generation
			}
		}
		if submitted == 0 {
			if err := e.waitForExecutionProgressMode(deadline, application); err != nil {
				return err
			}
			continue
		}

		remainingBudget := deadline.Sub(nowFn())
		if remainingBudget <= 0 {
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
		cutoverPending, cutoverWake := e.selectorCutoverSnapshot()
		if cutoverPending {
			e.markDispatchPending(pending)
			stopDeadlineTimer(budgetTimer)
			stopDeadlineTimer(stallTimer)
			stopDeadlineTimer(appTimer)
			e.handoffSelectorCutoverDispatch()
			return errSelectorCutoverHandoff
		}
		if appExpired {
			e.markDispatchPending(pending)
			stopDeadlineTimer(budgetTimer)
			stopDeadlineTimer(stallTimer)
			return ErrWriteDeadlineExceeded
		}
		stalled := false
		strictSelector := ticket.kind == proto.ExecutionKindSelector && len(ticket.routes) == 1 && !ticket.routes[0].bonded
		remaining := submitted
		for remaining > 0 && !stalled {
			select {
			case result := <-results:
				remaining--
				delete(pending, result.slot)
				if result.err == nil {
					if application {
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
				for slot, generation := range pending {
					if !slot.dispatchStalled.Load() {
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
				cutoverPending, cutoverWake = e.selectorCutoverSnapshot()
				if cutoverPending {
					e.markDispatchPending(pending)
					stopDeadlineTimer(budgetTimer)
					stopDeadlineTimer(stallTimer)
					stopDeadlineTimer(appTimer)
					e.handoffSelectorCutoverDispatch()
					return errSelectorCutoverHandoff
				}
			case <-e.closed:
				stopDeadlineTimer(budgetTimer)
				stopDeadlineTimer(stallTimer)
				stopDeadlineTimer(appTimer)
				return net.ErrClosed
			case <-budgetTimer.C:
				stopDeadlineTimer(stallTimer)
				stopDeadlineTimer(appTimer)
				return e.executionBudgetExceeded()
			case <-appWake:
				stopDeadlineTimer(appTimer)
				appTimer, appTimerC, appWake, appExpired = e.applicationDispatchDeadline(application)
				if appExpired {
					e.markDispatchPending(pending)
					stopDeadlineTimer(budgetTimer)
					stopDeadlineTimer(stallTimer)
					return ErrWriteDeadlineExceeded
				}
			case <-appTimerC:
				appTimer, appTimerC, appWake, appExpired = e.applicationDispatchDeadline(application)
				if appExpired {
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
		if err := e.waitForExecutionProgressMode(deadline, application); err != nil {
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
// ticket for the common root-selector-with-path-children shape. The committed
// active path remains the sole route. Blocking writes still run on the path
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
) (bool, error) {
	if runtime == nil || !runtime.flatLeafSelector {
		return false, nil
	}
	if pending, _ := e.selectorCutoverSnapshot(); pending && e.handoffSelectorCutoverDispatch() {
		return true, errSelectorCutoverHandoff
	}
	if e.isClosed() {
		return true, net.ErrClosed
	}

	e.pathsMu.RLock()
	slot := e.paths[e.activeID]
	eligible := slot != nil && runtime.ownsFlatSelectorLeaf(slot.localTXTargetID) &&
		e.dispatchScopeAllowsLocked(slot.id) && !slot.dispatchStalled.Load()
	e.pathsMu.RUnlock()
	if !eligible {
		return false, nil
	}

	waiter := acquireApplicationDispatchWaiter()
	generation := slot.dispatchNextGen.Add(1)
	if !slot.submitDispatch(pathDispatchJob{
		frame:            frame,
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
		applicationDeadline, applicationWake, expired := e.writeDeadlineSnapshot()
		if expired {
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
			slot.markDispatchStalled(generation)
			if e.handoffSelectorCutoverDispatch() {
				abandonApplicationDispatchWaiter(waiter)
				return true, errSelectorCutoverHandoff
			}
			continue
		}

		select {
		case dispatchResult := <-waiter.done:
			e.stopFlatSelectorDispatchTimer()
			releaseApplicationDispatchWaiter(waiter)
			if dispatchResult.err != nil {
				return false, nil
			}
			if _, _, expired := e.writeDeadlineSnapshot(); expired {
				return true, ErrWriteDeadlineExceeded
			}
			return true, nil
		case <-timerC:
			switch waitReason {
			case flatSelectorWaitStall:
				if !slot.dispatchStalled.Load() {
					runtime.stuckSkips.Add(1)
				}
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
			if pending, _ := e.selectorCutoverSnapshot(); pending {
				slot.markDispatchStalled(generation)
				if e.handoffSelectorCutoverDispatch() {
					abandonApplicationDispatchWaiter(waiter)
					return true, errSelectorCutoverHandoff
				}
			}
		case <-e.closed:
			e.stopFlatSelectorDispatchTimer()
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
	e.selectorCutoverMu.Lock()
	defer e.selectorCutoverMu.Unlock()
	if e.selectorCutoverPending {
		e.selectorCutoverHandedOff = true
		return true, errSelectorCutoverHandoff
	}
	if e.isClosed() {
		return true, net.ErrClosed
	}

	e.pathsMu.RLock()
	slot := e.paths[e.activeID]
	batchCapable := false
	if slot != nil {
		_, batchCapable = slot.conn.(transport.FrameBatchWriter)
	}
	eligible := slot != nil && batchCapable && runtime.ownsFlatSelectorLeaf(slot.localTXTargetID) &&
		e.dispatchScopeAllowsLocked(slot.id) && !slot.dispatchStalled.Load()
	e.pathsMu.RUnlock()
	if !eligible {
		return false, nil
	}

	generation := slot.dispatchNextGen.Add(1)
	if !slot.submitDispatch(pathDispatchJob{
		frame: frame, firstPublication: firstPublication, acceptedPacket: true, generation: generation,
	}) {
		return false, nil
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

	e.pathsMu.RLock()
	slot := e.paths[e.activeID]
	eligible := slot != nil && runtime.ownsFlatSelectorLeaf(slot.localTXTargetID) &&
		e.dispatchScopeAllowsLocked(slot.id) && !slot.dispatchStalled.Load()
	e.pathsMu.RUnlock()
	if !eligible {
		return nil, false, nil
	}

	waiter := acquireApplicationDispatchWaiter()
	generation := slot.dispatchNextGen.Add(1)
	if !slot.submitDispatch(pathDispatchJob{
		frame:            frame,
		firstPublication: firstPublication,
		applicationWait:  waiter,
		generation:       generation,
	}) {
		releaseApplicationDispatchWaiter(waiter)
		return nil, false, nil
	}
	return &flatSelectorPacketDispatch{
		runtime: runtime, slot: slot, waiter: waiter, generation: generation,
		migrationDeadline: migrationDeadline,
		stallDeadline:     nowFn().Add(e.executionStallWindowForSlot(slot)),
	}, true, nil
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
	for {
		applicationDeadline, applicationWake, expired := e.writeDeadlineSnapshot()
		if expired {
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
			dispatch.slot.markDispatchStalled(dispatch.generation)
			if e.handoffSelectorCutoverDispatch() {
				abandonApplicationDispatchWaiter(dispatch.waiter)
				return errSelectorCutoverHandoff
			}
			continue
		}

		select {
		case result := <-dispatch.waiter.done:
			stopDeadlineTimer(timer)
			releaseApplicationDispatchWaiter(dispatch.waiter)
			if result.err != nil {
				return errFlatSelectorPacketRedispatch
			}
			if _, _, expired := e.writeDeadlineSnapshot(); expired {
				return ErrWriteDeadlineExceeded
			}
			return nil
		case <-timer.C:
			switch waitReason {
			case flatSelectorWaitStall:
				if !dispatch.slot.dispatchStalled.Load() {
					dispatch.runtime.stuckSkips.Add(1)
				}
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
				dispatch.slot.markDispatchStalled(dispatch.generation)
				if e.handoffSelectorCutoverDispatch() {
					abandonApplicationDispatchWaiter(dispatch.waiter)
					return errSelectorCutoverHandoff
				}
			}
		case <-e.closed:
			stopDeadlineTimer(timer)
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
	quality := slot.quality()
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
	if !nowFn().Before(deadline) {
		return e.executionBudgetExceeded()
	}
	appTimer, appTimerC, appWake, expired := e.applicationDispatchDeadline(application)
	if expired {
		return ErrWriteDeadlineExceeded
	}
	defer stopDeadlineTimer(appTimer)
	timer := time.NewTimer(time.Millisecond)
	defer timer.Stop()
	select {
	case <-e.closed:
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
