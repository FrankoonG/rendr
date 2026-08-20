package engine

import (
	"errors"
	"io"
	"net"
	"os"
	"time"

	"github.com/FrankoonG/rendr/proto"
)

type writeTimeoutError struct{}

func (writeTimeoutError) Error() string   { return "rendr: write deadline exceeded" }
func (writeTimeoutError) Timeout() bool   { return true }
func (writeTimeoutError) Temporary() bool { return true }
func (writeTimeoutError) Unwrap() error   { return os.ErrDeadlineExceeded }

// ErrWriteDeadlineExceeded is the sentinel returned when an application DATA
// write cannot complete before SetWriteDeadline's absolute deadline.
var ErrWriteDeadlineExceeded net.Error = writeTimeoutError{}

type applicationWriteDeadlineState struct {
	deadline time.Time
	wake     chan struct{}
}

func newApplicationWriteDeadlineState(deadline time.Time) *applicationWriteDeadlineState {
	return &applicationWriteDeadlineState{deadline: deadline, wake: make(chan struct{})}
}

// SetWriteDeadline sets the absolute deadline for pending and future
// application DATA writes. Replacing the wake channel makes every waiter
// re-evaluate extensions and clears without retaining one timer per Conn.
func (e *Engine) SetWriteDeadline(t time.Time) error {
	e.writeDeadlineMu.Lock()
	previous := e.writeDeadlineState.Load()
	e.writeDeadlineState.Store(newApplicationWriteDeadlineState(t))
	if previous != nil {
		close(previous.wake)
	}
	e.writeDeadlineMu.Unlock()
	return nil
}

func writeDeadlineExceeded(deadline time.Time) bool {
	return !deadline.IsZero() && !time.Now().Before(deadline)
}

func (e *Engine) writeDeadlineSnapshot() (time.Time, <-chan struct{}, bool) {
	state := e.writeDeadlineState.Load()
	if state == nil {
		return time.Time{}, nil, false
	}
	return state.deadline, state.wake, writeDeadlineExceeded(state.deadline)
}

func (e *Engine) writeDeadlineLocked() time.Time {
	state := e.writeDeadlineState.Load()
	if state == nil {
		return time.Time{}
	}
	return state.deadline
}

func (e *Engine) acquireApplicationWritePermit() error {
	select {
	case <-e.appWritePermit:
		if e.isClosed() {
			e.releaseApplicationWritePermit()
			return net.ErrClosed
		}
		return nil
	default:
	}
	for {
		deadline, wake, expired := e.writeDeadlineSnapshot()
		if expired {
			return ErrWriteDeadlineExceeded
		}

		timer, timerC := writeDeadlineTimer(deadline)
		select {
		case <-e.appWritePermit:
			stopDeadlineTimer(timer)
			if e.isClosed() {
				e.releaseApplicationWritePermit()
				return net.ErrClosed
			}
			return nil
		case <-wake:
			stopDeadlineTimer(timer)
		case <-timerC:
		case <-e.closed:
			stopDeadlineTimer(timer)
			if err := e.CloseErr(); err != nil {
				return err
			}
			return net.ErrClosed
		}
	}
}

func (e *Engine) acquireApplicationSendSlot(frameBytes int) error {
	if frameBytes <= 0 || frameBytes > sendHistoryByteLimit {
		return errors.New("engine: invalid replay byte credit request")
	}
	waiting := false
	markWaiting := func() {
		if waiting {
			return
		}
		waiting = true
		e.sendHistMu.Lock()
		e.sendHist.creditWaiters++
		e.sendHist.backpressure++
		e.sendHist.generation++
		e.sendHistMu.Unlock()
	}
	defer func() {
		if !waiting {
			return
		}
		e.sendHistMu.Lock()
		if e.sendHist.creditWaiters > 0 {
			e.sendHist.creditWaiters--
		}
		e.sendHist.generation++
		e.sendHistMu.Unlock()
	}()

	select {
	case e.sendSlots <- struct{}{}:
		goto frameReserved
	default:
		markWaiting()
	}
	for {
		deadline, deadlineWake, expired := e.writeDeadlineSnapshot()
		if expired {
			return ErrWriteDeadlineExceeded
		}
		timer, timerC := writeDeadlineTimer(deadline)
		select {
		case e.sendSlots <- struct{}{}:
			stopDeadlineTimer(timer)
			goto frameReserved
		case <-deadlineWake:
			stopDeadlineTimer(timer)
			markWaiting()
		case <-timerC:
			markWaiting()
		case <-e.closed:
			stopDeadlineTimer(timer)
			return net.ErrClosed
		}
	}

frameReserved:
	e.sendHistMu.Lock()
	if e.closing.Load() {
		e.sendHistMu.Unlock()
		select {
		case <-e.sendSlots:
		default:
		}
		return net.ErrClosed
	}
	e.sendHist.reservedFrames++
	if e.sendHist.reservedFrames > e.sendHist.frameHighWater {
		e.sendHist.frameHighWater = e.sendHist.reservedFrames
	}
	e.sendHist.generation++
	e.sendHistMu.Unlock()

	for {
		e.sendHistMu.Lock()
		if e.closing.Load() {
			e.sendHistMu.Unlock()
			e.abandonApplicationSendReservation()
			return net.ErrClosed
		}
		if e.sendHist.reservedBytes <= sendHistoryByteLimit-frameBytes {
			e.sendHist.reservedBytes += frameBytes
			if e.sendHist.reservedBytes > e.sendHist.byteHighWater {
				e.sendHist.byteHighWater = e.sendHist.reservedBytes
			}
			e.sendHist.generation++
			e.sendHistMu.Unlock()
			return nil
		}
		creditWake := e.sendCreditWake
		e.sendHistMu.Unlock()
		markWaiting()

		deadline, deadlineWake, expired := e.writeDeadlineSnapshot()
		if expired {
			e.abandonApplicationSendReservation()
			return ErrWriteDeadlineExceeded
		}
		timer, timerC := writeDeadlineTimer(deadline)
		select {
		case <-creditWake:
			stopDeadlineTimer(timer)
		case <-deadlineWake:
			stopDeadlineTimer(timer)
		case <-timerC:
		case <-e.closed:
			stopDeadlineTimer(timer)
			e.abandonApplicationSendReservation()
			return net.ErrClosed
		}
	}
}

func (e *Engine) abandonApplicationSendReservation() {
	e.sendHistMu.Lock()
	closing := e.closing.Load()
	if e.sendHist.reservedFrames > 0 {
		e.sendHist.reservedFrames--
		e.sendHist.generation++
	} else if !closing {
		e.sendHistMu.Unlock()
		panic("engine: missing application replay frame reservation")
	}
	e.sendHistMu.Unlock()
	select {
	case <-e.sendSlots:
	default:
		if !closing {
			panic("engine: missing application replay frame token")
		}
	}
}

func (e *Engine) sendApplicationDataFrameDirect(payload []byte, runtime *executionRuntime) (bool, error) {
	if runtime == nil {
		return false, errExecutionRuntimeNotConfigured
	}
	if e.sendClosing.Load() {
		return false, net.ErrClosed
	}
	if e.sendWriteClosed.Load() {
		return false, io.ErrClosedPipe
	}
	frameBytes := e.applicationWireFrameBytes(len(payload))
	if err := e.acquireApplicationSendSlot(frameBytes); err != nil {
		return false, err
	}
	if err := e.sendMu.lockApplication(e); err != nil {
		e.releaseSendSlot(false, frameBytes)
		return false, err
	}
	sendLocked := true
	defer func() {
		if sendLocked {
			e.sendMu.Unlock()
		}
	}()
	if e.isClosed() || e.sendClosing.Load() {
		e.releaseSendSlot(false, frameBytes)
		return false, net.ErrClosed
	}
	if e.sendWriteClosed.Load() {
		e.releaseSendSlot(false, frameBytes)
		return false, io.ErrClosedPipe
	}

	e.writeDeadlineMu.Lock()
	if e.isClosed() || e.sendClosing.Load() {
		e.writeDeadlineMu.Unlock()
		e.releaseSendSlot(false, frameBytes)
		return false, net.ErrClosed
	}
	if e.sendWriteClosed.Load() {
		e.writeDeadlineMu.Unlock()
		e.releaseSendSlot(false, frameBytes)
		return false, io.ErrClosedPipe
	}
	if writeDeadlineExceeded(e.writeDeadlineLocked()) {
		e.writeDeadlineMu.Unlock()
		e.releaseSendSlot(false, frameBytes)
		return false, ErrWriteDeadlineExceeded
	}
	frame, err := e.buildAndPublishApplicationDataFrame(payload, runtime)
	e.writeDeadlineMu.Unlock()
	if err != nil {
		e.releaseSendSlot(false, frameBytes)
		return false, err
	}
	// The sequencer protects immutable publication, not physical carrier
	// latency. appWritePermit still orders stream calls, while the replay
	// ledger and receiver SEQ reorder preserve wire order if a later control
	// frame overtakes this DATA on a congested path. Releasing here lets policy
	// and recovery controls preempt a blocked DATA dispatch.
	if hook := e.applicationDataBeforeDetachedCustody; hook != nil {
		hook()
	}
	custodyTicket := e.beginDetachedStreamDispatch()
	e.sendMu.Unlock()
	sendLocked = false
	defer e.completeDetachedStreamDispatch(custodyTicket)
	dispatchErr := e.dispatchDetachedStreamApplication(
		frame, runtime, true, custodyTicket,
	)
	if errors.Is(dispatchErr, errSelectorCutoverHandoff) {
		dispatchErr = nil
	}
	if dispatchErr == nil {
		hdr, decodeErr := proto.DecodeHeader(frame[:proto.HeaderSize])
		if decodeErr == nil {
			e.armTailReplayForFrame(frame, hdr.Seq+1)
		}
	}
	return true, dispatchErr
}

// sendPacketDataFrameConcurrent preserves one linearized sequence/ledger/queue
// publication under sendMu, then releases the sequencer while this caller waits
// for its own physical result. net.PacketConn permits concurrent writers, and
// the bounded replay and dispatch queues retain ownership if a carrier fails.
// Stream writes keep their application-wide permit because their byte-call
// ordering and partial-write semantics are different.
func (e *Engine) sendPacketDataFrameConcurrent(payload []byte, runtime *executionRuntime, acceptQueued bool) (bool, error) {
	if runtime == nil {
		return false, errExecutionRuntimeNotConfigured
	}
	if e.sendClosing.Load() {
		return false, net.ErrClosed
	}
	if e.sendWriteClosed.Load() {
		return false, io.ErrClosedPipe
	}
	e.packetWritesInFlight.Add(1)
	defer e.packetWritesInFlight.Add(-1)
	frameBytes := e.applicationWireFrameBytes(len(payload))
	if err := e.acquireApplicationSendSlot(frameBytes); err != nil {
		return false, err
	}
	if err := e.sendMu.lockApplication(e); err != nil {
		e.releaseSendSlot(false, frameBytes)
		return false, err
	}
	sendLocked := true
	defer func() {
		if sendLocked {
			e.sendMu.Unlock()
		}
	}()
	if e.isClosed() || e.sendClosing.Load() {
		e.releaseSendSlot(false, frameBytes)
		return false, net.ErrClosed
	}
	if e.sendWriteClosed.Load() {
		e.releaseSendSlot(false, frameBytes)
		return false, io.ErrClosedPipe
	}

	e.writeDeadlineMu.Lock()
	if e.isClosed() || e.sendClosing.Load() {
		e.writeDeadlineMu.Unlock()
		e.releaseSendSlot(false, frameBytes)
		return false, net.ErrClosed
	}
	if e.sendWriteClosed.Load() {
		e.writeDeadlineMu.Unlock()
		e.releaseSendSlot(false, frameBytes)
		return false, io.ErrClosedPipe
	}
	if writeDeadlineExceeded(e.writeDeadlineLocked()) {
		e.writeDeadlineMu.Unlock()
		e.releaseSendSlot(false, frameBytes)
		return false, ErrWriteDeadlineExceeded
	}
	deadlineAtPublication := e.writeDeadlineLocked()
	frame, err := e.buildAndPublishApplicationDataFrame(payload, runtime)
	if err != nil {
		e.writeDeadlineMu.Unlock()
		e.releaseSendSlot(false, frameBytes)
		return false, err
	}
	if acceptQueued && deadlineAtPublication.IsZero() {
		handled, acceptErr := e.acceptFlatSelectorPacketDispatch(frame, runtime, true)
		if handled {
			target := e.sendPublishedNext.Load()
			e.armTailReplayForFrame(frame, target)
			e.writeDeadlineMu.Unlock()
			e.sendMu.Unlock()
			sendLocked = false
			if errors.Is(acceptErr, errSelectorCutoverHandoff) {
				acceptErr = nil
			}
			return true, acceptErr
		}
	}
	e.writeDeadlineMu.Unlock()

	var dispatchErr error
	if runtime != nil {
		dispatch, handled, startErr := e.startFlatSelectorPacketDispatch(
			frame, runtime, true, nowFn().Add(e.limits.MigrationBudget),
		)
		if handled {
			e.sendMu.Unlock()
			sendLocked = false
			dispatchErr = startErr
			if dispatchErr == nil {
				dispatchErr = e.waitFlatSelectorPacketDispatch(dispatch)
			}
			if errors.Is(dispatchErr, errFlatSelectorPacketRedispatch) {
				if lockErr := e.sendMu.lockApplication(e); lockErr != nil {
					dispatchErr = lockErr
				} else {
					sendLocked = true
					dispatchErr = e.dispatchRecursiveApplication(frame, runtime, true)
				}
			}
		} else {
			dispatchErr = e.dispatchRecursiveApplication(frame, runtime, true)
		}
	} else {
		dispatchErr = e.dispatch(frame, true)
	}
	if errors.Is(dispatchErr, errSelectorCutoverHandoff) {
		dispatchErr = nil
	}
	if dispatchErr == nil {
		hdr, decodeErr := proto.DecodeHeader(frame[:proto.HeaderSize])
		if decodeErr == nil {
			e.armTailReplayForFrame(frame, hdr.Seq+1)
		}
	}
	return true, dispatchErr
}

func stopDeadlineTimer(timer *time.Timer) {
	if timer == nil {
		return
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

func (e *Engine) releaseApplicationWritePermit() {
	select {
	case e.appWritePermit <- struct{}{}:
	default:
		panic("engine: application write permit invariant violated")
	}
}

// buildAndPublishApplicationDataFrame is called with sendMu and
// writeDeadlineMu held. It performs no network I/O.
func (e *Engine) buildAndPublishApplicationDataFrame(payload []byte, runtime *executionRuntime) ([]byte, error) {
	flags, wirePayload, attribution, err := e.encodeApplicationPayload(payload, runtime)
	if err != nil {
		return nil, err
	}
	seq, err := e.allocateSendSequence(false)
	if err != nil {
		e.beginSequenceExhaustionClose()
		return nil, err
	}
	frame := make([]byte, proto.HeaderSize+len(wirePayload))
	header := proto.Header{Version: proto.Version, Type: proto.FrameData, Flags: flags, Seq: seq}
	if err := header.Encode(frame[:proto.HeaderSize]); err != nil {
		return nil, err
	}
	copy(frame[proto.HeaderSize:], wirePayload)
	if err := e.reserveAndPublishOwnedApplicationFrame(frame, attribution, len(payload)); err != nil {
		return nil, err
	}
	return frame, nil
}
