package engine

import (
	"errors"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/proto"
)

// SendData splits buf into ≤MaxPayload frames, assigns SEQ, encodes
// them, and writes to the currently-active path. It blocks while the
// engine is in BridgeMigrating, but never returns a migration-class
// error to the caller (hard rule #1). Migration-budget exhaustion
// returns rendr.ErrMigrationBudgetExceeded.
func (e *Engine) SendData(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if e.sendWriteClosed.Load() {
		return 0, io.ErrClosedPipe
	}
	runtime, err := e.requireLocalExecutionRuntime()
	if err != nil {
		return 0, err
	}
	if err := e.acquireApplicationWritePermit(); err != nil {
		return 0, err
	}
	defer e.releaseApplicationWritePermit()
	sent := 0
	for sent < len(buf) {
		end := sent + MaxPayload
		if end > len(buf) {
			end = len(buf)
		}
		chunk := buf[sent:end]
		published, err := e.sendApplicationDataFrameDirect(chunk, runtime)
		if published {
			sent = end
		}
		if err != nil {
			return sent, err
		}
	}
	return sent, nil
}

// SendStreamFin closes only the local stream write direction. The FIN shares
// the DATA sequencer and replay ledger, so the peer cannot observe EOF before
// every preceding byte. The reverse stream remains usable until full Close.
func (e *Engine) SendStreamFin() error {
	if e.packetized {
		return ErrStreamHalfCloseUnsupported
	}
	if _, err := e.requireLocalExecutionRuntime(); err != nil {
		return err
	}
	e.streamFinOnce.Do(func() {
		e.sendWriteClosed.Store(true)
		e.streamFinErr = e.sendFrame(proto.FrameCtrl, proto.FlagsForCtrl(proto.CtrlStreamFin), nil)
		close(e.streamFinDone)
	})
	<-e.streamFinDone
	return e.streamFinErr
}

// SendPacket emits exactly one DATA frame carrying buf as payload.
// Returns ErrPacketTooLarge if buf plus the session DATA envelope exceeds
// either MaxPayload or the tightest admitted path frame budget. Unlike
// SendData, this never fragments: packet-boundary semantics require the
// receiver see the same byte boundary the sender drew. Zero-length buf is
// legal and produces a zero-payload DATA frame (keepalive shape).
//
// Hard rule #1 still applies: a migration in flight blocks SendPacket
// but never surfaces a migration-class error.
func (e *Engine) SendPacket(buf []byte) error {
	_, err := e.SendPacketResult(buf)
	return err
}

// SendPacketResult reports whether the complete datagram entered the replay
// ledger before an error. It lets net.PacketConn preserve atomic n semantics:
// callers observe either zero or the complete datagram length, never a prefix.
func (e *Engine) SendPacketResult(buf []byte) (bool, error) {
	if err := e.validatePacketPayloadSize(len(buf)); err != nil {
		return false, err
	}
	if e.sendWriteClosed.Load() {
		return false, io.ErrClosedPipe
	}
	runtime, err := e.requireLocalExecutionRuntime()
	if err != nil {
		return false, err
	}
	return e.sendPacketDataFrameConcurrent(buf, runtime, false)
}

// SendPacketAcceptedResult is the net.PacketConn send path. When a flat
// selector's active transport supports whole-frame batching and no write
// deadline is installed, success means the immutable datagram entered the
// engine's bounded replay and path-dispatch custody. Peer ACK, not local queue
// admission, releases that custody. Other graph shapes and deadline-bearing
// writes retain synchronous physical-dispatch semantics.
func (e *Engine) SendPacketAcceptedResult(buf []byte) (bool, error) {
	if err := e.validatePacketPayloadSize(len(buf)); err != nil {
		return false, err
	}
	if e.sendWriteClosed.Load() {
		return false, io.ErrClosedPipe
	}
	runtime, err := e.requireLocalExecutionRuntime()
	if err != nil {
		return false, err
	}
	return e.sendPacketDataFrameConcurrent(buf, runtime, true)
}

// SendBye emits the final sequenced frame. It shares the same sequencer as
// DATA so a concurrent successful Write is always ordered before the final
// sequence number and the receiver cannot observe an early clean EOF.
func (e *Engine) SendBye(reason proto.ByeReason) error {
	if _, err := e.requireLocalExecutionRuntime(); err != nil {
		return err
	}
	e.sessionEpochMu.Lock()
	e.policyLifecycleMu.Lock()
	e.policyStateMu.Lock()
	e.sendClosing.Store(true)
	e.policyStateMu.Unlock()
	e.policyLifecycleMu.Unlock()
	e.sessionEpochMu.Unlock()
	e.terminalOnce.Do(func() {
		e.terminalErr = e.sendTerminalFrame(reason)
		close(e.terminalDone)
	})
	<-e.terminalDone
	return e.terminalErr
}

// sendFrame builds a single rendr frame and pushes it on the active
// path. Frame type may be Data or Ctrl; for Ctrl, flags encodes the
// CtrlCode in its low 8 bits.
func (e *Engine) sendFrame(t proto.FrameType, flags uint16, payload []byte) error {
	_, err := e.sendFrameTracked(t, flags, payload)
	return err
}

// sendFrameTracked publishes one new sequenced frame and returns the exact
// immutable bytes owned by the replay ledger. Transaction retries can
// redispatch these bytes without allocating another SEQ or control slot.
func (e *Engine) sendFrameTracked(t proto.FrameType, flags uint16, payload []byte) ([]byte, error) {
	return e.sendFrameTrackedMode(t, flags, payload, false)
}

// sendFrameTrackedDetached publishes a sequenced frame under sendMu, then
// releases the sequencer before waiting for physical dispatch. It is reserved
// for controls whose caller treats replay-ledger custody as acceptance. Other
// protocol transactions keep synchronous sendMu ownership through dispatch.
func (e *Engine) sendFrameTrackedDetached(t proto.FrameType, flags uint16, payload []byte) ([]byte, error) {
	return e.sendFrameTrackedMode(t, flags, payload, true)
}

func (e *Engine) sendFrameTrackedMode(t proto.FrameType, flags uint16, payload []byte, detached bool) ([]byte, error) {
	if e.sendClosing.Load() {
		return nil, net.ErrClosed
	}
	if t == proto.FrameData && e.sendWriteClosed.Load() {
		return nil, io.ErrClosedPipe
	}
	if _, err := e.requireLocalExecutionRuntime(); err != nil {
		return nil, err
	}
	control := t == proto.FrameCtrl
	frameBytes := proto.HeaderSize + len(payload)
	if err := e.acquireSendSlot(control, frameBytes); err != nil {
		return nil, err
	}
	e.sendMu.Lock()
	sendLocked := true
	defer func() {
		if sendLocked {
			e.sendMu.Unlock()
		}
	}()

	frame, seq, err := e.publishTrackedFrameLocked(t, flags, payload, frameBytes)
	if err != nil {
		return nil, err
	}
	if detached {
		e.sendMu.Unlock()
		sendLocked = false
	}
	// Publication means the SEQ has a replay owner and may now be observed by
	// any path. Advancing before dispatch lets a fast race child ACK while a
	// slower sibling is still inside Write without having that ACK rejected.
	err = e.dispatchTrackedFrame(frame, seq)
	return frame, err
}

// sendFrameTrackedPreemptingReplay publishes a control frame that must make
// progress even when a selector cutover is synchronously replaying DATA on a
// blocked carrier. The temporary cutover wakes that replay and transfers its
// immutable prefix back to the ledger. Once this goroutine owns sendMu it
// closes the cutover and publishes the control before bounded replay resumes.
func (e *Engine) sendFrameTrackedPreemptingReplay(t proto.FrameType, flags uint16, payload []byte) ([]byte, error) {
	if t != proto.FrameCtrl {
		return nil, errors.New("engine: only control frames may preempt replay")
	}
	if e.sendClosing.Load() {
		return nil, net.ErrClosed
	}
	if _, err := e.requireLocalExecutionRuntime(); err != nil {
		return nil, err
	}
	frameBytes := proto.HeaderSize + len(payload)
	if err := e.acquireSendSlot(true, frameBytes); err != nil {
		return nil, err
	}

	cutoverGeneration := e.beginSelectorCutover()
	e.sendMu.Lock()
	handedOff := e.selectorCutoverDidHandoff(cutoverGeneration)
	replayTarget := e.sendPublishedNext.Load()
	e.finishSelectorCutover(cutoverGeneration)

	frame, seq, err := e.publishTrackedFrameLocked(t, flags, payload, frameBytes)
	if err == nil {
		err = e.dispatchTrackedReplayPreemptingControl(frame, seq)
	}
	e.sendMu.Unlock()

	if handedOff {
		e.requestReplayRange(e.sendAckNext.Load(), replayTarget)
	}
	return frame, err
}

// publishTrackedFrameLocked allocates one sequence and transfers the complete
// immutable frame into replay-ledger custody. The caller owns sendMu and has
// already reserved the matching send slot.
func (e *Engine) publishTrackedFrameLocked(t proto.FrameType, flags uint16, payload []byte, frameBytes int) ([]byte, uint64, error) {
	control := t == proto.FrameCtrl
	if e.isClosed() || e.sendClosing.Load() {
		e.releaseSendSlot(control, frameBytes)
		return nil, 0, net.ErrClosed
	}
	if t == proto.FrameData && e.sendWriteClosed.Load() {
		e.releaseSendSlot(control, frameBytes)
		return nil, 0, io.ErrClosedPipe
	}

	seq, err := e.allocateSendSequence(false)
	if err != nil {
		e.releaseSendSlot(control, frameBytes)
		e.beginSequenceExhaustionClose()
		return nil, 0, err
	}
	hdr := proto.Header{
		Version: proto.Version,
		Type:    t,
		Flags:   flags,
		Seq:     seq,
	}
	frame := make([]byte, proto.HeaderSize+len(payload))
	if err := hdr.Encode(frame[:proto.HeaderSize]); err != nil {
		e.releaseSendSlot(control, frameBytes)
		return nil, 0, err
	}
	copy(frame[proto.HeaderSize:], payload)

	if err := e.reserveAndPublishOwnedSendFrame(frame); err != nil {
		e.releaseSendSlot(control, frameBytes)
		return nil, 0, err
	}
	return frame, seq, nil
}

func (e *Engine) dispatchTrackedFrame(frame []byte, seq uint64) error {
	err := e.dispatch(frame, true)
	return e.finishTrackedFrameDispatch(frame, seq, err)
}

func (e *Engine) dispatchTrackedReplayPreemptingControl(frame []byte, seq uint64) error {
	runtime := e.localExecutionRuntime()
	if runtime == nil {
		return errExecutionRuntimeNotConfigured
	}
	err := e.dispatchRecursiveReplayPreemptingControl(frame, runtime)
	return e.finishTrackedFrameDispatch(frame, seq, err)
}

func (e *Engine) finishTrackedFrameDispatch(frame []byte, seq uint64, err error) error {
	if errors.Is(err, errSelectorCutoverHandoff) {
		err = nil
	}
	if err == nil {
		e.armTailReplayForFrame(frame, seq+1)
	}
	return err
}

func (e *Engine) replaySequencedFrame(frame []byte) error {
	if len(frame) < proto.HeaderSize {
		return proto.ErrBadHeader
	}
	e.sendMu.Lock()
	defer e.sendMu.Unlock()
	// sendClosing seals the sequencer against new publications, but already
	// published immutable ledger entries remain replayable until physical close.
	if e.isClosed() {
		return net.ErrClosed
	}
	return e.dispatchReplayFrameLocked(frame)
}

func (e *Engine) dispatchReplayFrameLocked(frame []byte) error {
	return e.dispatch(frame, false)
}

func (e *Engine) sendTerminalFrame(reason proto.ByeReason) error {
	if _, err := e.requireLocalExecutionRuntime(); err != nil {
		return err
	}
	e.sendMu.Lock()
	defer e.sendMu.Unlock()
	if e.isClosed() {
		return net.ErrClosed
	}
	seq, err := e.allocateSendSequence(true)
	if err != nil {
		e.setCloseErr(err)
		return err
	}
	payload := proto.ByePayload{Reason: reason}.Encode()
	hdr := proto.Header{
		Version: proto.Version,
		Type:    proto.FrameCtrl,
		Flags:   proto.FlagsForCtrl(proto.CtrlBye),
		Seq:     seq,
	}
	frame := make([]byte, proto.HeaderSize+len(payload))
	if err := hdr.Encode(frame[:proto.HeaderSize]); err != nil {
		return err
	}
	copy(frame[proto.HeaderSize:], payload)
	if err := e.reserveAndPublishOwnedTerminalFrame(frame); err != nil {
		return err
	}
	err = e.dispatch(frame, true)
	if errors.Is(err, errSelectorCutoverHandoff) {
		err = nil
	}
	if err == nil {
		e.armTailReplayForFrame(frame, seq+1)
	}
	return err
}

// allocateSendSequence is called only while sendMu is held. MaxSeq is
// reserved for the unique terminal BYE so every ordinary DATA/CTRL exhaustion
// has one representable clean-close frame left.
func (e *Engine) allocateSendSequence(terminal bool) (uint64, error) {
	next := atomic.LoadUint64(&e.sendSeq)
	limit := proto.MaxSeq - 1
	if terminal {
		limit = proto.MaxSeq
	}
	if next > limit {
		return 0, ErrSequenceExhausted
	}
	atomic.StoreUint64(&e.sendSeq, next+1)
	return next, nil
}

func (e *Engine) beginSequenceExhaustionClose() {
	e.sequenceExhaustOnce.Do(func() {
		e.setCloseErr(ErrSequenceExhausted)
		// Publish the no-new-work boundary before releasing sendMu. The
		// terminal allocator is deliberately independent of sendClosing and can
		// still consume the reserved final sequence from GracefulClose.
		e.BeginGracefulClose()
		go func() { _ = e.GracefulClose(proto.ByeNormal) }()
	})
}

func (e *Engine) publishSendSeq(next uint64) {
	e.sendHistMu.Lock()
	e.publishSendSeqLocked(next)
	e.sendHistMu.Unlock()
}

func (e *Engine) publishSendSeqLocked(next uint64) {
	current := e.sendPublishedNext.Load()
	if next > current {
		if next == 0 {
			panic("engine: zero sequenced publication frontier")
		}
		entry := e.sendHistoryEntryLocked(next - 1)
		if entry == nil {
			panic("engine: sequenced publication is missing its replay owner")
		}
		e.publishRootAttributionLocked(entry)
		e.sendPublishedNext.Store(next)
		e.sendHist.generation++
	}
}

// dispatch writes one immutable frame through the configured recursive target
// graph. There is no flat mode fallback: an engine without a runtime cannot
// infer target ownership from physical path IDs.
func (e *Engine) dispatch(frame []byte, firstPublication bool) error {
	runtime := e.localExecutionRuntime()
	if runtime == nil {
		return errExecutionRuntimeNotConfigured
	}
	return e.dispatchRecursive(frame, runtime, firstPublication)
}

func (e *Engine) redistributeFrames(frames [][]byte) error {
	if len(frames) == 0 || e.isClosed() {
		return nil
	}
	e.sendMu.Lock()
	defer e.sendMu.Unlock()
	return e.redistributeFramesLocked(frames)
}

func (e *Engine) redistributeFramesLocked(frames [][]byte) error {
	for _, frame := range frames {
		if e.isClosed() {
			return net.ErrClosed
		}
		if err := e.dispatchReplayFrameLocked(frame); err != nil {
			return err
		}
	}
	return nil
}

type replayRequestKind uint8

const (
	replayRequestFull replayRequestKind = iota + 1
	replayRequestBounded
	replayRequestGap
)

type replayRequest struct {
	nextSeq uint64
	target  uint64
	kind    replayRequestKind
}

func (e *Engine) requestReplay(nextSeq uint64) {
	e.queueReplay(replayRequest{nextSeq: nextSeq, kind: replayRequestFull})
}

func (e *Engine) requestReplayRange(nextSeq, target uint64) {
	if target <= nextSeq {
		return
	}
	e.queueReplay(replayRequest{nextSeq: nextSeq, target: target, kind: replayRequestBounded})
}

func (e *Engine) requestGapReplay(nextSeq uint64) {
	request := replayRequest{
		nextSeq: nextSeq,
		target:  e.sendPublishedNext.Load(),
		kind:    replayRequestGap,
	}
	if request.target <= request.nextSeq {
		return
	}
	e.queueReplay(request)
}

func (e *Engine) queueReplay(request replayRequest) {
	e.replayMu.Lock()
	if !e.replayPendingSet {
		e.replayPending = request
		e.replayPendingSet = true
	} else {
		pending := e.replayPending
		switch {
		case pending.kind == replayRequestFull:
			if request.nextSeq < pending.nextSeq {
				pending.nextSeq = request.nextSeq
			}
		case request.kind == replayRequestFull:
			if pending.nextSeq < request.nextSeq {
				request.nextSeq = pending.nextSeq
			}
			pending = request
		case pending.kind == replayRequestBounded || request.kind == replayRequestBounded:
			if request.nextSeq < pending.nextSeq {
				pending.nextSeq = request.nextSeq
			}
			if request.target > pending.target {
				pending.target = request.target
			}
			pending.kind = replayRequestBounded
		default: // two cumulative-gap requests
			if request.nextSeq < pending.nextSeq {
				pending.nextSeq = request.nextSeq
			}
			if request.target > pending.target {
				pending.target = request.target
			}
		}
		e.replayPending = pending
	}
	e.replayMu.Unlock()
	select {
	case e.replayWake <- struct{}{}:
	default:
	}
}

func (e *Engine) takeReplayRequest() (replayRequest, bool) {
	e.replayMu.Lock()
	defer e.replayMu.Unlock()
	if !e.replayPendingSet {
		return replayRequest{}, false
	}
	request := e.replayPending
	e.replayPending = replayRequest{}
	e.replayPendingSet = false
	return request, true
}

func (e *Engine) replayAckState() (nextSeq uint64, gap bool, seen bool, version uint64) {
	e.replayMu.Lock()
	defer e.replayMu.Unlock()
	return e.replayAckNext, e.replayAckGap, e.replayAckSeen, e.replayAckVersion
}

// publishReplayAck serializes ACK observations from independent path readers.
// NextSeq never regresses. At the same frontier, Gap=true dominates because a
// delayed no-gap ACK may predate the out-of-order frame that revealed the gap;
// without a wire ACK generation, clearing it would be unsafe. Advancing the
// cumulative frontier starts a new gap state.
func (e *Engine) publishReplayAck(nextSeq uint64, gap bool) bool {
	e.replayMu.Lock()
	defer e.replayMu.Unlock()
	if e.replayAckSeen {
		switch {
		case nextSeq < e.replayAckNext:
			return false
		case nextSeq == e.replayAckNext:
			if e.replayAckGap || !gap {
				return false
			}
		}
	}
	e.replayAckNext = nextSeq
	e.replayAckGap = gap
	e.replayAckSeen = true
	e.replayAckVersion++
	return true
}

func (e *Engine) fullReplayPending() bool {
	e.replayMu.Lock()
	defer e.replayMu.Unlock()
	return e.replayPendingSet && e.replayPending.kind != replayRequestGap
}

func (e *Engine) replayLoop() {
	var timer *time.Timer
	stopTimer := func() {
		if timer == nil || timer.Stop() {
			return
		}
		select {
		case <-timer.C:
		default:
		}
	}
	defer stopTimer()

	for {
		if request, ok := e.takeReplayRequest(); ok {
			switch request.kind {
			case replayRequestGap:
				e.replayGapUntilAcknowledged(request.nextSeq, request.target)
			case replayRequestBounded:
				e.replayRangeUntilSent(request.nextSeq, request.target)
			case replayRequestFull:
				e.replayUntilSent(request.nextSeq)
			}
			continue
		}

		var timerC <-chan time.Time
		if due, armed := e.tailReplayDue(nowFn()); armed {
			wait := due.Sub(nowFn())
			if wait < 0 {
				wait = 0
			}
			stopTimer()
			if timer == nil {
				timer = time.NewTimer(wait)
			} else {
				timer.Reset(wait)
			}
			timerC = timer.C
		} else {
			stopTimer()
		}

		select {
		case <-e.closed:
			return
		case <-e.replayWake:
		case <-timerC:
			if target, ok := e.takeTailReplayAttempt(nowFn()); ok {
				e.replayTailFrame(target)
			}
		}
	}
}

func (e *Engine) replayRangeUntilSent(nextSeq, target uint64) {
	backoff := 10 * time.Millisecond
	for nextSeq < target {
		if acked := e.sendAckNext.Load(); nextSeq < acked {
			nextSeq = acked
		}
		if nextSeq >= target {
			return
		}
		if hook := e.boundedReplayBeforeSnapshot; hook != nil {
			hook()
		}
		frames := e.sendHistoryRange(nextSeq, target)
		if len(frames) == 0 {
			return
		}
		if e.ActivePath() != 0 {
			if err := e.redistributeFrames(frames); err == nil {
				if target == e.sendPublishedNext.Load() {
					e.armTailReplayForFrame(frames[len(frames)-1], target)
				}
				return
			}
		}
		timer := time.NewTimer(backoff)
		select {
		case <-e.closed:
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}
		if backoff < 200*time.Millisecond {
			backoff *= 2
		}
	}
}

// replayRangeLocked writes a frozen prefix while the caller owns sendMu.
// Selector cutover uses this path so no newly published sequence can overtake
// the replay frontier on the replacement carrier.
func (e *Engine) replayRangeLocked(nextSeq, target uint64) error {
	if acked := e.sendAckNext.Load(); nextSeq < acked {
		nextSeq = acked
	}
	if nextSeq >= target {
		return nil
	}
	if hook := e.boundedReplayBeforeSnapshot; hook != nil {
		hook()
	}
	frames := e.sendHistoryRange(nextSeq, target)
	if len(frames) == 0 {
		return nil
	}
	if err := e.redistributeFramesLocked(frames); err != nil {
		return err
	}
	if target == e.sendPublishedNext.Load() {
		e.armTailReplayForFrame(frames[len(frames)-1], target)
	}
	return nil
}

// replayGapUntilAcknowledged repairs one cumulative gap at a time. Replaying
// the entire suffix on every transient cross-path reorder creates a replay
// storm; pacing at the ACK frontier lets already-buffered frames collapse the
// gap in one step while still walking every genuinely lost frame forward.
func (e *Engine) replayGapUntilAcknowledged(nextSeq, target uint64) {
	backoff := e.gapReplayBackoff
	if backoff <= 0 {
		backoff = 10 * time.Millisecond
	}
	frontier := nextSeq
	for frontier < target {
		if e.fullReplayPending() {
			return
		}
		acked, gap, seen, ackVersion := e.replayAckState()
		if seen && acked >= frontier && !gap {
			return
		}
		if acked > frontier {
			frontier = acked
			backoff = e.gapReplayBackoff
			if backoff <= 0 {
				backoff = 10 * time.Millisecond
			}
			if frontier >= target {
				return
			}
		}
		frame := e.sendHistoryFrame(frontier)
		if len(frame) == 0 {
			return
		}
		if e.ActivePath() != 0 {
			_ = e.replaySequencedFrame(frame)
		}

		timer := time.NewTimer(backoff)
	waitForProgress:
		for {
			select {
			case <-e.closed:
				if !timer.Stop() {
					<-timer.C
				}
				return
			case <-e.replayAckWake:
				_, _, _, currentVersion := e.replayAckState()
				if currentVersion <= ackVersion {
					// The wake may predate this replay attempt. It carries no
					// post-send progress and must not bypass backoff.
					continue
				}
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				break waitForProgress
			case <-e.replayWake:
				if e.fullReplayPending() {
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
					return
				}
				// A coalesced gap-only request does not prove progress. Keep
				// the existing timer so repeated gap ACKs cannot collapse the
				// exponential pacing into a replay storm.
			case <-timer.C:
				if backoff < 200*time.Millisecond {
					backoff *= 2
					if backoff > 200*time.Millisecond {
						backoff = 200 * time.Millisecond
					}
				}
				break waitForProgress
			}
		}
	}
}

func (e *Engine) replayUntilSent(nextSeq uint64) {
	backoff := 10 * time.Millisecond
	for {
		if acked := e.sendAckNext.Load(); nextSeq < acked {
			nextSeq = acked
		}
		frames := e.sendHistorySnapshot(nextSeq)
		if len(frames) == 0 {
			return
		}
		if e.ActivePath() != 0 {
			if err := e.redistributeFrames(frames); err == nil {
				if lastTarget, ok := sequencedFrameTarget(frames[len(frames)-1]); ok &&
					lastTarget == e.sendPublishedNext.Load() {
					e.armTailReplayForFrame(frames[len(frames)-1], lastTarget)
				}
				return
			}
		}
		timer := time.NewTimer(backoff)
		select {
		case <-e.closed:
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}
		if backoff < 200*time.Millisecond {
			backoff *= 2
		}
	}
}

func sequencedFrameTarget(frame []byte) (uint64, bool) {
	if len(frame) < proto.HeaderSize {
		return 0, false
	}
	hdr, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	if err != nil {
		return 0, false
	}
	return hdr.Seq + 1, true
}
