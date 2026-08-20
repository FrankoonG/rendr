package engine

import "errors"

var errSelectorCutoverHandoff = errors.New("engine: selector cutover owns published frame")

// beginSelectorCutover wakes a sequenced dispatch that is waiting on a
// physical writer. The frame is already in the replay ledger, so the selector
// can take sendMu and replay it after committing the new route.
func (e *Engine) beginSelectorCutover() uint64 {
	e.selectorCutoverMu.Lock()
	defer e.selectorCutoverMu.Unlock()
	for e.selectorCutoverPending {
		if hook := e.selectorCutoverBeforeWait; hook != nil {
			hook(e.selectorCutoverGeneration)
		}
		wake := e.selectorCutoverWake
		e.selectorCutoverMu.Unlock()
		select {
		case <-wake:
		case <-e.closed:
			e.selectorCutoverMu.Lock()
			return 0
		}
		e.selectorCutoverMu.Lock()
	}
	select {
	case <-e.closed:
		return 0
	default:
	}
	if e.selectorCutoverGeneration == ^uint64(0) {
		panic("engine: selector cutover generation exhausted")
	}
	e.selectorCutoverGeneration++
	e.selectorCutoverPending = true
	e.selectorCutoverHandedOff = e.claimUnownedDispatchCustodyLocked()
	e.selectorCutoverReplayRequired = e.selectorCutoverHandedOff
	close(e.selectorCutoverWake)
	e.selectorCutoverWake = make(chan struct{})
	return e.selectorCutoverGeneration
}

func (e *Engine) finishSelectorCutover(generation uint64) {
	e.selectorCutoverMu.Lock()
	defer e.selectorCutoverMu.Unlock()
	if !e.selectorCutoverPending || e.selectorCutoverGeneration != generation {
		return
	}
	e.selectorCutoverPending = false
	e.selectorCutoverHandedOff = false
	e.selectorCutoverReplayRequired = false
	close(e.selectorCutoverWake)
	e.selectorCutoverWake = make(chan struct{})
}

func (e *Engine) selectorCutoverSnapshot() (bool, <-chan struct{}) {
	generation, wake := e.selectorCutoverDispatchSnapshot()
	return generation != 0, wake
}

func (e *Engine) selectorCutoverDispatchSnapshot() (uint64, <-chan struct{}) {
	e.selectorCutoverMu.Lock()
	defer e.selectorCutoverMu.Unlock()
	if !e.selectorCutoverPending {
		return 0, e.selectorCutoverWake
	}
	return e.selectorCutoverGeneration, e.selectorCutoverWake
}

func (e *Engine) handoffSelectorCutoverDispatch(generation uint64, replayOwned bool) bool {
	e.selectorCutoverMu.Lock()
	defer e.selectorCutoverMu.Unlock()
	if generation == 0 || !e.selectorCutoverPending ||
		e.selectorCutoverGeneration != generation {
		return false
	}
	e.selectorCutoverHandedOff = true
	if !replayOwned {
		e.selectorCutoverReplayRequired = true
	}
	return true
}

func (e *Engine) selectorCutoverDidHandoff(generation uint64) bool {
	e.selectorCutoverMu.Lock()
	defer e.selectorCutoverMu.Unlock()
	return generation != 0 && e.selectorCutoverPending &&
		e.selectorCutoverGeneration == generation && e.selectorCutoverHandedOff
}

func (e *Engine) selectorCutoverRequiresReplay(generation uint64) bool {
	e.selectorCutoverMu.Lock()
	defer e.selectorCutoverMu.Unlock()
	return generation != 0 && e.selectorCutoverPending &&
		e.selectorCutoverGeneration == generation && e.selectorCutoverReplayRequired
}

// finishSelectorCutoverWithReplay closes one policy cutover before its FINAL
// control frame is published. A rejected transaction can still own a frame
// handed off by an in-flight dispatcher; replay that prefix under sendMu so
// FINAL cannot overtake it on the unchanged route.
func (e *Engine) finishSelectorCutoverWithReplay(generation uint64) {
	if generation == 0 {
		return
	}
	e.sendMu.Lock()
	defer e.sendMu.Unlock()
	handedOff := e.selectorCutoverDidHandoff(generation)
	replayRequired := handedOff && e.selectorCutoverRequiresReplay(generation)
	replayTarget := e.sendPublishedNext.Load()
	e.finishSelectorCutover(generation)
	if !replayRequired {
		return
	}
	if err := e.replayRangeLocked(e.sendAckNext.Load(), replayTarget); err != nil {
		e.requestReplayRange(e.sendAckNext.Load(), replayTarget)
	}
}

func (e *Engine) selectorCutoverGenerationPending(generation uint64) bool {
	e.selectorCutoverMu.Lock()
	defer e.selectorCutoverMu.Unlock()
	return generation != 0 && e.selectorCutoverPending &&
		e.selectorCutoverGeneration == generation
}

// finishSelectorCutoverForControl releases a cutover that will not publish a
// successful FINAL inside the existing lease. It freezes publication and
// detached-dispatch custody under sendMu before ending the exact generation.
func (e *Engine) finishSelectorCutoverForControl(generation uint64) {
	if generation == 0 {
		return
	}
	if !e.selectorCutoverGenerationPending(generation) {
		return
	}
	e.sendMu.Lock()
	defer e.sendMu.Unlock()
	if !e.selectorCutoverGenerationPending(generation) {
		return
	}
	handedOff := e.selectorCutoverDidHandoff(generation)
	replayRequired := handedOff && e.selectorCutoverRequiresReplay(generation)
	replayTarget := e.sendPublishedNext.Load()
	e.finishSelectorCutover(generation)
	if replayRequired {
		e.requestReplayRange(e.sendAckNext.Load(), replayTarget)
	}
}

func (e *Engine) nextDispatchCustodyTicketLocked() uint64 {
	if e.dispatchTicketIssued == ^uint64(0) {
		panic("engine: dispatch custody ticket exhausted")
	}
	return e.dispatchTicketIssued + 1
}

func (e *Engine) admitAcceptedPacketDispatchLocked(ticket uint64) {
	e.admitDispatchCustodyLocked(ticket)
	e.acceptedPacketDispatches++
}

func (e *Engine) completeAcceptedPacketDispatch(ticket uint64) {
	e.selectorCutoverMu.Lock()
	defer e.selectorCutoverMu.Unlock()
	if e.acceptedPacketDispatches == 0 {
		panic("engine: accepted packet dispatch completed without custody")
	}
	e.acceptedPacketDispatches--
	e.completeDispatchCustodyLocked(ticket)
}

func (e *Engine) beginDetachedStreamDispatch() uint64 {
	e.selectorCutoverMu.Lock()
	defer e.selectorCutoverMu.Unlock()
	ticket := e.nextDispatchCustodyTicketLocked()
	e.admitDispatchCustodyLocked(ticket)
	e.detachedStreamDispatches++
	return ticket
}

func (e *Engine) completeDetachedStreamDispatch(ticket uint64) {
	e.selectorCutoverMu.Lock()
	defer e.selectorCutoverMu.Unlock()
	if e.detachedStreamDispatches == 0 {
		panic("engine: detached stream dispatch completed without custody")
	}
	e.detachedStreamDispatches--
	e.completeDispatchCustodyLocked(ticket)
}

func (e *Engine) detachedStreamDispatchHandedOff(ticket uint64) bool {
	e.selectorCutoverMu.Lock()
	handedOff := ticket != 0 && ticket <= e.dispatchTicketClaimedThrough
	e.selectorCutoverMu.Unlock()
	return handedOff
}

func (e *Engine) handoffDetachedStreamDispatchesForReplay() {
	e.selectorCutoverMu.Lock()
	defer e.selectorCutoverMu.Unlock()
	e.claimUnownedDispatchCustodyLocked()
}

func (e *Engine) admitDispatchCustodyLocked(ticket uint64) {
	if ticket == 0 || ticket != e.dispatchTicketIssued+1 {
		panic("engine: dispatch custody ticket admitted out of order")
	}
	e.dispatchTicketIssued = ticket
	if e.selectorCutoverPending {
		e.dispatchTicketClaimedThrough = ticket
		e.selectorCutoverHandedOff = true
		e.selectorCutoverReplayRequired = true
		return
	}
	e.dispatchTicketsUnclaimed++
}

func (e *Engine) completeDispatchCustodyLocked(ticket uint64) {
	if ticket == 0 || ticket > e.dispatchTicketIssued {
		panic("engine: invalid dispatch custody completion")
	}
	if ticket <= e.dispatchTicketClaimedThrough {
		return
	}
	if e.dispatchTicketsUnclaimed == 0 {
		panic("engine: unclaimed dispatch custody underflow")
	}
	e.dispatchTicketsUnclaimed--
}

func (e *Engine) claimUnownedDispatchCustodyLocked() bool {
	if e.dispatchTicketsUnclaimed == 0 {
		return false
	}
	e.dispatchTicketClaimedThrough = e.dispatchTicketIssued
	e.dispatchTicketsUnclaimed = 0
	return true
}
