package engine

import "errors"

var errSelectorCutoverHandoff = errors.New("engine: selector cutover owns published frame")

// beginSelectorCutover wakes a sequenced dispatch that is waiting on a
// physical writer. The frame is already in the replay ledger, so the selector
// can take sendMu and replay it after committing the new route.
func (e *Engine) beginSelectorCutover() uint64 {
	e.selectorCutoverMu.Lock()
	defer e.selectorCutoverMu.Unlock()
	if e.selectorCutoverGeneration == ^uint64(0) {
		panic("engine: selector cutover generation exhausted")
	}
	e.selectorCutoverGeneration++
	e.selectorCutoverPending = true
	e.selectorCutoverHandedOff = e.acceptedPacketDispatches != 0 ||
		e.detachedStreamDispatches != 0
	if e.detachedStreamDispatches != 0 {
		e.advanceDetachedDispatchHandoffLocked()
	}
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
	close(e.selectorCutoverWake)
	e.selectorCutoverWake = make(chan struct{})
}

func (e *Engine) selectorCutoverSnapshot() (bool, <-chan struct{}) {
	e.selectorCutoverMu.Lock()
	defer e.selectorCutoverMu.Unlock()
	return e.selectorCutoverPending, e.selectorCutoverWake
}

func (e *Engine) handoffSelectorCutoverDispatch() bool {
	e.selectorCutoverMu.Lock()
	defer e.selectorCutoverMu.Unlock()
	if !e.selectorCutoverPending {
		return false
	}
	e.selectorCutoverHandedOff = true
	return true
}

func (e *Engine) selectorCutoverDidHandoff(generation uint64) bool {
	e.selectorCutoverMu.Lock()
	defer e.selectorCutoverMu.Unlock()
	return generation != 0 && e.selectorCutoverPending &&
		e.selectorCutoverGeneration == generation && e.selectorCutoverHandedOff
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
	replayTarget := e.sendPublishedNext.Load()
	e.finishSelectorCutover(generation)
	if !handedOff {
		return
	}
	if err := e.replayRangeLocked(e.sendAckNext.Load(), replayTarget); err != nil {
		e.requestReplayRange(e.sendAckNext.Load(), replayTarget)
	}
}

func (e *Engine) completeAcceptedPacketDispatch() {
	e.selectorCutoverMu.Lock()
	defer e.selectorCutoverMu.Unlock()
	if e.acceptedPacketDispatches == 0 {
		panic("engine: accepted packet dispatch completed without custody")
	}
	e.acceptedPacketDispatches--
}

func (e *Engine) beginDetachedStreamDispatch() (baseline uint64, handedOffAtStart bool) {
	e.selectorCutoverMu.Lock()
	defer e.selectorCutoverMu.Unlock()
	baseline = e.detachedDispatchHandoffGen
	e.detachedStreamDispatches++
	if e.selectorCutoverPending {
		handedOffAtStart = true
		e.selectorCutoverHandedOff = true
	}
	return baseline, handedOffAtStart
}

func (e *Engine) completeDetachedStreamDispatch() {
	e.selectorCutoverMu.Lock()
	defer e.selectorCutoverMu.Unlock()
	if e.detachedStreamDispatches == 0 {
		panic("engine: detached stream dispatch completed without custody")
	}
	e.detachedStreamDispatches--
}

func (e *Engine) detachedStreamDispatchHandedOff(baseline uint64, handedOffAtStart bool) bool {
	if handedOffAtStart {
		return true
	}
	e.selectorCutoverMu.Lock()
	handedOff := e.detachedDispatchHandoffGen > baseline
	e.selectorCutoverMu.Unlock()
	return handedOff
}

func (e *Engine) handoffDetachedStreamDispatchesForReplay() {
	e.selectorCutoverMu.Lock()
	defer e.selectorCutoverMu.Unlock()
	if e.detachedStreamDispatches != 0 {
		e.advanceDetachedDispatchHandoffLocked()
	}
}

func (e *Engine) advanceDetachedDispatchHandoffLocked() {
	if e.detachedDispatchHandoffGen == ^uint64(0) {
		panic("engine: detached dispatch handoff generation exhausted")
	}
	e.detachedDispatchHandoffGen++
}
