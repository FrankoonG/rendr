package engine

import "errors"

var errSelectorCutoverHandoff = errors.New("engine: selector cutover owns published frame")

// beginSelectorCutover wakes a sequenced dispatch that is waiting on a
// physical writer. The frame is already in the replay ledger, so the selector
// can take sendMu and replay it after committing the new route.
func (e *Engine) beginSelectorCutover() uint64 {
	e.selectorCutoverMu.Lock()
	defer e.selectorCutoverMu.Unlock()
	e.selectorCutoverGeneration++
	e.selectorCutoverPending = true
	e.selectorCutoverHandedOff = e.acceptedPacketDispatches != 0
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

func (e *Engine) completeAcceptedPacketDispatch() {
	e.selectorCutoverMu.Lock()
	defer e.selectorCutoverMu.Unlock()
	if e.acceptedPacketDispatches == 0 {
		panic("engine: accepted packet dispatch completed without custody")
	}
	e.acceptedPacketDispatches--
}
