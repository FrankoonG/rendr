package engine

import (
	"sync"

	"github.com/FrankoonG/rendr/proto"
)

// leafMobilityPolicyHold keeps the selector branch containing a physical leaf
// stable while that leaf's endpoint transaction is in flight. It does not
// fence control traffic or unrelated selectors.
type leafMobilityPolicyHold struct {
	slot *pathSlot
	once sync.Once
}

func holdLeafMobilityPolicy(slot *pathSlot) *leafMobilityPolicyHold {
	if slot == nil {
		return nil
	}
	slot.mobilityPolicyHolds.Add(1)
	return &leafMobilityPolicyHold{slot: slot}
}

func (h *leafMobilityPolicyHold) Release() {
	if h == nil || h.slot == nil {
		return
	}
	h.once.Do(func() {
		if h.slot.mobilityPolicyHolds.Add(-1) < 0 {
			panic("engine: leaf mobility policy hold underflow")
		}
	})
}

func (e *Engine) acquireLeafMobilityPolicyHold(slot *pathSlot) *leafMobilityPolicyHold {
	if e == nil || slot == nil {
		return nil
	}
	e.policyOwnerMu.Lock()
	hold := e.acquireLeafMobilityPolicyHoldOwned(slot)
	e.policyOwnerMu.Unlock()
	return hold
}

// acquireSelectedLeafMobilityPolicyHold linearizes a factual endpoint-change
// event with selector commits. If policy already moved elsewhere, the event
// may still refresh the inactive endpoint but must not pin the new branch.
func (e *Engine) acquireSelectedLeafMobilityPolicyHold(slot *pathSlot) *leafMobilityPolicyHold {
	if e == nil || slot == nil {
		return nil
	}
	e.policyOwnerMu.Lock()
	defer e.policyOwnerMu.Unlock()
	e.pathsMu.RLock()
	current := e.paths[slot.id]
	selected := current == slot && current.owner == slot.owner
	if selected {
		if len(e.dispatchScope) > 0 {
			selected = e.dispatchScope[slot.id]
		} else {
			selected = e.activeID == slot.id
		}
	}
	var hold *leafMobilityPolicyHold
	if selected {
		hold = holdLeafMobilityPolicy(slot)
	}
	e.pathsMu.RUnlock()
	return hold
}

// acquireLeafMobilityPolicyHoldOwned must run under policyOwnerMu. Policy
// selection commits use the same owner lock, making hold acquisition and a
// branch change one total order.
func (e *Engine) acquireLeafMobilityPolicyHoldOwned(slot *pathSlot) *leafMobilityPolicyHold {
	if e == nil || slot == nil {
		return nil
	}
	e.pathsMu.RLock()
	current := e.paths[slot.id]
	valid := current == slot && current.owner == slot.owner
	e.pathsMu.RUnlock()
	if !valid {
		return nil
	}
	return holdLeafMobilityPolicy(slot)
}

func (e *Engine) policySelectionHeldByLeafMobility(selectorID, targetID proto.TargetID) bool {
	runtime := e.localExecutionRuntime()
	if runtime == nil || runtime.plan == nil {
		return false
	}
	leaves := runtime.policySwitchLeaves(selectorID, targetID)
	if len(leaves) == 0 {
		return false
	}
	e.pathsMu.RLock()
	held := e.policySelectionHeldByLeafMobilityLocked(leaves)
	e.pathsMu.RUnlock()
	return held
}

// policySelectionHeldByLeafMobilityLocked is a defensive final commit check.
// Hold publication and selector commits are primarily serialized by
// policyOwnerMu; pathsMu keeps the checked physical generations stable.
func (e *Engine) policySelectionHeldByLeafMobilityLocked(leaves map[proto.TargetID]bool) bool {
	if len(leaves) == 0 {
		return false
	}
	for _, slot := range e.paths {
		if leaves[slot.localTXTargetID] && slot.mobilityPolicyHolds.Load() > 0 {
			return true
		}
	}
	return false
}
