package engine

import (
	"sync"

	"github.com/FrankoonG/rendr/proto"
)

// leafMobilityPolicyHold keeps the selector branch containing a physical leaf
// stable while that leaf's endpoint transaction is in flight. It does not
// fence control traffic or unrelated selectors.
type leafMobilityPolicyHold struct {
	slot         *pathSlot
	faultDerived bool
	mu           sync.Mutex
	held         bool
	done         bool
}

func newLeafMobilityPolicyHold(slot *pathSlot, faultDerived bool) *leafMobilityPolicyHold {
	if slot == nil {
		return nil
	}
	return &leafMobilityPolicyHold{slot: slot, faultDerived: faultDerived}
}

func holdLeafMobilityPolicy(slot *pathSlot) *leafMobilityPolicyHold {
	hold := newLeafMobilityPolicyHold(slot, false)
	if hold != nil {
		hold.Promote()
	}
	return hold
}

func (h *leafMobilityPolicyHold) Promote() bool {
	if h == nil || h.slot == nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.done {
		return false
	}
	if !h.held {
		if h.faultDerived {
			h.slot.mobilityFaultPolicyHolds.Add(1)
		}
		h.slot.mobilityPolicyHolds.Add(1)
		h.held = true
	}
	return true
}

func (h *leafMobilityPolicyHold) Release() {
	if h == nil || h.slot == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.done {
		return
	}
	h.done = true
	if h.held {
		if h.slot.mobilityPolicyHolds.Add(-1) < 0 {
			panic("engine: leaf mobility policy hold underflow")
		}
		if h.faultDerived && h.slot.mobilityFaultPolicyHolds.Add(-1) < 0 {
			panic("engine: leaf mobility fault policy hold underflow")
		}
	}
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
func (e *Engine) acquireSelectedLeafMobilityPolicyHold(slot *pathSlot, faultDerived bool) *leafMobilityPolicyHold {
	if e == nil || slot == nil {
		return nil
	}
	hold := newLeafMobilityPolicyHold(slot, faultDerived)
	e.pathsMu.RLock()
	present := false
	for _, slots := range []map[uint32]*pathSlot{e.paths, e.pendingPaths, e.stagedPaths} {
		if current := slots[slot.id]; current == slot && current.owner == slot.owner {
			present = true
			break
		}
	}
	if present && e.pathSlotInEffectiveProjectionLocked(e.localExecutionRuntime(), slot) {
		hold.Promote()
	}
	e.pathsMu.RUnlock()
	if !present {
		return nil
	}
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

func (e *Engine) policySelectionHeldByLeafMobility(
	selectorID, targetID proto.TargetID,
	origin policySelectionOrigin,
) bool {
	runtime := e.localExecutionRuntime()
	if runtime == nil || runtime.plan == nil {
		return false
	}
	e.pathsMu.RLock()
	held := e.policySelectionHeldByLeafMobilityLocked(runtime, selectorID, targetID, origin)
	e.pathsMu.RUnlock()
	return held
}

// policySelectionHeldByLeafMobilityLocked is the final commit check. pathsMu
// serializes nonblocking refresh hold publication with the physical policy
// projection; policyOwnerMu continues to serialize competing policy owners.
func (e *Engine) policySelectionHeldByLeafMobilityLocked(
	runtime *executionRuntime,
	selectorID, targetID proto.TargetID,
	origin policySelectionOrigin,
) bool {
	refs := e.policySwitchPhysicalPathRefsLocked(runtime, selectorID, targetID)
	if len(refs) == 0 {
		return false
	}
	for ref := range refs {
		slot := e.paths[ref.ID]
		if slot == nil || slot.owner != ref.Owner {
			continue
		}
		holds := slot.mobilityPolicyHolds.Load()
		if origin.isFactualFailure() {
			holds -= slot.mobilityFaultPolicyHolds.Load()
		}
		if holds > 0 {
			return true
		}
	}
	return false
}

func (e *Engine) policySwitchPhysicalPathRefsLocked(
	runtime *executionRuntime,
	selectorID, targetID proto.TargetID,
) map[PathRef]bool {
	if runtime == nil || runtime.plan == nil {
		return nil
	}
	attached := e.attachedLeafTargetsLocked()
	leaves := runtime.policySwitchLeaves(selectorID, targetID, attached)
	return e.physicalPathRefsForLeafTargetsLocked(leaves)
}

func (e *Engine) pathSlotInEffectiveProjectionLocked(runtime *executionRuntime, slot *pathSlot) bool {
	if slot == nil || e.paths[slot.id] != slot || slot.owner == 0 {
		return false
	}
	if runtime == nil || runtime.plan == nil {
		return false
	}
	leaves := runtime.effectiveLeafTargets(e.attachedLeafTargetsLocked())
	return leaves[slot.localTXTargetID]
}

func (e *Engine) attachedLeafTargetsLocked() map[proto.TargetID]bool {
	attached := make(map[proto.TargetID]bool, len(e.paths))
	for _, slot := range e.paths {
		attached[slot.localTXTargetID] = true
	}
	return attached
}

func (e *Engine) physicalPathRefsForLeafTargetsLocked(leaves map[proto.TargetID]bool) map[PathRef]bool {
	if len(leaves) == 0 {
		return nil
	}
	refs := make(map[PathRef]bool, len(leaves))
	for _, slot := range e.paths {
		if leaves[slot.localTXTargetID] {
			refs[PathRef{ID: slot.id, Owner: slot.owner}] = true
		}
	}
	return refs
}

// promoteEffectiveLeafMobilityRefreshPolicyHoldsLocked publishes provisional
// refresh holds when path or policy activation makes their exact physical
// generations effective. Caller holds policyOwnerMu and pathsMu.
func (e *Engine) promoteEffectiveLeafMobilityRefreshPolicyHoldsLocked(runtime *executionRuntime) {
	if runtime == nil || runtime.plan == nil {
		return
	}
	leaves := runtime.effectiveLeafTargets(e.attachedLeafTargetsLocked())
	e.leafRefreshMu.Lock()
	for ref, pending := range e.leafRefreshPending {
		if slot := e.paths[ref.ID]; slot != nil && slot.owner == ref.Owner && leaves[slot.localTXTargetID] {
			pending.policyHold.Promote()
		}
	}
	for ref, running := range e.leafRefreshRunning {
		if slot := e.paths[ref.ID]; slot != nil && slot.owner == ref.Owner && leaves[slot.localTXTargetID] {
			running.Promote()
		}
	}
	e.leafRefreshMu.Unlock()
}
