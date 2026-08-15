package engine

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

var errExecutionRuntimeNotConfigured = errors.New("engine: execution runtime is not configured")

type dispatchRoute struct {
	targetID proto.TargetID
	bonded   bool
}

type dispatchTicket struct {
	routes []dispatchRoute
	kind   proto.ExecutionKind
}

type executionRuntime struct {
	plan             *executionPlan
	flatLeafSelector bool

	mu         sync.Mutex
	selectors  map[proto.TargetID]*selectorExecutionState
	bonds      map[proto.TargetID]*bondExecutionState
	stuckSkips atomic.Uint64
}

type selectorExecutionState struct {
	desired               proto.TargetID
	effective             proto.TargetID
	generation            uint64
	peakHeld              bool
	qualityCandidate      proto.TargetID
	qualityCurrent        proto.TargetID
	qualityCandidateSpeed speedEvidence
	qualityCurrentSpeed   speedEvidence
	qualityTopologyEpoch  uint64
	qualitySince          time.Time
	lastQualityMove       time.Time
}

func (s *selectorExecutionState) clearQualityCandidate() {
	if s == nil {
		return
	}
	s.qualityCandidate = proto.TargetID{}
	s.qualityCurrent = proto.TargetID{}
	s.qualityCandidateSpeed = speedEvidence{}
	s.qualityCurrentSpeed = speedEvidence{}
	s.qualityTopologyEpoch = 0
	s.qualitySince = time.Time{}
}

type initialSelectorSelection struct {
	selectorID proto.TargetID
	targetID   proto.TargetID
}

type bondExecutionState struct {
	cursor       uint64
	currentChild proto.TargetID
	pinLeft      int
}

func newExecutionRuntime(plan *executionPlan) *executionRuntime {
	return &executionRuntime{
		plan:             plan,
		flatLeafSelector: isFlatLeafSelectorPlan(plan),
		selectors:        make(map[proto.TargetID]*selectorExecutionState),
		bonds:            make(map[proto.TargetID]*bondExecutionState),
	}
}

func isFlatLeafSelectorPlan(plan *executionPlan) bool {
	root, ok := plan.rootView()
	if !ok || root.kind != proto.GraphNodeKindSelector || len(root.children) == 0 {
		return false
	}
	for _, childID := range root.children {
		child, ok := plan.nodeView(childID)
		if !ok || child.kind != proto.GraphNodeKindPath {
			return false
		}
	}
	return true
}

func (r *executionRuntime) ownsFlatSelectorLeaf(targetID proto.TargetID) bool {
	if r == nil || !r.flatLeafSelector || targetID == (proto.TargetID{}) {
		return false
	}
	root, ok := r.plan.rootView()
	if !ok {
		return false
	}
	for _, childID := range root.children {
		if childID == targetID {
			return true
		}
	}
	return false
}

// flatSelectorDispatchLeaf resolves the sole leaf authorized by a flat
// selector. Physical path IDs are deliberately absent from this decision:
// they identify carrier incarnations, while the recursive runtime owns the
// logical target selection.
func (r *executionRuntime) flatSelectorDispatchLeaf(
	eligible, present map[proto.TargetID]bool,
) (proto.TargetID, bool) {
	if r == nil || !r.flatLeafSelector || r.plan == nil {
		return proto.TargetID{}, false
	}
	root, ok := r.plan.rootView()
	if !ok || root.kind != proto.GraphNodeKindSelector {
		return proto.TargetID{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.selectorDispatchChildLocked(
		root,
		func(id proto.TargetID) bool { return eligible[id] },
		func(id proto.TargetID) bool { return present[id] },
	)
}

func (r *executionRuntime) selectChild(selectorID, childID proto.TargetID) error {
	if r == nil || r.plan == nil {
		return fmt.Errorf("engine: execution runtime is not configured")
	}
	selector, ok := r.plan.nodeView(selectorID)
	if !ok || selector.kind != proto.GraphNodeKindSelector {
		return fmt.Errorf("engine: execution target is not a selector")
	}
	if err := r.plan.validateImmediateChild(selectorID, childID); err != nil {
		return err
	}
	r.mu.Lock()
	state := r.selectors[selectorID]
	if state == nil {
		state = &selectorExecutionState{}
		r.selectors[selectorID] = state
	}
	state.desired = childID
	r.mu.Unlock()
	return nil
}

// commitSelectorChild validates and publishes one selector decision while the
// caller applies its physical observation projection under the same runtime
// lock. A failed projection restores the exact prior selector state, so a
// rejected policy transaction cannot leave DATA using an uncommitted target.
func (r *executionRuntime) commitSelectorChild(
	selectorID, childID proto.TargetID,
	attached map[proto.TargetID]bool,
	apply func(map[proto.TargetID]bool) error,
) error {
	return r.commitSelectorChildOrigin(selectorID, childID, attached, policySelectionExternal, apply)
}

func (r *executionRuntime) commitSelectorChildOrigin(
	selectorID, childID proto.TargetID,
	attached map[proto.TargetID]bool,
	origin policySelectionOrigin,
	apply func(map[proto.TargetID]bool) error,
) error {
	if r == nil || r.plan == nil {
		return errExecutionRuntimeNotConfigured
	}
	selector, ok := r.plan.nodeView(selectorID)
	if !ok || selector.kind != proto.GraphNodeKindSelector {
		return fmt.Errorf("engine: execution target is not a selector")
	}
	if err := r.plan.validateImmediateChild(selectorID, childID); err != nil {
		return err
	}
	available := r.targetAvailability(attached)
	if !available(childID) {
		return fmt.Errorf("engine: selected target has no attached path")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	state, existed := r.selectors[selectorID]
	if !existed {
		state = &selectorExecutionState{}
		r.selectors[selectorID] = state
	}
	previous := *state
	changed := state.desired != childID
	if changed && state.generation == ^uint64(0) {
		if !existed {
			delete(r.selectors, selectorID)
		}
		return fmt.Errorf("engine: selector generation space exhausted")
	}
	state.desired = childID
	state.effective = childID
	if changed {
		state.generation++
	}
	switch origin {
	case policySelectionPeakPromote:
		state.peakHeld = true
	case policySelectionPeakReturn:
		state.peakHeld = false
	default:
		if !origin.isFactualFailure() || !selectorHasPeakCandidate(selector, childID) {
			state.peakHeld = false
		}
	}
	state.clearQualityCandidate()

	leaves := make(map[proto.TargetID]bool)
	r.collectEffectiveLeafSetLocked(r.plan.rootID, available, leaves)
	rollback := func() {
		if existed {
			*state = previous
		} else {
			delete(r.selectors, selectorID)
		}
	}
	if len(leaves) == 0 {
		rollback()
		return errNoExecutionRoute
	}
	if apply != nil {
		if err := apply(leaves); err != nil {
			rollback()
			return err
		}
	}
	return nil
}

func selectorHasPeakCandidate(selector executionPlanNode, targetID proto.TargetID) bool {
	for _, candidate := range selector.peakCandidates {
		if candidate == targetID {
			return true
		}
	}
	return false
}

func (r *executionRuntime) selectedChild(selectorID proto.TargetID) (desired, effective proto.TargetID, ok bool) {
	if r == nil {
		return proto.TargetID{}, proto.TargetID{}, false
	}
	r.mu.Lock()
	state := r.selectors[selectorID]
	if state != nil {
		desired, effective, ok = state.desired, state.effective, true
	}
	r.mu.Unlock()
	return desired, effective, ok
}

func (r *executionRuntime) selectorSelection(selectorID proto.TargetID) (desired, effective proto.TargetID, generation uint64, ok bool) {
	if r == nil {
		return proto.TargetID{}, proto.TargetID{}, 0, false
	}
	r.mu.Lock()
	state := r.selectors[selectorID]
	if state != nil {
		desired, effective, generation, ok = state.desired, state.effective, state.generation, true
	}
	r.mu.Unlock()
	return desired, effective, generation, ok
}

// rootPublicationAttribution snapshots the logical immediate child selected by
// the root selector. The caller serializes it with DATA publication through
// sendMu; nested selector activity is intentionally outside this cohort.
func (r *executionRuntime) rootPublicationAttribution() (
	selectorID, desired, effective proto.TargetID,
	generation uint64,
	ok bool,
) {
	if r == nil || r.plan == nil {
		return proto.TargetID{}, proto.TargetID{}, proto.TargetID{}, 0, false
	}
	root, exists := r.plan.rootView()
	if !exists || root.kind != proto.GraphNodeKindSelector {
		return proto.TargetID{}, proto.TargetID{}, proto.TargetID{}, 0, false
	}
	r.mu.Lock()
	state := r.selectors[root.targetID]
	if state != nil {
		desired = state.desired
		effective = state.effective
		generation = state.generation
	}
	r.mu.Unlock()
	return root.targetID, desired, effective, generation,
		state != nil && desired != (proto.TargetID{}) && generation != 0
}

// rootImmediateTarget returns the root selector child containing leafID. The
// graph is a tree, so exactly one immediate child can own a leaf.
func (r *executionRuntime) rootImmediateTarget(leafID proto.TargetID) (proto.TargetID, bool) {
	if r == nil || r.plan == nil || leafID == (proto.TargetID{}) {
		return proto.TargetID{}, false
	}
	root, ok := r.plan.rootView()
	if !ok || root.kind != proto.GraphNodeKindSelector {
		return proto.TargetID{}, false
	}
	for _, childID := range root.children {
		entry, exists := r.plan.nodes[childID]
		if !exists {
			continue
		}
		for _, descendant := range entry.leafIDs {
			if descendant == leafID {
				return childID, true
			}
		}
	}
	return proto.TargetID{}, false
}

func (r *executionRuntime) policySwitchLeaves(
	selectorID, targetID proto.TargetID,
	attached map[proto.TargetID]bool,
) map[proto.TargetID]bool {
	if r == nil || r.plan == nil {
		return nil
	}
	available := r.targetAvailability(attached)
	r.mu.Lock()
	defer r.mu.Unlock()
	selector, ok := r.plan.nodeView(selectorID)
	if !ok || selector.kind != proto.GraphNodeKindSelector {
		return nil
	}
	current, _ := r.selectorProjectionChildLocked(selector, available)
	if current == (proto.TargetID{}) || current == targetID {
		return nil
	}
	leaves := make(map[proto.TargetID]bool)
	r.collectEffectiveLeafSetLocked(current, available, leaves)
	r.collectEffectiveLeafSetLocked(targetID, available, leaves)
	return leaves
}

func (r *executionRuntime) effectiveLeafTargets(attached map[proto.TargetID]bool) map[proto.TargetID]bool {
	if r == nil || r.plan == nil {
		return nil
	}
	available := r.targetAvailability(attached)
	r.mu.Lock()
	defer r.mu.Unlock()
	leaves := make(map[proto.TargetID]bool)
	r.collectEffectiveLeafSetLocked(r.plan.rootID, available, leaves)
	return leaves
}

// selectorIsEffective reports whether selectorID participates in the current
// root projection. Selectors below an inactive selector branch are policy
// state only: changing them must not interrupt an unrelated active dispatch.
func (r *executionRuntime) selectorIsEffective(selectorID proto.TargetID, attached map[proto.TargetID]bool) bool {
	if r == nil || r.plan == nil {
		return false
	}
	available := r.targetAvailability(attached)
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.selectorIsEffectiveLocked(selectorID, available)
}

func (r *executionRuntime) selectorIsEffectiveLocked(
	selectorID proto.TargetID,
	available func(proto.TargetID) bool,
) bool {
	var visit func(proto.TargetID) bool
	visit = func(id proto.TargetID) bool {
		if !available(id) {
			return false
		}
		if id == selectorID {
			return true
		}
		node, ok := r.plan.nodeView(id)
		if !ok || node.kind == proto.GraphNodeKindPath {
			return false
		}
		if node.kind == proto.GraphNodeKindSelector {
			childID, selected := r.selectorProjectionChildLocked(node, available)
			return selected && visit(childID)
		}
		for _, childID := range node.children {
			if visit(childID) {
				return true
			}
		}
		return false
	}
	return visit(r.plan.rootID)
}

// policySelectionChangesEffectiveRoute reports whether selecting targetID
// changes the current root data-plane projection. A selector below an inactive
// branch and a desired-state change that preserves the effective fallback are
// policy-only updates; neither may seize an unrelated dispatch for replay.
func (r *executionRuntime) policySelectionChangesEffectiveRoute(
	selectorID, targetID proto.TargetID,
	attached map[proto.TargetID]bool,
) bool {
	if r == nil || r.plan == nil || targetID == (proto.TargetID{}) {
		return false
	}
	available := r.targetAvailability(attached)
	r.mu.Lock()
	defer r.mu.Unlock()
	selector, ok := r.plan.nodeView(selectorID)
	if !ok || selector.kind != proto.GraphNodeKindSelector || !available(targetID) ||
		!r.selectorIsEffectiveLocked(selectorID, available) {
		return false
	}
	current, selected := r.selectorProjectionChildLocked(selector, available)
	return selected && current != (proto.TargetID{}) && current != targetID
}

func (r *executionRuntime) targetAvailability(attached map[proto.TargetID]bool) func(proto.TargetID) bool {
	available := make(map[proto.TargetID]bool, len(r.plan.nodes))
	known := make(map[proto.TargetID]bool, len(r.plan.nodes))
	var targetAvailable func(proto.TargetID) bool
	targetAvailable = func(id proto.TargetID) bool {
		if known[id] {
			return available[id]
		}
		known[id] = true
		node, ok := r.plan.nodeView(id)
		if !ok {
			return false
		}
		if node.kind == proto.GraphNodeKindPath {
			available[id] = attached[id]
			return available[id]
		}
		for _, childID := range node.children {
			if targetAvailable(childID) {
				available[id] = true
			}
		}
		return available[id]
	}
	return targetAvailable
}

func (r *executionRuntime) collectEffectiveLeafSetLocked(
	id proto.TargetID,
	available func(proto.TargetID) bool,
	leaves map[proto.TargetID]bool,
) {
	node, ok := r.plan.nodeView(id)
	if !ok || !available(id) {
		return
	}
	if node.kind == proto.GraphNodeKindPath {
		leaves[id] = true
		return
	}
	if node.kind == proto.GraphNodeKindSelector {
		if childID, selected := r.selectorProjectionChildLocked(node, available); selected {
			r.collectEffectiveLeafSetLocked(childID, available, leaves)
		}
		return
	}
	for _, childID := range node.children {
		r.collectEffectiveLeafSetLocked(childID, available, leaves)
	}
}

// selectorProjectionChildLocked is the shared non-mutating selector resolver
// for policy/hold projections. It must match selectorChildLocked: a recovered
// desired child immediately outranks a stale fallback, followed by non-peak
// and peak children in manifest order.
func (r *executionRuntime) selectorProjectionChildLocked(
	node executionPlanNode,
	available func(proto.TargetID) bool,
) (proto.TargetID, bool) {
	state := r.selectors[node.targetID]
	if state != nil && state.desired != (proto.TargetID{}) && available(state.desired) {
		return state.desired, true
	}
	peaks := make(map[proto.TargetID]bool, len(node.peakCandidates))
	for _, id := range node.peakCandidates {
		peaks[id] = true
	}
	for _, peakPass := range []bool{false, true} {
		for _, childID := range node.children {
			if peaks[childID] == peakPass && available(childID) {
				return childID, true
			}
		}
	}
	return proto.TargetID{}, false
}

// initializeSelectorsForLeaf freezes the manifest branch that made a leaf's
// first physical generation usable. A committed selector branch may only be
// changed by the policy plane; the data plane must never silently route via a
// sibling when that branch is temporarily unavailable.
func (r *executionRuntime) initializeSelectorsForLeaf(leafID proto.TargetID) []initialSelectorSelection {
	return r.initializeSelectorsForLeafPolicy(leafID, nil)
}

func (r *executionRuntime) initializeSelectorsForLeafPolicy(
	leafID proto.TargetID,
	policySelections map[proto.TargetID]proto.TargetID,
) []initialSelectorSelection {
	if r == nil || r.plan == nil || leafID == (proto.TargetID{}) {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	initialized := make([]initialSelectorSelection, 0)
	r.initializeSelectorBranchLocked(r.plan.rootID, leafID, policySelections, &initialized)
	return initialized
}

func (r *executionRuntime) initializeSelectorBranchLocked(
	id, leafID proto.TargetID,
	policySelections map[proto.TargetID]proto.TargetID,
	initialized *[]initialSelectorSelection,
) bool {
	node, ok := r.plan.nodeView(id)
	if !ok {
		return false
	}
	if node.kind == proto.GraphNodeKindPath {
		return id == leafID
	}
	for _, childID := range node.children {
		if !r.initializeSelectorBranchLocked(childID, leafID, policySelections, initialized) {
			continue
		}
		if node.kind == proto.GraphNodeKindSelector {
			state := r.selectors[node.targetID]
			if state == nil {
				state = &selectorExecutionState{}
				r.selectors[node.targetID] = state
			}
			if state.desired == (proto.TargetID{}) {
				desired := policySelections[node.targetID]
				if desired == (proto.TargetID{}) {
					desired = childID
					*initialized = append(*initialized, initialSelectorSelection{
						selectorID: node.targetID,
						targetID:   childID,
					})
				}
				state.desired = desired
				state.effective = childID
				state.generation = 1
			}
		}
		return true
	}
	return false
}

func (r *executionRuntime) activeLeafTargets(attached map[proto.TargetID]bool) ([]proto.TargetID, proto.ExecutionKind, error) {
	if r == nil || r.plan == nil {
		return nil, 0, fmt.Errorf("engine: execution runtime is not configured")
	}
	var available func(proto.TargetID) bool
	available = func(id proto.TargetID) bool {
		node, ok := r.plan.nodeView(id)
		if !ok {
			return false
		}
		if node.kind == proto.GraphNodeKindPath {
			return attached[id]
		}
		for _, childID := range node.children {
			if available(childID) {
				return true
			}
		}
		return false
	}
	root, ok := r.plan.rootView()
	if !ok || !available(root.targetID) {
		return nil, 0, errNoExecutionRoute
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	kind := r.activeExecutionKindLocked(root.targetID, available)
	leaves := make([]proto.TargetID, 0)
	r.collectActiveLeavesLocked(root.targetID, available, &leaves)
	if len(leaves) == 0 {
		return nil, 0, errNoExecutionRoute
	}
	return leaves, kind, nil
}

func (r *executionRuntime) activeExecutionKindLocked(id proto.TargetID, available func(proto.TargetID) bool) proto.ExecutionKind {
	node, ok := r.plan.nodeView(id)
	if !ok {
		return proto.ExecutionKindSelector
	}
	if node.kind == proto.GraphNodeKindSelector {
		childID, selected := r.selectorChildLocked(node, available)
		if selected {
			return r.activeExecutionKindLocked(childID, available)
		}
		return proto.ExecutionKindSelector
	}
	switch node.kind {
	case proto.GraphNodeKindBond:
		return proto.ExecutionKindBond
	case proto.GraphNodeKindRace:
		return proto.ExecutionKindRace
	default:
		return proto.ExecutionKindSelector
	}
}

func (r *executionRuntime) collectActiveLeavesLocked(id proto.TargetID, available func(proto.TargetID) bool, leaves *[]proto.TargetID) {
	node, ok := r.plan.nodeView(id)
	if !ok || !available(id) {
		return
	}
	if node.kind == proto.GraphNodeKindPath {
		*leaves = append(*leaves, id)
		return
	}
	if node.kind == proto.GraphNodeKindSelector {
		if childID, selected := r.selectorChildLocked(node, available); selected {
			r.collectActiveLeavesLocked(childID, available, leaves)
		}
		return
	}
	for _, childID := range node.children {
		r.collectActiveLeavesLocked(childID, available, leaves)
	}
}

func (r *executionRuntime) buildTicket(attached map[proto.TargetID]bool, packetized bool, bondPinSize int) (dispatchTicket, error) {
	return r.buildTicketObserved(attached, nil, nil, packetized, bondPinSize, 0)
}

func (r *executionRuntime) buildTicketObserved(
	attached map[proto.TargetID]bool,
	qualities map[proto.TargetID]transport.PathQuality,
	capacities map[proto.TargetID]uint64,
	packetized bool,
	bondPinSize int,
	bondStuckMultiplier float64,
) (dispatchTicket, error) {
	return r.buildTicketObservedPresence(
		attached, attached, qualities, capacities, packetized, bondPinSize, bondStuckMultiplier,
	)
}

func (r *executionRuntime) buildTicketObservedPresence(
	eligible map[proto.TargetID]bool,
	present map[proto.TargetID]bool,
	qualities map[proto.TargetID]transport.PathQuality,
	capacities map[proto.TargetID]uint64,
	packetized bool,
	bondPinSize int,
	bondStuckMultiplier float64,
) (dispatchTicket, error) {
	if r == nil || r.plan == nil {
		return dispatchTicket{}, fmt.Errorf("engine: execution runtime is not configured")
	}
	root, ok := r.plan.rootView()
	if !ok {
		return dispatchTicket{}, fmt.Errorf("engine: execution plan has no root")
	}
	available := make(map[proto.TargetID]bool, len(r.plan.nodes))
	known := make(map[proto.TargetID]bool, len(r.plan.nodes))
	var nodeAvailable func(proto.TargetID) bool
	nodeAvailable = func(id proto.TargetID) bool {
		if known[id] {
			return available[id]
		}
		known[id] = true
		node, exists := r.plan.nodeView(id)
		if !exists {
			return false
		}
		if node.kind == proto.GraphNodeKindPath {
			available[id] = eligible[id]
			return available[id]
		}
		for _, childID := range node.children {
			if nodeAvailable(childID) {
				available[id] = true
				return true
			}
		}
		return false
	}
	if !nodeAvailable(root.targetID) {
		return dispatchTicket{}, errNoExecutionRoute
	}
	presentMemo := make(map[proto.TargetID]bool, len(r.plan.nodes))
	presentKnown := make(map[proto.TargetID]bool, len(r.plan.nodes))
	var nodePresent func(proto.TargetID) bool
	nodePresent = func(id proto.TargetID) bool {
		if presentKnown[id] {
			return presentMemo[id]
		}
		presentKnown[id] = true
		node, exists := r.plan.nodeView(id)
		if !exists {
			return false
		}
		if node.kind == proto.GraphNodeKindPath {
			presentMemo[id] = present[id]
			return presentMemo[id]
		}
		for _, childID := range node.children {
			if nodePresent(childID) {
				presentMemo[id] = true
				return true
			}
		}
		return false
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	routes, ok := r.buildNodeLocked(
		root.targetID, false, nodeAvailable, nodePresent, qualities, capacities,
		packetized, bondPinSize, bondStuckMultiplier,
	)
	if !ok || len(routes) == 0 {
		return dispatchTicket{}, errNoExecutionRoute
	}
	seen := make(map[proto.TargetID]struct{}, len(routes))
	unique := routes[:0]
	for _, route := range routes {
		if _, duplicate := seen[route.targetID]; duplicate {
			continue
		}
		seen[route.targetID] = struct{}{}
		unique = append(unique, route)
	}
	return dispatchTicket{
		routes: unique,
		kind:   r.activeExecutionKindLocked(root.targetID, nodeAvailable),
	}, nil
}

func (r *executionRuntime) buildNodeLocked(
	id proto.TargetID,
	bonded bool,
	available func(proto.TargetID) bool,
	present func(proto.TargetID) bool,
	qualities map[proto.TargetID]transport.PathQuality,
	capacities map[proto.TargetID]uint64,
	packetized bool,
	bondPinSize int,
	bondStuckMultiplier float64,
) ([]dispatchRoute, bool) {
	node, ok := r.plan.nodeView(id)
	if !ok || !available(id) {
		return nil, false
	}
	switch node.kind {
	case proto.GraphNodeKindPath:
		return []dispatchRoute{{targetID: id, bonded: bonded}}, true
	case proto.GraphNodeKindSelector:
		childID, ok := r.selectorDispatchChildLocked(node, available, present)
		if !ok {
			return nil, false
		}
		return r.buildNodeLocked(childID, bonded, available, present, qualities, capacities, packetized, bondPinSize, bondStuckMultiplier)
	case proto.GraphNodeKindBond:
		tried := make(map[proto.TargetID]bool, len(node.children))
		for len(tried) < len(node.children) {
			childID, ok := r.bondChildLocked(node, available, present, qualities, capacities, tried, packetized, bondPinSize, bondStuckMultiplier)
			if !ok {
				return nil, false
			}
			tried[childID] = true
			if routes, built := r.buildNodeLocked(childID, true, available, present, qualities, capacities, packetized, bondPinSize, bondStuckMultiplier); built {
				return routes, true
			}
		}
		return nil, false
	case proto.GraphNodeKindRace:
		var routes []dispatchRoute
		for _, childID := range node.children {
			if !available(childID) {
				continue
			}
			childRoutes, built := r.buildNodeLocked(childID, bonded, available, present, qualities, capacities, packetized, bondPinSize, bondStuckMultiplier)
			if built {
				routes = append(routes, childRoutes...)
			}
		}
		return routes, len(routes) != 0
	default:
		return nil, false
	}
}

func (r *executionRuntime) selectorChildLocked(node executionPlanNode, available func(proto.TargetID) bool) (proto.TargetID, bool) {
	state := r.selectors[node.targetID]
	if state == nil {
		state = &selectorExecutionState{}
		r.selectors[node.targetID] = state
	}
	if childID, selected := r.selectorProjectionChildLocked(node, available); selected {
		state.effective = childID
		return childID, true
	}
	state.effective = proto.TargetID{}
	return proto.TargetID{}, false
}

// selectorDispatchChildLocked distinguishes a physically absent selected
// target from one that is merely excluded by a blocked writer. Hard absence
// may use the selector's immediate death fallback. A present-but-stalled
// target must wait for a policy-plane cutover so DATA can never reach a
// sibling while ActivePath still names the selected target.
func (r *executionRuntime) selectorDispatchChildLocked(
	node executionPlanNode,
	eligible func(proto.TargetID) bool,
	present func(proto.TargetID) bool,
) (proto.TargetID, bool) {
	state := r.selectors[node.targetID]
	if state == nil {
		state = &selectorExecutionState{}
		r.selectors[node.targetID] = state
	}
	if state.desired != (proto.TargetID{}) {
		if eligible(state.desired) {
			state.effective = state.desired
			return state.desired, true
		}
		if present(state.desired) {
			state.effective = proto.TargetID{}
			return proto.TargetID{}, false
		}
	}
	peaks := make(map[proto.TargetID]bool, len(node.peakCandidates))
	for _, id := range node.peakCandidates {
		peaks[id] = true
	}
	for _, peakPass := range []bool{false, true} {
		for _, childID := range node.children {
			if peaks[childID] != peakPass || !eligible(childID) {
				continue
			}
			state.effective = childID
			return childID, true
		}
	}
	state.effective = proto.TargetID{}
	return proto.TargetID{}, false
}

func (r *executionRuntime) bondChildLocked(
	node executionPlanNode,
	available func(proto.TargetID) bool,
	present func(proto.TargetID) bool,
	qualities map[proto.TargetID]transport.PathQuality,
	capacities map[proto.TargetID]uint64,
	excluded map[proto.TargetID]bool,
	packetized bool,
	pinSize int,
	stuckMultiplier float64,
) (proto.TargetID, bool) {
	state := r.bonds[node.targetID]
	if state == nil {
		state = &bondExecutionState{}
		r.bonds[node.targetID] = state
	}
	// High RTT alone is not a stuck signal. The dispatcher excludes only
	// leaves whose writer has made no progress past its RTT-derived window.
	stuck := make(map[proto.TargetID]bool)
	if state.pinLeft > 0 && !excluded[state.currentChild] && !stuck[state.currentChild] && available(state.currentChild) {
		state.pinLeft--
		return state.currentChild, true
	}

	var totalWeight uint64
	for _, childID := range node.children {
		if excluded[childID] || stuck[childID] || !available(childID) {
			continue
		}
		weight := r.aggregateCapacityLocked(childID, available, present, capacities)
		if weight == 0 {
			weight = 1
		}
		totalWeight = saturatingAddUint64(totalWeight, weight)
	}
	if totalWeight == 0 {
		state.currentChild = proto.TargetID{}
		state.pinLeft = 0
		return proto.TargetID{}, false
	}
	slot := state.cursor % totalWeight
	var childID proto.TargetID
	var accumulated uint64
	for _, candidateID := range node.children {
		if excluded[candidateID] || stuck[candidateID] || !available(candidateID) {
			continue
		}
		weight := r.aggregateCapacityLocked(candidateID, available, present, capacities)
		if weight == 0 {
			weight = 1
		}
		accumulated = saturatingAddUint64(accumulated, weight)
		if slot < accumulated {
			childID = candidateID
			break
		}
	}
	if childID == (proto.TargetID{}) {
		return proto.TargetID{}, false
	}
	state.cursor++
	pin := pinSize
	if pin <= 0 {
		pin = defaultBondPinSize
	}
	if packetized {
		pin = 1
	}
	state.currentChild = childID
	state.pinLeft = pin - 1
	return childID, true
}

func (r *executionRuntime) aggregateCapacityLocked(
	id proto.TargetID,
	available func(proto.TargetID) bool,
	present func(proto.TargetID) bool,
	capacities map[proto.TargetID]uint64,
) uint64 {
	if !available(id) {
		return 0
	}
	node, ok := r.plan.nodeView(id)
	if !ok {
		return 0
	}
	if node.kind == proto.GraphNodeKindPath {
		return capacities[id]
	}
	if node.kind == proto.GraphNodeKindSelector {
		childID, ok := r.selectorDispatchChildLocked(node, available, present)
		if !ok {
			return 0
		}
		return r.aggregateCapacityLocked(childID, available, present, capacities)
	}
	var capacity uint64
	for _, childID := range node.children {
		childCapacity := r.aggregateCapacityLocked(childID, available, present, capacities)
		if node.kind == proto.GraphNodeKindRace {
			if childCapacity > capacity {
				capacity = childCapacity
			}
			continue
		}
		capacity = saturatingAddUint64(capacity, childCapacity)
	}
	return capacity
}

func (r *executionRuntime) bondStuckChildren(
	node executionPlanNode,
	available func(proto.TargetID) bool,
	qualities map[proto.TargetID]transport.PathQuality,
	multiplier float64,
) map[proto.TargetID]bool {
	stuck := make(map[proto.TargetID]bool)
	if len(qualities) == 0 || multiplier >= 1_000_000 {
		return stuck
	}
	if multiplier <= 1 {
		multiplier = 3
	}
	rtts := make(map[proto.TargetID]time.Duration, len(node.children))
	var best time.Duration
	for _, childID := range node.children {
		if !available(childID) {
			continue
		}
		rtt := r.aggregateRTT(childID, available, qualities)
		rtts[childID] = rtt
		if rtt > 0 && (best == 0 || rtt < best) {
			best = rtt
		}
	}
	if best == 0 {
		return stuck
	}
	threshold := time.Duration(float64(best) * multiplier)
	usable := 0
	skipped := uint64(0)
	for _, childID := range node.children {
		if rtt := rtts[childID]; rtt > threshold {
			stuck[childID] = true
			skipped++
		} else if available(childID) {
			usable++
		}
	}
	if usable == 0 {
		return make(map[proto.TargetID]bool)
	}
	r.stuckSkips.Add(skipped)
	return stuck
}

func (r *executionRuntime) aggregateRTT(id proto.TargetID, available func(proto.TargetID) bool, qualities map[proto.TargetID]transport.PathQuality) time.Duration {
	node, ok := r.plan.nodeView(id)
	if !ok || !available(id) {
		return 0
	}
	if node.kind == proto.GraphNodeKindPath {
		return qualities[id].RTT
	}
	if node.kind == proto.GraphNodeKindSelector {
		childID, ok := r.selectorChildLocked(node, available)
		if !ok {
			return 0
		}
		return r.aggregateRTT(childID, available, qualities)
	}
	var aggregate time.Duration
	for _, childID := range node.children {
		rtt := r.aggregateRTT(childID, available, qualities)
		if rtt <= 0 {
			continue
		}
		if node.kind == proto.GraphNodeKindBond {
			if rtt > aggregate {
				aggregate = rtt
			}
		} else if aggregate == 0 || rtt < aggregate {
			aggregate = rtt
		}
	}
	return aggregate
}

var errNoExecutionRoute = fmt.Errorf("engine: no attached path for execution graph")
