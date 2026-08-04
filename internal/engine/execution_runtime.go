package engine

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type dispatchRoute struct {
	targetID proto.TargetID
	bonded   bool
}

type dispatchTicket struct {
	routes []dispatchRoute
}

type executionRuntime struct {
	plan *executionPlan

	mu         sync.Mutex
	selectors  map[proto.TargetID]*selectorExecutionState
	bonds      map[proto.TargetID]*bondExecutionState
	stuckSkips atomic.Uint64
}

type selectorExecutionState struct {
	desired   proto.TargetID
	effective proto.TargetID
}

type bondExecutionState struct {
	cursor       uint64
	currentChild proto.TargetID
	pinLeft      int
}

func newExecutionRuntime(plan *executionPlan) *executionRuntime {
	return &executionRuntime{
		plan:      plan,
		selectors: make(map[proto.TargetID]*selectorExecutionState),
		bonds:     make(map[proto.TargetID]*bondExecutionState),
	}
}

func (r *executionRuntime) selectChild(selectorID, childID proto.TargetID) error {
	if r == nil || r.plan == nil {
		return fmt.Errorf("engine: execution runtime is not configured")
	}
	selector, ok := r.plan.node(selectorID)
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

func (r *executionRuntime) buildTicket(attached map[proto.TargetID]bool, packetized bool, bondPinSize int) (dispatchTicket, error) {
	return r.buildTicketObserved(attached, nil, packetized, bondPinSize, 0)
}

func (r *executionRuntime) buildTicketObserved(
	attached map[proto.TargetID]bool,
	qualities map[proto.TargetID]transport.PathQuality,
	packetized bool,
	bondPinSize int,
	bondStuckMultiplier float64,
) (dispatchTicket, error) {
	if r == nil || r.plan == nil {
		return dispatchTicket{}, fmt.Errorf("engine: execution runtime is not configured")
	}
	root, ok := r.plan.root()
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
		node, exists := r.plan.node(id)
		if !exists {
			return false
		}
		if node.kind == proto.GraphNodeKindPath {
			available[id] = attached[id]
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

	r.mu.Lock()
	defer r.mu.Unlock()
	routes, ok := r.buildNodeLocked(root.targetID, false, nodeAvailable, qualities, packetized, bondPinSize, bondStuckMultiplier)
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
	return dispatchTicket{routes: unique}, nil
}

func (r *executionRuntime) buildNodeLocked(
	id proto.TargetID,
	bonded bool,
	available func(proto.TargetID) bool,
	qualities map[proto.TargetID]transport.PathQuality,
	packetized bool,
	bondPinSize int,
	bondStuckMultiplier float64,
) ([]dispatchRoute, bool) {
	node, ok := r.plan.node(id)
	if !ok || !available(id) {
		return nil, false
	}
	switch node.kind {
	case proto.GraphNodeKindPath:
		return []dispatchRoute{{targetID: id, bonded: bonded}}, true
	case proto.GraphNodeKindSelector:
		childID, ok := r.selectorChildLocked(node, available)
		if !ok {
			return nil, false
		}
		return r.buildNodeLocked(childID, bonded, available, qualities, packetized, bondPinSize, bondStuckMultiplier)
	case proto.GraphNodeKindBond:
		tried := make(map[proto.TargetID]bool, len(node.children))
		for len(tried) < len(node.children) {
			childID, ok := r.bondChildLocked(node, available, qualities, tried, packetized, bondPinSize, bondStuckMultiplier)
			if !ok {
				return nil, false
			}
			tried[childID] = true
			if routes, built := r.buildNodeLocked(childID, true, available, qualities, packetized, bondPinSize, bondStuckMultiplier); built {
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
			childRoutes, built := r.buildNodeLocked(childID, bonded, available, qualities, packetized, bondPinSize, bondStuckMultiplier)
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
	if state.desired != (proto.TargetID{}) && available(state.desired) {
		state.effective = state.desired
		return state.desired, true
	}
	peaks := make(map[proto.TargetID]bool, len(node.peakCandidates))
	for _, id := range node.peakCandidates {
		peaks[id] = true
	}
	for _, peakPass := range []bool{false, true} {
		for _, childID := range node.children {
			if peaks[childID] != peakPass || !available(childID) {
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
	qualities map[proto.TargetID]transport.PathQuality,
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
	stuck := r.bondStuckChildren(node, available, qualities, stuckMultiplier)
	if state.pinLeft > 0 && !excluded[state.currentChild] && !stuck[state.currentChild] && available(state.currentChild) {
		state.pinLeft--
		return state.currentChild, true
	}

	var totalWeight uint64
	for _, childID := range node.children {
		if excluded[childID] || stuck[childID] || !available(childID) {
			continue
		}
		weight := uint64(1)
		if child, ok := r.plan.node(childID); ok && child.kind == proto.GraphNodeKindPath && child.weight > 0 {
			weight = uint64(child.weight)
		}
		totalWeight += weight
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
		weight := uint64(1)
		if child, ok := r.plan.node(candidateID); ok && child.kind == proto.GraphNodeKindPath && child.weight > 0 {
			weight = uint64(child.weight)
		}
		accumulated += weight
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
		rtt := r.aggregateRTT(childID, qualities)
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

func (r *executionRuntime) aggregateRTT(id proto.TargetID, qualities map[proto.TargetID]transport.PathQuality) time.Duration {
	node, ok := r.plan.node(id)
	if !ok {
		return 0
	}
	if node.kind == proto.GraphNodeKindPath {
		return qualities[id].RTT
	}
	var aggregate time.Duration
	for _, childID := range node.children {
		rtt := r.aggregateRTT(childID, qualities)
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
