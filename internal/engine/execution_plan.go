package engine

import (
	"fmt"

	"github.com/FrankoonG/rendr/proto"
)

// executionPlan is an owned, immutable projection of one canonical target
// graph. It contains scheduling identity only; carrier configuration remains
// outside the engine plan.
type executionPlan struct {
	rootID  proto.TargetID
	nodes   map[proto.TargetID]executionPlanEntry
	nodeIDs []proto.TargetID
}

type executionPlanEntry struct {
	node    executionPlanNode
	leafIDs []proto.TargetID
}

// executionPlanNode describes one logical executor or path. Children are the
// immediate logical children in manifest order, never a flattened leaf set.
type executionPlanNode struct {
	targetID       proto.TargetID
	kind           proto.GraphNodeKind
	name           string
	weight         uint16
	children       []proto.TargetID
	peakCandidates []proto.TargetID
}

type executionPlanLeaf struct {
	targetID proto.TargetID
	name     string
	weight   uint16
}

// compileExecutionPlan verifies and owns manifest before constructing the
// recursive executor plan. Canonical encoding normalizes node and selector-set
// order while retaining the semantically significant child order.
func compileExecutionPlan(manifest proto.GraphManifest) (*executionPlan, error) {
	canonical, err := manifest.Encode()
	if err != nil {
		return nil, fmt.Errorf("engine: invalid execution graph: %w", err)
	}
	owned, err := proto.DecodeGraphManifest(canonical)
	if err != nil {
		return nil, fmt.Errorf("engine: invalid canonical execution graph: %w", err)
	}

	plan := &executionPlan{
		rootID:  owned.RootID,
		nodes:   make(map[proto.TargetID]executionPlanEntry, len(owned.Nodes)),
		nodeIDs: make([]proto.TargetID, 0, len(owned.Nodes)),
	}
	names := make(map[string]proto.TargetID, len(owned.Nodes))
	for i := range owned.Nodes {
		node := owned.Nodes[i]
		if !node.Kind.Valid() {
			return nil, fmt.Errorf("engine: execution node %q has invalid kind %d", node.Name, node.Kind)
		}
		if node.ID != proto.DeriveTargetID(node.Kind, node.Name) {
			return nil, fmt.Errorf("engine: execution node %q has invalid target id", node.Name)
		}
		if _, duplicate := plan.nodes[node.ID]; duplicate {
			return nil, fmt.Errorf("engine: duplicate execution target id for %q", node.Name)
		}
		if previous, duplicate := names[node.Name]; duplicate {
			return nil, fmt.Errorf("engine: duplicate execution target name %q (%x and %x)", node.Name, previous, node.ID)
		}

		entry := executionPlanEntry{node: executionPlanNode{
			targetID:       node.ID,
			kind:           node.Kind,
			name:           node.Name,
			weight:         node.Weight,
			children:       append([]proto.TargetID(nil), node.Children...),
			peakCandidates: append([]proto.TargetID(nil), node.PeakCandidates...),
		}}
		plan.nodes[node.ID] = entry
		plan.nodeIDs = append(plan.nodeIDs, node.ID)
		names[node.Name] = node.ID
	}

	if _, ok := plan.nodes[plan.rootID]; !ok {
		return nil, fmt.Errorf("engine: execution graph root %x is missing", plan.rootID)
	}
	if err := plan.validateReferences(); err != nil {
		return nil, err
	}
	if err := plan.compileLeafDescendants(); err != nil {
		return nil, err
	}
	return plan, nil
}

func (p *executionPlan) validateReferences() error {
	parents := make(map[proto.TargetID]proto.TargetID, len(p.nodes)-1)
	for _, id := range p.nodeIDs {
		entry := p.nodes[id]
		node := entry.node
		switch node.kind {
		case proto.GraphNodeKindPath:
			if len(node.children) != 0 || len(node.peakCandidates) != 0 {
				return fmt.Errorf("engine: path execution node %q has group references", node.name)
			}
		case proto.GraphNodeKindSelector:
			if len(node.children) == 0 {
				return fmt.Errorf("engine: selector execution node %q has no children", node.name)
			}
			if node.weight != 0 {
				return fmt.Errorf("engine: selector execution node %q has path-only weight", node.name)
			}
		case proto.GraphNodeKindBond, proto.GraphNodeKindRace:
			if len(node.children) == 0 {
				return fmt.Errorf("engine: %s execution node %q has no children", node.kind, node.name)
			}
			if node.weight != 0 {
				return fmt.Errorf("engine: %s execution node %q has path-only weight", node.kind, node.name)
			}
			if len(node.peakCandidates) != 0 {
				return fmt.Errorf("engine: %s execution node %q has selector candidates", node.kind, node.name)
			}
		default:
			return fmt.Errorf("engine: execution node %q has invalid kind %d", node.name, node.kind)
		}

		children := make(map[proto.TargetID]struct{}, len(node.children))
		for _, childID := range node.children {
			child, ok := p.nodes[childID]
			if !ok {
				return fmt.Errorf("engine: execution node %q references missing child %x", node.name, childID)
			}
			if _, duplicate := children[childID]; duplicate {
				return fmt.Errorf("engine: execution node %q repeats child %x", node.name, childID)
			}
			children[childID] = struct{}{}
			if previousID, duplicate := parents[childID]; duplicate {
				previous := p.nodes[previousID]
				return fmt.Errorf("engine: execution target %q has multiple parents %q and %q", child.node.name, previous.node.name, node.name)
			}
			parents[childID] = id
			if (node.kind == proto.GraphNodeKindBond || node.kind == proto.GraphNodeKindRace) && child.node.kind == node.kind {
				return fmt.Errorf("engine: %s execution node %q contains unnormalized child %q", node.kind, node.name, child.node.name)
			}
		}

		peaks := make(map[proto.TargetID]struct{}, len(node.peakCandidates))
		for _, peakID := range node.peakCandidates {
			if _, duplicate := peaks[peakID]; duplicate {
				return fmt.Errorf("engine: selector execution node %q repeats peak candidate %x", node.name, peakID)
			}
			peaks[peakID] = struct{}{}
			if _, immediate := children[peakID]; !immediate {
				return fmt.Errorf("engine: selector execution node %q has non-child peak candidate %x", node.name, peakID)
			}
		}
	}
	if _, hasParent := parents[p.rootID]; hasParent {
		return fmt.Errorf("engine: execution graph root %q must not have a parent", p.nodes[p.rootID].node.name)
	}
	return nil
}

func (p *executionPlan) compileLeafDescendants() error {
	const (
		unvisited uint8 = iota
		visiting
		visited
	)
	state := make(map[proto.TargetID]uint8, len(p.nodes))
	depths := make(map[proto.TargetID]int, len(p.nodes))

	var visit func(proto.TargetID) ([]proto.TargetID, int, error)
	visit = func(id proto.TargetID) ([]proto.TargetID, int, error) {
		entry, ok := p.nodes[id]
		if !ok {
			return nil, 0, fmt.Errorf("engine: execution graph target %x is missing", id)
		}
		switch state[id] {
		case visiting:
			return nil, 0, fmt.Errorf("engine: execution graph contains a cycle at %q", entry.node.name)
		case visited:
			return entry.leafIDs, depths[id], nil
		}

		state[id] = visiting
		depth := 1
		var leaves []proto.TargetID
		if entry.node.kind == proto.GraphNodeKindPath {
			leaves = []proto.TargetID{id}
		} else {
			for _, childID := range entry.node.children {
				childLeaves, childDepth, err := visit(childID)
				if err != nil {
					return nil, 0, err
				}
				leaves = append(leaves, childLeaves...)
				if childDepth+1 > depth {
					depth = childDepth + 1
				}
			}
		}
		if depth > proto.GraphManifestMaxDepth {
			return nil, 0, fmt.Errorf("engine: execution graph depth %d exceeds maximum %d", depth, proto.GraphManifestMaxDepth)
		}
		if len(leaves) == 0 {
			return nil, 0, fmt.Errorf("engine: execution node %q has no path descendants", entry.node.name)
		}

		entry.leafIDs = append([]proto.TargetID(nil), leaves...)
		p.nodes[id] = entry
		depths[id] = depth
		state[id] = visited
		return entry.leafIDs, depth, nil
	}

	if _, _, err := visit(p.rootID); err != nil {
		return err
	}
	if len(state) != len(p.nodes) {
		return fmt.Errorf("engine: execution graph contains %d unreachable node(s)", len(p.nodes)-len(state))
	}
	return nil
}

// root returns an owned view of the plan root.
func (p *executionPlan) root() (executionPlanNode, bool) {
	if p == nil {
		return executionPlanNode{}, false
	}
	return p.node(p.rootID)
}

func (p *executionPlan) hasKind(kind proto.GraphNodeKind) bool {
	if p == nil {
		return false
	}
	for _, entry := range p.nodes {
		if entry.node.kind == kind {
			return true
		}
	}
	return false
}

// node returns an owned view of id. Mutating its slices cannot change p.
func (p *executionPlan) node(id proto.TargetID) (executionPlanNode, bool) {
	if p == nil {
		return executionPlanNode{}, false
	}
	entry, ok := p.nodes[id]
	if !ok {
		return executionPlanNode{}, false
	}
	return cloneExecutionPlanNode(entry.node), true
}

// leafDescendants returns path leaves in deterministic depth-first child
// order. A path node is its own sole leaf descendant.
func (p *executionPlan) leafDescendants(id proto.TargetID) ([]executionPlanLeaf, bool) {
	if p == nil {
		return nil, false
	}
	entry, ok := p.nodes[id]
	if !ok {
		return nil, false
	}
	leaves := make([]executionPlanLeaf, 0, len(entry.leafIDs))
	for _, leafID := range entry.leafIDs {
		leafEntry, ok := p.nodes[leafID]
		if !ok || leafEntry.node.kind != proto.GraphNodeKindPath {
			return nil, false
		}
		leaves = append(leaves, executionPlanLeaf{
			targetID: leafEntry.node.targetID,
			name:     leafEntry.node.name,
			weight:   leafEntry.node.weight,
		})
	}
	return leaves, true
}

// validateImmediateChild accepts only a direct logical edge. In particular,
// selecting a descendant leaf through a selector is rejected.
func (p *executionPlan) validateImmediateChild(parentID, childID proto.TargetID) error {
	if p == nil {
		return fmt.Errorf("engine: execution plan is nil")
	}
	parent, ok := p.nodes[parentID]
	if !ok {
		return fmt.Errorf("engine: execution parent %x is missing", parentID)
	}
	if parent.node.kind == proto.GraphNodeKindPath {
		return fmt.Errorf("engine: path execution node %q cannot have children", parent.node.name)
	}
	if _, ok := p.nodes[childID]; !ok {
		return fmt.Errorf("engine: execution child %x is missing", childID)
	}
	for _, candidate := range parent.node.children {
		if candidate == childID {
			return nil
		}
	}
	return fmt.Errorf("engine: target %x is not an immediate child of %q", childID, parent.node.name)
}

func cloneExecutionPlanNode(node executionPlanNode) executionPlanNode {
	node.children = append([]proto.TargetID(nil), node.children...)
	node.peakCandidates = append([]proto.TargetID(nil), node.peakCandidates...)
	return node
}
