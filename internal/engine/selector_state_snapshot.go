package engine

import (
	"bytes"
	"sort"

	"github.com/FrankoonG/rendr/proto"
)

// SelectorStateSnapshot is one immutable, complete local execution vector.
// StateEpoch changes whenever desired or effective selector routing changes.
type SelectorStateSnapshot struct {
	StateEpoch uint64
	Entries    []proto.SelectorStateEntry
}

// LocalSelectorStateSnapshot returns a publishable vector only when every
// selector in the frozen local graph has an initialized, valid state.
func (e *Engine) LocalSelectorStateSnapshot() (SelectorStateSnapshot, bool) {
	if e == nil {
		return SelectorStateSnapshot{}, false
	}
	runtime := e.localExecutionRuntime()
	if runtime == nil {
		return SelectorStateSnapshot{}, false
	}
	return runtime.selectorStateSnapshot()
}

func (r *executionRuntime) selectorStateSnapshot() (SelectorStateSnapshot, bool) {
	if r == nil || r.plan == nil {
		return SelectorStateSnapshot{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.selectorRevision == 0 {
		return SelectorStateSnapshot{}, false
	}

	selectorCount := 0
	for _, targetID := range r.plan.nodeIDs {
		node, ok := r.plan.nodeView(targetID)
		if ok && node.kind == proto.GraphNodeKindSelector {
			selectorCount++
		}
	}
	if selectorCount == 0 || len(r.selectors) < selectorCount {
		return SelectorStateSnapshot{}, false
	}

	entries := make([]proto.SelectorStateEntry, 0, selectorCount)
	for _, targetID := range r.plan.nodeIDs {
		node, ok := r.plan.nodeView(targetID)
		if !ok || node.kind != proto.GraphNodeKindSelector {
			continue
		}
		state := r.selectors[targetID]
		if state == nil || state.desired == (proto.TargetID{}) ||
			state.effective == (proto.TargetID{}) || state.generation == 0 ||
			r.plan.validateImmediateChild(targetID, state.desired) != nil ||
			r.plan.validateImmediateChild(targetID, state.effective) != nil {
			return SelectorStateSnapshot{}, false
		}
		entries = append(entries, proto.SelectorStateEntry{
			SelectorID:        targetID,
			DesiredTargetID:   state.desired,
			EffectiveTargetID: state.effective,
			Generation:        state.generation,
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		return bytes.Compare(entries[i].SelectorID[:], entries[j].SelectorID[:]) < 0
	})
	return SelectorStateSnapshot{StateEpoch: r.selectorRevision, Entries: entries}, true
}
