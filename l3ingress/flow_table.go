package l3ingress

import (
	"context"
	"sync"
	"time"
)

// FlowCloseReason is a machine-readable reason for ending a tracked
// ingress flow.
type FlowCloseReason string

const (
	FlowCloseManual       FlowCloseReason = "manual"
	FlowCloseIdle         FlowCloseReason = "idle"
	FlowCloseDeviceClosed FlowCloseReason = "device_closed"
)

// FlowTableOptions configures a FlowTable.
type FlowTableOptions struct {
	Now func() time.Time
}

// FlowSnapshot is a stable copy of one flow table entry.
type FlowSnapshot struct {
	Flow        FlowMeta
	Decision    FlowDecision
	Decided     bool
	Packets     uint64
	Bytes       uint64
	FirstSeen   time.Time
	LastSeen    time.Time
	Closed      bool
	ClosedAt    time.Time
	CloseReason FlowCloseReason
}

// FlowTable caches the external routing decision for each L3 flow and
// keeps basic lifecycle counters for later TUN adapters and embedders.
type FlowTable struct {
	mu     sync.Mutex
	router FlowDecisionFunc
	now    func() time.Time
	active map[L3Identity]*flowRecord
	closed map[L3Identity]FlowSnapshot
}

type flowRecord struct {
	flow      FlowMeta
	decision  FlowDecision
	decided   bool
	packets   uint64
	bytes     uint64
	firstSeen time.Time
	lastSeen  time.Time
}

// NewFlowTable creates a per-flow decision cache. A nil router is valid
// and records flows without marking them as externally decided.
func NewFlowTable(router FlowDecisionFunc, opts FlowTableOptions) *FlowTable {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &FlowTable{
		router: router,
		now:    now,
		active: make(map[L3Identity]*flowRecord),
		closed: make(map[L3Identity]FlowSnapshot),
	}
}

// Resolve returns the cached decision for flow, creating a new entry and
// invoking the router only on the first packet of a flow.
func (t *FlowTable) Resolve(ctx context.Context, flow FlowMeta, packetLen int) (FlowDecision, bool, FlowSnapshot, error) {
	if t == nil {
		return FlowDecision{}, false, FlowSnapshot{}, nil
	}
	if packetLen < 0 {
		packetLen = 0
	}
	id := flow.L3Identity
	t.mu.Lock()
	if rec := t.active[id]; rec != nil {
		rec.packets++
		rec.bytes += uint64(packetLen)
		rec.lastSeen = t.now()
		snap := rec.snapshot()
		t.mu.Unlock()
		return cloneDecision(rec.decision), false, snap, nil
	}
	t.mu.Unlock()

	if flow.CreatedAt.IsZero() {
		flow.CreatedAt = t.now()
	}
	flow = cloneFlowMeta(flow)
	var decision FlowDecision
	decided := false
	if t.router != nil {
		var err error
		decision, err = t.router(ctx, flow)
		if err != nil {
			return FlowDecision{}, false, FlowSnapshot{}, err
		}
		decision = cloneDecision(decision)
		decided = true
	}
	now := flow.CreatedAt
	rec := &flowRecord{
		flow:      flow,
		decision:  decision,
		decided:   decided,
		packets:   1,
		bytes:     uint64(packetLen),
		firstSeen: now,
		lastSeen:  now,
	}

	t.mu.Lock()
	if existing := t.active[id]; existing != nil {
		existing.packets++
		existing.bytes += uint64(packetLen)
		existing.lastSeen = t.now()
		snap := existing.snapshot()
		t.mu.Unlock()
		return cloneDecision(existing.decision), false, snap, nil
	}
	t.active[id] = rec
	snap := rec.snapshot()
	t.mu.Unlock()
	return cloneDecision(decision), true, snap, nil
}

// Snapshot returns one active flow snapshot.
func (t *FlowTable) Snapshot(id L3Identity) (FlowSnapshot, bool) {
	if t == nil {
		return FlowSnapshot{}, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	rec := t.active[id]
	if rec == nil {
		return FlowSnapshot{}, false
	}
	return rec.snapshot(), true
}

// ClosedSnapshot returns the last closed snapshot for id, if present.
func (t *FlowTable) ClosedSnapshot(id L3Identity) (FlowSnapshot, bool) {
	if t == nil {
		return FlowSnapshot{}, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	snap, ok := t.closed[id]
	if !ok {
		return FlowSnapshot{}, false
	}
	return cloneSnapshot(snap), true
}

// Snapshots returns all active flow snapshots.
func (t *FlowTable) Snapshots() []FlowSnapshot {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]FlowSnapshot, 0, len(t.active))
	for _, rec := range t.active {
		out = append(out, rec.snapshot())
	}
	return out
}

// Close ends active tracking for id and stores a final closed snapshot.
func (t *FlowTable) Close(id L3Identity, reason FlowCloseReason) (FlowSnapshot, bool) {
	if t == nil {
		return FlowSnapshot{}, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	rec := t.active[id]
	if rec == nil {
		return FlowSnapshot{}, false
	}
	delete(t.active, id)
	snap := rec.snapshot()
	snap.Closed = true
	snap.ClosedAt = t.now()
	snap.CloseReason = reason
	t.closed[id] = cloneSnapshot(snap)
	return snap, true
}

func (r *flowRecord) snapshot() FlowSnapshot {
	return FlowSnapshot{
		Flow:      cloneFlowMeta(r.flow),
		Decision:  cloneDecision(r.decision),
		Decided:   r.decided,
		Packets:   r.packets,
		Bytes:     r.bytes,
		FirstSeen: r.firstSeen,
		LastSeen:  r.lastSeen,
	}
}

func cloneSnapshot(s FlowSnapshot) FlowSnapshot {
	s.Flow = cloneFlowMeta(s.Flow)
	s.Decision = cloneDecision(s.Decision)
	return s
}

func cloneFlowMeta(flow FlowMeta) FlowMeta {
	flow.Labels = cloneStringMap(flow.Labels)
	return flow
}

func cloneDecision(decision FlowDecision) FlowDecision {
	decision.Labels = cloneStringMap(decision.Labels)
	return decision
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
