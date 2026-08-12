package l3ingress

import (
	"container/list"
	"context"
	"errors"
	"sync"
	"time"
)

const (
	// DefaultFlowTableActiveCapacity bounds active flows and in-flight routing
	// decisions when the caller leaves ActiveCapacity unset.
	DefaultFlowTableActiveCapacity = 4096
	// DefaultFlowTableClosedCapacity bounds retained diagnostic snapshots when
	// the caller leaves ClosedCapacity unset.
	DefaultFlowTableClosedCapacity = 4096
)

var (
	// ErrFlowTableFull means a new flow could not reserve capacity. Existing
	// flows remain usable and are never evicted to admit the new flow.
	ErrFlowTableFull = errors.New("l3ingress: active flow table is full")
	// ErrFlowGenerationExhausted means the table can no longer assign a unique
	// generation. It is terminal for that table and cannot occur through normal
	// operation.
	ErrFlowGenerationExhausted = errors.New("l3ingress: flow generation exhausted")
)

// FlowCloseReason is a machine-readable reason for ending a tracked
// ingress flow.
type FlowCloseReason string

const (
	FlowCloseManual       FlowCloseReason = "manual"
	FlowCloseIdle         FlowCloseReason = "idle"
	FlowCloseDeviceClosed FlowCloseReason = "device_closed"
	FlowCloseTCPFIN       FlowCloseReason = "tcp_fin"
	FlowCloseTCPRST       FlowCloseReason = "tcp_rst"
)

// FlowTableOptions configures a FlowTable.
type FlowTableOptions struct {
	Now            func() time.Time
	Observer       FlowObserver
	ActiveCapacity int
	ClosedCapacity int
}

// FlowRef identifies one activation generation of an L3 flow. Callers that
// perform asynchronous lifecycle work should retain the ref and use the
// generation-checked methods so stale work cannot affect a reused tuple.
type FlowRef struct {
	Identity   L3Identity
	Generation uint64
}

// FlowSnapshot is a stable copy of one flow table entry.
type FlowSnapshot struct {
	Ref            FlowRef
	Flow           FlowMeta
	Decision       FlowDecision
	Decided        bool
	Packets        uint64
	Bytes          uint64
	FirstSeen      time.Time
	LastSeen       time.Time
	Closed         bool
	ClosedAt       time.Time
	CloseReason    FlowCloseReason
	SelectedPaths  []string
	MigrationCount uint64
}

// FlowObserver receives stable lifecycle/stat snapshots as flows are
// created, updated, and closed.
type FlowObserver interface {
	ObserveFlow(FlowSnapshot)
}

// FlowObserverFunc adapts a function into FlowObserver.
type FlowObserverFunc func(FlowSnapshot)

func (f FlowObserverFunc) ObserveFlow(snapshot FlowSnapshot) {
	f(snapshot)
}

// FlowTable caches the external routing decision for each L3 flow and
// keeps basic lifecycle counters for later TUN adapters and embedders.
type FlowTable struct {
	mu             sync.Mutex
	router         FlowDecisionFunc
	now            func() time.Time
	observer       FlowObserver
	activeCapacity int
	closedCapacity int
	nextGeneration uint64
	active         map[L3Identity]*flowRecord
	activeOrder    list.List
	pending        map[L3Identity]*flowPending
	closed         map[L3Identity]*closedRecord
	closedOrder    list.List
}

type flowRecord struct {
	ref            FlowRef
	flow           FlowMeta
	decision       FlowDecision
	decided        bool
	packets        uint64
	bytes          uint64
	firstSeen      time.Time
	lastSeen       time.Time
	selectedPaths  []string
	migrationCount uint64
	order          *list.Element
}

type flowPending struct {
	done chan struct{}
}

type closedRecord struct {
	snapshot FlowSnapshot
	order    *list.Element
}

// NewFlowTable creates a per-flow decision cache. A nil router is valid
// and records flows without marking them as externally decided.
func NewFlowTable(router FlowDecisionFunc, opts FlowTableOptions) *FlowTable {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	if opts.ActiveCapacity < 0 {
		panic("l3ingress: active flow table capacity must not be negative")
	}
	if opts.ClosedCapacity < 0 {
		panic("l3ingress: closed flow table capacity must not be negative")
	}
	activeCapacity := opts.ActiveCapacity
	if activeCapacity == 0 {
		activeCapacity = DefaultFlowTableActiveCapacity
	}
	closedCapacity := opts.ClosedCapacity
	if closedCapacity == 0 {
		closedCapacity = DefaultFlowTableClosedCapacity
	}
	return &FlowTable{
		router:         router,
		now:            now,
		observer:       opts.Observer,
		activeCapacity: activeCapacity,
		closedCapacity: closedCapacity,
		active:         make(map[L3Identity]*flowRecord),
		pending:        make(map[L3Identity]*flowPending),
		closed:         make(map[L3Identity]*closedRecord),
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
	for {
		t.mu.Lock()
		if rec := t.active[id]; rec != nil {
			rec.packets++
			rec.bytes += uint64(packetLen)
			rec.lastSeen = t.now()
			t.activeOrder.MoveToBack(rec.order)
			snap := rec.snapshot()
			decision := cloneDecision(rec.decision)
			t.mu.Unlock()
			t.observe(snap)
			return decision, false, snap, nil
		}
		if pending := t.pending[id]; pending != nil {
			done := pending.done
			t.mu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return FlowDecision{}, false, FlowSnapshot{}, ctx.Err()
			}
		}
		if len(t.active)+len(t.pending) >= t.activeCapacity {
			t.mu.Unlock()
			return FlowDecision{}, false, FlowSnapshot{}, ErrFlowTableFull
		}
		if t.nextGeneration == ^uint64(0) {
			t.mu.Unlock()
			return FlowDecision{}, false, FlowSnapshot{}, ErrFlowGenerationExhausted
		}
		t.nextGeneration++
		ref := FlowRef{Identity: id, Generation: t.nextGeneration}
		pending := &flowPending{done: make(chan struct{})}
		t.pending[id] = pending
		seenAt := t.now()
		t.mu.Unlock()

		published := false
		defer func() {
			if !published {
				t.releasePending(id, pending)
			}
		}()

		if flow.CreatedAt.IsZero() {
			flow.CreatedAt = seenAt
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
		rec := &flowRecord{
			ref:       ref,
			flow:      flow,
			decision:  decision,
			decided:   decided,
			packets:   1,
			bytes:     uint64(packetLen),
			firstSeen: flow.CreatedAt,
			lastSeen:  seenAt,
		}

		t.mu.Lock()
		if t.pending[id] != pending {
			t.mu.Unlock()
			return FlowDecision{}, false, FlowSnapshot{}, ErrFlowTableFull
		}
		delete(t.pending, id)
		close(pending.done)
		t.active[id] = rec
		rec.order = t.activeOrder.PushBack(rec)
		snap := rec.snapshot()
		published = true
		t.mu.Unlock()
		t.observe(snap)
		return cloneDecision(decision), true, snap, nil
	}
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
	rec, ok := t.closed[id]
	if !ok {
		return FlowSnapshot{}, false
	}
	return cloneSnapshot(rec.snapshot), true
}

// Snapshots returns all active flow snapshots.
func (t *FlowTable) Snapshots() []FlowSnapshot {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]FlowSnapshot, 0, len(t.active))
	for elem := t.activeOrder.Front(); elem != nil; elem = elem.Next() {
		rec := elem.Value.(*flowRecord)
		out = append(out, rec.snapshot())
	}
	return out
}

// Close ends whichever activation generation is currently tracked for id and
// stores a final closed snapshot. Asynchronous callers that can race with tuple
// reuse should use CloseRef instead.
func (t *FlowTable) Close(id L3Identity, reason FlowCloseReason) (FlowSnapshot, bool) {
	return t.closeRef(FlowRef{Identity: id}, reason, false)
}

// CloseRef ends a flow only when ref still names its current activation
// generation. A stale ref is a no-op and cannot close a replacement flow.
func (t *FlowTable) CloseRef(ref FlowRef, reason FlowCloseReason) (FlowSnapshot, bool) {
	return t.closeRef(ref, reason, true)
}

func (t *FlowTable) closeRef(ref FlowRef, reason FlowCloseReason, requireGeneration bool) (FlowSnapshot, bool) {
	if t == nil {
		return FlowSnapshot{}, false
	}
	t.mu.Lock()
	rec := t.active[ref.Identity]
	if rec == nil || requireGeneration && (ref.Generation == 0 || rec.ref.Generation != ref.Generation) {
		t.mu.Unlock()
		return FlowSnapshot{}, false
	}
	snap := t.closeRecordLocked(rec, reason, t.now())
	t.mu.Unlock()
	t.observe(snap)
	return snap, true
}

// ReapIdle closes active flows last seen at or before cutoff. No idle timeout
// is installed implicitly: the owner chooses a protocol-appropriate cutoff and
// receives the same observer lifecycle events as explicit closes.
func (t *FlowTable) ReapIdle(cutoff time.Time) []FlowSnapshot {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	closedAt := t.now()
	var reaped []FlowSnapshot
	for elem := t.activeOrder.Front(); elem != nil; {
		next := elem.Next()
		rec := elem.Value.(*flowRecord)
		if !rec.lastSeen.After(cutoff) {
			reaped = append(reaped, t.closeRecordLocked(rec, FlowCloseIdle, closedAt))
		}
		elem = next
	}
	t.mu.Unlock()
	for _, snapshot := range reaped {
		t.observe(snapshot)
	}
	return reaped
}

// ReapClosed forgets retained closed snapshots whose close time is at or
// before cutoff. Closed snapshots are diagnostic history only; active flow
// state and observer delivery are unaffected.
func (t *FlowTable) ReapClosed(cutoff time.Time) int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	reaped := 0
	for elem := t.closedOrder.Front(); elem != nil; {
		next := elem.Next()
		rec := elem.Value.(*closedRecord)
		if !rec.snapshot.ClosedAt.After(cutoff) {
			t.removeClosedLocked(rec)
			reaped++
		}
		elem = next
	}
	return reaped
}

// RecordPathSelection records the currently selected underlying path names.
func (t *FlowTable) RecordPathSelection(id L3Identity, paths []string) (FlowSnapshot, bool) {
	return t.recordPaths(FlowRef{Identity: id}, paths, false, false)
}

// RecordPathSelectionRef records path state only for the named activation.
func (t *FlowTable) RecordPathSelectionRef(ref FlowRef, paths []string) (FlowSnapshot, bool) {
	return t.recordPaths(ref, paths, false, true)
}

// RecordMigration records that a flow migrated to the given path names.
func (t *FlowTable) RecordMigration(id L3Identity, paths []string) (FlowSnapshot, bool) {
	return t.recordPaths(FlowRef{Identity: id}, paths, true, false)
}

// RecordMigrationRef records a migration only for the named activation.
func (t *FlowTable) RecordMigrationRef(ref FlowRef, paths []string) (FlowSnapshot, bool) {
	return t.recordPaths(ref, paths, true, true)
}

func (t *FlowTable) recordPaths(ref FlowRef, paths []string, migrated, requireGeneration bool) (FlowSnapshot, bool) {
	if t == nil {
		return FlowSnapshot{}, false
	}
	t.mu.Lock()
	rec := t.active[ref.Identity]
	if rec == nil || requireGeneration && (ref.Generation == 0 || rec.ref.Generation != ref.Generation) {
		t.mu.Unlock()
		return FlowSnapshot{}, false
	}
	rec.selectedPaths = cloneStringSlice(paths)
	if migrated {
		rec.migrationCount++
	}
	snap := rec.snapshot()
	t.mu.Unlock()
	t.observe(snap)
	return snap, true
}

func (t *FlowTable) releasePending(id L3Identity, pending *flowPending) {
	t.mu.Lock()
	if t.pending[id] == pending {
		delete(t.pending, id)
		close(pending.done)
	}
	t.mu.Unlock()
}

func (t *FlowTable) closeRecordLocked(rec *flowRecord, reason FlowCloseReason, closedAt time.Time) FlowSnapshot {
	delete(t.active, rec.ref.Identity)
	t.activeOrder.Remove(rec.order)
	rec.order = nil

	snapshot := rec.snapshot()
	snapshot.Closed = true
	snapshot.ClosedAt = closedAt
	snapshot.CloseReason = reason
	if existing := t.closed[rec.ref.Identity]; existing != nil {
		t.removeClosedLocked(existing)
	}
	closed := &closedRecord{snapshot: cloneSnapshot(snapshot)}
	closed.order = t.closedOrder.PushBack(closed)
	t.closed[rec.ref.Identity] = closed
	for len(t.closed) > t.closedCapacity {
		oldest := t.closedOrder.Front().Value.(*closedRecord)
		t.removeClosedLocked(oldest)
	}
	return snapshot
}

func (t *FlowTable) removeClosedLocked(rec *closedRecord) {
	delete(t.closed, rec.snapshot.Ref.Identity)
	t.closedOrder.Remove(rec.order)
	rec.order = nil
}

func (t *FlowTable) observe(snapshot FlowSnapshot) {
	if t == nil || t.observer == nil {
		return
	}
	t.observer.ObserveFlow(cloneSnapshot(snapshot))
}

func (r *flowRecord) snapshot() FlowSnapshot {
	return FlowSnapshot{
		Ref:            r.ref,
		Flow:           cloneFlowMeta(r.flow),
		Decision:       cloneDecision(r.decision),
		Decided:        r.decided,
		Packets:        r.packets,
		Bytes:          r.bytes,
		FirstSeen:      r.firstSeen,
		LastSeen:       r.lastSeen,
		SelectedPaths:  cloneStringSlice(r.selectedPaths),
		MigrationCount: r.migrationCount,
	}
}

func cloneSnapshot(s FlowSnapshot) FlowSnapshot {
	s.Flow = cloneFlowMeta(s.Flow)
	s.Decision = cloneDecision(s.Decision)
	s.SelectedPaths = cloneStringSlice(s.SelectedPaths)
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

func cloneStringSlice(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
