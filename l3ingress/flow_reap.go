package l3ingress

import "time"

// TouchRef records non-ingress activity for the exact flow activation. It
// updates only lifetime state; ingress packet and byte counters remain tied to
// Resolve.
func (t *FlowTable) TouchRef(ref FlowRef) (FlowSnapshot, bool) {
	if t == nil || ref == (FlowRef{}) || ref.Generation == 0 {
		return FlowSnapshot{}, false
	}
	t.mu.Lock()
	rec := t.active[ref.Identity]
	if rec == nil || rec.ref != ref {
		t.mu.Unlock()
		return FlowSnapshot{}, false
	}
	rec.lastSeen = t.now()
	t.activeOrder.MoveToBack(rec.order)
	snapshot := rec.snapshot()
	t.mu.Unlock()
	t.observe(snapshot)
	return snapshot, true
}

// CloseIdleRef closes ref only when it is still the active generation and its
// last activity is at or before cutoff. The generation and cutoff checks share
// the same FlowTable critical section as removal.
func (t *FlowTable) CloseIdleRef(ref FlowRef, cutoff time.Time) (FlowSnapshot, bool) {
	if t == nil || ref == (FlowRef{}) || ref.Generation == 0 {
		return FlowSnapshot{}, false
	}
	t.mu.Lock()
	rec := t.active[ref.Identity]
	if rec == nil || rec.ref != ref || rec.lastSeen.After(cutoff) {
		t.mu.Unlock()
		return FlowSnapshot{}, false
	}
	snapshot := t.closeRecordLocked(rec, FlowCloseIdle, t.now())
	t.mu.Unlock()
	t.observe(snapshot)
	return snapshot, true
}
