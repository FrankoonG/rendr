package l3ingress

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestFlowTableCachesDecisionAndStats(t *testing.T) {
	id := L3Identity{
		Proto:   ProtocolTCP,
		SrcIP:   netip.MustParseAddr("10.0.0.1"),
		SrcPort: 1000,
		DstIP:   netip.MustParseAddr("203.0.113.1"),
		DstPort: 443,
	}
	created := time.Unix(100, 0)
	now := created
	var calls int
	table := NewFlowTable(func(_ context.Context, flow FlowMeta) (FlowDecision, error) {
		calls++
		if flow.L3Identity != id {
			t.Fatalf("router identity=%+v want %+v", flow.L3Identity, id)
		}
		return FlowDecision{
			Peer:   "peer-a",
			Egress: "direct",
			Labels: map[string]string{"class": "bulk"},
		}, nil
	}, FlowTableOptions{Now: func() time.Time { return now }})

	decision, createdFlow, snapshot, err := table.Resolve(context.Background(), FlowMeta{
		L3Identity: id,
		Direction:  DirectionIngress,
		CreatedAt:  created,
		Labels:     map[string]string{"user": "alice"},
	}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !createdFlow || calls != 1 || decision.Peer != "peer-a" || !snapshot.Decided {
		t.Fatalf("first resolve created=%v calls=%d decision=%+v snapshot=%+v", createdFlow, calls, decision, snapshot)
	}
	now = created.Add(2 * time.Second)
	decision.Labels["class"] = "mutated"

	decision, createdFlow, snapshot, err = table.Resolve(context.Background(), FlowMeta{
		L3Identity: id,
		Direction:  DirectionIngress,
		CreatedAt:  created.Add(time.Hour),
	}, 25)
	if err != nil {
		t.Fatal(err)
	}
	if createdFlow || calls != 1 {
		t.Fatalf("second resolve created=%v calls=%d want false/1", createdFlow, calls)
	}
	if decision.Labels["class"] != "bulk" {
		t.Fatalf("decision labels were not isolated: %+v", decision.Labels)
	}
	if snapshot.Packets != 2 || snapshot.Bytes != 125 {
		t.Fatalf("stats packets=%d bytes=%d want 2/125", snapshot.Packets, snapshot.Bytes)
	}
	if !snapshot.Flow.CreatedAt.Equal(created) || !snapshot.LastSeen.Equal(created.Add(2*time.Second)) {
		t.Fatalf("snapshot times=%+v", snapshot)
	}
	if snapshot.Flow.Labels["user"] != "alice" {
		t.Fatalf("flow labels=%+v", snapshot.Flow.Labels)
	}
}

func TestFlowTableCloseSnapshot(t *testing.T) {
	id := L3Identity{
		Proto:   ProtocolUDP,
		SrcIP:   netip.MustParseAddr("192.0.2.10"),
		SrcPort: 5353,
		DstIP:   netip.MustParseAddr("192.0.2.11"),
		DstPort: 53,
	}
	now := time.Unix(200, 0)
	table := NewFlowTable(nil, FlowTableOptions{Now: func() time.Time { return now }})
	if _, _, _, err := table.Resolve(context.Background(), FlowMeta{L3Identity: id, Direction: DirectionIngress}, 12); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	closed, ok := table.Close(id, FlowCloseIdle)
	if !ok {
		t.Fatal("Close returned false")
	}
	if !closed.Closed || closed.CloseReason != FlowCloseIdle || closed.Packets != 1 || closed.Bytes != 12 {
		t.Fatalf("closed snapshot=%+v", closed)
	}
	if _, ok := table.Snapshot(id); ok {
		t.Fatal("closed flow still active")
	}
	stored, ok := table.ClosedSnapshot(id)
	if !ok || !stored.ClosedAt.Equal(closed.ClosedAt) || stored.CloseReason != FlowCloseIdle {
		t.Fatalf("stored closed snapshot=%+v ok=%v", stored, ok)
	}
}

func TestFlowTableCachesDeniedDecision(t *testing.T) {
	id := L3Identity{
		Proto:   ProtocolUDP,
		SrcIP:   netip.MustParseAddr("10.0.0.3"),
		SrcPort: 1234,
		DstIP:   netip.MustParseAddr("203.0.113.3"),
		DstPort: 53,
	}
	var calls int
	table := NewFlowTable(func(context.Context, FlowMeta) (FlowDecision, error) {
		calls++
		return FlowDecision{Deny: true, DenyReason: "policy_blocked"}, nil
	}, FlowTableOptions{})
	decision, created, snapshot, err := table.Resolve(context.Background(), FlowMeta{
		L3Identity: id,
		Direction:  DirectionIngress,
	}, 40)
	if err != nil {
		t.Fatal(err)
	}
	if !created || !decision.Deny || decision.DenyReason != "policy_blocked" || !snapshot.Decision.Deny {
		t.Fatalf("first denied decision=%+v created=%v snapshot=%+v", decision, created, snapshot)
	}
	decision, created, snapshot, err = table.Resolve(context.Background(), FlowMeta{
		L3Identity: id,
		Direction:  DirectionIngress,
	}, 20)
	if err != nil {
		t.Fatal(err)
	}
	if created || calls != 1 {
		t.Fatalf("denied decision was not cached created=%v calls=%d", created, calls)
	}
	if !decision.Deny || snapshot.Packets != 2 || snapshot.Bytes != 60 {
		t.Fatalf("cached denied decision=%+v snapshot=%+v", decision, snapshot)
	}
}

func TestFlowTableObserverReceivesLifecycleSnapshots(t *testing.T) {
	id := L3Identity{
		Proto:   ProtocolUDP,
		SrcIP:   netip.MustParseAddr("10.0.0.4"),
		SrcPort: 1111,
		DstIP:   netip.MustParseAddr("203.0.113.4"),
		DstPort: 2222,
	}
	var snapshots []FlowSnapshot
	table := NewFlowTable(func(context.Context, FlowMeta) (FlowDecision, error) {
		return FlowDecision{Peer: "peer-a", Labels: map[string]string{"route": "fast"}}, nil
	}, FlowTableOptions{
		Observer: FlowObserverFunc(func(snapshot FlowSnapshot) {
			snapshots = append(snapshots, snapshot)
		}),
	})
	if _, _, _, err := table.Resolve(context.Background(), FlowMeta{L3Identity: id, Direction: DirectionIngress}, 10); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := table.Resolve(context.Background(), FlowMeta{L3Identity: id, Direction: DirectionIngress}, 15); err != nil {
		t.Fatal(err)
	}
	if _, ok := table.Close(id, FlowCloseIdle); !ok {
		t.Fatal("Close returned false")
	}
	if len(snapshots) != 3 {
		t.Fatalf("snapshots=%d want 3: %+v", len(snapshots), snapshots)
	}
	if snapshots[0].Packets != 1 || snapshots[0].Bytes != 10 || snapshots[0].Closed {
		t.Fatalf("created snapshot=%+v", snapshots[0])
	}
	if snapshots[1].Packets != 2 || snapshots[1].Bytes != 25 || snapshots[1].Closed {
		t.Fatalf("updated snapshot=%+v", snapshots[1])
	}
	if !snapshots[2].Closed || snapshots[2].CloseReason != FlowCloseIdle || snapshots[2].Packets != 2 {
		t.Fatalf("closed snapshot=%+v", snapshots[2])
	}
	snapshots[0].Decision.Labels["route"] = "mutated"
	stored, ok := table.ClosedSnapshot(id)
	if !ok {
		t.Fatal("closed snapshot missing")
	}
	if stored.Decision.Labels["route"] != "fast" {
		t.Fatalf("observer snapshot mutated table storage: %+v", stored.Decision.Labels)
	}
}

func TestFlowTableRecordsPathSelectionAndMigrations(t *testing.T) {
	id := L3Identity{
		Proto:   ProtocolTCP,
		SrcIP:   netip.MustParseAddr("10.0.0.5"),
		SrcPort: 1111,
		DstIP:   netip.MustParseAddr("203.0.113.5"),
		DstPort: 443,
	}
	var snapshots []FlowSnapshot
	table := NewFlowTable(nil, FlowTableOptions{
		Observer: FlowObserverFunc(func(snapshot FlowSnapshot) {
			snapshots = append(snapshots, snapshot)
		}),
	})
	if _, _, _, err := table.Resolve(context.Background(), FlowMeta{L3Identity: id, Direction: DirectionIngress}, 10); err != nil {
		t.Fatal(err)
	}
	snapshot, ok := table.RecordPathSelection(id, []string{"low-latency"})
	if !ok {
		t.Fatal("RecordPathSelection returned false")
	}
	if snapshot.MigrationCount != 0 || len(snapshot.SelectedPaths) != 1 || snapshot.SelectedPaths[0] != "low-latency" {
		t.Fatalf("selection snapshot=%+v", snapshot)
	}
	paths := []string{"bulk-a", "bulk-b"}
	snapshot, ok = table.RecordMigration(id, paths)
	if !ok {
		t.Fatal("RecordMigration returned false")
	}
	paths[0] = "mutated"
	if snapshot.MigrationCount != 1 || len(snapshot.SelectedPaths) != 2 || snapshot.SelectedPaths[0] != "bulk-a" {
		t.Fatalf("migration snapshot=%+v", snapshot)
	}
	stored, ok := table.Snapshot(id)
	if !ok {
		t.Fatal("active snapshot missing")
	}
	if stored.MigrationCount != 1 || stored.SelectedPaths[0] != "bulk-a" {
		t.Fatalf("stored snapshot=%+v", stored)
	}
	stored.SelectedPaths[0] = "mutated-again"
	stored, _ = table.Snapshot(id)
	if stored.SelectedPaths[0] != "bulk-a" {
		t.Fatalf("path selection was not isolated: %+v", stored.SelectedPaths)
	}
	if len(snapshots) != 3 {
		t.Fatalf("observer snapshots=%d want 3", len(snapshots))
	}
	if snapshots[2].MigrationCount != 1 || snapshots[2].SelectedPaths[1] != "bulk-b" {
		t.Fatalf("observer migration snapshot=%+v", snapshots[2])
	}
}

func TestFlowTableTracksIndependentSelectorFlows(t *testing.T) {
	interactive := L3Identity{
		Proto:   ProtocolTCP,
		SrcIP:   netip.MustParseAddr("10.0.0.10"),
		SrcPort: 42000,
		DstIP:   netip.MustParseAddr("203.0.113.10"),
		DstPort: 22,
	}
	bulk := L3Identity{
		Proto:   ProtocolTCP,
		SrcIP:   netip.MustParseAddr("10.0.0.11"),
		SrcPort: 43000,
		DstIP:   netip.MustParseAddr("203.0.113.11"),
		DstPort: 443,
	}
	calls := map[L3Identity]int{}
	table := NewFlowTable(func(_ context.Context, flow FlowMeta) (FlowDecision, error) {
		calls[flow.L3Identity]++
		switch flow.L3Identity {
		case interactive:
			return FlowDecision{
				Peer:   "peer-low",
				Egress: "direct",
				Labels: map[string]string{"class": "interactive"},
			}, nil
		case bulk:
			return FlowDecision{
				Peer:   "peer-bulk",
				Egress: "bond-egress",
				Labels: map[string]string{"class": "bulk"},
			}, nil
		default:
			t.Fatalf("unexpected flow identity: %+v", flow.L3Identity)
			return FlowDecision{}, nil
		}
	}, FlowTableOptions{})

	if _, created, _, err := table.Resolve(context.Background(), FlowMeta{
		L3Identity: interactive,
		Direction:  DirectionIngress,
	}, 64); err != nil || !created {
		t.Fatalf("interactive resolve created=%v err=%v", created, err)
	}
	if _, created, _, err := table.Resolve(context.Background(), FlowMeta{
		L3Identity: bulk,
		Direction:  DirectionIngress,
	}, 512); err != nil || !created {
		t.Fatalf("bulk resolve created=%v err=%v", created, err)
	}

	if _, ok := table.RecordPathSelection(interactive, []string{"path-a-low"}); !ok {
		t.Fatal("interactive path selection returned false")
	}
	if _, ok := table.RecordPathSelection(bulk, []string{"path-a-low"}); !ok {
		t.Fatal("bulk path selection returned false")
	}
	peakPaths := []string{"path-bulk-b", "path-bulk-c"}
	if _, ok := table.RecordMigration(bulk, peakPaths); !ok {
		t.Fatal("bulk migration returned false")
	}
	peakPaths[0] = "mutated"

	interactiveSnap, ok := table.Snapshot(interactive)
	if !ok {
		t.Fatal("interactive snapshot missing")
	}
	bulkSnap, ok := table.Snapshot(bulk)
	if !ok {
		t.Fatal("bulk snapshot missing")
	}
	if calls[interactive] != 1 || calls[bulk] != 1 {
		t.Fatalf("router calls interactive=%d bulk=%d want 1/1", calls[interactive], calls[bulk])
	}
	if interactiveSnap.Decision.Labels["class"] != "interactive" || interactiveSnap.Decision.Egress != "direct" {
		t.Fatalf("interactive decision leaked or changed: %+v", interactiveSnap.Decision)
	}
	if bulkSnap.Decision.Labels["class"] != "bulk" || bulkSnap.Decision.Egress != "bond-egress" {
		t.Fatalf("bulk decision leaked or changed: %+v", bulkSnap.Decision)
	}
	if interactiveSnap.MigrationCount != 0 || len(interactiveSnap.SelectedPaths) != 1 || interactiveSnap.SelectedPaths[0] != "path-a-low" {
		t.Fatalf("interactive selection changed by bulk migration: %+v", interactiveSnap)
	}
	if bulkSnap.MigrationCount != 1 || len(bulkSnap.SelectedPaths) != 2 || bulkSnap.SelectedPaths[0] != "path-bulk-b" || bulkSnap.SelectedPaths[1] != "path-bulk-c" {
		t.Fatalf("bulk migration not tracked independently: %+v", bulkSnap)
	}

	bulkSnap.SelectedPaths[0] = "mutated-again"
	storedBulk, ok := table.Snapshot(bulk)
	if !ok {
		t.Fatal("stored bulk snapshot missing")
	}
	if storedBulk.SelectedPaths[0] != "path-bulk-b" {
		t.Fatalf("bulk selected paths were not isolated: %+v", storedBulk.SelectedPaths)
	}
}

func TestFlowTableCapacityChargesPendingAndPreservesActiveFlow(t *testing.T) {
	first := flowTableTestIdentity(10001)
	second := flowTableTestIdentity(10002)
	entered := make(chan struct{})
	release := make(chan struct{})
	var routerCalls atomic.Int32
	table := NewFlowTable(func(_ context.Context, flow FlowMeta) (FlowDecision, error) {
		routerCalls.Add(1)
		if flow.L3Identity == first {
			close(entered)
			<-release
		}
		return FlowDecision{Peer: "peer-a"}, nil
	}, FlowTableOptions{ActiveCapacity: 1, ClosedCapacity: 1})

	type resolveResult struct {
		created  bool
		snapshot FlowSnapshot
		err      error
	}
	firstResult := make(chan resolveResult, 1)
	go func() {
		_, created, snapshot, err := table.Resolve(context.Background(), FlowMeta{
			L3Identity: first,
			Direction:  DirectionIngress,
		}, 10)
		firstResult <- resolveResult{created: created, snapshot: snapshot, err: err}
	}()

	<-entered
	table.mu.Lock()
	active, pending := len(table.active), len(table.pending)
	table.mu.Unlock()
	if active != 0 || pending != 1 || active+pending > table.activeCapacity {
		t.Fatalf("reserved cardinality active=%d pending=%d capacity=%d", active, pending, table.activeCapacity)
	}
	if _, created, _, err := table.Resolve(context.Background(), FlowMeta{
		L3Identity: second,
		Direction:  DirectionIngress,
	}, 20); !errors.Is(err, ErrFlowTableFull) || created {
		t.Fatalf("capacity resolve created=%v err=%v want false/%v", created, err, ErrFlowTableFull)
	}
	if got := routerCalls.Load(); got != 1 {
		t.Fatalf("router calls under pending capacity=%d want 1", got)
	}

	close(release)
	result := <-firstResult
	if result.err != nil || !result.created {
		t.Fatalf("first resolve created=%v err=%v", result.created, result.err)
	}
	if result.snapshot.Ref.Identity != first || result.snapshot.Ref.Generation == 0 {
		t.Fatalf("first flow ref=%+v", result.snapshot.Ref)
	}

	_, created, updated, err := table.Resolve(context.Background(), FlowMeta{
		L3Identity: first,
		Direction:  DirectionIngress,
	}, 5)
	if err != nil || created {
		t.Fatalf("existing resolve created=%v err=%v", created, err)
	}
	if updated.Ref != result.snapshot.Ref || updated.Packets != 2 || updated.Bytes != 15 {
		t.Fatalf("existing flow changed under capacity: %+v", updated)
	}
	if got := routerCalls.Load(); got != 1 {
		t.Fatalf("cached flow rerouted under capacity: calls=%d", got)
	}

	if _, ok := table.CloseRef(result.snapshot.Ref, FlowCloseManual); !ok {
		t.Fatal("generation-checked close did not release active capacity")
	}
	if _, created, _, err := table.Resolve(context.Background(), FlowMeta{
		L3Identity: second,
		Direction:  DirectionIngress,
	}, 20); err != nil || !created {
		t.Fatalf("resolve after capacity release created=%v err=%v", created, err)
	}
	if got := routerCalls.Load(); got != 2 {
		t.Fatalf("router calls after capacity release=%d want 2", got)
	}
}

func TestFlowTableRouterFailureReleasesReservedCapacity(t *testing.T) {
	first := flowTableTestIdentity(10501)
	second := flowTableTestIdentity(10502)
	routeErr := errors.New("route failed")
	table := NewFlowTable(func(_ context.Context, flow FlowMeta) (FlowDecision, error) {
		if flow.L3Identity == first {
			return FlowDecision{}, routeErr
		}
		return FlowDecision{Peer: "peer-b"}, nil
	}, FlowTableOptions{ActiveCapacity: 1, ClosedCapacity: 1})

	if _, created, _, err := table.Resolve(context.Background(), FlowMeta{
		L3Identity: first,
		Direction:  DirectionIngress,
	}, 10); !errors.Is(err, routeErr) || created {
		t.Fatalf("failed route created=%v err=%v", created, err)
	}
	table.mu.Lock()
	active, pending := len(table.active), len(table.pending)
	table.mu.Unlock()
	if active != 0 || pending != 0 {
		t.Fatalf("failed route retained capacity active=%d pending=%d", active, pending)
	}
	if _, created, _, err := table.Resolve(context.Background(), FlowMeta{
		L3Identity: second,
		Direction:  DirectionIngress,
	}, 20); err != nil || !created {
		t.Fatalf("resolve after failed route created=%v err=%v", created, err)
	}
}

func TestFlowTableIdleReapRejectsStaleGenerationWork(t *testing.T) {
	oldID := flowTableTestIdentity(11001)
	survivorID := flowTableTestIdentity(11002)
	now := time.Unix(1000, 0)
	var observedClosed []FlowSnapshot
	table := NewFlowTable(nil, FlowTableOptions{
		Now:            func() time.Time { return now },
		ActiveCapacity: 2,
		ClosedCapacity: 2,
		Observer: FlowObserverFunc(func(snapshot FlowSnapshot) {
			if snapshot.Closed {
				observedClosed = append(observedClosed, snapshot)
			}
		}),
	})

	_, _, oldSnapshot, err := table.Resolve(context.Background(), FlowMeta{
		L3Identity: oldID,
		Direction:  DirectionIngress,
	}, 10)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if _, _, _, err := table.Resolve(context.Background(), FlowMeta{
		L3Identity: survivorID,
		Direction:  DirectionIngress,
	}, 20); err != nil {
		t.Fatal(err)
	}
	cutoff := now
	now = now.Add(time.Second)
	if _, created, _, err := table.Resolve(context.Background(), FlowMeta{
		L3Identity: survivorID,
		Direction:  DirectionIngress,
	}, 5); err != nil || created {
		t.Fatalf("survivor refresh created=%v err=%v", created, err)
	}
	now = now.Add(time.Second)

	reaped := table.ReapIdle(cutoff)
	if len(reaped) != 1 || reaped[0].Ref != oldSnapshot.Ref {
		t.Fatalf("reaped=%+v want only ref %+v", reaped, oldSnapshot.Ref)
	}
	if !reaped[0].Closed || reaped[0].CloseReason != FlowCloseIdle || !reaped[0].ClosedAt.Equal(now) {
		t.Fatalf("idle snapshot=%+v", reaped[0])
	}
	if len(observedClosed) != 1 || observedClosed[0].Ref != oldSnapshot.Ref {
		t.Fatalf("closed observer snapshots=%+v", observedClosed)
	}
	if _, ok := table.Snapshot(survivorID); !ok {
		t.Fatal("fresh survivor was reaped")
	}

	now = now.Add(time.Second)
	_, created, replacement, err := table.Resolve(context.Background(), FlowMeta{
		L3Identity: oldID,
		Direction:  DirectionIngress,
	}, 30)
	if err != nil || !created {
		t.Fatalf("replacement resolve created=%v err=%v", created, err)
	}
	if replacement.Ref.Generation == oldSnapshot.Ref.Generation {
		t.Fatalf("replacement reused generation %d", replacement.Ref.Generation)
	}
	if _, ok := table.CloseRef(oldSnapshot.Ref, FlowCloseTCPRST); ok {
		t.Fatal("stale close removed replacement generation")
	}
	if _, ok := table.RecordMigrationRef(oldSnapshot.Ref, []string{"stale-path"}); ok {
		t.Fatal("stale migration mutated replacement generation")
	}
	current, ok := table.Snapshot(oldID)
	if !ok || current.Ref != replacement.Ref || current.MigrationCount != 0 || current.Closed {
		t.Fatalf("replacement after stale work=%+v ok=%v", current, ok)
	}
	closed, ok := table.ClosedSnapshot(oldID)
	if !ok || closed.Ref != oldSnapshot.Ref || closed.CloseReason != FlowCloseIdle {
		t.Fatalf("closed history changed by stale work=%+v ok=%v", closed, ok)
	}
}

func TestFlowTableClosedHistoryCapacityAndExplicitReap(t *testing.T) {
	base := time.Unix(2000, 0)
	now := base
	table := NewFlowTable(nil, FlowTableOptions{
		Now:            func() time.Time { return now },
		ActiveCapacity: 1,
		ClosedCapacity: 2,
	})
	ids := []L3Identity{
		flowTableTestIdentity(12001),
		flowTableTestIdentity(12002),
		flowTableTestIdentity(12003),
	}
	for index, id := range ids {
		now = base.Add(time.Duration(index) * time.Second)
		_, _, snapshot, err := table.Resolve(context.Background(), FlowMeta{
			L3Identity: id,
			Direction:  DirectionIngress,
		}, index+1)
		if err != nil {
			t.Fatalf("resolve %d: %v", index, err)
		}
		now = now.Add(500 * time.Millisecond)
		if _, ok := table.CloseRef(snapshot.Ref, FlowCloseManual); !ok {
			t.Fatalf("close %d returned false", index)
		}
		if len(table.closed) > 2 {
			t.Fatalf("closed history exceeded capacity: %d", len(table.closed))
		}
	}

	if _, ok := table.ClosedSnapshot(ids[0]); ok {
		t.Fatal("oldest closed snapshot survived capacity pressure")
	}
	for _, id := range ids[1:] {
		if _, ok := table.ClosedSnapshot(id); !ok {
			t.Fatalf("recent closed snapshot missing for %s", id)
		}
	}
	if got := table.ReapClosed(base.Add(1500 * time.Millisecond)); got != 1 {
		t.Fatalf("ReapClosed removed=%d want 1", got)
	}
	if _, ok := table.ClosedSnapshot(ids[1]); ok {
		t.Fatal("closed snapshot at cutoff was not reaped")
	}
	if _, ok := table.ClosedSnapshot(ids[2]); !ok {
		t.Fatal("newer closed snapshot was reaped")
	}
	if got := table.ReapClosed(now.Add(time.Second)); got != 1 {
		t.Fatalf("final ReapClosed removed=%d want 1", got)
	}
	if len(table.closed) != 0 || table.closedOrder.Len() != 0 {
		t.Fatalf("closed indexes diverged: map=%d order=%d", len(table.closed), table.closedOrder.Len())
	}
}

func flowTableTestIdentity(srcPort uint16) L3Identity {
	return L3Identity{
		Proto:   ProtocolUDP,
		SrcIP:   netip.MustParseAddr("192.0.2.100"),
		SrcPort: srcPort,
		DstIP:   netip.MustParseAddr("198.51.100.100"),
		DstPort: 443,
	}
}
