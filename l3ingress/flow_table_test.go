package l3ingress

import (
	"context"
	"net/netip"
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
