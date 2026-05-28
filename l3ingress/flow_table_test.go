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
