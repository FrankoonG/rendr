package l3ingress

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestFlowTableTouchRefAndCloseIdleRefAreGenerationAndCutoffExact(t *testing.T) {
	id := L3Identity{
		Proto: ProtocolUDP,
		SrcIP: netip.MustParseAddr("192.0.2.10"), SrcPort: 41000,
		DstIP: netip.MustParseAddr("198.51.100.10"), DstPort: 53,
	}
	now := time.Unix(10_000, 0)
	var table *FlowTable
	var observed []FlowSnapshot
	table = NewFlowTable(nil, FlowTableOptions{
		Now: func() time.Time { return now },
		Observer: FlowObserverFunc(func(snapshot FlowSnapshot) {
			// Reentry proves callbacks run after FlowTable.mu is released.
			_, _ = table.Snapshot(snapshot.Ref.Identity)
			observed = append(observed, snapshot)
		}),
	})
	_, _, first, err := table.Resolve(context.Background(), FlowMeta{
		L3Identity: id, Direction: DirectionIngress,
	}, 12)
	if err != nil {
		t.Fatal(err)
	}

	now = now.Add(5 * time.Second)
	touched, ok := table.TouchRef(first.Ref)
	if !ok {
		t.Fatal("TouchRef rejected the active generation")
	}
	if !touched.LastSeen.Equal(now) || touched.Packets != 1 || touched.Bytes != 12 {
		t.Fatalf("touch snapshot=%+v", touched)
	}
	if _, ok := table.CloseIdleRef(first.Ref, now.Add(-time.Nanosecond)); ok {
		t.Fatal("CloseIdleRef closed activity newer than cutoff")
	}
	closed, ok := table.CloseIdleRef(first.Ref, now)
	if !ok || closed.Ref != first.Ref || closed.CloseReason != FlowCloseIdle {
		t.Fatalf("exact-cutoff close=%+v ok=%v", closed, ok)
	}

	now = now.Add(time.Second)
	_, created, replacement, err := table.Resolve(context.Background(), FlowMeta{
		L3Identity: id, Direction: DirectionIngress,
	}, 20)
	if err != nil || !created {
		t.Fatalf("replacement created=%v err=%v", created, err)
	}
	if replacement.Ref == first.Ref {
		t.Fatal("replacement reused the closed generation")
	}
	staleTouchTime := now.Add(time.Hour)
	now = staleTouchTime
	if _, ok := table.TouchRef(first.Ref); ok {
		t.Fatal("stale TouchRef updated the replacement")
	}
	if _, ok := table.CloseIdleRef(first.Ref, staleTouchTime); ok {
		t.Fatal("stale CloseIdleRef closed the replacement")
	}
	current, ok := table.Snapshot(id)
	if !ok || current.Ref != replacement.Ref || current.LastSeen.Equal(staleTouchTime) {
		t.Fatalf("replacement after stale work=%+v ok=%v", current, ok)
	}
	if len(observed) != 4 {
		t.Fatalf("observer snapshots=%d want create/touch/close/replacement", len(observed))
	}
}

func TestFlowTableTouchRefRejectsZeroAndMissingRefs(t *testing.T) {
	table := NewFlowTable(nil, FlowTableOptions{})
	if _, ok := table.TouchRef(FlowRef{}); ok {
		t.Fatal("zero TouchRef succeeded")
	}
	if _, ok := table.CloseIdleRef(FlowRef{}, time.Now()); ok {
		t.Fatal("zero CloseIdleRef succeeded")
	}
	missing := FlowRef{
		Identity: L3Identity{
			Proto: ProtocolUDP,
			SrcIP: netip.MustParseAddr("192.0.2.11"), SrcPort: 42000,
			DstIP: netip.MustParseAddr("198.51.100.11"), DstPort: 53,
		},
		Generation: 1,
	}
	if _, ok := table.TouchRef(missing); ok {
		t.Fatal("missing TouchRef succeeded")
	}
	if _, ok := table.CloseIdleRef(missing, time.Now()); ok {
		t.Fatal("missing CloseIdleRef succeeded")
	}
}
