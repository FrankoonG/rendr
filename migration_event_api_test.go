package rendr

import (
	"context"
	"testing"
	"time"
)

func TestConnectionObserverMigrationEvent(t *testing.T) {
	ln, err := listenRuntimeTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan Conn, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, acceptErr := ln.Accept(ctx)
		if acceptErr != nil {
			t.Errorf("accept: %v", acceptErr)
			return
		}
		accepted <- conn
	}()

	controlled := newRuntimeControlledTCPTransport(t)
	dialer := &sessionDialer{
		Root: Selector("root", []Target{
			Path("A", controlled.Spec(ln.Addr().String(), "A")),
			Path("B", controlled.Spec(ln.Addr().String(), "B")),
		}),
		Retry: retryPolicy{MinBackoff: 5 * time.Second, MaxBackoff: 5 * time.Second},
	}
	controlled.Bind(t, dialer)

	client, err := dialer.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()
	if !waitForNPaths(t, client, server, controlled.Name(), ln.Addr().String(), 2, 8*time.Second) {
		t.Fatalf("expected two paths, got client=%d server=%d", len(client.Paths()), len(server.Paths()))
	}

	observer := client.(ConnectionObserver)
	events := make(chan MigrationEvent, 1)
	subscription := observer.OnMigrationEvent(func(event MigrationEvent) { events <- event })
	baseline := subscription.AfterOrdinal()
	if baseline != observer.MigrationCount() {
		t.Fatalf("subscription baseline=%d, MigrationCount=%d", baseline, observer.MigrationCount())
	}

	oldID := observer.ActivePath()
	var newID uint32
	for _, path := range client.Paths() {
		if path.ID != oldID {
			newID = path.ID
			break
		}
	}
	if newID == 0 {
		t.Fatal("no alternate path")
	}
	if err := client.(MigrationController).SelectTarget("root", pathNameByID(client.Paths(), newID)); err != nil {
		t.Fatalf("select alternate path: %v", err)
	}

	select {
	case event := <-events:
		if event.OldPathID != oldID || event.NewPathID != newID || event.Cause != "explicit" {
			t.Fatalf("event facts=%+v, want old=%d new=%d cause=explicit", event, oldID, newID)
		}
		if event.Ordinal == 0 || event.Ordinal != observer.MigrationCount() {
			t.Fatalf("event ordinal=%d, MigrationCount=%d", event.Ordinal, observer.MigrationCount())
		}
		if event.CommittedAt.IsZero() {
			t.Fatal("event commit timestamp is zero")
		}
		if event.Evidence.Kind != MigrationEvidenceSelector || event.Evidence.TopologyEpoch == 0 ||
			event.Evidence.HealthEpoch == 0 ||
			len(event.Evidence.ProbeGenerations) != 0 || event.Evidence.TransactionID != ([16]byte{}) ||
			event.Evidence.RefreshEvidenceGeneration != 0 || event.Evidence.SourceEndpointGeneration != 0 ||
			event.Evidence.ResultEndpointGeneration != 0 {
			t.Fatalf("explicit selector evidence=%+v", event.Evidence)
		}
		if event.Evidence.Source.PathID != oldID || event.Evidence.Result.PathID != newID ||
			event.Evidence.Source.PathOwner == 0 || event.Evidence.Result.PathOwner == 0 ||
			event.Evidence.Source.PathGeneration == 0 || event.Evidence.Result.PathGeneration == 0 ||
			event.Evidence.Source.RouteGeneration == 0 || event.Evidence.Result.RouteGeneration == 0 ||
			event.Evidence.Source.HealthRevision == 0 || event.Evidence.Result.HealthRevision == 0 ||
			event.Evidence.Source.LocalTargetID == ([16]byte{}) || event.Evidence.Result.LocalTargetID == ([16]byte{}) ||
			event.Evidence.Source.PeerTargetID == ([16]byte{}) || event.Evidence.Result.PeerTargetID == ([16]byte{}) {
			t.Fatalf("explicit selector physical bindings=%+v/%+v", event.Evidence.Source, event.Evidence.Result)
		}
		if event.Evidence.Selector.SelectorID == ([16]byte{}) || event.Evidence.Selector.TargetID == ([16]byte{}) ||
			event.Evidence.Selector.Origin != "explicit" || event.Evidence.Selector.CutoverGeneration == 0 ||
			!event.Evidence.Selector.CapturedAt.IsZero() || !event.Evidence.Selector.ValidUntil.IsZero() ||
			event.Evidence.Leaf != (MigrationLeafBinding{}) {
			t.Fatalf("explicit selector binding=%+v leaf=%+v", event.Evidence.Selector, event.Evidence.Leaf)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("typed migration event did not fire")
	}
	if err := subscription.Err(); err != nil {
		t.Fatalf("migration event subscription error: %v", err)
	}
	subscription.Cancel()
	select {
	case <-subscription.Done():
	case <-time.After(time.Second):
		t.Fatal("migration event subscription did not quiesce after cancellation")
	}
}
