package engine

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
)

func TestEnginePeerInstanceIdentityIsImmutableAndConcurrentSafe(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{})
	t.Cleanup(func() { _ = e.Close() })
	peer := proto.InstanceID{1}
	if err := e.installPeerInstanceID(peer); err != nil {
		t.Fatal(err)
	}
	if err := e.installPeerInstanceID(proto.InstanceID{2}); err == nil {
		t.Fatal("peer identity changed after initial publication")
	}
	var wg sync.WaitGroup
	for index := 0; index < 16; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for iteration := 0; iteration < 100; iteration++ {
				e.SetPeerInstanceID(peer)
				if got := e.PeerInstanceID(); got != peer {
					t.Errorf("peer identity=%x want=%x", got, peer)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestEngineCloseCannotResurrectPeerLedgerSession(t *testing.T) {
	for iteration := 0; iteration < 100; iteration++ {
		e := New(SideClient, NewClientFlowID(), Limits{})
		ledger := NewLeafMobilityPeerLedger()
		e.SetLeafMobilityPeerLedger(ledger)
		peer := proto.InstanceID{byte(iteration + 1), 1}
		start := make(chan struct{})
		installed := make(chan error, 1)
		closed := make(chan error, 1)
		go func() {
			<-start
			installed <- e.installPeerInstanceID(peer)
		}()
		go func() {
			<-start
			closed <- e.Close()
		}()
		close(start)
		<-installed
		if err := <-closed; err != nil {
			t.Fatal(err)
		}
		<-e.Closed()
		ledger.mu.Lock()
		refs := len(ledger.sessions)
		ledger.mu.Unlock()
		if refs != 0 {
			t.Fatalf("iteration %d retained %d sessions after close", iteration, refs)
		}
		if err := e.installPeerInstanceID(peer); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("iteration %d late identity error=%v want closed", iteration, err)
		}
	}
}

func TestEngineCloseSerializesPeerLedgerReplacement(t *testing.T) {
	for iteration := 0; iteration < 100; iteration++ {
		e := New(SideClient, NewClientFlowID(), Limits{})
		first := NewLeafMobilityPeerLedger()
		second := NewLeafMobilityPeerLedger()
		e.SetLeafMobilityPeerLedger(first)
		if err := e.installPeerInstanceID(proto.InstanceID{byte(iteration + 1), 2}); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		closed := make(chan error, 1)
		replaced := make(chan struct{})
		go func() {
			<-start
			e.SetLeafMobilityPeerLedger(second)
			close(replaced)
		}()
		go func() {
			<-start
			closed <- e.Close()
		}()
		close(start)
		<-replaced
		if err := <-closed; err != nil {
			t.Fatal(err)
		}
		<-e.Closed()
		for name, ledger := range map[string]*LeafMobilityPeerLedger{"first": first, "second": second} {
			ledger.mu.Lock()
			refs := len(ledger.sessions)
			ledger.mu.Unlock()
			if refs != 0 {
				t.Fatalf("iteration %d %s ledger retained %d sessions", iteration, name, refs)
			}
		}
	}
}

func bridgeHandshakeEngine(t *testing.T) *Engine {
	t.Helper()
	manifest, _ := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
	)
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	e.SetLocalInstanceID(proto.InstanceID{1})
	e.SetPeerInstanceID(proto.InstanceID{2})
	return e
}

func TestBridgeHandshakeContextClosesBlockedCandidate(t *testing.T) {
	e := bridgeHandshakeEngine(t)
	t.Cleanup(func() { _ = e.Close() })
	candidate, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = peer.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := PerformClientBridgeTagAckContext(ctx, candidate, e, "a")
		result <- err
	}()
	if _, _, err := ReadFirstFrame(peer); err != nil {
		t.Fatalf("read BRIDGE_TAG: %v", err)
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("bridge handshake error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("bridge handshake ignored context cancellation")
	}
	select {
	case <-candidate.closed:
	default:
		t.Fatal("context cancellation did not close candidate path")
	}
}

func TestBridgeHandshakeEngineCloseClosesBlockedCandidate(t *testing.T) {
	e := bridgeHandshakeEngine(t)
	candidate, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = peer.Close() })
	result := make(chan error, 1)
	go func() {
		_, err := PerformClientBridgeTagAckContext(context.Background(), candidate, e, "a")
		result <- err
	}()
	if _, _, err := ReadFirstFrame(peer); err != nil {
		t.Fatalf("read BRIDGE_TAG: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("bridge handshake error = %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("bridge handshake ignored engine close")
	}
	select {
	case <-candidate.closed:
	default:
		t.Fatal("engine close did not close candidate path")
	}
}

func TestHelloHandshakeContextClosesBlockedCandidate(t *testing.T) {
	e := bridgeHandshakeEngine(t)
	t.Cleanup(func() { _ = e.Close() })
	candidate, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = peer.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := PerformClientHelloAckContext(ctx, candidate, e, e.LocalInstanceID(), 0, "a")
		result <- err
	}()
	if _, _, err := ReadFirstFrame(peer); err != nil {
		t.Fatalf("read HELLO: %v", err)
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("hello handshake error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("hello handshake ignored context cancellation")
	}
	select {
	case <-candidate.closed:
	default:
		t.Fatal("context cancellation did not close HELLO candidate")
	}
}
