package engine

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
)

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
