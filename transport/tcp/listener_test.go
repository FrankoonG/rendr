package tcp

import (
	"context"
	"errors"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/transport"
)

func TestOwnedListenerCreatesAcceptorClaim(t *testing.T) {
	listener, err := Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if listener.SessionKind() != transport.PathSessionStream {
		t.Fatalf("SessionKind=%v, want stream", listener.SessionKind())
	}

	accepted := make(chan transport.PathConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		path, err := listener.AcceptPath(context.Background())
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- path
	}()
	client, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var path transport.PathConn
	select {
	case path = <-accepted:
	case err := <-acceptErr:
		t.Fatalf("AcceptPath: %v", err)
	case <-time.After(time.Second):
		t.Fatal("AcceptPath timed out")
	}
	defer path.Close()
	provider, ok := path.(leafmobility.Provider)
	if !ok || provider.LeafMobilityClaim() == nil {
		t.Fatal("owned listener path has no claim")
	}
	facts := provider.LeafMobilityClaim().Snapshot()
	wantOperations := leafmobility.Operation(0)
	if runtime.GOOS == "linux" && runtime.GOARCH == "amd64" {
		wantOperations = leafmobility.OperationTCPRepair
	}
	if facts.Kind != leafmobility.KindRawTCP || facts.Role != leafmobility.RoleAcceptor ||
		facts.Scope != leafmobility.ScopeEndpoint || facts.Operations != wantOperations {
		t.Fatalf("acceptor facts=%+v", facts)
	}
}

func TestOwnedListenerCancellationDoesNotPoisonNextAccept(t *testing.T) {
	listener, err := Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := listener.AcceptPath(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled AcceptPath=%v, want context.Canceled", err)
	}

	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	accepted := make(chan transport.PathConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		path, err := listener.AcceptPath(ctx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- path
	}()
	client, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	select {
	case path := <-accepted:
		_ = path.Close()
	case err := <-acceptErr:
		t.Fatalf("next AcceptPath inherited stale deadline: %v", err)
	case <-ctx.Done():
		t.Fatalf("next AcceptPath timed out: %v", ctx.Err())
	}
}

func TestOwnedListenerConcurrentWaiterHonorsContext(t *testing.T) {
	listener, err := Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	first := make(chan error, 1)
	go func() {
		_, err := listener.AcceptPath(context.Background())
		first <- err
	}()
	deadline := time.Now().Add(time.Second)
	for len(listener.accept) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(listener.accept) != 0 {
		t.Fatal("first AcceptPath did not acquire the serialized accept slot")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := listener.AcceptPath(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("concurrent AcceptPath=%v, want context deadline", err)
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("concurrent AcceptPath ignored context for %v", elapsed)
	}
	_ = listener.Close()
	select {
	case err := <-first:
		if err == nil {
			t.Fatal("first AcceptPath unexpectedly succeeded during listener close")
		}
	case <-time.After(time.Second):
		t.Fatal("listener Close did not release first AcceptPath")
	}
}
