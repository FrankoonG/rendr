//go:build linux && amd64

package tcp

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/transport"
)

type promotedTCPTransportProvider struct {
	*Transport
}

func TestTCPImplementationProviderRejectsPromotedWrapper(t *testing.T) {
	wrapper := &promotedTCPTransportProvider{Transport: New()}
	if _, ok := any(wrapper).(leafmobility.ImplementationProvider); !ok {
		t.Fatal("embedded Transport method was not promoted")
	}
	if _, err := leafmobility.CapabilitiesForImplementationProvider(wrapper); !errors.Is(err, leafmobility.ErrImplementationOwnerMismatch) {
		t.Fatalf("promoted wrapper error=%v, want owner mismatch", err)
	}
}

func TestTCPImplementationEvidenceMatchesProducedOwnedClaims(t *testing.T) {
	listener, err := Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

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

	implementation := New()
	dialed, err := implementation.DialPath(context.Background(), transport.PathSpec{Address: listener.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dialed.Close() })

	var acceptedPath transport.PathConn
	select {
	case acceptedPath = <-accepted:
		t.Cleanup(func() { _ = acceptedPath.Close() })
	case err := <-acceptErr:
		t.Fatalf("accept: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("accept timed out")
	}

	assertTCPProviderClaimConsistency(t, implementation, dialed)
	assertTCPProviderClaimConsistency(t, listener, acceptedPath)

	local, peer := net.Pipe()
	wrapped := Wrap(local)
	t.Cleanup(func() {
		_ = wrapped.Close()
		_ = peer.Close()
	})
	if _, ok := any(wrapped).(leafmobility.ImplementationProvider); ok {
		t.Fatal("generic tcp.Wrap PathConn became an implementation provider")
	}
	if claim := wrapped.LeafMobilityClaim(); claim != nil {
		t.Fatalf("generic tcp.Wrap acquired owned claim: %+v", claim.Snapshot())
	}
}

func assertTCPProviderClaimConsistency(
	t *testing.T,
	provider leafmobility.ImplementationProvider,
	path transport.PathConn,
) {
	t.Helper()
	capabilities, err := leafmobility.CapabilitiesForImplementationProvider(provider)
	if err != nil {
		t.Fatalf("implementation capabilities: %v", err)
	}
	if len(capabilities) != 1 || capabilities[0].Operation() != leafmobility.OperationTCPRepair {
		t.Fatalf("implementation capabilities=%v", capabilities)
	}
	claimProvider, ok := path.(leafmobility.Provider)
	if !ok || claimProvider.LeafMobilityClaim() == nil {
		t.Fatal("owned TCP path has no claim")
	}
	if operation := claimProvider.LeafMobilityClaim().Snapshot().Operations; operation != capabilities[0].Operation() {
		t.Fatalf("claim operation=%#x, implementation=%#x", operation, capabilities[0].Operation())
	}
}
