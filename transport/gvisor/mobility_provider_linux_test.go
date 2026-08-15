//go:build linux && amd64

package gvisor

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/transport"
)

type promotedGVisorTransportProvider struct {
	*Transport
}

func TestGVisorImplementationProviderIsPresentByDefault(t *testing.T) {
	for name, value := range map[string]any{
		"transport": New(),
		"listener":  &Listener{},
	} {
		provider, ok := value.(leafmobility.ImplementationProvider)
		if !ok {
			t.Fatalf("%s does not provide qualified gVisor packet-link mobility", name)
		}
		assertGVisorImplementationCapability(t, provider)
	}
}

func TestGVisorImplementationProviderRejectsPromotedWrapper(t *testing.T) {
	wrapper := &promotedGVisorTransportProvider{Transport: New()}
	if _, ok := any(wrapper).(leafmobility.ImplementationProvider); !ok {
		t.Fatal("embedded Transport method was not promoted")
	}
	if _, err := leafmobility.CapabilitiesForImplementationProvider(wrapper); !errors.Is(err, leafmobility.ErrImplementationOwnerMismatch) {
		t.Fatalf("promoted wrapper error=%v, want owner mismatch", err)
	}
}

func TestGVisorOuterDescriptorMatchesPacketOwnedClaims(t *testing.T) {
	requireOuterPacketSupport(t)
	listener, err := ListenPacket("127.0.0.1:0", WithTrustedCarrier())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	client, server := dialAndAccept(t, listener)
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	for _, test := range []struct {
		name     string
		provider leafmobility.ImplementationProvider
		path     transport.PathConn
	}{
		{name: "dialer", provider: listener.Factory(), path: client},
		{name: "acceptor", provider: listener, path: server},
	} {
		t.Run(test.name, func(t *testing.T) {
			assertGVisorImplementationCapability(t, test.provider)
			claimProvider, ok := test.path.(leafmobility.Provider)
			if !ok || claimProvider.LeafMobilityClaim() == nil {
				t.Fatal("packet-carried endpoint has no sealed claim")
			}
			claim := claimProvider.LeafMobilityClaim()
			capability, ok := leafmobility.CapabilityForClaim(claim)
			if !ok || capability.Operation() != leafmobility.OperationGVisorLinkRebind {
				t.Fatalf("endpoint claim capability=%v present=%t", capability.Operation(), ok)
			}
			facts := claim.Snapshot()
			if facts.Scope != leafmobility.ScopeEndpoint || facts.ResourceID == (leafmobility.ResourceID{}) {
				t.Fatalf("endpoint ownership facts=%+v", facts)
			}
		})
	}
}

func TestGVisorClosedPacketOwnerRejectsClaimConstruction(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	owner, err := newLinkOwner(
		linkID{1}, linkSecret{2}, leafmobility.RoleDialer, [4]byte{10, 64, 1, 1},
		newPacketWire(conn, false), &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}, nil,
		func([]byte) {},
	)
	if err != nil {
		t.Fatal(err)
	}
	owner.close()
	if _, err := newPacketLinkClaim(owner, leafmobility.RoleDialer); err == nil {
		t.Fatal("closed packet owner created a driven claim")
	}
}

func TestGVisorImplementationProviderDoesNotBypassPacketTrust(t *testing.T) {
	adapter := New()
	assertGVisorImplementationCapability(t, adapter)
	path, err := adapter.DialPath(context.Background(), transport.PathSpec{
		Transport: "gvisor",
		Address:   "127.0.0.1:1",
	})
	if path != nil {
		_ = path.Close()
		t.Fatal("untrusted packet transport returned a path")
	}
	if !errors.Is(err, ErrPacketTrustRequired) {
		t.Fatalf("untrusted packet transport error=%v, want %v", err, ErrPacketTrustRequired)
	}
}

func assertGVisorImplementationCapability(t testing.TB, provider leafmobility.ImplementationProvider) {
	t.Helper()
	capabilities, err := leafmobility.CapabilitiesForImplementationProvider(provider)
	if err != nil {
		t.Fatalf("implementation capabilities: %v", err)
	}
	if len(capabilities) != 1 || capabilities[0].Operation() != leafmobility.OperationGVisorLinkRebind {
		t.Fatalf("implementation capabilities=%v, want gVisor packet-link rebind only", capabilities)
	}
}
