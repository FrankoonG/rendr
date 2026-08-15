//go:build !linux || !amd64

package gvisor

import (
	"net"
	"testing"

	"github.com/FrankoonG/rendr/internal/leafmobility"
)

func TestGVisorImplementationProviderIsAbsentOnUnsupportedBuilds(t *testing.T) {
	for name, value := range map[string]any{
		"transport": New(),
		"listener":  &Listener{},
	} {
		if _, ok := value.(leafmobility.ImplementationProvider); ok {
			t.Fatalf("%s unexpectedly provides specialized packet-link mobility", name)
		}
	}
}

func TestGVisorPacketLinkClaimIsUndrivenOnUnsupportedBuilds(t *testing.T) {
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
	t.Cleanup(owner.close)

	claim, err := newPacketLinkClaim(owner, leafmobility.RoleDialer)
	if err != nil {
		t.Fatal(err)
	}
	facts := claim.Snapshot()
	if facts.Operations != 0 || facts.ResourceID != (leafmobility.ResourceID{}) {
		t.Fatalf("unsupported packet-link claim=%+v", facts)
	}
}
