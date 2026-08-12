package gvisor

import (
	"context"
	"errors"
	"testing"
)

func requireOuterPacketSupport(t testing.TB) {
	t.Helper()
	if err := PacketAvailable(); err != nil {
		if errors.Is(err, ErrOuterPacketUnsupported) {
			t.Skip("outer UDP packet carriers are unsupported on this platform")
		}
		t.Fatalf("outer UDP packet-carrier availability: %v", err)
	}
}

func observedOuterLocalTuple(t testing.TB, owner *linkOwner) string {
	t.Helper()
	if owner == nil {
		t.Fatal("outer route observation has no link owner")
	}
	owner.mu.Lock()
	wire := owner.active
	remote := cloneAddr(owner.peerRemote)
	owner.mu.Unlock()
	observation, err := owner.observeOuterRoute(context.Background(), wire, remote)
	if err != nil {
		t.Fatalf("observe active outer route: %v", err)
	}
	return observation.local.String()
}
