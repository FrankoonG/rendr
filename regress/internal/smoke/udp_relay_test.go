package smoke

import (
	"context"
	"testing"
	"time"
)

func TestRunUDPRelayServerMode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	r := RunUDPRelay(ctx, UDPRelayOpts{
		Packets:    64,
		Paths:      2,
		Migrations: 2,
		Server:     true,
	})
	if r.Failure != "" {
		t.Fatalf("RunUDPRelay failed: %s", r.Failure)
	}
}

func TestRunUDPRelayPortHop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	r := RunUDPRelayPortHop(ctx, UDPRelayOpts{
		Packets:    64,
		Paths:      2,
		Migrations: 2,
		PortHops:   3,
	})
	if r.Failure != "" {
		t.Fatalf("RunUDPRelayPortHop failed: %s", r.Failure)
	}
	if got := r.Detail["port_hops"]; got != 3 {
		t.Fatalf("port_hops detail=%v want 3", got)
	}
}

func TestMigrationPoints(t *testing.T) {
	points := migrationPoints(100, 3)
	for _, want := range []int{25, 50, 75} {
		if _, ok := points[want]; !ok {
			t.Fatalf("missing migration point %d in %#v", want, points)
		}
	}
}
