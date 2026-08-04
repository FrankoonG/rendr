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
	if r.InvalidReason != "" {
		t.Fatalf("RunUDPRelay invalid: %s", r.InvalidReason)
	}
	assertInflightMigrationDetail(t, r, 2)
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
	if r.InvalidReason != "" {
		t.Fatalf("RunUDPRelayPortHop invalid: %s", r.InvalidReason)
	}
	assertInflightMigrationDetail(t, r, 2)
	if got := r.Detail["port_hops"]; got != 3 {
		t.Fatalf("port_hops detail=%v want 3", got)
	}
}

func assertInflightMigrationDetail(t *testing.T, result Result, expected int) {
	t.Helper()
	if got := result.Detail["expected_inflight_migrations"]; got != expected {
		t.Fatalf("expected_inflight_migrations detail=%v want %d", got, expected)
	}
	if got := result.Detail["inflight_migrations"]; got != expected {
		t.Fatalf("inflight_migrations detail=%v want %d", got, expected)
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
