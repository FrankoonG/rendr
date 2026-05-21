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

func TestMigrationPoints(t *testing.T) {
	points := migrationPoints(100, 3)
	for _, want := range []int{25, 50, 75} {
		if _, ok := points[want]; !ok {
			t.Fatalf("missing migration point %d in %#v", want, points)
		}
	}
}
