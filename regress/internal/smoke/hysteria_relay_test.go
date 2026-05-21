package smoke

import (
	"context"
	"runtime"
	"testing"
	"time"
)

func TestRunHysteriaRelay(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Hysteria 2 relay smoke is validated on Linux regress hosts")
	}
	if !HysteriaAvailable() {
		t.Skip("hysteria binary not found")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r := RunHysteriaRelay(ctx, HysteriaRelayOpts{
		Paths:      2,
		Migrations: 2,
		DataSize:   4 << 20,
	})
	if r.Failure != "" {
		t.Fatalf("RunHysteriaRelay failed: %s", r.Failure)
	}
}
