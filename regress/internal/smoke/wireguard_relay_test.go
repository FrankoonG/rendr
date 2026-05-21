package smoke

import (
	"context"
	"runtime"
	"testing"
	"time"
)

func TestRunWireGuardRelay(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wireguard-go UDP endpoint smoke is validated on Linux regress hosts")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	r := RunWireGuardRelay(ctx, WireGuardRelayOpts{
		Messages:    24,
		MessageSize: 256,
		Paths:       2,
		Migrations:  2,
	})
	if r.Failure != "" {
		t.Fatalf("RunWireGuardRelay failed: %s", r.Failure)
	}
}
