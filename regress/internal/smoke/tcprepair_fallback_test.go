package smoke

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/transport/tcprepair"
)

func TestTCPRepairUnavailableFallsBackToGVisor(t *testing.T) {
	err := tcprepair.Available()
	if err == nil {
		t.Skip("tcprepair available; fallback path not exercised")
	}
	if !strings.Contains(err.Error(), "gvisor fallback") {
		t.Fatalf("tcprepair unavailable error does not name gvisor fallback: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r := RunG1(ctx, G1Opts{
		Size:       4 << 20,
		Migrations: 2,
		Paths:      2,
		Transport:  "gvisor",
	})
	if r.Failure != "" {
		t.Fatalf("gvisor fallback G1 failed: %s", r.Failure)
	}
}
