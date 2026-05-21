package smoke

import (
	"context"
	"testing"
	"time"
)

func TestRunG1GVisor(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	r := RunG1(ctx, G1Opts{
		Size:       4 << 20,
		Migrations: 2,
		Paths:      2,
		Transport:  "gvisor",
	})
	if r.Failure != "" {
		t.Fatalf("RunG1 gvisor failed: %s", r.Failure)
	}
}
