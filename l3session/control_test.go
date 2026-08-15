package l3session

import (
	"testing"
	"time"

	"github.com/FrankoonG/rendr"
)

type streamControl interface {
	rendr.Conn
	rendr.MigrationController
	rendr.ConnectionObserver
}

type packetControl interface {
	rendr.PacketConn
	rendr.MigrationController
	rendr.ConnectionObserver
}

func waitForSessionPathAttached(t testing.TB, status rendr.StatusReporter, name string, timeout time.Duration) rendr.PathStatus {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	last := status.Status()
	for {
		last = status.Status()
		for _, path := range last.Paths {
			if path.Name == name && path.State == rendr.PathAttached && path.ID != 0 {
				return path
			}
		}
		select {
		case <-deadline.C:
			t.Fatalf("path %q did not reach attached state within %s: session_state=%q effective_paths=%v path_status=%+v",
				name, timeout, last.State, last.EffectivePaths, last.Paths)
			return rendr.PathStatus{}
		case <-ticker.C:
		}
	}
}
