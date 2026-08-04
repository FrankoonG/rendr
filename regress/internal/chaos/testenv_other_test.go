//go:build !linux

package chaos

import "testing"

func testCanManageTC() bool { return false }

func testProcessGone(int) bool { return true }

func testWatcherShutdownBarrier(t *testing.T) {
	t.Helper()
	t.Skip("requires Linux netlink")
}
