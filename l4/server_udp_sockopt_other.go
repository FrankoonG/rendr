//go:build !unix && !windows

package l4

// clearBroadcast does nothing where the net package sets no SO_BROADCAST
// (plan9, js, wasip1; see udpTargetControl).
func clearBroadcast(uintptr) error { return nil }
