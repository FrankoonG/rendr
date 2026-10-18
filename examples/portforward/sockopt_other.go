//go:build !unix && !windows

package main

// clearBroadcast does nothing where the net package sets no SO_BROADCAST
// (plan9, js, wasip1).
func clearBroadcast(uintptr) error { return nil }
