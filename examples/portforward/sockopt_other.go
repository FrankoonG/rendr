//go:build !unix && !windows

package main

import "log"

// clearBroadcast does nothing where the net package sets no SO_BROADCAST
// (plan9, js, wasip1).
func clearBroadcast(uintptr) error { return nil }

// checkBuffers checks nothing where the socket buffers cannot be read
// back (plan9, js, wasip1).
func checkBuffers(*log.Logger, string, string, int) {}
