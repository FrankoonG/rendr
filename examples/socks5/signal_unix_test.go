//go:build unix

package main

import (
	"os"
	"syscall"
)

// stopSignals are the signals TestSocks5SignalExit sends.
var stopSignals = []stopSignal{{"SIGTERM", syscall.SIGTERM}, {"SIGINT", os.Interrupt}}

// childAttr is the children's process attributes.
func childAttr() *syscall.SysProcAttr { return nil }

// sendStop delivers sig to p.
func sendStop(p *os.Process, sig os.Signal) error { return p.Signal(sig) }
