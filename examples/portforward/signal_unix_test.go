//go:build unix

package main

import (
	"os"
	"syscall"
)

// stopSignals are the signals TestPortForwardExampleSignalExit sends.
var stopSignals = []stopSignal{{"SIGTERM", syscall.SIGTERM}, {"SIGINT", os.Interrupt}}

// stopResetsVisible: an exiting process closes its sockets with a FIN, so
// the reset of a forwarded connection proves Forward's shutdown path.
const stopResetsVisible = true

// childAttr is the children's process attributes.
func childAttr() *syscall.SysProcAttr { return nil }

// sendStop delivers sig to p.
func sendStop(p *os.Process, sig os.Signal) error { return p.Signal(sig) }
