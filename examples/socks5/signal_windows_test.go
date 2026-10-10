package main

import (
	"os"
	"syscall"
)

// stopSignals: Windows has no signals to send; CTRL_BREAK_EVENT to the
// child's process group is what Go delivers as os.Interrupt (R1-21: "the
// os.Interrupt equivalent where available").
var stopSignals = []stopSignal{{"CTRL_BREAK", os.Interrupt}}

// stopResetsVisible: Windows resets the sockets of an exiting process, so
// a reset proves nothing here (the "stopped" line does).
const stopResetsVisible = false

// childAttr starts each child in its own process group, the target of
// CTRL_BREAK_EVENT.
func childAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
}

var generateConsoleCtrlEvent = syscall.NewLazyDLL("kernel32.dll").NewProc("GenerateConsoleCtrlEvent")

// sendStop sends CTRL_BREAK_EVENT to p's process group; it fails where the
// test process shares no console with p.
func sendStop(p *os.Process, _ os.Signal) error {
	const ctrlBreakEvent = 1
	if r, _, err := generateConsoleCtrlEvent.Call(ctrlBreakEvent, uintptr(p.Pid)); r == 0 {
		return err
	}
	return nil
}
