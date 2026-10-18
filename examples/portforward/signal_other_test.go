//go:build !unix && !windows

package main

import (
	"errors"
	"os"
	"syscall"
)

// stopSignals: this platform cannot signal a child process.
var stopSignals []stopSignal

const stopResetsVisible = false

func childAttr() *syscall.SysProcAttr { return nil }

func sendStop(*os.Process, os.Signal) error { return errors.ErrUnsupported }
