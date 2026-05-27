//go:build linux

package main

import (
	"syscall"
	"time"
)

type processUsage struct {
	User time.Duration
	Sys  time.Duration
}

func readProcessUsage() (processUsage, bool) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return processUsage{}, false
	}
	return processUsage{
		User: timevalDuration(ru.Utime),
		Sys:  timevalDuration(ru.Stime),
	}, true
}

func timevalDuration(tv syscall.Timeval) time.Duration {
	return time.Duration(tv.Sec)*time.Second + time.Duration(tv.Usec)*time.Microsecond
}

func (u processUsage) sub(v processUsage) processUsage {
	return processUsage{
		User: u.User - v.User,
		Sys:  u.Sys - v.Sys,
	}
}
