//go:build !linux

package main

import "time"

type processUsage struct {
	User time.Duration
	Sys  time.Duration
}

func readProcessUsage() (processUsage, bool) {
	return processUsage{}, false
}

func (u processUsage) sub(v processUsage) processUsage {
	return processUsage{
		User: u.User - v.User,
		Sys:  u.Sys - v.Sys,
	}
}
