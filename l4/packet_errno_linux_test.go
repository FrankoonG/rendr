//go:build linux

package l4

import "syscall"

// ENONET (a host isolated by ICMP) exists on Linux only.
func init() { pfLinuxNoise = append(pfLinuxNoise, pfErrno{"ENONET", syscall.ENONET}) }
