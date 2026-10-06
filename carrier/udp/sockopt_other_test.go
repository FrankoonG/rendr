//go:build !linux && !windows

package udp

import (
	"errors"
	"testing"
)

// Socket options are not observed on this platform (compile-only, M2 design
// §A6.1: rendr sets no don't-fragment option here and sizes buffers best
// effort).

func wp5DF(bool) (level, opt, want int, ok bool) { return 0, 0, 0, false }

func wp5Getsockopt(uintptr, int, int) (int, error) {
	return 0, errors.New("socket options are not observed on this platform")
}

const (
	wp5SolSocket = 0
	wp5SoRcvbuf  = 0
	wp5SoSndbuf  = 0
)

// wp5BufferWant: −1, not observed on this platform.
func wp5BufferWant(*testing.T, int, bool) int { return -1 }
