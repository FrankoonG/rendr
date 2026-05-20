//go:build !linux

package chaos

import (
	"errors"
	"time"
)

// Profile is the same shape as the Linux file so callers can
// reference it on any GOOS. Apply errors out on non-Linux — chaos
// tier is Linux-only via the dispatcher gate.
type Profile struct {
	Bandwidth int64
	LossPct   float64
	Delay     time.Duration
	Jitter    time.Duration
}

var Realistic50M = Profile{Bandwidth: 50_000_000}
var LossyWAN = Profile{Bandwidth: 50_000_000, LossPct: 1.0, Delay: 80 * time.Millisecond, Jitter: 20 * time.Millisecond}

func Apply(_ Profile) (func() error, error) {
	return nil, errors.New("chaos.Apply: tc netem only supported on Linux")
}
