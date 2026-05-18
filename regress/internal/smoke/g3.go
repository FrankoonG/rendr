package smoke

import (
	"context"
	"fmt"
	"time"
)

// G3Opts configures one G3-smoke case (QUIC DATAGRAM 30k pps + ConnID
// migration). Defaults match docs/regression-suite.md §6.
type G3Opts struct {
	Duration   time.Duration // default 10s
	PPS        int           // default 30000
	PayloadLen int           // default 1024
	Migrations int           // default 3
}

func (o *G3Opts) withDefaults() {
	if o.Duration <= 0 {
		o.Duration = 10 * time.Second
	}
	if o.PPS <= 0 {
		o.PPS = 30000
	}
	if o.PayloadLen <= 0 {
		o.PayloadLen = 1024
	}
	if o.Migrations < 0 {
		o.Migrations = 0
	}
	if o.Migrations == 0 {
		o.Migrations = 3
	}
}

// RunG3 is the QUIC DATAGRAM packet-mode smoke. Implementation lands
// in a follow-up commit on the Linux test host; current state is a
// gated stub that fails noisily so we can't accidentally ship a
// silent skip from a Linux runner.
func RunG3(_ context.Context, opts G3Opts) Result {
	opts.withDefaults()
	t0 := time.Now()
	return Result{
		Name:     fmt.Sprintf("G3-smoke (%d pps, %s, %d migrations)", opts.PPS, opts.Duration, opts.Migrations),
		Duration: time.Since(t0),
		Failure:  "G3-smoke implementation pending (Linux host validation; regression-suite §14 step 7-equivalent for smoke)",
	}
}
