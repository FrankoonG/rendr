// Package tunfull defines the TUN translation of the existing full
// regression surface.
package tunfull

import (
	"context"
	"fmt"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/report"
)

// Options filters the TUN full baseline matrix.
type Options struct {
	Case string
}

// Planned cases mirror the non-TUN full surface that must eventually
// run through TUN ingress. They intentionally fail until their real
// TUN-backed implementations land; this preserves the hard guard that
// --tun-full must not report a false green.
var plannedCases = []string{
	"TUN-full.G1-smoke",
	"TUN-full.G2-smoke",
	"TUN-full.G3-smoke",
	"TUN-full.G4-path-death",
	"TUN-full.G5-path-recovery",
	"TUN-full.T3-xray-matrix",
	"TUN-full.T4-long-run",
	"TUN-full.T5-fallback",
	"TUN-full.T6-selector",
}

// Run records the TUN full baseline status. For now this is a
// structured, case-addressable guard: individual cases can be targeted
// with --case, but they remain failing until implemented.
func Run(_ context.Context, suite *report.Suite, _ string, opts Options) {
	matched := false
	for _, name := range plannedCases {
		if !caseMatches(opts.Case, name) {
			continue
		}
		matched = true
		suite.Add(UnimplementedCase(name))
	}
	if opts.Case != "" && !matched {
		suite.Add(report.Case{
			Name:    "TUN-full-case-filter",
			Tier:    "T7",
			Failure: fmt.Sprintf("no TUN full case matched %q", opts.Case),
		})
		return
	}
	if opts.Case == "" {
		suite.Add(UnimplementedCase("TUN-full-not-implemented"))
	}
}

// UnimplementedCase returns the explicit guard case used until real
// TUN full baseline cases are implemented.
func UnimplementedCase(name string) report.Case {
	if name == "" {
		name = "TUN-full-not-implemented"
	}
	return report.Case{
		Name:     name,
		Tier:     "T7",
		Duration: 0 * time.Second,
		Failure:  "--tun-full baseline is not implemented yet; T7 feature tests are not a full TUN regression",
	}
}

func caseMatches(filter, name string) bool {
	return filter == "" || filter == name
}
