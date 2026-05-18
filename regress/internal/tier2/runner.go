// Package tier2 runs phase-1 rendr-self-check G-mini cases. T2 is
// the rendr engine's own G1-G5 contract at smoke scale: small enough
// to fit in <8 min, large enough to catch engine-layer regressions
// before phase 2 burns CI time.
//
// Status: placeholder. T2 cases are still being migrated from
// chaos/cmd/{g1,g2,g4}/main.go per docs/regression-suite.md §14
// step 3. Until that lands, tier2.Run reports each case as skipped
// with reason "T2 migration pending". Phase 1 still passes; the
// skips show up in reports so the gap is visible.
package tier2

import (
	"context"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/report"
)

// Run records every T2 case as skipped until the chaos→smoke
// migration commit lands.
func Run(_ context.Context, suite *report.Suite, _ string) {
	pending := []string{
		"G1-smoke",
		"G2-smoke",
		"G3-smoke",
		"G4",
		"G5",
	}
	for _, name := range pending {
		suite.Add(report.Case{
			Name:       name,
			Tier:       "T2",
			SkipReason: "T2 smoke migration pending (regression-suite §14 step 3)",
			Duration:   0,
		})
	}
	// Touch the time import to keep gofmt happy if we later use time
	// without re-adding the import.
	_ = time.Duration(0)
}
