// Package runplan turns CLI scope and case filters into deterministic tier
// executions backed by the regression catalog.
package runplan

import (
	"fmt"
	"reflect"

	"github.com/FrankoonG/rendr/regress/internal/catalog"
	"github.com/FrankoonG/rendr/regress/internal/manifest"
)

// Request selects a normal (non-TUN) regression scope.
type Request struct {
	Phase    string
	Tier     string
	Full     bool
	Case     string
	FromCase string
}

// TierRun is one contiguous tier execution. Case selects exactly one case;
// FromCase selects the inclusive suffix of a tier; both empty means the full
// tier registry.
type TierRun struct {
	Tier     string
	Case     string
	FromCase string
}

// Plan is a validated, ordered execution plan.
type Plan struct {
	Runs           []TierRun
	CompletePhase1 bool
}

// HasPhase2 reports whether the plan enters any heavy tier.
func (p Plan) HasPhase2() bool {
	for _, run := range p.Runs {
		if run.Tier != "T1" && run.Tier != "T2" {
			return true
		}
	}
	return false
}

// Build validates the requested scope and applies exact or inclusive-resume
// selection against the same registry used by execution and reporting.
func Build(req Request) (Plan, error) {
	if err := validateRequest(req); err != nil {
		return Plan{}, err
	}
	scope, err := scopeSpecs(req)
	if err != nil {
		return Plan{}, err
	}
	selected, err := manifest.Select(scope, req.Case, req.FromCase)
	if err != nil {
		return Plan{}, fmt.Errorf("run plan: %w", err)
	}
	if len(selected) == 0 {
		return Plan{}, fmt.Errorf("run plan: selected scope contains no cases")
	}

	plan := Plan{CompletePhase1: containsCompletePhase1(selected)}
	if req.Case != "" {
		spec := selected[0]
		plan.Runs = []TierRun{{Tier: spec.Tier, Case: spec.ID}}
		return plan, nil
	}

	for i := 0; i < len(selected); {
		j := i + 1
		for j < len(selected) && selected[j].Tier == selected[i].Tier {
			j++
		}
		group := selected[i:j]
		run := TierRun{Tier: group[0].Tier}
		fullTier := catalog.ByTier(run.Tier)
		if !reflect.DeepEqual(group, fullTier) {
			if !isTierSuffix(group, fullTier) {
				return Plan{}, fmt.Errorf("run plan: selected %s cases are not a contiguous tier suffix", run.Tier)
			}
			run.FromCase = group[0].ID
		}
		plan.Runs = append(plan.Runs, run)
		i = j
	}
	return plan, nil
}

func validateRequest(req Request) error {
	if req.Case != "" && req.FromCase != "" {
		return fmt.Errorf("run plan: --case and --from-case are mutually exclusive")
	}
	switch req.Phase {
	case "", "1", "2":
	default:
		return fmt.Errorf("run plan: invalid --phase=%q; use 1 or 2", req.Phase)
	}
	if req.Full && (req.Phase != "" || req.Tier != "") {
		return fmt.Errorf("run plan: --full cannot be combined with --phase or --tier")
	}
	if req.Phase == "1" && req.Tier != "" {
		return fmt.Errorf("run plan: --phase=1 cannot be combined with --tier")
	}
	if req.Tier != "" {
		switch req.Tier {
		case "3", "4", "5", "6", "7", "8":
		default:
			return fmt.Errorf("run plan: invalid --tier=%q; use 3 through 8", req.Tier)
		}
	}
	return nil
}

func scopeSpecs(req Request) ([]manifest.Spec, error) {
	hasFilter := req.Case != "" || req.FromCase != ""
	switch {
	case req.Full:
		return catalog.NormalFull(), nil
	case req.Tier != "":
		return catalog.ByTier("T" + req.Tier), nil
	case req.Phase == "1":
		return catalog.Phase1(), nil
	case req.Phase == "2" && hasFilter:
		return catalog.Phase2(), nil
	case req.Phase == "2":
		return catalog.ByTier("T3"), nil
	case hasFilter:
		return catalog.NormalFull(), nil
	default:
		specs := catalog.Phase1()
		return append(specs, catalog.ByTier("T3")...), nil
	}
}

func containsCompletePhase1(selected []manifest.Spec) bool {
	want := catalog.Phase1()
	if len(selected) < len(want) {
		return false
	}
	for start := 0; start+len(want) <= len(selected); start++ {
		if reflect.DeepEqual(selected[start:start+len(want)], want) {
			return true
		}
	}
	return false
}

func isTierSuffix(selected, full []manifest.Spec) bool {
	if len(selected) == 0 || len(selected) > len(full) {
		return false
	}
	return reflect.DeepEqual(selected, full[len(full)-len(selected):])
}
