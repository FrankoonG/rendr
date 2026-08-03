// Package manifest defines the regression case catalog shared by listing,
// filtering, resume, execution, and reporting.
package manifest

import (
	"fmt"
	"time"
)

const (
	SuiteNormal = "normal"
	SuiteTUN    = "tun-full"
)

// Spec is the stable identity and release metadata for one executable case.
type Spec struct {
	ID        string        `json:"id"`
	Tier      string        `json:"tier"`
	Suite     string        `json:"suite"`
	Mandatory bool          `json:"mandatory"`
	Long      bool          `json:"long,omitempty"`
	Budget    time.Duration `json:"budget_ns,omitempty"`
}

// Required constructs a mandatory case in the normal regression suite.
func Required(id, tier string) Spec {
	return Spec{ID: id, Tier: tier, Suite: SuiteNormal, Mandatory: true}
}

// RequiredWithBudget constructs a mandatory normal-suite case with its
// execution deadline.
func RequiredWithBudget(id, tier string, budget time.Duration) Spec {
	spec := Required(id, tier)
	spec.Budget = budget
	return spec
}

// Validate rejects catalog states that could make listing and execution
// disagree or make a resume point ambiguous.
func Validate(specs []Spec) error {
	seen := make(map[string]int, len(specs))
	for i, spec := range specs {
		if spec.ID == "" {
			return fmt.Errorf("manifest: case %d has empty ID", i)
		}
		if spec.Tier == "" {
			return fmt.Errorf("manifest: case %q has empty tier", spec.ID)
		}
		if spec.Suite == "" {
			return fmt.Errorf("manifest: case %q has empty suite", spec.ID)
		}
		if prev, ok := seen[spec.ID]; ok {
			return fmt.Errorf("manifest: duplicate case ID %q at indexes %d and %d", spec.ID, prev, i)
		}
		seen[spec.ID] = i
	}
	return nil
}

// Select applies an exact case filter or an inclusive resume point. The
// caller must pass specs in execution order.
func Select(specs []Spec, caseID, fromCaseID string) ([]Spec, error) {
	if err := Validate(specs); err != nil {
		return nil, err
	}
	if caseID != "" && fromCaseID != "" {
		return nil, fmt.Errorf("manifest: --case and --from-case are mutually exclusive")
	}
	if caseID == "" && fromCaseID == "" {
		return append([]Spec(nil), specs...), nil
	}
	want := caseID
	if want == "" {
		want = fromCaseID
	}
	for i, spec := range specs {
		if spec.ID != want {
			continue
		}
		if caseID != "" {
			return []Spec{spec}, nil
		}
		return append([]Spec(nil), specs[i:]...), nil
	}
	if caseID != "" {
		return nil, fmt.Errorf("manifest: no case matched --case=%q", caseID)
	}
	return nil, fmt.Errorf("manifest: no case matched --from-case=%q", fromCaseID)
}
