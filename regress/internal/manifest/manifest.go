// Package manifest defines the regression case catalog shared by listing,
// filtering, resume, execution, and reporting.
package manifest

import (
	"fmt"
	"strings"
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
	Requires  []string      `json:"requires,omitempty"`
	Long      bool          `json:"long,omitempty"`
	Budget    time.Duration `json:"budget_ns,omitempty"`
}

// RequiredWithBudget constructs a mandatory normal-suite case with its
// execution deadline.
func RequiredWithBudget(id, tier string, budget time.Duration) Spec {
	return Spec{ID: id, Tier: tier, Suite: SuiteNormal, Mandatory: true, Budget: budget}
}

// Validate rejects catalog states that could make listing and execution
// disagree or make a resume point ambiguous.
func Validate(specs []Spec) error {
	seen := make(map[string]int, len(specs))
	for i, spec := range specs {
		if spec.ID == "" {
			return fmt.Errorf("manifest: case %d has empty ID", i)
		}
		if prev, ok := seen[spec.ID]; ok {
			return fmt.Errorf("manifest: duplicate case ID %q at indexes %d and %d", spec.ID, prev, i)
		}
		seen[spec.ID] = i
	}

	byID := make(map[string]Spec, len(specs))
	for _, spec := range specs {
		if spec.Tier == "" {
			return fmt.Errorf("manifest: case %q has empty tier", spec.ID)
		}
		if spec.Suite != SuiteNormal && spec.Suite != SuiteTUN {
			return fmt.Errorf("manifest: case %q has unsupported suite %q", spec.ID, spec.Suite)
		}
		if !spec.Mandatory {
			return fmt.Errorf("manifest: case %q is not mandatory", spec.ID)
		}
		if spec.Budget <= 0 {
			return fmt.Errorf("manifest: case %q has non-positive budget %s", spec.ID, spec.Budget)
		}
		byID[spec.ID] = spec
	}

	for _, spec := range specs {
		requireIndexes := make(map[string]int, len(spec.Requires))
		for i, requiredID := range spec.Requires {
			if prev, ok := requireIndexes[requiredID]; ok {
				return fmt.Errorf("manifest: case %q has duplicate prerequisite %q at indexes %d and %d", spec.ID, requiredID, prev, i)
			}
			requireIndexes[requiredID] = i

			required, ok := byID[requiredID]
			if !ok {
				return fmt.Errorf("manifest: case %q requires unknown prerequisite %q", spec.ID, requiredID)
			}
			if required.Suite != spec.Suite {
				return fmt.Errorf(
					"manifest: case %q in suite %q requires cross-suite prerequisite %q in suite %q",
					spec.ID, spec.Suite, required.ID, required.Suite,
				)
			}
		}
	}

	const (
		unvisited uint8 = iota
		visiting
		visited
	)
	states := make(map[string]uint8, len(specs))
	stack := make([]string, 0, len(specs))
	stackIndexes := make(map[string]int, len(specs))
	var visit func(string) error
	visit = func(id string) error {
		states[id] = visiting
		stackIndexes[id] = len(stack)
		stack = append(stack, id)
		for _, requiredID := range byID[id].Requires {
			switch states[requiredID] {
			case unvisited:
				if err := visit(requiredID); err != nil {
					return err
				}
			case visiting:
				cycle := append([]string(nil), stack[stackIndexes[requiredID]:]...)
				cycle = append(cycle, requiredID)
				return fmt.Errorf("manifest: cyclic prerequisites: %s", strings.Join(cycle, " -> "))
			}
		}
		stack = stack[:len(stack)-1]
		delete(stackIndexes, id)
		states[id] = visited
		return nil
	}
	for _, spec := range specs {
		if states[spec.ID] == unvisited {
			if err := visit(spec.ID); err != nil {
				return err
			}
		}
	}
	for _, spec := range specs {
		for _, requiredID := range spec.Requires {
			if seen[requiredID] >= seen[spec.ID] {
				return fmt.Errorf(
					"manifest: case %q requires %q, which must precede it in canonical order",
					spec.ID, requiredID,
				)
			}
		}
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
		return cloneSpecs(specs), nil
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
			return cloneSpecs(specs[i : i+1]), nil
		}
		return cloneSpecs(specs[i:]), nil
	}
	if caseID != "" {
		return nil, fmt.Errorf("manifest: no case matched --case=%q", caseID)
	}
	return nil, fmt.Errorf("manifest: no case matched --from-case=%q", fromCaseID)
}

// WithPrerequisites prepends the transitive prerequisites of selected cases.
// The registry is authoritative: prerequisites follow its canonical order and
// selected cases retain their first-occurrence order. The result contains each
// case at most once and does not alias Requires slices from either input.
func WithPrerequisites(registry, selected []Spec) ([]Spec, error) {
	if err := Validate(registry); err != nil {
		return nil, err
	}

	byID := make(map[string]Spec, len(registry))
	for _, spec := range registry {
		byID[spec.ID] = spec
	}
	selectedIDs := make([]string, 0, len(selected))
	selectedSet := make(map[string]struct{}, len(selected))
	for i, spec := range selected {
		canonical, ok := byID[spec.ID]
		if !ok {
			return nil, fmt.Errorf("manifest: selected case %q at index %d is not in canonical registry", spec.ID, i)
		}
		if !equalSpec(canonical, spec) {
			return nil, fmt.Errorf("manifest: selected case %q at index %d does not match canonical metadata", spec.ID, i)
		}
		if _, ok := selectedSet[spec.ID]; ok {
			continue
		}
		selectedSet[spec.ID] = struct{}{}
		selectedIDs = append(selectedIDs, spec.ID)
	}

	required := make(map[string]struct{})
	var collect func(string)
	collect = func(id string) {
		for _, requiredID := range byID[id].Requires {
			if _, ok := required[requiredID]; ok {
				continue
			}
			required[requiredID] = struct{}{}
			collect(requiredID)
		}
	}
	for _, id := range selectedIDs {
		collect(id)
	}

	result := make([]Spec, 0, len(required)+len(selectedIDs))
	added := make(map[string]struct{}, cap(result))
	for _, spec := range registry {
		if _, ok := required[spec.ID]; !ok {
			continue
		}
		result = append(result, cloneSpec(spec))
		added[spec.ID] = struct{}{}
	}
	for _, id := range selectedIDs {
		if _, ok := added[id]; ok {
			continue
		}
		result = append(result, cloneSpec(byID[id]))
		added[id] = struct{}{}
	}
	return result, nil
}

func cloneSpecs(specs []Spec) []Spec {
	if specs == nil {
		return nil
	}
	cloned := make([]Spec, len(specs))
	for i, spec := range specs {
		cloned[i] = cloneSpec(spec)
	}
	return cloned
}

func cloneSpec(spec Spec) Spec {
	if spec.Requires != nil {
		spec.Requires = append([]string{}, spec.Requires...)
	}
	return spec
}

func equalSpec(a, b Spec) bool {
	if a.ID != b.ID || a.Tier != b.Tier || a.Suite != b.Suite || a.Mandatory != b.Mandatory ||
		a.Long != b.Long || a.Budget != b.Budget || len(a.Requires) != len(b.Requires) {
		return false
	}
	for i := range a.Requires {
		if a.Requires[i] != b.Requires[i] {
			return false
		}
	}
	return true
}
