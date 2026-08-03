// Package catalog exposes the ordered normal regression case catalog.
package catalog

import (
	"fmt"

	"github.com/FrankoonG/rendr/regress/internal/manifest"
	"github.com/FrankoonG/rendr/regress/internal/tier1"
	"github.com/FrankoonG/rendr/regress/internal/tier2"
	"github.com/FrankoonG/rendr/regress/internal/tier3"
	"github.com/FrankoonG/rendr/regress/internal/tier4"
	"github.com/FrankoonG/rendr/regress/internal/tier5"
	"github.com/FrankoonG/rendr/regress/internal/tier6"
	"github.com/FrankoonG/rendr/regress/internal/tier7"
	"github.com/FrankoonG/rendr/regress/internal/tier8"
)

type phase uint8

const (
	phaseOne phase = iota + 1
	phaseTwo
)

type tierSource struct {
	tier  string
	phase phase
	specs func() []manifest.Spec
}

var normalSources = [...]tierSource{
	{tier: "T1", phase: phaseOne, specs: tier1.Specs},
	{tier: "T2", phase: phaseOne, specs: tier2.Specs},
	{tier: "T3", phase: phaseTwo, specs: tier3.Specs},
	{tier: "T4", phase: phaseTwo, specs: tier4.Specs},
	{tier: "T5", phase: phaseTwo, specs: tier5.Specs},
	{tier: "T6", phase: phaseTwo, specs: tier6.Specs},
	{tier: "T7", phase: phaseTwo, specs: tier7.Specs},
	{tier: "T8", phase: phaseTwo, specs: tier8.Specs},
}

// Phase1 returns a copy of the ordered T1-T2 normal regression catalog.
func Phase1() []manifest.Spec {
	return collect(func(source tierSource) bool { return source.phase == phaseOne })
}

// Phase2 returns a copy of the ordered T3-T8 normal regression catalog.
func Phase2() []manifest.Spec {
	return collect(func(source tierSource) bool { return source.phase == phaseTwo })
}

// NormalFull returns a copy of the ordered T1-T8 normal regression catalog.
func NormalFull() []manifest.Spec {
	return collect(func(tierSource) bool { return true })
}

// Lookup returns the normal-suite case with id and its owning tier metadata.
func Lookup(id string) (manifest.Spec, bool) {
	for _, source := range normalSources {
		for _, spec := range source.specs() {
			if spec.ID == id {
				return spec, true
			}
		}
	}
	return manifest.Spec{}, false
}

// ByTier returns a copy of the ordered normal-suite cases owned by tier.
func ByTier(tier string) []manifest.Spec {
	for _, source := range normalSources {
		if source.tier == tier {
			return clone(source.specs())
		}
	}
	return nil
}

// Validate checks the complete normal catalog's identities and ownership.
func Validate() error {
	return validateSources(normalSources[:])
}

func collect(include func(tierSource) bool) []manifest.Spec {
	var specs []manifest.Spec
	for _, source := range normalSources {
		if include(source) {
			specs = append(specs, source.specs()...)
		}
	}
	return specs
}

func clone(specs []manifest.Spec) []manifest.Spec {
	return append([]manifest.Spec(nil), specs...)
}

func validateSources(sources []tierSource) error {
	var specs []manifest.Spec
	for sourceIndex, source := range sources {
		if source.tier == "" {
			return fmt.Errorf("catalog: source %d has empty tier", sourceIndex)
		}
		if source.phase != phaseOne && source.phase != phaseTwo {
			return fmt.Errorf("catalog: tier %q has invalid phase %d", source.tier, source.phase)
		}
		if source.specs == nil {
			return fmt.Errorf("catalog: tier %q has no Specs registry", source.tier)
		}
		for specIndex, spec := range source.specs() {
			if spec.Tier != source.tier {
				return fmt.Errorf(
					"catalog: tier %q case %d (%q) declares tier %q",
					source.tier, specIndex, spec.ID, spec.Tier,
				)
			}
			if spec.Suite != manifest.SuiteNormal {
				return fmt.Errorf(
					"catalog: tier %q case %q declares suite %q, want %q",
					source.tier, spec.ID, spec.Suite, manifest.SuiteNormal,
				)
			}
			specs = append(specs, spec)
		}
	}
	if err := manifest.Validate(specs); err != nil {
		return fmt.Errorf("catalog: %w", err)
	}
	return nil
}
