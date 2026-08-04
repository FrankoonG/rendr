package catalog

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/manifest"
	"github.com/FrankoonG/rendr/regress/internal/tier1"
	"github.com/FrankoonG/rendr/regress/internal/tier2"
	"github.com/FrankoonG/rendr/regress/internal/tier3"
	"github.com/FrankoonG/rendr/regress/internal/tier4"
	"github.com/FrankoonG/rendr/regress/internal/tier5"
	"github.com/FrankoonG/rendr/regress/internal/tier6"
	"github.com/FrankoonG/rendr/regress/internal/tier7"
	"github.com/FrankoonG/rendr/regress/internal/tier8"
	"github.com/FrankoonG/rendr/regress/internal/tunfull"
)

const (
	phase1Count     = 20
	phase2Count     = 110
	normalFullCount = 130
	tunFullCount    = 12
	globalCaseCount = 142
)

var expectedTiers = []struct {
	tier  string
	count int
	specs func() []manifest.Spec
}{
	{tier: "T1", count: 10, specs: tier1.Specs},
	{tier: "T2", count: 10, specs: tier2.Specs},
	{tier: "T3", count: 44, specs: tier3.Specs},
	{tier: "T4", count: 11, specs: tier4.Specs},
	{tier: "T5", count: 6, specs: tier5.Specs},
	{tier: "T6", count: 10, specs: tier6.Specs},
	{tier: "T7", count: 30, specs: tier7.Specs},
	{tier: "T8", count: 9, specs: tier8.Specs},
}

func TestCatalogExactOrderAndCount(t *testing.T) {
	wantPhase1 := concatTierSpecs(expectedTiers[:2])
	wantPhase2 := concatTierSpecs(expectedTiers[2:])
	wantFull := concatTierSpecs(expectedTiers)

	assertCatalog(t, "Phase1", Phase1(), wantPhase1, phase1Count)
	assertCatalog(t, "Phase2", Phase2(), wantPhase2, phase2Count)
	assertCatalog(t, "NormalFull", NormalFull(), wantFull, normalFullCount)

	for _, expected := range expectedTiers {
		if got := len(expected.specs()); got != expected.count {
			t.Errorf("%s Specs count = %d, want %d", expected.tier, got, expected.count)
		}
	}

	all := append(NormalFull(), tunfull.Specs()...)
	if got := len(tunfull.Specs()); got != tunFullCount {
		t.Errorf("TUN executable count = %d, want %d", got, tunFullCount)
	}
	if got := len(all); got != globalCaseCount {
		t.Fatalf("global executable count = %d, want %d", got, globalCaseCount)
	}
	if err := manifest.ValidateCensus(all); err != nil {
		t.Fatalf("global contract census: %v", err)
	}
}

func TestCatalogIDsAreGloballyUnique(t *testing.T) {
	if err := Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}

	seen := make(map[string]string, normalFullCount)
	for _, spec := range NormalFull() {
		if owner, exists := seen[spec.ID]; exists {
			t.Fatalf("case %q is owned by both %s and %s", spec.ID, owner, spec.Tier)
		}
		seen[spec.ID] = spec.Tier
	}
	if len(seen) != normalFullCount {
		t.Fatalf("unique case count = %d, want %d", len(seen), normalFullCount)
	}
}

func TestLookupAndByTierPreserveOwnership(t *testing.T) {
	for _, expected := range expectedTiers {
		want := expected.specs()
		if got := ByTier(expected.tier); !reflect.DeepEqual(got, want) {
			t.Errorf("ByTier(%q) = %v, want %v", expected.tier, got, want)
		}
		for _, wantSpec := range want {
			got, ok := Lookup(wantSpec.ID)
			if !ok {
				t.Errorf("Lookup(%q) did not find case", wantSpec.ID)
				continue
			}
			if !reflect.DeepEqual(got, wantSpec) {
				t.Errorf("Lookup(%q) = %+v, want %+v", wantSpec.ID, got, wantSpec)
			}
			if got.Tier != expected.tier {
				t.Errorf("Lookup(%q).Tier = %q, want owner %q", wantSpec.ID, got.Tier, expected.tier)
			}
		}
	}

	if got := ByTier("T9"); got != nil {
		t.Errorf("ByTier(unknown) = %v, want nil", got)
	}
	if got, ok := Lookup("missing-case"); ok || !reflect.DeepEqual(got, manifest.Spec{}) {
		t.Errorf("Lookup(missing) = (%+v, %t), want zero, false", got, ok)
	}
}

func TestCatalogAPIsDoNotExposeMutableAliases(t *testing.T) {
	original := []manifest.Spec{{
		ID: "dependent", Tier: "T1", Suite: manifest.SuiteNormal, Mandatory: true,
		Budget: time.Second, Requires: []string{"preflight"},
	}}
	cloned := clone(original)
	cloned[0].Requires[0] = "mutated"
	if original[0].Requires[0] != "preflight" {
		t.Fatalf("clone exposed prerequisite slice alias: %+v", original[0])
	}

	getters := []struct {
		name string
		get  func() []manifest.Spec
	}{
		{name: "Phase1", get: Phase1},
		{name: "Phase2", get: Phase2},
		{name: "NormalFull", get: NormalFull},
		{name: "ByTier", get: func() []manifest.Spec { return ByTier("T3") }},
	}
	for _, getter := range getters {
		t.Run(getter.name, func(t *testing.T) {
			first := getter.get()
			want := first[0]
			first[0] = manifest.Spec{ID: "mutated", Tier: "mutated", Suite: manifest.SuiteTUN}

			second := getter.get()
			if !reflect.DeepEqual(second[0], want) {
				t.Fatalf("second call starts with %+v after mutation, want %+v", second[0], want)
			}
		})
	}

	want := NormalFull()[0]
	got, ok := Lookup(want.ID)
	if !ok {
		t.Fatalf("Lookup(%q) did not find case", want.ID)
	}
	got.ID = "mutated"
	again, ok := Lookup(want.ID)
	if !ok || !reflect.DeepEqual(again, want) {
		t.Fatalf("Lookup(%q) after result mutation = (%+v, %t), want (%+v, true)", want.ID, again, ok, want)
	}
}

func TestValidateSourcesRejectsInvalidCatalogs(t *testing.T) {
	tests := []struct {
		name    string
		sources []tierSource
		want    string
	}{
		{
			name: "duplicate ID across tiers",
			sources: []tierSource{
				testSource("T1", phaseOne, manifest.RequiredWithBudget("same", "T1", time.Second)),
				testSource("T2", phaseOne, manifest.RequiredWithBudget("same", "T2", time.Second)),
			},
			want: "duplicate case ID",
		},
		{
			name: "tier ownership mismatch",
			sources: []tierSource{
				testSource("T1", phaseOne, manifest.RequiredWithBudget("wrong-owner", "T2", time.Second)),
			},
			want: "declares tier \"T2\"",
		},
		{
			name: "suite mismatch",
			sources: []tierSource{
				testSource("T1", phaseOne, manifest.Spec{
					ID: "tun-case", Tier: "T1", Suite: manifest.SuiteTUN, Mandatory: true, Budget: time.Second,
				}),
			},
			want: "declares suite \"tun-full\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSources(tt.sources)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validateSources() = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func assertCatalog(t *testing.T, name string, got, want []manifest.Spec, wantCount int) {
	t.Helper()
	if len(got) != wantCount {
		t.Errorf("%s count = %d, want %d", name, len(got), wantCount)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s order/content differs from tier registry order", name)
	}
}

func concatTierSpecs(tiers []struct {
	tier  string
	count int
	specs func() []manifest.Spec
}) []manifest.Spec {
	var specs []manifest.Spec
	for _, tier := range tiers {
		specs = append(specs, tier.specs()...)
	}
	return specs
}

func testSource(tier string, phase phase, specs ...manifest.Spec) tierSource {
	return tierSource{
		tier:  tier,
		phase: phase,
		specs: func() []manifest.Spec { return clone(specs) },
	}
}
