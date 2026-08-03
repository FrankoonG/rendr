package manifest

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func testSpecs() []Spec {
	a := RequiredWithBudget("A", "T1", time.Second)
	b := RequiredWithBudget("B", "T1", time.Second)
	b.Requires = []string{"A"}
	c := RequiredWithBudget("C", "T1", time.Second)
	c.Requires = []string{"B"}
	return []Spec{a, b, c}
}

func testRegistry() []Spec {
	specs := testSpecs()
	d := RequiredWithBudget("D", "T1", time.Second)
	d.Requires = []string{"A"}
	tun := Spec{
		ID:        "TUN",
		Tier:      "T7",
		Suite:     SuiteTUN,
		Mandatory: true,
		Budget:    time.Second,
	}
	return append(specs, d, tun)
}

func TestSelectExactAndResume(t *testing.T) {
	tests := []struct {
		name string
		one  string
		from string
		want []string
	}{
		{name: "all", want: []string{"A", "B", "C"}},
		{name: "exact remains exact", one: "C", want: []string{"C"}},
		{name: "resume remains an inclusive suffix", from: "B", want: []string{"B", "C"}},
	}

	exact, err := SelectWithPrerequisites(testSpecs(), "C", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := specIDs(exact); !reflect.DeepEqual(got, []string{"A", "B", "C"}) {
		t.Fatalf("exact closure=%v", got)
	}
	resumed, err := SelectWithPrerequisites(testSpecs(), "", "C")
	if err != nil {
		t.Fatal(err)
	}
	if got := specIDs(resumed); !reflect.DeepEqual(got, []string{"A", "B", "C"}) {
		t.Fatalf("resume closure=%v", got)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Select(testSpecs(), tt.one, tt.from)
			if err != nil {
				t.Fatal(err)
			}
			if gotIDs := specIDs(got); !reflect.DeepEqual(gotIDs, tt.want) {
				t.Fatalf("ids=%v want %v", gotIDs, tt.want)
			}
		})
	}
}

func TestSelectRejectsAmbiguousOrMissingFilters(t *testing.T) {
	for _, tc := range []struct {
		name string
		one  string
		from string
		want string
	}{
		{name: "both", one: "A", from: "B", want: "mutually exclusive"},
		{name: "missing exact", one: "missing", want: "--case"},
		{name: "missing resume", from: "missing", want: "--from-case"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Select(testSpecs(), tc.one, tc.from)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v want substring %q", err, tc.want)
			}
		})
	}
}

func TestValidateAcceptsClosedAcyclicRegistry(t *testing.T) {
	if err := Validate(testRegistry()); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejectsManifestMutations(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]Spec) []Spec
		want   string
	}{
		{
			name: "empty ID",
			mutate: func(specs []Spec) []Spec {
				specs[0].ID = ""
				return specs
			},
			want: "empty ID",
		},
		{
			name: "duplicate ID",
			mutate: func(specs []Spec) []Spec {
				specs[1].ID = specs[0].ID
				return specs
			},
			want: "duplicate case ID",
		},
		{
			name: "empty tier",
			mutate: func(specs []Spec) []Spec {
				specs[0].Tier = ""
				return specs
			},
			want: "empty tier",
		},
		{
			name: "unsupported suite",
			mutate: func(specs []Spec) []Spec {
				specs[0].Suite = "other"
				return specs
			},
			want: "unsupported suite",
		},
		{
			name: "empty suite",
			mutate: func(specs []Spec) []Spec {
				specs[0].Suite = ""
				return specs
			},
			want: "unsupported suite",
		},
		{
			name: "optional case",
			mutate: func(specs []Spec) []Spec {
				specs[0].Mandatory = false
				return specs
			},
			want: "not mandatory",
		},
		{
			name: "zero budget",
			mutate: func(specs []Spec) []Spec {
				specs[0].Budget = 0
				return specs
			},
			want: "non-positive budget",
		},
		{
			name: "negative budget",
			mutate: func(specs []Spec) []Spec {
				specs[0].Budget = -time.Nanosecond
				return specs
			},
			want: "non-positive budget",
		},
		{
			name: "duplicate prerequisite",
			mutate: func(specs []Spec) []Spec {
				specs[1].Requires = []string{"A", "A"}
				return specs
			},
			want: "duplicate prerequisite",
		},
		{
			name: "unknown prerequisite",
			mutate: func(specs []Spec) []Spec {
				specs[1].Requires = []string{"missing"}
				return specs
			},
			want: "unknown prerequisite",
		},
		{
			name: "prerequisite follows dependent",
			mutate: func(specs []Spec) []Spec {
				specs[2].Requires = nil
				specs[0].Requires = []string{"C"}
				return specs
			},
			want: "must precede",
		},
		{
			name: "cross-suite prerequisite",
			mutate: func(specs []Spec) []Spec {
				specs[1].Requires = []string{"TUN"}
				return specs
			},
			want: "cross-suite prerequisite",
		},
		{
			name: "cross-tier prerequisite",
			mutate: func(specs []Spec) []Spec {
				specs[1].Tier = "T2"
				return specs
			},
			want: "cross-tier prerequisite",
		},
		{
			name: "self cycle",
			mutate: func(specs []Spec) []Spec {
				specs[0].Requires = []string{"A"}
				return specs
			},
			want: "cyclic prerequisites",
		},
		{
			name: "transitive cycle",
			mutate: func(specs []Spec) []Spec {
				specs[0].Requires = []string{"C"}
				return specs
			},
			want: "cyclic prerequisites",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			specs := tt.mutate(testRegistry())
			err := Validate(specs)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestWithPrerequisitesPrependsTransitiveClosure(t *testing.T) {
	registry := testRegistry()
	tests := []struct {
		name     string
		selected []Spec
		want     []string
	}{
		{
			name:     "transitive exact selection",
			selected: []Spec{registry[2]},
			want:     []string{"A", "B", "C"},
		},
		{
			name:     "canonical prerequisite and selected order",
			selected: []Spec{registry[2], registry[3]},
			want:     []string{"A", "B", "C", "D"},
		},
		{
			name:     "selected prerequisite and repeated selections deduplicate",
			selected: []Spec{registry[1], registry[2], registry[2]},
			want:     []string{"A", "B", "C"},
		},
		{
			name: "empty selection",
			want: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := WithPrerequisites(registry, tt.selected)
			if err != nil {
				t.Fatal(err)
			}
			if gotIDs := specIDs(got); !reflect.DeepEqual(gotIDs, tt.want) {
				t.Fatalf("ids=%v want %v", gotIDs, tt.want)
			}
		})
	}

	prerequisite := RequiredWithBudget("prerequisite", "T1", time.Second)
	independent := RequiredWithBudget("independent", "T1", time.Second)
	dependent := RequiredWithBudget("dependent", "T1", time.Second)
	dependent.Requires = []string{prerequisite.ID}
	full := []Spec{prerequisite, independent, dependent}
	got, err := WithPrerequisites(full, full)
	if err != nil {
		t.Fatal(err)
	}
	if gotIDs := specIDs(got); !reflect.DeepEqual(gotIDs, []string{"prerequisite", "independent", "dependent"}) {
		t.Fatalf("full closure reordered canonical selection: %v", gotIDs)
	}
	got, err = WithPrerequisites(full, full[1:])
	if err != nil {
		t.Fatal(err)
	}
	if gotIDs := specIDs(got); !reflect.DeepEqual(gotIDs, []string{"prerequisite", "independent", "dependent"}) {
		t.Fatalf("suffix closure did not prepend missing prerequisite: %v", gotIDs)
	}
}

func TestWithPrerequisitesRejectsUnknownSelection(t *testing.T) {
	_, err := WithPrerequisites(testRegistry(), []Spec{RequiredWithBudget("missing", "T1", time.Second)})
	if err == nil || !strings.Contains(err.Error(), "not in canonical registry") {
		t.Fatalf("err=%v", err)
	}

	changed := testRegistry()[2]
	changed.Budget++
	_, err = WithPrerequisites(testRegistry(), []Spec{changed})
	if err == nil || !strings.Contains(err.Error(), "does not match canonical metadata") {
		t.Fatalf("metadata mismatch err=%v", err)
	}

	registry := testRegistry()
	_, err = WithPrerequisites(registry, []Spec{registry[2], registry[1]})
	if err == nil || !strings.Contains(err.Error(), "out of canonical order") {
		t.Fatalf("noncanonical selection err=%v", err)
	}
}

func TestSelectionsDoNotAliasRequires(t *testing.T) {
	registry := testRegistry()
	selected, err := Select(registry, "C", "")
	if err != nil {
		t.Fatal(err)
	}
	selected[0].Requires[0] = "mutated-select"
	if got := registry[2].Requires[0]; got != "B" {
		t.Fatalf("Select result mutated registry prerequisite to %q", got)
	}

	selected, err = Select(registry, "C", "")
	if err != nil {
		t.Fatal(err)
	}
	expanded, err := WithPrerequisites(registry, selected)
	if err != nil {
		t.Fatal(err)
	}
	expanded[1].Requires[0] = "mutated-closure"
	if got := registry[1].Requires[0]; got != "A" {
		t.Fatalf("WithPrerequisites result mutated registry prerequisite to %q", got)
	}
	if got := selected[0].Requires[0]; got != "B" {
		t.Fatalf("WithPrerequisites result mutated selected prerequisite to %q", got)
	}
}

func specIDs(specs []Spec) []string {
	ids := make([]string, len(specs))
	for i, spec := range specs {
		ids[i] = spec.ID
	}
	return ids
}
