package tier7

import (
	"reflect"
	"testing"

	"github.com/FrankoonG/rendr/regress/internal/manifest"
)

var orderedCaseIDs = []string{
	"T7.capability.local-probe",
	"T7.tun.open-smoke",
	"T7.tun.packet-io",
	"T7.config.invalid-mtu",
	"T7.l3.identity-smoke",
	"T7.l3.identity-wire",
	"T7.capability.peer-denied",
	"T7.capability.peer-advertise",
	"T7.router.per-flow-hook",
	"T7.router.per-flow-cache",
	"T7.session.request",
	"T7.session.start",
	"T7.session.manager",
	"T7.session.lifecycle",
	"T7.session.path-observe",
	"T7.router.flow-deny",
	"T7.flow.lifecycle-stats",
	"T7.flow.observe",
	"T7.selector.per-flow",
	"T7.peer-egress-hook",
	"T7.tcp.peer-egress",
	"T7.udp.identity-smoke",
	"T7.udp.rendr-relay",
	"T7.udp.migration",
	"T7.tcp.rendr-relay",
	"T7.tcp.migration",
	"T7.tcp.lifecycle-flags",
	"T7.l3.parse-error-skip",
	"T7.l3.fragment-boundary",
	"T7.l3.unsupported-protocol",
}

func TestSpecsOrdered(t *testing.T) {
	specs := Specs()
	assertRequiredSpecs(t, specs)
	if got := specIDs(specs); !reflect.DeepEqual(got, orderedCaseIDs) {
		t.Fatalf("Specs IDs = %v, want %v", got, orderedCaseIDs)
	}
}

func TestSelectCaseDefs(t *testing.T) {
	t.Run("exact", func(t *testing.T) {
		defs, err := selectCaseDefs(Options{Case: orderedCaseIDs[5]})
		if err != nil {
			t.Fatal(err)
		}
		if got := defIDs(defs); !reflect.DeepEqual(got, orderedCaseIDs[5:6]) {
			t.Fatalf("selected IDs = %v, want %v", got, orderedCaseIDs[5:6])
		}
	})

	t.Run("inclusive resume", func(t *testing.T) {
		defs, err := selectCaseDefs(Options{FromCase: orderedCaseIDs[26]})
		if err != nil {
			t.Fatal(err)
		}
		if got := defIDs(defs); !reflect.DeepEqual(got, orderedCaseIDs[26:]) {
			t.Fatalf("selected IDs = %v, want %v", got, orderedCaseIDs[26:])
		}
	})

	t.Run("missing", func(t *testing.T) {
		if _, err := selectCaseDefs(Options{Case: "T7.missing"}); err == nil {
			t.Fatal("missing exact filter succeeded")
		}
		if _, err := selectCaseDefs(Options{FromCase: "T7.missing"}); err == nil {
			t.Fatal("missing resume filter succeeded")
		}
	})
}

func specIDs(specs []manifest.Spec) []string {
	ids := make([]string, len(specs))
	for i, spec := range specs {
		ids[i] = spec.ID
	}
	return ids
}

func assertRequiredSpecs(t *testing.T, specs []manifest.Spec) {
	t.Helper()
	if err := manifest.Validate(specs); err != nil {
		t.Fatal(err)
	}
	for _, spec := range specs {
		if !spec.Mandatory || spec.Suite != manifest.SuiteNormal || spec.Budget <= 0 {
			t.Fatalf("invalid required spec: %+v", spec)
		}
	}
}

func defIDs(defs []caseDef) []string {
	ids := make([]string, len(defs))
	for i, def := range defs {
		ids[i] = def.spec.ID
	}
	return ids
}
