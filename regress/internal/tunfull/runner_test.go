package tunfull

import (
	"context"
	"testing"

	"github.com/FrankoonG/rendr/regress/internal/report"
)

func TestRunTunFullCaseFilter(t *testing.T) {
	suite := report.New()
	Run(context.Background(), suite, ".", Options{Case: "TUN-full.G1-smoke"})
	if len(suite.Cases) != 1 {
		t.Fatalf("cases=%d want 1", len(suite.Cases))
	}
	c := suite.Cases[0]
	if c.Name != "TUN-full.G1-smoke" || c.Tier != "T7" || c.Failure == "" {
		t.Fatalf("bad filtered case: %+v", c)
	}
}

func TestRunTunFullCaseFilterMiss(t *testing.T) {
	suite := report.New()
	Run(context.Background(), suite, ".", Options{Case: "missing"})
	if len(suite.Cases) != 1 {
		t.Fatalf("cases=%d want 1", len(suite.Cases))
	}
	if suite.Cases[0].Name != "TUN-full-case-filter" || suite.Cases[0].Failure == "" {
		t.Fatalf("bad filter miss case: %+v", suite.Cases[0])
	}
}

func TestUnimplementedCaseFails(t *testing.T) {
	c := UnimplementedCase("")
	if c.Name != "TUN-full-not-implemented" || c.Tier != "T7" || c.Failure == "" {
		t.Fatalf("bad unimplemented case: %+v", c)
	}
}
