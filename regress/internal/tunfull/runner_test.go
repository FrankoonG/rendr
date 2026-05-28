package tunfull

import (
	"context"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/report"
)

func TestRunTunFullCaseFilter(t *testing.T) {
	suite := report.New()
	Run(context.Background(), suite, ".", Options{Case: "TUN-full.G1-smoke"})
	if len(suite.Cases) != 1 {
		t.Fatalf("cases=%d want 1", len(suite.Cases))
	}
	c := suite.Cases[0]
	if c.Name != "TUN-full.G1-smoke" || c.Tier != "T7" || c.Failure != "" {
		t.Fatalf("bad filtered case: %+v", c)
	}
}

func TestRunTunFullDefaultStillGuardsUnimplementedCases(t *testing.T) {
	suite := report.New()
	Run(context.Background(), suite, ".", Options{Case: "TUN-full.G3-smoke"})
	if len(suite.Cases) != 1 {
		t.Fatalf("cases=%d want 1", len(suite.Cases))
	}
	if !suite.AnyFailedAt("T7") {
		t.Fatal("unimplemented tun-full case unexpectedly has no guard failure")
	}
}

func TestRunG2SmokeShort(t *testing.T) {
	c := runG2Smoke(context.Background(), g2SmokeOptions{
		name:       "TUN-full.G2-smoke",
		duration:   300 * time.Millisecond,
		interval:   25 * time.Millisecond,
		paths:      2,
		migrations: 1,
	})
	if c.Name != "TUN-full.G2-smoke" || c.Tier != "T7" || c.Failure != "" {
		t.Fatalf("bad G2 smoke case: %+v", c)
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
