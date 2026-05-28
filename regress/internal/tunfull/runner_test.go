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
	Run(context.Background(), suite, ".", Options{Case: "TUN-full.T3-xray-matrix"})
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

func TestRunG3SmokeShort(t *testing.T) {
	c := runG3Smoke(context.Background(), g3Options{
		name:       "TUN-full.G3-smoke",
		duration:   300 * time.Millisecond,
		pps:        500,
		payloadLen: 256,
		paths:      2,
		migrations: 1,
		lossPct:    5,
		p95Ceiling: 200 * time.Millisecond,
	})
	if c.Name != "TUN-full.G3-smoke" || c.Tier != "T7" || c.Failure != "" {
		t.Fatalf("bad G3 case: %+v", c)
	}
}

func TestRunG4PathDeathShort(t *testing.T) {
	c := runG4PathDeath(context.Background(), g4Options{
		name:     "TUN-full.G4-path-death",
		duration: 600 * time.Millisecond,
		killAt:   100 * time.Millisecond,
		echoInt:  20 * time.Millisecond,
		paths:    2,
		budget:   time.Second,
	})
	if c.Name != "TUN-full.G4-path-death" || c.Tier != "T7" || c.Failure != "" {
		t.Fatalf("bad G4 case: %+v", c)
	}
}

func TestRunG5PathRecoveryShort(t *testing.T) {
	c := runG5PathRecovery(context.Background(), g5Options{
		name:         "TUN-full.G5-path-recovery",
		paths:        2,
		postAddBytes: 32 << 10,
	})
	if c.Name != "TUN-full.G5-path-recovery" || c.Tier != "T7" || c.Failure != "" {
		t.Fatalf("bad G5 case: %+v", c)
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
