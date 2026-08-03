// Package tier3 runs the path-factory x xray outbound matrix from
// docs/regression-suite.md section 7. The matrix remains authored as plain Go
// tests while this package gives the regress driver an explicit, ordered
// manifest and fail-closed JSON result parsing.
package tier3

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/gotestjson"
	"github.com/FrankoonG/rendr/regress/internal/manifest"
	"github.com/FrankoonG/rendr/regress/internal/report"
)

const matrixTestBudget = 6 * time.Minute

// Options filters the tier3 matrix execution.
type Options struct {
	Case     string
	FromCase string
}

type caseDef struct {
	spec     manifest.Spec
	expected []string
}

func matrixCase(testName string) caseDef {
	return caseDef{
		spec:     manifest.RequiredWithBudget(testName, "T3", matrixTestBudget),
		expected: []string{testName},
	}
}

// caseDefs freezes the top-level matrix tests and their execution/report
// order. TestTUNT3 remains part of the baseline until suite membership is
// redesigned in a later milestone.
var caseDefs = []caseDef{
	matrixCase("TestT3GlueAVMessOverRendrTransport"),
	matrixCase("TestT3GlueAVMessOverRendrTransportMigrates"),
	matrixCase("TestT3GlueAVLESSTLSOverRendrTransportMigrates"),
	matrixCase("TestT3GlueATrojanTLSOverRendrTransportMigrates"),
	matrixCase("TestT3GlueASS2022OverRendrTransportMigrates"),
	matrixCase("TestT3GlueAVLESSTLSOverRendrTransport"),
	matrixCase("TestT3GlueAVLESSTLSMLKEMOverRendrTransport"),
	matrixCase("TestT3GlueATrojanTLSOverRendrTransport"),
	matrixCase("TestT3GlueASS2022OverRendrTransport"),
	matrixCase("TestT3VlessTCPxVlessHysteria2Transport"),
	matrixCase("TestT3FreedomXFreedom"),
	matrixCase("TestT3StreamXrayBalancerFreedom"),
	matrixCase("TestT3MixedBareTCPxVlessVisionTLS"),
	matrixCase("TestT3ThreePath_SS_VMess_Vless"),
	matrixCase("TestT3VlessVisionTLSMLKEM_xItself"),
	matrixCase("TestT3StreamNestedTwoLayer"),
	matrixCase("TestT3StreamReverseOutbound"),
	matrixCase("TestT3PacketBareUDPFlowxUDPFlow"),
	matrixCase("TestT3PacketQUICDatagramxQUICDatagram"),
	matrixCase("TestT3PacketXrayFreedomUDPxUDPFlow"),
	matrixCase("TestT3PacketXrayBalancerUDPxUDPFlow"),
	matrixCase("TestT3VlessVisionRealityXItself"),
	matrixCase("TestT3StreamDirectXRelay"),
	matrixCase("TestT3StreamSS2022ViaRelay"),
	matrixCase("TestT3SS2022xSS2022"),
	matrixCase("TestT3PacketSS2022UDPxUDPFlow"),
	matrixCase("TestT3TrojanxTrojan"),
	matrixCase("TestTUNT3FreedomStreamOverTUN"),
	matrixCase("TestTUNT3SS2022StreamOverTUN"),
	matrixCase("TestTUNT3VMessStreamOverTUN"),
	matrixCase("TestTUNT3TrojanTLSStreamOverTUN"),
	matrixCase("TestTUNT3VLESSVisionTLSStreamOverTUN"),
	matrixCase("TestTUNT3VLESSVisionTLSMLKEMStreamOverTUN"),
	matrixCase("TestTUNT3VLESSVisionRealityStreamOverTUN"),
	matrixCase("TestTUNT3VLESSHysteria2TransportStreamOverTUN"),
	matrixCase("TestTUNT3MixedSS2022VMessStreamOverTUN"),
	matrixCase("TestTUNT3ThreePathSSVMessVLESSStreamOverTUN"),
	matrixCase("TestTUNT3DirectRelayStreamOverTUN"),
	matrixCase("TestTUNT3NestedTwoLayerStreamOverTUN"),
	matrixCase("TestTUNT3PacketXrayFreedomUDPxUDPFlowOverTUN"),
	matrixCase("TestTUNT3PacketXrayBalancerUDPxUDPFlowOverTUN"),
	matrixCase("TestT3VlessVisionTLSxItself"),
	matrixCase("TestT3VMessxVMess"),
	matrixCase("TestT3SS2022xVMess"),
}

// Specs returns a copy of the ordered T3 case manifest.
func Specs() []manifest.Spec {
	specs := make([]manifest.Spec, len(caseDefs))
	for i, def := range caseDefs {
		specs[i] = def.spec
	}
	return specs
}

func selectCaseDefs(opts Options) ([]caseDef, error) {
	selected, err := manifest.Select(Specs(), opts.Case, opts.FromCase)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]caseDef, len(caseDefs))
	for _, def := range caseDefs {
		byID[def.spec.ID] = def
	}
	defs := make([]caseDef, 0, len(selected))
	for _, spec := range selected {
		defs = append(defs, byID[spec.ID])
	}
	return defs, nil
}

func selectSpecs(opts Options) ([]manifest.Spec, error) {
	defs, err := selectCaseDefs(opts)
	if err != nil {
		return nil, err
	}
	specs := make([]manifest.Spec, len(defs))
	for i, def := range defs {
		specs[i] = def.spec
	}
	return specs, nil
}

// Run shells out to go test -json under the regress submodule and translates
// each selected top-level test outcome into a tier3 report.Case.
func Run(ctx context.Context, suite *report.Suite, rendrRoot string, opts Options) {
	selected, err := selectCaseDefs(opts)
	if err != nil {
		suite.Add(report.Case{
			Name:    "T3-case-filter",
			Tier:    "T3",
			Failure: fmt.Sprintf("select T3 cases case=%q from-case=%q: %v", opts.Case, opts.FromCase, err),
		})
		return
	}
	if len(selected) == 0 {
		suite.Add(report.Case{Name: "T3-matrix", Tier: "T3", InvalidReason: "no matrix tests selected"})
		return
	}

	expected := expectedTestNames(selected)
	cctx, cancel := context.WithTimeout(ctx, 8*time.Minute)
	defer cancel()
	result, runErr := tier3GoTestExecutor.Run(cctx, gotestjson.Request{
		Dir:         filepath.Join(rendrRoot, "regress"),
		Package:     "./internal/matrix/...",
		Pattern:     exactTestPattern(expected),
		Expected:    testExpectations(expected),
		TestTimeout: matrixTestBudget,
	})
	if runErr != nil && result.Passed() {
		result.Issues = append(result.Issues, gotestjson.Issue{Code: gotestjson.IssueCommandFailed, Detail: runErr.Error()})
	}
	for _, testCase := range goTestReportCases(selected, result) {
		suite.Add(testCase)
	}
}

func expectedTestNames(defs []caseDef) []string {
	var names []string
	for _, def := range defs {
		names = append(names, def.expected...)
	}
	return names
}
