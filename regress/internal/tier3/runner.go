// Package tier3 runs the path-factory x xray outbound matrix from
// docs/regression-suite.md section 7. The matrix remains authored as plain Go
// tests while this package gives the regress driver an explicit, ordered
// manifest and fail-closed JSON result parsing.
package tier3

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/FrankoonG/rendr/regress/internal/manifest"
	"github.com/FrankoonG/rendr/regress/internal/report"
)

const matrixTestBudget = 6 * time.Minute

// Options filters the tier3 matrix execution.
type Options struct {
	Case     string
	FromCase string
}

// caseSpecs freezes the top-level matrix tests and their execution/report
// order. TestTUNT3 remains part of the baseline until suite membership is
// redesigned in a later milestone.
var caseSpecs = []manifest.Spec{
	manifest.RequiredWithBudget("TestT3GlueAVMessOverRendrTransport", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestT3GlueAVMessOverRendrTransportMigrates", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestT3GlueAVLESSTLSOverRendrTransportMigrates", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestT3GlueATrojanTLSOverRendrTransportMigrates", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestT3GlueASS2022OverRendrTransportMigrates", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestT3GlueAVLESSTLSOverRendrTransport", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestT3GlueAVLESSTLSMLKEMOverRendrTransport", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestT3GlueATrojanTLSOverRendrTransport", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestT3GlueASS2022OverRendrTransport", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestT3VlessTCPxVlessHysteria2Transport", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestT3FreedomXFreedom", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestT3StreamXrayBalancerFreedom", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestT3MixedBareTCPxVlessVisionTLS", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestT3ThreePath_SS_VMess_Vless", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestT3VlessVisionTLSMLKEM_xItself", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestT3StreamNestedTwoLayer", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestT3StreamReverseOutbound", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestT3PacketBareUDPFlowxUDPFlow", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestT3PacketQUICDatagramxQUICDatagram", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestT3PacketXrayFreedomUDPxUDPFlow", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestT3PacketXrayBalancerUDPxUDPFlow", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestT3VlessVisionRealityXItself", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestT3StreamDirectXRelay", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestT3StreamSS2022ViaRelay", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestT3SS2022xSS2022", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestT3PacketSS2022UDPxUDPFlow", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestT3TrojanxTrojan", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestTUNT3FreedomStreamOverTUN", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestTUNT3SS2022StreamOverTUN", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestTUNT3VMessStreamOverTUN", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestTUNT3TrojanTLSStreamOverTUN", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestTUNT3VLESSVisionTLSStreamOverTUN", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestTUNT3VLESSVisionTLSMLKEMStreamOverTUN", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestTUNT3VLESSVisionRealityStreamOverTUN", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestTUNT3VLESSHysteria2TransportStreamOverTUN", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestTUNT3MixedSS2022VMessStreamOverTUN", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestTUNT3ThreePathSSVMessVLESSStreamOverTUN", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestTUNT3DirectRelayStreamOverTUN", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestTUNT3NestedTwoLayerStreamOverTUN", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestTUNT3PacketXrayFreedomUDPxUDPFlowOverTUN", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestTUNT3PacketXrayBalancerUDPxUDPFlowOverTUN", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestT3VlessVisionTLSxItself", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestT3VMessxVMess", "T3", matrixTestBudget),
	manifest.RequiredWithBudget("TestT3SS2022xVMess", "T3", matrixTestBudget),
}

// Specs returns a copy of the ordered T3 case manifest.
func Specs() []manifest.Spec {
	return append([]manifest.Spec(nil), caseSpecs...)
}

func selectSpecs(opts Options) ([]manifest.Spec, error) {
	return manifest.Select(Specs(), opts.Case, opts.FromCase)
}

// Run shells out to go test -json under the regress submodule and translates
// each selected top-level test outcome into a tier3 report.Case.
func Run(ctx context.Context, suite *report.Suite, rendrRoot string, opts Options) {
	selected, err := selectSpecs(opts)
	if err != nil {
		suite.Add(report.Case{
			Name:    "T3-case-filter",
			Tier:    "T3",
			Failure: fmt.Sprintf("select T3 cases case=%q from-case=%q: %v", opts.Case, opts.FromCase, err),
		})
		return
	}
	if len(selected) == 0 {
		suite.Add(report.Case{Name: "T3-matrix", Tier: "T3", Failure: "no matrix tests selected"})
		return
	}

	regressDir := filepath.Join(rendrRoot, "regress")
	start := time.Now()
	cctx, cancel := context.WithTimeout(ctx, 8*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(cctx, "go", buildGoTestArgs(selected)...)
	cmd.Dir = regressDir
	cmd.WaitDelay = 15 * time.Second
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		addSetupFailure(suite, start, "stdout pipe: "+err.Error())
		return
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		addSetupFailure(suite, start, "go test start: "+err.Error())
		return
	}

	cases, parseErr := parseTestEvents(stdout, selected)
	waitErr := cmd.Wait()
	if parseErr != nil {
		addSetupFailure(suite, start, "parse go test JSON: "+parseErr.Error())
		return
	}
	for _, c := range cases {
		suite.Add(c)
	}

	if waitErr == nil || errors.Is(waitErr, io.EOF) {
		return
	}
	var exitErr *exec.ExitError
	if !errors.As(waitErr, &exitErr) {
		addSetupFailure(suite, start, "go test wait: "+waitErr.Error())
		return
	}
	if !hasFailure(cases) {
		addSetupFailure(suite, start, "go test exited unsuccessfully without a selected test failure: "+waitErr.Error())
	}
}

func addSetupFailure(suite *report.Suite, start time.Time, failure string) {
	suite.Add(report.Case{
		Name:     "T3-setup",
		Tier:     "T3",
		Duration: time.Since(start),
		Failure:  failure,
	})
}

func hasFailure(cases []report.Case) bool {
	for _, c := range cases {
		if c.Failure != "" {
			return true
		}
	}
	return false
}

func buildGoTestArgs(selected []manifest.Spec) []string {
	return []string{
		"test",
		"-json",
		"-count=1",
		"-timeout",
		"6m",
		"-run",
		buildRunPattern(selected),
		"./internal/matrix/...",
	}
}

func buildRunPattern(selected []manifest.Spec) string {
	quoted := make([]string, len(selected))
	for i, spec := range selected {
		quoted[i] = regexp.QuoteMeta(spec.ID)
	}
	if len(quoted) == 1 {
		return "^" + quoted[0] + "$"
	}
	return "^(?:" + strings.Join(quoted, "|") + ")$"
}

func parseTestEvents(r io.Reader, selected []manifest.Spec) ([]report.Case, error) {
	selectedByID := make(map[string]struct{}, len(selected))
	for _, spec := range selected {
		selectedByID[spec.ID] = struct{}{}
	}

	records := make(map[string]*testRec, len(selected))
	selectedEvents := 0
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1<<20), 1<<22)
	for scanner.Scan() {
		var ev event
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			continue
		}
		if ev.Test == "" || strings.Contains(ev.Test, "/") {
			continue
		}
		if _, ok := selectedByID[ev.Test]; !ok {
			continue
		}
		selectedEvents++
		rec := records[ev.Test]
		if rec == nil {
			rec = &testRec{seen: true}
			records[ev.Test] = rec
		}
		switch ev.Action {
		case "output":
			if len(rec.output)+len(ev.Output) <= 16<<10 {
				rec.output += ev.Output
			}
		case "pass", "fail", "skip":
			rec.result = ev.Action
			rec.elapsed = time.Duration(ev.Elapsed * float64(time.Second))
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	cases := make([]report.Case, 0, len(selected))
	for _, spec := range selected {
		rec := records[spec.ID]
		c := report.Case{Name: spec.ID, Tier: spec.Tier}
		if rec == nil || !rec.seen {
			if selectedEvents == 0 {
				c.Failure = "matrix test absent: go test JSON contained zero selected tests"
			} else {
				c.Failure = "matrix test absent from go test JSON"
			}
			cases = append(cases, c)
			continue
		}
		c.Duration = rec.elapsed
		switch rec.result {
		case "pass":
		case "fail":
			c.Failure = withOutput("matrix test failed", rec.output)
		case "skip":
			c.SkipReason = "matrix test skipped"
		default:
			c.Failure = withOutput("matrix test produced no terminal pass/fail/skip event", rec.output)
		}
		cases = append(cases, c)
	}
	return cases, nil
}

func withOutput(message, output string) string {
	output = strings.TrimSpace(output)
	if output == "" {
		return message
	}
	return message + ":\n" + output
}

type event struct {
	Action  string  `json:"Action"`
	Test    string  `json:"Test"`
	Elapsed float64 `json:"Elapsed"`
	Output  string  `json:"Output"`
}

type testRec struct {
	seen    bool
	elapsed time.Duration
	result  string
	output  string
}
