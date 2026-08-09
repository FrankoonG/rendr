package tcpquarantine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"
)

var errFakeCommand = errors.New("fake nft command error")

type runnerCall struct {
	args  []string
	stdin []byte
}

type runnerStep struct {
	wantArgs  []string
	wantStdin []byte
	check     func(*testing.T, context.Context, runnerCall)
	run       func(context.Context) (RunResult, error)
	result    RunResult
	err       error
}

type scriptedRunner struct {
	t *testing.T

	mu    sync.Mutex
	steps []runnerStep
	calls []runnerCall
}

func newScriptedRunner(t *testing.T) *scriptedRunner {
	t.Helper()
	return &scriptedRunner{t: t}
}

func (runner *scriptedRunner) append(steps ...runnerStep) {
	runner.mu.Lock()
	runner.steps = append(runner.steps, steps...)
	runner.mu.Unlock()
}

func (runner *scriptedRunner) Run(ctx context.Context, args []string, stdin []byte) (RunResult, error) {
	call := runnerCall{args: append([]string(nil), args...), stdin: append([]byte(nil), stdin...)}
	runner.mu.Lock()
	if len(runner.steps) == 0 {
		runner.calls = append(runner.calls, call)
		runner.mu.Unlock()
		runner.t.Errorf("unexpected nft call: args=%q stdin=%q", args, stdin)
		return RunResult{}, errors.New("unexpected fake runner call")
	}
	step := runner.steps[0]
	runner.steps = runner.steps[1:]
	runner.calls = append(runner.calls, call)
	runner.mu.Unlock()

	if step.wantArgs != nil && !reflect.DeepEqual(args, step.wantArgs) {
		runner.t.Errorf("nft args = %q, want %q", args, step.wantArgs)
	}
	if step.wantStdin != nil && !bytes.Equal(stdin, step.wantStdin) {
		runner.t.Errorf("nft stdin = %q, want %q", stdin, step.wantStdin)
	}
	if step.check != nil {
		step.check(runner.t, ctx, call)
	}
	if step.run != nil {
		return step.run(ctx)
	}
	return step.result, step.err
}

func (runner *scriptedRunner) assertDone() {
	runner.t.Helper()
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if len(runner.steps) != 0 {
		runner.t.Errorf("%d expected nft calls were not made", len(runner.steps))
	}
}

func (runner *scriptedRunner) callCount() int {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return len(runner.calls)
}

func mustManager(t *testing.T, runner Runner) *Manager {
	t.Helper()
	manager, err := New(Config{
		Runner:           runner,
		ReconcileTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	scope, err := currentNamespaceScope()
	if err != nil {
		t.Fatalf("currentNamespaceScope() error = %v", err)
	}
	// Most lease tests isolate mutation semantics. Reconciliation has its own
	// scripted tests and production calls cannot set this package-private map.
	manager.reconciledScopes[scope] = struct{}{}
	return manager
}

func testTransactionID() TransactionID {
	var id TransactionID
	for index := range id {
		id[index] = 0x22
	}
	return id
}

func testTuple() Tuple {
	return Tuple{
		Local:  netip.MustParseAddrPort("192.0.2.10:43210"),
		Remote: netip.MustParseAddrPort("198.51.100.20:443"),
	}
}

func exactTableResult(t *testing.T, spec nftSpec, mutate func([]any)) RunResult {
	t.Helper()
	objects := exactTableObjects(spec)
	if mutate != nil {
		mutate(objects)
	}
	payload, err := json.Marshal(map[string]any{
		"nftables": objects,
		"future":   "ignored document field",
	})
	if err != nil {
		t.Fatalf("marshal nft JSON: %v", err)
	}
	return RunResult{Stdout: payload}
}

func exactTableObjects(spec nftSpec) []any {
	inputExpressions := tupleExpressions(
		spec.tuple.Remote.Addr().String(), spec.tuple.Local.Addr().String(),
		spec.tuple.Remote.Port(), spec.tuple.Local.Port(),
	)
	outputExpressions := tupleExpressions(
		spec.tuple.Local.Addr().String(), spec.tuple.Remote.Addr().String(),
		spec.tuple.Local.Port(), spec.tuple.Remote.Port(),
	)
	return []any{
		map[string]any{"metainfo": map[string]any{"json_schema_version": 1}},
		map[string]any{"table": map[string]any{
			"family": nftFamily, "name": spec.table, "handle": 41, "future": true,
		}},
		map[string]any{"chain": chainJSON(spec, inputChain)},
		map[string]any{"chain": chainJSON(spec, outputChain)},
		map[string]any{"rule": ruleJSON(spec, inputChain, inputExpressions)},
		map[string]any{"rule": ruleJSON(spec, outputChain, outputExpressions)},
	}
}

func chainJSON(spec nftSpec, name string) map[string]any {
	return map[string]any{
		"family": nftFamily,
		"table":  spec.table,
		"name":   name,
		"type":   chainType,
		"hook":   name,
		"prio":   chainPriority,
		"policy": chainPolicy,
		"handle": 42,
		"future": map[string]any{"ignored": true},
	}
}

func ruleJSON(spec nftSpec, chain string, expressions []any) map[string]any {
	return map[string]any{
		"family":  nftFamily,
		"table":   spec.table,
		"chain":   chain,
		"expr":    expressions,
		"comment": spec.comment,
		"handle":  43,
		"future":  true,
	}
}

func tupleExpressions(sourceAddress, destinationAddress string, sourcePort, destinationPort uint16) []any {
	return []any{
		matchJSON("ip", "saddr", sourceAddress),
		matchJSON("ip", "daddr", destinationAddress),
		matchJSON("tcp", "sport", sourcePort),
		matchJSON("tcp", "dport", destinationPort),
		map[string]any{"counter": map[string]any{"packets": 7, "bytes": 700, "future": true}},
		map[string]any{"drop": nil},
	}
}

func matchJSON(protocol, field string, value any) map[string]any {
	return map[string]any{"match": map[string]any{
		"op": "==",
		"left": map[string]any{"payload": map[string]any{
			"protocol": protocol,
			"field":    field,
			"future":   true,
		}},
		"right":  value,
		"future": true,
	}}
}

func emptyTablesResult(t *testing.T) RunResult {
	return tableListResult(t)
}

func tableListResult(t *testing.T, names ...string) RunResult {
	t.Helper()
	objects := []any{
		map[string]any{"metainfo": map[string]any{"json_schema_version": 1}},
		map[string]any{"future_metadata": map[string]any{"ignored": true}},
	}
	for _, name := range names {
		objects = append(objects, map[string]any{"table": map[string]any{
			"family": nftFamily,
			"name":   name,
		}})
	}
	payload, err := json.Marshal(map[string]any{
		"nftables": objects,
	})
	if err != nil {
		t.Fatalf("marshal empty nft table list: %v", err)
	}
	return RunResult{Stdout: payload}
}

func absentObservationSteps(t *testing.T, spec nftSpec) []runnerStep {
	t.Helper()
	return []runnerStep{
		{wantArgs: spec.listTableArgs(), err: errFakeCommand},
		{wantArgs: listTablesArgs(), result: emptyTablesResult(t)},
	}
}

func requireBoundedLiveContext(t *testing.T, ctx context.Context, _ runnerCall) {
	t.Helper()
	if err := ctx.Err(); err != nil {
		t.Errorf("reconcile context is already canceled: %v", err)
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Error("reconcile context has no deadline")
		return
	}
	if remaining := time.Until(deadline); remaining <= 0 || remaining > 2*time.Second {
		t.Errorf("reconcile deadline remaining = %s, want bounded positive duration", remaining)
	}
}

func mutateRule(objects []any, chain string, mutate func(map[string]any)) {
	for _, rawObject := range objects {
		object, ok := rawObject.(map[string]any)
		if !ok {
			continue
		}
		rule, ok := object["rule"].(map[string]any)
		if !ok || rule["chain"] != chain {
			continue
		}
		mutate(rule)
		return
	}
	panic(fmt.Sprintf("rule %q not found", chain))
}
