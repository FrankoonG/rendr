package tcpquarantine

import "testing"

func TestVerifyTableJSONAllowsMetadataButRejectsMutatedExpressions(t *testing.T) {
	manager := mustManager(t, newScriptedRunner(t))
	spec := manager.newSpec(testTransactionID(), testTuple())
	tests := []struct {
		name    string
		mutate  func([]any)
		wantErr bool
	}{
		{name: "extra metadata is ignored"},
		{
			name: "source address changed",
			mutate: func(objects []any) {
				mutateRule(objects, inputChain, func(rule map[string]any) {
					expressions := rule["expr"].([]any)
					match := expressions[0].(map[string]any)["match"].(map[string]any)
					match["right"] = "203.0.113.99"
				})
			},
			wantErr: true,
		},
		{
			name: "port changed",
			mutate: func(objects []any) {
				mutateRule(objects, outputChain, func(rule map[string]any) {
					expressions := rule["expr"].([]any)
					match := expressions[3].(map[string]any)["match"].(map[string]any)
					match["right"] = 444
				})
			},
			wantErr: true,
		},
		{
			name: "counter removed",
			mutate: func(objects []any) {
				mutateRule(objects, inputChain, func(rule map[string]any) {
					expressions := rule["expr"].([]any)
					expressions[4] = map[string]any{"counter": map[string]any{"packets": 0}}
				})
			},
			wantErr: true,
		},
		{
			name: "drop changed to accept",
			mutate: func(objects []any) {
				mutateRule(objects, outputChain, func(rule map[string]any) {
					expressions := rule["expr"].([]any)
					expressions[5] = map[string]any{"accept": nil}
				})
			},
			wantErr: true,
		},
		{
			name: "extra expression",
			mutate: func(objects []any) {
				mutateRule(objects, outputChain, func(rule map[string]any) {
					rule["expr"] = append(rule["expr"].([]any), map[string]any{"log": nil})
				})
			},
			wantErr: true,
		},
		{
			name: "comment changed",
			mutate: func(objects []any) {
				mutateRule(objects, inputChain, func(rule map[string]any) {
					rule["comment"] = "foreign-owner"
				})
			},
			wantErr: true,
		},
		{
			name: "base chain hook changed",
			mutate: func(objects []any) {
				for _, rawObject := range objects {
					object := rawObject.(map[string]any)
					chain, ok := object["chain"].(map[string]any)
					if ok && chain["name"] == inputChain {
						chain["hook"] = outputChain
					}
				}
			},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := exactTableResult(t, spec, test.mutate)
			err := verifyTableJSON(result.Stdout, spec)
			if (err != nil) != test.wantErr {
				t.Fatalf("verifyTableJSON() error = %v, wantErr = %v", err, test.wantErr)
			}
		})
	}
}

func TestTablePresentInListRejectsMalformedTableObject(t *testing.T) {
	manager := mustManager(t, newScriptedRunner(t))
	spec := manager.newSpec(testTransactionID(), testTuple())
	_, err := tablePresentInList([]byte(`{"nftables":[{"table":{"family":"inet"}}]}`), spec)
	if err == nil {
		t.Fatalf("tablePresentInList() error = %v, want malformed enumeration error", err)
	}
}

func TestTablePresentInListRejectsAmbiguousObjects(t *testing.T) {
	manager := mustManager(t, newScriptedRunner(t))
	spec := manager.newSpec(testTransactionID(), testTuple())
	payload := `{"nftables":[{"table":{"family":"inet","name":"elsewhere"},"chain":{}}]}`
	if _, err := tablePresentInList([]byte(payload), spec); err == nil {
		t.Fatalf("tablePresentInList(%s) unexpectedly succeeded", payload)
	}
}
