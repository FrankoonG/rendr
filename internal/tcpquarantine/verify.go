package tcpquarantine

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
)

type observedState uint8

const (
	stateUnknown observedState = iota
	stateAbsent
	stateExact
	stateMalformed
)

type observation struct {
	state observedState
	err   error
}

type nftDocument struct {
	NFTables []json.RawMessage `json:"nftables"`
}

type tableObject struct {
	Family string `json:"family"`
	Name   string `json:"name"`
}

type chainObject struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Hook   string `json:"hook"`
	Prio   int    `json:"prio"`
	Policy string `json:"policy"`
}

type ruleObject struct {
	Family  string            `json:"family"`
	Table   string            `json:"table"`
	Chain   string            `json:"chain"`
	Expr    []json.RawMessage `json:"expr"`
	Comment string            `json:"comment"`
}

func verifyNFTSchemaJSON(payload []byte) error {
	document, err := decodeNFTDocument(payload)
	if err != nil {
		return err
	}
	metainfo := 0
	for index, raw := range document.NFTables {
		var item map[string]json.RawMessage
		if err := json.Unmarshal(raw, &item); err != nil {
			return fmt.Errorf("nftables item %d: %w", index, err)
		}
		if len(item) != 1 {
			return fmt.Errorf("nftables item %d has %d object kinds", index, len(item))
		}
		if metadata, ok := item["metainfo"]; ok {
			if err := verifySchemaMetainfo(metadata); err != nil {
				return fmt.Errorf("metainfo: %w", err)
			}
			metainfo++
		}
	}
	if metainfo != 1 {
		return fmt.Errorf("expected one metainfo object, found %d", metainfo)
	}
	return nil
}

func verifySchemaMetainfo(raw json.RawMessage) error {
	var metadata struct {
		JSONSchemaVersion json.RawMessage `json:"json_schema_version"`
	}
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return err
	}
	if metadata.JSONSchemaVersion == nil {
		return errors.New("json_schema_version is missing")
	}
	version, err := parseUintJSON(metadata.JSONSchemaVersion)
	if err != nil {
		return fmt.Errorf("json_schema_version: %w", err)
	}
	if version != 1 {
		return fmt.Errorf("json_schema_version is %d, expected 1", version)
	}
	return nil
}

func verifyTableJSON(payload []byte, spec nftSpec) error {
	document, err := decodeNFTDocument(payload)
	if err != nil {
		return err
	}
	tables := 0
	chains := make(map[string]chainObject, 2)
	rules := make(map[string]ruleObject, 2)

	for index, raw := range document.NFTables {
		var item map[string]json.RawMessage
		if err := json.Unmarshal(raw, &item); err != nil {
			return fmt.Errorf("nftables item %d: %w", index, err)
		}
		if len(item) != 1 {
			return fmt.Errorf("nftables item %d has %d object kinds", index, len(item))
		}
		for kind, body := range item {
			switch kind {
			case "metainfo":
				continue
			case "table":
				var table tableObject
				if err := json.Unmarshal(body, &table); err != nil {
					return fmt.Errorf("decode table: %w", err)
				}
				if table.Family != nftFamily || table.Name != spec.table {
					return fmt.Errorf("unexpected table %q/%q", table.Family, table.Name)
				}
				tables++
			case "chain":
				var chain chainObject
				if err := json.Unmarshal(body, &chain); err != nil {
					return fmt.Errorf("decode chain: %w", err)
				}
				if err := verifyChain(chain, spec); err != nil {
					return err
				}
				if _, duplicate := chains[chain.Name]; duplicate {
					return fmt.Errorf("duplicate chain %q", chain.Name)
				}
				chains[chain.Name] = chain
			case "rule":
				var rule ruleObject
				if err := json.Unmarshal(body, &rule); err != nil {
					return fmt.Errorf("decode rule: %w", err)
				}
				if rule.Family != nftFamily || rule.Table != spec.table {
					return fmt.Errorf("rule belongs to unexpected table %q/%q", rule.Family, rule.Table)
				}
				if rule.Chain != inputChain && rule.Chain != outputChain {
					return fmt.Errorf("rule belongs to unexpected chain %q", rule.Chain)
				}
				if _, duplicate := rules[rule.Chain]; duplicate {
					return fmt.Errorf("duplicate rule in chain %q", rule.Chain)
				}
				rules[rule.Chain] = rule
			default:
				return fmt.Errorf("unexpected nftables object %q", kind)
			}
		}
	}

	if tables != 1 {
		return fmt.Errorf("expected one table, found %d", tables)
	}
	if len(chains) != 2 || len(rules) != 2 {
		return fmt.Errorf("expected two chains and two rules, found %d chains and %d rules", len(chains), len(rules))
	}
	if _, ok := chains[inputChain]; !ok {
		return errors.New("input base chain is missing")
	}
	if _, ok := chains[outputChain]; !ok {
		return errors.New("output base chain is missing")
	}
	if err := verifyRule(rules[inputChain], spec.comment,
		spec.tuple.Remote.Addr(), spec.tuple.Local.Addr(), spec.tuple.Remote.Port(), spec.tuple.Local.Port()); err != nil {
		return fmt.Errorf("input rule: %w", err)
	}
	if err := verifyRule(rules[outputChain], spec.comment,
		spec.tuple.Local.Addr(), spec.tuple.Remote.Addr(), spec.tuple.Local.Port(), spec.tuple.Remote.Port()); err != nil {
		return fmt.Errorf("output rule: %w", err)
	}
	return nil
}

func verifyChain(chain chainObject, spec nftSpec) error {
	if chain.Family != nftFamily || chain.Table != spec.table {
		return fmt.Errorf("chain %q belongs to unexpected table %q/%q", chain.Name, chain.Family, chain.Table)
	}
	if chain.Name != inputChain && chain.Name != outputChain {
		return fmt.Errorf("unexpected chain %q", chain.Name)
	}
	if chain.Type != chainType || chain.Hook != chain.Name || chain.Prio != chainPriority || chain.Policy != chainPolicy {
		return fmt.Errorf("chain %q is not the expected base chain", chain.Name)
	}
	return nil
}

func verifyRule(rule ruleObject, comment string, sourceAddress, destinationAddress netip.Addr, sourcePort, destinationPort uint16) error {
	if rule.Comment != comment {
		return fmt.Errorf("comment mismatch: got %q", rule.Comment)
	}
	if len(rule.Expr) != 6 {
		return fmt.Errorf("expected six expressions, found %d", len(rule.Expr))
	}
	expectedMatches := []struct {
		protocol string
		field    string
		value    any
	}{
		{protocol: "ip", field: "saddr", value: sourceAddress},
		{protocol: "ip", field: "daddr", value: destinationAddress},
		{protocol: "tcp", field: "sport", value: sourcePort},
		{protocol: "tcp", field: "dport", value: destinationPort},
	}
	for index, expected := range expectedMatches {
		if err := verifyMatchExpression(rule.Expr[index], expected.protocol, expected.field, expected.value); err != nil {
			return fmt.Errorf("expression %d: %w", index, err)
		}
	}
	if err := verifyCounterExpression(rule.Expr[4]); err != nil {
		return fmt.Errorf("counter expression: %w", err)
	}
	if err := verifyDropExpression(rule.Expr[5]); err != nil {
		return fmt.Errorf("drop expression: %w", err)
	}
	return nil
}

func verifyMatchExpression(raw json.RawMessage, protocol, field string, expected any) error {
	object, err := decodeSingleExpression(raw, "match")
	if err != nil {
		return err
	}
	var match struct {
		Op    string          `json:"op"`
		Left  json.RawMessage `json:"left"`
		Right json.RawMessage `json:"right"`
	}
	if err := json.Unmarshal(object, &match); err != nil {
		return fmt.Errorf("decode match: %w", err)
	}
	if match.Op != "==" {
		return fmt.Errorf("match operator is %q", match.Op)
	}
	var left map[string]json.RawMessage
	if err := json.Unmarshal(match.Left, &left); err != nil {
		return fmt.Errorf("decode match left operand: %w", err)
	}
	if len(left) != 1 {
		return errors.New("match left operand is not one payload selector")
	}
	payloadRaw, ok := left["payload"]
	if !ok {
		return errors.New("match left operand is not a payload selector")
	}
	var payload struct {
		Protocol string `json:"protocol"`
		Field    string `json:"field"`
	}
	if err := json.Unmarshal(payloadRaw, &payload); err != nil {
		return fmt.Errorf("decode payload selector: %w", err)
	}
	if payload.Protocol != protocol || payload.Field != field {
		return fmt.Errorf("payload selector is %s.%s", payload.Protocol, payload.Field)
	}

	switch value := expected.(type) {
	case netip.Addr:
		var encoded string
		if err := json.Unmarshal(match.Right, &encoded); err != nil {
			return fmt.Errorf("decode address: %w", err)
		}
		actual, err := netip.ParseAddr(encoded)
		if err != nil || actual != value {
			return fmt.Errorf("address is %q, expected %s", encoded, value)
		}
	case uint16:
		actual, err := parseUintJSON(match.Right)
		if err != nil || actual != uint64(value) {
			return fmt.Errorf("port is %s, expected %d", string(match.Right), value)
		}
	default:
		return fmt.Errorf("unsupported expected match value %T", expected)
	}
	return nil
}

func verifyCounterExpression(raw json.RawMessage) error {
	object, err := decodeSingleExpression(raw, "counter")
	if err != nil {
		return err
	}
	var counter map[string]json.RawMessage
	if err := json.Unmarshal(object, &counter); err != nil {
		return fmt.Errorf("decode counter: %w", err)
	}
	for _, field := range []string{"packets", "bytes"} {
		value, ok := counter[field]
		if !ok {
			return fmt.Errorf("counter %s is missing", field)
		}
		if _, err := parseUintJSON(value); err != nil {
			return fmt.Errorf("counter %s: %w", field, err)
		}
	}
	return nil
}

func verifyDropExpression(raw json.RawMessage) error {
	object, err := decodeSingleExpression(raw, "drop")
	if err != nil {
		return err
	}
	if !bytes.Equal(bytes.TrimSpace(object), []byte("null")) {
		return errors.New("drop verdict is not null")
	}
	return nil
}

func decodeSingleExpression(raw json.RawMessage, expectedKind string) (json.RawMessage, error) {
	var expression map[string]json.RawMessage
	if err := json.Unmarshal(raw, &expression); err != nil {
		return nil, fmt.Errorf("decode expression: %w", err)
	}
	if len(expression) != 1 {
		return nil, fmt.Errorf("expression has %d kinds", len(expression))
	}
	body, ok := expression[expectedKind]
	if !ok {
		return nil, fmt.Errorf("expected %q expression", expectedKind)
	}
	return body, nil
}

func parseUintJSON(raw json.RawMessage) (uint64, error) {
	encoded := string(bytes.TrimSpace(raw))
	if encoded == "" || encoded[0] < '0' || encoded[0] > '9' {
		return 0, errors.New("value is not an unsigned JSON integer")
	}
	return strconv.ParseUint(encoded, 10, 64)
}

func decodeNFTDocument(payload []byte) (nftDocument, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	var document nftDocument
	if err := decoder.Decode(&document); err != nil {
		return nftDocument{}, fmt.Errorf("decode nft JSON: %w", err)
	}
	if document.NFTables == nil {
		return nftDocument{}, errors.New("nft JSON has no nftables array")
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nftDocument{}, errors.New("nft JSON has trailing data")
		}
		return nftDocument{}, fmt.Errorf("decode trailing nft JSON: %w", err)
	}
	return document, nil
}

func tablePresentInList(payload []byte, spec nftSpec) (bool, error) {
	document, err := decodeNFTDocument(payload)
	if err != nil {
		return false, err
	}
	present := false
	for index, raw := range document.NFTables {
		var item map[string]json.RawMessage
		if err := json.Unmarshal(raw, &item); err != nil {
			return false, fmt.Errorf("nftables item %d: %w", index, err)
		}
		if len(item) != 1 {
			return false, fmt.Errorf("nftables item %d has %d object kinds", index, len(item))
		}
		tableRaw, ok := item["table"]
		if !ok {
			// nft adds new top-level metadata kinds over time. Absence is
			// determined solely by the complete set of well-formed table
			// objects emitted by the trusted list-tables command.
			continue
		}
		var table tableObject
		if err := json.Unmarshal(tableRaw, &table); err != nil {
			return false, fmt.Errorf("decode listed table: %w", err)
		}
		if table.Family == "" || table.Name == "" {
			return false, errors.New("listed table is missing family or name")
		}
		if table.Family == nftFamily && table.Name == spec.table {
			if present {
				return false, errors.New("table list contains duplicate quarantine tables")
			}
			present = true
		}
	}
	return present, nil
}
