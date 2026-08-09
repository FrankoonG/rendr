package tcpquarantine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ReconcileReport describes one complete scan of the current network
// namespace. A live table is owned by a process generation that was proved to
// still exist. Unknown tables are never deleted.
type ReconcileReport struct {
	Managed int
	Live    int
	Removed int
	Unknown int
}

// Reconcile removes exact quarantine tables whose creating process generation
// is proved dead. It never uses a name prefix alone as deletion authority.
func (manager *Manager) Reconcile(ctx context.Context) (ReconcileReport, error) {
	if ctx == nil {
		return ReconcileReport{}, errors.New("tcpquarantine: nil context")
	}
	scope, err := currentNamespaceScope()
	if err != nil {
		return ReconcileReport{}, errors.Join(ErrExecutionScopeChanged, err)
	}
	manager.reconcileMu.Lock()
	defer manager.reconcileMu.Unlock()
	report, err := manager.reconcileScope(ctx, scope)
	if err == nil {
		manager.reconciledScopes[scope] = struct{}{}
	}
	return report, err
}

func (manager *Manager) ensureReconciled(ctx context.Context, scope namespaceScope) error {
	manager.reconcileMu.Lock()
	defer manager.reconcileMu.Unlock()
	if _, ok := manager.reconciledScopes[scope]; ok {
		return nil
	}
	_, err := manager.reconcileScope(ctx, scope)
	if err == nil {
		manager.reconciledScopes[scope] = struct{}{}
	}
	return err
}

func (manager *Manager) reconcileScope(parent context.Context, scope namespaceScope) (ReconcileReport, error) {
	if manager == nil || manager.runner == nil || manager.processState == nil || !manager.process.valid() {
		return ReconcileReport{}, ErrReconcileIncomplete
	}
	if cause := context.Cause(parent); cause != nil {
		return ReconcileReport{}, fmt.Errorf("%w: %w", ErrReconcileIncomplete, cause)
	}
	deadline := time.Now().Add(manager.reconcileTimeout)
	if parentDeadline, ok := parent.Deadline(); ok && parentDeadline.Before(deadline) {
		deadline = parentDeadline
	}
	ctx, cancel := context.WithDeadline(parent, deadline)
	defer cancel()
	result, runErr := manager.runScoped(ctx, scope, listTablesArgs(), nil)
	if runErr = normalizeRunError("reconcile list tables", result, runErr); runErr != nil {
		return ReconcileReport{}, fmt.Errorf("%w: %w", ErrReconcileIncomplete, runErr)
	}
	identities, err := managedTablesInList(result.Stdout)
	if err != nil {
		return ReconcileReport{}, fmt.Errorf("%w: %w", ErrReconcileIncomplete, err)
	}
	sort.Slice(identities, func(left, right int) bool {
		return identities[left].spec().table < identities[right].spec().table
	})

	report := ReconcileReport{Managed: len(identities)}
	var reconcileErr error
	for _, identity := range identities {
		if identity.process == manager.process {
			report.Live++
			continue
		}
		state, stateErr := manager.processState(identity.process)
		state, stateErr = validateObservedProcessState(state, stateErr)
		switch state {
		case processStateAlive:
			report.Live++
			continue
		case processStateDead:
		default:
			report.Unknown++
			reconcileErr = errors.Join(reconcileErr, fmt.Errorf("table %s: %w", identity.spec().table, stateErr))
			continue
		}

		removed, removeErr := manager.removeStaleTable(ctx, scope, identity.spec())
		if removeErr != nil {
			report.Unknown++
			reconcileErr = errors.Join(reconcileErr, removeErr)
			continue
		}
		if removed {
			report.Removed++
		}
	}
	if reconcileErr != nil {
		return report, fmt.Errorf("%w: %w", ErrReconcileIncomplete, reconcileErr)
	}
	return report, nil
}

func (manager *Manager) removeStaleTable(ctx context.Context, scope namespaceScope, spec nftSpec) (bool, error) {
	if cause := context.Cause(ctx); cause != nil {
		return false, cause
	}
	result, runErr := manager.runScoped(ctx, scope, spec.listTableArgs(), nil)
	runErr = normalizeRunError("reconcile inspect table", result, runErr)
	if runErr != nil {
		allResult, allErr := manager.runScoped(ctx, scope, listTablesArgs(), nil)
		allErr = normalizeRunError("reconcile confirm table", allResult, allErr)
		if allErr != nil {
			return false, fmt.Errorf("table %s inspection is unknown: %w", spec.table, errors.Join(runErr, allErr))
		}
		present, parseErr := tableNamePresentInList(allResult.Stdout, spec.table)
		if parseErr != nil {
			return false, fmt.Errorf("table %s presence is unknown: %w", spec.table, errors.Join(runErr, parseErr))
		}
		if !present {
			return false, nil
		}
		return false, fmt.Errorf("table %s is listed but cannot be inspected: %w", spec.table, runErr)
	}
	if err := verifyTableJSON(result.Stdout, spec); err != nil {
		return false, fmt.Errorf("table %s: %w", spec.table, errors.Join(ErrManagedTableMalformed, err))
	}
	if cause := context.Cause(ctx); cause != nil {
		return false, cause
	}
	observation := manager.deleteAndObserveBounded(ctx, scope, spec, "reconcile delete table")
	if observation.state != stateAbsent {
		return false, fmt.Errorf("table %s: %w", spec.table, errors.Join(ErrCleanupIncomplete, observation.err))
	}
	return true, nil
}

func managedTablesInList(payload []byte) ([]managedTableIdentity, error) {
	document, err := decodeNFTDocument(payload)
	if err != nil {
		return nil, err
	}
	identities := make([]managedTableIdentity, 0)
	seen := make(map[string]struct{})
	for index, raw := range document.NFTables {
		var item map[string]json.RawMessage
		if err := json.Unmarshal(raw, &item); err != nil {
			return nil, fmt.Errorf("nftables item %d: %w", index, err)
		}
		if len(item) != 1 {
			return nil, fmt.Errorf("nftables item %d has %d object kinds", index, len(item))
		}
		tableRaw, ok := item["table"]
		if !ok {
			continue
		}
		var table tableObject
		if err := json.Unmarshal(tableRaw, &table); err != nil {
			return nil, fmt.Errorf("decode listed table: %w", err)
		}
		if table.Family == "" || table.Name == "" {
			return nil, errors.New("listed table is missing family or name")
		}
		if table.Family != nftFamily {
			continue
		}
		if strings.HasPrefix(table.Name, legacyPrefix) {
			return nil, fmt.Errorf("%w: legacy table %q has no process-generation ownership", ErrManagedTableMalformed, table.Name)
		}
		identity, managed, err := parseManagedTableName(table.Name)
		if err != nil {
			return nil, err
		}
		if !managed {
			continue
		}
		if _, duplicate := seen[table.Name]; duplicate {
			return nil, fmt.Errorf("duplicate managed table %q", table.Name)
		}
		seen[table.Name] = struct{}{}
		identities = append(identities, identity)
	}
	return identities, nil
}

func tableNamePresentInList(payload []byte, name string) (bool, error) {
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
			continue
		}
		var table tableObject
		if err := json.Unmarshal(tableRaw, &table); err != nil {
			return false, err
		}
		if table.Family == nftFamily && table.Name == name {
			if present {
				return false, fmt.Errorf("duplicate table %q", name)
			}
			present = true
		}
	}
	return present, nil
}
