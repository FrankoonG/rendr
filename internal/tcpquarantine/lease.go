package tcpquarantine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Manager owns one random nft namespace and creates transaction-bound leases.
type Manager struct {
	runner           Runner
	owner            ownerToken
	process          processIdentity
	processState     func(processIdentity) (processState, error)
	reconcileTimeout time.Duration

	mu                  sync.Mutex
	activeLeases        map[leaseKey]*leaseState
	nextLeaseGeneration uint64

	reconcileMu      sync.Mutex
	reconciledScopes map[namespaceScope]struct{}
}

// Lease retains cleanup ownership until absence has been independently proven.
// Lease values may be copied: every copy refers to one shared logical lease.
// Release is concurrency-safe, idempotent after success, and retryable after a
// failed or unknown observation.
type Lease struct {
	state *leaseState
}

type leaseKey struct {
	transactionID TransactionID
}

type leaseState struct {
	manager    *Manager
	key        leaseKey
	generation uint64
	spec       nftSpec
	scope      namespaceScope

	mu       sync.Mutex
	released bool
	attempt  *releaseAttempt
}

type releaseAttempt struct {
	done chan struct{}
	err  error
}

// Preflight verifies the nft JSON contract, asks nft to validate the complete
// install batch in check mode, and then independently proves that the table is
// absent. It never issues a delete.
func (manager *Manager) Preflight(ctx context.Context, transactionID TransactionID, tuple Tuple) error {
	if err := validateRequest(ctx, transactionID, tuple); err != nil {
		return err
	}
	scope, err := currentNamespaceScope()
	if err != nil {
		return errors.Join(ErrExecutionScopeChanged, err)
	}
	if err := manager.ensureReconciled(ctx, scope); err != nil {
		return err
	}
	spec := manager.newSpec(transactionID, tuple)
	schemaResult, schemaRunErr := manager.runScoped(ctx, scope, nftSchemaProbeArgs(), nil)
	schemaRunErr = normalizeRunError("preflight JSON schema", schemaResult, schemaRunErr)
	var semanticErr error
	if schemaRunErr != nil {
		semanticErr = errors.Join(ErrNFTSemanticPreflight, schemaRunErr)
	} else if err := verifyNFTSchemaJSON(schemaResult.Stdout); err != nil {
		semanticErr = errors.Join(ErrNFTSemanticPreflight, ErrNFTSchemaIncompatible, err)
	}
	if semanticErr == nil {
		checkResult, checkErr := manager.runScoped(ctx, scope, preflightInstallArgs(), spec.installBatch())
		if checkErr = normalizeRunError("preflight install check", checkResult, checkErr); checkErr != nil {
			semanticErr = errors.Join(ErrNFTSemanticPreflight, checkErr)
		}
	}
	observation := manager.observeBounded(ctx, scope, spec)

	switch observation.state {
	case stateAbsent:
		if cause := context.Cause(ctx); cause != nil {
			return errors.Join(cause, semanticErr)
		}
		return semanticErr
	case stateExact, stateMalformed:
		return fmt.Errorf("tcpquarantine: preflight: %w", errors.Join(ErrPreflightStateChanged, semanticErr, observation.err))
	default:
		return fmt.Errorf("tcpquarantine: preflight observation: %w", errors.Join(ErrStateUnknown, semanticErr, observation.err))
	}
}

// Install atomically submits both directions, independently verifies their
// exact semantics, and returns a lease only for the verified table. If cleanup
// cannot prove absence, Install returns both a non-nil lease and an error so the
// caller retains a retryable Release handle; that combination is never success.
func (manager *Manager) Install(ctx context.Context, transactionID TransactionID, tuple Tuple) (*Lease, error) {
	if err := validateRequest(ctx, transactionID, tuple); err != nil {
		return nil, err
	}
	scope, err := currentNamespaceScope()
	if err != nil {
		return nil, errors.Join(ErrExecutionScopeChanged, err)
	}
	if err := manager.ensureReconciled(ctx, scope); err != nil {
		return nil, err
	}
	spec := manager.newSpec(transactionID, tuple)
	state, err := manager.reserveLease(transactionID, spec, scope)
	if err != nil {
		return nil, err
	}
	lease := &Lease{state: state}
	result, runErr := manager.runScoped(ctx, scope, []string{"-f", "-"}, spec.installBatch())
	runErr = normalizeRunError("install", result, runErr)
	observation := manager.observeBounded(ctx, scope, spec)
	cancelCause := context.Cause(ctx)

	if observation.state == stateExact && cancelCause == nil {
		// The independently observed state is authoritative even when nft changed
		// it and then returned an error.
		return lease, nil
	}
	if observation.state == stateAbsent && cancelCause == nil {
		if err := state.markReleased(); err != nil {
			return nil, errors.Join(fmt.Errorf("tcpquarantine: install: %w", errors.Join(ErrInstallNotApplied, runErr)), err)
		}
		return nil, fmt.Errorf("tcpquarantine: install: %w", errors.Join(ErrInstallNotApplied, runErr))
	}

	primaryErr := installObservationError(runErr, observation, cancelCause)
	cleanup := manager.deleteAndObserveBounded(ctx, scope, spec, "install cleanup")
	if cleanup.state == stateAbsent {
		if err := state.markReleased(); err != nil {
			return nil, errors.Join(primaryErr, err)
		}
		return nil, primaryErr
	}
	return lease, errors.Join(primaryErr, fmt.Errorf("%w: %w", ErrCleanupIncomplete, cleanup.err))
}

func (manager *Manager) newSpec(transactionID TransactionID, tuple Tuple) nftSpec {
	return newNFTSpec(manager.process, manager.owner, transactionID, tuple)
}

func (manager *Manager) reserveLease(
	transactionID TransactionID,
	spec nftSpec,
	scope namespaceScope,
) (*leaseState, error) {
	key := leaseKey{transactionID: transactionID}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if current := manager.activeLeases[key]; current != nil {
		if current.spec.tuple == spec.tuple && current.scope == scope {
			return nil, ErrLeaseBusy
		}
		return nil, ErrLeaseConflict
	}
	if manager.nextLeaseGeneration == ^uint64(0) {
		return nil, ErrLeaseGenerationExhausted
	}
	manager.nextLeaseGeneration++
	if manager.activeLeases == nil {
		manager.activeLeases = make(map[leaseKey]*leaseState)
	}
	state := &leaseState{
		manager:    manager,
		key:        key,
		generation: manager.nextLeaseGeneration,
		spec:       spec,
		scope:      scope,
	}
	manager.activeLeases[key] = state
	return state, nil
}

func installObservationError(runErr error, observation observation, cancelCause error) error {
	joined := errors.Join(runErr, cancelCause, observation.err)
	switch observation.state {
	case stateExact:
		return fmt.Errorf("tcpquarantine: canceled install was reconciled before publication: %w", joined)
	case stateMalformed:
		return fmt.Errorf("tcpquarantine: install: %w", errors.Join(ErrVerificationFailed, joined))
	case stateAbsent:
		return fmt.Errorf("tcpquarantine: install: %w", errors.Join(ErrInstallNotApplied, joined))
	default:
		return fmt.Errorf("tcpquarantine: install: %w", errors.Join(ErrStateUnknown, joined))
	}
}

// Release removes the whole quarantine table with one batch. Concurrent calls
// share one in-flight attempt. A failed attempt leaves the lease retryable.
func (lease *Lease) Release(ctx context.Context) error {
	if ctx == nil {
		return errors.New("tcpquarantine: nil context")
	}
	if lease == nil || lease.state == nil {
		return ErrStaleLease
	}
	state := lease.state
	state.mu.Lock()
	if state.released {
		state.mu.Unlock()
		return nil
	}
	if current := state.attempt; current != nil {
		state.mu.Unlock()
		select {
		case <-current.done:
			return current.err
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	}
	attempt := &releaseAttempt{done: make(chan struct{})}
	state.attempt = attempt
	state.mu.Unlock()

	err := state.manager.release(ctx, state)

	state.mu.Lock()
	attempt.err = err
	if err == nil {
		err = state.markReleasedLocked()
		attempt.err = err
	}
	state.attempt = nil
	close(attempt.done)
	state.mu.Unlock()
	return err
}

func (state *leaseState) markReleased() error {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.markReleasedLocked()
}

func (state *leaseState) markReleasedLocked() error {
	if state.released {
		return nil
	}
	manager := state.manager
	manager.mu.Lock()
	defer manager.mu.Unlock()
	current := manager.activeLeases[state.key]
	if current != state || current.generation != state.generation {
		return ErrStaleLease
	}
	state.released = true
	delete(manager.activeLeases, state.key)
	return nil
}

func (manager *Manager) release(ctx context.Context, state *leaseState) error {
	if err := manager.requireActiveLease(state); err != nil {
		return err
	}
	result, runErr := manager.runScoped(ctx, state.scope, []string{"-f", "-"}, state.spec.deleteBatch())
	runErr = normalizeRunError("release", result, runErr)
	observation := manager.observeBounded(ctx, state.scope, state.spec)
	if observation.state == stateAbsent {
		return nil
	}
	if observation.state == stateExact || observation.state == stateMalformed {
		return fmt.Errorf("tcpquarantine: release: %w", errors.Join(ErrReleaseNotApplied, runErr, observation.err))
	}
	return fmt.Errorf("tcpquarantine: release: %w", errors.Join(ErrStateUnknown, runErr, observation.err))
}

func (manager *Manager) requireActiveLease(state *leaseState) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	current := manager.activeLeases[state.key]
	if current != state || current.generation != state.generation {
		return ErrStaleLease
	}
	return nil
}

func (manager *Manager) deleteAndObserveBounded(parent context.Context, scope namespaceScope, spec nftSpec, operation string) observation {
	ctx, cancel := manager.reconcileContext(parent)
	defer cancel()
	result, runErr := manager.runScoped(ctx, scope, []string{"-f", "-"}, spec.deleteBatch())
	runErr = normalizeRunError(operation, result, runErr)
	observed := manager.observe(ctx, scope, spec)
	if observed.state == stateExact {
		observed.err = errors.Join(runErr, ErrReleaseNotApplied)
	} else if observed.state != stateAbsent {
		observed.err = errors.Join(runErr, observed.err)
	}
	return observed
}

func (manager *Manager) observeBounded(parent context.Context, scope namespaceScope, spec nftSpec) observation {
	ctx, cancel := manager.reconcileContext(parent)
	defer cancel()
	return manager.observe(ctx, scope, spec)
}

func (manager *Manager) reconcileContext(parent context.Context) (context.Context, context.CancelFunc) {
	base := context.WithoutCancel(parent)
	deadline := time.Now().Add(manager.reconcileTimeout)
	if parentDeadline, ok := parent.Deadline(); ok && parentDeadline.Before(deadline) {
		deadline = parentDeadline
	}
	return context.WithDeadline(base, deadline)
}

func (manager *Manager) observe(ctx context.Context, scope namespaceScope, spec nftSpec) observation {
	result, runErr := manager.runScoped(ctx, scope, spec.listTableArgs(), nil)
	runErr = normalizeRunError("list table", result, runErr)
	if runErr == nil {
		if err := verifyTableJSON(result.Stdout, spec); err != nil {
			return observation{state: stateMalformed, err: fmt.Errorf("%w: %v", ErrVerificationFailed, err)}
		}
		return observation{state: stateExact}
	}

	allResult, allErr := manager.runScoped(ctx, scope, listTablesArgs(), nil)
	allErr = normalizeRunError("list tables", allResult, allErr)
	if allErr != nil {
		return observation{state: stateUnknown, err: errors.Join(runErr, allErr)}
	}
	present, parseErr := tablePresentInList(allResult.Stdout, spec)
	if parseErr != nil {
		return observation{state: stateUnknown, err: errors.Join(runErr, parseErr)}
	}
	if present {
		return observation{state: stateUnknown, err: errors.Join(runErr, errors.New("table is listed but exact inspection failed"))}
	}
	return observation{state: stateAbsent}
}

func (manager *Manager) runScoped(
	ctx context.Context,
	scope namespaceScope,
	args []string,
	stdin []byte,
) (RunResult, error) {
	if err := requireNamespaceScope(scope); err != nil {
		return RunResult{}, err
	}
	result, runErr := manager.runner.Run(ctx, args, stdin)
	return result, errors.Join(runErr, requireNamespaceScope(scope))
}

func validateRequest(ctx context.Context, transactionID TransactionID, tuple Tuple) error {
	if ctx == nil {
		return errors.New("tcpquarantine: nil context")
	}
	if transactionID.isZero() {
		return ErrInvalidTransactionID
	}
	return tuple.validate()
}
