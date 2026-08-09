//go:build linux

package tcpquarantine

import (
	"errors"
	"testing"
)

func TestLinuxProcessIdentityDistinguishesLivenessAndNamespace(t *testing.T) {
	current, err := currentProcessIdentity()
	if err != nil {
		t.Fatalf("currentProcessIdentity(): %v", err)
	}
	if state, err := observeProcessIdentity(current); err != nil || state != processStateAlive {
		t.Fatalf("observe current process = (%d, %v)", state, err)
	}

	reused := current
	reused.startTime++
	if state, err := observeProcessIdentity(reused); err != nil || state != processStateDead {
		t.Fatalf("observe reused PID generation = (%d, %v)", state, err)
	}

	foreignNamespace := current
	foreignNamespace.pidNamespaceInode++
	if state, err := observeProcessIdentity(foreignNamespace); state != processStateUnknown ||
		!errors.Is(validateProcessObservation(state, err), ErrProcessStateUnknown) {
		t.Fatalf("observe foreign PID namespace = (%d, %v)", state, err)
	}
}

func validateProcessObservation(state processState, err error) error {
	_, observedErr := validateObservedProcessState(state, err)
	return observedErr
}
