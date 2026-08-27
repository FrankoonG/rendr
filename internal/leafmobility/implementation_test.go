package leafmobility

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type implementationTestDriver struct {
	operation Operation
}

func (d *implementationTestDriver) Operation() Operation { return d.operation }

func (*implementationTestDriver) Preflight(
	context.Context,
	PreflightRequest,
) (DriverAttempt, PreflightResult, error) {
	return nil, PreflightResult{}, nil
}

type implementationValueDriver struct {
	operation Operation
}

func (d implementationValueDriver) Operation() Operation { return d.operation }

func (implementationValueDriver) Preflight(
	context.Context,
	PreflightRequest,
) (DriverAttempt, PreflightResult, error) {
	return nil, PreflightResult{}, nil
}

type implementationTestProvider struct {
	drivers []Driver
}

func (p *implementationTestProvider) LeafMobilityImplementation() ImplementationEvidence {
	return MustNewImplementationEvidence(p, p.drivers...)
}

type promotedImplementationProvider struct {
	*implementationTestProvider
}

type reboundImplementationProvider struct {
	evidence ImplementationEvidence
}

func (p *reboundImplementationProvider) LeafMobilityImplementation() ImplementationEvidence {
	return p.evidence
}

type invalidImplementationProvider struct{}

func (p *invalidImplementationProvider) LeafMobilityImplementation() ImplementationEvidence {
	return ImplementationEvidence{ownerType: reflect.TypeOf(p)}
}

func TestImplementationEvidenceRequiresExactDynamicOwner(t *testing.T) {
	owner := &implementationTestProvider{drivers: []Driver{
		&implementationTestDriver{operation: OperationQUICCIDRebind},
		&implementationTestDriver{operation: OperationTCPRepair},
	}}

	capabilities, err := CapabilitiesForImplementationProvider(owner)
	if err != nil {
		t.Fatalf("exact provider: %v", err)
	}
	if len(capabilities) != 2 || capabilities[0].Operation() != OperationTCPRepair ||
		capabilities[1].Operation() != OperationQUICCIDRebind {
		t.Fatalf("capabilities=%v", capabilityOperations(capabilities))
	}

	// Returned capabilities cannot mutate the provider's sealed evidence.
	capabilities[0] = Capability{}
	again, err := CapabilitiesForImplementationProvider(owner)
	if err != nil || again[0].Operation() != OperationTCPRepair {
		t.Fatalf("second resolution=(%v, %v)", capabilityOperations(again), err)
	}

	wrapper := &promotedImplementationProvider{implementationTestProvider: owner}
	if _, ok := any(wrapper).(ImplementationProvider); !ok {
		t.Fatal("embedded method was not promoted; test does not exercise the seal")
	}
	if _, err := CapabilitiesForImplementationProvider(wrapper); !errors.Is(err, ErrImplementationOwnerMismatch) {
		t.Fatalf("promoted wrapper error=%v, want owner mismatch", err)
	}
}

func TestImplementationEvidenceRejectsInvalidDrivers(t *testing.T) {
	owner := &implementationTestProvider{}
	var typedNil *implementationTestDriver
	tests := []struct {
		name    string
		drivers []Driver
	}{
		{name: "none"},
		{name: "typed nil", drivers: []Driver{typedNil}},
		{name: "value identity", drivers: []Driver{implementationValueDriver{operation: OperationTCPRepair}}},
		{name: "zero operation", drivers: []Driver{&implementationTestDriver{}}},
		{name: "unknown operation", drivers: []Driver{&implementationTestDriver{operation: 1 << 7}}},
		{name: "multiple operations", drivers: []Driver{&implementationTestDriver{
			operation: OperationTCPRepair | OperationQUICCIDRebind,
		}}},
		{name: "duplicate operation", drivers: []Driver{
			&implementationTestDriver{operation: OperationTCPRepair},
			&implementationTestDriver{operation: OperationTCPRepair},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewImplementationEvidence(owner, test.drivers...); err == nil {
				t.Fatal("invalid drivers were accepted")
			}
		})
	}

	var nilOwner *implementationTestProvider
	if _, err := NewImplementationEvidence(nilOwner, &implementationTestDriver{operation: OperationTCPRepair}); !errors.Is(err, ErrInvalidImplementationEvidence) {
		t.Fatalf("nil owner error=%v", err)
	}
	if _, err := CapabilitiesForImplementationProvider(nilOwner); !errors.Is(err, ErrInvalidImplementationEvidence) {
		t.Fatalf("nil provider error=%v", err)
	}
}

func TestRebindImplementationEvidenceRejectsNilParticipants(t *testing.T) {
	source := &implementationTestProvider{drivers: []Driver{
		&implementationTestDriver{operation: OperationQUICCIDRebind},
	}}
	var nilOwner *reboundImplementationProvider
	if _, err := RebindImplementationEvidence(nilOwner, source); !errors.Is(err, ErrInvalidImplementationEvidence) {
		t.Fatalf("nil owner error=%v", err)
	}

	owner := &reboundImplementationProvider{}
	var nilSource *implementationTestProvider
	if _, err := RebindImplementationEvidence(owner, nilSource); !errors.Is(err, ErrInvalidImplementationEvidence) {
		t.Fatalf("nil source error=%v", err)
	}
}

func TestRebindImplementationEvidenceRejectsInvalidAndPromotedSources(t *testing.T) {
	owner := &reboundImplementationProvider{}
	if _, err := RebindImplementationEvidence(owner, &invalidImplementationProvider{}); !errors.Is(err, ErrInvalidImplementationEvidence) {
		t.Fatalf("invalid source error=%v", err)
	}

	exact := &implementationTestProvider{drivers: []Driver{
		&implementationTestDriver{operation: OperationTCPRepair},
	}}
	promoted := &promotedImplementationProvider{implementationTestProvider: exact}
	if _, err := RebindImplementationEvidence(owner, promoted); !errors.Is(err, ErrImplementationOwnerMismatch) {
		t.Fatalf("promoted source error=%v, want owner mismatch", err)
	}
}

func TestRebindImplementationEvidenceSealsExactOwnerAndCopiesCapabilities(t *testing.T) {
	tcpDriver := &implementationTestDriver{operation: OperationTCPRepair}
	quicDriver := &implementationTestDriver{operation: OperationQUICCIDRebind}
	source := &implementationTestProvider{drivers: []Driver{quicDriver, tcpDriver}}
	owner := &reboundImplementationProvider{}

	evidence, err := RebindImplementationEvidence(owner, source)
	if err != nil {
		t.Fatal(err)
	}
	owner.evidence = evidence

	capabilities, err := CapabilitiesForImplementationProvider(owner)
	if err != nil {
		t.Fatalf("rebound provider: %v", err)
	}
	if got := capabilityOperations(capabilities); len(got) != 2 ||
		got[0] != OperationTCPRepair || got[1] != OperationQUICCIDRebind {
		t.Fatalf("rebound capabilities=%v", got)
	}

	// The rebound owner keeps a value snapshot independent of both future
	// source evidence and slices returned to consumers.
	tcpDriver.operation = OperationUDPFlowRebind
	source.drivers = source.drivers[:1]
	capabilities[0] = Capability{}
	again, err := CapabilitiesForImplementationProvider(owner)
	if err != nil {
		t.Fatalf("rebound provider after source mutation: %v", err)
	}
	if got := capabilityOperations(again); len(got) != 2 ||
		got[0] != OperationTCPRepair || got[1] != OperationQUICCIDRebind {
		t.Fatalf("rebound capabilities after mutation=%v", got)
	}

	promotedOwner := &struct{ *reboundImplementationProvider }{owner}
	if _, err := CapabilitiesForImplementationProvider(promotedOwner); !errors.Is(err, ErrImplementationOwnerMismatch) {
		t.Fatalf("promoted rebound owner error=%v, want owner mismatch", err)
	}
}

func capabilityOperations(capabilities []Capability) []Operation {
	operations := make([]Operation, len(capabilities))
	for index, capability := range capabilities {
		operations[index] = capability.Operation()
	}
	return operations
}
