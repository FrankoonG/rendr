package leafmobility

import (
	"errors"
	"fmt"
	"reflect"
)

var (
	ErrInvalidImplementationEvidence = errors.New("leafmobility: invalid implementation evidence")
	ErrImplementationOwnerMismatch   = errors.New("leafmobility: implementation owner mismatch")
)

// ImplementationProvider exposes sealed, session-level implementation
// evidence. Code outside this module cannot name the internal return type, so
// it cannot directly implement this interface. Embedded method promotion is
// checked against the exact dynamic owner type when evidence is consumed.
type ImplementationProvider interface {
	LeafMobilityImplementation() ImplementationEvidence
}

// ImplementationEvidence proves that one exact owner type contains concrete
// drivers. It does not prove endpoint ownership, platform availability, or
// eligibility for a destructive operation.
type ImplementationEvidence struct {
	ownerType    reflect.Type
	count        uint8
	capabilities [4]Capability
}

// NewImplementationEvidence derives opaque implementation evidence from real
// drivers. Callers cannot supply operation bits directly.
func NewImplementationEvidence(owner ImplementationProvider, drivers ...Driver) (ImplementationEvidence, error) {
	if interfaceIsNil(owner) {
		return ImplementationEvidence{}, fmt.Errorf("%w: nil owner", ErrInvalidImplementationEvidence)
	}
	if len(drivers) == 0 || len(drivers) > len((ImplementationEvidence{}).capabilities) {
		return ImplementationEvidence{}, fmt.Errorf("%w: driver count %d", ErrInvalidImplementationEvidence, len(drivers))
	}

	evidence := ImplementationEvidence{ownerType: reflect.TypeOf(owner)}
	var seen Operation
	for index, driver := range drivers {
		capability, err := CapabilityForDriver(driver)
		if err != nil {
			return ImplementationEvidence{}, fmt.Errorf("%w: driver %d: %w", ErrInvalidImplementationEvidence, index, err)
		}
		if seen.Has(capability.operation) {
			return ImplementationEvidence{}, fmt.Errorf(
				"%w: %w: duplicate operation %#x",
				ErrInvalidImplementationEvidence,
				ErrInvalidDriver,
				capability.operation,
			)
		}
		seen |= capability.operation

		// Keep the private capability array canonical regardless of provider
		// declaration order.
		insert := index
		for insert > 0 && evidence.capabilities[insert-1].operation > capability.operation {
			evidence.capabilities[insert] = evidence.capabilities[insert-1]
			insert--
		}
		evidence.capabilities[insert] = capability
		evidence.count++
	}
	return evidence, nil
}

// MustNewImplementationEvidence is NewImplementationEvidence for provider
// wiring fixed by the implementation's method set.
func MustNewImplementationEvidence(owner ImplementationProvider, drivers ...Driver) ImplementationEvidence {
	evidence, err := NewImplementationEvidence(owner, drivers...)
	if err != nil {
		panic(err)
	}
	return evidence
}

// RebindImplementationEvidence validates source's exact-owner evidence, then
// snapshots its canonical capabilities into evidence sealed to owner. It is
// intended only for internal wrappers that deliberately preserve a concrete
// implementation provider without relying on embedded method promotion.
func RebindImplementationEvidence(
	owner ImplementationProvider,
	source ImplementationProvider,
) (ImplementationEvidence, error) {
	capabilities, err := CapabilitiesForImplementationProvider(source)
	if err != nil {
		return ImplementationEvidence{}, fmt.Errorf("leafmobility: validate delegated implementation: %w", err)
	}
	if interfaceIsNil(owner) {
		return ImplementationEvidence{}, fmt.Errorf("%w: nil rebound owner", ErrInvalidImplementationEvidence)
	}

	evidence := ImplementationEvidence{
		ownerType: reflect.TypeOf(owner),
		count:     uint8(len(capabilities)),
	}
	copy(evidence.capabilities[:], capabilities)
	return evidence, nil
}

// CapabilitiesForImplementationProvider validates that evidence was minted by
// the provider's exact dynamic type and returns an independent capability
// slice. A wrapper that only promotes an embedded provider method is rejected.
func CapabilitiesForImplementationProvider(provider ImplementationProvider) ([]Capability, error) {
	if interfaceIsNil(provider) {
		return nil, fmt.Errorf("%w: nil provider", ErrInvalidImplementationEvidence)
	}
	evidence := provider.LeafMobilityImplementation()
	providerType := reflect.TypeOf(provider)
	if evidence.ownerType == nil || evidence.ownerType != providerType {
		return nil, fmt.Errorf(
			"%w: evidence owner %v, provider %v",
			ErrImplementationOwnerMismatch,
			evidence.ownerType,
			providerType,
		)
	}
	if evidence.count == 0 || int(evidence.count) > len(evidence.capabilities) {
		return nil, fmt.Errorf("%w: capability count %d", ErrInvalidImplementationEvidence, evidence.count)
	}

	capabilities := make([]Capability, int(evidence.count))
	var seen Operation
	for index := range capabilities {
		capability := evidence.capabilities[index]
		if !capability.operation.single() || seen.Has(capability.operation) ||
			(index > 0 && capabilities[index-1].operation >= capability.operation) {
			return nil, fmt.Errorf("%w: capability %d", ErrInvalidImplementationEvidence, index)
		}
		seen |= capability.operation
		capabilities[index] = capability
	}
	for index := int(evidence.count); index < len(evidence.capabilities); index++ {
		if evidence.capabilities[index] != (Capability{}) {
			return nil, fmt.Errorf("%w: trailing capability %d", ErrInvalidImplementationEvidence, index)
		}
	}
	return capabilities, nil
}
