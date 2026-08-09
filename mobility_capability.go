package rendr

import (
	"fmt"
	"sort"

	"github.com/FrankoonG/rendr/internal/leafmobility"
)

// mobilityCapabilitySet freezes implementation evidence independently of
// registry and target ordering. It never derives authority from carrier names
// or from a PathConn returned by a generic factory.
type mobilityCapabilitySet struct {
	byOperation map[leafmobility.Operation]leafmobility.Capability
}

func (s *mobilityCapabilitySet) addImplementation(value any) error {
	provider, ok := value.(leafmobility.ImplementationProvider)
	if !ok {
		return nil
	}
	capabilities, err := leafmobility.CapabilitiesForImplementationProvider(provider)
	if err != nil {
		return err
	}
	return s.add(capabilities...)
}

func (s *mobilityCapabilitySet) add(capabilities ...leafmobility.Capability) error {
	if len(capabilities) == 0 {
		return nil
	}
	if s.byOperation == nil {
		s.byOperation = make(map[leafmobility.Operation]leafmobility.Capability, len(capabilities))
	}
	for _, capability := range capabilities {
		operation := capability.Operation()
		if operation == 0 {
			return fmt.Errorf("rendr: invalid zero leaf mobility capability")
		}
		s.byOperation[operation] = capability
	}
	return nil
}

func (s mobilityCapabilitySet) snapshotAll() []leafmobility.Capability {
	capabilities := make([]leafmobility.Capability, 0, len(s.byOperation))
	for _, capability := range s.byOperation {
		capabilities = append(capabilities, capability)
	}
	sort.Slice(capabilities, func(i, j int) bool {
		return capabilities[i].Operation() < capabilities[j].Operation()
	})
	return capabilities
}

func (s mobilityCapabilitySet) snapshotForSession(session leafmobility.Session) ([]leafmobility.Capability, error) {
	if session != leafmobility.SessionStream && session != leafmobility.SessionPacket {
		return nil, fmt.Errorf("rendr: invalid leaf mobility session %d", session)
	}
	all := s.snapshotAll()
	capabilities := all[:0]
	for _, capability := range all {
		if capability.Operation().SupportsSession(session) {
			capabilities = append(capabilities, capability)
		}
	}
	return capabilities, nil
}

// mobilityCapabilities returns implementation evidence for every exact
// already-framed factory referenced by the frozen session graph. Generic
// stream and packet factories intentionally contribute nothing.
func (r *pathFactoryResolver) mobilityCapabilities(
	paths []PathSpec,
	session leafmobility.Session,
) ([]leafmobility.Capability, error) {
	if r == nil {
		return (mobilityCapabilitySet{}).snapshotForSession(session)
	}
	var set mobilityCapabilitySet
	seen := make(map[string]struct{}, len(paths))
	names := make([]string, 0, len(paths))
	for _, spec := range paths {
		if _, duplicate := seen[spec.Transport]; duplicate {
			continue
		}
		seen[spec.Transport] = struct{}{}
		names = append(names, spec.Transport)
	}
	sort.Strings(names)
	for _, name := range names {
		factory, ok := r.framed[name]
		if !ok {
			continue
		}
		if err := set.addImplementation(factory); err != nil {
			return nil, fmt.Errorf("rendr: path factory %q has invalid leaf mobility evidence: %w", name, err)
		}
	}
	return set.snapshotForSession(session)
}
