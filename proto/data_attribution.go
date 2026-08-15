package proto

import (
	"encoding/binary"
	"fmt"
)

const (
	maxDataRootSelectorOrdinal = GraphManifestMaxNodes - 1
	dataRootOrdinalMask        = uint16(0x03ff)
	dataRootCommittedFlag      = uint16(0x0400)
	dataRootDemandFlag         = uint16(0x0800)
	dataRootKnownFlags         = dataRootOrdinalMask | dataRootCommittedFlag | dataRootDemandFlag
	DataRootGenerationSize     = 8
)

// RootTracksDataAttribution reports whether the graph root has PeakTransfer
// candidates and therefore needs per-DATA delivery attribution. Ordinary
// selectors retain zero DATA flags and no payload prefix.
func RootTracksDataAttribution(manifest GraphManifest) bool {
	root, ok := manifest.Node(manifest.RootID)
	return ok && root.Kind == GraphNodeKindSelector && len(root.PeakCandidates) != 0
}

// DataFlagsForRootTarget encodes the root selector's immediate-child target
// as a one-based ordinal. committed says the logical selection was also the
// effective root child at publication. The receiver additionally verifies the
// physical leaf binding before using the frame as capacity evidence.
func DataFlagsForRootTarget(manifest GraphManifest, targetID TargetID, committed, demand bool) (uint16, error) {
	if err := manifest.Validate(); err != nil {
		return 0, fmt.Errorf("proto: DATA root attribution manifest: %w", err)
	}
	root, ok := manifest.Node(manifest.RootID)
	if !ok {
		return 0, fmt.Errorf("proto: DATA root attribution has no graph root")
	}
	if !RootTracksDataAttribution(manifest) {
		if targetID != (TargetID{}) || committed || demand {
			return 0, fmt.Errorf("proto: DATA flags for an untracked root require zero attribution")
		}
		return 0, nil
	}
	for i, childID := range root.Children {
		if childID != targetID {
			continue
		}
		ordinal := i + 1
		if ordinal > maxDataRootSelectorOrdinal {
			return 0, fmt.Errorf("proto: DATA root selector ordinal %d exceeds maximum %d", ordinal, maxDataRootSelectorOrdinal)
		}
		return DataFlagsForRootOrdinal(uint16(ordinal), committed, demand)
	}
	if targetID == (TargetID{}) {
		return 0, fmt.Errorf("proto: DATA flags for selector root require a non-zero immediate-child target")
	}
	return 0, fmt.Errorf("proto: DATA target %x is not an immediate child of root selector %x", targetID, manifest.RootID)
}

// DataFlagsForRootOrdinal encodes one validated immediate-child ordinal.
func DataFlagsForRootOrdinal(ordinal uint16, committed, demand bool) (uint16, error) {
	if ordinal == 0 || ordinal > maxDataRootSelectorOrdinal {
		return 0, fmt.Errorf("proto: DATA root selector ordinal %d is outside [1,%d]", ordinal, maxDataRootSelectorOrdinal)
	}
	flags := ordinal
	if committed {
		flags |= dataRootCommittedFlag
	}
	if demand {
		flags |= dataRootDemandFlag
	}
	return flags, nil
}

// RootOrdinalFromDataFlags strictly decodes the attribution bits without a
// graph lookup. Callers must still range-check the ordinal against the frozen
// root child list.
func RootOrdinalFromDataFlags(flags uint16) (ordinal uint16, committed, demand bool, err error) {
	if unknown := flags &^ dataRootKnownFlags; unknown != 0 {
		return 0, false, false, fmt.Errorf("proto: DATA root attribution contains unknown flags 0x%x", unknown)
	}
	ordinal = flags & dataRootOrdinalMask
	if ordinal == 0 {
		return 0, false, false, fmt.Errorf("proto: DATA root attribution contains zero ordinal")
	}
	return ordinal, flags&dataRootCommittedFlag != 0, flags&dataRootDemandFlag != 0, nil
}

// RootTargetFromDataFlags decodes a DATA attribution against the frozen root
// selector child order. Roots without PeakTransfer accept only zero flags.
func RootTargetFromDataFlags(manifest GraphManifest, flags uint16) (TargetID, bool, bool, error) {
	if err := manifest.Validate(); err != nil {
		return TargetID{}, false, false, fmt.Errorf("proto: DATA root attribution manifest: %w", err)
	}
	root, ok := manifest.Node(manifest.RootID)
	if !ok {
		return TargetID{}, false, false, fmt.Errorf("proto: DATA root attribution has no graph root")
	}
	if !RootTracksDataAttribution(manifest) {
		if flags != 0 {
			return TargetID{}, false, false, fmt.Errorf("proto: DATA flags for an untracked root must be zero, got 0x%x", flags)
		}
		return TargetID{}, false, false, nil
	}
	ordinalWire, committed, demand, err := RootOrdinalFromDataFlags(flags)
	if err != nil {
		return TargetID{}, false, false, err
	}
	ordinal := int(ordinalWire)
	if ordinal > len(root.Children) {
		return TargetID{}, false, false, fmt.Errorf("proto: DATA root selector ordinal %d exceeds %d children", ordinal, len(root.Children))
	}
	return root.Children[ordinal-1], committed, demand, nil
}

// EncodeDataRootGeneration prefixes application DATA with one non-zero
// selector generation. The prefix is stripped before stream or packet delivery.
func EncodeDataRootGeneration(generation uint64, payload []byte) ([]byte, error) {
	if generation == 0 {
		return nil, fmt.Errorf("proto: zero DATA root generation")
	}
	wire := make([]byte, DataRootGenerationSize+len(payload))
	binary.BigEndian.PutUint64(wire[:DataRootGenerationSize], generation)
	copy(wire[DataRootGenerationSize:], payload)
	return wire, nil
}

// DecodeDataRootGeneration returns the self-described selector generation and
// the application payload. The returned payload aliases wire.
func DecodeDataRootGeneration(wire []byte) (uint64, []byte, error) {
	if len(wire) < DataRootGenerationSize {
		return 0, nil, fmt.Errorf("proto: DATA root generation prefix too short: %d", len(wire))
	}
	generation := binary.BigEndian.Uint64(wire[:DataRootGenerationSize])
	if generation == 0 {
		return 0, nil, fmt.Errorf("proto: zero DATA root generation")
	}
	return generation, wire[DataRootGenerationSize:], nil
}
