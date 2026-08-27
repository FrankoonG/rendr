package proto

import (
	"encoding/binary"
	"fmt"
)

const (
	dataSelectorDemandFlag     = uint16(0x0001)
	DataSelectorStateEpochSize = 8
)

// GraphTracksSelectorState reports whether any selector in the frozen graph
// has PeakTransfer candidates. Such graphs bind each DATA frame to the exact
// full selector-state vector that was current when the frame was published.
func GraphTracksSelectorState(manifest GraphManifest) bool {
	for _, node := range manifest.Nodes {
		if node.Kind == GraphNodeKindSelector && len(node.PeakCandidates) != 0 {
			return true
		}
	}
	return false
}

// RootTracksDataAttribution reports whether the graph root has PeakTransfer
// candidates and therefore needs per-DATA delivery attribution. Ordinary
// selectors retain zero DATA flags and no payload prefix.
func RootTracksDataAttribution(manifest GraphManifest) bool {
	root, ok := manifest.Node(manifest.RootID)
	return ok && root.Kind == GraphNodeKindSelector && len(root.PeakCandidates) != 0
}

// DataFlagsForSelectorState encodes the only DATA-local attribution fact in
// protocol minor 21: whether the sender observed application demand at
// publication. Target, generation, and commit state come exclusively from the
// referenced selector-state vector.
func DataFlagsForSelectorState(tracked, demand bool) (uint16, error) {
	if !tracked {
		if demand {
			return 0, fmt.Errorf("proto: untracked DATA cannot carry demand")
		}
		return 0, nil
	}
	if demand {
		return dataSelectorDemandFlag, nil
	}
	return 0, nil
}

// DemandFromDataFlags strictly decodes DATA flags for a graph that either does
// or does not negotiate selector-state attribution.
func DemandFromDataFlags(tracked bool, flags uint16) (bool, error) {
	if !tracked {
		if flags != 0 {
			return false, fmt.Errorf("proto: untracked DATA has non-zero flags 0x%x", flags)
		}
		return false, nil
	}
	if unknown := flags &^ dataSelectorDemandFlag; unknown != 0 {
		return false, fmt.Errorf("proto: DATA selector-state attribution contains unknown flags 0x%x", unknown)
	}
	return flags&dataSelectorDemandFlag != 0, nil
}

// EncodeDataSelectorStateEpoch prefixes application DATA with the non-zero
// epoch of its immutable full selector-state vector. The prefix is stripped
// before stream or packet delivery.
func EncodeDataSelectorStateEpoch(stateEpoch uint64, payload []byte) ([]byte, error) {
	if stateEpoch == 0 {
		return nil, fmt.Errorf("proto: zero DATA selector state epoch")
	}
	wire := make([]byte, DataSelectorStateEpochSize+len(payload))
	binary.BigEndian.PutUint64(wire[:DataSelectorStateEpochSize], stateEpoch)
	copy(wire[DataSelectorStateEpochSize:], payload)
	return wire, nil
}

// DecodeDataSelectorStateEpoch returns the self-described state epoch and the
// application payload. The returned payload aliases wire.
func DecodeDataSelectorStateEpoch(wire []byte) (uint64, []byte, error) {
	if len(wire) < DataSelectorStateEpochSize {
		return 0, nil, fmt.Errorf("proto: DATA selector state epoch prefix too short: %d", len(wire))
	}
	stateEpoch := binary.BigEndian.Uint64(wire[:DataSelectorStateEpochSize])
	if stateEpoch == 0 {
		return 0, nil, fmt.Errorf("proto: zero DATA selector state epoch")
	}
	return stateEpoch, wire[DataSelectorStateEpochSize:], nil
}
