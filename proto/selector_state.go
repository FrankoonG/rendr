package proto

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	SelectorStateVersion      uint8 = 1
	SelectorStateHeaderSize         = 72
	SelectorStateEntrySize          = 56
	SelectorStateMaxWireBytes       = SelectorStateHeaderSize + GraphManifestMaxNodes*SelectorStateEntrySize
)

// ValidateSelectorStateCtrlFlags rejects any control code other than
// SELECTOR_STATE and all reserved FLAGS bits. Minor 21 defines no per-code
// FLAGS extensions for selector state publication.
func ValidateSelectorStateCtrlFlags(flags uint16) error {
	code := CtrlCodeFromFlags(flags)
	if code != CtrlSelectorState {
		return fmt.Errorf("proto: control %s is not a selector state control", code)
	}
	if flags != FlagsForCtrl(code) {
		return fmt.Errorf("proto: selector state control has non-zero reserved flags 0x%03x", flags&^FlagsForCtrl(code))
	}
	return nil
}

// SelectorStateEntry freezes one selector's desired and effective immediate
// child for a DATA attribution epoch. Generation identifies the committed
// selector execution; the enclosing StateEpoch changes for any vector update.
type SelectorStateEntry struct {
	SelectorID        TargetID
	DesiredTargetID   TargetID
	EffectiveTargetID TargetID
	Generation        uint64
}

// SelectorStatePayload is the canonical, full selector vector for one sender
// graph. Entries contain every selector in ascending SelectorID order.
type SelectorStatePayload struct {
	SessionEpoch  SessionEpoch
	Direction     SenderDirection
	GraphRevision uint64
	GraphDigest   GraphDigest
	StateEpoch    uint64
	Entries       []SelectorStateEntry
}

// EncodeSelectorState validates and encodes one canonical selector vector.
func EncodeSelectorState(
	payload SelectorStatePayload,
	manifest GraphManifest,
	binding GraphBinding,
) ([]byte, error) {
	if err := payload.Validate(manifest, binding); err != nil {
		return nil, err
	}
	wire := make([]byte, SelectorStateHeaderSize+len(payload.Entries)*SelectorStateEntrySize)
	wire[0] = SelectorStateVersion
	wire[1] = byte(payload.Direction)
	binary.BigEndian.PutUint64(wire[4:12], payload.GraphRevision)
	copy(wire[12:44], payload.GraphDigest[:])
	copy(wire[44:60], payload.SessionEpoch[:])
	binary.BigEndian.PutUint64(wire[60:68], payload.StateEpoch)
	binary.BigEndian.PutUint16(wire[68:70], uint16(len(payload.Entries)))
	offset := SelectorStateHeaderSize
	for _, entry := range payload.Entries {
		copy(wire[offset:offset+16], entry.SelectorID[:])
		copy(wire[offset+16:offset+32], entry.DesiredTargetID[:])
		copy(wire[offset+32:offset+48], entry.EffectiveTargetID[:])
		binary.BigEndian.PutUint64(wire[offset+48:offset+56], entry.Generation)
		offset += SelectorStateEntrySize
	}
	return wire, nil
}

// DecodeSelectorState decodes only the canonical representation accepted by
// Validate. It never sorts hostile input or allocates beyond graph limits.
func DecodeSelectorState(
	wire []byte,
	manifest GraphManifest,
	binding GraphBinding,
) (SelectorStatePayload, error) {
	if len(wire) < SelectorStateHeaderSize {
		return SelectorStatePayload{}, fmt.Errorf("proto: selector state payload too short: %d < %d", len(wire), SelectorStateHeaderSize)
	}
	if len(wire) > SelectorStateMaxWireBytes {
		return SelectorStatePayload{}, fmt.Errorf("proto: selector state payload exceeds %d bytes", SelectorStateMaxWireBytes)
	}
	if wire[0] != SelectorStateVersion {
		return SelectorStatePayload{}, fmt.Errorf("proto: selector state version %d is unsupported", wire[0])
	}
	if wire[2] != 0 || wire[3] != 0 || wire[70] != 0 || wire[71] != 0 {
		return SelectorStatePayload{}, fmt.Errorf("proto: selector state reserved bytes are non-zero")
	}
	count := int(binary.BigEndian.Uint16(wire[68:70]))
	if count > GraphManifestMaxNodes {
		return SelectorStatePayload{}, fmt.Errorf("proto: selector state has %d entries, maximum is %d", count, GraphManifestMaxNodes)
	}
	wantLength := SelectorStateHeaderSize + count*SelectorStateEntrySize
	if len(wire) != wantLength {
		return SelectorStatePayload{}, fmt.Errorf("proto: selector state length %d does not match entry count %d", len(wire), count)
	}
	payload := SelectorStatePayload{
		Direction:     SenderDirection(wire[1]),
		GraphRevision: binary.BigEndian.Uint64(wire[4:12]),
		StateEpoch:    binary.BigEndian.Uint64(wire[60:68]),
		Entries:       make([]SelectorStateEntry, count),
	}
	copy(payload.GraphDigest[:], wire[12:44])
	copy(payload.SessionEpoch[:], wire[44:60])
	offset := SelectorStateHeaderSize
	for index := range payload.Entries {
		entry := &payload.Entries[index]
		copy(entry.SelectorID[:], wire[offset:offset+16])
		copy(entry.DesiredTargetID[:], wire[offset+16:offset+32])
		copy(entry.EffectiveTargetID[:], wire[offset+32:offset+48])
		entry.Generation = binary.BigEndian.Uint64(wire[offset+48 : offset+56])
		offset += SelectorStateEntrySize
	}
	if err := payload.Validate(manifest, binding); err != nil {
		return SelectorStatePayload{}, err
	}
	return payload, nil
}

// Validate proves that payload is the complete canonical selector state for
// manifest and its exact negotiated binding.
func (payload SelectorStatePayload) Validate(manifest GraphManifest, binding GraphBinding) error {
	if err := manifest.Validate(); err != nil {
		return fmt.Errorf("proto: selector state graph: %w", err)
	}
	digest, err := manifest.Digest()
	if err != nil {
		return fmt.Errorf("proto: selector state graph digest: %w", err)
	}
	if binding.Revision == 0 || binding.Digest != digest {
		return fmt.Errorf("proto: selector state binding does not match graph")
	}
	if payload.SessionEpoch == (SessionEpoch{}) {
		return fmt.Errorf("proto: selector state has zero session epoch")
	}
	if !payload.Direction.Valid() {
		return fmt.Errorf("proto: selector state has invalid sender direction %d", payload.Direction)
	}
	if payload.GraphRevision != binding.Revision || payload.GraphDigest != binding.Digest {
		return fmt.Errorf("proto: selector state payload binding does not match negotiated graph")
	}
	if payload.StateEpoch == 0 {
		return fmt.Errorf("proto: selector state has zero state epoch")
	}

	selectors := make(map[TargetID]GraphNode)
	for _, node := range manifest.Nodes {
		if node.Kind == GraphNodeKindSelector {
			selectors[node.ID] = node
		}
	}
	if len(selectors) == 0 {
		return fmt.Errorf("proto: selector state graph has no selectors")
	}
	if len(payload.Entries) != len(selectors) {
		return fmt.Errorf("proto: selector state has %d entries, want %d", len(payload.Entries), len(selectors))
	}

	seen := make(map[TargetID]struct{}, len(payload.Entries))
	var previous TargetID
	for index, entry := range payload.Entries {
		if entry.SelectorID == (TargetID{}) || entry.DesiredTargetID == (TargetID{}) ||
			entry.EffectiveTargetID == (TargetID{}) || entry.Generation == 0 {
			return fmt.Errorf("proto: selector state entry %d contains a zero field", index)
		}
		if index != 0 && bytes.Compare(previous[:], entry.SelectorID[:]) >= 0 {
			return fmt.Errorf("proto: selector state entries are not in canonical selector-id order")
		}
		previous = entry.SelectorID
		node, ok := selectors[entry.SelectorID]
		if !ok {
			return fmt.Errorf("proto: selector state entry %d references an unknown selector", index)
		}
		if _, duplicate := seen[entry.SelectorID]; duplicate {
			return fmt.Errorf("proto: selector state repeats selector %x", entry.SelectorID)
		}
		seen[entry.SelectorID] = struct{}{}
		if !targetIDIn(entry.DesiredTargetID, node.Children) {
			return fmt.Errorf("proto: selector state desired target is not an immediate child of %q", node.Name)
		}
		if !targetIDIn(entry.EffectiveTargetID, node.Children) {
			return fmt.Errorf("proto: selector state effective target is not an immediate child of %q", node.Name)
		}
	}
	for selectorID := range selectors {
		if _, ok := seen[selectorID]; !ok {
			return fmt.Errorf("proto: selector state is missing selector %x", selectorID)
		}
	}
	return nil
}

func targetIDIn(target TargetID, candidates []TargetID) bool {
	for _, candidate := range candidates {
		if candidate == target {
			return true
		}
	}
	return false
}
