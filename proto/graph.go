package proto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
	"unicode/utf8"
)

const (
	// GraphManifestVersion is the first target-graph manifest wire version.
	GraphManifestVersion uint8 = 1

	GraphManifestMaxNodes     = 1024
	GraphManifestMaxDepth     = 32
	GraphManifestMaxNameBytes = 255
	// A manifest is embedded in one HELLO control frame. Leave room for the
	// fixed handshake envelope inside the engine's 32 KiB payload ceiling.
	GraphManifestMaxWireBytes = 30 << 10
)

const (
	graphManifestHeaderSize = 24
	graphNodeHeaderSize     = 24
)

var graphManifestMagic = [4]byte{'R', 'G', 'M', 'F'}

// GraphNodeKind identifies a target node on the wire. These values are a
// protocol contract and intentionally do not depend on public or engine enums.
type GraphNodeKind uint8

const (
	GraphNodeKindInvalid  GraphNodeKind = 0
	GraphNodeKindPath     GraphNodeKind = 1
	GraphNodeKindSelector GraphNodeKind = 2
	GraphNodeKindBond     GraphNodeKind = 3
	GraphNodeKindRace     GraphNodeKind = 4
)

// Valid reports whether k is a v1 target graph node kind.
func (k GraphNodeKind) Valid() bool {
	return k >= GraphNodeKindPath && k <= GraphNodeKindRace
}

func (k GraphNodeKind) String() string {
	switch k {
	case GraphNodeKindPath:
		return "path"
	case GraphNodeKindSelector:
		return "selector"
	case GraphNodeKindBond:
		return "bond"
	case GraphNodeKindRace:
		return "race"
	default:
		return fmt.Sprintf("graph-kind(%d)", uint8(k))
	}
}

// GraphNode is the wire-safe scheduling description of one target. It never
// contains carrier addresses, local bindings, credentials, or opaque options.
// Children retain scheduling order. PeakCandidates are an unordered selector
// set and are sorted by Encode.
type GraphNode struct {
	ID             TargetID
	Kind           GraphNodeKind
	Name           string
	Weight         uint16
	Children       []TargetID
	PeakCandidates []TargetID
}

// GraphManifest is an immutable target graph snapshot exchanged during
// session negotiation. Nodes may be supplied in any order; Encode sorts them
// by stable target identity.
type GraphManifest struct {
	RootID TargetID
	Nodes  []GraphNode
}

// Node returns a copy of the node identified by id.
func (m GraphManifest) Node(id TargetID) (GraphNode, bool) {
	for _, node := range m.Nodes {
		if node.ID == id {
			return node, true
		}
	}
	return GraphNode{}, false
}

// NodeByName returns a copy of the uniquely named node.
func (m GraphManifest) NodeByName(name string) (GraphNode, bool) {
	for _, node := range m.Nodes {
		if node.Name == name {
			return node, true
		}
	}
	return GraphNode{}, false
}

// DeriveTargetID returns the stable v1 identity for a node kind and name.
// Validate separately enforces the v1 name and kind constraints.
func DeriveTargetID(kind GraphNodeKind, name string) TargetID {
	h := sha256.New()
	h.Write([]byte("rendr-target-id-v1\x00"))
	h.Write([]byte{byte(kind)})
	var nameLen [2]byte
	binary.BigEndian.PutUint16(nameLen[:], uint16(len(name)))
	h.Write(nameLen[:])
	h.Write([]byte(name))
	var id TargetID
	copy(id[:], h.Sum(nil))
	return id
}

// Validate checks graph identity, shape, references, connectivity, cycles,
// and resource bounds without mutating the manifest.
func (m GraphManifest) Validate() error {
	if len(m.Nodes) == 0 {
		return fmt.Errorf("proto: graph manifest has no nodes")
	}
	if len(m.Nodes) > GraphManifestMaxNodes {
		return fmt.Errorf("proto: graph manifest has %d nodes, maximum is %d", len(m.Nodes), GraphManifestMaxNodes)
	}

	byID := make(map[TargetID]*GraphNode, len(m.Nodes))
	byName := make(map[string]TargetID, len(m.Nodes))
	wireSize := graphManifestHeaderSize
	for i := range m.Nodes {
		node := &m.Nodes[i]
		if !node.Kind.Valid() {
			return fmt.Errorf("proto: graph node %d has invalid kind %d", i, node.Kind)
		}
		if node.Name == "" {
			return fmt.Errorf("proto: graph node %d has empty name", i)
		}
		if !utf8.ValidString(node.Name) {
			return fmt.Errorf("proto: graph node %d name is not valid UTF-8", i)
		}
		if len(node.Name) > GraphManifestMaxNameBytes {
			return fmt.Errorf("proto: graph node %q name is %d bytes, maximum is %d", node.Name, len(node.Name), GraphManifestMaxNameBytes)
		}
		if want := DeriveTargetID(node.Kind, node.Name); node.ID != want {
			return fmt.Errorf("proto: graph node %q target id does not match kind and name", node.Name)
		}
		if _, exists := byID[node.ID]; exists {
			return fmt.Errorf("proto: duplicate graph target id for %q", node.Name)
		}
		if previous, exists := byName[node.Name]; exists {
			return fmt.Errorf("proto: duplicate graph target name %q (%x and %x)", node.Name, previous, node.ID)
		}
		byID[node.ID] = node
		byName[node.Name] = node.ID

		if len(node.Children) > GraphManifestMaxNodes {
			return fmt.Errorf("proto: graph node %q has too many children", node.Name)
		}
		if len(node.PeakCandidates) > GraphManifestMaxNodes {
			return fmt.Errorf("proto: graph node %q has too many peak candidates", node.Name)
		}
		wireSize += graphNodeHeaderSize + len(node.Name) + 16*(len(node.Children)+len(node.PeakCandidates))
		if wireSize > GraphManifestMaxWireBytes {
			return fmt.Errorf("proto: graph manifest wire size exceeds %d bytes", GraphManifestMaxWireBytes)
		}
		switch node.Kind {
		case GraphNodeKindPath:
			if len(node.Children) != 0 || len(node.PeakCandidates) != 0 {
				return fmt.Errorf("proto: path node %q must not have child or peak references", node.Name)
			}
		case GraphNodeKindSelector:
			if len(node.Children) == 0 {
				return fmt.Errorf("proto: selector node %q has no children", node.Name)
			}
			if node.Weight != 0 {
				return fmt.Errorf("proto: selector node %q has path-only weight", node.Name)
			}
		case GraphNodeKindBond, GraphNodeKindRace:
			if len(node.Children) == 0 {
				return fmt.Errorf("proto: %s node %q has no children", node.Kind, node.Name)
			}
			if node.Weight != 0 {
				return fmt.Errorf("proto: %s node %q has path-only weight", node.Kind, node.Name)
			}
			if len(node.PeakCandidates) != 0 {
				return fmt.Errorf("proto: %s node %q has selector-only peak candidates", node.Kind, node.Name)
			}
		}
	}

	if _, exists := byID[m.RootID]; !exists {
		return fmt.Errorf("proto: graph root %x does not identify a node", m.RootID)
	}

	parents := make(map[TargetID]TargetID, len(m.Nodes)-1)
	for i := range m.Nodes {
		node := &m.Nodes[i]
		children := make(map[TargetID]struct{}, len(node.Children))
		for _, childID := range node.Children {
			child, exists := byID[childID]
			if !exists {
				return fmt.Errorf("proto: graph node %q references missing child %x", node.Name, childID)
			}
			if _, duplicate := children[childID]; duplicate {
				return fmt.Errorf("proto: graph node %q repeats child %x", node.Name, childID)
			}
			children[childID] = struct{}{}
			if previous, duplicate := parents[childID]; duplicate {
				return fmt.Errorf("proto: graph target %q has multiple parents %q and %q", child.Name, byID[previous].Name, node.Name)
			}
			parents[childID] = node.ID
			if (node.Kind == GraphNodeKindBond || node.Kind == GraphNodeKindRace) && child.Kind == node.Kind {
				return fmt.Errorf("proto: %s node %q contains unnormalized %s child %q", node.Kind, node.Name, child.Kind, child.Name)
			}
		}
		peaks := make(map[TargetID]struct{}, len(node.PeakCandidates))
		for _, peakID := range node.PeakCandidates {
			if _, duplicate := peaks[peakID]; duplicate {
				return fmt.Errorf("proto: selector node %q repeats peak candidate %x", node.Name, peakID)
			}
			peaks[peakID] = struct{}{}
			if _, immediate := children[peakID]; !immediate {
				return fmt.Errorf("proto: selector node %q peak candidate %x is not an immediate child", node.Name, peakID)
			}
		}
	}
	if _, hasParent := parents[m.RootID]; hasParent {
		return fmt.Errorf("proto: graph root %q must not have a parent", byID[m.RootID].Name)
	}

	const (
		unvisited uint8 = iota
		visiting
		visited
	)
	state := make(map[TargetID]uint8, len(m.Nodes))
	depthMemo := make(map[TargetID]int, len(m.Nodes))
	var depth func(TargetID) (int, error)
	depth = func(id TargetID) (int, error) {
		switch state[id] {
		case visiting:
			return 0, fmt.Errorf("proto: target graph contains a cycle at %q", byID[id].Name)
		case visited:
			return depthMemo[id], nil
		}
		state[id] = visiting
		maxDepth := 1
		for _, childID := range byID[id].Children {
			childDepth, err := depth(childID)
			if err != nil {
				return 0, err
			}
			if childDepth+1 > maxDepth {
				maxDepth = childDepth + 1
			}
		}
		if maxDepth > GraphManifestMaxDepth {
			return 0, fmt.Errorf("proto: target graph depth %d exceeds maximum %d", maxDepth, GraphManifestMaxDepth)
		}
		state[id] = visited
		depthMemo[id] = maxDepth
		return maxDepth, nil
	}
	if _, err := depth(m.RootID); err != nil {
		return err
	}
	if len(state) != len(m.Nodes) {
		return fmt.Errorf("proto: target graph contains %d unreachable node(s)", len(m.Nodes)-len(state))
	}
	return nil
}

// Encode returns the unique canonical v1 wire representation of m.
func (m GraphManifest) Encode() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}

	nodes := append([]GraphNode(nil), m.Nodes...)
	sort.Slice(nodes, func(i, j int) bool {
		return bytes.Compare(nodes[i].ID[:], nodes[j].ID[:]) < 0
	})

	size := graphManifestHeaderSize
	for i := range nodes {
		size += graphNodeHeaderSize + len(nodes[i].Name) + 16*(len(nodes[i].Children)+len(nodes[i].PeakCandidates))
		if size > GraphManifestMaxWireBytes {
			return nil, fmt.Errorf("proto: graph manifest wire size exceeds %d bytes", GraphManifestMaxWireBytes)
		}
	}

	wire := make([]byte, graphManifestHeaderSize, size)
	copy(wire[0:4], graphManifestMagic[:])
	wire[4] = GraphManifestVersion
	binary.BigEndian.PutUint16(wire[6:8], uint16(len(nodes)))
	copy(wire[8:24], m.RootID[:])

	for i := range nodes {
		node := &nodes[i]
		peaks := append([]TargetID(nil), node.PeakCandidates...)
		sort.Slice(peaks, func(i, j int) bool {
			return bytes.Compare(peaks[i][:], peaks[j][:]) < 0
		})

		headerAt := len(wire)
		wire = append(wire, make([]byte, graphNodeHeaderSize)...)
		copy(wire[headerAt:headerAt+16], node.ID[:])
		wire[headerAt+16] = byte(node.Kind)
		wire[headerAt+17] = byte(len(node.Name))
		binary.BigEndian.PutUint16(wire[headerAt+18:headerAt+20], node.Weight)
		binary.BigEndian.PutUint16(wire[headerAt+20:headerAt+22], uint16(len(node.Children)))
		binary.BigEndian.PutUint16(wire[headerAt+22:headerAt+24], uint16(len(peaks)))
		wire = append(wire, node.Name...)
		for _, childID := range node.Children {
			wire = append(wire, childID[:]...)
		}
		for _, peakID := range peaks {
			wire = append(wire, peakID[:]...)
		}
	}
	return wire, nil
}

// DecodeGraphManifest parses only canonical v1 encodings. Lengths are checked
// against fixed limits and remaining input before any variable-size allocation.
func DecodeGraphManifest(wire []byte) (GraphManifest, error) {
	if len(wire) > GraphManifestMaxWireBytes {
		return GraphManifest{}, fmt.Errorf("proto: graph manifest is %d bytes, maximum is %d", len(wire), GraphManifestMaxWireBytes)
	}
	if len(wire) < graphManifestHeaderSize {
		return GraphManifest{}, fmt.Errorf("proto: graph manifest too short: %d < %d", len(wire), graphManifestHeaderSize)
	}
	if !bytes.Equal(wire[0:4], graphManifestMagic[:]) {
		return GraphManifest{}, fmt.Errorf("proto: invalid graph manifest magic")
	}
	if wire[4] != GraphManifestVersion {
		return GraphManifest{}, fmt.Errorf("proto: unsupported graph manifest version %d", wire[4])
	}
	if wire[5] != 0 {
		return GraphManifest{}, fmt.Errorf("proto: graph manifest reserved byte must be zero")
	}
	nodeCount := int(binary.BigEndian.Uint16(wire[6:8]))
	if nodeCount == 0 || nodeCount > GraphManifestMaxNodes {
		return GraphManifest{}, fmt.Errorf("proto: invalid graph manifest node count %d", nodeCount)
	}
	if len(wire)-graphManifestHeaderSize < nodeCount*graphNodeHeaderSize {
		return GraphManifest{}, fmt.Errorf("proto: graph manifest cannot contain %d node headers", nodeCount)
	}

	manifest := GraphManifest{Nodes: make([]GraphNode, 0, nodeCount)}
	copy(manifest.RootID[:], wire[8:24])
	offset := graphManifestHeaderSize
	for i := 0; i < nodeCount; i++ {
		if len(wire)-offset < graphNodeHeaderSize {
			return GraphManifest{}, fmt.Errorf("proto: graph node %d header is truncated", i)
		}
		header := wire[offset : offset+graphNodeHeaderSize]
		offset += graphNodeHeaderSize
		nameLen := int(header[17])
		childCount := int(binary.BigEndian.Uint16(header[20:22]))
		peakCount := int(binary.BigEndian.Uint16(header[22:24]))
		if nameLen == 0 {
			return GraphManifest{}, fmt.Errorf("proto: graph node %d has zero name length", i)
		}
		if childCount > GraphManifestMaxNodes || peakCount > GraphManifestMaxNodes {
			return GraphManifest{}, fmt.Errorf("proto: graph node %d reference count exceeds %d", i, GraphManifestMaxNodes)
		}
		bodySize := nameLen + 16*(childCount+peakCount)
		if bodySize > len(wire)-offset {
			return GraphManifest{}, fmt.Errorf("proto: graph node %d body is truncated", i)
		}

		node := GraphNode{
			Kind:           GraphNodeKind(header[16]),
			Name:           string(wire[offset : offset+nameLen]),
			Weight:         binary.BigEndian.Uint16(header[18:20]),
			Children:       make([]TargetID, childCount),
			PeakCandidates: make([]TargetID, peakCount),
		}
		copy(node.ID[:], header[0:16])
		offset += nameLen
		for child := range node.Children {
			copy(node.Children[child][:], wire[offset:offset+16])
			offset += 16
		}
		for peak := range node.PeakCandidates {
			copy(node.PeakCandidates[peak][:], wire[offset:offset+16])
			offset += 16
		}
		manifest.Nodes = append(manifest.Nodes, node)
	}
	if offset != len(wire) {
		return GraphManifest{}, fmt.Errorf("proto: graph manifest has %d trailing byte(s)", len(wire)-offset)
	}
	if err := manifest.Validate(); err != nil {
		return GraphManifest{}, err
	}
	canonical, err := manifest.Encode()
	if err != nil {
		return GraphManifest{}, err
	}
	if !bytes.Equal(canonical, wire) {
		return GraphManifest{}, fmt.Errorf("proto: graph manifest encoding is not canonical")
	}
	return manifest, nil
}

// Digest hashes the canonical wire representation of m.
func (m GraphManifest) Digest() (GraphDigest, error) {
	wire, err := m.Encode()
	if err != nil {
		return GraphDigest{}, err
	}
	return GraphDigest(sha256.Sum256(wire)), nil
}
