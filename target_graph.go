package rendr

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"

	"github.com/FrankoonG/rendr/proto"
)

const (
	targetGraphCanonicalVersion = 2
	targetGraphMaxDepth         = 32
	targetGraphMaxNodes         = 1024
)

// compiledTargetGraph is an immutable, validated snapshot of a Target graph.
// root contains the normalized scheduling tree; nodesByName also retains
// same-kind groups absorbed into bond and race scheduling domains.
type compiledTargetGraph struct {
	root        *targetGraphNode
	manifest    proto.GraphManifest
	canonical   []byte
	localDigest [sha256.Size]byte
	digest      proto.GraphDigest
	nodesByName map[string]*targetGraphNode
	nodesByID   map[proto.TargetID]*targetGraphNode
	leafIDs     map[proto.TargetID]struct{}
	nodeCount   int
	maxDepth    int
}

type targetGraphNode struct {
	kind      TargetKind
	name      string
	path      *PathSpec
	peak      *PeakTransfer
	children  []*targetGraphNode
	flattened bool
	id        proto.TargetID
}

type targetGraphCompiler struct {
	active      map[*GroupTarget]struct{}
	nodesByName map[string]*targetGraphNode
	flattened   []canonicalTargetIdentity
	nodeCount   int
	maxDepth    int
}

// compileTargetGraph validates, normalizes, serializes, and hashes root.
func compileTargetGraph(root Target) (compiledTargetGraph, error) {
	c := targetGraphCompiler{
		active:      make(map[*GroupTarget]struct{}),
		nodesByName: make(map[string]*targetGraphNode),
	}
	node, err := c.compile(root, 1)
	if err != nil {
		return compiledTargetGraph{}, err
	}

	canonical, err := json.Marshal(c.canonicalGraph(node))
	if err != nil {
		return compiledTargetGraph{}, fmt.Errorf("rendr: serialize target graph: %w", err)
	}
	manifest, digest, nodesByID, leafIDs, err := buildTargetGraphManifest(node)
	if err != nil {
		return compiledTargetGraph{}, err
	}
	return compiledTargetGraph{
		root:        node,
		manifest:    manifest,
		canonical:   canonical,
		localDigest: sha256.Sum256(canonical),
		digest:      digest,
		nodesByName: c.nodesByName,
		nodesByID:   nodesByID,
		leafIDs:     leafIDs,
		nodeCount:   c.nodeCount,
		maxDepth:    c.maxDepth,
	}, nil
}

type targetGraphManifestBuilder struct {
	nodes     []proto.GraphNode
	nodesByID map[proto.TargetID]*targetGraphNode
	leafIDs   map[proto.TargetID]struct{}
}

// buildTargetGraphManifest projects only remotely meaningful scheduling
// semantics. Dial addresses, local bindings, opaque options, policy tuning,
// and identities of same-mode groups absorbed during normalization remain in
// the local snapshot and never enter the session graph digest.
func buildTargetGraphManifest(root *targetGraphNode) (
	proto.GraphManifest,
	proto.GraphDigest,
	map[proto.TargetID]*targetGraphNode,
	map[proto.TargetID]struct{},
	error,
) {
	b := targetGraphManifestBuilder{
		nodesByID: make(map[proto.TargetID]*targetGraphNode),
		leafIDs:   make(map[proto.TargetID]struct{}),
	}
	rootID, err := b.add(root)
	if err != nil {
		return proto.GraphManifest{}, proto.GraphDigest{}, nil, nil, err
	}
	manifest := proto.GraphManifest{RootID: rootID, Nodes: b.nodes}
	digest, err := manifest.Digest()
	if err != nil {
		return proto.GraphManifest{}, proto.GraphDigest{}, nil, nil, fmt.Errorf("rendr: invalid target graph manifest: %w", err)
	}
	return manifest, digest, b.nodesByID, b.leafIDs, nil
}

func (b *targetGraphManifestBuilder) add(node *targetGraphNode) (proto.TargetID, error) {
	if node == nil {
		return proto.TargetID{}, fmt.Errorf("rendr: target graph manifest contains a nil node")
	}
	kind, err := graphNodeKind(node.kind)
	if err != nil {
		return proto.TargetID{}, err
	}
	id := proto.DeriveTargetID(kind, node.name)
	if previous, exists := b.nodesByID[id]; exists {
		return proto.TargetID{}, fmt.Errorf("rendr: target id collision between %q and %q", previous.name, node.name)
	}
	node.id = id
	b.nodesByID[id] = node

	wireNode := proto.GraphNode{ID: id, Kind: kind, Name: node.name}
	if node.kind == TargetKindPath {
		if node.path == nil {
			return proto.TargetID{}, fmt.Errorf("rendr: path target %q has no path spec", node.name)
		}
		wireNode.Weight = node.path.Weight
		b.leafIDs[id] = struct{}{}
		b.nodes = append(b.nodes, wireNode)
		return id, nil
	}

	childIDs := make(map[string]proto.TargetID, len(node.children))
	for _, child := range node.children {
		childID, err := b.add(child)
		if err != nil {
			return proto.TargetID{}, err
		}
		wireNode.Children = append(wireNode.Children, childID)
		childIDs[child.name] = childID
	}
	if node.peak != nil {
		for _, name := range node.peak.Targets {
			peakID, exists := childIDs[name]
			if !exists {
				return proto.TargetID{}, fmt.Errorf("rendr: selector target %q has unknown manifest PeakTransfer reference %q", node.name, name)
			}
			wireNode.PeakCandidates = append(wireNode.PeakCandidates, peakID)
		}
	}
	b.nodes = append(b.nodes, wireNode)
	return id, nil
}

func graphNodeKind(kind TargetKind) (proto.GraphNodeKind, error) {
	switch kind {
	case TargetKindPath:
		return proto.GraphNodeKindPath, nil
	case TargetKindSelector:
		return proto.GraphNodeKindSelector, nil
	case TargetKindBond:
		return proto.GraphNodeKindBond, nil
	case TargetKindRace:
		return proto.GraphNodeKindRace, nil
	default:
		return proto.GraphNodeKindInvalid, fmt.Errorf("rendr: unknown target kind %q", kind)
	}
}

// resolveSelectorChild resolves the public logical selection surface against
// the exact immutable graph used to configure the engine. Selection is scoped
// to an immediate child so a child group remains one target and cannot be
// confused with one of its physical leaves.
func (g compiledTargetGraph) resolveSelectorChild(selectorName, targetName string) (proto.TargetID, proto.TargetID, error) {
	return resolveSelectorChild(g.manifest, selectorName, targetName)
}

func resolveSelectorChild(manifest proto.GraphManifest, selectorName, targetName string) (proto.TargetID, proto.TargetID, error) {
	if len(manifest.Nodes) == 0 {
		return proto.TargetID{}, proto.TargetID{}, fmt.Errorf("rendr: target selection is unavailable because the session has no compiled target graph")
	}
	if selectorName == "" {
		return proto.TargetID{}, proto.TargetID{}, fmt.Errorf("rendr: selector name is empty")
	}
	var selector, target proto.GraphNode
	selectorFound, targetFound := false, false
	for _, node := range manifest.Nodes {
		if node.Name == selectorName {
			selector, selectorFound = node, true
		}
		if node.Name == targetName {
			target, targetFound = node, true
		}
	}
	if !selectorFound {
		return proto.TargetID{}, proto.TargetID{}, fmt.Errorf("rendr: selector target %q is not in the session graph", selectorName)
	}
	if selector.Kind != proto.GraphNodeKindSelector {
		return proto.TargetID{}, proto.TargetID{}, fmt.Errorf("rendr: target %q is %s, not a selector", selectorName, selector.Kind)
	}
	if targetName == "" {
		return proto.TargetID{}, proto.TargetID{}, fmt.Errorf("rendr: target name is empty for selector %q", selectorName)
	}
	if !targetFound {
		return proto.TargetID{}, proto.TargetID{}, fmt.Errorf("rendr: target %q is not in the session graph", targetName)
	}
	for _, childID := range selector.Children {
		if childID == target.ID {
			return selector.ID, target.ID, nil
		}
	}
	return proto.TargetID{}, proto.TargetID{}, fmt.Errorf("rendr: target %q is not an immediate child of selector %q", targetName, selectorName)
}

// compileDialPlan derives carrier dial order and recovery configuration from
// the same immutable graph that owns recursive execution and the wire digest.
// No caller may walk the mutable Target input a second time.
func (g compiledTargetGraph) compileDialPlan() (compiledTarget, error) {
	if g.root == nil {
		return compiledTarget{}, errNilTarget
	}
	plan, err := compileGraphNodeForDial(g.root)
	if err != nil {
		return compiledTarget{}, err
	}
	plan.graph = g
	plan.graphRevision = 1
	return plan, nil
}

func compileGraphNodeForDial(node *targetGraphNode) (compiledTarget, error) {
	if node.kind == TargetKindPath {
		if node.path == nil {
			return compiledTarget{}, fmt.Errorf("rendr: path target %q has no path spec", node.name)
		}
		return compiledTarget{
			paths: []PathSpec{clonePathSpec(*node.path)},
		}, nil
	}

	out := compiledTarget{peakTransfer: node.peak != nil}
	peakNames := make(map[string]bool)
	if node.peak != nil {
		for _, name := range node.peak.Targets {
			peakNames[name] = true
		}
	}
	children := append([]*targetGraphNode(nil), node.children...)
	if len(peakNames) != 0 {
		sort.SliceStable(children, func(i, j int) bool {
			return !peakNames[children[i].name] && peakNames[children[j].name]
		})
	}
	for _, child := range children {
		childPlan, err := compileGraphNodeForDial(child)
		if err != nil {
			return compiledTarget{}, err
		}
		out.paths = append(out.paths, childPlan.paths...)
		out.peakTransfer = out.peakTransfer || childPlan.peakTransfer
	}
	if len(out.paths) == 0 {
		return compiledTarget{}, errEmptyGroupTarget
	}
	return out, nil
}

func (g compiledTargetGraph) resolvePathSpec(spec PathSpec, attached []PathInfo) (PathSpec, error) {
	if name := pathSpecName(spec); name != "" {
		node, ok := g.nodesByName[name]
		if !ok || node.path == nil {
			return PathSpec{}, fmt.Errorf("rendr: %q is not a path in the session graph", name)
		}
		if !samePathConfig(*node.path, spec) {
			return PathSpec{}, fmt.Errorf("rendr: path %q does not match the frozen session graph", name)
		}
		return clonePathSpec(*node.path), nil
	}

	candidates := make([]*targetGraphNode, 0, 2)
	for _, node := range g.nodesByName {
		if node.path != nil && samePathConfig(*node.path, spec) {
			candidates = append(candidates, node)
		}
	}
	if len(candidates) == 0 {
		return PathSpec{}, fmt.Errorf("rendr: path is not present in the frozen session graph")
	}
	attachedNames := make(map[string]bool, len(attached))
	for _, path := range attached {
		attachedNames[pathSpecName(path.Spec)] = true
	}
	missing := make([]*targetGraphNode, 0, len(candidates))
	for _, candidate := range candidates {
		if !attachedNames[candidate.name] {
			missing = append(missing, candidate)
		}
	}
	if len(missing) == 1 {
		return clonePathSpec(*missing[0].path), nil
	}
	if len(candidates) == 1 {
		return clonePathSpec(*candidates[0].path), nil
	}
	return PathSpec{}, fmt.Errorf("rendr: path matches multiple graph leaves; specify a target name")
}

func samePathConfig(frozen, candidate PathSpec) bool {
	if frozen.Transport != candidate.Transport || frozen.Address != candidate.Address ||
		frozen.Local != candidate.Local || frozen.Weight != candidate.Weight {
		return false
	}
	for key, value := range frozen.Opts {
		if key != "name" && candidate.Opts[key] != value {
			return false
		}
	}
	for key, value := range candidate.Opts {
		if key != "name" && frozen.Opts[key] != value {
			return false
		}
	}
	return true
}

func (c *targetGraphCompiler) compile(target Target, depth int) (*targetGraphNode, error) {
	if target == nil || isTypedNilTarget(target) {
		return nil, errNilTarget
	}
	if depth > targetGraphMaxDepth {
		return nil, fmt.Errorf("rendr: target graph depth exceeds %d", targetGraphMaxDepth)
	}
	c.nodeCount++
	if c.nodeCount > targetGraphMaxNodes {
		return nil, fmt.Errorf("rendr: target graph node count exceeds %d", targetGraphMaxNodes)
	}
	if depth > c.maxDepth {
		c.maxDepth = depth
	}

	switch value := target.(type) {
	case PathTarget:
		return c.compilePath(value)
	case *PathTarget:
		return c.compilePath(*value)
	case GroupTarget:
		return c.compileGroup(value, depth)
	case *GroupTarget:
		if _, exists := c.active[value]; exists {
			return nil, fmt.Errorf("rendr: target graph cycle at %q", value.TargetName)
		}
		c.active[value] = struct{}{}
		defer delete(c.active, value)
		return c.compileGroup(*value, depth)
	default:
		return nil, fmt.Errorf("rendr: unsupported target type %T", target)
	}
}

func isTypedNilTarget(target Target) bool {
	value := reflect.ValueOf(target)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (c *targetGraphCompiler) compilePath(path PathTarget) (*targetGraphNode, error) {
	if err := c.reserveName(path.TargetName); err != nil {
		return nil, err
	}
	if specName := path.Spec.Opts["name"]; specName != "" && specName != path.TargetName {
		return nil, fmt.Errorf("rendr: path target %q conflicts with PathSpec option name %q", path.TargetName, specName)
	}

	spec := clonePathSpec(path.Spec)
	if spec.Opts == nil {
		spec.Opts = make(map[string]string, 1)
	}
	spec.Opts["name"] = path.TargetName
	node := &targetGraphNode{kind: TargetKindPath, name: path.TargetName, path: &spec}
	c.nodesByName[node.name] = node
	return node, nil
}

func (c *targetGraphCompiler) compileGroup(group GroupTarget, depth int) (*targetGraphNode, error) {
	if err := c.reserveName(group.TargetName); err != nil {
		return nil, err
	}
	switch group.Kind {
	case TargetKindSelector, TargetKindRace, TargetKindBond:
	default:
		return nil, fmt.Errorf("rendr: unknown target kind %q", group.Kind)
	}
	if len(group.Children) == 0 {
		return nil, errEmptyGroupTarget
	}
	if group.Peak != nil && group.Kind != TargetKindSelector {
		return nil, fmt.Errorf("rendr: PeakTransfer is only valid on selector target %q", group.TargetName)
	}

	node := &targetGraphNode{kind: group.Kind, name: group.TargetName}
	c.nodesByName[node.name] = node
	immediateNames := make(map[string]struct{}, len(group.Children))
	for _, child := range group.Children {
		compiledChild, err := c.compile(child, depth+1)
		if err != nil {
			return nil, err
		}
		immediateNames[compiledChild.name] = struct{}{}
		if (group.Kind == TargetKindBond || group.Kind == TargetKindRace) && compiledChild.kind == group.Kind {
			compiledChild.flattened = true
			c.flattened = append(c.flattened, canonicalTargetIdentity{Kind: compiledChild.kind, Name: compiledChild.name})
			node.children = append(node.children, compiledChild.children...)
			continue
		}
		node.children = append(node.children, compiledChild)
	}

	if group.Peak != nil {
		peak := clonePeakTransfer(*group.Peak)
		seen := make(map[string]struct{}, len(peak.Targets))
		for _, name := range peak.Targets {
			if _, duplicate := seen[name]; duplicate {
				return nil, fmt.Errorf("rendr: selector target %q has duplicate PeakTransfer reference %q", group.TargetName, name)
			}
			seen[name] = struct{}{}
			if _, exists := immediateNames[name]; !exists {
				return nil, fmt.Errorf("rendr: selector target %q has unknown PeakTransfer reference %q", group.TargetName, name)
			}
		}
		node.peak = &peak
	}
	return node, nil
}

func (c *targetGraphCompiler) reserveName(name string) error {
	if name == "" {
		return fmt.Errorf("rendr: target name is empty")
	}
	if _, exists := c.nodesByName[name]; exists {
		return fmt.Errorf("rendr: duplicate target name %q", name)
	}
	return nil
}

func clonePathSpec(spec PathSpec) PathSpec {
	clone := spec
	if spec.Opts != nil {
		clone.Opts = make(map[string]string, len(spec.Opts)+1)
		for key, value := range spec.Opts {
			clone.Opts[key] = value
		}
	}
	return clone
}

func clonePeakTransfer(peak PeakTransfer) PeakTransfer {
	clone := peak
	clone.Targets = append([]string(nil), peak.Targets...)
	return clone
}

type canonicalTargetGraph struct {
	Version   int                       `json:"version"`
	Root      canonicalTargetNode       `json:"root"`
	Flattened []canonicalTargetIdentity `json:"flattened,omitempty"`
}

type canonicalTargetIdentity struct {
	Kind TargetKind `json:"kind"`
	Name string     `json:"name"`
}

type canonicalTargetNode struct {
	Kind     TargetKind            `json:"kind"`
	Name     string                `json:"name"`
	Path     *canonicalTargetPath  `json:"path,omitempty"`
	Peak     *canonicalTargetPeak  `json:"peak,omitempty"`
	Children []canonicalTargetNode `json:"children,omitempty"`
}

type canonicalTargetPath struct {
	Carrier string                  `json:"carrier"`
	Address string                  `json:"address"`
	Local   string                  `json:"local"`
	Weight  uint16                  `json:"weight"`
	Options []canonicalTargetOption `json:"options"`
}

type canonicalTargetOption struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type canonicalTargetPeak struct {
	Targets []string `json:"targets"`
}

func (c *targetGraphCompiler) canonicalGraph(root *targetGraphNode) canonicalTargetGraph {
	flattened := append([]canonicalTargetIdentity(nil), c.flattened...)
	sort.Slice(flattened, func(i, j int) bool {
		if flattened[i].Kind != flattened[j].Kind {
			return flattened[i].Kind < flattened[j].Kind
		}
		return flattened[i].Name < flattened[j].Name
	})
	return canonicalTargetGraph{
		Version:   targetGraphCanonicalVersion,
		Root:      canonicalizeTargetNode(root),
		Flattened: flattened,
	}
}

func canonicalizeTargetNode(node *targetGraphNode) canonicalTargetNode {
	canonical := canonicalTargetNode{Kind: node.kind, Name: node.name}
	if node.path != nil {
		keys := make([]string, 0, len(node.path.Opts))
		for key := range node.path.Opts {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		options := make([]canonicalTargetOption, 0, len(keys))
		for _, key := range keys {
			options = append(options, canonicalTargetOption{Key: key, Value: node.path.Opts[key]})
		}
		canonical.Path = &canonicalTargetPath{
			Carrier: node.path.Transport,
			Address: node.path.Address,
			Local:   node.path.Local,
			Weight:  node.path.Weight,
			Options: options,
		}
	}
	if node.peak != nil {
		targets := append([]string(nil), node.peak.Targets...)
		sort.Strings(targets)
		canonical.Peak = &canonicalTargetPeak{
			Targets: targets,
		}
	}
	canonical.Children = make([]canonicalTargetNode, 0, len(node.children))
	for _, child := range node.children {
		canonical.Children = append(canonical.Children, canonicalizeTargetNode(child))
	}
	return canonical
}
