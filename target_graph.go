package rendr

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"sort"
)

const (
	targetGraphCanonicalVersion = 1
	targetGraphMaxDepth         = 32
	targetGraphMaxNodes         = 1024
)

// compiledTargetGraph is an immutable, validated snapshot of a Target graph.
// root contains the normalized scheduling tree; nodesByName also retains
// same-kind groups absorbed into bond and race scheduling domains.
type compiledTargetGraph struct {
	root        *targetGraphNode
	canonical   []byte
	digest      [sha256.Size]byte
	nodesByName map[string]*targetGraphNode
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
	return compiledTargetGraph{
		root:        node,
		canonical:   canonical,
		digest:      sha256.Sum256(canonical),
		nodesByName: c.nodesByName,
		nodeCount:   c.nodeCount,
		maxDepth:    c.maxDepth,
	}, nil
}

// compileDialPlan derives the temporary flat dispatcher input from the same
// immutable snapshot that owns the protocol digest. M4 replaces this flat
// projection with recursive executors; no caller may walk Root a second time.
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
			mode:     ModeSelector,
			paths:    []PathSpec{clonePathSpec(*node.path)},
			pathPeak: []bool{false},
		}, nil
	}

	mode, err := modeForTargetKind(node.kind)
	if err != nil {
		return compiledTarget{}, err
	}
	out := compiledTarget{mode: mode, peakTransfer: node.peak != nil}
	peakNames := make(map[string]bool)
	if node.peak != nil {
		out.peakOptions = clonePeakTransfer(*node.peak)
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
		childPeak := peakNames[child.name]
		out.paths = append(out.paths, childPlan.paths...)
		for _, nestedPeak := range childPlan.pathPeak {
			out.pathPeak = append(out.pathPeak, childPeak || nestedPeak)
		}
		out.peakTransfer = out.peakTransfer || childPlan.peakTransfer
		out.runtimeNested = out.runtimeNested || child.kind != TargetKindPath || childPlan.runtimeNested
		if childPeak && out.peakMode == 0 {
			out.peakMode = childPlan.mode
		}
		if out.peakMode == 0 && childPlan.peakMode != 0 {
			out.peakMode = childPlan.peakMode
		}
	}
	if len(out.paths) == 0 {
		return compiledTarget{}, errEmptyGroupTarget
	}
	if out.peakTransfer && out.peakMode == 0 {
		out.peakMode = ModeSelector
	}
	return out, nil
}

func modeForTargetKind(kind TargetKind) (Mode, error) {
	switch kind {
	case TargetKindSelector:
		return ModeSelector, nil
	case TargetKindBond:
		return ModeBond, nil
	case TargetKindRace:
		return ModeRace, nil
	default:
		return 0, fmt.Errorf("rendr: unknown target kind %q", kind)
	}
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
	Targets         []string `json:"targets"`
	SaturationRatio uint64   `json:"saturation_ratio_bits"`
	SaturationFor   int64    `json:"saturation_for_ns"`
	ReturnRatio     uint64   `json:"return_ratio_bits"`
	ReturnFor       int64    `json:"return_for_ns"`
	ProbeBudget     int64    `json:"probe_budget"`
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
			Targets:         targets,
			SaturationRatio: math.Float64bits(node.peak.SaturationRatio),
			SaturationFor:   int64(node.peak.SaturationFor),
			ReturnRatio:     math.Float64bits(node.peak.ReturnRatio),
			ReturnFor:       int64(node.peak.ReturnFor),
			ProbeBudget:     node.peak.ProbeBudget,
		}
	}
	canonical.Children = make([]canonicalTargetNode, 0, len(node.children))
	for _, child := range node.children {
		canonical.Children = append(canonical.Children, canonicalizeTargetNode(child))
	}
	return canonical
}
