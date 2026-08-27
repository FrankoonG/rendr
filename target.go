package rendr

import (
	"errors"
)

// Target is one node in a rendr policy graph.
//
// A Path, Selector, Race, or Bond is a Target. Selector children and cross-mode
// child groups remain one logical target. Nested Race-in-Race and Bond-in-Bond
// groups are flattened into the parent execution set.
type Target interface {
	Name() string
	targetNode()
}

// TargetKind identifies the hard execution semantics of a Target node.
type TargetKind string

const (
	TargetKindPath     TargetKind = "path"
	TargetKindSelector TargetKind = "selector"
	TargetKindRace     TargetKind = "race"
	TargetKindBond     TargetKind = "bond"
)

// PathTarget is a leaf target backed by one PathSpec.
type PathTarget struct {
	TargetName string
	Spec       PathSpec
}

func (p PathTarget) Name() string { return p.TargetName }
func (p PathTarget) targetNode()  {}

// Path constructs a named leaf target.
func Path(name string, spec PathSpec) Target {
	return PathTarget{TargetName: name, Spec: spec}
}

// GroupTarget is a composite target. Selector, Race, and Bond are all groups.
type GroupTarget struct {
	TargetName string
	Kind       TargetKind
	Children   []Target

	Peak *PeakTransfer
}

func (g GroupTarget) Name() string { return g.TargetName }
func (g GroupTarget) targetNode()  {}

// Selector constructs a quality-first selector target. If PeakTransfer is
// supplied, the listed child names are peak-transfer candidates.
func Selector(name string, children []Target, opts ...SelectorOption) Target {
	g := GroupTarget{TargetName: name, Kind: TargetKindSelector, Children: append([]Target(nil), children...)}
	for _, opt := range opts {
		if opt != nil {
			opt.applySelector(&g)
		}
	}
	return g
}

// Race constructs a race target.
func Race(name string, children []Target) Target {
	return GroupTarget{TargetName: name, Kind: TargetKindRace, Children: append([]Target(nil), children...)}
}

// Bond constructs a bond target.
func Bond(name string, children []Target) Target {
	return GroupTarget{TargetName: name, Kind: TargetKindBond, Children: append([]Target(nil), children...)}
}

// SelectorOption configures a Selector target.
type SelectorOption interface {
	applySelector(*GroupTarget)
}

// PeakTransfer marks selector children that should only be used as
// peak-transfer candidates unless normal targets are unavailable.
type PeakTransfer struct {
	Targets []string
}

func (p PeakTransfer) applySelector(g *GroupTarget) {
	cp := p
	cp.Targets = append([]string(nil), p.Targets...)
	g.Peak = &cp
}

// compiledTarget owns the immutable graph plus the ordered leaf dial plan.
// Runtime scheduling always uses graph; paths contains carrier configuration
// only for initial dial and recovery.
type compiledTarget struct {
	paths         []PathSpec
	primaryName   string
	peakTransfer  bool
	graph         compiledTargetGraph
	graphRevision uint64
	runtimeConfig RuntimeConfig
}

var (
	errNilTarget        = errors.New("rendr: nil target")
	errEmptyGroupTarget = errors.New("rendr: group target has no children")
)

func compileTargetForDial(root Target) (compiledTarget, error) {
	graph, err := compileTargetGraph(root)
	if err != nil {
		return compiledTarget{}, err
	}
	return graph.compileDialPlan()
}

func specWithTargetName(spec PathSpec, name string) PathSpec {
	if name == "" {
		return spec
	}
	if spec.Opts == nil {
		spec.Opts = map[string]string{"name": name}
		return spec
	}
	if spec.Opts["name"] == "" {
		cp := make(map[string]string, len(spec.Opts)+1)
		for k, v := range spec.Opts {
			cp[k] = v
		}
		cp["name"] = name
		spec.Opts = cp
	}
	return spec
}

func pathSpecName(spec PathSpec) string {
	if spec.Opts != nil {
		return spec.Opts["name"]
	}
	return ""
}

func targetPrimaryLeafName(root Target, name string) (string, bool) {
	if root == nil || name == "" {
		return "", false
	}
	return targetPrimaryLeafNameNode(root, name)
}

func targetPrimaryLeafNameNode(t Target, name string) (string, bool) {
	switch v := t.(type) {
	case PathTarget:
		if v.Name() == name {
			return v.Name(), true
		}
		return "", false
	case *PathTarget:
		if v == nil {
			return "", false
		}
		if v.Name() == name {
			return v.Name(), true
		}
		return "", false
	case GroupTarget:
		if v.Name() == name {
			return firstLeafName(v.Children)
		}
		for _, child := range v.Children {
			if got, ok := targetPrimaryLeafNameNode(child, name); ok {
				return got, true
			}
		}
	case *GroupTarget:
		if v == nil {
			return "", false
		}
		return targetPrimaryLeafNameNode(*v, name)
	}
	return "", false
}

func firstLeafName(children []Target) (string, bool) {
	for _, child := range children {
		switch v := child.(type) {
		case PathTarget:
			return v.Name(), true
		case *PathTarget:
			if v != nil {
				return v.Name(), true
			}
		case GroupTarget:
			if got, ok := firstLeafName(v.Children); ok {
				return got, true
			}
		case *GroupTarget:
			if v != nil {
				if got, ok := firstLeafName(v.Children); ok {
					return got, true
				}
			}
		}
	}
	return "", false
}
