package rendr

import (
	"errors"
	"fmt"
	"time"
)

// Target is one node in the v0.4 policy graph.
//
// A Path, Selector, Race, or Bond is a Target. Parent groups always see a child
// group as one logical target; group internals are execution details.
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
func Race(name string, children []Target, opts ...RaceOption) Target {
	g := GroupTarget{TargetName: name, Kind: TargetKindRace, Children: append([]Target(nil), children...)}
	for _, opt := range opts {
		if opt != nil {
			opt.applyRace(&g)
		}
	}
	return g
}

// Bond constructs a bond target.
func Bond(name string, children []Target, opts ...BondOption) Target {
	g := GroupTarget{TargetName: name, Kind: TargetKindBond, Children: append([]Target(nil), children...)}
	for _, opt := range opts {
		if opt != nil {
			opt.applyBond(&g)
		}
	}
	return g
}

// SelectorOption configures a Selector target.
type SelectorOption interface {
	applySelector(*GroupTarget)
}

// RaceOption is reserved for future race target knobs.
type RaceOption interface {
	applyRace(*GroupTarget)
}

// BondOption is reserved for future bond target knobs.
type BondOption interface {
	applyBond(*GroupTarget)
}

// PeakTransfer marks selector children that should only be used as
// peak-transfer candidates unless normal targets are unavailable.
//
// The minimal public form is Targets. The tuning fields are optional and keep
// zero-value defaults until the runtime policy layer consumes them.
type PeakTransfer struct {
	Targets []string

	SaturationRatio float64
	SaturationFor   time.Duration
	ReturnRatio     float64
	ReturnFor       time.Duration
	ProbeBudget     int64
}

func (p PeakTransfer) applySelector(g *GroupTarget) {
	cp := p
	cp.Targets = append([]string(nil), p.Targets...)
	g.Peak = &cp
}

type compiledTarget struct {
	mode          Mode
	paths         []PathSpec
	pathPeak      []bool
	peakTransfer  bool
	peakMode      Mode
	peakOptions   PeakTransfer
	runtimeNested bool
}

var (
	errNilTarget        = errors.New("rendr: nil target")
	errEmptyGroupTarget = errors.New("rendr: group target has no children")
)

func legacyRootTarget(mode Mode, paths []PathSpec) Target {
	children := make([]Target, 0, len(paths))
	for i, ps := range paths {
		children = append(children, Path(fmt.Sprintf("path-%d", i+1), ps))
	}
	if !mode.Valid() {
		mode = ModePrime
	}
	switch mode {
	case ModeRace:
		return Race("root", children)
	case ModeBond:
		return Bond("root", children)
	default:
		return Selector("root", children)
	}
}

func compileTargetForDial(root Target) (compiledTarget, error) {
	if root == nil {
		return compiledTarget{}, errNilTarget
	}
	return compileTargetNode(root, true)
}

func compileTargetNode(t Target, root bool) (compiledTarget, error) {
	switch v := t.(type) {
	case PathTarget:
		return compiledTarget{mode: ModePrime, paths: []PathSpec{specWithTargetName(v.Spec, v.TargetName)}, pathPeak: []bool{false}}, nil
	case *PathTarget:
		if v == nil {
			return compiledTarget{}, errNilTarget
		}
		return compiledTarget{mode: ModePrime, paths: []PathSpec{specWithTargetName(v.Spec, v.TargetName)}, pathPeak: []bool{false}}, nil
	case GroupTarget:
		return compileGroupTarget(v, root)
	case *GroupTarget:
		if v == nil {
			return compiledTarget{}, errNilTarget
		}
		return compileGroupTarget(*v, root)
	default:
		return compiledTarget{}, fmt.Errorf("rendr: unsupported target type %T", t)
	}
}

func compileGroupTarget(g GroupTarget, root bool) (compiledTarget, error) {
	if len(g.Children) == 0 {
		return compiledTarget{}, errEmptyGroupTarget
	}
	var out compiledTarget
	switch g.Kind {
	case TargetKindRace:
		out.mode = ModeRace
	case TargetKindBond:
		out.mode = ModeBond
	case TargetKindSelector:
		out.mode = ModePrime
	default:
		return compiledTarget{}, fmt.Errorf("rendr: unknown target kind %q", g.Kind)
	}
	out.peakTransfer = g.Peak != nil
	if g.Peak != nil {
		out.peakOptions = *g.Peak
		out.peakOptions.Targets = append([]string(nil), g.Peak.Targets...)
	}
	peakSet := map[string]bool{}
	if g.Peak != nil {
		for _, name := range g.Peak.Targets {
			peakSet[name] = true
		}
	}
	for _, child := range orderedChildren(g.Children, peakSet) {
		childPeak := child != nil && peakSet[child.Name()]
		ct, err := compileTargetNode(child, false)
		if err != nil {
			return compiledTarget{}, err
		}
		if !isPathOnly(child) {
			out.runtimeNested = true
		}
		out.paths = append(out.paths, ct.paths...)
		for _, peak := range ct.pathPeak {
			out.pathPeak = append(out.pathPeak, peak || childPeak)
		}
		out.peakTransfer = out.peakTransfer || ct.peakTransfer
		if childPeak && out.peakMode == 0 {
			out.peakMode = ct.mode
		}
		if out.peakMode == 0 && ct.peakMode != 0 {
			out.peakMode = ct.peakMode
		}
		out.runtimeNested = out.runtimeNested || ct.runtimeNested
	}
	if len(out.paths) == 0 {
		return compiledTarget{}, errEmptyGroupTarget
	}
	if len(out.pathPeak) != len(out.paths) {
		out.pathPeak = make([]bool, len(out.paths))
	}
	if out.peakTransfer && out.peakMode == 0 {
		out.peakMode = ModePrime
	}
	return out, nil
}

func orderedChildren(children []Target, peakSet map[string]bool) []Target {
	if len(peakSet) == 0 {
		return append([]Target(nil), children...)
	}
	out := make([]Target, 0, len(children))
	for _, c := range children {
		if c != nil && !peakSet[c.Name()] {
			out = append(out, c)
		}
	}
	for _, c := range children {
		if c != nil && peakSet[c.Name()] {
			out = append(out, c)
		}
	}
	return out
}

func isPathOnly(t Target) bool {
	switch t.(type) {
	case PathTarget, *PathTarget:
		return true
	default:
		return false
	}
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
