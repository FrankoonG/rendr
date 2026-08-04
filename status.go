package rendr

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport/gvisor"
	"github.com/FrankoonG/rendr/transport/tcprepair"
	"github.com/FrankoonG/rendr/tun"
)

// InstanceID identifies one running rendr runtime. It is generated at
// process/runtime start and is intentionally not persistent.
type InstanceID = proto.InstanceID

// CapabilityID is a stable, extensible capability identifier exposed
// through status APIs. Status snapshots list only confirmed available
// capabilities; absence means unavailable, unprobed, irrelevant, or
// not a rendr peer.
type CapabilityID string

const (
	CapRendr        CapabilityID = "rendr"
	CapL7           CapabilityID = "l7"
	CapTUN          CapabilityID = "tun"
	CapL3Identity   CapabilityID = "l3_identity"
	CapTCPRepair    CapabilityID = "tcp_repair"
	CapGVisor       CapabilityID = "gvisor"
	CapMixed        CapabilityID = "mixed"
	CapPacketMode   CapabilityID = "packet_mode"
	CapQUICDatagram CapabilityID = "quic_datagram"
)

type CapabilitySet []CapabilityID

func (s CapabilitySet) Has(id CapabilityID) bool {
	for _, got := range s {
		if got == id {
			return true
		}
	}
	return false
}

type LocalStatus struct {
	Caps CapabilitySet
}

// ProbeLocal reports locally available rendr capabilities. The ids
// argument is an optional filter; when empty it probes the default core set.
func ProbeLocal(_ context.Context, ids ...CapabilityID) (LocalStatus, error) {
	want := make(map[CapabilityID]bool, len(ids))
	for _, id := range ids {
		want[id] = true
	}
	include := func(id CapabilityID) bool { return len(want) == 0 || want[id] }
	var caps CapabilitySet
	add := func(id CapabilityID) {
		if include(id) && !caps.Has(id) {
			caps = append(caps, id)
		}
	}

	add(CapRendr)
	add(CapL7)
	add(CapMixed)
	add(CapPacketMode)
	add(CapQUICDatagram)
	if include(CapGVisor) && gvisor.Available() == nil {
		add(CapGVisor)
	}
	if include(CapTCPRepair) && tcprepair.Available() == nil {
		add(CapTCPRepair)
	}
	if include(CapTUN) && tun.Probe().Available {
		add(CapTUN)
	}
	return LocalStatus{Caps: caps}, nil
}

type PeerKind string

const (
	PeerUnknown PeerKind = "unknown"
	PeerNative  PeerKind = "native"
	PeerRendr   PeerKind = "rendr"
)

type Status struct {
	Local CapabilitySet
	Peer  PeerStatus
	Paths []PathStatus
}

type PeerStatus struct {
	Kind       PeerKind
	InstanceID InstanceID
	Caps       CapabilitySet
}

type PathState string

const (
	PathPending     PathState = "pending"
	PathDialing     PathState = "dialing"
	PathHandshaking PathState = "handshaking"
	PathAttached    PathState = "attached"
	PathUnavailable PathState = "unavailable"
	PathDegraded    PathState = "degraded"
	PathNative      PathState = "native"
)

type PathStatus struct {
	Name      string
	Transport string
	State     PathState
	Active    bool
	Primary   bool
	Caps      CapabilitySet
	LastError string
}

type StatusReporter interface {
	Status() Status
}

type IngressMode string

const (
	IngressTUN IngressMode = "tun"
	IngressL7  IngressMode = "l7"
)

type FallbackPolicy string

const (
	FallbackAllow FallbackPolicy = "allow"
	FallbackDeny  FallbackPolicy = "deny"
)

type RuntimeConfig struct {
	IngressMode IngressMode
	Fallback    FallbackPolicy
}

type PrimaryPolicy string

const (
	PrimaryPrefer  PrimaryPolicy = "prefer"
	PrimaryRequire PrimaryPolicy = "require"
)

type RetryPolicy struct {
	Enabled    bool
	MinBackoff time.Duration
	MaxBackoff time.Duration
	Jitter     float64
}

func capsFromProto(bits uint32) CapabilitySet {
	caps := CapabilitySet{CapRendr, CapL7}
	if bits&proto.CapsPacketMode != 0 {
		caps = append(caps, CapPacketMode)
	}
	if bits&proto.CapsL3Identity != 0 {
		caps = append(caps, CapL3Identity)
	}
	return caps
}

func pathCaps(spec PathSpec) CapabilitySet {
	caps := CapabilitySet{CapL7}
	switch spec.Transport {
	case "tcprepair":
		caps = append(caps, CapTCPRepair)
	case "gvisor":
		caps = append(caps, CapGVisor)
	case "quic":
		if spec.Opts != nil && spec.Opts["mode"] == "datagram" {
			caps = append(caps, CapQUICDatagram, CapPacketMode)
		}
	case "udpflow":
		caps = append(caps, CapPacketMode)
	}
	return caps
}

type pathStatusTracker struct {
	mu    sync.RWMutex
	paths []trackedPathStatus
}

type trackedPathStatus struct {
	spec      PathSpec
	state     PathState
	primary   bool
	lastError string
}

func newPathStatusTracker(paths []PathSpec, primaryName string) *pathStatusTracker {
	t := &pathStatusTracker{paths: make([]trackedPathStatus, len(paths))}
	for i, ps := range paths {
		name := pathSpecName(ps)
		if name == "" {
			name = "path-" + strconv.Itoa(i+1)
			ps = specWithTargetName(ps, name)
		}
		primary := false
		if primaryName != "" {
			primary = name == primaryName
		} else {
			primary = i == 0
		}
		t.paths[i] = trackedPathStatus{
			spec:    ps,
			state:   PathPending,
			primary: primary,
		}
	}
	return t
}

func (t *pathStatusTracker) set(index int, state PathState, err error) {
	if t == nil || index < 0 || index >= len(t.paths) {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.paths[index].state = state
	if err == nil {
		t.paths[index].lastError = ""
	} else {
		t.paths[index].lastError = err.Error()
	}
}

func (t *pathStatusTracker) snapshot(attached []PathInfo) []PathStatus {
	if t == nil {
		return nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()

	used := make([]bool, len(attached))
	out := make([]PathStatus, 0, len(t.paths)+len(attached))
	for _, tracked := range t.paths {
		if idx := matchAttachedPath(tracked.spec, attached, used); idx >= 0 {
			used[idx] = true
			out = append(out, pathStatusFromInfo(attached[idx], tracked.primary))
			continue
		}
		out = append(out, PathStatus{
			Name:      pathSpecName(tracked.spec),
			Transport: tracked.spec.Transport,
			State:     tracked.state,
			Primary:   tracked.primary,
			Caps:      pathCaps(tracked.spec),
			LastError: tracked.lastError,
		})
	}
	for i, p := range attached {
		if !used[i] {
			out = append(out, pathStatusFromInfo(p, false))
		}
	}
	return out
}

func matchAttachedPath(spec PathSpec, attached []PathInfo, used []bool) int {
	for i, p := range attached {
		if used[i] {
			continue
		}
		if pathSpecName(p.Spec) == pathSpecName(spec) && p.Spec.Transport == spec.Transport && p.Spec.Address == spec.Address {
			return i
		}
	}
	return -1
}

func pathStatusFromInfo(p PathInfo, primary bool) PathStatus {
	return PathStatus{
		Name:      pathSpecName(p.Spec),
		Transport: p.Spec.Transport,
		State:     PathAttached,
		Active:    p.Active,
		Primary:   primary,
		Caps:      pathCaps(p.Spec),
	}
}

func statusFromEngine(e *engine.Engine, _ Mode, tracker *pathStatusTracker) Status {
	local, _ := ProbeLocal(context.Background())
	peerKind := PeerUnknown
	switch e.PeerKind() {
	case engine.PeerRendr:
		peerKind = PeerRendr
	case engine.PeerNative:
		peerKind = PeerNative
	default:
		if e.PeerCaps() != 0 || e.PeerInstanceID() != (InstanceID{}) {
			peerKind = PeerRendr
		}
	}
	paths := e.Paths()
	out := tracker.snapshot(paths)
	if out == nil {
		out = make([]PathStatus, 0, len(paths))
		for _, p := range paths {
			out = append(out, pathStatusFromInfo(p, p.ID == 1))
		}
	}
	return Status{
		Local: local.Caps,
		Peer: PeerStatus{
			Kind:       peerKind,
			InstanceID: e.PeerInstanceID(),
			Caps:       capsFromProto(e.PeerCaps()),
		},
		Paths: out,
	}
}
