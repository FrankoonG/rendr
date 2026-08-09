package rendr

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/internal/platform"
	"github.com/FrankoonG/rendr/proto"
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
	// CapRendr confirms the local runtime or peer speaks the rendr session
	// protocol. It does not imply any optional leaf implementation.
	CapRendr CapabilityID = "rendr"
	// CapL7 confirms support for the generic framed stream contract.
	CapL7 CapabilityID = "l7"
	// CapL3Identity confirms that L3 identity metadata was negotiated for a
	// session. It does not claim that a TUN device is available.
	CapL3Identity CapabilityID = "l3_identity"
	// CapPacketMode confirms support for the generic framed packet contract.
	CapPacketMode CapabilityID = "packet_mode"
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
	Caps   CapabilitySet
	Kernel KernelFeatures
}

// ProbeLocal reports process-intrinsic core capabilities together with a
// process-shared active kernel-feature snapshot. The root package does not
// import optional adapters and never guesses from factory or transport names.
// The ids argument is an optional filter over the core capability set.
func ProbeLocal(ctx context.Context, ids ...CapabilityID) (LocalStatus, error) {
	if ctx != nil {
		select {
		case <-ctx.Done():
			return LocalStatus{}, ctx.Err()
		default:
		}
	}

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
	add(CapPacketMode)
	kernel, err := platform.Detect(ctx)
	if err != nil {
		return LocalStatus{Caps: caps}, err
	}
	return LocalStatus{Caps: caps, Kernel: kernelFeaturesFromPlatform(kernel)}, nil
}

func coreLocalStatus() LocalStatus {
	return LocalStatus{Caps: CapabilitySet{CapRendr, CapL7, CapPacketMode}}
}

func (status LocalStatus) snapshot(now time.Time) LocalStatus {
	status.Caps = append(CapabilitySet(nil), status.Caps...)
	status.Kernel = status.Kernel.snapshot(now)
	return status
}

type PeerKind string

const (
	PeerUnknown PeerKind = "unknown"
	PeerNative  PeerKind = "native"
	PeerRendr   PeerKind = "rendr"
)

type Status struct {
	FlowID   [16]byte
	State    string
	Protocol SessionProtocol
	Local    CapabilitySet
	Kernel   KernelFeatures
	Peer     PeerStatus
	Paths    []PathStatus
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
	ID        uint32
	Name      string
	Carrier   CarrierFamily
	State     PathState
	Active    bool
	Mobility  MobilityStatus
	LastError string
}

type StatusReporter interface {
	Status() Status
}

type primaryPolicy string

const (
	primaryPrefer  primaryPolicy = "prefer"
	primaryRequire primaryPolicy = "require"
)

type retryPolicy struct {
	Enabled    bool
	MinBackoff time.Duration
	MaxBackoff time.Duration
	Jitter     float64
}

func capsFromProto(kind PeerKind, bits uint32) CapabilitySet {
	if kind != PeerRendr {
		return nil
	}
	caps := CapabilitySet{CapRendr, CapL7}
	if bits&proto.CapsPacketMode != 0 {
		caps = append(caps, CapPacketMode)
	}
	if bits&proto.CapsL3Identity != 0 {
		caps = append(caps, CapL3Identity)
	}
	return caps
}

func peerStatus(kind PeerKind, instanceID InstanceID, bits uint32) PeerStatus {
	status := PeerStatus{Kind: kind}
	if kind != PeerRendr {
		return status
	}
	status.InstanceID = instanceID
	status.Caps = capsFromProto(kind, bits)
	return status
}

type pathStatusTracker struct {
	mu    sync.RWMutex
	paths []trackedPathStatus
}

type trackedPathStatus struct {
	spec      PathSpec
	state     PathState
	mobility  MobilityStatus
	lastError string
}

func newPathStatusTracker(paths []PathSpec, _ string) *pathStatusTracker {
	t := &pathStatusTracker{paths: make([]trackedPathStatus, len(paths))}
	for i, ps := range paths {
		name := pathSpecName(ps)
		if name == "" {
			name = "path-" + strconv.Itoa(i+1)
			ps = specWithTargetName(ps, name)
		}
		t.paths[i] = trackedPathStatus{
			spec:  ps,
			state: PathPending,
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

func (t *pathStatusTracker) setMobility(index int, mobility MobilityStatus) {
	if t == nil || index < 0 || index >= len(t.paths) {
		return
	}
	t.mu.Lock()
	t.paths[index].mobility = mobility
	t.mu.Unlock()
}

func (t *pathStatusTracker) setMobilityForSpec(spec PathSpec, mobility MobilityStatus) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for index := range t.paths {
		tracked := t.paths[index].spec
		if pathSpecName(tracked) == pathSpecName(spec) && tracked.Transport == spec.Transport && tracked.Address == spec.Address {
			t.paths[index].mobility = mobility
			return
		}
	}
}

func (t *pathStatusTracker) snapshot(attached []PathInfo, carrierMaps ...map[string]CarrierFamily) []PathStatus {
	if t == nil {
		return nil
	}
	var carriers map[string]CarrierFamily
	if len(carrierMaps) != 0 {
		carriers = carrierMaps[0]
	}
	t.mu.RLock()
	defer t.mu.RUnlock()

	used := make([]bool, len(attached))
	out := make([]PathStatus, 0, len(t.paths)+len(attached))
	for _, tracked := range t.paths {
		if idx := matchAttachedPath(tracked.spec, attached, used); idx >= 0 {
			used[idx] = true
			out = append(out, pathStatusFromInfo(attached[idx], tracked.mobility, carriers))
			continue
		}
		out = append(out, PathStatus{
			Name:      pathSpecName(tracked.spec),
			Carrier:   carrierForPathSpec(tracked.spec, carriers),
			State:     tracked.state,
			Mobility:  tracked.mobility,
			LastError: tracked.lastError,
		})
	}
	for i, p := range attached {
		if !used[i] {
			out = append(out, pathStatusFromInfo(p, MobilityStatus{}, carriers))
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

func pathStatusFromInfo(p PathInfo, mobility MobilityStatus, carriers map[string]CarrierFamily) PathStatus {
	return PathStatus{
		ID:       p.ID,
		Name:     pathSpecName(p.Spec),
		Carrier:  carrierForPathSpec(p.Spec, carriers),
		State:    PathAttached,
		Active:   p.Active,
		Mobility: mobility,
	}
}

func statusFromEngine(e *engine.Engine, _ Mode, tracker *pathStatusTracker, carriers map[string]CarrierFamily, localStatuses ...LocalStatus) Status {
	local := coreLocalStatus()
	if len(localStatuses) != 0 {
		local = localStatuses[0].snapshot(time.Now())
	}
	peerKind := PeerUnknown
	switch e.PeerKind() {
	case engine.PeerRendr:
		peerKind = PeerRendr
	case engine.PeerNative:
		peerKind = PeerNative
	default:
	}
	topology := e.TopologySnapshot()
	paths := topology.Paths
	out := tracker.snapshot(paths, carriers)
	if out == nil {
		out = make([]PathStatus, 0, len(paths))
		for _, p := range paths {
			out = append(out, pathStatusFromInfo(p, MobilityStatus{}, carriers))
		}
	}
	mobilityByPath := make(map[uint32]MobilityStatus, len(paths))
	for _, path := range paths {
		mobilityByPath[path.ID] = planLeafMobilityAt(path.Since)
	}
	for _, owned := range topology.LeafMobility {
		mobilityByPath[owned.Ref.ID] = planLeafMobilityAt(
			owned.PlannedAt,
			owned.Facts,
		)
	}
	for index := range out {
		if mobility, ok := mobilityByPath[out[index].ID]; ok {
			out[index].Mobility = mobility
		}
	}
	return Status{
		FlowID:   e.FlowID(),
		State:    topology.State.String(),
		Protocol: sessionProtocolForEngine(e),
		Local:    local.Caps,
		Kernel:   local.Kernel,
		Peer:     peerStatus(peerKind, e.PeerInstanceID(), e.PeerCaps()),
		Paths:    out,
	}
}

func carrierForPathSpec(spec PathSpec, carriers map[string]CarrierFamily) CarrierFamily {
	if carriers == nil {
		return CarrierUnknown
	}
	return carriers[spec.Transport]
}

func sessionProtocolForEngine(e *engine.Engine) SessionProtocol {
	if e != nil && e.Packetized() {
		return SessionProtocolFramedPacketV3
	}
	return SessionProtocolFramedStreamV3
}
