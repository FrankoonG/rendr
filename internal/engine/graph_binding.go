package engine

import (
	"fmt"
	"sync/atomic"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

// PathBinding records which leaf a physical path represents in each sender's
// immutable graph. The two identities are intentionally independent: a
// full-duplex carrier can have different names and graph positions in each
// direction.
type PathBinding struct {
	LocalTXTargetID proto.TargetID
	PeerTXTargetID  proto.TargetID
}

// graphBinding identifies one direction's immutable sender graph. A session
// has two bindings because each peer owns its own transmit policy graph.
type graphBinding struct {
	revision   uint64
	digest     proto.GraphDigest
	manifest   proto.GraphManifest
	configured bool
}

func (e *Engine) localGraphBinding() graphBinding {
	e.graphMu.RLock()
	binding := e.localGraph
	e.graphMu.RUnlock()
	return binding
}

func (e *Engine) localExecutionRuntime() *executionRuntime {
	e.graphMu.RLock()
	runtime := e.localExec
	e.graphMu.RUnlock()
	return runtime
}

func (e *Engine) peerGraphBinding() graphBinding {
	e.graphMu.RLock()
	binding := e.peerGraph
	e.graphMu.RUnlock()
	return binding
}

// ConfigureLocalGraph freezes the graph used by this engine's sender. It must
// run before a sequenced frame is allocated.
func (e *Engine) ConfigureLocalGraph(revision uint64, manifest proto.GraphManifest) error {
	if revision == 0 {
		return fmt.Errorf("engine: zero local graph revision")
	}
	owned, digest, err := ownGraphManifest(manifest)
	if err != nil {
		return fmt.Errorf("engine: invalid local graph: %w", err)
	}
	plan, err := compileExecutionPlan(owned)
	if err != nil {
		return err
	}
	e.sendMu.Lock()
	defer e.sendMu.Unlock()
	if atomic.LoadUint64(&e.sendSeq) != 0 || e.sendPublishedNext.Load() != 0 {
		return fmt.Errorf("engine: local graph already active")
	}
	e.sendHistMu.Lock()
	defer e.sendHistMu.Unlock()
	if len(e.sendHist.entries) != 0 {
		return fmt.Errorf("engine: local graph has replay history")
	}
	e.graphMu.Lock()
	if e.localGraph.configured {
		current := e.localGraph
		e.graphMu.Unlock()
		if current.revision == revision && current.digest == digest {
			return nil
		}
		return fmt.Errorf("engine: local graph is already configured")
	}
	binding := graphBinding{revision: revision, digest: digest, manifest: owned, configured: true}
	e.localGraph = binding
	e.localExec = newExecutionRuntime(plan)
	e.graphMu.Unlock()
	e.sendProof = proto.InitialAckProof(proto.SessionEpoch(e.flowID), senderDirection(e.side), revision, digest)
	e.sendAckProof = e.sendProof
	return nil
}

// ConfigurePeerGraph freezes the graph used by the peer's sender. It must run
// before this engine accepts a sequenced frame.
func (e *Engine) ConfigurePeerGraph(revision uint64, manifest proto.GraphManifest) error {
	if revision == 0 {
		return fmt.Errorf("engine: zero peer graph revision")
	}
	owned, digest, err := ownGraphManifest(manifest)
	if err != nil {
		return fmt.Errorf("engine: invalid peer graph: %w", err)
	}
	e.recvMu.Lock()
	defer e.recvMu.Unlock()
	if e.expectedRecvSeq != 0 || len(e.recvQueue) != 0 || len(e.recvDeliver) != 0 || e.recvPacketMarks != 0 {
		return fmt.Errorf("engine: peer graph already active")
	}
	e.graphMu.Lock()
	if e.peerGraph.configured {
		current := e.peerGraph
		e.graphMu.Unlock()
		if current.revision == revision && current.digest == digest {
			return nil
		}
		return fmt.Errorf("engine: peer graph is already configured")
	}
	e.peerGraph = graphBinding{revision: revision, digest: digest, manifest: owned, configured: true}
	e.graphMu.Unlock()
	e.recvProof = proto.InitialAckProof(proto.SessionEpoch(e.flowID), peerSenderDirection(e.side), revision, digest)
	return nil
}

// LocalNegotiation builds the HELLO/HELLO_ACK declaration for this sender.
func (e *Engine) LocalNegotiation() proto.Negotiation {
	binding := e.localGraphBinding()
	n := proto.NewNegotiation(proto.SessionEpoch(e.flowID))
	n.GraphRevision = binding.revision
	n.GraphDigest = binding.digest
	return n
}

func (e *Engine) LocalGraphManifest() proto.GraphManifest {
	binding := e.localGraphBinding()
	manifest, _, err := ownGraphManifest(binding.manifest)
	if err != nil {
		return proto.GraphManifest{}
	}
	return manifest
}

func (e *Engine) LocalPathTargetID(name string) (proto.TargetID, error) {
	binding := e.localGraphBinding()
	if !binding.configured {
		return proto.TargetID{}, fmt.Errorf("engine: local graph is not configured")
	}
	node, ok := binding.manifest.NodeByName(name)
	if !ok || node.Kind != proto.GraphNodeKindPath {
		return proto.TargetID{}, fmt.Errorf("engine: %q is not a path in the local graph", name)
	}
	return node.ID, nil
}

func (e *Engine) PeerPathName(id proto.TargetID) (string, error) {
	binding := e.peerGraphBinding()
	if !binding.configured {
		return "", fmt.Errorf("engine: peer graph is not configured")
	}
	node, ok := binding.manifest.Node(id)
	if !ok || node.Kind != proto.GraphNodeKindPath {
		return "", fmt.Errorf("engine: target is not a path in the peer graph")
	}
	return node.Name, nil
}

func (e *Engine) PeerPathTargetID(name string) (proto.TargetID, error) {
	binding := e.peerGraphBinding()
	if !binding.configured {
		return proto.TargetID{}, fmt.Errorf("engine: peer graph is not configured")
	}
	node, ok := binding.manifest.NodeByName(name)
	if !ok || node.Kind != proto.GraphNodeKindPath {
		return proto.TargetID{}, fmt.Errorf("engine: %q is not a path in the peer graph", name)
	}
	return node.ID, nil
}

// InferPathBinding is retained for engine-level tests and symmetric graph
// callers. Handshake code should pass the two negotiated IDs explicitly.
func (e *Engine) InferPathBinding(spec transport.PathSpec) (PathBinding, error) {
	name := ""
	if spec.Opts != nil {
		name = spec.Opts["name"]
	}
	local := e.localGraphBinding()
	peer := e.peerGraphBinding()
	if !local.configured && !peer.configured {
		return PathBinding{}, nil
	}
	if name == "" {
		return PathBinding{}, fmt.Errorf("engine: configured graph path has no target name")
	}
	var out PathBinding
	var err error
	if local.configured {
		out.LocalTXTargetID, err = e.LocalPathTargetID(name)
		if err != nil {
			return PathBinding{}, err
		}
	}
	if peer.configured {
		out.PeerTXTargetID, err = e.PeerPathTargetID(name)
		if err != nil {
			return PathBinding{}, err
		}
	}
	return out, nil
}

func (e *Engine) validatePathBinding(binding PathBinding) error {
	local := e.localGraphBinding()
	if local.configured {
		node, ok := local.manifest.Node(binding.LocalTXTargetID)
		if !ok || node.Kind != proto.GraphNodeKindPath {
			return fmt.Errorf("engine: local TX target is not a path in the bound graph")
		}
	} else if binding.LocalTXTargetID != (proto.TargetID{}) {
		return fmt.Errorf("engine: local TX target supplied without a local graph")
	}
	peer := e.peerGraphBinding()
	if peer.configured {
		node, ok := peer.manifest.Node(binding.PeerTXTargetID)
		if !ok || node.Kind != proto.GraphNodeKindPath {
			return fmt.Errorf("engine: peer TX target is not a path in the bound graph")
		}
	} else if binding.PeerTXTargetID != (proto.TargetID{}) {
		return fmt.Errorf("engine: peer TX target supplied without a peer graph")
	}
	return nil
}

// AcceptPeerNegotiation validates the peer's directional declaration and
// freezes it before any path reader can publish sequenced frames.
func (e *Engine) AcceptPeerNegotiation(peer proto.Negotiation, manifest proto.GraphManifest) error {
	local := e.LocalNegotiation()
	if peer.ProtocolMajor != local.ProtocolMajor {
		return fmt.Errorf("engine: protocol major mismatch: local=%d peer=%d", local.ProtocolMajor, peer.ProtocolMajor)
	}
	if peer.ProtocolMinor < local.ProtocolMinor {
		return fmt.Errorf("engine: protocol minor mismatch: local=%d peer=%d", local.ProtocolMinor, peer.ProtocolMinor)
	}
	if peer.SessionEpoch != proto.SessionEpoch(e.flowID) {
		return fmt.Errorf("engine: negotiation session epoch mismatch")
	}
	if local.Required&^peer.Supported != 0 {
		return fmt.Errorf("engine: peer lacks required features 0x%x", uint64(local.Required&^peer.Supported))
	}
	if peer.Required&^local.Supported != 0 {
		return fmt.Errorf("engine: local side lacks peer-required features 0x%x", uint64(peer.Required&^local.Supported))
	}
	digest, err := manifest.Digest()
	if err != nil {
		return fmt.Errorf("engine: invalid peer graph manifest: %w", err)
	}
	if digest != peer.GraphDigest {
		return fmt.Errorf("engine: peer graph digest mismatch")
	}
	return e.ConfigurePeerGraph(peer.GraphRevision, manifest)
}

// MirrorPeerGraphForLocal is the listener default until an embedder supplies
// an explicit server TX graph. It preserves directional bindings while using
// the dialer's graph for the reverse direction over the same leaf set.
func (e *Engine) MirrorPeerGraphForLocal() error {
	peer := e.peerGraphBinding()
	if !peer.configured {
		return fmt.Errorf("engine: peer graph is not configured")
	}
	local := e.localGraphBinding()
	if local.configured {
		return nil
	}
	return e.ConfigureLocalGraph(peer.revision, peer.manifest)
}

func ownGraphManifest(manifest proto.GraphManifest) (proto.GraphManifest, proto.GraphDigest, error) {
	wire, err := manifest.Encode()
	if err != nil {
		return proto.GraphManifest{}, proto.GraphDigest{}, err
	}
	owned, err := proto.DecodeGraphManifest(wire)
	if err != nil {
		return proto.GraphManifest{}, proto.GraphDigest{}, err
	}
	digest, err := owned.Digest()
	return owned, digest, err
}
