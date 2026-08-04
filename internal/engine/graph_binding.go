package engine

import (
	"fmt"
	"sync/atomic"

	"github.com/FrankoonG/rendr/proto"
)

// graphBinding identifies one direction's immutable sender graph. A session
// has two bindings because each peer owns its own transmit policy graph.
type graphBinding struct {
	revision   uint64
	digest     proto.GraphDigest
	configured bool
}

func bindingFromNegotiation(n proto.Negotiation) graphBinding {
	return graphBinding{revision: n.GraphRevision, digest: n.GraphDigest, configured: true}
}

func (e *Engine) localGraphBinding() graphBinding {
	e.graphMu.RLock()
	binding := e.localGraph
	e.graphMu.RUnlock()
	return binding
}

func (e *Engine) peerGraphBinding() graphBinding {
	e.graphMu.RLock()
	binding := e.peerGraph
	e.graphMu.RUnlock()
	return binding
}

// ConfigureLocalGraph freezes the graph used by this engine's sender. It must
// run before a sequenced frame is allocated.
func (e *Engine) ConfigureLocalGraph(revision uint64, digest proto.GraphDigest) error {
	if revision == 0 {
		return fmt.Errorf("engine: zero local graph revision")
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
	binding := graphBinding{revision: revision, digest: digest, configured: true}
	e.localGraph = binding
	e.graphMu.Unlock()
	e.sendProof = proto.InitialAckProof(proto.SessionEpoch(e.flowID), senderDirection(e.side), revision, digest)
	e.sendAckProof = e.sendProof
	return nil
}

// ConfigurePeerGraph freezes the graph used by the peer's sender. It must run
// before this engine accepts a sequenced frame.
func (e *Engine) ConfigurePeerGraph(revision uint64, digest proto.GraphDigest) error {
	if revision == 0 {
		return fmt.Errorf("engine: zero peer graph revision")
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
	e.peerGraph = graphBinding{revision: revision, digest: digest, configured: true}
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

// AcceptPeerNegotiation validates the peer's directional declaration and
// freezes it before any path reader can publish sequenced frames.
func (e *Engine) AcceptPeerNegotiation(peer proto.Negotiation) error {
	local := e.LocalNegotiation()
	if peer.ProtocolMajor != local.ProtocolMajor {
		return fmt.Errorf("engine: protocol major mismatch: local=%d peer=%d", local.ProtocolMajor, peer.ProtocolMajor)
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
	return e.ConfigurePeerGraph(peer.GraphRevision, peer.GraphDigest)
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
	return e.ConfigureLocalGraph(peer.revision, peer.digest)
}
