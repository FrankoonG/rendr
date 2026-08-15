package engine

import (
	"fmt"
	"sync/atomic"

	"github.com/FrankoonG/rendr/internal/leafmobility"
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
	revision                  uint64
	digest                    proto.GraphDigest
	manifest                  proto.GraphManifest
	rootSelectorID            proto.TargetID
	rootTracksLocalDelivery   bool
	rootTracksWireAttribution bool
	rootOrdinals              map[proto.TargetID]uint16
	rootTargets               []proto.TargetID
	rootLeafOwners            map[proto.TargetID]proto.TargetID
	names                     map[proto.TargetID]string
	leaves                    map[proto.TargetID]struct{}
	kinds                     map[proto.TargetID]proto.GraphNodeKind
	parents                   map[proto.TargetID]proto.TargetID
	ancestors                 map[proto.TargetID][]proto.TargetID
	configured                bool
}

func newGraphBinding(revision uint64, digest proto.GraphDigest, manifest proto.GraphManifest) graphBinding {
	binding := graphBinding{
		revision: revision, digest: digest, manifest: manifest,
		names:   make(map[proto.TargetID]string),
		leaves:  make(map[proto.TargetID]struct{}),
		kinds:   make(map[proto.TargetID]proto.GraphNodeKind),
		parents: make(map[proto.TargetID]proto.TargetID), configured: true,
	}
	for _, node := range manifest.Nodes {
		binding.names[node.ID] = node.Name
		binding.kinds[node.ID] = node.Kind
		if node.Kind == proto.GraphNodeKindPath {
			binding.leaves[node.ID] = struct{}{}
		}
		for _, childID := range node.Children {
			binding.parents[childID] = node.ID
		}
	}
	binding.ancestors = make(map[proto.TargetID][]proto.TargetID, len(manifest.Nodes))
	for _, node := range manifest.Nodes {
		chain := make([]proto.TargetID, 0, proto.GraphManifestMaxDepth)
		current := node.ID
		for len(chain) <= proto.GraphManifestMaxDepth {
			chain = append(chain, current)
			if current == manifest.RootID {
				binding.ancestors[node.ID] = chain
				break
			}
			parent, exists := binding.parents[current]
			if !exists {
				break
			}
			current = parent
		}
	}
	root, ok := manifest.Node(manifest.RootID)
	if !ok || root.Kind != proto.GraphNodeKindSelector {
		return binding
	}
	binding.rootSelectorID = root.ID
	binding.rootTracksLocalDelivery = true
	binding.rootTracksWireAttribution = proto.RootTracksDataAttribution(manifest)
	binding.rootTargets = append([]proto.TargetID(nil), root.Children...)
	binding.rootLeafOwners = make(map[proto.TargetID]proto.TargetID)
	if binding.rootTracksWireAttribution {
		binding.rootOrdinals = make(map[proto.TargetID]uint16, len(root.Children))
	}
	for index, childID := range root.Children {
		if binding.rootTracksWireAttribution {
			binding.rootOrdinals[childID] = uint16(index + 1)
		}
		binding.collectRootLeafOwners(childID, childID)
	}
	return binding
}

func (b *graphBinding) collectRootLeafOwners(id, owner proto.TargetID) {
	node, ok := b.manifest.Node(id)
	if !ok {
		return
	}
	if node.Kind == proto.GraphNodeKindPath {
		b.rootLeafOwners[id] = owner
		return
	}
	for _, childID := range node.Children {
		b.collectRootLeafOwners(childID, owner)
	}
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

func (e *Engine) requireLocalExecutionRuntime() (*executionRuntime, error) {
	runtime := e.localExecutionRuntime()
	if runtime == nil {
		return nil, errExecutionRuntimeNotConfigured
	}
	return runtime, nil
}

func (e *Engine) peerGraphBinding() graphBinding {
	e.graphMu.RLock()
	binding := e.peerGraph
	e.graphMu.RUnlock()
	return binding
}

func (b graphBinding) dataFlagsForRootTarget(targetID proto.TargetID, committed, demand bool) (uint16, error) {
	if !b.configured {
		return 0, fmt.Errorf("engine: graph is not configured")
	}
	if !b.rootTracksWireAttribution {
		if targetID != (proto.TargetID{}) || committed || demand {
			return 0, fmt.Errorf("engine: untracked root has DATA target attribution")
		}
		return 0, nil
	}
	flags, ok := b.rootOrdinals[targetID]
	if !ok || flags == 0 {
		return 0, fmt.Errorf("engine: DATA target is not a root selector child")
	}
	return proto.DataFlagsForRootOrdinal(flags, committed, demand)
}

func (b graphBinding) rootTargetFromDataFlags(flags uint16) (proto.TargetID, bool, bool, error) {
	if !b.configured {
		return proto.TargetID{}, false, false, fmt.Errorf("engine: graph is not configured")
	}
	if !b.rootTracksWireAttribution {
		if flags != 0 {
			return proto.TargetID{}, false, false, fmt.Errorf("engine: untracked root has non-zero DATA flags")
		}
		return proto.TargetID{}, false, false, nil
	}
	ordinal, committed, demand, err := proto.RootOrdinalFromDataFlags(flags)
	if err != nil || int(ordinal) > len(b.rootTargets) {
		return proto.TargetID{}, false, false, fmt.Errorf("engine: DATA root selector ordinal is invalid")
	}
	return b.rootTargets[int(ordinal)-1], committed, demand, nil
}

func (b graphBinding) rootTargetForLeaf(leafID proto.TargetID) (proto.TargetID, bool) {
	if !b.rootTracksLocalDelivery {
		return proto.TargetID{}, false
	}
	targetID, ok := b.rootLeafOwners[leafID]
	return targetID, ok
}

func (b graphBinding) targetName(targetID proto.TargetID) (string, bool) {
	if !b.configured || targetID == (proto.TargetID{}) {
		return "", false
	}
	name, ok := b.names[targetID]
	return name, ok && name != ""
}

func (b graphBinding) containsLeaf(leafID proto.TargetID) bool {
	if !b.configured || leafID == (proto.TargetID{}) {
		return false
	}
	_, ok := b.leaves[leafID]
	return ok
}

func (b graphBinding) containsTarget(targetID proto.TargetID) bool {
	if !b.configured || targetID == (proto.TargetID{}) {
		return false
	}
	_, ok := b.kinds[targetID]
	return ok
}

func (b graphBinding) targetKind(targetID proto.TargetID) (proto.GraphNodeKind, bool) {
	kind, ok := b.kinds[targetID]
	return kind, ok
}

// targetAncestors returns target followed by its parents through the root.
// Graph validation guarantees one parent per non-root node and bounded depth.
func (b graphBinding) targetAncestors(targetID proto.TargetID) ([]proto.TargetID, bool) {
	ancestors, ok := b.ancestors[targetID]
	return ancestors, ok
}

func (b graphBinding) commonTargetAncestor(left, right proto.TargetID) (proto.TargetID, bool) {
	leftAncestors, ok := b.targetAncestors(left)
	if !ok {
		return proto.TargetID{}, false
	}
	rightAncestors, ok := b.targetAncestors(right)
	if !ok {
		return proto.TargetID{}, false
	}
	for _, targetID := range rightAncestors {
		for _, candidate := range leftAncestors {
			if candidate == targetID {
				return targetID, true
			}
		}
	}
	return proto.TargetID{}, false
}

// ConfigureLocalMobilityCapabilities freezes driver-backed session families
// before the local graph and HELLO declaration are built. A sealed capability
// proves implementation presence only; every migration still needs a fresh
// factual candidate and peer-plan agreement for the exact owned claim.
func (e *Engine) ConfigureLocalMobilityCapabilities(capabilities ...leafmobility.Capability) error {
	var supported proto.LeafMobilitySet
	for _, capability := range capabilities {
		operation := capability.Operation()
		if operation == 0 {
			return fmt.Errorf("engine: invalid zero leaf mobility capability")
		}
		wire, err := operation.ProtocolSet()
		if err != nil {
			return err
		}
		supported |= wire
	}
	e.graphMu.Lock()
	defer e.graphMu.Unlock()
	if e.localGraph.configured || e.localNegotiationSet {
		return fmt.Errorf("engine: local mobility support is already frozen")
	}
	if e.localMobilitySupportSet && e.localMobilitySupport != supported {
		return fmt.Errorf("engine: local mobility support is already configured")
	}
	e.localMobilitySupport = supported
	e.localMobilitySupportSet = true
	return nil
}

// ConfigureLocalGraph freezes the graph used by this engine's sender. It must
// run before a sequenced frame is allocated.
func (e *Engine) ConfigureLocalGraph(revision uint64, manifest proto.GraphManifest) error {
	e.sessionEpochMu.Lock()
	defer e.sessionEpochMu.Unlock()
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
	e.graphMu.RLock()
	current := e.localGraph
	e.graphMu.RUnlock()
	if current.configured {
		if current.revision == revision && current.digest == digest {
			return nil
		}
		return fmt.Errorf("engine: local graph is already configured")
	}
	if e.hasPathPublication() {
		return fmt.Errorf("engine: cannot configure local graph after path publication")
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
	binding := newGraphBinding(revision, digest, owned)
	negotiation := proto.NewNegotiation(proto.SessionEpoch(e.FlowID()))
	negotiation.GraphRevision = revision
	negotiation.GraphDigest = digest
	negotiation.MobilitySupported = e.localMobilitySupport
	e.localGraph = binding
	e.localExec = newExecutionRuntime(plan)
	e.localNegotiation = negotiation
	e.localNegotiationSet = true
	e.graphMu.Unlock()
	e.sendProof = proto.InitialAckProof(proto.SessionEpoch(e.FlowID()), senderDirection(e.side), revision, digest)
	e.sendAckProof = e.sendProof
	return nil
}

// AdoptSessionEpoch replaces a client's provisional HELLO identity with the
// final epoch selected by the server. It is deliberately a one-time pre-path
// operation: changing identity after any peer, transport, replay, or payload
// evidence exists would splice two logical sessions together.
func (e *Engine) AdoptSessionEpoch(epoch [16]byte) error {
	if e == nil {
		return fmt.Errorf("engine: nil engine")
	}
	e.sessionEpochMu.Lock()
	defer e.sessionEpochMu.Unlock()
	if e.side != SideClient {
		return fmt.Errorf("engine: only a client may adopt a server session epoch")
	}
	if epoch == ([16]byte{}) {
		return fmt.Errorf("engine: zero server session epoch")
	}
	if e.sessionEpochAdopted {
		if e.flowID == epoch {
			return nil
		}
		return fmt.Errorf("engine: server session epoch is already adopted")
	}
	if epoch == e.flowID {
		return fmt.Errorf("engine: server session epoch was not reassigned")
	}
	if e.closing.Load() {
		return fmt.Errorf("engine: cannot adopt session epoch after close")
	}

	e.pathsMu.RLock()
	pathsPristine := len(e.paths) == 0 && len(e.pendingPaths) == 0 && len(e.stagedPaths) == 0 &&
		len(e.retainedPaths) == 0 && e.nextPathID == 0 && e.nextPathGen == 0
	e.pathsMu.RUnlock()
	if !pathsPristine {
		return fmt.Errorf("engine: cannot adopt session epoch after path publication")
	}
	e.attachMu.Lock()
	attachPristine := len(e.seenAttach) == 0 && len(e.seenAttachFIFO) == 0
	e.attachMu.Unlock()
	if !attachPristine {
		return fmt.Errorf("engine: cannot adopt session epoch after attach evidence")
	}
	e.identityMu.RLock()
	peerIdentitySet := e.peerInstance != (proto.InstanceID{})
	e.identityMu.RUnlock()
	if peerIdentitySet {
		return fmt.Errorf("engine: cannot adopt session epoch after peer identity")
	}

	e.leafTx.oobMu.Lock()
	e.leafTx.mu.Lock()
	leafPristine := e.leafTx.sessionLedger == nil && e.leafTx.outgoing == nil &&
		len(e.leafTx.incoming) == 0 && len(e.leafTx.completed) == 0 &&
		len(e.leafTx.rejected) == 0 && len(e.leafTx.actorTerminal) == 0 &&
		len(e.leafTx.oobSeen) == 0 && e.leafTx.messageSeq.Load() == 0
	e.leafTx.mu.Unlock()
	e.leafTx.oobMu.Unlock()
	if !leafPristine {
		return fmt.Errorf("engine: cannot adopt session epoch after mobility evidence")
	}

	e.sendMu.Lock()
	defer e.sendMu.Unlock()
	e.sendHistMu.Lock()
	defer e.sendHistMu.Unlock()
	e.recvMu.Lock()
	defer e.recvMu.Unlock()
	e.graphMu.Lock()
	defer e.graphMu.Unlock()
	if e.closing.Load() {
		return fmt.Errorf("engine: cannot adopt session epoch after close")
	}
	if atomic.LoadUint64(&e.sendSeq) != 0 || e.sendPublishedNext.Load() != 0 ||
		e.sendAckNext.Load() != 0 || len(e.sendHist.entries) != 0 {
		return fmt.Errorf("engine: cannot adopt session epoch after send evidence")
	}
	if e.expectedRecvSeq != 0 || e.recvAckSent != 0 || len(e.recvQueue) != 0 ||
		len(e.recvDeliver) != 0 || len(e.recvDeliverFrames) != 0 || e.recvPacketMarks != 0 ||
		len(e.recvFrameProofs) != 0 || e.recvDroppedThrough != 0 || e.recvTerminal {
		return fmt.Errorf("engine: cannot adopt session epoch after receive evidence")
	}
	if !e.localGraph.configured || !e.localNegotiationSet {
		return fmt.Errorf("engine: local graph must be frozen before session epoch adoption")
	}
	if e.peerGraph.configured || e.peerNegotiationSet {
		return fmt.Errorf("engine: cannot adopt session epoch after peer negotiation")
	}

	e.flowID = epoch
	e.localNegotiation.SessionEpoch = proto.SessionEpoch(epoch)
	e.sendProof = proto.InitialAckProof(proto.SessionEpoch(epoch), senderDirection(e.side), e.localGraph.revision, e.localGraph.digest)
	e.sendAckProof = e.sendProof
	e.recvProof = proto.InitialAckProof(proto.SessionEpoch(epoch), peerSenderDirection(e.side), e.peerGraph.revision, e.peerGraph.digest)
	flowSnapshot := epoch
	e.flowIDValue.Store(&flowSnapshot)
	e.sessionEpochAdopted = true
	return nil
}

// ConfigurePeerGraph freezes the graph used by the peer's sender. It must run
// before this engine accepts a sequenced frame.
func (e *Engine) ConfigurePeerGraph(revision uint64, manifest proto.GraphManifest) error {
	e.sessionEpochMu.Lock()
	defer e.sessionEpochMu.Unlock()
	return e.configurePeerGraph(revision, manifest)
}

func (e *Engine) configurePeerGraph(revision uint64, manifest proto.GraphManifest) error {
	if revision == 0 {
		return fmt.Errorf("engine: zero peer graph revision")
	}
	owned, digest, err := ownGraphManifest(manifest)
	if err != nil {
		return fmt.Errorf("engine: invalid peer graph: %w", err)
	}
	e.graphMu.RLock()
	current := e.peerGraph
	e.graphMu.RUnlock()
	if current.configured {
		if current.revision == revision && current.digest == digest {
			return nil
		}
		return fmt.Errorf("engine: peer graph is already configured")
	}
	if e.hasPathPublication() {
		return fmt.Errorf("engine: cannot configure peer graph after path publication")
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
	e.peerGraph = newGraphBinding(revision, digest, owned)
	e.graphMu.Unlock()
	e.recvProof = proto.InitialAckProof(proto.SessionEpoch(e.FlowID()), peerSenderDirection(e.side), revision, digest)
	return nil
}

// LocalNegotiation builds the HELLO/HELLO_ACK declaration for this sender.
func (e *Engine) LocalNegotiation() proto.Negotiation {
	e.graphMu.RLock()
	if e.localNegotiationSet {
		negotiation := e.localNegotiation
		e.graphMu.RUnlock()
		return negotiation
	}
	binding := e.localGraph
	supported := e.localMobilitySupport
	e.graphMu.RUnlock()
	n := proto.NewNegotiation(proto.SessionEpoch(e.FlowID()))
	n.GraphRevision = binding.revision
	n.GraphDigest = binding.digest
	n.MobilitySupported = supported
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

// PeerGraphManifest returns an owned snapshot of the graph used by the peer's
// sender. Callers use it for direction-specific policy decisions; mutating the
// returned manifest cannot alter the engine's negotiated graph binding.
func (e *Engine) PeerGraphManifest() proto.GraphManifest {
	binding := e.peerGraphBinding()
	manifest, _, err := ownGraphManifest(binding.manifest)
	if err != nil {
		return proto.GraphManifest{}
	}
	return manifest
}

// PathTargetBindings returns the immutable logical target identities currently
// bound to one physical path. It is an observation API for direction-aware
// policy controllers; routing remains owned by the recursive executor.
func (e *Engine) PathTargetBindings(pathID uint32) (localTX, peerTX proto.TargetID, ok bool) {
	e.pathsMu.RLock()
	slot := e.paths[pathID]
	if slot != nil {
		localTX, peerTX, ok = slot.localTXTargetID, slot.peerTXTargetID, true
	}
	e.pathsMu.RUnlock()
	return localTX, peerTX, ok
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
	if local.configured != peer.configured {
		return PathBinding{}, fmt.Errorf("engine: both directional graphs must be frozen before path publication")
	}
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
	peer := e.peerGraphBinding()
	if local.configured != peer.configured {
		return fmt.Errorf("engine: both directional graphs must be frozen before path publication")
	}
	if local.configured {
		node, ok := local.manifest.Node(binding.LocalTXTargetID)
		if !ok || node.Kind != proto.GraphNodeKindPath {
			return fmt.Errorf("engine: local TX target is not a path in the bound graph")
		}
	} else if binding.LocalTXTargetID != (proto.TargetID{}) {
		return fmt.Errorf("engine: local TX target supplied without a local graph")
	}
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

func (e *Engine) hasPathPublication() bool {
	e.pathsMu.RLock()
	published := len(e.paths) != 0 || len(e.pendingPaths) != 0 || len(e.stagedPaths) != 0 ||
		len(e.retainedPaths) != 0 || e.nextPathID != 0 || e.nextPathGen != 0
	e.pathsMu.RUnlock()
	return published
}

// AcceptPeerNegotiation validates the peer's directional declaration and
// freezes it before any path reader can publish sequenced frames.
func (e *Engine) AcceptPeerNegotiation(peer proto.Negotiation, manifest proto.GraphManifest) error {
	e.sessionEpochMu.Lock()
	defer e.sessionEpochMu.Unlock()
	if err := e.validatePeerNegotiation(peer, manifest); err != nil {
		return err
	}
	if err := e.configurePeerGraph(peer.GraphRevision, manifest); err != nil {
		return err
	}
	e.graphMu.Lock()
	if e.peerNegotiationSet && e.peerNegotiation != peer {
		e.graphMu.Unlock()
		return fmt.Errorf("%w: engine: peer negotiation changed", proto.ErrNegotiationIncompatible)
	}
	e.peerNegotiation = peer
	e.peerNegotiationSet = true
	e.graphMu.Unlock()
	return nil
}

// ValidatePeerNegotiation checks an admission retry without mutating receive
// state. Once HELLO has frozen a peer, retries must be byte-semantically
// identical even after DATA has started flowing.
func (e *Engine) ValidatePeerNegotiation(peer proto.Negotiation, manifest proto.GraphManifest) error {
	e.sessionEpochMu.Lock()
	defer e.sessionEpochMu.Unlock()
	return e.validatePeerNegotiation(peer, manifest)
}

func (e *Engine) validatePeerNegotiation(peer proto.Negotiation, manifest proto.GraphManifest) error {
	local := e.LocalNegotiation()
	if err := validateNegotiationCompatibility(local, peer); err != nil {
		return err
	}
	if peer.SessionEpoch != proto.SessionEpoch(e.FlowID()) {
		return fmt.Errorf("engine: negotiation session epoch mismatch")
	}
	digest, err := manifest.Digest()
	if err != nil {
		return fmt.Errorf("engine: invalid peer graph manifest: %w", err)
	}
	if digest != peer.GraphDigest {
		return fmt.Errorf("engine: peer graph digest mismatch")
	}
	e.graphMu.RLock()
	configured := e.peerGraph.configured
	current := e.peerGraph
	frozen := e.peerNegotiation
	frozenSet := e.peerNegotiationSet
	e.graphMu.RUnlock()
	if configured && (current.revision != peer.GraphRevision || current.digest != digest) {
		return fmt.Errorf("engine: peer graph binding changed")
	}
	if frozenSet && frozen != peer {
		return fmt.Errorf("%w: engine: peer negotiation changed", proto.ErrNegotiationIncompatible)
	}
	return nil
}

func validateNegotiationCompatibility(local, peer proto.Negotiation) error {
	if peer.ProtocolMajor != local.ProtocolMajor {
		return fmt.Errorf("%w: engine: protocol major mismatch: local=%d peer=%d", proto.ErrNegotiationIncompatible, local.ProtocolMajor, peer.ProtocolMajor)
	}
	if peer.ProtocolMinor < local.ProtocolMinor {
		return fmt.Errorf("%w: engine: protocol minor mismatch: local=%d peer=%d", proto.ErrNegotiationIncompatible, local.ProtocolMinor, peer.ProtocolMinor)
	}
	if missing := local.Required &^ peer.Supported; missing != 0 {
		return fmt.Errorf("%w: engine: peer lacks required features 0x%x", proto.ErrNegotiationIncompatible, uint64(missing))
	}
	if missing := peer.Required &^ local.Supported; missing != 0 {
		return fmt.Errorf("%w: engine: local side lacks peer-required features 0x%x", proto.ErrNegotiationIncompatible, uint64(missing))
	}
	if missing := local.MobilityRequired &^ peer.MobilitySupported; missing != 0 {
		return fmt.Errorf("%w: engine: peer lacks required leaf mobility 0x%x", proto.ErrNegotiationIncompatible, uint16(missing))
	}
	if missing := peer.MobilityRequired &^ local.MobilitySupported; missing != 0 {
		return fmt.Errorf("%w: engine: local side lacks peer-required leaf mobility 0x%x", proto.ErrNegotiationIncompatible, uint16(missing))
	}
	return nil
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
