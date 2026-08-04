package engine

import (
	"testing"

	"github.com/FrankoonG/rendr/proto"
)

func adversarialGraphManifest(rootName string, rootKind proto.GraphNodeKind, leafNames ...string) (proto.GraphManifest, []proto.TargetID) {
	leaves := make([]proto.GraphNode, len(leafNames))
	leafIDs := make([]proto.TargetID, len(leafNames))
	for i, name := range leafNames {
		leaves[i] = proto.GraphNode{
			ID:   proto.DeriveTargetID(proto.GraphNodeKindPath, name),
			Kind: proto.GraphNodeKindPath,
			Name: name,
		}
		leafIDs[i] = leaves[i].ID
	}
	root := proto.GraphNode{
		ID:       proto.DeriveTargetID(rootKind, rootName),
		Kind:     rootKind,
		Name:     rootName,
		Children: append([]proto.TargetID(nil), leafIDs...),
	}
	nodes := make([]proto.GraphNode, 0, len(leaves)+1)
	nodes = append(nodes, root)
	nodes = append(nodes, leaves...)
	return proto.GraphManifest{RootID: root.ID, Nodes: nodes}, leafIDs
}

func adversarialGraphDigest(t *testing.T, manifest proto.GraphManifest) proto.GraphDigest {
	t.Helper()
	digest, err := manifest.Digest()
	if err != nil {
		t.Fatalf("digest graph: %v", err)
	}
	return digest
}

func newGraphBindingEngine(t *testing.T, peerManifest proto.GraphManifest, peerRevision uint64) (*Engine, proto.InstanceID, proto.InstanceID) {
	t.Helper()
	flow := [16]byte{0x90, byte(peerRevision)}
	e := New(SideServer, flow, Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	localInstance := proto.InstanceID{0x10, byte(peerRevision)}
	peerInstance := proto.InstanceID{0x20, byte(peerRevision)}
	e.SetLocalInstanceID(localInstance)
	e.SetPeerInstanceID(peerInstance)
	if err := e.ConfigurePeerGraph(peerRevision, peerManifest); err != nil {
		t.Fatalf("ConfigurePeerGraph: %v", err)
	}
	return e, localInstance, peerInstance
}

func adversarialBridgeTag(t *testing.T, e *Engine, manifest proto.GraphManifest, revision uint64, targetID proto.TargetID, attachByte byte) proto.BridgeTagPayload {
	t.Helper()
	return proto.BridgeTagPayload{
		BridgeID:               e.FlowID(),
		InstanceID:             e.PeerInstanceID(),
		ExpectedPeerInstanceID: e.LocalInstanceID(),
		SessionEpoch:           proto.SessionEpoch(e.FlowID()),
		GraphRevision:          revision,
		GraphDigest:            adversarialGraphDigest(t, manifest),
		Direction:              peerSenderDirection(e.side),
		TargetID:               targetID,
		AttachID:               [16]byte{attachByte},
	}
}

func TestDirectionalGraphBindingsRemainAsymmetric(t *testing.T) {
	flow := [16]byte{0x31}
	e := New(SideClient, flow, Limits{}.Clamp())
	defer e.Close()
	local, _ := adversarialGraphManifest("client-selector", proto.GraphNodeKindSelector, "client-a", "client-b")
	peer, _ := adversarialGraphManifest("server-race", proto.GraphNodeKindRace, "server-a", "server-b")
	if err := e.ConfigureLocalGraph(7, local); err != nil {
		t.Fatalf("ConfigureLocalGraph: %v", err)
	}
	if err := e.ConfigurePeerGraph(13, peer); err != nil {
		t.Fatalf("ConfigurePeerGraph: %v", err)
	}

	localDigest := adversarialGraphDigest(t, local)
	peerDigest := adversarialGraphDigest(t, peer)
	if localDigest == peerDigest {
		t.Fatal("test setup produced identical directional graph digests")
	}
	localNegotiation := e.LocalNegotiation()
	if localNegotiation.GraphRevision != 7 || localNegotiation.GraphDigest != localDigest {
		t.Fatalf("local binding = (%d,%x), want (7,%x)", localNegotiation.GraphRevision, localNegotiation.GraphDigest, localDigest)
	}
	peerBinding := e.peerGraphBinding()
	if peerBinding.revision != 13 || peerBinding.digest != peerDigest {
		t.Fatalf("peer binding = (%d,%x), want (13,%x)", peerBinding.revision, peerBinding.digest, peerDigest)
	}
	if localNegotiation.GraphDigest == peerBinding.digest {
		t.Fatal("engine mirrored one direction's graph into the other")
	}
}

func TestConfigureLocalAndPeerGraphsAreImmutable(t *testing.T) {
	base, _ := adversarialGraphManifest("base-root", proto.GraphNodeKindSelector, "base-a", "base-b")
	different, _ := adversarialGraphManifest("different-root", proto.GraphNodeKindBond, "different-a", "different-b")

	tests := []struct {
		name      string
		configure func(*Engine, uint64, proto.GraphManifest) error
	}{
		{name: "local", configure: func(e *Engine, revision uint64, manifest proto.GraphManifest) error {
			return e.ConfigureLocalGraph(revision, manifest)
		}},
		{name: "peer", configure: func(e *Engine, revision uint64, manifest proto.GraphManifest) error {
			return e.ConfigurePeerGraph(revision, manifest)
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := New(SideClient, [16]byte{0x40}, Limits{}.Clamp())
			defer e.Close()
			if err := tc.configure(e, 5, base); err != nil {
				t.Fatalf("initial configuration: %v", err)
			}
			if err := tc.configure(e, 5, base); err != nil {
				t.Fatalf("identical idempotent configuration: %v", err)
			}
			if err := tc.configure(e, 6, base); err == nil {
				t.Fatal("accepted a different graph revision after configuration was frozen")
			}
			if err := tc.configure(e, 5, different); err == nil {
				t.Fatal("accepted a different graph manifest after configuration was frozen")
			}
		})
	}
}

func TestPerformClientHelloAckRequiresAcceptedPeerBindingEcho(t *testing.T) {
	clientManifest, clientLeaves := adversarialGraphManifest("client-root", proto.GraphNodeKindSelector, "client-a", "client-b")
	serverManifest, serverLeaves := adversarialGraphManifest("server-root", proto.GraphNodeKindRace, "server-a", "server-b")
	serverDigest := adversarialGraphDigest(t, serverManifest)

	tests := []struct {
		name       string
		mutateEcho func(*proto.GraphBinding)
		wantErr    bool
	}{
		{name: "exact echo"},
		{name: "wrong revision", wantErr: true, mutateEcho: func(binding *proto.GraphBinding) { binding.Revision++ }},
		{name: "wrong digest", wantErr: true, mutateEcho: func(binding *proto.GraphBinding) { binding.Digest[0] ^= 0xff }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			flow := [16]byte{0x50}
			client := New(SideClient, flow, Limits{}.Clamp())
			defer client.Close()
			clientInstance := proto.InstanceID{0x51}
			serverInstance := proto.InstanceID{0x52}
			client.SetLocalInstanceID(clientInstance)
			if err := client.ConfigureLocalGraph(17, clientManifest); err != nil {
				t.Fatal(err)
			}

			clientPath, serverPath := newMemoryPathPair()
			defer clientPath.Close()
			defer serverPath.Close()
			serverResult := make(chan error, 1)
			go func() {
				header, payload, err := ReadFirstFrame(serverPath)
				if err != nil {
					serverResult <- err
					return
				}
				if header.Type != proto.FrameCtrl || proto.CtrlCodeFromFlags(header.Flags) != proto.CtrlHello {
					serverResult <- errUnexpectedHandshakeFrame(header)
					return
				}
				hello, err := proto.DecodeHello(payload)
				if err != nil {
					serverResult <- err
					return
				}
				echo := proto.GraphBinding{Revision: hello.GraphRevision, Digest: hello.GraphDigest}
				if tc.mutateEcho != nil {
					tc.mutateEcho(&echo)
				}
				serverNegotiation := proto.NewNegotiation(proto.SessionEpoch(flow))
				serverNegotiation.GraphRevision = 23
				serverNegotiation.GraphDigest = serverDigest
				ack := proto.HelloAckPayload{
					Negotiation:         serverNegotiation,
					FlowID:              flow,
					InstanceID:          serverInstance,
					LocalTXManifest:     serverManifest,
					InitialTargetID:     serverLeaves[0],
					AcceptedPeerBinding: echo,
				}
				ackWire, err := ack.Encode()
				if err != nil {
					serverResult <- err
					return
				}
				serverResult <- writeCtrl(serverPath, proto.CtrlHelloAck, 0, ackWire, 0)
			}()

			ack, err := PerformClientHelloAck(clientPath, client, clientInstance, 0, "client-a")
			if serverErr := <-serverResult; serverErr != nil {
				t.Fatalf("server handshake: %v", serverErr)
			}
			if tc.wantErr {
				if err == nil {
					t.Fatal("accepted HELLO_ACK that did not echo the offered local-TX binding")
				}
				return
			}
			if err != nil {
				t.Fatalf("PerformClientHelloAck: %v", err)
			}
			if ack.GraphDigest != serverDigest || ack.GraphDigest == adversarialGraphDigest(t, clientManifest) {
				t.Fatal("valid asymmetric server local-TX graph was not accepted independently")
			}
			if ack.InitialTargetID != serverLeaves[0] || clientLeaves[0] == serverLeaves[0] {
				t.Fatal("handshake did not preserve the server's independent initial target")
			}
		})
	}
}

func TestValidateBridgeBindingRejectsForeignAndNonPathTargets(t *testing.T) {
	manifest, leaves := adversarialGraphManifest("peer-root", proto.GraphNodeKindSelector, "peer-a", "peer-b")
	revision := uint64(29)

	tests := []struct {
		name     string
		targetID proto.TargetID
	}{
		{name: "foreign path", targetID: proto.DeriveTargetID(proto.GraphNodeKindPath, "foreign")},
		{name: "group target", targetID: manifest.RootID},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, _, _ := newGraphBindingEngine(t, manifest, revision)
			tag := adversarialBridgeTag(t, e, manifest, revision, tc.targetID, 1)
			if err := e.ValidateBridgeBinding(tag); err == nil {
				t.Fatal("accepted BRIDGE target that is not a path leaf in the negotiated peer graph")
			}
		})
	}

	e, _, _ := newGraphBindingEngine(t, manifest, revision)
	valid := adversarialBridgeTag(t, e, manifest, revision, leaves[0], 2)
	if err := e.ValidateBridgeBinding(valid); err != nil {
		t.Fatalf("rejected valid graph path: %v", err)
	}
}

func TestValidateBridgeBindingRejectsWrongInstances(t *testing.T) {
	manifest, leaves := adversarialGraphManifest("peer-root", proto.GraphNodeKindSelector, "peer-a")
	revision := uint64(31)
	tests := []struct {
		name   string
		mutate func(*proto.BridgeTagPayload)
	}{
		{name: "zero sender", mutate: func(tag *proto.BridgeTagPayload) { tag.InstanceID = proto.InstanceID{} }},
		{name: "foreign sender", mutate: func(tag *proto.BridgeTagPayload) { tag.InstanceID = proto.InstanceID{0xff} }},
		{name: "zero receiver", mutate: func(tag *proto.BridgeTagPayload) { tag.ExpectedPeerInstanceID = proto.InstanceID{} }},
		{name: "foreign receiver", mutate: func(tag *proto.BridgeTagPayload) { tag.ExpectedPeerInstanceID = proto.InstanceID{0xee} }},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, _, _ := newGraphBindingEngine(t, manifest, revision)
			tag := adversarialBridgeTag(t, e, manifest, revision, leaves[0], byte(i+1))
			tc.mutate(&tag)
			if err := e.ValidateBridgeBinding(tag); err == nil {
				t.Fatal("accepted BRIDGE with wrong runtime instance identity")
			}
		})
	}
}

func TestValidateBridgeBindingRejectsDuplicateAttachID(t *testing.T) {
	manifest, leaves := adversarialGraphManifest("peer-root", proto.GraphNodeKindSelector, "peer-a", "peer-b")
	revision := uint64(37)
	e, _, _ := newGraphBindingEngine(t, manifest, revision)
	first := adversarialBridgeTag(t, e, manifest, revision, leaves[0], 0x77)
	if err := e.ValidateBridgeBinding(first); err != nil {
		t.Fatalf("first attach: %v", err)
	}
	if err := e.ValidateBridgeBinding(first); err == nil {
		t.Fatal("accepted a byte-identical replay of an attach token")
	}
	secondTargetSameToken := adversarialBridgeTag(t, e, manifest, revision, leaves[1], 0x77)
	if err := e.ValidateBridgeBinding(secondTargetSameToken); err == nil {
		t.Fatal("accepted an attach token replayed for another target")
	}
	unique := adversarialBridgeTag(t, e, manifest, revision, leaves[1], 0x78)
	if err := e.ValidateBridgeBinding(unique); err != nil {
		t.Fatalf("rejected unique attach token: %v", err)
	}
}

func TestValidateBridgeBindingRejectsStaleGraphBinding(t *testing.T) {
	manifest, leaves := adversarialGraphManifest("peer-root", proto.GraphNodeKindSelector, "peer-a")
	revision := uint64(41)
	tests := []struct {
		name   string
		mutate func(*proto.BridgeTagPayload)
	}{
		{name: "stale revision", mutate: func(tag *proto.BridgeTagPayload) { tag.GraphRevision-- }},
		{name: "foreign digest", mutate: func(tag *proto.BridgeTagPayload) { tag.GraphDigest[0] ^= 0xff }},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, _, _ := newGraphBindingEngine(t, manifest, revision)
			tag := adversarialBridgeTag(t, e, manifest, revision, leaves[0], byte(i+1))
			tc.mutate(&tag)
			if err := e.ValidateBridgeBinding(tag); err == nil {
				t.Fatal("accepted stale or invalid BRIDGE binding")
			}
		})
	}
}

func errUnexpectedHandshakeFrame(header proto.Header) error {
	return &unexpectedHandshakeFrameError{header: header}
}

type unexpectedHandshakeFrameError struct {
	header proto.Header
}

func (e *unexpectedHandshakeFrameError) Error() string {
	return "unexpected handshake frame"
}
