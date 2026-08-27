package engine

import (
	"testing"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

func configureLeafSelectorRuntime(t *testing.T, e *Engine, leafNames ...string) map[string]proto.TargetID {
	return configureLeafGroupRuntime(t, e, proto.GraphNodeKindSelector, leafNames...)
}

func configureLeafGroupRuntime(t *testing.T, e *Engine, kind proto.GraphNodeKind, leafNames ...string) map[string]proto.TargetID {
	t.Helper()
	if len(leafNames) == 0 {
		t.Fatal("group fixture requires at least one leaf")
	}
	nodes := make([]proto.GraphNode, 0, len(leafNames)+1)
	nodes = append(nodes, runtimeNode(kind, "root", leafNames...))
	for _, name := range leafNames {
		nodes = append(nodes, runtimeNode(proto.GraphNodeKindPath, name))
	}
	manifest, ids := runtimeGraph(t, nodes...)
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatalf("configure local group graph: %v", err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatalf("configure peer group graph: %v", err)
	}
	return ids
}

func configureSymmetricLeafGroupRuntime(t *testing.T, client, server *Engine, kind proto.GraphNodeKind, leafNames ...string) map[string]proto.TargetID {
	t.Helper()
	ids := configureLeafGroupRuntime(t, client, kind, leafNames...)
	serverIDs := configureLeafGroupRuntime(t, server, kind, leafNames...)
	for name, id := range ids {
		if serverIDs[name] != id {
			t.Fatalf("symmetric target %q differs: client=%x server=%x", name, id, serverIDs[name])
		}
	}
	return ids
}

func attachFixturePath(t *testing.T, e *Engine, pc transport.PathConn, spec transport.PathSpec, targetID proto.TargetID) uint32 {
	t.Helper()
	binding := PathBinding{LocalTXTargetID: targetID, PeerTXTargetID: targetID}
	if e.Packetized() {
		packetPath, ok := pc.(transport.PacketPathConn)
		if !ok {
			t.Fatalf("packet fixture path %q has no capacity contract", spec.Address)
		}
		capacity := packetPath.MaxFrameSize()
		binding.LocalReceiveFrameCapacity = uint32(capacity)
		binding.PeerReceiveFrameCapacity = uint32(capacity)
	}
	id, err := e.AttachPathBound(pc, spec, binding)
	if err != nil {
		t.Fatalf("attach fixture path %q: %v", spec.Address, err)
	}
	return id
}

func graphKindForExecutionFixture(t *testing.T, kind proto.ExecutionKind) proto.GraphNodeKind {
	t.Helper()
	switch kind {
	case proto.ExecutionKindSelector:
		return proto.GraphNodeKindSelector
	case proto.ExecutionKindBond:
		return proto.GraphNodeKindBond
	case proto.ExecutionKindRace:
		return proto.GraphNodeKindRace
	default:
		t.Fatalf("unsupported fixture execution kind %d", kind)
		return proto.GraphNodeKindInvalid
	}
}
