package engine

import (
	"testing"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

func TestRecursiveExplicitMigrateChangesActualDataRoute(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}

	captures := make(map[string]*captureDispatchPath, 2)
	pathIDs := make(map[string]uint32, 2)
	for _, name := range []string{"a", "b"} {
		path, peer := newMemoryPathPair()
		t.Cleanup(func() { _ = peer.Close() })
		capture := &captureDispatchPath{PathConn: path}
		captures[name] = capture
		id, err := e.AttachPathBound(capture, transport.PathSpec{Transport: "memory"}, PathBinding{
			LocalTXTargetID: ids[name],
			PeerTXTargetID:  ids[name],
		})
		if err != nil {
			t.Fatal(err)
		}
		pathIDs[name] = id
	}

	if _, err := e.SendData([]byte("before")); err != nil {
		t.Fatal(err)
	}
	if err := e.Migrate(pathIDs["b"]); err != nil {
		t.Fatal(err)
	}
	if _, err := e.SendData([]byte("after")); err != nil {
		t.Fatal(err)
	}

	for _, seq := range captures["a"].dataSequences() {
		if seq >= 1 {
			t.Fatalf("post-migration DATA remained on a: a=%v b=%v", captures["a"].dataSequences(), captures["b"].dataSequences())
		}
	}
	found := false
	for _, seq := range captures["b"].dataSequences() {
		if seq == 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("post-migration DATA did not reach b: a=%v b=%v", captures["a"].dataSequences(), captures["b"].dataSequences())
	}
}

func TestRecursiveReplayHonorsRootSelectorInsteadOfInactiveNestedScope(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "inner"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindSelector, "inner", "b", "c"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
		runtimeNode(proto.GraphNodeKindPath, "c"),
	)
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}

	captures := make(map[string]*captureDispatchPath, 3)
	for _, name := range []string{"a", "b", "c"} {
		path, peer := newMemoryPathPair()
		t.Cleanup(func() { _ = peer.Close() })
		capture := &captureDispatchPath{PathConn: path}
		captures[name] = capture
		if _, err := e.AttachPathBound(capture, transport.PathSpec{Transport: "memory"}, PathBinding{
			LocalTXTargetID: ids[name],
			PeerTXTargetID:  ids[name],
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.SelectLocalTarget(ids["inner"], ids["c"], "inactive-nested"); err != nil {
		t.Fatal(err)
	}

	frame := executionDataFrame(t, 77, []byte("replay"))
	if err := e.redistributeFrames([][]byte{frame}); err != nil {
		t.Fatal(err)
	}
	if got := captures["a"].dataSequences(); len(got) != 1 || got[0] != 77 {
		t.Fatalf("root-selected replay on a=%v, want [77]", got)
	}
	if got := captures["b"].dataSequences(); len(got) != 0 {
		t.Fatalf("replay leaked to inactive b: %v", got)
	}
	if got := captures["c"].dataSequences(); len(got) != 0 {
		t.Fatalf("replay leaked through inactive nested selection to c: %v", got)
	}
}

func TestInactiveNestedSelectorCannotRewriteRootActivePath(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "inner"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindSelector, "inner", "b", "c"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
		runtimeNode(proto.GraphNodeKindPath, "c"),
	)
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = e.Close() })
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	pathIDs := make(map[string]uint32, 3)
	for _, name := range []string{"a", "b", "c"} {
		path, peer := newMemoryPathPair()
		t.Cleanup(func() { _ = peer.Close() })
		id, err := e.AttachPathBound(path, transport.PathSpec{Transport: "memory"}, PathBinding{
			LocalTXTargetID: ids[name], PeerTXTargetID: ids[name],
		})
		if err != nil {
			t.Fatal(err)
		}
		pathIDs[name] = id
	}
	if got := e.ActivePath(); got != pathIDs["a"] {
		t.Fatalf("initial active=%d, want a=%d", got, pathIDs["a"])
	}
	if err := e.SelectLocalTarget(ids["inner"], ids["c"], "inactive-preselection"); err != nil {
		t.Fatal(err)
	}
	if got := e.ActivePath(); got != pathIDs["a"] {
		t.Fatalf("inactive nested selector rewrote active=%d, want root a=%d", got, pathIDs["a"])
	}
	if err := e.SelectLocalTarget(ids["root"], ids["inner"], "activate-inner"); err != nil {
		t.Fatal(err)
	}
	if got := e.ActivePath(); got != pathIDs["c"] {
		t.Fatalf("activated nested selector active=%d, want preselected c=%d", got, pathIDs["c"])
	}
}

func executionDataFrame(t *testing.T, seq uint64, payload []byte) []byte {
	t.Helper()
	frame := make([]byte, proto.HeaderSize+len(payload))
	if err := (proto.Header{Version: proto.Version, Type: proto.FrameData, Seq: seq}).Encode(frame[:proto.HeaderSize]); err != nil {
		t.Fatal(err)
	}
	copy(frame[proto.HeaderSize:], payload)
	return frame
}
