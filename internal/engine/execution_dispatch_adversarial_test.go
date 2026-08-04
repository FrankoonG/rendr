package engine

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

func TestRecursiveDispatchCrossModeTrafficIsNotFlattened(t *testing.T) {
	tests := []struct {
		name     string
		manifest func(*testing.T) (proto.GraphManifest, map[string]proto.TargetID)
		want     map[string]uint64
	}{
		{
			name: "race invokes one bond child per frame",
			manifest: func(t *testing.T) (proto.GraphManifest, map[string]proto.TargetID) {
				return runtimeGraph(t,
					runtimeNode(proto.GraphNodeKindRace, "root", "direct", "aggregate"),
					runtimeNode(proto.GraphNodeKindPath, "direct"),
					runtimeNode(proto.GraphNodeKindBond, "aggregate", "b", "c"),
					runtimeNode(proto.GraphNodeKindPath, "b"),
					runtimeNode(proto.GraphNodeKindPath, "c"),
				)
			},
			want: map[string]uint64{"direct": 4, "b": 2, "c": 2},
		},
		{
			name: "bond invokes whole race child",
			manifest: func(t *testing.T) (proto.GraphManifest, map[string]proto.TargetID) {
				return runtimeGraph(t,
					runtimeNode(proto.GraphNodeKindBond, "root", "direct", "redundant"),
					runtimeNode(proto.GraphNodeKindPath, "direct"),
					runtimeNode(proto.GraphNodeKindRace, "redundant", "b", "c"),
					runtimeNode(proto.GraphNodeKindPath, "b"),
					runtimeNode(proto.GraphNodeKindPath, "c"),
				)
			},
			want: map[string]uint64{"direct": 2, "b": 2, "c": 2},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest, _ := test.manifest(t)
			client, server, captures := newRecursiveEnginePair(t, manifest, "direct", "b", "c")
			client.SetPacketMode()
			server.SetPacketMode()
			for i := 0; i < 4; i++ {
				payload := []byte{byte(i + 1)}
				if err := client.SendPacket(payload); err != nil {
					t.Fatalf("SendPacket(%d): %v", i, err)
				}
				got, err := server.RecvPacket()
				if err != nil || !bytes.Equal(got, payload) {
					t.Fatalf("RecvPacket(%d)=(%x,%v), want %x", i, got, err, payload)
				}
			}
			waitForCapturedFrames(t, captures, test.want)
		})
	}
}

func TestRaceSlowChildCannotBlockFastChild(t *testing.T) {
	manifest, _ := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindRace, "root", "slow", "fast"),
		runtimeNode(proto.GraphNodeKindPath, "slow"),
		runtimeNode(proto.GraphNodeKindPath, "fast"),
	)
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{}.Clamp())
	server := New(SideServer, flow, Limits{}.Clamp())
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	configureRecursivePair(t, client, server, manifest)

	slowClient, slowServer := newMemoryPathPair()
	block := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(block) }) }
	t.Cleanup(release)
	blocked := &blockedDispatchPath{PathConn: slowClient, block: block}
	attachRecursivePath(t, client, server, "slow", blocked, slowServer)
	fastClient, fastServer := newMemoryPathPair()
	attachRecursivePath(t, client, server, "fast", fastClient, fastServer)

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := client.SendData([]byte("latency"))
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("SendData: %v", err)
		}
		if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
			t.Fatalf("fast race child was delayed by slow sibling: %v", elapsed)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("slow race child caused head-of-line blocking")
	}
	buf := make([]byte, 16)
	n, err := server.Recv(buf)
	if err != nil || string(buf[:n]) != "latency" {
		t.Fatalf("server Recv=(%q,%v)", buf[:n], err)
	}
	release()
}

func TestRaceBlockedAndFailedChildrenRespectMigrationBudget(t *testing.T) {
	manifest, _ := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindRace, "root", "blocked", "failed"),
		runtimeNode(proto.GraphNodeKindPath, "blocked"),
		runtimeNode(proto.GraphNodeKindPath, "failed"),
	)
	limits := Limits{MigrationBudget: 40 * time.Millisecond}.Clamp()
	client := New(SideClient, NewClientFlowID(), limits)
	t.Cleanup(func() { _ = client.Close() })
	if err := client.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := client.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}

	blockedBase, blockedPeer := newMemoryPathPair()
	defer blockedPeer.Close()
	block := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(block) }) }
	t.Cleanup(release)
	blocked := &blockedDispatchPath{PathConn: blockedBase, block: block}
	failedBase, failedPeer := newMemoryPathPair()
	defer failedPeer.Close()
	failed := &failedDispatchPath{PathConn: failedBase}
	blockedSpec := transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": "blocked"}}
	failedSpec := transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": "failed"}}
	if _, err := client.AttachPath(blocked, blockedSpec); err != nil {
		t.Fatal(err)
	}
	if _, err := client.AttachPath(failed, failedSpec); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	_, err := client.SendData([]byte("budget"))
	elapsed := time.Since(start)
	release()
	if err != ErrMigrationBudgetExceeded {
		t.Fatalf("SendData error=%v want %v", err, ErrMigrationBudgetExceeded)
	}
	if elapsed < limits.MigrationBudget || elapsed > 500*time.Millisecond {
		t.Fatalf("migration budget elapsed=%v want [%v,500ms]", elapsed, limits.MigrationBudget)
	}
}

func TestRecursivePolicySelectionIsOneSequencedBoundary(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	client := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	t.Cleanup(func() { _ = client.Close() })
	if err := client.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := client.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	captures := make(map[string]*captureDispatchPath, 2)
	for _, name := range []string{"a", "b"} {
		path, peer := newMemoryPathPair()
		t.Cleanup(func() { _ = peer.Close() })
		capture := &captureDispatchPath{PathConn: path}
		captures[name] = capture
		spec := transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": name}}
		if _, err := client.AttachPath(capture, spec); err != nil {
			t.Fatal(err)
		}
	}

	writesDone := make(chan error, 1)
	go func() {
		for i := 0; i < 20; i++ {
			if _, err := client.SendData([]byte{byte(i)}); err != nil {
				writesDone <- err
				return
			}
		}
		writesDone <- nil
	}()
	deadline := time.Now().Add(time.Second)
	for len(captures["a"].dataSequences()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if err := client.SelectLocalTarget(ids["root"], ids["b"], "linearization-test"); err != nil {
		t.Fatal(err)
	}
	if err := <-writesDone; err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		if _, err := client.SendData([]byte{byte(i + 20)}); err != nil {
			t.Fatal(err)
		}
	}
	aSeqs := captures["a"].dataSequences()
	bSeqs := captures["b"].dataSequences()
	if len(aSeqs)+len(bSeqs) != 30 || len(aSeqs) == 0 || len(bSeqs) == 0 {
		t.Fatalf("selector route counts a=%v b=%v", aSeqs, bSeqs)
	}
	if aSeqs[len(aSeqs)-1] >= bSeqs[0] {
		t.Fatalf("policy boundary interleaved old and new routes: a=%v b=%v", aSeqs, bSeqs)
	}
}

type blockedDispatchPath struct {
	transport.PathConn
	block <-chan struct{}
}

type failedDispatchPath struct{ transport.PathConn }

func (p *failedDispatchPath) Write([]byte) (int, error) { return 0, net.ErrClosed }

func (p *blockedDispatchPath) Write(frame []byte) (int, error) {
	select {
	case <-p.block:
		return p.PathConn.Write(frame)
	case <-time.After(5 * time.Second):
		return 0, net.ErrClosed
	}
}

func newRecursiveEnginePair(t *testing.T, manifest proto.GraphManifest, names ...string) (*Engine, *Engine, map[string]*captureDispatchPath) {
	t.Helper()
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{}.Clamp())
	server := New(SideServer, flow, Limits{}.Clamp())
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	configureRecursivePair(t, client, server, manifest)
	captures := make(map[string]*captureDispatchPath, len(names))
	for _, name := range names {
		clientPath, serverPath := newMemoryPathPair()
		capture := &captureDispatchPath{PathConn: clientPath}
		captures[name] = capture
		attachRecursivePath(t, client, server, name, capture, serverPath)
	}
	return client, server, captures
}

func configureRecursivePair(t *testing.T, client, server *Engine, manifest proto.GraphManifest) {
	t.Helper()
	for _, engine := range []*Engine{client, server} {
		if err := engine.ConfigureLocalGraph(1, manifest); err != nil {
			t.Fatal(err)
		}
		if err := engine.ConfigurePeerGraph(1, manifest); err != nil {
			t.Fatal(err)
		}
	}
}

func attachRecursivePath(t *testing.T, client, server *Engine, name string, clientPath, serverPath transport.PathConn) {
	t.Helper()
	spec := transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": name}}
	if _, err := client.AttachPath(clientPath, spec); err != nil {
		t.Fatalf("attach client %s: %v", name, err)
	}
	if _, err := server.AttachPath(serverPath, spec); err != nil {
		t.Fatalf("attach server %s: %v", name, err)
	}
}

type captureDispatchPath struct {
	transport.PathConn
	mu   sync.Mutex
	seqs []uint64
}

func (p *captureDispatchPath) Write(frame []byte) (int, error) {
	n, err := p.PathConn.Write(frame)
	if err == nil && n == len(frame) && len(frame) >= proto.HeaderSize {
		header, decodeErr := proto.DecodeHeader(frame[:proto.HeaderSize])
		if decodeErr == nil && header.Type == proto.FrameData {
			p.mu.Lock()
			p.seqs = append(p.seqs, header.Seq)
			p.mu.Unlock()
		}
	}
	return n, err
}

func (p *captureDispatchPath) dataSequences() []uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]uint64(nil), p.seqs...)
}

func waitForCapturedFrames(t *testing.T, captures map[string]*captureDispatchPath, want map[string]uint64) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		got := make(map[string]uint64, len(captures))
		for name, capture := range captures {
			got[name] = uint64(len(capture.dataSequences()))
		}
		if reflectDispatchCounts(got, want) {
			for name, capture := range captures {
				seqs := capture.dataSequences()
				for i := 1; i < len(seqs); i++ {
					if seqs[i] <= seqs[i-1] {
						t.Fatalf("path %s DATA sequences are not strictly increasing: %v", name, seqs)
					}
				}
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("dispatch counts=%v want=%v", got, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func reflectDispatchCounts(got, want map[string]uint64) bool {
	for name, count := range want {
		if got[name] != count {
			return false
		}
	}
	return true
}
