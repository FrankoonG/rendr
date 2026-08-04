package engine

import (
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

func TestRecursiveSelectorDecisionPriorityMatrix(t *testing.T) {
	now := time.Unix(100, 0)
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	tests := []struct {
		name string
		a    pathEvidenceObservation
		b    pathEvidenceObservation
		want proto.TargetID
	}{
		{
			name: "latency excludes stability and speed outside band",
			a:    selectorObservation(ids["a"], now, 100*time.Millisecond, 0, 100),
			b:    selectorObservation(ids["b"], now, 10*time.Millisecond, 50, 1),
			want: ids["b"],
		},
		{
			name: "stability wins inside latency band",
			a:    selectorObservation(ids["a"], now, 10*time.Millisecond, 50, 100),
			b:    selectorObservation(ids["b"], now, 11*time.Millisecond, 0, 1),
			want: ids["b"],
		},
		{
			name: "speed breaks latency and stability tie",
			a:    selectorObservation(ids["a"], now, 10*time.Millisecond, 0, 1),
			b:    selectorObservation(ids["b"], now, 11*time.Millisecond, 0, 10),
			want: ids["b"],
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime := mustExecutionRuntime(t, manifest)
			if err := runtime.selectChild(ids["root"], ids["a"]); err != nil {
				t.Fatal(err)
			}
			observations := map[proto.TargetID]pathEvidenceObservation{ids["a"]: test.a, ids["b"]: test.b}
			policy := selectorEvidencePolicy{latencyBandRatio: 0.25, latencyBandFloor: time.Millisecond, minimumConfidence: 1}
			_ = runtime.selectorDecisions(proto.SenderDirectionClientToServer, observations, now, policy, 0, 0)
			decisions := runtime.selectorDecisions(proto.SenderDirectionClientToServer, observations, now, policy, 0, 0)
			if len(decisions) != 1 || decisions[0].selectorID != ids["root"] || decisions[0].targetID != test.want {
				t.Fatalf("decisions=%+v want root->%x", decisions, test.want)
			}
		})
	}
}

func TestRecursiveSelectorUnknownAndStaleCannotEvictFreshCurrent(t *testing.T) {
	now := time.Unix(200, 0)
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	for _, test := range []struct {
		name string
		b    pathEvidenceObservation
	}{
		{name: "unknown", b: pathEvidenceObservation{targetID: ids["b"], live: true}},
		{name: "stale", b: selectorObservation(ids["b"], now.Add(-selectorEvidenceFreshFor-time.Second), time.Millisecond, 0, 100)},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime := mustExecutionRuntime(t, manifest)
			if err := runtime.selectChild(ids["root"], ids["a"]); err != nil {
				t.Fatal(err)
			}
			observations := map[proto.TargetID]pathEvidenceObservation{
				ids["a"]: selectorObservation(ids["a"], now, 10*time.Millisecond, 0, 1),
				ids["b"]: test.b,
			}
			policy := selectorEvidencePolicy{latencyBandRatio: 0.25, latencyBandFloor: time.Millisecond, minimumConfidence: 1}
			for i := 0; i < 3; i++ {
				if decisions := runtime.selectorDecisions(proto.SenderDirectionClientToServer, observations, now, policy, 0, 0); len(decisions) != 0 {
					t.Fatalf("untrusted challenger produced decision %+v", decisions)
				}
			}
		})
	}
}

func TestRecursiveSelectorSchedulerChangesActualDataRoute(t *testing.T) {
	now := time.Now()
	manifest, _ := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	limits := Limits{
		SelectorHysteresis:   0.25,
		SelectorLatencyFloor: time.Millisecond,
		SelectorDwell:        10 * time.Millisecond,
		SelectorCooldown:     10 * time.Millisecond,
	}.Clamp()
	client := New(SideClient, NewClientFlowID(), limits)
	t.Cleanup(func() { _ = client.Close() })
	if err := client.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := client.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}

	a, aPeer := newMemoryPathPair()
	b, bPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = aPeer.Close() })
	t.Cleanup(func() { _ = bPeer.Close() })
	a.quality = transport.PathQuality{RTT: 100 * time.Millisecond, At: now}
	b.quality = transport.PathQuality{RTT: 10 * time.Millisecond, At: now}
	aCapture := &captureDispatchPath{PathConn: a}
	bCapture := &captureDispatchPath{PathConn: b}
	aID, err := client.AttachPath(aCapture, transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": "a"}})
	if err != nil {
		t.Fatal(err)
	}
	bID, err := client.AttachPath(bCapture, transport.PathSpec{Transport: "memory", Opts: map[string]string{"name": "b"}})
	if err != nil {
		t.Fatal(err)
	}
	if client.ActivePath() != aID {
		t.Fatalf("initial active path=%d want=%d", client.ActivePath(), aID)
	}
	client.StartSelector(nil, 2*time.Millisecond)
	deadline := time.Now().Add(time.Second)
	for client.ActivePath() != bID && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if client.ActivePath() != bID {
		t.Fatalf("selector did not activate lower-latency path: active=%d want=%d", client.ActivePath(), bID)
	}
	if _, err := client.SendData([]byte("selected")); err != nil {
		t.Fatal(err)
	}
	if got := len(aCapture.dataSequences()); got != 0 {
		t.Fatalf("old selector path received %d DATA frames", got)
	}
	if got := len(bCapture.dataSequences()); got != 1 {
		t.Fatalf("selected path received %d DATA frames, want 1", got)
	}
}

func TestRecursiveSelectorChoosesImmediateBondAggregate(t *testing.T) {
	now := time.Now()
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "aggregate"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindBond, "aggregate", "b", "c"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
		runtimeNode(proto.GraphNodeKindPath, "c"),
	)
	limits := Limits{SelectorHysteresis: 0.25, SelectorLatencyFloor: time.Millisecond, SelectorDwell: 5 * time.Millisecond, SelectorCooldown: 5 * time.Millisecond}.Clamp()
	client := New(SideClient, NewClientFlowID(), limits)
	t.Cleanup(func() { _ = client.Close() })
	if err := client.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := client.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	client.SetPacketMode()
	captures := make(map[string]*captureDispatchPath, 3)
	qualities := map[string]time.Duration{"a": 50 * time.Millisecond, "b": 10 * time.Millisecond, "c": 12 * time.Millisecond}
	for _, name := range []string{"a", "b", "c"} {
		path, peer := newMemoryPathPair()
		t.Cleanup(func() { _ = peer.Close() })
		path.quality = transport.PathQuality{RTT: qualities[name], At: now}
		capture := &captureDispatchPath{PathConn: path}
		captures[name] = capture
		if _, err := client.AttachPath(capture, transport.PathSpec{Transport: "memory", Weight: 1, Opts: map[string]string{"name": name}}); err != nil {
			t.Fatal(err)
		}
	}
	client.StartSelector(nil, time.Millisecond)
	deadline := time.Now().Add(time.Second)
	for {
		desired, _, ok := client.localExecutionRuntime().selectedChild(ids["root"])
		if ok && desired == ids["aggregate"] {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("root selector did not choose bond aggregate; desired=%x", desired)
		}
		time.Sleep(time.Millisecond)
	}
	for i := 0; i < 4; i++ {
		if err := client.SendPacket([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	waitForCapturedFrames(t, captures, map[string]uint64{"a": 0, "b": 2, "c": 2})
}

func selectorObservation(id proto.TargetID, at time.Time, rtt time.Duration, loss uint16, weight uint16) pathEvidenceObservation {
	return pathEvidenceObservation{
		targetID: id,
		quality:  transport.PathQuality{RTT: rtt, At: at, LossPP: loss},
		weight:   weight,
		live:     true,
	}
}
