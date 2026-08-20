package engine

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type policySelectorGenerationForge struct {
	rewrite               func(proto.PolicyAck) proto.PolicyAck
	prepareGeneration     atomic.Uint64
	forgedFinalGeneration atomic.Uint64
	forgedFinalCount      atomic.Uint32
}

type policySelectorGenerationForgePath struct {
	inner transport.PathConn
	forge *policySelectorGenerationForge
}

func (p *policySelectorGenerationForgePath) Read(b []byte) (int, error) {
	return p.inner.Read(b)
}

func (p *policySelectorGenerationForgePath) Write(frame []byte) (int, error) {
	if len(frame) < proto.HeaderSize {
		return p.inner.Write(frame)
	}
	header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	if err != nil || header.Type != proto.FrameCtrl ||
		proto.CtrlCodeFromFlags(header.Flags) != proto.CtrlPolicyAck {
		return p.inner.Write(frame)
	}
	ack, err := proto.DecodePolicyAck(frame[proto.HeaderSize:])
	if err != nil {
		return p.inner.Write(frame)
	}
	ack = p.forge.rewrite(ack)
	if ack.Phase == proto.PolicyAckPhasePrepare {
		p.forge.prepareGeneration.Store(ack.SelectorGeneration)
	}
	if ack.Phase == proto.PolicyAckPhaseFinal {
		p.forge.forgedFinalGeneration.Store(ack.SelectorGeneration)
		p.forge.forgedFinalCount.Add(1)
	}
	payload, err := ack.Encode()
	if err != nil {
		return 0, err
	}
	if len(payload) != len(frame)-proto.HeaderSize {
		return 0, fmt.Errorf("forged policy ACK changed payload size")
	}
	rewritten := append([]byte(nil), frame...)
	copy(rewritten[proto.HeaderSize:], payload)
	return p.inner.Write(rewritten)
}

func (p *policySelectorGenerationForgePath) Close() error {
	return p.inner.Close()
}

func (p *policySelectorGenerationForgePath) Quality() transport.PathQuality {
	return p.inner.Quality()
}

func (p *policySelectorGenerationForgePath) OnDeath(fn func(transport.DeathCause, error)) {
	p.inner.OnDeath(fn)
}

func (p *policySelectorGenerationForgePath) LocalAddr() string {
	return p.inner.LocalAddr()
}

func (p *policySelectorGenerationForgePath) RemoteAddr() string {
	return p.inner.RemoteAddr()
}

func TestPolicyRequesterRejectsForgedFinalSelectorGeneration(t *testing.T) {
	const maxUint64 = ^uint64(0)
	tests := []struct {
		name             string
		sameTarget       bool
		prepareMaxUint64 bool
		finalMaxUint64   bool
		finalOffset      uint64
	}{
		{
			name: "equal-on-change",
		},
		{
			name:        "+2-on-change",
			finalOffset: 2,
		},
		{
			name:        "same-target+1",
			sameTarget:  true,
			finalOffset: 1,
		},
		{
			name:             "max-uint64-overflow",
			prepareMaxUint64: true,
			finalMaxUint64:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var forge *policySelectorGenerationForge
			forge = &policySelectorGenerationForge{
				rewrite: func(ack proto.PolicyAck) proto.PolicyAck {
					switch ack.Phase {
					case proto.PolicyAckPhasePrepare:
						if test.prepareMaxUint64 {
							ack.SelectorGeneration = maxUint64
						}
					case proto.PolicyAckPhaseFinal:
						if test.finalMaxUint64 {
							ack.SelectorGeneration = maxUint64
						} else {
							ack.SelectorGeneration = forge.prepareGeneration.Load() + test.finalOffset
						}
					}
					return ack
				},
			}
			client, _, selectorID, targetA, targetB :=
				newPolicySelectorGenerationForgePair(t, forge)
			targetID := targetB
			if test.sameTarget {
				targetID = targetA
			}

			var callbacks atomic.Uint32
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			err := client.requestPeerSelection(
				ctx,
				proto.PolicyActionSelectChild,
				selectorID,
				targetID,
				"forged-selector-generation",
				func(proto.TargetID, uint64, uint64) {
					callbacks.Add(1)
				},
			)
			if !errors.Is(err, ErrPeerProtocol) {
				t.Fatalf("request error=%v want ErrPeerProtocol", err)
			}
			if got := forge.forgedFinalCount.Load(); got == 0 {
				t.Fatal("forged FINAL stimulus did not occur")
			}
			prepareGeneration := forge.prepareGeneration.Load()
			wantFinalGeneration := prepareGeneration + test.finalOffset
			if test.finalMaxUint64 {
				wantFinalGeneration = maxUint64
			}
			if test.prepareMaxUint64 && prepareGeneration != maxUint64 {
				t.Fatalf("forged PREPARE selector generation=%d want MaxUint64", prepareGeneration)
			}
			if got := forge.forgedFinalGeneration.Load(); got != wantFinalGeneration {
				t.Fatalf("forged FINAL selector generation=%d want=%d", got, wantFinalGeneration)
			}
			if got := callbacks.Load(); got != 0 {
				t.Fatalf("committed callback count=%d want=0", got)
			}
			published := client.sendPublishedNext.Load()
			if _, sendErr := client.SendData([]byte("must-not-publish-after-policy-protocol-error")); sendErr == nil {
				t.Fatal("application DATA published after policy protocol error")
			}
			if got := client.sendPublishedNext.Load(); got != published {
				t.Fatalf("published frontier advanced after policy protocol error: before=%d after=%d", published, got)
			}
		})
	}
}

func TestPolicyRequesterRejectsForgedPrepareCurrentTarget(t *testing.T) {
	outsideGraph := proto.DeriveTargetID(proto.GraphNodeKindPath, "outside-policy-generation-graph")
	forge := &policySelectorGenerationForge{
		rewrite: func(ack proto.PolicyAck) proto.PolicyAck {
			if ack.Phase == proto.PolicyAckPhasePrepare {
				ack.CurrentTargetID = outsideGraph
			}
			return ack
		},
	}
	client, _, selectorID, _, targetB := newPolicySelectorGenerationForgePair(t, forge)
	var callbacks atomic.Uint32
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := client.requestPeerSelection(
		ctx,
		proto.PolicyActionSelectChild,
		selectorID,
		targetB,
		"forged-prepare-current-target",
		func(proto.TargetID, uint64, uint64) { callbacks.Add(1) },
	)
	if !errors.Is(err, ErrPeerProtocol) {
		t.Fatalf("request error=%v want ErrPeerProtocol", err)
	}
	if got := forge.forgedFinalCount.Load(); got != 0 {
		t.Fatalf("forged PREPARE advanced to FINAL count=%d", got)
	}
	if got := callbacks.Load(); got != 0 {
		t.Fatalf("committed callback count=%d want=0", got)
	}
	published := client.sendPublishedNext.Load()
	if _, sendErr := client.SendData([]byte("must-not-publish-after-forged-prepare")); sendErr == nil {
		t.Fatal("application DATA published after forged PREPARE")
	}
	if got := client.sendPublishedNext.Load(); got != published {
		t.Fatalf("published frontier advanced after forged PREPARE: before=%d after=%d", published, got)
	}
}

func TestPolicyPrepareCurrentTargetBindsObservedDeliveryGeneration(t *testing.T) {
	selectorID := proto.DeriveTargetID(proto.GraphNodeKindSelector, "observed-policy-selector")
	targetA := proto.DeriveTargetID(proto.GraphNodeKindPath, "observed-policy-a")
	targetB := proto.DeriveTargetID(proto.GraphNodeKindPath, "observed-policy-b")
	ack := proto.PolicyAck{
		SelectorGeneration: 5,
		CurrentTargetID:    targetB,
	}
	snapshot := TargetDeliverySnapshot{
		SelectorID:         selectorID,
		TargetID:           targetA,
		SelectorGeneration: 5,
		EvidenceEpoch:      1,
		Attributable:       true,
	}
	if err := validatePolicyPrepareDeliverySnapshot(selectorID, ack, snapshot); err == nil {
		t.Fatal("accepted PREPARE target contradicting equal-generation DATA evidence")
	}
	ack.SelectorGeneration = 4
	if err := validatePolicyPrepareDeliverySnapshot(selectorID, ack, snapshot); err == nil {
		t.Fatal("accepted PREPARE generation older than DATA evidence")
	}
	ack.SelectorGeneration = 6
	if err := validatePolicyPrepareDeliverySnapshot(selectorID, ack, snapshot); err != nil {
		t.Fatalf("rejected newer PREPARE generation: %v", err)
	}
	snapshot.Attributable = false
	ack.SelectorGeneration = 5
	if err := validatePolicyPrepareDeliverySnapshot(selectorID, ack, snapshot); err != nil {
		t.Fatalf("unattributable DATA constrained PREPARE: %v", err)
	}
}

func newPolicySelectorGenerationForgePair(
	t *testing.T,
	forge *policySelectorGenerationForge,
) (
	client *Engine,
	server *Engine,
	selectorID proto.TargetID,
	targetA proto.TargetID,
	targetB proto.TargetID,
) {
	t.Helper()
	pathA := proto.GraphNode{
		ID:   proto.DeriveTargetID(proto.GraphNodeKindPath, "policy-generation-a"),
		Kind: proto.GraphNodeKindPath,
		Name: "policy-generation-a",
	}
	pathB := proto.GraphNode{
		ID:   proto.DeriveTargetID(proto.GraphNodeKindPath, "policy-generation-b"),
		Kind: proto.GraphNodeKindPath,
		Name: "policy-generation-b",
	}
	selector := proto.GraphNode{
		ID:       proto.DeriveTargetID(proto.GraphNodeKindSelector, "policy-generation-root"),
		Kind:     proto.GraphNodeKindSelector,
		Name:     "policy-generation-root",
		Children: []proto.TargetID{pathA.ID, pathB.ID},
	}
	manifest := proto.GraphManifest{
		RootID: selector.ID,
		Nodes:  []proto.GraphNode{selector, pathA, pathB},
	}
	flow := [16]byte{0x91, 0x13}
	client = New(SideClient, flow, Limits{}.Clamp())
	server = New(SideServer, flow, Limits{}.Clamp())
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	for _, engine := range []*Engine{client, server} {
		if err := engine.ConfigureLocalGraph(1, manifest); err != nil {
			t.Fatal(err)
		}
		if err := engine.ConfigurePeerGraph(1, manifest); err != nil {
			t.Fatal(err)
		}
	}

	for _, path := range []proto.GraphNode{pathA, pathB} {
		clientPath, serverPath := newMemoryPathPair()
		spec := transport.PathSpec{
			Transport: "memory",
			Address:   path.Name,
			Opts:      map[string]string{"name": path.Name},
		}
		binding := PathBinding{LocalTXTargetID: path.ID, PeerTXTargetID: path.ID}
		if _, err := client.AttachPathBound(clientPath, spec, binding); err != nil {
			t.Fatal(err)
		}
		wrapped := &policySelectorGenerationForgePath{inner: serverPath, forge: forge}
		if _, err := server.AttachPathBound(wrapped, spec, binding); err != nil {
			t.Fatal(err)
		}
	}
	return client, server, selector.ID, pathA.ID, pathB.ID
}

var _ transport.PathConn = (*policySelectorGenerationForgePath)(nil)
