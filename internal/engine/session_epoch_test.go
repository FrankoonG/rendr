package engine

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/FrankoonG/rendr/proto"
)

func TestEngineAdoptSessionEpochRebindsPristineHandshakeEvidence(t *testing.T) {
	proposal := [16]byte{0x11}
	final := [16]byte{0x22}
	e := newSessionEpochTestEngine(t, SideClient, proposal)

	before := e.LocalNegotiation()
	if before.SessionEpoch != proto.SessionEpoch(proposal) {
		t.Fatalf("initial negotiation epoch=%x want=%x", before.SessionEpoch, proposal)
	}
	if err := e.AdoptSessionEpoch(final); err != nil {
		t.Fatal(err)
	}
	if got := e.FlowID(); got != final {
		t.Fatalf("FlowID=%x want=%x", got, final)
	}
	if got := e.LocalNegotiation().SessionEpoch; got != proto.SessionEpoch(final) {
		t.Fatalf("local negotiation epoch=%x want=%x", got, final)
	}
	local := e.localGraphBinding()
	wantSend := proto.InitialAckProof(proto.SessionEpoch(final), proto.SenderDirectionClientToServer, local.revision, local.digest)
	wantRecv := proto.InitialAckProof(proto.SessionEpoch(final), proto.SenderDirectionServerToClient, 1, proto.GraphDigest{})
	if e.sendProof != wantSend || e.sendAckProof != wantSend || e.recvProof != wantRecv {
		t.Fatalf("proofs were not rebound to final epoch: send=%x ack=%x recv=%x", e.sendProof, e.sendAckProof, e.recvProof)
	}
	if err := e.AdoptSessionEpoch(final); err != nil {
		t.Fatalf("exact adoption replay was not idempotent: %v", err)
	}
	if err := e.AdoptSessionEpoch([16]byte{0x23}); err == nil {
		t.Fatal("second distinct final epoch was accepted")
	}
}

func TestEngineAdoptSessionEpochLinearizesWithPeerIdentity(t *testing.T) {
	for iteration := 0; iteration < 256; iteration++ {
		proposal := [16]byte{0x41, byte(iteration), byte(iteration >> 8)}
		final := [16]byte{0x42, byte(iteration), byte(iteration >> 8)}
		e := newSessionEpochTestEngine(t, SideClient, proposal)
		peer := proto.InstanceID{0x51, byte(iteration), byte(iteration >> 8)}
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		var adoptErr, identityErr error
		go func() {
			defer wg.Done()
			<-start
			adoptErr = e.AdoptSessionEpoch(final)
		}()
		go func() {
			defer wg.Done()
			<-start
			identityErr = e.SetPeerInstanceID(peer)
		}()
		close(start)
		wg.Wait()
		if identityErr != nil {
			t.Fatalf("iteration %d identity error: %v", iteration, identityErr)
		}
		wantEpoch := proto.SessionEpoch(proposal)
		if adoptErr == nil {
			wantEpoch = proto.SessionEpoch(final)
		}
		if got := proto.SessionEpoch(e.FlowID()); got != wantEpoch {
			t.Fatalf("iteration %d FlowID=%x want=%x adoptErr=%v", iteration, got, wantEpoch, adoptErr)
		}
		e.leafTx.mu.Lock()
		ledgerEpoch := e.leafTx.sessionEpoch
		e.leafTx.mu.Unlock()
		if ledgerEpoch != wantEpoch {
			t.Fatalf("iteration %d ledger epoch=%x want=%x adoptErr=%v", iteration, ledgerEpoch, wantEpoch, adoptErr)
		}
		_ = e.Close()
	}
}

func TestEngineAdoptSessionEpochRejectsPublishedState(t *testing.T) {
	tests := []struct {
		name   string
		side   Side
		final  [16]byte
		mutate func(*Engine)
	}{
		{name: "zero", side: SideClient, final: [16]byte{}},
		{name: "proposal reused", side: SideClient, final: [16]byte{0x31}},
		{name: "server", side: SideServer, final: [16]byte{0x32}},
		{name: "peer identity", side: SideClient, final: [16]byte{0x32}, mutate: func(e *Engine) {
			if err := e.SetPeerInstanceID(proto.InstanceID{1}); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "path generation", side: SideClient, final: [16]byte{0x32}, mutate: func(e *Engine) {
			e.pathsMu.Lock()
			e.nextPathID = 1
			e.pathsMu.Unlock()
		}},
		{name: "send evidence", side: SideClient, final: [16]byte{0x32}, mutate: func(e *Engine) {
			atomic.StoreUint64(&e.sendSeq, 1)
		}},
		{name: "receive evidence", side: SideClient, final: [16]byte{0x32}, mutate: func(e *Engine) {
			e.recvMu.Lock()
			e.expectedRecvSeq = 1
			e.recvMu.Unlock()
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			proposal := [16]byte{0x31}
			e := newSessionEpochTestEngine(t, test.side, proposal)
			if test.mutate != nil {
				test.mutate(e)
			}
			if err := e.AdoptSessionEpoch(test.final); err == nil {
				t.Fatal("session epoch adoption unexpectedly succeeded")
			}
			if got := e.FlowID(); got != proposal {
				t.Fatalf("failed adoption changed FlowID=%x want=%x", got, proposal)
			}
		})
	}
}

func newSessionEpochTestEngine(t *testing.T, side Side, proposal [16]byte) *Engine {
	t.Helper()
	manifest, _ := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "path"),
		runtimeNode(proto.GraphNodeKindPath, "path"),
	)
	e := New(side, proposal, Limits{}.Clamp())
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		e.pathsMu.Lock()
		e.nextPathID = 0
		e.nextPathGen = 0
		e.pathsMu.Unlock()
		_ = e.Close()
	})
	return e
}
