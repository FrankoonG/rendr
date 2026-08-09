package engine

import (
	"encoding/binary"
	"errors"
	"sync"
	"testing"

	"github.com/FrankoonG/rendr/proto"
)

func TestLeafMobilityPeerLedgerConcurrentTransactionsAdvanceOnce(t *testing.T) {
	ledger := NewLeafMobilityPeerLedger()
	key := testPeerLedgerKey(1)
	transactions := [][16]byte{testPeerLedgerTransaction(1), testPeerLedgerTransaction(2)}
	start := make(chan struct{})
	results := make(chan error, len(transactions))
	var wg sync.WaitGroup
	for _, transactionID := range transactions {
		transactionID := transactionID
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			reservation, err := ledger.installValidated(key, transactionID, 0)
			if err == nil {
				err = ledger.compareAndAdvance(reservation)
			}
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	successes := 0
	for err := range results {
		if err == nil {
			successes++
			continue
		}
		if !errors.Is(err, ErrLeafMobilityPeerTransactionBusy) &&
			!errors.Is(err, ErrLeafMobilityPeerGenerationStale) {
			t.Fatalf("unexpected losing transaction error: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("successful advances=%d want=1", successes)
	}
	if generation, ok := ledger.current(key); !ok || generation != 1 {
		t.Fatalf("generation=(%d,%t) want=(1,true)", generation, ok)
	}
}

func TestLeafMobilityPeerLedgerAdvanceIdempotenceIsTransactionBound(t *testing.T) {
	ledger := NewLeafMobilityPeerLedger()
	key := testPeerLedgerKey(2)
	winner := testPeerLedgerTransaction(3)
	reservation, err := ledger.installValidated(key, winner, 9)
	if err != nil {
		t.Fatal(err)
	}
	forged := reservation
	forged.transactionID = testPeerLedgerTransaction(4)
	if err := ledger.compareAndAdvance(forged); !errors.Is(err, ErrLeafMobilityPeerTransactionBusy) {
		t.Fatalf("forged transaction before advance error=%v want busy", err)
	}
	if err := ledger.compareAndAdvance(reservation); err != nil {
		t.Fatal(err)
	}
	if err := ledger.compareAndAdvance(reservation); err != nil {
		t.Fatalf("same transaction replay: %v", err)
	}
	if err := ledger.compareAndAdvance(forged); !errors.Is(err, ErrLeafMobilityPeerGenerationStale) {
		t.Fatalf("forged transaction at next generation error=%v want stale", err)
	}
	replayed, err := ledger.installValidated(key, winner, 9)
	if !errors.Is(err, ErrLeafMobilityPeerTransactionClosed) || replayed != (leafMobilityPeerGenerationReservation{}) {
		t.Fatalf("same terminal transaction reinstall reservation=%+v error=%v", replayed, err)
	}

	loser := testPeerLedgerTransaction(5)
	if _, err := ledger.installValidated(key, loser, 9); !errors.Is(err, ErrLeafMobilityPeerGenerationStale) {
		t.Fatalf("different transaction old-base error=%v want stale", err)
	}
}

func TestLeafMobilityPeerLedgerPersistsAcrossEnginesInSession(t *testing.T) {
	ledger := NewLeafMobilityPeerLedger()
	key := testPeerLedgerKey(3)
	first := testPeerLedgerTransaction(5)
	reservation, err := ledger.installValidated(key, first, 41)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.compareAndAdvance(reservation); err != nil {
		t.Fatal(err)
	}

	// A replacement Engine/session observes the same Runtime-owned ledger.
	if generation, ok := ledger.current(key); !ok || generation != 42 {
		t.Fatalf("future session generation=(%d,%t) want=(42,true)", generation, ok)
	}
	if _, err := ledger.installValidated(key, testPeerLedgerTransaction(6), 41); !errors.Is(err, ErrLeafMobilityPeerGenerationStale) {
		t.Fatalf("old generation ABA error=%v want stale", err)
	}

	second, err := ledger.installValidated(key, testPeerLedgerTransaction(7), 42)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.compareAndAdvance(second); err != nil {
		t.Fatal(err)
	}
	if generation, ok := ledger.current(key); !ok || generation != 43 {
		t.Fatalf("generation=(%d,%t) want=(43,true)", generation, ok)
	}
}

func TestLeafMobilityPeerLedgerFastForwardsActorConsumedGeneration(t *testing.T) {
	ledger := NewLeafMobilityPeerLedger()
	key := testPeerLedgerKey(31)
	first, err := ledger.installValidated(key, testPeerLedgerTransaction(31), 4)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.release(first); err != nil {
		t.Fatal(err)
	}

	// Generation 6 was consumed locally by a proposal that never reached the
	// peer. A later transaction proves the actor has moved forward; accepting
	// that monotonic base also makes delayed generations 4 and 5 stale.
	next, err := ledger.installValidated(key, testPeerLedgerTransaction(32), 6)
	if err != nil {
		t.Fatalf("fast-forward install: %v", err)
	}
	if generation, ok := ledger.current(key); !ok || generation != 6 {
		t.Fatalf("fast-forward generation=(%d,%t) want=(6,true)", generation, ok)
	}
	if _, err := ledger.installValidated(key, testPeerLedgerTransaction(33), 5); !errors.Is(err, ErrLeafMobilityPeerTransactionBusy) {
		t.Fatalf("old generation while fast-forward transaction active error=%v want busy", err)
	}
	if err := ledger.release(next); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.installValidated(key, testPeerLedgerTransaction(34), 5); !errors.Is(err, ErrLeafMobilityPeerGenerationStale) {
		t.Fatalf("delayed old generation error=%v want stale", err)
	}
}

func TestLeafMobilityPeerLedgerSessionReferencesProtectEngineReplacement(t *testing.T) {
	ledger := NewLeafMobilityPeerLedger()
	key := testPeerLedgerKey(33)
	ledger.retainSession(key.peer, key.session)
	ledger.retainSession(key.peer, key.session)
	reservation, err := ledger.installValidated(key, testPeerLedgerTransaction(33), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.compareAndAdvance(reservation); err != nil {
		t.Fatal(err)
	}
	ledger.releaseSession(key.peer, key.session)
	if generation, ok := ledger.current(key); !ok || generation != 1 {
		t.Fatalf("first Engine close removed replacement state: generation=%d found=%t", generation, ok)
	}
	ledger.releaseSession(key.peer, key.session)
	if _, ok := ledger.current(key); ok {
		t.Fatal("last Engine close retained session ledger state")
	}
}

func TestLeafMobilityPeerLedgerUnvalidatedObservationDoesNotConsumeCapacity(t *testing.T) {
	ledger := NewLeafMobilityPeerLedger()
	for i := 0; i < leafMobilityPeerLedgerLimit*2; i++ {
		key := testPeerLedgerKey(uint64(i + 1))
		if generation, ok := ledger.current(key); ok || generation != 0 {
			t.Fatalf("current %d generation=%d found=%t", i, generation, ok)
		}
	}
	if got := len(ledger.entries); got != 0 {
		t.Fatalf("unvalidated observations installed %d entries", got)
	}
	if _, err := ledger.installValidated(testPeerLedgerKey(1), [16]byte{}, 0); !errors.Is(err, ErrLeafMobilityPeerTransactionRequired) {
		t.Fatalf("zero transaction error=%v", err)
	}
	zeroPeer := testPeerLedgerKey(1)
	zeroPeer.peer = proto.InstanceID{}
	if _, err := ledger.installValidated(zeroPeer, testPeerLedgerTransaction(1), 0); !errors.Is(err, ErrLeafMobilityPeerTransactionRequired) {
		t.Fatalf("zero peer error=%v", err)
	}
	zeroSession := testPeerLedgerKey(1)
	zeroSession.session = proto.SessionEpoch{}
	if _, err := ledger.installValidated(zeroSession, testPeerLedgerTransaction(1), 0); !errors.Is(err, ErrLeafMobilityPeerTransactionRequired) {
		t.Fatalf("zero session error=%v", err)
	}
	if got := len(ledger.entries); got != 0 {
		t.Fatalf("invalid transaction installed %d entries", got)
	}
}

func TestEngineLeafMobilityPeerLedgerCannotChangeAfterTransactionEvidence(t *testing.T) {
	tests := []struct {
		name string
		seed func(*leafMobilityRuntime)
	}{
		{
			name: "completed",
			seed: func(runtime *leafMobilityRuntime) {
				runtime.completed[[16]byte{1}] = completedLeafMobilityTransaction{}
			},
		},
		{
			name: "rejected",
			seed: func(runtime *leafMobilityRuntime) {
				runtime.rejected[[16]byte{1}] = rejectedLeafMobilityTransaction{}
			},
		},
		{
			name: "actor-terminal",
			seed: func(runtime *leafMobilityRuntime) {
				runtime.actorTerminal[[16]byte{1}] = actorLeafMobilityTombstone{}
			},
		},
		{
			name: "outbound-sequence",
			seed: func(runtime *leafMobilityRuntime) {
				runtime.messageSeq.Store(1)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			engine := New(SideClient, NewClientFlowID(), Limits{})
			t.Cleanup(func() { _ = engine.Close() })
			installed := NewLeafMobilityPeerLedger()
			replacement := NewLeafMobilityPeerLedger()
			engine.SetLeafMobilityPeerLedger(installed)
			engine.leafTx.mu.Lock()
			test.seed(engine.leafTx)
			engine.leafTx.mu.Unlock()
			engine.SetLeafMobilityPeerLedger(replacement)
			if engine.leafTx.peerLedger != installed {
				t.Fatal("transaction evidence allowed peer ledger replacement")
			}
		})
	}

	t.Run("inbound-oob", func(t *testing.T) {
		engine := New(SideClient, NewClientFlowID(), Limits{})
		t.Cleanup(func() { _ = engine.Close() })
		installed := NewLeafMobilityPeerLedger()
		replacement := NewLeafMobilityPeerLedger()
		engine.SetLeafMobilityPeerLedger(installed)
		engine.leafTx.oobMu.Lock()
		engine.leafTx.oobSeen[leafMobilityOOBKey{seq: 1}] = leafMobilityOOBRecord{}
		engine.leafTx.oobMu.Unlock()
		engine.SetLeafMobilityPeerLedger(replacement)
		if engine.leafTx.peerLedger != installed {
			t.Fatal("OOB evidence allowed peer ledger replacement")
		}
	})
}

func TestEngineLeafMobilityPeerLedgerCannotResetRetainedSession(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{})
	first := NewLeafMobilityPeerLedger()
	second := NewLeafMobilityPeerLedger()
	e.SetLeafMobilityPeerLedger(first)
	peer := proto.InstanceID{0x91}
	if err := e.SetPeerInstanceID(peer); err != nil {
		t.Fatal(err)
	}
	key := e.peerLeafLedgerKey(proto.LeafMobilityActorClient, proto.LeafMobilityResourceID{0x92})
	reservation, err := first.installValidated(key, testPeerLedgerTransaction(91), 7)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.release(reservation); err != nil {
		t.Fatal(err)
	}

	e.SetLeafMobilityPeerLedger(first)
	if generation, ok := first.current(key); !ok || generation != 8 {
		t.Fatalf("same-ledger reinjection reset generation=(%d,%t)", generation, ok)
	}
	e.SetLeafMobilityPeerLedger(second)
	if e.leafTx.peerLedger != first {
		t.Fatal("retained session switched peer ledger")
	}
	if generation, ok := first.current(key); !ok || generation != 8 {
		t.Fatalf("replacement attempt reset generation=(%d,%t)", generation, ok)
	}
	second.mu.Lock()
	secondRefs := len(second.sessions)
	second.mu.Unlock()
	if secondRefs != 0 {
		t.Fatalf("rejected replacement retained %d sessions", secondRefs)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLeafMobilityPeerLedgerCapacityIsTypedAndExistingKeysRemainUsable(t *testing.T) {
	ledger := NewLeafMobilityPeerLedger()
	firstKey := testPeerLedgerKey(1)
	ledger.retainSession(firstKey.peer, firstKey.session)
	for i := 0; i < leafMobilityPeerLedgerLimit; i++ {
		key := testPeerLedgerKey(uint64(i + 1))
		reservation, err := ledger.installValidated(key, testPeerLedgerTransaction(uint64(i+1)), 0)
		if err != nil {
			t.Fatalf("install %d: %v", i, err)
		}
		if err := ledger.release(reservation); err != nil {
			t.Fatalf("release %d: %v", i, err)
		}
	}
	if _, err := ledger.installValidated(
		testPeerLedgerKey(leafMobilityPeerLedgerLimit+1),
		testPeerLedgerTransaction(leafMobilityPeerLedgerLimit+1),
		0,
	); !errors.Is(err, ErrLeafMobilityAuthorityBusy) {
		t.Fatalf("capacity error=%v want busy", err)
	}
	otherSession := testPeerLedgerKey(leafMobilityPeerLedgerLimit + 1)
	otherSession.session = proto.SessionEpoch{3}
	ledger.retainSession(otherSession.peer, otherSession.session)
	if _, err := ledger.installValidated(otherSession, testPeerLedgerTransaction(8001), 0); err != nil {
		t.Fatalf("one full session blocked another session: %v", err)
	}
	ledger.releaseSession(otherSession.peer, otherSession.session)

	reservation, err := ledger.installValidated(testPeerLedgerKey(1), testPeerLedgerTransaction(9001), 1)
	if err != nil {
		t.Fatalf("existing key at capacity: %v", err)
	}
	if err := ledger.compareAndAdvance(reservation); err != nil {
		t.Fatalf("advance existing key at capacity: %v", err)
	}
	ledger.releaseSession(firstKey.peer, firstKey.session)
	if got := len(ledger.entries); got != 0 {
		t.Fatalf("closed session retained %d peer ledger entries", got)
	}
	ledger.retainSession(firstKey.peer, firstKey.session)
	if _, err := ledger.installValidated(testPeerLedgerKey(leafMobilityPeerLedgerLimit+1), testPeerLedgerTransaction(9999), 0); err != nil {
		t.Fatalf("new transaction after session reclamation: %v", err)
	}
}

func TestLeafMobilityPeerLedgerReleaseCannotAffectSuccessor(t *testing.T) {
	ledger := NewLeafMobilityPeerLedger()
	key := testPeerLedgerKey(5)
	first, err := ledger.installValidated(key, testPeerLedgerTransaction(10), 3)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.release(first); err != nil {
		t.Fatal(err)
	}
	if err := ledger.release(first); err != nil {
		t.Fatalf("release replay: %v", err)
	}
	second, err := ledger.installValidated(key, testPeerLedgerTransaction(11), 4)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.release(first); err != nil {
		t.Fatalf("late release replay: %v", err)
	}
	if err := ledger.release(second); err != nil {
		t.Fatalf("successor release after late predecessor replay: %v", err)
	}
	if _, err := ledger.installValidated(key, testPeerLedgerTransaction(10), 3); !errors.Is(err, ErrLeafMobilityPeerGenerationStale) {
		t.Fatalf("A-B-A replay error=%v want stale", err)
	}
}

func testPeerLedgerKey(value uint64) leafMobilityPeerLedgerKey {
	peer := proto.InstanceID{1}
	session := proto.SessionEpoch{2}
	var resource proto.LeafMobilityResourceID
	binary.BigEndian.PutUint64(resource[8:], value)
	return leafMobilityPeerLedgerKey{
		peer: peer, session: session, actor: proto.LeafMobilityActorClient, resource: resource,
	}
}

func testPeerLedgerTransaction(value uint64) [16]byte {
	var transactionID [16]byte
	binary.BigEndian.PutUint64(transactionID[8:], value)
	return transactionID
}
