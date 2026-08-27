package engine

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type enforcedPacketCapacityPath struct {
	transport.PathConn
	limit int
}

func (path *enforcedPacketCapacityPath) MaxFrameSize() int { return path.limit }

func (path *enforcedPacketCapacityPath) Write(frame []byte) (int, error) {
	if len(frame) > path.limit {
		return 0, errors.New("test packet path capacity exceeded")
	}
	return path.PathConn.Write(frame)
}

func TestPacketPathAdmissionRequiresMandatoryRuntimeControlCapacity(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	e.SetPacketMode()
	t.Cleanup(func() { _ = e.Close() })
	ids := configureLeafSelectorRuntime(t, e, "small")

	if got, want := mandatoryPacketControlFrameSize(), proto.HeaderSize+proto.LeafMobilityPeerPlanAckMaxSize; got != want {
		t.Fatalf("mandatory control frame bound=%d want largest encoded control %d", got, want)
	}
	if mandatoryPacketControlFrameSize() < proto.HeaderSize+proto.PathAdmissionAckMaxSize {
		t.Fatal("mandatory control frame bound does not cover path-admission ACK")
	}
	base, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = base.Close(); _ = peer.Close() })
	path := &enforcedPacketCapacityPath{
		PathConn: base,
		limit:    proto.HeaderSize + proto.AckPayloadSize - 1,
	}
	if _, err := e.AttachPathBound(
		path,
		transport.PathSpec{Transport: "small-control"},
		PathBinding{
			LocalTXTargetID:           ids["small"],
			PeerTXTargetID:            ids["small"],
			LocalReceiveFrameCapacity: uint32(path.limit),
			PeerReceiveFrameCapacity:  uint32(path.limit),
		},
	); !errors.Is(err, ErrPacketPathCapacityUnavailable) {
		t.Fatalf("undersized positive packet capacity error=%v want ErrPacketPathCapacityUnavailable", err)
	}
}

func TestPacketDirectionalTXLimitUsesLocalSendAndPeerReceiveCapacity(t *testing.T) {
	for _, test := range []struct {
		name   string
		local  int
		peer   int
		wantTX int64
	}{
		{name: "narrow peer limits wide local sender", local: 1400, peer: 1100, wantTX: 1100},
		{name: "local atomic send limit remains binding", local: 1100, peer: 1400, wantTX: 1100},
		{name: "replacement converges at surviving server limit", local: 1400, peer: 1250, wantTX: 1250},
	} {
		t.Run(test.name, func(t *testing.T) {
			e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
			e.SetPacketMode()
			t.Cleanup(func() { _ = e.Close() })
			ids := configureLeafSelectorRuntime(t, e, "path")
			path, peer := newMemoryPathPair()
			t.Cleanup(func() { _ = peer.Close() })
			_, err := e.AttachPathBound(
				&enforcedPacketCapacityPath{PathConn: path, limit: test.local},
				transport.PathSpec{Transport: "directional-capacity"},
				PathBinding{
					LocalTXTargetID:           ids["path"],
					PeerTXTargetID:            ids["path"],
					LocalReceiveFrameCapacity: uint32(test.local),
					PeerReceiveFrameCapacity:  uint32(test.peer),
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			if got := e.packetFrameLimit.Load(); got != test.wantTX {
				t.Fatalf("local atomic/peer receive=%d/%d produced TX limit=%d want %d", test.local, test.peer, got, test.wantTX)
			}
		})
	}
}

func TestPacketAdmissionRejectsChangedLocalReceiveCapacity(t *testing.T) {
	e := New(SideClient, NewClientFlowID(), Limits{}.Clamp())
	e.SetPacketMode()
	t.Cleanup(func() { _ = e.Close() })
	ids := configureLeafSelectorRuntime(t, e, "path")
	path, peer := newMemoryPathPair()
	t.Cleanup(func() { _ = peer.Close() })
	_, err := e.AttachPathBound(
		&enforcedPacketCapacityPath{PathConn: path, limit: 1400},
		transport.PathSpec{Transport: "capacity-mismatch"},
		PathBinding{
			LocalTXTargetID:           ids["path"],
			PeerTXTargetID:            ids["path"],
			LocalReceiveFrameCapacity: 1399,
			PeerReceiveFrameCapacity:  1400,
		},
	)
	if !errors.Is(err, ErrPacketPathCapacityUnavailable) {
		t.Fatalf("local receive capacity mismatch error=%v want ErrPacketPathCapacityUnavailable", err)
	}
}

func TestMinimumControlCapacityCarriesPacketsAcrossPathDeath(t *testing.T) {
	flow := NewClientFlowID()
	client := New(SideClient, flow, Limits{ProbeInterval: time.Hour}.Clamp())
	server := New(SideServer, flow, Limits{ProbeInterval: time.Hour}.Clamp())
	client.SetPacketMode()
	server.SetPacketMode()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	ids := configureSymmetricLeafGroupRuntime(t, client, server, proto.GraphNodeKindSelector, "first", "second")
	limit := mandatoryPacketControlFrameSize()

	clientFirst, serverFirst := newMemoryPathPair()
	clientSecond, serverSecond := newMemoryPathPair()
	for _, path := range []*memoryPathConn{clientFirst, serverFirst, clientSecond, serverSecond} {
		path := path
		t.Cleanup(func() { _ = path.Close() })
	}
	firstID := attachFixturePath(t, client, &enforcedPacketCapacityPath{PathConn: clientFirst, limit: limit}, transport.PathSpec{Transport: "memory", Address: "first-client"}, ids["first"])
	attachFixturePath(t, server, &enforcedPacketCapacityPath{PathConn: serverFirst, limit: limit}, transport.PathSpec{Transport: "memory", Address: "first-server"}, ids["first"])
	secondID := attachFixturePath(t, client, &enforcedPacketCapacityPath{PathConn: clientSecond, limit: limit}, transport.PathSpec{Transport: "memory", Address: "second-client"}, ids["second"])
	attachFixturePath(t, server, &enforcedPacketCapacityPath{PathConn: serverSecond, limit: limit}, transport.PathSpec{Transport: "memory", Address: "second-server"}, ids["second"])

	assertPacketRoundTrip := func(payload []byte) {
		t.Helper()
		if published, err := client.SendPacketResult(payload); err != nil || !published {
			t.Fatalf("packet publication=%t/%v", published, err)
		}
		if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		got, err := server.RecvPacket()
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("RecvPacket=%q/%v want %q", got, err, payload)
		}
	}
	assertPacketRoundTrip([]byte("before-capacity-migration"))
	clientFirst.Fail(errors.New("injected packet path death"))
	eventuallyEngine(t, time.Second, func() bool { return client.ActivePath() == secondID })
	if client.ActivePath() == firstID {
		t.Fatal("packet path did not migrate away from failed path")
	}
	assertPacketRoundTrip([]byte("after-capacity-migration"))
}

func TestPacketCapacityPrepareAndKnownAbortDoNotLowerSessionLimit(t *testing.T) {
	e, targets := newPacketBudgetEngine(t, "wide", "narrow")
	wide, widePeer := newMemoryPathPair()
	t.Cleanup(func() { _ = widePeer.Close() })
	attachFixedPacketPath(t, e, wide, widePacketFrameLimit, targets["wide"], "wide")

	narrow, narrowPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = narrowPeer.Close() })
	id, err := e.PreparePathBound(
		&fixedPacketFrameLimitPath{PathConn: narrow, limit: narrowPacketFrameLimit},
		transport.PathSpec{Transport: "memory", Address: "narrow"},
		PathBinding{LocalTXTargetID: targets["narrow"], PeerTXTargetID: targets["narrow"], LocalReceiveFrameCapacity: narrowPacketFrameLimit, PeerReceiveFrameCapacity: narrowPacketFrameLimit},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := e.packetFrameLimit.Load(); got != widePacketFrameLimit {
		t.Fatalf("prepared candidate lowered session limit to %d want %d", got, widePacketFrameLimit)
	}
	if err := e.StagePathAttach(id); err != nil {
		t.Fatal(err)
	}
	e.AbortPathAttach(id, errors.New("peer rejected candidate"))
	eventuallyEngine(t, time.Second, func() bool {
		e.pathsMu.RLock()
		defer e.pathsMu.RUnlock()
		return e.pendingPaths[id] == nil && e.stagedPaths[id] == nil
	})
	if got := e.packetFrameLimit.Load(); got != widePacketFrameLimit {
		t.Fatalf("known candidate abort lowered session limit to %d want %d", got, widePacketFrameLimit)
	}
}

func TestPacketCapacityActivationKnownFailureRollsBack(t *testing.T) {
	e, targets := newPacketBudgetEngine(t, "wide", "narrow")
	wide, widePeer := newMemoryPathPair()
	t.Cleanup(func() { _ = widePeer.Close() })
	attachFixedPacketPath(t, e, wide, widePacketFrameLimit, targets["wide"], "wide")

	narrow, narrowPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = narrowPeer.Close() })
	id, err := e.PreparePathBound(
		&fixedPacketFrameLimitPath{PathConn: narrow, limit: narrowPacketFrameLimit},
		transport.PathSpec{Transport: "memory", Address: "narrow"},
		PathBinding{LocalTXTargetID: targets["narrow"], PeerTXTargetID: targets["narrow"], LocalReceiveFrameCapacity: narrowPacketFrameLimit, PeerReceiveFrameCapacity: narrowPacketFrameLimit},
	)
	if err != nil {
		t.Fatal(err)
	}
	if published, err := e.SendPacketResult(largePacketForNarrowLimit(t, e)); err != nil || !published {
		t.Fatalf("large packet publication=%t/%v", published, err)
	}
	if err := e.StagePathAttach(id); err != nil {
		t.Fatal(err)
	}
	err = e.activateStagedPathContext(context.Background(), id, true, true)
	if !errors.Is(err, ErrPacketTooLarge) {
		t.Fatalf("known activation conflict error=%v want ErrPacketTooLarge", err)
	}
	if got := e.packetFrameLimit.Load(); got != widePacketFrameLimit {
		t.Fatalf("known activation failure lowered session limit to %d want %d", got, widePacketFrameLimit)
	}
	select {
	case <-e.Closed():
		t.Fatal("known activation failure closed the session")
	default:
	}
	e.AbortPathAttach(id, err)
}

func TestPacketCapacityActivationAmbiguityFailsClosedWithoutCommittingLimit(t *testing.T) {
	e, targets := newPacketBudgetEngine(t, "wide", "narrow")
	wide, widePeer := newMemoryPathPair()
	t.Cleanup(func() { _ = widePeer.Close() })
	attachFixedPacketPath(t, e, wide, widePacketFrameLimit, targets["wide"], "wide")

	narrow, narrowPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = narrowPeer.Close() })
	id, err := e.PreparePathBound(
		&fixedPacketFrameLimitPath{PathConn: narrow, limit: narrowPacketFrameLimit},
		transport.PathSpec{Transport: "memory", Address: "narrow"},
		PathBinding{LocalTXTargetID: targets["narrow"], PeerTXTargetID: targets["narrow"], LocalReceiveFrameCapacity: narrowPacketFrameLimit, PeerReceiveFrameCapacity: narrowPacketFrameLimit},
	)
	if err != nil {
		t.Fatal(err)
	}
	if published, err := e.SendPacketResult(largePacketForNarrowLimit(t, e)); err != nil || !published {
		t.Fatalf("large packet publication=%t/%v", published, err)
	}
	if err := e.StagePathAttach(id); err != nil {
		t.Fatal(err)
	}
	err = e.activateStagedPathContext(context.Background(), id, true, false)
	if !errors.Is(err, ErrPacketTooLarge) {
		t.Fatalf("ambiguous activation conflict error=%v want ErrPacketTooLarge", err)
	}
	select {
	case <-e.Closed():
	case <-time.After(time.Second):
		t.Fatal("ambiguous packet capacity outcome did not fail closed")
	}
	if got := e.packetFrameLimit.Load(); got != widePacketFrameLimit {
		t.Fatalf("ambiguous failed candidate committed session limit %d want %d", got, widePacketFrameLimit)
	}
}

func TestPacketCapacityRaisesOnlyAfterPeerConfirmedRetirement(t *testing.T) {
	newFixture := func(t *testing.T) (*Engine, uint32) {
		t.Helper()
		e, targets := newPacketBudgetEngine(t, "wide", "narrow")
		wide, widePeer := newMemoryPathPair()
		t.Cleanup(func() { _ = widePeer.Close() })
		attachFixedPacketPath(t, e, wide, widePacketFrameLimit, targets["wide"], "wide")
		narrow, narrowPeer := newMemoryPathPair()
		t.Cleanup(func() { _ = narrowPeer.Close() })
		narrowID := attachFixedPacketPath(t, e, narrow, narrowPacketFrameLimit, targets["narrow"], "narrow")
		if got := e.packetFrameLimit.Load(); got != narrowPacketFrameLimit {
			t.Fatalf("initial session limit=%d want=%d", got, narrowPacketFrameLimit)
		}
		return e, narrowID
	}

	t.Run("local deletion is not confirmation", func(t *testing.T) {
		e, narrowID := newFixture(t)
		if err := e.RemovePath(narrowID); err != nil {
			t.Fatal(err)
		}
		if got := e.packetFrameLimit.Load(); got != narrowPacketFrameLimit {
			t.Fatalf("unconfirmed local retirement raised limit=%d want=%d", got, narrowPacketFrameLimit)
		}
	})

	t.Run("cumulative ACK confirms retirement", func(t *testing.T) {
		e, narrowID := newFixture(t)
		if err := e.RemovePath(narrowID); err != nil {
			t.Fatal(err)
		}
		var ack proto.AckPayload
		eventuallyEngine(t, time.Second, func() bool {
			e.sendHistMu.Lock()
			defer e.sendHistMu.Unlock()
			for index := range e.sendHist.entries {
				entry := &e.sendHist.entries[index]
				hdr, err := proto.DecodeHeader(entry.frame)
				if err != nil || hdr.Type != proto.FrameCtrl || proto.CtrlCodeFromFlags(hdr.Flags) != proto.CtrlPathRetire {
					continue
				}
				binding := e.localGraphBinding()
				ack = proto.AckPayload{
					SessionEpoch:  proto.SessionEpoch(e.FlowID()),
					Direction:     senderDirection(e.side),
					GraphRevision: binding.revision,
					GraphDigest:   binding.digest,
					NextSeq:       entry.seq + 1,
					Proof:         entry.proof,
				}
				return true
			}
			return false
		})
		if !e.notePeerAck(ack) {
			t.Fatal("peer retirement ACK was rejected")
		}
		eventuallyEngine(t, time.Second, func() bool {
			return e.packetFrameLimit.Load() == widePacketFrameLimit
		})
	})
}

func prepareWiderSuccessorAfterConfirmedNarrowRetirement(t *testing.T) (*Engine, uint32, []byte) {
	t.Helper()
	e, targets := newPacketBudgetEngine(t, "leaf")

	narrow, narrowPeer := newMemoryPathPair()
	t.Cleanup(func() { _ = narrowPeer.Close() })
	narrowID := attachFixedPacketPath(t, e, narrow, narrowPacketFrameLimit, targets["leaf"], "narrow")
	e.pathsMu.RLock()
	narrowSlot := e.paths[narrowID]
	retirementKey := packetPathCapacityKeyForSlot(narrowSlot)
	e.pathsMu.RUnlock()
	if narrowSlot == nil {
		t.Fatal("narrow path is missing before replacement")
	}

	wide, widePeer := newMemoryPathPair()
	t.Cleanup(func() { _ = widePeer.Close() })
	wideID, err := e.PreparePathBound(
		&fixedPacketFrameLimitPath{PathConn: wide, limit: widePacketFrameLimit},
		transport.PathSpec{Transport: "memory", Address: "wide-staged"},
		fixedPacketCapacityBinding(targets["leaf"], widePacketFrameLimit),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.StagePathAttach(wideID); err != nil {
		t.Fatal(err)
	}
	if got := e.packetFrameLimit.Load(); got != narrowPacketFrameLimit {
		t.Fatalf("staging wider successor raised limit=%d want %d", got, narrowPacketFrameLimit)
	}

	failMemoryPath(t, e, narrowID, narrow, errors.New("injected narrow-path retirement"))
	e.pathsMu.Lock()
	e.confirmPacketPathCapacityKeyLocked(retirementKey)
	e.pathsMu.Unlock()
	if got := e.packetFrameLimit.Load(); got != narrowPacketFrameLimit {
		t.Fatalf("confirmation with only staged successor raised limit=%d want %d", got, narrowPacketFrameLimit)
	}
	e.pathsMu.RLock()
	staged := e.stagedPaths[wideID]
	e.pathsMu.RUnlock()
	if staged == nil || staged.packetCapacityCommitted {
		t.Fatalf("wider successor staged/committed=%t/%t want true/false", staged != nil, staged != nil && staged.packetCapacityCommitted)
	}
	return e, wideID, largePacketForNarrowLimit(t, e)
}

func TestPacketCapacityWiderStagedSuccessorRaisesAtActivationCommit(t *testing.T) {
	e, wideID, large := prepareWiderSuccessorAfterConfirmedNarrowRetirement(t)
	if err := e.validatePacketPayloadSize(len(large)); !errors.Is(err, ErrPacketTooLarge) {
		t.Fatalf("pre-activation payload validation=%v want ErrPacketTooLarge", err)
	}
	if err := e.ActivateStagedPath(wideID, false); err != nil {
		t.Fatal(err)
	}
	if got := e.packetFrameLimit.Load(); got != widePacketFrameLimit {
		t.Fatalf("activated wider successor limit=%d want %d", got, widePacketFrameLimit)
	}
	if err := e.validatePacketPayloadSize(len(large)); err != nil {
		t.Fatalf("post-activation payload remained constrained: %v", err)
	}
}

func TestPacketCapacityWiderSuccessorFailureDoesNotRaiseLimit(t *testing.T) {
	for _, test := range []struct {
		name  string
		abort func(*Engine, uint32) error
	}{
		{
			name: "known abort",
			abort: func(e *Engine, id uint32) error {
				e.AbortPathAttach(id, errors.New("injected wider successor rejection"))
				return nil
			},
		},
		{
			name: "removed during activation",
			abort: func(e *Engine, id uint32) error {
				e.activationAfterPredecessorDrain = func() {
					e.AbortPathAttach(id, errors.New("injected activation rollback"))
				}
				defer func() { e.activationAfterPredecessorDrain = nil }()
				return e.activateStagedPathContext(context.Background(), id, false, true)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			e, wideID, large := prepareWiderSuccessorAfterConfirmedNarrowRetirement(t)
			err := test.abort(e, wideID)
			if test.name == "removed during activation" && err == nil {
				t.Fatal("activation succeeded after its staged successor was aborted")
			}
			eventuallyEngine(t, time.Second, func() bool {
				e.pathsMu.RLock()
				defer e.pathsMu.RUnlock()
				return e.stagedPaths[wideID] == nil && e.paths[wideID] == nil
			})
			if got := e.packetFrameLimit.Load(); got != narrowPacketFrameLimit {
				t.Fatalf("failed wider successor raised limit=%d want %d", got, narrowPacketFrameLimit)
			}
			if err := e.validatePacketPayloadSize(len(large)); !errors.Is(err, ErrPacketTooLarge) {
				t.Fatalf("failed successor payload validation=%v want ErrPacketTooLarge", err)
			}
		})
	}
}

func TestPacketCapacityRaiseLinearizesAfterWiderActivationPublication(t *testing.T) {
	e, wideID, large := prepareWiderSuccessorAfterConfirmedNarrowRetirement(t)
	beforeRaise := make(chan struct{})
	releaseRaise := make(chan struct{})
	var enteredOnce, releaseOnce sync.Once
	e.packetActivationBeforeBudgetRaise = func() {
		enteredOnce.Do(func() { close(beforeRaise) })
		<-releaseRaise
	}
	release := func() { releaseOnce.Do(func() { close(releaseRaise) }) }
	t.Cleanup(func() {
		release()
		e.packetActivationBeforeBudgetRaise = nil
	})

	activated := make(chan error, 1)
	go func() { activated <- e.ActivateStagedPath(wideID, false) }()
	select {
	case <-beforeRaise:
	case <-time.After(time.Second):
		t.Fatal("wider activation did not reach capacity commit point")
	}
	if got := e.packetFrameLimit.Load(); got != narrowPacketFrameLimit {
		t.Fatalf("pre-commit limit=%d want %d", got, narrowPacketFrameLimit)
	}
	if err := e.validatePacketPayloadSize(len(large)); !errors.Is(err, ErrPacketTooLarge) {
		t.Fatalf("pre-commit payload validation=%v want ErrPacketTooLarge", err)
	}
	if published, err := e.SendPacketResult(large); published || !errors.Is(err, ErrPacketTooLarge) {
		t.Fatalf("concurrent pre-commit packet publication=%t/%v want false/ErrPacketTooLarge", published, err)
	}
	release()
	select {
	case err := <-activated:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("wider activation did not finish after capacity commit release")
	}
	if got := e.packetFrameLimit.Load(); got != widePacketFrameLimit {
		t.Fatalf("post-commit limit=%d want %d", got, widePacketFrameLimit)
	}
	if err := e.validatePacketPayloadSize(len(large)); err != nil {
		t.Fatalf("post-commit payload validation: %v", err)
	}
}
