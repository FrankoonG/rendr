package engine

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type policyAckIntercept struct {
	phase   proto.PolicyAckPhase
	drop    bool
	dropAll bool
	seen    chan struct{}
	release chan struct{}
	once    sync.Once
	dropped atomic.Uint32
}

type policyAckInterceptPath struct {
	inner     transport.PathConn
	intercept *policyAckIntercept
}

type policyControlDrop struct {
	code                 proto.CtrlCode
	dropAll              bool
	deliverBeforeRelease bool
	observed             chan proto.PolicyCommit
	release              chan struct{}
	observedOnce         sync.Once
	dropped              atomic.Uint32
}

type policyControlDropPath struct {
	inner transport.PathConn
	drop  *policyControlDrop
}

func (p *policyControlDropPath) Read(b []byte) (int, error) { return p.inner.Read(b) }
func (p *policyControlDropPath) Write(frame []byte) (int, error) {
	if len(frame) >= proto.HeaderSize {
		header, err := proto.DecodeHeader(frame[:proto.HeaderSize])
		if err == nil && header.Type == proto.FrameCtrl && proto.CtrlCodeFromFlags(header.Flags) == p.drop.code {
			observe := func() {
				if p.drop.observed == nil || p.drop.code != proto.CtrlPolicyCommit {
					return
				}
				commit, decodeErr := proto.DecodePolicyCommit(frame[proto.HeaderSize:])
				if decodeErr == nil {
					p.drop.observedOnce.Do(func() { p.drop.observed <- commit })
				}
			}
			if p.drop.deliverBeforeRelease {
				n, writeErr := p.inner.Write(frame)
				observe()
				if p.drop.release != nil {
					<-p.drop.release
				}
				return n, writeErr
			}
			observe()
			if p.drop.release != nil {
				<-p.drop.release
			}
			if p.drop.dropAll {
				p.drop.dropped.Add(1)
				return len(frame), nil
			}
			if p.drop.dropped.CompareAndSwap(0, 1) {
				return len(frame), nil
			}
		}
	}
	return p.inner.Write(frame)
}
func (p *policyControlDropPath) Close() error                                 { return p.inner.Close() }
func (p *policyControlDropPath) Quality() transport.PathQuality               { return p.inner.Quality() }
func (p *policyControlDropPath) OnDeath(fn func(transport.DeathCause, error)) { p.inner.OnDeath(fn) }
func (p *policyControlDropPath) LocalAddr() string                            { return p.inner.LocalAddr() }
func (p *policyControlDropPath) RemoteAddr() string                           { return p.inner.RemoteAddr() }

func (p *policyAckInterceptPath) Read(b []byte) (int, error) { return p.inner.Read(b) }

func (p *policyAckInterceptPath) Write(frame []byte) (int, error) {
	if len(frame) >= proto.HeaderSize {
		hdr, err := proto.DecodeHeader(frame[:proto.HeaderSize])
		if err == nil && hdr.Type == proto.FrameCtrl && proto.CtrlCodeFromFlags(hdr.Flags) == proto.CtrlPolicyAck {
			ack, decodeErr := proto.DecodePolicyAck(frame[proto.HeaderSize:])
			if decodeErr == nil && ack.Phase == p.intercept.phase {
				intercepted := false
				p.intercept.once.Do(func() {
					intercepted = true
					close(p.intercept.seen)
				})
				if p.intercept.dropAll {
					p.intercept.dropped.Add(1)
					return len(frame), nil
				}
				if intercepted {
					if p.intercept.drop {
						p.intercept.dropped.Add(1)
						return len(frame), nil
					}
					<-p.intercept.release
				}
			}
		}
	}
	return p.inner.Write(frame)
}

func (p *policyAckInterceptPath) Close() error                   { return p.inner.Close() }
func (p *policyAckInterceptPath) Quality() transport.PathQuality { return p.inner.Quality() }
func (p *policyAckInterceptPath) OnDeath(fn func(transport.DeathCause, error)) {
	p.inner.OnDeath(fn)
}
func (p *policyAckInterceptPath) LocalAddr() string  { return p.inner.LocalAddr() }
func (p *policyAckInterceptPath) RemoteAddr() string { return p.inner.RemoteAddr() }

func TestPolicyCommitOwnsDispatchBeforeFinalAck(t *testing.T) {
	client, server, selectorID, _, targetB, _, serverB := newPolicyE2EPair(t, &policyAckIntercept{
		phase:   proto.PolicyAckPhaseFinal,
		seen:    make(chan struct{}),
		release: make(chan struct{}),
	})
	intercept := serverPolicyIntercept(server)
	if intercept == nil {
		t.Fatal("test setup has no policy ACK interceptor")
	}

	result := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		result <- client.RequestPeerSelection(ctx, selectorID, targetB, "test-commit-order")
	}()

	select {
	case <-intercept.seen:
	case <-time.After(time.Second):
		t.Fatal("owner did not reach final policy ACK")
	}
	if got := server.ActivePath(); got != serverB {
		t.Fatalf("final ACK started before dispatch ownership: active=%d want=%d", got, serverB)
	}
	close(intercept.release)
	if err := <-result; err != nil {
		t.Fatalf("RequestPeerSelection: %v", err)
	}
}

func TestPolicyFeatureIsMandatoryAtGraphNegotiation(t *testing.T) {
	manifest, _ := adversarialGraphManifest("policy-feature-root", proto.GraphNodeKindSelector, "feature-a", "feature-b")
	flow := [16]byte{0x91, 0x11}
	e := New(SideClient, flow, Limits{}.Clamp())
	defer e.Close()
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	digest := adversarialGraphDigest(t, manifest)
	peer := proto.NewNegotiation(proto.SessionEpoch(flow))
	peer.GraphDigest = digest
	peer.Supported &^= proto.FeaturePolicyTransaction
	peer.Required &^= proto.FeaturePolicyTransaction
	if err := e.AcceptPeerNegotiation(peer, manifest); err == nil {
		t.Fatal("accepted a peer without mandatory policy transaction support")
	}
}

func TestPolicySelectionHonorsContextWithoutPath(t *testing.T) {
	manifest, leaves := adversarialGraphManifest("policy-timeout-root", proto.GraphNodeKindSelector, "timeout-a", "timeout-b")
	flow := [16]byte{0x91, 0x12}
	e := New(SideClient, flow, Limits{}.Clamp())
	defer e.Close()
	if err := e.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := e.ConfigurePeerGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := e.RequestPeerSelection(ctx, manifest.RootID, leaves[1], "no-path")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("RequestPeerSelection error=%v want context deadline", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("context cancellation took %v", elapsed)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel2()
	err = e.RequestPeerSelection(ctx2, manifest.RootID, leaves[0], "no-path-repeat")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second RequestPeerSelection error=%v want context deadline", err)
	}
	if got := atomic.LoadUint64(&e.sendSeq); got != 1 {
		t.Fatalf("blocked repeated requests published %d frames, want 1", got)
	}
}

func TestPolicyTransactionRecoversLostAckByIdempotentReplay(t *testing.T) {
	for _, phase := range []proto.PolicyAckPhase{proto.PolicyAckPhasePrepare, proto.PolicyAckPhaseFinal} {
		t.Run(policyAckPhaseName(phase), func(t *testing.T) {
			intercept := &policyAckIntercept{
				phase:   phase,
				drop:    true,
				seen:    make(chan struct{}),
				release: make(chan struct{}),
			}
			client, server, selectorID, _, targetB, _, serverB := newPolicyE2EPair(t, intercept)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := client.RequestPeerSelection(ctx, selectorID, targetB, "test-loss-recovery"); err != nil {
				t.Fatalf("RequestPeerSelection after dropped %s ACK: %v", policyAckPhaseName(phase), err)
			}
			if intercept.dropped.Load() != 1 {
				t.Fatalf("dropped ACK count=%d want=1", intercept.dropped.Load())
			}
			if got := server.ActivePath(); got != serverB {
				t.Fatalf("active path=%d want=%d", got, serverB)
			}
			server.policyStateMu.Lock()
			generation := server.policyGeneration
			completed := len(server.policyCompleted)
			server.policyStateMu.Unlock()
			if generation != 1 || completed != 1 {
				t.Fatalf("owner state generation=%d completed=%d, want 1/1", generation, completed)
			}
		})
	}
}

func TestPolicyTransactionRecoversLostRequestPhasesWithSameSequence(t *testing.T) {
	for _, code := range []proto.CtrlCode{proto.CtrlPolicyPrepare, proto.CtrlPolicyCommit} {
		t.Run(code.String(), func(t *testing.T) {
			drop := &policyControlDrop{code: code}
			client, _, selectorID, _, targetB, _, _ := newPolicyE2EPairWithDrops(t, nil, drop)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := client.RequestPeerSelection(ctx, selectorID, targetB, "test-request-phase-loss"); err != nil {
				t.Fatalf("RequestPeerSelection after dropped %s: %v", code, err)
			}
			if drop.dropped.Load() != 1 {
				t.Fatalf("dropped %s count=%d want=1", code, drop.dropped.Load())
			}
			if got := atomic.LoadUint64(&client.sendSeq); got != 2 {
				t.Fatalf("client sequenced frames=%d want=2", got)
			}
		})
	}
}

func TestDroppedCommitAndForgedFinalCannotAuthorizeSuccess(t *testing.T) {
	drop := &policyControlDrop{
		code:     proto.CtrlPolicyCommit,
		dropAll:  true,
		observed: make(chan proto.PolicyCommit, 1),
		release:  make(chan struct{}),
	}
	client, server, selectorID, targetA, targetB, serverA, _ := newPolicyE2EPairWithDrops(t, nil, drop)
	ctx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- client.RequestPeerSelection(ctx, selectorID, targetB, "forged-final-before-commit-receipt")
	}()

	var commit proto.PolicyCommit
	select {
	case commit = <-drop.observed:
	case <-time.After(time.Second):
		close(drop.release)
		t.Fatal("requester did not publish COMMIT to the blackhole")
	}
	client.policyStateMu.Lock()
	tx := client.policyOutgoing
	if tx == nil {
		client.policyStateMu.Unlock()
		close(drop.release)
		t.Fatal("outgoing transaction disappeared while COMMIT write was blocked")
	}
	if tx.commitDispatched {
		client.policyStateMu.Unlock()
		close(drop.release)
		t.Fatal("COMMIT became dispatched before its write returned")
	}
	digest := tx.digest
	client.policyStateMu.Unlock()
	forged := proto.PolicyAck{
		PolicyTransactionBinding: commit.PolicyTransactionBinding,
		Phase:                    proto.PolicyAckPhaseFinal,
		Code:                     proto.PolicyAckCodeAccept,
		Generation:               commit.Generation,
		CurrentGeneration:        commit.Generation,
		CurrentTargetID:          targetB,
		ResolvedTargetID:         targetB,
		ProposalDigest:           digest,
		ReservationID:            commit.ReservationID,
		CommitChallenge:          commit.CommitChallenge,
	}
	if err := client.handlePolicyAck(forged); err != nil {
		close(drop.release)
		t.Fatalf("early forged FINAL should be ignored, got %v", err)
	}
	client.policyStateMu.Lock()
	queuedFinals := len(tx.finalAcks)
	client.policyStateMu.Unlock()
	if queuedFinals != 0 {
		close(drop.release)
		t.Fatal("early forged FINAL entered the authorization mailbox")
	}
	close(drop.release)

	select {
	case err := <-result:
		if !errors.Is(err, ErrPolicyOutcomeUnknown) {
			t.Fatalf("dropped COMMIT result=%v want ErrPolicyOutcomeUnknown", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dropped COMMIT transaction did not respect its deadline")
	}
	if drop.dropped.Load() < 2 {
		t.Fatalf("dropped COMMIT count=%d, retry stimulus did not occur", drop.dropped.Load())
	}
	server.policyStateMu.Lock()
	generation := server.policyGeneration
	selection := server.policySelections[selectorID]
	server.policyStateMu.Unlock()
	if generation != 0 || selection != targetA || server.ActivePath() != serverA {
		t.Fatalf("forged FINAL changed owner generation=%d selection=%x active=%d", generation, selection, server.ActivePath())
	}
}

func TestLegitimateFinalAtCustodyBeforeCommitWriteReturnRequiresReplay(t *testing.T) {
	commitGate := &policyControlDrop{
		code:                 proto.CtrlPolicyCommit,
		deliverBeforeRelease: true,
		observed:             make(chan proto.PolicyCommit, 1),
		release:              make(chan struct{}),
	}
	finalDrop := &policyAckIntercept{
		phase:   proto.PolicyAckPhaseFinal,
		drop:    true,
		seen:    make(chan struct{}),
		release: make(chan struct{}),
	}
	client, server, selectorID, _, targetB, _, serverB := newPolicyE2EPairWithDrops(t, finalDrop, commitGate)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- client.RequestPeerSelection(ctx, selectorID, targetB, "legitimate-early-final-custody")
	}()

	var commit proto.PolicyCommit
	select {
	case commit = <-commitGate.observed:
	case <-time.After(time.Second):
		close(commitGate.release)
		close(finalDrop.release)
		t.Fatal("COMMIT was not delivered before its Write return gate")
	}
	deadline := time.Now().Add(time.Second)
	for server.ActivePath() != serverB {
		if time.Now().After(deadline) {
			close(commitGate.release)
			close(finalDrop.release)
			t.Fatal("owner did not commit before requester COMMIT Write returned")
		}
		time.Sleep(time.Millisecond)
	}

	client.policyStateMu.Lock()
	tx := client.policyOutgoing
	if tx == nil || tx.commitDispatched {
		client.policyStateMu.Unlock()
		close(commitGate.release)
		close(finalDrop.release)
		t.Fatalf("outgoing transaction before custody tx=%p commit-dispatched=%t", tx, tx != nil && tx.commitDispatched)
	}
	digest := tx.digest
	client.policyStateMu.Unlock()
	earlyFinal := proto.PolicyAck{
		PolicyTransactionBinding: commit.PolicyTransactionBinding,
		Phase:                    proto.PolicyAckPhaseFinal,
		Code:                     proto.PolicyAckCodeAccept,
		Generation:               commit.Generation,
		CurrentGeneration:        commit.Generation,
		CurrentTargetID:          targetB,
		ResolvedTargetID:         targetB,
		ProposalDigest:           digest,
		ReservationID:            commit.ReservationID,
		CommitChallenge:          commit.CommitChallenge,
	}
	earlyWire, err := earlyFinal.Encode()
	if err != nil {
		close(commitGate.release)
		close(finalDrop.release)
		t.Fatal(err)
	}
	earlyHeader := proto.Header{
		Version: proto.Version,
		Type:    proto.FrameCtrl,
		Flags:   proto.FlagsForCtrl(proto.CtrlPolicyAck),
		Seq:     0x7f00,
	}
	earlyMessage := policyMessage{
		kind: policyMessageAck,
		key: policyMessageKey{
			kind:        policyMessageAck,
			seq:         earlyHeader.Seq,
			frameDigest: recvFrameDigest(earlyHeader, earlyWire),
		},
		ack:  earlyFinal,
		done: make(chan error, 1),
	}
	client.recvMu.Lock()
	queued := client.enqueuePolicyMessageLocked(earlyMessage)
	client.recvMu.Unlock()
	if !queued {
		close(commitGate.release)
		close(finalDrop.release)
		t.Fatal("legitimate early FINAL did not enter policy custody")
	}
	select {
	case err := <-earlyMessage.done:
		if err != nil {
			close(commitGate.release)
			close(finalDrop.release)
			t.Fatalf("early FINAL custody result: %v", err)
		}
	case <-time.After(time.Second):
		close(commitGate.release)
		close(finalDrop.release)
		t.Fatal("early FINAL custody did not complete")
	}
	client.policyStateMu.Lock()
	queuedFinals := len(tx.finalAcks)
	commitDispatched := tx.commitDispatched
	client.policyStateMu.Unlock()
	if queuedFinals != 0 || commitDispatched {
		close(commitGate.release)
		close(finalDrop.release)
		t.Fatalf("early FINAL authorized before COMMIT return: mailbox=%d dispatched=%t", queuedFinals, commitDispatched)
	}

	close(commitGate.release)
	close(finalDrop.release)
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("RequestPeerSelection after exact replay: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("policy transaction did not converge after exact COMMIT/FINAL replay")
	}
	if finalDrop.dropped.Load() != 1 {
		t.Fatalf("dropped initial owner FINAL count=%d want=1", finalDrop.dropped.Load())
	}
}

func TestPolicyAckBlackholeReusesOneControlSequence(t *testing.T) {
	intercept := &policyAckIntercept{
		phase:   proto.PolicyAckPhasePrepare,
		dropAll: true,
		seen:    make(chan struct{}),
		release: make(chan struct{}),
	}
	client, server, selectorID, _, targetB, _, _ := newPolicyE2EPair(t, intercept)
	ctx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
	defer cancel()
	err := client.RequestPeerSelection(ctx, selectorID, targetB, "test-total-ack-blackhole")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("RequestPeerSelection error=%v want context deadline", err)
	}
	if intercept.dropped.Load() < 2 {
		t.Fatalf("prepare ACK replay count=%d, retry stimulus did not occur", intercept.dropped.Load())
	}
	if got := atomic.LoadUint64(&client.sendSeq); got != 1 {
		t.Fatalf("client sequenced frames=%d want=1", got)
	}
	if got := atomic.LoadUint64(&server.sendSeq); got != 1 {
		t.Fatalf("server sequenced frames=%d want=1", got)
	}
}

func newPolicyE2EPair(t *testing.T, intercept *policyAckIntercept) (
	client *Engine,
	server *Engine,
	selectorID proto.TargetID,
	targetA proto.TargetID,
	targetB proto.TargetID,
	serverA uint32,
	serverB uint32,
) {
	return newPolicyE2EPairWithDrops(t, intercept, nil)
}

func newPolicyE2EPairWithDrops(t *testing.T, intercept *policyAckIntercept, clientDrop *policyControlDrop) (
	client *Engine,
	server *Engine,
	selectorID proto.TargetID,
	targetA proto.TargetID,
	targetB proto.TargetID,
	serverA uint32,
	serverB uint32,
) {
	t.Helper()
	pathA := proto.GraphNode{ID: proto.DeriveTargetID(proto.GraphNodeKindPath, "policy-a"), Kind: proto.GraphNodeKindPath, Name: "policy-a"}
	pathB := proto.GraphNode{ID: proto.DeriveTargetID(proto.GraphNodeKindPath, "policy-b"), Kind: proto.GraphNodeKindPath, Name: "policy-b"}
	selector := proto.GraphNode{
		ID:       proto.DeriveTargetID(proto.GraphNodeKindSelector, "policy-root"),
		Kind:     proto.GraphNodeKindSelector,
		Name:     "policy-root",
		Children: []proto.TargetID{pathA.ID, pathB.ID},
	}
	manifest := proto.GraphManifest{RootID: selector.ID, Nodes: []proto.GraphNode{selector, pathA, pathB}}
	flow := [16]byte{0x91, 0x10}
	client = New(SideClient, flow, Limits{}.Clamp())
	server = New(SideServer, flow, Limits{}.Clamp())
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	for _, e := range []*Engine{client, server} {
		if err := e.ConfigureLocalGraph(1, manifest); err != nil {
			t.Fatal(err)
		}
		if err := e.ConfigurePeerGraph(1, manifest); err != nil {
			t.Fatal(err)
		}
	}

	for _, path := range []struct {
		name string
		id   *uint32
	}{
		{name: pathA.Name, id: &serverA},
		{name: pathB.Name, id: &serverB},
	} {
		clientPath, serverPath := newMemoryPathPair()
		spec := transport.PathSpec{Transport: "memory", Address: path.name, Opts: map[string]string{"name": path.name}}
		clientWrapped := transport.PathConn(clientPath)
		if clientDrop != nil {
			clientWrapped = &policyControlDropPath{inner: clientPath, drop: clientDrop}
		}
		targetID := pathA.ID
		if path.name == pathB.Name {
			targetID = pathB.ID
		}
		binding := PathBinding{LocalTXTargetID: targetID, PeerTXTargetID: targetID}
		if _, err := client.AttachPathBound(clientWrapped, spec, binding); err != nil {
			t.Fatal(err)
		}
		wrapped := transport.PathConn(serverPath)
		if intercept != nil {
			wrapped = &policyAckInterceptPath{inner: serverPath, intercept: intercept}
		}
		attached, err := server.AttachPathBound(wrapped, spec, binding)
		if err != nil {
			t.Fatal(err)
		}
		*path.id = attached
	}
	if server.ActivePath() != serverA {
		t.Fatalf("initial active path=%d want=%d", server.ActivePath(), serverA)
	}
	return client, server, selector.ID, pathA.ID, pathB.ID, serverA, serverB
}

func serverPolicyIntercept(e *Engine) *policyAckIntercept {
	e.pathsMu.RLock()
	defer e.pathsMu.RUnlock()
	for _, slot := range e.paths {
		if path, ok := slot.conn.(*policyAckInterceptPath); ok {
			return path.intercept
		}
	}
	return nil
}

func policyAckPhaseName(phase proto.PolicyAckPhase) string {
	switch phase {
	case proto.PolicyAckPhasePrepare:
		return "prepare"
	case proto.PolicyAckPhaseFinal:
		return "final"
	default:
		return "unknown"
	}
}

var _ transport.PathConn = (*policyAckInterceptPath)(nil)
var _ transport.PathConn = (*policyControlDropPath)(nil)
