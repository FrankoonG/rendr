package engine

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

func TestBridgeAdmissionRejectionIsNotProtocolViolation(t *testing.T) {
	initialClient, initialServer := newMemoryPathPair()
	client, server := establishHelloAdmissionPair(t, initialClient, initialServer)
	clientPath, serverPath := newMemoryPathPair()
	serverDone := make(chan error, 1)
	go func() {
		hdr, proposal, err := ReadFirstFrame(serverPath)
		if err == nil {
			err = validateAdmissionHeader(hdr, proto.CtrlBridgeTag)
		}
		var tag proto.BridgeTagPayload
		if err == nil {
			tag, err = proto.DecodeBridgeTag(proposal)
		}
		if err == nil {
			err = PerformBridgeAck(serverPath, tag, server.LocalInstanceID(), proto.AckRejectAttach, "injected rejection")
		}
		serverDone <- err
	}()
	_, err := PerformClientBridgeAdmissionContext(context.Background(), clientPath, client, "a", transport.PathSpec{Transport: "memory"})
	if err == nil {
		t.Fatal("bridge rejection was accepted")
	}
	if !errors.Is(err, ErrPathAdmissionRejected) {
		t.Fatalf("bridge rejection error=%v, want %v", err, ErrPathAdmissionRejected)
	}
	if errors.Is(err, ErrPeerProtocol) {
		t.Fatalf("valid bridge rejection was misclassified as peer protocol failure: %v", err)
	}
	if serverErr := <-serverDone; serverErr != nil {
		t.Fatal(serverErr)
	}
	if got := len(client.Paths()); got != 1 {
		t.Fatalf("rejected bridge published client path: %v", client.Paths())
	}
	if got := len(server.Paths()); got != 1 {
		t.Fatalf("rejected bridge published server path: %v", server.Paths())
	}
}

func TestBridgeAdmissionMalformedAndMismatchedAckAreProtocolFailures(t *testing.T) {
	tests := []struct {
		name    string
		payload func(proto.BridgeTagPayload, *Engine) []byte
	}{
		{
			name: "malformed",
			payload: func(proto.BridgeTagPayload, *Engine) []byte {
				return []byte{1, 2, 3}
			},
		},
		{
			name: "binding mismatch",
			payload: func(tag proto.BridgeTagPayload, server *Engine) []byte {
				responderTargetID, err := server.LocalPathTargetID("a")
				if err != nil {
					panic(err)
				}
				ack := proto.BridgeAckPayload{
					BridgeID:          tag.BridgeID,
					AttachID:          tag.AttachID,
					InstanceID:        server.LocalInstanceID(),
					SessionEpoch:      tag.SessionEpoch,
					Direction:         tag.Direction,
					GraphRevision:     tag.GraphRevision,
					GraphDigest:       tag.GraphDigest,
					TargetID:          tag.TargetID,
					ResponderTargetID: responderTargetID,
					Code:              proto.AckOK,
				}
				ack.AttachID[0] ^= 0xff
				return ack.Encode()
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			initialClient, initialServer := newMemoryPathPair()
			client, server := establishHelloAdmissionPair(t, initialClient, initialServer)
			clientPath, serverPath := newMemoryPathPair()
			serverDone := make(chan error, 1)
			go func() {
				hdr, proposal, err := ReadFirstFrame(serverPath)
				if err == nil {
					err = validateAdmissionHeader(hdr, proto.CtrlBridgeTag)
				}
				var tag proto.BridgeTagPayload
				if err == nil {
					tag, err = proto.DecodeBridgeTag(proposal)
				}
				if err == nil {
					err = writeAdmissionCtrlContext(context.Background(), serverPath, proto.CtrlBridgeAck, test.payload(tag, server))
				}
				serverDone <- err
			}()
			_, err := PerformClientBridgeAdmissionContext(context.Background(), clientPath, client, "a", transport.PathSpec{Transport: "memory"})
			if !errors.Is(err, ErrPeerProtocol) {
				t.Fatalf("bridge admission error=%v, want %v", err, ErrPeerProtocol)
			}
			if errors.Is(err, ErrPathAdmissionRejected) {
				t.Fatalf("malformed peer response was classified as valid rejection: %v", err)
			}
			if serverErr := <-serverDone; serverErr != nil {
				t.Fatal(serverErr)
			}
			if got := len(client.Paths()); got != 1 {
				t.Fatalf("malformed bridge response published client path: %v", client.Paths())
			}
		})
	}
}

type helloAdmissionServerResult struct {
	engine *Engine
	err    error
}

type admissionDropPath struct {
	transport.PathConn
	mu    sync.Mutex
	drops map[string]int
}

type blockingAdmissionPath struct {
	transport.PathConn
	key         string
	entered     chan struct{}
	release     chan struct{}
	enteredOnce sync.Once
	releaseOnce sync.Once
}

func newBlockingAdmissionPath(pc transport.PathConn, key string) *blockingAdmissionPath {
	return &blockingAdmissionPath{
		PathConn: pc,
		key:      key,
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
	}
}

func (p *blockingAdmissionPath) Write(frame []byte) (int, error) {
	if admissionFrameKey(frame) == p.key {
		p.enteredOnce.Do(func() { close(p.entered) })
		<-p.release
	}
	return p.PathConn.Write(frame)
}

func (p *blockingAdmissionPath) unblock() {
	p.releaseOnce.Do(func() { close(p.release) })
}

func (p *admissionDropPath) remaining(key string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.drops[key]
}

func (p *admissionDropPath) Write(frame []byte) (int, error) {
	key := admissionFrameKey(frame)
	p.mu.Lock()
	if key != "" && p.drops[key] > 0 {
		p.drops[key]--
		p.mu.Unlock()
		return len(frame), nil
	}
	p.mu.Unlock()
	return p.PathConn.Write(frame)
}

func admissionFrameKey(frame []byte) string {
	if len(frame) < proto.HeaderSize {
		return ""
	}
	hdr, err := proto.DecodeHeader(frame[:proto.HeaderSize])
	if err != nil || hdr.Type != proto.FrameCtrl {
		return ""
	}
	switch proto.CtrlCodeFromFlags(hdr.Flags) {
	case proto.CtrlPathAdmissionCommit:
		return "commit"
	case proto.CtrlPathAdmissionConfirm:
		return "confirm"
	case proto.CtrlPathAdmissionAck:
		ack, err := proto.DecodePathAdmissionAck(frame[proto.HeaderSize:])
		if err != nil {
			return ""
		}
		switch ack.Phase {
		case proto.PathAdmissionPhasePrepared:
			return "prepared"
		case proto.PathAdmissionPhaseCommitted:
			return "committed"
		case proto.PathAdmissionPhaseFinal:
			return "final"
		case proto.PathAdmissionPhaseActivated:
			return "activated"
		}
	}
	return ""
}

func TestHelloAdmissionPublishesBothSidesAndCarriesData(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
	)
	flowID := NewClientFlowID()
	client := New(SideClient, flowID, Limits{}.Clamp())
	t.Cleanup(func() { _ = client.Close() })
	if err := client.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	clientInstance := NewInstanceID()
	serverInstance := NewInstanceID()
	client.SetLocalInstanceID(clientInstance)

	clientPath, serverPath := newMemoryPathPair()
	serverDone := make(chan helloAdmissionServerResult, 1)
	go func() {
		hdr, proposalWire, err := ReadFirstFrame(serverPath)
		if err != nil {
			serverDone <- helloAdmissionServerResult{err: err}
			return
		}
		if err := validateAdmissionHeader(hdr, proto.CtrlHello); err != nil {
			serverDone <- helloAdmissionServerResult{err: err}
			return
		}
		hello, err := proto.DecodeHello(proposalWire)
		if err != nil {
			serverDone <- helloAdmissionServerResult{err: err}
			return
		}
		server := New(SideServer, hello.FlowID, Limits{}.Clamp())
		server.SetLocalInstanceID(serverInstance)
		server.SetPeerInstanceID(hello.InstanceID)
		server.SetPeerKind(PeerRendr)
		server.SetPeerCaps(hello.Caps)
		if err := server.AcceptPeerNegotiation(hello.Negotiation, hello.LocalTXManifest); err != nil {
			serverDone <- helloAdmissionServerResult{engine: server, err: err}
			return
		}
		if err := server.MirrorPeerGraphForLocal(); err != nil {
			serverDone <- helloAdmissionServerResult{engine: server, err: err}
			return
		}
		localTargetID, err := server.LocalPathTargetID("a")
		if err != nil {
			serverDone <- helloAdmissionServerResult{engine: server, err: err}
			return
		}
		pathID, err := server.PreparePathBound(serverPath, transport.PathSpec{Transport: "memory"}, PathBinding{
			LocalTXTargetID: localTargetID,
			PeerTXTargetID:  hello.InitialTargetID,
		})
		if err == nil {
			err = PerformServerHelloAdmission(context.Background(), serverPath, server, pathID,
				serverInstance, 0, localTargetID, hello.InitialTargetID, hello, proposalWire)
		}
		serverDone <- helloAdmissionServerResult{engine: server, err: err}
	}()

	admission, err := PerformClientHelloAdmissionContext(context.Background(), clientPath, client,
		clientInstance, 0, "a", transport.PathSpec{Transport: "memory"})
	if err != nil {
		t.Fatalf("client admission: %v", err)
	}
	client.SetPeerKind(PeerRendr)
	client.SetPeerInstanceID(admission.Ack.InstanceID)
	client.SetPeerCaps(admission.Ack.Caps)
	var server *Engine
	select {
	case result := <-serverDone:
		if result.err != nil {
			t.Fatalf("server admission: %v", result.err)
		}
		server = result.engine
	case <-time.After(2 * time.Second):
		t.Fatal("server admission did not finish")
	}
	t.Cleanup(func() { _ = server.Close() })
	if client.ActivePath() == 0 || server.ActivePath() == 0 {
		t.Fatalf("active paths client/server=%d/%d", client.ActivePath(), server.ActivePath())
	}
	if got := client.LocalGraphManifest(); got.RootID != ids["root"] {
		t.Fatalf("client graph root changed: %x", got.RootID)
	}

	want := []byte("admission-data")
	if _, err := client.SendData(want); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(want))
	n, err := server.Recv(buf)
	if err != nil || string(buf[:n]) != string(want) {
		t.Fatalf("server recv=%q err=%v want=%q", buf[:n], err, want)
	}
}

func TestHelloAdmissionRecoversEveryDroppedPhase(t *testing.T) {
	tests := []struct {
		name       string
		clientDrop string
		serverDrop string
	}{
		{name: "prepared", serverDrop: "prepared"},
		{name: "commit", clientDrop: "commit"},
		{name: "committed", serverDrop: "committed"},
		{name: "confirm", clientDrop: "confirm"},
		{name: "final", serverDrop: "final"},
		{name: "activated", serverDrop: "activated"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clientBase, serverBase := newMemoryPathPair()
			clientPath := &admissionDropPath{PathConn: clientBase, drops: make(map[string]int)}
			serverPath := &admissionDropPath{PathConn: serverBase, drops: make(map[string]int)}
			if test.clientDrop != "" {
				clientPath.drops[test.clientDrop] = 1
			}
			if test.serverDrop != "" {
				serverPath.drops[test.serverDrop] = 1
			}
			client, server := establishHelloAdmissionPair(t, clientPath, serverPath)
			if test.clientDrop != "" && clientPath.remaining(test.clientDrop) != 0 {
				t.Fatalf("client fault %q was not injected", test.clientDrop)
			}
			if test.serverDrop != "" && serverPath.remaining(test.serverDrop) != 0 {
				t.Fatalf("server fault %q was not injected", test.serverDrop)
			}
			want := []byte("phase-loss-" + test.name)
			if _, err := client.SendData(want); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, len(want))
			n, err := server.Recv(buf)
			if err != nil || string(buf[:n]) != string(want) {
				t.Fatalf("server recv=%q err=%v want=%q", buf[:n], err, want)
			}
		})
	}
}

func TestBridgeAdmissionSupersedesSameLeafWithoutDataLoss(t *testing.T) {
	initialClientPath, initialServerPath := newMemoryPathPair()
	client, server := establishHelloAdmissionPair(t, initialClientPath, initialServerPath)
	waitAdmissionCondition(t, time.Second, "initial admission cleanup", func() bool {
		clientState, serverState := snapshotAdmissionSets(client), snapshotAdmissionSets(server)
		return clientState.byPath == 0 && clientState.retained == 0 && clientState.predecessors == 0 &&
			serverState.byPath == 0 && serverState.retained == 0 && serverState.predecessors == 0
	})
	oldClient, oldServer := client.ActivePath(), server.ActivePath()

	clientPath, serverPath := newMemoryPathPair()
	admission := performBridgeAdmissionPair(t, client, server, clientPath, serverPath)
	if admission.PathID == oldClient || client.ActivePath() != admission.PathID {
		t.Fatalf("client active=%d old=%d admitted=%d", client.ActivePath(), oldClient, admission.PathID)
	}
	if server.ActivePath() == oldServer {
		t.Fatalf("server retained old path %d as active", oldServer)
	}

	wantUp := []byte("bridge-up")
	if _, err := client.SendData(wantUp); err != nil {
		t.Fatal(err)
	}
	up := make([]byte, len(wantUp))
	if n, err := server.Recv(up); err != nil || string(up[:n]) != string(wantUp) {
		t.Fatalf("upstream=%q err=%v", up[:n], err)
	}
	wantDown := []byte("bridge-down")
	if _, err := server.SendData(wantDown); err != nil {
		t.Fatal(err)
	}
	down := make([]byte, len(wantDown))
	if n, err := client.Recv(down); err != nil || string(down[:n]) != string(wantDown) {
		t.Fatalf("downstream=%q err=%v", down[:n], err)
	}
}

func TestBridgeAdmissionRecoversEveryDroppedPhase(t *testing.T) {
	tests := []struct {
		name       string
		clientDrop string
		serverDrop string
	}{
		{name: "prepared", serverDrop: "prepared"},
		{name: "commit", clientDrop: "commit"},
		{name: "committed", serverDrop: "committed"},
		{name: "confirm", clientDrop: "confirm"},
		{name: "final", serverDrop: "final"},
		{name: "activated", serverDrop: "activated"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			initialClient, initialServer := newMemoryPathPair()
			client, server := establishHelloAdmissionPair(t, initialClient, initialServer)
			oldClient, oldServer := client.ActivePath(), server.ActivePath()

			clientBase, serverBase := newMemoryPathPair()
			clientPath := &admissionDropPath{PathConn: clientBase, drops: make(map[string]int)}
			serverPath := &admissionDropPath{PathConn: serverBase, drops: make(map[string]int)}
			if test.clientDrop != "" {
				clientPath.drops[test.clientDrop] = 1
			}
			if test.serverDrop != "" {
				serverPath.drops[test.serverDrop] = 1
			}
			admission := performBridgeAdmissionPair(t, client, server, clientPath, serverPath)
			if test.clientDrop != "" && clientPath.remaining(test.clientDrop) != 0 {
				t.Fatalf("client fault %q was not injected", test.clientDrop)
			}
			if test.serverDrop != "" && serverPath.remaining(test.serverDrop) != 0 {
				t.Fatalf("server fault %q was not injected", test.serverDrop)
			}
			if admission.PathID == oldClient || client.ActivePath() != admission.PathID || server.ActivePath() == oldServer {
				t.Fatalf("replacement client=%d/%d server=%d/%d", oldClient, client.ActivePath(), oldServer, server.ActivePath())
			}
			waitAdmissionCondition(t, time.Second, "bridge admission cleanup", func() bool {
				clientState, serverState := snapshotAdmissionSets(client), snapshotAdmissionSets(server)
				return clientState.byPath == 0 && clientState.retained == 0 && clientState.predecessors == 0 &&
					serverState.byPath == 0 && serverState.retained == 0 && serverState.predecessors == 0
			})
			assertAdmissionPayload(t, client, server, []byte("bridge-phase-up-"+test.name))
			assertAdmissionPayload(t, server, client, []byte("bridge-phase-down-"+test.name))
		})
	}
}

func TestBridgeAdmissionRemovalWaitsForResponderActivation(t *testing.T) {
	manifest, ids := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a", "b"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
		runtimeNode(proto.GraphNodeKindPath, "b"),
	)
	initialClient, initialServer := newMemoryPathPair()
	client, server := establishHelloAdmissionPairWithGraph(t, initialClient, initialServer, manifest, "a")

	clientPath, serverBase := newMemoryPathPair()
	serverPath := newBlockingAdmissionPath(serverBase, "activated")
	t.Cleanup(serverPath.unblock)
	serverDone := startServerBridgeAdmission(server, serverPath)
	type clientResult struct {
		admission ClientBridgeAdmission
		err       error
	}
	clientDone := make(chan clientResult, 1)
	go func() {
		admission, err := PerformClientBridgeAdmissionContext(context.Background(), clientPath, client, "b",
			transport.PathSpec{Transport: "memory"})
		clientDone <- clientResult{admission: admission, err: err}
	}()

	select {
	case <-serverPath.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("responder did not reach terminal ACTIVATED write")
	}

	var pathID uint32
	var slot *pathSlot
	waitAdmissionCondition(t, time.Second, "admitted b path publication", func() bool {
		client.pathsMu.RLock()
		defer client.pathsMu.RUnlock()
		for id, candidate := range client.paths {
			if candidate.localTXTargetID == ids["b"] {
				pathID, slot = id, candidate
				return true
			}
		}
		return false
	})

	removed := make(chan error, 1)
	go func() { removed <- client.RemovePath(pathID) }()
	waitAdmissionCondition(t, time.Second, "removal admission wait", func() bool {
		return slot.removeWaiters.Load() > 0
	})
	select {
	case <-slot.admissionDone:
		t.Fatal("admission barrier closed before responder ACTIVATED was received")
	default:
	}
	select {
	case err := <-removed:
		t.Fatalf("RemovePath crossed unreceived responder activation: %v", err)
	default:
	}

	serverPath.unblock()
	select {
	case result := <-clientDone:
		if result.err != nil {
			t.Fatalf("client bridge admission: %v", result.err)
		}
		if result.admission.PathID != pathID {
			t.Fatalf("client admitted path=%d, want %d", result.admission.PathID, pathID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("client admission did not finish after responder activation release")
	}
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server bridge admission: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server admission did not finish after responder activation release")
	}
	select {
	case err := <-removed:
		if err != nil {
			t.Fatalf("remove admitted path: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RemovePath did not resume after responder activation")
	}
	if got := client.Paths(); len(got) != 1 || got[0].ID == pathID {
		t.Fatalf("remaining client paths=%v after removing admitted path %d", got, pathID)
	}
}

func performBridgeAdmissionPair(t *testing.T, client, server *Engine, clientPath, serverPath transport.PathConn) ClientBridgeAdmission {
	return performBridgeAdmissionPairTarget(t, client, server, clientPath, serverPath, "a")
}

func performBridgeAdmissionPairTarget(t *testing.T, client, server *Engine, clientPath, serverPath transport.PathConn, targetName string) ClientBridgeAdmission {
	t.Helper()
	serverDone := startServerBridgeAdmission(server, serverPath)
	admission, err := PerformClientBridgeAdmissionContext(context.Background(), clientPath, client, targetName,
		transport.PathSpec{Transport: "memory"})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	return admission
}

func startServerBridgeAdmission(server *Engine, serverPath transport.PathConn) <-chan error {
	serverDone := make(chan error, 1)
	go func() {
		hdr, proposalWire, err := ReadFirstFrame(serverPath)
		if err != nil {
			serverDone <- err
			return
		}
		if err := validateAdmissionHeader(hdr, proto.CtrlBridgeTag); err != nil {
			serverDone <- err
			return
		}
		tag, err := proto.DecodeBridgeTag(proposalWire)
		if err == nil {
			err = server.ValidateBridgeBinding(tag)
		}
		var peerName string
		if err == nil {
			peerName, err = server.PeerPathName(tag.TargetID)
		}
		var localTargetID proto.TargetID
		if err == nil {
			localTargetID, err = server.LocalPathTargetID(peerName)
		}
		var pathID uint32
		if err == nil {
			pathID, err = server.PreparePathBound(serverPath, transport.PathSpec{Transport: "memory"}, PathBinding{
				LocalTXTargetID: localTargetID, PeerTXTargetID: tag.TargetID,
			})
		}
		if err == nil {
			err = PerformServerBridgeAdmission(context.Background(), serverPath, server, pathID,
				server.LocalInstanceID(), localTargetID, tag, proposalWire)
		}
		serverDone <- err
	}()
	return serverDone
}

func assertAdmissionPayload(t *testing.T, sender, receiver *Engine, payload []byte) {
	t.Helper()
	if _, err := sender.SendData(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	n, err := receiver.Recv(got)
	if err != nil || string(got[:n]) != string(payload) {
		t.Fatalf("payload=%q err=%v want=%q", got[:n], err, payload)
	}
}

func establishHelloAdmissionPair(t *testing.T, clientPath, serverPath transport.PathConn) (*Engine, *Engine) {
	t.Helper()
	manifest, _ := runtimeGraph(t,
		runtimeNode(proto.GraphNodeKindSelector, "root", "a"),
		runtimeNode(proto.GraphNodeKindPath, "a"),
	)
	return establishHelloAdmissionPairWithGraph(t, clientPath, serverPath, manifest, "a")
}

func establishHelloAdmissionPairWithGraph(t *testing.T, clientPath, serverPath transport.PathConn, manifest proto.GraphManifest, initialName string) (*Engine, *Engine) {
	t.Helper()
	client := New(SideClient, NewClientFlowID(), Limits{ZombieMaxMigrations: 10}.Clamp())
	if err := client.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	clientInstance, serverInstance := NewInstanceID(), NewInstanceID()
	client.SetLocalInstanceID(clientInstance)
	serverDone := make(chan helloAdmissionServerResult, 1)
	go func() {
		hdr, proposalWire, err := ReadFirstFrame(serverPath)
		if err != nil {
			serverDone <- helloAdmissionServerResult{err: err}
			return
		}
		if err := validateAdmissionHeader(hdr, proto.CtrlHello); err != nil {
			serverDone <- helloAdmissionServerResult{err: err}
			return
		}
		hello, err := proto.DecodeHello(proposalWire)
		if err != nil {
			serverDone <- helloAdmissionServerResult{err: err}
			return
		}
		server := New(SideServer, hello.FlowID, Limits{ZombieMaxMigrations: 10}.Clamp())
		server.SetLocalInstanceID(serverInstance)
		server.SetPeerInstanceID(hello.InstanceID)
		server.SetPeerKind(PeerRendr)
		server.SetPeerCaps(hello.Caps)
		if err := server.AcceptPeerNegotiation(hello.Negotiation, hello.LocalTXManifest); err == nil {
			err = server.MirrorPeerGraphForLocal()
		}
		var localTargetID proto.TargetID
		if err == nil {
			localTargetID, err = server.LocalPathTargetID(initialName)
		}
		var pathID uint32
		if err == nil {
			pathID, err = server.PreparePathBound(serverPath, transport.PathSpec{Transport: "memory"}, PathBinding{
				LocalTXTargetID: localTargetID, PeerTXTargetID: hello.InitialTargetID,
			})
		}
		if err == nil {
			err = PerformServerHelloAdmission(context.Background(), serverPath, server, pathID,
				serverInstance, 0, localTargetID, hello.InitialTargetID, hello, proposalWire)
		}
		serverDone <- helloAdmissionServerResult{engine: server, err: err}
	}()
	admission, err := PerformClientHelloAdmissionContext(context.Background(), clientPath, client,
		clientInstance, 0, initialName, transport.PathSpec{Transport: "memory"})
	if err != nil {
		_ = client.Close()
		t.Fatal(err)
	}
	client.SetPeerKind(PeerRendr)
	client.SetPeerInstanceID(admission.Ack.InstanceID)
	client.SetPeerCaps(admission.Ack.Caps)
	result := <-serverDone
	if result.err != nil {
		_ = client.Close()
		if result.engine != nil {
			_ = result.engine.Close()
		}
		t.Fatal(result.err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = result.engine.Close()
	})
	return client, result.engine
}
