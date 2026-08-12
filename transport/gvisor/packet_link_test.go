package gvisor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/proto"
	"github.com/FrankoonG/rendr/transport"
)

type packetLinkBlockingCloseConn struct {
	net.Conn
	started chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (conn *packetLinkBlockingCloseConn) Close() error {
	conn.once.Do(func() { close(conn.started) })
	<-conn.release
	return conn.Conn.Close()
}

func TestPacketLinkCloseJoinsConcurrentOwnerCloser(t *testing.T) {
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	wire := newPacketWire(packetConn, false)
	owner, err := newLinkOwner(
		linkID{0x91}, linkSecret{0x92}, leafmobility.RoleDialer,
		[4]byte{10, 64, 0, 91}, wire,
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40991}, nil, func([]byte) {},
	)
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer right.Close()
	release := make(chan struct{})
	endpoint := &packetLinkBlockingCloseConn{Conn: left, started: make(chan struct{}), release: release}
	if err := owner.bindEndpoint(endpoint, nil); err != nil {
		close(release)
		t.Fatal(err)
	}

	firstDone := make(chan struct{})
	go func() {
		owner.failClosed(errors.New("injected concurrent owner close"))
		close(firstDone)
	}()
	select {
	case <-endpoint.started:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("first owner closer did not reach endpoint Close")
	}
	joined := make(chan struct{})
	go func() {
		owner.close()
		close(joined)
	}()
	select {
	case <-joined:
		close(release)
		t.Fatal("second owner Close returned before the active closer finished")
	case <-time.After(30 * time.Millisecond):
	}

	close(release)
	for name, done := range map[string]<-chan struct{}{"first closer": firstDone, "joined closer": joined, "owner": owner.done} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("%s did not finish", name)
		}
	}
}

func TestPacketLinkChallengeRoundTripUsesCandidateTuple(t *testing.T) {
	requireOuterPacketSupport(t)
	listener, err := ListenPacket("127.0.0.1:0", WithTrustedCarrier())
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, server := dialAndAccept(t, listener)
	defer client.Close()
	defer server.Close()
	clientOwner := client.(*retainedPathConn).link
	serverOwner := server.(*retainedPathConn).link
	clientOwner.mu.Lock()
	remote := cloneAddr(clientOwner.peerRemote)
	generation := clientOwner.localGeneration + 1
	clientOwner.mu.Unlock()
	candidate, _, err := clientOwner.openUDPCandidate(context.Background(), remote)
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.close()
	control := outerControl{
		Transaction: linkTransaction{1}, Agreement: linkAgreement{2}, Nonce: linkNonce{3}, ReceiveNext: 1,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := clientOwner.challengeCandidate(ctx, candidate, remote, generation, control); err != nil {
		serverOwner.mu.Lock()
		pending := serverOwner.pendingPeer
		peerGeneration := serverOwner.peerGeneration
		peerRemote := cloneAddr(serverOwner.peerRemote)
		serverOwner.mu.Unlock()
		t.Fatalf("challenge round trip: %v; server pending=%+v generation=%d remote=%v",
			err, pending, peerGeneration, peerRemote)
	}
	serverOwner.mu.Lock()
	pending := serverOwner.pendingPeer
	serverOwner.mu.Unlock()
	if pending == nil || pending.generation != generation || pending.control != control {
		t.Fatalf("server pending challenge=%+v", pending)
	}
}

func TestPacketLinkDataCannotPoisonPeerTuple(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	wire := newPacketWire(conn, false)
	expected := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 41001}
	var injected atomic.Int32
	owner, err := newLinkOwner(
		linkID{1}, linkSecret{2}, leafmobility.RoleAcceptor,
		[4]byte{10, 64, 0, 1}, wire, expected, nil,
		func([]byte) { injected.Add(1) },
	)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.close()
	packet := make([]byte, 20)
	packet[0] = 0x45
	copy(packet[12:16], owner.virtualIP[:])
	copy(packet[16:20], serverIPv4[:])
	datagram, err := encodeOuterData(owner.id, 1, 1, packet, owner.secret)
	if err != nil {
		t.Fatal(err)
	}
	attacker := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 41002}
	owner.handleDatagram(wire, attacker, datagram)
	if got := injected.Load(); got != 0 {
		t.Fatalf("attacker DATA injections=%d want=0", got)
	}
	owner.mu.Lock()
	remote := cloneAddr(owner.peerRemote)
	owner.mu.Unlock()
	if !addrEqual(remote, expected) {
		t.Fatalf("attacker DATA changed peer remote from %v to %v", expected, remote)
	}

	owner.handleDatagram(wire, expected, datagram)
	if got := injected.Load(); got != 1 {
		t.Fatalf("authenticated tuple DATA injections=%d want=1", got)
	}
	candidateConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	candidate := newPacketWire(candidateConn, false)
	owner.handleDatagram(candidate, expected, datagram)
	if got := injected.Load(); got != 1 {
		t.Fatalf("private staged candidate injected DATA: count=%d", got)
	}
	owner.mu.Lock()
	owner.wires[candidate] = struct{}{}
	owner.predecessor = wire
	owner.predecessorUntil = time.Now().Add(time.Second)
	owner.active = candidate
	owner.activationPending = true
	owner.mu.Unlock()
	publishedData, err := encodeOuterData(owner.id, 1, 2, packet, owner.secret)
	if err != nil {
		t.Fatal(err)
	}
	owner.handleDatagram(candidate, expected, publishedData)
	if got := injected.Load(); got != 2 {
		t.Fatalf("published candidate DATA injections=%d want=2", got)
	}
	owner.mu.Lock()
	owner.activationPending = false
	owner.mu.Unlock()
	activatedData, err := encodeOuterData(owner.id, 1, 3, packet, owner.secret)
	if err != nil {
		t.Fatal(err)
	}
	owner.handleDatagram(candidate, expected, activatedData)
	if got := injected.Load(); got != 3 {
		t.Fatalf("activated candidate DATA injections=%d want=3", got)
	}
}

func TestPacketLinkChallengeDoesNotPublishTuple(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	wire := newPacketWire(conn, false)
	expected := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 42001}
	owner, err := newLinkOwner(
		linkID{1}, linkSecret{2}, leafmobility.RoleAcceptor,
		[4]byte{10, 64, 0, 2}, wire, expected, nil, func([]byte) {},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.close()
	control := outerControl{
		Transaction: linkTransaction{1}, Agreement: linkAgreement{2}, Nonce: linkNonce{3}, ReceiveNext: 1,
	}
	payload, _ := marshalOuterControl(control)
	challenge, err := encodeOuterControl(outerFrame{
		Type: outerTypePathChallenge, LinkID: owner.id, Generation: 2, Payload: payload,
	}, owner.secret)
	if err != nil {
		t.Fatal(err)
	}
	candidate := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 42002}
	owner.handleDatagram(wire, candidate, challenge)
	owner.mu.Lock()
	remoteAfterChallenge := cloneAddr(owner.peerRemote)
	pending := owner.pendingPeer
	owner.mu.Unlock()
	if !addrEqual(remoteAfterChallenge, expected) || pending == nil {
		t.Fatalf("challenge remote=%v pending=%+v", remoteAfterChallenge, pending)
	}
	markPendingPeerQualified(t, owner, candidate, 2, control)

	commit, err := encodeOuterControl(outerFrame{
		Type: outerTypePathCommit, LinkID: owner.id, Generation: 2, Payload: payload,
	}, owner.secret)
	if err != nil {
		t.Fatal(err)
	}
	owner.handleDatagram(wire, candidate, commit)
	owner.mu.Lock()
	remoteAfterCommit := cloneAddr(owner.peerRemote)
	generation := owner.peerGeneration
	owner.mu.Unlock()
	if !addrEqual(remoteAfterCommit, candidate) || generation != 2 {
		t.Fatalf("commit remote=%v generation=%d", remoteAfterCommit, generation)
	}

	owner.handleDatagram(wire, expected, challenge)
	owner.mu.Lock()
	staleRemote := cloneAddr(owner.peerRemote)
	owner.mu.Unlock()
	if !addrEqual(staleRemote, candidate) {
		t.Fatalf("stale challenge reverted committed tuple to %v", staleRemote)
	}
}

func TestPacketLinkAbortReplayLedgerRejectsABAAndGCsOnCommit(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	wire := newPacketWire(conn, false)
	initial := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 42501}
	owner, err := newLinkOwner(
		linkID{1}, linkSecret{2}, leafmobility.RoleAcceptor,
		[4]byte{10, 64, 0, 22}, wire, initial, nil, func([]byte) {},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.close()
	candidate := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 42502}
	controlA := outerControl{
		Transaction: linkTransaction{4}, Agreement: linkAgreement{5}, Nonce: linkNonce{6}, ReceiveNext: 1,
	}
	controlB := outerControl{
		Transaction: linkTransaction{7}, Agreement: linkAgreement{8}, Nonce: linkNonce{9}, ReceiveNext: 1,
	}
	owner.handleDatagram(wire, candidate, mustOuterControl(t, owner, outerTypePathAbort, 2, controlA))
	owner.handleDatagram(wire, candidate, mustOuterControl(t, owner, outerTypePathChallenge, 2, controlB))
	owner.handleDatagram(wire, candidate, mustOuterControl(t, owner, outerTypePathAbort, 2, controlB))
	owner.handleDatagram(wire, candidate, mustOuterControl(t, owner, outerTypePathChallenge, 2, controlA))
	owner.handleDatagram(wire, candidate, mustOuterControl(t, owner, outerTypePathCommit, 2, controlA))
	owner.mu.Lock()
	remote := cloneAddr(owner.peerRemote)
	generation := owner.peerGeneration
	pending := owner.pendingPeer
	replays := len(owner.peerReplay)
	owner.mu.Unlock()
	if generation != 1 || !addrEqual(remote, initial) || pending != nil || replays != 2 {
		t.Fatalf("ABA replay state generation=%d remote=%v pending=%+v replays=%d", generation, remote, pending, replays)
	}

	controlC := outerControl{
		Transaction: linkTransaction{10}, Agreement: linkAgreement{11}, Nonce: linkNonce{12}, ReceiveNext: 1,
	}
	owner.handleDatagram(wire, candidate, mustOuterControl(t, owner, outerTypePathChallenge, 2, controlC))
	markPendingPeerQualified(t, owner, candidate, 2, controlC)
	owner.handleDatagram(wire, candidate, mustOuterControl(t, owner, outerTypePathCommit, 2, controlC))
	owner.mu.Lock()
	generation = owner.peerGeneration
	replays = len(owner.peerReplay)
	owner.mu.Unlock()
	if generation != 2 || replays != 0 {
		t.Fatalf("commit did not garbage-collect replay ledger: generation=%d replays=%d", generation, replays)
	}
}

func TestPacketLinkAbortReplayLedgerIsBounded(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	wire := newPacketWire(conn, false)
	remote := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 42601}
	owner, err := newLinkOwner(
		linkID{1}, linkSecret{2}, leafmobility.RoleAcceptor,
		[4]byte{10, 64, 0, 23}, wire, remote, nil, func([]byte) {},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.close()
	for index := 0; index < maxPeerReplayEntries+1; index++ {
		value := byte(index + 1)
		control := outerControl{
			Transaction: linkTransaction{value}, Agreement: linkAgreement{value}, Nonce: linkNonce{value}, ReceiveNext: 1,
		}
		owner.handleDatagram(wire, remote, mustOuterControl(t, owner, outerTypePathAbort, 2, control))
	}
	owner.mu.Lock()
	replays := len(owner.peerReplay)
	owner.mu.Unlock()
	if replays != maxPeerReplayEntries {
		t.Fatalf("replay entries=%d want bounded maximum=%d", replays, maxPeerReplayEntries)
	}
}

func TestPacketLinkConcurrentStaleTrafficCannotRevertCommit(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	wire := newPacketWire(conn, false)
	initial := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 43001}
	owner, err := newLinkOwner(
		linkID{1}, linkSecret{2}, leafmobility.RoleAcceptor,
		[4]byte{10, 64, 0, 3}, wire, initial, nil, func([]byte) {},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.close()
	first := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 43002}
	firstControl := outerControl{
		Transaction: linkTransaction{1}, Agreement: linkAgreement{1}, Nonce: linkNonce{1}, ReceiveNext: 1,
	}
	challenge2 := mustOuterControl(t, owner, outerTypePathChallenge, 2, firstControl)
	commit2 := mustOuterControl(t, owner, outerTypePathCommit, 2, firstControl)
	owner.handleDatagram(wire, first, challenge2)
	markPendingPeerQualified(t, owner, first, 2, firstControl)
	owner.handleDatagram(wire, first, commit2)

	second := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 43003}
	secondControl := outerControl{
		Transaction: linkTransaction{2}, Agreement: linkAgreement{2}, Nonce: linkNonce{2}, ReceiveNext: 1,
	}
	challenge3 := mustOuterControl(t, owner, outerTypePathChallenge, 3, secondControl)
	commit3 := mustOuterControl(t, owner, outerTypePathCommit, 3, secondControl)
	owner.handleDatagram(wire, second, challenge3)
	markPendingPeerQualified(t, owner, second, 3, secondControl)
	owner.handleDatagram(wire, second, commit3)

	packet := make([]byte, 20)
	packet[0] = 0x45
	copy(packet[12:16], owner.virtualIP[:])
	copy(packet[16:20], serverIPv4[:])
	staleData, err := encodeOuterData(owner.id, 1, 1, packet, owner.secret)
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	for range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for range 100 {
				owner.handleDatagram(wire, initial, staleData)
				owner.handleDatagram(wire, first, challenge2)
				owner.handleDatagram(wire, first, commit2)
				owner.handleDatagram(wire, second, commit3)
			}
		}()
	}
	wait.Wait()
	owner.mu.Lock()
	remote := cloneAddr(owner.peerRemote)
	generation := owner.peerGeneration
	owner.mu.Unlock()
	if generation != 3 || !addrEqual(remote, second) {
		t.Fatalf("stale traffic reverted peer mapping to generation=%d remote=%v", generation, remote)
	}
}

func TestPeerRebindCommitAdvancesRouteRefreshBaseline(t *testing.T) {
	if expectedPacketLinkOperation() == 0 {
		t.Skip("route refresh is enabled only for the driven packet-link build")
	}
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	wire := newPacketWire(conn, false)
	initial := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 43101}
	owner, err := newLinkOwner(
		linkID{31}, linkSecret{32}, leafmobility.RoleAcceptor,
		[4]byte{10, 64, 0, 33}, wire, initial, nil, func([]byte) {},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.close()
	if _, err := newPacketLinkClaim(owner, leafmobility.RoleAcceptor); err != nil {
		t.Fatal(err)
	}
	local := conn.LocalAddr().(*net.UDPAddr)
	initialRoute := mustOuterRouteObservation(t, outerUDPIPv4, local, initial, 1, 1260)
	candidate := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 43102}
	candidateRoute := mustOuterRouteObservation(t, outerUDPIPv4, local, candidate, 1, 1260)
	current := initialRoute
	owner.observeRoute = func(context.Context, *packetWire, net.Addr) (routeObservation, error) {
		return current, nil
	}
	refreshes := make(chan leafmobility.RefreshEvidence, 1)
	cancel, err := owner.subscribeRefresh(context.Background(), func(evidence leafmobility.RefreshEvidence) {
		refreshes <- evidence
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	control := outerControl{
		Transaction: linkTransaction{33}, Agreement: linkAgreement{34}, Nonce: linkNonce{35}, ReceiveNext: 1,
	}
	owner.mu.Lock()
	owner.pendingPeer = &peerCandidate{
		generation: 2, control: control, wire: wire, remote: cloneAddr(candidate), route: candidateRoute,
		qualified: true, expires: time.Now().Add(time.Second),
	}
	owner.mu.Unlock()
	current = candidateRoute
	owner.handleDatagram(wire, candidate, mustOuterControl(t, owner, outerTypePathCommit, 2, control))
	if !owner.observeRefresh(context.Background()) {
		t.Fatal("post-rebind route observation failed")
	}
	owner.mu.Lock()
	remote := cloneAddr(owner.peerRemote)
	baseline := owner.routeBaseline
	owner.mu.Unlock()
	if !addrEqual(remote, candidate) || baseline != candidateRoute.digest {
		t.Fatalf("peer commit remote=%v baseline=%x want %v/%x", remote, baseline, candidate, candidateRoute.digest)
	}
	select {
	case evidence := <-refreshes:
		t.Fatalf("valid peer rebind emitted false route refresh: %+v", evidence)
	case <-time.After(50 * time.Millisecond):
	}
}

func mustOuterControl(
	t testing.TB,
	owner *linkOwner,
	typ outerType,
	generation uint64,
	control outerControl,
) []byte {
	t.Helper()
	payload, err := marshalOuterControl(control)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := encodeOuterControl(outerFrame{
		Type: typ, LinkID: owner.id, Generation: generation, Payload: payload,
	}, owner.secret)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func markPendingPeerQualified(
	t testing.TB,
	owner *linkOwner,
	remote *net.UDPAddr,
	generation uint64,
	control outerControl,
) {
	t.Helper()
	local := owner.active.conn.LocalAddr().(*net.UDPAddr)
	route := mustOuterRouteObservation(t, outerUDPIPv4, local, remote, 1, 1260)
	owner.observeRoute = func(context.Context, *packetWire, net.Addr) (routeObservation, error) {
		return route, nil
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.pendingPeer == nil || owner.pendingPeer.generation != generation ||
		owner.pendingPeer.control != control || !addrEqual(owner.pendingPeer.remote, remote) {
		t.Fatalf("cannot qualify pending peer: %+v", owner.pendingPeer)
	}
	owner.pendingPeer.qualified = true
	owner.pendingPeer.route = route
}

func TestPacketCarrierSessionsHaveIndependentIdentityAndLifetime(t *testing.T) {
	requireOuterPacketSupport(t)
	listener, err := ListenPacket("127.0.0.1:0", WithTrustedCarrier())
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client1, server1 := dialAndAccept(t, listener)
	defer client1.Close()
	defer server1.Close()
	client2, server2 := dialAndAccept(t, listener)
	defer client2.Close()
	defer server2.Close()

	clientLink1 := client1.(*retainedPathConn).link
	clientLink2 := client2.(*retainedPathConn).link
	serverLink1 := server1.(*retainedPathConn).link
	serverLink2 := server2.(*retainedPathConn).link
	if clientLink1.id == clientLink2.id || serverLink1.id == serverLink2.id ||
		clientLink1.virtualIP == clientLink2.virtualIP || serverLink1.virtualIP == serverLink2.virtualIP {
		t.Fatalf("packet links reused identity: client ids=%x/%x ips=%v/%v server ids=%x/%x ips=%v/%v",
			clientLink1.id, clientLink2.id, clientLink1.virtualIP, clientLink2.virtualIP,
			serverLink1.id, serverLink2.id, serverLink1.virtualIP, serverLink2.virtualIP)
	}
	resources := []leafmobility.ResourceID{
		client1.(leafmobility.Provider).LeafMobilityClaim().Snapshot().ResourceID,
		server1.(leafmobility.Provider).LeafMobilityClaim().Snapshot().ResourceID,
		client2.(leafmobility.Provider).LeafMobilityClaim().Snapshot().ResourceID,
		server2.(leafmobility.Provider).LeafMobilityClaim().Snapshot().ResourceID,
	}
	if expectedPacketLinkOperation() != 0 {
		seen := make(map[leafmobility.ResourceID]struct{}, len(resources))
		for _, resource := range resources {
			if resource == (leafmobility.ResourceID{}) {
				t.Fatal("driven packet endpoint has zero mobility resource")
			}
			if _, exists := seen[resource]; exists {
				t.Fatalf("packet endpoints share mobility resource %x", resource)
			}
			seen[resource] = struct{}{}
		}
	}

	clientLink1.failClosed(net.ErrClosed)
	time.Sleep(10 * time.Millisecond)
	assertRoundTrip(t, client2, server2, []byte("second session survives first client failure"))
	assertRoundTrip(t, server2, client2, []byte("second session reverse direction survives"))
	assertNotCleaned(t, listener)
}

func TestPacketLinkIdleSilentDropDoesNotSynthesizeDeath(t *testing.T) {
	requireOuterPacketSupport(t)
	listener, err := ListenPacket("127.0.0.1:0", WithTrustedCarrier())
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	relay := newDefaultSilentDropRelay(t, listener.Addr())
	defer relay.Close()
	client, server := dialAndAcceptPacketAddress(t, listener, relay.Addr().String())
	defer client.Close()
	defer server.Close()
	clientOwner := client.(*retainedPathConn).link
	serverOwner := server.(*retainedPathConn).link
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		clientOwner.mu.Lock()
		clientPending := len(clientOwner.replayPackets)
		clientOwner.mu.Unlock()
		serverOwner.mu.Lock()
		serverPending := len(serverOwner.replayPackets)
		serverOwner.mu.Unlock()
		if clientPending == 0 && serverPending == 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	clientOwner.mu.Lock()
	clientPending := len(clientOwner.replayPackets)
	clientOwner.mu.Unlock()
	serverOwner.mu.Lock()
	serverPending := len(serverOwner.replayPackets)
	serverOwner.mu.Unlock()
	if clientPending != 0 || serverPending != 0 {
		t.Fatalf("idle precondition retained replay client/server=%d/%d", clientPending, serverPending)
	}
	relay.DropEstablished(t)
	time.Sleep(outerLivenessFailure + 2*outerLivenessTick)
	for name, owner := range map[string]*linkOwner{"client": clientOwner, "server": serverOwner} {
		owner.mu.Lock()
		closed, fault, retained := owner.closed || owner.closing, owner.wireFault, len(owner.replayPackets)
		owner.mu.Unlock()
		if closed || fault || retained != 0 {
			t.Fatalf("idle %s packet link closed/faulted/replay=%t/%t/%d", name, closed, fault, retained)
		}
	}
}

func TestDefaultPacketLinkSilentDropFailsOverToSecondLeafWithinFiveSeconds(t *testing.T) {
	requireOuterPacketSupport(t)
	listener, err := ListenPacket("127.0.0.1:0", WithTrustedCarrier())
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	relay := newDefaultSilentDropRelay(t, listener.Addr())
	defer relay.Close()
	clientA, serverA := dialAndAcceptPacketAddress(t, listener, relay.Addr().String())
	clientB, serverB := dialAndAccept(t, listener)
	clientAOwned := clientA.(*retainedPathConn)
	serverAOwned := serverA.(*retainedPathConn)
	clientBOwned := clientB.(*retainedPathConn)
	serverBOwned := serverB.(*retainedPathConn)
	for name, path := range map[string]*retainedPathConn{
		"client-a": clientAOwned, "server-a": serverAOwned,
		"client-b": clientBOwned, "server-b": serverBOwned,
	} {
		if got := path.LeafMobilityClaim().Snapshot().Operations; got != expectedPacketLinkOperation() {
			t.Fatalf("%s operations=%#x want=%#x", name, got, expectedPacketLinkOperation())
		}
	}

	limits := engine.DefaultLimits()
	limits.MigrationBudget = 10 * time.Second
	limits.ProbeInterval = 30 * time.Second
	flowID := [16]byte{0x91, 0x92, 0x93, 0x94}
	clientEngine := engine.New(engine.SideClient, flowID, limits)
	serverEngine := engine.New(engine.SideServer, flowID, limits)
	t.Cleanup(func() {
		_ = clientEngine.Close()
		_ = serverEngine.Close()
	})
	targetA, targetB := configureDefaultFallbackEngines(t, clientEngine, serverEngine)
	bindingA := engine.PathBinding{LocalTXTargetID: targetA, PeerTXTargetID: targetA}
	bindingB := engine.PathBinding{LocalTXTargetID: targetB, PeerTXTargetID: targetB}
	clientAID, err := clientEngine.AttachPathBound(
		&genericPacketPath{PathConn: clientA}, transport.PathSpec{Transport: "gvisor-a"}, bindingA,
	)
	if err != nil {
		t.Fatal(err)
	}
	serverAID, err := serverEngine.AttachPathBound(
		&genericPacketPath{PathConn: serverA}, transport.PathSpec{Transport: "gvisor-a"}, bindingA,
	)
	if err != nil {
		t.Fatal(err)
	}
	clientBID, err := clientEngine.AttachPathBound(
		&genericPacketPath{PathConn: clientB}, transport.PathSpec{Transport: "gvisor-b"}, bindingB,
	)
	if err != nil {
		t.Fatal(err)
	}
	serverBID, err := serverEngine.AttachPathBound(
		&genericPacketPath{PathConn: serverB}, transport.PathSpec{Transport: "gvisor-b"}, bindingB,
	)
	if err != nil {
		t.Fatal(err)
	}
	if clientEngine.ActivePath() != clientAID || serverEngine.ActivePath() != serverAID {
		t.Fatalf("initial active paths client/server=%d/%d want=%d/%d",
			clientEngine.ActivePath(), serverEngine.ActivePath(), clientAID, serverAID)
	}
	assertEnginePayload(t, clientEngine, serverEngine, []byte("default gvisor path a baseline"))
	assertEnginePayload(t, serverEngine, clientEngine, []byte("default gvisor reverse baseline"))
	if relay.DataFrames() == 0 {
		t.Fatal("silent-drop stimulus had no baseline DATA on the selected outer path")
	}

	relay.DropEstablished(t)
	started := time.Now()
	if err := clientEngine.SetReadDeadline(started.Add(6 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := serverEngine.SetReadDeadline(started.Add(6 * time.Second)); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	go func() {
		results <- enginePayload(clientEngine, serverEngine, bytes.Repeat([]byte{0x51}, 32<<10))
	}()
	go func() {
		results <- enginePayload(serverEngine, clientEngine, bytes.Repeat([]byte{0xa2}, 32<<10))
	}()
	for range 2 {
		select {
		case result := <-results:
			if result != nil {
				t.Fatal(result)
			}
		case <-time.After(6 * time.Second):
			t.Fatal("silent DROP did not converge through the fallback leaf")
		}
	}
	elapsed := time.Since(started)
	if elapsed > 5*time.Second {
		t.Fatalf("silent DROP fallback took %v", elapsed)
	}
	if clientEngine.ActivePath() != clientBID || serverEngine.ActivePath() != serverBID {
		t.Fatalf("fallback active paths client/server=%d/%d want=%d/%d",
			clientEngine.ActivePath(), serverEngine.ActivePath(), clientBID, serverBID)
	}
	for name, owner := range map[string]*linkOwner{"client": clientAOwned.link, "server": serverAOwned.link} {
		select {
		case <-owner.done:
		default:
			t.Fatalf("%s silently blackholed packet link did not surface PathConn death", name)
		}
	}
	clientBOwned.link.mu.Lock()
	clientFallbackFrames := clientBOwned.link.replaySequence
	clientBOwned.link.mu.Unlock()
	serverBOwned.link.mu.Lock()
	serverFallbackFrames := serverBOwned.link.replaySequence
	serverBOwned.link.mu.Unlock()
	if clientFallbackFrames == 0 || serverFallbackFrames == 0 {
		t.Fatalf("fallback leaf carried no outer payload client/server=%d/%d",
			clientFallbackFrames, serverFallbackFrames)
	}
}

type genericPacketPath struct {
	transport.PathConn
}

func configureDefaultFallbackEngines(
	t testing.TB,
	client *engine.Engine,
	server *engine.Engine,
) (proto.TargetID, proto.TargetID) {
	t.Helper()
	targetA := proto.DeriveTargetID(proto.GraphNodeKindPath, "default-gvisor-a")
	targetB := proto.DeriveTargetID(proto.GraphNodeKindPath, "default-gvisor-b")
	root := proto.DeriveTargetID(proto.GraphNodeKindSelector, "default-gvisor-root")
	manifest := proto.GraphManifest{RootID: root, Nodes: []proto.GraphNode{
		{ID: root, Kind: proto.GraphNodeKindSelector, Name: "default-gvisor-root", Children: []proto.TargetID{targetA, targetB}},
		{ID: targetA, Kind: proto.GraphNodeKindPath, Name: "default-gvisor-a"},
		{ID: targetB, Kind: proto.GraphNodeKindPath, Name: "default-gvisor-b"},
	}}
	if err := client.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := server.ConfigureLocalGraph(1, manifest); err != nil {
		t.Fatal(err)
	}
	if err := client.AcceptPeerNegotiation(server.LocalNegotiation(), server.LocalGraphManifest()); err != nil {
		t.Fatal(err)
	}
	if err := server.AcceptPeerNegotiation(client.LocalNegotiation(), client.LocalGraphManifest()); err != nil {
		t.Fatal(err)
	}
	clientID, serverID := engine.NewInstanceID(), engine.NewInstanceID()
	client.SetLocalInstanceID(clientID)
	server.SetLocalInstanceID(serverID)
	if err := client.SetPeerInstanceID(serverID); err != nil {
		t.Fatal(err)
	}
	if err := server.SetPeerInstanceID(clientID); err != nil {
		t.Fatal(err)
	}
	return targetA, targetB
}

func assertEnginePayload(t testing.TB, sender, receiver *engine.Engine, payload []byte) {
	t.Helper()
	if err := receiver.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := enginePayload(sender, receiver, payload); err != nil {
		t.Fatal(err)
	}
	_ = receiver.SetReadDeadline(time.Time{})
}

func enginePayload(sender, receiver *engine.Engine, payload []byte) error {
	n, err := sender.SendData(payload)
	if err != nil {
		return err
	}
	if n != len(payload) {
		return fmt.Errorf("short engine payload write %d/%d", n, len(payload))
	}
	got := make([]byte, len(payload))
	for offset := 0; offset < len(got); {
		n, err := receiver.Recv(got[offset:])
		if err != nil {
			return err
		}
		offset += n
	}
	if !bytes.Equal(got, payload) {
		return errors.New("engine payload changed across packet-link fallback")
	}
	return nil
}

func TestUnnegotiatedPacketLinkWriteFailureTerminatesOnlyEndpoint(t *testing.T) {
	requireOuterPacketSupport(t)
	listener, err := ListenPacket("127.0.0.1:0", WithTrustedCarrier())
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client1, server1 := dialAndAccept(t, listener)
	defer client1.Close()
	defer server1.Close()
	client2, server2 := dialAndAccept(t, listener)
	defer client2.Close()
	defer server2.Close()
	owner := client1.(*retainedPathConn).link
	owner.mu.Lock()
	active := owner.active
	owner.mu.Unlock()
	if err := active.replaceWriter(writeFailPacketWriter{}); err != nil {
		t.Fatal(err)
	}
	_, _ = client1.Write([]byte("force active outer write"))
	select {
	case <-owner.done:
	case <-time.After(testTimeout):
		t.Fatal("unnegotiated packet link did not terminate after its active wire failed")
	}
	assertRoundTrip(t, client2, server2, []byte("sibling remains usable after active wire failure"))
	assertNotCleaned(t, listener)
}

func TestPacketLinkCloseDoesNotWaitForBlockedWriter(t *testing.T) {
	requireOuterPacketSupport(t)
	listener, err := ListenPacket("127.0.0.1:0", WithTrustedCarrier())
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, server := dialAndAccept(t, listener)
	defer client.Close()
	defer server.Close()
	owner := client.(*retainedPathConn).link
	owner.mu.Lock()
	active := owner.active
	owner.mu.Unlock()
	blocked := newBlockingPacketWriter(nil)
	if err := active.replaceWriter(blocked); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- owner.sendPacket(testInnerPacket(owner, packetMTU)) }()
	select {
	case <-blocked.started:
	case <-time.After(time.Second):
		t.Fatal("packet write did not block")
	}
	started := time.Now()
	owner.close()
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("Close waited %v for blocked writer", elapsed)
	}
	select {
	case <-owner.done:
	case <-time.After(time.Second):
		t.Fatal("closed owner did not finish")
	}
	select {
	case <-result:
	case <-time.After(time.Second):
		t.Fatal("blocked packet write did not observe Close")
	}
}

func TestPacketLinkQueueAppliesBoundedLosslessBackpressure(t *testing.T) {
	requireOuterPacketSupport(t)
	listener, err := ListenPacket("127.0.0.1:0", WithTrustedCarrier())
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, server := dialAndAccept(t, listener)
	defer client.Close()
	defer server.Close()
	owner := client.(*retainedPathConn).link
	owner.mu.Lock()
	active := owner.active
	owner.mu.Unlock()
	active.writeMu.RLock()
	original := active.writer
	active.writeMu.RUnlock()
	packet := testInnerPacket(owner, packetMTU)
	blocked := newBlockingPacketWriter(original)
	blocked.trackPacket(owner.secret, packet)
	if err := active.replaceWriter(blocked); err != nil {
		t.Fatal(err)
	}
	const packets = packetOutboundQueued * 4
	var enqueued atomic.Int32
	producerDone := make(chan error, 1)
	go func() {
		for range packets {
			if err := owner.enqueuePacket(packet); err != nil {
				producerDone <- err
				return
			}
			enqueued.Add(1)
		}
		producerDone <- nil
	}()
	select {
	case <-blocked.started:
	case <-time.After(time.Second):
		t.Fatal("packet writer did not pause")
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for len(owner.outbound) != cap(owner.outbound) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := len(owner.outbound); got != packetOutboundQueued {
		t.Fatalf("queued packets=%d want bounded capacity=%d", got, packetOutboundQueued)
	}
	if got := enqueued.Load(); got > packetOutboundQueued+1 {
		t.Fatalf("producer escaped bounded backpressure with %d retained packets", got)
	}
	owner.mu.Lock()
	closed := owner.closed || owner.closing
	owner.mu.Unlock()
	if closed {
		t.Fatal("healthy endpoint failed closed on queue saturation")
	}
	close(blocked.release)
	select {
	case err := <-producerDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("backpressured producer did not resume")
	}
	deadline = time.Now().Add(5 * time.Second)
	for blocked.trackedPacketSequences() != packets && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := blocked.trackedPacketSequences(); got != packets {
		t.Fatalf("unique DATA sequences=%d want lossless packets=%d (all wire writes=%d)", got, packets, blocked.writes.Load())
	}
}

func TestSharedPacketLinkQueuePressureIsEndpointLocal(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	shared := newPacketWire(conn, true)
	remote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	first, err := newLinkOwner(
		linkID{1}, linkSecret{1}, leafmobility.RoleAcceptor, [4]byte{10, 64, 0, 41},
		shared, remote, nil, func([]byte) {},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer first.close()
	second, err := newLinkOwner(
		linkID{2}, linkSecret{2}, leafmobility.RoleAcceptor, [4]byte{10, 64, 0, 42},
		shared, remote, nil, func([]byte) {},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer second.close()
	firstPacket := testInnerPacket(first, packetMTU)
	for range cap(first.outbound) {
		if !first.enqueueSharedPacket(firstPacket) {
			t.Fatal("first endpoint queue rejected a packet before its bound")
		}
	}
	if first.enqueueSharedPacket(firstPacket) {
		t.Fatal("saturated shared endpoint exceeded its queue bound")
	}
	if !second.enqueueSharedPacket(testInnerPacket(second, packetMTU)) {
		t.Fatal("saturated first endpoint blocked sibling queue admission")
	}
	first.mu.Lock()
	firstClosed := first.closed || first.closing
	first.mu.Unlock()
	if firstClosed {
		t.Fatal("shared endpoint failed closed under bounded queue pressure")
	}
}

func TestPacketLinkReplayBudgetBackpressuresWithoutEviction(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	remote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	owner, err := newLinkOwner(
		linkID{1}, linkSecret{2}, leafmobility.RoleDialer, [4]byte{10, 64, 0, 31},
		newPacketWire(conn, false), remote, nil, func([]byte) {},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.close()
	packet := testInnerPacket(owner, packetMTU)
	owner.mu.Lock()
	owner.replayLimit = 2 * len(packet)
	owner.mu.Unlock()
	for range 2 {
		if err := owner.sendPacket(packet); err != nil {
			t.Fatal(err)
		}
	}
	third := make(chan error, 1)
	go func() { third <- owner.sendPacket(packet) }()
	select {
	case err := <-third:
		t.Fatalf("third packet escaped replay backpressure: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	owner.mu.Lock()
	retained, retainedBytes := len(owner.replayPackets), owner.replayBytes
	closed := owner.closed || owner.closing
	owner.ackReplayLocked(2)
	owner.mu.Unlock()
	if retained != 2 || retainedBytes != 2*len(packet) || closed {
		t.Fatalf("replay bound packets=%d bytes=%d closed=%t", retained, retainedBytes, closed)
	}
	select {
	case err := <-third:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("replay producer did not resume after cumulative DATA_ACK frontier")
	}
	owner.mu.Lock()
	retained, retainedBytes = len(owner.replayPackets), owner.replayBytes
	owner.mu.Unlock()
	if retained != 2 || retainedBytes != 2*len(packet) {
		t.Fatalf("post-resume replay bound packets=%d bytes=%d", retained, retainedBytes)
	}
}

func TestPacketLinkTinyPacketReplayEntryBudgetBackpressures(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	remote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	owner, err := newLinkOwner(
		linkID{1}, linkSecret{2}, leafmobility.RoleDialer, [4]byte{10, 64, 0, 34},
		newPacketWire(conn, false), remote, nil, func([]byte) {},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.close()
	packet := testInnerPacket(owner, 20)
	owner.mu.Lock()
	owner.replayLimit = 1 << 20
	owner.replayEntryLimit = 4
	owner.mu.Unlock()
	for range 4 {
		if err := owner.sendPacket(packet); err != nil {
			t.Fatal(err)
		}
	}
	fifth := make(chan error, 1)
	go func() { fifth <- owner.sendPacket(packet) }()
	select {
	case err := <-fifth:
		t.Fatalf("fifth tiny packet escaped entry backpressure: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	owner.mu.Lock()
	entries, replayBytes := len(owner.replayPackets), owner.replayBytes
	budget := owner.replayLease.budget.snapshot()
	owner.ackReplayLocked(2)
	owner.mu.Unlock()
	if entries != 4 || replayBytes != 4*len(packet) || budget.Entries != 4 || budget.Bytes != 4*len(packet) {
		t.Fatalf("tiny replay entries/bytes owner=%d/%d aggregate=%d/%d",
			entries, replayBytes, budget.Entries, budget.Bytes)
	}
	select {
	case err := <-fifth:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("tiny replay producer did not resume after one entry was released")
	}
	owner.mu.Lock()
	entries, replayBytes = len(owner.replayPackets), owner.replayBytes
	owner.mu.Unlock()
	if entries != 4 || replayBytes != 4*len(packet) {
		t.Fatalf("post-resume tiny replay entries/bytes=%d/%d", entries, replayBytes)
	}
}

func TestPacketReplayDomainAdmissionHasBoundedHeapEntriesAndCleanRelease(t *testing.T) {
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	budget := newDefaultPacketReplayBudget()
	leases := make([]*packetReplayLease, 0, maxPacketLinks)
	for range maxPacketLinks {
		lease, err := budget.acquire()
		if err != nil {
			t.Fatal(err)
		}
		if reserved, _ := lease.reserve(20, 1); !reserved {
			t.Fatal("aggregate replay budget rejected one tiny entry per admitted owner")
		}
		leases = append(leases, lease)
	}
	if _, err := budget.acquire(); !errors.Is(err, errPacketReplayAdmission) {
		t.Fatalf("owner admission beyond aggregate limit error=%v", err)
	}
	snapshot := budget.snapshot()
	if snapshot.Owners != maxPacketLinks || snapshot.Entries != maxPacketLinks ||
		snapshot.Bytes != 20*maxPacketLinks || snapshot.MaxBytes != maxReplayDomainBytes ||
		snapshot.MaxEntries != maxReplayDomainEntries {
		t.Fatalf("aggregate replay snapshot=%+v", snapshot)
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	heapGrowth := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	if heapGrowth > 16<<20 {
		t.Fatalf("%d replay owner leases grew heap by %d bytes", maxPacketLinks, heapGrowth)
	}

	leases[0].close()
	replacement, err := budget.acquire()
	if err != nil {
		t.Fatalf("released owner admission was not reusable: %v", err)
	}
	if reserved, _ := replacement.reserve(20, 1); !reserved {
		t.Fatal("replacement owner could not reserve released aggregate entry")
	}
	replacement.close()
	for _, lease := range leases[1:] {
		lease.close()
	}
	if released := budget.snapshot(); released.Owners != 0 || released.Bytes != 0 || released.Entries != 0 {
		t.Fatalf("aggregate replay ownership was not released: %+v", released)
	}
	runtime.KeepAlive(leases)

	tiny := newPacketReplayBudget(2, 1<<20, 2)
	first, _ := tiny.acquire()
	second, _ := tiny.acquire()
	if ok, _ := first.reserve(20, 1); !ok {
		t.Fatal("first aggregate entry reservation failed")
	}
	if ok, _ := second.reserve(20, 1); !ok {
		t.Fatal("second aggregate entry reservation failed")
	}
	if ok, changed := first.reserve(20, 1); ok || changed == nil {
		t.Fatal("aggregate entry limit did not return bounded backpressure")
	}
	second.close()
	if ok, _ := first.reserve(20, 1); !ok {
		t.Fatal("aggregate entry release did not wake capacity")
	}
	first.close()
	if released := tiny.snapshot(); released.Owners != 0 || released.Bytes != 0 || released.Entries != 0 {
		t.Fatalf("tiny aggregate replay ownership was not released: %+v", released)
	}
}

func TestPacketLinkReceiveSequenceWindowIsBounded(t *testing.T) {
	owner := &linkOwner{receiveNext: 1, receiveAhead: make(map[uint64]struct{})}
	for sequence := uint64(2); sequence <= maxReceiveAheadEntries; sequence++ {
		accepted, acknowledged := owner.recordReceiveSequenceLocked(sequence)
		if !accepted || !acknowledged {
			t.Fatalf("future sequence %d accepted/acknowledged=%t/%t", sequence, accepted, acknowledged)
		}
	}
	accepted, acknowledged := owner.recordReceiveSequenceLocked(maxReceiveAheadEntries + 1)
	if accepted || !acknowledged || len(owner.receiveAhead) != maxReceiveAheadEntries-1 {
		t.Fatalf("receive bound accepted/acknowledged=%t/%t entries=%d", accepted, acknowledged, len(owner.receiveAhead))
	}
	accepted, _ = owner.recordReceiveSequenceLocked(1)
	if !accepted || owner.receiveNext != maxReceiveAheadEntries+1 || len(owner.receiveAhead) != 0 {
		t.Fatalf("receive frontier=%d entries=%d", owner.receiveNext, len(owner.receiveAhead))
	}
}

func TestPacketLinkDuplicateDataACKRequestsBoundedReplay(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	remote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 46001}
	wire := newPacketWire(conn, false)
	owner, err := newLinkOwner(
		linkID{1}, linkSecret{2}, leafmobility.RoleDialer, [4]byte{10, 64, 0, 32},
		wire, remote, nil, func([]byte) {},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.close()
	packet := testInnerPacket(owner, packetMTU)
	owner.mu.Lock()
	for range maxCurrentReplayPackets + 10 {
		if _, _, retained := owner.retainReplayLocked(packet); !retained {
			owner.mu.Unlock()
			t.Fatal("test replay ledger exhausted unexpectedly")
		}
	}
	owner.mu.Unlock()
	payload, err := marshalOuterDataAck(1)
	if err != nil {
		t.Fatal(err)
	}
	datagram, err := encodeOuterControl(outerFrame{
		Type: outerTypeDataAck, LinkID: owner.id, Generation: 1, Payload: payload,
	}, owner.secret)
	if err != nil {
		t.Fatal(err)
	}
	for range duplicateDataAckTrigger {
		owner.handleDatagram(wire, remote, datagram)
	}
	select {
	case <-owner.dataReplayWake:
	default:
		t.Fatal("duplicate cumulative DATA_ACKs did not request replay")
	}
	if err := owner.replayOnCurrent(context.Background()); err != nil {
		t.Fatal(err)
	}
	owner.mu.Lock()
	retained := len(owner.replayPackets)
	replayed := owner.replayTransmitted
	owner.mu.Unlock()
	if retained != maxCurrentReplayPackets+10 {
		t.Fatalf("duplicate DATA_ACK mutated unacknowledged replay ledger: %d", retained)
	}
	if replayed != maxCurrentReplayPackets {
		t.Fatalf("current replay batch=%d want bounded maximum=%d", replayed, maxCurrentReplayPackets)
	}
}

func TestPacketLinkAuthenticatedControlReplayIsProgressAndRateBounded(t *testing.T) {
	t.Run("DATA_ACK", func(t *testing.T) {
		owner, wire, remote := newControlReplayFixture(t)
		ack := mustOuterDataAck(t, owner, 1)
		for round := 0; round < 16; round++ {
			for range duplicateDataAckTrigger {
				owner.handleDatagram(wire, remote, ack)
			}
			runtime.Gosched()
		}
		waitForReplayCount(t, owner, maxCurrentReplayPackets)
		assertReplayCount(t, owner, 1, maxCurrentReplayPackets)

		progress := mustOuterDataAck(t, owner, 2)
		owner.handleDatagram(wire, remote, progress)
		for range duplicateDataAckTrigger {
			owner.handleDatagram(wire, remote, progress)
		}
		waitForReplayCount(t, owner, 2*maxCurrentReplayPackets)
		assertReplayCount(t, owner, 2, 2*maxCurrentReplayPackets)
	})

	t.Run("PATH_COMMIT", func(t *testing.T) {
		owner, wire, remote := newControlReplayFixture(t)
		control := outerControl{
			Transaction: linkTransaction{21}, Agreement: linkAgreement{22}, Nonce: linkNonce{23}, ReceiveNext: 1,
		}
		owner.mu.Lock()
		owner.peerGeneration = 2
		owner.committedPeer = &committedPeer{generation: 2, control: control, remote: cloneAddr(remote)}
		owner.mu.Unlock()
		commit := mustOuterControl(t, owner, outerTypePathCommit, 2, control)
		for range 256 {
			owner.handleDatagram(wire, remote, commit)
			runtime.Gosched()
		}
		waitForReplayCount(t, owner, maxCurrentReplayPackets)
		assertReplayCount(t, owner, 1, maxCurrentReplayPackets)
	})

	t.Run("liveness", func(t *testing.T) {
		owner, wire, remote := newControlReplayFixture(t)
		payload, err := marshalOuterLiveness(outerLiveness{Nonce: linkNonce{31}, ReceiveNext: 1})
		if err != nil {
			t.Fatal(err)
		}
		challenge, err := encodeOuterControl(outerFrame{
			Type: outerTypeLivenessChallenge, LinkID: owner.id, Generation: 1, Payload: payload,
		}, owner.secret)
		if err != nil {
			t.Fatal(err)
		}
		for range 256 {
			owner.handleDatagram(wire, remote, challenge)
			runtime.Gosched()
		}
		waitForReplayCount(t, owner, maxCurrentReplayPackets)
		assertReplayCount(t, owner, 1, maxCurrentReplayPackets)
	})

	t.Run("sustained duplicate DATA_ACK exhausts into path failure", func(t *testing.T) {
		owner, wire, remote := newControlReplayFixture(t)
		ack := mustOuterDataAck(t, owner, 1)
		for attempt := 0; attempt < maxReplayNoProgress; attempt++ {
			owner.mu.Lock()
			if !owner.replayRequestAt.IsZero() {
				owner.replayRequestAt = time.Now().Add(-outerReplayNoProgress)
			}
			owner.mu.Unlock()
			for range duplicateDataAckTrigger {
				owner.handleDatagram(wire, remote, ack)
			}
			waitForReplayCount(t, owner, uint64(attempt+1)*maxCurrentReplayPackets)
		}
		owner.mu.Lock()
		owner.replayRequestAt = time.Now().Add(-outerReplayNoProgress)
		owner.mu.Unlock()
		for range duplicateDataAckTrigger {
			owner.handleDatagram(wire, remote, ack)
		}
		select {
		case <-owner.done:
		case <-time.After(time.Second):
			t.Fatal("no-progress replay budget exhaustion did not fail or migrate the packet link")
		}
		assertReplayCount(
			t, owner, maxReplayNoProgress,
			uint64(maxReplayNoProgress)*maxCurrentReplayPackets,
		)
	})
}

func newControlReplayFixture(t testing.TB) (*linkOwner, *packetWire, net.Addr) {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	remote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 46101}
	wire := newPacketWire(conn, false)
	if err := wire.replaceWriter(&countingPacketWriter{}); err != nil {
		t.Fatal(err)
	}
	owner, err := newLinkOwner(
		linkID{1}, linkSecret{2}, leafmobility.RoleDialer, [4]byte{10, 64, 0, 33},
		wire, remote, nil, func([]byte) {},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owner.close)
	packet := testInnerPacket(owner, packetMTU)
	owner.mu.Lock()
	for range maxCurrentReplayPackets + 10 {
		if _, _, retained := owner.retainReplayLocked(packet); !retained {
			owner.mu.Unlock()
			t.Fatal("control replay fixture exhausted its ledger")
		}
	}
	owner.mu.Unlock()
	owner.startOutbound()
	return owner, wire, remote
}

func mustOuterDataAck(t testing.TB, owner *linkOwner, receiveNext uint64) []byte {
	t.Helper()
	payload, err := marshalOuterDataAck(receiveNext)
	if err != nil {
		t.Fatal(err)
	}
	datagram, err := encodeOuterControl(outerFrame{
		Type: outerTypeDataAck, LinkID: owner.id, Generation: owner.peerGeneration, Payload: payload,
	}, owner.secret)
	if err != nil {
		t.Fatal(err)
	}
	return datagram
}

func waitForReplayCount(t testing.TB, owner *linkOwner, want uint64) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		owner.mu.Lock()
		got := owner.replayTransmitted
		owner.mu.Unlock()
		if got >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	owner.mu.Lock()
	got := owner.replayTransmitted
	owner.mu.Unlock()
	t.Fatalf("replay transmissions=%d want at least %d", got, want)
}

func assertReplayCount(t testing.TB, owner *linkOwner, activations, transmissions uint64) {
	t.Helper()
	owner.mu.Lock()
	gotActivations := owner.replayActivations
	gotTransmissions := owner.replayTransmitted
	owner.mu.Unlock()
	if gotActivations != activations || gotTransmissions != transmissions {
		t.Fatalf("replay activations/transmissions=%d/%d want=%d/%d",
			gotActivations, gotTransmissions, activations, transmissions)
	}
}

func TestBoundPacketLinkCancelsAdmissionExpiry(t *testing.T) {
	requireOuterPacketSupport(t)
	listener, err := ListenPacket("127.0.0.1:0", WithTrustedCarrier())
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, server := dialAndAccept(t, listener)
	defer client.Close()
	defer server.Close()
	serverOwner := server.(*retainedPathConn).link
	serverOwner.mu.Lock()
	timer := serverOwner.admissionTimer
	serverOwner.mu.Unlock()
	if timer != nil {
		t.Fatal("bound packet-link retained its admission expiry callback")
	}
}

func TestPacketListenerReplayOwnerAdmissionFailsAndReleasesCleanly(t *testing.T) {
	requireOuterPacketSupport(t)
	listener, err := ListenPacket("127.0.0.1:0", WithTrustedCarrier())
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	listener.lifecycleMu.Lock()
	listener.serverReplayBudget = newPacketReplayBudget(1, maxPacketReplayBytes, maxPacketReplayEntries)
	listener.lifecycleMu.Unlock()
	firstClient, firstServer := dialAndAccept(t, listener)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	second, secondErr := listener.Factory().DialPath(ctx, transport.PathSpec{Address: listener.Addr().String()})
	cancel()
	if second != nil {
		_ = second.Close()
		t.Fatal("aggregate owner admission unexpectedly accepted a second packet link")
	}
	if secondErr == nil {
		t.Fatal("aggregate owner admission rejection returned nil error")
	}
	if snapshot := listener.serverReplayBudget.snapshot(); snapshot.Owners != 1 {
		t.Fatalf("rejected admission changed aggregate ownership: %+v", snapshot)
	}

	_ = firstClient.Close()
	_ = firstServer.Close()
	deadline := time.Now().Add(time.Second)
	for listener.serverReplayBudget.snapshot().Owners != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if snapshot := listener.serverReplayBudget.snapshot(); snapshot.Owners != 0 || snapshot.Bytes != 0 || snapshot.Entries != 0 {
		t.Fatalf("closed packet link retained aggregate ownership: %+v", snapshot)
	}
	replacementClient, replacementServer := dialAndAccept(t, listener)
	_ = replacementClient.Close()
	_ = replacementServer.Close()
}

func TestPacketListenerCloseLinearizesAgainstOuterAdmission(t *testing.T) {
	requireOuterPacketSupport(t)
	for iteration := 0; iteration < 5; iteration++ {
		listener, err := ListenPacket("127.0.0.1:0", WithTrustedCarrier())
		if err != nil {
			t.Fatal(err)
		}
		result := make(chan transport.PathConn, 1)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			path, _ := listener.Factory().DialPath(ctx, transport.PathSpec{Address: listener.Addr().String()})
			result <- path
		}()
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case path := <-result:
			if path != nil {
				_ = path.Close()
			}
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("iteration %d: packet dial did not converge after listener close", iteration)
		}
		waitForCleanup(t, listener)
		listener.packetMu.RLock()
		links, addresses := len(listener.packetLinks), len(listener.packetByIP)
		listener.packetMu.RUnlock()
		if links != 0 || addresses != 0 {
			t.Fatalf("iteration %d: closed listener retained links=%d addresses=%d", iteration, links, addresses)
		}
	}
}

type writeFailPacketWriter struct{}

func (writeFailPacketWriter) WriteTo([]byte, net.Addr) (int, error) {
	return 0, errors.New("injected packet-link write failure")
}

func (writeFailPacketWriter) SetWriteDeadline(time.Time) error { return nil }

type countingPacketWriter struct {
	writes atomic.Uint64
}

func (writer *countingPacketWriter) WriteTo(packet []byte, _ net.Addr) (int, error) {
	writer.writes.Add(1)
	return len(packet), nil
}

func (*countingPacketWriter) SetWriteDeadline(time.Time) error { return nil }

type blockingPacketWriter struct {
	delegate packetWriter
	started  chan struct{}
	release  chan struct{}

	startOnce sync.Once
	mu        sync.Mutex
	deadline  time.Time
	changed   chan struct{}
	writes    atomic.Int32

	trackMu        sync.Mutex
	trackSecret    linkSecret
	trackedPayload []byte
	trackSequences map[uint64]struct{}
}

func newBlockingPacketWriter(delegate packetWriter) *blockingPacketWriter {
	return &blockingPacketWriter{
		delegate: delegate, started: make(chan struct{}), release: make(chan struct{}), changed: make(chan struct{}),
	}
}

func (writer *blockingPacketWriter) SetWriteDeadline(deadline time.Time) error {
	writer.mu.Lock()
	writer.deadline = deadline
	close(writer.changed)
	writer.changed = make(chan struct{})
	writer.mu.Unlock()
	if writer.delegate != nil {
		return writer.delegate.SetWriteDeadline(deadline)
	}
	return nil
}

func (writer *blockingPacketWriter) trackPacket(secret linkSecret, packet []byte) {
	writer.trackMu.Lock()
	writer.trackSecret = secret
	writer.trackedPayload = append([]byte(nil), packet...)
	writer.trackSequences = make(map[uint64]struct{})
	writer.trackMu.Unlock()
}

func (writer *blockingPacketWriter) trackedPacketSequences() int {
	writer.trackMu.Lock()
	defer writer.trackMu.Unlock()
	return len(writer.trackSequences)
}

func (writer *blockingPacketWriter) recordTrackedPacket(datagram []byte) {
	writer.trackMu.Lock()
	secret := writer.trackSecret
	want := append([]byte(nil), writer.trackedPayload...)
	tracking := writer.trackSequences != nil
	writer.trackMu.Unlock()
	if !tracking {
		return
	}
	frame, err := decodeOuter(datagram, secret)
	if err != nil || frame.Type != outerTypeData {
		return
	}
	data, err := parseOuterData(frame.Payload)
	if err != nil || !bytes.Equal(data.Packet, want) {
		return
	}
	writer.trackMu.Lock()
	writer.trackSequences[data.Sequence] = struct{}{}
	writer.trackMu.Unlock()
}

func (writer *blockingPacketWriter) WriteTo(packet []byte, remote net.Addr) (int, error) {
	writer.startOnce.Do(func() { close(writer.started) })
	for {
		writer.mu.Lock()
		deadline := writer.deadline
		changed := writer.changed
		writer.mu.Unlock()
		var timeout <-chan time.Time
		var timer *time.Timer
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return 0, packetWriterTimeout{}
			}
			timer = time.NewTimer(remaining)
			timeout = timer.C
		}
		select {
		case <-writer.release:
			if timer != nil {
				timer.Stop()
			}
			writer.recordTrackedPacket(packet)
			writer.writes.Add(1)
			if writer.delegate != nil {
				return writer.delegate.WriteTo(packet, remote)
			}
			return len(packet), nil
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
		case <-timeout:
			return 0, packetWriterTimeout{}
		}
	}
}

type packetWriterTimeout struct{}

func (packetWriterTimeout) Error() string   { return "injected packet writer timeout" }
func (packetWriterTimeout) Timeout() bool   { return true }
func (packetWriterTimeout) Temporary() bool { return true }

type defaultSilentDropRelay struct {
	conn   *net.UDPConn
	server *net.UDPAddr
	done   chan struct{}
	wait   sync.WaitGroup
	close  sync.Once

	mu         sync.Mutex
	client     *net.UDPAddr
	dropped    *net.UDPAddr
	drop       bool
	dataFrames uint64
}

func newDefaultSilentDropRelay(t testing.TB, server net.Addr) *defaultSilentDropRelay {
	t.Helper()
	serverUDP, ok := server.(*net.UDPAddr)
	if !ok {
		t.Fatalf("silent-drop server address=%T", server)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	relay := &defaultSilentDropRelay{
		conn: conn, server: cloneDefaultUDPAddr(serverUDP), done: make(chan struct{}),
	}
	relay.wait.Add(1)
	go relay.run()
	return relay
}

func (relay *defaultSilentDropRelay) Addr() net.Addr { return relay.conn.LocalAddr() }

func (relay *defaultSilentDropRelay) Close() {
	if relay == nil {
		return
	}
	relay.close.Do(func() {
		close(relay.done)
		_ = relay.conn.Close()
	})
	relay.wait.Wait()
}

func (relay *defaultSilentDropRelay) run() {
	defer relay.wait.Done()
	buffer := make([]byte, outerHeaderSize+outerDataSequenceSize+packetMTU+outerAuthTagSize+1)
	for {
		n, source, err := relay.conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		packet := append([]byte(nil), buffer[:n]...)
		header, _ := decodeOuterHeader(packet)
		if addrEqual(source, relay.server) {
			relay.mu.Lock()
			client := cloneDefaultUDPAddr(relay.client)
			drop := relay.drop && addrEqual(client, relay.dropped)
			if header.Type == outerTypeData && !relay.drop {
				relay.dataFrames++
			}
			relay.mu.Unlock()
			if client != nil && !drop {
				_, _ = relay.conn.WriteToUDP(packet, client)
			}
			continue
		}
		relay.mu.Lock()
		if relay.client == nil {
			relay.client = cloneDefaultUDPAddr(source)
		}
		drop := relay.drop && addrEqual(source, relay.dropped)
		if !relay.drop {
			relay.client = cloneDefaultUDPAddr(source)
			if header.Type == outerTypeData {
				relay.dataFrames++
			}
		}
		relay.mu.Unlock()
		if !drop {
			_, _ = relay.conn.WriteToUDP(packet, relay.server)
		}
	}
}

func (relay *defaultSilentDropRelay) DropEstablished(t testing.TB) {
	t.Helper()
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if relay.client == nil {
		t.Fatal("silent-drop relay has no established client")
	}
	relay.dropped = cloneDefaultUDPAddr(relay.client)
	relay.drop = true
}

func (relay *defaultSilentDropRelay) DataFrames() uint64 {
	relay.mu.Lock()
	defer relay.mu.Unlock()
	return relay.dataFrames
}

func cloneDefaultUDPAddr(value *net.UDPAddr) *net.UDPAddr {
	if value == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), value.IP...), Port: value.Port, Zone: value.Zone}
}

func dialAndAcceptPacketAddress(
	t testing.TB,
	listener *Listener,
	address string,
) (transport.PathConn, transport.PathConn) {
	t.Helper()
	type acceptedPath struct {
		path transport.PathConn
		err  error
	}
	accepted := make(chan acceptedPath, 1)
	go func() {
		path, err := listener.Accept(context.Background())
		accepted <- acceptedPath{path: path, err: err}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	client, err := listener.Factory().DialPath(ctx, transport.PathSpec{Address: address})
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-accepted:
		if result.err != nil {
			_ = client.Close()
			t.Fatal(result.err)
		}
		return client, result.path
	case <-time.After(2 * time.Second):
		_ = client.Close()
		t.Fatal("packet-link accept through silent-drop relay timed out")
		return nil, nil
	}
}

func testInnerPacket(owner *linkOwner, size int) []byte {
	packet := make([]byte, size)
	packet[0] = 0x45
	if owner.role == leafmobility.RoleDialer {
		copy(packet[12:16], owner.virtualIP[:])
		copy(packet[16:20], serverIPv4[:])
	} else {
		copy(packet[12:16], serverIPv4[:])
		copy(packet[16:20], owner.virtualIP[:])
	}
	return packet
}
