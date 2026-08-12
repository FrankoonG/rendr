package gvisor

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
)

type failingQualificationWriter struct {
	err error
}

func (writer failingQualificationWriter) WriteTo([]byte, net.Addr) (int, error) {
	return 0, writer.err
}

func (failingQualificationWriter) SetWriteDeadline(time.Time) error { return nil }

func TestPeerCommitRejectsQualificationFromDifferentFinalWireAndPMTU(t *testing.T) {
	predecessorConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	predecessor := newPacketWire(predecessorConn, false)
	candidateConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		predecessor.close()
		t.Fatal(err)
	}
	candidate := newPacketWire(candidateConn, false)
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 43172}
	owner, err := newLinkOwner(
		linkID{71}, linkSecret{72}, leafmobility.RoleAcceptor,
		[4]byte{10, 64, 0, 71}, predecessor, peer, nil, func([]byte) {},
	)
	if err != nil {
		candidate.close()
		t.Fatal(err)
	}
	defer owner.close()
	owner.mu.Lock()
	owner.wires[candidate] = struct{}{}
	owner.predecessor = predecessor
	owner.active = candidate
	owner.localGeneration = 2
	owner.activationPending = true
	owner.mu.Unlock()

	control := outerControl{
		Transaction: linkTransaction{73}, Agreement: linkAgreement{74}, Nonce: linkNonce{75}, ReceiveNext: 1,
	}
	qualifiedRoute := mustOuterRouteObservation(
		t, outerUDPIPv4, predecessor.conn.LocalAddr().(*net.UDPAddr), peer, 1, 1260,
	)
	finalRoute := mustOuterRouteObservation(
		t, outerUDPIPv4, candidate.conn.LocalAddr().(*net.UDPAddr), peer, 1, 1259,
	)
	owner.observeRoute = func(context.Context, *packetWire, net.Addr) (routeObservation, error) {
		return finalRoute, nil
	}
	owner.mu.Lock()
	owner.pendingPeer = &peerCandidate{
		generation: 2, control: control, wire: predecessor, remote: cloneAddr(peer), route: qualifiedRoute,
		qualified: true, expires: time.Now().Add(time.Second),
	}
	owner.mu.Unlock()

	owner.handleDatagram(candidate, peer, mustOuterControl(t, owner, outerTypePathCommit, 2, control))
	owner.mu.Lock()
	generation := owner.peerGeneration
	remote := cloneAddr(owner.peerRemote)
	owner.mu.Unlock()
	if generation != 1 || !addrEqual(remote, peer) {
		t.Fatalf("crossed qualification published final route generation=%d remote=%v", generation, remote)
	}
}

func TestConcurrentBilateralCommitRequiresExactFinalTupleAndPMTUProof(t *testing.T) {
	newWire := func() *packetWire {
		conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		return newPacketWire(conn, false)
	}
	leftPredecessor, leftCandidate := newWire(), newWire()
	rightPredecessor, rightCandidate := newWire(), newWire()
	leftOldPeer := cloneOuterUDPAddress(rightPredecessor.conn.LocalAddr().(*net.UDPAddr))
	rightOldPeer := cloneOuterUDPAddress(leftPredecessor.conn.LocalAddr().(*net.UDPAddr))
	leftFinalPeer := cloneOuterUDPAddress(rightCandidate.conn.LocalAddr().(*net.UDPAddr))
	rightFinalPeer := cloneOuterUDPAddress(leftCandidate.conn.LocalAddr().(*net.UDPAddr))
	newSide := func(id byte, role leafmobility.Role, predecessor, candidate *packetWire, peer *net.UDPAddr) *linkOwner {
		owner, err := newLinkOwner(
			linkID{id}, linkSecret{id + 1}, role,
			[4]byte{10, 64, 1, id}, predecessor, peer, nil, func([]byte) {},
		)
		if err != nil {
			t.Fatal(err)
		}
		owner.mu.Lock()
		owner.wires[candidate] = struct{}{}
		owner.predecessor = predecessor
		owner.active = candidate
		owner.localGeneration = 2
		owner.activationPending = true
		owner.mu.Unlock()
		owner.observeRoute = func(_ context.Context, wire *packetWire, remote net.Addr) (routeObservation, error) {
			return newRouteObservation(
				outerUDPIPv4, wire.conn.LocalAddr().(*net.UDPAddr), remote.(*net.UDPAddr),
				outerRoutePlatformEvidence{outputInterface: 1, pathMTU: 1260, pathMTUKnown: true},
			)
		}
		return owner
	}
	leftControl := outerControl{
		Transaction: linkTransaction{101}, Agreement: linkAgreement{102}, Nonce: linkNonce{103}, ReceiveNext: 1,
	}
	rightControl := outerControl{
		Transaction: linkTransaction{111}, Agreement: linkAgreement{112}, Nonce: linkNonce{113}, ReceiveNext: 1,
	}
	left := newSide(101, leafmobility.RoleDialer, leftPredecessor, leftCandidate, leftOldPeer)
	right := newSide(111, leafmobility.RoleAcceptor, rightPredecessor, rightCandidate, rightOldPeer)
	defer left.close()
	defer right.close()

	configure := func(
		owner *linkOwner,
		localControl, peerControl outerControl,
		predecessor, candidate *packetWire,
		oldPeer, finalPeer *net.UDPAddr,
		baseline byte,
	) {
		candidateOldRoute := mustOuterRouteObservation(
			t, outerUDPIPv4, candidate.conn.LocalAddr().(*net.UDPAddr), oldPeer, 1, 1260,
		)
		predecessorFinalRoute := mustOuterRouteObservation(
			t, outerUDPIPv4, predecessor.conn.LocalAddr().(*net.UDPAddr), finalPeer, 1, 1260,
		)
		owner.mu.Lock()
		owner.routeBaseline = [sha256.Size]byte{baseline}
		owner.pendingRefresh = &localRefreshCommit{
			wire: candidate, localGeneration: 2, peerGeneration: 1,
			control: localControl, remote: cloneAddr(oldPeer), route: candidateOldRoute,
		}
		owner.pendingPeer = &peerCandidate{
			generation: 2, control: peerControl, qualificationRound: 1, wire: predecessor,
			remote: cloneAddr(finalPeer), route: predecessorFinalRoute, qualified: true,
			expires: time.Now().Add(time.Second),
		}
		owner.mu.Unlock()
	}
	configure(left, leftControl, rightControl, leftPredecessor, leftCandidate, leftOldPeer, leftFinalPeer, 0xa1)
	configure(right, rightControl, leftControl, rightPredecessor, rightCandidate, rightOldPeer, rightFinalPeer, 0xb1)

	var commits sync.WaitGroup
	commits.Add(2)
	go func() {
		defer commits.Done()
		left.handleDatagram(
			leftPredecessor, leftFinalPeer,
			mustOuterControl(t, left, outerTypePathCommit, 2, rightControl),
		)
	}()
	go func() {
		defer commits.Done()
		right.handleDatagram(
			rightPredecessor, rightFinalPeer,
			mustOuterControl(t, right, outerTypePathCommit, 2, leftControl),
		)
	}()
	commits.Wait()

	left.mu.Lock()
	leftGeneration := left.peerGeneration
	leftBaseline := left.routeBaseline
	left.mu.Unlock()
	right.mu.Lock()
	rightGeneration := right.peerGeneration
	rightBaseline := right.routeBaseline
	rightPendingRoute := right.pendingRefresh.route
	right.mu.Unlock()
	if leftGeneration != 1 || rightGeneration != 2 {
		t.Fatalf("predecessor arbitration peer generations left=%d right=%d, want 1/2", leftGeneration, rightGeneration)
	}
	if leftBaseline != ([sha256.Size]byte{0xa1}) || rightBaseline != ([sha256.Size]byte{0xb1}) {
		t.Fatalf("predecessor commit changed successor baselines left=%x right=%x", leftBaseline, rightBaseline)
	}
	if rightPendingRoute.digest != ([sha256.Size]byte{}) {
		t.Fatalf("predecessor route overwrote pending successor route=%x", rightPendingRoute.digest)
	}

	finalRoute := mustOuterRouteObservation(
		t, outerUDPIPv4, leftCandidate.conn.LocalAddr().(*net.UDPAddr), leftFinalPeer, 1, 1260,
	)
	left.mu.Lock()
	left.pendingPeer = &peerCandidate{
		generation: 2, control: rightControl, qualificationRound: 2, wire: leftCandidate,
		remote: cloneAddr(leftFinalPeer), route: finalRoute, qualified: true,
		expires: time.Now().Add(time.Second),
	}
	left.mu.Unlock()
	left.handleDatagram(
		leftCandidate, leftFinalPeer,
		mustOuterControl(t, left, outerTypePathCommit, 2, rightControl),
	)
	left.mu.Lock()
	leftGeneration = left.peerGeneration
	leftBaseline = left.routeBaseline
	left.mu.Unlock()
	if leftGeneration != 2 || leftBaseline != finalRoute.digest {
		t.Fatalf("active final proof did not publish generation=%d baseline=%x want=%x", leftGeneration, leftBaseline, finalRoute.digest)
	}
}

func TestQualificationDoneWriteFailureRevokesResponderQualification(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	wire := newPacketWire(conn, false)
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 43272}
	owner, err := newLinkOwner(
		linkID{76}, linkSecret{77}, leafmobility.RoleAcceptor,
		[4]byte{10, 64, 0, 76}, wire, peer, nil, func([]byte) {},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.close()
	route := mustOuterRouteObservation(
		t, outerUDPIPv4, conn.LocalAddr().(*net.UDPAddr), peer, 1, 1260,
	)
	owner.observeRoute = func(context.Context, *packetWire, net.Addr) (routeObservation, error) {
		return route, nil
	}
	control := outerControl{
		Transaction: linkTransaction{78}, Agreement: linkAgreement{79}, Nonce: linkNonce{80}, ReceiveNext: 1,
	}
	qualificationContext, err := qualificationRebindContext(control)
	if err != nil {
		t.Fatal(err)
	}
	request := outerQualification{
		Purpose: outerQualificationRebind, Round: 1, InitiatorNonce: linkNonce{81}, Context: qualificationContext,
	}
	request.Binding = computeOuterQualificationBinding(
		owner.secret, owner.id, 2, request.Purpose, request.Round, request.InitiatorNonce, request.Context,
	)
	response, accepted := owner.acceptMaximumDataQualificationRequest(wire, peer, 2, request, route)
	if !accepted {
		t.Fatal("qualification request was not accepted")
	}
	injected := errors.New("injected QUALIFICATION_DONE write failure")
	if err := wire.replaceWriter(failingQualificationWriter{err: injected}); err != nil {
		t.Fatal(err)
	}
	payload, err := marshalOuterQualification(outerTypeQualificationConfirm, response)
	if err != nil {
		t.Fatal(err)
	}
	owner.handleMaximumDataQualification(wire, peer, outerFrame{
		Type: outerTypeQualificationConfirm, LinkID: owner.id, Generation: 2, Payload: payload,
	})
	owner.mu.Lock()
	pending := owner.pendingPeer
	qualification := owner.peerQualification
	owner.mu.Unlock()
	if pending != nil || qualification != nil {
		t.Fatalf("failed DONE retained responder authority pending=%+v qualification=%+v", pending, qualification)
	}
}

func TestSuccessorsPreserveWildcardBindAcrossSourceReplacement(t *testing.T) {
	activeConn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	active := newPacketWire(activeConn, false)
	active.bindMode = outerUDPIPv4
	active.bindKnown = true
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 43491}
	owner, err := newLinkOwner(
		linkID{91}, linkSecret{92}, leafmobility.RoleDialer,
		[4]byte{10, 64, 0, 91}, active, peer, nil, func([]byte) {},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.close()

	var routeMu sync.Mutex
	selectedSources := map[*packetWire]net.IP{active: net.IPv4(192, 0, 2, 10)}
	owner.observeRoute = func(_ context.Context, wire *packetWire, remote net.Addr) (routeObservation, error) {
		routeMu.Lock()
		selected := append(net.IP(nil), selectedSources[wire]...)
		routeMu.Unlock()
		if len(selected) == 0 {
			return routeObservation{}, errors.New("missing synthetic source selection")
		}
		local := wire.conn.LocalAddr().(*net.UDPAddr)
		local = &net.UDPAddr{IP: selected, Port: local.Port}
		return newRouteObservation(
			outerUDPIPv4, local, remote.(*net.UDPAddr),
			outerRoutePlatformEvidence{outputInterface: 7, pathMTU: 1260, pathMTUKnown: true},
		)
	}
	var opens int
	owner.openWire = func(mode outerUDPMode, local *net.UDPAddr, shared bool) (*packetWire, error) {
		if shared || mode != outerUDPIPv4 {
			return nil, errors.New("unexpected successor socket shape")
		}
		if local != nil && len(local.IP) != 0 && !local.IP.IsUnspecified() {
			return nil, fmt.Errorf("successor pinned removed selected source %s", local.IP)
		}
		conn, listenErr := net.ListenPacket("udp4", "0.0.0.0:0")
		if listenErr != nil {
			return nil, listenErr
		}
		wire := newPacketWire(conn, false)
		wire.bindMode = mode
		wire.bindLocal = cloneOuterUDPAddress(local)
		wire.bindKnown = true
		opens++
		routeMu.Lock()
		selectedSources[wire] = net.IPv4(192, 0, 2, byte(10+opens))
		routeMu.Unlock()
		return wire, nil
	}

	first, firstRoute, err := owner.openUDPCandidate(context.Background(), peer)
	if err != nil {
		t.Fatal(err)
	}
	defer first.close()
	if !firstRoute.local.IP.Equal(net.IPv4(192, 0, 2, 11)) {
		t.Fatalf("first successor selected source=%s", firstRoute.local.IP)
	}
	owner.mu.Lock()
	owner.active = first
	owner.mu.Unlock()
	second, secondRoute, err := owner.openUDPCandidate(context.Background(), peer)
	if err != nil {
		t.Fatal(err)
	}
	defer second.close()
	if !secondRoute.local.IP.Equal(net.IPv4(192, 0, 2, 12)) || opens != 2 {
		t.Fatalf("second successor source=%s opens=%d", secondRoute.local.IP, opens)
	}
}
