package gvisor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/transport"
	basetcp "github.com/FrankoonG/rendr/transport/tcp"
)

func TestOuterRouteEvidenceCoversScopedFlowOIFAndPMTU(t *testing.T) {
	base := mustOuterRouteObservation(t, outerUDPIPv6,
		&net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 41001, Zone: "if-a"},
		&net.UDPAddr{IP: net.ParseIP("fe80::2"), Port: 41002, Zone: "if-a"}, 7, 1280,
	)
	if base.family != outerUDPIPv6 || base.local.Port != 41001 || base.local.Zone != "if-a" ||
		base.remote.Port != 41002 || base.remote.Zone != "if-a" || base.outputInterface != 7 || base.pathMTU != 1280 {
		t.Fatalf("route evidence lost scoped flow fields: %+v", base)
	}
	mutations := map[string]routeObservation{
		"family": mustOuterRouteObservation(t, outerUDPIPv4,
			&net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 41001},
			&net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 41002}, 7, 1280),
		"local-port": mustOuterRouteObservation(t, outerUDPIPv6,
			&net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 41003, Zone: "if-a"}, base.remote, 7, 1280),
		"local-zone": mustOuterRouteObservation(t, outerUDPIPv6,
			&net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 41001, Zone: "if-b"}, base.remote, 7, 1280),
		"remote-address": mustOuterRouteObservation(t, outerUDPIPv6, base.local,
			&net.UDPAddr{IP: net.ParseIP("fe80::3"), Port: 41002, Zone: "if-a"}, 7, 1280),
		"remote-port": mustOuterRouteObservation(t, outerUDPIPv6, base.local,
			&net.UDPAddr{IP: net.ParseIP("fe80::2"), Port: 41003, Zone: "if-a"}, 7, 1280),
		"remote-zone": mustOuterRouteObservation(t, outerUDPIPv6, base.local,
			&net.UDPAddr{IP: net.ParseIP("fe80::2"), Port: 41002, Zone: "if-b"}, 7, 1280),
		"oif":  mustOuterRouteObservation(t, outerUDPIPv6, base.local, base.remote, 8, 1280),
		"pmtu": mustOuterRouteObservation(t, outerUDPIPv6, base.local, base.remote, 7, 1400),
	}
	for name, observation := range mutations {
		if observation.digest == base.digest {
			t.Errorf("%s mutation did not change route evidence digest", name)
		}
	}
	unknown, err := newRouteObservation(
		outerUDPIPv6, base.local, base.remote,
		outerRoutePlatformEvidence{outputInterface: 7, pathMTUKnown: false},
	)
	if err != nil {
		t.Fatal(err)
	}
	if unknown.pathMTUKnown || unknown.pathMTU != 0 || !unknown.qualifiesMaximumData() ||
		unknown.digest == base.digest {
		t.Fatalf("explicit unknown PMTU evidence=%+v", unknown)
	}
	namespaceA, err := newRouteObservation(
		outerUDPIPv6, base.local, base.remote,
		outerRoutePlatformEvidence{
			outputInterface: 7, pathMTU: 1280, pathMTUKnown: true,
			networkNamespace: outerNetNSIdentity{device: 1, inode: 2, cookie: 3, cookieKnown: true},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	namespaceB, err := newRouteObservation(
		outerUDPIPv6, base.local, base.remote,
		outerRoutePlatformEvidence{
			outputInterface: 7, pathMTU: 1280, pathMTUKnown: true,
			networkNamespace: outerNetNSIdentity{device: 1, inode: 4, cookie: 5, cookieKnown: true},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if namespaceA.digest == namespaceB.digest {
		t.Fatal("network namespace mutation did not change route evidence digest")
	}
}

func TestMaximumDataQualificationUsesFullDataBudget(t *testing.T) {
	owner, peer, candidate, remote, control := newMaximumDataQualificationPair(t)
	writer := &recordingForwardPacketWriter{PacketConn: candidate.conn}
	if err := candidate.replaceWriter(writer); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := owner.challengeCandidate(ctx, candidate, remote, 2, control); err != nil {
		t.Fatal(err)
	}
	writes := writer.snapshot()
	if len(writes) != 2 || len(writes[0]) != outerMaxDatagramSize || len(writes[1]) != outerMaxDatagramSize {
		t.Fatalf("maximum-DATA qualification writes=%d size=%d want 2/%d",
			len(writes), firstDatagramSize(writes), outerMaxDatagramSize)
	}
	for index, wantType := range []outerType{outerTypeQualificationRequest, outerTypeQualificationConfirm} {
		frame, err := decodeOuter(writes[index], owner.secret)
		if err != nil || frame.Type != wantType || frame.Generation != 2 {
			t.Fatalf("qualification leg %d frame=%+v err=%v", index, frame, err)
		}
	}
	peer.mu.Lock()
	pending := peer.pendingPeer
	peer.mu.Unlock()
	if pending == nil || !pending.qualified || pending.generation != 2 || pending.control != control {
		t.Fatalf("peer maximum-DATA proof=%+v", pending)
	}

	observation := mustOuterRouteObservation(
		t, outerUDPIPv4, candidate.conn.LocalAddr().(*net.UDPAddr), remote.(*net.UDPAddr), 1, 1260,
	)
	tooSmall := mustOuterRouteObservation(
		t, outerUDPIPv4, candidate.conn.LocalAddr().(*net.UDPAddr), remote.(*net.UDPAddr), 1, 1259,
	)
	if err := validateMaximumDataRoute(observation); err != nil {
		t.Fatal(err)
	}
	if err := validateMaximumDataRoute(tooSmall); !errors.Is(err, ErrOuterMTU) || !errors.Is(err, syscall.EMSGSIZE) {
		t.Fatalf("undersized route qualification error=%v", err)
	}
	if got := len(writer.snapshot()); got != 2 {
		t.Fatalf("static undersized route performed a write: writes=%d", got)
	}
}

func TestPublishCandidateRequalifiesMaximumData(t *testing.T) {
	for _, test := range []struct {
		name          string
		currentPMTU   int
		writeErr      error
		wantPublished bool
		wantRouteErr  bool
		wantMTUErr    bool
	}{
		{name: "stable", currentPMTU: 1260, wantPublished: true},
		{name: "mtu-evidence-changed", currentPMTU: 1261, wantRouteErr: true},
		{name: "maximum-data-emsgsize", currentPMTU: 1260, writeErr: syscall.EMSGSIZE, wantMTUErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			owner, peer, candidate, active, remote, control := newPublishQualificationPair(t)
			writer := &recordingForwardPacketWriter{PacketConn: candidate.conn, err: test.writeErr}
			if err := candidate.replaceWriter(writer); err != nil {
				t.Fatal(err)
			}
			expected := mustOuterRouteObservation(
				t, outerUDPIPv4, candidate.conn.LocalAddr().(*net.UDPAddr), remote.(*net.UDPAddr), 1, 1260,
			)
			current := mustOuterRouteObservation(
				t, outerUDPIPv4, candidate.conn.LocalAddr().(*net.UDPAddr), remote.(*net.UDPAddr), 1, test.currentPMTU,
			)
			owner.observeRoute = func(context.Context, *packetWire, net.Addr) (routeObservation, error) {
				return current, nil
			}
			owner.mu.Lock()
			owner.maintenance = true
			owner.wires[candidate] = struct{}{}
			maintenance := &linkMaintenance{owner: owner, incarnation: owner.incarnation}
			owner.mu.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			err := owner.publishCandidate(ctx, maintenance, candidate, 2, control, expected)
			if test.wantRouteErr && (err == nil || errors.Is(err, ErrOuterMTU)) {
				t.Fatalf("route evidence change error=%v", err)
			}
			if test.wantMTUErr && (!errors.Is(err, ErrOuterMTU) || !errors.Is(err, syscall.EMSGSIZE)) {
				t.Fatalf("maximum DATA publication error=%v", err)
			}
			if !test.wantRouteErr && !test.wantMTUErr && err != nil {
				t.Fatal(err)
			}
			owner.mu.Lock()
			published := owner.active == candidate
			owner.mu.Unlock()
			if published != test.wantPublished {
				t.Fatalf("published=%t want %t", published, test.wantPublished)
			}
			wantWrites := 0
			if !test.wantRouteErr && !test.wantMTUErr {
				wantWrites = 2
			} else if test.wantMTUErr {
				wantWrites = 1
			}
			if got := len(writer.snapshot()); got != wantWrites {
				t.Fatalf("prepublication maximum-DATA writes=%d want %d", got, wantWrites)
			}
			if !published && owner.active != active {
				t.Fatal("failed qualification replaced the active packet wire")
			}
			if published {
				peer.mu.Lock()
				qualified := peer.pendingPeer != nil && peer.pendingPeer.qualified
				peer.mu.Unlock()
				if !qualified {
					t.Fatal("publication did not leave a fresh peer-received maximum-DATA proof")
				}
			}
		})
	}
}

func TestMaximumDataQualificationRejectsLocalSendOnly(t *testing.T) {
	owner, candidate := newOuterTestOwner(t)
	writer := &recordingPacketWriter{}
	if err := candidate.replaceWriter(writer); err != nil {
		t.Fatal(err)
	}
	control := outerControl{
		Transaction: linkTransaction{21}, Agreement: linkAgreement{22}, Nonce: linkNonce{23}, ReceiveNext: 1,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 140*time.Millisecond)
	defer cancel()
	remote := cloneAddr(owner.peerRemote)
	if sent, err := owner.challengeCandidate(ctx, candidate, remote, 2, control); !sent ||
		!errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("local-send-only qualification=(sent=%t, err=%v)", sent, err)
	}
	writes := writer.snapshot()
	if len(writes) < 2 {
		t.Fatalf("local-send-only qualification attempts=%d want retry", len(writes))
	}
	for index, datagram := range writes {
		if len(datagram) != outerMaxDatagramSize {
			t.Fatalf("qualification attempt %d size=%d", index, len(datagram))
		}
	}
}

func TestInitialAdmissionRejectsControlOnlyRoute(t *testing.T) {
	requireOuterPacketSupport(t)
	listener, err := ListenPacket("127.0.0.1:0", WithTrustedCarrier())
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	relay := newMaximumDataDropRelay(t, listener.Addr())
	defer relay.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	path, err := New(WithTrustedCarrier()).DialPath(
		ctx, transport.PathSpec{Address: relay.Addr().String()},
	)
	if path != nil {
		_ = path.Close()
		t.Fatal("control-only route published a packet carrier")
	}
	var timeout net.Error
	if !errors.Is(err, context.DeadlineExceeded) && (!errors.As(err, &timeout) || !timeout.Timeout()) {
		t.Fatalf("control-only admission error=%v", err)
	}
	small, maximum := relay.counts()
	if small < 3 || maximum == 0 {
		t.Fatalf("control-only stimulus small=%d maximum=%d", small, maximum)
	}
}

func TestInitialAdmissionRequiresEveryMaximumDataQualificationLeg(t *testing.T) {
	requireOuterPacketSupport(t)
	tests := map[string]func(bool, int) bool{
		"request":  func(fromServer bool, _ int) bool { return !fromServer },
		"response": func(fromServer bool, _ int) bool { return fromServer },
		"confirm":  func(fromServer bool, ordinal int) bool { return !fromServer && ordinal >= 2 },
		"done":     func(fromServer bool, ordinal int) bool { return fromServer && ordinal >= 2 },
	}
	for name, drop := range tests {
		t.Run(name, func(t *testing.T) {
			listener, err := ListenPacket("127.0.0.1:0", WithTrustedCarrier())
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			relay := newQualificationLegDropRelay(t, listener.Addr(), drop)
			defer relay.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			path, err := New(WithTrustedCarrier()).DialPath(
				ctx, transport.PathSpec{Address: relay.Addr().String()},
			)
			if path != nil {
				_ = path.Close()
				t.Fatalf("missing %s leg still published a packet carrier", name)
			}
			var timeout net.Error
			if !errors.Is(err, context.DeadlineExceeded) && (!errors.As(err, &timeout) || !timeout.Timeout()) {
				t.Fatalf("missing %s leg error=%v", name, err)
			}
			clientMaximum, serverMaximum := relay.directionalMaximumCounts()
			if clientMaximum == 0 || name != "request" && serverMaximum == 0 {
				t.Fatalf("missing %s stimulus client=%d server=%d", name, clientMaximum, serverMaximum)
			}
		})
	}
}

func TestMaximumDataQualificationRejectsStaleAndCrossCandidateReplies(t *testing.T) {
	initiatorConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	responderConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		_ = initiatorConn.Close()
		t.Fatal(err)
	}
	crossConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		_ = initiatorConn.Close()
		_ = responderConn.Close()
		t.Fatal(err)
	}
	defer responderConn.Close()
	defer crossConn.Close()
	candidate := newPacketWire(initiatorConn, false)
	defer candidate.close()
	owner := &linkOwner{id: linkID{41}, secret: linkSecret{42}}
	control := outerControl{
		Transaction: linkTransaction{43}, Agreement: linkAgreement{44}, Nonce: linkNonce{45}, ReceiveNext: 1,
	}
	peerResult := make(chan error, 1)
	go func() {
		buffer := make([]byte, outerMaxDatagramSize+1)
		n, source, readErr := responderConn.ReadFrom(buffer)
		if readErr != nil {
			peerResult <- readErr
			return
		}
		frame, decodeErr := decodeOuter(buffer[:n], owner.secret)
		if decodeErr != nil || frame.Type != outerTypeQualificationRequest {
			peerResult <- errors.Join(errors.New("invalid qualification request"), decodeErr)
			return
		}
		request, parseErr := parseOuterQualification(frame.Type, frame.Payload)
		if parseErr != nil {
			peerResult <- parseErr
			return
		}
		response := request
		response.ResponderNonce = linkNonce{46}
		stale := response
		stale.InitiatorNonce[0] ^= 0xff
		if sendErr := sendQualificationTestFrame(
			responderConn, source, owner, outerTypeQualificationResponse, frame.Generation, stale,
		); sendErr != nil {
			peerResult <- sendErr
			return
		}
		if sendErr := sendQualificationTestFrame(
			crossConn, source, owner, outerTypeQualificationResponse, frame.Generation, response,
		); sendErr != nil {
			peerResult <- sendErr
			return
		}
		_ = responderConn.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
		if n, _, earlyErr := responderConn.ReadFrom(buffer); earlyErr == nil {
			early, _ := decodeOuter(buffer[:n], owner.secret)
			peerResult <- fmt.Errorf("stale/cross-candidate reply accepted early as type=%d", early.Type)
			return
		} else if timeout, ok := earlyErr.(net.Error); !ok || !timeout.Timeout() {
			peerResult <- earlyErr
			return
		}
		_ = responderConn.SetReadDeadline(time.Time{})
		if sendErr := sendQualificationTestFrame(
			responderConn, source, owner, outerTypeQualificationResponse, frame.Generation, response,
		); sendErr != nil {
			peerResult <- sendErr
			return
		}
		n, source, readErr = responderConn.ReadFrom(buffer)
		if readErr != nil {
			peerResult <- readErr
			return
		}
		confirmFrame, decodeErr := decodeOuter(buffer[:n], owner.secret)
		confirm, parseErr := parseOuterQualification(confirmFrame.Type, confirmFrame.Payload)
		if decodeErr != nil || parseErr != nil || confirmFrame.Type != outerTypeQualificationConfirm ||
			confirm != response {
			peerResult <- errors.Join(errors.New("invalid qualification confirmation"), decodeErr, parseErr)
			return
		}
		peerResult <- sendQualificationTestFrame(
			responderConn, source, owner, outerTypeQualificationDone, confirmFrame.Generation, confirm,
		)
	}()
	qualificationContext, err := qualificationRebindContext(control)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := owner.runMaximumDataQualification(
		ctx, candidate, responderConn.LocalAddr(), 2, outerQualificationRebind, qualificationContext,
	); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-peerResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("qualification peer did not finish")
	}
}

func TestMaximumDataQualificationReplayStateIsBoundedAndABASafe(t *testing.T) {
	owner, wire := newOuterTestOwner(t)
	remote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 47201}
	control := outerControl{
		Transaction: linkTransaction{51}, Agreement: linkAgreement{52}, Nonce: linkNonce{53}, ReceiveNext: 1,
	}
	qualificationContext, err := qualificationRebindContext(control)
	if err != nil {
		t.Fatal(err)
	}
	observation := mustOuterRouteObservation(
		t, outerUDPIPv4, wire.conn.LocalAddr().(*net.UDPAddr), remote, 1, 1260,
	)
	request := func(round uint32, nonce byte) outerQualification {
		initiator := linkNonce{nonce}
		return outerQualification{
			Purpose: outerQualificationRebind, Round: round, InitiatorNonce: initiator, Context: qualificationContext,
			Binding: computeOuterQualificationBinding(
				owner.secret, owner.id, 2, outerQualificationRebind, round, initiator, qualificationContext,
			),
		}
	}
	first := request(1, 54)
	firstResponse, accepted := owner.acceptMaximumDataQualificationRequest(wire, remote, 2, first, observation)
	if !accepted {
		t.Fatal("first qualification request was rejected")
	}
	duplicate, accepted := owner.acceptMaximumDataQualificationRequest(wire, remote, 2, first, observation)
	if !accepted || duplicate != firstResponse {
		t.Fatal("exact qualification replay did not reuse responder nonce")
	}
	if _, confirmation, accepted := owner.confirmMaximumDataQualification(wire, remote, 2, firstResponse, observation); !accepted || confirmation == nil || owner.finishMaximumDataQualification(confirmation, true) {
		t.Fatal("first qualification confirmation was rejected")
	}
	second := request(2, 55)
	secondResponse, accepted := owner.acceptMaximumDataQualificationRequest(wire, remote, 2, second, observation)
	if !accepted || secondResponse.ResponderNonce == firstResponse.ResponderNonce {
		t.Fatal("fresh same-candidate requalification did not replace the completed proof")
	}
	owner.mu.Lock()
	pendingAfterReplace := owner.pendingPeer
	owner.mu.Unlock()
	if pendingAfterReplace != nil {
		t.Fatal("old peer proof remained commit-eligible during requalification")
	}
	owner.mu.Lock()
	stateDuringSecond := owner.peerQualification
	owner.mu.Unlock()
	if _, accepted := owner.acceptMaximumDataQualificationRequest(wire, remote, 2, first, observation); accepted {
		t.Fatal("delayed older qualification request was accepted during a newer proof")
	}
	owner.mu.Lock()
	stateAfterInFlightReplay := owner.peerQualification
	pendingAfterInFlightReplay := owner.pendingPeer
	owner.mu.Unlock()
	if stateAfterInFlightReplay != stateDuringSecond || pendingAfterInFlightReplay != nil {
		t.Fatalf("older replay changed in-flight newer proof state=%+v pending=%+v",
			stateAfterInFlightReplay, pendingAfterInFlightReplay)
	}
	if _, _, accepted := owner.confirmMaximumDataQualification(wire, remote, 2, firstResponse, observation); accepted {
		t.Fatal("stale confirmation completed a replaced qualification")
	}
	cross := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: remote.Port + 1}
	if _, accepted := owner.acceptMaximumDataQualificationRequest(wire, cross, 2, second, observation); accepted {
		t.Fatal("cross-candidate request replaced an in-flight qualification")
	}
	if _, confirmation, accepted := owner.confirmMaximumDataQualification(wire, remote, 2, secondResponse, observation); !accepted || confirmation == nil || owner.finishMaximumDataQualification(confirmation, true) {
		t.Fatal("fresh qualification confirmation was rejected")
	}
	owner.mu.Lock()
	state := owner.peerQualification
	pending := owner.pendingPeer
	owner.mu.Unlock()
	if state == nil || !state.confirmed || pending == nil || !pending.qualified || pending.control != control {
		t.Fatalf("bounded qualification state=%+v pending=%+v", state, pending)
	}
	if _, accepted := owner.acceptMaximumDataQualificationRequest(wire, remote, 2, first, observation); accepted {
		t.Fatal("delayed older qualification request revoked a newer complete proof")
	}
	owner.mu.Lock()
	stateAfterReplay := owner.peerQualification
	pendingAfterReplay := owner.pendingPeer
	owner.mu.Unlock()
	if stateAfterReplay != state || pendingAfterReplay != pending ||
		stateAfterReplay.qualification.Round != second.Round || pendingAfterReplay.qualificationRound != second.Round {
		t.Fatalf("older replay changed latest proof state=%+v pending=%+v", stateAfterReplay, pendingAfterReplay)
	}
}

func TestSharedReaderTerminalErrorFailsEveryOwnerAndUnblocksListener(t *testing.T) {
	requireOuterPacketSupport(t)
	listener, err := ListenPacket("127.0.0.1:0", WithTrustedCarrier())
	if err != nil {
		t.Fatal(err)
	}
	clients := make([]transport.PathConn, 0, 2)
	servers := make([]transport.PathConn, 0, 2)
	for range 2 {
		client, server := dialAndAccept(t, listener)
		clients = append(clients, client)
		servers = append(servers, server)
	}
	defer func() {
		for _, path := range clients {
			_ = path.Close()
		}
		for _, path := range servers {
			_ = path.Close()
		}
	}()
	marker := errors.New("injected shared reader terminal failure")
	listener.failSharedPacketReader(errors.Join(marker, syscall.EMSGSIZE))
	for index, server := range servers {
		owner := server.(*retainedPathConn).link
		select {
		case <-owner.done:
		case <-time.After(time.Second):
			t.Fatalf("shared owner %d remained live", index)
		}
		terminal := owner.terminalError()
		if !errors.Is(terminal, marker) || !errors.Is(terminal, ErrOuterMTU) ||
			!errors.Is(terminal, syscall.EMSGSIZE) {
			t.Fatalf("shared owner %d terminal=%v", index, terminal)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if path, err := listener.Accept(ctx); path != nil || !errors.Is(err, marker) ||
		!errors.Is(err, ErrOuterMTU) {
		t.Fatalf("Accept after shared failure=(%v,%v)", path, err)
	}
	if err := listener.Close(); !errors.Is(err, marker) || !errors.Is(err, ErrOuterMTU) {
		t.Fatalf("Close after shared failure=%v", err)
	}
}

func TestSharedReaderPumpFansActualReadFailureToEveryOwner(t *testing.T) {
	requireOuterPacketSupport(t)
	listener, err := ListenPacket("127.0.0.1:0", WithTrustedCarrier())
	if err != nil {
		t.Fatal(err)
	}
	clients := make([]transport.PathConn, 0, 2)
	servers := make([]transport.PathConn, 0, 2)
	for range 2 {
		client, server := dialAndAccept(t, listener)
		clients = append(clients, client)
		servers = append(servers, server)
	}
	defer func() {
		for _, path := range clients {
			_ = path.Close()
		}
		for _, path := range servers {
			_ = path.Close()
		}
		_ = listener.Close()
	}()
	if err := listener.wire.Close(); err != nil {
		t.Fatal(err)
	}
	for index, server := range servers {
		owner := server.(*retainedPathConn).link
		select {
		case <-owner.done:
		case <-time.After(time.Second):
			t.Fatalf("shared reader pump left owner %d live", index)
		}
	}
	deadline := time.Now().Add(time.Second)
	for {
		listener.lifecycleMu.Lock()
		terminal := listener.terminalErr
		listener.lifecycleMu.Unlock()
		if terminal != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("shared reader pump did not retain its terminal cause")
		}
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if path, err := listener.Accept(ctx); path != nil || err == nil {
		t.Fatalf("Accept after actual shared read failure=(%v,%v)", path, err)
	}
}

func sendQualificationTestFrame(
	conn net.PacketConn,
	remote net.Addr,
	owner *linkOwner,
	typ outerType,
	generation uint64,
	qualification outerQualification,
) error {
	payload, err := marshalOuterQualification(typ, qualification)
	if err != nil {
		return err
	}
	datagram, err := encodeOuterControl(outerFrame{
		Type: typ, LinkID: owner.id, Generation: generation, Payload: payload,
	}, owner.secret)
	if err != nil {
		return err
	}
	if len(datagram) != outerMaxDatagramSize {
		return fmt.Errorf("qualification test datagram=%d", len(datagram))
	}
	n, err := conn.WriteTo(datagram, remote)
	if err == nil && n != len(datagram) {
		err = fmt.Errorf("qualification test short write %d/%d", n, len(datagram))
	}
	return err
}

func TestOuterMTURecoveryDeadlineIsSingleAndTerminalEvidenceIsStable(t *testing.T) {
	owner, _ := newOuterTestOwner(t)
	owner.mtuRecoveryBudget = 250 * time.Millisecond
	firstMarker := errors.New("first EMSGSIZE")
	firstCause := classifyOuterMTUError(outerMaxDatagramSize, errors.Join(firstMarker, syscall.EMSGSIZE))
	recovery := owner.noteOuterMTUFailure(firstCause)
	if recovery == nil {
		t.Fatal("first EMSGSIZE did not create a recovery episode")
	}
	initialDeadline := recovery.deadline
	secondMarker := errors.New("second EMSGSIZE")
	secondCause := classifyOuterMTUError(outerMaxDatagramSize, errors.Join(secondMarker, syscall.EMSGSIZE))
	if repeated := owner.noteOuterMTUFailure(secondCause); repeated != recovery ||
		!repeated.deadline.Equal(initialDeadline) {
		t.Fatal("repeated EMSGSIZE replaced or extended the recovery episode")
	}

	frameworkDeadline := time.Now().Add(80 * time.Millisecond)
	owner.bindOuterMTURecoveryDeadline(frameworkDeadline)
	boundDeadline := recovery.deadline
	if boundDeadline.After(frameworkDeadline) || !boundDeadline.Before(initialDeadline) {
		t.Fatalf("framework deadline was not applied once: initial=%v bound=%v framework=%v",
			initialDeadline, boundDeadline, frameworkDeadline)
	}
	owner.bindOuterMTURecoveryDeadline(time.Now().Add(time.Second))
	owner.noteOuterMTUFailure(secondCause)
	if !recovery.deadline.Equal(boundDeadline) {
		t.Fatalf("later EMSGSIZE/framework activity reset deadline from %v to %v", boundDeadline, recovery.deadline)
	}

	select {
	case <-owner.done:
	case <-time.After(time.Second):
		t.Fatal("outer MTU recovery deadline did not fail the owner closed")
	}
	terminalErr := owner.terminalError()
	if !errors.Is(terminalErr, ErrOuterMTU) || !errors.Is(terminalErr, syscall.EMSGSIZE) ||
		!errors.Is(terminalErr, firstMarker) || errors.Is(terminalErr, secondMarker) {
		t.Fatalf("terminal outer MTU evidence=%v", terminalErr)
	}
}

func TestSuccessorReceiverRejectsTruncatedOversizedDatagram(t *testing.T) {
	remote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 47002}
	conn := newScriptedPacketConn(
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 47001}, remote,
	)
	wire := newPacketWire(conn, false)
	injected := make(chan []byte, 2)
	owner, err := newLinkOwner(
		linkID{1}, linkSecret{2}, leafmobility.RoleDialer, [4]byte{10, 64, 0, 7},
		wire, remote, nil, func(packet []byte) { injected <- append([]byte(nil), packet...) },
	)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.close()
	owner.startReceiver(wire)

	truncatedPrefix := inboundTestPacket(owner, packetMTU, 0xa1)
	oversized, err := encodeOuterData(owner.id, 1, 1, truncatedPrefix, owner.secret)
	if err != nil {
		t.Fatal(err)
	}
	oversized = append(oversized, 0xde, 0xad)
	validPacket := inboundTestPacket(owner, packetMTU, 0xb2)
	valid, err := encodeOuterData(owner.id, 1, 1, validPacket, owner.secret)
	if err != nil {
		t.Fatal(err)
	}
	conn.queue(oversized)
	conn.queue(valid)
	select {
	case packet := <-injected:
		if !bytes.Equal(packet, validPacket) {
			t.Fatal("truncated oversized DATA prefix reached the successor endpoint")
		}
	case <-time.After(time.Second):
		t.Fatal("valid DATA after oversized datagram was not received")
	}
	select {
	case <-injected:
		t.Fatal("oversized and valid DATA were both injected")
	case <-time.After(30 * time.Millisecond):
	}
}

func TestOuterMTUTerminalCauseIsDeathOnly(t *testing.T) {
	owner, _ := newOuterTestOwner(t)
	left, right := net.Pipe()
	defer right.Close()
	if err := owner.bindEndpoint(left, nil); err != nil {
		t.Fatal(err)
	}
	path, err := newRetainedPacketPathConn(basetcp.Wrap(left), owner, leafmobility.RoleDialer)
	if err != nil {
		t.Fatal(err)
	}
	defer path.Close()
	type deathResult struct {
		cause transport.DeathCause
		err   error
	}
	death := make(chan deathResult, 1)
	path.OnDeath(func(cause transport.DeathCause, err error) {
		death <- deathResult{cause: cause, err: err}
	})
	readResult := make(chan error, 1)
	go func() {
		_, err := path.Read(make([]byte, basetcp.MaxFrameSize))
		readResult <- err
	}()

	terminal := classifyOuterMTUError(outerMaxDatagramSize, syscall.EMSGSIZE)
	owner.noteOuterMTUFailure(terminal)
	owner.failClosed(errors.New("gvisor: injected transaction cleanup failure"))
	select {
	case err := <-readResult:
		if !errors.Is(err, net.ErrClosed) || errors.Is(err, ErrOuterMTU) || errors.Is(err, syscall.EMSGSIZE) {
			t.Fatalf("application Read exposed terminal transport evidence: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("terminal owner close did not unblock application Read")
	}
	select {
	case result := <-death:
		if result.cause != transport.CauseTransportError || !errors.Is(result.err, ErrOuterMTU) ||
			!errors.Is(result.err, syscall.EMSGSIZE) {
			t.Fatalf("death evidence=(%v,%v)", result.cause, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("terminal owner close did not publish death evidence")
	}
}

func mustOuterRouteObservation(
	t testing.TB,
	family outerUDPMode,
	local, remote *net.UDPAddr,
	oif uint32,
	pmtu int,
) routeObservation {
	t.Helper()
	observation, err := newRouteObservation(
		family, local, remote, outerRoutePlatformEvidence{outputInterface: oif, pathMTU: pmtu},
	)
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

func newOuterTestOwner(t testing.TB) (*linkOwner, *packetWire) {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	wire := newPacketWire(conn, false)
	owner, err := newLinkOwner(
		linkID{1}, linkSecret{2}, leafmobility.RoleDialer, [4]byte{10, 64, 0, 6}, wire,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 46999}, nil, func([]byte) {},
	)
	if err != nil {
		wire.close()
		t.Fatal(err)
	}
	t.Cleanup(owner.close)
	return owner, wire
}

func newMaximumDataQualificationPair(
	t testing.TB,
) (*linkOwner, *linkOwner, *packetWire, net.Addr, outerControl) {
	t.Helper()
	initiatorConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	responderConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		_ = initiatorConn.Close()
		t.Fatal(err)
	}
	initiatorWire := newPacketWire(initiatorConn, false)
	responderWire := newPacketWire(responderConn, false)
	id, secret := linkID{1}, linkSecret{2}
	initiator, err := newLinkOwner(
		id, secret, leafmobility.RoleDialer, [4]byte{10, 64, 0, 31}, initiatorWire,
		responderConn.LocalAddr(), nil, func([]byte) {},
	)
	if err != nil {
		initiatorWire.close()
		responderWire.close()
		t.Fatal(err)
	}
	responder, err := newLinkOwner(
		id, secret, leafmobility.RoleAcceptor, [4]byte{10, 64, 0, 31}, responderWire,
		initiatorConn.LocalAddr(), nil, func([]byte) {},
	)
	if err != nil {
		initiator.close()
		responderWire.close()
		t.Fatal(err)
	}
	responder.observeRoute = func(_ context.Context, wire *packetWire, remote net.Addr) (routeObservation, error) {
		return newRouteObservation(
			outerUDPIPv4,
			wire.conn.LocalAddr().(*net.UDPAddr),
			remote.(*net.UDPAddr),
			outerRoutePlatformEvidence{outputInterface: 1, pathMTU: 1260, pathMTUKnown: true},
		)
	}
	responder.startReceiver(responderWire)
	t.Cleanup(initiator.close)
	t.Cleanup(responder.close)
	control := outerControl{
		Transaction: linkTransaction{1}, Agreement: linkAgreement{2}, Nonce: linkNonce{3}, ReceiveNext: 1,
	}
	return initiator, responder, initiatorWire, responderConn.LocalAddr(), control
}

func newPublishQualificationPair(
	t testing.TB,
) (*linkOwner, *linkOwner, *packetWire, *packetWire, net.Addr, outerControl) {
	t.Helper()
	candidateConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	activeConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		_ = candidateConn.Close()
		t.Fatal(err)
	}
	peerConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		_ = candidateConn.Close()
		_ = activeConn.Close()
		t.Fatal(err)
	}
	candidate := newPacketWire(candidateConn, false)
	active := newPacketWire(activeConn, false)
	peerWire := newPacketWire(peerConn, false)
	id, secret := linkID{11}, linkSecret{12}
	owner, err := newLinkOwner(
		id, secret, leafmobility.RoleDialer, [4]byte{10, 64, 0, 32}, active,
		peerConn.LocalAddr(), nil, func([]byte) {},
	)
	if err != nil {
		candidate.close()
		active.close()
		peerWire.close()
		t.Fatal(err)
	}
	peer, err := newLinkOwner(
		id, secret, leafmobility.RoleAcceptor, [4]byte{10, 64, 0, 32}, peerWire,
		activeConn.LocalAddr(), nil, func([]byte) {},
	)
	if err != nil {
		owner.close()
		candidate.close()
		peerWire.close()
		t.Fatal(err)
	}
	peer.observeRoute = func(_ context.Context, wire *packetWire, remote net.Addr) (routeObservation, error) {
		return newRouteObservation(
			outerUDPIPv4,
			wire.conn.LocalAddr().(*net.UDPAddr),
			remote.(*net.UDPAddr),
			outerRoutePlatformEvidence{outputInterface: 1, pathMTU: 1260, pathMTUKnown: true},
		)
	}
	peer.startReceiver(peerWire)
	t.Cleanup(owner.close)
	t.Cleanup(peer.close)
	control := outerControl{
		Transaction: linkTransaction{4}, Agreement: linkAgreement{5}, Nonce: linkNonce{6}, ReceiveNext: 1,
	}
	return owner, peer, candidate, active, peerConn.LocalAddr(), control
}

func firstDatagramSize(datagrams [][]byte) int {
	if len(datagrams) == 0 {
		return 0
	}
	return len(datagrams[0])
}

type recordingPacketWriter struct {
	mu     sync.Mutex
	writes [][]byte
	err    error
}

type recordingForwardPacketWriter struct {
	net.PacketConn
	mu     sync.Mutex
	writes [][]byte
	err    error
}

func (writer *recordingForwardPacketWriter) WriteTo(packet []byte, remote net.Addr) (int, error) {
	writer.mu.Lock()
	writer.writes = append(writer.writes, append([]byte(nil), packet...))
	err := writer.err
	writer.mu.Unlock()
	if err != nil {
		return 0, err
	}
	return writer.PacketConn.WriteTo(packet, remote)
}

func (writer *recordingForwardPacketWriter) snapshot() [][]byte {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	result := make([][]byte, len(writer.writes))
	for index := range writer.writes {
		result[index] = append([]byte(nil), writer.writes[index]...)
	}
	return result
}

func (writer *recordingPacketWriter) WriteTo(packet []byte, _ net.Addr) (int, error) {
	writer.mu.Lock()
	writer.writes = append(writer.writes, append([]byte(nil), packet...))
	err := writer.err
	writer.mu.Unlock()
	if err != nil {
		return 0, err
	}
	return len(packet), nil
}

func (*recordingPacketWriter) SetWriteDeadline(time.Time) error { return nil }

func (writer *recordingPacketWriter) snapshot() [][]byte {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	result := make([][]byte, len(writer.writes))
	for index := range writer.writes {
		result[index] = append([]byte(nil), writer.writes[index]...)
	}
	return result
}

type scriptedPacketConn struct {
	local  net.Addr
	remote net.Addr
	reads  chan []byte
	done   chan struct{}
	once   sync.Once
}

type maximumDataDropRelay struct {
	conn   *net.UDPConn
	server *net.UDPAddr
	done   chan struct{}
	wait   sync.WaitGroup
	once   sync.Once

	mu            sync.Mutex
	client        *net.UDPAddr
	small         int
	maximum       int
	clientMaximum int
	serverMaximum int
	dropMaximum   func(bool, int) bool
}

func newMaximumDataDropRelay(t testing.TB, server net.Addr) *maximumDataDropRelay {
	t.Helper()
	serverUDP, ok := server.(*net.UDPAddr)
	if !ok {
		t.Fatalf("maximum-DATA relay server=%T", server)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	relay := &maximumDataDropRelay{
		conn: conn, server: cloneOuterUDPAddress(serverUDP), done: make(chan struct{}),
		dropMaximum: func(bool, int) bool { return true },
	}
	relay.wait.Add(1)
	go relay.run()
	return relay
}

func newQualificationLegDropRelay(
	t testing.TB,
	server net.Addr,
	drop func(fromServer bool, ordinal int) bool,
) *maximumDataDropRelay {
	relay := newMaximumDataDropRelay(t, server)
	relay.mu.Lock()
	relay.dropMaximum = drop
	relay.mu.Unlock()
	return relay
}

func (relay *maximumDataDropRelay) Addr() net.Addr { return relay.conn.LocalAddr() }

func (relay *maximumDataDropRelay) Close() {
	relay.once.Do(func() {
		close(relay.done)
		_ = relay.conn.Close()
	})
	relay.wait.Wait()
}

func (relay *maximumDataDropRelay) counts() (int, int) {
	relay.mu.Lock()
	defer relay.mu.Unlock()
	return relay.small, relay.maximum
}

func (relay *maximumDataDropRelay) directionalMaximumCounts() (int, int) {
	relay.mu.Lock()
	defer relay.mu.Unlock()
	return relay.clientMaximum, relay.serverMaximum
}

func (relay *maximumDataDropRelay) run() {
	defer relay.wait.Done()
	buffer := make([]byte, outerMaxDatagramSize+1)
	for {
		n, source, err := relay.conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		fromServer := addrEqual(source, relay.server)
		relay.mu.Lock()
		if n == outerMaxDatagramSize {
			relay.maximum++
			ordinal := 0
			if fromServer {
				relay.serverMaximum++
				ordinal = relay.serverMaximum
			} else {
				relay.clientMaximum++
				ordinal = relay.clientMaximum
			}
			drop := relay.dropMaximum == nil || relay.dropMaximum(fromServer, ordinal)
			if drop {
				relay.mu.Unlock()
				continue
			}
		}
		relay.small++
		if !fromServer {
			relay.client = cloneOuterUDPAddress(source)
		}
		client := cloneOuterUDPAddress(relay.client)
		relay.mu.Unlock()
		destination := relay.server
		if fromServer {
			destination = client
		}
		if destination != nil {
			_, _ = relay.conn.WriteToUDP(buffer[:n], destination)
		}
	}
}

func newScriptedPacketConn(local, remote net.Addr) *scriptedPacketConn {
	return &scriptedPacketConn{local: local, remote: remote, reads: make(chan []byte, 2), done: make(chan struct{})}
}

func (conn *scriptedPacketConn) queue(datagram []byte) {
	conn.reads <- append([]byte(nil), datagram...)
}

func (conn *scriptedPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	select {
	case datagram := <-conn.reads:
		return copy(buffer, datagram), conn.remote, nil
	case <-conn.done:
		return 0, nil, net.ErrClosed
	}
}

func (*scriptedPacketConn) WriteTo(packet []byte, _ net.Addr) (int, error) {
	return len(packet), nil
}

func (conn *scriptedPacketConn) Close() error {
	conn.once.Do(func() { close(conn.done) })
	return nil
}

func (conn *scriptedPacketConn) LocalAddr() net.Addr         { return conn.local }
func (*scriptedPacketConn) SetDeadline(time.Time) error      { return nil }
func (*scriptedPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*scriptedPacketConn) SetWriteDeadline(time.Time) error { return nil }

func inboundTestPacket(owner *linkOwner, size int, marker byte) []byte {
	packet := make([]byte, size)
	packet[0] = 0x45
	packet[20] = marker
	if owner.role == leafmobility.RoleDialer {
		copy(packet[12:16], serverIPv4[:])
		copy(packet[16:20], owner.virtualIP[:])
	} else {
		copy(packet[12:16], owner.virtualIP[:])
		copy(packet[16:20], serverIPv4[:])
	}
	return packet
}
