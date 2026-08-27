package gvisor

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/leafmobility"
)

func TestOuterV6LiteralWireBudgets(t *testing.T) {
	values := map[string]struct {
		got  int
		want int
	}{
		"version":             {int(outerVersion), 6},
		"process-local-mtu":   {processLocalMTU, 1500},
		"ipv6-minimum-mtu":    {outerIPv6MinimumMTU, 1280},
		"ipv6-header":         {outerIPv6HeaderSize, 40},
		"udp-header":          {outerUDPHeaderSize, 8},
		"outer-data-overhead": {outerDataOverhead, 56},
		"inner-packet-mtu":    {packetMTU, 1176},
		"max-udp-datagram":    {outerMaxDatagramSize, 1232},
		"open":                {outerHeaderSize + outerOpenPayloadSize, 128},
		"cookie":              {outerHeaderSize + outerCookiePayloadSize, 64},
		"open-ack":            {outerHeaderSize + outerOpenAckPayloadSize + outerAuthTagSize, 100},
		"path-control":        {outerHeaderSize + outerControlPayloadSize + outerAuthTagSize, 120},
		"liveness-control":    {outerHeaderSize + outerLivenessPayloadSize + outerAuthTagSize, 72},
		"data-ack":            {outerHeaderSize + outerDataAckPayloadSize + outerAuthTagSize, 56},
		"qualification":       {outerHeaderSize + outerQualificationPayloadSize + outerAuthTagSize, 1232},
	}
	for name, value := range values {
		t.Run(name, func(t *testing.T) {
			if value.got != value.want {
				t.Fatalf("%s=%d want literal %d", name, value.got, value.want)
			}
		})
	}
	if got := outerIPv6HeaderSize + outerUDPHeaderSize + outerMaxDatagramSize; got != 1280 {
		t.Fatalf("maximum DATA IPv6 packet=%d want 1280", got)
	}

	id := linkID{1}
	secret := linkSecret{2}
	controlPayload, err := marshalOuterControl(outerControl{
		Transaction: linkTransaction{1}, Agreement: linkAgreement{2}, Nonce: linkNonce{3}, ReceiveNext: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	livenessPayload, err := marshalOuterLiveness(outerLiveness{Nonce: linkNonce{1}, ReceiveNext: 1})
	if err != nil {
		t.Fatal(err)
	}
	dataAckPayload, err := marshalOuterDataAck(1)
	if err != nil {
		t.Fatal(err)
	}
	qualificationContext, err := qualificationRebindContext(outerControl{
		Transaction: linkTransaction{1}, Agreement: linkAgreement{2}, Nonce: linkNonce{3}, ReceiveNext: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	qualification := outerQualification{
		Purpose: outerQualificationRebind, Round: 1, InitiatorNonce: linkNonce{4}, Context: qualificationContext,
		Binding: computeOuterQualificationBinding(
			secret, id, 1, outerQualificationRebind, 1, linkNonce{4}, qualificationContext,
		),
	}
	qualificationPayload, err := marshalOuterQualification(outerTypeQualificationRequest, qualification)
	if err != nil {
		t.Fatal(err)
	}
	cookiePayload, err := marshalOuterCookie(outerCookie{1})
	if err != nil {
		t.Fatal(err)
	}
	encoded := []struct {
		name  string
		frame outerFrame
		key   linkSecret
		want  int
	}{
		{
			name: "open",
			frame: outerFrame{Type: outerTypeOpen, Sender: leafmobility.RoleDialer, LinkID: id, Generation: 1, Payload: marshalOpen(
				linkPublicKey{1}, linkNonce{2}, outerCookie{3}, outerProof{4},
			)},
			want: 128,
		},
		{
			name: "cookie", frame: outerFrame{
				Type: outerTypeCookie, Sender: leafmobility.RoleAcceptor, LinkID: id, Generation: 1, Payload: cookiePayload,
			}, want: 64,
		},
		{
			name: "open-ack", frame: outerFrame{
				Type: outerTypeOpenAck, Sender: leafmobility.RoleAcceptor, LinkID: id, Generation: 1,
				Payload: marshalOpenAck(linkPublicKey{1}, [4]byte{10, 64, 0, 1}, linkNonce{2}),
			}, key: secret, want: 100,
		},
		{
			name: "path-control", frame: outerFrame{
				Type: outerTypePathChallenge, Sender: leafmobility.RoleDialer,
				LinkID: id, Generation: 1, Payload: controlPayload,
			}, key: secret, want: 120,
		},
		{
			name: "liveness-control", frame: outerFrame{
				Type: outerTypeLivenessChallenge, Sender: leafmobility.RoleDialer,
				LinkID: id, Generation: 1, Payload: livenessPayload,
			}, key: secret, want: 72,
		},
		{
			name: "data-ack", frame: outerFrame{
				Type: outerTypeDataAck, Sender: leafmobility.RoleDialer,
				LinkID: id, Generation: 1, Payload: dataAckPayload,
			}, key: secret, want: 56,
		},
		{
			name: "qualification", frame: outerFrame{
				Type: outerTypeQualificationRequest, Sender: leafmobility.RoleDialer,
				LinkID: id, Generation: 1, Payload: qualificationPayload,
			}, key: secret, want: 1232,
		},
	}
	for _, test := range encoded {
		t.Run("encoded-"+test.name, func(t *testing.T) {
			wire, err := encodeOuter(test.frame, test.key)
			if err != nil {
				t.Fatal(err)
			}
			if len(wire) != test.want {
				t.Fatalf("encoded %s=%d want literal %d", test.name, len(wire), test.want)
			}
		})
	}
}

func TestOuterV6DataMaximumAndOversizeRejection(t *testing.T) {
	id := linkID{1}
	secret := linkSecret{2}
	maximum := bytes.Repeat([]byte{0x45}, 1176)
	wire, err := encodeOuterData(id, 1, 1, maximum, secret, leafmobility.RoleDialer)
	if err != nil {
		t.Fatalf("encode 1176-byte DATA: %v", err)
	}
	if len(wire) != 1232 {
		t.Fatalf("1176-byte DATA wire=%d want 1232", len(wire))
	}
	if _, err := encodeOuterData(
		id, 1, 1, append(maximum, 0), secret, leafmobility.RoleDialer,
	); !errors.Is(err, errOuterControlMismatch) {
		t.Fatalf("encode 1177-byte DATA error=%v want size rejection", err)
	}

	oversizeWire := make([]byte, outerHeaderSize+outerDataSequenceSize+1177+outerAuthTagSize)
	copy(oversizeWire[:4], outerMagic[:])
	oversizeWire[4] = outerVersion
	oversizeWire[5] = byte(outerTypeData)
	oversizeWire[6] = byte(leafmobility.RoleDialer)
	oversizeWire[8] = 1
	oversizeWire[31] = 1
	oversizeWire[outerHeaderSize+outerDataSequenceSize-1] = 1
	if _, err := decodeOuterHeader(oversizeWire); !errors.Is(err, errOuterMalformed) {
		t.Fatalf("decode 1177-byte DATA error=%v want malformed", err)
	}
}

func TestOuterV6MaximumDataQualificationMutationsFailClosed(t *testing.T) {
	id, secret := linkID{9}, linkSecret{8}
	context, err := qualificationRebindContext(outerControl{
		Transaction: linkTransaction{7}, Agreement: linkAgreement{6}, Nonce: linkNonce{5}, ReceiveNext: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := outerQualification{
		Purpose: outerQualificationRebind, Round: 1, InitiatorNonce: linkNonce{4}, Context: context,
		Binding: computeOuterQualificationBinding(
			secret, id, 3, outerQualificationRebind, 1, linkNonce{4}, context,
		),
	}
	payload, err := marshalOuterQualification(outerTypeQualificationRequest, request)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func([]byte){
		"revision": func(value []byte) { value[0]++ },
		"reserved": func(value []byte) { value[2] = 1 },
		"round":    func(value []byte) { clear(value[4:8]) },
		"padding":  func(value []byte) { value[len(value)-1] = 1 },
		"purpose":  func(value []byte) { value[1] = 0xff },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := append([]byte(nil), payload...)
			mutate(candidate)
			if _, err := parseOuterQualification(outerTypeQualificationRequest, candidate); err == nil {
				t.Fatal("mutated qualification payload was accepted")
			}
		})
	}
	request.ResponderNonce = linkNonce{3}
	if _, err := marshalOuterQualification(outerTypeQualificationRequest, request); err == nil {
		t.Fatal("request with responder nonce was accepted")
	}
	request.ResponderNonce = linkNonce{}
	if _, err := marshalOuterQualification(outerTypeQualificationDone, request); err == nil {
		t.Fatal("DONE without responder nonce was accepted")
	}
}

func TestOuterV6RejectsVersion5(t *testing.T) {
	wire, err := encodeOuterData(
		linkID{1}, 1, 1, []byte{0x45}, linkSecret{2}, leafmobility.RoleDialer,
	)
	if err != nil {
		t.Fatal(err)
	}
	wire[4] = 5
	if _, err := decodeOuter(wire, linkSecret{2}, leafmobility.RoleDialer); !errors.Is(err, errOuterVersion) {
		t.Fatalf("decode v5 error=%v want unsupported version", err)
	}
}

func TestOuterUDPModeSelectionIsExplicit(t *testing.T) {
	listeners := []struct {
		name string
		addr *net.UDPAddr
		want outerUDPMode
	}{
		{name: "empty-host-is-dual", addr: &net.UDPAddr{}, want: outerUDPDualStack},
		{name: "ipv4-wildcard", addr: &net.UDPAddr{IP: net.IPv4zero}, want: outerUDPIPv4},
		{name: "ipv4", addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, want: outerUDPIPv4},
		{name: "ipv6-wildcard", addr: &net.UDPAddr{IP: net.IPv6unspecified}, want: outerUDPIPv6},
		{name: "ipv6", addr: &net.UDPAddr{IP: net.IPv6loopback}, want: outerUDPIPv6},
	}
	for _, test := range listeners {
		t.Run(test.name, func(t *testing.T) {
			got, err := outerUDPListenerMode(test.addr)
			if err != nil || got != test.want {
				t.Fatalf("listener mode=(%v,%v) want %v", got, err, test.want)
			}
		})
	}
	for name, address := range map[string]*net.UDPAddr{
		"nil":              nil,
		"empty":            {},
		"ipv4-unspecified": {IP: net.IPv4zero},
		"ipv6-unspecified": {IP: net.IPv6unspecified},
	} {
		t.Run("remote-"+name, func(t *testing.T) {
			if _, err := outerUDPRemoteMode(address); err == nil {
				t.Fatal("unspecified remote was accepted")
			}
		})
	}
}

func TestOuterUDPPMTUProofFailureClosesSocket(t *testing.T) {
	injected := errors.New("injected PMTU readback failure")
	var bound *net.UDPAddr
	conn, err := listenOuterUDPWithConfigurer(
		outerUDPIPv4,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
		func(conn *net.UDPConn, mode outerUDPMode) error {
			if mode != outerUDPIPv4 {
				t.Fatalf("configurer mode=%v want IPv4", mode)
			}
			bound = cloneUDPAddress(conn.LocalAddr().(*net.UDPAddr))
			return injected
		},
	)
	if conn != nil || !errors.Is(err, injected) {
		t.Fatalf("listen with failed PMTU proof=(%v,%v)", conn, err)
	}
	if bound == nil {
		t.Fatal("configurer did not observe the created socket")
	}
	rebound, err := net.ListenUDP("udp4", bound)
	if err != nil {
		t.Fatalf("PMTU proof failure leaked bound socket %s: %v", bound, err)
	}
	_ = rebound.Close()
}

func TestOuterEMSGSIZEClassificationAndNoUnchangedRouteRetry(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	wire := newPacketWire(conn, false)
	writer := &outerMTUFailWriter{}
	if err := wire.replaceWriter(writer); err != nil {
		wire.close()
		t.Fatal(err)
	}
	owner, err := newLinkOwner(
		linkID{1}, linkSecret{2}, leafmobility.RoleDialer, [4]byte{10, 64, 0, 3}, wire,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 46003}, nil, func([]byte) {},
	)
	if err != nil {
		wire.close()
		t.Fatal(err)
	}
	remote := cloneAddr(owner.peerRemote)
	n, direct := wire.writeTo(context.Background(), make([]byte, 1232), remote)
	var typed *OuterMTUError
	if n != 0 || !errors.Is(direct, ErrOuterMTU) || !errors.Is(direct, syscall.EMSGSIZE) ||
		!errors.As(direct, &typed) {
		owner.close()
		t.Fatalf("classified error=%v does not preserve stable type and errno", direct)
	}
	if typed.DatagramBytes != 1232 || typed.MaxDatagramBytes != 1232 {
		owner.close()
		t.Fatalf("typed outer MTU error=%+v", typed)
	}
	if writer.writes.Load() != 1 {
		owner.close()
		t.Fatalf("EMSGSIZE writes=%d want 1", writer.writes.Load())
	}

	local := cloneOuterUDPAddress(conn.LocalAddr().(*net.UDPAddr))
	udpRemote := cloneOuterUDPAddress(remote.(*net.UDPAddr))
	failedRoute, err := newRouteObservation(
		outerUDPIPv4, local, udpRemote,
		outerRoutePlatformEvidence{outputInterface: 1, pathMTU: 1259},
	)
	if err != nil {
		owner.close()
		t.Fatal(err)
	}
	recoveredRoute, err := newRouteObservation(
		outerUDPIPv4, local, udpRemote,
		outerRoutePlatformEvidence{outputInterface: 1, pathMTU: 1260},
	)
	if err != nil {
		owner.close()
		t.Fatal(err)
	}
	var routeMu sync.RWMutex
	currentRoute := failedRoute
	observed := make(chan struct{}, 8)
	owner.observeRoute = func(context.Context, *packetWire, net.Addr) (routeObservation, error) {
		routeMu.RLock()
		observation := currentRoute
		routeMu.RUnlock()
		select {
		case observed <- struct{}{}:
		default:
		}
		return observation, nil
	}
	owner.mtuRecoveryBudget = time.Second
	recovery := owner.noteOuterMTUFailure(direct)
	if recovery == nil {
		owner.close()
		t.Fatal("EMSGSIZE did not start an outer MTU recovery episode")
	}
	owner.mu.Lock()
	generation := owner.localGeneration
	owner.mu.Unlock()
	waitResult := make(chan error, 1)
	go func() { waitResult <- owner.waitForOuterRouteChange(wire, remote, generation, recovery) }()
	for range 2 {
		select {
		case <-observed:
		case <-time.After(time.Second):
			owner.close()
			t.Fatal("route retry gate did not observe failed and current routes")
		}
	}
	owner.mu.Lock()
	owner.signalChangedLocked()
	owner.mu.Unlock()
	select {
	case err := <-waitResult:
		owner.close()
		t.Fatalf("unchanged route released EMSGSIZE retry gate: %v", err)
	case <-time.After(2 * outerWriteRetryInterval):
	}
	routeMu.Lock()
	currentRoute = recoveredRoute
	routeMu.Unlock()
	owner.mu.Lock()
	owner.signalChangedLocked()
	owner.mu.Unlock()
	select {
	case err := <-waitResult:
		if err != nil {
			owner.close()
			t.Fatalf("MTU-only outer route retry gate error=%v", err)
		}
	case <-time.After(time.Second):
		owner.close()
		t.Fatal("same-source MTU-only route change did not release EMSGSIZE retry gate")
	}
	if err := owner.completeOuterMTURecovery(outerMaxDatagramSize); err != nil {
		owner.close()
		t.Fatal(err)
	}
	owner.close()
}

type outerMTUFailWriter struct{ writes atomic.Uint64 }

func (writer *outerMTUFailWriter) WriteTo([]byte, net.Addr) (int, error) {
	writer.writes.Add(1)
	return 0, syscall.EMSGSIZE
}

func (*outerMTUFailWriter) SetWriteDeadline(time.Time) error { return nil }

func cloneUDPAddress(address *net.UDPAddr) *net.UDPAddr {
	if address == nil {
		return nil
	}
	clone := *address
	clone.IP = append(net.IP(nil), address.IP...)
	return &clone
}
