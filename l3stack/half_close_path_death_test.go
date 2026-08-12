package l3stack

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	rendr "github.com/FrankoonG/rendr"
	"github.com/FrankoonG/rendr/l3ingress"
	"github.com/FrankoonG/rendr/l3session"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	gtcp "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// TestGatewayTCPHalfClosePathDeath is the deterministic public integration
// oracle for CLOSE.half-close-path-death.
func TestGatewayTCPHalfClosePathDeath(t *testing.T) {
	const (
		carrierA       = "half-close-a"
		carrierB       = "half-close-b"
		requestSize    = 64 << 10
		responseSize   = 512 << 10
		responsePrefix = 32 << 10
	)

	runtimeConfig := rendr.DefaultRuntimeConfig()
	runtimeConfig.Selector.QualityDwell = 30 * time.Second
	runtimeConfig.Selector.QualityCooldown = 30 * time.Second
	serverRuntime, err := rendr.NewRuntime(runtimeConfig)
	if err != nil {
		t.Fatal(err)
	}
	listenerA, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenerB, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = listenerA.Close()
		t.Fatal(err)
	}
	listener, err := serverRuntime.Listen(rendr.ListenConfig{
		AcceptL3Identity: true,
		Streams: []rendr.StreamSource{
			{Name: carrierA, Carrier: rendr.CarrierTCP, Listener: listenerA},
			{Name: carrierB, Carrier: rendr.CarrierTCP, Listener: listenerB},
		},
	})
	if err != nil {
		_ = listenerA.Close()
		_ = listenerB.Close()
		t.Fatal(err)
	}

	carriers := newHalfCloseCarrierSet()
	clientRuntime, err := rendr.NewRuntime(runtimeConfig)
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	for _, name := range []string{carrierA, carrierB} {
		if err := clientRuntime.RegisterStreamFactory(name, carriers.factory(name)); err != nil {
			_ = listener.Close()
			t.Fatal(err)
		}
	}
	root := rendr.Selector("root", []rendr.Target{
		rendr.Path("a", rendr.PathSpec{Transport: carrierA, Address: listenerA.Addr().String()}),
		rendr.Path("b", rendr.PathSpec{Transport: carrierB, Address: listenerB.Addr().String()}),
	})

	egressApp, egressPeer := newHalfCloseTCPConnPair(t)
	egress := &halfCloseTCPEgress{conn: egressPeer, identities: make(chan l3ingress.L3Identity, 1)}
	registry := l3ingress.NewEgressRegistry()
	if err := registry.Register("direct", egress); err != nil {
		_ = listener.Close()
		_ = egressApp.Close()
		_ = egressPeer.Close()
		t.Fatal(err)
	}

	peerCtx, stopPeer := context.WithCancel(context.Background())
	peerAccepted := make(chan rendr.Conn, 1)
	peerDone := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.AcceptStream(peerCtx)
		if acceptErr != nil {
			peerDone <- acceptErr
			return
		}
		peerAccepted <- conn
		relayErr := (&l3session.TCPPeerRelay{Conn: conn, Egresses: registry}).Run(peerCtx)
		closeErr := conn.Close()
		if relayErr != nil {
			relayErr = fmt.Errorf("TCPPeerRelay.Run: %w", relayErr)
		}
		if closeErr != nil {
			closeErr = fmt.Errorf("accepted Conn.Close: %w", closeErr)
		}
		peerDone <- errors.Join(relayErr, closeErr)
	}()

	flowErrors := make(chan error, 8)
	device := newHalfCloseTestDevice(1500)
	gateway, err := New(Config{
		Device:  device,
		Starter: &l3session.Starter{Runtime: clientRuntime},
		Router: func(context.Context, l3ingress.FlowMeta) (l3ingress.FlowDecision, error) {
			return l3ingress.FlowDecision{Peer: "peer-a", Root: root, Egress: "direct"}, nil
		},
		OnFlowError: func(_ l3ingress.L3Identity, err error) { flowErrors <- err },
	})
	if err != nil {
		stopPeer()
		_ = listener.Close()
		_ = egressApp.Close()
		t.Fatal(err)
	}
	gatewayCtx, stopGateway := context.WithCancel(context.Background())
	gatewayDone := make(chan error, 1)
	go func() { gatewayDone <- gateway.Run(gatewayCtx) }()

	clientStack, clientLink := newHalfCloseClientStack(
		t, header.IPv4ProtocolNumber, netip.MustParseAddr("10.0.0.2"), 24,
	)
	bridgeCtx, stopBridge := context.WithCancel(context.Background())
	bridgeHalfClosePackets(bridgeCtx, clientLink, device, header.IPv4ProtocolNumber)
	destination := netip.MustParseAddr("198.51.100.20")
	app, err := gonet.DialTCP(clientStack, tcpip.FullAddress{
		NIC: stackNICID, Addr: halfCloseTCPIPAddress(destination), Port: 443,
	}, header.IPv4ProtocolNumber)
	if err != nil {
		stopBridge()
		stopGateway()
		stopPeer()
		_ = gateway.Close()
		_ = listener.Close()
		_ = device.Close()
		_ = egressApp.Close()
		clientLink.Close()
		clientStack.Close()
		t.Fatal(err)
	}

	responseRelease := make(chan struct{})
	var releaseResponse sync.Once
	release := func() { releaseResponse.Do(func() { close(responseRelease) }) }
	cleanup := func() {
		release()
		stopBridge()
		stopGateway()
		stopPeer()
		_ = app.Close()
		_ = egressApp.Close()
		_ = device.Close()
		_ = listener.Close()
		clientLink.Close()
		clientStack.Close()
	}
	t.Cleanup(cleanup)

	local := app.LocalAddr().(*net.TCPAddr).AddrPort()
	id := l3ingress.L3Identity{
		Proto: l3ingress.ProtocolTCP, SrcIP: local.Addr(), SrcPort: local.Port(),
		DstIP: destination, DstPort: 443,
	}
	clientSession, clientControl := waitHalfCloseGatewaySession(t, gateway, id, 2)
	serverConn := waitHalfCloseAccepted(t, peerAccepted)
	serverControl, ok := serverConn.(halfCloseStreamControl)
	if !ok {
		t.Fatalf("accepted rendr Conn %T does not expose stream observation", serverConn)
	}
	waitHalfClosePaths(t, serverControl, 2)

	appHalf, ok := any(app).(interface{ CloseWrite() error })
	if !ok {
		t.Fatalf("application TCP endpoint %T does not support CloseWrite", app)
	}
	if _, ok := clientSession.Conn.(rendr.StreamHalfCloser); !ok {
		t.Fatalf("client rendr Conn %T does not support CloseWrite", clientSession.Conn)
	}
	if _, ok := serverConn.(rendr.StreamHalfCloser); !ok {
		t.Fatalf("accepted rendr Conn %T does not support CloseWrite", serverConn)
	}
	var egressHalf l3ingress.TCPConn = egressApp

	appHandle := reflect.ValueOf(app).Pointer()
	appLocal, appRemote := app.LocalAddr().String(), app.RemoteAddr().String()
	rendrConn := clientSession.Conn
	flowID := rendrConn.FlowID()
	rendrLocal, rendrRemote := halfCloseAddr(rendrConn.LocalAddr()), halfCloseAddr(rendrConn.RemoteAddr())
	egressHandle, err := halfCloseSocketHandle(egressApp)
	if err != nil {
		t.Fatalf("egress socket handle: %v", err)
	}
	egressLocal, egressRemote := egressApp.LocalAddr().String(), egressApp.RemoteAddr().String()
	if flowID == ([16]byte{}) || serverConn.FlowID() != flowID {
		t.Fatalf("rendr flow identity client=%x server=%x", flowID, serverConn.FlowID())
	}
	if got := carriers.successfulDials(carrierA); got != 1 {
		t.Fatalf("carrier %q successful dials=%d want=1", carrierA, got)
	}
	if got := carriers.successfulDials(carrierB); got != 1 {
		t.Fatalf("carrier %q successful dials=%d want=1", carrierB, got)
	}

	request := halfClosePayload(requestSize, 0x51)
	response := halfClosePayload(responseSize, 0xa7)
	requestHash, responseHash := sha256.Sum256(request), sha256.Sum256(response)
	requestDone := make(chan error, 1)
	egressDone := make(chan error, 1)
	go func() {
		got, readErr := io.ReadAll(egressApp)
		if readErr == nil && (len(got) != len(request) || sha256.Sum256(got) != requestHash) {
			readErr = fmt.Errorf("request integrity: bytes=%d/%d hash=%x/%x", len(got), len(request), sha256.Sum256(got), requestHash)
		}
		requestDone <- readErr
		if readErr != nil {
			egressDone <- readErr
			return
		}
		if writeErr := halfCloseWriteAll(egressApp, response[:responsePrefix]); writeErr != nil {
			egressDone <- writeErr
			return
		}
		select {
		case <-responseRelease:
		case <-peerCtx.Done():
			egressDone <- peerCtx.Err()
			return
		}
		if writeErr := halfCloseWriteAll(egressApp, response[responsePrefix:]); writeErr != nil {
			egressDone <- writeErr
			return
		}
		egressDone <- egressHalf.CloseWrite()
	}()

	prefixDelivered := make(chan struct{})
	responseDone := make(chan error, 1)
	if err := app.SetReadDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatal(err)
	}
	go func() {
		hash := sha256.New()
		buf := make([]byte, 16<<10)
		total := 0
		prefixSignaled := false
		for total < len(response) {
			want := len(buf)
			if remaining := len(response) - total; remaining < want {
				want = remaining
			}
			n, readErr := app.Read(buf[:want])
			if n > 0 {
				_, _ = hash.Write(buf[:n])
				total += n
				if !prefixSignaled && total >= responsePrefix {
					prefixSignaled = true
					close(prefixDelivered)
				}
			}
			if readErr != nil {
				responseDone <- fmt.Errorf("application read ended at %d/%d bytes before response completion: %w", total, len(response), readErr)
				return
			}
			if n == 0 {
				responseDone <- fmt.Errorf("application returned a zero read at %d/%d bytes", total, len(response))
				return
			}
		}
		if got := hash.Sum(nil); !reflect.DeepEqual(got, responseHash[:]) {
			responseDone <- fmt.Errorf("response hash=%x want=%x", got, responseHash)
			return
		}
		var extra [1]byte
		n, readErr := app.Read(extra[:])
		if n != 0 || !errors.Is(readErr, io.EOF) {
			responseDone <- fmt.Errorf("application terminal read=(%d,%v), want (0,EOF)", n, readErr)
			return
		}
		responseDone <- nil
	}()

	if err := halfCloseWriteAll(app, request); err != nil {
		t.Fatalf("application request write: %v", err)
	}
	if err := appHalf.CloseWrite(); err != nil {
		t.Fatalf("application CloseWrite: %v", err)
	}
	waitHalfCloseResult(t, "peer request EOF and hash", requestDone, 4*time.Second)
	waitHalfCloseSignal(t, "reverse response prefix", prefixDelivered, 4*time.Second)
	assertNoHalfCloseFlowError(t, flowErrors)

	before := serverControl.Stats()
	oldPath, ok := halfClosePathByID(before.Paths, before.ActivePath)
	if !ok {
		t.Fatalf("reverse sender active path %d missing from %+v", before.ActivePath, before.Paths)
	}
	clientBefore := clientControl.Stats()
	clientOldPath, ok := halfClosePathByID(clientBefore.Paths, clientBefore.ActivePath)
	if !ok || clientOldPath.Spec.Transport != oldPath.Spec.Transport {
		t.Fatalf("directional active carriers are not aligned before stimulus: client=%+v server=%+v", clientOldPath, oldPath)
	}
	survivorPath, ok := halfCloseOtherPath(before.Paths, oldPath.ID)
	if !ok {
		t.Fatalf("reverse sender has no pre-existing survivor: %+v", before.Paths)
	}
	if oldPath.Spec.Transport == survivorPath.Spec.Transport {
		t.Fatalf("carriers are not independently named: active=%+v survivor=%+v", oldPath, survivorPath)
	}
	activeCarrier, ok := carriers.snapshot(oldPath.Spec.Transport)
	if !ok || activeCarrier.readBytes < responsePrefix {
		t.Fatalf("active carrier %q did not carry the streaming response prefix: %+v", oldPath.Spec.Transport, activeCarrier)
	}
	survivorBefore, ok := carriers.snapshot(survivorPath.Spec.Transport)
	if !ok || survivorBefore.closed {
		t.Fatalf("survivor carrier %q is not independently live: %+v", survivorPath.Spec.Transport, survivorBefore)
	}

	migrations := make(chan halfCloseMigration, 4)
	cancelMigrations := serverControl.OnMigrate(func(oldID, newID uint32, cause string) {
		migrations <- halfCloseMigration{oldID: oldID, newID: newID, cause: cause}
	})
	defer cancelMigrations()
	if err := carriers.kill(oldPath.Spec.Transport); err != nil {
		t.Fatalf("kill active carrier %q: %v", oldPath.Spec.Transport, err)
	}
	if killed, _ := carriers.snapshot(oldPath.Spec.Transport); !killed.closed {
		t.Fatalf("active carrier %q did not physically close", oldPath.Spec.Transport)
	}
	if survivor, _ := carriers.snapshot(survivorPath.Spec.Transport); survivor.closed {
		t.Fatalf("killing %q also closed independent survivor %q", oldPath.Spec.Transport, survivorPath.Spec.Transport)
	}

	migration := waitHalfCloseMigration(t, migrations, oldPath.ID, 5*time.Second)
	if migration.cause != "death" {
		t.Fatalf("migration cause=%q want death", migration.cause)
	}
	if migration.newID == oldPath.ID {
		t.Fatalf("path death retained old active path %d", oldPath.ID)
	}
	afterDeath := serverControl.Stats()
	newPath, ok := halfClosePathByID(afterDeath.Paths, migration.newID)
	if !ok || newPath.Spec.Transport != survivorPath.Spec.Transport {
		t.Fatalf("death migration target=%+v want pre-existing survivor %q; paths=%+v", newPath, survivorPath.Spec.Transport, afterDeath.Paths)
	}
	if afterDeath.MigrationCount != before.MigrationCount+1 {
		t.Fatalf("death migrations=%d want=%d", afterDeath.MigrationCount, before.MigrationCount+1)
	}
	clientAfter := waitHalfCloseActiveTransport(t, clientControl, survivorPath.Spec.Transport, 5*time.Second)
	if clientAfter.MigrationCount != clientBefore.MigrationCount+1 {
		t.Fatalf("client death migrations=%d want=%d", clientAfter.MigrationCount, clientBefore.MigrationCount+1)
	}
	for _, path := range clientAfter.Paths {
		if path.Spec.Transport == oldPath.Spec.Transport {
			t.Fatalf("dead carrier %q remained attached on client: %+v", oldPath.Spec.Transport, clientAfter.Paths)
		}
	}
	if got := carriers.successfulDials(survivorPath.Spec.Transport); got != 1 {
		t.Fatalf("survivor %q was replaced instead of reused: successful dials=%d", survivorPath.Spec.Transport, got)
	}
	if got := carriers.successfulDials(oldPath.Spec.Transport); got != 1 {
		t.Fatalf("dead carrier %q was redialed: successful dials=%d", oldPath.Spec.Transport, got)
	}

	currentSession, ok := gateway.manager.Session(id)
	if !ok || currentSession != clientSession || currentSession.Conn != rendrConn {
		t.Fatalf("application rendr session was replaced: before=%p/%p after=%p/%p", clientSession, rendrConn, currentSession, func() rendr.Conn {
			if currentSession == nil {
				return nil
			}
			return currentSession.Conn
		}())
	}
	if currentSession.Conn.FlowID() != flowID || serverConn.FlowID() != flowID {
		t.Fatalf("flow ID changed across death: client=%x server=%x want=%x", currentSession.Conn.FlowID(), serverConn.FlowID(), flowID)
	}
	if reflect.ValueOf(app).Pointer() != appHandle || app.LocalAddr().String() != appLocal || app.RemoteAddr().String() != appRemote {
		t.Fatalf("application TCP handle/address changed: handle=%x/%x local=%q/%q remote=%q/%q",
			appHandle, reflect.ValueOf(app).Pointer(), appLocal, app.LocalAddr(), appRemote, app.RemoteAddr())
	}
	if halfCloseAddr(rendrConn.LocalAddr()) != rendrLocal || halfCloseAddr(rendrConn.RemoteAddr()) != rendrRemote {
		t.Fatalf("rendr application address changed: local=%q/%q remote=%q/%q",
			rendrLocal, halfCloseAddr(rendrConn.LocalAddr()), rendrRemote, halfCloseAddr(rendrConn.RemoteAddr()))
	}
	currentEgressHandle, err := halfCloseSocketHandle(egressApp)
	if err != nil || currentEgressHandle != egressHandle || egressApp.LocalAddr().String() != egressLocal || egressApp.RemoteAddr().String() != egressRemote {
		t.Fatalf("egress application fd/address changed: handle=%x/%x err=%v local=%q/%q remote=%q/%q",
			egressHandle, currentEgressHandle, err, egressLocal, egressApp.LocalAddr(), egressRemote, egressApp.RemoteAddr())
	}
	assertNoHalfCloseFlowError(t, flowErrors)

	release()
	waitHalfCloseResult(t, "complete reverse response and terminal EOF", responseDone, 5*time.Second)
	waitHalfCloseResult(t, "egress response CloseWrite", egressDone, 2*time.Second)
	survivorAfter, ok := carriers.snapshot(survivorPath.Spec.Transport)
	if !ok {
		t.Fatalf("survivor %q no longer names its pre-existing carrier", survivorPath.Spec.Transport)
	}
	if survivorAfter.readBytes < survivorBefore.readBytes {
		t.Fatalf("survivor %q read counter decreased from %d to %d", survivorPath.Spec.Transport, survivorBefore.readBytes, survivorAfter.readBytes)
	}
	if survivorAfter.readBytes-survivorBefore.readBytes < uint64(len(response)-responsePrefix) {
		t.Fatalf("survivor %q carried %d new wire bytes, want at least %d response bytes",
			survivorPath.Spec.Transport, survivorAfter.readBytes-survivorBefore.readBytes, len(response)-responsePrefix)
	}
	select {
	case got := <-egress.identities:
		if got != id {
			t.Fatalf("peer identity=%s want=%s", got, id)
		}
	case <-time.After(time.Second):
		t.Fatal("peer egress did not receive L3 identity")
	}
	assertNoHalfCloseFlowError(t, flowErrors)
	peerErr := waitHalfCloseError(t, "peer relay shutdown", peerDone, 2*time.Second)
	if peerErr != nil {
		t.Fatalf("peer relay shutdown: %v", peerErr)
	}
	waitHalfCloseSessionGone(t, gateway, id, 2*time.Second)

	teardownStarted := time.Now()
	teardownDone := make(chan error, 1)
	go func() {
		stopBridge()
		stopGateway()
		stopPeer()
		clientLink.Close()
		clientStack.Close()
		closeErr := errors.Join(app.Close(), egressApp.Close(), device.Close(), listener.Close(), carriers.closeAll(), gateway.Close())
		gatewayErr := <-gatewayDone
		teardownDone <- errors.Join(closeErr, halfCloseShutdownError(gatewayErr), halfCloseShutdownError(peerErr))
	}()
	select {
	case err := <-teardownDone:
		if err != nil {
			t.Fatalf("joined teardown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("joined teardown exceeded 3 seconds")
	}
	if elapsed := time.Since(teardownStarted); elapsed > 3*time.Second {
		t.Fatalf("joined teardown took %v", elapsed)
	}
	assertNoHalfCloseFlowError(t, flowErrors)
}

type halfCloseStreamControl interface {
	rendr.Conn
	rendr.ConnectionObserver
}

type halfCloseMigration struct {
	oldID uint32
	newID uint32
	cause string
}

func waitHalfCloseGatewaySession(
	t *testing.T,
	gateway *Gateway,
	id l3ingress.L3Identity,
	wantPaths int,
) (*l3session.Session, halfCloseStreamControl) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if session, ok := gateway.manager.Session(id); ok && session.Conn != nil {
			if control, ok := session.Conn.(halfCloseStreamControl); ok && len(control.Paths()) >= wantPaths {
				return session, control
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("TCP flow %s did not expose %d paths", id, wantPaths)
	return nil, nil
}

func waitHalfCloseAccepted(t *testing.T, accepted <-chan rendr.Conn) rendr.Conn {
	t.Helper()
	select {
	case conn := <-accepted:
		return conn
	case <-time.After(3 * time.Second):
		t.Fatal("peer did not accept rendr stream")
		return nil
	}
}

func waitHalfClosePaths(t *testing.T, control halfCloseStreamControl, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(control.Paths()) >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("rendr stream has %d paths, want %d", len(control.Paths()), want)
}

func waitHalfCloseActiveTransport(
	t *testing.T,
	control halfCloseStreamControl,
	want string,
	timeout time.Duration,
) rendr.ConnStats {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		stats := control.Stats()
		if active, ok := halfClosePathByID(stats.Paths, stats.ActivePath); ok && active.Spec.Transport == want {
			return stats
		}
		time.Sleep(time.Millisecond)
	}
	stats := control.Stats()
	t.Fatalf("active transport did not converge to %q: active=%d paths=%+v", want, stats.ActivePath, stats.Paths)
	return rendr.ConnStats{}
}

func waitHalfCloseSignal(t *testing.T, label string, signal <-chan struct{}, timeout time.Duration) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for %s", label)
	}
}

func waitHalfCloseResult(t *testing.T, label string, result <-chan error, timeout time.Duration) {
	t.Helper()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for %s", label)
	}
}

func waitHalfCloseError(t *testing.T, label string, result <-chan error, timeout time.Duration) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for %s", label)
		return nil
	}
}

func waitHalfCloseSessionGone(
	t *testing.T,
	gateway *Gateway,
	id l3ingress.L3Identity,
	timeout time.Duration,
) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, ok := gateway.manager.Session(id); !ok {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("TCP flow %s remained registered after both half-closes completed", id)
}

func waitHalfCloseMigration(
	t *testing.T,
	migrations <-chan halfCloseMigration,
	oldID uint32,
	timeout time.Duration,
) halfCloseMigration {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case migration := <-migrations:
			if migration.oldID == oldID {
				return migration
			}
		case <-timer.C:
			t.Fatalf("timed out waiting for death migration from path %d", oldID)
			return halfCloseMigration{}
		}
	}
}

func assertNoHalfCloseFlowError(t *testing.T, flowErrors <-chan error) {
	t.Helper()
	select {
	case err := <-flowErrors:
		t.Fatalf("flow-local error: %v", err)
	default:
	}
}

func halfClosePathByID(paths []rendr.PathInfo, id uint32) (rendr.PathInfo, bool) {
	for _, path := range paths {
		if path.ID == id {
			return path, true
		}
	}
	return rendr.PathInfo{}, false
}

func halfCloseOtherPath(paths []rendr.PathInfo, id uint32) (rendr.PathInfo, bool) {
	for _, path := range paths {
		if path.ID != id {
			return path, true
		}
	}
	return rendr.PathInfo{}, false
}

func halfCloseWriteAll(conn net.Conn, payload []byte) error {
	for len(payload) != 0 {
		n, err := conn.Write(payload)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(payload) {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}

func halfClosePayload(size int, seed byte) []byte {
	payload := make([]byte, size)
	state := uint32(seed) + 1
	for i := range payload {
		state = state*1664525 + 1013904223
		payload[i] = byte(state >> 24)
	}
	return payload
}

func halfCloseAddr(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.Network() + ":" + addr.String()
}

func halfCloseSocketHandle(conn net.Conn) (uintptr, error) {
	syscallConn, ok := conn.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		return 0, fmt.Errorf("%T does not expose SyscallConn", conn)
	}
	raw, err := syscallConn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var handle uintptr
	if err := raw.Control(func(fd uintptr) { handle = fd }); err != nil {
		return 0, err
	}
	if handle == 0 {
		return 0, errors.New("zero socket handle")
	}
	return handle, nil
}

func halfCloseShutdownError(err error) error {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

type halfCloseTestDevice struct {
	mtu       int
	inbound   chan []byte
	outbound  chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

func newHalfCloseTestDevice(mtu int) *halfCloseTestDevice {
	return &halfCloseTestDevice{
		mtu: mtu, inbound: make(chan []byte, 256), outbound: make(chan []byte, 256),
		closed: make(chan struct{}),
	}
}

func (d *halfCloseTestDevice) Read(buf []byte) (int, error) {
	return d.ReadContext(context.Background(), buf)
}

func (d *halfCloseTestDevice) ReadContext(ctx context.Context, buf []byte) (int, error) {
	select {
	case packet := <-d.inbound:
		if len(packet) > len(buf) {
			return 0, io.ErrShortBuffer
		}
		return copy(buf, packet), nil
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-d.closed:
		return 0, net.ErrClosed
	}
}

func (d *halfCloseTestDevice) Write(packet []byte) (int, error) {
	return d.WriteContext(context.Background(), packet)
}

func (d *halfCloseTestDevice) WriteContext(ctx context.Context, packet []byte) (int, error) {
	wire := append([]byte(nil), packet...)
	select {
	case d.outbound <- wire:
		return len(packet), nil
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-d.closed:
		return 0, net.ErrClosed
	}
}

func (d *halfCloseTestDevice) Close() error {
	d.closeOnce.Do(func() { close(d.closed) })
	return nil
}

func (*halfCloseTestDevice) Name() string { return "half-close-tun" }
func (d *halfCloseTestDevice) MTU() int   { return d.mtu }

func newHalfCloseClientStack(
	t *testing.T,
	network tcpip.NetworkProtocolNumber,
	clientIP netip.Addr,
	prefix int,
) (*stack.Stack, *channel.Endpoint) {
	t.Helper()
	link := channel.New(256, 1500, "")
	clientStack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{gtcp.NewProtocol},
	})
	if err := clientStack.CreateNIC(stackNICID, link); err != nil {
		clientStack.Close()
		link.Close()
		t.Fatalf("create half-close client NIC: %s", err)
	}
	if err := clientStack.AddProtocolAddress(stackNICID, tcpip.ProtocolAddress{
		Protocol:          network,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: halfCloseTCPIPAddress(clientIP), PrefixLen: prefix},
	}, stack.AddressProperties{}); err != nil {
		clientStack.Close()
		link.Close()
		t.Fatalf("add half-close client address: %s", err)
	}
	destination := header.IPv4EmptySubnet
	if network == header.IPv6ProtocolNumber {
		destination = header.IPv6EmptySubnet
	}
	clientStack.SetRouteTable([]tcpip.Route{{Destination: destination, NIC: stackNICID}})
	return clientStack, link
}

func bridgeHalfClosePackets(
	ctx context.Context,
	client *channel.Endpoint,
	device *halfCloseTestDevice,
	network tcpip.NetworkProtocolNumber,
) {
	go func() {
		for {
			packet := client.ReadContext(ctx)
			if packet == nil {
				return
			}
			view := packet.ToView()
			wire := append([]byte(nil), view.AsSlice()...)
			view.Release()
			packet.DecRef()
			select {
			case device.inbound <- wire:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		for {
			select {
			case wire := <-device.outbound:
				packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(wire)})
				client.InjectInbound(network, packet)
				packet.DecRef()
			case <-ctx.Done():
				return
			}
		}
	}()
}

func halfCloseTCPIPAddress(address netip.Addr) tcpip.Address {
	if address.Is4() {
		return tcpip.AddrFrom4(address.As4())
	}
	return tcpip.AddrFrom16(address.As16())
}

func newHalfCloseTCPConnPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan *net.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	var server *net.TCPConn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		_ = client.Close()
		_ = listener.Close()
		t.Fatal(err)
	case <-time.After(time.Second):
		_ = client.Close()
		_ = listener.Close()
		t.Fatal("timed out accepting half-close TCP pair")
	}
	_ = listener.Close()
	return client, server
}

type halfCloseTCPEgress struct {
	mu         sync.Mutex
	conn       l3ingress.TCPConn
	identities chan l3ingress.L3Identity
}

func (e *halfCloseTCPEgress) DialTCP(_ context.Context, id l3ingress.L3Identity) (l3ingress.TCPConn, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.conn == nil {
		return nil, errors.New("half-close egress already consumed")
	}
	conn := e.conn
	e.conn = nil
	e.identities <- id
	return conn, nil
}

func (*halfCloseTCPEgress) DialUDP(context.Context, l3ingress.L3Identity) (net.PacketConn, netip.AddrPort, error) {
	return nil, netip.AddrPort{}, errors.New("unexpected UDP egress")
}

type halfCloseCarrierSet struct {
	mu      sync.Mutex
	blocked map[string]bool
	conns   map[string][]*halfCloseCarrierConn
}

type halfCloseCarrierConn struct {
	net.Conn
	readBytes  atomic.Uint64
	writeBytes atomic.Uint64
	closed     atomic.Bool
	closeOnce  sync.Once
	closeErr   error
}

type halfCloseCarrierSnapshot struct {
	readBytes  uint64
	writeBytes uint64
	closed     bool
}

func newHalfCloseCarrierSet() *halfCloseCarrierSet {
	return &halfCloseCarrierSet{
		blocked: make(map[string]bool), conns: make(map[string][]*halfCloseCarrierConn),
	}
}

func (s *halfCloseCarrierSet) factory(name string) rendr.StreamFactory {
	return rendr.StreamFactory{
		Carrier: rendr.CarrierTCP,
		Dial: func(ctx context.Context, address string) (net.Conn, error) {
			s.mu.Lock()
			blocked := s.blocked[name]
			s.mu.Unlock()
			if blocked {
				return nil, errors.New("injected carrier death remains unavailable")
			}
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
			if err != nil {
				return nil, err
			}
			tracked := &halfCloseCarrierConn{Conn: conn}
			s.mu.Lock()
			if s.blocked[name] {
				s.mu.Unlock()
				_ = tracked.Close()
				return nil, errors.New("injected carrier died during dial")
			}
			s.conns[name] = append(s.conns[name], tracked)
			s.mu.Unlock()
			return tracked, nil
		},
	}
}

func (s *halfCloseCarrierSet) kill(name string) error {
	s.mu.Lock()
	s.blocked[name] = true
	conns := append([]*halfCloseCarrierConn(nil), s.conns[name]...)
	s.mu.Unlock()
	if len(conns) != 1 {
		return fmt.Errorf("carrier %q has %d live generations, want exactly one", name, len(conns))
	}
	return conns[0].Close()
}

func (s *halfCloseCarrierSet) successfulDials(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns[name])
}

func (s *halfCloseCarrierSet) snapshot(name string) (halfCloseCarrierSnapshot, bool) {
	s.mu.Lock()
	conns := append([]*halfCloseCarrierConn(nil), s.conns[name]...)
	s.mu.Unlock()
	if len(conns) != 1 {
		return halfCloseCarrierSnapshot{}, false
	}
	return halfCloseCarrierSnapshot{
		readBytes: conns[0].readBytes.Load(), writeBytes: conns[0].writeBytes.Load(), closed: conns[0].closed.Load(),
	}, true
}

func (s *halfCloseCarrierSet) closeAll() error {
	s.mu.Lock()
	var conns []*halfCloseCarrierConn
	for _, named := range s.conns {
		conns = append(conns, named...)
	}
	s.mu.Unlock()
	var err error
	for _, conn := range conns {
		err = errors.Join(err, conn.Close())
	}
	return err
}

func (c *halfCloseCarrierConn) Read(buf []byte) (int, error) {
	n, err := c.Conn.Read(buf)
	if n > 0 {
		c.readBytes.Add(uint64(n))
	}
	return n, err
}

func (c *halfCloseCarrierConn) Write(buf []byte) (int, error) {
	n, err := c.Conn.Write(buf)
	if n > 0 {
		c.writeBytes.Add(uint64(n))
	}
	return n, err
}

func (c *halfCloseCarrierConn) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.closeErr = c.Conn.Close()
	})
	return c.closeErr
}
