//go:build linux && amd64 && rendr_experimental_tcprepair

package tcp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FrankoonG/rendr/internal/engine"
	"github.com/FrankoonG/rendr/internal/leafmobility"
	"github.com/FrankoonG/rendr/transport"
	"golang.org/x/sys/unix"
)

func TestPrivilegedTCPRouteSourceMonitorIgnoresUnrelatedChangesAndDetectsSourceLoss(t *testing.T) {
	if os.Getenv("RENDR_TCP_REFRESH_TEST") != "1" {
		t.Skip("set RENDR_TCP_REFRESH_TEST=1 to exercise the real route/source monitor")
	}
	if os.Getenv("RENDR_TCP_REFRESH_NETNS") != "1" {
		t.Fatal("route/source monitor test must run in a dedicated network namespace")
	}
	const (
		clientIP    = "198.18.20.1"
		serverIP    = "198.18.20.2"
		unrelatedIP = "198.18.20.99"
	)
	runRefreshIP(t, "addr", "add", clientIP+"/32", "dev", "lo")
	runRefreshIP(t, "addr", "add", serverIP+"/32", "dev", "lo")
	t.Cleanup(func() {
		_ = exec.Command("/usr/sbin/ip", "route", "del", "local", clientIP+"/32", "dev", "lo").Run()
		_ = exec.Command("/usr/sbin/ip", "addr", "del", unrelatedIP+"/32", "dev", "lo").Run()
		_ = exec.Command("/usr/sbin/ip", "addr", "del", clientIP+"/32", "dev", "lo").Run()
		_ = exec.Command("/usr/sbin/ip", "addr", "del", serverIP+"/32", "dev", "lo").Run()
	})

	client, server := refreshMonitorTCPPair(t, clientIP, serverIP)
	path := wrapOwned(client, leafmobility.RoleDialer)
	issuer := leafmobility.NewAuthorityIssuer()
	binding := leafmobility.Binding{
		FlowID: [16]byte{1}, LocalTargetID: [16]byte{2}, PeerTargetID: [16]byte{3},
		PathID: 1, Owner: 1,
	}
	if err := issuer.BindClaim(path.claim, binding); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = path.claim.Retire(binding)
		_ = path.Close()
		_ = server.Close()
	})

	events := make(chan leafmobility.RefreshEvidence, 4)
	cancel, err := path.SubscribeLeafMobilityRefresh(context.Background(), func(evidence leafmobility.RefreshEvidence) {
		select {
		case events <- evidence:
		default:
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cancel)

	runRefreshIP(t, "addr", "add", unrelatedIP+"/32", "dev", "lo")
	runRefreshIP(t, "addr", "del", unrelatedIP+"/32", "dev", "lo")
	select {
	case <-events:
		t.Fatal("unrelated address changes altered the exact route/source fingerprint")
	case <-time.After(4 * pathRefreshPollInterval):
	}

	churnCtx, stopChurn := context.WithCancel(context.Background())
	churnStarted := make(chan struct{})
	churnDone := make(chan error, 1)
	go func() {
		started := false
		for {
			select {
			case <-churnCtx.Done():
				churnDone <- nil
				return
			default:
			}
			for _, arguments := range [][]string{
				{"addr", "add", unrelatedIP + "/32", "dev", "lo"},
				{"addr", "del", unrelatedIP + "/32", "dev", "lo"},
			} {
				if output, commandErr := exec.Command("/usr/sbin/ip", arguments...).CombinedOutput(); commandErr != nil {
					churnDone <- fmt.Errorf("ip %v: %w: %s", arguments, commandErr, bytes.TrimSpace(output))
					return
				}
			}
			if !started {
				started = true
				close(churnStarted)
			}
		}
	}()
	select {
	case <-churnStarted:
	case err := <-churnDone:
		t.Fatalf("unrelated route churn did not start: %v", err)
	case <-time.After(time.Second):
		t.Fatal("unrelated route churn did not start")
	}
	runRefreshIP(t, "addr", "del", clientIP+"/32", "dev", "lo")
	runRefreshIP(t, "route", "add", "local", clientIP+"/32", "dev", "lo")
	var evidence leafmobility.RefreshEvidence
	select {
	case evidence = <-events:
		stopChurn()
	case err := <-churnDone:
		stopChurn()
		t.Fatalf("unrelated route churn failed before source evidence: %v", err)
	case <-time.After(3 * time.Second):
		stopChurn()
		<-churnDone
		t.Fatal("source-address loss did not publish route/source evidence")
	}
	if err := <-churnDone; err != nil {
		t.Fatal(err)
	}
	snapshot, err := evidence.ValidateFor(path.claim, 0)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Reason != leafmobility.RefreshReasonRouteSourceChanged || snapshot.Generation == 0 ||
		snapshot.EndpointGeneration != path.claim.Snapshot().Generation || snapshot.Incarnation == 0 {
		t.Fatalf("refresh snapshot=%+v", snapshot)
	}

	// Reverting to the route/source facts of the still-current physical socket
	// must revoke the pending evidence and explicitly resolve its budget without
	// requesting another migration.
	runRefreshIP(t, "route", "del", "local", clientIP+"/32", "dev", "lo")
	runRefreshIP(t, "addr", "add", clientIP+"/32", "dev", "lo")
	select {
	case restored := <-events:
		restoredSnapshot, validateErr := restored.ValidateFor(path.claim, 0)
		if validateErr != nil {
			t.Fatal(validateErr)
		}
		if !restoredSnapshot.SourceUsable || restoredSnapshot.Reason != leafmobility.RefreshReasonRouteSourceRestored {
			t.Fatalf("route/source reversion snapshot=%+v", restoredSnapshot)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("route/source reversion did not resolve the pending change")
	}
	if _, err := evidence.ValidateFor(path.claim, 0); !errors.Is(err, leafmobility.ErrRefreshEvidenceStale) {
		t.Fatalf("reverted source did not revoke old evidence: %v", err)
	}

	assertRepairPathRoundTrip(t, path, server)
}

func TestRouteRefreshNetlinkRequestEncoding(t *testing.T) {
	body := make([]byte, unix.SizeofRtMsg)
	body[0], body[1] = unix.AF_INET, 32
	attribute := netlinkAttribute(unix.RTA_DST, net.IPv4(192, 0, 2, 1).To4())
	request := encodeNetlinkRequest(unix.RTM_GETROUTE, unix.NLM_F_REQUEST, 17, body, attribute)
	if got := int(binaryNativeUint32(request[0:4])); got != len(request) {
		t.Fatalf("netlink length=%d want=%d", got, len(request))
	}
	if got := binaryNativeUint16(request[4:6]); got != unix.RTM_GETROUTE {
		t.Fatalf("netlink type=%d", got)
	}
	if got := binaryNativeUint32(request[8:12]); got != 17 {
		t.Fatalf("netlink sequence=%d", got)
	}
	if !bytes.Equal(request[unix.SizeofNlMsghdr:unix.SizeofNlMsghdr+len(body)], body) {
		t.Fatal("netlink route body changed")
	}
}

func TestPrivilegedTCPRouteSourceMonitorInvalidatesWithoutReplacementRoute(t *testing.T) {
	if os.Getenv("RENDR_TCP_REFRESH_TEST") != "1" {
		t.Skip("set RENDR_TCP_REFRESH_TEST=1 to exercise the real route/source monitor")
	}
	if os.Getenv("RENDR_TCP_REFRESH_NETNS") != "1" {
		t.Fatal("route/source monitor negative control must run in a dedicated network namespace")
	}
	const (
		clientIP = "198.18.23.1"
		serverIP = "198.18.23.2"
	)
	runRefreshIP(t, "addr", "add", clientIP+"/32", "dev", "lo")
	runRefreshIP(t, "addr", "add", serverIP+"/32", "dev", "lo")
	t.Cleanup(func() {
		_ = exec.Command("/usr/sbin/ip", "addr", "del", clientIP+"/32", "dev", "lo").Run()
		_ = exec.Command("/usr/sbin/ip", "addr", "del", serverIP+"/32", "dev", "lo").Run()
	})

	client, server := refreshMonitorTCPPair(t, clientIP, serverIP)
	path := wrapOwned(client, leafmobility.RoleDialer)
	issuer := leafmobility.NewAuthorityIssuer()
	binding := leafmobility.Binding{
		FlowID: [16]byte{4}, LocalTargetID: [16]byte{5}, PeerTargetID: [16]byte{6},
		PathID: 1, Owner: 1,
	}
	if err := issuer.BindClaim(path.claim, binding); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = path.claim.Retire(binding)
		_ = path.Close()
		_ = server.Close()
	})
	events := make(chan leafmobility.RefreshEvidence, 2)
	cancel, err := path.SubscribeLeafMobilityRefresh(context.Background(), func(evidence leafmobility.RefreshEvidence) {
		select {
		case events <- evidence:
		default:
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cancel)
	baselineEvidence, err := path.refreshEmitter.Observe(leafmobility.RefreshReasonRouteSourceChanged)
	if err != nil {
		t.Fatal(err)
	}

	runRefreshIP(t, "addr", "del", clientIP+"/32", "dev", "lo")
	deadline := time.Now().Add(3 * time.Second)
	for {
		conn, _, ok := path.endpoint.current()
		if !ok {
			t.Fatal("source-loss negative control lost the live endpoint")
		}
		tcpConn, ok := conn.(*net.TCPConn)
		if !ok {
			t.Fatalf("source-loss endpoint type=%T want *net.TCPConn", conn)
		}
		ctx, stop := context.WithTimeout(context.Background(), pathRefreshQueryTimeout)
		_, observation, observeErr := captureTCPRouteObservation(ctx, tcpConn)
		stop()
		if errors.Is(observeErr, errReplacementRouteUnavailable) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("source loss retained a usable replacement route: observation=%+v err=%v", observation, observeErr)
		}
		time.Sleep(pathRefreshDebounce)
	}
	for {
		if _, validateErr := baselineEvidence.ValidateFor(path.claim, 0); errors.Is(validateErr, leafmobility.ErrRefreshEvidenceStale) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("unusable route did not revoke previously minted evidence")
		}
		time.Sleep(pathRefreshDebounce)
	}
	var unavailable leafmobility.RefreshEvidence
	select {
	case unavailable = <-events:
	case <-time.After(3 * time.Second):
		t.Fatal("unusable route did not publish a budget-starting factual event")
	}
	unavailableSnapshot, err := unavailable.ValidateFor(path.claim, 0)
	if err != nil {
		t.Fatal(err)
	}
	if unavailableSnapshot.SourceUsable || unavailableSnapshot.Reason != leafmobility.RefreshReasonRouteSourceUnavailable {
		t.Fatalf("unavailable route snapshot=%+v", unavailableSnapshot)
	}
	if _, err := path.refreshState.DigestForCommit(unavailable); !errors.Is(err, leafmobility.ErrRefreshSourceUnavailable) {
		t.Fatalf("unavailable route commit digest error=%v", err)
	}

	runRefreshIP(t, "addr", "add", clientIP+"/32", "dev", "lo")
	select {
	case restored := <-events:
		restoredSnapshot, validateErr := restored.ValidateFor(path.claim, 0)
		if validateErr != nil {
			t.Fatal(validateErr)
		}
		if !restoredSnapshot.SourceUsable || restoredSnapshot.Reason != leafmobility.RefreshReasonRouteSourceRestored {
			t.Fatalf("restored route snapshot=%+v", restoredSnapshot)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("restored baseline did not resolve the unavailable episode")
	}
	assertRepairPathRoundTrip(t, path, server)
}

func TestPrivilegedTCPRouteSourceMonitorDetectsRealOutputPathChange(t *testing.T) {
	if os.Getenv("RENDR_TCP_REFRESH_TEST") != "1" {
		t.Skip("set RENDR_TCP_REFRESH_TEST=1 to exercise the real route/source monitor")
	}
	if os.Getenv("RENDR_TCP_REFRESH_NETNS") != "1" {
		t.Fatal("route path-change test must run in a dedicated network namespace")
	}
	topology := newRefreshRouteTopology(t)
	client, server := refreshRouteTCPPair(t, topology.namespace, topology.clientIP, topology.serverIP)
	path := wrapOwned(client, leafmobility.RoleDialer)
	issuer := leafmobility.NewAuthorityIssuer()
	binding := leafmobility.Binding{
		FlowID: [16]byte{10}, LocalTargetID: [16]byte{11}, PeerTargetID: [16]byte{12},
		PathID: 1, Owner: 1,
	}
	if err := issuer.BindClaim(path.claim, binding); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = path.claim.Retire(binding)
		_ = path.Close()
		_ = server.Close()
	})
	events := make(chan leafmobility.RefreshEvidence, 2)
	cancel, err := path.SubscribeLeafMobilityRefresh(context.Background(), func(evidence leafmobility.RefreshEvidence) {
		select {
		case events <- evidence:
		default:
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cancel)
	pathA, err := net.InterfaceByName(topology.clientA)
	if err != nil {
		t.Fatal(err)
	}
	pathB, err := net.InterfaceByName(topology.clientB)
	if err != nil {
		t.Fatal(err)
	}
	if outputIf := refreshRouteOutputInterface(t, client); outputIf != pathA.Index {
		t.Fatalf("initial route OIF=%d want=%d", outputIf, pathA.Index)
	}
	pathBTX := refreshInterfaceCounter(t, topology.clientB, "tx_packets")

	runRefreshIP(t, "route", "replace", topology.serverIP+"/32", "via", topology.gatewayB, "dev", topology.clientB, "src", topology.clientIP)
	deadline := time.Now().Add(3 * time.Second)
	for refreshRouteOutputInterface(t, client) != pathB.Index {
		if time.Now().After(deadline) {
			t.Fatalf("replacement route did not select OIF %d", pathB.Index)
		}
		time.Sleep(pathRefreshDebounce)
	}
	var evidence leafmobility.RefreshEvidence
	select {
	case evidence = <-events:
	case <-time.After(3 * time.Second):
		t.Fatal("real OIF change did not publish route/source evidence")
	}
	if snapshot, validateErr := evidence.ValidateFor(path.claim, 0); validateErr != nil ||
		snapshot.EndpointGeneration != path.claim.Snapshot().Generation || snapshot.Incarnation == 0 {
		t.Fatalf("OIF-change evidence=%+v err=%v", snapshot, validateErr)
	}
	assertRepairPathRoundTrip(t, path, server)
	if after := refreshInterfaceCounter(t, topology.clientB, "tx_packets"); after <= pathBTX {
		t.Fatalf("path B data-plane counter=%d baseline=%d", after, pathBTX)
	}

	runRefreshIP(t, "route", "replace", topology.serverIP+"/32", "via", topology.gatewayA, "dev", topology.clientA, "src", topology.clientIP)
	deadline = time.Now().Add(3 * time.Second)
	for {
		if _, validateErr := evidence.ValidateFor(path.claim, 0); errors.Is(validateErr, leafmobility.ErrRefreshEvidenceStale) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("physical-route reversion did not revoke OIF-change evidence")
		}
		time.Sleep(pathRefreshDebounce)
	}
	select {
	case restored := <-events:
		snapshot, validateErr := restored.ValidateFor(path.claim, 0)
		if validateErr != nil {
			t.Fatal(validateErr)
		}
		if !snapshot.SourceUsable || snapshot.Reason != leafmobility.RefreshReasonRouteSourceRestored {
			t.Fatalf("physical-route reversion snapshot=%+v", snapshot)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("physical-route reversion did not resolve the published change episode")
	}
	pathATX := refreshInterfaceCounter(t, topology.clientA, "tx_packets")
	assertRepairPathRoundTrip(t, path, server)
	if after := refreshInterfaceCounter(t, topology.clientA, "tx_packets"); after <= pathATX {
		t.Fatalf("path A data-plane counter=%d baseline=%d", after, pathATX)
	}
}

func TestPrivilegedAutomaticTCPRepairOnSourceLoss(t *testing.T) {
	runPrivilegedAutomaticTCPRepairOnSourceLoss(t, true, true)
}

func runPrivilegedAutomaticTCPRepairOnSourceLoss(t *testing.T, capturePackets, verifySettled bool) {
	t.Helper()
	if os.Getenv("RENDR_TCP_REFRESH_TEST") != "1" || os.Getenv("RENDR_TCP_REPAIR_DRIVER_TEST") != "1" {
		t.Skip("set refresh and TCP_REPAIR driver test flags to exercise automatic migration")
	}
	if os.Getenv("RENDR_TCP_REFRESH_NETNS") != "1" || os.Getenv("RENDR_TCP_REPAIR_DRIVER_NETNS") != "1" {
		t.Fatal("automatic source-loss migration must run in a dedicated network namespace")
	}
	const (
		clientIP = "198.18.21.1"
		serverIP = "198.18.21.2"
	)
	runRefreshIP(t, "addr", "add", clientIP+"/32", "dev", "lo")
	runRefreshIP(t, "addr", "add", serverIP+"/32", "dev", "lo")
	t.Cleanup(func() {
		_ = exec.Command("/usr/sbin/ip", "route", "del", "local", clientIP+"/32", "dev", "lo").Run()
		_ = exec.Command("/usr/sbin/ip", "addr", "del", clientIP+"/32", "dev", "lo").Run()
		_ = exec.Command("/usr/sbin/ip", "addr", "del", serverIP+"/32", "dev", "lo").Run()
	})
	if capturePackets {
		installRefreshLoopbackRateLimit(t)
	}
	var capture *refreshTCPCapture
	if capturePackets {
		capture = startRefreshTCPCapture(t, clientIP, serverIP)
	}

	clientSocket, serverSocket := refreshMonitorTCPPair(t, clientIP, serverIP)
	clientPath, clientDriver := drivenRepairPath(clientSocket, leafmobility.RoleDialer)
	serverPath, serverDriver := drivenRepairPath(serverSocket, leafmobility.RoleAcceptor)
	var inspectionRecorder *kernel5TCPInspectionRecorder
	if capturePackets {
		inspectionRecorder = &kernel5TCPInspectionRecorder{}
		clientDriver.kernel = kernel5TCPRecordingRepairKernel{
			delegate: clientDriver.kernel,
			recorder: inspectionRecorder,
		}
	}
	// The exact stimulus is loss of the client's source address. Keep the peer
	// as a responder so this case proves one factual event maps to one actor.
	serverPath.refreshEmitter = nil
	clientGeneration := clientPath.claim.Snapshot().Generation
	serverGeneration := serverPath.claim.Snapshot().Generation
	preTuple := measureKernel5TCPPairTuple(t, clientPath, serverPath)

	flowID := [16]byte{0x71, 0x72, 0x73, 0x74}
	limits := engine.DefaultLimits()
	limits.MigrationBudget = 15 * time.Second
	limits.ProbeInterval = 30 * time.Second
	clientEngine := engine.New(engine.SideClient, flowID, limits)
	serverEngine := engine.New(engine.SideServer, flowID, limits)
	t.Cleanup(func() { _ = clientEngine.Close(); _ = serverEngine.Close() })
	rawTargetID, controlTargetID := configureRepairEnginePair(t, clientEngine, serverEngine, clientDriver, serverDriver)

	binding := engine.PathBinding{LocalTXTargetID: rawTargetID, PeerTXTargetID: rawTargetID}
	spec := transport.PathSpec{Transport: "tcp", Opts: map[string]string{"name": "raw-auto"}}
	clientPathID, err := clientEngine.AttachPathBound(clientPath, spec, binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := serverEngine.AttachPathBound(serverPath, spec, binding); err != nil {
		t.Fatal(err)
	}
	clientControlConn, serverControlConn := net.Pipe()
	controlBinding := engine.PathBinding{LocalTXTargetID: controlTargetID, PeerTXTargetID: controlTargetID}
	clientControl := Wrap(clientControlConn)
	serverControl := Wrap(serverControlConn)
	if _, err := clientEngine.AttachPathBound(clientControl, transport.PathSpec{Transport: "memory"}, controlBinding); err != nil {
		t.Fatal(err)
	}
	if _, err := serverEngine.AttachPathBound(serverControl, transport.PathSpec{Transport: "memory"}, controlBinding); err != nil {
		t.Fatal(err)
	}
	clientRef, ok := clientEngine.PathRef(clientPathID)
	if !ok {
		t.Fatal("automatic source path has no exact PathRef")
	}
	type migrateEvent struct {
		oldID uint32
		newID uint32
		cause string
	}
	migrations := make(chan migrateEvent, 4)
	cancelMigrateHook := clientEngine.OnMigrate(func(oldID, newID uint32, cause string) {
		migrations <- migrateEvent{oldID: oldID, newID: newID, cause: cause}
	})
	t.Cleanup(cancelMigrateHook)
	baselineMigrations := clientEngine.MigrationCount()
	clientPath.refreshMu.Lock()
	monitorInstalled := clientPath.refreshMonitor != nil && clientPath.refreshCallback != nil
	clientPath.refreshMu.Unlock()
	if !monitorInstalled {
		t.Fatal("negotiated owned TCP path did not install its route/source monitor")
	}

	migrationPayload := bytes.Repeat([]byte("automatic-source-loss-payload-"), 1<<18)
	postCommitPayload := []byte("client-to-committed-replacement")
	forwardPayload := make([]byte, 0, len(migrationPayload)+len(postCommitPayload))
	forwardPayload = append(forwardPayload, migrationPayload...)
	forwardPayload = append(forwardPayload, postCommitPayload...)
	wantDigest := sha256.Sum256(forwardPayload)
	receiveResult := make(chan driverReceiveResult, 1)
	go receiveDriverPayload(serverEngine, len(forwardPayload), receiveResult)
	sendResult := make(chan error, 1)
	baselineWrites := clientPath.Writes()
	go func() {
		n, sendErr := clientEngine.SendData(migrationPayload)
		if sendErr == nil && n != len(migrationPayload) {
			sendErr = io.ErrShortWrite
		}
		sendResult <- sendErr
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	waitForDriverWrites(t, ctx, clientPath, baselineWrites+8)
	if capturePackets {
		assertRefreshLoopbackRateLimit(t)
		select {
		case sendErr := <-sendResult:
			t.Fatalf("source-loss stimulus did not overlap an active forward send: %v", sendErr)
		default:
		}
	}

	runRefreshIP(t, "addr", "del", clientIP+"/32", "dev", "lo")
	runRefreshIP(t, "route", "add", "local", clientIP+"/32", "dev", "lo")
	var committedStatus engine.LeafMobilityInitiatorSnapshot
	for {
		status, exists := clientEngine.LeafMobilityInitiatorStatus(clientRef)
		if exists && status.Phase == engine.LeafMobilityInitiatorCommitted {
			if status.EvidenceReason != leafmobility.RefreshReasonRouteSourceChanged ||
				status.Operation != leafmobility.OperationTCPRepair || status.Error != "" {
				t.Fatalf("automatic initiator status=%+v", status)
			}
			committedStatus = status
			break
		}
		if exists && automaticInitiatorFailed(status.Phase) {
			t.Fatalf("automatic initiator terminated without commit: %+v", status)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("automatic source-loss migration timed out: %v", ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
	replacementCookie, err := measureKernel5TCPPathSocketCookie(clientPath)
	if err != nil {
		t.Fatalf("measure committed replacement SO_COOKIE: %v", err)
	}
	if err := <-sendResult; err != nil {
		t.Fatalf("SendData across automatic migration: %v", err)
	}
	if n, err := clientEngine.SendData(postCommitPayload); err != nil || n != len(postCommitPayload) {
		t.Fatalf("SendData on committed replacement=(%d,%v)", n, err)
	}
	received := <-receiveResult
	if received.err != nil || received.bytes != len(forwardPayload) || received.digest != wantDigest {
		t.Fatalf("automatic receive bytes=%d digest=%x err=%v", received.bytes, received.digest, received.err)
	}
	clientGenerationAfter := clientPath.claim.Snapshot().Generation
	serverGenerationAfter := serverPath.claim.Snapshot().Generation
	if clientGenerationAfter == clientGeneration {
		t.Fatalf("automatic migration retained client generation %d", clientGeneration)
	}
	if serverGenerationAfter != serverGeneration {
		t.Fatalf("responder generation changed from %d to %d", serverGeneration, serverGenerationAfter)
	}
	migrationsAfter := clientEngine.MigrationCount()
	if migrationsAfter != baselineMigrations+1 {
		t.Fatalf("automatic migration count=%d want=%d", migrationsAfter, baselineMigrations+1)
	}
	var committedMigration migrateEvent
	select {
	case event := <-migrations:
		if event.oldID != clientPathID || event.newID != clientPathID || event.cause != "leaf-mobility" {
			t.Fatalf("automatic migration event=%+v", event)
		}
		committedMigration = event
	case <-ctx.Done():
		t.Fatalf("automatic migration hook timed out: %v", ctx.Err())
	}
	if verifySettled {
		select {
		case event := <-migrations:
			t.Fatalf("physical-baseline commit emitted a second migration: %+v", event)
		case <-time.After(250 * time.Millisecond):
		}
		if got := clientEngine.MigrationCount(); got != baselineMigrations+1 {
			t.Fatalf("automatic migration count changed after baseline commit: got=%d want=%d", got, baselineMigrations+1)
		}
	}
	if clientControl.Writes() == 0 || clientControl.Reads() == 0 || serverControl.Writes() == 0 || serverControl.Reads() == 0 {
		t.Fatal("automatic migration did not use the independent control route")
	}
	reverse := []byte("server-to-automatically-restored-client")
	if n, err := serverEngine.SendData(reverse); err != nil || n != len(reverse) {
		t.Fatalf("reverse SendData=(%d,%v)", n, err)
	}
	buffer := make([]byte, len(reverse))
	reverseBytes, reverseErr := clientEngine.Recv(buffer)
	if reverseErr != nil || reverseBytes != len(reverse) || !bytes.Equal(buffer, reverse) {
		t.Fatalf("reverse Recv=(%d,%v,%q)", reverseBytes, reverseErr, buffer[:max(reverseBytes, 0)])
	}
	var preInspection, postInspection kernel5TCPInspectionEvidence
	var sourceCookie uint64
	if inspectionRecorder != nil {
		var err error
		preInspection, sourceCookie, err = inspectionRecorder.singleMeasurement()
		if err != nil {
			t.Fatalf("measure captured source TCP_REPAIR state and SO_COOKIE: %v", err)
		}
		if sourceCookie == replacementCookie {
			t.Fatalf("automatic TCP_REPAIR retained kernel socket SO_COOKIE=%d", sourceCookie)
		}
	}
	if os.Getenv(kernel5TCPRepairEvidenceEnvironment) != "" {
		var err error
		postInspection, err = measureKernel5TCPCurrentInspection(clientPath, clientDriver.quarantine)
		if err != nil {
			t.Fatalf("measure post-migration TCP_REPAIR state: %v", err)
		}
	}
	postTuple := measureKernel5TCPPairTuple(t, clientPath, serverPath)
	var captureEvidence kernel5TCPCaptureEvidence
	if capture != nil {
		var captureErr error
		captureEvidence, captureErr = capture.Stop()
		if captureErr != nil {
			t.Fatal(captureErr)
		}
		if err := validateKernel5TCPCaptureEvidence(captureEvidence); err != nil {
			t.Fatalf("capture oracle evidence is invalid: %v", err)
		}
	}
	reverseDigest := sha256.Sum256(reverse)
	receivedReverseDigest := sha256.Sum256(buffer[:reverseBytes])
	transactionID := fmt.Sprintf("%x", committedStatus.TransactionID)
	emitKernel5TCPRepairEligibleEvidence(t, kernel5TCPRepairEligibleEvidence{
		TestName:       "TestPrivilegedAutomaticTCPRepairOnSourceLoss",
		PreTuple:       preTuple,
		PostTuple:      postTuple,
		PreInspection:  preInspection,
		PostInspection: postInspection,
		SocketIncarnation: kernel5TCPSocketIncarnationEvidence{
			SourceCookie: sourceCookie, ReplacementCookie: replacementCookie,
			SourcePhase: kernel5TCPSourceSocketPhase, ReplacementPhase: kernel5TCPReplacementSocketPhase,
			TransactionID: transactionID, SourceEndpointGeneration: clientGeneration,
			ReplacementEndpointGeneration: clientGenerationAfter, CanonicalTuple: preTuple.Canonical,
		},
		ClaimGenerations: kernel5TCPClaimGenerationEvidence{
			ActorBefore: clientGeneration, ActorAfter: clientGenerationAfter,
			PeerBefore: serverGeneration, PeerAfter: serverGenerationAfter,
			StatusFrom: committedStatus.SourceEndpointGeneration,
			StatusTo:   committedStatus.ResultEndpointGeneration,
		},
		Commit: kernel5TCPCommitEvidence{
			Phase: "committed", Operation: "tcp_repair_same_peer_tuple", OperationCode: uint8(committedStatus.Operation),
			Reason: "route_source_changed", ReasonCode: uint8(committedStatus.EvidenceReason),
			PlanReason: committedStatus.PlanReason.String(), PlanReasonCode: uint16(committedStatus.PlanReason),
			TransactionID:      transactionID,
			EvidenceGeneration: committedStatus.EvidenceGeneration,
		},
		ForwardPayload: kernel5TCPPayloadEvidence{
			OfferedBytes: len(forwardPayload), ReceivedBytes: received.bytes,
			OfferedSHA256: fmt.Sprintf("%x", wantDigest), ReceivedSHA256: fmt.Sprintf("%x", received.digest),
		},
		ReversePayload: kernel5TCPPayloadEvidence{
			OfferedBytes: len(reverse), ReceivedBytes: reverseBytes,
			OfferedSHA256: fmt.Sprintf("%x", reverseDigest), ReceivedSHA256: fmt.Sprintf("%x", receivedReverseDigest),
		},
		BidirectionalReverseSuccess: reverseErr == nil && reverseBytes == len(reverse) && bytes.Equal(buffer[:reverseBytes], reverse),
		Migration: kernel5TCPMigrationEvidence{
			Before: baselineMigrations, After: migrationsAfter, Delta: migrationsAfter - baselineMigrations,
			Events: 1, OldPathID: committedMigration.oldID, NewPathID: committedMigration.newID, Cause: committedMigration.cause,
		},
		ControlRoute: kernel5TCPControlRouteEvidence{
			AttachedPaths: 1,
			ClientWrites:  clientControl.Writes(), ClientReads: clientControl.Reads(),
			ServerWrites: serverControl.Writes(), ServerReads: serverControl.Reads(),
		},
		InternalCapture: captureEvidence,
		SourceLoss: kernel5TCPSourceLossEvidence{
			Observed: true, SourceAddress: clientIP, ReplacementRouteInstalled: true,
			EvidenceGeneration:       committedStatus.EvidenceGeneration,
			SourceEndpointGeneration: committedStatus.SourceEndpointGeneration,
			Reason:                   "route_source_changed",
		},
	})
}

func TestPrivilegedAutomaticTCPRepairResourceSlope(t *testing.T) {
	if os.Getenv("RENDR_TCP_REPAIR_SLOPE_TEST") != "1" {
		t.Skip("set RENDR_TCP_REPAIR_SLOPE_TEST=1 to exercise automatic transaction resources")
	}
	if os.Getenv("RENDR_TCP_REFRESH_NETNS") != "1" || os.Getenv("RENDR_TCP_REPAIR_DRIVER_NETNS") != "1" {
		t.Fatal("automatic transaction resource test must run in a dedicated network namespace")
	}
	const (
		cycles       = 200
		warmupCycles = 20
	)
	baseline := sampleRefreshResources(t)
	var warm refreshResourceSample
	for cycle := 1; cycle <= cycles; cycle++ {
		t.Run(fmt.Sprintf("cycle-%03d", cycle), func(t *testing.T) {
			runPrivilegedAutomaticTCPRepairOnSourceLoss(t, false, false)
		})
		assertNoRefreshQuarantineTables(t)
		if cycle == warmupCycles {
			warm = sampleRefreshResources(t)
		}
	}
	end := sampleRefreshResources(t)
	if end.fds > baseline.fds+4 || end.goroutines > baseline.goroutines+8 {
		t.Fatalf("automatic transaction resource slope: baseline=%+v end=%+v", baseline, end)
	}
	if end.heapInuse > warm.heapInuse+16<<20 {
		t.Fatalf("automatic transaction heap slope: warm=%d end=%d", warm.heapInuse, end.heapInuse)
	}
	if end.rss > warm.rss+32<<20 {
		t.Fatalf("automatic transaction RSS slope: warm=%d end=%d", warm.rss, end.rss)
	}
}

func TestPrivilegedTCPRouteSourceMonitorResourceSlope(t *testing.T) {
	if os.Getenv("RENDR_TCP_REFRESH_TEST") != "1" {
		t.Skip("set RENDR_TCP_REFRESH_TEST=1 to exercise monitor resources")
	}
	if os.Getenv("RENDR_TCP_REFRESH_NETNS") != "1" {
		t.Fatal("route/source monitor resource test must run in a dedicated network namespace")
	}
	const (
		clientIP = "198.18.22.1"
		serverIP = "198.18.22.2"
		cycles   = 100
	)
	runRefreshIP(t, "addr", "add", clientIP+"/32", "dev", "lo")
	runRefreshIP(t, "addr", "add", serverIP+"/32", "dev", "lo")
	t.Cleanup(func() {
		_ = exec.Command("/usr/sbin/ip", "addr", "del", clientIP+"/32", "dev", "lo").Run()
		_ = exec.Command("/usr/sbin/ip", "addr", "del", serverIP+"/32", "dev", "lo").Run()
	})
	baselineFDs := refreshOpenFDs(t)
	baselineGoroutines := runtime.NumGoroutine()
	for cycle := 1; cycle <= cycles; cycle++ {
		client, server := refreshMonitorTCPPair(t, clientIP, serverIP)
		path := wrapOwned(client, leafmobility.RoleDialer)
		issuer := leafmobility.NewAuthorityIssuer()
		binding := leafmobility.Binding{
			FlowID: [16]byte{byte(cycle), 1}, LocalTargetID: [16]byte{2}, PeerTargetID: [16]byte{3},
			PathID: uint32(cycle), Owner: uint64(cycle),
		}
		if err := issuer.BindClaim(path.claim, binding); err != nil {
			t.Fatal(err)
		}
		cancel, err := path.SubscribeLeafMobilityRefresh(context.Background(), func(leafmobility.RefreshEvidence) {})
		if err != nil {
			t.Fatalf("cycle %d subscribe: %v", cycle, err)
		}
		cancel()
		if err := path.claim.Retire(binding); err != nil {
			t.Fatalf("cycle %d retire: %v", cycle, err)
		}
		if err := path.Close(); err != nil {
			t.Fatalf("cycle %d close path: %v", cycle, err)
		}
		if err := server.Close(); err != nil {
			t.Fatalf("cycle %d close peer: %v", cycle, err)
		}
	}
	runtime.GC()
	deadline := time.Now().Add(3 * time.Second)
	for {
		fds := refreshOpenFDs(t)
		goroutines := runtime.NumGoroutine()
		if fds <= baselineFDs+2 && goroutines <= baselineGoroutines+4 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("monitor resource slope after %d cycles: fds=%d baseline=%d goroutines=%d baseline=%d",
				cycles, fds, baselineFDs, goroutines, baselineGoroutines)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestPrivilegedTCPRouteSourceMonitorConcurrentCost(t *testing.T) {
	if os.Getenv("RENDR_TCP_REFRESH_SCALE_TEST") != "1" {
		t.Skip("set RENDR_TCP_REFRESH_SCALE_TEST=1 to exercise concurrent monitor cost")
	}
	if os.Getenv("RENDR_TCP_REFRESH_NETNS") != "1" {
		t.Fatal("concurrent monitor cost test must run in a dedicated network namespace")
	}
	const (
		clientIP = "198.18.24.1"
		serverIP = "198.18.24.2"
		paths    = 64
	)
	runRefreshIP(t, "addr", "add", clientIP+"/32", "dev", "lo")
	runRefreshIP(t, "addr", "add", serverIP+"/32", "dev", "lo")
	t.Cleanup(func() {
		_ = exec.Command("/usr/sbin/ip", "addr", "del", clientIP+"/32", "dev", "lo").Run()
		_ = exec.Command("/usr/sbin/ip", "addr", "del", serverIP+"/32", "dev", "lo").Run()
	})
	type monitoredPath struct {
		path    *PathConn
		peer    *net.TCPConn
		binding leafmobility.Binding
		cancel  func()
	}
	baseline := sampleRefreshResources(t)
	monitors := make([]monitoredPath, 0, paths)
	for index := 1; index <= paths; index++ {
		client, server := refreshMonitorTCPPair(t, clientIP, serverIP)
		path := wrapOwned(client, leafmobility.RoleDialer)
		binding := leafmobility.Binding{
			FlowID: [16]byte{byte(index), 7}, LocalTargetID: [16]byte{8}, PeerTargetID: [16]byte{9},
			PathID: uint32(index), Owner: uint64(index),
		}
		if err := leafmobility.NewAuthorityIssuer().BindClaim(path.claim, binding); err != nil {
			t.Fatal(err)
		}
		cancel, err := path.SubscribeLeafMobilityRefresh(context.Background(), func(leafmobility.RefreshEvidence) {})
		if err != nil {
			t.Fatalf("path %d subscribe: %v", index, err)
		}
		monitors = append(monitors, monitoredPath{path: path, peer: server, binding: binding, cancel: cancel})
	}
	active := sampleRefreshResources(t)
	if active.fds > baseline.fds+paths*3+8 || active.goroutines > baseline.goroutines+paths+8 {
		t.Fatalf("concurrent monitor cardinality: baseline=%+v active=%+v", baseline, active)
	}
	if active.heapInuse > baseline.heapInuse+(16<<20) || active.rss > baseline.rss+(32<<20) {
		t.Fatalf("concurrent monitor memory: baseline=%+v active=%+v", baseline, active)
	}
	startTicks := refreshProcessCPUTicks(t)
	time.Sleep(500 * time.Millisecond)
	usedTicks := refreshProcessCPUTicks(t) - startTicks
	ticksPerSecond := refreshClockTicksPerSecond(t)
	if usedTicks > ticksPerSecond/2 {
		t.Fatalf("%d idle monitors used %d CPU ticks in 500ms; one-core budget=%d", paths, usedTicks, ticksPerSecond/2)
	}
	for index := range monitors {
		monitor := monitors[index]
		monitor.cancel()
		if err := monitor.path.claim.Retire(monitor.binding); err != nil {
			t.Fatalf("path %d retire: %v", index+1, err)
		}
		if err := monitor.path.Close(); err != nil {
			t.Fatalf("path %d close: %v", index+1, err)
		}
		if err := monitor.peer.Close(); err != nil {
			t.Fatalf("path %d peer close: %v", index+1, err)
		}
	}
	end := sampleRefreshResources(t)
	if end.fds > baseline.fds+4 || end.goroutines > baseline.goroutines+8 {
		t.Fatalf("concurrent monitor teardown: baseline=%+v end=%+v", baseline, end)
	}
}

func automaticInitiatorFailed(phase engine.LeafMobilityInitiatorPhase) bool {
	switch phase {
	case engine.LeafMobilityInitiatorBaseline, engine.LeafMobilityInitiatorRolledBack,
		engine.LeafMobilityInitiatorRejected, engine.LeafMobilityInitiatorFailed,
		engine.LeafMobilityInitiatorSuperseded, engine.LeafMobilityInitiatorExpired,
		engine.LeafMobilityInitiatorFailClosed, engine.LeafMobilityInitiatorSubscriptionUnavailable:
		return true
	default:
		return false
	}
}

func binaryNativeUint16(value []byte) uint16 { return binary.NativeEndian.Uint16(value) }
func binaryNativeUint32(value []byte) uint32 { return binary.NativeEndian.Uint32(value) }

type refreshTCPCapture struct {
	command    *exec.Cmd
	path       string
	stderrDone <-chan refreshTCPDumpStderrResult

	stopOnce sync.Once
	evidence kernel5TCPCaptureEvidence
	err      error
}

type refreshTCPDumpStderrResult struct {
	output string
	err    error
}

func startRefreshTCPCapture(t testing.TB, clientIP, serverIP string) *refreshTCPCapture {
	t.Helper()
	if _, err := os.Stat("/usr/bin/tcpdump"); err != nil {
		t.Fatalf("tcp capture oracle unavailable: %v", err)
	}
	path := t.TempDir() + "/automatic-repair.pcap"
	filter := "tcp and ((src host " + clientIP + " and dst host " + serverIP + ") or (src host " + serverIP + " and dst host " + clientIP + "))"
	command := exec.Command("/usr/bin/tcpdump", "-i", "lo", "-nn", "-U", "-Z", "root", "-w", path, filter)
	command.Env = refreshTCPCaptureEnvironment()
	stderr, err := command.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	ready := make(chan error, 1)
	stderrDone := make(chan refreshTCPDumpStderrResult, 1)
	go func() {
		scanner := bufio.NewScanner(stderr)
		var output strings.Builder
		published := false
		for scanner.Scan() {
			line := scanner.Text()
			output.WriteString(line)
			output.WriteByte('\n')
			if !published && strings.Contains(line, "listening on lo") {
				published = true
				ready <- nil
			}
		}
		scanErr := scanner.Err()
		if !published {
			if scanErr != nil {
				ready <- scanErr
			} else {
				ready <- errors.New("tcpdump exited before capture became active")
			}
		}
		stderrDone <- refreshTCPDumpStderrResult{output: output.String(), err: scanErr}
	}()
	capture := &refreshTCPCapture{command: command, path: path, stderrDone: stderrDone}
	t.Cleanup(func() { _, _ = capture.Stop() })
	select {
	case err := <-ready:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("tcpdump did not confirm an active capture")
	}
	return capture
}

func (c *refreshTCPCapture) Stop() (kernel5TCPCaptureEvidence, error) {
	if c == nil {
		return kernel5TCPCaptureEvidence{}, errors.New("nil TCP capture oracle")
	}
	c.stopOnce.Do(func() {
		if signalErr := c.command.Process.Signal(os.Interrupt); signalErr != nil && !errors.Is(signalErr, os.ErrProcessDone) {
			c.err = errors.Join(c.err, signalErr)
		}
		stderrResult, stderrErr := waitRefreshTCPDumpStderr(c.stderrDone, 2*time.Second)
		if stderrErr != nil {
			killErr := c.command.Process.Kill()
			if errors.Is(killErr, os.ErrProcessDone) {
				killErr = nil
			}
			stderrResult, stderrErr = waitRefreshTCPDumpStderr(c.stderrDone, 2*time.Second)
			c.err = errors.Join(c.err, errors.New("tcpdump stderr did not close after interrupt"), killErr, stderrErr)
		}
		c.err = errors.Join(c.err, stderrResult.err, waitRefreshTCPDumpProcess(c.command, 2*time.Second))
		allPackets, readErr := readRefreshTCPCapture(c.path)
		if readErr != nil {
			c.err = errors.Join(c.err, readErr)
		} else if trimmed := bytes.TrimSpace(allPackets); len(trimmed) != 0 {
			c.evidence.Packets = bytes.Count(trimmed, []byte{'\n'}) + 1
		}
		resetPackets, readErr := readRefreshTCPCapture(c.path, "tcp[tcpflags] & tcp-rst != 0")
		if readErr != nil {
			c.err = errors.Join(c.err, readErr)
		} else if trimmed := bytes.TrimSpace(resetPackets); len(trimmed) != 0 {
			c.evidence.RSTPackets = bytes.Count(trimmed, []byte{'\n'}) + 1
		}
		statistics, statisticsErr := parseKernel5TCPCaptureStatistics(stderrResult.output)
		if statisticsErr != nil {
			c.err = errors.Join(c.err, statisticsErr)
		} else {
			c.evidence.KernelStatistics = statistics
			c.err = errors.Join(c.err, validateKernel5TCPCaptureEvidence(c.evidence))
		}
	})
	return c.evidence, c.err
}

func refreshTCPCaptureEnvironment() []string {
	environment := make([]string, 0, len(os.Environ())+2)
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "LC_ALL=") || strings.HasPrefix(entry, "LANG=") || strings.HasPrefix(entry, "LANGUAGE=") {
			continue
		}
		environment = append(environment, entry)
	}
	return append(environment, "LC_ALL=C", "LANG=C")
}

func waitRefreshTCPDumpStderr(
	done <-chan refreshTCPDumpStderrResult,
	timeout time.Duration,
) (refreshTCPDumpStderrResult, error) {
	if done == nil {
		return refreshTCPDumpStderrResult{}, errors.New("tcpdump stderr completion channel is nil")
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case result := <-done:
		return result, nil
	case <-timer.C:
		return refreshTCPDumpStderrResult{}, errors.New("tcpdump stderr drain timed out")
	}
}

func waitRefreshTCPDumpProcess(command *exec.Cmd, timeout time.Duration) error {
	if command == nil {
		return errors.New("nil tcpdump command")
	}
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-wait:
		return err
	case <-timer.C:
		killErr := command.Process.Kill()
		if errors.Is(killErr, os.ErrProcessDone) {
			killErr = nil
		}
		killTimer := time.NewTimer(timeout)
		defer killTimer.Stop()
		select {
		case waitErr := <-wait:
			return errors.Join(errors.New("tcpdump process reap timed out before kill"), killErr, waitErr)
		case <-killTimer.C:
			return errors.Join(errors.New("tcpdump process reap remained blocked after kill"), killErr)
		}
	}
}

func readRefreshTCPCapture(path string, filter ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	arguments := []string{"-nn", "-tt", "-r", path}
	arguments = append(arguments, filter...)
	command := exec.CommandContext(ctx, "/usr/bin/tcpdump", arguments...)
	command.Env = refreshTCPCaptureEnvironment()
	command.WaitDelay = 250 * time.Millisecond
	output, err := command.Output()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("offline tcpdump read timed out: %w", ctx.Err())
	}
	if err != nil {
		return nil, fmt.Errorf("offline tcpdump read: %w", err)
	}
	return output, nil
}

func TestKernel5TCPCaptureCleanupWaitsAreBounded(t *testing.T) {
	stderrDone := make(chan refreshTCPDumpStderrResult)
	started := time.Now()
	if _, err := waitRefreshTCPDumpStderr(stderrDone, 10*time.Millisecond); err == nil {
		t.Fatal("stderr drain wait unexpectedly succeeded")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("stderr drain timeout took %v", elapsed)
	}

	command := exec.Command("/usr/bin/sleep", "30")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if command.Process != nil {
			_ = command.Process.Kill()
		}
	})
	started = time.Now()
	if err := waitRefreshTCPDumpProcess(command, 10*time.Millisecond); err == nil {
		t.Fatal("process wait unexpectedly completed before the forced timeout")
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("process kill/reap timeout took %v", elapsed)
	}
}

type refreshRouteTopology struct {
	namespace string
	clientA   string
	clientB   string
	gatewayA  string
	gatewayB  string
	clientIP  string
	serverIP  string
}

func newRefreshRouteTopology(t testing.TB) refreshRouteTopology {
	t.Helper()
	suffix := fmt.Sprintf("%x", uint64(time.Now().UnixNano())&0xfffff)
	topology := refreshRouteTopology{
		namespace: "rendr_route_" + suffix,
		clientA:   "rca" + suffix,
		clientB:   "rcb" + suffix,
		gatewayA:  "192.0.2.2",
		gatewayB:  "192.0.2.6",
		clientIP:  "198.18.30.1",
		serverIP:  "198.18.30.2",
	}
	serverA, serverB := "rsa"+suffix, "rsb"+suffix
	runRefreshIP(t, "netns", "add", topology.namespace)
	t.Cleanup(func() {
		_ = exec.Command("/usr/sbin/ip", "link", "del", topology.clientA).Run()
		_ = exec.Command("/usr/sbin/ip", "link", "del", topology.clientB).Run()
		_ = exec.Command("/usr/sbin/ip", "addr", "del", topology.clientIP+"/32", "dev", "lo").Run()
		_ = exec.Command("/usr/sbin/ip", "netns", "del", topology.namespace).Run()
	})
	runRefreshIP(t, "link", "add", topology.clientA, "type", "veth", "peer", "name", serverA)
	runRefreshIP(t, "link", "add", topology.clientB, "type", "veth", "peer", "name", serverB)
	runRefreshIP(t, "link", "set", serverA, "netns", topology.namespace)
	runRefreshIP(t, "link", "set", serverB, "netns", topology.namespace)
	runRefreshIP(t, "addr", "add", "192.0.2.1/30", "dev", topology.clientA)
	runRefreshIP(t, "addr", "add", "192.0.2.5/30", "dev", topology.clientB)
	runRefreshIP(t, "addr", "add", topology.clientIP+"/32", "dev", "lo")
	runRefreshIP(t, "link", "set", topology.clientA, "up")
	runRefreshIP(t, "link", "set", topology.clientB, "up")
	for _, arguments := range [][]string{
		{"link", "set", "lo", "up"},
		{"addr", "add", "192.0.2.2/30", "dev", serverA},
		{"addr", "add", "192.0.2.6/30", "dev", serverB},
		{"addr", "add", topology.serverIP + "/32", "dev", "lo"},
		{"link", "set", serverA, "up"},
		{"link", "set", serverB, "up"},
		{"route", "add", topology.clientIP + "/32", "via", "192.0.2.1", "dev", serverA, "src", topology.serverIP},
	} {
		command := append([]string{"netns", "exec", topology.namespace, "/usr/sbin/ip"}, arguments...)
		runRefreshIP(t, command...)
	}
	runRefreshIP(t, "route", "add", topology.serverIP+"/32", "via", topology.gatewayA, "dev", topology.clientA, "src", topology.clientIP)
	for _, command := range []*exec.Cmd{
		exec.Command("/usr/sbin/sysctl", "-qw", "net.ipv4.conf."+topology.clientA+".rp_filter=0"),
		exec.Command("/usr/sbin/sysctl", "-qw", "net.ipv4.conf."+topology.clientB+".rp_filter=0"),
		exec.Command("/usr/sbin/ip", "netns", "exec", topology.namespace, "/usr/sbin/sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0"),
	} {
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("disable rp_filter: %v (%s)", err, output)
		}
	}
	return topology
}

func refreshRouteTCPPair(t testing.TB, namespace, clientIP, serverIP string) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	type listenResult struct {
		listener *net.TCPListener
		err      error
	}
	listening := make(chan listenResult, 1)
	accepted := make(chan struct {
		conn *net.TCPConn
		err  error
	}, 1)
	go func() {
		runtime.LockOSThread()
		namespaceFile, err := os.Open("/run/netns/" + namespace)
		if err != nil {
			runtime.UnlockOSThread()
			listening <- listenResult{err: err}
			return
		}
		defer namespaceFile.Close()
		if err := unix.Setns(int(namespaceFile.Fd()), unix.CLONE_NEWNET); err != nil {
			runtime.UnlockOSThread()
			listening <- listenResult{err: err}
			return
		}
		listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP(serverIP)})
		listening <- listenResult{listener: listener, err: err}
		if err != nil {
			return
		}
		conn, acceptErr := listener.AcceptTCP()
		_ = listener.Close()
		accepted <- struct {
			conn *net.TCPConn
			err  error
		}{conn: conn, err: acceptErr}
		// Return while locked so the runtime discards this namespace-bound thread.
	}()
	ready := <-listening
	if ready.err != nil {
		t.Fatal(ready.err)
	}
	t.Cleanup(func() { _ = ready.listener.Close() })
	dialer := net.Dialer{
		Timeout:   3 * time.Second,
		LocalAddr: &net.TCPAddr{IP: net.ParseIP(clientIP)},
	}
	conn, err := dialer.Dial("tcp4", ready.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client, ok := conn.(*net.TCPConn)
	if !ok {
		_ = conn.Close()
		t.Fatalf("route client type=%T want *net.TCPConn", conn)
	}
	result := <-accepted
	if result.err != nil {
		_ = client.Close()
		t.Fatal(result.err)
	}
	_ = client.SetKeepAlive(false)
	_ = result.conn.SetKeepAlive(false)
	return client, result.conn
}

func refreshRouteOutputInterface(t testing.TB, conn *net.TCPConn) int {
	t.Helper()
	flow, err := tcpRouteFlowKeyForConn(conn)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), pathRefreshQueryTimeout)
	defer cancel()
	fd, err := openTCPRouteNetlink(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	selection, _, err := queryRouteState(ctx, fd, 1, flow)
	if err != nil || !selection.usable || selection.outputIf == 0 {
		t.Fatalf("route selection=%+v err=%v", selection, err)
	}
	return int(selection.outputIf)
}

func refreshInterfaceCounter(t testing.TB, interfaceName, counter string) uint64 {
	t.Helper()
	content, err := os.ReadFile("/sys/class/net/" + interfaceName + "/statistics/" + counter)
	if err != nil {
		t.Fatal(err)
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(content)), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func refreshMonitorTCPPair(t testing.TB, clientIP, serverIP string) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP(serverIP)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	type acceptResult struct {
		conn *net.TCPConn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		conn, acceptErr := listener.AcceptTCP()
		accepted <- acceptResult{conn: conn, err: acceptErr}
	}()
	client, err := net.DialTCP("tcp4", &net.TCPAddr{IP: net.ParseIP(clientIP)}, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	result := <-accepted
	if result.err != nil {
		_ = client.Close()
		t.Fatal(result.err)
	}
	_ = client.SetKeepAlive(false)
	_ = result.conn.SetKeepAlive(false)
	return client, result.conn
}

func runRefreshIP(t testing.TB, arguments ...string) {
	t.Helper()
	command := exec.Command("/usr/sbin/ip", arguments...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("ip %v: %v (%s)", arguments, err, output)
	}
}

const refreshLoopbackQdiscHandle = "72a1:"

func installRefreshLoopbackRateLimit(t testing.TB) {
	t.Helper()
	command := exec.Command(
		"/usr/sbin/tc", "qdisc", "add", "dev", "lo", "root", "handle", refreshLoopbackQdiscHandle,
		"tbf", "rate", "40mbit", "burst", "65536", "latency", "1s",
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("install loopback TCP_REPAIR rate limit: %v (%s)", err, output)
	}
	t.Cleanup(func() {
		command := exec.Command(
			"/usr/sbin/tc", "qdisc", "del", "dev", "lo", "root", "handle", refreshLoopbackQdiscHandle,
		)
		if output, err := command.CombinedOutput(); err != nil {
			t.Errorf("remove loopback TCP_REPAIR rate limit: %v (%s)", err, output)
		}
	})
	assertRefreshLoopbackRateLimit(t)
}

func assertRefreshLoopbackRateLimit(t testing.TB) {
	t.Helper()
	output, err := exec.Command("/usr/sbin/tc", "-j", "qdisc", "show", "dev", "lo").Output()
	if err != nil {
		t.Fatalf("inspect loopback TCP_REPAIR rate limit: %v", err)
	}
	var qdiscs []struct {
		Kind   string `json:"kind"`
		Handle string `json:"handle"`
		Root   bool   `json:"root"`
	}
	if err := json.Unmarshal(output, &qdiscs); err != nil {
		t.Fatalf("decode loopback TCP_REPAIR rate limit: %v", err)
	}
	for _, qdisc := range qdiscs {
		if qdisc.Root && qdisc.Kind == "tbf" && qdisc.Handle == refreshLoopbackQdiscHandle {
			return
		}
	}
	t.Fatalf("loopback TCP_REPAIR rate limit is absent or replaced: %s", output)
}

type refreshResourceSample struct {
	fds        int
	rules      int
	goroutines int
	heapInuse  uint64
	rss        uint64
}

func sampleRefreshResources(t testing.TB) refreshResourceSample {
	t.Helper()
	runtime.GC()
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	return refreshResourceSample{
		fds: refreshOpenFDs(t), goroutines: runtime.NumGoroutine(),
		heapInuse: memory.HeapInuse, rss: refreshRSSBytes(t),
	}
}

func refreshRSSBytes(t testing.TB) uint64 {
	t.Helper()
	content, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "VmRSS:" {
			kilobytes, parseErr := strconv.ParseUint(fields[1], 10, 64)
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			return kilobytes * 1024
		}
	}
	t.Fatal("/proc/self/status has no VmRSS")
	return 0
}

func refreshProcessCPUTicks(t testing.TB) uint64 {
	t.Helper()
	content, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatal(err)
	}
	endName := bytes.LastIndexByte(content, ')')
	if endName < 0 {
		t.Fatal("/proc/self/stat has no process-name terminator")
	}
	fields := strings.Fields(string(content[endName+1:]))
	if len(fields) <= 12 {
		t.Fatal("/proc/self/stat is missing CPU fields")
	}
	userTicks, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	systemTicks, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return userTicks + systemTicks
}

func refreshClockTicksPerSecond(t testing.TB) uint64 {
	t.Helper()
	output, err := exec.Command("/usr/bin/getconf", "CLK_TCK").Output()
	if err != nil {
		t.Fatal(err)
	}
	ticks, err := strconv.ParseUint(strings.TrimSpace(string(output)), 10, 64)
	if err != nil || ticks == 0 {
		t.Fatalf("CLK_TCK=%q err=%v", output, err)
	}
	return ticks
}

func assertNoRefreshQuarantineTables(t testing.TB) {
	t.Helper()
	output, err := exec.Command("/usr/sbin/nft", "list", "tables").CombinedOutput()
	if err != nil {
		t.Fatalf("list nft tables: %v (%s)", err, output)
	}
	if bytes.Contains(output, []byte("rendr_q2")) {
		t.Fatalf("automatic transaction leaked quarantine table: %s", output)
	}
}

func refreshOpenFDs(t testing.TB) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}
